//! SASL authentication protocol handling (the `AUTHENTICATE` state machine).
//!
//! Supports `PLAIN` (username + password, verified against Argon2 hashes),
//! `EXTERNAL` (TLS client-certificate fingerprint), and `SCRAM-SHA-256` (the
//! challenge-response state machine lives in [`crate::scram`]). Credential
//! data is base64 and may be split into 400-byte chunks; this module
//! accumulates and decodes them.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// Maximum accumulated SASL payload (a DoS guard on the base64 buffer).
pub const MAX_SASL_LEN: usize = 8192;

/// One SASL response line is at most this many base64 bytes; an exactly-full
/// line signals that more follow.
const CHUNK_LEN: usize = 400;

/// A supported SASL mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// `PLAIN`: `authzid \0 authcid \0 password`.
    Plain,
    /// `EXTERNAL`: authenticate via the TLS client certificate.
    External,
    /// `SCRAM-SHA-256`: challenge/response (RFC 5802).
    Scram,
}

impl Mechanism {
    /// Resolve a mechanism name (case-insensitive).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Mechanism> {
        match name.to_ascii_uppercase().as_str() {
            "PLAIN" => Some(Mechanism::Plain),
            "EXTERNAL" => Some(Mechanism::External),
            "SCRAM-SHA-256" => Some(Mechanism::Scram),
            _ => None,
        }
    }
}

/// The multi-step state of a SCRAM exchange.
#[derive(Debug, Default)]
pub enum ScramPhase {
    /// No SCRAM in progress.
    #[default]
    Idle,
    /// Awaiting the client-first message.
    AwaitingClientFirst,
    /// Awaiting the client-final message (holds the server exchange state).
    AwaitingClientFinal(Box<crate::scram::Exchange>),
    /// Awaiting the empty final response; holds the resolved account name.
    AwaitingFinalAck(String),
}

/// Per-connection SASL negotiation state.
#[derive(Debug, Default)]
pub struct SaslSession {
    /// The in-progress mechanism, once selected.
    pub mechanism: Option<Mechanism>,
    /// SCRAM sub-state (for `Mechanism::Scram`).
    pub scram: ScramPhase,
    /// Accumulated base64 response chunks.
    buffer: String,
    /// The account name established on success (used to gate registration).
    pub authenticated_as: Option<String>,
}

/// Result of feeding one `AUTHENTICATE` data line.
#[derive(Debug, PartialEq, Eq)]
pub enum ChunkResult {
    /// The line was exactly full; more chunks are expected.
    NeedMore,
    /// Decoding completed; here are the raw credential bytes.
    Complete(Vec<u8>),
    /// The payload was malformed or too large.
    Invalid,
}

impl SaslSession {
    /// Reset all in-progress state (on abort or completion).
    pub fn reset(&mut self) {
        self.mechanism = None;
        self.scram = ScramPhase::Idle;
        self.buffer.clear();
    }

    /// Feed one `AUTHENTICATE` data line (`chunk`), where `"+"` denotes an empty
    /// response. Returns whether more is needed, the decoded bytes, or an error.
    pub fn push_chunk(&mut self, chunk: &str) -> ChunkResult {
        let empty_marker = chunk == "+";
        if !empty_marker {
            if self.buffer.len() + chunk.len() > MAX_SASL_LEN {
                return ChunkResult::Invalid;
            }
            self.buffer.push_str(chunk);
        }
        if empty_marker || chunk.len() < CHUNK_LEN {
            let result = match STANDARD.decode(self.buffer.as_bytes()) {
                Ok(bytes) => ChunkResult::Complete(bytes),
                Err(_) => ChunkResult::Invalid,
            };
            self.buffer.clear();
            result
        } else {
            ChunkResult::NeedMore
        }
    }
}

/// Decode SASL PLAIN credentials: `authzid \0 authcid \0 password`.
///
/// Returns `(authzid, authcid, password)`, or `None` if malformed.
#[must_use]
pub fn decode_plain(data: &[u8]) -> Option<(String, String, String)> {
    let mut parts = data.split(|&b| b == 0);
    let authzid = parts.next()?;
    let authcid = parts.next()?;
    let password = parts.next()?;
    if parts.next().is_some() {
        return None; // more than three fields
    }
    Some((
        String::from_utf8(authzid.to_vec()).ok()?,
        String::from_utf8(authcid.to_vec()).ok()?,
        String::from_utf8(password.to_vec()).ok()?,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn mechanism_parsing() {
        assert_eq!(Mechanism::from_name("plain"), Some(Mechanism::Plain));
        assert_eq!(Mechanism::from_name("EXTERNAL"), Some(Mechanism::External));
        assert_eq!(Mechanism::from_name("scram"), None);
    }

    #[test]
    fn single_chunk_decode() {
        let mut s = SaslSession::default();
        let payload = STANDARD.encode(b"\0alice\0s3cret");
        match s.push_chunk(&payload) {
            ChunkResult::Complete(bytes) => {
                assert_eq!(
                    decode_plain(&bytes),
                    Some((String::new(), "alice".into(), "s3cret".into()))
                );
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn empty_marker_is_terminal() {
        let mut s = SaslSession::default();
        assert_eq!(s.push_chunk("+"), ChunkResult::Complete(Vec::new()));
    }

    #[test]
    fn oversized_is_invalid() {
        let mut s = SaslSession::default();
        let big = "A".repeat(MAX_SASL_LEN + 1);
        assert_eq!(s.push_chunk(&big), ChunkResult::Invalid);
    }

    #[test]
    fn bad_plain_shapes() {
        assert_eq!(decode_plain(b"noNULs"), None);
        assert_eq!(decode_plain(b"a\0b\0c\0d"), None);
    }
}
