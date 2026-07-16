//! SASL SCRAM-SHA-256 (RFC 5802), server side.
//!
//! Credentials are stored as the salt, iteration count, `StoredKey`, and
//! `ServerKey` derived from the password (the plaintext is never kept). The
//! server never sees the password during authentication — it verifies the
//! client's proof against `StoredKey` and returns a `ServerSignature`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

const LEN: usize = 32;
type HmacSha256 = Hmac<Sha256>;

/// Stored SCRAM credentials for an account.
#[derive(Debug, Clone)]
pub struct ScramCreds {
    /// Per-account salt.
    pub salt: Vec<u8>,
    /// PBKDF2 iteration count.
    pub iterations: u32,
    /// `SHA256(HMAC(SaltedPassword, "Client Key"))`.
    pub stored_key: [u8; LEN],
    /// `HMAC(SaltedPassword, "Server Key")`.
    pub server_key: [u8; LEN],
}

impl ScramCreds {
    /// Encode the credentials as a single config-pasteable token:
    /// `<iterations>:<b64 salt>:<b64 stored_key>:<b64 server_key>`. Neither the
    /// password nor anything that yields it can be recovered from this.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.iterations,
            STANDARD.encode(&self.salt),
            STANDARD.encode(self.stored_key),
            STANDARD.encode(self.server_key),
        )
    }

    /// Parse the token produced by [`ScramCreds::encode`].
    #[must_use]
    pub fn decode(token: &str) -> Option<ScramCreds> {
        let mut parts = token.split(':');
        let iterations: u32 = parts.next()?.trim().parse().ok()?;
        let salt = STANDARD.decode(parts.next()?.trim()).ok()?;
        let stored_key: [u8; LEN] = STANDARD
            .decode(parts.next()?.trim())
            .ok()?
            .try_into()
            .ok()?;
        let server_key: [u8; LEN] = STANDARD
            .decode(parts.next()?.trim())
            .ok()?
            .try_into()
            .ok()?;
        if parts.next().is_some() || iterations == 0 || salt.is_empty() {
            return None;
        }
        Some(ScramCreds {
            salt,
            iterations,
            stored_key,
            server_key,
        })
    }
}

fn hmac(key: &[u8], msg: &[u8]) -> [u8; LEN] {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return [0; LEN];
    };
    mac.update(msg);
    let mut out = [0u8; LEN];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn sha256(data: &[u8]) -> [u8; LEN] {
    let mut out = [0u8; LEN];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

/// A deterministic 16-byte salt derived from a seed (test fixtures only; real
/// credentials use a random salt — see [`crate::account::AccountStore`]).
#[must_use]
pub fn deterministic_salt(seed: &str) -> Vec<u8> {
    sha256(seed.as_bytes())[..16].to_vec()
}

/// A fresh, unpredictable server nonce (lowercase hex) for a SCRAM exchange.
///
/// RFC 5802 §5.1 requires the server nonce to be unguessable; it is gathered
/// from the OS CSPRNG. Returns `None` if entropy is unavailable, in which case
/// the caller must abort the exchange rather than fall back to anything
/// predictable.
#[must_use]
pub fn random_nonce() -> Option<String> {
    let mut bytes = [0u8; 18];
    getrandom::fill(&mut bytes).ok()?;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    Some(out)
}

/// Derive SCRAM credentials from a plaintext password.
#[must_use]
pub fn derive(password: &str, salt: &[u8], iterations: u32) -> ScramCreds {
    let mut salted = [0u8; LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut salted);
    let client_key = hmac(&salted, b"Client Key");
    ScramCreds {
        salt: salt.to_vec(),
        iterations,
        stored_key: sha256(&client_key),
        server_key: hmac(&salted, b"Server Key"),
    }
}

/// The bare client-first message after stripping the GS2 header (`n,,` etc.).
fn client_first_bare(client_first: &str) -> Option<&str> {
    let first = client_first.find(',')?;
    let second = client_first[first + 1..].find(',')? + first + 1;
    Some(&client_first[second + 1..])
}

/// An in-progress server-side SCRAM exchange.
#[derive(Debug)]
pub struct Exchange {
    /// The canonical account name, once resolved.
    pub account: String,
    creds: ScramCreds,
    client_first_bare: String,
    server_first: String,
    combined_nonce: String,
}

impl Exchange {
    /// Begin from the client-first message, producing the server-first message.
    /// `lookup` resolves a username to `(canonical account, creds)`.
    #[must_use]
    pub fn start(
        client_first: &str,
        server_nonce: &str,
        lookup: impl FnOnce(&str) -> Option<(String, ScramCreds)>,
    ) -> Option<(Exchange, String)> {
        let bare = client_first_bare(client_first)?;
        let mut username = None;
        let mut client_nonce = None;
        for field in bare.split(',') {
            if let Some(u) = field.strip_prefix("n=") {
                username = Some(u.to_owned());
            } else if let Some(r) = field.strip_prefix("r=") {
                client_nonce = Some(r.to_owned());
            }
        }
        let (username, client_nonce) = (username?, client_nonce?);
        let (account, creds) = lookup(&username)?;
        let combined_nonce = format!("{client_nonce}{server_nonce}");
        let server_first = format!(
            "r={combined_nonce},s={},i={}",
            STANDARD.encode(&creds.salt),
            creds.iterations
        );
        Some((
            Exchange {
                account,
                creds,
                client_first_bare: bare.to_owned(),
                server_first: server_first.clone(),
                combined_nonce,
            },
            server_first,
        ))
    }

    /// Verify the client-final message; on success return the server-final
    /// (`v=…`) message, else `None`.
    #[must_use]
    pub fn finish(&self, client_final: &str) -> Option<String> {
        let mut nonce = None;
        let mut proof_b64 = None;
        for field in client_final.split(',') {
            if let Some(r) = field.strip_prefix("r=") {
                nonce = Some(r);
            } else if let Some(p) = field.strip_prefix("p=") {
                proof_b64 = Some(p);
            }
        }
        if nonce? != self.combined_nonce {
            return None;
        }
        let proof = STANDARD.decode(proof_b64?).ok()?;
        if proof.len() != LEN {
            return None;
        }

        let without_proof = format!("c=biws,r={}", self.combined_nonce);
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, self.server_first, without_proof
        );
        let client_signature = hmac(&self.creds.stored_key, auth_message.as_bytes());
        let mut client_key = [0u8; LEN];
        for i in 0..LEN {
            client_key[i] = proof[i] ^ client_signature[i];
        }
        if sha256(&client_key) != self.creds.stored_key {
            return None;
        }
        let server_signature = hmac(&self.creds.server_key, auth_message.as_bytes());
        Some(format!("v={}", STANDARD.encode(server_signature)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // A minimal SCRAM client, to drive the server through a full exchange.
    fn client_final(
        creds: &ScramCreds,
        cf_bare: &str,
        server_first: &str,
        password: &str,
    ) -> String {
        let combined = server_first
            .split(',')
            .find_map(|f| f.strip_prefix("r="))
            .unwrap();
        let mut salted = [0u8; LEN];
        pbkdf2::pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            &creds.salt,
            creds.iterations,
            &mut salted,
        );
        let client_key = hmac(&salted, b"Client Key");
        let stored = sha256(&client_key);
        let without_proof = format!("c=biws,r={combined}");
        let auth = format!("{cf_bare},{server_first},{without_proof}");
        let sig = hmac(&stored, auth.as_bytes());
        let mut proof = [0u8; LEN];
        for i in 0..LEN {
            proof[i] = client_key[i] ^ sig[i];
        }
        format!("{without_proof},p={}", STANDARD.encode(proof))
    }

    #[test]
    fn full_exchange_succeeds() {
        let creds = derive("hunter2", &deterministic_salt("alice"), 4096);
        let cf = "n,,n=alice,r=clientnonce";
        let creds_clone = creds.clone();
        let (exchange, server_first) = Exchange::start(cf, "servernonce", |u| {
            (u == "alice").then(|| ("Alice".to_owned(), creds_clone.clone()))
        })
        .unwrap();
        let cfin = client_final(&creds, "n=alice,r=clientnonce", &server_first, "hunter2");
        assert!(exchange.finish(&cfin).is_some());
        assert_eq!(exchange.account, "Alice");
    }

    #[test]
    fn wrong_password_fails() {
        let creds = derive("hunter2", &deterministic_salt("alice"), 4096);
        let creds_clone = creds.clone();
        let (exchange, server_first) = Exchange::start("n,,n=alice,r=cn", "sn", |_| {
            Some(("Alice".to_owned(), creds_clone.clone()))
        })
        .unwrap();
        let cfin = client_final(&creds, "n=alice,r=cn", &server_first, "wrong");
        assert!(exchange.finish(&cfin).is_none());
    }
}
