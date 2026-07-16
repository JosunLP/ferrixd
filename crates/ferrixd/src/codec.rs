//! IRC line framing.
//!
//! Splits the byte stream into lines on `\n` (tolerating a preceding `\r`) and
//! enforces a hard maximum line length. A frame that exceeds the cap drops the
//! connection — the first line of defence against a client that never sends a
//! newline and would otherwise grow the read buffer without bound.

use std::io;

use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// Decoder/encoder for IRC lines.
///
/// - Decoding yields one line per frame, with the trailing CRLF/LF stripped.
/// - Encoding writes raw bytes verbatim (callers pass fully-rendered lines that
///   already include their own CRLF).
#[derive(Debug, Clone)]
pub struct IrcCodec {
    max_line: usize,
}

impl IrcCodec {
    /// Create a codec that rejects any line longer than `max_line` bytes
    /// (excluding the line terminator).
    #[must_use]
    pub fn new(max_line: usize) -> Self {
        Self { max_line }
    }

    fn too_long(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("line exceeds {} bytes", self.max_line),
        )
    }
}

impl Decoder for IrcCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(newline) = memchr::memchr(b'\n', src) else {
            // No complete line yet. If we have already buffered more than a
            // full line's worth without a terminator, the peer is misbehaving.
            if src.len() > self.max_line {
                return Err(self.too_long());
            }
            return Ok(None);
        };

        // Split off the line including the '\n'.
        let mut line = src.split_to(newline + 1);
        // Drop the '\n' and an optional preceding '\r'.
        line.truncate(line.len() - 1);
        if line.last() == Some(&b'\r') {
            line.truncate(line.len() - 1);
        }

        if line.len() > self.max_line {
            return Err(self.too_long());
        }
        Ok(Some(line))
    }
}

impl Encoder<Bytes> for IrcCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn decodes_crlf_and_lf_lines() {
        let mut codec = IrcCodec::new(512);
        let mut buf = BytesMut::from(&b"PING one\r\nPING two\nPART"[..]);

        let first = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&first[..], b"PING one");
        let second = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&second[..], b"PING two");
        // "PART" has no terminator yet.
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn empty_line_is_yielded() {
        let mut codec = IrcCodec::new(512);
        let mut buf = BytesMut::from(&b"\r\n"[..]);
        let line = codec.decode(&mut buf).unwrap().unwrap();
        assert!(line.is_empty());
    }

    #[test]
    fn over_long_completed_line_errors() {
        let mut codec = IrcCodec::new(4);
        let mut buf = BytesMut::from(&b"abcdef\r\n"[..]);
        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn over_long_unterminated_buffer_errors() {
        let mut codec = IrcCodec::new(4);
        let mut buf = BytesMut::from(&b"abcdefghij"[..]);
        assert!(codec.decode(&mut buf).is_err());
    }

    #[test]
    fn encodes_bytes_verbatim() {
        let mut codec = IrcCodec::new(512);
        let mut dst = BytesMut::new();
        codec
            .encode(Bytes::from_static(b"PONG :x\r\n"), &mut dst)
            .unwrap();
        assert_eq!(&dst[..], b"PONG :x\r\n");
    }
}
