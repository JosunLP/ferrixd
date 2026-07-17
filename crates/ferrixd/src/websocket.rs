//! IRC-over-WebSocket transport (IRCv3 `websocket`), implemented from scratch.
//!
//! A WebSocket client speaks the same IRC protocol, but each IRC line travels as
//! exactly one WebSocket message (no trailing `\r\n` on the wire). This module
//! implements the server side of the RFC 6455 handshake and framing directly —
//! no external WebSocket crate — and exposes the connection as a plain
//! [`AsyncRead`]/[`AsyncWrite`] byte stream ([`WsStream`]) so it plugs straight
//! into the existing framing/rate-limiting pipeline in [`crate::connection`]:
//! reads surface each inbound message as `line\r\n`, and writes buffer until a
//! `\r\n`-terminated line is complete, then emit it as one WebSocket frame.
//!
//! Only the server role is needed, which keeps this small: inbound (client)
//! frames are always masked and are unmasked here; outbound (server) frames are
//! never masked. TLS (`wss://`) is terminated by [`tokio_rustls`] *before* the
//! handshake, so this layer only ever sees the decrypted byte stream.
//!
//! What is handled: the `Sec-WebSocket-Accept` handshake, subprotocol
//! negotiation (`text.ircv3.net` / `binary.ircv3.net`), text/binary data frames
//! (including fragmentation via continuation frames), ping→pong, close, and a
//! per-message size cap for DoS resistance. Reserved bits and unmasked client
//! frames are rejected per spec.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine;
use bytes::{Buf, BufMut, BytesMut};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// UTF-8 subprotocol: frames are sent as WebSocket text messages.
const TEXT_SUBPROTOCOL: &str = "text.ircv3.net";
/// Binary subprotocol: frames are sent as WebSocket binary messages.
const BINARY_SUBPROTOCOL: &str = "binary.ircv3.net";
/// The RFC 6455 handshake GUID appended to `Sec-WebSocket-Key` before hashing.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Cap on the HTTP upgrade request size (DoS guard on the handshake).
const MAX_HANDSHAKE_BYTES: usize = 8 * 1024;
/// How many socket bytes to read per `poll_read` of the underlying stream.
const READ_CHUNK: usize = 8 * 1024;
/// Hard cap on encoded outbound bytes queued for the socket. A peer that keeps
/// the pipe full while forcing us to queue control responses (e.g. a PING
/// flood against a non-reading client) is disconnected instead of growing
/// `tx_raw` without bound.
const MAX_TX_BUFFER: usize = 1024 * 1024;

/// WebSocket opcodes (RFC 6455 §5.2).
const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// Perform the WebSocket server handshake on `stream` and wrap the result as a
/// byte stream. `max_line` bounds an inbound message (DoS control) — matching
/// the codec's fatal frame length.
///
/// # Errors
///
/// Returns an error if the HTTP upgrade handshake is malformed or fails.
pub async fn accept<S>(mut stream: S, max_line: usize) -> io::Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read the HTTP upgrade request up to the header terminator.
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let header_end = loop {
        if let Some(pos) = find_crlf_crlf(&buf) {
            break pos + 4;
        }
        if buf.len() > MAX_HANDSHAKE_BYTES {
            return Err(reject(&mut stream, "handshake request too large").await);
        }
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    // Any bytes past the header belong to the frame stream (a client may
    // pipeline its first frame right after the handshake).
    let leftover = buf.split_off(header_end);

    let Some(request) = parse_request(&buf[..header_end]) else {
        return Err(reject(&mut stream, "malformed upgrade request").await);
    };
    if !request.is_get
        || !request.upgrade_ok
        || !request.connection_ok
        || request.version != "13"
        || request.key.is_empty()
    {
        return Err(reject(&mut stream, "not a WebSocket/13 upgrade").await);
    }

    let accept_key = compute_accept(&request.key);
    let subprotocol = select_subprotocol(&request.protocols);

    let mut response = String::with_capacity(160);
    response.push_str("HTTP/1.1 101 Switching Protocols\r\n");
    response.push_str("Upgrade: websocket\r\n");
    response.push_str("Connection: Upgrade\r\n");
    response.push_str("Sec-WebSocket-Accept: ");
    response.push_str(&accept_key);
    response.push_str("\r\n");
    if let Some(proto) = subprotocol {
        // We MUST echo the subprotocol we committed to, or a browser rejects it.
        response.push_str("Sec-WebSocket-Protocol: ");
        response.push_str(proto);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    // No agreed subprotocol → default to text (UTF-8), which is always valid
    // since the IRC line grammar is UTF-8 (see UTF8ONLY handling).
    let binary = subprotocol == Some(BINARY_SUBPROTOCOL);
    let mut ws = WsStream::new(stream, binary, max_line);
    ws.rx_raw.extend_from_slice(&leftover);
    Ok(ws)
}

/// Write a `400 Bad Request` and return an error describing why the handshake
/// was refused.
async fn reject<S>(stream: &mut S, why: &str) -> io::Error
where
    S: AsyncWrite + Unpin,
{
    let _ = stream
        .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        .await;
    let _ = stream.flush().await;
    io::Error::new(io::ErrorKind::InvalidData, why.to_owned())
}

/// The interesting fields of a parsed WebSocket upgrade request.
struct UpgradeRequest {
    is_get: bool,
    upgrade_ok: bool,
    connection_ok: bool,
    key: String,
    version: String,
    protocols: Vec<String>,
}

/// Parse the request line and headers of an HTTP upgrade request. Returns `None`
/// if the bytes are not valid UTF-8 or a header line is malformed.
fn parse_request(bytes: &[u8]) -> Option<UpgradeRequest> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut req = UpgradeRequest {
        is_get: request_line.starts_with("GET "),
        upgrade_ok: false,
        connection_ok: false,
        key: String::new(),
        version: String::new(),
        protocols: Vec::new(),
    };
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("sec-websocket-key") {
            req.key = value.to_owned();
        } else if name.eq_ignore_ascii_case("sec-websocket-version") {
            req.version = value.to_owned();
        } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            for proto in value.split(',') {
                let proto = proto.trim();
                if !proto.is_empty() {
                    req.protocols.push(proto.to_owned());
                }
            }
        } else if name.eq_ignore_ascii_case("upgrade")
            && value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("websocket"))
        {
            req.upgrade_ok = true;
        } else if name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("upgrade"))
        {
            req.connection_ok = true;
        }
    }
    Some(req)
}

/// Compute `Sec-WebSocket-Accept`: `base64(sha1(key + WS_GUID))` (RFC 6455 §4.2.2).
fn compute_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// Pick the first subprotocol the client offered that we support, honouring the
/// client's stated preference order.
fn select_subprotocol(offered: &[String]) -> Option<&'static str> {
    offered.iter().find_map(|proto| {
        if proto == TEXT_SUBPROTOCOL {
            Some(TEXT_SUBPROTOCOL)
        } else if proto == BINARY_SUBPROTOCOL {
            Some(BINARY_SUBPROTOCOL)
        } else {
            None
        }
    })
}

/// Find the `\r\n\r\n` header terminator, returning the index of its first byte.
fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// The result of trying to decode one frame from the inbound buffer.
enum FrameStatus {
    /// Not enough bytes buffered yet.
    NeedMore,
    /// A protocol violation (reserved bits, unmasked client frame, oversize).
    Protocol,
    /// A complete frame: `(fin, opcode, unmasked payload)`.
    Frame(bool, u8, Vec<u8>),
}

/// What to do after handling a decoded frame.
enum Action {
    /// Keep decoding.
    Continue,
    /// The peer closed: report EOF to the reader.
    Eof,
    /// A protocol violation: close and report EOF.
    Error,
}

/// An [`AsyncRead`]/[`AsyncWrite`] adapter that speaks WebSocket frames on the
/// wire and plain `line\r\n` IRC bytes to the rest of the server.
pub struct WsStream<S> {
    inner: S,
    /// `true` → emit binary frames (`binary.ircv3.net`); `false` → text frames.
    binary: bool,
    /// Largest message (or reassembled fragment chain) we will accept.
    max_message: usize,
    /// Raw bytes read from `inner`, not yet decoded into frames.
    rx_raw: BytesMut,
    /// Decoded payloads (each terminated with `\r\n`) awaiting the reader.
    read_buf: BytesMut,
    /// Set once the peer closed or the stream ended: further reads report EOF.
    read_eof: bool,
    /// Opcode of an in-progress fragmented message (`text`/`binary`), if any.
    frag_opcode: Option<u8>,
    /// Reassembly buffer for a fragmented message.
    frag_buf: Vec<u8>,
    /// Outbound IRC bytes accumulating until a full `\r\n`-terminated line.
    write_buf: BytesMut,
    /// Encoded outbound frame bytes (data + control) awaiting the socket.
    tx_raw: BytesMut,
    /// Whether a close frame has already been queued/sent.
    close_sent: bool,
}

impl<S> std::fmt::Debug for WsStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsStream")
            .field("binary", &self.binary)
            .field("rx_buffered", &self.rx_raw.len())
            .field("read_buffered", &self.read_buf.len())
            .field("tx_buffered", &self.tx_raw.len())
            .finish()
    }
}

impl<S> WsStream<S> {
    fn new(inner: S, binary: bool, max_message: usize) -> Self {
        Self {
            inner,
            binary,
            max_message,
            rx_raw: BytesMut::new(),
            read_buf: BytesMut::new(),
            read_eof: false,
            frag_opcode: None,
            frag_buf: Vec::new(),
            write_buf: BytesMut::new(),
            tx_raw: BytesMut::new(),
            close_sent: false,
        }
    }

    /// Copy buffered decoded bytes into `buf`; returns whether any were produced.
    fn serve_buffered(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        let n = self.read_buf.len().min(buf.remaining());
        if n == 0 {
            return false;
        }
        buf.put_slice(&self.read_buf[..n]);
        self.read_buf.advance(n);
        true
    }

    /// Try to decode a single frame from `rx_raw`, consuming it on success.
    fn take_frame(&mut self) -> FrameStatus {
        let rx: &[u8] = &self.rx_raw;
        if rx.len() < 2 {
            return FrameStatus::NeedMore;
        }
        let (b0, b1) = (rx[0], rx[1]);
        if b0 & 0x70 != 0 {
            return FrameStatus::Protocol; // reserved bits set, no extensions negotiated
        }
        let fin = b0 & 0x80 != 0;
        let opcode = b0 & 0x0F;
        let masked = b1 & 0x80 != 0;
        let len7 = (b1 & 0x7F) as usize;

        let (mut offset, payload_len) = if len7 < 126 {
            (2usize, len7)
        } else if len7 == 126 {
            if rx.len() < 4 {
                return FrameStatus::NeedMore;
            }
            (4usize, u16::from_be_bytes([rx[2], rx[3]]) as usize)
        } else {
            if rx.len() < 10 {
                return FrameStatus::NeedMore;
            }
            let mut len_bytes = [0u8; 8];
            len_bytes.copy_from_slice(&rx[2..10]);
            let len = u64::from_be_bytes(len_bytes);
            if len > self.max_message as u64 {
                return FrameStatus::Protocol;
            }
            (10usize, len as usize)
        };
        if payload_len > self.max_message {
            return FrameStatus::Protocol;
        }
        // Client-to-server frames MUST be masked (RFC 6455 §5.1).
        if !masked {
            return FrameStatus::Protocol;
        }
        if rx.len() < offset + 4 {
            return FrameStatus::NeedMore;
        }
        let mask = [rx[offset], rx[offset + 1], rx[offset + 2], rx[offset + 3]];
        offset += 4;
        let total = offset + payload_len;
        if rx.len() < total {
            return FrameStatus::NeedMore;
        }
        let mut payload = rx[offset..total].to_vec();
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
        // `rx` borrow ends here (its last use was building `payload`), so the
        // mutable advance below is sound under NLL.
        self.rx_raw.advance(total);
        FrameStatus::Frame(fin, opcode, payload)
    }

    /// Act on a decoded frame, updating reassembly state and queueing any
    /// control responses.
    fn handle_frame(&mut self, fin: bool, opcode: u8, payload: Vec<u8>) -> Action {
        match opcode {
            OP_CONTINUATION => {
                if self.frag_opcode.is_none() {
                    return Action::Error; // continuation without a start
                }
                if self.frag_buf.len() + payload.len() > self.max_message {
                    return Action::Error;
                }
                self.frag_buf.extend_from_slice(&payload);
                if fin {
                    self.frag_opcode = None;
                    let message = std::mem::take(&mut self.frag_buf);
                    self.deliver(&message);
                }
                Action::Continue
            }
            OP_TEXT | OP_BINARY => {
                if self.frag_opcode.is_some() {
                    return Action::Error; // new data frame mid-fragment
                }
                if fin {
                    self.deliver(&payload);
                } else {
                    self.frag_opcode = Some(opcode);
                    self.frag_buf = payload;
                }
                Action::Continue
            }
            OP_PING => {
                // Control frames must not be fragmented and are ≤ 125 bytes.
                if !fin || payload.len() > 125 {
                    return Action::Error;
                }
                self.push_frame(OP_PONG, &payload);
                Action::Continue
            }
            OP_PONG => {
                if !fin || payload.len() > 125 {
                    return Action::Error;
                }
                Action::Continue // unsolicited/echoed pong — nothing to do
            }
            OP_CLOSE => {
                self.begin_close(1000);
                Action::Eof
            }
            _ => Action::Error,
        }
    }

    /// Hand a decoded message to the reader as one `line\r\n` unit.
    fn deliver(&mut self, message: &[u8]) {
        self.read_buf.extend_from_slice(message);
        self.read_buf.extend_from_slice(b"\r\n");
    }

    /// Encode an unmasked server frame and queue it for the socket.
    fn push_frame(&mut self, opcode: u8, payload: &[u8]) {
        self.tx_raw.reserve(payload.len() + 10);
        self.tx_raw.put_u8(0x80 | opcode); // FIN set, single-frame message
        let len = payload.len();
        if len < 126 {
            self.tx_raw.put_u8(len as u8);
        } else if len <= u16::MAX as usize {
            self.tx_raw.put_u8(126);
            self.tx_raw.put_u16(len as u16);
        } else {
            self.tx_raw.put_u8(127);
            self.tx_raw.put_u64(len as u64);
        }
        self.tx_raw.extend_from_slice(payload);
    }

    /// Queue a close frame (once) carrying `code`.
    fn begin_close(&mut self, code: u16) {
        if self.close_sent {
            return;
        }
        self.close_sent = true;
        self.push_frame(OP_CLOSE, &code.to_be_bytes());
    }

    /// Split every complete `\r\n`-terminated line out of `write_buf` and encode
    /// it as one WebSocket data frame.
    fn queue_out_lines(&mut self) {
        let opcode = if self.binary { OP_BINARY } else { OP_TEXT };
        while let Some(nl) = memchr::memchr(b'\n', &self.write_buf) {
            let line = self.write_buf.split_to(nl + 1);
            // Drop the trailing `\n` and an optional preceding `\r`: the wire
            // message carries neither.
            let mut end = line.len() - 1;
            if end > 0 && line[end - 1] == b'\r' {
                end -= 1;
            }
            if end == 0 {
                continue; // blank line — nothing to send
            }
            self.push_frame(opcode, &line[..end]);
        }
    }
}

impl<S> WsStream<S>
where
    S: AsyncWrite + Unpin,
{
    /// Write as much of `tx_raw` to the socket as it will accept right now.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.tx_raw.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.tx_raw) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => self.tx_raw.advance(n),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.serve_buffered(buf) {
                return Poll::Ready(Ok(()));
            }
            if this.read_eof {
                return Poll::Ready(Ok(())); // 0 bytes filled → EOF
            }
            // Best-effort drain of queued control frames (PONG, CLOSE) to prevent
            // unbounded growth if a client sends only PING frames.
            if !this.tx_raw.is_empty() {
                let _ = this.poll_drain(cx);
            }
            // If the peer refuses to read while forcing us to queue responses,
            // give up rather than buffer without bound.
            if this.tx_raw.len() > MAX_TX_BUFFER {
                this.read_eof = true;
                return Poll::Ready(Err(io::Error::other("websocket send backlog exceeded")));
            }
            match this.take_frame() {
                FrameStatus::Frame(fin, opcode, payload) => {
                    match this.handle_frame(fin, opcode, payload) {
                        Action::Continue => continue,
                        Action::Eof => {
                            this.read_eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        Action::Error => {
                            this.begin_close(1002);
                            this.read_eof = true;
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
                FrameStatus::Protocol => {
                    this.begin_close(1002);
                    this.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                FrameStatus::NeedMore => {
                    let mut chunk = [0u8; READ_CHUNK];
                    let mut rb = ReadBuf::new(&mut chunk);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            let filled = rb.filled();
                            if filled.is_empty() {
                                this.read_eof = true;
                                return Poll::Ready(Ok(()));
                            }
                            this.rx_raw.extend_from_slice(filled);
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.write_buf.extend_from_slice(buf);
        this.queue_out_lines();
        // Best-effort push to the socket; whatever cannot go now is flushed by a
        // later `poll_flush` (which the framing layer calls after each line).
        let _ = this.poll_drain(cx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.begin_close(1000);
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_matches_rfc_6455_example() {
        // RFC 6455 §1.3 worked example.
        assert_eq!(
            compute_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn subprotocol_selection_honours_client_order() {
        let offered = vec!["binary.ircv3.net".to_owned(), "text.ircv3.net".to_owned()];
        assert_eq!(select_subprotocol(&offered), Some("binary.ircv3.net"));
        let offered = vec!["x".to_owned(), "text.ircv3.net".to_owned()];
        assert_eq!(select_subprotocol(&offered), Some("text.ircv3.net"));
        assert_eq!(select_subprotocol(&["nope".to_owned()]), None);
    }

    #[test]
    fn parse_request_extracts_upgrade_fields() {
        let raw = b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
            Connection: Upgrade\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\
            Sec-WebSocket-Protocol: text.ircv3.net, binary.ircv3.net\r\n\r\n";
        let req = parse_request(raw).expect("parse");
        assert!(req.is_get && req.upgrade_ok && req.connection_ok);
        assert_eq!(req.key, "abc");
        assert_eq!(req.version, "13");
        assert_eq!(req.protocols, vec!["text.ircv3.net", "binary.ircv3.net"]);
    }

    /// A masked client frame is decoded and surfaced as `payload\r\n`; a server
    /// line is encoded as one unmasked frame.
    #[test]
    fn frame_round_trip() {
        let mut ws = WsStream::new((), false, 4096);

        // Inbound: masked "NICK alice" text frame.
        let payload = b"NICK alice";
        let mask = [0x37u8, 0xfa, 0x21, 0x3d];
        ws.rx_raw.put_u8(0x81); // FIN | text
        ws.rx_raw.put_u8(0x80 | payload.len() as u8); // masked
        ws.rx_raw.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            ws.rx_raw.put_u8(b ^ mask[i % 4]);
        }
        match ws.take_frame() {
            FrameStatus::Frame(fin, opcode, decoded) => {
                assert!(fin);
                assert_eq!(opcode, OP_TEXT);
                let _ = ws.handle_frame(fin, opcode, decoded);
            }
            _ => panic!("expected a complete frame"),
        }
        assert_eq!(&ws.read_buf[..], b"NICK alice\r\n");

        // Outbound: an IRC line becomes one unmasked text frame.
        ws.write_buf.extend_from_slice(b":srv 001 alice :hi\r\n");
        ws.queue_out_lines();
        assert_eq!(ws.tx_raw[0], 0x81); // FIN | text
        assert_eq!(ws.tx_raw[1] & 0x80, 0); // server frames are not masked
        let len = (ws.tx_raw[1] & 0x7f) as usize;
        assert_eq!(&ws.tx_raw[2..2 + len], b":srv 001 alice :hi");
    }

    #[test]
    fn unmasked_client_frame_is_rejected() {
        let mut ws = WsStream::new((), false, 4096);
        ws.rx_raw.put_u8(0x81);
        ws.rx_raw.put_u8(0x02); // len 2, NOT masked
        ws.rx_raw.extend_from_slice(b"hi");
        assert!(matches!(ws.take_frame(), FrameStatus::Protocol));
    }
}
