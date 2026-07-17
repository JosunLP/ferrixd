//! Per-connection tasks.
//!
//! Each connection is driven by two tasks:
//!  * a **reader** (this function) that frames and parses inbound lines and
//!    dispatches commands, mutating shared state and queueing outbound messages;
//!  * a **writer** that drains the client's bounded SendQ mailbox to the socket.
//!
//! The reader owns the client lifecycle: when its loop ends it runs disconnect
//! cleanup exactly once, then signals the writer to flush and close.
//!
//! DoS controls: a per-IP connection cap, a token-bucket rate
//! limit on inbound commands ("Excess Flood"), and a bounded SendQ that closes a
//! client whose outbound queue overflows.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ferrix_protocol::{Limits, Message};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info};

use crate::codec::IrcCodec;
use crate::command;
use crate::metrics::Metrics;
use crate::session::Session;
use crate::state::{ClientEntry, MailboxRx, Outbound, Server};
use crate::wire::Line;

/// Shared context handed to every connection.
#[derive(Debug, Clone)]
pub struct ConnContext {
    /// The shared server state.
    pub server: Arc<Server>,
    /// Parser length budgets.
    pub limits: Limits,
    /// Fatal frame length for the codec.
    pub max_line: usize,
    /// How long a connection may remain unregistered before being closed.
    pub registration_timeout: Duration,
    /// Maximum simultaneous connections from one source IP.
    pub max_clients_per_ip: u32,
    /// Bounded SendQ depth (queued lines) before a slow client is dropped.
    pub sendq_lines: usize,
    /// Inbound command burst allowance (token-bucket size).
    pub recv_burst: u32,
    /// Sustained inbound command rate per second (token-bucket refill).
    pub recv_rate: u32,
    /// Idle interval after which the server pings a quiet client (and, if the
    /// previous ping went unanswered, disconnects it).
    pub ping_interval: Duration,
}

/// A simple token bucket for inbound-command rate limiting.
struct TokenBucket {
    tokens: f64,
    burst: f64,
    rate: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(burst: u32, rate: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(burst),
            burst: f64::from(burst),
            rate: f64::from(rate.max(1)),
            last: now,
        }
    }

    /// Refill for elapsed time and try to consume one token.
    fn try_consume(&mut self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Drive a single client connection to completion. `cert_fp` is the SHA-256
/// fingerprint of the client's TLS certificate, if it presented one (SASL
/// EXTERNAL); `None` for plaintext or certless connections. `secure` records
/// whether the transport is TLS (for `RPL_WHOISSECURE`).
pub async fn serve<S>(
    stream: S,
    peer: SocketAddr,
    ctx: ConnContext,
    cert_fp: Option<String>,
    secure: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let started = Instant::now();
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = FramedRead::new(read_half, IrcCodec::new(ctx.max_line));
    let mut writer = FramedWrite::new(write_half, IrcCodec::new(ctx.max_line));

    // D-Line: refuse a banned IP before doing any further work.
    if let Some(reason) = ctx.server.matches_dline(&peer.ip().to_string()) {
        debug!(%peer, "connection rejected: D-Lined");
        let bytes = Line::bare()
            .command("ERROR")
            .trailing(&format!("Closing Link: D-Lined: {reason}"))
            .build();
        let _ = writer.send(bytes).await;
        let _ = writer.close().await;
        return;
    }

    // Connection throttle: reject if this IP already has too many connections.
    if !ctx
        .server
        .try_add_connection(peer.ip(), ctx.max_clients_per_ip)
    {
        debug!(%peer, "connection rejected: per-IP limit reached");
        let bytes = Line::bare()
            .command("ERROR")
            .trailing("Too many connections from your IP")
            .build();
        let _ = writer.send(bytes).await;
        let _ = writer.close().await;
        return;
    }

    Metrics::incr(&ctx.server.metrics.connections_total);

    // Create the client's registry entry and bounded outbound mailbox.
    let id = ctx.server.alloc_id();
    let (entry, rx) = ClientEntry::new(id, peer.ip().to_string(), ctx.sendq_lines);
    entry.data.lock().secure = secure;
    let mut writer_task = tokio::spawn(writer_loop(writer, rx));

    let mut session = Session::new(ctx.server.clone(), entry.clone(), peer, cert_fp);

    let reg_deadline = tokio::time::sleep(ctx.registration_timeout);
    tokio::pin!(reg_deadline);
    let mut bucket = TokenBucket::new(ctx.recv_burst, ctx.recv_rate, started);

    // Idle detection: PING a quiet client, disconnect if it fails to reply.
    let mut ping = tokio::time::interval(ctx.ping_interval);
    ping.tick().await; // consume the immediate first tick
    let mut awaiting_pong = false;

    let reason = loop {
        tokio::select! {
            // Slot guard: a connection that never registers is closed.
            () = &mut reg_deadline, if !session.registered => {
                break "Registration timeout".to_owned();
            }

            // Forced teardown: SendQ overflow, KILL, or K-Line.
            () = entry.kill.notified() => {
                break entry.take_kill_reason().unwrap_or_else(|| "Killed".to_owned());
            }

            // Idle ping / ping-timeout.
            _ = ping.tick() => {
                if awaiting_pong {
                    break "Ping timeout".to_owned();
                }
                if session.registered {
                    entry.send_line(Line::bare().command("PING").trailing(&ctx.server.info.name));
                    awaiting_pong = true;
                }
            }

            frame = reader.next() => {
                let Some(frame) = frame else {
                    break "Connection closed".to_owned();
                };
                let line = match frame {
                    Ok(line) => line,
                    Err(err) => break format!("Input error: {err}"),
                };
                awaiting_pong = false; // any inbound traffic clears the ping wait
                // Inbound rate limit: sustained flooding drops the connection.
                if !bucket.try_consume(Instant::now()) {
                    break "Excess Flood".to_owned();
                }
                match Message::parse_with(&line, &ctx.limits) {
                    Ok(message) => {
                        Metrics::incr(&ctx.server.metrics.commands_total);
                        entry.data.lock().last_active = crate::state::now_unix();
                        session.begin_label(&message);
                        let label = command::metric_label(&message);
                        let started = Instant::now();
                        command::dispatch(&mut session, &message);
                        let micros = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
                        ctx.server.metrics.commands.observe(label, micros);
                        session.end_label();
                    }
                    Err(err) => debug!(%peer, %err, "ignoring malformed line"),
                }
                if let Some(reason) = session.quit.take() {
                    break reason;
                }
            }
        }
    };

    // Attribute the disconnect for metrics.
    match reason.as_str() {
        "SendQ exceeded" => Metrics::incr(&ctx.server.metrics.sendq_drops_total),
        "Excess Flood" => Metrics::incr(&ctx.server.metrics.flood_disconnects_total),
        "Registration timeout" => Metrics::incr(&ctx.server.metrics.registration_timeouts_total),
        _ => {}
    }

    // Withdraw this user from linked peers before local teardown clears state.
    if entry.data.lock().registered {
        ctx.server.withdraw_local(entry.id, &reason);
    }

    // Exactly-once cleanup: leave channels, broadcast QUIT, release the nick,
    // and drop the per-IP connection count.
    ctx.server.disconnect(&entry, &reason);
    ctx.server.remove_connection(peer.ip());

    // Ask the writer to flush queued messages, emit a final ERROR, and close.
    let farewell = Line::bare()
        .command("ERROR")
        .trailing(&format!("Closing link: {reason}"))
        .build();
    entry.close(farewell);
    drop(session);
    // Give the writer a moment to flush; if the socket is wedged (the reason we
    // may be here), abort it rather than hang forever.
    if tokio::time::timeout(Duration::from_secs(2), &mut writer_task)
        .await
        .is_err()
    {
        writer_task.abort();
    }

    info!(%peer, elapsed = ?started.elapsed(), %reason, "connection finished");
}

/// Drain the mailbox to the socket until it closes or a `Close` is processed.
async fn writer_loop<W>(mut writer: FramedWrite<W, IrcCodec>, mut rx: MailboxRx)
where
    W: AsyncWrite + Unpin,
{
    while let Some(message) = rx.recv().await {
        match message {
            Outbound::Line(bytes) => {
                if writer.send(bytes).await.is_err() {
                    break;
                }
            }
            Outbound::Close(bytes) => {
                let _ = writer.send(bytes).await;
                break;
            }
        }
    }
    // Best-effort graceful shutdown (flush + TLS close_notify).
    let _ = writer.close().await;
}
