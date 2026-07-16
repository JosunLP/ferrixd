//! Prometheus-style metrics and a minimal scrape endpoint.
//!
//! Counters are `AtomicU64`s incremented at the relevant sites; gauges (current
//! clients, channels) are read live from the registries at scrape time. The
//! `/metrics` endpoint is a hand-rolled HTTP/1.1 responder — no web framework —
//! so it adds no dependencies.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info};

use crate::state::Server;

/// How long a metrics client has to send its request line before it is dropped
/// (a slow-loris guard: the endpoint must not accumulate silent connections).
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Monotonic server counters.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Total connections accepted (past the per-IP throttle).
    pub connections_total: AtomicU64,
    /// Total commands dispatched.
    pub commands_total: AtomicU64,
    /// Total channel/direct messages relayed.
    pub messages_total: AtomicU64,
    /// Connections closed for SendQ overflow.
    pub sendq_drops_total: AtomicU64,
    /// Connections closed for inbound flooding.
    pub flood_disconnects_total: AtomicU64,
    /// Connections closed for failing to register in time.
    pub registration_timeouts_total: AtomicU64,
}

impl Metrics {
    /// Increment a counter by one.
    pub fn incr(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Render the metrics in the Prometheus text exposition format.
#[must_use]
pub fn render(server: &Server) -> String {
    let m = &server.metrics;
    let mut out = String::with_capacity(1024);
    let mut metric = |name: &str, help: &str, kind: &str, value: u64| {
        let _ = writeln!(out, "# HELP ferrixd_{name} {help}");
        let _ = writeln!(out, "# TYPE ferrixd_{name} {kind}");
        let _ = writeln!(out, "ferrixd_{name} {value}");
    };
    let load = |c: &AtomicU64| c.load(Ordering::Relaxed);

    metric(
        "connections_total",
        "Connections accepted",
        "counter",
        load(&m.connections_total),
    );
    metric(
        "commands_total",
        "Commands dispatched",
        "counter",
        load(&m.commands_total),
    );
    metric(
        "messages_total",
        "Messages relayed",
        "counter",
        load(&m.messages_total),
    );
    metric(
        "sendq_drops_total",
        "SendQ-overflow disconnects",
        "counter",
        load(&m.sendq_drops_total),
    );
    metric(
        "flood_disconnects_total",
        "Excess-flood disconnects",
        "counter",
        load(&m.flood_disconnects_total),
    );
    metric(
        "registration_timeouts_total",
        "Registration-timeout disconnects",
        "counter",
        load(&m.registration_timeouts_total),
    );
    metric(
        "clients",
        "Currently connected clients",
        "gauge",
        server.client_count() as u64,
    );
    metric(
        "channels",
        "Currently existing channels",
        "gauge",
        server.channel_count() as u64,
    );
    out
}

/// Serve the `/metrics` endpoint until the listener fails.
pub async fn serve(addr: SocketAddr, server: Arc<Server>) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding metrics endpoint on {addr}"))?;
    info!(%addr, "metrics endpoint listening");

    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                debug!(%err, "metrics accept failed");
                continue;
            }
        };
        let server = server.clone();
        tokio::spawn(async move {
            // Drain the request line (we serve the same body for any path).
            // A peer that connects and never speaks must not pin a task and an
            // fd forever, so the read is bounded.
            let mut scratch = [0u8; 1024];
            let read = tokio::time::timeout(REQUEST_TIMEOUT, stream.read(&mut scratch)).await;
            if read.is_err() {
                debug!("metrics request timed out before a request line arrived");
                return;
            }
            let body = render(&server);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::casemap::CaseMapping;
    use crate::state::ServerInfo;

    #[test]
    fn render_has_expected_series() {
        let server = Server::new(ServerInfo {
            name: "t".into(),
            sid: "42T".into(),
            network: "n".into(),
            version: "v".into(),
            created: "c".into(),
            casemapping: CaseMapping::Ascii,
            motd: Vec::new(),
            history_len: 10,
            history_max_targets: 1000,
            max_channels: 50,
            cloak_key: None,
            sts: None,
        });
        Metrics::incr(&server.metrics.connections_total);
        let text = render(&server);
        assert!(text.contains("ferrixd_connections_total 1"));
        assert!(text.contains("# TYPE ferrixd_clients gauge"));
        assert!(text.contains("ferrixd_channels 0"));
    }
}
