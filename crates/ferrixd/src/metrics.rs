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
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info};

use crate::state::Server;

/// How long a metrics client has to send its request line before it is dropped
/// (a slow-loris guard: the endpoint must not accumulate silent connections).
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Upper bounds (microseconds) of the per-command latency histogram buckets.
/// Cumulative Prometheus semantics: an observation counts in every bucket whose
/// bound it does not exceed, plus the implicit `+Inf` bucket (== `_count`).
const LATENCY_BUCKETS_US: [u64; 8] = [50, 100, 250, 500, 1_000, 5_000, 25_000, 100_000];

/// The `le` label for each bucket, in seconds (Prometheus base unit).
const LATENCY_BUCKETS_LE: [&str; 8] = [
    "5e-05", "0.0001", "0.00025", "0.0005", "0.001", "0.005", "0.025", "0.1",
];

/// A cumulative latency histogram with fixed buckets (see [`LATENCY_BUCKETS_US`]).
#[derive(Debug)]
pub struct Histogram {
    /// Cumulative bucket counts, aligned with [`LATENCY_BUCKETS_US`].
    buckets: [AtomicU64; 8],
    /// Total number of observations (the `+Inf` bucket).
    count: AtomicU64,
    /// Sum of all observations, in microseconds.
    sum_us: AtomicU64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
        }
    }
}

impl Histogram {
    /// Record one observation of `micros` microseconds.
    fn observe(&self, micros: u64) {
        for (bucket, &bound) in self.buckets.iter().zip(&LATENCY_BUCKETS_US) {
            if micros <= bound {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(micros, Ordering::Relaxed);
    }
}

/// Per-command latency histograms, keyed by an interned command label. The key
/// set is bounded to the known command verbs plus `"other"` (see
/// [`crate::command::metric_label`]), so a client sending arbitrary verbs cannot
/// grow the map without bound.
#[derive(Debug, Default)]
pub struct CommandMetrics {
    per_command: DashMap<&'static str, Histogram>,
}

impl CommandMetrics {
    /// Record that handling `command` took `micros` microseconds.
    pub fn observe(&self, command: &'static str, micros: u64) {
        // The common (warm) path is a shard read lock; only the first sighting
        // of each verb takes the write lock to insert its histogram.
        if let Some(histogram) = self.per_command.get(command) {
            histogram.observe(micros);
        } else {
            self.per_command.entry(command).or_default().observe(micros);
        }
    }
}

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
    /// Per-command handler-latency histograms.
    pub commands: CommandMetrics,
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

    render_command_histogram(&mut out, &m.commands);
    out
}

/// Append the per-command latency histogram in Prometheus text format. Commands
/// are emitted in a stable (sorted) order so scrapes diff cleanly.
fn render_command_histogram(out: &mut String, commands: &CommandMetrics) {
    let _ = writeln!(
        out,
        "# HELP ferrixd_command_duration_seconds Command handler latency by command"
    );
    let _ = writeln!(out, "# TYPE ferrixd_command_duration_seconds histogram");

    let mut labels: Vec<&'static str> = commands
        .per_command
        .iter()
        .map(|entry| *entry.key())
        .collect();
    labels.sort_unstable();

    for label in labels {
        let Some(histogram) = commands.per_command.get(label) else {
            continue;
        };
        for (bucket, le) in histogram.buckets.iter().zip(&LATENCY_BUCKETS_LE) {
            let _ = writeln!(
                out,
                "ferrixd_command_duration_seconds_bucket{{command=\"{label}\",le=\"{le}\"}} {}",
                bucket.load(Ordering::Relaxed)
            );
        }
        let count = histogram.count.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "ferrixd_command_duration_seconds_bucket{{command=\"{label}\",le=\"+Inf\"}} {count}"
        );
        // Microsecond sum rendered as seconds (Prometheus base unit).
        let sum_us = histogram.sum_us.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "ferrixd_command_duration_seconds_sum{{command=\"{label}\"}} {:.6}",
            sum_us as f64 / 1_000_000.0
        );
        let _ = writeln!(
            out,
            "ferrixd_command_duration_seconds_count{{command=\"{label}\"}} {count}"
        );
    }
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
            icon: None,
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

    #[test]
    fn command_histogram_is_cumulative_and_bounded() {
        let commands = CommandMetrics::default();
        commands.observe("JOIN", 30); // first bucket (<= 50us)
        commands.observe("JOIN", 700); // <= 1000us
                                       // An unknown verb must have been interned to "other" by the caller; the
                                       // histogram itself just stores whatever static label it is handed.
        commands.observe("other", 200_000); // beyond the last finite bucket

        let mut out = String::new();
        render_command_histogram(&mut out, &commands);

        // Cumulative: the <=0.001 bucket for JOIN counts both JOIN samples.
        assert!(out
            .contains("ferrixd_command_duration_seconds_bucket{command=\"JOIN\",le=\"0.001\"} 2"));
        // The smallest bucket only counts the 30us sample.
        assert!(out
            .contains("ferrixd_command_duration_seconds_bucket{command=\"JOIN\",le=\"5e-05\"} 1"));
        assert!(out.contains("ferrixd_command_duration_seconds_count{command=\"JOIN\"} 2"));
        // The over-range sample lands only in +Inf, not any finite bucket.
        assert!(
            out.contains("ferrixd_command_duration_seconds_bucket{command=\"other\",le=\"0.1\"} 0")
        );
        assert!(out
            .contains("ferrixd_command_duration_seconds_bucket{command=\"other\",le=\"+Inf\"} 1"));
        assert!(out.contains("# TYPE ferrixd_command_duration_seconds histogram"));
    }
}
