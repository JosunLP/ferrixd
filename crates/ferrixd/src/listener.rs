//! Listener layer: accept, TLS-terminate, and spawn a task per client.
//!
//! Sockets are bound by the caller and handed in already-bound, so binding
//! failures surface at startup and tests can listen on an ephemeral port.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, info_span, warn, Instrument};

use crate::connection::{self, ConnContext};

/// Accept TLS connections forever, terminating TLS before handing off.
pub async fn run_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    params: ConnContext,
    handshake_timeout: Duration,
) -> Result<()> {
    let addr = listener
        .local_addr()
        .context("reading TLS listener local address")?;
    info!(%addr, "TLS listener accepting");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                // Transient accept errors (e.g. fd exhaustion) must not kill the
                // listener.
                warn!(%addr, %err, "accept failed");
                continue;
            }
        };
        prepare(&stream, peer);

        let acceptor = acceptor.clone();
        let params = params.clone();
        tokio::spawn(async move {
            // A stalled TLS handshake must not pin a task/fd: bound it in time
            // (connection throttling / handshake CPU protection).
            let tls = match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(err)) => {
                    debug!(%peer, %err, "TLS handshake failed");
                    return;
                }
                Err(_elapsed) => {
                    debug!(%peer, "TLS handshake timed out");
                    return;
                }
            };
            // Extract the client certificate fingerprint for SASL EXTERNAL.
            let cert_fp = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(<[_]>::first)
                .map(crate::tls::cert_fingerprint);
            connection::serve(tls, peer, params, cert_fp, true)
                .instrument(info_span!("conn", %peer))
                .await;
        });
    }
}

/// Accept plaintext connections forever. Intended for local testing only; the
/// configuration layer refuses a non-loopback plaintext bind by default.
pub async fn run_plain(listener: TcpListener, params: ConnContext) -> Result<()> {
    let addr = listener
        .local_addr()
        .context("reading plaintext listener local address")?;
    warn!(%addr, "PLAINTEXT listener accepting — traffic on this port is unencrypted");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                warn!(%addr, %err, "accept failed");
                continue;
            }
        };
        prepare(&stream, peer);

        let params = params.clone();
        tokio::spawn(async move {
            connection::serve(stream, peer, params, None, false)
                .instrument(info_span!("conn", %peer))
                .await;
        });
    }
}

/// Common per-socket setup and logging.
fn prepare(stream: &TcpStream, peer: SocketAddr) {
    // Disable Nagle: IRC is latency-sensitive and messages are small.
    if let Err(err) = stream.set_nodelay(true) {
        debug!(%peer, %err, "set_nodelay failed");
    }
    debug!(%peer, "accepted connection");
}
