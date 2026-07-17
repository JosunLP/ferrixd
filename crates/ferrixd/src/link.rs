//! S2S link transport.
//!
//! Establishes authenticated TLS links (certificate-fingerprint pinning +
//! `PASS`/`SERVER` handshake), then runs a full-duplex link: a writer task
//! drains a mailbox to the peer, while the read loop applies inbound network
//! state — user introductions ([`LinkMessage::Uid`]), quits, and relayed
//! messages ([`LinkMessage::UserMessage`]). On link-up we burst our local users
//! to the peer; local user register/quit events are propagated by
//! [`crate::state::Server`].

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use ferrix_protocol::Message;
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};

use crate::codec::IrcCodec;
use crate::config::{LinkConfig, LinkProtocol};
use crate::s2s::LinkMessage;
use crate::state::{now_unix, LinkHandle, MemberPrefix, RemoteServer, RemoteUser, Server};
use crate::ts6::{self, Ts6In, UidMapper};
use crate::wire::Line;

const LINK_MAX_LINE: usize = 16_384;
const RECONNECT_DELAY: Duration = Duration::from_secs(30);
const LINK_SENDQ: usize = 4096;

/// Attempt a single outbound link to `peer` (operator `CONNECT`). Unlike
/// [`run_outbound`], it makes exactly one attempt and returns its result rather
/// than looping — so a manual `CONNECT` does not spawn a competing reconnect
/// loop alongside any config-driven one.
///
/// # Errors
///
/// Returns an error if the peer has no connect address or the attempt fails.
pub async fn connect_now(
    peer: LinkConfig,
    server: Arc<Server>,
    client_config: Arc<rustls::ClientConfig>,
) -> Result<()> {
    let Some(addr) = peer.connect else {
        bail!("link {} has no connect address (accept-only)", peer.name);
    };
    connect_once(&peer, addr, &server, &client_config).await
}

/// Keep an outbound link to `peer` up, reconnecting on failure.
pub async fn run_outbound(
    peer: LinkConfig,
    server: Arc<Server>,
    client_config: Arc<rustls::ClientConfig>,
) {
    let Some(addr) = peer.connect else {
        return; // accept-only link
    };
    loop {
        match connect_once(&peer, addr, &server, &client_config).await {
            Ok(()) => info!(peer = %peer.name, "S2S link closed"),
            Err(err) => warn!(peer = %peer.name, %err, "S2S link error"),
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

async fn connect_once(
    peer: &LinkConfig,
    addr: SocketAddr,
    server: &Arc<Server>,
    client_config: &Arc<rustls::ClientConfig>,
) -> Result<()> {
    let tcp = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting to peer {addr}"))?;
    let connector = TlsConnector::from(client_config.clone());
    let domain = rustls::pki_types::ServerName::try_from("ferrixd-link")
        .map_err(|e| anyhow::anyhow!("invalid link server name: {e}"))?;
    let tls = connector
        .connect(domain, tcp)
        .await
        .context("TLS handshake")?;

    let fingerprint = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(<[_]>::first)
        .map(crate::tls::cert_fingerprint);
    if fingerprint.as_deref() != Some(peer.fingerprint.as_str()) {
        bail!("peer certificate fingerprint does not match the pinned value");
    }

    match peer.protocol {
        LinkProtocol::Ferrix => establish(tls, &peer.password, &peer.name, server).await,
        LinkProtocol::Ts6 => establish_ts6(tls, &peer.password, &peer.name, server).await,
    }
}

/// Accept inbound links, matching each by its client-certificate fingerprint.
/// The acceptor is rebuilt per connection from `tls`, so a `REHASH` certificate
/// swap applies to new links too.
pub async fn run_link_listener(
    listener: TcpListener,
    tls: Arc<crate::tls::SharedServerTls>,
    server: Arc<Server>,
    links: Vec<LinkConfig>,
) -> Result<()> {
    let addr = listener
        .local_addr()
        .context("reading link listener address")?;
    info!(%addr, "S2S link listener accepting");
    let links = Arc::new(links);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                warn!(%addr, %err, "link accept failed");
                continue;
            }
        };
        let acceptor = tls.acceptor();
        let server = server.clone();
        let links = links.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(err) => {
                    debug!(%peer, %err, "link TLS handshake failed");
                    return;
                }
            };
            let fingerprint = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(<[_]>::first)
                .map(crate::tls::cert_fingerprint);
            let Some(fingerprint) = fingerprint else {
                warn!(%peer, "inbound link presented no certificate");
                return;
            };
            let Some(link) = links.iter().find(|l| l.fingerprint == fingerprint) else {
                warn!(%peer, "inbound link certificate is not a configured peer");
                return;
            };
            let result = match link.protocol {
                LinkProtocol::Ferrix => establish(tls, &link.password, &link.name, &server).await,
                LinkProtocol::Ts6 => establish_ts6(tls, &link.password, &link.name, &server).await,
            };
            if let Err(err) = result {
                warn!(peer = %link.name, %err, "inbound S2S link error");
            }
        });
    }
}

/// Run the handshake, register the link, burst, then drive it until it drops.
async fn establish<S>(
    stream: S,
    token: &str,
    expected_peer: &str,
    server: &Arc<Server>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (rd, wr) = tokio::io::split(stream);
    let mut reader = FramedRead::new(rd, IrcCodec::new(LINK_MAX_LINE));
    let mut writer = FramedWrite::new(wr, IrcCodec::new(LINK_MAX_LINE));

    writer
        .send(
            LinkMessage::Pass {
                token: token.to_owned(),
            }
            .to_line(),
        )
        .await?;
    writer
        .send(
            LinkMessage::Server {
                name: server.info.name.clone(),
                sid: server.info.sid.clone(),
                description: server.info.network.clone(),
            }
            .to_line(),
        )
        .await?;

    let LinkMessage::Pass { token: peer_token } = next_message(&mut reader).await? else {
        bail!("expected PASS from peer");
    };
    if !crate::s2s::tokens_match(&peer_token, token) {
        let _ = writer
            .send(
                LinkMessage::Error {
                    reason: "Bad link password".to_owned(),
                }
                .to_line(),
            )
            .await;
        bail!("link password mismatch");
    }
    let LinkMessage::Server {
        name,
        sid,
        description,
    } = next_message(&mut reader).await?
    else {
        bail!("expected SERVER from peer");
    };
    if name != expected_peer {
        bail!("peer announced unexpected server name {name:?}");
    }

    // Loop prevention: refuse the link if this server (or its name) is already
    // in the network via another path — the network must stay a tree.
    let (tx, rx) = mpsc::channel::<Bytes>(LINK_SENDQ);
    let handle = LinkHandle::new(sid.clone(), name.clone(), description, tx);
    if let Err(reason) = server.try_register_link(handle.clone()) {
        let _ = writer
            .send(
                LinkMessage::Error {
                    reason: reason.clone(),
                }
                .to_line(),
            )
            .await;
        bail!("link refused: {reason}");
    }
    info!(peer = %name, sid = %sid, "S2S link established");

    // Full-duplex: a writer task drains the mailbox; announce + burst; read loop.
    let shutdown = handle.shutdown_signal();
    tokio::spawn(link_writer(writer, rx));
    server.announce_link_to_others(&handle);
    server.burst_to_peer(&sid);

    let result = read_loop(&mut reader, &sid, server, &shutdown).await;
    server.drop_link(&sid);
    info!(peer = %name, "S2S link down");
    result
}

/// Apply inbound link messages to network state until the link closes or a local
/// `SQUIT` fires `shutdown`.
async fn read_loop<R>(
    reader: &mut FramedRead<R, IrcCodec>,
    peer_sid: &str,
    server: &Arc<Server>,
    shutdown: &tokio::sync::Notify,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = tokio::select! {
            biased;
            () = shutdown.notified() => {
                info!(%peer_sid, "link closed by local SQUIT");
                return Ok(());
            }
            frame = reader.next() => frame,
        };
        let Some(frame) = frame else {
            return Ok(());
        };
        let frame = frame?;
        let Ok(parsed) = Message::parse(&frame) else {
            continue;
        };
        let Some(link_msg) = LinkMessage::from_message(&parsed) else {
            debug!("unhandled link message");
            continue;
        };
        // Serialized copy for multi-hop forwarding: state changes applied from
        // this link are re-announced down every OTHER link (loop-free on a
        // link tree), so servers more than one hop away stay in sync.
        let raw = link_msg.to_line();
        match link_msg {
            LinkMessage::Uid {
                sid,
                uid,
                nick,
                user,
                host,
                account,
                realname,
                ..
            } => {
                // Origin enforcement: the uid must belong to the claimed SID, and
                // this peer must be authorised to route that SID (first announcer
                // wins; our own SID is never accepted). Otherwise a peer could
                // inject users attributed to another server — or to us.
                if !uid.starts_with(&sid) || !server.route_authorize(peer_sid, &sid) {
                    warn!(%peer_sid, %sid, %uid, "rejecting UID with unauthorised origin");
                    continue;
                }
                match server.accept_remote_user(RemoteUser {
                    server_sid: sid,
                    uid,
                    nick,
                    user,
                    host,
                    account: (account != "*").then_some(account),
                    realname,
                    away: None,
                    oper: false,
                    invisible: false,
                    bot: false,
                }) {
                    Some(kill) => {
                        // The incoming user lost a collision: reject it at its
                        // origin instead of forwarding the introduction.
                        server.send_to_link(peer_sid, kill.to_line());
                    }
                    None => server.forward_to_links(peer_sid, &raw),
                }
            }
            LinkMessage::Kill { uid, reason } => {
                // A peer may KILL a user it routes; a uid in our own namespace is
                // the legitimate cross-server (network) KILL path.
                if server.owns_local_uid(&uid) {
                    server.kill_by_uid(&uid, &reason);
                } else if server.remote_uid_authorized(peer_sid, &uid) {
                    server.kill_by_uid(&uid, &reason);
                    server.forward_to_links(peer_sid, &raw);
                } else if let Some(victim) = server.remote_user_by_uid(&uid) {
                    // An oper KILL travelling *towards* the victim's server
                    // (issued elsewhere in the tree): pass it along the route.
                    // The owner disconnects the client and the resulting QUIT
                    // purges everyone's bookkeeping on the way back.
                    server.send_towards(&victim.server_sid, raw.clone());
                } else {
                    warn!(%peer_sid, %uid, "rejecting KILL with unauthorised origin");
                }
            }
            LinkMessage::Nick { uid, nick } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    match server.remote_nick_change(&uid, &nick) {
                        Some(kill) => {
                            // The renamer lost a collision: kill it at its origin.
                            server.send_to_link(peer_sid, kill.to_line());
                        }
                        None => server.forward_to_links(peer_sid, &raw),
                    }
                } else {
                    warn!(%peer_sid, %uid, "rejecting NICK with unauthorised origin");
                }
            }
            LinkMessage::Quit { uid, reason } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    server.remote_quit(&uid, &reason);
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %uid, "rejecting QUIT with unauthorised origin");
                }
            }
            LinkMessage::UserMessage {
                source,
                target,
                notice,
                msgid,
                time_ms,
                tags,
                text,
            } => {
                if server.remote_source_authorized(peer_sid, &source) {
                    // Delivers locally, or forwards towards the target's server.
                    server.deliver_remote_message(
                        &source, &target, notice, msgid, time_ms, tags, &text,
                    );
                } else {
                    warn!(%peer_sid, %source, "rejecting relayed DM with forged source");
                }
            }
            LinkMessage::TagMessage {
                source,
                target,
                tags,
            } => {
                if server.remote_source_authorized(peer_sid, &source) {
                    // Delivers locally and relays onward (channel) or routes to
                    // the target's server (user).
                    server.deliver_tagmsg(peer_sid, &source, &target, &tags);
                } else {
                    warn!(%peer_sid, %source, "rejecting relayed TAGMSG with forged source");
                }
            }
            LinkMessage::Sjoin {
                channel,
                uid,
                op,
                voice,
                ts,
            } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    server.remote_join(&channel, &uid, MemberPrefix { op, voice }, ts);
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %uid, "rejecting SJOIN with unauthorised origin");
                }
            }
            LinkMessage::Spart {
                channel,
                uid,
                reason,
            } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    server.remote_part(&channel, &uid, &reason);
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %uid, "rejecting SPART with unauthorised origin");
                }
            }
            LinkMessage::ChanMessage {
                source,
                channel,
                notice,
                msgid,
                time_ms,
                tags,
                text,
            } => {
                if server.remote_source_authorized(peer_sid, &source) {
                    // Delivers locally and relays to other peers with members.
                    server.deliver_channel_message(
                        peer_sid, &source, &channel, notice, msgid, time_ms, tags, &text,
                    );
                } else {
                    warn!(%peer_sid, %source, "rejecting relayed channel message with forged source");
                }
            }
            LinkMessage::Stopic {
                channel,
                source,
                set_by,
                set_at,
                text,
            } => {
                if link_source_authorized(server, peer_sid, &source) {
                    server.remote_topic(&channel, &source, &set_by, set_at, &text);
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %source, "rejecting STOPIC with unauthorised origin");
                }
            }
            LinkMessage::Smode {
                channel,
                source,
                ts,
                flags,
                args,
            } => {
                if link_source_authorized(server, peer_sid, &source) {
                    server.remote_mode(&channel, &source, ts, &flags, &args);
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %source, "rejecting SMODE with unauthorised origin");
                }
            }
            LinkMessage::Skick {
                channel,
                source,
                target,
                reason,
            } => {
                if link_source_authorized(server, peer_sid, &source) {
                    server.remote_kick(&channel, &source, &target, &reason);
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %source, "rejecting SKICK with unauthorised origin");
                }
            }
            LinkMessage::Saway { uid, reason } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    server.remote_away(&uid, reason.as_deref());
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %uid, "rejecting SAWAY with unauthorised origin");
                }
            }
            LinkMessage::Saccount { uid, account } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    server.remote_account(&uid, (account != "*").then_some(account.as_str()));
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %uid, "rejecting SACCOUNT with unauthorised origin");
                }
            }
            LinkMessage::Ssetname { uid, realname } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    server.remote_setname(&uid, &realname);
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %uid, "rejecting SSETNAME with unauthorised origin");
                }
            }
            LinkMessage::Schghost { uid, host } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    server.remote_chghost(&uid, &host);
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %uid, "rejecting SCHGHOST with unauthorised origin");
                }
            }
            LinkMessage::Swallops { source, text } => {
                // Operator broadcasts are trusted network-wide (like KILL); the
                // source is a display prefix, not a forgeable local user.
                server.remote_wallops(&source, &text);
                server.forward_to_links(peer_sid, &raw);
            }
            LinkMessage::Sinvite {
                source,
                target,
                channel,
            } => {
                if source == "*" {
                    // Burst form: an invitation that was already pending on the
                    // peer. `target` is a folded nick, and nobody is notified —
                    // this only restores the `+i` bypass.
                    server.remote_invite_pending(&target, &channel);
                    server.forward_to_links(peer_sid, &raw);
                } else if !server.remote_uid_authorized(peer_sid, &source) {
                    warn!(%peer_sid, %source, "rejecting SINVITE with unauthorised origin");
                } else if server.owns_local_uid(&target) {
                    server.remote_invite(&source, &target, &channel);
                } else if let Some(user) = server.remote_user_by_uid(&target) {
                    // Not ours: pass it along the route towards the target.
                    server.send_towards(&user.server_sid, raw.clone());
                }
            }
            LinkMessage::Sumode { uid, flags } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    server.remote_umode(&uid, &flags);
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %uid, "rejecting SUMODE with unauthorised origin");
                }
            }
            LinkMessage::Sknock {
                source,
                channel,
                mask,
            } => {
                if server.remote_uid_authorized(peer_sid, &source) {
                    server.remote_knock(&channel, &mask);
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %source, "rejecting SKNOCK with unauthorised origin");
                }
            }
            LinkMessage::Sredact {
                source,
                target,
                msgid,
                reason,
            } => {
                if link_source_authorized(server, peer_sid, &source) {
                    server.remote_redact(&source, &target, &msgid, &reason);
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %source, "rejecting SREDACT with unauthorised origin");
                }
            }
            LinkMessage::Srename {
                source,
                old,
                new,
                reason,
            } => {
                if link_source_authorized(server, peer_sid, &source) {
                    server.remote_rename(&source, &old, &new, &reason);
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %source, "rejecting SRENAME with unauthorised origin");
                }
            }
            LinkMessage::Sban {
                add,
                mask,
                set_by,
                reason,
            } => {
                // Network bans are trusted network-wide and flooded to every
                // server (same trust model as KILL/WALLOPS).
                server.remote_gline(add, &mask, &set_by, &reason);
                server.forward_to_links(peer_sid, &raw);
            }
            LinkMessage::Sserver {
                name,
                sid,
                uplink,
                description,
            } => {
                // A topology introduction. If the announced server is already
                // known through another path, this link closes a cycle: refuse
                // it and drop the link (the network must stay a tree).
                match server.accept_remote_server(
                    peer_sid,
                    crate::state::RemoteServer {
                        sid,
                        name,
                        uplink,
                        description,
                    },
                ) {
                    Ok(()) => server.forward_to_links(peer_sid, &raw),
                    Err(reason) => {
                        warn!(%peer_sid, %reason, "dropping link: topology cycle detected");
                        server.send_to_link(peer_sid, LinkMessage::Error { reason }.to_line());
                        break;
                    }
                }
            }
            LinkMessage::Ping { token } => {
                server.send_to_link(peer_sid, LinkMessage::Pong { token }.to_line());
            }
            LinkMessage::Squit { sid, reason } => {
                if sid == peer_sid {
                    // The peer itself is going down: the whole link drops (and
                    // `drop_link` splits everything behind it).
                    info!(%sid, %reason, "peer SQUIT");
                    break;
                }
                // A server further away split: drop just that subtree, and let
                // the rest of the network do the same.
                if server.route_owner(&sid).as_deref() == Some(peer_sid) {
                    info!(%sid, %reason, "downstream SQUIT");
                    server.split_remote_server(&sid, "*.net *.split");
                    server.forward_to_links(peer_sid, &raw);
                } else {
                    warn!(%peer_sid, %sid, "rejecting SQUIT with unauthorised origin");
                }
            }
            LinkMessage::Error { reason } => {
                warn!(%reason, "peer link error");
                break;
            }
            other => debug!(?other, "unhandled link message"),
        }
    }
    Ok(())
}

/// Whether `source` (an acting user's uid, or `*` for the peer server itself,
/// e.g. during a burst) is a legitimate origin for state arriving on the link
/// from `peer_sid`.
fn link_source_authorized(server: &Server, peer_sid: &str, source: &str) -> bool {
    source == "*" || server.remote_uid_authorized(peer_sid, source)
}

/// Drain the mailbox to the link socket.
async fn link_writer<W>(mut writer: FramedWrite<W, IrcCodec>, mut rx: mpsc::Receiver<Bytes>)
where
    W: AsyncWrite + Unpin,
{
    while let Some(bytes) = rx.recv().await {
        if writer.send(bytes).await.is_err() {
            break;
        }
    }
    let _ = writer.close().await;
}

/// Read and decode the next [`LinkMessage`] (used during the handshake).
async fn next_message<R>(reader: &mut FramedRead<R, IrcCodec>) -> Result<LinkMessage>
where
    R: AsyncRead + Unpin,
{
    let frame = reader
        .next()
        .await
        .context("link closed during handshake")??;
    let parsed = Message::parse(&frame).map_err(|e| anyhow::anyhow!("malformed link line: {e}"))?;
    LinkMessage::from_message(&parsed).context("unrecognised link message")
}

// ---------------------------------------------------------------------------
// TS6 bridge transport (see `crate::ts6` for the grammar and translation).
// ---------------------------------------------------------------------------

/// Shared per-link TS6 state: the UID alias table (used by both directions)
/// and the peer's negotiated CAPAB set (used by the writer).
#[derive(Clone)]
struct Ts6Ctx {
    mapper: Arc<Mutex<UidMapper>>,
    caps: Arc<HashSet<String>>,
}

/// Cap on handshake lines before we give up (a TS6 peer sends 4–5).
const TS6_HANDSHAKE_MAX_LINES: usize = 32;

/// Run the TS6 handshake, register the link, burst, then drive it until it
/// drops. The peer is authenticated by TLS certificate pin (checked by the
/// caller) plus the link password carried in `PASS … TS 6`.
async fn establish_ts6<S>(
    stream: S,
    token: &str,
    expected_peer: &str,
    server: &Arc<Server>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    if !ts6::valid_sid(&server.info.sid) {
        bail!(
            "our SID {:?} is not TS6-shaped ([0-9][A-Z0-9][A-Z0-9]); cannot bridge",
            server.info.sid
        );
    }
    let (rd, wr) = tokio::io::split(stream);
    let mut reader = FramedRead::new(rd, IrcCodec::new(LINK_MAX_LINE));
    let mut writer = FramedWrite::new(wr, IrcCodec::new(LINK_MAX_LINE));

    // Both ends send eagerly: PASS, CAPAB, SERVER, then SVINFO after the
    // peer's identity checks out.
    writer
        .send(
            Line::bare()
                .command("PASS")
                .param(token)
                .param("TS")
                .param("6")
                .trailing(&server.info.sid)
                .build(),
        )
        .await?;
    writer
        .send(
            Line::bare()
                .command("CAPAB")
                .trailing(ts6::OUR_CAPAB)
                .build(),
        )
        .await?;
    writer
        .send(
            Line::bare()
                .command("SERVER")
                .param(&server.info.name)
                .param("1")
                .trailing(&server.info.network)
                .build(),
        )
        .await?;

    let mut peer_caps: HashSet<String> = HashSet::new();
    let mut peer_sid: Option<String> = None;
    let mut peer_name: Option<String> = None;
    let mut peer_desc = String::new();
    let mut lines = 0_usize;
    while peer_sid.is_none() || peer_name.is_none() {
        lines += 1;
        if lines > TS6_HANDSHAKE_MAX_LINES {
            bail!("peer never completed the TS6 handshake");
        }
        let frame = reader
            .next()
            .await
            .context("link closed during TS6 handshake")??;
        let Ok(parsed) = Message::parse(&frame) else {
            continue;
        };
        match ts6::parse_ts6(&parsed) {
            Ts6In::Pass { password, sid } => {
                if !crate::s2s::tokens_match(&password, token) {
                    let _ = writer
                        .send(
                            Line::bare()
                                .command("ERROR")
                                .trailing("Bad link password")
                                .build(),
                        )
                        .await;
                    bail!("TS6 link password mismatch");
                }
                if !ts6::valid_sid(&sid) {
                    bail!("peer announced malformed SID {sid:?}");
                }
                peer_sid = Some(sid);
            }
            Ts6In::Capab { caps } => peer_caps.extend(caps),
            Ts6In::Server { name, description } => {
                if name != expected_peer {
                    bail!("peer announced unexpected server name {name:?}");
                }
                peer_desc = description;
                peer_name = Some(name);
            }
            Ts6In::Svinfo { max, .. } => {
                if max < 6 {
                    bail!("peer only speaks TS{max}, need TS6");
                }
            }
            Ts6In::Error { reason } => bail!("peer error during TS6 handshake: {reason}"),
            _ => {}
        }
    }
    let (Some(sid), Some(name)) = (peer_sid, peer_name) else {
        bail!("TS6 handshake incomplete");
    };
    writer
        .send(
            Line::bare()
                .command("SVINFO")
                .param("6")
                .param("6")
                .param("0")
                .trailing(&now_unix().to_string())
                .build(),
        )
        .await?;

    // Loop prevention applies to bridged links too: the network stays a tree.
    let (tx, rx) = mpsc::channel::<Bytes>(LINK_SENDQ);
    let handle = LinkHandle::new(sid.clone(), name.clone(), peer_desc, tx);
    if let Err(reason) = server.try_register_link(handle.clone()) {
        let _ = writer
            .send(Line::bare().command("ERROR").trailing(&reason).build())
            .await;
        bail!("link refused: {reason}");
    }
    info!(peer = %name, sid = %sid, "TS6 link established");

    let ctx = Ts6Ctx {
        mapper: Arc::new(Mutex::new(UidMapper::default())),
        caps: Arc::new(peer_caps),
    };
    tokio::spawn(ts6_link_writer(writer, rx, server.clone(), ctx.clone()));
    server.announce_link_to_others(&handle);
    server.burst_to_peer(&sid);
    // End-of-burst marker: TS6 peers use the post-burst PING as the boundary.
    server.send_to_link(
        &sid,
        LinkMessage::Ping {
            token: server.info.name.clone(),
        }
        .to_line(),
    );

    let shutdown = handle.shutdown_signal();
    let result = ts6_read_loop(&mut reader, &sid, server, &ctx, &shutdown).await;
    server.drop_link(&sid);
    info!(peer = %name, "TS6 link down");
    result
}

/// Drain the mailbox to a TS6 peer: each queued native line is decoded and
/// re-encoded as TS6. The mailbox carries the exact same lines a ferrix peer
/// would receive, so every state producer stays protocol-agnostic.
async fn ts6_link_writer<W>(
    mut writer: FramedWrite<W, IrcCodec>,
    mut rx: mpsc::Receiver<Bytes>,
    server: Arc<Server>,
    ctx: Ts6Ctx,
) where
    W: AsyncWrite + Unpin,
{
    while let Some(bytes) = rx.recv().await {
        let body = &bytes[..bytes.len().saturating_sub(2)]; // strip CRLF
        let Ok(parsed) = Message::parse(body) else {
            continue;
        };
        let Some(msg) = LinkMessage::from_message(&parsed) else {
            continue;
        };
        let lines = {
            let mut mapper = ctx.mapper.lock();
            ts6::encode_outbound(&msg, &server, &mut mapper, &ctx.caps)
        };
        for line in lines {
            if writer.send(line).await.is_err() {
                return;
            }
        }
    }
    let _ = writer.close().await;
}

/// Apply inbound TS6 messages to network state until the link closes,
/// forwarding each accepted change to other links re-encoded as native
/// [`LinkMessage`]s (multi-hop stays in sync across the bridge).
#[allow(clippy::too_many_lines)]
async fn ts6_read_loop<R>(
    reader: &mut FramedRead<R, IrcCodec>,
    peer_sid: &str,
    server: &Arc<Server>,
    ctx: &Ts6Ctx,
    shutdown: &tokio::sync::Notify,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = tokio::select! {
            biased;
            () = shutdown.notified() => {
                info!(%peer_sid, "TS6 link closed by local SQUIT");
                return Ok(());
            }
            frame = reader.next() => frame,
        };
        let Some(frame) = frame else {
            return Ok(());
        };
        let frame = frame?;
        let Ok(parsed) = Message::parse(&frame) else {
            continue;
        };
        match ts6::parse_ts6(&parsed) {
            Ts6In::Sid {
                name,
                sid,
                uplink,
                description,
            } => {
                let uplink = uplink.unwrap_or_else(|| peer_sid.to_owned());
                match server.accept_remote_server(
                    peer_sid,
                    RemoteServer {
                        sid: sid.clone(),
                        name: name.clone(),
                        uplink: uplink.clone(),
                        description: description.clone(),
                    },
                ) {
                    Ok(()) => server.forward_to_links(
                        peer_sid,
                        &LinkMessage::Sserver {
                            name,
                            sid,
                            uplink,
                            description,
                        }
                        .to_line(),
                    ),
                    Err(reason) => {
                        warn!(%peer_sid, %reason, "dropping TS6 link: topology cycle detected");
                        server.send_to_link(peer_sid, LinkMessage::Error { reason }.to_line());
                        break;
                    }
                }
            }
            Ts6In::Euid {
                sid,
                uid,
                nick,
                user,
                host,
                account,
                realname,
            } => {
                let sid = sid.unwrap_or_else(|| peer_sid.to_owned());
                // Same origin enforcement as native links: the uid must sit in
                // the claimed SID's namespace, routed via this peer.
                if !uid.starts_with(&sid) || !server.route_authorize(peer_sid, &sid) {
                    warn!(%peer_sid, %sid, %uid, "rejecting EUID with unauthorised origin");
                    continue;
                }
                let fwd = LinkMessage::Uid {
                    sid: sid.clone(),
                    uid: uid.clone(),
                    lamport: 0,
                    nick: nick.clone(),
                    user: user.clone(),
                    host: host.clone(),
                    account: account.clone().unwrap_or_else(|| "*".to_owned()),
                    realname: realname.clone(),
                }
                .to_line();
                match server.accept_remote_user(RemoteUser {
                    server_sid: sid,
                    uid,
                    nick,
                    user,
                    host,
                    account,
                    realname,
                    away: None,
                    oper: false,
                    invisible: false,
                    bot: false,
                }) {
                    Some(kill) => {
                        server.send_to_link(peer_sid, kill.to_line());
                    }
                    None => server.forward_to_links(peer_sid, &fwd),
                }
            }
            Ts6In::Nick { uid, nick } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    match server.remote_nick_change(&uid, &nick) {
                        Some(kill) => {
                            server.send_to_link(peer_sid, kill.to_line());
                        }
                        None => server
                            .forward_to_links(peer_sid, &LinkMessage::Nick { uid, nick }.to_line()),
                    }
                } else {
                    warn!(%peer_sid, %uid, "rejecting NICK with unauthorised origin");
                }
            }
            Ts6In::Quit { uid, reason } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    server.remote_quit(&uid, &reason);
                    server.forward_to_links(peer_sid, &LinkMessage::Quit { uid, reason }.to_line());
                }
            }
            Ts6In::Sjoin {
                channel,
                ts,
                members,
                flags,
                args,
            } => {
                for (uid, prefix) in members {
                    if !server.remote_uid_authorized(peer_sid, &uid) {
                        warn!(%peer_sid, %uid, "rejecting SJOIN member with unauthorised origin");
                        continue;
                    }
                    let (op, voice) = (prefix.op, prefix.voice);
                    server.remote_join(&channel, &uid, prefix, ts);
                    server.forward_to_links(
                        peer_sid,
                        &LinkMessage::Sjoin {
                            channel: channel.clone(),
                            uid,
                            op,
                            voice,
                            ts,
                        }
                        .to_line(),
                    );
                }
                if flags.len() > 1 {
                    let args = {
                        let mapper = ctx.mapper.lock();
                        ts6::mode_args_to_ferrix(&flags, &args, &mapper)
                    };
                    server.remote_mode(&channel, "*", ts, &flags, &args);
                    server.forward_to_links(
                        peer_sid,
                        &LinkMessage::Smode {
                            channel,
                            source: "*".to_owned(),
                            ts,
                            flags,
                            args,
                        }
                        .to_line(),
                    );
                }
            }
            Ts6In::Join { uid, channel, ts } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    server.remote_join(&channel, &uid, MemberPrefix::default(), ts);
                    server.forward_to_links(
                        peer_sid,
                        &LinkMessage::Sjoin {
                            channel,
                            uid,
                            op: false,
                            voice: false,
                            ts,
                        }
                        .to_line(),
                    );
                } else {
                    warn!(%peer_sid, %uid, "rejecting JOIN with unauthorised origin");
                }
            }
            Ts6In::Part {
                uid,
                channels,
                reason,
            } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    for channel in channels.split(',').filter(|c| !c.is_empty()) {
                        server.remote_part(channel, &uid, &reason);
                        server.forward_to_links(
                            peer_sid,
                            &LinkMessage::Spart {
                                channel: channel.to_owned(),
                                uid: uid.clone(),
                                reason: reason.clone(),
                            }
                            .to_line(),
                        );
                    }
                }
            }
            Ts6In::Msg {
                source,
                target,
                notice,
                text,
            } => {
                if !server.remote_uid_authorized(peer_sid, &source) {
                    warn!(%peer_sid, %source, "rejecting message with unauthorised origin");
                    continue;
                }
                let mask = server.remote_source_mask(&source);
                if target.starts_with('#') || target.starts_with('&') {
                    // Delivers locally and relays to other peers with members.
                    // TS6 carries no msgid/time; each server mints its own.
                    server.deliver_channel_message(
                        peer_sid, &mask, &target, notice, None, None, None, &text,
                    );
                } else {
                    // The target may be one of our aliased UIDs, a native UID,
                    // or (services convenience) a bare nick.
                    let ferrix_target = ctx.mapper.lock().to_ferrix(&target);
                    let target_nick = server.nick_of_uid(&ferrix_target).unwrap_or(target);
                    server.deliver_remote_message(
                        &mask,
                        &target_nick,
                        notice,
                        None,
                        None,
                        None,
                        &text,
                    );
                }
            }
            Ts6In::Tmode {
                source,
                channel,
                ts,
                flags,
                args,
            } => {
                let (authorized, state_source) = ts6_actor(server, peer_sid, &source);
                if !authorized {
                    warn!(%peer_sid, %source, "rejecting TMODE with unauthorised origin");
                    continue;
                }
                let args = {
                    let mapper = ctx.mapper.lock();
                    ts6::mode_args_to_ferrix(&flags, &args, &mapper)
                };
                server.remote_mode(&channel, &state_source, ts, &flags, &args);
                server.forward_to_links(
                    peer_sid,
                    &LinkMessage::Smode {
                        channel,
                        source: state_source,
                        ts,
                        flags,
                        args,
                    }
                    .to_line(),
                );
            }
            Ts6In::Kick {
                source,
                channel,
                target,
                reason,
            } => {
                let (authorized, state_source) = ts6_actor(server, peer_sid, &source);
                if !authorized {
                    warn!(%peer_sid, %source, "rejecting KICK with unauthorised origin");
                    continue;
                }
                let target = ctx.mapper.lock().to_ferrix(&target);
                server.remote_kick(&channel, &state_source, &target, &reason);
                server.forward_to_links(
                    peer_sid,
                    &LinkMessage::Skick {
                        channel,
                        source: state_source,
                        target,
                        reason,
                    }
                    .to_line(),
                );
            }
            Ts6In::Topic {
                source,
                channel,
                text,
            } => {
                if !server.remote_uid_authorized(peer_sid, &source) {
                    warn!(%peer_sid, %source, "rejecting TOPIC with unauthorised origin");
                    continue;
                }
                let set_by = server
                    .nick_of_uid(&source)
                    .unwrap_or_else(|| source.clone());
                let set_at = now_unix();
                server.remote_topic(&channel, &source, &set_by, set_at, &text);
                server.forward_to_links(
                    peer_sid,
                    &LinkMessage::Stopic {
                        channel,
                        source,
                        set_by,
                        set_at,
                        text,
                    }
                    .to_line(),
                );
            }
            Ts6In::Tb {
                channel,
                set_at,
                set_by,
                text,
            } => {
                server.remote_topic(&channel, "*", &set_by, set_at, &text);
                server.forward_to_links(
                    peer_sid,
                    &LinkMessage::Stopic {
                        channel,
                        source: "*".to_owned(),
                        set_by,
                        set_at,
                        text,
                    }
                    .to_line(),
                );
            }
            Ts6In::Away { uid, reason } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    server.remote_away(&uid, reason.as_deref());
                    server
                        .forward_to_links(peer_sid, &LinkMessage::Saway { uid, reason }.to_line());
                }
            }
            Ts6In::Kill { target, reason } => {
                let uid = ctx.mapper.lock().to_ferrix(&target);
                if server.owns_local_uid(&uid) {
                    server.kill_by_uid(&uid, &reason);
                } else if server.remote_uid_authorized(peer_sid, &uid) {
                    server.kill_by_uid(&uid, &reason);
                    server.forward_to_links(peer_sid, &LinkMessage::Kill { uid, reason }.to_line());
                } else {
                    warn!(%peer_sid, %uid, "rejecting KILL with unauthorised origin");
                }
            }
            Ts6In::Login { uid, account } => {
                if server.remote_uid_authorized(peer_sid, &uid) {
                    server.remote_account(&uid, account.as_deref());
                    server.forward_to_links(
                        peer_sid,
                        &LinkMessage::Saccount {
                            uid,
                            account: account.unwrap_or_else(|| "*".to_owned()),
                        }
                        .to_line(),
                    );
                }
            }
            Ts6In::Wallops { source, text } => {
                // Trusted network-wide like KILL (the same model as a ferrix
                // link); the source is a display prefix, not a forgeable user.
                let mask = server.remote_source_mask(&source);
                server.remote_wallops(&mask, &text);
                server.forward_to_links(
                    peer_sid,
                    &LinkMessage::Swallops { source: mask, text }.to_line(),
                );
            }
            Ts6In::ChgHost { uid, host } => {
                let uid = ctx.mapper.lock().to_ferrix(&uid);
                if server.remote_uid_authorized(peer_sid, &uid) {
                    server.remote_chghost(&uid, &host);
                    server
                        .forward_to_links(peer_sid, &LinkMessage::Schghost { uid, host }.to_line());
                } else {
                    warn!(%peer_sid, %uid, "rejecting CHGHOST with unauthorised origin");
                }
            }
            Ts6In::Invite {
                source,
                target,
                channel,
            } => {
                let source = ctx.mapper.lock().to_ferrix(&source);
                let target = ctx.mapper.lock().to_ferrix(&target);
                if !server.remote_uid_authorized(peer_sid, &source) {
                    warn!(%peer_sid, %source, "rejecting INVITE with unauthorised origin");
                } else if server.owns_local_uid(&target) {
                    server.remote_invite(&source, &target, &channel);
                } else if let Some(user) = server.remote_user_by_uid(&target) {
                    server.send_towards(
                        &user.server_sid,
                        LinkMessage::Sinvite {
                            source,
                            target,
                            channel,
                        }
                        .to_line(),
                    );
                }
            }
            Ts6In::Save { uid } => {
                // The peer renamed a nick-collision loser to its UID; mirror it
                // or the two sides disagree about that user's nick forever.
                let uid = ctx.mapper.lock().to_ferrix(&uid);
                if server.remote_uid_authorized(peer_sid, &uid) {
                    if server.remote_nick_change(&uid, &uid).is_none() {
                        server.forward_to_links(
                            peer_sid,
                            &LinkMessage::Nick {
                                uid: uid.clone(),
                                nick: uid,
                            }
                            .to_line(),
                        );
                    }
                } else {
                    warn!(%peer_sid, %uid, "rejecting SAVE with unauthorised origin");
                }
            }
            Ts6In::Ping { origin } => {
                server.send_to_link(peer_sid, LinkMessage::Pong { token: origin }.to_line());
            }
            Ts6In::Squit { sid, reason } => {
                if sid == peer_sid {
                    info!(%sid, %reason, "TS6 peer SQUIT");
                    break;
                }
                if server.route_owner(&sid).as_deref() == Some(peer_sid) {
                    info!(%sid, %reason, "downstream SQUIT (TS6)");
                    server.split_remote_server(&sid, "*.net *.split");
                    server
                        .forward_to_links(peer_sid, &LinkMessage::Squit { sid, reason }.to_line());
                } else {
                    warn!(%peer_sid, %sid, "rejecting SQUIT with unauthorised origin");
                }
            }
            Ts6In::Error { reason } => {
                warn!(%reason, "TS6 peer link error");
                break;
            }
            Ts6In::Unknown(cmd) => debug!(%cmd, "unhandled TS6 command"),
            Ts6In::Pass { .. }
            | Ts6In::Capab { .. }
            | Ts6In::Server { .. }
            | Ts6In::Svinfo { .. }
            | Ts6In::Ignore => {}
        }
    }
    Ok(())
}

/// Resolve a TS6 actor (`source` of TMODE/KICK) to authorization plus the
/// native state source: a server SID acting on this link maps to `*`
/// (server-originated), a user UID stays itself.
fn ts6_actor(server: &Server, peer_sid: &str, source: &str) -> (bool, String) {
    if ts6::valid_sid(source) {
        let authorized =
            source == peer_sid || server.route_owner(source).as_deref() == Some(peer_sid);
        (authorized, "*".to_owned())
    } else {
        (
            server.remote_uid_authorized(peer_sid, source),
            source.to_owned(),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::casemap::CaseMapping;
    use crate::state::{ClientEntry, Member, MemberPrefix, Outbound, ServerInfo};
    use tokio::io::AsyncWriteExt;

    fn test_server() -> Arc<Server> {
        Server::new(ServerInfo {
            name: "irc.a".to_owned(),
            sid: "1AA".to_owned(),
            network: "n".to_owned(),
            icon: None,
            version: "v".to_owned(),
            created: "c".to_owned(),
            casemapping: CaseMapping::Ascii,
            motd: Vec::new(),
            history_len: 10,
            history_max_targets: 1000,
            max_channels: 50,
            cloak_key: None,
            sts: None,
        })
    }

    fn uid(sid: &str, uid: &str, nick: &str) -> LinkMessage {
        LinkMessage::Uid {
            sid: sid.to_owned(),
            uid: uid.to_owned(),
            lamport: 1,
            nick: nick.to_owned(),
            user: "u".to_owned(),
            host: "h".to_owned(),
            account: "*".to_owned(),
            realname: "r".to_owned(),
        }
    }

    fn drain(rx: &mut crate::state::MailboxRx) -> String {
        let mut out = String::new();
        while let Ok(msg) = rx.try_recv() {
            if let Outbound::Line(b) = msg {
                out.push_str(&String::from_utf8_lossy(&b));
            }
        }
        out
    }

    /// Drive the real inbound read loop over a duplex stream: an authorized peer's
    /// burst is applied, while frames that spoof our SID or forge a source are
    /// rejected by the origin checks.
    #[tokio::test]
    async fn read_loop_enforces_origin_and_applies_authorized_state() {
        let server = test_server();

        // Local registered client "alice" in #g.
        let (alice, mut alice_rx) = ClientEntry::new(1, "127.0.0.1".to_owned(), 64);
        {
            let mut d = alice.data.lock();
            d.nick = "alice".to_owned();
            d.user = "alice".to_owned();
            d.host = "h".to_owned();
            d.registered = true;
            d.channels.insert("#g".to_owned());
        }
        server.claim_nick(&server.fold("alice"), &alice);
        let (channel, _) = server.get_or_create_channel("#g", "#g");
        channel.data.lock().members.insert(
            alice.id,
            Member {
                entry: alice.clone(),
                prefix: MemberPrefix::default(),
            },
        );

        let (mut peer, srv) = tokio::io::duplex(16_384);
        // Authorized peer 2BB: introduce bob, join #g, speak.
        peer.write_all(&uid("2BB", "2BBbob", "bob").to_line())
            .await
            .unwrap();
        peer.write_all(
            &LinkMessage::Sjoin {
                channel: "#g".to_owned(),
                uid: "2BBbob".to_owned(),
                op: false,
                voice: false,
                ts: 0,
            }
            .to_line(),
        )
        .await
        .unwrap();
        peer.write_all(
            &LinkMessage::ChanMessage {
                source: "bob!u@h".to_owned(),
                channel: "#g".to_owned(),
                notice: false,
                msgid: None,
                time_ms: None,
                tags: None,
                text: "hi all".to_owned(),
            }
            .to_line(),
        )
        .await
        .unwrap();
        // Spoof: a UID claiming OUR sid must be rejected.
        peer.write_all(&uid("1AA", "1AAfake", "fake").to_line())
            .await
            .unwrap();
        // Forged source (not a known remote user routed via 2BB) must be dropped.
        peer.write_all(
            &LinkMessage::ChanMessage {
                source: "ghost!x@y".to_owned(),
                channel: "#g".to_owned(),
                notice: false,
                msgid: None,
                time_ms: None,
                tags: None,
                text: "spoofed".to_owned(),
            }
            .to_line(),
        )
        .await
        .unwrap();
        drop(peer); // EOF ends the read loop

        let mut reader = FramedRead::new(srv, IrcCodec::new(LINK_MAX_LINE));
        read_loop(&mut reader, "2BB", &server, &tokio::sync::Notify::new())
            .await
            .unwrap();

        let seen = drain(&mut alice_rx);
        // Authorized state was applied.
        assert!(
            seen.contains("JOIN") && seen.contains("bob") && seen.contains("hi all"),
            "authorized remote state not applied: {seen:?}"
        );
        // Spoofed/forged frames were rejected.
        assert!(
            !seen.contains("spoofed"),
            "forged-source message was delivered: {seen:?}"
        );
        assert!(
            server.find_remote_user("fake").is_none(),
            "a peer forged a user under our own SID"
        );
    }

    /// The read loop applies the state-sync messages (SJOIN prefix, STOPIC,
    /// SMODE, SAWAY) and forwards authorized frames to OTHER links, so a
    /// multi-hop (tree) topology stays in sync.
    #[tokio::test]
    async fn read_loop_applies_state_sync_and_forwards_to_other_links() {
        let server = test_server();

        // Local registered client "alice" in #g.
        let (alice, mut alice_rx) = ClientEntry::new(1, "127.0.0.1".to_owned(), 64);
        {
            let mut d = alice.data.lock();
            d.nick = "alice".to_owned();
            d.user = "alice".to_owned();
            d.host = "h".to_owned();
            d.registered = true;
            d.channels.insert("#g".to_owned());
        }
        server.claim_nick(&server.fold("alice"), &alice);
        let (channel, _) = server.get_or_create_channel("#g", "#g");
        channel.data.lock().members.insert(
            alice.id,
            Member {
                entry: alice.clone(),
                prefix: MemberPrefix::default(),
            },
        );

        // A second, already-established link that should receive forwards.
        let (fwd_tx, mut fwd_rx) = mpsc::channel::<Bytes>(256);
        server.register_link(LinkHandle::new(
            "3DD".to_owned(),
            "irc.d".to_owned(),
            "D".to_owned(),
            fwd_tx,
        ));

        let (mut peer, srv) = tokio::io::duplex(16_384);
        peer.write_all(&uid("2BB", "2BBbob", "bob").to_line())
            .await
            .unwrap();
        peer.write_all(
            &LinkMessage::Sjoin {
                channel: "#g".to_owned(),
                uid: "2BBbob".to_owned(),
                op: true,
                voice: false,
                ts: 0,
            }
            .to_line(),
        )
        .await
        .unwrap();
        peer.write_all(
            &LinkMessage::Stopic {
                channel: "#g".to_owned(),
                source: "2BBbob".to_owned(),
                set_by: "bob".to_owned(),
                set_at: 7,
                text: "synced topic".to_owned(),
            }
            .to_line(),
        )
        .await
        .unwrap();
        peer.write_all(
            &LinkMessage::Smode {
                channel: "#g".to_owned(),
                source: "2BBbob".to_owned(),
                ts: 0,
                flags: "+m".to_owned(),
                args: Vec::new(),
            }
            .to_line(),
        )
        .await
        .unwrap();
        peer.write_all(
            &LinkMessage::Saway {
                uid: "2BBbob".to_owned(),
                reason: Some("afk".to_owned()),
            }
            .to_line(),
        )
        .await
        .unwrap();
        drop(peer);

        let mut reader = FramedRead::new(srv, IrcCodec::new(LINK_MAX_LINE));
        read_loop(&mut reader, "2BB", &server, &tokio::sync::Notify::new())
            .await
            .unwrap();

        // Applied locally.
        let seen = drain(&mut alice_rx);
        assert!(
            seen.contains("TOPIC #g :synced topic") && seen.contains("MODE #g +m"),
            "state sync not announced to local member: {seen:?}"
        );
        {
            let d = channel.data.lock();
            assert!(d.remote_members.get("2BBbob").unwrap().prefix.op);
            assert!(d.modes.moderated);
            assert_eq!(d.topic.as_ref().unwrap().text, "synced topic");
        }
        assert_eq!(
            server.find_remote_user("bob").unwrap().away.as_deref(),
            Some("afk")
        );

        // Forwarded to the other link (multi-hop).
        let mut forwarded = String::new();
        while let Ok(bytes) = fwd_rx.try_recv() {
            forwarded.push_str(&String::from_utf8_lossy(&bytes));
        }
        assert!(
            forwarded.contains("UID 2BB 2BBbob")
                && forwarded.contains("SJOIN #g 2BBbob o")
                && forwarded.contains("STOPIC #g 2BBbob bob 7 :synced topic")
                && forwarded.contains("SMODE #g 2BBbob 0 +m")
                && forwarded.contains("SAWAY 2BBbob :afk"),
            "authorized frames were not forwarded to the other link: {forwarded:?}"
        );
    }

    /// A topology introduction that names a server already reachable through
    /// another link is a cycle: the read loop answers ERROR and drops the link.
    #[tokio::test]
    async fn read_loop_refuses_topology_cycles() {
        let server = test_server();
        let (b_tx, mut b_rx) = mpsc::channel::<Bytes>(256);
        server
            .try_register_link(LinkHandle::new(
                "2BB".to_owned(),
                "irc.b".to_owned(),
                "B".to_owned(),
                b_tx,
            ))
            .expect("first link registers");
        let (d_tx, _d_rx) = mpsc::channel::<Bytes>(256);
        server
            .try_register_link(LinkHandle::new(
                "3DD".to_owned(),
                "irc.d".to_owned(),
                "D".to_owned(),
                d_tx,
            ))
            .expect("second link registers");

        let (mut peer, srv) = tokio::io::duplex(16_384);
        // 2BB claims to front 3DD — but 3DD is directly linked to us.
        peer.write_all(
            &LinkMessage::Sserver {
                name: "irc.d2".to_owned(),
                sid: "3DD".to_owned(),
                uplink: "2BB".to_owned(),
                description: "D2".to_owned(),
            }
            .to_line(),
        )
        .await
        .unwrap();
        // The loop must break on the cycle; this frame must never be applied.
        peer.write_all(&uid("2BB", "2BBeve", "eve").to_line())
            .await
            .unwrap();
        drop(peer);

        let mut reader = FramedRead::new(srv, IrcCodec::new(LINK_MAX_LINE));
        read_loop(&mut reader, "2BB", &server, &tokio::sync::Notify::new())
            .await
            .unwrap();

        let mut sent = String::new();
        while let Ok(bytes) = b_rx.try_recv() {
            sent.push_str(&String::from_utf8_lossy(&bytes));
        }
        assert!(
            sent.contains("ERROR") && sent.contains("cycle"),
            "cycle must be answered with an ERROR: {sent:?}"
        );
        assert!(
            server.find_remote_user("eve").is_none(),
            "frames after a detected cycle must not be applied"
        );
    }

    /// The TS6 read loop translates a solanum-style burst into native state —
    /// topology, users (with accounts), memberships with prefixes, channel
    /// modes, topics, messages — enforces origin, and forwards everything to
    /// other links in the native format.
    #[tokio::test]
    async fn ts6_read_loop_applies_burst_and_forwards_natively() {
        let server = test_server();

        // Local registered client "alice" in #g.
        let (alice, mut alice_rx) = ClientEntry::new(1, "127.0.0.1".to_owned(), 64);
        {
            let mut d = alice.data.lock();
            d.nick = "alice".to_owned();
            d.user = "alice".to_owned();
            d.host = "h".to_owned();
            d.registered = true;
            d.channels.insert("#g".to_owned());
        }
        server.claim_nick(&server.fold("alice"), &alice);
        let (channel, _) = server.get_or_create_channel("#g", "#g");
        channel.data.lock().members.insert(
            alice.id,
            Member {
                entry: alice.clone(),
                prefix: MemberPrefix::default(),
            },
        );

        // A ferrix link that should receive native forwards.
        let (fwd_tx, mut fwd_rx) = mpsc::channel::<Bytes>(256);
        server
            .try_register_link(LinkHandle::new(
                "3DD".to_owned(),
                "irc.d".to_owned(),
                "D".to_owned(),
                fwd_tx,
            ))
            .expect("observer link registers");

        let (mut peer, srv) = tokio::io::duplex(16_384);
        for line in [
            // Topology: a leaf behind the TS6 peer.
            ":42X SID irc.leaf 2 5FF :Leaf",
            // Users: EUID with account, plus one on the leaf.
            ":42X EUID bob 1 1748000000 +i ~bob bhost 10.0.0.2 42XAAAAAB bhost bob :Bob",
            ":5FF EUID lea 2 1748000000 +i ~lea lhost 10.0.0.3 5FFAAAAAB lhost * :Lea",
            // Burst join with op prefix and channel modes.
            ":42X SJOIN 1748000001 #g +nt :@42XAAAAAB",
            // Live traffic.
            ":42XAAAAAB PRIVMSG #g :hi from ts6",
            ":42XAAAAAB TMODE 1748000001 #g +v 42XAAAAAB",
            ":42X TB #g 1748000002 bob :bridged topic",
            ":42XAAAAAB AWAY :bbl",
            ":42XAAAAAB ENCAP * LOGIN bobby",
            // Spoof: a UID outside the claimed SID namespace must be dropped.
            ":42X EUID fake 1 1 +i ~f fh 0 1AAAAAAAA fh * :Fake",
        ] {
            peer.write_all(format!("{line}\r\n").as_bytes())
                .await
                .unwrap();
        }
        drop(peer); // EOF ends the read loop

        let ctx = Ts6Ctx {
            mapper: Arc::new(Mutex::new(UidMapper::default())),
            caps: Arc::new(HashSet::new()),
        };
        let mut reader = FramedRead::new(srv, IrcCodec::new(LINK_MAX_LINE));
        ts6_read_loop(
            &mut reader,
            "42X",
            &server,
            &ctx,
            &tokio::sync::Notify::new(),
        )
        .await
        .unwrap();

        // Applied locally: alice saw the join, message, mode, and topic.
        let seen = drain(&mut alice_rx);
        assert!(
            seen.contains("JOIN #g")
                && seen.contains("hi from ts6")
                && seen.contains("MODE #g +v bob")
                && seen.contains("TOPIC #g :bridged topic"),
            "TS6 burst not applied to local member: {seen:?}"
        );
        {
            let d = channel.data.lock();
            assert!(d.remote_members.get("42XAAAAAB").unwrap().prefix.op);
            assert!(d.remote_members.get("42XAAAAAB").unwrap().prefix.voice);
            assert!(d.modes.no_external && d.modes.topic_lock);
        }
        let bob = server.find_remote_user("bob").unwrap();
        assert_eq!(bob.account.as_deref(), Some("bobby"), "ENCAP LOGIN applied");
        assert_eq!(bob.away.as_deref(), Some("bbl"));
        assert!(
            server.find_remote_user("lea").is_some(),
            "leaf user applied"
        );
        assert!(
            server.find_remote_user("fake").is_none(),
            "a UID outside its SID namespace must be rejected"
        );

        // Forwarded to the ferrix link in native format.
        let mut forwarded = String::new();
        while let Ok(bytes) = fwd_rx.try_recv() {
            forwarded.push_str(&String::from_utf8_lossy(&bytes));
        }
        assert!(
            forwarded.contains("SSERVER irc.leaf 5FF 42X")
                && forwarded.contains("UID 42X 42XAAAAAB")
                && forwarded.contains("UID 5FF 5FFAAAAAB")
                && forwarded.contains("SJOIN #g 42XAAAAAB o 1748000001")
                && forwarded.contains("SMODE #g * 1748000001 +nt")
                && forwarded.contains("STOPIC #g * bob 1748000002 :bridged topic")
                && forwarded.contains("SAWAY 42XAAAAAB :bbl")
                && forwarded.contains("SACCOUNT 42XAAAAAB bobby"),
            "TS6 events were not forwarded natively: {forwarded:?}"
        );
    }

    /// Full TS6 link bring-up against a scripted solanum-style peer: handshake
    /// (PASS/CAPAB/SERVER/SVINFO), then a translated burst — topology-safe
    /// EUIDs with TS6-shaped alias UIDs, SJOINs, and the end-of-burst PING.
    #[tokio::test]
    async fn ts6_handshake_and_burst_round_trip() {
        let server = test_server();

        // One registered local user in a channel so the burst has content.
        let (alice, _alice_rx) = ClientEntry::new(7, "127.0.0.1".to_owned(), 64);
        {
            let mut d = alice.data.lock();
            d.nick = "alice".to_owned();
            d.user = "~alice".to_owned();
            d.host = "h.example".to_owned();
            d.realname = "Alice".to_owned();
            d.registered = true;
            d.channels.insert("#g".to_owned());
        }
        server.claim_nick(&server.fold("alice"), &alice);
        let (channel, _) = server.get_or_create_channel("#g", "#g");
        channel.data.lock().members.insert(
            alice.id,
            Member {
                entry: alice.clone(),
                prefix: MemberPrefix {
                    op: true,
                    voice: false,
                },
            },
        );

        let (peer_io, srv_io) = tokio::io::duplex(65_536);
        let task_server = server.clone();
        let task =
            tokio::spawn(
                async move { establish_ts6(srv_io, "linkpw", "irc.sol", &task_server).await },
            );

        let (rd, wr) = tokio::io::split(peer_io);
        let mut rd = FramedRead::new(rd, IrcCodec::new(LINK_MAX_LINE));
        let mut wr = FramedWrite::new(wr, IrcCodec::new(LINK_MAX_LINE));
        for line in [
            "PASS linkpw TS 6 :42X",
            "CAPAB :QS EX IE EUID TB ENCAP",
            "SERVER irc.sol 1 :Solanum",
            "SVINFO 6 6 0 :1750000000",
        ] {
            wr.send(Bytes::from(format!("{line}\r\n"))).await.unwrap();
        }

        // Read our side up to the end-of-burst PING.
        let mut seen = String::new();
        while let Some(frame) = rd.next().await {
            let line = String::from_utf8_lossy(&frame.unwrap()).into_owned();
            let done = line.starts_with(":1AA PING");
            seen.push_str(&line);
            seen.push('\n');
            if done {
                break;
            }
        }
        assert!(
            seen.contains("PASS linkpw TS 6 :1AA"),
            "TS6 PASS not sent: {seen:?}"
        );
        assert!(seen.contains("CAPAB :") && seen.contains("EUID"));
        assert!(seen.contains("SERVER irc.a 1"));
        assert!(seen.contains("SVINFO 6 6 0"));
        // alice bursts as an EUID under a TS6-shaped alias in our namespace.
        assert!(
            seen.contains("EUID alice 2") && seen.contains(" 1AAAAAAAA "),
            "burst EUID missing or alias not TS6-shaped: {seen:?}"
        );
        assert!(
            seen.contains("SJOIN") && seen.contains("#g") && seen.contains("@1AAAAAAAA"),
            "burst SJOIN missing member with op prefix: {seen:?}"
        );
        assert!(server.has_links(), "link is registered during the session");

        // Peer disconnects: the bridge tears the link down cleanly.
        drop(rd);
        drop(wr);
        task.await.unwrap().unwrap();
        assert!(!server.has_links(), "link is dropped on disconnect");
    }
}
