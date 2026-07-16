//! Server-to-server (S2S) linking protocol.
//!
//! A modern, TLS-authenticated link protocol with logical (Lamport) clocks
//! rather than the legacy TS6 wall-clock scheme. This module defines the link
//! message grammar, a monotonic [`Lamport`] clock, and the authenticated
//! [`handshake`] that both ends run before bursting state.
//!
//! The wire format reuses the IRC line grammar (parsed by [`ferrix_protocol`]),
//! so a link is just another framed connection. Trust rests on **mutual TLS
//! certificate fingerprints** (pinned in config) plus a shared `PASS` token —
//! never a plaintext password over an unauthenticated channel.
//!
//! State synchronisation (user/channel burst, cross-server message relay, split
//! handling) builds on this foundation; see [`crate::link`] for the transport
//! and [`crate::state`] for how inbound frames are applied.

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use ferrix_protocol::{Command, Message};
use subtle::ConstantTimeEq;

/// Compare two link `PASS` tokens in constant time (independent of how many
/// leading bytes match), so a peer that has already cleared certificate-
/// fingerprint pinning cannot learn the token via a timing side-channel.
#[must_use]
pub fn tokens_match(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

use crate::wire::Line;

/// A monotonic Lamport logical clock for ordering link events without relying on
/// synchronised wall clocks.
#[derive(Debug, Default)]
pub struct Lamport(AtomicU64);

impl Lamport {
    /// Advance for a local event and return the new time.
    pub fn tick(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Merge a timestamp received from a peer: the clock jumps past it.
    pub fn observe(&self, peer: u64) -> u64 {
        let mut current = self.0.load(Ordering::Relaxed);
        loop {
            let next = current.max(peer) + 1;
            match self
                .0
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return next,
                Err(actual) => current = actual,
            }
        }
    }

    /// The current time without advancing.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A message exchanged over an S2S link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkMessage {
    /// `PASS <token>` — link authentication token (in addition to mTLS).
    Pass { token: String },
    /// `SERVER <name> <sid> :<description>` — introduce a server.
    Server {
        name: String,
        sid: String,
        description: String,
    },
    /// `SSERVER <name> <sid> <uplink> :<description>` — introduce a server
    /// elsewhere in the network (behind the announcing peer). `uplink` is the
    /// SID of the server it is connected to (its tree parent). Propagating the
    /// full topology lets every server detect a link that would close a cycle
    /// and refuse it ("server already exists").
    Sserver {
        name: String,
        sid: String,
        uplink: String,
        description: String,
    },
    /// `PING <token>` — keepalive.
    Ping { token: String },
    /// `PONG <token>` — keepalive reply.
    Pong { token: String },
    /// `UID <sid> <uid> <lamport> <nick> <user> <host> <account> :<realname>` —
    /// introduce a remote user.
    Uid {
        sid: String,
        uid: String,
        lamport: u64,
        nick: String,
        user: String,
        host: String,
        account: String,
        realname: String,
    },
    /// `NICK <uid> <newnick>` — a remote user changed nickname.
    Nick { uid: String, nick: String },
    /// `QUIT <uid> :<reason>` — a remote user has disconnected.
    Quit { uid: String, reason: String },
    /// `SMSG <source> <target> <P|N> <msgid|*> <time_ms|*> <tags|*> :<text>` — a
    /// relayed user message. `msgid`/`time_ms` carry the origin server's message
    /// id and send time so every server shows the SAME msgid and `server-time`
    /// (required for cross-server replies/reactions/REDACT); `tags` carries the
    /// sender's client-only (`+`-prefixed) tags. `*` = absent, and the receiver
    /// mints its own where it must.
    UserMessage {
        source: String,
        target: String,
        notice: bool,
        msgid: Option<String>,
        time_ms: Option<u64>,
        tags: Option<String>,
        text: String,
    },
    /// `SJOIN <channel> <uid> <flags> [<ts>]` — a remote user joined a channel.
    /// `flags` carries the member's channel prefix: `o` (op) and/or `v`
    /// (voice), or `-` for none (also used when bursting existing members).
    /// `ts` is the sender's channel-creation timestamp; the older channel wins
    /// a netjoin conflict (TS6 rules — see [`crate::state::Server::remote_join`]).
    /// `0`/absent means "unknown", which never triggers resolution.
    Sjoin {
        channel: String,
        uid: String,
        op: bool,
        voice: bool,
        ts: u64,
    },
    /// `SPART <channel> <uid> :<reason>` — a remote user left a channel.
    Spart {
        channel: String,
        uid: String,
        reason: String,
    },
    /// `SCMSG <source> <channel> <P|N> <msgid|*> <time_ms|*> <tags|*> :<text>` —
    /// a relayed channel message (see [`LinkMessage::UserMessage`] for the
    /// msgid/time/tags semantics).
    ChanMessage {
        source: String,
        channel: String,
        notice: bool,
        msgid: Option<String>,
        time_ms: Option<u64>,
        tags: Option<String>,
        text: String,
    },
    /// `SUMODE <uid> <flags>` — a user's umodes changed (`+i`, `+w`, `+o`, …).
    /// Keeps oper status and invisibility visible network-wide (remote WHOIS,
    /// LUSERS, oper-only visibility checks).
    Sumode { uid: String, flags: String },
    /// `SKNOCK <source> <channel> :<mask>` — someone knocked on an invite-only
    /// channel; delivered to that channel's operators on every server.
    Sknock {
        source: String,
        channel: String,
        mask: String,
    },
    /// `STAGMSG <source> <target> :<tags>` — a relayed tags-only message
    /// (IRCv3 `TAGMSG`). `tags` is the client-only (`+`-prefixed) tag section
    /// without its leading `@`; `target` is a channel display name or a nick.
    TagMessage {
        source: String,
        target: String,
        tags: String,
    },
    /// `SREDACT <source> <target> <msgid> :<reason>` — a message redaction
    /// (draft/message-redaction). `target` is a channel display name or a nick;
    /// every server deletes the message from its history and tells capable
    /// local clients.
    Sredact {
        source: String,
        target: String,
        msgid: String,
        reason: String,
    },
    /// `SRENAME <source> <old> <new> :<reason>` — a channel rename
    /// (draft/channel-rename), applied network-wide.
    Srename {
        source: String,
        old: String,
        new: String,
        reason: String,
    },
    /// `STOPIC <channel> <source> <setby> <setat> :<text>` — a channel topic
    /// changed. `source` is the acting user's uid, or `*` when the topic comes
    /// from the server itself (link-up burst). An empty `text` clears the topic.
    Stopic {
        channel: String,
        source: String,
        set_by: String,
        set_at: u64,
        text: String,
    },
    /// `SMODE <channel> <source> <ts> <flags> [args…]` — a channel mode change.
    /// `source` is the acting user's uid or `*` (burst). Arguments to `o`/`v`
    /// are network UIDs (never nicks, which can differ transiently per server).
    /// `ts` is the sender's channel-creation timestamp: modes from a *younger*
    /// view of the channel are ignored, so a netjoin cannot let the losing side
    /// overwrite the winner's modes. A mode string always starts with `+`/`-`,
    /// so the older 4-param form (no `ts`) is still unambiguous to parse.
    Smode {
        channel: String,
        source: String,
        ts: u64,
        flags: String,
        args: Vec<String>,
    },
    /// `SKICK <channel> <source> <target> :<reason>` — a user was kicked.
    /// `source` is the kicker's uid; `target` is the kicked user's uid.
    Skick {
        channel: String,
        source: String,
        target: String,
        reason: String,
    },
    /// `SAWAY <uid> [:<reason>]` — a user's away state changed. No reason
    /// means the user is back.
    Saway { uid: String, reason: Option<String> },
    /// `SACCOUNT <uid> <account|*>` — a user's login state changed (`*` means
    /// logged out).
    Saccount { uid: String, account: String },
    /// `SSETNAME <uid> :<realname>` — a user changed their real name
    /// (IRCv3 `setname`).
    Ssetname { uid: String, realname: String },
    /// `SCHGHOST <uid> <host>` — a user's displayed host changed.
    Schghost { uid: String, host: String },
    /// `SWALLOPS <source> :<text>` — an operator broadcast to umode `+w`
    /// users, network-wide. `source` is the sender's display prefix.
    Swallops { source: String, text: String },
    /// `SINVITE <source> <target> <channel>` — a cross-server invitation:
    /// `source` (uid) invites `target` (uid) into `channel`. Applied by the
    /// target's server, which records the pending invite and notifies the
    /// target.
    Sinvite {
        source: String,
        target: String,
        channel: String,
    },
    /// `SBAN <+|-> <mask> <setby> :<reason>` — add or remove a network-wide
    /// ban (G-Line). Applied by every server as a local K-Line.
    Sban {
        add: bool,
        mask: String,
        set_by: String,
        reason: String,
    },
    /// `KILL <uid> :<reason>` — forcibly remove a user (e.g. nick collision).
    Kill { uid: String, reason: String },
    /// `SQUIT <sid> :<reason>` — a server has split off.
    Squit { sid: String, reason: String },
    /// `ERROR :<reason>` — fatal link error.
    Error { reason: String },
}

/// The optional identity fields plus body shared by `SMSG`/`SCMSG`:
/// `(msgid, time_ms, client tags, text)`.
type MessageTail = (Option<String>, Option<u64>, Option<String>, String);

/// Encode a member prefix as SJOIN wire flags (`o`, `v`, `ov`, or `-`).
#[must_use]
fn prefix_flags(op: bool, voice: bool) -> String {
    let mut flags = String::new();
    if op {
        flags.push('o');
    }
    if voice {
        flags.push('v');
    }
    if flags.is_empty() {
        flags.push('-');
    }
    flags
}

impl LinkMessage {
    /// Serialize to a wire line (including CRLF).
    #[must_use]
    pub fn to_line(&self) -> Bytes {
        match self {
            LinkMessage::Pass { token } => Line::bare().command("PASS").trailing(token).build(),
            LinkMessage::Server {
                name,
                sid,
                description,
            } => Line::bare()
                .command("SERVER")
                .param(name)
                .param(sid)
                .trailing(description)
                .build(),
            LinkMessage::Sserver {
                name,
                sid,
                uplink,
                description,
            } => Line::bare()
                .command("SSERVER")
                .param(name)
                .param(sid)
                .param(uplink)
                .trailing(description)
                .build(),
            LinkMessage::Ping { token } => Line::bare().command("PING").trailing(token).build(),
            LinkMessage::Pong { token } => Line::bare().command("PONG").trailing(token).build(),
            LinkMessage::Uid {
                sid,
                uid,
                lamport,
                nick,
                user,
                host,
                account,
                realname,
            } => Line::bare()
                .command("UID")
                .param(sid)
                .param(uid)
                .param(&lamport.to_string())
                .param(nick)
                .param(user)
                .param(host)
                .param(account)
                .trailing(realname)
                .build(),
            LinkMessage::Nick { uid, nick } => {
                Line::bare().command("NICK").param(uid).param(nick).build()
            }
            LinkMessage::Quit { uid, reason } => Line::bare()
                .command("QUIT")
                .param(uid)
                .trailing(reason)
                .build(),
            LinkMessage::UserMessage {
                source,
                target,
                notice,
                msgid,
                time_ms,
                tags,
                text,
            } => Line::bare()
                .command("SMSG")
                .param(source)
                .param(target)
                .param(if *notice { "N" } else { "P" })
                .param(msgid.as_deref().unwrap_or("*"))
                .param(&time_ms.map_or_else(|| "*".to_owned(), |t| t.to_string()))
                .param(tags.as_deref().unwrap_or("*"))
                .trailing(text)
                .build(),
            LinkMessage::Sjoin {
                channel,
                uid,
                op,
                voice,
                ts,
            } => Line::bare()
                .command("SJOIN")
                .param(channel)
                .param(uid)
                .param(&prefix_flags(*op, *voice))
                .param(&ts.to_string())
                .build(),
            LinkMessage::Stopic {
                channel,
                source,
                set_by,
                set_at,
                text,
            } => Line::bare()
                .command("STOPIC")
                .param(channel)
                .param(source)
                .param(set_by)
                .param(&set_at.to_string())
                .trailing(text)
                .build(),
            LinkMessage::Smode {
                channel,
                source,
                ts,
                flags,
                args,
            } => {
                let mut line = Line::bare()
                    .command("SMODE")
                    .param(channel)
                    .param(source)
                    .param(&ts.to_string())
                    .param(flags);
                for arg in args {
                    line = line.param(arg);
                }
                line.build()
            }
            LinkMessage::Skick {
                channel,
                source,
                target,
                reason,
            } => Line::bare()
                .command("SKICK")
                .param(channel)
                .param(source)
                .param(target)
                .trailing(reason)
                .build(),
            LinkMessage::Saway { uid, reason } => {
                let line = Line::bare().command("SAWAY").param(uid);
                match reason {
                    Some(reason) => line.trailing(reason).build(),
                    None => line.build(),
                }
            }
            LinkMessage::Saccount { uid, account } => Line::bare()
                .command("SACCOUNT")
                .param(uid)
                .param(account)
                .build(),
            LinkMessage::Spart {
                channel,
                uid,
                reason,
            } => Line::bare()
                .command("SPART")
                .param(channel)
                .param(uid)
                .trailing(reason)
                .build(),
            LinkMessage::ChanMessage {
                source,
                channel,
                notice,
                msgid,
                time_ms,
                tags,
                text,
            } => Line::bare()
                .command("SCMSG")
                .param(source)
                .param(channel)
                .param(if *notice { "N" } else { "P" })
                .param(msgid.as_deref().unwrap_or("*"))
                .param(&time_ms.map_or_else(|| "*".to_owned(), |t| t.to_string()))
                .param(tags.as_deref().unwrap_or("*"))
                .trailing(text)
                .build(),
            LinkMessage::Sumode { uid, flags } => Line::bare()
                .command("SUMODE")
                .param(uid)
                .param(flags)
                .build(),
            LinkMessage::Sknock {
                source,
                channel,
                mask,
            } => Line::bare()
                .command("SKNOCK")
                .param(source)
                .param(channel)
                .trailing(mask)
                .build(),
            LinkMessage::TagMessage {
                source,
                target,
                tags,
            } => Line::bare()
                .command("STAGMSG")
                .param(source)
                .param(target)
                .trailing(tags)
                .build(),
            LinkMessage::Sredact {
                source,
                target,
                msgid,
                reason,
            } => Line::bare()
                .command("SREDACT")
                .param(source)
                .param(target)
                .param(msgid)
                .trailing(reason)
                .build(),
            LinkMessage::Srename {
                source,
                old,
                new,
                reason,
            } => Line::bare()
                .command("SRENAME")
                .param(source)
                .param(old)
                .param(new)
                .trailing(reason)
                .build(),
            LinkMessage::Ssetname { uid, realname } => Line::bare()
                .command("SSETNAME")
                .param(uid)
                .trailing(realname)
                .build(),
            LinkMessage::Schghost { uid, host } => Line::bare()
                .command("SCHGHOST")
                .param(uid)
                .param(host)
                .build(),
            LinkMessage::Swallops { source, text } => Line::bare()
                .command("SWALLOPS")
                .param(source)
                .trailing(text)
                .build(),
            LinkMessage::Sinvite {
                source,
                target,
                channel,
            } => Line::bare()
                .command("SINVITE")
                .param(source)
                .param(target)
                .param(channel)
                .build(),
            LinkMessage::Sban {
                add,
                mask,
                set_by,
                reason,
            } => Line::bare()
                .command("SBAN")
                .param(if *add { "+" } else { "-" })
                .param(mask)
                .param(set_by)
                .trailing(reason)
                .build(),
            LinkMessage::Kill { uid, reason } => Line::bare()
                .command("KILL")
                .param(uid)
                .trailing(reason)
                .build(),
            LinkMessage::Squit { sid, reason } => Line::bare()
                .command("SQUIT")
                .param(sid)
                .trailing(reason)
                .build(),
            LinkMessage::Error { reason } => Line::bare().command("ERROR").trailing(reason).build(),
        }
    }

    /// Parse the `[<msgid> <time> <tags>] :<text>` tail shared by `SMSG` and
    /// `SCMSG`, across the three wire generations (4, 6, or 7 params). `*`
    /// stands for an absent value.
    fn parse_message_tail(p: &[&str]) -> Option<MessageTail> {
        let star = |v: &str| (v != "*").then(|| v.to_owned());
        match p.len() {
            0..=4 => Some((None, None, None, (*p.get(3)?).to_owned())),
            5..=6 => Some((
                star(p.get(3)?),
                p.get(4)?.parse().ok(),
                None,
                (*p.get(5)?).to_owned(),
            )),
            _ => Some((
                star(p.get(3)?),
                p.get(4)?.parse().ok(),
                star(p.get(5)?),
                (*p.get(6)?).to_owned(),
            )),
        }
    }

    /// Parse from a decoded [`Message`].
    #[must_use]
    pub fn from_message(msg: &Message<'_>) -> Option<LinkMessage> {
        let Command::Named(name) = msg.command else {
            return None;
        };
        let p = msg.params.as_slice();
        let s = |i: usize| p.get(i).map(|v| (*v).to_owned());
        match name.to_ascii_uppercase().as_str() {
            "PASS" => Some(LinkMessage::Pass { token: s(0)? }),
            "SERVER" => Some(LinkMessage::Server {
                name: s(0)?,
                sid: s(1)?,
                description: s(2)?,
            }),
            "SSERVER" => Some(LinkMessage::Sserver {
                name: s(0)?,
                sid: s(1)?,
                uplink: s(2)?,
                description: s(3)?,
            }),
            "PING" => Some(LinkMessage::Ping { token: s(0)? }),
            "PONG" => Some(LinkMessage::Pong { token: s(0)? }),
            "UID" => Some(LinkMessage::Uid {
                sid: s(0)?,
                uid: s(1)?,
                lamport: p.get(2)?.parse().ok()?,
                nick: s(3)?,
                user: s(4)?,
                host: s(5)?,
                account: s(6)?,
                realname: s(7)?,
            }),
            "NICK" => Some(LinkMessage::Nick {
                uid: s(0)?,
                nick: s(1)?,
            }),
            "QUIT" => Some(LinkMessage::Quit {
                uid: s(0)?,
                reason: s(1)?,
            }),
            // SMSG/SCMSG grew over time: 4 params (text only) → 6 (origin msgid
            // + send time) → 7 (client-only tags). All three forms are parsed so
            // a mixed-version network keeps working.
            "SMSG" => {
                let (msgid, time_ms, tags, text) = Self::parse_message_tail(p)?;
                Some(LinkMessage::UserMessage {
                    source: s(0)?,
                    target: s(1)?,
                    notice: p.get(2).is_some_and(|f| f.eq_ignore_ascii_case("N")),
                    msgid,
                    time_ms,
                    tags,
                    text,
                })
            }
            "SJOIN" => {
                let flags = p.get(2).copied().unwrap_or("-");
                Some(LinkMessage::Sjoin {
                    channel: s(0)?,
                    uid: s(1)?,
                    op: flags.contains('o'),
                    voice: flags.contains('v'),
                    // Absent on the pre-TS wire form: "unknown", never resolves.
                    ts: p.get(3).and_then(|v| v.parse().ok()).unwrap_or(0),
                })
            }
            "STOPIC" => Some(LinkMessage::Stopic {
                channel: s(0)?,
                source: s(1)?,
                set_by: s(2)?,
                set_at: p.get(3)?.parse().ok()?,
                text: s(4)?,
            }),
            "SMODE" => {
                // A mode string always begins with `+`/`-`, so a numeric third
                // param unambiguously marks the TS-carrying form.
                let ts_at_2 = p.get(2).and_then(|v| v.parse::<u64>().ok());
                let (ts, flags_at) = match ts_at_2 {
                    Some(ts) => (ts, 3),
                    None => (0, 2),
                };
                Some(LinkMessage::Smode {
                    channel: s(0)?,
                    source: s(1)?,
                    ts,
                    flags: s(flags_at)?,
                    args: p
                        .get(flags_at + 1..)
                        .unwrap_or_default()
                        .iter()
                        .map(|a| (*a).to_owned())
                        .collect(),
                })
            }
            "SKICK" => Some(LinkMessage::Skick {
                channel: s(0)?,
                source: s(1)?,
                target: s(2)?,
                reason: s(3)?,
            }),
            "SAWAY" => Some(LinkMessage::Saway {
                uid: s(0)?,
                reason: s(1),
            }),
            "SSETNAME" => Some(LinkMessage::Ssetname {
                uid: s(0)?,
                realname: s(1)?,
            }),
            "SCHGHOST" => Some(LinkMessage::Schghost {
                uid: s(0)?,
                host: s(1)?,
            }),
            "SWALLOPS" => Some(LinkMessage::Swallops {
                source: s(0)?,
                text: s(1)?,
            }),
            "SINVITE" => Some(LinkMessage::Sinvite {
                source: s(0)?,
                target: s(1)?,
                channel: s(2)?,
            }),
            "SBAN" => Some(LinkMessage::Sban {
                add: p.first().copied()? == "+",
                mask: s(1)?,
                set_by: s(2)?,
                reason: s(3)?,
            }),
            "SACCOUNT" => Some(LinkMessage::Saccount {
                uid: s(0)?,
                account: s(1)?,
            }),
            "SPART" => Some(LinkMessage::Spart {
                channel: s(0)?,
                uid: s(1)?,
                reason: s(2)?,
            }),
            "SCMSG" => {
                let (msgid, time_ms, tags, text) = Self::parse_message_tail(p)?;
                Some(LinkMessage::ChanMessage {
                    source: s(0)?,
                    channel: s(1)?,
                    notice: p.get(2).is_some_and(|f| f.eq_ignore_ascii_case("N")),
                    msgid,
                    time_ms,
                    tags,
                    text,
                })
            }
            "SUMODE" => Some(LinkMessage::Sumode {
                uid: s(0)?,
                flags: s(1)?,
            }),
            "SKNOCK" => Some(LinkMessage::Sknock {
                source: s(0)?,
                channel: s(1)?,
                mask: s(2)?,
            }),
            "STAGMSG" => Some(LinkMessage::TagMessage {
                source: s(0)?,
                target: s(1)?,
                tags: s(2)?,
            }),
            "SREDACT" => Some(LinkMessage::Sredact {
                source: s(0)?,
                target: s(1)?,
                msgid: s(2)?,
                reason: s(3).unwrap_or_default(),
            }),
            "SRENAME" => Some(LinkMessage::Srename {
                source: s(0)?,
                old: s(1)?,
                new: s(2)?,
                reason: s(3).unwrap_or_default(),
            }),
            "KILL" => Some(LinkMessage::Kill {
                uid: s(0)?,
                reason: s(1)?,
            }),
            "SQUIT" => Some(LinkMessage::Squit {
                sid: s(0)?,
                reason: s(1)?,
            }),
            "ERROR" => Some(LinkMessage::Error { reason: s(0)? }),
            _ => None,
        }
    }
}

/// The result of a successful handshake: the peer's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkPeer {
    /// The peer server's name.
    pub name: String,
    /// The peer server's id (SID).
    pub sid: String,
    /// The peer's description.
    pub description: String,
}

/// A handshake failure.
#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// The `PASS` token did not match.
    BadPassword,
    /// The peer's announced name did not match the expected link.
    UnexpectedServer,
    /// A message was missing or malformed.
    Protocol,
}

/// Run the S2S authentication handshake over an already-connected stream.
///
/// Both ends send `PASS` + `SERVER`, then validate the peer's. `read_message`
/// yields the next decoded [`LinkMessage`] (or `None` on EOF); `send` writes one.
///
/// # Errors
///
/// Returns [`HandshakeError`] on a bad token, an unexpected peer name, or a
/// protocol violation.
pub async fn handshake<S, R>(
    local_name: &str,
    local_sid: &str,
    local_desc: &str,
    token: &str,
    expected_peer: &str,
    mut send: S,
    mut read_message: R,
) -> Result<LinkPeer, HandshakeError>
where
    S: FnMut(LinkMessage),
    R: AsyncNext,
{
    send(LinkMessage::Pass {
        token: token.to_owned(),
    });
    send(LinkMessage::Server {
        name: local_name.to_owned(),
        sid: local_sid.to_owned(),
        description: local_desc.to_owned(),
    });

    let pass = read_message.next().await.ok_or(HandshakeError::Protocol)?;
    let LinkMessage::Pass { token: peer_token } = pass else {
        return Err(HandshakeError::Protocol);
    };
    if !tokens_match(&peer_token, token) {
        return Err(HandshakeError::BadPassword);
    }

    let server = read_message.next().await.ok_or(HandshakeError::Protocol)?;
    let LinkMessage::Server {
        name,
        sid,
        description,
    } = server
    else {
        return Err(HandshakeError::Protocol);
    };
    if name != expected_peer {
        return Err(HandshakeError::UnexpectedServer);
    }
    Ok(LinkPeer {
        name,
        sid,
        description,
    })
}

/// Abstracts an async source of [`LinkMessage`]s so [`handshake`] can be tested
/// without a real socket.
pub trait AsyncNext {
    /// The next message, or `None` at end of stream.
    fn next(&mut self) -> impl std::future::Future<Output = Option<LinkMessage>>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn roundtrip(msg: LinkMessage) {
        let line = msg.to_line();
        let text = &line[..line.len() - 2]; // strip CRLF
        let parsed = Message::parse(text).unwrap();
        assert_eq!(LinkMessage::from_message(&parsed), Some(msg));
    }

    #[test]
    fn messages_round_trip() {
        roundtrip(LinkMessage::Pass {
            token: "s3cret".into(),
        });
        roundtrip(LinkMessage::Server {
            name: "irc.b.net".into(),
            sid: "42B".into(),
            description: "Hub B".into(),
        });
        roundtrip(LinkMessage::Uid {
            sid: "42B".into(),
            uid: "42BAAAAAA".into(),
            lamport: 17,
            nick: "bob".into(),
            user: "~bob".into(),
            host: "cloak.b".into(),
            account: "bob".into(),
            realname: "Bob Q".into(),
        });
        roundtrip(LinkMessage::Squit {
            sid: "42B".into(),
            reason: "ping timeout".into(),
        });
        roundtrip(LinkMessage::Sserver {
            name: "irc.c.net".into(),
            sid: "3CC".into(),
            uplink: "42B".into(),
            description: "Leaf C".into(),
        });
        roundtrip(LinkMessage::Nick {
            uid: "42BAAAAAA".into(),
            nick: "bob_".into(),
        });
        roundtrip(LinkMessage::Quit {
            uid: "42BAAAAAA".into(),
            reason: "Client Quit".into(),
        });
        roundtrip(LinkMessage::UserMessage {
            source: "alice!~a@host".into(),
            target: "bob".into(),
            notice: false,
            msgid: Some("42F-0000000000000001".into()),
            time_ms: Some(1_720_000_000_123),
            tags: Some("+typing=active".into()),
            text: "hello across the link".into(),
        });
        roundtrip(LinkMessage::UserMessage {
            source: "srv".into(),
            target: "bob".into(),
            notice: true,
            msgid: None,
            time_ms: None,
            tags: None,
            text: "notice text".into(),
        });
        roundtrip(LinkMessage::Sjoin {
            channel: "#global".into(),
            uid: "42BAAAAAA".into(),
            op: false,
            voice: false,
            ts: 1_720_000_000,
        });
        roundtrip(LinkMessage::Sjoin {
            channel: "#global".into(),
            uid: "42BAAAAAA".into(),
            op: true,
            voice: true,
            ts: 1_720_000_000,
        });
        roundtrip(LinkMessage::Stopic {
            channel: "#global".into(),
            source: "42BAAAAAA".into(),
            set_by: "bob".into(),
            set_at: 1234,
            text: "new topic".into(),
        });
        roundtrip(LinkMessage::Stopic {
            channel: "#global".into(),
            source: "*".into(),
            set_by: "bob".into(),
            set_at: 1234,
            text: String::new(), // cleared topic round-trips
        });
        roundtrip(LinkMessage::Smode {
            channel: "#global".into(),
            source: "42BAAAAAA".into(),
            ts: 1_720_000_000,
            flags: "+mk-l".into(),
            args: vec!["sekret".into()],
        });
        roundtrip(LinkMessage::Smode {
            channel: "#global".into(),
            source: "*".into(),
            ts: 1_720_000_000,
            flags: "+o".into(),
            args: vec!["42BAAAAAA".into()],
        });
        roundtrip(LinkMessage::Skick {
            channel: "#global".into(),
            source: "42BAAAAAA".into(),
            target: "1AA7".into(),
            reason: "flooding".into(),
        });
        roundtrip(LinkMessage::Saway {
            uid: "42BAAAAAA".into(),
            reason: Some("gone fishing".into()),
        });
        roundtrip(LinkMessage::Saway {
            uid: "42BAAAAAA".into(),
            reason: None,
        });
        roundtrip(LinkMessage::Saccount {
            uid: "42BAAAAAA".into(),
            account: "bob".into(),
        });
        roundtrip(LinkMessage::Saccount {
            uid: "42BAAAAAA".into(),
            account: "*".into(),
        });
        roundtrip(LinkMessage::Spart {
            channel: "#global".into(),
            uid: "42BAAAAAA".into(),
            reason: "Leaving".into(),
        });
        roundtrip(LinkMessage::ChanMessage {
            source: "alice!~a@host".into(),
            channel: "#global".into(),
            notice: false,
            msgid: Some("42F-00000000000000ff".into()),
            time_ms: Some(1_720_000_000_456),
            tags: None,
            text: "hi channel".into(),
        });
        roundtrip(LinkMessage::TagMessage {
            source: "alice!~a@host".into(),
            target: "#global".into(),
            tags: "+typing=active".into(),
        });
        roundtrip(LinkMessage::Sredact {
            source: "42BAAAAAA".into(),
            target: "#global".into(),
            msgid: "42F-00000000000000ff".into(),
            reason: "oops".into(),
        });
        roundtrip(LinkMessage::Srename {
            source: "42BAAAAAA".into(),
            old: "#global".into(),
            new: "#worldwide".into(),
            reason: "rebrand".into(),
        });
        roundtrip(LinkMessage::Ssetname {
            uid: "42BAAAAAA".into(),
            realname: "Bob Q. Public".into(),
        });
        roundtrip(LinkMessage::Schghost {
            uid: "42BAAAAAA".into(),
            host: "staff.b.net".into(),
        });
        roundtrip(LinkMessage::Swallops {
            source: "alice!~a@host".into(),
            text: "network maintenance in 5 minutes".into(),
        });
        roundtrip(LinkMessage::Sinvite {
            source: "42BAAAAAA".into(),
            target: "42F7".into(),
            channel: "#secret".into(),
        });
        roundtrip(LinkMessage::Sban {
            add: true,
            mask: "*!*@bad.example".into(),
            set_by: "alice".into(),
            reason: "spam".into(),
        });
        roundtrip(LinkMessage::Sban {
            add: false,
            mask: "*!*@bad.example".into(),
            set_by: "alice".into(),
            reason: "".into(),
        });
    }

    #[test]
    fn lamport_orders_events() {
        let clock = Lamport::default();
        assert_eq!(clock.tick(), 1);
        assert_eq!(clock.tick(), 2);
        assert_eq!(clock.observe(10), 11); // jump past a peer's time
        assert_eq!(clock.tick(), 12);
    }

    struct VecSource(std::collections::VecDeque<LinkMessage>);
    impl AsyncNext for VecSource {
        async fn next(&mut self) -> Option<LinkMessage> {
            self.0.pop_front()
        }
    }

    #[tokio::test]
    async fn handshake_accepts_matching_peer() {
        let mut sent = Vec::new();
        let peer = VecSource(
            [
                LinkMessage::Pass {
                    token: "tok".into(),
                },
                LinkMessage::Server {
                    name: "irc.b.net".into(),
                    sid: "42B".into(),
                    description: "B".into(),
                },
            ]
            .into(),
        );
        let result = handshake(
            "irc.a.net",
            "42A",
            "A",
            "tok",
            "irc.b.net",
            |m| sent.push(m),
            peer,
        )
        .await;
        assert_eq!(result.unwrap().sid, "42B");
        assert_eq!(sent.len(), 2); // we sent PASS + SERVER
    }

    #[tokio::test]
    async fn handshake_rejects_bad_token() {
        let peer = VecSource(
            [LinkMessage::Pass {
                token: "wrong".into(),
            }]
            .into(),
        );
        let result = handshake("a", "1", "A", "tok", "b", |_| {}, peer).await;
        assert_eq!(result, Err(HandshakeError::BadPassword));
    }
}
