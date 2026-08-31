//! TS6 bridge — linking with charybdis-family IRCds (solanum, ratbox, …).
//!
//! ferrixd's native S2S protocol (see [`crate::s2s`]) is the internal lingua
//! franca: every state change crosses the network as a [`LinkMessage`]. This
//! module translates at the edge, so a TS6 peer looks like any other link:
//!
//! - **outbound**: the link's mailbox receives native lines exactly like a
//!   ferrix peer; the TS6 writer task decodes each one and re-encodes it as
//!   TS6 (`EUID`, `SJOIN`, `TMODE`, …) via [`encode_outbound`].
//! - **inbound**: TS6 lines are parsed into [`Ts6In`] events, applied to
//!   server state, and forwarded to other links re-encoded as native
//!   [`LinkMessage`]s.
//!
//! ferrixd UIDs (`<SID><decimal client id>`) are not valid TS6 IDs (exactly
//! nine chars: a 3-char SID plus six `[A-Z0-9]`), so a per-link [`UidMapper`]
//! allocates TS6-shaped aliases and translates references in both directions.
//!
//! Deliberate simplifications, documented in the book: timestamps sent to the
//! peer are our wall clock (channel TS = creation time), and TS conflicts are
//! resolved by trusting the peer's view rather than the full TS6 rules —
//! appropriate for bridging a ferrix network to an existing TS6 network over
//! one authenticated link, not for adversarial meshes.

use std::collections::{HashMap, HashSet};

use bytes::Bytes;
use ferrix_protocol::{Command, Message};

use crate::s2s::LinkMessage;
use crate::state::{MemberPrefix, Server, now_unix};
use crate::wire::Line;

/// The CAPAB set we advertise: quit storms, ban/except/invex bursts, extended
/// user introductions, encapsulated commands, and topic bursts.
pub const OUR_CAPAB: &str = "QS EX IE EUID ENCAP TB";

/// Whether `s` is a well-formed TS6 SID: `[0-9][A-Z0-9][A-Z0-9]`.
#[must_use]
pub fn valid_sid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 3
        && b[0].is_ascii_digit()
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// Whether `s` is a well-formed TS6 UID: a SID followed by six `[A-Z0-9]`.
#[must_use]
pub fn valid_uid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 9
        && valid_sid(&s[..3])
        && b[3..]
            .iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// Bidirectional ferrix-UID ↔ TS6-UID aliasing for one TS6 link.
///
/// UIDs that are already TS6-shaped (notably those of users introduced *by*
/// TS6 peers) pass through unchanged; ferrix UIDs get an alias under the same
/// SID, so the origin server of every identifier is preserved.
#[derive(Debug, Default)]
pub struct UidMapper {
    to_ts6: HashMap<String, String>,
    to_ferrix: HashMap<String, String>,
    next: u64,
}

impl UidMapper {
    /// The TS6-shaped identifier for a ferrix UID, allocating an alias on
    /// first use. `None` if the UID's SID prefix is not TS6-shaped (such a
    /// user cannot be represented on a TS6 link).
    pub fn to_ts6(&mut self, ferrix_uid: &str) -> Option<String> {
        if valid_uid(ferrix_uid) {
            return Some(ferrix_uid.to_owned());
        }
        if let Some(alias) = self.to_ts6.get(ferrix_uid) {
            return Some(alias.clone());
        }
        let sid = ferrix_uid.get(..3).filter(|s| valid_sid(s))?;
        let alias = format!("{sid}{}", encode_id(self.next));
        self.next += 1;
        self.to_ts6.insert(ferrix_uid.to_owned(), alias.clone());
        self.to_ferrix.insert(alias.clone(), ferrix_uid.to_owned());
        Some(alias)
    }

    /// The ferrix UID behind a TS6 identifier: an allocated alias maps back,
    /// anything else (a TS6-native UID) passes through unchanged.
    #[must_use]
    pub fn to_ferrix(&self, ts6_uid: &str) -> String {
        self.to_ferrix
            .get(ts6_uid)
            .cloned()
            .unwrap_or_else(|| ts6_uid.to_owned())
    }
}

/// The six-character suffix for the `n`-th allocated alias: first char a
/// letter (as charybdis generates), the rest base-36.
fn encode_id(n: u64) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut out = [b'A'; 6];
    out[0] = ALPHA[usize::try_from((n / 36_u64.pow(5)) % 26).unwrap_or(0)];
    let mut rest = n % 36_u64.pow(5);
    for slot in out[1..].iter_mut().rev() {
        *slot = ALPHA[usize::try_from(rest % 36).unwrap_or(0)];
        rest /= 36;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A semantic inbound TS6 event (raw TS6 identifiers, not yet unaliased).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ts6In {
    /// `PASS <password> TS 6 :<sid>`
    Pass { password: String, sid: String },
    /// `CAPAB :<caps>`
    Capab { caps: Vec<String> },
    /// `SERVER <name> <hop> :<description>`
    Server { name: String, description: String },
    /// `SVINFO <max> <min> 0 :<time>` — TS version negotiation.
    Svinfo { max: u32, min: u32 },
    /// `:<uplink> SID <name> <hop> <sid> :<description>`
    Sid {
        name: String,
        sid: String,
        uplink: Option<String>,
        description: String,
    },
    /// `:<sid> EUID …` / `:<sid> UID …` — a user introduction.
    Euid {
        sid: Option<String>,
        uid: String,
        nick: String,
        user: String,
        host: String,
        account: Option<String>,
        realname: String,
    },
    /// `:<uid> NICK <newnick> [<ts>]`
    Nick { uid: String, nick: String },
    /// `:<uid> QUIT :<reason>`
    Quit { uid: String, reason: String },
    /// `:<sid> SJOIN <ts> <chan> <modes> [<args>…] :<members>`
    Sjoin {
        channel: String,
        /// The peer's channel-creation timestamp (TS6 resolves netjoin
        /// conflicts in favour of the older channel).
        ts: u64,
        members: Vec<(String, MemberPrefix)>,
        flags: String,
        args: Vec<String>,
    },
    /// `:<uid> JOIN <ts> <chan> +`
    Join {
        uid: String,
        channel: String,
        /// The peer's channel-creation timestamp.
        ts: u64,
    },
    /// `:<uid> PART <chan>{,<chan>} [:<reason>]`
    Part {
        uid: String,
        channels: String,
        reason: String,
    },
    /// `:<uid> PRIVMSG|NOTICE <target> :<text>`
    Msg {
        source: String,
        target: String,
        notice: bool,
        text: String,
    },
    /// `:<source> TMODE <ts> <chan> <modes> [<args>…]`
    Tmode {
        source: String,
        channel: String,
        /// The peer's channel-creation timestamp.
        ts: u64,
        flags: String,
        args: Vec<String>,
    },
    /// `:<source> KICK <chan> <target> [:<reason>]`
    Kick {
        source: String,
        channel: String,
        target: String,
        reason: String,
    },
    /// `:<uid> TOPIC <chan> :<text>`
    Topic {
        source: String,
        channel: String,
        text: String,
    },
    /// `:<sid> TB <chan> <ts> [<setby>] :<text>` — topic burst.
    Tb {
        channel: String,
        set_at: u64,
        set_by: String,
        text: String,
    },
    /// `:<uid> AWAY [:<reason>]`
    Away { uid: String, reason: Option<String> },
    /// `:<source> KILL <target> :<path>`
    Kill { target: String, reason: String },
    /// `:<source> SQUIT <sid> :<reason>`
    Squit { sid: String, reason: String },
    /// `PING <origin> [<dest>]`
    Ping { origin: String },
    /// `:<uid> ENCAP * LOGIN <account>` / `:<sid> ENCAP * SU <uid> [<account>]`
    Login {
        uid: String,
        account: Option<String>,
    },
    /// `:<source> WALLOPS :<text>` (also `OPERWALL`/`GLOBOPS`) — an operator
    /// broadcast, fanned out to our `+w` users.
    Wallops { source: String, text: String },
    /// `:<sid> ENCAP * CHGHOST <uid> <host>` / `:<source> CHGHOST <uid> <host>`
    ChgHost { uid: String, host: String },
    /// `:<uid> INVITE <target> <channel> [<ts>]`
    Invite {
        source: String,
        target: String,
        channel: String,
    },
    /// `:<sid> SAVE <uid> <ts>` — the peer resolved a nick collision by renaming
    /// the loser to its UID. Without applying it the two networks would keep
    /// different nicks for the same user.
    Save { uid: String },
    /// `ERROR :<reason>`
    Error { reason: String },
    /// Recognised but deliberately not bridged (PONG, user MODE, …).
    Ignore,
    /// Not a command we know; carried for logging.
    Unknown(String),
}

/// Parse one decoded TS6 line into a semantic event. Malformed known commands
/// come back as [`Ts6In::Ignore`] (dropped, never a link error): a TS6 peer
/// may legitimately send extended forms we don't track.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn parse_ts6(msg: &Message<'_>) -> Ts6In {
    let source = msg.source.as_ref().map(|s| s.name.to_owned());
    let Command::Named(name) = msg.command else {
        return Ts6In::Ignore; // numerics are informational on a link
    };
    let p = msg.params.as_slice();
    let s = |i: usize| p.get(i).map(|v| (*v).to_owned());
    let src = || source.clone().unwrap_or_default();
    match name.to_ascii_uppercase().as_str() {
        "PASS" => {
            // PASS <password> TS 6 :<sid>
            let ts6 = p.get(1).is_some_and(|v| v.eq_ignore_ascii_case("TS"))
                && p.get(2).is_some_and(|v| *v == "6");
            match (ts6, s(0), s(3)) {
                (true, Some(password), Some(sid)) => Ts6In::Pass { password, sid },
                _ => Ts6In::Ignore,
            }
        }
        "CAPAB" => Ts6In::Capab {
            caps: p
                .last()
                .map(|v| v.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default(),
        },
        "SERVER" => match (s(0), s(2)) {
            (Some(name), Some(description)) => Ts6In::Server { name, description },
            _ => Ts6In::Ignore,
        },
        "SVINFO" => match (
            p.first().and_then(|v| v.parse().ok()),
            p.get(1).and_then(|v| v.parse().ok()),
        ) {
            (Some(max), Some(min)) => Ts6In::Svinfo { max, min },
            _ => Ts6In::Ignore,
        },
        "SID" => match (s(0), s(2), s(3)) {
            (Some(name), Some(sid), Some(description)) => Ts6In::Sid {
                name,
                sid,
                uplink: source,
                description,
            },
            _ => Ts6In::Ignore,
        },
        // EUID nick hop ts umodes user host ip uid realhost account :gecos
        "EUID" => match (s(0), s(4), s(5), s(7), s(9), s(10)) {
            (Some(nick), Some(user), Some(host), Some(uid), Some(account), Some(realname)) => {
                Ts6In::Euid {
                    sid: source,
                    uid,
                    nick,
                    user,
                    host,
                    account: (account != "*").then_some(account),
                    realname,
                }
            }
            _ => Ts6In::Ignore,
        },
        // UID nick hop ts umodes user host ip uid :gecos
        "UID" => match (s(0), s(4), s(5), s(7), s(8)) {
            (Some(nick), Some(user), Some(host), Some(uid), Some(realname)) => Ts6In::Euid {
                sid: source,
                uid,
                nick,
                user,
                host,
                account: None,
                realname,
            },
            _ => Ts6In::Ignore,
        },
        "NICK" => match s(0) {
            Some(nick) => Ts6In::Nick { uid: src(), nick },
            None => Ts6In::Ignore,
        },
        "QUIT" => Ts6In::Quit {
            uid: src(),
            reason: s(0).unwrap_or_default(),
        },
        "SJOIN" => {
            // SJOIN <ts> <chan> <modes> [<args>…] :<members>
            let (Some(channel), Some(flags), Some(members)) = (s(1), s(2), p.last()) else {
                return Ts6In::Ignore;
            };
            let args: Vec<String> = p
                .get(3..p.len().saturating_sub(1))
                .unwrap_or_default()
                .iter()
                .map(|a| (*a).to_owned())
                .collect();
            let members = members
                .split_whitespace()
                .map(|m| {
                    let op = m.contains('@');
                    let voice = m.contains('+');
                    let uid = m.trim_start_matches(['@', '+']);
                    (uid.to_owned(), MemberPrefix { op, voice })
                })
                .collect();
            Ts6In::Sjoin {
                channel,
                // The peer's channel TS decides netjoin conflicts; unparseable
                // means "unknown" (0), which never resolves.
                ts: p.first().and_then(|v| v.parse().ok()).unwrap_or(0),
                members,
                flags,
                args,
            }
        }
        "JOIN" => match s(1) {
            // JOIN <ts> <chan> + — a post-burst single-user join.
            Some(channel) => Ts6In::Join {
                uid: src(),
                channel,
                ts: p.first().and_then(|v| v.parse().ok()).unwrap_or(0),
            },
            None => Ts6In::Ignore,
        },
        "PART" => match s(0) {
            Some(channels) => Ts6In::Part {
                uid: src(),
                channels,
                reason: s(1).unwrap_or_default(),
            },
            None => Ts6In::Ignore,
        },
        "PRIVMSG" | "NOTICE" => match (s(0), s(1)) {
            (Some(target), Some(text)) => Ts6In::Msg {
                source: src(),
                target,
                notice: name.eq_ignore_ascii_case("NOTICE"),
                text,
            },
            _ => Ts6In::Ignore,
        },
        "TMODE" => match (s(1), s(2)) {
            (Some(channel), Some(flags)) => Ts6In::Tmode {
                source: src(),
                channel,
                ts: p.first().and_then(|v| v.parse().ok()).unwrap_or(0),
                flags,
                args: p
                    .get(3..)
                    .unwrap_or_default()
                    .iter()
                    .map(|a| (*a).to_owned())
                    .collect(),
            },
            _ => Ts6In::Ignore,
        },
        "KICK" => match (s(0), s(1)) {
            (Some(channel), Some(target)) => Ts6In::Kick {
                source: src(),
                channel,
                target,
                reason: s(2).unwrap_or_default(),
            },
            _ => Ts6In::Ignore,
        },
        "TOPIC" => match s(0) {
            Some(channel) => Ts6In::Topic {
                source: src(),
                channel,
                text: s(1).unwrap_or_default(),
            },
            None => Ts6In::Ignore,
        },
        "TB" => {
            // TB <chan> <ts> [<setby>] :<text>
            let (Some(channel), Some(set_at), Some(text)) = (
                s(0),
                p.get(1).and_then(|v| v.parse().ok()),
                p.last().map(|v| (*v).to_owned()),
            ) else {
                return Ts6In::Ignore;
            };
            let set_by = if p.len() >= 4 {
                s(2).unwrap_or_default()
            } else {
                "*".to_owned()
            };
            Ts6In::Tb {
                channel,
                set_at,
                set_by,
                text,
            }
        }
        "AWAY" => Ts6In::Away {
            uid: src(),
            reason: s(0),
        },
        "KILL" => match s(0) {
            Some(target) => Ts6In::Kill {
                target,
                reason: s(1).unwrap_or_else(|| "Killed".to_owned()),
            },
            None => Ts6In::Ignore,
        },
        "SQUIT" => match s(0) {
            Some(sid) => Ts6In::Squit {
                sid,
                reason: s(1).unwrap_or_default(),
            },
            None => Ts6In::Ignore,
        },
        "PING" => Ts6In::Ping {
            origin: s(0).or(source).unwrap_or_default(),
        },
        "ENCAP" => match p.get(1).map(|v| v.to_ascii_uppercase()).as_deref() {
            Some("LOGIN") => Ts6In::Login {
                uid: src(),
                account: s(2),
            },
            Some("SU") => match s(2) {
                Some(uid) => Ts6In::Login {
                    uid,
                    account: s(3).filter(|a| !a.is_empty() && a != "*"),
                },
                None => Ts6In::Ignore,
            },
            // ENCAP * CHGHOST <uid> <host> — the form we ourselves emit.
            Some("CHGHOST") => match (s(2), s(3)) {
                (Some(uid), Some(host)) => Ts6In::ChgHost { uid, host },
                _ => Ts6In::Ignore,
            },
            _ => Ts6In::Ignore,
        },
        // Operator broadcasts, in all three spellings solanum may use.
        "WALLOPS" | "OPERWALL" | "GLOBOPS" => match s(0) {
            Some(text) => Ts6In::Wallops {
                source: src(),
                text,
            },
            None => Ts6In::Ignore,
        },
        // Bare CHGHOST (some TS6 dialects skip the ENCAP wrapper).
        "CHGHOST" => match (s(0), s(1)) {
            (Some(uid), Some(host)) => Ts6In::ChgHost { uid, host },
            _ => Ts6In::Ignore,
        },
        "INVITE" => match (s(0), s(1)) {
            (Some(target), Some(channel)) => Ts6In::Invite {
                source: src(),
                target,
                channel,
            },
            _ => Ts6In::Ignore,
        },
        "SAVE" => match s(0) {
            Some(uid) => Ts6In::Save { uid },
            None => Ts6In::Ignore,
        },
        "ERROR" => Ts6In::Error {
            reason: s(0).unwrap_or_default(),
        },
        "PONG" | "MODE" | "SVINFO2" | "RESV" | "UNRESV" | "XLINE" | "UNXLINE" | "BAN" | "ETB"
        | "EOB" | "SNOTE" | "CONNECT" | "ADMIN" | "INFO" | "LINKS" | "MOTD" | "STATS" | "TIME"
        | "TRACE" | "USERS" | "VERSION" | "WHOIS" | "LOCOPS" | "SIGNON" | "REHASH" | "DLINE"
        | "UNDLINE" | "KLINE" | "UNKLINE" | "NICKDELAY" | "KNOCK" | "CERTFP" => Ts6In::Ignore,
        other => Ts6In::Unknown(other.to_owned()),
    }
}

/// Walk a mode `flags` string and translate its argument list between the two
/// dialects. `map_uid` rewrites `o`/`v` prefix targets; `key_arg_on_remove`
/// controls the `-k` convention (TS6 carries a `*` argument, ferrix none).
fn translate_mode_args(
    flags: &str,
    args: &[String],
    key_arg_on_remove: bool,
    mut map_uid: impl FnMut(&str) -> Option<String>,
) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut rest = args.iter();
    let mut adding = true;
    for c in flags.chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,
            'o' | 'v' => {
                if let Some(arg) = rest.next() {
                    if let Some(mapped) = map_uid(arg) {
                        out.push(mapped);
                    } else {
                        out.push(arg.clone());
                    }
                }
            }
            'k' => {
                if adding {
                    if let Some(arg) = rest.next() {
                        out.push(arg.clone());
                    }
                } else {
                    // TS6 sends `-k *`; ferrix sends `-k` bare. Consume or
                    // synthesise the placeholder as the target dialect expects.
                    if !key_arg_on_remove {
                        let _ = rest.next(); // drop the inbound `*`
                    } else {
                        out.push("*".to_owned());
                    }
                }
            }
            'l' => {
                if adding && let Some(arg) = rest.next() {
                    out.push(arg.clone());
                }
            }
            'b' | 'e' | 'I' => {
                if let Some(arg) = rest.next() {
                    out.push(arg.clone());
                }
            }
            _ => {}
        }
    }
    out
}

/// Translate inbound TS6 mode arguments to ferrix conventions, unaliasing
/// `o`/`v` targets that refer to our users.
#[must_use]
pub fn mode_args_to_ferrix(flags: &str, args: &[String], mapper: &UidMapper) -> Vec<String> {
    translate_mode_args(flags, args, false, |uid| Some(mapper.to_ferrix(uid)))
}

/// The display prefix for a burst member: `@` (op), `+` (voice), both, or none.
fn member_prefix_str(prefix: MemberPrefix) -> &'static str {
    match (prefix.op, prefix.voice) {
        (true, true) => "@+",
        (true, false) => "@",
        (false, true) => "+",
        (false, false) => "",
    }
}

/// Encode one native [`LinkMessage`] as zero or more TS6 lines.
///
/// `server` supplies identity, nick→UID resolution, and channel timestamps;
/// `mapper` supplies TS6 aliases for ferrix UIDs; `peer_caps` is the peer's
/// negotiated CAPAB set (controls `EUID` vs `UID` and `TB`).
#[allow(clippy::too_many_lines)]
pub fn encode_outbound(
    msg: &LinkMessage,
    server: &Server,
    mapper: &mut UidMapper,
    peer_caps: &HashSet<String>,
) -> Vec<Bytes> {
    let our_sid = server.info.sid.as_str();
    let our_name = server.info.name.as_str();
    // Resolve a display source (`nick!user@host` or nick) to a TS6 identifier.
    let uid_for_source = |mapper: &mut UidMapper, source: &str| -> Option<String> {
        let nick = source.split('!').next().unwrap_or(source);
        let folded = server.fold(nick);
        if let Some(client) = server.find_client(&folded) {
            return mapper.to_ts6(&server.local_uid(client.id));
        }
        server
            .find_remote_user(&folded)
            .and_then(|u| mapper.to_ts6(&u.uid))
    };
    let channel_ts = |channel: &str| {
        server
            .find_channel(&server.fold(channel))
            .map_or_else(now_unix, |c| c.data.lock().created_at)
    };
    match msg {
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
            let Some(alias) = mapper.to_ts6(uid) else {
                return Vec::new();
            };
            let ts = now_unix().to_string();
            if peer_caps.contains("EUID") {
                vec![
                    Line::server(sid)
                        .command("EUID")
                        .param(nick)
                        .param("2")
                        .param(&ts)
                        .param("+i")
                        .param(user)
                        .param(host)
                        .param("0")
                        .param(&alias)
                        .param(host)
                        .param(account)
                        .trailing(realname)
                        .build(),
                ]
            } else {
                let mut lines = vec![
                    Line::server(sid)
                        .command("UID")
                        .param(nick)
                        .param("2")
                        .param(&ts)
                        .param("+i")
                        .param(user)
                        .param(host)
                        .param("0")
                        .param(&alias)
                        .trailing(realname)
                        .build(),
                ];
                if account != "*" {
                    lines.push(
                        Line::server(our_sid)
                            .command("ENCAP")
                            .param("*")
                            .param("SU")
                            .param(&alias)
                            .param(account)
                            .build(),
                    );
                }
                lines
            }
        }
        LinkMessage::Nick { uid, nick } => match mapper.to_ts6(uid) {
            Some(alias) => vec![
                Line::server(&alias)
                    .command("NICK")
                    .param(nick)
                    .trailing(&now_unix().to_string())
                    .build(),
            ],
            None => Vec::new(),
        },
        LinkMessage::Quit { uid, reason } => match mapper.to_ts6(uid) {
            Some(alias) => vec![
                Line::server(&alias)
                    .command("QUIT")
                    .trailing(reason)
                    .build(),
            ],
            None => Vec::new(),
        },
        // TS6 has no msgid/server-time on the wire; the origin identity is
        // dropped at the bridge and the far side mints its own.
        LinkMessage::UserMessage {
            source,
            target,
            notice,
            text,
            ..
        } => {
            let (Some(src), Some(dst)) = (
                uid_for_source(mapper, source),
                uid_for_source(mapper, target),
            ) else {
                return Vec::new();
            };
            vec![
                Line::server(&src)
                    .command(if *notice { "NOTICE" } else { "PRIVMSG" })
                    .param(&dst)
                    .trailing(text)
                    .build(),
            ]
        }
        LinkMessage::ChanMessage {
            source,
            channel,
            notice,
            text,
            ..
        } => match uid_for_source(mapper, source) {
            Some(src) => vec![
                Line::server(&src)
                    .command(if *notice { "NOTICE" } else { "PRIVMSG" })
                    .param(channel)
                    .trailing(text)
                    .build(),
            ],
            None => Vec::new(),
        },
        LinkMessage::Sjoin {
            channel,
            uid,
            op,
            voice,
            ts,
        } => match mapper.to_ts6(uid) {
            Some(alias) => {
                let member = format!(
                    "{}{alias}",
                    member_prefix_str(MemberPrefix {
                        op: *op,
                        voice: *voice
                    })
                );
                // TS6 carries the channel timestamp in SJOIN; use the one the
                // frame carries, falling back to our own view of the channel.
                let ts = if *ts > 0 { *ts } else { channel_ts(channel) };
                vec![
                    Line::server(our_sid)
                        .command("SJOIN")
                        .param(&ts.to_string())
                        .param(channel)
                        .param("+")
                        .trailing(&member)
                        .build(),
                ]
            }
            None => Vec::new(),
        },
        LinkMessage::Spart {
            channel,
            uid,
            reason,
        } => match mapper.to_ts6(uid) {
            Some(alias) => vec![
                Line::server(&alias)
                    .command("PART")
                    .param(channel)
                    .trailing(reason)
                    .build(),
            ],
            None => Vec::new(),
        },
        LinkMessage::Stopic {
            channel,
            source,
            set_by,
            set_at,
            text,
        } => {
            if source == "*" {
                // Burst topic: TB carries the original setter and timestamp.
                if !peer_caps.contains("TB") || text.is_empty() {
                    return Vec::new();
                }
                return vec![
                    Line::server(our_sid)
                        .command("TB")
                        .param(channel)
                        .param(&set_at.to_string())
                        .param(set_by)
                        .trailing(text)
                        .build(),
                ];
            }
            match mapper.to_ts6(source) {
                Some(src) => vec![
                    Line::server(&src)
                        .command("TOPIC")
                        .param(channel)
                        .trailing(text)
                        .build(),
                ],
                None => Vec::new(),
            }
        }
        LinkMessage::Smode {
            channel,
            source,
            ts,
            flags,
            args,
        } => {
            let src = if source == "*" {
                our_sid.to_owned()
            } else {
                match mapper.to_ts6(source) {
                    Some(src) => src,
                    None => return Vec::new(),
                }
            };
            let args = translate_mode_args(flags, args, true, |uid| mapper.to_ts6(uid));
            let ts = if *ts > 0 { *ts } else { channel_ts(channel) };
            let mut line = Line::server(&src)
                .command("TMODE")
                .param(&ts.to_string())
                .param(channel)
                .param(flags);
            for arg in &args {
                line = line.param(arg);
            }
            vec![line.build()]
        }
        LinkMessage::Skick {
            channel,
            source,
            target,
            reason,
        } => {
            let src = if source == "*" {
                Some(our_sid.to_owned())
            } else {
                mapper.to_ts6(source)
            };
            let (Some(src), Some(dst)) = (src, mapper.to_ts6(target)) else {
                return Vec::new();
            };
            vec![
                Line::server(&src)
                    .command("KICK")
                    .param(channel)
                    .param(&dst)
                    .trailing(reason)
                    .build(),
            ]
        }
        LinkMessage::Saway { uid, reason } => match mapper.to_ts6(uid) {
            Some(alias) => {
                let line = Line::server(&alias).command("AWAY");
                vec![match reason {
                    Some(reason) => line.trailing(reason).build(),
                    None => line.build(),
                }]
            }
            None => Vec::new(),
        },
        LinkMessage::Saccount { uid, account } => match mapper.to_ts6(uid) {
            Some(alias) => {
                let line = Line::server(our_sid)
                    .command("ENCAP")
                    .param("*")
                    .param("SU")
                    .param(&alias);
                vec![if account == "*" {
                    line.build()
                } else {
                    line.param(account).build()
                }]
            }
            None => Vec::new(),
        },
        LinkMessage::Kill { uid, reason } => match mapper.to_ts6(uid) {
            Some(alias) => vec![
                Line::server(our_sid)
                    .command("KILL")
                    .param(&alias)
                    .trailing(&format!("{our_name} ({reason})"))
                    .build(),
            ],
            None => Vec::new(),
        },
        // Realname changes have no TS6 equivalent; drop them at the bridge.
        LinkMessage::Ssetname { .. } => Vec::new(),
        // Umodes: only `+o`/`-o` has a TS6 equivalent worth sending, as a user
        // MODE line from the user itself.
        LinkMessage::Sumode { uid, flags } => match mapper.to_ts6(uid) {
            Some(alias) if flags.contains('o') => vec![
                Line::server(&alias)
                    .command("MODE")
                    .param(&alias)
                    .param(if flags.starts_with('-') { "-o" } else { "+o" })
                    .build(),
            ],
            _ => Vec::new(),
        },
        LinkMessage::Sknock {
            source,
            channel,
            mask: _,
        } => match mapper.to_ts6(source) {
            Some(alias) => vec![Line::server(&alias).command("KNOCK").param(channel).build()],
            None => Vec::new(),
        },
        // Message redaction, channel rename and tags-only messages cannot be
        // mapped onto TS6; dropped at the bridge (documented divergence).
        LinkMessage::Sredact { .. }
        | LinkMessage::Srename { .. }
        | LinkMessage::TagMessage { .. } => Vec::new(),
        LinkMessage::Schghost { uid, host } => match mapper.to_ts6(uid) {
            // charybdis-family servers accept an encapsulated CHGHOST.
            Some(alias) => vec![
                Line::server(our_sid)
                    .command("ENCAP")
                    .param("*")
                    .param("CHGHOST")
                    .param(&alias)
                    .param(host)
                    .build(),
            ],
            None => Vec::new(),
        },
        LinkMessage::Swallops { source, text } => vec![
            Line::server(source)
                .command("WALLOPS")
                .trailing(text)
                .build(),
        ],
        LinkMessage::Sinvite {
            source,
            target,
            channel,
        } => match (mapper.to_ts6(source), mapper.to_ts6(target)) {
            (Some(src), Some(tgt)) => vec![
                Line::server(&src)
                    .command("INVITE")
                    .param(&tgt)
                    .param(channel)
                    .param(&channel_ts(channel).to_string())
                    .build(),
            ],
            _ => Vec::new(),
        },
        // Network bans are not bridged into a TS6 network (their KLINE model
        // is per-user-duration ENCAP; mapping ours would be lossy).
        LinkMessage::Sban { .. } => Vec::new(),
        LinkMessage::Sserver {
            name,
            sid,
            uplink,
            description,
        } => vec![
            Line::server(uplink)
                .command("SID")
                .param(name)
                .param("2")
                .param(sid)
                .trailing(description)
                .build(),
        ],
        LinkMessage::Squit { sid, reason } => vec![
            Line::server(our_sid)
                .command("SQUIT")
                .param(sid)
                .trailing(reason)
                .build(),
        ],
        LinkMessage::Ping { token } => vec![
            Line::server(our_sid)
                .command("PING")
                .trailing(token)
                .build(),
        ],
        LinkMessage::Pong { token } => vec![
            Line::server(our_sid)
                .command("PONG")
                .param(our_name)
                .trailing(token)
                .build(),
        ],
        LinkMessage::Error { reason } => {
            vec![Line::bare().command("ERROR").trailing(reason).build()]
        }
        // Handshake-only messages never reach an established link's mailbox.
        LinkMessage::Pass { .. } | LinkMessage::Server { .. } => Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn parse_line(line: &str) -> Ts6In {
        parse_ts6(&Message::parse(line.as_bytes()).unwrap())
    }

    #[test]
    fn sid_and_uid_shapes() {
        assert!(valid_sid("1AA"));
        assert!(valid_sid("0X9"));
        assert!(!valid_sid("AAA")); // must start with a digit
        assert!(!valid_sid("1aa"));
        assert!(!valid_sid("1AAA"));
        assert!(valid_uid("1AAAAAAAB"));
        assert!(valid_uid("42XA0B3CZ"));
        assert!(!valid_uid("1AA17")); // a ferrix UID is not TS6-shaped
        assert!(!valid_uid("1AAaaaaaa"));
    }

    #[test]
    fn mapper_allocates_stable_aliases_and_reverses() {
        let mut m = UidMapper::default();
        let a = m.to_ts6("1AA7").unwrap();
        assert!(valid_uid(&a), "alias {a} is not a valid TS6 UID");
        assert!(a.starts_with("1AA"), "alias keeps the origin SID: {a}");
        assert_eq!(m.to_ts6("1AA7").unwrap(), a, "aliases are stable");
        assert_ne!(m.to_ts6("1AA8").unwrap(), a, "aliases are distinct");
        assert_eq!(m.to_ferrix(&a), "1AA7", "alias maps back");
        // TS6-native UIDs pass through both ways.
        assert_eq!(m.to_ts6("9ZZAAAAAA").unwrap(), "9ZZAAAAAA");
        assert_eq!(m.to_ferrix("9ZZAAAAAA"), "9ZZAAAAAA");
        // A non-TS6 SID cannot be represented.
        assert_eq!(m.to_ts6("locals"), None);
    }

    #[test]
    fn parses_handshake_lines() {
        assert_eq!(
            parse_line("PASS linkpw TS 6 :42X"),
            Ts6In::Pass {
                password: "linkpw".into(),
                sid: "42X".into()
            }
        );
        assert_eq!(
            parse_line("CAPAB :QS EX IE EUID ENCAP TB"),
            Ts6In::Capab {
                caps: ["QS", "EX", "IE", "EUID", "ENCAP", "TB"]
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect()
            }
        );
        assert_eq!(
            parse_line("SERVER irc.solanum.example 1 :Solanum test"),
            Ts6In::Server {
                name: "irc.solanum.example".into(),
                description: "Solanum test".into()
            }
        );
        assert_eq!(
            parse_line("SVINFO 6 6 0 :1750000000"),
            Ts6In::Svinfo { max: 6, min: 6 }
        );
    }

    #[test]
    fn parses_burst_and_traffic() {
        assert_eq!(
            parse_line(
                ":42X EUID alice 1 1748000000 +i ~alice host.example 10.0.0.1 42XAAAAAB real.example alice :Alice"
            ),
            Ts6In::Euid {
                sid: Some("42X".into()),
                uid: "42XAAAAAB".into(),
                nick: "alice".into(),
                user: "~alice".into(),
                host: "host.example".into(),
                account: Some("alice".into()),
                realname: "Alice".into(),
            }
        );
        assert_eq!(
            parse_line(":42X UID bob 1 1748000000 +i ~bob h.example 10.0.0.2 42XAAAAAC :Bob"),
            Ts6In::Euid {
                sid: Some("42X".into()),
                uid: "42XAAAAAC".into(),
                nick: "bob".into(),
                user: "~bob".into(),
                host: "h.example".into(),
                account: None,
                realname: "Bob".into(),
            }
        );
        assert_eq!(
            parse_line(":42X SJOIN 1748000001 #chat +nt :@42XAAAAAB +42XAAAAAC 42XAAAAAD"),
            Ts6In::Sjoin {
                channel: "#chat".into(),
                ts: 1_748_000_001,
                members: vec![
                    (
                        "42XAAAAAB".into(),
                        MemberPrefix {
                            op: true,
                            voice: false
                        }
                    ),
                    (
                        "42XAAAAAC".into(),
                        MemberPrefix {
                            op: false,
                            voice: true
                        }
                    ),
                    ("42XAAAAAD".into(), MemberPrefix::default()),
                ],
                flags: "+nt".into(),
                args: Vec::new(),
            }
        );
        assert_eq!(
            parse_line(":42X SJOIN 1748000001 #keyed +ntk sekrit :42XAAAAAB"),
            Ts6In::Sjoin {
                channel: "#keyed".into(),
                ts: 1_748_000_001,
                members: vec![("42XAAAAAB".into(), MemberPrefix::default())],
                flags: "+ntk".into(),
                args: vec!["sekrit".into()],
            }
        );
        assert_eq!(
            parse_line(":42XAAAAAB PRIVMSG #chat :hello from ts6"),
            Ts6In::Msg {
                source: "42XAAAAAB".into(),
                target: "#chat".into(),
                notice: false,
                text: "hello from ts6".into(),
            }
        );
        assert_eq!(
            parse_line(":42XAAAAAB TMODE 1748000001 #chat +o 42XAAAAAC"),
            Ts6In::Tmode {
                source: "42XAAAAAB".into(),
                channel: "#chat".into(),
                ts: 1_748_000_001,
                flags: "+o".into(),
                args: vec!["42XAAAAAC".into()],
            }
        );
        assert_eq!(
            parse_line(":42X TB #chat 1748000002 alice :welcome"),
            Ts6In::Tb {
                channel: "#chat".into(),
                set_at: 1_748_000_002,
                set_by: "alice".into(),
                text: "welcome".into(),
            }
        );
        assert_eq!(
            parse_line(":42XAAAAAB ENCAP * LOGIN alice"),
            Ts6In::Login {
                uid: "42XAAAAAB".into(),
                account: Some("alice".into()),
            }
        );
        assert_eq!(
            parse_line(":42X ENCAP * SU 42XAAAAAB :"),
            Ts6In::Login {
                uid: "42XAAAAAB".into(),
                account: None,
            }
        );
        assert_eq!(
            parse_line("PING :irc.solanum.example"),
            Ts6In::Ping {
                origin: "irc.solanum.example".into()
            }
        );
        assert_eq!(parse_line(":42XAAAAAB MODE 42XAAAAAB :+w"), Ts6In::Ignore);
    }

    #[test]
    fn mode_arg_translation_handles_key_conventions() {
        let mapper = UidMapper::default();
        // TS6 `-k *` drops the placeholder on the way in…
        assert_eq!(
            mode_args_to_ferrix("-k+o", &["*".to_owned(), "42XAAAAAB".to_owned()], &mapper),
            vec!["42XAAAAAB".to_owned()]
        );
        // …and ferrix `-k` (bare) gains one on the way out.
        let out = translate_mode_args("-k", &[], true, |_| None);
        assert_eq!(out, vec!["*".to_owned()]);
    }
}
