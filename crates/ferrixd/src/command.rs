//! Command dispatch and handlers.
//!
//! [`dispatch`] routes a parsed [`Message`] to a handler on [`Session`]. A small
//! set of commands works before registration (CAP/AUTHENTICATE/NICK/USER/PING/
//! PONG/QUIT); everything else requires a registered client and otherwise yields
//! `ERR_NOTREGISTERED`.
//!
//! Propagated events (PRIVMSG, JOIN, PART, QUIT, NICK, TOPIC, MODE, AWAY, …) are
//! sent through [`crate::deliver`] so each recipient gets the IRCv3 tags it has
//! negotiated (`server-time`, `account-tag`) and any cap-gated body variation
//! (`extended-join`).
//!
//! Locking note (see [`crate::state`]): "snapshot fields, drop the lock, then
//! act"; only nest ChannelData→ClientData, never the reverse; build [`Event`]s
//! *before* taking a channel lock.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use ferrix_protocol::{Command, Message};

use crate::cap::{self, Cap, CapSet, ReqParse};
use crate::casemap;
use crate::deliver::{self, Event};
use crate::history::{MessageKind, Selector, StoredMessage};
use crate::numeric::*;
use crate::sasl::{self, ChunkResult, Mechanism, ScramPhase};
use crate::scram;
use crate::session::{MultilineBatch, Session};
use crate::state::{self, now_unix, ChannelEntry, ClientEntry, Member, MemberPrefix, Topic};
use crate::wire::Line;

/// Uppercase a short ASCII command verb into a stack buffer, avoiding a heap
/// allocation on every inbound message. A verb longer than the buffer is never
/// a valid IRC command, so `None` falls through to `ERR_UNKNOWNCOMMAND`.
fn upper_verb<'a>(name: &str, buf: &'a mut [u8; 32]) -> Option<&'a str> {
    let bytes = name.as_bytes();
    let n = bytes.len();
    if n > buf.len() {
        return None;
    }
    for (dst, &src) in buf[..n].iter_mut().zip(bytes) {
        *dst = src.to_ascii_uppercase();
    }
    std::str::from_utf8(&buf[..n]).ok()
}

/// Intern a message's command verb to a stable `&'static str` for metrics
/// labelling. Only the known dispatched verbs are recognised; everything else
/// collapses to `"other"`, so a client cannot inflate metric cardinality with
/// arbitrary command names (a memory-DoS guard on the histogram map).
#[must_use]
pub fn metric_label(msg: &Message<'_>) -> &'static str {
    let Command::Named(name) = msg.command else {
        return "other";
    };
    let mut buf = [0u8; 32];
    let Some(upper) = upper_verb(name, &mut buf) else {
        return "other";
    };
    match upper {
        "CAP" => "CAP",
        "AUTHENTICATE" => "AUTHENTICATE",
        "WEBIRC" => "WEBIRC",
        "PASS" => "PASS",
        "NICK" => "NICK",
        "USER" => "USER",
        "PING" => "PING",
        "PONG" => "PONG",
        "QUIT" => "QUIT",
        "AWAY" => "AWAY",
        "BATCH" => "BATCH",
        "REGISTER" => "REGISTER",
        "JOIN" => "JOIN",
        "PART" => "PART",
        "PRIVMSG" => "PRIVMSG",
        "NOTICE" => "NOTICE",
        "TAGMSG" => "TAGMSG",
        "NAMES" => "NAMES",
        "WHO" => "WHO",
        "WHOIS" => "WHOIS",
        "USERHOST" => "USERHOST",
        "ISON" => "ISON",
        "TOPIC" => "TOPIC",
        "MODE" => "MODE",
        "SETNAME" => "SETNAME",
        "KICK" => "KICK",
        "INVITE" => "INVITE",
        "MONITOR" => "MONITOR",
        "WATCH" => "WATCH",
        "SILENCE" => "SILENCE",
        "GLOBOPS" => "GLOBOPS",
        "OPERWALL" => "OPERWALL",
        "MAP" => "MAP",
        "MARKREAD" => "MARKREAD",
        "REDACT" => "REDACT",
        "RENAME" => "RENAME",
        "OPER" => "OPER",
        "WALLOPS" => "WALLOPS",
        "KILL" => "KILL",
        "KLINE" => "KLINE",
        "UNKLINE" => "UNKLINE",
        "GLINE" => "GLINE",
        "UNGLINE" => "UNGLINE",
        "DLINE" => "DLINE",
        "UNDLINE" => "UNDLINE",
        "CHGHOST" => "CHGHOST",
        "REHASH" => "REHASH",
        "CONNECT" => "CONNECT",
        "SQUIT" => "SQUIT",
        "CHATHISTORY" => "CHATHISTORY",
        "METADATA" => "METADATA",
        "LIST" => "LIST",
        "LUSERS" => "LUSERS",
        "MOTD" => "MOTD",
        "VERSION" => "VERSION",
        "TIME" => "TIME",
        "ADMIN" => "ADMIN",
        "INFO" => "INFO",
        "LINKS" => "LINKS",
        "HELP" => "HELP",
        "WHOWAS" => "WHOWAS",
        "STATS" => "STATS",
        "KNOCK" => "KNOCK",
        "DIE" => "DIE",
        _ => "other",
    }
}

/// Route a parsed message to its handler.
pub fn dispatch(session: &mut Session, msg: &Message<'_>) {
    let Command::Named(name) = msg.command else {
        // Clients do not send numerics — but receiving one still counts as
        // traffic, so it closes the WEBIRC first-command window below.
        session.first_command_received = true;
        return;
    };
    let params = msg.params.as_slice();
    let mut verb_buf = [0u8; 32];
    let upper = upper_verb(name, &mut verb_buf);

    // WEBIRC must be the very first command on the connection; cmd_webirc
    // enforces that contract (and marks the connection itself). Every other
    // command — known, unknown, or numeric — closes the window structurally
    // here, so no dispatch arm can forget to.
    if upper == Some("WEBIRC") {
        return session.cmd_webirc(params);
    }
    session.first_command_received = true;

    // Commands allowed before (and after) registration.
    match upper {
        Some("CAP") => return session.cmd_cap(params),
        Some("AUTHENTICATE") => return session.cmd_authenticate(params),
        Some("PASS") => return session.cmd_pass(params),
        Some("NICK") => return session.cmd_nick(params),
        Some("USER") => return session.cmd_user(params),
        Some("PING") => return session.cmd_ping(params),
        // A PONG needs no reply; simply having been read already reset the
        // connection's idle timer (see `crate::connection`).
        Some("PONG") => return,
        Some("QUIT") => return session.cmd_quit(params),
        // draft/pre-away: a client that negotiated the cap may set its AWAY
        // status before registration completes (bouncers/multi-connection).
        Some("AWAY") if session.entry.caps().has(Cap::PreAway) => {
            return session.cmd_away(params);
        }
        _ => {}
    }

    if !session.registered {
        session.numeric(ERR_NOTREGISTERED, &[], Some("You have not registered"));
        return;
    }

    // Absorb messages belonging to an in-progress draft/multiline batch.
    if session.try_multiline_accumulate(msg) {
        return;
    }

    match upper {
        Some("BATCH") => session.cmd_batch(params),
        Some("REGISTER") => session.cmd_register(params),
        Some("JOIN") => session.cmd_join(params),
        Some("PART") => session.cmd_part(params),
        // Client-only tags ride along with the message across servers, so they
        // are lifted out of the raw frame here.
        Some("PRIVMSG") => session.cmd_message(params, false, client_tag_string(msg)),
        Some("NOTICE") => session.cmd_message(params, true, client_tag_string(msg)),
        Some("TAGMSG") => session.cmd_tagmsg(msg),
        Some("NAMES") => session.cmd_names(params),
        Some("WHO") => session.cmd_who(params),
        Some("WHOIS") => session.cmd_whois(params),
        Some("USERHOST") => session.cmd_userhost(params),
        Some("ISON") => session.cmd_ison(params),
        Some("TOPIC") => session.cmd_topic(params),
        Some("MODE") => session.cmd_mode(params),
        Some("AWAY") => session.cmd_away(params),
        Some("SETNAME") => session.cmd_setname(params),
        Some("KICK") => session.cmd_kick(params),
        Some("INVITE") => session.cmd_invite(params),
        Some("MONITOR") => session.cmd_monitor(params),
        // WATCH is the older spelling of MONITOR; accepted so legacy clients
        // get presence notifications instead of ERR_UNKNOWNCOMMAND.
        Some("WATCH") => session.cmd_watch(params),
        Some("SILENCE") => session.cmd_silence(params),
        Some("GLOBOPS") | Some("OPERWALL") => session.cmd_globops(params),
        Some("MAP") => session.cmd_map(),
        Some("MARKREAD") => session.cmd_markread(params),
        Some("REDACT") => session.cmd_redact(params),
        Some("RENAME") => session.cmd_rename(params),
        Some("OPER") => session.cmd_oper(params),
        Some("WALLOPS") => session.cmd_wallops(params),
        Some("KILL") => session.cmd_kill(params),
        Some("KLINE") => session.cmd_kline(params),
        Some("UNKLINE") => session.cmd_unkline(params),
        // G-Lines are network-wide: applied locally like a K-Line, then
        // propagated to every linked server.
        Some("GLINE") => session.cmd_gline(params),
        Some("UNGLINE") => session.cmd_ungline(params),
        Some("DLINE") => session.cmd_dline(params),
        Some("UNDLINE") => session.cmd_undline(params),
        Some("CHGHOST") => session.cmd_chghost(params),
        Some("REHASH") => session.cmd_rehash(),
        Some("CONNECT") => session.cmd_connect(params),
        Some("SQUIT") => session.cmd_squit(params),
        Some("CHATHISTORY") => session.cmd_chathistory(params),
        Some("METADATA") => session.cmd_metadata(params),
        Some("LIST") => session.cmd_list(params),
        Some("LUSERS") => session.send_lusers(),
        Some("MOTD") => session.send_motd(),
        Some("VERSION") => session.cmd_version(),
        Some("TIME") => session.cmd_time(),
        Some("ADMIN") => session.cmd_admin(),
        Some("INFO") => session.cmd_info(),
        Some("LINKS") => session.cmd_links(),
        Some("HELP") => session.cmd_help(params),
        Some("WHOWAS") => session.cmd_whowas(params),
        Some("STATS") => session.cmd_stats(params),
        Some("KNOCK") => session.cmd_knock(params),
        Some("DIE") => session.cmd_die(),
        _ => session.numeric(ERR_UNKNOWNCOMMAND, &[name], Some("Unknown command")),
    }
}

/// The `HELP` index: one entry per user-visible command, first line is the
/// usage synopsis. Kept in dispatch order of `dispatch` above.
static HELP_TOPICS: &[(&str, &[&str])] = &[
    (
        "CAP",
        &["CAP LS|REQ|END [args]", "IRCv3 capability negotiation."],
    ),
    (
        "AUTHENTICATE",
        &[
            "AUTHENTICATE <mechanism|payload>",
            "SASL login (PLAIN, EXTERNAL, SCRAM-SHA-256).",
        ],
    ),
    (
        "PASS",
        &[
            "PASS <password>",
            "Connection password (before registration).",
        ],
    ),
    ("NICK", &["NICK <nickname>", "Set or change your nickname."]),
    (
        "USER",
        &["USER <user> 0 * :<realname>", "Complete registration."],
    ),
    (
        "PING",
        &["PING <token>", "Keepalive; the server replies with PONG."],
    ),
    ("QUIT", &["QUIT [:<reason>]", "Disconnect from the server."]),
    (
        "JOIN",
        &[
            "JOIN <#chan>[,<#chan>] [key[,key]]",
            "Join one or more channels.",
        ],
    ),
    (
        "PART",
        &[
            "PART <#chan>[,<#chan>] [:<reason>]",
            "Leave one or more channels.",
        ],
    ),
    (
        "PRIVMSG",
        &[
            "PRIVMSG <target>[,<target>] :<text>",
            "Send a message to a user or channel.",
        ],
    ),
    (
        "NOTICE",
        &[
            "NOTICE <target> :<text>",
            "Send a notice (never auto-replied).",
        ],
    ),
    (
        "TAGMSG",
        &[
            "TAGMSG <target>",
            "Send a tags-only message (message-tags).",
        ],
    ),
    (
        "NAMES",
        &["NAMES <#chan>", "List the members of a channel."],
    ),
    (
        "WHO",
        &[
            "WHO <mask> [flags[%fields]]",
            "List users matching a mask (WHOX supported).",
        ],
    ),
    ("WHOIS", &["WHOIS <nick>", "Details about a user."]),
    (
        "WHOWAS",
        &[
            "WHOWAS <nick> [count]",
            "Recently-departed identities for a nick.",
        ],
    ),
    (
        "USERHOST",
        &[
            "USERHOST <nick> [nick ...]",
            "Compact user@host info for up to 5 nicks.",
        ],
    ),
    (
        "ISON",
        &[
            "ISON <nick> [nick ...]",
            "Which of the given nicks are online.",
        ],
    ),
    (
        "TOPIC",
        &["TOPIC <#chan> [:<text>]", "Show or set a channel topic."],
    ),
    (
        "MODE",
        &[
            "MODE <target> [modes] [args]",
            "Show or change user/channel modes.",
        ],
    ),
    (
        "AWAY",
        &["AWAY [:<message>]", "Set or clear your away status."],
    ),
    (
        "SETNAME",
        &[
            "SETNAME :<realname>",
            "Change your real name (IRCv3 setname).",
        ],
    ),
    (
        "KICK",
        &[
            "KICK <#chan> <nick> [:<reason>]",
            "Remove a user from a channel.",
        ],
    ),
    (
        "INVITE",
        &[
            "INVITE [<nick> <#chan>]",
            "Invite a user; no arguments lists your invitations.",
        ],
    ),
    (
        "KNOCK",
        &[
            "KNOCK <#chan>",
            "Ask the operators of an invite-only channel for an invite.",
        ],
    ),
    (
        "MONITOR",
        &[
            "MONITOR +|-|C|L|S [targets]",
            "Track when nicks come on/offline.",
        ],
    ),
    (
        "WATCH",
        &[
            "WATCH [+nick|-nick|C|L|S]...",
            "Presence notifications (the legacy spelling of MONITOR).",
        ],
    ),
    (
        "SILENCE",
        &[
            "SILENCE [+mask|-mask]",
            "Personal ignore list: private messages from a mask are dropped.",
        ],
    ),
    ("MAP", &["MAP", "The network as a tree of servers."]),
    (
        "MARKREAD",
        &[
            "MARKREAD <target> [timestamp=...]",
            "Get or set your read marker (draft/read-marker).",
        ],
    ),
    (
        "REDACT",
        &[
            "REDACT <target> <msgid> [:<reason>]",
            "Delete a sent message from history (draft/message-redaction).",
        ],
    ),
    (
        "RENAME",
        &[
            "RENAME <#old> <#new> [:<reason>]",
            "Rename a channel in place (draft/channel-rename).",
        ],
    ),
    (
        "LIST",
        &[
            "LIST [filters]",
            "List channels (ELIST: >n, <n, C/T comparators, masks).",
        ],
    ),
    ("LUSERS", &["LUSERS", "User / channel / server counts."]),
    ("MOTD", &["MOTD", "The message of the day."]),
    (
        "VERSION",
        &["VERSION", "Server version and ISUPPORT tokens."],
    ),
    ("TIME", &["TIME", "Server local time."]),
    ("ADMIN", &["ADMIN", "Administrative contact info."]),
    ("INFO", &["INFO", "About this server."]),
    ("LINKS", &["LINKS", "The servers of this network."]),
    (
        "STATS",
        &[
            "STATS u|o|k|d",
            "Server statistics (most letters are operator-only).",
        ],
    ),
    ("HELP", &["HELP [topic]", "This help."]),
    (
        "BATCH",
        &[
            "BATCH +|-<ref> <type>",
            "Client-initiated batches (draft/multiline).",
        ],
    ),
    (
        "REGISTER",
        &[
            "REGISTER <account|#chan> ...",
            "Register an account or channel.",
        ],
    ),
    (
        "CHATHISTORY",
        &[
            "CHATHISTORY <subcmd> <target> ...",
            "Play back message history.",
        ],
    ),
    (
        "METADATA",
        &[
            "METADATA <target> GET|SET|LIST|CLEAR ...",
            "User/channel metadata.",
        ],
    ),
    (
        "OPER",
        &["OPER <name> <password>", "Become an IRC operator."],
    ),
    (
        "WALLOPS",
        &["WALLOPS :<text>", "Operator broadcast to +w users."],
    ),
    (
        "GLOBOPS",
        &[
            "GLOBOPS :<text>",
            "Operator broadcast, marked [GLOBOPS] (oper only).",
        ],
    ),
    (
        "KILL",
        &[
            "KILL <nick>[,<nick>] [:<reason>]",
            "Operator: forcibly disconnect users.",
        ],
    ),
    (
        "KLINE",
        &[
            "KLINE <mask> [:<reason>]",
            "Operator: ban a nick!user@host mask.",
        ],
    ),
    ("UNKLINE", &["UNKLINE <mask>", "Operator: remove a K-Line."]),
    (
        "GLINE",
        &["GLINE <mask> [:<reason>]", "Operator: network-wide ban."],
    ),
    ("UNGLINE", &["UNGLINE <mask>", "Operator: remove a G-Line."]),
    (
        "DLINE",
        &[
            "DLINE <ip-mask> [:<reason>]",
            "Operator: ban connections by IP.",
        ],
    ),
    (
        "UNDLINE",
        &["UNDLINE <ip-mask>", "Operator: remove a D-Line."],
    ),
    (
        "CHGHOST",
        &[
            "CHGHOST <nick> <newhost>",
            "Operator: change a user's displayed host.",
        ],
    ),
    ("REHASH", &["REHASH", "Operator: reload the configuration."]),
    (
        "CONNECT",
        &[
            "CONNECT <name>",
            "Operator: link to a configured peer at runtime.",
        ],
    ),
    (
        "SQUIT",
        &[
            "SQUIT <server> [:reason]",
            "Operator: disconnect a directly-linked peer.",
        ],
    ),
    ("DIE", &["DIE", "Operator: shut the server down."]),
];

/// One `LIST` filter token (advertised as `ELIST=CMNTU`).
enum ListFilter {
    /// `>n` — more than n members.
    MinUsers(usize),
    /// `<n` — fewer than n members.
    MaxUsers(usize),
    /// `C<n` — created within the last n minutes.
    CreatedWithin(u64),
    /// `C>n` — created more than n minutes ago.
    CreatedBefore(u64),
    /// `T<n` — topic changed within the last n minutes.
    TopicWithin(u64),
    /// `T>n` — topic changed more than n minutes ago.
    TopicBefore(u64),
    /// A channel-name glob.
    Mask(String),
    /// `!mask` — name must not match the glob.
    NotMask(String),
}

/// Parse one `LIST` filter token; anything that is not a well-formed
/// comparator is treated as a channel-name mask.
fn parse_list_filter(token: &str) -> ListFilter {
    let parsed = match token.split_at_checked(1) {
        Some((">", n)) => n.parse().ok().map(ListFilter::MinUsers),
        Some(("<", n)) => n.parse().ok().map(ListFilter::MaxUsers),
        Some(("!", mask)) if !mask.is_empty() => Some(ListFilter::NotMask(mask.to_owned())),
        Some(("C" | "c", rest)) => match rest.split_at_checked(1) {
            Some(("<", n)) => n.parse().ok().map(ListFilter::CreatedWithin),
            Some((">", n)) => n.parse().ok().map(ListFilter::CreatedBefore),
            _ => None,
        },
        Some(("T" | "t", rest)) => match rest.split_at_checked(1) {
            Some(("<", n)) => n.parse().ok().map(ListFilter::TopicWithin),
            Some((">", n)) => n.parse().ok().map(ListFilter::TopicBefore),
            _ => None,
        },
        _ => None,
    };
    parsed.unwrap_or_else(|| ListFilter::Mask(token.to_owned()))
}

/// A parsed WHOX request: which fields to return and an optional query type
/// token echoed back in the `t` field.
struct WhoxRequest {
    fields: String,
    querytype: Option<String>,
}

/// One WHO result row, unified across local clients and users on linked
/// servers so the legacy (352) and WHOX (354) renderers cannot drift.
struct WhoRow {
    nick: String,
    user: String,
    host: String,
    /// The real IP, only when the requester may see it (`None` renders as the
    /// WHOX hidden-IP sentinel).
    ip: Option<String>,
    server: String,
    realname: String,
    away: bool,
    oper: bool,
    /// Umode `+B` (bot-mode): renders the `BOT` ISUPPORT character in WHO flags.
    bot: bool,
    account: Option<String>,
    idle: u64,
    hops: u32,
    prefix: MemberPrefix,
}

impl WhoRow {
    /// The WHO status field: `H`/`G` (here/gone), then `*` (oper), the bot-mode
    /// character (`+B`), and finally any channel prefixes (`@`/`+`).
    fn flags(&self, multi: bool) -> String {
        let mut f = String::with_capacity(4);
        f.push(if self.away { 'G' } else { 'H' });
        if self.oper {
            f.push('*');
        }
        if self.bot {
            f.push(BOT_UMODE);
        }
        f.push_str(&self.prefix.render(multi));
        f
    }
}

/// Parse a WHO second parameter of the form `<flags>%<fields>[,<querytype>]`.
/// Returns `None` when there is no `%` (i.e. a legacy WHO).
fn parse_whox(flags: &str) -> Option<WhoxRequest> {
    let pct = flags.find('%')?;
    let after = &flags[pct + 1..];
    let (fields, querytype) = match after.split_once(',') {
        Some((f, q)) => (f.to_owned(), Some(q.to_owned())),
        None => (after.to_owned(), None),
    };
    Some(WhoxRequest { fields, querytype })
}

/// Render a client's active user modes as `+…` (for `RPL_UMODEIS`).
fn render_user_modes(d: &state::ClientData) -> String {
    let mut s = String::from("+");
    if d.invisible {
        s.push('i');
    }
    if d.oper {
        s.push('o');
    }
    if d.wallops {
        s.push('w');
    }
    if d.bot {
        s.push(BOT_UMODE);
    }
    s
}

use crate::history::pair_key;

/// Parse a `chathistory` point selector: `*`, `timestamp=…`, or `msgid=…`.
fn parse_selector(token: &str) -> Option<Selector> {
    if token == "*" {
        return Some(Selector::Latest);
    }
    if let Some(ts) = token.strip_prefix("timestamp=") {
        return state::parse_server_time(ts).map(Selector::Timestamp);
    }
    token
        .strip_prefix("msgid=")
        .map(|id| Selector::MsgId(id.to_owned()))
}

/// Render a stored history message for a recipient, with `@batch`/`@time`/
/// `@msgid`/`@account` tags per capability.
fn render_stored(message: &StoredMessage, caps: CapSet, batch_ref: Option<&str>) -> Bytes {
    let mut out = String::with_capacity(message.text.len() + 96);
    let mut wrote = false;
    let sep = |out: &mut String, w: &mut bool| {
        out.push(if *w { ';' } else { '@' });
        *w = true;
    };
    if let Some(reference) = batch_ref {
        sep(&mut out, &mut wrote);
        out.push_str("batch=");
        out.push_str(reference);
    }
    if caps.has(Cap::ServerTime) {
        sep(&mut out, &mut wrote);
        out.push_str("time=");
        out.push_str(&state::format_server_time(message.time_ms));
    }
    if caps.has(Cap::MessageTags) {
        sep(&mut out, &mut wrote);
        out.push_str("msgid=");
        out.push_str(&message.msgid);
    }
    if let Some(account) = &message.account {
        if caps.has(Cap::AccountTag) {
            sep(&mut out, &mut wrote);
            out.push_str("account=");
            out.push_str(account);
        }
    }
    if wrote {
        out.push(' ');
    }
    out.push(':');
    out.push_str(&message.source);
    out.push(' ');
    out.push_str(message.kind.command());
    match message.kind {
        // `:source PRIVMSG/NOTICE/PART/TOPIC <target> :<text>` (PART keeps an
        // empty trailing reason — harmless and shape-stable).
        MessageKind::PrivMsg | MessageKind::Notice | MessageKind::Part | MessageKind::Topic => {
            out.push(' ');
            out.push_str(&message.target);
            out.push_str(" :");
            out.push_str(&message.text);
        }
        // `:source JOIN <target>`
        MessageKind::Join => {
            out.push(' ');
            out.push_str(&message.target);
        }
        // `:source QUIT :<reason>` / `:source NICK :<newnick>`
        MessageKind::Quit | MessageKind::Nick => {
            out.push_str(" :");
            out.push_str(&message.text);
        }
        // `:source KICK <target> <victim> :<reason>` (text = `victim reason`)
        MessageKind::Kick => {
            let (victim, reason) = message
                .text
                .split_once(' ')
                .unwrap_or((message.text.as_str(), ""));
            out.push(' ');
            out.push_str(&message.target);
            out.push(' ');
            out.push_str(victim);
            out.push_str(" :");
            out.push_str(reason);
        }
        // `:source MODE <target> <flags> [args…]` (text is already wire-form)
        MessageKind::Mode => {
            out.push(' ');
            out.push_str(&message.target);
            out.push(' ');
            out.push_str(&message.text);
        }
    }
    out.push_str("\r\n");
    Bytes::from(out)
}

/// Re-serialize a message's client-only (`+`-prefixed) tags into the compact
/// `key=value;key2` form used for delivery and S2S relay. `None` when the
/// message carries none.
fn client_tag_string(msg: &Message<'_>) -> Option<String> {
    let mut out = String::new();
    for tag in msg.tags.iter() {
        if !tag.key.starts_with('+') {
            continue;
        }
        if !out.is_empty() {
            out.push(';');
        }
        out.push_str(tag.key);
        if let Some(value) = &tag.value {
            out.push('=');
            out.push_str(&ferrix_protocol::tags::escape_value(value));
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Limits advertised in `RPL_ISUPPORT` and enforced here, so what the server
/// promises and what it accepts cannot drift (see `Session::send_isupport`).
/// Mode changes applied per `MODE` command (`MODES=6`).
pub(crate) const MAX_MODE_CHANGES: usize = 6;
/// Topic length in characters (`TOPICLEN`).
pub(crate) const MAX_TOPIC_LEN: usize = 390;
/// Kick-reason length in characters (`KICKLEN`).
pub(crate) const MAX_KICK_LEN: usize = 300;
/// Away-message length in characters (`AWAYLEN`).
pub(crate) const MAX_AWAY_LEN: usize = 200;
/// IRCv3 bot-mode user-mode letter, advertised as `ISUPPORT BOT=B` and enforced
/// here (`MODE <nick> +B`), so the advertisement cannot drift from behaviour.
pub(crate) const BOT_UMODE: char = 'B';

/// Truncate `text` to at most `max` characters (never splitting a UTF-8
/// codepoint), as the advertised `*LEN` tokens promise.
fn truncate_chars(text: &str, max: usize) -> &str {
    match text.char_indices().nth(max) {
        Some((end, _)) => &text[..end],
        None => text,
    }
}

/// Metadata limits (draft/metadata-2).
const MAX_METADATA_KEYS: usize = 20;
/// Maximum keys one client may subscribe to.
const MAX_METADATA_SUBS: usize = 20;
/// Maximum masks in one client's `SILENCE` list (advertised as `SILENCE=`).
pub(crate) const MAX_SILENCE_ENTRIES: usize = 32;
const MAX_METADATA_KEY_LEN: usize = 32;
const MAX_METADATA_VALUE_LEN: usize = 300;

/// Is `key` a valid metadata key?
fn valid_metadata_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_METADATA_KEY_LEN
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':' | b'/'))
}

/// Set or unset a metadata key, respecting the key-count limit.
fn apply_metadata(map: &mut HashMap<String, String>, key: &str, value: Option<&str>) {
    match value {
        Some(v) if map.len() < MAX_METADATA_KEYS || map.contains_key(key) => {
            map.insert(key.to_owned(), v.to_owned());
        }
        Some(_) => {} // at capacity, new key rejected
        None => {
            map.remove(key);
        }
    }
}

/// Normalise a ban/K-Line mask to full `nick!user@host` glob form. Extended
/// bans (`~a:…`) and IP masks are left untouched.
fn normalize_ban_mask(mask: &str) -> String {
    if mask.starts_with('~') {
        return mask.to_owned();
    }
    if mask.contains('!') {
        if mask.contains('@') {
            mask.to_owned()
        } else {
            format!("{mask}@*")
        }
    } else if mask.contains('@') {
        format!("*!{mask}")
    } else {
        format!("{mask}!*@*")
    }
}

impl Session {
    // ----------------------------------------------------------------- CAP ---

    fn cmd_cap(&mut self, params: &[&str]) {
        let Some(&sub) = params.first() else {
            return;
        };
        let target = self.nick_or_star();
        match sub.to_ascii_uppercase().as_str() {
            "LS" => {
                self.cap_negotiating = true;
                if params.get(1) == Some(&"302") {
                    self.cap_version = 302;
                }
                let sts = self.sts_token();
                self.send(
                    Line::server(self.server_name())
                        .command("CAP")
                        .param(&target)
                        .param("LS")
                        .trailing(&cap::ls_line(sts.as_deref())),
                );
            }
            "LIST" => {
                self.send(
                    Line::server(self.server_name())
                        .command("CAP")
                        .param(&target)
                        .param("LIST")
                        .trailing(&cap::list_line(self.entry.caps())),
                );
            }
            "REQ" => {
                self.cap_negotiating = true;
                let requested = params.get(1).copied().unwrap_or("");
                match cap::parse_req(requested) {
                    ReqParse::Ok(changes) => {
                        let mut caps = self.entry.caps();
                        for (c, enable) in changes {
                            if enable {
                                caps.insert(c);
                            } else {
                                caps.remove(c);
                            }
                        }
                        self.entry.set_caps(caps);
                        self.send(
                            Line::server(self.server_name())
                                .command("CAP")
                                .param(&target)
                                .param("ACK")
                                .trailing(requested),
                        );
                    }
                    ReqParse::Unknown => self.send(
                        Line::server(self.server_name())
                            .command("CAP")
                            .param(&target)
                            .param("NAK")
                            .trailing(requested),
                    ),
                }
            }
            "END" => {
                self.cap_negotiating = false;
                // draft/extended-isupport: deliver ISUPPORT during negotiation,
                // before RPL_WELCOME, for clients that asked for it early.
                if !self.registered
                    && !self.isupport_sent
                    && self.entry.caps().has(Cap::ExtendedIsupport)
                {
                    self.send_isupport();
                    self.isupport_sent = true;
                }
                self.maybe_register();
            }
            other => self.numeric(ERR_INVALIDCAPCMD, &[other], Some("Invalid CAP subcommand")),
        }
    }

    // ------------------------------------------------------------ SASL / AUTH ---

    fn cmd_authenticate(&mut self, params: &[&str]) {
        // During the pre-registration handshake a client may authenticate only
        // once. After registration, a client that negotiated `sasl` may
        // re-authenticate mid-session to switch to (or add) an account — the new
        // login replaces the old on success, while a failed attempt leaves the
        // existing login untouched (IRCv3 SASL 3.2 reauthentication).
        if !self.registered && self.account().is_some() {
            self.numeric(
                ERR_SASLALREADY,
                &[],
                Some("You have already authenticated using SASL"),
            );
            return;
        }
        if !self.entry.caps().has(Cap::Sasl) {
            self.numeric(ERR_SASLFAIL, &[], Some("SASL authentication failed"));
            return;
        }
        let Some(&arg) = params.first() else {
            self.numeric(ERR_SASLFAIL, &[], Some("SASL authentication failed"));
            return;
        };
        if arg == "*" {
            self.sasl.reset();
            self.numeric(ERR_SASLABORTED, &[], Some("SASL authentication aborted"));
            return;
        }

        match self.sasl.mechanism {
            None => match Mechanism::from_name(arg) {
                Some(mechanism) => {
                    self.sasl.mechanism = Some(mechanism);
                    if mechanism == Mechanism::Scram {
                        self.sasl.scram = ScramPhase::AwaitingClientFirst;
                    }
                    // Tell the client we are ready for the credential payload.
                    self.send(Line::bare().command("AUTHENTICATE").param("+"));
                }
                None => self.numeric(ERR_SASLFAIL, &[], Some("SASL authentication failed")),
            },
            Some(mechanism) => match self.sasl.push_chunk(arg) {
                ChunkResult::NeedMore => {}
                ChunkResult::Invalid => {
                    self.sasl.reset();
                    self.numeric(ERR_SASLTOOLONG, &[], Some("SASL message too long"));
                }
                ChunkResult::Complete(data) => match mechanism {
                    Mechanism::Scram => self.scram_step(&data),
                    _ => self.finish_sasl(mechanism, &data),
                },
            },
        }
    }

    fn finish_sasl(&mut self, mechanism: Mechanism, data: &[u8]) {
        self.sasl.reset();
        let result = match mechanism {
            Mechanism::Plain => sasl::decode_plain(data).and_then(|(_authz, authcid, password)| {
                self.server
                    .accounts
                    .verify_password(&authcid, &password)
                    .ok()
            }),
            Mechanism::External => {
                let requested = String::from_utf8_lossy(data);
                self.cert_fp
                    .as_ref()
                    .and_then(|fp| self.server.accounts.verify_fingerprint(&requested, fp).ok())
            }
            Mechanism::Scram => None,
        };
        match result {
            Some(account) => self.sasl_success(&account),
            None => self.numeric(ERR_SASLFAIL, &[], Some("SASL authentication failed")),
        }
    }

    /// Drive the multi-step SCRAM-SHA-256 exchange.
    fn scram_step(&mut self, data: &[u8]) {
        let Ok(text) = std::str::from_utf8(data) else {
            self.sasl.reset();
            self.numeric(ERR_SASLFAIL, &[], Some("SASL authentication failed"));
            return;
        };
        match std::mem::take(&mut self.sasl.scram) {
            ScramPhase::AwaitingClientFirst => {
                let Some(nonce) = scram::random_nonce() else {
                    self.sasl.reset();
                    self.numeric(ERR_SASLFAIL, &[], Some("SASL authentication failed"));
                    return;
                };
                let accounts = &self.server.accounts;
                match scram::Exchange::start(text, &nonce, |user| accounts.scram_lookup(user)) {
                    Some((exchange, server_first)) => {
                        self.send(
                            Line::bare()
                                .command("AUTHENTICATE")
                                .param(&STANDARD.encode(server_first)),
                        );
                        self.sasl.scram = ScramPhase::AwaitingClientFinal(Box::new(exchange));
                    }
                    None => {
                        self.sasl.reset();
                        self.numeric(ERR_SASLFAIL, &[], Some("SASL authentication failed"));
                    }
                }
            }
            ScramPhase::AwaitingClientFinal(exchange) => match exchange.finish(text) {
                Some(server_final) => {
                    self.send(
                        Line::bare()
                            .command("AUTHENTICATE")
                            .param(&STANDARD.encode(server_final)),
                    );
                    self.sasl.scram = ScramPhase::AwaitingFinalAck(exchange.account.clone());
                }
                None => {
                    self.sasl.reset();
                    self.numeric(ERR_SASLFAIL, &[], Some("SASL authentication failed"));
                }
            },
            ScramPhase::AwaitingFinalAck(account) => {
                self.sasl.reset();
                self.sasl_success(&account);
            }
            ScramPhase::Idle => {
                self.sasl.reset();
                self.numeric(ERR_SASLFAIL, &[], Some("SASL authentication failed"));
            }
        }
    }

    /// Common success path for any SASL mechanism.
    fn sasl_success(&mut self, account: &str) {
        self.entry.data.lock().account = Some(account.to_owned());
        self.announce_account(Some(account));
        let (nick, user, host) = self.identity();
        let nick = if nick == "*" { "*".to_owned() } else { nick };
        let user = if user.is_empty() {
            "*".to_owned()
        } else {
            user
        };
        let hostmask = format!("{nick}!{user}@{host}");
        self.numeric(
            RPL_LOGGEDIN,
            &[&hostmask, account],
            Some(&format!("You are now logged in as {account}")),
        );
        self.numeric(RPL_SASLSUCCESS, &[], Some("SASL authentication successful"));
    }

    // ---------------------------------------------------- batch / register ---

    fn cmd_batch(&mut self, params: &[&str]) {
        let Some(&reference) = params.first() else {
            return;
        };
        if let Some(name) = reference.strip_prefix('+') {
            // Only inbound draft/multiline batches are processed.
            if params.get(1) == Some(&"draft/multiline") {
                let Some(&target) = params.get(2) else {
                    self.fail("BATCH", "MULTILINE_INVALID_TARGET", &[], "Missing target");
                    return;
                };
                self.multiline = Some(MultilineBatch {
                    reference: name.to_owned(),
                    target: target.to_owned(),
                    is_notice: false,
                    lines: Vec::new(),
                    bytes: 0,
                    failed: false,
                });
            }
        } else if let Some(name) = reference.strip_prefix('-') {
            match self.multiline.take() {
                Some(batch) if batch.reference == name => self.flush_multiline(batch),
                other => self.multiline = other, // mismatched close: leave as-is
            }
        }
    }

    /// Deliver a completed multiline batch: `draft/multiline` recipients get the
    /// lines grouped in a real batch, everyone else gets them as individual
    /// messages (the spec's fallback). Both see the same text.
    fn flush_multiline(&mut self, batch: MultilineBatch) {
        if batch.failed || batch.lines.is_empty() {
            return;
        }
        let reference = self.server.history.next_msgid();
        self.multiline_frame(&batch.target, &reference, true);
        for (line, concat) in &batch.lines {
            // The concat marker is a client tag, so it reaches capable
            // recipients (and other servers) unchanged.
            let tags = concat.then(|| "+draft/multiline-concat".to_owned());
            self.cmd_message_inner(
                &[batch.target.as_str(), line.as_str()],
                batch.is_notice,
                tags,
                Some(&reference),
            );
        }
        self.multiline_frame(&batch.target, &reference, false);
    }

    /// Send the opening/closing `BATCH` frame of a multiline batch to the
    /// recipients that negotiated `draft/multiline` (nobody else may see it).
    fn multiline_frame(&self, target: &str, reference: &str, open: bool) {
        let (nick, user, host) = self.identity();
        let mut line = Line::user(&nick, &user, &host).command("BATCH");
        line = if open {
            line.param(&format!("+{reference}"))
                .param("draft/multiline")
                .param(target)
        } else {
            line.param(&format!("-{reference}"))
        };
        let event = Event::new(line.body());
        if casemap::is_valid_channel(target) {
            if let Some(channel) = self.server.find_channel(&self.server.fold(target)) {
                deliver::to_channel_capped(&channel, &event, Cap::Multiline, Some(self.entry.id));
            }
        } else if let Some(dest) = self.server.find_client(&self.server.fold(target)) {
            if dest.caps().has(Cap::Multiline) {
                deliver::to_client(&dest, &event);
            }
        }
        // The sender sees its own batch frames only with echo-message.
        let caps = self.entry.caps();
        if caps.has(Cap::EchoMessage) && caps.has(Cap::Multiline) {
            self.deliver_self(&event);
        }
    }

    fn cmd_register(&mut self, params: &[&str]) {
        // A channel name as the first argument registers a channel instead.
        if let Some(&first) = params.first() {
            if casemap::is_valid_channel(first) {
                self.register_channel_cmd(first);
                return;
            }
        }

        // REGISTER <account|*> <email> <password>
        let Some(&account) = params.first() else {
            self.fail("REGISTER", "NEED_MORE_PARAMS", &[], "Not enough parameters");
            return;
        };
        let Some(&password) = params.get(2) else {
            self.fail("REGISTER", "NEED_MORE_PARAMS", &[], "Not enough parameters");
            return;
        };
        let name = if account == "*" {
            self.entry.nick()
        } else {
            account.to_owned()
        };
        if !casemap::is_valid_nick(&name) {
            self.fail(
                "REGISTER",
                "BAD_ACCOUNT_NAME",
                &[&name],
                "Invalid account name",
            );
            return;
        }
        if self.server.accounts.exists(&name) {
            self.fail(
                "REGISTER",
                "ACCOUNT_EXISTS",
                &[&name],
                "Account already exists",
            );
            return;
        }
        if self.server.accounts.set_password(&name, password).is_err() {
            self.fail(
                "REGISTER",
                "TEMPORARILY_UNAVAILABLE",
                &[&name],
                "Registration failed",
            );
            return;
        }
        // Persist the new account so it survives a restart and REHASH.
        self.server.persist_account(&name);
        self.entry.data.lock().account = Some(name.clone());
        self.announce_account(Some(&name));
        self.send(
            Line::server(self.server_name())
                .command("REGISTER")
                .param("SUCCESS")
                .param(&name)
                .trailing("Account registered and logged in"),
        );
    }

    /// `REGISTER <#channel>` — register the channel to the caller's account.
    /// The caller must be logged in and a channel operator.
    fn register_channel_cmd(&mut self, name: &str) {
        let Some(account) = self.account() else {
            self.fail(
                "REGISTER",
                "ACCOUNT_REQUIRED",
                &[name],
                "You must be logged in to register a channel",
            );
            return;
        };
        let folded = self.server.fold(name);
        let Some(channel) = self.server.find_channel(&folded) else {
            self.fail("REGISTER", "INVALID_CHANNEL", &[name], "No such channel");
            return;
        };
        let (is_op, display) = {
            let data = channel.data.lock();
            (
                data.members
                    .get(&self.entry.id)
                    .is_some_and(|m| m.prefix.op),
                data.name.clone(),
            )
        };
        if !is_op {
            self.fail(
                "REGISTER",
                "CHANOPRIVSNEEDED",
                &[&display],
                "You must be a channel operator to register it",
            );
            return;
        }
        if !self.server.register_channel(&folded, &account) {
            self.fail(
                "REGISTER",
                "ALREADY_REGISTERED",
                &[&display],
                "Channel is already registered",
            );
            return;
        }
        self.send(
            Line::server(self.server_name())
                .command("REGISTER")
                .param("SUCCESS")
                .param(&display)
                .trailing(&format!("Channel registered to {account}")),
        );
    }

    // -------------------------------------------------------- registration ---

    fn cmd_nick(&mut self, params: &[&str]) {
        let Some(&nick) = params.first() else {
            self.numeric(ERR_NONICKNAMEGIVEN, &[], Some("No nickname given"));
            return;
        };
        if !casemap::is_valid_nick(nick) {
            self.numeric(ERR_ERRONEUSNICKNAME, &[nick], Some("Erroneous nickname"));
            return;
        }

        let folded = self.server.fold(nick);
        let current = self.entry.nick();
        let current_folded = if current == "*" {
            String::new()
        } else {
            self.server.fold(&current)
        };

        // Let WASM plugins veto a registered client's nick change (fail-open;
        // pre-registration nick selection during the handshake is not a
        // moderation event and is left untouched).
        if self.registered && nick != current {
            if let Some(plugin_host) = self.server.plugins() {
                if plugin_host.on_nick(&current, nick) == crate::plugin::Verdict::Block {
                    self.numeric(
                        ERR_ERRONEUSNICKNAME,
                        &[nick],
                        Some("Nickname change refused by server policy"),
                    );
                    return;
                }
            }
        }

        // A pure case change of the client's own nick: no re-claim needed.
        if !current_folded.is_empty() && folded == current_folded {
            if current != nick {
                self.entry.data.lock().nick = nick.to_owned();
                if self.registered {
                    self.broadcast_nick_change(&current, nick);
                    self.server.propagate_nick_change(self.entry.id, nick);
                }
            }
            return;
        }

        if !self.server.claim_nick(&folded, &self.entry) {
            self.numeric(
                ERR_NICKNAMEINUSE,
                &[nick],
                Some("Nickname is already in use"),
            );
            return;
        }
        if !current_folded.is_empty() {
            self.server.release_nick(&current_folded);
        }
        self.entry.data.lock().nick = nick.to_owned();

        if self.registered {
            // The old identity becomes WHOWAS history.
            {
                let d = self.entry.data.lock();
                let (user, host, realname) = (d.user.clone(), d.host.clone(), d.realname.clone());
                drop(d);
                self.server.record_whowas(&current, &user, &host, &realname);
            }
            self.broadcast_nick_change(&current, nick);
            self.server.propagate_nick_change(self.entry.id, nick);
            // MONITOR: the old nick just went offline, the new nick came online.
            self.server.monitor_offline(&current);
            self.server.monitor_online(nick, &self.entry.hostmask());
        } else {
            self.maybe_register();
        }
    }

    /// Announce a nick change to the client itself and everyone sharing a channel.
    fn broadcast_nick_change(&self, old: &str, new: &str) {
        let (user, host) = {
            let d = self.entry.data.lock();
            (d.user.clone(), d.host.clone())
        };
        let body = Line::user(old, &user, &host)
            .command("NICK")
            .trailing(new)
            .body();
        let event = self.event(body);
        self.deliver_self(&event);
        self.propagate(&event, None, false);
        // draft/event-playback: the nick change appears in each shared
        // channel's history.
        let channels = self.entry.data.lock().channels.clone();
        for folded in &channels {
            if let Some(channel) = self.server.find_channel(folded) {
                let display = channel.data.lock().name.clone();
                self.server.record_channel_event(
                    folded,
                    &display,
                    &format!("{old}!{user}@{host}"),
                    MessageKind::Nick,
                    new.to_owned(),
                );
            }
        }
    }

    fn cmd_user(&mut self, params: &[&str]) {
        if self.registered {
            self.numeric(ERR_ALREADYREGISTERED, &[], Some("You may not reregister"));
            return;
        }
        if params.len() < 4 {
            self.need_more_params("USER");
            return;
        }
        let username: String = params[0].chars().take(10).collect();
        let realname = params[3];
        {
            let mut d = self.entry.data.lock();
            // No ident (RFC 1413) lookup is performed, so the username is
            // marked untrusted with the conventional '~' prefix.
            d.user = format!("~{username}");
            d.realname = realname.to_owned();
        }
        self.has_user = true;
        self.maybe_register();
    }

    fn cmd_ping(&mut self, params: &[&str]) {
        let token = params.first().copied().unwrap_or("");
        self.send(
            Line::server(self.server_name())
                .command("PONG")
                .param(self.server_name())
                .trailing(token),
        );
    }

    fn cmd_quit(&mut self, params: &[&str]) {
        let reason = params.first().copied().unwrap_or("Client Quit");
        self.quit = Some(format!("Quit: {reason}"));
    }

    fn cmd_setname(&mut self, params: &[&str]) {
        let Some(&newname) = params.first() else {
            self.need_more_params("SETNAME");
            return;
        };
        self.entry.data.lock().realname = newname.to_owned();
        let (nick, user, host) = self.identity();
        let body = Line::user(&nick, &user, &host)
            .command("SETNAME")
            .trailing(newname)
            .body();
        let event = self.event(body);
        // Echo to self and to co-members that negotiated `setname`.
        self.propagate_monitored(&event, Cap::SetName, true);
        // Keep linked peers' view of the realname current (S2S).
        self.server.propagate_setname(self.entry.id, newname);
    }

    // ---------------------------------------------------------- channels ---

    fn cmd_join(&mut self, params: &[&str]) {
        let Some(&chanlist) = params.first() else {
            self.need_more_params("JOIN");
            return;
        };
        // `JOIN 0` means "part every channel I am in" (RFC 2812 §3.2.1).
        if chanlist == "0" {
            let mine: Vec<String> = self.entry.data.lock().channels.iter().cloned().collect();
            for folded in mine {
                let display = self
                    .server
                    .find_channel(&folded)
                    .map(|c| c.data.lock().name.clone());
                if let Some(display) = display {
                    self.part_one(&display, Some("Left all channels"));
                }
            }
            return;
        }
        let keys: Vec<&str> = params
            .get(1)
            .map(|k| k.split(',').collect())
            .unwrap_or_default();
        for (i, name) in chanlist.split(',').enumerate() {
            self.join_one(name, keys.get(i).copied());
        }
    }

    fn join_one(&mut self, name: &str, key: Option<&str>) {
        if !casemap::is_valid_channel(name) {
            self.numeric(ERR_NOSUCHCHANNEL, &[name], Some("No such channel"));
            return;
        }
        let folded = self.server.fold(name);
        {
            let d = self.entry.data.lock();
            if d.channels.contains(&folded) {
                return; // already a member
            }
            // Per-client channel cap (memory-amplification guard); opers bypass.
            if !d.oper && d.channels.len() >= self.server.info.max_channels {
                drop(d);
                self.numeric(
                    ERR_TOOMANYCHANNELS,
                    &[name],
                    Some("You have joined too many channels"),
                );
                return;
            }
        }

        // `_join_guard` keeps the channel unreapable until this JOIN finishes
        // inserting its member, closing the create/reap race (see `begin_join`).
        let (channel, created, _join_guard) = self.server.begin_join(&folded, name);

        // Enforce join restrictions (never for the creator of a fresh channel).
        // Operators bypass all; an invite bypasses `+i`.
        let hostmask = self.entry.hostmask();
        let folded_nick = self.server.fold(&self.entry.nick());
        let (is_oper, account) = {
            let d = self.entry.data.lock();
            (d.oper, d.account.clone())
        };
        if !created {
            let mut data = channel.data.lock();
            let invited = data.invited.contains(&folded_nick);
            let rejection: Option<(u16, &str)> = if !is_oper
                && data.is_banned(&hostmask, account.as_deref())
                && !data.is_excepted(&hostmask, account.as_deref())
            {
                Some((ERR_BANNEDFROMCHAN, "Cannot join channel (+b)"))
            } else if data.modes.invite_only
                && !invited
                && !is_oper
                && !data.matches_invex(&hostmask, account.as_deref())
            {
                Some((ERR_INVITEONLYCHAN, "Cannot join channel (+i)"))
            } else if data.modes.key.is_some() && data.modes.key.as_deref() != key {
                Some((ERR_BADCHANNELKEY, "Cannot join channel (+k)"))
            } else if data.modes.limit.is_some_and(|l| data.members.len() >= l) {
                Some((ERR_CHANNELISFULL, "Cannot join channel (+l)"))
            } else {
                None
            };
            if let Some((code, text)) = rejection {
                let display = data.name.clone();
                drop(data);
                self.numeric(code, &[&display], Some(text));
                return;
            }
            data.invited.remove(&folded_nick); // consume the invite
        }

        // Let WASM plugins veto the join (fail-open; the guard reaps a channel
        // this rejected join would have created).
        if let Some(plugin_host) = self.server.plugins() {
            if plugin_host.on_join(&self.entry.nick(), name) == crate::plugin::Verdict::Block {
                self.fail(
                    "JOIN",
                    "JOIN_BLOCKED",
                    &[name],
                    "Join blocked by server policy",
                );
                return;
            }
        }

        // The creator, or the registered founder, becomes channel operator.
        let is_founder = match self.account() {
            Some(account) => self
                .server
                .channel_founder(&folded)
                .is_some_and(|f| self.server.fold(&f) == self.server.fold(&account)),
            None => false,
        };
        let display = {
            let mut data = channel.data.lock();
            data.members.insert(
                self.entry.id,
                Member {
                    entry: self.entry.clone(),
                    prefix: MemberPrefix {
                        op: created || is_founder,
                        voice: false,
                    },
                },
            );
            data.name.clone()
        };
        self.entry.data.lock().channels.insert(folded);

        // Broadcast JOIN, with the `extended-join` suffix for capable recipients.
        let (nick, user, host, account, realname) = {
            let d = self.entry.data.lock();
            (
                d.nick.clone(),
                d.user.clone(),
                d.host.clone(),
                d.account.clone(),
                d.realname.clone(),
            )
        };
        let account_token = account.clone().unwrap_or_else(|| "*".to_owned());
        let body = Line::user(&nick, &user, &host)
            .command("JOIN")
            .param(&display)
            .body();
        let event = Event::new(body)
            .with_time(self.now_time())
            .with_account(account)
            .with_suffix(Cap::ExtendedJoin, format!(" {account_token} :{realname}"));
        // The joiner's own echo goes through the session so a labeled JOIN is
        // answered with a labeled echo (labeled-response).
        deliver::to_channel(&channel, &event, Some(self.entry.id));
        self.deliver_self(&event);
        self.server.record_channel_event(
            &self.server.fold(&display),
            &display,
            &format!("{nick}!{user}@{host}"),
            MessageKind::Join,
            String::new(),
        );

        self.send_topic_on_join(&channel, &display);
        // no-implicit-names: clients that negotiated the cap skip the automatic
        // NAMES burst on JOIN (they still get it from an explicit NAMES).
        if !self.entry.caps().has(Cap::NoImplicitNames) {
            self.send_names(&channel, &display);
        }

        // Tell linked peers a local user joined this channel (with its prefix,
        // so a creator/founder's op status is visible network-wide).
        self.server.propagate_sjoin(
            self.entry.id,
            &display,
            MemberPrefix {
                op: created || is_founder,
                voice: false,
            },
        );
    }

    fn cmd_part(&mut self, params: &[&str]) {
        let Some(&chanlist) = params.first() else {
            self.need_more_params("PART");
            return;
        };
        let reason = params.get(1).copied();
        for name in chanlist.split(',') {
            self.part_one(name, reason);
        }
    }

    fn part_one(&mut self, name: &str, reason: Option<&str>) {
        let folded = self.server.fold(name);
        let Some(channel) = self.server.find_channel(&folded) else {
            self.numeric(ERR_NOSUCHCHANNEL, &[name], Some("No such channel"));
            return;
        };
        let display = {
            let data = channel.data.lock();
            if !data.has_member(self.entry.id) {
                let display = data.name.clone();
                drop(data);
                self.numeric(
                    ERR_NOTONCHANNEL,
                    &[&display],
                    Some("You're not on that channel"),
                );
                return;
            }
            data.name.clone()
        };

        let (nick, user, host) = self.identity();
        let mut line = Line::user(&nick, &user, &host)
            .command("PART")
            .param(&display);
        if let Some(reason) = reason {
            line = line.trailing(reason);
        }
        let event = self.event(line.body());
        // Broadcast to everyone (including the parting client) before removal.
        deliver::to_channel(&channel, &event, Some(self.entry.id));
        self.deliver_self(&event);
        self.server.record_channel_event(
            &folded,
            &display,
            &format!("{nick}!{user}@{host}"),
            MessageKind::Part,
            reason.unwrap_or("").to_owned(),
        );

        channel.data.lock().members.remove(&self.entry.id);
        self.entry.data.lock().channels.remove(&folded);
        self.server
            .propagate_spart(self.entry.id, &display, reason.unwrap_or("Leaving"));
        self.server.reap_channel(&folded);
    }

    fn cmd_topic(&mut self, params: &[&str]) {
        let Some(&name) = params.first() else {
            self.need_more_params("TOPIC");
            return;
        };
        let folded = self.server.fold(name);
        let Some(channel) = self.server.find_channel(&folded) else {
            self.numeric(ERR_NOSUCHCHANNEL, &[name], Some("No such channel"));
            return;
        };

        match params.get(1) {
            None => {
                let (display, topic) = {
                    let d = channel.data.lock();
                    (d.name.clone(), d.topic.clone())
                };
                match topic {
                    Some(t) => {
                        self.numeric(RPL_TOPIC, &[&display], Some(&t.text));
                        self.numeric(
                            RPL_TOPICWHOTIME,
                            &[&display, &t.set_by, &t.set_at.to_string()],
                            None,
                        );
                    }
                    None => self.numeric(RPL_NOTOPIC, &[&display], Some("No topic is set")),
                }
            }
            Some(&new_topic) => {
                // TOPICLEN is advertised, so it is enforced.
                let new_topic = truncate_chars(new_topic, MAX_TOPIC_LEN);
                let (display, is_member, is_op, topic_lock) = {
                    let d = channel.data.lock();
                    let m = d.member(self.entry.id);
                    (
                        d.name.clone(),
                        m.is_some(),
                        m.is_some_and(|m| m.prefix.op),
                        d.modes.topic_lock,
                    )
                };
                if !is_member {
                    self.numeric(
                        ERR_NOTONCHANNEL,
                        &[&display],
                        Some("You're not on that channel"),
                    );
                    return;
                }
                if topic_lock && !is_op {
                    self.numeric(
                        ERR_CHANOPRIVSNEEDED,
                        &[&display],
                        Some("You're not channel operator"),
                    );
                    return;
                }
                // Let WASM plugins veto the topic change (fail-open).
                if let Some(plugin_host) = self.server.plugins() {
                    if plugin_host.on_topic(&self.entry.nick(), &display, new_topic)
                        == crate::plugin::Verdict::Block
                    {
                        self.fail(
                            "TOPIC",
                            "TOPIC_BLOCKED",
                            &[display.as_str()],
                            "Topic change blocked by server policy",
                        );
                        return;
                    }
                }
                let set_at = now_unix();
                let nick = self.entry.nick();
                {
                    let mut d = channel.data.lock();
                    d.topic = if new_topic.is_empty() {
                        None
                    } else {
                        Some(Topic {
                            text: new_topic.to_owned(),
                            set_by: nick.clone(),
                            set_at,
                        })
                    };
                }
                let (nick, user, host) = self.identity();
                let body = Line::user(&nick, &user, &host)
                    .command("TOPIC")
                    .param(&display)
                    .trailing(new_topic)
                    .body();
                let event = self.event(body);
                deliver::to_channel(&channel, &event, Some(self.entry.id));
                self.deliver_self(&event);
                self.server.record_channel_event(
                    &folded,
                    &display,
                    &self.entry.hostmask(),
                    MessageKind::Topic,
                    new_topic.to_owned(),
                );
                self.server.persist_registered(&folded);
                self.server
                    .propagate_topic(self.entry.id, &display, &nick, set_at, new_topic);
            }
        }
    }

    // ----------------------------------------------------------- messaging ---

    fn cmd_message(&mut self, params: &[&str], is_notice: bool, client_tags: Option<String>) {
        self.cmd_message_inner(params, is_notice, client_tags, None);
    }

    /// The message path. `batch_ref`, when set, groups the delivered line into
    /// that batch for `draft/multiline` recipients (see [`Session::flush_multiline`]).
    fn cmd_message_inner(
        &mut self,
        params: &[&str],
        is_notice: bool,
        client_tags: Option<String>,
        batch_ref: Option<&str>,
    ) {
        let Some(&target) = params.first() else {
            if !is_notice {
                self.numeric(ERR_NORECIPIENT, &[], Some("No recipient given"));
            }
            return;
        };
        let Some(&text) = params.get(1) else {
            if !is_notice {
                self.numeric(ERR_NOTEXTTOSEND, &[], Some("No text to send"));
            }
            return;
        };
        crate::metrics::Metrics::incr(&self.server.metrics.messages_total);
        let command = if is_notice { "NOTICE" } else { "PRIVMSG" };
        let kind = if is_notice {
            MessageKind::Notice
        } else {
            MessageKind::PrivMsg
        };
        let (nick, user, host) = self.identity();
        // Compute the sender's hostmask once; it feeds the history record, the
        // channel relay, and the DM relay below.
        let source_mask = format!("{nick}!{user}@{host}");
        let echo = self.entry.caps().has(Cap::EchoMessage);
        let is_bot = self.entry.data.lock().bot;
        let msgid = self.server.history.next_msgid();
        let now_ms = state::now_millis();
        let account = self.account();

        // STATUSMSG: a leading `@`/`+` on a channel target restricts delivery
        // to members holding at least that prefix (ops, or ops+voiced).
        let (status, target) = match target.split_at_checked(1) {
            Some(("@", rest)) if casemap::is_valid_channel(rest) => (Some(true), rest),
            Some(("+", rest)) if casemap::is_valid_channel(rest) => (Some(false), rest),
            _ => (None, target),
        };

        if casemap::is_valid_channel(target) {
            let folded = self.server.fold(target);
            let Some(channel) = self.server.find_channel(&folded) else {
                if !is_notice {
                    self.numeric(ERR_NOSUCHNICK, &[target], Some("No such nick/channel"));
                }
                return;
            };
            let display = {
                let data = channel.data.lock();
                let member = data.member(self.entry.id);
                if data.modes.no_external && member.is_none() {
                    let display = data.name.clone();
                    drop(data);
                    if !is_notice {
                        self.numeric(
                            ERR_CANNOTSENDTOCHAN,
                            &[&display],
                            Some("Cannot send to channel"),
                        );
                    }
                    return;
                }
                if data.modes.moderated && !member.is_some_and(|m| m.prefix.op || m.prefix.voice) {
                    let display = data.name.clone();
                    drop(data);
                    if !is_notice {
                        self.numeric(
                            ERR_CANNOTSENDTOCHAN,
                            &[&display],
                            Some("Cannot send to channel (+m)"),
                        );
                    }
                    return;
                }
                data.name.clone()
            };

            // Let WASM plugins veto the message before it is recorded or sent.
            if let Some(plugin_host) = self.server.plugins() {
                if plugin_host.on_channel_message(&nick, &display, text)
                    == crate::plugin::Verdict::Block
                {
                    if !is_notice {
                        self.fail(
                            command,
                            "MSG_BLOCKED",
                            &[&display],
                            "Message blocked by server policy",
                        );
                    }
                    return;
                }
            }

            // Record for chathistory before delivery so the stored msgid matches
            // what recipients see live. STATUSMSG stays out of the shared
            // history: replaying it to the whole channel would leak it.
            if status.is_none() {
                self.server.history.record(
                    &folded,
                    Arc::new(StoredMessage {
                        msgid: msgid.clone(),
                        time_ms: now_ms,
                        source: source_mask.clone(),
                        account: account.clone(),
                        kind,
                        target: display.clone(),
                        text: text.to_owned(),
                    }),
                );
            }

            let wire_target = match status {
                Some(true) => format!("@{display}"),
                Some(false) => format!("+{display}"),
                None => display.clone(),
            };
            let body = Line::user(&nick, &user, &host)
                .command(command)
                .param(&wire_target)
                .trailing(text)
                .body();
            let mut event = Event::new(body)
                .with_time(state::format_server_time(now_ms))
                .with_account(account)
                .with_msgid(msgid.clone())
                .with_bot(is_bot);
            if let Some(tags) = client_tags.clone() {
                event = event.with_client_tags(tags);
            }
            if let Some(reference) = batch_ref {
                event = event.with_batch(Cap::Multiline, reference.to_owned());
            }
            match status {
                Some(op_only) => {
                    // Deliver to the prefixed members; echo-message echoes to
                    // the sender regardless of its own prefix.
                    deliver::to_channel_status(&channel, &event, op_only, Some(self.entry.id));
                }
                None => deliver::to_channel(&channel, &event, Some(self.entry.id)),
            }
            // The sender's own copy goes through the session, so a labeled
            // PRIVMSG gets a labeled echo instead of a bare ACK.
            if echo {
                self.deliver_self(&event);
            }
            // Fan out to peers that have members in this channel, carrying our
            // msgid/time/tags so every server shows the same message identity.
            self.server.relay_channel_message(
                &source_mask,
                &wire_target,
                is_notice,
                Some(msgid),
                Some(now_ms),
                client_tags,
                text,
                None,
            );
        } else {
            let folded = self.server.fold(target);
            let Some(dest) = self.server.find_client(&folded) else {
                // Not local: relay to a remote user over the S2S link if known.
                if let Some(remote) = self.server.find_remote_user(&folded) {
                    // Record the outbound DM so CHATHISTORY covers cross-server
                    // conversations from this side too.
                    self.server.history.record(
                        &pair_key(&self.server.fold(&nick), &folded),
                        Arc::new(StoredMessage {
                            msgid: msgid.clone(),
                            time_ms: now_ms,
                            source: source_mask.clone(),
                            account: account.clone(),
                            kind,
                            target: remote.nick.clone(),
                            text: text.to_owned(),
                        }),
                    );
                    let relayed = crate::s2s::LinkMessage::UserMessage {
                        source: source_mask.clone(),
                        target: remote.nick.clone(),
                        notice: is_notice,
                        msgid: Some(msgid.clone()),
                        time_ms: Some(now_ms),
                        tags: client_tags.clone(),
                        text: text.to_owned(),
                    };
                    self.server
                        .send_towards(&remote.server_sid, relayed.to_line());
                    if echo {
                        let body = Line::user(&nick, &user, &host)
                            .command(command)
                            .param(&remote.nick)
                            .trailing(text)
                            .body();
                        let mut event = Event::new(body)
                            .with_time(state::format_server_time(now_ms))
                            .with_account(account)
                            .with_msgid(msgid)
                            .with_bot(is_bot);
                        if let Some(tags) = client_tags {
                            event = event.with_client_tags(tags);
                        }
                        self.deliver_self(&event);
                    }
                    if !is_notice {
                        if let Some(away) = &remote.away {
                            self.numeric(RPL_AWAY, &[&remote.nick], Some(away));
                        }
                    }
                } else if !is_notice {
                    self.numeric(ERR_NOSUCHNICK, &[target], Some("No such nick/channel"));
                }
                return;
            };
            let dest_nick = dest.nick();
            // Record the DM under the private conversation key (both parties can
            // replay it via CHATHISTORY of the other's nick).
            self.server.history.record(
                &pair_key(&self.server.fold(&nick), &self.server.fold(&dest_nick)),
                Arc::new(StoredMessage {
                    msgid: msgid.clone(),
                    time_ms: now_ms,
                    source: source_mask.clone(),
                    account: account.clone(),
                    kind,
                    target: dest_nick.clone(),
                    text: text.to_owned(),
                }),
            );
            let body = Line::user(&nick, &user, &host)
                .command(command)
                .param(&dest_nick)
                .trailing(text)
                .body();
            let mut event = Event::new(body)
                .with_time(state::format_server_time(now_ms))
                .with_account(account)
                .with_msgid(msgid)
                .with_bot(is_bot);
            if let Some(tags) = client_tags {
                event = event.with_client_tags(tags);
            }
            if let Some(reference) = batch_ref {
                event = event.with_batch(Cap::Multiline, reference.to_owned());
            }
            // A SILENCE'd sender is dropped without telling either side (the
            // point of a server-side ignore).
            if !dest.silences(&source_mask) {
                deliver::to_client(&dest, &event);
            }
            if echo {
                self.deliver_self(&event);
            }
            if !is_notice {
                if let Some(away) = dest.data.lock().away.clone() {
                    self.numeric(RPL_AWAY, &[&dest_nick], Some(&away));
                }
            }
        }
    }

    fn cmd_away(&mut self, params: &[&str]) {
        let (away_msg, ack) = match params.first() {
            Some(&msg) if !msg.is_empty() => (
                // AWAYLEN is advertised, so it is enforced.
                Some(truncate_chars(msg, MAX_AWAY_LEN).to_owned()),
                "You have been marked as being away",
            ),
            _ => (None, "You are no longer marked as being away"),
        };
        self.entry.data.lock().away = away_msg.clone();
        let code = if away_msg.is_some() {
            RPL_NOWAWAY
        } else {
            RPL_UNAWAY
        };
        self.numeric(code, &[], Some(ack));

        // draft/pre-away: a pre-registration AWAY only records the status — the
        // user is not yet in any channel, nor introduced to linked peers, so
        // there is nothing to notify (and the change in nick status, once the
        // user registers, is reported by the normal registration burst).
        if !self.registered {
            return;
        }

        // away-notify: tell capable co-members about the change.
        let (nick, user, host) = self.identity();
        let mut line = Line::user(&nick, &user, &host).command("AWAY");
        if let Some(msg) = &away_msg {
            line = line.trailing(msg);
        }
        let event = self.event(line.body());
        self.propagate_monitored(&event, Cap::AwayNotify, false);
        // Sync the away state to linked peers (remote WHOIS / away-notify).
        self.server
            .propagate_away(self.entry.id, away_msg.as_deref());
    }

    // -------------------------------------------------------------- queries ---

    /// `TAGMSG <target>` — relay a client's message tags (e.g. `+typing`,
    /// `+draft/reply`, `+draft/react`) to a channel or user with no message body.
    /// Only recipients with `message-tags` receive it.
    fn cmd_tagmsg(&mut self, msg: &Message<'_>) {
        let params = msg.params.as_slice();
        let Some(&target) = params.first() else {
            self.need_more_params("TAGMSG");
            return;
        };
        let Some(tagstr) = client_tag_string(msg) else {
            return; // no client tags to relay — nothing to do
        };
        let (nick, user, host) = self.identity();
        let source_mask = format!("{nick}!{user}@{host}");
        let echo = self.entry.caps().has(Cap::EchoMessage);
        let is_bot = self.entry.data.lock().bot;

        if casemap::is_valid_channel(target) {
            let folded = self.server.fold(target);
            let Some(channel) = self.server.find_channel(&folded) else {
                self.numeric(ERR_NOSUCHNICK, &[target], Some("No such nick/channel"));
                return;
            };
            let (display, blocked) = {
                let d = channel.data.lock();
                let member = d.member(self.entry.id);
                (d.name.clone(), d.modes.no_external && member.is_none())
            };
            if blocked {
                self.numeric(
                    ERR_CANNOTSENDTOCHAN,
                    &[&display],
                    Some("Cannot send to channel"),
                );
                return;
            }
            let event = Event::new(format!(":{source_mask} TAGMSG {display}"))
                .with_client_tags(tagstr.clone())
                .with_time(self.now_time())
                .with_account(self.account())
                .with_bot(is_bot);
            deliver::to_channel_capped(&channel, &event, Cap::MessageTags, Some(self.entry.id));
            if echo && self.entry.caps().has(Cap::MessageTags) {
                self.deliver_self(&event);
            }
            // Members on linked servers get it too (typing/react/reply are
            // useless if they stop at the server boundary).
            self.server
                .relay_tagmsg(&source_mask, &display, &tagstr, None);
        } else {
            let folded = self.server.fold(target);
            let Some(dest) = self.server.find_client(&folded) else {
                // Not local: route it to the user's server over S2S.
                if let Some(remote) = self.server.find_remote_user(&folded) {
                    self.server.send_tagmsg_towards(
                        &remote.server_sid,
                        &source_mask,
                        &remote.nick,
                        &tagstr,
                    );
                    if echo && self.entry.caps().has(Cap::MessageTags) {
                        let event = Event::new(format!(":{source_mask} TAGMSG {}", remote.nick))
                            .with_client_tags(tagstr)
                            .with_time(self.now_time())
                            .with_account(self.account())
                            .with_bot(is_bot);
                        self.deliver_self(&event);
                    }
                    return;
                }
                self.numeric(ERR_NOSUCHNICK, &[target], Some("No such nick/channel"));
                return;
            };
            let event = Event::new(format!(":{source_mask} TAGMSG {}", dest.nick()))
                .with_client_tags(tagstr)
                .with_time(self.now_time())
                .with_account(self.account())
                .with_bot(is_bot);
            if dest.caps().has(Cap::MessageTags) {
                deliver::to_client(&dest, &event);
            }
            if echo && dest.id != self.entry.id && self.entry.caps().has(Cap::MessageTags) {
                self.deliver_self(&event);
            }
        }
    }

    /// Whether this client may see `channel`'s membership in a listing
    /// (NAMES/WHO). A secret (`+s`) channel hides its members from anyone who is
    /// not a member; operators may always see.
    fn may_list_channel(&self, channel: &Arc<ChannelEntry>) -> bool {
        let (secret, is_member) = {
            let d = channel.data.lock();
            (d.modes.secret, d.members.contains_key(&self.entry.id))
        };
        !secret || is_member || self.entry.data.lock().oper
    }

    fn cmd_names(&mut self, params: &[&str]) {
        let Some(&target) = params.first() else {
            self.numeric(RPL_ENDOFNAMES, &["*"], Some("End of /NAMES list"));
            return;
        };
        for name in target.split(',') {
            let folded = self.server.fold(name);
            match self.server.find_channel(&folded) {
                Some(channel) if self.may_list_channel(&channel) => {
                    let display = channel.data.lock().name.clone();
                    self.send_names(&channel, &display);
                }
                // Unknown channel, or a secret channel the requester cannot see:
                // reveal nothing beyond the terminator.
                _ => self.numeric(RPL_ENDOFNAMES, &[name], Some("End of /NAMES list")),
            }
        }
    }

    fn send_topic_on_join(&self, channel: &Arc<ChannelEntry>, display: &str) {
        let topic = channel.data.lock().topic.clone();
        if let Some(t) = topic {
            self.numeric(RPL_TOPIC, &[display], Some(&t.text));
            self.numeric(
                RPL_TOPICWHOTIME,
                &[display, &t.set_by, &t.set_at.to_string()],
                None,
            );
        }
    }

    fn send_names(&self, channel: &Arc<ChannelEntry>, display: &str) {
        let multi = self.entry.caps().has(Cap::MultiPrefix);
        let userhost = self.entry.caps().has(Cap::UserhostInNames);
        // Channel status symbol: `@` marks a secret (+s) channel, `=` public.
        let symbol = if channel.data.lock().modes.secret {
            "@"
        } else {
            "="
        };

        let mut names: Vec<String> = Vec::new();
        for (entry, prefix) in channel.member_snapshot() {
            let d = entry.data.lock();
            names.push(if userhost {
                format!("{}{}!{}@{}", prefix.render(multi), d.nick, d.user, d.host)
            } else {
                format!("{}{}", prefix.render(multi), d.nick)
            });
        }
        for member in channel.remote_member_snapshot() {
            names.push(if userhost {
                format!("{}{}", member.prefix.render(multi), member.hostmask())
            } else {
                format!("{}{}", member.prefix.render(multi), member.nick)
            });
        }

        let mut chunk = String::new();
        for name in &names {
            if !chunk.is_empty() && chunk.len() + 1 + name.len() > 400 {
                self.numeric(RPL_NAMREPLY, &[symbol, display], Some(&chunk));
                chunk.clear();
            }
            if !chunk.is_empty() {
                chunk.push(' ');
            }
            chunk.push_str(name);
        }
        if !chunk.is_empty() {
            self.numeric(RPL_NAMREPLY, &[symbol, display], Some(&chunk));
        }
        self.numeric(RPL_ENDOFNAMES, &[display], Some("End of /NAMES list"));
    }

    fn cmd_who(&mut self, params: &[&str]) {
        // A bare WHO is a mask query over everyone, and must still terminate
        // with RPL_ENDOFWHO like every other form.
        let target = params.first().copied().unwrap_or("0");
        // Second parameter: WHOX `%<fields>[,querytype]` selects the extended
        // RPL_WHOSPCRPL (354) form; a legacy `o` before any `%` limits the
        // result to IRC operators.
        let second = params.get(1).copied().unwrap_or("");
        let whox = parse_whox(second);
        let opers_only = second.split('%').next().unwrap_or("").contains('o');
        let reply = |s: &Self, chan: &str, row: &WhoRow| {
            if opers_only && !row.oper {
                return;
            }
            match &whox {
                Some(req) => s.who_reply_x(chan, row, req),
                None => s.who_reply(chan, row),
            }
        };

        if casemap::is_valid_channel(target) {
            let folded = self.server.fold(target);
            if let Some(channel) = self.server.find_channel(&folded) {
                if self.may_list_channel(&channel) {
                    let display = channel.data.lock().name.clone();
                    for (entry, prefix) in channel.member_snapshot() {
                        reply(self, &display, &self.who_row_local(&entry, prefix));
                    }
                    // Members on linked servers are part of the channel too.
                    for member in channel.remote_member_snapshot() {
                        if let Some(user) = self
                            .server
                            .find_remote_user(&self.server.fold(&member.nick))
                        {
                            reply(self, &display, &Self::who_row_remote(&user, member.prefix));
                        }
                    }
                }
            }
        } else if !target.contains('*') && !target.contains('?') && target != "0" {
            // An exact nickname (local or remote).
            let folded = self.server.fold(target);
            if let Some(entry) = self.server.find_client(&folded) {
                reply(
                    self,
                    "*",
                    &self.who_row_local(&entry, MemberPrefix::default()),
                );
            } else if let Some(user) = self.server.find_remote_user(&folded) {
                reply(
                    self,
                    "*",
                    &Self::who_row_remote(&user, MemberPrefix::default()),
                );
            }
        } else {
            // Mask WHO (`0` means everyone). Matches nick, username, host, or
            // realname. Invisible (+i) users are hidden from non-operators who
            // do not share a channel with them.
            let mask = if target == "0" { "*" } else { target };
            let (requester_oper, requester_channels) = {
                let d = self.entry.data.lock();
                (d.oper, d.channels.clone())
            };
            for entry in self.server.clients_snapshot() {
                let visible = {
                    let d = entry.data.lock();
                    if !d.registered {
                        continue;
                    }
                    if !(crate::mask::matches(mask, &d.nick)
                        || crate::mask::matches(mask, &d.user)
                        || crate::mask::matches(mask, &d.host)
                        || crate::mask::matches(mask, &d.realname))
                    {
                        continue;
                    }
                    !d.invisible
                        || requester_oper
                        || entry.id == self.entry.id
                        || d.channels.iter().any(|c| requester_channels.contains(c))
                };
                if visible {
                    reply(
                        self,
                        "*",
                        &self.who_row_local(&entry, MemberPrefix::default()),
                    );
                }
            }
            for user in self.server.remote_users_snapshot() {
                if crate::mask::matches(mask, &user.nick)
                    || crate::mask::matches(mask, &user.user)
                    || crate::mask::matches(mask, &user.host)
                    || crate::mask::matches(mask, &user.realname)
                {
                    reply(
                        self,
                        "*",
                        &Self::who_row_remote(&user, MemberPrefix::default()),
                    );
                }
            }
        }
        self.numeric(RPL_ENDOFWHO, &[target], Some("End of /WHO list"));
    }

    /// Build a WHO result row for a local client.
    fn who_row_local(&self, entry: &Arc<ClientEntry>, prefix: MemberPrefix) -> WhoRow {
        let can_see_ip = self.entry.data.lock().oper || entry.id == self.entry.id;
        let d = entry.data.lock();
        WhoRow {
            nick: d.nick.clone(),
            user: d.user.clone(),
            host: d.host.clone(),
            ip: can_see_ip.then(|| d.real_ip.clone()),
            server: self.server_name().to_owned(),
            realname: d.realname.clone(),
            away: d.away.is_some(),
            oper: d.oper,
            bot: d.bot,
            account: d.account.clone(),
            idle: now_unix().saturating_sub(d.last_active),
            hops: 0,
            prefix,
        }
    }

    /// Build a WHO result row for a user on a linked server.
    fn who_row_remote(user: &state::RemoteUser, prefix: MemberPrefix) -> WhoRow {
        WhoRow {
            nick: user.nick.clone(),
            user: user.user.clone(),
            host: user.host.clone(),
            ip: None,
            server: user.server_sid.clone(),
            realname: user.realname.clone(),
            away: user.away.is_some(),
            oper: false,
            bot: user.bot,
            account: user.account.clone(),
            idle: 0,
            hops: 1,
            prefix,
        }
    }

    /// Emit an extended WHOX reply (`RPL_WHOSPCRPL`, 354) with only the requested
    /// fields, in the canonical WHOX order (realname, if requested, is trailing).
    fn who_reply_x(&self, channel: &str, row: &WhoRow, req: &WhoxRequest) {
        let multi = self.entry.caps().has(Cap::MultiPrefix);
        let has = |c: char| req.fields.contains(c);
        let mut fields: Vec<String> = Vec::new();
        if has('t') {
            fields.push(req.querytype.clone().unwrap_or_else(|| "0".to_owned()));
        }
        if has('c') {
            fields.push(channel.to_owned());
        }
        if has('u') {
            fields.push(row.user.clone());
        }
        if has('i') {
            fields.push(
                row.ip
                    .clone()
                    .unwrap_or_else(|| "255.255.255.255".to_owned()),
            );
        }
        if has('h') {
            fields.push(row.host.clone());
        }
        if has('s') {
            fields.push(row.server.clone());
        }
        if has('n') {
            fields.push(row.nick.clone());
        }
        if has('f') {
            fields.push(row.flags(multi));
        }
        if has('d') {
            fields.push(row.hops.to_string());
        }
        if has('l') {
            fields.push(row.idle.to_string());
        }
        if has('a') {
            fields.push(row.account.clone().unwrap_or_else(|| "0".to_owned()));
        }
        if has('o') {
            fields.push(if row.prefix.op { "999" } else { "n/a" }.to_owned());
        }
        let realname = has('r').then(|| row.realname.clone());
        let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        self.numeric(RPL_WHOSPCRPL, &refs, realname.as_deref());
    }

    fn who_reply(&self, channel: &str, row: &WhoRow) {
        let multi = self.entry.caps().has(Cap::MultiPrefix);
        let flags = row.flags(multi);
        let hop_real = format!("{} {}", row.hops, row.realname);
        self.numeric(
            RPL_WHOREPLY,
            &[
                channel,
                &row.user,
                &row.host,
                &row.server,
                &row.nick,
                &flags,
            ],
            Some(&hop_real),
        );
    }

    /// `WHOIS [<server>] <nicklist>` — the optional first parameter targets a
    /// server (we answer for the whole network anyway, so it is only skipped),
    /// and the nick list may be comma-separated.
    fn cmd_whois(&mut self, params: &[&str]) {
        if params.is_empty() {
            self.numeric(ERR_NONICKNAMEGIVEN, &[], Some("No nickname given"));
            return;
        }
        // Two parameters means `WHOIS <server> <nick>`: the nick is the last.
        let list = params.last().copied().unwrap_or_default();
        for nick in list.split(',').filter(|n| !n.is_empty()) {
            self.whois_one(nick);
        }
    }

    fn whois_one(&mut self, target: &str) {
        let folded = self.server.fold(target);
        let Some(entry) = self.server.find_client(&folded) else {
            // Fall back to a remote (linked) user if we know one.
            if let Some(remote) = self.server.find_remote_user(&folded) {
                self.numeric(
                    RPL_WHOISUSER,
                    &[&remote.nick, &remote.user, &remote.host, "*"],
                    Some(&remote.realname),
                );
                if remote.bot {
                    self.numeric(RPL_WHOISBOT, &[&remote.nick], Some("is a bot"));
                }
                self.numeric(
                    RPL_WHOISSERVER,
                    &[&remote.nick, &remote.server_sid],
                    Some("remote server"),
                );
                if let Some(account) = &remote.account {
                    self.numeric(
                        RPL_WHOISACCOUNT,
                        &[&remote.nick, account],
                        Some("is logged in as"),
                    );
                }
                if remote.oper {
                    self.numeric(
                        RPL_WHOISOPERATOR,
                        &[&remote.nick],
                        Some("is an IRC operator"),
                    );
                }
                if let Some(away) = &remote.away {
                    self.numeric(RPL_AWAY, &[&remote.nick], Some(away));
                }
                self.numeric(RPL_ENDOFWHOIS, &[&remote.nick], Some("End of /WHOIS list"));
                return;
            }
            self.numeric(ERR_NOSUCHNICK, &[target], Some("No such nick/channel"));
            self.numeric(RPL_ENDOFWHOIS, &[target], Some("End of /WHOIS list"));
            return;
        };

        let (
            nick,
            user,
            host,
            real_ip,
            realname,
            away,
            account,
            channels,
            connected_at,
            last_active,
            target_oper,
            target_secure,
        ) = {
            let d = entry.data.lock();
            (
                d.nick.clone(),
                d.user.clone(),
                d.host.clone(),
                d.real_ip.clone(),
                d.realname.clone(),
                d.away.clone(),
                d.account.clone(),
                d.channels.clone(),
                d.connected_at,
                d.last_active,
                d.oper,
                d.secure,
            )
        };
        let requester_oper = self.entry.data.lock().oper;
        let is_self = entry.id == self.entry.id;
        let target_bot = entry.data.lock().bot;

        self.numeric(RPL_WHOISUSER, &[&nick, &user, &host, "*"], Some(&realname));
        if target_bot {
            self.numeric(RPL_WHOISBOT, &[&nick], Some("is a bot"));
        }

        // Operators (and the user themselves) see the real IP behind any cloak.
        if requester_oper || is_self {
            let actual = format!("{user}@{real_ip}");
            self.numeric(
                RPL_WHOISACTUALLY,
                &[&nick, &actual, &real_ip],
                Some("Is actually using host"),
            );
        }

        let mut chanlist = Vec::new();
        for folded in &channels {
            if let Some(channel) = self.server.find_channel(folded) {
                let data = channel.data.lock();
                // Secret channels stay hidden from non-members only: the target
                // themself, a co-member, and operators still see them.
                if data.modes.secret
                    && !is_self
                    && !requester_oper
                    && !data.has_member(self.entry.id)
                {
                    continue;
                }
                if let Some(member) = data.member(entry.id) {
                    chanlist.push(format!("{}{}", member.prefix.symbol(), data.name));
                }
            }
        }
        if !chanlist.is_empty() {
            self.numeric(RPL_WHOISCHANNELS, &[&nick], Some(&chanlist.join(" ")));
        }

        self.numeric(
            RPL_WHOISSERVER,
            &[&nick, self.server_name()],
            Some(&self.server.info.version),
        );
        if target_oper {
            self.numeric(RPL_WHOISOPERATOR, &[&nick], Some("is an IRC operator"));
        }
        if target_secure {
            self.numeric(
                RPL_WHOISSECURE,
                &[&nick],
                Some("is using a secure connection"),
            );
        }
        let idle = now_unix().saturating_sub(last_active);
        self.numeric(
            RPL_WHOISIDLE,
            &[&nick, &idle.to_string(), &connected_at.to_string()],
            Some("seconds idle, signon time"),
        );
        if let Some(account) = account {
            self.numeric(
                RPL_WHOISACCOUNT,
                &[&nick, &account],
                Some("is logged in as"),
            );
        }
        if let Some(away) = away {
            self.numeric(RPL_AWAY, &[&nick], Some(&away));
        }
        self.numeric(RPL_ENDOFWHOIS, &[&nick], Some("End of /WHOIS list"));
    }

    // ----------------------------------------------------------------- MODE ---

    fn cmd_mode(&mut self, params: &[&str]) {
        let Some(&target) = params.first() else {
            self.need_more_params("MODE");
            return;
        };
        if casemap::is_valid_channel(target) {
            self.channel_mode(target, &params[1..]);
        } else {
            self.user_mode(target, &params[1..]);
        }
    }

    fn user_mode(&mut self, target: &str, args: &[&str]) {
        if self.server.fold(target) != self.server.fold(&self.entry.nick()) {
            // A nick nobody holds is "no such nick", not "not your modes".
            let folded = self.server.fold(target);
            if self.server.presence_mask(&folded).is_none() {
                self.numeric(ERR_NOSUCHNICK, &[target], Some("No such nick/channel"));
                return;
            }
            self.numeric(
                ERR_USERSDONTMATCH,
                &[],
                Some("Cannot change mode for other users"),
            );
            return;
        }
        // Query form: `MODE <self>` reports the current user modes.
        let Some(&flags) = args.first() else {
            let modes = render_user_modes(&self.entry.data.lock());
            self.numeric(RPL_UMODEIS, &[&modes], None);
            return;
        };

        let mut changed = state::ModeAccum::default();
        let mut unknown: Option<char> = None;
        {
            let mut d = self.entry.data.lock();
            let mut adding = true;
            for c in flags.chars() {
                match c {
                    '+' => adding = true,
                    '-' => adding = false,
                    'i' if d.invisible != adding => {
                        d.invisible = adding;
                        changed.push(adding, 'i');
                    }
                    'w' if d.wallops != adding => {
                        d.wallops = adding;
                        changed.push(adding, 'w');
                    }
                    // Bot-mode (`+B`): a client self-declares as a bot. Freely
                    // settable and clearable, mirroring the IRCv3 spec's example.
                    c if c == BOT_UMODE => {
                        if d.bot != adding {
                            d.bot = adding;
                            changed.push(adding, BOT_UMODE);
                        }
                    }
                    // Users may de-op themselves but can only gain `+o` via OPER.
                    'o' if !adding && d.oper => {
                        d.oper = false;
                        changed.push(false, 'o');
                    }
                    'i' | 'w' | 'o' => {} // no-op change
                    other => unknown = Some(other),
                }
            }
        }
        if let Some(flag) = unknown {
            self.numeric(
                ERR_UMODEUNKNOWNFLAG,
                &[&flag.to_string()],
                Some("Unknown MODE flag"),
            );
        }
        if !changed.is_empty() {
            let (nick, user, host) = self.identity();
            self.send(
                Line::user(&nick, &user, &host)
                    .command("MODE")
                    .param(&nick)
                    .param(&changed.flags),
            );
            // Linked servers track oper status and invisibility (remote WHOIS,
            // LUSERS, oper-only visibility).
            self.server.propagate_umodes(self.entry.id, &changed.flags);
        }
    }

    /// Report one channel list mode (`+b`/`+e`/`+I`) and its terminator.
    fn send_list_mode(&self, channel: &Arc<ChannelEntry>, which: char) {
        let (display, entries) = {
            let d = channel.data.lock();
            let list = match which {
                'b' => &d.bans,
                'e' => &d.exceptions,
                _ => &d.invex,
            };
            (d.name.clone(), list.clone())
        };
        let (item, end, endmsg) = match which {
            'b' => (RPL_BANLIST, RPL_ENDOFBANLIST, "End of channel ban list"),
            'e' => (
                RPL_EXCEPTLIST,
                RPL_ENDOFEXCEPTLIST,
                "End of channel exception list",
            ),
            _ => (
                RPL_INVEXLIST,
                RPL_ENDOFINVEXLIST,
                "End of channel invite exception list",
            ),
        };
        for entry in &entries {
            self.numeric(
                item,
                &[
                    &display,
                    &entry.mask,
                    &entry.set_by,
                    &entry.set_at.to_string(),
                ],
                None,
            );
        }
        self.numeric(end, &[&display], Some(endmsg));
    }

    fn channel_mode(&mut self, target: &str, args: &[&str]) {
        let folded = self.server.fold(target);
        let Some(channel) = self.server.find_channel(&folded) else {
            self.numeric(ERR_NOSUCHCHANNEL, &[target], Some("No such channel"));
            return;
        };

        // Query: report current modes.
        if args.is_empty() {
            let (display, flags, margs, created) = {
                let d = channel.data.lock();
                let (flags, margs) = d.modes.render(false);
                (d.name.clone(), flags, margs, d.created_at)
            };
            let mut line = Line::server(self.server_name())
                .code(RPL_CHANNELMODEIS)
                .param(&self.nick_or_star())
                .param(&display)
                .param(&flags);
            for arg in &margs {
                line = line.param(arg);
            }
            self.send(line);
            self.numeric(RPL_CREATIONTIME, &[&display, &created.to_string()], None);
            return;
        }

        // A bare list mode with no mask is a *query*, e.g. `MODE #chan b`,
        // `MODE #chan +b`, or several at once (`MODE #chan +beI`). Allowed for
        // anyone; only a genuine list query (no arguments) takes this path.
        if args.len() == 1 {
            let letters: Vec<char> = args[0]
                .trim_start_matches('+')
                .chars()
                .filter(|c| matches!(c, 'b' | 'e' | 'I'))
                .collect();
            let only_list_modes = !letters.is_empty()
                && args[0].chars().all(|c| matches!(c, 'b' | 'e' | 'I' | '+'))
                && !args[0].starts_with('-');
            if only_list_modes {
                for which in letters {
                    self.send_list_mode(&channel, which);
                }
                return;
            }
        }

        // Setting modes requires channel-operator privilege.
        let (display, is_member, is_op) = {
            let d = channel.data.lock();
            let m = d.member(self.entry.id);
            (d.name.clone(), m.is_some(), m.is_some_and(|m| m.prefix.op))
        };
        if !is_member {
            self.numeric(
                ERR_NOTONCHANNEL,
                &[&display],
                Some("You're not on that channel"),
            );
            return;
        }
        if !is_op {
            self.numeric(
                ERR_CHANOPRIVSNEEDED,
                &[&display],
                Some("You're not channel operator"),
            );
            return;
        }
        self.apply_channel_modes(&channel, &display, args);
    }

    fn apply_channel_modes(&self, channel: &Arc<ChannelEntry>, display: &str, args: &[&str]) {
        let modestr = args[0];
        let mut rest = args[1..].iter().copied();
        let mut adding = true;
        let mut accum = state::ModeAccum::default();
        let mut applied_args: Vec<String> = Vec::new();
        // Wire form of the applied arguments for S2S: `o`/`v` targets travel as
        // network UIDs (nicks can differ transiently between servers), and a
        // `-k`/`-l` consumes no argument.
        let mut wire_args: Vec<String> = Vec::new();

        {
            let mut data = channel.data.lock();
            for c in modestr.chars() {
                // MODES=6 is advertised, so it is enforced: everything past the
                // sixth applied change in one command is ignored.
                if accum.applied_count() >= MAX_MODE_CHANGES {
                    break;
                }
                match c {
                    '+' => adding = true,
                    '-' => adding = false,
                    'o' | 'v' => {
                        let Some(nick) = rest.next() else { continue };
                        let folded = self.server.fold(nick);
                        if let Some(target) = self.server.find_client(&folded) {
                            match data.members.get_mut(&target.id) {
                                Some(member) => {
                                    if c == 'o' {
                                        member.prefix.op = adding;
                                    } else {
                                        member.prefix.voice = adding;
                                    }
                                    accum.push(adding, c);
                                    applied_args.push(target.nick());
                                    wire_args.push(self.server.local_uid(target.id));
                                }
                                None => self.numeric(
                                    ERR_USERNOTINCHANNEL,
                                    &[nick, display],
                                    Some("They aren't on that channel"),
                                ),
                            }
                        } else if let Some(remote) = self.server.find_remote_user(&folded) {
                            // A member on a linked server can be (de)opped too.
                            match data.remote_members.get_mut(&remote.uid) {
                                Some(member) => {
                                    if c == 'o' {
                                        member.prefix.op = adding;
                                    } else {
                                        member.prefix.voice = adding;
                                    }
                                    accum.push(adding, c);
                                    applied_args.push(remote.nick.clone());
                                    wire_args.push(remote.uid.clone());
                                }
                                None => self.numeric(
                                    ERR_USERNOTINCHANNEL,
                                    &[nick, display],
                                    Some("They aren't on that channel"),
                                ),
                            }
                        } else {
                            self.numeric(ERR_NOSUCHNICK, &[nick], Some("No such nick/channel"));
                        }
                    }
                    'k' => {
                        if adding {
                            let Some(key) = rest.next() else { continue };
                            data.modes.key = Some(key.to_owned());
                            accum.push(true, 'k');
                            applied_args.push(key.to_owned());
                            wire_args.push(key.to_owned());
                        } else {
                            data.modes.key = None;
                            accum.push(false, 'k');
                            applied_args.push("*".to_owned());
                        }
                    }
                    'l' => {
                        if adding {
                            let Some(raw) = rest.next() else { continue };
                            if let Ok(limit) = raw.parse::<usize>() {
                                data.modes.limit = Some(limit);
                                accum.push(true, 'l');
                                applied_args.push(limit.to_string());
                                wire_args.push(limit.to_string());
                            }
                        } else {
                            data.modes.limit = None;
                            accum.push(false, 'l');
                        }
                    }
                    'b' | 'e' | 'I' => {
                        let Some(raw) = rest.next() else { continue };
                        let mask = normalize_ban_mask(raw);
                        let by = self.entry.nick();
                        let list = match c {
                            'b' => &mut data.bans,
                            'e' => &mut data.exceptions,
                            _ => &mut data.invex,
                        };
                        let before = applied_args.len();
                        state::apply_list_mode(
                            list,
                            adding,
                            mask,
                            &by,
                            &mut accum,
                            &mut applied_args,
                            c,
                        );
                        if applied_args.len() != before {
                            wire_args.push(applied_args[before].clone());
                        }
                    }
                    // Simple boolean modes (i/m/n/s/t) are driven by the single
                    // `BOOL_MODES` table; anything else is unknown.
                    other => {
                        if let Some(bm) = state::BOOL_MODES.iter().find(|m| m.letter == other) {
                            (bm.set)(&mut data.modes, adding);
                            accum.push(adding, other);
                        } else {
                            self.numeric(
                                ERR_UNKNOWNMODE,
                                &[&other.to_string()],
                                Some("is unknown mode char to me"),
                            );
                        }
                    }
                }
            }
        } // release the channel lock before broadcasting

        if accum.is_empty() {
            return;
        }
        let (nick, user, host) = self.identity();
        let mut line = Line::user(&nick, &user, &host)
            .command("MODE")
            .param(display)
            .param(&accum.flags);
        for arg in &applied_args {
            line = line.param(arg);
        }
        let event = self.event(line.body());
        deliver::to_channel(channel, &event, Some(self.entry.id));
        self.deliver_self(&event);
        let mode_text = if applied_args.is_empty() {
            accum.flags.clone()
        } else {
            format!("{} {}", accum.flags, applied_args.join(" "))
        };
        self.server.record_channel_event(
            &self.server.fold(display),
            display,
            &format!("{nick}!{user}@{host}"),
            MessageKind::Mode,
            mode_text,
        );
        self.server.persist_registered(&self.server.fold(display));
        self.server
            .propagate_mode(self.entry.id, display, &accum.flags, wire_args);
    }

    // ------------------------------------------------------------- moderation ---

    /// `KICK <chanlist> <userlist> [:<reason>]` — RFC 2812 allows either one
    /// channel with several users, or one channel per user in lockstep.
    fn cmd_kick(&mut self, params: &[&str]) {
        let (Some(&chanlist), Some(&userlist)) = (params.first(), params.get(1)) else {
            self.need_more_params("KICK");
            return;
        };
        let channels: Vec<&str> = chanlist.split(',').filter(|c| !c.is_empty()).collect();
        let users: Vec<&str> = userlist.split(',').filter(|u| !u.is_empty()).collect();
        if channels.len() == 1 {
            for user in users {
                self.kick_one(channels[0], user, params);
            }
        } else {
            for (chan, user) in channels.iter().zip(users.iter()) {
                self.kick_one(chan, user, params);
            }
        }
    }

    fn kick_one(&mut self, chan: &str, target_nick: &str, params: &[&str]) {
        let Some(channel) = self.server.find_channel(&self.server.fold(chan)) else {
            self.numeric(ERR_NOSUCHCHANNEL, &[chan], Some("No such channel"));
            return;
        };
        let target_folded = self.server.fold(target_nick);
        let local_target = self.server.find_client(&target_folded);
        let remote_target = if local_target.is_none() {
            self.server.find_remote_user(&target_folded)
        } else {
            None
        };
        if local_target.is_none() && remote_target.is_none() {
            self.numeric(ERR_NOSUCHNICK, &[target_nick], Some("No such nick/channel"));
            return;
        }

        let (display, is_member, is_op, target_member) = {
            let d = channel.data.lock();
            let target_in = match (&local_target, &remote_target) {
                (Some(target), _) => d.has_member(target.id),
                (None, Some(remote)) => d.remote_members.contains_key(&remote.uid),
                (None, None) => false,
            };
            (
                d.name.clone(),
                d.has_member(self.entry.id),
                d.member(self.entry.id).is_some_and(|m| m.prefix.op),
                target_in,
            )
        };
        if !is_member {
            self.numeric(
                ERR_NOTONCHANNEL,
                &[&display],
                Some("You're not on that channel"),
            );
            return;
        }
        if !is_op {
            self.numeric(
                ERR_CHANOPRIVSNEEDED,
                &[&display],
                Some("You're not channel operator"),
            );
            return;
        }
        if !target_member {
            self.numeric(
                ERR_USERNOTINCHANNEL,
                &[target_nick, &display],
                Some("They aren't on that channel"),
            );
            return;
        }

        let kicker = self.entry.nick();
        // KICKLEN is advertised, so it is enforced.
        let reason = truncate_chars(
            params.get(2).copied().unwrap_or(kicker.as_str()),
            MAX_KICK_LEN,
        );
        let (nick, user, host) = self.identity();
        let target_display = match (&local_target, &remote_target) {
            (Some(target), _) => target.nick(),
            (None, Some(remote)) => remote.nick.clone(),
            (None, None) => unreachable!("target existence checked above"),
        };
        let body = Line::user(&nick, &user, &host)
            .command("KICK")
            .param(&display)
            .param(&target_display)
            .trailing(reason)
            .body();
        let event = self.event(body);
        deliver::to_channel(&channel, &event, Some(self.entry.id));
        self.deliver_self(&event);
        self.server.record_channel_event(
            &self.server.fold(chan),
            &display,
            &format!("{nick}!{user}@{host}"),
            MessageKind::Kick,
            format!("{target_display} {reason}"),
        );

        let folded = self.server.fold(chan);
        let target_uid = match (&local_target, &remote_target) {
            (Some(target), _) => {
                channel.data.lock().members.remove(&target.id);
                target.data.lock().channels.remove(&folded);
                self.server.local_uid(target.id)
            }
            (None, Some(remote)) => {
                channel.data.lock().remote_members.remove(&remote.uid);
                self.server.remote_channel_removed(&remote.uid, &folded);
                remote.uid.clone()
            }
            (None, None) => unreachable!("target existence checked above"),
        };
        self.server.reap_channel(&folded);
        // Tell linked peers (the target's own server removes it and shows the
        // KICK to the target).
        self.server
            .propagate_kick(self.entry.id, &display, &target_uid, reason);
    }

    fn cmd_invite(&mut self, params: &[&str]) {
        // `INVITE` with no parameters lists the channels this client has a
        // pending invitation to (RPL_INVITELIST / RPL_ENDOFINVITELIST).
        if params.is_empty() {
            let folded_nick = self.server.fold(&self.entry.nick());
            for channel in self.server.channels_snapshot() {
                let name = {
                    let d = channel.data.lock();
                    d.invited.contains(&folded_nick).then(|| d.name.clone())
                };
                if let Some(name) = name {
                    self.numeric(RPL_INVITELIST, &[&name], None);
                }
            }
            self.numeric(RPL_ENDOFINVITELIST, &[], Some("End of /INVITE list"));
            return;
        }
        let (Some(&target_nick), Some(&chan)) = (params.first(), params.get(1)) else {
            self.need_more_params("INVITE");
            return;
        };
        let Some(target) = self.server.find_client(&self.server.fold(target_nick)) else {
            // A user on a linked server: validate locally, then route the
            // invitation to the target's server, which records it and
            // notifies the target.
            if let Some(remote) = self.server.find_remote_user(&self.server.fold(target_nick)) {
                self.invite_remote(&remote, chan);
                return;
            }
            self.numeric(ERR_NOSUCHNICK, &[target_nick], Some("No such nick/channel"));
            return;
        };
        let Some(channel) = self.server.find_channel(&self.server.fold(chan)) else {
            self.numeric(ERR_NOSUCHCHANNEL, &[chan], Some("No such channel"));
            return;
        };

        let (display, is_member, is_op, invite_only, target_in) = {
            let d = channel.data.lock();
            (
                d.name.clone(),
                d.has_member(self.entry.id),
                d.member(self.entry.id).is_some_and(|m| m.prefix.op),
                d.modes.invite_only,
                d.has_member(target.id),
            )
        };
        if !is_member {
            self.numeric(
                ERR_NOTONCHANNEL,
                &[&display],
                Some("You're not on that channel"),
            );
            return;
        }
        if invite_only && !is_op {
            self.numeric(
                ERR_CHANOPRIVSNEEDED,
                &[&display],
                Some("You're not channel operator"),
            );
            return;
        }
        let target_nick_display = target.nick();
        if target_in {
            self.numeric(
                ERR_USERONCHANNEL,
                &[&target_nick_display, &display],
                Some("is already on channel"),
            );
            return;
        }

        {
            // Bound the pending-invite set so a rapid INVITE flood cannot grow a
            // channel's memory without limit (invites are consumed on JOIN; any
            // that are never accepted would otherwise persist for the channel's
            // whole lifetime). When full, drop an arbitrary older pending invite.
            const MAX_PENDING_INVITES: usize = 256;
            let mut data = channel.data.lock();
            if data.invited.len() >= MAX_PENDING_INVITES {
                if let Some(victim) = data.invited.iter().next().cloned() {
                    data.invited.remove(&victim);
                }
            }
            data.invited.insert(self.server.fold(&target_nick_display));
        }
        self.numeric(RPL_INVITING, &[&target_nick_display, &display], None);

        let (nick, user, host) = self.identity();
        let body = Line::user(&nick, &user, &host)
            .command("INVITE")
            .param(&target_nick_display)
            .param(&display)
            .body();
        let event = self.event(body);
        deliver::to_client(&target, &event);
        // invite-notify: let capable channel members see the invitation.
        deliver::to_channel_capped(&channel, &event, Cap::InviteNotify, Some(self.entry.id));
    }

    /// The cross-server half of INVITE: run the same permission checks against
    /// our copy of the channel, then route an `SINVITE` towards the target's
    /// server.
    fn invite_remote(&mut self, remote: &state::RemoteUser, chan: &str) {
        let Some(channel) = self.server.find_channel(&self.server.fold(chan)) else {
            self.numeric(ERR_NOSUCHCHANNEL, &[chan], Some("No such channel"));
            return;
        };
        let (display, is_member, is_op, invite_only, target_in) = {
            let d = channel.data.lock();
            (
                d.name.clone(),
                d.has_member(self.entry.id),
                d.member(self.entry.id).is_some_and(|m| m.prefix.op),
                d.modes.invite_only,
                d.remote_members.contains_key(&remote.uid),
            )
        };
        if !is_member {
            self.numeric(
                ERR_NOTONCHANNEL,
                &[&display],
                Some("You're not on that channel"),
            );
            return;
        }
        if invite_only && !is_op {
            self.numeric(
                ERR_CHANOPRIVSNEEDED,
                &[&display],
                Some("You're not channel operator"),
            );
            return;
        }
        if target_in {
            self.numeric(
                ERR_USERONCHANNEL,
                &[&remote.nick, &display],
                Some("is already on channel"),
            );
            return;
        }
        let msg = crate::s2s::LinkMessage::Sinvite {
            source: self.server.local_uid(self.entry.id),
            target: remote.uid.clone(),
            channel: display.clone(),
        };
        self.server.send_towards(&remote.server_sid, msg.to_line());
        self.numeric(RPL_INVITING, &[&remote.nick, &display], None);

        // invite-notify for local members of the channel.
        let (nick, user, host) = self.identity();
        let body = Line::user(&nick, &user, &host)
            .command("INVITE")
            .param(&remote.nick)
            .param(&display)
            .body();
        let event = self.event(body);
        deliver::to_channel_capped(&channel, &event, Cap::InviteNotify, Some(self.entry.id));
    }

    fn cmd_oper(&mut self, params: &[&str]) {
        let (Some(&name), Some(&password)) = (params.first(), params.get(1)) else {
            self.need_more_params("OPER");
            return;
        };
        // The operator block may be restricted to certain hosts.
        let (hostmask, real_ip) = {
            let d = self.entry.data.lock();
            (
                format!("{}!{}@{}", d.nick, d.user, d.host),
                d.real_ip.clone(),
            )
        };
        if !self.server.oper_host_allowed(name, &hostmask, &real_ip) {
            self.numeric(ERR_NOOPERHOST, &[], Some("No O-lines for your host"));
            return;
        }
        if self.server.opers.verify_password(name, password).is_err() {
            self.numeric(ERR_PASSWDMISMATCH, &[], Some("Password incorrect"));
            return;
        }
        self.entry.data.lock().oper = true;
        let nick = self.entry.nick();
        self.send(
            Line::server(self.server_name())
                .command("MODE")
                .param(&nick)
                .param("+o"),
        );
        self.numeric(RPL_YOUREOPER, &[], Some("You are now an IRC operator"));
        // The whole network must know: remote WHOIS shows 313, and oper-only
        // checks elsewhere depend on it.
        self.server.propagate_umodes(self.entry.id, "+o");
    }

    /// `WALLOPS :message` — operator broadcast to every user with umode `+w`.
    fn cmd_wallops(&mut self, params: &[&str]) {
        if !self.require_oper() {
            return;
        }
        let Some(&text) = params.first() else {
            self.need_more_params("WALLOPS");
            return;
        };
        let (nick, user, host) = self.identity();
        let line = Line::user(&nick, &user, &host)
            .command("WALLOPS")
            .trailing(text)
            .build();
        self.server.wallops(&line);
        // Operator broadcasts reach +w users network-wide.
        self.server
            .propagate_wallops(&format!("{nick}!{user}@{host}"), text);
    }

    fn cmd_kill(&mut self, params: &[&str]) {
        if !self.require_oper() {
            return;
        }
        let Some(&targets) = params.first() else {
            self.need_more_params("KILL");
            return;
        };
        let reason = params.get(1).copied().unwrap_or("Killed");
        let killer = self.entry.nick();
        for target_nick in targets.split(',').filter(|s| !s.is_empty()) {
            // A server is not a KILLable target (RFC 2812 §3.7.1).
            if self.is_server_name(target_nick) {
                self.numeric(
                    ERR_CANTKILLSERVER,
                    &[target_nick],
                    Some("You can't kill a server!"),
                );
                continue;
            }
            let folded = self.server.fold(target_nick);
            if let Some(target) = self.server.find_client(&folded) {
                target.request_kill(&format!("Killed ({killer}: {reason})"));
            } else if let Some(remote) = self.server.find_remote_user(&folded) {
                // Route the KILL towards the owning server; it propagates the
                // resulting QUIT back through the tree.
                self.server
                    .kill_remote(&remote, &format!("Killed ({killer}: {reason})"));
                self.notice(&format!("KILL for {target_nick} sent to its server"));
            } else {
                self.numeric(ERR_NOSUCHNICK, &[target_nick], Some("No such nick/channel"));
            }
        }
    }

    /// Whether `name` names a server in the network: ourselves, a direct peer,
    /// or a known multi-hop server.
    fn is_server_name(&self, name: &str) -> bool {
        if name.eq_ignore_ascii_case(self.server_name()) {
            return true;
        }
        self.server
            .links_snapshot()
            .iter()
            .any(|l| l.name.eq_ignore_ascii_case(name))
            || self
                .server
                .remote_servers_snapshot()
                .iter()
                .any(|s| s.name.eq_ignore_ascii_case(name))
    }

    fn cmd_kline(&mut self, params: &[&str]) {
        if !self.require_oper() {
            return;
        }
        let Some(&raw_mask) = params.first() else {
            self.need_more_params("KLINE");
            return;
        };
        let mask = normalize_ban_mask(raw_mask);
        let reason = params.get(1).copied().unwrap_or("K-Lined").to_owned();
        self.server
            .add_kline(mask.clone(), reason.clone(), self.entry.nick());
        let affected = self
            .server
            .kill_matching(&mask, &format!("K-Lined: {reason}"));
        self.notice(&format!(
            "Added K-Line for {mask} ({affected} user(s) affected)"
        ));
    }

    fn cmd_unkline(&mut self, params: &[&str]) {
        if !self.require_oper() {
            return;
        }
        let Some(&raw_mask) = params.first() else {
            self.need_more_params("UNKLINE");
            return;
        };
        let mask = normalize_ban_mask(raw_mask);
        if self.server.remove_kline(&mask) {
            self.notice(&format!("Removed K-Line for {mask}"));
        } else {
            self.notice(&format!("No such K-Line: {mask}"));
        }
    }

    /// `GLINE <mask> [:<reason>]` — a network-wide ban: applied here like a
    /// K-Line and propagated to every linked server.
    fn cmd_gline(&mut self, params: &[&str]) {
        if !self.require_oper() {
            return;
        }
        let Some(&raw_mask) = params.first() else {
            self.need_more_params("GLINE");
            return;
        };
        let mask = normalize_ban_mask(raw_mask);
        let reason = params.get(1).copied().unwrap_or("G-Lined").to_owned();
        let set_by = self.entry.nick();
        self.server
            .add_kline(mask.clone(), reason.clone(), set_by.clone());
        let affected = self
            .server
            .kill_matching(&mask, &format!("G-Lined: {reason}"));
        self.server.propagate_gline(true, &mask, &set_by, &reason);
        self.notice(&format!(
            "Added G-Line for {mask} ({affected} local user(s) affected)"
        ));
    }

    /// `UNGLINE <mask>` — remove a network-wide ban everywhere.
    fn cmd_ungline(&mut self, params: &[&str]) {
        if !self.require_oper() {
            return;
        }
        let Some(&raw_mask) = params.first() else {
            self.need_more_params("UNGLINE");
            return;
        };
        let mask = normalize_ban_mask(raw_mask);
        let removed = self.server.remove_kline(&mask);
        self.server
            .propagate_gline(false, &mask, &self.entry.nick(), "");
        if removed {
            self.notice(&format!("Removed G-Line for {mask}"));
        } else {
            self.notice(&format!("No such G-Line here: {mask} (removal propagated)"));
        }
    }

    fn cmd_dline(&mut self, params: &[&str]) {
        if !self.require_oper() {
            return;
        }
        let Some(&mask) = params.first() else {
            self.need_more_params("DLINE");
            return;
        };
        let reason = params.get(1).copied().unwrap_or("D-Lined").to_owned();
        self.server
            .add_dline(mask.to_owned(), reason.clone(), self.entry.nick());
        let affected = self
            .server
            .kill_matching_ip(mask, &format!("D-Lined: {reason}"));
        self.notice(&format!(
            "Added D-Line for {mask} ({affected} user(s) affected)"
        ));
    }

    fn cmd_undline(&mut self, params: &[&str]) {
        if !self.require_oper() {
            return;
        }
        let Some(&mask) = params.first() else {
            self.need_more_params("UNDLINE");
            return;
        };
        if self.server.remove_dline(mask) {
            self.notice(&format!("Removed D-Line for {mask}"));
        } else {
            self.notice(&format!("No such D-Line: {mask}"));
        }
    }

    fn cmd_chghost(&mut self, params: &[&str]) {
        if !self.require_oper() {
            return;
        }
        let (Some(&target_nick), Some(&new_host)) = (params.first(), params.get(1)) else {
            self.need_more_params("CHGHOST");
            return;
        };
        let Some(target) = self.server.find_client(&self.server.fold(target_nick)) else {
            self.numeric(ERR_NOSUCHNICK, &[target_nick], Some("No such nick/channel"));
            return;
        };

        let (nick, user, old_host, channels) = {
            let mut d = target.data.lock();
            let old = (
                d.nick.clone(),
                d.user.clone(),
                d.host.clone(),
                d.channels.clone(),
            );
            d.host = new_host.to_owned();
            old
        };
        // CHGHOST is only meaningful to chghost-capable clients.
        let body = Line::user(&nick, &user, &old_host)
            .command("CHGHOST")
            .param(&user)
            .param(new_host)
            .body();
        let event = Event::new(body).with_time(self.now_time());

        let mut seen: HashSet<u64> = HashSet::new();
        if target.caps().has(Cap::ChgHost) {
            deliver::to_client(&target, &event);
        }
        seen.insert(target.id);
        for folded in &channels {
            if let Some(channel) = self.server.find_channel(folded) {
                let data = channel.data.lock();
                for member in data.members.values() {
                    if member.entry.caps().has(Cap::ChgHost) && seen.insert(member.entry.id) {
                        deliver::to_client(&member.entry, &event);
                    }
                }
            }
        }
        // extended-monitor watchers of the target hear about the change too.
        self.server
            .notify_extended_monitors(&self.server.fold(&nick), &event, Cap::ChgHost, &seen);
        self.notice(&format!("Changed host of {nick} to {new_host}"));
        // Linked peers must see the new host too (display + ban matching).
        self.server.propagate_chghost(target.id, new_host);
    }

    // ------------------------------------------------------------ chathistory ---

    fn cmd_chathistory(&mut self, params: &[&str]) {
        let Some(&sub) = params.first() else {
            self.fail("CHATHISTORY", "NEED_MORE_PARAMS", &[], "Missing subcommand");
            return;
        };
        let sub = sub.to_ascii_uppercase();

        if sub == "TARGETS" {
            self.chathistory_targets(&params[1..]);
            return;
        }

        let Some(&target) = params.get(1) else {
            self.fail("CHATHISTORY", "NEED_MORE_PARAMS", &[&sub], "Missing target");
            return;
        };
        // A nick target maps to the private conversation key with that nick.
        let folded = if casemap::is_valid_channel(target) {
            self.server.fold(target)
        } else {
            pair_key(
                &self.server.fold(&self.entry.nick()),
                &self.server.fold(target),
            )
        };

        // Channel history is visible only to members (privacy).
        if casemap::is_valid_channel(target)
            && !self
                .server
                .find_channel(&folded)
                .is_some_and(|c| c.data.lock().has_member(self.entry.id))
        {
            self.fail(
                "CHATHISTORY",
                "INVALID_TARGET",
                &[&sub, target],
                "You are not in that channel",
            );
            return;
        }

        let rest = &params[2..];
        let limit_at = |idx: usize| {
            rest.get(idx)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(50)
                .clamp(1, 100)
        };
        let history = &self.server.history;
        // draft/event-playback: only capable clients get JOIN/PART/… events
        // replayed; everyone else sees pure PRIVMSG/NOTICE history.
        let events = self.entry.caps().has(Cap::EventPlayback);
        let messages = match sub.as_str() {
            "LATEST" => {
                let sel = rest
                    .first()
                    .and_then(|s| parse_selector(s))
                    .unwrap_or(Selector::Latest);
                history.latest(&folded, &sel, limit_at(1), events)
            }
            "BEFORE" | "AFTER" | "AROUND" => {
                let Some(sel) = rest.first().and_then(|s| parse_selector(s)) else {
                    self.fail("CHATHISTORY", "INVALID_PARAMS", &[&sub], "Invalid selector");
                    return;
                };
                match sub.as_str() {
                    "BEFORE" => history.before(&folded, &sel, limit_at(1), events),
                    "AFTER" => history.after(&folded, &sel, limit_at(1), events),
                    _ => history.around(&folded, &sel, limit_at(1), events),
                }
            }
            "BETWEEN" => {
                let (Some(a), Some(b)) = (
                    rest.first().and_then(|s| parse_selector(s)),
                    rest.get(1).and_then(|s| parse_selector(s)),
                ) else {
                    self.fail(
                        "CHATHISTORY",
                        "INVALID_PARAMS",
                        &[&sub],
                        "Invalid selectors",
                    );
                    return;
                };
                history.between(&folded, &a, &b, limit_at(2), events)
            }
            _ => {
                self.fail(
                    "CHATHISTORY",
                    "INVALID_PARAMS",
                    &[&sub],
                    "Unknown subcommand",
                );
                return;
            }
        };

        self.send_history_batch(target, &messages);
    }

    /// Send history messages wrapped in a `chathistory` batch (if the client has
    /// `batch`), each tagged per its capabilities.
    fn send_history_batch(&self, target: &str, messages: &[Arc<StoredMessage>]) {
        let caps = self.entry.caps();
        let use_batch = caps.has(Cap::Batch);
        let reference = self.server.history.next_msgid();
        if use_batch {
            self.send(
                Line::server(self.server_name())
                    .command("BATCH")
                    .param(&format!("+{reference}"))
                    .param("chathistory")
                    .param(target),
            );
        }
        for message in messages {
            let batch = use_batch.then_some(reference.as_str());
            self.send_bytes(render_stored(message, caps, batch));
        }
        if use_batch {
            self.send(
                Line::server(self.server_name())
                    .command("BATCH")
                    .param(&format!("-{reference}")),
            );
        }
    }

    fn chathistory_targets(&self, args: &[&str]) {
        let after = args
            .first()
            .and_then(|s| parse_selector(s))
            .unwrap_or(Selector::Timestamp(0));
        let before = args
            .get(1)
            .and_then(|s| parse_selector(s))
            .unwrap_or(Selector::Latest);
        let limit = args
            .get(2)
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(50)
            .clamp(1, 100);
        let mine = self.entry.data.lock().channels.clone();
        let me = self.server.fold(&self.entry.nick());
        for (key, time_ms) in self.server.history.targets(&after, &before, limit) {
            // A DM ring is reported as the *other* party; a channel ring only
            // to a member.
            let target = match crate::history::pair_parties(&key) {
                Some((a, b)) if a == me || b == me => {
                    let partner = if a == me { b } else { a };
                    // Prefer the partner's current display nick; fall back to
                    // the folded form if they are gone.
                    self.server
                        .find_client(partner)
                        .map(|c| c.nick())
                        .or_else(|| self.server.find_remote_user(partner).map(|u| u.nick))
                        .unwrap_or_else(|| partner.to_owned())
                }
                Some(_) => continue, // someone else's conversation
                None if mine.contains(&key) => self
                    .server
                    .find_channel(&key)
                    .map(|c| c.data.lock().name.clone())
                    .unwrap_or(key),
                None => continue, // a channel the requester is not in
            };
            self.send(
                Line::server(self.server_name())
                    .command("CHATHISTORY")
                    .param("TARGETS")
                    .param(&target)
                    .param(&state::format_server_time(time_ms)),
            );
        }
    }

    // -------------------------------------------------------------------- LIST ---

    fn cmd_list(&mut self, params: &[&str]) {
        self.numeric(RPL_LISTSTART, &["Channel"], Some("Users  Name"));
        let filters: Vec<ListFilter> = params
            .first()
            .map(|list| {
                list.split(',')
                    .filter(|t| !t.is_empty())
                    .map(parse_list_filter)
                    .collect()
            })
            .unwrap_or_default();
        let now = now_unix();
        for channel in self.server.channels_snapshot() {
            let (name, count, secret, is_member, topic, created_at, topic_at) = {
                let d = channel.data.lock();
                (
                    d.name.clone(),
                    d.members.len() + d.remote_members.len(),
                    d.modes.secret,
                    d.has_member(self.entry.id),
                    d.topic.as_ref().map(|t| t.text.clone()).unwrap_or_default(),
                    d.created_at,
                    d.topic.as_ref().map(|t| t.set_at),
                )
            };
            if secret && !is_member {
                continue; // hide secret channels from non-members
            }
            let matches_all = filters.iter().all(|f| match f {
                ListFilter::MinUsers(n) => count > *n,
                ListFilter::MaxUsers(n) => count < *n,
                // C<n: created within the last n minutes; C>n: older.
                ListFilter::CreatedWithin(mins) => {
                    now.saturating_sub(created_at) < mins.saturating_mul(60)
                }
                ListFilter::CreatedBefore(mins) => {
                    now.saturating_sub(created_at) > mins.saturating_mul(60)
                }
                // T<n: topic changed within the last n minutes; T>n: older.
                ListFilter::TopicWithin(mins) => {
                    topic_at.is_some_and(|at| now.saturating_sub(at) < mins.saturating_mul(60))
                }
                ListFilter::TopicBefore(mins) => {
                    topic_at.is_some_and(|at| now.saturating_sub(at) > mins.saturating_mul(60))
                }
                // mask::matches is already case-insensitive.
                ListFilter::Mask(mask) => crate::mask::matches(mask, &name),
                ListFilter::NotMask(mask) => !crate::mask::matches(mask, &name),
            });
            if !matches_all {
                continue;
            }
            self.numeric(RPL_LIST, &[&name, &count.to_string()], Some(&topic));
        }
        self.numeric(RPL_LISTEND, &[], Some("End of /LIST"));
    }

    // ------------------------------------------------------ rehash / metadata ---

    fn cmd_rehash(&mut self) {
        if !self.require_oper() {
            return;
        }
        self.numeric(RPL_REHASHING, &["config"], Some("Rehashing"));
        match self.server.rehash() {
            Ok(()) => self.notice("Rehash complete"),
            Err(err) => self.notice(&format!("Rehash failed: {err}")),
        }
    }

    /// `CONNECT <name>`: operator-initiated outbound S2S link to a configured
    /// peer, established at runtime (beyond the config-driven links started at
    /// boot). One attempt is made; its outcome is logged.
    fn cmd_connect(&mut self, params: &[&str]) {
        if !self.require_oper() {
            return;
        }
        let Some(&name) = params.first() else {
            self.need_more_params("CONNECT");
            return;
        };
        let Some(peer) = self.server.link_config_by_name(name) else {
            self.numeric(
                ERR_NOSUCHSERVER,
                &[name],
                Some("No configured link by that name"),
            );
            return;
        };
        if peer.connect.is_none() {
            self.notice(&format!(
                "CONNECT: {} is accept-only (no address)",
                peer.name
            ));
            return;
        }
        if self.server.direct_link(&peer.name).is_some() {
            self.notice(&format!("CONNECT: {} is already linked", peer.name));
            return;
        }
        let Some(client_config) = self.server.link_client_config() else {
            self.notice("CONNECT: link TLS is not configured");
            return;
        };
        let server = self.server.clone();
        let peer_name = peer.name.clone();
        // A manual CONNECT overrides a prior operator SQUIT.
        server.clear_link_admin_down(&peer_name);
        self.notice(&format!("Connecting to {peer_name}..."));
        // Detached: the handshake and (on success) the link's read loop outlive
        // this command. Failures surface in the server log.
        tokio::spawn(async move {
            match crate::link::connect_now(peer, server, client_config).await {
                Ok(()) => tracing::info!(peer = %peer_name, "operator CONNECT link closed"),
                Err(err) => tracing::warn!(peer = %peer_name, %err, "operator CONNECT failed"),
            }
        });
    }

    /// `SQUIT <server> [:reason]`: operator-initiated teardown of a directly
    /// linked peer. The peer (and the subtree behind it) splits off via the
    /// usual netsplit path.
    fn cmd_squit(&mut self, params: &[&str]) {
        if !self.require_oper() {
            return;
        }
        let Some(&target) = params.first() else {
            self.need_more_params("SQUIT");
            return;
        };
        let reason = params
            .get(1)
            .copied()
            .filter(|r| !r.is_empty())
            .unwrap_or("SQUIT requested by operator");
        match self.server.squit_link(target, reason) {
            Some(name) => self.notice(&format!("SQUIT: closing link to {name}")),
            None => self.numeric(
                ERR_NOSUCHSERVER,
                &[target],
                Some("No such directly-linked server"),
            ),
        }
    }

    fn cmd_metadata(&mut self, params: &[&str]) {
        let (Some(&target), Some(&sub)) = (params.first(), params.get(1)) else {
            self.fail("METADATA", "INVALID_PARAMS", &[], "Not enough parameters");
            return;
        };
        match sub.to_ascii_uppercase().as_str() {
            "GET" => {
                let Some(map) = self.metadata_snapshot(target) else {
                    self.fail("METADATA", "INVALID_TARGET", &[target], "No such target");
                    return;
                };
                for &key in &params[2..] {
                    match map.get(key) {
                        Some(value) => self.numeric(RPL_KEYVALUE, &[target, key, "*"], Some(value)),
                        None => self.fail("METADATA", "KEY_NOT_SET", &[target, key], "Key not set"),
                    }
                }
            }
            "LIST" => {
                let Some(map) = self.metadata_snapshot(target) else {
                    self.fail("METADATA", "INVALID_TARGET", &[target], "No such target");
                    return;
                };
                for (key, value) in &map {
                    self.numeric(RPL_KEYVALUE, &[target, key, "*"], Some(value));
                }
                self.numeric(RPL_METADATAEND, &[], Some("End of metadata"));
            }
            "SET" => {
                let Some(&key) = params.get(2) else {
                    self.fail("METADATA", "INVALID_PARAMS", &["SET"], "Missing key");
                    return;
                };
                if !valid_metadata_key(key) {
                    self.fail("METADATA", "KEY_INVALID", &[target, key], "Invalid key");
                    return;
                }
                let value = params.get(3).copied().filter(|v| !v.is_empty());
                if value.is_some_and(|v| v.len() > MAX_METADATA_VALUE_LEN) {
                    self.fail(
                        "METADATA",
                        "VALUE_INVALID",
                        &[target, key],
                        "Value too long",
                    );
                    return;
                }
                if !self.metadata_set(target, key, value) {
                    self.fail(
                        "METADATA",
                        "KEY_NO_PERMISSION",
                        &[target, key],
                        "Permission denied",
                    );
                    return;
                }
                self.numeric(RPL_KEYVALUE, &[target, key, "*"], value);
                self.announce_metadata(target, key, value);
            }
            "CLEAR" => {
                let keys: Vec<String> = self
                    .metadata_snapshot(target)
                    .map(|m| m.keys().cloned().collect())
                    .unwrap_or_default();
                if self.metadata_clear(target) {
                    for key in keys {
                        self.announce_metadata(target, &key, None);
                    }
                    self.numeric(RPL_METADATAEND, &[], Some("End of metadata"));
                } else {
                    self.fail(
                        "METADATA",
                        "KEY_NO_PERMISSION",
                        &[target],
                        "Permission denied",
                    );
                }
            }
            // Subscriptions: the client asks to be told whenever these keys
            // change on anyone it can see.
            "SUB" => {
                if params.len() < 3 {
                    self.fail("METADATA", "INVALID_PARAMS", &["SUB"], "Missing keys");
                    return;
                }
                for &key in &params[2..] {
                    if !valid_metadata_key(key) {
                        self.fail("METADATA", "KEY_INVALID", &[key], "Invalid key");
                        continue;
                    }
                    let mut d = self.entry.data.lock();
                    if d.metadata_subs.len() >= MAX_METADATA_SUBS && !d.metadata_subs.contains(key)
                    {
                        drop(d);
                        self.fail(
                            "METADATA",
                            "TOO_MANY_SUBS",
                            &[key],
                            "Too many subscriptions",
                        );
                        break;
                    }
                    d.metadata_subs.insert(key.to_owned());
                    drop(d);
                    self.numeric(RPL_METADATASUBOK, &[key], None);
                }
            }
            "UNSUB" => {
                if params.len() < 3 {
                    self.fail("METADATA", "INVALID_PARAMS", &["UNSUB"], "Missing keys");
                    return;
                }
                for &key in &params[2..] {
                    self.entry.data.lock().metadata_subs.remove(key);
                    self.numeric(RPL_METADATAUNSUBOK, &[key], None);
                }
            }
            "SUBS" => {
                let subs: Vec<String> = self
                    .entry
                    .data
                    .lock()
                    .metadata_subs
                    .iter()
                    .cloned()
                    .collect();
                for chunk in subs.chunks(10) {
                    let refs: Vec<&str> = chunk.iter().map(String::as_str).collect();
                    self.numeric(RPL_METADATASUBS, &refs, None);
                }
                self.numeric(RPL_METADATAEND, &[], Some("End of metadata subscriptions"));
            }
            other => self.fail("METADATA", "INVALID_PARAMS", &[other], "Unknown subcommand"),
        }
    }

    /// Tell subscribers that `target`'s `key` changed (draft/metadata-2). A
    /// channel's metadata goes to its members; a user's to everyone sharing a
    /// channel with them, plus the user itself.
    fn announce_metadata(&self, target: &str, key: &str, value: Option<&str>) {
        let is_channel = casemap::is_valid_channel(target);
        let display = if is_channel {
            self.server
                .find_channel(&self.server.fold(target))
                .map(|c| c.data.lock().name.clone())
        } else if self.is_self_target(target) {
            Some(self.entry.nick())
        } else {
            self.server
                .find_client(&self.server.fold(target))
                .map(|c| c.nick())
        };
        let Some(display) = display else {
            return;
        };
        let mut line = Line::server(self.server_name())
            .command("METADATA")
            .param(&display)
            .param(key)
            .param("*");
        if let Some(value) = value {
            line = line.trailing(value);
        }
        let bytes = line.build();

        let deliver_to = |entry: &Arc<ClientEntry>| {
            let subscribed = entry.data.lock().metadata_subs.contains(key);
            if subscribed && entry.caps().has(Cap::Metadata) {
                entry.send(bytes.clone());
            }
        };
        let mut seen: HashSet<u64> = HashSet::new();
        if is_channel {
            if let Some(channel) = self.server.find_channel(&self.server.fold(target)) {
                for (entry, _) in channel.member_snapshot() {
                    if seen.insert(entry.id) {
                        deliver_to(&entry);
                    }
                }
            }
            return;
        }
        // A user's metadata: co-members across their channels, and themselves.
        let owner = if self.is_self_target(target) {
            Some(self.entry.clone())
        } else {
            self.server.find_client(&self.server.fold(target))
        };
        let Some(owner) = owner else { return };
        let channels = owner.data.lock().channels.clone();
        for folded in &channels {
            if let Some(channel) = self.server.find_channel(folded) {
                for (entry, _) in channel.member_snapshot() {
                    if seen.insert(entry.id) {
                        deliver_to(&entry);
                    }
                }
            }
        }
        if seen.insert(owner.id) {
            deliver_to(&owner);
        }
    }

    /// Whether `target` addresses this client's own metadata.
    fn is_self_target(&self, target: &str) -> bool {
        target == "*"
            || (!casemap::is_valid_channel(target)
                && self.server.fold(target) == self.server.fold(&self.entry.nick()))
    }

    /// A clone of a target's metadata (self, channel, or another user).
    fn metadata_snapshot(&self, target: &str) -> Option<HashMap<String, String>> {
        if self.is_self_target(target) {
            return Some(self.entry.data.lock().metadata.clone());
        }
        if casemap::is_valid_channel(target) {
            return self
                .server
                .find_channel(&self.server.fold(target))
                .map(|c| c.data.lock().metadata.clone());
        }
        self.server
            .find_client(&self.server.fold(target))
            .map(|c| c.data.lock().metadata.clone())
    }

    /// Set metadata on a permitted target. Returns `false` if not permitted.
    fn metadata_set(&self, target: &str, key: &str, value: Option<&str>) -> bool {
        if self.is_self_target(target) {
            apply_metadata(&mut self.entry.data.lock().metadata, key, value);
            return true;
        }
        if casemap::is_valid_channel(target) {
            let Some(channel) = self.server.find_channel(&self.server.fold(target)) else {
                return false;
            };
            let mut data = channel.data.lock();
            if !data.member(self.entry.id).is_some_and(|m| m.prefix.op) {
                return false;
            }
            apply_metadata(&mut data.metadata, key, value);
            return true;
        }
        false // cannot set another user's metadata
    }

    /// Clear metadata on a permitted target. Returns `false` if not permitted.
    fn metadata_clear(&self, target: &str) -> bool {
        if self.is_self_target(target) {
            self.entry.data.lock().metadata.clear();
            return true;
        }
        if casemap::is_valid_channel(target) {
            let Some(channel) = self.server.find_channel(&self.server.fold(target)) else {
                return false;
            };
            let mut data = channel.data.lock();
            if !data.member(self.entry.id).is_some_and(|m| m.prefix.op) {
                return false;
            }
            data.metadata.clear();
            return true;
        }
        false
    }

    // ------------------------------------------------ server-info queries ---

    fn cmd_version(&self) {
        let info = &self.server.info;
        let v = format!("{} {}", info.version, info.name);
        self.numeric(
            RPL_VERSION,
            &[&v],
            Some("ferrixd — a memory-safe, IRCv3 IRC daemon in Rust"),
        );
        self.send_isupport();
    }

    fn cmd_time(&self) {
        let now = state::format_datetime(state::now_unix());
        self.numeric(RPL_TIME, &[&self.server.info.name], Some(&now));
    }

    fn cmd_admin(&self) {
        let info = &self.server.info;
        self.numeric(
            RPL_ADMINME,
            &[&info.name],
            Some("Administrative info about this server"),
        );
        self.numeric(
            RPL_ADMINLOC1,
            &[],
            Some(&format!("Network: {}", info.network)),
        );
        self.numeric(RPL_ADMINLOC2, &[], Some(&format!("Server: {}", info.name)));
        self.numeric(
            RPL_ADMINEMAIL,
            &[],
            Some("Contact your network's operators"),
        );
    }

    fn cmd_info(&self) {
        for line in [
            format!("{} — the Ferrous IRC Daemon", self.server.info.version),
            "A from-scratch, memory-safe, IRCv3-complete IRC server in Rust.".to_owned(),
            "Zero unsafe code; TLS-first; horizontally shardable.".to_owned(),
        ] {
            self.numeric(RPL_INFO, &[], Some(&line));
        }
        self.numeric(RPL_ENDOFINFO, &[], Some("End of /INFO list"));
    }

    /// `PASS <password>` — connection password, only meaningful before
    /// registration; checked when registration completes.
    fn cmd_pass(&mut self, params: &[&str]) {
        if self.registered {
            self.numeric(ERR_ALREADYREGISTERED, &[], Some("You may not reregister"));
            return;
        }
        let Some(&password) = params.first() else {
            self.need_more_params("PASS");
            return;
        };
        self.pass = Some(password.to_owned());
    }

    /// `WEBIRC <password> <gateway> <hostname> <ip> [options…]` — a trusted
    /// web/IRC gateway rewrites this connection's apparent host and IP so users
    /// behind it are seen (and moderated) by their real address rather than the
    /// gateway's.
    ///
    /// Security: the command is refused unless it is the very first thing on the
    /// connection (before CAP/NICK/USER/PASS), the *real* peer address is on the
    /// gateway's allow-list, and the shared secret matches (constant-time). Any
    /// failure closes the connection without disclosing which check failed.
    fn cmd_webirc(&mut self, params: &[&str]) {
        // Must be the first command: a gateway sends it before anything else.
        // `first_command_received` covers registration and repeated WEBIRC too —
        // both require earlier commands, which set the flag in dispatch.
        if self.first_command_received {
            self.quit = Some("WEBIRC command out of sequence".to_owned());
            return;
        }
        // Mark that the first command has been received, so subsequent attempts
        // or other commands will be rejected.
        self.first_command_received = true;
        let (Some(&password), Some(&gateway), Some(&hostname), Some(&ip)) =
            (params.first(), params.get(1), params.get(2), params.get(3))
        else {
            self.quit = Some("WEBIRC: not enough parameters".to_owned());
            return;
        };
        // The address that must be allow-listed is the genuine peer (the
        // gateway), never a value the gateway supplied.
        let source_ip = self.peer.ip().to_string();
        if !self.server.webirc_authorize(&source_ip, gateway, password) {
            self.quit = Some("WEBIRC authentication failed".to_owned());
            return;
        }
        // Validate the spoofed IP so a compromised gateway cannot inject a
        // non-address into hostmasks, D-Line checks, or cloaking.
        let Ok(parsed_ip) = ip.parse::<std::net::IpAddr>() else {
            self.quit = Some("WEBIRC: invalid IP address".to_owned());
            return;
        };
        let real_ip = parsed_ip.to_string();
        // The gateway passed its own D-Line at connect; now enforce the *real*
        // client's IP against the D-Line list too.
        if let Some(reason) = self.server.matches_dline(&real_ip) {
            self.quit = Some(format!("D-Lined: {reason}"));
            return;
        }
        // `secure` in the options marks the client↔gateway leg as TLS.
        let secure = params.get(4..).is_some_and(|opts| opts.contains(&"secure"));
        {
            let mut d = self.entry.data.lock();
            d.real_ip = real_ip;
            d.host = hostname.to_owned();
            if secure {
                d.secure = true;
            }
        }
        tracing::debug!(gateway, hostname, ip, "WEBIRC applied");
    }

    /// `LINKS` — list every server in the network: ourselves, direct peers,
    /// and multi-hop servers, each with its uplink and hop count.
    fn cmd_links(&mut self) {
        let our_name = self.server.info.name.clone();
        let links = self.server.links_snapshot();
        let remotes = self.server.remote_servers_snapshot();

        // SID → name, to render each remote server's uplink and to walk the
        // tree for hop counts.
        let mut names: HashMap<String, String> = HashMap::new();
        names.insert(self.server.info.sid.clone(), our_name.clone());
        for link in &links {
            names.insert(link.sid.clone(), link.name.clone());
        }
        for remote in &remotes {
            names.insert(remote.sid.clone(), remote.name.clone());
        }
        // SID → uplink SID (direct peers hang off us).
        let mut uplinks: HashMap<String, String> = HashMap::new();
        for link in &links {
            uplinks.insert(link.sid.clone(), self.server.info.sid.clone());
        }
        for remote in &remotes {
            uplinks.insert(remote.sid.clone(), remote.uplink.clone());
        }
        let hops = |sid: &str| -> usize {
            let mut count = 0;
            let mut cursor = sid.to_owned();
            while let Some(up) = uplinks.get(&cursor) {
                count += 1;
                cursor = up.clone();
                if count > uplinks.len() {
                    break; // defensive: malformed topology must not spin
                }
            }
            count
        };

        self.numeric(
            RPL_LINKS,
            &[&our_name, &our_name],
            Some(&format!("0 {}", self.server.info.network)),
        );
        for link in &links {
            self.numeric(
                RPL_LINKS,
                &[&link.name, &our_name],
                Some(&format!("1 {}", link.description)),
            );
        }
        for remote in &remotes {
            let uplink_name = names.get(&remote.uplink).cloned().unwrap_or_default();
            self.numeric(
                RPL_LINKS,
                &[&remote.name, &uplink_name],
                Some(&format!("{} {}", hops(&remote.sid), remote.description)),
            );
        }
        self.numeric(RPL_ENDOFLINKS, &["*"], Some("End of /LINKS list"));
    }

    /// `HELP [topic]` — the command index, or usage for one command.
    fn cmd_help(&mut self, params: &[&str]) {
        let topic = params.first().map(|t| t.to_ascii_uppercase());
        match topic.as_deref() {
            None | Some("") => {
                self.numeric(RPL_HELPSTART, &["*"], Some("ferrixd help index"));
                self.numeric(
                    RPL_HELPTXT,
                    &["*"],
                    Some("Use HELP <command> for usage. Available commands:"),
                );
                let names: Vec<&str> = HELP_TOPICS.iter().map(|(name, _)| *name).collect();
                for chunk in names.chunks(8) {
                    self.numeric(RPL_HELPTXT, &["*"], Some(&chunk.join(" ")));
                }
                self.numeric(RPL_ENDOFHELP, &["*"], Some("End of /HELP"));
            }
            Some(subject) => {
                let Some((name, text)) = HELP_TOPICS.iter().find(|(name, _)| *name == subject)
                else {
                    self.numeric(
                        ERR_HELPNOTFOUND,
                        &[subject],
                        Some("No help available on this topic"),
                    );
                    return;
                };
                self.numeric(RPL_HELPSTART, &[name], Some(text[0]));
                for line in &text[1..] {
                    self.numeric(RPL_HELPTXT, &[name], Some(line));
                }
                self.numeric(RPL_ENDOFHELP, &[name], Some("End of /HELP"));
            }
        }
    }

    /// `WHOWAS <nick> [count]` — recently-departed identities for a nick.
    fn cmd_whowas(&mut self, params: &[&str]) {
        let Some(&target) = params.first() else {
            self.numeric(ERR_NONICKNAMEGIVEN, &[], Some("No nickname given"));
            return;
        };
        let limit = params
            .get(1)
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(10)
            .min(10);
        let entries = self.server.whowas_lookup(&self.server.fold(target), limit);
        if entries.is_empty() {
            self.numeric(
                ERR_WASNOSUCHNICK,
                &[target],
                Some("There was no such nickname"),
            );
        }
        for entry in &entries {
            self.numeric(
                RPL_WHOWASUSER,
                &[&entry.nick, &entry.user, &entry.host, "*"],
                Some(&entry.realname),
            );
            self.numeric(
                RPL_WHOISSERVER,
                &[&entry.nick, self.server_name()],
                Some(&state::format_datetime(entry.departed_at)),
            );
        }
        self.numeric(RPL_ENDOFWHOWAS, &[target], Some("End of WHOWAS"));
    }

    /// `STATS <letter>` — server statistics. `u` (uptime) is public; the
    /// ban/operator/link reports require operator privileges.
    fn cmd_stats(&mut self, params: &[&str]) {
        let letter = params.first().copied().unwrap_or("");
        let query = letter.chars().next().unwrap_or('*');
        match query.to_ascii_lowercase() {
            'u' => {
                let up = self.server.uptime_secs();
                let (days, rem) = (up / 86_400, up % 86_400);
                let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
                self.numeric(
                    RPL_STATSUPTIME,
                    &[],
                    Some(&format!("Server Up {days} days {h:02}:{m:02}:{s:02}")),
                );
            }
            'o' if self.require_oper() => {
                for name in self.server.oper_names() {
                    self.numeric(RPL_STATSOLINE, &["O", "*", "*", &name], None);
                }
            }
            'k' if self.require_oper() => {
                for ban in self.server.klines_snapshot() {
                    self.numeric(
                        RPL_STATSKLINE,
                        &["K", &ban.mask, "*"],
                        Some(&format!("{} (set by {})", ban.reason, ban.set_by)),
                    );
                }
            }
            'd' if self.require_oper() => {
                for ban in self.server.dlines_snapshot() {
                    self.numeric(
                        RPL_STATSDLINE,
                        &["D", &ban.mask, "*"],
                        Some(&format!("{} (set by {})", ban.reason, ban.set_by)),
                    );
                }
            }
            'o' | 'k' | 'd' => return, // require_oper already sent 481
            _ => {}
        }
        self.numeric(RPL_ENDOFSTATS, &[letter], Some("End of /STATS report"));
    }

    /// `KNOCK <channel>` — ask the operators of an invite-only channel for an
    /// invitation.
    fn cmd_knock(&mut self, params: &[&str]) {
        let Some(&chan) = params.first() else {
            self.need_more_params("KNOCK");
            return;
        };
        let Some(channel) = self.server.find_channel(&self.server.fold(chan)) else {
            self.numeric(ERR_NOSUCHCHANNEL, &[chan], Some("No such channel"));
            return;
        };
        let (display, is_member, invite_only, banned) = {
            let d = channel.data.lock();
            (
                d.name.clone(),
                d.has_member(self.entry.id),
                d.modes.invite_only,
                d.is_banned(&self.entry.hostmask(), self.account().as_deref()),
            )
        };
        if is_member {
            self.numeric(ERR_KNOCKONCHAN, &[&display], Some("Is already on channel"));
            return;
        }
        if !invite_only {
            self.numeric(ERR_CHANOPEN, &[&display], Some("Channel is open"));
            return;
        }
        if banned {
            self.numeric(
                ERR_BANNEDFROMCHAN,
                &[&display],
                Some("Cannot knock on channel (+b)"),
            );
            return;
        }
        // Tell every channel operator about the knock (numeric 710, addressed
        // per recipient), then confirm delivery to the requester.
        let (nick, user, host) = self.identity();
        let mask = format!("{nick}!{user}@{host}");
        for (member, prefix) in channel.member_snapshot() {
            if !prefix.op {
                continue;
            }
            let target_nick = member.nick();
            member.send_line(
                Line::server(self.server_name())
                    .code(RPL_KNOCK)
                    .param(&target_nick)
                    .param(&display)
                    .param(&mask)
                    .trailing("has asked for an invite"),
            );
        }
        // The channel's operators may all be on other servers, so the knock has
        // to cross the link too — otherwise the "delivered" below is a lie.
        self.server
            .propagate_knock(&self.server.local_uid(self.entry.id), &display, &mask);
        self.numeric(
            RPL_KNOCKDLVR,
            &[&display],
            Some("Your KNOCK has been delivered"),
        );
    }

    /// `DIE` — operator-initiated graceful shutdown of this server.
    fn cmd_die(&mut self) {
        if !self.require_oper() {
            return;
        }
        let nick = self.entry.nick();
        let line = Line::server(self.server_name())
            .command("WALLOPS")
            .trailing(&format!("Server shutting down (DIE by {nick})"))
            .build();
        self.server.wallops(&line);
        tracing::warn!(oper = %nick, "DIE received; requesting shutdown");
        self.server.request_shutdown();
    }

    /// `USERHOST nick [nick ...]` — up to 5 nicks; reply `nick[*]=[+|-]user@host`
    /// (`*` = operator, `+`/`-` = here/away).
    fn cmd_userhost(&self, params: &[&str]) {
        if params.is_empty() {
            self.need_more_params("USERHOST");
            return;
        }
        let mut replies: Vec<String> = Vec::new();
        for &nick in params.iter().take(5) {
            if let Some(client) = self.server.find_client(&self.server.fold(nick)) {
                let (n, user, host, away, oper) = {
                    let d = client.data.lock();
                    (
                        d.nick.clone(),
                        d.user.clone(),
                        d.host.clone(),
                        d.away.is_some(),
                        d.oper,
                    )
                };
                let star = if oper { "*" } else { "" };
                let flag = if away { "-" } else { "+" };
                replies.push(format!("{n}{star}={flag}{user}@{host}"));
            }
        }
        self.numeric(RPL_USERHOST, &[], Some(&replies.join(" ")));
    }

    /// `ISON nick [nick ...]` — reply the subset of the given nicks that are
    /// online (space-separated).
    fn cmd_ison(&self, params: &[&str]) {
        if params.is_empty() {
            self.need_more_params("ISON");
            return;
        }
        let mut online: Vec<String> = Vec::new();
        for &nick in params {
            let folded = self.server.fold(nick);
            // Network-wide, like MONITOR: a nick on a linked server is online.
            if let Some(client) = self.server.find_client(&folded) {
                online.push(client.nick());
            } else if let Some(remote) = self.server.find_remote_user(&folded) {
                online.push(remote.nick);
            }
        }
        self.numeric(RPL_ISON, &[], Some(&online.join(" ")));
    }

    // ---------------------------------------------------------------- utility ---

    /// Snapshot this client's `(nick, user, host)` for building source prefixes.
    /// `MONITOR (+|-|C|L|S) [targets]` — server-side presence notification.
    /// Watched nicks trigger RPL_MONONLINE/RPL_MONOFFLINE as they connect,
    /// disconnect, or change nick.
    fn cmd_monitor(&mut self, params: &[&str]) {
        const MONITOR_LIMIT: usize = 100;
        let Some(&sub) = params.first() else {
            self.need_more_params("MONITOR");
            return;
        };
        let id = self.entry.id;
        match sub {
            "+" => {
                let Some(&list) = params.get(1) else {
                    self.need_more_params("MONITOR");
                    return;
                };
                let mut online: Vec<String> = Vec::new();
                let mut offline: Vec<String> = Vec::new();
                for target in list.split(',').filter(|s| !s.is_empty()) {
                    let folded = self.server.fold(target);
                    {
                        let mut d = self.entry.data.lock();
                        if !d.monitor.contains(&folded) && d.monitor.len() >= MONITOR_LIMIT {
                            drop(d);
                            self.numeric(
                                ERR_MONLISTFULL,
                                &[&MONITOR_LIMIT.to_string(), target],
                                Some("Monitor list is full"),
                            );
                            break;
                        }
                        d.monitor.insert(folded.clone());
                    }
                    self.server.monitor_watch(&folded, id);
                    // Presence is network-wide: a nick on a linked server is
                    // online, not offline.
                    match self.server.presence_mask(&folded) {
                        Some(mask) => online.push(mask),
                        None => offline.push(target.to_owned()),
                    }
                }
                if !online.is_empty() {
                    self.numeric(RPL_MONONLINE, &[], Some(&online.join(",")));
                }
                if !offline.is_empty() {
                    self.numeric(RPL_MONOFFLINE, &[], Some(&offline.join(",")));
                }
            }
            "-" => {
                let Some(&list) = params.get(1) else {
                    return;
                };
                for target in list.split(',').filter(|s| !s.is_empty()) {
                    let folded = self.server.fold(target);
                    self.entry.data.lock().monitor.remove(&folded);
                    self.server.monitor_unwatch(&folded, id);
                }
            }
            "C" | "c" => {
                let watched: Vec<String> = self.entry.data.lock().monitor.drain().collect();
                for folded in watched {
                    self.server.monitor_unwatch(&folded, id);
                }
            }
            "L" | "l" => {
                let watched: Vec<String> = self.entry.data.lock().monitor.iter().cloned().collect();
                for chunk in watched.chunks(10) {
                    self.numeric(RPL_MONLIST, &[], Some(&chunk.join(",")));
                }
                self.numeric(RPL_ENDOFMONLIST, &[], Some("End of MONITOR list"));
            }
            "S" | "s" => {
                let watched: Vec<String> = self.entry.data.lock().monitor.iter().cloned().collect();
                let mut online: Vec<String> = Vec::new();
                let mut offline: Vec<String> = Vec::new();
                for folded in watched {
                    match self.server.presence_mask(&folded) {
                        Some(mask) => online.push(mask),
                        None => offline.push(folded),
                    }
                }
                if !online.is_empty() {
                    self.numeric(RPL_MONONLINE, &[], Some(&online.join(",")));
                }
                if !offline.is_empty() {
                    self.numeric(RPL_MONOFFLINE, &[], Some(&offline.join(",")));
                }
            }
            _ => {}
        }
    }

    /// `RENAME <old> <new> [:<reason>]` — rename a channel in place
    /// (draft/channel-rename): membership, modes, topic, metadata, history and
    /// registration all follow the new name. Requires channel-operator status.
    fn cmd_rename(&mut self, params: &[&str]) {
        let (Some(&old), Some(&new_name)) = (params.first(), params.get(1)) else {
            self.fail(
                "RENAME",
                "NEED_MORE_PARAMS",
                &["*"],
                "Not enough parameters",
            );
            return;
        };
        let reason = params.get(2).copied().unwrap_or("");
        if !casemap::is_valid_channel(new_name) {
            self.fail(
                "RENAME",
                "CANNOT_RENAME",
                &[old, new_name],
                "Invalid channel name",
            );
            return;
        }
        let old_folded = self.server.fold(old);
        let Some(channel) = self.server.find_channel(&old_folded) else {
            self.numeric(ERR_NOSUCHCHANNEL, &[old], Some("No such channel"));
            return;
        };
        let (old_display, is_member, is_op) = {
            let d = channel.data.lock();
            let m = d.member(self.entry.id);
            (d.name.clone(), m.is_some(), m.is_some_and(|m| m.prefix.op))
        };
        if !is_member {
            self.numeric(
                ERR_NOTONCHANNEL,
                &[&old_display],
                Some("You're not on that channel"),
            );
            return;
        }
        if !is_op {
            self.numeric(
                ERR_CHANOPRIVSNEEDED,
                &[&old_display],
                Some("You're not channel operator"),
            );
            return;
        }
        match self.server.rename_channel(&old_folded, new_name) {
            Ok(channel) => {
                let (nick, user, host) = self.identity();
                self.server.broadcast_rename(
                    &channel,
                    &old_display,
                    &format!("{nick}!{user}@{host}"),
                    reason,
                );
                self.server
                    .propagate_rename(self.entry.id, &old_display, new_name, reason);
            }
            Err(state::RenameError::NameInUse) => {
                self.fail(
                    "RENAME",
                    "CHANNEL_NAME_IN_USE",
                    &[old, new_name],
                    "Channel name already in use",
                );
            }
            Err(state::RenameError::NoSuchChannel) => {
                self.numeric(ERR_NOSUCHCHANNEL, &[old], Some("No such channel"));
            }
        }
    }

    /// `REDACT <target> <msgid> [:<reason>]` — delete a previously sent message
    /// from server history and tell capable clients (draft/message-redaction).
    /// Channel operators may redact any message; everyone else only their own.
    fn cmd_redact(&mut self, params: &[&str]) {
        let (Some(&target), Some(&msgid)) = (params.first(), params.get(1)) else {
            self.fail(
                "REDACT",
                "NEED_MORE_PARAMS",
                &["*"],
                "Not enough parameters",
            );
            return;
        };
        let reason = params.get(2).copied().unwrap_or("");
        let (nick, user, host) = self.identity();
        let folded_nick = self.server.fold(&nick);
        let author_of = |stored: &StoredMessage| {
            self.server
                .fold(stored.source.split('!').next().unwrap_or(&stored.source))
        };

        if casemap::is_valid_channel(target) {
            let folded = self.server.fold(target);
            let Some(channel) = self.server.find_channel(&folded) else {
                self.fail(
                    "REDACT",
                    "INVALID_TARGET",
                    &[target, msgid],
                    "No such channel",
                );
                return;
            };
            let (display, is_member, is_op) = {
                let d = channel.data.lock();
                let m = d.member(self.entry.id);
                (d.name.clone(), m.is_some(), m.is_some_and(|m| m.prefix.op))
            };
            if !is_member {
                self.fail(
                    "REDACT",
                    "INVALID_TARGET",
                    &[target, msgid],
                    "You are not in that channel",
                );
                return;
            }
            let Some(stored) = self.server.history.find(&folded, msgid) else {
                self.fail(
                    "REDACT",
                    "UNKNOWN_MSGID",
                    &[&display, msgid],
                    "Unknown message",
                );
                return;
            };
            if !is_op && author_of(&stored) != folded_nick {
                self.fail(
                    "REDACT",
                    "REDACT_FORBIDDEN",
                    &[&display, msgid],
                    "You may only redact your own messages",
                );
                return;
            }
            self.server.history.redact(&folded, msgid);
            let mut line = Line::user(&nick, &user, &host)
                .command("REDACT")
                .param(&display)
                .param(msgid);
            if !reason.is_empty() {
                line = line.trailing(reason);
            }
            let event = self.event(line.body());
            deliver::to_channel_capped(
                &channel,
                &event,
                Cap::MessageRedaction,
                Some(self.entry.id),
            );
            if self.entry.caps().has(Cap::MessageRedaction) {
                self.deliver_self(&event);
            }
            self.server
                .propagate_redact(self.entry.id, &display, msgid, reason);
        } else {
            // A direct message: history lives under the symmetric pair key, and
            // only the author may redact.
            let folded_target = self.server.fold(target);
            let pair = pair_key(&folded_nick, &folded_target);
            let Some(stored) = self.server.history.find(&pair, msgid) else {
                self.fail(
                    "REDACT",
                    "UNKNOWN_MSGID",
                    &[target, msgid],
                    "Unknown message",
                );
                return;
            };
            if author_of(&stored) != folded_nick {
                self.fail(
                    "REDACT",
                    "REDACT_FORBIDDEN",
                    &[target, msgid],
                    "You may only redact your own messages",
                );
                return;
            }
            self.server.history.redact(&pair, msgid);
            let mut line = Line::user(&nick, &user, &host)
                .command("REDACT")
                .param(target)
                .param(msgid);
            if !reason.is_empty() {
                line = line.trailing(reason);
            }
            let event = self.event(line.body());
            if let Some(dest) = self.server.find_client(&folded_target) {
                if dest.id != self.entry.id && dest.caps().has(Cap::MessageRedaction) {
                    deliver::to_client(&dest, &event);
                }
            }
            if self.entry.caps().has(Cap::MessageRedaction) {
                self.deliver_self(&event);
            }
            self.server
                .propagate_redact(self.entry.id, target, msgid, reason);
        }
    }

    /// `WATCH [+nick|-nick|C|L|S]…` — the legacy presence-notification command.
    /// It shares MONITOR's watch list, so a client may use either spelling.
    fn cmd_watch(&mut self, params: &[&str]) {
        if params.is_empty() {
            self.cmd_monitor(&["L"]);
            return;
        }
        let id = self.entry.id;
        for &token in params {
            match token.chars().next() {
                Some('+') => {
                    let nick = &token[1..];
                    if nick.is_empty() {
                        continue;
                    }
                    let folded = self.server.fold(nick);
                    self.entry.data.lock().monitor.insert(folded.clone());
                    self.server.monitor_watch(&folded, id);
                    match self.server.presence_mask(&folded) {
                        Some(mask) => {
                            let (n, rest) = mask.split_once('!').unwrap_or((nick, "*@*"));
                            let (user, host) = rest.split_once('@').unwrap_or(("*", "*"));
                            self.numeric(RPL_NOWON, &[n, user, host, "0"], Some("is online"));
                        }
                        None => {
                            self.numeric(RPL_NOWOFF, &[nick, "*", "*", "0"], Some("is offline"))
                        }
                    }
                }
                Some('-') => {
                    let nick = &token[1..];
                    if nick.is_empty() {
                        continue;
                    }
                    let folded = self.server.fold(nick);
                    self.entry.data.lock().monitor.remove(&folded);
                    self.server.monitor_unwatch(&folded, id);
                    self.numeric(
                        RPL_WATCHOFF,
                        &[nick, "*", "*", "0"],
                        Some("stopped watching"),
                    );
                }
                Some('C' | 'c') => self.cmd_monitor(&["C"]),
                Some('L' | 'l') => {
                    let watched: Vec<String> =
                        self.entry.data.lock().monitor.iter().cloned().collect();
                    for folded in watched {
                        if let Some(mask) = self.server.presence_mask(&folded) {
                            let (n, rest) = mask.split_once('!').unwrap_or((&folded, "*@*"));
                            let (user, host) = rest.split_once('@').unwrap_or(("*", "*"));
                            self.numeric(RPL_WATCHLIST, &[n, user, host, "0"], None);
                        } else {
                            self.numeric(RPL_WATCHLIST, &[&folded, "*", "*", "0"], None);
                        }
                    }
                    self.numeric(RPL_ENDOFWATCHLIST, &["L"], Some("End of WATCH list"));
                }
                Some('S' | 's') => self.cmd_monitor(&["S"]),
                _ => {}
            }
        }
    }

    /// `SILENCE [+mask|-mask]` — a personal ignore list: masks listed here are
    /// refused delivery of private messages to this client.
    fn cmd_silence(&mut self, params: &[&str]) {
        let Some(&token) = params.first() else {
            let masks = self.entry.data.lock().silence.clone();
            for mask in &masks {
                self.numeric(RPL_SILELIST, &[mask], None);
            }
            self.numeric(RPL_ENDOFSILELIST, &[], Some("End of SILENCE list"));
            return;
        };
        match token.split_at_checked(1) {
            Some(("+", mask)) if !mask.is_empty() => {
                let mask = normalize_ban_mask(mask);
                let mut d = self.entry.data.lock();
                if d.silence.len() >= MAX_SILENCE_ENTRIES {
                    drop(d);
                    self.numeric(ERR_SILELISTFULL, &[&mask], Some("Silence list is full"));
                    return;
                }
                d.silence.insert(mask.clone());
                drop(d);
                self.numeric(RPL_SILELIST, &[&mask], None);
            }
            Some(("-", mask)) if !mask.is_empty() => {
                let mask = normalize_ban_mask(mask);
                self.entry.data.lock().silence.remove(&mask);
                self.numeric(RPL_SILELIST, &[&mask], None);
            }
            _ => {
                let masks = self.entry.data.lock().silence.clone();
                for mask in &masks {
                    self.numeric(RPL_SILELIST, &[mask], None);
                }
                self.numeric(RPL_ENDOFSILELIST, &[], Some("End of SILENCE list"));
            }
        }
    }

    /// `GLOBOPS :<message>` — an operator broadcast to `+w` users network-wide,
    /// marked as a globops (WALLOPS carries the plain text).
    fn cmd_globops(&mut self, params: &[&str]) {
        if !self.require_oper() {
            return;
        }
        let Some(&text) = params.first() else {
            self.need_more_params("GLOBOPS");
            return;
        };
        let (nick, user, host) = self.identity();
        let source = format!("{nick}!{user}@{host}");
        let body = format!("[GLOBOPS] {text}");
        let line = Line::server(&source)
            .command("WALLOPS")
            .trailing(&body)
            .build();
        self.server.wallops(&line);
        self.server.propagate_wallops(&source, &body);
    }

    /// `MAP` — the network as a tree, one line per server.
    fn cmd_map(&mut self) {
        let our_sid = self.server.info.sid.clone();
        let our_name = self.server.info.name.clone();
        let links = self.server.links_snapshot();
        let remotes = self.server.remote_servers_snapshot();

        // Children of each SID, so the tree can be walked from us outwards.
        let mut children: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for link in &links {
            children
                .entry(our_sid.clone())
                .or_default()
                .push((link.sid.clone(), link.name.clone()));
        }
        for remote in &remotes {
            children
                .entry(remote.uplink.clone())
                .or_default()
                .push((remote.sid.clone(), remote.name.clone()));
        }
        let users = self.server.client_count();
        self.numeric(RPL_MAP, &[], Some(&format!("{our_name} [{users} users]")));

        // Depth-first walk; the depth cap is a defence against a malformed
        // topology rather than a real limit (the network is a tree).
        let mut stack: Vec<(String, usize)> = vec![(our_sid, 0)];
        let mut emitted = 0usize;
        while let Some((sid, depth)) = stack.pop() {
            let Some(kids) = children.get(&sid) else {
                continue;
            };
            for (child_sid, child_name) in kids.iter().rev() {
                emitted += 1;
                if emitted > 256 || depth > 32 {
                    break;
                }
                let indent = "  ".repeat(depth + 1);
                self.numeric(RPL_MAP, &[], Some(&format!("{indent}`- {child_name}")));
                stack.push((child_sid.clone(), depth + 1));
            }
        }
        self.numeric(RPL_MAPEND, &[], Some("End of /MAP"));
    }

    /// `MARKREAD <target> [timestamp=…]` — get or set the caller's read marker
    /// (draft/read-marker). Markers only move forward; setting one syncs it to
    /// every other connection of the same account that negotiated the cap.
    fn cmd_markread(&mut self, params: &[&str]) {
        let Some(&target) = params.first() else {
            self.fail("MARKREAD", "NEED_MORE_PARAMS", &["*"], "Missing parameters");
            return;
        };
        let folded = self.server.fold(target);
        let owner = self.server.read_marker_owner(&self.entry);
        let stored = match params.get(1) {
            None => self.server.read_marker_get(&owner, &folded),
            Some(&sel) => {
                let Some(ts) = sel
                    .strip_prefix("timestamp=")
                    .and_then(state::parse_server_time)
                else {
                    self.fail(
                        "MARKREAD",
                        "INVALID_PARAMS",
                        &[target, sel],
                        "Invalid timestamp",
                    );
                    return;
                };
                Some(self.server.read_marker_advance(&owner, &folded, ts))
            }
        };
        let value = match stored {
            Some(ms) => format!("timestamp={}", state::format_server_time(ms)),
            None => "*".to_owned(),
        };
        let line = Line::server(self.server_name())
            .command("MARKREAD")
            .param(target)
            .param(&value);
        // A set is echoed to the caller AND to the user's other connections
        // (same account) so all their clients stay in sync; a get only
        // answers the requester.
        if params.get(1).is_some() {
            let bytes = line.clone().build();
            for client in self.server.clients_snapshot() {
                if client.id == self.entry.id || !client.caps().has(Cap::ReadMarker) {
                    continue;
                }
                if self.server.read_marker_owner(&client) == owner {
                    client.send(bytes.clone());
                }
            }
        }
        self.send(line);
    }

    fn identity(&self) -> (String, String, String) {
        let d = self.entry.data.lock();
        (d.nick.clone(), d.user.clone(), d.host.clone())
    }

    /// Build a self-sourced [`Event`] carrying `server-time` and this client's
    /// account (for `account-tag`).
    fn event(&self, body: String) -> Event {
        Event::new(body)
            .with_time(self.now_time())
            .with_account(self.account())
    }

    /// Tell co-members with `account-notify` that this client's login state
    /// changed: `:nick!user@host ACCOUNT <account|*>`.
    fn announce_account(&self, account: Option<&str>) {
        let (nick, user, host) = self.identity();
        let body = Line::user(&nick, &user, &host)
            .command("ACCOUNT")
            .param(account.unwrap_or("*"))
            .body();
        let event = self.event(body);
        self.propagate_monitored(&event, Cap::AccountNotify, false);
        // Sync the login state to linked peers (remote account-tag/WHOIS).
        self.server.propagate_account(self.entry.id, account);
    }

    /// Deliver `event` to every distinct co-member across the client's channels
    /// (deduped, excluding self), optionally requiring a capability, and
    /// optionally echoing to the client itself. Returns the ids of everyone the
    /// event reached (including self), so follow-up fan-outs can dedupe.
    fn propagate(&self, event: &Event, required: Option<Cap>, include_self: bool) -> HashSet<u64> {
        let channels = self.entry.data.lock().channels.clone();
        let mut seen: HashSet<u64> = HashSet::new();
        seen.insert(self.entry.id);
        for folded in &channels {
            if let Some(channel) = self.server.find_channel(folded) {
                let data = channel.data.lock();
                for member in data.members.values() {
                    if member.entry.id == self.entry.id {
                        continue;
                    }
                    if required.is_some_and(|cap| !member.entry.caps().has(cap)) {
                        continue;
                    }
                    if seen.insert(member.entry.id) {
                        deliver::to_client(&member.entry, event);
                    }
                }
            }
        }
        if include_self {
            self.deliver_self(event);
        }
        seen
    }

    /// Like [`Session::propagate`], but additionally delivers the event to
    /// clients that MONITOR this nick and negotiated `extended-monitor` plus
    /// `required` — watchers see AWAY/ACCOUNT/SETNAME/CHGHOST changes for
    /// monitored nicks without sharing a channel (IRCv3 extended-monitor).
    fn propagate_monitored(&self, event: &Event, required: Cap, include_self: bool) {
        let seen = self.propagate(event, Some(required), include_self);
        self.server.notify_extended_monitors(
            &self.server.fold(&self.entry.nick()),
            event,
            required,
            &seen,
        );
    }
}
