//! Per-connection session: local registration state plus reply helpers.
//!
//! Owned by the connection's reader task, so its fields need no locking. Shared
//! identity (nick/user/host) lives in the client's [`ClientEntry`] data; the
//! session reads it there when building prefixes.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use ferrix_protocol::{Command, Message};

use crate::cap::{self, Cap};
use crate::numeric::*;
use crate::sasl::SaslSession;
use crate::state::{self, ClientEntry, Server};
use crate::wire::Line;

/// State for one client connection through registration and normal operation.
#[derive(Debug)]
pub struct Session {
    /// Shared server state.
    pub server: Arc<Server>,
    /// This client's registry entry (mailbox + shared data).
    pub entry: Arc<ClientEntry>,
    /// Peer socket address.
    pub peer: SocketAddr,
    /// SHA-256 fingerprint of the client's TLS certificate, if any (EXTERNAL).
    pub cert_fp: Option<String>,
    /// The credential from a pre-registration `PASS`, if any.
    pub pass: Option<String>,
    /// Whether a `USER` command has been accepted.
    pub has_user: bool,
    /// Whether the client is mid `CAP` negotiation (delays registration).
    pub cap_negotiating: bool,
    /// `CAP LS` version the client requested (302 for modern clients).
    pub cap_version: u32,
    /// SASL negotiation state.
    pub sasl: SaslSession,
    /// Whether registration has completed.
    pub registered: bool,
    /// Whether `RPL_ISUPPORT` has already been sent (draft/extended-isupport
    /// sends it during CAP negotiation; the registration burst then skips it).
    pub isupport_sent: bool,
    /// Set by a handler to end the connection with this quit reason.
    pub quit: Option<String>,
    /// Whether any command (or numeric) has been received on this connection —
    /// set structurally in dispatch to enforce the WEBIRC first-command
    /// contract (a successful WEBIRC sets it too, refusing a second one).
    pub first_command_received: bool,
    /// An in-progress inbound `draft/multiline` batch, if any.
    pub multiline: Option<MultilineBatch>,
    /// When a labeled command is in progress, its label and a buffer capturing
    /// the direct replies so they can be tagged/batched (labeled-response).
    label: RefCell<Option<String>>,
    label_buffer: RefCell<Option<Vec<Bytes>>>,
}

/// An inbound `draft/multiline` batch being assembled.
#[derive(Debug)]
pub struct MultilineBatch {
    /// The batch reference the client chose.
    pub reference: String,
    /// The message target (channel or nick).
    pub target: String,
    /// Whether the messages are NOTICEs (taken from the first line — the spec
    /// requires every line of a batch to use the same command).
    pub is_notice: bool,
    /// Accumulated `(text, concat)` lines; `concat` marks a line the client
    /// tagged `draft/multiline-concat` (join to the previous one on display).
    pub lines: Vec<(String, bool)>,
    /// Total bytes accumulated, against `max-bytes`.
    pub bytes: usize,
    /// Set once a limit was exceeded: the batch is dead and its close is
    /// ignored (the client has already been told with a `FAIL`).
    pub failed: bool,
}

impl Session {
    /// Create a session for a freshly-accepted connection.
    #[must_use]
    pub fn new(
        server: Arc<Server>,
        entry: Arc<ClientEntry>,
        peer: SocketAddr,
        cert_fp: Option<String>,
    ) -> Self {
        Self {
            server,
            entry,
            peer,
            cert_fp,
            pass: None,
            has_user: false,
            cap_negotiating: false,
            cap_version: 0,
            sasl: SaslSession::default(),
            registered: false,
            isupport_sent: false,
            quit: None,
            first_command_received: false,
            multiline: None,
            label: RefCell::new(None),
            label_buffer: RefCell::new(None),
        }
    }

    /// If `msg` is a PRIVMSG/NOTICE tagged for the open multiline batch, absorb
    /// its text into the batch and return `true` (so dispatch skips it).
    ///
    /// The advertised `max-lines`/`max-bytes` are enforced here: exceeding
    /// either kills the batch with the `FAIL` the spec defines, rather than
    /// silently dropping the overflow.
    pub fn try_multiline_accumulate(&mut self, msg: &Message<'_>) -> bool {
        let Some(batch) = msg.tag("batch").flatten() else {
            return false;
        };
        let Some(multiline) = self.multiline.as_mut() else {
            return false;
        };
        if multiline.reference != batch.as_ref() {
            return false;
        }
        let Command::Named(name) = msg.command else {
            return false;
        };
        let is_notice = name.eq_ignore_ascii_case("NOTICE");
        if !is_notice && !name.eq_ignore_ascii_case("PRIVMSG") {
            return false;
        }
        if multiline.failed {
            return true; // already told the client; swallow the rest
        }
        let Some(text) = msg.params.get(1) else {
            return true;
        };
        // The command type is fixed by the batch's first line.
        if multiline.lines.is_empty() {
            multiline.is_notice = is_notice;
        }
        let concat = msg.tag("draft/multiline-concat").is_some();
        let over_lines = multiline.lines.len() >= cap::MULTILINE_MAX_LINES;
        let over_bytes = multiline.bytes + text.len() > cap::MULTILINE_MAX_BYTES;
        if over_lines || over_bytes {
            multiline.failed = true;
            let (code, limit) = if over_lines {
                ("MULTILINE_MAX_LINES", cap::MULTILINE_MAX_LINES)
            } else {
                ("MULTILINE_MAX_BYTES", cap::MULTILINE_MAX_BYTES)
            };
            let limit = limit.to_string();
            self.fail("BATCH", code, &[&limit], "Multiline batch is too large");
            return true;
        }
        multiline.bytes += text.len();
        multiline.lines.push(((*text).to_owned(), concat));
        true
    }

    /// If `msg` carries a `@label` and the client negotiated labeled-response,
    /// start buffering direct replies so they can be labeled.
    pub fn begin_label(&self, msg: &Message<'_>) {
        if !self.entry.caps().has(Cap::LabeledResponse) {
            return;
        }
        if let Some(label) = msg.tag("label").flatten() {
            *self.label.borrow_mut() = Some(label.to_string());
            *self.label_buffer.borrow_mut() = Some(Vec::new());
        }
    }

    /// Flush a labeled command's buffered replies: an `ACK` if none, the label
    /// tag on a single reply, or a `labeled-response` batch for several.
    ///
    /// When the handler already framed its own batch (CHATHISTORY), the label
    /// belongs on that `BATCH` reference itself — wrapping it in a second batch
    /// would put two `batch` tags on the same line.
    pub fn end_label(&self) {
        let Some(label) = self.label.borrow_mut().take() else {
            return;
        };
        let Some(buffer) = self.label_buffer.borrow_mut().take() else {
            return;
        };
        let label_tag = format!("label={label}");
        match buffer.len() {
            0 => {
                let ack = Line::server(self.server_name()).command("ACK").build();
                self.entry.send(prepend_tag(&ack, &label_tag));
            }
            1 => self.entry.send(prepend_tag(&buffer[0], &label_tag)),
            _ if opens_batch(&buffer[0]) => {
                self.entry.send(prepend_tag(&buffer[0], &label_tag));
                for line in &buffer[1..] {
                    self.entry.send(line.clone());
                }
            }
            _ => {
                let reference = self.server.history.next_msgid();
                let open = Line::server(self.server_name())
                    .command("BATCH")
                    .param(&format!("+{reference}"))
                    .param("labeled-response")
                    .build();
                self.entry.send(prepend_tag(&open, &label_tag));
                let batch_tag = format!("batch={reference}");
                for line in &buffer {
                    self.entry.send(prepend_tag(line, &batch_tag));
                }
                self.entry.send(
                    Line::server(self.server_name())
                        .command("BATCH")
                        .param(&format!("-{reference}"))
                        .build(),
                );
            }
        }
    }

    /// Deliver an event to this client itself (an echo of its own JOIN, PART,
    /// PRIVMSG, …). Unlike [`crate::deliver::to_client`] this honours an
    /// in-flight labeled-response buffer, so the echo carries the `label` tag
    /// rather than the client getting an unlabeled echo plus a spurious `ACK`.
    pub fn deliver_self(&self, event: &crate::deliver::Event) {
        self.emit(event.render_for(self.entry.caps()));
    }

    /// Queue bytes, capturing them into the labeled-response buffer if one is
    /// open.
    fn emit(&self, bytes: Bytes) {
        if let Some(buffer) = self.label_buffer.borrow_mut().as_mut() {
            buffer.push(bytes);
        } else {
            self.entry.send(bytes);
        }
    }

    /// The client's logged-in account name, if any.
    #[must_use]
    pub fn account(&self) -> Option<String> {
        self.entry.data.lock().account.clone()
    }

    /// A fresh `server-time` timestamp for the current instant.
    #[must_use]
    pub fn now_time(&self) -> String {
        state::format_server_time(state::now_millis())
    }

    /// Replace the displayed host with a cloak (if cloaking is enabled). An
    /// authenticated user gets `account.<network>`; otherwise the IP is HMAC-cloaked.
    fn apply_cloak(&self) {
        let Some(key) = &self.server.info.cloak_key else {
            return;
        };
        let network = &self.server.info.network;
        let mut d = self.entry.data.lock();
        d.host = match &d.account {
            Some(account) => format!("{account}.{network}"),
            None => crate::cloak::cloak_ip(key, &d.real_ip, network),
        };
    }

    /// This server's name.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server.info.name
    }

    /// The `sts=…` CAP LS token for this connection, if a policy is configured.
    /// A plaintext connection is told the TLS port to upgrade to; a TLS
    /// connection is told how long to persist the policy.
    #[must_use]
    pub fn sts_token(&self) -> Option<String> {
        let policy = self.server.info.sts.as_ref()?;
        if self.entry.data.lock().secure {
            let preload = if policy.preload { ",preload" } else { "" };
            Some(format!("sts=duration={}{preload}", policy.duration))
        } else {
            Some(format!("sts=port={}", policy.port))
        }
    }

    /// Current nickname, or `*` if none has been accepted yet.
    #[must_use]
    pub fn nick_or_star(&self) -> String {
        let nick = self.entry.nick();
        if nick.is_empty() {
            "*".to_owned()
        } else {
            nick
        }
    }

    /// Has the client accepted a nickname?
    #[must_use]
    pub fn has_nick(&self) -> bool {
        self.entry.nick() != "*"
    }

    /// Queue a built line to this client. During a labeled command the line is
    /// buffered (to be tagged on flush) instead of sent immediately.
    pub fn send(&self, line: Line) {
        self.emit(line.build());
    }

    /// Queue raw, already-rendered bytes to this client (used by handlers like
    /// CHATHISTORY that frame their own batch). Labeled-response buffering
    /// applies, so a labeled request keeps its lines together and in order.
    pub fn send_bytes(&self, bytes: Bytes) {
        self.emit(bytes);
    }

    /// Send a numeric reply: `:server <code> <nick> [params...] [:trailing]`.
    pub fn numeric(&self, code: u16, params: &[&str], trailing: Option<&str>) {
        let mut line = Line::server(self.server_name())
            .code(code)
            .param(&self.nick_or_star());
        for param in params {
            line = line.param(param);
        }
        if let Some(text) = trailing {
            line = line.trailing(text);
        }
        self.send(line);
    }

    /// Send a server `NOTICE` to this client.
    pub fn notice(&self, text: &str) {
        self.send(
            Line::server(self.server_name())
                .command("NOTICE")
                .param(&self.nick_or_star())
                .trailing(text),
        );
    }

    /// Send an IRCv3 standard reply (`FAIL`/`WARN`/`NOTE`). If the client did not
    /// negotiate `standard-replies`, fall back to a human-readable `NOTICE` so
    /// the information is not silently lost.
    fn standard_reply(&self, kind: &str, command: &str, code: &str, context: &[&str], text: &str) {
        if self.entry.caps().has(Cap::StandardReplies) {
            let mut line = Line::server(self.server_name())
                .command(kind)
                .param(command)
                .param(code);
            for item in context {
                line = line.param(item);
            }
            self.send(line.trailing(text));
        } else {
            self.notice(&format!("{command} {code}: {text}"));
        }
    }

    /// Send a `FAIL` standard reply.
    pub fn fail(&self, command: &str, code: &str, context: &[&str], text: &str) {
        self.standard_reply("FAIL", command, code, context, text);
    }

    /// Send a `NOTE` standard reply.
    pub fn note(&self, command: &str, code: &str, context: &[&str], text: &str) {
        self.standard_reply("NOTE", command, code, context, text);
    }

    /// `ERR_NEEDMOREPARAMS` for a command that was missing arguments.
    pub fn need_more_params(&self, command: &str) {
        self.numeric(
            ERR_NEEDMOREPARAMS,
            &[command],
            Some("Not enough parameters"),
        );
    }

    /// Whether this client is an IRC operator. On failure emits
    /// `ERR_NOPRIVILEGES`, so the single call site can be `if !self.require_oper()
    /// { return; }`. This is the one authoritative operator gate — handlers must
    /// use it rather than re-implementing the check.
    pub fn require_oper(&self) -> bool {
        if self.entry.data.lock().oper {
            return true;
        }
        self.numeric(
            ERR_NOPRIVILEGES,
            &[],
            Some("Permission Denied- You're not an IRC operator"),
        );
        false
    }

    /// Attempt to complete registration if all preconditions are met.
    pub fn maybe_register(&mut self) {
        if self.registered || self.cap_negotiating || !self.has_user || !self.has_nick() {
            return;
        }
        self.complete_registration();
    }

    /// Emit the post-registration burst (001–005, LUSERS, MOTD) and flip state.
    fn complete_registration(&mut self) {
        // A configured connection password must have been supplied via PASS.
        if !self.server.client_password_ok(self.pass.as_deref()) {
            self.numeric(ERR_PASSWDMISMATCH, &[], Some("Password incorrect"));
            self.quit = Some("Bad password".to_owned());
            return;
        }
        // Refuse a K-Lined hostmask (real IP) before the client is admitted.
        if let Some(reason) = self.server.matches_kline(&self.entry.real_hostmask()) {
            self.quit = Some(format!("K-Lined: {reason}"));
            return;
        }
        self.apply_cloak();
        self.registered = true;
        self.entry.data.lock().registered = true;

        let nick = self.nick_or_star();
        let (user, host) = {
            let d = self.entry.data.lock();
            (d.user.clone(), d.host.clone())
        };
        let info = &self.server.info;

        self.numeric(
            RPL_WELCOME,
            &[],
            Some(&format!(
                "Welcome to the {} Network, {nick}!{user}@{host}",
                info.network
            )),
        );
        self.numeric(
            RPL_YOURHOST,
            &[],
            Some(&format!(
                "Your host is {}, running version {}",
                info.name, info.version
            )),
        );
        self.numeric(
            RPL_CREATED,
            &[],
            Some(&format!("This server was created {}", info.created)),
        );
        // Channel modes advertised in MYINFO derive from the single BOOL_MODES
        // table plus the parameterised key/limit modes.
        let chanmodes = format!("{}kl", state::bool_mode_letters());
        let umodes = format!("iow{}", crate::command::BOT_UMODE);
        self.numeric(
            RPL_MYINFO,
            &[&info.name, &info.version, &umodes, &chanmodes],
            None,
        );
        // draft/extended-isupport may have already sent this during CAP
        // negotiation; the spec lets the registration burst skip it then.
        if !self.isupport_sent {
            self.send_isupport();
            self.isupport_sent = true;
        }
        self.send_lusers();
        self.send_motd();

        // Introduce this new local user to any linked peers (S2S).
        self.server.introduce_local(&self.entry);

        // Notify anyone MONITORing this nick that it just came online.
        self.server
            .monitor_online(&self.entry.nick(), &self.entry.hostmask());

        // Observe-only plugin hook: a client finished registration (cannot be
        // vetoed — a K-Line/password refusal already returned above).
        if let Some(plugins) = self.server.plugins() {
            let account = self.entry.data.lock().account.clone();
            let outcome = plugins.on_connect(&nick, &user, &host, account.as_deref());
            self.server.apply_plugin_actions(outcome.actions);
        }
    }

    /// Send `RPL_ISUPPORT` (005) with the tokens we advertise, split across as
    /// many lines as needed (each well under the 512-byte line limit).
    pub(crate) fn send_isupport(&self) {
        let info = &self.server.info;
        let max_ch = info.max_channels;
        // CHANMODES type groups: A=list (b,e,I), B=always-param (k), C=param-when-set
        // (l), D=boolean (derived from the single BOOL_MODES table).
        let chanmodes = format!("CHANMODES=beI,k,l,{}", state::bool_mode_letters());
        let mut tokens: Vec<String> = vec![
            "CHANTYPES=#".to_owned(),
            chanmodes,
            "PREFIX=(ov)@+".to_owned(),
            // These four are enforced by the handlers from the same constants,
            // so the advertisement cannot drift from the behaviour.
            format!("MODES={}", crate::command::MAX_MODE_CHANGES),
            "EXCEPTS=e".to_owned(),
            "INVEX=I".to_owned(),
            // Account extban (`~a:<account>`), honoured in +b/+e/+I matching.
            "EXTBAN=~,a".to_owned(),
            "MAXLIST=b:100,e:100,I:100".to_owned(),
            "MONITOR=100".to_owned(),
            "WATCH=100".to_owned(),
            format!("SILENCE={}", crate::command::MAX_SILENCE_ENTRIES),
            "WHOX".to_owned(),
            "NICKLEN=30".to_owned(),
            "CHANNELLEN=50".to_owned(),
            format!("TOPICLEN={}", crate::command::MAX_TOPIC_LEN),
            format!("KICKLEN={}", crate::command::MAX_KICK_LEN),
            format!("AWAYLEN={}", crate::command::MAX_AWAY_LEN),
            format!("CHANLIMIT=#:{max_ch}"),
            format!("MAXCHANNELS={max_ch}"),
            "CHATHISTORY=100".to_owned(),
            "MSGREFTYPES=timestamp,msgid".to_owned(),
            "TARGMAX=PRIVMSG:1,NOTICE:1".to_owned(),
            "SAFELIST".to_owned(),
            "ELIST=CMNTU".to_owned(),
            "KNOCK".to_owned(),
            "STATUSMSG=@+".to_owned(),
            "UTF8ONLY".to_owned(),
            format!("BOT={}", crate::command::BOT_UMODE),
            format!("CASEMAPPING={}", info.casemapping.isupport_token()),
            format!("NETWORK={}", info.network),
        ];
        // draft/network-icon: advertise the network's icon URL when configured.
        if let Some(icon) = &info.icon {
            tokens.push(format!("draft/ICON={icon}"));
        }
        for chunk in tokens.chunks(13) {
            let refs: Vec<&str> = chunk.iter().map(String::as_str).collect();
            self.numeric(RPL_ISUPPORT, &refs, Some("are supported by this server"));
        }
    }

    /// Send the LUSERS burst.
    pub fn send_lusers(&self) {
        let users = self.server.client_count();
        let channels = self.server.channel_count();
        let invisible = self.server.invisible_count();
        let visible = users.saturating_sub(invisible);
        let links = self.server.link_count();
        let servers = 1 + links + self.server.remote_server_count();
        let global = users + self.server.remote_user_count();
        self.numeric(
            RPL_LUSERCLIENT,
            &[],
            Some(&format!(
                "There are {visible} users and {invisible} invisible on {servers} servers"
            )),
        );
        let opers = self.server.oper_count();
        if opers > 0 {
            self.numeric(
                RPL_LUSEROP,
                &[&opers.to_string()],
                Some("operator(s) online"),
            );
        }
        let unknown = self.server.unknown_count();
        if unknown > 0 {
            self.numeric(
                RPL_LUSERUNKNOWN,
                &[&unknown.to_string()],
                Some("unknown connection(s)"),
            );
        }
        let chan_count = channels.to_string();
        self.numeric(RPL_LUSERCHANNELS, &[&chan_count], Some("channels formed"));
        self.numeric(
            RPL_LUSERME,
            &[],
            Some(&format!("I have {users} clients and {links} servers")),
        );
        let count = users.to_string();
        self.numeric(
            RPL_LOCALUSERS,
            &[&count, &count],
            Some(&format!("Current local users {users}, max {users}")),
        );
        let global_str = global.to_string();
        self.numeric(
            RPL_GLOBALUSERS,
            &[&global_str, &global_str],
            Some(&format!("Current global users {global}, max {global}")),
        );
    }

    /// Send the message of the day (or `ERR_NOMOTD` if none configured).
    pub fn send_motd(&self) {
        let motd = self.server.motd();
        if motd.is_empty() {
            self.numeric(ERR_NOMOTD, &[], Some("MOTD File is missing"));
            return;
        }
        self.numeric(
            RPL_MOTDSTART,
            &[],
            Some(&format!("- {} Message of the day -", self.server.info.name)),
        );
        for line in motd {
            self.numeric(RPL_MOTD, &[], Some(&format!("- {line}")));
        }
        self.numeric(RPL_ENDOFMOTD, &[], Some("End of /MOTD command."));
    }
}

/// Whether a rendered line opens a batch (`… BATCH +<ref> …`) — the handler
/// framed its own batch, so a labeled response labels that reference instead of
/// nesting another batch around it.
fn opens_batch(line: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(line) else {
        return false;
    };
    // Skip any tag section, then the source prefix, then look at the verb.
    let rest = match text.strip_prefix('@') {
        Some(tagged) => tagged.split_once(' ').map_or("", |(_, r)| r),
        None => text,
    };
    let rest = match rest.strip_prefix(':') {
        Some(prefixed) => prefixed.split_once(' ').map_or("", |(_, r)| r),
        None => rest,
    };
    let mut tokens = rest.split(' ');
    tokens.next().is_some_and(|verb| verb == "BATCH")
        && tokens.next().is_some_and(|arg| arg.starts_with('+'))
}

/// Prepend a message tag to an already-rendered line, merging with any existing
/// leading tags.
fn prepend_tag(line: &[u8], tag: &str) -> Bytes {
    let mut out = Vec::with_capacity(line.len() + tag.len() + 2);
    out.push(b'@');
    out.extend_from_slice(tag.as_bytes());
    if line.first() == Some(&b'@') {
        out.push(b';');
        out.extend_from_slice(&line[1..]);
    } else {
        out.push(b' ');
        out.extend_from_slice(line);
    }
    Bytes::from(out)
}
