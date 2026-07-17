//! Shared server state: the client and channel registries.
//!
//! Concurrency model: one Tokio task per connection, each owning a
//! bounded outbound mailbox ([`Outbound`], the SendQ). Global state lives in sharded
//! [`DashMap`] registries so a lookup or a channel broadcast touches only the
//! relevant shard, not a global lock.
//!
//! Locking discipline — to stay deadlock-free:
//!  * at most one channel lock is held at a time;
//!  * a channel lock may be held while touching a member's *mailbox* (a
//!    non-blocking send), but never while locking another member's [`ClientData`];
//!  * to read member identities, take a [`ChannelEntry::member_snapshot`] first,
//!    then read each client's data with no channel lock held.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use tokio::sync::{mpsc, Notify};

use crate::account::AccountStore;
use crate::cap::CapSet;
use crate::casemap::CaseMapping;
use crate::chanreg::{self, ChanRegStore, RegisteredChannel};
use crate::config::Config;
use crate::history::History;
use crate::metrics::Metrics;
use crate::wire::Line;

/// Seconds since the Unix epoch, or 0 if the clock is before it.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Milliseconds since the Unix epoch, or 0 if the clock is before it.
#[must_use]
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Convert days-since-Unix-epoch to a `(year, month, day)` civil date
/// (Howard Hinnant's days-from-civil algorithm, inverted).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Days since the Unix epoch for a civil `(year, month, day)` (Howard Hinnant's
/// days-from-civil algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse an IRCv3 `server-time` timestamp (`YYYY-MM-DDTHH:MM:SS[.sss]Z`) into
/// epoch milliseconds. Returns `None` if malformed.
#[must_use]
pub fn parse_server_time(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let min: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let ms: i64 = if b.get(19) == Some(&b'.') {
        s.get(20..23).and_then(|m| m.parse().ok()).unwrap_or(0)
    } else {
        0
    };
    let total = days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec;
    if total < 0 {
        return None;
    }
    Some((total as u64) * 1000 + ms as u64)
}

/// Format epoch milliseconds as an IRCv3 `server-time` timestamp
/// (`YYYY-MM-DDTHH:MM:SS.sssZ`).
#[must_use]
pub fn format_server_time(millis: u64) -> String {
    let secs = millis / 1000;
    let ms = millis % 1000;
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{ms:03}Z")
}

/// Format Unix seconds as a `YYYY-MM-DD HH:MM:SS UTC` string, without pulling in
/// a date crate.
#[must_use]
pub fn format_datetime(secs: u64) -> String {
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02} UTC")
}

/// A message queued for delivery to a client's socket.
#[derive(Debug, Clone)]
pub enum Outbound {
    /// Write these bytes.
    Line(Bytes),
    /// Write these bytes, then close the connection.
    Close(Bytes),
}

/// Sender end of a client's bounded outbound mailbox (the SendQ).
pub type Mailbox = mpsc::Sender<Outbound>;
/// Receiver end, drained by the connection's writer task.
pub type MailboxRx = mpsc::Receiver<Outbound>;

/// Immutable-after-startup server identity and policy.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    /// This server's name (used as the source of server-generated messages).
    pub name: String,
    /// This server's id (SID) for S2S linking.
    pub sid: String,
    /// Advertised network name (`ISUPPORT NETWORK`).
    pub network: String,
    /// Optional network icon URL (`draft/network-icon`), advertised as the
    /// `draft/ICON` ISUPPORT token when set.
    pub icon: Option<String>,
    /// Version string.
    pub version: String,
    /// Human-readable creation time, captured at startup.
    pub created: String,
    /// Case-folding rule for the whole network.
    pub casemapping: CaseMapping,
    /// Message-of-the-day lines (may be empty).
    pub motd: Vec<String>,
    /// Maximum retained messages per target for `chathistory`.
    pub history_len: usize,
    /// Maximum number of distinct in-memory history targets (memory bound).
    pub history_max_targets: usize,
    /// Maximum channels a client may be in at once (`CHANLIMIT`/`MAXCHANNELS`).
    pub max_channels: usize,
    /// HMAC key for host cloaking; `None` disables cloaking.
    pub cloak_key: Option<String>,
    /// IRCv3 `sts` policy advertised in `CAP LS` (see [`crate::config::StsConfig`]).
    pub sts: Option<crate::config::StsConfig>,
}

/// A user on a linked (remote) server, learned over S2S.
#[derive(Debug, Clone)]
pub struct RemoteUser {
    /// The SID of the server the user is on.
    pub server_sid: String,
    /// The user's network-wide id.
    pub uid: String,
    /// Nickname.
    pub nick: String,
    /// Username / ident.
    pub user: String,
    /// Host (possibly cloaked).
    pub host: String,
    /// Account, if authenticated.
    pub account: Option<String>,
    /// Real name.
    pub realname: String,
    /// Away message, if the user is away (synced over S2S).
    pub away: Option<String>,
    /// Whether the user is an IRC operator (umode `+o`, synced over S2S) —
    /// remote WHOIS shows 313, and oper-only visibility rules need it.
    pub oper: bool,
    /// Umode `+i` (invisible), synced over S2S.
    pub invisible: bool,
    /// Umode `+B` (bot-mode), synced over S2S — remote WHOIS shows `RPL_WHOISBOT`.
    pub bot: bool,
}

impl RemoteUser {
    /// `nick!user@host` hostmask.
    #[must_use]
    pub fn hostmask(&self) -> String {
        format!("{}!{}@{}", self.nick, self.user, self.host)
    }
}

/// A handle to a linked peer server: its identity plus a channel to its writer.
#[derive(Debug, Clone)]
pub struct LinkHandle {
    /// The peer's SID.
    pub sid: String,
    /// The peer's server name.
    pub name: String,
    /// The peer's description (from its `SERVER` line).
    pub description: String,
    tx: mpsc::Sender<Bytes>,
    /// Fired to ask the link's read loop to stop (operator `SQUIT`). Shared with
    /// the loop, which selects on it alongside the socket.
    shutdown: Arc<Notify>,
}

impl LinkHandle {
    /// Create a handle wrapping the writer channel.
    #[must_use]
    pub fn new(sid: String, name: String, description: String, tx: mpsc::Sender<Bytes>) -> Self {
        Self {
            sid,
            name,
            description,
            tx,
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Queue bytes to the peer (best-effort).
    pub fn send(&self, bytes: Bytes) {
        let _ = self.tx.try_send(bytes);
    }

    /// Ask the link's read loop to stop (local `SQUIT`); the loop then unwinds
    /// through the usual `drop_link` netsplit path.
    pub fn request_close(&self) {
        self.shutdown.notify_one();
    }

    /// The shutdown signal to select on inside the read loop.
    #[must_use]
    pub fn shutdown_signal(&self) -> Arc<Notify> {
        self.shutdown.clone()
    }
}

/// A server elsewhere in the network — not directly linked to us, but reachable
/// through a peer. Learned from `SSERVER` topology introductions; used for
/// cycle detection (a link or introduction naming an already-known server is
/// refused) and for splitting whole subtrees on `SQUIT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteServer {
    /// The server's SID.
    pub sid: String,
    /// The server's name.
    pub name: String,
    /// SID of the server it is connected to (its parent in the link tree).
    pub uplink: String,
    /// The server's description.
    pub description: String,
}

/// Why a channel rename was refused (draft/channel-rename).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameError {
    /// The source channel does not exist.
    NoSuchChannel,
    /// The target name is already taken by another channel.
    NameInUse,
}

/// A server ban (K-Line): a hostmask that is refused at registration.
#[derive(Debug, Clone)]
pub struct ServerBan {
    /// The `nick!user@host` glob pattern.
    pub mask: String,
    /// The reason shown to the banned user.
    pub reason: String,
    /// Who set the ban.
    pub set_by: String,
    /// When it was set (Unix seconds).
    pub set_at: u64,
}

/// The whole mutable server: the two registries plus identity.
#[derive(Debug)]
pub struct Server {
    /// Server identity / policy.
    pub info: ServerInfo,
    /// Authentication material for SASL.
    pub accounts: AccountStore,
    /// IRC-operator credentials (name → Argon2 password), verified by `OPER`.
    pub opers: AccountStore,
    /// Server-side message history for `chathistory`.
    pub history: History,
    /// Runtime metrics counters.
    pub metrics: Metrics,
    /// Live message-of-the-day (swappable by `REHASH`).
    motd: RwLock<Vec<String>>,
    /// Path of the config file, for `REHASH`.
    config_path: Mutex<Option<PathBuf>>,
    /// Registered and registering clients, keyed by folded nickname.
    clients: DashMap<String, Arc<ClientEntry>>,
    /// Secondary index of local clients by their stable numeric id, so lookups
    /// by id (e.g. an inbound S2S KILL) are O(1) rather than a full scan.
    /// Populated when a client first claims a nick; removed on disconnect.
    by_id: DashMap<u64, Arc<ClientEntry>>,
    /// Channels, keyed by folded name.
    channels: DashMap<String, Arc<ChannelEntry>>,
    /// Live connection count per source IP (connection throttling).
    ip_conns: DashMap<IpAddr, u32>,
    /// MONITOR reverse index: folded target nick → the ids of clients watching
    /// it, so on/offline transitions can notify watchers in O(watchers).
    monitors: DashMap<String, HashSet<u64>>,
    /// Server bans (K-Lines / G-Lines) matched against `nick!user@host` at
    /// registration.
    server_bans: Mutex<Vec<ServerBan>>,
    /// IP bans (D-Lines) matched against the source IP at connect time.
    ip_bans: Mutex<Vec<ServerBan>>,
    /// Linked peer servers, keyed by SID (S2S).
    links: DashMap<String, LinkHandle>,
    /// Which directly-connected peer each network SID is reachable through
    /// (`sid` → `peer_sid`). Populated as servers announce themselves; used to
    /// reject a peer that tries to speak for a SID it does not route (S2S
    /// origin enforcement — see [`Server::route_authorize`]).
    remote_routes: DashMap<String, String>,
    /// Servers beyond our direct peers (multi-hop topology), keyed by SID.
    /// Kept in sync by `SSERVER` introductions and `SQUIT` splits; consulted to
    /// refuse links and introductions that would close a cycle.
    remote_servers: DashMap<String, RemoteServer>,
    /// Users on linked servers, keyed by folded nickname (S2S).
    remote_users: DashMap<String, RemoteUser>,
    /// Secondary index of remote users by UID → folded nick, so uid lookups are
    /// O(1). Kept consistent via [`Server::remote_insert`] /
    /// [`Server::remote_remove_by_uid`].
    remote_by_uid: DashMap<String, String>,
    /// Secondary index of remote users' channel memberships (uid → folded
    /// channel names), so a remote quit or nick change touches only that user's
    /// channels instead of scanning every channel (O(channels-of-user), not
    /// O(all channels) — the difference matters on a netsplit).
    remote_channels: DashMap<String, HashSet<String>>,
    /// Registered channels, keyed by folded name.
    registered_channels: DashMap<String, RegisteredChannel>,
    /// Persistent store for channel registrations (attached if configured).
    chanreg: OnceLock<ChanRegStore>,
    /// WebAssembly plugin host (attached if configured).
    plugins: OnceLock<crate::plugin::PluginHost>,
    /// Hot-swappable server-side TLS config, so `REHASH` can reload the
    /// certificate/key without a restart. Attached at startup when TLS listeners
    /// are wired up.
    tls: OnceLock<Arc<crate::tls::SharedServerTls>>,
    /// Monotonic id source for clients.
    next_id: AtomicU64,
    /// Startup time (Unix seconds), for `STATS u`.
    started_at: u64,
    /// Recently-departed identities for `WHOWAS`, newest last (bounded ring).
    whowas: Mutex<VecDeque<WhowasEntry>>,
    /// Per-operator hostmask allowlists (`OPER` → `ERR_NOOPERHOST`); an empty
    /// list means any host may use that operator block.
    oper_hosts: RwLock<HashMap<String, Vec<String>>>,
    /// Signalled by `DIE` to request a graceful process shutdown.
    shutdown: Notify,
    /// Optional connection password (`PASS`), swappable by `REHASH`.
    client_password: RwLock<Option<String>>,
    /// `draft/read-marker` state: `owner\0folded_target` → last-read time in
    /// epoch milliseconds. Owners are accounts when logged in (so markers sync
    /// across a user's connections), otherwise folded nicks.
    read_markers: DashMap<String, u64>,
    /// Trusted WEBIRC gateways (swappable by `REHASH`). Empty disables `WEBIRC`.
    webirc: RwLock<Vec<crate::config::WebircConfig>>,
    /// Configured S2S link definitions (refreshed by `REHASH`), so operator
    /// `CONNECT` can look up a peer by name at runtime.
    link_configs: RwLock<Vec<crate::config::LinkConfig>>,
    /// TLS client config for operator-initiated outbound links (`CONNECT`).
    /// Attached at startup when any links are configured.
    link_client_config: OnceLock<Arc<rustls::ClientConfig>>,
}

/// The `+o`/`+i`/`+B` umode string for a user, or `None` when none is set (so a
/// burst does not carry a pointless frame per plain user).
fn umode_flags(oper: bool, invisible: bool, bot: bool) -> Option<String> {
    let mut flags = String::new();
    if oper {
        flags.push('o');
    }
    if invisible {
        flags.push('i');
    }
    if bot {
        flags.push('B');
    }
    (!flags.is_empty()).then(|| format!("+{flags}"))
}

/// A departed identity retained for `WHOWAS` (bounded ring buffer).
#[derive(Debug, Clone)]
pub struct WhowasEntry {
    /// Nickname at departure.
    pub nick: String,
    /// Username / ident.
    pub user: String,
    /// Displayed host (cloaked form).
    pub host: String,
    /// Real name / GECOS.
    pub realname: String,
    /// When the nick was given up (Unix seconds).
    pub departed_at: u64,
}

/// Maximum retained `WHOWAS` entries (across all nicks).
const WHOWAS_CAPACITY: usize = 1024;

impl Server {
    /// Create an empty server with the given identity.
    #[must_use]
    pub fn new(info: ServerInfo) -> Arc<Self> {
        let accounts = AccountStore::new(info.casemapping);
        let opers = AccountStore::new(info.casemapping);
        let history = History::new(info.history_len, info.history_max_targets);
        // msgids are `<sid>-<counter>`: unique network-wide, so cross-server
        // msgid references (replies, reactions, REDACT) stay unambiguous.
        history.set_msgid_prefix(&info.sid);
        let motd = RwLock::new(info.motd.clone());
        Arc::new(Self {
            info,
            accounts,
            opers,
            history,
            metrics: Metrics::default(),
            motd,
            config_path: Mutex::new(None),
            clients: DashMap::new(),
            by_id: DashMap::new(),
            channels: DashMap::new(),
            ip_conns: DashMap::new(),
            monitors: DashMap::new(),
            server_bans: Mutex::new(Vec::new()),
            ip_bans: Mutex::new(Vec::new()),
            links: DashMap::new(),
            remote_routes: DashMap::new(),
            remote_servers: DashMap::new(),
            remote_users: DashMap::new(),
            remote_by_uid: DashMap::new(),
            remote_channels: DashMap::new(),
            registered_channels: DashMap::new(),
            chanreg: OnceLock::new(),
            plugins: OnceLock::new(),
            tls: OnceLock::new(),
            next_id: AtomicU64::new(1),
            started_at: now_unix(),
            whowas: Mutex::new(VecDeque::new()),
            oper_hosts: RwLock::new(HashMap::new()),
            shutdown: Notify::new(),
            client_password: RwLock::new(None),
            read_markers: DashMap::new(),
            webirc: RwLock::new(Vec::new()),
            link_configs: RwLock::new(Vec::new()),
            link_client_config: OnceLock::new(),
        })
    }

    /// Authorise a `WEBIRC` command: the connecting `source_ip` must match one of
    /// the configured gateway's `hosts` globs AND the `password` must match that
    /// gateway (constant-time). Returns `true` only when both hold. No gateways
    /// configured means the `WEBIRC` command is disabled and this is always
    /// `false`.
    #[must_use]
    pub fn webirc_authorize(&self, source_ip: &str, gateway: &str, password: &str) -> bool {
        use subtle::ConstantTimeEq;
        let mut ok = false;
        for gw in self.webirc.read().iter() {
            // Gate on the source address first, then compare the secret. The
            // password compare runs in constant time; we deliberately test every
            // matching gateway (no early return) so timing does not reveal which
            // gateway name or which host entry matched.
            let host_ok =
                gw.name == gateway && gw.hosts.iter().any(|h| crate::mask::matches(h, source_ip));
            let pass_ok: bool = gw.password.as_bytes().ct_eq(password.as_bytes()).into();
            ok |= host_ok & pass_ok;
        }
        ok
    }

    /// Check a client's `PASS` credential against the configured connection
    /// password. `true` when no password is required or the given one matches.
    #[must_use]
    pub fn client_password_ok(&self, given: Option<&str>) -> bool {
        match self.client_password.read().as_deref() {
            None => true,
            Some(required) => given == Some(required),
        }
    }

    /// Set or clear the connection password (config apply / tests).
    pub fn set_client_password(&self, password: Option<String>) {
        *self.client_password.write() = password;
    }

    /// Replace the trusted WEBIRC gateway set (config apply / tests).
    pub fn set_webirc_gateways(&self, gateways: Vec<crate::config::WebircConfig>) {
        *self.webirc.write() = gateways;
    }

    /// Seconds since the server started (`STATS u`).
    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        now_unix().saturating_sub(self.started_at)
    }

    /// Record a departed identity for `WHOWAS` (called on disconnect and on
    /// nick change, with the old nick).
    pub fn record_whowas(&self, nick: &str, user: &str, host: &str, realname: &str) {
        if nick.is_empty() || nick == "*" {
            return;
        }
        let mut ring = self.whowas.lock();
        if ring.len() >= WHOWAS_CAPACITY {
            ring.pop_front();
        }
        ring.push_back(WhowasEntry {
            nick: nick.to_owned(),
            user: user.to_owned(),
            host: host.to_owned(),
            realname: realname.to_owned(),
            departed_at: now_unix(),
        });
    }

    /// Record a channel membership/state event for `draft/event-playback`
    /// replay. Events share the msgid/time machinery of ordinary messages but
    /// are only replayed to clients that negotiated the cap.
    pub fn record_channel_event(
        &self,
        folded: &str,
        display: &str,
        source_mask: &str,
        kind: crate::history::MessageKind,
        text: String,
    ) {
        self.history.record(
            folded,
            Arc::new(crate::history::StoredMessage {
                msgid: self.history.next_msgid(),
                time_ms: now_millis(),
                source: source_mask.to_owned(),
                account: None,
                kind,
                target: display.to_owned(),
                text,
            }),
        );
    }

    /// The most recent `WHOWAS` entries for a (folded) nick, newest first.
    #[must_use]
    pub fn whowas_lookup(&self, folded_nick: &str, limit: usize) -> Vec<WhowasEntry> {
        self.whowas
            .lock()
            .iter()
            .rev()
            .filter(|e| self.fold(&e.nick) == folded_nick)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Whether `hostmask`/`ip` may use the operator block `name`
    /// (`ERR_NOOPERHOST`). An unlisted operator or an empty list allows any
    /// host.
    #[must_use]
    pub fn oper_host_allowed(&self, name: &str, hostmask: &str, ip: &str) -> bool {
        let hosts = self.oper_hosts.read();
        let Some(masks) = hosts.get(name) else {
            return true;
        };
        masks.is_empty()
            || masks
                .iter()
                .any(|m| crate::mask::matches(m, hostmask) || crate::mask::matches(m, ip))
    }

    /// Snapshot of the K-Lines, for `STATS k`.
    #[must_use]
    pub fn klines_snapshot(&self) -> Vec<ServerBan> {
        self.server_bans.lock().clone()
    }

    /// Snapshot of the D-Lines, for `STATS d`.
    #[must_use]
    pub fn dlines_snapshot(&self) -> Vec<ServerBan> {
        self.ip_bans.lock().clone()
    }

    /// Configured operator block names, for `STATS o`.
    #[must_use]
    pub fn oper_names(&self) -> Vec<String> {
        self.oper_hosts.read().keys().cloned().collect()
    }

    /// Request a graceful process shutdown (`DIE`). Stores a permit, so the
    /// request is not lost if it fires before the main loop starts waiting.
    pub fn request_shutdown(&self) {
        self.shutdown.notify_one();
    }

    /// Resolves when a shutdown has been requested via [`Server::request_shutdown`].
    pub async fn shutdown_requested(&self) {
        self.shutdown.notified().await;
    }

    /// Attach the WebAssembly plugin host.
    pub fn attach_plugins(&self, host: crate::plugin::PluginHost) {
        let _ = self.plugins.set(host);
    }

    /// The plugin host, if any plugins are loaded.
    #[must_use]
    pub fn plugins(&self) -> Option<&crate::plugin::PluginHost> {
        self.plugins.get().filter(|host| !host.is_empty())
    }

    /// Attach the hot-swappable TLS configuration (so `REHASH` can reload certs).
    pub fn attach_tls(&self, tls: Arc<crate::tls::SharedServerTls>) {
        let _ = self.tls.set(tls);
    }

    /// The hot-swappable TLS configuration, if TLS listeners are wired up.
    #[must_use]
    pub fn tls(&self) -> Option<&Arc<crate::tls::SharedServerTls>> {
        self.tls.get()
    }

    /// Attach the TLS client config used for operator-initiated outbound links.
    pub fn attach_link_client(&self, config: Arc<rustls::ClientConfig>) {
        let _ = self.link_client_config.set(config);
    }

    /// The TLS client config for operator `CONNECT`, if links are configured.
    #[must_use]
    pub fn link_client_config(&self) -> Option<Arc<rustls::ClientConfig>> {
        self.link_client_config.get().cloned()
    }

    /// A configured link definition matching `name` (case-insensitive), for
    /// operator `CONNECT`.
    #[must_use]
    pub fn link_config_by_name(&self, name: &str) -> Option<crate::config::LinkConfig> {
        self.link_configs
            .read()
            .iter()
            .find(|l| l.name.eq_ignore_ascii_case(name))
            .cloned()
    }

    /// Resolve `target` (a SID or a server name, case-insensitive) to a directly
    /// linked peer's handle.
    #[must_use]
    pub fn direct_link(&self, target: &str) -> Option<LinkHandle> {
        if let Some(handle) = self.links.get(target) {
            return Some(handle.clone());
        }
        self.links
            .iter()
            .find(|handle| handle.name.eq_ignore_ascii_case(target))
            .map(|handle| handle.clone())
    }

    /// Operator `SQUIT`: tear down the directly-linked peer named (or SID'd) by
    /// `target`. Notifies the peer, then asks the local read loop to unwind
    /// (which runs the usual [`Server::drop_link`] netsplit). Returns the peer's
    /// server name if a matching direct link existed.
    pub fn squit_link(&self, target: &str, reason: &str) -> Option<String> {
        let handle = self.direct_link(target)?;
        // Tell the peer we are dropping it (it sees this as an SQUIT for our SID
        // and unwinds its own side), then stop our read loop locally.
        let squit = crate::s2s::LinkMessage::Squit {
            sid: self.info.sid.clone(),
            reason: reason.to_owned(),
        };
        handle.send(squit.to_line());
        handle.request_close();
        Some(handle.name.clone())
    }

    /// The S2S UID for a local client (this server's SID + the client id).
    #[must_use]
    pub fn local_uid(&self, client_id: u64) -> String {
        format!("{}{}", self.info.sid, client_id)
    }

    /// Register a newly-established peer link.
    pub fn register_link(&self, handle: LinkHandle) {
        self.links.insert(handle.sid.clone(), handle);
    }

    /// Register a peer link only if it keeps the network a tree. A link to a
    /// server whose SID or name is already present — our own identity, a
    /// directly-linked peer, or a server reachable through another peer — would
    /// close a cycle, so it is refused with a reason for the `ERROR` line.
    /// On success the peer's route is claimed atomically (`sid → sid`), so a
    /// racing introduction of the same SID through another link loses.
    ///
    /// # Errors
    ///
    /// Returns the refusal reason when the peer is already in the network.
    pub fn try_register_link(&self, handle: LinkHandle) -> Result<(), String> {
        if handle.sid == self.info.sid || handle.name.eq_ignore_ascii_case(&self.info.name) {
            return Err(format!(
                "Server {} ({}) is our own identity",
                handle.name, handle.sid
            ));
        }
        if let Some(existing) = self.server_name_owner(&handle.name) {
            if existing != handle.sid {
                return Err(format!(
                    "Server {} already exists (SID {existing}) — link would create a loop",
                    handle.name
                ));
            }
        }
        // Atomic claim: whichever path announces this SID first owns the route.
        match self.remote_routes.entry(handle.sid.clone()) {
            Entry::Occupied(o) => {
                return Err(format!(
                    "Server {} ({}) is already reachable via {} — link would create a loop",
                    handle.name,
                    handle.sid,
                    o.get()
                ));
            }
            Entry::Vacant(v) => {
                v.insert(handle.sid.clone());
            }
        }
        self.links.insert(handle.sid.clone(), handle);
        Ok(())
    }

    /// The SID that currently owns `name` (a direct peer or a known multi-hop
    /// server), if any. Server names are unique network-wide.
    fn server_name_owner(&self, name: &str) -> Option<String> {
        if let Some(link) = self
            .links
            .iter()
            .find(|l| l.name.eq_ignore_ascii_case(name))
        {
            return Some(link.sid.clone());
        }
        self.remote_servers
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
            .map(|s| s.sid.clone())
    }

    /// Accept a topology introduction (`SSERVER`) arriving from `peer_sid`.
    /// Refused — with a reason suitable for an `ERROR` line, upon which the
    /// announcing link should be dropped — when the introduced server is
    /// already known through another path (a cycle) or clashes with our own
    /// identity or an existing server name.
    ///
    /// # Errors
    ///
    /// Returns the refusal reason when the introduction would close a cycle.
    pub fn accept_remote_server(&self, peer_sid: &str, server: RemoteServer) -> Result<(), String> {
        if server.sid == self.info.sid || server.name.eq_ignore_ascii_case(&self.info.name) {
            return Err(format!(
                "Server {} ({}) is our own identity — cycle detected",
                server.name, server.sid
            ));
        }
        if let Some(existing) = self.server_name_owner(&server.name) {
            if existing != server.sid {
                return Err(format!(
                    "Server {} already exists (SID {existing}) — cycle detected",
                    server.name
                ));
            }
        }
        if !self.route_authorize(peer_sid, &server.sid) {
            let via = self
                .remote_routes
                .get(&server.sid)
                .map_or_else(|| "another link".to_owned(), |o| o.clone());
            return Err(format!(
                "Server {} ({}) is already reachable via {via} — cycle detected",
                server.name, server.sid
            ));
        }
        self.remote_servers.insert(server.sid.clone(), server);
        Ok(())
    }

    /// The direct peer that owns the route for `sid`, if known.
    #[must_use]
    pub fn route_owner(&self, sid: &str) -> Option<String> {
        self.remote_routes.get(sid).map(|o| o.clone())
    }

    /// A snapshot of the known multi-hop servers (for topology bursts).
    #[must_use]
    pub fn remote_servers_snapshot(&self) -> Vec<RemoteServer> {
        self.remote_servers.iter().map(|s| s.clone()).collect()
    }

    /// Split server `sid` and everything behind it (its uplink subtree) off the
    /// network: quit their users from every channel and forget their routes.
    pub fn split_remote_server(&self, sid: &str, reason: &str) {
        // Collect the subtree: `sid` plus every server whose uplink chain
        // passes through it.
        let mut split: HashSet<String> = HashSet::from([sid.to_owned()]);
        loop {
            let more: Vec<String> = self
                .remote_servers
                .iter()
                .filter(|s| split.contains(&s.uplink) && !split.contains(&s.sid))
                .map(|s| s.sid.clone())
                .collect();
            if more.is_empty() {
                break;
            }
            split.extend(more);
        }
        self.remote_servers.retain(|k, _| !split.contains(k));
        self.remote_routes.retain(|k, _| !split.contains(k));
        let uids: Vec<String> = self
            .remote_users
            .iter()
            .filter(|u| split.contains(&u.server_sid))
            .map(|u| u.uid.clone())
            .collect();
        for uid in uids {
            self.remote_quit(&uid, reason);
        }
    }

    /// Announce a newly-linked direct peer to every *other* link, so the whole
    /// network learns the topology (and can refuse loop-closing links).
    pub fn announce_link_to_others(&self, handle: &LinkHandle) {
        let msg = crate::s2s::LinkMessage::Sserver {
            name: handle.name.clone(),
            sid: handle.sid.clone(),
            uplink: self.info.sid.clone(),
            description: handle.description.clone(),
        };
        self.forward_to_links(&handle.sid, &msg.to_line());
    }

    /// Drop a peer link: netsplit — quit all of its users from every channel
    /// and tell the rest of the network the subtree is gone.
    pub fn drop_link(&self, sid: &str) {
        self.links.remove(sid);
        // Forget every SID that was reachable through this peer, and quit all
        // users behind those SIDs (a whole subtree splits with the peer).
        let split_sids: Vec<String> = self
            .remote_routes
            .iter()
            .filter(|r| r.value() == sid)
            .map(|r| r.key().clone())
            .collect();
        self.remote_routes.retain(|_, owner| owner.as_str() != sid);
        self.remote_servers
            .retain(|k, _| !split_sids.contains(k) && k != sid);
        let uids: Vec<String> = self
            .remote_users
            .iter()
            .filter(|u| u.server_sid == sid || split_sids.contains(&u.server_sid))
            .map(|u| u.uid.clone())
            .collect();
        for uid in uids {
            self.remote_quit(&uid, "*.net *.split");
        }
        // The rest of the network splits the peer's subtree the same way.
        let squit = crate::s2s::LinkMessage::Squit {
            sid: sid.to_owned(),
            reason: "*.net *.split".to_owned(),
        };
        self.propagate_to_links(&squit.to_line());
    }

    /// Record and/or verify that network SID `sid` is reachable through the
    /// directly-connected peer `peer_sid`. The first peer to announce a SID owns
    /// its route; a later claim from a *different* peer is refused, and our own
    /// SID is never accepted from a peer. Returns `true` if `peer_sid` may speak
    /// for `sid`. This is the S2S origin-enforcement chokepoint: it stops a
    /// linked peer from injecting users or state attributed to another server
    /// (or to us).
    #[must_use]
    pub fn route_authorize(&self, peer_sid: &str, sid: &str) -> bool {
        if sid == self.info.sid {
            return false;
        }
        match self.remote_routes.entry(sid.to_owned()) {
            Entry::Occupied(o) => o.get() == peer_sid,
            Entry::Vacant(v) => {
                v.insert(peer_sid.to_owned());
                true
            }
        }
    }

    /// Whether `peer_sid` is authorised to act for the remote user identified by
    /// `uid` — that user must be on a server routed through this peer. Unknown
    /// or locally-owned uids are refused (the latter is the explicit
    /// network-KILL path, handled separately).
    #[must_use]
    pub fn remote_uid_authorized(&self, peer_sid: &str, uid: &str) -> bool {
        match self.remote_user_by_uid(uid) {
            Some(user) => self
                .remote_routes
                .get(&user.server_sid)
                .is_some_and(|owner| owner.as_str() == peer_sid),
            None => false,
        }
    }

    /// Whether `peer_sid` may relay a message whose display `source` is a
    /// `nick!user@host`: the named nick must be a known remote user routed via
    /// this peer. Prevents a peer forging traffic as another server's users.
    #[must_use]
    pub fn remote_source_authorized(&self, peer_sid: &str, source: &str) -> bool {
        let nick = source.split('!').next().unwrap_or(source);
        let folded = self.fold(nick);
        match self.remote_users.get(&folded) {
            Some(user) => self
                .remote_routes
                .get(&user.server_sid)
                .is_some_and(|owner| owner.as_str() == peer_sid),
            None => false,
        }
    }

    /// Whether any peer links are up.
    #[must_use]
    pub fn has_links(&self) -> bool {
        !self.links.is_empty()
    }

    /// Register (or replace) a remote user learned over S2S.
    pub fn register_remote_user(&self, user: RemoteUser) {
        let folded = self.fold(&user.nick);
        self.remote_insert(folded, user);
    }

    /// Insert or refresh a remote user at `folded`, keeping the uid→folded index
    /// consistent (and dropping the index entry of any different user this
    /// replaces at the same nick).
    fn remote_insert(&self, folded: String, user: RemoteUser) {
        let stale_uid = self
            .remote_users
            .get(&folded)
            .and_then(|prev| (prev.uid != user.uid).then(|| prev.uid.clone()));
        if let Some(old) = stale_uid {
            self.remote_by_uid.remove(&old);
        }
        self.remote_by_uid.insert(user.uid.clone(), folded.clone());
        self.remote_users.insert(folded, user);
    }

    /// Remove a remote user by UID via the index. Returns the removed record.
    fn remote_remove_by_uid(&self, uid: &str) -> Option<RemoteUser> {
        let folded = self.remote_by_uid.remove(uid).map(|(_, f)| f)?;
        self.remote_users.remove(&folded).map(|(_, u)| u)
    }

    /// Accept a remote user introduction, resolving any nick collision by a
    /// deterministic rule (the lexicographically smaller UID wins — no synced
    /// clock needed). Returns a `KILL` to send back to the peer if the incoming
    /// user loses and must be removed at its origin.
    #[must_use]
    pub fn accept_remote_user(&self, user: RemoteUser) -> Option<crate::s2s::LinkMessage> {
        let folded = self.fold(&user.nick);
        let kill_for = |uid: String| crate::s2s::LinkMessage::Kill {
            uid,
            reason: "Nick collision".to_owned(),
        };

        if let Some(local) = self.find_client(&folded) {
            if user.uid < self.local_uid(local.id) {
                local.request_kill("Nick collision"); // incoming wins
                let mask = user.hostmask();
                self.remote_insert(folded, user);
                self.monitor_online_mask(&mask);
                None
            } else {
                Some(kill_for(user.uid)) // local wins; reject incoming
            }
        } else if let Some(existing) = self.remote_users.get(&folded).map(|r| r.clone()) {
            if existing.uid == user.uid {
                self.remote_insert(folded, user); // re-introduction; refresh
                None
            } else if user.uid < existing.uid {
                let loser_sid = existing.server_sid.clone();
                self.send_towards(&loser_sid, kill_for(existing.uid.clone()).to_line());
                self.purge_remote_memberships(&existing.uid, "Nick collision");
                let mask = user.hostmask();
                self.remote_insert(folded, user);
                self.monitor_online_mask(&mask);
                None
            } else {
                Some(kill_for(user.uid))
            }
        } else {
            // A user appearing anywhere on the network is "online" to a
            // MONITOR watcher here — presence is network-wide, not per-server.
            let mask = user.hostmask();
            self.remote_insert(folded, user);
            self.monitor_online_mask(&mask);
            None
        }
    }

    /// Announce a local user's nick change to all peers (S2S).
    pub fn propagate_nick_change(&self, client_id: u64, new_nick: &str) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Nick {
            uid: self.local_uid(client_id),
            nick: new_nick.to_owned(),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Apply a remote user's nick change: re-key the registry, update channel
    /// memberships, and announce it to local members who share a channel.
    ///
    /// A nick change can collide with an existing holder just like an
    /// introduction; it is resolved by the same deterministic rule (smaller UID
    /// wins). Returns a `KILL` to send back towards the changer's server if the
    /// changer loses.
    #[must_use]
    pub fn remote_nick_change(&self, uid: &str, new_nick: &str) -> Option<crate::s2s::LinkMessage> {
        let old = self.remote_user_by_uid(uid)?;
        if old.nick == new_nick {
            return None;
        }
        let (old_folded, new_folded) = (self.fold(&old.nick), self.fold(new_nick));
        let kill_for = |uid: String| crate::s2s::LinkMessage::Kill {
            uid,
            reason: "Nick collision".to_owned(),
        };

        // Collision handling (unless this is a pure case change of the same nick).
        if new_folded != old_folded {
            if let Some(local) = self.find_client(&new_folded) {
                if uid < self.local_uid(local.id).as_str() {
                    local.request_kill("Nick collision"); // changer wins
                } else {
                    self.purge_remote_memberships(uid, "Nick collision");
                    self.remote_remove_by_uid(uid);
                    return Some(kill_for(uid.to_owned())); // incumbent wins
                }
            } else if let Some(existing) = self.remote_users.get(&new_folded).map(|r| r.clone()) {
                if uid < existing.uid.as_str() {
                    let loser_sid = existing.server_sid.clone();
                    self.send_towards(&loser_sid, kill_for(existing.uid.clone()).to_line());
                    self.purge_remote_memberships(&existing.uid, "Nick collision");
                    self.remote_by_uid.remove(&existing.uid);
                } else {
                    self.purge_remote_memberships(uid, "Nick collision");
                    self.remote_remove_by_uid(uid);
                    return Some(kill_for(uid.to_owned()));
                }
            }
        }

        self.remote_users.remove(&old_folded);
        let mut updated = old.clone();
        updated.nick = new_nick.to_owned();
        // Same uid, new nick key: `remote_insert` re-points the uid index.
        self.remote_insert(new_folded, updated);

        let line = Line::user(&old.nick, &old.user, &old.host)
            .command("NICK")
            .param(new_nick)
            .build();
        let mut notified: HashSet<u64> = HashSet::new();
        for channel in self.remote_membership_channels(uid) {
            let is_member = {
                let mut d = channel.data.lock();
                match d.remote_members.get_mut(uid) {
                    Some(member) => {
                        member.nick = new_nick.to_owned();
                        true
                    }
                    None => false,
                }
            };
            if is_member {
                for (entry, _) in channel.member_snapshot() {
                    if notified.insert(entry.id) {
                        entry.send(line.clone());
                    }
                }
                // draft/event-playback: the nick change appears in each
                // channel's history.
                let (folded, display) = {
                    let d = channel.data.lock();
                    (self.fold(&d.name), d.name.clone())
                };
                self.record_channel_event(
                    &folded,
                    &display,
                    &old.hostmask(),
                    crate::history::MessageKind::Nick,
                    new_nick.to_owned(),
                );
            }
        }
        // WHOWAS: the old remote identity is now history. MONITOR sees the old
        // nick go offline and the new one come online, exactly as for a local
        // nick change.
        self.record_whowas(&old.nick, &old.user, &old.host, &old.realname);
        self.monitor_offline(&old.nick);
        self.monitor_online(new_nick, &format!("{new_nick}!{}@{}", old.user, old.host));
        None
    }

    /// Drop `folded` from a remote user's channel-membership index (after the
    /// member entry itself was removed from the channel).
    pub fn remote_channel_removed(&self, uid: &str, folded: &str) {
        if let Some(mut set) = self.remote_channels.get_mut(uid) {
            set.remove(folded);
        }
    }

    /// The channels a remote user is currently a member of (via the
    /// `remote_channels` index — O(channels-of-user)).
    fn remote_membership_channels(&self, uid: &str) -> Vec<Arc<ChannelEntry>> {
        let Some(folded) = self.remote_channels.get(uid).map(|s| s.clone()) else {
            return Vec::new();
        };
        folded
            .iter()
            .filter_map(|name| self.find_channel(name))
            .collect()
    }

    /// Remove a remote user from every channel it is in, announcing a QUIT to
    /// each local member who shared one (deduped). Used by quits, netsplits and
    /// collision kills.
    fn purge_remote_memberships(&self, uid: &str, reason: &str) {
        let Some((_, folded_set)) = self.remote_channels.remove(uid) else {
            return;
        };
        let user = self.remote_user_by_uid(uid);
        let quit = user.as_ref().map(|user| {
            Line::user(&user.nick, &user.user, &user.host)
                .command("QUIT")
                .trailing(reason)
                .build()
        });
        let mut notified: HashSet<u64> = HashSet::new();
        for folded in folded_set {
            let Some(channel) = self.find_channel(&folded) else {
                continue;
            };
            let (removed, display) = {
                let mut d = channel.data.lock();
                (d.remote_members.remove(uid).is_some(), d.name.clone())
            };
            if removed {
                if let Some(quit) = &quit {
                    for (entry, _) in channel.member_snapshot() {
                        if notified.insert(entry.id) {
                            entry.send(quit.clone());
                        }
                    }
                }
                // draft/event-playback: the quit appears in each channel's
                // history (netsplits included).
                if let Some(user) = &user {
                    self.record_channel_event(
                        &folded,
                        &display,
                        &user.hostmask(),
                        crate::history::MessageKind::Quit,
                        reason.to_owned(),
                    );
                }
                self.reap_channel(&folded);
            }
        }
    }

    /// Handle an inbound `KILL` for `uid`: disconnect the local client if the UID
    /// is ours, otherwise drop the remote user.
    /// Whether `uid` is in this server's own UID namespace (`<our-sid><id>`).
    #[must_use]
    pub fn owns_local_uid(&self, uid: &str) -> bool {
        uid.strip_prefix(&self.info.sid)
            .and_then(|rest| rest.parse::<u64>().ok())
            .is_some()
    }

    pub fn kill_by_uid(&self, uid: &str, reason: &str) {
        if let Some(id) = uid
            .strip_prefix(&self.info.sid)
            .and_then(|rest| rest.parse::<u64>().ok())
        {
            if let Some(client) = self.by_id.get(&id).map(|c| c.clone()) {
                client.request_kill(reason);
            }
        } else {
            self.remote_quit(uid, reason);
        }
    }

    /// Route an oper-initiated KILL of a remote user towards its owning
    /// server. The owner disconnects the client, whose QUIT then propagates
    /// back through the tree and purges every server's bookkeeping.
    pub fn kill_remote(&self, user: &RemoteUser, reason: &str) {
        let line = crate::s2s::LinkMessage::Kill {
            uid: user.uid.clone(),
            reason: reason.to_owned(),
        }
        .to_line();
        self.send_towards(&user.server_sid, line);
    }

    /// Handle a remote user quitting: purge them from the registry and from
    /// every channel (announcing a QUIT to local members, deduped).
    pub fn remote_quit(&self, uid: &str, reason: &str) {
        // WHOWAS and MONITOR treat the network as one presence space: a remote
        // user leaving it is exactly as observable as a local one.
        let departed = self.remote_user_by_uid(uid);
        self.purge_remote_memberships(uid, reason);
        self.remote_remove_by_uid(uid);
        if let Some(user) = departed {
            self.record_whowas(&user.nick, &user.user, &user.host, &user.realname);
            self.monitor_offline(&user.nick);
        }
    }

    /// Look up a remote user by (folded) nickname.
    #[must_use]
    pub fn find_remote_user(&self, folded_nick: &str) -> Option<RemoteUser> {
        self.remote_users.get(folded_nick).map(|r| r.clone())
    }

    /// Send bytes to a specific peer link. Returns `false` if not linked.
    pub fn send_to_link(&self, sid: &str, bytes: Bytes) -> bool {
        match self.links.get(sid) {
            Some(link) => {
                link.send(bytes);
                true
            }
            None => false,
        }
    }

    /// The directly-connected link through which `sid` is reachable: the link
    /// itself, or (multi-hop) the peer that routes it. Returns the peer's SID.
    #[must_use]
    pub fn route_for(&self, sid: &str) -> Option<String> {
        if self.links.contains_key(sid) {
            return Some(sid.to_owned());
        }
        let owner = self.remote_routes.get(sid)?;
        self.links
            .contains_key(owner.value())
            .then(|| owner.clone())
    }

    /// Send bytes towards `sid`, following the route through an intermediate
    /// peer if the server is not directly linked. Returns `false` if unroutable.
    pub fn send_towards(&self, sid: &str, bytes: Bytes) -> bool {
        match self.route_for(sid) {
            Some(peer) => self.send_to_link(&peer, bytes),
            None => false,
        }
    }

    /// Broadcast bytes to every peer link.
    pub fn propagate_to_links(&self, bytes: &Bytes) {
        for link in self.links.iter() {
            link.send(bytes.clone());
        }
    }

    /// Forward bytes to every peer link except the one they arrived on. This is
    /// what makes multi-hop (tree) topologies work: state changes applied from
    /// one link are re-announced down every other link. Loop-free on a link
    /// tree (the configured topology); a cyclic mesh is not supported.
    pub fn forward_to_links(&self, origin_sid: &str, bytes: &Bytes) {
        for link in self.links.iter() {
            if link.sid != origin_sid {
                link.send(bytes.clone());
            }
        }
    }

    /// Send our full view of the network to a freshly-linked peer (burst):
    /// the topology (every other server we know), every user we know — local,
    /// and (multi-hop) remote users we route — with away state, then every
    /// channel's memberships (with prefixes), topic, modes, and
    /// ban/exception/invite lists.
    pub fn burst_to_peer(&self, sid: &str) {
        use crate::s2s::LinkMessage;
        let Some(link) = self.links.get(sid).map(|l| l.clone()) else {
            return;
        };

        // 0. Topology: every other server we know, parents before children so
        //    each `uplink` (and each user's SID below) is already introduced.
        //    This is what lets the peer refuse a later loop-closing link.
        let mut announced: HashSet<String> = HashSet::from([self.info.sid.clone()]);
        let mut queue: Vec<LinkMessage> = Vec::new();
        for other in self.links.iter() {
            if other.sid == sid {
                continue;
            }
            announced.insert(other.sid.clone());
            queue.push(LinkMessage::Sserver {
                name: other.name.clone(),
                sid: other.sid.clone(),
                uplink: self.info.sid.clone(),
                description: other.description.clone(),
            });
        }
        let mut pending = self.remote_servers_snapshot();
        pending.retain(|s| s.sid != sid);
        while !pending.is_empty() {
            let ready: Vec<RemoteServer> = {
                let (ready, rest): (Vec<_>, Vec<_>) = pending
                    .into_iter()
                    .partition(|s| announced.contains(&s.uplink));
                pending = rest;
                ready
            };
            if ready.is_empty() {
                // Orphaned uplinks (shouldn't happen on a consistent tree):
                // announce them anyway rather than dropping them silently.
                for s in pending.drain(..) {
                    queue.push(LinkMessage::Sserver {
                        name: s.name,
                        sid: s.sid,
                        uplink: s.uplink,
                        description: s.description,
                    });
                }
                break;
            }
            for s in ready {
                announced.insert(s.sid.clone());
                queue.push(LinkMessage::Sserver {
                    name: s.name,
                    sid: s.sid,
                    uplink: s.uplink,
                    description: s.description,
                });
            }
        }
        for msg in queue {
            link.send(msg.to_line());
        }

        // 1. Local users (+ away state).
        for entry in self.clients.iter() {
            let uid = self.local_uid(entry.id);
            let d = entry.data.lock();
            if !d.registered {
                continue;
            }
            link.send(
                LinkMessage::Uid {
                    sid: self.info.sid.clone(),
                    uid: uid.clone(),
                    lamport: 0,
                    nick: d.nick.clone(),
                    user: d.user.clone(),
                    host: d.host.clone(),
                    account: d.account.clone().unwrap_or_else(|| "*".to_owned()),
                    realname: d.realname.clone(),
                }
                .to_line(),
            );
            if let Some(away) = &d.away {
                link.send(
                    LinkMessage::Saway {
                        uid: uid.clone(),
                        reason: Some(away.clone()),
                    }
                    .to_line(),
                );
            }
            if let Some(flags) = umode_flags(d.oper, d.invisible, d.bot) {
                link.send(LinkMessage::Sumode { uid, flags }.to_line());
            }
        }

        // 2. Remote users we route (multi-hop): this peer reaches them via us.
        for user in self.remote_users.iter() {
            if user.server_sid == sid {
                continue; // never announce a peer's own users back to it
            }
            link.send(
                LinkMessage::Uid {
                    sid: user.server_sid.clone(),
                    uid: user.uid.clone(),
                    lamport: 0,
                    nick: user.nick.clone(),
                    user: user.user.clone(),
                    host: user.host.clone(),
                    account: user.account.clone().unwrap_or_else(|| "*".to_owned()),
                    realname: user.realname.clone(),
                }
                .to_line(),
            );
            if let Some(away) = &user.away {
                link.send(
                    LinkMessage::Saway {
                        uid: user.uid.clone(),
                        reason: Some(away.clone()),
                    }
                    .to_line(),
                );
            }
            if let Some(flags) = umode_flags(user.oper, user.invisible, user.bot) {
                link.send(
                    LinkMessage::Sumode {
                        uid: user.uid.clone(),
                        flags,
                    }
                    .to_line(),
                );
            }
        }

        // 3. Channels: memberships (with prefixes), topic, modes, lists.
        //    Every channel frame carries the channel's creation timestamp so the
        //    peer can resolve a netjoin conflict in favour of the older channel.
        for channel in self.channels_snapshot() {
            let d = channel.data.lock();
            let ts = d.created_at;
            for (id, member) in &d.members {
                link.send(
                    LinkMessage::Sjoin {
                        channel: d.name.clone(),
                        uid: self.local_uid(*id),
                        op: member.prefix.op,
                        voice: member.prefix.voice,
                        ts,
                    }
                    .to_line(),
                );
            }
            for (uid, member) in &d.remote_members {
                if member.server_sid == sid {
                    continue;
                }
                link.send(
                    LinkMessage::Sjoin {
                        channel: d.name.clone(),
                        uid: uid.clone(),
                        op: member.prefix.op,
                        voice: member.prefix.voice,
                        ts,
                    }
                    .to_line(),
                );
            }
            if let Some(topic) = &d.topic {
                link.send(
                    LinkMessage::Stopic {
                        channel: d.name.clone(),
                        source: "*".to_owned(),
                        set_by: topic.set_by.clone(),
                        set_at: topic.set_at,
                        text: topic.text.clone(),
                    }
                    .to_line(),
                );
            }
            let (flags, args) = d.modes.render(true);
            if flags.len() > 1 {
                link.send(
                    LinkMessage::Smode {
                        channel: d.name.clone(),
                        source: "*".to_owned(),
                        ts,
                        flags,
                        args,
                    }
                    .to_line(),
                );
            }
            for (letter, list) in [('b', &d.bans), ('e', &d.exceptions), ('I', &d.invex)] {
                for chunk in list.chunks(6) {
                    link.send(
                        LinkMessage::Smode {
                            channel: d.name.clone(),
                            source: "*".to_owned(),
                            ts,
                            flags: format!("+{}", letter.to_string().repeat(chunk.len())),
                            args: chunk.iter().map(|b| b.mask.clone()).collect(),
                        }
                        .to_line(),
                    );
                }
            }
            // Outstanding invitations, so a `+i` channel stays joinable for
            // someone invited before the link came up.
            for invited in &d.invited {
                link.send(
                    LinkMessage::Sinvite {
                        source: "*".to_owned(),
                        target: invited.clone(),
                        channel: d.name.clone(),
                    }
                    .to_line(),
                );
            }
        }

        // 4. End of burst: the peer now has our complete state.
        link.send(
            LinkMessage::Ping {
                token: self.info.sid.clone(),
            }
            .to_line(),
        );
    }

    /// Announce a newly-registered local user to all peers.
    pub fn introduce_local(&self, entry: &ClientEntry) {
        if self.links.is_empty() {
            return;
        }
        let uid = self.local_uid(entry.id);
        let d = entry.data.lock();
        let msg = crate::s2s::LinkMessage::Uid {
            sid: self.info.sid.clone(),
            uid: uid.clone(),
            lamport: 0,
            nick: d.nick.clone(),
            user: d.user.clone(),
            host: d.host.clone(),
            account: d.account.clone().unwrap_or_else(|| "*".to_owned()),
            realname: d.realname.clone(),
        };
        let umodes = umode_flags(d.oper, d.invisible, d.bot);
        drop(d);
        self.propagate_to_links(&msg.to_line());
        // Umodes travel separately (UID's shape is fixed), so a user that is
        // already an oper or invisible at introduction time stays so remotely.
        if let Some(flags) = umodes {
            self.propagate_to_links(&crate::s2s::LinkMessage::Sumode { uid, flags }.to_line());
        }
    }

    /// Announce a departing local user to all peers.
    pub fn withdraw_local(&self, client_id: u64, reason: &str) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Quit {
            uid: self.local_uid(client_id),
            reason: reason.to_owned(),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Deliver a message relayed from a peer to a local recipient — or, if the
    /// target lives behind another link (multi-hop), forward it towards its
    /// server. Local delivery is routed through [`crate::deliver::Event`] so a
    /// recipient gets the `@time`/`@msgid`/`@account` tags it negotiated, and
    /// the DM is recorded for `chathistory` exactly like a local one.
    #[allow(clippy::too_many_arguments)]
    pub fn deliver_remote_message(
        &self,
        source: &str,
        target: &str,
        notice: bool,
        msgid: Option<String>,
        time_ms: Option<u64>,
        tags: Option<String>,
        text: &str,
    ) {
        let folded_target = self.fold(target);
        let source_nick = source.split('!').next().unwrap_or(source);
        if let Some(client) = self.find_client(&folded_target) {
            let account = self
                .remote_users
                .get(&self.fold(source_nick))
                .and_then(|u| u.account.clone());
            // Keep the origin's msgid/time when the wire carried them, so the
            // message is identical on every server (cross-server msgid refs).
            let msgid = msgid.unwrap_or_else(|| self.history.next_msgid());
            let now_ms = time_ms.unwrap_or_else(now_millis);
            let target_nick = client.nick();
            self.history.record(
                &crate::history::pair_key(&self.fold(source_nick), &folded_target),
                Arc::new(crate::history::StoredMessage {
                    msgid: msgid.clone(),
                    time_ms: now_ms,
                    source: source.to_owned(),
                    account: account.clone(),
                    kind: if notice {
                        crate::history::MessageKind::Notice
                    } else {
                        crate::history::MessageKind::PrivMsg
                    },
                    target: target_nick.clone(),
                    text: text.to_owned(),
                }),
            );
            let command = if notice { "NOTICE" } else { "PRIVMSG" };
            let body = format!(":{source} {command} {target_nick} :{text}");
            let mut event = crate::deliver::Event::new(body)
                .with_time(format_server_time(now_ms))
                .with_account(account)
                .with_msgid(msgid);
            if let Some(tags) = tags {
                event = event.with_client_tags(tags);
            }
            // The recipient's SILENCE list applies to remote senders too.
            if client.silences(source) {
                return;
            }
            crate::deliver::to_client(&client, &event);
        } else if let Some(remote) = self.find_remote_user(&folded_target) {
            // Multi-hop: pass the message on towards the target's server,
            // keeping the origin msgid/time/tags intact.
            let msg = crate::s2s::LinkMessage::UserMessage {
                source: source.to_owned(),
                target: remote.nick.clone(),
                notice,
                msgid,
                time_ms,
                tags,
                text: text.to_owned(),
            };
            self.send_towards(&remote.server_sid, msg.to_line());
        }
    }

    /// Deliver a relayed `TAGMSG` (tags-only message) to local recipients and
    /// forward it onward: to peers with members for a channel target, or along
    /// the route to a remote user's server.
    pub fn deliver_tagmsg(&self, origin_sid: &str, source: &str, target: &str, tags: &str) {
        let source_nick = source.split('!').next().unwrap_or(source);
        let account = self
            .remote_users
            .get(&self.fold(source_nick))
            .and_then(|u| u.account.clone());
        if crate::casemap::is_valid_channel(target) {
            let folded = self.fold(target);
            let Some(channel) = self.find_channel(&folded) else {
                return;
            };
            let display = channel.data.lock().name.clone();
            let event = crate::deliver::Event::new(format!(":{source} TAGMSG {display}"))
                .with_client_tags(tags.to_owned())
                .with_time(format_server_time(now_millis()))
                .with_account(account);
            crate::deliver::to_channel_capped(&channel, &event, crate::cap::Cap::MessageTags, None);
            self.relay_tagmsg(source, &display, tags, Some(origin_sid));
        } else if let Some(client) = self.find_client(&self.fold(target)) {
            if client.caps().has(crate::cap::Cap::MessageTags) {
                let event =
                    crate::deliver::Event::new(format!(":{source} TAGMSG {}", client.nick()))
                        .with_client_tags(tags.to_owned())
                        .with_time(format_server_time(now_millis()))
                        .with_account(account);
                crate::deliver::to_client(&client, &event);
            }
        } else if let Some(remote) = self.find_remote_user(&self.fold(target)) {
            // Multi-hop: pass it along towards the target's server.
            let msg = crate::s2s::LinkMessage::TagMessage {
                source: source.to_owned(),
                target: remote.nick.clone(),
                tags: tags.to_owned(),
            };
            self.send_towards(&remote.server_sid, msg.to_line());
        }
    }

    /// Relay a `TAGMSG` to each peer that has a member of `channel_display`
    /// (except `origin_sid`), mirroring [`Server::relay_channel_message`].
    pub fn relay_tagmsg(
        &self,
        source: &str,
        channel_display: &str,
        tags: &str,
        origin_sid: Option<&str>,
    ) {
        if self.links.is_empty() {
            return;
        }
        let Some(channel) = self.find_channel(&self.fold(channel_display)) else {
            return;
        };
        let sids: HashSet<String> = channel
            .data
            .lock()
            .remote_members
            .values()
            .map(|m| m.server_sid.clone())
            .collect();
        if sids.is_empty() {
            return;
        }
        let peers: HashSet<String> = sids.iter().filter_map(|sid| self.route_for(sid)).collect();
        let bytes = crate::s2s::LinkMessage::TagMessage {
            source: source.to_owned(),
            target: channel_display.to_owned(),
            tags: tags.to_owned(),
        }
        .to_line();
        for peer in peers {
            if Some(peer.as_str()) == origin_sid {
                continue;
            }
            self.send_to_link(&peer, bytes.clone());
        }
    }

    /// Route a locally-originated `TAGMSG` to a remote user's server.
    pub fn send_tagmsg_towards(&self, sid: &str, source: &str, target: &str, tags: &str) {
        let msg = crate::s2s::LinkMessage::TagMessage {
            source: source.to_owned(),
            target: target.to_owned(),
            tags: tags.to_owned(),
        };
        self.send_towards(sid, msg.to_line());
    }

    /// Add an IP ban (D-Line).
    pub fn add_dline(&self, mask: String, reason: String, set_by: String) {
        self.ip_bans.lock().push(ServerBan {
            mask,
            reason,
            set_by,
            set_at: now_unix(),
        });
    }

    /// Remove an IP ban by exact mask. Returns whether one was removed.
    pub fn remove_dline(&self, mask: &str) -> bool {
        let mut bans = self.ip_bans.lock();
        let before = bans.len();
        bans.retain(|b| b.mask != mask);
        bans.len() != before
    }

    /// The ban reason if `ip` matches any D-Line.
    #[must_use]
    pub fn matches_dline(&self, ip: &str) -> Option<String> {
        self.ip_bans
            .lock()
            .iter()
            .find(|b| crate::mask::matches(&b.mask, ip))
            .map(|b| b.reason.clone())
    }

    /// The current message-of-the-day.
    #[must_use]
    pub fn motd(&self) -> Vec<String> {
        self.motd.read().clone()
    }

    /// Record the config path so `REHASH` can re-read it.
    pub fn set_config_path(&self, path: PathBuf) {
        *self.config_path.lock() = Some(path);
    }

    /// Reload the config file and re-apply accounts, opers, bans, and MOTD
    /// without dropping connections (`REHASH`).
    ///
    /// # Errors
    ///
    /// Returns a message if the config cannot be read/parsed or has no path.
    pub fn rehash(&self) -> Result<(), String> {
        let path = self
            .config_path
            .lock()
            .clone()
            .ok_or_else(|| "no config path recorded".to_owned())?;
        let config = Config::load(&path).map_err(|e| e.to_string())?;
        self.apply_config(&config)?;
        // Reload the TLS certificate/key without dropping the process. A failure
        // here leaves the previous config armed (see `SharedServerTls::reload`).
        if let Some(tls) = self.tls.get() {
            tls.reload(&config.tls)
                .map_err(|e| format!("reloading TLS material: {e}"))?;
        }
        Ok(())
    }

    /// Apply the auth/MOTD portions of `config` (used at startup and by `REHASH`).
    ///
    /// # Errors
    ///
    /// Returns a message if a password fails to hash or an operator lacks one.
    pub fn apply_config(&self, config: &Config) -> Result<(), String> {
        self.accounts.clear();
        for account in &config.accounts {
            if let Some(hash) = &account.password_hash {
                self.accounts.upsert_password(&account.name, hash.clone());
            } else if let Some(password) = &account.password {
                self.accounts.set_password(&account.name, password)?;
            }
            // A `password_hash` account has no recoverable plaintext, so SCRAM
            // credentials must be supplied explicitly (`ferrixd hash-password`
            // prints both). Without them SCRAM is simply unavailable for that
            // account and clients fall back to PLAIN.
            if let Some(token) = &account.scram {
                let creds = crate::scram::ScramCreds::decode(token).ok_or_else(|| {
                    format!("account {}: malformed scram credential", account.name)
                })?;
                self.accounts.upsert_scram(&account.name, creds);
            }
            for fingerprint in &account.fingerprints {
                self.accounts
                    .add_fingerprint(&account.name, fingerprint.to_lowercase());
            }
        }

        self.opers.clear();
        {
            let mut hosts = self.oper_hosts.write();
            hosts.clear();
            for oper in &config.operators {
                let hash = match (&oper.password_hash, &oper.password) {
                    (Some(hash), _) => hash.clone(),
                    (None, Some(password)) => AccountStore::hash_password_random(password)?,
                    (None, None) => return Err(format!("operator {} has no password", oper.name)),
                };
                self.opers.upsert_password(&oper.name, hash);
                hosts.insert(oper.name.clone(), oper.hosts.clone());
            }
        }

        {
            let mut bans = self.server_bans.lock();
            bans.clear();
            for ban in &config.bans {
                bans.push(ServerBan {
                    mask: ban.mask.clone(),
                    reason: ban.reason.clone(),
                    set_by: "config".to_owned(),
                    set_at: now_unix(),
                });
            }
        }

        *self.motd.write() = config.server.motd.clone();
        self.set_client_password(config.server.password.clone());
        *self.webirc.write() = config.webirc.clone();
        *self.link_configs.write() = config.links.clone();

        // Self-registered accounts survive a REHASH: re-apply the persisted set
        // on top of the config seed (config-defined names win on collision).
        self.restore_persisted_accounts();
        Ok(())
    }

    /// Load persisted self-registered accounts into the live store (no-op
    /// without a persistence backend). Existing names are left untouched.
    pub fn restore_persisted_accounts(&self) -> usize {
        let Some(store) = self.chanreg.get() else {
            return 0;
        };
        let records = store.load_accounts();
        let count = records.len();
        for record in records {
            self.accounts
                .restore_if_absent(&record.display, record.password_hash, record.scram);
        }
        count
    }

    /// Persist an account's current credentials (no-op without a backend).
    pub fn persist_account(&self, name: &str) {
        let Some(store) = self.chanreg.get() else {
            return;
        };
        if let Some((display, password_hash, scram)) = self.accounts.snapshot(name) {
            store.upsert_account(&chanreg::AccountRecord {
                folded: self.fold(name),
                display,
                password_hash,
                scram,
            });
        }
    }

    /// Add a server ban (K-Line).
    pub fn add_kline(&self, mask: String, reason: String, set_by: String) {
        self.server_bans.lock().push(ServerBan {
            mask,
            reason,
            set_by,
            set_at: now_unix(),
        });
    }

    /// Remove a server ban by exact mask. Returns whether one was removed.
    pub fn remove_kline(&self, mask: &str) -> bool {
        let mut bans = self.server_bans.lock();
        let before = bans.len();
        bans.retain(|b| b.mask != mask);
        bans.len() != before
    }

    /// The ban reason if `hostmask` (`nick!user@host`) matches any K-Line.
    #[must_use]
    pub fn matches_kline(&self, hostmask: &str) -> Option<String> {
        self.server_bans
            .lock()
            .iter()
            .find(|b| crate::mask::matches(&b.mask, hostmask))
            .map(|b| b.reason.clone())
    }

    /// Force-disconnect every connected client whose hostmask matches `mask`.
    /// Returns how many were killed.
    pub fn kill_matching(&self, mask: &str, reason: &str) -> usize {
        let mut count = 0;
        for entry in self.clients.iter() {
            if crate::mask::matches(mask, &entry.real_hostmask()) {
                entry.request_kill(reason);
                count += 1;
            }
        }
        count
    }

    /// Force-disconnect every connected client whose real IP matches `mask`.
    pub fn kill_matching_ip(&self, mask: &str, reason: &str) -> usize {
        let mut count = 0;
        for entry in self.clients.iter() {
            let ip = entry.data.lock().real_ip.clone();
            if crate::mask::matches(mask, &ip) {
                entry.request_kill(reason);
                count += 1;
            }
        }
        count
    }

    /// Register a new connection from `ip`, enforcing a per-IP maximum. Returns
    /// `false` (and counts nothing) if the IP is already at the limit.
    pub fn try_add_connection(&self, ip: IpAddr, max_per_ip: u32) -> bool {
        let mut count = self.ip_conns.entry(ip).or_insert(0);
        if *count >= max_per_ip {
            return false;
        }
        *count += 1;
        true
    }

    /// Drop a connection from the per-IP count.
    pub fn remove_connection(&self, ip: IpAddr) {
        if let Some(mut count) = self.ip_conns.get_mut(&ip) {
            *count = count.saturating_sub(1);
        }
        self.ip_conns.remove_if(&ip, |_, &v| v == 0);
    }

    /// Fold a name to its registry key form.
    #[must_use]
    pub fn fold(&self, name: &str) -> String {
        self.info.casemapping.fold(name)
    }

    /// Allocate a fresh, unique client id.
    pub fn alloc_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Number of clients currently tracked (registered or registering).
    #[must_use]
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Number of channels currently in existence.
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Number of local IRC operators (umode `+o`), for LUSERS/STATS.
    #[must_use]
    pub fn oper_count(&self) -> usize {
        self.clients
            .iter()
            .filter(|c| {
                let d = c.data.lock();
                d.registered && d.oper
            })
            .count()
    }

    /// Number of live connections that have not completed registration
    /// (`RPL_LUSERUNKNOWN`). Derived from the per-IP connection ledger, which
    /// tracks every accepted client socket from accept to disconnect.
    #[must_use]
    pub fn unknown_count(&self) -> usize {
        let conns: usize = self.ip_conns.iter().map(|e| *e.value() as usize).sum();
        let registered = self
            .clients
            .iter()
            .filter(|c| c.data.lock().registered)
            .count();
        conns.saturating_sub(registered)
    }

    /// Number of users on linked servers, for LUSERS global counts.
    #[must_use]
    pub fn remote_user_count(&self) -> usize {
        self.remote_users.len()
    }

    /// Number of directly-linked peer servers.
    #[must_use]
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Number of known servers beyond the direct peers (multi-hop topology).
    #[must_use]
    pub fn remote_server_count(&self) -> usize {
        self.remote_servers.len()
    }

    /// Snapshot of the directly-linked peers, for LINKS/LUSERS.
    #[must_use]
    pub fn links_snapshot(&self) -> Vec<LinkHandle> {
        self.links.iter().map(|e| e.value().clone()).collect()
    }

    /// Number of registered clients with umode `+i` (invisible), for LUSERS.
    #[must_use]
    pub fn invisible_count(&self) -> usize {
        self.clients
            .iter()
            .filter(|c| {
                let d = c.data.lock();
                d.registered && d.invisible
            })
            .count()
    }

    /// Fan `bytes` out to every local client with umode `+w` (WALLOPS).
    pub fn wallops(&self, bytes: &Bytes) {
        for entry in self.clients.iter() {
            if entry.data.lock().wallops {
                entry.send(bytes.clone());
            }
        }
    }

    // --------------------------------------------------------- read-marker ---

    /// The read-marker owner key for a client: the account when logged in (so
    /// markers are shared across that user's connections), else the folded
    /// nick. The `a`/`n` prefix keeps the two namespaces from colliding.
    #[must_use]
    pub fn read_marker_owner(&self, entry: &ClientEntry) -> String {
        let d = entry.data.lock();
        match &d.account {
            Some(account) => format!("a\0{}", self.fold(account)),
            None => format!("n\0{}", self.fold(&d.nick)),
        }
    }

    /// The stored read marker for `owner` on `folded_target`, if any.
    #[must_use]
    pub fn read_marker_get(&self, owner: &str, folded_target: &str) -> Option<u64> {
        self.read_markers
            .get(&format!("{owner}\0{folded_target}"))
            .map(|v| *v)
    }

    /// Advance the read marker (markers only move forward — an older timestamp
    /// leaves the stored one untouched). Returns the effective marker.
    pub fn read_marker_advance(&self, owner: &str, folded_target: &str, time_ms: u64) -> u64 {
        let mut slot = self
            .read_markers
            .entry(format!("{owner}\0{folded_target}"))
            .or_insert(time_ms);
        *slot = (*slot).max(time_ms);
        *slot
    }

    // ------------------------------------------------------------- MONITOR ---

    /// Register `watcher_id` as monitoring `folded` (target nick).
    pub fn monitor_watch(&self, folded: &str, watcher_id: u64) {
        self.monitors
            .entry(folded.to_owned())
            .or_default()
            .insert(watcher_id);
    }

    /// Stop `watcher_id` monitoring `folded`; drop the entry if now unwatched.
    pub fn monitor_unwatch(&self, folded: &str, watcher_id: u64) {
        if let Some(mut set) = self.monitors.get_mut(folded) {
            set.remove(&watcher_id);
            if set.is_empty() {
                drop(set);
                self.monitors.remove(folded);
            }
        }
    }

    /// Notify every watcher of `folded` that the nick came online (`RPL_MONONLINE`
    /// with `mask`) or went offline (`RPL_MONOFFLINE` with `payload`).
    fn notify_monitors(&self, folded: &str, code: u16, payload: &str) {
        let Some(watchers) = self.monitors.get(folded).map(|s| s.clone()) else {
            return;
        };
        for id in watchers {
            if let Some(w) = self.by_id.get(&id) {
                let wnick = w.nick();
                w.send(
                    Line::server(&self.info.name)
                        .code(code)
                        .param(&wnick)
                        .trailing(payload)
                        .build(),
                );
            }
        }
    }

    /// Deliver `event` to clients monitoring `folded` that negotiated
    /// `extended-monitor` plus `required`, skipping ids in `already` (they were
    /// reached via a shared channel). IRCv3 extended-monitor: watchers see
    /// AWAY/ACCOUNT/SETNAME/CHGHOST changes for monitored nicks.
    pub fn notify_extended_monitors(
        &self,
        folded: &str,
        event: &crate::deliver::Event,
        required: crate::cap::Cap,
        already: &HashSet<u64>,
    ) {
        let Some(watchers) = self.monitors.get(folded).map(|s| s.clone()) else {
            return;
        };
        for id in watchers {
            if already.contains(&id) {
                continue;
            }
            if let Some(watcher) = self.by_id.get(&id) {
                let caps = watcher.caps();
                if caps.has(crate::cap::Cap::ExtendedMonitor) && caps.has(required) {
                    crate::deliver::to_client(&watcher, event);
                }
            }
        }
    }

    /// Announce that `nick` (with hostmask `mask`) is now online to its watchers.
    pub fn monitor_online(&self, nick: &str, mask: &str) {
        self.notify_monitors(&self.fold(nick), crate::numeric::RPL_MONONLINE, mask);
    }

    /// [`Server::monitor_online`] for a full `nick!user@host` mask.
    fn monitor_online_mask(&self, mask: &str) {
        let nick = mask.split('!').next().unwrap_or(mask);
        self.monitor_online(nick, mask);
    }

    /// Announce that `nick` went offline to its watchers.
    pub fn monitor_offline(&self, nick: &str) {
        self.notify_monitors(&self.fold(nick), crate::numeric::RPL_MONOFFLINE, nick);
    }

    /// The `nick!user@host` of whoever holds this (folded) nick anywhere on the
    /// network — local or on a linked server — or `None` if nobody does.
    /// Presence (MONITOR, ISON) is network-wide, not per-server.
    #[must_use]
    pub fn presence_mask(&self, folded_nick: &str) -> Option<String> {
        self.find_client(folded_nick)
            .map(|c| c.hostmask())
            .or_else(|| self.find_remote_user(folded_nick).map(|u| u.hostmask()))
    }

    /// Look up a client by (already-folded) nickname.
    #[must_use]
    pub fn find_client(&self, folded_nick: &str) -> Option<Arc<ClientEntry>> {
        self.clients.get(folded_nick).map(|r| r.clone())
    }

    /// Look up a channel by (already-folded) name.
    #[must_use]
    pub fn find_channel(&self, folded_name: &str) -> Option<Arc<ChannelEntry>> {
        self.channels.get(folded_name).map(|r| r.clone())
    }

    /// A snapshot of all channels (for `LIST`).
    #[must_use]
    pub fn channels_snapshot(&self) -> Vec<Arc<ChannelEntry>> {
        self.channels.iter().map(|r| r.value().clone()).collect()
    }

    /// A snapshot of all local clients (for mask-based `WHO`).
    #[must_use]
    pub fn clients_snapshot(&self) -> Vec<Arc<ClientEntry>> {
        self.clients.iter().map(|r| r.value().clone()).collect()
    }

    /// A snapshot of all users on linked servers (for mask-based `WHO`).
    #[must_use]
    pub fn remote_users_snapshot(&self) -> Vec<RemoteUser> {
        self.remote_users
            .iter()
            .map(|r| r.value().clone())
            .collect()
    }

    /// Atomically claim `folded` for `entry`. Returns `false` if already taken
    /// by a *different* client.
    pub fn claim_nick(&self, folded: &str, entry: &Arc<ClientEntry>) -> bool {
        // A nick held by a remote (linked) user counts as in use, so a local
        // user cannot create a fresh cross-server collision.
        if self.remote_users.contains_key(folded) {
            return false;
        }
        match self.clients.entry(folded.to_owned()) {
            Entry::Occupied(o) => o.get().id == entry.id,
            Entry::Vacant(v) => {
                v.insert(entry.clone());
                // Index by stable id (idempotent across nick changes; removed on
                // disconnect) so lookups by id are O(1).
                self.by_id.insert(entry.id, entry.clone());
                true
            }
        }
    }

    /// Release a folded nickname from the registry.
    pub fn release_nick(&self, folded: &str) {
        self.clients.remove(folded);
    }

    /// Get an existing channel or create it. Returns `(channel, created)`.
    pub fn get_or_create_channel(
        &self,
        folded: &str,
        display_name: &str,
    ) -> (Arc<ChannelEntry>, bool) {
        match self.channels.entry(folded.to_owned()) {
            Entry::Occupied(o) => (o.get().clone(), false),
            Entry::Vacant(v) => {
                let channel = Arc::new(ChannelEntry::new(display_name));
                // A registered channel is re-seeded with its saved topic + modes.
                if let Some(record) = self.registered_channels.get(folded) {
                    seed_from_registration(&channel, &record);
                }
                v.insert(channel.clone());
                (channel, true)
            }
        }
    }

    /// Begin a JOIN: get-or-create the channel and register an in-flight join in
    /// one atomic step (the `joining` counter is bumped while the shard lock is
    /// held), then return a [`JoinGuard`] that keeps the channel unreapable until
    /// the caller has finished inserting its member. This closes the create/reap
    /// race: a concurrent PART+reap of the last member cannot delete the channel
    /// out from under an in-progress joiner.
    pub fn begin_join(
        self: &Arc<Self>,
        folded: &str,
        display_name: &str,
    ) -> (Arc<ChannelEntry>, bool, JoinGuard) {
        let (channel, created) = match self.channels.entry(folded.to_owned()) {
            Entry::Occupied(o) => {
                let channel = o.get().clone();
                // Bump under the shard lock so reap cannot interleave.
                channel.joining.fetch_add(1, Ordering::AcqRel);
                (channel, false)
            }
            Entry::Vacant(v) => {
                let channel = Arc::new(ChannelEntry::new(display_name));
                if let Some(record) = self.registered_channels.get(folded) {
                    seed_from_registration(&channel, &record);
                }
                channel.joining.fetch_add(1, Ordering::AcqRel);
                v.insert(channel.clone());
                (channel, true)
            }
        };
        let guard = JoinGuard {
            server: self.clone(),
            folded: folded.to_owned(),
            channel: channel.clone(),
        };
        (channel, created, guard)
    }

    /// Drop a channel if it has no local *or* remote members and no join is in
    /// flight (registered channels are still reaped when empty — the
    /// registration record persists). Also forgets the channel's in-memory
    /// history ring so reaped channels do not accumulate rings forever.
    pub fn reap_channel(&self, folded: &str) {
        let removed = self.channels.remove_if(folded, |_, ch| {
            let d = ch.data.lock();
            d.members.is_empty()
                && d.remote_members.is_empty()
                && ch.joining.load(Ordering::Acquire) == 0
        });
        if removed.is_some() {
            self.history.forget(folded);
        }
    }

    // ------------------------------------------------------- channel rename ---

    /// Rename a channel in place (draft/channel-rename): the entry keeps its
    /// members, modes, topic and metadata; the map key, every member's
    /// membership set, the history ring, read markers and the registration
    /// record move to the new name. A pure case change only updates the
    /// display name.
    pub fn rename_channel(
        &self,
        old_folded: &str,
        new_name: &str,
    ) -> Result<Arc<ChannelEntry>, RenameError> {
        let new_folded = self.fold(new_name);
        let Some(channel) = self.find_channel(old_folded) else {
            return Err(RenameError::NoSuchChannel);
        };
        if new_folded != old_folded {
            // Claim the new key atomically; refuse if any channel holds it.
            match self.channels.entry(new_folded.clone()) {
                Entry::Occupied(_) => return Err(RenameError::NameInUse),
                Entry::Vacant(slot) => {
                    slot.insert(channel.clone());
                }
            }
            self.channels.remove(old_folded);
        }
        let (local_ids, remote_uids) = {
            let mut d = channel.data.lock();
            d.name = new_name.to_owned();
            (
                d.members.keys().copied().collect::<Vec<_>>(),
                d.remote_members.keys().cloned().collect::<Vec<_>>(),
            )
        };
        if new_folded != old_folded {
            for id in local_ids {
                if let Some(entry) = self.by_id.get(&id).map(|e| e.clone()) {
                    let mut d = entry.data.lock();
                    d.channels.remove(old_folded);
                    d.channels.insert(new_folded.clone());
                }
            }
            for uid in remote_uids {
                if let Some(mut set) = self.remote_channels.get_mut(&uid) {
                    set.remove(old_folded);
                    set.insert(new_folded.clone());
                }
            }
            // History, registration and read markers follow the new name.
            self.history.rename_target(old_folded, &new_folded);
            if let Some((_, mut record)) = self.registered_channels.remove(old_folded) {
                record.folded = new_folded.clone();
                record.name = new_name.to_owned();
                self.registered_channels.insert(new_folded.clone(), record);
                if let Some(store) = self.chanreg.get() {
                    store.delete(old_folded);
                }
                self.persist_registered(&new_folded);
            }
            let suffix = format!("\0{old_folded}");
            let moved: Vec<(String, u64)> = self
                .read_markers
                .iter()
                .filter(|e| e.key().ends_with(&suffix))
                .map(|e| (e.key().clone(), *e.value()))
                .collect();
            for (key, value) in moved {
                self.read_markers.remove(&key);
                let owner = &key[..key.len() - suffix.len()];
                self.read_markers
                    .insert(format!("{owner}\0{new_folded}"), value);
            }
        }
        Ok(channel)
    }

    /// Announce a channel rename to local members: `RENAME` for clients with
    /// the cap, and a PART/JOIN + topic + NAMES resync for everyone else (the
    /// draft/channel-rename fallback).
    pub fn broadcast_rename(
        &self,
        channel: &Arc<ChannelEntry>,
        old_display: &str,
        source_mask: &str,
        reason: &str,
    ) {
        let (new_display, topic, names) = {
            let d = channel.data.lock();
            let mut names: Vec<(String, MemberPrefix)> = d
                .members
                .values()
                .map(|m| (m.entry.nick(), m.prefix))
                .collect();
            names.extend(
                d.remote_members
                    .values()
                    .map(|m| (m.nick.clone(), m.prefix)),
            );
            (d.name.clone(), d.topic.clone(), names)
        };
        let mut line = Line::server(source_mask)
            .command("RENAME")
            .param(old_display)
            .param(&new_display);
        if !reason.is_empty() {
            line = line.trailing(reason);
        }
        let event =
            crate::deliver::Event::new(line.body()).with_time(format_server_time(now_millis()));
        for (entry, _) in channel.member_snapshot() {
            let caps = entry.caps();
            if caps.has(crate::cap::Cap::ChannelRename) {
                crate::deliver::to_client(&entry, &event);
                continue;
            }
            // Fallback resync: the member sees itself leave the old name and
            // join the new one, then topic and NAMES restore its view.
            let mask = entry.hostmask();
            let nick = entry.nick();
            entry.send_line(
                Line::server(&mask)
                    .command("PART")
                    .param(old_display)
                    .trailing(&format!("Channel renamed to {new_display}")),
            );
            entry.send_line(Line::server(&mask).command("JOIN").param(&new_display));
            if let Some(t) = &topic {
                entry.send_line(
                    Line::server(&self.info.name)
                        .code(crate::numeric::RPL_TOPIC)
                        .param(&nick)
                        .param(&new_display)
                        .trailing(&t.text),
                );
            }
            let multi = caps.has(crate::cap::Cap::MultiPrefix);
            let rendered: Vec<String> = names
                .iter()
                .map(|(n, p)| format!("{}{n}", p.render(multi)))
                .collect();
            for chunk in rendered.chunks(12) {
                entry.send_line(
                    Line::server(&self.info.name)
                        .code(crate::numeric::RPL_NAMREPLY)
                        .param(&nick)
                        .param("=")
                        .param(&new_display)
                        .trailing(&chunk.join(" ")),
                );
            }
            entry.send_line(
                Line::server(&self.info.name)
                    .code(crate::numeric::RPL_ENDOFNAMES)
                    .param(&nick)
                    .param(&new_display)
                    .trailing("End of /NAMES list"),
            );
        }
    }

    /// Propagate a local channel rename to all peers (S2S).
    pub fn propagate_rename(&self, client_id: u64, old: &str, new: &str, reason: &str) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Srename {
            source: self.local_uid(client_id),
            old: old.to_owned(),
            new: new.to_owned(),
            reason: reason.to_owned(),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Apply a channel rename arriving over a link: move the local state and
    /// resync local members.
    pub fn remote_rename(&self, source: &str, old: &str, new: &str, reason: &str) {
        let old_folded = self.fold(old);
        if let Ok(channel) = self.rename_channel(&old_folded, new) {
            self.broadcast_rename(&channel, old, &self.remote_source_mask(source), reason);
        }
    }

    // ------------------------------------------------------ channel registration ---

    /// Attach the persistence store and load existing registrations.
    pub fn attach_chanreg(&self, store: ChanRegStore, records: Vec<RegisteredChannel>) {
        for record in records {
            self.registered_channels
                .insert(record.folded.clone(), record);
        }
        let _ = self.chanreg.set(store);
    }

    /// Whether a channel is registered.
    #[must_use]
    pub fn is_channel_registered(&self, folded: &str) -> bool {
        self.registered_channels.contains_key(folded)
    }

    /// The founder account of a registered channel, if any.
    #[must_use]
    pub fn channel_founder(&self, folded: &str) -> Option<String> {
        self.registered_channels
            .get(folded)
            .map(|r| r.founder.clone())
    }

    /// Register a channel to `founder`, capturing its current topic and modes.
    /// Returns `false` if it is already registered.
    pub fn register_channel(&self, folded: &str, founder: &str) -> bool {
        if self.registered_channels.contains_key(folded) {
            return false;
        }
        let record = self
            .find_channel(folded)
            .map(|ch| build_registration(folded, founder, &ch))
            .unwrap_or_else(|| RegisteredChannel {
                folded: folded.to_owned(),
                name: folded.to_owned(),
                founder: founder.to_owned(),
                topic_text: None,
                topic_setby: String::new(),
                topic_setat: 0,
                mode_flags: chanreg::MODE_NO_EXTERNAL | chanreg::MODE_TOPIC_LOCK,
                key: None,
                limit: None,
            });
        if let Some(store) = self.chanreg.get() {
            store.upsert(&record);
        }
        self.registered_channels.insert(folded.to_owned(), record);
        true
    }

    /// Drop a channel registration entirely.
    pub fn drop_channel_registration(&self, folded: &str) {
        if self.registered_channels.remove(folded).is_some() {
            if let Some(store) = self.chanreg.get() {
                store.delete(folded);
            }
        }
    }

    /// Refresh a registered channel's stored topic/modes from its live state
    /// (a no-op for unregistered channels). Call after a topic or mode change.
    pub fn persist_registered(&self, folded: &str) {
        if !self.registered_channels.contains_key(folded) {
            return;
        }
        let Some(channel) = self.find_channel(folded) else {
            return;
        };
        let founder = self
            .registered_channels
            .get(folded)
            .map_or_else(String::new, |r| r.founder.clone());
        let record = build_registration(folded, &founder, &channel);
        if let Some(store) = self.chanreg.get() {
            store.upsert(&record);
        }
        self.registered_channels.insert(folded.to_owned(), record);
    }

    /// Propagate a local user's channel join to all peers (S2S).
    pub fn propagate_sjoin(&self, client_id: u64, channel_display: &str, prefix: MemberPrefix) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Sjoin {
            channel: channel_display.to_owned(),
            uid: self.local_uid(client_id),
            op: prefix.op,
            voice: prefix.voice,
            ts: self.channel_ts(channel_display),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Propagate a local topic change to all peers (S2S).
    pub fn propagate_topic(
        &self,
        client_id: u64,
        channel_display: &str,
        set_by: &str,
        set_at: u64,
        text: &str,
    ) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Stopic {
            channel: channel_display.to_owned(),
            source: self.local_uid(client_id),
            set_by: set_by.to_owned(),
            set_at,
            text: text.to_owned(),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Propagate a local channel mode change to all peers (S2S). `args` must
    /// already be in wire form (UIDs for `o`/`v` targets).
    pub fn propagate_mode(
        &self,
        client_id: u64,
        channel_display: &str,
        flags: &str,
        args: Vec<String>,
    ) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Smode {
            channel: channel_display.to_owned(),
            source: self.local_uid(client_id),
            ts: self.channel_ts(channel_display),
            flags: flags.to_owned(),
            args,
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// A channel's creation timestamp (0 if we do not have the channel).
    #[must_use]
    pub fn channel_ts(&self, channel_display: &str) -> u64 {
        self.find_channel(&self.fold(channel_display))
            .map_or(0, |c| c.data.lock().created_at)
    }

    /// Propagate a local kick to all peers (S2S). `target_uid` is the kicked
    /// user's network UID (local or remote).
    pub fn propagate_kick(
        &self,
        kicker_id: u64,
        channel_display: &str,
        target_uid: &str,
        reason: &str,
    ) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Skick {
            channel: channel_display.to_owned(),
            source: self.local_uid(kicker_id),
            target: target_uid.to_owned(),
            reason: reason.to_owned(),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Propagate a local user's away-state change to all peers (S2S).
    pub fn propagate_away(&self, client_id: u64, reason: Option<&str>) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Saway {
            uid: self.local_uid(client_id),
            reason: reason.map(str::to_owned),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Propagate a local user's login-state change to all peers (S2S).
    pub fn propagate_account(&self, client_id: u64, account: Option<&str>) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Saccount {
            uid: self.local_uid(client_id),
            account: account.unwrap_or("*").to_owned(),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Propagate a local user's realname change to all peers (S2S).
    pub fn propagate_setname(&self, client_id: u64, realname: &str) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Ssetname {
            uid: self.local_uid(client_id),
            realname: realname.to_owned(),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Propagate a local user's umode change to all peers (S2S), so oper status
    /// and invisibility are visible network-wide.
    pub fn propagate_umodes(&self, client_id: u64, flags: &str) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Sumode {
            uid: self.local_uid(client_id),
            flags: flags.to_owned(),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Apply a remote user's umode change (`+o`, `-i`, …).
    pub fn remote_umode(&self, uid: &str, flags: &str) {
        let Some(folded) = self.remote_by_uid.get(uid).map(|f| f.clone()) else {
            return;
        };
        let Some(mut user) = self.remote_users.get_mut(&folded) else {
            return;
        };
        let mut adding = true;
        for c in flags.chars() {
            match c {
                '+' => adding = true,
                '-' => adding = false,
                'o' => user.oper = adding,
                'i' => user.invisible = adding,
                'B' => user.bot = adding,
                _ => {} // `+w` and friends are a local delivery choice
            }
        }
    }

    /// Deliver a `KNOCK` from another server to this server's channel operators
    /// (numeric 710), so knocking works when the ops live elsewhere.
    pub fn remote_knock(&self, channel_name: &str, mask: &str) {
        let Some(channel) = self.find_channel(&self.fold(channel_name)) else {
            return;
        };
        let display = channel.data.lock().name.clone();
        for (member, prefix) in channel.member_snapshot() {
            if !prefix.op {
                continue;
            }
            let nick = member.nick();
            member.send_line(
                Line::server(&self.info.name)
                    .code(crate::numeric::RPL_KNOCK)
                    .param(&nick)
                    .param(&display)
                    .param(mask)
                    .trailing("has asked for an invite"),
            );
        }
    }

    /// Propagate a local `KNOCK` to every peer that has a member of the channel
    /// (its operators may live on another server).
    pub fn propagate_knock(&self, source_uid: &str, channel_display: &str, mask: &str) {
        if self.links.is_empty() {
            return;
        }
        let Some(channel) = self.find_channel(&self.fold(channel_display)) else {
            return;
        };
        let sids: HashSet<String> = channel
            .data
            .lock()
            .remote_members
            .values()
            .map(|m| m.server_sid.clone())
            .collect();
        let peers: HashSet<String> = sids.iter().filter_map(|sid| self.route_for(sid)).collect();
        let bytes = crate::s2s::LinkMessage::Sknock {
            source: source_uid.to_owned(),
            channel: channel_display.to_owned(),
            mask: mask.to_owned(),
        }
        .to_line();
        for peer in peers {
            self.send_to_link(&peer, bytes.clone());
        }
    }

    /// Propagate a local user's displayed-host change to all peers (S2S).
    pub fn propagate_chghost(&self, client_id: u64, host: &str) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Schghost {
            uid: self.local_uid(client_id),
            host: host.to_owned(),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Propagate an operator broadcast (WALLOPS) to all peers (S2S).
    pub fn propagate_wallops(&self, source: &str, text: &str) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Swallops {
            source: source.to_owned(),
            text: text.to_owned(),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Propagate a local message redaction to all peers (S2S). Flooded like
    /// WALLOPS: every server holding replayable history for the target must
    /// delete the message.
    pub fn propagate_redact(&self, client_id: u64, target: &str, msgid: &str, reason: &str) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Sredact {
            source: self.local_uid(client_id),
            target: target.to_owned(),
            msgid: msgid.to_owned(),
            reason: reason.to_owned(),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Apply a message redaction arriving over a link: delete the message from
    /// local history and tell capable local clients (draft/message-redaction).
    pub fn remote_redact(&self, source: &str, target: &str, msgid: &str, reason: &str) {
        let mask = self.remote_source_mask(source);
        let build = |display: &str| {
            let mut line = Line::server(&mask)
                .command("REDACT")
                .param(display)
                .param(msgid);
            if !reason.is_empty() {
                line = line.trailing(reason);
            }
            crate::deliver::Event::new(line.body()).with_time(format_server_time(now_millis()))
        };
        if crate::casemap::is_valid_channel(target) {
            let folded = self.fold(target);
            self.history.redact(&folded, msgid);
            if let Some(channel) = self.find_channel(&folded) {
                let display = channel.data.lock().name.clone();
                crate::deliver::to_channel_capped(
                    &channel,
                    &build(&display),
                    crate::cap::Cap::MessageRedaction,
                    None,
                );
            }
        } else {
            // A DM redaction: the pair key is symmetric between the author and
            // the local target.
            let source_nick = mask.split('!').next().unwrap_or(&mask);
            let pair = crate::history::pair_key(&self.fold(source_nick), &self.fold(target));
            self.history.redact(&pair, msgid);
            if let Some(dest) = self.find_client(&self.fold(target)) {
                if dest.caps().has(crate::cap::Cap::MessageRedaction) {
                    crate::deliver::to_client(&dest, &build(target));
                }
            }
        }
    }

    /// Propagate a network-wide ban (G-Line) add/remove to all peers (S2S).
    pub fn propagate_gline(&self, add: bool, mask: &str, set_by: &str, reason: &str) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Sban {
            add,
            mask: mask.to_owned(),
            set_by: set_by.to_owned(),
            reason: reason.to_owned(),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Apply a remote user's realname change and announce it to local
    /// co-members with `setname`.
    pub fn remote_setname(&self, uid: &str, realname: &str) {
        let Some(folded) = self.remote_by_uid.get(uid).map(|f| f.clone()) else {
            return;
        };
        let user = {
            let Some(mut user) = self.remote_users.get_mut(&folded) else {
                return;
            };
            user.realname = realname.to_owned();
            user.clone()
        };
        let line = Line::user(&user.nick, &user.user, &user.host)
            .command("SETNAME")
            .trailing(realname)
            .build();
        self.announce_to_remote_comembers(uid, &line, crate::cap::Cap::SetName);
    }

    /// Apply a remote user's displayed-host change and announce it to local
    /// co-members with `chghost` (prefixed with the *old* host, per the spec).
    pub fn remote_chghost(&self, uid: &str, host: &str) {
        let Some(folded) = self.remote_by_uid.get(uid).map(|f| f.clone()) else {
            return;
        };
        let (user, old_host) = {
            let Some(mut user) = self.remote_users.get_mut(&folded) else {
                return;
            };
            let old_host = std::mem::replace(&mut user.host, host.to_owned());
            (user.clone(), old_host)
        };
        let line = Line::user(&user.nick, &user.user, &old_host)
            .command("CHGHOST")
            .param(&user.user)
            .param(host)
            .build();
        self.announce_to_remote_comembers(uid, &line, crate::cap::Cap::ChgHost);
    }

    /// Apply an operator broadcast arriving over a link: fan it out to local
    /// umode `+w` users as `:<source> WALLOPS :<text>`.
    pub fn remote_wallops(&self, source: &str, text: &str) {
        let line = Line::server(source)
            .command("WALLOPS")
            .trailing(text)
            .build();
        self.wallops(&line);
    }

    /// Apply a cross-server invitation targeting one of our local users:
    /// record the pending invite on the channel, deliver the INVITE line to
    /// the target, and tell `invite-notify` members.
    pub fn remote_invite(&self, source_uid: &str, target_uid: &str, channel_name: &str) {
        let folded = self.fold(channel_name);
        let Some(channel) = self.find_channel(&folded) else {
            return;
        };
        let Some(target) = target_uid
            .strip_prefix(&self.info.sid)
            .and_then(|rest| rest.parse::<u64>().ok())
            .and_then(|id| self.by_id.get(&id).map(|c| c.clone()))
        else {
            return;
        };
        let Some(source) = self.remote_user_by_uid(source_uid) else {
            return;
        };
        let (target_nick, display) = {
            let name = channel.data.lock().name.clone();
            (target.nick(), name)
        };
        {
            // Same bound as local INVITE: the pending set must not grow without
            // limit under an invite flood.
            const MAX_PENDING_INVITES: usize = 256;
            let mut data = channel.data.lock();
            if data.invited.len() >= MAX_PENDING_INVITES {
                if let Some(victim) = data.invited.iter().next().cloned() {
                    data.invited.remove(&victim);
                }
            }
            data.invited.insert(self.fold(&target_nick));
        }
        let body = Line::user(&source.nick, &source.user, &source.host)
            .command("INVITE")
            .param(&target_nick)
            .param(&display)
            .body();
        let event = crate::deliver::Event::new(body)
            .with_time(format_server_time(now_millis()))
            .with_account(source.account.clone());
        crate::deliver::to_client(&target, &event);
        crate::deliver::to_channel_capped(&channel, &event, crate::cap::Cap::InviteNotify, None);
    }

    /// Record a pending invitation learned from a peer's burst (`SINVITE` with
    /// a `*` source): no notification, just the `+i` bypass, so an invite issued
    /// before the link came up is not lost.
    pub fn remote_invite_pending(&self, folded_nick: &str, channel_name: &str) {
        let Some(channel) = self.find_channel(&self.fold(channel_name)) else {
            return;
        };
        const MAX_PENDING_INVITES: usize = 256;
        let mut data = channel.data.lock();
        if data.invited.len() >= MAX_PENDING_INVITES {
            return;
        }
        data.invited.insert(folded_nick.to_owned());
    }

    /// Apply a network-wide ban (G-Line) arriving over a link.
    pub fn remote_gline(&self, add: bool, mask: &str, set_by: &str, reason: &str) {
        if add {
            self.add_kline(mask.to_owned(), reason.to_owned(), set_by.to_owned());
            self.kill_matching(mask, &format!("G-Lined: {reason}"));
        } else {
            self.remove_kline(mask);
        }
    }

    /// Propagate a local user's channel part to all peers (S2S).
    pub fn propagate_spart(&self, client_id: u64, channel_display: &str, reason: &str) {
        if self.links.is_empty() {
            return;
        }
        let msg = crate::s2s::LinkMessage::Spart {
            channel: channel_display.to_owned(),
            uid: self.local_uid(client_id),
            reason: reason.to_owned(),
        };
        self.propagate_to_links(&msg.to_line());
    }

    /// Find a remote user by UID (linear scan; the remote set is small).
    pub(crate) fn remote_user_by_uid(&self, uid: &str) -> Option<RemoteUser> {
        let folded = self.remote_by_uid.get(uid)?;
        self.remote_users.get(folded.value()).map(|r| r.clone())
    }

    /// A remote user joined `channel_name` (with the given channel prefix): add
    /// them and tell local members. Re-joins refresh the stored prefix (burst).
    ///
    /// `peer_ts` is the sender's channel-creation timestamp. When both sides
    /// independently created the channel (the classic netjoin conflict), the
    /// **older channel wins** (TS6 rules): the younger side wipes its modes and
    /// every member's status, because for the winner that channel never
    /// existed. A `0` timestamp means "unknown" and never resolves.
    pub fn remote_join(
        self: &Arc<Self>,
        channel_name: &str,
        uid: &str,
        prefix: MemberPrefix,
        peer_ts: u64,
    ) {
        let Some(user) = self.remote_user_by_uid(uid) else {
            return;
        };
        let folded = self.fold(channel_name);
        // The same guard local JOINs use: while it is alive the channel cannot
        // be reaped out from under this insertion.
        let (channel, created, _guard) = self.begin_join(&folded, channel_name);
        if !created {
            self.reconcile_channel_ts(&channel, peer_ts);
        } else if peer_ts > 0 {
            channel.data.lock().created_at = peer_ts;
        }
        // If our (older) channel won, the joining member arrives with no status.
        let prefix = if self.channel_ts_wins_over(&channel, peer_ts) {
            MemberPrefix::default()
        } else {
            prefix
        };
        let (display, already) = {
            let mut d = channel.data.lock();
            let already = d
                .remote_members
                .insert(
                    uid.to_owned(),
                    RemoteMember {
                        nick: user.nick.clone(),
                        user: user.user.clone(),
                        host: user.host.clone(),
                        server_sid: user.server_sid.clone(),
                        prefix,
                    },
                )
                .is_some();
            (d.name.clone(), already)
        };
        self.remote_channels
            .entry(uid.to_owned())
            .or_default()
            .insert(folded);
        if already {
            return; // a burst re-join: membership refreshed, nothing to announce
        }
        // Rendered per recipient like a local JOIN, so `extended-join` clients
        // get the account/realname suffix and `server-time` clients a `@time`.
        let body = Line::user(&user.nick, &user.user, &user.host)
            .command("JOIN")
            .param(&display)
            .body();
        let account_token = user.account.clone().unwrap_or_else(|| "*".to_owned());
        let join = crate::deliver::Event::new(body)
            .with_time(format_server_time(now_millis()))
            .with_account(user.account.clone())
            .with_suffix(
                crate::cap::Cap::ExtendedJoin,
                format!(" {account_token} :{}", user.realname),
            );
        crate::deliver::to_channel(&channel, &join, None); // local members only
        self.record_channel_event(
            &self.fold(&display),
            &display,
            &user.hostmask(),
            crate::history::MessageKind::Join,
            String::new(),
        );
    }

    /// Whether our view of the channel is the authoritative (older) one, so a
    /// peer's member status and modes must be discarded.
    fn channel_ts_wins_over(&self, channel: &Arc<ChannelEntry>, peer_ts: u64) -> bool {
        if peer_ts == 0 {
            return false; // unknown timestamp: no resolution
        }
        channel.data.lock().created_at < peer_ts
    }

    /// Resolve a channel-timestamp conflict with a peer. If the peer's channel
    /// is older, ours never legitimately existed: adopt their timestamp, wipe
    /// our modes and every member's status, and tell local members what changed.
    fn reconcile_channel_ts(&self, channel: &Arc<ChannelEntry>, peer_ts: u64) {
        if peer_ts == 0 {
            return;
        }
        let (display, flags, args) = {
            let mut d = channel.data.lock();
            if peer_ts >= d.created_at {
                return; // we are the older (or equal) side: nothing to give up
            }
            d.created_at = peer_ts;

            // Build the deltas that take our view down to a blank channel, so
            // local clients see exactly what they lost.
            let mut accum = ModeAccum::default();
            let mut args: Vec<String> = Vec::new();
            for bm in BOOL_MODES {
                if (bm.get)(&d.modes) {
                    (bm.set)(&mut d.modes, false);
                    accum.push(false, bm.letter);
                }
            }
            if d.modes.key.take().is_some() {
                accum.push(false, 'k');
                args.push("*".to_owned());
            }
            if d.modes.limit.take().is_some() {
                accum.push(false, 'l');
            }
            for member in d.members.values_mut() {
                let prefix = std::mem::take(&mut member.prefix);
                if prefix.op {
                    accum.push(false, 'o');
                    args.push(member.entry.nick());
                }
                if prefix.voice {
                    accum.push(false, 'v');
                    args.push(member.entry.nick());
                }
            }
            for member in d.remote_members.values_mut() {
                let prefix = std::mem::take(&mut member.prefix);
                if prefix.op {
                    accum.push(false, 'o');
                    args.push(member.nick.clone());
                }
                if prefix.voice {
                    accum.push(false, 'v');
                    args.push(member.nick.clone());
                }
            }
            (d.name.clone(), accum.flags, args)
        };
        if flags.is_empty() {
            return;
        }
        let channel_name: &str = &display;
        tracing::info!(
            channel = channel_name,
            peer_ts,
            "channel timestamp conflict: older peer channel wins, dropping local modes and status"
        );
        let mut line = Line::server(&self.info.name)
            .command("MODE")
            .param(&display)
            .param(&flags);
        for arg in &args {
            line = line.param(arg);
        }
        channel.broadcast(&line.build(), None);
    }

    /// A remote user left `channel_name`.
    pub fn remote_part(&self, channel_name: &str, uid: &str, reason: &str) {
        let folded = self.fold(channel_name);
        let Some(channel) = self.find_channel(&folded) else {
            return;
        };
        let (removed, display) = {
            let mut d = channel.data.lock();
            (d.remote_members.remove(uid).is_some(), d.name.clone())
        };
        if removed {
            if let Some(mut set) = self.remote_channels.get_mut(uid) {
                set.remove(&folded);
            }
            if let Some(user) = self.remote_user_by_uid(uid) {
                let part = Line::user(&user.nick, &user.user, &user.host)
                    .command("PART")
                    .param(&display)
                    .trailing(reason)
                    .build();
                channel.broadcast(&part, None);
                self.record_channel_event(
                    &folded,
                    &display,
                    &user.hostmask(),
                    crate::history::MessageKind::Part,
                    reason.to_owned(),
                );
            }
            self.reap_channel(&folded);
        }
    }

    /// The local client id embedded in `uid`, if it is in our UID namespace.
    pub(crate) fn local_id_of_uid(&self, uid: &str) -> Option<u64> {
        uid.strip_prefix(&self.info.sid)
            .and_then(|rest| rest.parse::<u64>().ok())
    }

    /// The current nickname behind a network UID — a local client's or a
    /// remote user's (used by the TS6 bridge to address message targets).
    #[must_use]
    pub fn nick_of_uid(&self, uid: &str) -> Option<String> {
        if let Some(id) = self.local_id_of_uid(uid) {
            return self.by_id.get(&id).map(|e| e.nick());
        }
        self.remote_user_by_uid(uid).map(|u| u.nick)
    }

    /// The display source for an S2S event: the acting user's hostmask, our
    /// server name for `*` (server-originated, e.g. burst), or the raw uid as a
    /// last resort.
    pub(crate) fn remote_source_mask(&self, source: &str) -> String {
        if source == "*" {
            return self.info.name.clone();
        }
        if let Some(id) = self.local_id_of_uid(source) {
            if let Some(entry) = self.by_id.get(&id) {
                return entry.hostmask();
            }
        }
        match self.remote_user_by_uid(source) {
            Some(user) => user.hostmask(),
            None => source.to_owned(),
        }
    }

    /// The display nick for an S2S event source (see [`Self::remote_source_mask`]).
    fn remote_source_nick(&self, source: &str) -> String {
        let mask = self.remote_source_mask(source);
        mask.split('!').next().unwrap_or(&mask).to_owned()
    }

    /// Apply a topic change relayed over S2S and announce it to local members.
    pub fn remote_topic(
        &self,
        channel_name: &str,
        source: &str,
        set_by: &str,
        set_at: u64,
        text: &str,
    ) {
        let folded = self.fold(channel_name);
        let Some(channel) = self.find_channel(&folded) else {
            return;
        };
        let display = {
            let mut d = channel.data.lock();
            d.topic = if text.is_empty() {
                None
            } else {
                Some(Topic {
                    text: text.to_owned(),
                    set_by: set_by.to_owned(),
                    set_at,
                })
            };
            d.name.clone()
        };
        let topic = Line::server(&self.remote_source_mask(source))
            .command("TOPIC")
            .param(&display)
            .trailing(text)
            .build();
        channel.broadcast(&topic, None);
        // Topic bursts (`*` source) restate existing state; only user-driven
        // changes become history events.
        if source != "*" {
            self.record_channel_event(
                &folded,
                &display,
                &self.remote_source_mask(source),
                crate::history::MessageKind::Topic,
                text.to_owned(),
            );
        }
        self.persist_registered(&folded);
    }

    /// Apply a channel mode change relayed over S2S and announce it to local
    /// members. `o`/`v` arguments are network UIDs; they are resolved to local
    /// or remote members here (and rendered as nicks for the announcement).
    pub fn remote_mode(
        &self,
        channel_name: &str,
        source: &str,
        peer_ts: u64,
        flags: &str,
        args: &[String],
    ) {
        let folded = self.fold(channel_name);
        let Some(channel) = self.find_channel(&folded) else {
            return;
        };
        // TS resolution: modes from a *younger* view of the channel are stale —
        // that side lost the netjoin and its modes never applied. (An older
        // view wins and takes the channel's timestamp with it.)
        if peer_ts > 0 {
            if self.channel_ts_wins_over(&channel, peer_ts) {
                return;
            }
            self.reconcile_channel_ts(&channel, peer_ts);
        }
        let setter = self.remote_source_nick(source);

        // Pre-resolve argument-consuming modes OUTSIDE the channel lock (the
        // locking rules forbid touching another client's data under it).
        enum Step {
            Bool(char, bool),
            Prefix(char, bool, PrefixTarget, String),
            Key(bool, Option<String>),
            Limit(bool, Option<usize>),
            List(char, bool, String),
        }
        enum PrefixTarget {
            Local(u64),
            Remote(String),
        }
        let mut steps: Vec<Step> = Vec::new();
        let mut rest = args.iter();
        let mut adding = true;
        for c in flags.chars() {
            match c {
                '+' => adding = true,
                '-' => adding = false,
                'o' | 'v' => {
                    let Some(uid) = rest.next() else { continue };
                    if let Some(id) = self.local_id_of_uid(uid) {
                        if let Some(entry) = self.by_id.get(&id) {
                            steps.push(Step::Prefix(
                                c,
                                adding,
                                PrefixTarget::Local(id),
                                entry.nick(),
                            ));
                        }
                    } else if let Some(user) = self.remote_user_by_uid(uid) {
                        steps.push(Step::Prefix(
                            c,
                            adding,
                            PrefixTarget::Remote(uid.clone()),
                            user.nick,
                        ));
                    }
                }
                'k' => {
                    let key = if adding {
                        match rest.next() {
                            Some(key) => Some(key.clone()),
                            None => continue,
                        }
                    } else {
                        None
                    };
                    steps.push(Step::Key(adding, key));
                }
                'l' => {
                    let limit = if adding {
                        match rest.next().and_then(|v| v.parse::<usize>().ok()) {
                            Some(limit) => Some(limit),
                            None => continue,
                        }
                    } else {
                        None
                    };
                    steps.push(Step::Limit(adding, limit));
                }
                'b' | 'e' | 'I' => {
                    let Some(mask) = rest.next() else { continue };
                    steps.push(Step::List(c, adding, mask.clone()));
                }
                other => {
                    if BOOL_MODES.iter().any(|m| m.letter == other) {
                        steps.push(Step::Bool(other, adding));
                    }
                }
            }
        }

        let mut accum = ModeAccum::default();
        let mut applied_args: Vec<String> = Vec::new();
        let display = {
            let mut d = channel.data.lock();
            for step in steps {
                match step {
                    Step::Bool(c, adding) => {
                        if let Some(bm) = BOOL_MODES.iter().find(|m| m.letter == c) {
                            (bm.set)(&mut d.modes, adding);
                            accum.push(adding, c);
                        }
                    }
                    Step::Prefix(c, adding, target, nick) => {
                        let prefix = match target {
                            PrefixTarget::Local(id) => {
                                d.members.get_mut(&id).map(|m| &mut m.prefix)
                            }
                            PrefixTarget::Remote(uid) => {
                                d.remote_members.get_mut(&uid).map(|m| &mut m.prefix)
                            }
                        };
                        if let Some(prefix) = prefix {
                            if c == 'o' {
                                prefix.op = adding;
                            } else {
                                prefix.voice = adding;
                            }
                            accum.push(adding, c);
                            applied_args.push(nick);
                        }
                    }
                    Step::Key(adding, key) => {
                        d.modes.key = key.clone();
                        accum.push(adding, 'k');
                        applied_args.push(key.unwrap_or_else(|| "*".to_owned()));
                    }
                    Step::Limit(adding, limit) => {
                        d.modes.limit = limit;
                        accum.push(adding, 'l');
                        if let Some(limit) = limit {
                            applied_args.push(limit.to_string());
                        }
                    }
                    Step::List(c, adding, mask) => {
                        let list = match c {
                            'b' => &mut d.bans,
                            'e' => &mut d.exceptions,
                            _ => &mut d.invex,
                        };
                        apply_list_mode(
                            list,
                            adding,
                            mask,
                            &setter,
                            &mut accum,
                            &mut applied_args,
                            c,
                        );
                    }
                }
            }
            d.name.clone()
        };
        if accum.is_empty() {
            return;
        }
        let mut line = Line::server(&self.remote_source_mask(source))
            .command("MODE")
            .param(&display)
            .param(&accum.flags);
        for arg in &applied_args {
            line = line.param(arg);
        }
        channel.broadcast(&line.build(), None);
        // Mode bursts (`*` source) restate existing state; only user-driven
        // changes become history events.
        if source != "*" {
            let mode_text = if applied_args.is_empty() {
                accum.flags.clone()
            } else {
                format!("{} {}", accum.flags, applied_args.join(" "))
            };
            self.record_channel_event(
                &folded,
                &display,
                &self.remote_source_mask(source),
                crate::history::MessageKind::Mode,
                mode_text,
            );
        }
        self.persist_registered(&folded);
    }

    /// Apply a kick relayed over S2S: remove the target (local or remote) from
    /// the channel and announce the KICK to local members (including a local
    /// target, which sees its own kick).
    pub fn remote_kick(&self, channel_name: &str, source: &str, target_uid: &str, reason: &str) {
        let folded = self.fold(channel_name);
        let Some(channel) = self.find_channel(&folded) else {
            return;
        };
        let mask = self.remote_source_mask(source);
        if let Some(id) = self.local_id_of_uid(target_uid) {
            let Some(target) = self.by_id.get(&id).map(|e| e.clone()) else {
                return;
            };
            let (display, is_member) = {
                let d = channel.data.lock();
                (d.name.clone(), d.has_member(id))
            };
            if !is_member {
                return;
            }
            let kick = Line::server(&mask)
                .command("KICK")
                .param(&display)
                .param(&target.nick())
                .trailing(reason)
                .build();
            channel.broadcast(&kick, None); // the target is still a member: it sees the kick
            self.record_channel_event(
                &folded,
                &display,
                &mask,
                crate::history::MessageKind::Kick,
                format!("{} {reason}", target.nick()),
            );
            channel.data.lock().members.remove(&id);
            target.data.lock().channels.remove(&folded);
        } else {
            let (removed, display) = {
                let mut d = channel.data.lock();
                (d.remote_members.remove(target_uid), d.name.clone())
            };
            let Some(member) = removed else {
                return;
            };
            if let Some(mut set) = self.remote_channels.get_mut(target_uid) {
                set.remove(&folded);
            }
            let kick = Line::server(&mask)
                .command("KICK")
                .param(&display)
                .param(&member.nick)
                .trailing(reason)
                .build();
            channel.broadcast(&kick, None);
            self.record_channel_event(
                &folded,
                &display,
                &mask,
                crate::history::MessageKind::Kick,
                format!("{} {reason}", member.nick),
            );
        }
        self.reap_channel(&folded);
    }

    /// Apply a remote user's away-state change and announce it to local
    /// co-members with `away-notify`.
    pub fn remote_away(&self, uid: &str, reason: Option<&str>) {
        let Some(folded) = self.remote_by_uid.get(uid).map(|f| f.clone()) else {
            return;
        };
        let user = {
            let Some(mut user) = self.remote_users.get_mut(&folded) else {
                return;
            };
            user.away = reason.map(str::to_owned);
            user.clone()
        };
        let mut line = Line::user(&user.nick, &user.user, &user.host).command("AWAY");
        if let Some(reason) = reason {
            line = line.trailing(reason);
        }
        self.announce_to_remote_comembers(uid, &line.build(), crate::cap::Cap::AwayNotify);
    }

    /// Apply a remote user's login-state change and announce it to local
    /// co-members with `account-notify`.
    pub fn remote_account(&self, uid: &str, account: Option<&str>) {
        let Some(folded) = self.remote_by_uid.get(uid).map(|f| f.clone()) else {
            return;
        };
        let user = {
            let Some(mut user) = self.remote_users.get_mut(&folded) else {
                return;
            };
            user.account = account.map(str::to_owned);
            user.clone()
        };
        let line = Line::user(&user.nick, &user.user, &user.host)
            .command("ACCOUNT")
            .param(account.unwrap_or("*"))
            .build();
        self.announce_to_remote_comembers(uid, &line, crate::cap::Cap::AccountNotify);
    }

    /// Send `bytes` to every local client that shares a channel with the remote
    /// user `uid` and has negotiated `cap` (deduped). Clients monitoring the
    /// nick with `extended-monitor` (plus `cap`) hear about it too, even
    /// without a shared channel.
    fn announce_to_remote_comembers(&self, uid: &str, bytes: &Bytes, cap: crate::cap::Cap) {
        let mut notified: HashSet<u64> = HashSet::new();
        for channel in self.remote_membership_channels(uid) {
            for (entry, _) in channel.member_snapshot() {
                if entry.caps().has(cap) && notified.insert(entry.id) {
                    entry.send(bytes.clone());
                }
            }
        }
        let Some(folded) = self.remote_by_uid.get(uid).map(|f| f.clone()) else {
            return;
        };
        let Some(watchers) = self.monitors.get(&folded).map(|s| s.clone()) else {
            return;
        };
        for id in watchers {
            if notified.contains(&id) {
                continue;
            }
            if let Some(watcher) = self.by_id.get(&id) {
                let caps = watcher.caps();
                if caps.has(crate::cap::Cap::ExtendedMonitor) && caps.has(cap) {
                    watcher.send(bytes.clone());
                }
            }
        }
    }

    /// Deliver a channel message relayed from `origin_sid` to local members and
    /// forward to any other peers with members (loop-free for a link tree).
    #[allow(clippy::too_many_arguments)]
    pub fn deliver_channel_message(
        &self,
        origin_sid: &str,
        source: &str,
        channel_name: &str,
        notice: bool,
        msgid: Option<String>,
        time_ms: Option<u64>,
        tags: Option<String>,
        text: &str,
    ) {
        // A relayed STATUSMSG target keeps its `@`/`+` sigil on the wire.
        let (status, base_name) = match channel_name.split_at_checked(1) {
            Some(("@", rest)) => (Some(true), rest),
            Some(("+", rest)) => (Some(false), rest),
            _ => (None, channel_name),
        };
        let folded = self.fold(base_name);
        let Some(channel) = self.find_channel(&folded) else {
            return;
        };
        let source_nick = source.split('!').next().unwrap_or(source);
        // Relayed messages pass the same plugin policy as local ones; a block
        // also stops the onward relay so the whole (sub)tree stays consistent.
        if let Some(host) = self.plugins() {
            if host.on_channel_message(source_nick, base_name, text)
                == crate::plugin::Verdict::Block
            {
                return;
            }
        }
        let display = channel.data.lock().name.clone();
        let account = self
            .remote_users
            .get(&self.fold(source_nick))
            .and_then(|u| u.account.clone());
        // Keep the origin's msgid/time when the wire carried them, so the
        // message is identical on every server (cross-server msgid refs).
        let msgid = msgid.unwrap_or_else(|| self.history.next_msgid());
        let now_ms = time_ms.unwrap_or_else(now_millis);
        // Record for chathistory so replay works for S2S traffic too. STATUSMSG
        // stays out of the shared history (it would replay to non-holders).
        if status.is_none() {
            self.history.record(
                &folded,
                Arc::new(crate::history::StoredMessage {
                    msgid: msgid.clone(),
                    time_ms: now_ms,
                    source: source.to_owned(),
                    account: account.clone(),
                    kind: if notice {
                        crate::history::MessageKind::Notice
                    } else {
                        crate::history::MessageKind::PrivMsg
                    },
                    target: display.clone(),
                    text: text.to_owned(),
                }),
            );
        }
        let command = if notice { "NOTICE" } else { "PRIVMSG" };
        let wire_target = match status {
            Some(true) => format!("@{display}"),
            Some(false) => format!("+{display}"),
            None => display.clone(),
        };
        // Route through Event so recipients get the `@time`/`@msgid`/`@account`
        // tags they negotiated, matching locally-originated channel messages.
        let body = format!(":{source} {command} {wire_target} :{text}");
        let mut event = crate::deliver::Event::new(body)
            .with_time(format_server_time(now_ms))
            .with_account(account)
            .with_msgid(msgid.clone());
        if let Some(tags) = tags.clone() {
            event = event.with_client_tags(tags);
        }
        match status {
            Some(op_only) => crate::deliver::to_channel_status(&channel, &event, op_only, None),
            None => crate::deliver::to_channel(&channel, &event, None),
        }
        self.relay_channel_message(
            source,
            &wire_target,
            notice,
            Some(msgid),
            Some(now_ms),
            tags,
            text,
            Some(origin_sid),
        );
    }

    /// Relay a channel message to each peer that has a member (except `origin`).
    #[allow(clippy::too_many_arguments)]
    pub fn relay_channel_message(
        &self,
        source: &str,
        channel_name: &str,
        notice: bool,
        msgid: Option<String>,
        time_ms: Option<u64>,
        tags: Option<String>,
        text: &str,
        origin_sid: Option<&str>,
    ) {
        // Common single-node case: no peers, so nothing to relay. Bail before
        // taking the extra channel lock and scanning remote members.
        if self.links.is_empty() {
            return;
        }
        // A STATUSMSG target (`@#chan`/`+#chan`) travels with its sigil; the
        // membership lookup uses the bare channel name.
        let folded = self.fold(channel_name.trim_start_matches(['@', '+']));
        let Some(channel) = self.find_channel(&folded) else {
            return;
        };
        let sids: HashSet<String> = channel
            .data
            .lock()
            .remote_members
            .values()
            .map(|m| m.server_sid.clone())
            .collect();
        if sids.is_empty() {
            return;
        }
        // Resolve each member's server to the directly-connected peer that
        // routes it (multi-hop), deduping so a peer fronting several servers
        // gets exactly one copy.
        let peers: HashSet<String> = sids.iter().filter_map(|sid| self.route_for(sid)).collect();
        let bytes = crate::s2s::LinkMessage::ChanMessage {
            source: source.to_owned(),
            channel: channel_name.to_owned(),
            notice,
            msgid,
            time_ms,
            tags,
            text: text.to_owned(),
        }
        .to_line();
        for peer in peers {
            if Some(peer.as_str()) == origin_sid {
                continue;
            }
            self.send_to_link(&peer, bytes.clone());
        }
    }

    /// Full teardown for a departing client: remove it from every channel it is
    /// in, broadcast a single `QUIT` to everyone who shared a channel with it,
    /// and release its nickname.
    pub fn disconnect(&self, entry: &Arc<ClientEntry>, reason: &str) {
        let (nick, user, host, account, channels, registered) = {
            let d = entry.data.lock();
            (
                d.nick.clone(),
                d.user.clone(),
                d.host.clone(),
                d.account.clone(),
                d.channels.clone(),
                d.registered,
            )
        };

        if registered {
            let realname = entry.data.lock().realname.clone();
            self.record_whowas(&nick, &user, &host, &realname);
            // A single QUIT to everyone who shared a channel (deduped), rendered
            // per recipient so `server-time`/`account-tag` recipients get tags.
            let body = Line::user(&nick, &user, &host)
                .command("QUIT")
                .trailing(reason)
                .body();
            let quit = crate::deliver::Event::new(body)
                .with_time(format_server_time(now_millis()))
                .with_account(account);
            let mut notified: HashSet<u64> = HashSet::new();
            notified.insert(entry.id);
            for folded in &channels {
                if let Some(channel) = self.find_channel(folded) {
                    let display = {
                        let mut data = channel.data.lock();
                        data.members.remove(&entry.id);
                        for member in data.members.values() {
                            if notified.insert(member.entry.id) {
                                member.entry.send(quit.render_for(member.entry.caps()));
                            }
                        }
                        data.name.clone()
                    };
                    // draft/event-playback: the quit appears in each shared
                    // channel's history.
                    self.record_channel_event(
                        folded,
                        &display,
                        &format!("{nick}!{user}@{host}"),
                        crate::history::MessageKind::Quit,
                        reason.to_owned(),
                    );
                }
                self.reap_channel(folded);
            }
        }

        // Drop the id index entry (ids are monotonic and never reused).
        self.by_id.remove(&entry.id);

        // MONITOR: tell watchers this nick went offline, and drop this client's
        // own watches from the reverse index.
        if registered && !nick.is_empty() && nick != "*" {
            self.monitor_offline(&nick);
        }
        let watched: Vec<String> = {
            let d = entry.data.lock();
            d.monitor.iter().cloned().collect()
        };
        for folded in watched {
            self.monitor_unwatch(&folded, entry.id);
        }

        if !nick.is_empty() && nick != "*" {
            let folded = self.fold(&nick);
            // Only release the nick if we still own it (guard against a race
            // where another client already reclaimed it).
            if self.clients.get(&folded).is_some_and(|r| r.id == entry.id) {
                self.release_nick(&folded);
            }
        }
    }
}

/// A connected client: its outbound mailbox plus mutable identity/state.
#[derive(Debug)]
pub struct ClientEntry {
    /// Unique, stable connection id.
    pub id: u64,
    mailbox: Mailbox,
    /// Enabled IRCv3 capabilities, read lock-free on the broadcast hot path.
    caps: AtomicU32,
    /// Set when a send is dropped because the SendQ was full.
    overflow: AtomicBool,
    /// Notified when the connection must be torn down (SendQ overflow, KILL,
    /// K-Line). The reason is stored in `kill_reason`.
    pub kill: Notify,
    /// Why the connection is being killed (first writer wins).
    kill_reason: Mutex<Option<String>>,
    /// Mutable client state; lock briefly, never across an `.await`.
    pub data: Mutex<ClientData>,
}

impl ClientEntry {
    /// Create a client entry and its paired mailbox receiver, with a SendQ of
    /// `sendq` queued lines.
    pub fn new(id: u64, host: String, sendq: usize) -> (Arc<Self>, MailboxRx) {
        let (tx, rx) = mpsc::channel(sendq.max(1));
        let entry = Arc::new(Self {
            id,
            mailbox: tx,
            caps: AtomicU32::new(0),
            overflow: AtomicBool::new(false),
            kill: Notify::new(),
            kill_reason: Mutex::new(None),
            data: Mutex::new(ClientData::new(host)),
        });
        (entry, rx)
    }

    /// Record a teardown reason (first one wins) and wake the reader task.
    fn signal_kill(&self, reason: &str) {
        let mut slot = self.kill_reason.lock();
        if slot.is_none() {
            *slot = Some(reason.to_owned());
        }
        drop(slot);
        self.kill.notify_one();
    }

    /// Force this connection to close with `reason` (used by KILL / K-Line).
    /// Any bytes already queued are flushed before the socket closes.
    pub fn request_kill(&self, reason: &str) {
        self.signal_kill(reason);
    }

    /// Take the recorded teardown reason, if any.
    #[must_use]
    pub fn take_kill_reason(&self) -> Option<String> {
        self.kill_reason.lock().take()
    }

    /// The client's currently-enabled capabilities (lock-free).
    #[must_use]
    pub fn caps(&self) -> CapSet {
        CapSet::from_bits(self.caps.load(Ordering::Relaxed))
    }

    /// Replace the client's enabled capabilities (lock-free).
    pub fn set_caps(&self, caps: CapSet) {
        self.caps.store(caps.bits(), Ordering::Relaxed);
    }

    /// Queue bytes for delivery. If the SendQ is full the client is too slow:
    /// mark the overflow and signal teardown (the classic SendQ guard, §4.1).
    pub fn send(&self, bytes: Bytes) {
        match self.mailbox.try_send(Outbound::Line(bytes)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.overflow.store(true, Ordering::Relaxed);
                self.signal_kill("SendQ exceeded");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    /// Queue a built line for delivery.
    pub fn send_line(&self, line: Line) {
        self.send(line.build());
    }

    /// Queue final bytes and request the connection be closed afterwards
    /// (best-effort; dropped if the SendQ is already full).
    pub fn close(&self, bytes: Bytes) {
        let _ = self.mailbox.try_send(Outbound::Close(bytes));
    }

    /// Whether a send has been dropped due to SendQ overflow.
    #[must_use]
    pub fn overflowed(&self) -> bool {
        self.overflow.load(Ordering::Relaxed)
    }

    /// Current display nickname.
    #[must_use]
    pub fn nick(&self) -> String {
        self.data.lock().nick.clone()
    }

    /// `nick!user@host` hostmask (using the displayed, possibly cloaked host).
    #[must_use]
    pub fn hostmask(&self) -> String {
        let d = self.data.lock();
        format!("{}!{}@{}", d.nick, d.user, d.host)
    }

    /// `nick!user@ip` using the real IP — what K-Lines match against.
    #[must_use]
    pub fn real_hostmask(&self) -> String {
        let d = self.data.lock();
        format!("{}!{}@{}", d.nick, d.user, d.real_ip)
    }

    /// Whether this client has silenced `source_mask` (`SILENCE`), so a private
    /// message from it must not be delivered.
    #[must_use]
    pub fn silences(&self, source_mask: &str) -> bool {
        let d = self.data.lock();
        d.silence
            .iter()
            .any(|mask| crate::mask::matches(mask, source_mask))
    }
}

/// Mutable per-client identity and membership.
#[derive(Debug)]
pub struct ClientData {
    /// Display nickname (`*` until the first accepted `NICK`).
    pub nick: String,
    /// Username / ident (without the leading `~`, which is added on display).
    pub user: String,
    /// Displayed hostname (the peer IP, or a cloak once applied).
    pub host: String,
    /// The real source IP (never cloaked), for D-Lines and cloaking.
    pub real_ip: String,
    /// Real name / GECOS.
    pub realname: String,
    /// Whether registration has completed.
    pub registered: bool,
    /// Folded names of channels this client is in.
    pub channels: HashSet<String>,
    /// Away message, if the client is away.
    pub away: Option<String>,
    /// Logged-in account name, if authenticated via SASL.
    pub account: Option<String>,
    /// Whether the client is an IRC operator (umode `+o`).
    pub oper: bool,
    /// Whether the connection is TLS-secured (`RPL_WHOISSECURE`).
    pub secure: bool,
    /// Umode `+i`: invisible (excluded from the LUSERS visible count and from
    /// mask-based WHO by non-co-members).
    pub invisible: bool,
    /// Umode `+w`: receives server WALLOPS.
    pub wallops: bool,
    /// Umode `+B` (IRCv3 bot-mode): marks the user as a bot. Reported in WHOIS
    /// (`RPL_WHOISBOT`), WHO flags, and as a bare `@bot` message tag.
    pub bot: bool,
    /// Folded nicks this client is monitoring (MONITOR); mirrored in the
    /// server-wide `monitors` reverse index.
    pub monitor: HashSet<String>,
    /// `draft/metadata-2` key/value pairs on this user.
    pub metadata: HashMap<String, String>,
    /// `draft/metadata-2` keys this client has subscribed to (`METADATA SUB`):
    /// it receives a `METADATA` event whenever any visible user or channel
    /// changes one of them.
    pub metadata_subs: HashSet<String>,
    /// `SILENCE` list: `nick!user@host` globs whose private messages this
    /// client refuses (a personal, server-side ignore).
    pub silence: HashSet<String>,
    /// When the client connected (Unix seconds).
    pub connected_at: u64,
    /// Last time the client sent a command (Unix seconds), for WHOIS idle.
    pub last_active: u64,
}

impl ClientData {
    fn new(host: String) -> Self {
        Self {
            nick: "*".to_owned(),
            user: String::new(),
            real_ip: host.clone(),
            host,
            realname: String::new(),
            registered: false,
            channels: HashSet::new(),
            away: None,
            account: None,
            oper: false,
            secure: false,
            invisible: false,
            wallops: false,
            bot: false,
            monitor: HashSet::new(),
            metadata: HashMap::new(),
            metadata_subs: HashSet::new(),
            silence: HashSet::new(),
            connected_at: now_unix(),
            last_active: now_unix(),
        }
    }
}

/// Held for the duration of a JOIN attempt. While it is alive the channel
/// cannot be reaped (see [`Server::begin_join`]); on drop it releases the
/// in-flight count and reaps the channel if the join was rejected and left it
/// empty. Correct on every exit path (including a panic) via `Drop`.
#[derive(Debug)]
pub struct JoinGuard {
    server: Arc<Server>,
    folded: String,
    channel: Arc<ChannelEntry>,
}

impl Drop for JoinGuard {
    fn drop(&mut self) {
        self.channel.joining.fetch_sub(1, Ordering::AcqRel);
        self.server.reap_channel(&self.folded);
    }
}

/// A channel and its membership/topic/modes.
#[derive(Debug)]
pub struct ChannelEntry {
    /// Mutable channel state.
    pub data: Mutex<ChannelData>,
    /// Count of JOINs currently in flight (see [`JoinGuard`]). Incremented while
    /// the `channels` shard lock is held so it cannot race [`Server::reap_channel`],
    /// which refuses to remove a channel while this is non-zero. This closes the
    /// create/reap race where a joiner holds the channel `Arc` but has not yet
    /// inserted its member.
    joining: AtomicU32,
}

impl ChannelEntry {
    fn new(display_name: &str) -> Self {
        Self {
            data: Mutex::new(ChannelData {
                name: display_name.to_owned(),
                topic: None,
                members: HashMap::new(),
                remote_members: HashMap::new(),
                modes: ChannelModes::default(),
                bans: Vec::new(),
                exceptions: Vec::new(),
                invex: Vec::new(),
                invited: HashSet::new(),
                metadata: HashMap::new(),
                created_at: now_unix(),
            }),
            joining: AtomicU32::new(0),
        }
    }

    /// Send `bytes` to every member, optionally skipping the client with
    /// `except` id. Holds the channel lock only for the (non-blocking) sends.
    pub fn broadcast(&self, bytes: &Bytes, except: Option<u64>) {
        let data = self.data.lock();
        for member in data.members.values() {
            if Some(member.entry.id) == except {
                continue;
            }
            member.entry.send(bytes.clone());
        }
    }

    /// Snapshot members as `(entry, prefix)` pairs without holding the lock, so
    /// callers can read each client's identity without nesting locks.
    #[must_use]
    pub fn member_snapshot(&self) -> Vec<(Arc<ClientEntry>, MemberPrefix)> {
        self.data
            .lock()
            .members
            .values()
            .map(|m| (m.entry.clone(), m.prefix))
            .collect()
    }

    /// Snapshot remote members (for NAMES/WHO).
    #[must_use]
    pub fn remote_member_snapshot(&self) -> Vec<RemoteMember> {
        self.data.lock().remote_members.values().cloned().collect()
    }
}

/// Mutable channel state.
#[derive(Debug)]
pub struct ChannelData {
    /// Display name (original case of first creator).
    pub name: String,
    /// Current topic, if set.
    pub topic: Option<Topic>,
    /// Local members, keyed by client id (stable across nick changes).
    pub members: HashMap<u64, Member>,
    /// Members on linked servers, keyed by their network UID.
    pub remote_members: HashMap<String, RemoteMember>,
    /// Channel modes.
    pub modes: ChannelModes,
    /// `+b` ban list (hostmask patterns).
    pub bans: Vec<Ban>,
    /// `+e` ban-exception list — a match overrides a `+b` ban.
    pub exceptions: Vec<Ban>,
    /// `+I` invite-exception list — a match bypasses `+i` like a standing invite.
    pub invex: Vec<Ban>,
    /// Folded nicks currently invited (for `+i` bypass); consumed on join.
    pub invited: HashSet<String>,
    /// `draft/metadata-2` key/value pairs on this channel.
    pub metadata: HashMap<String, String>,
    /// Creation time (Unix seconds).
    pub created_at: u64,
}

impl ChannelData {
    /// Is the client with this id a member?
    #[must_use]
    pub fn has_member(&self, id: u64) -> bool {
        self.members.contains_key(&id)
    }

    /// The member record for a client id, if present.
    #[must_use]
    pub fn member(&self, id: u64) -> Option<&Member> {
        self.members.get(&id)
    }

    /// Whether the user matches any `+b` ban. Extended masks `~a:<glob>` match on
    /// account; all others are `nick!user@host` globs.
    #[must_use]
    pub fn is_banned(&self, hostmask: &str, account: Option<&str>) -> bool {
        self.bans
            .iter()
            .any(|b| ban_matches(&b.mask, hostmask, account))
    }

    /// Whether the user matches any `+e` ban exception (overrides a `+b` ban).
    #[must_use]
    pub fn is_excepted(&self, hostmask: &str, account: Option<&str>) -> bool {
        self.exceptions
            .iter()
            .any(|b| ban_matches(&b.mask, hostmask, account))
    }

    /// Whether the user matches any `+I` invite exception (bypasses `+i`).
    #[must_use]
    pub fn matches_invex(&self, hostmask: &str, account: Option<&str>) -> bool {
        self.invex
            .iter()
            .any(|b| ban_matches(&b.mask, hostmask, account))
    }
}

/// Accumulates a mode-change string like `+o-v` with correct sign transitions.
#[derive(Default)]
pub(crate) struct ModeAccum {
    pub(crate) flags: String,
    sign: Option<bool>,
    applied: usize,
}

impl ModeAccum {
    pub(crate) fn push(&mut self, adding: bool, c: char) {
        if self.sign != Some(adding) {
            self.flags.push(if adding { '+' } else { '-' });
            self.sign = Some(adding);
        }
        self.flags.push(c);
        self.applied += 1;
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.flags.is_empty()
    }

    /// How many mode changes have actually been applied (the `MODES` limit
    /// counts changes, not mode-string characters).
    pub(crate) fn applied_count(&self) -> usize {
        self.applied
    }
}

/// Per-list cap for the `+b`/`+e`/`+I` channel lists (`ISUPPORT MAXLIST`).
pub(crate) const MAX_LIST_ENTRIES: usize = 100;

/// Apply one add/remove to a channel list mode (`+b`/`+e`/`+I`), enforcing the
/// per-list cap and recording the change for the MODE echo. Shared by all three
/// list modes — and by the local and S2S apply paths — so their semantics
/// cannot drift.
pub(crate) fn apply_list_mode(
    list: &mut Vec<Ban>,
    adding: bool,
    mask: String,
    set_by: &str,
    accum: &mut ModeAccum,
    applied: &mut Vec<String>,
    flag: char,
) {
    if adding {
        if list.len() < MAX_LIST_ENTRIES && !list.iter().any(|b| b.mask == mask) {
            list.push(Ban {
                mask: mask.clone(),
                set_by: set_by.to_owned(),
                set_at: now_unix(),
            });
            accum.push(true, flag);
            applied.push(mask);
        }
    } else {
        let before = list.len();
        list.retain(|b| b.mask != mask);
        if list.len() != before {
            accum.push(false, flag);
            applied.push(mask);
        }
    }
}

/// Match a `+b` ban mask against a user (supporting the `~a:` account extban).
fn ban_matches(mask: &str, hostmask: &str, account: Option<&str>) -> bool {
    if let Some(pattern) = mask.strip_prefix("~a:") {
        return account.is_some_and(|a| crate::mask::matches(pattern, a));
    }
    crate::mask::matches(mask, hostmask)
}

/// A channel `+b` ban entry.
#[derive(Debug, Clone)]
pub struct Ban {
    /// The hostmask pattern (`nick!user@host` glob).
    pub mask: String,
    /// Who set it.
    pub set_by: String,
    /// When it was set (Unix seconds).
    pub set_at: u64,
}

/// One membership row: the client and its per-channel privileges.
#[derive(Debug)]
pub struct Member {
    /// The member's client handle.
    pub entry: Arc<ClientEntry>,
    /// Op/voice status in this channel.
    pub prefix: MemberPrefix,
}

/// A channel member who lives on a linked (remote) server.
#[derive(Debug, Clone)]
pub struct RemoteMember {
    /// The member's nickname.
    pub nick: String,
    /// The member's username / ident (for `userhost-in-names`, WHO).
    pub user: String,
    /// The member's host (for `userhost-in-names`, WHO).
    pub host: String,
    /// The SID of the server they are on.
    pub server_sid: String,
    /// Op/voice status in this channel.
    pub prefix: MemberPrefix,
}

impl RemoteMember {
    /// `nick!user@host` hostmask.
    #[must_use]
    pub fn hostmask(&self) -> String {
        format!("{}!{}@{}", self.nick, self.user, self.host)
    }
}

/// Per-channel member privileges.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemberPrefix {
    /// Channel operator (`+o`, shown as `@`).
    pub op: bool,
    /// Voiced (`+v`, shown as `+`).
    pub voice: bool,
}

impl MemberPrefix {
    /// The single highest-ranking prefix symbol (`@`, `+`, or empty).
    #[must_use]
    pub fn symbol(self) -> &'static str {
        if self.op {
            "@"
        } else if self.voice {
            "+"
        } else {
            ""
        }
    }

    /// Render prefixes for a NAMES/WHO reply. With `multi_prefix`, all applicable
    /// symbols are shown (e.g. `@+`); otherwise only the highest.
    #[must_use]
    pub fn render(self, multi_prefix: bool) -> String {
        if !multi_prefix {
            return self.symbol().to_owned();
        }
        let mut out = String::new();
        if self.op {
            out.push('@');
        }
        if self.voice {
            out.push('+');
        }
        out
    }
}

/// A channel topic and who set it when.
#[derive(Debug, Clone)]
pub struct Topic {
    /// The topic text.
    pub text: String,
    /// The nick that set it.
    pub set_by: String,
    /// When it was set (Unix seconds).
    pub set_at: u64,
}

/// Channel modes. Defaults to `+nt` (no external messages, topic-locked).
#[derive(Debug, Clone)]
pub struct ChannelModes {
    /// `+n`: only members may send to the channel.
    pub no_external: bool,
    /// `+t`: only ops may change the topic.
    pub topic_lock: bool,
    /// `+m`: moderated (only voiced/op may speak).
    pub moderated: bool,
    /// `+i`: invite-only.
    pub invite_only: bool,
    /// `+s`: secret (hidden from listings).
    pub secret: bool,
    /// `+k`: channel key (password).
    pub key: Option<String>,
    /// `+l`: member limit.
    pub limit: Option<usize>,
}

impl Default for ChannelModes {
    fn default() -> Self {
        Self {
            no_external: true,
            topic_lock: true,
            moderated: false,
            invite_only: false,
            secret: false,
            key: None,
            limit: None,
        }
    }
}

/// One simple (no-argument) boolean channel mode. [`BOOL_MODES`] is the single
/// source of truth for these: render, apply, registration seed/build, the
/// `ISUPPORT CHANMODES` type-D group and `RPL_MYINFO` all derive from it, so a
/// new boolean mode is added in exactly one place.
#[derive(Debug)]
pub(crate) struct BoolMode {
    /// Mode letter (e.g. `n`).
    pub letter: char,
    /// Read the mode's current state.
    pub get: fn(&ChannelModes) -> bool,
    /// Set the mode's state.
    pub set: fn(&mut ChannelModes, bool),
    /// Persistence bit in a [`RegisteredChannel`] `mode_flags`.
    pub persist_bit: u8,
}

/// Every simple boolean channel mode, in canonical (advertised) order.
pub(crate) const BOOL_MODES: &[BoolMode] = &[
    BoolMode {
        letter: 'i',
        get: |m| m.invite_only,
        set: |m, v| m.invite_only = v,
        persist_bit: chanreg::MODE_INVITE_ONLY,
    },
    BoolMode {
        letter: 'm',
        get: |m| m.moderated,
        set: |m, v| m.moderated = v,
        persist_bit: chanreg::MODE_MODERATED,
    },
    BoolMode {
        letter: 'n',
        get: |m| m.no_external,
        set: |m, v| m.no_external = v,
        persist_bit: chanreg::MODE_NO_EXTERNAL,
    },
    BoolMode {
        letter: 's',
        get: |m| m.secret,
        set: |m, v| m.secret = v,
        persist_bit: chanreg::MODE_SECRET,
    },
    BoolMode {
        letter: 't',
        get: |m| m.topic_lock,
        set: |m, v| m.topic_lock = v,
        persist_bit: chanreg::MODE_TOPIC_LOCK,
    },
];

/// The boolean channel-mode letters as a string (e.g. `imnst`), for the
/// `ISUPPORT CHANMODES` type-D group and `RPL_MYINFO`.
#[must_use]
pub(crate) fn bool_mode_letters() -> String {
    BOOL_MODES.iter().map(|m| m.letter).collect()
}

impl ChannelModes {
    /// Render the mode string and its arguments, e.g. `("+ntl", vec!["50"])`.
    /// If `reveal_key` is false, the key is shown as `*` (used in listings).
    #[must_use]
    pub fn render(&self, reveal_key: bool) -> (String, Vec<String>) {
        let mut flags = String::from("+");
        let mut args = Vec::new();
        for mode in BOOL_MODES {
            if (mode.get)(self) {
                flags.push(mode.letter);
            }
        }
        if let Some(key) = &self.key {
            flags.push('k');
            args.push(if reveal_key {
                key.clone()
            } else {
                "*".to_owned()
            });
        }
        if let Some(limit) = self.limit {
            flags.push('l');
            args.push(limit.to_string());
        }
        (flags, args)
    }
}

/// Seed a freshly-created channel with a registration's saved topic and modes.
fn seed_from_registration(channel: &ChannelEntry, record: &RegisteredChannel) {
    let mut d = channel.data.lock();
    if let Some(text) = &record.topic_text {
        d.topic = Some(Topic {
            text: text.clone(),
            set_by: record.topic_setby.clone(),
            set_at: record.topic_setat,
        });
    }
    let f = record.mode_flags;
    for mode in BOOL_MODES {
        (mode.set)(&mut d.modes, f & mode.persist_bit != 0);
    }
    d.modes.key = record.key.clone();
    d.modes.limit = record.limit.map(|v| v as usize);
}

/// Build a registration record from a channel's current topic and modes.
fn build_registration(folded: &str, founder: &str, channel: &ChannelEntry) -> RegisteredChannel {
    let d = channel.data.lock();
    let mut flags = 0u8;
    for mode in BOOL_MODES {
        if (mode.get)(&d.modes) {
            flags |= mode.persist_bit;
        }
    }
    let (topic_text, topic_setby, topic_setat) = match &d.topic {
        Some(t) => (Some(t.text.clone()), t.set_by.clone(), t.set_at),
        None => (None, String::new(), 0),
    };
    RegisteredChannel {
        folded: folded.to_owned(),
        name: d.name.clone(),
        founder: founder.to_owned(),
        topic_text,
        topic_setby,
        topic_setat,
        mode_flags: flags,
        key: d.modes.key.clone(),
        limit: d.modes.limit.map(|v| v as u64),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_server() -> Arc<Server> {
        Server::new(ServerInfo {
            name: "irc.a".to_owned(),
            sid: "1AA".to_owned(),
            network: "n".to_owned(),
            icon: None,
            version: "v".to_owned(),
            created: "c".to_owned(),
            casemapping: crate::casemap::CaseMapping::Ascii,
            motd: Vec::new(),
            history_len: 10,
            history_max_targets: 1000,
            max_channels: 50,
            cloak_key: None,
            sts: None,
        })
    }

    fn remote(sid: &str, uid: &str, nick: &str) -> RemoteUser {
        RemoteUser {
            server_sid: sid.to_owned(),
            uid: uid.to_owned(),
            nick: nick.to_owned(),
            user: "u".to_owned(),
            host: "h".to_owned(),
            account: None,
            realname: "r".to_owned(),
            away: None,
            oper: false,
            invisible: false,
            bot: false,
        }
    }

    #[test]
    fn remote_uid_index_survives_nick_change_and_quit() {
        let server = test_server();
        assert!(server.route_authorize("2BB", "2BB"));
        assert!(server
            .accept_remote_user(remote("2BB", "2BBaaa", "bob"))
            .is_none());

        // Lookup by uid resolves through the index.
        assert!(server.remote_uid_authorized("2BB", "2BBaaa"));

        // A nick change re-keys the nick map but the uid index still resolves.
        assert!(server.remote_nick_change("2BBaaa", "bobby").is_none());
        assert_eq!(server.find_remote_user("bobby").unwrap().uid, "2BBaaa");
        assert!(server.find_remote_user("bob").is_none());
        assert!(server.remote_uid_authorized("2BB", "2BBaaa"));

        // A quit clears both maps.
        server.remote_quit("2BBaaa", "gone");
        assert!(server.find_remote_user("bobby").is_none());
        assert!(!server.remote_uid_authorized("2BB", "2BBaaa"));
    }

    fn link_handle(sid: &str, name: &str) -> (LinkHandle, mpsc::Receiver<Bytes>) {
        let (tx, rx) = mpsc::channel(256);
        (
            LinkHandle::new(sid.to_owned(), name.to_owned(), "d".to_owned(), tx),
            rx,
        )
    }

    #[test]
    fn squit_resolves_by_sid_or_name_and_notifies_peer() {
        let server = test_server();
        let (b, mut b_rx) = link_handle("2BB", "irc.b");
        server.try_register_link(b).expect("link registers");

        // Resolvable by SID and by name (case-insensitive); unknown names miss.
        assert!(server.direct_link("2BB").is_some());
        assert!(server.direct_link("IRC.B").is_some());
        assert!(server.direct_link("irc.nope").is_none());

        // SQUIT by name returns the peer name and queues an SQUIT to the peer.
        let name = server.squit_link("irc.b", "bye now");
        assert_eq!(name.as_deref(), Some("irc.b"));
        let frame = b_rx.try_recv().expect("peer should receive an SQUIT frame");
        let text = String::from_utf8_lossy(&frame);
        assert!(text.contains("SQUIT"), "not an SQUIT: {text}");
        assert!(text.contains("bye now"), "reason missing: {text}");

        // SQUIT of an unknown server reports nothing to tear down.
        assert!(server.squit_link("irc.nope", "x").is_none());
    }

    #[test]
    fn loop_forming_links_are_refused() {
        let server = test_server();

        // Our own identity can never link to us.
        let (own_sid, _rx) = link_handle("1AA", "irc.elsewhere");
        assert!(server.try_register_link(own_sid).is_err());
        let (own_name, _rx) = link_handle("9ZZ", "irc.a");
        assert!(server.try_register_link(own_name).is_err());

        // First link to 2BB registers fine…
        let (b, _b_rx) = link_handle("2BB", "irc.b");
        server.try_register_link(b).expect("first link registers");

        // …a second connection claiming the same SID or name is a loop.
        let (b_again, _rx) = link_handle("2BB", "irc.b2");
        assert!(server.try_register_link(b_again).is_err());
        let (b_name, _rx) = link_handle("4DD", "IRC.B");
        assert!(
            server.try_register_link(b_name).is_err(),
            "server names are unique case-insensitively"
        );

        // A server known via 2BB (multi-hop) cannot also link directly.
        server
            .accept_remote_server(
                "2BB",
                RemoteServer {
                    sid: "3CC".to_owned(),
                    name: "irc.c".to_owned(),
                    uplink: "2BB".to_owned(),
                    description: "C".to_owned(),
                },
            )
            .expect("introduction via 2BB accepted");
        let (c_direct, _rx) = link_handle("3CC", "irc.c");
        assert!(
            server.try_register_link(c_direct).is_err(),
            "a direct link to a server already reachable via a peer closes a cycle"
        );

        // And the reverse: an introduction of an already-linked SID from a
        // different peer is a detected cycle.
        let (d, _d_rx) = link_handle("4DD", "irc.d");
        server.try_register_link(d).expect("second peer registers");
        assert!(
            server
                .accept_remote_server(
                    "4DD",
                    RemoteServer {
                        sid: "2BB".to_owned(),
                        name: "irc.b-again".to_owned(),
                        uplink: "4DD".to_owned(),
                        description: "B".to_owned(),
                    },
                )
                .is_err(),
            "an introduction of a directly-linked SID via another peer is a cycle"
        );
        assert!(
            server
                .accept_remote_server(
                    "4DD",
                    RemoteServer {
                        sid: "5EE".to_owned(),
                        name: "irc.c".to_owned(),
                        uplink: "4DD".to_owned(),
                        description: "C".to_owned(),
                    },
                )
                .is_err(),
            "a name collision under a fresh SID is still a cycle"
        );
    }

    #[test]
    fn split_remote_server_removes_whole_subtree_and_drop_link_propagates_squit() {
        let server = test_server();
        let (b, _b_rx) = link_handle("2BB", "irc.b");
        server.try_register_link(b).expect("link registers");
        let (d, mut d_rx) = link_handle("4DD", "irc.d");
        server.try_register_link(d).expect("link registers");

        // Topology behind 2BB: 2BB → 3CC → 5EE, with a user on each.
        for (sid, uplink, name) in [("3CC", "2BB", "irc.c"), ("5EE", "3CC", "irc.e")] {
            server
                .accept_remote_server(
                    "2BB",
                    RemoteServer {
                        sid: sid.to_owned(),
                        name: name.to_owned(),
                        uplink: uplink.to_owned(),
                        description: String::new(),
                    },
                )
                .expect("introduction accepted");
        }
        assert!(server.route_authorize("2BB", "2BB"));
        for (sid, uid, nick) in [
            ("2BB", "2BBu1", "berta"),
            ("3CC", "3CCu1", "carla"),
            ("5EE", "5EEu1", "emil"),
        ] {
            assert!(server.accept_remote_user(remote(sid, uid, nick)).is_none());
        }

        // A downstream SQUIT of 3CC takes 5EE with it, but 2BB stays.
        server.split_remote_server("3CC", "split");
        assert!(server.find_remote_user("carla").is_none());
        assert!(server.find_remote_user("emil").is_none());
        assert!(server.find_remote_user("berta").is_some());
        assert!(server.route_owner("3CC").is_none());
        assert!(server.route_owner("5EE").is_none());

        // 3CC can now legitimately re-link through 4DD (no stale route).
        assert!(server
            .accept_remote_server(
                "4DD",
                RemoteServer {
                    sid: "3CC".to_owned(),
                    name: "irc.c".to_owned(),
                    uplink: "4DD".to_owned(),
                    description: String::new(),
                },
            )
            .is_ok());

        // Dropping the 2BB link quits its users and tells 4DD via SQUIT.
        server.drop_link("2BB");
        assert!(server.find_remote_user("berta").is_none());
        let mut sent = String::new();
        while let Ok(bytes) = d_rx.try_recv() {
            sent.push_str(&String::from_utf8_lossy(&bytes));
        }
        assert!(
            sent.contains("SQUIT 2BB"),
            "remaining links must learn about the split: {sent:?}"
        );
    }

    /// Drain all currently-queued lines from a client mailbox into one string.
    fn drain_mailbox(rx: &mut MailboxRx) -> String {
        let mut out = String::new();
        while let Ok(msg) = rx.try_recv() {
            if let Outbound::Line(bytes) = msg {
                out.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
        out
    }

    #[test]
    fn bool_mode_table_drives_letters_and_render() {
        // Single source of truth: the advertised letters and a full render match
        // the table exactly, so ISUPPORT/MYINFO/apply/render cannot drift.
        assert_eq!(bool_mode_letters(), "imnst");
        // Explicit all-off state (channels default to +nt, so don't use Default).
        let mut modes = ChannelModes {
            no_external: false,
            topic_lock: false,
            moderated: false,
            invite_only: false,
            secret: false,
            key: None,
            limit: None,
        };
        for bm in BOOL_MODES {
            (bm.set)(&mut modes, true);
            assert!((bm.get)(&modes), "get/set mismatch for +{}", bm.letter);
        }
        let (flags, _) = modes.render(false);
        assert_eq!(flags, "+imnst");
    }

    #[test]
    fn s2s_federation_reaches_local_members() {
        let server = test_server(); // our SID is "1AA"

        // A local, registered client "alice" sitting in #global.
        let (alice, mut alice_rx) = ClientEntry::new(1, "127.0.0.1".to_owned(), 64);
        {
            let mut d = alice.data.lock();
            d.nick = "alice".to_owned();
            d.user = "alice".to_owned();
            d.host = "h".to_owned();
            d.registered = true;
            d.channels.insert("#global".to_owned());
        }
        server.claim_nick(&server.fold("alice"), &alice);
        let (channel, _) = server.get_or_create_channel("#global", "#global");
        channel.data.lock().members.insert(
            alice.id,
            Member {
                entry: alice.clone(),
                prefix: MemberPrefix::default(),
            },
        );

        // A peer 2BB introduces remote user "bob" and joins #global.
        assert!(server.route_authorize("2BB", "2BB"));
        assert!(server
            .accept_remote_user(remote("2BB", "2BBbob", "bob"))
            .is_none());
        server.remote_join("#global", "2BBbob", MemberPrefix::default(), 0);
        let joined = drain_mailbox(&mut alice_rx);
        assert!(
            joined.contains("JOIN") && joined.contains("bob"),
            "local member never saw the remote JOIN: {joined:?}"
        );

        // A channel message from bob reaches alice.
        server.deliver_channel_message(
            "2BB", "bob!u@h", "#global", false, None, None, None, "hi all",
        );
        let msg = drain_mailbox(&mut alice_rx);
        assert!(
            msg.contains("PRIVMSG #global") && msg.contains("hi all"),
            "local member never saw the remote message: {msg:?}"
        );

        // Bob renames; alice sees the NICK.
        assert!(server.remote_nick_change("2BBbob", "bobby").is_none());
        let nick = drain_mailbox(&mut alice_rx);
        assert!(
            nick.contains("NICK") && nick.contains("bobby"),
            "local member never saw the remote NICK: {nick:?}"
        );

        // Bob quits; alice sees the QUIT and the remote membership is purged.
        server.remote_quit("2BBbob", "gone");
        let quit = drain_mailbox(&mut alice_rx);
        assert!(
            quit.contains("QUIT"),
            "local member never saw the remote QUIT: {quit:?}"
        );
        assert!(channel.data.lock().remote_members.is_empty());
    }

    #[test]
    fn s2s_origin_enforcement() {
        let server = test_server(); // our SID is "1AA"

        // A peer owns its own SID and any SID it first announces behind it.
        assert!(server.route_authorize("2BB", "2BB"));
        assert!(server.route_authorize("2BB", "3CC"));
        // A different peer cannot claim a SID another peer already routes.
        assert!(!server.route_authorize("2DD", "3CC"));
        // No peer may ever speak for our own SID.
        assert!(!server.route_authorize("2BB", "1AA"));

        // A user introduced on 2BB is actionable only by 2BB.
        assert!(server
            .accept_remote_user(remote("2BB", "2BBaaa", "bob"))
            .is_none());
        assert!(server.remote_uid_authorized("2BB", "2BBaaa"));
        assert!(!server.remote_uid_authorized("2DD", "2BBaaa"));
        assert!(!server.remote_uid_authorized("2BB", "9ZZzzz")); // unknown uid

        // Message sources are validated the same way.
        assert!(server.remote_source_authorized("2BB", "bob!u@h"));
        assert!(!server.remote_source_authorized("2DD", "bob!u@h"));

        // A split drops the peer's routes so its SIDs can be re-announced later.
        server.drop_link("2BB");
        assert!(server.route_authorize("2DD", "3CC"));
    }

    #[test]
    fn join_guard_blocks_reap_until_join_completes() {
        let server = test_server();
        let folded = "#g".to_owned();

        let (channel, created, guard) = server.begin_join(&folded, "#g");
        assert!(created);
        // The channel is empty (the member has not been inserted yet), but a
        // concurrent reap MUST NOT delete it while the join is in flight.
        server.reap_channel(&folded);
        assert!(
            server.find_channel(&folded).is_some(),
            "reap removed a channel mid-join (the split-brain race)"
        );

        // Once the join finishes, dropping the guard reaps the still-empty
        // channel (this join was rejected, so no member remains).
        drop(guard);
        assert!(
            server.find_channel(&folded).is_none(),
            "empty channel not reaped after the join guard dropped"
        );
        let _ = channel;
    }

    #[test]
    fn remote_collision_resolves_by_smaller_uid() {
        let server = test_server();

        // First arrival: no collision.
        assert!(server
            .accept_remote_user(remote("1BB", "1BBaaa", "dup"))
            .is_none());
        assert_eq!(server.find_remote_user("dup").unwrap().uid, "1BBaaa");

        // A larger UID loses: a KILL is returned and the incumbent stays.
        let verdict = server.accept_remote_user(remote("1CC", "1CCaaa", "dup"));
        assert!(matches!(
            verdict,
            Some(crate::s2s::LinkMessage::Kill { .. })
        ));
        assert_eq!(server.find_remote_user("dup").unwrap().uid, "1BBaaa");

        // A smaller UID wins: it replaces the incumbent, no KILL returned.
        assert!(server
            .accept_remote_user(remote("1AA", "1AAaaa", "dup"))
            .is_none());
        assert_eq!(server.find_remote_user("dup").unwrap().uid, "1AAaaa");
    }

    #[test]
    fn remote_reintroduction_refreshes_without_kill() {
        let server = test_server();
        assert!(server
            .accept_remote_user(remote("1BB", "1BBaaa", "dup"))
            .is_none());
        // Same UID again (e.g. a re-burst) is not a collision.
        assert!(server
            .accept_remote_user(remote("1BB", "1BBaaa", "dup"))
            .is_none());
    }

    /// Set up a local registered client as a member of `chan`.
    fn local_in_channel(
        server: &Arc<Server>,
        id: u64,
        nick: &str,
        chan: &str,
        op: bool,
    ) -> (Arc<ClientEntry>, MailboxRx) {
        let (entry, rx) = ClientEntry::new(id, "127.0.0.1".to_owned(), 64);
        {
            let mut d = entry.data.lock();
            d.nick = nick.to_owned();
            d.user = nick.to_owned();
            d.host = "h".to_owned();
            d.registered = true;
            d.channels.insert(server.fold(chan));
        }
        server.claim_nick(&server.fold(nick), &entry);
        let (channel, _) = server.get_or_create_channel(&server.fold(chan), chan);
        channel.data.lock().members.insert(
            id,
            Member {
                entry: entry.clone(),
                prefix: MemberPrefix { op, voice: false },
            },
        );
        (entry, rx)
    }

    #[test]
    fn remote_topic_mode_kick_are_applied_and_announced() {
        let server = test_server(); // our SID is "1AA"
        let (alice, mut alice_rx) = local_in_channel(&server, 1, "alice", "#g", false);

        assert!(server.route_authorize("2BB", "2BB"));
        assert!(server
            .accept_remote_user(remote("2BB", "2BBbob", "bob"))
            .is_none());
        server.remote_join("#g", "2BBbob", MemberPrefix::default(), 0);
        let _ = drain_mailbox(&mut alice_rx);

        // Topic: applied and announced with the remote user's mask.
        server.remote_topic("#g", "2BBbob", "bob", 99, "hello from afar");
        let seen = drain_mailbox(&mut alice_rx);
        assert!(
            seen.contains("bob!u@h TOPIC #g :hello from afar"),
            "topic not announced: {seen:?}"
        );
        let channel = server.find_channel("#g").unwrap();
        assert_eq!(
            channel.data.lock().topic.as_ref().unwrap().text,
            "hello from afar"
        );

        // Mode: `+m` plus an op for a LOCAL member addressed by its UID.
        server.remote_mode("#g", "2BBbob", 0, "+mo", &["1AA1".to_owned()]);
        let seen = drain_mailbox(&mut alice_rx);
        assert!(
            seen.contains("MODE #g +mo alice"),
            "mode not announced with the nick: {seen:?}"
        );
        {
            let d = channel.data.lock();
            assert!(d.modes.moderated);
            assert!(d.members.get(&alice.id).unwrap().prefix.op);
        }

        // Kick of the local member: announced (the target sees it) and applied.
        server.remote_kick("#g", "2BBbob", "1AA1", "begone");
        let seen = drain_mailbox(&mut alice_rx);
        assert!(
            seen.contains("KICK #g alice :begone"),
            "kick not announced: {seen:?}"
        );
        assert!(!channel.data.lock().has_member(alice.id));
        assert!(!alice.data.lock().channels.contains("#g"));
    }

    #[test]
    fn remote_away_and_account_reach_capable_members_only() {
        let server = test_server();
        let (alice, mut alice_rx) = local_in_channel(&server, 1, "alice", "#g", false);
        let (_carol, mut carol_rx) = local_in_channel(&server, 2, "carol", "#g", false);
        alice.set_caps(crate::cap::CapSet::from_bits(
            crate::cap::Cap::AwayNotify.bit() | crate::cap::Cap::AccountNotify.bit(),
        ));

        assert!(server.route_authorize("2BB", "2BB"));
        assert!(server
            .accept_remote_user(remote("2BB", "2BBbob", "bob"))
            .is_none());
        server.remote_join("#g", "2BBbob", MemberPrefix::default(), 0);
        let _ = drain_mailbox(&mut alice_rx);
        let _ = drain_mailbox(&mut carol_rx);

        server.remote_away("2BBbob", Some("brb"));
        server.remote_account("2BBbob", Some("bobacc"));

        let alice_saw = drain_mailbox(&mut alice_rx);
        assert!(
            alice_saw.contains("AWAY :brb") && alice_saw.contains("ACCOUNT bobacc"),
            "capable member missed notifications: {alice_saw:?}"
        );
        let carol_saw = drain_mailbox(&mut carol_rx);
        assert!(
            !carol_saw.contains("AWAY") && !carol_saw.contains("ACCOUNT"),
            "incapable member got cap-gated notifications: {carol_saw:?}"
        );

        // The state itself is updated for WHOIS etc.
        let bob = server.find_remote_user("bob").unwrap();
        assert_eq!(bob.away.as_deref(), Some("brb"));
        assert_eq!(bob.account.as_deref(), Some("bobacc"));

        // Coming back clears the state.
        server.remote_away("2BBbob", None);
        assert!(server.find_remote_user("bob").unwrap().away.is_none());
    }

    #[test]
    fn remote_nick_change_collision_smaller_uid_wins() {
        let server = test_server();
        assert!(server.route_authorize("2BB", "2BB"));
        assert!(server.route_authorize("3CC", "3CC"));
        assert!(server
            .accept_remote_user(remote("2BB", "2BBaaa", "anna"))
            .is_none());
        assert!(server
            .accept_remote_user(remote("3CC", "3CCbbb", "bea"))
            .is_none());

        // The smaller uid renames onto "bea": the incumbent (larger uid) is
        // killed and the rename goes through.
        assert!(server.remote_nick_change("2BBaaa", "bea").is_none());
        assert_eq!(server.find_remote_user("bea").unwrap().uid, "2BBaaa");
        assert!(!server.remote_uid_authorized("3CC", "3CCbbb"));

        // A larger uid renaming onto an existing nick loses: a KILL comes back
        // and the renamer is dropped.
        assert!(server
            .accept_remote_user(remote("3CC", "3CCccc", "cora"))
            .is_none());
        let verdict = server.remote_nick_change("3CCccc", "bea");
        assert!(matches!(
            verdict,
            Some(crate::s2s::LinkMessage::Kill { ref uid, .. }) if uid == "3CCccc"
        ));
        assert!(server.find_remote_user("cora").is_none());
        assert_eq!(server.find_remote_user("bea").unwrap().uid, "2BBaaa");
    }

    #[test]
    fn remote_quit_notifies_shared_members_once() {
        let server = test_server();
        let (_alice, mut alice_rx) = local_in_channel(&server, 1, "alice", "#a", false);
        {
            // alice is also in #b.
            let (channel, _) = server.get_or_create_channel("#b", "#b");
            let entry = server.find_client("alice").unwrap();
            entry.data.lock().channels.insert("#b".to_owned());
            channel.data.lock().members.insert(
                1,
                Member {
                    entry,
                    prefix: MemberPrefix::default(),
                },
            );
        }
        assert!(server.route_authorize("2BB", "2BB"));
        assert!(server
            .accept_remote_user(remote("2BB", "2BBbob", "bob"))
            .is_none());
        server.remote_join("#a", "2BBbob", MemberPrefix::default(), 0);
        server.remote_join("#b", "2BBbob", MemberPrefix::default(), 0);
        let _ = drain_mailbox(&mut alice_rx);

        server.remote_quit("2BBbob", "gone");
        let seen = drain_mailbox(&mut alice_rx);
        assert_eq!(
            seen.matches("QUIT").count(),
            1,
            "QUIT must be deduped across shared channels: {seen:?}"
        );
        // Membership and index are fully purged.
        assert!(server
            .find_channel("#a")
            .is_none_or(|c| c.data.lock().remote_members.is_empty()));
        assert!(server
            .find_channel("#b")
            .is_none_or(|c| c.data.lock().remote_members.is_empty()));
    }

    /// Drain a link mailbox (the peer-facing byte stream) into one string.
    fn drain_link(rx: &mut mpsc::Receiver<Bytes>) -> String {
        let mut out = String::new();
        while let Ok(bytes) = rx.try_recv() {
            out.push_str(&String::from_utf8_lossy(&bytes));
        }
        out
    }

    #[test]
    fn burst_sends_users_memberships_topic_modes_and_lists() {
        let server = test_server(); // our SID is "1AA"
        let (alice, _alice_rx) = local_in_channel(&server, 1, "alice", "#g", true);
        alice.data.lock().away = Some("afk".to_owned());
        {
            let channel = server.find_channel("#g").unwrap();
            let mut d = channel.data.lock();
            d.topic = Some(Topic {
                text: "burst me".to_owned(),
                set_by: "alice".to_owned(),
                set_at: 42,
            });
            d.modes.moderated = true;
            d.modes.key = Some("sekret".to_owned());
            d.bans.push(Ban {
                mask: "*!*@bad.example".to_owned(),
                set_by: "alice".to_owned(),
                set_at: 42,
            });
        }
        // A remote user routed via another peer must also be bursted (multi-hop).
        assert!(server.route_authorize("3CC", "3CC"));
        assert!(server
            .accept_remote_user(remote("3CC", "3CCbob", "bob"))
            .is_none());
        server.remote_join("#g", "3CCbob", MemberPrefix::default(), 0);

        let (tx, mut rx) = mpsc::channel::<Bytes>(256);
        server.register_link(LinkHandle::new(
            "2BB".to_owned(),
            "irc.b".to_owned(),
            "B".to_owned(),
            tx,
        ));
        server.burst_to_peer("2BB");

        let burst = drain_link(&mut rx);
        assert!(
            burst.contains("UID 1AA 1AA1"),
            "local user missing: {burst}"
        );
        assert!(
            burst.contains("SAWAY 1AA1 :afk"),
            "away state missing: {burst}"
        );
        assert!(
            burst.contains("UID 3CC 3CCbob"),
            "routed remote user missing: {burst}"
        );
        assert!(
            burst.contains("SJOIN #g 1AA1 o"),
            "membership with op prefix missing: {burst}"
        );
        assert!(
            burst.contains("SJOIN #g 3CCbob -"),
            "remote membership missing: {burst}"
        );
        assert!(
            burst.contains("STOPIC #g * alice 42 :burst me"),
            "topic missing: {burst}"
        );
        assert!(
            burst.contains("SMODE #g *") && burst.contains("+mnt") && burst.contains("sekret"),
            "modes missing: {burst}"
        );
        assert!(
            burst.contains("+b *!*@bad.example"),
            "ban list missing: {burst}"
        );
        // The burst ends with a marker the peer can wait on.
        assert!(burst.contains("PING :1AA"), "end-of-burst missing: {burst}");
    }
}
