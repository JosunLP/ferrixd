//! WebAssembly plugin host.
//!
//! Plugins are sandboxed `.wasm` modules loaded at startup. They observe
//! server events, may veto or rewrite them, keep bounded per-plugin state,
//! query a read-only view of the world, run on a timer, and — when the operator
//! grants the capability — act on the server: notices, messages, kicks, channel
//! modes, topics, and K-Lines. All of it without native code in the daemon.
//!
//! Sandbox properties:
//!  * **Isolation** — WebAssembly has no ambient authority. A plugin can only
//!    call the host functions we explicitly provide (see [`register_host_api`]);
//!    it cannot touch the filesystem, network, or process. Persistence happens
//!    only through the host-managed, size-bounded key-value store.
//!  * **DoS resistance** — every hook call runs with a bounded *fuel* budget
//!    (an instruction counter) and a bounded linear-memory size. A plugin that
//!    loops forever runs out of fuel and traps; one that grows memory without
//!    limit hits the cap. The host treats a trap as "allow" (fail-open) so a
//!    broken plugin cannot wedge the server.
//!  * **Deny-by-default capabilities** — every active ability (see
//!    [`Capability`]) works only when the operator grants it to that plugin in
//!    the server config; a plugin cannot grant itself anything, and an
//!    ungranted call refuses and logs rather than silently succeeding.
//!  * **No event amplification** — plugin-produced output is sanitized (no
//!    CR/LF injection), budgeted per hook call, rate-limited per plugin, and
//!    server-originated output does not re-enter the plugin hooks — locally,
//!    or as a relayed message arriving from another node's plugin.
//!  * **Memory-safe by construction** — we use [`wasmi`], a pure-Rust
//!    interpreter, so the host stays free of a JIT and of `cmake`/C toolchains,
//!    consistent with the rest of ferrixd.
//!
//! ## Plugin ABI
//!
//! A plugin must export its linear memory as `memory` and a bump allocator
//! `alloc(i32) -> i32`. The host allocates via `alloc`, writes the UTF-8
//! payload into plugin memory, and calls the hook; a non-zero return blocks
//! the event. The full contract — every hook export and every `ferrix.*`
//! host import — is documented in `docs/reference/plugin-abi.md`.
//!
//! Both local and S2S-relayed channel messages pass through the message hooks,
//! so policy is uniform across the network's entry points on this node.
//!
//! Actions a plugin queues are never executed from inside the sandbox: the host
//! collects them in [`Outcome::actions`] and the server applies them after the
//! call returns (see `Server::apply_plugin_actions`), sourced from the server
//! itself and propagated over S2S like any other server-originated state.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, Weak};

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use parking_lot::Mutex;
use tracing::{debug, error, info, warn};
use wasmi::{
    Caller, Config, Engine, Extern, Linker, Memory, Module, ResourceLimiter, Store, StoreLimits,
    StoreLimitsBuilder, TypedFunc,
};

/// Default per-call fuel budget (instructions) if none is configured.
pub const DEFAULT_FUEL: u64 = 5_000_000;

/// Default cap on a plugin instance's linear memory (bytes).
pub const DEFAULT_MAX_MEMORY: usize = 16 * 1024 * 1024;

/// The ABI level reported to plugins in the `ferrix_on_load` payload.
pub const ABI_VERSION: u32 = 3;

// --- plugin output bounds (all enforced host-side) -------------------------
/// Longest replacement/notice text a plugin can produce (bytes, pre-truncated
/// on a char boundary). Comfortably under the 512-byte IRC line limit.
const MAX_TEXT_BYTES: usize = 400;
/// Longest custom FAIL reason a plugin can produce (bytes).
const MAX_REASON_BYTES: usize = 200;
/// Longest action target (nick or channel) a plugin can name (bytes).
const MAX_TARGET_BYTES: usize = 64;
/// Longest ban mask a plugin can name in a `kline` action (bytes).
const MAX_MASK_BYTES: usize = 128;
/// Longest mode string (flags plus arguments) a plugin can apply (bytes).
const MAX_MODE_BYTES: usize = 128;
/// Most arguments a plugin-supplied mode string may carry.
const MAX_MODE_ARGS: usize = 8;
/// Longest topic a plugin can set (bytes) — the server's own TOPICLEN.
const MAX_TOPIC_BYTES: usize = 390;
/// Most random bytes one `ferrix.random_bytes` call yields.
const MAX_RANDOM_BYTES: usize = 256;
/// Actions (e.g. notices) a single hook call may queue.
const MAX_ACTIONS_PER_CALL: usize = 4;
/// Actions a plugin may perform per rolling minute (across all hook calls).
const MAX_ACTIONS_PER_MINUTE: u32 = 120;
/// Largest response the query host functions will produce (bytes).
const MAX_QUERY_BYTES: usize = 64 * 1024;
/// Most member nicks a `channel_members` query returns.
const MAX_QUERY_MEMBERS: usize = 512;

// --- key-value store bounds ------------------------------------------------
const MAX_KV_KEYS: usize = 256;
const MAX_KV_KEY_BYTES: usize = 128;
const MAX_KV_VALUE_BYTES: usize = 8192;
const MAX_KV_TOTAL_BYTES: usize = 64 * 1024;
/// Minimum interval between two disk flushes of a plugin's KV store.
const KV_FLUSH_INTERVAL_MS: u64 = 2000;

/// Wall-clock milliseconds since the Unix epoch (also exposed to plugins as
/// `ferrix.now_ms`; not monotonic across clock adjustments).
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The decision a plugin returns for an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verdict {
    /// Let the event proceed.
    #[default]
    Allow,
    /// Block the event.
    Block,
}

/// An action a plugin queued during a hook call, executed by the server after
/// the call returns (never from inside the sandbox). Server-originated output
/// does not re-enter the plugin hooks, so a plugin cannot feed itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send a server NOTICE to a nick or channel. Requires the `send_notice`
    /// capability grant; target and text are already sanitized.
    Notice {
        /// Nick or channel name to deliver to.
        target: String,
        /// Notice body (control characters stripped, length-capped).
        text: String,
    },
    /// Send a server PRIVMSG to a nick or channel. Requires `send_message`.
    Message {
        /// Nick or channel name to deliver to.
        target: String,
        /// Message body (control characters stripped, length-capped).
        text: String,
    },
    /// Remove a user from a channel as the server. Requires `kick`.
    Kick {
        /// Channel to kick from.
        channel: String,
        /// Nick of the user to remove (local or on a linked server).
        nick: String,
        /// Kick reason.
        reason: String,
    },
    /// Apply a channel mode change as the server. Requires `mode`.
    Mode {
        /// Channel to change.
        channel: String,
        /// Mode flags.
        flags: String,
        /// Mode arguments, in flag order (nicks for `o`/`v`).
        args: Vec<String>,
    },
    /// Set (or clear, with empty text) a channel topic as the server.
    /// Requires `topic`.
    Topic {
        /// Channel to retopic.
        channel: String,
        /// New topic; empty clears it.
        text: String,
    },
    /// Add a K-Line and disconnect the users it matches. Requires `kline`.
    Kline {
        /// `nick!user@host` glob to ban.
        mask: String,
        /// Ban reason, shown to the disconnected users.
        reason: String,
        /// Who the ban is recorded as (`plugin:<name>`).
        set_by: String,
    },
}

/// The combined result of running one event through every plugin.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Block or allow. The first blocking plugin short-circuits.
    pub verdict: Verdict,
    /// Replacement text (message hooks only): the event proceeds with this
    /// text instead of the original. Already sanitized.
    pub replacement: Option<String>,
    /// Custom reason for the FAIL reply when blocked. Already sanitized.
    pub reason: Option<String>,
    /// Actions queued by plugins during this event, in call order.
    pub actions: Vec<Action>,
}

/// An active ability a plugin may be granted in the server config
/// (`[plugins.grants]`). Deny-by-default: no grant, no effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// May queue server NOTICEs via `ferrix.send_notice`.
    SendNotice,
    /// May queue server PRIVMSGs via `ferrix.send_message`.
    SendMessage,
    /// May remove users from channels via `ferrix.kick`.
    Kick,
    /// May change channel modes via `ferrix.set_mode`.
    Mode,
    /// May change channel topics via `ferrix.set_topic`.
    Topic,
    /// May ban hostmasks via `ferrix.kline`.
    Kline,
}

/// Grant table: the config spelling of every capability, in doc order.
const CAPABILITIES: &[(Capability, &str)] = &[
    (Capability::SendNotice, "send_notice"),
    (Capability::SendMessage, "send_message"),
    (Capability::Kick, "kick"),
    (Capability::Mode, "mode"),
    (Capability::Topic, "topic"),
    (Capability::Kline, "kline"),
];

impl Capability {
    fn parse(s: &str) -> Option<Self> {
        CAPABILITIES
            .iter()
            .find(|(_, name)| *name == s)
            .map(|&(cap, _)| cap)
    }

    fn name(self) -> &'static str {
        CAPABILITIES
            .iter()
            .find(|&&(cap, _)| cap == self)
            .map_or("unknown", |&(_, name)| name)
    }
}

/// A read-only view of the server the query host functions consult. The
/// server implements this; plugins can never mutate through it.
pub trait WorldView: Send + Sync {
    /// Nicks of every member of `channel` (local and remote), or `None` if
    /// the channel does not exist.
    fn channel_members(&self, channel: &str) -> Option<Vec<String>>;
    /// A JSON object describing a locally connected user, or `None` if the
    /// nick is unknown.
    fn user_info_json(&self, nick: &str) -> Option<String>;
    /// A JSON object describing this server and network (never fails: the
    /// server always knows itself).
    fn server_info_json(&self) -> String;
    /// A JSON object describing a channel (topic, modes, counts), or `None`
    /// if it does not exist.
    fn channel_info_json(&self, channel: &str) -> Option<String>;
    /// Display names of the channels a locally connected user is in, or
    /// `None` if the nick is unknown.
    fn user_channels(&self, nick: &str) -> Option<Vec<String>>;
}

/// Late-bound world reference: instances are created before the server exists,
/// so they share one slot that the startup code fills in.
type WorldSlot = OnceLock<Weak<dyn WorldView>>;

/// Every hook a plugin can export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Hook {
    Message,
    MessageV2,
    Join,
    Nick,
    Topic,
    Part,
    Kick,
    Mode,
    Invite,
    PrivateMessage,
    Connect,
    Quit,
    Away,
    Account,
    Timer,
    Load,
}

/// Export-name table; also drives hook discovery at load time.
const HOOK_EXPORTS: &[(Hook, &str)] = &[
    (Hook::Message, "ferrix_on_message"),
    (Hook::MessageV2, "ferrix_on_message_v2"),
    (Hook::Join, "ferrix_on_join"),
    (Hook::Nick, "ferrix_on_nick"),
    (Hook::Topic, "ferrix_on_topic"),
    (Hook::Part, "ferrix_on_part"),
    (Hook::Kick, "ferrix_on_kick"),
    (Hook::Mode, "ferrix_on_mode"),
    (Hook::Invite, "ferrix_on_invite"),
    (Hook::PrivateMessage, "ferrix_on_private_message"),
    (Hook::Connect, "ferrix_on_connect"),
    (Hook::Quit, "ferrix_on_quit"),
    (Hook::Away, "ferrix_on_away"),
    (Hook::Account, "ferrix_on_account"),
    (Hook::Timer, "ferrix_on_timer"),
    (Hook::Load, "ferrix_on_load"),
];

/// Per-hook-call scratch space host functions write into; harvested (and
/// reset) by the host after each call.
#[derive(Debug, Default)]
struct CallScratch {
    /// Whether `ferrix.set_text` is honoured for the current hook.
    allow_replace: bool,
    replacement: Option<String>,
    reason: Option<String>,
    actions: Vec<Action>,
}

/// The plugin's bounded key-value store (its only persistence channel).
#[derive(Debug, Default)]
struct KvStore {
    map: HashMap<String, Vec<u8>>,
    /// Sum of key + value byte lengths, kept in lockstep with `map`.
    total: usize,
    /// Backing file (host-managed), if the operator configured a state dir.
    path: Option<PathBuf>,
    dirty: bool,
    last_flush_ms: u64,
}

impl KvStore {
    /// Insert/replace/delete (empty value = delete). Returns `false` when a
    /// bound would be exceeded.
    fn set(&mut self, key: &str, value: &[u8]) -> bool {
        if key.is_empty() || key.len() > MAX_KV_KEY_BYTES || value.len() > MAX_KV_VALUE_BYTES {
            return false;
        }
        if value.is_empty() {
            if let Some(old) = self.map.remove(key) {
                self.total = self.total.saturating_sub(key.len() + old.len());
                self.dirty = true;
            }
            return true;
        }
        let old_len = self.map.get(key).map_or(0, Vec::len);
        let new_total = self
            .total
            .saturating_sub(old_len)
            .saturating_add(value.len())
            .saturating_add(if old_len == 0 { key.len() } else { 0 });
        if new_total > MAX_KV_TOTAL_BYTES {
            return false;
        }
        if old_len == 0 && self.map.len() >= MAX_KV_KEYS {
            return false;
        }
        self.map.insert(key.to_owned(), value.to_vec());
        self.total = new_total;
        self.dirty = true;
        true
    }

    /// Load the backing file (one `base64(key) base64(value)` pair per line).
    /// Entries that violate the bounds are skipped, so a tampered or
    /// downgraded file cannot overshoot the limits.
    fn load(&mut self) {
        let Some(path) = &self.path else { return };
        let Ok(contents) = std::fs::read_to_string(path) else {
            return; // no state yet, or unreadable — start empty either way
        };
        for line in contents.lines() {
            let Some((k64, v64)) = line.split_once(' ') else {
                continue;
            };
            let (Ok(key), Ok(value)) = (BASE64.decode(k64), BASE64.decode(v64)) else {
                continue;
            };
            let Ok(key) = String::from_utf8(key) else {
                continue;
            };
            let _ = self.set(&key, &value);
        }
        self.dirty = false;
    }

    /// Write the store to its backing file if dirty and the flush interval has
    /// elapsed (called after hook calls, off the wasm execution path).
    fn flush_if_due(&mut self, plugin: &str) {
        // Cheap gates first: the common case is a clean store on the per-message
        // hot path, so bail before cloning the path or reading the clock.
        if !self.dirty {
            return;
        }
        let Some(path) = self.path.as_ref() else {
            return;
        };
        let now = wall_ms();
        if now.saturating_sub(self.last_flush_ms) < KV_FLUSH_INTERVAL_MS {
            return;
        }
        let mut out = String::with_capacity(self.total * 2);
        for (key, value) in &self.map {
            out.push_str(&BASE64.encode(key.as_bytes()));
            out.push(' ');
            out.push_str(&BASE64.encode(value));
            out.push('\n');
        }
        // Write to a sibling temp file and rename into place, so a crash mid-
        // write can never truncate the live store (rename is atomic on the same
        // filesystem). A failed write leaves the previous state intact.
        let tmp = path.with_extension("kv.tmp");
        let result = std::fs::write(&tmp, &out).and_then(|()| std::fs::rename(&tmp, path));
        match result {
            Ok(()) => {
                self.dirty = false;
                self.last_flush_ms = now;
            }
            Err(err) => {
                let _ = std::fs::remove_file(&tmp);
                warn!(plugin, %err, "failed to persist plugin KV store");
            }
        }
    }
}

/// State threaded through a plugin's `Store`, available to host functions.
#[derive(Debug)]
struct HostState {
    name: String,
    /// Capabilities granted to this plugin in the server config.
    caps: Vec<Capability>,
    /// Late-bound read-only server view for the query host functions.
    world: Arc<WorldSlot>,
    /// Operator-supplied settings for this plugin (`[plugins.config.<name>]`),
    /// readable through `ferrix.config_get`.
    config: HashMap<String, String>,
    kv: KvStore,
    /// Linear-memory cap, consulted by wasmi on every `memory.grow`.
    limits: StoreLimits,
    /// Rolling-minute action rate limiting.
    window_start_ms: u64,
    window_actions: u32,
    /// Per-hook-call scratch (reset before, harvested after each call).
    call: CallScratch,
}

impl HostState {
    fn has_cap(&self, cap: Capability) -> bool {
        self.caps.contains(&cap)
    }

    /// Gate an active host function on its grant, logging the refusal once per
    /// call site so an operator can see which grant a plugin is missing.
    fn require_cap(&self, cap: Capability, func: &str) -> bool {
        if self.has_cap(cap) {
            return true;
        }
        warn!(
            plugin = %self.name,
            capability = cap.name(),
            "ferrix.{func} without the required grant"
        );
        false
    }

    /// Account one action against the per-call budget and the rolling-minute
    /// window; `false` means the action must be refused.
    fn take_action_slot(&mut self) -> bool {
        if self.call.actions.len() >= MAX_ACTIONS_PER_CALL {
            return false;
        }
        let now = wall_ms();
        if now.saturating_sub(self.window_start_ms) >= 60_000 {
            self.window_start_ms = now;
            self.window_actions = 0;
        }
        if self.window_actions >= MAX_ACTIONS_PER_MINUTE {
            return false;
        }
        self.window_actions += 1;
        true
    }
}

/// One loaded plugin instance (single-threaded; guarded by a `Mutex`).
struct PluginInstance {
    name: String,
    store: Store<HostState>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    hooks: HashMap<Hook, TypedFunc<(i32, i32), i32>>,
    // Simple observability counters (see [`PluginHost::stats`]).
    calls: u64,
    blocks: u64,
    traps: u64,
}

impl std::fmt::Debug for PluginInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginInstance")
            .field("name", &self.name)
            .field("hooks", &self.hooks.keys().collect::<Vec<_>>())
            .field("calls", &self.calls)
            .field("blocks", &self.blocks)
            .field("traps", &self.traps)
            .finish()
    }
}

/// Per-plugin counters for observability (`stats()`), monotonically increasing
/// since load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginStats {
    /// The plugin's name (file stem).
    pub name: String,
    /// Hook invocations (only hooks the plugin actually exports).
    pub calls: u64,
    /// Events this plugin blocked.
    pub blocks: u64,
    /// Traps / fuel exhaustions (each one failed open).
    pub traps: u64,
}

/// Append `s` to `out` as a JSON string literal (with escaping).
pub(crate) fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Append an optional string as a JSON value: the string literal, or `null`.
pub(crate) fn push_json_optional(out: &mut String, value: Option<&str>) {
    match value {
        Some(value) => push_json_string(out, value),
        None => out.push_str("null"),
    }
}

/// Build a flat JSON object from string fields.
fn json_event(fields: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(fields.iter().map(|(k, v)| k.len() + v.len() + 6).sum());
    out.push('{');
    for (i, (key, value)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_json_string(&mut out, key);
        out.push(':');
        push_json_string(&mut out, value);
    }
    out.push('}');
    out
}

/// Strip line breaks and NULs (IRC frame injection) and cap the byte length on
/// a char boundary. When `strip_ctl` is set, all other control characters go
/// too (for text that must be plain, like FAIL reasons).
fn sanitize_text(input: &str, max_bytes: usize, strip_ctl: bool) -> String {
    let mut out = String::with_capacity(input.len().min(max_bytes));
    for c in input.chars() {
        if matches!(c, '\r' | '\n' | '\0') {
            continue;
        }
        if strip_ctl && (c as u32) < 0x20 {
            continue;
        }
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    out
}

/// Whether a plugin-supplied action target (nick or channel) is safe to route.
fn valid_target(target: &str) -> bool {
    !target.is_empty()
        && target.len() <= MAX_TARGET_BYTES
        && !target
            .chars()
            .any(|c| c.is_whitespace() || (c as u32) < 0x21 || matches!(c, ',' | '*' | '?' | '!'))
}

/// Whether a plugin-supplied ban mask is safe to install as a K-Line. Masks
/// legitimately contain `!`, `@`, `*` and — for extended account bans like
/// `~a:name` — an embedded colon, so only framing hazards are checked: no
/// whitespace, no control characters, and no *leading* colon (which would turn
/// the mask into a trailing parameter wherever it is echoed).
fn valid_mask(mask: &str) -> bool {
    !mask.is_empty()
        && mask.len() <= MAX_MASK_BYTES
        && !mask.starts_with(':')
        && !mask.chars().any(|c| c.is_whitespace() || (c as u32) < 0x21)
}

/// Split a plugin-supplied mode string into flags plus arguments, rejecting
/// anything that is not a plain `[+-]<letters>` sequence with simple word
/// arguments. Returns `None` when the string is unusable.
fn parse_mode_string(raw: &str) -> Option<(String, Vec<String>)> {
    let mut words = raw.split_whitespace();
    let flags = words.next()?;
    if flags.len() > MAX_MODE_BYTES
        || !flags
            .chars()
            .all(|c| c == '+' || c == '-' || c.is_ascii_alphabetic())
        || !flags.chars().any(|c| c.is_ascii_alphabetic())
    {
        return None;
    }
    let mut args = Vec::new();
    for word in words {
        if args.len() >= MAX_MODE_ARGS {
            return None; // rather refuse than silently apply a truncated change
        }
        // A leading colon would smuggle a trailing parameter into the MODE
        // line; embedded ones are legitimate (`+b ~a:account`).
        if word.len() > MAX_TARGET_BYTES || word.starts_with(':') {
            return None;
        }
        args.push(word.to_owned());
    }
    Some((flags.to_owned(), args))
}

/// A registry of loaded WebAssembly plugins.
#[derive(Debug)]
pub struct PluginHost {
    engine: Engine,
    fuel: u64,
    max_memory: usize,
    expose_private_messages: bool,
    grants: HashMap<String, Vec<Capability>>,
    plugin_config: HashMap<String, HashMap<String, String>>,
    state_dir: Option<PathBuf>,
    world: Arc<WorldSlot>,
    plugins: Vec<Mutex<PluginInstance>>,
}

impl PluginHost {
    /// Create an empty host with the given per-call fuel budget.
    #[must_use]
    pub fn new(fuel: u64) -> Self {
        let mut config = Config::default();
        config.consume_fuel(true);
        PluginHost {
            engine: Engine::new(&config),
            fuel,
            max_memory: DEFAULT_MAX_MEMORY,
            expose_private_messages: false,
            grants: HashMap::new(),
            plugin_config: HashMap::new(),
            state_dir: None,
            world: Arc::new(OnceLock::new()),
            plugins: Vec::new(),
        }
    }

    /// Cap each plugin instance's linear memory (bytes). Applies to plugins
    /// loaded after this call.
    pub fn set_max_memory(&mut self, bytes: usize) {
        self.max_memory = bytes.max(64 * 1024);
    }

    /// Feed private messages (user-to-user PRIVMSG/NOTICE) to the
    /// `ferrix_on_private_message` hook. Off by default: this is a privacy
    /// decision the operator makes, not the plugin author.
    pub fn set_expose_private_messages(&mut self, expose: bool) {
        self.expose_private_messages = expose;
    }

    /// Whether private messages are fed to plugins.
    #[must_use]
    pub fn private_messages_exposed(&self) -> bool {
        self.expose_private_messages
    }

    /// Set the capability grants (plugin name → capability names) from the
    /// server config. Unknown capability names are logged and ignored.
    /// Applies to plugins loaded after this call.
    pub fn set_grants(&mut self, grants: &HashMap<String, Vec<String>>) {
        for (plugin, caps) in grants {
            let mut parsed = Vec::new();
            for cap in caps {
                match Capability::parse(cap) {
                    Some(c) if !parsed.contains(&c) => parsed.push(c),
                    Some(_) => {}
                    None => warn!(plugin, capability = %cap, "unknown plugin capability in grants"),
                }
            }
            self.grants.insert(plugin.clone(), parsed);
        }
    }

    /// Set the per-plugin operator settings (`[plugins.config.<name>]`),
    /// readable by a plugin through `ferrix.config_get`. Applies to plugins
    /// loaded after this call.
    pub fn set_plugin_config(&mut self, config: &HashMap<String, HashMap<String, String>>) {
        for (plugin, settings) in config {
            self.plugin_config.insert(plugin.clone(), settings.clone());
        }
    }

    /// Directory for host-managed per-plugin state files (the KV store's
    /// persistence). No dir → KV state is in-memory only.
    pub fn set_state_dir(&mut self, dir: PathBuf) {
        self.state_dir = Some(dir);
    }

    /// Attach the read-only server view for the query host functions. Called
    /// once at startup, after the server exists.
    pub fn set_world(&self, world: Weak<dyn WorldView>) {
        let _ = self.world.set(world);
    }

    /// Number of loaded plugins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether no plugins are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Per-plugin observability counters, in load order.
    #[must_use]
    pub fn stats(&self) -> Vec<PluginStats> {
        self.plugins
            .iter()
            .map(|plugin| {
                let plugin = plugin.lock();
                PluginStats {
                    name: plugin.name.clone(),
                    calls: plugin.calls,
                    blocks: plugin.blocks,
                    traps: plugin.traps,
                }
            })
            .collect()
    }

    /// Load every `*.wasm` file in `dir` (sorted for determinism).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read. Individual plugins that
    /// fail to load are logged and skipped.
    pub fn load_dir(&mut self, dir: &Path) -> Result<usize> {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("reading plugin directory {}", dir.display()))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "wasm"))
            .collect();
        files.sort();

        let mut loaded = 0;
        for path in files {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("plugin")
                .to_owned();
            match std::fs::read(&path) {
                Ok(bytes) => match self.load_bytes(&name, &bytes) {
                    Ok(()) => {
                        loaded += 1;
                        info!(plugin = %name, "loaded WASM plugin");
                    }
                    Err(err) => warn!(plugin = %name, %err, "failed to load plugin"),
                },
                Err(err) => warn!(path = %path.display(), %err, "failed to read plugin"),
            }
        }
        Ok(loaded)
    }

    /// Compile and instantiate a single plugin from WASM bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the module is invalid or lacks the required exports.
    pub fn load_bytes(&mut self, name: &str, wasm: &[u8]) -> Result<()> {
        let module = Module::new(&self.engine, wasm).context("compiling module")?;
        let caps = self.grants.get(name).cloned().unwrap_or_default();
        let mut kv = KvStore {
            path: self
                .state_dir
                .as_ref()
                .map(|dir| dir.join(format!("{name}.kv"))),
            ..KvStore::default()
        };
        kv.load();
        let mut store = Store::new(
            &self.engine,
            HostState {
                name: name.to_owned(),
                caps: caps.clone(),
                world: Arc::clone(&self.world),
                config: self.plugin_config.get(name).cloned().unwrap_or_default(),
                kv,
                limits: StoreLimitsBuilder::new()
                    .memory_size(self.max_memory)
                    .build(),
                window_start_ms: wall_ms(),
                window_actions: 0,
                call: CallScratch::default(),
            },
        );
        store.limiter(|state: &mut HostState| &mut state.limits as &mut dyn ResourceLimiter);
        store.set_fuel(self.fuel).context("setting initial fuel")?;

        let mut linker = Linker::new(&self.engine);
        register_host_api(&mut linker).context("registering host API")?;

        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .context("instantiating module")?;

        let memory = instance
            .get_memory(&store, "memory")
            .context("plugin must export its memory as `memory`")?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&store, "alloc")
            .context("plugin must export `alloc(i32) -> i32`")?;
        let mut hooks = HashMap::new();
        for &(hook, export) in HOOK_EXPORTS {
            if let Ok(func) = instance.get_typed_func::<(i32, i32), i32>(&store, export) {
                hooks.insert(hook, func);
            }
        }

        let mut plugin = PluginInstance {
            name: name.to_owned(),
            store,
            memory,
            alloc,
            hooks,
            calls: 0,
            blocks: 0,
            traps: 0,
        };

        // Lifecycle hook: tell the plugin what it was granted. Return value
        // and any queued state changes apply; actions are discarded (there is
        // no event to act on yet).
        if plugin.hooks.contains_key(&Hook::Load) {
            let mut granted = String::from("{\"api\":");
            granted.push_str(&ABI_VERSION.to_string());
            granted.push_str(",\"plugin\":");
            push_json_string(&mut granted, name);
            granted.push_str(",\"granted\":[");
            for (i, cap) in caps.iter().enumerate() {
                if i > 0 {
                    granted.push(',');
                }
                push_json_string(&mut granted, cap.name());
            }
            granted.push_str("]}");
            let _ = plugin.call(Hook::Load, &granted, self.fuel, false);
        }

        self.plugins.push(Mutex::new(plugin));
        Ok(())
    }

    /// Run one veto-style hook over every plugin: first block short-circuits;
    /// actions accumulate across plugins.
    fn run_veto(&self, hook: Hook, event: &str) -> Outcome {
        let mut out = Outcome::default();
        for plugin in &self.plugins {
            let mut plugin = plugin.lock();
            let (verdict, scratch) = plugin.call(hook, event, self.fuel, false);
            out.actions.extend(scratch.actions);
            if verdict == Verdict::Block {
                out.verdict = Verdict::Block;
                out.reason = scratch.reason;
                break;
            }
        }
        out
    }

    /// Run one observe-only hook: return values are ignored (the event has
    /// already happened), actions still accumulate.
    fn run_observe(&self, hook: Hook, event: &str) -> Outcome {
        let mut out = Outcome::default();
        for plugin in &self.plugins {
            let mut plugin = plugin.lock();
            let (_, scratch) = plugin.call(hook, event, self.fuel, false);
            out.actions.extend(scratch.actions);
        }
        out
    }

    /// The message pipeline: every plugin sees the text as rewritten by the
    /// plugins before it; the first block short-circuits.
    fn run_message(&self, hook: Hook, source: &str, target: &str, text: &str) -> Outcome {
        let mut out = Outcome::default();
        for plugin in &self.plugins {
            let current = out.replacement.as_deref().unwrap_or(text);
            let mut plugin = plugin.lock();
            let (verdict, scratch) = match hook {
                // Channel messages: prefer the v2 JSON hook, fall back to the
                // v1 raw-text hook for old plugins.
                Hook::MessageV2 => {
                    if plugin.hooks.contains_key(&Hook::MessageV2) {
                        let event = json_event(&[
                            ("source", source),
                            ("target", target),
                            ("text", current),
                        ]);
                        plugin.call(Hook::MessageV2, &event, self.fuel, true)
                    } else {
                        plugin.call(Hook::Message, current, self.fuel, true)
                    }
                }
                Hook::PrivateMessage => {
                    let event =
                        json_event(&[("source", source), ("target", target), ("text", current)]);
                    plugin.call(Hook::PrivateMessage, &event, self.fuel, true)
                }
                // The public v1-only entry point (raw text, no context).
                _ => plugin.call(hook, current, self.fuel, true),
            };
            out.actions.extend(scratch.actions);
            if let Some(replacement) = scratch.replacement {
                out.replacement = Some(replacement);
            }
            if verdict == Verdict::Block {
                out.verdict = Verdict::Block;
                out.reason = scratch.reason;
                break;
            }
        }
        out
    }

    /// Run the `on_message` hook of every plugin on the message `text` (v1,
    /// text-only). A plugin that traps or exhausts fuel is treated as allowed
    /// (fail-open) so it cannot wedge delivery.
    #[must_use]
    pub fn on_message(&self, text: &str) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        self.run_message(Hook::Message, "", "", text)
    }

    /// Run the message hooks of every plugin on a channel message with full
    /// context. A plugin exporting the v2 hook gets the JSON event; otherwise
    /// its v1 hook (raw text) is called. Plugins may rewrite the text via
    /// `ferrix.set_text`; later plugins see the rewritten text.
    #[must_use]
    pub fn on_channel_message(&self, source: &str, target: &str, text: &str) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        self.run_message(Hook::MessageV2, source, target, text)
    }

    /// Run the `on_private_message` hook on a user-to-user message. Does
    /// nothing unless the operator enabled `expose_private_messages`.
    #[must_use]
    pub fn on_private_message(&self, source: &str, target: &str, text: &str) -> Outcome {
        if self.plugins.is_empty() || !self.expose_private_messages {
            return Outcome::default();
        }
        self.run_message(Hook::PrivateMessage, source, target, text)
    }

    /// Run the `on_join` hook of every plugin. A block rejects the join.
    #[must_use]
    pub fn on_join(&self, nick: &str, channel: &str) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        self.run_veto(
            Hook::Join,
            &json_event(&[("nick", nick), ("channel", channel)]),
        )
    }

    /// Run the `on_nick` hook of every plugin. A block rejects the nick change.
    #[must_use]
    pub fn on_nick(&self, old: &str, new: &str) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        self.run_veto(Hook::Nick, &json_event(&[("old", old), ("new", new)]))
    }

    /// Run the `on_topic` hook of every plugin. A block rejects the topic change.
    #[must_use]
    pub fn on_topic(&self, nick: &str, channel: &str, topic: &str) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        self.run_veto(
            Hook::Topic,
            &json_event(&[("nick", nick), ("channel", channel), ("topic", topic)]),
        )
    }

    /// Run the `on_part` hook of every plugin. A block keeps the user in the
    /// channel.
    #[must_use]
    pub fn on_part(&self, nick: &str, channel: &str, reason: &str) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        self.run_veto(
            Hook::Part,
            &json_event(&[("nick", nick), ("channel", channel), ("reason", reason)]),
        )
    }

    /// Run the `on_kick` hook of every plugin. A block cancels the kick.
    #[must_use]
    pub fn on_kick(&self, nick: &str, channel: &str, target: &str, reason: &str) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        self.run_veto(
            Hook::Kick,
            &json_event(&[
                ("nick", nick),
                ("channel", channel),
                ("target", target),
                ("reason", reason),
            ]),
        )
    }

    /// Run the `on_mode` hook of every plugin on a channel mode change (the
    /// raw mode string with arguments). A block cancels the whole change.
    #[must_use]
    pub fn on_mode(&self, nick: &str, channel: &str, modes: &str) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        self.run_veto(
            Hook::Mode,
            &json_event(&[("nick", nick), ("channel", channel), ("modes", modes)]),
        )
    }

    /// Run the `on_invite` hook of every plugin. A block cancels the invite.
    #[must_use]
    pub fn on_invite(&self, nick: &str, channel: &str, target: &str) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        self.run_veto(
            Hook::Invite,
            &json_event(&[("nick", nick), ("channel", channel), ("target", target)]),
        )
    }

    /// Observe-only: a client finished registration. Return values are ignored.
    #[must_use]
    pub fn on_connect(&self, nick: &str, user: &str, host: &str, account: Option<&str>) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        let mut event = String::from("{\"nick\":");
        push_json_string(&mut event, nick);
        event.push_str(",\"user\":");
        push_json_string(&mut event, user);
        event.push_str(",\"host\":");
        push_json_string(&mut event, host);
        event.push_str(",\"account\":");
        push_json_optional(&mut event, account);
        event.push('}');
        self.run_observe(Hook::Connect, &event)
    }

    /// Observe-only: a registered client disconnected (QUIT, drop, kill).
    /// Return values are ignored.
    #[must_use]
    pub fn on_quit(&self, nick: &str, reason: &str) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        self.run_observe(
            Hook::Quit,
            &json_event(&[("nick", nick), ("reason", reason)]),
        )
    }

    /// Observe-only: a client's away state changed (`None` = back).
    #[must_use]
    pub fn on_away(&self, nick: &str, message: Option<&str>) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        let mut event = String::from("{\"nick\":");
        push_json_string(&mut event, nick);
        event.push_str(",\"message\":");
        push_json_optional(&mut event, message);
        event.push('}');
        self.run_observe(Hook::Away, &event)
    }

    /// Observe-only: a client logged in or out of an account (`None` = out).
    #[must_use]
    pub fn on_account(&self, nick: &str, account: Option<&str>) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        let mut event = String::from("{\"nick\":");
        push_json_string(&mut event, nick);
        event.push_str(",\"account\":");
        push_json_optional(&mut event, account);
        event.push('}');
        self.run_observe(Hook::Account, &event)
    }

    /// Observe-only: the periodic tick (`[plugins].tick_secs`). `tick` counts
    /// from 1 and lets a plugin sub-divide the interval without its own clock.
    #[must_use]
    pub fn on_timer(&self, tick: u64) -> Outcome {
        if self.plugins.is_empty() {
            return Outcome::default();
        }
        let event = format!("{{\"tick\":{tick},\"now_ms\":{}}}", wall_ms());
        self.run_observe(Hook::Timer, &event)
    }

    /// Whether any loaded plugin exports the timer hook (so the server can
    /// skip spawning the ticker entirely).
    #[must_use]
    pub fn wants_timer(&self) -> bool {
        self.plugins
            .iter()
            .any(|plugin| plugin.lock().hooks.contains_key(&Hook::Timer))
    }
}

impl PluginInstance {
    /// Call one hook with a UTF-8 payload, fail-open on any fault. Returns the
    /// verdict plus the scratch (replacement/reason/actions) the plugin's host
    /// calls produced; a trapped call discards its scratch.
    fn call(
        &mut self,
        hook: Hook,
        text: &str,
        fuel: u64,
        allow_replace: bool,
    ) -> (Verdict, CallScratch) {
        let Some(&func) = self.hooks.get(&hook) else {
            return (Verdict::Allow, CallScratch::default());
        };
        self.calls += 1;
        self.store.data_mut().call = CallScratch {
            allow_replace,
            ..CallScratch::default()
        };
        // Refuel for this call; a bad plugin cannot borrow against the next one.
        if self.store.set_fuel(fuel).is_err() {
            return (Verdict::Allow, CallScratch::default());
        }
        let bytes = text.as_bytes();
        let Ok(len) = i32::try_from(bytes.len()) else {
            return (Verdict::Allow, CallScratch::default());
        };
        let ptr = match self.alloc.call(&mut self.store, len) {
            Ok(ptr) => ptr,
            Err(err) => {
                warn!(plugin = %self.name, %err, "plugin alloc failed");
                self.traps += 1;
                return (Verdict::Allow, CallScratch::default());
            }
        };
        if let Err(err) = self.memory.write(&mut self.store, ptr as usize, bytes) {
            warn!(plugin = %self.name, %err, "writing event to plugin memory failed");
            return (Verdict::Allow, CallScratch::default());
        }
        let result = match func.call(&mut self.store, (ptr, len)) {
            Ok(0) => Verdict::Allow,
            Ok(_) => {
                self.blocks += 1;
                Verdict::Block
            }
            Err(err) => {
                warn!(plugin = %self.name, %err, "plugin trapped; allowing event");
                self.traps += 1;
                // A trapped call's queued output is dropped: the hook is
                // treated as if it never ran (fail-open, no side effects).
                self.store.data_mut().call = CallScratch::default();
                Verdict::Allow
            }
        };
        let scratch = std::mem::take(&mut self.store.data_mut().call);
        // Persist KV changes opportunistically, off the wasm execution path.
        let state = self.store.data_mut();
        let name = state.name.clone();
        state.kv.flush_if_due(&name);
        (result, scratch)
    }
}

/// Read a bounded UTF-8 string out of the calling plugin's memory. Lossy on
/// invalid UTF-8, `None` only when memory itself is unreadable.
fn read_plugin_string(
    caller: &Caller<'_, HostState>,
    ptr: i32,
    len: i32,
    max: usize,
) -> Option<String> {
    let Some(Extern::Memory(memory)) = caller.get_export("memory") else {
        return None;
    };
    let len = (len.max(0) as usize).min(max);
    let mut buf = vec![0u8; len];
    memory.read(caller, ptr.max(0) as usize, &mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Read bounded raw bytes out of the calling plugin's memory.
fn read_plugin_bytes(
    caller: &Caller<'_, HostState>,
    ptr: i32,
    len: i32,
    max: usize,
) -> Option<Vec<u8>> {
    let Some(Extern::Memory(memory)) = caller.get_export("memory") else {
        return None;
    };
    let len = (len.max(0) as usize).min(max);
    let mut buf = vec![0u8; len];
    memory.read(caller, ptr.max(0) as usize, &mut buf).ok()?;
    Some(buf)
}

/// Write `bytes` into plugin memory at `ptr` when `cap` suffices. Returns the
/// needed length either way (the "call again with a bigger buffer" contract),
/// or -1 when memory is unwritable.
fn write_plugin_bytes(caller: &mut Caller<'_, HostState>, ptr: i32, cap: i32, bytes: &[u8]) -> i32 {
    let Ok(needed) = i32::try_from(bytes.len()) else {
        return -1;
    };
    if needed > cap.max(0) {
        return needed;
    }
    let Some(Extern::Memory(memory)) = caller.get_export("memory") else {
        return -1;
    };
    if memory.write(caller, ptr.max(0) as usize, bytes).is_err() {
        return -1;
    }
    needed
}

/// Register the host functions available to every plugin (import module
/// `ferrix`). This is a plugin's complete ambient authority.
fn register_host_api(linker: &mut Linker<HostState>) -> Result<()> {
    // log(ptr, len): log a UTF-8 string at info level (truncated to 4 KiB).
    linker
        .func_wrap(
            "ferrix",
            "log",
            |caller: Caller<'_, HostState>, ptr: i32, len: i32| {
                if let Some(text) = read_plugin_string(&caller, ptr, len, 4096) {
                    info!(plugin = %caller.data().name, "plugin log: {text}");
                }
            },
        )
        .context("host function ferrix.log")?;

    // set_text(ptr, len): replace the current message's text (message hooks
    // only). Sanitized: no CR/LF/NUL, capped well under the line limit.
    linker
        .func_wrap(
            "ferrix",
            "set_text",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
                let Some(text) = read_plugin_string(&caller, ptr, len, 4096) else {
                    return;
                };
                let state = caller.data_mut();
                if !state.call.allow_replace {
                    warn!(plugin = %state.name, "ferrix.set_text outside a message hook ignored");
                    return;
                }
                let text = sanitize_text(&text, MAX_TEXT_BYTES, false);
                if !text.is_empty() {
                    state.call.replacement = Some(text);
                }
            },
        )
        .context("host function ferrix.set_text")?;

    // set_reason(ptr, len): custom reason for the FAIL reply when this hook
    // call blocks the event.
    linker
        .func_wrap(
            "ferrix",
            "set_reason",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
                let Some(text) = read_plugin_string(&caller, ptr, len, 1024) else {
                    return;
                };
                let reason = sanitize_text(&text, MAX_REASON_BYTES, true);
                if !reason.is_empty() {
                    caller.data_mut().call.reason = Some(reason);
                }
            },
        )
        .context("host function ferrix.set_reason")?;

    // send_notice(tptr, tlen, ptr, len) -> i32: queue a server NOTICE to a
    // nick or channel. 0 = queued; 1 = refused (no grant, bad target, or
    // budget/rate limit exhausted). Requires the `send_notice` capability.
    linker
        .func_wrap(
            "ferrix",
            "send_notice",
            |mut caller: Caller<'_, HostState>, tptr: i32, tlen: i32, ptr: i32, len: i32| -> i32 {
                let Some(target) = read_plugin_string(&caller, tptr, tlen, 512) else {
                    return 1;
                };
                let Some(text) = read_plugin_string(&caller, ptr, len, 4096) else {
                    return 1;
                };
                let state = caller.data_mut();
                if !state.require_cap(Capability::SendNotice, "send_notice") {
                    return 1;
                }
                if !valid_target(&target) {
                    return 1;
                }
                let text = sanitize_text(&text, MAX_TEXT_BYTES, false);
                if text.is_empty() || !state.take_action_slot() {
                    return 1;
                }
                state.call.actions.push(Action::Notice { target, text });
                0
            },
        )
        .context("host function ferrix.send_notice")?;

    // send_message(tptr, tlen, ptr, len) -> i32: queue a server PRIVMSG to a
    // nick or channel. Same contract and budget as send_notice; requires the
    // `send_message` capability.
    linker
        .func_wrap(
            "ferrix",
            "send_message",
            |mut caller: Caller<'_, HostState>, tptr: i32, tlen: i32, ptr: i32, len: i32| -> i32 {
                let Some(target) = read_plugin_string(&caller, tptr, tlen, 512) else {
                    return 1;
                };
                let Some(text) = read_plugin_string(&caller, ptr, len, 4096) else {
                    return 1;
                };
                let state = caller.data_mut();
                if !state.require_cap(Capability::SendMessage, "send_message") {
                    return 1;
                }
                if !valid_target(&target) {
                    return 1;
                }
                let text = sanitize_text(&text, MAX_TEXT_BYTES, false);
                if text.is_empty() || !state.take_action_slot() {
                    return 1;
                }
                state.call.actions.push(Action::Message { target, text });
                0
            },
        )
        .context("host function ferrix.send_message")?;

    // kick(cptr, clen, nptr, nlen, rptr, rlen) -> i32: queue a server KICK.
    // Requires the `kick` capability. 0 = queued, 1 = refused.
    linker
        .func_wrap(
            "ferrix",
            "kick",
            |mut caller: Caller<'_, HostState>,
             cptr: i32,
             clen: i32,
             nptr: i32,
             nlen: i32,
             rptr: i32,
             rlen: i32|
             -> i32 {
                let Some(channel) = read_plugin_string(&caller, cptr, clen, 512) else {
                    return 1;
                };
                let Some(nick) = read_plugin_string(&caller, nptr, nlen, 512) else {
                    return 1;
                };
                let reason = read_plugin_string(&caller, rptr, rlen, 1024).unwrap_or_default();
                let state = caller.data_mut();
                if !state.require_cap(Capability::Kick, "kick") {
                    return 1;
                }
                if !valid_target(&channel) || !channel.starts_with('#') || !valid_target(&nick) {
                    return 1;
                }
                let reason = sanitize_text(&reason, MAX_REASON_BYTES, true);
                if !state.take_action_slot() {
                    return 1;
                }
                let reason = if reason.is_empty() {
                    format!("Kicked by {}", state.name)
                } else {
                    reason
                };
                state.call.actions.push(Action::Kick {
                    channel,
                    nick,
                    reason,
                });
                0
            },
        )
        .context("host function ferrix.kick")?;

    // set_mode(cptr, clen, mptr, mlen) -> i32: queue a server-applied channel
    // mode change (`"+b nick!*@*"`). Requires the `mode` capability.
    linker
        .func_wrap(
            "ferrix",
            "set_mode",
            |mut caller: Caller<'_, HostState>,
             cptr: i32,
             clen: i32,
             mptr: i32,
             mlen: i32|
             -> i32 {
                let Some(channel) = read_plugin_string(&caller, cptr, clen, 512) else {
                    return 1;
                };
                let Some(modes) = read_plugin_string(&caller, mptr, mlen, 1024) else {
                    return 1;
                };
                let state = caller.data_mut();
                if !state.require_cap(Capability::Mode, "set_mode") {
                    return 1;
                }
                if !valid_target(&channel) || !channel.starts_with('#') {
                    return 1;
                }
                let Some((flags, args)) = parse_mode_string(&modes) else {
                    return 1;
                };
                if !state.take_action_slot() {
                    return 1;
                }
                state.call.actions.push(Action::Mode {
                    channel,
                    flags,
                    args,
                });
                0
            },
        )
        .context("host function ferrix.set_mode")?;

    // set_topic(cptr, clen, tptr, tlen) -> i32: queue a server-set channel
    // topic (empty text clears it). Requires the `topic` capability.
    linker
        .func_wrap(
            "ferrix",
            "set_topic",
            |mut caller: Caller<'_, HostState>,
             cptr: i32,
             clen: i32,
             tptr: i32,
             tlen: i32|
             -> i32 {
                let Some(channel) = read_plugin_string(&caller, cptr, clen, 512) else {
                    return 1;
                };
                let text = read_plugin_string(&caller, tptr, tlen, 4096).unwrap_or_default();
                let state = caller.data_mut();
                if !state.require_cap(Capability::Topic, "set_topic") {
                    return 1;
                }
                if !valid_target(&channel) || !channel.starts_with('#') {
                    return 1;
                }
                let text = sanitize_text(&text, MAX_TOPIC_BYTES, false);
                if !state.take_action_slot() {
                    return 1;
                }
                state.call.actions.push(Action::Topic { channel, text });
                0
            },
        )
        .context("host function ferrix.set_topic")?;

    // kline(mptr, mlen, rptr, rlen) -> i32: queue a K-Line for a hostmask glob
    // and the disconnect of the users it matches. Requires the `kline`
    // capability — the sharpest edge in the grants table.
    linker
        .func_wrap(
            "ferrix",
            "kline",
            |mut caller: Caller<'_, HostState>,
             mptr: i32,
             mlen: i32,
             rptr: i32,
             rlen: i32|
             -> i32 {
                let Some(mask) = read_plugin_string(&caller, mptr, mlen, 512) else {
                    return 1;
                };
                let reason = read_plugin_string(&caller, rptr, rlen, 1024).unwrap_or_default();
                let state = caller.data_mut();
                if !state.require_cap(Capability::Kline, "kline") {
                    return 1;
                }
                if !valid_mask(&mask) {
                    return 1;
                }
                let reason = sanitize_text(&reason, MAX_REASON_BYTES, true);
                if !state.take_action_slot() {
                    return 1;
                }
                let reason = if reason.is_empty() {
                    "K-Lined".to_owned()
                } else {
                    reason
                };
                state.call.actions.push(Action::Kline {
                    mask,
                    reason,
                    set_by: format!("plugin:{}", state.name),
                });
                0
            },
        )
        .context("host function ferrix.kline")?;

    // kv_set(kptr, klen, vptr, vlen) -> i32: store a value under a UTF-8 key
    // (empty value deletes). 0 = ok, 1 = refused (bounds exceeded).
    linker
        .func_wrap(
            "ferrix",
            "kv_set",
            |mut caller: Caller<'_, HostState>,
             kptr: i32,
             klen: i32,
             vptr: i32,
             vlen: i32|
             -> i32 {
                let Some(key) = read_plugin_string(&caller, kptr, klen, MAX_KV_KEY_BYTES + 1)
                else {
                    return 1;
                };
                let Some(value) = read_plugin_bytes(&caller, vptr, vlen, MAX_KV_VALUE_BYTES + 1)
                else {
                    return 1;
                };
                if caller.data_mut().kv.set(&key, &value) {
                    0
                } else {
                    1
                }
            },
        )
        .context("host function ferrix.kv_set")?;

    // kv_get(kptr, klen, outptr, outcap) -> i32: read a value. Returns the
    // value's length (written to outptr when it fits), or -1 when absent.
    linker
        .func_wrap(
            "ferrix",
            "kv_get",
            |mut caller: Caller<'_, HostState>,
             kptr: i32,
             klen: i32,
             outptr: i32,
             outcap: i32|
             -> i32 {
                let Some(key) = read_plugin_string(&caller, kptr, klen, MAX_KV_KEY_BYTES + 1)
                else {
                    return -1;
                };
                let Some(value) = caller.data().kv.map.get(&key).cloned() else {
                    return -1;
                };
                write_plugin_bytes(&mut caller, outptr, outcap, &value)
            },
        )
        .context("host function ferrix.kv_get")?;

    // now_ms() -> i64: wall-clock milliseconds since the Unix epoch (for
    // cooldowns and rate limiting; not monotonic across clock adjustments).
    linker
        .func_wrap(
            "ferrix",
            "now_ms",
            |_caller: Caller<'_, HostState>| -> i64 { wall_ms() as i64 },
        )
        .context("host function ferrix.now_ms")?;

    // channel_members(cptr, clen, outptr, outcap) -> i32: JSON array of the
    // channel's member nicks. Returns the needed length (written when it
    // fits), or -1 for an unknown channel.
    linker
        .func_wrap(
            "ferrix",
            "channel_members",
            |mut caller: Caller<'_, HostState>,
             cptr: i32,
             clen: i32,
             outptr: i32,
             outcap: i32|
             -> i32 {
                let Some(channel) = read_plugin_string(&caller, cptr, clen, 512) else {
                    return -1;
                };
                let Some(world) = caller.data().world.get().and_then(Weak::upgrade) else {
                    return -1;
                };
                let Some(members) = world.channel_members(&channel) else {
                    return -1;
                };
                let mut json = String::from("[");
                for (i, nick) in members.iter().take(MAX_QUERY_MEMBERS).enumerate() {
                    if i > 0 {
                        json.push(',');
                    }
                    push_json_string(&mut json, nick);
                    if json.len() > MAX_QUERY_BYTES {
                        break;
                    }
                }
                json.push(']');
                write_plugin_bytes(&mut caller, outptr, outcap, json.as_bytes())
            },
        )
        .context("host function ferrix.channel_members")?;

    // user_info(nptr, nlen, outptr, outcap) -> i32: JSON object describing a
    // locally connected user. Returns the needed length (written when it
    // fits), or -1 for an unknown nick.
    linker
        .func_wrap(
            "ferrix",
            "user_info",
            |mut caller: Caller<'_, HostState>,
             nptr: i32,
             nlen: i32,
             outptr: i32,
             outcap: i32|
             -> i32 {
                let Some(nick) = read_plugin_string(&caller, nptr, nlen, 128) else {
                    return -1;
                };
                let Some(world) = caller.data().world.get().and_then(Weak::upgrade) else {
                    return -1;
                };
                let Some(json) = world.user_info_json(&nick) else {
                    return -1;
                };
                write_plugin_bytes(&mut caller, outptr, outcap, json.as_bytes())
            },
        )
        .context("host function ferrix.user_info")?;

    // server_info(outptr, outcap) -> i32: JSON object describing this server
    // and network. Same length contract as the other queries; -1 only when the
    // server view is gone (shutdown).
    linker
        .func_wrap(
            "ferrix",
            "server_info",
            |mut caller: Caller<'_, HostState>, outptr: i32, outcap: i32| -> i32 {
                let Some(world) = caller.data().world.get().and_then(Weak::upgrade) else {
                    return -1;
                };
                let json = world.server_info_json();
                write_plugin_bytes(&mut caller, outptr, outcap, json.as_bytes())
            },
        )
        .context("host function ferrix.server_info")?;

    // channel_info(cptr, clen, outptr, outcap) -> i32: JSON object describing
    // a channel (topic, modes, counts). -1 for an unknown channel.
    linker
        .func_wrap(
            "ferrix",
            "channel_info",
            |mut caller: Caller<'_, HostState>,
             cptr: i32,
             clen: i32,
             outptr: i32,
             outcap: i32|
             -> i32 {
                let Some(channel) = read_plugin_string(&caller, cptr, clen, 512) else {
                    return -1;
                };
                let Some(world) = caller.data().world.get().and_then(Weak::upgrade) else {
                    return -1;
                };
                let Some(json) = world.channel_info_json(&channel) else {
                    return -1;
                };
                write_plugin_bytes(&mut caller, outptr, outcap, json.as_bytes())
            },
        )
        .context("host function ferrix.channel_info")?;

    // user_channels(nptr, nlen, outptr, outcap) -> i32: JSON array of the
    // channels a locally connected user is in. -1 for an unknown nick.
    linker
        .func_wrap(
            "ferrix",
            "user_channels",
            |mut caller: Caller<'_, HostState>,
             nptr: i32,
             nlen: i32,
             outptr: i32,
             outcap: i32|
             -> i32 {
                let Some(nick) = read_plugin_string(&caller, nptr, nlen, 128) else {
                    return -1;
                };
                let Some(world) = caller.data().world.get().and_then(Weak::upgrade) else {
                    return -1;
                };
                let Some(channels) = world.user_channels(&nick) else {
                    return -1;
                };
                let mut json = String::from("[");
                for (i, name) in channels.iter().take(MAX_QUERY_MEMBERS).enumerate() {
                    if i > 0 {
                        json.push(',');
                    }
                    push_json_string(&mut json, name);
                    if json.len() > MAX_QUERY_BYTES {
                        break;
                    }
                }
                json.push(']');
                write_plugin_bytes(&mut caller, outptr, outcap, json.as_bytes())
            },
        )
        .context("host function ferrix.user_channels")?;

    // config_get(kptr, klen, outptr, outcap) -> i32: read one operator-supplied
    // setting from `[plugins.config.<plugin>]`. -1 when the key is unset, so a
    // plugin can tell "empty string" from "not configured".
    linker
        .func_wrap(
            "ferrix",
            "config_get",
            |mut caller: Caller<'_, HostState>,
             kptr: i32,
             klen: i32,
             outptr: i32,
             outcap: i32|
             -> i32 {
                let Some(key) = read_plugin_string(&caller, kptr, klen, 256) else {
                    return -1;
                };
                let Some(value) = caller.data().config.get(&key).cloned() else {
                    return -1;
                };
                write_plugin_bytes(&mut caller, outptr, outcap, value.as_bytes())
            },
        )
        .context("host function ferrix.config_get")?;

    // random_bytes(outptr, len) -> i32: fill up to MAX_RANDOM_BYTES bytes from
    // the OS CSPRNG. A sandbox has no entropy of its own, and rolling one from
    // now_ms is how plugins end up with predictable nonces. Returns the number
    // of bytes written, or -1 on failure.
    linker
        .func_wrap(
            "ferrix",
            "random_bytes",
            |mut caller: Caller<'_, HostState>, outptr: i32, len: i32| -> i32 {
                let len = (len.max(0) as usize).min(MAX_RANDOM_BYTES);
                let mut buf = vec![0u8; len];
                if getrandom::fill(&mut buf).is_err() {
                    return -1;
                }
                let written = write_plugin_bytes(&mut caller, outptr, len as i32, &buf);
                if written < 0 { -1 } else { written }
            },
        )
        .context("host function ferrix.random_bytes")?;

    // log_at(level, ptr, len): like `log`, but choosing the severity
    // (0 = debug, 1 = info, 2 = warn, 3 = error). Anything else is info.
    linker
        .func_wrap(
            "ferrix",
            "log_at",
            |caller: Caller<'_, HostState>, level: i32, ptr: i32, len: i32| {
                let Some(text) = read_plugin_string(&caller, ptr, len, 4096) else {
                    return;
                };
                let plugin = &caller.data().name;
                match level {
                    0 => debug!(plugin = %plugin, "plugin log: {text}"),
                    2 => warn!(plugin = %plugin, "plugin log: {text}"),
                    3 => error!(plugin = %plugin, "plugin log: {text}"),
                    _ => info!(plugin = %plugin, "plugin log: {text}"),
                }
            },
        )
        .context("host function ferrix.log_at")?;

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // A plugin that blocks any message whose text starts with '!'.
    const BANG_BLOCKER: &str = r#"
        (module
          (import "ferrix" "log" (func $log (param i32 i32)))
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param $size i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $size)))
            (local.get $p))
          (func (export "ferrix_on_message") (param $ptr i32) (param $len i32) (result i32)
            ;; Locals must precede all instructions in WAT.
            (local $i i32)
            (call $log (local.get $ptr) (local.get $len))
            ;; Block if any byte is '!' (0x21) by scanning the payload.
            (local.set $i (local.get $ptr))
            (block $done
              (loop $scan
                (br_if $done (i32.ge_u (local.get $i)
                                       (i32.add (local.get $ptr) (local.get $len))))
                (if (i32.eq (i32.load8_u (local.get $i)) (i32.const 33))
                  (then (return (i32.const 1))))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $scan)))
            (i32.const 0)))
    "#;

    fn host_with_blocker() -> PluginHost {
        let wasm = wat::parse_str(BANG_BLOCKER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("bang", &wasm).unwrap();
        host
    }

    #[test]
    fn plugin_blocks_and_allows() {
        let host = host_with_blocker();
        assert_eq!(host.len(), 1);
        assert_eq!(host.on_message("hello everyone").verdict, Verdict::Allow);
        assert_eq!(host.on_message("ban them all!").verdict, Verdict::Block);
    }

    #[test]
    fn empty_host_allows_everything() {
        let host = PluginHost::new(DEFAULT_FUEL);
        assert_eq!(host.on_message("!whatever").verdict, Verdict::Allow);
    }

    // A v2 plugin sees the JSON event (source/target/text); on_join gets the
    // join event. This one blocks anything mentioning "#secret".
    const V2_BLOCKER: &str = r##"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param $size i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $size)))
            (local.get $p))
          ;; Return 1 if the payload contains the byte sequence "#secret".
          (func $scan (param $ptr i32) (param $len i32) (result i32)
            (local $i i32)
            (local $end i32)
            (local.set $i (local.get $ptr))
            (local.set $end (i32.add (local.get $ptr) (local.get $len)))
            (block $done
              (loop $l
                (br_if $done (i32.gt_u (i32.add (local.get $i) (i32.const 7))
                                       (local.get $end)))
                (if (i32.and
                      (i32.eq (i32.load8_u (local.get $i)) (i32.const 35))        ;; '#'
                      (i32.and
                        (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 1))) (i32.const 115)) ;; 's'
                        (i32.and
                          (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 2))) (i32.const 101)) ;; 'e'
                          (i32.and
                            (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 3))) (i32.const 99)) ;; 'c'
                            (i32.and
                              (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 4))) (i32.const 114)) ;; 'r'
                              (i32.and
                                (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 5))) (i32.const 101)) ;; 'e'
                                (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 6))) (i32.const 116)) ;; 't'
                              )))))) ;; 'secret' spelled out byte-wise
                  (then (return (i32.const 1))))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $l)))
            (i32.const 0))
          (func (export "ferrix_on_message_v2") (param $ptr i32) (param $len i32) (result i32)
            (call $scan (local.get $ptr) (local.get $len)))
          (func (export "ferrix_on_join") (param $ptr i32) (param $len i32) (result i32)
            (call $scan (local.get $ptr) (local.get $len))))
    "##;

    #[test]
    fn v2_hook_receives_context_and_join_hook_vetoes() {
        let wasm = wat::parse_str(V2_BLOCKER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("v2", &wasm).unwrap();

        // The channel name is only visible through the v2 JSON event.
        assert_eq!(
            host.on_channel_message("alice", "#secret", "harmless text")
                .verdict,
            Verdict::Block
        );
        assert_eq!(
            host.on_channel_message("alice", "#general", "harmless text")
                .verdict,
            Verdict::Allow
        );
        // Joins are vetoed through the dedicated hook.
        assert_eq!(host.on_join("alice", "#secret").verdict, Verdict::Block);
        assert_eq!(host.on_join("alice", "#general").verdict, Verdict::Allow);
    }

    #[test]
    fn v1_plugin_still_sees_raw_text_via_context_call() {
        // A v1-only plugin gets the raw text when the host has context.
        let host = host_with_blocker();
        assert_eq!(
            host.on_channel_message("alice", "#g", "no bang here")
                .verdict,
            Verdict::Allow
        );
        assert_eq!(
            host.on_channel_message("alice", "#g", "bang!").verdict,
            Verdict::Block
        );
        // And a v1-only plugin ignores joins entirely.
        assert_eq!(host.on_join("alice", "#g").verdict, Verdict::Allow);
    }

    // A plugin exporting the nick/topic hooks, both of which veto unconditionally.
    const HOOK_BLOCKER: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param $size i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $size)))
            (local.get $p))
          (func (export "ferrix_on_nick") (param i32 i32) (result i32) (i32.const 1))
          (func (export "ferrix_on_topic") (param i32 i32) (result i32) (i32.const 1)))
    "#;

    #[test]
    fn nick_and_topic_hooks_veto() {
        let wasm = wat::parse_str(HOOK_BLOCKER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("hooks", &wasm).unwrap();
        assert_eq!(host.on_nick("alice", "bob").verdict, Verdict::Block);
        assert_eq!(
            host.on_topic("alice", "#general", "welcome").verdict,
            Verdict::Block
        );
    }

    #[test]
    fn missing_nick_topic_hooks_allow() {
        // A plugin that exports neither hook must not block those events.
        let host = host_with_blocker();
        assert_eq!(host.on_nick("alice", "bob").verdict, Verdict::Allow);
        assert_eq!(
            host.on_topic("alice", "#general", "welcome").verdict,
            Verdict::Allow
        );
    }

    // The moderation hooks (part/kick/mode/invite) veto unconditionally.
    const MOD_BLOCKER: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param $size i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $size)))
            (local.get $p))
          (func (export "ferrix_on_part") (param i32 i32) (result i32) (i32.const 1))
          (func (export "ferrix_on_kick") (param i32 i32) (result i32) (i32.const 1))
          (func (export "ferrix_on_mode") (param i32 i32) (result i32) (i32.const 1))
          (func (export "ferrix_on_invite") (param i32 i32) (result i32) (i32.const 1)))
    "#;

    #[test]
    fn moderation_hooks_veto() {
        let wasm = wat::parse_str(MOD_BLOCKER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("mod", &wasm).unwrap();
        assert_eq!(host.on_part("a", "#c", "bye").verdict, Verdict::Block);
        assert_eq!(host.on_kick("a", "#c", "b", "r").verdict, Verdict::Block);
        assert_eq!(host.on_mode("a", "#c", "+m").verdict, Verdict::Block);
        assert_eq!(host.on_invite("a", "#c", "b").verdict, Verdict::Block);
        // A host without those hooks allows them.
        let plain = host_with_blocker();
        assert_eq!(plain.on_part("a", "#c", "bye").verdict, Verdict::Allow);
        assert_eq!(plain.on_kick("a", "#c", "b", "r").verdict, Verdict::Allow);
        assert_eq!(plain.on_mode("a", "#c", "+m").verdict, Verdict::Allow);
        assert_eq!(plain.on_invite("a", "#c", "b").verdict, Verdict::Allow);
    }

    // Observe hooks: return values are ignored (event already happened).
    const OBSERVER: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param $size i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $size)))
            (local.get $p))
          (func (export "ferrix_on_connect") (param i32 i32) (result i32) (i32.const 1))
          (func (export "ferrix_on_quit") (param i32 i32) (result i32) (i32.const 1)))
    "#;

    #[test]
    fn observe_hooks_cannot_veto() {
        let wasm = wat::parse_str(OBSERVER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("obs", &wasm).unwrap();
        assert_eq!(
            host.on_connect("alice", "u", "h", Some("acct")).verdict,
            Verdict::Allow
        );
        assert_eq!(host.on_quit("alice", "bye").verdict, Verdict::Allow);
    }

    // A plugin that rewrites every message to "[redacted]" via set_text and
    // supplies a custom reason before blocking messages containing 'X' (0x58).
    const REWRITER: &str = r#"
        (module
          (import "ferrix" "set_text" (func $set_text (param i32 i32)))
          (import "ferrix" "set_reason" (func $set_reason (param i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "[redacted]")
          (data (i32.const 16) "custom reason")
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param $size i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $size)))
            (local.get $p))
          (func (export "ferrix_on_message") (param $ptr i32) (param $len i32) (result i32)
            (local $i i32)
            (local.set $i (local.get $ptr))
            (block $done
              (loop $scan
                (br_if $done (i32.ge_u (local.get $i)
                                       (i32.add (local.get $ptr) (local.get $len))))
                (if (i32.eq (i32.load8_u (local.get $i)) (i32.const 88))
                  (then
                    (call $set_reason (i32.const 16) (i32.const 13))
                    (return (i32.const 1))))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $scan)))
            (call $set_text (i32.const 0) (i32.const 10))
            (i32.const 0)))
    "#;

    #[test]
    fn set_text_rewrites_and_set_reason_customizes_block() {
        let wasm = wat::parse_str(REWRITER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("rewriter", &wasm).unwrap();

        let out = host.on_channel_message("alice", "#g", "hello");
        assert_eq!(out.verdict, Verdict::Allow);
        assert_eq!(out.replacement.as_deref(), Some("[redacted]"));

        let out = host.on_channel_message("alice", "#g", "seX");
        assert_eq!(out.verdict, Verdict::Block);
        assert_eq!(out.reason.as_deref(), Some("custom reason"));
    }

    #[test]
    fn set_text_ignored_outside_message_hooks() {
        // A join hook calling set_text must not produce a replacement.
        const JOIN_REWRITER: &str = r#"
            (module
              (import "ferrix" "set_text" (func $set_text (param i32 i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "nope")
              (global $next (mut i32) (i32.const 4096))
              (func (export "alloc") (param $size i32) (result i32)
                (global.get $next))
              (func (export "ferrix_on_join") (param i32 i32) (result i32)
                (call $set_text (i32.const 0) (i32.const 4))
                (i32.const 0)))
        "#;
        let wasm = wat::parse_str(JOIN_REWRITER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("joinrw", &wasm).unwrap();
        let out = host.on_join("alice", "#g");
        assert_eq!(out.verdict, Verdict::Allow);
        assert!(out.replacement.is_none());
    }

    // A plugin that queues a notice to "#general" on every message.
    const NOTIFIER: &str = r##"
        (module
          (import "ferrix" "send_notice" (func $notice (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "#general")
          (data (i32.const 16) "seen a message")
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param $size i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $size)))
            (local.get $p))
          (func (export "ferrix_on_message") (param i32 i32) (result i32)
            (drop (call $notice (i32.const 0) (i32.const 8) (i32.const 16) (i32.const 14)))
            (i32.const 0)))
    "##;

    #[test]
    fn send_notice_requires_grant() {
        let wasm = wat::parse_str(NOTIFIER).unwrap();

        // Without a grant, the action is refused.
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("notifier", &wasm).unwrap();
        let out = host.on_message("hi");
        assert!(out.actions.is_empty());

        // With the grant, the notice is queued.
        let mut host = PluginHost::new(DEFAULT_FUEL);
        let mut grants = HashMap::new();
        grants.insert("notifier".to_owned(), vec!["send_notice".to_owned()]);
        host.set_grants(&grants);
        host.load_bytes("notifier", &wasm).unwrap();
        let out = host.on_message("hi");
        assert_eq!(
            out.actions,
            vec![Action::Notice {
                target: "#general".to_owned(),
                text: "seen a message".to_owned(),
            }]
        );
    }

    // A plugin abusing send_notice in a loop: the per-call budget caps it.
    const NOTICE_SPAMMER: &str = r##"
        (module
          (import "ferrix" "send_notice" (func $notice (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "#general")
          (data (i32.const 16) "spam")
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param $size i32) (result i32)
            (global.get $next))
          (func (export "ferrix_on_message") (param i32 i32) (result i32)
            (local $i i32)
            (block $done
              (loop $l
                (br_if $done (i32.ge_u (local.get $i) (i32.const 100)))
                (drop (call $notice (i32.const 0) (i32.const 8) (i32.const 16) (i32.const 4)))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $l)))
            (i32.const 0)))
    "##;

    #[test]
    fn send_notice_is_budgeted_per_call() {
        let wasm = wat::parse_str(NOTICE_SPAMMER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        let mut grants = HashMap::new();
        grants.insert("spammer".to_owned(), vec!["send_notice".to_owned()]);
        host.set_grants(&grants);
        host.load_bytes("spammer", &wasm).unwrap();
        let out = host.on_message("hi");
        assert_eq!(out.actions.len(), MAX_ACTIONS_PER_CALL);
    }

    // A counter plugin: increments a 1-byte counter under key "n" on every
    // message and blocks from the third message on.
    const COUNTER: &str = r#"
        (module
          (import "ferrix" "kv_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (import "ferrix" "kv_set" (func $set (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "n")
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param $size i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $size)))
            (local.get $p))
          (func (export "ferrix_on_message") (param i32 i32) (result i32)
            (local $n i32)
            ;; read counter into address 64 (1 byte)
            (if (i32.lt_s (call $get (i32.const 0) (i32.const 1) (i32.const 64) (i32.const 1))
                          (i32.const 0))
              (then (i32.store8 (i32.const 64) (i32.const 0))))
            (local.set $n (i32.add (i32.load8_u (i32.const 64)) (i32.const 1)))
            (i32.store8 (i32.const 64) (local.get $n))
            (drop (call $set (i32.const 0) (i32.const 1) (i32.const 64) (i32.const 1)))
            (i32.ge_u (local.get $n) (i32.const 3))))
    "#;

    #[test]
    fn kv_store_persists_state_across_calls() {
        let wasm = wat::parse_str(COUNTER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("counter", &wasm).unwrap();
        assert_eq!(host.on_message("1").verdict, Verdict::Allow);
        assert_eq!(host.on_message("2").verdict, Verdict::Allow);
        assert_eq!(host.on_message("3").verdict, Verdict::Block);
        assert_eq!(host.on_message("4").verdict, Verdict::Block);
    }

    #[test]
    fn kv_bounds_are_enforced() {
        let mut kv = KvStore::default();
        assert!(kv.set("k", b"v"));
        assert!(!kv.set("", b"v"));
        assert!(!kv.set(&"k".repeat(MAX_KV_KEY_BYTES + 1), b"v"));
        assert!(!kv.set("big", &vec![0u8; MAX_KV_VALUE_BYTES + 1]));
        // Delete via empty value.
        assert!(kv.set("k", b""));
        assert_eq!(kv.total, 0);
        // Key-count bound.
        for i in 0..MAX_KV_KEYS {
            assert!(kv.set(&format!("key{i}"), b"x"), "key {i} should fit");
        }
        assert!(!kv.set("overflow", b"x"));
    }

    #[test]
    fn kv_store_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("ferrixd-kv-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.kv");
        let mut kv = KvStore {
            path: Some(path.clone()),
            ..KvStore::default()
        };
        assert!(kv.set("alpha", b"one"));
        assert!(kv.set("beta", &[0, 159, 146, 150])); // non-UTF-8 value bytes
        kv.last_flush_ms = 0;
        kv.flush_if_due("p");
        assert!(!kv.dirty);

        let mut reloaded = KvStore {
            path: Some(path),
            ..KvStore::default()
        };
        reloaded.load();
        assert_eq!(
            reloaded.map.get("alpha").map(Vec::as_slice),
            Some(&b"one"[..])
        );
        assert_eq!(
            reloaded.map.get("beta").map(Vec::as_slice),
            Some(&[0u8, 159, 146, 150][..])
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    // now_ms sanity: the plugin returns block iff now_ms() > 0.
    const CLOCK: &str = r#"
        (module
          (import "ferrix" "now_ms" (func $now (result i64)))
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param i32) (result i32)
            (global.get $next))
          (func (export "ferrix_on_message") (param i32 i32) (result i32)
            (i64.gt_s (call $now) (i64.const 0))))
    "#;

    #[test]
    fn now_ms_returns_wall_clock() {
        let wasm = wat::parse_str(CLOCK).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("clock", &wasm).unwrap();
        assert_eq!(host.on_message("x").verdict, Verdict::Block);
    }

    struct FakeWorld;
    impl WorldView for FakeWorld {
        fn channel_members(&self, channel: &str) -> Option<Vec<String>> {
            (channel == "#general").then(|| vec!["alice".to_owned(), "bob".to_owned()])
        }
        fn user_info_json(&self, nick: &str) -> Option<String> {
            (nick == "alice").then(|| "{\"nick\":\"alice\"}".to_owned())
        }
        fn server_info_json(&self) -> String {
            "{\"name\":\"irc.test\",\"users\":2}".to_owned()
        }
        fn channel_info_json(&self, channel: &str) -> Option<String> {
            (channel == "#general").then(|| "{\"name\":\"#general\",\"members\":2}".to_owned())
        }
        fn user_channels(&self, nick: &str) -> Option<Vec<String>> {
            (nick == "alice").then(|| vec!["#general".to_owned()])
        }
    }

    // Queries #general's member list into memory at 512 and blocks iff the
    // response length is positive (i.e. the query succeeded).
    const QUERIER: &str = r##"
        (module
          (import "ferrix" "channel_members" (func $members (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "#general")
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param i32) (result i32)
            (global.get $next))
          (func (export "ferrix_on_message") (param i32 i32) (result i32)
            (i32.gt_s
              (call $members (i32.const 0) (i32.const 8) (i32.const 512) (i32.const 256))
              (i32.const 0))))
    "##;

    #[test]
    fn channel_members_query_reaches_the_world_view() {
        let wasm = wat::parse_str(QUERIER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("querier", &wasm).unwrap();
        // No world attached: query fails, verdict stays Allow.
        assert_eq!(host.on_message("x").verdict, Verdict::Allow);
        // With a world, the query succeeds and the test plugin blocks.
        let world: Arc<dyn WorldView> = Arc::new(FakeWorld);
        host.set_world(Arc::downgrade(&world));
        assert_eq!(host.on_message("x").verdict, Verdict::Block);
    }

    // --- ABI v3 -------------------------------------------------------------

    /// Grant `caps` to a plugin named `name` and load `wat_src` into a fresh host.
    fn host_with(name: &str, caps: &[&str], wat_src: &str) -> PluginHost {
        let wasm = wat::parse_str(wat_src).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        if !caps.is_empty() {
            let grants = HashMap::from([(
                name.to_owned(),
                caps.iter().map(|c| (*c).to_owned()).collect::<Vec<_>>(),
            )]);
            host.set_grants(&grants);
        }
        host.load_bytes(name, &wasm).unwrap();
        host
    }

    // Kicks alice from #general; returns the host function's own result, so a
    // refusal (1) surfaces as a Block and a queued kick (0) as an Allow.
    const KICKER: &str = r##"
        (module
          (import "ferrix" "kick" (func $kick (param i32 i32 i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "#general")
          (data (i32.const 16) "alice")
          (data (i32.const 32) "spam")
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param i32) (result i32)
            (global.get $next))
          (func (export "ferrix_on_message") (param i32 i32) (result i32)
            (call $kick (i32.const 0) (i32.const 8)
                        (i32.const 16) (i32.const 5)
                        (i32.const 32) (i32.const 4))))
    "##;

    #[test]
    fn kick_action_needs_its_grant() {
        // Ungranted: the host function refuses, nothing is queued.
        let host = host_with("kicker", &[], KICKER);
        let outcome = host.on_message("x");
        assert_eq!(outcome.verdict, Verdict::Block); // the refusal code, surfaced
        assert!(outcome.actions.is_empty());

        // Granted: the action is queued for the server to run after the call.
        let host = host_with("kicker", &["kick"], KICKER);
        let outcome = host.on_message("x");
        assert_eq!(outcome.verdict, Verdict::Allow);
        assert_eq!(
            outcome.actions,
            vec![Action::Kick {
                channel: "#general".to_owned(),
                nick: "alice".to_owned(),
                reason: "spam".to_owned(),
            }]
        );
    }

    // Moderates #general (+m) through the mode action.
    const MODERATOR: &str = r##"
        (module
          (import "ferrix" "set_mode" (func $mode (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "#general")
          (data (i32.const 16) "+m")
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param i32) (result i32)
            (global.get $next))
          (func (export "ferrix_on_message") (param i32 i32) (result i32)
            (call $mode (i32.const 0) (i32.const 8) (i32.const 16) (i32.const 2))))
    "##;

    #[test]
    fn mode_action_is_queued_with_its_grant() {
        let host = host_with("mod", &["mode"], MODERATOR);
        let outcome = host.on_message("x");
        assert_eq!(outcome.verdict, Verdict::Allow);
        assert_eq!(
            outcome.actions,
            vec![Action::Mode {
                channel: "#general".to_owned(),
                flags: "+m".to_owned(),
                args: Vec::new(),
            }]
        );
    }

    #[test]
    fn mode_strings_are_parsed_and_bounded() {
        assert_eq!(
            parse_mode_string("+b nick!*@*"),
            Some(("+b".to_owned(), vec!["nick!*@*".to_owned()]))
        );
        assert_eq!(parse_mode_string("+m"), Some(("+m".to_owned(), Vec::new())));
        // No mode letter, a smuggled trailing parameter, or too many arguments.
        assert_eq!(parse_mode_string("+"), None);
        assert_eq!(parse_mode_string(""), None);
        assert_eq!(parse_mode_string("+b :and a trailer"), None);
        // Extended account bans keep their embedded colon.
        assert_eq!(
            parse_mode_string("+b ~a:spammer"),
            Some(("+b".to_owned(), vec!["~a:spammer".to_owned()]))
        );
        let many = format!("+bbbbbbbbb{}", " m!*@*".repeat(MAX_MODE_ARGS + 1));
        assert_eq!(parse_mode_string(&many), None);
    }

    #[test]
    fn kline_masks_reject_framing_hazards() {
        assert!(valid_mask("*!*@spam.example"));
        assert!(valid_mask("~a:baduser"));
        assert!(!valid_mask(""));
        assert!(!valid_mask("has space"));
        assert!(!valid_mask(":leading-colon"));
        assert!(!valid_mask(&"a".repeat(MAX_MASK_BYTES + 1)));
    }

    // Reads `greeting` from the operator-supplied plugin config; blocks when
    // the key is present (a non-negative length), allows when it is not.
    const CONFIGURED: &str = r##"
        (module
          (import "ferrix" "config_get" (func $get (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "greeting")
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param i32) (result i32)
            (global.get $next))
          (func (export "ferrix_on_message") (param i32 i32) (result i32)
            (i32.ge_s
              (call $get (i32.const 0) (i32.const 8) (i32.const 512) (i32.const 256))
              (i32.const 0))))
    "##;

    #[test]
    fn config_get_reads_operator_settings() {
        let wasm = wat::parse_str(CONFIGURED).unwrap();

        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("cfg", &wasm).unwrap();
        assert_eq!(host.on_message("x").verdict, Verdict::Allow); // unset

        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.set_plugin_config(&HashMap::from([(
            "cfg".to_owned(),
            HashMap::from([("greeting".to_owned(), "moin".to_owned())]),
        )]));
        host.load_bytes("cfg", &wasm).unwrap();
        assert_eq!(host.on_message("x").verdict, Verdict::Block); // set
    }

    // Asks for 16 random bytes and blocks iff exactly that many were written.
    const DICE: &str = r##"
        (module
          (import "ferrix" "random_bytes" (func $rand (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param i32) (result i32)
            (global.get $next))
          (func (export "ferrix_on_message") (param i32 i32) (result i32)
            (i32.eq (call $rand (i32.const 512) (i32.const 16)) (i32.const 16))))
    "##;

    #[test]
    fn random_bytes_fills_the_requested_buffer() {
        let host = host_with("dice", &[], DICE);
        assert_eq!(host.on_message("x").verdict, Verdict::Block);
    }

    // A timer plugin that announces on every tick (observe-only hook, so the
    // return value is ignored — the queued action is the observable effect).
    const TICKER: &str = r##"
        (module
          (import "ferrix" "send_notice" (func $notice (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "#general")
          (data (i32.const 16) "tick")
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param i32) (result i32)
            (global.get $next))
          (func (export "ferrix_on_timer") (param i32 i32) (result i32)
            (call $notice (i32.const 0) (i32.const 8) (i32.const 16) (i32.const 4))))
    "##;

    #[test]
    fn timer_hook_fires_and_may_act() {
        let host = host_with("ticker", &["send_notice"], TICKER);
        assert!(host.wants_timer());
        assert_eq!(
            host.on_timer(1).actions,
            vec![Action::Notice {
                target: "#general".to_owned(),
                text: "tick".to_owned(),
            }]
        );
        // A plugin without the export never asks the server for a ticker.
        assert!(!host_with("bang", &[], BANG_BLOCKER).wants_timer());
    }

    // Echoes the away/account payload back as a notice, so the test can assert
    // on exactly what the host serialized.
    const STATE_OBSERVER: &str = r##"
        (module
          (import "ferrix" "send_notice" (func $notice (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "#log")
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param i32) (result i32)
            (global.get $next))
          (func $echo (param $ptr i32) (param $len i32) (result i32)
            (call $notice (i32.const 0) (i32.const 4) (local.get $ptr) (local.get $len)))
          (func (export "ferrix_on_away") (param $ptr i32) (param $len i32) (result i32)
            (call $echo (local.get $ptr) (local.get $len)))
          (func (export "ferrix_on_account") (param $ptr i32) (param $len i32) (result i32)
            (call $echo (local.get $ptr) (local.get $len))))
    "##;

    #[test]
    fn away_and_account_hooks_carry_nullable_fields() {
        let host = host_with("obs", &["send_notice"], STATE_OBSERVER);
        let text = |outcome: Outcome| {
            outcome
                .actions
                .into_iter()
                .find_map(|action| match action {
                    Action::Notice { text, .. } => Some(text),
                    _ => None,
                })
                .unwrap()
        };
        assert_eq!(
            text(host.on_away("alice", Some("brb"))),
            r#"{"nick":"alice","message":"brb"}"#
        );
        assert_eq!(
            text(host.on_away("alice", None)),
            r#"{"nick":"alice","message":null}"#
        );
        assert_eq!(
            text(host.on_account("alice", Some("acct"))),
            r#"{"nick":"alice","account":"acct"}"#
        );
        assert_eq!(
            text(host.on_account("alice", None)),
            r#"{"nick":"alice","account":null}"#
        );
    }

    // Queries server_info and blocks iff the response has a positive length.
    const INSPECTOR: &str = r##"
        (module
          (import "ferrix" "server_info" (func $info (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param i32) (result i32)
            (global.get $next))
          (func (export "ferrix_on_message") (param i32 i32) (result i32)
            (i32.gt_s (call $info (i32.const 512) (i32.const 256)) (i32.const 0))))
    "##;

    #[test]
    fn server_info_query_reaches_the_world_view() {
        let host = host_with("inspector", &[], INSPECTOR);
        assert_eq!(host.on_message("x").verdict, Verdict::Allow); // no world yet
        let world: Arc<dyn WorldView> = Arc::new(FakeWorld);
        host.set_world(Arc::downgrade(&world));
        assert_eq!(host.on_message("x").verdict, Verdict::Block);
    }

    #[test]
    fn every_capability_round_trips_through_its_config_name() {
        for &(cap, name) in CAPABILITIES {
            assert_eq!(Capability::parse(name), Some(cap));
            assert_eq!(cap.name(), name);
        }
        assert_eq!(Capability::parse("root"), None);
    }

    #[test]
    fn private_messages_are_gated_by_config() {
        const DM_BLOCKER: &str = r#"
            (module
              (memory (export "memory") 1)
              (global $next (mut i32) (i32.const 4096))
              (func (export "alloc") (param i32) (result i32)
                (global.get $next))
              (func (export "ferrix_on_private_message") (param i32 i32) (result i32)
                (i32.const 1)))
        "#;
        let wasm = wat::parse_str(DM_BLOCKER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("dm", &wasm).unwrap();
        // Off by default: the hook is never called.
        assert_eq!(
            host.on_private_message("alice", "bob", "hi").verdict,
            Verdict::Allow
        );
        host.set_expose_private_messages(true);
        assert_eq!(
            host.on_private_message("alice", "bob", "hi").verdict,
            Verdict::Block
        );
    }

    #[test]
    fn memory_growth_is_capped() {
        // A plugin that tries to grow memory by 64 pages (4 MiB) per message.
        const GROWER: &str = r#"
            (module
              (memory (export "memory") 1)
              (global $next (mut i32) (i32.const 4096))
              (func (export "alloc") (param i32) (result i32)
                (global.get $next))
              (func (export "ferrix_on_message") (param i32 i32) (result i32)
                ;; Block iff the grow FAILED (returns -1), i.e. the cap held.
                (i32.eq (memory.grow (i32.const 64)) (i32.const -1))))
        "#;
        let wasm = wat::parse_str(GROWER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.set_max_memory(1024 * 1024); // 1 MiB cap
        host.load_bytes("grower", &wasm).unwrap();
        // 4 MiB growth exceeds the 1 MiB cap → grow fails → plugin blocks.
        assert_eq!(host.on_message("x").verdict, Verdict::Block);
    }

    #[test]
    fn oversized_initial_memory_is_rejected_at_load() {
        // The cap must bound the module's *declared* initial memory too, not
        // just later growth — otherwise a plugin could reserve past the cap in
        // one shot at instantiation. wasmi runs the resource limiter during
        // memory construction, so this module fails to load.
        const BIG_INITIAL: &str = r#"
            (module
              (memory (export "memory") 64)  ;; 64 pages = 4 MiB initial
              (func (export "alloc") (param i32) (result i32) (i32.const 0)))
        "#;
        let wasm = wat::parse_str(BIG_INITIAL).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.set_max_memory(1024 * 1024); // 1 MiB cap < 4 MiB initial
        assert!(
            host.load_bytes("big", &wasm).is_err(),
            "a module declaring more initial memory than the cap must be rejected"
        );
        assert_eq!(host.len(), 0, "the rejected plugin must not be registered");
    }

    #[test]
    fn on_load_reports_grants() {
        // The plugin records the on_load payload length in a global; blocks
        // messages iff on_load ran with a non-empty payload.
        const LOADER: &str = r#"
            (module
              (memory (export "memory") 1)
              (global $next (mut i32) (i32.const 4096))
              (global $loaded (mut i32) (i32.const 0))
              (func (export "alloc") (param $size i32) (result i32)
                (local $p i32)
                (local.set $p (global.get $next))
                (global.set $next (i32.add (global.get $next) (local.get $size)))
                (local.get $p))
              (func (export "ferrix_on_load") (param i32 i32) (result i32)
                (global.set $loaded (local.get 1))
                (i32.const 0))
              (func (export "ferrix_on_message") (param i32 i32) (result i32)
                (i32.gt_s (global.get $loaded) (i32.const 0))))
        "#;
        let wasm = wat::parse_str(LOADER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("loader", &wasm).unwrap();
        assert_eq!(host.on_message("x").verdict, Verdict::Block);
    }

    #[test]
    fn stats_count_calls_blocks_and_traps() {
        let host = host_with_blocker();
        let _ = host.on_message("fine");
        let _ = host.on_message("blocked!");
        let stats = host.stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].name, "bang");
        assert_eq!(stats[0].calls, 2);
        assert_eq!(stats[0].blocks, 1);
        assert_eq!(stats[0].traps, 0);
    }

    #[test]
    fn sanitizer_strips_line_breaks_and_caps_length() {
        assert_eq!(sanitize_text("a\r\nb\0c", 100, false), "abc");
        assert_eq!(sanitize_text("a\x02b\x03c", 100, false), "a\x02b\x03c"); // formatting kept
        assert_eq!(sanitize_text("a\x02b", 100, true), "ab"); // plain text: ctl stripped
        assert_eq!(sanitize_text(&"x".repeat(1000), 10, false).len(), 10);
        // Never splits a multi-byte char.
        assert_eq!(sanitize_text("ééééé", 5, false), "éé");
    }

    #[test]
    fn json_escaping_is_wellformed() {
        let mut out = String::new();
        push_json_string(&mut out, "a\"b\\c\nd\te\u{1}");
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\\te\\u0001\"");
    }

    // A plugin that loops forever must run out of fuel and fail open (allow).
    #[test]
    fn infinite_loop_is_fuel_limited() {
        let spinner = r#"
            (module
              (memory (export "memory") 1)
              (global $next (mut i32) (i32.const 4096))
              (func (export "alloc") (param i32) (result i32)
                (global.get $next))
              (func (export "ferrix_on_message") (param i32 i32) (result i32)
                (loop $l (br $l))
                (i32.const 1)))
        "#;
        let wasm = wat::parse_str(spinner).unwrap();
        let mut host = PluginHost::new(1_000_000);
        host.load_bytes("spin", &wasm).unwrap();
        // Fuel exhaustion traps -> fail-open Allow, and crucially it returns.
        assert_eq!(host.on_message("hi").verdict, Verdict::Allow);
        assert_eq!(host.stats()[0].traps, 1);
    }

    // A trapping plugin that queued a notice before the trap: the queued
    // action must be discarded (trap = as if the hook never ran).
    #[test]
    fn trapped_call_discards_queued_actions() {
        const TRAP_AFTER_NOTICE: &str = r##"
            (module
              (import "ferrix" "send_notice" (func $notice (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "#general")
              (data (i32.const 16) "pre-trap")
              (global $next (mut i32) (i32.const 4096))
              (func (export "alloc") (param i32) (result i32)
                (global.get $next))
              (func (export "ferrix_on_message") (param i32 i32) (result i32)
                (drop (call $notice (i32.const 0) (i32.const 8) (i32.const 16) (i32.const 8)))
                (unreachable)))
        "##;
        let wasm = wat::parse_str(TRAP_AFTER_NOTICE).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        let mut grants = HashMap::new();
        grants.insert("trapper".to_owned(), vec!["send_notice".to_owned()]);
        host.set_grants(&grants);
        host.load_bytes("trapper", &wasm).unwrap();
        let out = host.on_message("hi");
        assert_eq!(out.verdict, Verdict::Allow);
        assert!(out.actions.is_empty());
    }

    #[test]
    fn rewrites_chain_across_plugins() {
        // Plugin A rewrites to "[redacted]"; plugin B blocks on 'X'. B must
        // see A's rewritten text, so an original containing 'X' passes.
        let rewriter = wat::parse_str(REWRITER).unwrap();
        let blocker = wat::parse_str(BANG_BLOCKER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("a-rewriter", &rewriter).unwrap();
        host.load_bytes("b-bang", &blocker).unwrap();
        // Original has a '!', but the rewriter replaces the text before the
        // bang-blocker sees it → allowed, with the replacement.
        let out = host.on_channel_message("alice", "#g", "hello!");
        assert_eq!(out.verdict, Verdict::Allow);
        assert_eq!(out.replacement.as_deref(), Some("[redacted]"));
    }

    #[test]
    fn valid_target_rejects_junk() {
        assert!(valid_target("#general"));
        assert!(valid_target("alice"));
        assert!(!valid_target(""));
        assert!(!valid_target("a b"));
        assert!(!valid_target("a\r\nQUIT"));
        assert!(!valid_target("*"));
        assert!(!valid_target(&"x".repeat(100)));
    }
}
