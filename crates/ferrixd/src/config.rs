//! Configuration model and loading.
//!
//! The schema is strict: unknown keys are a hard error (`deny_unknown_fields`),
//! so a typo fails loudly at startup rather than silently disabling a security
//! control.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use ferrix_protocol::Limits;
use serde::Deserialize;

/// Top-level daemon configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Server identity and listen addresses.
    pub server: ServerConfig,
    /// TLS material.
    pub tls: TlsConfig,
    /// Wire-length and timing budgets.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Seed accounts for SASL. Self-registered accounts are stored separately
    /// (see `[persistence]`) and merged on top of these.
    #[serde(default)]
    pub accounts: Vec<AccountConfig>,
    /// IRC operator credentials (used by the `OPER` command).
    #[serde(default)]
    pub operators: Vec<OperatorConfig>,
    /// Server bans (K-Lines) applied at startup.
    #[serde(default)]
    pub bans: Vec<BanConfig>,
    /// Optional SQLite persistence for message history.
    #[serde(default)]
    pub persistence: Option<PersistenceConfig>,
    /// Optional Prometheus metrics endpoint.
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    /// Server-to-server peer links.
    #[serde(default)]
    pub links: Vec<LinkConfig>,
    /// Optional WebAssembly plugin host.
    #[serde(default)]
    pub plugins: Option<PluginsConfig>,
    /// Trusted WEBIRC gateways (web/IRC gateways permitted to spoof a client's
    /// real host and IP). Empty (the default) disables the `WEBIRC` command.
    #[serde(default)]
    pub webirc: Vec<WebircConfig>,
}

/// A trusted WEBIRC gateway (IRCv3 `WEBIRC`). A gateway authenticates with a
/// shared password AND must connect from an allow-listed source address; both
/// checks must pass before it may rewrite a client's apparent host/IP.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebircConfig {
    /// Gateway identifier, matched against the WEBIRC `<gateway>` parameter.
    pub name: String,
    /// Shared secret the gateway presents as the WEBIRC `<password>`. Prefer a
    /// long random value; it is compared in constant time.
    pub password: String,
    /// Source-address globs (e.g. `127.0.0.1`, `10.0.0.*`) the gateway is
    /// allowed to connect from. A WEBIRC from any other address is refused.
    pub hosts: Vec<String>,
}

/// A configured S2S peer link.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkConfig {
    /// The peer server's name.
    pub name: String,
    /// Address to connect to (outbound); omit for accept-only links.
    #[serde(default)]
    pub connect: Option<SocketAddr>,
    /// The peer's pinned TLS certificate SHA-256 fingerprint (lowercase hex).
    pub fingerprint: String,
    /// Shared link password (`PASS` token), in addition to the certificate pin.
    pub password: String,
    /// Wire protocol spoken on this link: the native ferrix protocol
    /// (default), or `ts6` to bridge a charybdis-family IRCd (solanum, …).
    #[serde(default)]
    pub protocol: LinkProtocol,
}

/// The S2S wire protocol for a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkProtocol {
    /// ferrixd's native protocol (see `crate::s2s`).
    #[default]
    Ferrix,
    /// The TS6 protocol spoken by charybdis-family IRCds (see `crate::ts6`).
    Ts6,
}

/// Prometheus metrics endpoint settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Address to serve `/metrics` on (bind to loopback in production).
    pub bind: SocketAddr,
}

/// SQLite persistence settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistenceConfig {
    /// Path to the SQLite database file.
    pub path: PathBuf,
    /// Number of recent messages to load into memory at startup.
    #[serde(default = "default_load_limit")]
    pub load_limit: usize,
}

/// WebAssembly plugin host settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginsConfig {
    /// Directory of `.wasm` plugin files to load at startup.
    pub dir: PathBuf,
    /// Per-hook-call fuel budget (WASM instructions).
    #[serde(default = "default_plugin_fuel")]
    pub fuel: u64,
    /// Cap on each plugin instance's linear memory, in bytes.
    #[serde(default = "default_plugin_memory")]
    pub max_memory: usize,
    /// Feed user-to-user private messages to the `ferrix_on_private_message`
    /// hook. Off by default: exposing DMs to plugins is the operator's
    /// privacy decision, never the plugin author's.
    #[serde(default)]
    pub expose_private_messages: bool,
    /// Directory for host-managed per-plugin state files (the bounded
    /// key-value store's persistence). Unset → plugin state is in-memory only.
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    /// Capability grants, plugin name (file stem) → capability names
    /// (`send_notice`, `send_message`, `kick`, `mode`, `topic`, `kline`).
    /// Deny-by-default: an ungranted capability's host function refuses and
    /// logs.
    #[serde(default)]
    pub grants: HashMap<String, Vec<String>>,
    /// Per-plugin operator settings, plugin name (file stem) → key/value pairs,
    /// readable by the plugin through `ferrix.config_get`. Lets one `.wasm`
    /// file be deployed with site-specific parameters instead of recompiled.
    #[serde(default)]
    pub config: HashMap<String, HashMap<String, String>>,
    /// Interval in seconds between `ferrix_on_timer` calls. `0` (the default)
    /// disables the tick; the hook is also skipped when no plugin exports it.
    #[serde(default)]
    pub tick_secs: u64,
}

fn default_plugin_fuel() -> u64 {
    5_000_000
}

fn default_plugin_memory() -> usize {
    16 * 1024 * 1024
}

fn default_load_limit() -> usize {
    5000
}

/// An IRC operator credential.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorConfig {
    /// Operator name (the first `OPER` argument).
    pub name: String,
    /// Plaintext password (hashed at startup) — prefer `password_hash`.
    #[serde(default)]
    pub password: Option<String>,
    /// Pre-computed Argon2 PHC password hash.
    #[serde(default)]
    pub password_hash: Option<String>,
    /// Hostmask globs (`nick!user@host` or bare IP) allowed to use this block
    /// (`ERR_NOOPERHOST` otherwise). Empty (the default) allows any host.
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// A startup server ban (K-Line).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BanConfig {
    /// Hostmask glob (`nick!user@host`) to refuse at registration.
    pub mask: String,
    /// Reason shown to matched users.
    #[serde(default = "default_ban_reason")]
    pub reason: String,
}

fn default_ban_reason() -> String {
    "Banned".to_owned()
}

/// A seed account for SASL authentication.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    /// Account name.
    pub name: String,
    /// Plaintext password (hashed with Argon2id at startup — development
    /// convenience; prefer `password_hash` in production).
    #[serde(default)]
    pub password: Option<String>,
    /// Pre-computed Argon2 PHC password hash.
    #[serde(default)]
    pub password_hash: Option<String>,
    /// Pre-computed SCRAM-SHA-256 credential
    /// (`<iterations>:<b64 salt>:<b64 stored_key>:<b64 server_key>`, printed by
    /// `ferrixd hash-password`). Required for SCRAM logins on an account seeded
    /// with `password_hash`: the server never sees that account's plaintext and
    /// cannot derive them. An account seeded with plaintext `password` gets
    /// SCRAM credentials automatically.
    #[serde(default)]
    pub scram: Option<String>,
    /// Permitted TLS certificate SHA-256 fingerprints (lowercase hex) for
    /// SASL EXTERNAL.
    #[serde(default)]
    pub fingerprints: Vec<String>,
}

/// Server identity and listen addresses.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Advertised server name.
    pub name: String,
    /// Advertised network name (`ISUPPORT NETWORK`).
    #[serde(default = "default_network")]
    pub network: String,
    /// Optional network icon URL (IRCv3 `draft/network-icon`), advertised as the
    /// `draft/ICON` ISUPPORT token. Should be an HTTPS URL to a (square) image;
    /// a literal `{size}` template is passed through for clients to substitute.
    #[serde(default)]
    pub icon: Option<String>,
    /// Network-wide case-folding rule for nicks/channels.
    #[serde(default)]
    pub casemapping: crate::casemap::CaseMapping,
    /// Message-of-the-day lines (may be empty).
    #[serde(default)]
    pub motd: Vec<String>,
    /// HMAC key enabling host cloaking (omit to disable). Keep secret.
    #[serde(default)]
    pub cloak_key: Option<String>,
    /// This server's id (SID) for S2S linking.
    #[serde(default = "default_sid")]
    pub sid: String,
    /// Optional listen address for inbound S2S links.
    #[serde(default)]
    pub link_bind: Option<SocketAddr>,
    /// TLS listen address (the primary, mandatory transport).
    pub tls_bind: SocketAddr,
    /// Optional plaintext listen address. Disabled unless set.
    #[serde(default)]
    pub plain_bind: Option<SocketAddr>,
    /// Guard rail: a plaintext bind to a non-loopback address is refused unless
    /// this is explicitly set to `true` (plaintext is loopback-only
    /// by default). Also governs `ws_bind`.
    #[serde(default)]
    pub allow_plain_nonlocal: bool,
    /// Optional plaintext WebSocket (`ws://`) listen address. Like `plain_bind`,
    /// loopback-only unless `allow_plain_nonlocal = true` (prefer `wss_bind`).
    #[serde(default)]
    pub ws_bind: Option<SocketAddr>,
    /// Optional secure WebSocket (`wss://`) listen address, terminating TLS with
    /// the same certificate as `tls_bind` before the WebSocket handshake.
    #[serde(default)]
    pub wss_bind: Option<SocketAddr>,
    /// Optional connection password: clients must send a matching `PASS`
    /// before completing registration (`ERR_PASSWDMISMATCH` otherwise).
    #[serde(default)]
    pub password: Option<String>,
    /// Optional IRCv3 strict transport security (`sts`) policy. When set,
    /// plaintext connections are told the TLS port to upgrade to and TLS
    /// connections are told how long to remember the policy.
    #[serde(default)]
    pub sts: Option<StsConfig>,
}

/// IRCv3 `sts` (strict transport security) policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StsConfig {
    /// The TLS port clients should reconnect to (advertised on plaintext
    /// connections as `sts=port=<port>`).
    pub port: u16,
    /// How long (seconds) clients should persist the policy (advertised on TLS
    /// connections as `sts=duration=<secs>`). `0` tells clients to forget it.
    pub duration: u64,
    /// Ask clients to include this server in STS preload lists.
    #[serde(default)]
    pub preload: bool,
}

fn default_network() -> String {
    "ferrixnet".to_owned()
}

fn default_sid() -> String {
    "42F".to_owned()
}

/// TLS certificate material. Either provide `cert` + `key`, or set
/// `self_signed_dev = true` to generate an ephemeral certificate at startup.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to a PEM certificate chain.
    #[serde(default)]
    pub cert: Option<PathBuf>,
    /// Path to a PEM private key.
    #[serde(default)]
    pub key: Option<PathBuf>,
    /// Generate an ephemeral self-signed certificate at startup (development
    /// only). Ignored when `cert`/`key` are set.
    #[serde(default)]
    pub self_signed_dev: bool,
    /// Subject alternative names for the generated dev certificate.
    #[serde(default = "default_dev_hostnames")]
    pub dev_hostnames: Vec<String>,
}

/// Wire-length and connection-timing budgets.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum tag-section length in bytes (see [`Limits::max_tag_bytes`]).
    #[serde(default = "default_max_tag_bytes")]
    pub max_tag_bytes: usize,
    /// Maximum message-body length in bytes (see [`Limits::max_body_bytes`]).
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    /// Fatal frame length: a line longer than this drops the connection.
    #[serde(default = "default_max_line_bytes")]
    pub max_line_bytes: usize,
    /// Seconds a connection may remain unregistered before being closed.
    #[serde(default = "default_registration_timeout_secs")]
    pub registration_timeout_secs: u64,
    /// Seconds allowed for the TLS handshake before the attempt is aborted.
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    /// Maximum simultaneous connections from a single source IP (throttling).
    #[serde(default = "default_max_clients_per_ip")]
    pub max_clients_per_ip: u32,
    /// Maximum channels a single client may be in at once (advertised as
    /// `CHANLIMIT`/`MAXCHANNELS`; a memory-amplification guard).
    #[serde(default = "default_max_channels")]
    pub max_channels: usize,
    /// Outbound SendQ depth (bounded mailbox capacity, in lines). A client whose
    /// queue overflows is disconnected.
    #[serde(default = "default_sendq_lines")]
    pub sendq_lines: usize,
    /// Inbound command burst allowance (token-bucket size).
    #[serde(default = "default_recv_burst")]
    pub recv_burst: u32,
    /// Sustained inbound command rate per second (token-bucket refill).
    #[serde(default = "default_recv_rate")]
    pub recv_rate: u32,
    /// Maximum retained messages per target for `chathistory`.
    #[serde(default = "default_history_len")]
    pub history_len: usize,
    /// Maximum number of distinct history targets (channels + DM conversations)
    /// kept in memory. Bounds total history memory regardless of how many
    /// channels or direct-message pairs are active (see [`crate::history`]).
    #[serde(default = "default_history_max_targets")]
    pub history_max_targets: usize,
    /// Idle seconds before the server pings a quiet client (and disconnects it
    /// on a second miss).
    #[serde(default = "default_ping_interval_secs")]
    pub ping_interval_secs: u64,
}

impl LimitsConfig {
    /// Parser budgets derived from this configuration.
    #[must_use]
    pub fn parser_limits(&self) -> Limits {
        Limits {
            max_tag_bytes: self.max_tag_bytes,
            max_body_bytes: self.max_body_bytes,
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_tag_bytes: default_max_tag_bytes(),
            max_body_bytes: default_max_body_bytes(),
            max_line_bytes: default_max_line_bytes(),
            registration_timeout_secs: default_registration_timeout_secs(),
            handshake_timeout_secs: default_handshake_timeout_secs(),
            max_clients_per_ip: default_max_clients_per_ip(),
            max_channels: default_max_channels(),
            sendq_lines: default_sendq_lines(),
            recv_burst: default_recv_burst(),
            recv_rate: default_recv_rate(),
            history_len: default_history_len(),
            history_max_targets: default_history_max_targets(),
            ping_interval_secs: default_ping_interval_secs(),
        }
    }
}

fn default_ping_interval_secs() -> u64 {
    120
}

fn default_max_clients_per_ip() -> u32 {
    10
}
fn default_max_channels() -> usize {
    50
}
fn default_sendq_lines() -> usize {
    2048
}
fn default_recv_burst() -> u32 {
    20
}
fn default_recv_rate() -> u32 {
    10
}
fn default_history_len() -> usize {
    500
}
fn default_history_max_targets() -> usize {
    50_000
}

fn default_dev_hostnames() -> Vec<String> {
    vec!["localhost".to_owned()]
}
fn default_max_tag_bytes() -> usize {
    Limits::IRCV3_TAG_BYTES
}
fn default_max_body_bytes() -> usize {
    Limits::RFC1459_BODY_BYTES
}
fn default_max_line_bytes() -> usize {
    Limits::IRCV3_TAG_BYTES + Limits::RFC1459_BODY_BYTES + 1
}
fn default_registration_timeout_secs() -> u64 {
    30
}
fn default_handshake_timeout_secs() -> u64 {
    15
}

/// Errors that can occur while loading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The config file could not be read.
    // The `source` field is chained automatically by thiserror, so it is NOT
    // interpolated here — doing so would print the underlying error twice under
    // anyhow's `{:#}` chain formatting.
    #[error("reading config {path}")]
    Read {
        /// The path we tried to read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The config file could not be parsed / validated.
    #[error("parsing config {path}")]
    Parse {
        /// The path we tried to parse.
        path: PathBuf,
        /// The underlying TOML error. Boxed because `toml::de::Error` is large
        /// (it carries the input span); keeping it inline would bloat every
        /// `Result<_, ConfigError>` on the cold config-loading path
        /// (clippy::result_large_err).
        source: Box<toml::de::Error>,
    },
    /// The configuration was internally inconsistent.
    #[error("invalid config: {0}")]
    Invalid(String),
}

impl Config {
    /// Load and validate configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be read, fails to parse, or
    /// is semantically invalid.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Config = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Parse and validate configuration from an in-memory TOML string.
    ///
    /// Used for the built-in `--dev` configuration; [`Config::load`] wraps this
    /// with file I/O and path-aware error messages.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the text fails to parse or is semantically
    /// invalid.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: PathBuf::from("<builtin>"),
            source: Box::new(source),
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Check cross-field invariants that the type system cannot.
    fn validate(&self) -> Result<(), ConfigError> {
        // A plaintext listener on a non-loopback address is refused unless the
        // operator explicitly opts in.
        if let Some(addr) = self.server.plain_bind
            && !addr.ip().is_loopback()
            && !self.server.allow_plain_nonlocal
        {
            return Err(ConfigError::Invalid(format!(
                "plain_bind {addr} is not loopback; set allow_plain_nonlocal = true to permit \
                     cleartext on a public interface (not recommended)"
            )));
        }
        // The plaintext WebSocket listener is held to the same rule.
        if let Some(addr) = self.server.ws_bind
            && !addr.ip().is_loopback()
            && !self.server.allow_plain_nonlocal
        {
            return Err(ConfigError::Invalid(format!(
                "ws_bind {addr} is not loopback; set allow_plain_nonlocal = true to permit \
                     cleartext WebSocket on a public interface (use wss_bind instead)"
            )));
        }

        // TLS must have a way to obtain a certificate.
        let has_files = self.tls.cert.is_some() && self.tls.key.is_some();
        let half_files = self.tls.cert.is_some() ^ self.tls.key.is_some();
        if half_files {
            return Err(ConfigError::Invalid(
                "tls.cert and tls.key must be set together".to_owned(),
            ));
        }
        if !has_files && !self.tls.self_signed_dev {
            return Err(ConfigError::Invalid(
                "tls requires either cert+key or self_signed_dev = true".to_owned(),
            ));
        }

        // A SCRAM credential that cannot be parsed would silently disable SCRAM
        // for that account at startup; fail loudly here instead (so `ferrixd
        // check` catches it before a restart does).
        for account in &self.accounts {
            if let Some(token) = &account.scram
                && crate::scram::ScramCreds::decode(token).is_none()
            {
                return Err(ConfigError::Invalid(format!(
                    "account {}: malformed scram credential (expected \
                         <iterations>:<b64 salt>:<b64 stored_key>:<b64 server_key>, \
                         as printed by `ferrixd hash-password --toml`)",
                    account.name
                )));
            }
        }

        // The fatal frame length must be able to hold a maximal legal message.
        let min_line = self.limits.max_tag_bytes + self.limits.max_body_bytes;
        if self.limits.max_line_bytes < min_line {
            return Err(ConfigError::Invalid(format!(
                "limits.max_line_bytes ({}) must be >= max_tag_bytes + max_body_bytes ({})",
                self.limits.max_line_bytes, min_line
            )));
        }

        Ok(())
    }
}
