//! Command-line interface.
//!
//! `ferrixd` is primarily a daemon, but a good operator experience needs more
//! than "start the server": validating configuration before a restart, minting
//! development certificates, hashing passwords for the config file, computing
//! the certificate fingerprints used for SASL EXTERNAL and S2S link pinning, and
//! generating shell completions. Those live here as subcommands so the single
//! `ferrixd` binary is self-sufficient — no side scripts, no `openssl` incantations.
//!
//! Running with no subcommand (or `run`) starts the server; every other
//! subcommand is a short-lived utility that prints to stdout and exits.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use clap::builder::styling::{AnsiColor, Styles};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::connection::ConnContext;
use crate::state::{self, Server, ServerInfo};
use crate::{listener, tls};

/// Default configuration path when `--config` is not given.
const DEFAULT_CONFIG: &str = "ferrixd.toml";

/// The example configuration, embedded so `gen-config` needs no data files.
const EXAMPLE_CONFIG: &str = include_str!("../../../ferrixd.example.toml");

/// Built-in zero-setup configuration used by `run --dev`.
const DEV_CONFIG: &str = r#"
[server]
name = "dev.ferrixd.local"
network = "ferrixnet-dev"
tls_bind = "127.0.0.1:6697"
plain_bind = "127.0.0.1:6667"
motd = [
    "ferrixd development server.",
    "Ephemeral self-signed TLS — never expose this to a network.",
]

[tls]
self_signed_dev = true
dev_hostnames = ["localhost"]
"#;

/// Worked examples appended to the top-level `--help`.
const EXAMPLES: &str = "\
EXAMPLES:
  ferrixd                          Run using ./ferrixd.toml
  ferrixd -c /etc/ferrixd.toml     Run using a specific config
  ferrixd run --dev                Run a zero-config local dev server
  ferrixd check                    Validate the config and show what it starts
  ferrixd gen-config               Write a starter ferrixd.toml
  ferrixd gen-cert -H irc.me.test  Mint a self-signed cert + key
  ferrixd hash-password            Hash a password for [[accounts]]/[[operators]]
  ferrixd fingerprint cert.pem     Print a cert fingerprint for links/EXTERNAL
  ferrixd completions bash         Print a bash completion script

Set RUST_LOG (or --log) to tune logging, e.g. RUST_LOG=ferrixd=debug.";

/// ferrixd — the Ferrous IRC Daemon.
#[derive(Debug, Parser)]
#[command(
    name = "ferrixd",
    version,
    about = "Ferrous IRC Daemon — a memory-safe, IRCv3-complete IRC server",
    after_help = EXAMPLES,
    styles = help_styles(),
)]
struct Cli {
    #[command(flatten)]
    global: GlobalOpts,
    #[command(subcommand)]
    command: Option<Command>,
}

/// Options shared by every subcommand.
#[derive(Debug, clap::Args)]
struct GlobalOpts {
    /// Path to the TOML configuration file (used by `run` and `check`).
    #[arg(
        short = 'c',
        long,
        value_name = "PATH",
        default_value = DEFAULT_CONFIG,
        global = true
    )]
    config: PathBuf,

    /// Log verbosity, overriding RUST_LOG (error|warn|info|debug|trace, or a
    /// full tracing filter such as `ferrixd=debug,info`).
    #[arg(long, value_name = "FILTER", global = true)]
    log: Option<String>,

    /// Log output format.
    #[arg(
        long,
        value_enum,
        value_name = "FORMAT",
        default_value = "full",
        global = true
    )]
    log_format: LogFormat,

    /// When to colorize output.
    #[arg(
        long,
        value_enum,
        value_name = "WHEN",
        default_value = "auto",
        global = true
    )]
    color: ColorWhen,
}

/// How log records are rendered.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogFormat {
    /// One line per event with fields (the default).
    Full,
    /// Denser single-line output.
    Compact,
    /// Multi-line, human-friendly output.
    Pretty,
}

/// When colored output is emitted.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum ColorWhen {
    /// Colorize when writing to a terminal and NO_COLOR is unset.
    Auto,
    /// Always colorize.
    Always,
    /// Never colorize.
    Never,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the IRC server (this is the default when no subcommand is given).
    Run {
        /// Ignore the config file and run a zero-setup local dev server
        /// (self-signed TLS on 127.0.0.1:6697, plaintext on 127.0.0.1:6667).
        #[arg(long)]
        dev: bool,
    },

    /// Validate the configuration and print what it would start, then exit.
    Check,

    /// Write a starter configuration file.
    #[command(name = "gen-config", visible_alias = "genconfig")]
    GenConfig {
        /// Where to write the config.
        #[arg(short = 'o', long, value_name = "PATH", default_value = DEFAULT_CONFIG)]
        output: PathBuf,
        /// Overwrite an existing file.
        #[arg(short = 'f', long)]
        force: bool,
    },

    /// Generate a self-signed TLS certificate and private key (PEM).
    #[command(name = "gen-cert", visible_alias = "gencert")]
    GenCert {
        /// Subject alternative name (repeatable; defaults to `localhost`).
        #[arg(short = 'H', long = "host", value_name = "NAME")]
        hosts: Vec<String>,
        /// Where to write the certificate.
        #[arg(long, value_name = "PATH", default_value = "cert.pem")]
        cert: PathBuf,
        /// Where to write the private key.
        #[arg(long, value_name = "PATH", default_value = "key.pem")]
        key: PathBuf,
        /// Overwrite existing files.
        #[arg(short = 'f', long)]
        force: bool,
    },

    /// Hash a password (Argon2id) for an [[accounts]] or [[operators]] entry.
    ///
    /// The password is read without echo from the terminal, or as the first
    /// line of stdin when piped. The printed hash goes in `password_hash`.
    #[command(name = "hash-password", visible_alias = "hashpw")]
    HashPassword {
        /// Prompt twice and require the two entries to match.
        #[arg(long)]
        confirm: bool,
        /// Print ready-to-paste config lines — `password_hash` plus a `scram`
        /// credential, which an account needs for SASL SCRAM-SHA-256 (the
        /// server cannot derive it from the hash).
        #[arg(long)]
        toml: bool,
    },

    /// Print the SHA-256 fingerprint of a certificate.
    ///
    /// Use it for `[[links]].fingerprint` or an account's SASL EXTERNAL
    /// `fingerprints`.
    Fingerprint {
        /// Path to a PEM certificate.
        #[arg(value_name = "CERT.pem")]
        path: PathBuf,
    },

    /// Print a shell completion script for the given shell.
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

/// clap help color scheme.
fn help_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Green.on_default().bold())
        .usage(AnsiColor::Green.on_default().bold())
        .literal(AnsiColor::Cyan.on_default().bold())
        .placeholder(AnsiColor::Cyan.on_default())
}

/// CLI entrypoint. Parses arguments, dispatches to a subcommand, and turns any
/// error into a tidy diagnostic and a non-zero exit code.
#[must_use]
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    let color = resolve_color(cli.global.color);
    match dispatch(cli) {
        Ok(code) => code,
        Err(err) => {
            let style = Style::new(color);
            eprintln!("{} {err:#}", style.red("error:"));
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> Result<ExitCode> {
    let color = resolve_color(cli.global.color);
    let Cli { global, command } = cli;
    match command {
        None | Some(Command::Run { dev: false }) => cmd_run(&global, color, false),
        Some(Command::Run { dev: true }) => cmd_run(&global, color, true),
        Some(Command::Check) => cmd_check(&global, color),
        Some(Command::GenConfig { output, force }) => cmd_gen_config(&output, force, color),
        Some(Command::GenCert {
            hosts,
            cert,
            key,
            force,
        }) => cmd_gen_cert(&hosts, &cert, &key, force, color),
        Some(Command::HashPassword { confirm, toml }) => cmd_hash_password(confirm, toml),
        Some(Command::Fingerprint { path }) => cmd_fingerprint(&path),
        Some(Command::Completions { shell }) => cmd_completions(shell),
    }
}

// ---------------------------------------------------------------------------
// run — start the server
// ---------------------------------------------------------------------------

fn cmd_run(global: &GlobalOpts, color: bool, dev: bool) -> Result<ExitCode> {
    let (config, config_path) = if dev {
        (
            Config::from_toml(DEV_CONFIG).context("loading the built-in dev configuration")?,
            PathBuf::from("<dev>"),
        )
    } else {
        (
            Config::load(&global.config).with_context(|| {
                format!("loading configuration from {}", global.config.display())
            })?,
            global.config.clone(),
        )
    };

    init_tracing(global, color);
    print_banner(&config, global, color, dev);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building Tokio runtime")?;
    runtime.block_on(serve(config, config_path))?;
    Ok(ExitCode::SUCCESS)
}

async fn serve(config: Config, config_path: PathBuf) -> Result<()> {
    let tls_config = tls::build_server_config(&config.tls).context("configuring TLS")?;
    let acceptor = TlsAcceptor::from(tls_config);

    let server = Server::new(ServerInfo {
        name: config.server.name.clone(),
        sid: config.server.sid.clone(),
        network: config.server.network.clone(),
        version: concat!("ferrixd-", env!("CARGO_PKG_VERSION")).to_owned(),
        created: state::format_datetime(state::now_unix()),
        casemapping: config.server.casemapping,
        motd: config.server.motd.clone(),
        history_len: config.limits.history_len,
        history_max_targets: config.limits.history_max_targets,
        max_channels: config.limits.max_channels,
        cloak_key: config.server.cloak_key.clone(),
        sts: config.server.sts.clone(),
    });
    server.set_config_path(config_path);
    server
        .apply_config(&config)
        .map_err(|e| anyhow::anyhow!("applying config: {e}"))?;
    info!(
        accounts = server.accounts.len(),
        operators = server.opers.len(),
        bans = config.bans.len(),
        "seeded auth data"
    );

    // Optional SQLite persistence: load recent history and attach write-behind.
    if let Some(persistence) = &config.persistence {
        let path = persistence.path.display().to_string();
        let (loaded, sink) = crate::persist::open(&path, persistence.load_limit)
            .context("opening history persistence")?;
        let count = loaded.messages.len();
        for (folded, message) in loaded.messages {
            server.history.load(&folded, message);
        }
        server.history.seed_next_id(loaded.next_id);
        server.history.attach_persistence(sink);
        info!(path = %path, loaded = count, "history persistence enabled");

        // Channel registrations share the database (separate connection/table).
        let (store, records) =
            crate::chanreg::ChanRegStore::open(&path).context("opening channel registrations")?;
        let registered = records.len();
        server.attach_chanreg(store, records);
        info!(path = %path, registered, "channel registration enabled");

        // Self-registered accounts share the same database.
        let restored = server.restore_persisted_accounts();
        info!(path = %path, restored, "account registration enabled");
    }

    // Optional WebAssembly plugin host.
    if let Some(plugins_cfg) = &config.plugins {
        let mut host = crate::plugin::PluginHost::new(plugins_cfg.fuel);
        match host.load_dir(&plugins_cfg.dir) {
            Ok(count) => info!(count, dir = %plugins_cfg.dir.display(), "WASM plugins loaded"),
            Err(err) => error!(%err, "failed to read plugin directory"),
        }
        server.attach_plugins(host);
    }

    let params = ConnContext {
        server,
        limits: config.limits.parser_limits(),
        max_line: config.limits.max_line_bytes,
        registration_timeout: Duration::from_secs(config.limits.registration_timeout_secs),
        max_clients_per_ip: config.limits.max_clients_per_ip,
        sendq_lines: config.limits.sendq_lines,
        recv_burst: config.limits.recv_burst,
        recv_rate: config.limits.recv_rate,
        ping_interval: Duration::from_secs(config.limits.ping_interval_secs),
    };
    let handshake_timeout = Duration::from_secs(config.limits.handshake_timeout_secs);

    // Optional Prometheus metrics endpoint.
    if let Some(metrics_cfg) = &config.metrics {
        let addr = metrics_cfg.bind;
        let metrics_server = params.server.clone();
        tokio::spawn(async move {
            if let Err(err) = crate::metrics::serve(addr, metrics_server).await {
                error!(%err, "metrics endpoint exited with error");
            }
        });
    }

    // S2S peer links: outbound connectors and an optional listener.
    if !config.links.is_empty() {
        let link_client = tls::build_link_client_config(&config.tls).context("link TLS config")?;
        for link in &config.links {
            tokio::spawn(crate::link::run_outbound(
                link.clone(),
                params.server.clone(),
                link_client.clone(),
            ));
        }
    }
    if let Some(link_addr) = config.server.link_bind {
        let link_listener = TcpListener::bind(link_addr)
            .await
            .with_context(|| format!("binding link listener on {link_addr}"))?;
        let link_server = params.server.clone();
        let link_acceptor = acceptor.clone();
        let links = config.links.clone();
        tokio::spawn(async move {
            if let Err(err) =
                crate::link::run_link_listener(link_listener, link_acceptor, link_server, links)
                    .await
            {
                error!(%err, "S2S link listener exited with error");
            }
        });
    }

    // Bind the TLS listener up front so a bind failure is fatal at startup.
    let tls_addr = config.server.tls_bind;
    let tls_listener = TcpListener::bind(tls_addr)
        .await
        .with_context(|| format!("binding TLS listener on {tls_addr}"))?;
    let tls_task = tokio::spawn(listener::run_tls(
        tls_listener,
        acceptor,
        params.clone(),
        handshake_timeout,
    ));

    // Optionally bind and spawn the plaintext listener.
    let plain_task = match config.server.plain_bind {
        Some(addr) => {
            let plain_listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding plaintext listener on {addr}"))?;
            Some(tokio::spawn(listener::run_plain(
                plain_listener,
                params.clone(),
            )))
        }
        None => None,
    };

    info!("ferrixd is running; press Ctrl-C to stop");

    // Run until a listener fails fatally or the operator interrupts.
    tokio::select! {
        result = tls_task => {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(err)) => error!(%err, "TLS listener exited with error"),
                Err(err) => error!(%err, "TLS listener task panicked"),
            }
        }
        result = flatten_optional(plain_task) => {
            if let Err(err) = result {
                error!(%err, "plaintext listener exited with error");
            }
        }
        signal = tokio::signal::ctrl_c() => {
            match signal {
                Ok(()) => info!("received Ctrl-C; shutting down"),
                Err(err) => error!(%err, "failed to listen for Ctrl-C; shutting down"),
            }
        }
        signal = terminate_signal() => {
            match signal {
                Ok(()) => info!("received SIGTERM; shutting down"),
                Err(err) => error!(%err, "failed to listen for SIGTERM; shutting down"),
            }
        }
        () = params.server.shutdown_requested() => {
            info!("shutdown requested by an operator (DIE); shutting down");
        }
    }

    // The history writer runs write-behind on its own thread; give whatever it
    // has already accepted a bounded window to reach disk before the process
    // (and with it that thread) goes away.
    drain_persistence(&params.server).await;
    Ok(())
}

/// How long a graceful shutdown waits for the persistence queue to commit.
const SHUTDOWN_FLUSH_GRACE: Duration = Duration::from_secs(2);

/// Wait (up to [`SHUTDOWN_FLUSH_GRACE`]) for the write-behind persistence queue
/// to commit everything it has accepted. A no-op when persistence is disabled.
async fn drain_persistence(server: &Arc<state::Server>) {
    let Some(drained) = server.history.flush_barrier() else {
        return;
    };
    match tokio::time::timeout(SHUTDOWN_FLUSH_GRACE, drained).await {
        Ok(Ok(())) => info!("history persistence queue drained"),
        Ok(Err(_)) => warn!("history persistence writer stopped before draining the queue"),
        Err(_) => warn!(
            grace_secs = SHUTDOWN_FLUSH_GRACE.as_secs(),
            "history persistence queue did not drain within the grace period"
        ),
    }
}

/// Resolve when the process receives SIGTERM — what `docker stop`, Kubernetes,
/// and most service managers send — so containers shut down as gracefully as a
/// Ctrl-C. Pends forever on platforms without Unix signals.
async fn terminate_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        sigterm.recv().await;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::future::pending().await
    }
}

/// Await an optional listener task, or pend forever if there is none — so the
/// `select!` arm is inert when no plaintext listener is configured.
async fn flatten_optional(task: Option<tokio::task::JoinHandle<Result<()>>>) -> Result<()> {
    match task {
        Some(handle) => match handle.await {
            Ok(inner) => inner,
            Err(join_err) => Err(anyhow::anyhow!("listener task panicked: {join_err}")),
        },
        None => std::future::pending().await,
    }
}

// ---------------------------------------------------------------------------
// check — validate configuration
// ---------------------------------------------------------------------------

fn cmd_check(global: &GlobalOpts, color: bool) -> Result<ExitCode> {
    let config = Config::load(&global.config)
        .with_context(|| format!("loading configuration from {}", global.config.display()))?;
    // Actually build the TLS material so cert/key problems surface here, not at
    // the next restart.
    tls::build_server_config(&config.tls).context("validating TLS certificate material")?;

    let style = Style::new(color);
    println!(
        "{} {}",
        style.green("✓"),
        style.bold(&format!("{} is valid", global.config.display()))
    );
    println!();
    print_summary(&config, &style);
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// gen-config — write a starter config
// ---------------------------------------------------------------------------

fn cmd_gen_config(output: &Path, force: bool, color: bool) -> Result<ExitCode> {
    guard_new_file(output, force)?;
    std::fs::write(output, EXAMPLE_CONFIG)
        .with_context(|| format!("writing {}", output.display()))?;
    let style = Style::new(color);
    println!(
        "{} wrote starter config to {}",
        style.green("✓"),
        style.bold(&output.display().to_string())
    );
    println!(
        "  {} edit it, then run: {}",
        style.dim("→"),
        style.cyan(&format!("ferrixd -c {}", output.display()))
    );
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// gen-cert — mint a self-signed certificate
// ---------------------------------------------------------------------------

fn cmd_gen_cert(
    hosts: &[String],
    cert_path: &Path,
    key_path: &Path,
    force: bool,
    color: bool,
) -> Result<ExitCode> {
    // Guard both destinations before writing either, so a name clash doesn't
    // leave a half-written pair on disk.
    guard_new_file(cert_path, force)?;
    guard_new_file(key_path, force)?;

    let generated = tls::generate_self_signed_pem(hosts)?;
    std::fs::write(cert_path, &generated.cert_pem)
        .with_context(|| format!("writing {}", cert_path.display()))?;
    std::fs::write(key_path, &generated.key_pem)
        .with_context(|| format!("writing {}", key_path.display()))?;
    restrict_permissions(key_path)?;

    let style = Style::new(color);
    let shown_hosts = if hosts.is_empty() {
        "localhost".to_owned()
    } else {
        hosts.join(", ")
    };
    println!("{} generated self-signed certificate", style.green("✓"));
    println!("  {}   {}", style.dim("hosts      "), shown_hosts);
    println!("  {}   {}", style.dim("cert       "), cert_path.display());
    println!(
        "  {}   {} {}",
        style.dim("key        "),
        key_path.display(),
        style.dim("(mode 0600 on unix)")
    );
    println!(
        "  {}   {}",
        style.dim("fingerprint"),
        style.cyan(&generated.fingerprint)
    );
    println!();
    println!("Point your config at it:");
    println!("{}", style.dim("  [tls]"));
    println!(
        "{}",
        style.dim(&format!("  cert = \"{}\"", cert_path.display()))
    );
    println!(
        "{}",
        style.dim(&format!("  key  = \"{}\"", key_path.display()))
    );
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// hash-password — Argon2id PHC hash for the config file
// ---------------------------------------------------------------------------

fn cmd_hash_password(confirm: bool, toml: bool) -> Result<ExitCode> {
    let password = read_password(confirm)?;
    if password.is_empty() {
        anyhow::bail!("refusing to hash an empty password");
    }
    let hash = hash_argon2(&password)?;
    if !toml {
        println!("{hash}");
        return Ok(ExitCode::SUCCESS);
    }
    // Both credentials for the same password: the Argon2 hash verifies SASL
    // PLAIN, the SCRAM token enables SCRAM-SHA-256 (which cannot be derived
    // from the hash, so it has to be minted here alongside it).
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt)
        .map_err(|e| anyhow::anyhow!("gathering entropy for the SCRAM salt: {e}"))?;
    let creds = crate::scram::derive(
        &password,
        &salt,
        crate::account::AccountStore::scram_iterations(),
    );
    println!("password_hash = \"{hash}\"");
    println!("scram = \"{}\"", creds.encode());
    Ok(ExitCode::SUCCESS)
}

fn read_password(confirm: bool) -> Result<String> {
    if std::io::stdin().is_terminal() {
        let password = rpassword::prompt_password("Password: ").context("reading password")?;
        if confirm {
            let again =
                rpassword::prompt_password("Confirm password: ").context("reading confirmation")?;
            if password != again {
                anyhow::bail!("passwords did not match");
            }
        }
        Ok(password)
    } else {
        // Piped input: take the first line, dropping the trailing newline.
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("reading password from stdin")?;
        Ok(line.trim_end_matches(['\n', '\r']).to_owned())
    }
}

/// Hash a password to an Argon2id PHC string using a fresh random salt.
fn hash_argon2(password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|e| anyhow::anyhow!("gathering entropy: {e}"))?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow::anyhow!("encoding salt: {e}"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))
}

// ---------------------------------------------------------------------------
// fingerprint — SHA-256 of a certificate
// ---------------------------------------------------------------------------

fn cmd_fingerprint(path: &Path) -> Result<ExitCode> {
    let fingerprint = tls::fingerprint_file(path)?;
    // Print only the value so it composes in shell substitutions.
    println!("{fingerprint}");
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// completions — shell completion script
// ---------------------------------------------------------------------------

fn cmd_completions(shell: clap_complete::Shell) -> Result<ExitCode> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_owned();
    clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

/// Refuse to clobber an existing file unless `force` is set.
fn guard_new_file(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists (pass --force to overwrite)",
            path.display()
        );
    }
    Ok(())
}

/// Tighten a private key file to owner-only on unix; a no-op elsewhere.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn resolve_color(when: ColorWhen) -> bool {
    match when {
        ColorWhen::Always => true,
        ColorWhen::Never => false,
        ColorWhen::Auto => {
            std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
        }
    }
}

fn init_tracing(global: &GlobalOpts, color: bool) {
    let filter = match &global.log {
        Some(directive) => EnvFilter::try_new(directive).unwrap_or_else(|_| EnvFilter::new("info")),
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    };
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(color)
        .with_target(false);
    match global.log_format {
        LogFormat::Full => builder.init(),
        LogFormat::Compact => builder.compact().init(),
        LogFormat::Pretty => builder.pretty().init(),
    }
}

/// The startup banner: a compact, at-a-glance summary of what is coming up.
fn print_banner(config: &Config, global: &GlobalOpts, color: bool, dev: bool) {
    let style = Style::new(color);
    let version = env!("CARGO_PKG_VERSION");
    println!();
    println!(
        "  {} {}  {}",
        style.bold("ferrixd"),
        style.cyan(version),
        style.dim("· Ferrous IRC Daemon")
    );
    if dev {
        println!(
            "  {}",
            style.yellow("development mode — self-signed TLS, do not expose")
        );
    }
    let rule = "─".repeat(52);
    println!("  {}", style.dim(&rule));
    print_summary(config, &style);
    let log = global
        .log
        .clone()
        .or_else(|| std::env::var("RUST_LOG").ok())
        .unwrap_or_else(|| "info".to_owned());
    banner_row(
        &style,
        "log",
        &format!("{log} ({})", log_format_name(global.log_format)),
    );
    println!("  {}", style.dim(&rule));
    println!();
}

/// The shared body of the banner and `check` output.
fn print_summary(config: &Config, style: &Style) {
    let server = &config.server;
    banner_row(
        style,
        "server",
        &format!(
            "{}  {}",
            style.bold(&server.name),
            style.dim(&format!("network {} · SID {}", server.network, server.sid))
        ),
    );

    let tls_source = if config.tls.cert.is_some() {
        "certificate files".to_owned()
    } else {
        format!("self-signed [{}]", config.tls.dev_hostnames.join(", "))
    };
    banner_row(
        style,
        "tls",
        &format!("{}  {}", server.tls_bind, style.dim(&tls_source)),
    );

    match server.plain_bind {
        Some(addr) => banner_row(style, "plain", &addr.to_string()),
        None => banner_row(style, "plain", &style.dim("disabled")),
    }

    if server.link_bind.is_some() || !config.links.is_empty() {
        let listen = server
            .link_bind
            .map(|a| format!("listen {a}"))
            .unwrap_or_else(|| "no listener".to_owned());
        banner_row(
            style,
            "links",
            &format!("{listen} · {} configured", config.links.len()),
        );
    }

    if let Some(metrics) = &config.metrics {
        banner_row(style, "metrics", &format!("{}/metrics", metrics.bind));
    }

    match &config.persistence {
        Some(p) => banner_row(
            style,
            "history",
            &format!("{} {}", p.path.display(), style.dim("(persistent)")),
        ),
        None => banner_row(style, "history", &style.dim("in-memory")),
    }

    if let Some(plugins) = &config.plugins {
        banner_row(style, "plugins", &plugins.dir.display().to_string());
    }

    banner_row(
        style,
        "auth",
        &format!(
            "{} · {} · {}",
            plural(config.accounts.len(), "account", "accounts"),
            plural(config.operators.len(), "operator", "operators"),
            plural(config.bans.len(), "ban", "bans"),
        ),
    );
}

fn banner_row(style: &Style, label: &str, value: &str) {
    println!("  {}  {value}", style.dim(&format!("{label:<9}")));
}

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

fn log_format_name(format: LogFormat) -> &'static str {
    match format {
        LogFormat::Full => "full",
        LogFormat::Compact => "compact",
        LogFormat::Pretty => "pretty",
    }
}

/// A tiny ANSI styler that no-ops when color is disabled — enough for the banner
/// and utility output without pulling in a color crate.
#[derive(Debug, Clone, Copy)]
struct Style {
    color: bool,
}

impl Style {
    fn new(color: bool) -> Self {
        Self { color }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }
    fn dim(&self, text: &str) -> String {
        self.paint("2", text)
    }
    fn red(&self, text: &str) -> String {
        self.paint("31", text)
    }
    fn green(&self, text: &str) -> String {
        self.paint("32", text)
    }
    fn yellow(&self, text: &str) -> String {
        self.paint("33", text)
    }
    fn cyan(&self, text: &str) -> String {
        self.paint("36", text)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        // clap's own internal consistency checker; catches conflicting args,
        // duplicate flags, bad value parsers, etc. at test time.
        Cli::command().debug_assert();
    }

    #[test]
    fn dev_config_parses_and_validates() {
        let config = Config::from_toml(DEV_CONFIG).expect("built-in dev config must be valid");
        assert!(config.server.plain_bind.is_some());
        assert!(config.tls.self_signed_dev);
    }

    #[test]
    fn embedded_example_config_is_valid() {
        Config::from_toml(EXAMPLE_CONFIG).expect("shipped example config must be valid");
    }

    #[test]
    fn hashing_produces_verifiable_argon2() {
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        let hash = hash_argon2("hunter2").expect("hashing should succeed");
        let parsed = PasswordHash::new(&hash).expect("valid PHC string");
        assert!(Argon2::default()
            .verify_password(b"hunter2", &parsed)
            .is_ok());
        assert!(Argon2::default()
            .verify_password(b"wrong", &parsed)
            .is_err());
    }

    #[test]
    fn style_is_inert_without_color() {
        let plain = Style::new(false);
        assert_eq!(plain.bold("x"), "x");
        let colored = Style::new(true);
        assert!(colored.bold("x").contains("\x1b["));
    }

    #[test]
    fn plural_agrees_with_count() {
        assert_eq!(plural(0, "ban", "bans"), "0 bans");
        assert_eq!(plural(1, "ban", "bans"), "1 ban");
        assert_eq!(plural(3, "ban", "bans"), "3 bans");
    }
}
