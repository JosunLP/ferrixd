<!-- markdownlint-disable MD033 MD036 MD041 -->
<div align="center">

<img src="docs/public/logo.svg" alt="ferrixd — Fe, element 26" width="120">

# ferrixd

**The Ferrous IRC Daemon**

A from-scratch, memory-safe, IRCv3-complete IRC server in Rust —<br>
TLS-first, federated over mutual TLS, and load-tested to
100,000 concurrent connections on a single node.

[![CI](https://github.com/josunlp/ferrixd/actions/workflows/ci.yml/badge.svg)](https://github.com/josunlp/ferrixd/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-stable-d4581e?logo=rust&logoColor=white)
![unsafe_code](https://img.shields.io/badge/unsafe__code-forbid-1b1815)
![IRCv3](https://img.shields.io/badge/IRCv3-29_capabilities-d4581e)
![License](https://img.shields.io/badge/license-MIT_%2F_Apache--2.0-1b1815)

**[📖 Documentation](https://josunlp.github.io/ferrixd/)** ·
[Quick Start](https://josunlp.github.io/ferrixd/guide/quick-start) ·
[Installation](https://josunlp.github.io/ferrixd/guide/installation) ·
[Configuration](https://josunlp.github.io/ferrixd/guide/configuration) ·
[Federation](https://josunlp.github.io/ferrixd/guide/federation) ·
[CLI](https://josunlp.github.io/ferrixd/reference/cli)

</div>

IRC is the simplest federated chat protocol that actually works: plain text
over a socket, readable with `openssl s_client`, implementable in an
afternoon. What it never had was a server built like it matters — memory-safe,
spec-complete, hostile-input-proof, and honest about persistence. **ferrixd**
is that server: element 26, oxidised into software.

**Version 1.1.0** builds on the stable 1.0 line: a security-hardened, IRCv3
server with persistent message history, a federated server-to-server mesh, a
sandboxed WASM plugin host, and a demonstrated density of ~100k concurrent
connections per node — now also reachable over WebSockets, with WEBIRC gateway
support, bot-mode, live link management, and TLS reload without a restart. The
[documentation](https://josunlp.github.io/ferrixd/) (source in
[`docs/`](docs/), deployed via GitHub Pages) covers installation, the full
configuration and command reference, operators, federation, and the plugin API
in depth — this README is the short tour.

## Highlights

<table>
<tr>
<td width="33%" valign="top">
<b>🦀 Memory-safe to the wire</b><br>
Zero <code>unsafe</code> code, forbidden at the workspace level. The zero-copy
parser is fuzzed in its own audited crate and never panics on hostile input.
</td>
<td width="33%" valign="top">
<b>🔐 TLS-first, hardened by default</b><br>
TLS is the primary transport. SASL <code>PLAIN</code>, <code>EXTERNAL</code>,
and <code>SCRAM-SHA-256</code> over Argon2id-hashed accounts, verified in
constant time.
</td>
<td width="33%" valign="top">
<b>📡 IRCv3-complete</b><br>
29 negotiable capabilities, from <code>server-time</code> and
<code>message-tags</code> to <code>draft/chathistory</code> and
<code>labeled-response</code>.
</td>
</tr>
<tr>
<td valign="top">
<b>🕸️ Federated, without the folklore</b><br>
Mutual-TLS certificate pinning, Lamport clocks instead of synchronized wall
time, deterministic nick-collision resolution, and clean netsplits across
multi-hop link trees.
</td>
<td valign="top">
<b>🧱 History that survives restarts</b><br>
Server-side chathistory with msgid continuity, backed by SQLite write-behind.
Registered channels restore topic, modes, and founder after a restart.
</td>
<td valign="top">
<b>🧩 Sandboxed WASM plugins</b><br>
Moderation hooks run in a pure-Rust interpreter under a per-call fuel budget —
a runaway plugin traps, it never wedges the server.
</td>
</tr>
<tr>
<td valign="top">
<b>🛡️ Built to be attacked</b><br>
Bounded SendQ, token-bucket rate limits, per-IP throttling, ping timeouts,
K/D/G-lines, HMAC host cloaking, and fail-closed configuration.
</td>
<td valign="top">
<b>⚡ 100k connections per node</b><br>
~13.8 KB of memory per connection at 100,000 concurrent clients on an 8-core
host — one async task per connection, sharded state instead of a global lock.
</td>
<td valign="top">
<b>📦 One static binary</b><br>
Prebuilt for Linux (static musl), macOS, Windows, FreeBSD, and Android/Termux,
with a checksum-verifying one-line installer.
</td>
</tr>
</table>

## Feature tour

### Core IRC

`NICK`/`USER` registration, `JOIN`/`PART`/`PRIVMSG`/`NOTICE`/`TAGMSG`/`QUIT`,
`NAMES`, `TOPIC`, `LIST`, `AWAY`, `PING`/`PONG`, `MOTD`/`LUSERS`, and consistent
case mapping. `WHO` supports mask queries (globs against nick, user, host,
and realname) and **WHOX** field selectors; `WHO`/`WHOIS` resolve users
anywhere on the network. **`MONITOR`** provides presence notifications for up
to 100 targets. Channel modes `+o/+v/+i/+m/+n/+s/+t/+k/+l` plus `+b/+e/+I` lists.

*Docs: [Channels](https://josunlp.github.io/ferrixd/guide/channels)*

### Accounts & authentication

SASL `PLAIN`, `EXTERNAL`, and `SCRAM-SHA-256` (challenge/response, stored
keys); passwords are Argon2id-hashed and verified in constant time. Users can
self-register with `REGISTER` (`draft/account-registration`); registered
accounts are persisted in SQLite and survive restarts and `REHASH`.

*Docs: [Accounts & SASL](https://josunlp.github.io/ferrixd/guide/accounts)*

### Moderation & operators

`KICK`, `INVITE` (with `invite-notify` and `+i` bypass), channel ban,
exception, and invite-exemption lists (`+b/+e/+I`, glob masks + `~a:` account
extbans),
IRC operators (`OPER`), `KILL`, `CHGHOST`, **HMAC host cloaking**, and server
bans (`KLINE`/`GLINE` at registration, `DLINE` by IP at connect). `REHASH`
reloads accounts, operators, bans, and the MOTD from disk without dropping
connections.

*Docs: [Operators & Moderation](https://josunlp.github.io/ferrixd/guide/operators)*

### History & modern UX

- Server-side message history: `draft/chathistory`
  (`LATEST`/`BEFORE`/`AFTER`/`AROUND`/`BETWEEN`/`TARGETS`) replayed in a
  `batch`, `msgid` tags on live and replayed messages, and DM history —
  **SQLite write-behind persistence** keeps history (and its msgids) across
  restarts.
- `draft/multiline` batches, `draft/metadata-2`
  (`METADATA GET/SET/LIST/CLEAR` on users and channels), and
  `standard-replies` (`FAIL`/`NOTE`).
- **Channel registration** — `REGISTER #channel` records a founder account;
  topic and modes are persisted and restored on restart, and the founder is
  auto-opped on join.

*Docs: [Message History](https://josunlp.github.io/ferrixd/guide/history)*

### Federation (S2S)

An authenticated server-to-server mesh: mutual-TLS
**certificate-fingerprint pinning** + `PASS`/`SERVER` handshake + Lamport
logical clocks. On link-up, servers **burst** their full state to each other —
users (with away status), channel members with `@`/`+` prefixes, topics,
modes, and ban lists. After that, everything propagates live:

- cross-server `PRIVMSG`/`NOTICE` (channels and DMs, recorded into
  chathistory), plus network-wide `WHOIS` and `WHO`;
- `JOIN`/`PART`/`KICK`/`MODE`/`TOPIC`/`AWAY`/account changes on cross-server
  channels, with message fan-out deduplicated per peer and forwarded loop-free
  along the link tree;
- **multi-hop routing** — indirect servers are reached through intermediate
  links (A—B—C chains work), with the topology propagated network-wide and
  **loop prevention** enforcing the link tree: a link or introduction that
  would close a cycle is refused with `ERROR :Server … already exists`;
- a **TS6 bridge** — set `protocol = "ts6"` on a link to federate with
  charybdis-family IRCds (solanum, …): users, channels (prefixes, modes,
  topics), messages, away/account state, and netsplits translate in both
  directions at the edge, while ferrix links keep the native protocol;
- **netsplit handling** — `QUIT`/`SQUIT`/link-drop clean up a peer's users and
  channel memberships and announce it locally;
- **nick-collision handling** — a nick held on a linked server is refused
  locally, and a genuine simultaneous collision is resolved deterministically
  (the smaller network UID wins — no synchronized clocks required).

*Docs: [Federation (S2S)](https://josunlp.github.io/ferrixd/guide/federation)*

### WASM plugin host

Sandboxed `.wasm` plugins run in the pure-Rust
[`wasmi`](https://docs.rs/wasmi) interpreter — no JIT, no `cmake`. Hooks:
`on_message` (v1 plain-text, or v2 with JSON `{"source","target","text"}`) can
veto channel messages — including ones relayed over S2S — and `ferrix_on_join`
can veto joins. Each call runs under a bounded *fuel* budget, so a runaway
plugin traps instead of wedging the server (blocked calls fail open). Plugins
have no ambient authority — only the host functions we grant.

*Docs: [WASM Plugins](https://josunlp.github.io/ferrixd/guide/plugins)*

### Hardening

- `unsafe_code = "forbid"` across the whole workspace.
- No `panic!`/`unwrap`/`expect` in the data path — enforced as clippy lints
  promoted to errors in CI.
- The parser lives in its own dependency-light crate
  ([`ferrix-protocol`](crates/ferrix-protocol/)) so it can be fuzzed and
  audited in isolation; it never panics on hostile input, and message tags
  (8191 B) and body (512 B) have separate length budgets.
- DoS controls: bounded SendQ, per-connection token-bucket rate limiting,
  per-IP connection throttling, and server-initiated ping timeout.

### Performance & observability

Load-tested to **~100k concurrent connections** on an 8-core host at
**~1.38 GB RSS (~13.8 KB/connection)**, scaling linearly with a fixed
worker-thread count (one async task per connection, not one OS thread) — see
[`loadtest/`](loadtest/) for the generator and methodology. A Prometheus
`/metrics` endpoint and per-connection tracing spans cover operations.

*Docs: [Observability](https://josunlp.github.io/ferrixd/guide/observability)*

## IRCv3 capabilities

`sasl=PLAIN,EXTERNAL,SCRAM-SHA-256` · `message-tags` · `server-time` ·
`echo-message` · `account-tag` · `account-notify` · `away-notify` ·
`extended-join` · `chghost` · `setname` · `multi-prefix` ·
`userhost-in-names` · `cap-notify` · `invite-notify` · `batch` ·
`labeled-response` · `standard-replies` · `extended-monitor` ·
`no-implicit-names` · `draft/chathistory` · `draft/metadata-2` ·
`draft/multiline` · `draft/account-registration` · `draft/read-marker` ·
`draft/event-playback` · `draft/message-redaction` ·
`draft/channel-rename` · `draft/pre-away` · `draft/extended-isupport`

Plus `sts` (strict transport security): advertised per connection when a policy
is configured, but never `REQ`able — so it is not counted among the 29.

Beyond the negotiable set, ferrixd also implements the IRCv3 server features that
are **not** capabilities: **bot-mode** (`ISUPPORT BOT=B`, umode `+B`, `RPL_WHOISBOT`,
the WHO `B` flag, and a bare `@bot` message tag), **WEBIRC** (trusted gateways may
rewrite a client's apparent host/IP), **UTF8ONLY** (the whole wire protocol is
UTF-8-validated, so non-UTF-8 content is never relayed), **`draft/ICON`**
(network-icon), and **IRC over WebSockets** (`ws://`/`wss://`, negotiating the
`text.ircv3.net` and `binary.ircv3.net` subprotocols).

## Installing

Every release ships prebuilt binaries for **Linux**
(x86_64/aarch64/i686/armv7/armv6, fully static musl), **macOS** (Apple Silicon +
Intel), **Windows** (x64/ARM64/x86), **FreeBSD** (x86_64/i686), and
**Android/Termux** (aarch64), built by
[`release.yml`](.github/workflows/release.yml). The installer verifies every
download against the release's SHA-256 checksum.

Linux · macOS · FreeBSD · Android (Termux):

```sh
# install — re-run any time; also serves as "switch to latest"
curl -fsSL https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.sh | sh

# update (updates in place, prints old -> new version)
curl -fsSL https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.sh | sh -s -- update

# uninstall (config + database stay)
curl -fsSL https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.sh | sh -s -- uninstall
```

Windows (PowerShell):

```powershell
# install
irm https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.ps1 | iex

# update / uninstall
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.ps1))) update
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.ps1))) uninstall
```

Defaults: binaries land in `/usr/local/bin` (as root) or `~/.local/bin`
(as user) — `$PREFIX/bin` on Termux, `%LOCALAPPDATA%\Programs\ferrixd` on
Windows (added to the user `PATH`). Pin a version with
`sh -s -- install --version v1.1.0` (PowerShell: `... install v1.1.0`);
override the directory with `--dir`/`-Dir` or `$FERRIXD_INSTALL_DIR`.

Cutting a release: bump `version` in `Cargo.toml`, then publish a GitHub Release
tagged `vX.Y.Z` (e.g. `gh release create vX.Y.Z`) — the workflow refuses a
release whose tag disagrees with the crate version.

*Docs: [Installation](https://josunlp.github.io/ferrixd/guide/installation)*

## Running it (development)

The fastest path needs no config file at all:

```sh
# Zero-config local server: self-signed TLS on :6697, plaintext on :6667.
cargo run -p ferrixd -- run --dev

# Connect with a TLS client (self-signed → skip verification):
openssl s_client -connect localhost:6697 -quiet 2>/dev/null
#   then type, e.g.:  PING :hello    → server replies:  PONG ...
# …or, since --dev also opens a loopback plaintext port:
nc 127.0.0.1 6667
```

For a real deployment, scaffold and validate a config first:

```sh
ferrixd gen-config            # writes ./ferrixd.toml
ferrixd check                 # validates it, prints what it starts
ferrixd                       # runs with ./ferrixd.toml (or -c <path>)
```

See [`ferrixd.example.toml`](ferrixd.example.toml) for every knob, or the
guides on [configuration](https://josunlp.github.io/ferrixd/guide/configuration),
[TLS certificates](https://josunlp.github.io/ferrixd/guide/tls), and
[production deployment](https://josunlp.github.io/ferrixd/guide/deployment).

## Running it (Docker)

The repo ships a multi-stage `Dockerfile`: a static musl build in `rust:alpine`
dropped into a small Alpine runtime image that runs as a non-root user. `docker
stop` (SIGTERM) triggers the same graceful shutdown as Ctrl-C.

```sh
docker build -t ferrixd .

# Scaffold a config into the current directory, then edit it.
# (--user: the container writes into the bind mount as *you*, not uid 10001.)
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/etc/ferrixd ferrixd gen-config

# Validate it, then run:
docker run --rm -v "$PWD/ferrixd.toml":/etc/ferrixd/ferrixd.toml:ro ferrixd check
docker run -d --name ferrixd -p 6697:6697 \
    -v "$PWD/ferrixd.toml":/etc/ferrixd/ferrixd.toml:ro \
    -v ferrixd-data:/var/lib/ferrixd \
    ferrixd

# …or the same via compose (ports, volumes, healthcheck included):
docker compose up -d
```

Paths inside the container: the config is expected at `/etc/ferrixd/ferrixd.toml`
(the image's workdir, so the default `./ferrixd.toml` resolves there), and
durable state belongs on the `/var/lib/ferrixd` volume — set
`[persistence] path = "/var/lib/ferrixd/ferrixd.db"` to survive container
recreation. Real TLS certificates are extra read-only mounts referenced from
the config; `self_signed_dev = true` needs none. Every utility subcommand works
through the same entrypoint, e.g. `docker run --rm -it ferrixd hash-password`
(`-it` because the prompt is interactive) or `docker run --rm ferrixd --help`.

## Command-line interface

The single `ferrixd` binary is self-sufficient — no side scripts, no `openssl`.
Run `ferrixd --help` (or `ferrixd <cmd> --help`) for full details.

| Command                                | What it does                                                               |
| -------------------------------------- | -------------------------------------------------------------------------- |
| `ferrixd [run]`                        | Run the server (default). `run --dev` = zero-config local server.          |
| `ferrixd check`                        | Validate the config **and** its TLS material, then print a summary.        |
| `ferrixd gen-config`                   | Write a starter `ferrixd.toml`.                                            |
| `ferrixd gen-cert -H irc.example.test` | Mint a self-signed cert + key (PEM), print the fingerprint.                |
| `ferrixd hash-password [--toml]`       | Read a password (no echo) → Argon2id hash; `--toml` adds the `scram` line. |
| `ferrixd fingerprint cert.pem`         | SHA-256 fingerprint for `[[links]]` / SASL EXTERNAL.                       |
| `ferrixd completions <shell>`          | Emit a completion script (bash/zsh/fish/…).                                |

Global flags (valid before any subcommand): `-c/--config <PATH>`,
`--log <FILTER>` (overrides `RUST_LOG`), `--log-format full|compact|pretty`, and
`--color auto|always|never`.

*Docs: [CLI Reference](https://josunlp.github.io/ferrixd/reference/cli)*

## Workspace layout

```bash
ferrixd/
├── crates/
│   ├── ferrix-protocol/   # zero-copy IRC/IRCv3 message model, parser, encoder
│   └── ferrixd/           # the daemon: config, TLS, codec, listener, connection,
│                          #   state, session, command; cap, deliver (tagging),
│                          #   account (Argon2), sasl, scram, cloak, mask, history,
│                          #   persist + chanreg (SQLite), metrics, s2s + link
│                          #   (federation), plugin (WASM/wasmi), casemap, wire, numeric
├── docs/                  # documentation site (VitePress → GitHub Pages)
├── fuzz/                  # cargo-fuzz harness for the parser (nightly)
├── loadtest/              # connection-density load generator (excluded crate)
├── scripts/               # one-line install/update/uninstall (sh + PowerShell)
└── .github/workflows/     # CI (fmt, clippy, test, cargo-deny) + release builds
```

## Testing

```sh
cargo test                     # unit + integration tests (incl. S2S federation e2e)
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Fuzzing (requires nightly + cargo-fuzz):
cargo install cargo-fuzz
cargo +nightly fuzz run parse_message
```

## Stability

**1.0.0 is the first stable release.** Within the 1.x series, the
configuration schema, the client-facing protocol (commands, numerics, the
advertised capability set), the CLI, the plugin ABI, and the S2S wire protocol
are covered by semantic versioning — servers of different 1.x versions
interoperate on a link. Draft IRCv3 capabilities track their upstream
specifications and may change with them. The Rust library APIs are *not*
covered: the daemon is the product.

See the [CHANGELOG](CHANGELOG.md) for what shipped, and
[the roadmap](https://josunlp.github.io/ferrixd/internals/roadmap) for what
may come next.

## License

Dual-licensed under either of

- MIT ([LICENSE-MIT](LICENSE-MIT) · <https://opensource.org/licenses/MIT>)
- Apache-2.0 ([LICENSE-APACHE](LICENSE-APACHE) ·
  <https://www.apache.org/licenses/LICENSE-2.0>)

at your option. Unless you state otherwise, any contribution you intentionally
submit for inclusion shall be dual-licensed as above, without additional terms.

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security
issues go through [SECURITY.md](SECURITY.md), not the public issue tracker.

---

<div align="center">
<sub><b>ferrixd</b> — the Ferrous IRC Daemon ·
<a href="https://josunlp.github.io/ferrixd/">documentation</a> ·
<a href="https://github.com/josunlp/ferrixd/issues">issues</a></sub>
</div>
