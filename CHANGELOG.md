# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Plugin ABI v2** — the WASM plugin system grows from "observe and veto"
  into a full extension surface, without loosening the sandbox
  ([reference](https://josunlp.github.io/ferrixd/reference/plugin-abi)):
  - **New veto hooks**: `ferrix_on_part`, `ferrix_on_kick`,
    `ferrix_on_mode` (channel modes, after the op check),
    `ferrix_on_invite` (local and remote-target), and
    `ferrix_on_private_message` — the latter only when the operator opts in
    via `plugins.expose_private_messages` (DM privacy stays the operator's
    call, never the plugin author's).
  - **Lifecycle hooks** (observe-only): `ferrix_on_connect`,
    `ferrix_on_quit`, and `ferrix_on_load` (reports the plugin's granted
    capabilities at startup).
  - **Message rewriting**: `ferrix.set_text` lets a message hook replace
    the text (censoring, formatting, expansion); the rewrite reaches echo,
    history, later plugins in the chain, and the S2S relay. Host-side
    sanitization strips CR/LF/NUL and caps the length, so a plugin can
    never inject protocol frames.
  - **Custom block reasons**: `ferrix.set_reason` customizes the `FAIL`
    reply of a veto.
  - **Bounded per-plugin key-value store**: `ferrix.kv_get`/`kv_set`
    (256 keys / 64 KiB per plugin), optionally persisted to
    `plugins.state_dir` by the host — plugins still never touch the
    filesystem.
  - **Read-only world queries**: `ferrix.channel_members`,
    `ferrix.user_info`, and `ferrix.now_ms` for cooldowns and rate limits.
  - **Capability-gated actions**: `ferrix.send_notice` sends server
    NOTICEs to nicks or channels — only with a per-plugin
    `[plugins.grants]` entry (deny-by-default), budgeted (4 per hook call,
    120/minute), and executed after the sandboxed call returns;
    server-originated notices do not re-enter the hooks.
  - **Per-instance memory cap** (`plugins.max_memory`, default 16 MiB):
    fuel already bounded CPU; `memory.grow` is now bounded too.
  - **Per-plugin stats** (calls, blocks, traps) tracked by the host.
  - Everything is backwards-compatible: all new hooks are optional
    exports, all new host functions optional imports — 1.1 plugins load
    and run unchanged.

## [1.1.0] — 2026-07-18

### Added

- **IRC over WebSockets** — new `ws://` (`ws_bind`) and `wss://` (`wss_bind`)
  listeners, negotiating the `text.ircv3.net` and `binary.ircv3.net`
  subprotocols. Each IRC line is one WebSocket message (no CRLF on the wire);
  TLS is terminated before the handshake and the byte stream reuses the existing
  framing, rate-limiting, and SASL EXTERNAL path.
- **WEBIRC** — trusted web/IRC gateways (`[[webirc]]` blocks) may rewrite a
  client's apparent host and IP. A gateway must present the shared secret
  (compared in constant time) **and** connect from an allow-listed source
  address; the spoofed IP is re-checked against D-lines. `REHASH`-reloadable.
- **Bot mode** (IRCv3) — user mode `+B`, advertised as `ISUPPORT BOT=B`, shown
  in `WHOIS` (`RPL_WHOISBOT`, 335) and the `WHO` flags, and added as a bare
  `@bot` message tag on a bot's messages. Synced across S2S links.
- **`no-implicit-names`** capability — suppresses the automatic `NAMES` burst on
  `JOIN` (explicit `NAMES` still replies).
- **`draft/pre-away`** capability — accept `AWAY` before registration completes.
- **`draft/extended-isupport`** capability — deliver `RPL_ISUPPORT` during CAP
  negotiation, before `RPL_WELCOME`.
- **`draft/network-icon`** — advertise a network icon URL as the `draft/ICON`
  ISUPPORT token (`server.icon`).
- **SASL reauthentication** — a registered client that negotiated `sasl` may
  re-run `AUTHENTICATE` mid-session to switch to (or add) an account. The new
  login replaces the old on success; a failed attempt leaves the existing login
  untouched (IRCv3 SASL 3.2).
- **Live link management** — operator `CONNECT <name>` dials a configured S2S
  peer at runtime, and `SQUIT <server> [:reason]` tears a directly-linked peer
  (and its subtree) down through the usual netsplit path. A `SQUIT` also stops
  the peer's boot-time auto-dial loop until a `CONNECT` clears it, and the
  auto-dial loops pick up `REHASH`ed link edits (and stop for removed links)
  on their next attempt.
- **Per-command metric histograms** — `/metrics` now exposes
  `ferrixd_command_duration_seconds`, a per-command handler-latency histogram.
  Label cardinality is bounded to the known command verbs plus `other`.
- **TLS reload without restart** — `REHASH` reloads the certificate and key for
  every TLS listener (client, `wss://`, and the S2S link listener) without
  dropping the process or any live connection; a failed reload keeps the
  previous material armed. The outbound-link client TLS is now attached
  unconditionally and rebuilt on every `REHASH`, so operator `CONNECT` works for
  links added after startup and every outbound (re)connect — the auto-dial loop
  included — presents the reloaded certificate instead of the one captured when
  the loop was first spawned.
- **`EXTBAN=~,a` ISUPPORT token** — the account extban (`~a:`, honoured in
  `+b`/`+e`/`+I` since 1.0) is now advertised to clients in `RPL_ISUPPORT`.
- **Plugin hooks for nick and topic changes** — the WASM host gains
  `ferrix_on_nick` and `ferrix_on_topic`, which can observe and veto those
  moderation events on the same fail-open ABI as messages and joins.

The negotiable capability set grows from 26 to 29. `UTF8ONLY` remains enforced
by the UTF-8-validating parser (non-UTF-8 content is never relayed).

## [1.0.0] — 2026-07-16

The first stable release. ferrixd is a from-scratch, memory-safe, IRCv3
IRC server: TLS-first, federated over mutual TLS, with persistent message
history and a sandboxed WebAssembly plugin host.

### Stability promise

From 1.0.0 on, the following are covered by semantic versioning and will not
change incompatibly within the 1.x series:

- the **configuration schema** (`ferrixd.toml`) — new keys may be added with
  defaults, existing keys keep their meaning;
- the **client-facing protocol** — commands, numerics, and the advertised
  capability set (draft capabilities track their upstream specifications and
  may change with them; see [Compatibility](docs/reference/capabilities.md));
- the **CLI** — subcommands and flags;
- the **plugin ABI** (`crates/ferrixd/src/plugin.rs`);
- the **S2S wire protocol** stays compatible across 1.x: frames are extended
  only in backwards-compatible ways, and older forms remain parseable, so
  servers of different 1.x versions interoperate.

The Rust library APIs (`ferrixd`, `ferrix-protocol`) are **not** covered: the
daemon is the product, the crates are its implementation.

### Server

- Full client protocol: registration, channels (`+o +v +i +m +n +s +t +k +l`
  plus `+b`/`+e`/`+I` lists with `~a:` account extbans), messaging, `WHO`
  (mask + WHOX), `WHOIS`, `WHOWAS`, `MONITOR`/`WATCH`, `SILENCE`, `LIST`
  (ELIST filters), `KNOCK`, `MAP`, `HELP`, `STATS`, `LINKS`.
- 26 negotiable IRCv3 capabilities, including `sasl`, `message-tags`,
  `server-time`, `echo-message`, `labeled-response`, `batch`,
  `extended-monitor`, `draft/chathistory`, `draft/multiline`,
  `draft/metadata-2`, `draft/read-marker`, `draft/event-playback`,
  `draft/message-redaction`, `draft/channel-rename` — plus `sts`, advertised
  per connection but not itself negotiable.
- SASL `PLAIN`, `EXTERNAL`, and `SCRAM-SHA-256` over Argon2id-hashed accounts,
  verified in constant time; account self-registration (`REGISTER`).

### Federation

- Authenticated S2S mesh: mutual-TLS certificate-fingerprint pinning plus a
  shared `PASS` token; full state burst on link-up with an end-of-burst marker.
- Multi-hop routing with topology propagation and **loop prevention** (the
  network is enforced as a tree); deterministic nick-collision resolution;
  TS6-style channel-timestamp resolution on netjoin (the older channel wins).
- A **TS6 bridge** (`protocol = "ts6"`) to charybdis-family IRCds (solanum, …).

### Durability & operations

- Message history with `msgid` continuity, backed by SQLite write-behind
  persistence; the queue is drained on graceful shutdown.
- Registered channels retain founder, topic, and modes across restarts.
- `REHASH` reloads accounts, operators, bans, MOTD, and the connection
  password without dropping connections.
- Prometheus `/metrics`, structured tracing, and a load-tested density of
  ~100k concurrent connections per node.

### Security

- Zero `unsafe` code (`unsafe_code = "forbid"` workspace-wide); the parser is
  fuzzed in its own crate and never panics on hostile input.
- TLS is the primary transport; a plaintext listener is loopback-only unless
  explicitly opted into.
- Bounded SendQ, token-bucket rate limits, per-IP connection throttling, ping
  timeouts, K/D/G-lines, and HMAC host cloaking.

[1.1.0]: https://github.com/josunlp/ferrixd/releases/tag/v1.1.0
[1.0.0]: https://github.com/josunlp/ferrixd/releases/tag/v1.0.0
