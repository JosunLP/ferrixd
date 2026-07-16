# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-07-14

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
  `extended-monitor`, `sts`, `draft/chathistory`, `draft/multiline`,
  `draft/metadata-2`, `draft/read-marker`, `draft/event-playback`,
  `draft/message-redaction`, `draft/channel-rename`.
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

[1.0.0]: https://github.com/j-pfalzgraf/ferrixd/releases/tag/v1.0.0
