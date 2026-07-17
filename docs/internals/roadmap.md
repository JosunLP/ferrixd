# Roadmap

ferrixd reached **1.0.0** — the first stable release — and **1.1.0** extends it
(IRC over WebSockets, WEBIRC, bot-mode, live link management, TLS reload, and
more; see the [changelog](https://github.com/josunlp/ferrixd/blob/main/CHANGELOG.md)).
This page records what the current release contains, what the stability promise
covers, and what may come next.

## Stability promise (1.x)

Covered by semantic versioning; these will not change incompatibly within 1.x:

| Surface              | Promise                                                                                                         |
| -------------------- | --------------------------------------------------------------------------------------------------------------- |
| Configuration schema | new keys may appear with defaults; existing keys keep their meaning                                             |
| Client protocol      | commands, numerics, and the advertised capability set                                                           |
| CLI                  | subcommands and flags                                                                                           |
| Plugin ABI           | hook signatures and the memory contract ([reference](/reference/plugin-abi))                                    |
| S2S wire protocol    | frames extend only backwards-compatibly; older forms stay parseable, so mixed-version 1.x networks interoperate |

Two deliberate exceptions:

- **Draft IRCv3 capabilities** (`draft/*`) track their upstream specifications
  and change when those do. When a draft is ratified, ferrixd adopts the
  ratified name (and `cap-notify` clients learn about it live).
- **The Rust library APIs** (`ferrixd`, `ferrix-protocol`) are not covered. The
  daemon is the product; the crates are its implementation.

## What ferrixd contains

- **Protocol surface**: the RFC core plus 29 IRCv3 capabilities
  ([list](/reference/capabilities)) — what the server advertises, it enforces —
  plus non-capability features (bot-mode, WEBIRC, UTF8ONLY, network-icon) and
  IRC over WebSockets (`ws://`/`wss://`).
- **Federation**: complete state synchronization across multi-hop link trees
  with loop prevention and TS-based netjoin resolution
  ([protocol](/reference/s2s-protocol)), plus a
  [TS6 bridge](/guide/federation#bridging-to-ts6-ircds) to charybdis-family
  IRCds.
- **Persistence**: message history (with `msgid` continuity), channel
  registrations, and self-registered accounts survive restarts; the write-behind
  queue is drained on graceful shutdown.
- **Security**: zero `unsafe`, a fuzzed parser, TLS-first transport, Argon2id
  credentials, and the DoS controls in [Limits](/reference/limits).
- **Density**: ~100k concurrent connections per node demonstrated.
- **Releases**: prebuilt binaries for 7 targets with a checksum-verifying
  installer ([installation](/guide/installation)).

## Since 1.0 (unreleased)

Work that has landed on top of 1.0 — most of it former Horizon items — while
holding the 1.x stability promise:

- **SASL reauthentication.** A registered client that negotiated `sasl` may
  re-run `AUTHENTICATE` mid-session to switch (or add) an account. The new login
  replaces the old on success; a failed attempt leaves the existing login
  untouched.
- **Richer plugin hooks.** The WASM host now also observes and can veto **nick
  changes** (`ferrix_on_nick`) and **topic changes** (`ferrix_on_topic`), on the
  same fail-open ABI as messages and joins
  ([reference](/reference/plugin-abi)).
- **Live link management.** Operators can bring S2S links up and down at
  runtime with `CONNECT <name>` and `SQUIT <server> [:reason]`, beyond the
  config-driven links started at boot.
- **Per-command metric histograms.** `/metrics` now exposes
  `ferrixd_command_duration_seconds`, a per-command handler-latency histogram
  (bounded label cardinality: known verbs plus `other`).
- **TLS reload without restart.** `REHASH` now reloads the certificate and key
  for every TLS listener (client, `wss://`, and S2S) without dropping the
  process or any live connection; a bad reload leaves the previous material
  armed.

## Horizon

Direction, not commitment:

- **Draft-spec tracking.** The `draft/*` capabilities follow their specs;
  ratified names are adopted as they land.
- **Even richer plugin hooks.** Nick and topic events are covered; moderation
  actions (kick, mode, kline) are the natural next extension of the same ABI.
- **Outbound-link certificate reload.** TLS reload covers the listeners today;
  rotating the certificate an *existing outbound* link presents still needs a
  re-link (`SQUIT` + `CONNECT`).

If you want to influence any of this, open an issue —
[GitHub](https://github.com/josunlp/ferrixd/issues).
