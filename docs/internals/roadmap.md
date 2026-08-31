# Roadmap

ferrixd reached **1.0.0** — the first stable release — **1.1.0** extended it
(IRC over WebSockets, WEBIRC, bot-mode, live link management, TLS reload), and
**1.2.0** grew the plugin system into a full extension surface (Plugin ABI v2).
**1.3.0** finishes that arc: plugins can now *act* — kick, mode, topic, K-Line
and message, each behind its own grant (Plugin ABI v3; see the
[changelog](https://github.com/josunlp/ferrixd/blob/main/CHANGELOG.md)).
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

## Since 1.0

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
- **Plugin ABI v2.** The moderation events (part, kick, mode, invite), DM
  filtering (operator-gated), lifecycle hooks (connect/quit/load), message
  **rewriting** (`ferrix.set_text`), custom block reasons, a bounded
  persistent key-value store, read-only world queries, a per-instance
  memory cap, and the first capability-gated action (`ferrix.send_notice`,
  deny-by-default via `[plugins.grants]`) — the sandbox properties are
  unchanged: fail-open, fuel-bounded, no ambient authority.
- **Plugin ABI v3.** Observation became agency. Five more capability-gated
  actions (`send_message`, `kick`, `set_mode`, `set_topic`, `kline`), each
  behind its own grant and applied *as the server* — so a plugin's kick or
  mode change propagates across the link tree instead of stopping at the node
  that ran it. Plus a periodic `ferrix_on_timer` hook, away/account
  observation, richer queries (`server_info`, `channel_info`,
  `user_channels`), CSPRNG bytes, levelled logging, and operator-supplied
  per-plugin settings (`[plugins.config.<name>]`) so one `.wasm` file is
  configured rather than recompiled per site. Old plugins load unchanged.
- **Per-plugin metrics.** `/metrics` reports calls, blocks and traps per
  plugin, so a plugin that starts failing open is alertable rather than
  merely logged.
- **Live link management.** Operators can bring S2S links up and down at
  runtime with `CONNECT <name>` and `SQUIT <server> [:reason]`, beyond the
  config-driven links started at boot.
- **Per-command metric histograms.** `/metrics` now exposes
  `ferrixd_command_duration_seconds`, a per-command handler-latency histogram
  (bounded label cardinality: known verbs plus `other`).
- **TLS reload without restart.** `REHASH` now reloads the certificate and key
  for every TLS listener (client, `wss://`, and S2S) without dropping the
  process or any live connection; a bad reload leaves the previous material
  armed. Outbound links also pick up the reloaded certificate on their next
  (re)connect — the auto-dial reconnect loop included — so certificate rotation
  no longer needs a manual re-link.

## Horizon

Direction, not commitment:

- **Draft-spec tracking.** The `draft/*` capabilities follow their specs;
  ratified names are adopted as they land.
- **Plugin capabilities beyond the channel.** Kick, mode, topic and kline
  as actions have landed; what is left of the same grants model is the
  network layer — a plugin asking for a `GLINE`, or driving `CONNECT` /
  `SQUIT`. Those touch the whole link tree rather than one channel, so they
  want an operator story (audit trail, revocation) before an ABI.
- **A plugin package format.** Plugins are bare `.wasm` files today; a
  manifest (name, ABI level, requested capabilities) would let the host
  refuse a plugin whose requests exceed its grants at *load* time instead of
  refusing each call.

If you want to influence any of this, open an issue —
[GitHub](https://github.com/josunlp/ferrixd/issues).
