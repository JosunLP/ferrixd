# Roadmap

ferrixd reached **1.0.0** — the first stable release. This page records what
that release contains, what the stability promise covers, and what may come
next.

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

## What 1.0 contains

- **Protocol surface**: the RFC core plus 26 IRCv3 capabilities
  ([list](/reference/capabilities)) — what the server advertises, it enforces.
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

## Horizon

Direction, not commitment:

- **Draft-spec tracking.** The `draft/*` capabilities follow their specs;
  ratified names are adopted as they land.
- **SASL reauthentication.** Mid-session `AUTHENTICATE` is not supported today.
- **Richer plugin hooks.** The WASM host currently vetoes messages and joins;
  more events (nick changes, topic changes, moderation actions) are a natural
  extension of the same ABI.
- **Operational conveniences.** Live link management (beyond config-driven),
  per-command metric histograms, and TLS reload without restart are recurring
  candidates.

If you want to influence any of this, open an issue —
[GitHub](https://github.com/josunlp/ferrixd/issues).
