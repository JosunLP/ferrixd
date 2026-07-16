# Security Model

ferrixd assumes it will be attacked — by hostile bytes, hostile clients,
hostile networks, and occasionally hostile plugins. This page maps the
defenses layer by layer.

## Memory safety

- `unsafe_code = "forbid"` — workspace-wide, checked by the compiler. Not
  "minimal unsafe": zero.
- **No `panic!`/`unwrap`/`expect` in the data path** — clippy lints
  promoted to errors in CI. A malformed input is an `Err`, not an abort.
- The parser is **fuzzed** (`cargo-fuzz`) and lives in an isolated crate
  with separate tag/body length budgets, so a pathological frame is
  rejected by arithmetic, not by luck.

## Transport security

- **TLS-first**: the primary listener is TLS; the plaintext listener is
  loopback-only unless explicitly overridden
  ([details](/guide/tls#plaintext-and-why-it-is-caged)).
- **Handshake budget** (`handshake_timeout_secs`) — slow-handshake
  connection-slot exhaustion doesn't work.
- **S2S links** are mutual TLS with **pinned certificate fingerprints** on
  both sides plus a shared secret compared in **constant time** — no CA
  trust, no plaintext link mode.

## Credential handling

| Secret | Storage | Verification |
| --- | --- | --- |
| Account passwords | Argon2id PHC hashes | constant-time |
| Operator passwords | Argon2id PHC hashes | constant-time |
| SCRAM credentials | derived keys only (salt, 4096 iterations, stored key, server key) | challenge–response; plaintext never stored |
| Link passwords | config | constant-time comparison |
| Client certificates | SHA-256 fingerprint allow-lists | exact match |

Passwords never appear in logs. `ferrixd hash-password` exists so
plaintext never needs to touch a production config.

## DoS controls

Every per-client resource is bounded, and every bound has a defined
consequence and a metric:

| Control | Bound | Consequence | Metric |
| --- | --- | --- | --- |
| Inbound rate | token bucket: `recv_burst` / `recv_rate` | disconnect `Excess Flood` | `ferrixd_flood_disconnects_total` |
| Outbound queue | `sendq_lines` | disconnect `SendQ exceeded` | `ferrixd_sendq_drops_total` |
| Registration | `registration_timeout_secs` | disconnect | `ferrixd_registration_timeouts_total` |
| TLS handshake | `handshake_timeout_secs` | abort | — |
| Idle | `ping_interval_secs` ×2 | disconnect `Ping timeout` | — |
| Per-IP connections | `max_clients_per_ip` | refuse | — |
| Channels per client | `max_channels` | `405` | — |
| History memory | `history_len` × `history_max_targets` | LRU eviction | — |
| Frame length | `max_line_bytes` | disconnect | — |
| SASL buffer | 8 KiB | `ERR_SASLTOOLONG` | — |
| Link mailbox | 4,096 frames | link dropped | — |

Two structural properties matter as much as the numbers:

- **No lock is held across I/O.** Delivery snapshots recipients, drops
  locks, then sends to bounded queues — a slow client can only hurt
  itself.
- **The write-behind history queue** keeps disk latency out of the message
  path entirely.

D-lines reject banned IPs **at TCP accept**, before any TLS work — the
cheapest possible rejection for volumetric abuse.

## Configuration as a defense

Config parsing is **fail-closed**: unknown keys are startup errors. The
class of bug where a mistyped security setting silently doesn't apply does
not exist. `ferrixd check` validates config and TLS material offline.

## Identity & spoofing resistance

- **Host cloaks are HMAC-based** — unforgeable without `cloak_key`, stable
  per host (or per account), and K-lines match the *real* host regardless.
- **Account extbans** (`~a:`) bind moderation to authenticated identity
  rather than spoofable masks.
- **S2S origin enforcement**: the first link to announce a SID owns its
  route; every inbound frame is validated against the announcing link. A
  compromised or misconfigured peer cannot inject state for servers it
  doesn't route, cannot spoof your own SID, and collisions resolve
  deterministically. Forged frames are dropped and logged.

## Plugin containment

Plugins are **untrusted code by contract**
([ABI](/reference/plugin-abi)):

- pure-Rust interpreter (no JIT — `MemoryDenyWriteExecute` stays on);
- no ambient authority — the only host import is a logger;
- deterministic **fuel budget** per call — infinite loops trap;
- **fail-open** — a plugin crash degrades to "no filtering", never to an
  outage or a wedged event loop.

## Reporting

If you believe you've found a security issue, please use
[GitHub's private vulnerability reporting](https://github.com/j-pfalzgraf/ferrixd/security)
rather than a public issue.
