# Operators & Moderation

Two tiers of authority exist in ferrixd:

- **Channel operators** (`+o` in a channel) moderate their channel: topic,
  modes, kicks, invites, bans. Covered in [Channels](/guide/channels).
- **IRC operators** (*opers*, user mode `+o`) run the server: they can
  disconnect users, ban hosts and IPs network-entry-wide, change hosts,
  broadcast, and hot-reload the config.

This page is about the second tier.

## Becoming an oper

Opers are declared in the config:

```toml
[[operators]]
name = "admin"
password_hash = "$argon2id$…"    # ferrixd hash-password
```

At runtime:

```
OPER admin s3cret
```

Success returns `381 RPL_YOUREOPER` and sets user mode `+o`. Failures return
`491 ERR_NOOPERHOST`. Like accounts, operator blocks are Argon2id-verified in
constant time and reloadable via `REHASH`.

An oper can drop the flag with `MODE <nick> -o` (it cannot be set that way —
only `OPER` grants it).

What opers are exempt from: the per-client channel cap (`max_channels`).
What they are *not* exempt from: flood control and SendQ — a misbehaving
oper connection is still a misbehaving connection.

## The moderation toolbox

| Command | Scope | Effect |
| --- | --- | --- |
| `KILL <nick> :<reason>` | one user | immediate disconnect, network-wide (propagated over S2S) |
| `KLINE <mask> :<reason>` | host mask | ban at registration + kill current matches |
| `UNKLINE <mask>` | host mask | lift a K-line |
| `GLINE` / `UNGLINE` | host mask | network-wide ban: applied like a K-Line on every linked server |
| `DLINE <ip-mask> :<reason>` | IP mask | ban **at connect**, before TLS/registration + kill current matches |
| `UNDLINE <ip-mask>` | IP mask | lift a D-line |
| `CHGHOST <nick> <user> <host>` | one user | change displayed user@host |
| `WALLOPS :<text>` | all `+w` users | operator broadcast |
| `REHASH` | server | hot-reload config subset + TLS certificate/key |
| `CONNECT <name>` | S2S link | bring up a configured peer link at runtime |
| `SQUIT <server> [:reason]` | S2S link | disconnect a directly-linked peer (and its subtree) |

### K-lines: banning by mask

```
KLINE *!*@*.bad.example :Spam network
```

Masks are `nick!user@host` globs (`*` and `?`). K-lines are enforced when a
connection registers, and adding one immediately kills already-connected
matches. Startup K-lines live in the config:

```toml
[[bans]]
mask = "*!*@203.0.113.0/24"
reason = "Banned network"
```

::: tip K-lines see the real host
With [cloaking](#host-cloaking) enabled, users display a cloak — but K-line
matching runs against the **real** hostname/IP, which the server keeps
internally. You ban what's actually there, not the cloak.
:::

### D-lines: banning by IP, before the handshake

```
DLINE 203.0.113.* :DDoS source
```

D-lines are checked at TCP accept time — before the TLS handshake, before
registration. This makes them the cheapest way to shed an abusive source:
no handshake CPU is spent on banned IPs.

### KILL

```
KILL mallory :Ban evasion
```

Disconnects the user wherever they are — including on a linked server (the
kill propagates over S2S with proper origin checks).

## Host cloaking

With a cloak key configured, ferrixd replaces user hostnames with an
HMAC-derived cloak at registration:

```toml
[server]
cloak_key = "a-long-random-secret"
```

- Anonymous users get a cloak derived from `HMAC(cloak_key, real-host)` —
  stable per host, so channel bans on a cloak still work, but unlinkable to
  the real address without the key.
- Authenticated users are cloaked as `account.<network>` (e.g.
  `alice.ferrixnet`) — identity-based, stable across networks and IPs.

Because the cloak is an HMAC, it is **unforgeable**: nobody can present
someone else's cloak. Keep `cloak_key` secret and consistent across all
linked servers. Opers can still see and act on real hosts (K-lines match
real hosts; `WHOIS` shows `338 RPL_WHOISACTUALLY` to privileged queries),
and `CHGHOST` can override a displayed host manually.

## REHASH

```
REHASH
```

Reloads from the config file the server was started with, **without
dropping connections**, and answers `382 RPL_REHASHING`. What it reloads:

| Reloaded | Not reloaded (restart required) |
| --- | --- |
| `[[accounts]]` | listeners (`tls_bind`, `plain_bind`, `link_bind`) |
| `[[operators]]` | `[limits]` |
| `[[bans]]` (K-lines) | `[persistence]`, `[metrics]`, `[plugins]` |
| `motd`, `[tls]` certificates, `[[links]]` | |

Self-registered (persisted) accounts are re-applied on top of the config
accounts after a rehash, so a `REHASH` never wipes runtime registrations.

## Oper visibility

- `WHOIS` on an oper shows the operator numeric.
- `WALLOPS` reaches users with `+w` set (`MODE <nick> +w`).
- Failed and successful `OPER` attempts are logged with the connection's
  tracing span — see [Observability](/guide/observability).

## Recommended practice

1. **One `[[operators]]` block per human**, named after the human — shared
   oper passwords defeat the audit trail.
2. **Use `password_hash`, never `password`**, in any config that leaves your
   machine.
3. **Prefer D-lines for volumetric abuse** (cheapest rejection), K-lines for
   targeted bans, channel bans for channel problems.
4. **`REHASH` after every config edit** you expect to be live — and remember
   the not-reloaded column above.
