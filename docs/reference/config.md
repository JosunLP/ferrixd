# Configuration Reference

The complete schema of `ferrixd.toml`. Every table and field, with types,
defaults, and validation rules. For a guided walkthrough, see the
[configuration guide](/guide/configuration).

::: warning Unknown keys are errors
Configuration is **fail-closed**: every table rejects unknown keys. A typo
prevents startup instead of being silently ignored. Validate with
`ferrixd check` after every edit.
:::

Conventions below: **required** fields have no default; everything else may
be omitted. Durations are integer seconds; sizes are bytes.

## `[server]` — required

Identity and listeners.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | **required** | advertised server name, used in numerics and message prefixes |
| `network` | string | `"ferrixnet"` | network name (`ISUPPORT NETWORK=`) |
| `casemapping` | `"ascii"` \| `"rfc1459"` | `"ascii"` | nick/channel case folding; must be identical network-wide |
| `motd` | array of string | `[]` | message of the day, one entry per line; `REHASH`-reloadable |
| `cloak_key` | string | *unset* | HMAC key enabling [host cloaking](/guide/operators#host-cloaking); omit to disable; keep secret and identical on linked servers |
| `sid` | string | `"42F"` | server ID for S2S; unique per network |
| `link_bind` | socket address | *unset* | inbound S2S listener, e.g. `"0.0.0.0:6666"` |
| `tls_bind` | socket address | **required** | primary TLS listener, e.g. `"0.0.0.0:6697"` |
| `plain_bind` | socket address | *unset* | plaintext listener; loopback-only unless `allow_plain_nonlocal` |
| `allow_plain_nonlocal` | bool | `false` | permit a non-loopback `plain_bind` (e.g. behind a local TLS-terminating proxy) |
| `password` | string | *unset* | connection password: clients must send a matching `PASS` before registration (464 otherwise); `REHASH`-reloadable |
| `sts` | table | *unset* | IRCv3 strict transport security policy: `{ port = 6697, duration = 2592000, preload = false }`; plaintext connections are told the TLS `port`, TLS connections the `duration` (seconds; `0` clears the policy) |

**Validation:** a non-loopback `plain_bind` with `allow_plain_nonlocal =
false` is a configuration error.

## `[tls]` — required

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `cert` | path | *unset* | PEM certificate chain (leaf first) |
| `key` | path | *unset* | PEM private key |
| `self_signed_dev` | bool | `false` | generate an ephemeral self-signed cert at startup — **development only**; ignored when `cert`/`key` are set |
| `dev_hostnames` | array of string | `["localhost"]` | SANs for the dev certificate |

**Validation:** `cert` and `key` must be set together; if neither is set,
`self_signed_dev` must be `true`.

## `[limits]` — optional

All fields optional; defaults shown. See also
[Limits & Defaults](/reference/limits) for the hardcoded constants.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `max_tag_bytes` | int | `8191` | wire budget for the message-tags section (IRCv3) |
| `max_body_bytes` | int | `512` | wire budget for the message body (RFC 1459) |
| `max_line_bytes` | int | `8704` | fatal frame length — longer frames drop the connection; must be ≥ `max_tag_bytes + max_body_bytes` |
| `registration_timeout_secs` | int | `30` | seconds a connection may stay unregistered |
| `handshake_timeout_secs` | int | `15` | TLS handshake budget |
| `ping_interval_secs` | int | `120` | idle seconds before a server `PING`; a second missed interval disconnects |
| `max_clients_per_ip` | int | `10` | simultaneous connections per source IP |
| `max_channels` | int | `50` | channels per client (`CHANLIMIT`); opers exempt |
| `sendq_lines` | int | `2048` | outbound queue depth in lines; overflow disconnects (`SendQ exceeded`) |
| `recv_burst` | int | `20` | inbound token-bucket burst allowance |
| `recv_rate` | int | `10` | sustained inbound commands/second; exhaustion disconnects (`Excess Flood`) |
| `history_len` | int | `500` | retained messages per chathistory target; `0` = current-run only |
| `history_max_targets` | int | `50000` | cap on distinct in-memory history targets; LRU-evicted beyond |

## `[[accounts]]` — optional, repeatable

SASL seed accounts. See [Accounts & SASL](/guide/accounts).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | **required** | account name |
| `password` | string | *unset* | plaintext password, Argon2id-hashed at startup — development convenience |
| `password_hash` | string | *unset* | precomputed Argon2 PHC string (`ferrixd hash-password`) — production |
| `scram` | string | *unset* | precomputed SCRAM-SHA-256 credential (`<iterations>:<b64 salt>:<b64 stored_key>:<b64 server_key>`). **Required for SCRAM logins on a `password_hash` account** — the server never sees that account's plaintext and cannot derive them. `ferrixd hash-password --toml` prints `password_hash` and `scram` together; an account seeded with plaintext `password` gets SCRAM credentials automatically |
| `fingerprints` | array of string | `[]` | permitted TLS client-cert SHA-256 fingerprints (lowercase hex) for SASL EXTERNAL |

`REHASH`-reloadable. Self-registered accounts (via `REGISTER`) are stored
in `[persistence]` and merged on top.

## `[[operators]]` — optional, repeatable

IRC operator credentials for `OPER`. See
[Operators & Moderation](/guide/operators).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | **required** | operator name |
| `password` | string | *unset* | plaintext (dev only) |
| `password_hash` | string | *unset* | Argon2 PHC string (production) |
| `hosts` | array of string | `[]` | hostmask globs (`nick!user@host` or bare IP) allowed to use this block; anywhere else gets `491 ERR_NOOPERHOST`; empty = any host |

**Validation:** each operator needs `password` or `password_hash`.
`REHASH`-reloadable.

## `[[bans]]` — optional, repeatable

Startup K-lines, enforced at registration.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `mask` | string | **required** | `nick!user@host` glob (`*`, `?`) |
| `reason` | string | `"Banned"` | shown to the banned client |

`REHASH`-reloadable. Runtime additions: `KLINE`/`DLINE`
([moderation guide](/guide/operators#the-moderation-toolbox)).

## `[persistence]` — optional

SQLite durability for history, registered channels, and self-registered
accounts. Omit for in-memory-only operation. See
[Message History](/guide/history#persistence).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | path | **required** | SQLite database file (created if missing; WAL mode) |
| `load_limit` | int | `5000` | most-recent history rows loaded into RAM at startup |

## `[metrics]` — optional

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `bind` | socket address | **required** | HTTP listener for `/metrics`; **bind to loopback** — the endpoint has no auth |

Catalogue: [Metrics reference](/reference/metrics).

## `[plugins]` — optional

WASM plugin host. See [WASM Plugins](/guide/plugins).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `dir` | path | **required** | directory scanned for `*.wasm` at startup (sorted filename order) |
| `fuel` | int | `5000000` | per-hook-call instruction budget |

## `[[links]]` — optional, repeatable

S2S peer definitions. See [Federation](/guide/federation).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | **required** | peer's advertised `server.name`; must match at handshake |
| `connect` | socket address | *unset* | peer's `link_bind`; omit for accept-only links |
| `fingerprint` | string | **required** | peer TLS cert SHA-256, lowercase hex (`ferrixd fingerprint`) — pinned |
| `password` | string | **required** | shared link secret, compared in constant time |
| `protocol` | string | `"ferrix"` | wire protocol on this link: `"ferrix"` (native) or `"ts6"` (charybdis-family bridge, e.g. solanum) |

## What `REHASH` reloads

| Reloadable at runtime | Restart required |
| --- | --- |
| `[[accounts]]`, `[[operators]]`, `[[bans]]`, `server.motd`, `server.password` | listeners, `[tls]`, `[limits]`, `[persistence]`, `[metrics]`, `[plugins]`, `[[links]]`, `sid`, `cloak_key`, `casemapping` |

## Complete annotated example

The exact file `ferrixd gen-config` writes:

<<< @/../ferrixd.example.toml{toml}
