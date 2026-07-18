# Configuration

ferrixd reads a single TOML file — `./ferrixd.toml` by default, or wherever
`-c/--config` points. This page is a guided tour; the complete field-by-field
schema lives in the [configuration reference](/reference/config).

## The workflow

```sh
ferrixd gen-config     # 1. scaffold a commented ferrixd.toml
$EDITOR ferrixd.toml   # 2. edit
ferrixd check          # 3. validate config AND TLS material, print a summary
ferrixd                # 4. run (equivalent to `ferrixd run`)
```

`ferrixd check` is not a syntax check only — it loads the certificates and
keys, so a broken PEM file fails **here**, not at 3 a.m. during a restart.

::: tip Fail-closed configuration
The parser rejects unknown keys. If you typo `moddt = […]`, the server
refuses to start instead of silently ignoring your MOTD. This is deliberate:
a config that loads is a config that means what you think it means.
:::

## A minimal real server

```toml
[server]
name = "irc.example.org"        # advertised server name (numerics, prefixes)
network = "examplenet"          # ISUPPORT NETWORK=
tls_bind = "0.0.0.0:6697"

[tls]
cert = "/etc/ferrixd/fullchain.pem"
key  = "/etc/ferrixd/privkey.pem"
```

That's everything a working TLS-only server needs. Everything else on this
page is opt-in.

## Section by section

### `[server]` — identity and listeners

```toml
[server]
name = "irc.example.org"
network = "examplenet"
casemapping = "ascii"           # or "rfc1459"; must match network-wide
motd = [
    "Welcome to examplenet.",
    "Be excellent to each other.",
]
tls_bind = "0.0.0.0:6697"
```

- `casemapping` decides how nicks and channel names fold (`ascii` is the
  modern default; `rfc1459` treats `{}|^` as `[]\~`). Pick one per network
  and don't change it with users online.
- `motd` is a list of lines, no file needed. Reloadable with
  [`REHASH`](/guide/operators#rehash).

- `icon` (optional) advertises a network icon URL to clients that support it
  (IRCv3 `draft/network-icon`, sent as `ISUPPORT draft/ICON=`):

```toml
icon = "https://examplenet.org/icon.svg"
```

**Plaintext**, if you really need it, is loopback-only by design:

```toml
plain_bind = "127.0.0.1:6667"
# binding plain_bind to a non-loopback address is a config ERROR unless:
# allow_plain_nonlocal = true
```

**WebSockets** let browser clients connect natively (no gateway):

```toml
wss_bind = "0.0.0.0:443"        # secure; terminates TLS with the [tls] cert
ws_bind  = "127.0.0.1:8080"     # plaintext; loopback-only (same rule as plain_bind)
```

`wss_bind` is the browser-facing form and reuses the `[tls]` certificate (and
its `REHASH` reloads). Each IRC line is one WebSocket message; the server
negotiates the `text.ircv3.net`/`binary.ircv3.net` subprotocols. See
[TLS → WebSocket transport](/guide/tls#websocket-transport-ws-wss).

**Host cloaking** hides user hostnames behind an unforgeable HMAC:

```toml
cloak_key = "a-long-random-secret-keep-this-private"
```

See [Operators & Moderation](/guide/operators#host-cloaking) for what cloaks
look like and how bans interact with them.

**Federation** identity (only needed when linking servers):

```toml
sid = "42F"                     # unique server id across the network
link_bind = "0.0.0.0:6666"      # inbound S2S listener (omit for connect-only)
```

### `[tls]` — certificates

```toml
[tls]
cert = "/etc/ferrixd/fullchain.pem"
key  = "/etc/ferrixd/privkey.pem"
# or, for development only:
# self_signed_dev = true
# dev_hostnames = ["localhost", "irc.example.test"]
```

`cert`/`key` must be set together. If neither is set, `self_signed_dev`
must be `true`. Full details, Let's Encrypt notes, and the built-in
`gen-cert` helper: [TLS Certificates](/guide/tls).

### `[limits]` — budgets and DoS controls

Every limit has a sensible default; the section is optional. The interesting
knobs:

```toml
[limits]
registration_timeout_secs = 30  # unregistered connections are dropped after this
handshake_timeout_secs = 15     # TLS handshake budget
ping_interval_secs = 120        # idle PING; 2nd miss disconnects

max_clients_per_ip = 10         # per-IP connection throttle
max_channels = 50               # per-client channel cap (opers exempt)
sendq_lines = 2048              # outbound queue depth; overflow = disconnect
recv_burst = 20                 # inbound token bucket: burst…
recv_rate = 10                  # …and sustained commands/sec

history_len = 500               # retained messages per chathistory target
history_max_targets = 50000     # bound on distinct in-memory history targets
```

Wire-length budgets (`max_tag_bytes`, `max_body_bytes`, `max_line_bytes`)
default to the IRCv3 values — leave them alone unless you know why you're
changing them. The full table with all defaults:
[Limits & Defaults](/reference/limits).

### `[[accounts]]` — seed accounts for SASL

```toml
[[accounts]]
name = "alice"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$…$…"   # ferrixd hash-password
fingerprints = ["a1b2c3…"]                             # SASL EXTERNAL (optional)
```

Plaintext `password = "…"` also works (hashed with Argon2id at startup) but
belongs in development only. Users can also self-register at runtime with
`REGISTER`, and those accounts persist if `[persistence]` is enabled. All of
this: [Accounts & SASL](/guide/accounts).

### `[[operators]]` — IRC operators

```toml
[[operators]]
name = "admin"
password_hash = "$argon2id$…"
```

Grants access to `OPER`, and through it `KILL`, K/D/G-lines, `WALLOPS`,
`CHGHOST`, and `REHASH`. See [Operators & Moderation](/guide/operators).

### `[[bans]]` — startup K-lines

```toml
[[bans]]
mask = "*!*@203.0.113.0/24"
reason = "Banned network"
```

Matched at registration; reloadable with `REHASH`.

### `[[webirc]]` — trusted WEBIRC gateways

Let a web/IRC gateway present a client's real host and IP (so users behind it
are seen and moderated by their own address, not the gateway's):

```toml
[[webirc]]
name = "kiwi"                        # matched against the WEBIRC <gateway> field
password = "long-random-shared-secret"
hosts = ["127.0.0.1", "10.0.0.*"]   # source addresses the gateway may use
```

A `WEBIRC` is honoured only as the connection's first command, from an
allow-listed source, with a matching secret (compared in constant time); the
spoofed IP is then re-checked against D-lines. Reloadable with `REHASH`.

### `[persistence]` — SQLite durability

```toml
[persistence]
path = "/var/lib/ferrixd/ferrixd.db"
load_limit = 5000               # recent messages loaded into RAM at startup
```

One file, three jobs: chathistory rows, registered channels, and
self-registered accounts all live here and survive restarts — including
`msgid` continuity. Omit the section for in-memory-only operation.
Details: [Message History](/guide/history).

### `[metrics]` — Prometheus endpoint

```toml
[metrics]
bind = "127.0.0.1:9090"         # scrape http://127.0.0.1:9090/metrics
```

Bind it to loopback (or a private interface) — there is no auth on the
endpoint. Metric catalogue: [Metrics](/reference/metrics).

### `[plugins]` — WASM plugin host

```toml
[plugins]
dir = "/etc/ferrixd/plugins"    # every *.wasm in here is loaded at startup
fuel = 5000000                  # per-call instruction budget
```

See [WASM Plugins](/guide/plugins).

### `[[links]]` — S2S peers

```toml
[[links]]
name = "irc2.example.org"
connect = "irc2.example.org:6666"   # omit for accept-only
fingerprint = "a1b2c3…"             # peer cert SHA-256 (ferrixd fingerprint)
password = "shared-link-secret"
```

See [Federation](/guide/federation) for the full linking walkthrough.

## Reloading without restarting

`REHASH` (oper-only) re-reads the config file and applies the reloadable
subset — **accounts, operators, bans, the MOTD, WEBIRC gateways, the
connection password, and the TLS certificate/key** — without dropping a
single connection. Listener bind addresses and limits still require a
restart. See [what `REHASH` reloads](/reference/config#what-rehash-reloads)
and [Operators & Moderation](/guide/operators#rehash).

## Validating in CI

`ferrixd check` exits non-zero on any problem, which makes it a natural
pre-deploy gate:

```sh
ferrixd -c deploy/ferrixd.toml check
```
