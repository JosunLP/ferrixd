# TLS Certificates

TLS is ferrixd's primary transport — the `[tls]` section is required, and
the server won't start without either a real certificate or an explicit
opt-in to a development self-signed one.

## Option A: real certificates (production)

```toml
[tls]
cert = "/etc/ferrixd/fullchain.pem"
key  = "/etc/ferrixd/privkey.pem"
```

Both paths must be PEM. `cert` should be the **full chain** (leaf first,
then intermediates) so clients can validate without fetching intermediates.
`cert` and `key` must be set together — configuring only one is an error.

### Let's Encrypt

Any ACME client works; ferrixd just reads PEM files. With certbot:

```sh
certbot certonly --standalone -d irc.example.org
```

```toml
[tls]
cert = "/etc/letsencrypt/live/irc.example.org/fullchain.pem"
key  = "/etc/letsencrypt/live/irc.example.org/privkey.pem"
```

Two operational notes:

1. **Permissions.** ferrixd should run as an unprivileged user; make sure
   that user can read the key (a deploy hook that copies the pair into
   `/etc/ferrixd/` with tight ownership is the usual pattern).
2. **Renewal is hot — no restart.** `REHASH` reloads the certificate and
   key for every TLS listener (client, `wss://`, and the S2S link
   listener) and rebuilds the TLS client configuration used for **all**
   outbound links, without dropping the process or any live connection: only
   handshakes started after the reload use the new material. Point your
   certbot deploy hook at a `REHASH` (e.g. send the operator command, or
   trigger it however you drive the server) instead of a full restart. If
   the new PEM is unreadable or malformed the reload fails and the
   **previous** certificate stays armed, so a botched renewal never leaves
   the listener without a certificate. An established outbound link keeps the
   certificate it handshook with until it reconnects; the next (re)connect —
   whether the auto-dial reconnect loop after a drop, an operator `CONNECT`,
   or a `SQUIT` + `CONNECT` — presents the reloaded certificate automatically.

Validate before reloading:

```sh
ferrixd check
```

`check` builds the actual TLS configuration, so an unreadable key, a
mismatched pair, or a malformed PEM fails here with a precise error.

## Option B: self-signed (development)

```toml
[tls]
self_signed_dev = true
dev_hostnames = ["localhost", "irc.example.test"]
```

Generates an **ephemeral** certificate at startup — new on every start,
never written to disk. Clients must disable verification. This is exactly
what `ferrixd run --dev` uses. Never use it in production; the config
comment says the same thing.

If `cert`/`key` are set, `self_signed_dev` is ignored.

## Option C: pinned self-signed (small private networks)

Between "real CA" and "ephemeral throwaway" there is a third, perfectly
sound setup for private networks: a **stable** self-signed certificate that
clients and link peers pin by fingerprint.

```sh
ferrixd gen-cert -H irc.example.test -H irc-alt.example.test \
    --cert /etc/ferrixd/cert.pem --key /etc/ferrixd/key.pem
```

`gen-cert` writes the pair (private key `chmod 0600` on Unix), and prints
the certificate's SHA-256 fingerprint. Reference the files from `[tls]` as
in Option A. You can re-print the fingerprint any time:

```sh
ferrixd fingerprint /etc/ferrixd/cert.pem
```

This is also the recommended setup for **S2S links**, which don't use CA
validation at all — peers authenticate each other by pinned fingerprint
plus a shared secret. See [Federation](/guide/federation).

## Client certificates (SASL EXTERNAL)

ferrixd accepts TLS client certificates and can use their SHA-256
fingerprint as an authentication factor via SASL `EXTERNAL` — passwordless
login. The account lists its permitted fingerprints:

```toml
[[accounts]]
name = "alice"
fingerprints = ["3f6a…"]   # lowercase hex SHA-256
```

Generate a client cert with any tool (or `ferrixd gen-cert`), get its
fingerprint with `ferrixd fingerprint`, and configure your IRC client to
present it. Details: [Accounts & SASL](/guide/accounts#sasl-external).

## Plaintext, and why it is caged

```toml
[server]
plain_bind = "127.0.0.1:6667"
```

A plaintext listener exists because `nc 127.0.0.1 6667` is a wonderful
debugging tool. It is restricted to loopback: a non-loopback `plain_bind`
fails validation unless you also set `allow_plain_nonlocal = true`, which
exists for one legitimate case — terminating TLS in a trusted local proxy.
If that's not you, don't set it.

## WebSocket transport (`ws://` / `wss://`)

Browser clients speak IRC over WebSockets. ferrixd serves them natively — no
gateway process:

```toml
[server]
wss_bind = "0.0.0.0:8443"  # secure: terminates TLS with the [tls] cert below
ws_bind  = "127.0.0.1:8080" # plaintext: loopback-only unless allow_plain_nonlocal
```

`wss_bind` uses the same certificate as `tls_bind` (and picks up a
`REHASH`-triggered certificate swap the same way). Each IRC line is one
WebSocket message with no trailing CRLF; the server negotiates the
`text.ircv3.net` and `binary.ircv3.net` subprotocols. `ws_bind` is plaintext
and, like `plain_bind`, is loopback-only unless `allow_plain_nonlocal = true` —
prefer `wss_bind` for anything a browser reaches over the network.

## Timeouts

Two `[limits]` knobs guard the connection setup path:

| Setting | Default | Guards against |
| --- | --- | --- |
| `handshake_timeout_secs` | 15 | clients that open a socket and stall the TLS handshake |
| `registration_timeout_secs` | 30 | connections that complete TLS but never register |

Both free the slot by closing the connection.
