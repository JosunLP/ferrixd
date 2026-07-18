# Accounts & SASL

ferrixd has accounts built in — no external services daemon. An account
gives a user a stable identity: it shows up in `account-tag` and
`extended-join`, drives account extbans (`~a:`), grants an unforgeable
cloak, and is what channel registration hangs off.

There are two ways accounts come to exist:

1. **Seeded from the config** — `[[accounts]]` tables, the operator-managed
   way.
2. **Self-registered at runtime** — the `REGISTER` command
   (`draft/account-registration`), persisted to SQLite when
   `[persistence]` is enabled.

## Seeding accounts in the config

```toml
[[accounts]]
name = "alice"
# Production: a precomputed Argon2id PHC hash.
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$…$…"
# SASL EXTERNAL: permitted TLS client-cert fingerprints (lowercase hex SHA-256).
fingerprints = ["3f6a1c…"]

[[accounts]]
name = "bob"
# Development convenience: plaintext, hashed with Argon2id at startup.
password = "change-me"
```

Generate hashes with the built-in helper (prompts without echo; `--confirm`
prompts twice):

```sh
ferrixd hash-password
```

Config accounts are reloadable at runtime with
[`REHASH`](/guide/operators#rehash).

::: details How passwords are stored and checked
Passwords are hashed with **Argon2id** and verified in constant time. For
SCRAM, the server derives and stores the SCRAM key material
(salt, 4096 PBKDF2 iterations, stored key, server key) — the plaintext
password is never kept. See [Security Model](/internals/security).
:::

## SASL mechanisms

ferrixd advertises `sasl=PLAIN,EXTERNAL,SCRAM-SHA-256` in `CAP LS 302`.

### PLAIN

The workhorse. The client sends `\0username\0password` base64-encoded during
registration; the server verifies against the Argon2id hash. Since the
transport is TLS, the password is never on the wire in the clear.

Client-side (WeeChat):

```
/set irc.server.ferrix.sasl_mechanism plain
/set irc.server.ferrix.sasl_username alice
/set irc.server.ferrix.sasl_password s3cret
```

### SCRAM-SHA-256

Challenge–response: the password never leaves the client, and the server
stores only derived keys. Prefer it when your client supports it — it also
protects the password from a compromised-but-passive server.

::: warning A `password_hash` account needs an explicit `scram` credential
SCRAM key material cannot be derived from an Argon2 hash — deriving it needs
the plaintext, which a `password_hash` account never gives the server. Such
an account can therefore do PLAIN but **not** SCRAM unless you also supply a
`scram = "…"` credential. Mint both at once:

```
$ ferrixd hash-password --toml
Password:
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$…"
scram = "4096:…:…:…"
```

Paste both lines into the `[[accounts]]` block. An account seeded with a
plaintext `password` gets its SCRAM credentials derived automatically and
needs nothing extra.
:::

```
/set irc.server.ferrix.sasl_mechanism scram-sha-256
```

### SASL EXTERNAL

Passwordless: authentication is the TLS client certificate itself. The
server hashes the presented certificate (SHA-256) and matches it against the
account's `fingerprints` list.

Setup:

```sh
# 1. Mint a client certificate (any tool works; gen-cert is convenient)
ferrixd gen-cert -H alice --cert alice.pem --key alice.key

# 2. Read its fingerprint
ferrixd fingerprint alice.pem
```

```toml
# 3. Allow it on the account
[[accounts]]
name = "alice"
fingerprints = ["<the fingerprint>"]
```

```
# 4. Point the client at the cert and select EXTERNAL (WeeChat)
/set irc.server.ferrix.tls_cert ~/.config/weechat/alice.pem
/set irc.server.ferrix.sasl_mechanism external
```

## The wire flow

For the curious (or for writing a bot without a SASL library) — PLAIN looks
like this during connection registration:

```
» CAP LS 302
« :irc.example.org CAP * LS :sasl=PLAIN,EXTERNAL,SCRAM-SHA-256 …
» CAP REQ :sasl
« :irc.example.org CAP * ACK :sasl
» AUTHENTICATE PLAIN
« AUTHENTICATE +
» AUTHENTICATE AGFsaWNlAHMzY3JldA==
« :irc.example.org 900 * *!*@* alice :You are now logged in as alice
« :irc.example.org 903 * :SASL authentication successful
» CAP END
```

Long payloads are chunked in 400-byte `AUTHENTICATE` lines per the spec; the
server bounds the accumulated buffer at 8192 bytes (`ERR_SASLTOOLONG`
beyond that).

### Reauthentication

A client that negotiated `sasl` may run `AUTHENTICATE` again **after**
registration to switch to (or add) an account, without reconnecting (IRCv3
SASL 3.2). The exchange is identical to the one above — the same `900`/`903`
confirm the new login. On success the new account replaces the old (and
co-members with `account-notify` see the `ACCOUNT` change); a **failed**
attempt is rejected with `904 ERR_SASLFAIL` and the existing login is kept.
During the initial handshake, by contrast, a client may authenticate only
once (`907 ERR_SASLALREADY`).

## Self-registration: `REGISTER`

With the `draft/account-registration` capability, users can create their own
account:

```
REGISTER * your@email.example s3cret
```

(The first parameter is the account name; `*` means "use my current nick".)
Outcomes are reported as `standard-replies`, e.g.
`FAIL REGISTER ACCOUNT_EXISTS …` if the name is taken.

- With `[persistence]` configured, self-registered accounts are stored in
  SQLite and survive restarts.
- Without it, they last until the process exits — fine for testing, surprising
  in production, so enable persistence on real servers.

::: warning No email verification
The email parameter is accepted but not verified — there is no outbound
mail. Treat self-registration as open enrollment, or disable exposure by
simply not advertising it to your users and seeding accounts via config.
:::

## What an account changes

Once logged in (any mechanism):

| Effect | Where it shows |
| --- | --- |
| `account-tag` on your messages | clients with the cap see `@account=alice` |
| `extended-join` | your account name in JOIN lines |
| `account-notify` | login/logout broadcast to common channels |
| `RPL_WHOISACCOUNT` (330) | `WHOIS` shows "is logged in as" |
| Account extbans | `+b ~a:badguy` matches the account, not the mask |
| Cloak `alice.<network>` | with `cloak_key` set, your host is your identity |
| Channel registration | `REGISTER #chan` requires a logged-in founder |

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `904 ERR_SASLFAIL` on PLAIN | wrong password, or account only exists in a config that hasn't been `REHASH`ed |
| `904` on EXTERNAL | client didn't present a certificate, or fingerprint not in `fingerprints` (must be lowercase hex) |
| `905 ERR_SASLTOOLONG` | client sent >8 KiB of SASL data — misbehaving client |
| `906 ERR_SASLABORTED` | client sent `AUTHENTICATE *` — usually a client-side timeout |
| Account gone after restart | self-registered without `[persistence]` |
