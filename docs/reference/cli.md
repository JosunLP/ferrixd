# CLI Reference

The single `ferrixd` binary contains the server and all of its tooling —
no side scripts, no `openssl` required. `ferrixd --help` and
`ferrixd <cmd> --help` are always authoritative.

## Global flags

Valid before any subcommand:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-c, --config <PATH>` | `ferrixd.toml` | config file path |
| `--log <FILTER>` | — | log filter, overrides `RUST_LOG` (e.g. `debug`, `info,ferrixd::link=debug`) |
| `--log-format <FMT>` | `full` | `full` \| `compact` \| `pretty` |
| `--color <WHEN>` | `auto` | `auto` \| `always` \| `never` |

Exit status: `0` on success; any error prints `error: …` to stderr and
exits `1`.

## `ferrixd [run]`

Runs the server. `run` is the default — `ferrixd` alone does the same.

```sh
ferrixd
ferrixd run --dev
```

| Flag | Meaning |
| --- | --- |
| `--dev` | ignore the config file; start a zero-config local server: TLS on `127.0.0.1:6697` (ephemeral self-signed cert) plus plaintext on `127.0.0.1:6667` |

Starts, in order: the TLS listener, the plaintext listener (if configured),
the metrics endpoint (if configured), S2S outbound connectors and the link
listener (if configured). Runs until `Ctrl-C` or `SIGTERM` — both trigger
the same graceful shutdown (persistence queue drained, connections closed).

## `ferrixd check`

```sh
ferrixd -c /etc/ferrixd/ferrixd.toml check
```

Loads and validates the configuration **and builds the TLS material** —
certificate/key errors surface here rather than at startup. Prints a
colorized summary of what a `run` would start (listeners, limits, counts of
accounts/operators/bans, persistence, metrics, links, plugins). Exits
non-zero on any problem; designed as a CI/deploy gate.

## `ferrixd gen-config`

Alias: `genconfig`.

```sh
ferrixd gen-config                 # writes ./ferrixd.toml
ferrixd gen-config -o /etc/ferrixd/ferrixd.toml -f
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-o, --output <PATH>` | `ferrixd.toml` | destination |
| `-f, --force` | off | overwrite an existing file |

Writes the fully commented example configuration (the same one documented
in the [configuration reference](/reference/config)).

## `ferrixd gen-cert`

Alias: `gencert`.

```sh
ferrixd gen-cert -H irc.example.org -H irc-alt.example.org \
    --cert /etc/ferrixd/cert.pem --key /etc/ferrixd/key.pem
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-H, --host <NAME>` | `localhost` | subject/SAN hostname; repeatable |
| `--cert <PATH>` | `cert.pem` | certificate output |
| `--key <PATH>` | `key.pem` | private key output (mode `0600` on Unix) |
| `-f, --force` | off | overwrite existing files |

Mints a self-signed certificate + key (PEM) and prints the certificate's
SHA-256 fingerprint — ready for `[[links]].fingerprint` pinning or SASL
EXTERNAL.

## `ferrixd hash-password`

Alias: `hashpw`.

```sh
ferrixd hash-password
ferrixd hash-password --confirm
ferrixd hash-password --toml               # password_hash + scram, ready to paste
echo -n 's3cret' | ferrixd hash-password    # first stdin line when not a TTY
```

| Flag | Meaning |
| --- | --- |
| `--confirm` | prompt twice and require a match |
| `--toml` | print `password_hash = "…"` **and** `scram = "…"` — the SCRAM credential an account needs for SASL SCRAM-SHA-256, which cannot be derived from the Argon2 hash ([why](/guide/accounts#scram-sha-256)) |

Reads a password (no echo on a TTY) and prints its **Argon2id** PHC hash
for `password_hash` fields in `[[accounts]]` / `[[operators]]`. Refuses an
empty password.

## `ferrixd fingerprint`

```sh
ferrixd fingerprint /etc/ferrixd/cert.pem
```

Prints the SHA-256 fingerprint (lowercase hex) of a PEM certificate — the
format expected by `[[links]].fingerprint` and `[[accounts]].fingerprints`.

## `ferrixd completions`

```sh
ferrixd completions bash|zsh|fish|elvish|powershell
```

Emits a shell-completion script to stdout. See
[Installation](/guide/installation#shell-completions) for where to put it.

## Signals

| Signal | Effect |
| --- | --- |
| `SIGINT` (Ctrl-C) | graceful shutdown |
| `SIGTERM` | graceful shutdown (what `systemctl stop` / `docker stop` send) |

Graceful shutdown drains the persistence write queue (2-second grace) and
closes connections cleanly.
