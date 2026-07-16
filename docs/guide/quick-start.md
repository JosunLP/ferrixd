# Quick Start

Goal: a running IRC server and two connected clients, in about a minute.
No config file, no certificates, nothing to clean up afterwards.

## 1. Get a binary

Either install a release build:

```sh
curl -fsSL https://raw.githubusercontent.com/j-pfalzgraf/ferrixd/main/scripts/install.sh | sh
```

…or run straight from a source checkout:

```sh
git clone https://github.com/j-pfalzgraf/ferrixd
cd ferrixd
cargo run -p ferrixd -- run --dev   # add `--release` for realistic performance
```

(For all install options — Windows, Docker, Termux, version pinning — see
[Installation](/guide/installation).)

## 2. Start a dev server

```sh
ferrixd run --dev
```

`--dev` ignores any config file and starts a zero-config local server:

- **TLS** on `127.0.0.1:6697` with an ephemeral self-signed certificate,
- **plaintext** on `127.0.0.1:6667` (loopback only, so `nc` works too).

You should see the listeners in the startup log. Stop it any time with
`Ctrl-C` — shutdown is graceful.

::: warning Dev mode is for development
The self-signed certificate changes on every start and the state is
in-memory only. For anything reachable from another machine, write a config:
[Configuration](/guide/configuration).
:::

## 3. Talk to it by hand

The fastest sanity check needs no IRC client at all:

```sh
nc 127.0.0.1 6667
```

Then type raw IRC — the protocol is line-based text:

```
NICK alice
USER alice 0 * :Alice
```

The server replies with the welcome burst (`001`…`005`, LUSERS, MOTD). Now:

```
JOIN #forge
PRIVMSG #forge :hello, world
PING :are-you-there
```

…and you'll get your join echo and `PONG :are-you-there` back. Over TLS the
same works via:

```sh
openssl s_client -connect 127.0.0.1:6697 -quiet
```

## 4. Connect a real client

Point any IRC client at `localhost` port `6697` with TLS enabled and
**certificate verification disabled** (it's self-signed). For example, with
[WeeChat](https://weechat.org/):

```
/server add ferrix localhost/6697 -tls
/set irc.server.ferrix.tls_verify off
/connect ferrix
/join #forge
```

Open a second client (or a second `nc`), join `#forge`, and chat. You now
have message echo, `server-time` tags, away notifications — the works —
between two clients over TLS.

## 5. Peek at the modern parts

With a client that speaks IRCv3 (most do), try:

```
/msg #forge hello again
/quote CHATHISTORY LATEST #forge * 10
```

The server replays recent channel history in a `batch`, each message carrying
the same `msgid` it had when delivered live.

## Next steps

- [Installation](/guide/installation) — put a release binary on a real host.
- [Configuration](/guide/configuration) — `gen-config`, `check`, and a
  walkthrough of every section.
- [TLS Certificates](/guide/tls) — real certs, or `gen-cert` for pinned
  self-signed setups.
- [Accounts & SASL](/guide/accounts) — give users durable identities.
