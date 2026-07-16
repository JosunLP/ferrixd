# What is ferrixd?

**ferrixd** (*Ferrous IRC Daemon*) is an RFC-conformant, IRCv3-complete IRC
server written from scratch in Rust. It exists because IRC — the oldest
federated chat protocol still in daily use — deserved a server built with
modern engineering standards: memory safety, attack resistance, honest
persistence, and high connection density.

The name is a chemistry joke that got out of hand: **Fe**, element 26, is
iron; Rust is what iron becomes; ferrixd is an IRC daemon written in Rust.
The logo is iron's periodic-table tile.

## What you get

A single static binary that is:

- **A complete IRC server.** Registration, channels, modes, topics, WHO/WHOIS,
  MOTD, LUSERS, MONITOR, LIST — the full classic surface, with consistent
  `ascii` or `rfc1459` case mapping.
- **An IRCv3 server.** 26 capabilities, including `server-time`,
  `message-tags`, `batch`, `echo-message`, `labeled-response`,
  `standard-replies`, `draft/chathistory`, `draft/multiline`, and
  `draft/metadata-2`. Capabilities are implemented against the spec text, not
  against what other servers happen to do. See the
  [capability reference](/reference/capabilities).
- **Its own services.** Accounts, SASL (`PLAIN`, `EXTERNAL`,
  `SCRAM-SHA-256`), account self-registration, and channel registration are
  built into the daemon — there is no bolted-on NickServ/ChanServ
  pseudo-server to keep in sync or crash independently.
- **A federation node.** Servers link over mutual TLS with pinned certificate
  fingerprints and form a multi-hop mesh: cross-server channels, messages,
  WHOIS, netsplit cleanup, and deterministic nick-collision resolution — no
  synchronized clocks required. See [Federation](/guide/federation).
- **Extensible, safely.** Moderation hooks can be written as sandboxed WASM
  plugins executed under a fuel budget — a buggy or malicious plugin traps
  instead of hanging the server. See [WASM Plugins](/guide/plugins).
- **Operable.** Prometheus metrics, structured tracing, `REHASH` hot-reload,
  a config validator (`ferrixd check`), and built-in helpers for certificates
  and password hashes. See [Observability](/guide/observability).

## What makes it different

### Memory safety is not negotiable

`unsafe_code = "forbid"` applies to the entire workspace — not "minimal
unsafe", **zero**. The wire parser, the security-critical hot path, lives in
its own dependency-light crate (`ferrix-protocol`) so it can be fuzzed and
audited in isolation. It parses without copying, never panics on hostile
input, and CI promotes `panic!`/`unwrap`/`expect` in the data path to
build errors.

### TLS is the transport, not an option

The primary listener is TLS. A plaintext listener exists for local testing
only: binding it to a non-loopback address is a **configuration error**
unless you explicitly set `allow_plain_nonlocal = true`. Passwords are hashed
with Argon2id and verified in constant time; hosts can be cloaked with an
HMAC so they are unforgeable.

### Designed for hostile networks

Every resource a client can consume is bounded: outbound queues (SendQ),
inbound command rate (token bucket), connections per IP, registration time,
TLS handshake time, history memory, list-mode entries. Exceeding a bound has
a defined, documented consequence — usually disconnection with a reason that
shows up in the [metrics](/reference/metrics).

### Density as a feature

One async task per connection — not one thread — over a fixed worker pool and
sharded shared state. Load-tested to **~100,000 concurrent connections** on
an 8-core host at ~1.38 GB RSS (~13.8 KB per connection), scaling linearly.
The methodology and generator live in the repository's `loadtest/` directory.

## What it is not

- **Not a TS6/legacy-protocol server.** The S2S protocol is modern and
  ferrixd-native ([spec here](/reference/s2s-protocol)). Linking to
  charybdis/solanum works through the dedicated
  [TS6 bridge](/guide/federation#bridging-to-ts6-ircds), which translates
  at the network edge — the native protocol stays legacy-free.
- **Not a hosted service.** ferrixd is software you run. It has no accounts
  web portal, no built-in web client.
- **Not finished deciding what IRC should be.** Draft capabilities
  (`draft/…`) are implemented as drafts and will track the specs as they
  stabilize.

## Where to go next

| You want to… | Read |
| --- | --- |
| See it run in 60 seconds | [Quick Start](/guide/quick-start) |
| Install it properly | [Installation](/guide/installation) |
| Configure a real server | [Configuration](/guide/configuration) |
| Link two servers | [Federation](/guide/federation) |
| Look up an exact flag, cap, or limit | [Reference](/reference/cli) |
| Understand how it's built | [Architecture](/internals/architecture) |
