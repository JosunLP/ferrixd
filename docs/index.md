---
layout: home

hero:
  name: ferrixd
  text: The Ferrous IRC Daemon
  tagline: >-
    A from-scratch, memory-safe, IRCv3-complete IRC server in Rust —
    TLS-first, federated over mutual TLS, and load-tested to 100,000
    concurrent connections on a single node.
  image:
    src: /logo.svg
    alt: ferrixd — Fe, element 26
  actions:
    - theme: brand
      text: Quick Start
      link: /guide/quick-start
    - theme: alt
      text: Install
      link: /guide/installation
    - theme: alt
      text: What is ferrixd?
      link: /guide/what-is-ferrixd

features:
  - icon: 🦀
    title: Memory-safe to the wire
    details: >-
      Zero unsafe code — forbidden at the workspace level. The zero-copy
      parser lives in its own audited, fuzzed crate and never panics on
      hostile input. No panic!/unwrap in the data path, enforced by CI.
  - icon: 🔐
    title: TLS-first, hardened by default
    details: >-
      TLS is the primary transport; plaintext must be explicitly enabled and
      is loopback-only unless you insist. SASL PLAIN, EXTERNAL, and
      SCRAM-SHA-256 over Argon2id-hashed accounts, verified in constant time.
  - icon: 📡
    title: IRCv3-complete
    details: >-
      26 capabilities including server-time, message-tags, batch,
      labeled-response, draft/chathistory, draft/multiline, and
      draft/metadata-2 — implemented against the spec text and covered by
      the integration suite.
  - icon: 🕸️
    title: Federated, without the folklore
    details: >-
      A modern S2S mesh — mutual-TLS certificate pinning, Lamport clocks
      instead of synchronized wall time, deterministic nick-collision
      resolution, and clean netsplit handling across multi-hop link trees.
  - icon: 🧱
    title: History that survives restarts
    details: >-
      Server-side chathistory with msgid continuity, backed by SQLite
      write-behind persistence. Channels can be registered; their topic,
      modes, and founder come back after a restart.
  - icon: 🧩
    title: Sandboxed WASM plugins
    details: >-
      Extend moderation with .wasm plugins run by a pure-Rust interpreter
      under a per-call fuel budget — a runaway plugin traps, it never wedges
      the server. No ambient authority.
  - icon: 🛡️
    title: Built to be attacked
    details: >-
      Bounded SendQ, token-bucket rate limits, per-IP throttling, ping
      timeouts, K/D/G-lines, HMAC host cloaking, and fail-closed
      configuration — a typo is an error, not a silent misconfiguration.
  - icon: ⚡
    title: 100k connections per node
    details: >-
      ~13.8 KB of memory per connection at 100,000 concurrent clients on an
      8-core host — one async task per connection, a fixed worker-thread
      count, and sharded state instead of a global lock.
  - icon: 📦
    title: One static binary
    details: >-
      Prebuilt for Linux (static musl), macOS, Windows, FreeBSD, and
      Android/Termux, with a checksum-verifying one-line installer. Config
      generation, cert minting, and password hashing are built in.
---

<IrcTerminal />

<div class="fx-home-outro">

## Thirty-five years old, and still the right shape

IRC is the simplest federated chat protocol that actually works: plain text
over a socket, readable with `openssl s_client`, implementable in an
afternoon. What it never had was a server built like it matters — memory-safe,
spec-complete, hostile-input-proof, and honest about persistence.

**ferrixd** is that server. Element 26, oxidised into software.

```sh
curl -fsSL https://raw.githubusercontent.com/j-pfalzgraf/ferrixd/main/scripts/install.sh | sh
ferrixd gen-config && ferrixd check && ferrixd
```

</div>

<style>
.fx-home-outro {
  max-width: 960px;
  margin: 0 auto;
  padding: 48px 24px 24px;
}
.fx-home-outro h2 {
  border-top: none;
  font-size: 26px;
  letter-spacing: -0.02em;
}
</style>
