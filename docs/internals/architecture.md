# Architecture

How ferrixd is put together, and why. This page is for contributors and
for operators who want to reason about the system they run.

## Design tenets

The implementation follows a written technical plan; four decisions from it
shape everything:

1. **Single-node first.** The single-server experience was built and
   hardened before federation, so the design isn't chained to legacy
   netsplit semantics. S2S arrived last, as a layer — not as the
   foundation everything else must appease.
2. **Integrated services.** Accounts, SASL, and channel registration are
   part of the daemon. The traditional pseudo-server services model
   (NickServ as a fake linked server) is a fragile artifact of history,
   not a requirement.
3. **Sharded state + mailboxes**, not one big lock and not one big actor.
   Shared state lives in concurrent maps; each connection owns a private
   outbound mailbox. The dispatcher is the single authorization
   chokepoint.
4. **Adversarial testing from day one.** The parser is fuzzed; an
   end-to-end integration suite drives real connections; clippy lints
   promoting `panic!`/`unwrap` to errors gate CI.

## Workspace layout

```
ferrixd/
├── crates/
│   ├── ferrix-protocol/   # zero-copy IRC/IRCv3 message model, parser, encoder
│   └── ferrixd/           # the daemon
├── fuzz/                  # cargo-fuzz harness for the parser (nightly)
├── loadtest/              # connection-density load generator (excluded crate)
├── scripts/               # install/update/uninstall (sh + PowerShell)
└── .github/workflows/     # CI + release build matrix
```

### `ferrix-protocol`: the parser in a padded cell

The wire parser is the security-critical hot path: it faces every byte an
attacker can send. It therefore lives in its **own dependency-light
crate**, where it can be fuzzed and audited in isolation:

- **Zero-copy** — parsing borrows from the input buffer; hostile input
  costs no allocations.
- **Total** — malformed frames return `Result::Err`, never panic. The
  fuzz harness (`cargo +nightly fuzz run parse_message`) enforces this
  continuously.
- **Budgeted** — tags (8,191 B) and body (512 B) have separate length
  budgets, per IRCv3.

### `ferrixd`: the daemon

Module map (all under `crates/ferrixd/src/`):

| Area | Modules |
| --- | --- |
| Boot & I/O | `cli`, `config`, `tls`, `codec`, `listener`, `connection` |
| Core model | `state` (registries), `session` (per-connection), `command` (dispatch + handlers), `casemap`, `wire`, `numeric` |
| IRCv3 | `cap`, `deliver` (per-recipient tagging), `batch`/multiline handling |
| Identity | `account` (Argon2), `sasl`, `scram`, `cloak`, `mask` (glob matching) |
| Durability | `history`, `persist` (SQLite write-behind), `chanreg` |
| Federation | `s2s` (protocol), `link` (transport) |
| Extensibility | `plugin` (WASM host) |
| Ops | `metrics` |

## Concurrency model

The shape: **one async task per connection** (tokio, fixed worker-thread
count), **sharded shared state**, and **message-passing for output**.

```
                    ┌───────────────────────────────────────────────┐
                    │                Arc<Server>                    │
                    │  DashMap<folded nick → ClientEntry>           │
                    │  DashMap<folded chan → ChannelEntry>          │
                    │  history · accounts · bans · links · plugins  │
                    └───────┬──────────────────────────┬────────────┘
             lock, mutate,  │                          │
             snapshot, drop │                          │
   ┌────────────────────────┴───┐          ┌───────────┴────────────────┐
   │ conn A                     │          │ conn B                     │
   │ reader task ── dispatch    │          │ reader task ── dispatch    │
   │ writer task ◄─ mailbox ◄───┼──────────┼─► mailbox ─► writer task   │
   └────────────────────────────┘          └────────────────────────────┘
```

- **Reader task**: decodes lines, rate-limits (token bucket), dispatches
  commands. It also `select!`s on a kill signal so `KILL`/K-lines can
  terminate a connection from outside.
- **Writer task**: drains the connection's **bounded** mailbox (the SendQ,
  `sendq_lines` deep) to the socket. A client that won't read gets
  disconnected when its queue fills — backpressure never propagates into
  the sender's task.
- **Registries** are `DashMap`s keyed by **case-folded** names. Channel
  members are keyed by **client id**, not nick — nick changes re-key
  nothing.
- **Delivery** is "snapshot under lock, send after unlock": fan-out
  collects recipients' mailbox handles while holding a channel lock, drops
  the lock, then sends. Sends are non-blocking (bounded queue, drop-on-
  overflow), so no lock is ever held across I/O.

### Locking discipline

Mutexes are `parking_lot` (non-reentrant), and the rules are strict:

- Hold at most **one channel lock** at a time.
- A channel lock may be held while pushing to a member's *mailbox*, but
  **never** while locking another client's data.
- The only permitted nesting is `ChannelData → ClientData` — never the
  reverse.
- Reply helpers lock the calling session's own client entry, so handlers
  must not call them while already holding that lock.

These rules are what make "100k connections, no global lock" safe rather
than lucky.

## Per-recipient delivery

IRCv3 makes every recipient different: one has `server-time`, another has
`account-tag`, a third negotiated nothing. ferrixd renders messages **per
capability set** at delivery time (`deliver`), so each client gets exactly
the tags it negotiated — and the tag bytes for capabilities nobody asked
for are never even serialized.

## Data flow of one message

```
socket bytes ─► codec (length budgets) ─► ferrix-protocol parse (zero-copy)
  ─► dispatch (auth chokepoint) ─► plugin veto? ─► history record (msgid)
  ─► channel fan-out (snapshot members) ─► per-recipient tagging
  ─► bounded mailboxes ─► writer tasks ─► sockets
  └─► S2S: SCMSG to each link routing members (dedup, loop-free)
```

## Density: why 100k fits

- One **task**, not one thread, per connection; the runtime multiplexes
  over a fixed worker pool.
- Sharded maps — contention is per-entry, not global.
- Zero-copy parsing and per-recipient rendering only for negotiated tags.
- Bounded queues everywhere — memory per connection is a budget, not a
  hope. Measured: **~13.8 KB per connection** at 100k concurrent
  connections (~1.38 GB RSS) on an 8-core host, scaling linearly. The
  generator and methodology are in
  [`loadtest/`](https://github.com/j-pfalzgraf/ferrixd/tree/main/loadtest).

## Where federation slots in

S2S (`s2s` + `link`) is a peer of the client layer, not its foundation:
remote users appear in the same registries (keyed by network UID), channel
membership spans servers transparently, and the delivery path treats "a
link that routes members" as one more recipient with deduplication. The
[S2S protocol](/reference/s2s-protocol) page covers the wire side;
[Security Model](/internals/security) covers its trust invariants.
