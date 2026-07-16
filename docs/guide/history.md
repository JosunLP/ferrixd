# Message History

ferrixd keeps server-side message history for channels **and** direct
messages, replayable through the IRCv3 `draft/chathistory` extension, with
optional SQLite persistence so history — and its message IDs — survive
restarts.

## How it works

Every `PRIVMSG`/`NOTICE` to a channel or user is recorded in an in-memory
ring buffer per *target* (a channel, or a normalized DM pair). Each message
gets:

- a **`msgid`** — a monotonically increasing, server-assigned ID, attached
  as a message tag to clients with `message-tags`, identical live and in
  replay;
- a **`time`** timestamp (`server-time` format, millisecond UTC).

Clients fetch history with `CHATHISTORY`:

```
CHATHISTORY LATEST #forge * 50
CHATHISTORY BEFORE #forge timestamp=2026-07-13T20:00:00.000Z 100
CHATHISTORY AFTER  #forge msgid=00000000000004cf 50
CHATHISTORY AROUND #forge msgid=00000000000004cf 30
CHATHISTORY BETWEEN #forge msgid=00000000000004cf timestamp=2026-07-13T21:00:00.000Z 100
CHATHISTORY TARGETS timestamp=2026-07-13T00:00:00.000Z timestamp=2026-07-13T23:59:59.000Z 20
```

Replies arrive inside a `batch` of type `chathistory` (when the client has
the `batch` cap), so clients can render them as backlog rather than live
traffic. Requests are capped at 100 messages each (`CHATHISTORY=100` in
ISUPPORT, default 50 when no limit is given). The full grammar:
[CHATHISTORY reference](/reference/chathistory).

**Access control:** channel history requires **current membership** —
non-members get `FAIL CHATHISTORY INVALID_TARGET`. DM history is only
visible to the two participants (the target is the symmetric pair).

## Sizing the in-memory store

Two `[limits]` knobs bound memory no matter how busy the network gets:

```toml
[limits]
history_len = 500           # messages kept per target (ring buffer)
history_max_targets = 50000 # distinct targets kept in memory
```

- `history_len` — per-channel/per-DM-pair retention. `0` disables replay
  usefully (only the current run's messages).
- `history_max_targets` — a global cap on distinct targets. Past it, the
  least-recently-active targets are evicted in batches. This means an
  attacker opening DMs to thousands of nicks cannot grow memory unboundedly.

## Persistence

Without persistence, history lives exactly as long as the process. To make
it durable:

```toml
[persistence]
path = "/var/lib/ferrixd/ferrixd.db"
load_limit = 5000           # most-recent rows loaded into RAM at startup
```

What you get:

- **History survives restarts.** At startup, the most recent `load_limit`
  messages are loaded back into the in-memory rings.
- **`msgid` continuity.** The msgid counter reseeds past the highest
  persisted ID, so IDs never repeat or go backwards across restarts —
  clients' "what did I miss" logic keeps working.
- **The same file also stores** [registered channels](/guide/channels#channel-registration)
  and [self-registered accounts](/guide/accounts#self-registration-register).

### Write path (and what a crash can cost)

Writes are **write-behind**: messages are appended to an unbounded queue
drained by a dedicated writer thread, batching up to 256 inserts per
transaction into SQLite (WAL mode). This keeps the hot path free of disk
I/O — a slow disk slows history durability, never message delivery.

The trade-off: an unclean crash can lose the last instants of unflushed
history. On graceful shutdown (Ctrl-C / SIGTERM) the queue is drained with
a 2-second grace period.

### Retention on disk

The on-disk table is pruned at startup to the most recent **100,000 rows**;
within a run it grows with traffic. The in-memory rings are what serve
requests — disk exists to survive restarts, not as an unbounded archive.
If you need long-term archival, scrape it from SQLite directly (schema in
the [reference](/reference/chathistory#sqlite-schema)) — it's a normal
database file, safe to read with WAL mode.

## Interaction with other features

| Feature | Interaction |
| --- | --- |
| `echo-message` | your own messages come back with their `msgid`, so your client can correlate |
| `draft/multiline` | multiline batches are recorded and replayed as their parts |
| Plugins | a message [vetoed by a plugin](/guide/plugins) is never recorded |
| Federation | messages relayed from linked servers are recorded on each server hosting members, so history works network-wide |
| `TARGETS` | lists the targets (channels + DM partners) with activity in a time window — lets clients discover missed conversations |

## Operational notes

- Put the database on the persistent volume in Docker
  (`/var/lib/ferrixd`) — see [Installation](/guide/installation#docker).
- The write queue is unbounded by design (history must not drop under
  burst); if the disk is dramatically slower than traffic, memory holds the
  difference. Watch process RSS via the [metrics endpoint](/guide/observability).
- Deleting the file while stopped resets history and registrations;
  ferrixd recreates the schema on next start.
