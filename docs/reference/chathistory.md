# CHATHISTORY Reference

The `draft/chathistory` extension, as ferrixd implements it. Conceptual
overview and sizing: [Message History guide](/guide/history).

## Request grammar

```
CHATHISTORY <subcommand> <target> <selector…> <limit>
```

- **`target`** — a channel (membership required) or a nick (DM history —
  the target pair is symmetric, both participants see the same timeline).
- **`selector`** — `*`, `timestamp=<ISO8601 with ms, UTC>`, or
  `msgid=<id>` (`MSGREFTYPES=timestamp,msgid`).
- **`limit`** — messages to return; clamped to **1…100**
  (`CHATHISTORY=100` in ISUPPORT); defaults to **50** when absent or
  unparseable.

## Subcommands

| Subcommand | Form | Returns |
| --- | --- | --- |
| `LATEST` | `LATEST <target> * <limit>` | the most recent messages |
| `LATEST` | `LATEST <target> <sel> <limit>` | messages newer than the selector |
| `BEFORE` | `BEFORE <target> <sel> <limit>` | messages older than the selector |
| `AFTER` | `AFTER <target> <sel> <limit>` | messages newer than the selector |
| `AROUND` | `AROUND <target> <sel> <limit>` | messages surrounding the selector |
| `BETWEEN` | `BETWEEN <target> <sel1> <sel2> <limit>` | messages between two selectors (either order) |
| `TARGETS` | `TARGETS <ts1> <ts2> <limit>` | which targets (channels/DM partners) have activity in the window |

Examples:

```
CHATHISTORY LATEST #forge * 50
CHATHISTORY BEFORE #forge timestamp=2026-07-13T20:00:00.000Z 100
CHATHISTORY AFTER  alice msgid=00000000000004cf 50
CHATHISTORY BETWEEN #forge msgid=00000000000004cf timestamp=2026-07-13T21:00:00.000Z 100
CHATHISTORY TARGETS timestamp=2026-07-13T00:00:00.000Z timestamp=2026-07-13T23:59:59.000Z 20
```

## Response format

With the `batch` capability, results arrive wrapped:

```
« :irc.example.org BATCH +ref chathistory #forge
« @batch=ref;msgid=…;time=… :bob!bob@host PRIVMSG #forge :…
« @batch=ref;msgid=…;time=… :eve!eve@host NOTICE #forge :…
« :irc.example.org BATCH -ref
```

Replayed messages carry the **same `msgid`** they had live, and their
original `time=`. `account=` tags are replayed for clients with
`account-tag`. Without `batch`, messages are sent unwrapped.

## Errors (`standard-replies`)

| Reply | When |
| --- | --- |
| `FAIL CHATHISTORY NEED_MORE_PARAMS` | missing subcommand/target/selector |
| `FAIL CHATHISTORY INVALID_TARGET` | channel you're not a member of, or unknown target |
| `FAIL CHATHISTORY INVALID_PARAMS` | malformed selector, unknown subcommand |

## Storage semantics

- **msgid** — a server-assigned, strictly monotonic 16-hex-digit ID.
  Ordering by msgid equals ordering by arrival. With persistence enabled,
  the counter continues across restarts (no reuse, no regression).
- **Ring buffers** — per-target retention is `history_len` (default 500);
  the number of distinct targets is bounded by `history_max_targets`
  (default 50,000) with least-recently-active eviction.
- **What's recorded** — `PRIVMSG` and `NOTICE` to channels and users
  (including multiline batch parts). Plugin-vetoed messages are not
  recorded. `TAGMSG` is not recorded.

## SQLite schema

With `[persistence]` enabled, history rows are written behind (batches of
up to 256 per transaction, WAL journal) to:

```sql
CREATE TABLE history (
   id      INTEGER PRIMARY KEY AUTOINCREMENT,
   folded  TEXT    NOT NULL,   -- case-folded target (channel or DM pair key)
   msgid   TEXT    NOT NULL,
   time_ms INTEGER NOT NULL,   -- unix milliseconds, UTC
   source  TEXT    NOT NULL,   -- nick!user@host at send time
   account TEXT,               -- sender's account, if logged in
   kind    INTEGER NOT NULL,   -- 0 = PRIVMSG, 1 = NOTICE
   target  TEXT    NOT NULL,   -- display form of the target
   body    TEXT    NOT NULL
);
CREATE INDEX idx_history_folded ON history(folded, id);
```

On startup the most recent `load_limit` rows (default 5000) are loaded into
RAM and the msgid counter reseeds past the highest loaded ID. The table is
pruned at startup to the most recent 100,000 rows. The file is a normal
SQLite database — safe to query read-only for archival or analytics.
