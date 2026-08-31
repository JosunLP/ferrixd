# Plugin ABI

The exact contract between ferrixd and a WASM plugin. Tutorial with a
complete Rust example: [WASM Plugins guide](/guide/plugins).

## Runtime

- Interpreter: [`wasmi`](https://docs.rs/wasmi) — pure Rust, no JIT.
- Target: any `wasm32-unknown-unknown` module (no WASI — there is no
  filesystem to import anyway).
- Loading: every `*.wasm` in `[plugins].dir`, sorted by filename; that
  order is also hook invocation order. A file that fails to instantiate is
  logged and skipped.
- Fuel: each hook call executes under `[plugins].fuel` instructions
  (default **5,000,000**). Exhaustion traps the call.
- Memory: a plugin's linear memory may grow up to `[plugins].max_memory`
  bytes (default **16 MiB**); a `memory.grow` beyond the cap fails.
- Timer: with `[plugins].tick_secs > 0` the host calls `ferrix_on_timer`
  on every loaded plugin that exports it, on the same fuel budget as any
  other hook.
- Error policy: **fail-open** — a trap, missing export at call time, or
  out-of-fuel condition allows the event and logs the failure. A trapped
  call's queued output (replacement text, reason, actions) is discarded:
  the hook behaves as if it never ran. A plugin can degrade to a no-op; it
  cannot take the server down or veto by crashing.

## Required exports

| Export | Signature | Purpose |
| --- | --- | --- |
| `memory` | linear memory | the host reads/writes event payloads here |
| `alloc` | `(i32) -> i32` | return a pointer to `len` writable bytes; the host calls this before each event to place the payload |

`alloc` may be a trivial bump allocator; **the host never frees what it
returns**. Exactly one payload is live per hook call (the host allocates,
writes, calls the hook, and the hook consumes it before returning), so the
safe idiom is to reuse a single fixed buffer. A plugin that instead hands
out fresh memory on every call — and never reclaims it — grows its own
linear memory monotonically until it hits `max_memory`, after which every
`alloc` fails and the plugin fail-opens. That is bounded (it can never
exhaust host RAM beyond the per-instance cap), but it silently disables the
plugin, so manage the buffer deliberately.

## Hook exports (all optional)

Every hook has the signature `(ptr: i32, len: i32) -> i32` and receives a
UTF-8 payload written at `ptr` (`len` bytes). Return `0` to allow;
non-zero blocks the event (except the observe-only hooks, whose return
value is ignored).

### Veto hooks

| Export | Payload (JSON unless noted) | Blocked event yields |
| --- | --- | --- |
| `ferrix_on_message` | raw message text (v1) | `FAIL PRIVMSG MSG_BLOCKED` |
| `ferrix_on_message_v2` | `{"source","target","text"}` | `FAIL PRIVMSG MSG_BLOCKED` |
| `ferrix_on_private_message` | `{"source","target","text"}` | `FAIL PRIVMSG MSG_BLOCKED` |
| `ferrix_on_join` | `{"nick","channel"}` | `FAIL JOIN JOIN_BLOCKED` |
| `ferrix_on_nick` | `{"old","new"}` | `432 ERR_ERRONEUSNICKNAME` |
| `ferrix_on_topic` | `{"nick","channel","topic"}` | `FAIL TOPIC TOPIC_BLOCKED` |
| `ferrix_on_part` | `{"nick","channel","reason"}` | `FAIL PART PART_BLOCKED` |
| `ferrix_on_kick` | `{"nick","channel","target","reason"}` | `FAIL KICK KICK_BLOCKED` |
| `ferrix_on_mode` | `{"nick","channel","modes"}` (raw mode string + args) | `FAIL MODE MODE_BLOCKED` |
| `ferrix_on_invite` | `{"nick","channel","target"}` | `FAIL INVITE INVITE_BLOCKED` |

### Observe-only hooks (return value ignored)

| Export | Payload | Fires when |
| --- | --- | --- |
| `ferrix_on_connect` | `{"nick","user","host","account"}` (`account` may be `null`) | a client completed registration |
| `ferrix_on_quit` | `{"nick","reason"}` | a registered client disconnects (QUIT, drop, KILL) |
| `ferrix_on_away` | `{"nick","message"}` (`message` is `null` when the user came back) | a registered client set or cleared its away state |
| `ferrix_on_account` | `{"nick","account"}` (`account` may be `null`) | a client logged in to or out of an account |
| `ferrix_on_timer` | `{"tick":<n>,"now_ms":<n>}` | every `[plugins].tick_secs` seconds (see below) |
| `ferrix_on_load` | `{"api":3,"plugin":"<name>","granted":["…"]}` | once at load time, reporting the granted capabilities |

Rules:

- If a plugin exports both `ferrix_on_message` and `ferrix_on_message_v2`,
  **only v2 is called**.
- Channel message hooks fire for every channel `PRIVMSG`/`NOTICE` this
  node delivers — locally originated **and** relayed over S2S.
- `ferrix_on_private_message` fires **only** when the operator set
  `[plugins].expose_private_messages = true`; by default plugins never see
  DMs.
- `ferrix_on_nick` fires for a **registered** client's nick change (not
  for the nick chosen during the initial handshake); `ferrix_on_topic`,
  `ferrix_on_kick`, `ferrix_on_mode` (channel modes only, after the op
  check), and `ferrix_on_invite` fire after the channel's own permission
  checks — plugin policy narrows authority, never widens it.
- Plugins are consulted in load order; the **first block short-circuits**
  (later plugins don't see the event).
- A blocked message is not delivered, not echoed, and not recorded in
  history.
- `ferrix_on_timer` only runs when the operator set `[plugins].tick_secs`
  to a non-zero value **and** at least one plugin exports the hook; there
  is no event context, so `set_text` does nothing and only actions apply.
  Ticks are skipped rather than queued if the host falls behind.

## Host imports

Module name `ferrix`. This is the complete ambient authority of a plugin;
everything else is compute under the fuel budget.

### Always available

| Import | Signature | Behavior |
| --- | --- | --- |
| `log` | `(ptr, len)` | logs a UTF-8 string at `info` level, truncated to 4096 bytes |
| `set_text` | `(ptr, len)` | replace the current message's text (message hooks only, then return `0`). Sanitized: CR/LF/NUL stripped, capped at 400 bytes. Later plugins see the rewritten text; the rewrite reaches echo, history, and the S2S relay |
| `set_reason` | `(ptr, len)` | set a custom reason for the `FAIL` reply when this call returns non-zero. Control characters stripped, capped at 200 bytes |
| `kv_set` | `(kptr, klen, vptr, vlen) -> i32` | store a value under a UTF-8 key; empty value deletes. `0` = ok, `1` = a bound was exceeded |
| `kv_get` | `(kptr, klen, outptr, outcap) -> i32` | returns the value length, written to `outptr` when `outcap` suffices; `-1` when absent |
| `now_ms` | `() -> i64` | wall-clock milliseconds since the Unix epoch (for cooldowns; not monotonic across clock adjustments) |
| `channel_members` | `(cptr, clen, outptr, outcap) -> i32` | JSON array of the channel's member nicks (local + remote, first 512). Returns the needed length, written when it fits; `-1` for an unknown channel |
| `user_info` | `(nptr, nlen, outptr, outcap) -> i32` | JSON `{"nick","user","host","account","away","oper","bot"}` for a locally connected user. Same length contract; `-1` for an unknown nick |
| `user_channels` | `(nptr, nlen, outptr, outcap) -> i32` | JSON array of the channels a locally connected user is in (first 512). Same length contract; `-1` for an unknown nick |
| `channel_info` | `(cptr, clen, outptr, outcap) -> i32` | JSON `{"name","topic","topic_set_by","topic_set_at","modes","members","remote_members","bans","created_at","registered"}`. The `+k` key is never reported. `-1` for an unknown channel |
| `server_info` | `(outptr, outcap) -> i32` | JSON `{"name","sid","network","version","users","remote_users","channels","opers","servers","uptime_secs"}` |
| `config_get` | `(kptr, klen, outptr, outcap) -> i32` | read one operator-supplied setting from `[plugins.config.<plugin>]`. Same length contract; `-1` when the key is unset (so "" and "not configured" stay distinguishable) |
| `random_bytes` | `(outptr, len) -> i32` | fill up to **256** bytes from the OS CSPRNG; returns the count written, `-1` on failure. A sandbox has no entropy of its own — do not roll nonces from `now_ms` |
| `log_at` | `(level, ptr, len)` | like `log`, choosing the severity: `0` debug, `1` info, `2` warn, `3` error (anything else: info) |

### Capability-gated (see `[plugins].grants`)

Every action below returns `0` when it was queued and `1` when it was
refused — no grant, an invalid target, or the budget exhausted. All of them
execute host-side *after* the hook call returns, sourced from the server
itself.

| Import | Capability | Signature | Behavior |
| --- | --- | --- | --- |
| `send_notice` | `send_notice` | `(tptr, tlen, ptr, len) -> i32` | queue a server NOTICE to a nick or channel |
| `send_message` | `send_message` | `(tptr, tlen, ptr, len) -> i32` | queue a server PRIVMSG to a nick or channel |
| `kick` | `kick` | `(cptr, clen, nptr, nlen, rptr, rlen) -> i32` | remove a nick from a channel; an empty reason becomes `Kicked by <plugin>` |
| `set_mode` | `mode` | `(cptr, clen, mptr, mlen) -> i32` | apply a channel mode change, e.g. `"+b nick!*@*"` or `"+m"` |
| `set_topic` | `topic` | `(cptr, clen, tptr, tlen) -> i32` | set a channel topic, truncated to the advertised `TOPICLEN` in characters; empty text clears it |
| `kline` | `kline` | `(mptr, mlen, rptr, rlen) -> i32` | K-Line a `nick!user@host` glob and disconnect whoever it matches |

Action budget: at most **4** actions per hook call and **120** per rolling
minute per plugin. Server-originated output does **not** re-enter the
plugin hooks, so a plugin cannot feed itself an event loop.

Bounds and shapes:

- Targets are at most 64 bytes and may not contain whitespace, `,`, `*`,
  `?`, `!` or control characters. `kick`, `set_mode` and `set_topic`
  require a channel (`#…`).
- A mode string is one `[+-]` flag word (≤128 bytes) plus at most **8**
  arguments of ≤64 bytes each (`"+bo mask nick"`). `o`/`v` arguments are nicks; the host
  translates them to network UIDs. A nick that resolves to nobody cancels
  the **whole** change rather than applying half of it.
- A K-Line mask is at most 128 bytes, carries no whitespace and no leading
  `:` (extended `~a:account` masks are fine). It is recorded as set by
  `plugin:<name>`, applies to this node like the `KLINE` command, and — as
  with `KLINE` — is not propagated across the network.
- Channel-directed notices and messages are relayed to the peers holding
  members, so plugin output reaches the whole channel, not just this node.
  Kicks, modes and topics likewise reach the whole network, attributed to the
  server whose plugin produced them and recorded in every node's history.
- Actions the plugin queued during a call that later traps are discarded
  along with the rest of its output.

### Key-value store bounds

| Bound | Value |
| --- | --- |
| keys per plugin | 256 |
| key length | 128 bytes (UTF-8) |
| value length | 8192 bytes |
| total (keys + values) | 64 KiB |

The store is per-plugin and in-memory; with `[plugins].state_dir` set, the
host persists it to `<state_dir>/<plugin>.kv` (flushed at most every 2
seconds, off the wasm execution path). Plugins never see the file.

### Operator settings

`ferrix.config_get` reads `[plugins.config.<plugin>]` — a plain string
table the operator fills in, so one `.wasm` file can be deployed with
site-specific parameters instead of recompiled per network:

```toml
[plugins.config.greeter]
channel = "#lobby"
message = "Welcome!"

[plugins.grants]
greeter = ["send_notice"]
```

The table is read once at load time. It is configuration, not state: a
plugin cannot write to it (that is what the key-value store is for).

## Call sequence

For each event, per plugin, the host:

1. serializes the event payload (UTF-8/JSON as above);
2. calls the plugin's `alloc(len)` → `ptr`;
3. writes the payload into `memory` at `ptr`;
4. sets the fuel budget and calls the hook with `(ptr, len)`;
5. interprets the return value (`0`/non-zero), treating any trap as `0`
   (allow) and discarding the trapped call's queued output;
6. applies a surviving replacement (`set_text` + return `0`) and executes
   queued actions.

Payloads are never null-terminated; always use the `len` you're given.

## Versioning expectations

- New hooks arrive as new optional exports — old plugins keep working.
- New host functions arrive as new imports under the `ferrix` module; a
  plugin that doesn't import them is unaffected.
- Message-event schema changes arrive as a new suffix (`_v3`, …) rather
  than mutating `_v2`'s JSON.
- Unknown JSON fields may appear in payloads at any time; parse leniently.
- New capabilities arrive as new names in `[plugins.grants]`; an
  unrecognised name is logged and ignored, never granted.
- The `api` field in the `ferrix_on_load` payload identifies the ABI
  level (currently `3`). Every ABI 1 and 2 plugin loads and runs unchanged:
  the v3 hooks are optional exports and the v3 host functions optional
  imports.
