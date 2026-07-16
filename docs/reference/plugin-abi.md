# Plugin ABI

The exact contract between ferrixd and a WASM plugin. Tutorial with a
complete Rust example: [WASM Plugins guide](/guide/plugins).

## Runtime

- Interpreter: [`wasmi`](https://docs.rs/wasmi) — pure Rust, no JIT.
- Target: any `wasm32-unknown-unknown` module (no WASI — there is no
  filesystem or clock to import anyway).
- Loading: every `*.wasm` in `[plugins].dir`, sorted by filename; that
  order is also hook invocation order. A file that fails to instantiate is
  logged and skipped.
- Fuel: each hook call executes under `[plugins].fuel` instructions
  (default **5,000,000**). Exhaustion traps the call.
- Error policy: **fail-open** — a trap, missing export at call time, or
  out-of-fuel condition allows the event and logs the failure. A plugin
  can degrade to a no-op; it cannot take the server down or veto by
  crashing.

## Required exports

| Export | Signature | Purpose |
| --- | --- | --- |
| `memory` | linear memory | the host reads/writes event payloads here |
| `alloc` | `(i32) -> i32` | return a pointer to `len` writable bytes; the host calls this before each event to place the payload |

`alloc` may be a trivial bump allocator; the host never frees.

## Hook exports (all optional)

| Export | Payload (UTF-8, written at `ptr`, `len` bytes) | Return |
| --- | --- | --- |
| `ferrix_on_message(ptr: i32, len: i32) -> i32` | raw message text (v1) | `0` = allow, non-zero = block |
| `ferrix_on_message_v2(ptr: i32, len: i32) -> i32` | JSON `{"source":"<nick>","target":"<#channel>","text":"<text>"}` | `0` = allow, non-zero = block |
| `ferrix_on_join(ptr: i32, len: i32) -> i32` | JSON `{"nick":"<nick>","channel":"<#channel>"}` | `0` = allow, non-zero = reject join |

Rules:

- If a plugin exports both `ferrix_on_message` and `ferrix_on_message_v2`,
  **only v2 is called**.
- Message hooks fire for every channel `PRIVMSG`/`NOTICE` this node
  delivers — locally originated **and** relayed over S2S.
- Plugins are consulted in load order; the **first block short-circuits**
  (later plugins don't see the event).
- A blocked message is not delivered, not echoed, and not recorded in
  history; the sender receives `FAIL PRIVMSG MSG_BLOCKED` (or the NOTICE
  fallback). A blocked join yields `FAIL JOIN JOIN_BLOCKED`.

## Host imports

Module name `ferrix`:

| Import | Signature | Behavior |
| --- | --- | --- |
| `ferrix.log` | `(ptr: i32, len: i32)` | logs a UTF-8 string from plugin memory at `info` level, truncated to 4096 bytes |

That is the complete ambient authority of a plugin: compute (bounded by
fuel) and one log function.

## Call sequence

For each event, per plugin, the host:

1. serializes the event payload (UTF-8/JSON as above);
2. calls the plugin's `alloc(len)` → `ptr`;
3. writes the payload into `memory` at `ptr`;
4. sets the fuel budget and calls the hook with `(ptr, len)`;
5. interprets the return value (`0`/non-zero), treating any trap as `0`
   (allow).

Payloads are never null-terminated; always use the `len` you're given.

## Versioning expectations

- New hooks arrive as new optional exports — old plugins keep working.
- Message-event schema changes arrive as a new suffix (`_v3`, …) rather
  than mutating `_v2`'s JSON.
- Unknown JSON fields may appear in payloads at any time; parse leniently.
