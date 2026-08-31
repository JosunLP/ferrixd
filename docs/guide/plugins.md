# WASM Plugins

ferrixd can load **WebAssembly plugins** that hook into server events:
they can veto or **rewrite** messages, veto joins, nick changes, topics,
parts, kicks, mode changes, and invites, observe connects, quits, away and
account changes, run on a timer, keep bounded persistent state, query a
read-only view of the server, and — when the operator grants it — act:
notices, messages, kicks, modes, topics, K-Lines. Plugins run inside a
pure-Rust WASM interpreter ([`wasmi`](https://docs.rs/wasmi)) under a
strict sandbox:

- **No ambient authority.** A plugin can only call the host functions
  ferrixd provides (`ferrix.*`). No filesystem, no network, no process —
  persistence exists only through the host-managed, size-bounded
  key-value store.
- **A fuel budget per call and a memory cap per instance.** Every hook
  invocation gets a bounded number of WASM instructions (default
  5,000,000); linear memory tops out at `max_memory` (default 16 MiB). An
  infinite loop *traps* instead of wedging the server; unbounded
  `memory.grow` fails.
- **Fail-open on error.** If a plugin traps, runs out of fuel, or is
  malformed, the event is **allowed** and the trapped call's queued output
  is discarded — a broken plugin degrades to a no-op, never to a denial
  of service against your own users.
- **Deny-by-default capabilities.** Active abilities (sending notices or
  messages, kicking, setting modes and topics, K-Lining) work only when
  *you* grant them per plugin in the config; a plugin cannot grant itself
  anything. Plugin-produced text is sanitized (no CR/LF injection),
  budgeted, and rate-limited, and server-originated output never re-enters
  the plugin hooks.

## Enabling the plugin host

```toml
[plugins]
dir = "/etc/ferrixd/plugins"     # every *.wasm here is loaded at startup
fuel = 5000000                   # per-call instruction budget (optional)
max_memory = 16777216            # per-instance linear-memory cap in bytes (optional)
state_dir = "/var/lib/ferrixd/plugin-state"  # optional: persist plugin KV stores
expose_private_messages = false  # optional: feed DMs to plugins (privacy: your call)
tick_secs = 0                    # optional: >0 calls ferrix_on_timer that often

[plugins.grants]                 # optional: per-plugin capabilities
"20-modbot" = ["send_notice", "kick", "mode"]

[plugins.config."20-modbot"]     # optional: settings the plugin reads back
report_channel = "#ops"
threshold = "5"
```

The grant names are `send_notice`, `send_message`, `kick`, `mode`, `topic`
and `kline`. Grant the narrowest set that does the job: `kline` bans a
hostmask and disconnects everyone it matches, which is the one grant that
can lock users out of the server. An unrecognised name is logged and
ignored — it never becomes a grant.

Files load in sorted filename order (which is also hook call order — handy
for prioritization: `10-antispam.wasm`, `20-links.wasm`). A file that fails
to load is logged and skipped; the server still starts.

## What plugins can do

| Hook | Fires on | Non-zero return means |
| --- | --- | --- |
| `ferrix_on_message` / `_v2` | every channel `PRIVMSG`/`NOTICE` (local and federated) | message blocked |
| `ferrix_on_private_message` | user-to-user `PRIVMSG`/`NOTICE` (only if `expose_private_messages`) | message blocked |
| `ferrix_on_join` | every channel join attempt (local and federated) | join rejected |
| `ferrix_on_nick` | a registered local client's nick change | nick change rejected |
| `ferrix_on_topic` | a local `TOPIC` that sets a new topic | topic change rejected |
| `ferrix_on_part` | a local `PART` | part rejected (user stays) |
| `ferrix_on_kick` | a local `KICK` (after the op check) | kick cancelled |
| `ferrix_on_mode` | a local channel `MODE` change (after the op check) | whole change cancelled |
| `ferrix_on_invite` | a local `INVITE` (after the checks) | invite cancelled |
| `ferrix_on_connect` | a client completes registration | *(observe-only)* |
| `ferrix_on_quit` | a registered client disconnects | *(observe-only)* |
| `ferrix_on_away` | a client goes away or comes back | *(observe-only)* |
| `ferrix_on_account` | a client logs in to or out of an account | *(observe-only)* |
| `ferrix_on_timer` | every `tick_secs` seconds, if you set it | *(observe-only)* |
| `ferrix_on_load` | once at load, with your granted capabilities | *(observe-only)* |

The `message` and `join` hooks run for **local and federated traffic alike**, so policy is uniform
for everything this node delivers. The moderation hooks (`nick`, `topic`, `part`, `kick`, `mode`,
`invite`) run for local session commands, always *after* the channel's own permission checks —
plugin policy narrows authority, never widens it. `ferrix_on_timer` is the one hook with no
event behind it: it fires on the interval you configure (and only if some plugin exports it),
which is where cooldown expiry, counter rollover and scheduled announcements belong.
A blocked message is not delivered and
not recorded in history; the sender gets `FAIL PRIVMSG MSG_BLOCKED …`
(standard-replies, with NOTICE fallback), with your custom reason if the
plugin set one via `ferrix.set_reason`. Plugins are consulted in order;
the first block wins.

Beyond vetoing, message hooks can **rewrite**: call `ferrix.set_text` with
the replacement and return `0`. The rewritten text is what recipients,
history, and linked servers see, and what later plugins in the chain are
shown. The host sanitizes every plugin-produced string (CR/LF stripped,
length-capped), so a plugin can never smuggle protocol frames.

Plugins also get, without any grant:

- `ferrix.kv_get` / `ferrix.kv_set` — a per-plugin key-value store
  (bounded: 256 keys / 64 KiB; persisted under `state_dir` if configured).
  Karma counters, flood trackers, warn lists.
- `ferrix.now_ms` — wall-clock time for cooldowns and rate limiting.
- `ferrix.random_bytes` — entropy from the OS CSPRNG. A sandbox has none of
  its own, and nonces rolled from the clock are guessable.
- `ferrix.channel_members`, `ferrix.user_info`, `ferrix.user_channels`,
  `ferrix.channel_info`, `ferrix.server_info` — read-only queries against
  the live server state.
- `ferrix.config_get` — the operator's `[plugins.config.<name>]` settings,
  so one `.wasm` file ships to every network and is *configured*, not
  recompiled, per site.
- `ferrix.log` / `ferrix.log_at` — into the server log, at a level you pick.

Granted plugins can also **act**. Every action is queued during the hook
call and executed by the server afterwards, sourced from the server itself
(max 4 per hook call, 120/minute per plugin):

| Host function | Grant | Does |
| --- | --- | --- |
| `ferrix.send_notice` | `send_notice` | server NOTICE to a nick or channel |
| `ferrix.send_message` | `send_message` | server PRIVMSG to a nick or channel |
| `ferrix.kick` | `kick` | remove a user from a channel |
| `ferrix.set_mode` | `mode` | apply channel modes, e.g. `+b` or `+m` |
| `ferrix.set_topic` | `topic` | set or clear a channel topic |
| `ferrix.kline` | `kline` | ban a hostmask and disconnect who it matches |

That is enough for a moderation bot that warns, mutes the channel, bans the
mask, kicks the offender, and reports what it did — with the operator
deciding, grant by grant, how far it may go. Channel-directed notices and
messages are relayed to linked servers, so the whole channel sees them;
K-Lines, like the `KLINE` command, apply to the node that ran them.

## Writing a plugin in Rust

A plugin is a plain `wasm32-unknown-unknown` cdylib exporting the ABI
(exact contract: [Plugin ABI reference](/reference/plugin-abi)). A minimal
message filter:

```rust
// Cargo.toml: crate-type = ["cdylib"]; build with:
//   cargo build --release --target wasm32-unknown-unknown

// The host calls `alloc(len)` once before each hook, writes the event payload
// there, then calls the hook — which reads it and returns. IMPORTANT: the host
// never frees what `alloc` returns, so handing out fresh memory every call
// would grow this plugin's linear memory monotonically toward `max_memory` and
// then fail-open. Reuse one fixed buffer instead: exactly one payload is live
// at a time, so nothing needs to accumulate.
const BUF_CAP: usize = 16 * 1024; // ample for a chat line + JSON context
static mut BUF: [u8; BUF_CAP] = [0; BUF_CAP];

#[no_mangle]
pub extern "C" fn alloc(_len: i32) -> i32 {
    // Payloads are bounded by the server's line limit, so the fixed buffer is
    // always large enough; the host bounds-checks its write against our memory.
    unsafe { core::ptr::addr_of_mut!(BUF) as i32 }
}

// Log through the host (the only capability we're granted).
#[link(wasm_import_module = "ferrix")]
extern "C" {
    fn log(ptr: i32, len: i32);
}

fn host_log(msg: &str) {
    unsafe { log(msg.as_ptr() as i32, msg.len() as i32) }
}

// v2 hook: payload is JSON {"source":"nick","target":"#chan","text":"..."}.
// Return non-zero to block the message.
#[no_mangle]
pub extern "C" fn ferrix_on_message_v2(ptr: i32, len: i32) -> i32 {
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    let Ok(event) = std::str::from_utf8(bytes) else { return 0 };

    if event.to_ascii_lowercase().contains("buy cheap gold") {
        host_log("blocked a spam message");
        return 1;
    }
    0
}
```

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/myplugin.wasm /etc/ferrixd/plugins/
```

Restart ferrixd (plugins are loaded at startup, not `REHASH`-able), and
watch the log for the plugin being registered.

::: details Why does the *plugin* use `unsafe` when ferrixd forbids it?
The `unsafe` here lives in **your** plugin, on the far side of the sandbox
boundary — it's the standard way to touch raw WASM linear memory. The
server that executes it contains zero unsafe code and treats the plugin as
untrusted input: whatever the plugin does, it can only compute (bounded by
fuel) and call `ferrix.log`.
:::

Any language that compiles to WASM works the same way — export `memory`,
`alloc`, and the hooks; that's the whole contract.

## v1 vs v2 message hooks

- `ferrix_on_message(ptr, len)` — **v1**: receives just the raw message
  text. Simplest possible filter.
- `ferrix_on_message_v2(ptr, len)` — **v2**: receives a JSON event with
  `source` (nick), `target` (channel), and `text`. If a plugin exports
  both, **only v2 is called**.

`ferrix_on_join(ptr, len)` receives `{"nick":"…","channel":"…"}` and
non-zero rejects the join (the user gets `FAIL JOIN JOIN_BLOCKED`).

`ferrix_on_nick(ptr, len)` receives `{"old":"…","new":"…"}` for a
registered client's nick change; non-zero keeps the old nick (the user
gets `432 ERR_ERRONEUSNICKNAME`). `ferrix_on_topic(ptr, len)` receives
`{"nick":"…","channel":"…","topic":"…"}` when a `TOPIC` sets a new topic
(after the channel's own permission checks); non-zero rejects it (the user
gets `FAIL TOPIC TOPIC_BLOCKED`). Every hook is an optional export, so
existing plugins keep working unchanged — the full payload catalogue for
the moderation and lifecycle hooks is in the
[Plugin ABI reference](/reference/plugin-abi).

## Choosing a fuel budget

Fuel is a deterministic instruction budget, not wall time. The default
(5,000,000) is generous for string scanning on chat-sized payloads while
still bounding a runaway loop to well under a millisecond of interpreter
work. Raise it if your plugin legitimately does heavy per-message work;
remember it runs on every channel message this node handles.

If a plugin exhausts its fuel, that call traps → the event is allowed →
the trap is logged. Watch your logs after deploying a new plugin.

## Debugging

- `ferrix.log(ptr, len)` writes into ferrixd's structured log at `info`
  level (truncated to 4 KiB) — your `println!` equivalent.
- Load failures and traps appear in the server log with the plugin's
  filename.
- Test locally against `ferrixd run --dev` with the `[plugins]` section in
  a dev config: `ferrixd -c dev.toml`.
