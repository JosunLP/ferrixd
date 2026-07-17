# WASM Plugins

ferrixd can load **WebAssembly plugins** that hook into server events —
today: vetoing channel messages and joins. Plugins run inside a pure-Rust
WASM interpreter ([`wasmi`](https://docs.rs/wasmi)) under a strict sandbox:

- **No ambient authority.** A plugin can only call the host functions
  ferrixd grants (currently: a logger). No filesystem, no network, no
  clock, nothing.
- **A fuel budget per call.** Every hook invocation gets a bounded number
  of WASM instructions (default 5,000,000). An infinite loop *traps*
  instead of wedging the server.
- **Fail-open on error.** If a plugin traps, runs out of fuel, or is
  malformed, the event is **allowed** — a broken plugin degrades to a
  no-op, never to a denial of service against your own users.

## Enabling the plugin host

```toml
[plugins]
dir = "/etc/ferrixd/plugins"   # every *.wasm here is loaded at startup
fuel = 5000000                 # per-call instruction budget (optional)
```

Files load in sorted filename order (which is also hook call order — handy
for prioritization: `10-antispam.wasm`, `20-links.wasm`). A file that fails
to load is logged and skipped; the server still starts.

## What plugins can do

| Hook | Fires on | Non-zero return means |
| --- | --- | --- |
| `ferrix_on_message` / `_v2` | every channel `PRIVMSG`/`NOTICE` | message blocked |
| `ferrix_on_join` | every channel join attempt | join rejected |
| `ferrix_on_nick` | a registered client's nick change | nick change rejected |
| `ferrix_on_topic` | a `TOPIC` that sets a new topic | topic change rejected |

Hooks run for **local and federated traffic alike**, so policy is uniform
for everything this node delivers. A blocked message is not delivered and
not recorded in history; the sender gets `FAIL PRIVMSG MSG_BLOCKED …`
(standard-replies, with NOTICE fallback). Plugins are consulted in order;
the first block wins.

## Writing a plugin in Rust

A plugin is a plain `wasm32-unknown-unknown` cdylib exporting the ABI
(exact contract: [Plugin ABI reference](/reference/plugin-abi)). A minimal
message filter:

```rust
// Cargo.toml: crate-type = ["cdylib"]; build with:
//   cargo build --release --target wasm32-unknown-unknown

use std::alloc::{alloc as raw_alloc, Layout};

// Host writes event payloads into memory we hand out.
#[no_mangle]
pub extern "C" fn alloc(len: i32) -> i32 {
    let layout = Layout::from_size_align(len as usize, 1).unwrap();
    unsafe { raw_alloc(layout) as i32 }
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
gets `FAIL TOPIC TOPIC_BLOCKED`). Both are optional exports, so existing
plugins keep working unchanged.

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
