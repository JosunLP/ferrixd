//! WebAssembly plugin host.
//!
//! Plugins are sandboxed `.wasm` modules loaded at startup. They can observe
//! events (currently channel messages) and return a verdict (allow / block),
//! enabling moderation, filtering, and custom policy without native code in the
//! daemon.
//!
//! Sandbox properties:
//!  * **Isolation** — WebAssembly has no ambient authority. A plugin can only
//!    call the host functions we explicitly provide (see [`register_host_api`]);
//!    it cannot touch the filesystem, network, or process.
//!  * **DoS resistance** — every hook call runs with a bounded *fuel* budget
//!    (an instruction counter). A plugin that loops forever runs out of fuel and
//!    traps; the host treats a trap as "allow" (fail-open) so a broken plugin
//!    cannot wedge the server.
//!  * **Memory-safe by construction** — we use [`wasmi`], a pure-Rust
//!    interpreter, so the host stays free of a JIT and of `cmake`/C toolchains,
//!    consistent with the rest of ferrixd.
//!
//! ## Plugin ABI
//!
//! A plugin must export its linear memory as `memory` and a bump allocator
//! `alloc(i32) -> i32`. The host allocates via `alloc`, writes the UTF-8
//! payload into plugin memory, and calls the hook; a non-zero return blocks
//! the event. The host provides one import: `ferrix.log(ptr: i32, len: i32)`
//! to log a UTF-8 string from plugin memory.
//!
//! Hooks (all optional):
//!  * `ferrix_on_message(ptr, len) -> i32` — **v1**: receives the raw message
//!    text of a channel PRIVMSG/NOTICE.
//!  * `ferrix_on_message_v2(ptr, len) -> i32` — **v2**: receives a JSON event
//!    `{"source":"<nick>","target":"<#channel>","text":"<text>"}`. When both
//!    are exported, only v2 is called.
//!  * `ferrix_on_join(ptr, len) -> i32` — receives
//!    `{"nick":"<nick>","channel":"<#channel>"}`; non-zero blocks the join.
//!
//! Both local and S2S-relayed channel messages pass through the message hooks,
//! so policy is uniform across the network's entry points on this node.

use std::path::Path;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tracing::{info, warn};
use wasmi::{Caller, Config, Engine, Extern, Linker, Memory, Module, Store, TypedFunc};

/// Default per-call fuel budget (instructions) if none is configured.
pub const DEFAULT_FUEL: u64 = 5_000_000;

/// The decision a plugin returns for an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Let the event proceed.
    Allow,
    /// Block the event.
    Block,
}

/// State threaded through a plugin's `Store`, available to host functions.
#[derive(Debug)]
struct HostState {
    name: String,
}

/// One loaded plugin instance (single-threaded; guarded by a `Mutex`).
struct PluginInstance {
    name: String,
    store: Store<HostState>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    on_message: Option<TypedFunc<(i32, i32), i32>>,
    on_message_v2: Option<TypedFunc<(i32, i32), i32>>,
    on_join: Option<TypedFunc<(i32, i32), i32>>,
}

impl std::fmt::Debug for PluginInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginInstance")
            .field("name", &self.name)
            .field("on_message", &self.on_message.is_some())
            .field("on_message_v2", &self.on_message_v2.is_some())
            .field("on_join", &self.on_join.is_some())
            .finish()
    }
}

/// Append `s` to `out` as a JSON string literal (with escaping).
fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A registry of loaded WebAssembly plugins.
#[derive(Debug)]
pub struct PluginHost {
    engine: Engine,
    fuel: u64,
    plugins: Vec<Mutex<PluginInstance>>,
}

impl PluginHost {
    /// Create an empty host with the given per-call fuel budget.
    #[must_use]
    pub fn new(fuel: u64) -> Self {
        let mut config = Config::default();
        config.consume_fuel(true);
        PluginHost {
            engine: Engine::new(&config),
            fuel,
            plugins: Vec::new(),
        }
    }

    /// Number of loaded plugins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether no plugins are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Load every `*.wasm` file in `dir` (sorted for determinism).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read. Individual plugins that
    /// fail to load are logged and skipped.
    pub fn load_dir(&mut self, dir: &Path) -> Result<usize> {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("reading plugin directory {}", dir.display()))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "wasm"))
            .collect();
        files.sort();

        let mut loaded = 0;
        for path in files {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("plugin")
                .to_owned();
            match std::fs::read(&path) {
                Ok(bytes) => match self.load_bytes(&name, &bytes) {
                    Ok(()) => {
                        loaded += 1;
                        info!(plugin = %name, "loaded WASM plugin");
                    }
                    Err(err) => warn!(plugin = %name, %err, "failed to load plugin"),
                },
                Err(err) => warn!(path = %path.display(), %err, "failed to read plugin"),
            }
        }
        Ok(loaded)
    }

    /// Compile and instantiate a single plugin from WASM bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the module is invalid or lacks the required exports.
    pub fn load_bytes(&mut self, name: &str, wasm: &[u8]) -> Result<()> {
        let module = Module::new(&self.engine, wasm).context("compiling module")?;
        let mut store = Store::new(
            &self.engine,
            HostState {
                name: name.to_owned(),
            },
        );
        store.set_fuel(self.fuel).context("setting initial fuel")?;

        let mut linker = Linker::new(&self.engine);
        register_host_api(&mut linker).context("registering host API")?;

        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .context("instantiating module")?;

        let memory = instance
            .get_memory(&store, "memory")
            .context("plugin must export its memory as `memory`")?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&store, "alloc")
            .context("plugin must export `alloc(i32) -> i32`")?;
        let on_message = instance
            .get_typed_func::<(i32, i32), i32>(&store, "ferrix_on_message")
            .ok();
        let on_message_v2 = instance
            .get_typed_func::<(i32, i32), i32>(&store, "ferrix_on_message_v2")
            .ok();
        let on_join = instance
            .get_typed_func::<(i32, i32), i32>(&store, "ferrix_on_join")
            .ok();

        self.plugins.push(Mutex::new(PluginInstance {
            name: name.to_owned(),
            store,
            memory,
            alloc,
            on_message,
            on_message_v2,
            on_join,
        }));
        Ok(())
    }

    /// Run the `on_message` hook of every plugin on the message `text` (v1,
    /// text-only). If any blocks, the result is [`Verdict::Block`]. A plugin
    /// that traps or exhausts fuel is treated as [`Verdict::Allow`] (fail-open)
    /// so it cannot wedge delivery.
    #[must_use]
    pub fn on_message(&self, text: &str) -> Verdict {
        if self.plugins.is_empty() {
            return Verdict::Allow;
        }
        for plugin in &self.plugins {
            let mut plugin = plugin.lock();
            let func = plugin.on_message;
            if plugin.call(func, text, self.fuel) == Verdict::Block {
                return Verdict::Block;
            }
        }
        Verdict::Allow
    }

    /// Run the message hooks of every plugin on a channel message with full
    /// context. A plugin exporting the v2 hook gets the JSON event; otherwise
    /// its v1 hook (raw text) is called.
    #[must_use]
    pub fn on_channel_message(&self, source: &str, target: &str, text: &str) -> Verdict {
        if self.plugins.is_empty() {
            return Verdict::Allow;
        }
        let mut event = String::with_capacity(text.len() + source.len() + target.len() + 40);
        event.push_str("{\"source\":");
        push_json_string(&mut event, source);
        event.push_str(",\"target\":");
        push_json_string(&mut event, target);
        event.push_str(",\"text\":");
        push_json_string(&mut event, text);
        event.push('}');
        for plugin in &self.plugins {
            let mut plugin = plugin.lock();
            let verdict = match plugin.on_message_v2 {
                Some(func) => plugin.call(Some(func), &event, self.fuel),
                None => {
                    let func = plugin.on_message;
                    plugin.call(func, text, self.fuel)
                }
            };
            if verdict == Verdict::Block {
                return Verdict::Block;
            }
        }
        Verdict::Allow
    }

    /// Run the `on_join` hook of every plugin. A non-zero return blocks the
    /// join (fail-open on traps, like the message hooks).
    #[must_use]
    pub fn on_join(&self, nick: &str, channel: &str) -> Verdict {
        if self.plugins.is_empty() {
            return Verdict::Allow;
        }
        let mut event = String::with_capacity(nick.len() + channel.len() + 32);
        event.push_str("{\"nick\":");
        push_json_string(&mut event, nick);
        event.push_str(",\"channel\":");
        push_json_string(&mut event, channel);
        event.push('}');
        for plugin in &self.plugins {
            let mut plugin = plugin.lock();
            let func = plugin.on_join;
            if plugin.call(func, &event, self.fuel) == Verdict::Block {
                return Verdict::Block;
            }
        }
        Verdict::Allow
    }
}

impl PluginInstance {
    /// Call one hook with a UTF-8 payload, fail-open on any fault.
    fn call(&mut self, func: Option<TypedFunc<(i32, i32), i32>>, text: &str, fuel: u64) -> Verdict {
        let Some(func) = func else {
            return Verdict::Allow;
        };
        // Refuel for this call; a bad plugin cannot borrow against the next one.
        if self.store.set_fuel(fuel).is_err() {
            return Verdict::Allow;
        }
        let bytes = text.as_bytes();
        let Ok(len) = i32::try_from(bytes.len()) else {
            return Verdict::Allow;
        };
        let ptr = match self.alloc.call(&mut self.store, len) {
            Ok(ptr) => ptr,
            Err(err) => {
                warn!(plugin = %self.name, %err, "plugin alloc failed");
                return Verdict::Allow;
            }
        };
        if let Err(err) = self.memory.write(&mut self.store, ptr as usize, bytes) {
            warn!(plugin = %self.name, %err, "writing event to plugin memory failed");
            return Verdict::Allow;
        }
        match func.call(&mut self.store, (ptr, len)) {
            Ok(0) => Verdict::Allow,
            Ok(_) => Verdict::Block,
            Err(err) => {
                warn!(plugin = %self.name, %err, "plugin trapped; allowing message");
                Verdict::Allow
            }
        }
    }
}

/// Register the host functions available to every plugin.
fn register_host_api(linker: &mut Linker<HostState>) -> Result<()> {
    linker
        .func_wrap(
            "ferrix",
            "log",
            |caller: Caller<'_, HostState>, ptr: i32, len: i32| {
                let Some(Extern::Memory(memory)) = caller.get_export("memory") else {
                    return;
                };
                let len = len.max(0) as usize;
                let mut buf = vec![0u8; len.min(4096)];
                if memory.read(&caller, ptr.max(0) as usize, &mut buf).is_ok() {
                    let text = String::from_utf8_lossy(&buf);
                    info!(plugin = %caller.data().name, "plugin log: {text}");
                }
            },
        )
        .context("host function ferrix.log")?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // A plugin that blocks any message whose text starts with '!'.
    const BANG_BLOCKER: &str = r#"
        (module
          (import "ferrix" "log" (func $log (param i32 i32)))
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param $size i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $size)))
            (local.get $p))
          (func (export "ferrix_on_message") (param $ptr i32) (param $len i32) (result i32)
            ;; Locals must precede all instructions in WAT.
            (local $i i32)
            (call $log (local.get $ptr) (local.get $len))
            ;; The event JSON embeds the message text; block if any byte is '!'
            ;; (0x21) by scanning the payload.
            (local.set $i (local.get $ptr))
            (block $done
              (loop $scan
                (br_if $done (i32.ge_u (local.get $i)
                                       (i32.add (local.get $ptr) (local.get $len))))
                (if (i32.eq (i32.load8_u (local.get $i)) (i32.const 33))
                  (then (return (i32.const 1))))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $scan)))
            (i32.const 0)))
    "#;

    fn host_with_blocker() -> PluginHost {
        let wasm = wat::parse_str(BANG_BLOCKER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("bang", &wasm).unwrap();
        host
    }

    #[test]
    fn plugin_blocks_and_allows() {
        let host = host_with_blocker();
        assert_eq!(host.len(), 1);
        assert_eq!(host.on_message("hello everyone"), Verdict::Allow);
        assert_eq!(host.on_message("ban them all!"), Verdict::Block);
    }

    #[test]
    fn empty_host_allows_everything() {
        let host = PluginHost::new(DEFAULT_FUEL);
        assert_eq!(host.on_message("!whatever"), Verdict::Allow);
    }

    // A v2 plugin sees the JSON event (source/target/text); on_join gets the
    // join event. This one blocks anything mentioning "#secret".
    const V2_BLOCKER: &str = r##"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 4096))
          (func (export "alloc") (param $size i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $size)))
            (local.get $p))
          ;; Return 1 if the payload contains the byte sequence "#secret".
          (func $scan (param $ptr i32) (param $len i32) (result i32)
            (local $i i32)
            (local $end i32)
            (local.set $i (local.get $ptr))
            (local.set $end (i32.add (local.get $ptr) (local.get $len)))
            (block $done
              (loop $l
                (br_if $done (i32.gt_u (i32.add (local.get $i) (i32.const 7))
                                       (local.get $end)))
                (if (i32.and
                      (i32.eq (i32.load8_u (local.get $i)) (i32.const 35))        ;; '#'
                      (i32.and
                        (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 1))) (i32.const 115)) ;; 's'
                        (i32.and
                          (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 2))) (i32.const 101)) ;; 'e'
                          (i32.and
                            (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 3))) (i32.const 99)) ;; 'c'
                            (i32.and
                              (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 4))) (i32.const 114)) ;; 'r'
                              (i32.and
                                (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 5))) (i32.const 101)) ;; 'e'
                                (i32.eq (i32.load8_u (i32.add (local.get $i) (i32.const 6))) (i32.const 116)) ;; 't'
                              )))))) ;; 'secret' spelled out byte-wise
                  (then (return (i32.const 1))))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $l)))
            (i32.const 0))
          (func (export "ferrix_on_message_v2") (param $ptr i32) (param $len i32) (result i32)
            (call $scan (local.get $ptr) (local.get $len)))
          (func (export "ferrix_on_join") (param $ptr i32) (param $len i32) (result i32)
            (call $scan (local.get $ptr) (local.get $len))))
    "##;

    #[test]
    fn v2_hook_receives_context_and_join_hook_vetoes() {
        let wasm = wat::parse_str(V2_BLOCKER).unwrap();
        let mut host = PluginHost::new(DEFAULT_FUEL);
        host.load_bytes("v2", &wasm).unwrap();

        // The channel name is only visible through the v2 JSON event.
        assert_eq!(
            host.on_channel_message("alice", "#secret", "harmless text"),
            Verdict::Block
        );
        assert_eq!(
            host.on_channel_message("alice", "#general", "harmless text"),
            Verdict::Allow
        );
        // Joins are vetoed through the dedicated hook.
        assert_eq!(host.on_join("alice", "#secret"), Verdict::Block);
        assert_eq!(host.on_join("alice", "#general"), Verdict::Allow);
    }

    #[test]
    fn v1_plugin_still_sees_raw_text_via_context_call() {
        // A v1-only plugin gets the raw text when the host has context.
        let host = host_with_blocker();
        assert_eq!(
            host.on_channel_message("alice", "#g", "no bang here"),
            Verdict::Allow
        );
        assert_eq!(
            host.on_channel_message("alice", "#g", "bang!"),
            Verdict::Block
        );
        // And a v1-only plugin ignores joins entirely.
        assert_eq!(host.on_join("alice", "#g"), Verdict::Allow);
    }

    #[test]
    fn json_escaping_is_wellformed() {
        let mut out = String::new();
        push_json_string(&mut out, "a\"b\\c\nd\te\u{1}");
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\\te\\u0001\"");
    }

    // A plugin that loops forever must run out of fuel and fail open (allow).
    #[test]
    fn infinite_loop_is_fuel_limited() {
        let spinner = r#"
            (module
              (memory (export "memory") 1)
              (global $next (mut i32) (i32.const 4096))
              (func (export "alloc") (param i32) (result i32)
                (global.get $next))
              (func (export "ferrix_on_message") (param i32 i32) (result i32)
                (loop $l (br $l))
                (i32.const 1)))
        "#;
        let wasm = wat::parse_str(spinner).unwrap();
        let mut host = PluginHost::new(1_000_000);
        host.load_bytes("spin", &wasm).unwrap();
        // Fuel exhaustion traps -> fail-open Allow, and crucially it returns.
        assert_eq!(host.on_message("hi"), Verdict::Allow);
    }
}
