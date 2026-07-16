#![no_main]
//! Fuzz target for the IRC message parser — the security-critical hot path
//! (plan §10.3). Two invariants are checked on every input:
//!
//! 1. **No panic.** The parser must return a `Result` for *any* byte string,
//!    never panic, overflow, or hang.
//! 2. **Render round-trip.** If an input parses, rendering it and re-parsing
//!    must yield an equal message — the encoder and parser agree.

use libfuzzer_sys::fuzz_target;

use ferrix_protocol::{Limits, Message};

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();

    // Invariant 1: parsing arbitrary bytes never panics.
    let Ok(message) = Message::parse_with(data, &limits) else {
        return;
    };

    // Invariant 2: parse -> render -> parse is a fixed point. Structural
    // equality is checked via Debug strings so the two messages keep
    // independent lifetimes (a direct value comparison would force the fuzz
    // input's lifetime to unify with the rendered buffer's).
    let rendered = message.render();
    let structure = format!("{message:?}");
    // Bind the re-parse to a named local so it drops before `rendered` does.
    let reparsed = Message::parse_with(rendered.as_bytes(), &limits);
    match reparsed {
        Ok(ref roundtripped) => {
            assert_eq!(
                structure,
                format!("{roundtripped:?}"),
                "round-trip mismatch\n  input:    {data:?}\n  rendered: {rendered:?}"
            );
        }
        Err(err) => panic!("rendered output failed to re-parse: {err} (rendered: {rendered:?})"),
    }
});
