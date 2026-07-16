//! Randomized "smoke fuzz" that runs on stable, in the ordinary test job.
//!
//! It mirrors the cargo-fuzz target in `fuzz/` (which needs nightly): the
//! parser must never panic on arbitrary bytes, and any input that parses must
//! survive a render → re-parse round-trip. The PRNG is deterministic, so a
//! failure is always reproducible from the seed printed in the panic.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ferrix_protocol::{Limits, Message};

/// Deterministic xorshift64* PRNG — no external dependency, fully reproducible.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// The two invariants, checked for a single input.
fn check(input: &[u8]) {
    let limits = Limits::default();
    let Ok(message) = Message::parse_with(input, &limits) else {
        return; // A rejected input is fine; it just must not have panicked.
    };
    let rendered = message.render();
    let structure = format!("{message:?}");
    let reparsed =
        Message::parse_with(rendered.as_bytes(), &limits).expect("rendered output must re-parse");
    assert_eq!(
        structure,
        format!("{reparsed:?}"),
        "round-trip mismatch\n  input:    {input:?}\n  rendered: {rendered:?}"
    );
}

#[test]
fn uniform_random_bytes() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    let mut buf = Vec::with_capacity(64);
    for _ in 0..100_000 {
        buf.clear();
        let len = (rng.next_u64() % 64) as usize;
        for _ in 0..len {
            buf.push((rng.next_u64() & 0xff) as u8);
        }
        check(&buf);
    }
}

#[test]
fn structured_irc_tokens() {
    // Biasing the alphabet toward IRC delimiters drives the generator deep into
    // the tag / source / trailing branches far more often than uniform noise.
    const ALPHABET: &[u8] = b"@:! ;=\\\r\nabcXYZ0129#+/.PRIVMSG\xff\x00";
    let mut rng = Rng(0xdead_beef_cafe_babe);
    let mut buf = Vec::with_capacity(48);
    for _ in 0..100_000 {
        buf.clear();
        let len = (rng.next_u64() % 48) as usize;
        for _ in 0..len {
            let idx = (rng.next_u64() as usize) % ALPHABET.len();
            buf.push(ALPHABET[idx]);
        }
        check(&buf);
    }
}
