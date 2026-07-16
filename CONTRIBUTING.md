# Contributing to ferrixd

Thanks for wanting to help. This file is the short version; the
[Development guide](https://j-pfalzgraf.github.io/ferrixd/internals/development)
has the long one.

## Ground rules

These are enforced by CI, not by taste:

- **No `unsafe`.** `unsafe_code = "forbid"` applies to the whole workspace.
- **No panics on the data path.** `unwrap`, `expect`, `panic!`, and `todo!` are
  lint-denied outside tests. Handle the error or make the state unrepresentable.
- **`cargo fmt` and `cargo clippy --all-targets -- -D warnings` must be clean.**
- **Every behaviour change carries a test.** Protocol work belongs in
  `crates/ferrixd/tests/integration.rs`, which drives the real `serve` loop over
  in-memory sockets — a unit test on a helper is not enough to prove a client
  sees the right thing.
- **The parser is fuzzed.** A change to `crates/ferrix-protocol` must survive
  `cargo +nightly fuzz run parse` locally.

## Getting set up

```sh
cargo test --workspace          # unit + integration tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo run -p ferrixd -- run --dev   # a zero-config server on localhost
```

`run --dev` starts a self-signed TLS listener on `127.0.0.1:6697` and plaintext
on `127.0.0.1:6667` — point a client at it and try your change for real.

## Protocol changes

ferrixd tries to be a *correct* IRCv3 server, not an opinionated one:

- follow the [IRCv3 specifications](https://ircv3.net/); when a draft
  capability changes upstream, the implementation follows it;
- what the server advertises it must enforce — if you add an `ISUPPORT` token
  or a capability value, wire it to the constant the handler actually uses;
- a new client-visible state change almost always needs an S2S frame too, or it
  silently stops at the server boundary. See
  [the S2S protocol reference](https://j-pfalzgraf.github.io/ferrixd/reference/s2s-protocol).

Backwards compatibility on a link matters: extend a frame with optional trailing
parameters and keep parsing the old form, so a 1.x network with mixed versions
keeps working.

## Commits and pull requests

- Explain **why** in the commit body, not just what — the diff already says what.
- Keep a PR to one topic. A refactor and a fix in one branch is two reviews
  fighting each other.
- Update the docs in `docs/` in the same PR. A feature nobody can find is not
  finished.

## Security issues

Do not open a public issue — see [SECURITY.md](SECURITY.md).
