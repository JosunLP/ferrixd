# Building & Testing

Everything you need to hack on ferrixd.

## Toolchain

The workspace pins its Rust version in `rust-toolchain.toml`; with
`rustup`, the right compiler is selected automatically:

```sh
git clone https://github.com/josunlp/ferrixd
cd ferrixd
cargo build            # debug
cargo build --release  # optimized (release profile strips symbols)
```

No system libraries needed for the default build — SQLite is bundled
(`rusqlite`/`bundled`) and the WASM interpreter (`wasmi`) is pure Rust.

Run a development server from the checkout:

```sh
cargo run -p ferrixd -- run --dev
```

## The quality gates

Exactly what CI runs — all four must pass:

```sh
cargo test                                # unit + integration tests
cargo clippy --all-targets -- -D warnings # lints are errors
cargo fmt --check                         # formatting
cargo deny check                          # license/advisory/dependency audit
```

Two lint policies deserve a call-out, because they're unusual and
non-negotiable:

- `unsafe_code = "forbid"` at the workspace level — code that needs
  `unsafe` needs a different design.
- `panic!`/`unwrap`/`expect` are **clippy errors in the data path** — use
  `Result` and structured errors. Tests are exempt.

## Testing philosophy

- **Unit tests** live beside their modules; **integration tests** drive
  real connections (including TLS) against an in-process server.
- **Conformance**: capabilities are implemented against the IRCv3 spec
  text. Running the [irctest](https://github.com/progval/irctest) suite
  against a local build is a useful external check, but it is not (yet)
  wired into CI.
- **Fuzzing** the protocol parser (nightly toolchain):

  ```sh
  cargo install cargo-fuzz
  cargo +nightly fuzz run parse_message
  ```

  The harness asserts the parser never panics and respects its length
  budgets on arbitrary input. If you touch `ferrix-protocol`, run the
  fuzzer for a while before opening a PR.

## Load testing

The `loadtest/` crate (excluded from the workspace build) is the
connection-density generator behind the 100k figure:

```sh
cd loadtest
cargo run --release -- --help
```

It opens tens of thousands of registered connections with configurable
join/message behavior and reports latency and throughput. Methodology
notes live in `loadtest/`'s README. The headline result: ~100,000
concurrent connections on an 8-core host at ~1.38 GB RSS (~13.8 KB per
connection), scaling linearly with connection count.

## Repository layout for contributors

| Path                      | What lives there                                                                         |
| ------------------------- | ---------------------------------------------------------------------------------------- |
| `crates/ferrix-protocol/` | wire model, parser, encoder — dependency-light, fuzz-facing                              |
| `crates/ferrixd/src/`     | the daemon (module map in [Architecture](/internals/architecture))                       |
| `fuzz/`                   | cargo-fuzz targets                                                                       |
| `loadtest/`               | density load generator (own crate, excluded)                                             |
| `scripts/`                | installer scripts (POSIX sh — must stay dash/BusyBox/Termux-compatible — and PowerShell) |
| `docs/`                   | this documentation (VitePress)                                                           |
| `.github/workflows/`      | `ci.yml` (gates above) and `release.yml` (7-target build matrix)                         |

## Working on the docs

```sh
cd docs
npm install
npm run dev      # live-reload dev server
npm run build    # what CI/Pages runs; also checks internal links
```

## Cutting a release

1. Bump `version` in the workspace `Cargo.toml`
   (`[workspace.package]`).
2. Commit, tag `vX.Y.Z` (must equal the crate version — the workflow
   refuses mismatches), push the tag.
3. `release.yml` builds all seven targets (musl statics via `cross`,
   native macOS/Windows), generates SHA-256 checksums, and publishes the
   GitHub release. A `workflow_dispatch` run is a dry run: builds
   everything, publishes nothing.

## Conventions

- Match the existing style; `rustfmt` settles formatting arguments.
- Error handling: `thiserror`-style structured errors in library code,
  `anyhow` at the CLI boundary.
- New capabilities: implement against the IRCv3 spec text, add
  integration tests, and cover negotiation (LS/REQ/ACK/NAK) — not just
  the happy path.
- New limits: every bound needs a defined consequence, a log line, and —
  if clients can hit it — a metric.
