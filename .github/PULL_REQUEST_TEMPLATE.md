<!--
Thanks for contributing to ferrixd! Please read CONTRIBUTING.md first.
Keep a PR to one topic — a refactor and a fix in one branch is two reviews fighting each other.
-->

## Summary

<!-- What does this change do, and why? The diff already says *what* — explain *why*. -->

## Related issues

<!-- e.g. "Closes #123", "Refs #456". Delete if none. -->

## Type of change

<!-- Mark all that apply with an [x]. -->

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ Feature (non-breaking change that adds functionality)
- [ ] 📡 Protocol / conformance fix (client-facing or S2S wire behaviour)
- [ ] 💥 Breaking change (incompatible with the 1.x stability promise — explain below)
- [ ] 📚 Documentation
- [ ] 🧹 Refactor / internal (no behaviour change)
- [ ] 🔧 Build / CI / tooling

## How was this tested?

<!-- Describe how you verified this. Delete lines that don't apply. -->

- [ ] `cargo test --workspace --all-features`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo fmt --all --check`
- [ ] Added or updated an integration test in `crates/ferrixd/tests/`
- [ ] Ran it for real against `cargo run -p ferrixd -- run --dev`
- [ ] Parser change: survives `cargo +nightly fuzz run parse_message`

## Protocol & compatibility

<!-- Delete this section entirely if the change touches no protocol surface. -->

- [ ] A client-visible state change also propagates over S2S (or intentionally does not — say which).
- [ ] Anything advertised (`ISUPPORT` token, capability value) is wired to the constant the handler enforces.
- [ ] S2S frame changes are backwards-compatible: extended with optional trailing params, old form still parses.
- [ ] Draft IRCv3 behaviour matches the current upstream spec (link it in the description).

## Checklist

- [ ] No `unsafe` — `unsafe_code = "forbid"` still holds workspace-wide.
- [ ] No `unwrap`/`expect`/`panic!`/`todo!` on the data path (outside tests).
- [ ] Every behaviour change carries a test.
- [ ] Docs under `docs/` are updated in this same PR (a feature nobody can find isn't finished).
- [ ] `CHANGELOG.md` is updated for user-visible changes.
- [ ] The commit messages explain **why**, and this PR is scoped to a single topic.

<!-- By submitting, you agree your contribution is dual-licensed under MIT OR Apache-2.0 (see README §License). -->
