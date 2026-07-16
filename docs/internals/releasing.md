# Releasing

Cutting a release is a tag push. Everything else — building for seven targets,
checksumming, and publishing — is done by
[`release.yml`](https://github.com/j-pfalzgraf/ferrixd/blob/main/.github/workflows/release.yml).

## The one rule

**Bump the version before you tag.** The release workflow's first job refuses a
tag whose name disagrees with `[workspace.package] version` in `Cargo.toml` —
otherwise the published binaries would report a version they are not.

## Checklist

```sh
# 1. Bump the version (workspace + the internal dependency's `version = "…"`).
$EDITOR Cargo.toml
cargo check --workspace          # refreshes Cargo.lock

# 2. Record what changed.
$EDITOR CHANGELOG.md

# 3. The gates CI will run anyway — run them first.
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check

# 4. Prove the artifact, not just the source.
cargo build --release -p ferrixd && ./target/release/ferrixd --version
docker build -t ferrixd:test . && docker run --rm ferrixd:test --version

# 5. Commit, tag, push.
git commit -am "Release vX.Y.Z"
git tag -a vX.Y.Z -m "ferrixd vX.Y.Z"
git push origin main --follow-tags
```

A `workflow_dispatch` run of the release workflow builds every target **without
publishing** — use it to smoke-test a change to the build matrix before tagging.

## What the workflow produces

For each of the seven targets, a version-less archive plus its checksum
(`ferrixd-<target>.tar.gz` / `.zip`, and `.sha256`), attached to a GitHub
release along with a `SHA256SUMS` file. The names carry no version so that
`releases/latest/download/…` stays a stable URL — which is exactly what
[`scripts/install.sh`](https://github.com/j-pfalzgraf/ferrixd/blob/main/scripts/install.sh)
downloads and verifies.

## Publishing to crates.io (optional)

The crates carry complete metadata, but `ferrixd` depends on `ferrix-protocol`,
so the order matters:

```sh
cargo publish -p ferrix-protocol
cargo publish -p ferrixd          # only after the first is on the index
```

## Versioning

[Semantic versioning](https://semver.org/). What 1.x guarantees — the config
schema, the client protocol, the CLI, the plugin ABI, and S2S wire
compatibility — is spelled out in the [roadmap](/internals/roadmap#stability-promise-1-x).
