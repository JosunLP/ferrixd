# ---------------------------------------------------------------------------
# Build stage — rust:alpine targets musl, so `cargo build --release` yields a
# fully static binary and the runtime stage needs no libc or shared objects.
# The build context is whitelisted by .dockerignore (no target/, no .git/).
# ---------------------------------------------------------------------------
FROM rust:1-alpine AS build

# musl-dev supplies the libc headers for the bundled C in the dependency tree
# (ring's shims, rusqlite's sqlite3.c). No cmake, no openssl — by design.
RUN apk add --no-cache musl-dev

WORKDIR /src
COPY . .

# BuildKit cache mounts keep the crates.io registry and incremental artifacts
# across rebuilds; the binary is copied out because cache mounts do not become
# image layers.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p ferrixd \
    && cp target/release/ferrixd /ferrixd

# ---------------------------------------------------------------------------
# Runtime stage — minimal Alpine, non-root. The binary is static, so Alpine
# (vs. scratch) only buys busybox for debugging and container healthchecks.
# ---------------------------------------------------------------------------
FROM alpine:3.22

RUN addgroup -g 10001 -S ferrixd \
    && adduser -u 10001 -S -G ferrixd -H -h /var/lib/ferrixd ferrixd \
    && mkdir -p /etc/ferrixd /var/lib/ferrixd \
    && chown ferrixd:ferrixd /etc/ferrixd /var/lib/ferrixd

COPY --from=build /ferrixd /usr/local/bin/ferrixd

# 6697 TLS (primary) · 6667 optional plaintext · 6666 optional S2S links ·
# 9090 optional Prometheus metrics. Which are live is decided by ferrixd.toml.
EXPOSE 6697 6667 6666 9090

USER ferrixd
# The default config path is ./ferrixd.toml, so the workdir doubles as the
# config home: mount a config at /etc/ferrixd/ferrixd.toml and every
# subcommand (run, check, gen-config, …) finds it without -c.
WORKDIR /etc/ferrixd

# `docker stop` sends SIGTERM, which ferrixd handles as a graceful shutdown.
ENTRYPOINT ["/usr/local/bin/ferrixd"]
