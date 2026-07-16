# Installation

Every release ships prebuilt, checksum-verified binaries for:

| Platform            | Target                       | Notes                             |
| ------------------- | ---------------------------- | --------------------------------- |
| Linux x86_64        | `x86_64-unknown-linux-musl`  | fully static — runs on any distro |
| Linux aarch64       | `aarch64-unknown-linux-musl` | fully static                      |
| macOS Apple Silicon | `aarch64-apple-darwin`       |                                   |
| macOS Intel         | `x86_64-apple-darwin`        |                                   |
| Windows x64         | `x86_64-pc-windows-msvc`     |                                   |
| FreeBSD x86_64      | `x86_64-unknown-freebsd`     |                                   |
| Android (Termux)    | `aarch64-linux-android`      | installs to `$PREFIX/bin`         |

Asset names are version-less (`ferrixd-<target>.tar.gz` / `.zip`), so
`releases/latest/download/…` URLs are stable. Every download is verified
against its published SHA-256 checksum by the installer.

## One-line install

**Linux · macOS · FreeBSD · Android (Termux):**

```sh
curl -fsSL https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.sh | sh
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.ps1 | iex
```

Where the binary lands:

| Context           | Directory                                                    |
| ----------------- | ------------------------------------------------------------ |
| Unix, run as root | `/usr/local/bin`                                             |
| Unix, run as user | `~/.local/bin`                                               |
| Termux            | `$PREFIX/bin`                                                |
| Windows           | `%LOCALAPPDATA%\Programs\ferrixd` (added to the user `PATH`) |

Override the directory with `--dir <PATH>` (PowerShell: `-Dir`) or the
`FERRIXD_INSTALL_DIR` environment variable.

::: tip Re-running is safe
The install command is idempotent — re-running it switches you to the latest
release. There is also an explicit `update` verb (below) that finds your
existing binary and reports `old → new`.
:::

## Update

```sh
curl -fsSL https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.sh | sh -s -- update
```

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.ps1))) update
```

`update` locates the installed binary (on `PATH` first, then the default
directories) and replaces it **in place** via a staged copy and an atomic
rename — safe to run while the server is running; restart to pick up the new
version.

## Uninstall

```sh
curl -fsSL https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.sh | sh -s -- uninstall
```

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.ps1))) uninstall
```

Uninstall removes only the binary. Your configuration and SQLite database
stay where they are.

## Pinning a version

```sh
curl -fsSL https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.sh | sh -s -- install --version v0.1.0
```

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.ps1))) install v0.1.0
```

Other installer flags: `--dry-run` prints what would happen without touching
anything.

## Docker

The repository ships a multi-stage `Dockerfile` (static musl build in
`rust:alpine`, dropped into a small Alpine runtime, running as a non-root
user) and a `docker-compose.yml` with ports, volumes, and a healthcheck.

```sh
docker build -t ferrixd .

# Scaffold a config into the current directory, then edit it.
# --user makes the container write the file as you, not uid 10001.
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/etc/ferrixd ferrixd gen-config

# Validate, then run:
docker run --rm -v "$PWD/ferrixd.toml":/etc/ferrixd/ferrixd.toml:ro ferrixd check
docker run -d --name ferrixd -p 6697:6697 \
    -v "$PWD/ferrixd.toml":/etc/ferrixd/ferrixd.toml:ro \
    -v ferrixd-data:/var/lib/ferrixd \
    ferrixd

# …or the same via compose:
docker compose up -d
```

Paths inside the container:

- the config is expected at `/etc/ferrixd/ferrixd.toml` (the image workdir,
  so the default `./ferrixd.toml` resolves there);
- durable state belongs on the `/var/lib/ferrixd` volume — set
  `[persistence] path = "/var/lib/ferrixd/ferrixd.db"` so history and
  registrations survive container recreation;
- real TLS certificates are extra read-only mounts referenced from the
  config; `self_signed_dev = true` needs none.

`docker stop` (SIGTERM) triggers the same graceful shutdown as `Ctrl-C`.
Every utility subcommand works through the same entrypoint:

```sh
docker run --rm -it ferrixd hash-password   # -it: the prompt is interactive
docker run --rm ferrixd --help
```

See [Production Deployment](/guide/deployment) for a full compose + systemd
walkthrough.

## Building from source

You need a Rust toolchain (the workspace pins its version via
`rust-toolchain.toml`; `rustup` picks it up automatically):

```sh
git clone https://github.com/josunlp/ferrixd
cd ferrixd
cargo build --release -p ferrixd
# → target/release/ferrixd
```

No C toolchain gymnastics required in the default configuration — SQLite is
bundled (`rusqlite` with the `bundled` feature) and the WASM interpreter is
pure Rust. Details, tests, fuzzing, and cross-compilation notes:
[Building & Testing](/internals/development).

## Shell completions

The binary generates its own completion scripts:

```sh
ferrixd completions bash > /etc/bash_completion.d/ferrixd
ferrixd completions zsh  > "${fpath[1]}/_ferrixd"
ferrixd completions fish > ~/.config/fish/completions/ferrixd.fish
```

## Verifying a download manually

Each release asset has a companion `.sha256` file plus a combined
`SHA256SUMS`:

```sh
curl -fsSLO https://github.com/josunlp/ferrixd/releases/latest/download/ferrixd-x86_64-unknown-linux-musl.tar.gz
curl -fsSLO https://github.com/josunlp/ferrixd/releases/latest/download/ferrixd-x86_64-unknown-linux-musl.tar.gz.sha256
sha256sum -c ferrixd-x86_64-unknown-linux-musl.tar.gz.sha256
```
