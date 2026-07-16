#!/bin/sh
# ferrixd installer — one-line install / update / uninstall of the prebuilt
# ferrixd binary from GitHub releases (https://github.com/josunlp/ferrixd).
#
#   install:   curl -fsSL https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.sh | sh
#   update:    curl -fsSL https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.sh | sh -s -- update
#   uninstall: curl -fsSL https://raw.githubusercontent.com/josunlp/ferrixd/main/scripts/install.sh | sh -s -- uninstall
#
# Supported platforms: Linux x86_64/aarch64/i686/armv7/armv6 (fully static
# musl — runs on any distro and any libc/kernel vintage), macOS (Apple Silicon
# + Intel), FreeBSD x86_64/aarch64/i686, Android aarch64 (Termux). Windows
# users: scripts/install.ps1 (x64/ARM64/x86). Every download is verified
# against the release's SHA-256 checksum before anything is written to the
# install directory.
#
# POSIX sh on purpose — must run under dash, BusyBox ash (Alpine), and
# Termux's sh, not just bash.

set -u

REPO="josunlp/ferrixd"
BIN="ferrixd"

say()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
ferrixd installer

usage: install.sh [install|update|uninstall] [options]

commands:
  install      download the latest (or --version) release        [default]
  update       replace an existing install, show old -> new version
  uninstall    remove the installed binary (config/data untouched)

options:
  --version vX.Y.Z   pin a specific release (default: latest)
  --dir DIR          install directory; default: \$FERRIXD_INSTALL_DIR if set,
                     \$PREFIX/bin on Termux, /usr/local/bin as root,
                     ~/.local/bin otherwise
  --dry-run          print what would happen without touching anything

one-liners:
  curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install.sh | sh
  curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install.sh | sh -s -- update
  curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install.sh | sh -s -- uninstall
EOF
}

# --- argument parsing --------------------------------------------------------

CMD=install
VERSION=latest
DIR="${FERRIXD_INSTALL_DIR:-}"
DRY=0

while [ $# -gt 0 ]; do
    case "$1" in
        install | update | uninstall) CMD=$1 ;;
        --version)
            shift
            [ $# -gt 0 ] || die "--version needs an argument"
            VERSION=$1
            ;;
        --version=*) VERSION=${1#--version=} ;;
        --dir)
            shift
            [ $# -gt 0 ] || die "--dir needs an argument"
            DIR=$1
            ;;
        --dir=*) DIR=${1#--dir=} ;;
        --dry-run) DRY=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done

# --- platform + directory selection -------------------------------------------

TARGET=
detect_target() {
    os=$(uname -s 2>/dev/null || echo unknown)
    arch=$(uname -m 2>/dev/null || echo unknown)
    case "$arch" in
        x86_64 | amd64) arch=x86_64 ;;
        aarch64 | arm64) arch=aarch64 ;;
        i386 | i486 | i586 | i686 | x86) arch=i686 ;;
        # armv8l = 32-bit userland on ARMv8; runs the armv7 binary.
        armv7l | armv7 | armv8l) arch=armv7 ;;
        armv6l | armv6) arch=armv6 ;;
    esac
    # Termux reports "Linux" from `uname -s`; `-o` distinguishes Android.
    # (macOS/BSD uname may lack -o entirely, hence the stderr discard.)
    if [ "$(uname -o 2>/dev/null || true)" = "Android" ]; then
        os=Android
    fi
    case "$os/$arch" in
        Linux/x86_64) TARGET=x86_64-unknown-linux-musl ;;
        Linux/aarch64) TARGET=aarch64-unknown-linux-musl ;;
        Linux/i686) TARGET=i686-unknown-linux-musl ;;
        Linux/armv7) TARGET=armv7-unknown-linux-musleabihf ;;
        Linux/armv6) TARGET=arm-unknown-linux-musleabihf ;;
        Android/aarch64) TARGET=aarch64-linux-android ;;
        Darwin/x86_64) TARGET=x86_64-apple-darwin ;;
        Darwin/aarch64) TARGET=aarch64-apple-darwin ;;
        FreeBSD/x86_64) TARGET=x86_64-unknown-freebsd ;;
        FreeBSD/aarch64) TARGET=aarch64-unknown-freebsd ;;
        FreeBSD/i686) TARGET=i686-unknown-freebsd ;;
        *) die "no prebuilt binary for $os/$arch — build from source instead: cargo build --release -p ferrixd" ;;
    esac
}

default_dir() {
    [ -n "$DIR" ] && return 0
    if [ "$(uname -o 2>/dev/null || true)" = "Android" ] && [ -n "${PREFIX:-}" ]; then
        DIR="$PREFIX/bin" # Termux: the only writable, PATH'd bin dir
    elif [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
        DIR=/usr/local/bin
    else
        DIR="$HOME/.local/bin"
    fi
}

# --- download + checksum helpers ----------------------------------------------

fetch() { # $1 = url, $2 = output file
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        die "need curl or wget to download"
    fi
}

sha256_hex() { # $1 = file
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 -r "$1" | cut -d' ' -f1
    else
        die "need sha256sum, shasum, or openssl to verify the download"
    fi
}

# Locate an existing install: PATH first, then the default directories.
EXISTING=
find_existing() {
    EXISTING=$(command -v "$BIN" 2>/dev/null || true)
    [ -n "$EXISTING" ] && return 0
    for d in "${FERRIXD_INSTALL_DIR:-}" "${PREFIX:-}/bin" /usr/local/bin "${HOME:-}/.local/bin"; do
        if [ -n "$d" ] && [ -x "$d/$BIN" ]; then
            EXISTING="$d/$BIN"
            return 0
        fi
    done
}

# --- commands ------------------------------------------------------------------

do_install() {
    detect_target

    old_version=""
    if [ "$CMD" = "update" ]; then
        find_existing
        if [ -n "$EXISTING" ]; then
            # Update in place — wherever it lives, not wherever we'd default to.
            DIR=$(dirname "$EXISTING")
            old_version=$("$EXISTING" --version 2>/dev/null || true)
        else
            warn "no existing $BIN found — performing a fresh install"
        fi
    fi
    default_dir

    case "$VERSION" in
        latest) url_base="https://github.com/$REPO/releases/latest/download" ;;
        *) url_base="https://github.com/$REPO/releases/download/v${VERSION#v}" ;;
    esac
    asset="$BIN-$TARGET.tar.gz"

    say "platform: $TARGET"
    say "release:  $VERSION"
    say "asset:    $url_base/$asset"
    say "install:  $DIR/$BIN"
    if [ "$DRY" = 1 ]; then
        say "(dry run — nothing downloaded or written)"
        return 0
    fi

    tmp=$(mktemp -d "${TMPDIR:-/tmp}/ferrixd-install.XXXXXX") || die "mktemp failed"
    trap 'rm -rf "$tmp"' EXIT INT TERM

    say "downloading..."
    fetch "$url_base/$asset" "$tmp/$asset" ||
        die "download failed — check the network, and that release '$VERSION' exists at https://github.com/$REPO/releases"
    fetch "$url_base/$asset.sha256" "$tmp/$asset.sha256" || die "checksum download failed"

    want=$(cut -d' ' -f1 <"$tmp/$asset.sha256")
    got=$(sha256_hex "$tmp/$asset")
    { [ -n "$want" ] && [ "$want" = "$got" ]; } ||
        die "SHA-256 mismatch (expected '$want', got '$got') — refusing to install"

    tar -xzf "$tmp/$asset" -C "$tmp" || die "extraction failed"
    [ -f "$tmp/$BIN" ] || die "archive did not contain $BIN"

    mkdir -p "$DIR" || die "cannot create $DIR (need root? or set --dir / FERRIXD_INSTALL_DIR)"
    # Stage next to the destination, then rename: atomic, and safe to run
    # while an older ferrixd is still executing (no ETXTBSY).
    cp "$tmp/$BIN" "$DIR/.$BIN.new" || die "cannot write to $DIR (need root? or set --dir / FERRIXD_INSTALL_DIR)"
    chmod 755 "$DIR/.$BIN.new"
    mv -f "$DIR/.$BIN.new" "$DIR/$BIN"

    new_version=$("$DIR/$BIN" --version 2>/dev/null || echo "$BIN (version unknown)")
    if [ -n "$old_version" ]; then
        say "updated: $old_version -> $new_version"
    else
        say "installed: $new_version -> $DIR/$BIN"
    fi

    case ":$PATH:" in
        *":$DIR:"*) ;;
        *) warn "$DIR is not on your PATH — add it, e.g.: export PATH=\"$DIR:\$PATH\"" ;;
    esac
}

do_uninstall() {
    if [ -n "$DIR" ]; then
        EXISTING="$DIR/$BIN"
        [ -e "$EXISTING" ] || die "$EXISTING not found"
    else
        find_existing
        [ -n "$EXISTING" ] || die "$BIN not found on PATH or in the default install directories"
    fi
    say "removing: $EXISTING"
    if [ "$DRY" = 1 ]; then
        say "(dry run — nothing removed)"
        return 0
    fi
    rm -f "$EXISTING" || die "could not remove $EXISTING (need root?)"
    say "uninstalled. Config files (ferrixd.toml) and databases were left untouched."
}

case "$CMD" in
    install | update) do_install ;;
    uninstall) do_uninstall ;;
esac
