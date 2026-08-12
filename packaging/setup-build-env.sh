#!/usr/bin/env bash
#
# setup-build-env.sh — prepare a build host for insomnia.
#
# Installs everything needed to build the insomnia daemon and the Debian
# package, mirroring the steps in the CI workflows under .github/workflows/
# (ci.yaml, build-amd64.yaml, build-arm64.yaml).
#
# What it installs:
#   * APT system packages (build-essential, protobuf-compiler, ...) for the
#     Rust build (the vendored zebra-rs proto files compile at build time).
#   * The stable Rust toolchain via rustup (if cargo is not already present).
#   * cargo-deb (via `cargo install`), the Debian package builder.
#
# Usage:
#   packaging/setup-build-env.sh [options]
#
# Options:
#   --no-cargo-deb  Skip cargo-deb (only needed to build the .deb package).
#   --no-rust    Do not install rustup/Rust (assume a toolchain is present).
#   -h, --help   Show this help and exit.
#
# The script is idempotent: re-running it skips work that is already done.

set -euo pipefail

# ---- configuration -----------------------------------------------------------

INSTALL_CARGO_DEB=1
INSTALL_RUST=1

# System packages. protobuf-compiler is the only one `cargo build`/`cargo test`
# needs beyond a C toolchain; build-essential/pkg-config/curl/git/make round
# out the build.
APT_PACKAGES=(
    build-essential
    pkg-config
    curl
    git
    make
    protobuf-compiler
)

# ---- helpers -----------------------------------------------------------------

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '\033[1;33m warning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m error:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0"
}

# sudo wrapper: use sudo only when not already root.
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

need_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---- argument parsing --------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --no-cargo-deb) INSTALL_CARGO_DEB=0 ;;
        --no-rust)  INSTALL_RUST=0 ;;
        -h|--help)  usage; exit 0 ;;
        *)          die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

# ---- preflight ---------------------------------------------------------------

if ! need_cmd apt-get; then
    die "this script targets Ubuntu/Debian (apt-get not found)."
fi

if [ -n "$SUDO" ] && ! need_cmd sudo; then
    die "not running as root and 'sudo' is not installed; re-run as root or install sudo."
fi

ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
log "Preparing insomnia build environment (arch: ${ARCH})"

# ---- 1. system packages ------------------------------------------------------

log "Installing system packages via apt"
$SUDO apt-get update
$SUDO apt-get install -y "${APT_PACKAGES[@]}"

# ---- 2. Rust stable ----------------------------------------------------------

# Make an existing rustup/cargo visible even if the current shell was started
# before it was installed.
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

if [ "$INSTALL_RUST" -eq 1 ]; then
    if need_cmd cargo && need_cmd rustup; then
        log "Rust toolchain already present ($(rustc --version 2>/dev/null || echo unknown)); skipping rustup install"
    else
        log "Installing the stable Rust toolchain via rustup"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
else
    info "Skipping Rust install (--no-rust)"
fi

need_cmd cargo || die "cargo not found on PATH. Install Rust (rustup) or drop --no-rust, then re-run."

# ---- 3. cargo-deb (Debian package builder) ----------------------------------

if [ "$INSTALL_CARGO_DEB" -eq 1 ]; then
    if cargo deb --version >/dev/null 2>&1; then
        log "cargo-deb already installed ($(cargo deb --version 2>/dev/null | head -n1)); skipping"
    else
        log "Installing cargo-deb via cargo install"
        cargo install cargo-deb --locked
    fi
else
    info "Skipping cargo-deb (--no-cargo-deb). Only needed to build the .deb package."
fi

# ---- done --------------------------------------------------------------------

log "Build environment ready."
echo
info "Next steps:"
info "  cargo build --release    # build the insomnia daemon"
if [ "$INSTALL_CARGO_DEB" -eq 1 ]; then
    info "  cd packaging && make ${ARCH}   # build the .deb package"
fi
if [ "$INSTALL_RUST" -eq 1 ] && [ -f "$HOME/.cargo/env" ]; then
    info ""
    info "  If 'cargo' isn't found in a new shell, run: . \"\$HOME/.cargo/env\""
fi
