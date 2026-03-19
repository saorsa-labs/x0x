#!/usr/bin/env bash
# x0xd installer (daemon only)
#
# Canonical usage:
#   curl -sfL https://x0x.md/install.sh | bash -s -- --start --health

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

REPO="saorsa-labs/x0x"
RELEASE_URL="https://github.com/$REPO/releases/latest/download"
BIN_DIR="$HOME/.local/bin"
TARGET_BIN="$BIN_DIR/x0xd"
HEALTH_URL="http://127.0.0.1:12700/health"
HEALTH_TIMEOUT_SECS="${X0X_HEALTH_TIMEOUT_SECS:-30}"

INSTALL_ONLY=false
START=false
HEALTH=false
UPGRADE=false
VERIFY=true

info() {
    echo -e "${BLUE}[*]${NC} $1"
}

ok() {
    echo -e "${GREEN}[+]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

fail() {
    echo -e "${RED}[x]${NC} $1" >&2
    exit 1
}

usage() {
    cat <<'EOF'
x0xd installer (daemon only)

Options:
  --install-only   Install binary only (do not start or health-check)
  --start          Start x0xd after installation
  --health         Wait for /health after start (or check existing daemon)
  --upgrade        Reinstall even if x0xd is already present
  --no-verify      Skip archive signature verification
  -h, --help       Show this help

Examples:
  curl -sfL https://x0x.md/install.sh | bash -s -- --start --health
  curl -sfL https://x0x.md/install.sh | bash -s -- --install-only
EOF
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

download() {
    local url="$1"
    local out="$2"

    if have_cmd curl; then
        curl -sfL "$url" -o "$out"
    elif have_cmd wget; then
        wget -qO "$out" "$url"
    else
        fail "Neither curl nor wget is available"
    fi
}

http_ok() {
    local url="$1"
    if have_cmd curl; then
        curl -sf "$url" >/dev/null 2>&1
    elif have_cmd wget; then
        wget -qO- "$url" >/dev/null 2>&1
    else
        return 1
    fi
}

detect_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)
            case "$arch" in
                x86_64)
                    PLATFORM="linux-x64-gnu"
                    ;;
                aarch64)
                    PLATFORM="linux-arm64-gnu"
                    ;;
                *)
                    fail "Unsupported Linux architecture: $arch"
                    ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                x86_64)
                    PLATFORM="macos-x64"
                    ;;
                arm64)
                    PLATFORM="macos-arm64"
                    ;;
                *)
                    fail "Unsupported macOS architecture: $arch"
                    ;;
            esac
            ;;
        *)
            fail "Unsupported operating system: $os"
            ;;
    esac

    ARCHIVE="x0x-${PLATFORM}.tar.gz"
    SIGNATURE="${ARCHIVE}.asc"
    INNER_BINARY="x0x-${PLATFORM}/x0xd"
}

verify_archive() {
    local archive_path="$1"
    local signature_path="$2"
    local key_path="$3"
    local gpg_home="$4"

    if [ "$VERIFY" = false ]; then
        warn "Skipping signature verification (--no-verify)"
        return
    fi

    if ! have_cmd gpg; then
        warn "gpg not found; signature verification skipped"
        warn "Install gnupg to enable signature verification, then re-run the installer"
        return
    fi

    mkdir -p "$gpg_home"
    chmod 700 "$gpg_home"

    info "Importing signing key"
    gpg --batch --homedir "$gpg_home" --import "$key_path" >/dev/null 2>&1 \
        || fail "Failed to import signing key"

    info "Verifying archive signature"
    if gpg --batch --no-tty --status-fd 1 --homedir "$gpg_home" --verify "$signature_path" "$archive_path" 2>/dev/null \
        | grep -Eq "\[GNUPG:\] GOODSIG|\[GNUPG:\] VALIDSIG"; then
        ok "Archive signature verified"
    else
        fail "Archive signature verification failed"
    fi
}

start_daemon() {
    if http_ok "$HEALTH_URL"; then
        ok "x0xd already appears to be running"
        return
    fi

    local daemon_path="x0xd"
    if ! have_cmd x0xd; then
        daemon_path="$TARGET_BIN"
    fi

    info "Starting x0xd"
    nohup "$daemon_path" >/dev/null 2>&1 &
    sleep 1
}

wait_for_health() {
    local i
    info "Waiting for x0xd health check (${HEALTH_TIMEOUT_SECS}s timeout)"
    for ((i = 1; i <= HEALTH_TIMEOUT_SECS; i++)); do
        if http_ok "$HEALTH_URL"; then
            ok "x0xd is healthy"
            return
        fi
        sleep 1
    done

    fail "x0xd did not become healthy at $HEALTH_URL"
}

for arg in "$@"; do
    case "$arg" in
        --install-only)
            INSTALL_ONLY=true
            ;;
        --start)
            START=true
            ;;
        --health)
            HEALTH=true
            ;;
        --upgrade)
            UPGRADE=true
            ;;
        --no-verify)
            VERIFY=false
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "Unknown option: $arg (use --help)"
            ;;
    esac
done

if [ "$INSTALL_ONLY" = true ] && { [ "$START" = true ] || [ "$HEALTH" = true ]; }; then
    fail "--install-only cannot be combined with --start or --health"
fi

echo -e "${BLUE}x0xd installer${NC}"
echo -e "${BLUE}==============${NC}"

detect_platform

mkdir -p "$BIN_DIR"

if [ -x "$TARGET_BIN" ] && [ "$UPGRADE" = false ]; then
    ok "x0xd already installed at $TARGET_BIN"
    info "Use --upgrade to reinstall from latest release"
else
    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    ARCHIVE_PATH="$TMPDIR/$ARCHIVE"
    SIGNATURE_PATH="$TMPDIR/$SIGNATURE"
    KEY_PATH="$TMPDIR/SAORSA_PUBLIC_KEY.asc"
    GPG_HOME="$TMPDIR/gnupg-home"

    info "Downloading $ARCHIVE"
    download "$RELEASE_URL/$ARCHIVE" "$ARCHIVE_PATH"

    if [ "$VERIFY" = true ]; then
        info "Downloading signature and public key"
        download "$RELEASE_URL/$SIGNATURE" "$SIGNATURE_PATH"
        download "$RELEASE_URL/SAORSA_PUBLIC_KEY.asc" "$KEY_PATH"
    fi

    verify_archive "$ARCHIVE_PATH" "$SIGNATURE_PATH" "$KEY_PATH" "$GPG_HOME"

    info "Extracting x0xd"
    tar -xzf "$ARCHIVE_PATH" -C "$TMPDIR" "$INNER_BINARY" \
        || fail "Failed to extract x0xd from archive"

    mv "$TMPDIR/$INNER_BINARY" "$TARGET_BIN"
    chmod +x "$TARGET_BIN"
    ok "Installed x0xd to $TARGET_BIN"
fi

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        warn "$BIN_DIR is not in PATH"
        warn "Add: export PATH=\"\$HOME/.local/bin:\$PATH\""
        ;;
esac

if [ "$START" = true ]; then
    start_daemon
fi

if [ "$HEALTH" = true ]; then
    wait_for_health
fi

ok "Done"
if [ "$START" = true ] && [ "$HEALTH" = false ]; then
    info "To verify now: curl -sf $HEALTH_URL"
fi
