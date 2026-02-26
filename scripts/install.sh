#!/usr/bin/env bash
# x0x Installation Script (Unix/macOS/Linux)
#
# Usage:
#   curl -sfL https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh | sh
#   curl -sfL https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh | sh -s -- -y
#   bash install.sh              # interactive (prompts where needed)
#   bash install.sh -y           # non-interactive (sensible defaults)
#
# Non-interactive mode is automatic when no TTY is detected (e.g., agents, CI, Docker).

set -euo pipefail

# - Configuration ------------------------------------------------------------

REPO="${X0X_REPO:-saorsa-labs/x0x}"
RELEASE_URL="${X0X_RELEASE_URL:-https://github.com/$REPO/releases/latest/download}"
INSTALL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/x0x"
BIN_DIR="$HOME/.local/bin"
API_ENDPOINT="${X0X_API_ENDPOINT:-http://127.0.0.1:12700}"
SKIP_GPG="${X0X_SKIP_GPG:-false}"

# - Detect interactive mode --------------------------------------------------

INTERACTIVE=true
if ! [ -t 0 ]; then
    INTERACTIVE=false
fi

# Parse flags
while [[ $# -gt 0 ]]; do
    case $1 in
        -y|--yes|--non-interactive)
            INTERACTIVE=false
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# - Colors (disabled if not a terminal) -------------------------------------

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# - Helpers -----------------------------------------------------------------

info()    { echo -e "${BLUE}i${NC} $*"; }
success() { echo -e "${GREEN}ok${NC} $*"; }
warn()    { echo -e "${YELLOW}warn${NC} $*"; }
fail()    { echo -e "${RED}err${NC} $*"; }

download() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        if ! curl -sfL "$url" -o "$dest" 2>/dev/null; then
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -qO "$dest" "$url" 2>/dev/null; then
            return 1
        fi
    else
        fail "Neither curl nor wget found. Install one and re-run."
        exit 1
    fi

    if [ ! -s "$dest" ]; then
        return 1
    fi
    return 0
}

# - Install state for summary -----------------------------------------------

SKILL_INSTALLED=false
DAEMON_INSTALLED=false
DAEMON_STARTED=false
HEALTH_OK=false
GPG_VERIFIED=false
X0XD_VERSION=""
AGENT_ID=""
INSTALL_WARNINGS=()

# - Preflight checks ---------------------------------------------------------

if [ -z "${HOME:-}" ]; then
    fail "HOME environment variable not set. Cannot determine install location."
    exit 1
fi

echo -e "${BLUE}x0x Installation Script${NC}"
echo -e "${BLUE}========================${NC}"
if [ "$INTERACTIVE" = false ]; then
    info "Non-interactive mode (no TTY detected or -y flag used)"
fi
echo ""

# - GPG verification ---------------------------------------------------------

GPG_AVAILABLE=false
if [ "$SKIP_GPG" = "true" ]; then
    info "Skipping GPG verification (X0X_SKIP_GPG=true)"
    INSTALL_WARNINGS+=("gpg_skipped: signature verification disabled by X0X_SKIP_GPG")
elif command -v gpg >/dev/null 2>&1; then
    GPG_AVAILABLE=true
else
    if [ "$INTERACTIVE" = true ]; then
        warn "GPG not found. Signature verification will be skipped."
        echo ""
        echo "To enable signature verification, install GPG:"
        echo "  macOS:  brew install gnupg"
        echo "  Ubuntu: sudo apt install gnupg"
        echo "  Fedora: sudo dnf install gnupg"
        echo ""
        read -p "Continue without verification? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        info "GPG not found. Skipping signature verification."
        INSTALL_WARNINGS+=("gpg_missing: signature verification skipped (GPG not installed)")
    fi
fi

# - Download SKILL.md --------------------------------------------------------

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "Downloading SKILL.md..."
if download "$RELEASE_URL/SKILL.md" "SKILL.md"; then
    success "SKILL.md downloaded"
    SKILL_INSTALLED=true
else
    fail "Failed to download SKILL.md from $RELEASE_URL/SKILL.md"
    fail "Check your internet connection or try again later."
    exit 1
fi

# - GPG signature verification -----------------------------------------------

if [ "$GPG_AVAILABLE" = true ]; then
    echo "Downloading signature..."
    if download "$RELEASE_URL/SKILL.md.sig" "SKILL.md.sig" && \
       download "$RELEASE_URL/SAORSA_PUBLIC_KEY.asc" "SAORSA_PUBLIC_KEY.asc"; then

        gpg --import SAORSA_PUBLIC_KEY.asc 2>&1 | grep -v "^gpg:" || true

        echo "Verifying signature..."
        if gpg --verify SKILL.md.sig SKILL.md 2>&1 | grep -q "Good signature"; then
            success "Signature verified"
            GPG_VERIFIED=true
        else
            if [ "$INTERACTIVE" = true ]; then
                fail "Signature verification failed"
                echo ""
                echo "This file may have been tampered with."
                read -p "Install anyway? (y/N) " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    exit 1
                fi
            else
                warn "Signature verification failed. Continuing anyway (non-interactive mode)."
                INSTALL_WARNINGS+=("gpg_failed: SKILL.md signature verification failed")
            fi
        fi
    else
        warn "Could not download signature files. Skipping verification."
        INSTALL_WARNINGS+=("gpg_download_failed: could not download signature files")
    fi
fi

# - Platform detection -------------------------------------------------------

echo ""
echo "Detecting platform..."

OS="$(uname -s)"
ARCH="$(uname -m)"
PLATFORM=""

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64)  PLATFORM="linux-x64-gnu" ;;
            aarch64) PLATFORM="linux-arm64-gnu" ;;
            *)
                warn "Unsupported Linux architecture: $ARCH. x0xd daemon installation skipped."
                INSTALL_WARNINGS+=("unsupported_arch: $ARCH")
                ;;
        esac
        ;;
    Darwin)
        case "$ARCH" in
            arm64)   PLATFORM="macos-arm64" ;;
            x86_64)  PLATFORM="macos-x64" ;;
            *)
                warn "Unsupported macOS architecture: $ARCH. x0xd daemon installation skipped."
                INSTALL_WARNINGS+=("unsupported_arch: $ARCH")
                ;;
        esac
        ;;
    *)
        warn "Unsupported operating system: $OS. x0xd supports Linux and macOS."
        INSTALL_WARNINGS+=("unsupported_os: $OS")
        ;;
esac

info "Platform: $OS $ARCH${PLATFORM:+ ($PLATFORM)}"

# - x0xd daemon binary -------------------------------------------------------

if [ -n "$PLATFORM" ]; then
    ARCHIVE="x0x-${PLATFORM}.tar.gz"
    ARCHIVE_URL="$RELEASE_URL/$ARCHIVE"
    TMPDIR="$(mktemp -d)"

    if [ -f "$BIN_DIR/x0xd" ]; then
        EXISTING_VERSION=$("$BIN_DIR/x0xd" --version 2>/dev/null || echo "unknown")
        info "Existing x0xd found ($EXISTING_VERSION). Upgrading..."
    fi

    echo "Downloading x0xd ($PLATFORM)..."
    if download "$ARCHIVE_URL" "$TMPDIR/$ARCHIVE"; then
        echo "Extracting x0xd..."
        if tar -xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR" "x0x-${PLATFORM}/x0xd" 2>/dev/null; then
            mkdir -p "$BIN_DIR"

            if curl -s "$API_ENDPOINT/health" >/dev/null 2>&1; then
                info "Stopping running x0xd for upgrade..."
                pkill -f "x0xd" 2>/dev/null || true
                sleep 1
            fi

            mv "$TMPDIR/x0x-${PLATFORM}/x0xd" "$BIN_DIR/x0xd"
            chmod +x "$BIN_DIR/x0xd"
            DAEMON_INSTALLED=true

            X0XD_VERSION=$("$BIN_DIR/x0xd" --version 2>/dev/null || echo "unknown")
            success "x0xd installed to: $BIN_DIR/x0xd ($X0XD_VERSION)"

            if [ "$OS" = "Darwin" ]; then
                if command -v xattr >/dev/null 2>&1 && xattr -l "$BIN_DIR/x0xd" 2>/dev/null | grep -q "com.apple.quarantine"; then
                    info "Removing macOS quarantine attribute..."
                    xattr -d com.apple.quarantine "$BIN_DIR/x0xd" 2>/dev/null || {
                        warn "Could not remove macOS quarantine."
                        INSTALL_WARNINGS+=("macos_quarantine: xattr fix may be required")
                    }
                fi
            fi
        else
            fail "Failed to extract x0xd from archive."
            INSTALL_WARNINGS+=("extract_failed: could not extract x0xd")
        fi
    else
        fail "Failed to download x0xd binary from $ARCHIVE_URL"
        warn "SKILL.md was installed but x0xd daemon is not available."
        INSTALL_WARNINGS+=("download_failed: could not download x0xd binary")
    fi

    rm -rf "$TMPDIR"

    if [ "$DAEMON_INSTALLED" = true ]; then
        case ":$PATH:" in
            *":$BIN_DIR:"*) ;;
            *)
                export PATH="$BIN_DIR:$PATH"
                warn "$BIN_DIR is not in your PATH."
                echo "  Added for this session. To make permanent, add to your shell profile:"
                echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
                INSTALL_WARNINGS+=("path_missing: $BIN_DIR not in PATH")
                ;;
        esac
    fi
fi

# - Post-install: start x0xd and health check --------------------------------

if [ "$DAEMON_INSTALLED" = true ]; then
    echo ""

    if curl -s "$API_ENDPOINT/health" >/dev/null 2>&1; then
        info "x0xd is already running."
        DAEMON_STARTED=true
    else
        if command -v lsof >/dev/null 2>&1 && lsof -i :12700 >/dev/null 2>&1; then
            warn "Port 12700 is in use by another process."
            warn "x0xd installed but cannot start on default port."
            echo "  Free the port or configure a different one in $INSTALL_DIR/config.toml"
            INSTALL_WARNINGS+=("port_conflict: port 12700 is in use")
        else
            info "Starting x0xd..."
            "$BIN_DIR/x0xd" > "$INSTALL_DIR/x0xd.log" 2>&1 &
            X0XD_PID=$!

            for i in $(seq 1 10); do
                if curl -s "$API_ENDPOINT/health" >/dev/null 2>&1; then
                    DAEMON_STARTED=true
                    break
                fi
                sleep 1
            done

            if [ "$DAEMON_STARTED" = true ]; then
                success "x0xd started (PID $X0XD_PID)"
            else
                warn "x0xd started but health check timed out after 10s."
                warn "Try: curl $API_ENDPOINT/health"
                INSTALL_WARNINGS+=("health_timeout: x0xd started but health timed out")
            fi
        fi
    fi

    if [ "$DAEMON_STARTED" = true ]; then
        HEALTH_JSON=$(curl -s "$API_ENDPOINT/health" 2>/dev/null || echo "")
        if [ -n "$HEALTH_JSON" ]; then
            HEALTH_OK=true
            success "Health check passed"

            AGENT_JSON=$(curl -s "$API_ENDPOINT/agent" 2>/dev/null || echo "")
            if [ -n "$AGENT_JSON" ]; then
                AGENT_ID=$(echo "$AGENT_JSON" | grep -o '"agent_id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"agent_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo "")
                if [ -n "$AGENT_ID" ]; then
                    success "Identity created: ${AGENT_ID:0:16}..."
                fi
            fi

            PEER_COUNT=$(echo "$HEALTH_JSON" | grep -o '"peers"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*$' || echo "0")
            if [ "$PEER_COUNT" = "0" ]; then
                info "0 peers connected (normal on first start - peers will connect shortly)"
            else
                success "$PEER_COUNT peer(s) connected"
            fi
        fi
    fi
fi

# - Summary ------------------------------------------------------------------

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  x0x installation complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

if [ "$SKILL_INSTALLED" = true ]; then
    echo "  SKILL.md:  $INSTALL_DIR/SKILL.md"
fi
if [ "$DAEMON_INSTALLED" = true ]; then
    echo "  x0xd:      $BIN_DIR/x0xd${X0XD_VERSION:+ ($X0XD_VERSION)}"
    echo "  API:       $API_ENDPOINT"
fi
if [ "$HEALTH_OK" = true ]; then
    echo "  Status:    Running and healthy"
fi
if [ -n "$AGENT_ID" ]; then
    echo "  Agent ID:  ${AGENT_ID:0:16}..."
fi

if [ ${#INSTALL_WARNINGS[@]} -gt 0 ]; then
    echo ""
    echo "  Warnings:"
    for w in "${INSTALL_WARNINGS[@]}"; do
        echo "    - $w"
    done
fi

echo ""

# - Machine-readable summary (for agents) ------------------------------------

echo "--- x0x-install-summary ---"
echo "status: $([ "$SKILL_INSTALLED" = true ] && echo 'success' || echo 'failed')"
echo "skill_path: $INSTALL_DIR/SKILL.md"
echo "skill_installed: $SKILL_INSTALLED"
echo "daemon_installed: $DAEMON_INSTALLED"
if [ "$DAEMON_INSTALLED" = true ]; then
    echo "x0xd_path: $BIN_DIR/x0xd"
    echo "x0xd_version: ${X0XD_VERSION:-unknown}"
fi
echo "daemon_running: $DAEMON_STARTED"
echo "health: $([ "$HEALTH_OK" = true ] && echo 'ok' || echo 'failed')"
echo "api_endpoint: $API_ENDPOINT"
echo "gpg_verified: $GPG_VERIFIED"
if [ -n "$AGENT_ID" ]; then
    echo "agent_id: $AGENT_ID"
fi
if [ ${#INSTALL_WARNINGS[@]} -gt 0 ]; then
    echo "warnings: ${INSTALL_WARNINGS[*]}"
fi
echo "--- end ---"
