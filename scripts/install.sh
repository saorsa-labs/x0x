#!/usr/bin/env sh
# x0x installer — installs the x0x agent network.
#
# Usage:
#   curl -sfL https://x0x.md | sh                    # install + start
#   curl -sfL https://x0x.md | sh -s -- --autostart   # install + start + autostart on boot
#   bash install.sh --name alice                      # named instance
#
# What it does:
#   1. Detects platform (Linux/macOS, x64/arm64)
#   2. Downloads latest release from GitHub
#   3. Stops any running x0xd instance
#   4. Installs x0xd (daemon) + x0x (CLI) to ~/.local/bin
#   5. Starts the daemon
#   6. Optionally configures autostart on boot (--autostart)
#
# Requirements: curl or wget, tar, sh
# No root/sudo required (except --autostart on Linux uses systemd).

set -e

REPO="saorsa-labs/x0x"
URL="https://github.com/$REPO/releases/latest/download"
BIN="$HOME/.local/bin"
NAME=""
AUTOSTART=false

# ── Parse args ────────────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --autostart) AUTOSTART=true ;;
        --name)      shift; NAME="$1" ;;
        --name=*)    NAME="${1#*=}" ;;
    esac
    shift
done

# ── Detect platform ──────────────────────────────────────────────────────────

OS=$(uname -s)
ARCH=$(uname -m)
case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64)  PLATFORM="linux-x64-gnu" ;;
            aarch64) PLATFORM="linux-arm64-gnu" ;;
            *) echo "Unsupported: $OS $ARCH"; exit 1 ;;
        esac ;;
    Darwin)
        case "$ARCH" in
            arm64)  PLATFORM="macos-arm64" ;;
            x86_64) PLATFORM="macos-x64" ;;
            *) echo "Unsupported: $OS $ARCH"; exit 1 ;;
        esac ;;
    *) echo "Unsupported: $OS"; exit 1 ;;
esac

# ── Data directory ───────────────────────────────────────────────────────────

case "$OS" in
    Darwin) DATABASE="$HOME/Library/Application Support" ;;
    *)      DATABASE="${XDG_DATA_HOME:-$HOME/.local/share}" ;;
esac
SHARED_DIR="$DATABASE/x0x"
if [ -n "$NAME" ]; then
    INSTANCE_DIR="$DATABASE/x0x-$NAME"
else
    INSTANCE_DIR="$SHARED_DIR"
fi

# ── Stop any running instance ───────────────────────────────────────────────

XOX="$BIN/x0x"
if [ -f "$XOX" ]; then
    echo "Stopping running instance..."
    if [ -n "$NAME" ]; then
        "$XOX" --name "$NAME" stop >/dev/null 2>&1 || true
    else
        "$XOX" stop >/dev/null 2>&1 || true
    fi
    sleep 1
fi

# ── Download and install ────────────────────────────────────────────────────

echo "x0x installer"
echo "  Platform: $PLATFORM"
echo "  Install:  $BIN"

ARCHIVE="x0x-${PLATFORM}.tar.gz"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Downloading..."
if command -v curl >/dev/null 2>&1; then
    curl -sfL "$URL/$ARCHIVE" -o "$TMP/$ARCHIVE"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP/$ARCHIVE" "$URL/$ARCHIVE"
else
    echo "Error: need curl or wget"; exit 1
fi

mkdir -p "$BIN"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP"

INSTALLED=""
for bin in x0xd x0x; do
    SRC="$TMP/x0x-${PLATFORM}/$bin"
    if [ -f "$SRC" ]; then
        cp "$SRC" "$BIN/$bin"
        chmod +x "$BIN/$bin"
        INSTALLED="$INSTALLED $bin"
    fi
done
echo "Installed:$INSTALLED"

# Clean up stale x0x-bootstrap binary (removed in v0.8.0)
if [ -f "$BIN/x0x-bootstrap" ]; then
    rm -f "$BIN/x0x-bootstrap"
    echo "Removed stale x0x-bootstrap (no longer needed since v0.8.0)"
fi

# Check PATH
case ":$PATH:" in
    *":$BIN:"*) ;;
    *)
        echo ""
        echo "  Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\""
        echo "  Add to ~/.bashrc or ~/.zshrc to make permanent."
        ;;
esac

# ── Seed the shared peer cache ──────────────────────────────────────────────

mkdir -p "$SHARED_DIR"
# The daemon seeds the cache on first run from compiled-in peers.
# We just ensure the shared directory exists so all instances can find it.

# ── Start daemon ────────────────────────────────────────────────────────────

echo ""
XOXD="$BIN/x0xd"
CMD="$XOXD"
if [ -n "$NAME" ]; then
    CMD="$XOXD --name $NAME"
fi

mkdir -p "$INSTANCE_DIR"
echo "Starting: $CMD"
nohup $CMD >> "$INSTANCE_DIR/x0xd.log" 2>&1 &
PID=$!

# Wait for port file
PORTFILE="$INSTANCE_DIR/api.port"
TRIES=0
while [ ! -f "$PORTFILE" ] && [ $TRIES -lt 30 ]; do
    sleep 1
    TRIES=$((TRIES + 1))
done

if [ ! -f "$PORTFILE" ]; then
    echo "Timeout waiting for daemon. Check: cat $INSTANCE_DIR/x0xd.log"
    exit 1
fi

API=$(cat "$PORTFILE")

# Wait for healthy
TRIES=0
while [ $TRIES -lt 15 ]; do
    if curl -sf "http://$API/health" >/dev/null 2>&1; then break; fi
    sleep 1
    TRIES=$((TRIES + 1))
done

HEALTH=$(curl -sf "http://$API/health" 2>/dev/null || echo '{"ok":false}')
AGENT=$(curl -sf "http://$API/agent" 2>/dev/null || echo '{}')

echo ""
echo "x0x is running"
echo "  API:    http://$API"
echo "  Health: $HEALTH"
echo "  Agent:  $AGENT"
echo "  Log:    $INSTANCE_DIR/x0xd.log"
echo "  PID:    $PID"

# ── Autostart on boot (optional) ────────────────────────────────────────────

if [ "$AUTOSTART" = true ]; then
    echo ""
    "$XOX" autostart
fi

# ── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "Try:  x0x gui                   Open the web GUI"
echo "      x0x autostart             Start on boot"
echo "      x0x autostart --remove    Remove autostart"
echo ""
echo "Docs: https://github.com/$REPO"
