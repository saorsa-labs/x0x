#!/usr/bin/env sh
# x0x installer — installs the x0x agent network.
#
# Usage:
#   curl -sfL https://x0x.md | sh                    # install + start
#   curl -sfL https://x0x.md | sh -s -- --autostart   # install + start + autostart on boot
#   bash install.sh --name alice                      # named instance
#   sh install.sh --verify-only                       # download + verify, install nothing
#
# What it does:
#   1. Detects platform (Linux/macOS, x64/arm64)
#   2. Downloads latest release from GitHub
#   3. Verifies its SHA-256 and, when gpg is present, its GPG signature against
#      the pinned Saorsa Labs release key (fails closed on any mismatch)
#   4. Stops any running x0xd instance
#   5. Installs x0xd (daemon) + x0x (CLI) to ~/.local/bin
#   6. Starts the daemon
#   7. Optionally configures autostart on boot (--autostart)
#
# Requirements: curl or wget, tar, sh, sha256sum or shasum. gpg is strongly
# recommended; without it only the checksum is verified (with a warning).
# No root/sudo required (except --autostart on Linux uses systemd).

set -e

REPO="saorsa-labs/x0x"
URL="https://github.com/$REPO/releases/latest/download"
BIN="$HOME/.local/bin"
NAME=""
NAME_SET=false
AUTOSTART=false
VERIFY_ONLY=false
# Saorsa Labs release signing key (primary fingerprint of SAORSA_PUBLIC_KEY.asc).
# Rotate only with a reviewed installer change.
TRUSTED_FPR="CEB3506E7DCB8A2DD2D679E8EDDA4827D89C0F29"

# ── Parse args ────────────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --autostart)
            AUTOSTART=true
            shift
            ;;
        --verify-only)
            VERIFY_ONLY=true
            shift
            ;;
        --name)
            shift
            NAME="${1-}"
            NAME_SET=true
            if [ $# -gt 0 ]; then
                shift
            fi
            ;;
        --name=*)
            NAME="${1#*=}"
            NAME_SET=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

if [ "$NAME_SET" = true ]; then
    if [ -z "$NAME" ] || [ ${#NAME} -gt 64 ]; then
        echo "Error: instance name must be 1-64 characters" >&2
        exit 1
    fi
    case "$NAME" in
        [abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]*)
            ;;
        *)
            echo "Error: instance name must start with alphanumeric and contain only alphanumeric or hyphens" >&2
            exit 1
            ;;
    esac
    case "$NAME" in
        *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-]*)
            echo "Error: instance name must start with alphanumeric and contain only alphanumeric or hyphens" >&2
            exit 1
            ;;
    esac
fi

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

# ── Download and verify ─────────────────────────────────────────────────────

echo "x0x installer"
echo "  Platform: $PLATFORM"
echo "  Install:  $BIN"

ARCHIVE="x0x-${PLATFORM}.tar.gz"
TMP=$(mktemp -d)
NEW_XOXD=""
NEW_XOX=""
# $TMP also holds the throwaway GnuPG home, so this removes it too.
trap 'rm -rf "$TMP"; rm -f "$NEW_XOXD" "$NEW_XOX"' EXIT

if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER="wget"
else
    echo "Error: need curl or wget"; exit 1
fi

fetch() {
    if [ "$DOWNLOADER" = "curl" ]; then
        curl -sfL "$1" -o "$2" || { echo "Error: download failed: $1" >&2; exit 1; }
    else
        wget -qO "$2" "$1" || { echo "Error: download failed: $1" >&2; exit 1; }
    fi
}

verify_failed() {
    echo "" >&2
    echo "Error: VERIFICATION FAILED for $ARCHIVE: $1" >&2
    echo "The download may have been tampered with. Nothing was installed." >&2
    exit 1
}

echo "Downloading..."
fetch "$URL/$ARCHIVE" "$TMP/$ARCHIVE"
fetch "$URL/$ARCHIVE.sha256" "$TMP/$ARCHIVE.sha256"

# SHA-256: always required.
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA=$(sha256sum "$TMP/$ARCHIVE" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA=$(shasum -a 256 "$TMP/$ARCHIVE" | awk '{print $1}')
else
    echo "Error: need sha256sum or shasum to verify the download" >&2
    exit 1
fi
EXPECTED_SHA=$(awk 'NR == 1 {print tolower($1)}' "$TMP/$ARCHIVE.sha256")
case "$EXPECTED_SHA" in
    *[!0-9a-f]*|"") verify_failed "malformed $ARCHIVE.sha256" ;;
esac
[ ${#EXPECTED_SHA} -eq 64 ] || verify_failed "malformed $ARCHIVE.sha256"
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    verify_failed "SHA-256 mismatch (expected $EXPECTED_SHA, got $ACTUAL_SHA)"
fi
echo "  SHA-256 verified ($ACTUAL_SHA)"

# GPG: required when gpg is present. Everything happens in a throwaway GnuPG
# home under $TMP, so the user's own keyring is never read or written.
if command -v gpg >/dev/null 2>&1; then
    fetch "$URL/$ARCHIVE.asc" "$TMP/$ARCHIVE.asc"
    fetch "$URL/SAORSA_PUBLIC_KEY.asc" "$TMP/SAORSA_PUBLIC_KEY.asc"
    GNUPG_TMP="$TMP/gnupg"
    mkdir -m 700 "$GNUPG_TMP"

    # The downloaded key must be the pinned one before we trust anything it signs.
    KEY_FPRS=$(gpg --homedir "$GNUPG_TMP" --batch --with-colons --show-keys \
        --fingerprint "$TMP/SAORSA_PUBLIC_KEY.asc" 2>/dev/null \
        | awk -F: '$1 == "fpr" {print toupper($10)}')
    if ! printf '%s\n' "$KEY_FPRS" | grep -qx "$TRUSTED_FPR"; then
        verify_failed "SAORSA_PUBLIC_KEY.asc is not the pinned release key ($TRUSTED_FPR)"
    fi
    gpg --homedir "$GNUPG_TMP" --batch --quiet --import "$TMP/SAORSA_PUBLIC_KEY.asc" \
        >/dev/null 2>&1 || verify_failed "gpg could not import the release key"

    # Accept only a VALIDSIG whose signing key or primary key is the pinned one.
    GPG_STATUS=$(gpg --homedir "$GNUPG_TMP" --batch --status-fd 1 \
        --verify "$TMP/$ARCHIVE.asc" "$TMP/$ARCHIVE" 2>/dev/null) \
        || verify_failed "GPG signature is not valid"
    SIGNERS=$(printf '%s\n' "$GPG_STATUS" \
        | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" {print toupper($3); if (NF >= 12) print toupper($12)}')
    if ! printf '%s\n' "$SIGNERS" | grep -qx "$TRUSTED_FPR"; then
        verify_failed "GPG signature was not made by the pinned release key ($TRUSTED_FPR)"
    fi
    if command -v gpgconf >/dev/null 2>&1; then
        gpgconf --homedir "$GNUPG_TMP" --kill all >/dev/null 2>&1 || true
    fi
    echo "  GPG signature verified ($TRUSTED_FPR)"
else
    echo "" >&2
    echo "################################################################" >&2
    echo "# WARNING: gpg NOT FOUND - the GPG signature was NOT verified. #" >&2
    echo "# Only the SHA-256 checksum was checked, and that checksum was #" >&2
    echo "# downloaded from the same place as the archive. Install gpg   #" >&2
    echo "# and re-run to verify this release was signed by Saorsa Labs. #" >&2
    echo "################################################################" >&2
    echo "" >&2
fi

if [ "$VERIFY_ONLY" = true ]; then
    echo "Verify-only: $ARCHIVE verified; nothing installed."
    exit 0
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

# ── Install ─────────────────────────────────────────────────────────────────

http_get() {
    if [ "$DOWNLOADER" = "curl" ]; then
        curl -sf "$1"
    else
        wget -qO- "$1"
    fi
}

# GET with the daemon's bearer token (every route except /health needs it).
http_get_auth() {
    if [ "$DOWNLOADER" = "curl" ]; then
        curl -sf -H "Authorization: Bearer $2" "$1"
    else
        wget -qO- --header="Authorization: Bearer $2" "$1"
    fi
}

mkdir -p "$BIN"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP"

for bin in x0xd x0x; do
    SRC="$TMP/x0x-${PLATFORM}/$bin"
    if [ ! -f "$SRC" ] || [ -L "$SRC" ] || [ ! -x "$SRC" ]; then
        echo "Error: release archive missing executable $bin" >&2
        exit 1
    fi
done

NEW_XOXD="$BIN/x0xd.new.$$"
NEW_XOX="$BIN/x0x.new.$$"
cp "$TMP/x0x-${PLATFORM}/x0xd" "$NEW_XOXD"
cp "$TMP/x0x-${PLATFORM}/x0x" "$NEW_XOX"
chmod +x "$NEW_XOXD" "$NEW_XOX"
mv "$NEW_XOXD" "$BIN/x0xd"
mv "$NEW_XOX" "$BIN/x0x"
INSTALLED=" x0xd x0x"
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

mkdir -p "$INSTANCE_DIR"
if [ -n "$NAME" ]; then
    echo "Starting: $XOXD --name $NAME"
    nohup "$XOXD" --name "$NAME" >> "$INSTANCE_DIR/x0xd.log" 2>&1 &
else
    echo "Starting: $XOXD"
    nohup "$XOXD" >> "$INSTANCE_DIR/x0xd.log" 2>&1 &
fi
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
HEALTH_OK=false
while [ $TRIES -lt 15 ]; do
    if HEALTH=$(http_get "http://$API/health" 2>/dev/null); then
        HEALTH_OK=true
        break
    fi
    sleep 1
    TRIES=$((TRIES + 1))
done

if [ "$HEALTH_OK" != true ]; then
    echo "Timeout waiting for healthy daemon. Check: cat $INSTANCE_DIR/x0xd.log"
    exit 1
fi

TOKEN=$(cat "$INSTANCE_DIR/api-token" 2>/dev/null || true)
AGENT=$(http_get_auth "http://$API/agent" "$TOKEN" 2>/dev/null || echo '{}')

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
    if [ -n "$NAME" ]; then
        "$XOX" --name "$NAME" autostart
    else
        "$XOX" autostart
    fi
fi

# ── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "Try:  x0x gui                   Open the web GUI"
echo "      x0x autostart             Start on boot"
echo "      x0x autostart --remove    Remove autostart"
echo ""
echo "Docs: https://github.com/$REPO"
