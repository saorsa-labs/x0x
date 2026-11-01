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
#   3. Verifies its SHA-256, the sidecar checksum and the signed ML-DSA-65
#      release manifest, whose version and channel must match the resolved
#      release tag (through an installed x0x when available, else the
#      release's own binary — the updater's verify path — before the
#      archive is unpacked), and, when gpg is present, its GPG signature
#      against the pinned Saorsa Labs release key (fails closed on any
#      mismatch)
#   4. Stops any running x0xd instance
#   5. Installs x0xd (daemon) + x0x (CLI) to ~/.local/bin
#   6. Starts the daemon
#   7. Optionally configures autostart on boot (--autostart)
#
# Requirements: curl or wget, tar, gzip (GNU tar execs it for .tar.gz), sh,
# sha256sum or shasum. gpg is strongly
# recommended; without it the checksum and the signed ML-DSA manifest are
# verified but not the independent GPG signature (with a warning).
# No root/sudo required (except --autostart on Linux uses systemd).

set -e

REPO="saorsa-labs/x0x"
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
TARGET_TRIPLE=""
case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64)  PLATFORM="linux-x64-gnu"; TARGET_TRIPLE="x86_64-unknown-linux-gnu" ;;
            aarch64) PLATFORM="linux-arm64-gnu"; TARGET_TRIPLE="aarch64-unknown-linux-gnu" ;;
            *) echo "Unsupported: $OS $ARCH"; exit 1 ;;
        esac ;;
    Darwin)
        case "$ARCH" in
            arm64)  PLATFORM="macos-arm64"; TARGET_TRIPLE="aarch64-apple-darwin" ;;
            x86_64) PLATFORM="macos-x64"; TARGET_TRIPLE="x86_64-apple-darwin" ;;
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

# Resolve the latest release tag first, through the same API the updater
# uses, and download every file from that tag. This keeps the tag and the
# assets from disagreeing when a release is published mid-install, and the
# manifest's version and channel must match the tag below, so a manifest
# from one release cannot be served for another. The tag comes from an
# unauthenticated API, so this is not downgrade protection: the updater's
# newer-version and manifest-age checks (src/upgrade/monitor.rs) are what
# refuse an older release, and this installer does not replicate them.
echo "Resolving the latest release..."
fetch "https://api.github.com/repos/$REPO/releases/latest" "$TMP/latest.json"
TAG=$(tr -d '\n\r' < "$TMP/latest.json" | awk '{
    if (match($0, /"tag_name": *"[^"]*"/)) {
        tag = substr($0, RSTART, RLENGTH)
        sub(/"tag_name": *"/, "", tag)
        sub(/"$/, "", tag)
        print tag
        exit
    }
}')
case "$TAG" in
    v?*) ;;
    *) verify_failed "could not resolve the latest release tag" ;;
esac
URL="https://github.com/$REPO/releases/download/$TAG"

echo "Downloading $TAG..."
fetch "$URL/$ARCHIVE" "$TMP/$ARCHIVE"
fetch "$URL/$ARCHIVE.sha256" "$TMP/$ARCHIVE.sha256"
fetch "$URL/release-manifest.json" "$TMP/release-manifest.json"
fetch "$URL/release-manifest.json.sig" "$TMP/release-manifest.json.sig"

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
    echo "# The checksum and the ML-DSA manifest were checked. With      #" >&2
    echo "# no installed post-v0.46.5 x0x, the manifest is checked by    #" >&2
    echo "# the downloaded binary itself, not by an independent key.     #" >&2
    echo "# Install gpg and re-run for a check that does not depend      #" >&2
    echo "# on this download.                                            #" >&2
    echo "################################################################" >&2
    echo "" >&2
fi

# ── Signed release manifest (ML-DSA-65, as the updater checks it) ───────────
#
# The updater refuses a release whose manifest signature fails against the
# release key compiled into the binary (src/upgrade/signature.rs). This
# installer reuses that verify path instead of adding a second
# implementation. Four steps, in this order:
#
#   1. Bind: the manifest's version and channel must match the resolved
#      release tag (stable, non-prerelease, same version), before any of
#      the archive's bytes run. A genuinely-signed manifest for a
#      different release is refused. The stable, non-prerelease shape is
#      the updater's rule (src/upgrade/monitor.rs); matching the tag is
#      this installer's addition.
#   2. Bind: the manifest's archive_sha256 entry for this platform must
#      name the downloaded archive, still before extraction.
#   3. Sign: an already-installed x0x — its key was trusted by an earlier
#      install — runs the inert --verify-release-manifest probe
#      (src/upgrade/verification_probe.rs), which reads only the two
#      downloaded files, and this runs before the archive is unpacked at
#      all. The bound hash and the verified signature therefore always
#      apply to the same bytes.
#   4. Only then is the archive unpacked, into a fresh subfolder, so its
#      entries can never replace the manifest and signature that were
#      bound and checked. On a first install, or when the installed x0x
#      predates v0.46.5 (exit 2 on the probe argument), the release's own
#      x0x from that subfolder does the check instead — a stated
#      self-attest limit; the pinned GPG signature stays the independent
#      anchor there.
#
# A missing manifest or signature, a bad signature, a version or channel
# that differs from the release tag, or a hash that differs from the
# manifest entry stops the install before anything is installed.
# Releases before v0.46.5 predate the probe in the release binaries and no
# longer install.

# The version and channel come off the raw bytes with the same whitespace-
# tolerant match the hash binding below uses; the probe has not run yet.
MANIFEST_VERSION=$(tr -d '\n\r' < "$TMP/release-manifest.json" | awk '{
    if (match($0, /"version": *"[^"]*"/)) {
        field = substr($0, RSTART, RLENGTH)
        sub(/"version": *"/, "", field)
        sub(/"$/, "", field)
        print field
        exit
    }
}')
MANIFEST_CHANNEL=$(tr -d '\n\r' < "$TMP/release-manifest.json" | awk '{
    if (match($0, /"channel": *"[^"]*"/)) {
        field = substr($0, RSTART, RLENGTH)
        sub(/"channel": *"/, "", field)
        sub(/"$/, "", field)
        print field
        exit
    }
}')
if [ -z "$MANIFEST_VERSION" ] || [ -z "$MANIFEST_CHANNEL" ]; then
    verify_failed "manifest is missing its version or channel field"
fi
case "$MANIFEST_VERSION" in
    *-*) verify_failed "manifest version $MANIFEST_VERSION is a prerelease; the updater refuses non-stable manifests" ;;
esac
if [ "$MANIFEST_CHANNEL" != "stable" ]; then
    verify_failed "manifest channel '$MANIFEST_CHANNEL' is not stable; the updater refuses non-stable manifests"
fi
if [ "$MANIFEST_VERSION" != "${TAG#v}" ]; then
    verify_failed "manifest version $MANIFEST_VERSION ($MANIFEST_CHANNEL) does not match the resolved release tag $TAG"
fi
echo "  Manifest version $MANIFEST_VERSION ($MANIFEST_CHANNEL) matches $TAG"

# The manifest's archive_sha256 must name this archive before extraction:
# this refuses a swapped archive without executing any of its content. The
# release pipeline emits pretty-printed JSON with a stable field order
# (target, archive_url, archive_sha256); newlines are stripped so the same
# match works on a compact manifest.
MANIFEST_SHA=$(tr -d '\n\r' < "$TMP/release-manifest.json" | awk -v t="$TARGET_TRIPLE" '{
    if (match($0, "\"target\": *\"" t "\"[^}]*\"archive_sha256\": *\"[0-9a-fA-F]+\"")) {
        asset = substr($0, RSTART, RLENGTH)
        if (match(asset, /"archive_sha256": *"[0-9a-fA-F]+"/)) {
            field = substr(asset, RSTART, RLENGTH)
            sub(/"archive_sha256": *"/, "", field)
            sub(/"$/, "", field)
            print tolower(field)
            exit
        }
    }
}')
case "$MANIFEST_SHA" in
    *[!0-9a-f]*|"")
        verify_failed "manifest has no archive_sha256 entry for $TARGET_TRIPLE"
        ;;
esac
[ ${#MANIFEST_SHA} -eq 64 ] || verify_failed "malformed archive_sha256 entry for $TARGET_TRIPLE"
if [ "$MANIFEST_SHA" != "$ACTUAL_SHA" ]; then
    verify_failed "archive SHA-256 does not match the manifest entry for $TARGET_TRIPLE (expected $MANIFEST_SHA, got $ACTUAL_SHA)"
fi
echo "  Archive hash matches the manifest entry ($TARGET_TRIPLE)"

# Unpack into a fresh subfolder, never $TMP itself: a crafted archive
# carrying its own release-manifest.json and .sig must not be able to
# overwrite the files the binding and the signature check read. mkdir
# without -p is the freshness guard; a symlinked top-level folder in the
# archive is refused before anything under it is used.
EXTRACT="$TMP/extract"
unpack_release() {
    mkdir "$EXTRACT" || verify_failed "could not create the unpack folder"
    tar -xzf "$TMP/$ARCHIVE" -C "$EXTRACT" || verify_failed "could not unpack $ARCHIVE"
    if [ -L "$EXTRACT/x0x-${PLATFORM}" ] || [ ! -d "$EXTRACT/x0x-${PLATFORM}" ]; then
        echo "Error: release archive missing directory x0x-${PLATFORM}" >&2
        exit 1
    fi
}

# Prefer an already-installed x0x as the verifier: its key was trusted by an
# earlier install, so the check does not depend on this download. The probe
# runs before the archive is unpacked, and the manifest and signature it
# reads are the downloaded files, which no archive byte has touched.
# Installed binaries from v0.46.5 know --verify-release-manifest and exit 0
# (valid) or 1 (invalid); a pre-probe installed binary rejects the unknown
# argument with exit code 2, and first installs have no binary yet, so both
# fall back to the release's own x0x, unpacked into the fresh subfolder.
# Limit, stated plainly: on those fallback paths the manifest is checked by
# the downloaded binary itself, so an attacker controlling the whole origin
# could self-attest; the pinned GPG signature stays the independent check
# there. This is the updater's verify path, so --verify-only also executes
# the release binary on a fallback.
MANIFEST="$TMP/release-manifest.json"
MANIFEST_SIG="$TMP/release-manifest.json.sig"
VERIFY_BIN=""
PROBE_RC=0
if [ -x "$BIN/x0x" ]; then
    "$BIN/x0x" --verify-release-manifest "$MANIFEST" "$MANIFEST_SIG" >/dev/null 2>&1 || PROBE_RC=$?
    if [ "$PROBE_RC" -ne 2 ]; then
        VERIFY_BIN="$BIN/x0x"
    fi
fi
if [ -z "$VERIFY_BIN" ]; then
    if [ -x "$BIN/x0x" ]; then
        echo "" >&2
        echo "Warning: the installed x0x predates v0.46.5 and cannot check the" >&2
        echo "manifest, so the downloaded binary verifies its own release. The" >&2
        echo "pinned GPG signature stays the independent check for this install." >&2
    fi
    unpack_release
    PROBE="$EXTRACT/x0x-${PLATFORM}/x0x"
    if [ ! -f "$PROBE" ] || [ -L "$PROBE" ] || [ ! -x "$PROBE" ]; then
        echo "Error: release archive missing executable x0x" >&2
        exit 1
    fi
    VERIFY_BIN="$PROBE"
    PROBE_RC=0
    "$VERIFY_BIN" --verify-release-manifest "$MANIFEST" "$MANIFEST_SIG" || PROBE_RC=$?
fi
if [ "$PROBE_RC" -eq 126 ] || [ "$PROBE_RC" -eq 127 ]; then
    echo "Error: cannot execute $VERIFY_BIN to verify the release (noexec mount or bad interpreter?); nothing installed." >&2
    if [ "$VERIFY_BIN" = "$BIN/x0x" ]; then
        echo "The installed x0x is unusable. Remove $BIN/x0x and re-run to repair the install." >&2
    fi
    exit 1
fi
if [ "$PROBE_RC" -ge 128 ]; then
    echo "Error: the verifier $VERIFY_BIN was killed by signal $((PROBE_RC - 128)); nothing installed." >&2
    if [ "$VERIFY_BIN" = "$BIN/x0x" ]; then
        echo "The installed x0x did not survive its own verification run (wrong architecture, bad code signature). Remove $BIN/x0x and re-run to repair the install." >&2
    fi
    exit 1
fi
if [ "$PROBE_RC" -ne 0 ]; then
    verify_failed "release-manifest.json failed ML-DSA signature verification"
fi
if [ "$VERIFY_BIN" = "$BIN/x0x" ]; then
    echo "  ML-DSA-65 manifest signature verified (by the installed x0x)"
else
    echo "  ML-DSA-65 manifest signature verified"
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

# The installed-verifier path skips the earlier unpack; extract now.
if [ ! -d "$EXTRACT" ]; then
    unpack_release
fi

for bin in x0xd x0x; do
    SRC="$EXTRACT/x0x-${PLATFORM}/$bin"
    if [ ! -f "$SRC" ] || [ -L "$SRC" ] || [ ! -x "$SRC" ]; then
        echo "Error: release archive missing executable $bin" >&2
        exit 1
    fi
done

NEW_XOXD="$BIN/x0xd.new.$$"
NEW_XOX="$BIN/x0x.new.$$"
cp "$EXTRACT/x0x-${PLATFORM}/x0xd" "$NEW_XOXD"
cp "$EXTRACT/x0x-${PLATFORM}/x0x" "$NEW_XOX"
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
