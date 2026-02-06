#!/bin/bash
#
# verify-skill.sh - Verify GPG signature on SKILL.md
#
# Downloads SKILL.md and SKILL.md.sig from GitHub release,
# fetches Saorsa Labs public key, and verifies the signature.
#
# Usage:
#   ./scripts/verify-skill.sh [--version <VERSION>] [--offline]
#

set -euo pipefail

# Configuration
REPO="saorsa-labs/x0x"
GITHUB_API="https://api.github.com/repos/${REPO}/releases"
KEYSERVER="keys.openpgp.org"
SAORSA_GPG_KEY_ID="david@saorsalabs.com"

# Script variables
OFFLINE_MODE=0
VERSION=""
SKILL_FILE="SKILL.md"
SIG_FILE="SKILL.md.sig"
PUBKEY_FILE="SAORSA_PUBLIC_KEY.asc"
TEMP_DIR=""

# Cleanup on exit
cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

# Print messages
info() { echo "[*] $*"; }
success() { echo "✓ $*"; }
error() { echo "✗ Error: $*" >&2; }

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version) VERSION="$2"; shift 2 ;;
            --offline) OFFLINE_MODE=1; shift ;;
            --help) show_help; exit 0 ;;
            *) error "Unknown option: $1"; exit 1 ;;
        esac
    done
}

# Check required tools
check_tools() {
    info "Checking required tools..."
    command -v gpg &> /dev/null || { error "gpg not found"; exit 1; }
    if [ "$OFFLINE_MODE" -eq 0 ]; then
        command -v curl &> /dev/null || command -v wget &> /dev/null || { error "curl or wget not found"; exit 1; }
    fi
    success "All required tools found"
}

# Download file
download_file() {
    local url="$1" output="$2"
    info "Downloading: $(basename "$output")"
    
    if command -v curl &> /dev/null; then
        curl --silent --show-error --location -o "$output" "$url" || { error "Failed to download: $url"; return 1; }
    else
        wget --quiet -O "$output" "$url" || { error "Failed to download: $url"; return 1; }
    fi
    
    success "Downloaded: $(basename "$output")"
}

# Get latest release
get_latest_release() {
    info "Fetching latest release from GitHub..."
    VERSION=$(curl --silent "$GITHUB_API/latest" | grep -o '"tag_name": "[^"]*' | cut -d'"' -f4 | head -1)
    [ -n "$VERSION" ] || { error "Could not determine latest release"; return 1; }
    info "Latest release: $VERSION"
}

# Download release files
download_release() {
    TEMP_DIR=$(mktemp -d)
    local release_url="https://github.com/${REPO}/releases/download/${VERSION}"
    
    download_file "${release_url}/SKILL.md" "${TEMP_DIR}/${SKILL_FILE}" || return 1
    download_file "${release_url}/SKILL.md.sig" "${TEMP_DIR}/${SIG_FILE}" || return 1
    download_file "${release_url}/SAORSA_PUBLIC_KEY.asc" "${TEMP_DIR}/${PUBKEY_FILE}" || return 1
    
    SKILL_FILE="${TEMP_DIR}/${SKILL_FILE}"
    SIG_FILE="${TEMP_DIR}/${SIG_FILE}"
    PUBKEY_FILE="${TEMP_DIR}/${PUBKEY_FILE}"
}

# Fetch public key from keyserver
fetch_public_key() {
    if [ ! -f "$PUBKEY_FILE" ]; then
        info "Importing public key from keyserver..."
        gpg --keyserver "$KEYSERVER" --recv-keys "$SAORSA_GPG_KEY_ID" 2>&1 | grep -q imported || { error "Failed to import key"; return 1; }
        success "Public key imported from $KEYSERVER"
    else
        info "Importing public key from file..."
        gpg --import "$PUBKEY_FILE" 2>&1 | grep -q imported || { error "Failed to import key"; return 1; }
        success "Public key imported"
    fi
}

# Verify signature
verify_signature() {
    info "Verifying signature..."
    [ -f "$SKILL_FILE" ] || { error "SKILL.md not found"; return 1; }
    [ -f "$SIG_FILE" ] || { error "Signature file not found"; return 1; }

    # Use exit code for verification (locale-independent)
    if gpg --verify "$SIG_FILE" "$SKILL_FILE" 2>/dev/null; then
        success "✓ Signature is valid"
        return 0
    else
        error "✗ Signature verification failed"
        return 1
    fi
}

# Main workflow
main() {
    parse_args "$@"
    echo "=== SKILL.md GPG Signature Verification ==="
    echo ""
    
    check_tools
    
    if [ -z "$VERSION" ] && [ "$OFFLINE_MODE" -eq 0 ]; then
        get_latest_release || exit 1
    fi
    
    if [ "$OFFLINE_MODE" -eq 0 ]; then
        [ -n "$VERSION" ] || { error "No version specified"; exit 1; }
        download_release || exit 1
    else
        for f in "$SKILL_FILE" "$SIG_FILE" "$PUBKEY_FILE"; do
            [ -f "$f" ] || { error "File not found: $f"; exit 1; }
        done
    fi
    
    echo ""
    fetch_public_key || exit 1
    echo ""
    verify_signature || exit 1
    
    echo ""
    echo "=== Signature Details ==="
    LANG=C gpg --verify "$SIG_FILE" "$SKILL_FILE" 2>&1 | grep -E "(Good signature|Primary key fingerprint)" || true
    echo ""
    echo "✓ Verification successful!"
    exit 0
}

main "$@"
