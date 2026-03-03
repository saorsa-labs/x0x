#!/usr/bin/env bash
# x0x Installation Script (Unix/macOS/Linux)

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

REPO="saorsa-labs/x0x"
RELEASE_URL="https://github.com/$REPO/releases/latest/download"
VERSION="${X0X_VERSION:-0.2.0}"
INSTALL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/x0x"
BIN_DIR="$HOME/.local/bin"
INTERACTIVE=false

for arg in "$@"; do
    case "$arg" in
        --interactive)
            INTERACTIVE=true
            ;;
        *)
            printf '{"status":"error","error":"Unknown argument: %s","code":"invalid_argument"}\n' "$arg"
            exit 1
            ;;
    esac
done

json_escape() {
    local text="$1"
    text="${text//\\/\\\\}"
    text="${text//\"/\\\"}"
    text="${text//$'\n'/ }"
    printf '%s' "$text"
}

emit_json_error() {
    local code="$1"
    local message="$2"
    local exit_code="${3:-1}"
    local escaped
    escaped="$(json_escape "$message")"
    printf '{"status":"error","error":"%s","code":"%s"}\n' "$escaped" "$code"
    exit "$exit_code"
}

emit_json_already_installed() {
    local path="$1"
    local escaped
    escaped="$(json_escape "$path")"
    printf '{"status":"error","error":"x0xd already exists at install path","code":"already_installed","x0xd_path":"%s"}\n' "$escaped"
    exit 1
}

log_info() {
    if [ "$INTERACTIVE" = true ]; then
        echo -e "$1"
    else
        printf '%s\n' "$1" >&2
    fi
}

log_warn() {
    if [ "$INTERACTIVE" = true ]; then
        echo -e "${YELLOW}$1${NC}"
    else
        printf 'warning: %s\n' "$1" >&2
    fi
}

download_file() {
    local url="$1"
    local dest="$2"
    if command -v curl > /dev/null 2>&1; then
        if ! curl -sfL "$url" -o "$dest"; then
            emit_json_error "download_failed" "Failed to download $url"
        fi
    elif command -v wget > /dev/null 2>&1; then
        if ! wget -qO "$dest" "$url"; then
            emit_json_error "download_failed" "Failed to download $url"
        fi
    else
        emit_json_error "download_failed" "Neither curl nor wget found"
    fi
}

detect_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)
            case "$arch" in
                x86_64) printf '%s' "linux-x64-gnu" ;;
                aarch64) printf '%s' "linux-arm64-gnu" ;;
                *) printf '%s' "" ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                arm64) printf '%s' "macos-arm64" ;;
                x86_64) printf '%s' "macos-x64" ;;
                *) printf '%s' "" ;;
            esac
            ;;
        *)
            printf '%s' ""
            ;;
    esac
}

if [ "$INTERACTIVE" = true ]; then
    echo -e "${BLUE}x0x Installation Script${NC}"
    echo -e "${BLUE}========================${NC}"
    echo ""
fi

GPG_AVAILABLE=true
GPG_VERIFIED=false

if ! command -v gpg > /dev/null 2>&1; then
    GPG_AVAILABLE=false
    if [ "$INTERACTIVE" = true ]; then
        echo -e "${YELLOW}Warning: GPG not found. Signature verification will be skipped.${NC}"
        echo ""
        echo "To enable signature verification, install GPG:"
        echo "  macOS:  brew install gnupg"
        echo "  Ubuntu: sudo apt install gnupg"
        echo "  Fedora: sudo dnf install gnupg"
        echo ""
        read -p "Continue without verification? (y/N) " -n 1 -r
        echo
        if [[ ! ${REPLY:-} =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        log_warn "GPG not found; proceeding without signature verification"
    fi
fi

if ! mkdir -p "$INSTALL_DIR"; then
    emit_json_error "permission_denied" "Cannot create install directory $INSTALL_DIR"
fi

if ! cd "$INSTALL_DIR"; then
    emit_json_error "permission_denied" "Cannot access install directory $INSTALL_DIR"
fi

log_info "Downloading SKILL.md..."
download_file "$RELEASE_URL/SKILL.md" "SKILL.md"

if [ "$GPG_AVAILABLE" = true ]; then
    log_info "Downloading signature..."
    download_file "$RELEASE_URL/SKILL.md.sig" "SKILL.md.sig"
    download_file "$RELEASE_URL/SAORSA_PUBLIC_KEY.asc" "SAORSA_PUBLIC_KEY.asc"

    log_info "Importing Saorsa Labs public key..."
    if ! gpg --import SAORSA_PUBLIC_KEY.asc > /dev/null 2>&1; then
        if [ "$INTERACTIVE" = true ]; then
            echo -e "${RED}Failed to import GPG key${NC}"
            exit 1
        fi
        emit_json_error "gpg_verification_failed" "Failed to import GPG key"
    fi

    log_info "Verifying signature..."
    if gpg --verify SKILL.md.sig SKILL.md > /dev/null 2>&1; then
        GPG_VERIFIED=true
        if [ "$INTERACTIVE" = true ]; then
            echo -e "${GREEN}Signature verified${NC}"
        fi
    else
        if [ "$INTERACTIVE" = true ]; then
            echo -e "${RED}Signature verification failed${NC}"
            echo ""
            echo "This file may have been tampered with."
            read -p "Install anyway? (y/N) " -n 1 -r
            echo
            if [[ ! ${REPLY:-} =~ ^[Yy]$ ]]; then
                exit 1
            fi
        else
            emit_json_error "gpg_verification_failed" "GPG signature verification failed"
        fi
    fi
fi

log_info "Detecting platform..."
PLATFORM="$(detect_platform)"
if [ -z "$PLATFORM" ]; then
    if [ "$INTERACTIVE" = true ]; then
        log_warn "Unsupported platform; x0xd daemon installation skipped"
        PLATFORM=""
    else
        emit_json_error "unsupported_platform" "No x0xd binary available for this OS/arch"
    fi
fi

X0XD_PATH="$BIN_DIR/x0xd"
if [ -e "$X0XD_PATH" ] && [ "$INTERACTIVE" = false ]; then
    emit_json_already_installed "$X0XD_PATH"
fi

if [ -n "$PLATFORM" ]; then
    ARCHIVE="x0x-${PLATFORM}.tar.gz"
    TMPDIR="$(mktemp -d)"
    if [ -z "$TMPDIR" ]; then
        emit_json_error "permission_denied" "Could not create temporary directory"
    fi

    log_info "Downloading x0xd ($PLATFORM)..."
    download_file "$RELEASE_URL/$ARCHIVE" "$TMPDIR/$ARCHIVE"

    log_info "Extracting x0xd..."
    if ! tar -xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR" "x0x-${PLATFORM}/x0xd"; then
        rm -rf "$TMPDIR" >/dev/null 2>&1 || true
        emit_json_error "download_failed" "Downloaded archive is invalid or missing x0xd"
    fi

    if ! mkdir -p "$BIN_DIR"; then
        rm -rf "$TMPDIR" >/dev/null 2>&1 || true
        emit_json_error "permission_denied" "Cannot create binary directory $BIN_DIR"
    fi

    if ! mv "$TMPDIR/x0x-${PLATFORM}/x0xd" "$X0XD_PATH"; then
        rm -rf "$TMPDIR" >/dev/null 2>&1 || true
        emit_json_error "permission_denied" "Cannot write x0xd to $X0XD_PATH"
    fi

    if ! chmod +x "$X0XD_PATH"; then
        rm -rf "$TMPDIR" >/dev/null 2>&1 || true
        emit_json_error "permission_denied" "Cannot mark x0xd executable at $X0XD_PATH"
    fi

    rm -rf "$TMPDIR" >/dev/null 2>&1 || true
fi

if [ "$INTERACTIVE" = true ]; then
    echo ""
    echo -e "${GREEN}Installation complete${NC}"
    echo ""
    echo "SKILL.md installed to: $INSTALL_DIR/SKILL.md"
    if [ -n "$PLATFORM" ]; then
        echo "x0xd installed to:     $X0XD_PATH"
    fi
    echo ""
    echo "Next steps:"
    if [ -n "$PLATFORM" ]; then
        echo "  1. Run x0xd:"
        echo "       x0xd"
        echo "  2. Manage contacts:"
        echo "       curl http://127.0.0.1:12700/contacts"
        echo "  3. Review SKILL.md: cat $INSTALL_DIR/SKILL.md"
        echo ""
    else
        echo "  1. Review SKILL.md: cat $INSTALL_DIR/SKILL.md"
        echo ""
    fi
    echo "  4. Install SDK:"
    echo "     - Rust:       cargo add x0x"
    echo "     - TypeScript: npm install x0x"
    echo "     - Python:     pip install agent-x0x"
    echo ""
    echo "Learn more: https://github.com/$REPO"
    exit 0
fi

printf '{"status":"ok","x0xd_path":"%s","skill_path":"%s","gpg_verified":%s,"platform":"%s","version":"%s"}\n' \
    "$X0XD_PATH" "$INSTALL_DIR/SKILL.md" "$GPG_VERIFIED" "$PLATFORM" "$VERSION"
