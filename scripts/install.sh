#!/usr/bin/env bash
# x0x Installation Script (Unix/macOS/Linux)

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

REPO="saorsa-labs/x0x"
RELEASE_URL="https://github.com/$REPO/releases/latest/download"
INSTALL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/x0x"
BIN_DIR="$HOME/.local/bin"

echo -e "${BLUE}x0x Installation Script${NC}"
echo -e "${BLUE}========================${NC}"
echo ""

# Check if GPG is installed
if ! command -v gpg &> /dev/null; then
    echo -e "${YELLOW}⚠ Warning: GPG not found. Signature verification will be skipped.${NC}"
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
    GPG_AVAILABLE=false
else
    GPG_AVAILABLE=true
fi

# Create install directory
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "Downloading SKILL.md..."
if command -v curl &> /dev/null; then
    curl -sfL "$RELEASE_URL/SKILL.md" -o SKILL.md
elif command -v wget &> /dev/null; then
    wget -qO SKILL.md "$RELEASE_URL/SKILL.md"
else
    echo -e "${RED}✗ Error: Neither curl nor wget found${NC}"
    exit 1
fi

if [ "$GPG_AVAILABLE" = true ]; then
    echo "Downloading signature..."
    if command -v curl &> /dev/null; then
        curl -sfL "$RELEASE_URL/SKILL.md.sig" -o SKILL.md.sig
        curl -sfL "$RELEASE_URL/SAORSA_PUBLIC_KEY.asc" -o SAORSA_PUBLIC_KEY.asc
    else
        wget -qO SKILL.md.sig "$RELEASE_URL/SKILL.md.sig"
        wget -qO SAORSA_PUBLIC_KEY.asc "$RELEASE_URL/SAORSA_PUBLIC_KEY.asc"
    fi

    echo "Importing Saorsa Labs public key..."
    gpg --import SAORSA_PUBLIC_KEY.asc 2>&1 | grep -v "^gpg:" || true

    echo "Verifying signature..."
    if gpg --verify SKILL.md.sig SKILL.md 2>&1 | grep -q "Good signature"; then
        echo -e "${GREEN}✓ Signature verified${NC}"
    else
        echo -e "${RED}✗ Signature verification failed${NC}"
        echo ""
        echo "This file may have been tampered with."
        read -p "Install anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
fi

# ── x0xd daemon binary ────────────────────────────────────────────────────────

echo ""
echo "Detecting platform..."

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64)  PLATFORM="linux-x64-gnu" ;;
            aarch64) PLATFORM="linux-arm64-gnu" ;;
            *)
                echo -e "${YELLOW}⚠ Unsupported Linux architecture: $ARCH${NC}"
                echo "  x0xd daemon installation skipped."
                PLATFORM=""
                ;;
        esac
        ;;
    Darwin)
        case "$ARCH" in
            arm64)   PLATFORM="macos-arm64" ;;
            x86_64)  PLATFORM="macos-x64" ;;
            *)
                echo -e "${YELLOW}⚠ Unsupported macOS architecture: $ARCH${NC}"
                echo "  x0xd daemon installation skipped."
                PLATFORM=""
                ;;
        esac
        ;;
    *)
        echo -e "${YELLOW}⚠ Unsupported operating system: $OS${NC}"
        echo "  x0xd daemon installation is only supported on Linux and macOS."
        echo "  Skipping daemon installation."
        PLATFORM=""
        ;;
esac

if [ -n "$PLATFORM" ]; then
    ARCHIVE="x0x-${PLATFORM}.tar.gz"
    ARCHIVE_URL="$RELEASE_URL/$ARCHIVE"
    TMPDIR="$(mktemp -d)"

    echo "Downloading x0xd ($PLATFORM)..."
    if command -v curl &> /dev/null; then
        curl -sfL "$ARCHIVE_URL" -o "$TMPDIR/$ARCHIVE"
    else
        wget -qO "$TMPDIR/$ARCHIVE" "$ARCHIVE_URL"
    fi

    echo "Extracting x0xd..."
    tar -xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR" "x0x-${PLATFORM}/x0xd"

    mkdir -p "$BIN_DIR"
    mv "$TMPDIR/x0x-${PLATFORM}/x0xd" "$BIN_DIR/x0xd"
    chmod +x "$BIN_DIR/x0xd"

    rm -rf "$TMPDIR"

    echo -e "${GREEN}✓ x0xd installed to: $BIN_DIR/x0xd${NC}"

    # Warn if ~/.local/bin is not in PATH
    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *)
            echo ""
            echo -e "${YELLOW}⚠ $BIN_DIR is not in your PATH.${NC}"
            echo "  Add it by appending one of the following to your shell profile:"
            echo ""
            echo "    # bash (~/.bashrc or ~/.bash_profile)"
            echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
            echo ""
            echo "    # zsh (~/.zshrc)"
            echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
            echo ""
            echo "  Then reload your shell: source ~/.bashrc  (or ~/.zshrc)"
            ;;
    esac
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}✓ Installation complete${NC}"
echo ""
echo "SKILL.md installed to: $INSTALL_DIR/SKILL.md"
if [ -n "$PLATFORM" ]; then
    echo "x0xd installed to:     $BIN_DIR/x0xd"
fi
echo ""
echo "Next steps:"
if [ -n "$PLATFORM" ]; then
    echo "  1. Run x0xd:"
    echo "       x0xd"
    echo "     (x0xd creates your identity on first run and joins the global network)"
    echo "     (If x0xd is not found, ensure $BIN_DIR is in your PATH — see above)"
    echo ""
    echo "  2. Manage contacts:"
    echo "       curl http://127.0.0.1:12700/contacts"
    echo ""
    echo "  3. Review SKILL.md: cat $INSTALL_DIR/SKILL.md"
    echo ""
    echo "  4. Install SDK:"
else
    echo "  1. Review SKILL.md: cat $INSTALL_DIR/SKILL.md"
    echo ""
    echo "  2. Install SDK:"
fi
echo "     - Rust:       cargo add x0x"
echo "     - TypeScript: npm install x0x"
echo "     - Python:     pip install agent-x0x"
echo ""
echo "Learn more: https://github.com/$REPO"
