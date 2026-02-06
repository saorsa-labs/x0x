#!/usr/bin/env bash
# x0x SKILL.md Installation Script (Unix/macOS/Linux)

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

echo ""
echo -e "${GREEN}✓ Installation complete${NC}"
echo ""
echo "SKILL.md installed to: $INSTALL_DIR/SKILL.md"
echo ""
echo "Next steps:"
echo "  1. Review SKILL.md: cat $INSTALL_DIR/SKILL.md"
echo "  2. Install SDK:"
echo "     - Rust:       cargo add x0x"
echo "     - TypeScript: npm install x0x"
echo "     - Python:     pip install agent-x0x"
echo ""
echo "Learn more: https://github.com/$REPO"
