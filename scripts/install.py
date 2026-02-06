#!/usr/bin/env python3
"""
x0x SKILL.md Installation Script (Cross-Platform Python)

This script works on any platform with Python 3.6+.
"""

import os
import sys
import subprocess
import urllib.request
from pathlib import Path

# ANSI color codes (work on most terminals)
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'  # No Color

REPO = "saorsa-labs/x0x"
RELEASE_URL = f"https://github.com/{REPO}/releases/latest/download"

# Platform-specific install directory
if sys.platform == "win32":
    INSTALL_DIR = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))) / "x0x"
else:
    xdg_data = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    INSTALL_DIR = Path(xdg_data) / "x0x"


def print_color(text, color=NC):
    """Print colored text (may not work on all Windows terminals)."""
    print(f"{color}{text}{NC}")


def check_gpg():
    """Check if GPG is available."""
    try:
        subprocess.run(["gpg", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def download_file(url, dest):
    """Download a file from URL to destination."""
    print(f"Downloading {dest.name}...")
    try:
        urllib.request.urlretrieve(url, dest)
    except Exception as e:
        print_color(f"✗ Error downloading {url}: {e}", RED)
        sys.exit(1)


def verify_signature(skill_file, sig_file, key_file):
    """Verify GPG signature."""
    print("Importing Saorsa Labs public key...")
    try:
        subprocess.run(
            ["gpg", "--import", str(key_file)],
            capture_output=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print_color(f"✗ Failed to import key: {e}", RED)
        return False
    
    print("Verifying signature...")
    try:
        result = subprocess.run(
            ["gpg", "--verify", str(sig_file), str(skill_file)],
            capture_output=True,
            text=True
        )
        if "Good signature" in result.stderr:
            print_color("✓ Signature verified", GREEN)
            return True
        else:
            print_color("✗ Signature verification failed", RED)
            return False
    except subprocess.CalledProcessError:
        print_color("✗ Signature verification failed", RED)
        return False


def main():
    print_color("x0x Installation Script", BLUE)
    print_color("========================", BLUE)
    print()
    
    # Check GPG
    gpg_available = check_gpg()
    if not gpg_available:
        print_color("⚠ Warning: GPG not found. Signature verification will be skipped.", YELLOW)
        print()
        print("To enable signature verification, install GPG:")
        print("  Windows: https://gnupg.org/download/")
        print("  macOS:   brew install gnupg")
        print("  Linux:   apt/dnf install gnupg")
        print()
        response = input("Continue without verification? (y/N) ").strip().lower()
        if response != "y":
            sys.exit(1)
    
    # Create install directory
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    os.chdir(INSTALL_DIR)
    
    # Download SKILL.md
    skill_file = INSTALL_DIR / "SKILL.md"
    download_file(f"{RELEASE_URL}/SKILL.md", skill_file)
    
    # Download and verify signature if GPG available
    if gpg_available:
        sig_file = INSTALL_DIR / "SKILL.md.sig"
        key_file = INSTALL_DIR / "SAORSA_PUBLIC_KEY.asc"
        
        download_file(f"{RELEASE_URL}/SKILL.md.sig", sig_file)
        download_file(f"{RELEASE_URL}/SAORSA_PUBLIC_KEY.asc", key_file)
        
        if not verify_signature(skill_file, sig_file, key_file):
            print()
            print("This file may have been tampered with.")
            response = input("Install anyway? (y/N) ").strip().lower()
            if response != "y":
                sys.exit(1)
    
    print()
    print_color("✓ Installation complete", GREEN)
    print()
    print(f"SKILL.md installed to: {INSTALL_DIR / 'SKILL.md'}")
    print()
    print("Next steps:")
    print("  1. Review SKILL.md: cat", str(INSTALL_DIR / "SKILL.md"))
    print("  2. Install SDK:")
    print("     - Rust:       cargo add x0x")
    print("     - TypeScript: npm install x0x")
    print("     - Python:     pip install agent-x0x")
    print()
    print(f"Learn more: https://github.com/{REPO}")


if __name__ == "__main__":
    main()
