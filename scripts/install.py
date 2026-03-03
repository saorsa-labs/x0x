#!/usr/bin/env python3
"""
x0x Installation Script (Cross-Platform Python)

Downloads and installs:
  - SKILL.md (with optional GPG verification)
  - x0xd daemon binary (platform-detected)

Works on any platform with Python 3.6+.
"""

import os
import sys
import platform
import subprocess
import tarfile
import tempfile
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

# Platform-specific install directory for SKILL.md
if sys.platform == "win32":
    INSTALL_DIR = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))) / "x0x"
else:
    xdg_data = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    INSTALL_DIR = Path(xdg_data) / "x0x"

# Unix binary install directory
DAEMON_INSTALL_DIR = Path.home() / ".local" / "bin"


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


def detect_platform():
    """
    Detect the current platform and return the archive platform string.

    Returns the platform string (e.g. "linux-x64-gnu") or None if unsupported.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        if machine in ("x86_64", "amd64"):
            return "linux-x64-gnu"
        elif machine in ("aarch64", "arm64"):
            return "linux-arm64-gnu"
        else:
            return None
    elif system == "darwin":
        if machine in ("arm64", "aarch64"):
            return "macos-arm64"
        elif machine in ("x86_64", "amd64"):
            return "macos-x64"
        else:
            return None
    else:
        return None


def install_daemon():
    """
    Download and install the x0xd daemon binary for the current platform.

    Extracts x0xd from the platform-specific release archive and installs it
    to ~/.local/bin/x0xd with executable permissions.
    """
    print_color("Installing x0xd daemon...", BLUE)

    plat = detect_platform()
    if plat is None:
        system = platform.system()
        machine = platform.machine()
        print_color(
            f"  Skipping daemon install: unsupported platform ({system}/{machine}).",
            YELLOW
        )
        print(f"  To install x0xd manually, download the appropriate archive from:")
        print(f"  https://github.com/{REPO}/releases/latest")
        return

    archive_name = f"x0x-{plat}.tar.gz"
    archive_url = f"{RELEASE_URL}/{archive_name}"
    # The binary lives at x0x-{platform}/x0xd inside the archive
    inner_path = f"x0x-{plat}/x0xd"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        archive_dest = tmp / archive_name

        print(f"  Downloading {archive_name}...")
        try:
            urllib.request.urlretrieve(archive_url, archive_dest)
        except Exception as e:
            print_color(f"  ✗ Error downloading {archive_url}: {e}", RED)
            print_color("  Skipping daemon install.", YELLOW)
            return

        print(f"  Extracting x0xd...")
        try:
            with tarfile.open(archive_dest, "r:gz") as tf:
                member = tf.getmember(inner_path)
                # Extract only the x0xd binary, streaming into a file object
                src = tf.extractfile(member)
                if src is None:
                    raise KeyError(f"{inner_path} is not a regular file in the archive")

                DAEMON_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
                daemon_dest = DAEMON_INSTALL_DIR / "x0xd"
                with open(daemon_dest, "wb") as dst:
                    dst.write(src.read())
        except KeyError:
            print_color(
                f"  ✗ {inner_path} not found in archive. "
                "The release format may have changed.",
                RED
            )
            print_color("  Skipping daemon install.", YELLOW)
            return
        except Exception as e:
            print_color(f"  ✗ Extraction failed: {e}", RED)
            print_color("  Skipping daemon install.", YELLOW)
            return

        daemon_dest.chmod(0o755)
        print_color(f"  ✓ x0xd installed to {daemon_dest}", GREEN)

    # Warn if ~/.local/bin is not on PATH
    local_bin = str(DAEMON_INSTALL_DIR)
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    if local_bin not in path_dirs:
        print_color(
            f"\n  Warning: {local_bin} is not in your PATH.",
            YELLOW
        )
        print("  Add it to your shell profile to use x0xd directly:")
        print(f'    export PATH="{local_bin}:$PATH"')


def main():
    print_color("x0x Installation Script", BLUE)
    print_color("========================", BLUE)
    print()

    # Check GPG
    gpg_available = check_gpg()
    if not gpg_available:
        print_color("Warning: GPG not found. Signature verification will be skipped.", YELLOW)
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

    # Install the x0xd daemon binary
    print()
    install_daemon()

    print()
    print_color("✓ Installation complete", GREEN)
    print()
    print(f"SKILL.md installed to: {INSTALL_DIR / 'SKILL.md'}")
    print()
    print("Next steps:")
    print("  1. Review SKILL.md: cat", str(INSTALL_DIR / "SKILL.md"))
    print("  2. Start the daemon (creates your identity on first run):")
    print("       x0xd")
    print("  3. Install SDK:")
    print("     - Rust:       cargo add x0x")
    print("     - TypeScript: npm install x0x")
    print("     - Python:     pip install agent-x0x")
    print()
    print(f"Learn more: https://github.com/{REPO}")


if __name__ == "__main__":
    main()
