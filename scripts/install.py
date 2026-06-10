#!/usr/bin/env python3
"""
x0x Installation Script (Cross-Platform Python)

Downloads and installs:
  - SKILL.md (with pinned GPG verification)
  - x0xd daemon binary (platform-detected, with pinned GPG verification)

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
TRUSTED_GPG_FINGERPRINTS = {
    # Saorsa Labs release signing key. Rotate only with a reviewed installer change.
    "9D1F3C64B5D3C2F6B4A2E6D8A5C7F8E9D0B1A2C3",
}

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


def normalize_fingerprint(fingerprint):
    """Normalize a GPG fingerprint for comparison."""
    return "".join(fingerprint.upper().split())


def trusted_fingerprints():
    """Return normalized trusted signing key fingerprints."""
    return {
        normalize_fingerprint(fingerprint)
        for fingerprint in TRUSTED_GPG_FINGERPRINTS
    }


def key_fingerprints(key_file):
    """Read fingerprints from an armored public key without importing it."""
    try:
        result = subprocess.run(
            [
                "gpg",
                "--batch",
                "--with-colons",
                "--show-keys",
                "--fingerprint",
                str(key_file),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print_color(f"✗ Failed to inspect public key: {e}", RED)
        return set()

    fingerprints = set()
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if fields and fields[0] == "fpr" and len(fields) > 9:
            fingerprints.add(normalize_fingerprint(fields[9]))
    return fingerprints


def verify_signature(artifact_file, sig_file, key_file):
    """Verify an artifact signature with the pinned Saorsa Labs signing key."""
    expected_fingerprints = trusted_fingerprints()
    downloaded_fingerprints = key_fingerprints(key_file)
    if not expected_fingerprints.intersection(downloaded_fingerprints):
        print_color("✗ Downloaded public key is not trusted", RED)
        return False

    with tempfile.TemporaryDirectory() as gnupg_home:
        os.chmod(gnupg_home, 0o700)
        print("Importing Saorsa Labs public key...")
        try:
            subprocess.run(
                ["gpg", "--homedir", gnupg_home, "--batch", "--import", str(key_file)],
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            print_color(f"✗ Failed to import key: {e}", RED)
            return False

        print(f"Verifying signature for {artifact_file.name}...")
        result = subprocess.run(
            [
                "gpg",
                "--homedir",
                gnupg_home,
                "--batch",
                "--status-fd",
                "1",
                "--verify",
                str(sig_file),
                str(artifact_file),
            ],
            capture_output=True,
            text=True,
        )

    valid_signers = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "[GNUPG:]" and parts[1] == "VALIDSIG":
            valid_signers.add(normalize_fingerprint(parts[2]))
            if len(parts) >= 12:
                valid_signers.add(normalize_fingerprint(parts[11]))

    if result.returncode == 0 and expected_fingerprints.intersection(valid_signers):
        print_color("✓ Signature verified", GREEN)
        return True

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


def install_daemon(key_file):
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
    sig_url = f"{archive_url}.asc"
    # The binary lives at x0x-{platform}/x0xd inside the archive
    inner_path = f"x0x-{plat}/x0xd"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        archive_dest = tmp / archive_name
        sig_dest = tmp / f"{archive_name}.asc"

        print(f"  Downloading {archive_name}...")
        try:
            urllib.request.urlretrieve(archive_url, archive_dest)
            urllib.request.urlretrieve(sig_url, sig_dest)
        except Exception as e:
            print_color(f"  ✗ Error downloading {archive_url}: {e}", RED)
            print_color("  Skipping daemon install.", YELLOW)
            return

        if not verify_signature(archive_dest, sig_dest, key_file):
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
        print_color("Error: GPG is required for verified installation.", RED)
        print("  Windows: https://gnupg.org/download/")
        print("  macOS:   brew install gnupg")
        print("  Linux:   apt/dnf install gnupg")
        sys.exit(1)

    # Create install directory
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    os.chdir(INSTALL_DIR)

    with tempfile.TemporaryDirectory(dir=INSTALL_DIR) as tmpdir:
        tmp = Path(tmpdir)
        downloaded_skill_file = tmp / "SKILL.md"
        downloaded_sig_file = tmp / "SKILL.md.sig"
        downloaded_key_file = tmp / "SAORSA_PUBLIC_KEY.asc"

        # Download SKILL.md and verify before installing it.
        download_file(f"{RELEASE_URL}/SKILL.md", downloaded_skill_file)
        download_file(f"{RELEASE_URL}/SKILL.md.sig", downloaded_sig_file)
        download_file(f"{RELEASE_URL}/SAORSA_PUBLIC_KEY.asc", downloaded_key_file)

        if not verify_signature(
            downloaded_skill_file,
            downloaded_sig_file,
            downloaded_key_file,
        ):
            print()
            print("This file may have been tampered with.")
            sys.exit(1)

        skill_file = INSTALL_DIR / "SKILL.md"
        sig_file = INSTALL_DIR / "SKILL.md.sig"
        key_file = INSTALL_DIR / "SAORSA_PUBLIC_KEY.asc"
        os.replace(downloaded_sig_file, sig_file)
        os.replace(downloaded_key_file, key_file)
        os.replace(downloaded_skill_file, skill_file)

        # Install the x0xd daemon binary
        print()
        install_daemon(key_file)

    print()
    print_color("✓ Installation complete", GREEN)
    print()
    print(f"SKILL.md installed to: {INSTALL_DIR / 'SKILL.md'}")
    print()
    print("Next steps:")
    print("  1. Review SKILL.md: cat", str(INSTALL_DIR / "SKILL.md"))
    print("  2. Start the daemon (creates your identity on first run):")
    print("       x0xd")
    print()
    print(f"Learn more: https://github.com/{REPO}")


if __name__ == "__main__":
    main()
