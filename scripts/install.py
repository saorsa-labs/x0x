#!/usr/bin/env python3
"""
x0x Installation Script (Cross-Platform Python)

Default mode is non-interactive and machine-readable:
- progress/warnings to stderr
- final JSON result to stdout

Use --interactive for human-friendly prompts/output.
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, Optional

# ANSI color codes (interactive mode only)
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"

REPO = "saorsa-labs/x0x"
RELEASE_URL = f"https://github.com/{REPO}/releases/latest/download"
VERSION = os.environ.get("X0X_VERSION", "0.2.0")

if sys.platform == "win32":
    INSTALL_DIR = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))) / "x0x"
else:
    xdg_data = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    INSTALL_DIR = Path(xdg_data) / "x0x"

DAEMON_INSTALL_DIR = Path.home() / ".local" / "bin"


class InstallError(Exception):
    def __init__(self, code: str, message: str, extra: Optional[Dict[str, str]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.extra = extra or {}


def emit_error_json(
    code: str, message: str, extra: Optional[Dict[str, str]] = None
) -> None:
    payload = {"status": "error", "error": message, "code": code}
    if extra:
        payload.update(extra)
    print(json.dumps(payload, separators=(",", ":")))


def log(msg: str, interactive: bool, color: Optional[str] = None) -> None:
    if interactive:
        if color:
            print(f"{color}{msg}{NC}")
        else:
            print(msg)
    else:
        print(msg, file=sys.stderr)


def warn(msg: str, interactive: bool) -> None:
    if interactive:
        log(msg, interactive=True, color=YELLOW)
    else:
        print(f"warning: {msg}", file=sys.stderr)


def check_gpg() -> bool:
    try:
        subprocess.run(["gpg", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def download_file(url: str, dest: Path) -> None:
    try:
        urllib.request.urlretrieve(url, dest)
    except Exception as exc:
        raise InstallError(
            "download_failed", f"Failed to download {url}: {exc}"
        ) from exc


def verify_signature(skill_file: Path, sig_file: Path, key_file: Path) -> bool:
    try:
        subprocess.run(
            ["gpg", "--import", str(key_file)], capture_output=True, check=True
        )
    except subprocess.CalledProcessError as exc:
        raise InstallError(
            "gpg_verification_failed", f"Failed to import GPG key: {exc}"
        ) from exc

    result = subprocess.run(
        ["gpg", "--verify", str(sig_file), str(skill_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and "Good signature" in result.stderr


def detect_platform() -> Optional[str]:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        if machine in ("x86_64", "amd64"):
            return "linux-x64-gnu"
        if machine in ("aarch64", "arm64"):
            return "linux-arm64-gnu"
    elif system == "darwin":
        if machine in ("arm64", "aarch64"):
            return "macos-arm64"
        if machine in ("x86_64", "amd64"):
            return "macos-x64"
    return None


def install_daemon(plat: str, interactive: bool) -> Path:
    archive_name = f"x0x-{plat}.tar.gz"
    archive_url = f"{RELEASE_URL}/{archive_name}"
    inner_path = f"x0x-{plat}/x0xd"
    daemon_dest = DAEMON_INSTALL_DIR / "x0xd"

    if daemon_dest.exists() and not interactive:
        raise InstallError(
            "already_installed",
            "x0xd already exists at install path",
            extra={"x0xd_path": str(daemon_dest)},
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        archive_dest = tmp / archive_name

        log(f"Downloading x0xd ({plat})...", interactive)
        download_file(archive_url, archive_dest)

        log("Extracting x0xd...", interactive)
        try:
            with tarfile.open(archive_dest, "r:gz") as tf:
                member = tf.getmember(inner_path)
                src = tf.extractfile(member)
                if src is None:
                    raise InstallError(
                        "download_failed", f"{inner_path} missing in archive"
                    )

                try:
                    DAEMON_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
                except PermissionError as exc:
                    raise InstallError(
                        "permission_denied",
                        f"Cannot create binary directory {DAEMON_INSTALL_DIR}",
                    ) from exc

                try:
                    with open(daemon_dest, "wb") as dst:
                        dst.write(src.read())
                except PermissionError as exc:
                    raise InstallError(
                        "permission_denied",
                        f"Cannot write x0xd to {daemon_dest}",
                    ) from exc
        except InstallError:
            raise
        except KeyError as exc:
            raise InstallError(
                "download_failed", f"{inner_path} missing in archive"
            ) from exc
        except tarfile.TarError as exc:
            raise InstallError(
                "download_failed", f"Invalid archive downloaded: {exc}"
            ) from exc

    try:
        daemon_dest.chmod(0o755)
    except PermissionError as exc:
        raise InstallError(
            "permission_denied", f"Cannot mark x0xd executable at {daemon_dest}"
        ) from exc

    return daemon_dest


def run(interactive: bool) -> None:
    if interactive:
        log("x0x Installation Script", interactive=True, color=BLUE)
        log("========================", interactive=True, color=BLUE)
        print()

    gpg_available = check_gpg()
    gpg_verified = False

    if not gpg_available:
        if interactive:
            warn(
                "Warning: GPG not found. Signature verification will be skipped.",
                interactive=True,
            )
            print()
            print("To enable signature verification, install GPG:")
            print("  Windows: https://gnupg.org/download/")
            print("  macOS:   brew install gnupg")
            print("  Linux:   apt/dnf install gnupg")
            print()
            if input("Continue without verification? (y/N) ").strip().lower() != "y":
                sys.exit(1)
        else:
            warn(
                "GPG not found; proceeding without signature verification",
                interactive=False,
            )

    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        os.chdir(INSTALL_DIR)
    except PermissionError as exc:
        raise InstallError(
            "permission_denied", f"Cannot access install directory {INSTALL_DIR}"
        ) from exc

    skill_file = INSTALL_DIR / "SKILL.md"
    log("Downloading SKILL.md...", interactive)
    download_file(f"{RELEASE_URL}/SKILL.md", skill_file)

    if gpg_available:
        sig_file = INSTALL_DIR / "SKILL.md.sig"
        key_file = INSTALL_DIR / "SAORSA_PUBLIC_KEY.asc"

        log("Downloading signature...", interactive)
        download_file(f"{RELEASE_URL}/SKILL.md.sig", sig_file)
        download_file(f"{RELEASE_URL}/SAORSA_PUBLIC_KEY.asc", key_file)

        log("Importing Saorsa Labs public key...", interactive)
        verified = verify_signature(skill_file, sig_file, key_file)

        if verified:
            gpg_verified = True
            if interactive:
                log("Signature verified", interactive=True, color=GREEN)
        elif interactive:
            log("Signature verification failed", interactive=True, color=RED)
            print()
            print("This file may have been tampered with.")
            if input("Install anyway? (y/N) ").strip().lower() != "y":
                sys.exit(1)
        else:
            raise InstallError(
                "gpg_verification_failed", "GPG signature verification failed"
            )

    log("Detecting platform...", interactive)
    plat = detect_platform()
    if plat is None:
        if interactive:
            warn(
                "Unsupported platform; x0xd daemon installation skipped",
                interactive=True,
            )
            daemon_path = None
        else:
            raise InstallError(
                "unsupported_platform", "No x0xd binary available for this OS/arch"
            )
    else:
        daemon_path = install_daemon(plat, interactive)

    if interactive:
        print()
        log("Installation complete", interactive=True, color=GREEN)
        print()
        print(f"SKILL.md installed to: {skill_file}")
        if daemon_path:
            print(f"x0xd installed to:     {daemon_path}")
        print()
        print("Next steps:")
        if daemon_path:
            print("  1. Run x0xd:")
            print("       x0xd")
            print("  2. Manage contacts:")
            print("       curl http://127.0.0.1:12700/contacts")
            print(f"  3. Review SKILL.md: cat {skill_file}")
            print("  4. Install SDK:")
        else:
            print(f"  1. Review SKILL.md: cat {skill_file}")
            print("  2. Install SDK:")
        print("     - Rust:       cargo add x0x")
        print("     - TypeScript: npm install x0x")
        print("     - Python:     pip install agent-x0x")
        print()
        print(f"Learn more: https://github.com/{REPO}")
        return

    if daemon_path is None or plat is None:
        raise InstallError(
            "unsupported_platform", "No x0xd binary available for this OS/arch"
        )

    payload = {
        "status": "ok",
        "x0xd_path": str(daemon_path),
        "skill_path": str(skill_file),
        "gpg_verified": gpg_verified,
        "platform": plat,
        "version": VERSION,
    }
    print(json.dumps(payload, separators=(",", ":")))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--help", action="store_true")
    args, unknown = parser.parse_known_args()
    if unknown:
        raise InstallError("invalid_argument", f"Unknown argument: {unknown[0]}")
    if args.help:
        print("Usage: install.py [--interactive]")
        sys.exit(0)
    return args


def main() -> None:
    try:
        args = parse_args()
        run(interactive=args.interactive)
    except InstallError as err:
        emit_error_json(err.code, err.message, err.extra)
        sys.exit(1)


if __name__ == "__main__":
    main()
