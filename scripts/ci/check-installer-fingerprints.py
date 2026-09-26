#!/usr/bin/env python3
"""Fail if any installer pins a release-signing fingerprint other than the real one (#939).

scripts/install.py shipped a placeholder fingerprint, so it rejected every
genuine release. This check keeps every installer's pin equal to CANONICAL and,
with --release, CANONICAL equal to the primary fingerprint of the
SAORSA_PUBLIC_KEY.asc published with the latest release.

Any 40-hex-digit token in an installer is treated as a fingerprint pin, so a
new or changed pin cannot silently drift. Installers in REQUIRED must pin.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

CANONICAL = "CEB3506E7DCB8A2DD2D679E8EDDA4827D89C0F29"
KEY_URL = "https://github.com/saorsa-labs/x0x/releases/latest/download/SAORSA_PUBLIC_KEY.asc"

ROOT = Path(__file__).resolve().parents[2]
INSTALLERS = [
    "scripts/install.py",
    "scripts/install.ps1",
    "scripts/install.sh",
    ".deployment/install.sh",
    "docs/GPG_SIGNING.md",
]
# Files that must carry the pin: every installer that downloads a release
# (install.sh is the `curl x0x.md | sh` path, #955; install.ps1 is Windows, #937)
# and the doc that prints it. .deployment/install.sh downloads nothing.
REQUIRED = {
    "scripts/install.py",
    "scripts/install.sh",
    "scripts/install.ps1",
    "docs/GPG_SIGNING.md",
}

HEX40 = re.compile(r"\b[0-9A-Fa-f]{40}\b")


def check_installers() -> list[str]:
    errors = []
    for rel in INSTALLERS:
        path = ROOT / rel
        if not path.exists():
            errors.append(f"{rel}: missing")
            continue
        pins = {m.upper() for m in HEX40.findall(path.read_text(encoding="utf-8"))}
        wrong = sorted(pins - {CANONICAL})
        if wrong:
            errors.append(f"{rel}: pins {', '.join(wrong)}, expected {CANONICAL}")
        elif rel in REQUIRED and CANONICAL not in pins:
            errors.append(f"{rel}: does not pin {CANONICAL}")
        else:
            print(f"ok  {rel}: {'pins ' + CANONICAL if pins else 'no pin'}")
    return errors


def check_release() -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        key = Path(tmp) / "SAORSA_PUBLIC_KEY.asc"
        with urllib.request.urlopen(KEY_URL, timeout=30) as resp:
            key.write_bytes(resp.read())
        out = subprocess.run(
            ["gpg", "--batch", "--show-keys", "--with-colons", "--with-fingerprint", str(key)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    # The first fpr record after the pub record is the primary key's fingerprint.
    lines = out.splitlines()
    primary = None
    for i, line in enumerate(lines):
        if line.startswith("pub:"):
            fpr = next((l for l in lines[i + 1:] if l.startswith("fpr:")), "")
            primary = fpr.split(":")[9].upper() if fpr else None
            break
    if primary != CANONICAL:
        return [f"latest release key primary fingerprint is {primary}, expected {CANONICAL}"]
    print(f"ok  latest release SAORSA_PUBLIC_KEY.asc: {primary}")
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--release",
        action="store_true",
        help="also compare against the key published with the latest release (needs network + gpg)",
    )
    args = parser.parse_args()
    errors = check_installers()
    if args.release:
        errors += check_release()
    for err in errors:
        print(f"FAIL {err}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
