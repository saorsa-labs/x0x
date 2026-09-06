#!/usr/bin/env python3
"""Check both Linux ELF inputs and capture versions inside admitted namespace."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

EXPECTED_LEGACY_SHA256 = "3421ee169a416b4ea2b1c1687470eb80543bb860ca5636700d1b9d6162e0a437"


def regular(path):
    if path.is_symlink() or not path.is_file() or not path.stat().st_mode & 0o111:
        raise RuntimeError(f"binary is not a regular executable: {path}")


def inspect(path, expected_version):
    regular(path)
    kind = subprocess.check_output(["file", "-b", str(path)], text=True).strip()
    if "ELF 64-bit LSB pie executable" not in kind or "x86-64" not in kind:
        raise RuntimeError(f"unexpected Linux ELF: {kind}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    version = subprocess.run([str(path), "--version"], check=True,
                             capture_output=True, text=True, timeout=20)
    output = (version.stdout + version.stderr).strip()
    if expected_version not in output:
        raise RuntimeError(f"version output lacks {expected_version}: {output!r}")
    return {"sha256": digest, "file": kind, "version": output}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--current", required=True, type=Path)
    parser.add_argument("--legacy", required=True, type=Path)
    parser.add_argument("--expected-current-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    current = inspect(args.current, "0.41.3")
    legacy = inspect(args.legacy, "0.30.1")
    if current["sha256"] != args.expected_current_sha256:
        raise RuntimeError("current binary hash changed between build and namespace")
    if legacy["sha256"] != EXPECTED_LEGACY_SHA256:
        raise RuntimeError("legacy binary hash is not the authenticated v0.30.1 artifact")
    args.output.write_text(json.dumps({"status": "pass", "current": current,
                                       "legacy": legacy}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "fail", "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1)
