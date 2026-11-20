#!/usr/bin/env python3
"""Render the systemd drop-in that runs an instance's x0xd through the stable
launcher (#1378). Used by `install.sh --launcher`; off unless that flag is
given.

The drop-in replaces the unit's ExecStart with the launcher's trial form:

    x0x-launcher --host-root <data root> --instance <id> -- <x0xd> <args>

The data root is the one x0xd itself reports (`x0xd <args> --check`, run as
the unit's user; it reads the config and writes nothing), so the installer
has no second data_dir algorithm (design chapter §2). The launcher exits 75
after a daemon it owns ends, so the unit needs Restart=always. The launcher
exits 78 when no restart can help and 64 on a usage error, so systemd must not
restart either. KillMode=mixed sends the stop signal to the launcher only,
which stops x0xd within its own 45 s window.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path

INSTANCE_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
# Tokens that systemd reads literally in ExecStart: no quoting, `$` or `%`.
SAFE_TOKEN = re.compile(r"[A-Za-z0-9_@+=:,./-]+")
DATA_DIR_LINE = re.compile(r'^\s*data_dir: "(?P<path>[^"\\]+)",$', re.MULTILINE)


class Refused(Exception):
    pass


def unit_exec_start(unit_text: str) -> list[str]:
    lines = [
        line.split("=", 1)[1].strip()
        for line in unit_text.splitlines()
        if line.strip().startswith("ExecStart=")
    ]
    if len(lines) != 1 or not lines[0]:
        raise Refused("the unit must have exactly one non-empty ExecStart line")
    tokens = shlex.split(lines[0])
    for token in tokens:
        if not SAFE_TOKEN.fullmatch(token):
            raise Refused(f"ExecStart token {token!r} needs systemd quoting; migrate by hand")
    return tokens


def daemon_data_root(binary: str, args: list[str], home: str, user: str) -> str:
    # As root, run the check as the unit's user, so it reads what x0xd reads.
    prefix = ["runuser", "-u", user, "--"] if os.geteuid() == 0 and user != "root" else []
    result = subprocess.run(
        [*prefix, binary, *args, "--check"],
        env={"HOME": home, "PATH": "/usr/bin:/bin"},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise Refused(f"`{binary} --check` failed: {result.stdout.strip()} {result.stderr.strip()}")
    found = DATA_DIR_LINE.findall(result.stdout)
    if len(found) != 1:
        raise Refused(f"`{binary} --check` did not report exactly one data_dir")
    return found[0]


def check_host_root(path: str, owner: int) -> str:
    if not os.path.isabs(path):
        raise Refused(f"the data root {path} is not absolute")
    try:
        canonical = os.path.realpath(path, strict=True)
    except OSError as error:
        raise Refused(f"the data root {path} must exist (start x0xd once first): {error}")
    info = os.stat(canonical)
    if not stat.S_ISDIR(info.st_mode):
        raise Refused(f"the data root {canonical} is not a directory")
    if info.st_uid != owner:
        raise Refused(f"the data root {canonical} is owned by uid {info.st_uid}, not {owner}")
    if info.st_mode & 0o022:
        raise Refused(f"the data root {canonical} is writable by group or others")
    if not SAFE_TOKEN.fullmatch(canonical):
        raise Refused(f"the data root {canonical!r} needs systemd quoting")
    return canonical


def render(
    unit_text: str,
    binary: str,
    launcher: str,
    instance: str,
    home: str,
    owner: int,
    user: str,
) -> str:
    if not INSTANCE_ID.fullmatch(instance) or instance in (".", ".."):
        raise Refused(f"instance id {instance!r} is not valid for the launcher")
    for path in (binary, launcher):
        if not os.path.isabs(path) or not SAFE_TOKEN.fullmatch(path):
            raise Refused(f"{path!r} must be an absolute path without spaces or quotes")
    if os.path.basename(launcher) != "x0x-launcher":
        raise Refused(f"{launcher} is not named x0x-launcher")
    tokens = unit_exec_start(unit_text)
    if tokens[0] != binary:
        raise Refused(f"the unit runs {tokens[0]}, not {binary}")
    args = tokens[1:]
    root = check_host_root(daemon_data_root(binary, args, home, user), owner)
    exec_start = " ".join(
        [launcher, "--host-root", root, "--instance", instance, "--", binary, *args]
    )
    return (
        "# Installed by .deployment/install.sh --launcher (#1378). Remove this file\n"
        "# and run `systemctl daemon-reload` to return to the direct job.\n"
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart={exec_start}\n"
        "Restart=always\n"
        "RestartPreventExitStatus=64 78\n"
        "KillMode=mixed\n"
        "TimeoutStopSec=60\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Render the x0x-launcher systemd drop-in.")
    parser.add_argument("--unit", required=True, help="the instance's unit file")
    parser.add_argument("--binary", required=True, help="the installed x0xd path")
    parser.add_argument("--launcher", required=True, help="the installed launcher path")
    parser.add_argument("--instance", required=True, help="the manifest instance id")
    parser.add_argument("--home", required=True, help="HOME of the unit's user")
    parser.add_argument("--owner", required=True, type=int, help="uid of the unit's user")
    parser.add_argument("--user", required=True, help="the unit's user")
    options = parser.parse_args()
    try:
        sys.stdout.write(
            render(
                Path(options.unit).read_text(encoding="utf-8"),
                options.binary,
                options.launcher,
                options.instance,
                options.home,
                options.owner,
                options.user,
            )
        )
    except Refused as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
