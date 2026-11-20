#!/usr/bin/env python3
"""Install the stable launcher and the systemd drop-in that runs an
instance's x0xd through it (#1378). Used by `install.sh --launcher`; off
unless that flag is given.

The drop-in replaces the unit's ExecStart with the launcher's trial form:

    x0x-launcher --host-root <data root> --instance <id> -- <x0xd> <args>

The data root is the one x0xd itself reports (`x0xd <args> --check`, run as
the unit's user; it reads the config and writes nothing), so the installer
has no second data_dir algorithm (design chapter §2). The launcher exits 75
after a daemon it owns ends, so the unit needs Restart=always. The launcher
exits 78 when no restart can help and 64 on a usage error, so systemd must not
restart either. KillMode=mixed sends the stop signal to the launcher only,
which stops x0xd within its own 45 s window.

The unit's user is the last `User=` in the unit and its other drop-ins (in
name order), or root. Any failure leaves no launcher drop-in behind, so the
unit runs x0xd directly; install.sh then reloads systemd.
"""

from __future__ import annotations

import argparse
import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

INSTANCE_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
# Tokens that systemd reads literally in ExecStart: no quoting, `$` or `%`.
SAFE_TOKEN = re.compile(r"[A-Za-z0-9_@+=:,./-]+")
DATA_DIR_LINE = re.compile(r'^\s*data_dir: "(?P<path>[^"\\]+)",$', re.MULTILINE)
# runuser is in /usr/sbin on Debian, Ubuntu and Fedora.
CHECK_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


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
    try:
        tokens = shlex.split(lines[0])
    except ValueError as error:
        raise Refused(f"the unit's ExecStart cannot be split ({error}); migrate by hand")
    for token in tokens:
        if not SAFE_TOKEN.fullmatch(token):
            raise Refused(f"ExecStart token {token!r} needs systemd quoting; migrate by hand")
    return tokens


def unit_user(unit_text: str, dropin: Path) -> str:
    """The last `User=` in the unit, then in its other drop-ins by name."""
    texts = [unit_text]
    if dropin.parent.is_dir():
        texts += [
            conf.read_text(encoding="utf-8")
            for conf in sorted(dropin.parent.glob("*.conf"))
            if conf.name != dropin.name and conf.is_file()
        ]
    users = [
        line.split("=", 1)[1].strip()
        for text in texts
        for line in text.splitlines()
        if line.strip().startswith("User=")
    ]
    return users[-1] if users and users[-1] else "root"


def daemon_data_root(binary: str, args: list[str], home: str, user: str) -> str:
    # As root, run the check as the unit's user, so it reads what x0xd reads.
    prefix: list[str] = []
    if os.geteuid() == 0 and user != "root":
        runuser = shutil.which("runuser", path=CHECK_PATH)
        if runuser is None:
            raise Refused(f"runuser is not in {CHECK_PATH}; it runs the check as {user}")
        prefix = [runuser, "-u", user, "--"]
    result = subprocess.run(
        [*prefix, binary, *args, "--check"],
        env={"HOME": home, "PATH": CHECK_PATH},
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


def install_launcher(source: Path, launcher: Path) -> None:
    if not source.is_file():
        raise Refused(f"launcher not found: {source}")
    staged = launcher.with_name(f".{launcher.name}.tmp")
    shutil.copyfile(source, staged)
    staged.chmod(0o755)
    os.replace(staged, launcher)


def write_dropin(dropin: Path, text: str) -> None:
    dropin.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    staged = dropin.with_name(f".{dropin.name}.tmp")
    with open(staged, "w", encoding="utf-8") as file:
        file.write(text)
        file.flush()
        os.fsync(file.fileno())
    staged.chmod(0o644)
    os.replace(staged, dropin)


def install(options: argparse.Namespace) -> None:
    dropin = Path(options.dropin)
    if dropin.name != "30-x0x-launcher.conf":
        raise Refused(f"{dropin} is not a 30-x0x-launcher.conf drop-in")
    if not os.access(options.binary, os.X_OK):
        raise Refused(f"x0xd is not installed at {options.binary}")
    unit_text = Path(options.unit).read_text(encoding="utf-8")
    user = unit_user(unit_text, dropin)
    try:
        account = pwd.getpwnam(user)
    except KeyError:
        raise Refused(f"the unit's user {user} does not exist")
    install_launcher(Path(options.launcher_source), Path(options.launcher))
    text = render(
        unit_text,
        options.binary,
        options.launcher,
        options.instance,
        account.pw_dir,
        account.pw_uid,
        user,
    )
    write_dropin(dropin, text)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Install x0x-launcher and its systemd drop-in for one instance."
    )
    parser.add_argument("--unit", required=True, help="the instance's installed unit file")
    parser.add_argument("--binary", required=True, help="the installed x0xd path")
    parser.add_argument("--launcher-source", required=True, help="the x0x-launcher to install")
    parser.add_argument("--launcher", required=True, help="where to install the launcher")
    parser.add_argument("--instance", required=True, help="the manifest instance id")
    parser.add_argument("--dropin", required=True, help="the drop-in path to write")
    options = parser.parse_args()
    try:
        install(options)
    except Exception as error:
        dropin = Path(options.dropin)
        try:
            dropin.with_name(f".{dropin.name}.tmp").unlink(missing_ok=True)
            dropin.unlink(missing_ok=True)
        except OSError as cleanup:
            print(f"error: cannot remove {dropin}: {cleanup}", file=sys.stderr)
        detail = str(error) if isinstance(error, Refused) else f"{type(error).__name__}: {error}"
        print(f"error: {detail}", file=sys.stderr)
        return 1
    print(f"[install] launcher drop-in: {options.dropin}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
