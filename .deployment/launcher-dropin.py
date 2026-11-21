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

The unit's user and ExecStart are the effective ones: the unit file and every
drop-in systemd applies to it (under /etc, /run and /usr/lib, in name order),
the launcher drop-in itself left out. The helper reads them from the files
and, when systemd answers, asks it too (`systemctl daemon-reload`, then
`systemctl show`); an answer that differs from the files is refused, as is a
unit file or drop-in that shadows this one or a later drop-in that would
undo the launcher drop-in. Any failure leaves no launcher drop-in behind, so
the unit runs x0xd directly; install.sh then reloads systemd.
"""

from __future__ import annotations

import argparse
import os
import pwd
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

INSTANCE_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
# Tokens that systemd reads literally in ExecStart: no quoting, `$` or `%`.
SAFE_TOKEN = re.compile(r"[A-Za-z0-9_@+=:,./-]+")
DATA_DIR_LINE = re.compile(r'^\s*data_dir: "(?P<path>[^"\\]+)",$', re.MULTILINE)
# runuser is in /usr/sbin on Debian, Ubuntu and Fedora.
CHECK_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


# The system manager's unit search path, highest precedence first
# (systemd.unit(5)). The directory of the unit being installed takes the
# place of /etc/systemd/system.
ETC_UNITS = "/etc/systemd/system"
SEARCH_PATH = (
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    ETC_UNITS,
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator.late",
)
# What the launcher drop-in sets; a drop-in applied after it must not set any.
DROPIN_KEYS = (
    "ExecStart",
    "Restart",
    "RestartPreventExitStatus",
    "KillMode",
    "TimeoutStopSec",
    "TimeoutSec",
)
# The daemon's data directory depends on these; the installer's `--check`
# runs with HOME and PATH only, so a unit that sets them is refused.
DATA_ENV = ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME")
# Present when systemd is the running service manager (sd_booted(3)).
SYSTEMD_RUNTIME = "/run/systemd/system"
SHOW_PROPERTIES = ("LoadState", "FragmentPath", "DropInPaths", "User", "ExecStart")


class Refused(Exception):
    pass


class Settings(NamedTuple):
    user: str
    exec_start: list[str]
    fragment: str
    dropins: list[str]


def service_assignments(text: str) -> list[tuple[str, str]]:
    """The `Key=value` lines of the [Service] section in order, as systemd
    reads them: comments skipped, a line ending in `\\` joined to the next."""
    lines: list[str] = []
    pending: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line[:1] in ("#", ";") or (pending is None and not line):
            continue
        if line.endswith("\\"):
            pending = line[:-1] if pending is None else f"{pending} {line[:-1]}"
            continue
        lines.append(line if pending is None else f"{pending} {line}")
        pending = None
    if pending is not None:
        lines.append(pending)
    section = None
    assignments = []
    for line in lines:
        if line.startswith("["):
            section = line
        elif section == "[Service]" and "=" in line:
            key, value = line.split("=", 1)
            assignments.append((key.strip(), value.strip()))
    return assignments


def exec_tokens(value: str) -> list[str]:
    try:
        tokens = shlex.split(value)
    except ValueError as error:
        raise Refused(f"the unit's ExecStart cannot be split ({error}); migrate by hand")
    for token in tokens:
        if not SAFE_TOKEN.fullmatch(token):
            raise Refused(f"ExecStart token {token!r} needs systemd quoting; migrate by hand")
    return tokens


def unit_exec_start(*texts: str) -> list[str]:
    """The one ExecStart that `texts` (the unit, then its drop-ins in
    order) leave: an empty `ExecStart=` clears the earlier ones."""
    values: list[str] = []
    for text in texts:
        for key, value in service_assignments(text):
            if key == "ExecStart":
                values = values + [value] if value else []
    if len(values) != 1:
        raise Refused("the unit must have exactly one effective ExecStart")
    tokens = exec_tokens(values[0])
    if not tokens:
        raise Refused("the unit's ExecStart is empty")
    return tokens


def unit_user(*texts: str) -> str:
    """The last `User=` in `texts`; an empty one, or none, is root."""
    user = ""
    for text in texts:
        for key, value in service_assignments(text):
            if key == "User":
                user = value
    return user or "root"


def dropin_dirs(name: str) -> list[str]:
    """The drop-in directory names systemd reads for unit `name`, the unit's
    own first: `x0xd-a.service.d`, `x0xd-.service.d`, `service.d`."""
    stem, _, kind = name.rpartition(".")
    names = [f"{name}.d"]
    if "@" in stem:
        names.append(f"{stem.split('@', 1)[0]}@.{kind}.d")
    parts = stem.split("-")
    names += [f"{'-'.join(parts[:i])}-.{kind}.d" for i in range(len(parts) - 1, 0, -1)]
    names.append(f"{kind}.d")
    return names


def unit_files(unit: Path, dropin: Path) -> tuple[Path, list[Path]]:
    """The unit file systemd loads for `unit`'s name and the drop-ins it
    applies, in order, without the launcher drop-in `dropin`."""
    # On a merged-/usr host /lib is a link to usr/lib: one directory, read once.
    roots: list[Path] = []
    seen: set[str] = set()
    for entry in SEARCH_PATH:
        root = unit.parent if entry == ETC_UNITS else Path(entry)
        real = os.path.realpath(root)
        if real not in seen:
            seen.add(real)
            roots.append(root)
    fragment = next((d / unit.name for d in roots if os.path.lexists(d / unit.name)), None)
    if fragment is None:
        raise Refused(f"the unit {unit} does not exist")
    if fragment != unit:
        raise Refused(f"{fragment} overrides {unit}; migrate by hand")
    if os.path.realpath(unit) == os.devnull:
        raise Refused(f"{unit.name} is masked")
    found: dict[str, Path] = {}
    for root in roots:
        for directory in dropin_dirs(unit.name):
            path = root / directory
            if not path.is_dir():
                continue
            for conf in sorted(path.glob("*.conf")):
                if conf == dropin:
                    continue
                if conf.name == dropin.name:
                    raise Refused(f"{conf} would replace the launcher drop-in; remove it")
                if conf.name in found:
                    raise Refused(
                        f"drop-ins {found[conf.name]} and {conf} share a name; "
                        "systemd applies one of them only; migrate by hand"
                    )
                found[conf.name] = conf
    return unit, [found[name] for name in sorted(found)]


def file_settings(unit: Path, dropin: Path) -> Settings:
    fragment, dropins = unit_files(unit, dropin)
    texts = [fragment.read_text(encoding="utf-8")]
    for conf in dropins:
        if os.path.realpath(conf) == os.devnull:
            texts.append("")
            continue
        text = conf.read_text(encoding="utf-8")
        texts.append(text)
        if conf.name > dropin.name:
            for key, _ in service_assignments(text):
                if key in DROPIN_KEYS:
                    raise Refused(f"{conf} sets {key}= after the launcher drop-in; migrate by hand")
    check_environment(texts)
    return Settings(
        user=unit_user(*texts),
        exec_start=unit_exec_start(*texts),
        fragment=str(fragment),
        dropins=[str(conf) for conf in dropins],
    )


def check_environment(texts: list[str]) -> None:
    """Refuse a unit whose environment can move the daemon's data
    directory away from what the installer's `--check` (HOME and PATH
    only) reports: an EnvironmentFile=, or an Environment= that sets HOME
    or an XDG base directory."""
    for text in texts:
        for key, value in service_assignments(text):
            if key == "EnvironmentFile" and value:
                raise Refused("the unit sets EnvironmentFile=; migrate by hand")
            if key != "Environment":
                continue
            try:
                assignments = shlex.split(value)
            except ValueError as error:
                raise Refused(f"the unit's Environment= cannot be split ({error})")
            for assignment in assignments:
                name = assignment.split("=", 1)[0]
                if name in DATA_ENV:
                    raise Refused(f"the unit sets {name} in Environment=; migrate by hand")


def systemd_settings(name: str) -> Settings | None:
    """systemd's view of unit `name` after a reload. None only when systemd
    is not the running service manager; when it is, a reload or a query
    that fails is refused."""
    running = os.path.isdir(SYSTEMD_RUNTIME)
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        if running:
            raise Refused("systemd is running but systemctl is not found")
        return None

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [systemctl, *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    reload = run("daemon-reload")
    if reload.returncode != 0:
        if running:
            raise Refused(f"systemctl daemon-reload failed: {reload.stderr.strip()}")
        return None
    properties = [arg for prop in SHOW_PROPERTIES for arg in ("-p", prop)]
    shown = run("show", *properties, "--", name)
    if shown.returncode != 0:
        if running:
            raise Refused(f"systemctl show {name} failed: {shown.stderr.strip()}")
        return None
    values = dict(line.split("=", 1) for line in shown.stdout.splitlines() if "=" in line)
    if values.get("LoadState") != "loaded":
        raise Refused(f"systemd does not load {name} (LoadState={values.get('LoadState')})")
    commands = re.findall(r"\{ path=(\S+) ; argv\[\]=([^;]*) ; ", values.get("ExecStart", ""))
    if len(commands) != 1 or values.get("ExecStart", "").count("{") != 1:
        raise Refused(f"systemd reports {name} without exactly one ExecStart")
    path, argv = commands[0]
    tokens = argv.split()
    if not tokens or tokens[0] != path or not all(SAFE_TOKEN.fullmatch(t) for t in tokens):
        raise Refused(f"systemd reports an ExecStart for {name} that needs quoting: {argv!r}")
    return Settings(
        user=values.get("User") or "root",
        exec_start=tokens,
        fragment=values.get("FragmentPath", ""),
        dropins=values.get("DropInPaths", "").split(),
    )


def effective_settings(unit: Path, dropin: Path) -> Settings:
    files = file_settings(unit, dropin)
    asked = systemd_settings(unit.name)
    if asked is None:
        print("[install] systemd did not answer; using the unit files", file=sys.stderr)
    elif asked != files:
        differs = [field for field in Settings._fields if getattr(asked, field) != getattr(files, field)]
        raise Refused(
            f"systemd's {', '.join(differs)} for {unit.name} differs from its unit files; "
            "migrate by hand"
        )
    return files


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
    """The data root with its parent resolved. Its last component is not
    followed, as the launcher does not follow it: a symlink is refused."""
    if not os.path.isabs(path):
        raise Refused(f"the data root {path} is not absolute")
    name = os.path.basename(path.rstrip("/"))
    if name in ("", ".", ".."):
        raise Refused(f"the data root {path} names no directory")
    try:
        parent = os.path.realpath(os.path.dirname(path.rstrip("/")), strict=True)
        canonical = os.path.join(parent, name)
        info = os.lstat(canonical)
    except OSError as error:
        raise Refused(f"the data root {path} must exist (start x0xd once first): {error}")
    if stat.S_ISLNK(info.st_mode):
        raise Refused(f"the data root {path} is a symlink; the launcher does not follow it")
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
    exec_start: list[str],
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
    if exec_start[0] != binary:
        raise Refused(f"the unit runs {exec_start[0]}, not {binary}")
    args = exec_start[1:]
    for index, token in enumerate(args):
        if token.startswith("--config="):
            raise Refused("x0xd does not read --config=; use --config <absolute path>")
        if token == "--config" and not os.path.isabs(args[index + 1] if index + 1 < len(args) else ""):
            raise Refused("the unit's --config must be an absolute path (WorkingDirectory= is not used)")
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


def replace_file(target: Path, write, mode: int) -> None:
    """Put a new `target` in one step: a new temporary file in its
    directory (O_EXCL, mode 0700, so no other account can open it while it
    is written), `write(file)`, the final mode, fsync, rename, then fsync of
    the directory. The umask plays no part. A failure before the rename
    removes the temporary file and leaves `target` as it was; a failed
    directory fsync is raised after the rename, when `target` is already
    the new file."""
    staged = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(staged, flags, 0o700)
    try:
        with os.fdopen(fd, "wb") as file:
            write(file)
            file.flush()
            os.fchmod(file.fileno(), mode)
            os.fsync(file.fileno())
        os.replace(staged, target)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def install_launcher(source: Path, launcher: Path) -> None:
    if not source.is_file():
        raise Refused(f"launcher not found: {source}")

    def copy(file) -> None:
        with open(source, "rb") as original:
            shutil.copyfileobj(original, file)

    replace_file(launcher, copy, 0o755)


def write_dropin(dropin: Path, text: str) -> None:
    dropin.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    replace_file(dropin, lambda file: file.write(text.encode("utf-8")), 0o644)


def install(options: argparse.Namespace) -> None:
    dropin = Path(options.dropin)
    if dropin.name != "30-x0x-launcher.conf":
        raise Refused(f"{dropin} is not a 30-x0x-launcher.conf drop-in")
    if not os.access(options.binary, os.X_OK):
        raise Refused(f"x0xd is not installed at {options.binary}")
    # systemd must not see an earlier launcher drop-in when it is asked.
    dropin.unlink(missing_ok=True)
    settings = effective_settings(Path(options.unit), dropin)
    user = settings.user
    try:
        account = pwd.getpwnam(user)
    except KeyError:
        raise Refused(f"the unit's user {user} does not exist")
    install_launcher(Path(options.launcher_source), Path(options.launcher))
    text = render(
        settings.exec_start,
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
