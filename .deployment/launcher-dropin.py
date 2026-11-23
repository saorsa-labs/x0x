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

The plan anchor (#2012). The trial form also names a root-owned plan anchor,
`--plan-anchor <path>`, that the launcher checks before it gives a trial: a
JSON file that names the approved install (the daemon and CLI targets) and
each participant (instance id and data root). There is ONE anchor per
install, `<anchor dir>/install-<key>.anchor.json`, where `<key>` is the first
16 hex digits of the SHA-256 of the canonical daemon target. Every unit that
runs that install names the same file, and each install of a unit adds or
replaces its own participant there. A journal's plan binding carries one
anchor digest and the plan must name every participant of the install, so
units that share one install (the fleet's x0xd and x0xd-443) must name
byte-identical anchors; one shared file makes that true by construction. The
file is written in one canonical form (sorted keys and participants), so a
rerun that changes nothing leaves the same bytes. The anchor directory and
every directory above it must be root's and not writable by group or others
(a sticky directory is allowed), as the launcher checks; its path is
canonical (on macOS /etc is /private/etc).

A new anchor changes the digest that every binding of the install was made
against, and a launcher refuses (exit 78) a trial whose binding does not
match. So the anchor is rewritten only when no data root it names, before or
after, holds a host journal other than an idle or superseded one. Removing a
unit's launcher drop-in (`--remove`) also removes its participant from the
anchor, and the file with the last one, under the same rule.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import pwd
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import time
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
# The launcher's plan anchor (src/upgrade/plan_binding.rs).
ANCHOR_SCHEMA = 1
ANCHOR_KIND = "plan_anchor"
ANCHOR_MAX_BYTES = 64 * 1024
DEFAULT_ANCHOR_DIR = "/etc/x0x/launcher"
JOURNAL_FILE_NAME = "upgrade-journal.json"
# The journal readers' record size limit (src/upgrade/journal.rs).
JOURNAL_MAX_BYTES = 1024 * 1024
# Journal phases under which no launcher reads the anchor again.
ANCHOR_FREE_PHASES = ("idle", "superseded")
# The data root's stage lock (src/upgrade/prepare.rs STAGE_LOCK_NAME). A
# producer holds it from its anchor read to its Staged journal (#2012).
STAGE_LOCK_NAME = "upgrade-stage.lock"


class Refused(Exception):
    pass


class Held(Refused):
    """A host journal holds the install as it is: the plan anchor or the
    launcher cannot change now. Nothing was changed: the launcher, the
    drop-in and the anchor are as they were."""


class RestoreFailed(Refused):
    """A late refusal whose restore failed: the state is reported as it is."""


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
    anchor: str | None = None,
) -> str:
    return render_with_root(exec_start, binary, launcher, instance, home, owner, user, anchor)[0]


def unit_host_root(exec_start: list[str], binary: str, home: str, owner: int, user: str) -> str:
    """The data root the unit's x0xd reports, checked as the launcher
    checks its host root."""
    if exec_start[0] != binary:
        raise Refused(f"the unit runs {exec_start[0]}, not {binary}")
    args = exec_start[1:]
    for index, token in enumerate(args):
        if token.startswith("--config="):
            raise Refused("x0xd does not read --config=; use --config <absolute path>")
        if token == "--config" and not os.path.isabs(args[index + 1] if index + 1 < len(args) else ""):
            raise Refused("the unit's --config must be an absolute path (WorkingDirectory= is not used)")
    return check_host_root(daemon_data_root(binary, args, home, user), owner)


def render_with_root(
    exec_start: list[str],
    binary: str,
    launcher: str,
    instance: str,
    home: str,
    owner: int,
    user: str,
    anchor: str | None = None,
) -> tuple[str, str]:
    """The drop-in text and the host root it names."""
    if not INSTANCE_ID.fullmatch(instance) or instance in (".", ".."):
        raise Refused(f"instance id {instance!r} is not valid for the launcher")
    for path in (binary, launcher):
        if not os.path.isabs(path) or not SAFE_TOKEN.fullmatch(path):
            raise Refused(f"{path!r} must be an absolute path without spaces or quotes")
    if os.path.basename(launcher) != "x0x-launcher":
        raise Refused(f"{launcher} is not named x0x-launcher")
    if anchor is not None and (not os.path.isabs(anchor) or not SAFE_TOKEN.fullmatch(anchor)):
        raise Refused(f"the plan anchor {anchor!r} must be an absolute path without spaces")
    root = unit_host_root(exec_start, binary, home, owner, user)
    named = ["--plan-anchor", anchor] if anchor is not None else []
    command = " ".join(
        [launcher, "--host-root", root, "--instance", instance, *named, "--", *exec_start]
    )
    text = (
        "# Installed by .deployment/install.sh --launcher (#1378). To return to the\n"
        "# direct job, run .deployment/install.sh without --launcher: it also takes\n"
        "# this unit out of the plan anchor. Do not just delete this file.\n"
        "[Service]\n"
        "ExecStart=\n"
        f"ExecStart={command}\n"
        "Restart=always\n"
        "RestartPreventExitStatus=64 78\n"
        "KillMode=mixed\n"
        "TimeoutStopSec=60\n"
    )
    return text, root


def check_anchor_dir(path: str) -> Path:
    """The anchor directory, created (0755) if missing, in canonical form.
    It and every directory above it must be a directory of root (or of the
    account that runs this, which install.sh requires to be root) that no
    group or other account can write unless it is sticky: the launcher
    refuses an anchor under any other directory."""
    if not os.path.isabs(path):
        raise Refused(f"the anchor directory {path} is not absolute")
    # Each missing directory is made 0755 whatever the umask.
    missing = []
    probe = Path(path)
    while not os.path.lexists(probe):
        missing.append(probe)
        probe = probe.parent
    for directory in reversed(missing):
        os.mkdir(directory, 0o700)
        os.chmod(directory, 0o755)
    canonical = Path(os.path.realpath(path, strict=True))
    owners = {0, os.geteuid()}
    for directory in (canonical, *canonical.parents):
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode):
            raise Refused(f"{directory} is not a directory")
        if info.st_uid not in owners:
            raise Refused(f"{directory} is owned by uid {info.st_uid}, not root")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise Refused(f"{directory} is writable by group or others")
    if not SAFE_TOKEN.fullmatch(str(canonical)):
        raise Refused(f"the anchor directory {canonical!r} needs systemd quoting")
    return canonical


def anchor_path(anchor_dir: Path, daemon_target: str) -> Path:
    key = hashlib.sha256(daemon_target.encode("utf-8")).hexdigest()[:16]
    return anchor_dir / f"install-{key}.anchor.json"


def install_targets(binary: str) -> tuple[str, str]:
    """The canonical daemon target and the CLI target beside it (`x0x`, the
    companion the self-update swaps with the daemon)."""
    try:
        daemon = os.path.realpath(binary, strict=True)
    except OSError as error:
        raise Refused(f"x0xd is not installed at {binary}: {error}")
    cli = os.path.join(os.path.dirname(daemon), "x0x")
    if os.path.lexists(cli):
        cli = os.path.realpath(cli)
    if cli == daemon:
        raise Refused(f"the CLI target {cli} is the daemon")
    return daemon, cli


def read_anchor(path: Path) -> tuple[bytes, dict] | None:
    """The anchor at `path` and its bytes; None when there is none. One that
    is not a regular file of root (or this account), is writable by group
    or others, or is not a plan anchor is refused, not replaced."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise Refused(f"cannot read the plan anchor {path}: {error}")
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
            raise Refused(f"the plan anchor {path} is not a regular file of root; remove it")
        if info.st_mode & 0o022:
            raise Refused(f"the plan anchor {path} is writable by group or others; remove it")
        data = file.read(ANCHOR_MAX_BYTES + 1)
    try:
        anchor = json.loads(data)
    except ValueError:
        anchor = None
    if (
        len(data) > ANCHOR_MAX_BYTES
        or not isinstance(anchor, dict)
        or anchor.get("schema") != ANCHOR_SCHEMA
        or anchor.get("record_kind") != ANCHOR_KIND
        or not isinstance(anchor.get("participants"), list)
    ):
        raise Refused(f"{path} is not a plan anchor of schema {ANCHOR_SCHEMA}; remove it")
    return data, anchor


def render_anchor(daemon: str, cli: str, participants: dict[str, str]) -> bytes:
    """The anchor in its one canonical form: sorted keys, participants
    sorted by instance id, two-space indent, a final newline."""
    anchor = {
        "schema": ANCHOR_SCHEMA,
        "record_kind": ANCHOR_KIND,
        "daemon_target": daemon,
        "cli_target": cli,
        "participants": [
            {"instance_id": instance, "data_root": root}
            for instance, root in sorted(participants.items())
        ],
    }
    return (json.dumps(anchor, indent=2, sort_keys=True) + "\n").encode("utf-8")


def journal_phase(data_root: str) -> str | None:
    """The phase of the host journal in `data_root`; None when there is
    none. The journal is in the daemon account's directory and this runs as
    root, so it is opened without following a symlink and without blocking
    on a FIFO, and must be a regular file. One that cannot be read counts as
    a journal a launcher may still read."""
    path = os.path.join(data_root, JOURNAL_FILE_NAME)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as error:
        return f"unreadable ({error.strerror})"
    with os.fdopen(fd, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            return "unreadable (not a regular file)"
        data = file.read(JOURNAL_MAX_BYTES + 1)
    if len(data) > JOURNAL_MAX_BYTES:
        return "unreadable (too large)"
    try:
        phase = json.loads(data).get("phase")
    except (ValueError, AttributeError):
        phase = None
    return phase if isinstance(phase, str) else "unreadable"


def check_no_journal(data_roots: set[str]) -> None:
    """Refuse (`Held`, nothing changed) while a host journal in any of
    `data_roots` is in any phase but idle or superseded. Such a journal is
    either an active transaction (the launcher may not be replaced, ADR
    0094 §5) or one whose launcher still reads the anchor on every start
    (HostCommitted, Restored: its binding was made against the current
    anchor bytes, so a new anchor makes that launcher refuse, exit 78)."""
    for root in sorted(data_roots):
        phase = journal_phase(root)
        if phase is not None and phase not in ANCHOR_FREE_PHASES:
            raise Held(
                f"the host journal in {root} is {phase}; the launcher, its drop-in and the "
                "plan anchor cannot change while a launcher may still read it. For an update "
                "in progress, wait until it settles: a committed update becomes idle once "
                "every instance's launcher has retired its trial, and an interrupted one "
                "becomes superseded at the next start. A restored journal stays restored: stop "
                "the install's units, move "
                f"{JOURNAL_FILE_NAME} and its upgrade-plan-binding.*.json files aside, run "
                "the install again, then start the units (docs/upgrade-system.md, 'Moving a "
                "data root to another install')"
            )


def anchor_participants(path: Path, daemon: str) -> tuple[bytes | None, dict[str, str]]:
    """The anchor's bytes (None: no file) and its participants. An anchor
    for another install at this path is refused."""
    current = read_anchor(path)
    if current is None:
        return None, {}
    data, anchor = current
    if anchor.get("daemon_target") != daemon:
        raise Refused(f"{path} anchors {anchor.get('daemon_target')}, not {daemon}; remove it")
    participants: dict[str, str] = {}
    for entry in anchor["participants"]:
        if not isinstance(entry, dict) or not {"instance_id", "data_root"} <= entry.keys():
            raise Refused(f"{path} has a malformed participant; remove it")
        participants[str(entry["instance_id"])] = str(entry["data_root"])
    return data, participants


def anchor_change(
    path: Path, daemon: str, cli: str, instance: str, root: str | None
) -> tuple[bytes | None, bytes | None]:
    """The anchor bytes before and after setting (`root`) or removing
    (`root` None) this unit's participant; None for no file. The caller
    checks the journals (`check_no_journal`) first."""
    old, participants = anchor_participants(path, daemon)
    if root is None:
        participants.pop(instance, None)
    else:
        participants[instance] = root
    return old, render_anchor(daemon, cli, participants) if participants else None


def write_anchor(path: Path, data: bytes | None) -> None:
    """Replace the anchor atomically (temporary file, fsync, rename,
    directory fsync), or remove it and fsync the directory."""
    if data is None:
        if os.path.lexists(path):
            path.unlink()
            fsync_dir(path.parent)
    else:
        replace_file(path, lambda file: file.write(data), 0o644)


def fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def install_lock(anchor_dir: Path, wait: float):
    """An exclusive lock on `<anchor dir>/.install.lock` for a whole run, so
    two runs for units of one install (which share one anchor) never
    read-modify-write the anchor at once. Waiting longer than `wait`
    seconds is refused, nothing changed."""
    path = anchor_dir / ".install.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused(f"{path} is not a regular file")
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise Held(f"another launcher install holds {path}; run again when it ends")
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)


class StageLocks:
    """The stage locks of data roots, held until `close` (#2012). Every
    producer stage holds its data root's stage lock from its anchor read to
    its Staged journal, so while the installer holds the lock of every data
    root the anchor names, before and after its change, from its journal
    check to its last anchor write, a stage either finished before the
    check (and the check sees its journal) or reads the new anchor."""

    def __init__(self, wait: float):
        self.deadline = time.monotonic() + wait
        self.fds: dict[str, int] = {}

    def take(self, roots: set[str]) -> None:
        for root in sorted(roots - self.fds.keys()):
            fd = open_stage_lock(root)
            if fd is None:
                continue
            self.fds[root] = fd
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= self.deadline:
                        raise Held(f"an update is staging in {root}; run again when it ends")
                    time.sleep(0.1)

    def close(self) -> None:
        for fd in self.fds.values():
            os.close(fd)
        self.fds.clear()


def open_stage_lock(root: str) -> int | None:
    """Open `<root>/upgrade-stage.lock`; None when the data root does not
    exist (no stage can run there). The data root is opened first as a
    directory without following a symlink, and the lock file is opened,
    created and given away relative to that handle, so the daemon's account
    cannot swap a path component for a link between the steps. A missing
    lock file is created 0600 for the data root's owner, the account the
    producer runs as. Anything but a regular file is refused."""
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise Refused(f"cannot open the data root {root} for its stage lock: {error}")
    try:
        info = os.fstat(directory)
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            fd = os.open(STAGE_LOCK_NAME, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
            try:
                os.fchown(fd, info.st_uid, info.st_gid)
                os.fchmod(fd, 0o600)
            except OSError:
                os.close(fd)
                raise
        except FileExistsError:
            try:
                fd = os.open(STAGE_LOCK_NAME, flags, dir_fd=directory)
            except OSError as error:
                raise Refused(f"cannot open the stage lock in {root}: {error}")
        except OSError as error:
            raise Refused(f"cannot create the stage lock in {root}: {error}")
    finally:
        os.close(directory)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise Refused(f"the stage lock in {root} is not a regular file")
    return fd


@contextlib.contextmanager
def stage_locks(wait: float):
    locks = StageLocks(wait)
    try:
        yield locks
    finally:
        locks.close()


def read_regular(path: Path, what: str) -> bytes | None:
    """The bytes of the regular file at `path`, opened without following a
    symlink; None when there is none. Anything else there is refused."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise Refused(f"{what} {path} cannot be read without following a link: {error}")
    with os.fdopen(fd, "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise Refused(f"{what} {path} is not a regular file")
        return file.read()


def anchored_roots(path: Path, daemon: str) -> set[str]:
    return set(anchor_participants(path, daemon)[1].values())


def reload_systemd() -> None:
    systemctl = shutil.which("systemctl")
    if systemctl is not None:
        subprocess.run([systemctl, "daemon-reload"], stdin=subprocess.DEVNULL,
                       capture_output=True, timeout=60, check=False)


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


def install_launcher(data: bytes, launcher: Path) -> None:
    replace_file(launcher, lambda file: file.write(data), 0o755)


def write_dropin(dropin: Path, text: str) -> None:
    dropin.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    replace_file(dropin, lambda file: file.write(text.encode("utf-8")), 0o644)


def lock_wait() -> float:
    try:
        return float(os.environ.get("X0X_INSTALL_LOCK_WAIT", "120"))
    except ValueError:
        return 120.0


def install(options: argparse.Namespace) -> None:
    """Every check runs before the first change. The changes then keep one
    rule at every step, a crash included: the anchor names this unit only
    while its drop-in is in place. So the unit leaves the anchor first, the
    launcher and the drop-in are written, and the unit enters the anchor
    last."""
    dropin = Path(options.dropin)
    if dropin.name != "30-x0x-launcher.conf":
        raise Refused(f"{dropin} is not a 30-x0x-launcher.conf drop-in")
    if not os.access(options.binary, os.X_OK):
        raise Refused(f"x0xd is not installed at {options.binary}")
    daemon, cli = install_targets(options.binary)
    anchor_dir = check_anchor_dir(options.anchor_dir)
    anchor = anchor_path(anchor_dir, daemon)
    launcher = Path(options.launcher)
    new_launcher = read_regular(Path(options.launcher_source), "the launcher source")
    if new_launcher is None:
        raise Refused(f"launcher not found: {options.launcher_source}")
    with install_lock(anchor_dir, lock_wait()), stage_locks(lock_wait()) as staging:
        # The unit files alone: systemd still sees the earlier drop-in.
        files = file_settings(Path(options.unit), dropin)
        account = unit_account(files.user)
        early = unit_host_root(files.exec_start, options.binary, account.pw_dir, account.pw_uid, files.user)
        staging.take(anchored_roots(anchor, daemon) | {early})
        check_no_journal(anchored_roots(anchor, daemon) | {early})
        installed = read_regular(launcher, "the installed launcher")
        previous = read_regular(dropin, "the launcher drop-in")
        old_anchor, without = anchor_change(anchor, daemon, cli, options.instance, None)
        # The first change. An error before it changes nothing at all.
        options.changed = True
        write_anchor(anchor, without)
        try:
            # systemd must not see an earlier launcher drop-in when it is asked.
            dropin.unlink(missing_ok=True)
            settings = effective_settings(Path(options.unit), dropin)
            account = unit_account(settings.user)
            text, root = render_with_root(
                settings.exec_start,
                options.binary,
                options.launcher,
                options.instance,
                account.pw_dir,
                account.pw_uid,
                settings.user,
                str(anchor),
            )
            staging.take(set(anchor_participants(anchor, daemon)[1].values()) | {early, root})
            check_no_journal(set(anchor_participants(anchor, daemon)[1].values()) | {early, root})
        except Held as held:
            # Back as it was: the drop-in first, then the anchor, then
            # systemd. A failure part way keeps the rule: the anchor is
            # restored only after the drop-in.
            try:
                if previous is not None:
                    write_dropin(dropin, previous.decode("utf-8"))
                write_anchor(anchor, old_anchor)
            except Exception as error:
                raise RestoreFailed(
                    f"{held}; restoring the drop-in and the plan anchor then failed ({error}): "
                    f"{options.instance} is out of the anchor and its drop-in may be missing"
                ) from error
            reload_systemd()
            options.changed = False
            raise
        if installed is not None and installed != new_launcher:
            install_launcher(installed, launcher.with_name(f"{launcher.name}.previous"))
        if installed != new_launcher:
            install_launcher(new_launcher, launcher)
        write_dropin(dropin, text)
        _, new = anchor_change(anchor, daemon, cli, options.instance, root)
        write_anchor(anchor, new)
    if not os.path.exists(cli):
        print(f"[install] note: no CLI at {cli}; no trial can start until it is installed",
              file=sys.stderr)


def unit_account(user: str) -> pwd.struct_passwd:
    try:
        return pwd.getpwnam(user)
    except KeyError:
        raise Refused(f"the unit's user {user} does not exist")


def anchor_of(options: argparse.Namespace) -> tuple[Path, str, str] | None:
    if not (os.path.lexists(options.binary) and os.path.isdir(options.anchor_dir)):
        return None
    daemon, cli = install_targets(options.binary)
    return anchor_path(Path(os.path.realpath(options.anchor_dir)), daemon), daemon, cli


def remove(options: argparse.Namespace) -> None:
    """Remove this unit's participant from the install's anchor, then its
    launcher drop-in (in that order, so the anchor never names an unbound
    unit). Refused, with nothing changed, while a journal of the install
    may still be read."""
    dropin = Path(options.dropin)
    if dropin.name != "30-x0x-launcher.conf":
        raise Refused(f"{dropin} is not a 30-x0x-launcher.conf drop-in")
    found = anchor_of(options)
    if found is not None:
        anchor, daemon, cli = found
        with install_lock(anchor.parent, lock_wait()), stage_locks(lock_wait()) as staging:
            old, new = anchor_change(anchor, daemon, cli, options.instance, None)
            if new != old:
                staging.take(anchored_roots(anchor, daemon))
                check_no_journal(anchored_roots(anchor, daemon))
                write_anchor(anchor, new)
            dropin.unlink(missing_ok=True)
    else:
        dropin.unlink(missing_ok=True)


def forget(options: argparse.Namespace) -> None:
    """After a failed install that removed the drop-in: take this unit out
    of the anchor too, so the anchor never names a unit that is not bound.
    This runs whatever the journals say: a launcher that then refuses a
    binding (exit 78) fails closed, while an anchor that names an unbound
    unit could let a trial leave that unit unsupervised."""
    found = anchor_of(options)
    if found is None:
        return
    anchor, daemon, cli = found
    with install_lock(anchor.parent, lock_wait()):
        old, new = anchor_change(anchor, daemon, cli, options.instance, None)
        if new != old:
            write_anchor(anchor, new)
            print(f"[install] removed {options.instance} from the plan anchor {anchor}",
                  file=sys.stderr)


def failed(options: argparse.Namespace, error: Exception) -> int:
    """An install that failed after its first change. The unit leaves the
    anchor FIRST (`forget`), and only then is the drop-in removed, so a
    crash between the two, or a `forget` that fails, never leaves the anchor
    naming an unbound unit. If `forget` fails, the drop-in stays: the unit
    is still bound and still anchored (exit 4)."""
    detail = str(error) if isinstance(error, Refused) else f"{type(error).__name__}: {error}"
    print(f"error: {detail}", file=sys.stderr)
    try:
        forget(options)
    except Exception as cleanup:
        print(
            f"error: cannot take {options.instance} out of the plan anchor ({cleanup}); the "
            "launcher drop-in is left as it is, so the anchor names the unit only while its "
            "drop-in is in place. Fix the cause and run the install again.",
            file=sys.stderr,
        )
        return 4
    dropin = Path(options.dropin)
    try:
        dropin.unlink(missing_ok=True)
    except OSError as cleanup:
        print(f"error: cannot remove {dropin}: {cleanup}", file=sys.stderr)
        return 4
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Install x0x-launcher and its systemd drop-in for one instance."
    )
    parser.add_argument("--unit", help="the instance's installed unit file")
    parser.add_argument("--binary", required=True, help="the installed x0xd path")
    parser.add_argument("--launcher-source", help="the x0x-launcher to install")
    parser.add_argument("--launcher", help="where to install the launcher")
    parser.add_argument("--instance", required=True, help="the manifest instance id")
    parser.add_argument("--dropin", required=True, help="the drop-in path to write")
    parser.add_argument(
        "--anchor-dir", default=DEFAULT_ANCHOR_DIR, help="the directory of the plan anchors"
    )
    parser.add_argument(
        "--remove", action="store_true", help="remove the drop-in and this unit's participant"
    )
    options = parser.parse_args()
    if options.remove:
        try:
            remove(options)
        except Exception as error:
            detail = str(error) if isinstance(error, Refused) else f"{type(error).__name__}: {error}"
            print(f"error: {detail}", file=sys.stderr)
            return 2 if isinstance(error, Held) else 1
        print(f"[install] removed launcher drop-in: {options.dropin}")
        return 0
    if not (options.unit and options.launcher_source and options.launcher):
        parser.error("--unit, --launcher-source and --launcher are required to install")
    options.changed = False
    try:
        install(options)
    except Held as error:
        if not options.changed:
            print(f"error: {error}", file=sys.stderr)
            return 2
        return failed(options, error)
    except Exception as error:
        if not options.changed:
            detail = str(error) if isinstance(error, Refused) else f"{type(error).__name__}: {error}"
            print(f"error: {detail}", file=sys.stderr)
            print("error: the launcher step failed before its first change; nothing changed",
                  file=sys.stderr)
            return 2
        return failed(options, error)
    print(f"[install] launcher drop-in: {options.dropin}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
