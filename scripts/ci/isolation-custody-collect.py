#!/usr/bin/env python3
"""Closed collector for issue #417 isolation custody and cleanup receipts.

The wrapper chain writes its receipts into `$RUNNER_TEMP`, which dies with the
runner, so the only evidence a reviewer can otherwise reach is the free-text
job log. This turns those receipts into one small, strictly typed, uploadable
artifact.

Closed by construction, in four senses:

1. **Exclusive output.** The output directory is created exclusively (no
   `exist_ok`, no symlink follow) and the receipt is created `O_EXCL |
   O_NOFOLLOW`. A pre-existing file, directory or symlink at the predictable
   path is a hard failure. The workflow uploads only after this process emits
   its fixed `receipt_eligible=true` output, so a stale path is not eligible.

2. **Closed input allowlist.** Six generated files are read and nothing else
   in `$RUNNER_TEMP` is touched. `runtime.json`, `cargo.json` and
   `binaries.json` are never read — they carry argv, the inherited
   environment and absolute build paths.

3. **Closed schemas.** Every admitted receipt is validated against exact key
   sets, exact Python types (a `bool` is rejected where an `int` is required),
   closed enums, hex-40/hex-64 formats and normalised relative paths. An
   arbitrary string cannot reach the artifact.

4. **Bound roles.** Each isolated run carries a public role stamped by the
   wrapper, and the acceptance run is bound to the exact build-custody
   scratch it consumed and to the executed test target.

Sources (see `isolated-runtime.py`, `nextest-isolated.sh`, `nextest-reuse.py`):

  $RUNNER_TEMP/x0x-isolation-*/role.json        public role + scratch binding
  $RUNNER_TEMP/x0x-isolation-*/admission.json   namespace admission state
  $RUNNER_TEMP/x0x-isolation-*/supervisor.json  teardown/cleanup receipt
  $RUNNER_TEMP/x0x-isolation-*/exit.json        admitted command exit
  $RUNNER_TEMP/x0x-metadata-*/custody.json      build-input hashes + source
  $RUNNER_TEMP/x0x-metadata-*/lock.sha256       Cargo.lock digest

Every record is validated independently, so a malformed later receipt never
discards an earlier valid one. Failures are reported as closed
`(stage, code)` pairs; parser exception text derived from receipt content is
never emitted.

Exit status: non-zero when the job otherwise succeeded but any receipt is
missing, malformed or unbound — a green test run cannot be reported without
its custody. When the job is already failing, valid records and closed error
codes are retained and the collector exits 0 rather than masking the real
failure.
"""
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

SCHEMA = "x0x.isolation-custody/2"

HEX40 = re.compile(r"\A[0-9a-f]{40}\Z")
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
HEX16 = re.compile(r"\A[0-9a-f]{16}\Z")
NAMESPACE = re.compile(r"\Anet:\[[0-9]{1,20}\]\Z")
IFNAME = re.compile(r"\A[a-z0-9_.-]{1,15}\Z")
SAFE_PATH = re.compile(r"\A[A-Za-z0-9._][A-Za-z0-9._/-]{0,255}\Z")
SCRATCH_NAME = re.compile(r"\Ax0x-metadata-[A-Za-z0-9_.-]{1,64}\Z")
EVIDENCE_NAME = re.compile(r"\Ax0x-isolation-[A-Za-z0-9_.-]{1,64}\Z")
LOCK_LINE = re.compile(r"\A([0-9a-f]{64})[ \t]+\*?Cargo\.lock\Z")
ROLE = re.compile(r"\A[a-z][a-z0-9-]{0,31}\Z")

# `isolated-runtime.py::supervise` writes exactly these cancellation reasons.
SUPERVISOR_REASONS = (None, "signal", "deadline", "caller-pipe-closed")
CAPABILITY_KEYS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
# `nextest-reuse.py::inputs` always contributes exactly these three.
NON_BINARY_INPUTS = ("Cargo.lock", "binaries.json", "cargo.json")

# Substrings that must never appear in the emitted receipt.
LEAK_MARKERS = ("/home/", "/Users/", "/root/", "/tmp/",
                "ghp_", "ghs_", "github_pat_", "-----BEGIN")
LEAK_ENV_KEYS = ("RUNNER_TEMP", "GITHUB_WORKSPACE", "HOME", "CARGO_HOME",
                 "RUSTUP_HOME", "GITHUB_TOKEN", "X0X_API_TOKEN")

STAGES = ("output", "isolation", "build_custody", "job")
CODES = (
    "OUTPUT_NOT_EXCLUSIVE", "OUTPUT_NOT_EMPTY",
    "RECEIPT_MISSING", "RECEIPT_UNPARSEABLE",
    "SCHEMA_KEYS", "SCHEMA_TYPE", "SCHEMA_VALUE",
    "ADMISSION_INTERFACE", "ADMISSION_ROUTE", "ADMISSION_CAPABILITIES",
    "ADMISSION_UID", "ADMISSION_NO_NEW_PRIVS", "ADMISSION_NAMESPACE",
    "EXIT_MISSING", "EXIT_NONZERO",
    "SUPERVISOR_CANCELLED", "SUPERVISOR_UNREAPED",
    "ROLE_SET_MISMATCH", "ACCEPTANCE_BINDING", "SCRATCH_COUNT",
    "RUN_COUNT",
    "CUSTODY_SOURCE", "CUSTODY_LOCK", "CUSTODY_INPUTS", "CUSTODY_TARGET",
    "PATH_UNSAFE", "LEAK_GUARD",
)


class Rejected(Exception):
    """A receipt is missing, malformed, or does not say what it must say."""

    def __init__(self, code, where=""):
        assert code in CODES, code
        super().__init__(code)
        self.code = code
        self.where = where


# ---------------------------------------------------------------- typing ----
def as_int(value, code="SCHEMA_TYPE"):
    # `isinstance(True, int)` is True in Python; a bool must never satisfy an
    # int field, or `exit: false` reads as a successful exit.
    if isinstance(value, bool) or not isinstance(value, int):
        raise Rejected(code)
    return value


def as_bool(value):
    if not isinstance(value, bool):
        raise Rejected("SCHEMA_TYPE")
    return value


def as_number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Rejected("SCHEMA_TYPE")
    return float(value)


def as_match(value, pattern, code="SCHEMA_VALUE"):
    if not isinstance(value, str):
        raise Rejected("SCHEMA_TYPE")
    if not pattern.match(value):
        raise Rejected(code)
    return value


def exact_keys(mapping, keys, optional=()):
    if not isinstance(mapping, dict):
        raise Rejected("SCHEMA_TYPE")
    present = set(mapping)
    if not set(keys) <= present or not present <= set(keys) | set(optional):
        raise Rejected("SCHEMA_KEYS")
    return mapping


def safe_path(raw, workspace):
    """Repo-relative when inside the checkout, else bare basename.

    Absolute paths identify the runner's directory layout and the caller's
    home; neither is needed to review custody, and both are exactly what the
    artifact must not carry. The result is re-checked against `SAFE_PATH`, so
    a hostile basename cannot smuggle arbitrary bytes into the receipt.
    """
    if not isinstance(raw, str):
        raise Rejected("SCHEMA_TYPE")
    path = Path(raw)
    relative = None
    if workspace is not None:
        try:
            relative = path.relative_to(workspace).as_posix()
        except ValueError:
            relative = None
    candidate = relative if relative is not None else path.name
    if ".." in Path(candidate).parts:
        raise Rejected("PATH_UNSAFE")
    return as_match(candidate, SAFE_PATH, "PATH_UNSAFE")


def executable_target_path(raw, workspace):
    """Return a repo-relative executable path under this checkout's target."""
    if workspace is None:
        raise Rejected("CUSTODY_TARGET")
    candidate = Path(raw)
    try:
        workspace_root = workspace.resolve(strict=True)
        target_root = (workspace_root / "target").resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        info = os.lstat(candidate)
    except (OSError, RuntimeError) as error:
        raise Rejected("CUSTODY_TARGET") from error
    if not resolved.is_relative_to(target_root):
        raise Rejected("CUSTODY_TARGET")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise Rejected("CUSTODY_TARGET")
    if not (info.st_mode & 0o111):
        raise Rejected("CUSTODY_TARGET")
    try:
        relative = resolved.relative_to(workspace_root).as_posix()
    except ValueError as error:
        raise Rejected("CUSTODY_TARGET") from error
    return as_match(relative, SAFE_PATH, "CUSTODY_TARGET")


def read_json(path):
    try:
        raw = path.read_text()
    except (OSError, UnicodeError) as error:
        raise Rejected("RECEIPT_MISSING", path.name) from error
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        # The decoder message quotes the offending bytes; never propagate it.
        raise Rejected("RECEIPT_UNPARSEABLE", path.name) from error


# --------------------------------------------------------------- records ----
def role_facts(directory, allowed_roles):
    raw = exact_keys(read_json(directory / "role.json"), ("role", "scratch"))
    role = as_match(raw["role"], ROLE)
    if role not in allowed_roles:
        raise Rejected("ROLE_SET_MISMATCH")
    scratch = raw["scratch"]
    if scratch is not None:
        scratch = as_match(scratch, SCRATCH_NAME)
    return {"role": role, "scratch": scratch}


def admission_facts(directory):
    raw = exact_keys(
        read_json(directory / "admission.json"),
        ("namespace", "links", "routes", "uid", "gid", "capabilities", "no_new_privs", "namespace_changed"),
    )
    if not isinstance(raw["links"], list) or not isinstance(raw["routes"], dict):
        raise Rejected("SCHEMA_TYPE")
    exact_keys(raw["routes"], ("-4", "-6"))
    interfaces = [as_match(link.get("ifname"), IFNAME, "ADMISSION_INTERFACE")
                  for link in raw["links"] if isinstance(link, dict)]
    if len(interfaces) != len(raw["links"]) or interfaces != ["lo"]:
        raise Rejected("ADMISSION_INTERFACE")

    routes = []
    for rows in raw["routes"].values():
        if not isinstance(rows, list):
            raise Rejected("SCHEMA_TYPE")
        for row in rows:
            if not isinstance(row, dict):
                raise Rejected("SCHEMA_TYPE")
            routes.append(row)
    for row in routes:
        if row.get("dev") != "lo" or row.get("dst") == "default" or "gateway" in row:
            raise Rejected("ADMISSION_ROUTE")

    if as_int(raw["uid"], "ADMISSION_UID") <= 0:
        raise Rejected("ADMISSION_UID")
    if as_int(raw["gid"]) <= 0:
        raise Rejected("ADMISSION_UID")
    if as_int(raw["no_new_privs"], "ADMISSION_NO_NEW_PRIVS") != 1:
        raise Rejected("ADMISSION_NO_NEW_PRIVS")
    if raw["namespace_changed"] is not True:
        raise Rejected("ADMISSION_NAMESPACE")
    as_match(raw["namespace"], NAMESPACE)

    capabilities = exact_keys(raw["capabilities"], CAPABILITY_KEYS)
    for key in CAPABILITY_KEYS:
        if int(as_match(capabilities[key], HEX16, "ADMISSION_CAPABILITIES"), 16) != 0:
            raise Rejected("ADMISSION_CAPABILITIES")

    return {
        "namespace_changed": True,
        "interfaces": interfaces,
        "route_count": len(routes),
        "all_routes_dev_lo": True,
        "no_default_route": True,
        "no_gateway_route": True,
        "unprivileged_uid": True,
        "no_new_privs": 1,
        "capability_sets_empty": True,
    }


def supervisor_facts(directory):
    raw = exact_keys(
        read_json(directory / "supervisor.json"),
        ("reason", "child_pid", "child_exit", "child_reaped", "seconds"),
    )
    reason = raw["reason"]
    if reason is not None:
        as_match(reason, ROLE)
    if reason not in SUPERVISOR_REASONS:
        raise Rejected("SCHEMA_VALUE")
    if as_int(raw["child_pid"]) <= 0:  # validated, then deliberately dropped
        raise Rejected("SCHEMA_VALUE")
    child_exit = as_int(raw["child_exit"])
    seconds = as_number(raw["seconds"])
    if seconds < 0 or not math.isfinite(seconds):
        raise Rejected("SCHEMA_VALUE")
    return {
        "reason": reason,
        "child_exit": child_exit,
        "child_reaped": as_bool(raw["child_reaped"]),
        "seconds": round(seconds, 1),
    }


def exit_facts(directory):
    receipt = directory / "exit.json"
    if receipt.is_symlink():
        raise Rejected("RECEIPT_MISSING")
    if not receipt.is_file():
        return None
    return as_int(exact_keys(read_json(receipt), ("exit",))["exit"], "SCHEMA_TYPE")


def isolation_record(directory, require_success, allowed_roles, workspace):
    """Validate one isolated run in full. Raises `Rejected` with a closed code."""
    record = {
        "evidence": as_match(directory.name, EVIDENCE_NAME, "PATH_UNSAFE"),
        "role": role_facts(directory, allowed_roles),
        "admission": admission_facts(directory),
        "supervisor": supervisor_facts(directory),
        "exit": exit_facts(directory),
    }
    if require_success:
        if record["exit"] is None:
            raise Rejected("EXIT_MISSING")
        if record["exit"] != 0:
            raise Rejected("EXIT_NONZERO")
        if record["supervisor"]["reason"] is not None:
            raise Rejected("SUPERVISOR_CANCELLED")
        if not record["supervisor"]["child_reaped"]:
            raise Rejected("SUPERVISOR_UNREAPED")
    safe_path(str(workspace or "."), workspace)  # workspace itself must normalise
    return record


def custody_record(directory, github_sha, target, workspace):
    raw = exact_keys(read_json(directory / "custody.json"), ("files", "source"))
    source = raw["source"]
    if not isinstance(source, list) or len(source) != 2:
        raise Rejected("CUSTODY_SOURCE")
    head = as_match(source[0], HEX40, "CUSTODY_SOURCE")
    tree = as_match(source[1], HEX40, "CUSTODY_SOURCE")
    if github_sha and head != github_sha:
        raise Rejected("CUSTODY_SOURCE")

    files = raw["files"]
    if not isinstance(files, dict) or not files:
        raise Rejected("CUSTODY_INPUTS")
    inputs = {}
    for path, digest in sorted(files.items()):
        input_path = Path(path)
        safe = safe_path(path, workspace)
        digest = as_match(digest, HEX64, "CUSTODY_INPUTS")
        if safe in NON_BINARY_INPUTS:
            try:
                resolved = input_path.resolve(strict=True)
            except OSError as error:
                raise Rejected("CUSTODY_INPUTS") from error
            if safe == "Cargo.lock":
                expected = (workspace / safe).resolve() if workspace else None
            else:
                expected = (directory / safe).resolve()
            if expected is None or resolved != expected:
                raise Rejected("CUSTODY_INPUTS")
        else:
            safe = executable_target_path(path, workspace)
        if safe in inputs:
            raise Rejected("CUSTODY_INPUTS")
        inputs[safe] = digest
    if len(inputs) != len(files):
        raise Rejected("CUSTODY_INPUTS")
    # The three non-binary inputs must be present by exact identity, not by
    # counting: `len(files) - 3` would label any other entry a test binary.
    for required in NON_BINARY_INPUTS:
        if required not in inputs:
            raise Rejected("CUSTODY_INPUTS")
    binaries = sorted(set(inputs) - set(NON_BINARY_INPUTS))
    if not binaries:
        raise Rejected("CUSTODY_INPUTS")
    # Bind the retained binary set to the target the job actually executed.
    target_binary = re.compile(r"\A(?:.*/)?" + re.escape(target) + r"-[0-9a-f]{8,32}\Z")
    executed = [name for name in binaries if target_binary.match(name)]
    if not executed:
        raise Rejected("CUSTODY_TARGET")

    try:
        lock_line = (directory / "lock.sha256").read_text().strip()
    except (OSError, UnicodeError) as error:
        raise Rejected("CUSTODY_LOCK") from error
    matched = LOCK_LINE.match(lock_line)
    if matched is None:
        raise Rejected("CUSTODY_LOCK")
    if inputs.get("Cargo.lock") != matched.group(1):
        raise Rejected("CUSTODY_LOCK")
    if not github_sha or head != github_sha:
        raise Rejected("CUSTODY_SOURCE")

    return {
        "scratch": as_match(directory.name, SCRATCH_NAME, "PATH_UNSAFE"),
        "source_head": head,
        "source_tree": tree,
        "matches_event_commit": True,
        "lock_sha256": matched.group(1),
        "target": as_match(target, SAFE_PATH, "CUSTODY_TARGET"),
        "target_binaries": executed,
        "input_count": len(inputs),
        "inputs": inputs,
    }


# ----------------------------------------------------------------- output ----
def assert_no_leak(receipt):
    """Refuse to emit absolute paths, runner layout or credential markers."""
    text = json.dumps(receipt)
    for marker in LEAK_MARKERS:
        if marker in text:
            raise Rejected("LEAK_GUARD", marker)
    for key in LEAK_ENV_KEYS:
        value = os.environ.get(key)
        if value and value in text:
            raise Rejected("LEAK_GUARD", f"${key}")


def exclusive_output(directory):
    """Create the output directory exclusively; never adopt what is there.

    `mkdir(exist_ok=True)` would adopt a pre-existing directory — or a symlink
    to one — and any raw file already inside it would be uploaded alongside
    the receipt. `mkdir()` without `exist_ok` fails on a file, a directory and
    a symlink alike.
    """
    try:
        directory.mkdir(parents=True)
    except (FileExistsError, NotADirectoryError) as error:
        raise Rejected("OUTPUT_NOT_EXCLUSIVE", directory.name) from error
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode):
        raise Rejected("OUTPUT_NOT_EXCLUSIVE", directory.name)
    if any(directory.iterdir()):
        raise Rejected("OUTPUT_NOT_EMPTY", directory.name)
    return directory


def write_receipt(directory, receipt):
    """Create the sole receipt atomically, refusing to follow a symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    handle = os.open(directory / "custody-receipt.json", flags, 0o600)
    with os.fdopen(handle, "w") as output:
        output.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    entries = sorted(entry.name for entry in directory.iterdir())
    if entries != ["custody-receipt.json"]:
        raise Rejected("OUTPUT_NOT_EMPTY", directory.name)


def mark_upload_eligible():
    """Tell Actions that the exact receipt path was created and validated."""
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        return
    with Path(output).open("a", encoding="ascii") as stream:
        stream.write("receipt_eligible=true\n")


def error(stage, code, where=""):
    assert stage in STAGES and code in CODES, (stage, code)
    return {"stage": stage, "code": code, "where": where}


def collect(runner_temp, expect, github_sha, workspace, roles, target, min_runs):
    """Validate every record independently; never discard a valid one."""
    require_success = expect == "success"
    receipt = {
        "schema": SCHEMA,
        "expect": expect if expect in ("success", "failure", "cancelled") else "unknown",
        "expected_roles": sorted(roles),
        "target": target,
        "minimum_runs": min_runs,
        "isolation_runs": [],
        "build_custody": [],
        "errors": [],
    }

    isolation_candidates = sorted(runner_temp.glob("x0x-isolation-*"))
    metadata_candidates = sorted(runner_temp.glob("x0x-metadata-*"))
    isolation_dirs = [p for p in isolation_candidates if p.is_dir() and not p.is_symlink()]
    metadata_dirs = [p for p in metadata_candidates if p.is_dir() and not p.is_symlink()]
    receipt["isolation_run_count"] = len(isolation_dirs)
    receipt["build_custody_count"] = len(metadata_dirs)
    if len(isolation_dirs) < min_runs:
        receipt["errors"].append(error("job", "RUN_COUNT"))
    for path in isolation_candidates:
        if path not in isolation_dirs:
            receipt["errors"].append(error("isolation", "PATH_UNSAFE"))
    for path in metadata_candidates:
        if path not in metadata_dirs:
            receipt["errors"].append(error("build_custody", "PATH_UNSAFE"))

    for directory in isolation_dirs:
        try:
            record = isolation_record(directory, require_success, roles, workspace)
            receipt["isolation_runs"].append(record)
            if not require_success:
                if record["exit"] is None:
                    receipt["errors"].append(error("isolation", "EXIT_MISSING"))
                elif record["exit"] != 0:
                    receipt["errors"].append(error("isolation", "EXIT_NONZERO"))
                if record["supervisor"]["reason"] is not None:
                    receipt["errors"].append(error("isolation", "SUPERVISOR_CANCELLED"))
                if not record["supervisor"]["child_reaped"]:
                    receipt["errors"].append(error("isolation", "SUPERVISOR_UNREAPED"))
        except Rejected as rejected:
            receipt["errors"].append(error("isolation", rejected.code, rejected.where))
    for directory in metadata_dirs:
        try:
            receipt["build_custody"].append(
                custody_record(directory, github_sha, target, workspace))
        except Rejected as rejected:
            receipt["errors"].append(error("build_custody", rejected.code, rejected.where))

    # Role and binding requirements are job-level, so they are evaluated after
    # every individually valid record has already been retained.
    observed = sorted(run["role"]["role"] for run in receipt["isolation_runs"])
    receipt["observed_roles"] = observed
    if observed != sorted(roles):
        receipt["errors"].append(error("job", "ROLE_SET_MISMATCH"))
    if len(metadata_dirs) != 1 or len(receipt["build_custody"]) != 1:
        receipt["errors"].append(error("job", "SCRATCH_COUNT"))
    elif "acceptance" in roles:
        scratch = receipt["build_custody"][0]["scratch"]
        bound = [run for run in receipt["isolation_runs"]
                 if run["role"]["role"] == "acceptance"
                 and run["role"]["scratch"] == scratch]
        if len(bound) != 1:
            receipt["errors"].append(error("job", "ACCEPTANCE_BINDING"))

    receipt["valid"] = not receipt["errors"]
    receipt["status"] = "complete" if receipt["valid"] else "incomplete"
    return receipt


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: isolation-custody-collect.py OUTPUT_DIR")
    output = Path(sys.argv[1])
    runner_temp = Path(os.environ["RUNNER_TEMP"])
    workspace = os.environ.get("GITHUB_WORKSPACE")
    workspace = Path(workspace) if workspace else None
    expect = os.environ.get("X0X_CUSTODY_EXPECT", "success").lower()
    if expect not in ("success", "failure", "cancelled"):
        raise SystemExit("custody collector: SCHEMA_VALUE")
    min_runs_raw = os.environ.get("X0X_CUSTODY_MIN_RUNS", "1")
    if not re.fullmatch(r"[1-9][0-9]{0,3}", min_runs_raw):
        raise SystemExit("custody collector: SCHEMA_VALUE")
    min_runs = int(min_runs_raw)
    github_sha = os.environ.get("GITHUB_SHA", "")
    target = os.environ.get("X0X_CUSTODY_TARGET", "")
    roles_raw = [role for role in os.environ.get("X0X_CUSTODY_ROLES", "").split(",") if role]
    roles = sorted(roles_raw)
    if not target or not roles:
        raise SystemExit(
            "custody collector: X0X_CUSTODY_TARGET and X0X_CUSTODY_ROLES are required")
    try:
        target = as_match(target, SAFE_PATH, "CUSTODY_TARGET")
        if len(set(roles)) != len(roles):
            raise Rejected("ROLE_SET_MISMATCH")
        for role in roles:
            as_match(role, ROLE, "ROLE_SET_MISMATCH")
    except Rejected as rejected:
        raise SystemExit(f"custody collector: {rejected.code}")

    # Exclusive output first: a compromised output path must fail before any
    # receipt content is produced, and before the uploader can see anything.
    try:
        exclusive_output(output)
    except Rejected as rejected:
        raise SystemExit(f"custody collector: {rejected.code} ({rejected.where})")

    receipt = collect(runner_temp, expect, github_sha, workspace, roles, target, min_runs)
    try:
        assert_no_leak(receipt)
    except Rejected as leak:
        write_receipt(output, {"schema": SCHEMA, "status": "withheld", "valid": False,
                               "errors": [error("output", leak.code, leak.where)]})
        mark_upload_eligible()
        raise SystemExit(f"custody collector: {leak.code} ({leak.where})")
    write_receipt(output, receipt)
    mark_upload_eligible()

    summary = {"status": receipt["status"], "valid": receipt["valid"],
               "isolation_runs": receipt["isolation_run_count"],
               "build_custody": receipt["build_custody_count"],
               "observed_roles": receipt["observed_roles"],
               "errors": [f"{item['stage']}:{item['code']}" for item in receipt["errors"]]}
    print(json.dumps(summary), flush=True)
    if receipt["errors"] and expect == "success":
        raise SystemExit("custody collector: "
                         + ",".join(f"{i['stage']}:{i['code']}" for i in receipt["errors"]))


if __name__ == "__main__":
    main()
