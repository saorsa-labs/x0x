#!/usr/bin/env python3
"""#703 caller-and-adapter optimized test-profile 100k diagnostic runner
(ephemeral Linux CI only). Experiment, not a proven fix.

Runs the exact ignored test
  gossip::pubsub::tests::test_slow_subscriber_isolated_at_100k_messages
at source commit 27a3354d44d59986e83a2e29ff7c0c6569634e7a with the plain
cargo test command (no --release), once, inside a fresh loopback-only
network namespace, with the original 100_000 message count and all
original assertions unchanged.

The only manifest delta vs the base tree is package-specific opt-level 3
for the sampled keccak primitive, fips204, its concrete saorsa-pqc and
ant-quic signing adapters, and the x0x test target itself (authorized upper control), which this script
verifies exactly (no arbitrary Cargo.toml edits), and it retains the full
verbose rustc invocations so the profile proof — keccak, all three signing-path
crates, plus the single x0x `--test` invocation compiled with
-C opt-level=3 — can be verified from the artifacts.

Phases:
  outer  (default)  : verify tree/source/Cargo delta, generate+hash lock,
                      build (plain cargo test, verbose), select the
                      exact libtest binary, capture profile evidence,
                      then re-exec into the netns.
  inner  (--inner)  : already inside the netns as the original runner
                      UID/GID; run the single bounded 600s execution and
                      verify the proof.
  self-test         : deterministic offline checks of artifact selection,
                      proof verification, custody, Cargo-delta parsing,
                      profile evidence, and exit-code mapping. No cargo,
                      no namespaces, safe on any host.

HOME is never overridden, redirected, or deleted anywhere in this script.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import ctypes
import shutil
import shlex
import subprocess
import sys
import time
from pathlib import Path

BASE_COMMIT = "27a3354d44d59986e83a2e29ff7c0c6569634e7a"
BASE_TREE = "ab8412cbdd86ddec97f86a6a384aab34d30cbc39"
SOURCE_PATH = "src/gossip/pubsub.rs"
SOURCE_SHA256 = "5ad301d726732027cc2ca9026db58d0dbca27ad70a1327b16b7a5f7d512f6c42"
SELECTOR = "gossip::pubsub::tests::test_slow_subscriber_isolated_at_100k_messages"
EXPECTED_MESSAGES = 100_000

PROFILE_LABEL = "caller-and-adapter-optimized-test-profile"

# The ONLY permitted Cargo.toml change vs base: five package-specific
# overrides (the sampled primitive, three signing-path adapters, and the x0x test target as
# authorized upper control), added exactly as prescribed (no removals).
EXPECTED_CARGO_ADDITIONS = [
    "# #703: caller-and-adapter optimized test profile (experiment). Optimize the",
    "# sampled Keccak primitive, concrete ML-DSA adapter path (fips204, saorsa-pqc,",
    "# ant-quic), and x0x test target itself; workspace-wide dev/test profiles and",
    "# every release profile stay untouched.",
    "[profile.test.package.keccak]",
    "opt-level = 3",
    "",
    "[profile.test.package.fips204]",
    "opt-level = 3",
    "",
    "[profile.test.package.saorsa-pqc]",
    "opt-level = 3",
    "",
    "[profile.test.package.ant-quic]",
    "opt-level = 3",
    "",
    "[profile.test.package.x0x]",
    "opt-level = 3",
    "",
]

# 600 s outer bound (reported default-profile ceiling bound), then TERM,
# then KILL after a grace period. No automatic retry or extension.
OUTER_TIMEOUT_SECONDS = 600
TERM_GRACE_SECONDS = 10
# Hosted run 34920522172 produced a 501,261,776-byte DWARF recording. The
# generic 10-second process grace killed perf before it could finalize that
# file, so recorder shutdown gets a separate bound without extending the
# unchanged 600-second test deadline.
PERF_FINALIZE_GRACE_SECONDS = 120
PERF_REPORT_TIMEOUT_SECONDS = 180
# Worst case: TERM communicate, KILL communicate, then the final bounded wait
# after closing the owned pipe.
PERF_REPORT_CLEANUP_GRACE_SECONDS = 3 * TERM_GRACE_SECONDS
BOOKKEEPING_GRACE_SECONDS = 30
# The privileged launcher does not finish until the bounded test, its TERM
# grace, perf finalization, both sequential reports, and final bookkeeping do.
INNER_COMPLETION_TIMEOUT_SECONDS = (
    OUTER_TIMEOUT_SECONDS
    + TERM_GRACE_SECONDS
    + PERF_FINALIZE_GRACE_SECONDS
    + 2 * (PERF_REPORT_TIMEOUT_SECONDS + PERF_REPORT_CLEANUP_GRACE_SECONDS)
    + BOOKKEEPING_GRACE_SECONDS
)
# If the outer phase is interrupted, SIGTERM makes the observer helper unwind
# through its finally block. Keep that helper alive long enough to finalize perf.
OBSERVER_HELPER_CLEANUP_GRACE_SECONDS = (
    PERF_FINALIZE_GRACE_SECONDS + BOOKKEEPING_GRACE_SECONDS
)

INNER_FLAG_ENV = "X0X_703_INNER"
INNER_RESULT_NAME = "inner-result.json"
REPORT_NAME = "run-report.json"
PERF_DATA_NAME = "perf.data"
TARGET_RECORD_NAME = "target-record.json"
OBSERVER_READY_NAME = "observer-ready.json"
TEST_BINARY_ARTIFACT_NAME = "test-binary"


def output_bytes(value) -> bytes:
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode(errors="replace")


def run_perf_report(perf_data: Path, output_path: Path, mode_args: list[str],
                    timeout: float = PERF_REPORT_TIMEOUT_SECONDS,
                    cleanup_grace: float = TERM_GRACE_SECONDS,
                    popen=subprocess.Popen) -> dict:
    """Run one owned perf report and retain output, including on timeout."""
    argv = [
        "perf", "report", "--stdio", *mode_args, "--max-stack", "32",
        "--no-inline", "--percent-limit", "0.5", "-i", str(perf_data),
    ]
    proc = popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    timed_out = False
    forced_kill = False
    cleanup_error = None
    partial = b""
    try:
        final, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        partial = output_bytes(error.output)
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            final, _ = proc.communicate(timeout=cleanup_grace)
        except subprocess.TimeoutExpired as error:
            forced_kill = True
            later = output_bytes(error.output)
            if len(later) > len(partial):
                partial = later
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                final, _ = proc.communicate(timeout=cleanup_grace)
            except subprocess.TimeoutExpired as error:
                later = output_bytes(error.output)
                if len(later) > len(partial):
                    partial = later
                cleanup_error = "report process did not reap after SIGKILL"
                if proc.stdout is not None:
                    proc.stdout.close()
                try:
                    proc.wait(timeout=cleanup_grace)
                except subprocess.TimeoutExpired:
                    cleanup_error += "; bounded final wait expired"
                final = b""
    final_bytes = output_bytes(final)
    retained = final_bytes if len(final_bytes) >= len(partial) else partial + final_bytes
    output_path.write_bytes(retained)
    text = retained.decode(errors="replace")
    return {
        "argv": argv,
        "native_exit": proc.returncode,
        "has_samples": report_has_samples(text),
        "timed_out": timed_out,
        "forced_kill": forced_kill,
        "output_bytes": len(retained),
        "cleanup_error": cleanup_error,
    }


def perf_precheck(artifact_dir: Path, *, perf: str | None = None, command=None) -> dict:
    """Prove unprivileged sampling works before paying the build cost."""
    command = run if command is None else command
    executable = perf if perf is not None else shutil.which("perf")
    evidence = {"executable": executable, "ok": False}
    if executable is None:
        evidence["reason"] = "perf executable unavailable"
        return evidence
    try:
        version = command(
            [executable, "version"], capture_output=True, text=True, timeout=10
        )
    except subprocess.TimeoutExpired:
        evidence["reason"] = "perf version precheck timed out"
        return evidence
    probe = artifact_dir / "perf-precheck.data"
    try:
        capture = command(
            ["sudo", "--preserve-env=HOME,PATH", "--", sys.executable,
             str(Path(__file__).resolve()), "--perf-precheck-helper", "--precheck-output",
             str(probe), "--perf-executable", executable],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        evidence["reason"] = "perf capture precheck timed out"
        return evidence
    evidence.update({
        "version_exit": version.returncode,
        "version_stdout": version.stdout,
        "version_stderr": version.stderr,
        "capture_exit": capture.returncode,
        "capture_stdout": capture.stdout,
        "capture_stderr": capture.stderr,
        "capture_bytes": probe.stat().st_size if probe.exists() else 0,
    })
    evidence["ok"] = (
        version.returncode == 0
        and capture.returncode == 0
        and evidence["capture_bytes"] > 0
    )
    if not evidence["ok"]:
        evidence["reason"] = "bounded privileged perf capture unavailable"
    return evidence


def report_has_samples(text: str) -> bool:
    for line in text.splitlines():
        match = re.match(r"^\s*(\d+(?:\.\d+)?)%", line)
        if match is not None and float(match.group(1)) > 0:
            return True
    return False


def profiling_status(test_exit: int, perf_exit: int, timed_out: bool,
                     data_bytes: int, reports: dict) -> dict:
    reports_ok = set(reports) == {"self", "children"} and all(
        row.get("native_exit") == 0
        and row.get("has_samples") is True
        and not row.get("timed_out", False)
        and row.get("cleanup_error") is None
        for row in reports.values()
    )
    capture_ok = data_bytes > 0 and perf_exit == 0 and reports_ok
    return {
        "capture_ok": capture_ok,
        "test_ok": test_exit == 0 and not timed_out,
        "timed_out": timed_out,
        "test_native_exit": test_exit,
        "perf_capture_exit": perf_exit,
        "data_bytes": data_bytes,
        "reports_ok": reports_ok,
    }


def stop_owned_group(proc: subprocess.Popen, first_signal: signal.Signals,
                     grace: int = TERM_GRACE_SECONDS,
                     kill_group=os.killpg) -> bool:
    if proc.poll() is not None:
        return False
    try:
        kill_group(proc.pid, first_signal)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=grace)
        return False
    except subprocess.TimeoutExpired:
        try:
            kill_group(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        return True


def finalize_perf_observer(proc: subprocess.Popen,
                           grace: int = PERF_FINALIZE_GRACE_SECONDS,
                           kill_group=os.killpg) -> bool:
    """Interrupt owned perf and wait for data finalization before forced kill."""
    return stop_owned_group(proc, signal.SIGINT, grace, kill_group)


def remaining_test_seconds(released_monotonic: float,
                           now: float | None = None) -> float:
    """Return the unspent part of the unchanged test execution deadline."""
    current = time.monotonic() if now is None else now
    return max(0.0, OUTER_TIMEOUT_SECONDS - (current - released_monotonic))


def install_cleanup_signals() -> None:
    terminating = False
    def terminate(signum, _frame):
        nonlocal terminating
        if terminating:
            return
        terminating = True
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_json(path: Path, value: dict) -> None:
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(value, indent=2) + "\n")
    os.replace(tmp, path)


def proc_identity(pid: int) -> dict:
    root = Path(f"/proc/{pid}")
    stat = (root / "stat").read_text()
    tail = stat[stat.rfind(")") + 2:].split()
    status_text = (root / "status").read_text()
    status = dict(line.split(":", 1) for line in status_text.splitlines() if ":" in line)
    return {
        "pid": pid,
        "start_time": int(tail[19]),
        "exe": os.readlink(root / "exe"),
        "argv": (root / "cmdline").read_bytes().split(b"\0")[:-1],
        "netns": os.readlink(root / "ns/net"),
        "uid": int(status["Uid"].split()[0]),
        "gid": int(status["Gid"].split()[0]),
        "groups": [int(value) for value in status.get("Groups", "").split()],
        "caps": {key: status.get(key, "").strip() for key in
                 ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
        "no_new_privs": status.get("NoNewPrivs", "").strip(),
    }


def policy_matches(identity: dict, uid: int, gid: int, netns: str) -> bool:
    return (
        identity["uid"] == uid and identity["gid"] == gid
        and identity["groups"] == [] and identity["netns"] == netns
        and identity["no_new_privs"] == "1"
        and all(value and int(value, 16) == 0 for value in identity["caps"].values())
    )


def wait_json(path: Path, timeout_seconds: int) -> dict:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            return json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {path.name}")


def wait_stopped(pid: int, timeout_seconds: int = 10) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WUNTRACED | os.WNOHANG)
        if waited == pid:
            if os.WIFSTOPPED(status):
                return
            raise RuntimeError("test wrapper exited before stopping")
        time.sleep(0.02)
    raise TimeoutError("timed out waiting for stopped test wrapper")


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, **kw)


def git_output(repo: Path, *args: str) -> str:
    return run(["git", "-C", str(repo), *args], capture_output=True, text=True).stdout.strip()


def validate_changed_paths(changed: set[str]) -> None:
    allowed = {"Cargo.toml", ".github/workflows/build.yml", "scripts/ci/run-703-optimized.py"}
    unexpected = sorted(changed - allowed)
    if unexpected:
        raise ValueError(f"source changes outside diagnostic workflow: {unexpected}")
    missing = sorted(allowed - changed)
    if missing:
        raise ValueError(f"diagnostic workflow files missing from HEAD delta: {missing}")


def parse_profile_delta(diff_text: str) -> tuple[list[str], list[str]]:
    """Return (added, removed) body lines from a Cargo.toml diff."""
    added: list[str] = []
    removed: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
        elif line.startswith("-"):
            removed.append(line[1:])
    return added, removed


def validate_cargo_delta(diff_text: str) -> None:
    """Assert the Cargo.toml change is EXACTLY the prescribed block."""
    added, removed = parse_profile_delta(diff_text)
    if removed:
        raise ValueError(f"Cargo.toml delta removes lines (not permitted): {removed}")
    if added != EXPECTED_CARGO_ADDITIONS:
        raise ValueError(
            "Cargo.toml delta is not the exact prescribed "
            "five package-specific blocks (keccak + three adapters + x0x upper control); "
            f"added={added!r}")


def extract_rustc_invocations(build_stderr_text: str) -> list[str]:
    """Return the full rustc command lines cargo printed under -v."""
    out: list[str] = []
    for line in build_stderr_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Running `") and stripped.endswith("`"):
            command = stripped[len("Running `"):-1]
            tokens = shlex.split(command)
            if tokens and Path(tokens[0]).name == "rustc":
                out.append(command)
    return out


def extract_profile_evidence(build_stderr_text: str) -> dict:
    """Verify and record the caller-and-adapter optimized test-profile proof.

    Fails closed unless keccak, fips204, saorsa-pqc, and ant-quic invocations carry
    -C opt-level=3, and the single x0x `--test` invocation is also compiled
    at -C opt-level=3 (authorized upper control via
    [profile.test.package.x0x]).
    """
    invocations = extract_rustc_invocations(build_stderr_text)
    def crate_name(command: str) -> str | None:
        tokens = shlex.split(command)
        for i, token in enumerate(tokens[:-1]):
            if token == "--crate-name":
                return tokens[i + 1]
        return None

    optimized_crates = ("keccak", "fips204", "saorsa_pqc", "ant_quic")
    optimized = {
        name: [c for c in invocations if crate_name(c) == name]
        for name in optimized_crates
    }
    test_bins = [c for c in invocations
                 if crate_name(c) == "x0x" and "--test" in shlex.split(c)]

    def opt_level(cmd: str) -> str | None:
        toks = shlex.split(cmd)
        for i, tok in enumerate(toks):
            if tok.startswith("-Copt-level="):
                return tok.split("=", 1)[1]
            if tok == "-C" and i + 1 < len(toks) and toks[i + 1].startswith("opt-level="):
                return toks[i + 1].split("=", 1)[1]
            if tok.startswith("-C opt-level="):
                return tok.split("=", 1)[1]
        return None

    failures: list[str] = []
    for name, commands in optimized.items():
        if not commands:
            failures.append(f"no {name} rustc invocation captured")
        elif any(opt_level(command) != "3" for command in commands):
            failures.append(
                f"{name} not compiled with -C opt-level=3 in every captured "
                f"invocation (levels={[opt_level(c) for c in commands]})")
    if len(test_bins) != 1:
        failures.append(f"expected exactly one x0x --test invocation, got {len(test_bins)}")
    else:
        lvl = opt_level(test_bins[0])
        if lvl != "3":
            failures.append(
                f"x0x test binary opt-level is {lvl!r}, expected 3 "
                "(authorized upper control)")
    if failures:
        raise SystemExit("FAIL: caller-and-adapter optimized test-profile evidence: "
                         + "; ".join(failures))
    return {
        "profile": PROFILE_LABEL,
        "optimized_crate_opt_levels": {
            name: opt_level(commands[0]) for name, commands in optimized.items()
        },
        "x0x_test_opt_level": opt_level(test_bins[0]) if test_bins else None,
        "optimized_crate_invocations": {
            name: commands for name, commands in optimized.items()
        },
        "x0x_test_invocation": test_bins[0] if test_bins else None,
        "rustc_invocation_count": len(invocations),
    }


def select_test_binary(build_json_text: str) -> tuple[str, list[str]]:
    """Return (executable, notes) for the unique compiler-artifact whose
    target kind contains 'lib' and whose executable is non-null.

    Checks the native exit BEFORE this is called (caller contract).
    """
    matches: list[str] = []
    for line in build_json_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact":
            continue
        target = msg.get("target", {})
        kinds = target.get("kind", [])
        exe = msg.get("executable")
        if "lib" in kinds and exe:
            matches.append(exe)
    if not matches:
        raise SystemExit("FAIL: no compiler-artifact with lib kind and non-null executable")
    if len(matches) != 1:
        raise SystemExit(f"FAIL: ambiguous lib test binaries: {matches}")
    return matches[0], [f"selected {matches[0]}"]


def verify_proof(proof: dict) -> tuple[bool, list[str]]:
    """Verify the proof against the unchanged base assertions.

    Returns (ok, notes). decode_to_delivery_drops == 0 is an additional
    acceptance requirement layered over the unchanged test assertions.
    """
    notes: list[str] = []

    def need(cond: bool, label: str) -> bool:
        notes.append(("PASS: " if cond else "FAIL: ") + label)
        return cond

    ok = True
    ok &= need(proof.get("messages") == EXPECTED_MESSAGES,
               f"proof messages == {EXPECTED_MESSAGES}")
    ok &= need(proof.get("publish_total") == EXPECTED_MESSAGES,
               f"proof publish_total == {EXPECTED_MESSAGES} (assertion)")
    ok &= need(proof.get("fast_received") == EXPECTED_MESSAGES,
               f"proof fast_received == {EXPECTED_MESSAGES} (assertion)")
    drops = proof.get("slow_subscriber_dropped")
    ok &= need(isinstance(drops, int) and drops >= 1,
               f"proof slow_subscriber_dropped >= 1 (assertion), got {drops!r}")
    closed = proof.get("subscriber_channel_closed")
    ok &= need(isinstance(closed, int) and closed >= 1,
               f"proof subscriber_channel_closed >= 1 (assertion), got {closed!r}")

    ok &= need(proof.get("decode_to_delivery_drops") == 0,
               "proof decode_to_delivery_drops == 0 (acceptance requirement), "
               f"got {proof.get('decode_to_delivery_drops')!r}")
    return bool(ok), notes


def parse_libtest_summary(log_text: str) -> tuple[int, int]:
    """Return (passed, failed) from the libtest summary line."""
    passed = failed = -1
    for line in log_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("test result:") and "passed" in stripped:
            for part in stripped.split(";"):
                part = part.strip()
                for key, store in (("passed", "passed"), ("failed", "failed")):
                    if part.endswith(key):
                        try:
                            value = int(part[: -len(key)].strip().rsplit(" ", 1)[-1])
                        except (ValueError, IndexError):
                            continue
                        if store == "passed":
                            passed = value
                        else:
                            failed = value
    return passed, failed


def namespace_state(parent: str, *, command=run, current: str | None = None) -> dict:
    """Return checked network-namespace state or fail closed."""
    current_ns = current if current is not None else os.readlink("/proc/self/ns/net")
    if current_ns == parent:
        raise RuntimeError("network namespace did not change")

    def ip_json(*args: str) -> list[dict]:
        proc = command(["/usr/sbin/ip", *args], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"ip {' '.join(args)} exited {proc.returncode}")
        try:
            value = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"ip {' '.join(args)} returned invalid JSON") from exc
        if not isinstance(value, list):
            raise RuntimeError(f"ip {' '.join(args)} returned non-list JSON")
        return value

    links = ip_json("-j", "link")
    if [row.get("ifname") for row in links] != ["lo"]:
        raise RuntimeError(f"foreign interfaces: {links}")
    routes = {
        family: ip_json(family, "-j", "route", "show", "table", "all")
        for family in ("-4", "-6")
    }
    foreign = [row for rows in routes.values() for row in rows
               if row.get("dev") != "lo" or row.get("dst") == "default" or "gateway" in row]
    if foreign:
        raise RuntimeError(f"foreign route: {foreign}")
    return {"namespace": current_ns, "links": links, "routes": routes}


def privilege_state(expected_uid: int, expected_gid: int,
                    status_text: str | None = None) -> dict:
    if os.getuid() != expected_uid or os.getgid() != expected_gid or os.geteuid() == 0:
        raise RuntimeError("runtime uid/gid do not match the original unprivileged owner")
    if os.getgroups():
        raise RuntimeError("runtime supplementary groups are not empty")
    text = status_text if status_text is not None else Path("/proc/self/status").read_text()
    status = dict(line.split(":", 1) for line in text.splitlines() if ":" in line)
    cap_keys = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    for key in cap_keys:
        try:
            nonzero = int(status[key].strip(), 16)
        except (KeyError, ValueError) as exc:
            raise RuntimeError(f"missing or malformed {key}") from exc
        if nonzero:
            raise RuntimeError(f"{key} is not empty")
    if status.get("NoNewPrivs", "").strip() != "1":
        raise RuntimeError("NoNewPrivs is not set")
    return {"uid": os.getuid(), "gid": os.getgid(),
            "groups": os.getgroups(),
            "capabilities": {key: status[key].strip() for key in cap_keys},
            "no_new_privs": 1}


def outer_phase(repo: Path, artifact_dir: Path) -> int:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    head = git_output(repo, "rev-parse", "HEAD")
    tree = git_output(repo, "rev-parse", "HEAD^{tree}")
    branch = git_output(repo, "rev-parse", "--abbrev-ref", "HEAD")
    ancestor = run(["git", "-C", str(repo), "merge-base", "--is-ancestor",
                    BASE_COMMIT, "HEAD"]).returncode
    if ancestor != 0:
        raise SystemExit(f"FAIL: required base {BASE_COMMIT} is not an ancestor of HEAD {head}")
    changed_output = git_output(repo, "diff", "--name-only", f"{BASE_COMMIT}..HEAD")
    changed = {line for line in changed_output.splitlines() if line}
    try:
        validate_changed_paths(changed)
    except ValueError as exc:
        raise SystemExit(f"FAIL: {exc}") from exc
    dirty = git_output(repo, "status", "--porcelain")
    if dirty:
        raise SystemExit(f"FAIL: checkout is not clean: {dirty.splitlines()}")
    base_tree = git_output(repo, "rev-parse", f"{BASE_COMMIT}^{{tree}}")
    if base_tree != BASE_TREE:
        raise SystemExit(f"FAIL: base tree {base_tree} != required tree {BASE_TREE}")
    cargo_diff = git_output(repo, "diff", f"{BASE_COMMIT}..HEAD", "--", "Cargo.toml")
    try:
        validate_cargo_delta(cargo_diff)
    except ValueError as exc:
        raise SystemExit(f"FAIL: {exc}") from exc
    source = repo / SOURCE_PATH
    source_sha = sha256_file(source)
    base_source = run(["git", "-C", str(repo), "show", f"{BASE_COMMIT}:{SOURCE_PATH}"],
                      capture_output=True)
    if base_source.returncode != 0:
        raise SystemExit(f"FAIL: cannot read {SOURCE_PATH} from required base")
    base_source_sha = hashlib.sha256(base_source.stdout).hexdigest()
    if source_sha != SOURCE_SHA256 or base_source_sha != SOURCE_SHA256:
        raise SystemExit(
            f"FAIL: {SOURCE_PATH} custody differs (worktree={source_sha}, base={base_source_sha})")
    print(f"base/source verified: HEAD={head} tree={tree} branch={branch} changes={sorted(changed)}")
    print(f"source blob {SOURCE_PATH} sha256={source_sha}")
    print("Cargo.toml delta verified: exact keccak/fips204/saorsa-pqc/ant-quic/x0x opt-level=3 blocks")

    perf_evidence = perf_precheck(artifact_dir)
    (artifact_dir / "perf-precheck.json").write_text(
        json.dumps(perf_evidence, indent=2) + "\n"
    )
    if not perf_evidence["ok"]:
        raise SystemExit("FAIL: bounded privileged perf precheck failed before build")

    # Fresh lock: the prior run retained no lock custody.
    lock = repo / "Cargo.lock"
    if run(["cargo", "generate-lockfile"], cwd=repo).returncode != 0:
        raise SystemExit("FAIL: cargo generate-lockfile")
    lock_sha = sha256_file(lock)
    print(f"Cargo.lock sha256={lock_sha}")

    env = dict(os.environ)
    env["CARGO_BUILD_JOBS"] = "4"
    # Cargo's inherited CI color setting must not decorate the retained
    # compiler commands that the profile verifier parses.
    env["CARGO_TERM_COLOR"] = "never"
    # Plain cargo test with package overrides; retain verbose profile proof.
    proc = run(
        ["cargo", "test", "-v", "--locked", "--all-features", "--lib",
         SELECTOR, "--no-run", "--message-format=json"],
        cwd=repo, env=env, capture_output=True, text=True,
    )
    build_json = artifact_dir / "build-messages.json"
    build_json.write_text(proc.stdout)
    (artifact_dir / "build-stderr.log").write_text(proc.stderr)
    print(f"build native exit: {proc.returncode}")
    if proc.returncode != 0:
        raise SystemExit(f"FAIL: cargo build exited {proc.returncode}")
    postbuild_lock_sha = sha256_file(lock)
    if postbuild_lock_sha != lock_sha:
        raise SystemExit(
            f"FAIL: Cargo.lock changed during locked build ({lock_sha} -> {postbuild_lock_sha})")
    # Profile proof: fail closed before selecting/running anything.
    profile_evidence = extract_profile_evidence(proc.stderr)
    print(
        "profile evidence: optimized="
        f"{profile_evidence['optimized_crate_opt_levels']} "
        f"x0x-test opt-level={profile_evidence['x0x_test_opt_level']}")
    # Native exit checked BEFORE parsing/selecting.
    test_binary, notes = select_test_binary(proc.stdout)
    for n in notes:
        print(n)

    listing = run([test_binary, "--list", "--exact", SELECTOR],
                  capture_output=True, text=True)
    if listing.returncode != 0:
        raise SystemExit(f"FAIL: --list exited {listing.returncode}")
    listed = [l for l in listing.stdout.splitlines() if l.strip() and ": test" in l]
    if len(listed) != 1:
        raise SystemExit(f"FAIL: --list --exact returned {len(listed)} tests, expected 1")
    print(f"--list --exact matched exactly 1 test")

    binary_sha = sha256_file(Path(test_binary))
    print(f"test binary sha256={binary_sha}")
    retained_binary = artifact_dir / TEST_BINARY_ARTIFACT_NAME
    shutil.copy2(test_binary, retained_binary)
    retained_sha = sha256_file(retained_binary)
    if retained_sha != binary_sha:
        raise SystemExit(
            f"FAIL: retained test binary hash differs ({binary_sha} -> {retained_sha})"
        )
    atomic_json(artifact_dir / "test-binary-custody.json", {
        "original_path": str(Path(test_binary).resolve()),
        "retained_path": str(retained_binary.resolve()),
        "sha256": binary_sha,
        "bytes": retained_binary.stat().st_size,
    })

    # Record outer netns inode so the inner phase can prove separation.
    outer_netns = os.readlink("/proc/self/ns/net")
    (artifact_dir / "outer-netns.txt").write_text(outer_netns)

    inner_result_path = artifact_dir / INNER_RESULT_NAME
    uid, gid = os.getuid(), os.getgid()
    # Preserve the inherited HOME through sudo without assigning or replacing it.
    # The root launcher raises loopback before dropping to the original uid/gid.
    inner_env = dict(os.environ)
    inner_env["X0X_703_ARTIFACT_DIR"] = str(artifact_dir)
    inner_env[INNER_FLAG_ENV] = "1"
    inner_env["X0X_703_RUNNER_UID"] = str(uid)
    inner_env["X0X_703_RUNNER_GID"] = str(gid)
    preserve = (f"HOME,PATH,X0X_703_ARTIFACT_DIR,{INNER_FLAG_ENV},"
                "X0X_703_RUNNER_UID,X0X_703_RUNNER_GID")
    inner_cmd = [
        "sudo", f"--preserve-env={preserve}", "--",
        "unshare", "--net", "--",
        sys.executable, str(Path(__file__).resolve()), "--netns-launch",
        "--runner-uid", str(uid), "--runner-gid", str(gid),
        "--test-binary", test_binary, "--artifact-dir", str(artifact_dir),
    ]
    install_cleanup_signals()
    launcher = subprocess.Popen(inner_cmd, cwd=repo, env=inner_env, start_new_session=True)
    observer_helper = None
    target_pidfd = None
    try:
        target = wait_json(artifact_dir / TARGET_RECORD_NAME, 30)
        live = proc_identity(int(target["pid"]))
        expected_wrapper_argv = target["wrapper_argv"]
        live_argv = [part.decode(errors="replace") for part in live["argv"]]
        if (live["start_time"] != target["start_time"]
                or live["exe"] != target["wrapper_exe"]
                or live_argv != expected_wrapper_argv
                or not policy_matches(live, uid, gid, target["netns"])):
            raise SystemExit("FAIL: stopped wrapper identity mismatch")
        target_pidfd = os.pidfd_open(int(target["pid"]))
        if proc_identity(int(target["pid"]))["start_time"] != target["start_time"]:
            raise SystemExit("FAIL: target identity changed while opening pidfd")
        observer_cmd = [
            "sudo", f"--preserve-env=HOME,PATH", "--", sys.executable,
            str(Path(__file__).resolve()), "--observer", "--artifact-dir",
            str(artifact_dir), "--test-binary", test_binary,
            "--target-pid", str(target["pid"]), "--target-start", str(target["start_time"]),
        ]
        observer_helper = subprocess.Popen(observer_cmd, cwd=repo, start_new_session=True)
        ready = wait_json(artifact_dir / OBSERVER_READY_NAME, 30)
        if not ready.get("attached"):
            raise SystemExit(f"FAIL: perf observer did not attach: {ready}")
        atomic_json(artifact_dir / "test-release.json", {"target_start": target["start_time"]})
        signal.pidfd_send_signal(target_pidfd, signal.SIGCONT)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            current = proc_identity(int(target["pid"]))
            if current["exe"] == str(Path(test_binary).resolve()):
                expected_argv = [part.encode() for part in [
                    test_binary, "--exact", SELECTOR, "--ignored", "--nocapture",
                    "--test-threads=1",
                ]]
                if current["argv"] != expected_argv or not policy_matches(
                    current, uid, gid, target["netns"]
                ):
                    raise SystemExit("FAIL: test argv differs after wrapper exec")
                break
            time.sleep(0.02)
        else:
            raise SystemExit("FAIL: stopped wrapper did not exec exact test binary")
        rc = launcher.wait(timeout=INNER_COMPLETION_TIMEOUT_SECONDS)
        observer_helper.wait(timeout=OBSERVER_HELPER_CLEANUP_GRACE_SECONDS)
    finally:
        stop_owned_group(launcher, signal.SIGTERM, TERM_GRACE_SECONDS + 5)
        if observer_helper is not None:
            stop_owned_group(
                observer_helper,
                signal.SIGTERM,
                OBSERVER_HELPER_CLEANUP_GRACE_SECONDS,
            )
        if target_pidfd is not None:
            os.close(target_pidfd)

    if not inner_result_path.exists():
        raise SystemExit(f"FAIL: inner phase produced no {INNER_RESULT_NAME} (sudo exit {rc})")
    inner = json.loads(inner_result_path.read_text())

    report = {
        "profile": PROFILE_LABEL,
        "head": head,
        "tree": tree,
        "branch": branch,
        f"{SOURCE_PATH}_sha256": source_sha,
        "cargo_lock_sha256": lock_sha,
        "cargo_profile_delta": EXPECTED_CARGO_ADDITIONS,
        "profile_evidence": profile_evidence,
        "perf_precheck": perf_evidence,
        "test_binary_sha256": binary_sha,
        "inner": inner,
    }
    (artifact_dir / REPORT_NAME).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if rc == 0 and inner.get("ok") is True else 1


def netns_launch(test_binary: str, artifact_dir: Path, uid: int, gid: int) -> int:
    """Raise loopback as root, then replace this process with the unprivileged inner."""
    if os.geteuid() != 0:
        raise SystemExit("FAIL: netns launcher must run as root")
    ip = shutil.which("ip")
    if ip is None:
        raise SystemExit("FAIL: iproute2 unavailable before privilege drop")
    raised = run([ip, "link", "set", "lo", "up"])
    if raised.returncode != 0:
        raise SystemExit(f"FAIL: raising loopback exited {raised.returncode}")
    command = [
        "/usr/bin/setpriv", f"--reuid={uid}", f"--regid={gid}", "--clear-groups",
        "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
        sys.executable, str(Path(__file__).resolve()), "--inner",
        "--test-binary", test_binary, "--artifact-dir", str(artifact_dir),
    ]
    os.execvp(command[0], command)
    return 1


def stopped_exec(started_path: Path, command: list[str]) -> int:
    os.kill(os.getpid(), signal.SIGSTOP)
    identity = proc_identity(os.getpid())
    atomic_json(started_path, {
        "pid": os.getpid(),
        "start_time": identity["start_time"],
        "released_monotonic": time.monotonic(),
    })
    os.execv(command[0], command)
    return 1


def perf_precheck_helper(perf: str, output: Path) -> int:
    if os.geteuid() != 0:
        raise SystemExit("FAIL: perf precheck helper must be root")
    parent_pid = os.getppid()
    install_cleanup_signals()
    if ctypes.CDLL(None).prctl(1, int(signal.SIGTERM), 0, 0, 0) != 0:
        raise SystemExit("FAIL: cannot install precheck parent-death signal")
    if os.getppid() != parent_pid:
        raise SystemExit("FAIL: precheck parent exited during setup")
    child = subprocess.Popen(
        [perf, "record", "-q", "-o", str(output), "--", "/bin/true"],
        start_new_session=True,
    )
    try:
        return child.wait(timeout=5)
    finally:
        stop_owned_group(child, signal.SIGTERM)


def observer_phase(artifact_dir: Path, test_binary: str, target_pid: int,
                   target_start: int) -> int:
    if os.geteuid() != 0:
        raise SystemExit("FAIL: observer helper must be root")
    parent_pid = os.getppid()
    install_cleanup_signals()
    if ctypes.CDLL(None).prctl(1, int(signal.SIGTERM), 0, 0, 0) != 0:
        raise SystemExit("FAIL: cannot install observer parent-death signal")
    if os.getppid() != parent_pid:
        raise SystemExit("FAIL: observer parent exited during setup")
    target = proc_identity(target_pid)
    record = json.loads((artifact_dir / TARGET_RECORD_NAME).read_text())
    expected_binary = str(Path(test_binary).resolve())
    live_argv = [part.decode(errors="replace") for part in target["argv"]]
    if (record.get("pid") != target_pid
            or record.get("start_time") != target_start
            or target["start_time"] != target_start
            or target["exe"] != record.get("wrapper_exe")
            or live_argv != record.get("wrapper_argv")
            or not policy_matches(
                target, record.get("uid"), record.get("gid"), record.get("netns")
            )
            or target["netns"] == record.get("outer_netns")
            or record.get("expected_test_binary") != expected_binary
            or record.get("expected_test_sha256") != sha256_file(Path(expected_binary))):
        raise SystemExit("FAIL: observer target custody record mismatch")
    perf = shutil.which("perf")
    if perf is None:
        raise SystemExit("FAIL: perf unavailable to observer helper")
    perf_data = artifact_dir / PERF_DATA_NAME
    perf_log = artifact_dir / "perf-observer.log"
    forced_kill = False
    with perf_log.open("wb") as log:
        observer = subprocess.Popen(
            [perf, "record", "--no-buildid", "-F", "99", "--call-graph", "dwarf", "--inherit",
             "-o", str(perf_data), "-p", str(target_pid)],
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 10
            attached = False
            while time.monotonic() < deadline and observer.poll() is None:
                fd_root = Path(f"/proc/{observer.pid}/fd")
                try:
                    attached = any("perf_event" in os.readlink(fd) for fd in fd_root.iterdir())
                except (FileNotFoundError, PermissionError):
                    attached = False
                if attached:
                    break
                time.sleep(0.05)
            atomic_json(artifact_dir / OBSERVER_READY_NAME, {
                "attached": attached,
                "observer_pid": observer.pid,
                "target_pid": target_pid,
                "target_start": target_start,
            })
            if not attached:
                return 2
            wait_json(artifact_dir / "test-done.json", OUTER_TIMEOUT_SECONDS + 60)
            forced_kill = finalize_perf_observer(observer)
            return observer.returncode
        finally:
            forced_kill = finalize_perf_observer(observer) or forced_kill
            if perf_data.exists():
                os.chown(perf_data, target["uid"], -1)
            atomic_json(artifact_dir / "observer-result.json", {
                "native_exit": observer.returncode,
                "forced_kill": forced_kill,
                "target_pid": target_pid,
                "target_start": target_start,
            })


def inner_phase(test_binary: str, artifact_dir: Path) -> int:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    checks: list[tuple[bool, str]] = []

    expected_uid = int(os.environ.get("X0X_703_RUNNER_UID", "-1"))
    expected_gid = int(os.environ.get("X0X_703_RUNNER_GID", "-1"))
    outer_netns = (artifact_dir / "outer-netns.txt").read_text().strip()
    try:
        net_state = namespace_state(outer_netns)
        priv_state = privilege_state(expected_uid, expected_gid)
        checks.extend([
            (True, f"network namespace admitted: {net_state['namespace']}"),
            (True, f"uid/gid/groups/capabilities admitted: {priv_state}"),
        ])
    except RuntimeError as exc:
        checks.append((False, str(exc)))

    failed_checks = [msg for ok, msg in checks if not ok]
    for ok, msg in checks:
        print(("PASS: " if ok else "FAIL: ") + msg)
    if failed_checks:
        print("namespace isolation verification failed; refusing to run test")
        return 2

    test_log = artifact_dir / "test.log"
    proof_path = artifact_dir / "proof.json"
    env = dict(os.environ)
    env["X0X_SLOW_CONSUMER_PROOF"] = str(proof_path)
    for var in ("X0X_SLOW_SUBSCRIBER_MESSAGES",):
        env.pop(var, None)

    cmd = [test_binary, "--exact", SELECTOR, "--ignored", "--nocapture",
           "--test-threads=1"]
    print(f"executing ({PROFILE_LABEL}): {' '.join(cmd)}")
    started = time.monotonic()
    timed_out = False
    perf_data = artifact_dir / PERF_DATA_NAME
    with test_log.open("wb") as log_fh:
        started_path = artifact_dir / "test-started.json"
        install_cleanup_signals()
        proc = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--stopped-exec",
             str(started_path), "--", *cmd],
            stdout=log_fh, stderr=subprocess.STDOUT, env=env, start_new_session=True,
        )
        try:
            wait_stopped(proc.pid)
            wrapper = proc_identity(proc.pid)
            atomic_json(artifact_dir / TARGET_RECORD_NAME, {
            "pid": proc.pid,
            "start_time": wrapper["start_time"],
            "wrapper_exe": wrapper["exe"],
            "wrapper_argv": [part.decode(errors="replace") for part in wrapper["argv"]],
            "netns": wrapper["netns"],
            "outer_netns": outer_netns,
            "uid": wrapper["uid"],
            "gid": wrapper["gid"],
            "groups": wrapper["groups"],
            "caps": wrapper["caps"],
            "no_new_privs": wrapper["no_new_privs"],
            "expected_test_binary": str(Path(test_binary).resolve()),
            "expected_test_sha256": sha256_file(Path(test_binary)),
            })
            release = wait_json(artifact_dir / "test-release.json", 30)
            if release.get("target_start") != wrapper["start_time"]:
                raise RuntimeError("test release identity mismatch")
            started_record = wait_json(started_path, 30)
            if (started_record.get("pid") != proc.pid
                    or started_record.get("start_time") != wrapper["start_time"]):
                raise RuntimeError("test-started identity mismatch")
            started = float(started_record["released_monotonic"])
            try:
                proc.communicate(timeout=remaining_test_seconds(started))
            except subprocess.TimeoutExpired:
                timed_out = True
                print(f"outer bound {OUTER_TIMEOUT_SECONDS}s reached; sending TERM")
                stop_owned_group(proc, signal.SIGTERM)
            elapsed = round(time.monotonic() - started, 4)
        finally:
            stop_owned_group(proc, signal.SIGTERM)
    native_exit = proc.returncode
    atomic_json(artifact_dir / "test-done.json", {
        "test_native_exit": native_exit,
        "timed_out": timed_out,
        "elapsed_seconds": elapsed,
    })
    observer_result = wait_json(
        artifact_dir / "observer-result.json", OBSERVER_HELPER_CLEANUP_GRACE_SECONDS
    )
    perf_exit = int(observer_result["native_exit"])
    reports = {}
    for mode, args in (
        ("self", ["--no-children"]),
        ("children", ["--children"]),
    ):
        reports[mode] = run_perf_report(
            perf_data,
            artifact_dir / f"perf-report-{mode}.txt",
            args,
        )
    perf_bytes = perf_data.stat().st_size if perf_data.exists() else 0
    status = profiling_status(native_exit, perf_exit, timed_out, perf_bytes, reports)
    status["perf_forced_kill"] = bool(observer_result.get("forced_kill", False))
    print(f"native exit={native_exit} elapsed={elapsed}s timed_out={timed_out}")

    log_text = test_log.read_text(errors="replace")
    passed, failed = parse_libtest_summary(log_text)
    proof_notes: list[str] = []
    proof_sha = None
    ok = status["capture_ok"] and status["test_ok"] and passed == 1 and failed == 0
    if proof_path.exists():
        proof_sha = sha256_file(proof_path)
        proof_ok, proof_notes = verify_proof(json.loads(proof_path.read_text()))
        ok = ok and proof_ok
    else:
        proof_notes.append("FAIL: no proof.json produced")
        ok = False

    for n in proof_notes:
        print(n)

    result = {
        "profile": PROFILE_LABEL,
        "ok": ok,
        "timed_out": timed_out,
        "native_exit": native_exit,
        "profiling_status": status,
        "perf_capture_bytes": perf_bytes,
        "perf_reports": reports,
        "elapsed_seconds": elapsed,
        "outer_timeout_seconds": OUTER_TIMEOUT_SECONDS,
        "tests_passed": passed,
        "tests_failed": failed,
        "proof_sha256": proof_sha,
        "isolation_checks": [{"ok": o, "msg": m} for o, m in checks],
        "namespace_state": net_state if "net_state" in locals() else None,
        "privilege_state": priv_state if "priv_state" in locals() else None,
        "proof_notes": proof_notes,
        "test_binary": test_binary,
    }
    (artifact_dir / INNER_RESULT_NAME).write_text(json.dumps(result, indent=2) + "\n")
    return 0 if ok else 1


def self_test() -> int:
    failures = 0

    class PerfResult:
        def __init__(self, code: int, stdout: str = "", stderr: str = ""):
            self.returncode = code
            self.stdout = stdout
            self.stderr = stderr

    class FakeOwnedProcess:
        def __init__(self, finalize_seconds: int):
            self.pid = 4242
            self.returncode = None
            self.finalize_seconds = finalize_seconds
            self.waits: list[int | None] = []
            self.signals: list[signal.Signals] = []

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.waits.append(timeout)
            if self.returncode is not None:
                return self.returncode
            if timeout is not None and timeout < self.finalize_seconds:
                raise subprocess.TimeoutExpired("perf", timeout)
            self.returncode = 0
            return self.returncode

        def kill_group(self, pid, signum):
            if pid != self.pid:
                raise AssertionError("foreign PID signalled")
            self.signals.append(signum)
            if signum == signal.SIGKILL:
                self.returncode = -int(signal.SIGKILL)

    with __import__("tempfile").TemporaryDirectory() as raw:
        tmp = Path(raw)
        missing = perf_precheck(tmp, perf=None, command=lambda *_a, **_k: PerfResult(1))
        failures += missing.get("ok", True)
        denied = perf_precheck(
            tmp, perf="perf", command=lambda cmd, **_k: PerfResult(0) if "version" in cmd else PerfResult(13)
        )
        failures += denied.get("ok", True)

        seen_report_argv = []

        def report_process(code: str):
            def launch(argv, **kwargs):
                seen_report_argv.append(argv)
                return subprocess.Popen([sys.executable, "-c", code], **kwargs)
            return launch

        successful = run_perf_report(
            tmp / "perf.data",
            tmp / "report-success.txt",
            ["--no-children"],
            timeout=1,
            popen=report_process("print(' 91.00% command symbol', flush=True)"),
        )
        failures += successful["native_exit"] != 0 or not successful["has_samples"]
        failures += successful["timed_out"]
        failures += not all(
            token in seen_report_argv[-1]
            for token in ("--max-stack", "32", "--no-inline", "--percent-limit", "0.5")
        )

        failed = run_perf_report(
            tmp / "perf.data",
            tmp / "report-failed.txt",
            ["--children"],
            timeout=1,
            popen=report_process("import sys; print('report failed'); sys.exit(7)"),
        )
        failures += failed["native_exit"] != 7 or failed["timed_out"]

        timed = run_perf_report(
            tmp / "perf.data",
            tmp / "report-timeout.txt",
            ["--children"],
            timeout=0.05,
            cleanup_grace=0.05,
            popen=report_process(
                "import time; print('partial report evidence', flush=True); time.sleep(10)"
            ),
        )
        failures += not timed["timed_out"] or timed["native_exit"] is None
        failures += b"partial report evidence" not in (tmp / "report-timeout.txt").read_bytes()

        forced = run_perf_report(
            tmp / "perf.data",
            tmp / "report-forced-kill.txt",
            ["--children"],
            timeout=0.05,
            cleanup_grace=0.05,
            popen=report_process(
                "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "print('forced partial evidence', flush=True); time.sleep(10)"
            ),
        )
        failures += not forced["timed_out"] or not forced["forced_kill"]
        failures += forced["native_exit"] != -int(signal.SIGKILL)
        failures += forced["cleanup_error"] is not None
        failures += b"forced partial evidence" not in (
            tmp / "report-forced-kill.txt"
        ).read_bytes()
    good_reports = {
        "self": {"native_exit": 0, "has_samples": True},
        "children": {"native_exit": 0, "has_samples": True},
    }
    failures += not profiling_status(0, 0, False, 100, good_reports)["capture_ok"]
    failures += profiling_status(7, 0, False, 100, good_reports)["test_ok"]
    failures += profiling_status(-15, 0, True, 100, good_reports)["test_ok"]
    failures += profiling_status(0, 9, False, 100, good_reports)["capture_ok"]
    failed_report = {
        "self": {"native_exit": 1, "has_samples": False},
        "children": {"native_exit": 0, "has_samples": True},
    }
    failures += profiling_status(0, 0, False, 100, failed_report)["capture_ok"]
    timed_out_report = {
        "self": {"native_exit": 0, "has_samples": True, "timed_out": True},
        "children": {"native_exit": 0, "has_samples": True},
    }
    failures += profiling_status(0, 0, False, 100, timed_out_report)["capture_ok"]
    cleanup_failed_report = {
        "self": {
            "native_exit": 0,
            "has_samples": True,
            "cleanup_error": "bounded final wait expired",
        },
        "children": {"native_exit": 0, "has_samples": True},
    }
    failures += profiling_status(
        0, 0, False, 100, cleanup_failed_report
    )["capture_ok"]
    empty_reports = {
        "self": {"native_exit": 0, "has_samples": False},
        "children": {"native_exit": 0, "has_samples": False},
    }
    failures += profiling_status(0, 0, False, 100, empty_reports)["capture_ok"]
    failures += profiling_status(0, 0, False, 0, good_reports)["capture_ok"]
    failures += not report_has_samples("  91.23% command symbol\n")
    failures += report_has_samples("   0.00% command symbol\n")
    failures += report_has_samples("# no samples\n")

    # The production perf-finalization path must wait beyond the former generic
    # 10-second grace. The negative control proves that old path force-kills the
    # same 30-second finalizer, while the new path sends SIGINT and exits zero.
    old = FakeOwnedProcess(finalize_seconds=30)
    old_forced = stop_owned_group(
        old, signal.SIGINT, TERM_GRACE_SECONDS, old.kill_group
    )
    failures += not old_forced
    failures += old.signals != [signal.SIGINT, signal.SIGKILL]
    failures += old.returncode != -int(signal.SIGKILL)
    print("PASS self-test: old 10-second perf finalization path requires SIGKILL")
    repaired = FakeOwnedProcess(finalize_seconds=30)
    repaired_forced = finalize_perf_observer(repaired, kill_group=repaired.kill_group)
    failures += repaired_forced
    failures += repaired.signals != [signal.SIGINT]
    failures += repaired.returncode != 0
    print("PASS self-test: repaired perf finalization waits after SIGINT without SIGKILL")

    # Exact source-custody delta rejects missing and additional files.
    expected_delta = {"Cargo.toml", ".github/workflows/build.yml",
                      "scripts/ci/run-703-optimized.py"}
    validate_changed_paths(expected_delta)
    for label, paths in (("missing runner", {"Cargo.toml", ".github/workflows/build.yml"}),
                         ("extra source", expected_delta | {"src/lib.rs"})):
        try:
            validate_changed_paths(paths)
            print(f"FAIL self-test: custody should reject {label}")
            failures += 1
        except ValueError:
            print(f"PASS self-test: custody rejects {label}")

    # Cargo delta must be exactly the prescribed block.
    good_diff = ("diff --git a/Cargo.toml b/Cargo.toml\n"
                 "index aaa..bbb 100644\n"
                 "--- a/Cargo.toml\n"
                 "+++ b/Cargo.toml\n"
                 "@@ -194,3 +194,10 @@\n")
    for line in EXPECTED_CARGO_ADDITIONS:
        good_diff += "+" + line + "\n"
    validate_cargo_delta(good_diff)
    for label, diff in (
        ("removals", "--- a/Cargo.toml\n+++ b/Cargo.toml\n@@\n-old\n"),
        ("extra addition", good_diff + "+extra = true\n"),
        ("missing line", good_diff.replace("+opt-level = 3\n", "")),
        ("wrong block", "--- a/Cargo.toml\n+++ b/Cargo.toml\n@@\n"
                        "+[profile.test]\n+opt-level = 3\n"),
    ):
        try:
            validate_cargo_delta(diff)
            print(f"FAIL self-test: cargo delta should reject {label}")
            failures += 1
        except ValueError:
            print(f"PASS self-test: cargo delta rejects {label}")

    # Profile evidence from retained rustc invocations.
    optimized_cmds = [
        f"rustc --crate-name {name} --crate-type lib --edition 2021 "
        "-C opt-level=3 -C embed-bitcode=no src/lib.rs"
        for name in ("keccak", "fips204", "saorsa_pqc", "ant_quic")
    ]
    test_cmd = ("rustc --crate-name x0x --crate-type lib --test --edition 2021 "
                "-C opt-level=3 src/lib.rs")
    stderr_good = "".join(f"     Running `{cmd}`\n" for cmd in optimized_cmds)
    stderr_good += f"     Running `{test_cmd}`\n"
    ev = extract_profile_evidence(stderr_good)
    failures += any(level != "3" for level in ev["optimized_crate_opt_levels"].values())
    failures += ev["x0x_test_opt_level"] != "3"
    absolute_commands = stderr_good.replace(
        "`rustc ", "`'/opt/rust toolchain/bin/rustc' ")
    ev = extract_profile_evidence(absolute_commands)
    failures += any(level != "3" for level in ev["optimized_crate_opt_levels"].values())
    failures += ev["x0x_test_opt_level"] != "3"
    for label, text in (
        ("adapter not optimized", stderr_good.replace(
            "--crate-name ant_quic --crate-type lib --edition 2021 -C opt-level=3",
            "--crate-name ant_quic --crate-type lib --edition 2021 -C opt-level=0")),
        ("x0x test binary not optimized", stderr_good.replace(
            "--crate-name x0x --crate-type lib --test --edition 2021 -C opt-level=3",
            "--crate-name x0x --crate-type lib --test --edition 2021 -C opt-level=0")),
        ("x0x test binary default opt-level", stderr_good.replace(
            " --test --edition 2021 -C opt-level=3", " --test --edition 2021")),
        ("missing x0x test invocation", "".join(
            line for line in stderr_good.splitlines() if "--crate-name x0x " not in line) + "\n"),
        ("no fips invocation", "\n".join(
            line for line in stderr_good.splitlines() if "--crate-name fips204 " not in line)),
        ("no keccak invocation", "\n".join(
            line for line in stderr_good.splitlines() if "--crate-name keccak " not in line)),
        ("keccak not optimized", stderr_good.replace(
            "--crate-name keccak --crate-type lib --edition 2021 -C opt-level=3",
            "--crate-name keccak --crate-type lib --edition 2021 -C opt-level=0")),
        ("crate-name prefix collision", stderr_good.replace(
            "--crate-name fips204 ", "--crate-name fips204_other ")),
    ):
        try:
            extract_profile_evidence(text)
            print(f"FAIL self-test: profile evidence should reject {label}")
            failures += 1
        except SystemExit:
            print(f"PASS self-test: profile evidence rejects {label}")

    # Namespace parsing fails closed on command errors and foreign routes.
    class StubResult:
        def __init__(self, code: int, value: object):
            self.returncode = code
            self.stdout = json.dumps(value)
    def good_ip(cmd: list[str], **_kw):
        if cmd[1:3] == ["-j", "link"]:
            return StubResult(0, [{"ifname": "lo"}])
        return StubResult(0, [{"dst": "127.0.0.0/8", "dev": "lo"}])
    state = namespace_state("net:[1]", command=good_ip, current="net:[2]")
    failures += state["namespace"] != "net:[2]"
    def failed_ip(_cmd: list[str], **_kw):
        return StubResult(7, [])
    try:
        namespace_state("net:[1]", command=failed_ip, current="net:[2]")
        failures += 1
        print("FAIL self-test: failed ip command accepted")
    except RuntimeError:
        print("PASS self-test: failed ip command rejected")
    def foreign_route(cmd: list[str], **_kw):
        if cmd[1:3] == ["-j", "link"]:
            return StubResult(0, [{"ifname": "lo"}])
        return StubResult(0, [{"dst": "default", "dev": "eth0", "gateway": "192.0.2.1"}])
    try:
        namespace_state("net:[1]", command=foreign_route, current="net:[2]")
        failures += 1
        print("FAIL self-test: foreign route accepted")
    except RuntimeError:
        print("PASS self-test: foreign route rejected")
    try:
        privilege_state(os.getuid() + 1, os.getgid())
        failures += 1
        print("FAIL self-test: wrong uid accepted")
    except RuntimeError:
        print("PASS self-test: wrong uid rejected")

    # Artifact selection.
    good = "\n".join([
        json.dumps({"reason": "compiler-artifact", "target": {"kind": ["lib"]},
                    "executable": "/x/deps/x0x-abc"}),
        json.dumps({"reason": "compiler-artifact", "target": {"kind": ["bin"]},
                    "executable": "/x/x0x"}),
        json.dumps({"reason": "compiler-artifact", "target": {"kind": ["lib"]},
                    "executable": None}),
        "not json",
    ])
    exe, _ = select_test_binary(good)
    failures += exe != "/x/deps/x0x-abc"
    for label, payload in (
        ("no lib artifact", json.dumps({"reason": "compiler-artifact",
                                        "target": {"kind": ["bin"]}, "executable": "/x"})),
        ("ambiguous", "\n".join([
            json.dumps({"reason": "compiler-artifact", "target": {"kind": ["lib"]},
                        "executable": "/a"}),
            json.dumps({"reason": "compiler-artifact", "target": {"kind": ["lib"]},
                        "executable": "/b"}),
        ])),
    ):
        try:
            select_test_binary(payload)
            print(f"FAIL self-test: selection should have failed: {label}")
            failures += 1
        except SystemExit:
            print(f"PASS self-test: selection rejects {label}")

    # Proof verification.
    base = {"messages": 100000, "publish_total": 100000, "fast_received": 100000,
            "slow_subscriber_dropped": 1, "subscriber_channel_closed": 1,
            "decode_to_delivery_drops": 0}
    ok, _ = verify_proof(dict(base))
    failures += not ok
    for label, patch in (
        ("publish_total short", {"publish_total": 99999}),
        ("fast_received short", {"fast_received": 0}),
        ("zero drops", {"slow_subscriber_dropped": 0}),
        ("zero closed", {"subscriber_channel_closed": 0}),
    ):
        bad = dict(base)
        bad.update(patch)
        ok, _ = verify_proof(bad)
        if ok:
            print(f"FAIL self-test: proof should have failed: {label}")
            failures += 1
        else:
            print(f"PASS self-test: proof rejects {label}")
    # The additional acceptance criterion is fail-closed.
    supp = dict(base, decode_to_delivery_drops=5)
    ok, _ = verify_proof(supp)
    if ok:
        print("FAIL self-test: nonzero decode_to_delivery_drops must fail acceptance")
        failures += 1
    else:
        print("PASS self-test: nonzero decode_to_delivery_drops fails acceptance")

    # libtest summary parsing.
    log = "running 1 test\ntest gossip::pubsub::tests::x ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.00s\n"
    p, f = parse_libtest_summary(log)
    failures += (p, f) != (1, 0)
    p, f = parse_libtest_summary("test result: FAILED. 0 passed; 1 failed;")
    failures += (p, f) != (0, 1)

    print("self-test failures:", failures)
    return 1 if failures else 0


def main() -> int:
    if "--stopped-exec" in sys.argv:
        marker = sys.argv.index("--stopped-exec")
        remainder = sys.argv[marker + 1:]
        if len(remainder) < 3 or remainder[1] != "--":
            raise SystemExit("stopped exec requires a started path and command")
        return stopped_exec(Path(remainder[0]), remainder[2:])
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inner", action="store_true")
    ap.add_argument("--netns-launch", action="store_true")
    ap.add_argument("--observer", action="store_true")
    ap.add_argument("--perf-precheck-helper", action="store_true")
    ap.add_argument("--precheck-output")
    ap.add_argument("--perf-executable")
    ap.add_argument("--target-pid", type=int)
    ap.add_argument("--target-start", type=int)
    ap.add_argument("--runner-uid", type=int)
    ap.add_argument("--runner-gid", type=int)
    ap.add_argument("--test-binary")
    ap.add_argument("--artifact-dir")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--repo", default=os.getcwd())
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if args.perf_precheck_helper:
        if not args.precheck_output or not args.perf_executable:
            raise SystemExit("perf precheck helper requires output and executable")
        return perf_precheck_helper(args.perf_executable, Path(args.precheck_output))
    if args.observer:
        if (not args.artifact_dir or not args.test_binary
                or args.target_pid is None or args.target_start is None):
            raise SystemExit("observer requires artifact, binary, PID, and start time")
        return observer_phase(
            Path(args.artifact_dir), args.test_binary, args.target_pid, args.target_start
        )
    if args.netns_launch:
        if (not args.test_binary or not args.artifact_dir
                or args.runner_uid is None or args.runner_gid is None):
            raise SystemExit("netns launcher requires binary, artifact dir, uid, and gid")
        return netns_launch(args.test_binary, Path(args.artifact_dir),
                            args.runner_uid, args.runner_gid)
    if os.environ.get(INNER_FLAG_ENV) == "1" or args.inner:
        if not args.test_binary or not args.artifact_dir:
            raise SystemExit("inner phase requires --test-binary and --artifact-dir")
        return inner_phase(args.test_binary, Path(args.artifact_dir))
    if not args.artifact_dir:
        raise SystemExit("outer phase requires --artifact-dir")
    return outer_phase(Path(args.repo).resolve(), Path(args.artifact_dir))


if __name__ == "__main__":
    sys.exit(main())
