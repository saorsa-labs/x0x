#!/usr/bin/env python3
"""#703 default-test-profile 100k diagnostic runner (ephemeral Linux CI only).

Runs the exact ignored test
  gossip::pubsub::tests::test_slow_subscriber_isolated_at_100k_messages
at source commit 27a3354d44d59986e83a2e29ff7c0c6569634e7a in the DEFAULT
cargo test profile (no --release), once, inside a fresh loopback-only
network namespace, with the original 100_000 message count and all
original assertions unchanged.

The only manifest delta vs the base tree is
  [profile.test.package.fips204] opt-level = 3
which this script verifies exactly (no arbitrary Cargo.toml edits), and it
retains the full verbose rustc invocations so the profile proof — fips204
compiled with -C opt-level=3, the x0x test binary left at the default
debug opt-level — can be verified from the artifacts.

Phases:
  outer  (default)  : verify tree/source/Cargo delta, generate+hash lock,
                      build (default test profile, verbose), select the
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

PROFILE_LABEL = "default-test-profile"

# The ONLY permitted Cargo.toml change vs base: the fips204 test-profile
# override block, added lines exactly as prescribed (no removals).
EXPECTED_CARGO_ADDITIONS = [
    "# #703: the unchanged-assertions 100k test times out (902s) in the default",
    "# test profile; the only CPU samples were fips204 ML-DSA signing. Optimize",
    "# only the fips204 package within the test profile — the whole dev/test",
    "# profile and all release profiles stay untouched.",
    "[profile.test.package.fips204]",
    "opt-level = 3",
    "",
]

# 600 s outer bound (reported default-profile ceiling bound), then TERM,
# then KILL after a grace period. No automatic retry or extension.
OUTER_TIMEOUT_SECONDS = 600
TERM_GRACE_SECONDS = 10

INNER_FLAG_ENV = "X0X_703_INNER"
INNER_RESULT_NAME = "inner-result.json"
REPORT_NAME = "run-report.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


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
            f"[profile.test.package.fips204] block; added={added!r}")


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
    """Verify and record the default-test-profile proof from rustc args.

    Fails closed unless exactly one fips204 rustc invocation carries
    -C opt-level=3, and the single x0x `--test` invocation stays at the
    default debug opt-level (no -C opt-level, or opt-level=0).
    """
    invocations = extract_rustc_invocations(build_stderr_text)
    def crate_name(command: str) -> str | None:
        tokens = shlex.split(command)
        for i, token in enumerate(tokens[:-1]):
            if token == "--crate-name":
                return tokens[i + 1]
        return None

    fips = [c for c in invocations if crate_name(c) == "fips204"]
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
    if len(fips) == 0:
        failures.append("no fips204 rustc invocation captured")
    fips_ok = sum(1 for c in fips if opt_level(c) == "3")
    if len(fips) != fips_ok:
        failures.append(f"fips204 not compiled with -C opt-level=3 in every "
                        f"captured invocation (levels={[opt_level(c) for c in fips]})")
    if len(test_bins) != 1:
        failures.append(f"expected exactly one x0x --test invocation, got {len(test_bins)}")
    else:
        lvl = opt_level(test_bins[0])
        if lvl not in (None, "0"):
            failures.append(f"x0x test binary opt-level is {lvl!r}, expected default (None or 0)")
    if failures:
        raise SystemExit("FAIL: default-test-profile evidence: " + "; ".join(failures))
    return {
        "profile": PROFILE_LABEL,
        "fips204_opt_level": opt_level(fips[0]),
        "x0x_test_opt_level": opt_level(test_bins[0]) if test_bins else None,
        "fips204_invocation": fips[0],
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
    print(f"Cargo.toml delta verified: exact [profile.test.package.fips204] opt-level=3 block")

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
    # Default cargo test profile (no --release). -v retains the full rustc
    # invocations on stderr as the profile proof for fips204 and the test
    # binary; JSON artifacts go to stdout.
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
    print(f"profile evidence: fips204 opt-level={profile_evidence['fips204_opt_level']} "
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
    rc = run(inner_cmd, cwd=repo, env=inner_env).returncode

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
    with test_log.open("wb") as log_fh:
        proc = subprocess.Popen(cmd, stdout=log_fh, stderr=subprocess.STDOUT, env=env)
        try:
            proc.communicate(timeout=OUTER_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            print(f"outer bound {OUTER_TIMEOUT_SECONDS}s reached; sending TERM")
            proc.terminate()
            try:
                proc.wait(timeout=TERM_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                print("TERM grace expired; sending KILL")
                proc.kill()
                proc.wait()
    elapsed = round(time.monotonic() - started, 4)
    native_exit = proc.returncode
    print(f"native exit={native_exit} elapsed={elapsed}s timed_out={timed_out}")

    log_text = test_log.read_text(errors="replace")
    passed, failed = parse_libtest_summary(log_text)
    proof_notes: list[str] = []
    proof_sha = None
    ok = (not timed_out) and native_exit == 0 and passed == 1 and failed == 0
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
    fips_cmd = ("rustc --crate-name fips204 --crate-type lib --edition 2021 "
                "-C opt-level=3 -C embed-bitcode=no src/lib.rs")
    test_cmd = ("rustc --crate-name x0x --crate-type lib --test --edition 2021 "
                "-C opt-level=0 src/lib.rs")
    stderr_good = (f"     Running `{fips_cmd}`\n     Running `{test_cmd}`\n")
    ev = extract_profile_evidence(stderr_good)
    failures += ev["fips204_opt_level"] != "3"
    failures += ev["x0x_test_opt_level"] != "0"
    absolute_commands = stderr_good.replace(
        "`rustc ", "`'/opt/rust toolchain/bin/rustc' ")
    ev = extract_profile_evidence(absolute_commands)
    failures += ev["fips204_opt_level"] != "3"
    for label, text in (
        ("fips not optimized", f"     Running `{fips_cmd.replace('opt-level=3', 'opt-level=0')}`\n"
                               f"     Running `{test_cmd}`\n"),
        ("test binary optimized", f"     Running `{fips_cmd}`\n"
                                  f"     Running `{test_cmd.replace('opt-level=0', 'opt-level=3')}`\n"),
        ("no fips invocation", f"     Running `{test_cmd}`\n"),
        ("crate-name prefix collision", stderr_good.replace(
            "--crate-name fips204 ", "--crate-name fips204_other ")),
    ):
        try:
            extract_profile_evidence(text)
            print(f"FAIL self-test: profile evidence should reject {label}")
            failures += 1
        except SystemExit:
            print(f"PASS self-test: profile evidence rejects {label}")
    # Default (omitted) opt-level on the test binary is acceptable.
    ev = extract_profile_evidence(
        f"     Running `{fips_cmd}`\n"
        f"     Running `{test_cmd.replace('-C opt-level=0 ', '')}`\n")
    failures += ev["x0x_test_opt_level"] is not None

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
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inner", action="store_true")
    ap.add_argument("--netns-launch", action="store_true")
    ap.add_argument("--runner-uid", type=int)
    ap.add_argument("--runner-gid", type=int)
    ap.add_argument("--test-binary")
    ap.add_argument("--artifact-dir")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--repo", default=os.getcwd())
    args = ap.parse_args()

    if args.self_test:
        return self_test()
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
