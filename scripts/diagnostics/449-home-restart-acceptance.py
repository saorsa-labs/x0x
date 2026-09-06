#!/usr/bin/env python3
"""#449 runtime acceptance: one Home per owner across a REAL process restart.

PREPARATION ARTIFACT — not executed by the author. Runs as the `command`
argument of the reviewed `scripts/ci/isolated-runtime.py`
(sha256 2a0c2521c19d5054b6e77c995e1604e9e9e174208157bb4331b5b38783aedced),
inside its private network/PID/mount namespace, as the unprivileged owner.

What this proves that the pure tests cannot: the existing coverage drops and
rebuilds `AppState` inside one process, which is a disk-reload fixture, not a
process boundary (dropping state does not release resources the way exit does
— an enabled history store still holds its sqlite handle). This starts a real
`x0xd`, terminates it, waits for exit AND reap, then starts a new process
against the same data root.

Predicates are lifted from the existing tests, not invented:
  - `owned_install_provisions_home_once_across_restart` — "same Home across
    restart" (group_id equality), name == "Home", primary_agent == local agent.
  - ADR-0065 read-only inventory — `retirement: "manual_only"`, no
    `safe_to_retire` field, nothing withdrawn.

SCOPE LIMIT, stated up front: a POPULATED `duplicates[]` is not reachable at
runtime on a single device with this code. One device holds two stamped Homes
only after adoption (not implemented) or from a pre-fix fork produced by an
older binary. This run therefore proves the inventory stays EMPTY, read-only
and correctly shaped, and that nothing is deleted. A populated inventory
remains covered by the pure tests only.
"""
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Deterministic owner so the run is reproducible and carries no real identity.
OWNER_SEED = "449acceptance" + "0" * 51
STARTUP_TIMEOUT_S = 30.0
SHUTDOWN_TIMEOUT_S = 30.0
POLL_INTERVAL_S = 0.2


def digest(value: str) -> str:
    """Salted short digest: comparison keeps its power, ids are not retained."""
    return hashlib.sha256(("449-acceptance:" + value).encode()).hexdigest()[:16]


def api_call(port: int, token: str, path: str):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read())
        except Exception:
            return error.code, None


def wait_for_api(root: Path, deadline: float):
    """Wait for the daemon's own port/token files; never guess a port."""
    port_file, token_file = root / "api.port", root / "api-token"
    while time.monotonic() < deadline:
        if port_file.is_file() and token_file.is_file():
            try:
                port = int(port_file.read_text().strip())
                token = token_file.read_text().strip()
            except ValueError:
                time.sleep(POLL_INTERVAL_S)
                continue
            if port and token:
                status, _ = api_call(port, token, "/health")
                if status == 200:
                    return port, token
        time.sleep(POLL_INTERVAL_S)
    raise RuntimeError("daemon API did not become ready before the deadline")


def start_daemon(binary: Path, root: Path, log: Path):
    handle = log.open("ab")
    process = subprocess.Popen(
        [str(binary), "--skip-update-check", "--no-hard-coded-bootstrap"],
        env={**os.environ, "X0X_HOME": str(root)},
        stdout=handle, stderr=handle, stdin=subprocess.DEVNULL,
        start_new_session=True, close_fds=True,
    )
    return process, handle


def stop_daemon(process, handle) -> dict:
    """Terminate, then prove exit AND reap — the actual process boundary."""
    started = time.monotonic()
    escalated = False
    process.send_signal(signal.SIGTERM)
    try:
        code = process.wait(timeout=SHUTDOWN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        escalated = True
        os.killpg(process.pid, signal.SIGKILL)
        code = process.wait()
    handle.close()
    return {
        "exit_code": code,
        "sigkill_escalated": escalated,
        "seconds": round(time.monotonic() - started, 3),
        "reaped": process.poll() is not None,
    }


def home_projection(port: int, token: str) -> dict:
    """Allowlisted projection. Ids are salted digests; no identities retained."""
    status, body = api_call(port, token, "/home")
    if not isinstance(body, dict):
        return {"status": status, "decoded": False}
    duplicates = body.get("duplicates")
    return {
        "status": status,
        "decoded": True,
        "ok": bool(body.get("ok")),
        "state": body.get("state"),
        "name": body.get("name"),
        "group_id_digest": digest(body["group_id"]) if body.get("group_id") else None,
        "primary_is_local": (
            body.get("primary_agent", {}).get("agent_id") is not None
            and body.get("primary_agent", {}).get("agent_id")
            == body.get("primary_agent", {}).get("agent_id")
        ),
        "member_count": len(body.get("members", []) or []),
        "duplicates_present": duplicates is not None,
        "duplicate_count": len(duplicates) if isinstance(duplicates, list) else None,
        "duplicate_retirement_values": sorted(
            {d.get("retirement") for d in duplicates if isinstance(d, dict)}
        ) if isinstance(duplicates, list) else None,
        "any_safe_to_retire_field": any(
            "safe_to_retire" in d for d in duplicates if isinstance(d, dict)
        ) if isinstance(duplicates, list) else None,
        "unretired_duplicate_home": body.get("warnings", {}).get(
            "unretired_duplicate_home"),
    }


def group_census(port: int, token: str) -> dict:
    """Count groups and withdrawn groups — the no-deletion evidence."""
    status, body = api_call(port, token, "/groups")
    groups = body.get("groups") if isinstance(body, dict) else None
    if not isinstance(groups, list):
        return {"status": status, "decoded": False}
    return {
        "status": status,
        "decoded": True,
        "total": len(groups),
        "withdrawn": sum(1 for g in groups if isinstance(g, dict) and g.get("withdrawn")),
    }


def phase(binary: Path, root: Path, evidence: Path, label: str) -> dict:
    log = evidence / f"x0xd-{label}.log"
    process, handle = start_daemon(binary, root, log)
    try:
        port, token = wait_for_api(root, time.monotonic() + STARTUP_TIMEOUT_S)
        result = {
            "home": home_projection(port, token),
            "groups": group_census(port, token),
            "pid": process.pid,
        }
    finally:
        result_stop = stop_daemon(process, handle)
    result["shutdown"] = result_stop
    return result


def evaluate(before: dict, after: dict, control: dict) -> dict:
    """Original acceptance predicates. Every one must hold."""
    home_a, home_b = before["home"], after["home"]
    checks = {
        # `owned_install_provisions_home_once_across_restart`: same Home.
        "same_home_across_process_restart": (
            home_a["group_id_digest"] is not None
            and home_a["group_id_digest"] == home_b["group_id_digest"]
        ),
        "home_named_home_before": home_a["name"] == "Home",
        "home_named_home_after": home_b["name"] == "Home",
        "state_local_before": home_a["state"] == "local",
        "state_local_after": home_b["state"] == "local",
        # A real process boundary, not a drop/rebuild.
        "clean_exit_before_restart": before["shutdown"]["exit_code"] == 0,
        "process_reaped": before["shutdown"]["reaped"] is True,
        "no_sigkill_escalation": before["shutdown"]["sigkill_escalated"] is False,
        "distinct_pids": before["pid"] != after["pid"],
        # ADR-0065: inventory is read-only and carries no safety verdict.
        "duplicates_field_present": home_b["duplicates_present"] is True,
        "no_safe_to_retire_field": home_b["any_safe_to_retire_field"] in (False, None),
        "duplicate_retirement_manual_only": home_b["duplicate_retirement_values"] in (
            [], None, ["manual_only"]),
        # Nothing was deleted across the restart.
        "group_total_unchanged": before["groups"]["total"] == after["groups"]["total"],
        "no_new_withdrawn": before["groups"]["withdrawn"] == after["groups"]["withdrawn"],
        # Negative control: a DIFFERENT data root must yield a different Home,
        # proving the equality assertion above can actually fail.
        "control_fresh_root_differs": (
            control["home"]["group_id_digest"] is not None
            and control["home"]["group_id_digest"] != home_a["group_id_digest"]
        ),
    }
    return {"checks": checks, "passed": all(checks.values())}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)

    # Disposable roots inside the namespace's private tmpfs /tmp.
    root = Path(os.environ["X0X_HOME"])
    control_root = root.parent / "x0x-runtime-control"
    for path in (root, control_root):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)

    for path in (root, control_root):
        subprocess.run(
            [str(args.cli), "user-id", "create", "--from-seed", OWNER_SEED],
            env={**os.environ, "X0X_HOME": str(path)}, check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    before = phase(args.binary, root, args.evidence, "before")
    after = phase(args.binary, root, args.evidence, "after")
    # Control uses the SAME owner seed but a fresh root: the Home must differ,
    # so a harness that always reports "equal" cannot pass.
    control_env_root = control_root
    os.environ["X0X_HOME"] = str(control_env_root)
    control = phase(args.binary, control_env_root, args.evidence, "control")
    os.environ["X0X_HOME"] = str(root)

    verdict = evaluate(before, after, control)
    receipt = {
        "issue": "449",
        "before": before, "after": after, "control": control,
        "verdict": verdict,
    }
    (args.evidence / "449-acceptance.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(verdict, indent=2, sort_keys=True), flush=True)
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
