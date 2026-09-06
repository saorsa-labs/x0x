#!/usr/bin/env python3
"""#449 runtime acceptance: one Home per owner across a REAL process restart.

PREPARATION ARTIFACT — the author has not executed the runtime path. Only
`--self-test` (pure, no daemon, no network) has been run.

Runs as the `command` argument of the reviewed, UNCHANGED
`scripts/ci/isolated-runtime.py`
(sha256 2a0c2521c19d5054b6e77c995e1604e9e9e174208157bb4331b5b38783aedced).
THAT WRAPPER IS THE ISOLATION BOUNDARY, and it is mandatory: it owns the
private network/PID/mount namespace, the `namespace_state` admission check
(loopback only, no default route, no foreign interfaces), the drop to an
unprivileged uid with empty capabilities, the deadline/cancellation supervisor
and the admission/exit/supervisor receipts. This file asserts nothing about
isolation and must never be run outside it.

Why runtime at all: the existing #449 tests drop and rebuild `AppState` inside
ONE process — a disk-reload fixture, not a process boundary. (Concretely:
enabling history in that fixture fails with "database is locked", because drop
does not release the sqlite handle the way exit does.) Only a real
exit/reap/respawn retires the limitation ADR-0060 and ADR-0065 both record as
unvalidated.

Predicates are lifted from the existing tests, not invented:
  `owned_install_provisions_home_once_across_restart` — group_id equality
  ("same Home across restart"), name == "Home", primary agent is the local
  agent, local agent is a member; ADR-0065 — duplicates read-only
  (`retirement: "manual_only"`, NO `safe_to_retire`), nothing withdrawn.

SCOPE LIMIT: a POPULATED `duplicates[]` is not runtime-reachable on a single
device with this code — one device holds two stamped Homes only after adoption
(not implemented) or from a pre-fix fork made by an older binary, and seeding
one would mean forging a sealed record. This run proves the inventory is
present, decoded, EXPLICITLY EMPTY and correctly shaped. A populated inventory
stays covered by pure tests only. No adoption, retirement, multi-device
convergence or issue closure is claimed.
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

# 64 hex chars = 32 bytes. `x0x user-id create --from-seed` hex::decodes this
# (src/cli/commands/user_id.rs:147); a non-hex seed aborts before any daemon
# starts, so this MUST stay hex.
OWNER_SEED = "44900000" * 8
CONTROL_SEED = "44911111" * 8
STARTUP_TIMEOUT_S = 30.0
SHUTDOWN_TIMEOUT_S = 30.0
POLL_INTERVAL_S = 0.2
DUPLICATE_KEYS = {"group_id", "retirement", "evidence_against_deletion"}


class PhaseError(RuntimeError):
    """Structured failure so a receipt is still written (review P2)."""

    def __init__(self, stage, detail):
        super().__init__(f"{stage}: {detail}")
        self.stage = stage
        self.detail = detail


def digest(value):
    """Salted short digest: comparison keeps its power, ids are not retained."""
    if value is None:
        return None
    return hashlib.sha256(("449-acceptance:" + value).encode()).hexdigest()[:16]


def api_call(port, token, path):
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
    except Exception:
        return None, None


def wait_for_api(root, deadline):
    port_file, token_file = root / "api.port", root / "api-token"
    while time.monotonic() < deadline:
        if port_file.is_file() and token_file.is_file():
            try:
                port = int(port_file.read_text().strip())
                token = token_file.read_text().strip()
            except ValueError:
                time.sleep(POLL_INTERVAL_S)
                continue
            if port and token and api_call(port, token, "/health")[0] == 200:
                return port, token
        time.sleep(POLL_INTERVAL_S)
    raise PhaseError("startup", "daemon API not ready before deadline")


def start_daemon(binary, root, log_path):
    handle = log_path.open("ab")
    process = subprocess.Popen(
        [str(binary), "--skip-update-check", "--no-hard-coded-bootstrap"],
        env={**os.environ, "X0X_HOME": str(root)},
        stdout=handle, stderr=handle, stdin=subprocess.DEVNULL,
        start_new_session=True, close_fds=True,
    )
    return process, handle


def stop_daemon(process, handle):
    """Terminate, then prove exit AND reap — the actual process boundary."""
    started = time.monotonic()
    escalated = False
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            code = process.wait(timeout=SHUTDOWN_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            escalated = True
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
    else:
        code = process.returncode
    handle.close()
    return {
        "exit_code": code,
        "sigkill_escalated": escalated,
        "clean_exit": code == 0 and not escalated,
        "reaped": process.poll() is not None,
        "seconds": round(time.monotonic() - started, 3),
    }


def duplicates_projection(raw):
    """Strict schema. A non-list, or any entry with unexpected shape, FAILS —
    it is never flattened to None and then accepted (review P2)."""
    if not isinstance(raw, list):
        return {"decoded": False, "reason": "duplicates is not a list"}
    entries = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != DUPLICATE_KEYS:
            return {"decoded": False, "reason": "duplicate entry schema mismatch"}
        if not isinstance(item.get("group_id"), str):
            return {"decoded": False, "reason": "duplicate group_id not a string"}
        if not isinstance(item.get("evidence_against_deletion"), list):
            return {"decoded": False, "reason": "evidence_against_deletion not a list"}
        entries.append(item)
    return {
        "decoded": True,
        "count": len(entries),
        "is_empty": len(entries) == 0,
        "retirement_values": sorted({e["retirement"] for e in entries}),
        "any_safe_to_retire_field": False,  # schema equality already excludes it
    }


def observe(port, token):
    """One observation. Fetches the REAL local agent id and compares it in
    memory against the Home projection (review P2); only booleans and salted
    digests are retained."""
    agent_status, agent_body = api_call(port, token, "/agent")
    if agent_status != 200 or not isinstance(agent_body, dict):
        raise PhaseError("observe", f"/agent status {agent_status}")
    local_agent = agent_body.get("agent_id")
    if not isinstance(local_agent, str) or not local_agent:
        raise PhaseError("observe", "/agent returned no agent_id")

    home_status, home = api_call(port, token, "/home")
    if home_status != 200 or not isinstance(home, dict):
        raise PhaseError("observe", f"/home status {home_status}")

    primary = home.get("primary_agent")
    primary_id = primary.get("agent_id") if isinstance(primary, dict) else None
    members = home.get("members")
    member_ids = (
        [m.get("agent_id") for m in members if isinstance(m, dict)]
        if isinstance(members, list) else None
    )

    groups_status, groups_body = api_call(port, token, "/groups")
    groups = groups_body.get("groups") if isinstance(groups_body, dict) else None
    if groups_status != 200 or not isinstance(groups, list):
        raise PhaseError("observe", f"/groups status {groups_status}")

    return {
        "home_status": home_status,
        "home_ok": bool(home.get("ok")),
        "state": home.get("state"),
        "name": home.get("name"),
        "group_id_digest": digest(home.get("group_id")),
        # Real comparisons, not self-comparisons.
        "primary_is_local_agent": primary_id == local_agent,
        "local_agent_is_member": (
            member_ids is not None and local_agent in member_ids),
        "members_decoded": member_ids is not None,
        "member_count": len(member_ids) if member_ids is not None else None,
        "duplicates": duplicates_projection(home.get("duplicates")),
        "unretired_duplicate_home": home.get("warnings", {}).get(
            "unretired_duplicate_home"),
        "group_total": len(groups),
        "group_withdrawn": sum(
            1 for g in groups if isinstance(g, dict) and g.get("withdrawn")),
    }


def phase(binary, root, private_logs, label):
    """Always returns a structured result; failures never escape without one."""
    log_path = private_logs / f"x0xd-{label}.log"
    process, handle = start_daemon(binary, root, log_path)
    outcome = {"label": label, "pid": process.pid, "ok": False,
               "failure": None, "observation": None}
    try:
        port, token = wait_for_api(root, time.monotonic() + STARTUP_TIMEOUT_S)
        outcome["observation"] = observe(port, token)
        outcome["ok"] = True
    except PhaseError as error:
        outcome["failure"] = {"stage": error.stage, "detail": error.detail}
    except Exception as error:  # classified, never silent
        outcome["failure"] = {"stage": "unexpected", "detail": type(error).__name__}
    finally:
        outcome["shutdown"] = stop_daemon(process, handle)
    return outcome


def evaluate(before, after, control):
    """Original acceptance predicates. Every one must hold."""
    phases = {"before": before, "after": after, "control": control}
    checks = {f"phase_{name}_observed": p["ok"] for name, p in phases.items()}
    # Clean stop AND reap for ALL phases, not only the restart arm.
    for name, p in phases.items():
        checks[f"phase_{name}_clean_exit"] = p["shutdown"]["clean_exit"] is True
        checks[f"phase_{name}_reaped"] = p["shutdown"]["reaped"] is True
        checks[f"phase_{name}_no_sigkill"] = p["shutdown"]["sigkill_escalated"] is False
    if not all(p["ok"] for p in phases.values()):
        return {"checks": checks, "passed": False,
                "reason": "one or more phases did not produce an observation"}

    a, b, c = before["observation"], after["observation"], control["observation"]
    for name, obs in (("before", a), ("after", b), ("control", c)):
        checks[f"{name}_home_200"] = obs["home_status"] == 200
        checks[f"{name}_state_local"] = obs["state"] == "local"
        checks[f"{name}_named_home"] = obs["name"] == "Home"
        checks[f"{name}_primary_is_local_agent"] = obs["primary_is_local_agent"] is True
        checks[f"{name}_local_agent_is_member"] = obs["local_agent_is_member"] is True
        checks[f"{name}_duplicates_decoded"] = obs["duplicates"]["decoded"] is True
        checks[f"{name}_duplicates_explicitly_empty"] = (
            obs["duplicates"].get("is_empty") is True)
        checks[f"{name}_no_safe_to_retire"] = (
            obs["duplicates"].get("any_safe_to_retire_field") is False)
        checks[f"{name}_retirement_manual_only"] = (
            obs["duplicates"].get("retirement_values") in ([], ["manual_only"]))

    # THE restart predicate.
    checks["same_home_across_process_restart"] = (
        a["group_id_digest"] is not None
        and a["group_id_digest"] == b["group_id_digest"])
    checks["distinct_pids"] = before["pid"] != after["pid"]
    # Nothing deleted across the restart.
    checks["group_total_unchanged"] = a["group_total"] == b["group_total"]
    checks["no_new_withdrawn"] = a["group_withdrawn"] == b["group_withdrawn"]
    # CONTRAST fixture (not a mutation test of restart behaviour): a distinct
    # owner on a distinct root must yield a distinct Home, so an evaluator that
    # always reported "equal" cannot pass.
    checks["contrast_distinct_root_differs"] = (
        c["group_id_digest"] is not None
        and c["group_id_digest"] != a["group_id_digest"])
    return {"checks": checks, "passed": all(checks.values()), "reason": None}


# --------------------------- pure self-test ---------------------------------

def _obs(**over):
    base = {
        "home_status": 200, "home_ok": True, "state": "local", "name": "Home",
        "group_id_digest": "aaaa", "primary_is_local_agent": True,
        "local_agent_is_member": True, "members_decoded": True, "member_count": 1,
        "duplicates": {"decoded": True, "count": 0, "is_empty": True,
                       "retirement_values": [], "any_safe_to_retire_field": False},
        "unretired_duplicate_home": False, "group_total": 1, "group_withdrawn": 0,
    }
    base.update(over)
    return base


def _phase(observation, pid=1, clean=True):
    return {"label": "x", "pid": pid, "ok": observation is not None, "failure": None,
            "observation": observation,
            "shutdown": {"exit_code": 0 if clean else 137,
                         "sigkill_escalated": not clean,
                         "clean_exit": clean, "reaped": True, "seconds": 0.1}}


def self_test():
    """Pure positive/negative controls for the evaluator and the schema. No
    daemon, no network, no filesystem. Each negative must FAIL the verdict —
    otherwise the corresponding check has no power."""
    cases = []

    def case(name, expect_pass, before, after, control):
        got = evaluate(before, after, control)["passed"]
        cases.append((name, expect_pass, got))

    good_a, good_b = _obs(), _obs()
    contrast = _obs(group_id_digest="bbbb")
    case("positive", True, _phase(good_a, 1), _phase(good_b, 2), _phase(contrast, 3))
    case("different_home_after_restart", False,
         _phase(good_a, 1), _phase(_obs(group_id_digest="zzzz"), 2), _phase(contrast, 3))
    case("primary_not_local_agent", False,
         _phase(_obs(primary_is_local_agent=False), 1), _phase(good_b, 2),
         _phase(contrast, 3))
    case("local_agent_not_member", False,
         _phase(good_a, 1), _phase(_obs(local_agent_is_member=False), 2),
         _phase(contrast, 3))
    case("duplicates_not_decoded", False,
         _phase(good_a, 1),
         _phase(_obs(duplicates={"decoded": False, "reason": "x"}), 2),
         _phase(contrast, 3))
    case("duplicate_reports_safe_to_retire", False,
         _phase(good_a, 1),
         _phase(_obs(duplicates={"decoded": True, "count": 1, "is_empty": False,
                                 "retirement_values": ["manual_only"],
                                 "any_safe_to_retire_field": True}), 2),
         _phase(contrast, 3))
    case("duplicate_retirement_not_manual_only", False,
         _phase(good_a, 1),
         _phase(_obs(duplicates={"decoded": True, "count": 1, "is_empty": False,
                                 "retirement_values": ["automatic"],
                                 "any_safe_to_retire_field": False}), 2),
         _phase(contrast, 3))
    case("group_withdrawn_across_restart", False,
         _phase(good_a, 1), _phase(_obs(group_withdrawn=1), 2), _phase(contrast, 3))
    case("group_disappeared_across_restart", False,
         _phase(good_a, 1), _phase(_obs(group_total=0), 2), _phase(contrast, 3))
    case("state_not_local", False,
         _phase(good_a, 1), _phase(_obs(state="elsewhere"), 2), _phase(contrast, 3))
    case("non_200_home", False,
         _phase(good_a, 1), _phase(_obs(home_status=503), 2), _phase(contrast, 3))
    case("contrast_root_did_not_differ", False,
         _phase(good_a, 1), _phase(good_b, 2), _phase(_obs(), 3))
    case("same_pid_is_not_a_restart", False,
         _phase(good_a, 1), _phase(good_b, 1), _phase(contrast, 3))
    case("phase_failed_to_observe", False,
         _phase(good_a, 1), _phase(None, 2), _phase(contrast, 3))
    case("sigkill_escalation_in_control_phase", False,
         _phase(good_a, 1), _phase(good_b, 2), _phase(contrast, 3, clean=False))

    schema = [
        ("list_of_valid_entries", [{"group_id": "g", "retirement": "manual_only",
                                    "evidence_against_deletion": []}], True),
        ("not_a_list", {"group_id": "g"}, False),
        ("none", None, False),
        ("entry_with_extra_safe_to_retire", [{"group_id": "g",
                                              "retirement": "manual_only",
                                              "evidence_against_deletion": [],
                                              "safe_to_retire": True}], False),
        ("entry_missing_key", [{"group_id": "g", "retirement": "manual_only"}], False),
        ("evidence_not_a_list", [{"group_id": "g", "retirement": "manual_only",
                                  "evidence_against_deletion": "x"}], False),
    ]
    for name, raw, expect in schema:
        cases.append((f"schema:{name}", expect, duplicates_projection(raw)["decoded"]))

    failed = [(n, e, g) for n, e, g in cases if e != g]
    for name, expect, got in cases:
        print(f"{'ok  ' if expect == got else 'FAIL'} {name} (expected {expect}, got {got})")
    print(f"\n{len(cases) - len(failed)}/{len(cases)} controls passed")
    return 1 if failed else 0


# ------------------------------- runtime ------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true",
                        help="pure controls only; no daemon, no network")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not (args.binary and args.cli and args.evidence):
        parser.error("--binary, --cli and --evidence are required for a runtime run")

    args.evidence.mkdir(parents=True, exist_ok=True)
    # Daemon logs stay in the namespace's PRIVATE tmpfs and die with it.
    # `evidence` is the surviving directory and receives ONLY the allowlisted
    # receipt (review P2).
    root = Path(os.environ["X0X_HOME"])
    private_logs = root.parent / "x0x-449-logs"
    control_root = root.parent / "x0x-449-control"
    for path in (root, control_root, private_logs):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)

    receipt = {"issue": "449", "preparation": False, "phases": {}, "verdict": None}
    try:
        for path, seed in ((root, OWNER_SEED), (control_root, CONTROL_SEED)):
            result = subprocess.run(
                [str(args.cli), "user-id", "create", "--from-seed", seed],
                env={**os.environ, "X0X_HOME": str(path)},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if result.returncode != 0:
                raise PhaseError("owner-key", f"user-id create exit {result.returncode}")

        before = phase(args.binary, root, private_logs, "before")
        after = phase(args.binary, root, private_logs, "after")
        os.environ["X0X_HOME"] = str(control_root)
        control = phase(args.binary, control_root, private_logs, "control")
        os.environ["X0X_HOME"] = str(root)

        receipt["phases"] = {"before": before, "after": after, "control": control}
        receipt["verdict"] = evaluate(before, after, control)
    except PhaseError as error:
        receipt["verdict"] = {"checks": {}, "passed": False,
                              "reason": f"{error.stage}: {error.detail}"}
    except Exception as error:
        receipt["verdict"] = {"checks": {}, "passed": False,
                              "reason": f"unexpected: {type(error).__name__}"}
    finally:
        # A receipt is ALWAYS written, including on setup failure.
        (args.evidence / "449-acceptance.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt["verdict"], indent=2, sort_keys=True), flush=True)
    return 0 if receipt["verdict"] and receipt["verdict"]["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
