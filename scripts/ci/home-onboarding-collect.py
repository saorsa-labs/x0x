#!/usr/bin/env python3
"""Sanitize one-shot Home acceptance receipts; never copy raw runtime data."""
import argparse, json, math, re
from pathlib import Path

RECEIPTS = ("admission.json", "exit.json", "supervisor.json")
CAPABILITIES = {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}
SOURCE_FILES = {
    "tests/home_onboarding_isolated.rs",
    "scripts/ci/isolated-runtime.py", "scripts/ci/isolation-witness.py",
    "scripts/ci/nextest-reuse.py", "scripts/ci/home-onboarding-collect.py",
    "scripts/ci/home-onboarding-collect-controls.py",
    "ci/home-onboarding/Cargo.lock.fixture",
}
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
MIN_RUNTIME_REMAINING_SECONDS = 915
TEST_NAME = "home_onboarding_single_announce_restart"
QUALIFIED_TEST_NAME = f"x0x::home_onboarding_isolated${TEST_NAME}"
PHASES = {
    "fixture_setup", "key_create", "owner_initial_start", "joiner_initial_start",
    "profile_identity", "peer_connect", "consent_negative", "announce",
    "owner_sync", "device_enroll", "canonical_home", "seat_invite",
    "wrong_owner_negative", "wrong_mode_negative", "home_join", "active_home",
    "initial_seal", "initial_stop", "owner_restart", "joiner_restart",
    "restart_identity", "restart_home", "restart_seal", "final_stop", "complete",
}
CHILD_LABELS = {"owner_initial", "joiner_initial", "owner_restart", "joiner_restart"}


def admission_deadline_exit(remaining):
    """Return the closed exit for a late/invalid runtime admission clock."""
    if type(remaining) not in {int, float} or not math.isfinite(remaining):
        return 124
    return None if remaining >= MIN_RUNTIME_REMAINING_SECONDS else 124


def nextest_receipt_from_lines(lines):
    """Project pinned nextest 0.9.126 libtest-json-plus 0.1 without stdout."""
    suite_started = []
    suite_terminal = []
    test_started = 0
    test_terminal = []
    ignored_events = {}
    parse_valid = True
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Isolation evidence: "):
            continue
        try:
            value = json.loads(line)
        except (TypeError, json.JSONDecodeError):
            parse_valid = False
            continue
        if not isinstance(value, dict):
            parse_valid = False
            continue
        kind, event = value.get("type"), value.get("event")
        if kind == "suite" and event == "started":
            count = value.get("test_count")
            if type(count) is not int or count < 0:
                parse_valid = False
            else:
                suite_started.append(count)
        elif kind == "suite" and event in {"ok", "failed"}:
            suite_terminal.append(event)
        elif kind == "test":
            if value.get("name") != QUALIFIED_TEST_NAME:
                name = value.get("name")
                if (not isinstance(name, str)
                        or not name.startswith("x0x::home_onboarding_isolated$")
                        or event not in {"started", "ignored"}):
                    parse_valid = False
                else:
                    ignored_events.setdefault(name, []).append(event)
                continue
            if event == "started":
                test_started += 1
            elif event in {"ok", "failed", "ignored"}:
                test_terminal.append(event)
            else:
                parse_valid = False
        else:
            parse_valid = False
    parse_valid &= (
        len(suite_started) == 1
        and len(suite_terminal) == 1
        and test_started == 1
        and len(test_terminal) == 1
        and all(events == ["started", "ignored"] for events in ignored_events.values())
    )
    return {
        "schema": 1,
        "present": True,
        "parse_valid": bool(parse_valid),
        "suite_started_count": len(suite_started),
        "suite_test_count": suite_started[0] if len(suite_started) == 1 else None,
        "suite_terminal": suite_terminal[0] if len(suite_terminal) == 1 else "invalid",
        "selected_test_started_count": test_started,
        "selected_test_terminal_count": len(test_terminal),
        "selected_test_terminal": test_terminal[0] if len(test_terminal) == 1 else "invalid",
    }


def exact_keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"unexpected {label} schema")


def read_optional(path):
    if path.is_symlink():
        raise ValueError(f"unsafe symlink: {path}")
    if not path.exists():
        return None
    if not path.is_file():
        raise ValueError(f"not a file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected object: {path}")
    return value


def digest(value):
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def source_receipt(value):
    if value is None:
        return {"schema": 1, "present": False, "head": None, "tree": None,
                "files": {}, "unchanged": False}, False
    exact_keys(value, {"schema", "head", "tree", "files", "unchanged"}, "source")
    if value["schema"] != 1 or type(value["unchanged"]) is not bool:
        raise ValueError("invalid source scalar types")
    if not isinstance(value["head"], str) or HEX40.fullmatch(value["head"]) is None:
        raise ValueError("invalid source head")
    if not isinstance(value["tree"], str) or HEX40.fullmatch(value["tree"]) is None:
        raise ValueError("invalid source tree")
    if not isinstance(value["files"], dict) or set(value["files"]) != SOURCE_FILES:
        raise ValueError("unexpected source file set")
    if not all(digest(item) for item in value["files"].values()):
        raise ValueError("invalid source digest")
    return {"schema": 1, "present": True, "head": value["head"],
            "tree": value["tree"], "files": value["files"],
            "unchanged": value["unchanged"]}, value["unchanged"]


def build_receipt(value):
    empty = {"schema": 1, "present": False, "lock_sha256": None,
             "cargo_metadata_sha256": None, "binaries_metadata_sha256": None,
             "custody_sha256": None,
             "binaries": {}, "fresh_target": False, "unchanged": False}
    if value is None:
        return empty, False
    exact_keys(value, {"schema", "lock_sha256", "cargo_metadata_sha256",
               "binaries_metadata_sha256", "custody_sha256", "binaries",
               "fresh_target", "unchanged"}, "build")
    if value["schema"] != 1 or type(value["fresh_target"]) is not bool or type(value["unchanged"]) is not bool:
        raise ValueError("invalid build scalar types")
    for field in ("lock_sha256", "cargo_metadata_sha256", "binaries_metadata_sha256", "custody_sha256"):
        if not digest(value[field]): raise ValueError("invalid build digest")
    if not isinstance(value["binaries"], dict) or set(value["binaries"]) != {"x0x", "x0xd", "home_onboarding_isolated"}:
        raise ValueError("unexpected executable set")
    safe, match = {}, True
    for name, item in value["binaries"].items():
        if not isinstance(item, dict) or not set(item).issubset({"path", "pre_sha256", "post_sha256"}) or not {"pre_sha256", "post_sha256"}.issubset(item):
            raise ValueError("invalid executable custody schema")
        pre, post = item["pre_sha256"], item["post_sha256"]
        if not digest(pre) or (post is not None and not digest(post)):
            raise ValueError("invalid executable digest")
        safe[name] = {"pre_sha256": pre, "post_sha256": post}
        match &= post is not None and pre == post
    result = {"schema": 1, "present": True,
              **{field: value[field] for field in ("lock_sha256", "cargo_metadata_sha256", "binaries_metadata_sha256", "custody_sha256")},
              "binaries": safe, "fresh_target": value["fresh_target"],
              "unchanged": value["unchanged"]}
    return result, value["fresh_target"] and value["unchanged"] and match


def runtime_receipt(value):
    empty = {"schema": 1, "present": False, "wrapper_exit": None,
             "wrapper_evidence": None, "selector": None, "target": None,
             "no_tests_fail": False}
    if value is None:
        return empty, False
    exact_keys(value, {"schema", "wrapper_exit", "wrapper_evidence", "selector", "target", "no_tests_fail"}, "runtime")
    if value["schema"] != 1 or type(value["wrapper_exit"]) is not int:
        raise ValueError("invalid runtime scalar types")
    if value["wrapper_evidence"] is not None and not isinstance(value["wrapper_evidence"], str):
        raise ValueError("invalid wrapper evidence type")
    if value["selector"] != "test(=home_onboarding_single_announce_restart)" or value["target"] != "home_onboarding_isolated" or value["no_tests_fail"] is not True:
        raise ValueError("unexpected test selection contract")
    return {"schema": 1, "present": True, **{key: value[key] for key in value if key != "schema"}}, value["wrapper_exit"] == 0


def nextest_receipt(value):
    empty = {"schema": 1, "present": False, "parse_valid": False,
             "suite_started_count": 0, "suite_test_count": None,
             "suite_terminal": "missing", "selected_test_started_count": 0,
             "selected_test_terminal_count": 0, "selected_test_terminal": "missing"}
    if value is None:
        return empty, False
    keys = {"schema", "present", "parse_valid", "suite_started_count",
            "suite_test_count", "suite_terminal", "selected_test_started_count",
            "selected_test_terminal_count", "selected_test_terminal"}
    exact_keys(value, keys, "nextest")
    if value["schema"] != 1 or value["present"] is not True or type(value["parse_valid"]) is not bool:
        raise ValueError("invalid nextest scalar types")
    for field in ("suite_started_count", "selected_test_started_count", "selected_test_terminal_count"):
        if type(value[field]) is not int or value[field] < 0:
            raise ValueError("invalid nextest count")
    if value["suite_test_count"] is not None and (type(value["suite_test_count"]) is not int or value["suite_test_count"] < 0):
        raise ValueError("invalid suite test count")
    if value["suite_terminal"] not in {"ok", "failed", "invalid"} or value["selected_test_terminal"] not in {"ok", "failed", "ignored", "invalid"}:
        raise ValueError("invalid nextest terminal")
    ok = (value["parse_valid"] is True and value["suite_started_count"] == 1
          and value["selected_test_started_count"] == 1
          and value["selected_test_terminal_count"] == 1
          and value["suite_terminal"] == "ok" and value["selected_test_terminal"] == "ok")
    return value, ok


def test_receipt(value, run_nonce, source):
    empty = {"schema": 1, "present": False, "test": TEST_NAME,
             "run_nonce": run_nonce, "source_head": source["head"],
             "source_tree": source["tree"], "entered": False, "phase": "fixture_setup",
             "result": "missing", "failure_kind": "unknown_cause",
             "last_http_status": None, "cli_exit_code": None, "cli_signaled": False,
             "children": {}}
    if value is None:
        return empty, False, False
    keys = {"schema", "test", "run_nonce", "source_head", "source_tree", "entered",
            "phase", "result", "failure_kind", "last_http_status", "cli_exit_code",
            "cli_signaled", "children"}
    exact_keys(value, keys, "test diagnostic")
    if value["schema"] != 1 or value["test"] != TEST_NAME or value["run_nonce"] != run_nonce:
        raise ValueError("test diagnostic binding mismatch")
    if value["source_head"] != source["head"] or value["source_tree"] != source["tree"]:
        raise ValueError("test diagnostic source mismatch")
    if value["entered"] is not True or value["phase"] not in PHASES:
        raise ValueError("invalid test diagnostic phase")
    if value["result"] not in {"running", "passed", "failed"}:
        raise ValueError("invalid test diagnostic result")
    if value["failure_kind"] not in {"none", "stage_failed", "unknown_cause"}:
        raise ValueError("invalid test diagnostic failure kind")
    if value["last_http_status"] is not None and (type(value["last_http_status"]) is not int or not 100 <= value["last_http_status"] <= 599):
        raise ValueError("invalid diagnostic HTTP status")
    if value["cli_exit_code"] is not None and type(value["cli_exit_code"]) is not int:
        raise ValueError("invalid diagnostic CLI exit")
    if type(value["cli_signaled"]) is not bool:
        raise ValueError("invalid diagnostic CLI signal flag")
    if not isinstance(value["children"], dict) or set(value["children"]) != CHILD_LABELS:
        raise ValueError("invalid diagnostic child set")
    safe_children = {}
    cleanup_ok = True
    for label, child in value["children"].items():
        exact_keys(child, {"started", "cleanup", "exit_code", "signaled", "escalation"}, "diagnostic child")
        if type(child["started"]) is not bool or type(child["signaled"]) is not bool:
            raise ValueError("invalid diagnostic child booleans")
        if child["cleanup"] not in {"not_started", "running", "reaped", "cleanup_failed"}:
            raise ValueError("invalid diagnostic cleanup")
        if child["escalation"] not in {"none", "kill", "kill_failed"}:
            raise ValueError("invalid diagnostic escalation")
        if child["exit_code"] is not None and type(child["exit_code"]) is not int:
            raise ValueError("invalid diagnostic child exit")
        if child["cleanup"] == "not_started" and (child["started"] or child["exit_code"] is not None or child["signaled"] or child["escalation"] != "none"):
            raise ValueError("inconsistent unstarted child")
        if child["cleanup"] == "running" and (not child["started"] or child["exit_code"] is not None or child["signaled"] or child["escalation"] != "none"):
            raise ValueError("inconsistent running child")
        if child["cleanup"] in {"reaped", "cleanup_failed"} and not child["started"]:
            raise ValueError("cleanup recorded for unstarted child")
        if child["cleanup"] == "reaped" and ((child["exit_code"] is None) == (child["signaled"] is False)):
            raise ValueError("inconsistent reaped status")
        if child["cleanup"] == "cleanup_failed" and child["exit_code"] is not None:
            raise ValueError("failed cleanup has exit status")
        cleanup_ok &= child["cleanup"] in {"not_started", "reaped"}
        safe_children[label] = child
    if value["result"] == "passed" and (value["phase"] != "complete" or value["failure_kind"] != "none"):
        raise ValueError("inconsistent passed diagnostic")
    if value["result"] == "failed" and value["failure_kind"] not in {"stage_failed", "unknown_cause"}:
        raise ValueError("inconsistent failed diagnostic")
    if value["result"] == "running" and value["failure_kind"] != "none":
        raise ValueError("inconsistent running diagnostic")
    cli_ok = value["cli_exit_code"] == 0 and value["cli_signaled"] is False
    children_ok = cleanup_ok and all(
        child["started"] is True and child["cleanup"] == "reaped"
        and child["exit_code"] == 0 and child["signaled"] is False
        and child["escalation"] == "none" for child in safe_children.values())
    result = {"schema": 1, "present": True, **{key: value[key] for key in value if key not in {"schema", "children"}}, "children": safe_children}
    return result, value["result"] == "passed" and cli_ok and children_ok, cleanup_ok


def wrapper_path(value, runner_temp):
    if value is None:
        return None
    path = Path(value)
    if path.is_symlink():
        raise ValueError("wrapper evidence is a symlink")
    path = path.resolve(strict=True)
    if not path.is_relative_to(runner_temp.resolve(strict=True)) or not path.is_dir():
        raise ValueError("wrapper evidence escaped RUNNER_TEMP")
    return path


def admission_receipt(value):
    exact_keys(value, {"namespace", "links", "routes", "uid", "gid", "capabilities", "no_new_privs"}, "admission")
    links, routes, caps = value["links"], value["routes"], value["capabilities"]
    if not isinstance(links, list) or not isinstance(routes, dict) or set(routes) != {"-4", "-6"} or not all(isinstance(rows, list) for rows in routes.values()) or not isinstance(caps, dict) or set(caps) != CAPABILITIES:
        raise ValueError("invalid admission collections")
    return {
        "namespace_changed": isinstance(value["namespace"], str),
        "interfaces_loopback_only": [row.get("ifname") for row in links] == ["lo"],
        "routes_loopback_only": all(row.get("dev") == "lo" and row.get("dst") != "default" and "gateway" not in row for rows in routes.values() for row in rows),
        "capabilities_empty": all(isinstance(bits, str) and int(bits, 16) == 0 for bits in caps.values()),
        "no_new_privs": value["no_new_privs"] == 1,
        "unprivileged": type(value["uid"]) is int and value["uid"] > 0 and type(value["gid"]) is int and value["gid"] > 0,
    }


def sanitize(root, safe, runner_temp, run_nonce):
    if not isinstance(run_nonce, str) or re.fullmatch(r"[0-9]+:[0-9]+", run_nonce) is None:
        raise ValueError("invalid run nonce")
    if root.is_symlink() or safe.is_symlink():
        raise ValueError("receipt path is a symlink")
    root = root.resolve(strict=True); runner_temp = runner_temp.resolve(strict=True)
    if not root.is_relative_to(runner_temp) or safe.parent.resolve(strict=True) != root:
        raise ValueError("receipt roots escaped RUNNER_TEMP")
    if safe.exists():
        raise ValueError("safe output already exists")
    safe.mkdir(mode=0o700)
    source, source_ok = source_receipt(read_optional(root / "source.json"))
    build, build_ok = build_receipt(read_optional(root / "build.json"))
    runtime, runtime_ok = runtime_receipt(read_optional(root / "runtime.json"))
    nextest, nextest_ok = nextest_receipt(read_optional(root / "nextest.json"))
    diagnostic, diagnostic_ok, daemon_cleanup_ok = test_receipt(
        read_optional(root / "test-diagnostic.json"), run_nonce, source)
    wrapper = wrapper_path(runtime["wrapper_evidence"], runner_temp)
    sanitized, present = {}, {name: False for name in RECEIPTS}
    if wrapper is not None:
        for name in RECEIPTS:
            value = read_optional(wrapper / name)
            if value is None: continue
            present[name] = True
            if name == "admission.json": sanitized[name] = admission_receipt(value)
            elif name == "exit.json":
                exact_keys(value, {"exit"}, "exit")
                if type(value["exit"]) is not int: raise ValueError("invalid child exit")
                sanitized[name] = value
            else:
                exact_keys(value, {"reason", "child_pid", "child_exit", "child_reaped", "seconds"}, "supervisor")
                if value["reason"] not in {None, "deadline", "signal", "caller-pipe-closed"} or type(value["child_pid"]) is not int or value["child_pid"] <= 0 or type(value["child_exit"]) is not int or type(value["child_reaped"]) is not bool or type(value["seconds"]) not in {int, float} or value["seconds"] < 0:
                    raise ValueError("invalid supervisor receipt")
                sanitized[name] = {"reason": value["reason"], "child_exit": value["child_exit"], "child_reaped": value["child_reaped"]}
    for name, value in {"source.json": source, "build.json": build,
                        "nextest.json": nextest, "test-diagnostic.json": diagnostic,
                        **sanitized}.items():
        (safe / name).write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    (safe / "runtime.json").write_text(json.dumps({
        "schema": 1, "present": runtime["present"],
        "wrapper_exit": runtime["wrapper_exit"],
        "selected_test_count": nextest["selected_test_started_count"],
        "selected_test_name": TEST_NAME,
        "selected_test_status": nextest["selected_test_terminal"],
    }, sort_keys=True) + "\n")
    admission = sanitized.get("admission.json", {}); child = sanitized.get("exit.json", {}); supervisor = sanitized.get("supervisor.json", {})
    wrapper_exit_consistent = (runtime["wrapper_exit"] == child.get("exit")
                               == supervisor.get("child_exit"))
    wrapper_cleanup_ok = (supervisor.get("reason") is None
                          and supervisor.get("child_reaped") is True
                          and wrapper_exit_consistent)
    accepted = (source_ok and build_ok and runtime_ok and nextest_ok and diagnostic_ok
                and daemon_cleanup_ok and wrapper_exit_consistent
                and all(present.values()) and bool(admission)
                and all(item is True for item in admission.values())
                and child.get("exit") == 0 and wrapper_cleanup_ok)
    if accepted:
        stage = "none"
    elif not source_ok:
        stage = "source"
    elif not build["present"]:
        stage = "build"
    elif runtime["present"] and runtime["wrapper_exit"] == 124:
        stage = "runtime"
    elif not build_ok:
        stage = "build"
    elif not runtime["present"] or runtime["wrapper_exit"] in {124, 125, 126}:
        stage = "runtime"
    elif not all(present.values()):
        stage = "collection"
    elif not wrapper_exit_consistent:
        stage = "collection"
    elif not admission or not all(item is True for item in admission.values()):
        stage = "admission"
    elif not diagnostic["present"]:
        stage = "collection"
    elif not wrapper_cleanup_ok or not daemon_cleanup_ok:
        stage = "cleanup"
    elif (not nextest["parse_valid"]
          or nextest["selected_test_started_count"] != 1
          or nextest["selected_test_terminal_count"] != 1):
        stage = "selection"
    elif not nextest_ok or not diagnostic_ok:
        stage = "test"
    elif not runtime_ok:
        stage = "test"
    else:
        stage = "test"
    (safe / "outcome.json").write_text(json.dumps({"schema": 1, "accepted": bool(accepted), "failure_stage": stage}, sort_keys=True) + "\n")
    return bool(accepted)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True); parser.add_argument("--safe", type=Path, required=True); parser.add_argument("--runner-temp", type=Path, required=True)
    parser.add_argument("--run-nonce", required=True)
    args = parser.parse_args(); sanitize(args.root, args.safe, args.runner_temp, args.run_nonce); return 0


if __name__ == "__main__": raise SystemExit(main())
