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


def admission_deadline_exit(remaining):
    """Return the closed exit for a late/invalid runtime admission clock."""
    if type(remaining) not in {int, float} or not math.isfinite(remaining):
        return 124
    return None if remaining >= MIN_RUNTIME_REMAINING_SECONDS else 124


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


def sanitize(root, safe, runner_temp):
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
    for name, value in {"source.json": source, "build.json": build, **sanitized}.items():
        (safe / name).write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    selected = 1 if runtime_ok else None
    (safe / "runtime.json").write_text(json.dumps({"schema": 1, "present": runtime["present"], "wrapper_exit": runtime["wrapper_exit"], "selected_test_count": selected, "selected_test_name": "home_onboarding_single_announce_restart", "selected_test_status": "passed" if runtime_ok else "failed_or_incomplete"}, sort_keys=True) + "\n")
    admission = sanitized.get("admission.json", {}); child = sanitized.get("exit.json", {}); supervisor = sanitized.get("supervisor.json", {})
    accepted = source_ok and build_ok and runtime_ok and all(present.values()) and bool(admission) and all(item is True for item in admission.values()) and child.get("exit") == 0 and supervisor == {"reason": None, "child_exit": 0, "child_reaped": True}
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
    elif not runtime_ok:
        stage = "runtime"
    elif not all(present.values()):
        stage = "collection"
    elif not admission or not all(item is True for item in admission.values()):
        stage = "admission"
    elif supervisor.get("child_reaped") is not True:
        stage = "cleanup"
    else:
        stage = "test"
    (safe / "outcome.json").write_text(json.dumps({"schema": 1, "accepted": bool(accepted), "failure_stage": stage}, sort_keys=True) + "\n")
    return bool(accepted)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True); parser.add_argument("--safe", type=Path, required=True); parser.add_argument("--runner-temp", type=Path, required=True)
    args = parser.parse_args(); sanitize(args.root, args.safe, args.runner_temp); return 0


if __name__ == "__main__": raise SystemExit(main())
