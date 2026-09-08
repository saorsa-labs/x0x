#!/usr/bin/env python3
"""Inert controls for closed Home acceptance receipts."""
import importlib.util
import json
from pathlib import Path
import tempfile

MODULE = Path(__file__).with_name("home-onboarding-collect.py")
SPEC = importlib.util.spec_from_file_location("home_collect", MODULE)
assert SPEC and SPEC.loader
collect = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collect)
NONCE = "34171638282:1"
HEAD, TREE = "c" * 40, "d" * 40


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def nextest_lines(terminal="ok", name=collect.QUALIFIED_TEST_NAME):
    return [json.dumps({"type": "suite", "event": "started", "test_count": 7}),
            json.dumps({"type": "test", "event": "started", "name": name}),
            json.dumps({"type": "test", "event": terminal, "name": name}),
            json.dumps({"type": "suite", "event": terminal})]


def pinned_nextest_09126_lines():
    """Observed from cargo-nextest 0.9.126 ignored-only output."""
    other = "x0x::home_onboarding_isolated$unrelated"
    return [json.dumps({"type": "suite", "event": "started", "test_count": 1,
                        "nextest": {"crate": "x0x", "test_binary": "home_onboarding_isolated", "kind": "test"}}),
            json.dumps({"type": "test", "event": "started", "name": other}),
            json.dumps({"type": "test", "event": "started", "name": collect.QUALIFIED_TEST_NAME}),
            json.dumps({"type": "test", "event": "ignored", "name": other}),
            json.dumps({"type": "test", "event": "ok", "name": collect.QUALIFIED_TEST_NAME, "exec_time": 0.01}),
            json.dumps({"type": "suite", "event": "ok", "passed": 1, "failed": 0,
                        "ignored": 1, "measured": 0, "filtered_out": 18446744073709551615,
                        "exec_time": 0.01,
                        "nextest": {"crate": "x0x", "test_binary": "home_onboarding_isolated", "kind": "test"}})]


def diagnostic(result="passed", phase="complete"):
    children = {label: {"started": True, "cleanup": "reaped", "exit_code": 0,
                "signaled": False, "escalation": "none"}
                for label in collect.CHILD_LABELS}
    return {"schema": 1, "test": collect.TEST_NAME, "run_nonce": NONCE,
            "source_head": HEAD, "source_tree": TREE, "entered": True,
            "phase": phase, "result": result,
            "failure_kind": "none" if result != "failed" else "stage_failed",
            "last_http_status": 200, "cli_exit_code": 0, "cli_signaled": False,
            "children": children}


def fixture(root: Path):
    run, safe, wrapper = root / "run", root / "run/safe", root / "isolation"
    run.mkdir(); wrapper.mkdir()
    files = {name: "a" * 64 for name in collect.SOURCE_FILES}
    binaries = {name: {"pre_sha256": "b" * 64, "post_sha256": "b" * 64}
                for name in ("x0x", "x0xd", "home_onboarding_isolated")}
    write(run / "source.json", {"schema": 1, "head": HEAD, "tree": TREE,
          "files": files, "unchanged": True})
    write(run / "build.json", {"schema": 1, "lock_sha256": "e" * 64,
          "cargo_metadata_sha256": "f" * 64, "binaries_metadata_sha256": "1" * 64,
          "custody_sha256": "2" * 64, "binaries": binaries,
          "fresh_target": True, "unchanged": True})
    write(run / "runtime.json", {"schema": 1, "wrapper_exit": 0,
          "wrapper_evidence": str(wrapper),
          "selector": "test(=home_onboarding_single_announce_restart)",
          "target": "home_onboarding_isolated", "no_tests_fail": True})
    write(run / "nextest.json", collect.nextest_receipt_from_lines(pinned_nextest_09126_lines()))
    write(run / "test-diagnostic.json", diagnostic())
    write(wrapper / "admission.json", {"namespace": "net:[2]", "links": [{"ifname": "lo"}],
          "routes": {"-4": [{"dev": "lo", "dst": "local"}], "-6": []},
          "uid": 1001, "gid": 1001,
          "capabilities": {key: "0000000000000000" for key in collect.CAPABILITIES},
          "no_new_privs": 1})
    write(wrapper / "exit.json", {"exit": 0})
    write(wrapper / "supervisor.json", {"reason": None, "child_pid": 42,
          "child_exit": 0, "child_reaped": True, "seconds": 1.0})
    return run, safe, wrapper


def rejected(mutator, message):
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory); run, safe, wrapper = fixture(temp)
        mutator(run, wrapper)
        try:
            collect.sanitize(run, safe, temp, NONCE)
        except ValueError:
            return
        raise AssertionError(message)


def main():
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory); run, safe, _ = fixture(temp)
        assert collect.sanitize(run, safe, temp, NONCE)
        assert json.loads((safe / "outcome.json").read_text())["accepted"] is True
        nextest = json.loads((safe / "nextest.json").read_text())
        assert nextest["suite_test_count"] == 1
        assert nextest["selected_test_started_count"] == 1

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory); run, safe, wrapper = fixture(temp)
        (wrapper / "exit.json").unlink()
        assert not collect.sanitize(run, safe, temp, NONCE)
        assert json.loads((safe / "outcome.json").read_text())["failure_stage"] == "collection"

    rejected(lambda run, wrapper: write(run / "runtime.json", {
        **json.loads((run / "runtime.json").read_text()), "wrapper_evidence": "/tmp"}),
        "escaped wrapper accepted")
    rejected(lambda run, wrapper: write(wrapper / "supervisor.json", {
        "reason": "mystery", "child_pid": 1, "child_exit": 0,
        "child_reaped": True, "seconds": 1}), "unknown supervisor accepted")
    rejected(lambda run, wrapper: write(wrapper / "admission.json", {
        **json.loads((wrapper / "admission.json").read_text()), "routes": {}}),
        "forged admission accepted")

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory); run, safe, _ = fixture(temp)
        safe.mkdir(); (safe / "raw-secret").write_text("secret")
        try: collect.sanitize(run, safe, temp, NONCE)
        except ValueError: pass
        else: raise AssertionError("dirty safe directory accepted")

    rejected(lambda run, wrapper: write(run / "source.json", {
        **json.loads((run / "source.json").read_text()), "head": "bad"}),
        "forged source accepted")
    rejected(lambda run, wrapper: write(run / "test-diagnostic.json", {
        **json.loads((run / "test-diagnostic.json").read_text()), "run_nonce": "1:2"}),
        "replayed diagnostic accepted")
    rejected(lambda run, wrapper: write(run / "test-diagnostic.json", {
        **json.loads((run / "test-diagnostic.json").read_text()), "raw_error": "secret"}),
        "raw diagnostic field accepted")
    rejected(lambda run, wrapper: write(run / "test-diagnostic.json", {
        **json.loads((run / "test-diagnostic.json").read_text()), "last_http_status": True}),
        "forged HTTP status accepted")
    rejected(lambda run, wrapper: write(run / "nextest.json", {
        **json.loads((run / "nextest.json").read_text()), "raw_output": "secret"}),
        "raw nextest field accepted")

    for lines in (nextest_lines(name="x0x::other$test"),
                  nextest_lines() + [nextest_lines()[1]],
                  nextest_lines(name=collect.QUALIFIED_TEST_NAME + " #2"),
                  nextest_lines() + ["not-json secret"]):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory); run, safe, _ = fixture(temp)
            write(run / "nextest.json", collect.nextest_receipt_from_lines(lines))
            assert not collect.sanitize(run, safe, temp, NONCE)
            assert json.loads((safe / "outcome.json").read_text())["failure_stage"] == "selection"

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory); run, safe, _ = fixture(temp)
        write(run / "nextest.json", collect.nextest_receipt_from_lines(nextest_lines("failed")))
        write(run / "test-diagnostic.json", diagnostic("failed", "announce"))
        runtime = json.loads((run / "runtime.json").read_text()); runtime["wrapper_exit"] = 100
        write(run / "runtime.json", runtime)
        write(run.parent / "isolation" / "exit.json", {"exit": 100})
        supervisor = json.loads((run.parent / "isolation" / "supervisor.json").read_text())
        supervisor["child_exit"] = 100
        write(run.parent / "isolation" / "supervisor.json", supervisor)
        assert not collect.sanitize(run, safe, temp, NONCE)
        result = json.loads((safe / "test-diagnostic.json").read_text())
        assert result["phase"] == "announce" and result["failure_kind"] == "stage_failed"
        assert json.loads((safe / "outcome.json").read_text())["failure_stage"] == "test"

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory); run, safe, _ = fixture(temp)
        value = diagnostic("failed", "owner_initial_start")
        value["children"]["owner_initial"].update(cleanup="cleanup_failed", exit_code=None)
        write(run / "test-diagnostic.json", value)
        assert not collect.sanitize(run, safe, temp, NONCE)
        assert json.loads((safe / "outcome.json").read_text())["failure_stage"] == "cleanup"

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory); run, safe, _ = fixture(temp)
        value = diagnostic("failed", "fixture_setup")
        value["cli_exit_code"] = None
        for child in value["children"].values():
            child.update(started=False, cleanup="not_started", exit_code=None)
        write(run / "test-diagnostic.json", value)
        assert not collect.sanitize(run, safe, temp, NONCE)
        assert json.loads((safe / "outcome.json").read_text())["failure_stage"] == "test"

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory); run, safe, _ = fixture(temp)
        (run / "test-diagnostic.json").unlink()
        assert not collect.sanitize(run, safe, temp, NONCE)
        assert json.loads((safe / "outcome.json").read_text())["accepted"] is False

    assert collect.admission_deadline_exit(915) is None
    assert collect.admission_deadline_exit(914.999) == 124
    print("home onboarding collector controls: 20/20 passed")


if __name__ == "__main__":
    main()
