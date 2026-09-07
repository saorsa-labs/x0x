#!/usr/bin/env python3
"""Inert controls for the Home acceptance receipt sanitizer."""

import importlib.util
import json
from pathlib import Path
import tempfile

MODULE = Path(__file__).with_name("home-onboarding-collect.py")
SPEC = importlib.util.spec_from_file_location("home_collect", MODULE)
assert SPEC and SPEC.loader
collect = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collect)


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def fixture(root: Path) -> tuple[Path, Path, Path]:
    run = root / "run"
    safe = run / "safe"
    wrapper = root / "x0x-isolation-good"
    run.mkdir(); wrapper.mkdir()
    files = {name: "a" * 64 for name in collect.SOURCE_FILES}
    binaries = {name: {"pre_sha256": "b" * 64, "post_sha256": "b" * 64}
                for name in ("x0x", "x0xd", "home_onboarding_isolated")}
    write(run / "source.json", {"schema": 1, "head": "c" * 40, "tree": "d" * 40,
          "files": files, "unchanged": True})
    write(run / "build.json", {"schema": 1, "lock_sha256": "e" * 64,
          "cargo_metadata_sha256": "f" * 64, "binaries_metadata_sha256": "1" * 64,
          "custody_sha256": "2" * 64,
          "binaries": binaries, "fresh_target": True, "unchanged": True})
    write(run / "runtime.json", {"schema": 1, "wrapper_exit": 0,
          "wrapper_evidence": str(wrapper),
          "selector": "test(=home_onboarding_single_announce_restart)",
          "target": "home_onboarding_isolated", "no_tests_fail": True})
    write(wrapper / "admission.json", {"namespace": "net:[2]", "links": [{"ifname": "lo"}],
          "routes": {"-4": [{"dev": "lo", "dst": "local"}], "-6": []},
          "uid": 1001, "gid": 1001,
          "capabilities": {key: "0000000000000000" for key in
                           ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
          "no_new_privs": 1})
    write(wrapper / "exit.json", {"exit": 0})
    write(wrapper / "supervisor.json", {"reason": None, "child_pid": 42,
          "child_exit": 0, "child_reaped": True, "seconds": 1.0})
    return run, safe, wrapper


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        run, safe, wrapper = fixture(temp)
        assert collect.sanitize(run, safe, temp) is True
        assert json.loads((safe / "outcome.json").read_text())["accepted"] is True
        assert "child_pid" not in (safe / "supervisor.json").read_text()

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        run, safe, wrapper = fixture(temp)
        (wrapper / "exit.json").unlink()
        assert collect.sanitize(run, safe, temp) is False
        assert json.loads((safe / "outcome.json").read_text())["failure_stage"] == "collection"

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        run, safe, _ = fixture(temp)
        runtime = json.loads((run / "runtime.json").read_text())
        runtime["wrapper_evidence"] = "/tmp"
        write(run / "runtime.json", runtime)
        try:
            collect.sanitize(run, safe, temp)
        except ValueError as error:
            assert "symlink" in str(error) or "escaped RUNNER_TEMP" in str(error)
        else:
            raise AssertionError("unsafe wrapper path was accepted")

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        run, safe, wrapper = fixture(temp)
        write(wrapper / "supervisor.json", {"reason": "mystery", "child_pid": 1,
              "child_exit": 0, "child_reaped": True, "seconds": 1})
        try:
            collect.sanitize(run, safe, temp)
        except ValueError as error:
            assert "invalid supervisor receipt" in str(error)
        else:
            raise AssertionError("unknown supervisor reason was accepted")

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        run, safe, wrapper = fixture(temp)
        admission = json.loads((wrapper / "admission.json").read_text())
        admission["routes"] = {}
        write(wrapper / "admission.json", admission)
        try:
            collect.sanitize(run, safe, temp)
        except ValueError as error:
            assert "invalid admission collections" in str(error)
        else:
            raise AssertionError("missing route families were accepted")

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        run, safe, wrapper = fixture(temp)
        supervisor = json.loads((wrapper / "supervisor.json").read_text())
        supervisor["child_exit"] = False
        write(wrapper / "supervisor.json", supervisor)
        try:
            collect.sanitize(run, safe, temp)
        except ValueError as error:
            assert "invalid supervisor receipt" in str(error)
        else:
            raise AssertionError("boolean child exit was accepted")

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        run, safe, _ = fixture(temp)
        safe.mkdir(); (safe / "raw-secret").write_text("must not survive")
        try:
            collect.sanitize(run, safe, temp)
        except ValueError as error:
            assert "already exists" in str(error)
        else:
            raise AssertionError("dirty safe directory was accepted")

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        run, safe, _ = fixture(temp)
        source = json.loads((run / "source.json").read_text())
        source["files"] = {"foreign": "g" * 64}
        write(run / "source.json", source)
        try:
            collect.sanitize(run, safe, temp)
        except ValueError as error:
            assert "source file set" in str(error)
        else:
            raise AssertionError("forged source map was accepted")

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        run, safe, _ = fixture(temp)
        source = json.loads((run / "source.json").read_text())
        source["head"] = "not-a-commit"
        write(run / "source.json", source)
        try:
            collect.sanitize(run, safe, temp)
        except ValueError as error:
            assert "source head" in str(error)
        else:
            raise AssertionError("forged source hash was accepted")

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        run, safe, _ = fixture(temp)
        (run / "build.json").unlink(); (run / "runtime.json").unlink()
        assert collect.sanitize(run, safe, temp) is False
        assert json.loads((safe / "outcome.json").read_text())["failure_stage"] == "build"
        assert json.loads((safe / "build.json").read_text())["present"] is False

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        run, safe, _ = fixture(temp)
        runtime = json.loads((run / "runtime.json").read_text())
        assert collect.admission_deadline_exit(915) is None
        assert collect.admission_deadline_exit(914.999) == 124
        assert collect.admission_deadline_exit(float("nan")) == 124
        deadline_exit = collect.admission_deadline_exit(914.999)
        runtime.update(wrapper_exit=deadline_exit, wrapper_evidence=None)
        write(run / "runtime.json", runtime)
        assert collect.sanitize(run, safe, temp) is False
        assert json.loads((safe / "outcome.json").read_text())["failure_stage"] == "runtime"

    print("home onboarding collector controls: 11/11 passed")


if __name__ == "__main__":
    main()
