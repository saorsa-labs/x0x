#!/usr/bin/env python3
"""Offline controls for the closed #417 custody collector."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "collector", Path(__file__).with_name("isolation-custody-collect.py")
)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)

HEAD = "7367c2ce3cf05cbc3406df631e20029353fa1e1d"
TREE = "bbb6db34fed961a721b446f87fb310f37331cc1d"
CAPABILITIES = {key: "0000000000000000" for key in collector.CAPABILITY_KEYS}
ADMISSION = {
    "namespace": "net:[4026532567]", "namespace_changed": True,
    "links": [{"ifname": "lo", "address": "00:00:00:00:00:00"}],
    "routes": {"-4": [{"dst": "127.0.0.0/8", "dev": "lo"}], "-6": []},
    "uid": 1001, "gid": 1001, "capabilities": CAPABILITIES, "no_new_privs": 1,
}
SUPERVISOR = {"reason": None, "child_pid": 4242, "child_exit": 0,
              "child_reaped": True, "seconds": 50.62}


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)
        self.runner_temp = self.root / "_temp"
        self.workspace = self.root / "workspace"
        self.output = self.root / "out"
        self.runner_temp.mkdir(); self.workspace.mkdir()
        (self.workspace / "Cargo.lock").write_text("lock fixture\n")

    def isolation(self, name, role="selection", scratch=None, admission=None,
                  supervisor=None, exit_code=0):
        directory = self.runner_temp / name
        directory.mkdir()
        (directory / "role.json").write_text(json.dumps({"role": role, "scratch": scratch}))
        (directory / "admission.json").write_text(json.dumps(admission or ADMISSION))
        (directory / "supervisor.json").write_text(json.dumps(supervisor or SUPERVISOR))
        if exit_code is not None:
            (directory / "exit.json").write_text(json.dumps({"exit": exit_code}))
        (directory / "runtime.json").write_text(json.dumps(
            {"command": ["cargo"], "env": {"HOME": "/home/runner"},
             "evidence": str(directory)}))
        return directory

    def metadata(self, source=None, files=None, name="x0x-metadata-bbb"):
        directory = self.runner_temp / name
        directory.mkdir()
        binary = self.workspace / "target/debug/deps/voice_datagram_e2e-66a743b2"
        generated = {
            str(self.workspace / "Cargo.lock"): "a" * 64,
            str(directory / "binaries.json"): "b" * 64,
            str(directory / "cargo.json"): "c" * 64,
            str(binary): "d" * 64,
        }
        payload = files if files is not None else generated
        for path in payload:
            if path.endswith(("Cargo.lock", "binaries.json", "cargo.json")) or "voice_datagram_e2e-" in path:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).touch(exist_ok=True)
                if "voice_datagram_e2e-" in path:
                    Path(path).chmod(0o755)
        (directory / "custody.json").write_text(json.dumps(
            {"files": payload, "source": source if source is not None else [HEAD, TREE]}))
        lock_digest = payload.get(str(self.workspace / "Cargo.lock"), "e" * 64)
        (directory / "lock.sha256").write_text(lock_digest + "  Cargo.lock\n")
        (directory / "cargo.json").write_text(json.dumps({"packages": []}))
        (directory / "binaries.json").write_text(json.dumps({"rust-binaries": {}}))
        return directory

    def run_collector(self, expect="success", roles="selection,acceptance",
                      target="voice_datagram_e2e", sha=HEAD, min_runs="2"):
        environment = {
            "RUNNER_TEMP": str(self.runner_temp), "GITHUB_WORKSPACE": str(self.workspace),
            "X0X_CUSTODY_EXPECT": expect, "X0X_CUSTODY_MIN_RUNS": "2",
            "X0X_CUSTODY_ROLES": roles, "X0X_CUSTODY_TARGET": target, "GITHUB_SHA": sha,
            "X0X_CUSTODY_MIN_RUNS": min_runs,
            "GITHUB_OUTPUT": str(self.root / "github-output"),
        }
        old = dict(os.environ); os.environ.clear(); os.environ.update(environment)
        old_argv = list(collector.sys.argv); collector.sys.argv = ["collector", str(self.output)]
        try:
            collector.main()
        finally:
            collector.sys.argv = old_argv; os.environ.clear(); os.environ.update(old)

    def receipt(self):
        return json.loads((self.output / "custody-receipt.json").read_text())

    def valid_pair(self):
        metadata = self.metadata()
        self.isolation("x0x-isolation-selection", role="selection")
        self.isolation("x0x-isolation-acceptance", role="acceptance", scratch=metadata.name)

    def assert_refused(self, code, **kwargs):
        with self.assertRaises(SystemExit) as raised:
            self.run_collector(**kwargs)
        self.assertIn(code, str(raised.exception))
        return self.receipt()

    def reset(self):
        self.temporary.cleanup(); self.setUp()

    def test_valid_roles_binding_and_target_are_complete(self):
        self.valid_pair(); self.run_collector(); receipt = self.receipt()
        self.assertEqual(receipt["status"], "complete"); self.assertTrue(receipt["valid"])
        self.assertEqual(receipt["observed_roles"], ["acceptance", "selection"])
        self.assertEqual(receipt["build_custody"][0]["target_binaries"],
                         ["target/debug/deps/voice_datagram_e2e-66a743b2"])

    def test_receipt_drops_sensitive_paths_pid_and_runtime_files(self):
        self.valid_pair(); self.run_collector(); text = (self.output / "custody-receipt.json").read_text()
        self.assertNotIn(str(self.runner_temp), text); self.assertNotIn(str(self.workspace), text)
        self.assertNotIn("/home/runner", text); self.assertNotIn("4242", text)
        self.assertIn("target/debug/deps/voice_datagram_e2e-66a743b2", text)

    def test_boolean_cannot_satisfy_integer_or_namespace_fields(self):
        self.valid_pair(); path = self.runner_temp / "x0x-isolation-selection" / "admission.json"
        raw = json.loads(path.read_text()); raw["uid"] = True; path.write_text(json.dumps(raw))
        self.assert_refused("isolation:ADMISSION_UID")
        self.reset(); self.valid_pair(); path = self.runner_temp / "x0x-isolation-selection" / "admission.json"
        raw = json.loads(path.read_text()); raw["namespace_changed"] = False; path.write_text(json.dumps(raw))
        self.assert_refused("isolation:ADMISSION_NAMESPACE")

    def test_supervisor_types_and_bounds_are_closed(self):
        self.valid_pair(); path = self.runner_temp / "x0x-isolation-selection" / "supervisor.json"
        raw = json.loads(path.read_text()); raw["child_reaped"] = "true"; path.write_text(json.dumps(raw))
        self.assert_refused("isolation:SCHEMA_TYPE")

    def test_source_lock_and_target_are_linked(self):
        self.valid_pair(); path = self.runner_temp / "x0x-metadata-bbb" / "custody.json"
        raw = json.loads(path.read_text()); raw["files"][str(self.workspace / "Cargo.lock")] = "e" * 64
        path.write_text(json.dumps(raw)); self.assert_refused("build_custody:CUSTODY_LOCK")
        self.reset(); self.valid_pair(); path = self.runner_temp / "x0x-metadata-bbb" / "custody.json"
        raw = json.loads(path.read_text()); old = str(self.workspace / "target/debug/deps/voice_datagram_e2e-66a743b2")
        raw["files"][str(self.workspace / "target/debug/deps/other-66a743b2")] = raw["files"].pop(old)
        path.write_text(json.dumps(raw)); self.assert_refused("build_custody:CUSTODY_TARGET")

    def test_binary_target_path_is_workspace_executable_and_not_a_lookalike(self):
        self.valid_pair()
        path = self.runner_temp / "x0x-metadata-bbb" / "custody.json"
        raw = json.loads(path.read_text())
        old = str(self.workspace / "target/debug/deps/voice_datagram_e2e-66a743b2")
        outside = self.root / "outside" / "voice_datagram_e2e-66a743b2"
        outside.parent.mkdir()
        outside.write_text("lookalike")
        outside.chmod(0o755)
        raw["files"][str(outside)] = raw["files"].pop(old)
        path.write_text(json.dumps(raw))
        self.assert_refused("build_custody:CUSTODY_TARGET")
        self.reset(); self.valid_pair()
        path = self.runner_temp / "x0x-metadata-bbb" / "custody.json"
        raw = json.loads(path.read_text())
        binary = self.workspace / "target/debug/deps/voice_datagram_e2e-66a743b2"
        binary.chmod(0o644)
        raw["files"][str(binary)] = raw["files"].pop(str(binary))
        path.write_text(json.dumps(raw))
        self.assert_refused("build_custody:CUSTODY_TARGET")
        self.reset(); self.valid_pair()
        path = self.runner_temp / "x0x-metadata-bbb" / "custody.json"
        raw = json.loads(path.read_text())
        binary = self.workspace / "target/debug/deps/voice_datagram_e2e-66a743b2"
        link = self.root / "target-link"
        link.symlink_to(binary)
        raw["files"][str(link)] = raw["files"].pop(str(binary))
        path.write_text(json.dumps(raw))
        self.assert_refused("build_custody:CUSTODY_TARGET")

    def test_missing_exit_nonzero_cancel_and_unreaped_fail_green_job(self):
        self.valid_pair(); (self.runner_temp / "x0x-isolation-selection" / "exit.json").unlink()
        self.assert_refused("isolation:EXIT_MISSING")
        self.reset(); self.valid_pair(); path = self.runner_temp / "x0x-isolation-selection" / "exit.json"
        path.write_text('{"exit": 101}'); self.assert_refused("isolation:EXIT_NONZERO")
        self.reset(); self.valid_pair(); path = self.runner_temp / "x0x-isolation-selection" / "supervisor.json"
        raw = json.loads(path.read_text()); raw["reason"] = "deadline"; path.write_text(json.dumps(raw))
        self.assert_refused("isolation:SUPERVISOR_CANCELLED")
        self.reset(); self.valid_pair(); path = self.runner_temp / "x0x-isolation-selection" / "supervisor.json"
        raw = json.loads(path.read_text()); raw["child_reaped"] = False
        path.write_text(json.dumps(raw)); self.assert_refused("isolation:SUPERVISOR_UNREAPED")

    def test_admission_interface_route_and_capability_negatives(self):
        for mutate, code in (
            (lambda a: a["links"].append({"ifname": "eth0"}), "ADMISSION_INTERFACE"),
            (lambda a: a["routes"]["-4"].append({"dst": "default", "dev": "lo"}), "ADMISSION_ROUTE"),
            (lambda a: a["capabilities"].update(CapEff="0000000000000001"), "ADMISSION_CAPABILITIES"),
        ):
            self.valid_pair(); path = self.runner_temp / "x0x-isolation-selection" / "admission.json"
            raw = json.loads(path.read_text()); mutate(raw); path.write_text(json.dumps(raw))
            self.assert_refused(f"isolation:{code}"); self.reset()

    def test_role_scratch_source_and_extra_directory_negatives(self):
        self.valid_pair(); path = self.runner_temp / "x0x-isolation-acceptance" / "role.json"
        path.write_text(json.dumps({"role": "acceptance", "scratch": "x0x-metadata-other"}))
        self.assert_refused("job:ACCEPTANCE_BINDING")
        self.reset(); self.valid_pair(); path = self.runner_temp / "x0x-metadata-bbb" / "custody.json"
        raw = json.loads(path.read_text()); raw["source"][0] = "deadbeef" * 5; path.write_text(json.dumps(raw))
        self.assert_refused("build_custody:CUSTODY_SOURCE")
        self.reset(); self.valid_pair(); self.isolation("x0x-isolation-extra", role="extra")
        self.assert_refused("isolation:ROLE_SET_MISMATCH")

    def test_output_is_exclusive_and_symlink_safe(self):
        self.valid_pair(); self.output.mkdir(); (self.output / "raw-secret").write_text("ghp_secret")
        with self.assertRaises(SystemExit) as raised: self.run_collector()
        self.assertIn("OUTPUT_NOT_EXCLUSIVE", str(raised.exception))

    def test_upload_eligibility_requires_exclusive_receipt_creation(self):
        self.valid_pair(); self.output.mkdir()
        (self.output / "custody-receipt.json").write_text("stale")
        with self.assertRaises(SystemExit): self.run_collector()
        self.assertFalse((self.root / "github-output").exists())
        self.reset(); self.valid_pair(); self.run_collector()
        self.assertEqual((self.root / "github-output").read_text(), "receipt_eligible=true\n")

    def test_input_scratch_symlink_or_file_cannot_be_ignored(self):
        self.valid_pair()
        (self.runner_temp / "x0x-isolation-junk").write_text("raw")
        with self.assertRaises(SystemExit) as raised:
            self.run_collector()
        self.assertIn("isolation:PATH_UNSAFE", str(raised.exception))
        self.reset(); self.valid_pair()
        target = self.root / "metadata-target"; target.mkdir()
        (self.runner_temp / "x0x-metadata-junk").symlink_to(target, target_is_directory=True)
        with self.assertRaises(SystemExit) as raised:
            self.run_collector()
        self.assertIn("build_custody:PATH_UNSAFE", str(raised.exception))
        self.reset(); self.valid_pair(); target = self.root / "raw"; target.write_text("ghs_secret")
        self.output.symlink_to(target)
        with self.assertRaises(SystemExit) as raised: self.run_collector()
        self.assertIn("OUTPUT_NOT_EXCLUSIVE", str(raised.exception))

    def test_failing_job_keeps_valid_records_and_closed_errors(self):
        self.metadata(); self.isolation("x0x-isolation-selection", role="selection")
        self.isolation("x0x-isolation-acceptance", role="acceptance", scratch="x0x-metadata-bbb",
                       supervisor={**SUPERVISOR, "reason": "deadline"}, exit_code=None)
        self.run_collector(expect="failure"); receipt = self.receipt()
        self.assertEqual(receipt["status"], "incomplete"); self.assertEqual(len(receipt["isolation_runs"]), 2)
        self.assertTrue(all(set(item) == {"stage", "code", "where"} for item in receipt["errors"]))

    def test_failing_job_preserves_valid_prior_record_when_later_json_is_bad(self):
        self.metadata(); self.isolation("x0x-isolation-selection", role="selection")
        later = self.isolation("x0x-isolation-acceptance", role="acceptance", scratch="x0x-metadata-bbb")
        (later / "supervisor.json").write_text("{not json")
        self.run_collector(expect="failure"); receipt = self.receipt()
        self.assertEqual(len(receipt["isolation_runs"]), 1)
        self.assertTrue(any(item["code"] == "RECEIPT_UNPARSEABLE" for item in receipt["errors"]))

    def test_malformed_paths_and_no_evidence_fail_green_job(self):
        self.valid_pair(); path = self.runner_temp / "x0x-metadata-bbb" / "custody.json"
        raw = json.loads(path.read_text()); lock = str(self.workspace / "Cargo.lock")
        raw["files"]["/tmp/evil/Cargo.lock"] = raw["files"].pop(lock); path.write_text(json.dumps(raw))
        self.assert_refused("build_custody:CUSTODY_INPUTS")
        self.reset(); self.assert_refused("job:ROLE_SET_MISMATCH")

    def test_leak_guard_uses_closed_rejection(self):
        with self.assertRaises(collector.Rejected): collector.assert_no_leak({"note": "ghp_secret"})
        with self.assertRaises(collector.Rejected): collector.assert_no_leak({"note": "/home/runner/private"})

    def test_minimum_run_count_and_expectation_are_closed(self):
        self.valid_pair()
        self.assert_refused("job:RUN_COUNT", min_runs="3")
        self.reset()
        self.valid_pair()
        with self.assertRaises(SystemExit) as raised:
            self.run_collector(expect="unknown")
        self.assertIn("SCHEMA_VALUE", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
