#!/usr/bin/env python3
"""Inert controls for #623; never starts CPU workers or product tests."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock


ENTRY = Path(__file__).with_name("issue623-dial-contention.py")
SPEC = importlib.util.spec_from_file_location("issue623", ENTRY)
issue623 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(issue623)


class Issue623Controls(unittest.TestCase):
    def test_workflow_is_branch_scoped_and_runs_both_arms(self):
        workflow = (ENTRY.parents[2] / ".github/workflows/issue-623-dial-contention.yml").read_text()
        self.assertIn("branches:\n      - codex/623-dial-contention-proof", workflow)
        self.assertNotIn("workflow_dispatch", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("fail-fast: false", workflow)
        self.assertIn("arm: [baseline, candidate]", workflow)
        self.assertIn("timeout-minutes: 180", workflow)

    def test_cgroup_quota_reduces_affinity_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "actions" / "job"
            nested.mkdir(parents=True)
            (nested / "cpu.max").write_text("150000 100000\n")
            proc = root / "proc-cgroup"
            proc.write_text("0::/actions/job\n")
            with unittest.mock.patch.object(
                issue623.os, "sched_getaffinity", lambda _pid: {0, 1, 2, 3}, create=True
            ):
                facts = issue623.cpu_facts(root, proc)
        self.assertEqual(facts["effective_cpus"], 1.5)
        self.assertEqual(facts["worker_count"], 8)

    def test_baseline_and_candidate_graphs_are_distinct(self):
        self.assertEqual(issue623.cargo_config("baseline"), [])
        candidate = " ".join(issue623.cargo_config("candidate"))
        self.assertIn(issue623.ANT_REPAIR, candidate)
        self.assertIn(issue623.ANT_REPOSITORY, candidate)

    def test_only_exact_terminal_abort_is_classified(self):
        exact = f"ConnectionFailed: {issue623.EXPECTED_ABORT}".encode()
        self.assertEqual(issue623.classify(100, exact), "EXPECTED_TERMINAL_DIAL_ABORT")
        self.assertEqual(issue623.classify(1, exact), "OTHER_FAILURE")
        self.assertEqual(issue623.classify(1, b"another timeout"), "OTHER_FAILURE")
        self.assertEqual(issue623.classify(0, exact), "PASS")

    def test_deadline_or_signal_never_inherits_buffered_expected_abort(self):
        exact = f"ConnectionFailed: {issue623.EXPECTED_ABORT}".encode()
        self.assertEqual(issue623.classify(124, exact), "ISOLATION_DEADLINE")
        self.assertEqual(issue623.classify(-15, exact), "SIGNAL_15")

    def test_isolation_receipt_binds_role_scratch_and_reaping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scratch = root / "x0x-metadata-fixed"
            scratch.mkdir()
            evidence = root / "x0x-isolation-fixed"
            evidence.mkdir()
            (evidence / "admission.json").write_text('{"namespace_changed":true,"no_new_privs":1}')
            (evidence / "supervisor.json").write_text('{"reason":null,"child_reaped":true}')
            (evidence / "role.json").write_text(
                '{"role":"run-01","scratch":"x0x-metadata-fixed"}'
            )
            (evidence / "exit.json").write_text('{"exit":1}')
            facts = issue623.isolation_facts(root, set(), "run-01", scratch)
        self.assertTrue(facts["child_reaped"])
        self.assertEqual(facts["admitted_exit"], 1)

    def test_worker_cleanup_reaps_every_owned_process(self):
        live = Mock()
        live.poll.side_effect = [None, -15]
        live.wait.return_value = -15
        stopped = Mock()
        stopped.poll.return_value = 0
        receipt = issue623.stop_workers([live, stopped])
        live.terminate.assert_called_once_with()
        stopped.terminate.assert_not_called()
        self.assertEqual(receipt, {"started": 2, "reaped": 2})

    def test_cleanup_escalates_bounded_worker(self):
        worker = Mock()
        worker.poll.side_effect = [None, -9]
        worker.wait.side_effect = [subprocess.TimeoutExpired("worker", 5), 0]
        receipt = issue623.stop_workers([worker])
        worker.terminate.assert_called_once_with()
        worker.kill.assert_called_once_with()
        self.assertEqual(receipt["reaped"], 1)


if __name__ == "__main__":
    unittest.main()
