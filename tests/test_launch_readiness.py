#!/usr/bin/env python3
"""Focused tests for the launch-readiness gate policy."""

from __future__ import annotations

import csv
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


def load_launch_readiness():
    script = Path(__file__).with_name("launch_readiness.py")
    spec = importlib.util.spec_from_file_location("launch_readiness", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LaunchReadinessGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lr = load_launch_readiness()

    def test_broad_launch_per_peer_timeout_gate_is_ratio_based(self) -> None:
        deltas = {
            "nyc": {
                "dispatcher_completed": 1000,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 160,
            }
        }
        posts = {"nyc": {"suppressed_peers_size": 0}}
        scenario = self.lr.ScenarioResult(name="fanout_burst", duration_secs=1.0)

        passed, violations = self.lr.evaluate_slos(
            "broad-launch", deltas, posts, scenario
        )

        self.assertTrue(passed)
        self.assertEqual([], violations)

    def test_broad_launch_rejects_high_per_peer_timeout_ratio(self) -> None:
        deltas = {
            "sydney": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 40,
            }
        }
        posts = {"sydney": {"suppressed_peers_size": 0}}
        scenario = self.lr.ScenarioResult(name="fanout_burst", duration_secs=1.0)

        passed, violations = self.lr.evaluate_slos(
            "broad-launch", deltas, posts, scenario
        )

        self.assertFalse(passed)
        self.assertIn("per_peer_timeout/dispatcher_completed ratio", violations[0])

    def test_broad_launch_suppressed_peers_gate_is_ratio_based(self) -> None:
        deltas = {
            "nuremberg": {
                "dispatcher_completed": 1000,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
            }
        }
        posts = {
            "nuremberg": {
                "suppressed_peers_size": 134,
                "known_peer_topic_pairs": 1422,
            }
        }
        scenario = self.lr.ScenarioResult(name="fanout_burst", duration_secs=1.0)

        passed, violations = self.lr.evaluate_slos(
            "broad-launch", deltas, posts, scenario
        )

        self.assertTrue(passed)
        self.assertEqual([], violations)

    def test_broad_launch_rejects_high_suppressed_peers_ratio(self) -> None:
        deltas = {
            "nuremberg": {
                "dispatcher_completed": 1000,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
            }
        }
        posts = {
            "nuremberg": {
                "suppressed_peers_size": 134,
                "known_peer_topic_pairs": 1000,
            }
        }
        scenario = self.lr.ScenarioResult(name="fanout_burst", duration_secs=1.0)

        passed, violations = self.lr.evaluate_slos(
            "broad-launch", deltas, posts, scenario
        )

        self.assertFalse(passed)
        self.assertIn("suppressed_peers/known_peer_topic_pairs ratio", violations[0])

    def test_nonzero_suppressed_with_zero_known_pairs_fails_ratio_gate(self) -> None:
        ratio = self.lr.suppressed_peers_ratio(
            {"suppressed_peers_size": 1, "known_peer_topic_pairs": 0}
        )

        self.assertEqual(float("inf"), ratio)

    def test_limited_production_still_uses_absolute_timeout_cap(self) -> None:
        deltas = {
            "helsinki": {
                "dispatcher_completed": 10_000,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 201,
            }
        }
        posts = {"helsinki": {"suppressed_peers_size": 0}}
        scenario = self.lr.ScenarioResult(name="fanout_burst", duration_secs=1.0)

        passed, violations = self.lr.evaluate_slos(
            "limited-production", deltas, posts, scenario
        )

        self.assertFalse(passed)
        self.assertIn("per_peer_timeout delta 201", violations[0])

    def test_nonzero_timeouts_with_zero_completed_fail_ratio_gate(self) -> None:
        ratio = self.lr.per_peer_timeout_ratio(
            {"dispatcher_completed": 0, "per_peer_timeout_count": 1}
        )

        self.assertEqual(float("inf"), ratio)

    def test_drop_ratio_uses_produced_delta(self) -> None:
        ratio = self.lr.dropped_full_ratio(
            {"recv_pump_dropped_full": 5, "recv_pump_produced_total": 100}
        )

        self.assertEqual(0.05, ratio)

    def test_report_outputs_append_new_csv_fields_and_markdown_ratios(self) -> None:
        scenario = self.lr.ScenarioResult(name="fanout_burst", duration_secs=1.0)
        deltas = {
            "nyc": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 1,
                "recv_pump_produced_total": 200,
                "per_peer_timeout_count": 5,
                "_post": {
                    "recv_pump_latest_depth": 7,
                    "suppressed_peers_size": 3,
                    "known_peer_topic_pairs": 60,
                    "pubsub_workers": 2,
                },
            }
        }
        results = [(scenario, deltas, True, [])]

        with tempfile.TemporaryDirectory() as tmp:
            proof_dir = Path(tmp)
            self.lr.write_summary_md(proof_dir, "broad-launch", results)
            self.lr.write_summary_csv(proof_dir, results)

            md = (proof_dir / "summary.md").read_text(encoding="utf-8")
            self.assertIn("drop_ratio", md)
            self.assertIn("pp_to/completed", md)
            self.assertIn("depth_post", md)
            self.assertIn("suppressed/known", md)

            with (proof_dir / "summary.csv").open(newline="") as f:
                rows = list(csv.reader(f))
            self.assertEqual(
                [
                    "scenario",
                    "node",
                    "passed",
                    "fail_reason",
                    "dispatcher_timed_out_delta",
                    "recv_pump_dropped_full_delta",
                    "per_peer_timeout_delta",
                    "suppressed_peers_post",
                    "pubsub_workers_post",
                    "violations_count",
                ],
                rows[0][:10],
            )
            self.assertEqual(
                [
                    "per_peer_timeout_to_completed_ratio",
                    "recv_pump_drop_full_ratio",
                    "recv_pump_latest_depth_post",
                    "suppressed_peers_to_known_ratio",
                    "known_peer_topic_pairs_post",
                ],
                rows[0][10:],
            )
            self.assertEqual("0.050000", rows[1][10])
            self.assertEqual("0.005000", rows[1][11])
            self.assertEqual("7", rows[1][12])
            self.assertEqual("0.050000", rows[1][13])
            self.assertEqual("60", rows[1][14])


if __name__ == "__main__":
    unittest.main()
