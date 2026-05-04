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

    def test_broad_launch_accepts_warmed_soak_suppression_variance(self) -> None:
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
                "suppressed_peers_size": 154,
                "known_peer_topic_pairs": 1359,
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

    def test_netem_commands_apply_cleanup_and_verify_named_qdisc(self) -> None:
        apply_cmd = self.lr.netem_apply_command("eth0", 1500, 200, "normal")
        cleanup_cmd = self.lr.netem_cleanup_command("eth0")
        verify_cmd = self.lr.netem_verify_clean_command("eth0")

        self.assertIn("tc qdisc add dev eth0 root netem delay 1500ms 200ms", apply_cmd)
        self.assertIn("distribution normal", apply_cmd)
        self.assertEqual("tc qdisc del dev eth0 root 2>/dev/null || true", cleanup_cmd)
        self.assertEqual("! tc qdisc show dev eth0 | grep -q netem", verify_cmd)

    def test_partition_iptables_commands_use_comment_and_cleanup_loop(self) -> None:
        apply_cmd = self.lr.iptables_apply_command("170.64.176.102", 5483)
        cleanup_cmd = self.lr.iptables_cleanup_command("170.64.176.102", 5483)
        verify_cmd = self.lr.iptables_verify_clean_command("170.64.176.102", 5483)

        self.assertIn("iptables -I INPUT 1", apply_cmd)
        self.assertIn("--sport 5483", apply_cmd)
        self.assertIn("--comment x0x-partition-recovery", apply_cmd)
        self.assertIn("while iptables -C INPUT", cleanup_cmd)
        self.assertIn("iptables -D INPUT", cleanup_cmd)
        self.assertTrue(verify_cmd.startswith("! iptables -C INPUT"))

    def test_partition_pair_rejects_anchor_and_unknown_nodes(self) -> None:
        nodes = {"nyc": ("1", "t"), "sfo": ("2", "t"), "sydney": ("3", "t")}

        self.assertEqual(
            ("sfo", "sydney"),
            self.lr.parse_partition_pair("sfo,sydney", "nyc", nodes),
        )
        with self.assertRaises(ValueError):
            self.lr.parse_partition_pair("nyc,sfo", "nyc", nodes)
        with self.assertRaises(ValueError):
            self.lr.parse_partition_pair("sfo,moon", "nyc", nodes)

    def test_dispatcher_timeout_exempt_nodes_are_scenario_scoped(self) -> None:
        deltas = {
            "sfo": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 1,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
            },
            "nyc": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
            },
        }
        posts = {
            "sfo": {"suppressed_peers_size": 0, "known_peer_topic_pairs": 100},
            "nyc": {"suppressed_peers_size": 0, "known_peer_topic_pairs": 100},
        }
        scenario = self.lr.ScenarioResult(
            name="partition_recovery",
            duration_secs=1.0,
            extra_metrics={"dispatcher_timeout_exempt_nodes": "sfo"},
        )

        passed, violations = self.lr.evaluate_slos(
            "broad-launch", deltas, posts, scenario
        )

        self.assertTrue(passed)
        self.assertEqual([], violations)

    def test_suppression_ratio_exempt_nodes_are_scenario_scoped(self) -> None:
        deltas = {
            "sydney": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
            },
            "nyc": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
            },
        }
        posts = {
            "sydney": {"suppressed_peers_size": 50, "known_peer_topic_pairs": 100},
            "nyc": {"suppressed_peers_size": 5, "known_peer_topic_pairs": 100},
        }
        scenario = self.lr.ScenarioResult(
            name="high_rtt_peer",
            duration_secs=1.0,
            extra_metrics={"suppression_ratio_exempt_nodes": "sydney"},
        )

        passed, violations = self.lr.evaluate_slos(
            "broad-launch", deltas, posts, scenario
        )

        self.assertTrue(passed)
        self.assertEqual([], violations)

    def test_target_cooling_observed_uses_per_observer_deltas(self) -> None:
        start = {
            "observers": {
                "nyc": {
                    "suppressed_entries": 10,
                    "suppressed_topics": ["old"],
                    "cooling_events": 5.0,
                    "outbound_send_timeouts": 100.0,
                },
                "sfo": {
                    "suppressed_entries": 0,
                    "suppressed_topics": [],
                    "cooling_events": 2.0,
                    "outbound_send_timeouts": 20.0,
                },
                "sydney": {
                    "suppressed_entries": 0,
                    "suppressed_topics": [],
                    "cooling_events": 0.0,
                    "outbound_send_timeouts": 0.0,
                },
            }
        }
        mid = {
            "observers": {
                "nyc": {
                    "suppressed_entries": 4,
                    "suppressed_topics": ["old"],
                    "cooling_events": 5.0,
                    "outbound_send_timeouts": 140.0,
                },
                "sfo": {
                    "suppressed_entries": 1,
                    "suppressed_topics": ["new-topic"],
                    "cooling_events": 3.0,
                    "outbound_send_timeouts": 20.0,
                },
                "sydney": {
                    "suppressed_entries": 0,
                    "suppressed_topics": [],
                    "cooling_events": 0.0,
                    "outbound_send_timeouts": 0.0,
                },
            }
        }

        summary = self.lr.target_cooling_delta_summary(
            start,
            mid,
            exclude_node="sydney",
        )

        self.assertTrue(summary["cooling_observed"])
        self.assertEqual(["sfo"], summary["cooling_event_observers"])
        self.assertEqual(["nyc"], summary["outbound_send_timeout_observers"])
        self.assertEqual(["sfo"], summary["new_suppression_observers"])
        self.assertEqual(
            ["new-topic"],
            summary["observers"]["sfo"]["new_suppressed_topics"],
        )

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
