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
                "data_tx_high_water_count": 0,
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
                "data_tx_high_water_count": 0,
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
                "data_tx_high_water_count": 0,
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
                "data_tx_high_water_count": 0,
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
                "data_tx_high_water_count": 0,
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

    def test_diff_counters_clamps_monotonic_resets(self) -> None:
        delta = self.lr.diff_counters(
            {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 10,
                "recv_pump_dropped_full": 2,
                "per_peer_timeout_count": 50,
            },
            {},
        )

        self.assertEqual(0, delta["dispatcher_completed"])
        self.assertEqual(0, delta["dispatcher_timed_out"])
        self.assertEqual(0, delta["recv_pump_dropped_full"])
        self.assertEqual(0, delta["per_peer_timeout_count"])

    def test_connectivity_scalars_preserve_missing_data_tx(self) -> None:
        counters = self.lr.extract_connectivity_scalars({"gso": {"bundle_send_total": 3}})

        self.assertIsNone(counters["data_tx_high_water_count"])
        self.assertEqual(3, counters["gso_bundle_send_total"])

    def test_diff_counters_marks_missing_connectivity_delta(self) -> None:
        delta = self.lr.diff_counters(
            {"data_tx_high_water_count": 4},
            {},
        )

        self.assertIsNone(delta["data_tx_high_water_count"])

    def test_broad_launch_rejects_missing_connectivity_diagnostics(self) -> None:
        deltas = {
            "nyc": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
                "data_tx_high_water_count": None,
                "diagnostics_connectivity_pre_fetched": False,
                "diagnostics_connectivity_post_fetched": False,
            }
        }
        posts = {"nyc": {"suppressed_peers_size": 0, "known_peer_topic_pairs": 100}}
        scenario = self.lr.ScenarioResult(name="fanout_burst", duration_secs=1.0)

        passed, violations = self.lr.evaluate_slos(
            "broad-launch", deltas, posts, scenario
        )

        self.assertFalse(passed)
        self.assertTrue(
            any("data_tx_high_water_count_delta unmeasurable" in v for v in violations),
            violations,
        )

    def test_extract_counters_aggregates_pubsub_cache_stats(self) -> None:
        diag = {
            "pubsub_stages": {
                "topic_caches": [
                    {
                        "topic": "x0x.discovery.groups",
                        "cache": {
                            "msg_count": 10,
                            "total_bytes": 12_000,
                            "oldest_age_secs": 45,
                            "evicted_by_age": 2,
                            "evicted_by_bytes": 3,
                            "evicted_by_count": 4,
                        },
                    },
                    {
                        "topic": "x0x.presence.global",
                        "cache": {
                            "msg_count": 5,
                            "total_bytes": 500,
                            "oldest_age_secs": 12,
                            "evicted_by_age": 1,
                            "evicted_by_bytes": 0,
                            "evicted_by_count": 0,
                        },
                    },
                ]
            }
        }

        counters = self.lr.extract_counters(diag)

        self.assertEqual(2, counters["pubsub_cache_topics"])
        self.assertEqual(15, counters["pubsub_cache_msg_count"])
        self.assertEqual(12_500, counters["pubsub_cache_total_bytes"])
        self.assertEqual(45, counters["pubsub_cache_oldest_age_secs_max"])
        self.assertEqual(3, counters["pubsub_cache_evicted_by_age"])
        self.assertEqual(3, counters["pubsub_cache_evicted_by_bytes"])
        self.assertEqual(4, counters["pubsub_cache_evicted_by_count"])

    def test_extract_counters_reports_topic_suppression_diagnostics(self) -> None:
        diag = {
            "pubsub_stages": {
                "suppressed_peers_by_topic": {
                    "x0x.presence.global": ["peer-a", "peer-b"],
                    "x0x.discovery.groups": ["peer-c"],
                },
                "peer_scores_by_topic": {
                    "x0x.discovery.groups": {"peer-c": {"role": "lazy"}},
                    "x0x.presence.global": {"peer-a": {"role": "cooled"}},
                },
            }
        }

        counters = self.lr.extract_counters(diag)

        self.assertEqual(2, counters["suppressed_topics_total"])
        self.assertEqual(2, counters["suppressed_topic_top_count"])
        self.assertEqual(
            "x0x.presence.global:2;x0x.discovery.groups:1",
            counters["suppressed_topics_top3"],
        )
        self.assertEqual(2, counters["peer_scores_topics_total"])

    def test_extract_counters_groups_legacy_flat_suppression_rows(self) -> None:
        diag = {
            "pubsub_stages": {
                "suppressed_peers": [
                    {"topic": "topic-a", "peer_id": "peer-1"},
                    {"topic": "topic-a", "peer_id": "peer-1"},
                    {"topic": "topic-a", "peer_id": "peer-2"},
                    {"topic": "topic-b", "peer_id": "peer-3"},
                ],
                "peer_scores": [
                    {"topic": "topic-a", "peer_id": "peer-1"},
                    {"topic": "topic-b", "peer_id": "peer-3"},
                ],
            }
        }

        counters = self.lr.extract_counters(diag)

        self.assertEqual(2, counters["suppressed_topics_total"])
        self.assertEqual(2, counters["suppressed_topic_top_count"])
        self.assertEqual("topic-a:2;topic-b:1", counters["suppressed_topics_top3"])
        self.assertEqual(2, counters["peer_scores_topics_total"])

    def test_extract_connectivity_scalars_reports_transport_summary(self) -> None:
        diag = {
            "per_peer_transport": [
                {
                    "peer_id": "peer-a",
                    "connected": True,
                    "rtt_ms": 42,
                    "packet_loss_rate": 0.0012,
                    "idle_for_ms": 10,
                },
                {
                    "peer_id": "peer-b",
                    "connected": False,
                    "rtt_ms": 7,
                    "packet_loss_rate": 0.0,
                },
            ]
        }

        scalars = self.lr.extract_connectivity_scalars(diag)

        self.assertEqual(2, scalars["transport_peer_count"])
        self.assertEqual(1, scalars["transport_connected_count"])
        self.assertEqual(42, scalars["transport_rtt_ms_max"])
        self.assertEqual(1200, scalars["transport_packet_loss_ppm_max"])
        self.assertIn("peer-a", scalars["transport_peers_top3"])

    def test_diff_counters_skips_textual_diagnostic_fields(self) -> None:
        delta = self.lr.diff_counters(
            {"suppressed_topics_top3": "topic-a:1"},
            {"suppressed_topics_top3": "topic-a:2", "suppressed_topics_total": 2},
        )

        self.assertNotIn("suppressed_topics_top3", delta)
        self.assertEqual(2, delta["suppressed_topics_total"])

    def test_diff_counters_clamps_pubsub_cache_eviction_resets(self) -> None:
        delta = self.lr.diff_counters(
            {
                "pubsub_cache_evicted_by_age": 10,
                "pubsub_cache_evicted_by_bytes": 20,
                "pubsub_cache_evicted_by_count": 30,
            },
            {},
        )

        self.assertEqual(0, delta["pubsub_cache_evicted_by_age"])
        self.assertEqual(0, delta["pubsub_cache_evicted_by_bytes"])
        self.assertEqual(0, delta["pubsub_cache_evicted_by_count"])

    def test_redact_auth_tokens_masks_bearer_values(self) -> None:
        text = "curl -H 'Authorization: Bearer abc123SECRET' http://127.0.0.1"

        redacted = self.lr.redact_auth_tokens(text)

        self.assertNotIn("abc123SECRET", redacted)
        self.assertIn("Bearer [REDACTED]", redacted)

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

    def test_broad_launch_dispatcher_timeout_strict_zero_passes_at_zero(self) -> None:
        deltas = {
            "nyc": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
                "data_tx_high_water_count": 0,
            }
        }
        posts = {"nyc": {"suppressed_peers_size": 0, "known_peer_topic_pairs": 100}}
        scenario = self.lr.ScenarioResult(
            name="fanout_burst",
            duration_secs=1.0,
        )

        passed, violations = self.lr.evaluate_slos(
            "broad-launch", deltas, posts, scenario
        )

        self.assertTrue(passed)
        self.assertEqual([], violations)

    def test_broad_launch_dispatcher_timeout_strict_zero_fails_at_one(self) -> None:
        deltas = {
            "helsinki": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 1,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
                "data_tx_high_water_count": 0,
            }
        }
        posts = {
            "helsinki": {"suppressed_peers_size": 0, "known_peer_topic_pairs": 100}
        }
        scenario = self.lr.ScenarioResult(name="fanout_burst", duration_secs=1.0)

        passed, violations = self.lr.evaluate_slos(
            "broad-launch", deltas, posts, scenario
        )

        self.assertFalse(passed)
        self.assertTrue(
            any("dispatcher_timed_out delta" in v for v in violations),
            violations,
        )

    def test_broad_launch_phase_a_strict_thirty_passes_at_thirty(self) -> None:
        deltas = {
            "nyc": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
                "data_tx_high_water_count": 0,
            }
        }
        posts = {"nyc": {"suppressed_peers_size": 0, "known_peer_topic_pairs": 100}}
        scenario = self.lr.ScenarioResult(
            name="baseline",
            duration_secs=1.0,
            extra_metrics={"phase_a_received": 30, "phase_a_sent": 30},
        )

        passed, violations = self.lr.evaluate_slos(
            "broad-launch", deltas, posts, scenario
        )

        self.assertTrue(passed)
        self.assertEqual([], violations)

    def test_broad_launch_phase_a_strict_thirty_fails_at_twenty_nine(self) -> None:
        deltas = {
            "nyc": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
                "data_tx_high_water_count": 0,
            }
        }
        posts = {"nyc": {"suppressed_peers_size": 0, "known_peer_topic_pairs": 100}}
        scenario = self.lr.ScenarioResult(
            name="baseline",
            duration_secs=1.0,
            extra_metrics={"phase_a_received": 29, "phase_a_sent": 29},
        )

        passed, violations = self.lr.evaluate_slos(
            "broad-launch", deltas, posts, scenario
        )

        self.assertFalse(passed)
        self.assertTrue(
            any("phase A received" in v for v in violations),
            violations,
        )

    def test_broad_launch_phase_a_sent_only_gap_is_explicitly_handled(self) -> None:
        deltas = {
            "nyc": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
                "data_tx_high_water_count": 0,
            }
        }
        posts = {"nyc": {"suppressed_peers_size": 0, "known_peer_topic_pairs": 100}}
        scenario = self.lr.ScenarioResult(
            name="baseline",
            duration_secs=1.0,
            extra_metrics={"phase_a_received": 30, "phase_a_sent": 29},
        )

        passed, violations = self.lr.evaluate_slos(
            "broad-launch", deltas, posts, scenario
        )

        self.assertFalse(passed)
        self.assertIn("phase A sent 29 < gate 30", violations)
        self.assertNotIn("phase A received 30 < gate 30", violations)

    def test_broad_launch_phase_a_received_only_gap_is_explicitly_handled(self) -> None:
        deltas = {
            "nyc": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
                "data_tx_high_water_count": 0,
            }
        }
        posts = {"nyc": {"suppressed_peers_size": 0, "known_peer_topic_pairs": 100}}
        scenario = self.lr.ScenarioResult(
            name="baseline",
            duration_secs=1.0,
            extra_metrics={"phase_a_received": 29, "phase_a_sent": 30},
        )

        passed, violations = self.lr.evaluate_slos(
            "broad-launch", deltas, posts, scenario
        )

        self.assertFalse(passed)
        self.assertIn("phase A received 29 < gate 30", violations)
        self.assertNotIn("phase A sent 30 < gate 30", violations)

    def test_dispatcher_timeout_exempt_nodes_are_scenario_scoped(self) -> None:
        deltas = {
            "sfo": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 1,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
                "data_tx_high_water_count": 0,
            },
            "nyc": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
                "data_tx_high_water_count": 0,
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
                "data_tx_high_water_count": 0,
            },
            "nyc": {
                "dispatcher_completed": 100,
                "dispatcher_timed_out": 0,
                "recv_pump_dropped_full": 0,
                "per_peer_timeout_count": 0,
                "data_tx_high_water_count": 0,
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
            self.assertIn("X0X-0075", md)

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
                    "suppressed_topics_post",
                    "suppressed_topic_top_count_post",
                    "suppressed_topics_top3_post",
                    "peer_score_topics_post",
                    "diagnostics_connectivity_pre_fetched",
                    "diagnostics_connectivity_post_fetched",
                    "data_tx_depth_post",
                    "data_tx_capacity_post",
                    "data_tx_high_water_count_delta",
                    "gso_bundle_send_total_delta",
                    "gso_bundle_partial_send_delta",
                    "transport_peer_count_post",
                    "transport_connected_count_post",
                    "transport_rtt_ms_max_post",
                    "transport_packet_loss_ppm_max_post",
                    "transport_peers_top3_post",
                ],
                rows[0][10:],
            )
            self.assertEqual("0.050000", rows[1][10])
            self.assertEqual("0.005000", rows[1][11])
            self.assertEqual("7", rows[1][12])
            self.assertEqual("0.050000", rows[1][13])
            self.assertEqual("60", rows[1][14])
            self.assertEqual("false", rows[1][19])
            self.assertEqual("false", rows[1][20])
            self.assertEqual("MISSING", rows[1][23])


if __name__ == "__main__":
    unittest.main()
