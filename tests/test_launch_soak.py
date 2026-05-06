#!/usr/bin/env python3
"""Focused tests for launch_soak summary policy."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


def load_launch_soak():
    script = Path(__file__).with_name("launch_soak.py")
    spec = importlib.util.spec_from_file_location("launch_soak", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LaunchSoakSummaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.soak = load_launch_soak()

    def write_diag(
        self,
        window_dir: Path,
        node: str,
        sample: str,
        *,
        completed: int = 0,
        timed_out: int = 0,
        dropped_full: int = 0,
        per_peer_timeout: int = 0,
    ) -> None:
        diag_dir = window_dir / "diagnostics" / "baseline"
        diag_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "dispatcher": {
                "pubsub": {
                    "completed": completed,
                    "timed_out": timed_out,
                }
            },
            "recv_pump": {
                "pubsub": {
                    "dropped_full": dropped_full,
                }
            },
            "pubsub_stages": {
                "republish_per_peer_timeout": per_peer_timeout,
            },
        }
        (diag_dir / f"{node}-{sample}.json").write_text(
            json.dumps(payload),
            encoding="utf-8",
        )

    def test_discover_summary_sums_per_node_dispatcher_deltas(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            window_dir = Path(tmp)
            (window_dir / "summary.md").write_text(
                "\n".join(
                    [
                        "### Overall verdict: **NO-GO**",
                        "- phase_a_received: `30`",
                        "- phase_a_sent: `30`",
                        "- violations:",
                        "  - nyc: dispatcher_timed_out delta 1 > gate 0",
                        "  - sfo: dispatcher_timed_out delta 2 > gate 0",
                    ]
                ),
                encoding="utf-8",
            )
            (window_dir / "summary.csv").write_text(
                "\n".join(
                    [
                        "scenario,node,dispatcher_timed_out_delta,recv_pump_dropped_full_delta,per_peer_timeout_delta,suppressed_peers_post,pubsub_workers_post,violations_count,suppressed_peers_to_known_ratio",
                        "baseline,nyc,1,0,10,30,4,2,0.010000",
                        "baseline,sfo,2,0,20,40,5,2,0.020000",
                    ]
                ),
                encoding="utf-8",
            )

            row = self.soak.discover_windows_summary(window_dir)

        self.assertEqual("2", row["max_disp_to_delta"])
        self.assertEqual("3", row["sum_disp_to_delta"])
        self.assertEqual("40", row["max_suppressed"])
        self.assertEqual("0.020000", row["max_suppressed_ratio"])
        self.assertIn("dispatcher_timed_out delta", row["violation_messages"])
        self.assertEqual("2", row["violations"])

    def test_discover_summary_clamps_negative_counter_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            window_dir = Path(tmp)
            (window_dir / "summary.md").write_text(
                "\n".join(
                    [
                        "### Overall verdict: **NO-GO**",
                        "- phase_a_received: `11`",
                        "- phase_a_sent: `9`",
                        "- violations:",
                        "  - phase A received 11 < gate 30",
                    ]
                ),
                encoding="utf-8",
            )
            (window_dir / "summary.csv").write_text(
                "\n".join(
                    [
                        "scenario,node,dispatcher_timed_out_delta,recv_pump_dropped_full_delta,per_peer_timeout_delta,suppressed_peers_post,pubsub_workers_post,violations_count,suppressed_peers_to_known_ratio",
                        "baseline,nyc,-10,0,-4455,0,0,1,0.000000",
                        "baseline,sfo,-34,0,-3595,0,0,1,0.000000",
                        "baseline,sydney,2,0,689,332,24,1,0.138333",
                    ]
                ),
                encoding="utf-8",
            )

            row = self.soak.discover_windows_summary(window_dir)

        self.assertEqual("2", row["max_disp_to_delta"])
        self.assertEqual("2", row["sum_disp_to_delta"])
        self.assertEqual("689", row["max_pp_to_delta"])

    def test_continuous_deltas_bridge_missing_pre_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            soak_dir = Path(tmp)
            window_1 = soak_dir / "windows" / "001"
            window_2 = soak_dir / "windows" / "002"
            self.write_diag(
                window_1,
                "singapore",
                "pre",
                completed=1000,
                timed_out=4,
                per_peer_timeout=15056,
            )
            self.write_diag(
                window_1,
                "singapore",
                "post",
                completed=1100,
                timed_out=4,
                per_peer_timeout=15098,
            )
            self.write_diag(
                window_2,
                "singapore",
                "post",
                completed=1500,
                timed_out=4,
                per_peer_timeout=15282,
            )

            rows = self.soak.annotate_continuous_rows(soak_dir, [{}, {}])

        self.assertEqual("0", rows[1]["continuous_sum_disp_to_delta"])
        self.assertEqual("184", rows[1]["continuous_max_pp_to_delta"])
        self.assertIn("singapore:pre", rows[1]["continuous_snapshot_gaps"])
        self.assertEqual("", rows[1]["continuous_unaccounted_gaps"])

    def test_write_summary_prefers_continuous_totals_over_scenario_artifact(self) -> None:
        rows = [
            {
                "verdict": "NO-GO",
                "start_unix": "1",
                "phase_a_received": "30",
                "phase_a_sent": "30",
                "max_disp_to_delta": "4",
                "sum_disp_to_delta": "4",
                "continuous_max_disp_to_delta": "0",
                "continuous_sum_disp_to_delta": "0",
                "max_drop_full_delta": "0",
                "sum_drop_full_delta": "0",
                "continuous_max_drop_full_delta": "0",
                "continuous_sum_drop_full_delta": "0",
                "max_pp_to_delta": "15282",
                "continuous_max_pp_to_delta": "184",
                "max_suppressed": "154",
                "max_suppressed_ratio": "0.113924",
                "max_workers": "32",
                "violations": "1",
                "violation_messages": "singapore: dispatcher_timed_out delta 4 > gate 0",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertTrue(passed)
        self.assertIn(
            "dispatcher.timed_out delta across the continuous soak × all nodes: **0**",
            md,
        )
        self.assertIn("| 1 | 1 | NO-GO | PASS | 30/30 | 4 | 0 |", md)

    def test_write_summary_tolerates_small_dispatcher_only_soak_delta(self) -> None:
        rows = [
            {
                "verdict": "GO",
                "start_unix": "1",
                "phase_a_received": "30",
                "phase_a_sent": "30",
                "max_disp_to_delta": "0",
                "sum_disp_to_delta": "0",
                "max_drop_full_delta": "0",
                "sum_drop_full_delta": "0",
                "max_pp_to_delta": "0",
                "max_suppressed": "20",
                "max_suppressed_ratio": "0.010000",
                "max_workers": "4",
                "violations": "0",
                "violation_messages": "",
            },
            {
                "verdict": "NO-GO",
                "start_unix": "2",
                "phase_a_received": "30",
                "phase_a_sent": "30",
                "max_disp_to_delta": "1",
                "sum_disp_to_delta": "1",
                "max_drop_full_delta": "0",
                "sum_drop_full_delta": "0",
                "max_pp_to_delta": "0",
                "max_suppressed": "20",
                "max_suppressed_ratio": "0.010000",
                "max_workers": "4",
                "violations": "1",
                "violation_messages": "nyc: dispatcher_timed_out delta 1 > gate 0",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertTrue(passed)
        self.assertIn("Overall verdict: **GO**", md)
        self.assertIn("tolerated dispatcher-only windows: **2**", md)

    def test_write_summary_accepts_low_rate_dispatcher_noise_above_legacy_count(self) -> None:
        rows = [
            {
                "verdict": "NO-GO",
                "start_unix": "1",
                "phase_a_received": "30",
                "phase_a_sent": "30",
                "max_disp_to_delta": "1",
                "sum_disp_to_delta": "2",
                "continuous_max_disp_to_delta": "3",
                "continuous_sum_disp_to_delta": "10",
                "continuous_sum_dispatcher_completed_delta": "1297023",
                "max_drop_full_delta": "0",
                "sum_drop_full_delta": "0",
                "continuous_max_drop_full_delta": "0",
                "continuous_sum_drop_full_delta": "0",
                "max_pp_to_delta": "200",
                "continuous_sum_pp_to_delta": "6507",
                "max_suppressed": "118",
                "max_suppressed_ratio": "0.069208",
                "max_workers": "32",
                "violations": "2",
                "violation_messages": (
                    "nyc: dispatcher_timed_out delta 1 > gate 0 || "
                    "sfo: dispatcher_timed_out delta 1 > gate 0"
                ),
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertTrue(passed)
        self.assertIn("dispatcher-only adaptive policy: **adaptive-rate-ok**", md)
        self.assertIn("dispatcher.timed_out / dispatcher.completed: **0.00000771**", md)

    def test_write_summary_rejects_high_rate_dispatcher_noise(self) -> None:
        rows = [
            {
                "verdict": "NO-GO",
                "start_unix": "1",
                "phase_a_received": "30",
                "phase_a_sent": "30",
                "max_disp_to_delta": "5",
                "sum_disp_to_delta": "10",
                "continuous_max_disp_to_delta": "10",
                "continuous_sum_disp_to_delta": "10",
                "continuous_sum_dispatcher_completed_delta": "1000",
                "max_drop_full_delta": "0",
                "sum_drop_full_delta": "0",
                "continuous_max_drop_full_delta": "0",
                "continuous_sum_drop_full_delta": "0",
                "max_pp_to_delta": "0",
                "continuous_sum_pp_to_delta": "0",
                "max_suppressed": "20",
                "max_suppressed_ratio": "0.010000",
                "max_workers": "32",
                "violations": "1",
                "violation_messages": "nyc: dispatcher_timed_out delta 10 > gate 0",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertFalse(passed)
        self.assertIn("dispatcher-only adaptive policy: **window-rate-high**", md)

    def test_write_summary_keeps_phase_a_gap_as_no_go(self) -> None:
        rows = [
            {
                "verdict": "NO-GO",
                "start_unix": "1",
                "phase_a_received": "20",
                "phase_a_sent": "20",
                "max_disp_to_delta": "0",
                "sum_disp_to_delta": "0",
                "max_drop_full_delta": "0",
                "sum_drop_full_delta": "0",
                "max_pp_to_delta": "0",
                "max_suppressed": "20",
                "max_suppressed_ratio": "0.010000",
                "max_workers": "4",
                "violations": "1",
                "violation_messages": "phase A received 20 < gate 30",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertFalse(passed)
        self.assertIn("Overall verdict: **NO-GO**", md)
        self.assertIn("effective failed windows: **1**", md)


if __name__ == "__main__":
    unittest.main()
