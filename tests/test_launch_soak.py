#!/usr/bin/env python3
"""Focused tests for launch_soak summary policy."""

from __future__ import annotations

import importlib.util
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
                    ]
                ),
                encoding="utf-8",
            )
            (window_dir / "summary.csv").write_text(
                "\n".join(
                    [
                        "scenario,node,dispatcher_timed_out_delta,recv_pump_dropped_full_delta,per_peer_timeout_delta,suppressed_peers_post,pubsub_workers_post,violations_count,suppressed_peers_to_known_ratio",
                        "baseline,nyc,1,0,10,30,4,1,0.010000",
                        "baseline,sfo,2,0,20,40,5,1,0.020000",
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
