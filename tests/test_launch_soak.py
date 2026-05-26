#!/usr/bin/env python3
"""Focused tests for launch_soak summary policy."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict


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

    def _make_row(
        self,
        *,
        verdict: str = "GO",
        phase_a_sent: int = 30,
        phase_a_received: int = 30,
        violation_messages: str = "",
        disp_to: int = 0,
        drop_full: int = 0,
        loss_ppm: int = 0,
        rtt_ms: int = 0,
        start_unix: str = "1",
    ) -> Dict[str, str]:
        return {
            "verdict": verdict,
            "start_unix": start_unix,
            "phase_a_received": str(phase_a_received),
            "phase_a_sent": str(phase_a_sent),
            "max_transport_loss_ppm": str(loss_ppm),
            "max_transport_rtt_ms": str(rtt_ms),
            "max_disp_to_delta": str(disp_to),
            "sum_disp_to_delta": str(disp_to),
            "continuous_max_disp_to_delta": str(disp_to),
            "continuous_sum_disp_to_delta": str(disp_to),
            "continuous_sum_dispatcher_completed_delta": "1000000",
            "max_drop_full_delta": str(drop_full),
            "sum_drop_full_delta": str(drop_full),
            "continuous_max_drop_full_delta": str(drop_full),
            "continuous_sum_drop_full_delta": str(drop_full),
            "max_pp_to_delta": "0",
            "continuous_sum_pp_to_delta": "0",
            "max_suppressed": "0",
            "max_suppressed_ratio": "0.000000",
            "max_workers": "32",
            "violations": str(len([m for m in violation_messages.split(" || ") if m])),
            "violation_messages": violation_messages,
        }

    def test_aggregate_phase_a_tolerated_when_ratio_holds(self) -> None:
        # 4 windows: 30, 30, 29, 30 sent → 119/120 = 99.17% ≥ 98% SLO.
        # Window 3 has only the phase_a tail violation, so it joins
        # tolerated_phase_a_windows and the soak passes.
        rows = [
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="1"),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="2"),
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=29,
                phase_a_received=29,
                violation_messages=(
                    "scenario errored: phase A exit code 1 || "
                    "phase A received 29 < gate 30"
                ),
                start_unix="3",
            ),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="4"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertTrue(passed, md)
        self.assertIn("Overall verdict: **GO**", md)
        self.assertIn("tolerated phase-A tail windows: **3**", md)
        self.assertIn("aggregate Phase A sent: **119/120**", md)
        self.assertIn("aggregate Phase A SLO: **PASS**", md)

    def test_aggregate_phase_a_rejected_when_ratio_below_slo(self) -> None:
        # 4 windows: 30, 30, 28, 28 sent → 116/120 = 96.67% < 98% SLO.
        # Both NO-GO windows go to effective_failed because aggregate
        # ratio falls below the floor.
        rows = [
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="1"),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="2"),
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=28,
                phase_a_received=28,
                violation_messages=(
                    "scenario errored: phase A exit code 1 || "
                    "phase A received 28 < gate 30"
                ),
                start_unix="3",
            ),
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=28,
                phase_a_received=28,
                violation_messages=(
                    "scenario errored: phase A exit code 1 || "
                    "phase A received 28 < gate 30"
                ),
                start_unix="4",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertFalse(passed, md)
        self.assertIn("Overall verdict: **NO-GO**", md)
        self.assertIn("aggregate Phase A SLO: **FAIL**", md)
        self.assertIn("effective failed windows: **3,4**", md)
        self.assertIn("tolerated phase-A tail windows: **none**", md)

    def test_phase_a_loss_tolerated_when_transport_degraded(self) -> None:
        # 116/120 = 96.67% < 98% SLO, BUT the failing windows show genuine
        # transport degradation (high UDP loss / black-holed RTT), so the
        # Phase-A shortfall is infra-attributed and tolerated above the 70%
        # catastrophe floor with drop_full=0 → GO. (Mirrors the 2026-05-26
        # prod-parity soak: APAC PMTU black-hole, 6-18% loss, RTT to 30s.)
        rows = [
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="1"),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="2"),
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=28,
                phase_a_received=28,
                loss_ppm=70000,
                rtt_ms=4000,
                violation_messages=(
                    "scenario errored: phase A exit code 1 || "
                    "phase A received 28 < gate 30"
                ),
                start_unix="3",
            ),
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=28,
                phase_a_received=28,
                loss_ppm=120000,
                rtt_ms=16000,
                violation_messages=(
                    "scenario errored: phase A exit code 1 || "
                    "phase A received 28 < gate 30"
                ),
                start_unix="4",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertTrue(passed, md)
        self.assertIn("Overall verdict: **GO**", md)
        self.assertIn("aggregate Phase A SLO: **INFRA-DEGRADED", md)
        self.assertIn("INFRA-degraded windows (transport black-hole/loss): **3,4**", md)
        self.assertIn("effective failed windows: **none**", md)

    def test_phase_a_loss_with_healthy_transport_still_fails(self) -> None:
        # Same 96.67% < 98% shortfall but transport is HEALTHY (no loss, low
        # RTT) — so the Phase-A loss is a real regression, NOT infra, and the
        # soak fails. Guards against the recalibration masking code bugs.
        rows = [
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="1"),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="2"),
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=28,
                phase_a_received=28,
                loss_ppm=0,
                rtt_ms=300,
                violation_messages=(
                    "scenario errored: phase A exit code 1 || "
                    "phase A received 28 < gate 30"
                ),
                start_unix="3",
            ),
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=28,
                phase_a_received=28,
                loss_ppm=0,
                rtt_ms=300,
                violation_messages=(
                    "scenario errored: phase A exit code 1 || "
                    "phase A received 28 < gate 30"
                ),
                start_unix="4",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertFalse(passed, md)
        self.assertIn("Overall verdict: **NO-GO**", md)
        self.assertIn("effective failed windows: **3,4**", md)

    def test_transport_degraded_does_not_excuse_drop_full(self) -> None:
        # Even with transport degradation, recv_pump.dropped_full > 0 is a hard
        # gate — the run must FAIL (drop_full is exactly what the fix protects).
        rows = [
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="1"),
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=28,
                phase_a_received=28,
                loss_ppm=120000,
                rtt_ms=16000,
                drop_full=42,
                violation_messages=(
                    "phase A received 28 < gate 30 || "
                    "recv_pump_dropped_full delta 42 > gate 0"
                ),
                start_unix="2",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertFalse(passed, md)
        self.assertIn("Overall verdict: **NO-GO**", md)

    def test_aggregate_phase_a_tolerates_mixed_phase_a_and_dispatcher_tail(self) -> None:
        # Mirrors the actual 2026-05-11 soak window 1:
        # phase_a_sent=29 plus 1 helsinki dispatcher timeout. With
        # other windows clean, aggregate is 119/120 = 99.17% ≥ 98% SLO,
        # so the mixed window is tolerated.
        rows = [
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=29,
                phase_a_received=30,
                disp_to=1,
                violation_messages=(
                    "scenario errored: phase A exit code 1 || "
                    "phase A sent 29 < gate 30 || "
                    "helsinki: dispatcher_timed_out delta 1 > gate 0"
                ),
                start_unix="1",
            ),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="2"),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="3"),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="4"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertTrue(passed, md)
        self.assertIn("Overall verdict: **GO**", md)
        self.assertIn("tolerated phase-A tail windows: **1**", md)

    def test_aggregate_phase_a_98_percent_boundary_at_or_above_slo_passes(self) -> None:
        # 4 windows: 29, 29, 30, 30 sent → 118/120 = 98.33% ≥ 98% SLO.
        # Both tail windows are tolerated; soak passes. This is the
        # 2026-05-11 19:26Z pre-hedge datum point that the 0.98 bar
        # was calibrated from (proofs/launch-readiness-soak-20260511T192622Z).
        rows = [
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=29,
                phase_a_received=30,
                violation_messages="phase A sent 29 < gate 30",
                start_unix="1",
            ),
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=29,
                phase_a_received=30,
                violation_messages="phase A sent 29 < gate 30",
                start_unix="2",
            ),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="3"),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="4"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertTrue(passed, md)
        self.assertIn("Overall verdict: **GO**", md)
        self.assertIn("aggregate Phase A sent: **118/120**", md)
        self.assertIn("aggregate Phase A SLO: **PASS**", md)

    def test_write_summary_rejects_malformed_phase_a_violation_message(self) -> None:
        rows = [
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=29,
                phase_a_received=30,
                violation_messages="phase A received 30 < gate 30",
                start_unix="1",
            ),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="2"),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="3"),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="4"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertFalse(passed, md)
        self.assertIn("aggregate Phase A SLO: **PASS**", md)
        self.assertIn("tolerated phase-A tail windows: **none**", md)
        self.assertIn("effective failed windows: **1**", md)

    def test_aggregate_phase_a_just_below_98_percent_fails(self) -> None:
        # 4 windows: 29, 29, 29, 30 sent → 117/120 = 97.5% < 98% SLO.
        # Three tail-only windows would have been tolerated at the
        # old 96.67% behaviour but reject under the calibrated 0.98 bar.
        rows = [
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=29,
                phase_a_received=29,
                violation_messages="phase A received 29 < gate 30",
                start_unix="1",
            ),
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=29,
                phase_a_received=29,
                violation_messages="phase A received 29 < gate 30",
                start_unix="2",
            ),
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=29,
                phase_a_received=29,
                violation_messages="phase A received 29 < gate 30",
                start_unix="3",
            ),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="4"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertFalse(passed, md)
        self.assertIn("Overall verdict: **NO-GO**", md)
        self.assertIn("aggregate Phase A sent: **117/120**", md)
        self.assertIn("aggregate Phase A SLO: **FAIL**", md)

    def test_aggregate_phase_a_does_not_excuse_non_tail_violations(self) -> None:
        # Aggregate is 119/120 = 99.17% (would tolerate phase_a tail),
        # but the offending window also has a suppression-ratio
        # violation. Non-tail violations never enter the tolerated
        # sets, so the window goes to effective_failed.
        rows = [
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="1"),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="2"),
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=29,
                phase_a_received=29,
                violation_messages=(
                    "phase A received 29 < gate 30 || "
                    "nyc: suppressed_peers/known_peer_topic_pairs ratio "
                    "0.250 > gate 0.120 (500 / 2000)"
                ),
                start_unix="3",
            ),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="4"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertFalse(passed, md)
        self.assertIn("Overall verdict: **NO-GO**", md)
        self.assertIn("effective failed windows: **3**", md)

    def test_aggregate_phase_a_does_not_excuse_drop_full(self) -> None:
        # drop_full > 0 is a hard floor — even with perfect Phase A
        # aggregate the window cannot be tolerated.
        rows = [
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="1"),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="2"),
            self._make_row(
                verdict="NO-GO",
                phase_a_sent=29,
                phase_a_received=29,
                drop_full=1,
                violation_messages=(
                    "phase A received 29 < gate 30 || "
                    "nyc: recv_pump_dropped_full delta 1 > gate 0"
                ),
                start_unix="3",
            ),
            self._make_row(phase_a_sent=30, phase_a_received=30, start_unix="4"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            passed = self.soak.write_summary(Path(tmp), "broad-launch", rows)
            md = (Path(tmp) / "summary.md").read_text(encoding="utf-8")

        self.assertFalse(passed, md)
        self.assertIn("Overall verdict: **NO-GO**", md)

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
