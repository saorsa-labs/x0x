#!/usr/bin/env python3
"""Unit tests for the X0X-0019 topic overlay scale harness."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


def load_topic_overlay_scale():
    script = Path(__file__).with_name("topic_overlay_scale.py")
    spec = importlib.util.spec_from_file_location("topic_overlay_scale", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TopicOverlayScaleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scale = load_topic_overlay_scale()

    def config(self, peers: int, lazy_cap: int = 16):
        return self.scale.ScaleConfig(
            peer_count=peers,
            topic="x0x.scale.hot",
            publish_rate=1.0,
            duration_secs=5.0,
            churn_rate=0.0,
            eager_min=6,
            eager_target=8,
            eager_max=12,
            lazy_cap=lazy_cap,
            convergence_secs=30.0,
            seed=1019,
        )

    def test_bounded_overlay_keeps_eager_and_lazy_degrees_capped(self) -> None:
        config = self.config(1_000)
        overlay = self.scale.build_overlay(config)

        eager_degrees = [len(peers) for peers in overlay.eager]
        lazy_degrees = [len(peers) for peers in overlay.lazy]

        self.assertGreaterEqual(min(eager_degrees), config.eager_min)
        self.assertLessEqual(max(eager_degrees), config.eager_max)
        self.assertLessEqual(max(lazy_degrees), config.lazy_cap)

    def test_full_view_negative_control_is_detected(self) -> None:
        config = self.config(1_000)
        full_view = self.scale.build_overlay(config, full_view_lazy=True)
        result = self.scale.evaluate_case(config, full_view, peak_memory_bytes=0)

        self.assertEqual("NO-GO", result.verdict)
        self.assertTrue(result.full_view_negative_control_detected)
        self.assertIn("p99 lazy degree", result.violations)

    def test_per_node_work_bound_does_not_grow_with_peer_count(self) -> None:
        small = self.scale.run_case(self.config(1_000), full_view_lazy=False)
        large = self.scale.run_case(self.config(5_000), full_view_lazy=False)

        self.assertEqual("GO", small.verdict)
        self.assertEqual("GO", large.verdict)
        self.assertLessEqual(
            abs(small.outbound_work_p99_per_node - large.outbound_work_p99_per_node),
            2,
        )

    def test_delivery_is_complete_for_connected_bounded_overlay(self) -> None:
        result = self.scale.run_case(self.config(1_000), full_view_lazy=False)

        self.assertEqual("GO", result.verdict)
        self.assertEqual(1.0, result.delivery_ratio)

    def test_cli_writes_summary_and_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proof_dir = Path(tmp) / "proof"
            rc = self.scale.main(
                [
                    "--peers",
                    "1000",
                    "--publish-rate",
                    "1",
                    "--duration-secs",
                    "5",
                    "--lazy-cap",
                    "16",
                    "--proof-dir",
                    str(proof_dir),
                ]
            )

            self.assertEqual(0, rc)
            self.assertTrue((proof_dir / "summary.md").is_file())
            self.assertTrue((proof_dir / "metrics.csv").is_file())
            summary = (proof_dir / "summary.md").read_text(encoding="utf-8")
            self.assertIn("Verdict: **GO**", summary)


if __name__ == "__main__":
    unittest.main()
