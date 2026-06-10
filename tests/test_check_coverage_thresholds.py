#!/usr/bin/env python3
"""Focused regression tests for scripts/check-coverage-thresholds.py."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECK_COVERAGE = ROOT / "scripts" / "check-coverage-thresholds.py"


class CoverageThresholdTests(unittest.TestCase):
    def run_threshold_check(
        self, module_mode: str, *, enforce_modules: bool = False
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            lcov = tmp / "lcov.info"
            thresholds = tmp / "coverage-thresholds.toml"

            lcov.write_text(
                "\n".join(
                    [
                        "TN:",
                        "SF:src/lib.rs",
                        "DA:1,1",
                        "LF:1",
                        "LH:1",
                        "end_of_record",
                    ]
                ),
                encoding="utf-8",
            )
            thresholds.write_text(
                "\n".join(
                    [
                        "[global]",
                        "line_floor = 0",
                        "",
                        "[[modules]]",
                        'name = "missing-module"',
                        "paths = [",
                        '  "missing/*.rs"',
                        "]",
                        "target = 90",
                        f'mode = "{module_mode}"',
                    ]
                ),
                encoding="utf-8",
            )

            command = [
                sys.executable,
                str(CHECK_COVERAGE),
                "--lcov",
                str(lcov),
                "--thresholds",
                str(thresholds),
            ]
            if enforce_modules:
                command.append("--enforce-modules")

            return subprocess.run(
                command,
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_required_module_without_lcov_match_fails(self) -> None:
        result = self.run_threshold_check("required")

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn(
            "error: missing-module: no LCOV records matched", result.stderr
        )

    def test_enforced_advisory_module_without_lcov_match_fails(self) -> None:
        result = self.run_threshold_check("advisory", enforce_modules=True)

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn(
            "error: missing-module: no LCOV records matched", result.stderr
        )

    def test_unenforced_advisory_module_without_lcov_match_warns(self) -> None:
        result = self.run_threshold_check("advisory")

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn(
            "warning: missing-module: no LCOV records matched", result.stderr
        )


if __name__ == "__main__":
    unittest.main()
