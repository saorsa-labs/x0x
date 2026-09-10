#!/usr/bin/env python3
"""Run the real shell scanner over inert text; never compile or execute Rust."""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCANNER = Path(__file__).resolve().with_name("check-panics.sh")


class PanicScanner(unittest.TestCase):
    def scan(self, relative, source):
        with tempfile.TemporaryDirectory(prefix="x0x-panic-scanner-") as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "x0x").mkdir()
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
            result = subprocess.run(
                ["bash", str(SCANNER)],
                cwd=root,
                env={**os.environ, "LC_ALL": "C"},
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        # Retain actual scanner output even for passing synthetic controls.
        print(f"\n{self.id()}: scanner exit {result.returncode}", flush=True)
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", flush=True)
        self.assertEqual(result.stderr, "", "scanner regex/tool errors must be visible")
        return result

    def assert_clean(self, result):
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("PASS: No .expect() calls in production code", result.stdout)
        self.assertIn("All checks passed", result.stdout)

    def test_production_expect_is_rejected(self):
        result = self.scan("src/production.rs", 'fn f() { value.expect("required"); }\n')
        self.assertEqual(result.returncode, 1, "production expect must fail the real scanner")
        self.assertIn('src/production.rs:1:fn f() { value.expect("required"); }', result.stdout)
        self.assertIn("FOUND: .expect() calls in production code", result.stdout)
        self.assertIn("Found 1 issue(s)", result.stdout)

    def test_clean_production_is_accepted(self):
        self.assert_clean(self.scan("src/production.rs", "fn f() { value.map_err(convert)?; }\n"))

    def test_inner_cfg_test_is_accepted(self):
        self.assert_clean(self.scan("src/helper.rs", '#![cfg(test)]\nfn f() { value.expect("test"); }\n'))

    def test_comment_expect_is_accepted(self):
        # Exercises the shared pattern's ERE consumer, not just BRE matching.
        self.assert_clean(self.scan("src/production.rs", '// value.expect("comment");\n'))

    def test_lookalikes_are_accepted(self):
        self.assert_clean(self.scan("src/production.rs", 'valuexexpect("text");\nvalue.expect_value;\n'))

    def test_tests_path_is_accepted(self):
        self.assert_clean(self.scan("src/tests.rs", 'fn f() { value.expect("test"); }\n'))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", type=Path, default=SCANNER)
    args, unittest_args = parser.parse_known_args()
    SCANNER = args.scanner.resolve(strict=True)
    unittest.main(argv=[__file__, *unittest_args], verbosity=2)
