#!/usr/bin/env python3
"""The current ADR count fails when a record would pass the limit of 15."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("adr_count", ROOT / "scripts/check-adr-count.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class AdrCountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / "docs/adr", self.root / "docs/adr", symlinks=True)
        archive = self.root / "docs/adr-archive"
        archive.mkdir()
        shutil.copy2(ROOT / "docs/adr-archive/move.json", archive / "move.json")

    def test_repository_count_stays_within_the_limit_of_15(self):
        self.assertEqual(CHECK.validate(ROOT), [])
        count, extras = CHECK.current_records(ROOT)
        self.assertEqual(count, 15)
        self.assertEqual(extras, [])
        self.assertEqual(
            CHECK.pass_line(count),
            "PASS: 15 current ADRs, within the limit of 15. Plan: docs/adr/consolidated/README.md",
        )
        reported = subprocess.check_output(
            [sys.executable, str(ROOT / "scripts/check-adr-count.py")],
            text=True,
        )
        self.assertEqual(
            reported,
            "PASS: 15 current ADRs, within the limit of 15. Plan: docs/adr/consolidated/README.md\n",
        )
        self.assertNotIn("UNPLACED", reported)

    def test_extra_numbered_adr_exceeds_the_limit_of_15(self):
        extra = self.root / "docs/adr/0117-extra-record.md"
        extra.write_text("# ADR 0117\n\n- **Status:** Proposed\n")
        errors = CHECK.validate(self.root)
        self.assertEqual(
            errors,
            [
                "16 current ADRs exceeds the limit of 15. "
                "Extra: 0117-extra-record.md. "
                "Plan: docs/adr/consolidated/README.md"
            ],
        )

    def test_nested_file_reusing_a_mapped_number_counts(self):
        extra = self.root / "docs/adr/drafts/0115-new-decision.md"
        extra.parent.mkdir()
        extra.write_text("# ADR 0115\n\n- **Status:** Proposed\n")
        errors = CHECK.validate(self.root)
        self.assertEqual(
            errors,
            [
                "16 current ADRs exceeds the limit of 15. "
                "Extra: drafts/0115-new-decision.md. "
                "Plan: docs/adr/consolidated/README.md"
            ],
        )

    def test_transient_file_stays_outside_the_count(self):
        extra = self.root / "docs/adr/transient/0117-new-decision.md"
        extra.parent.mkdir()
        extra.write_text("# ADR 0117\n\n- **Status:** Proposed\n")
        self.assertEqual(CHECK.validate(self.root), [])
        count, extras = CHECK.current_records(self.root)
        self.assertEqual((count, extras), (15, []))

    def test_extra_consolidated_record_exceeds_the_limit_of_15(self):
        extra = self.root / "docs/adr/consolidated/hidden/A16-r01-extra.md"
        extra.parent.mkdir()
        extra.write_text("# A16 Extra\n")
        errors = CHECK.validate(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("16 current ADRs exceeds the limit of 15.", errors[0])
        self.assertIn("Plan: docs/adr/consolidated/README.md", errors[0])

    def test_mapped_numbered_adr_stays_outside_the_count(self):
        count, extras = CHECK.current_records(self.root)
        self.assertEqual((count, extras), (15, []))
        mapped = CHECK.mapped_ids(self.root)
        self.assertIn("0001", mapped)
        self.assertIn("0114", mapped)
        self.assertIn("0115", mapped)
        self.assertIn("0116", mapped)
        self.assertEqual(len(mapped), 102)


if __name__ == "__main__":
    unittest.main()
