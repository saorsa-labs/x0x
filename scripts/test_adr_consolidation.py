#!/usr/bin/env python3
"""Offline checks for real ways to bypass the 15-slot transition rule."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("consolidation", ROOT / "scripts/check-adr-consolidation.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class ConsolidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "docs/adr/consolidated"
        shutil.copytree(ROOT / "docs/adr/consolidated", self.directory)
        self.index_path = self.directory / "index.json"
        self.index = json.loads(self.index_path.read_text())

    def save_index(self):
        self.index_path.write_text(json.dumps(self.index))

    def record_hash(self, slot_index=0):
        """Re-record a mutated slot file's sha256, as a ruled supersession PR would."""
        slot = self.index["slots"][slot_index]
        slot["sha256"] = hashlib.sha256((self.directory / slot["path"]).read_bytes()).hexdigest()
        self.save_index()

    def assert_rejected(self, phrase):
        errors = CHECK.validate(self.root)
        self.assertTrue(any(phrase in error for error in errors), errors)

    def test_agreed_set_is_valid_without_network_or_daemon(self):
        self.assertEqual(CHECK.validate(self.root), [])

    def test_sixteenth_slot_cannot_be_hidden_by_increasing_declared_limit(self):
        self.index["maximum_current_adrs"] = 16
        self.index["slots"].append({"id": "A16", "revision": 1, "path": "A16-r01-extra.md", "title": "Extra"})
        self.save_index()
        self.assert_rejected("maximum current ADR count must remain 15")
        self.assert_rejected("Unknown ADR slot 'A16'")

    def test_unindexed_record_cannot_bypass_limit_in_a_subdirectory(self):
        path = self.directory / "hidden/A16-r01-extra.md"
        path.parent.mkdir()
        path.write_text("# A16 Extra\n")
        self.assert_rejected("Unindexed records")

    def test_duplicate_slot_cannot_replace_another_current_decision(self):
        self.index["slots"][-1] = self.index["slots"][0]
        self.save_index()
        self.assert_rejected("Duplicate current slot A01")
        self.assert_rejected("Missing current slots: A15")

    def test_missing_record_cannot_leave_an_index_only_promise(self):
        (self.directory / self.index["slots"][0]["path"]).unlink()
        self.assert_rejected("cannot read record")

    STATUS_LINE = "- **Status:** Accepted (David, course-correction directive, 7 Nov 2026, ruling 2)"

    def test_status_cannot_be_reverted_without_davids_ruling(self):
        path = self.directory / self.index["slots"][0]["path"]
        self.assertIn(self.STATUS_LINE, path.read_text())
        path.write_text(path.read_text().replace(self.STATUS_LINE, "- **Status:** Proposed"))
        self.assert_rejected("slot status must remain Accepted")

    def test_status_annotations_use_the_leading_lifecycle_token(self):
        path = self.directory / self.index["slots"][0]["path"]
        original = path.read_text()
        for status in ("Accepted (record)", "**Accepted** review recorded", "Accepted; folded 7 Nov 2026"):
            with self.subTest(status=status):
                path.write_text(original.replace(self.STATUS_LINE, f"- **Status:** {status}"))
                self.record_hash()
                self.assertEqual(CHECK.validate(self.root), [])
        for status in ("Proposed", "Proposed (Accepted draft)", "AcceptedElsewhere"):
            with self.subTest(status=status):
                path.write_text(original.replace(self.STATUS_LINE, f"- **Status:** {status}"))
                self.record_hash()
                self.assert_rejected("slot status must remain Accepted")

    def test_missing_or_duplicate_status_cannot_bypass_the_lock(self):
        path = self.directory / self.index["slots"][0]["path"]
        original = path.read_text()
        for replacement in ("", f"{self.STATUS_LINE}\n- **Status:** Accepted"):
            with self.subTest(replacement=replacement):
                path.write_text(original.replace(self.STATUS_LINE, replacement))
                self.assert_rejected("slot status must remain Accepted")

    def test_title_must_match_the_index(self):
        self.index["slots"][0]["title"] = "Different title"
        self.save_index()
        self.assert_rejected("title must match the selected slot")

    def test_every_required_section_must_be_present(self):
        path = self.directory / self.index["slots"][0]["path"]
        original = path.read_text()
        for section in sorted(CHECK.REQUIRED_SECTIONS):
            with self.subTest(section=section):
                path.write_text(original.replace(f"## {section}\n", "## Other\n"))
                self.assert_rejected(f"missing ## {section}")

    def test_selected_record_cannot_be_a_symlink(self):
        path = self.directory / self.index["slots"][0]["path"]
        target = self.root / "external.md"
        path.rename(target)
        path.symlink_to(target)
        self.assert_rejected("records must be regular files, not links")

    def test_revision_must_match_the_record_path(self):
        self.index["slots"][0]["revision"] = 2
        self.save_index()
        self.assert_rejected("use its own Axx-rNN-title.md file and matching revision")

    def test_slot_identity_must_match_the_record_path(self):
        self.index["slots"][0]["path"] = self.index["slots"][1]["path"]
        self.save_index()
        self.assert_rejected("use its own Axx-rNN-title.md file and matching revision")

    def test_phase_cannot_change_without_davids_ruling(self):
        for phase in ("active", "transfer_review"):
            with self.subTest(phase=phase):
                self.index["phase"] = phase
                self.save_index()
                self.assert_rejected("Only schema 1 accepted is supported")

    def test_record_path_cannot_escape_the_governed_directory(self):
        self.index["slots"][0]["path"] = "../0001-bootstrap-peers-are-seed-hints-only.md"
        self.save_index()
        self.assert_rejected("use its own Axx-rNN-title.md file")

    def test_accepted_decision_rewrite_is_rejected_without_an_index_update(self):
        path = self.directory / self.index["slots"][0]["path"]
        path.write_text(path.read_text().replace("## Decision", "## Decision\n\nRewritten.", 1))
        self.assert_rejected("does not match the sha256 recorded in index.json")

    def test_ruled_supersession_records_the_new_hash_and_passes(self):
        path = self.directory / self.index["slots"][0]["path"]
        path.write_text(path.read_text().replace("## Decision", "## Decision\n\nRuled change.", 1))
        self.record_hash()
        self.assertEqual(CHECK.validate(self.root), [])

    def test_missing_or_malformed_slot_hash_is_rejected(self):
        for bad in (None, "abc", "G" * 64, hashlib.sha256(b"x").hexdigest().upper()):
            with self.subTest(sha256=bad):
                if bad is None:
                    self.index["slots"][0].pop("sha256", None)
                else:
                    self.index["slots"][0]["sha256"] = bad
                self.save_index()
                self.assert_rejected("must record the slot file's sha256")

    def test_malformed_index_fails_closed_with_a_clear_result(self):
        self.index_path.write_text("{")
        self.assert_rejected("Cannot read the consolidated index")


if __name__ == "__main__":
    unittest.main()
