#!/usr/bin/env python3
"""The current ADR count fails when a record would pass the limit of 15."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("adr_count", ROOT / "scripts/check-adr-count.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
GITHUB_ENV_KEYS = (
    "GITHUB_EVENT_NAME",
    "GITHUB_BEFORE",
    "GITHUB_BASE_SHA",
    "GITHUB_BASE_REF",
)
STALE_BEFORE = "0a15ce643a7da30956b5a18fd870a9f50acfb047"


class AdrCountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / "docs/adr", self.root / "docs/adr", symlinks=True)
        archive = self.root / "docs/adr-archive"
        archive.mkdir()
        shutil.copy2(ROOT / "docs/adr-archive/move.json", archive / "move.json")
        self._saved_github_env = {key: os.environ.get(key) for key in GITHUB_ENV_KEYS}
        for key in GITHUB_ENV_KEYS:
            os.environ.pop(key, None)
        self.addCleanup(self._restore_github_env)
        self.addCleanup(self._remove_worktree)

    def _remove_worktree(self) -> None:
        root = getattr(self, "root", None)
        if root is None or not root.exists():
            return
        if (root / ".git").exists():
            # A fsmonitor daemon writes into .git after the test returns.
            subprocess.run(
                ["git", "-C", str(root), "fsmonitor--daemon", "stop"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        last_error: OSError | None = None
        for _ in range(8):
            try:
                shutil.rmtree(root)
            except OSError as exc:
                last_error = exc
                time.sleep(0.05)
                continue
            return
        if last_error is not None:
            raise last_error

    def _restore_github_env(self) -> None:
        for key, value in self._saved_github_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_repository_count_stays_within_the_limit_of_15(self):
        self.assertEqual(CHECK.validate(ROOT), [])
        count, extras = CHECK.current_records(ROOT)
        self.assertEqual(count, 15)
        self.assertEqual(extras, [])
        self.assertEqual(
            CHECK.pass_line(count),
            "PASS: 15 current ADRs, within the limit of 15. Plan: docs/adr/consolidated/README.md",
        )
        env = os.environ.copy()
        for key in GITHUB_ENV_KEYS:
            env.pop(key, None)
        reported = subprocess.check_output(
            [sys.executable, str(ROOT / "scripts/check-adr-count.py")],
            text=True,
            env=env,
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
        extra.parent.mkdir(exist_ok=True)
        extra.write_text("# ADR 0117\n\n- **Status:** Proposed\n")
        self.assertEqual(CHECK.validate(self.root), [])
        count, extras = CHECK.current_records(self.root)
        self.assertEqual((count, extras), (15, []))

    def test_invented_archive_record_is_rejected(self):
        name = "0117-invented.md"
        payload = b"# Invented\n"
        archive = self.root / "docs/adr-archive" / name
        archive.write_bytes(payload)
        source = self.root / "docs/adr" / name
        source.symlink_to(f"../adr-archive/{name}")
        manifest_path = self.root / "docs/adr-archive/move.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["moves"].append(
            {
                "from": f"docs/adr/{name}",
                "to": f"docs/adr-archive/{name}",
                "link": f"../adr-archive/{name}",
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        errors = CHECK.validate(self.root)
        self.assertIn(
            "docs/adr/0117-invented.md: newly invented archive record is not in "
            "the approved historical source set.",
            errors,
        )

    def test_transfer_row_cannot_approve_an_invented_archive(self):
        name = "0117-review-invented.md"
        payload = b"# Invented\n"
        archive = self.root / "docs/adr-archive" / name
        archive.write_bytes(payload)
        source = self.root / "docs/adr" / name
        source.symlink_to(f"../adr-archive/{name}")
        manifest_path = self.root / "docs/adr-archive/move.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["moves"].append(
            {
                "from": f"docs/adr/{name}",
                "to": f"docs/adr-archive/{name}",
                "link": f"../adr-archive/{name}",
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        transfer = self.root / "docs/adr/consolidated/TRANSFER.md"
        row = (
            "| [ADR 0117: Invented](../0117-review-invented.md) | Proposed | "
            "[A01](A01-r01-purpose-and-product-limits.md) | Pending |\n"
        )
        text = transfer.read_text(encoding="utf-8")
        self.assertIn("\n## Rulings", text)
        transfer.write_text(text.replace("\n## Rulings", "\n" + row + "\n## Rulings", 1), encoding="utf-8")
        approved = CHECK.approved_historical_sources()
        self.assertIn("docs/adr/0115-identity-discovery-authority.md", approved)
        self.assertIn("docs/adr/0116-local-history-retention-policy.md", approved)
        self.assertNotIn(f"docs/adr/{name}", approved)
        errors = CHECK.validate(self.root)
        self.assertIn(
            f"docs/adr/{name}: newly invented archive record is not in "
            "the approved historical source set.",
            errors,
        )
        self.assertIn(
            f"docs/adr/{name}: transfer row is not in the approved historical source set.",
            errors,
        )

    def _git(self, *args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(self.root), *args], text=True
        ).strip()

    def _init_repo(self) -> None:
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.root, check=True)
        for key, value in (
            ("user.name", "Test"),
            ("user.email", "test@example.com"),
            ("commit.gpgsign", "false"),
            ("gc.auto", "0"),
            ("gc.autoDetach", "false"),
            ("core.fsmonitor", "false"),
            ("maintenance.auto", "false"),
        ):
            subprocess.run(["git", "config", key, value], cwd=self.root, check=True)

    def _commit_all(self, message: str) -> str:
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-q", "-m", message], cwd=self.root, check=True)
        return self._git("rev-parse", "HEAD")

    def _add_invented_archive(self, name: str) -> None:
        payload = b"# Invented\n"
        archive = self.root / "docs/adr-archive" / name
        archive.write_bytes(payload)
        source = self.root / "docs/adr" / name
        source.symlink_to(f"../adr-archive/{name}")
        manifest_path = self.root / "docs/adr-archive/move.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["moves"].append(
            {
                "from": f"docs/adr/{name}",
                "to": f"docs/adr-archive/{name}",
                "link": f"../adr-archive/{name}",
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        transfer = self.root / "docs/adr/consolidated/TRANSFER.md"
        row = (
            f"| [ADR 0117: Invented](../{name}) | Proposed | "
            "[A01](A01-r01-purpose-and-product-limits.md) | Pending |\n"
        )
        text = transfer.read_text(encoding="utf-8")
        transfer.write_text(
            text.replace("\n## Rulings", "\n" + row + "\n## Rulings", 1),
            encoding="utf-8",
        )

    def test_push_event_cannot_approve_an_invented_archive(self):
        self._init_repo()
        before = self._commit_all("approved history")
        name = "0117-review-invented.md"
        self._add_invented_archive(name)
        head = self._commit_all("invent archive on main")
        self._git("update-ref", "refs/remotes/origin/main", head)
        self.assertEqual(self._git("rev-parse", "main"), head)
        self.assertEqual(self._git("rev-parse", "origin/main"), head)
        head_listing = self._git("ls-tree", "--name-only", head, "docs/adr/")
        before_listing = self._git("ls-tree", "--name-only", before, "docs/adr/")
        self.assertIn(f"docs/adr/{name}", head_listing)
        self.assertNotIn(f"docs/adr/{name}", before_listing)
        for key in GITHUB_ENV_KEYS:
            self.assertNotIn(key, os.environ)
        os.environ["GITHUB_EVENT_NAME"] = ""
        os.environ["GITHUB_BASE_SHA"] = ""
        os.environ["GITHUB_BASE_REF"] = ""
        os.environ["GITHUB_BEFORE"] = before
        self.assertEqual(CHECK._history_base(self.root), before)
        self.assertNotEqual(CHECK._history_base(self.root), head)
        errors = CHECK.validate(self.root)
        self.assertIn(
            f"docs/adr/{name}: newly invented archive record is not in "
            "the approved historical source set.",
            errors,
        )
        self.assertIn(
            f"docs/adr/{name}: transfer row is not in the approved historical source set.",
            errors,
        )
        self.assertIn(
            "16 current ADRs exceeds the limit of 15. "
            f"Extra: {name}. "
            "Plan: docs/adr/consolidated/README.md",
            errors,
        )
        os.environ.pop("GITHUB_BEFORE", None)
        self.assertEqual(CHECK._history_base(self.root), before)
        self.assertNotEqual(CHECK._history_base(self.root), head)
        local_errors = CHECK.validate(self.root)
        self.assertIn(
            f"docs/adr/{name}: newly invented archive record is not in "
            "the approved historical source set.",
            local_errors,
        )
        os.environ["GITHUB_BEFORE"] = "0" * 40
        closed = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "Cannot resolve the approved historical source set from GITHUB_BEFORE."
                in error
                for error in closed
            )
        )

    def test_stale_github_before_outside_the_repo_still_reports_the_pr_count(self):
        self._init_repo()
        base = self._commit_all("approved history")
        name = "0117-review-invented.md"
        self._add_invented_archive(name)
        self._commit_all("invent archive on the previous head")
        (self.root / "note.txt").write_text("force-push replacement\n")
        head = self._commit_all("replacement head")
        self._git("update-ref", "refs/remotes/origin/main", head)
        self.assertIsNone(CHECK._resolve_commit(self.root, STALE_BEFORE))
        os.environ["GITHUB_EVENT_NAME"] = "pull_request"
        os.environ["GITHUB_BEFORE"] = STALE_BEFORE
        os.environ["GITHUB_BASE_SHA"] = base
        os.environ["GITHUB_BASE_REF"] = "main"
        self.assertEqual(CHECK._history_base(self.root), base)
        errors = CHECK.validate(self.root)
        self.assertFalse(
            any("GITHUB_BEFORE" in error for error in errors),
            errors,
        )
        self.assertIn(
            f"docs/adr/{name}: newly invented archive record is not in "
            "the approved historical source set.",
            errors,
        )
        self.assertIn(
            f"docs/adr/{name}: transfer row is not in the approved historical source set.",
            errors,
        )
        self.assertIn(
            "16 current ADRs exceeds the limit of 15. "
            f"Extra: {name}. "
            "Plan: docs/adr/consolidated/README.md",
            errors,
        )

    def test_pull_request_fails_closed_when_the_base_sha_is_absent(self):
        self._init_repo()
        base = self._commit_all("approved history")
        name = "0117-review-invented.md"
        self._add_invented_archive(name)
        self._commit_all("invent archive")
        os.environ["GITHUB_EVENT_NAME"] = "pull_request"
        os.environ["GITHUB_BEFORE"] = base
        os.environ["GITHUB_BASE_SHA"] = STALE_BEFORE
        os.environ["GITHUB_BASE_REF"] = "main"
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "Cannot resolve the approved historical source set from GITHUB_BASE_SHA."
                in error
                for error in errors
            ),
            errors,
        )
        self.assertFalse(any("newly invented archive record" in error for error in errors))

    def test_push_fails_closed_when_github_before_is_absent(self):
        self._init_repo()
        base = self._commit_all("approved history")
        (self.root / "note.txt").write_text("later\n")
        self._commit_all("later")
        os.environ["GITHUB_EVENT_NAME"] = "push"
        os.environ["GITHUB_BEFORE"] = STALE_BEFORE
        os.environ["GITHUB_BASE_SHA"] = base
        os.environ["GITHUB_BASE_REF"] = "main"
        self.assertIsNone(CHECK._resolve_commit(self.root, STALE_BEFORE))
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "Cannot resolve the approved historical source set from GITHUB_BEFORE."
                in error
                for error in errors
            ),
            errors,
        )
        self.assertFalse(any("exceeds the limit" in error for error in errors))

    def test_deleted_transfer_row_counts_the_archived_source(self):
        transfer = self.root / "docs/adr/consolidated/TRANSFER.md"
        text = transfer.read_text(encoding="utf-8")
        needle = "../0115-identity-discovery-authority.md"
        self.assertEqual(text.count(needle), 1)
        kept = [line for line in text.splitlines() if needle not in line]
        transfer.write_text("\n".join(kept) + "\n", encoding="utf-8")
        errors = CHECK.validate(self.root)
        self.assertEqual(
            errors,
            [
                "16 current ADRs exceeds the limit of 15. "
                "Extra: 0115-identity-discovery-authority.md. "
                "Plan: docs/adr/consolidated/README.md"
            ],
        )

    def test_source_mapping_must_name_a_slot(self):
        transfer = self.root / "docs/adr/consolidated/TRANSFER.md"
        text = transfer.read_text(encoding="utf-8")
        old = "](A02-r01-identity-keys-and-device-enrollment.md)"
        new = "](A16-r01-not-a-slot.md)"
        self.assertIn(old, text)
        transfer.write_text(text.replace(old, new, 1), encoding="utf-8")
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any("source-to-slot mapping must name one slot A01-A15." in error for error in errors)
        )

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
