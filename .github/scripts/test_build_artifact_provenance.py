#!/usr/bin/env python3
"""Offline controls for build_artifact_provenance.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("build_artifact_provenance.py")
SPEC = importlib.util.spec_from_file_location("build_artifact_provenance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PROVENANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVENANCE)


class ProvenanceFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.artifact = self.root / "artifact"
        self.release = self.root / "target" / "release"
        self.messages = self.root / "cargo-build.jsonl"
        self.repo.mkdir()
        (self.repo / "Cargo.toml").write_text('[package]\nname = "fixture"\nversion = "0.1.0"\n')
        (self.repo / "Cargo.lock").write_text("version = 4\n")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "Cargo.toml"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=Fixture", "-c",
             "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], check=True
        )
        self.release.mkdir(parents=True)
        (self.release / "x0x").write_bytes(b"cli")
        (self.release / "x0xd").write_bytes(b"daemon")
        (self.release / "x0x-keygen").write_bytes(b"utility")
        (self.release / "x0x-keygen.d").write_bytes(b"dependency metadata")
        (self.release / "x0x.pdb").write_bytes(b"debug metadata")
        self.write_messages(("x0x", False), ("x0xd", True), ("x0x-keygen", False))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def prepare(self) -> None:
        PROVENANCE.prepare(self.repo, self.artifact, "linux-x64-gnu", "x86_64-unknown-linux-gnu")

    def write_messages(
        self,
        *binaries: tuple[str, bool],
        success: bool = True,
        windows_paths: bool = False,
    ) -> None:
        records = []
        for name, fresh in binaries:
            executable = (
                rf"C:\cargo\target\release\{name}.exe"
                if windows_paths
                else f"/cross/container/target/release/{name}"
            )
            records.append({
                "reason": "compiler-artifact",
                "target": {"kind": ["bin"], "name": name},
                "executable": executable,
                "fresh": fresh,
            })
        records.append({"reason": "build-finished", "success": success})
        self.messages.write_text("".join(json.dumps(row) + "\n" for row in records))

    def test_stages_and_verifies_exact_upload_set(self) -> None:
        self.prepare()
        PROVENANCE.finalize(self.repo, self.artifact, self.release, self.messages)
        PROVENANCE.verify_artifact(self.artifact)
        self.assertEqual(
            {"Cargo.lock", "build-provenance.json", "x0x", "x0xd", "x0x-keygen"},
            {path.name for path in self.artifact.iterdir()},
        )

    def test_source_change_after_prepare_is_rejected(self) -> None:
        self.prepare()
        (self.repo / "Cargo.toml").write_text("changed\n")
        with self.assertRaisesRegex(RuntimeError, "tracked source differs"):
            PROVENANCE.finalize(self.repo, self.artifact, self.release, self.messages)

    def test_lock_change_after_prepare_is_rejected(self) -> None:
        self.prepare()
        (self.repo / "Cargo.lock").write_text("version = 3\n")
        with self.assertRaisesRegex(RuntimeError, "cargo_lock_sha256 changed"):
            PROVENANCE.finalize(self.repo, self.artifact, self.release, self.messages)

    def test_missing_daemon_or_cli_is_rejected(self) -> None:
        for missing in ("x0x", "x0xd"):
            with self.subTest(missing=missing):
                artifact = self.root / f"artifact-{missing}"
                PROVENANCE.prepare(
                    self.repo, artifact, "linux-x64-gnu", "x86_64-unknown-linux-gnu"
                )
                (self.release / missing).unlink()
                with self.assertRaisesRegex(RuntimeError, f"binary output is missing: {missing}"):
                    PROVENANCE.finalize(self.repo, artifact, self.release, self.messages)
                (self.release / missing).write_bytes(missing.encode())

    def test_unmanifested_file_in_staged_artifact_is_rejected(self) -> None:
        self.prepare()
        PROVENANCE.finalize(self.repo, self.artifact, self.release, self.messages)
        (self.artifact / "x0x-stale").write_bytes(b"unmanifested")
        with self.assertRaisesRegex(RuntimeError, "unexpected files"):
            PROVENANCE.verify_artifact(self.artifact)

    def test_staged_binary_tamper_is_rejected(self) -> None:
        self.prepare()
        PROVENANCE.finalize(self.repo, self.artifact, self.release, self.messages)
        (self.artifact / "x0xd").write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "artifact binary hash mismatch"):
            PROVENANCE.verify_artifact(self.artifact)

    def test_windows_requires_exe_names(self) -> None:
        artifact = self.root / "windows-artifact"
        PROVENANCE.prepare(self.repo, artifact, "windows-x64", "x86_64-pc-windows-msvc")
        self.write_messages(("x0x", False), ("x0xd", False))
        with self.assertRaisesRegex(RuntimeError, "does not match its bin target"):
            PROVENANCE.finalize(self.repo, artifact, self.release, self.messages)

    def test_windows_paths_stage_current_exe_artifacts(self) -> None:
        for name in ("x0x.exe", "x0xd.exe", "x0x-keygen.exe"):
            (self.release / name).write_bytes(name.encode())
        artifact = self.root / "windows-positive"
        PROVENANCE.prepare(self.repo, artifact, "windows-x64", "x86_64-pc-windows-msvc")
        self.write_messages(
            ("x0x", False), ("x0xd", True), ("x0x-keygen", False), windows_paths=True
        )
        PROVENANCE.finalize(self.repo, artifact, self.release, self.messages)
        self.assertEqual(
            {"Cargo.lock", "build-provenance.json", "x0x.exe", "x0xd.exe", "x0x-keygen.exe"},
            {path.name for path in artifact.iterdir()},
        )

    def test_stale_extra_binary_without_current_artifact_record_is_excluded(self) -> None:
        (self.release / "x0x-stale-feature").write_bytes(b"stale cache output")
        self.prepare()
        PROVENANCE.finalize(self.repo, self.artifact, self.release, self.messages)
        self.assertNotIn("x0x-stale-feature", {path.name for path in self.artifact.iterdir()})

    def test_exact_cross_rustup_preamble_before_cargo_is_accepted(self) -> None:
        self.messages.write_text(
            "\n\x1b[1m  1.95.0-x86_64-unknown-linux-gnu unchanged - "
            "rustc 1.95.0 (59807616e 2026-04-14)\x1b[0m\n\n"
            + self.messages.read_text()
        )
        self.prepare()
        PROVENANCE.finalize(self.repo, self.artifact, self.release, self.messages)
        self.assertEqual(
            PROVENANCE.sha256(self.messages),
            PROVENANCE.read_json(self.artifact / PROVENANCE.MANIFEST)[
                "cargo_build_messages_sha256"
            ],
        )

    def test_next_version_cross_rustup_preamble_is_accepted(self) -> None:
        self.messages.write_text(
            "  1.96.0-x86_64-unknown-linux-gnu unchanged - "
            "rustc 1.96.0 (abcdef123 2026-06-01)\n"
            + self.messages.read_text()
        )
        self.prepare()
        PROVENANCE.finalize(self.repo, self.artifact, self.release, self.messages)

    def test_inconsistent_cross_rustup_versions_are_rejected(self) -> None:
        self.messages.write_text(
            "  1.96.0-x86_64-unknown-linux-gnu unchanged - "
            "rustc 1.95.0 (abcdef123 2026-06-01)\n"
            + self.messages.read_text()
        )
        self.prepare()
        with self.assertRaisesRegex(RuntimeError, "invalid Cargo build record at line 1"):
            PROVENANCE.finalize(self.repo, self.artifact, self.release, self.messages)

    def test_unknown_or_malformed_build_record_is_rejected(self) -> None:
        original = self.messages.read_text()
        for label, prefix in (
            ("unknown", "cross emitted an unknown status\n"),
            ("malformed-json", '{"reason":"compiler-artifact"\n'),
        ):
            with self.subTest(label=label):
                artifact = self.root / f"artifact-{label}"
                self.messages.write_text(prefix + original)
                PROVENANCE.prepare(
                    self.repo, artifact, "linux-x64-gnu", "x86_64-unknown-linux-gnu"
                )
                with self.assertRaisesRegex(RuntimeError, "invalid Cargo build record at line 1"):
                    PROVENANCE.finalize(self.repo, artifact, self.release, self.messages)

    def test_cross_rustup_preamble_after_cargo_starts_is_rejected(self) -> None:
        lines = self.messages.read_text().splitlines()
        lines.insert(
            1,
            "  1.95.0-x86_64-unknown-linux-gnu unchanged - "
            "rustc 1.95.0 (59807616e 2026-04-14)",
        )
        self.messages.write_text("\n".join(lines) + "\n")
        self.prepare()
        with self.assertRaisesRegex(RuntimeError, "invalid Cargo build record at line 2"):
            PROVENANCE.finalize(self.repo, self.artifact, self.release, self.messages)

    def test_failed_or_missing_build_completion_is_rejected(self) -> None:
        for label, records in (
            ("failed", (("x0x", False), ("x0xd", False))),
            ("missing", (("x0x", False), ("x0xd", False))),
        ):
            with self.subTest(label=label):
                artifact = self.root / f"artifact-{label}"
                PROVENANCE.prepare(
                    self.repo, artifact, "linux-x64-gnu", "x86_64-unknown-linux-gnu"
                )
                self.write_messages(*records, success=False)
                if label == "missing":
                    lines = self.messages.read_text().splitlines()
                    self.messages.write_text("\n".join(lines[:-1]) + "\n")
                with self.assertRaisesRegex(RuntimeError, "Cargo build"):
                    PROVENANCE.finalize(self.repo, artifact, self.release, self.messages)


if __name__ == "__main__":
    unittest.main()
