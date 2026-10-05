#!/usr/bin/env python3
"""Inert controls for the release metadata and archived-byte gates."""
import json
import io
from pathlib import Path
import tempfile
import tarfile
import subprocess
import unittest
from unittest.mock import patch

from m2_release_signing_gate import (
    archived_binaries, bound_build_messages, control_fixture, digest, production_features,
    production_fixture, require_control,
)
from m2_release_signing_gate_fixture import verify_helper_lock


class SigningMetadataControls(unittest.TestCase):
    @staticmethod
    def records():
        return [{"reason": "compiler-artifact", "features": [],
                 "target": {"kind": ["bin"], "name": name},
                 "executable": "/target/release/" + name,
                 "profile": {"debug_assertions": False}} for name in ("x0x", "x0xd")] + [
                     {"reason": "build-finished", "success": True}]

    def admit(self, records):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "build.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in records))
            return production_features(path)

    def test_default_production_build_is_accepted(self):
        self.assertEqual(self.admit(self.records()), {"x0x": [], "x0xd": []})

    def test_test_signing_on_either_binary_is_rejected(self):
        for index in (0, 1):
            rows = self.records()
            rows[index]["features"] = ["upgrade-test-signing"]
            with self.assertRaisesRegex(ValueError, "includes upgrade-test-signing"):
                self.admit(rows)

    def test_missing_feature_profile_or_binary_evidence_is_rejected(self):
        for name in ("features", "profile", "executable"):
            rows = self.records()
            del rows[0][name]
            with self.assertRaises(ValueError):
                self.admit(rows)
        with self.assertRaises(ValueError):
            self.admit(self.records()[1:])

    def test_debug_assertions_and_failed_or_missing_completion_are_rejected(self):
        rows = self.records()
        rows[0]["profile"]["debug_assertions"] = True
        with self.assertRaises(ValueError):
            self.admit(rows)
        rows = self.records()
        rows[-1]["success"] = False
        with self.assertRaises(ValueError):
            self.admit(rows)
        with self.assertRaises(ValueError):
            self.admit(self.records()[:-1])


class ArchivedByteControls(unittest.TestCase):
    def fixture(self, root, members):
        custody = root / "custody"
        custody.mkdir()
        (custody / "Cargo.lock").write_bytes(b"locked graph")
        binaries = {"x0x": b"cli", "x0xd": b"daemon"}
        for name, data in binaries.items():
            (custody / name).write_bytes(data)
        (custody / "build-provenance.json").write_text(json.dumps({
            "target": "x86_64-unknown-linux-gnu", "cargo_lock_file": "Cargo.lock",
            "cargo_lock_sha256": digest(b"locked graph"),
            "cargo_build_messages_sha256": digest(b"cargo evidence"),
            "binaries": [{"file": name, "size": len(data), "sha256": digest(data)}
                         for name, data in binaries.items()]}))
        archive = root / "package.tar.gz"
        with tarfile.open(archive, "w:gz") as package:
            for name, data in members:
                row = tarfile.TarInfo("package/" + name)
                row.size = len(data)
                package.addfile(row, io.BytesIO(data))
        destination = root / "unpacked"
        destination.mkdir()
        return archive, destination, custody

    def test_exact_archived_custody_bytes_are_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.fixture(Path(temp), [("x0x", b"cli"), ("x0xd", b"daemon")])
            self.assertEqual(archived_binaries(*args),
                             {"x0x": digest(b"cli"), "x0xd": digest(b"daemon")})

    def test_changed_missing_and_duplicate_archive_members_are_rejected(self):
        for members in ([("x0x", b"changed"), ("x0xd", b"daemon")],
                        [("x0x", b"cli")],
                        [("x0x", b"cli"), ("x0x", b"cli"), ("x0xd", b"daemon")]):
            with tempfile.TemporaryDirectory() as temp:
                args = self.fixture(Path(temp), members)
                with self.assertRaises(ValueError):
                    archived_binaries(*args)


    def test_build_messages_must_match_custody(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, _, custody = self.fixture(root, [("x0x", b"cli"), ("x0xd", b"daemon")])
            messages = root / "build.jsonl"
            messages.write_bytes(b"cargo evidence")
            self.assertEqual(bound_build_messages(messages, custody), digest(b"cargo evidence"))
            messages.write_bytes(b"different evidence")
            with self.assertRaisesRegex(ValueError, "build messages differ"):
                bound_build_messages(messages, custody)
            manifest_path = custody / "build-provenance.json"
            manifest = json.loads(manifest_path.read_text())
            del manifest["cargo_build_messages_sha256"]
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "build messages differ"):
                bound_build_messages(messages, custody)


class ProbeDiagnosticControls(unittest.TestCase):
    def test_negative_requires_signature_diagnostic(self):
        for code, stderr in ((1, b"loader failed"), (0, b"signature is invalid"), (2, b"signature is invalid")):
            with self.assertRaisesRegex(ValueError, "control failed"):
                require_control(subprocess.CompletedProcess([], code, b"", stderr), 1, "x0xd", "throwaway")
        require_control(subprocess.CompletedProcess([], 1, b"", b"signature is invalid"), 1, "x0xd", "throwaway")
        require_control(subprocess.CompletedProcess([], 0, b"", b""), 0, "x0xd", "production")


class SharedFixtureControls(unittest.TestCase):
    def fixture(self, root):
        directory = root / "controls"
        directory.mkdir()
        contents = production_fixture() | {"throwaway.pub": b"p" * 1952,
                                           "throwaway.sig": b"s" * 3309}
        for name, data in contents.items():
            (directory / name).write_bytes(data)
        evidence = {"schema": 1, "result": "PASS", "own_key_verified": True,
                    "algorithm": "ML-DSA-65", "context": "x0x-release-v1",
                    "GITHUB_SHA": "test-sha", "GITHUB_RUN_ID": "123",
                    "GITHUB_RUN_ATTEMPT": "1",
                    "sha256": {name: digest(data) for name, data in contents.items()}}
        raw = json.dumps(evidence).encode()
        (directory / "receipt.json").write_bytes(raw)
        destination = root / "destination"
        destination.mkdir()
        return directory, digest(raw), destination

    def admit(self, directory, expected, destination):
        # Synthetic fixture receipts exercise admission only, never crypto.
        with patch.dict("os.environ", {}, clear=True):
            control_fixture(directory, expected, destination, {})

    def test_producer_bound_public_bundle_is_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            args = self.fixture(Path(temp))
            self.admit(*args)

    def test_receipt_or_file_mutation_and_unexpected_secret_are_rejected(self):
        for name in ("receipt.json", "throwaway.sig", "throwaway.pub",
                     "release-manifest.json", "release-manifest.json.sig", "throwaway.secret"):
            with tempfile.TemporaryDirectory() as temp:
                directory, expected, destination = self.fixture(Path(temp))
                (directory / name).write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    self.admit(directory, expected, destination)

    def test_missing_files_or_positive_control_are_rejected(self):
        for name in ("throwaway.sig", "throwaway.pub", "release-manifest.json.sig"):
            with tempfile.TemporaryDirectory() as temp:
                directory, expected, destination = self.fixture(Path(temp))
                (directory / name).unlink()
                with self.assertRaises(ValueError):
                    self.admit(directory, expected, destination)
        with tempfile.TemporaryDirectory() as temp:
            directory, _, destination = self.fixture(Path(temp))
            receipt = directory / "receipt.json"
            evidence = json.loads(receipt.read_bytes())
            evidence["own_key_verified"] = False
            receipt.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(ValueError, "own-key verification"):
                self.admit(directory, digest(receipt.read_bytes()), destination)

    def test_equal_or_earlier_attempt_in_same_run_is_accepted(self):
        for producer, current in (("1", "1"), ("1", "2"), ("2", "10")):
            with self.subTest(producer=producer, current=current):
                with tempfile.TemporaryDirectory() as temp:
                    directory, _, destination = self.fixture(Path(temp))
                    receipt = directory / "receipt.json"
                    evidence = json.loads(receipt.read_bytes())
                    evidence["GITHUB_RUN_ATTEMPT"] = producer
                    receipt.write_text(json.dumps(evidence))
                    with patch.dict("os.environ", {"GITHUB_SHA": "test-sha",
                                    "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": current},
                                    clear=True):
                        control_fixture(directory, digest(receipt.read_bytes()), destination, {})

    def test_another_workflow_run_is_rejected_even_with_earlier_attempt(self):
        with tempfile.TemporaryDirectory() as temp:
            directory, expected, destination = self.fixture(Path(temp))
            with patch.dict("os.environ", {"GITHUB_SHA": "test-sha",
                            "GITHUB_RUN_ID": "456", "GITHUB_RUN_ATTEMPT": "2"}, clear=True):
                with self.assertRaisesRegex(ValueError, "another workflow execution"):
                    control_fixture(directory, expected, destination, {})

    def test_future_missing_or_invalid_producer_attempt_is_rejected(self):
        for attempt in ("3", "11", "0", "-1", "invalid", None):
            with self.subTest(attempt=attempt):
                with tempfile.TemporaryDirectory() as temp:
                    directory, _, destination = self.fixture(Path(temp))
                    receipt = directory / "receipt.json"
                    evidence = json.loads(receipt.read_bytes())
                    if attempt is None:
                        del evidence["GITHUB_RUN_ATTEMPT"]
                    else:
                        evidence["GITHUB_RUN_ATTEMPT"] = attempt
                    receipt.write_text(json.dumps(evidence))
                    with patch.dict("os.environ", {"GITHUB_SHA": "test-sha",
                                    "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"},
                                    clear=True):
                        with self.assertRaises(ValueError):
                            control_fixture(directory, digest(receipt.read_bytes()), destination, {})

    def test_receipted_production_fixture_still_requires_committed_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            directory, _, destination = self.fixture(Path(temp))
            (directory / "release-manifest.json").write_bytes(b"changed")
            receipt = directory / "receipt.json"
            evidence = json.loads(receipt.read_bytes())
            evidence["sha256"]["release-manifest.json"] = digest(b"changed")
            receipt.write_text(json.dumps(evidence))
            with self.assertRaisesRegex(ValueError, "committed production fixture"):
                self.admit(directory, digest(receipt.read_bytes()), destination)


class FixtureLockControls(unittest.TestCase):
    def test_lock_pruning_is_allowed_but_dependency_drift_is_rejected(self):
        dependency = ('[[package]]\nname = "fips204"\nversion = "0.4.6"\n'
                      'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                      'checksum = "pinned"\n')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            helper = root / "helper"
            helper.mkdir()
            (root / "Cargo.lock").write_text(dependency)
            (helper / "Cargo.lock").write_text(dependency)
            verify_helper_lock(helper, root)
            for changed in (dependency.replace("0.4.6", "0.4.7"),
                            dependency.replace("pinned", "changed")):
                (helper / "Cargo.lock").write_text(changed)
                with self.assertRaisesRegex(ValueError, "committed Cargo.lock"):
                    verify_helper_lock(helper, root)


if __name__ == "__main__":
    unittest.main()
