#!/usr/bin/env python3
"""Offline controls for release_artifact_custody.py."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

SOURCE = Path(__file__).with_name("release_artifact_custody.py")
SPEC = importlib.util.spec_from_file_location("release_artifact_custody", SOURCE)
assert SPEC and SPEC.loader
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class CustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", self.repo], check=True)
        subprocess.run(["git", "-C", self.repo, "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", self.repo, "config", "user.name", "Test"], check=True)
        (self.repo / ".gitignore").write_text("Cargo.lock\n")
        (self.repo / "Cargo.toml").write_text("[package]\nname='fixture'\nversion='0.1.0'\n")
        subprocess.run(["git", "-C", self.repo, "add", "."], check=True)
        subprocess.run(["git", "-C", self.repo, "commit", "-qm", "fixture"], check=True)
        (self.repo / "Cargo.lock").write_bytes(b"lock-v1")
        self.custody = self.root / "custody"
        C.resolve(self.repo, self.custody)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def provenance(self, platform: str, target: str, suffix: str = "") -> dict[str, object]:
        lock = (self.custody / "Cargo.lock").read_bytes()
        identity = C.load(self.custody / C.LOCK_MANIFEST)
        binaries = []
        for name, data in ((f"x0x{suffix}", b"cli-" + platform.encode()), (f"x0xd{suffix}", b"daemon-" + platform.encode())):
            binaries.append({"file": name, "sha256": sha(data), "size": len(data)})
        return {**identity, "platform": platform, "target": target,
                "cargo_lock_sha256": sha(lock), "binaries": binaries}

    def archive(
        self,
        directory: Path,
        platform: str,
        *,
        omit: str = "",
        tamper: str = "",
        target: str | None = None,
        lock_data: bytes | None = None,
    ) -> Path:
        suffix = ".exe" if platform == "windows-x64" else ""
        declared_target = target or C.PLATFORM_TARGETS[platform]
        provenance = self.provenance(platform, declared_target, suffix)
        root = f"x0x-{platform}"
        files: dict[str, bytes] = {
            f"{root}/Cargo.lock": lock_data or (self.custody / "Cargo.lock").read_bytes(),
            f"{root}/{C.PROVENANCE}": (json.dumps(provenance) + "\n").encode(),
        }
        for entry in provenance["binaries"]:
            name = str(entry["file"])
            if name != omit:
                data = (b"cli-" if name == f"x0x{suffix}" else b"daemon-") + platform.encode()
                files[f"{root}/{name}"] = b"changed" if name == tamper else data
        if suffix:
            path = directory / f"x0x-{platform}.zip"
            with zipfile.ZipFile(path, "w") as archive:
                for name, data in files.items(): archive.writestr(name, data)
        else:
            path = directory / f"x0x-{platform}.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                for name, data in files.items():
                    info = tarfile.TarInfo(name); info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
        path.with_name(f"{path.name}.sha256").write_text(f"{C.digest(path)}  {path.name}\n")
        return path

    def test_install_rejects_source_and_lock_drift(self) -> None:
        (self.repo / "Cargo.toml").write_text("changed")
        with self.assertRaisesRegex(RuntimeError, "tracked source"):
            C.verify_lock(self.repo, self.custody, True)
        subprocess.run(["git", "-C", self.repo, "checkout", "--", "Cargo.toml"], check=True)
        (self.custody / "Cargo.lock").write_bytes(b"other")
        with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
            C.verify_lock(self.repo, self.custody, True)

    def test_archive_rejects_binary_tamper_and_missing_required_output(self) -> None:
        directory = self.root / "archives"; directory.mkdir()
        manifest = C.load(self.custody / C.LOCK_MANIFEST)
        with self.assertRaisesRegex(RuntimeError, "binary hash mismatch"):
            C.verify_archive(self.archive(directory, "linux-x64-gnu", tamper="x0xd"), manifest)
        for path in directory.iterdir(): path.unlink()
        with self.assertRaisesRegex(RuntimeError, "binary is missing"):
            C.verify_archive(self.archive(directory, "linux-x64-gnu", omit="x0x"), manifest)

    def test_archive_rejects_lock_and_source_mismatch(self) -> None:
        directory = self.root / "archives"; directory.mkdir()
        archive = self.archive(directory, "linux-x64-gnu")
        manifest = C.load(self.custody / C.LOCK_MANIFEST)
        manifest["source_tree"] = "f" * 40
        with self.assertRaisesRegex(RuntimeError, "source_tree"):
            C.verify_archive(archive, manifest)

        directory = self.root / "lock-tamper"; directory.mkdir()
        with self.assertRaisesRegex(RuntimeError, "Cargo.lock"):
            C.verify_archive(
                self.archive(directory, "linux-x64-gnu", lock_data=b"different-lock"),
                C.load(self.custody / C.LOCK_MANIFEST),
            )

    def test_archive_rejects_wrong_target_for_platform(self) -> None:
        directory = self.root / "wrong-target"; directory.mkdir()
        archive = self.archive(
            directory,
            "macos-arm64",
            target="x86_64-unknown-linux-gnu",
        )
        with self.assertRaisesRegex(RuntimeError, "target identity"):
            C.verify_archive(archive, C.load(self.custody / C.LOCK_MANIFEST))

    def test_archive_rejects_duplicate_and_link_members(self) -> None:
        manifest = C.load(self.custody / C.LOCK_MANIFEST)
        duplicate = self.root / "x0x-linux-x64-gnu.tar.gz"
        with tarfile.open(duplicate, "w:gz") as archive:
            for _ in range(2):
                info = tarfile.TarInfo("x0x-linux-x64-gnu/Cargo.lock")
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
        with self.assertRaisesRegex(RuntimeError, "duplicate archive member"):
            C.verify_archive(duplicate, manifest)

        linked = self.root / "x0x-linux-x64-gnu-linked.tar.gz"
        with tarfile.open(linked, "w:gz") as archive:
            info = tarfile.TarInfo("x0x-linux-x64-gnu/x0xd")
            info.type = tarfile.SYMTYPE
            info.linkname = "/tmp/not-the-packaged-binary"
            archive.addfile(info)
        with self.assertRaisesRegex(RuntimeError, "non-regular archive member"):
            C.archive_members(linked)

        zip_link = self.root / "x0x-windows-x64.zip"
        with zipfile.ZipFile(zip_link, "w") as archive:
            info = zipfile.ZipInfo("x0x-windows-x64/x0xd.exe")
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            archive.writestr(info, "target")
        with self.assertRaisesRegex(RuntimeError, "non-regular archive member"):
            C.archive_members(zip_link)

    def test_aggregate_requires_every_platform_and_accepts_signed_stage_hashes(self) -> None:
        artifacts = self.root / "artifacts"; artifacts.mkdir()
        for platform in C.PLATFORM_TARGETS:
            directory = artifacts / f"release-{platform}"; directory.mkdir()
            self.archive(directory, platform)
        missing = artifacts / "release-macos-arm64" / "x0x-macos-arm64.tar.gz"
        held = missing.read_bytes(); missing.unlink()
        missing_checksum = missing.with_name(f"{missing.name}.sha256")
        held_checksum = missing_checksum.read_bytes(); missing_checksum.unlink()
        with self.assertRaisesRegex(RuntimeError, "platform set mismatch"):
            C.aggregate(self.custody, artifacts, self.root / "aggregate.json")
        missing.write_bytes(held)
        missing_checksum.write_bytes(held_checksum)
        output = self.root / "aggregate.json"
        C.aggregate(self.custody, artifacts, output)
        value = json.loads(output.read_text())
        self.assertEqual({entry["platform"] for entry in value["archives"]}, C.PLATFORMS)
        for entry in value["archives"]:
            archive = artifacts / f"release-{entry['platform']}" / entry["archive"]
            self.assertEqual(entry["sha256"], C.digest(archive))


if __name__ == "__main__":
    unittest.main()
