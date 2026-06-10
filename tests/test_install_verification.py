#!/usr/bin/env python3
"""Focused tests for installer artifact verification."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest import mock


def load_installer():
    script = Path(__file__).resolve().parents[1] / "scripts" / "install.py"
    spec = importlib.util.spec_from_file_location("install_script", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class InstallerVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = load_installer()

    def test_signature_rejects_untrusted_public_key(self) -> None:
        trusted = next(iter(self.installer.trusted_fingerprints()))
        untrusted = "0" * len(trusted)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            artifact = tmp / "SKILL.md"
            signature = tmp / "SKILL.md.sig"
            key = tmp / "SAORSA_PUBLIC_KEY.asc"
            artifact.write_text("skill", encoding="utf-8")
            signature.write_text("sig", encoding="utf-8")
            key.write_text("key", encoding="utf-8")

            def fake_run(args, **kwargs):
                if "--show-keys" in args:
                    stdout = f"fpr:::::::::{untrusted}:\n"
                    return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
                self.fail("untrusted keys must fail before import or verify")

            with mock.patch.object(self.installer.subprocess, "run", fake_run):
                self.assertFalse(
                    self.installer.verify_signature(artifact, signature, key)
                )

    def test_signature_requires_trusted_validsig(self) -> None:
        trusted = next(iter(self.installer.trusted_fingerprints()))
        untrusted = "0" * len(trusted)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            artifact = tmp / "SKILL.md"
            signature = tmp / "SKILL.md.sig"
            key = tmp / "SAORSA_PUBLIC_KEY.asc"
            artifact.write_text("skill", encoding="utf-8")
            signature.write_text("sig", encoding="utf-8")
            key.write_text("key", encoding="utf-8")

            def fake_run(args, **kwargs):
                if "--show-keys" in args:
                    stdout = f"fpr:::::::::{trusted}:\n"
                    return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
                if "--import" in args:
                    return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
                if "--verify" in args:
                    stdout = f"[GNUPG:] VALIDSIG {untrusted} 0 0 0 0 0 0 0 0\n"
                    return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
                self.fail(f"unexpected gpg invocation: {args}")

            with mock.patch.object(self.installer.subprocess, "run", fake_run):
                self.assertFalse(
                    self.installer.verify_signature(artifact, signature, key)
                )

    def test_daemon_archive_is_not_extracted_when_signature_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            key = tmp / "SAORSA_PUBLIC_KEY.asc"
            key.write_text("key", encoding="utf-8")
            daemon_dir = tmp / "bin"

            def fake_urlretrieve(url, dest):
                dest = Path(dest)
                if url.endswith(".tar.gz"):
                    with tarfile.open(dest, "w:gz") as archive:
                        data = b"daemon"
                        info = tarfile.TarInfo("x0x-linux-x64-gnu/x0xd")
                        info.size = len(data)
                        archive.addfile(info, BytesIO(data))
                else:
                    dest.write_text("sig", encoding="utf-8")

            with mock.patch.object(self.installer, "detect_platform", return_value="linux-x64-gnu"), \
                 mock.patch.object(self.installer.urllib.request, "urlretrieve", fake_urlretrieve), \
                 mock.patch.object(self.installer, "verify_signature", return_value=False), \
                 mock.patch.object(self.installer, "DAEMON_INSTALL_DIR", daemon_dir):
                self.installer.install_daemon(key)

            self.assertFalse((daemon_dir / "x0xd").exists())

    def test_failed_skill_verification_preserves_existing_install(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            install_dir = Path(tmpdir) / "install"
            install_dir.mkdir()
            skill = install_dir / "SKILL.md"
            skill.write_text("trusted skill", encoding="utf-8")
            cwd = Path.cwd()

            def fake_download(url, dest):
                Path(dest).write_text(f"downloaded from {url}", encoding="utf-8")

            with mock.patch.object(self.installer, "INSTALL_DIR", install_dir), \
                 mock.patch.object(self.installer, "check_gpg", return_value=True), \
                 mock.patch.object(self.installer, "download_file", fake_download), \
                 mock.patch.object(self.installer, "verify_signature", return_value=False), \
                 mock.patch.object(self.installer, "install_daemon") as install_daemon:
                try:
                    with self.assertRaises(SystemExit):
                        self.installer.main()
                finally:
                    os.chdir(cwd)

            self.assertEqual(skill.read_text(encoding="utf-8"), "trusted skill")
            install_daemon.assert_not_called()


if __name__ == "__main__":
    unittest.main()
