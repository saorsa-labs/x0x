#!/usr/bin/env python3
"""Regression tests for the signed-manifest gate in scripts/install.ps1 (#1355).

The Windows counterpart of tests/test_install_manifest_verify.py, run under
real PowerShell (pwsh) on the local machine. Two rules of the installer are
pinned:

  * the release-identity binding: the signed manifest's version and
    channel must name the resolved release tag — stable, non-prerelease,
    same version — or nothing is installed. The stable, non-prerelease
    shape is the updater's rule (src/upgrade/monitor.rs); matching the
    tag is the installer's own addition — the updater never compares the
    manifest version with the tag;
  * an installed x0x.exe that exists but cannot launch stops the install
    instead of falling back to the downloaded binary, which would let an
    unverified download decide its own install.

The script under test is the real one; only its download base URL is patched,
to a fake GitHub release served over local HTTP. The fake release's x0x.exe
delegates the --verify-release-manifest probe to the fixture binary compiled
from src/upgrade/signature.rs (imported from test_install_manifest_verify).

The suite skips itself when pwsh is absent. X0X_PS1_INSTALL_SCRIPT runs
against another copy of the script (used to reproduce the pre-fix red
state). X0X_PS1_TEST_SCRATCH overrides the scratch directory (default: the
issue evidence dir when present, else the system temp).
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from collections.abc import Callable, Iterator
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_install_manifest_verify import build_fixture, manifest_bytes, write_executable

ROOT = Path(__file__).resolve().parents[1]
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
EVIDENCE_PWSH = Path.home() / "x0x-zcode" / "evidence" / "1355" / "tools" / "pwsh" / "pwsh"
EVIDENCE_SCRATCH = Path.home() / "x0x-zcode" / "evidence" / "1355" / "ps1scratch"

TAG = "v0.48.0"
ASSET = "x0x-windows-x64.zip"
WINDOWS_TARGET = "x86_64-pc-windows-msvc"
RELEASE_PATH = f"gh/saorsa-labs/x0x/releases/download/{TAG}"

X0XD_EXE = "#!/bin/sh\nexit 0\n"


def install_script() -> Path:
    override = os.environ.get("X0X_PS1_INSTALL_SCRIPT")
    return Path(override) if override else INSTALL_PS1


def find_pwsh() -> str | None:
    found = shutil.which("pwsh")
    if found:
        return found
    override = os.environ.get("X0X_TEST_PWSH")
    if override and Path(override).exists():
        return override
    # Developer machines without pwsh on PATH: the self-contained copy this
    # run downloaded under its evidence dir. CI runners have pwsh on PATH.
    return str(EVIDENCE_PWSH) if EVIDENCE_PWSH.exists() else None


@contextlib.contextmanager
def scratch_directory() -> Iterator[Path]:
    override = os.environ.get("X0X_PS1_TEST_SCRATCH")
    if override:
        root = Path(override)
        root.mkdir(parents=True, exist_ok=True)
    else:
        root = EVIDENCE_SCRATCH if EVIDENCE_SCRATCH.is_dir() else None
    with tempfile.TemporaryDirectory(dir=root) as tmpdir:
        yield Path(tmpdir)


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass

    def guess_type(self, path: str) -> str:
        # The GitHub API reply has no extension; Invoke-RestMethod needs the
        # JSON content type to deserialize it.
        if path.endswith("/releases/latest"):
            return "application/json"
        return super().guess_type(path)


@contextlib.contextmanager
def serve_release_directory(root: Path) -> Iterator[int]:
    """Serve `root` over HTTP on 127.0.0.1, ephemeral port; yields the port."""
    handler = functools.partial(_QuietHandler, directory=str(root))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def write_release_zip(path: Path, entries: dict[str, str]) -> None:
    """A flat Windows release zip. The entries carry the exec bit (zip
    external_attr), which Expand-Archive honors, so #!/bin/sh scripts work
    as stand-in exes under pwsh on unix."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, script in entries.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.create_system = 3  # Unix
            info.external_attr = 0o755 << 16
            archive.writestr(info, script)


def good_manifest(digest: str) -> bytes:
    return manifest_bytes(digest, target=WINDOWS_TARGET, version="0.48.0", channel="stable")


class InstallPs1VerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("cargo") is None:
            raise unittest.SkipTest("cargo is required to build the manifest fixture")
        cls.pwsh = find_pwsh()
        if cls.pwsh is None:
            if os.environ.get("CI"):
                # A silent skip here leaves CI green while the ps1 gate rots.
                raise AssertionError(
                    "pwsh is required on CI runners (ubuntu-latest ships it)"
                )
            raise unittest.SkipTest(
                "pwsh is required to exercise scripts/install.ps1 "
                "(not on PATH, no X0X_TEST_PWSH, no evidence-dir copy)"
            )
        # Like the sh suite: a failed fixture build fails the suite, it does
        # not skip it.
        cls.verifier, cls.secret = build_fixture()

    def sign(self, manifest: bytes, tmp: Path, secret: Path | None = None) -> bytes:
        """Sign through the fixture binary, as the release pipeline would."""
        scratch = tmp / "signing"
        scratch.mkdir(exist_ok=True)
        manifest_path = scratch / "release-manifest.json"
        signature_path = scratch / "release-manifest.json.sig"
        manifest_path.write_bytes(manifest)
        subprocess.run(
            [
                str(self.verifier),
                "sign",
                str(manifest_path),
                str(secret or self.secret),
                str(signature_path),
            ],
            check=True,
            timeout=60,
        )
        return signature_path.read_bytes()

    def keygen(self, tmp: Path) -> Path:
        """A second throwaway key pair, for signatures the verifier rejects."""
        scratch = tmp / "keys"
        scratch.mkdir(exist_ok=True)
        secret = scratch / "other-secret.bin"
        subprocess.run(
            [str(self.verifier), "keygen", str(scratch / "other.pub"), str(secret)],
            check=True,
            timeout=60,
        )
        return secret

    def release_x0x_exe(self, delegates: bool) -> str:
        """The release's x0x.exe: the probe logs itself, then either runs the
        real verifier, or accepts any manifest (lenient, to isolate which
        verifier the installer chose)."""
        branch = f'    exec "{self.verifier}" verify "$2" "$3"\n' if delegates else "    exit 0\n"
        return (
            "#!/bin/sh\n"
            'if [ "$1" = "--verify-release-manifest" ]; then\n'
            "    printf '%s\\n' probe >> \"$PROBE_CALLS\"\n"
            f"{branch}"
            "fi\n"
            "exit 0\n"
        )

    def installed_probe_exe(self) -> str:
        """An installed x0x.exe like a real v0.48 one: unknown arguments are
        rejected with exit 2, the probe really verifies."""
        return (
            "#!/bin/sh\n"
            'if [ "$1" = "--verify-release-manifest" ] && [ $# -eq 3 ]; then\n'
            "    printf '%s\\n' installed-probe >> \"$PROBE_CALLS\"\n"
            f'    exec "{self.verifier}" verify "$2" "$3"\n'
            "fi\n"
            'echo "error: unexpected argument" >&2\n'
            "exit 2\n"
        )

    def run_installer(
        self,
        tmp: Path,
        manifest: bytes | Callable[[str], bytes],
        *,
        secret: Path | None = None,
        archive_probe_delegates: bool = True,
        pre_install: Callable[[Path], None] | None = None,
        use_version_param: bool = True,
        served_manifest_override: bytes | Callable[[str], bytes] | None = None,
        missing: frozenset[str] = frozenset(),
    ) -> tuple[int, str, Path, Path]:
        """Build the fake Windows release, serve it over local HTTP, patch
        only the script's download base URLs, run it under pwsh, and return
        (exit code, combined output, install dir, probe-calls log).

        `manifest` is fixed bytes or a factory that receives the zip's real
        SHA-256 (the good path needs the manifest to name it, and the bad
        ones must fail on their version or channel, not on the hash).
        `secret` signs with another throwaway key (the wrong-key case).
        With `archive_probe_delegates=False` the release's x0x.exe accepts
        any manifest, isolating the installed-verifier behavior.
        `pre_install` populates the install dir before the run. With
        `use_version_param=False` no -Version is passed and the GitHub
        releases/latest API is served (and patched) instead, exercising the
        script's own tag resolution. `served_manifest_override` replaces the
        manifest bytes after they were signed (the tamper case); `missing`
        names release files the fake origin does not carry."""
        bindir = tmp / "bindir"
        release_dir = tmp / "web" / RELEASE_PATH
        release_dir.mkdir(parents=True, exist_ok=True)
        if pre_install is not None:
            pre_install(bindir)
        pwsh_tmp = tmp / "pwsh-tmp"
        pwsh_tmp.mkdir()
        empty_path = tmp / "empty-path"
        empty_path.mkdir()
        probe_calls = tmp / "probe-calls.log"

        archive = tmp / ASSET
        write_release_zip(
            archive,
            {
                "x0xd.exe": X0XD_EXE,
                "x0x.exe": self.release_x0x_exe(archive_probe_delegates),
            },
        )
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if callable(manifest):
            manifest = manifest(digest)
        signature = self.sign(manifest, tmp, secret)
        served_manifest = manifest
        if served_manifest_override is not None:
            if callable(served_manifest_override):
                served_manifest_override = served_manifest_override(digest)
            served_manifest = served_manifest_override
        (release_dir / ASSET).write_bytes(archive.read_bytes())
        (release_dir / f"{ASSET}.sha256").write_text(f"{digest}  {ASSET}\n", encoding="utf-8")
        if "release-manifest.json" not in missing:
            (release_dir / "release-manifest.json").write_bytes(served_manifest)
        if "release-manifest.json.sig" not in missing:
            (release_dir / "release-manifest.json.sig").write_bytes(signature)
        if not use_version_param:
            api_file = tmp / "web" / "api" / "repos" / "saorsa-labs" / "x0x" / "releases" / "latest"
            api_file.parent.mkdir(parents=True, exist_ok=True)
            api_file.write_text(f'{{"tag_name": "{TAG}"}}\n', encoding="utf-8")

        with serve_release_directory(tmp / "web") as port:
            script = install_script().read_text(encoding="utf-8")
            patched = script.replace("https://github.com/", f"http://127.0.0.1:{port}/gh/")
            if not use_version_param:
                patched = patched.replace(
                    "https://api.github.com/", f"http://127.0.0.1:{port}/api/"
                )
            # $Repo stays a PowerShell variable in the patched text; only
            # check that the real download bases were swapped.
            if "https://github.com/" in patched or f"http://127.0.0.1:{port}/gh/" not in patched:
                raise AssertionError("failed to patch the install.ps1 download base URL")
            if not use_version_param and "https://api.github.com/" in patched:
                raise AssertionError("failed to patch the install.ps1 API base URL")
            script_path = tmp / "install.ps1"
            script_path.write_text(patched, encoding="utf-8")

            env = os.environ.copy()
            for name in ("TMP", "TEMP", "TMPDIR"):
                env[name] = str(pwsh_tmp)
            env.update(
                {
                    "PROBE_CALLS": str(probe_calls),
                    # An empty PATH keeps host gpg out of the script: the GPG
                    # branch downloads files this fake release does not
                    # carry. The probe exes run by absolute path.
                    "PATH": str(empty_path),
                    # Windows-only locations the script probes for Gpg4win;
                    # defined so Join-Path never sees a null under unix pwsh.
                    "LOCALAPPDATA": str(tmp / "localappdata"),
                    "ProgramFiles": str(tmp / "windows-dirs"),
                    "ProgramFiles(x86)": str(tmp / "windows-dirs"),
                }
            )
            for name in [n for n in env if n.lower() in ("http_proxy", "https_proxy", "all_proxy")]:
                del env[name]

            argv = [
                self.pwsh,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
            ]
            if use_version_param:
                argv += ["-Version", TAG]
            argv += ["-InstallDir", str(bindir)]
            result = subprocess.run(
                argv,
                cwd=str(tmp),
                env=env,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=120,
            )
        return result.returncode, result.stdout + result.stderr, bindir, probe_calls

    @staticmethod
    def flat(output: str) -> str:
        """Collapse whitespace and the `|` gutters of pwsh's error display:
        long throw messages wrap across lines, so needles must not depend
        on where the wrap falls. No needle contains a pipe."""
        return " ".join(output.replace("|", " ").split())

    def assert_refused(
        self,
        rc: int,
        output: str,
        bindir: Path,
        probe_calls: Path,
        *needles: str,
        probe_log: list[str] | None = None,
    ) -> None:
        """A refusal: nothing installed, and the probe-calls log equals
        `probe_log` (default: no probe call at all, as the shell suite)."""
        self.assertNotEqual(rc, 0, output)
        for needle in needles:
            self.assertIn(needle, self.flat(output))
        self.assertNotIn("Installed:", output)
        self.assertFalse((bindir / "x0x.exe").exists())
        self.assertFalse((bindir / "x0xd.exe").exists())
        calls = probe_calls.read_text(encoding="utf-8").splitlines() if probe_calls.exists() else []
        self.assertEqual(calls, probe_log if probe_log is not None else [])

    def test_good_signed_manifest_installs(self) -> None:
        with scratch_directory() as tmp:
            rc, output, bindir, probe_calls = self.run_installer(tmp, good_manifest)
            self.assertEqual(rc, 0, output)
            self.assertIn("Manifest version 0.48.0 (stable) matches v0.48.0", self.flat(output))
            self.assertIn("ML-DSA-65 manifest signature verified", output)
            self.assertNotIn("by the installed x0x.exe", output)
            self.assertIn("Installed:", output)
            self.assertTrue((bindir / "x0x.exe").exists())
            self.assertTrue((bindir / "x0xd.exe").exists())
            calls = probe_calls.read_text(encoding="utf-8").splitlines() if probe_calls.exists() else []
            self.assertEqual(calls, ["probe"])

    def test_manifest_version_differs_from_tag(self) -> None:
        with scratch_directory() as tmp:
            rc, output, bindir, probe_calls = self.run_installer(
                tmp,
                lambda digest: manifest_bytes(
                    digest, target=WINDOWS_TARGET, version="0.47.0", channel="stable"
                ),
            )
            self.assert_refused(rc, output, bindir, probe_calls, "but release v0.48.0 was requested")

    def test_manifest_channel_not_stable(self) -> None:
        with scratch_directory() as tmp:
            rc, output, bindir, probe_calls = self.run_installer(
                tmp,
                lambda digest: manifest_bytes(
                    digest, target=WINDOWS_TARGET, version="0.48.0", channel="prerelease"
                ),
            )
            self.assert_refused(
                rc, output, bindir, probe_calls, "stable, non-prerelease releases only"
            )

    def test_manifest_is_prerelease(self) -> None:
        with scratch_directory() as tmp:
            rc, output, bindir, probe_calls = self.run_installer(
                tmp,
                lambda digest: manifest_bytes(
                    digest, target=WINDOWS_TARGET, version="0.48.0-rc1", channel="stable"
                ),
            )
            self.assert_refused(
                rc, output, bindir, probe_calls, "stable, non-prerelease releases only"
            )

    def test_manifest_channel_must_match_case_sensitively(self) -> None:
        # The updater and install.sh compare the channel byte-for-byte;
        # PowerShell's -eq is case-insensitive by default, so "Stable" must
        # still be refused.
        with scratch_directory() as tmp:
            rc, output, bindir, probe_calls = self.run_installer(
                tmp,
                lambda digest: manifest_bytes(
                    digest, target=WINDOWS_TARGET, version="0.48.0", channel="Stable"
                ),
            )
            self.assert_refused(
                rc, output, bindir, probe_calls, "stable, non-prerelease releases only"
            )

    def test_latest_resolution_installs(self) -> None:
        # No -Version: the script resolves the tag itself through the GitHub
        # releases/latest API (patched to the fake origin), and the good
        # manifest for that tag installs.
        with scratch_directory() as tmp:
            rc, output, bindir, probe_calls = self.run_installer(
                tmp, good_manifest, use_version_param=False
            )
            self.assertEqual(rc, 0, output)
            self.assertIn("Release: v0.48.0", output)
            self.assertIn("Manifest version 0.48.0 (stable) matches v0.48.0", self.flat(output))
            self.assertIn("Installed:", output)
            self.assertTrue((bindir / "x0x.exe").exists())
            self.assertTrue((bindir / "x0xd.exe").exists())
            calls = probe_calls.read_text(encoding="utf-8").splitlines() if probe_calls.exists() else []
            self.assertEqual(calls, ["probe"])

    def test_tampered_manifest_refused(self) -> None:
        # The manifest is signed, then different bytes are served: only the
        # ML-DSA signature can catch the swap. The release's own x0x.exe
        # extracts and runs, then rejects the tampered bytes.
        with scratch_directory() as tmp:
            rc, output, bindir, probe_calls = self.run_installer(
                tmp,
                good_manifest,
                served_manifest_override=lambda digest: good_manifest(digest).replace(
                    b'"timestamp": 0', b'"timestamp": 1'
                ),
            )
            self.assert_refused(
                rc,
                output,
                bindir,
                probe_calls,
                "ML-DSA manifest signature FAILED",
                probe_log=["probe"],
            )

    def test_signature_by_wrong_key_refused(self) -> None:
        # The manifest bytes are unchanged but signed by an unrelated key:
        # the release's own x0x.exe runs the check and rejects the key.
        with scratch_directory() as tmp:
            rc, output, bindir, probe_calls = self.run_installer(
                tmp,
                good_manifest,
                secret=self.keygen(tmp),
            )
            self.assert_refused(
                rc,
                output,
                bindir,
                probe_calls,
                "ML-DSA manifest signature FAILED",
                probe_log=["probe"],
            )

    def test_manifest_hash_mismatch_refused(self) -> None:
        # A correctly signed manifest that names another archive's hash is
        # refused by the binding, before extraction.
        with scratch_directory() as tmp:
            rc, output, bindir, probe_calls = self.run_installer(
                tmp, lambda digest: manifest_bytes("4" * 64, target=WINDOWS_TARGET)
            )
            self.assert_refused(rc, output, bindir, probe_calls, "SHA-256 mismatch")

    def test_manifest_without_windows_target_refused(self) -> None:
        # A correctly signed manifest with no windows asset: the hash lookup
        # fails closed, before extraction.
        with scratch_directory() as tmp:
            rc, output, bindir, probe_calls = self.run_installer(
                tmp,
                lambda digest: manifest_bytes(
                    digest, target="x86_64-unknown-linux-gnu", version="0.48.0", channel="stable"
                ),
            )
            self.assert_refused(
                rc,
                output,
                bindir,
                probe_calls,
                "no archive_sha256 entry for x86_64-pc-windows-msvc",
            )

    def test_manifest_target_case_must_match(self) -> None:
        # Pins the -ceq case-sensitive target comparison from commit e9fce0c9:
        # a regression to -eq, which folds case, must stay red.
        with scratch_directory() as tmp:
            rc, output, bindir, probe_calls = self.run_installer(
                tmp,
                lambda digest: manifest_bytes(
                    digest, target="X86_64-PC-WINDOWS-MSVC", version="0.48.0", channel="stable"
                ),
            )
            self.assert_refused(
                rc,
                output,
                bindir,
                probe_calls,
                "no archive_sha256 entry for x86_64-pc-windows-msvc",
            )

    def test_missing_manifest_refused(self) -> None:
        # pwsh's error display for the failed download shows the status
        # code, not the URL, so the 404 is the visible cause.
        with scratch_directory() as tmp:
            rc, output, bindir, probe_calls = self.run_installer(
                tmp,
                good_manifest,
                missing=frozenset({"release-manifest.json"}),
            )
            self.assert_refused(rc, output, bindir, probe_calls, "404")

    def test_missing_signature_refused(self) -> None:
        # The signature download fails like the manifest one: the 404 is the
        # visible cause, and no release byte runs.
        with scratch_directory() as tmp:
            rc, output, bindir, probe_calls = self.run_installer(
                tmp,
                good_manifest,
                missing=frozenset({"release-manifest.json.sig"}),
            )
            self.assert_refused(rc, output, bindir, probe_calls, "404")

    def test_installed_verifier_launch_failure_stops_install(self) -> None:
        with scratch_directory() as tmp:

            def pre_install(bindir: Path) -> None:
                bindir.mkdir(parents=True, exist_ok=True)
                installed = bindir / "x0x.exe"
                installed.write_bytes(b"corrupt, not an executable\n")
                # Not executable: pwsh prints an OS error, leaves
                # $LASTEXITCODE null, and does not terminate.
                installed.chmod(0o644)
                (bindir / "x0xd.exe").write_bytes(b"dummy daemon\n")

            rc, output, bindir, probe_calls = self.run_installer(
                tmp,
                good_manifest,
                archive_probe_delegates=False,
                pre_install=pre_install,
            )
            self.assertNotEqual(rc, 0, output)
            self.assertIn("could not be launched to verify the manifest", self.flat(output))
            self.assertNotIn("Installed:", output)
            # The pre-existing binary is untouched, bytes and mode.
            installed = bindir / "x0x.exe"
            self.assertEqual(installed.read_bytes(), b"corrupt, not an executable\n")
            self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o644)
            self.assertEqual((bindir / "x0xd.exe").read_bytes(), b"dummy daemon\n")
            # The downloaded verifier never ran.
            calls = probe_calls.read_text(encoding="utf-8").splitlines() if probe_calls.exists() else []
            self.assertEqual(calls, [])

    def test_installed_verifier_refusal_blocks_install(self) -> None:
        with scratch_directory() as tmp:
            installed_probe = self.installed_probe_exe()

            def pre_install(bindir: Path) -> None:
                bindir.mkdir(parents=True, exist_ok=True)
                write_executable(bindir / "x0x.exe", installed_probe)

            rc, output, bindir, probe_calls = self.run_installer(
                tmp,
                good_manifest,
                secret=self.keygen(tmp),
                archive_probe_delegates=False,
                pre_install=pre_install,
            )
            self.assertNotEqual(rc, 0, output)
            self.assertIn("ML-DSA manifest signature FAILED", self.flat(output))
            self.assertNotIn("Installed:", output)
            # Nothing was installed over the existing binary, and the
            # downloaded verifier (lenient here) never ran.
            self.assertEqual((bindir / "x0x.exe").read_text(encoding="utf-8"), installed_probe)
            self.assertFalse((bindir / "x0xd.exe").exists())
            calls = probe_calls.read_text(encoding="utf-8").splitlines() if probe_calls.exists() else []
            self.assertEqual(calls, ["installed-probe"])

    def test_pre_probe_installed_exe_falls_back_to_release_exe(self) -> None:
        # Mirrors the shell suite's pre-probe fallback test: an installed
        # x0x.exe from before v0.46.5 rejects the probe argument with exit 2
        # (and never logs), so the installer warns and falls back to the
        # release's own x0x.exe for the check, then completes the install.
        with scratch_directory() as tmp:
            pre_probe = (
                "#!/bin/sh\n"
                'if [ "$1" = "--verify-release-manifest" ]; then\n'
                '    echo "error: unexpected argument" >&2\n'
                "    exit 2\n"
                "fi\n"
                "exit 0\n"
            )

            def pre_install(bindir: Path) -> None:
                bindir.mkdir(parents=True, exist_ok=True)
                write_executable(bindir / "x0x.exe", pre_probe)

            rc, output, bindir, probe_calls = self.run_installer(
                tmp, good_manifest, pre_install=pre_install
            )
            self.assertEqual(rc, 0, output)
            self.assertIn("predates v0.46.5", self.flat(output))
            self.assertIn("ML-DSA-65 manifest signature verified", output)
            self.assertNotIn("by the installed x0x.exe", output)
            self.assertIn("Installed:", output)
            self.assertTrue((bindir / "x0xd.exe").exists())
            # The good release replaces the pre-probe binary, and the
            # release's own x0x.exe did the verifying.
            self.assertNotEqual((bindir / "x0x.exe").read_text(encoding="utf-8"), pre_probe)
            calls = probe_calls.read_text(encoding="utf-8").splitlines() if probe_calls.exists() else []
            self.assertEqual(calls, ["probe"])


if __name__ == "__main__":
    unittest.main()
