#!/usr/bin/env python3
"""Focused regression tests for scripts/install.sh."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_install_manifest_verify import build_installer_tools

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "scripts" / "install.sh"
PLATFORM = "linux-x64-gnu"
TARGET_TRIPLE = "x86_64-unknown-linux-gnu"


def installer_tools(tmp: Path) -> Path:
    """The PATH half next to each test's fake binaries: exactly the tools
    scripts/install.sh resolves from PATH (see
    test_install_manifest_verify.build_installer_tools) plus python3, which
    the fake sleep delegates to. Never /usr/bin or /bin wholesale: on a host
    with gpg there, the GPG branch (install.sh:212) would demand .asc files
    the fake release does not serve and the install would die before the
    checks these tests pin (Greptile P1 on #1753)."""
    return build_installer_tools(tmp / "installer-tools", extra=("python3",))


def write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)


def fake_uname(path: Path) -> None:
    write_executable(
        path / "uname",
        """#!/usr/bin/env sh
case "$1" in
    -s) echo Linux ;;
    -m) echo x86_64 ;;
    *) exit 1 ;;
esac
""",
    )


def fake_x0x(path: Path, extra_env: dict[str, str] | None = None) -> None:
    """The release's x0x. The --verify-release-manifest probe answers as a
    genuine release binary would (verification itself is covered by
    tests/test_install_manifest_verify.py); every other call logs its args."""
    env_lines = "".join(f'{k}="{v}"\n' for k, v in (extra_env or {}).items())
    write_executable(
        path,
        f"""#!/usr/bin/env sh
{env_lines}if [ "$1" = "--verify-release-manifest" ]; then
    exit 0
fi
printf '%s\\n' "$*" >> "$XOX_CALLS"
""",
    )


def signed_release_files(archive: Path) -> dict[str, bytes]:
    """Downloads a fake release serves per URL: the archive, its sidecar
    checksum, a manifest whose linux-x64-gnu entry carries the archive's
    real SHA-256 (the signature is inert here; see fake_x0x), and the
    GitHub API reply naming the tag the manifest's version and channel
    match (the installer refuses a manifest that names another release)."""
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    manifest = json.dumps(
        {
            "schema_version": 1,
            "version": "0.48.0",
            "channel": "stable",
            "timestamp": 0,
            "assets": [
                {
                    "target": TARGET_TRIPLE,
                    "archive_url": f"http://fixtures/{archive.name}",
                    "archive_sha256": digest,
                    "signature_url": f"http://fixtures/{archive.name}.sig",
                }
            ],
            "skill_url": "",
            "skill_sha256": "0" * 64,
        },
        indent=2,
    ).encode()
    return {
        archive.name: archive.read_bytes(),
        f"{archive.name}.sha256": f"{digest}  {archive.name}\n".encode(),
        "release-manifest.json": manifest,
        "release-manifest.json.sig": b"inert signature bytes",
        "latest.json": b'{"tag_name": "v0.48.0"}\n',
    }


def fake_curl_script(files_dir: Path, archive: Path, health_result: str) -> str:
    """One fake curl serving every release URL with the right bytes: the
    archive, its sidecar checksum, the signed-manifest pair and the
    latest-release API reply from files_dir. `health_result` is the
    fallback for API GETs."""
    return f"""#!/usr/bin/env sh
OUT=""
URL=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) shift; OUT="$1" ;;
        http*) URL="$1" ;;
    esac
    shift
done
if [ -n "$OUT" ]; then
    case "$URL" in
        *api.github.com/repos/*releases/latest) cat "{files_dir / 'latest.json'}" > "$OUT"; exit 0 ;;
        *release-manifest.json.sig) cat "{files_dir / 'release-manifest.json.sig'}" > "$OUT"; exit 0 ;;
        *release-manifest.json) cat "{files_dir / 'release-manifest.json'}" > "$OUT"; exit 0 ;;
        *.sha256) cat "{files_dir / (archive.name + '.sha256')}" > "$OUT"; exit 0 ;;
        *) cat "{archive}" > "$OUT"; exit 0 ;;
    esac
fi
{health_result}
"""


class InstallShellAutostartTests(unittest.TestCase):
    def test_named_autostart_forwards_name_to_x0x(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            fake_bin = tmp / "fake-bin"
            archive_dir = tmp / "archive" / f"x0x-{PLATFORM}"
            home = tmp / "home"
            data_home = tmp / "data"
            calls = tmp / "x0x-calls.log"
            daemon_calls = tmp / "x0xd-calls.log"
            archive = tmp / f"x0x-{PLATFORM}.tar.gz"

            fake_bin.mkdir()
            archive_dir.mkdir(parents=True)
            home.mkdir()

            fake_uname(fake_bin)

            write_executable(
                archive_dir / "x0xd",
                """#!/usr/bin/env sh
{
    printf '%s\\n' "$0"
    printf '%s\\n' "$#"
    for arg do
        printf '%s\\n' "$arg"
    done
} >> "$XOXD_CALLS"
NAME=""
while [ $# -gt 0 ]; do
    case "$1" in
        --name) shift; NAME="$1" ;;
    esac
    shift
done
if [ -n "$NAME" ]; then
    DIR="${XDG_DATA_HOME:-$HOME/.local/share}/x0x-$NAME"
else
    DIR="${XDG_DATA_HOME:-$HOME/.local/share}/x0x"
fi
mkdir -p "$DIR"
printf '%s\\n' "127.0.0.1:65535" > "$DIR/api.port"
""",
            )

            fake_x0x(archive_dir / "x0x")

            with tarfile.open(archive, "w:gz") as tar:
                tar.add(archive_dir / "x0xd", arcname=f"x0x-{PLATFORM}/x0xd")
                tar.add(archive_dir / "x0x", arcname=f"x0x-{PLATFORM}/x0x")

            files_dir = tmp / "files"
            files_dir.mkdir()
            for name, data in signed_release_files(archive).items():
                (files_dir / name).write_bytes(data)

            write_executable(
                fake_bin / "curl",
                fake_curl_script(
                    files_dir,
                    archive,
                    """case "$URL" in
    */health) printf '%s\\n' '{"ok":true}' ;;
    */agent) printf '%s\\n' '{}' ;;
    *) exit 1 ;;
esac
""",
                ),
            )

            env = os.environ.copy()
            env.update(
                {
                    "HOME": str(home),
                    "XDG_DATA_HOME": str(data_home),
                    "PATH": f"{fake_bin}{os.pathsep}{installer_tools(tmp)}",
                    "TMPDIR": str(tmp),
                    "XOX_CALLS": str(calls),
                    "XOXD_CALLS": str(daemon_calls),
                }
            )

            result = subprocess.run(
                ["sh", str(INSTALL_SH), "--name", "alice", "--autostart"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=20,
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(
                calls.read_text(encoding="utf-8").splitlines(),
                ["--name alice autostart"],
            )
            self.assertEqual(
                daemon_calls.read_text(encoding="utf-8").splitlines(),
                [str(home / ".local" / "bin" / "x0xd"), "2", "--name", "alice"],
            )

    def test_invalid_name_with_option_text_is_rejected_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            home = tmp / "home"
            data_home = tmp / "data"
            home.mkdir()

            env = os.environ.copy()
            env.update(
                {
                    "HOME": str(home),
                    "XDG_DATA_HOME": str(data_home),
                    "PATH": str(installer_tools(tmp)),
                    "TMPDIR": str(tmp),
                }
            )

            result = subprocess.run(
                ["sh", str(INSTALL_SH), "--name", "alice --api-port 12345"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=20,
            )

            output = result.stderr + result.stdout
            self.assertNotEqual(result.returncode, 0, output)
            self.assertIn("instance name must start with alphanumeric", output)
            self.assertNotIn("Downloading", output)

    def test_missing_daemon_binary_fails_before_starting_stale_daemon(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            fake_bin = tmp / "fake-bin"
            archive_dir = tmp / "archive" / f"x0x-{PLATFORM}"
            home = tmp / "home"
            data_home = tmp / "data"
            install_bin = home / ".local" / "bin"
            archive = tmp / f"x0x-{PLATFORM}.tar.gz"
            nohup_calls = tmp / "nohup-calls.log"

            fake_bin.mkdir()
            archive_dir.mkdir(parents=True)
            install_bin.mkdir(parents=True)

            fake_uname(fake_bin)

            write_executable(
                fake_bin / "nohup",
                """#!/usr/bin/env sh
printf '%s\\n' "$*" >> "$NOHUP_CALLS"
exit 0
""",
            )

            write_executable(
                fake_bin / "sleep",
                """#!/usr/bin/env sh
:
""",
            )

            fake_x0x(archive_dir / "x0x")

            stale_cli = """#!/usr/bin/env sh
exit 0
"""
            stale_daemon = """#!/usr/bin/env sh
printf '%s\\n' stale-daemon
"""
            write_executable(install_bin / "x0x", stale_cli)
            write_executable(install_bin / "x0xd", stale_daemon)

            with tarfile.open(archive, "w:gz") as tar:
                tar.add(archive_dir / "x0x", arcname=f"x0x-{PLATFORM}/x0x")

            files_dir = tmp / "files"
            files_dir.mkdir()
            for name, data in signed_release_files(archive).items():
                (files_dir / name).write_bytes(data)

            write_executable(fake_bin / "curl", fake_curl_script(files_dir, archive, "exit 1"))

            env = os.environ.copy()
            env.update(
                {
                    "HOME": str(home),
                    "XDG_DATA_HOME": str(data_home),
                    "PATH": f"{fake_bin}{os.pathsep}{installer_tools(tmp)}",
                    "TMPDIR": str(tmp),
                    "NOHUP_CALLS": str(nohup_calls),
                }
            )

            result = subprocess.run(
                ["sh", str(INSTALL_SH)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=20,
            )

            output = result.stderr + result.stdout
            self.assertNotEqual(result.returncode, 0, output)
            self.assertIn("release archive missing executable x0xd", output)
            self.assertNotIn("Installed:", output)
            self.assertNotIn("Starting:", output)
            self.assertFalse(nohup_calls.exists())
            self.assertEqual(
                (install_bin / "x0x").read_text(encoding="utf-8"),
                stale_cli,
            )
            self.assertEqual(
                (install_bin / "x0xd").read_text(encoding="utf-8"),
                stale_daemon,
            )

    def test_unhealthy_daemon_fails_install(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            fake_bin = tmp / "fake-bin"
            archive_dir = tmp / "archive" / f"x0x-{PLATFORM}"
            home = tmp / "home"
            data_home = tmp / "data"
            archive = tmp / f"x0x-{PLATFORM}.tar.gz"

            fake_bin.mkdir()
            archive_dir.mkdir(parents=True)
            home.mkdir()

            fake_uname(fake_bin)

            write_executable(
                fake_bin / "sleep",
                """#!/usr/bin/env sh
python3 -c 'import time; time.sleep(0.01)'
""",
            )

            write_executable(
                archive_dir / "x0xd",
                """#!/usr/bin/env sh
DIR="${XDG_DATA_HOME:-$HOME/.local/share}/x0x"
mkdir -p "$DIR"
printf '%s\\n' "127.0.0.1:65535" > "$DIR/api.port"
""",
            )

            fake_x0x(archive_dir / "x0x")

            with tarfile.open(archive, "w:gz") as tar:
                tar.add(archive_dir / "x0xd", arcname=f"x0x-{PLATFORM}/x0xd")
                tar.add(archive_dir / "x0x", arcname=f"x0x-{PLATFORM}/x0x")

            files_dir = tmp / "files"
            files_dir.mkdir()
            for name, data in signed_release_files(archive).items():
                (files_dir / name).write_bytes(data)

            write_executable(fake_bin / "curl", fake_curl_script(files_dir, archive, "exit 7"))

            env = os.environ.copy()
            env.update(
                {
                    "HOME": str(home),
                    "XDG_DATA_HOME": str(data_home),
                    "PATH": f"{fake_bin}{os.pathsep}{installer_tools(tmp)}",
                    "TMPDIR": str(tmp),
                }
            )

            result = subprocess.run(
                ["sh", str(INSTALL_SH)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=20,
            )

            output = result.stderr + result.stdout
            self.assertNotEqual(result.returncode, 0, output)
            self.assertIn("Timeout waiting for healthy daemon", output)
            self.assertNotIn("x0x is running", output)


if __name__ == "__main__":
    unittest.main()
