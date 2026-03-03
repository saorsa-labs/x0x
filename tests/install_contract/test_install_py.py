import json
import os
import platform
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "install.py"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SUCCESS_KEYS = {
    "status",
    "x0xd_path",
    "skill_path",
    "gpg_verified",
    "platform",
    "version",
}


def detect_platform_tag() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "linux":
        if machine in ("x86_64", "amd64"):
            return "linux-x64-gnu"
        if machine in ("aarch64", "arm64"):
            return "linux-arm64-gnu"
    elif system == "darwin":
        if machine in ("arm64", "aarch64"):
            return "macos-arm64"
        if machine in ("x86_64", "amd64"):
            return "macos-x64"
    raise RuntimeError(f"Unsupported test platform: {system}/{machine}")


def create_release_fixture(base_dir: Path, plat: str) -> Path:
    release_dir = base_dir / "release"
    release_dir.mkdir(parents=True, exist_ok=True)

    (release_dir / "SKILL.md").write_text(
        (FIXTURES_DIR / "SKILL.md").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (release_dir / "SKILL.md.sig").write_text("not-used-in-tests\n", encoding="utf-8")
    (release_dir / "SAORSA_PUBLIC_KEY.asc").write_text(
        "not-used-in-tests\n", encoding="utf-8"
    )

    archive_name = f"x0x-{plat}.tar.gz"
    archive_path = release_dir / archive_name
    with tempfile.TemporaryDirectory() as td:
        staging = Path(td) / f"x0x-{plat}"
        staging.mkdir(parents=True, exist_ok=True)
        daemon = staging / "x0xd"
        daemon.write_text(
            (FIXTURES_DIR / "x0xd").read_text(encoding="utf-8"), encoding="utf-8"
        )
        daemon.chmod(daemon.stat().st_mode | stat.S_IXUSR)
        with tarfile.open(archive_path, "w:gz") as tf:
            tf.add(staging / "x0xd", arcname=f"x0x-{plat}/x0xd")

    return release_dir


class InstallPyContractTests(unittest.TestCase):
    def run_script(self, *args: str, env_overrides=None):
        env = os.environ.copy()
        if env_overrides:
            env.update(env_overrides)
        return subprocess.run(
            ["python3", str(SCRIPT_PATH), *args],
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

    def test_non_interactive_success_contract(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            plat = detect_platform_tag()
            release_dir = create_release_fixture(root, plat)
            install_dir = root / "install"
            bin_dir = root / "bin"

            proc = self.run_script(
                env_overrides={
                    "X0X_RELEASE_URL": release_dir.as_uri(),
                    "X0X_INSTALL_DIR": str(install_dir),
                    "X0X_BIN_DIR": str(bin_dir),
                    "X0X_SKIP_GPG": "1",
                }
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["status"], "ok")
            self.assertFalse(payload["gpg_verified"])
            self.assertTrue(SUCCESS_KEYS.issubset(payload.keys()))
            self.assertIn("Downloading SKILL.md", proc.stderr)
            self.assertNotIn("Continue without verification", proc.stdout + proc.stderr)
            self.assertNotIn("(y/N)", proc.stdout + proc.stderr)

    def test_invalid_argument_contract(self):
        proc = self.run_script("--nope")
        self.assertNotEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["code"], "invalid_argument")

    def test_already_installed_failure_contract(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            plat = detect_platform_tag()
            release_dir = create_release_fixture(root, plat)
            install_dir = root / "install"
            bin_dir = root / "bin"
            bin_dir.mkdir(parents=True, exist_ok=True)
            (bin_dir / "x0xd").write_text("existing\n", encoding="utf-8")

            proc = self.run_script(
                env_overrides={
                    "X0X_RELEASE_URL": release_dir.as_uri(),
                    "X0X_INSTALL_DIR": str(install_dir),
                    "X0X_BIN_DIR": str(bin_dir),
                    "X0X_SKIP_GPG": "1",
                }
            )

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["status"], "error")
            self.assertEqual(payload["code"], "already_installed")
            self.assertEqual(payload["x0xd_path"], str(bin_dir / "x0xd"))

    def test_success_keys_parity_with_shell_contract(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            plat = detect_platform_tag()
            release_dir = create_release_fixture(root, plat)
            install_dir = root / "install"
            bin_dir = root / "bin"

            proc = self.run_script(
                env_overrides={
                    "X0X_RELEASE_URL": release_dir.as_uri(),
                    "X0X_INSTALL_DIR": str(install_dir),
                    "X0X_BIN_DIR": str(bin_dir),
                    "X0X_SKIP_GPG": "1",
                }
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(set(payload.keys()), SUCCESS_KEYS)


if __name__ == "__main__":
    unittest.main()
