import shutil
import subprocess
import sys
import tempfile
import unittest
import os
from pathlib import Path


class RunnerDeploymentTests(unittest.TestCase):
    def run_deploy_with_fake_ssh(self, network: str) -> str:
        tests_dir = Path(__file__).parent
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_tests = root / "tests"
            (fixture_tests / "lib").mkdir(parents=True)
            (fixture_tests / "runners").mkdir()
            for relative in (
                "e2e_deploy.sh",
                "x0x-network.sh",
                "result_framing.py",
                "runners/install_runner_bundle.sh",
                "runners/x0x_test_runner.py",
                "runners/x0x-test-runner.service",
            ):
                destination = fixture_tests / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(tests_dir / relative, destination)
            (root / "Cargo.toml").write_text(
                '[package]\nname = "runner-deploy-fixture"\nversion = "9.8.7"\n'
            )
            binary = root / "target/x86_64-unknown-linux-gnu/release/x0xd"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"offline-fixture")
            (fixture_tests / "lib/deploy_upload.sh").write_text(
                "x0x_upload_binary() { :; }\n"
                "x0x_scan_and_repush_stragglers() { STRAGGLERS_REPUSHED=0; }\n"
            )
            bin_dir = root / "bin"
            bin_dir.mkdir()
            (bin_dir / "sleep").write_text("#!/bin/sh\nexit 0\n")
            remote_log = root / "remote.log"
            fake_ssh = bin_dir / "fake-ssh"
            fake_ssh.write_text(
                """#!/usr/bin/env bash
set -eu
cmd="${*: -1}"
payload=$(cat || true)
printf 'COMMAND:%s\\nPAYLOAD-BEGIN\\n%s\\nPAYLOAD-END\\n' "$cmd" "$payload" >> "$X0X_FAKE_REMOTE_LOG"
case "$cmd" in
  true) ;;
  *"systemctl is-active"*) echo active ;;
  *"api-token"*) echo fixture-token ;;
  *"/health"*) printf '{"ok":true,"version":"9.8.7"}\\n' ;;
  *"/network/status"*) printf '{"connected_peers":5}\\n' ;;
esac
"""
            )
            for executable in (fixture_tests / "e2e_deploy.sh", bin_dir / "sleep", fake_ssh):
                executable.chmod(0o755)
            env = dict(
                os.environ,
                PATH=f"{bin_dir}:{os.environ['PATH']}",
                SKIP_BUILD="1",
                CONFIGURE_LOG_CAPS="0",
                DEPLOY_RUNNER="1",
                X0X_DEPLOY_SSH_CMD=str(fake_ssh),
                X0X_FAKE_REMOTE_LOG=str(remote_log),
            )
            completed = subprocess.run(
                ["bash", "tests/e2e_deploy.sh", "--network", network],
                cwd=root,
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            return remote_log.read_text()

    @staticmethod
    def rendered_unit(remote: str, unit_name: str) -> str:
        marker = f"COMMAND:cat > /tmp/{unit_name}.codex\nPAYLOAD-BEGIN\n"
        return remote.split(marker, 1)[1].split("\nPAYLOAD-END\n", 1)[0]

    def test_test_network_deploy_installs_and_starts_testnet_runner(self) -> None:
        remote = self.run_deploy_with_fake_ssh("test")
        unit = self.rendered_unit(remote, "x0x-test-runner-testnet.service")
        self.assertIn("After=x0xd-testnet.service", unit)
        self.assertIn("Wants=x0xd-testnet.service", unit)
        self.assertNotIn("After=x0xd.service", unit)
        self.assertNotIn("Wants=x0xd.service", unit)
        self.assertIn("EnvironmentFile=/etc/x0x-test-runner-testnet.env", unit)
        self.assertIn("ExecStart=/usr/local/bin/x0x-test-runner-testnet.py", unit)
        self.assertIn("/tmp/x0x-result-framing.py.codex / testnet", remote)
        self.assertIn("systemctl restart x0x-test-runner-testnet.service", remote)
        self.assertNotIn("x0x-test-runner-test.py", remote)

    def test_prod_deploy_keeps_prod_runner_dependencies(self) -> None:
        remote = self.run_deploy_with_fake_ssh("prod")
        unit = self.rendered_unit(remote, "x0x-test-runner.service")
        self.assertIn("After=x0xd.service", unit)
        self.assertIn("Wants=x0xd.service", unit)
        self.assertNotIn("After=x0xd-testnet.service", unit)
        self.assertNotIn("Wants=x0xd-testnet.service", unit)
        self.assertIn("EnvironmentFile=/etc/x0x-test-runner.env", unit)
        self.assertIn("ExecStart=/usr/local/bin/x0x-test-runner-prod.py", unit)
        self.assertIn("systemctl restart x0x-test-runner.service", remote)

    def test_installed_runner_finds_shared_framing_helper(self) -> None:
        tests_dir = Path(__file__).parent
        with tempfile.TemporaryDirectory() as tmp:
            installer = tests_dir / "runners" / "install_runner_bundle.sh"
            completed = subprocess.run(
                [str(installer), str(tests_dir / "runners" / "x0x_test_runner.py"),
                 str(tests_dir / "result_framing.py"), tmp, "testnet"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            runner = Path(tmp) / "usr/local/bin/x0x-test-runner-testnet.py"
            completed = subprocess.run(
                [sys.executable, str(runner), "--help"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIn("x0x mesh-relay test runner", completed.stdout)

    def test_failed_staging_cannot_replace_runnable_bundle(self) -> None:
        tests_dir = Path(__file__).parent
        with tempfile.TemporaryDirectory() as tmp:
            installer = tests_dir / "runners" / "install_runner_bundle.sh"
            runner_source = tests_dir / "runners" / "x0x_test_runner.py"
            helper_source = tests_dir / "result_framing.py"
            args = [str(installer), str(runner_source), str(helper_source), tmp, "prod"]
            self.assertEqual(0, subprocess.run(args, check=False).returncode)
            runnable = Path(tmp) / "usr/local/bin/x0x-test-runner-prod.py"
            before = runnable.resolve()
            missing = subprocess.run(
                [str(installer), str(runner_source), str(Path(tmp) / "missing.py"),
                 tmp, "prod"],
                capture_output=True, check=False,
            )
            self.assertEqual(2, missing.returncode)
            self.assertEqual(before, runnable.resolve())
            env = dict(os.environ, X0X_INSTALL_FAIL_AFTER_RUNNER="1")
            failed = subprocess.run(args, env=env, capture_output=True, check=False)
            self.assertEqual(70, failed.returncode)
            self.assertEqual(before, runnable.resolve())

            changed_runner = Path(tmp) / "changed-runner.py"
            shutil.copy2(runner_source, changed_runner)
            changed_runner.write_text(changed_runner.read_text() + "\n# bundle change\n")
            changed_args = [str(installer), str(changed_runner), str(helper_source), tmp, "prod"]
            self.assertEqual(0, subprocess.run(changed_args, check=False).returncode)
            self.assertNotEqual(before, runnable.resolve())


if __name__ == "__main__":
    unittest.main()
