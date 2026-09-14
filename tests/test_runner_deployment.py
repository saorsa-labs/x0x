import shutil
import subprocess
import sys
import tempfile
import unittest
import os
from pathlib import Path


class RunnerDeploymentTests(unittest.TestCase):
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
