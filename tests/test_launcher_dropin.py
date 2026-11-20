#!/usr/bin/env python3
"""Tests for .deployment/launcher-dropin.py (#1378)."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".deployment" / "launcher-dropin.py"
TESTNET_UNIT = ROOT / ".deployment" / "systemd" / "x0xd-testnet.service"


class LauncherDropinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.data_root = self.tmp / "home" / ".local" / "share" / "x0x-testnet"
        self.data_root.mkdir(parents=True, mode=0o700)
        self.binary = self.tmp / "x0xd-testnet"
        self.log = self.tmp / "x0xd.log"
        self.write_daemon(f'    data_dir: "{self.data_root}",')
        self.launcher = str(self.tmp / "x0x-launcher")
        self.unit = self.tmp / "x0xd-testnet.service"
        self.unit.write_text(
            TESTNET_UNIT.read_text(encoding="utf-8").replace(
                "/opt/x0x/x0xd-testnet", str(self.binary)
            ),
            encoding="utf-8",
        )

    def write_daemon(self, data_dir_line: str, status: int = 0) -> None:
        self.binary.write_text(
            "#!/bin/sh\n"
            f'echo "HOME=$HOME $*" > "{self.log}"\n'
            "echo 'Configuration is valid'\n"
            "echo 'DaemonConfig {'\n"
            f"echo '{data_dir_line}'\n"
            "echo '}'\n"
            f"exit {status}\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)

    def run_script(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        options = {
            "--unit": str(self.unit),
            "--binary": str(self.binary),
            "--launcher": self.launcher,
            "--instance": "testnet",
            "--home": str(self.tmp / "home"),
            "--owner": str(os.getuid()),
            "--user": "root" if os.getuid() == 0 else os.environ.get("USER", "nobody"),
        }
        options.update(overrides)
        argv = [sys.executable, "-I", str(SCRIPT)]
        for key, value in options.items():
            argv += [key, value]
        return subprocess.run(argv, capture_output=True, text=True, check=False)

    def refused(self, why: str, **overrides: str) -> str:
        result = self.run_script(**overrides)
        self.assertEqual(result.returncode, 1, f"{why}: {result.stdout}")
        self.assertEqual(result.stdout, "", why)
        return result.stderr

    def test_renders_the_trial_form_from_the_unit_and_the_daemon(self) -> None:
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines()[2:],
            [
                "[Service]",
                "ExecStart=",
                f"ExecStart={self.launcher} --host-root {self.data_root} --instance testnet "
                f"-- {self.binary} --name testnet --config /etc/x0x/config-testnet.toml",
                "Restart=always",
                "RestartPreventExitStatus=64 78",
                "KillMode=mixed",
                "TimeoutStopSec=60",
            ],
        )
        self.assertEqual(
            self.log.read_text(encoding="utf-8").strip(),
            f"HOME={self.tmp / 'home'} --name testnet --config /etc/x0x/config-testnet.toml "
            "--check",
        )

    def test_the_host_root_is_canonical(self) -> None:
        link = self.tmp / "link"
        link.symlink_to(self.data_root)
        self.write_daemon(f'    data_dir: "{link}",')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"--host-root {self.data_root} ", result.stdout)

    def test_refuses_what_the_launcher_would_refuse(self) -> None:
        self.assertIn("instance id", self.refused("bad instance", **{"--instance": ".."}))
        self.assertIn(
            "not named x0x-launcher",
            self.refused("wrong launcher", **{"--launcher": str(self.tmp / "other")}),
        )
        self.assertIn(
            "not " + str(self.tmp / "elsewhere"),
            self.refused("unit runs another binary", **{"--binary": str(self.tmp / "elsewhere")}),
        )
        self.assertIn("owned by uid", self.refused("wrong owner", **{"--owner": "4242"}))
        self.data_root.chmod(0o770)
        self.assertIn("writable by group", self.refused("group-writable root"))
        self.data_root.chmod(0o700)
        self.write_daemon(f'    data_dir: "{self.tmp / "missing"}",')
        self.assertIn("start x0xd once first", self.refused("missing root"))
        self.write_daemon(f'    data_dir: "{self.data_root}",', status=1)
        self.assertIn("--check` failed", self.refused("daemon check fails"))
        self.write_daemon("    nothing: 1,")
        self.assertIn("exactly one data_dir", self.refused("no data_dir"))

    def test_refuses_a_unit_that_needs_systemd_quoting(self) -> None:
        for exec_start in (
            f'ExecStart={self.binary} --name "test net"',
            f"ExecStart={self.binary} --name $NAME",
            f"ExecStart={self.binary} --name %i",
        ):
            self.unit.write_text(f"[Service]\n{exec_start}\n", encoding="utf-8")
            self.assertIn("quoting", self.refused(exec_start))
        self.unit.write_text(
            f"[Service]\nExecStart={self.binary}\nExecStart={self.binary}\n", encoding="utf-8"
        )
        self.assertIn("exactly one", self.refused("two ExecStart lines"))


if __name__ == "__main__":
    unittest.main()
