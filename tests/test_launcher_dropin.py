#!/usr/bin/env python3
"""Tests for .deployment/launcher-dropin.py and `install.sh --launcher` (#1378)."""

from __future__ import annotations

import importlib.util
import json
import os
import pwd
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / ".deployment"
SCRIPT = DEPLOYMENT / "launcher-dropin.py"
TESTNET_UNIT = DEPLOYMENT / "systemd" / "x0xd-testnet.service"
ME = pwd.getpwuid(os.getuid())

spec = importlib.util.spec_from_file_location("launcher_dropin", SCRIPT)
assert spec is not None and spec.loader is not None
dropin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dropin)


def fake_daemon(path: Path, log: Path, data_dir_line: str, status: int = 0) -> None:
    path.write_text(
        "#!/bin/sh\n"
        f'echo "HOME=$HOME $*" > "{log}"\n'
        "echo 'Configuration is valid'\n"
        "echo 'DaemonConfig {'\n"
        f"echo '{data_dir_line}'\n"
        "echo '}'\n"
        f"exit {status}\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.home = self.tmp / "home"
        self.data_root = self.home / ".local" / "share" / "x0x-testnet"
        self.data_root.mkdir(parents=True, mode=0o700)
        self.data_root.chmod(0o700)
        self.binary = self.tmp / "x0xd-testnet"
        self.log = self.tmp / "x0xd.log"
        self.write_daemon(f'    data_dir: "{self.data_root}",')
        self.launcher = str(self.tmp / "x0x-launcher")
        self.unit_text = TESTNET_UNIT.read_text(encoding="utf-8").replace(
            "/opt/x0x/x0xd-testnet", str(self.binary)
        )

    def write_daemon(self, data_dir_line: str, status: int = 0) -> None:
        fake_daemon(self.binary, self.log, data_dir_line, status)

    def render(self, **overrides: object) -> str:
        options: dict[str, object] = {
            "unit_text": self.unit_text,
            "binary": str(self.binary),
            "launcher": self.launcher,
            "instance": "testnet",
            "home": str(self.home),
            "owner": os.getuid(),
            "user": ME.pw_name,
        }
        options.update(overrides)
        return dropin.render(**options)

    def refused(self, why: str, **overrides: object) -> str:
        with self.assertRaises(dropin.Refused, msg=why) as caught:
            self.render(**overrides)
        return str(caught.exception)

    def test_renders_the_trial_form_from_the_unit_and_the_daemon(self) -> None:
        self.assertEqual(
            self.render().splitlines()[2:],
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
            f"HOME={self.home} --name testnet --config /etc/x0x/config-testnet.toml --check",
        )

    def test_the_host_root_is_canonical(self) -> None:
        link = self.tmp / "link"
        link.symlink_to(self.data_root)
        self.write_daemon(f'    data_dir: "{link}",')
        self.assertIn(f"--host-root {self.data_root} ", self.render())

    def test_refuses_what_the_launcher_would_refuse(self) -> None:
        self.assertIn("instance id", self.refused("bad instance", instance=".."))
        self.assertIn(
            "not named x0x-launcher",
            self.refused("wrong launcher", launcher=str(self.tmp / "other")),
        )
        self.assertIn(
            "not " + str(self.tmp / "elsewhere"),
            self.refused("unit runs another binary", binary=str(self.tmp / "elsewhere")),
        )
        self.assertIn("owned by uid", self.refused("wrong owner", owner=4242))
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
            self.assertIn(
                "quoting", self.refused(exec_start, unit_text=f"[Service]\n{exec_start}\n")
            )
        self.assertIn(
            "cannot be split",
            self.refused(
                "unbalanced quote",
                unit_text=f"[Service]\nExecStart={self.binary} --name \"testnet\n",
            ),
        )
        self.assertIn(
            "exactly one",
            self.refused(
                "two ExecStart lines",
                unit_text=f"[Service]\nExecStart={self.binary}\nExecStart={self.binary}\n",
            ),
        )

    def test_as_root_the_check_runs_through_runuser_from_sbin(self) -> None:
        self.assertIn("/usr/sbin", dropin.CHECK_PATH.split(":"))
        runuser = self.tmp / "runuser"
        runuser.write_text(
            '#!/bin/sh\n[ "$1 $2 $3" = "-u alice --" ] || exit 9\nshift 3\nexec "$@"\n',
            encoding="utf-8",
        )
        runuser.chmod(0o755)
        with mock.patch.object(dropin.os, "geteuid", return_value=0):
            with mock.patch.object(dropin.shutil, "which", return_value=str(runuser)) as which:
                self.assertIn("--host-root", self.render(user="alice"))
            which.assert_called_once_with("runuser", path=dropin.CHECK_PATH)
            with mock.patch.object(dropin.shutil, "which", return_value=None):
                self.assertIn("runuser is not in", self.refused("no runuser", user="alice"))


class InstallShTests(unittest.TestCase):
    """Runs `.deployment/install.sh --instance testnet --launcher PATH` from a
    scratch copy of the deployment tree whose manifest points every
    destination into a scratch root; `id -u` and `systemctl` are stubs."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.deploy = self.tmp / "deploy"
        (self.deploy / "systemd").mkdir(parents=True)
        (self.deploy / "config").mkdir()
        for name in ("install.sh", "launcher-dropin.py"):
            shutil.copy2(DEPLOYMENT / name, self.deploy / name)
        shutil.copy2(
            DEPLOYMENT / "config" / "bootstrap-config-testnet.toml",
            self.deploy / "config" / "bootstrap-config-testnet.toml",
        )
        root = self.tmp / "root"
        self.unit = root / "etc" / "systemd" / "system" / "x0xd-testnet.service"
        self.dropin_dir = self.unit.parent / "x0xd-testnet.service.d"
        self.dropin = self.dropin_dir / "30-x0x-launcher.conf"
        self.config = root / "etc" / "x0x" / "config-testnet.toml"
        self.binary = root / "opt" / "x0x" / "x0xd-testnet"
        self.binary.parent.mkdir(parents=True)
        self.log = self.tmp / "x0xd.log"
        self.data_root = self.tmp / "data" / "x0x-testnet"
        self.data_root.mkdir(parents=True, mode=0o700)
        self.data_root.chmod(0o700)
        self.write_daemon(0)
        self.write_unit(f"User={ME.pw_name}")
        manifest = json.loads((DEPLOYMENT / "authority-inventory.json").read_text("utf-8"))
        testnet = next(i for i in manifest["instances"] if i["id"] == "testnet")
        testnet["unit"]["destination"] = str(self.unit)
        testnet["config"]["destination"] = str(self.config)
        testnet["binary"]["destination"] = str(self.binary)
        (self.deploy / "authority-inventory.json").write_text(json.dumps(manifest), "utf-8")
        self.launcher_src = self.tmp / "x0x-launcher-src"
        self.launcher_src.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.stubs = self.tmp / "stubs"
        self.stubs.mkdir()
        self.calls = self.tmp / "systemctl.calls"
        self.stub("id", '[ "$1" = "-u" ] && [ $# -eq 1 ] && { echo 0; exit 0; }\n'
                  'exec /usr/bin/id "$@"\n')
        self.stub("systemctl", f'echo "$*" >> "{self.calls}"\n')

    def stub(self, name: str, body: str) -> None:
        path = self.stubs / name
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(0o755)

    def write_daemon(self, status: int) -> None:
        fake_daemon(self.binary, self.log, f'    data_dir: "{self.data_root}",', status)

    def write_unit(self, extra: str, exec_args: str | None = None) -> None:
        text = TESTNET_UNIT.read_text(encoding="utf-8")
        text = text.replace("/opt/x0x/x0xd-testnet", str(self.binary))
        text = text.replace("/etc/x0x/config-testnet.toml", str(self.config))
        if exec_args is not None:
            text = text.replace("--name testnet", exec_args)
        text = text.replace("[Service]\n", f"[Service]\n{extra}\n")
        (self.deploy / "systemd" / "x0xd-testnet.service").write_text(text, "utf-8")

    def install(self, launcher: bool = True) -> subprocess.CompletedProcess[str]:
        self.calls.unlink(missing_ok=True)
        argv = ["bash", str(self.deploy / "install.sh"), "--instance", "testnet"]
        if launcher:
            argv += ["--launcher", str(self.launcher_src)]
        env = dict(os.environ, PATH=f"{self.stubs}:{os.environ.get('PATH', '/usr/bin:/bin')}")
        return subprocess.run(argv, capture_output=True, text=True, env=env, check=False)

    def systemctl_calls(self) -> list[str]:
        return self.calls.read_text("utf-8").splitlines() if self.calls.exists() else []

    def assert_installed(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        launcher = self.binary.with_name("x0x-launcher")
        self.assertTrue(os.access(launcher, os.X_OK))
        text = self.dropin.read_text("utf-8")
        self.assertIn(
            f"ExecStart={launcher} --host-root {self.data_root} --instance testnet -- "
            f"{self.binary} --name testnet --config {self.config}\n",
            text,
        )
        self.assertEqual(self.dropin.stat().st_mode & 0o777, 0o644)
        self.assertEqual(sorted(p.name for p in self.dropin_dir.iterdir() if p.name.startswith(".")), [])
        self.assertEqual(self.systemctl_calls(), ["daemon-reload", "enable x0xd-testnet"])

    def test_a_fresh_host_and_a_rerun_install_the_drop_in(self) -> None:
        self.assertFalse(self.dropin_dir.exists())
        self.assert_installed(self.install())
        self.assert_installed(self.install())

    def test_the_last_user_outside_the_launcher_drop_in_is_the_units_user(self) -> None:
        self.write_unit("User=nobody")
        self.dropin_dir.mkdir(parents=True)
        (self.dropin_dir / "20-user.conf").write_text(f"[Service]\nUser={ME.pw_name}\n", "utf-8")
        self.dropin.write_text("[Service]\nUser=nobody\n", "utf-8")
        self.assert_installed(self.install())
        (self.dropin_dir / "20-user.conf").unlink()
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("owned by uid", result.stderr)

    def test_a_failed_rerun_leaves_the_direct_job_and_reloads(self) -> None:
        self.assert_installed(self.install())
        self.write_daemon(1)
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("--check` failed", result.stderr)
        self.assertIn("runs x0xd directly", result.stderr)
        self.assertFalse(self.dropin.exists())
        self.assertEqual(self.systemctl_calls(), ["daemon-reload"])

    def test_an_unsplittable_exec_start_is_a_typed_refusal(self) -> None:
        self.write_unit(f"User={ME.pw_name}", exec_args='--name "testnet')
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("error: the unit's ExecStart cannot be split", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(self.dropin.exists())

    def test_an_install_without_the_flag_removes_the_drop_in(self) -> None:
        self.assert_installed(self.install())
        result = self.install(launcher=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.dropin.exists())


if __name__ == "__main__":
    unittest.main()
