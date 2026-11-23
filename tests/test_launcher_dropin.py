#!/usr/bin/env python3
"""Tests for .deployment/launcher-dropin.py and `install.sh --launcher` (#1378)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pwd
import shutil
import subprocess
import sys
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


# The helper's own calls: a reload, then the question to systemd.
HELPER_CALLS = [
    "daemon-reload",
    "show -p LoadState -p FragmentPath -p DropInPaths -p User -p ExecStart -- x0xd-testnet.service",
]


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
            "exec_start": dropin.unit_exec_start(self.unit_text),
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
            self.render().splitlines()[3:],
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

    def test_the_host_root_has_its_parent_resolved_but_is_no_symlink(self) -> None:
        link = self.tmp / "link"
        link.symlink_to(self.data_root.parent)
        self.write_daemon(f'    data_dir: "{link / self.data_root.name}",')
        self.assertIn(f"--host-root {self.data_root} ", self.render())
        # The launcher does not follow a symlinked data directory (#1378).
        final = self.tmp / "final-link"
        final.symlink_to(self.data_root)
        self.write_daemon(f'    data_dir: "{final}",')
        self.assertIn("is a symlink", self.refused("symlinked data root"))

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

    def test_refuses_a_config_path_the_check_cannot_resolve(self) -> None:
        for args in (["--config", "rel.toml"], ["--config=/etc/x0x/c.toml"], ["--config"]):
            self.assertIn(
                "--config",
                self.refused(" ".join(args), exec_start=[str(self.binary), *args]),
            )

    def exec_refused(self, why: str, *texts: str) -> str:
        with self.assertRaises(dropin.Refused, msg=why) as caught:
            dropin.unit_exec_start(*texts)
        return str(caught.exception)

    def test_refuses_a_unit_that_needs_systemd_quoting(self) -> None:
        for exec_start in (
            f'ExecStart={self.binary} --name "test net"',
            f"ExecStart={self.binary} --name $NAME",
            f"ExecStart={self.binary} --name %i",
        ):
            self.assertIn("quoting", self.exec_refused(exec_start, f"[Service]\n{exec_start}\n"))
        self.assertIn(
            "cannot be split",
            self.exec_refused(
                "unbalanced quote", f"[Service]\nExecStart={self.binary} --name \"testnet\n"
            ),
        )
        self.assertIn(
            "exactly one",
            self.exec_refused(
                "two ExecStart lines",
                f"[Service]\nExecStart={self.binary}\nExecStart={self.binary}\n",
            ),
        )

    def test_exec_start_and_user_follow_systemds_override_rules(self) -> None:
        unit = f"[Service]\nUser=a\nExecStart={self.binary} --name one\n"
        override = f"[Service]\n# comment\nExecStart=\nExecStart={self.binary} \\\n  --name two\n"
        self.assertEqual(dropin.unit_exec_start(unit, override), [str(self.binary), "--name", "two"])
        self.assertIn("exactly one", self.exec_refused("reset only", unit, "[Service]\nExecStart=\n"))
        self.assertIn(
            "exactly one",
            self.exec_refused("appended", unit, f"[Service]\nExecStart={self.binary}\n"),
        )
        self.assertEqual(dropin.unit_user(unit, "[Service]\nUser=b\n"), "b")
        self.assertEqual(dropin.unit_user(unit, "[Service]\nUser=\n"), "root")
        self.assertEqual(dropin.unit_user(unit, "[Unit]\nUser=c\n"), "a")

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


class UnitFileTests(unittest.TestCase):
    """The file-based reading of the effective unit, over a search path of
    scratch directories in systemd's precedence order."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.transient = self.tmp / "run" / "systemd" / "transient"
        self.etc = self.tmp / "etc" / "systemd" / "system"
        self.run_dir = self.tmp / "run" / "systemd" / "system"
        self.usr = self.tmp / "usr" / "lib" / "systemd" / "system"
        for directory in (self.transient, self.etc, self.run_dir, self.usr):
            directory.mkdir(parents=True)
        search = (str(self.transient), dropin.ETC_UNITS, str(self.run_dir), str(self.usr))
        for name, value in (
            ("SEARCH_PATH", search),
            ("SYSTEMD_RUNTIME", str(self.tmp / "no-systemd")),
        ):
            patcher = mock.patch.object(dropin, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.unit = self.etc / "x0xd-testnet.service"
        self.unit.write_text(
            "[Service]\nUser=alice\nExecStart=/opt/x0x/x0xd --name testnet\n", "utf-8"
        )
        self.dropin = self.etc / "x0xd-testnet.service.d" / "30-x0x-launcher.conf"

    def conf(self, root: Path, directory: str, name: str, text: str) -> Path:
        path = root / directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"[Service]\n{text}\n", "utf-8")
        return path

    def settings(self) -> "dropin.Settings":
        return dropin.file_settings(self.unit, self.dropin)

    def refused(self, why: str) -> str:
        with self.assertRaises(dropin.Refused, msg=why) as caught:
            self.settings()
        return str(caught.exception)

    def test_drop_ins_under_run_and_usr_lib_apply_in_name_order(self) -> None:
        usr = self.conf(self.usr, "service.d", "10-all.conf", "User=bob")
        run = self.conf(
            self.run_dir, "x0xd-.service.d", "20-exec.conf",
            "ExecStart=\nExecStart=/opt/x0x/x0xd --name testnet --relay",
        )
        etc = self.conf(self.etc, "x0xd-testnet.service.d", "25-user.conf", "User=carol")
        self.dropin.write_text("[Service]\nUser=nobody\nExecStart=\n", "utf-8")
        self.assertEqual(
            self.settings(),
            dropin.Settings(
                user="carol",
                exec_start=["/opt/x0x/x0xd", "--name", "testnet", "--relay"],
                fragment=str(self.unit),
                dropins=[str(usr), str(run), str(etc)],
            ),
        )

    def test_a_shadowing_unit_or_drop_in_is_refused(self) -> None:
        self.conf(self.run_dir, "x0xd-testnet.service.d", "30-x0x-launcher.conf", "User=x")
        self.assertIn("would replace the launcher drop-in", self.refused("same name as ours"))
        shutil.rmtree(self.run_dir / "x0xd-testnet.service.d")
        self.conf(self.run_dir, "x0xd-testnet.service.d", "10-a.conf", "User=x")
        self.conf(self.usr, "service.d", "10-a.conf", "User=y")
        self.assertIn("share a name", self.refused("duplicate drop-in name"))
        shutil.rmtree(self.usr / "service.d")
        shutil.rmtree(self.run_dir / "x0xd-testnet.service.d")
        (self.transient / self.unit.name).write_text("[Service]\nExecStart=/bin/true\n", "utf-8")
        self.assertIn("overrides", self.refused("transient unit"))
        (self.transient / self.unit.name).unlink()
        (self.usr / self.unit.name).write_text("[Service]\nExecStart=/bin/true\n", "utf-8")
        self.assertEqual(self.settings().user, "alice", "a lower unit file is shadowed")

    def test_a_linked_search_root_is_read_once(self) -> None:
        # Merged /usr: /lib/systemd/system is /usr/lib/systemd/system.
        lib = self.tmp / "lib"
        lib.mkdir()
        (lib / "systemd").symlink_to(self.usr.parent)
        search = (*dropin.SEARCH_PATH, str(lib / "systemd" / "system"))
        vendor = self.conf(self.usr, "service.d", "10-x.conf", "TimeoutStopFailureMode=abort")
        with mock.patch.object(dropin, "SEARCH_PATH", search):
            self.assertEqual(self.settings().dropins, [str(vendor)])

    def test_an_environment_that_moves_the_data_directory_is_refused(self) -> None:
        for line in ("Environment=XDG_DATA_HOME=/srv", 'Environment="A=1" HOME=/srv',
                     "EnvironmentFile=/etc/default/x0x"):
            conf = self.conf(self.etc, "x0xd-testnet.service.d", "20-env.conf", line)
            self.assertIn("migrate by hand", self.refused(line))
            conf.unlink()
        self.conf(self.etc, "x0xd-testnet.service.d", "20-env.conf", "Environment=RUST_LOG=info")
        self.assertEqual(self.settings().user, "alice")

    def test_a_failed_question_to_a_running_systemd_is_refused(self) -> None:
        running = self.tmp / "run-systemd"
        running.mkdir()
        with mock.patch.object(dropin, "SYSTEMD_RUNTIME", str(running)):
            for why, script in (
                ("reload fails", self.fake_systemctl("", status=1)),
                ("show fails", self.fake_systemctl("", status=0, show_status=1)),
                ("no systemctl", None),
            ):
                with self.assertRaises(dropin.Refused, msg=why):
                    self.effective(script)

    def test_a_drop_in_after_the_launchers_that_undoes_it_is_refused(self) -> None:
        for key in ("ExecStart=", "Restart=no", "KillMode=process", "TimeoutSec=5"):
            conf = self.conf(self.etc, "x0xd-testnet.service.d", "50-late.conf", key)
            self.assertIn("after the launcher drop-in", self.refused(key))
            conf.unlink()
        self.conf(self.etc, "x0xd-testnet.service.d", "50-late.conf", "User=dave")
        self.assertEqual(self.settings().user, "dave")

    def fake_systemctl(self, show: str, status: int = 0, show_status: int = 0) -> Path:
        script = self.tmp / "systemctl"
        script.write_text(
            "#!/bin/sh\n"
            f'[ "$1" = daemon-reload ] && exit {status}\n'
            f"cat <<'EOF'\n{show}\nEOF\nexit {show_status}\n",
            "utf-8",
        )
        script.chmod(0o755)
        return script

    def show(self, settings: "dropin.Settings") -> str:
        argv = " ".join(settings.exec_start)
        return (
            f"LoadState=loaded\nFragmentPath={settings.fragment}\n"
            f"DropInPaths={' '.join(settings.dropins)}\nUser={settings.user}\n"
            f"ExecStart={{ path={settings.exec_start[0]} ; argv[]={argv} ; ignore_errors=no ; "
            "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        )

    def effective(self, script: Path | None) -> "dropin.Settings":
        with mock.patch.object(dropin.shutil, "which", return_value=script and str(script)):
            return dropin.effective_settings(self.unit, self.dropin)

    def test_systemds_answer_must_match_the_unit_files(self) -> None:
        self.conf(self.run_dir, "x0xd-testnet.service.d", "20-user.conf", "User=bob")
        files = self.settings()
        self.assertEqual(self.effective(self.fake_systemctl(self.show(files))), files)
        self.assertEqual(self.effective(None), files, "no systemctl: the files")
        self.assertEqual(
            self.effective(self.fake_systemctl("", status=1)), files, "no running systemd"
        )
        for field, value in (
            ("user", "alice"),
            ("exec_start", ["/opt/x0x/x0xd", "--name", "other"]),
            ("dropins", []),
            ("fragment", str(self.usr / self.unit.name)),
        ):
            script = self.fake_systemctl(self.show(files._replace(**{field: value})))
            with self.assertRaises(dropin.Refused, msg=field) as caught:
                self.effective(script)
            self.assertIn("differs from its unit files", str(caught.exception))
        for why, show in (
            ("not loaded", "LoadState=not-found\n"),
            ("two commands", self.show(files) + " ; { path=/bin/true ; argv[]=/bin/true ; }"),
            ("quoted", self.show(files._replace(exec_start=["/opt/x0x/x0xd", '"a b"']))),
        ):
            with self.assertRaises(dropin.Refused, msg=why):
                self.effective(self.fake_systemctl(show))


class ReplaceFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.source = self.tmp / "source"
        self.source.write_bytes(b"launcher bytes")
        self.target = self.tmp / "bin" / "x0x-launcher"
        self.target.parent.mkdir()

    def test_the_launcher_is_written_whole_with_its_mode_under_any_umask(self) -> None:
        opened: list[int] = []
        real_open = os.open

        def record_open(path, flags, mode=0o777, *args, **kwargs):
            if str(path).endswith(".tmp"):
                opened.append(flags)
                self.assertEqual(mode, 0o700)
            return real_open(path, flags, mode, *args, **kwargs)

        for umask in (0o000, 0o077, 0o022):
            previous = os.umask(umask)
            try:
                with mock.patch.object(dropin.os, "open", side_effect=record_open):
                    with mock.patch.object(dropin.os, "fsync", wraps=os.fsync) as fsync:
                        dropin.install_launcher(self.source.read_bytes(), self.target)
            finally:
                os.umask(previous)
            self.assertEqual(self.target.read_bytes(), b"launcher bytes")
            self.assertEqual(self.target.stat().st_mode & 0o7777, 0o755, oct(umask))
            self.assertEqual(fsync.call_count, 2, "the file, then its directory")
            self.assertEqual(os.listdir(self.target.parent), ["x0x-launcher"])
        self.assertTrue(all(flags & os.O_EXCL and flags & os.O_CREAT for flags in opened))

    def test_a_failed_write_leaves_the_old_file_and_no_temporary(self) -> None:
        self.target.write_bytes(b"old")

        def fail(file) -> None:
            file.write(b"partial")
            raise OSError("disk full")

        with self.assertRaises(OSError):
            dropin.replace_file(self.target, fail, 0o755)
        self.assertEqual(self.target.read_bytes(), b"old")
        self.assertEqual(os.listdir(self.target.parent), ["x0x-launcher"])

    def test_the_drop_in_is_0644_under_a_tight_umask(self) -> None:
        conf = self.tmp / "unit.d" / "30-x0x-launcher.conf"
        previous = os.umask(0o077)
        try:
            dropin.write_dropin(conf, "[Service]\n")
        finally:
            os.umask(previous)
        self.assertEqual(conf.stat().st_mode & 0o777, 0o644)
        self.assertEqual(conf.read_text("utf-8"), "[Service]\n")


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
        # `systemctl show` answers with show.out when the test wrote one;
        # otherwise it fails, as on a host without a running systemd.
        self.show_out = self.tmp / "show.out"
        self.answer: dict[str, object] = {}
        self.stub(
            "systemctl",
            f'echo "$*" >> "{self.calls}"\n'
            f'if [ "$1" = show ]; then [ -f "{self.show_out}" ] || exit 1; cat "{self.show_out}"; fi\n',
        )
        self.anchor_dir = self.tmp / "etc-x0x" / "launcher"
        self.anchor = self.anchor_dir / dropin.anchor_path(
            self.anchor_dir, str(self.binary)
        ).name
        self.env: dict[str, str] = {}

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

    def install(
        self, launcher: bool = True, fetch: bool = False
    ) -> subprocess.CompletedProcess[str]:
        """Run install.sh. systemd's stubbed answer agrees with the unit
        files, changed by `self.answer`, so the run does not depend on
        whether this host runs systemd."""
        self.calls.unlink(missing_ok=True)
        self.show_out.unlink(missing_ok=True)
        self.unit.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.deploy / "systemd" / "x0xd-testnet.service", self.unit)
        try:
            self.systemd_answers(**self.answer)
        except dropin.Refused:
            pass
        argv = ["bash", str(self.deploy / "install.sh"), "--instance", "testnet"]
        if launcher:
            argv += ["--launcher"] if fetch else ["--launcher", str(self.launcher_src)]
        env = {
            **os.environ,
            "PATH": f"{self.stubs}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "X0X_LAUNCHER_ANCHOR_DIR": str(self.anchor_dir),
            **self.env,
        }
        return subprocess.run(argv, capture_output=True, text=True, env=env, check=False)

    def systemctl_calls(self) -> list[str]:
        return self.calls.read_text("utf-8").splitlines() if self.calls.exists() else []

    def assert_installed(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        launcher = self.binary.with_name("x0x-launcher")
        self.assertTrue(os.access(launcher, os.X_OK))
        text = self.dropin.read_text("utf-8")
        self.assertIn(
            f"ExecStart={launcher} --host-root {self.data_root} --instance testnet "
            f"--plan-anchor {self.anchor} -- "
            f"{self.binary} --name testnet --config {self.config}\n",
            text,
        )
        self.assertEqual(self.dropin.stat().st_mode & 0o777, 0o644)
        self.assertEqual(
            json.loads(self.anchor.read_text("utf-8")),
            {
                "schema": 1,
                "record_kind": "plan_anchor",
                "daemon_target": str(self.binary),
                "cli_target": str(self.binary.with_name("x0x")),
                "participants": [{"instance_id": "testnet", "data_root": str(self.data_root)}],
            },
        )
        self.assertEqual(self.anchor.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.anchor.stat().st_uid, os.geteuid())
        self.assertEqual(sorted(p.name for p in self.dropin_dir.iterdir() if p.name.startswith(".")), [])
        self.assertEqual(
            self.systemctl_calls(), [*HELPER_CALLS, "daemon-reload", "enable x0xd-testnet"]
        )

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

    def test_a_rerun_that_fails_before_any_change_changes_nothing(self) -> None:
        self.assert_installed(self.install())
        before = self.anchor.read_bytes()
        dropin_before = self.dropin.read_bytes()
        self.write_daemon(1)
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("--check` failed", result.stderr)
        self.assertIn("changed nothing", result.stderr)
        self.assertEqual(self.dropin.read_bytes(), dropin_before)
        self.assertEqual(self.anchor.read_bytes(), before)
        # The helper never asked systemd; install.sh reloads once.
        self.assertEqual(self.systemctl_calls(), ["daemon-reload"])
        # #2186 review: a missing launcher source over an in-flight journal
        # fails its first check and must not unbind the unit either.
        self.write_daemon(0)
        self.write_journal("swapped_cli")
        self.launcher_src.unlink()
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("launcher not found", result.stderr)
        self.assertEqual(self.dropin.read_bytes(), dropin_before)
        self.assertEqual(self.anchor.read_bytes(), before)

    def run_helper(self) -> int:
        """`launcher-dropin.py` in this process, for a rerun with systemd's
        answer agreeing with the unit files."""
        self.unit.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.deploy / "systemd" / "x0xd-testnet.service", self.unit)
        self.systemd_answers()
        argv = [
            "launcher-dropin.py", "--unit", str(self.unit), "--binary", str(self.binary),
            "--launcher-source", str(self.launcher_src),
            "--launcher", str(self.binary.with_name("x0x-launcher")),
            "--instance", "testnet", "--dropin", str(self.dropin),
            "--anchor-dir", str(self.anchor_dir),
        ]
        env = {"PATH": f"{self.stubs}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
        with mock.patch.object(sys, "argv", argv), mock.patch.dict(os.environ, env):
            return dropin.main()

    def fail_the_last_anchor_write(self):
        """Make the final anchor write (the unit entering the anchor) fail,
        after the drop-in was written."""
        real = dropin.write_anchor

        def write(path, data):
            if data is not None and b'"testnet"' in data:
                raise OSError("disk full")
            return real(path, data)

        return mock.patch.object(dropin, "write_anchor", write)

    def test_a_failed_clean_up_keeps_the_drop_in(self) -> None:
        # #2186 review: the unit leaves the anchor before its drop-in goes;
        # if that fails, the drop-in stays (exit 4).
        self.assert_installed(self.install())
        with self.fail_the_last_anchor_write(), mock.patch.object(
            dropin, "forget", side_effect=OSError("lock wait")
        ):
            self.assertEqual(self.run_helper(), 4)
        self.assertTrue(self.dropin.exists())
        self.assertFalse(self.anchor.exists() and "testnet" in self.anchor.read_text("utf-8"))

    def test_a_crash_between_the_clean_up_steps_keeps_the_drop_in(self) -> None:
        self.assert_installed(self.install())
        with self.fail_the_last_anchor_write(), mock.patch.object(
            dropin, "forget", side_effect=KeyboardInterrupt("power loss")
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.run_helper()
        self.assertTrue(self.dropin.exists())

    def test_a_failed_restore_after_a_late_refusal_is_typed_and_loud(self) -> None:
        self.assert_installed(self.install())
        count = self.tmp / "checks"
        text = self.binary.read_text("utf-8").replace(
            "#!/bin/sh\n",
            "#!/bin/sh\n"
            f'n=$(cat "{count}" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "{count}"\n'
            f'[ $n -eq 2 ] && echo \'{{"phase": "booting"}}\' > "{self.data_root}/upgrade-journal.json"\n',
            1,
        )
        self.binary.write_text(text, "utf-8")
        import contextlib
        import io

        err = io.StringIO()
        with mock.patch.object(dropin, "write_dropin", side_effect=OSError("disk full")):
            with contextlib.redirect_stderr(err):
                status = self.run_helper()
        self.assertEqual(status, 1, err.getvalue())
        self.assertIn("restoring the drop-in and the plan anchor then failed", err.getvalue())
        # The unit is not bound and not anchored: consistent.
        self.assertFalse(self.dropin.exists())
        self.assertFalse(self.anchor.exists())

    def test_a_failure_after_the_first_change_unbinds_and_unanchors(self) -> None:
        self.assert_installed(self.install())
        with self.fail_the_last_anchor_write():
            self.assertEqual(self.run_helper(), 1)
        self.assertFalse(self.dropin.exists())
        self.assertFalse(self.anchor.exists())

    def test_an_unsplittable_exec_start_is_a_typed_refusal(self) -> None:
        self.write_unit(f"User={ME.pw_name}", exec_args='--name "testnet')
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("error: the unit's ExecStart cannot be split", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(self.dropin.exists())

    def systemd_answers(self, **changes: object) -> None:
        files = dropin.file_settings(self.unit, self.dropin)._replace(**changes)
        self.show_out.write_text(
            f"LoadState=loaded\nFragmentPath={files.fragment}\n"
            f"DropInPaths={' '.join(files.dropins)}\nUser={files.user}\n"
            f"ExecStart={{ path={files.exec_start[0]} ; argv[]={' '.join(files.exec_start)} ; "
            "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; "
            "status=0/0 }\n",
            "utf-8",
        )

    def test_systemd_is_asked_and_must_agree_with_the_unit_files(self) -> None:
        self.assert_installed(self.install())
        self.answer = {"user": "nobody"}
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("systemd's user for x0xd-testnet.service differs", result.stderr)
        self.assertFalse(self.dropin.exists())

    def test_an_install_without_the_flag_removes_the_drop_in(self) -> None:
        self.assert_installed(self.install())
        result = self.install(launcher=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.dropin.exists())
        # The unit was the anchor's last participant, so the anchor goes too.
        self.assertFalse(self.anchor.exists())

    def write_journal(self, phase: str) -> None:
        (self.data_root / "upgrade-journal.json").write_text(
            json.dumps({"phase": phase}), "utf-8"
        )

    def test_a_rerun_keeps_the_same_anchor_bytes(self) -> None:
        self.assert_installed(self.install())
        before = self.anchor.read_bytes()
        self.write_journal("idle")
        self.assert_installed(self.install())
        self.assertEqual(self.anchor.read_bytes(), before)

    def test_the_anchor_does_not_change_while_a_journal_is_in_flight(self) -> None:
        self.assert_installed(self.install())
        before = self.anchor.read_bytes()
        dropin_before = self.dropin.read_bytes()
        for phase in ("staged", "swapped_cli", "host_committed", "restored", "garbage"):
            self.write_journal(phase)
            # Removing the unit would change the anchor: refused, nothing changes.
            result = self.install(launcher=False)
            self.assertEqual(result.returncode, 1, phase)
            self.assertIn(f"is {phase}", result.stderr)
            self.assertIn("are kept", result.stderr)
            self.assertEqual(self.dropin.read_bytes(), dropin_before, phase)
            self.assertEqual(self.anchor.read_bytes(), before, phase)
            # A rerun is refused too, before anything is touched.
            result = self.install()
            self.assertEqual(result.returncode, 1, phase)
            self.assertIn("changed nothing", result.stderr)
            self.assertEqual(self.dropin.read_bytes(), dropin_before, phase)
            self.assertEqual(self.anchor.read_bytes(), before, phase)
        # A FIFO or a symlink at the journal path counts as a journal, and
        # does not hang the installer.
        journal = self.data_root / "upgrade-journal.json"
        journal.unlink()
        os.mkfifo(journal)
        result = self.install(launcher=False)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("not a regular file", result.stderr)
        journal.unlink()
        target = self.tmp / "elsewhere.json"
        target.write_text('{"phase": "idle"}', "utf-8")
        journal.symlink_to(target)
        result = self.install(launcher=False)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("unreadable", result.stderr)
        journal.unlink()
        for phase in ("idle", "superseded"):
            self.write_journal(phase)
            self.assert_installed(self.install())
        result = self.install(launcher=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.anchor.exists())

    def test_the_launcher_is_replaced_only_with_no_active_transaction(self) -> None:
        # ADR 0094 §5: the launcher is updated only with no active
        # transaction, and the old launcher is kept.
        self.assert_installed(self.install())
        launcher = self.binary.with_name("x0x-launcher")
        old = launcher.read_bytes()
        dropin_before = self.dropin.read_bytes()
        self.launcher_src.write_text("#!/bin/sh\nexit 3\n", encoding="utf-8")
        self.write_journal("booting")
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("the launcher, its drop-in and the plan anchor cannot change", result.stderr)
        self.assertIn("changed nothing", result.stderr)
        self.assertEqual(launcher.read_bytes(), old)
        self.assertEqual(self.dropin.read_bytes(), dropin_before)
        # HostCommitted and Restored still give a trial: not replaced either.
        for phase in ("host_committed", "restored"):
            self.write_journal(phase)
            self.assertEqual(self.install().returncode, 1, phase)
            self.assertEqual(launcher.read_bytes(), old, phase)
        self.write_journal("idle")
        self.assert_installed(self.install())
        self.assertEqual(launcher.read_bytes(), self.launcher_src.read_bytes())
        self.assertEqual(launcher.with_name("x0x-launcher.previous").read_bytes(), old)

    def test_a_moved_data_root_is_refused_while_its_journal_is_in_flight(self) -> None:
        self.assert_installed(self.install())
        before = self.anchor.read_bytes()
        dropin_before = self.dropin.read_bytes()
        self.write_journal("swapped_cli")
        moved = self.tmp / "data" / "x0x-moved"
        moved.mkdir(mode=0o700)
        moved.chmod(0o700)
        fake_daemon(self.binary, self.log, f'    data_dir: "{moved}",')
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("changed nothing", result.stderr)
        self.assertEqual(self.dropin.read_bytes(), dropin_before)
        self.assertEqual(self.anchor.read_bytes(), before)
        # Refused before systemd was asked by the helper (install.sh then
        # reloads once, with the drop-in in place), so systemd never reloaded the
        # unit without its launcher drop-in.
        self.assertEqual(self.systemctl_calls(), ["daemon-reload"])

    def test_a_failed_first_install_leaves_no_anchor_and_no_drop_in(self) -> None:
        self.write_daemon(1)
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertFalse(self.dropin.exists())
        self.assertFalse(self.anchor.exists())
        # A drop-in that cannot be written restores the anchor (none here).
        self.write_daemon(0)
        self.dropin_dir.mkdir(parents=True)
        self.dropin_dir.chmod(0o500)
        self.addCleanup(self.dropin_dir.chmod, 0o700)
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("runs x0xd directly", result.stderr)
        self.assertFalse(self.anchor.exists())

    def test_the_anchor_path_is_canonical(self) -> None:
        real = self.tmp / "private-etc"
        real.mkdir()
        real.chmod(0o755)
        link = self.tmp / "etc-link"
        link.symlink_to(real)
        self.env = {"X0X_LAUNCHER_ANCHOR_DIR": str(link / "launcher")}
        self.anchor = real / "launcher" / self.anchor.name
        self.assert_installed(self.install())
        self.assertIn(f"--plan-anchor {self.anchor} ", self.dropin.read_text("utf-8"))

    def test_an_anchor_directory_others_can_write_is_refused(self) -> None:
        self.anchor_dir.mkdir(parents=True)
        self.anchor_dir.chmod(0o777)
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("writable by group or others", result.stderr)
        self.assertFalse(self.dropin.exists())

    def test_a_journal_that_appears_before_the_late_check_restores_everything(self) -> None:
        self.assert_installed(self.install())
        launcher = self.binary.with_name("x0x-launcher")
        old_launcher = launcher.read_bytes()
        before = self.anchor.read_bytes()
        dropin_before = self.dropin.read_bytes()
        self.launcher_src.write_text("#!/bin/sh\nexit 4\n", encoding="utf-8")
        # The daemon's second `--check` (after systemd was asked) leaves an
        # in-flight journal, as a stage starting at that moment would.
        count = self.tmp / "checks"
        text = self.binary.read_text("utf-8").replace(
            "#!/bin/sh\n",
            "#!/bin/sh\n"
            f'n=$(cat "{count}" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "{count}"\n'
            f'[ $n -eq 2 ] && echo \'{{"phase": "booting"}}\' > "{self.data_root}/upgrade-journal.json"\n',
            1,
        )
        self.binary.write_text(text, "utf-8")
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("is booting", result.stderr)
        self.assertIn("changed nothing", result.stderr)
        self.assertEqual(self.dropin.read_bytes(), dropin_before)
        self.assertEqual(self.anchor.read_bytes(), before)
        self.assertEqual(launcher.read_bytes(), old_launcher)
        # systemd was asked without the drop-in, so it is reloaded with it
        # back: by the helper, then by install.sh.
        self.assertEqual(
            self.systemctl_calls(), [*HELPER_CALLS, "daemon-reload", "daemon-reload"]
        )

    def test_another_participants_journal_holds_the_launcher_and_the_anchor(self) -> None:
        self.assert_installed(self.install())
        other = self.tmp / "data" / "x0x-443"
        other.mkdir(mode=0o700)
        old, new = dropin.anchor_change(
            self.anchor, str(self.binary), str(self.binary.with_name("x0x")), "443", str(other)
        )
        dropin.write_anchor(self.anchor, new)
        before = self.anchor.read_bytes()
        launcher = self.binary.with_name("x0x-launcher")
        old_launcher = launcher.read_bytes()
        (other / "upgrade-journal.json").write_text('{"phase": "booting"}', "utf-8")
        self.launcher_src.write_text("#!/bin/sh\nexit 5\n", encoding="utf-8")
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(f"{other} is booting", result.stderr)
        self.assertEqual(launcher.read_bytes(), old_launcher)
        self.assertEqual(self.anchor.read_bytes(), before)
        # Refused by the first check: the helper never asked systemd.
        self.assertEqual(self.systemctl_calls(), ["daemon-reload"])

    def test_a_symlink_at_the_launcher_path_is_refused_not_followed(self) -> None:
        self.assert_installed(self.install())
        launcher = self.binary.with_name("x0x-launcher")
        target = self.tmp / "elsewhere-launcher"
        target.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
        launcher.unlink()
        launcher.symlink_to(target)
        self.launcher_src.write_text("#!/bin/sh\nexit 8\n", encoding="utf-8")
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("installed launcher", result.stderr)
        self.assertTrue(launcher.is_symlink())
        self.assertFalse(launcher.with_name("x0x-launcher.previous").exists())

    def test_two_runs_for_one_install_take_turns(self) -> None:
        self.assert_installed(self.install())
        before = self.anchor.read_bytes()
        dropin_before = self.dropin.read_bytes()
        lock = os.open(self.anchor_dir / ".install.lock", os.O_RDWR)
        self.addCleanup(os.close, lock)
        import fcntl

        fcntl.flock(lock, fcntl.LOCK_EX)
        self.env = {"X0X_INSTALL_LOCK_WAIT": "0.5"}
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("another launcher install holds", result.stderr)
        self.assertEqual(self.anchor.read_bytes(), before)
        self.assertEqual(self.dropin.read_bytes(), dropin_before)
        fcntl.flock(lock, fcntl.LOCK_UN)
        self.assert_installed(self.install())

    def test_a_crash_at_any_step_never_leaves_the_anchor_naming_an_unbound_unit(self) -> None:
        """Power loss after each change of a rerun with a new launcher: the
        anchor names this unit only while its drop-in is in place."""
        self.assert_installed(self.install())
        self.launcher_src.write_text("#!/bin/sh\nexit 6\n", encoding="utf-8")
        argv = [
            "launcher-dropin.py", "--unit", str(self.unit), "--binary", str(self.binary),
            "--launcher-source", str(self.launcher_src),
            "--launcher", str(self.binary.with_name("x0x-launcher")),
            "--instance", "testnet", "--dropin", str(self.dropin),
            "--anchor-dir", str(self.anchor_dir),
        ]
        env = {"PATH": f"{self.stubs}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
        crashed_at = 0
        for crash in range(1, 20):
            self.assert_installed(self.install())
            self.launcher_src.write_text(f"#!/bin/sh\nexit {crash}\n", encoding="utf-8")
            calls = {"n": 0}

            def crashing(real):
                def step(*args, **kwargs):
                    result = real(*args, **kwargs)
                    calls["n"] += 1
                    if calls["n"] == crash:
                        raise KeyboardInterrupt("power loss")
                    return result
                return step

            patches = [
                mock.patch.object(dropin, name, crashing(getattr(dropin, name)))
                for name in ("write_anchor", "write_dropin", "install_launcher")
            ]
            real_unlink = Path.unlink

            def unlink(path, *args, **kwargs):
                real_unlink(path, *args, **kwargs)
                if path == self.dropin:
                    calls["n"] += 1
                    if calls["n"] == crash:
                        raise KeyboardInterrupt("power loss")

            patches.append(mock.patch.object(Path, "unlink", unlink))
            with mock.patch.object(sys, "argv", argv), mock.patch.dict(os.environ, env):
                for patch in patches:
                    patch.start()
                try:
                    dropin.main()
                    finished = True
                except KeyboardInterrupt:
                    finished = False
                finally:
                    for patch in patches:
                        patch.stop()
            named = self.anchor.exists() and "testnet" in self.anchor.read_text("utf-8")
            if named:
                self.assertTrue(self.dropin.exists(), f"crash after change {crash}")
            if finished:
                crashed_at = crash
                break
        self.assertGreater(crashed_at, 3, "every change was crashed once")

    def fetch_stubs(self, signature: str = "good", sha_ok: bool = True, key: str = "key") -> None:
        """A release directory served by a curl stub, a gpg stub that reports
        the pinned key and a VALIDSIG only for a good signature, and Linux
        x86_64 for uname."""
        release = self.tmp / "release" / "v0.49.1"
        staging = self.tmp / "pkg" / "x0x-launcher-linux-x64-gnu"
        staging.mkdir(parents=True)
        shutil.copy2(self.launcher_src, staging / "x0x-launcher")
        release.mkdir(parents=True)
        archive = release / "x0x-launcher-linux-x64-gnu.tar.gz"
        subprocess.run(
            ["tar", "-czf", str(archive), "-C", str(staging.parent), staging.name], check=True
        )
        digest = hashlib.sha256(archive.read_bytes()).hexdigest() if sha_ok else "0" * 64
        (release / f"{archive.name}.sha256").write_text(f"{digest}  {archive.name}\n", "utf-8")
        (release / f"{archive.name}.asc").write_text(signature, "utf-8")
        (release / "SAORSA_PUBLIC_KEY.asc").write_text(key, "utf-8")
        self.env = {"X0X_RELEASE_BASE": str(self.tmp / "release")}
        fpr = "CEB3506E7DCB8A2DD2D679E8EDDA4827D89C0F29"
        # curl -sfL URL -o FILE, with URL a local path under the release base.
        self.stub("curl", 'cp "$2" "$4"\n')
        self.stub("uname", '[ "$1" = -s ] && echo Linux || echo x86_64\n')
        self.stub(
            "sha256sum",
            'python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],\'rb\').read()).hexdigest(), sys.argv[1])" "$1"\n',
        )
        self.stub(
            "gpg",
            'for a in "$@"; do last2="$last"; last="$a"; done\n'
            'case " $* " in *" --show-keys "*)\n'
            f'  [ "$(cat "$last")" = key ] && echo "fpr:::::::::{fpr}:" || echo "fpr:::::::::0000:"\n'
            "  exit 0 ;; esac\n"
            'case " $* " in *" --import "*) exit 0 ;; esac\n'
            f'[ "$(cat "$last2")" = good ] && echo "[GNUPG:] VALIDSIG {fpr} x" && exit 0\n'
            # A valid signature, but by another key.
            '[ "$(cat "$last2")" = other ] && echo "[GNUPG:] VALIDSIG 0000 x" && exit 0\n'
            "exit 1\n",
        )
        fake = self.binary.read_text("utf-8").replace(
            "#!/bin/sh\n", '#!/bin/sh\n[ "$1" = --version ] && { echo "x0xd 0.49.1"; exit 0; }\n', 1
        )
        self.binary.write_text(fake, "utf-8")

    def test_the_launcher_is_fetched_and_verified_without_a_path(self) -> None:
        self.fetch_stubs()
        self.assert_installed(self.install(fetch=True))
        self.assertEqual(
            self.binary.with_name("x0x-launcher").read_bytes(), self.launcher_src.read_bytes()
        )

    def test_a_fetched_launcher_that_fails_verification_changes_nothing(self) -> None:
        for signature, sha_ok, why in (
            ("bad", True, "not valid"),
            ("other", True, "not signed by the pinned release key"),
            ("good", False, ".sha256"),
            ("key:wrong", True, "not the pinned release key"),
            ("empty-sha", True, ".sha256"),
        ):
            if signature.startswith("key:"):
                self.fetch_stubs(key=signature[4:])
            elif signature == "empty-sha":
                # An empty .sha256 and a sha256sum that prints nothing.
                self.fetch_stubs()
                release = self.tmp / "release" / "v0.49.1"
                (release / "x0x-launcher-linux-x64-gnu.tar.gz.sha256").write_text("", "utf-8")
                self.stub("sha256sum", "exit 0\n")
            else:
                self.fetch_stubs(signature=signature, sha_ok=sha_ok)
            result = self.install(fetch=True)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn(why, result.stderr)
            self.assertIn("the launcher was not fetched", result.stderr)
            self.assertFalse(self.dropin.exists())
            self.assertFalse(self.binary.with_name("x0x-launcher").exists())
            shutil.rmtree(self.tmp / "release")
            shutil.rmtree(self.tmp / "pkg")


class AnchorTests(unittest.TestCase):
    """The shared plan anchor of one install (#2012)."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.path = self.tmp / "install.anchor.json"
        self.roots = {name: self.tmp / name for name in ("x0xd", "x0xd-443")}
        for root in self.roots.values():
            root.mkdir()

    def change(self, instance: str, root: Path | None) -> None:
        old, new = dropin.anchor_change(
            self.path, "/opt/x0x/x0xd", "/opt/x0x/x0x", instance, None if root is None else str(root)
        )
        if new != old:
            roots = dropin.anchored_roots(self.path, "/opt/x0x/x0xd")
            dropin.check_no_journal(roots | ({str(root)} if root else set()))
            dropin.write_anchor(self.path, new)

    def test_two_units_of_one_install_share_one_canonical_anchor(self) -> None:
        self.change("x0xd-443", self.roots["x0xd-443"])
        self.change("x0xd", self.roots["x0xd"])
        first = self.path.read_bytes()
        anchor = json.loads(first)
        self.assertEqual(
            [p["instance_id"] for p in anchor["participants"]], ["x0xd", "x0xd-443"]
        )
        # The same units in the other order give the same bytes.
        self.path.unlink()
        self.change("x0xd", self.roots["x0xd"])
        self.change("x0xd-443", self.roots["x0xd-443"])
        self.assertEqual(self.path.read_bytes(), first)
        self.change("x0xd", None)
        self.assertEqual(
            [p["instance_id"] for p in json.loads(self.path.read_bytes())["participants"]],
            ["x0xd-443"],
        )

    def test_an_in_flight_journal_of_any_participant_holds_the_anchor(self) -> None:
        self.change("x0xd", self.roots["x0xd"])
        (self.roots["x0xd"] / "upgrade-journal.json").write_text('{"phase": "booting"}', "utf-8")
        before = self.path.read_bytes()
        with self.assertRaises(dropin.Held):
            self.change("x0xd-443", self.roots["x0xd-443"])
        self.assertEqual(self.path.read_bytes(), before)

    def test_the_anchor_directory_is_made_0755_under_any_umask(self) -> None:
        for umask in (0o002, 0o077):
            base = self.tmp / f"umask-{umask:o}"
            old = os.umask(umask)
            try:
                made = dropin.check_anchor_dir(str(base / "etc" / "launcher"))
            finally:
                os.umask(old)
            for directory in (made, made.parent, base):
                self.assertEqual(directory.stat().st_mode & 0o777, 0o755, f"{umask:o} {directory}")

    def test_the_anchor_is_replaced_by_rename_never_in_place(self) -> None:
        self.change("x0xd", self.roots["x0xd"])
        with open(self.path, "rb") as reader:
            first = reader.read()
            self.change("x0xd-443", self.roots["x0xd-443"])
            reader.seek(0)
            # A reader of the old file still sees the old bytes whole.
            self.assertEqual(reader.read(), first)
        self.assertNotEqual(self.path.read_bytes(), first)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o644)

    def test_a_symlinked_anchor_is_not_followed(self) -> None:
        self.change("x0xd", self.roots["x0xd"])
        real = self.tmp / "real.anchor.json"
        self.path.rename(real)
        self.path.symlink_to(real)
        with self.assertRaises(dropin.Refused) as caught:
            dropin.read_anchor(self.path)
        self.assertIn("cannot read", str(caught.exception))

    def test_the_installer_anchor_is_the_shared_fixture(self) -> None:
        # The Rust reader parses the same bytes
        # (plan_binding::tests::the_installer_anchor_fixture_parses).
        fixture = ROOT / "tests" / "fixtures" / "plan-anchor-installer.json"
        self.assertEqual(
            dropin.render_anchor(
                "/opt/x0x/x0xd",
                "/opt/x0x/x0x",
                {"x0xd-443": "/var/lib/x0x-443", "x0xd": "/root/.local/share/x0x"},
            ),
            fixture.read_bytes(),
        )

    def test_an_anchor_of_another_install_or_a_loose_file_is_refused(self) -> None:
        self.change("x0xd", self.roots["x0xd"])
        with self.assertRaises(dropin.Refused) as caught:
            dropin.anchor_change(self.path, "/srv/other/x0xd", "/srv/other/x0x", "x0xd", "/r")
        self.assertIn("anchors /opt/x0x/x0xd", str(caught.exception))
        self.path.chmod(0o666)
        with self.assertRaises(dropin.Refused) as caught:
            self.change("x0xd-443", self.roots["x0xd-443"])
        self.assertIn("writable by group or others", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
