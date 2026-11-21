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
                        dropin.install_launcher(self.source, self.target)
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

    def test_a_failed_rerun_leaves_the_direct_job_and_reloads(self) -> None:
        self.assert_installed(self.install())
        self.write_daemon(1)
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("--check` failed", result.stderr)
        self.assertIn("runs x0xd directly", result.stderr)
        self.assertFalse(self.dropin.exists())
        self.assertEqual(self.systemctl_calls(), [*HELPER_CALLS, "daemon-reload"])

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


if __name__ == "__main__":
    unittest.main()
