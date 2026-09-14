#!/usr/bin/env python3
"""Inert controls for the #690 systemd acceptance runner."""
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import textwrap
import unittest

RUNNER = Path(__file__).with_name("linux690-systemd-acceptance.sh")


def executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class RunnerControls(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[dict[str, str], Path]:
        bin_dir = root / "bin"
        state = root / "state"
        bin_dir.mkdir()
        state.mkdir()
        executable(bin_dir / "timeout", "#!/bin/sh\nshift\nshift\nexec \"$@\"\n")
        executable(
            bin_dir / "systemd-run",
            textwrap.dedent(r"""#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
args=sys.argv[1:]
if args and args[0] == "--user": args=args[1:]
if os.environ.get("FAKE_HOLD_RUN") == "1":
 import time
 (pathlib.Path(os.environ["FAKE_STATE"])/"hold-started").touch()
 marker=pathlib.Path(os.environ["FAKE_STATE"])/"release-hold"
 while not marker.exists(): time.sleep(.01)
unit=next(a.split("=",1)[1] for a in args if a.startswith("--unit="))
artifact=pathlib.Path(args[args.index("--artifact")+1])
artifact.mkdir(parents=True, exist_ok=True)
case=unit.removesuffix(".service").rsplit("-",1)[-1]
if "on-failure" in unit: verdict, detail = "not_guaranteed", "Restart=on-failure"
elif "prevent-exit-zero" in unit: verdict, detail = "not_guaranteed", "RestartPreventExitStatus lists 0"
elif "remain-after-exit" in unit: verdict, detail = "not_guaranteed", "RemainAfterExit=yes"
else: verdict, detail = "verified", None
def record(number, pid, invocation_id):
 value={"schema":1,"invocation":number,"pid":pid,"invocation_id":invocation_id,
 "argv":["fixture"],"unix_ms":1,"exit_intent":"clean_exit_after_release" if number==1 else "wait_for_manager_stop",
 "verdict":verdict,"unit":unit if verdict=="verified" else None,"user_manager":True if verdict=="verified" else None,
 "restart":"always" if verdict=="verified" else None,"template_version":1 if verdict=="verified" else None,"detail":detail}
 (artifact/f"invocation-{number}.json").write_text(json.dumps(value)+"\n")
record(1,111,"inv-1")
(pathlib.Path(os.environ["FAKE_STATE"])/f"unit-{unit}").touch()
if verdict == "verified":
 code='''import json,pathlib,sys,time\np=pathlib.Path(sys.argv[1]); unit=sys.argv[2]; state=pathlib.Path(sys.argv[3])\nwhile not (p/"release-first").exists():\n if (state/f"stopped-{unit}").exists(): raise SystemExit(0)\n time.sleep(.01)\nv=json.loads((p/"invocation-1.json").read_text()); v.update(invocation=2,pid=222,invocation_id="inv-2",exit_intent="wait_for_manager_stop"); (p/"invocation-2.json").write_text(json.dumps(v)+"\\n")\n'''
 worker=subprocess.Popen([sys.executable,"-c",code,str(artifact),unit,os.environ["FAKE_STATE"]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 (pathlib.Path(os.environ["FAKE_STATE"])/f"worker-pid-{unit}").write_text(str(worker.pid))
print(unit)
"""),
        )
        executable(
            bin_dir / "systemctl",
            textwrap.dedent(r"""#!/usr/bin/env python3
import os, pathlib, sys
args=sys.argv[1:]
if args and args[0] == "--user": args=args[1:]
state=pathlib.Path(os.environ["FAKE_STATE"])
if args == ["--version"]: print("systemd 999"); raise SystemExit(0)
if args and args[0] == "show" and len(args)>1 and not args[1].startswith("-"):
 unit=args[1]
 if "LoadState" in args:
  if os.environ.get("FAKE_CLEANUP_QUERY_FAIL") == "1": raise SystemExit(7)
  print("not-found" if (state/f"stopped-{unit}").exists() else "loaded"); raise SystemExit(0)
 print(f"Id={unit}\nMainPID=222\nInvocationID=inv-2\nRestart=always\nRestartPreventExitStatus=\nRemainAfterExit=no\nType=simple\nStartLimitIntervalUSec=0\nStartLimitBurst=5\nActiveEnterTimestampMonotonic=1\nExecStart=fixture\nEnvironment=X0X_TEMPLATE_VERSION=1\nResult=success\nExecMainCode=exited\nExecMainStatus=0\nNRestarts=1")
 raise SystemExit(0)
if args and args[0] == "show": print("999"); raise SystemExit(0)
if args and args[0] == "stop": (state/f"stopped-{args[1]}").touch(); raise SystemExit(0)
if args and args[0] == "reset-failed": raise SystemExit(0)
raise SystemExit(3)
"""),
        )
        executable(bin_dir / "journalctl", "#!/bin/sh\nexit 0\n")
        probe = root / "probe"
        executable(probe, "#!/bin/sh\nexit 99\n")
        env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", FAKE_STATE=str(state))
        return env, probe

    def run_fixture(self, fail_cleanup: bool) -> tuple[subprocess.CompletedProcess[str], Path]:
        root = Path(tempfile.mkdtemp(prefix="linux690-runner-control-"))
        env, probe = self.fixture(root)
        if fail_cleanup:
            env["FAKE_CLEANUP_QUERY_FAIL"] = "1"
        result = subprocess.run(
            [str(RUNNER), "--probe", str(probe), "--manager", "user", "--artifact-root", str(root / "artifacts")],
            env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False,
        )
        return result, root / "artifacts"

    def test_inert_success_reaches_all_cases_and_cleans(self) -> None:
        result, artifact = self.run_fixture(False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS artifact_root=", result.stdout)
        statuses = (artifact / "command-statuses.txt").read_text(encoding="utf-8")
        self.assertIn("run-positive=0", statuses)
        self.assertIn("show-respawn-positive=0", statuses)
        self.assertIn("FINAL_EXIT=0", (artifact / "exit-status.txt").read_text(encoding="utf-8"))

    def test_inert_cleanup_query_failure_is_nonzero(self) -> None:
        result, artifact = self.run_fixture(True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        statuses = (artifact / "command-statuses.txt").read_text(encoding="utf-8")
        self.assertRegex(statuses, r"absence-.*=7")
        self.assertIn("FINAL_EXIT=1", (artifact / "exit-status.txt").read_text(encoding="utf-8"))

    def test_inert_term_preserves_signal_status_and_cleans(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="linux690-runner-signal-"))
        env, probe = self.fixture(root)
        env["FAKE_HOLD_RUN"] = "1"
        artifact = root / "artifacts"
        process = subprocess.Popen(
            [str(RUNNER), "--probe", str(probe), "--manager", "user", "--artifact-root", str(artifact)],
            env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        for _ in range(100):
            if (root / "state" / "hold-started").exists():
                break
            import time
            time.sleep(0.01)
        os.kill(process.pid, signal.SIGTERM)
        (root / "state" / "release-hold").touch()
        stdout, stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 143, stdout + stderr)
        self.assertIn("FINAL_EXIT=143", (artifact / "exit-status.txt").read_text(encoding="utf-8"))
        pid_files = list((root / "state").glob("worker-pid-*"))
        self.assertEqual(len(pid_files), 1)
        worker_pid = int(pid_files[0].read_text(encoding="utf-8"))
        import time
        for _ in range(100):
            try:
                os.kill(worker_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.01)
        else:
            self.fail(f"detached fake worker {worker_pid} survived fixture cleanup")


if __name__ == "__main__":
    unittest.main()
