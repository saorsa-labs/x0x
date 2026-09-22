#!/usr/bin/env python3
"""Isolated #623 A/B runner. Linux CI only; never a developer-host load tool."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time


SELECTOR = "legacy_bus_interop_tests::paired_controlled_load_bus_eager_attempts_default_vs_optout"
ANT_REPOSITORY = "https://github.com/saorsa-labs/ant-quic.git"
ANT_REPAIR = "4264c345cffe29ad04463fa9c2ee8a2492a38fc2"
EXPECTED_ABORT = "DirectIPv4: Timeout; DirectIPv6: Happy Eyeballs timed out"
RUNS = 10


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_number(path: Path) -> float | None:
    try:
        value = path.read_text(encoding="ascii").strip()
        return None if value == "max" else float(value)
    except (OSError, ValueError):
        return None


def current_cgroup(root: Path, proc_cgroup: Path = Path("/proc/self/cgroup")) -> Path:
    try:
        rows = proc_cgroup.read_text(encoding="ascii").splitlines()
    except OSError:
        return root
    unified = [row.split(":", 2)[2] for row in rows if row.startswith("0::")]
    if len(unified) == 1:
        candidate = root / unified[0].lstrip("/")
        if (candidate / "cpu.max").is_file():
            return candidate
    return root


def cpu_facts(cgroup: Path = Path("/sys/fs/cgroup"), proc_cgroup: Path = Path("/proc/self/cgroup")) -> dict[str, object]:
    affinity = sorted(os.sched_getaffinity(0))
    quota = None
    period = None
    cgroup = current_cgroup(cgroup, proc_cgroup)
    cpu_max = cgroup / "cpu.max"
    if cpu_max.is_file():
        raw_quota, raw_period = cpu_max.read_text(encoding="ascii").split()
        quota = None if raw_quota == "max" else float(raw_quota)
        period = float(raw_period)
    else:
        quota = read_number(cgroup / "cpu" / "cpu.cfs_quota_us")
        period = read_number(cgroup / "cpu" / "cpu.cfs_period_us")
        if quota is not None and quota < 0:
            quota = None
    quota_cpus = None if quota is None or not period or period <= 0 else quota / period
    effective = float(len(affinity)) if quota_cpus is None else min(len(affinity), quota_cpus)
    if effective <= 0:
        raise RuntimeError("effective CPU budget is not positive")
    worker_count = math.ceil(5 * effective)
    if not 1 <= worker_count <= 256:
        raise RuntimeError("5x worker count is outside the admitted 1..256 bound")
    return {
        "affinity_cpu_count": len(affinity),
        "affinity_cpu_ids": affinity,
        "cgroup_quota_us": quota,
        "cgroup_period_us": period,
        "cgroup_quota_cpus": quota_cpus,
        "effective_cpus": effective,
        "worker_count": worker_count,
    }


def isolation_facts(root: Path, before: set[Path], role: str, scratch: Path) -> dict[str, object]:
    after = set(root.glob("x0x-isolation-*"))
    created = after - before
    if len(created) != 1:
        raise RuntimeError("isolated trial did not produce exactly one evidence directory")
    directory = created.pop()
    admission = json.loads((directory / "admission.json").read_text())
    supervisor = json.loads((directory / "supervisor.json").read_text())
    stamped = json.loads((directory / "role.json").read_text())
    child_exit = json.loads((directory / "exit.json").read_text())["exit"]
    if (
        admission.get("namespace_changed") is not True
        or admission.get("no_new_privs") != 1
        or supervisor.get("reason") is not None
        or supervisor.get("child_reaped") is not True
        or stamped != {"role": role, "scratch": scratch.name}
    ):
        raise RuntimeError("isolated trial custody is incomplete")
    return {
        "namespace_changed": True,
        "no_new_privs": 1,
        "supervisor_reason": None,
        "child_reaped": True,
        "admitted_exit": child_exit,
    }


def classify(returncode: int, output: bytes) -> str:
    if returncode == 0:
        return "PASS"
    if returncode == 124:
        return "ISOLATION_DEADLINE"
    if returncode < 0:
        return f"SIGNAL_{-returncode}"
    # cargo-nextest reserves 100 for a completed test run with at least one
    # failing test. A deadline/signal/setup failure may retain buffered panic
    # text, but it did not complete the controlled trial and must never count
    # as baseline reproduction evidence.
    text = output.decode("utf-8", errors="replace")
    if returncode == 100 and EXPECTED_ABORT in text:
        return "EXPECTED_TERMINAL_DIAL_ABORT"
    return "OTHER_FAILURE"


def stop_workers(workers: list[subprocess.Popen[bytes]]) -> dict[str, object]:
    for worker in workers:
        if worker.poll() is None:
            worker.terminate()
    deadline = time.monotonic() + 5
    for worker in workers:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            worker.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            worker.kill()
            worker.wait()
    return {"started": len(workers), "reaped": sum(worker.poll() is not None for worker in workers)}


def cargo_config(arm: str) -> list[str]:
    if arm == "baseline":
        return []
    return [
        "--config", f'patch.crates-io.ant-quic.git="{ANT_REPOSITORY}"',
        "--config", f'patch.crates-io.ant-quic.rev="{ANT_REPAIR}"',
    ]


def run_checked(command: list[str], *, stdout=None) -> None:
    subprocess.run(command, check=True, stdout=stdout)


def prepare(root: Path, arm: str) -> tuple[Path, dict[str, object]]:
    scratch = Path(tempfile.mkdtemp(prefix="x0x-metadata-", dir=root))
    config = cargo_config(arm)
    with (scratch / "cargo.json").open("wb") as output:
        run_checked(["cargo", "metadata", "--format-version", "1", "--all-features", *config], stdout=output)
    lock_hash = sha256(Path("Cargo.lock"))
    (scratch / "lock.sha256").write_text(f"{lock_hash}  Cargo.lock\n", encoding="ascii")
    with (scratch / "binaries.json").open("wb") as output:
        run_checked([
            "cargo", "nextest", "list", "--all-features", "--lib", *config,
            "--locked", "--cargo-metadata", str(scratch / "cargo.json"),
            "--list-type", "binaries-only", "--message-format", "json",
        ], stdout=output)
    if sha256(Path("Cargo.lock")) != lock_hash:
        raise RuntimeError("Cargo.lock changed during binary preparation")
    run_checked([sys.executable, "scripts/ci/nextest-reuse.py", "record", str(scratch)])
    custody = json.loads((scratch / "custody.json").read_text())
    binaries = sorted(
        (Path(path).name, digest) for path, digest in custody["files"].items()
        if re.fullmatch(r"x0x-[0-9a-f]{8,32}", Path(path).name)
    )
    if len(binaries) != 1:
        raise RuntimeError("expected exactly one x0x lib test binary")
    metadata = json.loads((scratch / "cargo.json").read_text())
    ant = [package for package in metadata["packages"] if package["name"] == "ant-quic"]
    if len(ant) != 1:
        raise RuntimeError("resolved graph must contain exactly one ant-quic package")
    source = str(ant[0].get("source", ""))
    expected = "registry+" if arm == "baseline" else f"git+{ANT_REPOSITORY}"
    if ant[0]["version"] != "0.27.52" or not source.startswith(expected):
        raise RuntimeError(f"{arm} resolved unexpected ant-quic source")
    if arm == "candidate" and not source.endswith(f"#{ANT_REPAIR}"):
        raise RuntimeError("candidate did not resolve the exact repair commit")
    return scratch, {
        "lock_sha256": lock_hash,
        "test_binary": {"name": binaries[0][0], "sha256": binaries[0][1]},
        "ant_quic": {"version": ant[0]["version"], "source": source},
    }


def execute(args: argparse.Namespace) -> int:
    if sys.platform != "linux" or not os.environ.get("GITHUB_ACTIONS"):
        raise RuntimeError("#623 contention proof is admitted only on GitHub-hosted Linux")
    root = Path(args.output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    head, tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD", "HEAD^{tree}"], text=True
    ).splitlines()
    receipt_path = root / "receipt.json"
    receipt: dict[str, object] = {
        "schema": "x0x.issue623-dial-contention/1",
        "arm": args.arm,
        "source": {"head": head, "tree": tree},
        "phase": "preparing",
    }

    def save() -> None:
        temporary = receipt_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        temporary.replace(receipt_path)

    save()
    workers: list[subprocess.Popen[bytes]] = []
    runs: list[dict[str, object]] = []
    cleanup: dict[str, object] = {"started": 0, "reaped": 0}
    try:
        scratch, build = prepare(root, args.arm)
        cpu = cpu_facts()
        receipt.update(build=build, cpu=cpu, phase="running", runs=runs)
        save()
        interrupted = []
        active: list[subprocess.Popen[bytes]] = []

        def cancel(signum, _frame):
            interrupted.append(signum)
            if active and active[0].poll() is None:
                active[0].terminate()

        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, cancel)
        worker_program = (
            "from pathlib import Path\n"
            "import sys\n"
            "Path(sys.argv[1]).write_text('ready')\n"
            "value=1\n"
            "while True:\n"
            " value=(value*6364136223846793005+1)&((1<<64)-1)\n"
        )
        markers = [root / f"worker-{number:03d}.ready" for number in range(int(cpu["worker_count"]))]
        for marker in markers:
            workers.append(subprocess.Popen(
                [sys.executable, "-c", worker_program, str(marker)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ))
        ready_deadline = time.monotonic() + 30
        while not all(marker.is_file() for marker in markers):
            if any(worker.poll() is not None for worker in workers):
                raise RuntimeError("CPU worker exited before readiness")
            if time.monotonic() >= ready_deadline:
                raise RuntimeError("CPU worker readiness deadline expired")
            time.sleep(0.01)
        for number in range(1, RUNS + 1):
            env = os.environ.copy()
            env.update(
                RUNNER_TEMP=str(root),
                X0X_CUSTODY_SCRATCH=str(scratch),
                X0X_ISOLATION_ROLE=f"run-{number:02d}",
                X0X_RUNTIME_TIMEOUT_SECONDS="900",
            )
            role = f"run-{number:02d}"
            env["X0X_ISOLATION_ROLE"] = role
            before = set(root.glob("x0x-isolation-*"))
            started = time.monotonic()
            process = subprocess.Popen([
                sys.executable, "scripts/ci/isolated-runtime.py", sys.executable,
                "scripts/ci/nextest-reuse.py", "run", str(scratch),
                "--no-fail-fast", "-E", f"test(={SELECTOR})",
            ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            active[:] = [process]
            output, _ = process.communicate()
            active.clear()
            custody = isolation_facts(root, before, role, scratch)
            if custody["admitted_exit"] != process.returncode:
                raise RuntimeError("isolated and native exits disagree")
            runs.append({
                "run": number,
                "native_exit": process.returncode,
                "classification": classify(process.returncode, output),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "output_sha256": hashlib.sha256(output).hexdigest(),
                "isolation": custody,
            })
            save()
            if interrupted:
                raise InterruptedError(f"cancelled by signal {interrupted[-1]}")
    finally:
        cleanup = stop_workers(workers)
        receipt.update({
            "phase": "complete" if len(runs) == RUNS else "incomplete",
            "load": {"multiple": 5, **cleanup},
            "selector": SELECTOR,
            "requested_runs": RUNS,
            "completed_runs": len(runs),
            "runs": runs,
        })
        save()
    complete = len(runs) == RUNS and cleanup["started"] == cleanup["reaped"]
    if args.arm == "candidate":
        accepted = complete and all(run["classification"] == "PASS" for run in runs)
    else:
        classifications = {run["classification"] for run in runs}
        accepted = (
            complete
            and classifications <= {"PASS", "EXPECTED_TERMINAL_DIAL_ABORT"}
            and "EXPECTED_TERMINAL_DIAL_ABORT" in classifications
        )
    return 0 if accepted else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arm", choices=("baseline", "candidate"), required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(execute(parse_args()))
