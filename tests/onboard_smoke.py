#!/usr/bin/env python3
"""#894 onboarding smoke: a fresh agent follows ONLY `x0x onboard` output.

The inviter runs x0xd from this build. The new agent gets exactly what an
inviter hands over -- the recipe `x0x onboard` prints and the card file it
writes -- and runs the recipe's shell commands in a fresh HOME:
install (scripts/install.sh from this tree, fed this build's binaries as a
release-layout archive), start, import the inviter's card and DM back. The
recipe's optional last step hands the new agent's card to the inviter, which
replies. Success: the new agent's x0xd is healthy and a DM crossed each way.

Substitutions, all logged in the evidence directory:
  * the recipe's installer URL -> file:// of this tree's scripts/install.sh;
  * X0X_INSTALL_FROM=<dir with the archive built from --bin-dir>, so nothing is
    downloaded from a published release;
  * X0X_NO_HARD_CODED_BOOTSTRAP=1 plus a fresh-HOME config.toml whose only
    bootstrap peer is the inviter. The inviter has no bootstrap peers at all.
Streaming `x0x direct events` runs in the background; `x0x direct send`
is retried as the recipe's note allows.

Both daemons join the network, so this runs only inside the loopback-only
namespace from scripts/ci/isolated-runtime.py and refuses to start anywhere
else (see tests/CLAUDE.md). CI job: "Onboarding smoke (Linux)" in
.github/workflows/integration.yml.

Usage:
  python3 scripts/ci/isolated-runtime.py python3 tests/onboard_smoke.py \\
      --bin-dir target/release --evidence-dir "$RUNNER_TEMP/onboard-smoke"
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH_URL = "https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh"
INVITER_QUIC = "127.0.0.1:25483"
INVITER_API = "127.0.0.1:22700"
LINK_RE = re.compile(r"x0x://agent/[A-Za-z0-9_-]+")
STEP_RE = re.compile(r"^## (\d+)\. (.+?)\n\n```sh\n(.*?)```", re.M | re.S)


class SmokeFailure(Exception):
    pass


def log(msg: str) -> None:
    print(f"[onboard-smoke] {msg}", flush=True)


def require_loopback_namespace() -> None:
    """Fail closed unless the only interface is `lo` (isolated-runtime.py)."""
    if sys.platform != "linux":
        raise SmokeFailure("Linux only: run inside scripts/ci/isolated-runtime.py")
    # /proc/self/net follows this process's network namespace; /sys/class/net
    # shows the namespace sysfs was mounted in (the host's, under unshare).
    lines = Path("/proc/self/net/dev").read_text().splitlines()[2:]
    ifaces = sorted(line.split(":", 1)[0].strip() for line in lines)
    if ifaces != ["lo"]:
        raise SmokeFailure(
            f"refusing to start daemons outside a loopback-only namespace (interfaces: {ifaces})"
        )


def release_platform() -> str:
    arch = {"x86_64": "x64", "aarch64": "arm64"}.get(platform.machine())
    if arch is None:
        raise SmokeFailure(f"unsupported machine {platform.machine()}")
    return f"linux-{arch}-gnu"


def package(bin_dir: Path, dist: Path) -> None:
    """Lay out this build like a release asset (release.yml 'Package (tar.gz)')."""
    plat = release_platform()
    staging = f"x0x-{plat}"
    archive = dist / f"{staging}.tar.gz"
    dist.mkdir(parents=True)
    with tarfile.open(archive, "w:gz") as tar:
        for name in ("x0xd", "x0x"):
            src = bin_dir / name
            if not src.is_file():
                raise SmokeFailure(f"missing built binary {src}")
            tar.add(src, arcname=f"{staging}/{name}")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (dist / f"{archive.name}.sha256").write_text(f"{digest}  {archive.name}\n")
    log(f"packaged {archive.name} sha256={digest}")


def base_env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("XDG_", "X0X_"))}
    env.update(HOME=str(home), NO_COLOR="1")
    return env


def run(cmd, env, cwd, out: Path, timeout: float = 60) -> subprocess.CompletedProcess:
    res = subprocess.run(cmd, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                         capture_output=True, text=True, timeout=timeout)
    with out.open("a") as fh:
        fh.write(f"$ {cmd if isinstance(cmd, str) else shlex.join(cmd)}\n"
                 f"[exit {res.returncode}]\n{res.stdout}{res.stderr}\n")
    return res


def wait_for(what: str, deadline_s: float, probe, interval: float = 2.0):
    end = time.monotonic() + deadline_s
    while True:
        value = probe()
        if value:
            return value
        if time.monotonic() >= end:
            raise SmokeFailure(f"timed out after {deadline_s:.0f}s waiting for {what}")
        time.sleep(interval)


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


class NewAgentShell:
    """Runs recipe lines one at a time; exported variables carry over."""

    def __init__(self, env: dict[str, str], cwd: Path, evidence: Path):
        self.env, self.cwd, self.evidence = env, cwd, evidence
        self.state = cwd.parent / "shell-exports.sh"
        self.state.write_text("")

    def wrap(self, line: str) -> str:
        return (f". {shlex.quote(str(self.state))}\n{line}\n"
                f"__rc=$?\nexport -p > {shlex.quote(str(self.state))}\nexit $__rc\n")

    def run(self, line: str, timeout: float = 60) -> subprocess.CompletedProcess:
        return run(["bash", "-c", self.wrap(line)], self.env, self.cwd,
                   self.evidence / "new-agent-commands.log", timeout)

    def spawn(self, line: str, out: Path) -> subprocess.Popen:
        with (self.evidence / "new-agent-commands.log").open("a") as fh:
            fh.write(f"$ {line}   [background -> {out.name}]\n")
        return subprocess.Popen(["bash", "-c", self.wrap(line)], env=self.env, cwd=self.cwd,
                                stdin=subprocess.DEVNULL, stdout=out.open("w"),
                                stderr=subprocess.STDOUT, start_new_session=True)


def send_with_retry(runner, line: str, what: str, deadline_s: float = 240) -> str:
    """Retry per the recipe note; after 120s of 409s use its --no-durable-ack."""
    start = time.monotonic()
    attempt = line

    def probe():
        nonlocal attempt
        res = runner(attempt)
        if res.returncode == 0:
            return attempt
        if ("recipient_ack_semantics_unavailable" in res.stdout + res.stderr
                and time.monotonic() - start > 120 and "--no-durable-ack" not in attempt):
            attempt = f"{line} --no-durable-ack"
        return None

    return wait_for(what, deadline_s, probe, interval=5)


def events_with_payload(path: Path, payload_b64: str) -> list[dict]:
    """JSON `direct_message` events (inviter runs `--json direct events`)."""
    found = []
    for raw in path.read_text(errors="replace").splitlines():
        try:
            event = json.loads(raw)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get("payload") == payload_b64:
            found.append(event)
    return found


def parse_recipe(text: str) -> list[tuple[str, list[str]]]:
    steps = [(title, [ln for ln in body.splitlines() if ln.strip()])
             for _, title, body in STEP_RE.findall(text)]
    if not steps:
        raise SmokeFailure("x0x onboard printed no recipe steps")
    return steps


def smoke(args, work: Path, evidence: Path, procs: list) -> dict:
    x0xd, x0x = args.bin_dir / "x0xd", args.bin_dir / "x0x"
    dist = work / "dist"
    package(args.bin_dir, dist)

    # ── Inviter: this build, no bootstrap peers, loopback only ────────────
    inv_home = work / "inviter-home"
    inv_cfg = inv_home / ".config" / "x0x" / "config.toml"
    inv_cfg.parent.mkdir(parents=True)
    inv_cfg.write_text(f'bind_address = "{INVITER_QUIC}"\napi_address = "{INVITER_API}"\n'
                       'bootstrap_peers = []\n')
    inv_env = base_env(inv_home)
    procs.append(subprocess.Popen(
        [str(x0xd), "--no-hard-coded-bootstrap", "--skip-update-check"], env=inv_env,
        cwd=inv_home, stdin=subprocess.DEVNULL, start_new_session=True,
        stdout=(evidence / "inviter-x0xd.log").open("w"), stderr=subprocess.STDOUT))
    inv_log = evidence / "inviter-commands.log"

    def inviter(*argv: str, timeout: float = 60):
        return run([str(x0x), *argv], inv_env, inv_home, inv_log, timeout)

    wait_for("inviter x0xd health", 90, lambda: inviter("health").returncode == 0)

    # ── The hand-over: recipe text + card file, nothing else ──────────────
    handover = inv_home / "handover"
    handover.mkdir()
    res = inviter("onboard", "--card-file", str(handover / "x0x-invite-card.txt"))
    if res.returncode != 0:
        raise SmokeFailure(f"x0x onboard failed: {res.stderr.strip()}")
    recipe = res.stdout
    (evidence / "recipe.md").write_text(recipe)
    steps = parse_recipe(recipe)
    log(f"recipe: {len(recipe)} bytes, steps: {[t for t, _ in steps]}")

    # ── New agent: fresh HOME; config pins the inviter as the only peer ───
    new_home = work / "new-home"
    new_cwd = new_home / "onboarding"
    new_cwd.mkdir(parents=True)
    for card in handover.iterdir():
        shutil.copy(card, new_cwd / card.name)
    new_cfg = new_home / ".config" / "x0x" / "config.toml"
    new_cfg.parent.mkdir(parents=True)
    new_cfg.write_text(f'bootstrap_peers = ["{INVITER_QUIC}"]\n')
    new_env = base_env(new_home)
    new_env.update(X0X_INSTALL_FROM=str(dist), X0X_NO_HARD_CODED_BOOTSTRAP="1")
    shell = NewAgentShell(new_env, new_cwd, evidence)

    inviter_events = evidence / "inviter-direct-events.jsonl"
    new_events = evidence / "new-agent-direct-events.log"
    result: dict = {"recipe_steps": [t for t, _ in steps], "substitutions": []}
    sent_text = new_link = None

    for title, lines in steps:
        log(f"step: {title}")
        for line in lines:
            if line.startswith("curl ") and INSTALL_SH_URL in line:
                local = f"file://{args.repo / 'scripts' / 'install.sh'}"
                result["substitutions"].append({"from": INSTALL_SH_URL, "to": local})
                line = line.replace(INSTALL_SH_URL, local)
            if line.startswith("x0x direct events"):
                procs.append(shell.spawn(line, new_events))
                continue
            if line.startswith("x0x direct send "):
                sent_text = shlex.split(line)[4]
                procs.append(subprocess.Popen(
                    [str(x0x), "--json", "direct", "events"], env=inv_env, cwd=inv_home,
                    stdin=subprocess.DEVNULL, stdout=inviter_events.open("w"),
                    stderr=subprocess.STDOUT, start_new_session=True))
                time.sleep(2)
                result["new_agent_send"] = send_with_retry(
                    lambda cmd: shell.run(cmd), line, "new agent -> inviter DM accepted")
                continue
            res = shell.run(line, timeout=300 if "install.sh" in line else 60)
            if line.startswith("x0x agent card"):
                match = LINK_RE.search(res.stdout)
                new_link = match.group(0) if match else None
            if res.returncode != 0:
                raise SmokeFailure(f"recipe command failed ({res.returncode}): {line}\n"
                                   f"{res.stdout[-2000:]}{res.stderr[-2000:]}")

    if sent_text is None:
        raise SmokeFailure("recipe has no `x0x direct send` step")
    if new_link is None:
        raise SmokeFailure("recipe's `x0x agent card` step produced no x0x://agent/ link")

    # ── Direction 1: the inviter received the new agent's DM ──────────────
    got = wait_for("inviter to receive the new agent's DM", 90,
                   lambda: events_with_payload(inviter_events, b64(sent_text)))
    new_id = got[0]["sender"]
    result["new_agent_id"] = new_id
    log(f"inviter received {sent_text!r} from {new_id}")

    # ── Direction 2: inviter imports the handed-back card and replies ─────
    res = inviter("agent", "import", new_link, "--trust", "known")
    if res.returncode != 0:
        raise SmokeFailure(f"inviter could not import the new agent's card: {res.stderr}")
    reply = f"welcome to x0x {secrets.token_hex(6)}"
    result["inviter_send"] = send_with_retry(
        lambda cmd: run(["bash", "-c", cmd], {**inv_env, "PATH": f"{args.bin_dir}:{inv_env['PATH']}"},
                        inv_home, inv_log),
        f"x0x direct send {new_id} {shlex.quote(reply)}", "inviter -> new agent DM accepted")
    wait_for("new agent's `x0x direct events` to show the reply", 90,
             lambda: b64(reply) in new_events.read_text(errors="replace"))
    log(f"new agent received {reply!r}")

    res = shell.run("x0x health")
    if res.returncode != 0:
        raise SmokeFailure(f"new agent x0xd unhealthy at the end: {res.stdout}{res.stderr}")
    result["new_agent_healthy"] = True
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bin-dir", type=Path, required=True, help="dir with built x0xd + x0x")
    ap.add_argument("--repo", type=Path, default=ROOT, help="x0x checkout (for scripts/install.sh)")
    ap.add_argument("--evidence-dir", type=Path, required=True, help="logs + summary.json")
    args = ap.parse_args()
    args.bin_dir, args.repo = args.bin_dir.resolve(), args.repo.resolve()
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    procs: list[subprocess.Popen] = []
    work = Path(tempfile.mkdtemp(prefix="onboard-smoke-"))
    summary: dict = {"ok": False}
    try:
        require_loopback_namespace()
        summary.update(smoke(args, work, evidence, procs))
        summary["ok"] = True
        log("PASS: fresh agent installed, started, and exchanged DMs both ways")
    except (SmokeFailure, subprocess.TimeoutExpired) as exc:
        summary["error"] = str(exc)
        log(f"FAIL: {exc}")
    finally:
        new_bin = work / "new-home" / ".local" / "bin" / "x0x"
        if new_bin.exists():
            subprocess.run([str(new_bin), "stop"], env=base_env(work / "new-home"),
                           capture_output=True, timeout=30, check=False)
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        daemon_log = work / "new-home" / ".local" / "share" / "x0x" / "x0xd.log"
        if daemon_log.exists():
            shutil.copy(daemon_log, evidence / "new-agent-x0xd.log")
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
