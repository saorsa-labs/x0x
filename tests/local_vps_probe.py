#!/usr/bin/env python3
"""Local↔VPS DM probe — runs alongside a fleet soak.

Boots a local x0xd that joins the live VPS bootstrap mesh, then every
PROBE_INTERVAL seconds for DURATION minutes, for each VPS:

  - send DM local → VPS, expect ok:true
  - send DM VPS → local (via ssh-curl), expect ok:true on the VPS side
  - watch local /direct/events SSE for the VPS→local payload

The VPS daemons bind their API to 127.0.0.1:12600, so VPS-side calls go
via `ssh root@<ip> curl ...`. Local-side calls use direct HTTP to
127.0.0.1:19201.

Records per-tick pass/fail counts per peer to a CSV. Prints a summary at
exit.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

NODES = {
    "nyc":       "142.93.199.50",
    "sfo":       "147.182.234.192",
    "singapore": "152.42.210.67",
    "sydney":    "170.64.176.102",
}

DATA_DIR = Path("/tmp/x0x-local-probe")
CONFIG_PATH = DATA_DIR / "config.toml"
LOG_PATH = DATA_DIR / "log"
TOKEN_PATH = DATA_DIR / "api-token"
LOCAL_API = "http://127.0.0.1:19201"

SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            "-o", "ControlMaster=no", "-o", "ControlPath=none"]


def log(msg: str) -> None:
    print(f"[probe] {time.strftime('%H:%M:%S')} {msg}", flush=True)


def ssh_run(ip: str, cmd: str, timeout: float = 12.0) -> tuple[int, str]:
    """Run a shell command on a VPS via SSH; return (exit_code, stdout).

    On timeout or any subprocess failure, return (124, "") so callers see a
    non-zero exit code instead of crashing the probe. SSH timeouts are an
    expected hazard during a 4 h soak (transient mesh stress, route flaps);
    the probe must keep recording instead of dying.
    """
    try:
        proc = subprocess.run(
            ["ssh", *SSH_OPTS, f"root@{ip}", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        return 124, ""
    except Exception:
        return 1, ""


def ssh_get_token(ip: str) -> str:
    rc, out = ssh_run(ip, "cat /root/.local/share/x0x/api-token")
    if rc != 0:
        raise RuntimeError(f"ssh token fetch failed for {ip}")
    return out.strip()


# Default API port — testnet. main() overrides from --network.
API_PORT: int = 13600


def vps_api_get(ip: str, token: str, path: str) -> tuple[int, dict]:
    """GET a VPS API path via ssh-curl."""
    cmd = (f"curl -s -m 8 -H 'Authorization: Bearer {token}' "
           f"-w '\\n%{{http_code}}' http://127.0.0.1:{API_PORT}{path}")
    rc, out = ssh_run(ip, cmd, timeout=14.0)
    if rc != 0:
        return 0, {"error": "ssh_failed"}
    parts = out.rsplit("\n", 1)
    if len(parts) != 2:
        return 0, {"error": "no_status"}
    body, status = parts[0], parts[1].strip()
    try:
        return int(status), json.loads(body) if body else {}
    except Exception:
        return int(status) if status.isdigit() else 0, {"raw": body[:200]}


def vps_api_post(ip: str, token: str, path: str, body: dict) -> tuple[int, dict]:
    """POST JSON to a VPS API path via ssh-curl."""
    body_json = json.dumps(body).replace("'", "'\\''")
    cmd = (f"curl -s -m 8 -X POST "
           f"-H 'Authorization: Bearer {token}' "
           f"-H 'Content-Type: application/json' "
           f"-d '{body_json}' "
           f"-w '\\n%{{http_code}}' http://127.0.0.1:{API_PORT}{path}")
    rc, out = ssh_run(ip, cmd, timeout=16.0)
    if rc != 0:
        return 0, {"error": "ssh_failed"}
    parts = out.rsplit("\n", 1)
    if len(parts) != 2:
        return 0, {"error": "no_status"}
    body_str, status = parts[0], parts[1].strip()
    try:
        return int(status), json.loads(body_str) if body_str else {}
    except Exception:
        return int(status) if status.isdigit() else 0, {"raw": body_str[:200]}


def http_request(method: str, url: str, token: str, body: dict | None = None,
                 timeout: float = 10.0) -> tuple[int, dict]:
    data = None
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return 0, {"error": str(e)}


def wait_for_local_health(deadline_secs: int = 30) -> bool:
    token = TOKEN_PATH.read_text().strip() if TOKEN_PATH.exists() else ""
    for _ in range(deadline_secs):
        status, body = http_request("GET", f"{LOCAL_API}/health", token, timeout=2.0)
        if status == 200 and body.get("ok"):
            return True
        time.sleep(1)
    return False


def get_local_agent_id(token: str) -> str | None:
    status, body = http_request("GET", f"{LOCAL_API}/agent", token)
    if status != 200:
        return None
    return body.get("agent_id")


def get_vps_agent_id(ip: str, token: str) -> str | None:
    status, body = vps_api_get(ip, token, "/agent")
    if status != 200:
        return None
    return body.get("agent_id")


def local_dm_send(local_token: str, recipient_agent_id: str, payload: bytes) -> dict:
    body = {
        "agent_id": recipient_agent_id,
        "payload": base64.b64encode(payload).decode(),
    }
    _, resp = http_request("POST", f"{LOCAL_API}/direct/send", local_token,
                           body=body, timeout=15.0)
    return resp


def vps_dm_send(ip: str, token: str, recipient_agent_id: str, payload: bytes) -> dict:
    body = {
        "agent_id": recipient_agent_id,
        "payload": base64.b64encode(payload).decode(),
    }
    _, resp = vps_api_post(ip, token, "/direct/send", body)
    return resp


def local_dm_recv(local_token: str, sender_agent_id: str, expected: bytes,
                  wait_secs: float = 5.0,
                  watcher: "DirectEventWatcher | None" = None) -> bool:
    if watcher is None:
        watcher = DirectEventWatcher(local_token)
        watcher.start()
        try:
            return watcher.wait_for(sender_agent_id, expected, wait_secs)
        finally:
            watcher.stop()
    return watcher.wait_for(sender_agent_id, expected, wait_secs)


class DirectEventWatcher:
    """Long-lived /direct/events SSE consumer for local inbound DMs."""

    def __init__(self, token: str) -> None:
        self.token = token
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._cv = threading.Condition()
        self._messages: list[tuple[str, bytes]] = []
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()
        self._ready.wait(timeout=5.0)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)

    def wait_for(self, sender_agent_id: str, expected: bytes, wait_secs: float) -> bool:
        deadline = time.time() + wait_secs
        with self._cv:
            while True:
                if any(sender == sender_agent_id and payload == expected
                       for sender, payload in self._messages):
                    return True
                remaining = deadline - time.time()
                if remaining <= 0:
                    return False
                self._cv.wait(timeout=min(0.5, remaining))

    def _run(self) -> None:
        while not self._stop.is_set():
            req = urllib.request.Request(f"{LOCAL_API}/direct/events", method="GET")
            req.add_header("Authorization", f"Bearer {self.token}")
            try:
                with urllib.request.urlopen(req, timeout=15.0) as resp:
                    self._ready.set()
                    event_type = "message"
                    data_lines: list[str] = []
                    while not self._stop.is_set():
                        raw = resp.readline()
                        if not raw:
                            break
                        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                        if line == "":
                            if data_lines:
                                self._route_event(event_type, "\n".join(data_lines))
                            event_type = "message"
                            data_lines = []
                            continue
                        if line.startswith(":"):
                            continue
                        if line.startswith("event:"):
                            event_type = line[6:].strip()
                        elif line.startswith("data:"):
                            data_lines.append(line[5:].lstrip())
            except Exception:
                self._ready.set()
                if not self._stop.is_set():
                    time.sleep(1)

    def _route_event(self, event_type: str, data: str) -> None:
        if event_type != "direct_message":
            return
        try:
            msg = json.loads(data)
            sender = msg.get("sender") or ""
            payload = base64.b64decode(msg.get("payload") or "")
        except Exception:
            return
        with self._cv:
            self._messages.append((sender, payload))
            if len(self._messages) > 1000:
                del self._messages[:500]
            self._cv.notify_all()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--network", choices=["test", "prod"], default="test",
                    help="Which VPS fleet to probe. Default 'test' (testnet 6483/13600). "
                         "'prod' probes the production fleet (REAL USERS, 5s Ctrl-C window).")
    ap.add_argument("--duration-mins", type=float, default=30.0)
    ap.add_argument("--probe-interval-secs", type=int, default=60)
    ap.add_argument("--out-dir", default="proofs/local-probe")
    ap.add_argument("--x0xd", default="target/release/x0xd")
    args = ap.parse_args()

    # Network selection — banner + 5s hold on prod. Sets API_PORT for the
    # vps_api_get/post curl calls below (which substitute it via .format()).
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent))
    from x0x_network import select_network as _x0x_select, banner as _x0x_banner
    _net = _x0x_select(args)
    _x0x_banner(_net)
    global API_PORT
    API_PORT = _net.api_port

    out_dir = Path(args.out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)
    DATA_DIR.mkdir(parents=True)

    config = """instance_name = "local-probe"
network_id = "x0x.prod"
data_dir = "/tmp/x0x-local-probe"
bind_address = "0.0.0.0:15484"
api_address = "127.0.0.1:19201"
log_level = "warn"
"""
    CONFIG_PATH.write_text(config)

    x0xd = Path(args.x0xd).resolve()
    if not x0xd.exists():
        log(f"x0xd binary not found at {x0xd}")
        return 1

    log(f"booting local x0xd: {x0xd}")
    log_fh = LOG_PATH.open("w")
    proc = subprocess.Popen(
        [str(x0xd), "--config", str(CONFIG_PATH)],
        stdout=log_fh, stderr=subprocess.STDOUT,
    )
    local_events: DirectEventWatcher | None = None

    try:
        if not wait_for_local_health(deadline_secs=30):
            log("local x0xd failed to come up; check log")
            log(LOG_PATH.read_text()[-2000:])
            return 1

        local_token = TOKEN_PATH.read_text().strip()
        local_aid = get_local_agent_id(local_token)
        log(f"local agent_id: {local_aid[:16]}...")

        log("fetching VPS API tokens via SSH")
        vps_tokens = {name: ssh_get_token(ip) for name, ip in NODES.items()}

        log("fetching VPS agent_ids via SSH-curl")
        vps_agents: dict[str, str] = {}
        for name, ip in NODES.items():
            aid = get_vps_agent_id(ip, vps_tokens[name])
            if aid:
                vps_agents[name] = aid
                log(f"  {name}: {aid[:16]}...")
            else:
                log(f"  {name}: failed (skipping)")

        if not vps_agents:
            log("no VPS agent_ids resolved; aborting probe")
            return 1

        log("settling for 30s to let local node discover VPS peers via gossip")
        time.sleep(30)

        local_events = DirectEventWatcher(local_token)
        local_events.start()

        csv_path = out_dir / "probe.csv"
        with csv_path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["tick_unix", "tick_iso", "node",
                             "local_to_vps_send_ok", "vps_to_local_send_ok",
                             "vps_to_local_recv_ok", "rtt_dm_local_to_vps_ms"])

            duration_secs = int(args.duration_mins * 60)
            start = time.time()
            tick = 0
            counts = {n: {"l2v_send": 0, "v2l_send": 0, "v2l_recv": 0, "fail": 0}
                      for n in vps_agents}

            while time.time() - start < duration_secs:
                tick += 1
                tick_unix = int(time.time())
                tick_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(tick_unix))
                log(f"tick {tick}: probing {len(vps_agents)} VPS")

                for name in vps_agents:
                    vps_ip = NODES[name]
                    vps_tok = vps_tokens[name]
                    vps_aid = vps_agents[name]

                    payload_l2v = f"probe-l2v-{tick}-{name}".encode()
                    t0 = time.time()
                    resp = local_dm_send(local_token, vps_aid, payload_l2v)
                    rtt_ms = int((time.time() - t0) * 1000)
                    l2v_send_ok = bool(resp.get("ok")) if isinstance(resp, dict) else False
                    if l2v_send_ok:
                        counts[name]["l2v_send"] += 1

                    payload_v2l = f"probe-v2l-{tick}-{name}".encode()
                    resp = vps_dm_send(vps_ip, vps_tok, local_aid, payload_v2l)
                    v2l_send_ok = bool(resp.get("ok")) if isinstance(resp, dict) else False
                    if v2l_send_ok:
                        counts[name]["v2l_send"] += 1

                    v2l_recv_ok = False
                    if v2l_send_ok:
                        v2l_recv_ok = local_dm_recv(local_token, vps_aid,
                                                    payload_v2l, wait_secs=5.0,
                                                    watcher=local_events)
                        if v2l_recv_ok:
                            counts[name]["v2l_recv"] += 1

                    if not (l2v_send_ok and v2l_send_ok and v2l_recv_ok):
                        counts[name]["fail"] += 1
                        log(f"  {name}: FAIL l2v_send={l2v_send_ok} "
                            f"v2l_send={v2l_send_ok} v2l_recv={v2l_recv_ok}")

                    writer.writerow([tick_unix, tick_iso, name,
                                     int(l2v_send_ok), int(v2l_send_ok),
                                     int(v2l_recv_ok), rtt_ms])
                    f.flush()

                elapsed = int(time.time() - start)
                remaining = duration_secs - elapsed
                if remaining <= 0:
                    break
                sleep_for = min(args.probe_interval_secs, max(1, remaining))
                time.sleep(sleep_for)

        summary = out_dir / "summary.md"
        total_ticks = tick
        with summary.open("w") as f:
            f.write(f"# Local↔VPS DM probe summary\n\n")
            f.write(f"- Duration: {args.duration_mins} min, {total_ticks} ticks at "
                    f"{args.probe_interval_secs}s interval\n")
            f.write(f"- Local agent_id: `{local_aid[:16]}…`\n\n")
            f.write("| Node | l2v_send | v2l_send | v2l_recv | fail |\n")
            f.write("|---|---:|---:|---:|---:|\n")
            for n in vps_agents:
                c = counts[n]
                f.write(f"| {n} | {c['l2v_send']}/{total_ticks} | "
                        f"{c['v2l_send']}/{total_ticks} | "
                        f"{c['v2l_recv']}/{total_ticks} | {c['fail']} |\n")
            total_pass = sum(c["l2v_send"] + c["v2l_send"] + c["v2l_recv"]
                             for c in counts.values())
            total_attempts = total_ticks * len(vps_agents) * 3
            rate = total_pass / total_attempts if total_attempts else 0
            f.write(f"\n**Net delivery rate**: {total_pass}/{total_attempts} = "
                    f"{rate:.1%}\n")
        log(f"summary: {summary}")
        log(f"csv: {csv_path}")
        log(f"counts: {counts}")
        return 0

    finally:
        if local_events is not None:
            local_events.stop()
        log("shutting down local x0xd")
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log_fh.close()


if __name__ == "__main__":
    sys.exit(main())
