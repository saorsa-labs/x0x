#!/usr/bin/env python3
"""Live MacBook/studio x0x smoke suite.

This is intentionally not a CI test. It starts one local installed x0xd and one
studio x0xd over SSH, opens an SSH tunnel to the studio API/GUI, then proves the
distributed GUI-facing flows with unique per-run payloads.

Environment:
  STUDIO_SSH_TARGET=studio1@studio1.local
  LOCAL_X0XD=/Users/davidirvine/.local/bin/x0xd
  REMOTE_X0XD=/Users/studio1/.local/bin/x0xd
  KEEP_X0X_STUDIO_LIVE=1
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
STUDIO = os.environ.get("STUDIO_SSH_TARGET", "studio1@studio1.local")
LOCAL_X0XD = Path(
    os.environ.get("LOCAL_X0XD", "/Users/davidirvine/.local/bin/x0xd")
)
if not LOCAL_X0XD.exists():
    LOCAL_X0XD = ROOT / "target" / "release" / "x0xd"
REMOTE_X0XD = os.environ.get("REMOTE_X0XD", "/Users/studio1/.local/bin/x0xd")
KEEP = os.environ.get("KEEP_X0X_STUDIO_LIVE") == "1"
MANIFEST_PATH = os.environ.get("X0X_STUDIO_MANIFEST")


def pick_tcp_port() -> int:
    for _ in range(200):
        port = random.randint(22000, 52000)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("could not pick a free TCP port")


RUN_ID = f"{int(time.time())}-{os.getpid()}-{random.randint(1000, 9999)}"
LOCAL_NAME = f"live-macbook-{RUN_ID}"
REMOTE_NAME = f"live-studio-{RUN_ID}"
LOCAL_DIR = Path(tempfile.mkdtemp(prefix=f"x0x-live-macbook-{RUN_ID}-", dir="/tmp"))
REMOTE_DIR = f"/tmp/x0x-live-studio-{RUN_ID}"
LOCAL_API = pick_tcp_port()
LOCAL_QUIC = pick_tcp_port()
TUNNEL_PORT = pick_tcp_port()
REMOTE_API = int(os.environ.get("REMOTE_API_PORT", "0"))
REMOTE_QUIC = int(os.environ.get("REMOTE_QUIC_PORT", "0"))
PROCS: list[subprocess.Popen[Any]] = []
PASSES = 0
REMOTE_PID: str | None = None


def log(message: str) -> None:
    print(message, flush=True)


def ok(label: str, detail: str = "") -> None:
    global PASSES
    PASSES += 1
    log(f"PASS {label}" + (f": {detail}" if detail else ""))


def die(label: str, detail: str = "") -> None:
    raise AssertionError(f"FAIL {label}" + (f": {detail}" if detail else ""))


def run_cmd(
    args: list[str],
    *,
    input_text: str | None = None,
    timeout: float = 30,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        args,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed {args}: rc={proc.returncode}\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return proc


def ssh(command: str, *, timeout: float = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run_cmd(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            STUDIO,
            command,
        ],
        timeout=timeout,
        check=check,
    )


def pick_remote_tcp_ports(count: int) -> list[int]:
    script = f"""
python3 - <<'PY'
import random
import socket
import sys

sockets = []
ports = []
count = {count}
try:
    for _ in range(count):
        for _attempt in range(300):
            port = random.randint(22000, 52000)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("0.0.0.0", port))
            except OSError:
                sock.close()
                continue
            sockets.append(sock)
            ports.append(port)
            break
        else:
            raise RuntimeError("could not pick a free TCP port")
    print(" ".join(str(port) for port in ports))
finally:
    for sock in sockets:
        sock.close()
PY
"""
    proc = ssh(script, timeout=20)
    ports = [int(part) for part in proc.stdout.split()]
    if len(ports) != count or len(set(ports)) != count:
        die("studio remote ports", proc.stdout.strip())
    return ports


def b64(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return base64.b64encode(value).decode()


def api_url(port: int, path: str) -> str:
    return f"http://127.0.0.1:{port}{path}"


def http_json(
    port: int,
    token: str | None,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    timeout: float = 20,
    allow_status: set[int] | None = None,
    require_ok: bool = True,
) -> dict[str, Any]:
    headers: dict[str, str] = {}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    request = urllib.request.Request(
        api_url(port, path), data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as err:
        raw = err.read()
        status = err.code
    text = raw.decode(errors="replace") if raw else ""
    try:
        parsed: dict[str, Any] = json.loads(text) if text else {}
    except json.JSONDecodeError:
        parsed = {"raw": text}
    status_ok = 200 <= status < 300 if allow_status is None else status in allow_status
    if not status_ok:
        die(f"{method} {path}", f"HTTP {status}: {text[:500]}")
    if require_ok and parsed.get("ok") is False:
        die(f"{method} {path}", f"ok=false: {parsed}")
    return parsed


def http_text(port: int, token: str | None, path: str, *, timeout: float = 15) -> str:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = urllib.request.Request(api_url(port, path), headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode(errors="replace")


def wait_health(port: int, label: str) -> None:
    deadline = time.time() + 60
    last: Any = None
    while time.time() < deadline:
        try:
            response = http_json(
                port, None, "GET", "/health", timeout=2, require_ok=False
            )
            if response.get("ok") is True:
                ok(f"{label} health")
                return
            last = response
        except Exception as exc:  # noqa: BLE001 - diagnostic surface
            last = exc
        time.sleep(1)
    die(f"{label} health", str(last))


def wait_file(path: Path, label: str) -> str:
    deadline = time.time() + 30
    while time.time() < deadline:
        if path.exists():
            return path.read_text().strip()
        time.sleep(0.25)
    die(label, f"{path} missing")
    raise AssertionError("unreachable")


class SseCollector:
    def __init__(self, name: str, port: int, token: str, path: str):
        self.name = name
        self.port = port
        self.token = token
        self.path = path
        self.events: list[dict[str, Any]] = []
        self.error: str | None = None
        self.ready = threading.Event()
        self.lock = threading.Lock()
        self.stop = False
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(8):
            die(f"{self.name} SSE", "did not connect")
        if self.error:
            die(f"{self.name} SSE", self.error)

    def _run(self) -> None:
        request = urllib.request.Request(
            api_url(self.port, self.path),
            headers={"Authorization": f"Bearer {self.token}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                self.ready.set()
                event_name: str | None = None
                data_lines: list[str] = []
                while not self.stop:
                    raw = response.readline()
                    if not raw:
                        break
                    line = raw.decode(errors="replace").rstrip("\r\n")
                    if not line or line.startswith(":"):
                        if data_lines:
                            data = "\n".join(data_lines)
                            try:
                                parsed: Any = json.loads(data)
                            except json.JSONDecodeError:
                                parsed = data
                            with self.lock:
                                self.events.append(
                                    {"event": event_name, "data": parsed, "raw": data}
                                )
                            data_lines = []
                            event_name = None
                        continue
                    if line.startswith("event:"):
                        event_name = line[6:].strip()
                    elif line.startswith("data:"):
                        data_lines.append(line[5:].strip())
        except Exception as exc:  # noqa: BLE001 - reported by harness
            self.error = repr(exc)
            self.ready.set()

    def snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.events)

    def wait_for(
        self, predicate: Callable[[dict[str, Any]], bool], timeout: float = 35
    ) -> dict[str, Any] | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            for event in self.snapshot():
                try:
                    if predicate(event):
                        return event
                except Exception:
                    pass
            time.sleep(0.25)
        return None


def direct_payload_text(event: dict[str, Any]) -> str:
    try:
        payload = (event.get("data") or {}).get("payload", "")
        return base64.b64decode(payload).decode(errors="replace")
    except Exception:
        return ""


def pubsub_payload_text(event: dict[str, Any]) -> str:
    try:
        payload = ((event.get("data") or {}).get("data") or {}).get("payload", "")
        return base64.b64decode(payload).decode(errors="replace")
    except Exception:
        return ""


def pubsub_topic(event: dict[str, Any]) -> str:
    return (((event.get("data") or {}).get("data") or {}).get("topic") or "")


def cleanup(success: bool) -> None:
    if KEEP:
        log("KEEP_X0X_STUDIO_LIVE=1; leaving run-created daemons and SSH tunnel running")
        log(f"left local_dir={LOCAL_DIR}")
        log(f"left remote_dir={REMOTE_DIR}")
        return
    for proc in reversed(PROCS):
        try:
            proc.terminate()
        except Exception:
            pass
    time.sleep(1)
    for proc in reversed(PROCS):
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass
    ssh(
        f"if [ -f {shlex.quote(REMOTE_DIR)}/pid ]; then "
        f"kill -TERM $(cat {shlex.quote(REMOTE_DIR)}/pid) 2>/dev/null || true; "
        "sleep 1; "
        f"kill -KILL $(cat {shlex.quote(REMOTE_DIR)}/pid) 2>/dev/null || true; "
        "fi",
        timeout=20,
        check=False,
    )
    if success and not KEEP:
        ssh(f"rm -rf {shlex.quote(REMOTE_DIR)}", timeout=20, check=False)
        ssh(f"rm -rf ~/.x0x-{shlex.quote(REMOTE_NAME)}", timeout=20, check=False)
        shutil.rmtree(Path.home() / f".x0x-{LOCAL_NAME}", ignore_errors=True)
        shutil.rmtree(LOCAL_DIR, ignore_errors=True)


def write_config(path: Path, api_port: int, quic_port: int, data_dir: str) -> None:
    path.write_text(
        "\n".join(
            [
                f'api_address = "127.0.0.1:{api_port}"',
                f'bind_address = "0.0.0.0:{quic_port}"',
                f'data_dir = "{data_dir}"',
                "bootstrap_peers = []",
                'log_level = "info"',
                "rendezvous_enabled = false",
                "heartbeat_interval_secs = 2",
                "identity_ttl_secs = 30",
                "presence_beacon_interval_secs = 2",
                "presence_event_poll_interval_secs = 2",
                "presence_offline_timeout_secs = 10",
                "directory_digest_interval_secs = 2",
                "group_card_republish_interval_secs = 0",
                "[update]",
                "enabled = false",
                "",
            ]
        )
    )


def start_daemons() -> tuple[str, str]:
    global REMOTE_API, REMOTE_QUIC, REMOTE_PID
    if REMOTE_API <= 0 or REMOTE_QUIC <= 0:
        REMOTE_API, REMOTE_QUIC = pick_remote_tcp_ports(2)
    if REMOTE_API == REMOTE_QUIC:
        die("studio remote ports distinct", f"{REMOTE_API} == {REMOTE_QUIC}")

    log(f"run={RUN_ID}")
    log(f"local_dir={LOCAL_DIR}")
    log(f"remote_dir={REMOTE_DIR}")
    log(
        "ports "
        f"local_api={LOCAL_API} local_quic={LOCAL_QUIC} "
        f"tunnel={TUNNEL_PORT} remote_api={REMOTE_API} remote_quic={REMOTE_QUIC}"
    )
    if not LOCAL_X0XD.exists():
        die("local x0xd exists", str(LOCAL_X0XD))
    ok("local x0xd selected", str(LOCAL_X0XD))

    local_config = LOCAL_DIR / "config.toml"
    write_config(local_config, LOCAL_API, LOCAL_QUIC, str(LOCAL_DIR))
    local_log = open(LOCAL_DIR / "x0xd.log", "wb")
    local_proc = subprocess.Popen(
        [
            str(LOCAL_X0XD),
            "--config",
            str(local_config),
            "--name",
            LOCAL_NAME,
            "--skip-update-check",
        ],
        stdout=local_log,
        stderr=subprocess.STDOUT,
    )
    PROCS.append(local_proc)
    wait_health(LOCAL_API, "macbook daemon")
    local_token = wait_file(LOCAL_DIR / "api-token", "local API token")
    ok("macbook token created")

    remote_config = "\n".join(
        [
            f'api_address = "127.0.0.1:{REMOTE_API}"',
            f'bind_address = "0.0.0.0:{REMOTE_QUIC}"',
            f'data_dir = "{REMOTE_DIR}"',
            "bootstrap_peers = []",
            'log_level = "info"',
            "rendezvous_enabled = false",
            "heartbeat_interval_secs = 2",
            "identity_ttl_secs = 30",
            "presence_beacon_interval_secs = 2",
            "presence_event_poll_interval_secs = 2",
            "presence_offline_timeout_secs = 10",
            "directory_digest_interval_secs = 2",
            "group_card_republish_interval_secs = 0",
            "[update]",
            "enabled = false",
            "",
        ]
    )
    remote_script = f"""
set -eu
rm -rf {shlex.quote(REMOTE_DIR)}
mkdir -p {shlex.quote(REMOTE_DIR)}
cat > {shlex.quote(REMOTE_DIR)}/config.toml <<'EOF_CFG'
{remote_config}EOF_CFG
nohup {shlex.quote(REMOTE_X0XD)} --config {shlex.quote(REMOTE_DIR)}/config.toml --name {shlex.quote(REMOTE_NAME)} --skip-update-check > {shlex.quote(REMOTE_DIR)}/x0xd.log 2>&1 &
echo $! > {shlex.quote(REMOTE_DIR)}/pid
cat {shlex.quote(REMOTE_DIR)}/pid
"""
    proc = run_cmd(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            STUDIO,
            "sh",
            "-s",
        ],
        input_text=remote_script,
        timeout=30,
    )
    REMOTE_PID = proc.stdout.strip()
    log(f"remote_pid={REMOTE_PID}")
    ok("studio daemon started")

    tunnel = subprocess.Popen(
        [
            "ssh",
            "-N",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "BatchMode=yes",
            "-L",
            f"127.0.0.1:{TUNNEL_PORT}:127.0.0.1:{REMOTE_API}",
            STUDIO,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    PROCS.append(tunnel)
    wait_health(TUNNEL_PORT, "studio daemon via SSH tunnel")
    studio_token = ssh(f"cat {shlex.quote(REMOTE_DIR)}/api-token", timeout=15).stdout.strip()
    ok("studio token created")
    return local_token, studio_token


def write_manifest(
    local_token: str,
    studio_token: str,
    mac: dict[str, str] | None = None,
    studio: dict[str, str] | None = None,
) -> None:
    if not MANIFEST_PATH:
        return
    manifest = {
        "run_id": RUN_ID,
        "keep": KEEP,
        "studio_ssh_target": STUDIO,
        "local": {
            "name": LOCAL_NAME,
            "api_base": f"http://127.0.0.1:{LOCAL_API}",
            "api_port": LOCAL_API,
            "quic_port": LOCAL_QUIC,
            "token": local_token,
            "data_dir": str(LOCAL_DIR),
            "pid": PROCS[0].pid if PROCS else None,
            "agent": mac,
        },
        "studio": {
            "name": REMOTE_NAME,
            "api_base": f"http://127.0.0.1:{TUNNEL_PORT}",
            "tunnel_port": TUNNEL_PORT,
            "remote_api_port": REMOTE_API,
            "remote_quic_port": REMOTE_QUIC,
            "token": studio_token,
            "remote_dir": REMOTE_DIR,
            "remote_pid": REMOTE_PID,
            "agent": studio,
        },
        "ssh_tunnel": {
            "local_port": TUNNEL_PORT,
            "remote_host": "127.0.0.1",
            "remote_port": REMOTE_API,
            "pid": PROCS[-1].pid if PROCS else None,
        },
    }
    path = Path(MANIFEST_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    ok("studio run manifest written", str(path))


def assert_gui(studio_token: str) -> None:
    gui = http_text(TUNNEL_PORT, studio_token, "/gui")
    for needle in [
        "Subsystem Diagnostics",
        "Remote Exec",
        "admin-sign-payload",
        "/agent/sign",
        "/diagnostics/groups",
        "/exec/run",
    ]:
        if needle not in gui:
            die("studio GUI served patched surface", f"missing {needle}")
    ok("studio GUI served through SSH forwarding", f"{len(gui)} bytes")


def connect_agents(local_token: str, studio_token: str) -> tuple[dict[str, str], dict[str, str]]:
    mac = http_json(LOCAL_API, local_token, "GET", "/agent")
    studio = http_json(TUNNEL_PORT, studio_token, "GET", "/agent")
    if mac["agent_id"] == studio["agent_id"]:
        die("distinct live agent IDs")
    ok(
        "distinct live agent IDs",
        f"mac={mac['agent_id'][:12]} studio={studio['agent_id'][:12]}",
    )

    mac_card = http_json(
        LOCAL_API,
        local_token,
        "GET",
        "/agent/card?include_local_addresses=true&display_name=MacBook%20Live",
    )
    studio_card = http_json(
        TUNNEL_PORT,
        studio_token,
        "GET",
        "/agent/card?include_local_addresses=true&display_name=Studio%20Live",
    )
    mac_addrs = (mac_card.get("card") or {}).get("addresses") or []
    studio_addrs = (studio_card.get("card") or {}).get("addresses") or []
    if not mac_addrs:
        die("macbook card has local addresses")
    if not studio_addrs:
        die("studio card has local addresses")
    ok("macbook card addresses", ",".join(mac_addrs[:5]))
    ok("studio card addresses", ",".join(studio_addrs[:5]))

    http_json(
        LOCAL_API,
        local_token,
        "POST",
        "/agent/card/import",
        {"card": studio_card["link"], "trust_level": "Trusted"},
    )
    http_json(
        TUNNEL_PORT,
        studio_token,
        "POST",
        "/agent/card/import",
        {"card": mac_card["link"], "trust_level": "Trusted"},
    )
    if studio["agent_id"] not in json.dumps(
        http_json(LOCAL_API, local_token, "GET", "/contacts")
    ):
        die("macbook sees studio contact")
    if mac["agent_id"] not in json.dumps(
        http_json(TUNNEL_PORT, studio_token, "GET", "/contacts")
    ):
        die("studio sees macbook contact")
    ok("cards imported into contacts both ways")

    response = http_json(
        LOCAL_API,
        local_token,
        "POST",
        "/agents/connect",
        {"agent_id": studio["agent_id"]},
        timeout=75,
    )
    if response.get("outcome") not in {"Direct", "Coordinated", "AlreadyConnected"}:
        die("macbook connects to studio", json.dumps(response))
    ok("macbook connects to studio", response.get("outcome", ""))
    time.sleep(2)

    response = http_json(
        TUNNEL_PORT,
        studio_token,
        "POST",
        "/agents/connect",
        {"agent_id": mac["agent_id"]},
        timeout=75,
    )
    if response.get("outcome") not in {"Direct", "Coordinated", "AlreadyConnected"}:
        die("studio connects to macbook", json.dumps(response))
    ok("studio connects to macbook", response.get("outcome", ""))
    time.sleep(3)
    return mac, studio


def direct_messages(local_token: str, studio_token: str, mac_id: str, studio_id: str) -> None:
    mac_stream = SseCollector("macbook /direct/events", LOCAL_API, local_token, "/direct/events")
    studio_stream = SseCollector(
        "studio /direct/events", TUNNEL_PORT, studio_token, "/direct/events"
    )
    mac_stream.start()
    studio_stream.start()
    ok("direct SSE streams connected")

    mac_to_studio = f"live macbook to studio {RUN_ID}"
    studio_to_mac = f"live studio to macbook {RUN_ID}"
    http_json(
        LOCAL_API,
        local_token,
        "POST",
        "/direct/send",
        {"agent_id": studio_id, "payload": b64(mac_to_studio)},
        timeout=30,
    )
    if not studio_stream.wait_for(
        lambda event: direct_payload_text(event) == mac_to_studio
        and (event.get("data") or {}).get("verified") is True,
        timeout=35,
    ):
        die(
            "studio receives verified direct DM from macbook",
            json.dumps(studio_stream.snapshot())[:1000],
        )
    ok("studio receives verified direct DM from macbook", mac_to_studio)

    http_json(
        TUNNEL_PORT,
        studio_token,
        "POST",
        "/direct/send",
        {"agent_id": mac_id, "payload": b64(studio_to_mac)},
        timeout=30,
    )
    if not mac_stream.wait_for(
        lambda event: direct_payload_text(event) == studio_to_mac
        and (event.get("data") or {}).get("verified") is True,
        timeout=35,
    ):
        die(
            "macbook receives verified direct DM from studio",
            json.dumps(mac_stream.snapshot())[:1000],
        )
    ok("macbook receives verified direct DM from studio", studio_to_mac)


def contacts(local_token: str, studio_token: str, mac: dict[str, str], studio: dict[str, str]) -> None:
    fake_agent = "11" * 32
    fake_machine = "22" * 32
    cases = [
        ("macbook", LOCAL_API, local_token, studio["agent_id"], studio["machine_id"]),
        ("studio", TUNNEL_PORT, studio_token, mac["agent_id"], mac["machine_id"]),
    ]
    for label, port, token, peer_id, peer_machine in cases:
        http_json(
            port,
            token,
            "POST",
            "/contacts",
            {"agent_id": fake_agent, "trust_level": "Unknown", "label": f"{label}-fake"},
        )
        for level in ["Known", "Trusted", "Blocked"]:
            http_json(port, token, "PATCH", f"/contacts/{fake_agent}", {"trust_level": level})
        decision = http_json(
            port,
            token,
            "POST",
            "/trust/evaluate",
            {"agent_id": fake_agent, "machine_id": fake_machine},
        )
        if "RejectBlocked" not in json.dumps(decision):
            die(f"{label} fake contact blocked evaluation", json.dumps(decision))
        http_json(port, token, "PATCH", f"/contacts/{fake_agent}", {"trust_level": "Trusted"})
        http_json(port, token, "POST", "/contacts/trust", {"agent_id": fake_agent, "level": "Known"})
        http_json(port, token, "DELETE", f"/contacts/{fake_agent}")
        if fake_agent in json.dumps(http_json(port, token, "GET", "/contacts")):
            die(f"{label} fake contact removed")

        http_json(port, token, "PATCH", f"/contacts/{peer_id}", {"trust_level": "Blocked"})
        decision = http_json(
            port,
            token,
            "POST",
            "/trust/evaluate",
            {"agent_id": peer_id, "machine_id": peer_machine},
        )
        if "RejectBlocked" not in json.dumps(decision):
            die(f"{label} real peer blocked evaluation", json.dumps(decision))
        http_json(port, token, "PATCH", f"/contacts/{peer_id}", {"trust_level": "Trusted"})
        decision = http_json(
            port,
            token,
            "POST",
            "/trust/evaluate",
            {"agent_id": peer_id, "machine_id": peer_machine},
        )
        if "RejectBlocked" in json.dumps(decision):
            die(f"{label} real peer unblocked evaluation", json.dumps(decision))
        ok(f"{label} add/remove/block/unblock contact lifecycle")


def diagnostics_and_signing(local_token: str, studio_token: str) -> None:
    for label, port, token in [
        ("macbook", LOCAL_API, local_token),
        ("studio", TUNNEL_PORT, studio_token),
    ]:
        signed = http_json(
            port,
            token,
            "POST",
            "/agent/sign",
            {"payload_b64": b64(f"signature proof {label} {RUN_ID}")},
        )
        for key in ["agent_id", "public_key_b64", "signature_b64", "algorithm"]:
            if key not in signed:
                die(f"{label} agent sign response", f"missing {key}: {signed}")
        for path in [
            "/diagnostics/ack",
            "/diagnostics/dm",
            "/diagnostics/groups",
            "/diagnostics/exec",
            "/exec/sessions",
        ]:
            http_json(port, token, "GET", path, require_ok=False)
        bad = http_json(
            port,
            token,
            "POST",
            "/exec/run",
            {"agent_id": "nothex", "argv": ["echo", "x"]},
            allow_status={400},
            require_ok=False,
        )
        if "invalid" not in json.dumps(bad).lower() and "agent_id" not in json.dumps(bad).lower():
            die(f"{label} exec bad request validation", json.dumps(bad))
        cancel = http_json(
            port,
            token,
            "POST",
            "/exec/cancel",
            {"request_id": "nothex"},
            allow_status={400},
            require_ok=False,
        )
        if "invalid" not in json.dumps(cancel).lower() and "request" not in json.dumps(cancel).lower():
            die(f"{label} exec cancel validation", json.dumps(cancel))
        ok(f"{label} diagnostics/sign/exec surface")


def tasks(local_token: str, studio_token: str) -> None:
    for label, port, token in [
        ("macbook", LOCAL_API, local_token),
        ("studio", TUNNEL_PORT, studio_token),
    ]:
        list_id = f"live-tasks-{label}-{RUN_ID}"
        http_json(port, token, "POST", "/task-lists", {"name": f"Live Tasks {label}", "topic": list_id})
        first = http_json(
            port,
            token,
            "POST",
            f"/task-lists/{list_id}/tasks",
            {"title": f"{label} task one", "description": RUN_ID},
        )
        http_json(
            port,
            token,
            "POST",
            f"/task-lists/{list_id}/tasks",
            {"title": f"{label} task two", "description": RUN_ID},
        )
        task_id = first.get("task_id")
        if not task_id:
            die(f"{label} task id returned", json.dumps(first))
        http_json(port, token, "PATCH", f"/task-lists/{list_id}/tasks/{task_id}", {"action": "claim"})
        http_json(
            port,
            token,
            "PATCH",
            f"/task-lists/{list_id}/tasks/{task_id}",
            {"action": "complete"},
        )
        listed = http_json(port, token, "GET", f"/task-lists/{list_id}/tasks")
        task_items = listed.get("tasks") or []
        if len(task_items) < 2:
            die(f"{label} task list has tasks", json.dumps(listed))
        if not any(
            str(task.get("state", "")).lower().startswith(("completed", "done"))
            for task in task_items
        ):
            die(f"{label} completed task visible", json.dumps(listed))
        ok(f"{label} task lifecycle", f"{len(task_items)} tasks")


def kv_store(local_token: str, studio_token: str) -> None:
    store_id = f"live-kv-{RUN_ID}"
    http_json(LOCAL_API, local_token, "POST", "/stores", {"name": "Live KV", "topic": store_id})
    http_json(TUNNEL_PORT, studio_token, "POST", f"/stores/{store_id}/join")
    value = f"kv from macbook {RUN_ID}"
    http_json(
        LOCAL_API,
        local_token,
        "PUT",
        f"/stores/{store_id}/proof",
        {"value": b64(value), "content_type": "text/plain"},
    )
    got = None
    for _ in range(30):
        try:
            response = http_json(
                TUNNEL_PORT,
                studio_token,
                "GET",
                f"/stores/{store_id}/proof",
                require_ok=False,
            )
            if response.get("value"):
                got = base64.b64decode(response["value"]).decode(errors="replace")
                break
        except Exception:
            pass
        time.sleep(1)
    if got != value:
        die("studio reads macbook KV value after join", repr(got))
    ok("studio reads macbook KV value after join", value)
    http_json(LOCAL_API, local_token, "DELETE", f"/stores/{store_id}/proof")


def spaces(local_token: str, studio_token: str) -> None:
    created = http_json(
        LOCAL_API,
        local_token,
        "POST",
        "/groups",
        {
            "name": f"Live Studio Space {RUN_ID}",
            "description": "MacBook/studio live test",
            "preset": "public_open",
        },
    )
    group_id = created.get("group_id") or created.get("id")
    if not group_id:
        die("space group created", json.dumps(created))
    invite_response = http_json(LOCAL_API, local_token, "POST", f"/groups/{group_id}/invite")
    invite = invite_response.get("invite_link") or invite_response.get("invite")
    if not invite or not invite.startswith("x0x://invite/"):
        die("space invite created", json.dumps(invite_response))
    joined = http_json(
        TUNNEL_PORT,
        studio_token,
        "POST",
        "/groups/join",
        {"invite": invite},
        timeout=30,
    )
    studio_group_id = joined.get("group_id") or joined.get("id") or group_id
    time.sleep(5)
    http_json(LOCAL_API, local_token, "PUT", f"/groups/{group_id}/display-name", {"name": "MacBook Live"})
    http_json(
        TUNNEL_PORT,
        studio_token,
        "PUT",
        f"/groups/{studio_group_id}/display-name",
        {"name": "Studio Live"},
    )
    http_json(LOCAL_API, local_token, "GET", f"/groups/{group_id}/messages")
    http_json(TUNNEL_PORT, studio_token, "GET", f"/groups/{studio_group_id}/messages")

    local_message = f"space message macbook {RUN_ID}"
    studio_message = f"space message studio {RUN_ID}"
    http_json(
        LOCAL_API,
        local_token,
        "POST",
        f"/groups/{group_id}/send",
        {"body": local_message, "kind": "chat"},
        timeout=30,
    )
    seen = False
    for retry in range(45):
        messages = http_json(
            TUNNEL_PORT, studio_token, "GET", f"/groups/{studio_group_id}/messages"
        ).get("messages") or []
        if local_message in json.dumps(messages):
            seen = True
            break
        if retry in {10, 20, 30}:
            http_json(
                LOCAL_API,
                local_token,
                "POST",
                f"/groups/{group_id}/send",
                {"body": local_message, "kind": "chat"},
                timeout=30,
            )
        time.sleep(1)
    if not seen:
        die("studio receives macbook space message")
    ok("studio receives macbook space message", local_message)

    http_json(
        TUNNEL_PORT,
        studio_token,
        "POST",
        f"/groups/{studio_group_id}/send",
        {"body": studio_message, "kind": "chat"},
        timeout=30,
    )
    seen = False
    for retry in range(45):
        messages = http_json(LOCAL_API, local_token, "GET", f"/groups/{group_id}/messages").get(
            "messages"
        ) or []
        if studio_message in json.dumps(messages):
            seen = True
            break
        if retry in {10, 20, 30}:
            http_json(
                TUNNEL_PORT,
                studio_token,
                "POST",
                f"/groups/{studio_group_id}/send",
                {"body": studio_message, "kind": "chat"},
                timeout=30,
            )
        time.sleep(1)
    if not seen:
        die("macbook receives studio space message")
    ok("macbook receives studio space message", studio_message)


def swarm_topics(local_token: str, studio_token: str, mac_id: str, studio_id: str) -> None:
    task_topic = "x0x-swarm/tasks"
    result_topic = "x0x-swarm/results"
    subscriptions = [
        (LOCAL_API, local_token, http_json(LOCAL_API, local_token, "POST", "/subscribe", {"topic": task_topic})["subscription_id"]),
        (
            LOCAL_API,
            local_token,
            http_json(LOCAL_API, local_token, "POST", "/subscribe", {"topic": result_topic})[
                "subscription_id"
            ],
        ),
        (
            TUNNEL_PORT,
            studio_token,
            http_json(TUNNEL_PORT, studio_token, "POST", "/subscribe", {"topic": task_topic})[
                "subscription_id"
            ],
        ),
        (
            TUNNEL_PORT,
            studio_token,
            http_json(TUNNEL_PORT, studio_token, "POST", "/subscribe", {"topic": result_topic})[
                "subscription_id"
            ],
        ),
    ]
    mac_events = SseCollector("macbook /events", LOCAL_API, local_token, "/events")
    studio_events = SseCollector("studio /events", TUNNEL_PORT, studio_token, "/events")
    mac_events.start()
    studio_events.start()
    ok("swarm SSE streams connected")
    time.sleep(5)

    task = json.dumps(
        {
            "id": f"swarm-{RUN_ID}",
            "event": "posted",
            "description": f"swarm task {RUN_ID}",
            "capability": "live-test",
            "requester": mac_id,
            "timestamp": int(time.time() * 1000),
        },
        separators=(",", ":"),
    )
    result = json.dumps(
        {
            "task_id": f"swarm-{RUN_ID}",
            "event": "completed",
            "result": f"swarm result {RUN_ID}",
            "agent": studio_id,
            "timestamp": int(time.time() * 1000),
        },
        separators=(",", ":"),
    )
    for _ in range(6):
        http_json(LOCAL_API, local_token, "POST", "/publish", {"topic": task_topic, "payload": b64(task)})
        if studio_events.wait_for(
            lambda event: pubsub_topic(event) == task_topic and pubsub_payload_text(event) == task,
            timeout=5,
        ):
            break
        time.sleep(2)
    else:
        die("studio receives GUI swarm task topic", json.dumps(studio_events.snapshot())[:1200])
    ok("studio receives GUI swarm task topic")

    for _ in range(6):
        http_json(
            TUNNEL_PORT,
            studio_token,
            "POST",
            "/publish",
            {"topic": result_topic, "payload": b64(result)},
        )
        if mac_events.wait_for(
            lambda event: pubsub_topic(event) == result_topic
            and pubsub_payload_text(event) == result,
            timeout=5,
        ):
            break
        time.sleep(2)
    else:
        die("macbook receives GUI swarm result topic", json.dumps(mac_events.snapshot())[:1200])
    ok("macbook receives GUI swarm result topic")

    for port, token, sub_id in subscriptions:
        http_json(port, token, "DELETE", f"/subscribe/{sub_id}", require_ok=False)
    ok("swarm subscriptions cleaned")


def file_transfer(local_token: str, studio_token: str, studio_id: str) -> None:
    body = f"live file transfer {RUN_ID}\n".encode()
    source_path = LOCAL_DIR / "live-file.txt"
    source_path.write_bytes(body)
    sha = hashlib.sha256(body).hexdigest()
    sent = http_json(
        LOCAL_API,
        local_token,
        "POST",
        "/files/send",
        {
            "agent_id": studio_id,
            "filename": "live-file.txt",
            "size": len(body),
            "sha256": sha,
            "path": str(source_path),
        },
        timeout=30,
    )
    transfer_id = sent.get("transfer_id")
    if not transfer_id:
        die("file transfer id returned", json.dumps(sent))
    incoming = None
    for _ in range(40):
        transfers = http_json(TUNNEL_PORT, studio_token, "GET", "/files/transfers").get(
            "transfers"
        ) or []
        incoming = next(
            (
                transfer
                for transfer in transfers
                if transfer.get("transfer_id") == transfer_id
                and transfer.get("direction") == "Receiving"
            ),
            None,
        )
        if incoming:
            break
        time.sleep(0.5)
    if not incoming:
        die("studio sees incoming file offer")
    ok("studio sees incoming file offer", transfer_id)
    http_json(TUNNEL_PORT, studio_token, "POST", f"/files/accept/{transfer_id}", timeout=30)

    sender_done: dict[str, Any] = {}
    receiver_done: dict[str, Any] = {}
    for _ in range(90):
        sender_done = http_json(
            LOCAL_API, local_token, "GET", f"/files/transfers/{transfer_id}"
        ).get("transfer") or {}
        receiver_done = http_json(
            TUNNEL_PORT, studio_token, "GET", f"/files/transfers/{transfer_id}"
        ).get("transfer") or {}
        if sender_done.get("status") == "Complete" and receiver_done.get("status") == "Complete":
            break
        if sender_done.get("status") == "Failed" or receiver_done.get("status") == "Failed":
            die("file transfer failed", f"sender={sender_done} receiver={receiver_done}")
        time.sleep(1)
    if sender_done.get("status") != "Complete" or receiver_done.get("status") != "Complete":
        die("file transfer completes", f"sender={sender_done} receiver={receiver_done}")
    output_path = receiver_done.get("output_path")
    if not output_path:
        die("receiver output path recorded", json.dumps(receiver_done))
    remote_sha = ssh(
        f"shasum -a 256 {shlex.quote(output_path)} | cut -d' ' -f1", timeout=20
    ).stdout.strip()
    if remote_sha != sha:
        die("studio file checksum matches", f"{remote_sha} != {sha}")
    ok("file transfer completes with checksum", transfer_id)


def main() -> int:
    success = False
    try:
        local_token, studio_token = start_daemons()
        assert_gui(studio_token)
        mac, studio = connect_agents(local_token, studio_token)
        write_manifest(local_token, studio_token, mac, studio)
        direct_messages(local_token, studio_token, mac["agent_id"], studio["agent_id"])
        contacts(local_token, studio_token, mac, studio)
        diagnostics_and_signing(local_token, studio_token)
        tasks(local_token, studio_token)
        kv_store(local_token, studio_token)
        spaces(local_token, studio_token)
        swarm_topics(local_token, studio_token, mac["agent_id"], studio["agent_id"])
        file_transfer(local_token, studio_token, studio["agent_id"])
        mac_status = http_json(LOCAL_API, local_token, "GET", "/network/status", require_ok=False)
        studio_status = http_json(
            TUNNEL_PORT, studio_token, "GET", "/network/status", require_ok=False
        )
        ok(
            "final network status",
            f"mac peers={mac_status.get('connected_peers')} "
            f"studio peers={studio_status.get('connected_peers')}",
        )
        success = True
        log(f"LIVE_STUDIO_E2E_OK passes={PASSES}")
        return 0
    except Exception as exc:  # noqa: BLE001 - prints diagnostics then exits nonzero
        log(f"LIVE_STUDIO_E2E_FAILED: {exc}")
        local_log = LOCAL_DIR / "x0xd.log"
        log("--- local log tail ---")
        if local_log.exists():
            log("\n".join(local_log.read_text(errors="replace").splitlines()[-120:]))
        else:
            log("<missing>")
        log("--- remote log tail ---")
        try:
            log(ssh(f"tail -n 120 {shlex.quote(REMOTE_DIR)}/x0xd.log 2>/dev/null || true").stdout)
        except Exception as tail_exc:  # noqa: BLE001
            log(f"<could not fetch remote log: {tail_exc}>")
        log(f"left local_dir={LOCAL_DIR}")
        log(f"left remote_dir={REMOTE_DIR}")
        return 1
    finally:
        cleanup(success)


if __name__ == "__main__":
    sys.exit(main())
