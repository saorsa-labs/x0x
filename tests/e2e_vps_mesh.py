#!/usr/bin/env python3
"""x0x VPS all-pairs DM matrix — Phase-A mesh harness (direct-DM control plane).

Drives the full 6-node fleet through *one* SSH tunnel to an anchor node.
All test actions flow as direct DMs from the anchor's agent to each
runner's agent; results return as direct DMs captured on the anchor's
``/direct/events`` SSE stream. Pubsub is used exactly once, for the
anchor announcement during discover.

Architecture::

    Mac harness ──SSH tunnel──► anchor daemon ──QUIC mesh──► every node
        │                            │
        │                            ├── publishes one discover envelope
        │                            │   on x0x.test.discover.v1
        │                            │   carrying anchor_aid
        │                            │
        │                            ├── /direct/send  command DMs
        │                            │     x0xtest|cmd|<b64-json>
        │                            │
        │                            └── /direct/events SSE
        │                                  x0xtest|res|<b64-json>  (results)

Pubsub is no longer used after discover, so PlumTree degradation under
sustained orchestrator runs no longer affects test reliability. The runner
keeps the legacy results-topic fallback so an old orchestrator can still
reach a Phase-A runner.

Usage::

    bash tests/e2e_deploy.sh   # also installs/refreshes the Phase-A runner
    python3 tests/e2e_vps_mesh.py [--anchor nyc] [--settle-secs 30]

Exit code is 0 when every directed pair delivers a DM round-trip within
the settle window.
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

DISCOVER_TOPIC = "x0x.test.discover.v1"
LEGACY_CONTROL_TOPIC = "x0x.test.control.v1"
LEGACY_RESULTS_TOPIC = "x0x.test.results.v1"
# Phase-A direct-DM control plane uses these prefixes on the test traffic:
#   x0xtest|cmd|<b64-json>   orchestrator → runner command
#   x0xtest|res|<b64-json>   runner → orchestrator result
PREFIX_CMD = b"x0xtest|cmd|"
PREFIX_RES = b"x0xtest|res|"
# Command DMs use the daemon's default resilient DM path. The harness gets
# stronger application-level proof from source `send_result` and destination
# `received_dm` envelopes, so raw receive-ACK is disabled by default. Keep this
# knob for a future explicit --raw-ack-stress mode; ordinary mesh correctness
# should not depend on ant-quic receive-ACK timing.
COMMAND_DM_ACK_MS: Optional[int] = None

NODES_DEFAULT: List[str] = [
    "nyc",
    "sfo",
    "helsinki",
    "nuremberg",
    "singapore",
    "sydney",
]


def now_ms() -> int:
    return int(time.time() * 1000)


# ─── token file parsing ────────────────────────────────────────────────


def load_tokens(path: str) -> Dict[str, Tuple[str, str]]:
    """Parse tests/.vps-tokens.env and return {node: (ip, token)}."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"token file not found: {path}")
    ips: Dict[str, str] = {}
    toks: Dict[str, str] = {}
    pattern = re.compile(r'^([A-Z]+)_(IP|TK)="?([^"]+)"?\s*$')
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = pattern.match(line)
            if not m:
                continue
            node = m.group(1).lower()
            kind = m.group(2)
            value = m.group(3)
            if kind == "IP":
                ips[node] = value
            else:
                toks[node] = value
    out: Dict[str, Tuple[str, str]] = {}
    for n, ip in ips.items():
        if n in toks:
            out[n] = (ip, toks[n])
    return out


# ─── HTTP client ───────────────────────────────────────────────────────


class X0xClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def _req(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        timeout: float = 15.0,
    ) -> Dict[str, Any]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read() or b"{}")

    def health(self) -> Dict[str, Any]:
        return self._req("GET", "/health")

    def agent(self) -> Dict[str, Any]:
        return self._req("GET", "/agent")

    def subscribe(self, topic: str) -> Dict[str, Any]:
        return self._req("POST", "/subscribe", body={"topic": topic})

    def publish(self, topic: str, payload: bytes) -> Dict[str, Any]:
        return self._req(
            "POST",
            "/publish",
            body={
                "topic": topic,
                "payload": base64.b64encode(payload).decode("ascii"),
            },
        )

    def direct_send(
        self,
        agent_id: str,
        payload: bytes,
        require_ack_ms: Optional[int] = COMMAND_DM_ACK_MS,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "agent_id": agent_id,
            "payload": base64.b64encode(payload).decode("ascii"),
        }
        if require_ack_ms is not None:
            body["require_ack_ms"] = require_ack_ms
        return self._req("POST", "/direct/send", body=body)

    def open_sse(self, path: str, timeout: float = 3600 * 6):
        req = urllib.request.Request(
            self.base_url + path,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "text/event-stream",
            },
        )
        return urllib.request.urlopen(req, timeout=timeout)


# ─── SSH tunnel manager ────────────────────────────────────────────────


@dataclass
class TunnelHandle:
    process: subprocess.Popen
    local_port: int
    pid: int


def start_ssh_tunnel(ip: str, local_port: int) -> TunnelHandle:
    """Open a backgrounded SSH tunnel forwarding ``local_port`` → 12600.

    The tunnel is a single SSH connection that survives the whole test
    run; every API call to the anchor reuses it.
    """
    if shutil.which("ssh") is None:
        raise RuntimeError("ssh not on PATH")
    cmd = [
        "ssh",
        "-N",
        "-L",
        f"127.0.0.1:{local_port}:127.0.0.1:12600",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "BatchMode=yes",
        "-o",
        "ServerAliveInterval=30",
        f"root@{ip}",
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    # Wait for the tunnel to accept connections.
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{local_port}/health", timeout=2
            ) as resp:
                if resp.status == 200 or resp.status == 401:
                    return TunnelHandle(
                        process=proc,
                        local_port=local_port,
                        pid=proc.pid,
                    )
        except urllib.error.HTTPError as exc:
            # 401 means tunnel works; we just don't have a token configured.
            if exc.code == 401:
                return TunnelHandle(
                    process=proc,
                    local_port=local_port,
                    pid=proc.pid,
                )
        except Exception:
            pass
        if proc.poll() is not None:
            err = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
            raise RuntimeError(f"ssh tunnel exited early: {err}")
        time.sleep(0.5)
    proc.terminate()
    raise RuntimeError(f"ssh tunnel to {ip}:12600 not ready in 15s")


def stop_ssh_tunnel(t: TunnelHandle) -> None:
    try:
        t.process.terminate()
        t.process.wait(timeout=5)
    except Exception:
        try:
            t.process.kill()
        except Exception:
            pass


# ─── results SSE listener ──────────────────────────────────────────────


@dataclass
class RunnerInfo:
    node: str
    agent_id: str
    machine_id: str


@dataclass
class SendResult:
    request_id: str
    node: str
    outcome: Any
    digest_marker: Optional[str]
    details: Dict[str, Any]


@dataclass
class ReceivedDm:
    request_id: str
    node: str
    digest_marker: Optional[str]
    details: Dict[str, Any]
    received_at_ms: int


@dataclass
class ResultsBus:
    discover: queue.Queue = field(default_factory=queue.Queue)
    sends: queue.Queue = field(default_factory=queue.Queue)
    received: queue.Queue = field(default_factory=queue.Queue)


def consume_sse(
    client: X0xClient,
    path: str,
    bus: ResultsBus,
    stop: threading.Event,
    log: logging.Logger,
    label: str,
) -> None:
    """Long-lived consumer of an SSE endpoint on the anchor.

    Two streams are run in parallel from this function (one thread each):

    - ``/direct/events`` — primary Phase-A results channel; events have
      type ``direct_message`` and the payload is the full DM body.
    - ``/events`` — pubsub fallback channel; only the legacy results
      topic is recognised and routed through the same bus.
    """
    while not stop.is_set():
        try:
            log.info("opening %s SSE on anchor (%s)", path, label)
            resp = client.open_sse(path)
        except Exception as exc:
            log.warning("%s SSE open failed: %s — retrying", label, exc)
            stop.wait(2)
            continue
        try:
            event_type = "message"
            data_lines: List[str] = []
            for raw in resp:
                if stop.is_set():
                    return
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line == "":
                    if data_lines:
                        _route_sse_event(
                            event_type,
                            "\n".join(data_lines),
                            bus,
                            log,
                            label,
                        )
                    event_type = "message"
                    data_lines = []
                    continue
                if line.startswith(":"):
                    continue
                if line.startswith("event:"):
                    event_type = line[6:].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
        except Exception as exc:
            log.warning("%s SSE read error: %s — reconnecting", label, exc)
        finally:
            try:
                resp.close()
            except Exception:
                pass
        stop.wait(2)


def _route_sse_event(
    event_type: str,
    data: str,
    bus: ResultsBus,
    log: logging.Logger,
    label: str,
) -> None:
    if event_type == "direct_message":
        # Phase-A: result envelopes arrive as direct DMs on /direct/events.
        try:
            msg = json.loads(data)
        except json.JSONDecodeError:
            return
        payload_b64 = msg.get("payload")
        if not payload_b64:
            return
        try:
            payload = base64.b64decode(payload_b64)
        except Exception:
            return
        if not payload.startswith(PREFIX_RES):
            return
        try:
            body = json.loads(base64.b64decode(payload[len(PREFIX_RES):]))
        except Exception as exc:
            log.debug("res DM payload parse error: %s", exc)
            return
        _enqueue_result_envelope(body, bus, source=label)
        return

    if event_type != "message":
        return
    # Pubsub fallback path — only the legacy results topic is honoured;
    # everything else (including the discover topic itself when it loops
    # back to the publisher) is ignored.
    try:
        env = json.loads(data)
    except json.JSONDecodeError:
        return
    inner = env.get("data") if "data" in env else env
    if not isinstance(inner, dict):
        return
    if inner.get("topic") != LEGACY_RESULTS_TOPIC:
        return
    payload_b64 = inner.get("payload")
    if not payload_b64:
        return
    try:
        body = json.loads(base64.b64decode(payload_b64))
    except Exception as exc:
        log.debug("legacy results payload parse error: %s", exc)
        return
    _enqueue_result_envelope(body, bus, source=label)


def _enqueue_result_envelope(
    body: Dict[str, Any],
    bus: ResultsBus,
    source: str,
) -> None:
    kind = body.get("kind")
    details = body.get("details") or {}
    details.setdefault("via_sse", source)
    body["details"] = details
    if kind == "discover_reply" or kind == "runner_ready":
        bus.discover.put(
            RunnerInfo(
                node=body.get("node", "?"),
                agent_id=body.get("agent_id", ""),
                machine_id=body.get("machine_id", ""),
            )
        )
    elif kind == "send_result":
        bus.sends.put(
            SendResult(
                request_id=body.get("request_id", ""),
                node=body.get("node", "?"),
                outcome=body.get("outcome"),
                digest_marker=body.get("digest_marker"),
                details=details,
            )
        )
    elif kind == "received_dm":
        bus.received.put(
            ReceivedDm(
                request_id=body.get("request_id", ""),
                node=body.get("node", "?"),
                digest_marker=body.get("digest_marker"),
                details=details,
                received_at_ms=body.get("ts_ms") or now_ms(),
            )
        )


# ─── matrix orchestration ──────────────────────────────────────────────


def publish_discover(
    client: X0xClient, anchor_aid: str, request_id: str
) -> None:
    """One-shot pubsub announcement carrying anchor_aid for runners.

    Every subsequent command flows as a direct DM, but discovery is a
    chicken/egg case — runners don't yet know who the orchestrator is —
    so we use exactly one pubsub round here to bootstrap.
    """
    payload = json.dumps(
        {
            "command_id": request_id,
            "target_node": "*",
            "action": "discover",
            "anchor_aid": anchor_aid,
            "params": {
                "request_id": request_id,
                "anchor_aid": anchor_aid,
            },
        }
    ).encode("utf-8")
    client.publish(DISCOVER_TOPIC, payload)


def send_command_dm(
    client: X0xClient,
    target_aid: str,
    cmd: Dict[str, Any],
    log: logging.Logger,
    anchor_aid: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Send a runner command — direct DM if remote, pubsub if collocated.

    When the target runner lives on the anchor's own daemon (single-host
    smoke, or when the anchor is also one of the matrix nodes), the local
    daemon refuses a self-DM. We fall back to publishing the command on
    the legacy control topic; the runner subscribed to that topic will
    pick it up and reply via DM as usual.
    """
    envelope = json.dumps(cmd).encode("utf-8")
    if anchor_aid and target_aid == anchor_aid:
        # Anchor-collocated runner: publish on the legacy control topic.
        try:
            client.publish(LEGACY_CONTROL_TOPIC, envelope)
            return {"ok": True, "via": "legacy_control_pubsub"}
        except Exception as exc:
            log.warning(
                "anchor-local pubsub command failed: %s", exc
            )
            return None
    wire = PREFIX_CMD + base64.b64encode(envelope)
    try:
        return client.direct_send(target_aid, wire)
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read())
        except Exception:
            body = {"status": exc.code, "reason": exc.reason}
        log.warning(
            "command DM to %s… failed (HTTP %s): %s",
            target_aid[:16],
            exc.code,
            body,
        )
        return None
    except Exception as exc:
        log.warning("command DM to %s… failed: %s", target_aid[:16], exc)
        return None


def discover_runners(
    client: X0xClient,
    bus: ResultsBus,
    expected_nodes: List[str],
    anchor_aid: str,
    timeout_secs: int,
    log: logging.Logger,
    republish_every_secs: int = 12,
) -> Dict[str, RunnerInfo]:
    """Publish a discover announcement and collect node→runner_info.

    The runner replies via direct DM rather than pubsub, so the orchestrator
    only ever sees one pubsub round per harness run. The announcement is
    republished periodically while runners are still missing — this is
    cheap (one pubsub publish per cycle) and tolerates a runner that came
    up after the first publish.
    """
    log.info("discover: expecting %d runners (anchor=%s…)",
             len(expected_nodes), anchor_aid[:16])
    found: Dict[str, RunnerInfo] = {}
    deadline = time.time() + timeout_secs
    next_republish = 0.0
    while time.time() < deadline and len(found) < len(expected_nodes):
        if time.time() >= next_republish:
            try:
                publish_discover(client, anchor_aid, str(uuid.uuid4()))
            except Exception as exc:
                log.warning("discover republish failed: %s", exc)
            next_republish = time.time() + republish_every_secs
        remaining = min(
            republish_every_secs,
            max(0.25, deadline - time.time()),
        )
        try:
            info = bus.discover.get(timeout=remaining)
        except queue.Empty:
            continue
        if info.node in expected_nodes and info.node not in found:
            found[info.node] = info
            log.info(
                "  ✓ %-12s agent=%s… machine=%s…",
                info.node,
                info.agent_id[:16],
                info.machine_id[:16],
            )
    missing = [n for n in expected_nodes if n not in found]
    if missing:
        log.warning("discover missing: %s", missing)
    return found


@dataclass
class MatrixOutcome:
    sent: int = 0
    send_ok: int = 0
    send_fail: int = 0
    received: int = 0
    receive_miss: int = 0
    failures: List[str] = field(default_factory=list)


def run_all_pairs_matrix(
    client: X0xClient,
    bus: ResultsBus,
    runners: Dict[str, RunnerInfo],
    anchor_aid: str,
    settle_secs: int,
    log: logging.Logger,
) -> MatrixOutcome:
    """Fan out a single send command per directed pair via direct DMs."""
    nodes = list(runners.keys())
    pairs: List[Tuple[str, str, str, str]] = []
    proof_token = f"mesh-{int(time.time())}"
    for src in nodes:
        for dst in nodes:
            if src == dst:
                continue
            request_id = f"{proof_token}-{src}-{dst}"
            digest = f"{src[:3]}-{dst[:3]}"
            pairs.append((src, dst, request_id, digest))

    log.info(
        "fan-out: %d directed pairs × 1 message each via direct DMs "
        "(proof_token=%s)",
        len(pairs),
        proof_token,
    )

    expected_send_rids = set()
    expected_recv_pairs: Dict[Tuple[str, str], bool] = {}
    dm_dispatch_failures: List[str] = []

    for src, dst, request_id, digest in pairs:
        recipient_aid = runners[dst].agent_id
        runner_aid = runners[src].agent_id
        cmd = {
            "command_id": f"matrix-{request_id}",
            "target_node": src,
            "action": "send_dm",
            "anchor_aid": anchor_aid,
            "params": {
                "recipient_aid": recipient_aid,
                "payload_b64": base64.b64encode(
                    f"matrix:{request_id}".encode("utf-8")
                ).decode("ascii"),
                "request_id": request_id,
                "digest_marker": digest,
                "anchor_aid": anchor_aid,
            },
        }
        resp = send_command_dm(
            client, runner_aid, cmd, log, anchor_aid=anchor_aid
        )
        if resp is None:
            dm_dispatch_failures.append(request_id)
        expected_send_rids.add(request_id)
        expected_recv_pairs[(dst, request_id)] = True
        # Tiny inter-DM breather; the anchor's local /direct/send is fast,
        # but a 50 ms pause keeps the daemon receive/control queues smooth.
        time.sleep(0.05)

    if dm_dispatch_failures:
        log.warning(
            "%d command DMs failed to dispatch from anchor "
            "(reported as command_dispatch_fail)",
            len(dm_dispatch_failures),
        )

    log.info("waiting %ds for results to settle", settle_secs)
    deadline = time.time() + settle_secs
    out = MatrixOutcome()
    seen_sends: Dict[str, SendResult] = {}
    seen_recv: Dict[Tuple[str, str], ReceivedDm] = {}

    while time.time() < deadline:
        # Drain both queues opportunistically.
        progress = False
        try:
            sr = bus.sends.get_nowait()
            seen_sends[sr.request_id] = sr
            progress = True
        except queue.Empty:
            pass
        try:
            rd = bus.received.get_nowait()
            seen_recv[(rd.node, rd.request_id)] = rd
            progress = True
        except queue.Empty:
            pass
        if not progress:
            time.sleep(0.1)
        # Fast-exit when everything observable has arrived.
        if (
            len(seen_sends) >= len(expected_send_rids)
            and len(seen_recv) >= len(expected_recv_pairs)
        ):
            log.info("all expected results observed before deadline")
            break

    # Tally.
    for request_id in expected_send_rids:
        sr = seen_sends.get(request_id)
        out.sent += 1
        if sr is None:
            out.send_fail += 1
            if request_id in dm_dispatch_failures:
                out.failures.append(f"command_dispatch_fail {request_id}")
            else:
                out.failures.append(f"send_no_result {request_id}")
            continue
        if sr.outcome == "ok":
            out.send_ok += 1
        else:
            out.send_fail += 1
            out.failures.append(
                f"send_err {sr.node} {request_id}: {sr.outcome}"
            )

    for (dst, request_id) in expected_recv_pairs:
        rd = seen_recv.get((dst, request_id))
        if rd is None:
            out.receive_miss += 1
            out.failures.append(f"recv_miss {dst} {request_id}")
        else:
            out.received += 1

    return out


# ─── reporting ─────────────────────────────────────────────────────────


def print_summary(out: MatrixOutcome, total_pairs: int, log: logging.Logger) -> None:
    log.info("=" * 64)
    log.info("All-pairs DM matrix — mesh-driven harness")
    log.info("  Sent:     %d / %d", out.send_ok, out.sent)
    log.info("  Received: %d / %d", out.received, total_pairs)
    log.info("  Send fails:    %d", out.send_fail)
    log.info("  Receive misses: %d", out.receive_miss)
    log.info("=" * 64)
    if out.failures:
        log.info("Failure list (first 30):")
        for f in out.failures[:30]:
            log.info("  - %s", f)


# ─── entry point ───────────────────────────────────────────────────────


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Mesh-relay all-pairs DM matrix harness"
    )
    parser.add_argument(
        "--anchor",
        default="nyc",
        help="node label to use as the SSH-tunneled anchor (default nyc)",
    )
    parser.add_argument(
        "--local-port",
        type=int,
        default=22600,
        help="local port for the anchor SSH tunnel (default 22600)",
    )
    parser.add_argument(
        "--discover-secs",
        type=int,
        default=30,
        help="seconds to wait for runner discovery (default 30)",
    )
    parser.add_argument(
        "--settle-secs",
        type=int,
        default=45,
        help="seconds to wait for matrix results after publishing (default 45)",
    )
    parser.add_argument(
        "--nodes",
        nargs="+",
        default=NODES_DEFAULT,
        help="expected node labels (default: %(default)s)",
    )
    parser.add_argument(
        "--tokens-file",
        default=None,
        help="path to tests/.vps-tokens.env (default: relative to script)",
    )
    parser.add_argument(
        "--no-tunnel",
        action="store_true",
        help="skip SSH tunnel; talk to --api-base directly with --api-token "
        "(used for local smoke tests where the anchor is on this host)",
    )
    parser.add_argument(
        "--api-base",
        default=None,
        help="anchor API base URL when --no-tunnel is set",
    )
    parser.add_argument(
        "--api-token",
        default=None,
        help="anchor API bearer token when --no-tunnel is set",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    log = logging.getLogger("e2e_vps_mesh")

    if args.no_tunnel:
        if not args.api_base or not args.api_token:
            log.error("--no-tunnel requires --api-base and --api-token")
            return 2
        anchor_token = args.api_token
        anchor_base = args.api_base
        tunnel = None
        log.info("anchor=%s base=%s (no SSH tunnel)", args.anchor, anchor_base)
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        tokens_path = (
            args.tokens_file
            or os.environ.get("X0X_TOKENS_FILE")
            or os.path.join(script_dir, ".vps-tokens.env")
        )
        tokens = load_tokens(tokens_path)
        if args.anchor not in tokens:
            log.error("anchor %s missing from %s", args.anchor, tokens_path)
            return 2
        anchor_ip, anchor_token = tokens[args.anchor]
        log.info("anchor=%s ip=%s", args.anchor, anchor_ip)
        log.info("opening SSH tunnel %d → %s:12600", args.local_port, anchor_ip)
        tunnel = start_ssh_tunnel(anchor_ip, args.local_port)
        anchor_base = f"http://127.0.0.1:{args.local_port}"

    try:
        client = X0xClient(anchor_base, anchor_token)
        health = client.health()
        if not health.get("ok"):
            log.error("anchor health failed: %s", health)
            return 3
        log.info(
            "anchor health ok: version=%s peers=%s",
            health.get("version"),
            health.get("peers"),
        )

        # Anchor's own agent_id — runners DM their results back here.
        agent_info = client.agent()
        anchor_aid = agent_info.get("agent_id")
        if not isinstance(anchor_aid, str) or len(anchor_aid) != 64:
            log.error("anchor /agent missing agent_id: %s", agent_info)
            return 3
        log.info("anchor agent_id=%s…", anchor_aid[:16])

        # Pubsub fallback: subscribe the legacy results topic so an old
        # runner that publishes its results still reaches us. Phase-A
        # runners will deliver via direct DMs instead, but the
        # subscription is cheap and guards against a half-deployed fleet.
        try:
            sub = client.subscribe(LEGACY_RESULTS_TOPIC)
            log.info(
                "subscribed to %s (id=%s) — legacy fallback",
                LEGACY_RESULTS_TOPIC,
                sub.get("subscription_id"),
            )
        except Exception as exc:
            log.warning("legacy results subscription failed: %s", exc)

        # Two SSE consumers in parallel: /direct/events is the primary
        # Phase-A channel; /events is the pubsub fallback.
        stop = threading.Event()
        bus = ResultsBus()
        sse_threads = [
            threading.Thread(
                target=consume_sse,
                args=(client, "/direct/events", bus, stop, log, "direct"),
                daemon=True,
            ),
            threading.Thread(
                target=consume_sse,
                args=(client, "/events", bus, stop, log, "pubsub"),
                daemon=True,
            ),
        ]
        for t in sse_threads:
            t.start()
        # Give both SSE streams a beat to land.
        time.sleep(2)

        runners = discover_runners(
            client,
            bus,
            args.nodes,
            anchor_aid=anchor_aid,
            timeout_secs=args.discover_secs,
            log=log,
        )
        if len(runners) < 2:
            log.error("need at least 2 runners; found %s", list(runners.keys()))
            return 4

        out = run_all_pairs_matrix(
            client,
            bus,
            runners,
            anchor_aid=anchor_aid,
            settle_secs=args.settle_secs,
            log=log,
        )
        total_pairs = len(runners) * (len(runners) - 1)
        print_summary(out, total_pairs, log)
        rc = 0 if out.send_fail == 0 and out.receive_miss == 0 else 1
        stop.set()
        return rc
    finally:
        if tunnel is not None:
            stop_ssh_tunnel(tunnel)


if __name__ == "__main__":
    sys.exit(main())
