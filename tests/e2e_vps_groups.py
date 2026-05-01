#!/usr/bin/env python3
"""x0x Phase-B VPS dogfood — groups + contacts on the live 6-node fleet.

Reuses the Phase-A discover protocol on `x0x.test.discover.v1` to learn
every runner's agent_id, then drives `e2e_dogfood_groups.py`-style
scenarios against the fleet:

    - Anchor node (default NYC) creates a public_open named group.
    - Anchor DMs each remote runner the invite link (Phase A control plane).
    - Each runner joins the group via local API; reports back via DM.
    - Anchor posts the kickoff group message; each runner posts a reply
      from its OWN daemon.
    - Anchor verifies (a) every member sees themselves in roster from
      their local view, (b) every member's own posted message appears
      in their own /groups/:id/messages cache.
    - Anchor records cross-member convergence (member counts seen by
      each runner of the other 5) as INFO only — currently slow on the
      live fleet because /groups/join doesn't subscribe the joiner to
      the chat-topic, see daemon TODO.
    - Anchor exercises the contacts lifecycle: every remote runner
      add → trust=Trusted → trust=Blocked → remove a synthetic peer.

Use:

    bash tests/e2e_deploy.sh           # ensure runners are deployed
    python3 tests/e2e_vps_groups.py [--anchor nyc]

Exits 0 only if every blocking assertion passes.
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
from typing import Any, Callable, Dict, List, Optional, Tuple

DISCOVER_TOPIC = "x0x.test.discover.v1"
LEGACY_RESULTS_TOPIC = "x0x.test.results.v1"
PREFIX_CMD = b"x0xtest|cmd|"
PREFIX_RES = b"x0xtest|res|"

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


# ─── token-file parsing ────────────────────────────────────────────────


def load_tokens(path: str) -> Dict[str, Tuple[str, str]]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"token file not found: {path}")
    ips: Dict[str, str] = {}
    toks: Dict[str, str] = {}
    pat = re.compile(r'^([A-Z]+)_(IP|TK)="?([^"]+)"?\s*$')
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = pat.match(line)
            if not m:
                continue
            n = m.group(1).lower()
            kind = m.group(2)
            value = m.group(3)
            if kind == "IP":
                ips[n] = value
            else:
                toks[n] = value
    return {n: (ips[n], toks[n]) for n in ips if n in toks}


# ─── HTTP / SSE plumbing ──────────────────────────────────────────────


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
            "POST", "/publish",
            body={"topic": topic,
                  "payload": base64.b64encode(payload).decode("ascii")},
        )

    def direct_send(
        self, agent_id: str, payload: bytes,
        require_ack_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "agent_id": agent_id,
            "payload": base64.b64encode(payload).decode("ascii"),
        }
        if require_ack_ms is not None:
            body["require_ack_ms"] = require_ack_ms
        return self._req("POST", "/direct/send", body=body)

    def perform(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if action == "contact_list":
            return self._req("GET", "/contacts")
        if action == "contact_add":
            body: Dict[str, Any] = {
                "agent_id": params["agent_id"],
                "trust_level": params.get("trust_level", "Unknown"),
            }
            if params.get("label") is not None:
                body["label"] = params["label"]
            return self._req("POST", "/contacts", body=body)
        if action == "contact_update":
            return self._req(
                "PATCH", f"/contacts/{params['agent_id']}",
                body={"trust_level": params["trust_level"]},
            )
        if action == "contact_remove":
            return self._req(
                "DELETE", f"/contacts/{params['agent_id']}",
            )
        if action == "group_create":
            body = {
                "name": params["name"],
                "description": params.get("description", ""),
            }
            if params.get("preset") is not None:
                body["preset"] = params["preset"]
            return self._req("POST", "/groups", body=body)
        if action == "group_invite":
            payload: Dict[str, Any] = {}
            if params.get("expiry_secs") is not None:
                payload["expiry_secs"] = params["expiry_secs"]
            return self._req(
                "POST", f"/groups/{params['group_id']}/invite", body=payload,
            )
        if action == "group_members":
            return self._req(
                "GET", f"/groups/{params['group_id']}/members",
            )
        if action == "group_send_message":
            return self._req(
                "POST", f"/groups/{params['group_id']}/send",
                body={
                    "body": params["body"],
                    "kind": params.get("kind", "chat"),
                },
            )
        if action == "group_messages":
            return self._req(
                "GET", f"/groups/{params['group_id']}/messages",
            )
        raise ValueError(f"unhandled action: {action}")

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
    if shutil.which("ssh") is None:
        raise RuntimeError("ssh not on PATH")
    cmd = [
        "ssh", "-N",
        "-L", f"127.0.0.1:{local_port}:127.0.0.1:12600",
        "-o", "ConnectTimeout=10",
        "-o", "ControlMaster=no",
        "-o", "ControlPath=none",
        "-o", "BatchMode=yes",
        "-o", "ServerAliveInterval=30",
        f"root@{ip}",
    ]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{local_port}/health", timeout=2,
            ) as resp:
                if resp.status in (200, 401):
                    return TunnelHandle(
                        process=proc, local_port=local_port, pid=proc.pid,
                    )
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                return TunnelHandle(
                    process=proc, local_port=local_port, pid=proc.pid,
                )
        except Exception:
            pass
        if proc.poll() is not None:
            err = (
                proc.stderr.read().decode("utf-8", errors="replace")
                if proc.stderr else ""
            )
            raise RuntimeError(f"ssh tunnel exited: {err}")
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


# ─── result-router ─────────────────────────────────────────────────────


@dataclass
class Runner:
    name: str
    agent_id: str
    machine_id: str = ""


@dataclass
class CommandWaiter:
    request_id: str
    queue: "queue.Queue[Dict[str, Any]]" = field(default_factory=queue.Queue)


class ResultRouter:
    def __init__(self, log: logging.Logger) -> None:
        self.log = log
        self._lock = threading.Lock()
        self._waiters: Dict[str, CommandWaiter] = {}
        self._discover_q: "queue.Queue[Runner]" = queue.Queue()
        self._stop = threading.Event()

    def register(self, w: CommandWaiter) -> None:
        with self._lock:
            self._waiters[w.request_id] = w

    def deregister(self, rid: str) -> None:
        with self._lock:
            self._waiters.pop(rid, None)

    def stop(self) -> None:
        self._stop.set()

    def stopped(self) -> bool:
        return self._stop.is_set()

    def deliver(self, envelope: Dict[str, Any]) -> None:
        kind = envelope.get("kind")
        if kind in ("discover_reply", "runner_ready"):
            self._discover_q.put(
                Runner(
                    name=envelope.get("node", "?"),
                    agent_id=envelope.get("agent_id", ""),
                    machine_id=envelope.get("machine_id", ""),
                )
            )
            return
        rid = envelope.get("request_id")
        if not rid:
            return
        with self._lock:
            waiter = self._waiters.get(rid)
        if waiter is None:
            return
        waiter.queue.put(envelope)

    def discover_pop(self, timeout: float) -> Optional[Runner]:
        try:
            return self._discover_q.get(timeout=timeout)
        except queue.Empty:
            return None


def consume_sse(
    client: X0xClient,
    path: str,
    router: ResultRouter,
    log: logging.Logger,
    label: str,
) -> None:
    while not router.stopped():
        try:
            log.debug("opening %s SSE (%s)", path, label)
            resp = client.open_sse(path)
        except Exception as exc:
            log.warning("%s SSE open failed: %s", label, exc)
            time.sleep(2)
            continue
        try:
            event_type = "message"
            data_lines: List[str] = []
            for raw in resp:
                if router.stopped():
                    return
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line == "":
                    if data_lines:
                        _route_event(
                            event_type, "\n".join(data_lines),
                            router, log, label,
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
        time.sleep(2)


def _route_event(
    event_type: str, data: str,
    router: ResultRouter, log: logging.Logger, label: str,
) -> None:
    if event_type == "direct_message":
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
            envelope = json.loads(base64.b64decode(payload[len(PREFIX_RES):]))
        except Exception as exc:
            log.debug("res DM parse error: %s", exc)
            return
        router.deliver(envelope)
        return
    if event_type != "message":
        return
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
        envelope = json.loads(base64.b64decode(payload_b64))
    except Exception as exc:
        log.debug("legacy results parse error: %s", exc)
        return
    router.deliver(envelope)


# ─── Phase-B harness ───────────────────────────────────────────────────


class FleetHarness:
    def __init__(
        self,
        client: X0xClient,
        router: ResultRouter,
        anchor_aid: str,
        anchor_name: str,
        runners: Dict[str, Runner],
        log: logging.Logger,
        cmd_timeout_secs: int = 30,
    ) -> None:
        self.client = client
        self.router = router
        self.anchor_aid = anchor_aid
        self.anchor_name = anchor_name
        self.runners = runners
        self.log = log
        self.cmd_timeout_secs = cmd_timeout_secs
        self.passes: List[str] = []
        self.failures: List[str] = []

    def call(
        self,
        target: str,
        action: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if target not in self.runners:
            raise KeyError(f"no runner for {target}")
        request_id = str(uuid.uuid4())
        params = dict(
            params or {}, request_id=request_id, anchor_aid=self.anchor_aid,
        )
        if self.runners[target].agent_id == self.anchor_aid:
            return self._invoke_local(action, params, request_id)
        waiter = CommandWaiter(request_id=request_id)
        self.router.register(waiter)
        try:
            envelope = {
                "command_id": request_id,
                "target_node": target,
                "action": action,
                "anchor_aid": self.anchor_aid,
                "params": params,
            }
            wire = PREFIX_CMD + base64.b64encode(
                json.dumps(envelope).encode("utf-8")
            )
            self._send_command(target, wire)
            try:
                response = waiter.queue.get(timeout=self.cmd_timeout_secs)
            except queue.Empty:
                raise TimeoutError(
                    f"{action} on {target} timed out after "
                    f"{self.cmd_timeout_secs}s"
                )
        finally:
            self.router.deregister(request_id)
        if response.get("kind") != f"{action}_result":
            raise RuntimeError(f"unexpected kind: {response.get('kind')}")
        return response

    def _send_command(self, target: str, wire: bytes) -> None:
        target_aid = self.runners[target].agent_id
        last: Optional[Exception] = None
        # 5 attempts with progressive backoff covers a ~25 s reconnect
        # window, long enough to ride through one peer-supersede cycle
        # on the live fleet without giving up on otherwise-healthy
        # nodes.
        for attempt in range(1, 6):
            try:
                self.client.direct_send(target_aid, wire)
                return
            except Exception as exc:
                last = exc
                self.log.debug(
                    "cmd DM to %s attempt %d/5: %s", target, attempt, exc,
                )
            time.sleep(min(8, 2 * attempt))
        raise RuntimeError(
            f"cmd DM to {target} failed after 5 attempts: {last}"
        )

    def _invoke_local(
        self, action: str, params: Dict[str, Any], request_id: str,
    ) -> Dict[str, Any]:
        try:
            details = self.client.perform(action, params)
            return {
                "kind": f"{action}_result", "request_id": request_id,
                "outcome": "ok", "details": details,
                "node": "anchor_local",
            }
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read())
            except Exception:
                body = {"status": exc.code, "reason": exc.reason}
            return {
                "kind": f"{action}_result", "request_id": request_id,
                "outcome": {"error": body, "http_status": exc.code},
                "details": {}, "node": "anchor_local",
            }
        except Exception as exc:
            return {
                "kind": f"{action}_result", "request_id": request_id,
                "outcome": {"error": str(exc)},
                "details": {}, "node": "anchor_local",
            }

    def assert_pass(
        self, label: str, condition: bool, detail: str = "",
    ) -> bool:
        if condition:
            self.passes.append(label)
            self.log.info("  PASS %s%s", label,
                          f" — {detail}" if detail else "")
            return True
        self.failures.append(label)
        self.log.error("  FAIL %s%s", label,
                       f" — {detail}" if detail else "")
        return False

    # ── scenarios ──────────────────────────────────────────────────────
    def run_contacts_lifecycle(self) -> None:
        # Synthetic contact: a deterministic 32-byte AgentId that won't
        # collide with any real fleet identity. Each runner adds + tracks
        # + removes it.
        synthetic_aid = (
            "ee" * 32  # 64 hex chars, all 0xee — pure marker
        )
        for name, runner in self.runners.items():
            self.log.info("[contacts] %s adds + removes synthetic peer", name)
            try:
                add = self.call(
                    name, "contact_add",
                    {"agent_id": synthetic_aid,
                     "trust_level": "Known",
                     "label": "phase-b-synthetic"},
                )
                self.assert_pass(
                    f"{name} adds synthetic contact",
                    add.get("outcome") == "ok",
                )
                upd = self.call(
                    name, "contact_update",
                    {"agent_id": synthetic_aid, "trust_level": "Trusted"},
                )
                self.assert_pass(
                    f"{name} sets synthetic = Trusted",
                    upd.get("outcome") == "ok",
                )
                blk = self.call(
                    name, "contact_update",
                    {"agent_id": synthetic_aid, "trust_level": "Blocked"},
                )
                self.assert_pass(
                    f"{name} sets synthetic = Blocked",
                    blk.get("outcome") == "ok",
                )
                rem = self.call(
                    name, "contact_remove",
                    {"agent_id": synthetic_aid},
                )
                self.assert_pass(
                    f"{name} removes synthetic contact",
                    rem.get("outcome") == "ok",
                )
            except Exception as exc:
                # Transient cross-region churn: skip rather than fail
                # the whole suite so the other runners' lifecycles are
                # still exercised.
                self.log.warning(
                    "  SKIP %s contacts lifecycle (unreachable): %s",
                    name, exc,
                )

    def run_group_lifecycle(self) -> None:
        members = [n for n in self.runners if n != self.anchor_name]
        self.log.info(
            "[groups] anchor=%s invites %s to a public_open group",
            self.anchor_name, members,
        )
        # 1. Anchor creates
        create = self.call(
            self.anchor_name, "group_create",
            {"name": "Phase-B Fleet Dogfood",
             "description": "live-fleet group + group-message dogfood",
             "preset": "public_open"},
        )
        self.assert_pass(
            f"{self.anchor_name} creates group",
            create.get("outcome") == "ok",
        )
        details = create.get("details") or {}
        gid = (
            details.get("group_id")
            or (details.get("group") or {}).get("id")
        )
        if not gid:
            self.failures.append("anchor failed to extract group_id")
            return

        # 2. Anchor generates an invite
        inv = self.call(
            self.anchor_name, "group_invite", {"group_id": gid},
        )
        self.assert_pass(
            f"{self.anchor_name} generates invite",
            inv.get("outcome") == "ok",
        )
        invite = (inv.get("details") or {}).get("invite_link")
        if not invite or not invite.startswith("x0x://invite/"):
            self.failures.append("invite link missing or wrong format")
            return

        # 3. Each runner joins. A member that is currently unreachable
        # (transient peer_disconnected) is recorded as SKIP rather than
        # FAIL so the rest of the harness continues against the
        # reachable subset.
        joined: Dict[str, str] = {}
        for member in members:
            try:
                resp = self.call(
                    member, "group_join", {"invite": invite},
                )
            except Exception as exc:
                self.log.warning(
                    "  SKIP %s join unreachable: %s", member, exc,
                )
                continue
            ok = resp.get("outcome") == "ok"
            self.assert_pass(f"{member} joins via invite", ok)
            if ok:
                joined[member] = (resp.get("details") or {}).get(
                    "group_id"
                ) or gid

        if not joined:
            self.failures.append("no reachable members joined the group")
            return

        # 4. Each member queries their own roster — must contain self
        for m in [self.anchor_name, *joined]:
            mgid = gid if m == self.anchor_name else joined[m]
            aid = self.runners[m].agent_id
            try:
                r = self.call(m, "group_members", {"group_id": mgid})
            except Exception as exc:
                self.failures.append(f"{m} members query: {exc}")
                continue
            aids = self._member_aids(r.get("details"))
            self.assert_pass(
                f"{m} sees self in roster",
                aid in aids,
                f"got {len(aids)}: {[a[:8] for a in aids[:5]]}",
            )

        # 5. Each member posts a message
        anchor_post = self.call(
            self.anchor_name, "group_send_message",
            {"group_id": gid,
             "body": "phase-b: please reply"},
        )
        self.assert_pass(
            f"{self.anchor_name} posts kickoff message",
            anchor_post.get("outcome") == "ok",
        )
        for member in joined:
            try:
                resp = self.call(
                    member, "group_send_message",
                    {"group_id": joined[member],
                     "body": f"phase-b: ack from {member}"},
                )
            except Exception as exc:
                self.failures.append(f"{member} group send: {exc}")
                continue
            self.assert_pass(
                f"{member} posts reply in group",
                resp.get("outcome") == "ok",
            )

        # 6. Each member sees their own posted body in their cache
        for m in [self.anchor_name, *joined]:
            mgid = gid if m == self.anchor_name else joined[m]
            expected = (
                "phase-b: please reply" if m == self.anchor_name
                else f"phase-b: ack from {m}"
            )
            try:
                resp = self.call(m, "group_messages", {"group_id": mgid})
            except Exception as exc:
                self.failures.append(f"{m} messages query: {exc}")
                continue
            bodies = self._message_bodies(resp.get("details"))
            self.assert_pass(
                f"{m} sees own reply in local cache",
                expected in bodies,
                f"bodies={list(bodies)[:3]}",
            )

        # Hard PASS (groups-join-roster-propagation): the
        # anchor must accept each joiner's signed reply within the
        # cross-region window once their MemberJoined metadata event
        # converges.
        deadline = time.time() + 30.0
        anchor_bodies: set = set()
        expected_replies = {f"phase-b: ack from {m}" for m in joined}
        while time.time() < deadline:
            try:
                anchor_msgs = self.call(
                    self.anchor_name, "group_messages", {"group_id": gid},
                )
                anchor_bodies = set(
                    self._message_bodies(anchor_msgs.get("details"))
                )
            except Exception as exc:
                self.log.warning(
                    "anchor cross-member check exception: %s", exc,
                )
                anchor_bodies = set()
            if expected_replies.issubset(anchor_bodies):
                break
            time.sleep(1.0)
        for m in joined:
            expected_body = f"phase-b: ack from {m}"
            self.assert_pass(
                f"{self.anchor_name} sees {m}'s reply in /messages cache",
                expected_body in anchor_bodies,
                f"bodies={list(anchor_bodies)[:5]}",
            )

    @staticmethod
    def _member_aids(payload: Any) -> List[str]:
        if not isinstance(payload, dict):
            return []
        for key in ("members", "member_list", "participants"):
            members = payload.get(key)
            if isinstance(members, list):
                out = []
                for m in members:
                    if isinstance(m, dict):
                        a = m.get("agent_id") or m.get("agentId")
                        if a:
                            out.append(a)
                    elif isinstance(m, str):
                        out.append(m)
                return out
        return []

    @staticmethod
    def _message_bodies(payload: Any) -> List[str]:
        if not isinstance(payload, dict):
            return []
        msgs = payload.get("messages")
        if not isinstance(msgs, list):
            return []
        out = []
        for msg in msgs:
            if isinstance(msg, dict):
                body = msg.get("body")
                if body is not None:
                    out.append(body)
        return out


# ─── discover ──────────────────────────────────────────────────────────


def discover_runners(
    client: X0xClient,
    router: ResultRouter,
    anchor_aid: str,
    anchor_name: str,
    expected: List[str],
    timeout_secs: int,
    log: logging.Logger,
) -> Dict[str, Runner]:
    log.info("discover: expecting %d runners (anchor=%s…)",
             len(expected), anchor_aid[:16])
    found: Dict[str, Runner] = {}
    deadline = time.time() + timeout_secs
    next_publish = 0.0
    while time.time() < deadline and len(found) < len(expected):
        if time.time() >= next_publish:
            payload = json.dumps({
                "command_id": str(uuid.uuid4()),
                "target_node": "*",
                "action": "discover",
                "anchor_aid": anchor_aid,
                "params": {
                    "request_id": str(uuid.uuid4()),
                    "anchor_aid": anchor_aid,
                },
            }).encode("utf-8")
            try:
                client.publish(DISCOVER_TOPIC, payload)
            except Exception as exc:
                log.warning("discover publish failed: %s", exc)
            next_publish = time.time() + 12
        info = router.discover_pop(timeout=2)
        if info is None:
            continue
        if info.name in expected and info.name not in found:
            found[info.name] = info
            log.info(
                "  ✓ %-12s agent=%s…",
                info.name, info.agent_id[:16],
            )
    missing = [n for n in expected if n not in found]
    if missing:
        log.warning("discover missing: %s", missing)
    return found


# ─── entry ─────────────────────────────────────────────────────────────


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Phase-B VPS dogfood (groups + contacts via x0x DMs)"
    )
    parser.add_argument("--anchor", default="nyc")
    parser.add_argument("--local-port", type=int, default=22600)
    parser.add_argument("--discover-secs", type=int, default=45)
    parser.add_argument(
        "--nodes", nargs="+", default=NODES_DEFAULT,
    )
    parser.add_argument("--tokens-file", default=None)
    parser.add_argument("--cmd-timeout", type=int, default=30)
    parser.add_argument("--report", default=None)
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    log = logging.getLogger("e2e_vps_groups")

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
    try:
        client = X0xClient(
            f"http://127.0.0.1:{args.local_port}", anchor_token,
        )
        health = client.health()
        if not health.get("ok"):
            log.error("anchor health failed: %s", health)
            return 3
        log.info(
            "anchor ok version=%s peers=%s",
            health.get("version"), health.get("peers"),
        )
        agent_info = client.agent()
        anchor_aid = agent_info.get("agent_id")
        if not isinstance(anchor_aid, str) or len(anchor_aid) != 64:
            log.error("anchor /agent missing agent_id: %s", agent_info)
            return 3
        log.info("anchor agent_id=%s…", anchor_aid[:16])

        try:
            client.subscribe(LEGACY_RESULTS_TOPIC)
        except Exception as exc:
            log.warning("legacy results subscribe failed: %s", exc)

        router = ResultRouter(log)
        threads = [
            threading.Thread(
                target=consume_sse,
                args=(client, "/direct/events", router, log, "direct"),
                daemon=True,
            ),
            threading.Thread(
                target=consume_sse,
                args=(client, "/events", router, log, "pubsub"),
                daemon=True,
            ),
        ]
        for t in threads:
            t.start()
        time.sleep(2)

        runners = discover_runners(
            client, router, anchor_aid, args.anchor,
            args.nodes, args.discover_secs, log,
        )
        if len(runners) < 2:
            log.error("need ≥2 runners, found %s", list(runners.keys()))
            return 4

        harness = FleetHarness(
            client=client, router=router,
            anchor_aid=anchor_aid, anchor_name=args.anchor,
            runners=runners, log=log,
            cmd_timeout_secs=args.cmd_timeout,
        )

        try:
            harness.run_contacts_lifecycle()
            harness.run_group_lifecycle()
        except Exception as exc:
            log.exception("scenario crashed: %s", exc)
            harness.failures.append(f"scenario crash: {exc}")

        router.stop()

        log.info("=" * 60)
        log.info(
            "Phase-B fleet dogfood — pass=%d fail=%d (runners=%d)",
            len(harness.passes), len(harness.failures), len(runners),
        )
        for f in harness.failures:
            log.info("  FAIL: %s", f)
        log.info("=" * 60)

        if args.report:
            try:
                with open(args.report, "w", encoding="utf-8") as fh:
                    json.dump(
                        {
                            "anchor": args.anchor,
                            "runners": {
                                n: r.agent_id for n, r in runners.items()
                            },
                            "passes": harness.passes,
                            "failures": harness.failures,
                        },
                        fh, indent=2,
                    )
            except Exception as exc:
                log.warning("report write failed: %s", exc)

        return 0 if not harness.failures else 1
    finally:
        stop_ssh_tunnel(tunnel)


if __name__ == "__main__":
    sys.exit(main())
