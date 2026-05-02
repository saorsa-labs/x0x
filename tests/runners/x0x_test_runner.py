#!/usr/bin/env python3
"""x0x mesh-relay test runner — Phase A (direct-DM control plane).

One instance runs as a systemd service on every VPS bootstrap node. It
subscribes to ONE pubsub topic for discovery and the daemon's local
/direct/events SSE stream for everything else. The Mac harness drives
the 6-node fleet via a single SSH-tunneled connection to one anchor
node, fanning commands out as direct DMs from the anchor's agent.

Wire protocol — three DM payload prefixes:

    x0xtest|cmd|<base64-json>          orchestrator → runner
    x0xtest|res|<base64-json>          runner → orchestrator
    x0xtest|hop|<rid>|<digest>|
        <anchor_aid_hex>|<payload>     runner → runner test traffic;
                                       receiver DMs `res` back to
                                       anchor_aid embedded in the hop

Pubsub is used exclusively for the one-shot anchor announcement (topic
`x0x.test.discover.v1`). After every runner replies via DM, all command/
result traffic stays on point-to-point DMs — no PlumTree dependence,
no anti-entropy lag, and no leaked subscriptions.

Stdlib only. Python 3.8+.

Environment / CLI:
    NODE_NAME         human-readable node label, e.g. "nyc"
    X0X_API_BASE      default http://127.0.0.1:12600
    X0X_API_TOKEN     path to token file or literal token; default
                      /var/lib/x0x/api-token (Linux service path)
    LOG_LEVEL         INFO|DEBUG; default INFO

Topics:
    DISCOVER = x0x.test.discover.v1   (one-shot pubsub bootstrap only)

Backward compatibility: the runner still recognises the legacy
`x0xtest|<rid>|<digest>|<extra>` prefix from older orchestrators and
echoes a result back via the **legacy** results topic when it cannot
infer an anchor agent_id.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import queue
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, Optional, Tuple

DISCOVER_TOPIC = "x0x.test.discover.v1"
# Legacy topics retained so an older orchestrator that publishes on the
# v1 control topic can still drive a Phase-A runner (no protocol break).
LEGACY_CONTROL_TOPIC = "x0x.test.control.v1"
LEGACY_RESULTS_TOPIC = "x0x.test.results.v1"
SSE_RECONNECT_BACKOFF_SECS = 2
PUBLISH_RETRY_BACKOFF_SECS = 1
PUBLISH_RETRY_MAX = 3
TEST_DM_RETRY_BACKOFF_SECS = 1
TEST_DM_RETRY_MAX = 3
# Direct-DM result delivery does NOT request the raw-QUIC receive-ACK.
# That path fast-fails with `peer_disconnected` when the QUIC connection
# is momentarily superseded (a normal occurrence on a long-lived live
# fleet), and result loss is far worse than result latency. Letting the
# daemon use its default DM path (gossip-inbox first, with one retry)
# trades ~100-500 ms of extra latency for resilience to mid-session
# QUIC churn.
RESULT_DM_ACK_MS: Optional[int] = None


def now_ms() -> int:
    return int(time.time() * 1000)


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(s: str) -> bytes:
    return base64.b64decode(s)


def load_token(token_spec: str) -> str:
    """Load API token from a path or literal string.

    A token-file path is preferred (canonical Linux service location);
    fall back to treating the spec as the token itself if it does not
    point at a readable file.
    """
    if os.path.isfile(token_spec):
        with open(token_spec, "r", encoding="utf-8") as f:
            return f.read().strip()
    return token_spec.strip()


class X0xClient:
    """Minimal stdlib-only x0xd REST client."""

    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _request(
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
            headers=self._headers,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
        if not raw:
            return {}
        return json.loads(raw)

    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/health")

    def agent(self) -> Dict[str, Any]:
        return self._request("GET", "/agent")

    def publish(self, topic: str, payload: bytes) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/publish",
            body={"topic": topic, "payload": b64encode(payload)},
        )

    def subscribe(self, topic: str) -> Dict[str, Any]:
        return self._request("POST", "/subscribe", body={"topic": topic})

    def direct_send(
        self,
        agent_id: str,
        payload: bytes,
        require_ack_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "agent_id": agent_id,
            "payload": b64encode(payload),
        }
        if require_ack_ms is not None:
            body["require_ack_ms"] = require_ack_ms
        return self._request("POST", "/direct/send", body=body)

    # ─── contacts ──────────────────────────────────────────────────────
    def contacts_list(self) -> Dict[str, Any]:
        return self._request("GET", "/contacts")

    def contacts_add(
        self, agent_id: str, trust_level: str = "Unknown",
        label: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"agent_id": agent_id, "trust_level": trust_level}
        if label is not None:
            body["label"] = label
        return self._request("POST", "/contacts", body=body)

    def contacts_update(self, agent_id: str, trust_level: str) -> Dict[str, Any]:
        return self._request(
            "PATCH", f"/contacts/{agent_id}",
            body={"trust_level": trust_level},
        )

    def contacts_remove(self, agent_id: str) -> Dict[str, Any]:
        return self._request("DELETE", f"/contacts/{agent_id}")

    # ─── named groups ──────────────────────────────────────────────────
    def groups_create(
        self, name: str, description: str = "",
        preset: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"name": name, "description": description}
        if preset is not None:
            body["preset"] = preset
        return self._request("POST", "/groups", body=body)

    def groups_list(self) -> Dict[str, Any]:
        return self._request("GET", "/groups")

    def groups_info(self, gid: str) -> Dict[str, Any]:
        return self._request("GET", f"/groups/{gid}")

    def groups_invite(
        self, gid: str, expiry_secs: Optional[int] = None
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {}
        if expiry_secs is not None:
            body["expiry_secs"] = expiry_secs
        return self._request("POST", f"/groups/{gid}/invite", body=body)

    def groups_join(self, invite: str) -> Dict[str, Any]:
        return self._request("POST", "/groups/join", body={"invite": invite})

    def groups_members(self, gid: str) -> Dict[str, Any]:
        return self._request("GET", f"/groups/{gid}/members")

    def groups_send_message(
        self, gid: str, body: str, kind: str = "chat"
    ) -> Dict[str, Any]:
        return self._request(
            "POST", f"/groups/{gid}/send",
            body={"body": body, "kind": kind},
        )

    def groups_messages(self, gid: str) -> Dict[str, Any]:
        return self._request("GET", f"/groups/{gid}/messages")

    def groups_set_display_name(self, gid: str, name: str) -> Dict[str, Any]:
        return self._request(
            "PUT", f"/groups/{gid}/display-name", body={"name": name},
        )

    def groups_leave(self, gid: str) -> Dict[str, Any]:
        return self._request("DELETE", f"/groups/{gid}")

    def open_sse(self, path: str, timeout: float = 60.0):
        req = urllib.request.Request(
            self.base_url + path,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "text/event-stream",
            },
        )
        return urllib.request.urlopen(req, timeout=timeout)


class TestRunner:
    """Single-node mesh test runner."""

    def __init__(self, node_name: str, client: X0xClient) -> None:
        self.node_name = node_name
        self.client = client
        self.log = logging.getLogger(f"runner[{node_name}]")
        self._stop = threading.Event()
        # Outbound delivery is a (envelope, target_aid) tuple.
        # target_aid=None means publish on the legacy results topic
        # (last-resort fallback for orchestrators that don't include
        # an anchor address).
        self._send_q: "queue.Queue[Tuple[Dict[str, Any], Optional[str]]]" = (
            queue.Queue()
        )
        self._agent_id: Optional[str] = None
        self._machine_id: Optional[str] = None
        # Cached anchor agent_id from the last discover round so a
        # `runner_ready` heartbeat can find the orchestrator after a
        # daemon restart, even before the orchestrator publishes a
        # fresh discover.
        self._last_known_anchor_aid: Optional[str] = None

    # ─── lifecycle ─────────────────────────────────────────────────────
    def run(self) -> int:
        try:
            self._bootstrap()
        except Exception as exc:
            self.log.error("bootstrap failed: %s", exc)
            return 2

        threads = [
            threading.Thread(target=self._control_listener_loop, daemon=True),
            threading.Thread(target=self._direct_listener_loop, daemon=True),
            threading.Thread(target=self._publisher_loop, daemon=True),
        ]
        for t in threads:
            t.start()

        self._announce_ready()

        try:
            while not self._stop.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        self._stop.set()
        return 0

    def _bootstrap(self) -> None:
        health = self.client.health()
        if not health.get("ok", False):
            raise RuntimeError(f"daemon not healthy: {health}")
        agent = self.client.agent()
        self._agent_id = agent.get("agent_id")
        self._machine_id = agent.get("machine_id")
        if not self._agent_id:
            raise RuntimeError(f"no agent_id in /agent response: {agent}")
        self.log.info(
            "bootstrap ok: node=%s agent=%s… machine=%s…",
            self.node_name,
            self._agent_id[:16],
            (self._machine_id or "")[:16],
        )
        for topic in (DISCOVER_TOPIC, LEGACY_CONTROL_TOPIC):
            try:
                self.client.subscribe(topic)
                self.log.info("subscribed to %s", topic)
            except Exception as exc:
                self.log.warning(
                    "subscribe %s failed (continuing): %s", topic, exc
                )

    def _announce_ready(self) -> None:
        # Best-effort: if we already know an anchor from a previous
        # discover round (cached across restarts via the daemon's gossip
        # state isn't possible, so this only fires after a re-discover),
        # DM it directly. Otherwise fall back to the legacy results
        # topic so an orchestrator that's already listening on pubsub
        # can still see us come up.
        self._enqueue_result(
            {
                "kind": "runner_ready",
                "command_id": None,
                "request_id": None,
                "outcome": "ok",
                "details": {"started_at_ms": now_ms()},
            },
            target_aid=self._last_known_anchor_aid,
        )

    # ─── outbound delivery (DM-first, pubsub fallback) ─────────────────
    def _publisher_loop(self) -> None:
        while not self._stop.is_set():
            try:
                envelope, target_aid = self._send_q.get(timeout=0.5)
            except queue.Empty:
                continue
            payload = json.dumps(envelope).encode("utf-8")
            if target_aid:
                if self._send_result_dm(target_aid, payload, envelope):
                    continue
                # DM failed irretrievably — fall through to pubsub so the
                # orchestrator at least sees the result on the legacy
                # topic if it's still listening there.
                self.log.warning(
                    "DM result to %s… failed, falling back to pubsub",
                    target_aid[:16],
                )
            self._publish_result_legacy(payload, envelope)

    def _send_result_dm(
        self,
        target_aid: str,
        payload: bytes,
        envelope: Dict[str, Any],
    ) -> bool:
        # Result DMs MUST go through the daemon's default DM path so the
        # gossip-inbox fallback covers brief raw-QUIC outages. Setting
        # require_ack_ms here would force raw_quic_acked and lose the
        # message if the QUIC connection happens to be in supersede.
        wire = b"x0xtest|res|" + base64.b64encode(payload)
        for attempt in range(1, PUBLISH_RETRY_MAX + 1):
            try:
                self.client.direct_send(
                    target_aid, wire, require_ack_ms=RESULT_DM_ACK_MS
                )
                return True
            except urllib.error.HTTPError as exc:
                # 404 = recipient_key_unavailable; not transient.
                if exc.code == 404:
                    self.log.debug(
                        "DM result giving up: HTTP 404 %s",
                        exc.reason,
                    )
                    return False
                self.log.debug(
                    "DM result attempt %d/%d HTTP %d: %s",
                    attempt,
                    PUBLISH_RETRY_MAX,
                    exc.code,
                    exc.reason,
                )
                time.sleep(PUBLISH_RETRY_BACKOFF_SECS * attempt)
            except Exception as exc:
                self.log.debug(
                    "DM result attempt %d/%d failed: %s",
                    attempt,
                    PUBLISH_RETRY_MAX,
                    exc,
                )
                time.sleep(PUBLISH_RETRY_BACKOFF_SECS * attempt)
        return False

    def _publish_result_legacy(
        self, payload: bytes, envelope: Dict[str, Any]
    ) -> None:
        for attempt in range(1, PUBLISH_RETRY_MAX + 1):
            try:
                self.client.publish(LEGACY_RESULTS_TOPIC, payload)
                return
            except Exception as exc:
                self.log.warning(
                    "publish result attempt %d/%d failed: %s",
                    attempt,
                    PUBLISH_RETRY_MAX,
                    exc,
                )
                time.sleep(PUBLISH_RETRY_BACKOFF_SECS * attempt)
        self.log.error("dropping result after retries: %s", envelope)

    def _enqueue_result(
        self,
        body: Dict[str, Any],
        target_aid: Optional[str] = None,
    ) -> None:
        body.setdefault("node", self.node_name)
        body.setdefault("agent_id", self._agent_id)
        body.setdefault("machine_id", self._machine_id)
        body.setdefault("ts_ms", now_ms())
        self._send_q.put((body, target_aid))

    # ─── control-topic listener ────────────────────────────────────────
    def _control_listener_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._consume_sse(
                    "/events",
                    handler=self._handle_pubsub_event,
                    label="pubsub-events",
                )
            except Exception as exc:
                self.log.warning("pubsub SSE disconnected: %s", exc)
                time.sleep(SSE_RECONNECT_BACKOFF_SECS)

    def _direct_listener_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._consume_sse(
                    "/direct/events",
                    handler=self._handle_direct_event,
                    label="direct-events",
                )
            except Exception as exc:
                self.log.warning("direct SSE disconnected: %s", exc)
                time.sleep(SSE_RECONNECT_BACKOFF_SECS)

    def _consume_sse(self, path: str, handler, label: str) -> None:
        self.log.info("opening SSE %s", path)
        # Long-lived stream — set a generous timeout.
        resp = self.client.open_sse(path, timeout=3600 * 6)
        try:
            event_type = "message"
            data_lines = []
            for raw in resp:
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line == "":
                    if data_lines:
                        data = "\n".join(data_lines)
                        try:
                            handler(event_type, data)
                        except Exception as exc:
                            self.log.warning(
                                "handler raised on %s: %s", label, exc
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
        finally:
            try:
                resp.close()
            except Exception:
                pass

    # ─── event handlers ────────────────────────────────────────────────
    def _handle_pubsub_event(self, event_type: str, data: str) -> None:
        if event_type != "message":
            return
        try:
            envelope = json.loads(data)
        except json.JSONDecodeError:
            return
        outer = envelope.get("data") if "data" in envelope else envelope
        if not isinstance(outer, dict):
            return
        topic = outer.get("topic")
        if topic not in (DISCOVER_TOPIC, LEGACY_CONTROL_TOPIC):
            return
        payload_b64 = outer.get("payload")
        if not payload_b64:
            return
        try:
            cmd = json.loads(b64decode(payload_b64))
        except Exception as exc:
            self.log.debug("pubsub payload parse error: %s", exc)
            return
        # Cache the anchor so subsequent (out-of-band) results can
        # find it. The new protocol always sends commands as DMs, so
        # this is mostly relevant for the discover round.
        anchor = cmd.get("anchor_aid") or (
            cmd.get("params") or {}
        ).get("anchor_aid")
        if isinstance(anchor, str) and len(anchor) == 64:
            self._last_known_anchor_aid = anchor
        self._dispatch_command(cmd, source_aid=anchor)

    def _handle_direct_event(self, event_type: str, data: str) -> None:
        if event_type != "direct_message":
            return
        try:
            msg = json.loads(data)
        except json.JSONDecodeError:
            return
        payload_b64 = msg.get("payload")
        if not payload_b64:
            return
        try:
            payload = b64decode(payload_b64)
        except Exception:
            return
        sender_aid = msg.get("sender")
        if not payload.startswith(b"x0xtest|"):
            return
        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            return
        # Phase A protocol: x0xtest|cmd|<b64-json> | x0xtest|res|<b64-json>
        # | x0xtest|hop|<rid>|<digest>|<anchor_aid>|<rest>
        # Legacy:        x0xtest|<rid>|<digest>|<extra>
        parts = text.split("|", 3)
        if len(parts) < 3:
            return
        marker = parts[1]

        if marker == "cmd":
            self._handle_command_dm(parts[2:], sender_aid)
            return
        if marker == "res":
            # Other runner is replying to us — only the orchestrator
            # cares; ignore on a runner.
            return
        if marker == "hop":
            self._handle_hop_dm(text, payload, msg)
            return
        # Legacy v0 prefix: marker is actually the request_id; let the
        # heuristic in _handle_legacy_test_dm decide whether to echo.
        self._handle_legacy_test_dm(text, payload, msg)

    def _handle_command_dm(
        self,
        rest_parts: list,
        sender_aid: Optional[str],
    ) -> None:
        if not rest_parts:
            return
        try:
            envelope_b64 = rest_parts[0]
            envelope_bytes = b64decode(envelope_b64)
            cmd = json.loads(envelope_bytes)
        except Exception as exc:
            self.log.debug("command DM parse error: %s", exc)
            return
        if isinstance(sender_aid, str) and len(sender_aid) == 64:
            self._last_known_anchor_aid = sender_aid
        self._dispatch_command(cmd, source_aid=sender_aid)

    def _handle_hop_dm(
        self,
        text: str,
        payload: bytes,
        msg: Dict[str, Any],
    ) -> None:
        # Format: x0xtest|hop|<request_id>|<digest>|<anchor_aid>|<rest>
        parts = text.split("|", 5)
        if len(parts) < 5:
            return
        request_id = parts[2] or None
        digest = parts[3] or None
        anchor = parts[4] or None
        if anchor and len(anchor) == 64:
            self._last_known_anchor_aid = anchor
        self._enqueue_result(
            {
                "kind": "received_dm",
                "command_id": None,
                "request_id": request_id,
                "outcome": "ok",
                "digest_marker": digest,
                "details": {
                    "sender": msg.get("sender"),
                    "machine_id": msg.get("machine_id"),
                    "verified": msg.get("verified"),
                    "trust_decision": msg.get("trust_decision"),
                    "bytes": len(payload),
                    "via": "hop_dm",
                },
            },
            target_aid=anchor,
        )

    def _handle_legacy_test_dm(
        self,
        text: str,
        payload: bytes,
        msg: Dict[str, Any],
    ) -> None:
        # Legacy: x0xtest|<request_id>|<digest>|<extra>
        parts = text.split("|", 4)
        request_id = parts[1] if len(parts) > 1 else None
        digest = parts[2] if len(parts) > 2 else None
        # No embedded anchor address in legacy traffic — fall back to
        # last-known and (failing that) pubsub.
        self._enqueue_result(
            {
                "kind": "received_dm",
                "command_id": None,
                "request_id": request_id,
                "outcome": "ok",
                "digest_marker": digest,
                "details": {
                    "sender": msg.get("sender"),
                    "machine_id": msg.get("machine_id"),
                    "verified": msg.get("verified"),
                    "trust_decision": msg.get("trust_decision"),
                    "bytes": len(payload),
                    "via": "legacy_dm",
                },
            },
            target_aid=self._last_known_anchor_aid,
        )

    # ─── command dispatch ──────────────────────────────────────────────
    def _dispatch_command(
        self,
        cmd: Dict[str, Any],
        source_aid: Optional[str] = None,
    ) -> None:
        target = cmd.get("target_node", "*")
        if target not in (self.node_name, "*"):
            return
        action = cmd.get("action")
        cmd_id = cmd.get("command_id")
        params = cmd.get("params", {}) or {}
        # Anchor address is taken from the explicit field on the command
        # envelope, falling back to the sender of the command DM (the
        # orchestrator's own agent on the anchor node) and finally to
        # the last-known anchor cached during a previous discover.
        anchor_aid = (
            cmd.get("anchor_aid")
            or params.get("anchor_aid")
            or source_aid
            or self._last_known_anchor_aid
        )
        if isinstance(anchor_aid, str) and len(anchor_aid) == 64:
            self._last_known_anchor_aid = anchor_aid
        else:
            anchor_aid = self._last_known_anchor_aid
        self.log.debug(
            "dispatch %s for cmd=%s (anchor=%s…)",
            action,
            cmd_id,
            (anchor_aid or "")[:16],
        )
        try:
            if action == "discover":
                self._enqueue_result(
                    {
                        "kind": "discover_reply",
                        "command_id": cmd_id,
                        "request_id": params.get("request_id"),
                        "outcome": "ok",
                        "details": {"node": self.node_name},
                    },
                    target_aid=anchor_aid,
                )
            elif action == "noop_ack":
                self._enqueue_result(
                    {
                        "kind": "ack",
                        "command_id": cmd_id,
                        "request_id": params.get("request_id"),
                        "outcome": "ok",
                    },
                    target_aid=anchor_aid,
                )
            elif action == "send_dm":
                self._do_send_dm(cmd_id, params, anchor_aid)
            elif action in (
                "contact_add",
                "contact_update",
                "contact_remove",
                "contact_list",
                "group_create",
                "group_invite",
                "group_join",
                "group_list",
                "group_info",
                "group_members",
                "group_send_message",
                "group_messages",
                "group_set_display_name",
                "group_leave",
            ):
                self._do_simple_action(action, cmd_id, params, anchor_aid)
            else:
                self._enqueue_result(
                    {
                        "kind": "error",
                        "command_id": cmd_id,
                        "request_id": params.get("request_id"),
                        "outcome": {"error": f"unknown action: {action}"},
                    },
                    target_aid=anchor_aid,
                )
        except Exception as exc:
            self.log.exception("command failed: %s", exc)
            self._enqueue_result(
                {
                    "kind": "error",
                    "command_id": cmd_id,
                    "request_id": params.get("request_id"),
                    "outcome": {"error": str(exc)},
                },
                target_aid=anchor_aid,
            )

    def _do_send_dm(
        self,
        cmd_id: Optional[str],
        params: Dict[str, Any],
        anchor_aid: Optional[str],
    ) -> None:
        recipient = params.get("recipient_aid")
        payload_b64 = params.get("payload_b64", "")
        request_id = params.get("request_id") or str(uuid.uuid4())
        require_ack_ms = params.get("require_ack_ms")
        if not recipient:
            self._enqueue_result(
                {
                    "kind": "send_result",
                    "command_id": cmd_id,
                    "request_id": request_id,
                    "outcome": {"error": "missing recipient_aid"},
                },
                target_aid=anchor_aid,
            )
            return
        try:
            payload = b64decode(payload_b64) if payload_b64 else b""
        except Exception as exc:
            self._enqueue_result(
                {
                    "kind": "send_result",
                    "command_id": cmd_id,
                    "request_id": request_id,
                    "outcome": {"error": f"bad payload base64: {exc}"},
                },
                target_aid=anchor_aid,
            )
            return
        digest = params.get("digest_marker")
        # Build a Phase-A `hop` envelope so the recipient can DM the
        # `received_dm` receipt straight back to the orchestrator. The
        # anchor address is embedded inline; no extra runner state.
        if not payload.startswith(b"x0xtest|"):
            tag = digest or request_id
            anchor_inline = anchor_aid or ""
            payload = (
                f"x0xtest|hop|{request_id}|{tag}|{anchor_inline}|".encode(
                    "utf-8"
                )
                + payload
            )
        t0 = time.time()
        last_error: Dict[str, Any] = {}
        last_status: Optional[int] = None
        for attempt in range(1, TEST_DM_RETRY_MAX + 1):
            try:
                resp = self.client.direct_send(
                    recipient,
                    payload,
                    require_ack_ms=require_ack_ms,
                )
                elapsed_ms = int((time.time() - t0) * 1000)
                self._enqueue_result(
                    {
                        "kind": "send_result",
                        "command_id": cmd_id,
                        "request_id": request_id,
                        "outcome": "ok" if resp.get("ok") else {"error": resp},
                        "digest_marker": digest,
                        "details": {
                            "path": resp.get("path"),
                            "retries_used": resp.get("retries_used"),
                            "remote_request_id": resp.get("request_id"),
                            "wall_clock_ms": elapsed_ms,
                            "recipient_aid": recipient,
                            "runner_attempts": attempt,
                        },
                    },
                    target_aid=anchor_aid,
                )
                return
            except urllib.error.HTTPError as exc:
                try:
                    last_error = json.loads(exc.read())
                except Exception:
                    last_error = {"status": exc.code, "reason": exc.reason}
                last_status = exc.code
                self.log.debug(
                    "test DM attempt %d/%d to %s… HTTP %d: %s",
                    attempt,
                    TEST_DM_RETRY_MAX,
                    recipient[:16],
                    exc.code,
                    last_error,
                )
                if exc.code == 404:
                    break
            except Exception as exc:
                last_error = {"error": str(exc)}
                last_status = None
                self.log.debug(
                    "test DM attempt %d/%d to %s… failed: %s",
                    attempt,
                    TEST_DM_RETRY_MAX,
                    recipient[:16],
                    exc,
                )

            if attempt < TEST_DM_RETRY_MAX:
                time.sleep(TEST_DM_RETRY_BACKOFF_SECS * attempt)

        elapsed_ms = int((time.time() - t0) * 1000)
        details: Dict[str, Any] = {
            "wall_clock_ms": elapsed_ms,
            "recipient_aid": recipient,
            "runner_attempts": attempt,
        }
        if last_status is not None:
            details["http_status"] = last_status
        self._enqueue_result(
            {
                "kind": "send_result",
                "command_id": cmd_id,
                "request_id": request_id,
                "outcome": {"error": last_error},
                "digest_marker": digest,
                "details": details,
            },
            target_aid=anchor_aid,
        )

    # ─── Phase B: groups + contacts dispatch ───────────────────────────
    #
    # Each action maps 1:1 to a daemon REST call on the runner's local
    # API. The result envelope kind is "<action>_result" and `details`
    # carries the unredacted JSON response so the orchestrator can
    # inspect it (member rosters, message lists, contact-list deltas,
    # …).
    def _do_simple_action(
        self,
        action: str,
        cmd_id: Optional[str],
        params: Dict[str, Any],
        anchor_aid: Optional[str],
    ) -> None:
        request_id = params.get("request_id") or str(uuid.uuid4())
        try:
            response = self._invoke_simple(action, params)
            self._enqueue_result(
                {
                    "kind": f"{action}_result",
                    "command_id": cmd_id,
                    "request_id": request_id,
                    "outcome": "ok",
                    "details": response,
                },
                target_aid=anchor_aid,
            )
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read())
            except Exception:
                body = {"status": exc.code, "reason": exc.reason}
            self._enqueue_result(
                {
                    "kind": f"{action}_result",
                    "command_id": cmd_id,
                    "request_id": request_id,
                    "outcome": {"error": body, "http_status": exc.code},
                },
                target_aid=anchor_aid,
            )
        except Exception as exc:
            self.log.exception("%s action failed: %s", action, exc)
            self._enqueue_result(
                {
                    "kind": f"{action}_result",
                    "command_id": cmd_id,
                    "request_id": request_id,
                    "outcome": {"error": str(exc)},
                },
                target_aid=anchor_aid,
            )

    def _invoke_simple(
        self, action: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        if action == "contact_list":
            return self.client.contacts_list()
        if action == "contact_add":
            return self.client.contacts_add(
                agent_id=params["agent_id"],
                trust_level=params.get("trust_level", "Unknown"),
                label=params.get("label"),
            )
        if action == "contact_update":
            return self.client.contacts_update(
                agent_id=params["agent_id"],
                trust_level=params["trust_level"],
            )
        if action == "contact_remove":
            return self.client.contacts_remove(params["agent_id"])
        if action == "group_create":
            return self.client.groups_create(
                name=params["name"],
                description=params.get("description", ""),
                preset=params.get("preset"),
            )
        if action == "group_list":
            return self.client.groups_list()
        if action == "group_info":
            return self.client.groups_info(params["group_id"])
        if action == "group_invite":
            return self.client.groups_invite(
                params["group_id"],
                expiry_secs=params.get("expiry_secs"),
            )
        if action == "group_join":
            return self.client.groups_join(params["invite"])
        if action == "group_members":
            return self.client.groups_members(params["group_id"])
        if action == "group_send_message":
            return self.client.groups_send_message(
                params["group_id"],
                params["body"],
                kind=params.get("kind", "chat"),
            )
        if action == "group_messages":
            return self.client.groups_messages(params["group_id"])
        if action == "group_set_display_name":
            return self.client.groups_set_display_name(
                params["group_id"], params["name"]
            )
        if action == "group_leave":
            return self.client.groups_leave(params["group_id"])
        raise ValueError(f"unhandled action: {action}")


def main() -> int:
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    node_name = os.environ.get("NODE_NAME") or os.uname().nodename
    base = os.environ.get("X0X_API_BASE", "http://127.0.0.1:12600")
    token_spec = os.environ.get("X0X_API_TOKEN", "/var/lib/x0x/api-token")
    token = load_token(token_spec)
    if not token:
        logging.error("X0X_API_TOKEN empty after loading from %s", token_spec)
        return 2

    client = X0xClient(base, token)
    runner = TestRunner(node_name=node_name, client=client)
    return runner.run()


if __name__ == "__main__":
    sys.exit(main())
