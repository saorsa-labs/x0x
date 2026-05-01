#!/usr/bin/env python3
"""x0x Phase-D fast dogfood — 2-instance local smoke (~30 s wall-clock).

Designed as the canonical pre-commit test: spawned by
``tests/e2e_dogfood_local.sh`` against alice + bob daemons booted on the
same Mac with no bootstrap. Every assertion is a DM round-trip or a
group-message round-trip — `curl localhost` is used only for the bash
wrapper's daemon-readiness probe + card exchange (same trust domain as
the daemons themselves).

What gets exercised:

    Identity
        anchor /agent → returns deterministic agent_id
    Contacts
        anchor adds bob → list reflects → trust = Trusted → Blocked → remove
    Direct messaging
        anchor → bob test DM with `x0xtest|hop|...` envelope
        bob's runner echoes a `received_dm` result back to the anchor
    Named groups (public_open)
        anchor creates → invite → bob joins
        each member posts; each member sees own message in local cache
        bob leaves → bob's /groups list no longer contains the group

Exits 0 only if every assertion passes. The test must complete within
``--budget-secs`` (default 60); failing the budget is a regression
because the cross-mesh-of-two pair should never need more than a couple
of seconds for any single round-trip.
"""
from __future__ import annotations

import argparse
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
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


PREFIX_CMD = b"x0xtest|cmd|"
PREFIX_RES = b"x0xtest|res|"
PREFIX_HOP = b"x0xtest|hop|"


def now_ms() -> int:
    return int(time.time() * 1000)


# ─── HTTP / SSE plumbing (subset of the e2e_dogfood_groups.py client) ─


class X0xClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def _req(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        timeout: float = 10.0,
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

    def direct_send(
        self, agent_id: str, payload: bytes,
    ) -> Dict[str, Any]:
        return self._req(
            "POST", "/direct/send",
            body={
                "agent_id": agent_id,
                "payload": base64.b64encode(payload).decode("ascii"),
            },
        )

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
        if action == "group_list":
            return self._req("GET", "/groups")
        if action == "group_leave":
            return self._req(
                "DELETE", f"/groups/{params['group_id']}",
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


# ─── result + hop router (handles both res-DMs and hop-DM receipts) ────


@dataclass
class CommandWaiter:
    request_id: str
    queue: "queue.Queue[Dict[str, Any]]" = field(default_factory=queue.Queue)


@dataclass
class HopWaiter:
    request_id: str
    queue: "queue.Queue[Dict[str, Any]]" = field(default_factory=queue.Queue)


class Router:
    def __init__(self, log: logging.Logger) -> None:
        self.log = log
        self._cmd_lock = threading.Lock()
        self._cmd_waiters: Dict[str, CommandWaiter] = {}
        self._hop_lock = threading.Lock()
        self._hop_waiters: Dict[str, HopWaiter] = {}
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def stopped(self) -> bool:
        return self._stop.is_set()

    def register_cmd(self, w: CommandWaiter) -> None:
        with self._cmd_lock:
            self._cmd_waiters[w.request_id] = w

    def deregister_cmd(self, rid: str) -> None:
        with self._cmd_lock:
            self._cmd_waiters.pop(rid, None)

    def register_hop(self, w: HopWaiter) -> None:
        with self._hop_lock:
            self._hop_waiters[w.request_id] = w

    def deregister_hop(self, rid: str) -> None:
        with self._hop_lock:
            self._hop_waiters.pop(rid, None)

    def deliver_res(self, envelope: Dict[str, Any]) -> None:
        rid = envelope.get("request_id")
        if not rid:
            return
        with self._cmd_lock:
            waiter = self._cmd_waiters.get(rid)
        if waiter is not None:
            waiter.queue.put(envelope)
            return
        # A `res` envelope of kind `received_dm` may carry the DM hop
        # request_id rather than a command request_id — route by that.
        if envelope.get("kind") == "received_dm":
            with self._hop_lock:
                waiter = self._hop_waiters.get(rid)
            if waiter is not None:
                waiter.queue.put(envelope)


def consume_direct_sse(
    client: X0xClient, router: Router, log: logging.Logger,
) -> None:
    while not router.stopped():
        try:
            resp = client.open_sse("/direct/events")
        except Exception as exc:
            log.warning("direct SSE open failed: %s", exc)
            time.sleep(1)
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
                        _route_direct_event(
                            event_type, "\n".join(data_lines),
                            router, log,
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
            log.warning("direct SSE read error: %s", exc)
        finally:
            try:
                resp.close()
            except Exception:
                pass
        time.sleep(1)


def _route_direct_event(
    event_type: str, data: str,
    router: Router, log: logging.Logger,
) -> None:
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
        payload = base64.b64decode(payload_b64)
    except Exception:
        return
    if payload.startswith(PREFIX_RES):
        try:
            envelope = json.loads(
                base64.b64decode(payload[len(PREFIX_RES):]),
            )
        except Exception as exc:
            log.debug("res parse error: %s", exc)
            return
        router.deliver_res(envelope)
        return


# ─── harness ───────────────────────────────────────────────────────────


@dataclass
class Runner:
    name: str
    agent_id: str


class Phase_D_Harness:
    def __init__(
        self,
        client: X0xClient,
        router: Router,
        anchor_aid: str,
        anchor_name: str,
        peer: Runner,
        log: logging.Logger,
        cmd_timeout_secs: int = 15,
    ) -> None:
        self.client = client
        self.router = router
        self.anchor_aid = anchor_aid
        self.anchor_name = anchor_name
        self.peer = peer
        self.log = log
        self.cmd_timeout_secs = cmd_timeout_secs
        self.passes: List[str] = []
        self.failures: List[str] = []

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

    # ── primitives ─────────────────────────────────────────────────────
    def call_local(
        self, action: str, params: Dict[str, Any],
    ) -> Dict[str, Any]:
        try:
            return {
                "outcome": "ok",
                "details": self.client.perform(action, params),
            }
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read())
            except Exception:
                body = {"status": exc.code, "reason": exc.reason}
            return {
                "outcome": {"error": body, "http_status": exc.code},
                "details": {},
            }

    def call_remote(
        self, action: str, params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        request_id = str(uuid.uuid4())
        params = dict(
            params or {}, request_id=request_id, anchor_aid=self.anchor_aid,
        )
        envelope = {
            "command_id": request_id,
            "target_node": self.peer.name,
            "action": action,
            "anchor_aid": self.anchor_aid,
            "params": params,
        }
        wire = PREFIX_CMD + base64.b64encode(
            json.dumps(envelope).encode("utf-8")
        )
        waiter = CommandWaiter(request_id=request_id)
        self.router.register_cmd(waiter)
        try:
            self.client.direct_send(self.peer.agent_id, wire)
            try:
                response = waiter.queue.get(timeout=self.cmd_timeout_secs)
            except queue.Empty:
                raise TimeoutError(
                    f"{action} on {self.peer.name} timed out"
                )
        finally:
            self.router.deregister_cmd(request_id)
        if response.get("kind") != f"{action}_result":
            raise RuntimeError(f"unexpected kind: {response.get('kind')}")
        return response

    def hop_round_trip(self, payload: bytes) -> Dict[str, Any]:
        """Send a DM directly to the peer and wait for the runner's
        `received_dm` echo back via direct DM."""
        request_id = str(uuid.uuid4())
        digest = "phase-d"
        wire = (
            PREFIX_HOP
            + f"{request_id}|{digest}|{self.anchor_aid}|".encode("utf-8")
            + payload
        )
        waiter = HopWaiter(request_id=request_id)
        self.router.register_hop(waiter)
        try:
            self.client.direct_send(self.peer.agent_id, wire)
            try:
                return waiter.queue.get(timeout=self.cmd_timeout_secs)
            except queue.Empty:
                raise TimeoutError("hop DM never echoed back")
        finally:
            self.router.deregister_hop(request_id)

    # ── scenarios ──────────────────────────────────────────────────────
    def run(self) -> None:
        self.scenario_identity()
        self.scenario_contacts()
        self.scenario_direct_message()
        self.scenario_group_lifecycle()

    def scenario_identity(self) -> None:
        info = self.client.agent()
        self.assert_pass(
            "anchor /agent returns 64-hex agent_id",
            isinstance(info.get("agent_id"), str)
            and len(info["agent_id"]) == 64,
        )

    def scenario_contacts(self) -> None:
        peer_aid = self.peer.agent_id
        before = self.call_local("contact_list", {})
        self.assert_pass(
            "anchor contact_list returns dict",
            isinstance(before["details"], dict),
        )

        add = self.call_local(
            "contact_add",
            {"agent_id": peer_aid, "trust_level": "Known",
             "label": self.peer.name},
        )
        self.assert_pass(
            "anchor adds peer as Known",
            add["outcome"] == "ok",
        )

        listed = self.call_local("contact_list", {})
        aids = self._contact_aids(listed["details"])
        self.assert_pass(
            "list now includes peer",
            peer_aid in aids,
            f"got {len(aids)} contacts",
        )

        for level in ("Trusted", "Blocked"):
            up = self.call_local(
                "contact_update",
                {"agent_id": peer_aid, "trust_level": level},
            )
            self.assert_pass(
                f"anchor sets peer = {level}",
                up["outcome"] == "ok",
            )

        rem = self.call_local("contact_remove", {"agent_id": peer_aid})
        self.assert_pass(
            "anchor removes peer",
            rem["outcome"] == "ok",
        )
        listed_after = self.call_local("contact_list", {})
        self.assert_pass(
            "list no longer includes peer",
            peer_aid not in self._contact_aids(listed_after["details"]),
        )

    def scenario_direct_message(self) -> None:
        marker = uuid.uuid4().hex[:12]
        try:
            echo = self.hop_round_trip(
                f"phase-d-dm:{marker}".encode("utf-8")
            )
        except Exception as exc:
            self.failures.append(f"hop DM round-trip: {exc}")
            return
        self.assert_pass(
            "DM round-trip echoes received_dm back to anchor",
            echo.get("kind") == "received_dm",
            f"sender={(echo.get('details') or {}).get('sender','')[:16]}…",
        )
        self.assert_pass(
            "DM digest_marker preserved end-to-end",
            echo.get("digest_marker") == "phase-d",
        )

    def scenario_group_lifecycle(self) -> None:
        create = self.call_local(
            "group_create",
            {"name": "Phase-D Smoke",
             "description": "fast-smoke group",
             "preset": "public_open"},
        )
        self.assert_pass(
            "anchor creates group", create["outcome"] == "ok",
        )
        details = create.get("details") or {}
        gid = (
            details.get("group_id")
            or (details.get("group") or {}).get("id")
        )
        if not gid:
            self.failures.append("anchor missing group_id from create")
            return

        inv = self.call_local("group_invite", {"group_id": gid})
        invite_url = (inv.get("details") or {}).get("invite_link")
        self.assert_pass(
            "anchor mints x0x://invite/ link",
            isinstance(invite_url, str)
            and invite_url.startswith("x0x://invite/"),
        )
        if not invite_url:
            return

        try:
            join = self.call_remote(
                "group_join", {"invite": invite_url},
            )
        except Exception as exc:
            self.failures.append(f"peer group_join: {exc}")
            return
        self.assert_pass(
            "peer joins via invite", join.get("outcome") == "ok",
        )
        peer_gid = (join.get("details") or {}).get("group_id") or gid

        # Each member posts in the group and sees their own message.
        anchor_msg = self.call_local(
            "group_send_message",
            {"group_id": gid,
             "body": "phase-d: anchor pings",
             "kind": "chat"},
        )
        self.assert_pass(
            "anchor posts group message",
            anchor_msg["outcome"] == "ok",
        )
        try:
            peer_msg = self.call_remote(
                "group_send_message",
                {"group_id": peer_gid,
                 "body": "phase-d: peer ack",
                 "kind": "chat"},
            )
        except Exception as exc:
            self.failures.append(f"peer group_send_message: {exc}")
            return
        self.assert_pass(
            "peer posts group message",
            peer_msg.get("outcome") == "ok",
        )

        anchor_view = self.call_local(
            "group_messages", {"group_id": gid},
        )
        anchor_bodies = self._message_bodies(anchor_view["details"])
        self.assert_pass(
            "anchor sees own message in local cache",
            "phase-d: anchor pings" in anchor_bodies,
        )

        try:
            peer_view = self.call_remote(
                "group_messages", {"group_id": peer_gid},
            )
        except Exception as exc:
            self.failures.append(f"peer group_messages: {exc}")
            return
        peer_bodies = self._message_bodies(peer_view.get("details") or {})
        self.assert_pass(
            "peer sees own message in local cache",
            "phase-d: peer ack" in peer_bodies,
        )

        # Peer leaves; their /groups list no longer contains the group.
        try:
            leave = self.call_remote(
                "group_leave", {"group_id": peer_gid},
            )
        except Exception as exc:
            self.failures.append(f"peer group_leave: {exc}")
            return
        self.assert_pass(
            "peer leaves group", leave.get("outcome") == "ok",
        )
        try:
            after = self.call_remote("group_list", {})
        except Exception as exc:
            self.failures.append(f"peer group_list after leave: {exc}")
            return
        groups = (after.get("details") or {}).get("groups") or []
        listed_again = any(
            isinstance(g, dict) and (g.get("group_id") or g.get("id")) == peer_gid
            for g in groups
        )
        self.assert_pass(
            "peer's /groups no longer lists the group",
            not listed_again,
        )

    @staticmethod
    def _contact_aids(payload: Any) -> List[str]:
        if not isinstance(payload, dict):
            return []
        contacts = payload.get("contacts")
        if not isinstance(contacts, list):
            return []
        out: List[str] = []
        for c in contacts:
            if isinstance(c, dict):
                aid = c.get("agent_id") or c.get("agentId")
                if aid:
                    out.append(aid)
        return out

    @staticmethod
    def _message_bodies(payload: Any) -> List[str]:
        if not isinstance(payload, dict):
            return []
        msgs = payload.get("messages")
        if not isinstance(msgs, list):
            return []
        out: List[str] = []
        for m in msgs:
            if isinstance(m, dict):
                body = m.get("body")
                if body is not None:
                    out.append(body)
        return out


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Phase-D fast 2-instance dogfood smoke",
    )
    parser.add_argument("--api-base", required=True)
    parser.add_argument("--api-token", required=True)
    parser.add_argument("--anchor", default="alice")
    parser.add_argument("--peer-name", default="bob")
    parser.add_argument("--peer-aid", required=True,
                        help="64-hex agent_id of the peer runner")
    parser.add_argument("--cmd-timeout", type=int, default=15)
    parser.add_argument("--budget-secs", type=int, default=60)
    parser.add_argument("--report", default=None)
    args = parser.parse_args(argv)

    if len(args.peer_aid) != 64:
        print(f"--peer-aid must be 64 hex chars, got len={len(args.peer_aid)}",
              file=sys.stderr)
        return 2

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    log = logging.getLogger("e2e_dogfood_local")

    started = time.time()
    client = X0xClient(args.api_base, args.api_token)
    health = client.health()
    if not health.get("ok"):
        log.error("anchor health failed: %s", health)
        return 2
    anchor_aid = client.agent().get("agent_id")
    if not isinstance(anchor_aid, str) or len(anchor_aid) != 64:
        log.error("anchor missing agent_id")
        return 2
    log.info("anchor=%s aid=%s…", args.anchor, anchor_aid[:16])
    log.info("peer=%s aid=%s…", args.peer_name, args.peer_aid[:16])

    router = Router(log)
    sse_thread = threading.Thread(
        target=consume_direct_sse, args=(client, router, log), daemon=True,
    )
    sse_thread.start()
    time.sleep(1)

    harness = Phase_D_Harness(
        client=client, router=router,
        anchor_aid=anchor_aid, anchor_name=args.anchor,
        peer=Runner(name=args.peer_name, agent_id=args.peer_aid),
        log=log, cmd_timeout_secs=args.cmd_timeout,
    )

    try:
        harness.run()
    except Exception as exc:
        log.exception("scenario crashed: %s", exc)
        harness.failures.append(f"scenario crash: {exc}")

    router.stop()
    elapsed = time.time() - started
    log.info("=" * 60)
    log.info(
        "Phase-D smoke — pass=%d fail=%d elapsed=%.1fs (budget=%ds)",
        len(harness.passes), len(harness.failures), elapsed,
        args.budget_secs,
    )
    for f in harness.failures:
        log.info("  FAIL: %s", f)
    log.info("=" * 60)

    if elapsed > args.budget_secs:
        harness.failures.append(
            f"BUDGET: {elapsed:.1f}s > {args.budget_secs}s"
        )
        log.error("  BUDGET EXCEEDED: %.1fs > %ds",
                  elapsed, args.budget_secs)

    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "anchor": args.anchor,
                        "anchor_aid": anchor_aid,
                        "peer": args.peer_name,
                        "peer_aid": args.peer_aid,
                        "passes": harness.passes,
                        "failures": harness.failures,
                        "elapsed_secs": elapsed,
                    },
                    fh, indent=2,
                )
        except Exception as exc:
            log.warning("could not write report: %s", exc)

    return 0 if not harness.failures else 1


if __name__ == "__main__":
    sys.exit(main())
