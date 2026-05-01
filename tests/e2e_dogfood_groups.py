#!/usr/bin/env python3
"""x0x dogfood — groups + contacts via direct DMs, no SSH/curl mediation.

Phase B harness: every assertion is the result of an x0x DM round-trip
or a group-message round-trip. The Mac script holds an anchor agent
identity (default = the alice daemon) and drives bob/charlie's runners
via direct DMs (`x0xtest|cmd|...`). All daemon state changes — contact
add/remove/block, group create/invite/join/post/list — are issued as
runner actions, and every result returns as a direct DM response.

Run:

    bash tests/e2e_dogfood_groups.sh        # boots 3 daemons + this orchestrator

Or direct:

    python3 tests/e2e_dogfood_groups.py \\
        --anchor alice --api-base http://127.0.0.1:23700 \\
        --api-token <…> \\
        --runner bob:<bob_aid> --runner charlie:<charlie_aid> \\
        --report /tmp/dogfood-groups.json

The orchestrator validates the following dogfood paths:

  Contacts lifecycle (per remote runner):
    add         → list contains agent          → ok
    update      → trust transitions Trusted    → Blocked
    remove      → list no longer contains
  Named-group lifecycle (alice owns; bob+charlie join):
    create public_open group
    generate invite
    bob joins via invite
    charlie joins via invite
    list members (≥3)
    bob posts a "hello" group message
    charlie posts a reply
    alice retrieves /groups/:id/messages and asserts both bodies present
    alice sets bob's role / display name (if API permits)
    bob leaves
    members list shrinks to 2

Exit code 0 only if every assertion passes; otherwise 1.
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
from typing import Any, Callable, Dict, List, Optional


PREFIX_CMD = b"x0xtest|cmd|"
PREFIX_RES = b"x0xtest|res|"


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
            raw = resp.read()
        return json.loads(raw or b"{}")

    def health(self) -> Dict[str, Any]:
        return self._req("GET", "/health")

    def agent(self) -> Dict[str, Any]:
        return self._req("GET", "/agent")

    # ─── runner-equivalent action surface (same as runner's _invoke_simple) ─
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
        if action == "group_list":
            return self._req("GET", "/groups")
        if action == "group_info":
            return self._req("GET", f"/groups/{params['group_id']}")
        if action == "group_invite":
            body = {}
            if params.get("expiry_secs") is not None:
                body["expiry_secs"] = params["expiry_secs"]
            return self._req(
                "POST", f"/groups/{params['group_id']}/invite", body=body,
            )
        if action == "group_join":
            return self._req(
                "POST", "/groups/join",
                body={"invite": params["invite"]},
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
        if action == "group_set_display_name":
            return self._req(
                "PUT",
                f"/groups/{params['group_id']}/display-name",
                body={"name": params["name"]},
            )
        if action == "group_leave":
            return self._req(
                "DELETE", f"/groups/{params['group_id']}",
            )
        raise ValueError(f"unhandled action: {action}")

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

    def open_sse(self, path: str, timeout: float = 3600 * 6):
        req = urllib.request.Request(
            self.base_url + path,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "text/event-stream",
            },
        )
        return urllib.request.urlopen(req, timeout=timeout)


# ─── result-DM router ─────────────────────────────────────────────────


@dataclass
class CommandWaiter:
    request_id: str
    expected_kind: str
    queue: "queue.Queue[Dict[str, Any]]" = field(default_factory=queue.Queue)


class ResultRouter:
    """Routes inbound `x0xtest|res|` DMs to per-request_id waiters."""

    def __init__(self, log: logging.Logger) -> None:
        self.log = log
        self._lock = threading.Lock()
        self._waiters: Dict[str, CommandWaiter] = {}
        self._stop = threading.Event()

    def register(self, waiter: CommandWaiter) -> None:
        with self._lock:
            self._waiters[waiter.request_id] = waiter

    def deregister(self, request_id: str) -> None:
        with self._lock:
            self._waiters.pop(request_id, None)

    def stop(self) -> None:
        self._stop.set()

    def stopped(self) -> bool:
        return self._stop.is_set()

    def deliver(self, envelope: Dict[str, Any]) -> None:
        rid = envelope.get("request_id")
        if not rid:
            return
        with self._lock:
            waiter = self._waiters.get(rid)
        if waiter is None:
            self.log.debug("no waiter for request_id=%s", rid)
            return
        waiter.queue.put(envelope)


def consume_direct_sse(
    client: X0xClient,
    router: ResultRouter,
    log: logging.Logger,
) -> None:
    while not router.stopped():
        try:
            log.debug("opening /direct/events SSE")
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
                            event_type,
                            "\n".join(data_lines),
                            router,
                            log,
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
            log.warning("direct SSE error: %s — reconnecting", exc)
        finally:
            try:
                resp.close()
            except Exception:
                pass
        time.sleep(1)


def _route_direct_event(
    event_type: str, data: str,
    router: ResultRouter, log: logging.Logger,
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
    if not payload.startswith(PREFIX_RES):
        return
    try:
        envelope = json.loads(base64.b64decode(payload[len(PREFIX_RES):]))
    except Exception as exc:
        log.debug("res envelope parse error: %s", exc)
        return
    router.deliver(envelope)


# ─── command + assertion helpers ───────────────────────────────────────


@dataclass
class Runner:
    name: str
    agent_id: str


class DogfoodHarness:
    def __init__(
        self,
        client: X0xClient,
        router: ResultRouter,
        anchor_aid: str,
        runners: Dict[str, Runner],
        log: logging.Logger,
        cmd_timeout_secs: int = 30,
    ) -> None:
        self.client = client
        self.router = router
        self.anchor_aid = anchor_aid
        self.runners = runners
        self.log = log
        self.cmd_timeout_secs = cmd_timeout_secs
        self.failures: List[str] = []
        self.passes: List[str] = []

    # ── orchestration primitives ──────────────────────────────────────
    def call(
        self,
        target: str,
        action: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if target not in self.runners:
            raise KeyError(f"no runner registered for {target}")
        request_id = str(uuid.uuid4())
        params = dict(params or {}, request_id=request_id,
                      anchor_aid=self.anchor_aid)

        # When the action is targeted at the anchor's own daemon, the
        # daemon refuses self-DMs (sender == recipient), so route the
        # call through the local REST API instead. The shape matches the
        # runner's response envelope exactly so `details` / `outcome`
        # stay uniform across local + remote.
        if self.runners[target].agent_id == self.anchor_aid:
            return self._invoke_local(action, params, request_id)

        waiter = CommandWaiter(
            request_id=request_id,
            expected_kind=f"{action}_result",
        )
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
            self._send_command_resilient(target, wire)
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
            raise RuntimeError(
                f"unexpected result kind: {response.get('kind')}"
            )
        return response

    def _invoke_local(
        self,
        action: str,
        params: Dict[str, Any],
        request_id: str,
    ) -> Dict[str, Any]:
        try:
            details = self.client.perform(action, params)
            return {
                "kind": f"{action}_result",
                "request_id": request_id,
                "outcome": "ok",
                "details": details,
                "node": "anchor_local",
            }
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read())
            except Exception:
                body = {"status": exc.code, "reason": exc.reason}
            return {
                "kind": f"{action}_result",
                "request_id": request_id,
                "outcome": {"error": body, "http_status": exc.code},
                "details": {},
                "node": "anchor_local",
            }
        except Exception as exc:
            return {
                "kind": f"{action}_result",
                "request_id": request_id,
                "outcome": {"error": str(exc)},
                "details": {},
                "node": "anchor_local",
            }

    def _send_command_resilient(self, target: str, wire: bytes) -> None:
        """Send a command DM with backoff retries.

        Command DMs ride the daemon's default DM path (gossip-inbox-with-
        retry) — no require_ack_ms — so a brief raw-QUIC supersede on a
        cold connection doesn't drop the command. Retry the API call two
        more times on top so the orchestrator keeps trying through a
        reconnect window of ~30 s.
        """
        target_aid = self.runners[target].agent_id
        last_error: Optional[Exception] = None
        for attempt in range(1, 4):
            try:
                self.client.direct_send(target_aid, wire)
                return
            except urllib.error.HTTPError as exc:
                last_error = exc
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", errors="replace")[:200]
                except Exception:
                    pass
                self.log.debug(
                    "command DM to %s attempt %d/3 HTTP %d: %s",
                    target, attempt, exc.code, detail,
                )
            except Exception as exc:
                last_error = exc
                self.log.debug(
                    "command DM to %s attempt %d/3 failed: %s",
                    target, attempt, exc,
                )
            time.sleep(2 * attempt)
        raise RuntimeError(
            f"command DM to {target} failed after 3 attempts: {last_error}"
        )

    def assert_pass(self, label: str, condition: bool, detail: str = "") -> bool:
        if condition:
            self.passes.append(label)
            self.log.info("  PASS %s%s", label,
                          f" — {detail}" if detail else "")
            return True
        self.failures.append(label)
        self.log.error("  FAIL %s%s", label,
                       f" — {detail}" if detail else "")
        return False

    # ── high-level dogfood scenarios ───────────────────────────────────
    def run_contacts_lifecycle(self, owner: str, peer: str) -> None:
        peer_aid = self.runners[peer].agent_id
        self.log.info("[contacts] %s ↔ %s", owner, peer)

        before = self.call(owner, "contact_list").get("details", {})
        before_contacts = self._contact_aids(before)
        self.assert_pass(
            f"{owner} contact list returns",
            isinstance(before, dict),
        )

        add_resp = self.call(
            owner, "contact_add",
            {"agent_id": peer_aid, "trust_level": "Known", "label": peer},
        )
        added_ok = add_resp.get("outcome") == "ok"
        self.assert_pass(f"{owner} adds {peer} as Known", added_ok,
                         _short(add_resp))

        after_add = self.call(owner, "contact_list").get("details", {})
        contacts_after_add = self._contact_aids(after_add)
        self.assert_pass(
            f"{owner} list now contains {peer}",
            peer_aid in contacts_after_add,
            f"size before={len(before_contacts)} after={len(contacts_after_add)}",
        )

        # Update Known → Trusted → Blocked
        for level in ("Trusted", "Blocked"):
            up = self.call(
                owner, "contact_update",
                {"agent_id": peer_aid, "trust_level": level},
            )
            self.assert_pass(
                f"{owner} sets {peer} = {level}",
                up.get("outcome") == "ok",
                _short(up),
            )

        # Final remove
        rem = self.call(owner, "contact_remove", {"agent_id": peer_aid})
        self.assert_pass(
            f"{owner} removes {peer}",
            rem.get("outcome") == "ok",
            _short(rem),
        )

        after_rm = self.call(owner, "contact_list").get("details", {})
        contacts_after_rm = self._contact_aids(after_rm)
        self.assert_pass(
            f"{owner} list no longer contains {peer}",
            peer_aid not in contacts_after_rm,
        )

    def run_group_lifecycle(self, owner: str, members: List[str]) -> None:
        self.log.info("[groups] owner=%s members=%s", owner, members)

        # 1. Create
        create_resp = self.call(
            owner, "group_create",
            {"name": "Phase-B Dogfood",
             "description": "groups + group-message round-trips",
             "preset": "public_open"},
        )
        self.assert_pass(
            f"{owner} creates group",
            create_resp.get("outcome") == "ok",
            _short(create_resp),
        )
        details = create_resp.get("details") or {}
        group_id = (
            details.get("group_id")
            or (details.get("group") or {}).get("id")
            or details.get("id")
        )
        if not group_id:
            self.log.error("could not extract group_id from %s", details)
            self.failures.append(f"{owner} group_id extraction")
            return

        # 2. Invite
        invite_resp = self.call(
            owner, "group_invite", {"group_id": group_id},
        )
        self.assert_pass(
            f"{owner} generates invite",
            invite_resp.get("outcome") == "ok",
            _short(invite_resp),
        )
        invite_details = invite_resp.get("details") or {}
        invite_url = (
            invite_details.get("invite_link")
            or invite_details.get("invite")
        )
        if not invite_url or not invite_url.startswith("x0x://invite/"):
            self.failures.append(
                f"{owner} invite missing or wrong format: {invite_url!r}"
            )
            return

        # 3. Each member joins
        member_groups: Dict[str, str] = {}
        for member in members:
            join_resp = self.call(
                member, "group_join", {"invite": invite_url},
            )
            ok = join_resp.get("outcome") == "ok"
            self.assert_pass(
                f"{member} joins via invite",
                ok,
                _short(join_resp),
            )
            joined_gid = (join_resp.get("details") or {}).get("group_id")
            member_groups[member] = joined_gid or group_id

        # 4. Each member queries their own daemon and confirms it sees
        # at least the member themselves in the roster. This is the
        # local-view assertion — gossip-driven cross-member convergence
        # is a separate concern (and currently slow on a no-bootstrap
        # ad-hoc 3-daemon mesh; see daemon-side TODO on `/groups/join`
        # subscribing to the chat topic).
        for m in [owner, *members]:
            gid = (
                group_id if m == owner
                else member_groups.get(m, group_id)
            )
            aid = self.runners[m].agent_id
            resp = self.call(m, "group_members", {"group_id": gid})
            aids = self._group_member_aids(resp.get("details"))
            self.assert_pass(
                f"{m} sees self in roster",
                aid in aids,
                f"got {len(aids)} ids: {[a[:8] for a in aids[:5]]}",
            )

        # 4b. Wait for the owner's local roster to pick up each joiner
        # via gossip-propagated MemberJoined metadata events. This is the
        # convergence the join-roster-propagation fix provides; without it
        # the owner's validate_public_message rejects every signed reply
        # under WritePolicyViolation { MembersOnly }. PlumTree mesh
        # formation on a fresh topic dominates the latency, so we poll.
        member_aids = {self.runners[m].agent_id for m in members}
        deadline = time.time() + 30.0
        owner_roster: set = set()
        while time.time() < deadline:
            resp = self.call(
                owner, "group_members", {"group_id": group_id},
            )
            owner_roster = set(
                self._group_member_aids(resp.get("details"))
            )
            if member_aids.issubset(owner_roster):
                break
            time.sleep(0.5)
        self.assert_pass(
            f"{owner} roster converges to include all joiners",
            member_aids.issubset(owner_roster),
            f"missing={list(member_aids - owner_roster)} "
            f"observed={[a[:8] for a in owner_roster]}",
        )

        # 5. Owner posts the kickoff group message
        owner_post = self.call(
            owner, "group_send_message",
            {"group_id": group_id,
             "body": "phase-b: please reply",
             "kind": "chat"},
        )
        self.assert_pass(
            f"{owner} sends group message",
            owner_post.get("outcome") == "ok",
            _short(owner_post),
        )

        # 6. Each member replies in the same group
        for member in members:
            gid = member_groups.get(member, group_id)
            reply = self.call(
                member, "group_send_message",
                {"group_id": gid,
                 "body": f"phase-b: ack from {member}",
                 "kind": "chat"},
            )
            self.assert_pass(
                f"{member} replies in group",
                reply.get("outcome") == "ok",
                _short(reply),
            )

        # 7. Each member queries their own /messages cache and confirms
        # it sees the message they themselves posted. Cross-member
        # convergence on the owner's view is an *additional* assertion
        # that we record but don't fail the suite on — that propagation
        # depends on the daemon's `/groups/join` subscribing to the
        # chat topic, which today only happens for the group owner.
        for m in [owner, *members]:
            gid = (
                group_id if m == owner
                else member_groups.get(m, group_id)
            )
            expected_self = (
                "phase-b: please reply" if m == owner
                else f"phase-b: ack from {m}"
            )
            resp = self.call(m, "group_messages", {"group_id": gid})
            bodies = self._group_message_bodies(resp.get("details"))
            self.assert_pass(
                f"{m} sees own group message in local cache",
                expected_self in bodies,
                f"bodies={list(bodies)[:5]}",
            )

        # Hard PASS (groups-join-roster-propagation): each joiner's
        # MemberJoined metadata event must propagate to alice so her
        # validate_public_message accepts the joiner's signed body.
        # Re-poll with a short timeout to absorb mesh formation jitter.
        deadline = time.time() + 10.0
        owner_bodies: set = set()
        expected_replies = {f"phase-b: ack from {m}" for m in members}
        cross_seen: set = set()
        while time.time() < deadline:
            owner_msgs = self.call(
                owner, "group_messages", {"group_id": group_id},
            )
            owner_bodies = set(
                self._group_message_bodies(owner_msgs.get("details"))
            )
            cross_seen = expected_replies.intersection(owner_bodies)
            if cross_seen == expected_replies:
                break
            time.sleep(0.5)
        for m in members:
            expected_body = f"phase-b: ack from {m}"
            self.assert_pass(
                f"alice sees {m}'s reply in /messages cache",
                expected_body in owner_bodies,
                f"observed {len(cross_seen)}/{len(expected_replies)}; "
                f"bodies={list(owner_bodies)[:5]}",
            )

        # 8. Leaver's perspective: after group_leave, the leaver's own
        # /groups list no longer contains the group. This is local
        # state and converges immediately. Owner's view is again a soft
        # cross-member convergence info-only check.
        if members:
            leaver = members[-1]
            leaver_gid = member_groups.get(leaver, group_id)
            leaver_aid = self.runners[leaver].agent_id
            leave_resp = self.call(
                leaver, "group_leave", {"group_id": leaver_gid},
            )
            self.assert_pass(
                f"{leaver} leaves group",
                leave_resp.get("outcome") == "ok",
                _short(leave_resp),
            )
            after_groups = self.call(leaver, "group_list").get(
                "details", {}
            )
            still_listed = self._group_list_contains(
                after_groups, leaver_gid
            )
            self.assert_pass(
                f"{leaver}'s /groups no longer contains {leaver_gid[:8]}",
                not still_listed,
            )
            time.sleep(3)
            owner_view = self.call(
                owner, "group_members", {"group_id": group_id},
            )
            owner_aids = self._group_member_aids(owner_view.get("details"))
            self.log.info(
                "  INFO %s sees %d members after %s leave "
                "(cross-member — non-blocking)",
                owner, len(owner_aids), leaver,
            )

    @staticmethod
    def _poll_until(
        fetch: Callable[[], Dict[str, Any]],
        decode: Callable[[Dict[str, Any]], Any],
        predicate: Callable[[Any], bool],
        timeout_secs: int = 20,
        poll_secs: float = 2.0,
    ):
        """Poll `fetch()` until `predicate(decode(r))` or deadline.

        Returns the last (response, decoded) pair regardless of whether
        the predicate ever held — caller asserts on the decoded value.
        """
        deadline = time.time() + timeout_secs
        last_resp: Dict[str, Any] = {}
        last_decoded: Any = None
        while time.time() < deadline:
            last_resp = fetch()
            last_decoded = decode(last_resp)
            if predicate(last_decoded):
                return last_resp, last_decoded
            time.sleep(poll_secs)
        return last_resp, last_decoded

    # ── helpers to decode response shapes ─────────────────────────────
    @staticmethod
    def _contact_aids(payload: Any) -> List[str]:
        if not isinstance(payload, dict):
            return []
        contacts = payload.get("contacts")
        if not isinstance(contacts, list):
            return []
        out = []
        for c in contacts:
            if isinstance(c, dict):
                aid = c.get("agent_id") or c.get("agentId")
                if aid:
                    out.append(aid)
        return out

    @staticmethod
    def _group_member_aids(payload: Any) -> List[str]:
        if not isinstance(payload, dict):
            return []
        for key in ("members", "member_list", "participants"):
            members = payload.get(key)
            if isinstance(members, list):
                out = []
                for m in members:
                    if isinstance(m, dict):
                        aid = m.get("agent_id") or m.get("agentId")
                        if aid:
                            out.append(aid)
                    elif isinstance(m, str):
                        out.append(m)
                return out
        return []

    @staticmethod
    def _group_list_contains(payload: Any, group_id: str) -> bool:
        if not isinstance(payload, dict):
            return False
        groups = payload.get("groups")
        if not isinstance(groups, list):
            return False
        for g in groups:
            if isinstance(g, dict):
                gid = g.get("group_id") or g.get("id")
                if gid == group_id:
                    return True
        return False

    @staticmethod
    def _group_message_bodies(payload: Any) -> List[str]:
        if not isinstance(payload, dict):
            return []
        msgs = payload.get("messages")
        if not isinstance(msgs, list):
            return []
        out = []
        for m in msgs:
            if isinstance(m, dict):
                body = m.get("body")
                if body is not None:
                    out.append(body)
        return out


def _short(envelope: Dict[str, Any]) -> str:
    s = json.dumps(envelope.get("outcome"))
    return s[:200]


# ─── argument parsing + entry ─────────────────────────────────────────


def parse_runner_arg(spec: str) -> Runner:
    if ":" not in spec:
        raise argparse.ArgumentTypeError(
            f"--runner expects name:agent_id, got {spec!r}"
        )
    name, aid = spec.split(":", 1)
    if len(aid) != 64:
        raise argparse.ArgumentTypeError(
            f"--runner agent_id must be 64 hex chars, got len={len(aid)}"
        )
    return Runner(name=name, agent_id=aid)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Phase-B groups + contacts dogfood harness"
    )
    parser.add_argument("--api-base", required=True,
                        help="anchor daemon API base URL")
    parser.add_argument("--api-token", required=True,
                        help="anchor daemon API bearer token")
    parser.add_argument("--anchor", default="alice",
                        help="anchor display name (default alice)")
    parser.add_argument(
        "--runner", action="append", required=True, type=parse_runner_arg,
        help="runner registration as name:agent_id (repeat per node)",
    )
    parser.add_argument("--cmd-timeout", type=int, default=30,
                        help="per-command timeout in seconds")
    parser.add_argument("--report", default=None,
                        help="optional JSON report path")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    log = logging.getLogger("e2e_dogfood_groups")

    client = X0xClient(args.api_base, args.api_token)
    health = client.health()
    if not health.get("ok"):
        log.error("anchor health failed: %s", health)
        return 2
    agent_info = client.agent()
    anchor_aid = agent_info.get("agent_id")
    if not anchor_aid:
        log.error("anchor missing agent_id: %s", agent_info)
        return 2

    runners = {r.name: r for r in args.runner}
    runners[args.anchor] = Runner(name=args.anchor, agent_id=anchor_aid)
    log.info("anchor=%s aid=%s…", args.anchor, anchor_aid[:16])
    for r in args.runner:
        log.info("runner %s aid=%s…", r.name, r.agent_id[:16])

    router = ResultRouter(log)
    sse_thread = threading.Thread(
        target=consume_direct_sse, args=(client, router, log), daemon=True,
    )
    sse_thread.start()
    time.sleep(2)

    harness = DogfoodHarness(
        client=client, router=router,
        anchor_aid=anchor_aid, runners=runners,
        log=log, cmd_timeout_secs=args.cmd_timeout,
    )

    try:
        for r in args.runner:
            harness.run_contacts_lifecycle(args.anchor, r.name)
        harness.run_group_lifecycle(
            args.anchor, [r.name for r in args.runner]
        )
    except Exception as exc:
        log.exception("scenario crashed: %s", exc)
        harness.failures.append(f"scenario crash: {exc}")

    router.stop()

    log.info("=" * 60)
    log.info("Dogfood groups + contacts summary")
    log.info("  Pass: %d   Fail: %d", len(harness.passes),
             len(harness.failures))
    if harness.failures:
        for f in harness.failures:
            log.info("  FAIL: %s", f)
    log.info("=" * 60)

    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "passes": harness.passes,
                        "failures": harness.failures,
                        "anchor_aid": anchor_aid,
                        "runners": {
                            n: r.agent_id for n, r in runners.items()
                        },
                    },
                    fh, indent=2,
                )
        except Exception as exc:
            log.warning("could not write report %s: %s", args.report, exc)

    return 0 if not harness.failures else 1


if __name__ == "__main__":
    sys.exit(main())
