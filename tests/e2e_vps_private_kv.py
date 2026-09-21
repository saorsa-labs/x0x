#!/usr/bin/env python3
"""Strict testnet acceptance for private TreeKEM and canonical Home Wiki/Web stores.

The harness reuses the ordinary #565 tunnel, API, polling, evidence, and service
custody primitives. It never addresses a production unit. Both scenarios are
selected explicitly with ``--scenario``; missing Home ownership/seating support
is a failed prerequisite, never a skip or a substitute group.
"""
from __future__ import annotations

import argparse
import json
import uuid
from typing import Any, Callable

from e2e_tunnel import TunnelHandle, start_ssh_tunnel, stop_ssh_tunnel
from e2e_vps_groups import NODES_DEFAULT, load_tokens
from e2e_vps_kv import Api, Evidence, Scenario as SharedScenario, ServiceCustody, active_provider_ids, enc, poll


class Scenario(SharedScenario):
    def join_private(self, owner: str, member: str, gid: str, invite: str | None = None) -> None:
        self.join(owner, member, gid, invite)

    def home(self, owner: str) -> tuple[str, str]:
        status, body = self.c[owner].request("GET", "/home")
        self.e.check("canonical Home is locally available", status == 200 and body.get("state") == "local",
                     status=status, state=body.get("state"))
        gid, owner_id = body.get("group_id"), body.get("owner_user_id")
        self.e.check("Home identifiers returned", isinstance(gid, str) and bool(gid)
                     and isinstance(owner_id, str) and len(owner_id) == 64)
        owner_agent = self.c[owner].agent_id()
        roster_status, roster = self.c[owner].request("GET", f"/groups/{enc(gid)}/members")
        active = active_provider_ids(roster_status, roster)
        self.e.check("Home fixture starts owner-only", roster_status == 200 and active == {owner_agent},
                     status=roster_status, active_count=len(active))
        return gid, owner_id

    def require_home_identity(self, node: str, owner_id: str) -> None:
        status, body = self.c[node].request("GET", "/agent/user-id")
        self.e.check(f"{node} is owner-certified for Home", status == 200
                     and body.get("user_id") == owner_id, status=status)

    def home_invite(self, owner: str, member: str, gid: str, owner_id: str) -> str:
        aid = self.c[member].agent_id()
        status, body = self.c[owner].request("POST", "/home/seat", {"agent_id": aid})
        self.e.check(f"Home seat invite for {member}", status == 200 and body.get("ok") is True
                     and body.get("group_id") == gid and body.get("owner_user_id") == owner_id
                     and body.get("intended_joiner") == aid and body.get("seated") is False,
                     status=status, reason=body.get("reason"))
        invite = body.get("invite")
        self.e.check(f"addressed Home invite for {member}", isinstance(invite, str)
                     and invite.startswith("x0x://invite/"))
        return invite

    def join_home(self, owner: str, member: str, gid: str, owner_id: str, invite: str) -> None:
        status, body = self.c[member].request("POST", "/groups/join", {
            "invite": invite, "mode": "home", "expected_owner_user_id": owner_id})
        self.e.check(f"{member} joined canonical Home", status in (200, 201)
                     and body.get("ok") is not False and body.get("group_id", gid) == gid,
                     status=status)
        aid = self.c[member].agent_id()
        poll(f"{member} Home seat reaches owner", self.timeout,
             lambda: self.c[owner].request("GET", f"/groups/{enc(gid)}/members"),
             lambda result: result[0] == 200
             and any(row.get("agent_id") == aid for row in result[1].get("members", [])))

    def exercise(self, label: str, owner: str, writer: str, late: str, revoked: str,
                 gid: str, late_invite: str, join_late: Callable[[], None],
                 stop_owner: Callable[[], None], restart_writer: Callable[[str, set[str]], None]) -> None:
        stores: dict[str, str] = {}
        actor_ids = {node: self.c[node].agent_id() for node in (owner, writer, late)}
        key_prefix = f"x0x-e2e-{uuid.uuid4().hex}"
        owner_key, member_key, removed_key, forbidden_key = (
            f"{key_prefix}-owner", f"{key_prefix}-member", f"{key_prefix}-removed",
            f"{key_prefix}-revoked")
        for app in ("wiki", "web"):
            first = self.open_store(owner, gid, app)
            second = self.open_store(writer, gid, app)
            sid = first.get("id")
            self.e.check(f"{label} deterministic {app} store", isinstance(sid, str) and sid == second.get("id"))
            stores[app] = sid
            self.open_store(revoked, gid, app)
            self.e.check(f"{label} owner writes {app}", self.put(owner, sid, owner_key, f"{label}-owner-{app}")[0] == 200)
            self.e.check(f"{label} member writes {app}", self.put(writer, sid, member_key, f"{label}-member-{app}")[0] == 200)
            self.await_value(owner, sid, member_key, f"{label}-member-{app}")
            self.e.check(f"{label} seeds tombstone {app}", self.put(owner, sid, removed_key, "gone")[0] == 200)
            self.await_value(writer, sid, removed_key, "gone")
            self.e.check(f"{label} deletes before late join {app}",
                         self.c[owner].request("DELETE", f"/stores/{enc(sid)}/{enc(removed_key)}")[0] == 200)
            self.await_absent(writer, sid, removed_key)

        revoke_id = self.c[revoked].agent_id()
        self.e.check(f"{label} removes member",
                     self.c[owner].request("DELETE", f"/groups/{enc(gid)}/members/{revoke_id}")[0] == 200)
        poll(f"{label} revocation reaches former member", self.timeout,
             lambda: self.c[revoked].request("POST", f"/groups/{enc(gid)}/stores", {"name": "wiki"}),
             lambda result: result[0] in (403, 404, 409))
        denied = self.put(revoked, stores["wiki"], forbidden_key, "bad")
        self.e.check(f"{label} revoked mutation refused", denied[0] in (403, 404), status=denied[0])
        self.prove_denied_did_not_converge(owner, writer, stores["wiki"], forbidden_key)

        # The late invite is minted before the creator goes offline. The join
        # and retained encrypted/tombstone recovery must then be served by the
        # remaining member; no creator request can answer after stop_owner.
        self.e.check(f"{label} late invite retained", late_invite.startswith("x0x://invite/"))
        stop_owner()
        join_late()
        for app, sid in stores.items():
            reopened = self.open_store(late, gid, app)
            self.e.check(f"{label} late {app} identity", reopened.get("id") == sid)
            self.await_value(late, sid, owner_key, f"{label}-owner-{app}")
            self.await_value(late, sid, member_key, f"{label}-member-{app}")
            self.await_absent(late, sid, removed_key)

        expected = set(actor_ids.values())
        restart_writer(gid, expected)
        for app, sid in stores.items():
            self.e.check(f"{label} restart {app} identity", self.open_store(writer, gid, app).get("id") == sid)
            self.await_value(writer, sid, owner_key, f"{label}-owner-{app}")
            self.await_value(writer, sid, member_key, f"{label}-member-{app}")
            self.await_absent(writer, sid, removed_key)

    def run_private(self, owner: str, writer: str, late: str, revoked: str,
                    stop_owner: Callable[[], None], restart_writer: Callable[[str, set[str]], None]) -> None:
        created = self.ok(owner, "POST", "/groups", {
            "name": f"private-kv-e2e-{uuid.uuid4().hex[:10]}", "preset": "private_secure"})
        gid = created.get("group_id") or (created.get("group") or {}).get("id")
        self.e.check("private_secure group id returned", isinstance(gid, str) and bool(gid))
        self.join_private(owner, writer, gid)
        self.join_private(owner, revoked, gid)
        late_invite = self.invite(owner, late, gid)
        self.exercise("private_secure", owner, writer, late, revoked, gid, late_invite,
                      lambda: self.join_private(writer, late, gid, late_invite), stop_owner, restart_writer)

    def run_home(self, owner: str, writer: str, late: str, revoked: str,
                 stop_owner: Callable[[], None], restart_writer: Callable[[str, set[str]], None]) -> None:
        gid, owner_id = self.home(owner)
        for node in (writer, late, revoked):
            self.require_home_identity(node, owner_id)
        writer_invite = self.home_invite(owner, writer, gid, owner_id)
        revoked_invite = self.home_invite(owner, revoked, gid, owner_id)
        late_invite = self.home_invite(owner, late, gid, owner_id)
        self.join_home(owner, writer, gid, owner_id, writer_invite)
        self.join_home(owner, revoked, gid, owner_id, revoked_invite)
        self.exercise("home", owner, writer, late, revoked, gid, late_invite,
                      lambda: self.join_home(writer, late, gid, owner_id, late_invite), stop_owner, restart_writer)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", choices=["test"], required=True)
    parser.add_argument("--tokens-file", required=True)
    parser.add_argument("--scenario", action="append", choices=["private_secure", "home"], required=True)
    parser.add_argument("--nodes", nargs=5, default=NODES_DEFAULT[:5],
                        metavar=("OWNER", "WRITER", "LATE", "OUTSIDER", "REVOKED"))
    parser.add_argument("--local-port-base", type=int, default=23700)
    parser.add_argument("--poll-timeout", type=float, default=120)
    parser.add_argument("--allow-service-restart", action="store_true")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    if not args.allow_service_restart:
        parser.error("private/Home acceptance requires --allow-service-restart")
    if len(set(args.scenario)) != len(args.scenario):
        parser.error("each --scenario may be selected only once")
    if len(set(args.nodes)) != 5:
        parser.error("--nodes must contain five distinct node labels")
    tokens = load_tokens(args.tokens_file, var_prefix="TEST")
    missing = [node for node in args.nodes if node not in tokens]
    if missing:
        parser.error(f"missing testnet token/IP entries: {missing}")
    endpoints = {node: tokens[node][0] for node in args.nodes}
    if len(set(endpoints.values())) != 5:
        parser.error("--nodes must resolve to five distinct endpoints")

    tunnels: dict[str, TunnelHandle] = {}
    clients: dict[str, Api] = {}
    evidence = Evidence()
    custody = ServiceCustody(endpoints)
    succeeded = False

    def await_health(node: str) -> None:
        client = clients.get(node)
        if client is None:
            raise RuntimeError(f"no owned API client available to verify {node} health")
        poll(f"{node} health", 60, lambda: client.request("GET", "/health"),
             lambda result: result[0] == 200 and result[1].get("ok") is True)

    try:
        for index, node in enumerate(args.nodes):
            ip, token = tokens[node]
            tunnel = start_ssh_tunnel(ip, args.local_port_base + index, remote_port=13600)
            tunnels[node] = tunnel
            clients[node] = Api(f"http://127.0.0.1:{tunnel.local_port}", token)
        owner, writer, late, _outsider, revoked = args.nodes
        identities = {node: clients[node].agent_id() for node in args.nodes}
        if len(set(identities.values())) != 5:
            raise RuntimeError("scenario requires five distinct daemon agent identities")

        scenario = Scenario(clients, evidence, args.poll_timeout)
        for selected in args.scenario:
            stopped: set[str] = set()

            def stop_owner() -> None:
                custody.stop(owner)
                stopped.add(owner)

            def restart_writer(gid: str, expected: set[str]) -> None:
                status, roster = clients[writer].request("GET", f"/groups/{enc(gid)}/members")
                active = active_provider_ids(status, roster)
                evidence.check(f"{selected} exact retained providers established", active == expected,
                               active_count=len(active), expected_count=len(expected))
                custody.stop(late)
                stopped.add(late)
                custody.restart(writer)
                await_health(writer)

            if selected == "private_secure":
                scenario.run_private(owner, writer, late, revoked, stop_owner, restart_writer)
            else:
                scenario.run_home(owner, writer, late, revoked, stop_owner, restart_writer)
            # Scenarios are isolated and explicit. Restore their stopped nodes
            # before starting the next scenario on the same five identities.
            for node in sorted(stopped):
                if node in custody.restore_required:
                    if not __import__("e2e_vps_kv").service(endpoints[node], "is-active"):
                        __import__("e2e_vps_kv").service(endpoints[node], "start")
                    await_health(node)
                    custody.restore_required.remove(node)
        succeeded = True
    except Exception as error:
        evidence.assertions.append({"label": "harness", "passed": False, "error": str(error)})
    finally:
        for error in custody.restore(await_health):
            evidence.assertions.append({"label": error, "passed": False})
            succeeded = False
        for tunnel in list(tunnels.values()):
            try:
                stop_ssh_tunnel(tunnel)
            except Exception as error:
                evidence.assertions.append({"label": f"cleanup: {type(error).__name__}", "passed": False})
                succeeded = False
        try:
            with open(args.report, "w", encoding="utf-8") as output:
                json.dump({"scenario": args.scenario, "assertions": evidence.assertions}, output, indent=2)
        except Exception:
            succeeded = False
    return 0 if succeeded and all(item["passed"] for item in evidence.assertions) else 1


if __name__ == "__main__":
    raise SystemExit(main())
