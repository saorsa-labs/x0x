#!/usr/bin/env python3
"""Strict testnet acceptance for private TreeKEM and canonical Home Wiki/Web stores.

The harness reuses the ordinary #565 tunnel, API, polling, evidence, and service
custody primitives. It never addresses a production unit. Both scenarios are
selected explicitly with ``--scenario``; missing Home ownership/seating support
is a failed prerequisite, never a skip or a substitute group.
"""
from __future__ import annotations

import argparse
import datetime
import json
import time
import uuid
from typing import Any, Callable

from e2e_tunnel import TunnelHandle, start_ssh_tunnel, stop_ssh_tunnel
from e2e_vps_groups import NODES_DEFAULT, load_tokens
from e2e_vps_kv import Api, Evidence, Scenario as SharedScenario, ServiceCustody, active_provider_ids, enc, poll, safe_identifier


# #824: the documented transient `GET /home` state while startup provisioning
# waits (at most 90 s) for owner sync. Readers poll through it, and only it.
HOME_PROVISIONING_PENDING = "provisioning_pending"


def settled_home(client: Api, label: str, timeout: float) -> tuple[int, dict[str, Any]]:
    """`GET /home` once provisioning has left the transient pending state."""
    return poll(f"{label} Home provisioning settles", timeout,
                lambda: client.request("GET", "/home"),
                lambda result: not (result[0] == 200
                                    and result[1].get("state") == HOME_PROVISIONING_PENDING))


def machine_id(client: Api) -> str:
    status, body = client.request("GET", "/agent")
    value = body.get("machine_id")
    if status != 200 or not isinstance(value, str) or len(value) != 64:
        raise RuntimeError("/agent did not return a 64-hex machine_id")
    return value


class Scenario(SharedScenario):
    def join_private(self, owner: str, member: str, gid: str, invite: str | None = None) -> None:
        invite = invite or self.invite(owner, member, gid)
        self._join_with_local_readiness(
            owner, member, gid, {"invite": invite},
            accepted_label=f"{member} joined expected group",
            readiness_label=f"{member} private join reaches owner and local readiness",
            operation="private_join_readiness")

    def home(self, owner: str) -> tuple[str, str]:
        status, body = settled_home(self.c[owner], owner, self.timeout)
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
        # Product contract: only a device serving the canonical Home may seat
        # (`POST /home/seat` refuses otherwise). A device that has just been
        # seated reaches `local` with the canonical gid only once its own join
        # completes, so waiting for exactly that is readiness, not masking. A
        # device stuck on a duplicate never matches and the poll fails.
        poll(f"{owner} serves the canonical Home before seating {member}", self.timeout,
             lambda: self.c[owner].request("GET", "/home"),
             lambda result: result[0] == 200 and result[1].get("state") == "local"
             and result[1].get("group_id") == gid)
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
        self._join_with_local_readiness(
            owner, member, gid,
            {"invite": invite, "mode": "home", "expected_owner_user_id": owner_id},
            accepted_label=f"{member} canonical Home join request accepted",
            readiness_label=f"{member} Home seat reaches owner and local readiness",
            operation="home_join_readiness")

    def _join_with_local_readiness(self, owner: str, member: str, gid: str,
                                   join_body: dict[str, Any], accepted_label: str,
                                   readiness_label: str, operation: str) -> None:
        status, body = self.c[member].request("POST", "/groups/join", join_body)
        body = body if isinstance(body, dict) else {}
        join_state = body.get("join_state")
        if join_state not in ("active", "pending_authority_commit", "idle", "timed_out"):
            join_state = "other" if join_state is not None else None
        self.e.check(accepted_label, status in (200, 201)
                     and body.get("ok") is not False and body.get("group_id", gid) == gid,
                     status=status, join_state=join_state)
        aid = self.c[member].agent_id()
        started = time.monotonic()
        deadline = started + self.timeout
        owner_samples = local_samples = 0
        owner_last: Any = None
        local_last: Any = None
        owner_body: dict[str, Any] = {}
        local_body: dict[str, Any] = {}
        owner_ready = False
        local_ready = False
        first_sample_utc = last_sample_utc = None
        last_error: str | None = None
        deadline_reached = False

        def safe_request(client: Any, method: str, path: str) -> tuple[Any, str | None]:
            try:
                return client.request(method, path), None
            except Exception as error:
                return None, type(error).__name__

        def state_label(response_body: dict[str, Any]) -> str | None:
            value = response_body.get("membership_state")
            allowed = {"active", "pending_authority_commit", "pending", "idle", "not_member"}
            return value if isinstance(value, str) and value in allowed else (
                "other" if value is not None else None)

        while time.monotonic() < deadline:
            sampled = datetime.datetime.now(datetime.timezone.utc).isoformat()
            first_sample_utc = first_sample_utc or sampled
            last_sample_utc = sampled
            owner_samples += 1
            owner_last, request_error = safe_request(
                self.c[owner], "GET", f"/groups/{enc(gid)}/members")
            last_error = request_error or last_error
            owner_body = (owner_last[1] if isinstance(owner_last, tuple) and len(owner_last) > 1
                          and isinstance(owner_last[1], dict) else {})
            members = owner_body.get("members")
            rows = members if isinstance(members, list) else None
            owner_ready = (isinstance(owner_last, tuple) and owner_last[0] == 200
                           and rows is not None
                           and any(isinstance(row, dict) and row.get("agent_id") == aid for row in rows))
            if time.monotonic() >= deadline:
                deadline_reached = True
                break
            local_samples += 1
            local_last, request_error = safe_request(
                self.c[member], "GET", f"/groups/{enc(gid)}")
            last_error = request_error or last_error
            local_body = (local_last[1] if isinstance(local_last, tuple) and len(local_last) > 1
                          and isinstance(local_last[1], dict) else {})
            local_ready = (isinstance(local_last, tuple) and local_last[0] == 200
                           and local_body.get("group_id") == gid
                           and state_label(local_body) == "active")
            if time.monotonic() >= deadline:
                deadline_reached = True
                break
            if owner_ready and local_ready:
                elapsed = round(time.monotonic() - started, 3)
                self.e.record_poll(
                    {"label": readiness_label, "elapsed_seconds": elapsed,
                     "first_sample_utc": first_sample_utc, "last_sample_utc": last_sample_utc,
                     "probe_count": owner_samples, "last_status": owner_last[0] if isinstance(owner_last, tuple) else None,
                     "local_last_status": local_last[0] if isinstance(local_last, tuple) else None,
                     "last_http_status": owner_last[0] if isinstance(owner_last, tuple) else None,
                     "local_membership_state": "active", "outcome": "accepted",
                     "local_observed_group_id": safe_identifier(local_body.get("group_id")),
                     "observed_member_count": len(rows) if rows is not None else None,
                     "expected_member_present": True, "last_error_class": last_error},
                    operation=operation, node=member, owner=owner,
                    group_id=safe_identifier(gid), deadline_seconds=self.timeout,
                    observed_member_count=len(rows) if rows is not None else None,
                    expected_member_present=True, local_probe_count=local_samples)
                return
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(1.0, remaining))

        diagnostic_started = time.monotonic()
        deadline_reached = time.monotonic() >= deadline
        join_status, terminal_error = safe_request(
            self.c[member], "GET", f"/groups/{enc(gid)}/join-status")
        terminal_body = (join_status[1] if isinstance(join_status, tuple) and len(join_status) > 1
                         and isinstance(join_status[1], dict) else {})
        terminal = terminal_body.get("last_join_outcome")
        terminal_value = terminal.get("outcome") if isinstance(terminal, dict) else None
        terminal_outcome = (terminal_value if isinstance(terminal_value, str)
                            and terminal_value in {"refused", "timed_out"} else
                            ("other" if terminal_value is not None else None))
        elapsed = round(diagnostic_started - started, 3)
        self.e.record_poll(
            {"label": readiness_label, "elapsed_seconds": elapsed,
             "first_sample_utc": first_sample_utc, "last_sample_utc": last_sample_utc,
             "probe_count": owner_samples, "last_status": owner_last[0] if isinstance(owner_last, tuple) else None,
             "local_last_status": local_last[0] if isinstance(local_last, tuple) else None,
             "last_http_status": owner_last[0] if isinstance(owner_last, tuple) else None,
             "local_membership_state": state_label(local_body),
             "local_observed_group_id": safe_identifier(local_body.get("group_id")),
             "terminal_join_status": join_status[0] if isinstance(join_status, tuple) else None,
             "terminal_join_outcome": terminal_outcome,
             "terminal_join_status_error_class": terminal_error,
             "deadline_reached_before_acceptance": deadline_reached,
             "diagnostic_elapsed_seconds": round(time.monotonic() - diagnostic_started, 3),
             "last_error_class": last_error, "outcome": "timeout"},
            operation=operation, node=member, owner=owner,
            group_id=safe_identifier(gid), deadline_seconds=self.timeout,
            observed_member_count=(len(owner_body.get("members"))
                                   if isinstance(owner_last, tuple) and owner_last[0] == 200
                                   and isinstance(owner_body.get("members"), list) else None),
            expected_member_present=(owner_ready if isinstance(owner_last, tuple)
                                     and owner_last[0] == 200
                                     and isinstance(owner_body.get("members"), list) else None),
            local_probe_count=local_samples)
        raise AssertionError(f"{readiness_label} did not converge in {self.timeout:g}s")

    def exercise(self, label: str, owner: str, writer: str, late: str, admin: str, revoked: str,
                 gid: str, admit_admin: Callable[[], None], mint_late: Callable[[], str],
                 join_late: Callable[[str], None], stop_owner: Callable[[], None],
                 stop_admin: Callable[[], None], is_offline: Callable[[str], bool],
                 restart_writer: Callable[[str, set[str]], None],
                 before_admission: Callable[[], None] | None = None,
                 admission_offline_label: str | None = None,
                 history_offline_label: str | None = None) -> None:
        stores: dict[str, str] = {}
        actor_ids = {node: self.c[node].agent_id() for node in (owner, writer, late, admin)}
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

        # Only the invite's online inviter can author the signed MemberAdded, so
        # the late invite comes from a separately admitted, promoted Admin and is
        # minted after the removal. The writer stays a plain Member: it witnesses
        # the Admin's commit while the owner is offline, then the Admin is stopped
        # too so retained encrypted/tombstone history can only come from the writer.
        admit_admin()
        self.promote_admin(owner, admin, gid)
        # The plain-Member writer must observe the Admin role before the late
        # invite exists, so its roster witness cannot race permission propagation.
        self.await_admin(writer, admin, gid)
        if before_admission is not None:
            before_admission()
        late_invite = mint_late()
        self.e.check(f"{label} late invite retained", late_invite.startswith("x0x://invite/"))
        stop_owner()
        if admission_offline_label is not None:
            self.e.check(admission_offline_label, is_offline(owner))
        join_late(late_invite)
        stop_admin()
        self.e.check(history_offline_label or f"{label} owner and admin stopped before late history",
                     is_offline(owner) and is_offline(admin))
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

    def run_private(self, owner: str, writer: str, late: str, admin: str, revoked: str,
                    stop_owner: Callable[[], None], stop_admin: Callable[[], None],
                    is_offline: Callable[[str], bool],
                    restart_writer: Callable[[str, set[str]], None]) -> None:
        created = self.ok(owner, "POST", "/groups", {
            "name": f"private-kv-e2e-{uuid.uuid4().hex[:10]}", "preset": "private_secure"})
        gid = created.get("group_id") or (created.get("group") or {}).get("id")
        self.e.check("private_secure group id returned", isinstance(gid, str) and bool(gid))
        self.join_private(owner, writer, gid)
        self.join_private(owner, revoked, gid)
        self.exercise("private_secure", owner, writer, late, admin, revoked, gid,
                      lambda: self.join_private(owner, admin, gid),
                      lambda: self.invite(admin, late, gid),
                      lambda invite: self.join_private(writer, late, gid, invite),
                      stop_owner, stop_admin, is_offline, restart_writer)

    def run_home(self, owner: str, writer: str, late: str, admin: str, revoked: str,
                 stop_owner: Callable[[], None], stop_admin: Callable[[], None],
                 is_offline: Callable[[str], bool],
                 restart_writer: Callable[[str, set[str]], None]) -> None:
        gid, owner_id = self.home(owner)
        for node in (writer, late, revoked, admin):
            self.require_home_identity(node, owner_id)
        writer_invite = self.home_invite(owner, writer, gid, owner_id)
        revoked_invite = self.home_invite(owner, revoked, gid, owner_id)
        self.join_home(owner, writer, gid, owner_id, writer_invite)
        self.join_home(owner, revoked, gid, owner_id, revoked_invite)

        # Every Home device holds the owner key (Home admission needs each
        # device's own user-identity announcement), so the writer's witness
        # status rests on its role: a Member cannot mint, only the Admin can.
        def writer_is_member() -> None:
            writer_id = self.c[writer].agent_id()
            status, body = self.c[owner].request("GET", f"/groups/{enc(gid)}/members")
            role = next((row.get("role") for row in body.get("members", [])
                         if isinstance(row, dict) and row.get("agent_id") == writer_id), None)
            self.e.check("home writer remains Member role", status == 200 and role == "member",
                         status=status, role=role)

        self.exercise("home", owner, writer, late, admin, revoked, gid,
                      lambda: self.join_home(owner, admin, gid, owner_id,
                                             self.home_invite(owner, admin, gid, owner_id)),
                      lambda: self.home_invite(admin, late, gid, owner_id),
                      lambda invite: self.join_home(writer, late, gid, owner_id, invite),
                      stop_owner, stop_admin, is_offline, restart_writer,
                      before_admission=writer_is_member,
                      admission_offline_label="original owner device offline during admission",
                      history_offline_label=("owner and admin devices offline during history; "
                                             "history served by same-owner Member-role device"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", choices=["test"], required=True)
    parser.add_argument("--tokens-file", required=True)
    parser.add_argument("--scenario", action="append", choices=["private_secure", "home"], required=True)
    parser.add_argument("--nodes", nargs=5, default=NODES_DEFAULT[:5],
                        metavar=("OWNER", "WRITER", "LATE", "ADMIN", "REVOKED"))
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
        owner, writer, late, admin, revoked = args.nodes
        identities = {node: clients[node].agent_id() for node in args.nodes}
        if len(set(identities.values())) != 5:
            raise RuntimeError("scenario requires five distinct daemon agent identities")

        scenario = Scenario(clients, evidence, args.poll_timeout)
        for selected in args.scenario:
            stopped: set[str] = set()

            def stop_owner() -> None:
                custody.stop(owner)
                stopped.add(owner)

            def stop_admin() -> None:
                custody.stop(admin)
                stopped.add(admin)

            def is_offline(node: str) -> bool:
                return not __import__("e2e_vps_kv").service(endpoints[node], "is-active")

            def restart_writer(gid: str, expected: set[str]) -> None:
                status, roster = clients[writer].request("GET", f"/groups/{enc(gid)}/members")
                active = active_provider_ids(status, roster)
                evidence.check(f"{selected} exact retained providers established", active == expected,
                               active_count=len(active), expected_count=len(expected))
                evidence.check(f"{selected} owner and admin stopped before writer restart",
                               is_offline(owner) and is_offline(admin))
                custody.stop(late)
                stopped.add(late)
                custody.restart(writer)
                await_health(writer)

            if selected == "private_secure":
                scenario.run_private(owner, writer, late, admin, revoked, stop_owner, stop_admin,
                                     is_offline, restart_writer)
            else:
                scenario.run_home(owner, writer, late, admin, revoked, stop_owner, stop_admin,
                                  is_offline, restart_writer)
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
                json.dump({"scenario": args.scenario, "stores": evidence.stores, "polls": evidence.polls,
                           "assertions": evidence.assertions}, output, indent=2)
        except Exception:
            succeeded = False
    return 0 if succeeded and all(item["passed"] for item in evidence.assertions) else 1


if __name__ == "__main__":
    raise SystemExit(main())
