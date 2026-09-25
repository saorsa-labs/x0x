#!/usr/bin/env python3
"""Testnet-only GSS invite and encrypted Wiki KV acceptance for #794.

This intentionally uses the public-request-secure preset: the server source
maps that MLS-encrypted discoverable policy to the GSS plane.  It does not
address production units and requires the explicit restart flag.
"""
from __future__ import annotations

import argparse
import base64
import json
import time
import uuid
from typing import Any

from e2e_tunnel import TunnelHandle, start_ssh_tunnel, stop_ssh_tunnel
from e2e_vps_groups import NODES_DEFAULT, load_tokens
from e2e_vps_kv import Api, Evidence, ServiceCustody, enc, read_response_class, safe_identifier, value_hash, poll
from e2e_vps_private_kv import Scenario as PrivateScenario

SERVICE = "x0xd-testnet.service"


class Scenario(PrivateScenario):
    """Small GSS-only scenario reusing the strict local-readiness primitive."""

    def create_gss_group(self, owner: str) -> str:
        payload = self.c[owner].request("POST", "/groups", {
            "name": f"gss-invite-kv-{uuid.uuid4().hex[:10]}",
            "policy": {
                "discoverability": "public_directory",
                "admission": "request_access",
                "confidentiality": "mls_encrypted",
                "read_access": "members_only",
                "write_access": "members_only",
            },
        })
        status, body = payload
        gid = body.get("group_id") or (body.get("group") or {}).get("id")
        self.e.check("GSS group created", status in (200, 201) and isinstance(gid, str) and bool(gid), status=status)
        policy = body.get("policy") or {}
        self.e.check("GSS group policy", policy.get("confidentiality") == "mls_encrypted",
                     confidentiality=policy.get("confidentiality"))
        # The create response exposes the effective policy, while the server
        # source selects GSS for non-hidden MlsEncrypted groups; TreeKEM is
        # entered only for hidden MlsEncrypted groups.  Keep this source-bound
        # assertion explicit without inventing an undocumented response field.
        self.e.check("GSS secure-plane policy path", policy.get("discoverability") == "public_directory",
                     secure_plane="gss-by-policy")
        return gid

    def join_gss(self, owner: str, member: str, gid: str) -> None:
        invite_status, invite_body = self.c[owner].request("POST", f"/groups/{enc(gid)}/invite", {})
        invite = invite_body.get("invite_link")
        self.e.check("signed GSS invite issued", invite_status in (200, 201)
                     and isinstance(invite, str) and invite.startswith("x0x://invite/"), status=invite_status)
        # This is the existing single 120-second owner-roster + local-active barrier.
        self._join_with_local_readiness(
            owner, member, gid, {"invite": invite},
            accepted_label=f"{member} GSS invite join accepted",
            readiness_label=f"{member} GSS owner roster and local active",
            operation="gss_invite_local_readiness")

    def open_full_wiki(self, node: str, gid: str, *, wait_for_gss_secret: bool = False) -> str:
        """Open Wiki, optionally waiting only for the joiner's GSS secret.

        MemberAdded/local-active can precede the independent SecureShareDelivered
        message. Only its exact pending 409 is retryable; every other response
        fails immediately. The post-restart call remains single-shot.
        """
        started = time.monotonic()
        deadline = started + self.timeout
        last_status: int | None = None
        last_class: str | None = None
        while True:
            status, body = self.c[node].request("POST", f"/groups/{enc(gid)}/stores", {"name": "wiki"})
            sid = body.get("id")
            last_status, last_class = status, read_response_class(status, body)
            if status in (200, 201) and isinstance(sid, str) and bool(sid):
                if wait_for_gss_secret:
                    self.e.record_poll(
                        {"label": f"{node} GSS secret before Wiki open",
                         "elapsed_seconds": round(time.monotonic() - started, 3),
                         "last_status": last_status, "last_response_class": last_class,
                         "outcome": "accepted"},
                        operation="gss_secret_store_open", node=node,
                        group_id=safe_identifier(gid), app="wiki")
                self.e.record_store(node, gid, "wiki", body)
                self.store_context[sid] = (gid, "wiki")
                return sid
            pending = (status == 409
                       and body.get("error") == "local daemon holds no shared secret for this group yet")
            if not wait_for_gss_secret or not pending:
                self.e.check(f"{node} Wiki store opened", False, status=status,
                             response_class=last_class)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.e.check(f"{node} GSS secret became available before Wiki open", False,
                             status=last_status, response_class=last_class,
                             elapsed_seconds=round(time.monotonic() - started, 3))
            time.sleep(min(1.0, remaining))

    def require_gss_store_identity(self, owner_sid: str, member_sid: str) -> None:
        # A different store identifier is a hard failure; never derive or shorten it locally.
        self.e.check("owner and joiner use returned full Wiki id",
                     isinstance(owner_sid, str) and bool(owner_sid) and owner_sid == member_sid,
                     owner_store_id=safe_identifier(owner_sid), joiner_store_id=safe_identifier(member_sid))

    def put_checked(self, node: str, sid: str, key: str, value: str) -> None:
        status, body = self.put(node, sid, key, value)
        self.e.check(f"{node} writes {key}", status in (200, 201) and body.get("ok") is not False,
                     status=status, response_class=read_response_class(status, body))

    def await_key_not_found(self, node: str, sid: str, key: str) -> None:
        def read() -> tuple[int, dict[str, Any]]:
            return self.c[node].request("GET", f"/stores/{enc(sid)}/{enc(key)}")
        def accepted(result: tuple[int, dict[str, Any]]) -> bool:
            status, body = result
            # 404 store-not-found is never an acceptable deletion receipt.
            return status == 404 and body.get("error") == "key not found"
        result = poll(f"{node} observes exact key_not_found for {key}", self.timeout, read, accepted,
                      lambda facts, last: self.e.record_poll(
                          facts, operation="key_not_found", node=node,
                          store_topic=safe_identifier(sid), key=safe_identifier(key),
                          response_class=read_response_class(last[0], last[1]) if isinstance(last, tuple) else None,
                          observed_value_sha256=value_hash(last[1]) if isinstance(last, tuple) else None))
        self.e.check(f"{node} deletion is exact key_not_found", accepted(result),
                     response_class=read_response_class(result[0], result[1]))

    def run_gss(self, owner: str, member: str, restart_member: Any) -> None:
        gid = self.create_gss_group(owner)
        self.join_gss(owner, member, gid)
        owner_sid = self.open_full_wiki(owner, gid)
        member_sid = self.open_full_wiki(member, gid, wait_for_gss_secret=True)
        self.require_gss_store_identity(owner_sid, member_sid)

        self.put_checked(owner, owner_sid, "owner-page", "owner-gss")
        self.await_value(member, owner_sid, "owner-page", "owner-gss")
        self.put_checked(member, owner_sid, "member-page", "member-gss")
        self.await_value(owner, owner_sid, "member-page", "member-gss")
        status, body = self.c[owner].request("DELETE", f"/stores/{enc(owner_sid)}/{enc('owner-page')}")
        self.e.check("owner deletes Wiki key", status in (200, 204) and body.get("error") not in ("store not found", "key not found"), status=status)
        self.await_key_not_found(member, owner_sid, "owner-page")

        before_agent = self.c[member].agent_id()
        restart_member()
        after_agent = self.c[member].agent_id()
        self.e.check("joiner restart retains identity", after_agent == before_agent)
        status, group = self.c[member].request("GET", f"/groups/{enc(gid)}")
        self.e.check("joiner restart retains active GSS membership", status == 200
                     and group.get("group_id") == gid and group.get("membership_state") == "active", status=status)
        persisted = self.open_full_wiki(member, gid)
        self.e.check("joiner restart retains full Wiki store id", persisted == owner_sid,
                     store_id=safe_identifier(persisted))
        self.await_value(member, owner_sid, "member-page", "member-gss")
        self.await_key_not_found(member, owner_sid, "owner-page")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", choices=["test"], required=True)
    parser.add_argument("--tokens-file", required=True)
    parser.add_argument("--nodes", nargs=2, default=NODES_DEFAULT[:2], metavar=("OWNER", "JOINER"))
    parser.add_argument("--local-port-base", type=int, default=23800)
    parser.add_argument("--poll-timeout", type=float, default=120)
    parser.add_argument("--allow-service-restart", action="store_true")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    if not args.allow_service_restart:
        parser.error("GSS acceptance requires --allow-service-restart")
    if len(set(args.nodes)) != 2:
        parser.error("--nodes must contain two distinct node labels")
    tokens = load_tokens(args.tokens_file, var_prefix="TEST")
    missing = [node for node in args.nodes if node not in tokens]
    if missing:
        parser.error(f"missing testnet token/IP entries: {missing}")
    endpoints = {node: tokens[node][0] for node in args.nodes}
    if len(set(endpoints.values())) != 2:
        parser.error("--nodes must resolve to two distinct endpoints")
    tunnels: dict[str, TunnelHandle] = {}
    clients: dict[str, Api] = {}
    evidence = Evidence()
    custody = ServiceCustody(endpoints)
    succeeded = False

    def await_health(node: str) -> None:
        status, body = clients[node].request("GET", "/health")
        if status != 200 or body.get("ok") is not True:
            raise RuntimeError(f"{SERVICE} health failed on {node}")

    try:
        for index, node in enumerate(args.nodes):
            ip, token = tokens[node]
            tunnels[node] = start_ssh_tunnel(ip, args.local_port_base + index, remote_port=13600)
            clients[node] = Api(f"http://127.0.0.1:{tunnels[node].local_port}", token)
            custody.require_active(node)
        owner, member = args.nodes
        identities = {node: clients[node].agent_id() for node in args.nodes}
        if len(set(identities.values())) != 2:
            raise RuntimeError("GSS scenario requires distinct daemon identities")
        scenario = Scenario(clients, evidence, args.poll_timeout)
        def restart_member() -> None:
            custody.restart(member)
            poll(f"{member} health", 60, lambda: clients[member].request("GET", "/health"),
                 lambda result: result[0] == 200 and result[1].get("ok") is True)

        scenario.run_gss(owner, member, restart_member)
        succeeded = True
    except Exception as error:
        evidence.assertions.append({"label": "harness", "passed": False, "error": type(error).__name__})
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
                json.dump({"scenario": "gss_invite_encrypted_wiki", "stores": evidence.stores,
                           "polls": evidence.polls, "assertions": evidence.assertions}, output, indent=2)
        except Exception:
            succeeded = False
    return 0 if succeeded and all(item["passed"] for item in evidence.assertions) else 1


if __name__ == "__main__":
    raise SystemExit(main())
