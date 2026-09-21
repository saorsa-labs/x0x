#!/usr/bin/env python3
"""Strict testnet acceptance for ordinary shared Wiki/Web stores (#565).

This is separate from legacy-import and GUI acceptance. It opens one owned SSH
tunnel per selected testnet daemon. Service stops/restarts are refused unless
``--allow-service-restart`` is supplied; only ``x0xd-testnet.service`` is ever
addressed and every previously-active service is restored in ``finally``.
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from e2e_tunnel import TunnelHandle, start_ssh_tunnel, stop_ssh_tunnel
from e2e_vps_groups import NODES_DEFAULT, load_tokens

SERVICE = "x0xd-testnet.service"


class Api:
    def __init__(self, base: str, token: str) -> None:
        self.base, self.token = base.rstrip("/"), token

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            try:
                payload = json.loads(error.read() or b"{}")
            except json.JSONDecodeError:
                payload = {"error": error.reason}
            return error.code, payload

    def agent_id(self) -> str:
        status, body = self.request("GET", "/agent")
        value = body.get("agent_id")
        if status != 200 or not isinstance(value, str) or len(value) != 64:
            raise RuntimeError("/agent did not return a 64-hex agent_id")
        return value


def enc(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def active_provider_ids(status: int, roster: dict[str, Any]) -> set[str]:
    if status != 200:
        return set()
    return {row["agent_id"] for row in roster.get("members", [])
            if isinstance(row, dict) and isinstance(row.get("agent_id"), str)}


def poll(label: str, timeout: float, probe: Callable[[], Any], accept: Callable[[Any], bool]) -> Any:
    deadline, last, last_error = time.monotonic() + timeout, None, None
    while time.monotonic() < deadline:
        try:
            last = probe()
            if accept(last):
                return last
        except Exception as error:
            last_error = type(error).__name__
        time.sleep(1)
    status = last[0] if isinstance(last, tuple) and last and isinstance(last[0], int) else None
    raise AssertionError(f"{label} did not converge in {timeout:g}s; last_status={status}; last_error={last_error}")


@dataclass
class Evidence:
    assertions: list[dict[str, Any]] = field(default_factory=list)

    def check(self, label: str, condition: bool, **facts: Any) -> None:
        self.assertions.append({"label": label, "passed": bool(condition), **facts})
        if not condition:
            raise AssertionError(f"{label}: {facts}")


class Scenario:
    def __init__(self, clients: dict[str, Api], evidence: Evidence, timeout: float = 120) -> None:
        self.c, self.e, self.timeout = clients, evidence, timeout

    def ok(self, node: str, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        status, payload = self.c[node].request(method, path, body)
        self.e.check(f"{node} {method} {path}", status in (200, 201) and payload.get("ok") is not False,
                     status=status)
        return payload

    def invite(self, owner: str, member: str, gid: str) -> str:
        invite = self.ok(owner, "POST", f"/groups/{enc(gid)}/invite", {}).get("invite_link")
        self.e.check(f"invite for {member}", isinstance(invite, str) and invite.startswith("x0x://invite/"))
        return invite

    def join(self, owner: str, member: str, gid: str, invite: str | None = None) -> None:
        invite = invite or self.invite(owner, member, gid)
        joined = self.ok(member, "POST", "/groups/join", {"invite": invite})
        self.e.check(f"{member} joined expected group", joined.get("group_id", gid) == gid)
        aid = self.c[member].agent_id()
        poll(f"{member} roster on owner", self.timeout,
             lambda: self.c[owner].request("GET", f"/groups/{enc(gid)}/members"),
             lambda result: result[0] == 200 and any(row.get("agent_id") == aid for row in result[1].get("members", [])))

    def open_store(self, node: str, gid: str, app: str) -> dict[str, Any]:
        return self.ok(node, "POST", f"/groups/{enc(gid)}/stores", {"name": app})

    def put(self, node: str, sid: str, key: str, value: str) -> tuple[int, dict[str, Any]]:
        return self.c[node].request("PUT", f"/stores/{enc(sid)}/{enc(key)}", {
            "value": base64.b64encode(value.encode()).decode(), "content_type": "text/plain"})

    def read_value(self, node: str, sid: str, key: str) -> tuple[int, str | None]:
        status, body = self.c[node].request("GET", f"/stores/{enc(sid)}/{enc(key)}")
        raw = body.get("value")
        return status, base64.b64decode(raw).decode() if status == 200 and isinstance(raw, str) else None

    def await_value(self, node: str, sid: str, key: str, value: str) -> None:
        result = poll(f"{node} receives {key}", self.timeout,
                      lambda: self.read_value(node, sid, key), lambda got: got == (200, value))
        self.e.check(f"{node} converged {key}", result == (200, value), value_sha256=__import__("hashlib").sha256(value.encode()).hexdigest())

    def await_absent(self, node: str, sid: str, key: str) -> None:
        result = poll(f"{node} observes removal {key}", self.timeout,
                      lambda: self.read_value(node, sid, key), lambda got: got[0] == 404)
        self.e.check(f"{node} converged removal {key}", result[0] == 404)

    def prove_denied_did_not_converge(self, observer: str, writer: str, sid: str, forbidden: str) -> None:
        barrier = f"barrier-{uuid.uuid4().hex}"
        self.e.check("valid barrier write accepted", self.put(writer, sid, barrier, "barrier")[0] == 200)
        self.await_value(observer, sid, barrier, "barrier")
        self.await_absent(observer, sid, forbidden)

    def run(self, owner: str, writer: str, late: str, outsider: str, revoked: str,
            stop_owner: Callable[[], None], restart_writer: Callable[[str], None]) -> None:
        created = self.ok(owner, "POST", "/groups", {"name": f"kv-e2e-{uuid.uuid4().hex[:10]}", "preset": "public_open"})
        gid = created.get("group_id") or (created.get("group") or {}).get("id")
        self.e.check("group id returned", isinstance(gid, str) and bool(gid))
        self.join(owner, writer, gid); self.join(owner, revoked, gid)
        late_invite = self.invite(owner, late, gid)
        stores: dict[str, str] = {}
        for app in ("wiki", "web"):
            a, b = self.open_store(owner, gid, app), self.open_store(writer, gid, app)
            self.e.check(f"deterministic {app} store", a.get("id") == b.get("id") and a.get("store_id") == b.get("store_id"))
            stores[app] = a["id"]
        self.open_store(revoked, gid, "wiki")

        announce = self.ok(owner, "POST", "/groups", {"name": f"kv-nonwriter-{uuid.uuid4().hex[:10]}", "preset": "public_announce"})
        announce_gid = announce.get("group_id") or (announce.get("group") or {}).get("id")
        self.e.check("announcement group id returned", isinstance(announce_gid, str) and bool(announce_gid))
        self.join(owner, writer, announce_gid)
        announce_store = self.open_store(writer, announce_gid, "wiki")["id"]
        nonwriter = self.put(writer, announce_store, "forbidden-member-write", "bad")
        self.e.check("active nonwriter mutation refused", nonwriter[0] == 403, status=nonwriter[0])
        for app, sid in stores.items():
            self.e.check(f"owner writes {app}", self.put(owner, sid, "owner-page", f"owner-{app}")[0] == 200)
            self.e.check(f"writer writes {app}", self.put(writer, sid, "writer-page", f"writer-{app}")[0] == 200)
            self.await_value(owner, sid, "writer-page", f"writer-{app}")
            self.e.check(f"seed removal {app}", self.put(owner, sid, "removed-page", "gone")[0] == 200)
            self.await_value(writer, sid, "removed-page", "gone")
            self.e.check(f"remove {app}", self.c[owner].request("DELETE", f"/stores/{enc(sid)}/removed-page")[0] == 200)
            self.await_absent(writer, sid, "removed-page")
        outsider_open = self.c[outsider].request("POST", f"/groups/{enc(gid)}/stores", {"name": "wiki"})
        self.e.check("outsider group-store open refused", outsider_open[0] in (403, 404), status=outsider_open[0])
        outsider_denied = self.put(outsider, stores["wiki"], "outsider-forbidden", "bad")
        self.e.check("outsider mutation refused", outsider_denied[0] in (403, 404), status=outsider_denied[0])
        self.prove_denied_did_not_converge(owner, writer, stores["wiki"], "outsider-forbidden")
        revoke_aid = self.c[revoked].agent_id()
        self.e.check("owner removes member", self.c[owner].request("DELETE", f"/groups/{enc(gid)}/members/{revoke_aid}")[0] == 200)
        poll("revocation reaches former member", self.timeout,
             lambda: self.c[revoked].request("POST", f"/groups/{enc(gid)}/stores", {"name": "wiki"}),
             lambda result: result[0] in (403, 404, 409))
        before = self.read_value(owner, stores["wiki"], "forbidden")
        denied = self.put(revoked, stores["wiki"], "forbidden", "bad")
        self.e.check("revoked mutation refused", denied[0] in (403, 404), status=denied[0])
        self.e.check("revoked key absent before barrier", before[0] == 404)
        self.prove_denied_did_not_converge(owner, writer, stores["wiki"], "forbidden")
        stop_owner()
        self.join(writer, late, gid, late_invite)
        for app, sid in stores.items():
            reopened = self.open_store(late, gid, app)
            self.e.check(f"late deterministic {app} identity", reopened.get("id") == sid)
            self.await_value(late, sid, "owner-page", f"owner-{app}")
            self.await_value(late, sid, "writer-page", f"writer-{app}")
            self.await_absent(late, sid, "removed-page")
        restart_writer(gid)
        for app, sid in stores.items():
            self.e.check(f"writer restart identity {app}", self.open_store(writer, gid, app).get("id") == sid)
            self.await_value(writer, sid, "owner-page", f"owner-{app}")
            self.await_value(writer, sid, "writer-page", f"writer-{app}")
            self.await_absent(writer, sid, "removed-page")


def service(ip: str, verb: str) -> bool:
    if verb not in {"start", "stop", "restart", "is-active"}:
        raise ValueError("unsupported service verb")
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                             f"root@{ip}", "systemctl", verb, SERVICE], check=False, timeout=20)
    if verb == "is-active":
        if result.returncode == 0:
            return True
        if result.returncode == 3:
            return False
        raise RuntimeError(f"systemctl is-active {SERVICE} failed with rc={result.returncode}")
    if result.returncode != 0:
        raise RuntimeError(f"systemctl {verb} {SERVICE} failed")
    return True


class ServiceCustody:
    def __init__(self, endpoints: dict[str, str]) -> None:
        self.endpoints = endpoints
        self.restore_required: set[str] = set()

    def require_active(self, node: str) -> None:
        if not service(self.endpoints[node], "is-active"):
            raise RuntimeError(f"scenario prerequisite failed: {SERVICE} was not active on {node}")

    def stop(self, node: str) -> None:
        self.require_active(node)
        self.restore_required.add(node)  # before mutation: transport may fail after remote stop
        service(self.endpoints[node], "stop")
        if service(self.endpoints[node], "is-active"):
            raise RuntimeError(f"{SERVICE} remained active on {node} after stop")

    def restart(self, node: str) -> None:
        self.require_active(node)
        self.restore_required.add(node)  # before mutation: restart may stop then lose transport
        service(self.endpoints[node], "restart")

    def restore(self, health: Callable[[str], None]) -> list[str]:
        errors = []
        for node in sorted(self.restore_required):
            try:
                if not service(self.endpoints[node], "is-active"):
                    service(self.endpoints[node], "start")
                health(node)
            except Exception as error:
                errors.append(f"restore {node}: {type(error).__name__}")
        return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", choices=["test"], required=True)
    parser.add_argument("--tokens-file", required=True)
    parser.add_argument("--nodes", nargs=5, default=NODES_DEFAULT[:5], metavar=("OWNER", "WRITER", "LATE", "OUTSIDER", "REVOKED"))
    parser.add_argument("--local-port-base", type=int, default=23600)
    parser.add_argument("--poll-timeout", type=float, default=120)
    parser.add_argument("--allow-service-restart", action="store_true")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    if not args.allow_service_restart:
        parser.error("this scenario requires --allow-service-restart for owner-offline and persistence assertions")
    tokens = load_tokens(args.tokens_file, var_prefix="TEST")
    if len(set(args.nodes)) != 5:
        parser.error("--nodes must contain five distinct node labels")
    missing = [node for node in args.nodes if node not in tokens]
    if missing: parser.error(f"missing testnet token/IP entries: {missing}")
    endpoints = {node: tokens[node][0] for node in args.nodes}
    if len(set(endpoints.values())) != 5:
        parser.error("--nodes must resolve to five distinct endpoints")
    tunnels: dict[str, TunnelHandle] = {}; clients: dict[str, Api] = {}
    evidence = Evidence(); succeeded = False
    custody = ServiceCustody(endpoints)
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
            tunnels[node] = tunnel; clients[node] = Api(f"http://127.0.0.1:{tunnel.local_port}", token)
        owner, writer, late, outsider, revoked = args.nodes
        actor_ids = {node: clients[node].agent_id() for node in args.nodes}
        if len(set(actor_ids.values())) != 5:
            raise RuntimeError("scenario requires five distinct daemon agent identities")
        def stop_owner() -> None:
            custody.stop(owner)
        def restart_writer(gid: str) -> None:
            status, roster = clients[writer].request("GET", f"/groups/{enc(gid)}/members")
            active = active_provider_ids(status, roster)
            expected = {actor_ids[owner], actor_ids[writer], actor_ids[late]}
            evidence.check("eligible retained providers established", active == expected,
                           active_count=len(active), expected_count=len(expected))
            custody.stop(late)
            custody.restart(writer)
            await_health(writer)
        Scenario(clients, evidence, args.poll_timeout).run(owner, writer, late, outsider, revoked, stop_owner, restart_writer)
        succeeded = True
    except Exception as error:
        evidence.assertions.append({"label": "harness", "passed": False, "error": str(error)})
    finally:
        for error in custody.restore(await_health):
            succeeded = False; evidence.assertions.append({"label": error, "passed": False})
        for node, tunnel in list(tunnels.items()):
            try: stop_ssh_tunnel(tunnel)
            except Exception as error:
                succeeded = False
                evidence.assertions.append({"label": f"cleanup {node}: {type(error).__name__}", "passed": False})
        try:
            with open(args.report, "w", encoding="utf-8") as output:
                json.dump({"scenario": "ordinary-shared-wiki-web", "assertions": evidence.assertions}, output, indent=2)
        except Exception:
            succeeded = False
    return 0 if succeeded and all(item["passed"] for item in evidence.assertions) else 1


if __name__ == "__main__":
    raise SystemExit(main())
