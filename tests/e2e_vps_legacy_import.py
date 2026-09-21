#!/usr/bin/env python3
"""Strict testnet E2E for normal-success legacy Wiki/Web imports (#565).

This intentionally does not claim the cfg(test)-only pending-intent failure
window. It reuses the ordinary-store harness's owned tunnels and service custody.
"""
from __future__ import annotations

import argparse
import base64
import json
import time
import uuid
from typing import Any

from e2e_tunnel import start_ssh_tunnel, stop_ssh_tunnel
from e2e_vps_groups import load_tokens
from e2e_vps_kv import Api, Evidence, ServiceCustody, enc, poll


class LegacyScenario:
    def __init__(self, clients: dict[str, Api], evidence: Evidence, timeout: float) -> None:
        self.c, self.e, self.timeout = clients, evidence, timeout

    def call(self, node: str, method: str, path: str, body: dict[str, Any] | None = None,
             accepted: tuple[int, ...] = (200, 201)) -> dict[str, Any]:
        status, payload = self.c[node].request(method, path, body)
        self.e.check(f"{node} {method} {path}", status in accepted, status=status)
        return payload

    def invite_join(self, owner: str, member: str, gid: str) -> None:
        invite = self.call(owner, "POST", f"/groups/{enc(gid)}/invite", {}).get("invite_link")
        self.e.check(f"invite for {member}", isinstance(invite, str) and invite.startswith("x0x://invite/"))
        self.call(member, "POST", "/groups/join", {"invite": invite})
        aid = self.c[member].agent_id()
        poll(f"{member} roster", self.timeout,
             lambda: self.c[owner].request("GET", f"/groups/{enc(gid)}/members"),
             lambda r: r[0] == 200 and any(x.get("agent_id") == aid for x in r[1].get("members", [])))

    def put(self, node: str, sid: str, key: str, value: str) -> int:
        return self.c[node].request("PUT", f"/stores/{enc(sid)}/{enc(key)}", {
            "value": base64.b64encode(value.encode()).decode(), "content_type": "text/plain"})[0]

    def read(self, node: str, sid: str, key: str) -> tuple[int, str | None]:
        status, body = self.c[node].request("GET", f"/stores/{enc(sid)}/{enc(key)}")
        raw = body.get("value")
        return status, base64.b64decode(raw).decode() if status == 200 and isinstance(raw, str) else None

    def legacy_source(self, node: str, gid: str, app: str, prefix: str = "legacy") -> str:
        topic = f"x0x-{app}-{gid[:16]}"
        source = self.call(node, "POST", "/stores", {"name": app, "topic": topic, "policy": "signed"})
        sid = source.get("id") or source.get("topic") or source.get("store_id")
        self.e.check(f"{node} {app} legacy source id", isinstance(sid, str) and bool(sid))
        self.e.check(f"{node} seeds imported {app}", self.put(node, sid, f"{prefix}-imported", f"legacy-{app}") == 200)
        self.e.check(f"{node} seeds overlap {app}", self.put(node, sid, f"{prefix}-overlap", "source-overlap") == 200)
        self.e.check(f"{node} seeds removed {app}", self.put(node, sid, f"{prefix}-removed", "gone") == 200)
        self.e.check(f"{node} removes legacy {app}", self.c[node].request("DELETE", f"/stores/{enc(sid)}/{prefix}-removed")[0] == 200)
        return sid

    def candidate(self, node: str, gid: str, app: str) -> dict[str, Any]:
        listing = self.call(node, "GET", f"/groups/{enc(gid)}/stores/{app}/legacy-imports")
        candidates = listing.get("candidates", [])
        self.e.check(f"{node} lists exactly one current {app} source", len(candidates) == 1)
        return candidates[0]

    def barrier_absence(self, observer: str, writer: str, sid: str, forbidden: str) -> None:
        barrier = f"barrier-{uuid.uuid4().hex}"
        self.e.check("valid writer barrier accepted", self.put(writer, sid, barrier, "barrier") == 200)
        poll("valid barrier converges", self.timeout, lambda: self.read(observer, sid, barrier), lambda r: r == (200, "barrier"))
        deadline = time.monotonic() + min(self.timeout, 3.0)
        observations = 0
        while True:
            absent = self.read(observer, sid, forbidden)
            self.e.check("forbidden mutation remains absent", absent[0] == 404)
            observations += 1
            if time.monotonic() >= deadline:
                break
            time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
        self.e.check("forbidden mutation absent through stability window", observations >= 2)

    def assert_snapshot(self, node: str, sid: str, app: str, phase: str) -> None:
        self.e.check(f"{app} {phase} active persisted", self.read(node, sid, "legacy-imported") == (200, f"legacy-{app}"))
        self.e.check(f"{app} {phase} removal persisted", self.read(node, sid, "legacy-removed")[0] == 404)
        self.e.check(f"{app} {phase} local persisted", self.read(node, sid, "destination-only") == (200, f"local-{app}"))

    def await_observer_snapshot(self, observer: str, sid: str, app: str) -> None:
        poll(f"{app} observer imported value", self.timeout,
             lambda: self.read(observer, sid, "legacy-imported"),
             lambda r: r == (200, f"legacy-{app}"))
        poll(f"{app} observer tombstone", self.timeout,
             lambda: self.read(observer, sid, "legacy-removed"), lambda r: r[0] == 404)

    def assert_candidate_conflict(self, candidate: dict[str, Any], app: str) -> None:
        self.e.check(f"{app} preview reports overlap",
                     "legacy-overlap" in candidate.get("conflicts", []))

    def assert_receipt(self, receipt: dict[str, Any], *, key: str, digest: str,
                       source_id: str, gid: str, app: str, writer_aid: str) -> None:
        self.e.check(f"{app} receipt binds request",
                     receipt.get("idempotency_key") == key
                     and receipt.get("source_digest") == digest
                     and receipt.get("source_store_id") == source_id
                     and receipt.get("group_id") == gid
                     and receipt.get("app") == app
                     and receipt.get("endorser") == writer_aid)

    def run(self, owner: str, writer: str, observer: str, revoked: str,
            stop_owner: Any, restart_writer: Any) -> None:
        created = self.call(owner, "POST", "/groups", {"name": f"legacy-{uuid.uuid4().hex[:10]}", "preset": "public_open"})
        gid = created.get("group_id") or (created.get("group") or {}).get("id")
        self.e.check("canonical group id", isinstance(gid, str) and len(gid) >= 16)
        self.invite_join(owner, writer, gid); self.invite_join(owner, observer, gid); self.invite_join(owner, revoked, gid)
        writer_aid = self.c[writer].agent_id()
        revoked_aid = self.c[revoked].agent_id()
        self.legacy_source(revoked, gid, "wiki", "revoked")
        revoked_candidate = self.candidate(revoked, gid, "wiki")
        revoked_destination = self.call(observer, "POST", f"/groups/{enc(gid)}/stores", {"name": "wiki"})["id"]
        revoked_writer_destination = self.call(writer, "POST", f"/groups/{enc(gid)}/stores", {"name": "wiki"})["id"]
        self.e.check("revoked refusal uses matching writer and observer stores",
                     revoked_writer_destination == revoked_destination)
        self.e.check("owner removes source holder", self.c[owner].request("DELETE", f"/groups/{enc(gid)}/members/{revoked_aid}")[0] == 200)
        denied = poll("revoked import refusal", self.timeout,
                      lambda: self.c[revoked].request("GET", f"/groups/{enc(gid)}/stores/wiki/legacy-imports"),
                      lambda r: r[0] in (403, 409) or (r[0] == 200 and r[1].get("candidates") and r[1]["candidates"][0].get("can_import") is False))
        self.e.check("revoked writer cannot endorse", denied[0] in (200, 403, 409), status=denied[0])
        revoked_post, _ = self.c[revoked].request(
            "POST", f"/groups/{enc(gid)}/stores/wiki/legacy-imports/{enc(revoked_candidate['source_store_id'])}",
            {"source_digest": revoked_candidate["source_digest"], "idempotency_key": f"revoked-{uuid.uuid4().hex}"},
        )
        self.e.check("revoked import mutation refused", revoked_post == 403, status=revoked_post)
        self.barrier_absence(observer, writer, revoked_destination, "revoked-imported")

        announce = self.call(owner, "POST", "/groups", {"name": f"legacy-reader-{uuid.uuid4().hex[:8]}", "preset": "public_announce"})
        announce_gid = announce.get("group_id") or (announce.get("group") or {}).get("id")
        self.e.check("nonwriter group id", isinstance(announce_gid, str) and len(announce_gid) >= 16)
        self.invite_join(owner, writer, announce_gid); self.invite_join(owner, observer, announce_gid)
        self.legacy_source(writer, announce_gid, "wiki", "reader")
        reader_candidate = self.candidate(writer, announce_gid, "wiki")
        reader_destination = self.call(owner, "POST", f"/groups/{enc(announce_gid)}/stores", {"name": "wiki"})["id"]
        reader_observer_destination = self.call(observer, "POST", f"/groups/{enc(announce_gid)}/stores", {"name": "wiki"})["id"]
        self.e.check("reader refusal uses matching writer and observer stores",
                     reader_observer_destination == reader_destination)
        self.e.check("active reader cannot endorse", reader_candidate.get("can_import") is False)
        reader_status, _ = self.c[writer].request(
            "POST", f"/groups/{enc(announce_gid)}/stores/wiki/legacy-imports/{enc(reader_candidate['source_store_id'])}",
            {"source_digest": reader_candidate["source_digest"], "idempotency_key": f"reader-{uuid.uuid4().hex}"},
        )
        self.e.check("active reader import refused", reader_status == 403, status=reader_status)
        self.barrier_absence(observer, owner, reader_destination, "reader-imported")

        records = []

        for app in ("wiki", "web"):
            self.legacy_source(writer, gid, app)
            destination = self.call(writer, "POST", f"/groups/{enc(gid)}/stores", {"name": app})
            destination_id = destination["id"]
            self.e.check(f"destination-only {app} write", self.put(writer, destination_id, "destination-only", f"local-{app}") == 200)
            self.e.check(f"overlap {app} write", self.put(writer, destination_id, "legacy-overlap", f"destination-overlap-{app}") == 200)
            candidate = self.candidate(writer, gid, app)
            self.e.check(f"{app} writer may endorse", candidate.get("can_import") is True)
            self.assert_candidate_conflict(candidate, app)
            source_id, digest = candidate.get("source_store_id"), candidate.get("source_digest")
            self.e.check(f"{app} reviewed binding", isinstance(source_id, str) and isinstance(digest, str))
            downloaded = self.call(writer, "GET", f"/groups/{enc(gid)}/stores/{app}/legacy-imports/{enc(source_id)}")
            snapshot = base64.b64decode(downloaded["snapshot_b64"])
            self.e.check(f"{app} reviewed download is nonempty and digest-bound", bool(snapshot) and downloaded.get("source_digest") == digest)
            if app == "wiki":
                stop_owner()
            key = f"legacy-normal-{app}-{uuid.uuid4().hex}"
            imported = self.call(writer, "POST", f"/groups/{enc(gid)}/stores/{app}/legacy-imports/{enc(source_id)}",
                                 {"source_digest": digest, "idempotency_key": key})
            self.e.check(f"{app} import accepted for sharing", imported.get("publish_accepted") is True)
            receipt = imported.get("receipt") or {}
            self.assert_receipt(receipt, key=key, digest=digest, source_id=source_id,
                                gid=gid, app=app, writer_aid=writer_aid)
            self.e.check(f"{app} active value imported", self.read(writer, destination_id, "legacy-imported") == (200, f"legacy-{app}"))
            self.e.check(f"{app} tombstone retained", self.read(writer, destination_id, "legacy-removed")[0] == 404)
            self.e.check(f"{app} destination content preserved", self.read(writer, destination_id, "destination-only") == (200, f"local-{app}"))
            observer_store = self.call(observer, "POST", f"/groups/{enc(gid)}/stores", {"name": app})["id"]
            self.e.check(f"{app} observer deterministic id", observer_store == destination_id)
            self.await_observer_snapshot(observer, observer_store, app)
            records.append((app, destination_id, source_id, digest, key, receipt))

        restart_writer(gid)
        for app, destination_id, source_id, digest, key, receipt in records:
            reopened = self.call(writer, "POST", f"/groups/{enc(gid)}/stores", {"name": app})
            self.e.check(f"{app} restart deterministic id", reopened.get("id") == destination_id)
            self.assert_snapshot(writer, destination_id, app, "before replay")
            replay = self.call(writer, "POST", f"/groups/{enc(gid)}/stores/{app}/legacy-imports/{enc(source_id)}",
                               {"source_digest": digest, "idempotency_key": key})
            self.e.check(f"{app} restart replay returns same receipt", replay.get("receipt") == receipt and replay.get("publish_accepted") is True)
            self.assert_snapshot(writer, destination_id, app, "after replay")
            conflict_status, _ = self.c[writer].request("POST", f"/groups/{enc(gid)}/stores/{app}/legacy-imports/{enc(source_id)}",
                                                        {"source_digest": "00" * 32, "idempotency_key": key})
            self.e.check(f"{app} idempotency conflict refused", conflict_status == 409, status=conflict_status)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--network", choices=["test"], required=True)
    p.add_argument("--tokens-file", required=True); p.add_argument("--report", required=True)
    p.add_argument("--nodes", nargs=4, default=["nyc", "sfo", "helsinki", "nuremberg"],
                   metavar=("OWNER", "WRITER", "OBSERVER", "REVOKED"))
    p.add_argument("--local-port-base", type=int, default=23700); p.add_argument("--poll-timeout", type=float, default=120)
    p.add_argument("--allow-service-restart", action="store_true")
    a = p.parse_args()
    if not a.allow_service_restart: p.error("--allow-service-restart is required")
    if len(set(a.nodes)) != 4: p.error("four distinct node labels are required")
    tokens = load_tokens(a.tokens_file, var_prefix="TEST")
    if any(n not in tokens for n in a.nodes): p.error("node token/IP entry missing")
    endpoints = {n: tokens[n][0] for n in a.nodes}
    if len(set(endpoints.values())) != 4: p.error("four distinct endpoints are required")
    tunnels, clients, evidence = {}, {}, Evidence(); custody = ServiceCustody(endpoints); success = False
    def health(node: str) -> None:
        client = clients.get(node)
        if client is None: raise RuntimeError("health client unavailable")
        poll(f"{node} health", 60, lambda: client.request("GET", "/health"), lambda r: r[0] == 200 and r[1].get("ok") is True)
    try:
        for i, node in enumerate(a.nodes):
            tunnel = start_ssh_tunnel(tokens[node][0], a.local_port_base + i, remote_port=13600)
            tunnels[node] = tunnel; clients[node] = Api(f"http://127.0.0.1:{tunnel.local_port}", tokens[node][1])
        agent_ids = {node: clients[node].agent_id() for node in a.nodes}
        if len(set(agent_ids.values())) != 4: raise RuntimeError("four distinct agents are required")
        owner, writer, observer, revoked = a.nodes
        def restart_writer_without_provider(gid: str) -> None:
            status, body = clients[writer].request("GET", f"/groups/{enc(gid)}/members")
            if status != 200:
                raise RuntimeError("current roster unavailable before isolated restart")
            active = {row.get("agent_id") for row in body.get("members", [])}
            expected = {agent_ids[owner], agent_ids[writer], agent_ids[observer]}
            evidence.check("restart roster has exactly current authorized holders", active == expected,
                           active_count=len(active), expected_count=len(expected))
            custody.stop(observer)
            custody.restart(writer)
            health(writer)
        LegacyScenario(clients, evidence, a.poll_timeout).run(
            owner, writer, observer, revoked,
            lambda: custody.stop(owner),
            restart_writer_without_provider,
        )
        success = True
    except Exception as error:
        evidence.assertions.append({"label": f"harness {type(error).__name__}", "passed": False})
    finally:
        for error in custody.restore(health): success = False; evidence.assertions.append({"label": error, "passed": False})
        for node, tunnel in list(tunnels.items()):
            try: stop_ssh_tunnel(tunnel)
            except Exception as error: success = False; evidence.assertions.append({"label": f"cleanup {node} {type(error).__name__}", "passed": False})
        try:
            with open(a.report, "w", encoding="utf-8") as out: json.dump({"scenario": "legacy-normal-success", "assertions": evidence.assertions}, out, indent=2)
        except Exception: success = False
    return 0 if success and all(x["passed"] for x in evidence.assertions) else 1


if __name__ == "__main__": raise SystemExit(main())
