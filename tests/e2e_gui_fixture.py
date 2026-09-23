#!/usr/bin/env python3
"""Dedicated GUI acceptance fixture on the isolated synthetic Home plane.

Prepares known, nonsensitive, real-API-authored Wiki/Web state (canonical
Home, one private_secure space, one public_announce space with a generic signed
legacy Wiki/Web source), atomically retains a redacted fixture manifest plus
a ready marker, then holds every owned synthetic process and tunnel alive for
a bounded operator browser phase before the authoritative finally restores
custody. Acceptance is never the ready marker: a structured browser result
must bind this exact run/fixture identity and every required scenario must
have succeeded.

Operator contract (see also final-gui-acceptance-readiness-sol.md):
  * poll for ``ready.json`` in --evidence-dir; it names the manifest and the
    result path and carries the deadline budget;
  * exchange the durable daemon token for a session token strictly in memory
    through an already-owned tunnel; no auth value ever belongs in any file,
    argument, or output produced by this driver;
  * perform the browser scenarios listed in ``required_scenarios``;
  * atomically write ``browser-result.json`` (write a temporary file in the
    same directory, then rename) shaped as
    ``{"run_id": ..., "network_id": ..., "manifest_sha256": ...,
    "scenarios": [{"name": ...,
    "status": "pass"|...}, ...]}`` before the deadline.

Every cleanup path (success, explicit browser failure, timeout, absent or
invalid result, provisioning failure, report-write failure) still stops all
owned synthetic processes and tunnels, attempts every cleanup even when one
fails, preserves the retained roots/evidence, and exposes cleanup failures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import time
import uuid
from typing import Any, Callable
from e2e_home_fixture import Node, Remote, SyntheticProcessCustody, config_bytes
from e2e_tunnel import start_ssh_tunnel, stop_ssh_tunnel
from e2e_vps_groups import load_tokens
from e2e_vps_kv import Api, Evidence, enc, poll
from e2e_vps_legacy_import import LegacyScenario
from e2e_vps_private_kv import Scenario

REQUIRED_SCENARIOS = (
    "home-wiki-read", "home-wiki-save", "home-web-read", "home-web-save",
    "private-wiki-read", "private-wiki-save", "private-web-read", "private-web-save",
    "legacy-wiki-writer-preview", "legacy-wiki-writer-import", "legacy-wiki-reader-refusal",
    "legacy-web-writer-preview", "legacy-web-writer-import", "legacy-web-reader-refusal",
)
MANIFEST_NAME, READY_NAME, RESULT_NAME, REPORT_NAME = (
    "manifest.json", "ready.json", "browser-result.json", "report.json")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def write_json_atomic(path: str, payload: Any) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as output:
        json.dump(payload, output, indent=2)
    os.replace(tmp, path)


def redact_result(payload: Any, expected_run: str, expected_network: str,
                  expected_manifest_sha256: str) -> Any:
    """Whitelist identity and scenario statuses; never persist other fields."""
    if not isinstance(payload, dict):
        return None
    scenarios = payload.get("scenarios")
    return {"run_id": expected_run if payload.get("run_id") == expected_run else None,
            "network_id": expected_network if payload.get("network_id") == expected_network else None,
            "manifest_sha256": expected_manifest_sha256
            if payload.get("manifest_sha256") == expected_manifest_sha256 else None,
            "scenarios": [{"name": row.get("name") if row.get("name") in REQUIRED_SCENARIOS
                           else "<unknown>",
                           "status": row.get("status") if row.get("status") in ("pass", "fail")
                           else "<invalid>"}
                          for row in scenarios if isinstance(row, dict)]
            if isinstance(scenarios, list) else None}


def validate_browser_result(payload: Any, expected_run: str, expected_network: str,
                            expected_manifest_sha256: str) -> tuple[str, str]:
    """Classify an operator browser result.

    Returns (state, reason) with state "pass" (terminal success), "fail"
    (terminal failure: stale binding, unknown or explicitly failed scenario,
    conflicting duplicates), or "wait" (absent identity, malformed, or partial
    result that may still be completed before the deadline).
    """
    if not isinstance(payload, dict):
        return "wait", "result is not a JSON object"
    run_id, network_id = payload.get("run_id"), payload.get("network_id")
    if isinstance(run_id, str) and run_id != expected_run:
        return "fail", "stale result bound to another fixture run"
    manifest_sha256 = payload.get("manifest_sha256")
    if isinstance(network_id, str) and network_id != expected_network:
        return "fail", "result bound to another network"
    if isinstance(manifest_sha256, str) and manifest_sha256 != expected_manifest_sha256:
        return "fail", "result bound to another manifest"
    if (run_id != expected_run or network_id != expected_network
            or manifest_sha256 != expected_manifest_sha256):
        return "wait", "result identity is incomplete"
    scenarios = payload.get("scenarios")
    if (not isinstance(scenarios, list) or not scenarios
            or not all(isinstance(row, dict) for row in scenarios)):
        return "wait", "scenarios missing or malformed"
    observed: dict[str, str] = {}
    for row in scenarios:
        name, status = row.get("name"), row.get("status")
        if not isinstance(name, str) or not isinstance(status, str):
            return "wait", "scenario entry is malformed"
        if name in observed and observed[name] != status:
            return "fail", "conflicting duplicate browser scenario"
        observed[name] = status
    unknown = sorted(name for name in observed if name not in REQUIRED_SCENARIOS)
    if unknown:
        return "fail", "unknown browser scenario"
    failed = sorted(name for name, status in observed.items() if status != "pass")
    if failed:
        return "fail", f"explicit browser failure: {failed}"
    missing = [name for name in REQUIRED_SCENARIOS if name not in observed]
    if missing:
        return "wait", f"partial result missing {missing}"
    return "pass", "every required browser scenario succeeded"


def wait_for_browser_result(result_path: str, expected_run: str, expected_network: str,
                            expected_manifest_sha256: str, deadline_secs: float,
                            now: Callable[[], float] = time.monotonic,
                            sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    """Bounded ready/done handshake; timeout is always a failure, never a skip."""
    if not math.isfinite(deadline_secs) or deadline_secs <= 0:
        raise ValueError("browser deadline must be finite and positive")
    deadline = now() + deadline_secs
    last_state, last_reason = "absent", "no result file appeared"
    while True:
        try:
            with open(result_path, encoding="utf-8") as handle:
                raw = handle.read()
        except FileNotFoundError:
            pass
        except OSError as error:
            last_state, last_reason = "invalid", f"result unreadable: {type(error).__name__}"
        else:
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                last_state, last_reason = "invalid", "result is not valid JSON"
            else:
                state, reason = validate_browser_result(
                    payload, expected_run, expected_network, expected_manifest_sha256)
                last_state, last_reason = state, reason
                if state != "wait":
                    if now() >= deadline:
                        return {"status": "fail", "reason": f"deadline {state}: {reason}",
                                "result": None}
                    return {"status": state, "reason": reason,
                            "result": redact_result(payload, expected_run, expected_network,
                                                    expected_manifest_sha256)}
        if now() >= deadline:
            return {"status": "fail", "reason": f"deadline {last_state}: {last_reason}", "result": None}
        sleep(min(1.0, max(0.0, deadline - now())))


def provision_space(scenario: Scenario, evidence: Evidence, space: str, gid: str,
                    author: str, observer: str, key_prefix: str) -> dict[str, Any]:
    stores: dict[str, str] = {}
    pages: list[dict[str, str]] = []
    for app in ("wiki", "web"):
        first = scenario.open_store(author, gid, app)
        second = scenario.open_store(observer, gid, app)
        sid = first.get("id")
        evidence.check(f"{space} deterministic {app} store",
                       isinstance(sid, str) and bool(sid) and sid == second.get("id"))
        key = f"{key_prefix}-{space}-{app}"
        value = f"gui-{space}-{app}-page-{key_prefix[-12:]}"
        evidence.check(f"{space} {app} page authored through the real API",
                       scenario.put(author, sid, key, value)[0] == 200)
        scenario.await_value(observer, sid, key, value)
        stores[app] = sid
        pages.append({"app": app, "key": key, "value_sha256": sha256_text(value)})
    return {"group_id": gid, "stores": stores, "pages": pages}


def run_fixture(args: argparse.Namespace, remote: Remote, evidence: Evidence,
                resources: dict[str, Any]) -> bool:
    os.makedirs(args.evidence_dir, exist_ok=True)
    if any(os.path.lexists(os.path.join(args.evidence_dir, name))
           for name in (MANIFEST_NAME, READY_NAME, RESULT_NAME, REPORT_NAME)):
        resources["prior_run_rejected"] = True
        raise RuntimeError("fixture evidence directory contains a prior run")
    run_id = uuid.uuid4().hex
    plane, root = f"x0x.home.e2e.{run_id}", f"/var/tmp/x0x-home-e2e-{run_id}"
    tokens = load_tokens(args.hosts_file, var_prefix="TEST")
    missing = [label for label in args.nodes if label not in tokens]
    if missing: raise RuntimeError("fixture host mapping missing")
    hosts = [tokens[label][0] for label in args.nodes]
    if len(set(hosts)) != len(hosts): raise RuntimeError("fixture requires distinct hosts")
    nodes = {label: Node(label, host, args.api_port_base + i, args.quic_port_base + i, root)
             for i, (label, host) in enumerate(zip(args.nodes, hosts))}
    custody = SyntheticProcessCustody(remote, args.daemon_binary, run_id)
    tunnels: list[Any] = []
    resources["custody"], resources["tunnels"] = custody, tunnels
    owner, writer, reader = args.nodes
    bootstrap = f"{nodes[owner].host}:{nodes[owner].quic_port}"
    for label, node in nodes.items():
        custody.prepare(node, config_bytes(node, plane, None if label == owner else bootstrap))
    custody.create_owner_key(nodes[owner], args.cli_binary)
    clients: dict[str, Api] = {}
    for label, node in nodes.items():
        custody.start(node)
        tunnel = start_ssh_tunnel(node.host, args.local_port_base + len(tunnels),
                                  remote_port=node.api_port)
        tunnels.append(tunnel)
        clients[label] = Api(f"http://127.0.0.1:{tunnel.local_port}", custody.token(node))
    receipts = {label: custody.hashes(node) for label, node in nodes.items()}
    binary_hashes = {receipt[1] for receipt in receipts.values()}
    evidence.check("fixture custody receipt is reproducible", len(binary_hashes) == 1,
                   run_id=run_id, network_id=plane,
                   binary_sha256=next(iter(binary_hashes), None),
                   config_sha256={label: receipt[0] for label, receipt in receipts.items()})
    resources["manifest"] = {
        "run_id": run_id, "network_id": plane,
        "binary_sha256": next(iter(binary_hashes), None),
        "config_sha256": {label: receipt[0] for label, receipt in receipts.items()},
    }
    scenario, legacy = Scenario(clients, evidence, args.poll_timeout), \
        LegacyScenario(clients, evidence, args.poll_timeout)

    owner_key_sha = custody.key_fingerprint(nodes[owner])
    evidence.check("synthetic owner key fingerprint recorded", owner_key_sha is not None,
                   owner_key_sha256=owner_key_sha)
    card_status, response = clients[writer].request("GET", "/agent/card")
    card = response.get("card") if isinstance(response, dict) else None
    public_key = card.get("agent_public_key") if isinstance(card, dict) else None
    signature = card.get("signature") if isinstance(card, dict) else None
    evidence.check(f"{writer} signed card exposes public key", card_status == 200
                   and isinstance(response, dict) and response.get("ok") is True
                   and isinstance(public_key, str)
                   and re.fullmatch(r"[0-9a-f]{3904}", public_key) is not None
                   and isinstance(signature, str)
                   and re.fullmatch(r"[0-9a-f]{6618}", signature) is not None,
                   status=card_status)
    custody.stop(writer)
    issue_status, issued = clients[owner].request("POST", "/owner/agents/issue",
                                                  {"agent_public_key": public_key, "mode": "acp",
                                                   "label": f"gui-e2e-{writer}"})
    certificate = (issued.get("certificate") or {}).get("storage_b64")
    evidence.check(f"owner certifies {writer}", issue_status == 200
                   and isinstance(certificate, str), status=issue_status)
    custody.write_certificate(nodes[writer], certificate)
    fingerprint = custody.copy_owner_key(nodes[owner], nodes[writer])
    evidence.check(f"{writer} holds the synthetic owner key", fingerprint == owner_key_sha,
                   owner_key_sha256=fingerprint)
    custody.start(nodes[writer])
    poll(f"{writer} restarts certified", args.poll_timeout,
         lambda: clients[writer].request("GET", "/health"),
         lambda result: result[0] == 200 and result[1].get("ok") is True)
    announce_status, _ = clients[writer].request("POST", "/announce",
                                                 {"include_user_identity": True,
                                                  "human_consent": True})
    evidence.check(f"{writer} publishes owner certificate", announce_status in (200, 201),
                   status=announce_status)

    home_gid, owner_id = scenario.home(owner)
    home_status, home = clients[owner].request("GET", "/home")
    evidence.check("synthetic owner provisions verified local Home", home_status == 200
                   and home.get("state") == "local"
                   and (home.get("primary_agent") or {}).get("verified") is True,
                   status=home_status, state=home.get("state"))
    scenario.require_home_identity(writer, owner_id)
    writer_invite = scenario.home_invite(owner, writer, home_gid, owner_id)
    scenario.join_home(owner, writer, home_gid, owner_id, writer_invite)

    key_prefix = f"x0x-gui-e2e-{run_id[:12]}"
    spaces = {"home": provision_space(scenario, evidence, "home", home_gid, owner, writer,
                                      key_prefix)}
    created = scenario.ok(owner, "POST", "/groups", {
        "name": f"gui-private-{uuid.uuid4().hex[:10]}", "preset": "private_secure"})
    private_gid = created.get("group_id") or (created.get("group") or {}).get("id")
    evidence.check("private_secure group id returned", isinstance(private_gid, str)
                   and bool(private_gid))
    scenario.join_private(owner, writer, private_gid)
    spaces["private"] = provision_space(scenario, evidence, "private", private_gid,
                                        owner, writer, key_prefix)

    legacy_created = legacy.call(owner, "POST", "/groups", {
        "name": f"gui-legacy-{uuid.uuid4().hex[:10]}", "preset": "public_announce"})
    legacy_gid = legacy_created.get("group_id") or (legacy_created.get("group") or {}).get("id")
    evidence.check("legacy public_announce group id returned", isinstance(legacy_gid, str)
                   and len(legacy_gid) >= 16)
    legacy.invite_join(owner, writer, legacy_gid)
    legacy.invite_join(owner, reader, legacy_gid)
    reader_aid = clients[reader].agent_id()
    legacy_apps: dict[str, Any] = {}
    for app in ("wiki", "web"):
        source_id = legacy.legacy_source(owner, legacy_gid, app)
        destination_id = legacy.call(owner, "POST", f"/groups/{enc(legacy_gid)}/stores",
                                     {"name": app})["id"]
        observer_destination_id = legacy.call(
            writer, "POST", f"/groups/{enc(legacy_gid)}/stores", {"name": app}).get("id")
        evidence.check(f"{app} observer opens the same legacy destination",
                       isinstance(destination_id, str) and bool(destination_id)
                       and observer_destination_id == destination_id)
        evidence.check(f"{app} destination-only write",
                       legacy.put(owner, destination_id, "destination-only", f"local-{app}") == 200)
        evidence.check(f"{app} overlap write",
                       legacy.put(owner, destination_id, "legacy-overlap",
                                  f"destination-overlap-{app}") == 200)
        candidate = legacy.candidate(owner, legacy_gid, app)
        evidence.check(f"{app} writer may endorse", candidate.get("can_import") is True)
        evidence.check(f"{app} source matches API return",
                       candidate.get("source_store_id") == source_id)
        evidence.check(f"{app} writer source has the authored pages",
                       candidate.get("keys") == ["legacy-imported", "legacy-overlap"]
                       and isinstance(candidate.get("source_digest"), str)
                       and bool(candidate["source_digest"]))
        evidence.check(f"{app} preview reports overlap",
                       "legacy-overlap" in candidate.get("conflicts", []))
        evidence.check(f"{app} candidate is unambiguous",
                       candidate.get("ambiguous_group_prefix") is False)
        legacy_apps[app] = {
            "destination_store_id": destination_id,
            "writer_source_store_id": candidate.get("source_store_id"),
            "writer_source_digest": candidate.get("source_digest"),
            "writer_conflicts": candidate.get("conflicts", []),
            "writer_source_keys": candidate.get("keys", []),
            "writer_source_pages": [
                {"key": "legacy-imported", "value_sha256": sha256_text(f"legacy-{app}")},
                {"key": "legacy-overlap", "value_sha256": sha256_text("source-overlap")}],
            "destination_only": {"key": "destination-only",
                                 "value_sha256": sha256_text(f"local-{app}")},
            "overlap": {"key": "legacy-overlap",
                        "value_sha256": sha256_text(f"destination-overlap-{app}")},
        }
    for app in ("wiki", "web"):
        reader_source = legacy.legacy_source(reader, legacy_gid, app, "reader")
        refused = poll(f"{app} active reader refusal reaches card state", args.poll_timeout,
                       lambda app=app: clients[reader].request(
                           "GET", f"/groups/{enc(legacy_gid)}/stores/{app}/legacy-imports"),
                       lambda result: result[0] == 200 and result[1].get("candidates")
                       and result[1]["candidates"][0].get("can_import") is False
                       and result[1]["candidates"][0].get("source_store_id") == reader_source
                       and bool(result[1]["candidates"][0].get("import_refusal_reason")))
        reader_candidate = refused[1]["candidates"][0]
        evidence.check(f"{app} reader card binds its own signed source",
                       isinstance(reader_candidate.get("source_digest"), str)
                       and bool(reader_candidate["source_digest"])
                       and reader_candidate.get("source_store_id") == reader_source
                       and reader_candidate.get("keys") == ["reader-imported", "reader-overlap"])
        legacy_apps[app]["reader_source_store_id"] = reader_source
        legacy_apps[app]["reader_source_digest"] = reader_candidate["source_digest"]
        legacy_apps[app]["reader_source_keys"] = reader_candidate.get("keys", [])
        legacy_apps[app]["reader_source_pages"] = [
            {"key": "reader-imported", "value_sha256": sha256_text(f"legacy-{app}")},
            {"key": "reader-overlap", "value_sha256": sha256_text("source-overlap")}]
        refusal_status, _ = clients[reader].request(
            "POST", f"/groups/{enc(legacy_gid)}/stores/{app}/legacy-imports/"
            f"{enc(reader_source)}",
            {"source_digest": reader_candidate["source_digest"],
             "idempotency_key": f"gui-reader-{uuid.uuid4().hex}"})
        evidence.check(f"{app} active reader import mutation refused",
                       refusal_status == 403, status=refusal_status)
        evidence.check(f"{app} refused import preserves destination-only value",
                       legacy.read(owner, legacy_apps[app]["destination_store_id"],
                                   "destination-only") == (200, f"local-{app}"))
        evidence.check(f"{app} refused import preserves overlap value",
                       legacy.read(owner, legacy_apps[app]["destination_store_id"],
                                   "legacy-overlap") == (200, f"destination-overlap-{app}"))
        legacy.barrier_absence(writer, owner, legacy_apps[app]["destination_store_id"],
                               "reader-imported")
    for app in ("wiki", "web"):
        still = legacy.candidate(owner, legacy_gid, app)
        evidence.check(f"{app} writer endorsement survives reader refusal",
                       still.get("can_import") is True)

    manifest = {
        "run_id": run_id, "network_id": plane,
        "custody": resources["manifest"],
        "nodes": [{"label": label, "agent_id": clients[label].agent_id(),
                   "api_port": node.api_port, "quic_port": node.quic_port,
                   "tunnel_local_port": tunnel.local_port}
                  for (label, node), tunnel in zip(nodes.items(), tunnels)],
        "spaces": spaces,
        "legacy": {"group_id": legacy_gid,
                   "writer": {"label": owner, "agent_id": clients[owner].agent_id()},
                   "reader": {"label": reader, "agent_id": reader_aid},
                   "apps": legacy_apps},
        "required_scenarios": list(REQUIRED_SCENARIOS),
    }
    evidence_dir = args.evidence_dir
    manifest_path = os.path.join(evidence_dir, MANIFEST_NAME)
    write_json_atomic(manifest_path, manifest)
    with open(manifest_path, "rb") as manifest_file:
        manifest_sha256 = hashlib.sha256(manifest_file.read()).hexdigest()
    write_json_atomic(os.path.join(evidence_dir, READY_NAME), {
        "run_id": run_id, "network_id": plane, "ready_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                        time.gmtime()),
        "manifest_sha256": manifest_sha256,
        "browser_deadline_secs": args.browser_deadline_secs,
        "manifest": MANIFEST_NAME, "browser_result": RESULT_NAME,
        "tunnels": {row["label"]: row["tunnel_local_port"] for row in manifest["nodes"]},
        "required_scenarios": list(REQUIRED_SCENARIOS)})
    print(f"run_id {run_id} ready: {os.path.join(evidence_dir, READY_NAME)}")
    outcome = wait_for_browser_result(os.path.join(evidence_dir, RESULT_NAME), run_id, plane,
                                      manifest_sha256,
                                      args.browser_deadline_secs)
    resources["browser"] = outcome
    print(f"browser result: {outcome['status']} ({outcome['reason']})")
    evidence.check("browser acceptance result binds this run and passes every required scenario",
                   outcome["status"] == "pass", reason=outcome["reason"])
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", choices=["synthetic-home"], required=True)
    parser.add_argument("--hosts-file", required=True)
    parser.add_argument("--nodes", nargs=3, required=True,
                        metavar=("OWNER", "WRITER", "READER"))
    parser.add_argument("--daemon-binary", required=True)
    parser.add_argument("--cli-binary", required=True)
    parser.add_argument("--api-port-base", type=int, default=15600)
    parser.add_argument("--quic-port-base", type=int, default=8483)
    parser.add_argument("--local-port-base", type=int, default=25700)
    parser.add_argument("--poll-timeout", type=float, default=120)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--browser-deadline-secs", type=float, default=900)
    args = parser.parse_args()
    if len(set(args.nodes)) != 3: parser.error("three distinct node labels are required")
    if not os.path.isabs(args.evidence_dir): parser.error("--evidence-dir must be absolute")
    if not math.isfinite(args.browser_deadline_secs) or args.browser_deadline_secs <= 0:
        parser.error("--browser-deadline-secs must be finite and positive")
    evidence, resources, succeeded = Evidence(), {}, False
    try:
        succeeded = run_fixture(args, Remote(), evidence, resources)
    except Exception as error:
        evidence.assertions.append({"label": f"fixture {type(error).__name__}", "passed": False})
    finally:
        custody = resources.get("custody")
        custody_errors: list[str] = []
        if custody is not None:
            try:
                for error in custody.restore():
                    custody_errors.append(error)
                    evidence.assertions.append({"label": error, "passed": False}); succeeded = False
            except Exception as error:
                detail = f"custody cleanup {type(error).__name__}"
                custody_errors.append(detail)
                evidence.assertions.append({"label": detail, "passed": False}); succeeded = False
        tunnel_errors = 0
        for tunnel in resources.get("tunnels", []):
            try: stop_ssh_tunnel(tunnel)
            except Exception as error:
                tunnel_errors += 1
                evidence.assertions.append({"label": f"tunnel cleanup {type(error).__name__}",
                                            "passed": False}); succeeded = False
        if not resources.get("prior_run_rejected"):
            try:
                os.makedirs(args.evidence_dir, exist_ok=True)
                write_json_atomic(os.path.join(args.evidence_dir, REPORT_NAME), {
                    "scenario": "synthetic-home-gui", "custody": resources.get("manifest"),
                    "browser": resources.get("browser"),
                    "cleanup": {"custody_errors": custody_errors, "tunnel_errors": tunnel_errors},
                    "assertions": evidence.assertions})
            except Exception: succeeded = False
    return 0 if succeeded and all(row["passed"] for row in evidence.assertions) else 1


if __name__ == "__main__": raise SystemExit(main())
