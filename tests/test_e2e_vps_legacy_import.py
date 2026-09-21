#!/usr/bin/env python3
"""Offline controls for the legacy normal-success E2E harness."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


def load():
    tests = Path(__file__).parent
    sys.path.insert(0, str(tests))
    spec = importlib.util.spec_from_file_location("e2e_vps_legacy_import", tests / "e2e_vps_legacy_import.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module); return module


class FakeApi:
    def __init__(self): self.calls = []; self.values = {}
    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if path == "/stores": return 201, {"ok": True, "id": "legacy-id"}
        if method == "PUT":
            self.values[path] = body["value"]
            return 200, {"ok": True}
        if method == "GET":
            if path in self.values: return 200, {"ok": True, "value": self.values[path]}
            return 404, {"ok": False}
        return 200, {"ok": True}


class LegacyHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.m = load()

    def test_legacy_source_uses_exact_historical_topic_and_real_store_routes(self):
        api = FakeApi(); evidence = self.m.Evidence()
        scenario = self.m.LegacyScenario({"writer": api}, evidence, 1)
        sid = scenario.legacy_source("writer", "abcdef0123456789" + "00" * 24, "wiki")
        self.assertEqual("legacy-id", sid)
        self.assertEqual({"name": "wiki", "topic": "x0x-wiki-abcdef0123456789", "policy": "signed"}, api.calls[0][2])
        self.assertEqual(["POST", "PUT", "PUT", "PUT", "DELETE"], [call[0] for call in api.calls])
        self.assertIn("legacy-overlap", api.calls[2][1])

    def test_snapshot_oracle_requires_active_tombstone_and_destination_content(self):
        scenario = self.m.LegacyScenario({}, self.m.Evidence(), 1)
        scenario.read = mock.Mock(side_effect=[
            (200, "legacy-wiki"), (404, None), (200, "local-wiki")])
        scenario.assert_snapshot("writer", "store", "wiki", "before replay")
        self.assertEqual(3, scenario.read.call_count)
        scenario.read = mock.Mock(side_effect=[
            (404, None), (404, None), (200, "local-wiki")])
        with self.assertRaises(AssertionError):
            scenario.assert_snapshot("writer", "store", "wiki", "after replay")

    def test_observer_and_refusal_oracles_use_positive_barriers(self):
        writer, observer = FakeApi(), FakeApi()
        scenario = self.m.LegacyScenario({"writer": writer, "observer": observer}, self.m.Evidence(), 20)
        scenario.put = mock.Mock(return_value=200)
        scenario.read = mock.Mock(side_effect=[
            (200, "legacy-web"), (404, None),
            (200, "barrier"), (404, None), (404, None),
        ])
        scenario.await_observer_snapshot("observer", "store", "web")
        ticks = iter(range(100))
        with mock.patch.object(self.m.time, "monotonic", side_effect=lambda: float(next(ticks))), \
             mock.patch.object(self.m.time, "sleep"):
            scenario.barrier_absence("observer", "writer", "store", "forbidden")
        scenario.put.assert_called_once()
        calls = scenario.read.call_args_list
        self.assertEqual("legacy-imported", calls[0].args[2])
        self.assertEqual("legacy-removed", calls[1].args[2])
        self.assertTrue(calls[2].args[2].startswith("barrier-"))
        self.assertEqual("forbidden", calls[3].args[2])
        self.assertEqual("forbidden", calls[4].args[2])

    def test_conflict_and_full_receipt_binding_are_mandatory(self):
        scenario = self.m.LegacyScenario({}, self.m.Evidence(), 1)
        scenario.assert_candidate_conflict({"conflicts": ["legacy-overlap"]}, "wiki")
        receipt = {"idempotency_key": "key", "source_digest": "digest",
                   "source_store_id": "source", "group_id": "group",
                   "app": "wiki", "endorser": "writer"}
        scenario.assert_receipt(receipt, key="key", digest="digest", source_id="source",
                                gid="group", app="wiki", writer_aid="writer")
        bad = dict(receipt); bad["endorser"] = "owner"
        with self.assertRaises(AssertionError):
            scenario.assert_receipt(bad, key="key", digest="digest", source_id="source",
                                    gid="group", app="wiki", writer_aid="writer")
        with self.assertRaises(AssertionError):
            scenario.assert_candidate_conflict({"conflicts": []}, "wiki")

    def test_candidate_requires_exactly_one_source(self):
        class Listings(FakeApi):
            def request(self, method, path, body=None):
                return 200, {"ok": True, "candidates": [{"source_store_id": "s"}, {"source_store_id": "t"}]}
        scenario = self.m.LegacyScenario({"writer": Listings()}, self.m.Evidence(), 1)
        with self.assertRaises(AssertionError): scenario.candidate("writer", "g" * 64, "wiki")

    def test_restart_flag_required_before_tokens_or_tunnels(self):
        argv = ["legacy", "--network", "test", "--tokens-file", "missing", "--report", "unused"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.m, "start_ssh_tunnel") as tunnel, self.assertRaises(SystemExit):
            self.m.main()
        tunnel.assert_not_called()

    def test_duplicate_nodes_fail_before_tunnels(self):
        argv = ["legacy", "--network", "test", "--tokens-file", "missing", "--report", "unused",
                "--allow-service-restart", "--nodes", "a", "a", "b", "c"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.m, "start_ssh_tunnel") as tunnel, self.assertRaises(SystemExit):
            self.m.main()
        tunnel.assert_not_called()

    def test_partial_tunnel_failure_cleans_owned_tunnel_and_returns_one(self):
        nodes = ["a", "b", "c", "d"]; tokens = {n: (f"192.0.2.{i}", n) for i, n in enumerate(nodes, 1)}
        tunnel = mock.Mock(local_port=25000)
        argv = ["legacy", "--network", "test", "--tokens-file", "tokens", "--report", "report.json",
                "--allow-service-restart", "--nodes", *nodes]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.m, "load_tokens", return_value=tokens), \
             mock.patch.object(self.m, "start_ssh_tunnel", side_effect=[tunnel, RuntimeError("second")]), \
             mock.patch.object(self.m, "stop_ssh_tunnel") as stop, mock.patch("builtins.open", mock.mock_open()):
            self.assertEqual(1, self.m.main())
        stop.assert_called_once_with(tunnel)

    def test_main_restart_isolates_every_other_current_holder(self):
        nodes = ["owner", "writer", "observer", "revoked"]
        tokens = {n: (f"192.0.2.{i}", n) for i, n in enumerate(nodes, 1)}
        agent_ids = {n: f"agent-{n}" for n in nodes}
        class Client:
            def __init__(self, node): self.node = node
            def agent_id(self): return agent_ids[self.node]
            def request(self, method, path, body=None):
                if path.endswith("/members"):
                    return 200, {"members": [{"agent_id": agent_ids[n]} for n in nodes[:3]]}
                return 200, {"ok": True}
        clients = [Client(n) for n in nodes]
        tunnels = [mock.Mock(local_port=25000 + i) for i in range(4)]
        custody = mock.Mock()
        custody.restore.return_value = []
        def exercise(_self, owner, writer, observer, revoked, stop_owner, restart_writer):
            stop_owner(); restart_writer("g" * 64)
        argv = ["legacy", "--network", "test", "--tokens-file", "tokens", "--report", "report.json",
                "--allow-service-restart", "--nodes", *nodes]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.m, "load_tokens", return_value=tokens), \
             mock.patch.object(self.m, "start_ssh_tunnel", side_effect=tunnels), \
             mock.patch.object(self.m, "stop_ssh_tunnel"), mock.patch.object(self.m, "Api", side_effect=clients), \
             mock.patch.object(self.m, "ServiceCustody", return_value=custody), \
             mock.patch.object(self.m.LegacyScenario, "run", autospec=True, side_effect=exercise), \
             mock.patch("builtins.open", mock.mock_open()):
            self.assertEqual(0, self.m.main())
        self.assertEqual([mock.call("owner"), mock.call("observer")], custody.stop.call_args_list)
        custody.restart.assert_called_once_with("writer")

    def test_full_scenario_requires_open_handles_and_rejects_stopped_nodes(self):
        class Backend:
            def __init__(self):
                self.groups = {}; self.opens = set(); self.values = {}; self.sources = {}
                self.stopped = set(); self.group_seq = 0

            def request(self, node, method, path, body):
                if node in self.stopped:
                    raise RuntimeError("stopped node request")
                parts = path.strip("/").split("/")
                if method == "POST" and path == "/groups":
                    self.group_seq += 1; gid = f"group-{self.group_seq:02d}" + "0" * 56
                    self.groups[gid] = {"preset": body["preset"], "members": {"owner"}}
                    return 201, {"group_id": gid}
                if method == "POST" and len(parts) == 3 and parts[0] == "groups" and parts[2] == "invite":
                    return 200, {"invite_link": f"x0x://invite/{parts[1]}"}
                if method == "POST" and path == "/groups/join":
                    gid = body["invite"].rsplit("/", 1)[1]; self.groups[gid]["members"].add(node)
                    return 200, {"ok": True}
                if method == "GET" and len(parts) == 3 and parts[0] == "groups" and parts[2] == "members":
                    return 200, {"members": [{"agent_id": f"agent-{n}"} for n in self.groups[parts[1]]["members"]]}
                if method == "DELETE" and len(parts) == 4 and parts[0] == "groups" and parts[2] == "members":
                    removed = parts[3].removeprefix("agent-"); self.groups[parts[1]]["members"].discard(removed)
                    return 200, {"ok": True}
                if method == "POST" and path == "/stores":
                    sid = f"source-{node}-{body['name']}-{len(self.sources)}"
                    self.sources[sid] = {"node": node, "app": body["name"]}; self.opens.add((node, sid))
                    return 201, {"id": sid}
                if len(parts) >= 3 and parts[0] == "groups" and parts[2] == "stores":
                    gid = parts[1]
                    app = body["name"] if len(parts) == 3 else parts[3]
                    sid = f"canonical-{gid}-{app}"
                    if method == "POST" and len(parts) == 3:
                        self.opens.add((node, sid)); return 201, {"id": sid}
                    if len(parts) == 5 and parts[4] == "legacy-imports" and method == "GET":
                        source = next(v | {"sid": k} for k, v in reversed(self.sources.items()) if v["app"] == app)
                        can_import = self.groups[gid]["preset"] == "public_open" and node in self.groups[gid]["members"]
                        return 200, {"candidates": [{"source_store_id": source["sid"], "source_digest": "d" * 64,
                                                      "can_import": can_import, "conflicts": ["legacy-overlap"]}]}
                    if len(parts) == 6 and parts[4] == "legacy-imports" and method == "GET":
                        return 200, {"snapshot_b64": "eA==", "source_digest": "d" * 64}
                    if len(parts) == 6 and parts[4] == "legacy-imports" and method == "POST":
                        if self.groups[gid]["preset"] != "public_open" or node not in self.groups[gid]["members"]:
                            return 403, {"ok": False}
                        source_id = parts[5]; source = self.sources[source_id]
                        for key, value in list(self.values.items()):
                            if key[0] == source_id: self.values[(sid, key[1])] = value
                        receipt = {"idempotency_key": body["idempotency_key"], "source_digest": body["source_digest"],
                                   "source_store_id": source_id, "group_id": gid, "app": source["app"],
                                   "endorser": f"agent-{node}"}
                        if body["source_digest"] != "d" * 64: return 409, {"ok": False}
                        return 200, {"publish_accepted": True, "receipt": receipt}
                if parts[0] == "stores" and len(parts) == 3:
                    sid, key = parts[1], parts[2]
                    if (node, sid) not in self.opens: return 404, {"ok": False}
                    if method == "PUT": self.values[(sid, key)] = body["value"]; return 200, {"ok": True}
                    if method == "DELETE": self.values.pop((sid, key), None); return 200, {"ok": True}
                    if method == "GET":
                        value = self.values.get((sid, key))
                        return (200, {"value": value}) if value is not None else (404, {"ok": False})
                raise AssertionError((node, method, path))

        class Client:
            def __init__(self, backend, node): self.backend, self.node = backend, node
            def agent_id(self): return f"agent-{self.node}"
            def request(self, method, path, body=None): return self.backend.request(self.node, method, path, body or {})

        backend = Backend(); nodes = ("owner", "writer", "observer", "revoked")
        scenario = self.m.LegacyScenario({n: Client(backend, n) for n in nodes}, self.m.Evidence(), 20)
        ticks = iter(range(1000))
        def stop_owner(): backend.stopped.add("owner")
        def restart_writer(_gid):
            backend.stopped.add("observer"); backend.stopped.add("writer"); backend.stopped.remove("writer")
        with mock.patch.object(self.m.time, "monotonic", side_effect=lambda: float(next(ticks))), \
             mock.patch.object(self.m.time, "sleep"):
            scenario.run(*nodes, stop_owner, restart_writer)
        self.assertIn("owner", backend.stopped)
        self.assertIn("observer", backend.stopped)


if __name__ == "__main__": unittest.main()
