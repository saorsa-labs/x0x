#!/usr/bin/env python3
"""Offline controls for the ordinary shared-store VPS harness."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


def load_harness():
    tests = Path(__file__).parent
    sys.path.insert(0, str(tests))
    spec = importlib.util.spec_from_file_location("e2e_vps_kv", tests / "e2e_vps_kv.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeApi:
    def __init__(self) -> None:
        self.calls = []

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "PUT": return 200, {"ok": True}
        if method == "GET": return 404, {"ok": False}
        return 200, {"ok": True, "id": "store", "store_id": "digest"}


class FakeClock:
    def __init__(self): self.now = 0.0
    def monotonic(self): return self.now
    def sleep(self, seconds): self.now += seconds


class FakeWorld:
    """In-memory group model encoding named_groups.rs MemberJoined rules: only the
    invite's inviter, while online and Admin, turns a join into a roster entry."""

    def __init__(self, nodes):
        self.nodes, self.online = nodes, set(nodes)
        self.groups, self.invites, self.kv, self.timeline = {}, {}, {}, []

    def client(self, node): return FakeNodeApi(self, node)
    def aid(self, node): return hashlib.sha256(node.encode()).hexdigest()

    def request(self, node, method, path, body):
        if node not in self.online: raise ConnectionError(f"{node} offline")
        group = self.groups.get(path.split("/")[2]) if path.startswith("/groups/") else None
        role = group["members"].get(self.aid(node)) if group else None
        writer_role = next((g["members"].get(self.aid("writer")) for g in self.groups.values()
                            if g["preset"] == "public_open"), None)
        self.timeline.append((node, method, path, writer_role))
        if path == "/agent": return 200, {"agent_id": self.aid(node)}
        if method == "POST" and path == "/groups":
            gid = f"g{len(self.groups) + 1}"
            self.groups[gid] = {"preset": body["preset"], "members": {self.aid(node): "admin"}}
            return 200, {"ok": True, "group_id": gid}
        if method == "POST" and path == "/groups/join":
            inviter, gid = self.invites[body["invite"]]
            members = self.groups[gid]["members"]
            if inviter in self.online and members.get(self.aid(inviter)) == "admin":
                members[self.aid(node)] = "member"
            return 200, {"ok": True, "group_id": gid}
        gid = path.split("/")[2] if group else None
        if method == "POST" and path.endswith("/invite"):
            if role != "admin": return 403, {"ok": False}
            link = f"x0x://invite/{len(self.invites)}"
            self.invites[link] = (node, gid)
            return 200, {"ok": True, "invite_link": link}
        if method == "GET" and path.endswith("/members"):
            return 200, {"members": [{"agent_id": a, "role": r} for a, r in group["members"].items()]}
        if method == "PATCH" and path.endswith("/role"):
            if role != "admin": return 403, {"ok": False}
            group["members"][path.split("/")[4]] = body["role"]
            return 200, {"ok": True, "role": body["role"]}
        if method == "DELETE" and path.startswith("/groups/"):
            group["members"].pop(path.split("/")[4], None)
            return 200, {"ok": True}
        if method == "POST" and path.endswith("/stores"):
            if role is None: return 403, {"ok": False}
            return 200, {"ok": True, "id": f"{gid}-{body['name']}", "store_id": f"d-{gid}-{body['name']}"}
        _, _, sid, key = path.split("/")
        store_group = self.groups[sid.split("-")[0]]
        if method == "GET":
            value = self.kv.get((sid, key))
            return (200, {"value": value}) if value else (404, {"error": "key not found"})
        store_role = store_group["members"].get(self.aid(node))
        if store_role is None or (store_group["preset"] == "public_announce" and store_role != "admin"):
            return 403, {"ok": False}
        if method == "DELETE": self.kv.pop((sid, key), None)
        else: self.kv[(sid, key)] = body["value"]
        return 200, {"ok": True}


class FakeNodeApi:
    def __init__(self, world, node): self.world, self.node = world, node
    def request(self, method, path, body=None): return self.world.request(self.node, method, path, body)
    def agent_id(self): return self.world.aid(self.node)


class OnlineInviterOrderingTests(unittest.TestCase):
    """Decision B: a separate online Admin (the former outsider) mints the late
    invite; the writer stays a plain Member and is the only history source."""
    NODES = ("owner", "writer", "late", "outsider", "revoked")

    @classmethod
    def setUpClass(cls): cls.kv = load_harness()

    def run_scenario(self, revert=None):
        world = FakeWorld(self.NODES)
        log = world.timeline
        evidence = self.kv.Evidence()
        scenario = self.kv.Scenario({node: world.client(node) for node in self.NODES}, evidence)
        polls = []
        real_poll, real_invite, real_promote = self.kv.poll, scenario.invite, scenario.promote_admin
        real_check, real_record_poll = evidence.check, evidence.record_poll
        def check(label, condition, **facts):
            log.append(("@check", label)); real_check(label, condition, **facts)
        def record_poll(facts, **context):
            log.append(("@poll", facts["label"], context.get("node"), facts["outcome"]))
            real_record_poll(facts, **context)
        def spy_poll(label, timeout, *args):
            polls.append((label, timeout))
            return real_poll(label, timeout, *args)
        def invite(owner, member, gid):
            if revert == "owner_minted" and member == "late": owner = "owner"
            return real_invite(owner, member, gid)
        def promote_admin(owner, member, gid):
            return real_promote(owner, "writer" if revert == "writer_promoted" else member, gid)
        def stop_owner():
            log.append(("@stop_owner",)); world.online.discard("owner")
        def stop_admin():
            log.append(("@stop_admin",))
            if revert != "history_before_stop_admin": world.online.discard("outsider")
        def offline(node): return node not in world.online
        def restart_writer(gid):
            log.append(("@restart_writer",))
            active = self.kv.active_provider_ids(*world.request("writer", "GET", f"/groups/{gid}/members", None))
            evidence.check("eligible retained providers established",
                           active == {world.aid(n) for n in ("owner", "writer", "late", "outsider")})
            evidence.check("owner and admin offline before writer restart", offline("owner") and offline("outsider"))
        clock = FakeClock()
        error = None
        with mock.patch.object(self.kv, "poll", spy_poll), mock.patch.object(scenario, "invite", invite), \
             mock.patch.object(scenario, "promote_admin", promote_admin), \
             mock.patch.object(evidence, "check", check), mock.patch.object(evidence, "record_poll", record_poll), \
             mock.patch.object(self.kv.time, "monotonic", clock.monotonic), \
             mock.patch.object(self.kv.time, "sleep", clock.sleep):
            try:
                scenario.run(*self.NODES, stop_owner, restart_writer, stop_admin=stop_admin, offline=offline)
            except AssertionError as caught:
                error = caught
        return world, evidence, polls, error

    @staticmethod
    def first(log, predicate):
        return next(i for i, entry in enumerate(log) if predicate(entry))

    def ordering(self, log):
        f = lambda pred: self.first(log, pred)
        return [
            ("outsider negatives", f(lambda e: e == ("@check", "outsider mutation refused"))),
            ("revocation negatives", f(lambda e: e == ("@check", "revoked key absent before barrier"))),
            ("outsider join", f(lambda e: e[:3] == ("outsider", "POST", "/groups/join"))),
            ("promote outsider", f(lambda e: e == ("@check", "owner promotes outsider to admin"))),
            ("promotion on writer", f(lambda e: e[:3] == ("@poll", "outsider admin role on writer", "writer"))),
            ("admin invite", f(lambda e: e[:2] == ("outsider", "POST") and e[2].endswith("/invite"))),
            ("stop_owner", f(lambda e: e == ("@stop_owner",))),
            ("late join", f(lambda e: e[:3] == ("late", "POST", "/groups/join"))),
            ("writer roster poll", f(lambda e: e == ("@poll", "late roster on owner", "writer", "accepted"))),
            ("stop_admin", f(lambda e: e == ("@stop_admin",))),
            ("offline check", f(lambda e: e == ("@check", "owner and admin offline before late history"))),
            ("first late history read", f(lambda e: e[0] == "late" and "/stores" in e[2])),
            ("restart", f(lambda e: e == ("@restart_writer",))),
        ]

    def test_decision_b_ordering_is_enforced(self):
        world, _evidence, _polls, error = self.run_scenario()
        self.assertIsNone(error)
        steps = self.ordering(world.timeline)
        for (before, i), (after, j) in zip(steps, steps[1:]):
            self.assertLess(i, j, f"{before} must precede {after}")

    def test_writer_is_never_promoted_and_outsider_mints_late_invite(self):
        world, evidence, _polls, error = self.run_scenario()
        self.assertIsNone(error)
        self.assertNotIn("owner promotes writer to admin", [a["label"] for a in evidence.assertions])
        writer_roles = [e[3] for e in world.timeline if not e[0].startswith("@") and e[3] is not None]
        self.assertTrue(writer_roles)
        self.assertEqual({"member"}, set(writer_roles))
        invites = [e for e in world.timeline if len(e) > 2 and e[1] == "POST" and e[2].endswith("/invite")]
        self.assertEqual("outsider", invites[-1][0])
        self.assertEqual(("outsider", "g1"), world.invites[max(world.invites)])

    def test_restart_expects_outsider_provider_and_all_polls_keep_timeout(self):
        _world, evidence, polls, error = self.run_scenario()
        self.assertIsNone(error)
        labels = [a["label"] for a in evidence.assertions if a["passed"]]
        self.assertIn("eligible retained providers established", labels)
        self.assertIn("owner and admin offline before writer restart", labels)
        self.assertTrue(polls)
        self.assertTrue(all(timeout == 120 for _label, timeout in polls))

    def test_revert_history_read_before_stop_admin_fails(self):
        _world, _evidence, _polls, error = self.run_scenario("history_before_stop_admin")
        self.assertIsNotNone(error)
        self.assertIn("owner and admin offline before late history", str(error))

    def test_revert_owner_minted_late_invite_times_out_on_writer_roster(self):
        _world, evidence, _polls, error = self.run_scenario("owner_minted")
        self.assertIsNotNone(error)
        self.assertIn("late roster on owner did not converge in 120s", str(error))
        last = evidence.polls[-1]
        self.assertEqual(("writer", "timeout"), (last["node"], last["outcome"]))

    def test_revert_writer_promoted_fails(self):
        _world, _evidence, _polls, error = self.run_scenario("writer_promoted")
        self.assertIsNotNone(error)

class KvHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.kv = load_harness()

    def test_restart_capability_is_required_before_token_or_tunnel_access(self):
        argv = ["e2e_vps_kv.py", "--network", "test", "--tokens-file", "/not/read",
                "--report", "/not/written"]
        with mock.patch.object(sys, "argv", argv), self.assertRaises(SystemExit) as raised:
            self.kv.main()
        self.assertEqual(2, raised.exception.code)

    def test_service_command_is_fixed_to_testnet_unit(self):
        completed = subprocess.CompletedProcess([], 0)
        with mock.patch.object(self.kv.subprocess, "run", return_value=completed) as run:
            self.assertTrue(self.kv.service("192.0.2.1", "restart"))
        self.assertEqual(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "root@192.0.2.1", "systemctl", "restart", "x0xd-testnet.service"],
            run.call_args.args[0],
        )
        with self.assertRaises(ValueError): self.kv.service("192.0.2.1", "enable")

    def test_is_active_transport_failure_is_not_inactive(self):
        completed = subprocess.CompletedProcess([], 255)
        with mock.patch.object(self.kv.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "rc=255"):
                self.kv.service("192.0.2.1", "is-active")

    def test_store_helpers_encode_values_and_require_observed_absence(self):
        api = FakeApi(); evidence = self.kv.Evidence()
        scenario = self.kv.Scenario({"writer": api}, evidence, timeout=0.1)
        status, _ = scenario.put("writer", "topic/id", "page key", "hello")
        self.assertEqual(200, status)
        self.assertEqual("aGVsbG8=", api.calls[-1][2]["value"])
        self.assertIn("topic%2Fid/page%20key", api.calls[-1][1])
        scenario.await_absent("writer", "topic/id", "removed")
        self.assertTrue(evidence.assertions[-1]["passed"])

    def test_poll_fails_closed_with_last_observation(self):
        with mock.patch.object(self.kv.time, "sleep", return_value=None):
            with self.assertRaisesRegex(AssertionError, "last_status=404"):
                self.kv.poll("missing", 0.001, lambda: (404, {}), lambda value: value[0] == 200)

    def test_poll_tolerates_transient_probe_errors(self):
        observations = iter([ConnectionError("restart"), (200, {"ok": True})])
        def probe():
            value = next(observations)
            if isinstance(value, Exception): raise value
            return value
        with mock.patch.object(self.kv.time, "sleep", return_value=None):
            self.assertEqual((200, {"ok": True}), self.kv.poll("health", 1, probe, lambda value: value[0] == 200))

    def test_timeout_receipt_keeps_store_identity_status_and_bounded_timing(self):
        evidence = self.kv.Evidence()
        scenario = self.kv.Scenario({}, evidence, timeout=0.001)
        scenario.store_context["x0x/group/safe/kv/topic"] = ("group-safe", "web")
        with mock.patch.object(scenario, "read_value", return_value=(404, None)), \
             mock.patch.object(self.kv.time, "sleep", return_value=None), \
             self.assertRaises(AssertionError):
            scenario.await_value("owner", "x0x/group/safe/kv/topic", "writer-page", "expected")
        receipt = evidence.polls[-1]
        self.assertEqual("timeout", receipt["outcome"])
        self.assertEqual(404, receipt["last_status"])
        self.assertEqual("web", receipt["app"])
        self.assertEqual("group-safe", receipt["group_id"])
        self.assertEqual("x0x/group/safe/kv/topic", receipt["store_topic"])
        self.assertGreater(receipt["probe_count"], 0)
        self.assertIsNotNone(receipt["first_sample_utc"])
        self.assertIsNotNone(receipt["last_sample_utc"])
        self.assertEqual(receipt, evidence.report()["polls"][-1])

    def test_real_read_path_distinguishes_closed_404_classes(self):
        class MissingApi:
            def __init__(self, error): self.error = error
            def request(self, method, path, body=None): return 404, {"error": self.error}
        for error, expected in (("store not found", "store_not_found"),
                                ("key not found", "key_not_found")):
            with self.subTest(error=error):
                evidence = self.kv.Evidence()
                scenario = self.kv.Scenario({"reader": MissingApi(error)}, evidence, timeout=0.001)
                scenario.store_context["topic"] = ("group", "web")
                with mock.patch.object(self.kv.time, "sleep", return_value=None), \
                     self.assertRaises(AssertionError):
                    scenario.await_value("reader", "topic", "writer-page", "expected")
                self.assertEqual(expected, evidence.polls[-1]["response_class"])
                self.assertEqual(404, evidence.polls[-1]["last_status"])

    def test_success_receipt_keeps_matching_hashes_without_value(self):
        evidence = self.kv.Evidence()
        scenario = self.kv.Scenario({}, evidence, timeout=1)
        scenario.store_context["topic"] = ("group", "wiki")
        with mock.patch.object(scenario, "read_value", return_value=(200, "sensitive-value")):
            scenario.await_value("writer", "topic", "owner-page", "sensitive-value")
        receipt = evidence.polls[-1]
        self.assertEqual("accepted", receipt["outcome"])
        self.assertEqual(receipt["expected_value_sha256"], receipt["observed_value_sha256"])
        self.assertNotIn("sensitive-value", json.dumps(evidence.polls))

    def test_unsafe_server_fields_and_tokens_never_enter_receipt(self):
        evidence = self.kv.Evidence()
        secret = "Bearer token-secret-value"
        evidence.record_store("owner", secret, "web", {"id": secret, "store_id": secret})
        evidence.assertions.append({"label": "harness", "passed": False,
                                    "error_class": type(RuntimeError(secret)).__name__})
        serialized = json.dumps(evidence.report())
        self.assertNotIn(secret, serialized)
        self.assertIsNone(evidence.stores[0]["topic"])
        self.assertIsNone(evidence.stores[0]["store_id"])
        class SecretErrorApi:
            def request(self, method, path, body=None): return 404, {"error": secret}
        scenario = self.kv.Scenario({"reader": SecretErrorApi()}, evidence, timeout=0.001)
        with mock.patch.object(self.kv.time, "sleep", return_value=None), \
             self.assertRaises(AssertionError):
            scenario.await_value("reader", "topic", "key", "expected")
        serialized = json.dumps(evidence.report())
        self.assertNotIn(secret, serialized)
        self.assertEqual("http_error", evidence.polls[-1]["response_class"])

    def test_custody_records_restore_before_partial_stop_or_restart_failure(self):
        calls = []
        def partial(_ip, verb):
            calls.append(verb)
            if verb == "is-active": return True
            raise RuntimeError("transport lost")
        custody = self.kv.ServiceCustody({"a": "192.0.2.1"})
        with mock.patch.object(self.kv, "service", side_effect=partial):
            with self.assertRaises(RuntimeError): custody.stop("a")
        self.assertEqual({"a"}, custody.restore_required)
        custody = self.kv.ServiceCustody({"a": "192.0.2.1"})
        with mock.patch.object(self.kv, "service", side_effect=partial):
            with self.assertRaises(RuntimeError): custody.restart("a")
        self.assertEqual({"a"}, custody.restore_required)

    def test_duplicate_actor_labels_fail_before_tunnels(self):
        argv = ["e2e_vps_kv.py", "--network", "test", "--tokens-file", "/not/read",
                "--report", "/not/written", "--allow-service-restart", "--nodes",
                "nyc", "nyc", "late", "outsider", "revoked"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.kv, "load_tokens", return_value={}), \
             mock.patch.object(self.kv, "start_ssh_tunnel") as tunnel, self.assertRaises(SystemExit):
            self.kv.main()
        tunnel.assert_not_called()

    def test_reporting_failure_does_not_skip_all_tunnel_cleanup(self):
        nodes = ["a", "b", "c", "d", "e"]
        tokens = {node: (f"192.0.2.{i}", node) for i, node in enumerate(nodes, 1)}
        tunnels = [mock.Mock(local_port=24000 + i) for i in range(5)]
        argv = ["e2e_vps_kv.py", "--network", "test", "--tokens-file", "tokens",
                "--report", "/cannot/write", "--allow-service-restart", "--nodes", *nodes]
        class MainApi:
            count = 0
            def __init__(self, _base, _token): self.ident = chr(97 + MainApi.count) * 64; MainApi.count += 1
            def agent_id(self): return self.ident
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.kv, "load_tokens", return_value=tokens), \
             mock.patch.object(self.kv, "start_ssh_tunnel", side_effect=tunnels), \
             mock.patch.object(self.kv, "stop_ssh_tunnel", side_effect=[RuntimeError("one"), None, None, None, None]) as stop, \
             mock.patch.object(self.kv, "Api", MainApi), mock.patch.object(self.kv.Scenario, "run"), \
             mock.patch("builtins.open", side_effect=OSError("report")):
            self.assertEqual(1, self.kv.main())
        self.assertEqual(5, stop.call_count)

    def test_second_tunnel_failure_cleans_first_without_unbound_health_callback(self):
        nodes = ["a", "b", "c", "d", "e"]
        tokens = {node: (f"192.0.2.{i}", node) for i, node in enumerate(nodes, 1)}
        tunnel = mock.Mock(local_port=24000)
        argv = ["e2e_vps_kv.py", "--network", "test", "--tokens-file", "tokens",
                "--report", "report.json", "--allow-service-restart", "--nodes", *nodes]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.kv, "load_tokens", return_value=tokens), \
             mock.patch.object(self.kv, "start_ssh_tunnel", side_effect=[tunnel, RuntimeError("second")]), \
             mock.patch.object(self.kv, "stop_ssh_tunnel") as stop, \
             mock.patch("builtins.open", mock.mock_open()):
            self.assertEqual(1, self.kv.main())
        stop.assert_called_once_with(tunnel)

    def test_agent_id_failure_cleans_every_owned_tunnel(self):
        nodes = ["a", "b", "c", "d", "e"]
        tokens = {node: (f"192.0.2.{i}", node) for i, node in enumerate(nodes, 1)}
        tunnels = [mock.Mock(local_port=24100 + i) for i in range(5)]
        argv = ["e2e_vps_kv.py", "--network", "test", "--tokens-file", "tokens",
                "--report", "report.json", "--allow-service-restart", "--nodes", *nodes]
        class BadIdentityApi:
            def __init__(self, _base, _token): pass
            def agent_id(self): raise RuntimeError("bad identity")
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.kv, "load_tokens", return_value=tokens), \
             mock.patch.object(self.kv, "start_ssh_tunnel", side_effect=tunnels), \
             mock.patch.object(self.kv, "stop_ssh_tunnel") as stop, mock.patch.object(self.kv, "Api", BadIdentityApi), \
             mock.patch("builtins.open", mock.mock_open()):
            self.assertEqual(1, self.kv.main())
        self.assertEqual(5, stop.call_count)

    def test_restart_provider_inventory_rejects_peer_assisted_false_positive(self):
        expected = {"owner", "writer", "late"}
        exact = {"members": [{"agent_id": item} for item in expected]}
        assisted = {"members": [*exact["members"], {"agent_id": "unexpected-holder"}]}
        self.assertEqual(expected, self.kv.active_provider_ids(200, exact))
        self.assertNotEqual(expected, self.kv.active_provider_ids(200, assisted))


if __name__ == "__main__": unittest.main()
