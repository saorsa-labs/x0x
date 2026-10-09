#!/usr/bin/env python3
"""Offline controls for private/Home VPS acceptance."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


HARNESS = Path(__file__).parent / "e2e_vps_private_kv.py"
IDS = {"owner": "1" * 64, "writer": "2" * 64, "late": "3" * 64, "admin": "5" * 64, "revoked": "4" * 64}


def load_harness():
    tests = Path(__file__).parent
    sys.path.insert(0, str(tests))
    spec = importlib.util.spec_from_file_location("e2e_vps_private_kv", HARNESS)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_mutant(name: str, *edits: tuple[str, str]):
    """Load the harness with textual reverts applied; each edit must match exactly once."""
    source = HARNESS.read_text()
    for old, new in edits:
        if source.count(old) != 1:
            raise AssertionError(f"mutation anchor not unique: {old!r}")
        source = source.replace(old, new)
    module = types.ModuleType(name)
    module.__file__ = str(HARNESS)
    sys.modules[name] = module
    exec(compile(source, str(HARNESS), "exec"), module.__dict__)
    return module


def trace_scenario(h, label: str) -> tuple[list[tuple], set[str]]:
    """Run one scenario with every network effect replaced by an ordered event log."""
    events: list[tuple] = []
    stopped: set[str] = set()
    restart_expected: set[str] = set()

    class TraceApi:
        def __init__(self, node):
            self.node = node

        def agent_id(self):
            return IDS[self.node]

        def request(self, method, path, body=None):
            if self.node in stopped:
                raise AssertionError(f"{self.node} API used after stop")
            if method == "DELETE" and "/members/" in path:
                events.append(("remove", self.node))
            if method == "GET" and path == "/agent/user-id":
                events.append(("identity", self.node))
                return 200, {"ok": True, "user_id": "f" * 64}
            if method == "GET" and path == "/groups/gid/members":
                events.append(("roster-read", self.node))
                return 200, {"members": [{"agent_id": IDS["writer"], "role": "member"}]}
            return 200, {"ok": True}

    clients = {node: TraceApi(node) for node in IDS}
    scenario = h.Scenario(clients, h.Evidence())
    scenario.ok = mock.Mock(return_value={"group_id": "gid"})
    scenario.home = mock.Mock(return_value=("gid", "f" * 64))
    scenario.join_private = mock.Mock(side_effect=lambda inviter, member, *_a: events.append(("join", inviter, member)))
    scenario.join_home = mock.Mock(side_effect=lambda inviter, member, *_a: events.append(("join", inviter, member)))
    scenario.invite = mock.Mock(side_effect=lambda minter, member, _gid: (
        events.append(("mint", minter, member)), "x0x://invite/i")[1])
    scenario.home_invite = mock.Mock(side_effect=lambda minter, member, *_a: (
        events.append(("mint", minter, member)), "x0x://invite/h")[1])
    scenario.promote_admin = mock.Mock(side_effect=lambda by, member, _gid: events.append(("promote", by, member)))
    scenario.await_admin = mock.Mock(side_effect=lambda observer, member, *_a: events.append(("admin-seen", observer, member)))
    scenario.open_store = mock.Mock(side_effect=lambda node, _gid, app: (
        events.append(("history", node)) if node == "late" else None, {"id": f"sid-{app}"})[1])
    scenario.put = mock.Mock(side_effect=lambda node, *_a: (403, {}) if node == "revoked" else (200, {}))
    def await_value(node, sid, key, *_a, **_k):
        if node == "late":
            events.append(("history", node))
        elif node == "writer" and key.endswith("-owner"):
            events.append(("owner-key", node, sid))
    scenario.await_value = mock.Mock(side_effect=await_value)
    scenario.await_absent = mock.Mock(side_effect=lambda node, *_a: events.append(("history", node)) if node == "late" else None)
    scenario.prove_denied_did_not_converge = mock.Mock()

    def stop(node):
        events.append(("stop", node)); stopped.add(node)

    def restart_writer(_gid, expected):
        events.append(("restart",)); restart_expected.update(expected)

    run = scenario.run_private if label == "private_secure" else scenario.run_home
    with mock.patch.object(h, "poll", return_value=(403, {"ok": False})):
        run("owner", "writer", "late", "admin", "revoked", lambda: stop("owner"), lambda: stop("admin"),
            lambda node: node in stopped, restart_writer)
    return events, restart_expected


def assert_decision_b(test: unittest.TestCase, label: str, events: list[tuple], expected: set[str]) -> None:
    def first(event):
        test.assertIn(event, events, f"{label}: missing {event}")
        return events.index(event)
    chain = [("remove", "owner"), ("join", "owner", "admin"), ("promote", "owner", "admin"),
             ("admin-seen", "writer", "admin"), ("mint", "admin", "late"), ("stop", "owner"),
             ("join", "writer", "late"), ("stop", "admin"), ("history", "late"), ("restart",)]
    positions = [first(event) for event in chain]
    test.assertEqual(sorted(positions), positions, f"{label}: out of order {list(zip(chain, positions))}")
    # R19: once the owner and Admin stop, the writer is the only history
    # source, so it must hold BOTH owner keys before the owner goes offline.
    for sid in ("sid-wiki", "sid-web"):
        test.assertLess(first(("owner-key", "writer", sid)), first(("stop", "owner")),
                        f"{label}: writer {sid} owner-key barrier must precede the offline step")
    test.assertNotIn(("promote", "owner", "writer"), events, "writer must stay a plain Member")
    test.assertEqual([("mint", "admin", "late")], [e for e in events if e[:1] == ("mint",) and e[2] == "late"])
    test.assertEqual(set(IDS[n] for n in ("owner", "writer", "late", "admin")), expected)
    if label == "home":
        test.assertLess(first(("identity", "admin")), first(("join", "owner", "admin")))
        # Writer-role check reads the owner's roster while the owner is still online.
        test.assertLess(first(("roster-read", "owner")), first(("stop", "owner")))


class FakeApi:
    def __init__(self, agent: str = "a" * 64) -> None:
        self.agent = agent
        self.calls = []

    def agent_id(self):
        return self.agent

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        return 500, {"ok": False}


class PrivateKvHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h = load_harness()

    def test_scenario_and_restart_capabilities_are_required_before_tokens(self):
        base = ["e2e_vps_private_kv.py", "--network", "test", "--tokens-file", "/not/read",
                "--report", "/not/written"]
        with mock.patch.object(sys, "argv", base), mock.patch.object(self.h, "load_tokens") as load, \
                self.assertRaises(SystemExit):
            self.h.main()
        load.assert_not_called()
        with mock.patch.object(sys, "argv", base + ["--scenario", "home"]), \
                mock.patch.object(self.h, "load_tokens") as load, self.assertRaises(SystemExit):
            self.h.main()
        load.assert_not_called()

    def test_home_uses_real_seat_and_pinned_join_shapes(self):
        owner, member = FakeApi("1" * 64), FakeApi("2" * 64)
        owner.request = mock.Mock(side_effect=[
            (200, {"ok": True, "state": "local", "group_id": "home-id"}),
            (200, {"ok": True, "group_id": "home-id", "owner_user_id": "f" * 64,
                   "intended_joiner": "2" * 64, "seated": False,
                   "invite": "x0x://invite/real"}),
            (200, {"members": [{"agent_id": "2" * 64}]})])
        member.request = mock.Mock(side_effect=[
            (200, {"ok": True, "group_id": "home-id", "join_state": "pending_authority_commit"}),
            (200, {"ok": True, "group_id": "home-id", "membership_state": "active"}),
        ])
        scenario = self.h.Scenario({"owner": owner, "member": member}, self.h.Evidence())
        invite = scenario.home_invite("owner", "member", "home-id", "f" * 64)
        with mock.patch.object(self.h, "poll", return_value=(200, {"members": [{"agent_id": "2" * 64}]})):
            scenario.join_home("owner", "member", "home-id", "f" * 64, invite)
        self.assertEqual(("GET", "/home"), owner.request.call_args_list[0].args)
        self.assertEqual(("POST", "/home/seat", {"agent_id": "2" * 64}), owner.request.call_args_list[1].args)
        self.assertEqual({"invite": "x0x://invite/real", "mode": "home",
                          "expected_owner_user_id": "f" * 64}, member.request.call_args_list[0].args[2])

    def _fake_clock(self):
        clock = [100.0]
        return (mock.patch.object(self.h.time, "monotonic", side_effect=lambda: clock[0]),
                mock.patch.object(self.h.time, "sleep",
                                  side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)))

    def test_home_seat_waits_until_the_minter_serves_the_canonical_home(self):
        # #824: a device that was just seated (an admin) reaches `local` with the
        # canonical gid only after its own join completes. Seating before then
        # is refused by the product, so the harness waits for exactly that.
        owner, member = FakeApi("1" * 64), FakeApi("2" * 64)
        owner.request = mock.Mock(side_effect=[
            (200, {"ok": True, "state": "elsewhere", "canonical_group_id": "home-id"}),
            (200, {"ok": True, "state": "local", "group_id": "home-id"}),
            (200, {"ok": True, "group_id": "home-id", "owner_user_id": "f" * 64,
                   "intended_joiner": "2" * 64, "seated": False, "invite": "x0x://invite/real"})])
        scenario = self.h.Scenario({"owner": owner, "member": member}, self.h.Evidence(), timeout=5)
        monotonic, sleep = self._fake_clock()
        with monotonic, sleep:
            scenario.home_invite("owner", "member", "home-id", "f" * 64)
        self.assertEqual(("POST", "/home/seat", {"agent_id": "2" * 64}), owner.request.call_args_list[2].args)
        self.assertTrue(all(item["passed"] for item in scenario.e.assertions))

    def test_home_seat_never_mints_from_a_device_serving_a_duplicate_home(self):
        # #824: a `local` Home with a DIFFERENT gid is the duplicate. The wait
        # must not accept it and must never reach `POST /home/seat`.
        owner, member = FakeApi("1" * 64), FakeApi("2" * 64)
        owner.request = mock.Mock(return_value=(200, {"ok": True, "state": "local", "group_id": "dup-id"}))
        scenario = self.h.Scenario({"owner": owner, "member": member}, self.h.Evidence(), timeout=3)
        monotonic, sleep = self._fake_clock()
        with monotonic, sleep, self.assertRaises(AssertionError):
            scenario.home_invite("owner", "member", "home-id", "f" * 64)
        self.assertNotIn("/home/seat", [call.args[1] for call in owner.request.call_args_list])

    def test_home_reader_polls_only_through_provisioning_pending(self):
        # #824: `provisioning_pending` is the one documented transient state.
        # The reader waits through it and then applies the unchanged checks.
        owner = FakeApi("1" * 64)
        owner.request = mock.Mock(side_effect=[
            (200, {"ok": True, "state": "provisioning_pending"}),
            (200, {"ok": True, "state": "local", "group_id": "home-id", "owner_user_id": "f" * 64}),
            (200, {"members": [{"agent_id": "1" * 64, "state": "active"}]})])
        scenario = self.h.Scenario({"owner": owner}, self.h.Evidence(), timeout=5)
        monotonic, sleep = self._fake_clock()
        with monotonic, sleep:
            gid, _ = scenario.home("owner")
        self.assertEqual("home-id", gid)
        self.assertEqual(("GET", "/home"), owner.request.call_args_list[1].args[:2])
        self.assertTrue(all(item["passed"] for item in scenario.e.assertions))

    def test_home_reader_does_not_wait_on_a_terminal_state(self):
        owner = FakeApi("1" * 64)
        owner.request = mock.Mock(return_value=(404, {"ok": False, "error": "no Home provisioned"}))
        status, _ = self.h.settled_home(owner, "owner", 5)
        self.assertEqual(404, status)
        self.assertEqual(1, owner.request.call_count)

    def test_private_join_waits_for_exact_local_group_after_owner_roster(self):
        owner, member = FakeApi("1" * 64), FakeApi("2" * 64)
        sealed: dict[str, str] = {}
        owner_reads = {"n": 0}
        local_reads = {"n": 0}

        def owner_request(method, path, body=None):
            if str(path).endswith("/secure/encrypt"):
                sealed["payload"] = body["payload_b64"]
                return 200, {"ok": True, "ciphertext_b64": "Y2lwaGVy", "secret_epoch": 2,
                             "secure_plane": "treekem"}
            owner_reads["n"] += 1
            if owner_reads["n"] == 1:
                return 200, {"members": []}
            return 200, {"members": [{"agent_id": "2" * 64}]}

        def member_request(method, path, body=None):
            if method == "POST" and path == "/groups/join":
                return 201, {"ok": True, "group_id": "private-id",
                             "join_state": "pending_authority_commit"}
            if str(path).endswith("/secure/decrypt"):
                return 200, {"ok": True, "payload_b64": sealed["payload"], "secret_epoch": 2,
                             "secure_plane": "treekem"}
            local_reads["n"] += 1
            if local_reads["n"] == 1:
                return 200, {"group_id": "private-id", "membership_state": "pending_authority_commit"}
            return 200, {"group_id": "private-id", "membership_state": "active"}

        owner.request = mock.Mock(side_effect=owner_request)
        member.request = mock.Mock(side_effect=member_request)
        scenario = self.h.Scenario({"owner": owner, "member": member}, self.h.Evidence(), timeout=2)
        clock = [100.0]
        with mock.patch.object(self.h.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(self.h.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            scenario.join_private("owner", "member", "private-id", "x0x://invite/private")
        self.assertEqual(("POST", "/groups/join", {"invite": "x0x://invite/private"}),
                         member.request.call_args_list[0].args)
        readiness = scenario.e.polls[-1]
        self.assertEqual("private_join_readiness", readiness["operation"])
        self.assertEqual("accepted", readiness["outcome"])
        self.assertEqual("active", readiness["local_membership_state"])
        self.assertEqual(2, readiness["probe_count"])
        self.assertTrue(readiness["epoch_key_installed"])
        self.assertEqual("decrypted", readiness["decrypt_class"])
        self.assertEqual(2, readiness["secret_epoch"])
        self.assertNotIn("Y2lwaGVy", json.dumps(readiness))

    def test_private_join_requires_local_readiness_when_owner_is_ready_first(self):
        owner, member = FakeApi("1" * 64), FakeApi("2" * 64)
        sealed: dict[str, str] = {}
        local_reads = {"n": 0}

        def owner_request(method, path, body=None):
            if str(path).endswith("/secure/encrypt"):
                sealed["payload"] = body["payload_b64"]
                return 200, {"ok": True, "ciphertext_b64": "Y2lwaGVy", "secret_epoch": 4,
                             "secure_plane": "treekem"}
            return 200, {"members": [{"agent_id": "2" * 64}]}

        def member_request(method, path, body=None):
            if method == "POST" and path == "/groups/join":
                return 201, {"ok": True, "group_id": "private-id",
                             "join_state": "pending_authority_commit"}
            if str(path).endswith("/secure/decrypt"):
                return 200, {"ok": True, "payload_b64": sealed["payload"], "secret_epoch": 4,
                             "secure_plane": "treekem"}
            local_reads["n"] += 1
            if local_reads["n"] == 1:
                return 200, {"group_id": "private-id", "membership_state": "pending_authority_commit"}
            return 200, {"group_id": "private-id", "membership_state": "active"}

        owner.request = mock.Mock(side_effect=owner_request)
        member.request = mock.Mock(side_effect=member_request)
        scenario = self.h.Scenario({"owner": owner, "member": member}, self.h.Evidence(), timeout=2)
        clock = [100.0]
        with mock.patch.object(self.h.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(self.h.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            scenario.join_private("owner", "member", "private-id", "x0x://invite/private")
        readiness = scenario.e.polls[-1]
        self.assertEqual("accepted", readiness["outcome"])
        self.assertEqual(2, readiness["probe_count"])
        self.assertEqual(2, readiness["local_probe_count"])
        self.assertEqual(["/groups/join", "/groups/private-id", "/groups/private-id",
                          "/groups/private-id/secure/decrypt"],
                         [call.args[1] for call in member.request.call_args_list])
        self.assertTrue(readiness["epoch_key_installed"])

    def test_private_join_readiness_rejects_active_roster_without_welcome_key(self):
        # #1214: roster + local active passed while the joiner had logged
        # "failed to fetch TreeKEM Welcome blob". That is not key readiness.
        owner, member = FakeApi("1" * 64), FakeApi("2" * 64)
        owner.request = mock.Mock(side_effect=lambda method, path, body=None: (
            (200, {"ok": True, "ciphertext_b64": "Y2lwaGVy", "secret_epoch": 3,
                   "secure_plane": "treekem"})
            if str(path).endswith("/secure/encrypt") else
            (200, {"members": [{"agent_id": "2" * 64}]})))
        member.request = mock.Mock(side_effect=lambda method, path, body=None: (
            (201, {"ok": True, "group_id": "private-id", "join_state": "pending_authority_commit"})
            if method == "POST" and path == "/groups/join" else
            (424, {"ok": False, "error": "TreeKEM group not loaded — restart or re-share required"})
            if str(path).endswith("/secure/decrypt") else
            (200, {"group_id": "private-id", "membership_state": "active"})
            if path == "/groups/private-id" else
            (200, {"last_join_outcome": {"outcome": "timed_out"}})))
        scenario = self.h.Scenario({"owner": owner, "member": member}, self.h.Evidence(), timeout=2)
        clock = [100.0]
        with mock.patch.object(self.h.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(self.h.time, "sleep",
                                  side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                self.assertRaisesRegex(AssertionError, "private join reaches owner and local readiness"):
            scenario.join_private("owner", "member", "private-id", "x0x://invite/private")
        readiness = scenario.e.polls[-1]
        self.assertEqual("timeout", readiness["outcome"])
        self.assertEqual("active", readiness["local_membership_state"])
        self.assertFalse(readiness["epoch_key_installed"])
        self.assertEqual("treekem_not_loaded", readiness["decrypt_class"])
        self.assertTrue(readiness["deadline_reached_before_acceptance"])
        self.assertNotIn("Y2lwaGVy", json.dumps(readiness))

    def test_private_join_rejects_active_local_wrong_group(self):
        owner, member = FakeApi("1" * 64), FakeApi("2" * 64)
        owner.request = mock.Mock(return_value=(200, {"members": [{"agent_id": "2" * 64}]}))
        member.request = mock.Mock(side_effect=lambda method, path, body=None: (
            (201, {"ok": True, "group_id": "private-id", "join_state": "pending_authority_commit"})
            if method == "POST" else
            (200, {"group_id": "other-group", "membership_state": "active"})
            if path == "/groups/private-id" else
            (200, {"last_join_outcome": {"outcome": "timed_out"}})))
        scenario = self.h.Scenario({"owner": owner, "member": member}, self.h.Evidence(), timeout=1)
        clock = [100.0]
        with mock.patch.object(self.h.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(self.h.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                self.assertRaisesRegex(AssertionError, "private join reaches owner and local readiness"):
            scenario.join_private("owner", "member", "private-id", "x0x://invite/private")
        readiness = scenario.e.polls[-1]
        self.assertEqual("timeout", readiness["outcome"])
        self.assertEqual("active", readiness["local_membership_state"])
        self.assertEqual("other-group", readiness["local_observed_group_id"])
        self.assertTrue(readiness["deadline_reached_before_acceptance"])

    def test_private_join_rejects_local_activation_after_deadline(self):
        owner, member = FakeApi("1" * 64), FakeApi("2" * 64)
        clock = [100.0]
        owner.request = mock.Mock(return_value=(200, {"members": [{"agent_id": "2" * 64}]}))

        def member_request(method, path, body=None):
            if method == "POST":
                return 201, {"ok": True, "group_id": "private-id", "join_state": "pending_authority_commit"}
            if path == "/groups/private-id":
                clock[0] = 103.0
                return 200, {"group_id": "private-id", "membership_state": "active"}
            return 200, {"last_join_outcome": {"outcome": "timed_out"}}

        member.request = mock.Mock(side_effect=member_request)
        scenario = self.h.Scenario({"owner": owner, "member": member}, self.h.Evidence(), timeout=2)
        with mock.patch.object(self.h.time, "monotonic", side_effect=lambda: clock[0]), \
                self.assertRaisesRegex(AssertionError, "private join reaches owner and local readiness"):
            scenario.join_private("owner", "member", "private-id", "x0x://invite/private")
        readiness = scenario.e.polls[-1]
        self.assertEqual("timeout", readiness["outcome"])
        self.assertTrue(readiness["deadline_reached_before_acceptance"])
        self.assertEqual(1, readiness["local_probe_count"])

    def test_private_join_never_ready_fails_within_single_deadline_and_receipt(self):
        owner, member = FakeApi("1" * 64), FakeApi("2" * 64)
        owner.request = mock.Mock(return_value=(200, {"members": [{"agent_id": "2" * 64}]}))
        member.request = mock.Mock(side_effect=lambda method, path, body=None: (
            (201, {"ok": True, "group_id": "private-id", "join_state": "pending_authority_commit"})
            if method == "POST" else
            (200, {"group_id": "private-id", "membership_state": "pending_authority_commit"})
            if path == "/groups/private-id" else
            (200, {"last_join_outcome": {"outcome": "timed_out"}})))
        scenario = self.h.Scenario({"owner": owner, "member": member}, self.h.Evidence(), timeout=2)
        clock = [100.0]
        with mock.patch.object(self.h.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(self.h.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                self.assertRaisesRegex(AssertionError, "private join reaches owner and local readiness"):
            scenario.join_private("owner", "member", "private-id", "x0x://invite/private")
        readiness = scenario.e.polls[-1]
        self.assertEqual("timeout", readiness["outcome"])
        self.assertTrue(readiness["deadline_reached_before_acceptance"])
        self.assertEqual("pending_authority_commit", readiness["local_membership_state"])
        self.assertEqual("timed_out", readiness["terminal_join_outcome"])
        self.assertLessEqual(readiness["elapsed_seconds"], 2)

    def test_private_join_rejects_response_after_deadline_before_local_probe(self):
        owner, member = FakeApi("1" * 64), FakeApi("2" * 64)
        clock = [100.0]
        owner.request = mock.Mock(side_effect=lambda method, path, body=None: (
            clock.__setitem__(0, 103.0) or (200, {"members": [{"agent_id": "2" * 64}]})))
        member.request = mock.Mock(side_effect=[
            (201, {"ok": True, "group_id": "private-id", "join_state": "pending_authority_commit"}),
            (200, {"group_id": "private-id", "membership_state": "active"}),
            (200, {"last_join_outcome": {"outcome": "timed_out"}}),
        ])
        scenario = self.h.Scenario({"owner": owner, "member": member}, self.h.Evidence(), timeout=2)
        with mock.patch.object(self.h.time, "monotonic", side_effect=lambda: clock[0]), \
                self.assertRaisesRegex(AssertionError, "private join reaches owner and local readiness"):
            scenario.join_private("owner", "member", "private-id", "x0x://invite/private")
        readiness = scenario.e.polls[-1]
        self.assertEqual("timeout", readiness["outcome"])
        self.assertEqual(0, readiness["local_probe_count"])
        self.assertTrue(readiness["deadline_reached_before_acceptance"])

    def test_missing_or_remote_home_fails_prerequisite(self):
        api = FakeApi()
        for status, body in [(404, {"error": "no Home"}),
                             (200, {"ok": True, "state": "elsewhere", "owner_user_id": "f" * 64})]:
            api.request = mock.Mock(return_value=(status, body))
            scenario = self.h.Scenario({"owner": api}, self.h.Evidence())
            with self.assertRaises(AssertionError):
                scenario.home("owner")

    def test_home_preflight_requires_owner_only_fixture_and_matching_owner_identity(self):
        api = FakeApi("1" * 64)
        api.request = mock.Mock(side_effect=[
            (200, {"ok": True, "state": "local", "group_id": "home", "owner_user_id": "f" * 64}),
            (200, {"members": [{"agent_id": "1" * 64}, {"agent_id": "2" * 64}]})])
        scenario = self.h.Scenario({"owner": api}, self.h.Evidence())
        with self.assertRaisesRegex(AssertionError, "owner-only"):
            scenario.home("owner")
        member = FakeApi("2" * 64)
        member.request = mock.Mock(return_value=(200, {"ok": True, "user_id": "e" * 64}))
        scenario = self.h.Scenario({"member": member}, self.h.Evidence())
        with self.assertRaisesRegex(AssertionError, "owner-certified"):
            scenario.require_home_identity("member", "f" * 64)

    def test_private_group_creation_is_explicit(self):
        scenario = self.h.Scenario({}, self.h.Evidence())
        scenario.ok = mock.Mock(return_value={"group_id": "gid"})
        scenario.join_private = mock.Mock()
        scenario.invite = mock.Mock(return_value="x0x://invite/late")
        scenario.exercise = mock.Mock()
        scenario.run_private("owner", "writer", "late", "admin", "revoked", mock.Mock(), mock.Mock(),
                             mock.Mock(), mock.Mock())
        scenario.ok.assert_called_once_with("owner", "POST", "/groups", mock.ANY)
        self.assertEqual("private_secure", scenario.ok.call_args.args[3]["preset"])

    def test_home_seating_refusal_is_not_skipped(self):
        owner, member = FakeApi("1" * 64), FakeApi("2" * 64)
        owner.request = mock.Mock(return_value=(409, {"ok": False, "reason": "elsewhere"}))
        scenario = self.h.Scenario({"owner": owner, "member": member}, self.h.Evidence())
        with self.assertRaises(AssertionError):
            scenario.home_invite("owner", "member", "home-id", "f" * 64)

    def test_exercise_never_calls_stopped_owner_or_admin(self):
        class StopAwareApi(FakeApi):
            def agent_id(self):
                if self.agent in stopped:
                    raise AssertionError("stopped identity used after stop")
                return super().agent_id()

            def request(self, method, path, body=None):
                if self.agent in stopped:
                    raise AssertionError("stopped API used after stop")
                return 200, {"ok": True}
        for label in ("private_secure", "home"):
            stopped: set[str] = set()
            clients = {"owner": StopAwareApi("1" * 64), "writer": StopAwareApi("2" * 64),
                       "late": StopAwareApi("3" * 64), "admin": StopAwareApi("5" * 64),
                       "revoked": StopAwareApi("4" * 64)}
            scenario = self.h.Scenario(clients, self.h.Evidence())
            scenario.open_store = mock.Mock(side_effect=lambda _node, _gid, app: {"id": f"sid-{app}"})
            scenario.put = mock.Mock(side_effect=lambda node, *_args: (
                (403, {"ok": False}) if node == "revoked" else (200, {"ok": True})))
            scenario.await_value = mock.Mock()
            scenario.await_absent = mock.Mock()
            scenario.prove_denied_did_not_converge = mock.Mock()
            scenario.promote_admin = mock.Mock()
            scenario.await_admin = mock.Mock()

            with mock.patch.object(self.h, "poll", return_value=(403, {"ok": False})):
                scenario.exercise(label, "owner", "writer", "late", "admin", "revoked", "gid",
                                  mock.Mock(), mock.Mock(return_value="x0x://invite/late"), mock.Mock(),
                                  lambda: stopped.add("1" * 64), lambda: stopped.add("5" * 64),
                                  lambda node: IDS[node] in stopped, mock.Mock())
            scenario.promote_admin.assert_called_once_with("owner", "admin", "gid")
            scenario.await_admin.assert_called_once_with("writer", "admin", "gid")

    def test_history_reads_refused_unless_owner_and_admin_are_offline(self):
        # The recorded offline check is what proves only the writer can serve
        # history; a stop that did not take must abort before any late read.
        scenario = self.h.Scenario({n: FakeApi(i) for n, i in IDS.items()}, self.h.Evidence())
        for method in ("open_store", "await_value", "await_absent", "prove_denied_did_not_converge",
                       "promote_admin", "await_admin"):
            setattr(scenario, method, mock.Mock(return_value={"id": "sid"}))
        scenario.put = mock.Mock(side_effect=lambda node, *_a: (403, {}) if node == "revoked" else (200, {}))
        for api in scenario.c.values():
            api.request = mock.Mock(return_value=(200, {"ok": True}))
        with mock.patch.object(self.h, "poll", return_value=(403, {})), \
                self.assertRaisesRegex(AssertionError, "owner and admin stopped before late history"):
            scenario.exercise("private_secure", "owner", "writer", "late", "admin", "revoked", "gid",
                              mock.Mock(), mock.Mock(return_value="x0x://invite/l"), mock.Mock(),
                              mock.Mock(), mock.Mock(), lambda node: node == "owner", mock.Mock())
        late_reads = [c for c in scenario.open_store.call_args_list if c.args[0] == "late"]
        self.assertEqual([], late_reads)
        scenario.await_admin.assert_called_once_with("writer", "admin", "gid")

    def test_decision_b_ordering_per_scenario(self):
        for label in ("private_secure", "home"):
            with self.subTest(label=label):
                events, expected = trace_scenario(self.h, label)
                assert_decision_b(self, label, events, expected)

    def test_home_labels_and_writer_member_role_are_recorded(self):
        # Home evidence must name the ORIGINAL OWNER DEVICE and the same-owner
        # Member-role provider; private_secure keeps its original label.
        for label, present, absent in (
                ("home", ["original owner device offline during admission",
                          "owner and admin devices offline during history; "
                          "history served by same-owner Member-role device",
                          "home writer remains Member role"],
                 ["home owner and admin stopped before late history"]),
                ("private_secure", ["private_secure owner and admin stopped before late history"],
                 ["original owner device offline during admission", "home writer remains Member role"])):
            with self.subTest(label=label):
                evidence = self.h.Evidence()
                original = self.h.Evidence
                with mock.patch.object(self.h, "Evidence", lambda: evidence):
                    trace_scenario(self.h, label)
                self.h.Evidence = original
                labels = [row["label"] for row in evidence.assertions]
                for wanted in present:
                    self.assertIn(wanted, labels)
                for unwanted in absent:
                    self.assertNotIn(unwanted, labels)
                self.assertFalse(any("owner user offline" in l or "all owner keys offline" in l for l in labels))

    def test_home_writer_promoted_to_admin_fails_role_check(self):
        scenario = self.h.Scenario({n: FakeApi(i) for n, i in IDS.items()}, self.h.Evidence())
        scenario.c["owner"].request = mock.Mock(return_value=(200, {"members": [
            {"agent_id": IDS["writer"], "role": "admin"}]}))
        scenario.home = mock.Mock(return_value=("gid", "f" * 64))
        scenario.require_home_identity = mock.Mock()
        scenario.home_invite = mock.Mock(return_value="x0x://invite/h")
        scenario.join_home = mock.Mock()
        def run_hook(*args, before_admission=None, **_kwargs):
            before_admission()
        scenario.exercise = mock.Mock(side_effect=run_hook)
        with self.assertRaisesRegex(AssertionError, "home writer remains Member role"):
            scenario.run_home("owner", "writer", "late", "admin", "revoked", mock.Mock(), mock.Mock(),
                              mock.Mock(), mock.Mock())

    def test_revert_controls_fail(self):
        history_before_stop_admin = load_mutant("mut_history_before_stop_admin", (
            """            stop_admin()
            self.e.check(history_offline_label or f"{label} owner and admin stopped before late history",
                         is_offline(owner) and is_offline(admin))
""", ""), ("""        expected = set(actor_ids.values())
""", """        stop_admin()
        expected = set(actor_ids.values())
"""))
        owner_minted = load_mutant("mut_owner_minted",
                                   ("lambda: self.invite(admin, late, gid)", "lambda: self.invite(owner, late, gid)"),
                                   ("lambda: self.home_invite(admin, late, gid, owner_id)",
                                    "lambda: self.home_invite(owner, late, gid, owner_id)"))
        mint_before_removal = load_mutant("mut_mint_before_removal", (
            """        late_invite = mint_late()
""", ""), ("""        revoke_id = self.c[revoked].agent_id()
""", """        late_invite = mint_late()
        revoke_id = self.c[revoked].agent_id()
"""))
        barrier_block = (
            """        # The plain-Member writer must observe the Admin role before the late
        # invite exists, so its roster witness cannot race permission propagation.
        self.await_admin(writer, admin, gid)
""", "")
        barrier_removed = load_mutant("mut_barrier_removed", barrier_block)
        barrier_after_mint = load_mutant("mut_barrier_after_mint", barrier_block, (
            """        late_invite = mint_late()
""", """        late_invite = mint_late()
        self.await_admin(writer, admin, gid)
"""))
        owner_key_barrier = ("""            self.await_owner_key_barrier(label, writer, stores, owner_key)
""", "")
        owner_key_barrier_removed = load_mutant("mut_owner_key_barrier_removed", owner_key_barrier)
        owner_key_barrier_after_offline = load_mutant(
            "mut_owner_key_barrier_after_offline", owner_key_barrier, ("""            join_late(late_invite)
""", """            join_late(late_invite)
            self.await_owner_key_barrier(label, writer, stores, owner_key)
"""))
        for name, mutant in (("history before stop_admin", history_before_stop_admin),
                             ("owner-minted late invite", owner_minted),
                             ("late mint before removal", mint_before_removal),
                             ("writer barrier removed", barrier_removed),
                             ("writer barrier moved after mint", barrier_after_mint),
                             ("owner-key barrier removed", owner_key_barrier_removed),
                             ("owner-key barrier after owner offline", owner_key_barrier_after_offline)):
            for label in ("private_secure", "home"):
                with self.subTest(mutant=name, label=label):
                    events, expected = trace_scenario(mutant, label)
                    with self.assertRaises(AssertionError):
                        assert_decision_b(self, label, events, expected)

    def _failing_exercise(self, await_value, state_sync):
        """Run exercise() to its failure; return (scenario, stopped, error)."""
        scenario = self.h.Scenario({n: FakeApi(i) for n, i in IDS.items()}, self.h.Evidence())
        for node, api in scenario.c.items():
            api.request = mock.Mock(side_effect=lambda method, path, body=None, node=node: (
                state_sync(node) if path == "/diagnostics/state-sync" else (200, {"ok": True})))
        scenario.open_store = mock.Mock(side_effect=lambda _node, _gid, app: {"id": f"sid-{app}"})
        scenario.put = mock.Mock(side_effect=lambda node, *_a: (403, {}) if node == "revoked" else (200, {}))
        scenario.await_value = mock.Mock(side_effect=await_value)
        for method in ("await_absent", "prove_denied_did_not_converge", "promote_admin", "await_admin"):
            setattr(scenario, method, mock.Mock())
        stopped: list[str] = []
        with mock.patch.object(self.h, "poll", return_value=(403, {})), \
                self.assertRaises(AssertionError) as raised:
            scenario.exercise("private_secure", "owner", "writer", "late", "admin", "revoked", "gid",
                              mock.Mock(), mock.Mock(return_value="x0x://invite/l"), mock.Mock(),
                              lambda: stopped.append("owner"), lambda: stopped.append("admin"),
                              lambda node: node in stopped, mock.Mock())
        return scenario, stopped, raised.exception

    def test_owner_key_barrier_timeout_is_a_product_failure_before_any_stop(self):
        # R19: a writer that never held the owner key leaves the late member
        # nothing to sync. Everything is online at the barrier, so the timeout
        # is a product (writer convergence) failure, and it leaves the
        # late-history precondition unmet; the owner must still be online.
        def await_value(node, _sid, key, *_a, **_k):
            if node == "writer" and key.endswith("-owner"):
                raise self.h.PollTimeout("writer receives k", 120, 120.2, 404, None)
        scenario, stopped, error = self._failing_exercise(
            await_value, lambda _node: (200, {"ok": True, "stores": {}}))
        self.assertIn("did not converge", str(error))
        self.assertEqual([], stopped)
        barrier_calls = [c for c in scenario.await_value.call_args_list
                         if c.args[0] == "writer" and c.args[2].endswith("-owner")]
        self.assertEqual({"barrier": "writer_owner_key_before_offline"}, barrier_calls[0].kwargs)
        failed = [row for row in scenario.e.assertions if not row["passed"]]
        self.assertEqual(1, len(failed))
        self.assertIn("product failure", failed[0]["label"])
        self.assertIn("late-history precondition unmet", failed[0]["label"])
        self.assertNotIn("not a product verdict", failed[0]["label"])
        self.assertEqual("product_failure", failed[0]["verdict"])
        self.assertEqual("unmet", failed[0]["late_history_precondition"])
        self.assertIn("writer receives k did not converge", failed[0]["poll_timeout"])

    def test_owner_key_barrier_passes_both_stores_before_offline(self):
        scenario = self.h.Scenario({n: FakeApi(i) for n, i in IDS.items()}, self.h.Evidence())
        scenario.await_value = mock.Mock()
        scenario.await_owner_key_barrier("private_secure", "writer",
                                         {"wiki": "sid-wiki", "web": "sid-web"}, "k-owner")
        self.assertEqual([mock.call("writer", "sid-wiki", "k-owner", "private_secure-owner-wiki",
                                    barrier="writer_owner_key_before_offline"),
                          mock.call("writer", "sid-web", "k-owner", "private_secure-owner-web",
                                    barrier="writer_owner_key_before_offline")],
                         scenario.await_value.call_args_list)

    def test_late_history_failure_captures_paired_safe_state_sync_counters(self):
        secret = "Bearer token-secret-value"
        def await_value(node, _sid, key, *_a, **_k):
            if node == "late" and key.endswith("-owner"):
                raise self.h.PollTimeout("late receives k", 120, 120.2, 404, None)
        def state_sync(node):
            if node == "late":
                return 200, {"ok": True, "token": secret, "stores": {
                    "sid-wiki": {"requests_sent": 4, "incoming_record_merges": 2,
                                 "rejected_other": True, "requests_answered": secret,
                                 "note": secret},
                    secret: {"requests_sent": 9}}}
            raise RuntimeError(secret)
        scenario, stopped, error = self._failing_exercise(await_value, state_sync)
        self.assertIn("did not converge", str(error))
        self.assertEqual(["owner", "admin"], stopped)
        rows = [row for row in scenario.e.polls if row.get("operation") == "state_sync_failure_snapshot"]
        self.assertEqual([("writer", "wiki"), ("writer", "web"), ("late", "wiki"), ("late", "web")],
                         [(row["node"], row["app"]) for row in rows])
        by_key = {(row["node"], row["app"]): row for row in rows}
        self.assertEqual({"requests_sent": 4, "incoming_record_merges": 2},
                         by_key[("late", "wiki")]["counters"])
        self.assertTrue(by_key[("late", "wiki")]["topic_open"])
        self.assertEqual(200, by_key[("late", "wiki")]["http_status"])
        self.assertFalse(by_key[("late", "web")]["topic_open"])
        self.assertEqual({}, by_key[("late", "web")]["counters"])
        self.assertEqual("RuntimeError", by_key[("writer", "wiki")]["error_class"])
        self.assertIsNone(by_key[("writer", "wiki")]["http_status"])
        for row in rows:
            self.assertLessEqual(set(row["counters"]), set(self.h.STATE_SYNC_COUNTERS))
            self.assertTrue(all(type(value) is int for value in row["counters"].values()))
        self.assertNotIn("token-secret-value", json.dumps(scenario.e.report()))

    def test_partial_tunnel_acquisition_and_report_failure_still_cleanup(self):
        nodes = ["a", "b", "c", "d", "e"]
        tokens = {node: (f"192.0.2.{index}", node) for index, node in enumerate(nodes, 1)}
        first = mock.Mock(local_port=25001)
        argv = ["e2e_vps_private_kv.py", "--network", "test", "--tokens-file", "tokens",
                "--scenario", "private_secure", "--allow-service-restart",
                "--nodes", *nodes, "--report", "/cannot/write"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.h, "load_tokens", return_value=tokens), \
                mock.patch.object(self.h, "start_ssh_tunnel", side_effect=[first, RuntimeError("second")]), \
                mock.patch.object(self.h, "stop_ssh_tunnel") as stop, \
                mock.patch("builtins.open", side_effect=OSError("report")):
            self.assertEqual(1, self.h.main())
        stop.assert_called_once_with(first)

    def test_main_report_exports_stores_and_polls_alongside_assertions(self):
        # GUI acceptance must read group/store IDs and poll receipts from the
        # private/Home report alone, exactly as from the Home fixture report.
        nodes = ["a", "b", "c", "d", "e"]
        tokens = {node: (f"192.0.2.{index}", node) for index, node in enumerate(nodes, 1)}
        tunnels = [mock.Mock(local_port=25200 + index) for index in range(5)]
        recorded = {}

        class IdentityApi:
            next_id = 0
            def __init__(self, _base, _token):
                self.ident = f"{IdentityApi.next_id:064x}"; IdentityApi.next_id += 1
            def agent_id(self): return self.ident
            def request(self, *_args): return 200, {"ok": True}

        class RecordingScenario:
            def __init__(self, _clients, evidence, _timeout): recorded["evidence"] = evidence
            def run_private(self, *_args):
                evidence = recorded["evidence"]
                evidence.check("private_secure removes member", True)
                for app in ("wiki", "web"):
                    evidence.record_store("writer", "gid", app, {"id": f"topic-{app}", "store_id": "0" * 64})
                evidence.record_poll({"label": "late roster on owner", "outcome": "accepted"},
                                     operation="role", node="writer", group_id="gid", role="admin")

        custody = mock.Mock(); custody.restore.return_value = []
        with tempfile.TemporaryDirectory(prefix="private-kv-report-") as root:
            report = Path(root) / "report.json"
            argv = ["e2e_vps_private_kv.py", "--network", "test", "--tokens-file", "tokens",
                    "--scenario", "private_secure", "--allow-service-restart",
                    "--nodes", *nodes, "--report", str(report)]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(self.h, "load_tokens", return_value=tokens), \
                    mock.patch.object(self.h, "start_ssh_tunnel", side_effect=tunnels), \
                    mock.patch.object(self.h, "stop_ssh_tunnel"), mock.patch.object(self.h, "Api", IdentityApi), \
                    mock.patch.object(self.h, "Scenario", RecordingScenario), \
                    mock.patch.object(self.h, "ServiceCustody", mock.Mock(return_value=custody)):
                self.assertEqual(0, self.h.main())
            data = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual({"scenario", "stores", "polls", "assertions"}, set(data))
        self.assertEqual(["private_secure"], data["scenario"])
        self.assertEqual([{"node": "writer", "group_id": "gid", "app": app,
                           "topic": f"topic-{app}", "store_id": "0" * 64}
                          for app in ("wiki", "web")], data["stores"])
        self.assertEqual([{"operation": "role", "node": "writer", "group_id": "gid",
                           "role": "admin", "label": "late roster on owner",
                           "outcome": "accepted"}], data["polls"])
        self.assertTrue(data["assertions"])
        self.assertTrue(all(row["passed"] for row in data["assertions"]))

    def test_main_restores_service_after_scenario_failure_and_report_failure(self):
        nodes = ["a", "b", "c", "d", "e"]
        tokens = {node: (f"192.0.2.{index}", node) for index, node in enumerate(nodes, 1)}
        tunnels = [mock.Mock(local_port=25100 + index) for index in range(5)]
        argv = ["e2e_vps_private_kv.py", "--network", "test", "--tokens-file", "tokens",
                "--scenario", "private_secure", "--allow-service-restart",
                "--nodes", *nodes, "--report", "/cannot/write"]
        class IdentityApi:
            next_id = 0
            def __init__(self, _base, _token):
                self.ident = f"{IdentityApi.next_id:064x}"; IdentityApi.next_id += 1
            def agent_id(self): return self.ident
            def request(self, *_args): return 200, {"ok": True}
        def fail_after_stop(_self, _owner, _writer, _late, _admin, _revoked, stop_owner, stop_admin,
                            _offline, _restart):
            stop_owner(); stop_admin(); raise RuntimeError("scenario")
        service_calls = []
        down: set[str] = set()
        def fake_service(ip, verb):
            service_calls.append(verb)
            if verb == "stop":
                down.add(ip)
            elif verb == "start":
                down.discard(ip)
            return verb != "is-active" or ip not in down
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.h, "load_tokens", return_value=tokens), \
                mock.patch.object(self.h, "start_ssh_tunnel", side_effect=tunnels), \
                mock.patch.object(self.h, "stop_ssh_tunnel"), mock.patch.object(self.h, "Api", IdentityApi), \
                mock.patch.object(self.h.Scenario, "run_private", fail_after_stop), \
                mock.patch("e2e_vps_kv.service", side_effect=fake_service), \
                mock.patch("builtins.open", side_effect=OSError("report")):
            self.assertEqual(1, self.h.main())
        self.assertEqual(2, service_calls.count("stop"))
        self.assertEqual(2, service_calls.count("start"))


if __name__ == "__main__":
    unittest.main()
