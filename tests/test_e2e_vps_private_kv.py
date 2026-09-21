#!/usr/bin/env python3
"""Offline controls for private/Home VPS acceptance."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


def load_harness():
    tests = Path(__file__).parent
    sys.path.insert(0, str(tests))
    spec = importlib.util.spec_from_file_location("e2e_vps_private_kv", tests / "e2e_vps_private_kv.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
            (200, {"ok": True, "group_id": "home-id", "owner_user_id": "f" * 64,
                   "intended_joiner": "2" * 64, "seated": False,
                   "invite": "x0x://invite/real"})])
        member.request = mock.Mock(return_value=(200, {"ok": True, "group_id": "home-id"}))
        scenario = self.h.Scenario({"owner": owner, "member": member}, self.h.Evidence())
        invite = scenario.home_invite("owner", "member", "home-id", "f" * 64)
        with mock.patch.object(self.h, "poll", return_value=(200, {"members": [{"agent_id": "2" * 64}]})):
            scenario.join_home("owner", "member", "home-id", "f" * 64, invite)
        self.assertEqual(("POST", "/home/seat", {"agent_id": "2" * 64}), owner.request.call_args_list[0].args)
        self.assertEqual({"invite": "x0x://invite/real", "mode": "home",
                          "expected_owner_user_id": "f" * 64}, member.request.call_args.args[2])

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
        scenario.run_private("owner", "writer", "late", "revoked", mock.Mock(), mock.Mock())
        scenario.ok.assert_called_once_with("owner", "POST", "/groups", mock.ANY)
        self.assertEqual("private_secure", scenario.ok.call_args.args[3]["preset"])

    def test_home_seating_refusal_is_not_skipped(self):
        owner, member = FakeApi("1" * 64), FakeApi("2" * 64)
        owner.request = mock.Mock(return_value=(409, {"ok": False, "reason": "elsewhere"}))
        scenario = self.h.Scenario({"owner": owner, "member": member}, self.h.Evidence())
        with self.assertRaises(AssertionError):
            scenario.home_invite("owner", "member", "home-id", "f" * 64)

    def test_exercise_never_calls_stopped_owner(self):
        class StopAwareApi(FakeApi):
            def agent_id(self):
                if self.agent == "1" * 64 and stopped[0]:
                    raise AssertionError("owner identity used after stop")
                return super().agent_id()

            def request(self, method, path, body=None):
                if self.agent == "1" * 64 and stopped[0]:
                    raise AssertionError("owner API used after stop")
                return 200, {"ok": True}
        for label in ("private_secure", "home"):
            stopped = [False]
            clients = {"owner": StopAwareApi("1" * 64), "writer": StopAwareApi("2" * 64),
                       "late": StopAwareApi("3" * 64), "revoked": StopAwareApi("4" * 64)}
            scenario = self.h.Scenario(clients, self.h.Evidence())
            scenario.open_store = mock.Mock(side_effect=lambda _node, _gid, app: {"id": f"sid-{app}"})
            scenario.put = mock.Mock(side_effect=lambda node, *_args: (
                (403, {"ok": False}) if node == "revoked" else (200, {"ok": True})))
            scenario.await_value = mock.Mock()
            scenario.await_absent = mock.Mock()
            scenario.prove_denied_did_not_converge = mock.Mock()

            def stop_owner():
                stopped[0] = True

            with mock.patch.object(self.h, "poll", return_value=(403, {"ok": False})):
                scenario.exercise(label, "owner", "writer", "late", "revoked", "gid",
                                  "x0x://invite/late", mock.Mock(), stop_owner, mock.Mock())

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
        def fail_after_stop(_self, _owner, _writer, _late, _revoked, stop_owner, _restart):
            stop_owner(); raise RuntimeError("scenario")
        service_calls = []
        def fake_service(_ip, verb):
            service_calls.append(verb)
            return verb != "is-active" or service_calls.count("is-active") == 1
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.h, "load_tokens", return_value=tokens), \
                mock.patch.object(self.h, "start_ssh_tunnel", side_effect=tunnels), \
                mock.patch.object(self.h, "stop_ssh_tunnel"), mock.patch.object(self.h, "Api", IdentityApi), \
                mock.patch.object(self.h.Scenario, "run_private", fail_after_stop), \
                mock.patch("e2e_vps_kv.service", side_effect=fake_service), \
                mock.patch("builtins.open", side_effect=OSError("report")):
            self.assertEqual(1, self.h.main())
        self.assertIn("stop", service_calls)
        self.assertIn("start", service_calls)


if __name__ == "__main__":
    unittest.main()
