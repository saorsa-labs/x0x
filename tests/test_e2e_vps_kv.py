#!/usr/bin/env python3
"""Offline controls for the ordinary shared-store VPS harness."""
from __future__ import annotations

import importlib.util
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
