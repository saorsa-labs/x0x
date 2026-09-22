#!/usr/bin/env python3
"""Offline controls for the Phase-A receive-ACKed raw-DM request contract."""

from __future__ import annotations

import base64
import importlib.util
import logging
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch


def load_runner():
    script = Path(__file__).parent / "runners" / "x0x_test_runner.py"
    spec = importlib.util.spec_from_file_location("x0x_test_runner_raw_contract", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_mesh():
    tests_dir = Path(__file__).parent
    if str(tests_dir) not in sys.path:
        sys.path.insert(0, str(tests_dir))
    script = tests_dir / "e2e_vps_mesh.py"
    spec = importlib.util.spec_from_file_location("e2e_vps_mesh_raw_contract", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RecordingClient:
    def __init__(self) -> None:
        self.calls = []

    def direct_send(self, agent_id, payload, **kwargs):
        self.calls.append((agent_id, payload, kwargs))
        return {"ok": True, "path": "raw_quic_acked", "request_id": "01"}


class FailingRawClient(RecordingClient):
    def __init__(self) -> None:
        super().__init__()
        self.published = []
        self.fallback = threading.Event()

    def direct_send(self, agent_id, payload, **kwargs):
        self.calls.append((agent_id, payload, kwargs))
        raise TimeoutError("inert raw failure")

    def publish(self, topic, payload, **kwargs):
        self.published.append((topic, payload, kwargs))
        self.fallback.set()


class RawQuicContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_runner()
        cls.mesh = load_mesh()

    def test_http_client_omits_durable_field_unless_explicit(self):
        client = self.mod.X0xClient("http://127.0.0.1:1", "fixture")
        bodies = []
        client._request = lambda method, path, body=None, timeout=15.0: bodies.append(body) or {"ok": True}

        client.direct_send("00" * 32, b"ordinary")
        client.direct_send("00" * 32, b"raw", require_durable_app_ack=False)

        self.assertNotIn("require_durable_app_ack", bodies[0])
        self.assertIs(bodies[1]["require_durable_app_ack"], False)

    def test_phase_a_data_send_explicitly_selects_receive_acked_raw(self):
        client = RecordingClient()
        runner = self.mod.TestRunner("sfo", client)
        results = []
        runner._enqueue_result = lambda result, **kwargs: results.append(result)
        runner._do_send_dm(
            "command-1",
            {
                "recipient_aid": "11" * 32,
                "payload_b64": base64.b64encode(b"payload").decode(),
                "request_id": "request-1",
                "prefer_raw_quic_if_connected": True,
                "raw_quic_receive_ack_ms": 12_000,
                "stop_fallback_on_raw_error": True,
            },
            "22" * 32,
            False,
        )

        options = client.calls[0][2]
        self.assertIs(options["require_durable_app_ack"], False)
        self.assertEqual(12_000, options["raw_quic_receive_ack_ms"])
        self.assertTrue(options["stop_fallback_on_raw_error"])
        self.assertEqual("raw_quic_acked", results[0]["details"]["path"])

    def test_raw_result_reply_explicitly_opts_out_of_durable_default(self):
        client = RecordingClient()
        runner = self.mod.TestRunner("singapore", client)
        envelope = {"kind": "received_dm", "request_id": "r", "command_id": "c"}

        self.assertTrue(runner._send_result_wire("33" * 32, b"wire", envelope, 1, 1))

        options = client.calls[0][2]
        self.assertIs(options["require_durable_app_ack"], False)
        self.assertEqual(self.mod.RESULT_RAW_QUIC_ACK_MS, options["raw_quic_receive_ack_ms"])
        self.assertTrue(options["stop_fallback_on_raw_error"])

    def test_raw_result_failure_reaches_existing_legacy_fallback(self):
        client = FailingRawClient()
        runner = self.mod.TestRunner("singapore", client)
        envelope = {
            "kind": "send_result",
            "request_id": "fallback-r",
            "command_id": "fallback-c",
        }

        with patch.object(self.mod, "PUBLISH_RETRY_MAX", 1), patch.object(
            self.mod, "PUBLISH_RETRY_BACKOFF_SECS", 0.0
        ):
            runner._enqueue_result(envelope, target_aid="88" * 32)
            publisher = threading.Thread(target=runner._publisher_loop)
            publisher.start()
            self.assertTrue(client.fallback.wait(timeout=1))
            runner._stop.set()
            publisher.join(timeout=1)

        self.assertFalse(publisher.is_alive())
        self.assertIs(client.calls[0][2]["require_durable_app_ack"], False)
        self.assertEqual(self.mod.LEGACY_RESULTS_TOPIC, client.published[0][0])

    def test_non_terminal_raw_request_does_not_silently_change_receipt_tier(self):
        client = RecordingClient()
        runner = self.mod.TestRunner("sfo", client)
        runner._enqueue_result = lambda *args, **kwargs: None
        runner._do_send_dm(
            "command-2",
            {
                "recipient_aid": "44" * 32,
                "payload_b64": "",
                "request_id": "request-2",
                "prefer_raw_quic_if_connected": True,
                "raw_quic_receive_ack_ms": 12_000,
                "stop_fallback_on_raw_error": False,
            },
            "55" * 32,
            False,
        )

        self.assertIsNone(client.calls[0][2]["require_durable_app_ack"])

    def test_mesh_command_serializes_complete_raw_contract(self):
        client = self.mesh.X0xClient("http://127.0.0.1:1", "fixture")
        requests = []
        client._req = lambda method, path, body=None, timeout=15.0: requests.append(
            (method, path, body)
        ) or {"ok": True, "path": "raw_quic_acked"}

        result = self.mesh.send_command_dm(
            client,
            "66" * 32,
            {"action": "noop_ack", "request_id": "command-3"},
            logging.getLogger("raw-contract"),
        )

        self.assertEqual("raw_quic_acked", result["path"])
        method, path, body = requests[0]
        self.assertEqual(("POST", "/direct/send"), (method, path))
        self.assertTrue(body["prefer_raw_quic_if_connected"])
        self.assertEqual(
            self.mesh.COMMAND_RAW_QUIC_ACK_MS,
            body["raw_quic_receive_ack_ms"],
        )
        self.assertTrue(body["stop_fallback_on_raw_error"])
        self.assertIs(body["require_durable_app_ack"], False)

    def test_disabled_command_ack_retains_durable_default(self):
        client = self.mesh.X0xClient("http://127.0.0.1:1", "fixture")
        bodies = []
        client._req = lambda method, path, body=None, timeout=15.0: bodies.append(
            body
        ) or {"ok": True}
        with patch.object(self.mesh, "COMMAND_RAW_QUIC_ACK_MS", None):
            self.mesh.send_command_dm(
                client, "66" * 32, {"action": "noop_ack"},
                logging.getLogger("raw-contract"),
            )
        self.assertNotIn("require_durable_app_ack", bodies[0])

    def test_disabled_result_ack_retains_durable_default(self):
        client = RecordingClient()
        runner = self.mod.TestRunner("singapore", client)
        with patch.object(self.mod, "RESULT_RAW_QUIC_ACK_MS", None):
            self.assertTrue(runner._send_result_wire(
                "33" * 32, b"wire", {"kind": "received_dm"}, 1, 1,
            ))
        self.assertIsNone(client.calls[0][2]["require_durable_app_ack"])

    def test_mesh_ordinary_send_retains_durable_default(self):
        client = self.mesh.X0xClient("http://127.0.0.1:1", "fixture")
        bodies = []
        client._req = lambda method, path, body=None, timeout=15.0: bodies.append(
            body
        ) or {"ok": True}

        client.direct_send("77" * 32, b"ordinary")

        self.assertNotIn("require_durable_app_ack", bodies[0])


if __name__ == "__main__":
    unittest.main()
