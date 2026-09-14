#!/usr/bin/env python3
"""Focused tests for the VPS mesh harness split-soak controls."""

from __future__ import annotations

import base64
import importlib.util
import json
import logging
import sys
import unittest
from pathlib import Path
from unittest import mock


def load_mesh():
    tunnel_script = Path(__file__).with_name("e2e_tunnel.py")
    tunnel_spec = importlib.util.spec_from_file_location("e2e_tunnel", tunnel_script)
    assert tunnel_spec is not None
    tunnel_module = importlib.util.module_from_spec(tunnel_spec)
    assert tunnel_spec.loader is not None
    sys.modules[tunnel_spec.name] = tunnel_module
    tunnel_spec.loader.exec_module(tunnel_module)

    script = Path(__file__).with_name("e2e_vps_mesh.py")
    spec = importlib.util.spec_from_file_location("e2e_vps_mesh", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeClient:
    def __init__(self) -> None:
        self.published: list[tuple[str, bytes]] = []
        self.direct_sent: list[tuple[str, bytes]] = []

    def publish(self, topic: str, payload: bytes) -> None:
        self.published.append((topic, payload))

    def direct_send(self, target_aid: str, payload: bytes, **_kwargs):
        self.direct_sent.append((target_aid, payload))
        return {"ok": True, "via": "direct"}


class MainFakeClient:
    def __init__(self, _base_url: str, _token: str) -> None:
        pass

    def health(self):
        return {"ok": True, "version": "test", "peers": 6}

    def agent(self):
        return {"agent_id": "a" * 64}

    def subscribe(self, _topic: str):
        return {"subscription_id": "test"}


class E2eVpsMeshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mesh = load_mesh()

    def test_publish_discover_marks_no_pubsub_after_discover(self) -> None:
        client = FakeClient()

        self.mesh.publish_discover(
            client,
            "a" * 64,
            "request-1",
            no_pubsub_after_discover=True,
        )

        self.assertEqual(self.mesh.DISCOVER_TOPIC, client.published[0][0])
        payload = json.loads(client.published[0][1])
        self.assertTrue(payload["no_pubsub_after_discover"])
        self.assertTrue(payload["params"]["no_pubsub_after_discover"])

    def test_anchor_local_command_can_avoid_pubsub_fallback(self) -> None:
        client = FakeClient()
        command = {"action": "noop_ack", "params": {}}
        anchor = "a" * 64

        result = self.mesh.send_command_dm(
            client,
            anchor,
            command,
            logging.getLogger("test"),
            anchor_aid=anchor,
            allow_anchor_pubsub=False,
        )

        self.assertEqual({"ok": True, "via": "direct"}, result)
        self.assertEqual([], client.published)
        self.assertEqual(anchor, client.direct_sent[0][0])
        wire = client.direct_sent[0][1]
        self.assertTrue(wire.startswith(self.mesh.PREFIX_CMD))
        decoded = json.loads(base64.b64decode(wire[len(self.mesh.PREFIX_CMD):]))
        self.assertEqual(command, decoded)

    def test_matrix_pending_requests_survive_dispatch_longer_than_120_seconds(self):
        bus = self.mesh.ResultsBus()
        runners = {
            name: self.mesh.RunnerInfo(name, char * 64, f"machine-{name}")
            for name, char in zip(("a", "b", "c", "d"), "abcd")
        }
        clock = [1_000.0]

        def now():
            return clock[0]

        def delayed_send(_client, _target, cmd, _log, **_kwargs):
            clock[0] += 15.0
            rid = cmd["params"]["request_id"]
            src = cmd["target_node"]
            recipient = cmd["params"]["recipient_aid"]
            dst = next(name for name, info in runners.items()
                       if info.agent_id == recipient)
            bus.sends.put(self.mesh.SendResult(rid, src, "ok", None, {}))
            bus.received.put(self.mesh.ReceivedDm(rid, dst, None, {}, 0))
            return {"ok": True}

        bus.chunks.clock = now
        with mock.patch.object(self.mesh.time, "monotonic", side_effect=now), \
             mock.patch.object(self.mesh, "send_command_dm", side_effect=delayed_send), \
             mock.patch.object(self.mesh.time, "sleep", return_value=None):
            outcome = self.mesh.run_all_pairs_matrix(
                FakeClient(), bus, runners, runners["a"].agent_id, 30,
                logging.getLogger("delayed-matrix"),
            )
        self.assertGreater(clock[0] - 1_000.0, 120.0)
        self.assertEqual(12, outcome.send_ok)
        self.assertEqual(12, outcome.received)

    def run_main_with_nodes(
        self,
        requested: list[str],
        discovered: list[str],
        *,
        allow_skips: bool = False,
    ):
        runners = {
            node: self.mesh.RunnerInfo(node, node * 64, node * 64)
            for node in discovered
        }
        outcome = self.mesh.MatrixOutcome(sent=len(runners) * (len(runners) - 1))
        argv = [
            "--no-tunnel",
            "--api-base",
            "http://unused.invalid",
            "--api-token",
            "test",
            "--nodes",
            *requested,
            "--post-discover-settle-secs",
            "0",
        ]
        if allow_skips:
            argv.append("--allow-skips")
        with (
            mock.patch.object(self.mesh, "X0xClient", MainFakeClient),
            mock.patch.object(self.mesh, "discover_runners", return_value=runners),
            mock.patch.object(self.mesh, "run_all_pairs_matrix", return_value=outcome) as matrix,
            mock.patch.object(self.mesh, "print_summary") as summary,
            mock.patch.object(self.mesh, "consume_sse"),
            mock.patch.object(self.mesh.time, "sleep"),
        ):
            with self.assertLogs("e2e_vps_mesh", level=logging.INFO) as logs:
                rc = self.mesh.main(argv)
        return rc, matrix, summary, "\n".join(logs.output)

    def test_main_full_six_runs_thirty_directed_pairs(self) -> None:
        nodes = list(self.mesh.NODES_DEFAULT)

        rc, matrix, summary, logs = self.run_main_with_nodes(nodes, nodes)

        self.assertEqual(0, rc, logs)
        matrix.assert_called_once()
        summary.assert_called_once_with(mock.ANY, 30, mock.ANY)

    def test_main_missing_runner_fails_before_matrix(self) -> None:
        nodes = list(self.mesh.NODES_DEFAULT)

        rc, matrix, summary, logs = self.run_main_with_nodes(nodes, nodes[:-1])

        self.assertNotEqual(0, rc)
        matrix.assert_not_called()
        summary.assert_not_called()
        self.assertIn(nodes[-1], logs)
        self.assertIn("strict mode", logs)

    def test_main_fewer_than_two_fails_before_matrix(self) -> None:
        rc, matrix, summary, logs = self.run_main_with_nodes(["nyc"], ["nyc"])

        self.assertNotEqual(0, rc)
        matrix.assert_not_called()
        summary.assert_not_called()
        self.assertIn("need at least 2 runners", logs)

    def test_main_allow_skips_runs_clearly_labelled_partial_subset(self) -> None:
        nodes = list(self.mesh.NODES_DEFAULT)

        rc, matrix, summary, logs = self.run_main_with_nodes(
            nodes,
            nodes[:3],
            allow_skips=True,
        )

        self.assertEqual(0, rc, logs)
        matrix.assert_called_once()
        summary.assert_called_once_with(mock.ANY, 6, mock.ANY)
        self.assertIn("PARTIAL SUBSET MODE", logs)
        self.assertIn("unsuitable for fleet-release acceptance", logs)

    def test_main_deliberate_complete_two_node_inventory_is_strict_success(self) -> None:
        nodes = ["nyc", "sfo"]

        rc, matrix, summary, logs = self.run_main_with_nodes(nodes, nodes)

        self.assertEqual(0, rc, logs)
        matrix.assert_called_once()
        summary.assert_called_once_with(mock.ANY, 2, mock.ANY)
        self.assertNotIn("PARTIAL SUBSET MODE", logs)


if __name__ == "__main__":
    unittest.main()
