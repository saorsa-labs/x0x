#!/usr/bin/env python3
"""Focused tests for the VPS mesh harness split-soak controls."""

from __future__ import annotations

import base64
import importlib.util
import json
import logging
import sys
import threading
import time
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

    def test_direct_discovery_targets_only_selected_remote_and_keeps_request_id(self):
        client = FakeClient()
        bus = self.mesh.ResultsBus()
        bus.discover.put(self.mesh.RunnerInfo("sfo", "b" * 64, "machine-sfo"))
        found = self.mesh.discover_runners(
            client, bus, ["sfo"], "a" * 64, 1, logging.getLogger("test"),
            runner_agent_ids={"sfo": "b" * 64, "sydney": "c" * 64},
        )
        self.assertEqual(["sfo"], list(found))
        self.assertEqual([], client.published)
        self.assertEqual(1, len(client.direct_sent))
        target, wire = client.direct_sent[0]
        self.assertEqual("b" * 64, target)
        cmd = json.loads(base64.b64decode(wire[len(self.mesh.PREFIX_CMD):]))
        self.assertEqual("sfo", cmd["target_node"])
        self.assertEqual(cmd["command_id"], cmd["params"]["request_id"])
        self.assertEqual("a" * 64, cmd["anchor_aid"])

    def test_acked_direct_discovery_without_reply_falls_back_after_interval(self):
        bus = self.mesh.ResultsBus()

        class AckOnlyClient(FakeClient):
            def publish(self, topic, payload):
                # The runner responds only to PubSub: the earlier HTTP ACK
                # came from a stale but syntactically valid agent ID.
                self.assert_direct_sent_before_fallback()
                super().publish(topic, payload)
                bus.discover.put(self_reply)

            def assert_direct_sent_before_fallback(self):
                if len(self.direct_sent) != 1 or self.published:
                    raise AssertionError("PubSub fallback fired before one direct attempt")

        self_reply = self.mesh.RunnerInfo("sfo", "b" * 64, "machine-sfo")
        client = AckOnlyClient()
        found = self.mesh.discover_runners(
            client, bus, ["sfo"], "a" * 64, 1,
            logging.getLogger("test"), republish_every_secs=0.05,
            runner_agent_ids={"sfo": "c" * 64},
        )
        self.assertEqual(self_reply, found["sfo"])
        self.assertEqual(1, len(client.direct_sent))
        self.assertEqual(1, len(client.published))
        target, wire = client.direct_sent[0]
        self.assertEqual("c" * 64, target)
        direct_cmd = json.loads(base64.b64decode(wire[len(self.mesh.PREFIX_CMD):]))
        fallback_cmd = json.loads(client.published[0][1])
        self.assertEqual("sfo", fallback_cmd["target_node"])
        self.assertEqual(direct_cmd["anchor_aid"], fallback_cmd["anchor_aid"])

    def test_discovery_attributes_reply_to_fallback_after_direct_ack(self):
        bus = self.mesh.ResultsBus()

        class ReplyOnFallback(FakeClient):
            def publish(self, topic, payload):
                super().publish(topic, payload)
                command = json.loads(payload)
                self_reply = {
                    "kind": "discover_reply",
                    "node": "sfo",
                    "agent_id": "b" * 64,
                    "machine_id": "machine-sfo",
                    "request_id": command["params"]["request_id"],
                }
                self_mesh._enqueue_result_envelope(self_reply, bus, "direct")

        self_mesh = self.mesh
        client = ReplyOnFallback()
        with self.assertLogs("discovery-attribution", level=logging.INFO) as logs:
            found = self.mesh.discover_runners(
                client, bus, ["sfo"], "a" * 64, 1,
                logging.getLogger("discovery-attribution"),
                republish_every_secs=0.05,
                runner_agent_ids={"sfo": "c" * 64},
            )
        direct_wire = client.direct_sent[0][1]
        direct_command = json.loads(base64.b64decode(
            direct_wire[len(self.mesh.PREFIX_CMD):]
        ))
        fallback_command = json.loads(client.published[0][1])
        self.assertNotEqual(
            direct_command["params"]["request_id"],
            fallback_command["params"]["request_id"],
        )
        self.assertEqual(
            fallback_command["params"]["request_id"],
            found["sfo"].request_id,
        )
        self.assertIn("node=sfo channel=pubsub", "\n".join(logs.output))
        self.assertRegex("\n".join(logs.output), r"announce_reply_latency_ms=[0-9]+")

    def test_discovery_direct_replies_have_unique_ids_and_positive_latency(self):
        bus = self.mesh.ResultsBus()

        class ReplyOnDirect(FakeClient):
            def direct_send(self, target_aid, payload, **kwargs):
                result = super().direct_send(target_aid, payload, **kwargs)
                command = json.loads(base64.b64decode(
                    payload[len(self_mesh.PREFIX_CMD):]
                ))
                time.sleep(0.002)
                self_mesh._enqueue_result_envelope({
                    "kind": "discover_reply",
                    "node": command["target_node"],
                    "agent_id": target_aid,
                    "machine_id": "machine-" + command["target_node"],
                    "request_id": command["params"]["request_id"],
                }, bus, "direct")
                return result

        self_mesh = self.mesh
        client = ReplyOnDirect()
        with self.assertLogs("discovery-direct-latency", level=logging.INFO) as logs:
            found = self.mesh.discover_runners(
                client, bus, ["sfo", "sydney"], "a" * 64, 1,
                logging.getLogger("discovery-direct-latency"),
                runner_agent_ids={"sfo": "b" * 64, "sydney": "c" * 64},
            )
        ids = [info.request_id for info in found.values()]
        self.assertEqual(2, len(set(ids)))
        self.assertEqual(2, len(client.direct_sent))
        matched = [line for line in logs.output if "channel=direct" in line]
        self.assertEqual(2, len(matched))
        for line in matched:
            self.assertRegex(line, r"announce_reply_latency_ms=[1-9][0-9]*")

    def test_unsolicited_runner_ready_has_unknown_channel_and_latency(self):
        bus = self.mesh.ResultsBus()

        class UnsolicitedReady(FakeClient):
            def publish(self, topic, payload):
                super().publish(topic, payload)
                self_mesh._enqueue_result_envelope({
                    "kind": "runner_ready",
                    "node": "sfo",
                    "agent_id": "b" * 64,
                    "machine_id": "machine-sfo",
                }, bus, "pubsub")

        self_mesh = self.mesh
        with self.assertLogs("discovery-unsolicited", level=logging.INFO) as logs:
            self.mesh.discover_runners(
                UnsolicitedReady(), bus, ["sfo"], "a" * 64, 1,
                logging.getLogger("discovery-unsolicited"),
            )
        self.assertIn(
            "node=sfo channel=unknown announce_reply_latency_ms=unknown",
            "\n".join(logs.output),
        )

    def test_malformed_discover_request_id_cannot_break_attribution(self):
        bus = self.mesh.ResultsBus()
        self.mesh._enqueue_result_envelope({
            "kind": "discover_reply",
            "node": "sfo",
            "agent_id": "b" * 64,
            "machine_id": "machine-sfo",
            "request_id": {"unhashable": True},
        }, bus, "direct")
        self.assertIsNone(bus.discover.get_nowait().request_id)

    def test_slow_direct_sends_leave_time_for_fallback_and_finish_workers(self):
        nodes = ["sfo", "helsinki", "nuremberg", "singapore", "sydney"]
        aids = {node: format(index + 1, "x") * 64
                for index, node in enumerate(nodes)}
        bus = self.mesh.ResultsBus()
        lock = threading.Lock()
        active = 0
        peak_active = 0
        completed = []
        observed_budgets = []

        class ReplyOnFallback(FakeClient):
            def publish(self, topic, payload):
                super().publish(topic, payload)
                node = json.loads(payload)["target_node"]
                bus.discover.put(self_reply[node])

        self_reply = {
            node: self.mesh.RunnerInfo(node, aids[node], f"machine-{node}")
            for node in nodes
        }
        client = ReplyOnFallback()

        def slow_send(_client, aid, cmd, _log, **kwargs):
            nonlocal active, peak_active
            with lock:
                active += 1
                peak_active = max(peak_active, active)
                observed_budgets.append(kwargs["http_timeout_secs"])
            time.sleep(0.12)
            with lock:
                active -= 1
                completed.append(cmd["target_node"])
            return {"ok": True}

        started = time.monotonic()
        with mock.patch.object(self.mesh, "send_command_dm", side_effect=slow_send):
            found = self.mesh.discover_runners(
                client, bus, nodes, "a" * 64, 0.8,
                logging.getLogger("test"), republish_every_secs=0.2,
                runner_agent_ids=aids,
            )
        elapsed = time.monotonic() - started
        self.assertEqual(set(nodes), set(found))
        self.assertEqual(set(nodes), set(completed))
        self.assertEqual(0, active)
        self.assertGreaterEqual(peak_active, 2)
        self.assertEqual(5, len(client.published))
        self.assertTrue(all(budget < 0.8 for budget in observed_budgets))
        self.assertLess(elapsed, 0.7, "fallback missed its reserved discovery time")

    def test_discovery_falls_back_on_missing_id_failed_send_and_self_dm(self):
        for ids, fail_send in (({}, False), ({"sfo": "wrong"}, False),
                               ({"sfo": "b" * 64}, True),
                               ({"sfo": "a" * 64}, False)):
            with self.subTest(ids=ids, fail_send=fail_send):
                client = FakeClient()
                bus = self.mesh.ResultsBus()
                bus.discover.put(self.mesh.RunnerInfo("sfo", "b" * 64, "machine-sfo"))
                if fail_send:
                    client.direct_send = mock.Mock(side_effect=OSError("send failed"))
                found = self.mesh.discover_runners(
                    client, bus, ["sfo"], "a" * 64, 1,
                    logging.getLogger("test"), runner_agent_ids=ids,
                )
                self.assertIn("sfo", found)
                self.assertEqual(self.mesh.DISCOVER_TOPIC, client.published[0][0])
                payload = json.loads(client.published[0][1])
                self.assertEqual(payload["command_id"], payload["params"]["request_id"])
                self.assertEqual("sfo", payload["target_node"])
                if ids.get("sfo") in ("a" * 64, "wrong"):
                    self.assertEqual([], client.direct_sent)

    def test_lookup_validates_ids_and_closes_every_owned_tunnel(self):
        agents = {"sfo": "b" * 64, "helsinki": "wrong",
                  "sydney": "a" * 64}
        opened = []
        closed = []
        def open_tunnel(ip, port, remote_port):
            handle = mock.Mock(ip=ip, local_port=port, remote_port=remote_port)
            opened.append(handle)
            return handle
        # Each lookup gets its own temporary tunnel and one API client.
        client_urls = []
        def make_client(url, _token):
            index = len(client_urls)
            node = ("sfo", "helsinki", "sydney")[index]
            client_urls.append(url)
            return mock.Mock(agent=lambda: {"agent_id": agents[node]})
        with mock.patch.object(self.mesh, "start_ssh_tunnel", side_effect=open_tunnel), \
             mock.patch.object(self.mesh, "stop_ssh_tunnel", side_effect=closed.append), \
             mock.patch.object(self.mesh, "X0xClient", side_effect=make_client):
            ids = self.mesh.lookup_runner_agents(
                ["nyc", "sfo", "helsinki", "sydney", "unselected"],
                "nyc", "a" * 64,
                {node: (node + ".invalid", "token") for node in agents},
                13600, logging.getLogger("test"),
            )
        self.assertEqual({"nyc": "a" * 64, "sfo": "b" * 64}, ids)
        self.assertEqual(opened, closed)
        self.assertEqual(3, len(opened))
        self.assertEqual(3, len(client_urls))

    def test_lookup_closes_tunnel_when_agent_request_fails(self):
        handle = mock.Mock()
        with mock.patch.object(self.mesh, "start_ssh_tunnel", return_value=handle), \
             mock.patch.object(self.mesh, "stop_ssh_tunnel") as stop, \
             mock.patch.object(self.mesh, "X0xClient") as client_type:
            client_type.return_value.agent.side_effect = OSError("API unavailable")
            ids = self.mesh.lookup_runner_agents(
                ["sfo"], "nyc", "a" * 64,
                {"sfo": ("sfo.invalid", "token")}, 13600,
                logging.getLogger("test"),
            )
        self.assertEqual({}, ids)
        stop.assert_called_once_with(handle)

    def test_no_remote_urls_uses_pubsub(self):
        client = FakeClient()
        bus = self.mesh.ResultsBus()
        bus.discover.put(self.mesh.RunnerInfo("sfo", "b" * 64, "machine-sfo"))
        self.mesh.discover_runners(
            client, bus, ["sfo"], "a" * 64, 1,
            logging.getLogger("test"), runner_agent_ids={},
        )
        self.assertEqual([], client.direct_sent)
        self.assertEqual(self.mesh.DISCOVER_TOPIC, client.published[0][0])

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
            mock.patch.object(self.mesh, "discover_runners", return_value=runners) as discover,
            mock.patch.object(self.mesh, "lookup_runner_agents") as lookup,
            mock.patch.object(self.mesh, "run_all_pairs_matrix", return_value=outcome) as matrix,
            mock.patch.object(self.mesh, "print_summary") as summary,
            mock.patch.object(self.mesh, "consume_sse"),
            mock.patch.object(self.mesh.time, "sleep"),
        ):
            with self.assertLogs("e2e_vps_mesh", level=logging.INFO) as logs:
                rc = self.mesh.main(argv)
        lookup.assert_not_called()
        self.assertEqual({}, discover.call_args.kwargs["runner_agent_ids"])
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
