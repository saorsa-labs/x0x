#!/usr/bin/env python3
"""Focused tests for the VPS mesh test runner."""

from __future__ import annotations

import importlib.util
import json
import queue
import sys
import unittest
from pathlib import Path


def load_runner():
    script = Path(__file__).parent / "runners" / "x0x_test_runner.py"
    spec = importlib.util.spec_from_file_location("x0x_test_runner", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_mesh():
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
        self.next_id = 1
        self.published: list[tuple[str, bytes]] = []
        self.subscribed: list[str] = []
        self.unsubscribed: list[str] = []

    def publish(self, topic: str, payload: bytes) -> None:
        self.published.append((topic, payload))

    def subscribe(self, topic: str) -> dict[str, str]:
        sub_id = f"sub-{self.next_id}"
        self.next_id += 1
        self.subscribed.append(topic)
        return {"subscription_id": sub_id}

    def unsubscribe(self, subscription_id: str) -> dict[str, bool]:
        self.unsubscribed.append(subscription_id)
        return {"ok": True}


class X0xTestRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner_mod = load_runner()
        cls.mesh = load_mesh()

    def test_resubscribe_replaces_stale_control_topic_subscriptions(self) -> None:
        client = FakeClient()
        runner = self.runner_mod.TestRunner("nyc", client)

        runner._subscribe_control_topics()
        first_ids = dict(runner._subscription_ids)
        runner._subscribe_control_topics()

        self.assertEqual(
            [
                self.runner_mod.DISCOVER_TOPIC,
                self.runner_mod.LEGACY_CONTROL_TOPIC,
                self.runner_mod.DISCOVER_TOPIC,
                self.runner_mod.LEGACY_CONTROL_TOPIC,
            ],
            client.subscribed,
        )
        self.assertEqual(
            [first_ids[self.runner_mod.DISCOVER_TOPIC],
             first_ids[self.runner_mod.LEGACY_CONTROL_TOPIC]],
            client.unsubscribed,
        )
        self.assertNotEqual(first_ids, runner._subscription_ids)

    def test_result_queue_drops_oldest_when_full(self) -> None:
        client = FakeClient()
        runner = self.runner_mod.TestRunner("nyc", client)
        runner._send_q = queue.Queue(maxsize=2)

        runner._enqueue_result({"kind": "send_result", "request_id": "old"})
        runner._enqueue_result({"kind": "send_result", "request_id": "middle"})
        runner._enqueue_result({"kind": "send_result", "request_id": "new"})

        queued = [runner._send_q.get_nowait()[0]["request_id"] for _ in range(2)]
        self.assertEqual(["middle", "new"], queued)

    def test_result_queue_prunes_stale_entries(self) -> None:
        client = FakeClient()
        runner = self.runner_mod.TestRunner("nyc", client)
        runner._send_q = queue.Queue(maxsize=4)
        stale_ts = (
            self.runner_mod.now_ms()
            - ((self.runner_mod.RESULT_QUEUE_MAX_AGE_SECS + 1) * 1000)
        )
        runner._send_q.put_nowait(
            ({"kind": "send_result", "request_id": "stale", "ts_ms": stale_ts}, None)
        )

        runner._enqueue_result({"kind": "send_result", "request_id": "fresh"})

        queued = [runner._send_q.get_nowait()[0]["request_id"]]
        self.assertEqual(["fresh"], queued)

    def test_no_pubsub_after_discover_unsubscribes_control_topics(self) -> None:
        client = FakeClient()
        runner = self.runner_mod.TestRunner(
            "nyc",
            client,
            no_pubsub_after_discover=True,
        )
        runner._subscribe_control_topics()
        first_ids = dict(runner._subscription_ids)

        runner._dispatch_command(
            {
                "command_id": "discover-1",
                "action": "discover",
                "anchor_aid": "a" * 64,
                "params": {"request_id": "discover-1"},
            },
            source_aid=None,
        )

        self.assertTrue(runner._pubsub_disabled_after_discover)
        self.assertEqual([], sorted(runner._subscription_ids))
        self.assertEqual(sorted(first_ids.values()), sorted(client.unsubscribed))

        runner._subscribe_control_topics()
        self.assertEqual(
            [self.runner_mod.DISCOVER_TOPIC, self.runner_mod.LEGACY_CONTROL_TOPIC],
            client.subscribed,
        )

    def test_discover_payload_flag_unsubscribes_control_topics(self) -> None:
        client = FakeClient()
        runner = self.runner_mod.TestRunner(
            "nyc",
            client,
            no_pubsub_after_discover=False,
        )
        runner._subscribe_control_topics()
        first_ids = dict(runner._subscription_ids)

        self.mesh.publish_discover(
            client,
            "a" * 64,
            "discover-1",
            no_pubsub_after_discover=True,
        )
        self.assertEqual(self.mesh.DISCOVER_TOPIC, client.published[0][0])
        payload = json.loads(client.published[0][1])
        self.assertTrue(payload["no_pubsub_after_discover"])
        self.assertTrue(payload["params"]["no_pubsub_after_discover"])

        runner._dispatch_command(payload, source_aid=None)

        self.assertTrue(runner._pubsub_disabled_after_discover)
        self.assertEqual([], sorted(runner._subscription_ids))
        self.assertEqual(sorted(first_ids.values()), sorted(client.unsubscribed))

        runner._subscribe_control_topics()
        self.assertEqual(
            [self.runner_mod.DISCOVER_TOPIC, self.runner_mod.LEGACY_CONTROL_TOPIC],
            client.subscribed,
        )


if __name__ == "__main__":
    unittest.main()
