#!/usr/bin/env python3
"""Focused tests for the VPS mesh test runner."""

from __future__ import annotations

import importlib.util
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


class FakeClient:
    def __init__(self) -> None:
        self.next_id = 1
        self.subscribed: list[str] = []
        self.unsubscribed: list[str] = []

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


if __name__ == "__main__":
    unittest.main()
