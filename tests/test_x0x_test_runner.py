#!/usr/bin/env python3
"""Focused tests for the VPS mesh test runner."""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import queue
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
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


def load_groups():
    script = Path(__file__).with_name("e2e_vps_groups.py")
    spec = importlib.util.spec_from_file_location("e2e_vps_groups", script)
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
        self.direct: list[tuple[str, bytes]] = []
        self.direct_error_code: int | None = None

    def publish(self, topic: str, payload: bytes, **_kwargs) -> None:
        self.published.append((topic, payload))

    def subscribe(self, topic: str) -> dict[str, str]:
        sub_id = f"sub-{self.next_id}"
        self.next_id += 1
        self.subscribed.append(topic)
        return {"subscription_id": sub_id}

    def unsubscribe(self, subscription_id: str) -> dict[str, bool]:
        self.unsubscribed.append(subscription_id)
        return {"ok": True}

    def direct_send(self, target_aid: str, payload: bytes, **_kwargs) -> dict[str, bool]:
        self.direct.append((target_aid, payload))
        if self.direct_error_code is not None:
            raise urllib.error.HTTPError(
                "http://local/direct/send", self.direct_error_code,
                "fake direct rejection", {}, io.BytesIO(b"{}"),
            )
        return {"ok": True}


class X0xTestRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner_mod = load_runner()
        cls.mesh = load_mesh()
        cls.groups = load_groups()

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
            (
                {"kind": "send_result", "request_id": "stale", "ts_ms": stale_ts},
                None,
                False,
                time.monotonic(),
                None,
            )
        )

        runner._enqueue_result({"kind": "send_result", "request_id": "fresh"})

        queued = [runner._send_q.get_nowait()[0]["request_id"]]
        self.assertEqual(["fresh"], queued)

    def test_result_dm_negotiates_chunks_and_preserves_legacy_behavior(self) -> None:
        client = FakeClient()
        runner = self.runner_mod.TestRunner("nyc", client)
        anchor = "a" * 64
        small = {"kind": "api_result", "request_id": "small"}
        small_payload = json.dumps(small).encode()
        self.assertTrue(runner._send_result_dm(anchor, small_payload, small))
        self.assertEqual(1, len(client.direct))
        self.assertTrue(client.direct[0][1].startswith(b"x0xtest|res|"))

        large = {"kind": "api_result", "request_id": "large",
                 "details": {"body": "x" * 60_000}}
        large_payload = json.dumps(large).encode()
        self.assertFalse(runner._send_result_dm(anchor, large_payload, large))
        self.assertEqual(1, len(client.direct))

        self.assertTrue(runner._send_result_dm(anchor, large_payload, large, True))
        chunks = [wire for _, wire in client.direct[1:]]
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(wire.startswith(b"x0xtest|res2|") for wire in chunks))
        self.assertTrue(all(len(wire) <= self.runner_mod.DM_MAX_BYTES for wire in chunks))

    def test_chunk_413_falls_back_to_legacy_pubsub(self) -> None:
        from unittest.mock import patch

        client = FakeClient()
        client.direct_error_code = 413
        runner = self.runner_mod.TestRunner("nyc", client)
        anchor = "a" * 64
        large = {"kind": "api_result", "request_id": "large-413",
                 "details": {"body": "x" * 60_000}}
        with patch.object(self.runner_mod.time, "sleep", return_value=None), \
                self.assertLogs("runner[nyc]", level="DEBUG") as captured:
            runner._enqueue_result(large, target_aid=anchor, result_chunks_v2=True)
            publisher = threading.Thread(target=runner._publisher_loop)
            publisher.start()
            deadline = time.monotonic() + 2.0
            while not client.published and time.monotonic() < deadline:
                threading.Event().wait(0.01)
            runner._stop.set()
            publisher.join(timeout=10.0)
        self.assertFalse(publisher.is_alive())
        frame_count = len(self.runner_mod.frame_result(
            json.dumps(large).encode(), "fixture-transfer", "large-413",
        ))
        self.assertEqual(
            frame_count * self.runner_mod.PUBLISH_RETRY_MAX,
            len(client.direct),
        )
        self.assertEqual(self.runner_mod.LEGACY_RESULTS_TOPIC, client.published[0][0])
        logs = "\n".join(captured.output)
        self.assertEqual(
            frame_count * self.runner_mod.PUBLISH_RETRY_MAX,
            logs.count("stage=wire_complete"),
        )
        for frame_index in range(1, frame_count + 1):
            self.assertEqual(
                self.runner_mod.PUBLISH_RETRY_MAX,
                logs.count(f"wire={frame_index}/{frame_count}"),
            )
        self.assertIn("outcome=http_413", logs)
        self.assertIn("stage=fallback_complete", logs)
        self.assertNotIn("fake direct rejection", logs)

    def test_chunk_negotiation_is_scoped_to_each_command(self) -> None:
        client = FakeClient()
        runner = self.runner_mod.TestRunner("nyc", client)
        anchor = "a" * 64
        base = {"action": "noop_ack", "anchor_aid": anchor,
                "params": {"request_id": "r"}}
        runner._dispatch_command(dict(base, command_id="v2", result_chunks_v2=True))
        runner._dispatch_command(dict(base, command_id="v1"))
        first = runner._send_q.get_nowait()
        second = runner._send_q.get_nowait()
        self.assertTrue(first[2])
        self.assertFalse(second[2])

    def _direct_command(self, runner, sender, command):
        wire = b"x0xtest|cmd|" + base64.b64encode(json.dumps(command).encode())
        runner._handle_direct_event(
            "direct_message",
            json.dumps({
                "sender": sender,
                "payload": base64.b64encode(wire).decode(),
            }),
        )

    @staticmethod
    def _command(request_id, action="group_join", **params):
        return {
            "command_id": request_id,
            "target_node": "nyc",
            "action": action,
            "result_chunks_v2": True,
            "params": {"request_id": request_id, **params},
        }

    @staticmethod
    def _complete_queued_delivery(runner):
        body, target, chunks, _, replay_key = runner._send_q.get_nowait()
        key = runner._result_delivery_key(body, target, chunks, replay_key)
        if key is not None:
            with runner._queued_result_lock:
                runner._queued_result_keys.discard(key)
            runner._mark_replay_delivery_finished(replay_key)
        return body

    def test_duplicate_discovery_is_coalesced_in_result_queue(self) -> None:
        runner = self.runner_mod.TestRunner("nyc", FakeClient())
        command = self._command("discover-1", action="discover")
        sender = "a" * 64

        for _ in range(6):
            self._direct_command(runner, sender, command)

        self.assertEqual(1, runner._send_q.qsize())

    def test_untrusted_discovery_cannot_poison_direct_replay_namespace(self) -> None:
        runner = self.runner_mod.TestRunner("nyc", FakeClient())
        sender = "a" * 64
        calls = []

        def action(_action, command_id, params, anchor, chunks):
            calls.append(params["invite"])
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok"},
                anchor, chunks,
            )

        from unittest.mock import patch
        with patch.object(runner, "_do_simple_action", side_effect=action):
            runner._dispatch_command(
                self._command("scope-id", invite="legacy"),
                source_aid=sender,
                source_authenticated=False,
            )
            self._direct_command(
                runner, sender, self._command("scope-id", invite="direct"),
            )

        self.assertEqual(["legacy", "direct"], calls)
        self.assertEqual(2, runner._send_q.qsize())
        self.assertEqual(2, len(runner._replay))

    def test_command_sender_omits_terminal_retry_sleep(self) -> None:
        from unittest.mock import Mock, patch

        client = Mock()
        client.direct_send.side_effect = TimeoutError("no ack")
        harness = self.groups.FleetHarness(
            client=client,
            router=Mock(),
            anchor_aid="a" * 64,
            anchor_name="nyc",
            runners={"sfo": self.groups.Runner("sfo", "b" * 64)},
            log=Mock(),
        )
        with patch.object(self.groups.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "failed after 5 attempts"):
                harness._send_command("sfo", b"command")

        self.assertEqual(5, client.direct_send.call_count)
        self.assertEqual([2, 4, 6, 8], [call.args[0] for call in sleep.call_args_list])
        self.assertEqual(
            96.0,
            self.groups.COMMAND_DISPATCH_BUDGET_SECS,
        )

    def test_duplicate_group_join_runs_once_and_reuses_completed_result(self) -> None:
        runner = self.runner_mod.TestRunner("nyc", FakeClient())
        command = self._command("join-1", invite="invite")
        sender = "a" * 64
        calls = []

        def action(_action, command_id, params, anchor, chunks):
            calls.append(command_id)
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok"},
                anchor, chunks,
            )

        from unittest.mock import patch
        with patch.object(runner, "_do_simple_action", side_effect=action):
            self._direct_command(runner, sender, command)
            self._direct_command(runner, sender, command)

        self.assertEqual(["join-1"], calls)
        self.assertEqual(1, runner._send_q.qsize())
        self._complete_queued_delivery(runner)
        self._direct_command(runner, sender, command)
        self.assertEqual(["join-1"], calls)
        self.assertEqual(1, runner._send_q.qsize())

    def test_same_request_from_two_authenticated_senders_runs_twice(self) -> None:
        runner = self.runner_mod.TestRunner("nyc", FakeClient())
        command = self._command("shared-id", invite="invite")
        calls = []

        def action(_action, command_id, params, anchor, chunks):
            calls.append(anchor)
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok"},
                anchor, chunks,
            )

        from unittest.mock import patch
        with patch.object(runner, "_do_simple_action", side_effect=action):
            self._direct_command(runner, "a" * 64, command)
            self._direct_command(runner, "b" * 64, command)

        self.assertEqual(["a" * 64, "b" * 64], calls)

    def test_same_sender_request_payload_conflict_is_refused(self) -> None:
        runner = self.runner_mod.TestRunner("nyc", FakeClient())
        sender = "a" * 64
        calls = []

        def action(_action, command_id, params, anchor, chunks):
            calls.append(params["invite"])
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok"},
                anchor, chunks,
            )

        from unittest.mock import patch
        with patch.object(runner, "_do_simple_action", side_effect=action):
            self._direct_command(runner, sender, self._command("join-2", invite="one"))
            self._direct_command(runner, sender, self._command("join-2", invite="two"))

        self.assertEqual(["one"], calls)
        queued = [runner._send_q.get_nowait()[0] for _ in range(2)]
        self.assertEqual("group_join_result", queued[0]["kind"])
        self.assertEqual("error", queued[1]["kind"])
        self.assertIn("different command", queued[1]["outcome"]["error"])

    def test_inflight_duplicate_and_capacity_pressure_never_rerun(self) -> None:
        from unittest.mock import patch

        runner = self.runner_mod.TestRunner("nyc", FakeClient())
        entered = threading.Event()
        release = threading.Event()
        calls = []

        def action(_action, command_id, params, anchor, chunks):
            calls.append(command_id)
            entered.set()
            self.assertTrue(release.wait(timeout=2))
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok"},
                anchor, chunks,
            )

        first = self._command("join-live", invite="one")
        with patch.object(self.runner_mod, "COMMAND_REPLAY_MAX_ENTRIES", 1), \
                patch.object(runner, "_do_simple_action", side_effect=action):
            worker = threading.Thread(
                target=self._direct_command,
                args=(runner, "a" * 64, first),
            )
            worker.start()
            self.assertTrue(entered.wait(timeout=2))
            self._direct_command(runner, "a" * 64, first)
            self._direct_command(
                runner, "a" * 64,
                self._command("join-pressure", invite="two"),
            )
            release.set()
            worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(["join-live"], calls)
        queued = [runner._send_q.get_nowait()[0] for _ in range(2)]
        self.assertEqual(["error", "group_join_result"], [x["kind"] for x in queued])

    def test_replay_cache_ttl_and_byte_bound_allow_fresh_execution(self) -> None:
        from unittest.mock import patch

        runner = self.runner_mod.TestRunner("nyc", FakeClient())
        calls = []

        def action(_action, command_id, params, anchor, chunks):
            calls.append(command_id)
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok",
                 "details": "x" * 100},
                anchor, chunks,
            )

        command = self._command("join-expire", invite="one")
        clock = [0.0]
        with patch.object(self.runner_mod, "COMMAND_REPLAY_TTL_SECS", 1), \
                patch.object(self.runner_mod, "COMMAND_REPLAY_MAX_BYTES", 4096), \
                patch.object(runner, "_do_simple_action", side_effect=action), \
                patch.object(self.runner_mod.time, "monotonic",
                             side_effect=lambda: clock[0]):
            self._direct_command(runner, "a" * 64, command)
            self._complete_queued_delivery(runner)
            clock[0] = 2.0
            self._direct_command(runner, "a" * 64, command)

        self.assertEqual(["join-expire", "join-expire"], calls)

        bounded = self.runner_mod.TestRunner("nyc", FakeClient())
        bounded_calls = []
        def bounded_action(_action, command_id, params, anchor, chunks):
            bounded_calls.append(command_id)
            bounded._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok",
                 "details": "x" * 100},
                anchor, chunks,
            )
        with patch.object(self.runner_mod, "COMMAND_REPLAY_MAX_BYTES", 32), \
                patch.object(bounded, "_do_simple_action", side_effect=bounded_action):
            self._direct_command(bounded, "b" * 64, command)
            self.assertLessEqual(
                bounded._replay_bytes,
                self.runner_mod.COMMAND_REPLAY_MAX_BYTES,
            )
            self._complete_queued_delivery(bounded)
            self._direct_command(bounded, "b" * 64, command)
        self.assertEqual(0, bounded._replay_bytes)
        self.assertEqual(1, len(bounded._replay))
        self.assertEqual(["join-expire"], bounded_calls)
        self.assertEqual("error", bounded._send_q.get_nowait()[0]["kind"])

    def test_completed_replay_cache_refuses_pressure_without_rerun(self) -> None:
        from unittest.mock import patch

        runner = self.runner_mod.TestRunner("nyc", FakeClient())
        calls = []

        def action(_action, command_id, params, anchor, chunks):
            calls.append(command_id)
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok"},
                anchor, chunks,
            )

        with patch.object(self.runner_mod, "COMMAND_REPLAY_MAX_ENTRIES", 1), \
                patch.object(runner, "_do_simple_action", side_effect=action):
            self._direct_command(
                runner, "a" * 64, self._command("first", invite="one"),
            )
            self._complete_queued_delivery(runner)
            self._direct_command(
                runner, "a" * 64, self._command("second", invite="two"),
            )
            self._direct_command(
                runner, "a" * 64, self._command("first", invite="one"),
            )

        self.assertEqual(["first"], calls)
        self.assertEqual(1, len(runner._replay))
        queued = [runner._send_q.get_nowait()[0] for _ in range(2)]
        self.assertEqual(["error", "group_join_result"], [x["kind"] for x in queued])

    def test_pending_large_results_never_exceed_replay_byte_bound(self) -> None:
        from unittest.mock import patch

        runner = self.runner_mod.TestRunner("nyc", FakeClient())
        calls = []

        def action(_action, command_id, params, anchor, chunks):
            calls.append(command_id)
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok",
                 "details": "x" * 400},
                anchor, chunks,
            )

        with patch.object(self.runner_mod, "COMMAND_REPLAY_MAX_BYTES", 512), \
                patch.object(runner, "_do_simple_action", side_effect=action):
            for index in range(5):
                self._direct_command(
                    runner,
                    "a" * 64,
                    self._command(f"large-{index}", invite="one"),
                )
                self.assertLessEqual(runner._replay_bytes, 512)
            self._direct_command(
                runner, "a" * 64,
                self._command("large-4", invite="one"),
            )

        self.assertEqual([f"large-{index}" for index in range(5)], calls)
        self.assertLessEqual(runner._replay_bytes, 512)
        self.assertEqual(6, runner._send_q.qsize())
        self.assertEqual("error", list(runner._send_q.queue)[-1][0]["kind"])

    def test_reinsert_full_releases_delivery_pin_for_retry_and_expiry(self) -> None:
        from unittest.mock import patch

        runner = self.runner_mod.TestRunner("nyc", FakeClient())
        command = self._command("reinsert-full", invite="one")
        calls = []

        def action(_action, command_id, params, anchor, chunks):
            calls.append(command_id)
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok"},
                anchor, chunks,
            )

        class FullDuringReinsert:
            def __init__(self, item):
                self.item = item
                self.returned = False

            def get_nowait(self):
                if self.returned:
                    raise queue.Empty
                self.returned = True
                return self.item

            def put_nowait(self, _item):
                raise queue.Full

        with patch.object(runner, "_do_simple_action", side_effect=action):
            self._direct_command(runner, "a" * 64, command)
            queued = runner._send_q.get_nowait()
            runner._send_q = FullDuringReinsert(queued)
            runner._prune_stale_results(self.runner_mod.now_ms())

            replay_key = ("direct:" + ("a" * 64), "reinsert-full")
            self.assertFalse(runner._replay[replay_key]["delivery_pending"])

            runner._send_q = queue.Queue()
            self._direct_command(runner, "a" * 64, command)
            self.assertEqual(["reinsert-full"], calls)
            self.assertEqual(1, runner._send_q.qsize())
            self._complete_queued_delivery(runner)

            runner._replay[replay_key]["completed_at"] -= (
                self.runner_mod.COMMAND_REPLAY_TTL_SECS + 1
            )
            with runner._replay_lock:
                runner._prune_replay_locked(time.monotonic())
            self.assertNotIn(replay_key, runner._replay)

    def test_completed_command_without_result_never_reexecutes(self) -> None:
        from unittest.mock import patch

        runner = self.runner_mod.TestRunner("nyc", FakeClient())
        command = self._command("missing-result", invite="one")
        calls = []

        def action(*_args):
            calls.append("called")

        with patch.object(runner, "_do_simple_action", side_effect=action):
            self._direct_command(runner, "a" * 64, command)
            self._direct_command(runner, "a" * 64, command)

        self.assertEqual(["called"], calls)
        self.assertEqual("error", runner._send_q.get_nowait()[0]["kind"])

    def test_legacy_publication_releases_tracked_result_without_target(self) -> None:
        from unittest.mock import patch

        client = FakeClient()
        runner = self.runner_mod.TestRunner("nyc", client)
        command = self._command("legacy-result", invite="one")

        def action(_action, command_id, params, _anchor, chunks):
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok"},
                None, chunks,
            )

        with patch.object(runner, "_do_simple_action", side_effect=action):
            self._direct_command(runner, "a" * 64, command)

        replay_key = ("direct:" + ("a" * 64), "legacy-result")
        publisher = threading.Thread(target=runner._publisher_loop)
        publisher.start()
        deadline = time.monotonic() + 2
        while not client.published and time.monotonic() < deadline:
            threading.Event().wait(0.01)
        runner._stop.set()
        publisher.join(timeout=2)

        self.assertFalse(publisher.is_alive())
        self.assertTrue(client.published)
        self.assertFalse(runner._replay[replay_key]["delivery_pending"])
        runner._replay[replay_key]["completed_at"] -= (
            self.runner_mod.COMMAND_REPLAY_TTL_SECS + 1
        )
        with runner._replay_lock:
            runner._prune_replay_locked(time.monotonic())
        self.assertNotIn(replay_key, runner._replay)

    def test_final_queue_rejection_releases_tracked_result_without_target(self) -> None:
        from unittest.mock import patch

        class AlwaysFull:
            def put_nowait(self, _item):
                raise queue.Full

            def get_nowait(self):
                raise queue.Empty

        runner = self.runner_mod.TestRunner("nyc", FakeClient())
        runner._send_q = AlwaysFull()
        command = self._command("legacy-drop", invite="one")

        def action(_action, command_id, params, _anchor, chunks):
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok"},
                None, chunks,
            )

        with patch.object(runner, "_do_simple_action", side_effect=action):
            self._direct_command(runner, "a" * 64, command)

        replay_key = ("direct:" + ("a" * 64), "legacy-drop")
        self.assertFalse(runner._replay[replay_key]["delivery_pending"])

    def test_chunk_failures_fall_back_within_enqueue_budget(self) -> None:
        from unittest.mock import patch

        fallback_timeouts = []
        raw_started = threading.Event()
        delivery_started = [0.0]

        class BudgetClient(FakeClient):
            def direct_send(self, _target, _payload, **kwargs):
                raw_started.set()
                threading.Event().wait(0.18)
                raise TimeoutError("controlled raw timeout")

            def publish(self, topic, payload, **kwargs):
                fallback_timeouts.append(
                    (time.monotonic() - delivery_started[0], kwargs["timeout"])
                )
                return super().publish(topic, payload)

        client = BudgetClient()
        runner = self.runner_mod.TestRunner("nyc", client)
        result = {
            "kind": "group_messages_result",
            "command_id": "large-budget",
            "request_id": "large-budget",
            "outcome": "ok",
            "details": {"body": "x" * 60_000},
        }

        with patch.object(runner, "_sleep_within_deadline", return_value=False), \
                patch.object(self.runner_mod, "RESULT_RAW_BUDGET_SECS", 0.15), \
                patch.object(self.runner_mod, "RESULT_TOTAL_BUDGET_SECS", 0.30):
            delivery_started[0] = time.monotonic()
            runner._enqueue_result(
                result, target_aid="a" * 64, result_chunks_v2=True,
            )
            publisher = threading.Thread(target=runner._publisher_loop)
            publisher.start()
            deadline = time.monotonic() + 2
            while not client.published and time.monotonic() < deadline:
                threading.Event().wait(0.01)
            runner._stop.set()
            publisher.join(timeout=2)

        self.assertFalse(publisher.is_alive())
        self.assertGreater(len(self.runner_mod.frame_result(
            json.dumps(result).encode(), "transfer", "large-budget",
        )), 1)
        self.assertTrue(raw_started.is_set())
        self.assertEqual(1, len(fallback_timeouts))
        fallback_elapsed, fallback_timeout = fallback_timeouts[0]
        self.assertGreaterEqual(fallback_elapsed, 0.14)
        self.assertGreater(fallback_timeout, 0)
        self.assertLessEqual(fallback_timeout, 0.30 - fallback_elapsed + 0.01)

    def test_three_delayed_chunks_start_concurrently_and_finish_in_budget(self) -> None:
        lock = threading.Lock()
        all_started = threading.Event()
        starts = []

        class DelayedClient(FakeClient):
            def direct_send(self, target_aid, payload, **kwargs):
                with lock:
                    starts.append(time.monotonic())
                    if len(starts) == 3:
                        all_started.set()
                if not all_started.wait(timeout=1):
                    raise TimeoutError("three frames did not overlap")
                threading.Event().wait(0.05)
                return super().direct_send(target_aid, payload, **kwargs)

        runner = self.runner_mod.TestRunner("nyc", DelayedClient())
        result = {
            "kind": "group_messages_result",
            "request_id": "three-concurrent-frames",
            "details": {"body": "x" * 60_000},
        }
        payload = json.dumps(result).encode()
        frames = self.runner_mod.frame_result(
            payload, "fixture-transfer", result["request_id"],
        )
        self.assertEqual(3, len(frames))

        started = time.monotonic()
        self.assertTrue(runner._send_result_dm(
            "a" * 64, payload, result, True, started + 1,
        ))
        self.assertLess(time.monotonic() - started, 1)
        self.assertLess(max(starts) - min(starts), 0.2)
        runner._stop_publisher_workers([])

    def test_expired_chunk_transfer_performs_no_http(self) -> None:
        client = FakeClient()
        runner = self.runner_mod.TestRunner("nyc", client)
        result = {
            "kind": "group_messages_result",
            "request_id": "expired-chunks",
            "details": {"body": "x" * 60_000},
        }
        payload = json.dumps(result).encode()

        self.assertFalse(runner._send_result_dm(
            "a" * 64, payload, result, True, time.monotonic() - 1,
        ))
        self.assertEqual([], client.direct)
        runner._stop_publisher_workers([])

    def test_queued_chunk_expiring_behind_http_slots_performs_no_http(self) -> None:
        release = threading.Event()
        client = FakeClient()
        runner = self.runner_mod.TestRunner("nyc", client)

        def occupy_slot() -> bool:
            return release.wait(timeout=2)

        blockers = [
            runner._submit_http_job(occupy_slot, time.monotonic() + 1)
            for _ in range(self.runner_mod.RESULT_HTTP_WORKERS)
        ]
        self.assertTrue(all(blocker is not None for blocker in blockers))
        envelope = {"kind": "api_result", "request_id": "queued-expiry"}
        expires = time.monotonic() + 0.05
        queued = runner._submit_http_job(
            runner._send_result_wire,
            expires,
            "a" * 64, b"frame", envelope, 1, 1, expires,
        )
        self.assertIsNotNone(queued)
        threading.Event().wait(0.08)
        release.set()
        self.assertFalse(queued.result(timeout=1))
        self.assertEqual([], client.direct)
        runner._stop_publisher_workers([])

    def test_slow_result_does_not_starve_next_result_raw_window(self) -> None:
        slow_entered = threading.Event()
        fast_entered = threading.Event()
        release = threading.Event()

        class ConcurrentClient(FakeClient):
            def direct_send(self, target_aid, payload, **kwargs):
                if target_aid == "a" * 64:
                    slow_entered.set()
                    if not release.wait(timeout=2):
                        raise TimeoutError("fixture release missing")
                else:
                    fast_entered.set()
                return super().direct_send(target_aid, payload, **kwargs)

        runner = self.runner_mod.TestRunner("nyc", ConcurrentClient())
        runner._enqueue_result(
            {"kind": "send_result", "request_id": "slow"}, "a" * 64,
        )
        workers = runner._start_publisher_workers()
        self.assertTrue(slow_entered.wait(timeout=1))
        fast_enqueued = time.monotonic()
        runner._enqueue_result(
            {"kind": "send_result", "request_id": "fast"}, "b" * 64,
        )
        self.assertTrue(fast_entered.wait(timeout=1))
        self.assertLess(
            time.monotonic() - fast_enqueued,
            self.runner_mod.RESULT_RAW_BUDGET_SECS,
        )
        release.set()
        runner._stop_publisher_workers(workers)
        self.assertFalse(any(worker.is_alive() for worker in workers))

    def test_run_starts_publisher_pool_once(self) -> None:
        from unittest.mock import patch

        runner = self.runner_mod.TestRunner("nyc", FakeClient())

        def announce_and_stop() -> None:
            runner._stop.set()

        with patch.object(runner, "_bootstrap"), \
                patch.object(runner, "_control_listener_loop"), \
                patch.object(runner, "_direct_listener_loop"), \
                patch.object(runner, "_announce_ready", side_effect=announce_and_stop):
            self.assertEqual(0, runner.run())

        publisher_threads = [
            thread for thread in threading.enumerate()
            if thread.name.startswith("x0x-result-publisher-")
        ]
        self.assertEqual([], publisher_threads)

    def test_publisher_parallelism_is_bounded(self) -> None:
        lock = threading.Lock()
        release = threading.Event()
        four_entered = threading.Event()
        active = 0
        maximum = 0

        class BlockingClient(FakeClient):
            def direct_send(inner_self, target_aid, payload, **kwargs):
                nonlocal active, maximum
                with lock:
                    active += 1
                    maximum = max(maximum, active)
                    if active == self.runner_mod.RESULT_PUBLISHER_WORKERS:
                        four_entered.set()
                try:
                    if not release.wait(timeout=2):
                        raise TimeoutError("fixture release missing")
                    return super().direct_send(target_aid, payload, **kwargs)
                finally:
                    with lock:
                        active -= 1

        runner = self.runner_mod.TestRunner("nyc", BlockingClient())
        for index in range(self.runner_mod.RESULT_PUBLISHER_WORKERS * 2):
            runner._enqueue_result(
                {"kind": "send_result", "request_id": f"bounded-{index}"},
                f"{index:064x}",
            )
        workers = runner._start_publisher_workers()
        self.assertTrue(four_entered.wait(timeout=1))
        threading.Event().wait(0.05)
        self.assertEqual(self.runner_mod.RESULT_PUBLISHER_WORKERS, maximum)
        self.assertEqual(self.runner_mod.RESULT_PUBLISHER_WORKERS, active)
        release.set()
        runner._stop_publisher_workers(workers)
        self.assertFalse(any(worker.is_alive() for worker in workers))

    def test_chunk_http_parallelism_is_globally_bounded_across_results(self) -> None:
        lock = threading.Lock()
        release = threading.Event()
        four_entered = threading.Event()
        active = 0
        maximum = 0
        fallback_entered = threading.Event()

        def enter() -> None:
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
                if active == self.runner_mod.RESULT_HTTP_WORKERS:
                    four_entered.set()

        def leave() -> None:
            nonlocal active
            with lock:
                active -= 1

        class BlockingClient(FakeClient):
            def direct_send(inner_self, target_aid, payload, **kwargs):
                enter()
                try:
                    if not release.wait(timeout=2):
                        raise TimeoutError("fixture release missing")
                    return super().direct_send(target_aid, payload, **kwargs)
                finally:
                    leave()

            def publish(inner_self, topic, payload, **kwargs):
                enter()
                fallback_entered.set()
                try:
                    return super().publish(topic, payload, **kwargs)
                finally:
                    leave()

        runner = self.runner_mod.TestRunner("nyc", BlockingClient())
        for index in range(2):
            runner._enqueue_result(
                {"kind": "group_messages_result", "request_id": f"large-{index}",
                 "details": {"body": "x" * 60_000}},
                f"{index + 1:064x}", True,
            )
        workers = runner._start_publisher_workers()
        self.assertTrue(four_entered.wait(timeout=1))
        fallback_result = []
        fallback = threading.Thread(target=lambda: fallback_result.append(
            runner._publish_result_legacy(
                b"fallback", {"kind": "api_result", "request_id": "fallback"},
                time.monotonic() + 1,
            )
        ))
        fallback.start()
        threading.Event().wait(0.05)
        self.assertFalse(fallback_entered.is_set())
        self.assertEqual(self.runner_mod.RESULT_HTTP_WORKERS, maximum)
        release.set()
        fallback.join(timeout=1)
        self.assertFalse(fallback.is_alive())
        self.assertEqual([True], fallback_result)
        self.assertTrue(fallback_entered.is_set())
        self.assertLessEqual(maximum, self.runner_mod.RESULT_HTTP_WORKERS)
        runner._stop_publisher_workers(workers)
        self.assertFalse(any(worker.is_alive() for worker in workers))

    def test_http_task_admission_is_bounded(self) -> None:
        release = threading.Event()
        runner = self.runner_mod.TestRunner("nyc", FakeClient())

        def blocked() -> bool:
            return release.wait(timeout=2)

        futures = [
            runner._submit_http_job(blocked, time.monotonic() + 1)
            for _ in range(self.runner_mod.RESULT_HTTP_TASKS_MAX)
        ]
        self.assertTrue(all(future is not None for future in futures))
        rejected = runner._submit_http_job(blocked, time.monotonic() + 0.05)
        self.assertIsNone(rejected)
        with runner._http_futures_lock:
            self.assertEqual(
                self.runner_mod.RESULT_HTTP_TASKS_MAX,
                len(runner._http_futures),
            )
        release.set()
        for future in futures:
            self.assertTrue(future.result(timeout=1))
        runner._stop_publisher_workers([])

    def test_blocked_daemon_http_does_not_hold_process_open(self) -> None:
        runner_path = Path(__file__).parent / "runners" / "x0x_test_runner.py"
        script = r'''
import importlib.util
import sys
import threading

spec = importlib.util.spec_from_file_location("exit_runner", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

class Client:
    pass

runner = module.TestRunner("exit", Client())
entered = threading.Event()
blocked = threading.Event()

def never_finishes():
    entered.set()
    blocked.wait()
    return True

future = runner._submit_http_job(never_finishes, None)
assert future is not None and entered.wait(1)
runner._stop_publisher_workers([])
print("stop-returned")
'''
        completed = subprocess.run(
            [sys.executable, "-c", script, str(runner_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("stop-returned", completed.stdout)

    def test_replay_stays_coalesced_during_concurrent_publication(self) -> None:
        from unittest.mock import patch

        entered = threading.Event()
        release = threading.Event()
        calls = []

        class BlockingClient(FakeClient):
            def direct_send(self, target_aid, payload, **kwargs):
                entered.set()
                if not release.wait(timeout=2):
                    raise TimeoutError("fixture release missing")
                return super().direct_send(target_aid, payload, **kwargs)

        runner = self.runner_mod.TestRunner("nyc", BlockingClient())
        command = self._command("pool-replay", invite="one")

        def action(_action, command_id, params, anchor, chunks):
            calls.append(command_id)
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok"},
                anchor, chunks,
            )

        with patch.object(runner, "_do_simple_action", side_effect=action):
            self._direct_command(runner, "a" * 64, command)
            workers = runner._start_publisher_workers()
            self.assertTrue(entered.wait(timeout=1))
            self._direct_command(runner, "a" * 64, command)
            self.assertEqual(["pool-replay"], calls)
            release.set()
            runner._stop_publisher_workers(workers)

        replay_key = ("direct:" + ("a" * 64), "pool-replay")
        self.assertFalse(runner._replay[replay_key]["delivery_pending"])
        self.assertFalse(any(worker.is_alive() for worker in workers))

    def test_replay_pin_waits_for_timed_out_http_task_to_finish(self) -> None:
        from unittest.mock import patch

        entered = threading.Event()
        release = threading.Event()

        class LingeringClient(FakeClient):
            def direct_send(self, target_aid, payload, **kwargs):
                entered.set()
                if not release.wait(timeout=2):
                    raise TimeoutError("fixture release missing")
                return super().direct_send(target_aid, payload, **kwargs)

        runner = self.runner_mod.TestRunner("nyc", LingeringClient())
        command = self._command("lingering-http", invite="one")

        def action(_action, command_id, params, anchor, chunks):
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok"},
                anchor, chunks,
            )

        with patch.object(runner, "_do_simple_action", side_effect=action), \
                patch.object(self.runner_mod, "RESULT_RAW_BUDGET_SECS", 0.05), \
                patch.object(self.runner_mod, "RESULT_TOTAL_BUDGET_SECS", 0.1), \
                patch.object(runner, "_publish_result_legacy", return_value=False):
            self._direct_command(runner, "a" * 64, command)
            workers = runner._start_publisher_workers()
            self.assertTrue(entered.wait(timeout=1))
            threading.Event().wait(0.1)
            replay_key = ("direct:" + ("a" * 64), "lingering-http")
            self.assertTrue(runner._replay[replay_key]["delivery_pending"])
            release.set()
            deadline = time.monotonic() + 1
            while (runner._replay[replay_key]["delivery_pending"]
                   and time.monotonic() < deadline):
                threading.Event().wait(0.01)
            self.assertFalse(runner._replay[replay_key]["delivery_pending"])
            runner._stop_publisher_workers(workers)

    def test_expired_queued_result_skips_transport_and_releases_pin(self) -> None:
        from unittest.mock import patch

        clock = [0.0]
        client = FakeClient()
        runner = self.runner_mod.TestRunner("nyc", client)
        command = self._command("expired-delivery", invite="one")

        def action(_action, command_id, params, anchor, chunks):
            runner._enqueue_result(
                {"kind": "group_join_result", "command_id": command_id,
                 "request_id": params["request_id"], "outcome": "ok"},
                anchor, chunks,
            )

        with patch.object(runner, "_do_simple_action", side_effect=action), \
                patch.object(
                    self.runner_mod.time, "monotonic", side_effect=lambda: clock[0],
                ):
            self._direct_command(runner, "a" * 64, command)
            clock[0] = self.runner_mod.RESULT_TOTAL_BUDGET_SECS + 1
            publisher = threading.Thread(target=runner._publisher_loop)
            publisher.start()
            while not runner._send_q.empty():
                threading.Event().wait(0.01)
            runner._stop.set()
            publisher.join(timeout=2)

        replay_key = ("direct:" + ("a" * 64), "expired-delivery")
        self.assertFalse(publisher.is_alive())
        self.assertFalse(client.direct)
        self.assertFalse(client.published)
        self.assertFalse(runner._replay[replay_key]["delivery_pending"])

    def test_oversized_result_reports_failure_when_pubsub_is_disabled(self) -> None:
        from unittest.mock import patch

        client = FakeClient()
        runner = self.runner_mod.TestRunner("nyc", client)
        runner._pubsub_disabled_after_discover = True
        fallback_finished = threading.Event()
        publish_legacy = runner._publish_result_legacy

        def publish_legacy_then_signal(*args, **kwargs):
            try:
                return publish_legacy(*args, **kwargs)
            finally:
                fallback_finished.set()

        result = {
            "kind": "group_messages_result",
            "command_id": "no-pubsub",
            "request_id": "no-pubsub",
            "outcome": "ok",
            "details": {"body": "x" * 60_000},
        }

        with self.assertLogs(runner.log, level="ERROR") as captured, patch.object(
            runner,
            "_publish_result_legacy",
            side_effect=publish_legacy_then_signal,
        ):
            runner._enqueue_result(result, target_aid=None, result_chunks_v2=False)
            publisher = threading.Thread(target=runner._publisher_loop)
            publisher.start()
            finished = fallback_finished.wait(timeout=2)
            runner._stop.set()
            publisher.join(timeout=2)

        self.assertTrue(finished, "publisher did not finish the disabled fallback")
        self.assertFalse(publisher.is_alive())
        self.assertFalse(client.direct)
        self.assertFalse(client.published)
        logs = "\n".join(captured.output)
        self.assertIn("pubsub fallback is disabled", logs)
        self.assertIn("result delivery failed within budget", logs)

    def test_result_stage_logs_queue_wait_and_owned_publish_completion(self) -> None:
        from unittest.mock import patch

        entered = threading.Event()
        release = threading.Event()
        coordinator_deadline_read = threading.Event()
        clock_lock = threading.Lock()
        clock_values = iter([10.0, 12.0, 13.0, 15.0, 16.0, 18.0, 20.0])

        def controlled_monotonic() -> float:
            with clock_lock:
                value = next(clock_values)
                if value == 15.0:
                    coordinator_deadline_read.set()
                return value

        class StagedClient(FakeClient):
            def direct_send(self, target_aid, payload, **kwargs):
                entered.set()
                if not release.wait(timeout=2.0):
                    raise TimeoutError("fixture release missing")
                return super().direct_send(target_aid, payload, **kwargs)

        runner = self.runner_mod.TestRunner("sin", StagedClient())
        send_result_wire = runner._send_result_wire

        def gated_send_result_wire(*args, **kwargs):
            if not coordinator_deadline_read.wait(timeout=2):
                raise TimeoutError("coordinator did not calculate its deadline")
            return send_result_wire(*args, **kwargs)

        envelope = {
            "kind": "api_result",
            "request_id": "request-7",
            "command_id": "command-7",
            "details": {"token": "must-not-log"},
        }
        with patch.object(
            self.runner_mod.time,
            "monotonic",
            side_effect=controlled_monotonic,
        ), patch.object(
            runner,
            "_send_result_wire",
            side_effect=gated_send_result_wire,
        ), self.assertLogs("runner[sin]", level="INFO") as captured:
            runner._enqueue_result(envelope, target_aid="a" * 64)
            publisher = threading.Thread(target=runner._publisher_loop)
            publisher.start()
            self.assertTrue(entered.wait(timeout=2.0))
            runner._stop.set()
            release.set()
            publisher.join(timeout=2.0)

        self.assertFalse(publisher.is_alive())
        logs = "\n".join(captured.output)
        self.assertIn("stage=enqueued kind=api_result", logs)
        self.assertIn("request_id=request-7 command_id=command-7", logs)
        self.assertIn("stage=publish_start", logs)
        self.assertIn("queue_wait_ms=2000.0", logs)
        self.assertIn("stage=wire_complete", logs)
        self.assertIn("wire=1/1 attempt=1/3 duration_ms=2000.0 outcome=ok", logs)
        self.assertIn("stage=publish_complete", logs)
        self.assertIn("mode=v1 duration_ms=8000.0", logs)
        self.assertNotIn("must-not-log", logs)

    def test_command_stage_logs_are_timed_and_redact_failure_details(self) -> None:
        from unittest.mock import patch

        runner = self.runner_mod.TestRunner("sin", FakeClient())
        command = {
            "action": "group_list",
            "command_id": "command-8",
            "anchor_aid": "a" * 64,
            "params": {"request_id": "request-8"},
        }
        with patch.object(
            runner,
            "_do_simple_action",
            side_effect=RuntimeError("secret response body"),
        ), patch.object(
            self.runner_mod.time,
            "monotonic",
            side_effect=[20.0, 21.0, 23.0],
        ), self.assertLogs("runner[sin]", level="INFO") as captured:
            runner._dispatch_command(command)

        logs = "\n".join(captured.output)
        self.assertIn(
            "command stage=start action=group_list request_id=request-8 "
            "command_id=command-8 monotonic=20.000000",
            logs,
        )
        self.assertIn("error_type=RuntimeError", logs)
        self.assertIn(
            "command stage=end action=group_list request_id=request-8 "
            "command_id=command-8 monotonic=23.000000 "
            "duration_ms=3000.0 dispatch_status=raised",
            logs,
        )
        self.assertNotIn("secret response body", logs)

    def test_runner_does_not_echo_chunked_result_dm(self) -> None:
        client = FakeClient()
        runner = self.runner_mod.TestRunner("nyc", client)
        payload = json.dumps({"request_id": "r", "kind": "api_result"}).encode()
        frame = self.runner_mod.frame_result(payload, "transfer", "r")[0]
        runner._handle_direct_event(
            "direct_message",
            json.dumps({"sender": "a" * 64,
                        "payload": base64.b64encode(frame).decode()}),
        )
        self.assertTrue(runner._send_q.empty())

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

class TokenRotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_runner()

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.token_file = Path(self.tmp.name) / "api-token"
        self.token_file.write_text("old-fixture-token")
        self.client = self.mod.X0xClient(
            "http://127.0.0.1:1", "old-fixture-token", str(self.token_file)
        )

    def error(self, code=401):
        import io
        error = self.mod.urllib.error.HTTPError(
            "http://127.0.0.1:1/fixture", code, "fixture", {}, io.BytesIO(b"denied")
        )
        self.addCleanup(error.close)
        return error

    def rotated_request(self, sse):
        import io
        from unittest.mock import patch
        calls = []
        rejected = self.error()
        def open_request(req, timeout):
            calls.append((req, timeout))
            if len(calls) == 1:
                self.token_file.write_text("new-fixture-token\n")
                raise rejected
            self.assertEqual("Bearer new-fixture-token", req.get_header("Authorization"))
            return io.BytesIO(b"data: fixture\n\n" if sse else b'{"ok":true}')
        with patch.object(self.mod.urllib.request, "urlopen", side_effect=open_request):
            if sse:
                with self.client.open_sse("/events", timeout=42) as response:
                    self.assertEqual(b"data: fixture\n\n", response.read())
            else:
                self.assertEqual({"ok": True}, self.client.publish("fixture", b"value"))
        self.assertEqual(2, len(calls))
        self.assertTrue(rejected.closed)
        self.assertEqual(calls[0][0].data, calls[1][0].data)
        self.assertEqual(calls[0][0].get_method(), calls[1][0].get_method())
        self.assertGreater(calls[1][1], 0)
        self.assertLessEqual(calls[1][1], calls[0][1])
        if sse:
            self.assertEqual("text/event-stream", calls[1][0].get_header("Accept"))
        else:
            self.assertEqual("POST", calls[1][0].get_method())
            self.assertEqual({"topic": "fixture", "payload": "dmFsdWU="}, json.loads(calls[1][0].data))

    def test_rest_reloads_rotated_file_and_preserves_post(self):
        self.rotated_request(False)

    def test_sse_reloads_rotated_file_and_preserves_accept(self):
        self.rotated_request(True)

    def test_success_does_not_reload_or_retry(self):
        import io
        from unittest.mock import patch
        self.token_file.write_text("unneeded-fixture-token")
        with patch.object(self.mod.urllib.request, "urlopen", return_value=io.BytesIO(b'{"ok":true}')) as opened:
            self.assertEqual({"ok": True}, self.client.health())
        self.assertEqual(1, opened.call_count)
        self.assertEqual("old-fixture-token", self.client.token)

    def test_unusable_or_unchanged_file_preserves_401_without_retry(self):
        from unittest.mock import patch
        for contents in ("old-fixture-token", "", "  ", None, b"\xff"):
            with self.subTest(contents=contents):
                if contents is None:
                    self.token_file.unlink(missing_ok=True)
                elif isinstance(contents, bytes):
                    self.token_file.write_bytes(contents)
                else:
                    self.token_file.write_text(contents)
                denied = self.error()
                with patch.object(self.mod.urllib.request, "urlopen", side_effect=denied) as opened:
                    with self.assertRaises(self.mod.urllib.error.HTTPError) as caught:
                        self.client.health()
                self.assertIs(denied, caught.exception)
                self.assertEqual(1, opened.call_count)
                self.assertEqual("old-fixture-token", self.client.token)

    def test_literal_token_has_no_reload_path(self):
        from unittest.mock import patch
        client = self.mod.X0xClient("http://127.0.0.1:1", "literal-fixture")
        with patch.object(self.mod.urllib.request, "urlopen", side_effect=self.error()) as opened:
            with self.assertRaises(self.mod.urllib.error.HTTPError):
                client.open_sse("/events")
        self.assertEqual(1, opened.call_count)

    def test_unsafe_replacement_preserves_401_and_cache_then_recovers(self):
        import io
        from unittest.mock import patch
        unsafe_tokens = (
            "fixture-secret\nsecond-line", "fixture-secret\rsecond-line",
            "fixture-secret\tsecond-part", "fixture-secret second-part",
            "fixture-secret\x00", "fixture-secret\x7f", "fixture-secret\u00e9",
            "fixture-secret\u2603",
        )
        for sse in (False, True):
            for unsafe_token in unsafe_tokens:
                with self.subTest(sse=sse, kind=repr(unsafe_token)):
                    self.client.token = "old-fixture-token"
                    self.token_file.write_text(unsafe_token, encoding="utf-8")
                    denied = self.error()
                    with patch.object(self.mod.urllib.request, "urlopen", side_effect=denied) as opened:
                        with self.assertRaises(self.mod.urllib.error.HTTPError) as caught:
                            self.client.open_sse("/events") if sse else self.client.health()
                    self.assertIs(denied, caught.exception)
                    self.assertNotIn("fixture-secret", str(caught.exception))
                    self.assertEqual(1, opened.call_count)
                    self.assertEqual("Bearer old-fixture-token", opened.call_args.args[0].get_header("Authorization"))
                    self.assertEqual("old-fixture-token", self.client.token)

                    # A corrected file must still refresh on the next 401;
                    # the rejected contents never poison the shared cache.
                    self.token_file.write_text("fixed-fixture-token\n")
                    with patch.object(self.mod.urllib.request, "urlopen", side_effect=[self.error(), io.BytesIO(b'{"ok":true}')]) as opened:
                        if sse:
                            with self.client.open_sse("/events") as response:
                                self.assertEqual(b'{"ok":true}', response.read())
                        else:
                            self.assertEqual({"ok": True}, self.client.health())
                    self.assertEqual(2, opened.call_count)
                    self.assertEqual("Bearer fixed-fixture-token", opened.call_args.args[0].get_header("Authorization"))
                    self.assertEqual("fixed-fixture-token", self.client.token)

    def test_bad_replacement_is_retried_only_once_for_rest_and_sse(self):
        from unittest.mock import patch
        for sse in (False, True):
            with self.subTest(sse=sse):
                self.client.token = "old-fixture-token"
                self.token_file.write_text("new-but-rejected")
                final = self.error()
                with patch.object(self.mod.urllib.request, "urlopen", side_effect=[self.error(), final]) as opened:
                    with self.assertRaises(self.mod.urllib.error.HTTPError) as caught:
                        self.client.open_sse("/events") if sse else self.client.health()
                self.assertIs(final, caught.exception)
                self.assertEqual(2, opened.call_count)

    def test_non_401_and_transport_errors_never_replay(self):
        from unittest.mock import patch
        self.token_file.write_text("new-fixture-token")
        for error in (self.error(403), self.error(500), TimeoutError("fixture")):
            with self.subTest(error=type(error).__name__):
                with patch.object(self.mod.urllib.request, "urlopen", side_effect=error) as opened:
                    with self.assertRaises(type(error)):
                        self.client.publish("fixture", b"value")
                self.assertEqual(1, opened.call_count)
                self.assertEqual("old-fixture-token", self.client.token)

    def test_concurrent_refresh_reuses_new_token_even_if_file_disappears(self):
        import io
        from unittest.mock import patch
        calls = []
        def open_request(req, timeout):
            calls.append(req)
            if len(calls) == 1:
                self.token_file.write_text("new-fixture-token")
                self.assertTrue(self.client._reload_token("old-fixture-token"))
                self.token_file.unlink()
                raise self.error()
            self.assertEqual("Bearer new-fixture-token", req.get_header("Authorization"))
            return io.BytesIO(b'{"ok":true}')
        with patch.object(self.mod.urllib.request, "urlopen", side_effect=open_request):
            self.assertEqual({"ok": True}, self.client.health())
        self.assertEqual(2, len(calls))

    def test_main_retains_file_source_but_not_literal_source(self):
        from unittest.mock import patch
        for spec, expected_file in ((str(self.token_file), str(self.token_file)), ("literal-fixture", None)):
            with self.subTest(expected_file=expected_file):
                with patch.dict(self.mod.os.environ, {"X0X_API_TOKEN": spec}), patch.object(self.mod, "X0xClient") as client, patch.object(self.mod, "TestRunner") as runner:
                    runner.return_value.run.return_value = 0
                    self.assertEqual(0, self.mod.main([]))
                self.assertEqual(expected_file, client.call_args.kwargs["token_file"])

    def test_main_retains_file_source_when_file_disappears_after_read(self):
        from contextlib import contextmanager
        from unittest.mock import patch
        original_open = open

        @contextmanager
        def open_then_remove(*args, **kwargs):
            with original_open(*args, **kwargs) as source:
                yield source
            # The read has completed, but main has not constructed its client.
            self.token_file.unlink()

        with patch.dict(self.mod.os.environ, {"X0X_API_TOKEN": str(self.token_file)}), patch("builtins.open", side_effect=open_then_remove), patch.object(self.mod, "TestRunner") as runner:
            runner.return_value.run.return_value = 0
            self.assertEqual(0, self.mod.main([]))
        client = runner.call_args.kwargs["client"]
        self.assertFalse(self.token_file.exists())
        self.assertEqual("old-fixture-token", client.token)
        self.assertEqual(str(self.token_file), client._token_file)
        self.token_file.write_text("new-fixture-token")
        self.assertTrue(client._reload_token("old-fixture-token"))
        self.assertEqual("new-fixture-token", client.token)

    def test_main_literal_does_not_gain_file_source_if_path_appears(self):
        from unittest.mock import patch
        self.token_file.unlink()
        original_isfile = self.mod.os.path.isfile

        def classify_then_create(path):
            is_file = original_isfile(path)
            if path == str(self.token_file) and not is_file:
                self.token_file.write_text("unrelated-fixture-token")
            return is_file

        with patch.dict(self.mod.os.environ, {"X0X_API_TOKEN": str(self.token_file)}), patch.object(self.mod.os.path, "isfile", side_effect=classify_then_create), patch.object(self.mod, "TestRunner") as runner:
            runner.return_value.run.return_value = 0
            self.assertEqual(0, self.mod.main([]))
        client = runner.call_args.kwargs["client"]
        self.assertTrue(self.token_file.exists())
        self.assertEqual(str(self.token_file), client.token)
        self.assertIsNone(client._token_file)
        self.assertFalse(client._reload_token(str(self.token_file)))
        self.assertEqual(str(self.token_file), client.token)

    def test_load_token_keeps_string_return_value(self):
        self.assertEqual("old-fixture-token", self.mod.load_token(str(self.token_file)))
        self.assertEqual("literal-fixture", self.mod.load_token("literal-fixture"))


if __name__ == "__main__":
    unittest.main()
