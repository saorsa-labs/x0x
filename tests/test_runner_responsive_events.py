#!/usr/bin/env python3
"""Offline deterministic tests for runner event-reader responsiveness.

A slow command (blocking direct_send) must not stall the SSE event
readers: with the command worker running, admission enqueues and the
reader returns immediately, while received_dm receipts and discovery
handling stay prompt. FIFO serial execution, in-flight duplicate
coalescing, explicit queue-full rejection, and worker shutdown
ownership are proven with Event-controlled fixtures only — no network,
daemon, or timing-dependent retries.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import queue
import threading
import time
import unittest
from pathlib import Path

# Promptness ceiling: orders of magnitude above the enqueue path's
# microseconds, far below one send_dm retry budget (3x15s HTTP plus
# backoff) that the pre-worker reader used to block for.
PROMPT_SECS = 2.0


def load_runner():
    script = Path(__file__).parent / "runners" / "x0x_test_runner.py"
    spec = importlib.util.spec_from_file_location("x0x_runner_responsive", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BlockingSendClient:
    """Fake daemon client whose direct_send blocks until released.

    Only the command worker calls direct_send here: these tests never
    start publisher workers, so result DMs stay queued in _send_q.
    """

    def __init__(self) -> None:
        self.send_entered = threading.Event()
        self.release_send = threading.Event()
        self.send_calls: list[tuple[str, bytes]] = []
        self._lock = threading.Lock()

    def direct_send(self, target_aid: str, payload: bytes, **_kwargs) -> dict:
        with self._lock:
            self.send_calls.append((target_aid, payload))
        self.send_entered.set()
        if not self.release_send.wait(timeout=10.0):
            raise TimeoutError("fixture release_send missing")
        return {"ok": True}


class RunnerResponsiveEventsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = load_runner()

    def setUp(self) -> None:
        self.client = BlockingSendClient()
        self.runner = self.mod.TestRunner("nyc", self.client)
        self.sender = "a" * 64

    def _send_dm_command(self, request_id: str, recipient: str = "b" * 64) -> None:
        """Feed a send_dm command DM exactly as the direct reader sees it."""
        command = {
            "command_id": request_id,
            "target_node": "nyc",
            "action": "send_dm",
            "params": {
                "request_id": request_id,
                "recipient_aid": recipient,
                "payload_b64": base64.b64encode(b"probe").decode(),
            },
        }
        self._direct_event(command)

    def _direct_event(self, command: dict) -> None:
        wire = b"x0xtest|cmd|" + base64.b64encode(json.dumps(command).encode())
        self.runner._handle_direct_event(
            "direct_message",
            json.dumps({
                "sender": self.sender,
                "payload": base64.b64encode(wire).decode(),
            }),
        )

    def _hop_event(self, request_id: str = "hop-1") -> None:
        payload = (
            f"x0xtest|hop|{request_id}|digest|{self.sender}|body".encode()
        )
        self.runner._handle_direct_event(
            "direct_message",
            json.dumps({
                "sender": "c" * 64,
                "payload": base64.b64encode(payload).decode(),
            }),
        )

    def _pubsub_discover(self, request_id: str = "disc-1") -> None:
        command = {
            "command_id": request_id,
            "target_node": "nyc",
            "action": "discover",
            "anchor_aid": self.sender,
            "params": {"request_id": request_id, "anchor_aid": self.sender},
        }
        self.runner._handle_pubsub_event(
            "message",
            json.dumps({
                "data": {
                    "topic": self.mod.DISCOVER_TOPIC,
                    "payload": base64.b64encode(
                        json.dumps(command).encode()
                    ).decode(),
                }
            }),
        )

    @staticmethod
    def _drain_results(runner, kinds=None) -> list[dict]:
        bodies = []
        while True:
            try:
                body = runner._send_q.get_nowait()[0]
            except queue.Empty:
                break
            if kinds is None or body.get("kind") in kinds:
                bodies.append(body)
        return bodies

    def test_reader_stays_responsive_while_send_blocked(self) -> None:
        worker = self.runner._start_command_worker()
        try:
            started = time.monotonic()
            self._send_dm_command("slow-1")
            self.assertLess(time.monotonic() - started, PROMPT_SECS)
            # Worker is now blocked inside direct_send on slow-1.
            self.assertTrue(self.client.send_entered.wait(timeout=PROMPT_SECS))

            # received_dm receipt still flows while the send is blocked.
            self._hop_event()
            deadline = time.monotonic() + PROMPT_SECS
            receipts: list[dict] = []
            while time.monotonic() < deadline and not receipts:
                receipts = self._drain_results(self.runner, {"received_dm"})
                if not receipts:
                    threading.Event().wait(0.01)
            self.assertTrue(receipts, "received_dm not enqueued while send blocked")
            self.assertEqual("hop-1", receipts[0]["request_id"])
            self.assertFalse(
                self.client.release_send.is_set(),
                "fixture must still be blocked for this proof",
            )

            # Pubsub discovery handling returns promptly too; its reply
            # is FIFO-bound behind the running send by design.
            started = time.monotonic()
            self._pubsub_discover()
            self.assertLess(time.monotonic() - started, PROMPT_SECS)

            self.client.release_send.set()
            deadline = time.monotonic() + PROMPT_SECS
            replies: list[dict] = []
            while time.monotonic() < deadline and len(replies) < 2:
                # Accumulate across polls: _drain_results consumes the
                # queue, so reassigning would discard a reply that
                # landed in an earlier poll.
                replies.extend(
                    self._drain_results(
                        self.runner, {"send_result", "discover_reply"}
                    )
                )
                if len(replies) < 2:
                    threading.Event().wait(0.01)
            self.assertEqual(
                ["send_result", "discover_reply"],
                [body["kind"] for body in replies],
            )
            self.assertEqual("slow-1", replies[0]["request_id"])
            self.assertEqual("disc-1", replies[1]["request_id"])
        finally:
            self.client.release_send.set()
            self.runner._stop.set()
            self.runner._stop_command_worker(worker)
        self.assertFalse(worker.is_alive())

    def test_worker_executes_commands_in_fifo_order_serially(self) -> None:
        overlap = threading.Event()
        active = 0
        original_direct_send = self.client.direct_send

        def guarded_direct_send(target_aid, payload, **kwargs):
            nonlocal active
            active += 1
            if active > 1:
                overlap.set()
            try:
                return original_direct_send(target_aid, payload, **kwargs)
            finally:
                active -= 1

        self.client.direct_send = guarded_direct_send
        worker = self.runner._start_command_worker()
        try:
            # First command blocks the worker; two more queue behind it.
            self._send_dm_command("fifo-1")
            self.assertTrue(self.client.send_entered.wait(timeout=PROMPT_SECS))
            self._send_dm_command("fifo-2")
            self._send_dm_command("fifo-3")
            self.client.release_send.set()
            deadline = time.monotonic() + PROMPT_SECS
            while time.monotonic() < deadline and len(self.client.send_calls) < 3:
                threading.Event().wait(0.01)
        finally:
            self.client.release_send.set()
            self.runner._stop.set()
            self.runner._stop_command_worker(worker)
        self.assertEqual(3, len(self.client.send_calls))
        order = [call[1].decode().split("|")[2] for call in self.client.send_calls]
        self.assertEqual(["fifo-1", "fifo-2", "fifo-3"], order)
        self.assertFalse(overlap.is_set(), "command executions overlapped")
        results = self._drain_results(self.runner, {"send_result"})
        self.assertEqual(
            ["fifo-1", "fifo-2", "fifo-3"],
            [body["request_id"] for body in results],
        )
        self.assertFalse(worker.is_alive())

    def test_duplicate_command_coalesces_while_in_flight(self) -> None:
        worker = self.runner._start_command_worker()
        try:
            self._send_dm_command("dup-1")
            self.assertTrue(self.client.send_entered.wait(timeout=PROMPT_SECS))
            started = time.monotonic()
            for _ in range(3):
                self._send_dm_command("dup-1")  # identical retransmits
            self.assertLess(time.monotonic() - started, PROMPT_SECS)
            self.assertEqual(
                1, len(self.client.send_calls),
                "duplicate executed while original in flight",
            )
            self.client.release_send.set()
            deadline = time.monotonic() + PROMPT_SECS
            results: list[dict] = []
            while time.monotonic() < deadline and not results:
                results = self._drain_results(self.runner, {"send_result"})
                if not results:
                    threading.Event().wait(0.01)
            self.assertEqual(1, len(results))
            self.assertEqual("dup-1", results[0]["request_id"])
        finally:
            self.client.release_send.set()
            self.runner._stop.set()
            self.runner._stop_command_worker(worker)
        self.assertEqual(1, len(self.client.send_calls))

    def test_full_command_queue_rejects_explicitly_and_rolls_back(self) -> None:
        # One slot: first command occupies the worker, second fills the
        # queue, third must be rejected without blocking the reader.
        self.runner._command_q = queue.Queue(maxsize=1)
        worker = threading.Thread(
            target=self.runner._command_worker_loop, daemon=True
        )
        worker.start()
        try:
            self._send_dm_command("q-1")
            self.assertTrue(self.client.send_entered.wait(timeout=PROMPT_SECS))
            self._send_dm_command("q-2")
            started = time.monotonic()
            self._send_dm_command("q-3")
            self.assertLess(time.monotonic() - started, PROMPT_SECS)

            rejected = self._drain_results(self.runner, {"error"})
            self.assertEqual(1, len(rejected), "queue-full rejection missing")
            self.assertEqual("q-3", rejected[0]["request_id"])
            self.assertEqual(
                {"error": "runner command queue is full"},
                rejected[0]["outcome"],
            )
            # Rollback: the rejected request_id is not remembered, so a
            # retransmit executes fresh once the backlog drains.
            self.assertNotIn(("direct:" + self.sender, "q-3"), self.runner._replay)
            self.assertEqual(
                1, len(self.client.send_calls), "rejected command executed"
            )

            self.client.release_send.set()
            deadline = time.monotonic() + PROMPT_SECS
            while time.monotonic() < deadline and len(self.client.send_calls) < 2:
                threading.Event().wait(0.01)
            self._send_dm_command("q-3")  # retransmit after drain
            deadline = time.monotonic() + PROMPT_SECS
            while time.monotonic() < deadline and len(self.client.send_calls) < 3:
                threading.Event().wait(0.01)
        finally:
            self.client.release_send.set()
            self.runner._stop.set()
            self.runner._stop_command_worker(worker)
        self.assertEqual(
            ["q-1", "q-2", "q-3"],
            [call[1].decode().split("|")[2] for call in self.client.send_calls],
        )

    def test_shutdown_cleans_worker_and_aborts_queued_commands(self) -> None:
        worker = self.runner._start_command_worker()
        self._send_dm_command("sd-1")
        self.assertTrue(self.client.send_entered.wait(timeout=PROMPT_SECS))
        self._send_dm_command("sd-2")  # queued behind the active send

        self.runner._stop.set()
        self.client.release_send.set()  # active command finishes inside bound
        with self.assertLogs("runner[nyc]", level="WARNING") as captured:
            self.runner._stop_command_worker(worker)

        self.assertFalse(worker.is_alive(), "worker survived shutdown")
        self.assertEqual(
            1, len(self.client.send_calls), "queued command ran after shutdown"
        )
        logs = "\n".join(captured.output)
        self.assertIn("aborted 1 queued commands at shutdown", logs)
        # Aborted entry rolled back: retransmit would be admitted fresh.
        self.assertNotIn(("direct:" + self.sender, "sd-2"), self.runner._replay)

    def test_admission_after_stop_is_rejected_not_lost(self) -> None:
        # A reader still finishing an SSE event after shutdown began
        # must not enqueue a command that no worker will ever run:
        # admission is rejected explicitly — error result, replay
        # rollback, warning log — instead of vanishing silently.
        worker = self.runner._start_command_worker()
        try:
            self.runner._stop.set()
            started = time.monotonic()
            with self.assertLogs("runner[nyc]", level="WARNING") as captured:
                self._send_dm_command("late-1")
            self.assertLess(time.monotonic() - started, PROMPT_SECS)
        finally:
            self.client.release_send.set()
            self.runner._stop_command_worker(worker)

        self.assertFalse(worker.is_alive())
        self.assertEqual(
            [], self.client.send_calls, "post-stop command must not execute"
        )
        rejected = self._drain_results(self.runner, {"error"})
        self.assertEqual(1, len(rejected), "post-stop rejection missing")
        self.assertEqual("late-1", rejected[0]["request_id"])
        self.assertEqual(
            {"error": "runner is shutting down"}, rejected[0]["outcome"]
        )
        # Rejection rolled the admitted entry back; nothing lingers.
        self.assertNotIn(("direct:" + self.sender, "late-1"), self.runner._replay)
        logs = "\n".join(captured.output)
        self.assertIn("late-1", logs)
        self.assertIn("shutting down", logs)

    def test_shutdown_join_timeout_still_aborts_queued_commands(self) -> None:
        # The join-timeout branch: a worker stuck in an active command
        # past the result budget must not block the queued-command
        # rollback. _NeverJoins stands in for that stuck worker so the
        # branch is exercised deterministically, not after 30 wall
        # seconds of a real join timeout.
        class _NeverJoins:
            def join(self, timeout=None):
                return None

            def is_alive(self):
                return True

        self.runner._command_q = queue.Queue(maxsize=self.mod.COMMAND_QUEUE_MAX)
        self._send_dm_command("stuck-1")  # admitted, queued, no consumer
        self.runner._stop.set()
        with self.assertLogs("runner[nyc]", level="WARNING") as captured:
            self.runner._stop_command_worker(_NeverJoins())

        logs = "\n".join(captured.output)
        self.assertIn("left a bounded active command running", logs)
        self.assertIn("aborted 1 queued commands at shutdown", logs)
        # Aborted entry rolled back: retransmit would be admitted fresh.
        self.assertNotIn(
            ("direct:" + self.sender, "stuck-1"), self.runner._replay
        )
        self.assertEqual([], self.client.send_calls)


if __name__ == "__main__":
    unittest.main()
