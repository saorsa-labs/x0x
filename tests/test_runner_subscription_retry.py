#!/usr/bin/env python3
"""Offline controls for the control-topic subscription retry liveness fix.

A runner whose POST /subscribe fails (daemon restart, 5xx, malformed
response) must NOT enter the long-lived /events SSE session with a
missing subscription: it would silently miss discover commands for up
to six hours, deferring recovery to the next accidental SSE disconnect.
These tests pin the contract that both required control topics must
return a usable subscription_id before /events opens, and that the
control listener retries through its bounded backoff until they do.
They also pin the stale-subscription swap lifecycle: a tracked id is
retired only after its DELETE succeeds or the daemon proves it absent
(404 — the daemon's subscription map is in-process, wiped on restart),
so an ambiguous delete neither loses the tracked handle nor creates a
duplicate replacement subscriber.
"""

from __future__ import annotations

import importlib.util
import io
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


def load_runner():
    script = Path(__file__).parent / "runners" / "x0x_test_runner.py"
    spec = importlib.util.spec_from_file_location("x0x_test_runner", script)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def service_unavailable() -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "http://127.0.0.1:12600/subscribe", 503, "Service Unavailable",
        {}, io.BytesIO(b"{}"),
    )


def subscription_not_found() -> urllib.error.HTTPError:
    """The daemon's DELETE /subscribe/:id answer for an unknown id.

    Mirrors src/server/routes/messaging.rs `unsubscribe`: the id map is
    in-process, so a daemon restart makes every pre-restart id answer
    404 {"ok": false, "error": "subscription not found"}.
    """
    return urllib.error.HTTPError(
        "http://127.0.0.1:12600/subscribe/sub-1", 404, "Not Found",
        {}, io.BytesIO(b'{"ok": false, "error": "subscription not found"}'),
    )


class ScriptedClient:
    """Fake X0xClient scripting per-call subscribe and delete outcomes.

    Outcomes are consumed in call order: "ok" succeeds (a fresh valid
    subscription id for subscribe, the daemon's {"ok": true} delete
    confirmation for unsubscribe), an Exception instance is raised, and
    any other value is returned verbatim as the response body
    (malformed-response controls). Once a script runs out, calls
    succeed. `unsubscribed` records only ids whose DELETE returned 2xx.
    """

    def __init__(self, subscribe_outcomes=None, journal=None,
                 unsubscribe_outcomes=None) -> None:
        self.next_id = 1
        self.subscribe_outcomes = list(subscribe_outcomes or [])
        self.unsubscribe_outcomes = list(unsubscribe_outcomes or [])
        self.journal = journal if journal is not None else []
        self.unsubscribed: list[str] = []

    def subscribe(self, topic: str) -> dict:
        self.journal.append(("subscribe", topic))
        outcome = (
            self.subscribe_outcomes.pop(0)
            if self.subscribe_outcomes
            else "ok"
        )
        if isinstance(outcome, Exception):
            raise outcome
        if outcome == "ok":
            sub_id = f"sub-{self.next_id}"
            self.next_id += 1
            return {"subscription_id": sub_id}
        return outcome

    def unsubscribe(self, subscription_id: str) -> dict:
        self.journal.append(("unsubscribe", subscription_id))
        outcome = (
            self.unsubscribe_outcomes.pop(0)
            if self.unsubscribe_outcomes
            else "ok"
        )
        if isinstance(outcome, Exception):
            raise outcome
        if outcome == "ok":
            self.unsubscribed.append(subscription_id)
            return {"ok": True}
        return outcome


class RunnerSubscriptionRetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = load_runner()

    def _runner(self, client) -> "self.mod.TestRunner":
        return self.mod.TestRunner("nyc", client)

    def _drive_control_listener(self, runner, journal, sessions=1) -> list:
        """Run _control_listener_loop with /events stubbed.

        The stub records each SSE open in the shared journal and stops
        the loop after `sessions` successful sessions, so the returned
        journal shows exactly when /events was (not) opened relative to
        every subscribe/unsubscribe attempt.
        """
        opened = []

        def fake_consume_sse(path, handler=None, label=None):
            opened.append(path)
            journal.append(("sse", path))
            if len(opened) >= sessions:
                runner._stop.set()

        runner._consume_sse = fake_consume_sse
        with mock.patch.object(self.mod, "SSE_RECONNECT_BACKOFF_SECS", 0):
            runner._control_listener_loop()
        return opened

    def test_request_failure_retries_and_defers_sse(self) -> None:
        # Iteration 1: both required topics fail with daemon 5xx. The
        # runner must treat that as an iteration failure and retry via
        # the bounded backoff — /events must not open until BOTH topics
        # have a live subscription.
        journal: list = []
        client = ScriptedClient(
            [service_unavailable(), service_unavailable()], journal,
        )
        runner = self._runner(client)

        opened = self._drive_control_listener(runner, journal)

        self.assertEqual(
            [
                ("subscribe", self.mod.DISCOVER_TOPIC),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                ("subscribe", self.mod.DISCOVER_TOPIC),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                ("sse", "/events"),
            ],
            journal,
        )
        self.assertEqual(["/events"], opened)
        self.assertEqual(
            {self.mod.DISCOVER_TOPIC, self.mod.LEGACY_CONTROL_TOPIC},
            set(runner._subscription_ids),
        )

    def test_malformed_response_is_failure_not_success(self) -> None:
        # A 200 response without a usable subscription_id is NOT a
        # subscribed topic: accepting it would open a six-hour SSE
        # session for a subscription the daemon never registered.
        malformed_responses = [
            {},
            {"subscription_id": 42},
            {"subscription_id": ""},
        ]
        for bad in malformed_responses:
            with self.subTest(bad=bad):
                journal: list = []
                client = ScriptedClient([bad, bad], journal)
                runner = self._runner(client)

                opened = self._drive_control_listener(runner, journal)

                self.assertEqual(
                    [
                        ("subscribe", self.mod.DISCOVER_TOPIC),
                        ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                        ("subscribe", self.mod.DISCOVER_TOPIC),
                        ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                        ("sse", "/events"),
                    ],
                    journal,
                )
                self.assertEqual(["/events"], opened)
                tracked = runner._subscription_ids
                self.assertEqual(2, len(tracked))
                self.assertTrue(
                    all(isinstance(v, str) and v for v in tracked.values())
                )

    def test_partial_success_is_swapped_not_leaked(self) -> None:
        # Iteration 1: DISCOVER succeeds, LEGACY fails. The iteration
        # fails overall (no SSE), and the partially successful
        # subscription must stay tracked so the retry retires it with a
        # successful delete and swaps in exactly one replacement — no
        # lost tracked handle, no tracked duplicate. (Server-side
        # at-most-one is only guaranteed for tracked ids: a 2xx
        # subscribe whose body carries no usable id can create an
        # untracked subscription this runner cannot address — see
        # test_malformed_response_is_failure_not_success.)
        journal: list = []
        client = ScriptedClient(["ok", service_unavailable()], journal)
        runner = self._runner(client)

        opened = self._drive_control_listener(runner, journal)

        # Iteration 1 stores sub-1 for DISCOVER only; iteration 2
        # retires it before resubscribing, then registers LEGACY.
        self.assertEqual(
            [
                ("subscribe", self.mod.DISCOVER_TOPIC),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                ("unsubscribe", "sub-1"),
                ("subscribe", self.mod.DISCOVER_TOPIC),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                ("sse", "/events"),
            ],
            journal,
        )
        self.assertEqual(["/events"], opened)
        self.assertEqual(["sub-1"], client.unsubscribed)
        self.assertEqual(
            {
                self.mod.DISCOVER_TOPIC: "sub-2",
                self.mod.LEGACY_CONTROL_TOPIC: "sub-3",
            },
            runner._subscription_ids,
        )

    def test_success_path_opens_sse_once_without_churn(self) -> None:
        # Existing happy path is unchanged: first try subscribes both
        # topics, opens /events once, and swaps nothing.
        journal: list = []
        client = ScriptedClient(journal=journal)
        runner = self._runner(client)

        opened = self._drive_control_listener(runner, journal)

        self.assertEqual(
            [
                ("subscribe", self.mod.DISCOVER_TOPIC),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                ("sse", "/events"),
            ],
            journal,
        )
        self.assertEqual(["/events"], opened)
        self.assertEqual([], client.unsubscribed)

    def test_subscribe_control_topics_raises_on_request_failure(self) -> None:
        client = ScriptedClient([service_unavailable(), "ok"])
        runner = self._runner(client)

        with self.assertRaises(RuntimeError) as ctx:
            runner._subscribe_control_topics()

        message = str(ctx.exception)
        self.assertIn("control-topic subscription incomplete", message)
        self.assertIn(self.mod.DISCOVER_TOPIC, message)
        # The failed topic (DISCOVER, scripted first) stays unregistered
        # even though LEGACY succeeded: one topic failing is fatal.
        self.assertIn(
            self.mod.LEGACY_CONTROL_TOPIC, runner._subscription_ids
        )
        self.assertNotIn(self.mod.DISCOVER_TOPIC, runner._subscription_ids)

    def test_subscribe_control_topics_raises_on_malformed_response(self) -> None:
        client = ScriptedClient([{"topic": "no-id-here"}, "ok"])
        runner = self._runner(client)

        with self.assertRaises(RuntimeError) as ctx:
            runner._subscribe_control_topics()

        self.assertIn("missing subscription_id", str(ctx.exception))

    def test_subscribe_control_topics_disabled_is_noop(self) -> None:
        journal: list = []
        client = ScriptedClient(journal=journal)
        runner = self._runner(client)
        runner._pubsub_disabled_after_discover = True

        self.assertIsNone(runner._subscribe_control_topics())

        self.assertEqual([], journal)
        self.assertEqual({}, runner._subscription_ids)


    def test_ambiguous_delete_retains_handle_and_blocks_replacement(self) -> None:
        # Failure-then-success deletion control (r1 review): popping the
        # old id before its DELETE settled let a failed delete plus a
        # successful subscribe lose the handle and orphan a live
        # subscriber on every retry. An ambiguous delete (5xx — the id
        # may still be live daemon-side) must retain the tracked id and
        # fail that topic with NO replacement create; the bounded retry
        # re-attempts the SAME delete.
        journal: list = []
        client = ScriptedClient(journal=journal)
        runner = self._runner(client)
        runner._subscribe_control_topics()
        self.assertEqual(
            {
                self.mod.DISCOVER_TOPIC: "sub-1",
                self.mod.LEGACY_CONTROL_TOPIC: "sub-2",
            },
            runner._subscription_ids,
        )

        # Iteration 2: DISCOVER's delete fails ambiguously; LEGACY's
        # delete succeeds and swaps cleanly.
        client.unsubscribe_outcomes = [service_unavailable()]
        with self.assertRaises(RuntimeError) as ctx:
            runner._subscribe_control_topics()

        self.assertIn("unsubscribe stale sub-1 failed", str(ctx.exception))
        # No lost handle: sub-1 stays tracked through the ambiguity.
        self.assertEqual(
            "sub-1", runner._subscription_ids[self.mod.DISCOVER_TOPIC]
        )
        # No duplicate create: DISCOVER was not resubscribed while its
        # delete was unresolved — only LEGACY swapped in iteration 2.
        self.assertEqual(
            [
                ("subscribe", self.mod.DISCOVER_TOPIC),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                ("unsubscribe", "sub-1"),
                ("unsubscribe", "sub-2"),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
            ],
            journal,
        )
        self.assertEqual(["sub-2"], client.unsubscribed)

        # Iteration 3: the SAME delete is retried, succeeds, and only
        # then is the replacement created.
        runner._subscribe_control_topics()
        self.assertEqual(
            [
                ("subscribe", self.mod.DISCOVER_TOPIC),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                ("unsubscribe", "sub-1"),
                ("unsubscribe", "sub-2"),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                ("unsubscribe", "sub-1"),
                ("subscribe", self.mod.DISCOVER_TOPIC),
                ("unsubscribe", "sub-3"),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
            ],
            journal,
        )
        self.assertEqual(["sub-2", "sub-1", "sub-3"], client.unsubscribed)
        self.assertEqual(
            {
                self.mod.DISCOVER_TOPIC: "sub-4",
                self.mod.LEGACY_CONTROL_TOPIC: "sub-5",
            },
            runner._subscription_ids,
        )

    def test_ambiguous_delete_backoff_keeps_sse_closed(self) -> None:
        # End-to-end through the control listener's bounded backoff:
        # while DISCOVER's stale delete keeps failing ambiguously,
        # /events must stay closed and no replacement DISCOVER subscribe
        # may run; the loop keeps re-attempting the same delete until it
        # succeeds, then subscribes exactly one replacement.
        journal: list = []
        client = ScriptedClient(
            subscribe_outcomes=[
                "ok",                      # it1: DISCOVER -> sub-1
                service_unavailable(),     # it1: LEGACY fails
                "ok",                      # it2: LEGACY (untracked) -> sub-2
                "ok",                      # it3: DISCOVER -> sub-3
                "ok",                      # it3: LEGACY -> sub-4
            ],
            unsubscribe_outcomes=[
                service_unavailable(),     # it2: delete sub-1 ambiguous
                "ok",                      # it3: delete sub-1
                "ok",                      # it3: delete sub-2
            ],
            journal=journal,
        )
        runner = self._runner(client)

        opened = self._drive_control_listener(runner, journal)

        self.assertEqual(
            [
                ("subscribe", self.mod.DISCOVER_TOPIC),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                ("unsubscribe", "sub-1"),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                ("unsubscribe", "sub-1"),
                ("subscribe", self.mod.DISCOVER_TOPIC),
                ("unsubscribe", "sub-2"),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                ("sse", "/events"),
            ],
            journal,
        )
        self.assertEqual(["/events"], opened)
        self.assertEqual(["sub-1", "sub-2"], client.unsubscribed)
        self.assertEqual(
            {
                self.mod.DISCOVER_TOPIC: "sub-3",
                self.mod.LEGACY_CONTROL_TOPIC: "sub-4",
            },
            runner._subscription_ids,
        )

    def test_daemon_restart_404_is_idempotent_recovery(self) -> None:
        # Absent-after-daemon-restart control (r1 review): the daemon's
        # subscription map is in-process, so after a restart every
        # pre-restart id answers DELETE with 404 "subscription not
        # found". That is the backend PROVING the id absent — it must
        # count as idempotent success so the runner resubscribes and
        # reopens /events in the same iteration instead of stalling in
        # the ambiguous-delete path.
        journal: list = []
        client = ScriptedClient(
            unsubscribe_outcomes=[subscription_not_found(), subscription_not_found()],
            journal=journal,
        )
        runner = self._runner(client)

        opened = self._drive_control_listener(runner, journal, sessions=2)

        self.assertEqual(
            [
                ("subscribe", self.mod.DISCOVER_TOPIC),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                ("sse", "/events"),
                ("unsubscribe", "sub-1"),
                ("subscribe", self.mod.DISCOVER_TOPIC),
                ("unsubscribe", "sub-2"),
                ("subscribe", self.mod.LEGACY_CONTROL_TOPIC),
                ("sse", "/events"),
            ],
            journal,
        )
        self.assertEqual(["/events", "/events"], opened)
        # Both deletes answered 404, never a 2xx delete confirmation.
        self.assertEqual([], client.unsubscribed)
        self.assertEqual(
            {
                self.mod.DISCOVER_TOPIC: "sub-3",
                self.mod.LEGACY_CONTROL_TOPIC: "sub-4",
            },
            runner._subscription_ids,
        )


if __name__ == "__main__":
    unittest.main()
