#!/usr/bin/env python3
"""Focused tests for the VPS mesh test runner."""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import queue
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


class FakeClient:
    def __init__(self) -> None:
        self.next_id = 1
        self.published: list[tuple[str, bytes]] = []
        self.subscribed: list[str] = []
        self.unsubscribed: list[str] = []
        self.direct: list[tuple[str, bytes]] = []
        self.direct_error_code: int | None = None

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
        self.assertGreaterEqual(len(client.direct), self.runner_mod.PUBLISH_RETRY_MAX)
        self.assertEqual(self.runner_mod.LEGACY_RESULTS_TOPIC, client.published[0][0])
        logs = "\n".join(captured.output)
        self.assertEqual(
            self.runner_mod.PUBLISH_RETRY_MAX,
            logs.count("stage=wire_complete"),
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

    def test_result_stage_logs_queue_wait_and_owned_publish_completion(self) -> None:
        from unittest.mock import patch

        entered = threading.Event()
        release = threading.Event()

        class StagedClient(FakeClient):
            def direct_send(self, target_aid, payload, **kwargs):
                entered.set()
                if not release.wait(timeout=2.0):
                    raise TimeoutError("fixture release missing")
                return super().direct_send(target_aid, payload, **kwargs)

        runner = self.runner_mod.TestRunner("sin", StagedClient())
        envelope = {
            "kind": "api_result",
            "request_id": "request-7",
            "command_id": "command-7",
            "details": {"token": "must-not-log"},
        }
        with patch.object(
            self.runner_mod.time,
            "monotonic",
            side_effect=[10.0, 12.0, 13.0, 15.0, 16.0],
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
        self.assertEqual(calls[0][1], calls[1][1])
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
