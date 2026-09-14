import base64
import json
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from result_framing import (
    CHUNK_BYTES, DM_MAX_BYTES, MAX_BUFFERED_BYTES, MAX_REQUESTS, MAX_RESULT_BYTES,
    MAX_TOMBSTONES, MAX_TRANSFERS,
    RESULT_PREFIX_V1, RESULT_PREFIX_V2,
    ResultReassembler, frame_result,
)


class Clock:
    now = 10.0
    def __call__(self):
        return self.now


def result(request_id: str, size: int = 60_000) -> bytes:
    return json.dumps({"kind": "api_result", "request_id": request_id,
                       "details": {"body": "x" * size}}).encode()


class ResultFramingTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.rx = ResultReassembler(self.clock)
        self.rx.register("r1", ["sender-a"], 20.0)

    def test_large_result_frames_under_dm_limit_and_reassembles_once(self):
        payload = result("r1")
        self.assertGreater(len(RESULT_PREFIX_V1 + base64.b64encode(payload)), DM_MAX_BYTES)
        frames = frame_result(payload, "t1", "r1")
        self.assertGreater(len(frames), 1)
        self.assertTrue(all(len(frame) <= DM_MAX_BYTES for frame in frames))
        delivered = [self.rx.accept("sender-a", f) for f in reversed(frames)]
        values = [v for v in delivered if v is not None]
        self.assertEqual(1, len(values))
        self.assertEqual(json.loads(payload), values[0])
        self.assertIsNone(self.rx.accept("sender-a", frames[0]))

    def test_near_maximum_result_reassembles(self):
        payload = result("r1", MAX_RESULT_BYTES - 256)
        self.assertLessEqual(len(payload), MAX_RESULT_BYTES)
        frames = frame_result(payload, "near-limit", "r1")
        values = [self.rx.accept("sender-a", frame) for frame in frames]
        self.assertEqual(json.loads(payload), next(v for v in values if v is not None))

    def test_sender_request_deadline_and_missing_chunk_are_fenced(self):
        frames = frame_result(result("r1"), "t1", "r1")
        self.assertIsNone(self.rx.accept("wrong-sender", frames[0]))
        self.assertIsNone(self.rx.accept("sender-a", frames[0]))
        self.clock.now = 21.0
        for frame in frames[1:]:
            self.assertIsNone(self.rx.accept("sender-a", frame))
        self.assertEqual({}, self.rx.transfers)
        self.assertEqual(0, self.rx.buffered)

    def test_duplicate_registration_does_not_extend_lifetime(self):
        self.assertTrue(self.rx.register("r1", ["sender-a"], 200.0))
        self.clock.now = 21.0
        frames = frame_result(result("r1"), "late", "r1")
        self.assertTrue(all(self.rx.accept("sender-a", frame) is None for frame in frames))

    def test_pending_request_is_armed_after_dispatch_and_keeps_early_chunks(self):
        rx = ResultReassembler(self.clock)
        self.assertTrue(rx.register_pending("during-dispatch", ["sender-a"], 100.0))
        frames = frame_result(
            result("during-dispatch"), "pending", "during-dispatch",
        )
        self.assertIsNone(rx.accept("sender-a", frames[0]))
        self.clock.now = 15.0
        self.assertTrue(rx.arm("during-dispatch", 20.0))
        values = [rx.accept("sender-a", frame) for frame in frames[1:]]
        self.assertEqual(1, sum(value is not None for value in values))
        self.assertFalse(rx.arm("during-dispatch", 30.0))

    def test_parallel_chunk_delivery_is_serialized(self):
        frames = frame_result(result("r1"), "parallel", "r1")
        delivered = []
        delivered_lock = threading.Lock()

        def accept(frame):
            value = self.rx.accept("sender-a", frame)
            if value is not None:
                with delivered_lock:
                    delivered.append(value)

        threads = [threading.Thread(target=accept, args=(frame,)) for frame in frames]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(1, len(delivered))

    def test_conflicting_duplicate_and_metadata_reject_transfer(self):
        frames = frame_result(result("r1"), "t1", "r1")
        self.assertIsNone(self.rx.accept("sender-a", frames[0]))
        raw = json.loads(base64.b64decode(frames[0][len(RESULT_PREFIX_V2):]))
        raw["data"] = base64.b64encode(b"different").decode()
        conflict = b"x0xtest|res2|" + base64.b64encode(
            json.dumps(raw, separators=(",", ":")).encode()
        )
        self.assertIsNone(self.rx.accept("sender-a", conflict))
        self.assertEqual({}, self.rx.transfers)

        wrong_body = frame_result(result("another-request"), "t2", "r1")
        delivered = [self.rx.accept("sender-a", frame) for frame in wrong_body]
        self.assertTrue(all(value is None for value in delivered))

    def test_transfer_and_aggregate_caps_are_bounded(self):
        for i in range(MAX_TRANSFERS):
            rid = f"r{i}"
            self.rx.register(rid, ["sender-a"], 20.0)
            frame = frame_result(result(rid), f"t{i}", rid)[0]
            self.assertIsNone(self.rx.accept("sender-a", frame))
        self.rx.register("overflow", ["sender-a"], 20.0)
        self.rx.accept("sender-a", frame_result(result("overflow"), "overflow", "overflow")[0])
        self.assertLessEqual(len(self.rx.transfers), MAX_TRANSFERS)
        self.assertLessEqual(self.rx.buffered, MAX_BUFFERED_BYTES)

        limited = ResultReassembler(self.clock, max_buffered_bytes=CHUNK_BYTES * 2)
        for i in range(3):
            rid = f"limited-{i}"
            self.assertTrue(limited.register(rid, ["sender-a"], 20.0))
            limited.accept("sender-a", frame_result(result(rid), rid, rid)[0])
        self.assertEqual(CHUNK_BYTES * 2, limited.buffered)
        self.assertEqual(2, len(limited.transfers))

    def test_strict_metadata_and_declared_total_are_checked_before_buffering(self):
        frame = frame_result(result("r1"), "strict", "r1")[0]
        original = json.loads(base64.b64decode(frame[len(RESULT_PREFIX_V2):]))
        for field, value in (
            ("v", 1), ("index", "0"), ("count", 2.0), ("total", True),
        ):
            raw = dict(original)
            raw[field] = value
            invalid_type = RESULT_PREFIX_V2 + base64.b64encode(
                json.dumps(raw, separators=(",", ":")).encode()
            )
            self.assertIsNone(self.rx.accept("sender-a", invalid_type))
            self.assertEqual(0, self.rx.buffered)

        raw = dict(original)
        raw["index"] = 0
        raw["total"] = 1
        undersized_total = RESULT_PREFIX_V2 + base64.b64encode(
            json.dumps(raw, separators=(",", ":")).encode()
        )
        self.assertIsNone(self.rx.accept("sender-a", undersized_total))
        self.assertEqual(0, self.rx.buffered)

    def test_wire_and_request_metadata_are_bounded(self):
        frame = frame_result(result("r1"), "t1", "r1")[0]
        self.assertIsNone(self.rx.accept("sender-a", frame + b"x" * DM_MAX_BYTES))
        for i in range(MAX_REQUESTS + 10):
            self.assertTrue(self.rx.register(f"bounded-{i}", ["sender-a"], 30.0 + i))
        self.assertEqual(MAX_REQUESTS, len(self.rx.requests))
        self.assertFalse(self.rx.register("x" * 257, ["sender-a"], 50.0))
        self.assertFalse(self.rx.register("valid", [], 50.0))

    def test_completed_tombstones_are_bounded(self):
        for i in range(MAX_TOMBSTONES + 10):
            rid = f"complete-{i}"
            self.assertTrue(self.rx.register(rid, ["sender-a"], 20.0 + i))
            payload = result(rid, size=1)
            frames = frame_result(payload, f"transfer-{i}", rid)
            values = [self.rx.accept("sender-a", frame) for frame in frames]
            self.assertEqual(1, sum(value is not None for value in values))
        self.assertEqual(MAX_TOMBSTONES, len(self.rx.completed))


if __name__ == "__main__":
    unittest.main()
