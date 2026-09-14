import importlib.util
import json
import logging
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests.result_framing import frame_result


def load_groups():
    tests_dir = Path(__file__).parent
    sys.path.insert(0, str(tests_dir))
    spec = importlib.util.spec_from_file_location(
        "e2e_vps_groups", tests_dir / "e2e_vps_groups.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class GroupDispatchDeadlineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.groups = load_groups()

    def test_response_window_starts_after_delayed_command_dispatch(self):
        clock = [1_000.0]
        router = self.groups.ResultRouter(logging.getLogger("group-deadline"))
        target_aid = "b" * 64

        class Client:
            attempts = 0

            def direct_send(inner_self, _target, _wire):
                inner_self.attempts += 1
                clock[0] += 15.0
                if inner_self.attempts < 5:
                    raise OSError("delayed command dispatch")
                envelope = {
                    "kind": "contact_list_result", "request_id": request_id,
                    "outcome": "ok", "details": {},
                }
                frames = frame_result(
                    json.dumps(envelope).encode(), "during-dispatch", request_id,
                )
                for frame in frames:
                    router.deliver_chunk(target_aid, frame)
                return {"ok": True}

        request_id = None
        original_register = router.register_pending

        def capture_register(waiter, sender, deadline):
            nonlocal request_id
            request_id = waiter.request_id
            return original_register(waiter, sender, deadline)

        router.register_pending = capture_register
        harness = self.groups.FleetHarness(
            Client(), router, "a" * 64, "anchor",
            {"remote": self.groups.Runner("remote", target_aid, "machine")},
            logging.getLogger("group-deadline"), cmd_timeout_secs=30,
        )

        def fake_sleep(seconds):
            clock[0] += seconds

        router._chunks.clock = lambda: clock[0]
        with mock.patch.object(self.groups.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(self.groups.time, "sleep", side_effect=fake_sleep):
            response = harness.call("remote", "contact_list")
        self.assertEqual("ok", response["outcome"])
        self.assertEqual(95.0, clock[0] - 1_000.0)


if __name__ == "__main__":
    unittest.main()
