import base64
import importlib.util
import json
import logging
import sys
import time
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


class GroupDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.groups = load_groups()

    def test_targeted_direct_discovery_reports_channel_and_latency(self):
        groups = self.groups
        router = groups.ResultRouter(logging.getLogger("groups-discovery-direct"))

        class Client:
            sent = []
            published = []

            def direct_send(self, aid, wire, **kwargs):
                self.sent.append((aid, wire, kwargs))
                command = json.loads(base64.b64decode(wire[len(groups.PREFIX_CMD):]))
                router.deliver({
                    "kind": "discover_reply", "node": command["target_node"],
                    "agent_id": aid, "machine_id": "machine",
                    "request_id": command["params"]["request_id"],
                }, aid)
                return {"ok": True}

            def publish(self, topic, payload):
                self.published.append((topic, payload))

        client = Client()
        with self.assertLogs("groups-discovery-direct", level=logging.INFO) as logs:
            found = groups.discover_runners(
                client, router, "a" * 64, "nyc", ["sfo", "sydney"], 1,
                logging.getLogger("groups-discovery-direct"),
                runner_agent_ids={"sfo": "b" * 64, "sydney": "c" * 64},
            )
        self.assertEqual({"sfo", "sydney"}, set(found))
        self.assertEqual([], client.published)
        self.assertEqual(2, len(client.sent))
        request_ids = set()
        for aid, wire, kwargs in client.sent:
            self.assertTrue(wire.startswith(groups.PREFIX_CMD))
            command = json.loads(base64.b64decode(wire[len(groups.PREFIX_CMD):]))
            self.assertIn(command["target_node"], found)
            self.assertEqual(found[command["target_node"]].agent_id, aid)
            self.assertEqual(command["command_id"], command["params"]["request_id"])
            self.assertLess(kwargs["timeout"], 1)
            request_ids.add(command["command_id"])
        self.assertEqual(2, len(request_ids))
        self.assertEqual(2, sum("channel=direct" in line for line in logs.output))
        self.assertRegex("\n".join(logs.output), r"announce_reply_latency_ms=[0-9]+\.[0-9]+")

    def test_direct_ack_without_reply_falls_back_only_after_interval(self):
        groups = self.groups
        router = groups.ResultRouter(logging.getLogger("groups-discovery-fallback"))

        class Client:
            sent = []
            published = []

            def direct_send(self, aid, wire, **_kwargs):
                self.sent.append((aid, wire))
                return {"ok": True}

            def publish(self, topic, payload):
                self.published.append((topic, payload))
                command = json.loads(payload)
                router.deliver({
                    "kind": "discover_reply", "node": command["target_node"],
                    "agent_id": "b" * 64, "machine_id": "machine",
                    "request_id": command["params"]["request_id"],
                }, "b" * 64)

        client = Client()
        start = time.monotonic()
        with self.assertLogs("groups-discovery-fallback", level=logging.INFO) as logs:
            found = groups.discover_runners(
                client, router, "a" * 64, "nyc", ["sfo"], 1,
                logging.getLogger("groups-discovery-fallback"),
                runner_agent_ids={"sfo": "b" * 64},
                republish_every_secs=0.05,
            )
        self.assertGreaterEqual(time.monotonic() - start, 0.04)
        self.assertEqual("sfo", found["sfo"].name)
        self.assertEqual(1, len(client.sent))
        self.assertEqual(1, len(client.published))
        command = json.loads(client.published[0][1])
        self.assertEqual("sfo", command["target_node"])
        self.assertEqual(command["command_id"], command["params"]["request_id"])
        self.assertIn("node=sfo channel=pubsub", "\n".join(logs.output))

    def test_missing_or_self_id_uses_targeted_pubsub(self):
        groups = self.groups
        for ids in ({}, {"sfo": "invalid"}, {"sfo": "a" * 64}):
            with self.subTest(ids=ids):
                router = groups.ResultRouter(logging.getLogger("groups-discovery-id"))

                class Client:
                    sent = []
                    published = []

                    def direct_send(self, aid, wire, **_kwargs):
                        self.sent.append((aid, wire))
                        return {"ok": True}

                    def publish(self, topic, payload):
                        self.published.append((topic, payload))
                        command = json.loads(payload)
                        router.deliver({
                            "kind": "discover_reply", "node": "sfo",
                            "agent_id": "b" * 64,
                            "request_id": command["params"]["request_id"],
                        }, "b" * 64)

                client = Client()
                found = groups.discover_runners(
                    client, router, "a" * 64, "nyc", ["sfo"], 1,
                    logging.getLogger("groups-discovery-id"), runner_agent_ids=ids,
                )
                self.assertIn("sfo", found)
                self.assertEqual([], client.sent)
                self.assertEqual(groups.DISCOVER_TOPIC, client.published[0][0])
                self.assertEqual("sfo", json.loads(client.published[0][1])["target_node"])

    def test_lookup_closes_owned_tunnel_after_agent_failure(self):
        groups = self.groups
        handle = mock.Mock()
        with mock.patch.object(groups, "start_ssh_tunnel", return_value=handle), \
             mock.patch.object(groups, "stop_ssh_tunnel") as stop, \
             mock.patch.object(groups, "X0xClient") as client_type:
            client_type.return_value.agent.side_effect = OSError("API unavailable")
            ids = groups.lookup_runner_agents(
                ["nyc", "sfo"], "nyc", "a" * 64,
                {"sfo": ("sfo.invalid", "token")}, 13600,
                logging.getLogger("groups-discovery-lookup"),
            )
        self.assertEqual({"nyc": "a" * 64}, ids)
        stop.assert_called_once_with(handle)


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

    def test_valid_result_stops_retries_when_command_ack_is_lost(self):
        router = self.groups.ResultRouter(logging.getLogger("group-ack-result"))
        target_aid = "b" * 64
        request_id = None

        class Client:
            attempts = 0

            def direct_send(inner_self, _target, _wire):
                inner_self.attempts += 1
                router.deliver(
                    {
                        "kind": "contact_list_result",
                        "request_id": request_id,
                        "outcome": "ok",
                    },
                    target_aid,
                )
                raise TimeoutError("command ack lost")

        original_register = router.register_pending

        def capture_register(waiter, sender, deadline):
            nonlocal request_id
            request_id = waiter.request_id
            return original_register(waiter, sender, deadline)

        router.register_pending = capture_register
        client = Client()
        harness = self.groups.FleetHarness(
            client, router, "a" * 64, "anchor",
            {"remote": self.groups.Runner("remote", target_aid)},
            logging.getLogger("group-ack-result"),
        )

        response = harness.call("remote", "contact_list")
        self.assertEqual("ok", response["outcome"])
        self.assertEqual(1, client.attempts)

    def test_wrong_sender_result_does_not_stop_command_retries(self):
        router = self.groups.ResultRouter(logging.getLogger("group-wrong-sender"))
        target_aid = "b" * 64
        request_id = None

        class Client:
            attempts = 0

            def direct_send(inner_self, _target, _wire):
                inner_self.attempts += 1
                router.deliver(
                    {"kind": "contact_list_result", "request_id": request_id,
                     "outcome": "ok"},
                    "c" * 64,
                )
                raise TimeoutError("no ack")

        original_register = router.register_pending

        def capture_register(waiter, sender, deadline):
            nonlocal request_id
            request_id = waiter.request_id
            return original_register(waiter, sender, deadline)

        router.register_pending = capture_register
        client = Client()
        harness = self.groups.FleetHarness(
            client, router, "a" * 64, "anchor",
            {"remote": self.groups.Runner("remote", target_aid)},
            logging.getLogger("group-wrong-sender"),
        )
        with mock.patch.object(self.groups.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "failed after 5 attempts"):
                harness.call("remote", "contact_list")
        self.assertEqual(5, client.attempts)

    def test_wrong_request_result_does_not_stop_command_retries(self):
        router = self.groups.ResultRouter(logging.getLogger("group-wrong-request"))
        target_aid = "b" * 64

        class Client:
            attempts = 0

            def direct_send(inner_self, _target, _wire):
                inner_self.attempts += 1
                router.deliver(
                    {"kind": "contact_list_result", "request_id": "other",
                     "outcome": "ok"},
                    target_aid,
                )
                raise TimeoutError("no ack")

        client = Client()
        harness = self.groups.FleetHarness(
            client, router, "a" * 64, "anchor",
            {"remote": self.groups.Runner("remote", target_aid)},
            logging.getLogger("group-wrong-request"),
        )
        with mock.patch.object(self.groups.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "failed after 5 attempts"):
                harness.call("remote", "contact_list")
        self.assertEqual(5, client.attempts)

    def test_wrong_kind_result_fails_instead_of_ending_as_success(self):
        router = self.groups.ResultRouter(logging.getLogger("group-wrong-kind"))
        target_aid = "b" * 64
        request_id = None

        class Client:
            def direct_send(inner_self, _target, _wire):
                router.deliver(
                    {"kind": "group_list_result", "request_id": request_id,
                     "outcome": "ok"},
                    target_aid,
                )
                raise TimeoutError("no ack")

        original_register = router.register_pending

        def capture_register(waiter, sender, deadline):
            nonlocal request_id
            request_id = waiter.request_id
            return original_register(waiter, sender, deadline)

        router.register_pending = capture_register
        harness = self.groups.FleetHarness(
            Client(), router, "a" * 64, "anchor",
            {"remote": self.groups.Runner("remote", target_aid)},
            logging.getLogger("group-wrong-kind"),
        )
        with self.assertRaisesRegex(RuntimeError, "unexpected kind"):
            harness.call("remote", "contact_list")

    def test_route_event_requires_verified_expected_sender_for_all_formats(self):
        expected = "b" * 64
        wrong = "c" * 64
        request_id = "route-admission"
        envelope = {
            "kind": "contact_list_result",
            "request_id": request_id,
            "outcome": "ok",
        }
        v1 = self.groups.PREFIX_RES + base64.b64encode(
            json.dumps(envelope).encode(),
        )
        v2 = frame_result(
            json.dumps(envelope).encode(), "route-transfer", request_id,
        )[0]

        def route_and_take(event_type, data):
            router = self.groups.ResultRouter(logging.getLogger("route-admission"))
            waiter = self.groups.CommandWaiter(request_id)
            router.register_pending(
                waiter, expected, self.groups.time.monotonic() + 100.0,
            )
            self.groups._route_event(
                event_type, json.dumps(data), router,
                logging.getLogger("route-admission"), "fixture",
            )
            try:
                return waiter.queue.get_nowait()
            except self.groups.queue.Empty:
                return None

        for wire in (v1, v2):
            with self.subTest(format="direct", verified=False, prefix=wire[:12]):
                self.assertIsNone(route_and_take("direct_message", {
                    "sender": expected,
                    "verified": False,
                    "payload": base64.b64encode(wire).decode(),
                }))
            with self.subTest(format="direct", sender="wrong", prefix=wire[:12]):
                self.assertIsNone(route_and_take("direct_message", {
                    "sender": wrong,
                    "verified": True,
                    "payload": base64.b64encode(wire).decode(),
                }))
            with self.subTest(format="direct", accepted=True, prefix=wire[:12]):
                self.assertEqual(envelope, route_and_take("direct_message", {
                    "sender": expected,
                    "verified": True,
                    "payload": base64.b64encode(wire).decode(),
                }))

        legacy_data = {
            "type": "message",
            "data": {
                "topic": self.groups.LEGACY_RESULTS_TOPIC,
                "sender": expected,
                "verified": True,
                "payload": base64.b64encode(
                    json.dumps(envelope).encode(),
                ).decode(),
            },
        }
        self.assertEqual(envelope, route_and_take("message", legacy_data))
        legacy_data["data"]["verified"] = False
        self.assertIsNone(route_and_take("message", legacy_data))
        legacy_data["data"]["verified"] = True
        legacy_data["data"]["sender"] = wrong
        self.assertIsNone(route_and_take("message", legacy_data))


if __name__ == "__main__":
    unittest.main()
