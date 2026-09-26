import unittest
from unittest.mock import patch

import e2e_vps_gss_invite_kv as h
from e2e_vps_kv import Evidence


class FakeApi:
    def __init__(self, aid, responses=None):
        self.aid = aid
        self.responses = list(responses or [])
        self.calls = []

    def agent_id(self):
        return self.aid

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if self.responses:
            item = self.responses.pop(0)
            return item() if callable(item) else item
        return 500, {"error": "unconfigured"}


class GssHarnessTests(unittest.TestCase):
    def scenario(self, clients, timeout=0.02):
        return h.Scenario(clients, Evidence(), timeout=timeout)

    def test_gss_join_requires_owner_roster_and_local_active(self):
        owner = FakeApi("a" * 64, [(200, {"invite_link": "x0x://invite/redacted"}), (200, {"members": []})])
        member = FakeApi("b" * 64, [
            (201, {"ok": True, "group_id": "g"}),
            (200, {"group_id": "wrong", "membership_state": "active"}),
            (200, {"last_join_outcome": {"outcome": "timed_out"}}),
        ])
        s = self.scenario({"owner": owner, "member": member})
        with self.assertRaises(AssertionError):
            s.join_gss("owner", "member", "g")
        self.assertTrue(any(p.get("outcome") == "timeout" for p in s.e.polls))
        self.assertNotIn("x0x://invite/redacted", str(s.e.polls))


    def test_initial_joiner_open_retries_only_exact_pending_409(self):
        member = FakeApi("b" * 64, [
            (409, {"error": "local daemon holds no shared secret for this group yet"}),
            (201, {"id": "full-wiki-id", "store_id": "full-wiki-id"}),
        ])
        s = self.scenario({"member": member}, timeout=0.02)
        with patch.object(h.time, "sleep", return_value=None):
            self.assertEqual(s.open_full_wiki("member", "g", wait_for_gss_secret=True), "full-wiki-id")
        self.assertEqual(len(member.calls), 2)
        self.assertEqual(s.e.polls[-1]["last_response_class"], "none")
        self.assertEqual(s.e.polls[-1]["outcome"], "accepted")

    def test_initial_joiner_open_rejects_wrong_409_immediately(self):
        member = FakeApi("b" * 64, [(409, {"error": "store not found"})])
        s = self.scenario({"member": member}, timeout=1)
        with self.assertRaises(AssertionError):
            s.open_full_wiki("member", "g", wait_for_gss_secret=True)
        self.assertEqual(len(member.calls), 1)

    def test_no_secret_timeout_fails_without_real_sleep(self):
        member = FakeApi("b" * 64, [(409, {"error": "local daemon holds no shared secret for this group yet"})])
        s = self.scenario({"member": member}, timeout=0.02)
        clock = iter((0.0, 1.0, 1.0))
        with patch.object(h.time, "monotonic", side_effect=lambda: next(clock)), \
             patch.object(h.time, "sleep", return_value=None), \
             self.assertRaises(AssertionError):
            s.open_full_wiki("member", "g", wait_for_gss_secret=True)
        self.assertEqual(len(member.calls), 1)
        self.assertEqual(s.e.assertions[-1]["label"], "member GSS secret became available before Wiki open")
        self.assertGreaterEqual(s.e.assertions[-1]["elapsed_seconds"], s.timeout)
        self.assertEqual(s.e.assertions[-1]["response_class"], "http_error")

    def test_wrong_full_store_id_fails_identity_barrier(self):
        s = self.scenario({})
        with self.assertRaises(AssertionError):
            s.require_gss_store_identity("full-store-id-a", "full-store-id-b")
        self.assertFalse(s.e.assertions[-1]["passed"])

    def test_delivery_refusal_and_store_not_found_do_not_pass(self):
        member = FakeApi("b" * 64, [(403, {"error": "forbidden"}), (404, {"error": "store not found"})])
        s = self.scenario({"member": member})
        with self.assertRaises(AssertionError):
            s.put_checked("member", "full-store-id", "key", "secret-value")
        with self.assertRaises(AssertionError):
            s.await_key_not_found("member", "full-store-id", "key")
        self.assertNotIn("secret-value", str(s.e.assertions))

    def test_positive_join_barrier_accepts_both_independent_facts(self):
        owner = FakeApi("a" * 64, [(200, {"invite_link": "x0x://invite/redacted"}), (200, {"members": [{"agent_id": "b" * 64}]})])
        member = FakeApi("b" * 64, [
            (201, {"ok": True, "group_id": "g"}),
            (200, {"group_id": "g", "membership_state": "active"}),
        ])
        s = self.scenario({"owner": owner, "member": member})
        s.join_gss("owner", "member", "g")
        self.assertTrue(s.e.polls[-1]["outcome"] == "accepted")


if __name__ == "__main__":
    unittest.main()
