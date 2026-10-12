"""Pure-python tests for the #1216 survivor-rekey fixture. No daemon, no network."""
import base64
import hashlib
import json
import math
import os
import tempfile
import threading
import unittest
import uuid

import e2e_vps_survivor_rekey as h
from e2e_vps_kv import PollTimeout

LABELS = ["nyc", "sfo", "helsinki", "nuremberg", "singapore"]
GID = "f" * 64
STABLE = "e" * 64
CLEAN_JOURNAL = {"attributed_epochs": [], "attributed_max_epoch": None, "unattributed": 0, "info_lines": 12}


class FakeClock:
    """Monotonic time that moves only when the scenario sleeps."""

    def __init__(self):
        self.t = 1000.0

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += max(0.0, seconds)


class FakeNet:
    """One group on one secure plane, shared by every fake daemon.

    `override(net, label, method, path, body)` may return a (status, body) response,
    raise, or return None to fall through to the normal behaviour.
    """

    def __init__(self, plane, labels, *, lag=None, leak_to=None, leak_to_on_ban=None, withhold_join_key=(),
                 reseal_leaks=False, seat_banned=False, on_health=None, override=None):
        self.plane, self.labels, self.lock = plane, list(labels), threading.Lock()
        self.epoch = 0
        self.state = {label: None for label in labels}
        self.have = {label: None for label in labels}
        self.agents = {label: hashlib.sha256(label.encode()).hexdigest() for label in labels}
        self.by_agent = {aid: label for label, aid in self.agents.items()}
        self.lag, self.pending = dict(lag or {}), {}
        self.leak_to, self.leak_to_on_ban = leak_to, leak_to_on_ban
        self.bypass = set([leak_to] if leak_to else [])
        self.withhold_join_key = set(withhold_join_key)
        self.reseal_leaks, self.seat_banned, self.on_health = reseal_leaks, seat_banned, on_health
        self.override, self.flags = override, set()
        self.messages, self.uptime, self.restarts = {}, {label: 1000 for label in labels}, []
        self.secrets = set()  # strings that must never reach a report

    def node(self, label):
        return FakeNode(self, label)

    def restart(self, label):
        self.uptime[label] = 0
        self.restarts.append(label)

    def _rotate(self, exclude, leak=None):
        self.epoch += 1
        owner = self.labels[0]
        self.have[owner] = self.epoch
        for label in self.labels:
            if label == owner or label in exclude or self.state[label] != "active":
                continue
            delay = self.lag.get(label, 0)
            if delay <= 0:
                self.have[label] = self.epoch
            else:
                self.pending[label] = (delay, self.epoch)
        for leaked in (self.leak_to, leak):
            if leaked is not None:
                self.have[leaked] = self.epoch
                self.bypass.add(leaked)

    def _tick(self, label):
        if label in self.pending:
            remaining, epoch = self.pending[label]
            if remaining <= 1:
                del self.pending[label]
                self.have[label] = epoch
            else:
                self.pending[label] = (remaining - 1, epoch)

    def handle(self, label, method, path, body):
        if self.override is not None:
            response = self.override(self, label, method, path, body)
            if response is not None:
                return response
        g = f"/groups/{GID}"
        if method == "GET" and path == "/agent":
            return 200, {"agent_id": self.agents[label]}
        if method == "GET" and path == "/health":
            if self.on_health is not None:
                self.on_health(label)
            return 200, {"ok": True, "version": "0.46.3", "uptime_secs": self.uptime[label]}
        if method == "POST" and path == "/groups":
            self.state[label], self.epoch, self.have[label] = "active", 1, 1
            policy = (dict(h.GSS_POLICY) if self.plane == "gss"
                      else {"discoverability": "hidden", "confidentiality": "mls_encrypted"})
            return 201, {"ok": True, "group_id": GID, "policy": policy}
        if method == "GET" and path == f"{g}/state":
            return 200, {"ok": True, "group_id": STABLE, "mls_group_id": GID}
        if method == "POST" and path == f"{g}/invite":
            link = f"x0x://invite/fake-{uuid.uuid4().hex}"
            self.secrets.add(link)
            return 200, {"ok": True, "invite_link": link}
        if method == "POST" and path == "/groups/join":
            if self.state[label] == "banned":
                if self.seat_banned:
                    self.state[label], self.have[label] = "active", self.epoch
                return 200, {"ok": True, "group_id": GID, "join_state": "pending_authority_commit",
                             "already_joined": False}
            self.state[label] = "active"
            if self.plane == "treekem":  # the add commit moves every member to a new epoch
                self.epoch += 1
                for other in self.labels:
                    if self.state[other] == "active" and self.have[other] is not None:
                        self.have[other] = self.epoch
            self.have[label] = None if label in self.withhold_join_key else self.epoch
            return 200, {"ok": True, "group_id": GID, "join_state": "active"}
        if method == "GET" and path == f"{g}/members":
            return 200, {"members": [{"agent_id": self.agents[x], "state": self.state[x]}
                                     for x in self.labels if self.state[x] in ("active", "banned")]}
        if method == "GET" and path == g:
            if self.state[label] == "active":
                return 200, {"group_id": GID, "membership_state": "active"}
            if self.state[label] in ("removed", "banned"):
                return 200, {"group_id": GID, "membership_state": "not_member"}
            return 404, {"error": "group not found"}
        if method == "GET" and path == f"{g}/join-status":
            return 200, {"join_state": "idle", "last_join_outcome": {"outcome": "refused", "reason": "banned"}}
        if method == "POST" and path == f"{g}/secure/encrypt":
            if self.state[label] != "active" or self.have[label] is None:
                return 403, {"ok": False, "error": "not a member"}
            ciphertext = base64.b64encode(uuid.uuid4().bytes).decode()
            self.messages[ciphertext] = (self.have[label], body["payload_b64"])
            self.secrets.add(ciphertext)
            if self.plane == "gss":
                return 200, {"ok": True, "ciphertext_b64": ciphertext, "nonce_b64": "bm9uY2Vub25jZQ==",
                             "secret_epoch": self.have[label]}
            return 200, {"ok": True, "ciphertext_b64": ciphertext, "secret_epoch": self.have[label],
                         "secure_plane": "treekem"}
        if method == "POST" and path == f"{g}/secure/decrypt":
            self._tick(label)
            if self.state[label] not in ("active", "banned") and label not in self.bypass:
                return 403, {"ok": False, "error": "not a member"}
            epoch, payload = self.messages[body["ciphertext_b64"]]
            have = self.have[label]
            if self.plane == "gss":
                if have is None:
                    return 424, {"ok": False, "error": "no shared secret available"}
                if have != epoch:
                    return 409, {"ok": False, "error": "epoch mismatch — re-share required",
                                 "local_epoch": have, "ciphertext_epoch": epoch}
                return 200, {"ok": True, "payload_b64": payload, "secret_epoch": epoch}
            if have is None:
                return 424, {"ok": False, "error": "TreeKEM group not loaded — restart or re-share required"}
            if have < epoch:
                return 400, {"ok": False, "error": "treekem decrypt failed: unknown epoch"}
            return 200, {"ok": True, "payload_b64": payload, "secret_epoch": have, "secure_plane": "treekem"}
        if method == "DELETE" and path.startswith(f"{g}/members/"):
            target = self.by_agent[path.rsplit("/", 1)[1]]
            self.state[target] = "removed"
            self._rotate(exclude=(target,))
            return 200, {"ok": True, "removed_member": self.agents[target]}
        if method == "POST" and path.startswith(f"{g}/ban/"):
            target = self.by_agent[path.rsplit("/", 1)[1]]
            self.state[target] = "banned"
            self._rotate(exclude=(target,), leak=self.leak_to_on_ban)
            return 200, {"ok": True, "revision": 9}
        if method == "POST" and path == f"{g}/secure/reseal":
            target = self.by_agent[body["recipient"]]
            if self.reseal_leaks or self.state[target] == "active":
                self.secrets.add("SECRET-ENVELOPE")
                return 200, {"ok": True, "envelope_b64": "SECRET-ENVELOPE"}
            if self.state[target] == "banned":
                return 409, {"ok": False, "error": "recipient is not an active member",
                             "reason": "recipient_not_active"}
            return 404, {"ok": False, "error": "recipient is not a member"}
        return 500, {"error": f"unhandled {method} {path}"}


class FakeNode:
    def __init__(self, net, label):
        self.net, self.label = net, label

    def agent_id(self):
        return self.net.agents[self.label]

    def request(self, method, path, body=None, timeout=20.0):
        with self.net.lock:
            return self.net.handle(self.label, method, path, body)


def scenario(plane, poll_timeout=0.5, share_installs=None, binary_sha="a" * 64, remote_clock=True,
             **net_kwargs):
    """share_installs: None (clean scan), False (no journal scan), or callable(net, node, gid).

    The fake node clock is a counter; every reading is logged in net.clock_reads as
    (node, value, that node's membership state at the time)."""
    net = FakeNet(plane, LABELS, **net_kwargs)
    clock = FakeClock()
    scans = []
    net.clock_reads, net.install_scans = [], []

    def journal(node, since):
        scans.append((node, since))
        return {"counts": {"recipient_undiscovered": 0}, "since_unix": since, "info_lines": 3}

    def installs(node, since, gid):
        net.install_scans.append((node, since))
        if callable(share_installs):
            return share_installs(net, node, gid)
        return dict(CLEAN_JOURNAL)

    def node_clock(node):
        value = 1_800_000_000 + len(net.clock_reads)
        net.clock_reads.append((node, value, net.state[node]))
        return value

    s = h.RekeyScenario({label: net.node(label) for label in LABELS}, h.RekeyEvidence(), poll_timeout,
                        rekey_timeout=30, watch_secs=10, rejoin_watch_secs=5, restart_lead_secs=15,
                        probe_period=1.0, versions={label: "0.46.3" for label in LABELS},
                        journal_scan=journal, share_install_scan=None if share_installs is False else installs,
                        remote_clock=node_clock if remote_clock else None,
                        binary_sha=(lambda node: binary_sha), clock=clock.now, sleep=clock.sleep)
    return s, net, clock, scans


def failed_labels(s):
    return [row["label"] for row in s.e.assertions if not row["passed"]]


def row(s, label):
    return next(r for r in s.e.assertions if r["label"] == label)


def obs_of(*classes, epochs=None):
    obs = h.ExclusionObservation()
    for index, cls in enumerate(classes):
        obs.observe(100.0 + index, cls, (epochs or {}).get(index))
    return obs


class PureHelperTests(unittest.TestCase):
    def test_normalize_version(self):
        self.assertEqual(h.normalize_version("x0xd 0.46.3"), "0.46.3")
        self.assertEqual(h.normalize_version("0.46.3"), "0.46.3")
        self.assertEqual(h.normalize_version("x0xd 0.47.0-rc.1"), "0.47.0-rc.1")
        self.assertIsNone(h.normalize_version("x0xd"))
        self.assertIsNone(h.normalize_version(None))

    def test_assign_roles(self):
        roles = h.assign_roles(LABELS)
        self.assertEqual(roles, {"remover": "nyc", "survivors": ["sfo", "helsinki"],
                                 "remove_target": "nuremberg", "ban_target": "singapore"})
        with self.assertRaises(ValueError):
            h.assign_roles(LABELS[:4])
        with self.assertRaises(ValueError):
            h.assign_roles(["nyc", "sfo", "nyc", "helsinki", "sydney"])

    def test_plane_and_sealed_from_encrypt(self):
        gss = {"ok": True, "ciphertext_b64": "Y3Q=", "nonce_b64": "bm9uY2U=", "secret_epoch": 3}
        tk = {"ok": True, "ciphertext_b64": "Y3Q=", "secret_epoch": 7, "secure_plane": "treekem"}
        self.assertEqual(h.plane_of_encrypt(gss), "gss")
        self.assertEqual(h.plane_of_encrypt(tk), "treekem")
        self.assertIsNone(h.plane_of_encrypt({"ciphertext_b64": "Y3Q=", "secret_epoch": 1}))
        self.assertIsNone(h.plane_of_encrypt({"secure_plane": "gss", "nonce_b64": "x"}))
        self.assertEqual(h.sealed_from_encrypt(gss), {"ciphertext_b64": "Y3Q=", "nonce_b64": "bm9uY2U=",
                                                      "secret_epoch": 3})
        self.assertEqual(h.sealed_from_encrypt(tk), {"ciphertext_b64": "Y3Q=", "secret_epoch": 7})
        self.assertIsNone(h.sealed_from_encrypt({"ciphertext_b64": "Y3Q=", "secret_epoch": "3"}))
        self.assertIsNone(h.sealed_from_encrypt({"ok": False, "ciphertext_b64": "Y3Q=", "secret_epoch": 3}))
        self.assertIsNone(h.sealed_from_encrypt({"ciphertext_b64": "Y3Q=", "secret_epoch": True}))

    def test_classify_decrypt_and_exclusion_kind(self):
        want = "cGF5bG9hZA=="
        cases = [
            ((200, {"ok": True, "payload_b64": want, "secret_epoch": 4}), ("decrypted", 4), "leak"),
            ((200, {"ok": True, "payload_b64": "b3RoZXI=", "secret_epoch": 4}), ("wrong_plaintext", 4), "leak"),
            ((409, {"error": "epoch mismatch — re-share required", "local_epoch": 3}), ("epoch_mismatch", 3), "key"),
            ((424, {"error": "no shared secret available"}), ("no_secret", None), "key"),
            ((424, {"error": "TreeKEM group not loaded — restart or re-share required"}),
             ("treekem_not_loaded", None), "key"),
            ((403, {"error": "decryption failed"}), ("decrypt_failed", None), "key"),
            ((400, {"error": "treekem decrypt failed: bad"}), ("treekem_decrypt_failed", None), "key"),
            ((403, {"error": "not a member"}), ("not_member", None), "gate"),
            ((404, {"error": "group not found"}), ("group_not_found", None), "gate"),
            # Review r2 item 2: only the exact typed responses count; everything else is an error.
            ((409, {"error": "x", "reason": "fork_quarantined"}), ("fork_quarantined", None), "error"),
            ((403, {"error": "x", "reason": "fork_quarantined"}), ("fork_quarantined", None), "error"),
            ((500, {"error": "x", "reason": "fork_quarantined"}), ("fork_quarantined", None), "error"),
            ((403, {"error": "rider"}), ("forbidden", None), "error"),
            ((403, {"error": "not a member", "reason": "group_membership_required"}), ("forbidden", None), "error"),
            ((404, {"error": "store not found"}), ("not_found_other", None), "error"),
            ((404, {}), ("not_found_other", None), "error"),
            ((500, {"error": "not a member"}), ("http_other", None), "error"),
            ((500, {"error": "epoch mismatch — re-share required", "local_epoch": 3}), ("http_other", None), "error"),
            ((409, {"error": "epoch mismatch", "local_epoch": 3, "reason": "x"}), ("conflict", None), "error"),
            ((409, {"error": "other"}), ("conflict", None), "error"),
            ((424, {"error": "else"}), ("failed_dependency", None), "error"),
            ((400, {"error": "invalid base64 nonce"}), ("bad_request", None), "error"),
            ((500, {"error": "boom"}), ("http_other", None), "error"),
            ((None, {}), ("http_other", None), "error"),
            ((409, ["not", "a", "dict"]), ("conflict", None), "error"),
        ]
        for (status, body), expected, kind in cases:
            with self.subTest(status=status, body=body):
                self.assertEqual(h.classify_decrypt(status, body, want), expected)
                self.assertEqual(h.exclusion_kind(expected[0]), kind)
        self.assertEqual(h.exclusion_kind("transport:TimeoutError"), "error")
        self.assertEqual(h.single_probe_verdict("not_member"), ("pass", "gate"))
        self.assertEqual(h.single_probe_verdict("epoch_mismatch"), ("pass", "key"))
        self.assertEqual(h.single_probe_verdict("decrypted"), ("fail", "leak"))
        self.assertEqual(h.single_probe_verdict("http_other"), ("inconclusive", "error"))
        self.assertEqual(h.single_probe_verdict("transport:URLError"), ("inconclusive", "error"))

    def test_member_is_active(self):
        roster = {"members": [{"agent_id": "a", "state": "Active"}, {"agent_id": "b", "state": "banned"}]}
        self.assertTrue(h.member_is_active(200, roster, "a"))
        self.assertFalse(h.member_is_active(200, roster, "b"))
        self.assertFalse(h.member_is_active(200, roster, "c"))
        self.assertIsNone(h.member_is_active(500, roster, "a"))
        self.assertIsNone(h.member_is_active(None, {}, "a"))
        self.assertIsNone(h.member_is_active(200, {"members": None}, "a"))
        # Review r2 item 3: a malformed row makes the whole read invalid, never a valid absence.
        for rows in ([{"agent_id": "a"}], [{"agent_id": "b", "state": "active"}, {"agent_id": "a"}],
                     [{"agent_id": "a", "state": None}], [{"agent_id": "a", "state": "weird"}],
                     [{"state": "active"}], ["a"]):
            with self.subTest(rows=rows):
                self.assertIsNone(h.member_is_active(200, {"members": rows}, "a"))
        self.assertFalse(h.member_is_active(200, {"members": []}, "a"))

    def test_restart_bounds(self):
        self.assertTrue(h.restart_lead_ok(10.0))
        self.assertTrue(h.restart_lead_ok(20.0))
        self.assertFalse(h.restart_lead_ok(9.99))
        self.assertFalse(h.restart_lead_ok(20.01))
        self.assertFalse(h.restart_lead_ok(float("nan")))
        self.assertTrue(h.restart_observed(3, 4.0))
        self.assertFalse(h.restart_observed(500, 4.0))
        self.assertFalse(h.restart_observed(None, 4.0))
        self.assertFalse(h.restart_observed(True, 4.0))

    def test_parse_journal_matches_counts_without_text(self):
        text = "\n".join([
            'WARN x0x::direct: pinned send: no verified source stage="send" agent_prefix=ab12 '
            'outcome="err_recipient_undiscovered" waited_ms=1500',
            '{"fields":{"outcome":"err_recipient_undiscovered","waited_ms":20}}',
            "WARN failed to fetch TreeKEM Welcome blob after retries group=deadbeef",
            "DEBUG secure share recipient not yet discovered; resending: recipient_undiscovered",
            "DEBUG secure share write failed; retrying: timeout",
            "INFO unrelated line",
            "x0x-rekey-info-lines=42",
        ])
        parsed = h.parse_journal_matches(text)
        self.assertEqual(parsed["counts"], {"recipient_undiscovered": 2, "welcome_fetch_failed": 1,
                                            "share_resend_undiscovered": 1, "share_write_retry": 1})
        self.assertEqual(parsed["recipient_undiscovered_waited_ms"], [1500, 20])
        self.assertEqual(parsed["recipient_undiscovered_waited_ms_max"], 1500)
        self.assertEqual(parsed["info_lines"], 42)
        self.assertNotIn("deadbeef", json.dumps(parsed))
        self.assertIsNone(h.parse_journal_matches("")["info_lines"])

    def test_parse_share_installs_attributes_by_stable_id(self):
        text = "\n".join([
            f"INFO x0x: Phase D.2: stored new group shared secret (epoch 4) via KEM-sealed envelope "
            f"group_id={STABLE} secret_epoch=4",
            '{"level":"INFO","fields":{"message":"Phase D.2: stored new group shared secret (epoch 6) '
            f'via KEM-sealed envelope","group_id":"{STABLE}","secret_epoch":6}}}}',
            "INFO x0x: Phase D.2: stored new group shared secret (epoch 9) via KEM-sealed envelope "
            f"group_id={'d' * 64} secret_epoch=9",
            "x0x-rekey-info-lines=7",
        ])
        parsed = h.parse_share_installs(text, STABLE)
        self.assertEqual(parsed, {"attributed_epochs": [4, 6], "attributed_max_epoch": 6,
                                  "unattributed": 1, "info_lines": 7})
        self.assertNotIn(STABLE, json.dumps(parsed))
        self.assertEqual(h.parse_sha256sum(f"{'a' * 64}  /proc/12/exe\n"), "a" * 64)
        self.assertIsNone(h.parse_sha256sum("garbage /proc/12/exe"))
        self.assertIsNone(h.parse_sha256sum(""))

    def test_rekey_tracker(self):
        tracker = h.RekeyTracker(("sfo", "helsinki"), ("nuremberg", "sydney"), started=100.0)
        tracker.observe("sfo", 100.5, "epoch_mismatch", 3)
        tracker.observe("helsinki", 100.6, "decrypted", 4)
        tracker.observe("nuremberg", 100.6, "epoch_mismatch", 3)
        tracker.observe("sydney", 100.6, "not_member", None)
        self.assertEqual(tracker.pending(), ["sfo"])
        tracker.observe("sfo", 102.25, "decrypted", 4)
        tracker.observe("sfo", 103.0, "epoch_mismatch", 3)  # ignored after success
        tracker.observe("nuremberg", 104.0, "not_member", None)
        summary = tracker.summary()
        self.assertEqual(summary["rekey_latency_s"], {"helsinki": 0.6, "sfo": 2.25})
        self.assertEqual(summary["slowest_survivor"], "sfo")
        self.assertEqual(summary["rekey_latency_max_s"], 2.25)
        self.assertEqual(summary["survivor_probe_classes"]["sfo"], {"epoch_mismatch": 1, "decrypted": 1})
        nuremberg = summary["excluded"]["nuremberg"]
        self.assertEqual(nuremberg["classes"], {"epoch_mismatch": 1, "not_member": 1})
        self.assertEqual((nuremberg["key_probes"], nuremberg["gate_probes"], nuremberg["errors"]), (1, 1, 0))
        self.assertEqual(nuremberg["max_local_epoch"], 3)
        self.assertEqual(nuremberg["last_class"], "not_member")
        self.assertEqual(nuremberg["observed_until_s"], 4.0)
        self.assertFalse(tracker.leaked())
        tracker.observe("sydney", 105.0, "wrong_plaintext", 4)
        self.assertTrue(tracker.leaked())
        with self.assertRaises(ValueError):
            tracker.observe("tokyo", 105.0, "decrypted", 4)
        with self.assertRaises(ValueError):
            h.RekeyTracker(("sfo",), ("sfo",), started=0.0)


class ExclusionVerdictTests(unittest.TestCase):
    """Review items 1 and 2: errors are never exclusion; D60 is claimed only with key evidence."""

    def test_exclusion_verdict(self):
        self.assertEqual(h.exclusion_verdict(obs_of()), ("inconclusive", "unobserved"))
        self.assertEqual(h.exclusion_verdict(obs_of("not_member", "not_member")), ("pass", "gate"))
        self.assertEqual(h.exclusion_verdict(obs_of("not_member", "epoch_mismatch")), ("pass", "key"))
        self.assertEqual(h.exclusion_verdict(obs_of("not_member", "http_other")), ("inconclusive", "error_responses"))
        self.assertEqual(h.exclusion_verdict(obs_of("transport:TimeoutError")), ("inconclusive", "error_responses"))
        self.assertEqual(h.exclusion_verdict(obs_of("http_other", "decrypted")), ("fail", "leak"))

    def test_d60_needs_key_evidence_and_journal_silence_proves_nothing(self):
        gate = obs_of("not_member", "not_member")
        self.assertEqual(h.d60_verdict(gate, 5, None), ("limited", "membership_gate"))
        # Review r2 item 4: an empty install scan is never a pass, whatever else the window holds.
        for journal in (dict(CLEAN_JOURNAL), {**CLEAN_JOURNAL, "info_lines": 10 ** 6},
                        {**CLEAN_JOURNAL, "info_lines": 0}, {"error_class": "ssh_failed"},
                        {**CLEAN_JOURNAL, "unattributed": 1},
                        {**CLEAN_JOURNAL, "attributed_epochs": [4], "attributed_max_epoch": 4}):
            with self.subTest(journal=journal):
                self.assertEqual(h.d60_verdict(gate, 5, journal), ("limited", "membership_gate"))
        # The leak direction stays: an install line for this group at the new epoch fails,
        # even with no other info lines and even when decrypt probes erred.
        installed = {**CLEAN_JOURNAL, "attributed_epochs": [5], "attributed_max_epoch": 5, "info_lines": 0}
        self.assertEqual(h.d60_verdict(gate, 5, installed), ("fail", "journal_install"))
        self.assertEqual(h.d60_verdict(obs_of("http_other"), 5, installed), ("fail", "journal_install"))
        self.assertEqual(h.d60_verdict(obs_of("epoch_mismatch", epochs={0: 4}), 5, installed),
                         ("fail", "journal_install"))
        # Key material consulted on the last probe covers the window.
        self.assertEqual(h.d60_verdict(obs_of("not_member", "epoch_mismatch", epochs={1: 4}), 5, None),
                         ("pass", "key"))
        self.assertEqual(h.d60_verdict(obs_of("treekem_decrypt_failed"), 5, None), ("pass", "key"))
        self.assertEqual(h.d60_verdict(obs_of("no_secret"), 5, None), ("pass", "key"))

    def test_d60_epoch_mismatch_needs_the_local_epoch(self):
        """Review r2 item 1."""
        self.assertEqual(h.d60_verdict(obs_of("epoch_mismatch"), 5, None), ("limited", "epoch_unreported"))
        self.assertEqual(h.d60_verdict(obs_of("epoch_mismatch", "epoch_mismatch", epochs={0: 4}), 5, None),
                         ("limited", "epoch_unreported"))
        self.assertEqual(h.d60_verdict(obs_of("epoch_mismatch", epochs={0: 4}), 5, None), ("pass", "key"))
        obs = obs_of("epoch_mismatch")
        self.assertIsNone(obs.last_epoch)
        self.assertEqual(h.classify_decrypt(409, {"error": "epoch mismatch — re-share required"}, "x"),
                         ("epoch_mismatch", None))
        self.assertEqual(h.classify_decrypt(409, {"error": "epoch mismatch", "local_epoch": "4"}, "x"),
                         ("epoch_mismatch", None))
        # Key evidence early, gate late: the end of the window is not covered.
        self.assertEqual(h.d60_verdict(obs_of("epoch_mismatch", "not_member", epochs={0: 4}), 5, None),
                         ("limited", "membership_gate"))
        self.assertEqual(h.d60_verdict(obs_of("epoch_mismatch", epochs={0: 5}), 5, None),
                         ("fail", "local_epoch_reached"))
        self.assertEqual(h.d60_verdict(obs_of("decrypted"), 5, None), ("fail", "leak"))
        self.assertEqual(h.d60_verdict(obs_of("not_member", "http_other"), 5, dict(CLEAN_JOURNAL)),
                         ("inconclusive", "error_responses"))
        self.assertEqual(h.d60_verdict(obs_of(), 5, dict(CLEAN_JOURNAL)), ("inconclusive", "unobserved"))


class RefusalVerdictTests(unittest.TestCase):
    """Review items 3 and 4."""

    def test_reseal_needs_the_explicit_ineligible_refusal(self):
        self.assertEqual(h.classify_reseal(200, {"envelope_b64": "S"}), "sealed")
        self.assertEqual(h.classify_reseal(404, {"error": "recipient is not a member"}), "recipient_not_member")
        self.assertEqual(h.classify_reseal(404, {"error": "group not found"}), "http_other")
        self.assertEqual(h.classify_reseal(409, {"reason": "recipient_not_active"}), "recipient_not_active")
        self.assertEqual(h.classify_reseal(409, {"error": "group is withdrawn"}), "http_other")
        self.assertEqual(h.classify_reseal(403, {}), "forbidden")
        self.assertEqual(h.classify_reseal(500, {}), "http_other")
        self.assertEqual(h.classify_reseal(None, {}), "transport_error")
        self.assertEqual(h.reseal_verdict("recipient_not_member"), "pass")
        self.assertEqual(h.reseal_verdict("recipient_not_active"), "pass")
        self.assertEqual(h.reseal_verdict("sealed"), "fail")
        for cls in ("http_other", "transport_error", "forbidden", "failed_dependency"):
            self.assertEqual(h.reseal_verdict(cls), "inconclusive")

    def test_join_classifiers(self):
        self.assertEqual(h.classify_join_attempt(200, {"join_state": "pending_authority_commit",
                                                       "already_joined": False}),
                         {"status": 200, "join_state": "pending_authority_commit", "already_joined": False,
                          "refusal_code": None})
        self.assertEqual(h.classify_join_attempt(409, {"join_state": "<script>", "already_joined": "yes"}),
                         {"status": 409, "join_state": "other", "already_joined": None, "refusal_code": None})
        self.assertEqual(h.classify_join_attempt(409, {"error": "join_already_pending"})["refusal_code"],
                         "join_already_pending")
        # Review r3: a fork quarantine is never a join refusal (inconclusive everywhere).
        self.assertNotIn("fork_quarantined", h.JOIN_REFUSAL_CODES)
        for status, body in ((409, {"error": "x", "reason": "fork_quarantined"}),
                             (409, {"error": "fork_quarantined"}),
                             (403, {"error": "join_already_pending"}), (409, {"error": "banned"}),
                             (409, {"error": "invite free text"}), (500, {"error": "invite_unsigned"})):
            with self.subTest(status=status, body=body):
                self.assertIsNone(h.classify_join_attempt(status, body)["refusal_code"])
        self.assertEqual(h.classify_join_status(200, {"join_state": "idle", "last_join_outcome": {
            "outcome": "refused", "reason": "banned"}}),
            {"status": 200, "join_state": "idle", "outcome": "refused", "reason": "banned", "valid": True})
        self.assertEqual(h.classify_join_status(404, {"last_join_outcome": {"outcome": "x", "reason": "free text"}}),
                         {"status": 404, "join_state": None, "outcome": "other", "reason": "other", "valid": True})
        self.assertFalse(h.classify_join_status(500, {})["valid"])
        self.assertFalse(h.classify_join_status(None, {})["valid"])
        self.assertFalse(h.classify_join_status(200, {"join_state": "weird"})["valid"])
        self.assertEqual(h.classify_local_membership(200, {"membership_state": "active"}), "seat")
        self.assertEqual(h.classify_local_membership(200, {"membership_state": "not_member"}), "unseated")
        self.assertEqual(h.classify_local_membership(404, {}), "unseated")
        self.assertEqual(h.classify_local_membership(200, {}), "invalid")
        self.assertEqual(h.classify_local_membership(500, {}), "invalid")
        self.assertEqual(h.classify_local_membership(None, {}), "invalid")

    def test_rejoin_verdict(self):
        pending = {"status": 200, "join_state": "pending_authority_commit", "already_joined": False,
                   "refusal_code": None}
        refused = {"status": 409, "join_state": None, "already_joined": None, "refusal_code": "invite_unsigned"}
        status_ok = {"valid": True, "outcome": None}
        status_refused = {"valid": True, "outcome": "refused"}
        self.assertEqual(h.rejoin_verdict(pending, [False, False], "unseated", status_ok), ("pass", "unseated"))
        self.assertEqual(h.rejoin_verdict(pending, [False], "unseated", status_refused), ("pass", "refused"))
        self.assertEqual(h.rejoin_verdict(refused, [False], "unseated", status_ok), ("pass", "refused"))
        # Review r2 item 3: an untyped 403/404/409 is not a refusal.
        for status in (403, 404, 409, 422):
            with self.subTest(untyped=status):
                self.assertEqual(h.rejoin_verdict({"status": status, "refusal_code": None}, [False], "unseated",
                                                  status_ok), ("inconclusive", "untyped_join_refusal"))
        self.assertEqual(h.rejoin_verdict(pending, [False, True], "unseated", status_ok),
                         ("fail", "seated_on_remover_roster"))
        self.assertEqual(h.rejoin_verdict(pending, [False], "seat", status_ok), ("fail", "target_reports_active"))
        self.assertEqual(h.rejoin_verdict({**pending, "join_state": "active"}, [False], "unseated", status_ok),
                         ("fail", "join_reported_active"))
        self.assertEqual(h.rejoin_verdict({**pending, "already_joined": True}, [False], "unseated", status_ok),
                         ("fail", "join_reported_active"))
        for attempt in ({"status": None}, {"status": 500}, {"status": 302}):
            with self.subTest(attempt=attempt):
                self.assertEqual(h.rejoin_verdict(attempt, [False], "unseated", status_ok),
                                 ("inconclusive", "join_request_error"))
        self.assertEqual(h.rejoin_verdict(pending, [False, None], "unseated", status_ok),
                         ("inconclusive", "invalid_roster_read"))
        self.assertEqual(h.rejoin_verdict(pending, [], "unseated", status_ok), ("inconclusive", "invalid_roster_read"))
        self.assertEqual(h.rejoin_verdict(pending, [False], "invalid", status_ok),
                         ("inconclusive", "invalid_local_read"))
        self.assertEqual(h.rejoin_verdict(pending, [False], "unseated", {"valid": False}),
                         ("inconclusive", "invalid_join_status"))


class HostsFileTests(unittest.TestCase):
    """Review item 5: complete, valid per-node metadata; live verification."""

    def doc(self, **override):
        hosts = [{"label": label, "public_ipv4": f"203.0.113.{i + 1}",
                  "daemon_sha256": ("a" if i % 2 else "b") * 64,
                  "daemon_version": "x0xd 0.46.3" if i % 2 else "x0xd 0.46.2"}
                 for i, label in enumerate(LABELS)]
        doc = {"schema_version": 1, "kind": "x0x-testnet-hosts", "hosts": hosts}
        doc.update(override)
        return doc

    def endpoints(self):
        return {label: f"203.0.113.{i + 1}" for i, label in enumerate(LABELS)}

    def test_per_node_map_never_collapses_to_one_binary(self):
        mapped, problems = h.node_binary_map(self.doc(), self.endpoints())
        self.assertEqual(problems, [])
        self.assertEqual(mapped["nyc"], {"daemon_sha256": "b" * 64, "deployed_version": "0.46.2"})
        self.assertEqual(mapped["sfo"], {"daemon_sha256": "a" * 64, "deployed_version": "0.46.3"})
        self.assertEqual(len({entry["daemon_sha256"] for entry in mapped.values()}), 2)

    def test_missing_or_malformed_metadata_is_a_problem(self):
        for key, value in (("daemon_sha256", ""), ("daemon_sha256", "A" * 64), ("daemon_sha256", None),
                           ("daemon_version", ""), ("daemon_version", "x0xd"), ("daemon_version", None)):
            with self.subTest(key=key, value=value):
                doc = self.doc()
                doc["hosts"][1][key] = value
                mapped, problems = h.node_binary_map(doc, self.endpoints())
                self.assertNotIn("sfo", mapped)
                self.assertEqual(len(problems), 1)
                self.assertIn("sfo", problems[0])

    def test_problems_name_labels_not_addresses(self):
        endpoints = self.endpoints()
        endpoints["sfo"] = "198.51.100.9"
        endpoints["sydney"] = "198.51.100.10"
        _mapped, problems = h.node_binary_map(self.doc(), endpoints)
        self.assertEqual(problems, ["hosts file address for sfo differs from the tokens file",
                                    "hosts file has no entry for sydney"])
        self.assertNotIn("198.51.100", " ".join(problems))
        self.assertTrue(h.node_binary_map({"kind": "other"}, endpoints)[1])
        self.assertTrue(h.node_binary_map(self.doc(hosts="x"), endpoints)[1])
        dup = self.doc()
        dup["hosts"].append(dict(dup["hosts"][0]))
        self.assertIn("hosts file lists nyc twice", h.node_binary_map(dup, self.endpoints())[1])

    def test_live_version_and_running_binary_must_match_each_node(self):
        mapped, _ = h.node_binary_map(self.doc(), self.endpoints())
        versions = {node: entry["deployed_version"] for node, entry in mapped.items()}
        shas = {node: entry["daemon_sha256"] for node, entry in mapped.items()}
        self.assertEqual({v for _, v, _ in h.binary_checks(mapped, versions, shas)}, {"pass"})
        verdicts = dict((node, v) for node, v, _ in h.binary_checks(
            mapped, {**versions, "nyc": "0.46.3"}, {**shas, "sfo": "c" * 64, "helsinki": None}))
        self.assertEqual(verdicts["nyc"], "fail")          # version differs from its own deploy
        self.assertEqual(verdicts["sfo"], "fail")          # running binary differs
        self.assertEqual(verdicts["helsinki"], "inconclusive")  # unreadable, never a pass
        verdicts = dict((node, v) for node, v, _ in h.binary_checks(mapped, {**versions, "nuremberg": None}, shas))
        self.assertEqual(verdicts["nuremberg"], "inconclusive")
        self.assertEqual(h.binary_checks({}, {}, {}), [])

    def test_expect_mixed_needs_verified_running_binaries(self):
        mapped, _ = h.node_binary_map(self.doc(), self.endpoints())
        shas = {node: entry["daemon_sha256"] for node, entry in mapped.items()}
        self.assertEqual(h.mixed_check(mapped, shas)[0], "pass")
        self.assertEqual(h.mixed_check(mapped, {**shas, "sfo": None})[0], "inconclusive")
        self.assertEqual(h.mixed_check(mapped, {**shas, "sfo": "c" * 64})[0], "inconclusive")
        same = {node: {"daemon_sha256": "a" * 64, "deployed_version": "0.46.3"} for node in LABELS}
        verdict, facts = h.mixed_check(same, {node: "a" * 64 for node in LABELS})
        self.assertEqual((verdict, facts["distinct_running_binaries"]), ("fail", 1))

    def test_resolve_hosts_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            tokens = os.path.join(tmp, "vps-tokens-test.env")
            open(tokens, "w").close()
            self.assertEqual(h.resolve_hosts_json(None, tokens), (None, "absent"))
            sibling = os.path.join(tmp, "testnet-hosts.json")
            open(sibling, "w").close()
            self.assertEqual(h.resolve_hosts_json(None, tokens), (sibling, "sibling"))
            self.assertEqual(h.resolve_hosts_json("/x/hosts.json", tokens), ("/x/hosts.json", "explicit"))


class ArgumentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tokens = os.path.join(self.tmp.name, "vps-tokens-test.env")
        with open(self.tokens, "w") as handle:
            for i, label in enumerate(LABELS + ["sydney"]):
                handle.write(f'TEST_{label.upper()}_IP="203.0.113.{i + 1}"\nTEST_{label.upper()}_TK="{"0" * 63}{i}"\n')

    def tearDown(self):
        self.tmp.cleanup()

    def argv(self, *extra):
        return ["--network", "test", "--tokens-file", self.tokens, "--report", "/dev/null", *extra]

    def write_hosts(self, mutate=None):
        hosts = [{"label": label, "public_ipv4": f"203.0.113.{i + 1}", "daemon_sha256": str(i % 2) * 64,
                  "daemon_version": "x0xd 0.46.3"} for i, label in enumerate(LABELS + ["sydney"])]
        if mutate:
            mutate(hosts)
        with open(os.path.join(self.tmp.name, "testnet-hosts.json"), "w") as handle:
            json.dump({"schema_version": 1, "kind": "x0x-testnet-hosts", "hosts": hosts}, handle)

    def test_eph_table_argv_parses(self):
        args = h.parse_and_validate(self.argv("--nodes", *LABELS, "--variant", "plain", "--variant", "restart",
                                              "--allow-service-restart"))
        self.assertEqual(args.variant, ["plain", "restart"])
        self.assertEqual(args.plane, ["gss", "treekem"])
        self.assertEqual(args.roles["remover"], "nyc")
        self.assertEqual(args.hosts_json_source, "absent")
        self.assertEqual(args.node_binaries, {})
        self.assertEqual((args.watch_secs, args.rejoin_watch_secs, args.restart_lead_secs), (40.0, 30.0, 15.0))

    def test_defaults_run_both_variants_and_need_restart_permission(self):
        with self.assertRaises(SystemExit):
            h.parse_and_validate(self.argv())
        args = h.parse_and_validate(self.argv("--variant", "plain"))
        self.assertEqual(args.nodes, LABELS)

    def test_rejections(self):
        for extra in (("--variant", "plain", "--nodes", *LABELS[:4]),
                      ("--variant", "plain", "--nodes", "nyc", "sfo", "nyc", "helsinki", "sydney"),
                      ("--variant", "plain", "--nodes", *LABELS[:4], "london"),
                      ("--variant", "plain", "--variant", "plain"),
                      ("--variant", "plain", "--restart-lead-secs", "25"),
                      ("--variant", "plain", "--expect-mixed")):
            with self.subTest(extra=extra), self.assertRaises(SystemExit):
                h.parse_and_validate(self.argv(*extra))

    def test_durations_must_be_finite_and_above_their_minimums(self):
        """Review item 7."""
        bad = {"--watch-secs": ("0", "-1", "nan", "inf", "-inf", "29.9", "abc", "3601"),
               "--rejoin-watch-secs": ("0", "-5", "nan", "9"),
               "--rekey-timeout": ("0", "nan", "inf", "9"),
               "--poll-timeout": ("-1", "nan", "5"),
               "--restart-lead-secs": ("nan", "inf", "9.9", "20.5")}
        for flag, values in bad.items():
            for value in values:
                with self.subTest(flag=flag, value=value), self.assertRaises(SystemExit):
                    h.parse_and_validate(self.argv("--variant", "plain", flag, value))
        args = h.parse_and_validate(self.argv("--variant", "plain", "--watch-secs", "30", "--rejoin-watch-secs", "10",
                                              "--rekey-timeout", "10", "--poll-timeout", "10",
                                              "--restart-lead-secs", "20"))
        self.assertEqual((args.watch_secs, args.rejoin_watch_secs, args.restart_lead_secs), (30.0, 10.0, 20.0))
        clients = {label: object() for label in LABELS}
        for kwargs in ({"watch_secs": float("nan")}, {"watch_secs": 0}, {"rejoin_watch_secs": -1},
                       {"rekey_timeout": float("inf")}, {"probe_period": float("nan")}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                h.RekeyScenario(clients, h.RekeyEvidence(), 1.0, **kwargs)
        with self.assertRaises(ValueError):
            h.RekeyScenario(clients, h.RekeyEvidence(), float("nan"))

    def test_sibling_hosts_file_must_be_complete(self):
        self.write_hosts()
        args = h.parse_and_validate(self.argv("--variant", "plain", "--expect-mixed"))
        self.assertEqual(args.hosts_json_source, "sibling")
        self.assertEqual(len(args.hosts_json_sha256), 64)
        self.assertEqual(set(args.node_binaries), set(LABELS))
        for mutate in (lambda hosts: hosts[1].update(public_ipv4="198.51.100.1"),
                       lambda hosts: hosts[2].update(daemon_sha256=""),
                       lambda hosts: hosts[3].update(daemon_version="unknown"),
                       lambda hosts: hosts[4].pop("daemon_version")):
            self.write_hosts(mutate)
            with self.assertRaises(SystemExit):
                h.parse_and_validate(self.argv("--variant", "plain"))


class ScenarioTests(unittest.TestCase):
    def run_block(self, plane, variant="plain", **kwargs):
        s, net, clock, scans = scenario(plane, **kwargs)
        restart = net.restart if variant == "restart" else None
        s.run_block(variant, plane, h.assign_roles(LABELS), restart)
        return s, net, clock, scans

    def run_failing_block(self, plane, expected=AssertionError, **kwargs):
        s, net, _clock, _scans = scenario(plane, **kwargs)
        with self.assertRaises(expected):
            s.run_block("plain", plane, h.assign_roles(LABELS), None)
        return s, net

    def test_block_passes_on_both_planes_and_variants(self):
        for plane in h.PLANES:
            for variant in h.VARIANTS:
                with self.subTest(plane=plane, variant=variant):
                    s, net, _clock, scans = self.run_block(plane, variant, lag={"sfo": 3})
                    self.assertEqual(failed_labels(s), [])
                    self.assertEqual(s.e.verdict(), "pass")
                    self.assertEqual([c["case"] for c in s.e.cases],
                                     [f"{variant}/{plane}/remove", f"{variant}/{plane}/ban"])
                    remove, ban = s.e.cases
                    self.assertEqual(remove["survivors"], ["sfo", "helsinki", "singapore"])
                    self.assertEqual(ban["survivors"], ["sfo", "helsinki"])
                    self.assertEqual((remove["departed"], ban["departed"]), ([], ["nuremberg"]))
                    for case in s.e.cases:
                        self.assertEqual(case["outcome"], "passed")
                        self.assertEqual(case["stable_group_id"], STABLE)
                        self.assertGreater(case["epoch_after"], case["epoch_before"])
                        self.assertEqual(case["rekey"]["rekey_latency_s"]["sfo"], 2.0)
                        self.assertEqual(case["rekey"]["slowest_survivor"], "sfo")
                        self.assertEqual(case["rekey"]["unconverged"], [])
                        self.assertEqual(case["versions"]["survivors"]["sfo"], "0.46.3")
                        self.assertIn("journal_remover", case)
                        for obs in case["rekey"]["excluded"].values():
                            self.assertGreaterEqual(obs["probes"], 10)
                            self.assertEqual(obs["errors"], 0)
                        if variant == "restart":
                            self.assertEqual(case["restart"]["lead_seconds"], 15.0)
                        else:
                            self.assertIsNone(case["restart"])
                        self.assertEqual("reseal" in case, plane == "gss")
                    # Review item 6: the earlier removed member is probed during the ban.
                    self.assertEqual(set(ban["rekey"]["excluded"]), {"singapore", "nuremberg"})
                    self.assertEqual(ban["exclusion_evidence"]["singapore"]["d60"], "key")
                    self.assertEqual(ban["rejoin"]["seat_reason"], "refused")
                    self.assertNotIn("rejoin", remove)
                    self.assertEqual(net.restarts, ["nyc", "nyc"] if variant == "restart" else [])
                    # The remover's journal window starts at its own clock, read at case start.
                    self.assertEqual([node for node, _ in scans], ["nyc", "nyc"])
                    self.assertTrue(all(isinstance(since, int) for _, since in scans))
                    limited = sorted((lim["case"], lim["node"]) for lim in s.e.limitations)
                    labels = [r["label"] for r in s.e.assertions]
                    # A removed member answers the membership gate and journal silence is no
                    # evidence, so its D60 is listed as limited and never claimed, on both planes.
                    self.assertEqual(limited, [(f"{variant}/{plane}/ban", "nuremberg"),
                                               (f"{variant}/{plane}/remove", "nuremberg")])
                    self.assertNotIn(f"{variant}/{plane}/remove: no post-remove key reaches nuremberg "
                                     f"during the watch (D60)", labels)
                    self.assertTrue(all(lim["evidence_class"] == "limited" for lim in s.e.limitations))
                    self.assertEqual(remove["exclusion_evidence"]["nuremberg"]["d60"], "membership_gate")
                    if plane == "gss":
                        self.assertEqual(remove["reseal"]["response_class"], "recipient_not_member")
                        self.assertEqual(ban["reseal"]["response_class"], "recipient_not_active")
                        self.assertEqual(ban["rekey"]["excluded"]["singapore"]["max_local_epoch"],
                                         ban["epoch_before"])
                        # Leak scans ran for every excluded node, from clocks read before the act.
                        self.assertEqual(sorted(node for node, _ in net.install_scans),
                                         ["nuremberg", "nuremberg", "singapore"])
                    else:
                        self.assertEqual(net.install_scans, [])
                    self.assertIn(f"{variant}/{plane}: helsinki key installed after join "
                                  f"(decrypts post-join message)", labels)
                    self.assertIn(f"{variant}/{plane}/ban: no post-ban key reaches singapore during the watch (D60)",
                                  labels)
                    self.assertIn(f"{variant}/{plane}/ban: nuremberg cannot decrypt the post-ban message", labels)
                    report = json.dumps(s.e.report())
                    for secret in net.secrets:
                        self.assertNotIn(secret, report)

    # --- item 1: D60 needs key evidence --------------------------------------

    def test_gss_removed_member_with_or_without_journal_scan_is_limited(self):
        for share_installs in (False, None):
            with self.subTest(share_installs=share_installs):
                s, *_ = self.run_block("gss", share_installs=share_installs)
                self.assertEqual(failed_labels(s), [])
                self.assertEqual(sorted((lim["case"], lim["node"]) for lim in s.e.limitations),
                                 [("plain/gss/ban", "nuremberg"), ("plain/gss/remove", "nuremberg")])
                self.assertNotIn("plain/gss/remove: no post-remove key reaches nuremberg during the watch (D60)",
                                 [r["label"] for r in s.e.assertions])

    def test_epoch_mismatch_without_local_epoch_is_limited_not_claimed(self):
        """Review r2 item 1, end to end: the banned GSS target answers a typed epoch
        mismatch that omits its local epoch."""
        def no_local_epoch(net, label, method, path, body):
            if label == "singapore" and path.endswith("/secure/decrypt") and net.state["singapore"] == "banned":
                return 409, {"ok": False, "error": "epoch mismatch — re-share required"}
            return None
        s, *_ = self.run_block("gss", override=no_local_epoch)
        self.assertEqual(failed_labels(s), [])
        limitation = next(lim for lim in s.e.limitations if lim["node"] == "singapore")
        self.assertEqual((limitation["case"], limitation["gate_evidence"]), ("plain/gss/ban", "epoch_unreported"))
        self.assertNotIn("plain/gss/ban: no post-ban key reaches singapore during the watch (D60)",
                         [r["label"] for r in s.e.assertions])

    def test_journal_window_starts_at_the_node_clock_read_before_the_action(self):
        """Review r2 item 5: the install-scan start is each excluded node's own clock,
        read before the removal, never a duration computed at scan time."""
        s, net, *_ = self.run_block("gss")
        reads = {value: (node, state) for node, value, state in net.clock_reads}
        remove_case = s.e.cases[0]
        nuremberg_since = remove_case["node_clocks"]["nuremberg"]
        self.assertEqual(reads[nuremberg_since], ("nuremberg", "active"))  # still a member: before the act
        self.assertIn(("nuremberg", nuremberg_since), net.install_scans)
        ban_case = s.e.cases[1]
        self.assertEqual(reads[ban_case["node_clocks"]["singapore"]], ("singapore", "active"))
        self.assertEqual(reads[ban_case["node_clocks"]["nyc"]][0], "nyc")

    def test_missing_node_clock_disables_the_leak_scan(self):
        s, net, *_ = self.run_block("gss", remote_clock=False)
        self.assertEqual(net.install_scans, [])
        self.assertEqual(s.e.cases[0]["share_install_witness"]["nuremberg"], {"error_class": "no_remote_clock"})
        self.assertEqual(failed_labels(s), [])

    def test_gss_share_install_on_removed_member_fails_d60(self):
        def installs(net, node, gid):
            leaked = node == "nuremberg" and net.state["nuremberg"] == "removed"
            return {**CLEAN_JOURNAL, "attributed_epochs": [net.epoch] if leaked else [],
                    "attributed_max_epoch": net.epoch if leaked else None}
        s, _net = self.run_failing_block("gss", share_installs=installs)
        failing = row(s, "plain/gss/remove: no post-remove key reaches nuremberg during the watch (D60)")
        self.assertFalse(failing["passed"])
        self.assertEqual(failing["evidence_class"], "journal_install")
        self.assertNotIn("verdict", failing)
        self.assertEqual(s.e.verdict(), "fail")

    # --- item 2: an erroring excluded node is inconclusive ---------------------

    def test_target_server_errors_make_the_case_inconclusive(self):
        def errors(net, label, method, path, body):
            if label == "nuremberg" and path.endswith("/secure/decrypt") and net.state["nuremberg"] == "removed":
                return 500, {"error": "boom"}
            return None
        s, _net = self.run_failing_block("gss", override=errors)
        decrypt = row(s, "plain/gss/remove: nuremberg cannot decrypt the post-remove message")
        d60 = row(s, "plain/gss/remove: no post-remove key reaches nuremberg during the watch (D60)")
        for result in (decrypt, d60):
            self.assertFalse(result["passed"])
            self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(s.e.cases[0]["outcome"], "inconclusive")
        self.assertEqual(s.e.verdict(), "inconclusive")

    def test_target_transport_errors_make_the_case_inconclusive(self):
        def offline(net, label, method, path, body):
            if label == "nuremberg" and path.endswith("/secure/decrypt") and net.state["nuremberg"] == "removed":
                raise TimeoutError("offline")
            return None
        s, _net = self.run_failing_block("treekem", override=offline)
        decrypt = row(s, "plain/treekem/remove: nuremberg cannot decrypt the post-remove message")
        self.assertEqual((decrypt["passed"], decrypt["verdict"]), (False, "inconclusive"))
        self.assertEqual(list(decrypt["probe_classes"]), ["transport:TimeoutError"])
        self.assertEqual(s.e.cases[0]["outcome"], "inconclusive")

    def test_untyped_or_fork_refusals_from_the_target_are_inconclusive(self):
        """Review r2 item 2, end to end."""
        for name, response in (("unrelated 403", (403, {"error": "rider tokens cannot read"})),
                               ("fork 500", (500, {"error": "x", "reason": "fork_quarantined"})),
                               ("fork 409", (409, {"error": "x", "reason": "fork_quarantined"})),
                               ("untyped 404", (404, {"error": "store not found"}))):
            with self.subTest(name=name):
                def refuse(net, label, method, path, body, response=response):
                    if (label == "nuremberg" and path.endswith("/secure/decrypt")
                            and net.state["nuremberg"] == "removed"):
                        return response
                    return None
                s, _net = self.run_failing_block("treekem", expected=h.Inconclusive, override=refuse)
                result = row(s, "plain/treekem/remove: nuremberg cannot decrypt the post-remove message")
                self.assertEqual((result["passed"], result["verdict"]), (False, "inconclusive"))
                self.assertEqual(s.e.verdict(), "inconclusive")

    def test_final_probe_error_is_inconclusive(self):
        def final_errors(net, label, method, path, body):
            if path.endswith("/secure/reseal"):
                net.flags.add("after_reseal")
            if label == "nuremberg" and path.endswith("/secure/decrypt") and "after_reseal" in net.flags:
                return 503, {"error": "unavailable"}
            return None
        s, _net = self.run_failing_block("gss", override=final_errors)
        final = row(s, "plain/gss/remove: nuremberg cannot decrypt the final message")
        self.assertEqual((final["passed"], final["verdict"], final["response_class"]),
                         (False, "inconclusive", "http_other"))
        self.assertEqual(s.e.cases[0]["outcome"], "inconclusive")

    # --- item 3: reseal needs the explicit refusal ----------------------------

    def test_reseal_server_error_or_transport_error_is_inconclusive(self):
        for name, response in (("http500", (500, {"error": "boom"})), ("transport", ConnectionError("down"))):
            with self.subTest(name=name):
                def reseal(net, label, method, path, body, response=response):
                    if path.endswith("/secure/reseal"):
                        if isinstance(response, Exception):
                            raise response
                        return response
                    return None
                s, _net = self.run_failing_block("gss", override=reseal)
                result = row(s, "plain/gss/remove: remover refuses to seal the current secret to nuremberg "
                                "(recipient ineligible)")
                self.assertEqual((result["passed"], result["verdict"]), (False, "inconclusive"))
                self.assertEqual(s.e.cases[0]["outcome"], "inconclusive")

    def test_reseal_to_removed_member_fails_and_envelope_never_recorded(self):
        s, _net = self.run_failing_block("gss", reseal_leaks=True)
        self.assertEqual(failed_labels(s), ["plain/gss/remove: remover refuses to seal the current secret to "
                                            "nuremberg (recipient ineligible)"])
        self.assertEqual(s.e.verdict(), "fail")
        self.assertNotIn("SECRET-ENVELOPE", json.dumps(s.e.report()))

    # --- item 4: the banned re-join outcome is asserted ------------------------

    def test_rejoin_request_failure_is_inconclusive(self):
        def join_fails(net, label, method, path, body):
            if label == "singapore" and path == "/groups/join" and net.state["singapore"] == "banned":
                raise ConnectionError("down")
            return None
        s, _net = self.run_failing_block("treekem", override=join_fails)
        result = row(s, "plain/treekem/ban: banned singapore re-join is never seated")
        self.assertEqual((result["passed"], result["verdict"], result["reason"]),
                         (False, "inconclusive", "join_request_error"))
        self.assertEqual(s.e.cases[1]["outcome"], "inconclusive")

    def test_invalid_roster_reads_during_rejoin_are_inconclusive(self):
        def roster_fails(net, label, method, path, body):
            if label == "singapore" and path == "/groups/join" and net.state["singapore"] == "banned":
                net.flags.add("rejoin")
            if label == "nyc" and path.endswith("/members") and method == "GET" and "rejoin" in net.flags:
                return 500, {"error": "boom"}
            return None
        s, _net = self.run_failing_block("gss", override=roster_fails)
        result = row(s, "plain/gss/ban: banned singapore re-join is never seated")
        self.assertEqual((result["passed"], result["verdict"], result["reason"]),
                         (False, "inconclusive", "invalid_roster_read"))
        self.assertGreater(result["roster_reads"]["invalid"], 0)

    def test_untyped_join_refusal_is_inconclusive(self):
        """Review r2 item 3, end to end."""
        def untyped(net, label, method, path, body):
            if label == "singapore" and path == "/groups/join" and net.state["singapore"] == "banned":
                return 409, {"ok": False, "error": "conflict"}
            return None
        s, _net = self.run_failing_block("gss", expected=h.Inconclusive, override=untyped)
        result = row(s, "plain/gss/ban: banned singapore re-join is never seated")
        self.assertEqual((result["verdict"], result["reason"]), ("inconclusive", "untyped_join_refusal"))

    def test_fork_quarantined_rejoin_is_inconclusive_not_a_pass(self):
        """Review r3: a typed fork-quarantine 409 on the banned re-join must not pass."""
        for body in ({"ok": False, "error": "group is fork-quarantined", "reason": "fork_quarantined"},
                     {"ok": False, "error": "fork_quarantined"}):
            with self.subTest(body=body):
                def quarantined(net, label, method, path, request, body=body):
                    if label == "singapore" and path == "/groups/join" and net.state["singapore"] == "banned":
                        return 409, body
                    return None
                s, _net = self.run_failing_block("gss", expected=h.Inconclusive, override=quarantined)
                result = row(s, "plain/gss/ban: banned singapore re-join is never seated")
                self.assertEqual((result["passed"], result["verdict"], result["reason"]),
                                 (False, "inconclusive", "untyped_join_refusal"))
                self.assertIsNone(result["attempt"]["refusal_code"])
                s.e.assertions.append(h.aborted_row("plain/gss: block aborted", h.Inconclusive("x")))
                self.assertEqual(h.final_verdict(s.e, True), "inconclusive")
                self.assertEqual(h.exit_code(h.final_verdict(s.e, True)), 3)

    def test_typed_join_refusal_passes(self):
        def typed(net, label, method, path, body):
            if label == "singapore" and path == "/groups/join" and net.state["singapore"] == "banned":
                return 409, {"ok": False, "error": "join_already_pending"}
            return None
        s, *_ = self.run_block("gss", override=typed)
        self.assertEqual(failed_labels(s), [])
        self.assertEqual(s.e.cases[1]["rejoin"]["seat_reason"], "refused")
        self.assertEqual(s.e.cases[1]["rejoin"]["attempt"]["refusal_code"], "join_already_pending")

    def test_roster_rows_missing_state_during_rejoin_are_inconclusive(self):
        """Review r2 item 3: a row without its state is an invalid read, not a valid absence."""
        def stateless(net, label, method, path, body):
            if label == "singapore" and path == "/groups/join" and net.state["singapore"] == "banned":
                net.flags.add("rejoin")
            if label == "nyc" and method == "GET" and path.endswith("/members") and "rejoin" in net.flags:
                return 200, {"members": [{"agent_id": net.agents[x]} for x in net.labels
                                         if net.state[x] in ("active", "banned")]}
            return None
        s, _net = self.run_failing_block("gss", expected=h.Inconclusive, override=stateless)
        result = row(s, "plain/gss/ban: banned singapore re-join is never seated")
        self.assertEqual((result["verdict"], result["reason"]), ("inconclusive", "invalid_roster_read"))

    def test_invalid_join_status_is_inconclusive(self):
        def status_fails(net, label, method, path, body):
            if label == "singapore" and path.endswith("/join-status"):
                return 500, {}
            return None
        s, _net = self.run_failing_block("gss", override=status_fails)
        result = row(s, "plain/gss/ban: banned singapore re-join is never seated")
        self.assertEqual((result["verdict"], result["reason"]), ("inconclusive", "invalid_join_status"))

    def test_seated_banned_member_fails_the_rejoin_check(self):
        s, _net = self.run_failing_block("treekem", seat_banned=True)
        result = row(s, "plain/treekem/ban: banned singapore re-join is never seated")
        self.assertFalse(result["passed"])
        self.assertNotIn("verdict", result)
        self.assertEqual(s.e.cases[1]["outcome"], "failed")

    # --- item 6: the earlier removed member is probed during the ban ------------

    def test_ban_rotation_reaching_the_removed_member_is_caught_by_decrypt(self):
        s, _net = self.run_failing_block("gss", leak_to_on_ban="nuremberg")
        self.assertIn("plain/gss/ban: nuremberg cannot decrypt the post-ban message", failed_labels(s))
        self.assertEqual(s.e.cases[0]["outcome"], "passed")
        self.assertEqual(s.e.cases[1]["outcome"], "failed")

    def test_ban_rotation_reaching_the_removed_member_is_caught_by_journal(self):
        def installs(net, node, gid):
            leaked = node == "nuremberg" and net.state["singapore"] == "banned"
            return {**CLEAN_JOURNAL, "attributed_epochs": [net.epoch] if leaked else [],
                    "attributed_max_epoch": net.epoch if leaked else None}
        s, _net = self.run_failing_block("gss", share_installs=installs)
        self.assertEqual(failed_labels(s),
                         ["plain/gss/ban: no post-ban key reaches nuremberg during the watch (D60)"])

    # --- earlier behaviour ---------------------------------------------------

    def test_leak_to_removed_member_fails_the_d60_checks(self):
        s, _net = self.run_failing_block("gss", leak_to="nuremberg")
        self.assertEqual(failed_labels(s), [
            "plain/gss/remove: nuremberg cannot decrypt the post-remove message",
            "plain/gss/remove: no post-remove key reaches nuremberg during the watch (D60)"])
        self.assertEqual(s.e.cases[0]["outcome"], "failed")
        self.assertIn("journal_remover", s.e.cases[0])

    def test_survivor_that_never_rekeys_fails_but_target_is_still_watched(self):
        s, _net = self.run_failing_block("treekem", lag={"helsinki": 10 ** 6})
        self.assertEqual(failed_labels(s),
                         ["plain/treekem/remove: helsinki rekeyed and decrypts the post-remove message"])
        rekey = s.e.cases[0]["rekey"]
        self.assertEqual(rekey["unconverged"], ["helsinki"])
        self.assertGreaterEqual(rekey["excluded"]["nuremberg"]["observed_until_s"], 30.0)

    def test_join_readiness_needs_the_key_not_the_roster(self):
        s, _net = self.run_failing_block("treekem", expected=PollTimeout, poll_timeout=0.05,
                                         withhold_join_key=("helsinki",))
        last = s.e.assertions[-1]
        self.assertEqual(last["label"], "plain/treekem: helsinki key installed after join (decrypts post-join message)")
        self.assertFalse(last["passed"])
        self.assertIn("poll_timeout", last)
        # The roster-and-local-active barrier itself was satisfied: only the key proof failed.
        self.assertTrue(any(p.get("label") == "plain/treekem: helsinki on owner roster and locally active"
                            and p.get("outcome") == "accepted" for p in s.e.polls))

    def test_restart_with_a_changed_binary_fails(self):
        shas = iter(["a" * 64, "b" * 64])
        s, net, *_ = scenario("gss")
        s.binary_sha = lambda node: next(shas)
        with self.assertRaises(AssertionError):
            s.run_block("restart", "gss", h.assign_roles(LABELS), net.restart)
        self.assertEqual(failed_labels(s), ["restart/gss/remove: remover runs the same binary after the restart"])

    def test_restart_with_an_unreadable_binary_is_inconclusive(self):
        s, net, *_ = scenario("gss", binary_sha=None)
        with self.assertRaises(AssertionError):
            s.run_block("restart", "gss", h.assign_roles(LABELS), net.restart)
        result = row(s, "restart/gss/remove: remover runs the same binary after the restart")
        self.assertEqual((result["passed"], result["verdict"]), (False, "inconclusive"))

    def test_slow_restart_is_inconclusive(self):
        holder = {}

        def slow_health(label):
            if label == "nyc" and holder["net"].uptime["nyc"] == 0 and not holder.get("slowed"):
                holder["slowed"] = True
                holder["clock"].sleep(25)

        s, net, clock, _ = scenario("gss", on_health=slow_health)
        holder.update(net=net, clock=clock)
        with self.assertRaises(AssertionError):
            s.run_block("restart", "gss", h.assign_roles(LABELS), net.restart)
        failing = next(r for r in s.e.assertions if not r["passed"])
        self.assertEqual(failing["label"], "restart/gss/remove: remove starts 10-20 s after the remover restart")
        self.assertEqual(failing["verdict"], "inconclusive")
        self.assertEqual(failing["lead_seconds"], 25.0)
        self.assertEqual(s.e.cases[0]["outcome"], "inconclusive")


class EvidenceTests(unittest.TestCase):
    def test_verdict_rows_and_outcomes(self):
        e = h.RekeyEvidence()
        self.assertEqual(e.verdict_row("a", "pass"), "pass")
        self.assertEqual(e.verdict(), "pass")
        e.verdict_row("b", "inconclusive")
        self.assertEqual(e.assertions[-1], {"label": "b", "passed": False, "verdict": "inconclusive"})
        self.assertEqual(e.verdict(), "inconclusive")
        self.assertEqual(h.rows_outcome(e.assertions, True), "inconclusive")
        e.verdict_row("c", "fail")
        self.assertEqual(e.verdict(), "fail")
        self.assertEqual(h.rows_outcome(e.assertions, True), "failed")
        self.assertEqual(h.rows_outcome([{"label": "x", "passed": True}], False), "failed")
        with self.assertRaises(ValueError):
            e.verdict_row("d", "limited")
        self.assertIn("limitations", e.report())
        with self.assertRaises(h.Inconclusive):
            h.require_all_pass("case", ["pass", "inconclusive"])
        with self.assertRaises(AssertionError) as raised:
            h.require_all_pass("case", ["inconclusive", "fail"])
        self.assertNotIsInstance(raised.exception, h.Inconclusive)
        h.require_all_pass("case", ["pass", "pass"])
        self.assertTrue(math.isfinite(h.DURATION_BOUNDS["--watch-secs"][0]))

    def test_inconclusive_stays_inconclusive_end_to_end(self):
        """Review r2 item 6: the block handler's row, the report verdict and the exit code."""
        inconclusive_row = h.aborted_row("plain/gss: block aborted", h.Inconclusive("x"))
        self.assertEqual(inconclusive_row, {"label": "plain/gss: block aborted", "passed": False,
                                            "error_class": "Inconclusive", "verdict": "inconclusive"})
        failure_row = h.aborted_row("plain/gss: block aborted", AssertionError("x"))
        self.assertNotIn("verdict", failure_row)
        self.assertEqual(h.exit_code("pass"), 0)
        self.assertEqual(h.exit_code("fail"), 1)
        self.assertEqual(h.exit_code("inconclusive"), 3)
        e = h.RekeyEvidence()
        self.assertEqual(h.final_verdict(e, True), "fail")  # no case cannot pass
        e.verdict_row("x", "inconclusive")
        self.assertEqual(h.final_verdict(e, False), "inconclusive")
        e.cases.append({"case": "c"})
        e.assertions.append(failure_row)
        self.assertEqual(h.final_verdict(e, True), "fail")

    def test_block_handler_keeps_an_inconclusive_case_inconclusive(self):
        def errors(net, label, method, path, body):
            if label == "nuremberg" and path.endswith("/secure/decrypt") and net.state["nuremberg"] == "removed":
                return 502, {}
            return None
        s, net, *_ = scenario("gss", override=errors)
        try:
            s.run_block("plain", "gss", h.assign_roles(LABELS), None)
        except Exception as error:  # what main() does with a block's exception
            s.e.assertions.append(h.aborted_row("plain/gss: block aborted", error))
        self.assertEqual(s.e.cases[0]["outcome"], "inconclusive")
        self.assertEqual(s.e.assertions[-1]["verdict"], "inconclusive")
        self.assertEqual(s.e.verdict(), "inconclusive")
        self.assertEqual(h.final_verdict(s.e, True), "inconclusive")
        self.assertEqual(h.exit_code(h.final_verdict(s.e, True)), 3)

    def test_block_handler_keeps_a_failed_case_failed(self):
        s, *_ = scenario("gss", leak_to="nuremberg")
        try:
            s.run_block("plain", "gss", h.assign_roles(LABELS), None)
        except Exception as error:
            s.e.assertions.append(h.aborted_row("plain/gss: block aborted", error))
        self.assertEqual(s.e.verdict(), "fail")
        self.assertEqual(h.exit_code(h.final_verdict(s.e, True)), 1)

    def test_remote_clock_and_journal_window_helpers(self):
        self.assertEqual(h.parse_remote_clock("1800000000\n"), 1800000000)
        for text in ("", "abc", "-5", "12", None, "1800000000 extra"):
            self.assertIsNone(h.parse_remote_clock(text))
        self.assertEqual(h.journal_since(1800000000), "1799999999")
        self.assertIsNone(h.journal_since(None))
        self.assertIsNone(h.journal_since(True))
        # Without a node clock no scan runs (and no SSH is attempted).
        self.assertEqual(h.scan_journal("203.0.113.1", None), {"error_class": "no_remote_clock"})
        self.assertEqual(h.scan_share_installs("203.0.113.1", None, STABLE), {"error_class": "no_remote_clock"})


if __name__ == "__main__":
    unittest.main()
