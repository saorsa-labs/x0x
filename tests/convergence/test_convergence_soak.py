"""Offline storage-isolation regressions; never start a daemon."""

import importlib.util
import pathlib
import tempfile
import tomllib
import unittest


SCRIPT = pathlib.Path(__file__).with_name("convergence_soak.py")
SPEC = importlib.util.spec_from_file_location("convergence_soak", SCRIPT)
SOAK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOAK)


class NodeIdentityIsolationTests(unittest.TestCase):
    def test_current_and_legacy_nodes_use_disposable_identity_directory(self):
        # A named legacy daemon otherwise falls back to the real user's home,
        # even though application data already lives in a temporary directory.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            identities = []
            for name, binary in (("current", "x0xd"),
                                 ("mv-lb-owner", "x0xd-0.30.1"),
                                 ("mv-dg-joiner", "x0xd-0.30.1")):
                with self.subTest(name=name):
                    node = SOAK.Node(name, 27810, 27910, root,
                                     pathlib.Path(binary), "warn")
                    node.write_config([])
                    config = tomllib.loads(node.config_path.read_text())
                    identity = pathlib.Path(config["identity_dir"])
                    self.assertEqual(identity, node.data_dir)
                    self.assertTrue(identity.is_relative_to(root))
                    self.assertTrue(identity.is_dir())
                    self.assertEqual(config["data_dir"], str(identity))
                    self.assertEqual(config["instance_name"], name)
                    self.assertEqual(config["bootstrap_peers"], [])
                    self.assertFalse(config["update"]["enabled"])
                    identities.append(identity)
            self.assertEqual(len(set(identities)), len(identities))

    def test_port_reconfiguration_preserves_identity_storage(self):
        # The reconnect phase changes transport coordinates, not the storage
        # that supplies MachineId/AgentId on the next daemon start.
        with tempfile.TemporaryDirectory() as tmp:
            node = SOAK.Node("reconnect", 27812, 27912, pathlib.Path(tmp),
                             pathlib.Path("x0xd"), "warn")
            node.write_config([27910])
            before = tomllib.loads(node.config_path.read_text())
            marker = pathlib.Path(before["identity_dir"]) / "identity-marker"
            marker.write_text("disposable test marker, not key material")
            node.reconfigure_port(28111, [27910, 27911])
            after = tomllib.loads(node.config_path.read_text())
            self.assertEqual(after["identity_dir"], before["identity_dir"])
            self.assertEqual(after["data_dir"], before["data_dir"])
            self.assertEqual(after["api_address"], before["api_address"])
            self.assertEqual(after["bind_address"], "127.0.0.1:28111")
            self.assertEqual(after["bootstrap_peers"],
                             ["127.0.0.1:27910", "127.0.0.1:27911"])
            self.assertEqual(marker.read_text(),
                             "disposable test marker, not key material")




class ModernOnlyPredicateTests(unittest.TestCase):
    """Hermetic ADR-014 modern-only classifier + env-refuse self-tests."""

    def test_refuse_legacy_env_when_env_set(self):
        err = SOAK.refuse_legacy_env_under_modern_only(
            legacy_binary=None,
            environ={"X0XD_LEGACY_BINARY": "/tmp/fake-x0xd-0.30.1"})
        self.assertIsNotNone(err)
        self.assertIn("REFUSING", err)
        self.assertIn("X0XD_LEGACY_BINARY", err)

    def test_refuse_legacy_env_when_flag_path_set(self):
        err = SOAK.refuse_legacy_env_under_modern_only(
            legacy_binary="/tmp/fake-x0xd-0.30.1",
            environ={})
        self.assertIsNotNone(err)
        self.assertIn("REFUSING", err)

    def test_allow_when_legacy_unset(self):
        err = SOAK.refuse_legacy_env_under_modern_only(
            legacy_binary=None, environ={})
        self.assertIsNone(err)

    def test_classifier_labels_mixed_version_not_pass(self):
        raw = [
            {"name": "mixed_version_skew_load_bearing", "status": "pass"},
            {"name": "mixed_version_skew_degraded", "status": "unsupported"},
            {"name": "malicious_owner_announce", "status": "pass"},
        ]
        classified = SOAK.classify_prereq_gates_for_modern(raw)
        by_name = {g["name"]: g for g in classified}
        for name in SOAK.MODERN_EXCLUDED_GATE_NAMES:
            self.assertIn(name, by_name)
            self.assertEqual(by_name[name]["status"],
                             SOAK.NOT_IN_MODERN_PREDICATE)
            self.assertNotEqual(by_name[name]["status"], "pass")
        self.assertEqual(by_name["malicious_owner_announce"]["status"], "pass")

    def test_modern_excluded_gate_record_never_pass(self):
        rec = SOAK.modern_excluded_gate_record(
            "mixed_version_skew_load_bearing")
        self.assertEqual(rec["status"], SOAK.NOT_IN_MODERN_PREDICATE)
        self.assertEqual(rec["predicate"], SOAK.NOT_IN_MODERN_PREDICATE)
        self.assertNotEqual(rec["status"], "pass")

    def test_policy_admission_none_policy_incomplete(self):
        g = SOAK.classify_modern_policy_admission(None, False)
        self.assertEqual(g["name"], SOAK.MODERN_POLICY_ADMISSION)
        self.assertEqual(g["status"], SOAK.INCOMPLETE_POLICY)
        self.assertNotEqual(g["status"], "pass")

    def test_policy_admission_none_grants_incomplete(self):
        # reject_v1 without proven grants-disabled evidence must not PASS
        g = SOAK.classify_modern_policy_admission("reject_v1", None)
        self.assertEqual(g["status"], SOAK.INCOMPLETE_POLICY)
        self.assertNotEqual(g["status"], "pass")

    def test_policy_admission_accept_v1_fail(self):
        g = SOAK.classify_modern_policy_admission("accept_v1", False)
        self.assertEqual(g["status"], "fail")
        self.assertIn("AcceptV1", g["reason"])

    def test_policy_admission_grants_enabled_fail(self):
        g = SOAK.classify_modern_policy_admission("reject_v1", True)
        self.assertEqual(g["status"], "fail")
        self.assertEqual(g["reason"], "grants_enabled")

    def test_policy_admission_reject_v1_grants_disabled_pass(self):
        g = SOAK.classify_modern_policy_admission("reject_v1", False)
        self.assertEqual(g["status"], "pass")
        self.assertEqual(g["outer_signature_policy"], "reject_v1")
        self.assertIs(g["grants_enabled"], False)

    def test_policy_admission_extract_missing_grants_is_none(self):
        # #546 tip exposes policy/receipts but not grants — must stay unproven
        body = {"outer_signature_policy": "reject_v1", "outer_v1_receipts": 0}
        self.assertEqual(
            SOAK.extract_policy_from_diagnostics_body(body), "reject_v1")
        self.assertIsNone(
            SOAK.extract_grants_enabled_from_diagnostics_body(body))

    def test_shared_prereq_gate_is_blocking_incomplete_under_modern_expect_fixed(self):
        # Call the production helper (not a local copy) so divergence/deletion
        # of the shared predicate is caught.
        kw = dict(modern_only=True, expect_fixed=True)
        self.assertTrue(SOAK.prereq_gate_is_blocking(
            {"status": SOAK.INCOMPLETE_POLICY}, **kw))
        self.assertTrue(SOAK.prereq_gate_is_blocking(
            {"status": "fail"}, **kw))
        self.assertTrue(SOAK.prereq_gate_is_blocking(
            {"status": "unsupported"}, **kw))
        self.assertFalse(SOAK.prereq_gate_is_blocking(
            {"status": SOAK.NOT_IN_MODERN_PREDICATE}, **kw))
        self.assertFalse(SOAK.prereq_gate_is_blocking(
            {"status": "pass"}, **kw))

    def test_summarize_overall_fails_on_incomplete_policy_modern_expect_fixed(self):
        # summarize OVERALL must share the same blocking as main() exit.
        class Args:
            nodes = 3
            expect_fixed = True
            modern_only = True
        runs = [{"pass": True, "phases": {}, "diagnostics_deltas": {}}]
        gates = [{"name": SOAK.MODERN_POLICY_ADMISSION,
                  "status": SOAK.INCOMPLETE_POLICY}]
        text = SOAK.summarize(runs, Args(), prereq_gates=gates)
        self.assertIn("OVERALL: FAIL", text)
        self.assertNotIn("OVERALL: PASS", text)

    def test_summarize_overall_pass_when_only_not_in_modern(self):
        class Args:
            nodes = 3
            expect_fixed = True
            modern_only = True
        runs = [{"pass": True, "phases": {}, "diagnostics_deltas": {}}]
        gates = [{"name": "mixed_version_skew_load_bearing",
                  "status": SOAK.NOT_IN_MODERN_PREDICATE}]
        text = SOAK.summarize(runs, Args(), prereq_gates=gates)
        self.assertIn("OVERALL: PASS", text)

    def test_grants_extractor_null_empty_wrong_types_are_none(self):
        # P2-1: bool(None/0/"") must NOT become False; empty inventory ≠ disabled.
        cases = [
            {"legacy_grants_enabled": None},
            {"legacy_grants_enabled": 0},
            {"legacy_grants_enabled": ""},
            {"grants_enabled": None},
            {"grants_enabled": 0},
            {"grants_enabled": ""},
            {"legacy_grants": []},
            {"legacy_grants": {}},
            {"migration_grants": []},
            {"migration_grants": {}},
            {"migration_grants": None},
        ]
        for body in cases:
            with self.subTest(body=body):
                self.assertIsNone(
                    SOAK.extract_grants_enabled_from_diagnostics_body(body))

    def test_grants_extractor_classifier_null_empty_do_not_pass(self):
        # extractor→classifier: malformed evidence must stay incomplete, never PASS.
        bodies = [
            {"outer_signature_policy": "reject_v1",
             "legacy_grants_enabled": None},
            {"outer_signature_policy": "reject_v1",
             "legacy_grants_enabled": 0},
            {"outer_signature_policy": "reject_v1",
             "legacy_grants_enabled": ""},
            {"outer_signature_policy": "reject_v1", "legacy_grants": []},
            {"outer_signature_policy": "reject_v1", "legacy_grants": {}},
            {"outer_signature_policy": "reject_v1", "migration_grants": []},
            # enabled-but-empty inventory is not a disabled attestation
            {"outer_signature_policy": "reject_v1",
             "legacy_grants": [], "grants_note": "enabled-but-empty"},
        ]
        for body in bodies:
            with self.subTest(body=body):
                g_flag = SOAK.extract_grants_enabled_from_diagnostics_body(body)
                self.assertIsNone(g_flag)
                gate = SOAK.classify_modern_policy_admission(
                    "reject_v1", g_flag)
                self.assertEqual(gate["status"], SOAK.INCOMPLETE_POLICY)
                self.assertNotEqual(gate["status"], "pass")

    def test_grants_extractor_explicit_false_passes_classifier(self):
        for key in ("legacy_grants_enabled", "grants_enabled"):
            with self.subTest(key=key):
                body = {"outer_signature_policy": "reject_v1", key: False}
                g_flag = SOAK.extract_grants_enabled_from_diagnostics_body(body)
                self.assertIs(g_flag, False)
                gate = SOAK.classify_modern_policy_admission(
                    "reject_v1", g_flag)
                self.assertEqual(gate["status"], "pass")

    def test_classifier_requires_grants_enabled_is_false(self):
        # Identity check: not-True/not-None must not PASS.
        for bad in (0, "", [], {}, "disabled"):
            with self.subTest(bad=bad):
                gate = SOAK.classify_modern_policy_admission("reject_v1", bad)
                self.assertEqual(gate["status"], SOAK.INCOMPLETE_POLICY)

    def test_probe_reaps_owned_child_on_wait_ready_failure(self):
        # P2-3: inert Node — start ok, wait_ready raises → exact stop/reap;
        # outcome remains incomplete_policy. No PID/port scanning.
        stops = []

        class InertNode:
            def __init__(self, name, api_port, quic_port, root_dir, x0xd,
                         log_level):
                self.name = name
                self.api_port = api_port
                self.quic_port = quic_port
                self.proc = object()
                self.token = None
                self._started = False

            def write_config(self, bootstrap_quic_ports):
                return None

            def start(self):
                self._started = True

            def wait_ready(self, timeout=60):
                raise RuntimeError(f"{self.name}: /health not up in {timeout}s")

            def stop(self, grace=8):
                # Match Node.stop: idempotent once reaped (helper + finally).
                if self.proc is None:
                    return
                stops.append(self)
                self.proc = None

            @property
            def running(self):
                return self.proc is not None

            def req(self, *a, **k):
                raise AssertionError("req must not be called after wait failure")

        class Args:
            api_base = 27810
            quic_base = 27910
            x0xd = pathlib.Path("x0xd")
            log_level = "warn"

        real_node = SOAK.Node
        SOAK.Node = InertNode
        try:
            with tempfile.TemporaryDirectory() as tmp:
                gate = SOAK.run_modern_policy_admission_gate(
                    Args(), tmp, nodes=[])
        finally:
            SOAK.Node = real_node

        self.assertEqual(gate["status"], SOAK.INCOMPLETE_POLICY)
        self.assertEqual(len(stops), 1, "owned child must be stop/reaped exactly")
        self.assertIs(stops[0].proc, None)


if __name__ == "__main__":
    unittest.main()
