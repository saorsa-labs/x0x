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

    def test_prereq_blocking_incomplete_under_modern_expect_fixed(self):
        # Mirror main()._prereq_blocking: incomplete_policy blocks modern
        class Args:
            modern_only = True
            expect_fixed = True
        args = Args()
        def _prereq_blocking(g):
            st = g.get("status")
            if args.modern_only and st == SOAK.NOT_IN_MODERN_PREDICATE:
                return False
            if args.modern_only and st == SOAK.INCOMPLETE_POLICY:
                return True
            return st in ("fail", "unsupported")
        self.assertTrue(_prereq_blocking(
            {"status": SOAK.INCOMPLETE_POLICY}))
        self.assertTrue(_prereq_blocking({"status": "fail"}))
        self.assertFalse(_prereq_blocking(
            {"status": SOAK.NOT_IN_MODERN_PREDICATE}))
        self.assertFalse(_prereq_blocking({"status": "pass"}))


if __name__ == "__main__":
    unittest.main()
