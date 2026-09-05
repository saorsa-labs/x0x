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


if __name__ == "__main__":
    unittest.main()
