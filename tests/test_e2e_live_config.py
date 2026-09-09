"""Inert checks for the actual config renderer; no fleet or token access."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

from e2e_live_config import render_config


class LiveConfigTests(unittest.TestCase):
    def setUp(self):
        self.owner = tempfile.TemporaryDirectory(prefix="x0x config test ")
        self.addCleanup(self.owner.cleanup)
        self.repository = Path(self.owner.name)
        self.authority = self.repository / ".deployment/config/bootstrap-config-testnet.toml"
        self.authority.parent.mkdir(parents=True)

    def write_peers(self, peers):
        self.authority.write_text("bootstrap_peers = " + json.dumps(peers) + "\n")

    def test_testnet_reads_ordered_authority_and_roundtrips_paths(self):
        peers = ["[::1]:6483", "127.0.0.1:6483"]
        self.write_peers(peers)
        path = 'data with spaces, "quotes", \\slash, ü, \U0001f680 and \x7f'
        config = tomllib.loads(render_config("test", self.repository, path))
        self.assertEqual(config["bootstrap_peers"], peers)
        self.assertEqual(config["data_dir"], path)
        self.assertEqual(config["instance_name"], "e2e-live")
        self.assertEqual(config["bind_address"], "0.0.0.0:15483")
        self.assertEqual(config["api_address"], "127.0.0.1:19200")
        self.assertEqual(config["log_level"], "warn")
        self.assertNotIn("network_id", config)
        self.assertEqual(config["update"], {"enabled": False, "gossip_updates": False})

    def test_actual_tracked_testnet_authority_is_used(self):
        repository = Path(__file__).resolve().parent.parent
        authority = repository / ".deployment/config/bootstrap-config-testnet.toml"
        with authority.open("rb") as stream:
            expected = tomllib.load(stream)["bootstrap_peers"]
        config = tomllib.loads(render_config("test", repository, "/tmp/x0x-e2e-live"))
        self.assertEqual(config["bootstrap_peers"], expected)

    def test_prod_omits_override_even_without_testnet_authority(self):
        config = tomllib.loads(render_config("prod", self.repository, "data"))
        self.assertNotIn("bootstrap_peers", config)
        self.assertNotIn("network_id", config)
        self.assertEqual(config["update"], {"enabled": False, "gossip_updates": False})

    def test_bad_authority_never_falls_back_to_prod(self):
        cases = [[], "127.0.0.1:6483", [1], ["127.0.0.1:5483"],
                 ["127.0.0.1:443"], ["host.invalid:6483"], ["::1:6483"],
                 ["[127.0.0.1]:6483"], ["[fe80::1%lo]:6483"]]
        for peers in cases:
            with self.subTest(peers=peers):
                self.write_peers(peers)
                with self.assertRaises(ValueError):
                    render_config("test", self.repository, "data")

    def test_missing_malformed_or_absent_list_fails(self):
        with self.assertRaises(FileNotFoundError):
            render_config("test", self.repository, "data")
        for text in ["bootstrap_peers = [", "log_level = 'warn'\n"]:
            with self.subTest(text=text):
                self.authority.write_text(text)
                with self.assertRaises(ValueError):
                    render_config("test", self.repository, "data")

    def test_cli_failure_returns_no_usable_config(self):
        helper = Path(__file__).with_name("e2e_live_config.py")
        result = subprocess.run(
            [sys.executable, "-B", str(helper), "--network", "test",
             "--repository", str(self.repository), "--data-dir", "data"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("Cannot prepare live-test configuration", result.stderr)

    def test_unknown_network_is_rejected(self):
        with self.assertRaises(ValueError):
            render_config("unknown", self.repository, "data")

    def test_non_unicode_path_is_rejected_before_rendering(self):
        with self.assertRaises(UnicodeError):
            render_config("prod", self.repository, "invalid-\udcff")


if __name__ == "__main__":
    unittest.main()
