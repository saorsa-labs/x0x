#!/usr/bin/env python3
"""Offline controls for the isolated synthetic Home fixture."""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def load():
    tests = Path(__file__).parent
    sys.path.insert(0, str(tests))
    spec = importlib.util.spec_from_file_location("e2e_home_fixture", tests / "e2e_home_fixture.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module); return module


class HomeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.h = load()

    def node(self, label="owner"):
        return self.h.Node(label, "192.0.2.1", 14600, 7483,
                           "/var/tmp/x0x-home-e2e-" + "a" * 32)

    def test_config_is_isolated_and_never_uses_prod_or_testnet_plane(self):
        text = self.h.config_bytes(self.node(), "x0x.home.e2e." + "a" * 32, None).decode()
        self.assertIn('network_id = "x0x.home.e2e.', text)
        self.assertIn("bootstrap_peers = []", text)
        self.assertIn("mdns_enabled = false", text)
        self.assertIn("port_mapping_enabled = false", text)
        self.assertIn("rendezvous_enabled = false", text)
        self.assertNotIn("x0x.testnet", text)

    def test_remote_command_preserves_hostile_arguments_and_stdin(self):
        args = ["space value", "apostrophe'quote", "dollar$()", "semi;colon", "star*"]
        script = "printf '<%s>\\n' \"$@\"; cat"
        command = self.h.Remote.command(script, args, input_bytes=True)
        result = subprocess.run(command, shell=True, input=b"synthetic-stdin", capture_output=True,
                                timeout=5, check=True)
        expected = b"".join(f"<{value}>\n".encode() for value in args) + b"synthetic-stdin"
        self.assertEqual(expected, result.stdout)
        streamed = self.h.Remote.command(script, args, input_bytes=False)
        result = subprocess.run(streamed, shell=True, input=script.encode(), capture_output=True,
                                timeout=5, check=True)
        self.assertEqual(b"".join(f"<{value}>\n".encode() for value in args), result.stdout)

    def test_partial_start_creates_cleanup_obligation_before_ssh_result(self):
        remote = mock.Mock()
        remote.run.side_effect = RuntimeError("ambiguous ssh failure")
        custody = self.h.SyntheticProcessCustody(remote, "/opt/x0x/x0xd", "a" * 32)
        with self.assertRaises(RuntimeError): custody.start(self.node())
        self.assertEqual(self.node(), custody.started["owner"])

    def test_generated_stop_validator_checks_exact_argv_and_start_time(self):
        with tempfile.TemporaryDirectory(prefix="home-fixture-shell-") as root:
            proc = Path(root) / "proc"; process = proc / "4242"; process.mkdir(parents=True)
            Path(f"{root}/fixture.marker").write_text("marker\n")
            Path(f"{root}/config.toml").write_text("fixture=true\n")
            binary = Path(root) / "x0xd"; binary.write_bytes(b"synthetic-binary")
            (process / "exe").write_bytes(binary.read_bytes())
            argv = bytes(binary) + b"\0--config\0" + f"{root}/config.toml".encode() + b"\0"
            (process / "cmdline").write_bytes(argv)
            fields = ["0"] * 22; fields[4] = "4242"; fields[21] = "98765"
            (process / "stat").write_text(" ".join(fields) + "\n")
            Path(f"{root}/daemon.pid").write_text("4242 98765\n")
            for name, path in (("config", Path(root) / "config.toml"), ("binary", binary)):
                digest = subprocess.check_output(["sha256sum", str(path)], text=True).split()[0]
                Path(f"{root}/{name}.sha256").write_text(digest + "\n")
            script = self.h.stop_script(str(proc), terminate=False)
            command = self.h.Remote.command(script, [root, "marker", str(binary)], input_bytes=False)
            subprocess.run(command, shell=True, input=script.encode(), timeout=5, check=True)
            (process / "cmdline").write_bytes(argv + b"unexpected\0")
            refused = subprocess.run(command, shell=True, input=script.encode(), timeout=5, check=False)
            self.assertNotEqual(0, refused.returncode)
            (process / "cmdline").write_bytes(argv)
            Path(f"{root}/daemon.pid").write_text("4242 98766\n")
            reused = subprocess.run(command, shell=True, input=script.encode(), timeout=5, check=False)
            self.assertNotEqual(0, reused.returncode)

    def test_generated_cleanup_term_kill_timeout_and_identity_change(self):
        for mode, expected, calls, receipt_remains in (
            ("term_success", 0, ["-TERM"], False),
            ("kill_needed", 0, ["-TERM", "-KILL"], False),
            ("timeout", 42, ["-TERM", "-KILL"], True),
            ("identity_change", 0, ["-TERM"], False),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="home-stop-") as root:
                proc = Path(root) / "proc"; process = proc / "4242"; process.mkdir(parents=True)
                Path(f"{root}/fixture.marker").write_text("marker\n")
                Path(f"{root}/config.toml").write_text("fixture=true\n")
                binary = Path(root) / "x0xd"; binary.write_bytes(b"synthetic-binary")
                (process / "exe").write_bytes(binary.read_bytes())
                argv = bytes(binary) + b"\0--config\0" + f"{root}/config.toml".encode() + b"\0"
                (process / "cmdline").write_bytes(argv)
                fields = ["0"] * 22; fields[4] = "4242"; fields[21] = "98765"
                (process / "stat").write_text(" ".join(fields) + "\n")
                Path(f"{root}/daemon.pid").write_text("4242 98765\n")
                for name, path in (("config", Path(root) / "config.toml"), ("binary", binary)):
                    digest = subprocess.check_output(["sha256sum", str(path)], text=True).split()[0]
                    Path(f"{root}/{name}.sha256").write_text(digest + "\n")
                log = Path(root) / "signals"
                killer = Path(root) / "kill-stub"
                killer.write_text("""#!/bin/sh
echo "$1" >> "$SIGNAL_LOG"
case "$FIXTURE_MODE:$1" in
  term_success:-TERM|kill_needed:-KILL) rm -rf "$PROC_ROOT/4242" ;;
  identity_change:-TERM) awk '{$22=98766; print}' "$PROC_ROOT/4242/stat" > "$PROC_ROOT/stat.tmp"; mv "$PROC_ROOT/stat.tmp" "$PROC_ROOT/4242/stat" ;;
esac
"""); killer.chmod(0o700)
                sleeper = Path(root) / "sleep-stub"; sleeper.write_text("#!/bin/sh\nexit 0\n"); sleeper.chmod(0o700)
                script = self.h.stop_script(str(proc), kill_command=str(killer), sleep_command=str(sleeper))
                command = self.h.Remote.command(script, [root, "marker", str(binary)], input_bytes=False)
                env = dict(os.environ, FIXTURE_MODE=mode, PROC_ROOT=str(proc), SIGNAL_LOG=str(log))
                result = subprocess.run(command, shell=True, input=script.encode(), timeout=5,
                                        check=False, env=env)
                self.assertEqual(expected, result.returncode)
                self.assertEqual(calls, log.read_text().splitlines())
                self.assertEqual(receipt_remains, Path(f"{root}/daemon.pid").exists())

    def test_missing_cmdline_requires_proof_recorded_identity_is_gone(self):
        for mode, expected, receipt_remains in (
            ("same", 41, True), ("changed", 0, False), ("vanished", 0, False),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="home-cmdline-") as root:
                proc = Path(root) / "proc"; process = proc / "4242"; process.mkdir(parents=True)
                Path(f"{root}/fixture.marker").write_text("marker\n")
                Path(f"{root}/daemon.pid").write_text("4242 98765\n")
                fields = ["0"] * 22; fields[4] = "4242"
                fields[21] = "98766" if mode == "changed" else "98765"
                (process / "stat").write_text(" ".join(fields) + "\n")
                if mode == "vanished":
                    (process / "stat").unlink()
                # No cmdline exists. A signal stub would make any accidental
                # progression beyond the identity proof observable.
                signal_stub = Path(root) / "signal-stub"
                signal_stub.write_text("#!/bin/sh\nexit 99\n"); signal_stub.chmod(0o700)
                script = self.h.stop_script(str(proc), kill_command=str(signal_stub))
                command = self.h.Remote.command(script, [root, "marker", str(Path(root) / "x0xd")],
                                                input_bytes=False)
                result = subprocess.run(command, shell=True, input=script.encode(), timeout=5,
                                        check=False)
                self.assertEqual(expected, result.returncode)
                self.assertEqual(receipt_remains, Path(f"{root}/daemon.pid").exists())

    def test_unowned_and_identity_mismatch_stops_fail_closed(self):
        remote = mock.Mock()
        custody = self.h.SyntheticProcessCustody(remote, "/opt/x0x/x0xd", "a" * 32)
        with self.assertRaisesRegex(RuntimeError, "unowned"):
            custody.stop("owner")
        custody.started["owner"] = self.node()
        remote.run.side_effect = RuntimeError("owned remote operation failed (1)")
        with self.assertRaises(RuntimeError): custody.stop("owner")
        # A failed validation is not converted into a successful stop or dropped obligation.
        self.assertIn("owner", custody.started)

    def args(self):
        return argparse.Namespace(hosts_file="hosts", nodes=["owner", "writer", "late", "revoked", "outsider"],
                                  daemon_binary="/opt/x0x/x0xd", cli_binary="/opt/x0x/x0x",
                                  api_port_base=14600, quic_port_base=7483, local_port_base=24700,
                                  poll_timeout=20)

    def test_full_preparation_certifies_only_members_and_proves_outsider_denial(self):
        args = self.args(); evidence = self.h.Evidence(); resources = {}
        tokens = {n: (f"192.0.2.{i}", "unused") for i, n in enumerate(args.nodes, 1)}
        class Custody:
            instance = None
            def __init__(self, *_args): self.stopped = set(); self.certs = []; Custody.instance = self
            def prepare(self, *_args): pass
            def create_owner_key(self, *_args): pass
            def start(self, node): self.stopped.discard(node.label)
            def stop(self, label): self.stopped.add(label)
            def restart(self, label): self.stopped.discard(label)
            def write_certificate(self, node, cert): self.certs.append((node.label, cert))
            def token(self, _node): return "synthetic-token"
            def hashes(self, node): return (str(args.nodes.index(node.label) + 1) * 64, "f" * 64)
            def restore(self): return []
        class Client:
            def __init__(self, label): self.label = label; self.calls = []
            def agent_id(self):
                if self.label in Custody.instance.stopped: raise AssertionError("stopped identity queried")
                return (str(args.nodes.index(self.label) + 1) * 64)[:64]
            def request(self, method, path, body=None):
                if self.label in Custody.instance.stopped: raise AssertionError("stopped daemon queried")
                self.calls.append((method, path, body))
                if path == "/home": return 200, {"state": "local", "owner_user_id": "f" * 64,
                                                    "primary_agent": {"verified": True}}
                if path == "/agent/card": return 200, {"agent_public_key": f"pub-{self.label}"}
                if path == "/owner/agents/issue": return 200, {"certificate": {"storage_b64": "Y2VydA=="}}
                if path == "/home/seat": return 200, {"invite": "x0x://invite/outsider"}
                if path == "/groups/join": return 403, {"ok": False}
                if path.endswith("/members"):
                    return 200, {"members": [{"agent_id": (str(i) * 64)[:64]} for i in (1, 2, 3)]}
                return 200, {"ok": True}
        clients = {n: Client(n) for n in args.nodes}
        tunnels = [mock.Mock(local_port=24700 + i) for i in range(5)]
        def scenario(_self, owner, writer, late, revoked, stop_owner, restart_writer):
            self.assertEqual((owner, writer, late, revoked), tuple(args.nodes[:4]))
            stop_owner(); restart_writer("gid", {clients[n].agent_id() for n in ("writer", "late")}
                                                  | {("1" * 64)})
        with mock.patch.object(self.h, "load_tokens", return_value=tokens), \
             mock.patch.object(self.h, "SyntheticProcessCustody", Custody), \
             mock.patch.object(self.h, "start_ssh_tunnel", side_effect=tunnels), \
             mock.patch.object(self.h, "Api", side_effect=[clients[n] for n in args.nodes]), \
             mock.patch.object(self.h.Scenario, "run_home", autospec=True, side_effect=scenario), \
             mock.patch.object(self.h.uuid, "uuid4", return_value=mock.Mock(hex="a" * 32)):
            self.assertTrue(self.h.run_fixture(args, mock.Mock(), evidence, resources))
        self.assertEqual(["writer", "late", "revoked"], [label for label, _ in Custody.instance.certs])
        outsider_join = [c for c in clients["outsider"].calls if c[1] == "/groups/join"]
        self.assertEqual(1, len(outsider_join))
        self.assertIn("owner", Custody.instance.stopped)
        self.assertIn("late", Custody.instance.stopped)

    def test_partial_provision_and_report_failure_still_cleanup_every_resource(self):
        custody = mock.Mock(); custody.restore.return_value = []
        tunnel = mock.Mock()
        def fail(_args, _remote, _evidence, resources):
            resources["custody"] = custody; resources["tunnels"] = [tunnel]
            raise RuntimeError("partial provision")
        argv = ["fixture", "--network", "synthetic-home", "--hosts-file", "hosts",
                "--nodes", "a", "b", "c", "d", "e", "--daemon-binary", "/x0xd",
                "--cli-binary", "/x0x", "--report", "/cannot/write"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(self.h, "run_fixture", side_effect=fail), \
             mock.patch.object(self.h, "stop_ssh_tunnel") as stop, \
             mock.patch("builtins.open", side_effect=OSError("report")):
            self.assertEqual(1, self.h.main())
        custody.restore.assert_called_once_with(); stop.assert_called_once_with(tunnel)


if __name__ == "__main__": unittest.main()
