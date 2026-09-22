#!/usr/bin/env python3
"""Offline controls for the isolated synthetic Home fixture."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
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

    def run_model(self, fixture=None, scenario_cls=None):
        """Run the REAL run_fixture -> run_home -> exercise ordering against a stateful model.

        The model encodes the product facts the harness depends on: a Home join is
        admitted only by an online inviter, POST /home/seat needs the owner key and an
        Admin seat, user-identity announce needs the owner key, and an uncertified,
        keyless device is refused (403).
        """
        h = fixture or self.h
        args = self.args(); evidence = self.h.Evidence(); resources = {}
        tokens = {n: (f"192.0.2.{i}", "unused") for i, n in enumerate(args.nodes, 1)}
        ids = {n: (str(i) * 64) for i, n in enumerate(args.nodes, 1)}
        owner_user, gid, owner_key = "f" * 64, "home-gid", "k" * 64
        events: list[tuple] = []
        world = {"seats": {"owner": "admin"}, "certs": set(), "announced": set(), "invites": {}, "kv": {}}

        class Custody:
            instance = None
            def __init__(self, *_args):
                self.offline, self.keys, self.started = set(), {}, set(); Custody.instance = self
            def prepare(self, *_args): pass
            def create_owner_key(self, node, *_args): self.keys[node.label] = owner_key
            def start(self, node):
                self.offline.discard(node.label); self.started.add(node.label); events.append(("start", node.label))
            def stop(self, label):
                if label not in self.started: raise RuntimeError("unowned")
                self.offline.add(label); events.append(("stop", label))
            def restart(self, label): self.stop(label); self.offline.discard(label); events.append(("start", label))
            def write_certificate(self, node, _cert): world["certs"].add(node.label)
            def key_fingerprint(self, node):
                events.append(("keycheck", node.label)); return self.keys.get(node.label)
            def copy_owner_key(self, source, target):
                if target.label in self.keys or target.label not in self.offline:
                    raise RuntimeError("key copy refused")
                self.keys[target.label] = self.keys[source.label]; events.append(("copy", target.label))
                return self.keys[target.label]
            def token(self, _node): return "synthetic-token"
            def hashes(self, node): return (str(args.nodes.index(node.label) + 1) * 64, "f" * 64)
            def restore(self): return []

        def online(label): return label not in Custody.instance.offline

        class Client:
            def __init__(self, label): self.label = label
            def agent_id(self):
                if not online(self.label): raise AssertionError(f"stopped {self.label} identity queried")
                return ids[self.label]
            def request(self, method, path, body=None):
                me = self.label
                if not online(me): raise AssertionError(f"stopped {me} daemon queried")
                events.append(("req", me, method, path))
                seats = world["seats"]
                keyed = me in Custody.instance.keys
                if path == "/home": return 200, {"state": "local", "group_id": gid, "owner_user_id": owner_user,
                                                    "primary_agent": {"verified": True}}
                if path == "/health": return 200, {"ok": True}
                if path == "/agent/card": return 200, {"agent_public_key": f"pub-{me}"}
                if path == "/agent/user-id": return 200, {"ok": True, "user_id": owner_user if keyed else None}
                if path == "/owner/agents/issue": return 200, {"certificate": {"storage_b64": "Y2VydA=="}}
                if path == "/announce":
                    if not (keyed and me in world["certs"]): return 400, {"ok": False}
                    world["announced"].add(me); return 200, {"ok": True}
                if path == "/home/seat":
                    target = next(n for n, i in ids.items() if i == body["agent_id"])
                    if not keyed or seats.get(me) != "admin": return 403, {"ok": False}
                    invite = f"x0x://invite/{me}-{target}"; world["invites"][invite] = me
                    return 200, {"ok": True, "group_id": gid, "owner_user_id": owner_user,
                                 "intended_joiner": ids[target], "seated": False, "invite": invite}
                if path == "/groups/join":
                    if me not in world["announced"]: return 403, {"ok": False}
                    if online(world["invites"][body["invite"]]): seats[me] = "member"
                    return 200, {"ok": True, "group_id": gid}
                members = f"/groups/{gid}/members"
                if path == members:
                    return 200, {"members": [{"agent_id": ids[n], "role": r} for n, r in seats.items()]}
                if method == "PATCH" and path.startswith(members + "/"):
                    target = next(n for n, i in ids.items() if i in path)
                    seats[target] = body["role"]; return 200, {"ok": True, "role": body["role"]}
                if method == "DELETE" and path.startswith(members + "/"):
                    seats.pop(next(n for n, i in ids.items() if i in path)); return 200, {"ok": True}
                if path == f"/groups/{gid}/stores":
                    if me not in seats: return 403, {"ok": False}
                    return 200, {"ok": True, "id": f"sid-{body['name']}", "store_id": "0" * 64}
                if path.startswith("/stores/"):
                    if me not in seats: return 403, {"ok": False}
                    if method == "PUT": world["kv"][path] = body["value"]; return 200, {"ok": True}
                    if method == "DELETE": world["kv"].pop(path, None); return 200, {"ok": True}
                    if path in world["kv"]: return 200, {"ok": True, "value": world["kv"][path]}
                    return 404, {"ok": False}
                raise AssertionError(f"unmodelled request {method} {path}")

        def fake_poll(label, _timeout, probe, accept, receipt=None):
            result = probe()
            if not accept(result): raise AssertionError(f"{label}: condition not met")
            return result

        clients = {n: Client(n) for n in args.nodes}
        tunnels = [mock.Mock(local_port=24700 + i) for i in range(5)]
        patches = [mock.patch.object(h, "load_tokens", return_value=tokens),
                   mock.patch.object(h, "SyntheticProcessCustody", Custody),
                   mock.patch.object(h, "start_ssh_tunnel", side_effect=tunnels),
                   mock.patch.object(h, "Api", side_effect=[clients[n] for n in args.nodes]),
                   mock.patch.object(h, "poll", fake_poll),
                   mock.patch("e2e_vps_kv.poll", fake_poll),
                   mock.patch("e2e_vps_private_kv.poll", fake_poll),
                   mock.patch.object(h.uuid, "uuid4", return_value=mock.Mock(hex="a" * 32))]
        if scenario_cls is not None:
            patches.append(mock.patch.object(h, "Scenario", scenario_cls))
            patches.append(mock.patch.object(sys.modules[scenario_cls.__module__], "poll", fake_poll))
        error = None
        with contextlib.ExitStack() as stack:
            for patch in patches: stack.enter_context(patch)
            try:
                h.run_fixture(args, mock.Mock(), evidence, resources)
            except AssertionError as caught:
                error = caught
        return events, Custody.instance, world, evidence, error

    def test_full_preparation_certifies_same_owner_devices_and_proves_outsider_denial(self):
        events, custody, world, evidence, error = self.run_model()
        self.assertIsNone(error)
        self.assertTrue(all(row["passed"] for row in evidence.assertions))
        # Every Home device holds the SAME fixture owner key and a certificate.
        self.assertEqual({"owner", "writer", "late", "revoked", "outsider"}, set(custody.keys))
        self.assertEqual(1, len(set(custody.keys.values())))
        self.assertEqual({"writer", "late", "revoked", "outsider"}, world["certs"])
        # The 403 negative happens before any key reaches the fifth node.
        denial = events.index(("req", "outsider", "POST", "/groups/join"))
        self.assertLess(events.index(("keycheck", "outsider")), denial)
        self.assertLess(denial, events.index(("copy", "outsider")))
        labels = [row["label"] for row in evidence.assertions]
        self.assertIn("uncertified outsider is refused Home", labels)
        self.assertIn("original owner device offline during admission", labels)
        self.assertIn("owner and admin devices offline during history; "
                      "history served by same-owner Member-role device", labels)
        self.assertIn("home writer remains Member role", labels)
        # Writer is never promoted; the outsider-turned-admin is.
        patches = [e for e in events if e[:3] == ("req", "owner", "PATCH")]
        self.assertEqual(1, len(patches)); self.assertIn("5" * 64, patches[0][3])
        self.assertEqual("member", world["seats"]["writer"])
        # Ordering chain through the real run_home/exercise. Certification also
        # stops devices, so the admin stop and writer restart are the LAST stops.
        def last(event): return len(events) - 1 - events[::-1].index(event)
        late_seat = [i for i, e in enumerate(events) if e[:2] == ("req", "outsider") and e[3] == "/home/seat"][-1]
        # The plain-Member writer observes the Admin role after promotion and
        # before the late invite is minted (its roster read in that window).
        writer_sees_admin = next(i for i in range(events.index(patches[0]), late_seat)
                                 if events[i][:4] == ("req", "writer", "GET", "/groups/home-gid/members"))
        chain = [next(i for i, e in enumerate(events) if e[:3] == ("req", "owner", "DELETE")),
                 events.index(patches[0]), writer_sees_admin, late_seat, events.index(("stop", "owner")),
                 events.index(("req", "late", "POST", "/groups/join")), last(("stop", "outsider")),
                 next(i for i, e in enumerate(events) if e[:2] == ("req", "late") and "/stores" in e[3]),
                 last(("stop", "writer"))]
        self.assertEqual(sorted(chain), chain)
        self.assertEqual({"owner", "writer", "late", "outsider"}, set(world["seats"]))

    def test_revert_controls_fail(self):
        tests = Path(__file__).parent
        def mutant(path, name, *edits):
            source = (tests / path).read_text()
            for old, new in edits:
                if source.count(old) != 1: raise AssertionError(f"anchor not unique: {old!r}")
                source = source.replace(old, new)
            module = types.ModuleType(name); module.__file__ = str(tests / path)
            sys.modules[name] = module; exec(compile(source, str(tests / path), "exec"), module.__dict__)
            return module
        fixture = "e2e_home_fixture.py"; harness = "e2e_vps_private_kv.py"
        cases = {
            "announce without owner key": (mutant(fixture, "m_nokey", (
                "        fingerprint = custody.copy_owner_key(nodes[owner], nodes[label])\n",
                "        fingerprint = owner_key_sha\n")), None),
            "outsider keyed before denial": (mutant(fixture, "m_early", (
                "    admin = outsider\n    certify_same_owner_device(admin)\n", "    admin = outsider\n"), (
                "    evidence.check(\"outsider holds no owner key before denial\",",
                "    certify_same_owner_device(outsider)\n    evidence.check(\"outsider holds no owner key before denial\",")),
                None),
            "history before admin stop": (None, mutant(harness, "m_hist", (
                """        stop_admin()
        self.e.check(history_offline_label""", """        self.e.check(history_offline_label"""), (
                "        expected = set(actor_ids.values())\n",
                "        stop_admin()\n        expected = set(actor_ids.values())\n")).Scenario),
            "late seat minted by owner after stop": (None, mutant(harness, "m_owner", (
                "lambda: self.home_invite(admin, late, gid, owner_id)",
                "lambda: self.home_invite(owner, late, gid, owner_id)")).Scenario),
            "late seat minted by writer": (None, mutant(harness, "m_writer", (
                "lambda: self.home_invite(admin, late, gid, owner_id)",
                "lambda: self.home_invite(writer, late, gid, owner_id)")).Scenario),
        }
        for name, (fixture_module, scenario_cls) in cases.items():
            with self.subTest(revert=name):
                _events, _custody, _world, evidence, error = self.run_model(fixture_module, scenario_cls)
                failed = error is not None or not all(row["passed"] for row in evidence.assertions)
                self.assertTrue(failed, f"revert {name} was not detected")

    def test_copy_owner_key_validates_custody_and_never_returns_key_bytes(self):
        remote = mock.Mock()
        custody = self.h.SyntheticProcessCustody(remote, "/opt/x0x/x0xd", "m" * 32)
        owner, target = self.node("owner"), self.node("writer")
        custody.started["writer"] = target
        with self.assertRaises(RuntimeError):
            custody.copy_owner_key(owner, target)  # running device refused
        custody.offline.add("writer")
        key = b"synthetic-owner-key"
        digest = hashlib.sha256(key).hexdigest()
        remote.run.side_effect = [key, b"", (digest + "\n").encode()]
        self.assertEqual(digest, custody.copy_owner_key(owner, target))
        read, write, verify = remote.run.call_args_list
        self.assertIn("fixture.marker", read.args[1]); self.assertTrue(read.kwargs["capture"])
        self.assertEqual(key, write.kwargs["input_bytes"])
        self.assertIn("umask 077", write.args[1]); self.assertIn('[ ! -e "$root/identity/user.key" ]', write.args[1])
        self.assertIn("user.key.tmp", write.args[1]); self.assertNotIn(key.decode(), " ".join(write.args[2]))
        with self.assertRaises(ValueError):
            custody.copy_owner_key(owner, owner)

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

    def test_main_report_exports_stores_polls_and_custody_for_gui_acceptance(self):
        # Root GUI acceptance must work from the frozen report alone: group and
        # store IDs plus page keys from evidence.stores, convergence receipts
        # from evidence.polls, custody hash receipts from the manifest.
        manifest = {"run_id": "a" * 32, "network_id": f"x0x.home.e2e.{'a' * 32}",
                    "binary_sha256": "b" * 64, "config_sha256": {"owner": "c" * 64}}
        def populate(_args, _remote, evidence, resources):
            resources["manifest"] = manifest
            evidence.check("home writer remains Member role", True, role="member")
            for app in ("wiki", "web"):
                evidence.record_store("writer", "home-gid", app,
                                      {"id": f"topic-{app}", "store_id": "0" * 64})
            evidence.record_poll({"label": "late roster on owner", "outcome": "accepted"},
                                 operation="role", node="writer", group_id="home-gid", role="admin")
            return True
        with tempfile.TemporaryDirectory(prefix="home-fixture-report-") as root:
            report = Path(root) / "report.json"
            argv = ["fixture", "--network", "synthetic-home", "--hosts-file", "hosts",
                    "--nodes", "a", "b", "c", "d", "e", "--daemon-binary", "/x0xd",
                    "--cli-binary", "/x0x", "--report", str(report)]
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(self.h, "run_fixture", side_effect=populate):
                self.assertEqual(0, self.h.main())
            data = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual({"scenario", "custody", "stores", "polls", "assertions"}, set(data))
        self.assertEqual("synthetic-home", data["scenario"])
        self.assertEqual(manifest, data["custody"])
        self.assertEqual([{"node": "writer", "group_id": "home-gid", "app": app,
                           "topic": f"topic-{app}", "store_id": "0" * 64}
                          for app in ("wiki", "web")], data["stores"])
        self.assertEqual([{"operation": "role", "node": "writer", "group_id": "home-gid",
                           "role": "admin", "label": "late roster on owner",
                           "outcome": "accepted"}], data["polls"])
        self.assertTrue(data["assertions"])
        self.assertTrue(all(row["passed"] for row in data["assertions"]))


if __name__ == "__main__": unittest.main()
