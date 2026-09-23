#!/usr/bin/env python3
"""Offline controls for the isolated synthetic Home fixture."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import re
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

    def run_join_offline(self, evidence, responses, *, join_state="pending_authority_commit",
                         local_responses=None, local_join_status=(200, {}), request_advance=0.0,
                         owner_error_at=(), local_error_at=(), terminal_error=None):
        """Drive the real Home readiness barrier against fake APIs and a virtual clock."""
        owner, member = mock.Mock(), mock.Mock()
        local_responses = local_responses or [(200, {"ok": True, "group_id": "home-gid",
                                                       "membership_state": "active"})]
        member.agent_id.return_value = "a" * 64
        samples = []
        local_samples = []
        clock = types.SimpleNamespace(now=1000.0)
        def owner_roster(method, path):
            self.assertEqual(("GET", "/groups/home-gid/members"), (method, path))
            index = len(samples)
            samples.append(None)
            clock.now += request_advance
            if index in owner_error_at:
                raise RuntimeError("synthetic owner request failure")
            response = responses[min(index, len(responses) - 1)]
            samples[-1] = response
            return response
        def member_api(method, path, body=None):
            if method == "POST":
                return (200, {"ok": True, "group_id": "home-gid", "join_state": join_state})
            if path == "/groups/home-gid":
                index = len(local_samples)
                local_samples.append(None)
                clock.now += request_advance
                if index in local_error_at:
                    raise RuntimeError("synthetic local request failure")
                response = local_responses[min(index, len(local_responses) - 1)]
                local_samples[-1] = response
                return response
            if path == "/groups/home-gid/join-status":
                if terminal_error is not None:
                    raise RuntimeError(terminal_error)
                return local_join_status
            raise AssertionError((method, path))
        owner.request.side_effect = owner_roster
        member.request.side_effect = member_api
        def sleep(seconds): clock.now += seconds
        poll_time = self.h.Scenario.join_home.__globals__["poll"].__globals__["time"]
        with mock.patch.object(poll_time, "monotonic", side_effect=lambda: clock.now), \
             mock.patch.object(poll_time, "sleep", side_effect=sleep):
            self.h.Scenario({"owner": owner, "member": member}, evidence, 120).join_home(
                "owner", "member", "home-gid", "b" * 64, "x0x://invite/secret-synthetic")
        return samples

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

    def run_model(self, fixture=None, scenario_cls=None, card_reply=None):
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
        public_keys = {n: f"{i:02x}" * 1952 for i, n in enumerate(args.nodes, 1)}
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
                if path == "/agent/card":
                    if card_reply is not None: return 200, card_reply
                    return 200, {"ok": True, "card": {"agent_id": ids[me],
                                                      "agent_public_key": public_keys[me],
                                                      "signature": "ab" * 3309}, "link": "x0x://agent"}
                if path == "/agent/user-id": return 200, {"ok": True, "user_id": owner_user if keyed else None}
                if path == "/owner/agents/issue":
                    target = body["label"].removeprefix("home-e2e-")
                    if me != "owner" or body["mode"] != "acp" or body["agent_public_key"] != public_keys[target]:
                        return 400, {"ok": False}
                    return 200, {"certificate": {"storage_b64": "Y2VydA=="}}
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
                if path == f"/groups/{gid}":
                    return 200, {"ok": True, "group_id": gid,
                                 "membership_state": "active" if me in seats else "pending_authority_commit"}
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

    def test_card_envelope_rejects_missing_or_malformed_signed_fields_before_issuance(self):
        key, signature = "02" * 1952, "ab" * 3309
        invalid = {
            "top-level fields only": {"ok": True, "agent_public_key": key, "signature": signature},
            "wrong nested shape": {"ok": True, "card": [key, signature]},
            "missing public key": {"ok": True, "card": {"signature": signature}},
            "unsigned": {"ok": True, "card": {"agent_public_key": key}},
            "malformed public key": {"ok": True, "card": {"agent_public_key": "zz" * 1952,
                                                        "signature": signature}},
            "malformed signature": {"ok": True, "card": {"agent_public_key": key,
                                                       "signature": "ab" * 3308}},
        }
        for name, reply in invalid.items():
            with self.subTest(card=name):
                events, _custody, _world, evidence, error = self.run_model(card_reply=reply)
                self.assertIsInstance(error, AssertionError)
                self.assertFalse(next(row["passed"] for row in evidence.assertions
                                      if row["label"] == "writer signed card exposes public key"))
                self.assertNotIn(("req", "owner", "POST", "/owner/agents/issue"), events)

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

    def test_witness_parser_accepts_exact_line_and_rejects_malformed(self):
        """Locks the receipt grammar; any drift in the logged line must fail parsing."""
        digest = "ab" * 32
        good = (f"x0x_control_blob_witness stage={self.h.WITNESS_STAGE} kind=member_added "
                f"byte_len=60000 digest={digest}")
        self.assertEqual({"stage": self.h.WITNESS_STAGE, "kind": "member_added",
                          "byte_len": 60000, "digest": digest},
                         self.h.parse_witness_line(good))
        for bad in (good + " ", good.replace(digest, digest[:63]),
                    good.replace("byte_len=60000", "byte_len="),
                    good.replace("x0x_control_blob_witness", "x0x_control_blob_witness2")):
            with self.subTest(line=bad):
                with self.assertRaises(RuntimeError): self.h.parse_witness_line(bad)

    def test_witness_oracle_credits_only_right_stage_and_oversized_kinds(self):
        """Wrong stage, at-limit size, missing or substitute kind must fail an acceptance row."""
        def witness(kind, byte_len, stage=None):
            return {"stage": stage or self.h.WITNESS_STAGE, "kind": kind, "byte_len": byte_len,
                    "digest": "ab" * 32, "node": "writer"}
        for name, receipts, passed in (
            ("both kinds oversized", [witness("member_added", 49_153), witness("join_result", 60_000)], [True, True]),
            ("member_added missing", [witness("join_result", 60_000)], [False, True]),
            ("wrong stage", [witness("member_added", 60_000, stage="handler_applied"),
                             witness("join_result", 60_000)], [False, True]),
            ("byte_len at the DM limit", [witness("member_added", 49_152), witness("join_result", 60_000)], [False, True]),
            ("named_group_event substitute", [witness("named_group_event", 60_000),
                                              witness("join_result", 60_000)], [False, True]),
        ):
            with self.subTest(case=name):
                rows = self.h.witness_assertions(receipts)
                self.assertEqual(["oversized member_added reassembled and validated for handler",
                                  "oversized join_result reassembled and validated for handler"],
                                 [row["label"] for row in rows])
                self.assertEqual(passed, [row["passed"] for row in rows])

    def test_custody_collects_bounded_strictly_parsed_node_tagged_witnesses(self):
        """Oversized, overlong or unparsable witness output must fail collection, not pass."""
        remote = mock.Mock()
        custody = self.h.SyntheticProcessCustody(remote, "/opt/x0x/x0xd", "m" * 32)
        custody.started["writer"] = self.node("writer")
        line = (f"x0x_control_blob_witness stage={self.h.WITNESS_STAGE} kind=member_added "
                f"byte_len=60000 digest={'ab' * 32}\n").encode()
        remote.run.return_value = line
        self.assertEqual([{"stage": self.h.WITNESS_STAGE, "kind": "member_added",
                           "byte_len": 60000, "digest": "ab" * 32, "node": "writer"}],
                         custody.control_blob_witnesses())
        self.assertTrue(remote.run.call_args.kwargs["capture"])
        remote.run.return_value = line + b"x0x_control_blob_witness garbage\n"
        with self.assertRaises(RuntimeError): custody.control_blob_witnesses()
        remote.run.return_value = line * (self.h.WITNESS_LINES_PER_NODE + 1)
        with self.assertRaises(RuntimeError): custody.control_blob_witnesses()
        remote.run.return_value = b"x" * (self.h.WITNESS_BYTES_PER_NODE + 1)
        with self.assertRaises(RuntimeError): custody.control_blob_witnesses()

    def test_witness_script_emits_one_line_past_the_bound_so_overflow_fails_closed(self):
        """Real overflow must fail closed: the remote head passes exactly N+1
        lines through, N+1 raises in collection, and the at-bound output still
        collects."""
        def script_output(log_lines):
            with tempfile.TemporaryDirectory(prefix="home-witness-bound-") as root:
                Path(f"{root}/fixture.marker").write_text("marker\n")
                logs = Path(root) / "logs"; logs.mkdir()
                line = (f"x0x_control_blob_witness stage={self.h.WITNESS_STAGE} "
                        f"kind=member_added byte_len=60000 digest={'ab' * 32}")
                (logs / "daemon.log").write_text("\n".join([line] * log_lines) + "\n")
                command = self.h.Remote.command(self.h.WITNESS_SCRIPT, [root, "marker"],
                                                input_bytes=False)
                return subprocess.run(command, shell=True,
                                      input=self.h.WITNESS_SCRIPT.encode(),
                                      capture_output=True, timeout=5, check=True).stdout
        emitted = script_output(self.h.WITNESS_LINES_PER_NODE + 2)
        self.assertEqual(self.h.WITNESS_LINES_PER_NODE + 1, len(emitted.splitlines()))
        remote = mock.Mock(); remote.run.side_effect = lambda *_args, **_kwargs: emitted
        custody = self.h.SyntheticProcessCustody(remote, "/opt/x0x/x0xd", "m" * 32)
        custody.started["writer"] = self.node("writer")
        with self.assertRaisesRegex(RuntimeError, "lines exceed the bound"):
            custody.control_blob_witnesses()
        remote.run.side_effect = lambda *_args, **_kwargs: script_output(
            self.h.WITNESS_LINES_PER_NODE)
        self.assertEqual(self.h.WITNESS_LINES_PER_NODE,
                         len(custody.control_blob_witnesses()))

    def test_rust_witness_line_format_still_matches_the_fixture_receipt_regex(self):
        """If the control_blob.rs format literal or stage drifts, or the dm.rs
        payload limit moves, the fixture must fail loudly."""
        rust = (Path(__file__).resolve().parent.parent /
                "src/server/routes/named_groups/control_blob.rs").read_text(encoding="utf-8")
        template = re.search(r'fn witness_line\b.*?"([^"]*x0x_control_blob_witness[^"]*)"',
                             rust, re.DOTALL)
        stage = re.search(r'const WITNESS_STAGE: &str = "([^"]+)"', rust)
        self.assertIsNotNone(template)
        self.assertIsNotNone(stage)
        values = iter(("60000", "ab" * 32))
        rendered = re.sub(r"\{\}", lambda _m: next(values),
                          template.group(1).replace("{WITNESS_STAGE}", stage.group(1))
                                           .replace("{kind}", "member_added"))
        self.assertEqual({"stage": self.h.WITNESS_STAGE, "kind": "member_added",
                          "byte_len": 60000, "digest": "ab" * 32},
                         self.h.parse_witness_line(rendered))
        dm = (Path(__file__).resolve().parent.parent /
              "src/dm.rs").read_text(encoding="utf-8")
        limit = re.search(r"pub const MAX_PAYLOAD_BYTES: usize = ([0-9_]+);", dm)
        self.assertIsNotNone(limit, "src/dm.rs MAX_PAYLOAD_BYTES anchor drifted")
        self.assertEqual(self.h.DM_MAX_PAYLOAD_BYTES, int(limit.group(1).replace("_", "")))

    def test_main_collects_witnesses_after_restore_and_fails_closed_without_them(self):
        """Exit stays 1 without both receipts; collection must follow restore so logs are flushed."""
        order: list[str] = []
        custody = mock.Mock()
        custody.restore.side_effect = lambda: (order.append("restore"), [])[1]
        custody.control_blob_witnesses.side_effect = lambda: (order.append("witnesses"), [])[1]
        def populated(_args, _remote, _evidence, resources):
            resources["custody"] = custody
            return True
        def run_main(populate):
            with tempfile.TemporaryDirectory(prefix="home-witness-") as root:
                report = Path(root) / "report.json"
                argv = ["fixture", "--network", "synthetic-home", "--hosts-file", "hosts",
                        "--nodes", "a", "b", "c", "d", "e", "--daemon-binary", "/x0xd",
                        "--cli-binary", "/x0x", "--report", str(report)]
                with mock.patch.object(sys, "argv", argv), \
                     mock.patch.object(self.h, "run_fixture", side_effect=populate):
                    code = self.h.main()
                return code, json.loads(report.read_text(encoding="utf-8"))
        with self.subTest(case="missing receipts"):
            code, data = run_main(populated)
            self.assertEqual(1, code)
            self.assertEqual(["restore", "witnesses"], order)
            self.assertEqual(["oversized member_added reassembled and validated for handler",
                              "oversized join_result reassembled and validated for handler"],
                             [row["label"] for row in data["assertions"] if not row["passed"]])
        with self.subTest(case="collection error"):
            custody.control_blob_witnesses.side_effect = RuntimeError("witness ssh failure")
            code, data = run_main(populated)
            self.assertEqual(1, code)
            self.assertEqual(["control blob witness collection RuntimeError"],
                             [row["label"] for row in data["assertions"] if not row["passed"]])
        with self.subTest(case="no custody"):
            code, data = run_main(lambda _a, _r, _e, _res: True)
            self.assertEqual(1, code)
            self.assertEqual(["control blob witness collection unavailable"],
                             [row["label"] for row in data["assertions"] if not row["passed"]])
            self.assertEqual([], data["control_blob_witnesses"])

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
        """Exit 0 needs witness receipts in the report; GUI acceptance reads them from the file."""
        # Root GUI acceptance must work from the frozen report alone: group and
        # store IDs plus page keys from evidence.stores, convergence receipts
        # from evidence.polls, custody hash receipts from the manifest, and
        # runtime control-blob witnesses collected after restore.
        manifest = {"run_id": "a" * 32, "network_id": f"x0x.home.e2e.{'a' * 32}",
                    "binary_sha256": "b" * 64, "config_sha256": {"owner": "c" * 64}}
        witnesses = [{"stage": self.h.WITNESS_STAGE, "kind": "member_added", "byte_len": 60_000,
                      "digest": "a" * 64, "node": "writer"},
                     {"stage": self.h.WITNESS_STAGE, "kind": "join_result", "byte_len": 50_000,
                      "digest": "b" * 64, "node": "late"}]
        custody = mock.Mock()
        custody.restore.return_value = []
        custody.control_blob_witnesses.return_value = witnesses
        def populate(_args, _remote, evidence, resources):
            resources["manifest"], resources["custody"] = manifest, custody
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
        self.assertEqual({"scenario", "custody", "stores", "polls", "control_blob_witnesses",
                          "assertions"}, set(data))
        self.assertEqual("synthetic-home", data["scenario"])
        self.assertEqual(manifest, data["custody"])
        self.assertEqual(witnesses, data["control_blob_witnesses"])
        self.assertEqual([{"node": "writer", "group_id": "home-gid", "app": app,
                           "topic": f"topic-{app}", "store_id": "0" * 64}
                          for app in ("wiki", "web")], data["stores"])
        self.assertEqual([{"operation": "role", "node": "writer", "group_id": "home-gid",
                           "role": "admin", "label": "late roster on owner",
                           "outcome": "accepted"}], data["polls"])
        self.assertTrue(data["assertions"])
        self.assertTrue(all(row["passed"] for row in data["assertions"]))
        self.assertEqual(["oversized member_added reassembled and validated for handler",
                          "oversized join_result reassembled and validated for handler"],
                         [row["label"] for row in data["assertions"]
                          if row["label"].startswith("oversized")])

    def test_home_join_seat_receipt_distinguishes_delayed_timeout_and_http_error(self):
        secret = "DO-NOT-RETAIN-CERT-OR-TOKEN"
        target = {"agent_id": "a" * 64, "role": "member"}
        other = {"agent_id": "c" * 64, "role": "owner"}
        delayed = self.h.Evidence()
        samples = self.run_join_offline(delayed, [
            (200, {"members": [other], "token": secret}),
            (200, {"members": [other], "certificate": secret}),
            (200, {"members": [other, target], "invite": secret})])
        self.assertEqual(3, len(samples))
        self.assertEqual("pending_authority_commit", delayed.assertions[0]["join_state"])
        self.assertTrue(delayed.assertions[0]["passed"])
        accepted = delayed.polls[0]
        self.assertEqual(("member Home seat reaches owner and local readiness", "accepted", 120, 2.0, 200, 2, True),
                         (accepted["label"], accepted["outcome"], accepted["deadline_seconds"],
                          accepted["elapsed_seconds"], accepted["last_http_status"],
                          accepted["observed_member_count"], accepted["expected_member_present"]))
        self.assertEqual("active", accepted["local_membership_state"])
        self.assertEqual(3, accepted["local_probe_count"])
        self.assertNotIn(secret, json.dumps(delayed.polls))

        for label, response, expected_status, expected_count, expected_present in (
            ("unseated", (200, {"members": [other], "certificate": secret}), 200, 1, False),
            ("http_error", (503, {"members": [target], "error": secret}), 503, None, None),
        ):
            with self.subTest(label=label):
                evidence = self.h.Evidence()
                with self.assertRaisesRegex(AssertionError, "member Home seat reaches owner and local readiness"):
                    self.run_join_offline(evidence, [response], join_state=secret)
                self.assertEqual("other", evidence.assertions[0]["join_state"])
                receipt = evidence.polls[0]
                self.assertEqual("timeout", receipt["outcome"])
                self.assertEqual(120, receipt["deadline_seconds"])
                self.assertEqual(120.0, receipt["elapsed_seconds"])
                self.assertEqual(expected_status, receipt["last_http_status"])
                self.assertEqual(expected_count, receipt["observed_member_count"])
                self.assertEqual(expected_present, receipt["expected_member_present"])
                self.assertEqual(120, receipt["probe_count"])
                self.assertNotIn(secret, json.dumps({"polls": evidence.polls,
                                                    "assertions": evidence.assertions}))

    def test_home_join_waits_for_local_active_after_owner_roster(self):
        evidence = self.h.Evidence()
        samples = self.run_join_offline(
            evidence,
            [(200, {"members": [{"agent_id": "a" * 64}]})],
            local_responses=[
                (200, {"ok": True, "group_id": "home-gid", "membership_state": "pending_authority_commit"}),
                (200, {"ok": True, "group_id": "home-gid", "membership_state": "active"}),
            ],
        )
        self.assertEqual(2, len(samples))
        receipt = evidence.polls[0]
        self.assertEqual("accepted", receipt["outcome"])
        self.assertEqual("active", receipt["local_membership_state"])
        self.assertEqual(2, receipt["local_probe_count"])
        self.assertEqual(1, receipt["observed_member_count"])

    def test_home_join_local_pending_timeout_records_terminal_status(self):
        evidence = self.h.Evidence()
        with self.assertRaisesRegex(AssertionError, "local readiness"):
            self.run_join_offline(
                evidence,
                [(200, {"members": [{"agent_id": "a" * 64}]})],
                local_responses=[(200, {"ok": True, "group_id": "home-gid",
                                        "membership_state": "pending_authority_commit"})],
                local_join_status=(404, {"error": "group_not_found",
                                         "last_join_outcome": {"outcome": "timed_out",
                                                                "reason": "synthetic"}}),
            )
        receipt = evidence.polls[0]
        self.assertEqual("timeout", receipt["outcome"])
        self.assertEqual(120, receipt["elapsed_seconds"])
        self.assertEqual(404, receipt["terminal_join_status"])
        self.assertEqual("timed_out", receipt["terminal_join_outcome"])
        self.assertEqual("pending_authority_commit", receipt["local_membership_state"])
        self.assertNotIn("synthetic", json.dumps(evidence.polls))

    def test_home_join_local_http_error_fails_without_claiming_active(self):
        evidence = self.h.Evidence()
        with self.assertRaisesRegex(AssertionError, "local readiness"):
            self.run_join_offline(
                evidence,
                [(200, {"members": [{"agent_id": "a" * 64}]})],
                local_responses=[(503, {"error": "synthetic-secret"})],
                local_join_status=(503, {"error": "join status unavailable"}),
            )
        receipt = evidence.polls[0]
        self.assertEqual("timeout", receipt["outcome"])
        self.assertEqual(503, receipt["local_last_status"])
        self.assertIsNone(receipt["local_membership_state"])
        self.assertNotIn("synthetic-secret", json.dumps(evidence.polls))

    def test_home_join_shared_deadline_does_not_double_owner_and_local_waits(self):
        evidence = self.h.Evidence()
        with self.assertRaisesRegex(AssertionError, "local readiness"):
            self.run_join_offline(
                evidence,
                [(200, {"members": [{"agent_id": "c" * 64}]})],
                local_responses=[(200, {"ok": True, "group_id": "wrong-group",
                                        "membership_state": "active"})],
            )
        receipt = evidence.polls[0]
        self.assertEqual(120, receipt["elapsed_seconds"])
        self.assertEqual(120, receipt["probe_count"])
        self.assertEqual(120, receipt["local_probe_count"])

    def test_home_join_request_and_terminal_errors_still_emit_bounded_receipt(self):
        evidence = self.h.Evidence()
        with self.assertRaisesRegex(AssertionError, "local readiness"):
            self.run_join_offline(
                evidence,
                [(200, {"members": [{"agent_id": "a" * 64}]})],
                local_responses=[(200, {"group_id": "home-gid", "membership_state": "pending_authority_commit"})],
                owner_error_at=tuple(range(200)),
                terminal_error="secret-terminal-error",
            )
        receipt = evidence.polls[0]
        self.assertEqual("timeout", receipt["outcome"])
        self.assertEqual("RuntimeError", receipt["last_error_class"])
        self.assertEqual("RuntimeError", receipt["terminal_join_status_error_class"])
        self.assertIsNone(receipt["terminal_join_status"])
        self.assertNotIn("secret-terminal-error", json.dumps(evidence.polls))

    def test_home_join_unknown_state_and_terminal_outcome_are_redacted_to_other(self):
        evidence = self.h.Evidence()
        with self.assertRaisesRegex(AssertionError, "local readiness"):
            self.run_join_offline(
                evidence,
                [(200, {"members": [{"agent_id": "a" * 64}]})],
                local_responses=[(200, {"ok": True, "group_id": "home-gid",
                                        "membership_state": ["SECRET_STATE"]})],
                local_join_status=(404, {"last_join_outcome": {"outcome": ["SECRET_OUTCOME"]}}),
            )
        receipt = evidence.polls[0]
        self.assertEqual("other", receipt["local_membership_state"])
        self.assertEqual("other", receipt["terminal_join_outcome"])
        self.assertNotIn("SECRET_STATE", json.dumps(evidence.polls))
        self.assertNotIn("SECRET_OUTCOME", json.dumps(evidence.polls))

    def test_home_join_rejects_readiness_that_crosses_shared_deadline(self):
        evidence = self.h.Evidence()
        with self.assertRaisesRegex(AssertionError, "local readiness"):
            self.run_join_offline(
                evidence,
                [(200, {"members": [{"agent_id": "a" * 64}]})],
                request_advance=61.0,
            )
        receipt = evidence.polls[0]
        self.assertEqual("timeout", receipt["outcome"])
        self.assertTrue(receipt["deadline_reached_before_acceptance"])
        self.assertEqual(1, receipt["probe_count"])
        self.assertEqual(1, receipt["local_probe_count"])
        self.assertGreaterEqual(receipt["elapsed_seconds"], 120)

    def test_failed_home_seat_poll_still_reports_and_cleans_up(self):
        custody = mock.Mock(); custody.restore.return_value = []
        tunnel = mock.Mock()
        def fail(_args, _remote, evidence, resources):
            resources["custody"] = custody
            resources["tunnels"] = [tunnel]
            resources["manifest"] = {"run_id": "a" * 32}
            self.run_join_offline(evidence, [(200, {"members": []})])
        with tempfile.TemporaryDirectory(prefix="home-seat-report-") as root:
            report = Path(root) / "report.json"
            argv = ["fixture", "--network", "synthetic-home", "--hosts-file", "hosts",
                    "--nodes", "a", "b", "c", "d", "e", "--daemon-binary", "/x0xd",
                    "--cli-binary", "/x0x", "--report", str(report)]
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(self.h, "run_fixture", side_effect=fail), \
                 mock.patch.object(self.h, "stop_ssh_tunnel") as stop:
                self.assertEqual(1, self.h.main())
            data = json.loads(report.read_text(encoding="utf-8"))
        custody.restore.assert_called_once_with()
        stop.assert_called_once_with(tunnel)
        self.assertEqual("timeout", data["polls"][0]["outcome"])
        self.assertEqual(200, data["polls"][0]["last_http_status"])
        self.assertFalse(data["polls"][0]["expected_member_present"])
        self.assertEqual("fixture AssertionError", data["assertions"][-1]["label"])
        self.assertFalse(data["assertions"][-1]["passed"])


if __name__ == "__main__": unittest.main()
