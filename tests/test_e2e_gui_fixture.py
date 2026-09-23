#!/usr/bin/env python3
"""Offline controls for the dedicated GUI acceptance fixture driver.

No SSH, daemon, tunnel, browser, or network action runs here: every remote,
custody, tunnel, and API participant is replaced, and the ready/done
handshake is exercised with an injected clock.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock


def load():
    tests = Path(__file__).parent
    sys.path.insert(0, str(tests))
    spec = importlib.util.spec_from_file_location("e2e_gui_fixture", tests / "e2e_gui_fixture.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module); return module


RUN = "a" * 32
NETWORK = f"x0x.home.e2e.{RUN}"
MANIFEST_SHA = "e" * 64


def complete_result(**overrides):
    payload = {"run_id": RUN, "network_id": NETWORK, "manifest_sha256": MANIFEST_SHA,
               "scenarios": [{"name": name, "status": "pass"}
                             for name in load().REQUIRED_SCENARIOS]}
    for key, value in overrides.items():
        if key == "drop":
            payload["scenarios"] = [row for row in payload["scenarios"]
                                    if row["name"] not in value]
        elif key == "fail":
            payload["scenarios"] = [{"name": row["name"],
                                     "status": "fail" if row["name"] in value else row["status"]}
                                    for row in payload["scenarios"]]
        else:
            payload[key] = value
    return payload


class Clock:
    def __init__(self): self.t, self.sleeps = 0.0, 0

    def now(self): return self.t

    def sleep(self, seconds): self.sleeps += 1; self.t += max(seconds, 0.0)


class ValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.h = load()

    def validate(self, payload):
        return self.h.validate_browser_result(payload, RUN, NETWORK, MANIFEST_SHA)

    def test_complete_passing_result_is_the_only_pass_state(self):
        self.assertEqual(("pass", "every required browser scenario succeeded"),
                         self.validate(complete_result()))

    def test_stale_run_binding_fails_even_when_all_scenarios_pass(self):
        state, reason = self.validate(complete_result(run_id="b" * 32))
        self.assertEqual(state, "fail"); self.assertIn("stale", reason)

    def test_incomplete_identity_waits_because_operator_may_still_be_writing(self):
        for payload in ({**complete_result(), "network_id": None},
                        {**complete_result(), "manifest_sha256": None}):
            self.assertEqual("wait", self.validate(payload)[0])

    def test_wrong_network_or_manifest_is_terminal(self):
        for payload in (complete_result(network_id="x0x.home.e2e." + "c" * 32),
                        complete_result(manifest_sha256="f" * 64)):
            self.assertEqual("fail", self.validate(payload)[0])

    def test_partial_result_waits_and_never_passes(self):
        state, reason = self.validate(complete_result(drop=("home-wiki-save",)))
        self.assertEqual("wait", state); self.assertIn("missing", reason)

    def test_explicit_browser_failure_is_terminal(self):
        state, reason = self.validate(complete_result(fail=("legacy-web-reader-refusal",)))
        self.assertEqual("fail", state); self.assertIn("legacy-web-reader-refusal", reason)

    def test_unknown_scenario_is_rejected(self):
        state, reason = self.validate(complete_result(
            scenarios=complete_result()["scenarios"] + [{"name": "ambient-mdns", "status": "pass"}]))
        self.assertEqual("fail", state); self.assertIn("unknown", reason)

    def test_conflicting_duplicate_scenario_is_rejected(self):
        state, _ = self.validate(complete_result(
            scenarios=complete_result()["scenarios"] + [{"name": "home-wiki-read", "status": "fail"}]))
        self.assertEqual("fail", state)

    def test_malformed_payloads_wait_rather_than_crash(self):
        for payload in (None, [], "x", {}, {"run_id": RUN, "network_id": NETWORK},
                        {"run_id": RUN, "network_id": NETWORK, "scenarios": []},
                        {"run_id": RUN, "network_id": NETWORK, "scenarios": "yes"},
                        {"run_id": RUN, "network_id": NETWORK, "scenarios": [{}]},
                        {"run_id": RUN, "network_id": NETWORK, "scenarios": [{"name": 1, "status": "pass"}]}):
            self.assertEqual("wait", self.validate(payload)[0], payload)


class BarrierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.h = load()

    def wait(self, path, deadline=3.0, clock=None, sleep=None):
        clock = clock or Clock()
        return self.h.wait_for_browser_result(path, RUN, NETWORK, MANIFEST_SHA, deadline,
                                              now=clock.now, sleep=sleep or clock.sleep), clock

    def write(self, root, payload):
        path = Path(root) / "browser-result.json"
        path.write_text(json.dumps(payload) if not isinstance(payload, str) else payload,
                        encoding="utf-8")
        return str(path)

    def test_absent_result_times_out_as_failure(self):
        with tempfile.TemporaryDirectory() as root:
            outcome, clock = self.wait(str(Path(root) / "browser-result.json"))
            self.assertEqual("fail", outcome["status"]); self.assertIn("absent", outcome["reason"])
            self.assertIsNone(outcome["result"]); self.assertGreaterEqual(clock.sleeps, 3)

    def test_partial_result_at_deadline_fails(self):
        with tempfile.TemporaryDirectory() as root:
            outcome, _ = self.wait(self.write(root, complete_result(drop=("home-web-save",))))
            self.assertEqual("fail", outcome["status"]); self.assertIn("partial", outcome["reason"])

    def test_stale_result_fails_immediately_without_burning_the_deadline(self):
        with tempfile.TemporaryDirectory() as root:
            outcome, clock = self.wait(self.write(root, complete_result(run_id="d" * 32)))
            self.assertEqual("fail", outcome["status"]); self.assertIn("stale", outcome["reason"])
            self.assertEqual(0, clock.sleeps)

    def test_explicit_failure_is_terminal_before_the_deadline(self):
        with tempfile.TemporaryDirectory() as root:
            outcome, clock = self.wait(self.write(root, complete_result(fail=("home-wiki-read",))))
            self.assertEqual("fail", outcome["status"]); self.assertEqual(0, clock.sleeps)

    def test_valid_result_first_observed_after_deadline_fails(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.write(root, complete_result())
            clock = iter((0.0, 4.0))
            outcome = self.h.wait_for_browser_result(
                path, RUN, NETWORK, MANIFEST_SHA, 3.0, now=lambda: next(clock))
            self.assertEqual("fail", outcome["status"])
            self.assertIn("deadline pass", outcome["reason"])
            self.assertIsNone(outcome["result"])

    def test_transient_invalid_write_then_valid_result_passes(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.write(root, "{half-written json")
            clock = Clock()

            def sleep(seconds):
                clock.sleep(seconds)
                if clock.sleeps == 1:
                    Path(path).write_text(json.dumps(complete_result()), encoding="utf-8")

            outcome, _ = self.wait(path, sleep=sleep)
            self.assertEqual("pass", outcome["status"]); self.assertEqual(1, clock.sleeps)
            self.assertEqual(outcome["result"]["run_id"], RUN)

    def test_result_summary_is_redacted_to_identity_and_statuses(self):
        payload = complete_result(); payload["operator_notes"] = "session abc"
        summary = self.h.redact_result(payload, RUN, NETWORK, MANIFEST_SHA)
        self.assertEqual({"run_id", "network_id", "manifest_sha256", "scenarios"}, set(summary))
        self.assertNotIn("operator_notes", json.dumps(summary))

    def test_invalid_scenario_fields_and_stale_identity_are_not_retained(self):
        payload = complete_result(run_id="sensitive-value", network_id="sensitive-value",
                                  manifest_sha256="sensitive-value")
        payload["scenarios"].append({"name": "sensitive-value", "status": "sensitive-value"})
        summary = self.h.redact_result(payload, RUN, NETWORK, MANIFEST_SHA)
        self.assertNotIn("sensitive-value", json.dumps(summary))


class AtomicWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.h = load()

    def test_replaces_existing_file_and_leaves_no_temporary(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "ready.json"
            path.write_text('{"old": true}', encoding="utf-8")
            self.h.write_json_atomic(str(path), {"run_id": RUN})
            self.assertEqual({"run_id": RUN}, json.loads(path.read_text(encoding="utf-8")))
            self.assertEqual([], list(Path(root).glob("*.tmp")))


HOME_GID, PRIV_GID, LEG_GID = "h" * 24, "p" * 24, "l" * 24
OWNER_ID = "f" * 64


class World:
    """Stateful stand-in for three synthetic daemons' API surface."""

    def __init__(self, labels):
        self.aids = {label: (str(index + 1) * 64)[:64] for index, label in enumerate(labels)}
        self.members = {HOME_GID: {labels[0]}}
        self.public_announce: set[str] = set()
        self.stores: dict[tuple[str, str], str] = {}
        self.bound_stores: set[tuple[str, str]] = set()
        self.skip_legacy_observer_bind = False
        self.wrong_legacy_observer_id = False
        self.certified = []
        self.import_attempts: list[tuple[str, str, str]] = []

    def roster(self, gid):
        return {"members": [{"agent_id": self.aids[label]} for label in self.members[gid]]}

    def candidate(self, gid, app, label):
        member = label in self.members.get(gid, set())
        writer = member and (gid not in self.public_announce or label == "owner")
        return {"target_group_id": gid, "source_store_id": f"src-{label}-{app}",
                "source_digest": f"digest-{label}-{app}",
                "keys": [f"{'legacy' if label == 'owner' else 'reader'}-imported",
                         f"{'legacy' if label == 'owner' else 'reader'}-overlap"],
                "conflicts": ["legacy-overlap"], "can_import": writer,
                "ambiguous_group_prefix": False,
                "import_refusal_reason": None if writer
                else "your current group role cannot endorse legacy history"}

    def route(self, label, method, path, body):
        if path == "/home" and method == "GET":
            return 200, {"state": "local", "group_id": HOME_GID, "owner_user_id": OWNER_ID,
                         "primary_agent": {"verified": True}}
        if path == "/agent" and method == "GET":
            return 200, {"agent_id": self.aids[label]}
        if path == "/agent/card" and method == "GET":
            return 200, {"ok": True, "card": {"agent_public_key": "a" * 3904,
                                                "signature": "b" * 6618}}
        if path == "/agent/user-id" and method == "GET":
            return 200, {"user_id": OWNER_ID}
        if path == "/health" and method == "GET":
            return 200, {"ok": True}
        if path == "/announce" and method == "POST":
            return 200, {"ok": True}
        if path == "/owner/agents/issue" and method == "POST":
            self.certified.append(body.get("label"))
            return 200, {"certificate": {"storage_b64": "Y2VydA=="}}
        if path == "/home/seat" and method == "POST":
            return 200, {"ok": True, "group_id": HOME_GID, "owner_user_id": OWNER_ID,
                         "intended_joiner": body.get("agent_id"), "seated": False,
                         "invite": f"x0x://invite/{HOME_GID}"}
        if path == "/groups" and method == "POST":
            gid = PRIV_GID if body.get("preset") == "private_secure" else LEG_GID
            self.members[gid] = {label}
            if body.get("preset") == "public_announce":
                self.public_announce.add(gid)
            return 200, {"ok": True, "group_id": gid}
        if path == "/groups/join" and method == "POST":
            gid = body.get("invite", "").removeprefix("x0x://invite/")
            self.members[gid].add(label)
            return 200, {"ok": True, "group_id": gid}
        match = re.fullmatch(r"/groups/([^/]+)", path)
        if match and method == "GET":
            return 200, {"ok": True, "group_id": match.group(1),
                         "membership_state": "active"}
        match = re.fullmatch(r"/groups/([^/]+)/invite", path)
        if match and method == "POST":
            return 200, {"invite_link": f"x0x://invite/{match.group(1)}"}
        match = re.fullmatch(r"/groups/([^/]+)/members", path)
        if match and method == "GET":
            return 200, self.roster(match.group(1))
        match = re.fullmatch(r"/groups/([^/]+)/stores/([^/]+)/legacy-imports/([^/]+)", path)
        if match and method == "POST":
            gid, app, source_id = match.groups()
            self.import_attempts.append((label, app, source_id))
            candidate = self.candidate(gid, app, label)
            if (source_id != candidate["source_store_id"]
                    or body.get("source_digest") != candidate["source_digest"]):
                return 409, {"ok": False}
            return (200 if candidate["can_import"] else 403), {"ok": False}
        match = re.fullmatch(r"/groups/([^/]+)/stores", path)
        if match and method == "POST":
            gid = match.group(1)
            sid = f"{gid}:{body.get('name')}"
            if not (gid == LEG_GID and label == "writer"
                    and self.skip_legacy_observer_bind):
                self.bound_stores.add((label, sid))
            returned_id = "wrong-store" if (gid == LEG_GID and label == "writer"
                                            and self.wrong_legacy_observer_id) else sid
            return 200, {"ok": True, "id": returned_id}
        match = re.fullmatch(r"/groups/([^/]+)/stores/([^/]+)/legacy-imports", path)
        if match and method == "GET":
            return 200, {"ok": True, "candidates": [self.candidate(match.group(1),
                                                                   match.group(2), label)]}
        if path == "/stores" and method == "POST":
            sid = f"src-{label}-{body.get('name')}"
            self.bound_stores.add((label, sid))
            return 200, {"ok": True, "id": sid}
        match = re.fullmatch(r"/stores/([^/]+)/([^/]+)", path)
        if match:
            sid, key = (urllib.parse.unquote(value) for value in match.groups())
            if (label, sid) not in self.bound_stores:
                return 404, {"error": "store not opened on this node"}
            if method == "PUT":
                self.stores[(sid, key)] = base64.b64decode(body["value"]).decode()
                return 200, {"ok": True}
            if method == "GET":
                if (sid, key) not in self.stores:
                    return 404, {"error": "not found"}
                return 200, {"value": base64.b64encode(
                    self.stores[(sid, key)].encode()).decode()}
            if method == "DELETE":
                self.stores.pop((sid, key), None)
                return 200, {"ok": True}
        raise AssertionError(f"unexpected API call {label} {method} {path}")


class FakeClient:
    def __init__(self, label, world):
        self.label, self.world = label, world

    def agent_id(self):
        if self.label in Custody.instance.stopped:
            raise AssertionError("stopped daemon queried")
        return self.world.aids[self.label]

    def request(self, method, path, body=None):
        if self.label in Custody.instance.stopped:
            raise AssertionError("stopped daemon queried")
        return self.world.route(self.label, method, path, body)


class Custody:
    instance = None

    def __init__(self, _remote, _binary, _marker):
        self.stopped, self.certs, self.keys = set(), [], {}
        Custody.instance = self

    def prepare(self, _node, _config): pass

    def create_owner_key(self, node, _cli): self.keys[node.label] = "owner-key"

    def key_fingerprint(self, node): return self.keys.get(node.label)

    def copy_owner_key(self, source, target):
        if target.label not in self.stopped:
            raise AssertionError("key copy requires stopped target")
        self.keys[target.label] = self.keys[source.label]
        return self.keys[target.label]

    def start(self, node): self.stopped.discard(node.label)

    def stop(self, label): self.stopped.add(label)

    def write_certificate(self, node, cert): self.certs.append((node.label, cert))

    def token(self, node): return f"synthetic-token-{node.label}"

    def hashes(self, _node): return ("1" * 64, "2" * 64)

    def restore(self): return []


class RunFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.h = load()

    def args(self, evidence_dir):
        return argparse.Namespace(
            hosts_file="hosts", nodes=["owner", "writer", "reader"],
            daemon_binary="/opt/x0x/x0xd", cli_binary="/opt/x0x/x0x",
            api_port_base=15600, quic_port_base=8483, local_port_base=25700,
            poll_timeout=20, evidence_dir=evidence_dir, browser_deadline_secs=900)

    def test_reader_source_swap_is_rejected_by_the_api_model(self):
        world = World(["owner", "writer", "reader"])
        world.members[LEG_GID] = {"owner", "reader"}
        world.public_announce.add(LEG_GID)
        status, _ = world.route("reader", "POST",
                                f"/groups/{LEG_GID}/stores/wiki/legacy-imports/src-owner-wiki",
                                {"source_digest": "digest-owner-wiki"})
        self.assertEqual(409, status)
        status, _ = world.route("reader", "POST",
                                f"/groups/{LEG_GID}/stores/wiki/legacy-imports/src-reader-wiki",
                                {"source_digest": "digest-reader-wiki"})
        self.assertEqual(403, status)

    def test_positive_path_prepares_binds_and_accepts(self):
        h = self.h
        with tempfile.TemporaryDirectory() as evidence:
            args, world = self.args(evidence), World(["owner", "writer", "reader"])
            tokens = {n: (f"192.0.2.{i}", "unused") for i, n in enumerate(args.nodes, 1)}
            clients = {n: FakeClient(n, world) for n in args.nodes}
            tunnels = [mock.Mock(local_port=25700 + i) for i in range(3)]
            browser = mock.Mock(
                return_value={"status": "pass", "reason": "every required browser scenario succeeded",
                              "result": None})
            evidence_rec, resources = h.Evidence(), {}
            with mock.patch.object(h, "load_tokens", return_value=tokens), \
                 mock.patch.object(h, "SyntheticProcessCustody", Custody), \
                 mock.patch.object(h, "start_ssh_tunnel", side_effect=tunnels), \
                 mock.patch.object(h, "Api", side_effect=[clients[n] for n in args.nodes]), \
                 mock.patch.object(h, "wait_for_browser_result", browser), \
                 mock.patch.object(h.uuid, "uuid4", return_value=mock.Mock(hex=RUN)):
                self.assertTrue(h.run_fixture(args, h.Remote(), evidence_rec, resources))
            ready = json.loads(Path(evidence, "ready.json").read_text(encoding="utf-8"))
            browser.assert_called_once_with(f"{evidence}/browser-result.json", RUN, NETWORK,
                                            ready["manifest_sha256"], 900)
            self.assertEqual([("writer", "Y2VydA==")], Custody.instance.certs)
            self.assertEqual("owner-key", Custody.instance.keys["writer"])
            self.assertIn("reader", world.members[LEG_GID])
            self.assertIn(("writer", f"{LEG_GID}:wiki"), world.bound_stores)
            self.assertIn(("writer", f"{LEG_GID}:web"), world.bound_stores)
            manifest = json.loads(Path(evidence, "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(RUN, manifest["run_id"]); self.assertEqual(NETWORK, manifest["network_id"])
            self.assertEqual(hashlib.sha256(Path(evidence, "manifest.json").read_bytes()).hexdigest(),
                             ready["manifest_sha256"])
            self.assertEqual({"wiki": f"{HOME_GID}:wiki", "web": f"{HOME_GID}:web"},
                             manifest["spaces"]["home"]["stores"])
            page = manifest["spaces"]["private"]["pages"][0]
            self.assertEqual(hashlib.sha256(
                f"gui-private-{page['app']}-page-{RUN[:12]}".encode()).hexdigest(),
                page["value_sha256"])
            legacy = manifest["legacy"]["apps"]["web"]
            self.assertEqual("src-owner-web", legacy["writer_source_store_id"])
            self.assertEqual("digest-owner-web", legacy["writer_source_digest"])
            self.assertEqual(["legacy-overlap"], legacy["writer_conflicts"])
            self.assertEqual("src-reader-web", legacy["reader_source_store_id"])
            self.assertEqual("digest-reader-web", legacy["reader_source_digest"])
            self.assertEqual([("reader", "wiki", "src-reader-wiki"),
                              ("reader", "web", "src-reader-web")], world.import_attempts)
            self.assertNotIn((LEG_GID + ":web", "reader-imported"), world.stores)
            self.assertEqual("owner", manifest["legacy"]["writer"]["label"])
            self.assertEqual("reader", manifest["legacy"]["reader"]["label"])
            self.assertEqual(list(h.REQUIRED_SCENARIOS), ready["required_scenarios"])
            self.assertEqual(900, ready["browser_deadline_secs"])
            self.assertEqual({"owner": 25700, "writer": 25701, "reader": 25702}, ready["tunnels"])
            for name in ("manifest.json", "ready.json"):
                self.assertNotIn("synthetic-token",
                                 Path(evidence, name).read_text(encoding="utf-8"))
            self.assertTrue(all(row["passed"] for row in evidence_rec.assertions))

    def test_missing_or_wrong_observer_destination_fails_before_browser(self):
        h = self.h
        for defect in ("skip_legacy_observer_bind", "wrong_legacy_observer_id"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as evidence:
                args, world = self.args(evidence), World(["owner", "writer", "reader"])
                args.poll_timeout = 0.05
                setattr(world, defect, True)
                tokens = {n: (f"192.0.2.{i}", "unused") for i, n in enumerate(args.nodes, 1)}
                clients = {n: FakeClient(n, world) for n in args.nodes}
                tunnels = [mock.Mock(local_port=25700 + i) for i in range(3)]
                with mock.patch.object(h, "load_tokens", return_value=tokens), \
                     mock.patch.object(h, "SyntheticProcessCustody", Custody), \
                     mock.patch.object(h, "start_ssh_tunnel", side_effect=tunnels), \
                     mock.patch.object(h, "Api", side_effect=[clients[n] for n in args.nodes]), \
                     mock.patch.object(h, "wait_for_browser_result") as browser, \
                     mock.patch.object(h.uuid, "uuid4", return_value=mock.Mock(hex=RUN)):
                    with self.assertRaises(AssertionError):
                        h.run_fixture(args, h.Remote(), h.Evidence(), {})
                browser.assert_not_called()

    def test_existing_result_is_rejected_before_process_custody(self):
        h = self.h
        with tempfile.TemporaryDirectory() as evidence:
            Path(evidence, "browser-result.json").write_text("{}", encoding="utf-8")
            args = self.args(evidence)
            tokens = {n: (f"192.0.2.{i}", "unused") for i, n in enumerate(args.nodes, 1)}
            with mock.patch.object(h, "load_tokens", return_value=tokens), \
                 mock.patch.object(h, "SyntheticProcessCustody", Custody), \
                 mock.patch.object(h, "start_ssh_tunnel") as start:
                with self.assertRaisesRegex(RuntimeError, "prior run"):
                    h.run_fixture(args, h.Remote(), h.Evidence(), {})
            start.assert_not_called()

    def test_browser_failure_fails_the_fixture(self):
        h = self.h
        with tempfile.TemporaryDirectory() as evidence:
            args, world = self.args(evidence), World(["owner", "writer", "reader"])
            tokens = {n: (f"192.0.2.{i}", "unused") for i, n in enumerate(args.nodes, 1)}
            clients = {n: FakeClient(n, world) for n in args.nodes}
            tunnels = [mock.Mock(local_port=25700 + i) for i in range(3)]
            browser = mock.Mock(return_value={"status": "fail",
                                              "reason": "explicit browser failure: ['home-wiki-save']",
                                              "result": None})
            with mock.patch.object(h, "load_tokens", return_value=tokens), \
                 mock.patch.object(h, "SyntheticProcessCustody", Custody), \
                 mock.patch.object(h, "start_ssh_tunnel", side_effect=tunnels), \
                 mock.patch.object(h, "Api", side_effect=[clients[n] for n in args.nodes]), \
                 mock.patch.object(h, "wait_for_browser_result", browser), \
                 mock.patch.object(h.uuid, "uuid4", return_value=mock.Mock(hex=RUN)):
                with self.assertRaises(AssertionError):
                    h.run_fixture(args, h.Remote(), h.Evidence(), {})


class MainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.h = load()

    def argv(self, evidence):
        return ["gui-fixture", "--network", "synthetic-home", "--hosts-file", "hosts",
                "--nodes", "owner", "writer", "reader", "--daemon-binary", "/x0xd",
                "--cli-binary", "/x0x", "--evidence-dir", evidence,
                "--browser-deadline-secs", "5"]

    def test_nonfinite_browser_deadlines_are_rejected_before_setup(self):
        h = self.h
        with tempfile.TemporaryDirectory() as evidence:
            for value in ("nan", "inf", "-inf"):
                with self.subTest(value=value), \
                     mock.patch.object(sys, "argv", self.argv(evidence)[:-1] + [value]), \
                     mock.patch.object(h, "run_fixture") as run, \
                     contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        h.main()
                    run.assert_not_called()

    def test_prior_report_remains_byte_identical_and_no_setup_runs(self):
        h = self.h
        with tempfile.TemporaryDirectory() as evidence:
            prior = b"prior authoritative report: keep exactly these bytes\n"
            report = Path(evidence, "report.json")
            report.write_bytes(prior)
            with mock.patch.object(sys, "argv", self.argv(evidence)), \
                 mock.patch.object(h, "load_tokens") as tokens, \
                 mock.patch.object(h, "SyntheticProcessCustody") as custody, \
                 mock.patch.object(h, "start_ssh_tunnel") as tunnel:
                self.assertEqual(1, h.main())
            self.assertEqual(prior, report.read_bytes())
            tokens.assert_not_called()
            custody.assert_not_called()
            tunnel.assert_not_called()

    def test_provisioning_failure_still_cleans_every_resource_and_reports(self):
        h = self.h
        custody = mock.Mock(); custody.restore.return_value = []
        tunnels = [mock.Mock(), mock.Mock()]
        stops = [RuntimeError("first tunnel"), None]

        def stop_tunnel(_tunnel):
            failure = stops.pop(0)
            if failure is not None:
                raise failure

        def fail(_args, _remote, _evidence, resources):
            resources["custody"], resources["tunnels"] = custody, tunnels
            raise RuntimeError("partial provision")

        with tempfile.TemporaryDirectory() as evidence:
            with mock.patch.object(sys, "argv", self.argv(evidence)), \
                 mock.patch.object(h, "run_fixture", side_effect=fail), \
                 mock.patch.object(h, "stop_ssh_tunnel", side_effect=stop_tunnel) as stop:
                self.assertEqual(1, h.main())
            custody.restore.assert_called_once_with()
            self.assertEqual(2, stop.call_count)
            report = json.loads(Path(evidence, "report.json").read_text(encoding="utf-8"))
            self.assertEqual(1, report["cleanup"]["tunnel_errors"])
            self.assertFalse(all(row["passed"] for row in report["assertions"]))
            self.assertIn("RuntimeError", " ".join(row["label"] for row in report["assertions"]))

    def test_cleanup_failure_is_exposed_and_fails_the_run(self):
        h = self.h
        custody = mock.Mock()
        custody.restore.return_value = ["cleanup reader: RuntimeError"]

        def succeed(_args, _remote, _evidence, resources):
            resources["custody"], resources["tunnels"] = custody, []
            resources["browser"] = {"status": "pass", "reason": "every required browser scenario succeeded"}
            resources["manifest"] = {"run_id": RUN}
            return True

        with tempfile.TemporaryDirectory() as evidence:
            with mock.patch.object(sys, "argv", self.argv(evidence)), \
                 mock.patch.object(h, "run_fixture", side_effect=succeed):
                self.assertEqual(1, h.main())
            report = json.loads(Path(evidence, "report.json").read_text(encoding="utf-8"))
            self.assertEqual(["cleanup reader: RuntimeError"], report["cleanup"]["custody_errors"])
            self.assertEqual("pass", report["browser"]["status"])

    def test_successful_run_exits_zero_with_report(self):
        h = self.h

        def succeed(_args, _remote, _evidence, resources):
            resources["custody"] = mock.Mock(); resources["custody"].restore.return_value = []
            resources["tunnels"] = []
            resources["browser"] = {"status": "pass", "reason": "ok"}
            resources["manifest"] = {"run_id": RUN}
            return True

        with tempfile.TemporaryDirectory() as evidence:
            with mock.patch.object(sys, "argv", self.argv(evidence)), \
                 mock.patch.object(h, "run_fixture", side_effect=succeed):
                self.assertEqual(0, h.main())
            report = json.loads(Path(evidence, "report.json").read_text(encoding="utf-8"))
            self.assertEqual(RUN, report["custody"]["run_id"])
            self.assertEqual("pass", report["browser"]["status"])


if __name__ == "__main__": unittest.main()
