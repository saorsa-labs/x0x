#!/usr/bin/env python3
"""Inert controls for the exact #491 RT3 harness functions."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from unittest import mock


HARNESS_PATH = Path(__file__).with_name("rt3_harness.py")
WORKFLOW_PATH = HARNESS_PATH.parent.parent / ".github/workflows/build.yml"
SPEC = importlib.util.spec_from_file_location("rt3_harness", HARNESS_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load RT3 harness")
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class HarnessControls(unittest.TestCase):
    class InertProcess:
        def __init__(self) -> None:
            self.pid = 12345
            self.returncode: int | None = None
            self.wait_calls = 0

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: int) -> int:
            del timeout
            self.wait_calls += 1
            self.returncode = 0
            return self.returncode

    @staticmethod
    def workflow_step_script(name: str, next_name: str) -> str:
        workflow = WORKFLOW_PATH.read_text()
        block = workflow.split(f"      - name: {name}\n", 1)[1]
        block = block.split(f"      - name: {next_name}\n", 1)[0]
        return textwrap.dedent(block.split("        run: |\n", 1)[1])

    @classmethod
    def run_inert_build(cls, mode: str, collect_failure: bool = False) -> dict[str, object]:
        fake_cargo = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

args = sys.argv[1:]
if args == ['-V']:
    print('cargo 1.95.0 (inert)')
    raise SystemExit(0)
if args and args[0] == 'metadata':
    print(json.dumps({'packages': [{
        'id': 'path+file:///inert#x0x@0.41.3',
        'name': 'x0x', 'version': '0.41.3', 'source': None,
        'manifest_path': str(Path.cwd() / 'Cargo.toml'),
    }]}))
    raise SystemExit(0)
if not args or args[0] != 'build':
    raise SystemExit(97)
if os.environ['FAKE_BUILD_MODE'] == 'build_failure':
    raise SystemExit(23)
target = Path(os.environ['CARGO_TARGET_DIR'])
manifest = str(Path.cwd() / 'Cargo.toml')
package = 'path+file:///inert#x0x@0.41.3'
for name in ('x0xd', 'x0x', 'rt3_fixture'):
    binary = target / 'debug' / name
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text(name)
    binary.chmod(0o700)
    if name == 'x0x':
        print(json.dumps({
            'reason': 'compiler-artifact', 'package_id': package,
            'target': {'name': 'x0x', 'kind': ['lib']},
            'executable': None, 'manifest_path': manifest, 'fresh': False,
        }))
    print(json.dumps({
        'reason': 'compiler-artifact', 'package_id': package,
        'target': {'name': name, 'kind': ['bin']},
        'executable': str(binary), 'manifest_path': manifest,
        'fresh': os.environ['FAKE_BUILD_MODE'] == 'fresh_x0x' and name == 'x0x',
    }))
'''
        fake_rustc = "#!/usr/bin/env bash\nprintf '%s\\n' 'rustc 1.95.0 (inert)'\n"
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary)
            work = runner / "work"
            root = runner / "root"
            safe = root / "safe"
            tools = runner / "tools"
            for path in (work, root, safe, tools):
                path.mkdir()
            lock = HARNESS_PATH.parent.parent / "ci/491-rt3/Cargo.lock.fixture"
            fixture_files = {
                "Cargo.toml": b'[package]\nname = "x0x"\nversion = "0.41.3"\n',
                "src/bin/rt3_fixture.rs": b"inert fixture\n",
                "tests/rt3_harness.py": b"inert harness\n",
                "tests/rt3_harness_controls.py": b"inert controls\n",
                "scripts/ci/isolated-runtime.py": b"inert wrapper\n",
                "scripts/ci/isolation-witness.py": b"inert witness\n",
                "ci/491-rt3/Cargo.lock.fixture": lock.read_bytes(),
            }
            for name, contents in fixture_files.items():
                destination = work / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(contents)
            (work / "Cargo.lock").write_bytes(lock.read_bytes())
            (root / "source.json").write_text(
                json.dumps(
                    {
                        "head": "a" * 40,
                        "tree": "b" * 40,
                        "files": {
                            name: __import__("hashlib").sha256(contents).hexdigest()
                            for name, contents in fixture_files.items()
                        },
                    }
                )
            )
            (tools / "cargo").write_text(fake_cargo)
            (tools / "rustc").write_text(fake_rustc)
            for executable in (tools / "cargo", tools / "rustc"):
                executable.chmod(0o700)
            environment = {
                **os.environ,
                "PATH": f"{tools}:{os.environ['PATH']}",
                "RT3_ROOT": str(root),
                "RT3_SAFE": str(safe),
                "FAKE_BUILD_MODE": mode,
            }
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    cls.workflow_step_script(
                        "Build fresh locked daemon CLI and typed witness",
                        "Collect pre-runtime build receipts",
                    ),
                ],
                cwd=work,
                env=environment,
                capture_output=True,
                text=True,
            )
            selection = json.loads((safe / "build-selection.json").read_text())
            collection_result = None
            collection = None
            if collect_failure:
                collection_result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        cls.workflow_step_script(
                            "Collect pre-runtime build receipts",
                            "Run inert witness and harness controls",
                        ),
                    ],
                    cwd=work,
                    env=environment,
                    capture_output=True,
                    text=True,
                )
                if (safe / "collection.json").is_file():
                    collection = json.loads((safe / "collection.json").read_text())
            rows = [
                json.loads(line)
                for line in (root / "build.jsonl").read_text().splitlines()
                if line.startswith("{")
            ]
            return {
                "returncode": result.returncode,
                "selection": selection,
                "collection_returncode": (
                    None if collection_result is None else collection_result.returncode
                ),
                "collection": collection,
                "safe_names": {path.name for path in safe.iterdir()},
                "raw_names": {path.name for path in root.iterdir()} - {"safe"},
                "build_record_present": (root / "build.json").is_file(),
                "x0x_name_rows": sum(
                    row.get("target", {}).get("name") == "x0x" for row in rows
                ),
            }

    @staticmethod
    def clean_children() -> list[dict[str, object]]:
        return [
            {
                "name": name,
                "shutdown_status": 200,
                "escalation": "none",
                "exit_status": 0,
                "reaped": True,
            }
            for name in ("owner", "device", "positive", "negative")
        ]

    @staticmethod
    def readiness_harness(temporary: str) -> object:
        return HARNESS.Harness(
            argparse.Namespace(
                artifacts=temporary,
                x0xd="/inert/x0xd",
                x0x="/inert/x0x",
                fixture="/inert/rt3_fixture",
            )
        )

    def test_start_child_accepts_current_socket_address_advertisement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            data.mkdir()
            (data / "api.port").write_text("127.0.0.1:49152\n")
            (data / "api-token").write_text("inert-token\n")
            harness = self.readiness_harness(temporary)
            process = self.InertProcess()
            with (
                mock.patch.object(HARNESS.subprocess, "Popen", return_value=process),
                mock.patch.object(
                    harness,
                    "http",
                    return_value=(200, {"ok": True}),
                ) as http,
                mock.patch.object(HARNESS.time, "monotonic", side_effect=[0.0, 0.0]),
            ):
                result = harness.start_child("owner", root / "owner.toml", data)
            self.assertEqual(result, ("http://127.0.0.1:49152", "inert-token"))
            http.assert_called_once_with(
                "GET", "http://127.0.0.1:49152", "inert-token", "/health"
            )
            self.assertEqual(process.wait_calls, 0)
            harness.children["owner"].log_handle.close()

    def test_start_child_rejects_unsafe_advertisements_and_cleans_up(self) -> None:
        rejected = (
            "localhost:49152",
            "10.0.0.1:49152",
            "127.0.0.1:0",
            "127.0.0.1:65536",
            "127.0.0.1:not-a-port",
            "49152",
        )
        for advertisement in rejected:
            with self.subTest(advertisement=advertisement):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    data = root / "data"
                    data.mkdir()
                    (data / "api.port").write_text(advertisement)
                    (data / "api-token").write_text("inert-token")
                    harness = self.readiness_harness(temporary)
                    process = self.InertProcess()
                    with (
                        mock.patch.object(
                            HARNESS.subprocess, "Popen", return_value=process
                        ),
                        mock.patch.object(harness, "http") as http,
                        mock.patch.object(
                            HARNESS.time,
                            "monotonic",
                            side_effect=[0.0, 0.0, 46.0],
                        ),
                        mock.patch.object(HARNESS.time, "sleep"),
                    ):
                        with self.assertRaises(HARNESS.DiagnosticFailure) as error:
                            harness.start_child("owner", root / "owner.toml", data)
                    self.assertEqual(error.exception.error_class, "timeout")
                    http.assert_not_called()
                    self.assertEqual(process.wait_calls, 1)
                    self.assertEqual(
                        harness.children["owner"].receipt(),
                        {
                            "name": "owner",
                            "shutdown_status": None,
                            "escalation": "none",
                            "exit_status": 0,
                            "reaped": True,
                        },
                    )

    def test_actual_positive_and_negative_predicates(self) -> None:
        before = {"state_revision": 7, "state_hash": "aa", "roster_root": "bb"}
        positive = {
            "ok": True,
            "commit": {"revision": 8},
            "evicted": [],
        }
        after_positive = {
            "state_revision": 8,
            "state_hash": "cc",
            "roster_root": "bb",
        }
        self.assertTrue(
            all(HARNESS.positive_observation(before, 200, positive, after_positive).values())
        )
        self.assertFalse(
            all(HARNESS.positive_observation(before, 409, positive, after_positive).values())
        )

        negative = {
            "ok": False,
            "error": "owner-certified group has members pending certificate resolution: []",
        }
        self.assertTrue(
            all(HARNESS.negative_observation(before, 409, negative, before.copy()).values())
        )
        mutated = dict(before, state_revision=8)
        self.assertFalse(
            all(HARNESS.negative_observation(before, 409, negative, mutated).values())
        )

        hydration = {
            "ok": True,
            "revision": 8,
            "description": "rt3-hydration-probe",
        }
        self.assertTrue(
            all(
                HARNESS.positive_hydration_observation(
                    before, 200, hydration, after_positive
                ).values()
            )
        )
        pending = {
            "ok": False,
            "error": "seal failed: owner-certified group has members pending certificate resolution",
        }
        self.assertTrue(
            all(
                HARNESS.negative_hydration_observation(
                    before, 500, pending, before.copy()
                ).values()
            )
        )

        self.assertEqual(
            HARNESS.owner_join_request("invite", "owner"),
            {
                "invite": "invite",
                "display_name": "rt3-device",
                "mode": "home",
                "expected_owner_user_id": "owner",
            },
        )

    def test_discriminating_http_failures_are_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = argparse.Namespace(
                artifacts=temporary,
                x0xd="/bin/false",
                x0x="/bin/false",
                fixture="/bin/false",
            )
            harness = HARNESS.Harness(args)
            before = {"state_revision": 7, "state_hash": "aa", "roster_root": "bb"}
            unexpected_positive = HARNESS.positive_hydration_observation(
                before,
                409,
                {"ok": False, "error": "unexpected"},
                before.copy(),
            )
            harness.record_result(
                "positive_hydration_status",
                409,
                {
                    "positive_hydration_revision_increment": unexpected_positive[
                        "revision_increment"
                    ],
                    "positive_hydration_roster_unchanged": unexpected_positive[
                        "roster_unchanged"
                    ],
                    "positive_description_updated": unexpected_positive[
                        "description_updated"
                    ],
                },
            )
            self.assertEqual(harness.observations["positive_hydration_status"], 409)
            self.assertFalse(
                harness.observations["positive_hydration_revision_increment"]
            )
            self.assertFalse(harness.observations["positive_description_updated"])

            wrong_negative = HARNESS.negative_hydration_observation(
                before,
                500,
                {"ok": False, "error": "different internal error"},
                before.copy(),
            )
            harness.record_result(
                "negative_hydration_status",
                500,
                {
                    "negative_hydration_pending_class": wrong_negative["pending_class"],
                    "negative_hydration_state_unchanged": wrong_negative[
                        "state_unchanged"
                    ],
                },
            )
            self.assertEqual(harness.observations["negative_hydration_status"], 500)
            self.assertFalse(harness.observations["negative_hydration_pending_class"])
            self.assertTrue(harness.observations["negative_hydration_state_unchanged"])

    def test_missing_outcome_retains_timeout_wrapper_receipts(self) -> None:
        workflow = WORKFLOW_PATH.read_text()
        block = workflow.split("      - name: Collect privacy-safe receipts\n", 1)[1]
        block = block.split("      - name: Enforce semantic acceptance\n", 1)[0]
        script = textwrap.dedent(block.split("        run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary)
            root = runner / "root"
            raw = root / "raw"
            safe = root / "safe"
            wrapper = runner / "wrapper"
            for path in (raw, safe, wrapper):
                path.mkdir(parents=True)
            (root / "runtime.json").write_text(
                json.dumps(
                    {
                        "harness_exit": 124,
                        "source_unchanged": True,
                        "wrapper_evidence": str(wrapper),
                    }
                )
            )
            (root / "source.json").write_text(json.dumps({"head": "aa", "files": {}}))
            (root / "build.json").write_text(
                json.dumps(
                    {
                        "exit": 0,
                        "lock_sha256": "bb",
                        "rustc": "rustc",
                        "cargo": "cargo",
                        "binaries": {},
                        "packages": [],
                    }
                )
            )
            (wrapper / "admission.json").write_text(
                json.dumps(
                    {
                        "namespace": "net:[2]",
                        "links": [{"ifname": "lo"}],
                        "routes": {"-4": [], "-6": []},
                        "capabilities": {
                            key: "0000000000000000"
                            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
                        },
                        "no_new_privs": 1,
                    }
                )
            )
            (wrapper / "supervisor.json").write_text(
                json.dumps(
                    {
                        "reason": "deadline",
                        "child_exit": -15,
                        "child_reaped": True,
                    }
                )
            )
            environment = {
                **os.environ,
                "RT3_ROOT": str(root),
                "RT3_RAW": str(raw),
                "RT3_SAFE": str(safe),
                "RUNNER_TEMP": str(runner),
            }
            subprocess.run(["bash", "-c", script], env=environment, check=True)
            collection = json.loads((safe / "collection.json").read_text())
            self.assertEqual(
                collection,
                {
                    "schema": 1,
                    "outcome_present": False,
                    "admission_present": True,
                    "exit_present": False,
                    "supervisor_present": True,
                    "failure_class": "missing_harness_outcome",
                    "accepted": False,
                },
            )
            self.assertEqual(json.loads((safe / "runtime.json").read_text())["harness_exit"], 124)
            self.assertEqual(json.loads((safe / "supervisor.json").read_text())["reason"], "deadline")
            self.assertTrue((safe / "admission.json").is_file())
            self.assertFalse((safe / "outcome.json").exists())
            self.assertFalse((safe / "exit.json").exists())

    def test_build_selection_ignores_same_name_library_row(self) -> None:
        result = self.run_inert_build("success")
        selection = result["selection"]
        self.assertEqual(result["returncode"], 0)
        self.assertTrue(selection["accepted"])
        self.assertEqual(selection["stage"], "complete")
        self.assertEqual(result["x0x_name_rows"], 2)
        self.assertEqual(selection["binaries"]["x0x"]["candidate_count"], 1)
        self.assertTrue(selection["binaries"]["x0x"]["fresh_false"])
        self.assertTrue(selection["binaries"]["x0x"]["manifest_match"])
        self.assertTrue(selection["source_unchanged"])
        self.assertTrue(selection["lock_matches"])
        self.assertTrue(result["build_record_present"])
        self.assertEqual(result["safe_names"], {"build-selection.json"})

    def test_build_failure_exit_is_retained_without_raw_uploads(self) -> None:
        result = self.run_inert_build("build_failure", collect_failure=True)
        selection = result["selection"]
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(selection["status"], 1)
        self.assertEqual(selection["build_exit"], 23)
        self.assertEqual(selection["error_class"], "build_failed")
        self.assertFalse(selection["accepted"])
        self.assertEqual(result["collection_returncode"], 0)
        self.assertEqual(
            result["collection"],
            {
                "schema": 1,
                "phase": "pre_runtime_build",
                "failure_class": "build_failed",
                "accepted": False,
            },
        )
        self.assertEqual(
            result["safe_names"],
            {"build-selection.json", "source.json", "collection.json"},
        )
        self.assertIn("build.jsonl", result["raw_names"])
        self.assertIn("build.stderr", result["raw_names"])
        self.assertNotIn("build.jsonl", result["safe_names"])
        self.assertNotIn("build.stderr", result["safe_names"])

    def test_fresh_binary_row_fails_closed_with_scalar_receipt(self) -> None:
        result = self.run_inert_build("fresh_x0x", collect_failure=True)
        selection = result["selection"]
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(selection["build_exit"], 0)
        self.assertEqual(selection["error_class"], "artifact_freshness")
        self.assertEqual(selection["binaries"]["x0x"]["candidate_count"], 1)
        self.assertFalse(selection["binaries"]["x0x"]["fresh_false"])
        self.assertFalse(selection["accepted"])
        self.assertEqual(result["collection_returncode"], 0)
        self.assertEqual(result["collection"]["failure_class"], "artifact_freshness")
        self.assertFalse(result["collection"]["accepted"])

    def test_flat_agent_and_group_shapes(self) -> None:
        group = {
            "ok": True,
            "membership_state": "active",
            "members": [
                {"agent_id": "aa", "state": "active"},
                {"agent_id": "bb", "state": "removed"},
            ],
        }
        self.assertEqual(HARNESS.active_agent_ids(group), {"aa"})
        self.assertEqual(HARNESS.active_agent_ids({"members": {}}), set())

    def test_lane_manifest_accepts_only_cache_absence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            positive = root / "positive"
            negative = root / "negative"
            for lane in (positive, negative):
                (lane / "identity").mkdir(parents=True)
                (lane / "data").mkdir()
                (lane / "data" / "home-suite-groups.json").write_text("{}")
                (lane / "identity" / "user.key").write_bytes(b"secret")
            (positive / "identity" / "announce-blob-cache.bin").write_bytes(b"cache")
            positive_manifest = HARNESS.Harness.regular_manifest(positive)
            negative_manifest = HARNESS.Harness.regular_manifest(negative)
            cache = "identity/announce-blob-cache.bin"
            self.assertIn(cache, positive_manifest)
            positive_manifest.pop(cache)
            self.assertEqual(positive_manifest, negative_manifest)

            config = root / "lane.toml"
            HARNESS.Harness.write_config(
                config,
                positive / "identity",
                positive / "data",
                12345,
                [],
            )
            text = config.read_text()
            self.assertIn(f'identity_dir = "{positive / "identity"}"', text)
            self.assertIn(f'data_dir = "{positive / "data"}"', text)
            self.assertIn("bootstrap_peers = []", text)

    def test_receipt_acceptance_is_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary)
            args = argparse.Namespace(
                artifacts=str(artifacts),
                x0xd="/bin/false",
                x0x="/bin/false",
                fixture="/bin/false",
            )
            harness = HARNESS.Harness(args)
            for row in self.clean_children():
                child = type("ReceiptChild", (), {"receipt": lambda self, row=row: row})()
                harness.children[str(row["name"])] = child
            harness.stage = "complete"
            for key in harness.observations:
                if not key.endswith("_status"):
                    harness.observations[key] = True
            harness.observations["positive_hydration_status"] = 200
            harness.observations["positive_seal_status"] = 200
            harness.observations["negative_hydration_status"] = 500
            harness.observations["negative_seal_status"] = 409
            harness.write_receipt(0, True)
            receipt = json.loads((artifacts / "harness-outcome.json").read_text())
            self.assertTrue(receipt["accepted"])
            harness.observations["negative_seal_state_unchanged"] = False
            harness.write_receipt(0, True)
            receipt = json.loads((artifacts / "harness-outcome.json").read_text())
            self.assertFalse(receipt["accepted"])

            children = self.clean_children()
            children[0]["exit_status"] = 1
            self.assertFalse(HARNESS.children_accepted(children))


if __name__ == "__main__":
    unittest.main()
