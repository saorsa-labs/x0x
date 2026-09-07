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


HARNESS_PATH = Path(__file__).with_name("rt3_harness.py")
SPEC = importlib.util.spec_from_file_location("rt3_harness", HARNESS_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load RT3 harness")
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class HarnessControls(unittest.TestCase):
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
        workflow = (HARNESS_PATH.parent.parent / ".github/workflows/build.yml").read_text()
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
