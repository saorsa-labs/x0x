#!/usr/bin/env python3
"""#1283: the daemon-mesh acceptance cases stay in the quic-localhost group.

`check-nextest-mesh-group.py` asks nextest itself (`show-config test-groups`)
which test-group each issue #321 acceptance case runs in. It does not
re-implement filterset or glob semantics: an earlier Python evaluator used
`fnmatch`, which differs from nextest's globset matcher, and passed
`binary(delegation_spaces) & not test(#[^x]*)` although nextest moves all
three cases out of the group (#1283 review).

Two layers:

* Parser and workflow controls run everywhere (the Format Check job). They
  prove the strict output parser fails closed and that the acceptance step
  builds its `-E` selector from the checker, so the checked and the run
  selector cannot diverge.
* Live controls run where the test binaries are built (the groups job sets
  `X0X_MESH_GROUP_LIVE=1`). nextest evaluates the real config and mutated
  configs; each negative control is a config that nextest itself reports
  outside the serial group, and the check must reject it. With the variable
  set, a missing cargo-nextest is an error, not a skip.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "nextest_mesh_group",
    Path(__file__).with_name("check-nextest-mesh-group.py"),
)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK  # dataclasses resolve their module by name
SPEC.loader.exec_module(CHECK)

CONFIG = ROOT / ".config" / "nextest.toml"
INTEGRATION_WORKFLOW = ROOT / ".github" / "workflows" / "integration.yml"
LIVE = os.environ.get("X0X_MESH_GROUP_LIVE") == "1"

# nextest 0.9.126 output for the real config (captured, #1283 round 3).
SERIALISED = """\
group: membership-cluster (max threads = 2)
    (no matches)
group: quic-localhost (max threads = 1)
  * override for default profile with filter 'binary(delegation_spaces)':
      x0x::delegation_spaces:
          delegated_child_cold_wake_rehydrates_carrier_and_sends_as
          delegation_carrier_verified_history_survives_receiver_restart
          delegation_survives_restart_via_history
group: @global
    (no matches)
"""

# nextest output for `binary(delegation_spaces) & not test(#[^x]*)`.
DROPPED = """\
group: membership-cluster (max threads = 2)
    (no matches)
group: quic-localhost (max threads = 1)
    (no matches)
group: @global
  * from default settings:
      x0x::delegation_spaces:
          delegated_child_cold_wake_rehydrates_carrier_and_sends_as
          delegation_carrier_verified_history_survives_receiver_restart
          delegation_survives_restart_via_history
"""

DELEGATION_OVERRIDE = (
    '[[profile.default.overrides]]\n'
    'filter = "binary(delegation_spaces)"\n'
    'test-group = "quic-localhost"\n'
)


def check_text(text: str) -> None:
    CHECK.check_assignment(CHECK.parse_show_test_groups(text))


class Parser(unittest.TestCase):
    def test_serialised_output_passes(self) -> None:
        check_text(SERIALISED)

    def test_cases_in_the_default_group_are_rejected(self) -> None:
        with self.assertRaisesRegex(CHECK.CheckError, "@global"):
            check_text(DROPPED)

    def test_cases_in_another_group_are_rejected(self) -> None:
        moved = SERIALISED.replace(
            "group: membership-cluster (max threads = 2)\n    (no matches)\n", ""
        ).replace("group: quic-localhost", "group: membership-cluster")
        with self.assertRaisesRegex(CHECK.CheckError, "membership-cluster"):
            check_text(moved + "group: quic-localhost (max threads = 1)\n    (no matches)\n")

    def test_one_case_split_out_is_rejected(self) -> None:
        split = SERIALISED.replace(
            "          delegation_survives_restart_via_history\n"
            "group: @global\n    (no matches)\n",
            "group: @global\n  * from default settings:\n"
            "      x0x::delegation_spaces:\n"
            "          delegation_survives_restart_via_history\n",
        )
        with self.assertRaisesRegex(CHECK.CheckError, "delegation_survives_restart_via_history"):
            check_text(split)

    def test_parallel_group_is_rejected(self) -> None:
        with self.assertRaisesRegex(CHECK.CheckError, "max threads"):
            check_text(SERIALISED.replace("quic-localhost (max threads = 1)", "quic-localhost (max threads = 2)"))

    def test_missing_or_extra_selected_cases_are_rejected(self) -> None:
        missing = SERIALISED.replace("          delegation_survives_restart_via_history\n", "")
        with self.assertRaisesRegex(CHECK.CheckError, "missing"):
            check_text(missing)
        extra = SERIALISED.replace(
            "          delegation_survives_restart_via_history\n",
            "          delegation_survives_restart_via_history\n          another_mesh_test\n",
        )
        with self.assertRaisesRegex(CHECK.CheckError, "unexpected"):
            check_text(extra)

    def test_unknown_line_shapes_fail_closed(self) -> None:
        for bad in (
            SERIALISED.replace("group: @global", "Group: @global"),
            SERIALISED.replace("  * override for", "  - override for"),
            SERIALISED.replace("      x0x::delegation_spaces:", "     x0x::delegation_spaces:"),
            SERIALISED + "warning: something new\n",
            "",
        ):
            with self.assertRaises(CHECK.CheckError):
                check_text(bad)

    def test_tests_without_a_source_line_fail_closed(self) -> None:
        bare = SERIALISED.replace(
            "  * override for default profile with filter 'binary(delegation_spaces)':\n", ""
        )
        with self.assertRaises(CHECK.CheckError):
            check_text(bare)


class Workflow(unittest.TestCase):
    """The acceptance step runs the selector the checker checks."""

    def setUp(self) -> None:
        text = INTEGRATION_WORKFLOW.read_text(encoding="utf-8")
        blocks = text.split("\n      - name: ")
        self.names = [b.split("\n", 1)[0].strip("'") for b in blocks]
        self.blocks = dict(zip(self.names, blocks))
        self.acceptance = "Run issue #321 delegation and cold-wake acceptance"
        self.check = "Check issue #321 delegation cases are serialised (#1283)"

    def test_acceptance_step_reads_its_filter_from_the_checker(self) -> None:
        step = self.blocks[self.acceptance]
        self.assertIn(
            'filter="$(python3 -B scripts/ci/check-nextest-mesh-group.py --print-filter)"',
            step,
        )
        self.assertIn("-E \"$filter\"", step)
        self.assertNotIn("test(=", step)
        for arg in ("--all-features", f"--test {CHECK.BINARY}", "--run-ignored ignored-only"):
            self.assertIn(arg, step)
        self.assertEqual(
            CHECK.SELECTION_ARGS,
            ("--all-features", "--test", CHECK.BINARY, "--run-ignored", "ignored-only"),
        )

    def test_live_check_runs_before_the_acceptance_step(self) -> None:
        step = self.blocks[self.check]
        self.assertIn("if: always()", step)
        self.assertIn(
            "X0X_MESH_GROUP_LIVE=1 python3 -B scripts/ci/test_nextest_mesh_serialization.py -v",
            step,
        )
        self.assertEqual(self.names.index(self.check) + 1, self.names.index(self.acceptance))

    def test_filter_names_every_case_exactly(self) -> None:
        self.assertEqual(
            CHECK.acceptance_filter(),
            " | ".join(f"test(={name})" for name in CHECK.ACCEPTANCE_CASES),
        )


@unittest.skipUnless(LIVE, "set X0X_MESH_GROUP_LIVE=1 where test binaries are built")
class Live(unittest.TestCase):
    """nextest evaluates the real and mutated configs; the check must agree."""

    def setUp(self) -> None:
        if shutil.which("cargo-nextest") is None:
            self.fail("X0X_MESH_GROUP_LIVE=1 but cargo-nextest is not installed")
        self.config = CONFIG.read_text(encoding="utf-8")
        self.assertEqual(self.config.count(DELEGATION_OVERRIDE), 1)
        self.scratch = ROOT / "target" / "mesh-group-controls"
        self.scratch.mkdir(parents=True, exist_ok=True)

    def run_with(self, label: str, text: str | None) -> dict:
        config = None
        if text is not None:
            config = self.scratch / f"{label}.toml"
            config.write_text(text, encoding="utf-8")
        return CHECK.parse_show_test_groups(CHECK.show_test_groups(config))

    def mutated(self, override: str) -> str:
        return self.config.replace(DELEGATION_OVERRIDE, override)

    def assert_rejected(self, label: str, text: str) -> None:
        # nextest must accept the mutated config and its output must parse;
        # only the assignment check may reject it. A nextest error or an
        # unparsable output is a test error, never a passing control.
        groups = self.run_with(label, text)
        with self.assertRaises(CHECK.CheckError, msg=label):
            CHECK.check_assignment(groups)

    def test_real_config_serialises_every_case(self) -> None:
        CHECK.check_assignment(self.run_with("real", None))

    def test_glob_that_drops_every_case_is_rejected(self) -> None:
        # The #1283 round-3 counterexample: fnmatch read this as keeping the
        # cases; nextest's globset drops all three.
        self.assert_rejected(
            "glob-drop",
            self.mutated(
                DELEGATION_OVERRIDE.replace(
                    '"binary(delegation_spaces)"',
                    '"binary(delegation_spaces) & not test(#[^x]*)"',
                )
            ),
        )

    def test_commented_out_group_is_rejected(self) -> None:
        self.assert_rejected(
            "commented-group",
            self.mutated(DELEGATION_OVERRIDE.replace("test-group", "# test-group")),
        )

    def test_negated_filter_is_rejected(self) -> None:
        self.assert_rejected(
            "negated",
            self.mutated(
                DELEGATION_OVERRIDE.replace(
                    '"binary(delegation_spaces)"', '"not binary(delegation_spaces)"'
                )
            ),
        )

    def test_test_name_filter_dropping_one_case_is_rejected(self) -> None:
        self.assert_rejected(
            "drop-one",
            self.mutated(
                DELEGATION_OVERRIDE.replace(
                    '"binary(delegation_spaces)"',
                    '"binary(delegation_spaces) - test(=delegation_survives_restart_via_history)"',
                )
            ),
        )

    def test_retargeted_group_is_rejected(self) -> None:
        self.assert_rejected(
            "retargeted",
            self.mutated(DELEGATION_OVERRIDE.replace('"quic-localhost"', '"membership-cluster"')),
        )

    def test_earlier_override_reassigning_one_case_is_rejected(self) -> None:
        earlier = (
            '[[profile.default.overrides]]\n'
            'filter = "test(/carrier_verified/)"\n'
            'test-group = "membership-cluster"\n\n'
        )
        self.assert_rejected("earlier", self.mutated(earlier + DELEGATION_OVERRIDE))

    def test_parallel_group_is_rejected(self) -> None:
        text = self.config.replace(
            "[test-groups.quic-localhost]\nmax-threads = 1\n",
            "[test-groups.quic-localhost]\nmax-threads = 2\n",
        )
        self.assertNotEqual(text, self.config)
        self.assert_rejected("parallel", text)

    def test_earlier_timeout_only_override_keeps_the_group(self) -> None:
        # Positive control: nextest resolves each setting separately, so an
        # earlier override without test-group does not erase the group.
        earlier = (
            '[[profile.default.overrides]]\n'
            'filter = "binary(delegation_spaces)"\n'
            'slow-timeout = "120s"\n\n'
        )
        CHECK.check_assignment(self.run_with("timeout-only", self.mutated(earlier + DELEGATION_OVERRIDE)))


if __name__ == "__main__":
    unittest.main()
