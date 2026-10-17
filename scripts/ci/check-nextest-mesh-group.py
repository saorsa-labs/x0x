#!/usr/bin/env python3
"""#1283: nextest itself must place the daemon-mesh acceptance cases in
the quic-localhost serial group.

The groups job's issue #321 acceptance selector runs three daemon-mesh tests
from `delegation_spaces` in one nextest invocation. nextest runs each test as
its own process, so the binary's in-process suite lock cannot serialise them;
without a `quic-localhost` group assignment all three pairs form
simultaneously inside the single loopback network namespace the isolated
runtime grants the invocation. Run 37898362740 (issue #1283) lost two of
those three meshes.

This check does not re-implement nextest's filterset or glob semantics: a
Python re-implementation drifted from nextest's matcher and passed a filter
that dropped all three cases (#1283 review). It asks nextest. It runs
`cargo nextest show-config test-groups --show-default` with the acceptance
step's own build flags and filterset (`acceptance_filter()` is the single
source the workflow step also reads), and requires that:

* the selector selects exactly the three acceptance cases;
* nextest reports each case once, in the `quic-localhost` group;
* nextest reports `quic-localhost` with `max threads = 1`.

The output parser accepts only the line shapes it knows and fails closed on
anything else, so a nextest output change is a loud failure, not a pass.

Usage:
  check-nextest-mesh-group.py --print-filter
  check-nextest-mesh-group.py [--config-file PATH]

Listing is inert: nextest runs each test binary with `--list` only, and no
test body or daemon starts.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

PACKAGE = "x0x"
BINARY = "delegation_spaces"
GROUP = "quic-localhost"
GROUP_MAX_THREADS = "1"

# The issue #321 acceptance cases. The workflow step builds its `-E`
# filterset from `--print-filter`, so the checked selector and the run
# selector cannot diverge.
ACCEPTANCE_CASES = (
    "delegation_survives_restart_via_history",
    "delegation_carrier_verified_history_survives_receiver_restart",
    "delegated_child_cold_wake_rehydrates_carrier_and_sends_as",
)

# The acceptance step's build and runtime selection, minus `-E`.
SELECTION_ARGS = ("--all-features", "--test", BINARY, "--run-ignored", "ignored-only")


class CheckError(Exception):
    """The nextest output is malformed or the assignment is wrong."""


def acceptance_filter() -> str:
    return " | ".join(f"test(={name})" for name in ACCEPTANCE_CASES)


@dataclass
class Group:
    name: str
    max_threads: str | None
    tests: list[tuple[str, str]] = field(default_factory=list)


_GROUP = re.compile(r"group: (\S+?)(?: \(max threads = (\S+)\))?")
_SOURCE = re.compile(r"\* (?:override for \S+ profile with filter '.*'|from default settings):")
_BINARY_ID = re.compile(r"[A-Za-z0-9_\-]+(?:::[A-Za-z0-9_\-/]+)?:")
_TEST_NAME = re.compile(r"[A-Za-z0-9_:]+")


def parse_show_test_groups(text: str) -> dict[str, Group]:
    """Parse `cargo nextest show-config test-groups` output.

    Accepted shapes, by indentation (nextest 0.9.12x–0.9.14x):

        group: <name> (max threads = <n>)     | group: @global
          * override for <profile> profile with filter '<expr>':
          * from default settings:
            (no matches)
              <binary-id>:
                  <test name>

    Any other line raises CheckError.
    """
    groups: dict[str, Group] = {}
    current: Group | None = None
    source = False
    binary: str | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()

        def bad(reason: str) -> CheckError:
            return CheckError(f"nextest output line {number} {reason}: {raw!r}")

        if indent == 0:
            match = _GROUP.fullmatch(line)
            if match is None:
                raise bad("is not a group header")
            name, threads = match.groups()
            if name in groups:
                raise bad("repeats a group")
            current = groups[name] = Group(name, threads)
            source, binary = False, None
        elif current is None:
            raise bad("precedes any group header")
        elif indent == 2 and _SOURCE.fullmatch(line):
            source, binary = True, None
        elif indent == 4 and line == "(no matches)":
            if source or current.tests:
                raise bad("follows matches")
        elif indent == 6 and source and _BINARY_ID.fullmatch(line):
            binary = line[:-1]
        elif indent == 10 and binary is not None and _TEST_NAME.fullmatch(line):
            current.tests.append((binary, line))
        else:
            raise bad("has an unknown shape")
    if not groups:
        raise CheckError("nextest printed no test groups")
    return groups


def check_assignment(groups: dict[str, Group]) -> None:
    """Raise CheckError unless nextest serialises every acceptance case."""
    binary_id = f"{PACKAGE}::{BINARY}"
    placed: dict[str, list[str]] = {}
    for group in groups.values():
        for test_binary, name in group.tests:
            placed.setdefault(f"{test_binary} {name}", []).append(group.name)
    expected = {f"{binary_id} {name}" for name in ACCEPTANCE_CASES}
    if set(placed) != expected:
        raise CheckError(
            "the acceptance selector must select exactly the issue #321 cases; "
            f"missing {sorted(expected - set(placed))}, "
            f"unexpected {sorted(set(placed) - expected)}"
        )
    wrong = {test: names for test, names in placed.items() if names != [GROUP]}
    if wrong:
        raise CheckError(
            f"nextest must run every acceptance case once in the {GROUP} "
            f"test-group (#1283); nextest reports {wrong}. The daemon-mesh "
            "selector would otherwise run its pairs concurrently in one "
            "loopback namespace."
        )
    threads = groups[GROUP].max_threads
    if threads != GROUP_MAX_THREADS:
        raise CheckError(
            f"nextest reports {GROUP} max threads = {threads!r}; it must be "
            f"{GROUP_MAX_THREADS} to serialise the acceptance cases (#1283)"
        )


def show_test_groups(config_file: Path | None = None) -> str:
    command = ["cargo", "nextest"]
    if config_file is not None:
        command += ["--config-file", str(config_file)]
    command += [
        "show-config",
        "test-groups",
        "--show-default",
        "--no-pager",
        "--color",
        "never",
        *SELECTION_ARGS,
        "-E",
        acceptance_filter(),
    ]
    command.append("--locked")
    result = subprocess.run(
        command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if result.returncode != 0:
        raise CheckError(
            f"{' '.join(command)} exited {result.returncode}:\n{result.stderr}"
        )
    return result.stdout


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--print-filter", action="store_true")
    parser.add_argument("--config-file", type=Path)
    args = parser.parse_args(argv)
    if args.print_filter:
        print(acceptance_filter())
        return 0
    output = ""
    try:
        output = show_test_groups(args.config_file)
        check_assignment(parse_show_test_groups(output))
    except CheckError as error:
        print(output, file=sys.stderr)
        print(f"#1283 mesh serialisation check FAILED: {error}", file=sys.stderr)
        return 1
    print(
        f"#1283: nextest runs {len(ACCEPTANCE_CASES)} acceptance cases in "
        f"{GROUP} (max threads = {GROUP_MAX_THREADS})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
