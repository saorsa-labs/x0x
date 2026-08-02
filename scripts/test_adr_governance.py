#!/usr/bin/env python3
"""Unit + end-to-end tests for scripts/adr-governance.py.

The pure-helper tests cover is_template_repair and has_section in
isolation: those decisions are the safety-critical gates that decide
whether an edit to an Accepted ADR is a permitted heading-only fix or a
forbidden mutation.

The end-to-end tests cover the five post-ADR-0028 governance properties
that the production code added. Each property is exercised by driving
the real ``main()`` path against a temporary git repository, not by
calling helpers directly:

    1. Mutation of an Accepted ADR's same-stem grounding fails closed.
    2. Deletion of an Accepted ADR's grounding fails closed.
    3. Amendment of a Proposed ADR's grounding is allowed (and passes).
    4. ``## Validation Notes`` is rejected where ``## Validation`` is
       required (exact-heading, not leading-word).
    5. A two-commit branch-new ADR whose second-commit required-heading
       defect is still caught against the original branch base.

Each end-to-end test has a passing control and a discriminating failing
arm: the failing arm flips the one variable that determines whether the
property holds, so a passing result on the failing arm proves the test
is not trivially green (or red).

The printed file count in the success message is checked separately so
``ADR governance passed (N ADR file(s) ...)`` always states what it
actually counts.

Run: python3 scripts/test_adr_governance.py
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# --- Load the validator module in-process for the helper tests. ---
_spec = importlib.util.spec_from_file_location(
    "adr_governance", Path(__file__).with_name("adr-governance.py")
)
assert _spec and _spec.loader
adr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adr)

_VALIDATOR_PATH = Path(__file__).with_name("adr-governance.py")


# --- Helper-test fixtures: minimal Accepted ADR with a mistitled Validation ---
_MISTITLED = """\
- Status: Accepted (2026-06-11)

## Context
Some context.

## Decision
The decision body.

## Consequences
The consequences.

## Acceptance criteria
- criterion one
- criterion two
"""

_REPAIRED = _MISTITLED.replace("## Acceptance criteria", "## Validation")


# --- End-to-end fixtures: minimal Proposed / Accepted ADR bodies ---
_ADR_PROPOSED = """\
# ADR 0042: Test Proposal

- Status: Proposed
- Date: 2026-08-02

## Context

Test context.

## Decision

Test decision body.

## Consequences

Test consequences body.

## Validation

Test validation body.
"""

_ADR_ACCEPTED = _ADR_PROPOSED.replace(
    "- Status: Proposed", "- Status: Accepted (2026-08-02)"
)

_GROUNDING = """\
# Grounding for ADR 0042: Test Proposal

- Status: Proposed grounding
- Recorded: 2026-08-02
- Decision: [ADR 0042](../adr/0042-test.md)

Test grounding body.
"""


def check(name: str, cond: bool) -> bool:
    print(f"{'ok' if cond else 'FAIL'} - {name}")
    return cond


# ===========================================================================
# End-to-end harness: temporary git repository + real subprocess invocation.
# ===========================================================================

def _init_repo(work: Path) -> None:
    """Initialise an empty git repository on ``main`` with one base commit.

    The base commit contains a placeholder file so subsequent ``git diff``
    invocations can resolve the merge-base. GPG signing is disabled so
    temporary commits don't require a signing key.
    """
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=work, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=work, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"], cwd=work, check=True
    )
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=work, check=True)
    subprocess.run(["git", "config", "tag.gpgsign", "false"], cwd=work, check=True)
    (work / ".placeholder").write_text("init\n")
    subprocess.run(["git", "add", ".placeholder"], cwd=work, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=work, check=True)


def _run_validator(work: Path) -> tuple[int, str]:
    """Invoke the production ``adr-governance.py`` from ``work``.

    Returns ``(exit_code, combined_stdout_stderr)``. The GitHub-Actions
    environment variables that would force a different ``base_ref()`` are
    stripped so the validator picks the local merge-base path.
    """
    env = os.environ.copy()
    env.pop("GITHUB_BASE_REF", None)
    env.pop("GITHUB_BEFORE", None)
    p = subprocess.run(
        [sys.executable, str(_VALIDATOR_PATH)],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _seed_base(
    work: Path,
    *,
    adr_text: str,
    with_grounding: bool = True,
) -> None:
    """Write the ADR (and optionally its same-stem grounding) on ``main``.

    Creates and commits both files, then branches off to ``feature`` so
    subsequent edits land on a non-default branch — this is the topology
    the production validator is designed to inspect.
    """
    (work / "docs" / "adr").mkdir(parents=True)
    (work / "docs" / "adr" / "0042-test.md").write_text(adr_text)
    if with_grounding:
        (work / "docs" / "grounding").mkdir(parents=True)
        (work / "docs" / "grounding" / "0042-test.md").write_text(_GROUNDING)
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "seed base"], cwd=work, check=True)
    subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)


def main() -> int:
    results: list[bool] = []

    # -----------------------------------------------------------------------
    # Helper tests: pre-existing pure-function coverage.
    # -----------------------------------------------------------------------
    results.append(check(
        "heading-only rename restoring a required section is a repair",
        adr.is_template_repair(_MISTITLED, _REPAIRED),
    ))
    results.append(check(
        "no-op edit on an already-compliant ADR is not a repair",
        not adr.is_template_repair(_REPAIRED, _REPAIRED),
    ))
    results.append(check(
        "editing decision body is not a repair",
        not adr.is_template_repair(
            _MISTITLED,
            _REPAIRED.replace("The decision body.", "A reworded decision."),
        ),
    ))
    results.append(check(
        "adding a new section with new content is not a repair",
        not adr.is_template_repair(
            _MISTITLED.replace(
                "## Acceptance criteria\n- criterion one\n- criterion two\n", ""
            ),
            _MISTITLED.replace("## Acceptance criteria", "## Validation"),
        ),
    ))
    results.append(check(
        "rename that does not restore a required section is not a repair",
        not adr.is_template_repair(
            _MISTITLED,
            _MISTITLED.replace("## Acceptance criteria", "## Notes"),
        ),
    ))
    results.append(check(
        "has_section detects present heading",
        adr.has_section(_REPAIRED, "Validation"),
    ))
    results.append(check(
        "has_section rejects absent heading",
        not adr.has_section(_MISTITLED, "Validation"),
    ))

    # -----------------------------------------------------------------------
    # Property 1 — mutation of an Accepted ADR's same-stem grounding fails
    # closed. The pairing is by filename stem: grounding/0042-test.md
    # freezes when docs/adr/0042-test.md is Accepted.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_ACCEPTED)
        (work / "docs" / "grounding" / "0042-test.md").write_text(
            _GROUNDING + "\nEXTRA: mutation appended.\n"
        )
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "mutate accepted grounding"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "P1 pass: mutating an Accepted ADR's same-stem grounding fails closed",
            rc == 1 and "cannot modify grounding for Accepted ADR "
            "docs/adr/0042-test.md" in out,
        ))

    # Discriminating arm — same setup with the ADR set to Proposed proves the
    # failure is gated on ADR acceptance and not on the presence of a
    # mutation alone.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_PROPOSED)
        (work / "docs" / "grounding" / "0042-test.md").write_text(
            _GROUNDING + "\nEXTRA: mutation appended.\n"
        )
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "mutate proposed grounding"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "P1 fail-arm: mutating a Proposed ADR's grounding is allowed",
            rc == 0 and "ADR governance passed" in out,
        ))

    # -----------------------------------------------------------------------
    # Property 2 — deletion of an Accepted ADR's grounding fails closed.
    # A grounding file paired with an Accepted ADR must remain in place;
    # removing it is treated as an impermissible mutation of the freeze.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_ACCEPTED)
        (work / "docs" / "grounding" / "0042-test.md").unlink()
        subprocess.run(["git", "add", "-A"], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "delete accepted grounding"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "P2 pass: deleting an Accepted ADR's grounding fails closed",
            rc == 1 and "cannot delete grounding for Accepted ADR "
            "docs/adr/0042-test.md" in out,
        ))

    # Discriminating arm — Proposed ADR, same delete.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_PROPOSED)
        (work / "docs" / "grounding" / "0042-test.md").unlink()
        subprocess.run(["git", "add", "-A"], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "delete proposed grounding"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "P2 fail-arm: deleting a Proposed ADR's grounding is allowed",
            rc == 0 and "ADR governance passed" in out,
        ))

    # -----------------------------------------------------------------------
    # Property 3 — amendment of a Proposed ADR's grounding is allowed.
    # The positive path is the main assertion; the discriminating arm
    # proves the validator is exercising real checks on this fixture by
    # introducing an unrelated grounding defect (an orphan grounding with
    # no same-stem ADR) and confirming the validator catches it.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_PROPOSED)
        (work / "docs" / "grounding" / "0042-test.md").write_text(
            _GROUNDING + "\nEXTRA: amended prose added.\n"
        )
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "amend proposed grounding"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "P3 pass: amending a Proposed ADR's grounding passes the gate",
            rc == 0 and "ADR governance passed" in out,
        ))

    # Discriminating arm — same Proposed fixture plus an orphan grounding
    # file. The validator must fail with the orphan error, proving the
    # validator actually ran the grounding checks (rather than trivially
    # returning 0 on this fixture).
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_PROPOSED)
        (work / "docs" / "grounding" / "0099-orphan.md").write_text(
            "# Grounding for ADR 0099\n\norphan\n"
        )
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "add orphan grounding"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "P3 fail-arm: Proposed + orphan grounding fails the orphan check",
            rc == 1 and "grounding file has no same-stem ADR "
            "docs/adr/0099-orphan.md" in out,
        ))

    # -----------------------------------------------------------------------
    # Property 4 — a branch-new ADR whose author wrote ``## Validation Notes``
    # in the Validation slot must be rejected. The pre-fix regex used a
    # leading-word boundary that let ``## Validation Notes`` satisfy the
    # Validation requirement; the post-fix regex anchors the heading line
    # so the extra word makes the heading a different section.
    # -----------------------------------------------------------------------
    adr_with_notes = _ADR_PROPOSED.replace("## Validation\n", "## Validation Notes\n")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        # Branch-new ADR: it does not exist on main.
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "adr" / "0050-test.md").write_text(adr_with_notes)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "branch-new ADR with Validation Notes"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "P4 pass: branch-new ADR with '## Validation Notes' is rejected",
            rc == 1 and "missing required section '## Validation'" in out
            and "docs/adr/0050-test.md" in out,
        ))

    # Discriminating arm — same fixture with the exact `## Validation`
    # heading must pass, proving the validator does not always reject
    # branch-new ADRs (and that the heading match is exact).
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "adr" / "0050-test.md").write_text(_ADR_PROPOSED)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "branch-new ADR with exact ## Validation"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "P4 fail-arm: branch-new ADR with exact '## Validation' passes",
            rc == 0 and "ADR governance passed" in out,
        ))

    # -----------------------------------------------------------------------
    # Property 5 — a two-commit branch-new ADR whose second commit
    # introduces a required-heading defect is still caught against the
    # original branch base. The old ``HEAD^1`` fallback would treat the
    # ADR as pre-existing at HEAD^1 (commit 1) and skip the structural
    # check; the production ``base_ref()`` finds the real fork point
    # (merge-base with main) so the defect is detected at HEAD.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        (work / "docs" / "adr").mkdir(parents=True)
        # Commit 1: valid branch-new ADR.
        (work / "docs" / "adr" / "0051-test.md").write_text(_ADR_PROPOSED)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "add branch-new ADR"],
            cwd=work,
            check=True,
        )
        # Commit 2: introduce the heading defect on the same file.
        defective = _ADR_PROPOSED.replace("## Validation\n", "## Validation Notes\n")
        (work / "docs" / "adr" / "0051-test.md").write_text(defective)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "introduce Validation Notes defect"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "P5 pass: 2-commit branch-new with 2nd-commit defect is caught",
            rc == 1 and "missing required section '## Validation'" in out
            and "docs/adr/0051-test.md" in out,
        ))

    # Discriminating arm — same two-commit topology, but commit 2 only
    # touches body text and keeps every required heading. The validator
    # must pass, proving the failure on the pass arm is gated on the
    # heading defect and not on the two-commit shape.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "adr" / "0051-test.md").write_text(_ADR_PROPOSED)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "add branch-new ADR"],
            cwd=work,
            check=True,
        )
        body_edited = _ADR_PROPOSED.replace(
            "Test decision body.", "Test decision body, expanded."
        )
        (work / "docs" / "adr" / "0051-test.md").write_text(body_edited)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "edit body without breaking headings"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "P5 fail-arm: 2-commit branch-new with body-only edit passes",
            rc == 0 and "ADR governance passed" in out,
        ))

    # -----------------------------------------------------------------------
    # File-count accuracy: the success message must state what it counts.
    # ADRs are counted from docs/adr/*.md; groundings from docs/grounding/
    # *.md whose same-stem ADR exists. Both clauses appear when at least
    # one grounding is present; the grounding clause is dropped when no
    # grounding files survive at HEAD.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "grounding").mkdir(parents=True)
        (work / "docs" / "adr" / "0001-a.md").write_text(_ADR_PROPOSED)
        (work / "docs" / "adr" / "0002-b.md").write_text(_ADR_PROPOSED)
        (work / "docs" / "grounding" / "0001-a.md").write_text(_GROUNDING)
        (work / "docs" / "grounding" / "0002-b.md").write_text(_GROUNDING)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "2 ADRs + 2 groundings"],
            cwd=work,
            check=True,
        )
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        rc, out = _run_validator(work)
        results.append(check(
            "count: success message names 2 ADRs and 2 groundings when both exist",
            rc == 0
            and "2 ADR file(s) and 2 grounding file(s) checked" in out,
        ))

    # No grounding directory: the success message must drop the grounding
    # clause entirely so it never states a grounding count of zero.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "adr" / "0001-a.md").write_text(_ADR_PROPOSED)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "1 ADR only"], cwd=work, check=True)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        rc, out = _run_validator(work)
        results.append(check(
            "count: success message names only ADRs when no grounding dir exists",
            rc == 0
            and "1 ADR file(s) checked" in out
            and "grounding" not in out,
        ))

    failed = results.count(False)
    print(f"\n{len(results) - failed}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
