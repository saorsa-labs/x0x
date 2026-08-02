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


def _run_validator(
    work: Path,
    env_overrides: dict[str, str] | None = None,
    *,
    strip: tuple[str, ...] = (
        "GITHUB_BASE_REF",
        "GITHUB_BEFORE",
        "GITHUB_BASE_SHA",
    ),
) -> tuple[int, str]:
    """Invoke the production ``adr-governance.py`` from ``work``.

    The default strip removes all GitHub-Actions vars that influence
    ``base_ref()`` so the validator picks the local merge-base path.
    Tests that need a different code path (e.g. on-main exercises the
    ``HEAD^1`` fallback, unresolved-base exercises the fail-closed
    error) pass ``env_overrides`` to set the vars they want.

    Returns ``(exit_code, combined_stdout_stderr)``.
    """
    env = os.environ.copy()
    for var in strip:
        env.pop(var, None)
    if env_overrides:
        env.update(env_overrides)
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


def _seed_transition(
    work: Path,
    *,
    base_adr_text: str = _ADR_PROPOSED,
    base_grounding: str = _GROUNDING,
    trans_adr_text: str = _ADR_ACCEPTED,
    trans_grounding: str | None = None,
) -> None:
    """Two-stage seed: base ADR is Proposed + grounding A, then branch to
    ``feature`` and commit a transition that flips the ADR to Accepted
    and (by default) edits the grounding A->B.

    The base ADR is Proposed so the snapshot selector must walk
    ``base..HEAD`` to find the transition commit. Tests that need this
    selector behaviour (Dario rollback, snapshot-advance, blob-read
    PATH-shim) use this helper; tests where the base is already
    Accepted can use :func:`_seed_base` directly.

    Pass ``trans_grounding=base_grounding`` to keep the grounding
    unchanged at the transition commit, leaving a follow-up commit to
    introduce the grounding mutation the arm exercises.
    """
    (work / "docs" / "adr").mkdir(parents=True)
    (work / "docs" / "grounding").mkdir(parents=True)
    (work / "docs" / "adr" / "0042-test.md").write_text(base_adr_text)
    (work / "docs" / "grounding" / "0042-test.md").write_text(base_grounding)
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "base: proposed + grounding A"],
        cwd=work, check=True,
    )
    subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
    (work / "docs" / "adr" / "0042-test.md").write_text(trans_adr_text)
    if trans_grounding is None:
        trans_grounding = base_grounding + "\nB: transition commit edit.\n"
    (work / "docs" / "grounding" / "0042-test.md").write_text(trans_grounding)
    subprocess.run(["git", "add", "."], cwd=work, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "c1: accept ADR + grounding A->B"],
        cwd=work, check=True,
    )


def _setup_path_shim(work: Path, fail_pattern: str) -> Path:
    """Install a PATH shim that exits 86 when a ``git`` argument equals
    *fail_pattern* exactly. All other invocations delegate to the real
    git binary via ``exec``. Returns the shim directory so the caller
    can prepend it to ``PATH``.
    """
    shim_dir = work / "shim"
    shim_dir.mkdir()
    real_git = subprocess.check_output(
        ["which", "git"], text=True
    ).strip()
    shim = shim_dir / "git"
    shim.write_text(
        "#!/bin/sh\n"
        f'real_git="{real_git}"\n'
        "for arg in \"$@\"; do\n"
        f'    if [ "$arg" = "{fail_pattern}" ]; then\n'
        '        echo "shim: failed $arg" >&2\n'
        "        exit 86\n"
        "    fi\n"
        "done\n"
        'exec "$real_git" "$@"\n'
    )
    shim.chmod(0o755)
    return shim_dir


def _setup_path_shim_matching(work: Path, fail_substr: str) -> Path:
    """Like :func:`_setup_path_shim` but matches *fail_substr* as a
    substring of any single argument using a shell case-glob. Useful
    for failing an arg like ``--diff-filter=A`` regardless of position.
    """
    shim_dir = work / "shim"
    shim_dir.mkdir()
    real_git = subprocess.check_output(
        ["which", "git"], text=True
    ).strip()
    shim = shim_dir / "git"
    shim.write_text(
        "#!/bin/sh\n"
        f'real_git="{real_git}"\n'
        "for arg in \"$@\"; do\n"
        f'        case "$arg" in\n'
        f'            *{fail_substr}*) echo "shim: matched $arg" >&2; exit 86 ;;\n'
        f"        esac\n"
        "done\n"
        'exec "$real_git" "$@"\n'
    )
    shim.chmod(0o755)
    return shim_dir


def _run_validator_with_shim(
    work: Path,
    shim_dir: Path,
    *,
    env_overrides: dict[str, str] | None = None,
) -> tuple[int, str]:
    """Invoke the production validator with the shim ``git`` prepended
    to ``PATH``. The default behaviour strips the GitHub-Actions vars
    so the validator picks the local merge-base path.
    """
    env = os.environ.copy()
    for var in ("GITHUB_BASE_REF", "GITHUB_BEFORE", "GITHUB_BASE_SHA"):
        env.pop(var, None)
    if env_overrides:
        env.update(env_overrides)
    env["PATH"] = f"{shim_dir}:" + env.get("PATH", "")
    p = subprocess.run(
        [sys.executable, str(_VALIDATOR_PATH)],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return p.returncode, (p.stdout or "") + (p.stderr or "")


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
    # The contract is:
    #   ADR governance passed (N ADR file(s) discovered[,
    #   M ADR(s) structurally validated][, K grounding file(s) paired]).
    # - N = ADR files discovered under docs/adr/.
    # - M = ADRs that actually ran the required-section loop (is_new at
    #   base_ref); the clause is dropped when M == 0, so an edited
    #   pre-existing ADR is not counted as "structurally validated".
    # - K = paired grounding files; the clause is dropped when no
    #   groundings exist.
    # These tests assert the exact quantities — discovery, validation,
    # and pairing are three independent counts.
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
        rc, out = _run_validator(work)
        # Both ADRs are is_new at base (they don't exist at the placeholder
        # commit), so n_structurally_validated == 2 and the validated
        # clause IS present. The paired clause is present.
        expected = (
            "ADR governance passed "
            "(2 ADR file(s) discovered, 2 ADR(s) structurally validated, "
            "2 grounding file(s) paired)."
        )
        results.append(check(
            "count: 2 ADRs + 2 groundings reports exact message",
            rc == 0 and expected in out,
        ))

    # Discriminating arm: 3 ADRs on the base commit, 1 of 3 edited on
    # the branch. The edited ADR is pre-existing so is_new is False at
    # base_ref and the required-section loop does NOT run for it.
    # n_structurally_validated is 0; the validated clause is dropped
    # entirely from the success message. This arm proves the fix
    # counts only ADRs that ran the structural check — the pre-fix
    # message reported n_validated = len(files_to_validate) which
    # would have included the edited ADR.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "grounding").mkdir(parents=True)
        for n in ("0001-a", "0002-b", "0003-c"):
            (work / "docs" / "adr" / f"{n}.md").write_text(_ADR_PROPOSED)
            (work / "docs" / "grounding" / f"{n}.md").write_text(_GROUNDING)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "3 ADRs + 3 groundings on base"],
            cwd=work,
            check=True,
        )
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        # Edit only 1 of 3 ADRs on the branch.
        edited = _ADR_PROPOSED.replace("Test decision body.", "Edited body.")
        (work / "docs" / "adr" / "0002-b.md").write_text(edited)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "edit one ADR"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        expected = (
            "ADR governance passed "
            "(3 ADR file(s) discovered, 3 grounding file(s) paired)."
        )
        results.append(check(
            "count: 3 ADRs/discovered, 1 edited, drops validated clause",
            rc == 0
            and expected in out
            and "ADR(s) structurally validated" not in out,
        ))

    # No grounding directory: the success message drops the grounding
    # clause entirely so it never states a grounding count of zero.
    # The 1 ADR is is_new at base, so the validated clause IS present.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "adr" / "0001-a.md").write_text(_ADR_PROPOSED)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "1 ADR only"], cwd=work, check=True,
        )
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        rc, out = _run_validator(work)
        expected = (
            "ADR governance passed "
            "(1 ADR file(s) discovered, 1 ADR(s) structurally validated)."
        )
        results.append(check(
            "count: no grounding dir drops the paired clause",
            rc == 0
            and expected in out
            and "grounding" not in out,
        ))

    # -----------------------------------------------------------------------
    # Property 6 — on-main: a mutation on the default branch must be
    # caught. The pre-fix ``base_ref()`` resolved ``merge-base main HEAD``
    # to HEAD on main, diffing HEAD...HEAD and returning an empty change
    # set so the validator passed silently. The fix rejects base == HEAD
    # and falls back to ``HEAD^1``, which exposes the mutation commit.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        # Commit 1: Accepted ADR + grounding on main.
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "grounding").mkdir(parents=True)
        (work / "docs" / "adr" / "0042-test.md").write_text(_ADR_ACCEPTED)
        (work / "docs" / "grounding" / "0042-test.md").write_text(_GROUNDING)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "add accepted ADR on main"],
            cwd=work,
            check=True,
        )
        # Commit 2 (still on main): mutate both the ADR body and the
        # grounding. The body change breaks is_template_repair so the
        # immutability check fires; the grounding is paired with an
        # Accepted ADR so the grounding check fires too.
        mutated = _ADR_ACCEPTED.replace(
            "Test decision body.", "Mutated decision body."
        )
        (work / "docs" / "adr" / "0042-test.md").write_text(mutated)
        (work / "docs" / "grounding" / "0042-test.md").write_text(
            _GROUNDING + "\nMUTATED: grounding content.\n"
        )
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "mutate accepted ADR + grounding on main"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "P6 pass: on-main mutation of Accepted ADR + grounding fails closed",
            rc == 1
            and "Accepted ADRs are immutable" in out
            and "cannot modify grounding for Accepted ADR "
            "docs/adr/0042-test.md" in out,
        ))

    # Discriminating arm — on-main, but the only change is a branch-new
    # ADR with valid structure. The validator must pass, proving the
    # P6 failure is gated on the mutation shape and not on the on-main
    # topology (the HEAD^1 fallback still produces a usable base).
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "adr" / "0050-test.md").write_text(_ADR_PROPOSED)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "branch-new ADR on main"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "P6 fail-arm: on-main branch-new valid ADR passes",
            rc == 0 and "ADR governance passed" in out,
        ))

    # -----------------------------------------------------------------------
    # Property 7 — unresolved/invalid base: an event-derived base that
    # cannot resolve to a valid non-HEAD commit must fail closed. The
    # pre-fix code returned an empty change set and exited 0, silently
    # disabling every change-specific check. The fix resolves every
    # candidate through ``git rev-parse --verify`` and fails closed
    # with a message naming the attempted selectors when none resolves
    # to a valid non-HEAD commit.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "adr" / "0001-a.md").write_text(_ADR_PROPOSED)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "1 ADR"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(
            work,
            env_overrides={
                "GITHUB_BASE_SHA": "deadbeef" * 5,  # 40 hex chars, non-existent
            },
        )
        results.append(check(
            "P7 pass: invalid GITHUB_BASE_SHA fails closed",
            rc == 1
            and "Event base selector(s) could not resolve to a valid "
            "non-HEAD commit: GITHUB_BASE_SHA="
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" in out,
        ))

    # Discriminating arm — same fixture with a clean base (no env
    # override, local merge-base). The validator must pass, proving the
    # P7 failure is gated on the invalid base and not on the fixture.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "adr" / "0001-a.md").write_text(_ADR_PROPOSED)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "1 ADR"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "P7 fail-arm: clean base passes",
            rc == 0 and "ADR governance passed" in out,
        ))

    # -----------------------------------------------------------------------
    # P7 control: unresolved GITHUB_BASE_REF (Sam #1). The production
    # resolver attempts ``git rev-parse --verify origin/{ref}``. A repo
    # without an ``origin`` remote (the temporary fixture) cannot
    # resolve any ref, so the validator must fail closed and name the
    # attempted selector — local fallbacks are NOT consulted when an
    # event selector was explicitly provided.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "adr" / "0001-a.md").write_text(_ADR_PROPOSED)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "1 ADR"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(
            work,
            env_overrides={"GITHUB_BASE_REF": "definitely-missing-base"},
        )
        results.append(check(
            "P7 control: unresolved GITHUB_BASE_REF fails closed",
            rc == 1
            and "Event base selector(s) could not resolve to a valid "
            "non-HEAD commit: GITHUB_BASE_REF=definitely-missing-base" in out,
        ))

    # -----------------------------------------------------------------------
    # P7 control: all-zero GITHUB_BASE_SHA (Watson). GitHub emits an
    # all-zero SHA when no base commit is selected. The production
    # _is_valid_base guard rejects any candidate starting with
    # ``0000000`` (7 zeros), so this never resolves to a usable base.
    # The validator must fail closed and name the attempted selector.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "adr" / "0001-a.md").write_text(_ADR_PROPOSED)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "1 ADR"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(
            work,
            env_overrides={"GITHUB_BASE_SHA": "0" * 40},
        )
        results.append(check(
            "P7 control: all-zero GITHUB_BASE_SHA fails closed",
            rc == 1
            and "Event base selector(s) could not resolve to a valid "
            "non-HEAD commit: GITHUB_BASE_SHA=" + "0" * 40 in out,
        ))

    # -----------------------------------------------------------------------
    # P7 control: all-zero GITHUB_BEFORE (Watson). Same GitHub default
    # but for push events. The validator must fail closed; the message
    # names the attempted selector.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "adr" / "0001-a.md").write_text(_ADR_PROPOSED)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "1 ADR"],
            cwd=work,
            check=True,
        )
        rc, out = _run_validator(
            work,
            env_overrides={"GITHUB_BEFORE": "0" * 40},
        )
        results.append(check(
            "P7 control: all-zero GITHUB_BEFORE fails closed",
            rc == 1
            and "Event base selector(s) could not resolve to a valid "
            "non-HEAD commit: GITHUB_BEFORE=" + "0" * 40 in out,
        ))

    # -----------------------------------------------------------------------
    # P7 control: divergent-history push (Watson #2). The push event
    # has GITHUB_BEFORE = the old tip on ``main`` (which contains an
    # Accepted ADR + paired grounding) and HEAD = a force-pushed commit
    # on a divergent branch that deletes both files. Three-dot diff
    # resolves merge-base to the empty ancestor commit (which never had
    # the ADR), so the deletion is invisible — exit 0. Two-dot diff
    # (used for push events) compares the old tip directly to HEAD and
    # sees the deletion — exit 1 with "Accepted ADRs are immutable".
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        # Commit A: empty (just placeholder). main == A.
        # Branch old_main and add an Accepted ADR + paired grounding.
        subprocess.run(
            ["git", "checkout", "-q", "-b", "old_main"], cwd=work, check=True
        )
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "grounding").mkdir(parents=True)
        (work / "docs" / "adr" / "0042-test.md").write_text(_ADR_ACCEPTED)
        (work / "docs" / "grounding" / "0042-test.md").write_text(_GROUNDING)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "B: add accepted ADR + grounding"],
            cwd=work,
            check=True,
        )
        old_tip = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=work, text=True
        ).strip()
        # Create divergent history: branch from the empty ancestor A
        # (NOT from B) and produce a new tip that does NOT contain the
        # Accepted ADR but DOES have a docs/adr/ directory (the
        # production validator early-returns when docs/adr/ is absent
        # at HEAD). This simulates a force-push that rewrites main's
        # history away from the Accepted ADR.
        ancestor = subprocess.check_output(
            ["git", "rev-parse", "old_main^"], cwd=work, text=True
        ).strip()
        subprocess.run(
            ["git", "checkout", "-q", ancestor], cwd=work, check=True
        )
        subprocess.run(
            ["git", "checkout", "-q", "-b", "new_tip"], cwd=work, check=True
        )
        # A different ADR file (with deliberately dissimilar content
        # so git's auto-rename detection does not collapse it with the
        # deleted 0042-test.md) so docs/adr/ exists at HEAD; the
        # deletion target (0042-test.md) is absent. This is what a real
        # force-push of an unrelated branch over main looks like: the
        # push target lost the ADR but the directory remained.
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "adr" / "9999-other.md").write_text("# stub\n")
        (work / "newfile.txt").write_text("force-push noise\n")
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "C: divergent tip, no 0042 ADR"],
            cwd=work,
            check=True,
        )
        # Sanity: divergent branch (new_tip) does not see the deleted
        # ADR; merge-base with old_tip is the empty ancestor (so three-
        # dot diff will not see the 0042 deletion).
        files_visible = subprocess.check_output(
            ["git", "ls-tree", "-r", "--name-only", "HEAD"],
            cwd=work,
            text=True,
        ).strip().splitlines()
        assert "docs/adr/0042-test.md" not in files_visible, (
            "fixture invariant: new_tip must not contain the Accepted ADR"
        )
        merge_base = subprocess.check_output(
            ["git", "merge-base", old_tip, "HEAD"], cwd=work, text=True
        ).strip()
        assert merge_base == ancestor, (
            "fixture invariant: merge-base must be the empty ancestor "
            "for three-dot diff to mask the 0042 deletion"
        )
        # Run the validator as a push event: GITHUB_BEFORE = old tip.
        rc, out = _run_validator(
            work,
            env_overrides={"GITHUB_BEFORE": old_tip},
        )
        results.append(check(
            "P7 control: divergent-history push catches deleted Accepted ADR",
            rc == 1
            and "Accepted ADRs are immutable" in out
            and "cannot delete grounding for Accepted ADR "
            "docs/adr/0042-test.md" in out,
        ))

    # -----------------------------------------------------------------------
    # Sam control: delete the COMPLETE docs/adr + docs/grounding trees in
    # one commit so both directories are absent at HEAD (no-empty-dir
    # post-checkout). Pre-fix code early-returned exit 0 when docs/adr/
    # was absent, masking every deletion against the immutable-set
    # check. Post-fix code falls through with an empty ADR set and the
    # base/change analysis still inspects the deleted paths so both the
    # Accepted-ADR immutability and grounding-freeze errors fire.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_ACCEPTED)
        # Sanity: the seed-base commit on the feature branch has the
        # ADR + grounding in place.
        assert (work / "docs" / "adr" / "0042-test.md").exists()
        assert (work / "docs" / "grounding" / "0042-test.md").exists()
        # Delete the entire docs/ tree (both directories) and commit.
        subprocess.run(
            ["rm", "-rf", "docs/adr", "docs/grounding"], cwd=work, check=True
        )
        subprocess.run(["git", "add", "-A"], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "delete entire docs tree"],
            cwd=work, check=True,
        )
        # Sanity: the directories must be absent at HEAD — git won't
        # carry empty dirs, so a successful commit here proves the
        # deletion actually landed in the tracked tree.
        assert not (work / "docs" / "adr").exists(), (
            "fixture invariant: docs/adr/ must be absent at HEAD"
        )
        assert not (work / "docs" / "grounding").exists(), (
            "fixture invariant: docs/grounding/ must be absent at HEAD"
        )
        base_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD^"], cwd=work, text=True
        ).strip()
        rc, out = _run_validator(
            work, env_overrides={"GITHUB_BEFORE": base_sha},
        )
        results.append(check(
            "Sam: delete-whole-tree fails closed (ADR immutability + grounding freeze)",
            rc == 1
            and "Accepted ADRs are immutable" in out
            and "cannot delete grounding for Accepted ADR "
            "docs/adr/0042-test.md" in out,
        ))

    # -----------------------------------------------------------------------
    # Dario control: ADR rename evasion (BLOCKING 1, half A). ``git mv``
    # an Accepted ADR to a new stem and rewrite the Decision body so the
    # rewrite intent is unambiguous. Pre-fix git diff (with rename
    # detection on) collapsed the rename to the destination path only;
    # the deleted source was invisible, so the immutability check was
    # dodged and the validator passed silently. The 20ea0a2 fix adds
    # --no-renames so both halves of the rename appear in the diff and
    # the Accepted-source immutability check fires on the deleted path.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        # No grounding to avoid orphan noise on the deletion half.
        _seed_base(work, adr_text=_ADR_ACCEPTED, with_grounding=False)
        subprocess.run(
            ["git", "mv", "docs/adr/0042-test.md", "docs/adr/0043-renamed.md"],
            cwd=work, check=True,
        )
        mutated = (
            (work / "docs/adr/0043-renamed.md").read_text()
            .replace("Test decision body.", "COMPLETELY DIFFERENT DECISION.")
        )
        (work / "docs/adr/0043-renamed.md").write_text(mutated)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "rename + rewrite accepted ADR"],
            cwd=work, check=True,
        )
        base_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD^"], cwd=work, text=True
        ).strip()
        rc, out = _run_validator(
            work, env_overrides={"GITHUB_BEFORE": base_sha},
        )
        results.append(check(
            "Dario: rename + rewrite of Accepted ADR fails closed",
            rc == 1
            and "Accepted ADRs are immutable" in out
            and "docs/adr/0042-test.md" in out,
        ))

    # -----------------------------------------------------------------------
    # Dario control: PR-path ADR rename evasion (pins the three-dot
    # diff branch at scripts/adr-governance.py :259). The push-path
    # rename red arm above only exercises GITHUB_BEFORE (:255). A
    # regression that drops --no-renames from the three-dot site only
    # would pass every existing test in this file but re-open the
    # evasion on every PR run, because PRs use the three-dot
    # merge-base diff. This arm sets GITHUB_BASE_SHA=<base> with
    # GITHUB_BEFORE and GITHUB_BASE_REF unset, so the validator
    # reaches :259 and the deleted-source Accepted immutability
    # check must fire on docs/adr/0042-test.md. Mutation proof:
    # removing --no-renames from :259 only must make THIS row red
    # while the push-path rename row above (GITHUB_BEFORE) stays
    # green. The grounding half rides the same code path; one arm
    # is sufficient to pin the PR site.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        # No grounding to avoid orphan noise on the deletion half.
        _seed_base(work, adr_text=_ADR_ACCEPTED, with_grounding=False)
        subprocess.run(
            ["git", "mv", "docs/adr/0042-test.md", "docs/adr/0043-renamed.md"],
            cwd=work, check=True,
        )
        mutated = (
            (work / "docs/adr/0043-renamed.md").read_text()
            .replace("Test decision body.", "COMPLETELY DIFFERENT DECISION.")
        )
        (work / "docs/adr/0043-renamed.md").write_text(mutated)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "rename + rewrite accepted ADR"],
            cwd=work, check=True,
        )
        base_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD^"], cwd=work, text=True
        ).strip()
        # GITHUB_BEFORE and GITHUB_BASE_REF are absent - the helper's
        # default strip removes them - so the validator reaches
        # changed_files_against_base's three-dot branch (:259)
        # exclusively via GITHUB_BASE_SHA=base_sha here.
        rc, out = _run_validator(
            work, env_overrides={"GITHUB_BASE_SHA": base_sha},
        )
        results.append(check(
            "Dario: PR-path rename + rewrite of Accepted ADR fails closed",
            rc == 1
            and "Accepted ADRs are immutable" in out
            and "docs/adr/0042-test.md" in out,
        ))

    # Discriminating arm — same rename on a Proposed ADR (no rewrite).
    # The validator must pass, proving the red-arm failure is gated on
    # the Accepted status and not on the rename mechanism itself.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_PROPOSED, with_grounding=False)
        subprocess.run(
            ["git", "mv", "docs/adr/0042-test.md", "docs/adr/0043-renamed.md"],
            cwd=work, check=True,
        )
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "rename proposed ADR"],
            cwd=work, check=True,
        )
        base_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD^"], cwd=work, text=True
        ).strip()
        rc, out = _run_validator(
            work, env_overrides={"GITHUB_BEFORE": base_sha},
        )
        results.append(check(
            "Dario fail-arm: rename of Proposed ADR is allowed",
            rc == 0 and "ADR governance passed" in out,
        ))

    # -----------------------------------------------------------------------
    # Dario control: grounding rename evasion (BLOCKING 1, half B).
    # ``git mv`` the grounding of an Accepted ADR onto the stem of a
    # Proposed ADR so the source path is deleted and the destination
    # path is on a non-Accepted ADR. Pre-fix git diff collapsed the
    # rename to the destination only; the deleted source was invisible
    # so the grounding-freeze check was dodged. With --no-renames the
    # deleted source is reported and the freeze fires on the deleted
    # path. The destination is paired with a Proposed ADR so the
    # orphan check does not produce noise.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_ACCEPTED)
        # Add a Proposed ADR at the destination stem so the renamed
        # grounding will be paired (avoids orphan noise). Do NOT
        # pre-create the destination grounding file — ``git mv`` will
        # create it from the source content. Pre-creating the
        # destination would also conflict with ``git mv``'s refusal
        # to overwrite an existing destination.
        (work / "docs/adr" / "0050-other.md").write_text(_ADR_PROPOSED)
        subprocess.run(
            [
                "git", "mv",
                "docs/grounding/0042-test.md",
                "docs/grounding/0050-other.md",
            ],
            cwd=work, check=True,
        )
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "rename grounding 0042 onto 0050 stem"],
            cwd=work, check=True,
        )
        base_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD^"], cwd=work, text=True
        ).strip()
        rc, out = _run_validator(
            work, env_overrides={"GITHUB_BEFORE": base_sha},
        )
        results.append(check(
            "Dario: grounding rename (Accepted source) fails closed",
            rc == 1
            and "cannot delete grounding for Accepted ADR "
            "docs/adr/0042-test.md" in out,
        ))

    # Discriminating arm — same cross-stem rename but on a Proposed
    # ADR's grounding. The validator must pass, proving the red-arm
    # failure is gated on the Accepted source and not on the rename
    # itself or on the orphan check.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        # Two Proposed ADRs at the base; only the source ADR has a
        # paired grounding so the destination stem is unoccupied at
        # base — ``git mv`` then creates the destination grounding
        # cleanly (it refuses to overwrite an existing destination).
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "grounding").mkdir(parents=True)
        for stem in ("0050-a", "0051-b"):
            (work / "docs" / "adr" / f"{stem}.md").write_text(_ADR_PROPOSED)
        (work / "docs/grounding" / "0050-a.md").write_text(_GROUNDING)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "2 proposed ADRs, 1 grounding"],
            cwd=work, check=True,
        )
        subprocess.run(
            ["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True,
        )
        subprocess.run(
            [
                "git", "mv",
                "docs/grounding/0050-a.md",
                "docs/grounding/0051-b.md",
            ],
            cwd=work, check=True,
        )
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            [
                "git", "commit", "-q",
                "-m",
                "rename proposed grounding 0050-a -> 0051-b",
            ],
            cwd=work, check=True,
        )
        base_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD^"], cwd=work, text=True
        ).strip()
        rc, out = _run_validator(
            work, env_overrides={"GITHUB_BEFORE": base_sha},
        )
        results.append(check(
            "Dario fail-arm: grounding rename between Proposed stems is allowed",
            rc == 0 and "ADR governance passed" in out,
        ))

    # -----------------------------------------------------------------------
    # Dario BLOCKING 2 control: abbreviated GITHUB_BEFORE that resolves
    # to HEAD must fail closed. The pre-existing P7 controls use
    # unresolvable selectors (random hex / all-zero) and the all-zero
    # GITHUB_BASE_SHA — every one of them is rejected by raw string
    # comparison without ever exercising _resolve, so a regression
    # that drops _resolve(before) would still pass all 28 existing
    # tests. Abbreviated HEAD is the discriminating input: under the
    # raw-string regression the abbrev differs from the full HEAD SHA,
    # _is_valid_base accepts it, changed_files_against_base runs
    # ``git diff abbrev HEAD`` (which resolves to an empty diff) and
    # the validator returns 0 — exactly the failure this control
    # guards against.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_ACCEPTED)
        head_full = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=work, text=True
        ).strip()
        head_abbrev = head_full[:8]
        # Sanity: the abbreviated SHA must resolve to the full HEAD
        # SHA — otherwise this control is not actually exercising the
        # _resolve path.
        resolved = subprocess.check_output(
            ["git", "rev-parse", head_abbrev], cwd=work, text=True
        ).strip()
        assert resolved == head_full, (
            "fixture invariant: abbreviated HEAD SHA must resolve to full HEAD"
        )
        rc, out = _run_validator(
            work, env_overrides={"GITHUB_BEFORE": head_abbrev},
        )
        results.append(check(
            "Dario: abbreviated GITHUB_BEFORE resolves to HEAD and fails closed",
            rc == 1
            and f"GITHUB_BEFORE={head_abbrev}" in out
            and "could not resolve to a valid non-HEAD commit" in out,
        ))

    # -----------------------------------------------------------------------
    # Dario rollback arms (a)/(b)/(c) — required by `559e8ce2` and refined
    # by `c3a2ccec`. The selector must be history-driven; gating it on
    # HEAD lifecycle status is self-disabling because the edit that
    # leaves the Accepted state is precisely the edit the control
    # exists to forbid.
    #
    # Two-stage fixture: base ADR is Proposed so the snapshot is at the
    # transition commit (c1), not at base. The transition flips to
    # Accepted and edits the grounding (A->B). The rollback commit on
    # the feature branch walks the snapshot back.
    #
    # Mutations cited per Kimi `c3a2ccec` and Dario `2aa663d7`:
    #   MUT2a — disable the freeze in `_frozen_adr_snapshot` only when
    #           the ADR *exists* at HEAD and is no longer Accepted;
    #           absent-at-HEAD still falls through to the history
    #           scan. Under this restricted shape arm (a) goes red
    #           AND arm (b) goes red — both rely on the
    #           ADR-immutability row. Applied literally as "gate on
    #           HEAD status" without the exists-at-HEAD restriction,
    #           the mutation is MUT1 (which is self-disabling on
    #           absent-at-HEAD paths and reddens unrelated
    #           delete/rename arms).
    #   MUT2b — disable the freeze in `_frozen_grounding_snapshot`
    #           only when the ADR *exists* at HEAD and is no longer
    #           Accepted; absent-at-HEAD still falls through to the
    #           history scan. Under this restricted shape only arm
    #           (b) goes red — its grounding-freeze row assertion is
    #           the load-bearing discriminator. Arm (b) keeps exit 1
    #           via the ADR row from the same fixture, so the row
    #           assertion (not just the exit code) is what proves the
    #           freeze engaged.
    # -----------------------------------------------------------------------
    # Dario rollback (a): rollback Accepted->Proposed + body edit. The
    # grounding row must NOT fire (the rollback did not touch it), so
    # the sole catcher is the ADR-immutability row. Cite MUT2a.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_transition(work)
        rolled_back = _ADR_ACCEPTED.replace(
            "- Status: Accepted (2026-08-02)", "- Status: Proposed"
        ).replace("Test decision body.", "ROLLED BACK decision body.")
        (work / "docs" / "adr" / "0042-test.md").write_text(rolled_back)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "rollback: accepted -> proposed + body edit"],
            cwd=work, check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "Dario rollback (a): rollback + body edit fires ADR-immutability (MUT2a)",
            rc == 1
            and "Accepted ADRs are immutable" in out
            and "docs/adr/0042-test.md" in out,
        ))

    # Dario rollback (b): rollback + grounding reverted to base bytes.
    # The grounding-freeze row MUST be present (not just exit 1) — an
    # exit-code-only arm (b) would stay green under MUT2b because the
    # ADR-immutability row from the same fixture would still fire to
    # exit 1. Cite MUT2b.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_transition(work)
        rolled_back = _ADR_ACCEPTED.replace(
            "- Status: Accepted (2026-08-02)", "- Status: Proposed"
        )
        (work / "docs" / "adr" / "0042-test.md").write_text(rolled_back)
        # Revert the grounding to its base bytes (A).
        (work / "docs" / "grounding" / "0042-test.md").write_text(_GROUNDING)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "rollback + grounding revert to base A"],
            cwd=work, check=True,
        )
        rc, out = _run_validator(work)
        has_adr_row = (
            "Accepted ADRs are immutable" in out
            and "docs/adr/0042-test.md" in out
        )
        has_grounding_row = (
            "cannot modify grounding for Accepted ADR" in out
            and "docs/grounding/0042-test.md" in out
        )
        results.append(check(
            "Dario rollback (b): rollback + grounding revert fires ADR + grounding rows (MUT2b)",
            rc == 1 and has_adr_row and has_grounding_row,
        ))

    # Dario rollback (c) — revert-control: same grounding revert, ADR
    # left Accepted. The grounding row fires (snapshot is B, head is A)
    # but the ADR row does NOT (HEAD body == snapshot body). The
    # control isolates rollback as the sole variable between (b) and
    # (c). Correct as an exit-1 + grounding-row assertion; the ADR
    # row must be absent to prove the control is doing its job.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_transition(work)
        # Revert the grounding to base bytes (A) — NOT touching the ADR.
        (work / "docs" / "grounding" / "0042-test.md").write_text(_GROUNDING)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "revert-control: grounding revert only"],
            cwd=work, check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "Dario rollback (c): revert-control fires grounding-freeze (no ADR row)",
            rc == 1
            and "cannot modify grounding for Accepted ADR" in out
            and "docs/grounding/0042-test.md" in out
            and "Accepted ADRs are immutable" not in out,
        ))

    # -----------------------------------------------------------------------
    # Directly-Accepted — branch-new ADR added in a single commit with
    # status Accepted. The snapshot selector must find the transition
    # when the transition commit is the only commit in base..HEAD, and
    # the freeze must catch post-acceptance mutations.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "grounding").mkdir(parents=True)
        (work / "docs" / "adr" / "0042-test.md").write_text(_ADR_ACCEPTED)
        (work / "docs" / "grounding" / "0042-test.md").write_text(_GROUNDING)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "directly-Accepted ADR + grounding A"],
            cwd=work, check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "directly-Accepted: branch-new accepted in one commit, no mutation passes",
            rc == 0 and "ADR governance passed" in out,
        ))
        # Mutate the grounding on a follow-up commit and confirm the
        # snapshot at the transition commit catches the mutation. The
        # selector must walk base..HEAD to find the transition even
        # though it is the only commit in the range.
        mutated = _GROUNDING + "\nMUTATED: post-acceptance grounding edit.\n"
        (work / "docs" / "grounding" / "0042-test.md").write_text(mutated)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "mutate frozen grounding post-acceptance"],
            cwd=work, check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "directly-Accepted: post-acceptance grounding mutation fails closed",
            rc == 1
            and "cannot modify grounding for Accepted ADR" in out
            and "docs/grounding/0042-test.md" in out,
        ))

    # -----------------------------------------------------------------------
    # CRLF rows — both unconditional. Both rows are MANDATORY and
    # UNCONDITIONAL: each CRLF row pins a byte-exact successor-7 snapshot
    # comparison site against a text-mode regression. A text-mode read
    # (`text=True`) at either site universal-newline normalises CRLF to
    # LF, making the mutated values text-equal; the byte-exact
    # implementation must reject them. The rows are unconditional rather
    # than conditional on the loader because the two consumers — the
    # grounding snapshot and the ADR snapshot — may diverge later: today
    # `file_at` is the single loader every comparison reads, so the
    # grounding row alone would pin the loader; the ADR row exists for
    # that consumer-specific divergence case, not because both rows
    # individually pin the loader today. Each row has its own mutation:
    #   MUT-grounding — text=True on the grounding read path only.
    #   MUT-ADR       — newline normalisation (e.g. replace b"\r\n" with
    #                   b"\n" on the read bytes) at the ADR comparison
    #                   site :567 only, leaving grounding byte-exact.
    #
    # -----------------------------------------------------------------------
    # CRLF grounding row: grounding frozen at base (Accepted); branch
    # converts the grounding from LF to CRLF. The post-fix byte-exact
    # comparison must detect the change and fire the grounding-freeze row.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_ACCEPTED)
        gr_path = work / "docs" / "grounding" / "0042-test.md"
        content_bytes = gr_path.read_bytes()
        crlf_bytes = content_bytes.replace(b"\n", b"\r\n")
        assert b"\r\n" in crlf_bytes, "fixture must actually introduce CRLF"
        gr_path.write_bytes(crlf_bytes)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "convert grounding LF->CRLF"],
            cwd=work, check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "CRLF grounding row: LF->CRLF conversion of frozen grounding fails closed (MUT-grounding)",
            rc == 1
            and "cannot modify grounding for Accepted ADR" in out
            and "docs/grounding/0042-test.md" in out,
        ))

    # CRLF ADR row: ADR frozen at base (Accepted); branch converts the
    # ADR from LF to CRLF. The post-fix byte-exact comparison at the
    # ADR comparison site must fire the ADR-immutability row.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_ACCEPTED)
        adr_path = work / "docs" / "adr" / "0042-test.md"
        content_bytes = adr_path.read_bytes()
        crlf_bytes = content_bytes.replace(b"\n", b"\r\n")
        assert b"\r\n" in crlf_bytes, "fixture must actually introduce CRLF"
        adr_path.write_bytes(crlf_bytes)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "convert ADR LF->CRLF"],
            cwd=work, check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "CRLF ADR row: LF->CRLF conversion of frozen ADR fails closed (MUT-ADR)",
            rc == 1
            and "Accepted ADRs are immutable" in out
            and "docs/adr/0042-test.md" in out,
        ))

    # -----------------------------------------------------------------------
    # Leading-newline rows (B1/B2) — pinning the successor-7 byte-exact
    # comparison sites against a whitespace-stripping regression. Successor-7
    # introduced these comparisons. Successor-7 reads the historical blob
    # as RAW BYTES via `file_at()` → `subprocess.check_output(
    # ["git","show", <ref>:<path>], stderr=subprocess.PIPE)`: no `run()`,
    # no text mode, no `.strip()` at that historical-blob read. (The
    # `run()` → `check_output(text=True, stderr=DEVNULL).strip()` chain
    # belongs to the predecessor f1d4d8b loader; successor-7's `run()` at
    # scripts/adr-governance.py:57-58 STILL EXISTS and is still
    # `text=True` with `.strip()`, used by `_resolve`, `base_ref`, the
    # three diff sites, the history scans, and the discovery scan. Only
    # `file_at`'s historical-blob read is raw.) `git show <ref>:<path>`
    # returns the blob bytes exactly; the `0x0a` in these fixtures is
    # inserted below into the blob. In the deliberate regression
    # mutation, `.strip()` is applied at the new comparison sites and
    # removes that fixture-added leading LF before comparison, so the
    # byte-exact contract is lost. This is a regression pin, not a claim
    # about a bypass in the pre-successor validator. The measured 52/54
    # disjoint pair is: `.strip()` at both comparison sites leaves only
    # B1/B2 red, while `text=True` at both sites leaves only the CRLF
    # rows red.
    # -----------------------------------------------------------------------
    # B1: leading 0x0a inserted into the grounding after the freeze.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_ACCEPTED)
        gr_path = work / "docs" / "grounding" / "0042-test.md"
        content_bytes = gr_path.read_bytes()
        gr_path.write_bytes(b"\n" + content_bytes)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "insert leading 0x0a into grounding"],
            cwd=work, check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "B1 leading-newline grounding: leading 0x0a in grounding fails closed",
            rc == 1
            and "cannot modify grounding for Accepted ADR" in out
            and "docs/grounding/0042-test.md" in out,
        ))

    # B2: leading 0x0a inserted into the ADR after the freeze.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_base(work, adr_text=_ADR_ACCEPTED)
        adr_path = work / "docs" / "adr" / "0042-test.md"
        content_bytes = adr_path.read_bytes()
        adr_path.write_bytes(b"\n" + content_bytes)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "insert leading 0x0a into ADR"],
            cwd=work, check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "B2 leading-newline ADR: leading 0x0a in ADR fails closed",
            rc == 1
            and "Accepted ADRs are immutable" in out
            and "docs/adr/0042-test.md" in out,
        ))

    # -----------------------------------------------------------------------
    # PATH-shim tests — pin that operational failures of the loader
    # (a fake ``git`` that exits 86 for a specific argument) are typed
    # as operational errors and fail closed, NOT treated as file
    # absence. The pre-fix `file_at` and `_resolve` had a single
    # `subprocess.check_output` call; without a typed distinction
    # between "blob does not exist" and "blob read failed", a failure
    # would silently look like absence and the freeze would not engage.
    # The successor-7 typed error/absence distinction is the property
    # these tests pin.
    # -----------------------------------------------------------------------
    # Blob-read PATH-shim: fail `git show <C1>:docs/adr/0042-test.md`
    # (the transition commit's ADR blob read inside
    # `_frozen_adr_snapshot`). The validator must fail closed and
    # surface the operational error rather than treating the read as
    # absence (which would let the freeze switch off).
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_transition(work)
        c1 = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=work, text=True
        ).strip()
        shim_dir = _setup_path_shim(work, f"{c1}:docs/adr/0042-test.md")
        rc, out = _run_validator_with_shim(work, shim_dir)
        results.append(check(
            "blob-read PATH-shim: fail `git show <C1>:docs/adr/0042-test.md` fails closed (operational error)",
            rc == 1
            and "Failed to scan history" in out
            and "docs/adr/0042-test.md" in out
            and "returned non-zero exit status 86" in out,
        ))

    # Companion: fail `git show <C1>:docs/grounding/0042-test.md` (the
    # transition commit's grounding blob read inside
    # `_frozen_grounding_snapshot`). Same fail-closed contract on the
    # grounding path. The companion pins a second loader site so a
    # regression that only handles the ADR path is caught.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_transition(work)
        c1 = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=work, text=True
        ).strip()
        shim_dir = _setup_path_shim(work, f"{c1}:docs/grounding/0042-test.md")
        rc, out = _run_validator_with_shim(work, shim_dir)
        results.append(check(
            "blob-read PATH-shim companion: fail `git show <C1>:docs/grounding/0042-test.md` fails closed",
            rc == 1
            and "Failed to scan history" in out
            and "docs/grounding/0042-test.md" in out
            and "returned non-zero exit status 86" in out,
        ))

    # PATH-shim discovery-fail: fail `git log --diff-filter=A`
    # (the history-driven added-path discovery scan inside
    # ``main()``). The validator must fail closed and surface a
    # governance error rather than silently treating the discovery
    # scan as empty — an empty discovery would let a branch-new
    # directly-Accepted ADR that was later deleted slip through.
    # Substring match on `--diff-filter=A` covers the exact flag
    # regardless of position.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_transition(work)
        shim_dir = _setup_path_shim_matching(work, "--diff-filter=A")
        rc, out = _run_validator_with_shim(work, shim_dir)
        results.append(check(
            "PATH-shim discovery-fail: fail `git log --diff-filter=A` fails closed",
            rc == 1
            and "Failed to scan history for added ADR/grounding files" in out,
        ))

    # -----------------------------------------------------------------------
    # Net-zero delete-both — base lacks the ADR/grounding pair; branch
    # adds an ADR directly Accepted with grounding, then deletes both
    # before HEAD. Final base-relative diff is empty (net-zero). The
    # history-driven discovery pass (which uses `git log
    # --diff-filter=A`) is the SOLE mechanism that catches the
    # deletions; the supplementary ADR/grounding passes iterate
    # `changed` which is empty. Without this arm a branch-new
    # directly-Accepted ADR that was later deleted would pass
    # undetected.
    #
    # Mutation proof: discarding the successful history-driven
    # discovery result after the real `git log` returns (so
    # `ever_added` is empty for this fixture while preserving the
    # discovery exception path) turns this row red — the validator
    # passes incorrectly — the source path is not in `changed`
    # (the three-dot diff is empty for net-zero), so no ADR or
    # grounding read fires — and the row's expected error message
    # is absent, failing the `rc == 1` / `out` assertions. The
    # row passes only when history-driven discovery is the sole
    # mechanism catching the deletion.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "grounding").mkdir(parents=True)
        (work / "docs" / "adr" / "0042-test.md").write_text(_ADR_ACCEPTED)
        (work / "docs" / "grounding" / "0042-test.md").write_text(_GROUNDING)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "add directly-Accepted ADR + grounding"],
            cwd=work, check=True,
        )
        # Delete both files in a follow-up commit (net-zero diff vs base).
        (work / "docs" / "adr" / "0042-test.md").unlink()
        (work / "docs" / "grounding" / "0042-test.md").unlink()
        subprocess.run(["git", "add", "-A"], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "delete both files (net-zero diff)"],
            cwd=work, check=True,
        )
        # Sanity: HEAD must not contain either file — git won't carry
        # empty directories, so a successful delete commit here proves
        # the deletion actually landed.
        head_files = subprocess.check_output(
            ["git", "ls-tree", "-r", "--name-only", "HEAD"],
            cwd=work, text=True,
        ).strip().splitlines()
        assert "docs/adr/0042-test.md" not in head_files, (
            "fixture invariant: HEAD must not contain the deleted ADR"
        )
        assert "docs/grounding/0042-test.md" not in head_files, (
            "fixture invariant: HEAD must not contain the deleted grounding"
        )
        rc, out = _run_validator(work)
        results.append(check(
            "net-zero delete-both: history-driven discovery catches both deletions",
            rc == 1
            and "Accepted ADRs are immutable and cannot be deleted" in out
            and "docs/adr/0042-test.md" in out
            and "cannot delete grounding for Accepted ADR" in out
            and "docs/grounding/0042-test.md" in out,
        ))

    # -----------------------------------------------------------------------
    # Net-zero rename — base lacks the pair; branch adds an ADR
    # directly Accepted with grounding, then renames both to a new
    # stem before HEAD. `--diff-filter=A` over history surfaces
    # the source paths as adds and `ever_added` collects them.
    # Both freezes (source ADR
    # immutability and source grounding immutability) come from the
    # single history-driven discovery pass: the source paths are
    # absent at both base and HEAD, so they are NOT in `changed`;
    # the only path that surfaces them is `--diff-filter=A` over
    # history, which adds them to `ever_added`. Existing rename
    # and delete tests start with an Accepted ADR at base, so they
    # do not exercise historical added-path discovery.
    #
    # Mutation proof: discarding the successful history-driven
    # discovery result after the real `git log` returns (so
    # `ever_added` is empty for this fixture while preserving the
    # discovery exception path) turns BOTH rows red, failing the
    # dual-row assertion. The row passes only when history-driven
    # discovery is the sole mechanism.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "grounding").mkdir(parents=True)
        (work / "docs" / "adr" / "0042-test.md").write_text(_ADR_ACCEPTED)
        (work / "docs" / "grounding" / "0042-test.md").write_text(_GROUNDING)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "add directly-Accepted ADR + grounding"],
            cwd=work, check=True,
        )
        # Rename both via `git mv`. The source paths/stem are absent at
        # base and HEAD and therefore absent from `changed`; `changed`
        # still contains the two destination paths. Both source freezes
        # come from the single history-driven discovery pass via
        # `--diff-filter=A`: the source paths were added in C1 and enter
        # `ever_added`, so only history-driven discovery surfaces them
        # after the rename.
        subprocess.run(
            ["git", "mv", "docs/adr/0042-test.md", "docs/adr/0043-renamed.md"],
            cwd=work, check=True,
        )
        subprocess.run(
            ["git", "mv", "docs/grounding/0042-test.md", "docs/grounding/0043-renamed.md"],
            cwd=work, check=True,
        )
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "rename both to new stems"],
            cwd=work, check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "net-zero rename: source paths caught by history-driven discovery",
            rc == 1
            and "Accepted ADRs are immutable and cannot be deleted" in out
            and "docs/adr/0042-test.md" in out
            and "cannot delete grounding for Accepted ADR" in out
            and "docs/grounding/0042-test.md" in out,
        ))

    # -----------------------------------------------------------------------
    # Net-zero delete-both with PATH shim forcing `git log
    # --diff-filter=A` to fail (exit 86). The validator must fail
    # closed and surface the "Failed to scan history" error rather
    # than silently treating the discovery scan as empty.
    #
    # Adjacent real-git control: the net-zero delete-both arm above
    # exercises the same fixture WITHOUT the shim. The discriminator
    # is a fail-open wrapper that silently returns `ever_added = []`
    # from the discovery-scan except branch (without appending to
    # `errors`) — under that wrapper this shim row goes green (no
    # scan error) while the real-git net-zero delete-both arm
    # above stays red (the deletion errors come from successful
    # discovery, which the fail-open wrapper does not affect).
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "grounding").mkdir(parents=True)
        (work / "docs" / "adr" / "0042-test.md").write_text(_ADR_ACCEPTED)
        (work / "docs" / "grounding" / "0042-test.md").write_text(_GROUNDING)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "add directly-Accepted ADR + grounding"],
            cwd=work, check=True,
        )
        (work / "docs" / "adr" / "0042-test.md").unlink()
        (work / "docs" / "grounding" / "0042-test.md").unlink()
        subprocess.run(["git", "add", "-A"], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "delete both files (net-zero diff)"],
            cwd=work, check=True,
        )
        shim_dir = _setup_path_shim_matching(work, "--diff-filter=A")
        rc, out = _run_validator_with_shim(work, shim_dir)
        results.append(check(
            "net-zero + discovery-scan PATH-shim: fail `git log --diff-filter=A` fails closed",
            rc == 1
            and "Failed to scan history for added ADR/grounding files" in out,
        ))

    # -----------------------------------------------------------------------
    # Genuine absence control — branch adds an ADR directly Accepted
    # with NO grounding file at any commit. The validator must pass:
    # the "no grounding at snapshot AND no grounding at HEAD" branch
    # in the grounding loop is a legitimate not-a-violation case
    # (ADR predates the grounding convention).
    #
    # Mutation proof: changing that branch to fire an error ("always
    # error when no grounding exists for an Accepted ADR") makes this
    # row red — proving the legitimate-not-a-violation path is
    # specifically being exercised. The previously committed
    # "companion" was a second failing `git show` shim, not this
    # absence control.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        (work / "docs" / "adr").mkdir(parents=True)
        # Note: docs/grounding/ is intentionally NOT created.
        (work / "docs" / "adr" / "0042-test.md").write_text(_ADR_ACCEPTED)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "directly-Accepted ADR, never-existing grounding"],
            cwd=work, check=True,
        )
        # Sanity: HEAD must contain the ADR but no grounding file.
        head_files = subprocess.check_output(
            ["git", "ls-tree", "-r", "--name-only", "HEAD"],
            cwd=work, text=True,
        ).strip().splitlines()
        assert "docs/adr/0042-test.md" in head_files
        assert not any(p.startswith("docs/grounding/") for p in head_files), (
            "fixture invariant: grounding must never exist for this absence control"
        )
        rc, out = _run_validator(work)
        results.append(check(
            "absence control: Accepted ADR with never-existing grounding passes",
            rc == 0 and "ADR governance passed" in out,
        ))

    # -----------------------------------------------------------------------
    # Snapshot-advance blob-read topology — C1 adds an ADR Accepted
    # with grounding A (unchanged from base); C2 changes grounding
    # A→B. The PATH shim fails only
    # `git show <C1>:docs/adr/0042-test.md` (the transition
    # commit's ADR blob read inside `_frozen_adr_snapshot`). The
    # validator must fail closed with a read error rather than
    # silently advancing the snapshot to C2 (which would let the
    # A→B grounding change pass undetected). The previously
    # committed shim row stopped at C1 and so did not pin the false
    # advance to C2.
    #
    # Mutation proof: changing the operational-error handler in
    # `file_at` from `raise` to `return None` makes the shim row
    # below green (snapshot advances to C2 silently, the freeze
    # doesn't engage on the A→B change) while the no-shim A→B run
    # further below remains red (the no-shim path is unaffected by
    # the mutation because `file_at` doesn't raise on it).
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        # C1: ADR Accepted + grounding A (unchanged from base).
        _seed_transition(work, trans_grounding=_GROUNDING)
        # C2: edit grounding A→B (different bytes).
        mutated_grounding = _GROUNDING + "\nB: post-acceptance grounding A->B.\n"
        (work / "docs" / "grounding" / "0042-test.md").write_text(mutated_grounding)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "c2: grounding A->B"],
            cwd=work, check=True,
        )
        c1 = subprocess.check_output(
            ["git", "rev-parse", "HEAD~1"], cwd=work, text=True
        ).strip()
        shim_dir = _setup_path_shim(work, f"{c1}:docs/adr/0042-test.md")
        rc, out = _run_validator_with_shim(work, shim_dir)
        results.append(check(
            "snapshot-advance: shim on C1 ADR read fails closed (no silent advance to C2)",
            rc == 1
            and "Failed to scan history" in out
            and "docs/adr/0042-test.md" in out
            and "returned non-zero exit status 86" in out,
        ))

    # No-shim A→B run — must fire grounding-freeze error (proves the
    # A→B grounding change is detected when the loader works). The
    # companion row is the discriminator anchor: under the
    # `except: return None` mutation in `file_at`, this run stays
    # red while the shimmed run above goes green.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        _seed_transition(work, trans_grounding=_GROUNDING)
        mutated_grounding = _GROUNDING + "\nB: post-acceptance grounding A->B.\n"
        (work / "docs" / "grounding" / "0042-test.md").write_text(mutated_grounding)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "c2: grounding A->B"],
            cwd=work, check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "snapshot-advance no-shim control: A→B grounding change fails closed",
            rc == 1
            and "cannot modify grounding for Accepted ADR" in out
            and "docs/grounding/0042-test.md" in out,
        ))

    # -----------------------------------------------------------------------
    # Directly-Accepted ADR-bytes mutation — branch-new ADR added in
    # one commit with status Accepted, then a follow-up commit edits
    # the ADR body (the grounding is untouched). The
    # ADR-immutability row must fire on the body change.
    #
    # Mutation proof: reverting to base-only `old = file_at(base)`
    # selection — i.e., changing the unconditional ADR loop to use
    # the base bytes instead of the history-driven snapshot — makes
    # THIS row fail (the pre-fix code would skip the freeze entirely
    # because `file_at(base, adr)` returns None for a branch-new
    # ADR). The grounding row stays independent (the grounding is
    # unchanged in this arm, so the grounding freeze doesn't engage
    # either before or after the mutation).
    #
    # The existing directly-Accepted arms above cover the pass case
    # and the grounding mutation case; this row extends the
    # directly-Accepted coverage to the ADR body mutation that the
    # previous suite did not exercise.
    # -----------------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        _init_repo(work)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], cwd=work, check=True)
        (work / "docs" / "adr").mkdir(parents=True)
        (work / "docs" / "grounding").mkdir(parents=True)
        (work / "docs" / "adr" / "0042-test.md").write_text(_ADR_ACCEPTED)
        (work / "docs" / "grounding" / "0042-test.md").write_text(_GROUNDING)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "directly-Accepted ADR + grounding A"],
            cwd=work, check=True,
        )
        # Edit ADR body, keep status Accepted, don't touch grounding.
        mutated = _ADR_ACCEPTED.replace(
            "Test decision body.", "MUTATED decision body."
        )
        (work / "docs" / "adr" / "0042-test.md").write_text(mutated)
        subprocess.run(["git", "add", "."], cwd=work, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "mutate directly-Accepted ADR body"],
            cwd=work, check=True,
        )
        rc, out = _run_validator(work)
        results.append(check(
            "directly-Accepted ADR-bytes: post-acceptance ADR body mutation fails closed",
            rc == 1
            and "Accepted ADRs are immutable" in out
            and "docs/adr/0042-test.md" in out,
        ))

    failed = results.count(False)
    print(f"\n{len(results) - failed}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
