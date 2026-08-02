#!/usr/bin/env python3
"""Repository-local ADR governance checks.

Enforces:
- ADR files live under docs/adr/ and use NNNN-short-title.md (the established
  convention in this repository, e.g. 0001-bootstrap-peers-are-seed-hints-only.md).
- Required template sections exist on ADRs added by the change (pre-existing
  ADRs keep their original structure).  Section headings must match exactly:
  ``## Validation`` satisfies the requirement but ``## Validation Notes`` does
  not.
- Status is present and starts with an allowed lifecycle value. Annotations
  after the status are fine, e.g. "Accepted (2026-06-07). Follow-up in ...".
- Accepted ADRs are immutable after acceptance. If a decision changes, create a
  new ADR and supersede by reference rather than editing the Accepted ADR.
- Same-stem grounding files in docs/grounding/ are paired with their ADR by
  NNNN-short-title stem.  Grounding for an Accepted ADR is frozen: mutation and
  deletion both fail closed.  Grounding for a Proposed ADR remains amendable.
- The branch/PR base selector ensures a branch-new ADR is treated as ``is_new``
  across amendment commits, so structural checks always run on the final state.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ADR_DIR = Path("docs/adr")
GROUNDING_DIR = Path("docs/grounding")
ALLOWED_STATUSES = {"Proposed", "Accepted", "Superseded", "Deprecated", "Rejected"}
REQUIRED_SECTIONS = ["Context", "Decision", "Consequences", "Validation"]
FILENAME_RE = re.compile(r"^\d{4}-[a-z0-9][a-z0-9-]*\.md$")
ADR_PATH_RE = re.compile(r"^docs/adr/\d{4}-[a-z0-9][a-z0-9-]*\.md$")
GROUNDING_PATH_RE = re.compile(r"^docs/grounding/\d{4}-[a-z0-9][a-z0-9-]*\.md$")
# Existing ADRs use two status styles: a header bullet ("- Status: ...",
# "- **Status:** ...") or a "## Status" section with the value on the next line.
STATUS_BULLET_RE = re.compile(r"(?im)^\s*[-*]\s*\*{0,2}Status:?\*{0,2}:?\s*(.+?)\s*$")
STATUS_SECTION_RE = re.compile(r"(?im)^##\s+Status[ \t]*\n(?:[ \t]*\n)*[ \t]*(.+?)[ \t]*$")
NON_ADR_FILES = {"README.md", "TEMPLATE.md", "TOOLING.md"}


def run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()


def status_of(text: str) -> str | None:
    m = STATUS_BULLET_RE.search(text) or STATUS_SECTION_RE.search(text)
    return m.group(1).strip().strip("*").strip() if m else None


def status_token(status: str) -> str:
    """Leading lifecycle word of a status line, e.g. 'Accepted' from
    'Accepted (2026-06-07). The roster-removal half ships in PR #99'."""
    return status.split()[0].strip("*").rstrip(".,;:") if status.split() else status


def has_section(text: str, section: str) -> bool:
    """True when ``## {section}`` appears as an exact ATX heading.

    The match is exact: ``## Validation`` satisfies the ``Validation``
    requirement but ``## Validation Notes`` does not, because a heading
    with extra words is a different section.  Trailing whitespace on the
    heading line is tolerated.
    """
    return re.search(rf"(?im)^##\s+{re.escape(section)}[ \t]*$", text) is not None


def non_heading_lines(text: str) -> list[str]:
    """Body lines, excluding markdown ATX headings. Used to prove an edit
    touched only headings and left the decision content untouched."""
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def is_template_repair(old: str, new: str) -> bool:
    """True when the only change to an Accepted ADR is editing headings to
    restore previously-missing required template sections.

    This narrowly permits fixing a mistitled heading on an already-Accepted
    ADR (e.g. renaming '## Acceptance criteria' to the required
    '## Validation') without a force-push or a superseding ADR. It is a
    template-conformance repair, not a decision change, so it does not
    violate the spirit of immutability. The gate is deliberately tight:

    - the base version must have been missing at least one required section,
    - the new version must contain every required section, and
    - every non-heading line must be byte-for-byte identical.

    Any edit that touches body content (adding a new section with new prose,
    rewording the decision, etc.) fails the last condition and falls through
    to the immutability error, where it belongs.
    """
    missing_before = [s for s in REQUIRED_SECTIONS if not has_section(old, s)]
    if not missing_before:
        return False
    if any(not has_section(new, s) for s in REQUIRED_SECTIONS):
        return False
    return non_heading_lines(old) == non_heading_lines(new)


_ZERO_SHA_PREFIX = "0000000"


def _is_valid_base(candidate: str, head: str) -> bool:
    """True when *candidate* is a non-empty, non-zero, non-HEAD SHA."""
    return (
        bool(candidate)
        and not candidate.startswith(_ZERO_SHA_PREFIX)
        and candidate != head
    )


def base_ref() -> str | None:
    """Return the ref to diff against for ``is_new`` and immutability checks.

    Every candidate is validated against HEAD: a base that equals HEAD
    always yields an empty diff, so it is rejected and the next selector
    is tried.  This prevents a push-to-main regression where
    ``merge-base main HEAD`` resolves to HEAD itself.

    Resolution order:

    1. ``GITHUB_BASE_REF`` — set on pull requests, points at the target
       branch.  ``origin/{ref}`` captures every commit on the PR branch,
       so a new ADR added in an early commit and amended later is always
       treated as ``is_new``.
    2. ``GITHUB_BASE_SHA`` — the exact PR base SHA, supplied by the
       workflow from ``github.event.pull_request.base.sha``.
    3. ``GITHUB_BEFORE`` — the previous branch tip on push events,
       supplied by the workflow from ``github.event.before``.  An
       all-zero SHA (branch creation / force-push) is rejected.
    4. ``git merge-base <default> HEAD`` — for local runs, find the
       fork point from ``main`` or ``master`` so the entire branch is
       covered, not just the last commit.
    5. ``HEAD^1`` — last resort, correct only for single-commit changes.
    """
    try:
        head = run(["git", "rev-parse", "HEAD"])
    except Exception:
        return None

    ref = os.environ.get("GITHUB_BASE_REF")
    if ref:
        try:
            resolved = run(["git", "rev-parse", f"origin/{ref}"])
            if _is_valid_base(resolved, head):
                return resolved
        except Exception:
            pass

    base_sha = os.environ.get("GITHUB_BASE_SHA")
    if base_sha and _is_valid_base(base_sha, head):
        return base_sha

    before = os.environ.get("GITHUB_BEFORE")
    if before and _is_valid_base(before, head):
        return before

    for default in ("main", "master", "origin/main", "origin/master"):
        try:
            mb = run(["git", "merge-base", default, "HEAD"])
            if _is_valid_base(mb, head):
                return mb
        except Exception:
            continue

    try:
        parent = run(["git", "rev-parse", "HEAD^1"])
        if _is_valid_base(parent, head):
            return parent
    except Exception:
        pass

    return None


def changed_files_against_base(base: str) -> list[str] | None:
    """Return changed file paths relative to *base*, or ``None`` when the
    base cannot be resolved (fail-closed signal so the caller can reject
    rather than silently treating a broken diff as an empty change set).
    """
    try:
        return run(["git", "diff", "--name-only", f"{base}...HEAD"]).splitlines()
    except Exception:
        try:
            return run(["git", "diff", "--name-only", f"{base}", "HEAD"]).splitlines()
        except Exception:
            return None


def file_at(ref: str, path: str) -> str | None:
    try:
        return run(["git", "show", f"{ref}:{path}"])
    except Exception:
        return None


def adr_status_for_grounding(grounding_name: str, ref: str = "HEAD") -> str | None:
    """Return the lifecycle status token of the same-stem ADR for a
    grounding file path, or ``None`` when no paired ADR exists.

    ``grounding_name`` is a repo-relative path like
    ``docs/grounding/0028-foo.md``.  The same-stem ADR is
    ``docs/adr/0028-foo.md``.
    """
    stem = Path(grounding_name).stem
    adr_path = f"docs/adr/{stem}.md"
    text = file_at(ref, adr_path)
    if text is None:
        return None
    st = status_of(text)
    return status_token(st) if st else None


def main() -> int:
    errors: list[str] = []
    if not ADR_DIR.exists():
        print("No docs/adr directory; nothing to validate.")
        return 0

    # Every markdown file in docs/adr/ must either be a known support file or
    # follow the NNNN-short-title.md convention. This catches misnamed new
    # ADRs that would otherwise dodge validation entirely.
    adr_files: list[Path] = []
    for path in sorted(ADR_DIR.glob("*.md")):
        if path.name in NON_ADR_FILES:
            continue
        if not FILENAME_RE.match(path.name):
            errors.append(f"{path}: filename must match NNNN-short-title.md")
            continue
        adr_files.append(path)

    # Collect same-stem grounding files from docs/grounding/.  Each grounding
    # file must pair with a same-stem ADR; the ADR's lifecycle status
    # determines whether the grounding is amendable (Proposed) or frozen
    # (Accepted).
    grounding_files: list[Path] = []
    if GROUNDING_DIR.exists():
        for path in sorted(GROUNDING_DIR.glob("*.md")):
            if not FILENAME_RE.match(path.name):
                errors.append(f"{path}: filename must match NNNN-short-title.md")
                continue
            stem = path.stem
            adr_path = ADR_DIR / f"{stem}.md"
            if not adr_path.exists():
                errors.append(f"{path}: grounding file has no same-stem ADR {adr_path.as_posix()}")
                continue
            grounding_files.append(path)

    base = base_ref()
    if base:
        changed = changed_files_against_base(base)
        if changed is None:
            errors.append(
                f"Cannot resolve base ref '{base}'. "
                f"Change-specific structural and immutability checks cannot run."
            )
            changed = []
    else:
        changed = []
    changed_adr_paths = {Path(name) for name in changed if ADR_PATH_RE.match(name)}

    # Grandfather legacy ADRs when first installing governance. Enforce full
    # structure on ADRs touched by this PR, while still checking duplicate
    # numbers across the full directory.
    files_to_validate = sorted((p for p in changed_adr_paths if p.exists()), key=str) if base else adr_files

    seen_numbers: dict[str, Path] = {}
    for path in adr_files:
        number = path.name.split("-", 1)[0]
        if number in seen_numbers:
            errors.append(f"{path}: duplicate ADR number also used by {seen_numbers[number]}")
        seen_numbers[number] = path

    for path in files_to_validate:
        text = path.read_text(encoding="utf-8")
        st = status_of(text)
        if not st:
            errors.append(f"{path}: missing Status")
        elif status_token(st) not in ALLOWED_STATUSES:
            errors.append(
                f"{path}: invalid Status '{st}' (must start with one of: {', '.join(sorted(ALLOWED_STATUSES))})"
            )
        # Full template structure is required for ADRs new in this change.
        # Edited pre-existing ADRs keep their original structure (the
        # immutability check below still guards Accepted ones).
        is_new = base is not None and file_at(base, path.as_posix()) is None
        if is_new:
            for section in REQUIRED_SECTIONS:
                if not has_section(text, section):
                    errors.append(f"{path}: missing required section '## {section}'")

    if base:
        for name in changed:
            if not ADR_PATH_RE.match(name):
                continue
            old = file_at(base, name)
            if old is None:
                continue
            old_status = status_of(old)
            if old_status and status_token(old_status) == "Accepted":
                new = file_at("HEAD", name)
                if new is not None and is_template_repair(old, new):
                    # Heading-only repair restoring a missing required
                    # section; allowed without superseding. See is_template_repair.
                    continue
                errors.append(
                    f"{name}: Accepted ADRs are immutable. Create a new superseding ADR instead of editing this file."
                )

        # Grounding file protection: a grounding file paired with an Accepted
        # ADR is frozen — mutation and deletion both fail closed.  Grounding
        # for a Proposed ADR remains amendable.
        for name in changed:
            if not GROUNDING_PATH_RE.match(name):
                continue
            adr_status = adr_status_for_grounding(name, "HEAD")
            if adr_status is None:
                # ADR might have been deleted in this change; check the base.
                adr_status = adr_status_for_grounding(name, base)
            if adr_status != "Accepted":
                continue
            new_grounding = file_at("HEAD", name)
            if new_grounding is None:
                errors.append(
                    f"{name}: cannot delete grounding for Accepted ADR "
                    f"docs/adr/{Path(name).stem}.md. "
                    f"Grounding files freeze with ADR acceptance."
                )
            else:
                errors.append(
                    f"{name}: cannot modify grounding for Accepted ADR "
                    f"docs/adr/{Path(name).stem}.md. "
                    f"Grounding files freeze with ADR acceptance."
                )

    if errors:
        print("ADR governance failed:")
        for e in errors:
            print(f"- {e}")
        return 1
    n_discovered = len(adr_files)
    n_validated = len(files_to_validate)
    parts = [f"{n_discovered} ADR file(s) discovered"]
    if n_validated != n_discovered:
        parts.append(f"{n_validated} ADR(s) structurally validated")
    if grounding_files:
        parts.append(f"{len(grounding_files)} grounding file(s) paired")
    print(f"ADR governance passed ({', '.join(parts)}).")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
