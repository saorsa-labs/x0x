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


def _resolve(candidate: str) -> str | None:
    """Resolve *candidate* to a full 40-hex commit SHA via ``git rev-parse
    --verify``.  Returns ``None`` when the candidate is not a valid commit.
    """
    try:
        return run(["git", "rev-parse", "--verify", f"{candidate}^{{commit}}"])
    except Exception:
        return None


def _is_valid_base(candidate: str | None, head: str) -> bool:
    """True when *candidate* is a non-empty, non-zero, non-HEAD SHA."""
    return (
        candidate is not None
        and bool(candidate)
        and not candidate.startswith(_ZERO_SHA_PREFIX)
        and candidate != head
    )


def base_ref() -> tuple[str | None, str | None, bool]:
    """Return ``(base_sha, error, is_push_event)``.

    *base_sha* is a resolved non-HEAD commit SHA to diff against, or ``None``.
    *error* is a fail-closed message when an explicitly supplied event
    selector could not resolve to a valid non-HEAD commit.  *is_push_event*
    is ``True`` when the base came from ``GITHUB_BEFORE`` (a push event),
    indicating the caller should use a direct two-dot diff instead of the
    three-dot merge-base diff used for PRs.

    When any event selector (``GITHUB_BASE_REF``, ``GITHUB_BASE_SHA``,
    ``GITHUB_BEFORE``) is explicitly provided, every candidate is resolved
    through ``git rev-parse --verify`` and the resolved SHA is compared to
    HEAD.  If none resolves to a valid non-HEAD commit, *error* is set and
    the caller must fail closed — local fallbacks are not used.

    When no event selector is provided, local fallbacks (``merge-base``,
    ``HEAD^1``) are used as before.
    """
    try:
        head = run(["git", "rev-parse", "HEAD"])
    except Exception:
        return (None, None, False)

    # Track whether any event selector was explicitly provided.
    has_event_selector = False
    resolved_base: str | None = None
    is_push = False

    ref = os.environ.get("GITHUB_BASE_REF")
    if ref:
        has_event_selector = True
        resolved = _resolve(f"origin/{ref}")
        if _is_valid_base(resolved, head):
            resolved_base = resolved

    if resolved_base is None:
        base_sha = os.environ.get("GITHUB_BASE_SHA")
        if base_sha:
            has_event_selector = True
            resolved = _resolve(base_sha)
            if _is_valid_base(resolved, head):
                resolved_base = resolved

    if resolved_base is None:
        before = os.environ.get("GITHUB_BEFORE")
        if before:
            has_event_selector = True
            resolved = _resolve(before)
            if _is_valid_base(resolved, head):
                resolved_base = resolved
                is_push = True

    if resolved_base is not None:
        return (resolved_base, None, is_push)

    if has_event_selector:
        # An event selector was explicitly provided but none resolved to a
        # valid non-HEAD commit.  Fail closed instead of falling to local
        # heuristics.
        attempted: list[str] = []
        if ref:
            attempted.append(f"GITHUB_BASE_REF={ref}")
        base_sha = os.environ.get("GITHUB_BASE_SHA")
        if base_sha:
            attempted.append(f"GITHUB_BASE_SHA={base_sha}")
        before = os.environ.get("GITHUB_BEFORE")
        if before:
            attempted.append(f"GITHUB_BEFORE={before}")
        return (
            None,
            f"Event base selector(s) could not resolve to a valid non-HEAD "
            f"commit: {'; '.join(attempted)}. "
            f"Change-specific structural and immutability checks cannot run.",
            False,
        )

    # No event selector: use local fallbacks.
    for default in ("main", "master", "origin/main", "origin/master"):
        try:
            mb = run(["git", "merge-base", default, "HEAD"])
            if _is_valid_base(mb, head):
                return (mb, None, False)
        except Exception:
            continue

    try:
        parent = run(["git", "rev-parse", "HEAD^1"])
        if _is_valid_base(parent, head):
            return (parent, None, False)
    except Exception:
        pass

    return (None, None, False)


def changed_files_against_base(base: str, is_push: bool = False) -> list[str] | None:
    """Return changed file paths relative to *base*, or ``None`` when the
    base cannot be resolved (fail-closed signal so the caller can reject
    rather than silently treating a broken diff as an empty change set).

    For push events (*is_push* is ``True``), use a direct two-dot diff
    (``git diff <base> HEAD``) to capture every file changed between the
    old and new tips, including deletions on divergent history.

    For PR events, use a three-dot merge-base diff
    (``git diff <base>...HEAD``) to capture only the branch's own changes,
    falling back to two-dot if three-dot fails.
    """
    if is_push:
        try:
            return run(["git", "diff", "--no-renames", "--name-only", f"{base}", "HEAD"]).splitlines()
        except Exception:
            return None
    try:
        return run(["git", "diff", "--no-renames", "--name-only", f"{base}...HEAD"]).splitlines()
    except Exception:
        try:
            return run(["git", "diff", "--no-renames", "--name-only", f"{base}", "HEAD"]).splitlines()
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
    # Do NOT early-return when docs/adr/ is absent.  If the directory was
    # deleted in this change, the base/change analysis below must still run
    # so Accepted-ADR immutability and grounding freeze are enforced on
    # the deleted paths.  Fall through with an empty ADR set instead.

    # Every markdown file in docs/adr/ must either be a known support file or
    # follow the NNNN-short-title.md convention. This catches misnamed new
    # ADRs that would otherwise dodge validation entirely.
    adr_files: list[Path] = []
    if ADR_DIR.exists():
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

    base, base_error, is_push = base_ref()
    if base_error:
        errors.append(base_error)
        changed = []
    elif base:
        changed = changed_files_against_base(base, is_push)
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

    n_structurally_validated = 0
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
            n_structurally_validated += 1
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
    parts = [f"{n_discovered} ADR file(s) discovered"]
    if n_structurally_validated > 0:
        parts.append(f"{n_structurally_validated} ADR(s) structurally validated")
    if grounding_files:
        parts.append(f"{len(grounding_files)} grounding file(s) paired")
    print(f"ADR governance passed ({', '.join(parts)}).")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
