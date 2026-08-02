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
- Accepted ADRs are immutable after acceptance. The first commit in the
  compared history (base..HEAD) where an ADR becomes Accepted establishes
  the frozen ADR bytes as well as its grounding snapshot. At every later
  HEAD, the ADR must remain byte-identical to that snapshot; body edits,
  status rollback (Accepted→Proposed), deletion, and rename fail closed —
  even when the PR base predates the ADR entirely. If a decision changes,
  create a new ADR and supersede by reference rather than editing the
  Accepted ADR.
- Same-stem grounding files in docs/grounding/ are paired with their ADR by
  NNNN-short-title stem.  Grounding freezes at the first commit in the compared
  history (base..HEAD) where the paired ADR is Accepted, or at the base if the
  ADR is already Accepted there.  The frozen snapshot includes any grounding
  amendment made in the transition commit.  After freezing, mutation, deletion,
  rename, and first-time addition all fail closed — even when the PR base
  predates the ADR entirely.  Grounding for a Proposed ADR remains amendable.
- The branch/PR base selector ensures a branch-new ADR is treated as ``is_new``
  across amendment commits, so structural checks always run on the final state.
- The helper ``is_template_repair`` operates on ``str``.  Byte-level comparison
  of snapshot/HEAD happens in the caller; the helper is only consulted on a
  byte difference.  Decoding is strict UTF-8 — a non-UTF-8 ADR file surfaces
  as a governance error rather than silently changing the lifecycle predicate.
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

    Operates on already-decoded ``str`` copies; the caller is responsible
    for byte-exact comparison of snapshot/HEAD first and only invoking this
    helper on a confirmed byte difference.  Strict UTF-8 decoding at the
    call site ensures a non-UTF-8 ADR surfaces as a governance error
    rather than silently changing the lifecycle predicate.

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


def file_at(ref: str, path: str) -> bytes | None:
    """Return the exact raw blob bytes of *path* at *ref*, or ``None``
    when the path does not exist at that ref.

    Uses ``subprocess.check_output`` without ``text=True`` so that
    universal-newline translation does NOT normalise CRLF to LF.
    The immutability and grounding-freeze comparisons are byte-exact.

    Raises on operational failures (e.g. a PATH shim that fails the
    ``git show`` command) so the caller can surface a governance error
    rather than silently treating the read as file absence.  Only a
    genuine git "path does not exist" result maps to ``None``.
    """
    try:
        return subprocess.check_output(
            ["git", "show", f"{ref}:{path}"],
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr or b""
        # Strict UTF-8 decode: if the error message is not valid UTF-8 we
        # cannot run the absence check, so fall through to re-raise as an
        # operational error.  This avoids silently masking a real failure
        # as file absence.
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8")
        # Git has two distinct messages for "path absent at this ref":
        #   "path '...' does not exist in '...'"
        #   "path '...' exists on disk, but not in '...'"
        # Both are legitimate absence — return None so callers treat
        # the file as not present at that ref.
        if "does not exist" in stderr or "exists on disk, but not in" in stderr:
            return None
        raise


def file_at_text(ref: str, path: str) -> str | None:
    """Like :func:`file_at` but returns a decoded ``str``.

    Decoding is strict UTF-8 — a non-UTF-8 file raises
    :class:`UnicodeDecodeError` so the caller can surface it as a
    governance error rather than silently changing a downstream
    predicate via replacement characters.  Use this only where text
    parsing (status, section headings) is needed; byte comparisons
    must use :func:`file_at` directly.
    """
    raw = file_at(ref, path)
    if raw is None:
        return None
    return raw.decode("utf-8")


def adr_status_for_grounding(grounding_name: str, ref: str = "HEAD") -> str | None:
    """Return the lifecycle status token of the same-stem ADR for a
    grounding file path, or ``None`` when no paired ADR exists.

    ``grounding_name`` is a repo-relative path like
    ``docs/grounding/0028-foo.md``.  The same-stem ADR is
    ``docs/adr/0028-foo.md``.
    """
    stem = Path(grounding_name).stem
    adr_path = f"docs/adr/{stem}.md"
    text = file_at_text(ref, adr_path)
    if text is None:
        return None
    st = status_of(text)
    return status_token(st) if st else None


def _frozen_grounding_snapshot(
    grounding_name: str, base: str
) -> tuple[str | None, bytes | None, str | None]:
    """Return ``(snapshot_commit, snapshot_text, error)`` for the frozen
    grounding.

    The frozen snapshot is the grounding content at the first commit in the
    compared history (base..HEAD) where the paired ADR is Accepted, or at
    *base* if the ADR is already Accepted there.  The snapshot includes any
    grounding amendment made in the transition commit itself.

    Returns ``(None, None, None)`` when the ADR is never Accepted in the
    compared history (grounding remains amendable).  *snapshot_text* may be
    ``None`` when the grounding file did not exist at the snapshot commit
    (first-time grounding addition after acceptance must fail closed).

    *error* is set when the history scan, a blob read, or the strict
    UTF-8 decode of the paired ADR's status text fails (e.g. ``git log``
    raises, a ``git show`` for the snapshot blob is forced to fail by a
    PATH shim, or the ADR file is not valid UTF-8) so the caller can
    report a governance error rather than silently treating the grounding
    as amendable or advancing to a later, already-mutated snapshot.
    """
    try:
        # Fast path: ADR is already Accepted at the comparison base.
        if adr_status_for_grounding(grounding_name, base) == "Accepted":
            return (base, file_at(base, grounding_name), None)

        # Walk base..HEAD in chronological order to locate the transition.
        commits = run(
            ["git", "log", "--reverse", "--format=%H", f"{base}..HEAD"]
        ).splitlines()

        for commit in commits:
            if adr_status_for_grounding(grounding_name, commit) == "Accepted":
                return (commit, file_at(commit, grounding_name), None)

        return (None, None, None)
    except Exception as exc:
        return (None, None, f"Failed to scan history for {grounding_name}: {exc}")


def _frozen_adr_snapshot(
    adr_name: str, base: str
) -> tuple[str | None, bytes | None, str | None]:
    """Return ``(snapshot_commit, snapshot_text, error)`` for the frozen
    ADR bytes.

    The frozen snapshot is the ADR content at the first commit in the
    compared history (base..HEAD) where the ADR is Accepted, or at *base*
    if the ADR is already Accepted there.  The snapshot includes any body
    or status change made in the transition commit itself.

    Returns ``(None, None, None)`` when the ADR is never Accepted in the
    compared history (amendable).  *error* is set when the history scan,
    a blob read, or the strict UTF-8 decode of the status text fails
    (e.g. ``git log`` raises, a ``git show`` for the snapshot blob is
    forced to fail by a PATH shim, or the ADR file is not valid UTF-8)
    so the caller can report a governance error rather than silently
    treating the ADR as amendable or advancing to a later,
    already-mutated snapshot.
    """
    try:
        # Fast path: ADR is already Accepted at the comparison base.
        adr_bytes = file_at(base, adr_name)
        if adr_bytes is not None:
            try:
                adr_text = adr_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                return (
                    None,
                    None,
                    f"Failed to scan history for {adr_name}: not valid UTF-8 ({exc})",
                )
            st = status_of(adr_text)
            if st and status_token(st) == "Accepted":
                return (base, adr_bytes, None)

        # Walk base..HEAD in chronological order to locate the transition.
        commits = run(
            ["git", "log", "--reverse", "--format=%H", f"{base}..HEAD"]
        ).splitlines()

        for commit in commits:
            raw = file_at(commit, adr_name)
            if raw is not None:
                try:
                    raw_text = raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    return (
                        None,
                        None,
                        f"Failed to scan history for {adr_name}: not valid UTF-8 ({exc})",
                    )
                st = status_of(raw_text)
                if st and status_token(st) == "Accepted":
                    return (commit, raw, None)

        return (None, None, None)
    except Exception as exc:
        return (None, None, f"Failed to scan history for {adr_name}: {exc}")


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
        try:
            is_new = base is not None and file_at(base, path.as_posix()) is None
        except Exception as exc:
            errors.append(f"Failed to read {path.as_posix()} at base {base}: {exc}")
            continue
        if is_new:
            n_structurally_validated += 1
            for section in REQUIRED_SECTIONS:
                if not has_section(text, section):
                    errors.append(f"{path}: missing required section '## {section}'")

    if base:
        # Accepted-ADR immutability: for every ADR at HEAD, derive the frozen
        # ADR snapshot (first Accepted commit in base..HEAD, or base if
        # already Accepted there).  HEAD must be byte-identical to the
        # frozen snapshot.  Body edits, status rollback (Accepted→Proposed),
        # deletion, and rename all fail closed — even when the PR base
        # predates the ADR entirely.  The legitimate Proposed→Accepted
        # commit passes because it creates the snapshot.
        #
        # The check is unconditional: for every ADR at HEAD, derive its
        # frozen snapshot and compare HEAD directly to that snapshot
        # regardless of membership in `changed`.  The old base-relative
        # lookup (`old = file_at(base, name)`) missed ADRs that transitioned
        # to Accepted within the branch, because the base predates the ADR
        # and `file_at(base, name)` returns None.
        for adr_path in adr_files:
            adr_name = adr_path.as_posix()
            snapshot_commit, snapshot_text, snap_error = _frozen_adr_snapshot(
                adr_name, base
            )
            if snap_error is not None:
                errors.append(snap_error)
                continue
            if snapshot_commit is None:
                # ADR is never Accepted in the compared history → amendable.
                continue
            try:
                head_text = file_at("HEAD", adr_name)
            except Exception as exc:
                errors.append(f"Failed to read {adr_name} at HEAD: {exc}")
                continue
            if head_text is None:
                # ADR exists on disk but not at HEAD?  Should not happen for
                # files in adr_files, but fail closed if it does.
                errors.append(
                    f"{adr_name}: Accepted ADRs are immutable and cannot be deleted. "
                    f"Create a new superseding ADR instead."
                )
                continue
            if head_text != snapshot_text:
                # Byte diff: decode strict UTF-8 copies and let
                # ``is_template_repair`` adjudicate.  A decode failure here
                # is itself a governance violation: a non-UTF-8 ADR file
                # cannot be evaluated against the lifecycle predicate, so
                # surface the failure and skip the template-repair check.
                try:
                    snapshot_text_str = snapshot_text.decode("utf-8")
                    head_text_str = head_text.decode("utf-8")
                except UnicodeDecodeError as exc:
                    errors.append(
                        f"{adr_name}: Accepted ADR is not valid UTF-8 ({exc}). "
                        f"Accepted ADRs are immutable and cannot be edited."
                    )
                    continue
                if is_template_repair(snapshot_text_str, head_text_str):
                    # Heading-only repair restoring a missing required
                    # section; allowed without superseding.
                    continue
                errors.append(
                    f"{adr_name}: Accepted ADRs are immutable. "
                    f"Create a new superseding ADR instead of editing this file."
                )

        # Supplementary pass: catch ADRs that were Accepted at some point in
        # the compared history but are deleted at HEAD (absent from
        # `adr_files`).  These appear in `changed` as deleted ADR paths.
        checked_adr_stems = {p.stem for p in adr_files}
        for name in changed:
            if not ADR_PATH_RE.match(name):
                continue
            if Path(name).stem in checked_adr_stems:
                continue  # ADR exists at HEAD, already checked above
            snapshot_commit, _snapshot_text, snap_error = _frozen_adr_snapshot(
                name, base
            )
            if snap_error is not None:
                errors.append(snap_error)
                continue
            if snapshot_commit is None:
                continue  # Never Accepted, no immutability violation
            errors.append(
                f"{name}: Accepted ADRs are immutable and cannot be deleted. "
                f"Create a new superseding ADR instead."
            )

        # Grounding file protection: freeze grounding at the first commit in
        # the compared history (base..HEAD) where the paired ADR is Accepted,
        # or at the base if the ADR is already Accepted there.  The frozen
        # snapshot includes any grounding amendment made in the transition
        # commit.  After freezing, mutation, deletion, rename, and first-time
        # addition all fail closed — even when the PR base predates the ADR
        # entirely.  Grounding for a Proposed ADR remains amendable.
        #
        # The check is driven from the history scan, not from HEAD status:
        # for every ADR at HEAD (regardless of its current status), derive
        # its same-stem grounding path and frozen snapshot.  If the ADR was
        # Accepted at any commit in base..HEAD (or at base), the grounding is
        # frozen and HEAD must match the snapshot.  This catches status
        # rollback (Accepted→Proposed): the ADR is still in the frozen set
        # because it was Accepted in history, even though it is Proposed at
        # HEAD.  Membership in `changed` (which is relative to the comparison
        # base, not the acceptance snapshot) must NOT be the selector.
        for adr_path in adr_files:
            stem = adr_path.stem
            gname = f"docs/grounding/{stem}.md"
            snapshot_commit, snapshot_text, snap_error = _frozen_grounding_snapshot(gname, base)
            if snap_error is not None:
                errors.append(snap_error)
                continue
            if snapshot_commit is None:
                # ADR is never Accepted in the compared history → amendable.
                continue
            try:
                head_grounding = file_at("HEAD", gname)
            except Exception as exc:
                errors.append(f"Failed to read {gname} at HEAD: {exc}")
                continue
            adr_ref = f"docs/adr/{stem}.md"
            if snapshot_text is None and head_grounding is None:
                # No grounding existed at the snapshot and none exists now —
                # the ADR predates the grounding convention.  Not a violation.
                continue
            elif head_grounding is None:
                errors.append(
                    f"{gname}: cannot delete grounding for Accepted ADR "
                    f"{adr_ref}. "
                    f"Grounding files freeze with ADR acceptance."
                )
            elif snapshot_text is None:
                # Grounding did not exist at the acceptance commit but exists
                # at HEAD — first-time addition after acceptance.
                errors.append(
                    f"{gname}: cannot add grounding for Accepted ADR "
                    f"{adr_ref} after acceptance. "
                    f"Grounding files freeze with ADR acceptance."
                )
            elif head_grounding != snapshot_text:
                errors.append(
                    f"{gname}: cannot modify grounding for Accepted ADR "
                    f"{adr_ref}. "
                    f"Grounding files freeze with ADR acceptance."
                )

        # Supplementary pass: catch grounding files for ADRs that were
        # Accepted at the base but deleted at HEAD (so they are absent from
        # `adr_files` and the unconditional loop above misses them).  These
        # appear in `changed` as deleted grounding paths.
        checked_stems = {p.stem for p in adr_files}
        for name in changed:
            if not GROUNDING_PATH_RE.match(name):
                continue
            if Path(name).stem in checked_stems:
                continue
            snapshot_commit, snapshot_text, snap_error = _frozen_grounding_snapshot(name, base)
            if snap_error is not None:
                errors.append(snap_error)
                continue
            if snapshot_commit is None:
                continue
            try:
                head_grounding = file_at("HEAD", name)
            except Exception as exc:
                errors.append(f"Failed to read {name} at HEAD: {exc}")
                continue
            adr_ref = f"docs/adr/{Path(name).stem}.md"
            if snapshot_text is None and head_grounding is None:
                continue
            elif head_grounding is None and snapshot_text is not None:
                errors.append(
                    f"{name}: cannot delete grounding for Accepted ADR "
                    f"{adr_ref}. "
                    f"Grounding files freeze with ADR acceptance."
                )
            elif head_grounding is not None and snapshot_text is None:
                errors.append(
                    f"{name}: cannot add grounding for Accepted ADR "
                    f"{adr_ref} after acceptance. "
                    f"Grounding files freeze with ADR acceptance."
                )
            elif head_grounding is not None and snapshot_text is not None and head_grounding != snapshot_text:
                errors.append(
                    f"{name}: cannot modify grounding for Accepted ADR "
                    f"{adr_ref}. "
                    f"Grounding files freeze with ADR acceptance."
                )

        # History-driven discovery pass: catch ADRs and groundings that were
        # ever added in base..HEAD (and thus may have been Accepted) but are
        # absent from both `adr_files` (not at HEAD) and `changed` (net-zero:
        # added and deleted within the branch produces no net diff entry).
        # Without this pass, a branch-new directly-Accepted ADR that is later
        # deleted passes undetected.  `git log --diff-filter=A` finds every
        # file added in any commit in the range, regardless of later deletion.
        all_checked_stems = {p.stem for p in adr_files}
        # Also include stems already checked via the changed-based passes
        for name in changed:
            if ADR_PATH_RE.match(name) or GROUNDING_PATH_RE.match(name):
                all_checked_stems.add(Path(name).stem)

        try:
            ever_added = run([
                "git", "log", "--no-renames", "--diff-filter=A",
                "--name-only", "--format=", f"{base}..HEAD"
            ]).splitlines()
        except Exception as exc:
            errors.append(
                f"Failed to scan history for added ADR/grounding files: {exc}"
            )
            ever_added = []

        for name in ever_added:
            if ADR_PATH_RE.match(name):
                if Path(name).stem in all_checked_stems:
                    continue  # Already checked above
                snapshot_commit, _snapshot_text, snap_error = _frozen_adr_snapshot(
                    name, base
                )
                if snap_error is not None:
                    errors.append(snap_error)
                    continue
                if snapshot_commit is None:
                    continue  # Never Accepted
                errors.append(
                    f"{name}: Accepted ADRs are immutable and cannot be deleted. "
                    f"Create a new superseding ADR instead."
                )
            elif GROUNDING_PATH_RE.match(name):
                if Path(name).stem in all_checked_stems:
                    continue  # Already checked above
                snapshot_commit, snapshot_text, snap_error = _frozen_grounding_snapshot(
                    name, base
                )
                if snap_error is not None:
                    errors.append(snap_error)
                    continue
                if snapshot_commit is None:
                    continue  # Paired ADR never Accepted
                try:
                    head_grounding = file_at("HEAD", name)
                except Exception as exc:
                    errors.append(f"Failed to read {name} at HEAD: {exc}")
                    continue
                adr_ref = f"docs/adr/{Path(name).stem}.md"
                if snapshot_text is None and head_grounding is None:
                    continue
                elif head_grounding is None and snapshot_text is not None:
                    errors.append(
                        f"{name}: cannot delete grounding for Accepted ADR "
                        f"{adr_ref}. "
                        f"Grounding files freeze with ADR acceptance."
                    )
                elif head_grounding is not None and snapshot_text is None:
                    errors.append(
                        f"{name}: cannot add grounding for Accepted ADR "
                        f"{adr_ref} after acceptance. "
                        f"Grounding files freeze with ADR acceptance."
                    )
                elif head_grounding is not None and snapshot_text is not None and head_grounding != snapshot_text:
                    errors.append(
                        f"{name}: cannot modify grounding for Accepted ADR "
                        f"{adr_ref}. "
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
