#!/usr/bin/env python3
"""Count current ADRs and fail when the total exceeds 15.

The plan is docs/adr/consolidated/README.md. An exact ``docs/adr/NNNN-*.md``
path does not count only when it is an approved historical source, ``move.json``
records that path, and the path is a symlink to the recorded archive link.
The approved set is the numbered ``docs/adr/`` listing at a trusted
pre-change commit, including ADR 0115 and ADR 0116. Pull requests use the
merge-base. Push runs use ``GITHUB_BEFORE``. A local checkout of an updated
main uses its parent. The candidate HEAD never approves its own archive
entries. The check fails closed when that commit cannot be resolved. The
set does not come from the working-tree ``TRANSFER.md``. A path is excluded
only when that history approves it, ``move.json`` records it, and the table
has exactly one valid slot row for it. A transfer row or ``move.json`` entry
outside that set is rejected. Files under ``docs/adr/transient/`` do not
count (D242). A nested file that reuses a mapped number counts. A legal run
prints the pass line only.

This check reads local files and local git history. It never starts x0xd or
contacts the network.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

LIMIT = 15
PLAN = "docs/adr/consolidated/README.md"
SLOT_FILE = re.compile(r"A\d{2}-r\d{2}-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
NUMBERED_FILE = re.compile(r"(\d{4})-[a-z0-9][a-z0-9-]*\.md$")
MAPPED_LINK = re.compile(r"\]\(\.\./(\d{4})-")
SOURCE_FILE = re.compile(r"\]\(\.\./(\d{4}-[a-z0-9][a-z0-9-]*\.md)\)")
SLOT_LINK = re.compile(
    r"\]\((A(?:0[1-9]|1[0-5])-r\d{2}-[a-z0-9]+(?:-[a-z0-9]+)*\.md)\)"
)
NUMBERED_REPO_PATH = re.compile(r"^docs/adr/\d{4}-[a-z0-9][a-z0-9-]*\.md$")
# David placed these two after the original 100-row source set.
EXPLICIT_HISTORICAL_ADDITIONS = {
    "docs/adr/0115-identity-discovery-authority.md",
    "docs/adr/0116-local-history-retention-policy.md",
}


def pass_line(count: int) -> str:
    return f"PASS: {count} current ADRs, within the limit of {LIMIT}. Plan: {PLAN}"


def fail_line(count: int, extras: list[str]) -> str:
    extra = ""
    if extras:
        extra = " Extra: " + ", ".join(extras) + "."
    return f"{count} current ADRs exceeds the limit of {LIMIT}.{extra} Plan: {PLAN}"


def _is_record(path: Path) -> bool:
    return path.is_symlink() or path.is_file()


def mapped_ids(root: Path) -> set[str]:
    text = (root / "docs/adr/consolidated/TRANSFER.md").read_text(encoding="utf-8")
    table = text.split("\n## Rulings", 1)[0]
    return set(MAPPED_LINK.findall(table))


def _transfer_table(root: Path) -> str:
    text = (root / "docs/adr/consolidated/TRANSFER.md").read_text(encoding="utf-8")
    return text.split("\n## Rulings", 1)[0]


def source_slot_map(root: Path) -> tuple[dict[str, str], list[str]]:
    """Map each approved historical source path to its slot file."""
    errors: list[str] = []
    mapping: dict[str, str] = {}
    duplicates: set[str] = set()
    consolidated = root / "docs/adr/consolidated"
    for line in _transfer_table(root).splitlines():
        sources = SOURCE_FILE.findall(line)
        if not sources:
            continue
        if len(sources) != 1:
            errors.append(
                "A historical source row must name one ADR: " + ", ".join(sources) + "."
            )
            continue
        src = f"docs/adr/{sources[0]}"
        slots = SLOT_LINK.findall(line)
        if len(slots) != 1:
            errors.append(f"{src}: source-to-slot mapping must name one slot A01-A15.")
            continue
        if src in mapping or src in duplicates:
            errors.append(f"{src}: historical source is mapped more than once.")
            mapping.pop(src, None)
            duplicates.add(src)
            continue
        slot = slots[0]
        if not (consolidated / slot).is_file():
            errors.append(f"{src}: target slot {slot} is missing.")
            continue
        mapping[src] = slot
    return mapping, errors


def _move_entries(root: Path) -> list[dict]:
    manifest_path = root / "docs/adr-archive/move.json"
    if not manifest_path.is_file():
        return []
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = data.get("moves") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError("docs/adr-archive/move.json: moves must be a list.")
    return [entry for entry in entries if isinstance(entry, dict)]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _git_repo(root: Path | None) -> Path:
    if root is not None and (root / ".git").exists():
        return root
    return _repo_root()


def _git(args: list[str], repo: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args],
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()


def _resolve_commit(repo: Path, rev: str) -> str | None:
    try:
        resolved = _git(["rev-parse", "--verify", f"{rev}^{{commit}}"], repo)
    except (subprocess.CalledProcessError, OSError):
        return None
    if not resolved or resolved == "0" * 40 or set(resolved) <= {"0"}:
        return None
    return resolved


def _unresolved(source: str) -> ValueError:
    return ValueError(f"Cannot resolve the approved historical source set from {source}.")


def _history_base(repo: Path) -> str:
    """Return a pre-change commit. Never the candidate HEAD.

    Pull requests use the merge-base with ``GITHUB_BASE_SHA``. Push runs use
    ``GITHUB_BEFORE``. When those refs are absent and the branch refs point
    at HEAD, the parent commit is the trusted set. HEAD is not a fallback.
    """
    head = _resolve_commit(repo, "HEAD")
    if head is None:
        raise _unresolved("HEAD")

    before = os.environ.get("GITHUB_BEFORE", "").strip()
    if before:
        resolved = None if before.startswith("0000000") else _resolve_commit(repo, before)
        if resolved is None or resolved == head:
            raise _unresolved("GITHUB_BEFORE")
        return resolved

    base_sha = os.environ.get("GITHUB_BASE_SHA", "").strip()
    if base_sha:
        resolved = None if base_sha.startswith("0000000") else _resolve_commit(repo, base_sha)
        if resolved is None or resolved == head:
            raise _unresolved("GITHUB_BASE_SHA")
        try:
            base = _git(["merge-base", resolved, head], repo)
        except (subprocess.CalledProcessError, OSError):
            raise _unresolved("GITHUB_BASE_SHA") from None
        if not base or base == head:
            raise _unresolved("GITHUB_BASE_SHA")
        return base

    for cand in ("origin/main", "main", "origin/master", "master"):
        resolved = _resolve_commit(repo, cand)
        if resolved is None or resolved == head:
            continue
        try:
            base = _git(["merge-base", resolved, head], repo)
        except (subprocess.CalledProcessError, OSError):
            continue
        if base and base != head:
            return base

    parent = _resolve_commit(repo, "HEAD^1")
    if parent is None or parent == head:
        raise _unresolved("HEAD^1")
    return parent


def approved_historical_sources(root: Path | None = None) -> set[str]:
    """Numbered ADR paths before this change, including 0115 and 0116.

    The working-tree transfer table cannot add a path to this set. The
    candidate HEAD cannot add a path either.
    """
    repo = _git_repo(root)
    listing = _git(["ls-tree", "--name-only", _history_base(repo), "docs/adr/"], repo)
    found = {line for line in listing.splitlines() if NUMBERED_REPO_PATH.match(line)}
    missing = EXPLICIT_HISTORICAL_ADDITIONS - found
    if missing:
        raise ValueError(
            "Approved historical source set is missing explicit additions: "
            + ", ".join(sorted(missing))
            + "."
        )
    return found


def transfer_history_errors(root: Path, approved: set[str]) -> list[str]:
    """Reject a transfer row whose source is not in the approved history."""
    mapping, errors = source_slot_map(root)
    for src in sorted(mapping):
        if src not in approved:
            errors.append(
                f"{src}: transfer row is not in the approved historical source set."
            )
    return errors


def invented_archive_errors(root: Path, approved: set[str]) -> list[str]:
    """Reject a move.json path that is not an approved historical source."""
    errors: list[str] = []
    for entry in _move_entries(root):
        src = entry.get("from")
        if isinstance(src, str) and src in approved:
            continue
        shown = src if isinstance(src, str) else "<missing path>"
        errors.append(
            f"{shown}: newly invented archive record is not in the approved historical source set."
        )
    errors.sort()
    return errors


def recorded_archive_paths(root: Path) -> set[str]:
    """Return exact old paths that are recorded archive links.

    A path is excluded only when ``move.json`` records it and the file at
    that path is a symlink to the recorded link. A nested file that reuses
    the same number does not match.
    """
    recorded: set[str] = set()
    for entry in _move_entries(root):
        if not isinstance(entry, dict):
            continue
        src = entry.get("from")
        link = entry.get("link")
        if not isinstance(src, str) or not isinstance(link, str):
            continue
        # docs/adr/NNNN-name.md only. A nested path is never an old path.
        if not src.startswith("docs/adr/") or src.count("/") != 2:
            continue
        path = root / src
        if not path.is_symlink():
            continue
        target = path.readlink()
        target_text = target.as_posix() if isinstance(target, Path) else str(target)
        if target_text != link:
            continue
        recorded.add(src)
    return recorded


def current_records(
    root: Path, approved: set[str] | None = None
) -> tuple[int, list[str]]:
    """Return the current count and the relative paths that raised it."""
    if approved is None:
        approved = approved_historical_sources(root)
    mapping, _map_errors = source_slot_map(root)
    # History alone is not enough. Exclusion also needs one valid slot row.
    archived = recorded_archive_paths(root) & approved & set(mapping)
    slot_count = 0
    consolidated = root / "docs/adr/consolidated"
    if consolidated.exists():
        for path in consolidated.rglob("*"):
            if _is_record(path) and SLOT_FILE.fullmatch(path.name):
                slot_count += 1
    extras: list[str] = []
    adr_dir = root / "docs/adr"
    if adr_dir.exists():
        for path in adr_dir.rglob("*"):
            if not _is_record(path) or not NUMBERED_FILE.fullmatch(path.name):
                continue
            relative = path.relative_to(adr_dir)
            if relative.parts and relative.parts[0] in {"consolidated", "transient"}:
                continue
            repo_path = f"docs/adr/{relative.as_posix()}"
            if repo_path in archived:
                continue
            extras.append(relative.as_posix())
    extras.sort()
    return slot_count + len(extras), extras


def validate(root: Path) -> list[str]:
    try:
        approved = approved_historical_sources(root)
        errors = transfer_history_errors(root, approved)
        errors.extend(invented_archive_errors(root, approved))
        count, extras = current_records(root, approved)
    except (
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as exc:
        return [f"Cannot count ADRs: {exc}. Plan: {PLAN}"]
    if count > LIMIT:
        errors.append(fail_line(count, extras))
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = validate(root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    count, _extras = current_records(root)
    print(pass_line(count))
    return 0


if __name__ == "__main__":
    sys.exit(main())
