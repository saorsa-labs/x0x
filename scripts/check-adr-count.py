#!/usr/bin/env python3
"""Count current ADRs and fail when the total exceeds 15.

The plan is docs/adr/consolidated/README.md. An exact ``docs/adr/NNNN-*.md``
path does not count only when it is an approved historical source, ``move.json``
records that path, and the path is a symlink to the recorded archive link.
A new ``move.json`` entry outside that set is rejected. Files under
``docs/adr/transient/`` do not count (D242). A nested file that reuses a
mapped number counts. A legal run prints the pass line only.

This check reads local files only. It never starts x0xd or contacts the network.
"""
from __future__ import annotations

import json
import re
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
        if src in mapping:
            errors.append(f"{src}: historical source is mapped more than once.")
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


def current_records(root: Path) -> tuple[int, list[str]]:
    """Return the current count and the relative paths that raised it."""
    approved, _map_errors = source_slot_map(root)
    archived = recorded_archive_paths(root) & set(approved)
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
        approved, errors = source_slot_map(root)
        errors.extend(invented_archive_errors(root, set(approved)))
        count, extras = current_records(root)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
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
