#!/usr/bin/env python3
"""Count current ADRs and fail when the total exceeds 15.

The plan is docs/adr/consolidated/README.md. An exact ``docs/adr/NNNN-*.md``
path does not count when ``docs/adr-archive/move.json`` records it and that
path is a symlink to the recorded archive link. Files under
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


def recorded_archive_paths(root: Path) -> set[str]:
    """Return exact old paths that are recorded archive links.

    A path is excluded only when ``move.json`` records it and the file at
    that path is a symlink to the recorded link. A nested file that reuses
    the same number does not match.
    """
    manifest_path = root / "docs/adr-archive/move.json"
    if not manifest_path.is_file():
        return set()
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = data.get("moves") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError("docs/adr-archive/move.json: moves must be a list.")
    recorded: set[str] = set()
    for entry in entries:
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
    archived = recorded_archive_paths(root)
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
        count, extras = current_records(root)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return [f"Cannot count ADRs: {exc}. Plan: {PLAN}"]
    if count > LIMIT:
        return [fail_line(count, extras)]
    return []


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
