#!/usr/bin/env python3
"""Count current ADRs and fail when the total exceeds 15.

The plan is docs/adr/consolidated/README.md. Numbered ADRs listed in the
transfer map keep their paths and do not count. ADR 0115 and ADR 0116 were
accepted after that map. The plan assigns them no slot. They stay in force
and stay outside this count.

This check reads local files only. It never starts x0xd or contacts the network.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

LIMIT = 15
PLAN = "docs/adr/consolidated/README.md"
# Accepted after the #1244 map. No slot is assigned. Leave these files unchanged.
HOLD = frozenset({"0115", "0116"})
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


def current_records(root: Path) -> tuple[int, list[str]]:
    """Return the current count and the relative paths that raised it."""
    mapped = mapped_ids(root)
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
            if relative.parts and relative.parts[0] == "consolidated":
                continue
            number = NUMBERED_FILE.fullmatch(path.name).group(1)
            if number in mapped or number in HOLD:
                continue
            extras.append(relative.as_posix())
    extras.sort()
    return slot_count + len(extras), extras


def validate(root: Path) -> list[str]:
    try:
        count, extras = current_records(root)
    except (OSError, UnicodeError) as exc:
        return [f"Cannot count ADRs: {exc}. Plan: {PLAN}"]
    if count > LIMIT:
        return [fail_line(count, extras)]
    return []


def hold_note(root: Path) -> str | None:
    present = []
    for number in sorted(HOLD):
        if any((root / "docs/adr").glob(f"{number}-*.md")):
            present.append(f"ADR {number}")
    if not present:
        return None
    if len(present) == 1:
        names = present[0]
    elif len(present) == 2:
        names = f"{present[0]} and {present[1]}"
    else:
        names = ", ".join(present)
    return f"NOTE: {names} are outside the #1244 map. They stay in force outside this count."


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = validate(root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    count, _extras = current_records(root)
    print(pass_line(count))
    note = hold_note(root)
    if note:
        print(note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
