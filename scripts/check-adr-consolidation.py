#!/usr/bin/env python3
"""Check the 15-slot set while legacy ADRs still govern implementation.

This check does not replace adr-governance.py. Formal acceptance requires a
follow-up that adds revision-aware frozen history and completes the transfer.
It reads local files only. It never starts x0xd or contacts the network.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SLOTS = {f"A{i:02d}" for i in range(1, 16)}
RECORD_NAME = re.compile(r"(A\d{2})-r(\d{2})-[a-z0-9]+(?:-[a-z0-9]+)*\.md")
SUPPORT_FILES = {"README.md", "TRANSFER.md", "index.json"}
REQUIRED_SECTIONS = {"Context", "Decision", "Consequences", "Validation"}


def status_token(status: str) -> str:
    """Read the leading lifecycle word, as adr-governance.py does."""
    return status.split()[0].strip("*").rstrip(".,;:") if status.split() else status


def validate(root: Path) -> list[str]:
    directory = root / "docs/adr/consolidated"
    errors: list[str] = []
    try:
        index = json.loads((directory / "index.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        return [f"Cannot read the consolidated index: {exc}"]
    if not isinstance(index, dict):
        return ["The consolidated index must be an object."]
    if index.get("schema_version") != 1 or index.get("phase") != "transfer_review":
        errors.append("Only schema 1 transfer_review is supported. Add acceptance controls before activation.")
    if index.get("maximum_current_adrs") != 15:
        errors.append("The maximum current ADR count must remain 15.")
    slots = index.get("slots")
    if not isinstance(slots, list):
        return errors + ["The index must contain a slots list."]
    if len(slots) != 15:
        errors.append("The agreed review set must select exactly 15 records, A01 through A15.")
    seen: set[str] = set()
    selected: set[str] = set()
    for slot in slots:
        if not isinstance(slot, dict):
            errors.append("Each slot must be an object.")
            continue
        identity = slot.get("id")
        if not isinstance(identity, str) or identity not in SLOTS:
            errors.append(f"Unknown ADR slot {identity!r}; do not create A16 or a second consolidated series.")
            continue
        if identity in seen:
            errors.append(f"Duplicate current slot {identity}.")
        seen.add(identity)
        name = slot.get("path")
        match = RECORD_NAME.fullmatch(name) if isinstance(name, str) else None
        revision = slot.get("revision")
        if (not match or match[1] != identity or type(revision) is not int
                or revision < 1 or int(match[2]) != revision):
            errors.append(f"{identity}: use its own Axx-rNN-title.md file and matching revision.")
            continue
        selected.add(name)
        path = directory / name
        if path.is_symlink():
            errors.append(f"{name}: records must be regular files, not links.")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(f"{name}: cannot read record: {exc}")
            continue
        title = slot.get("title")
        if not isinstance(title, str) or not text.startswith(f"# {identity} {title}\n"):
            errors.append(f"{name}: title must match the selected slot.")
        statuses = re.findall(r"^- \*\*Status:\*\* (.+)$", text, re.MULTILINE)
        if [status_token(status) for status in statuses] != ["Proposed"]:
            errors.append(f"{name}: replacement status must remain Proposed until transfer and acceptance controls are complete.")
        for section in sorted(REQUIRED_SECTIONS):
            if not re.search(rf"^## {section}$", text, re.MULTILINE):
                errors.append(f"{name}: missing ## {section}.")
    if seen != SLOTS:
        errors.append("Missing current slots: " + ", ".join(sorted(SLOTS - seen)))
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file() or p.is_symlink()}
    unexpected = actual - SUPPORT_FILES - selected
    if unexpected:
        errors.append("Unindexed records or unsupported files: " + ", ".join(sorted(unexpected)))
    missing_support = SUPPORT_FILES - actual
    if missing_support:
        errors.append("Missing supporting files: " + ", ".join(sorted(missing_support)))
    return errors


def main() -> int:
    errors = validate(Path(__file__).resolve().parents[1])
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("PASS: 15 distinct Proposed replacement ADRs; legacy governance remains required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
