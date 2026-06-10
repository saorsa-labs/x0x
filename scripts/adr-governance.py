#!/usr/bin/env python3
"""Repository-local ADR governance checks.

Enforces:
- ADR files live under docs/adr/ and use NNNN-short-title.md (the established
  convention in this repository, e.g. 0001-bootstrap-peers-are-seed-hints-only.md).
- Required template sections exist on ADRs added by the change (pre-existing
  ADRs keep their original structure).
- Status is present and starts with an allowed lifecycle value. Annotations
  after the status are fine, e.g. "Accepted (2026-06-07). Follow-up in ...".
- Accepted ADRs are immutable after acceptance. If a decision changes, create a
  new ADR and supersede by reference rather than editing the Accepted ADR.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ADR_DIR = Path("docs/adr")
ALLOWED_STATUSES = {"Proposed", "Accepted", "Superseded", "Deprecated", "Rejected"}
REQUIRED_SECTIONS = ["Context", "Decision", "Consequences", "Validation"]
FILENAME_RE = re.compile(r"^\d{4}-[a-z0-9][a-z0-9-]*\.md$")
ADR_PATH_RE = re.compile(r"^docs/adr/\d{4}-[a-z0-9][a-z0-9-]*\.md$")
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


def base_ref() -> str | None:
    ref = os.environ.get("GITHUB_BASE_REF")
    if ref:
        return f"origin/{ref}"
    # On push, compare against first parent where available.
    try:
        return run(["git", "rev-parse", "HEAD^1"])
    except Exception:
        return None


def changed_files_against_base(base: str) -> list[str]:
    try:
        return run(["git", "diff", "--name-only", f"{base}...HEAD"]).splitlines()
    except Exception:
        try:
            return run(["git", "diff", "--name-only", f"{base}", "HEAD"]).splitlines()
        except Exception:
            return []


def file_at(ref: str, path: str) -> str | None:
    try:
        return run(["git", "show", f"{ref}:{path}"])
    except Exception:
        return None


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

    base = base_ref()
    changed = changed_files_against_base(base) if base else []
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
                if not re.search(rf"(?im)^##\s+{re.escape(section)}\b", text):
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
                errors.append(
                    f"{name}: Accepted ADRs are immutable. Create a new superseding ADR instead of editing this file."
                )

    if errors:
        print("ADR governance failed:")
        for e in errors:
            print(f"- {e}")
        return 1
    print(f"ADR governance passed ({len(adr_files)} ADR file(s) checked).")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
