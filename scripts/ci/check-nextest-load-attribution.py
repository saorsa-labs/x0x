#!/usr/bin/env python3
"""Reject an unverified ambient-load cause in .config/nextest.toml (#702).

The #316, #510 and ADR 0030 slice 3 scheduler overrides may record what a
run observed. They must not state ambient suite load as the established
trigger. Issue #702 records that this attribution was not measured.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / ".config" / "nextest.toml"

# Contiguous claims in the pre-#702 comments. Matching is on comment text
# with leading '#' markers removed and wrapped lines joined.
STALE_CLAIMS = (
    "the trigger is ambient suite load",
    "the trigger here is ambient load",
    "starving their timing windows",
    "starving the dial's timing window",
)

MARKER = "The ambient-load attribution is unverified (#702)."


def _comment_text(lines: list[str]) -> str:
    parts: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            parts.append(stripped[1:].strip())
        else:
            parts.append(stripped)
    return " ".join(part for part in parts if part)


def _stanzas(text: str) -> list[tuple[str, str]]:
    """Return (preceding comment, stanza body) for each TOML table."""
    lines = text.splitlines()
    headers = [
        i
        for i, line in enumerate(lines)
        if line.startswith("[") and "]" in line and not line.lstrip().startswith("#")
    ]
    found: list[tuple[str, str]] = []
    for index, start in enumerate(headers):
        end = headers[index + 1] if index + 1 < len(headers) else len(lines)
        cursor = start - 1
        while cursor >= 0 and lines[cursor].strip() == "":
            cursor -= 1
        comment: list[str] = []
        while cursor >= 0 and lines[cursor].lstrip().startswith("#"):
            comment.append(lines[cursor])
            cursor -= 1
        comment.reverse()
        found.append((_comment_text(comment), "\n".join(lines[start:end])))
    return found


def _is_316(body: str) -> bool:
    return (
        "direct_send_with_require_ack_round_trips_to_live_peer" in body
        and "threads-required = 4" in body
    )


def _is_adr0030(body: str) -> bool:
    return (
        'filter = "binary(gossip_plane_isolation)"' in body
        and "threads-required = 4" in body
    )


def _is_510(body: str) -> bool:
    first = body.splitlines()[0] if body else ""
    return first.strip() == "[test-groups.membership-cluster]"


ANCHORS = (
    ("#316", _is_316),
    ("ADR 0030 slice 3", _is_adr0030),
    ("#510", _is_510),
)


def attribution_errors(text: str) -> list[str]:
    """Return one error per stale claim or missing #702 qualification."""
    errors: list[str] = []
    normalized = _comment_text(text.splitlines())
    for claim in STALE_CLAIMS:
        if claim in normalized:
            errors.append(f"stale ambient-load claim still present: {claim}")
    comments = {name: [] for name, _ in ANCHORS}
    for comment, body in _stanzas(text):
        for name, matches in ANCHORS:
            if matches(body):
                comments[name].append(comment)
    for name, _ in ANCHORS:
        found = comments[name]
        if len(found) != 1:
            errors.append(f"{name}: expected one override comment, found {len(found)}")
            continue
        if MARKER not in found[0]:
            errors.append(f"{name}: comment must contain {MARKER}")
    return errors


def main() -> int:
    if not CONFIG.is_file():
        print(f"FAIL missing {CONFIG}", file=sys.stderr)
        return 1
    errors = attribution_errors(CONFIG.read_text(encoding="utf-8"))
    for err in errors:
        print(f"FAIL {err}", file=sys.stderr)
    if errors:
        return 1
    print("ok  .config/nextest.toml: ambient-load attribution is marked unverified (#702)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
