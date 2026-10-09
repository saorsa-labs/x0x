#!/usr/bin/env python3
"""Fail when the x0x skill exceeds its token budget (#1173).

SKILL.md is the core file an agent can use alone for a first direct message,
a group join, and a scratch KV write. The four topic pages hold the rest.
There are at most five skill files.

One token is 4 UTF-8 bytes, rounded up. That is the same scale as the issue's
82 KB ≈ 20.7k tokens (82,685 bytes is 20,672 tokens). The core budget is
8,000 tokens. Each topic page budget is 4,000 tokens.

--self-test builds temporary trees and checks that an over-budget file fails
and an in-budget file passes.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

CORE = "SKILL.md"
CORE_BUDGET = 8000
PAGE_BUDGET = 4000
PAGES = (
    "docs/skill/owner.md",
    "docs/skill/messaging.md",
    "docs/skill/stores.md",
    "docs/skill/operations.md",
)
# A release and ClawHub ship SKILL.md alone. Topic links must be absolute
# repository URLs, not paths relative to a checkout.
TOPIC_URL = "https://github.com/saorsa-labs/x0x/blob/main/"
# Commands the core must contain so the first three actions do not depend
# on a topic page. The topic pages may repeat them.
CORE_MARKERS = (
    "x0x direct send",
    "/groups/join",
    "x0x store create",
    "-X PUT",
    "/stores/",
    # The scratch example is a local: topic and is not a private store.
    "local:scratch-pad",
    "non-sensitive",
)


def tokens(data: bytes) -> int:
    return (len(data) + 3) // 4


def check(root: Path) -> list[str]:
    errors: list[str] = []
    skill_dir = root / "docs" / "skill"
    found: list[str] = []
    if skill_dir.is_dir():
        found = sorted(
            path.relative_to(root).as_posix() for path in skill_dir.rglob("*.md")
        )
    else:
        errors.append("docs/skill/: missing topic-page directory")

    expected = sorted(PAGES)
    if found != expected:
        errors.append(
            "docs/skill markdown set is "
            f"{found or '[]'}, expected {expected} (at most 5 skill files)"
        )

    core_path = root / CORE
    core_text = ""
    if not core_path.is_file():
        errors.append(f"{CORE}: missing")
    else:
        data = core_path.read_bytes()
        count = tokens(data)
        print(f"{count:5} tokens  {CORE}  (budget {CORE_BUDGET})")
        if count > CORE_BUDGET:
            errors.append(f"{CORE}: {count} tokens exceeds the core budget of {CORE_BUDGET}")
        try:
            core_text = data.decode("utf-8")
        except UnicodeError:
            errors.append(f"{CORE}: not UTF-8")
        else:
            for marker in CORE_MARKERS:
                if marker not in core_text:
                    errors.append(f"{CORE}: missing first-action marker {marker!r}")
            if "](docs/skill/" in core_text:
                errors.append(
                    f"{CORE}: topic link is relative; use an absolute GitHub URL"
                )
            for page in PAGES:
                url = TOPIC_URL + page
                if url not in core_text:
                    errors.append(f"{CORE}: missing absolute topic URL {url}")

    for page in PAGES:
        path = root / page
        if not path.is_file():
            if skill_dir.is_dir():
                errors.append(f"{page}: missing")
            continue
        data = path.read_bytes()
        count = tokens(data)
        print(f"{count:5} tokens  {page}  (budget {PAGE_BUDGET})")
        if count > PAGE_BUDGET:
            errors.append(f"{page}: {count} tokens exceeds the page budget of {PAGE_BUDGET}")
        try:
            data.decode("utf-8")
        except UnicodeError:
            errors.append(f"{page}: not UTF-8")
    return errors


def _pad(text: str, nbytes: int) -> str:
    raw = text.encode("utf-8")
    if len(raw) > nbytes:
        raise RuntimeError(f"marker text is {len(raw)} bytes, longer than {nbytes}")
    return text + ("x" * (nbytes - len(raw)))


VALID_CORE = """---
name: fixture
---

# fixture

https://github.com/saorsa-labs/x0x/blob/main/docs/skill/owner.md
https://github.com/saorsa-labs/x0x/blob/main/docs/skill/messaging.md
https://github.com/saorsa-labs/x0x/blob/main/docs/skill/stores.md
https://github.com/saorsa-labs/x0x/blob/main/docs/skill/operations.md

x0x direct send
/groups/join
x0x store create
-X PUT
/stores/
local:scratch-pad
non-sensitive
"""


def _write_tree(root: Path, core: str, pages: dict[str, str]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(core, encoding="utf-8")
    for name, body in pages.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


def _valid_pages() -> dict[str, str]:
    return {page: f"# {page}\n\nshort.\n" for page in PAGES}


def self_test() -> int:
    failures: list[str] = []

    def expect_fail(name: str, root: Path, needle: str) -> None:
        errors = check(root)
        if not any(needle in error for error in errors):
            failures.append(f"{name}: expected {needle!r} in {errors}")
        else:
            print(f"self-test fail-as-expected  {name}")

    def expect_pass(name: str, root: Path) -> None:
        errors = check(root)
        if errors:
            failures.append(f"{name}: expected pass, got {errors}")
        else:
            print(f"self-test pass  {name}")

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)

        ok = base / "ok"
        _write_tree(ok, _pad(VALID_CORE, CORE_BUDGET * 4), _valid_pages())
        expect_pass("core at 8000 tokens", ok)

        over = base / "over-core"
        _write_tree(over, _pad(VALID_CORE, CORE_BUDGET * 4 + 4), _valid_pages())
        expect_fail("core at 8001 tokens", over, "exceeds the core budget")

        missing = base / "missing-dm"
        _write_tree(missing, VALID_CORE.replace("x0x direct send", "x0x direct drop"), _valid_pages())
        expect_fail("core without direct send", missing, "x0x direct send")

        fat_page = base / "fat-page"
        pages = _valid_pages()
        pages["docs/skill/operations.md"] = _pad("# operations\n", PAGE_BUDGET * 4 + 4)
        _write_tree(fat_page, VALID_CORE, pages)
        expect_fail("page at 4001 tokens", fat_page, "exceeds the page budget")

        page_ok = base / "page-ok"
        pages = _valid_pages()
        pages["docs/skill/operations.md"] = _pad("# operations\n", PAGE_BUDGET * 4)
        _write_tree(page_ok, VALID_CORE, pages)
        expect_pass("page at 4000 tokens", page_ok)

        extra = base / "extra"
        pages = _valid_pages()
        pages["docs/skill/extra.md"] = "# extra\n"
        _write_tree(extra, VALID_CORE, pages)
        expect_fail("sixth skill file", extra, "markdown set")

        relative = base / "relative"
        _write_tree(
            relative,
            VALID_CORE.replace(
                "https://github.com/saorsa-labs/x0x/blob/main/docs/skill/owner.md",
                "docs/skill/owner.md",
                1,
            )
            + "\nSee [Owner](docs/skill/owner.md).\n",
            _valid_pages(),
        )
        expect_fail("relative topic link", relative, "topic link is relative")

    if failures:
        for failure in failures:
            print(f"SELF-TEST FAILED  {failure}", file=sys.stderr)
        return 1
    print("self-test ok")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove over-budget fixtures fail and in-budget fixtures pass",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    errors = check(ROOT)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("skill token budget ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
