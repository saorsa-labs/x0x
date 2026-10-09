#!/bin/bash
# check-panics.sh - Scan for unwrap/expect/panic in production code
# Enforces zero-panic policy for x0x project

set -e

echo "=== Panic Scanner ==="
echo "Scanning src/ and x0x/ for unwrap/expect/panic in production code..."
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

FOUND_ISSUES=0

# Lines that belong to a test-only item, keyed as "path:line".
# Populated once by load_test_regions.
declare -A IN_TEST=()

# A line is test-only when it sits in a #[cfg(test)], #[cfg(all(..., test, ...))],
# #[test], or #[tokio::test] item, or after #![cfg(test)]. The item ends when
# its brace body closes, or at ';' / ',' when it has no body. Strings,
# characters, and comments do not move the brace depth, so a format string
# that continues with a backslash cannot close the item early.
load_test_regions() {
    local tmp
    tmp=$(mktemp)
    if ! python3 - "$tmp" << 'PY'
from __future__ import annotations

import os
import sys

BLOCK_WORDS = {
    "fn",
    "struct",
    "enum",
    "impl",
    "mod",
    "trait",
    "union",
    "const",
    "static",
    "type",
    "use",
    "extern",
    "macro_rules",
    "async",
    "unsafe",
    "pub",
}


def test_lines(text: str) -> set[int]:
    """Return 1-based line numbers that are inside test-only source."""
    lines = text.splitlines()
    marked: set[int] = set()

    depth = 0
    paren = 0
    bracket = 0
    angle = 0
    in_block = False
    in_raw = False
    raw_hashes = 0
    in_string = False
    file_test = False

    active = False
    floor = 0
    paren_floor = 0
    bracket_floor = 0
    phase = "header"  # header | body | after
    mode = ""  # "" | block | expr

    def end_item() -> None:
        nonlocal active, phase, mode
        active = False
        phase = "header"
        mode = ""

    def start_item() -> None:
        nonlocal active, floor, paren_floor, bracket_floor, phase, mode
        active = True
        floor = depth
        paren_floor = paren
        bracket_floor = bracket
        phase = "header"
        mode = ""

    def at_item_level() -> bool:
        return depth == floor and paren == paren_floor and bracket == bracket_floor

    for idx, line in enumerate(lines):
        if file_test:
            marked.add(idx + 1)
            continue

        line_in_test = active and phase != "after"
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            nxt = line[i + 1] if i + 1 < n else ""

            if in_raw:
                if ch == '"' and line[i + 1 : i + 1 + raw_hashes] == "#" * raw_hashes:
                    in_raw = False
                    i += 1 + raw_hashes
                    continue
                i += 1
                continue

            if in_string:
                if ch == "\\":
                    if i + 1 >= n:
                        break
                    i += 2
                    continue
                if ch == '"':
                    in_string = False
                    i += 1
                    continue
                i += 1
                continue

            if in_block:
                if ch == "*" and nxt == "/":
                    in_block = False
                    i += 2
                    continue
                i += 1
                continue

            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block = True
                i += 2
                continue

            if ch == '"':
                hashes = _raw_hashes(line, i)
                if hashes >= 0:
                    in_raw = True
                    raw_hashes = hashes
                    i += 1
                    continue
                in_string = True
                i += 1
                continue

            if ch == "'":
                i = _skip_tick(line, i)
                continue

            if ch == "#":
                kind = _attr_kind(line, i)
                if active and phase == "after":
                    end_item()
                if kind == "file":
                    file_test = True
                    line_in_test = True
                    break
                if kind in {"cfg", "test"} and not active:
                    start_item()
                    line_in_test = True
                i += 1
                continue

            if active and phase == "after":
                if ch.isspace():
                    i += 1
                    continue
                if _word_at(line, i) == "else":
                    phase = "header"
                    mode = ""
                    line_in_test = True
                    i += 4
                    continue
                end_item()
                continue

            if ch == "{":
                if active and phase == "header" and at_item_level():
                    phase = "body"
                    line_in_test = True
                depth += 1
                i += 1
                continue

            if ch == "}":
                if depth > 0:
                    depth -= 1
                if active and phase == "body" and depth == floor and paren == paren_floor and bracket == bracket_floor:
                    phase = "after"
                    line_in_test = True
                elif active and phase == "header" and depth < floor and paren == paren_floor and bracket == bracket_floor:
                    end_item()
                i += 1
                continue

            if ch == "(":
                paren += 1
                i += 1
                continue
            if ch == ")":
                if active and phase == "header" and paren <= paren_floor and depth == floor and bracket == bracket_floor:
                    end_item()
                    continue
                if paren > 0:
                    paren -= 1
                i += 1
                continue
            if ch == "[":
                bracket += 1
                i += 1
                continue
            if ch == "]":
                if active and phase == "header" and bracket <= bracket_floor and depth == floor and paren == paren_floor:
                    end_item()
                    continue
                if bracket > 0:
                    bracket -= 1
                i += 1
                continue
            if ch == "<":
                angle += 1
                i += 1
                continue
            if ch == ">":
                if angle > 0:
                    angle -= 1
                i += 1
                continue

            if ch == ";" and active and phase == "header" and at_item_level():
                end_item()
                line_in_test = True
                i += 1
                continue

            if (
                ch == ","
                and active
                and phase == "header"
                and mode == "expr"
                and angle == 0
                and at_item_level()
            ):
                end_item()
                line_in_test = True
                i += 1
                continue

            if ch.isalpha() or ch == "_":
                word = _word_at(line, i)
                if (
                    active
                    and phase == "header"
                    and mode == ""
                    and at_item_level()
                    and angle == 0
                ):
                    mode = "block" if word in BLOCK_WORDS else "expr"
                if active:
                    line_in_test = True
                i += len(word)
                continue

            if active and phase != "after":
                line_in_test = True
            i += 1

        if in_string and not _odd_trailing_backslash(line):
            in_string = False

        if line_in_test:
            marked.add(idx + 1)

    return marked


def _word_at(line: str, i: int) -> str:
    j = i + 1
    while j < len(line) and (line[j].isalnum() or line[j] == "_"):
        j += 1
    return line[i:j]


def _attr_kind(line: str, i: int) -> str:
    if line[:i].strip() != "":
        return ""
    rest = line[i:]
    if rest.startswith("#![cfg(test)]"):
        return "file"
    if rest.startswith("#[cfg(test)]"):
        return "cfg"
    if rest.startswith("#[test]") or rest.startswith("#[test("):
        return "test"
    if rest.startswith("#[tokio::test]") or rest.startswith("#[tokio::test("):
        return "test"
    if _cfg_all_requires_test(rest):
        return "cfg"
    return ""


def _odd_trailing_backslash(line: str) -> bool:
    count = 0
    j = len(line) - 1
    while j >= 0 and line[j] == "\\":
        count += 1
        j -= 1
    return count % 2 == 1


def _cfg_all_requires_test(rest: str) -> bool:
    """True when every build of this attribute requires cfg(test)."""
    prefix = "#[cfg(all("
    if not rest.startswith(prefix):
        return False
    depth = 1
    atoms: list[str] = []
    current: list[str] = []
    for ch in rest[len(prefix) :]:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            if depth == 0:
                atoms.append("".join(current).strip())
                break
            current.append(ch)
        elif ch == "," and depth == 1:
            atoms.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    return "test" in atoms


def _raw_hashes(line: str, quote: int) -> int:
    j = quote - 1
    hashes = 0
    while j >= 0 and line[j] == "#":
        hashes += 1
        j -= 1
    if j < 0 or line[j] != "r":
        return -1
    j -= 1
    for _ in range(2):
        if j >= 0 and line[j] in "bc":
            j -= 1
        else:
            break
    if j >= 0 and (line[j].isalnum() or line[j] == "_"):
        return -1
    return hashes


def _skip_tick(line: str, i: int) -> int:
    n = len(line)
    if i + 1 >= n:
        return i + 1
    if line[i + 1] == "\\":
        j = i + 2
        if j < n and line[j] in "ux":
            j += 1
            while j < n and line[j] != "'":
                j += 1
            return min(n, j + 1)
        return min(n, i + 4)
    if i + 2 < n and line[i + 2] == "'":
        return i + 3
    j = i + 1
    while j < n and (line[j].isalnum() or line[j] == "_"):
        j += 1
    return j


def _emit(root, out):
    if not os.path.isdir(root):
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name != "target"]
        for name in filenames:
            if not name.endswith(".rs"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, ".").replace(os.sep, "/")
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
            for number in test_lines(text):
                out.write(f"{rel}\t{number}\n")

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    _emit("src", handle)
    _emit("x0x", handle)
PY
    then
        rm -f "$tmp"
        echo "panic scanner could not classify #[cfg(test)] regions" >&2
        exit 1
    fi
    while IFS=$'\t' read -r file num; do
        [[ -n "$file" && -n "$num" ]] || continue
        IN_TEST["${file}:${num}"]=1
    done < "$tmp"
    rm -f "$tmp"
}

is_in_test_code() {
    [[ -n "${IN_TEST["$1:$2"]+x}" ]]
}

# Function to scan and report
scan_pattern() {
    local pattern="$1"
    local description="$2"
    local paths="src/ x0x/"
    local found_in_prod=0

    echo "Checking for: $description"

    # Scan for pattern
    while IFS= read -r match; do
        # Skip if in tests/ directory, a file named tests.rs (file-level test
        # submodules declared via `#[cfg(test)] mod tests;` in the parent, e.g.
        # src/connect/acl/tests.rs), or .bak files.
        if echo "$match" | grep -qE "(tests/|/tests\.rs:|\.bak:|\.rs:.*//.*$pattern)"; then
            continue
        fi

        # Extract file and line number
        local file=$(echo "$match" | cut -d: -f1)
        local line_num=$(echo "$match" | cut -d: -f2)

        # Check if in test code
        if is_in_test_code "$file" "$line_num"; then
            continue
        fi

        # Found in production code
        echo "  $match"
        found_in_prod=1
    # -a (treat binary as text) is defence in depth. GNU/BSD grep decide
    # binary-or-not from an early read buffer, so a NUL near the top of a file
    # would make the whole file emit no file:line matches and drop silently out
    # of this scan. The NUL tripwire above is the primary guard; -a means the
    # scan itself stays correct regardless of where such a byte lands or which
    # grep implementation runs it.
    done < <(grep -arn "$pattern" $paths 2>/dev/null || true)

    if [ $found_in_prod -eq 1 ]; then
        echo -e "${RED}✗ FOUND: $description in production code${NC}"
        FOUND_ISSUES=$((FOUND_ISSUES + 1))
    else
        echo -e "${GREEN}✓ PASS: No $description in production code${NC}"
    fi
    echo ""
}

# Tripwire: fail if any .rs file contains a raw NUL byte.
#
# A NUL in a source file makes text tools classify it as binary and skip it
# silently. Which tools, and from where in the file, varies: ripgrep and ugrep
# bail on the first NUL wherever it sits, while GNU/BSD grep decide from an
# early read buffer and will happily scan past a NUL that lands late. So a
# late NUL can leave this gate working while breaking every rg-based code
# search — a split that is worse than a clean failure, because the gate looks
# healthy.
#
# Testing for the defect itself (a NUL byte) rather than for "some grep thinks
# this is binary" makes the check deterministic and independent of which tool
# and which implementation happens to run. src/dm_inbox.rs carried four raw
# NULs in byte-string literals where \x00 escapes were meant; this is what
# would have caught them.
check_no_nul_bytes() {
    echo "Checking for: raw NUL bytes in .rs sources"
    local binary_found=0
    while IFS= read -r f; do
        [ -s "$f" ] || continue
        # Strip NULs and compare: identical means the file had none.
        if ! LC_ALL=C tr -d '\000' < "$f" | cmp -s - "$f"; then
            echo "  $f contains raw NUL byte(s)"
            binary_found=1
        fi
    done < <(find src/ x0x/ -name '*.rs' -type f 2>/dev/null)

    if [ $binary_found -eq 1 ]; then
        echo -e "${RED}✗ FOUND: raw NUL bytes in .rs sources — text tools"
        echo -e "  classify these files as binary and skip them silently.${NC}"
        echo -e "  Write the byte escaped instead (\\\\x00, not a literal NUL)."
        FOUND_ISSUES=$((FOUND_ISSUES + 1))
    else
        echo -e "${GREEN}✓ PASS: No raw NUL bytes in .rs sources${NC}"
    fi
    echo ""
}

check_no_nul_bytes

load_test_regions

# Scan for problematic patterns
scan_pattern "\.unwrap()" ".unwrap() calls"
scan_pattern "\.expect[(]" ".expect() calls"
scan_pattern "panic!" "panic! macro"
scan_pattern "todo!" "todo! macro"
scan_pattern "unimplemented!" "unimplemented! macro"

echo "=== Results ==="
if [ $FOUND_ISSUES -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed - zero panics in production code${NC}"
    exit 0
else
    echo -e "${RED}✗ Found $FOUND_ISSUES issue(s) - panics detected in production code${NC}"
    echo ""
    echo "ERROR: Production code must not use unwrap/expect/panic."
    echo "Use Result<T, E> and ? operator for error handling."
    echo ""
    exit 1
fi
