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

# Lines that belong to a proved test-only item, keyed as "path:line".
# Populated once by load_test_regions.
declare -A IN_TEST=()

# A span is test-only only when two things are proved: a test attribute and
# that item's closing delimiter. Attributes are the exact forms in this tree:
# #[cfg(test)], #![cfg(test)], #[cfg(all(test, unix))], #[test], #[tokio::test],
# and #[tokio::test(...)]. A body item closes at the matching '}'. An item
# with no body closes at ';' or ','. A crate-level #![cfg(test)] runs to EOF.
# Anything else stays production. That includes a header whose extent is
# uncertain because of '!' (never type, macro, signature macro) and any
# attribute this list does not name. Strings and comments are skipped so a
# brace inside them cannot extend a region. An unclosed string, comment, or
# item is not committed. Line numbers follow grep: newlines are preserved and
# split on LF only. Bytes after the closing delimiter on the same line stay
# production.
load_test_regions() {
    local tmp
    tmp=$(mktemp)
    if ! python3 - "$tmp" << 'PY'
from __future__ import annotations

import os
import sys

ITEM_ATTRS = (
    "#[cfg(test)]",
    "#[cfg(all(test, unix))]",
    "#[test]",
)
FILE_ATTR = "#![cfg(test)]"
TOKIO_ATTR = "#[tokio::test"


def test_lines(text: str) -> dict[int, str]:
    """Return 1-based lines to a proved test-span spec.

    ``*`` means the whole line is test-only. Otherwise the spec is a
    comma-separated list of half-open byte ranges.
    """
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    line_bytes = [len(line.encode("utf-8")) for line in lines]
    byte_ofs: list[list[int]] = []
    for line in lines:
        ofs = [0]
        for ch in line:
            ofs.append(ofs[-1] + len(ch.encode("utf-8")))
        byte_ofs.append(ofs)

    regions: dict[int, list[list[int]]] = {}
    depth = 0
    paren = 0
    bracket = 0
    block = 0
    in_string = False
    in_raw = False
    raw_hashes = 0
    # (line, byte just after the brace) for each unmatched '{'.
    opens: list[tuple[int, int]] = []

    active = False
    body = False
    floor = 0
    paren_floor = 0
    bracket_floor = 0
    origin: tuple[int, int] | None = None
    file_test = False

    def add_span(line_no: int, start: int, end: int) -> None:
        if end <= start:
            return
        regions.setdefault(line_no, []).append([start, end])

    def commit(end_line: int, end_byte: int) -> None:
        nonlocal active, body, origin
        if origin is None:
            active = False
            body = False
            return
        start_line, start_byte = origin
        if end_line <= start_line:
            add_span(start_line, start_byte, end_byte)
        else:
            add_span(start_line, start_byte, line_bytes[start_line - 1])
            for mid in range(start_line + 1, end_line):
                add_span(mid, 0, line_bytes[mid - 1])
            add_span(end_line, 0, end_byte)
        active = False
        body = False
        origin = None

    def discard() -> None:
        nonlocal active, body, origin
        active = False
        body = False
        origin = None

    def at_item_level() -> bool:
        return depth == floor and paren == paren_floor and bracket == bracket_floor

    for idx, line in enumerate(lines):
        line_no = idx + 1
        if file_test:
            add_span(line_no, 0, line_bytes[idx])
            continue

        n = len(line)
        i = 0
        while i < n:
            ch = line[i]
            nxt = line[i + 1] if i + 1 < n else ""

            if in_raw:
                if ch == '"' and line[i + 1 : i + 1 + raw_hashes] == "#" * raw_hashes:
                    in_raw = False
                    i += 1 + raw_hashes
                else:
                    i += 1
                continue

            if in_string:
                if ch == "\\":
                    i = n if i + 1 >= n else i + 2
                    continue
                if ch == '"':
                    in_string = False
                    i += 1
                    continue
                i += 1
                continue

            if block:
                if ch == "/" and nxt == "*":
                    block += 1
                    i += 2
                    continue
                if ch == "*" and nxt == "/":
                    block -= 1
                    i += 2
                    continue
                i += 1
                continue

            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                block = 1
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

            if line[:i].strip() == "":
                kind, length = _attr_kind(line[i:])
                if kind == "file" and depth == 0:
                    file_test = True
                    add_span(line_no, byte_ofs[idx][i], line_bytes[idx])
                    break
                if kind == "file" and depth > 0 and not active:
                    active = True
                    body = True
                    floor = depth - 1
                    paren_floor = paren
                    bracket_floor = bracket
                    origin = opens[-1] if opens else (line_no, byte_ofs[idx][i])
                    i += length
                    continue
                if kind == "item":
                    # A header that never reached ';' / ',' / '{' was not
                    # proved. Drop it and let this attribute start clean.
                    if active and not body:
                        discard()
                    if not active:
                        active = True
                        body = False
                        floor = depth
                        paren_floor = paren
                        bracket_floor = bracket
                        origin = (line_no, byte_ofs[idx][i])
                        i += length
                        continue

            # '!' before the body is a macro or a never type. The closing
            # delimiter is not proved, so the candidate stays production.
            if (
                active
                and not body
                and ch == "!"
                and nxt != "="
                and at_item_level()
            ):
                discard()
                i += 1
                continue

            if ch == "{":
                if active and not body and at_item_level():
                    body = True
                depth += 1
                i += 1
                opens.append((line_no, byte_ofs[idx][i]))
                continue
            if ch == "}":
                # A header with no body of its own ends when its parent closes.
                if (
                    active
                    and not body
                    and depth == floor
                    and paren == paren_floor
                    and bracket == bracket_floor
                ):
                    commit(line_no, byte_ofs[idx][i])
                if depth > 0:
                    depth -= 1
                if opens:
                    opens.pop()
                if active and body and depth == floor and paren == paren_floor and bracket == bracket_floor:
                    i += 1
                    commit(line_no, byte_ofs[idx][i])
                    continue
                i += 1
                continue
            if ch == "(":
                paren += 1
                i += 1
                continue
            if ch == ")":
                if paren > 0:
                    paren -= 1
                i += 1
                continue
            if ch == "[":
                bracket += 1
                i += 1
                continue
            if ch == "]":
                if bracket > 0:
                    bracket -= 1
                i += 1
                continue
            if ch == ";" and active and not body and at_item_level():
                i += 1
                commit(line_no, byte_ofs[idx][i])
                continue
            # Variant, field, parameter, or match arm. A comma before the
            # body also ends the header; the bytes after it stay production.
            if ch == "," and active and not body and at_item_level():
                i += 1
                commit(line_no, byte_ofs[idx][i])
                continue
            i += 1

    if active and (in_string or in_raw or block or not body):
        discard()
    elif active:
        # Body never closed. Do not commit an open region.
        discard()

    specs: dict[int, str] = {}
    for number, spans in regions.items():
        spec = _span_spec(spans, line_bytes[number - 1])
        if spec:
            specs[number] = spec
    return specs


def _attr_kind(rest: str) -> tuple[str, int]:
    if rest.startswith(FILE_ATTR):
        return ("file", len(FILE_ATTR))
    for attr in ITEM_ATTRS:
        if rest.startswith(attr):
            return ("item", len(attr))
    length = _tokio_attr_len(rest)
    if length:
        return ("item", length)
    return ("", 0)


def _tokio_attr_len(rest: str) -> int:
    """Length of a finished ``#[tokio::test]`` or ``#[tokio::test(...)]``.

    The argument list is part of the attribute. An unclosed list is not an
    identified attribute, so the following item stays production.
    """
    if not rest.startswith(TOKIO_ATTR):
        return 0
    if rest.startswith(TOKIO_ATTR + "]"):
        return len(TOKIO_ATTR) + 1
    if not rest.startswith(TOKIO_ATTR + "("):
        return 0
    depth = 0
    in_string = False
    i = len(TOKIO_ATTR)
    n = len(rest)
    while i < n:
        ch = rest[i]
        if in_string:
            if ch == "\\":
                i += 2 if i + 1 < n else 1
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                return 0
            depth -= 1
            if depth == 0:
                if i + 1 < n and rest[i + 1] == "]":
                    return i + 2
                return 0
        i += 1
    return 0


def _span_spec(spans: list[list[int]], nbytes: int) -> str:
    merged: list[list[int]] = []
    for start, end in spans:
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1][1] = end
        else:
            merged.append([start, end])
    if not merged:
        return ""
    if len(merged) == 1 and merged[0][0] == 0 and merged[0][1] >= nbytes > 0:
        return "*"
    return ",".join(f"{start}-{end}" for start, end in merged)


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
            with open(path, encoding="utf-8", errors="replace", newline="") as handle:
                text = handle.read()
            for number, spec in test_lines(text).items():
                out.write(f"{rel}\t{number}\t{spec}\n")

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    _emit("src", handle)
    _emit("x0x", handle)
PY
    then
        rm -f "$tmp"
        echo "panic scanner could not classify #[cfg(test)] regions" >&2
        exit 1
    fi
    while IFS=$'\t' read -r file num spec; do
        [[ -n "$file" && -n "$num" && -n "$spec" ]] || continue
        IN_TEST["${file}:${num}"]="$spec"
    done < "$tmp"
    rm -f "$tmp"
}

# spec is "*" or comma-separated half-open byte ranges, for example "0-12,40-55".
_offset_in_spans() {
    local offset="$1"
    local spec="$2"
    local part start end
    local IFS=','
    for part in $spec; do
        start=${part%%-*}
        end=${part#*-}
        if (( offset >= start && offset < end )); then
            return 0
        fi
    done
    return 1
}

# Return 0 when every occurrence of pattern on this line is inside a test span.
is_in_test_code() {
    local file="$1"
    local line_num="$2"
    local content="$3"
    local pattern="$4"
    local spec="${IN_TEST["$file:$line_num"]-}"
    local offset found=0
    [[ -n "$spec" ]] || return 1
    [[ "$spec" == "*" ]] && return 0
    while IFS=: read -r offset _; do
        [[ -n "$offset" ]] || continue
        found=1
        if ! _offset_in_spans "$offset" "$spec"; then
            return 1
        fi
    done < <(printf '%s\n' "$content" | grep -aboE -- "$pattern" || true)
    [[ "$found" -eq 1 ]]
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

        # Extract file, line number, and the source line (it may contain ':').
        local file="${match%%:*}"
        local rest="${match#*:}"
        local line_num="${rest%%:*}"
        local content="${rest#*:}"

        # Skip only when the matched bytes themselves sit in a proved test item.
        if is_in_test_code "$file" "$line_num" "$content" "$pattern"; then
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
