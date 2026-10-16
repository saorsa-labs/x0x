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

# Proved test spans and comment spans, keyed as "path:line". Bash 4 keeps
# them in memory. Bash 3.2 (macOS /bin/bash) has no associative arrays, so
# lookup reads REGIONS_FILE instead. `declare -A` runs only on Bash 4+.
USE_ASSOC=0
REGIONS_FILE=""
if [ "${BASH_VERSINFO[0]:-0}" -ge 4 ] && [ -z "${X0X_PANIC_SCAN_FILE_REGIONS:-}" ]; then
    USE_ASSOC=1
    declare -A IN_TEST=()
    declare -A IN_COMMENT=()
fi
cleanup_regions() {
    if [ -n "${REGIONS_FILE:-}" ]; then
        rm -f "$REGIONS_FILE"
    fi
}
trap cleanup_regions EXIT

# A span is test-only only when a test attribute and that item's closing
# delimiter are both proved. Attributes are the exact forms in this tree:
# #[cfg(test)], #![cfg(test)], #[cfg(all(test, unix))], #[test], #[tokio::test],
# and #[tokio::test(...)]. A body closes at the matching '}'. An item with no
# body closes at ';' or ','. A crate-level #![cfg(test)] (no open brace, paren,
# or bracket) runs to EOF. A nested #![cfg(test)] closes with its module. An
# attribute inside an unclassified macro argument does not start a region:
# the macro can drop it and emit the item as production code. A weak keyword
# (such as union) and a raw identifier (r#name) are macro names. A name that
# can be either an item or a macro stays unclassified across whitespace and
# comments. The next significant token decides: '!' is a macro, anything else
# is an item. A proved
# enclosing test item still covers those bytes. '-> !' is a never type, not
# a macro. A macro token tree in a signature or expression is not the body. A
# macro item closes at its '}' or at ';' / ',' after ')' or ']'. An attributed
# element also ends when its enclosing array or tuple closes. An unclosed
# string, comment, or item is not committed. Line numbers follow grep. Bytes
# after the closing delimiter on the same line stay production. A comment does
# not hide a panic, and '//' inside a string is not a comment.
load_test_regions() {
    local tmp
    tmp=$(mktemp)
    REGIONS_FILE=$tmp
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


INTRODUCERS = frozenset({
    "fn", "struct", "enum", "mod", "trait", "impl", "type", "const", "static",
    "use", "union", "async", "unsafe", "extern", "where",
    "if", "while", "loop", "match", "let", "for", "return", "else", "move",
})
# Weak keywords may name a macro. union is also an item introducer.
WEAK_KEYWORDS = frozenset({"union", "macro_rules", "safe", "raw"})
_CLOSERS = {"{": "}", "(": ")", "[": "]"}


def test_lines(text: str) -> tuple[dict[int, str], dict[int, str]]:
    """Return proved test spans and comment spans, keyed by 1-based line.

    ``*`` means the whole line. Otherwise the spec is a comma-separated list
    of half-open byte ranges.
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
    comments: dict[int, list[list[int]]] = {}
    depth = 0
    paren = 0
    bracket = 0
    block = 0
    in_string = False
    in_raw = False
    raw_hashes = 0
    # (line, byte just after the brace) for each unmatched '{'.
    opens: list[tuple[int, int]] = []
    # (closer, is_item) for a macro token tree in a header.
    macro_frames: list[tuple[str, bool]] = []

    active = False
    body = False
    floor = 0
    paren_floor = 0
    bracket_floor = 0
    origin: tuple[int, int] | None = None
    file_test = False
    ident = ""
    prev_token = ""
    saw_introducer = False
    # Introducer that may still be a macro once separators are skipped.
    pending_introducer = False
    pending = False
    pending_item = False
    # The next '(' / '[' / '{' is an unclassified macro argument.
    await_macro = False
    comment_origin: tuple[int, int] | None = None

    def add_span(store: dict[int, list[list[int]]], line_no: int, start: int, end: int) -> None:
        if end <= start:
            return
        store.setdefault(line_no, []).append([start, end])

    def add_range(store: dict[int, list[list[int]]], start_line: int, start_byte: int, end_line: int, end_byte: int) -> None:
        if end_line <= start_line:
            add_span(store, start_line, start_byte, end_byte)
            return
        add_span(store, start_line, start_byte, line_bytes[start_line - 1])
        for mid in range(start_line + 1, end_line):
            add_span(store, mid, 0, line_bytes[mid - 1])
        add_span(store, end_line, 0, end_byte)

    def _clear_header() -> None:
        nonlocal active, body, origin, ident, prev_token, saw_introducer, pending_introducer, pending, pending_item, await_macro
        active = False
        body = False
        origin = None
        ident = ""
        prev_token = ""
        saw_introducer = False
        pending_introducer = False
        pending = False
        pending_item = False
        await_macro = False
        macro_frames.clear()

    def commit(end_line: int, end_byte: int) -> None:
        if origin is not None:
            add_range(regions, origin[0], origin[1], end_line, end_byte)
        _clear_header()

    def discard() -> None:
        _clear_header()

    def at_item_level() -> bool:
        return depth == floor and paren == paren_floor and bracket == bracket_floor

    def _finish_ident(ch: str = "", nxt: str = "") -> None:
        nonlocal ident, prev_token, saw_introducer, pending_introducer
        if not ident:
            return
        prev_token = ident
        # An adjacent '!' is a macro. A separator is not a decision yet.
        macro_bang = ch == "!" and nxt != "=" and _is_macro_name(ident)
        if (
            active
            and not body
            and not macro_frames
            and not pending
            and at_item_level()
            and ident in INTRODUCERS
            and not macro_bang
        ):
            if _is_macro_name(ident) and _is_separator(ch, nxt):
                pending_introducer = True
            else:
                saw_introducer = True
        ident = ""

    def _open_frame(ch: str, is_item: bool, i: int) -> int:
        nonlocal depth, paren, bracket
        macro_frames.append((_CLOSERS[ch], is_item))
        i += 1
        if ch == "{":
            depth += 1
            opens.append((line_no, byte_ofs[idx][i]))
        elif ch == "(":
            paren += 1
        else:
            bracket += 1
        return i

    def _close_frame(i: int) -> tuple[int, bool, str]:
        nonlocal depth, paren, bracket
        closer, is_item = macro_frames.pop()
        i += 1
        if closer == "}":
            if depth > 0:
                depth -= 1
            if opens:
                opens.pop()
        elif closer == ")":
            if paren > 0:
                paren -= 1
        elif bracket > 0:
            bracket -= 1
        return i, is_item, closer

    for idx, line in enumerate(lines):
        line_no = idx + 1
        if file_test:
            add_span(regions, line_no, 0, line_bytes[idx])
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
                    if block == 0 and comment_origin is not None:
                        add_range(comments, comment_origin[0], comment_origin[1], line_no, byte_ofs[idx][i])
                        comment_origin = None
                    continue
                i += 1
                continue

            if ident == "r" and ch == "#":
                # Do not reuse `body`: that flag means the test item has opened.
                raw_name = _raw_ident_body(line, i + 1)
                if raw_name is not None:
                    ident = "r#" + raw_name
                    i += 1 + len(raw_name)
                    continue

            if ident and not (ch.isalnum() or ch == "_"):
                _finish_ident(ch, nxt)

            if ch.isspace():
                i += 1
                continue

            if ch == "/" and nxt == "/":
                add_span(comments, line_no, byte_ofs[idx][i], line_bytes[idx])
                break
            if ch == "/" and nxt == "*":
                block = 1
                comment_origin = (line_no, byte_ofs[idx][i])
                i += 2
                continue

            if pending_introducer:
                # The next significant token chooses item or macro.
                if not (ch == "!" and nxt != "=" and _is_macro_name(prev_token)):
                    if (
                        active
                        and not body
                        and not macro_frames
                        and not pending
                        and at_item_level()
                    ):
                        saw_introducer = True
                pending_introducer = False

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
                prev_token = "'"
                continue

            if macro_frames:
                if ch in "({[":
                    i = _open_frame(ch, False, i)
                    continue
                if ch == macro_frames[-1][0]:
                    i, is_item, closer = _close_frame(i)
                    if not macro_frames and is_item and closer == "}":
                        commit(line_no, byte_ofs[idx][i])
                    continue
                i += 1
                continue

            if pending:
                if ch in "({[":
                    is_item = pending_item
                    pending = False
                    i = _open_frame(ch, is_item, i)
                    continue
                if ch.isalnum() or ch == "_":
                    while i < n and (line[i].isalnum() or line[i] == "_"):
                        i += 1
                    continue
                pending = False
                discard()

            if await_macro:
                if ch in "({[":
                    await_macro = False
                    i = _open_frame(ch, False, i)
                    continue
                if ch.isalnum() or ch == "_":
                    while i < n and (line[i].isalnum() or line[i] == "_"):
                        i += 1
                    continue
                await_macro = False

            if line[:i].strip() == "":
                kind, length = _attr_kind(line[i:])
                if kind == "file" and depth == 0 and paren == 0 and bracket == 0:
                    file_test = True
                    add_span(regions, line_no, byte_ofs[idx][i], line_bytes[idx])
                    break
                if kind == "file" and depth > 0 and not active:
                    active = True
                    body = True
                    floor = depth - 1
                    paren_floor = paren
                    bracket_floor = bracket
                    origin = opens[-1] if opens else (line_no, byte_ofs[idx][i])
                    saw_introducer = False
                    i += length
                    continue
                if kind == "file":
                    i += length
                    continue
                if kind == "item":
                    if active and not body:
                        discard()
                    if not active:
                        active = True
                        body = False
                        floor = depth
                        paren_floor = paren
                        bracket_floor = bracket
                        origin = (line_no, byte_ofs[idx][i])
                        saw_introducer = False
                        i += length
                        continue

            if ch.isalnum() or ch == "_":
                ident += ch
                i += 1
                continue

            if ch == "!" and nxt != "=" and _is_macro_name(prev_token):
                if active and not body:
                    pending = True
                    pending_item = (not saw_introducer) and at_item_level()
                else:
                    # Not a proved test header. The argument stays production
                    # even when it contains a test attribute.
                    await_macro = True
                prev_token = "!"
                i += 1
                continue

            if ch == "-" and nxt == ">":
                prev_token = "->"
                i += 2
                continue

            if ch == "{":
                if active and not body and at_item_level():
                    body = True
                depth += 1
                i += 1
                opens.append((line_no, byte_ofs[idx][i]))
                continue
            if ch == "}":
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
                if (
                    active
                    and not body
                    and paren < paren_floor
                    and depth == floor
                    and bracket == bracket_floor
                ):
                    i += 1
                    commit(line_no, byte_ofs[idx][i])
                    continue
                i += 1
                continue
            if ch == "[":
                bracket += 1
                i += 1
                continue
            if ch == "]":
                if bracket > 0:
                    bracket -= 1
                if (
                    active
                    and not body
                    and bracket < bracket_floor
                    and depth == floor
                    and paren == paren_floor
                ):
                    i += 1
                    commit(line_no, byte_ofs[idx][i])
                    continue
                i += 1
                continue
            if ch == ";" and active and not body and at_item_level():
                i += 1
                commit(line_no, byte_ofs[idx][i])
                continue
            if ch == "," and active and not body and at_item_level():
                i += 1
                commit(line_no, byte_ofs[idx][i])
                continue
            prev_token = ch
            i += 1

        if ident:
            _finish_ident()

    # An unclosed comment is not proved, so those bytes stay production.
    if active:
        discard()

    return _specs(regions, line_bytes), _specs(comments, line_bytes)


def _is_ident(token: str) -> bool:
    if not token or token[0].isdigit() or not (token[0].isalpha() or token[0] == "_"):
        return False
    return all(ch.isalnum() or ch == "_" for ch in token)


def _raw_ident_body(line: str, start: int) -> str | None:
    """Identifier after ``r#``, or None when this is a raw string."""
    if start >= len(line):
        return None
    ch = line[start]
    if ch in "\"#":
        return None
    if not (ch.isalpha() or ch == "_"):
        return None
    end = start + 1
    while end < len(line) and (line[end].isalnum() or line[end] == "_"):
        end += 1
    return line[start:end]


def _is_separator(ch: str, nxt: str) -> bool:
    """Whitespace, a line break, or a comment is not a classification token."""
    if ch == "" or ch.isspace():
        return True
    return ch == "/" and nxt in "/*"


def _is_macro_name(token: str) -> bool:
    if token.startswith("r#") and _is_ident(token[2:]):
        return True
    if not _is_ident(token):
        return False
    if token in INTRODUCERS and token not in WEAK_KEYWORDS:
        return False
    return True


def _specs(spans_by_line: dict[int, list[list[int]]], line_bytes: list[int]) -> dict[int, str]:
    specs: dict[int, str] = {}
    for number, spans in spans_by_line.items():
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
            tests, comment_spans = test_lines(text)
            numbers = set(tests) | set(comment_spans)
            for number in sorted(numbers):
                out.write(
                    f"{rel}\t{number}\t{tests.get(number, '')}\t{comment_spans.get(number, '')}\n"
                )

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    _emit("src", handle)
    _emit("x0x", handle)
PY
    then
        rm -f "$tmp"
        REGIONS_FILE=""
        echo "panic scanner could not classify #[cfg(test)] regions" >&2
        exit 1
    fi
    if [ "$USE_ASSOC" -eq 1 ]; then
        while IFS=$'\t' read -r file num test_spec comment_spec; do
            [[ -n "$file" && -n "$num" ]] || continue
            if [[ -n "$test_spec" ]]; then
                IN_TEST["${file}:${num}"]="$test_spec"
            fi
            if [[ -n "$comment_spec" ]]; then
                IN_COMMENT["${file}:${num}"]="$comment_spec"
            fi
        done < "$tmp"
        rm -f "$tmp"
        REGIONS_FILE=""
    fi
}

# spec is "*" or comma-separated half-open byte ranges, for example "0-12,40-55".
_offset_in_spans() {
    local offset="$1"
    local spec="$2"
    local part start end
    [[ -n "$spec" ]] || return 1
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

# Return 0 when every match sits in a proved test span or a comment span.
is_in_test_code() {
    local file="$1"
    local line_num="$2"
    local content="$3"
    local pattern="$4"
    local test_spec="" comment_spec="" row offset found=0
    if [ "$USE_ASSOC" -eq 1 ]; then
        test_spec="${IN_TEST["$file:$line_num"]-}"
        comment_spec="${IN_COMMENT["$file:$line_num"]-}"
    else
        row=$(awk -F '\t' -v f="$file" -v n="$line_num" '
            $1 == f && $2 == n { printf "%s\t%s", $3, $4; exit }
        ' "$REGIONS_FILE") || row=""
        if [[ "$row" == *$'\t'* ]]; then
            test_spec=${row%%$'\t'*}
            comment_spec=${row#*$'\t'}
        else
            test_spec=$row
            comment_spec=""
        fi
    fi
    [[ -n "$test_spec" || -n "$comment_spec" ]] || return 1
    if [[ "$test_spec" == "*" || "$comment_spec" == "*" ]]; then
        return 0
    fi
    while IFS=: read -r offset _; do
        [[ -n "$offset" ]] || continue
        found=1
        if ! _offset_in_spans "$offset" "$test_spec" && ! _offset_in_spans "$offset" "$comment_spec"; then
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
        # Skip tests/ paths, a file named tests.rs (a `#[cfg(test)] mod tests`
        # submodule, for example src/connect/acl/tests.rs), and .bak files.
        # Comment matches are spans, so '//' inside a string does not skip the line.
        if echo "$match" | grep -qE "(tests/|/tests\.rs:|\.bak:)"; then
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
