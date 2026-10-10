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

# A match is test-only when its byte offset sits in a #[cfg(test)],
# #[cfg(all(..., test, ...))], #[test], or #[tokio::test] item, or after a
# crate-level #![cfg(test)]. A nested #![cfg(test)] ends with its module.
# The item ends when its brace body closes, or at ';' / ',' when it has no
# body. Strings stay open until the closing quote, block comments nest, and
# '<' counts as a generic only in type position. A comparison does not.
# A brace that begins a const-generic argument is not the item body, even
# when whitespace or a comment separates it from the comma. Code after the
# closing brace on the same line is still production. Line numbers follow
# grep and split on LF only. Cfg commas inside comments, quotes, or raw
# strings are not predicate separators.
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


def test_lines(text: str) -> dict[int, str]:
    """Return 1-based lines to a test-span spec.

    ``*`` means the whole line is test-only. Otherwise the spec is a
    comma-separated list of half-open byte ranges that are test-only.
    """
    # grep -n splits on LF only. str.splitlines() also breaks on U+2028,
    # U+2029, and form feed, which would mark a later physical line as test.
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    regions: dict[int, str] = {}

    depth = 0
    paren = 0
    bracket = 0
    angle = 0
    block_depth = 0
    in_raw = False
    raw_hashes = 0
    in_string = False
    file_test = False
    bracket_stack: list[dict[str, object]] = []
    const_expr = 0
    type_mode = False
    # Previous non-trivia token. Whitespace, newlines, and comments do not
    # clear it, so a const-generic `{` can sit on the next line.
    prev_token = ""

    active = False
    floor = 0
    paren_floor = 0
    bracket_floor = 0
    phase = "header"  # header | body | after
    mode = ""  # "" | block | expr

    def end_item() -> None:
        nonlocal active, phase, mode, type_mode
        active = False
        phase = "header"
        mode = ""
        type_mode = False

    def in_value_expr() -> bool:
        if const_expr > 0:
            return True
        if any(frame["expr"] for frame in bracket_stack):
            return True
        return not type_mode

    def opens_generic(at: str, i: int) -> bool:
        # '<=' is a comparison. Turbofish '::<' is always a generic.
        # In a value expression, every other '<' is an operator. In type
        # position, '<' after a path or delimiter starts type arguments.
        if i + 1 < len(at) and at[i + 1] == "=":
            return False
        kind, text = _prev_sig(at, i)
        if text == "::":
            return True
        if in_value_expr():
            return False
        if kind == "ident" or text in "><,([{":
            return True
        return kind == "start"

    def remember(token: str) -> None:
        nonlocal prev_token
        prev_token = token

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
            regions[idx + 1] = "*"
            continue

        n = len(line)
        byte_of = [0]
        for character in line:
            byte_of.append(byte_of[-1] + len(character.encode("utf-8")))
        spans: list[list[int]] = []
        # Character index where the current test span opened, if any.
        mark = [0 if (active and phase != "after") else None]

        def stop_marking(at: int) -> None:
            start_i = mark[0]
            if start_i is None:
                return
            mark[0] = None
            if at <= start_i:
                return
            start_b = byte_of[start_i]
            end_b = byte_of[at]
            if spans and start_b <= spans[-1][1]:
                if end_b > spans[-1][1]:
                    spans[-1][1] = end_b
            else:
                spans.append([start_b, end_b])

        def ensure_marking(at: int) -> None:
            if mark[0] is None:
                mark[0] = at

        i = 0
        while i < n:
            ch = line[i]
            nxt = line[i + 1] if i + 1 < n else ""

            if in_raw:
                if ch == '"' and line[i + 1 : i + 1 + raw_hashes] == "#" * raw_hashes:
                    in_raw = False
                    remember('"')
                    i += 1 + raw_hashes
                    continue
                i += 1
                continue

            # A regular string stays open until its closing quote, including
            # across a newline that is not escaped with a backslash.
            if in_string:
                if ch == "\\":
                    if i + 1 >= n:
                        break
                    i += 2
                    continue
                if ch == '"':
                    in_string = False
                    remember('"')
                    i += 1
                    continue
                i += 1
                continue

            # Rust block comments nest. The first */ does not end an outer comment.
            if ch == "/" and nxt == "*":
                block_depth += 1
                i += 2
                continue
            if block_depth:
                if ch == "*" and nxt == "/":
                    block_depth -= 1
                    i += 2
                    continue
                i += 1
                continue

            if ch == "/" and nxt == "/":
                if active and phase == "after":
                    stop_marking(i)
                    end_item()
                elif active:
                    ensure_marking(i)
                    stop_marking(n)
                else:
                    stop_marking(i)
                break

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
                remember("'")
                continue

            if ch == "#":
                kind = _attr_kind(line, i)
                if active and phase == "after":
                    stop_marking(i)
                    end_item()
                if kind == "file":
                    # Crate-level inner attributes cover the rest of the file.
                    # A nested #![cfg(test)] applies only to its enclosing item.
                    if depth == 0:
                        file_test = True
                        mark[0] = 0
                        i = n
                        break
                    if not active:
                        start_item()
                        floor = depth - 1
                        phase = "body"
                        mode = "block"
                        ensure_marking(0)
                    i += len("#![cfg(test)]")
                    remember("]")
                    continue
                if kind in {"cfg", "test"} and not active:
                    start_item()
                    ensure_marking(i)
                i += 1
                continue

            if active and phase == "after":
                if ch.isspace():
                    i += 1
                    continue
                if _word_at(line, i) == "else":
                    phase = "header"
                    mode = ""
                    remember("ident")
                    ensure_marking(i)
                    i += 4
                    continue
                stop_marking(i)
                end_item()
                continue

            if ch == "-" and nxt == ">":
                type_mode = True
                remember(">")
                i += 2
                continue

            if ch == ":":
                if nxt == ":":
                    remember(":")
                    i += 2
                    continue
                type_mode = True
                remember(":")
                i += 1
                continue

            if ch == "=":
                # Associated-type bindings (`Item = Vec<u8>`) stay in type
                # position. An `=` outside angle brackets ends a type.
                if angle == 0:
                    type_mode = False
                remember("=")
                i += 2 if nxt in "=>" else 1
                continue

            if ch == "{":
                if const_expr > 0:
                    const_expr += 1
                    remember("{")
                    if active and phase != "after":
                        ensure_marking(i)
                    i += 1
                    continue
                # `{` starts a const-generic argument only after `<` or `,`.
                # Those tokens stay visible across whitespace, newlines, and
                # comments. `if 1 < 2 { 1 }` is an expression block.
                if (
                    angle > 0
                    and mode == "block"
                    and phase == "header"
                    and prev_token in {"<", ","}
                ):
                    const_expr = 1
                    remember("{")
                    if active:
                        ensure_marking(i)
                    i += 1
                    continue
                if active and phase == "header" and at_item_level():
                    phase = "body"
                    ensure_marking(i)
                remember("{")
                type_mode = False
                depth += 1
                i += 1
                continue

            if ch == "}":
                if const_expr > 0:
                    const_expr -= 1
                    remember("}")
                    if active and phase != "after":
                        ensure_marking(i)
                    i += 1
                    continue
                if depth > 0:
                    depth -= 1
                if (
                    active
                    and phase == "body"
                    and depth == floor
                    and paren == paren_floor
                    and bracket == bracket_floor
                ):
                    phase = "after"
                    i += 1
                    continue
                if (
                    active
                    and phase == "header"
                    and depth < floor
                    and paren == paren_floor
                    and bracket == bracket_floor
                ):
                    stop_marking(i)
                    end_item()
                    continue
                remember("}")
                i += 1
                continue

            if ch == "(":
                remember("(")
                paren += 1
                i += 1
                continue
            if ch == ")":
                if (
                    active
                    and phase == "header"
                    and paren <= paren_floor
                    and depth == floor
                    and bracket == bracket_floor
                ):
                    stop_marking(i)
                    end_item()
                    continue
                remember(")")
                if paren > 0:
                    paren -= 1
                i += 1
                continue
            if ch == "[":
                remember("[")
                bracket_stack.append({"expr": False, "depth": depth, "paren": paren})
                bracket += 1
                i += 1
                continue
            if ch == "]":
                if (
                    active
                    and phase == "header"
                    and bracket <= bracket_floor
                    and depth == floor
                    and paren == paren_floor
                ):
                    stop_marking(i)
                    end_item()
                    continue
                remember("]")
                if bracket_stack:
                    bracket_stack.pop()
                if bracket > 0:
                    bracket -= 1
                i += 1
                continue
            if ch == "<":
                if opens_generic(line, i):
                    angle += 1
                elif nxt == "=":
                    remember("=")
                    i += 2
                    continue
                remember("<")
                i += 1
                continue
            if ch == ">":
                if nxt == "=":
                    remember("=")
                    i += 2
                    continue
                if angle > 0:
                    angle -= 1
                remember(">")
                i += 1
                continue

            if ch == ";":
                remember(";")
                if (
                    bracket_stack
                    and const_expr == 0
                    and depth == bracket_stack[-1]["depth"]
                    and paren == bracket_stack[-1]["paren"]
                ):
                    bracket_stack[-1]["expr"] = True
                elif angle == 0 and const_expr == 0:
                    type_mode = False
                if active and phase == "header" and at_item_level() and const_expr == 0:
                    i += 1
                    stop_marking(i)
                    end_item()
                    continue
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
                remember(",")
                i += 1
                stop_marking(i)
                end_item()
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
                if word in {
                    "fn",
                    "struct",
                    "enum",
                    "impl",
                    "trait",
                    "type",
                    "const",
                    "static",
                    "union",
                    "as",
                }:
                    type_mode = True
                elif word == "for":
                    j = i + len(word)
                    while j < n and line[j].isspace():
                        j += 1
                    # `for<'a>` is a type binder. `for x in` is a loop.
                    type_mode = j < n and line[j] == "<"
                elif word in {"if", "while", "loop", "match", "return", "let"}:
                    type_mode = False
                remember("ident")
                if active and phase != "after":
                    ensure_marking(i)
                i += len(word)
                continue

            if ch.isspace():
                i += 1
                continue
            if active and phase != "after":
                ensure_marking(i)
            remember(ch)
            i += 1

        stop_marking(n)
        spec = _span_spec(spans, byte_of[n])
        if spec:
            regions[idx + 1] = spec

    return regions


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

def _prev_sig(line: str, i: int) -> tuple[str, str]:
    j = i - 1
    while j >= 0 and line[j].isspace():
        j -= 1
    if j < 0:
        return "start", ""
    ch = line[j]
    if ch == ":" and j > 0 and line[j - 1] == ":":
        return "punct", "::"
    if ch in "<>()[]{},;:=+-*/%&|^!":
        return "punct", ch
    if ch.isdigit():
        return "num", ch
    if ch.isalnum() or ch == "_":
        k = j
        while k >= 0 and (line[k].isalnum() or line[k] == "_"):
            k -= 1
        return "ident", line[k + 1 : j + 1]
    return "other", ch


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


def _cfg_all_requires_test(rest: str) -> bool:
    """True when every build of this attribute requires cfg(test).

    Comments are trivia. Ordinary strings and raw strings are one literal,
    so a comma inside them is not a predicate separator. An attribute this
    cannot lex is scanned rather than treated as test-only.
    """
    prefix = "#[cfg(all("
    if not rest.startswith(prefix):
        return False
    n = len(rest)
    i = len(prefix)
    depth = 1
    atoms: list[str] = []
    current: list[str] = []
    while i < n and depth > 0:
        nxt = _cfg_skip_trivia(rest, i)
        if nxt is None:
            return False
        i = nxt
        if i >= n:
            break
        raw_end = _cfg_raw_string_end(rest, i)
        if raw_end is not None:
            if raw_end < 0:
                return False
            current.append(rest[i:raw_end])
            i = raw_end
            continue
        ch = rest[i]
        if ch in "\"'":
            end = _cfg_quoted_end(rest, i)
            if end < 0:
                return False
            current.append(rest[i:end])
            i = end
            continue
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            if depth == 0:
                atoms.append("".join(current).strip())
                return "test" in atoms
            current.append(ch)
        elif ch == "," and depth == 1:
            atoms.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1
    return False


def _cfg_skip_trivia(rest: str, i: int) -> int | None:
    n = len(rest)
    while i < n:
        if rest[i].isspace():
            i += 1
            continue
        if rest.startswith("//", i):
            return None
        if rest.startswith("/*", i):
            comment = 1
            i += 2
            while i < n and comment:
                if rest.startswith("/*", i):
                    comment += 1
                    i += 2
                elif rest.startswith("*/", i):
                    comment -= 1
                    i += 2
                else:
                    i += 1
            if comment:
                return None
            continue
        return i
    return i


def _cfg_raw_string_end(rest: str, i: int) -> int | None:
    """Index after a raw string at i, -1 if unclosed, None if not one."""
    if i > 0 and (rest[i - 1].isalnum() or rest[i - 1] == "_"):
        return None
    j = i
    prefixes = 0
    while prefixes < 2 and j < len(rest) and rest[j] in "bc":
        j += 1
        prefixes += 1
    if j >= len(rest) or rest[j] != "r":
        return None
    j += 1
    hashes = 0
    while j < len(rest) and rest[j] == "#":
        hashes += 1
        j += 1
    if j >= len(rest) or rest[j] != '"':
        return None
    j += 1
    closer = '"' + ("#" * hashes)
    end = rest.find(closer, j)
    if end < 0:
        return -1
    return end + len(closer)


def _cfg_quoted_end(rest: str, i: int) -> int:
    quote = rest[i]
    j = i + 1
    n = len(rest)
    while j < n:
        if rest[j] == "\\":
            j += 2
            continue
        if rest[j] == quote:
            return j + 1
        j += 1
    return -1


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

        # Skip only when the matched bytes themselves sit in a test item.
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
