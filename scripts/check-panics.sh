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

# Function to check if a file line is in a test module or function
is_in_test_code() {
    local file="$1"
    local line_num="$2"

    # Check if file contains #[cfg(test)] or #[test] before the line.
    # Also honour the inner `#![cfg(test)]` attribute, which gates an entire
    # file as test-only (e.g. src/cli/commands/test_support.rs); once seen it
    # applies to every subsequent line in the file.
    awk -v line="$line_num" '
        NR <= line {
            if (/^[[:space:]]*#!\[cfg\(test\)\]/) {
                in_test = 1
            }
            if (/^[[:space:]]*#\[cfg\(test\)\]/ || /^[[:space:]]*#\[test\]/) {
                in_test = 1
            }
            if (in_test && /^[[:space:]]*mod [a-z_]+ \{/) {
                test_module = 1
            }
        }
        END { if (in_test || test_module) exit 0; else exit 1; }
    ' "$file"
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

# Scan for problematic patterns
scan_pattern "\.unwrap()" ".unwrap() calls"
scan_pattern "\.expect\(" ".expect() calls"
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
