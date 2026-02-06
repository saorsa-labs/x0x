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

    # Check if file contains #[cfg(test)] or #[test] before the line
    awk -v line="$line_num" '
        NR <= line {
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
        # Skip if in tests/ directory or .bak files
        if echo "$match" | grep -qE "(tests/|\.bak:|\.rs:.*//.*$pattern)"; then
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
    done < <(grep -rn "$pattern" $paths 2>/dev/null || true)

    if [ $found_in_prod -eq 1 ]; then
        echo -e "${RED}✗ FOUND: $description in production code${NC}"
        FOUND_ISSUES=$((FOUND_ISSUES + 1))
    else
        echo -e "${GREEN}✓ PASS: No $description in production code${NC}"
    fi
    echo ""
}

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
