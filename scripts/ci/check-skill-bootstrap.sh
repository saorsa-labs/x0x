#!/usr/bin/env bash

set -euo pipefail

FILE="SKILL.md"

require() {
    local pattern="$1"
    local message="$2"
    if ! grep -qE "$pattern" "$FILE"; then
        echo "Missing: $message"
        exit 1
    fi
}

require "^## Prerequisites" "Prerequisites section"
require "x0xd daemon" "x0xd daemon prerequisite wording"
require 'there is no `x0x` binary' "binary name clarification"
require "curl -s http://127.0.0.1:12700/health" "health check command"
require "curl -sfL https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh \| sh" "self-bootstrap install command"
require "^## Troubleshooting" "Troubleshooting section"

echo "SKILL.md bootstrap checks passed"
