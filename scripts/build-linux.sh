#!/bin/bash
# Cross-compile x0x-bootstrap for Linux x64 (VPS deployment)
# Usage: ./scripts/build-linux.sh

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for cargo-zigbuild
if ! command -v cargo-zigbuild >/dev/null 2>&1; then
    log_error "cargo-zigbuild not found"
    log_info "Install with: cargo install cargo-zigbuild"
    log_info "Also install zig: brew install zig (macOS) or apt install zig (Linux)"
    exit 1
fi

# Check for strip utility
if ! command -v strip >/dev/null 2>&1; then
    log_warn "strip utility not found - binary will not be stripped"
fi

TARGET="x86_64-unknown-linux-gnu"
PACKAGE="x0x-bootstrap"
BINARY_NAME="x0x-bootstrap"

log_info "Building $PACKAGE for $TARGET..."

# Build with cargo-zigbuild
log_info "Running cargo zigbuild..."
cargo zigbuild \
    --target "$TARGET" \
    --release \
    -p "$PACKAGE" \
    2>&1 | tee /tmp/build-linux.log

if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
    log_error "Build failed - see /tmp/build-linux.log"
    exit 1
fi

BINARY_PATH="target/$TARGET/release/$BINARY_NAME"

if [[ ! -f "$BINARY_PATH" ]]; then
    log_error "Binary not found: $BINARY_PATH"
    exit 1
fi

log_info "Build successful: $BINARY_PATH"

# Get binary size before stripping
SIZE_BEFORE=$(du -h "$BINARY_PATH" | cut -f1)
log_info "Binary size (before strip): $SIZE_BEFORE"

# Strip debug symbols
if command -v strip >/dev/null 2>&1; then
    log_info "Stripping debug symbols..."
    strip "$BINARY_PATH"
    SIZE_AFTER=$(du -h "$BINARY_PATH" | cut -f1)
    log_info "Binary size (after strip): $SIZE_AFTER"
else
    SIZE_AFTER=$SIZE_BEFORE
fi

# Verify binary
log_info "Verifying binary..."
file "$BINARY_PATH" | tee /tmp/binary-info.txt

if ! file "$BINARY_PATH" | grep -q "ELF 64-bit"; then
    log_error "Binary is not ELF 64-bit x86-64"
    exit 1
fi

log_info "Binary format: OK (ELF 64-bit)"

# Check binary size (should be <30MB)
SIZE_BYTES=$(stat -f%z "$BINARY_PATH" 2>/dev/null || stat -c%s "$BINARY_PATH")
SIZE_MB=$((SIZE_BYTES / 1024 / 1024))

if [[ $SIZE_MB -gt 30 ]]; then
    log_warn "Binary size is ${SIZE_MB}MB (expected <30MB)"
else
    log_info "Binary size check: OK (${SIZE_MB}MB)"
fi

# Optional: Check ldd (only works on Linux)
if command -v ldd >/dev/null 2>&1; then
    log_info "Checking dynamic dependencies..."
    ldd "$BINARY_PATH" 2>&1 | head -10 || log_warn "ldd check failed (expected on macOS)"
fi

log_info ""
log_info "✅ Build complete!"
log_info ""
log_info "Binary location: $BINARY_PATH"
log_info "Final size: $SIZE_AFTER ($SIZE_MB MB)"
log_info ""
log_info "Next steps:"
log_info "  1. Test binary: scp to VPS and run"
log_info "  2. Deploy: .deployment/deploy.sh <node>"
log_info "  3. Verify: .deployment/health-check.sh <node>"
