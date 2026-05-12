# x0x justfile — standard Saorsa Labs recipes plus x0x-specific tooling.
#
# Run `just --list` to see every recipe.

set shell := ["bash", "-uc"]
set dotenv-load := false

default:
    @just --list

# ── Core Rust checks ──────────────────────────────────────────────────────

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --all-targets --all-features -- -D warnings

test:
    cargo nextest run --all-features --workspace

test-verbose:
    cargo nextest run --all-features --workspace --no-capture

build:
    cargo build --all-features

build-release:
    cargo build --release --all-features

doc:
    cargo doc --all-features --no-deps

clean:
    cargo clean

quick-check: fmt-check lint test

check: fmt-check lint build test doc

# ── Test coverage (line/region) ───────────────────────────────────────────
#
# Uses cargo-llvm-cov + nextest. Install once with:
#   cargo install cargo-llvm-cov --locked
# Coverage data lives under target/llvm-cov-target/ — `just coverage-clean`
# wipes it if results look stale.

# Run the full nextest suite under llvm-cov and open an HTML report.
coverage:
    cargo llvm-cov --all-features --workspace --html nextest

# Print a one-shot text summary (fast — useful before pushing).
coverage-summary:
    cargo llvm-cov --all-features --workspace --summary-only nextest

# Emit lcov.info for editors (e.g. Coverage Gutters) and future CI uploads.
coverage-lcov:
    cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info nextest

# Run the CI-style floor gate and advisory per-module threshold report.
coverage-check:
    cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info --fail-under-lines 48 nextest
    python3 scripts/check-coverage-thresholds.py --lcov lcov.info --thresholds coverage-thresholds.toml --enforce-global

# Wipe cached profraw/profdata when results look stale.
coverage-clean:
    cargo llvm-cov clean --workspace

# ── GUI coverage (API-surface, not line coverage) ─────────────────────────

# Build the coverage tool and run it against src/gui/x0x-gui.html.
gui-coverage:
    cargo build --release --bin gui-coverage
    ./target/release/gui-coverage

# Same but emit JSON for CI consumption.
gui-coverage-json:
    cargo build --release --bin gui-coverage
    ./target/release/gui-coverage --json

# ── Routes inspection ─────────────────────────────────────────────────────

# Print all API routes in human-readable table form.
routes:
    cargo run --release --bin x0x -- routes

# Emit all API routes as JSON (consumed by tooling and CI).
routes-json:
    cargo run --release --bin x0x -- routes --json

# ── Cross-compilation (VPS deploy) ────────────────────────────────────────

build-linux:
    cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin x0xd

# ── Release dry-run ───────────────────────────────────────────────────────

release-dryrun:
    bash scripts/release-dryrun.sh
