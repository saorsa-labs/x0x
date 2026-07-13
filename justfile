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

# ── Release ───────────────────────────────────────────────────────────────

# Bump the version everywhere the release `version_sync` gate checks
# (Cargo.toml + SKILL.md) in one shot, then verify they agree. Always use
# this instead of hand-editing a version — hand-editing one file and
# forgetting the other is what broke the 0.22.1 and 0.23.0 release tags.
# Usage: just bump-version 0.24.0
bump-version VERSION:
    bash scripts/bump-version.sh {{VERSION}}

release-dryrun:
    bash scripts/release-dryrun.sh

# ── Convergence soak (tests/convergence) ──────────────────────────────────

# Full soak: repeat the 3-node convergence scenario (cold-join, live
# propagation, restart recovery, concurrent claims, signed-store non-owner
# write, malformed/pre-restart fence, named new-port reconnect) with
# per-phase gossip-diagnostics deltas, EXACT-VALUE oracles, and
# binary/source provenance. Requires a release x0xd
# (`cargo build --release --bin x0xd`) or X0XD_TEST_BINARY. Forwards
# X0XD_LEGACY_BINARY to enable the mixed-version gate. This is a
# DEVELOPMENT soak — it is NOT release-authoritative; use
# `just convergence-release` for the gating recipe.
# Usage: just convergence-soak [RUNS]
convergence-soak RUNS="10":
    python3 tests/convergence/convergence_soak.py --runs {{RUNS}}

# Single-run smoke of the convergence harness (same phases, one pass).
convergence-soak-quick:
    python3 tests/convergence/convergence_soak.py --runs 1

# Authoritative RELEASE convergence recipe. Self-contained: builds the daemon
# AND the in-repo hostile gossip injector (x0xd-forge-injector) so the
# forged-first-seen admission gate runs for real — no undocumented external
# binary required. Requires --expect-fixed (every known-gap becomes a hard
# gate), an AUTHENTICATED v0.30.1 legacy binary (X0XD_LEGACY_BINARY — the only
# artifact that cannot be built from this tree; the harness verifies
# --version == 0.30.1), and 10/10 clean runs. The harness refuses a binary
# older than the reviewed sources. Under --expect-fixed an UNSUPPORTED or
# unproven phase is a FAILURE, and provenance refusal fails fast. UNSUPPORTED
# is failure: this recipe gates a release. convergence-soak-quick stays
# available as a one-run smoke.
convergence-release:
    @test -n "${X0XD_LEGACY_BINARY:-}" || { echo "X0XD_LEGACY_BINARY must point at an authenticated v0.30.1 x0xd"; exit 2; }
    cargo build --release --bin x0xd --bin x0xd-forge-injector
    python3 tests/convergence/convergence_soak.py --runs 10 --expect-fixed
