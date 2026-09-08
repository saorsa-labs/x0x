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
    python3 scripts/dev/test-isolated.py nextest --all-features --workspace --

test-verbose:
    python3 scripts/dev/test-isolated.py nextest --all-features --workspace -- --no-capture

# Full-coverage suite run. nextest is fail-fast by default: the first failure
# cancels everything still queued, so a single flake can hide up to ~800
# unexecuted tests (observed 2503/3300 and 2885/3300 partial runs during
# v0.41.1 post-release verification). Use this whenever a run must prove the
# whole suite rather than everything-up-to-first-failure.
test-full:
    python3 scripts/dev/test-isolated.py nextest --all-features --workspace -- --no-fail-fast

# Run the F1 GSS-rotation ADR gate tests (gate 3 ordering + gate 7a
# producer). The filter `test(/(^|::)f1_/)` selects the five f1_
# tests added to `mod tests` in src/server/routes/named_groups.rs. The
# `(^|::)` form also discovers future top-level integration tests.
# `--no-fail-fast --test-threads=1` is required so the §7a mutation
# receipt's PASS/PASS/FAIL split by test name is unambiguous.
adr-gates-f1:
    python3 scripts/dev/test-isolated.py nextest -p x0x --all-features -- --no-fail-fast --test-threads=1 -E 'test(/(^|::)f1_/)'

# Live counterpart to `adr-gates-f1`: spawns three real x0xd daemons and proves
# the ADMIN REMOVE path rotates the GSS secret cross-daemon. Separate from
# `adr-gates-f1` because the test is `#[ignore]`d (real daemons, ~1 min) and so
# is not selected by that recipe's default run. Validated against a pre-F1
# build (e301371), where R1 and R3 fail — see the file header.
adr-gates-f1-live:
    python3 scripts/dev/test-isolated.py nextest -p x0x --all-features -- --no-fail-fast --test-threads=1 --run-ignored all -E 'test(/(^|::)f1_.*_live/)'

build:
    cargo build --all-features

build-release:
    cargo build --release --all-features

doc:
    cargo doc --all-features --no-deps

clean:
    cargo clean

quick-check: fmt-check lint test

# ── Deployment authority (ADR 0026, design chapter §3) ────────────────────

# Reconcile .deployment/ against the authoritative instance inventory: fails
# on a competing/second production authority, a flag-less or disagreeing prod
# unit --config (§6 step 2), a missing declared artifact, an orphan unit or
# config, a duplicate root, or deploy-443.sh cloning a non-authoritative
# config. Pure bash — no fleet contact, no Rust. Reached by `just check` and
# by pull-request CI.
deploy-check:
    bash .deployment/scripts/check-authority.sh

# Exercise every disclosed control against temp copies (each must flip red).
deploy-check-selftest:
    bash .deployment/scripts/check-authority.sh --self-test

check: fmt-check deploy-check lint build test doc audit deny

# KV append-only REST/e2e suite (#[ignore] — boots real x0xd daemons, so it
# needs a built binary and cannot run hermetically under plain `just test`).
test-kv-e2e:
    python3 scripts/dev/test-isolated.py check
    cargo build --release --bin x0xd
    python3 scripts/dev/test-isolated.py nextest --all-features --test kv_append_only_rest -- -- --ignored

# CRDT-subscription restart-recovery suite (#[ignore] — boots real x0xd
# daemons; covers the issue #238 rehydration-wedge and zombie-subscription
# regressions plus the original restart-amnesia tests).
test-recovery-e2e:
    python3 scripts/dev/test-isolated.py check
    cargo build --bin x0xd
    python3 scripts/dev/test-isolated.py nextest --all-features --test crdt_subscription_persistence -- --run-ignored all

# Issue #277 datagram-lane acceptance (ADR-0042 (c)) — #[ignore]d because it
# binds real UDP sockets on loopback. Two independent halves in one suite:
# the deterministic jitter-counter phase oracles (exact reordered /
# late_dropped / duplicates_dropped deltas on a clean lane) and the
# loss/resilience/SNR/latency/path-custody posture behind a lossy proxy.
# Single-threaded: the phase oracles assert exact counters and must not
# contend for the runner.
#
# This developer entrypoint uses the same Linux isolation/custody wrappers as
# CI. Unsupported hosts fail closed; it does not grant final acceptance credit.
test-voice-datagram-e2e:
    python3 scripts/dev/test-isolated.py voice

# ── Test coverage (line/region) ───────────────────────────────────────────
#
# Uses cargo-llvm-cov + nextest. Install once with:
#   cargo install cargo-llvm-cov --locked
# Each invocation retains a fresh coverage target under its printed
# target/dev-isolation/run-*/ directory. Clean only an explicit completed run.

# Run the full nextest suite under llvm-cov and open an HTML report.
coverage:
    python3 scripts/dev/test-isolated.py coverage --all-features --workspace -- --package '*' --html

# Print a one-shot text summary (fast — useful before pushing).
coverage-summary:
    python3 scripts/dev/test-isolated.py coverage --all-features --workspace -- --package '*' --summary-only

# Emit lcov.info for editors (e.g. Coverage Gutters) and future CI uploads.
coverage-lcov:
    python3 scripts/dev/test-isolated.py coverage --all-features --workspace -- --package '*' --lcov --output-path lcov.info

# Run the CI-style floor gate and advisory per-module threshold report.
coverage-check:
    python3 scripts/dev/test-isolated.py coverage --all-features --workspace -- --package '*' --lcov --output-path lcov.info --fail-under-lines 48
    python3 scripts/check-coverage-thresholds.py --lcov lcov.info --thresholds coverage-thresholds.toml --enforce-global

# Remove only a completed developer run's coverage target; preserve custody.
coverage-clean RUN:
    python3 scripts/dev/test-isolated.py coverage-clean {{quote(RUN)}}

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

# ADR-014 modern-only RELEASE convergence recipe (additive; stock
# `convergence-release` unchanged). Fail-closed if X0XD_LEGACY_BINARY is set
# (stock-in-modern-predicate refused). Builds x0xd + x0xd-forge-injector, then
# runs soak --runs 10 --expect-fixed --modern-only (mixed-version labeled
# not_in_modern_predicate; never PASS). modern_policy_admission fails closed
# until #546 diagnostics prove outer_signature_policy=reject_v1 and legacy
# grants disabled on the freeze tip (incomplete_policy/fail both block).
# Do not fake 10/10 here.
convergence-release-modern:
    @if [ -n "${X0XD_LEGACY_BINARY:-}" ]; then echo "REFUSING convergence-release-modern: X0XD_LEGACY_BINARY must be unset (ADR-014 fail-closed)"; exit 2; fi
    cargo build --release --bin x0xd --bin x0xd-forge-injector
    python3 tests/convergence/convergence_soak.py --runs 10 --expect-fixed --modern-only

# Check dependencies against the RustSec advisory database (supply-chain guard)
audit:
    cargo audit

# Block banned/typosquat crates and unknown sources (supply-chain guard)
deny:
    cargo deny check bans sources
