# MANDATORY: Pre-Submit Checks for Rust Patches

**Before submitting ANY patch that touches Rust code (`*.rs`, `Cargo.toml`, `Cargo.lock`), you MUST run, in this exact order, until all three pass clean:**

1. `cargo fmt --all`
2. `cargo clippy --all-features --all-targets -- -D warnings`
3. `cargo check --workspace --all-targets`

Re-run after every code change. Do not silence warnings with `#[allow(...)]` unless the surrounding code already does. If a fix cannot pass these checks, report what failed — do NOT submit a known-failing patch.

External validation pipelines (clawpatch, CI) gate on the standard `--all-targets -- -D warnings` clippy check. Do **not** add extra `-D clippy::panic`, `-D clippy::unwrap_used`, `-D clippy::expect_used`, or similar custom denies for this gate; those trip on existing test code and are stricter than CI.

---
# AGENTS.md

This file provides guidance to Codex and other AI coding assistants.

For comprehensive architecture documentation, build commands, API surface, test organization, and module details, see **[CLAUDE.md](./CLAUDE.md)** — the canonical reference for this repository.
