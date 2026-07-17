# MANDATORY: Pre-Submit Checks for Rust Patches

**Before submitting ANY patch that touches Rust code (`*.rs`, `Cargo.toml`, `Cargo.lock`), you MUST run, in this exact order, until all three pass clean:**

1. `cargo fmt --all`
2. `cargo clippy --all-features --all-targets -- -D warnings`
3. `cargo check --workspace --all-targets`

Re-run after every code change. Do not silence warnings with `#[allow(...)]` unless the surrounding code already does. If a fix cannot pass these checks, report what failed — do NOT submit a known-failing patch.

### Gate execution rules (learned the hard way — red PRs shipped through these holes)

- **NEVER pipe a gate through `tail`/`head`/`grep` in a `&&` chain.** `cargo clippy ... 2>&1 | tail -5 && cargo nextest run ...` exits with `tail`'s status, so a FAILING clippy reads as success and the chain continues. Run each gate as its own command with its own exit code; if a pipeline is unavoidable, prefix with `set -o pipefail`, and print full output on failure — not a truncated tail.
- **Gates must pass on the exact tree that gets pushed.** Re-run after every amend/fixup/review-loop commit, not just once early in the session. A gate pass on an earlier commit proves nothing about the pushed one.
- **Every agent that lands commits owns a gate pass over its own diff** (workers, reviewers, orchestrators alike). "The next agent runs the gate" is how rustfmt/clippy failures end up in PRs. If you were told to skip gates, the agent that pushes MUST run them — no exceptions.
- **A `| tail`-style output filter is fine for readability only AFTER the gate's exit code has been captured and checked** (`GATE_OUTPUT=$(cargo clippy ... 2>&1); echo $?; echo "$GATE_OUTPUT" | tail -20`).

External validation pipelines (clawpatch, CI) gate on the standard `--all-targets -- -D warnings` clippy check. Do **not** add extra `-D clippy::panic`, `-D clippy::unwrap_used`, `-D clippy::expect_used`, or similar custom denies for this gate; those trip on existing test code and are stricter than CI.

---
# AGENTS.md

This file provides guidance to Codex and other AI coding assistants.

For comprehensive architecture documentation, build commands, API surface, test organization, and module details, see **[CLAUDE.md](./CLAUDE.md)** — the canonical reference for this repository.
