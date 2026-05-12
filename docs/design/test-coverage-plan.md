# Test Coverage Plan — Path to 90%

**Status**: draft for team review
**Owner**: TBA
**Date**: 2026-05-12
**Tooling**: `cargo-llvm-cov` 0.8.6 + `cargo-nextest` (already wired)
**Mandate**: bring workspace line coverage to **≥ 90%**, without padding the suite with tests that fail Rule 9 ("tests verify intent, not just behavior").

---

## 1. Baseline (2026-05-12, workspace, all-features, nextest)

| Metric | Covered | Missed | **%** |
|---|---|---|---|
| Lines | 18,534 / 38,655 | 20,121 | **47.95%** |
| Regions | 30,985 / 59,643 | 28,658 | **51.95%** |
| Functions | 2,136 / 4,031 | 1,895 | **52.99%** |

**Headline target**: 90% of lines covered → at most **3,866** uncovered lines remain. We need to cover **16,256 additional lines** (an 81% reduction in misses).

**Pre-existing artefacts that are *not* line coverage and are kept as-is**:
- `tests/api_coverage.rs` — REST handler ↔ test reference guard
- `src/bin/gui_coverage.rs` — GUI HTML ↔ endpoint guard

These remain in CI as **surface-coverage gates**. They complement, not replace, the line/region coverage measured here.

---

## 2. Gap inventory (where the 20,121 missed lines live)

| Bucket | Files / area | Missed lines | Cause |
|---|---|---|---|
| **A. CLI command handlers** | `src/cli/commands/*.rs` + `src/cli/mod.rs` | ~3,800 | Driven by the binary; library nextest never exercises them. Most are at 0%. |
| **B. REST handler + Agent core** | `src/lib.rs` (8,404 lines, 50.69% covered) | ~3,400 | `Agent` builder branches, REST handler bodies, error mapping. |
| **C. Exec subsystem** | `exec/service.rs` (48%), `exec/audit.rs` (33%) | ~930 | New feature; happy-path-only tests. ACL deny, timeout, audit emission missing. |
| **D. Network transport** | `network.rs` (68%) | ~840 | Real-network branches; ant-quic error paths; reconnection logic. |
| **E. Direct messaging** | `dm_send.rs` (44%), `dm_inbox.rs` (55%), `dm.rs` (90%) | ~580 | Retry/dedupe/back-pressure paths under-tested. |
| **F. Self-update** | `upgrade/apply.rs` (51%), `upgrade/monitor.rs` (14%), `upgrade/mod.rs` (87%), `upgrade/signature.rs` (88%) | ~600 | Filesystem-bound code; needs tempdir harness + signature-failure paths. |
| **G. Gossip pipeline** | `gossip/pubsub.rs` (80%), `gossip/runtime.rs` (84%) | ~510 | Back-pressure, subscriber-channel-closed, decode-error branches. |
| **H. Sync / persistence** | `crdt/sync.rs` (57%), `crdt/persistence.rs` (0%), `kv/sync.rs` (54%) | ~290 | No direct unit tests of the sync state machines. |
| **I. Identity / storage** | `identity.rs` (84%), `storage.rs` (78%) | ~305 | Cert verification edge cases, storage-IO error injection. |
| **J. Groups (MLS-adjacent)** | `groups/kem_envelope.rs` (63%), `groups/mod.rs` (82%), `mls/group.rs` (90%) | ~250 | KEM failure paths, member-change races. |
| **K. Presence / contacts** | `presence.rs` (86%), `contacts.rs` (97%) | ~200 | FOAF walks, trust-decision branches. |

**Total addressable**: ~11,700 lines from named buckets. The remaining ~8,400 lines are scattered across files in the 80–95% band (most of `crdt/*`, `groups/*`, `mls/*`, `kv/*`). Closing those is mechanical: error paths, edge cases, one-off branches.

---

## 3. Strategy

### 3.1 Principles

1. **Tests encode intent, not behaviour.** Every new test answers a *why* — a business invariant, a regression we never want again, a correctness property. If a test can still pass after a meaningful logic change, it is wrong (CLAUDE.md Rule 9).
2. **Refactor before mocking.** If code is hard to test, the design is wrong, not the test. Prefer extracting a pure function or accepting a trait param over heavy mock scaffolding.
3. **Coverage is a measurement, not a goal.** The goal is "every meaningful branch has a reason to exist and a test that fires when its reason disappears." 90% falls out.
4. **Honesty over padding.** Genuinely unreachable lines (transport-layer OS errors, defensive `unreachable!`) get explicit exclusions with a written reason. We never write a do-nothing test to hit a line.
5. **Parallel workstreams.** The buckets above are independent; assign one owner each.

### 3.2 Phased ratchet

| Phase | Floor | Scope | Gate behaviour |
|---|---|---|---|
| Baseline | 48% | Wire `cargo-llvm-cov` into CI, publish LCOV artifact, PR-comment delta. Floor enforced loosely. | CI fails if coverage drops by **> 0.5%** vs `main`. |
| Phase 1 | **65%** | Buckets A (CLI), H (sync/persistence), G (gossip back-pressure), small wins in I/J/K. | Floor raised; per-PR delta gate remains. |
| Phase 2 | **80%** | Buckets B (REST/Agent), C (exec), E (DM), F (upgrade). | Floor raised; per-module advisory targets published. |
| Phase 3 | **90%** | Bucket D (network), remaining stragglers in B/C/F, final sweep. | Floor at 90%; PRs that cannot maintain it must propose an exclusion *with justification*. |

The CI ratchet is what makes 90% durable. Without it, coverage drifts down between releases.

### 3.3 Workstreams (parallelisable)

| WS | Owner | Buckets | Est. dev-days |
|---|---|---|---|
| **WS-1 — CLI test harness** | 1 dev | A | ~6 |
| **WS-2 — REST/API integration** | 1 dev | B | ~10 |
| **WS-3 — Subsystem deep-dives** | 1–2 devs | C, E, F | ~9 |
| **WS-4 — CRDT / sync / persistence** | 0.5 dev | H, J, partial K | ~4 |
| **WS-5 — Network targeted** | 1 dev | D | ~5 |
| **WS-6 — CI / tooling / ratchet** | 0.5 dev | infra | ~3 |

**Wall-clock with 3 devs in parallel**: ~3 weeks. With 4 devs: ~2 weeks.

---

## 4. Per-workstream design

### WS-1 — CLI command test harness

**Problem**: every `src/cli/commands/*.rs` is at 0% because the CLI is a binary that talks to a running daemon. No daemon, no exercise.

**Solution**: introduce a thin `ApiClient` trait that each command takes by reference. The real implementation is the existing HTTP client; the test implementation is an in-memory fake that returns canned responses.

```rust
// src/cli/client.rs (new)
#[async_trait]
pub trait ApiClient: Send + Sync {
    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T>;
    async fn post<B: Serialize + Send, T: DeserializeOwned>(&self, path: &str, body: B) -> Result<T>;
    // ... whatever shape the existing client has
}

// src/cli/commands/identity.rs (refactor)
pub async fn run_show(client: &dyn ApiClient, args: ShowArgs) -> Result<()> { ... }
```

**Tests** live in `#[cfg(test)] mod tests` inside each command file:
- Snapshot the formatted human-readable output with `insta` (one snapshot per command × output mode).
- Assert that the `ApiClient` was called with the expected path + body.
- Cover the error-formatting branch (network error, 4xx, 5xx).

**Snapshot file location**: `src/cli/commands/snapshots/` (insta default).

**End-to-end smoke**: keep a small `tests/cli_smoke.rs` that spawns `x0xd`, runs ~5 representative commands via `assert_cmd`, and asserts exit codes. This is for confidence, not coverage.

**Acceptance**: CLI tree from ~3% → **≥ 80%**. +3,000 lines.

**New crates**:
- `insta` (1.x) — dev-dep
- `assert_cmd` (2.x) — dev-dep
- `async-trait` — likely already present

---

### WS-2 — REST/API integration test family

**Problem**: `src/lib.rs` is 8,404 lines, 50.69% covered, and most of it is REST handlers + `Agent` construction.

**Solution**: a single `tests/api_handlers/` directory containing one test file per logical endpoint group (mirroring `docs/api-reference.md` sections). Each test imports a shared harness.

```rust
// tests/api_handlers/common.rs
pub async fn router_with_test_agent() -> (Router, TestAgent) {
    let agent = AgentBuilder::default()
        .with_machine_key(tmp_path())
        .with_agent_key(tmp_path())
        .build()
        .await
        .unwrap();
    let router = x0x::api::build_router(agent.clone());
    (router, TestAgent(agent))
}

// tests/api_handlers/identity.rs
#[tokio::test]
async fn get_identity_returns_machine_and_agent_ids() {
    let (router, _agent) = router_with_test_agent().await;
    let resp = router.oneshot(req!(GET "/identity")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: IdentityResponse = json(resp).await;
    assert!(body.machine_id.len() == 64); // hex of 32-byte hash
}
```

**Coverage shape per endpoint** (the contract for each test file):
1. Happy path (success status + body shape)
2. Each documented 4xx (auth missing, validation failure, not-found)
3. Each documented 5xx if reachable in-process (timeout, transport)
4. State-mutation: assert side effect on the agent (not just the response)

**Endpoint count**: 128. Average 3 tests per endpoint = ~384 tests.

**Why this works**:
- `axum::Router::oneshot` calls handlers without binding a port — fast, deterministic, parallel.
- `Agent` is constructible with tmp keys; no network required for most endpoints.
- For endpoints that *require* network (publish, presence), use a 2-agent in-process loopback fixture.

**Acceptance**: `lib.rs` 50% → **≥ 90%**, `api/*` 100%. +3,400 lines.

---

### WS-3 — Subsystem deep-dives (exec, DM, upgrade)

#### C. Exec (`exec/service.rs`, `exec/audit.rs`, `exec/acl.rs`)

Currently optimised for the success path. Add deterministic unit tests for:
- ACL deny (caller not in `allowed_agents`, command not in `allowed_commands`, env-var leak prevention).
- Timeout reached → SIGKILL emitted → audit row recorded.
- Output-size cap reached → connection closes with the documented error.
- Audit log: assert a row is written for each (success | denied | killed | failed) outcome, with correct fields.
- Protocol decode failures → connection closed without state corruption.

**Acceptance**: `exec/service.rs` 48% → **≥ 85%**, `exec/audit.rs` 33% → **≥ 90%**. +700 lines.

#### E. Direct messaging (`dm_send.rs`, `dm_inbox.rs`)

Already has integration tests for happy path. Add:
- **Send side**: peer unreachable → retry with exponential backoff → eventual giveup. Hedge-send dedupe (we already shipped X0X-0066 — there must be a unit test for the dedupe invariant). Cooling-active path.
- **Inbox side**: capacity overflow → oldest message evicted with `DmOverflow` event. Stale message TTL expiry. Out-of-order delivery → re-ordering.
- **ACK-v2**: `request_id` collision → counter increments, no panic. ACK-without-message → ignored.

**Acceptance**: `dm_send.rs` 44% → **≥ 85%**, `dm_inbox.rs` 55% → **≥ 85%**. +500 lines.

#### F. Self-update (`upgrade/*`)

`upgrade/apply.rs` (51%) and `upgrade/monitor.rs` (14%) are filesystem-bound. Use `tempfile::tempdir()` for every test.

- `apply.rs`: rollback when signature verify fails, rollback when post-apply health check fails, atomic-rename invariants on Linux and macOS, refuse-to-downgrade rule.
- `monitor.rs`: state machine for `Idle → Detected → Downloading → Verified → Applied`, transition guards, timeout in each state.
- `signature.rs`: tampered manifest, expired signature, wrong key.

**Acceptance**: `upgrade/apply.rs` 51% → **≥ 85%**, `upgrade/monitor.rs` 14% → **≥ 80%**, `upgrade/signature.rs` 88% → **≥ 95%**. +500 lines.

---

### WS-4 — CRDT / sync / persistence

Smallest workstream but the cleanest gains: pure data structures, no I/O.

- `crdt/persistence.rs` (0%): round-trip serialize/deserialize for every CRDT type. Corrupted-buffer rejection. Version-mismatch handling.
- `crdt/sync.rs` (57%): Bloom-filter false-positive path, mismatched-version sync attempt, partial-delta application then resumption.
- `kv/sync.rs` (54%): same shape as `crdt/sync.rs` for KvStore.
- `groups/kem_envelope.rs` (63%): KEM decapsulation failure, wrong recipient, replay rejection.

**Acceptance**: each from current % to **≥ 90%**. +400 lines.

Add **proptest** stories where they don't exist:
- CRDT convergence: any permutation of N deltas applied in any order yields the same state.
- KvStore last-write-wins under concurrent puts.
- TaskList OR-Set monotonicity.

**Acceptance**: +300 lines net from proptests touching previously-uncovered branches.

---

### WS-5 — Network transport (`network.rs`)

Hardest workstream. 842 missed lines, of which an estimated 200–300 are genuinely OS- or ant-quic-internal-error paths that cannot be exercised without injection.

**Approach**:
1. Refactor `network.rs` to extract a `NetworkPolicy` trait for the decisions that don't depend on ant-quic state (peer selection, cooling, back-pressure). Unit-test the policy.
2. For ant-quic boundary code, use the existing 3-daemon loopback harness pattern (see `tests/e2e_stress_gossip.sh`'s in-process equivalent) to cover reconnect, supersede, and close paths.
3. Mark unreachable transport-error branches with a `coverage(off)` shim or pull them into a thin `unreachable_io` helper that's excluded by filename.

**Acceptance**: `network.rs` 68% → **≥ 85%** with **< 5%** of the file under documented exclusion. +500 lines.

---

### WS-6 — CI / tooling / ratchet

| Item | Where |
|---|---|
| Install `cargo-llvm-cov` in CI | `.github/workflows/ci.yml` — new step `cargo install --locked cargo-llvm-cov` (cached). |
| Coverage job (Linux only — fastest) | New job `coverage:` running `cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info nextest`. |
| Upload artefact | Upload `lcov.info` as a workflow artefact. Optional: Codecov push (decide separately — Codecov adds a third-party dep). |
| PR-comment delta bot | A small script that compares the PR's LCOV total against `main`'s and posts a comment. Use [`codecov/codecov-action`](https://github.com/codecov/codecov-action) **or** a homegrown 30-line script if we skip Codecov. |
| Floor gate | `--fail-under-lines <N>` flag on the coverage step. Starts at 48 and ratchets per Phase. |
| Per-module advisory targets | A `coverage-thresholds.toml` file in repo root, read by a small CI script that warns (does not fail) when a named module slips. |
| Local recipes (already done) | `just coverage`, `just coverage-summary`, `just coverage-lcov`, `just coverage-clean`. |

**CI cost estimate**: instrumented build + 1097-test nextest ≈ 6–12 min on the GHA Linux runners (vs ~4 min for a normal build). Acceptable. Add it as a *required* check after the floor stabilises.

---

## 5. Exclusion policy

Some code legitimately cannot be exercised by tests without harming production safety. The rule:

1. **Default**: no exclusions. Refactor for testability instead.
2. **Justified exclusion**: a one-line comment immediately above the excluded line(s), in the format:
   ```rust
   // coverage-skip: <one-line reason> (<reviewer initials>, <YYYY-MM-DD>)
   ```
   Plus an entry in `docs/coverage-exclusions.md` (new file) with the file:line range and the same reason.
3. **Categories that may be excluded with justification**:
   - OS-error paths from `std::io` that require fault-injection drivers.
   - `#[cold] fn impossible_state() -> !` defensive panics that exist solely to prove an invariant.
   - Generated code (none currently, but if proto/build.rs generators appear).
4. **Categories that may NOT be excluded**:
   - Error mapping in REST handlers (always reachable via a test).
   - CLI commands (always reachable via the ApiClient harness).
   - Any code that returns `Result::Err(_)` from a public API.
5. **Review**: every PR that adds an exclusion needs an explicit `+1` from a code-owner in `docs/coverage-exclusions.md`.

**Budget**: total excluded lines must remain **< 2%** of executable lines (≤ ~770 lines at current size).

---

## 6. Quality bar (Rule 9 enforcement)

Each new test must satisfy *all* of:

1. **Name describes the why**: `test_dm_send_dedupes_request_id_across_original_and_hedge` ✅, `test_dm_send_works` ❌.
2. **One business invariant per test**: if the test asserts two unrelated things, split it.
3. **Failure message is diagnostic**: bare `assert_eq!(a, b)` is acceptable only when the two values name themselves. Otherwise use `assert_eq!(a, b, "expected ack count to match send count; ...")`.
4. **No `unwrap()` in test bodies that would hide a panic from another assertion** — use `?` where possible, or `expect("...")` with a sentence-long message.
5. **Mutates production code without breaking the test** triggers a code-review smell. If a test only re-states what the code does (e.g. asserts that a getter returns the field it returns), it is a Rule 9 violation and must be rewritten or removed.

**Reviewer checklist** (added to PR template):
- [ ] Each new test has a why-named name.
- [ ] No assertion in a new test is a tautology against the implementation.
- [ ] Coverage delta is reported in the PR description, sourced from CI.
- [ ] If exclusions were added, justification is logged in `docs/coverage-exclusions.md`.

---

## 7. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Tests become coverage-padding (Rule 9 violations) | Medium | High — silent erosion of suite value | Mandatory reviewer checklist + spot-audit one test per PR. |
| CI time grows past 15 min total | Medium | Medium — slows iteration | Cache `~/.cargo/bin/cargo-llvm-cov`, partition nextest, run coverage only on PRs targeting `main`. |
| Flaky network tests in WS-5 erode trust | High | Medium | Mark flaky tests `#[ignore]` immediately and file a fix-it ticket; do not retry. |
| Refactor required by WS-1 destabilises the CLI | Low | High — user-facing | One-PR-per-command refactors, no behavioural changes, screenshot-tested with snapshots before merging. |
| 90% target not reachable without > 2% exclusions | Medium | Medium — drops the bar | If hit, escalate: discuss raising exclusion budget vs lowering target to ~85% with explicit per-bucket sub-targets. |
| WS-2 conflicts with `tests/api_coverage.rs` semantics | Low | Low | Keep `api_coverage.rs` as the surface-existence guard; WS-2 tests live in a different directory and a different shape (handler exercise, not symbol reference). |

---

## 8. Acceptance criteria (definition of done)

The plan is complete when **all** of:

1. CI `coverage` job exists, runs on every PR to `main`, and fails when line coverage drops below the active floor.
2. `cargo llvm-cov nextest --all-features --workspace --summary-only` reports `≥ 90.0%` lines covered.
3. `docs/coverage-exclusions.md` lists every excluded region, with reasons, totalling **< 2%** of executable lines.
4. The 1097-test suite has grown to the agreed size (estimated ~1,800–2,000 tests). No test in the suite is `#[ignore]`d without a linked ticket.
5. PR template includes the reviewer checklist from §6.
6. This document is updated with the final per-bucket numbers and any deviations from the plan.

---

## 9. Out of scope

- Mutation testing (e.g. `cargo-mutants`). Worth piloting later; not part of the 90% mandate.
- Fuzzing (`cargo-fuzz`). Already partially present in upstream `ant-quic`; x0x can adopt opportunistically.
- Coverage of binary entry points (`src/bin/x0x.rs`, `src/bin/x0xd.rs` `main`). These are thin wrappers; their bodies don't need line coverage. Surface coverage is via the smoke tests in WS-1 and the existing e2e suite.
- GUI HTML coverage. That's owned by `gui-coverage` and is a separate surface-coverage gate.

---

## 10. Handoff packet (2026-05-12)

This is the work split for the first implementation wave. Keep each item as a
separate PR so owners can move in parallel without rebasing through unrelated
refactors.

| PR | Owner | Scope | Files | Exit criteria |
|---|---|---|---|---|
| **WS-6a — coverage gate** | CI/tooling | Add line coverage CI, threshold config, exclusions register, PR checklist. | `.github/workflows/ci.yml`, `coverage-thresholds.toml`, `scripts/check-coverage-thresholds.py`, `docs/coverage-exclusions.md`, `.github/pull_request_template.md`, `justfile`, `docs/cicd.md` | `just --list` shows `coverage-check`; CI uploads `lcov.info`; global 48% floor is enforced. |
| **WS-1a — CLI ApiClient pilot** | CLI | Introduce object-safe `ApiClient` around existing JSON client calls; pilot on identity commands only. | `src/cli/mod.rs`, `src/cli/commands/identity.rs` | `DaemonClient` implements `ApiClient`; identity command tests can fake `ensure_running`, `get`, `post`, and `format`. |
| **WS-1b — CLI command sweep** | CLI | Move non-streaming command modules onto `ApiClient`, one module per commit. | `src/cli/commands/*.rs` except daemon/upgrade/streaming modules | Each refactored command has why-named tests for success, API error, and request shape. |
| **WS-2a — router extraction** | REST/API | Move daemon router/state out of `src/bin/x0xd.rs` into library API module. | `src/bin/x0xd.rs`, `src/api/mod.rs` or `src/api/router.rs`, `Cargo.toml` | `x0xd` calls `x0x::api::build_router(...)`; integration tests can import router construction; `tower` dev-dep available for `ServiceExt::oneshot`. |
| **WS-2b — status/identity handler tests** | REST/API | Establish in-process `tests/api_handlers` harness and first endpoint family. | `tests/api_handlers/common.rs`, `tests/api_handlers/status.rs`, `tests/api_handlers/identity.rs` | `/health`, `/status`, `/shutdown`, `/agent`, `/agent/card` have happy path and auth/error coverage where documented. |

### WS-1 notes

The first `ApiClient` boundary should mirror the current CLI shape, not invent a
generic typed client yet. Use `serde_json::Value` for bodies and responses so
the trait remains object-safe:

```rust
#[async_trait]
pub trait ApiClient: Send + Sync {
    async fn ensure_running(&self) -> anyhow::Result<()>;
    async fn get(&self, path: &str) -> anyhow::Result<serde_json::Value>;
    async fn get_query(&self, path: &str, query: &[(&str, &str)]) -> anyhow::Result<serde_json::Value>;
    async fn post(&self, path: &str, body: &serde_json::Value) -> anyhow::Result<serde_json::Value>;
    async fn post_empty(&self, path: &str) -> anyhow::Result<serde_json::Value>;
    async fn patch(&self, path: &str, body: &serde_json::Value) -> anyhow::Result<serde_json::Value>;
    async fn put(&self, path: &str, body: &serde_json::Value) -> anyhow::Result<serde_json::Value>;
    async fn delete(&self, path: &str) -> anyhow::Result<serde_json::Value>;
    fn format(&self) -> OutputFormat;
}
```

Do not force streaming commands into this first trait. `get_stream` leaks
`reqwest::Response` and needs a separate stream abstraction.

### WS-2 notes

`Router::oneshot` is not possible from integration tests yet because the real
Axum router and handlers live privately in `src/bin/x0xd.rs`. The first REST PR
is therefore structural: expose a library-owned `ApiState` and
`build_router(...)`, then let the daemon wire production state into that router.

Start handler coverage with status and identity endpoints. They prove auth
middleware, state wiring, and identity access without requiring a joined gossip
network. Leave SSE/WebSocket and network-dependent endpoints for later harness
iterations.

---

## 11. References

- [taiki-e/cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)
- [cargo-nextest coverage integration](https://nexte.st/docs/integrations/test-coverage/)
- [rustc Instrumentation-based Code Coverage](https://doc.rust-lang.org/rustc/instrument-coverage.html)
- `CLAUDE.md` — Rules 2, 3, 9, 12
- `tests/CLAUDE.md` — current integration & e2e test layout
- `docs/api-reference.md` — endpoint inventory for WS-2
