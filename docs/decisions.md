# CRDT Persistence Decisions

This file records the architectural decisions behind x0x CRDT persistence so reviewers and future contributors can understand the reasoning alongside the implementation.

---

## 2026-Feb-09: Persistence is optional and local

**Context:** x0x peers need to interoperate even when hosts have different local storage policies.

**Decision:** Persistence is optional, disabled by default, and local to each node.

**Rationale:** A node can gain restart continuity without imposing requirements on other peers.

**Consequences:** Wire protocol behavior and convergence semantics are unchanged for mixed persistent/non-persistent networks.

## 2026-Feb-09: Persisted protocol state is plaintext by design

**Context:** Application-layer at-rest encryption was evaluated and removed from scope.

**Decision:** Persisted protocol snapshots are plaintext. Security boundary is filesystem permissions, OS controls, and optional full-disk encryption.

**Rationale:** This keeps persistence simple and avoids key custody/rotation/recovery complexity in this subsystem.

**Consequences:** x0x does not manage keys for snapshot storage; operators needing at-rest confidentiality should use host-level controls.

## 2026-Feb-09: Failure mode model uses degraded-by-default policy

**Context:** Persistence failures should not stop agents from participating in the network by default.

**Decision:** Default mode is `degraded`; `strict` is opt-in.

**Rationale:** Agent availability is prioritized unless operators explicitly require fail-fast behavior.

**Consequences:** Health and observability surfaces must clearly communicate degraded state and recovery outcomes.

## 2026-Feb-09: Missing storage path handling is mode-specific

**Context:** Between runs, the configured storage path may be missing (first bootstrap, moved directory, deleted store, or misconfiguration).

**Decision:**

- In `degraded` mode, x0x attempts to create the configured path. If creation succeeds, startup proceeds with empty local state and network resync. If creation fails, runtime continues in memory and surfaces degraded health.
- In `strict` mode, a missing path is a startup error unless explicit `initialize_if_missing` intent is provided.
- x0x does not auto-discover moved paths; configured location is authoritative.

**Rationale:** This keeps startup behavior deterministic and prevents silent data loss in strict deployments while preserving availability in degraded mode.

**Consequences:** Operators must treat path configuration as explicit operational state. Strict deployments need deliberate first-run initialization and clear recovery procedures when storage paths change.

## 2026-Feb-09: Strict first-run initialization requires explicit intent

**Context:** Strict mode must distinguish first bootstrap from unexpected missing/moved storage.

**Decision:** Strict startup requires explicit `initialize_if_missing` intent and writes a manifest sentinel.

**Rationale:** Prevents silent re-initialization and preserves predictable startup semantics.

**Consequences:** Missing manifest in strict mode is a startup error unless explicit initialization intent is provided.

## 2026-Feb-09: V1 backend is file snapshots only

**Context:** Initial delivery focuses on proven orchestration behavior rather than backend diversity.

**Decision:** V1 ships a file-snapshot backend with atomic temp-write + fsync + rename semantics.

**Rationale:** File snapshots are portable, dependency-light, and easy to reason about.

**Consequences:** Additional backends are follow-up work behind feature flags.

## 2026-Feb-09: Snapshot compatibility is one release back

**Context:** Persisted schema must evolve without unbounded migration debt.

**Decision:** Snapshot loading compatibility is guaranteed one release back.

**Rationale:** Balances upgrade practicality with maintainable migration scope.

**Consequences:** Older snapshots may require stepwise upgrade or network resync.

## 2026-Feb-09: Recovery scan semantics are newest-to-oldest with candidate-local skip

**Context:** Snapshot directories can contain invalid, unreadable, corrupt, or legacy artifacts.

**Decision:** Recovery scans newest-to-oldest and skips candidate-local failures (including unsupported legacy encrypted artifacts), returning no-loadable-snapshot only when no valid candidate remains.

**Rationale:** Maximizes successful recovery from valid local state while keeping behavior deterministic.

**Consequences:** Quarantine is best-effort and must not break iteration guarantees.

## 2026-Feb-09: Checkpoint policy is hybrid with explicit request support

**Context:** Durability and write efficiency need balanced defaults.

**Decision:** Hybrid policy combines mutation threshold, dirty time floor, debounce floor, explicit requests, and graceful-shutdown final checkpoint attempt.

**Rationale:** Covers active mutation bursts and long idle periods with pending changes.

**Consequences:** Runtime controls must remain bounded by host policy.

## 2026-Feb-09: Retention and budget are first-class controls

**Context:** Persistence must stay bounded on constrained hosts.

**Decision:** Keep limited checkpoint history per entity, enforce storage budget thresholds, and apply mode-specific behavior at hard budget limits.

**Rationale:** Prevents unbounded growth while preserving recent recovery history.

**Consequences:** Budget/retention behavior is test-covered and observable through health/log surfaces.

## 2026-Feb-09: Binding contracts must match core persistence contracts

**Context:** Node and Python consumers require parity with Rust core behavior.

**Decision:** Bindings expose parity for persistence config defaults, health payloads, checkpoint frequency and bounds, and bounded runtime controls.

**Rationale:** Avoids cross-language drift and keeps runtime behavior predictable.

**Consequences:** Parity tests are required to enforce contract consistency.
