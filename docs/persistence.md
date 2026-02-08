## CRDT Persistence v1

Phase 01 persistence is for **protocol-managed CRDT state only**. It is optional, disabled by default, and remains plaintext-at-rest by design in v1.

## What Is Persisted (and What Is Not)

- Persisted: protocol snapshot envelopes for CRDT task-list state (`schema_version`, codec marker/version, integrity digest, payload).
- Not persisted by this subsystem: application-level knowledge stores, external business records, secrets management, or app-owned domain data.
- Boundary: x0x owns protocol recovery/convergence state; application data ownership remains with host applications.

## Startup and Recovery Flow

- Persistence disabled: runtime remains in-memory and behavior is unchanged.
- Persistence enabled, degraded mode (default): startup attempts local load; on load/format/storage failure, runtime continues with empty local state and converges via network resync.
- Persistence enabled, strict mode: startup failures are fail-closed.
- Strict first-run initialization requires explicit `initialize_if_missing` intent and manifest sentinel handling.
- Recovery path loads the latest valid snapshot and then rejoins normal anti-entropy/merge behavior.

## Mode Semantics: Strict vs Degraded

- `degraded` (default): prioritize availability and convergence continuity.
- `strict`: prioritize local durability guarantees; persistence errors fail startup/checkpoint operations.
- Unsupported legacy encrypted artifacts are deterministic by mode:
  - strict -> typed fail (`UnsupportedLegacyEncryptedArtifact`)
  - degraded -> typed skip/continue (`DegradedSkippedLegacyArtifact`) and resync path

## Checkpoint Policy Semantics

Defaults are ADR-locked and enforced:

- mutation threshold: checkpoint at `32` local mutations
- dirty-time floor: checkpoint at `5m` if dirty
- debounce floor: suppress repeated checkpoints within `2s`
- explicit checkpoint requests: supported, but still honor dirty/debounce semantics
- graceful shutdown: attempts final checkpoint with strict/degraded outcome behavior

## Retention and Storage Budget

Defaults:

- checkpoints retained per entity: `3`
- storage budget: `256MB`
- warning/critical pressure thresholds: `80%` / `90%`

Behavior at `100%` budget is mode-dependent:

- strict: fail-closed behavior
- degraded: skip persistence write and continue runtime operation

Retention trimming keeps newest snapshots by canonical timestamp filename order and ignores malformed snapshot filenames.

## Snapshot Format and Legacy Artifact Handling

- v1 backend is file snapshots only.
- Snapshot envelope is plaintext with integrity metadata only (no key-provider/encryption claims).
- One-release migration compatibility window is enforced at snapshot schema evaluation.
- Unsupported legacy encrypted snapshot artifacts are detected during load and mapped to deterministic strict/degraded outcomes.

## Security Boundary (Plaintext at Rest)

Persistence in Phase 01 is intentionally plaintext-at-rest. x0x does **not** provide built-in application-layer encryption for persisted protocol state in this phase.

Operator guidance:

- use filesystem permissions and least-privilege service accounts
- place persistence roots on encrypted volumes where available
- use host full-disk encryption (FDE) and standard backup/access controls

Do not interpret v1 persistence as a confidentiality guarantee for local snapshot files.

## Persistence Runtime Controls (Node/Python)

Bindings preserve the same plaintext scope and core contract semantics.

### Defaults and observability

- Use the same core contract in both bindings for persistence observability: `health`, `checkpoint_frequency`, and `checkpoint_frequency_bounds`.
- `health` includes: `mode`, `state`, `degraded`, `last_recovery_outcome`, `last_error`, and `budget_pressure`.
- `checkpoint_frequency` reports current runtime values: `mutation_threshold`, `dirty_time_floor_secs`, `debounce_floor_secs`.
- `checkpoint_frequency_bounds` reports host envelope limits and `allow_runtime_checkpoint_frequency_adjustment`.

### Runtime adjustment behavior

- Runtime checkpoint-frequency updates are bounded by host policy envelope values.
- Out-of-range or disallowed requests return deterministic invalid-request errors with stable codes:
  - `runtime_checkpoint_adjustment_not_allowed`
  - `mutation_threshold_out_of_bounds`
  - `dirty_time_floor_out_of_bounds`
  - `debounce_floor_out_of_bounds`
  - `invalid_host_policy_envelope`

### Example flow (binding semantics)

1. Query observability contract.
2. Inspect `checkpoint_frequency_bounds`.
3. Submit a bounded update request.
4. If rejected, branch on deterministic error `code` and surface operator guidance.
