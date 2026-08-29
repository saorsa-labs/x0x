# ADR 0048: Task Lists Coordinate via Per-Entity CRDTs with Signed Provenance

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0040 (delegation builds on task lists); ADR-0021 (reuses the provenance pattern); `docs/primers/coordination.md`. Backfill record for shipped behavior.

## Context

`src/crdt/` ships multi-agent task-list coordination with no deciding ADR.
A `TaskList` is an OR-Set of task IDs, an LWW ordering register and name,
and per-task content (`src/crdt/task_list.rs:96-130`). A `TaskItem`'s
checkbox is an OR-Set of `CheckboxState` (`Empty`, `Claimed`, `Done`, each
carrying agent + timestamp; concurrent claims resolve to the earliest
timestamp, `src/crdt/checkbox.rs:28-65`), while title/description/assignee/
priority are LWW registers (`src/crdt/task_item.rs:48-100`).

## Decision Drivers

- Agents concurrently claim/complete tasks with no coordinator and no
  merge conflicts.
- Authorship of claim/complete must survive gossip relay — the transport
  signer is not the author.
- Group-confidential lists must not ship before their crypto exists.

## Considered Options

1. Server-assigned ordering with OT.
2. Whole-list LWW snapshots.
3. Per-entity CRDTs (OR-Set membership/checkbox, LWW metadata) with signed
   operation attestations (chosen).

## Decision

1. Entity mapping is fixed: list membership OR-Set; list order/name LWW;
   checkbox OR-Set; item metadata fields LWW
   (`src/crdt/task_list.rs:96-130`, `src/crdt/task_item.rs:48-100`).
2. Claim/complete operations carry an `OpAttestation` — ML-DSA-65 over
   domain-separated layouts `x0x.task.claim.v2` / `x0x.task.complete.v2`
   binding scope, task, agent, timestamp
   (`src/crdt/provenance.rs:58-61,91-111`). Attestations union-merge with
   the checkbox states; absent or invalid provenance fails closed (`src/crdt/task_item.rs:84-100`).
3. Sync is gossip deltas plus a `/state-sync` side channel for cold start,
   with retries at 1/5/15/30 s then exponential capped at 300 s until
   convergence (`src/crdt/sync.rs:25-65`) — holders do not volunteer state periodically.
4. `EncryptedTaskListDelta` exists (bincode payload sealed with the
   current MLS epoch cipher, AAD binding group + epoch,
   `src/crdt/encrypted.rs:11-25,51-73`) but is not wired into the default
   sync path; the shipped wire format remains plaintext `TaskListDelta` (`src/crdt/sync.rs:25-30`).

## Consequences

### Positive

- Conflict-free concurrent coordination; authorship verifiable offline;
   relayed operations validate identically to direct ones.

### Negative / Trade-offs

- LWW metadata silently drops concurrent edits; the primer's "30 s
  anti-entropy" wording is stale relative to the reactive retry ladder.

### Neutral / Operational

- ADR-0040's `owner_agent` transfer composes with this model rather than
  replacing it.

## Validation

- `tests/crdt_convergence_concurrent.rs`; provenance verification tests in
  `src/crdt/provenance.rs`.

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
