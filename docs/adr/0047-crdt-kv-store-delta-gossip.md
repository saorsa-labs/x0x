# ADR 0047: The KV Store Is CRDT-Backed with Delta Gossip and a Reserved `Encrypted` Policy

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0015 (PR #87 `Encrypted`-policy guardrail); `docs/design/encrypted-kvstore.md` (proposal only). Backfill record for shipped behavior.

## Context

`src/kv/` ships a replicated KV store with no deciding ADR (ADR-0015 only
side-references it). The module declares its architecture in-file:
OR-Set + LWW-Register with delta-based synchronization over anti-entropy
gossip (`src/kv/mod.rs:3-5`).

## Decision Drivers

- Peers replicate small shared state without a coordinator or locks.
- Late joiners must catch up without a global archive (ADR-0006 posture).
- Group-encrypted replication must not silently ship as plaintext.

## Considered Options

1. Last-writer-wins KV without set semantics.
2. Transactional replicated log (requires a leader).
3. Composed CRDTs — OR-Set membership + LWW values — delta-synced over
   gossip (chosen).

## Decision

1. A `KvStore` is an OR-Set of keys plus per-key LWW entries (highest
   `updated_at` wins, deterministic hash tie-break,
   `src/kv/entry.rs:15-17`) plus an LWW name register
   (`src/kv/store.rs:636-645`).
2. Changes propagate as encoded `(PeerId, KvStoreDelta)` deltas on a gossip
   topic (`src/kv/sync.rs:1114-1122`); `StateRequest` recovery republishes
   full state so late joiners retrieve pre-subscription keys
   (`src/kv/sync.rs:428-433`).
3. `AccessPolicy::{Signed, Allowlisted, Encrypted, AppendOnly, SelfKeyed}`
   governs writes. `Encrypted` is **reserved and fail-closed**: ordinary
   construction and writes on deserialized encrypted replicas are rejected
   with `EncryptedPolicyReserved` (`src/kv/store.rs:760-770,1168-1181`)
   because current gossip carries plaintext bincode deltas — the
   encrypted design (`docs/design/encrypted-kvstore.md`) is explicitly
   "Proposal — design document only, not implemented".
4. `SelfKeyed` namespaces are quota-bounded per agent: 64 keys / 256 KiB
   (`src/kv/store.rs:137,145`), enforced by deterministic lowest-N
   admission with identical local and remote predicates
   (`src/kv/store.rs:1115-1148`).

## Consequences

### Positive

- Convergent, coordinator-free replication; quotas are abuse-proof because
  every replica computes the same admission.

### Negative / Trade-offs

- Deltas are plaintext bincode today; group-confidential KV waits on the
  encrypted-store design.

### Neutral / Operational

- LWW means concurrent writes lose all but one value; callers needing
  set semantics use OR-Set keys, not entry values.

## Validation

- `src/kv/` merge/delta/quota unit tests; convergence behavior exercised
  via `tests/crdt_convergence_concurrent.rs` (named by ADR-0025's
  grounding as an evidence surface).

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
