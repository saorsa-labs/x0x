# ADR 0041: Cross-Machine State Sync — Tiered, Owner-to-Owner Only

- **Status:** Accepted (2026-08-27) — **amends ADR-0023’s non-goals** (see Amends)
- **Date:** 2026-08-27
- **Decision owners:** David Irvine (direction), omp (drafting), Claude (review)
- **Reviewers:** David Irvine (approved 2026-08-27)
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** ADR-0023 — its "serving history to the network" non-goal deferred cross-node backfill to "a separate future ADR with its own trust model"; this is that ADR, scoped owner-to-owner only.
- **Related:** ADR-0006, ADR-0015, ADR-0022, ADR-0023, ADR-0030, ADR-0036, ADR-0037, ADR-0038

## Context

ADR-0023 made history deliberately local-only. The Home product promise
("follows you across machines", ADR-0037/0038) breaks without a bounded
answer to which state moves. Unbounded replication would abandon the
participant-held-data philosophy (ADR-0006) and silently widen the
plaintext-at-rest footprint (ADR-0015).

## Decision Drivers

- A new machine must reach identity/roster parity without ceremony.
- No global archive, no third-party replica, no gossip fan-out of history.
- The trust model must be explicit: owner machines only.

## Considered Options

1. Full state replication (all history everywhere).
2. Nothing replicates; manual export/import.
3. Tiered replication with an explicit never-tier (chosen).

## Decision

- **Tier 1 — must replicate:** owner profile, agent and machine names
  (ADR-0036), Home roster + policy (ADR-0038), sub-agent registry
  (ADR-0039) — small signed objects synced as owner-key-authenticated
  state-commits over ADR-0022 byte streams between the owner's machines.
  Conflict policy: last-writer-wins by state-commit height; roster mutations
  are single-owner-authorized, so conflicts are rare.
- **Tier 2 — pull-on-demand:** Home history only; a new machine backfills
  from a live peer over the same stream (`/history?scope=group:<home>`),
  owner-to-owner on demand, governed by the receiver's retention bounds.
- **Tier 3 — never replicates:** non-Home group history, DM history, exec
  session state. Per-machine, full stop.

ADR-0023's privacy claim is preserved by construction: replication is
owner-to-owner over authenticated streams (ADR-0022 identity gate +
ML-DSA owner signatures), never a network-served archive.

## Consequences

### Positive

- "Pick up any machine and continue" holds for Home without abandoning
  participant-held data.

### Negative / Trade-offs

- Tier 2 moves plaintext history onto additional owner disks — same-owner
  trust; the ADR-0015 footprint becomes multi-disk and must be stated plainly.
- A compromised "owner machine" could poison Tier 1; bounded by owner-key
  authentication and the connect-ACL gate (ADR-0022), not eliminated.

### Neutral / Operational

- GUI Settings gains a Retention pane and a per-space "synced from
  \<machine\> at \<time\>" indicator.

## Validation

- Two-daemon test: Tier 1 converges on both machines; a forged
  state-commit from a non-owner key is rejected.
- Tier 2 backfill respects the receiver's retention bounds under a tight budget.
- Tier 3: the sync stream surface is a deny-by-default allowlist — no
  test path can emit non-Home/DM/exec state.

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
