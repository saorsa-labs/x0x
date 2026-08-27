# ADR 0040: Agent-to-Agent Delegation in Spaces

- **Status:** Accepted (2026-08-27)
- **Date:** 2026-08-27
- **Decision owners:** David Irvine (direction), omp (drafting), Claude (review)
- **Reviewers:** David Irvine (approved 2026-08-27)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0010/0012 (GSS + TreeKEM sealed store), ADR-0023 (durable history), ADR-0030 (DM durable-ACK v2, hardened by #380: PRs #396/#408/#410), ADR-0036, ADR-0038, ADR-0039

## Context

The multi-agent workspace model (2–6 agents in one space handing tasks to
each other) is half-built: CRDT task lists have claim/complete but transfer
is unauthenticated intent, @mentions are computed by GUI string matching,
and shared credentials do not exist (2026-08-23 gap analysis).

## Decision Drivers

- Delegation must be auditable in durable history after the fact.
- Authority passed to a delegate must be bounded and expiring.
- Ownership transfer must be cryptographic, not UI convention.

## Considered Options

1. Keep claim-as-ownership; add GUI conventions.
2. Full capability calculus with unbounded re-delegation.
3. One signed envelope type plus a depth cap (chosen).

## Decision

- Standardize a signed envelope on the existing group message bus:
  `Delegation { task_ref, from_agent, to_agent, authority_scope, expiry }`;
  `authority_scope` bounds what the delegate may do in the delegator's name
  (send-as, task-execute — nothing else).
- Task-list CRDT gains an explicit `owner_agent` field; transfers are
  signed by the current owner. Claiming no longer implies ownership.
- @mention addressing becomes a daemon-side structured `mentions:
  [AgentId]` field instead of GUI string matching.
- Shared credentials: one sealed per-space secret slot in the group's
  GSS/TreeKEM-sealed store, per-agent grants recorded as signed
  state-commits; plaintext never leaves the sealed plane.
- Delegation depth caps at 2 (A→B→C, not further), keeping the
  accountability chain legible in history.
- **Delivery substrate:** the delegator→delegate handoff rides DMs with
  durable application ACK — DM protocol v2 (ADR-0030) as hardened by the
  #380 campaign (PRs #396/#408/#410, v0.39.7–v0.39.9) — so "delegated"
  means the delegate's daemon durably committed the handoff or the sender
  got a typed refusal, never a black hole. The envelope itself is recorded
  in group history (ADR-0023).

## Consequences

### Positive

- Auditable delegation chain in durable history; revoking an agent's
  membership auto-expires its delegations and re-keys the space.

### Negative / Trade-offs

- Another message schema to version; credential slots inherit MLS epoch
  complexity on every membership change.

### Neutral / Operational

- Sub-agents (ADR-0039) and Home members (ADR-0038) delegate through the
  same envelope; no mode-specific paths.

## Validation

- Forge tests: non-owner transfer, expired, depth-3 delegation — all rejected.
- Restart test: a delegated task survives daemon restart via history; the
  handoff DM yields a durable ACK or a typed 409.
- Sealed-slot test: membership removal rotates the slot key; the removed
  agent cannot decrypt.

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
