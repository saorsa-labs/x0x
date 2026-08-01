# ADR 0028: Authenticated Causal-Predecessor Delivery

- **Status:** Proposed
- **Date:** 2026-08-01
- **Decision owners:** David Irvine
- **Reviewers:** Sam (author); Dario (independent review pending); Watson
  (orchestrator)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [frozen grounding](../grounding/0028-authenticated-causal-predecessor-delivery.md);
  [join and roster propagation reference](../design/groups-join-roster-propagation.md);
  ADR 0025

## Context

A request-access approval is not a standalone roster mutation. It depends on
the requester-authored `JoinRequestCreated` transition that supplies the
pending request and the previous signed state. Metadata gossip can omit that
predecessor for an active witness, while direct approval fan-out can still
deliver the approval. The witness then correctly rejects it because the
pending request and state-chain link are absent.

Delivery order is not an authorization signal. Removing the pending-request
check, treating an authority's copy as requester-authenticated, lengthening a
timeout, or assuming background sends remain ordered would turn a liveness gap
into an integrity gap.

## Considered Options

1. **Authenticated predecessor relay plus bounded causal queue (chosen).** It
   preserves the current event schema and contains recovery to the proven
   request/approval relationship.
2. **Carry signed predecessor evidence inside every approval.** Strong
   co-delivery, but a larger versioned schema and duplicated evidence.
3. **Create a general signed-event gap log.** Potentially reusable, but it
   broadens authorization, persistence, ordering, and resource policy beyond
   the proven non-TreeKEM gap.
4. **Keep best-effort gossip or weaken apply validation.** Rejected: delay does
   not create missing evidence, and ungrounded approval must not mutate state.

## Decision

The request-access path will preserve and retry the requester-authored signed
predecessor to active witnesses. Receivers will durably and boundedly queue a
dependent approval that arrives first, without mutating group state.

The relay is a courier, not an author. A receiver must validate the original
requester's signature over the exact predecessor payload and bind its group,
request, requester, and state transition before applying it. The relay's
authenticated identity controls who may consume relay resources; it cannot
substitute for requester authentication.

Queue admission requires every check possible without the predecessor,
including structural signature, group, actor, and current authority. The
approval applies exactly once only after the matching predecessor applies and
its request identity and `prev_state_hash` match the resulting state. A
missing, expired, conflicting, or invalid predecessor remains unapplied.

The linked reference governs queue, retry, expiry, deduplication, persistence,
restart, and observability. Those mechanisms may evolve while bounded,
fail-closed, origin-authenticated, and exactly-once application remain true.

## Consequences

### Positive

- Witnesses converge across request/approval reordering while requester and
  authority signatures retain distinct meanings.
- At-least-once delivery does not become double application; a permanently
  missing predecessor consumes finite resources and never becomes success.

### Negative / Trade-offs

- Daemons need a durable bounded queue/outbox, restart cleanup, and separate
  representation of carrier identity and cryptographic origin.
- Finite retries cannot promise delivery across a partition longer than the
  retention policy.

### Neutral / Operational

- Pending-request and state-chain checks remain mandatory. This decision does
  not generalize the TreeKEM queue or alter admission policy; limits and retry
  schedules remain implementation policy.

## Validation

Acceptance requires independent behavioural controls showing:

1. request then approval converges and mutates the witness roster once;
2. approval before request performs no mutation, then applies once after the
   matching signed predecessor arrives;
3. a permanently missing predecessor stays bounded, expires, and never
   succeeds;
4. a tampered predecessor, wrong request identity, or wrong
   `prev_state_hash` fails closed without roster mutation;
5. immediate and delayed duplicates remain idempotent across live operation
   and restart; and
6. the unchanged five-daemon active-recipient family reports 5 passed and
   0 failed.

Controls must observe mutation, rejection, bounds, expiry, deduplication, and
restart directly. Receipt traces or a longer timeout are insufficient.

## Grounding

See the [frozen evidence](../grounding/0028-authenticated-causal-predecessor-delivery.md)
and [mutable reference implementation](../design/groups-join-roster-propagation.md).

## Notes for AI-assisted work

AI tools may help draft this ADR, but must not mark it Accepted without human
review. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
