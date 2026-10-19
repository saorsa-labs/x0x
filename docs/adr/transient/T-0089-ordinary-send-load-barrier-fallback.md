# T-0089-ordinary-send-load-barrier-fallback: ordinary sends keep fallback after a load-barrier failure

- **Status:** Accepted
- **Accepted:** David Irvine, 19 Oct 2026, 13:13 BST (startup load-barrier rule).
- **Target slot:** A03
- **Date:** 2026-10-19
- **Decision owners:** David Irvine
- **Reviewers:** Claude and Codex exact-head re-reviews pending on PR #1453
- **Supersedes:** ADR 0089 §5's blanket send-result statement only, as clarified below.
- **Superseded by:** none
- **Related:** [PR #1453](https://github.com/saorsa-labs/x0x/pull/1453), part of [#1239](https://github.com/saorsa-labs/x0x/issues/1239), slice 2; [ADR 0089](../0089-relationship-peer-evidence-survives-restart.md); D242; R3, R5 and R6.

## Context

ADR 0089 §5 says a send returns retryable `RecipientUndiscovered` when the
startup load barrier times out or its queue overflows. That wording does not
distinguish strict durable-ACK sends from ordinary sends. PR #1453 bounds
evidence work while retaining ordinary delivery through existing fallback.

David's 19 October ruling settles that distinction. Engineer's clarification
of the [13:17 question](https://github.com/saorsa-labs/x0x/pull/1453#issuecomment-6267006360)
confirms that the existing fallback errors remain. These errors describe
unchanged behaviour on the #1453 branch for #1239, not a separate
error-contract ruling by David.

## Decision Drivers

- Strict durable acknowledgements need verified evidence bound to a machine.
- Optional evidence failure must not remove ordinary delivery paths.
- The load wait must fit the send's existing evidence budget.
- Callers must retain the existing fallback errors and retry behaviour.

## Considered Options

1. Refuse every send when the startup barrier times out or overflows.
2. Refuse strict sends and let ordinary sends take the existing no-evidence path.
3. Let ordinary sends fall back but replace all no-card errors with `NoConnectivity`.

## Decision

Use option 2. On a startup load-barrier timeout or overflow, strict
durable-ACK sends return retryable `RecipientUndiscovered`. The barrier wait
is bounded by the remaining `timeout_per_attempt` evidence budget and the
existing five-second load limit. An unbound contact card cannot satisfy
the strict evidence requirement.

Ordinary sends treat either barrier failure as no evidence. They take the
existing no-evidence path: contact-card selection, then the existing gossip
or raw-QUIC fallback as applicable. Usable adverts keep their existing
precedence. The fallback returns its actual result.

These are preserved existing errors when no usable capability remains:

- With `require_gossip`, return `RecipientKeyUnavailable`.
- Otherwise, raw-QUIC fallback maps `NetworkError::NodeCreation` to
  `DmError::NoConnectivity` when local networking is unavailable, such as
  a network that is not initialized.
- With the recipient still unresolved, raw-QUIC fallback maps
  `NetworkError::AgentNotFound` to retryable `DmError::RecipientUndiscovered`.

This list explains those conditions; it does not replace other existing
fallback errors. Discovery preflight keeps its existing error and accounting.
The ruling changes neither incoming-frame
handling nor the barrier's queue limits, counters or recovery guarantee.

## Consequences

### Positive

- Ordinary delivery remains available when evidence loading cannot finish.
- Strict sends retain a retryable refusal without weakening acknowledgement proof.

### Negative / Trade-offs

- A barrier failure alone cannot predict an ordinary send's final error.

### Neutral / Operational

- Wire, storage and API contracts remain unchanged. Later transport and raw
  resolution keep their existing budgets.
- ADR 0089 stays immutable. This A03 transient does not count toward the
  15-slot cap. Fold it only when David asks.

## Validation

Compare `SendEvidence::wait`, contact-card selection and the final send/error
mapping with this rule. Existing load tests cover strict refusal, ordinary
card publication and absent-network fallback. Barrier tests cover timeout
and overflow. This documentation change requires ADR governance, consolidation,
count and format checks. Source confirmation is not a new runtime result
or an independent approval review.

## Notes for AI-assisted work

Accepted status records David's barrier ruling. The error list records
preserved behaviour, not a separately accepted API change. Do not edit
ADR 0089 or fold this record into A03 without David's instruction.
