# A07 Messages Receipts History and Retry

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

x0x must report what happened to a message. A successful send must not imply that an external agent accepted or completed the work.

## Context

The system has gossip, direct messages, group messages, durable local history and live streams. These surfaces provide different guarantees. A timeout can occur after the recipient saved a message. A live consumer can disconnect or fall behind.

## Decision

We will use stable message identities and explicit receipt levels. A caller can query the result using its logical request ID.

The delivery model has these distinct states:

1. Queued at sender: the sender has saved the obligation under a stated expiry and retention policy.
2. Committed at recipient: the recipient has verified and durably saved the message.
3. Accepted by consumer: the adapter has saved enough state to recover the work.
4. Started: the runtime has begun the work.
5. Completed, refused, failed or expired: the application reports a terminal result.

The existing DM-v2 acknowledgment retains its current meaning: verified envelope, completed local dispatch and awaited history commit. It must not be renamed to imply consumer acceptance.

## Durable delivery

Use one shared durable delivery mechanism for obligations that require retry. Different protocols can have different payloads and completion rules. They must not each build a separate queue and crash-recovery system.

Save an accepted obligation before reporting durable admission. Retain it until its completion condition succeeds or a visible policy outcome ends it.

Each retry retains the same logical identity. Receivers detect duplicates across restart within the stated retention contract.

Delivery is at least once. An adapter records the event-to-run relation before it acknowledges acceptance. External effects require their own idempotency key or execution fence. x0x does not promise exactly-once shell commands or model calls.

A lost response after recipient commit must not force the sender to guess whether the work exists. A status query must distinguish confirmed results from unknown results.

## Consumer recovery

Each consumer has a durable position and explicit acknowledgments. Use separate positions for independent agents.

Subscribe to live data and recover stored data without an unreported gap. A consumer that falls beyond retention receives a clear resynchronization result. It must not silently skip to the newest event.

Apply current permissions to replay and live delivery. Retained history is not permission to disclose data to a revoked or removed participant.

An event envelope binds its source, destination, type, identity and relevant group or task. Correlation and causation fields support replies and diagnosis. Content references must retain the same access rules as inline content.

## Bounds and offline behavior

Define limits for count, bytes, age, retries and work per consumer. Refuse admission when the guarantee cannot be met. Record expiry, revocation and capacity failures as queryable outcomes.

An offline adapter can recover from its daemon. When all destination devices are offline, the sender can retain and retry within policy. Additional custodians require an explicit storage and trust decision.

Realtime media and best-effort presence do not use the durable work queue.

## Consequences

Callers can distinguish delivery from work completion and recover after a lost response. Durable queues consume storage. Consumers must handle duplicate events and explicit retention limits.

## Alternatives

A WebSocket alone gives low latency but does not provide durable consumer state.

A global central broker would provide a convenient queue service but add a dependency outside the current peer model. Borrow durable-consumer semantics without requiring that deployment.

## Validation

History, durable DM receipts, logical IDs and bounded backfill exist. The common Outbox design and full consumer inbox remain incomplete.

Test crash boundaries on both peers and the adapter. Test duplicate delivery, a lost acknowledgment, capacity refusal, expiry and revocation during replay.

## Matters to settle

Specify cursor scope, retention defaults and the sender-status query. Review any new wire or storage format under [A15](A15-r01-compatibility-validation-and-decision-rules.md) before implementation.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0021 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0021-dm-origin-machine-attestation.md) · [ADR 0023 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0023-durable-local-history.md) · [ADR 0028 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0028-authenticated-causal-predecessor-delivery.md) · [ADR 0029 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0029-public-message-threading.md) · [ADR 0030 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0030-dm-durable-application-ack-v2.md) · [ADR 0050 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0050-dm-over-gossip-base-transport.md) · [ADR 0077 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0077-share-grant-owner-side-redelivery-outbox.md)

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
