# A07 Messages Receipts History and Retry

- **Status:** Accepted (David, course-correction directive, 7 Nov 2026, ruling 2)
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Active since 7 November 2026. The 15 accepted slots are the live decision authority.
- **Supersedes:** The archived numbered records mapped to this slot in [TRANSFER.md](TRANSFER.md). The archive stays the historical record. Existing implementation gates remain in force.

David accepted the 15 slots at their current revisions on 7 November 2026 (course-correction directive, ruling 2). They are the live decision authority. The numbered records stay in [docs/adr-archive](../../adr-archive/ARCHIVE.md) as the historical record. [docs/adr-archive/move.json](../../adr-archive/move.json) records the archive transfer David accepted on 10 October 2026. Use the [index](README.md) for the current rules.

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

The existing DM-v2 acknowledgment retains its current meaning ([ADR 0030](../0030-dm-durable-application-ack-v2.md) §1 and §7; [ADR 0116](../0116-local-history-retention-policy.md) §3). A successful acknowledgment confirms a verified envelope and a durable local record. For an ordinary DM, local dispatch completes, and then the recipient awaits a history commit or matches an existing committed row. A registered durable protocol handler confirms its own store. The acknowledgment must not be renamed to imply consumer acceptance.

## Durable delivery

Use one shared durable delivery mechanism for obligations that require retry. Different protocols can have different payloads and completion rules. They must not each build a separate queue and crash-recovery system.

Save an accepted obligation before reporting durable admission. Retain it until its completion condition succeeds or a visible policy outcome ends it.

Each retry retains the same logical identity. Receivers detect duplicates across restart within the stated retention contract.

Delivery is at least once. An adapter records the event-to-run relation before it acknowledges acceptance. External effects require their own idempotency key or execution fence. x0x does not promise exactly-once shell commands or model calls.

A lost response after recipient commit must not force the sender to guess whether the work exists. A status query must distinguish confirmed results from unknown results.

A late durable DM acknowledgment is recorded (amendment of 14 Nov 2026, #1109). A durable (v2) `POST /direct/send` that runs out of its budget answers 504 with `outcome: "ack_unknown"` and the caller's `logical_id` (null when the caller gave none). A 504 means the result is unknown, not that the message was not delivered. When the send gives up, the sender keeps a record of the request: its id and the exact binding of the abandoned waiter (recipient agent, the recipient machine when pinned, protocol version). If an `Accepted` v2 acknowledgment with that exact binding arrives later, the record changes to `delivered_late`. A mismatched sender, machine or protocol, a v1 acknowledgment, or a refusal changes nothing. A v2 acknowledgment inside the budget is recorded as `delivered`, and a later resend under the same logical id that gives up does not hide it. `GET /direct/receipts/{logical_id}?agent_id=<recipient>` (CLI `x0x direct receipt`) reports `delivered`, `delivered_late`, `pending` or `unknown`. The recipient is part of the key because a logical id is scoped to one directed pair. Records live for 10 minutes after the send resolved or gave up, at most 4,096 of them; the oldest goes first, and an expired or evicted record reads `unknown`. The records are in memory only; a restart forgets them. v1 sends keep no record. No wire change. Authority: David delegated design decisions to Claude, chat 10 Nov 2026; the coordinating Claude session chose this design on 14 Nov 2026.

A durable send can be queued until a deadline (amendment of 16 Nov 2026, #1109 slice S1; Claude under David's delegation of 10 Nov 2026 and A15). This is option 2 of the triage comment on #1109. `POST /direct/send` with `deliver_until_ms` (unix ms) and a `logical_id` runs every existing pre-send check, writes the send to a durable outbox in the daemon data directory, and answers 202 `outcome: "queued"`. The request needs durable semantics and a deadline that is in the future and at most 24 hours ahead; otherwise it answers 400 (`deliver_until_requires_durable`, `deliver_until_requires_logical_id`, `deliver_until_passed`, `deliver_until_too_far`). A repeat with the same `logical_id`, recipient and bytes answers the same 202 and stores nothing new; other bytes answer 409 `idempotency_conflict`. A worker sends each queued send once per due pass with the durable config under its request id, so the recipient's replay cache makes every attempt one request. A late acknowledgment of an earlier attempt settles the send as delivered with no new send. A cold recipient (no v2 capability advert yet), a timeout, an offline peer and the other transient errors keep the send and schedule the next attempt (2, 5, 10, 30, then 60 s). Any other error drops it as `failed` with the route's error code. At the deadline it is dropped as `expired`, and no attempt runs past the deadline. The outbox survives a restart, and `GET /direct/receipts/{logical_id}` reads `queued` while the send is held. The `delivered`, `expired` and `failed` outcomes are kept in memory with the receipt ledger's bounds. Caps: 64 sends or 4 MiB per recipient and 1,024 sends or 32 MiB per daemon; a full outbox answers 429 `outbox_full` and never evicts an accepted send. A sidecar that fails its checks at startup is moved aside and the outbox starts empty. Review changes of the same date: every receipt is bound to the BLAKE3 digest of the payload it proves delivered, so a receipt for other bytes under the same logical id neither settles a queued send nor lets other bytes be queued under that key (409 `idempotency_conflict`). Before each attempt the worker checks the recipient again; a blocked or revoked contact ends the send as `failed` with `recipient_blocked`, and blocking a contact removes its queued sends. 202 needs a confirmed directory sync; otherwise the answer is 503 `outbox_not_durable`. `DELETE /direct/receipts/{logical_id}` cancels a held send (`cancelled`). Retries run on a monotonic clock; only the deadline uses the wall clock, and after a restart every held send is due at once. Queued payloads are stored unsealed on disk, in a file with owner-only permissions (0600). No wire change.

Queued-send outcomes survive a restart (amendment of 16 Nov 2026, #1109 slice S2; Claude under David's delegation of 10 Nov 2026 and A15). The terminal outcomes of a queued send (`delivered`, `expired`, `failed` with its code, `cancelled`), each with the BLAKE3 digest of its payload, are written to an owner-only sidecar next to the outbox, kept 24 hours and at most 4,096 (oldest first), and loaded at start, so `GET /direct/receipts/{logical_id}` answers the same after a restart. A bad sidecar is moved aside and the daemon starts. An accepted v2 acknowledgment that matches no waiter and no record (for example after a restart) settles a held send as delivered without another send, only when the acknowledgment's authenticated agent is the send's recipient; anything else changes nothing, and the acknowledgment handling and origin attribution are unchanged. When a recipient's verified capability advert that supports durable delivery arrives, its held sends become due at once; the worker's own interval keeps the scheduled passes whatever the wake-up rate. Review changes of the same date: before each attempt the daemon durably records the digest of the bytes it sends under that request id (kept 24 hours with the outcomes). An orphan acknowledgment settles a held send only when exactly one digest was ever attempted under that id, to that recipient, and it equals the held bytes; after `expired`, `failed` or `cancelled` the same acknowledgment records `delivered_late` with that digest; anything else changes nothing and is logged. Other bytes under an id whose earlier bytes were attempted answer 409 `idempotency_conflict`, because their delivery cannot be known. Every transition writes the outcome durably before it removes the obligation; a failed outcome write leaves the send held (a cancel answers 503 `outbox_not_durable`), and at load an obligation that also has an outcome is removed. No wire change.

Three limits on the queued-send worker (amendment of 17 Nov 2026, review of #1983; Claude under David's delegation of 10 Nov 2026 and A15). First, an advert nudges one recipient at most once every 2 seconds, so a flood of adverts cannot resend faster than the first retry interval. Second, attempt records are never dropped by count before their 24 hours: when held sends and attempt records together reach 4 096, a new queued send answers 429 `outbox_full`. Third, when a pass decides an outcome but cannot write it, the outcome is kept in memory and the next pass writes it again without a new attempt; a restart forgets it, and the send is decided again. No wire change.

A late acknowledgment after a restart must come from the recipient machine (amendment of 17 Nov 2026, #2007; Claude under David's delegation of 10 Nov 2026 and A15). Before a restart, a v2 acknowledgment must match the agent and the machine that the waiter was sent to. After a pass, the attempt record of each request ID also keeps the recipient machine IDs that the attempts were sent to (at most 4, oldest first). An orphan acknowledgment settles a held send, or records `delivered_late`, only when its authenticated agent is the recipient and the machine it came from is in that list. That machine is the attested or bound machine of the ACK, else the machine it claims, the same value a waiter checks before a restart. An acknowledgment from the same agent on another machine changes nothing. An attempt record with no machine, for example one written before this amendment, still loads, but no orphan acknowledgment settles it; the held send is sent again. A crash between an attempt and the end of its pass also leaves no machine, with the same result. The sidecar gains an optional field; no wire change and no API change.

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

History, durable DM receipts, logical IDs and bounded backfill exist. ADR 0116 recording and retention policy is implemented. By default, `dm_recording` is `inherit`. With `ephemeral`, a new ordinary DM-v2 request without a committed row is withheld before dispatch and gets no acknowledgment; a matching committed duplicate can still be acknowledged. Grant redelivery and public-group bootstrap have separate outboxes. The shared durable delivery mechanism and full consumer inbox are not implemented.

Test crash boundaries on both peers and the adapter. Test duplicate delivery, a lost acknowledgment, capacity refusal, expiry and revocation during replay.

## Matters to settle

Specify cursor scope, retention defaults and the sender-status query. Review any new wire or storage format under [A15](A15-r01-compatibility-validation-and-decision-rules.md) before implementation.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0021 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0021-dm-origin-machine-attestation.md) · [ADR 0023 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0023-durable-local-history.md) · [ADR 0028 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0028-authenticated-causal-predecessor-delivery.md) · [ADR 0029 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0029-public-message-threading.md) · [ADR 0030 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0030-dm-durable-application-ack-v2.md) · [ADR 0050 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0050-dm-over-gossip-base-transport.md) · [ADR 0077 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0077-share-grant-owner-side-redelivery-outbox.md)

David placed [ADR 0116](../0116-local-history-retention-policy.md) in A07 on 10 Oct 2026. It amends ADR 0023. It also touches [A08](A08-r01-groups-home-membership-and-repair.md) and cites [ADR 0030](../0030-dm-durable-application-ack-v2.md). Those links are not a second placement.

Decision source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Implementation checked on 12 October 2026 at commit `8cb6488331e6c1226913104ddb99ca4ec18bec37`.

[All 15 ADRs](README.md)
