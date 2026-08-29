# ADR-0030 mechanics — Key implementation facts and validation matrix

> Extracted 2026-08-29 from the immutable [ADR 0030](../adr/0030-dm-durable-application-ack-v2.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the grounding (branch-verified implementation facts) and the
> validation inventory relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

Key implementation facts (verified on the branch, 2026-08-13):

- Envelope layout is unchanged between v1 and v2; only ACK semantics differ
  (`src/dm.rs:1586-1588`). `protocol_version` is already in the signed
  bytes and mirrored in the ADR-0021 attestation.
- Strict sends fail closed with a clean, typed error — not a black hole:
  missing/insufficient capability ⇒ `DmError::AckSemanticsUnavailable` ⇒
  REST **409 `recipient_ack_semantics_unavailable`**, after a targeted
  capability refresh attempt (`src/lib.rs:5252-5262`, routes/direct.rs).
- `DmCapabilities.max_protocol_version` already exists on v0.37.x cards
  and adverts; 0.37 peers advertise 1. The branch adds strict predicates,
  signed capability adverts on `x0x/caps/v1`, and a targeted refresh
  protocol.
- Receiver ordering under v2: per-logical-request lock → replay-cache
  binding check → durable-history lookup → dispatch → **history commit
  awaited** → ACK. Commit failure withholds the ACK
  (`src/dm_inbox.rs:1157-1608`).
- Durable v2 is **at-least-once across restart** (documented on the
  branch in `dm-over-gossip.md`): the replay cache is memory-only; a
  restart can re-dispatch an already-committed envelope.

---

## Validation

Required before any slice merges; the full matrix before the 0.38 tag:

- new→new durable ACK: receiver history row committed before sender 200.
- new(strict)→0.37 peer: 409 `recipient_ack_semantics_unavailable`,
  bounded latency (no hang), after one forced refresh.
- new(explicit non-strict)→0.37 peer: delivered, `Ok` = level 2.
- 0.37→new: unchanged v1 delivery both message classes (DM + group).
- Restart + same `logical_id`/`request_id`: exactly one durable history
  row (`Duplicate` re-ACK), possible re-dispatch documented.
- Reused `logical_id` with different bytes: 409 `idempotency_conflict`.
- Consent bootstrap: stranger refused; Known + remove/re-add installs;
  outbox survives sender restart; obligation cleared only by
  frontier-matching v2 ACK.
- Wiring tests per ADR 0025 (dispatch-level, revert-guarded), not only
  unit tests — the F2 standard.
