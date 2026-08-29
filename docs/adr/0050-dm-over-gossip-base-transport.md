# ADR 0050: Direct Messages Ride a KEM-Sealed, Signed, Replay-Protected Gossip Base

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0021 (origin-machine attestation amends it); ADR-0030 (durable ACK v2 amends it); `docs/design/dm-over-gossip.md`. Backfill record for the base transport those ADRs amend.

## Context

DMs moved from raw QUIC streams to a gossip-borne sealed-envelope format
with no ADR for the base transport — ADRs 0021/0030 only amend it. A `DmEnvelope`
carries version, request ID, sender/machine/recipient IDs, time bounds, body,
and an ML-DSA signature (`src/dm.rs:164`). The payload is ML-KEM-768
encapsulation of a per-message content key plus ChaCha20-Poly1305 AEAD
(`src/dm.rs:222,1391`).

## Decision Drivers

- Delivery must not require a direct connection or inbound reachability.
- Replayed or re-ordered envelopes must be detectable with bounded state.
- Receipt semantics must be explicit on the wire, not inferred.

## Considered Options

1. Raw QUIC streams only (legacy `0x10`, `src/direct.rs:80-84`).
2. Transport-layer security over gossip.
3. Signed KEM-sealed envelopes over gossip with bounded replay cache and explicit ACK outcomes (chosen).

## Decision

1. Envelope: ML-DSA-signed `DmEnvelope`; payload sealed per-recipient with
   ML-KEM-768 + ChaCha20-Poly1305 (`src/dm.rs:164,222,1391`). Protocol
   level 2 is the durable-ACK version (`DM_PROTOCOL_DURABLE_ACK = 2`,
   `src/dm.rs:32`); receivers drop higher versions without ACK.
2. Replay protection is a bounded LRU `RecentDeliveryCache` keyed by
   `(sender_agent_id, request_id)` — 10,000 entries, 630 s TTL (max
   envelope lifetime 600 s plus 30 s skew tolerance,
   `src/dm.rs:1014,1080`); durable ACKs additionally bind a digest of the
   exact accepted bytes (`DmDurableBindingDigest`, `src/dm.rs:1039`).
3. ACK outcomes are wire-explicit: `Accepted`, `RejectedByPolicy`,
   `AckSemanticsUnavailable`, `IdempotencyConflict`
   (`DmAckOutcome`, `src/dm.rs:263`); receipt path is reported as
   `DmPath::{Loopback, GossipInbox, RawQuic, RawQuicAcked, relay}` (`src/dm.rs:815`).
4. Sender path selection is capability-driven (`src/lib.rs:5141-5145,
   5350-5389`): gossip-inbox is chosen when the recipient advertises
   `gossip_inbox` with a non-empty KEM key; raw QUIC is attempted first
   only when neither gossip nor durable ACK is required
   (`src/lib.rs:5520-5549`); strict durable sends never silently downgrade (`src/lib.rs:5354-5458`).

## Consequences

### Positive

- DMs work behind NAT with no inbound path; replay state is bounded;
  senders learn real outcomes.

### Negative / Trade-offs

- Raw-QUIC fallback still exists (`src/direct.rs:80-84`) although the
  design doc announced its removal in 0.19.0/0.20.0 — doc drift, code wins.

### Neutral / Operational

- `docs/design/dm-over-gossip.md` remains the reference; its embedded
  `DM_PROTOCOL_VERSION = 1` example predates v2.

## Validation

- `src/dm.rs` round-trip/replay/timestamp-window tests; capability
  dispatch tests in `src/lib.rs`; ADR-0030's validation matrix (now in
  `docs/design/adr-0030-mechanics.md`).

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
