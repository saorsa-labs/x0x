# T-file-control-ack: Application acknowledgement for file control frames

- **Status:** Proposed
- **Date:** 2026-10-12
- **Target slot:** A10
- **Decision owners:** David Irvine must accept this record before merge
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #1102; ADR 0055; ADR 0093; PR #1323

This record is Proposed. It is not a numbered ADR. David must accept it before merge.

## Context

ADR 0055 carries file transfer as JSON frames on the direct-message path. A raw QUIC receive-ACK means the transport drained the bytes. It does not mean the peer stored the offer. Issue #1102 shows a dropped frame while the sender observes HTTP 200. Slot A10 requires shared file data to name its holder and its failure result.

## Decision Drivers

- A dropped offer must not be reported as success.
- The peer that stores the offer, accept, or reject must confirm it.
- A chunk acknowledgement must not confirm a control frame.
- History must not store this confirmation as chat.
- This record must not allocate a new ADR 0093 capability bit.

## Considered Options

1. Keep the raw QUIC receive-ACK as success. This preserves false success.
2. Allocate a new ADR 0093 bit. That needs a separate accepted registry change.
3. Infer support from the crate version or DM protocol version 2. ADR 0093 rejects that inference. v0.47.0 and this tree advertise the same bits and the same DM protocol version. The crate version is still 0.47.0.
4. Add `file-control-ack` and wait for it from the addressed peer. This is the proposed option.

## Decision

We will add `FileMessage::ControlAck` with wire tag `file-control-ack`. The frame names the transfer id and the operation: `offer`, `accept`, or `reject`. The peer sends it only after it accepts that control frame. The sender waits for a matching frame from that same peer. A chunk acknowledgement whose id is `ctrl:<op>:<id>` must not complete the wait. An acknowledgement from any other agent must not complete the wait.

A missing acknowledgement fails the call. An offer becomes Failed and returns HTTP 500. An empty accept may return to pending so the caller can retry. Stored bytes stay. A chunk that has passed admission and has not yet updated the byte count stays in progress. The accept timeout and that admission are one state transition. History classifies the frame as ephemeral.

This record does not skip the wait for v0.47.0. No existing signal identifies a peer that sends the new frame. A later accepted decision must name that signal.

## Consequences

### Positive

- Success means the addressed peer committed the control frame.
- A forged chunk acknowledgement cannot finish the wait.
- Shutdown releases only the caller's waiter.

### Negative / Trade-offs

- A healthy v0.47.0 peer stores the offer and does not send `file-control-ack`. This build still reports failure, so a later accept cannot start.
- Concurrent accepts share one waiter. The last caller removes the map entry.

### Neutral / Operational

- Older peers ignore an unknown JSON tag.
- David must accept this Proposed record before merge.

## Validation

Tests must reject a chunk acknowledgement for `ctrl:<op>:<id>`, pause chunk zero across an expired accept wait, join a second accept on one slot, keep that slot when one waiter times out, and end a withheld acknowledgement on shutdown. History tests must keep the tag ephemeral.

## Notes for AI-assisted work

Do not mark this record Accepted. David accepts it before merge. Do not create a numbered ADR from this file. Do not allocate an ADR 0093 capability bit from this file.
