# T-file-control-ack: Application acknowledgement for file control frames

- **Status:** Accepted
- **Date:** 2026-10-12
- **Accepted:** 2026-10-12 13:08 Europe/London by David Irvine, slot A10, option (b)
- **Target slot:** A10
- **Decision owners:** David Irvine
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #1102; ADR 0055; ADR 0093; PR #1323

David accepted this record at 13:08 London on 12 Oct 2026. He chose option (b) for slot A10. ADR 0093 bytes stay unchanged.

## Context

ADR 0055 carries file transfer as JSON frames on the direct-message path. A raw QUIC receive-ACK means the transport drained the bytes. It does not mean the peer stored the offer. A v0.47.0 peer stores the offer and does not send `file-control-ack`.

## Decision Drivers

- A dropped offer must not be success when the peer speaks the new frame.
- A stored offer on a v0.47.0 peer must count as success.
- The signal is a capability bit. A version string does not name this handler.
- A chunk acknowledgement must not confirm a control frame.
- History must not store this confirmation as chat.

## Considered Options

1. Option (a). Infer support from the crate version or DM protocol version 2. ADR 0093 rejects that inference.
2. Option (b). Add capability bit 3, `file_control_ack_v1`. Wait only when a verified advert sets that bit. David accepted this option.
3. Always wait. A healthy v0.47.0 peer then returns HTTP 500 and the send becomes Failed.

## Decision

We will add `FileMessage::ControlAck` with wire tag `file-control-ack`. The frame names the transfer id and the operation: `offer`, `accept`, or `reject`.

Bit 3 is `file_control_ack_v1` (`1 << 3`). Bits 0, 1, and 2 stay assigned. This record allocates bit 3. It does not edit ADR 0093.

A node waits for `file-control-ack` only when the peer's current verified advert sets bit 3. A missing acknowledgement fails the call. An offer becomes Failed and returns HTTP 500. An empty accept may return to pending.

A verified advert without bit 3 is v0.47.0. Do not wait. Do not send the frame. A stored offer is success. Do not return HTTP 500. Do not mark the send Failed.

No verified advert uses that success path. Do not wait. Still send the frame. The peer may already be waiting on this node's advert. A v0.47.0 peer ignores the unknown tag.

A chunk acknowledgement whose id is `ctrl:<op>:<id>` must not complete the wait. An acknowledgement from any other agent must not complete the wait. History classifies the frame as ephemeral.

## Consequences

### Positive

- A peer that advertises bit 3 reports success only after it commits the control frame.
- A v0.47.0 peer that stores the offer keeps a working transfer.
- A forged chunk acknowledgement cannot finish the wait.

### Negative / Trade-offs

- No verified advert uses the old path. A new peer whose advert has not arrived can still report success for a dropped offer.
- Concurrent accepts share one waiter. The last caller removes it.

### Neutral / Operational

- David folds this Accepted record into slot A10 only when he asks.

## Validation

A v0.47.0 advert without bit 3 must treat a stored offer as success. A peer that advertises bit 3 must wait for `file-control-ack`. Tests must reject a chunk acknowledgement for `ctrl:<op>:<id>` and must keep the history tag ephemeral.

## Notes for AI-assisted work

Do not fold this Accepted record in this pull request. Do not edit ADR 0093 to add bit 3.
