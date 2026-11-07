# T-ant-quic-0-27-61-transport-hardening: accept the ant-quic 0.27.61 receive-side changes

- **Status:** Accepted (David Irvine, 2026-10-17)
- **Target slot:** A05
- **Date:** 2026-10-17
- **Decision owners:** David Irvine. Only David accepts this record.
- **Reviewers:** David
- **Supersedes:** none
- **Superseded by:** none
- **Related:** x0x #1445 (release 0.48.1), ant-quic #331, ant-quic #335, ADR 0087 rule 8, A15

## Context

x0x 0.48.1 pins ant-quic `=0.27.61`. That version comes from ant-quic #331 and #335. It also pins saorsa-gossip `=0.5.90`. That bump changes only the ant-quic pin; the saorsa-gossip sources are unchanged from 0.5.89.

ant-quic 0.27.61 changes how a node receives stream data and DATAGRAM frames. Under ADR 0087 rule 8, a change to network behaviour needs an Accepted decision record before it merges to `main`. This record is that decision.

## Decision Drivers

- Fix the stream reassembly bugs that ant-quic #331 found.
- Follow RFC 9221 §3 for the DATAGRAM size limit.
- Keep the x0x API unchanged.

## Considered Options

1. Accept the ant-quic 0.27.61 receive-side changes.
2. Stay on ant-quic 0.27.60. This keeps the bugs that #331 fixes and the permissive DATAGRAM check. Rejected.
3. Check only the DATAGRAM payload against the limit. This does not comply with RFC 9221. Rejected.

## Decision

Use option 1. Accept these changes.

1. Stream reassembly merges overlapping or adjacent chunks. It does not copy buffered bytes again. `read_to_end` enforces its size bound and its entry-count bound.
2. The DATAGRAM receive limit applies to the whole encoded frame, as RFC 9221 §3 requires. The limit is capped at the advertised `u16` value. An advertised limit of 0 rejects every DATAGRAM frame.
3. The sender treats a peer limit of 0 or 1 as "datagrams unsupported". `max_size` returns `None`, and a send fails with `UnsupportedByPeer`.

## Consequences

### Positive

- Stream reassembly no longer copies buffered bytes again, and `read_to_end` stays inside its bounds.
- The DATAGRAM check complies with RFC 9221.

### Negative / Trade-offs

- An old sender can send an empty DATAGRAM to a peer that advertises a limit of 0 or 1. That peer now rejects the frame.

### Neutral / Operational

- No x0x API changes.
- The ant-quic sender already reserves the full 9 bytes of frame overhead, so x0x-to-x0x DATAGRAM traffic stays inside the limit.

## Validation

The ant-quic 0.27.61 tests cover reassembly merges, `read_to_end` bounds, the whole-frame DATAGRAM check, and the 0 and 1 limits. The x0x 0.48.1 CI runs against this pin.

## Notes for AI-assisted work

Fold only when David asks.
