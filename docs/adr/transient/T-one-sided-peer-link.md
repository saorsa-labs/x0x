# T-one-sided-peer-link: detect a one-sided link and re-dial it once

- **Status:** Proposed
- **Target slot:** A05
- **Date:** 2026-10-15
- **Decision owners:** David Irvine
- **Related:** #1419, ant-quic#332

## Context

A MASQUE relay can supersede the live link on one side only (ant-quic#332). The other side still reports the old connection as connected. `GET /health`, `GET /peers` and `GET /status` then read healthy.

`last_sent_at` and `last_received_at` in ant-quic 0.27.60 count application data only. A healthy peer can be quiet on both directions. An eph run with both ages above 600 s, while other pairs were fresh, is not this rule. Both ages on that peer were stale.

ant-quic owns the connection winner. This decision does not change that crate or the plane gate. Until ant-quic#332 is fixed, x0x detects a one-sided link and makes one bounded re-dial.

## Decision

A connected peer is one-sided only when one direction on that same peer is at least 60 s old and the other direction is at most 10 s old. A missing timestamp is neither. Both directions stale, both missing, or one stale and the other between those bounds, are not one-sided. Fresh traffic on a different peer does not select a quiet peer.

The health refresher stores the one-sided peer set, then returns. It does not wait on a re-dial. `GET /health` stays a lock-free snapshot read (issue #600). When the count is above zero, `GET /health` and `GET /status` are `degraded` and carry a reason. `ok` stays true. `GET /peers` reads that stored set and sets `link` to `degraded`. One WARN is written the first time a peer is one-sided, and again only after recovery.

Repair disconnects that peer and dials it once, with a 3 s bound. A suppressed peer is not dialled. The next attempt waits 60 s. The disconnect is reconnect-eligible, so the scheduler also sees it. Both share one dial permit. A claim cancels the scheduler attempt. The permit leaves the map when the repair finishes, or when the peer is gone, unless another holder remains. Recovery means the peer is still connected and is not one-sided. A quiet peer clears the warning and keeps the 60 s timestamp. A sample that omits the peer is not recovery. There is no wire change.

## Consequences

A monitor that pages on `degraded` will see a one-sided link. A quiet peer stays up. A repeated one-sided winner waits 60 s. Peer counts stay current while a re-dial waits.

## Alternatives

Wait for ant-quic#332. The daemon stays `healthy` while one direction is dead.

Re-dial on every health tick. A peer that does not recover is dialled without a bound.

Flag a peer because a different peer had recent traffic. A quiet peer is then torn down.

Treat every idle peer as one-sided. A quiet pair is torn down.

Probe a quiet peer and disconnect when the probe fails. A probe can drop a healthy quiet peer. This decision does not probe.

## Validation

A quiet peer stays up while another peer is fresh. One stale direction and one fresh direction on the same peer is on the list. The re-dial runs once. A second pass inside the backoff does not dial. An empty sample keeps the warning and does not dial. A quiet sample clears the warning and keeps the backoff. The degraded count is stored before the repair task runs. The dial permit does not stay after the repair, or after the peer is gone, unless another holder remains. An active hold, and a claim during the cache wait, do not dial.

