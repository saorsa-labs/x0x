# T-one-sided-peer-link: detect a one-sided link and re-dial it once

- **Status:** Proposed
- **Target slot:** A05
- **Date:** 2026-10-15
- **Decision owners:** David Irvine
- **Related:** #1419, ant-quic#332

## Context

A MASQUE relay connection can supersede the live link on one side only (ant-quic#332). The other side still reports the old connection as connected. `GET /health`, `GET /peers` and `GET /status` then read healthy. They count peers and send-ready winners. They do not compare send age and receive age across peers.

In eph run `r0481pre-e2e` (x0x `5b90adb`, ant-quic 0.27.60) one direction had `last_sent` at 610 s and the other had `last_received` at 725 s. Every other pair was under 2 s. Pubsub frames on the superseded generation were refused. SWIM acks and beacons timed out.

ant-quic owns the connection winner. This decision does not change that crate. It does not change the plane gate. Until ant-quic#332 is fixed, x0x must see the one-sided link and make one bounded re-dial so both sides install one connection.

## Decision

A connected peer is one-sided when its send age or its receive age is at least 60 s, and at least one other connected peer still has send or receive traffic at most 10 s old. A missing timestamp is not stale and does not count as flowing traffic. A single quiet peer is not one-sided. A node whose every peer is quiet is not one-sided.

The health refresher reads connection health. `GET /health` stays a lock-free read of that snapshot (issue #600). When the count is above zero, `GET /health` and `GET /status` are `degraded` and carry a reason. `ok` stays true. `GET /peers` sets `link` to `degraded` on that peer. The refresher writes one WARN line the first time that peer is one-sided. It writes the line again only after the peer recovers and the condition returns.

Repair is one re-dial. The node disconnects that peer and dials it again. The attempt has a 3 s bound. A suppressed peer is not dialled. The next attempt waits 60 s. A peer that recovers can be repaired again later. There is no wire change.

## Consequences

A fleet monitor that treats `status: "degraded"` as a page will see a one-sided link. A healthy mesh with fresh traffic keeps the same health response. The re-dial drops the old connection for that attempt. If ant-quic installs a one-sided winner again, x0x waits 60 s before the next attempt. It does not loop on the health tick.

## Alternatives

Wait for ant-quic#332 and leave the health response as it is. The daemon stays `healthy` while gossip on that peer is dead.

Re-dial on every health tick. A peer that does not recover is dialled without a bound.

Treat every idle peer as one-sided, including a lone peer. A quiet pair is torn down with no evidence that other traffic still flows.

## Validation

A simulation test moves the winner on one node only. The gate reports that peer. The re-dial runs once. Traffic then flows both ways. A second pass inside the backoff does not dial. A lone stale age, and a mesh where every peer is stale, stay off the list.
