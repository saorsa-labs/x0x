# T-one-sided-peer-link: detect a one-sided link and re-dial it once

- **Status:** Proposed
- **Target slot:** A05
- **Date:** 2026-10-15
- **Decision owners:** David Irvine
- **Related:** #1419, ant-quic#332

## Context

A MASQUE relay can supersede the live link on one side only (ant-quic#332). The other side still reports the old connection as connected. `GET /health`, `GET /peers` and `GET /status` then read healthy. They do not compare send age and receive age.

In eph run `r0481pre-e2e` (x0x `5b90adb`, ant-quic 0.27.60) one direction had `last_sent` at 610 s and the other had `last_received` at 725 s. Every other pair was under 2 s.

ant-quic owns the connection winner. This decision does not change that crate or the plane gate. Until ant-quic#332 is fixed, x0x detects the one-sided link and makes one bounded re-dial so both sides install one connection.

## Decision

A connected peer is one-sided when its send age or its receive age is at least 60 s, and another connected peer still has send or receive traffic at most 10 s old. A missing timestamp is not stale and is not flowing traffic. A single quiet peer is not one-sided. A node whose every peer is quiet is not one-sided.

The health refresher reads connection health off the request path. `GET /health` stays a lock-free snapshot read (issue #600). The refresher stores the one-sided count before it waits on a re-dial. A re-dial may take 3 s and peers are repaired one at a time, so the degraded signal does not wait. When the count is above zero, `GET /health` and `GET /status` are `degraded` and carry a reason. `ok` stays true. `GET /peers` sets `link` to `degraded`. The refresher writes one WARN the first time a peer is one-sided, and again only after that peer recovers and the condition returns.

Repair disconnects that peer and dials it once. The attempt has a 3 s bound. A suppressed peer is not dialled. The next attempt waits 60 s. The disconnect is reconnect-eligible, so the proactive scheduler also sees it. The scheduler waits out the same 60 s. It does not start its 1 s ladder inside that window. The repair dial is the attempt for the window. Recovery means the peer is connected and neither direction is stale. Recovery clears the warning. The 60 s timestamp stays. A sample that drops the peer because no other peer has fresh traffic is not recovery. That sample keeps the warning and the timestamp. There is no wire change.

## Consequences

A monitor that treats `degraded` as a page will see a one-sided link. If ant-quic installs a one-sided winner again, x0x waits 60 s. It does not loop on the health tick.

## Alternatives

Wait for ant-quic#332 and leave health as it is. The daemon stays `healthy` while gossip on that peer is dead.

Re-dial on every health tick. A peer that does not recover is dialled without a bound.

Treat every idle peer as one-sided. A quiet pair is torn down with no evidence that other traffic still flows.

## Validation

A simulation moves the winner on one node. The gate reports that peer. The re-dial runs once. A second pass inside the backoff does not dial. A lone stale age, and a mesh where every peer is stale, stay off the list. An empty or inconclusive sample does not warn again and does not dial. The degraded count is stored before the re-dial wait. The scheduler does not dial inside the 60 s window. A delayed or discarded simulated frame does not count as received.
