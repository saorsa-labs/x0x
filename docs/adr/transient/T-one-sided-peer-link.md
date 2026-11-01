# T-one-sided-peer-link: detect a one-sided link and re-dial it once

- **Status:** Proposed
- **Target slot:** A05
- **Date:** 2026-10-15 (both-directions-stale probe added 2026-10-31)
- **Decision owners:** David Irvine
- **Related:** #1419, ant-quic#332

## Context

A MASQUE relay can supersede the live link on one side only (ant-quic#332). The other side still reports the old connection as connected. `GET /health`, `GET /peers` and `GET /status` then read healthy. The eph `r0481pre-e2e` run also saw both directions idle on one peer, 610 s sent and 725 s received, while every other pair stayed under 2 s.

`last_sent_at` and `last_received_at` in ant-quic 0.27.60 count application data only. A healthy peer can be quiet on both directions. Ages alone cannot tell that quiet link from a broken one.

ant-quic owns the connection winner. This decision does not change that crate or the plane gate. Until ant-quic#332 is fixed, x0x detects a one-sided link and makes one bounded re-dial.

## Decision

A connected peer is one-sided when one direction on that same peer is at least 60 s old and the other direction is at most 10 s old. A missing timestamp is neither. Both directions stale, both missing, or one stale and the other between those bounds, are not one-sided by ages alone. Fresh traffic on a different peer does not select a quiet peer by itself.

A peer with both directions at least 60 s old, while another sampled peer still has traffic, is a liveness-probe candidate. The probe is the existing ant-quic `probe_peer` envelope, bounded at 3 s. Only a failure that names the link confirms it: the probe timed out, or the connection was closed, including a superseded connection. A generic send error is not counted, because the endpoint also uses it for local failures. A busy endpoint (`ProbeOverBudget`), a shutdown, a peer that left the table and a peer without probe support are inconclusive. An inconclusive peer is neither degraded nor dialled, and an inconclusive probe extends no confirmation, so a peer is degraded and re-dialled only while a confirming probe sits inside the 60 s window. Each peer is probed at most once per 60 s window; a successful re-dial spends the verdict, so that link's next probe starts fresh. At most two probes run per health tick, never-probed candidates first and then the longest since their last probe. Two sits inside ant-quic's endpoint-wide budget of four probe slots, so other probe callers keep headroom. A probe whose send stalls past the outer bound keeps running in its own task until ant-quic finishes it, because a probe dropped mid-flight would leave ant-quic's in-flight mark stuck and fail every later probe on that connection. Such a flight can outlive the 60 s per-peer window, so one peer can briefly hold two probes at once; that stays inside ant-quic's four slots. Shutdown aborts and joins every live flight, so no flight outlives the endpoint. Each probe is under an outer 4 s bound, one second more than the probe budget, because ant-quic's own bound starts at the reply wait. A probe that cannot finish inside the outer bound counts as a probe timeout. A peer this node probed inside the last 14 s does not count as the flowing peer for another candidate, so probing cannot bootstrap probing on a quiet node, and a node whose every peer is quiet and unconfirmed probes nobody. A peer already confirmed broken is probed again after its window even when nothing else flows. A confirmed peer stays in the degraded set while its sample stays both-directions stale inside the window, also when every other peer goes quiet. While the probe cooldown is live, the send-fresh shape the probe itself creates does not act through the immediate same-peer rule: this node's own send is not peer traffic. A successful re-dial spends the verdict, so a healed link leaves the set at once.

The health refresher resolves the probe, stores the one-sided peer set, then returns. It does not wait on a re-dial. `GET /health` stays a lock-free snapshot read (issue #600). When the count is above zero, `GET /health` and `GET /status` are `degraded` and carry a reason. `ok` stays true. `GET /peers` reads that stored set and sets `link` to `degraded`. One WARN is written the first time a peer is one-sided, and again after recovery or after a quiet sample ended the episode.

Repair disconnects that peer and dials it once, with a 3 s bound. A suppressed peer is not dialled. The next attempt waits 60 s. The disconnect is reconnect-eligible, so the scheduler also sees it. Both share one dial permit. A claim cancels the scheduler attempt. The permit leaves the map when the repair finishes, or when the peer is gone, unless another holder remains. Recovery means the peer carries traffic on one direction. A quiet sample clears the warning only while no live confirmation says the link is broken. A sample that omits the peer is not recovery. There is no wire change.

## Consequences

A monitor that pages on `degraded` will see a one-sided link, in one direction or both. A quiet peer stays up: it answers the probe. Peer counts stay current while a re-dial waits. A refresher tick waits at most the 4 s outer probe bound while a probe is due, beside the wait for the node lock. A node with at least one flowing peer probes each quiet peer about once a minute.

## Alternatives

Wait for ant-quic#332. The daemon stays `healthy` while one direction is dead.

Re-dial on every health tick. A peer that does not recover is dialled without a bound.

Flag a peer because a different peer had recent traffic. A quiet peer is then torn down. Fresh traffic elsewhere now starts only a probe; the probe failure selects.

Treat every idle peer as one-sided. A quiet pair is torn down.

Probe without bounds and disconnect on any failure. This record probes at most once per peer per 60 s window, treats an inconclusive probe as inconclusive, and re-dials once per window.

## Validation

A quiet peer stays up while another peer is fresh: the quiet link answers the probe. A one-ended winner refuses that end's sends and its probe. The other end can still deliver, so the peer is degraded. A both-directions-stale link while another peer flows fails the probe, is degraded, warns once and is re-dialled once. Both directions deliver after that re-dial. The confirmed failure stays degraded when every other peer goes quiet, and is probed again after the window. A busy endpoint, an unsupported peer and a missing peer are inconclusive: they do not dial and extend no confirmation. A second pass inside the backoff does not dial and does not warn again. A healed link leaves the degraded set at once. An empty sample keeps the warning and does not dial. A quiet sample without a confirmation clears the warning and keeps the backoff. The degraded count is stored before the repair task runs. The dial permit does not stay after the repair, or after the peer is gone, unless another holder remains. An active hold, and a claim during the cache wait, do not dial.
