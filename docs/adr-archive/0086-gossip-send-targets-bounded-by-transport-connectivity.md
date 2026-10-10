# ADR 0086: Gossip Send Targets Are Bounded by Transport Connectivity

- **Status:** Accepted
- **Accepted:** 2026-09-28 by David Irvine (#1036 product fix; the implementation merged to main in #1059 ahead of acceptance and is ratified by this acceptance; OMP cross-model review round 1 approved the implementing PR; status change applied by Claude at his instruction)
- **Date:** 2026-09-28
- **Decision owners:** David Irvine (decision), Claude x0x-32 (drafting)
- **Reviewers:** OMP (cross-model review, per the 2026-09-28 resolution plan); David Irvine (acceptance)
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** ADR-0049. ADR-0049 records presence beacons over the global
  topic but does not say which peers a beacon is sent to. This ADR adds that
  rule: beacon and FOAF targets are connected peers only. ADR-0049's text is
  not edited.
- **Vision requirement:** R4 (connectivity better than Tailscale), with R3
  (all my machines connected). A daemon that fills its host's disk with log
  lines stops being a reliable node for every machine that depends on it.
  This is also a correctness fix to shipped behaviour (ADR 0072, item 5).
- **Related:** #1036 (P1: syslog flood of about 16 GB/day), the product PR
  from `fix/1036-stale-send-targets`, CI mirror #1037, ant-quic 0.27.54
  (tag `v0.27.54` = 08c284a9), N18 (upstream saorsa-gossip: HyParView never
  prunes never-connected peers), N28 (prod `RUST_LOG` drop-ins missing from
  `authority-inventory.json`), ADR-0026, ADR-0049, issue #206 and #292 (plane
  admission)

## Context

- **Every x0x gossip send needs a live connection.** All sends go through
  ant-quic's `send`. A send to a peer with no connection fails fast with
  `Peer not found`. Up to ant-quic 0.27.53 each such failure logged one
  `WARN` line of about 690 bytes.
- **Two send-target sets were not bounded by the transport.**
  - **HyParView active view.** saorsa-gossip adds peers to the active view
    from JOIN/FORWARDJOIN random walks, including peers several hops away
    that this node never connects to. Nothing prunes the view by transport
    connectivity. The view's peers are SWIM-probed (1 s period), shuffled and
    forwarded to for as long as they stay in it.
  - **Presence broadcast set.** x0x seeded presence beacon and FOAF targets
    from `active_view() ∪ connected_peers()`, so every stale active-view
    entry also got a beacon every 30 s.
- **What it cost.** On the prod fleet the stale entries produced thousands
  of fast-fail sends per hour per node (about 5,100 `send_error` lines per
  hour), which grew syslog by an estimated 16 GB/day. Relay nodes were hit
  hardest.
- **The ops mitigation is already live** on all six prod hosts: an rsyslog
  filter drops the `send_error` lines, logrotate has a `maxsize`, and
  systemd `RUST_LOG` drop-ins lower ant-quic's send logging. It stops the
  disk filling. It does not stop the useless sends, and it depends on
  per-host configuration that is not yet in the authority inventory (N28).

## Decision Drivers

- **I12 (resource bounds).** A daemon never fills its host's disk, and every
  bound is visible.
- **Stop the sends, not only the log lines.** Each useless send still
  builds a frame that is then dropped, and SWIM keeps probing peers that
  cannot answer.
- **Do not change gossip delivery semantics.** PlumTree eager/lazy planes,
  plane admission (#206/#292) and anti-entropy stay as they are.
- **Fixes only until v0.46.0.** The change must be small, local to x0x plus
  a patch-level ant-quic pin, and testable without sockets.
- **The root cause is upstream** (saorsa-gossip membership, N18). x0x needs
  a bound now that does not wait for an upstream release.

## Considered Options

1. **Ops only.** Keep the rsyslog filter, logrotate cap and `RUST_LOG`
   drop-ins; change no code. Rejected as the whole answer: the sends
   continue, every new host needs the same configuration, and a daemon run
   outside the fleet (a laptop, a new VPS) still floods.
2. **Log bounding in ant-quic only.** Pin ant-quic 0.27.54 and change
   nothing in x0x. Rejected as the whole answer: it bounds the log volume
   but x0x still sends to peers it can never reach.
3. **Fix HyParView upstream only** (N18: prune never-connected peers inside
   saorsa-gossip membership). This is the right long-term home. Rejected for
   v0.46.0 alone: it needs a saorsa-gossip release and a pin bump, and the
   presence broadcast set is x0x code anyway.
4. **Filter every send at the x0x transport** (`GossipTransport::send`
   refuses peers with no connection). Rejected: it hides the symptom at the
   last step, SWIM would still see those peers as live members and keep
   probing, and it changes the error contract for every caller.
5. **Prune immediately on disconnect** (threshold 0). Rejected: a peer that
   drops between two connectivity snapshots, or is mid-reconnect, would be
   churned out of and back into the active view, and each restore can
   demote another peer to the passive view.
6. **Bound send targets by transport connectivity in x0x, with a grace
   period, and pin ant-quic 0.27.54 for log bounding** (chosen).

## Decision

We will bound x0x's gossip send targets by transport connectivity:

1. **Stale threshold: 60 s.** `STALE_SEND_TARGET_AFTER` in
   `src/gossip/stale_targets.rs`. A peer counts as connected when it is in
   `NetworkNode::send_ready_peers()`, which is ant-quic
   `Node::connected_peers()` with no gossip-admission filter.
2. **Prune.** The existing 15 s membership keepalive pass in
   `GossipRuntime` also runs `maintain_active_view`. A HyParView active-view
   peer that has been absent from the connected snapshot for at least 60 s
   is removed with `Membership::remove_active`. The absence clock starts at
   the first pass that sees the peer disconnected and is kept after a prune,
   so a peer that a random walk re-adds while still disconnected is pruned
   again on the next pass without a fresh grace period.
3. **Restore.** A peer this node pruned is added back with
   `Membership::add_active` on the first pass that sees it connected again.
   Any connected sighting resets its absence clock.
4. **Presence targets are connected peers only.** Beacon and FOAF targets
   are `presence_broadcast_targets(active_view, connected_peers)`: the
   active view filtered to connected peers, plus the transport table.
   This applies at startup seeding and at the 30 s refresh.
5. **Connectivity means transport connectivity, not gossip admission.** A
   `PlanePending` peer (connected, plane hello not yet resolved, at most
   10 s) and a peer whose `PoolEviction`/`PolicyRejection` tombstone is
   live while its connection is still closing both count as connected. Only
   a send with no connection fails with `Peer not found`; gossip admission
   stays the job of `peer_admission` and `gossip_plane_peers`. Once a
   tombstoned or plane-refused peer's connection closes, it is an ordinary
   disconnected peer and is pruned one threshold later.
6. **Presence and pruning use the same connectivity source.**
   `NetworkNode::connected_peers()` (presence) and
   `NetworkNode::send_ready_peers()` (pruning) both return ant-quic
   `Node::connected_peers()` projected to peer ids. Over one snapshot a
   pruned peer is never a presence target and a presence target is never
   pruned. If either function gains a filter, this ADR needs revisiting.
7. **PlumTree planes are untouched.** Topic eager/lazy sets are already
   refreshed from the connected gossip plane every second, so IHAVE and
   anti-entropy repair reach a reconnecting peer as soon as it is connected
   again.
8. **Tracking is bounded.** The tracker keeps at most 4,096 absent and 4,096
   pruned peers (`MAX_TRACKED_PEERS`). Past the cap it drops absence clocks
   for peers no longer in the view, then all of them; a full pruned set is
   cleared.
9. **Dependency: ant-quic `=0.27.54`.** It bounds `Peer not found` send
   logging: the line is `DEBUG`, logged at most once per peer per 60 s
   window with a suppressed count, and peers past 4,096 tracked share one
   aggregate overflow window. Every not-found send is still counted in
   `EndpointStats::send_peer_not_found`. Real transport errors stay at
   `WARN`. The x0x pruning removes most of the sends; the ant-quic bound
   caps the log cost of whatever remains (sends inside the 60 s grace,
   races with a closing connection, other callers).
10. **The ops mitigation stays in place.** The rsyslog filter, logrotate
    `maxsize` and `RUST_LOG` drop-ins are not removed when this ships. They
    are defence in depth for other log sources and older binaries during a
    rolling upgrade. Removing any of them needs its own decision, backed by
    fleet evidence from this release. Recording the drop-ins in
    `authority-inventory.json` and deploy-check is tracked separately (N28).
11. **ANSI colour.** `x0xd` writes ANSI colour codes to stdout only when
    stdout is a terminal and `NO_COLOR` is unset; file and JSON sinks never
    carry them. Under systemd/journald the codes only inflated syslog.

## Consequences

### Positive

- Sends to peers with no connection stop within about 75 s of the
  disconnect (60 s threshold plus up to one 15 s pass), instead of lasting
  as long as the peer stays in the active view.
- SWIM stops probing pruned peers: `remove_active` marks them dead, so
  probes, shuffles and presence all stop together.
- Syslog volume from send failures drops to near zero, measured as
  `send_error` lines per 24 h after promotion (about 5,100 per hour before).
- The fix does not depend on any host configuration.

### Negative / Trade-offs

- **Flapping peers.** A peer that disconnects for 60 s or more, reconnects,
  and repeats is pruned and restored once per cycle. Each cycle is one
  `remove_active` plus one `add_active`. A peer that is connected only
  between two 15 s samples can still be pruned, because the tracker only
  sees the samples; it is restored on the first sample that sees it
  connected.
- **Restore can demote another peer.** saorsa-gossip's `add_active` demotes
  an arbitrary active peer to the passive view when the active view is
  full. A restore can therefore displace a healthy peer.
- **Pruned peers leave HyParView entirely.** `remove_active` does not move
  the peer to the passive view. It comes back only through this tracker's
  restore or a later random walk.
- **The 4,096 caps.** Past 4,096 pruned peers the pruned set is cleared: a
  peer that then reconnects is not restored explicitly (PlumTree and
  presence still reach it once it is connected; HyParView re-learns it by
  random walk). Past 4,096 absence clocks the clocks are dropped and absent
  peers get a fresh 60 s grace. Both are memory bounds, not expected
  operating points. ant-quic's 4,096-peer log table has the same shape:
  peers past it share one aggregate log line.
- **SWIM interaction.** `remove_active` marks the peer SWIM-dead and
  `add_active` marks it alive. A pruned peer that is in fact reachable by
  another route is reported dead to SWIM until it reconnects to this node.
  That matches this node's view (no connection), but SWIM state is now
  partly driven by the transport table rather than by probes.
- **Two sampling cadences.** Pruning samples every 15 s and presence every
  30 s. They share a source but not a clock, so for up to one pass a
  just-reconnected peer can be a presence target while still pruned from
  the view. This is benign and converges on the next pruning pass.
- **Workaround in x0x for an upstream defect.** When N18 lands in
  saorsa-gossip, part of this becomes redundant and should be reviewed.

### Neutral / Operational

- The ops mitigation stays in place on all six hosts (Decision 10).
- `#1036` stays open until 24 h of fleet evidence after promotion shows
  about zero `send_error` lines per 24 h.
- `x0xd` logs are uncoloured under systemd; operators who want colour run
  it in a terminal.

## Validation

- **Unit tests (inert, no sockets):** `src/gossip/stale_targets.rs`:
  threshold and grace, reconnect restore, no fresh grace on re-add, active
  view wiring, presence filter, pool-tombstoned peer pruned after the
  threshold, plane-pending peer counts as connected, and presence/pruning
  agreement over one snapshot. Each #1036 W2 test was shown red against a
  hand-revert of the logic it pins.
- **Fleet evidence:** after promotion, `send_error` lines per 24 h per host
  (target about 0 versus about 5,100 per hour before), with the rsyslog
  filter's drop counter as the cross-check; `EndpointStats::send_peer_not_found`
  growth rate; active-view size and prune/restore counts from the
  `x0x#1036` debug lines.
- **Review triggers:** revisit this ADR if `connected_peers()` or
  `send_ready_peers()` gains a filter, if saorsa-gossip lands N18, if the
  keepalive cadence changes, or if fleet data shows restore-driven demotion
  churn.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without
human review**. Accepted ADRs are immutable: create a new superseding ADR
rather than editing an Accepted ADR.
