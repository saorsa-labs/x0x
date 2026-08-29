# ADR-0003: Auto-Connect to Discovered Agents

## Status

Accepted — The identity listener auto-connects to discovered agents via `connect_addr()` in `start_identity_listener()` (`src/lib.rs`). Guards prevent redundant connections using an `auto_connect_attempted` HashSet. HyParView membership also contributes to overlay routing, but the direct auto-connect mechanism described here is implemented and active.

## Context

x0x agents discover each other through gossip identity announcements that propagate
through the bootstrap mesh. Each announcement contains the agent's network address
and transport peer ID. Before this change, discovery was read-only — the identity
listener cached the discovered agent's details but never initiated a connection.

This created a gap: two agents that shared bootstrap nodes could discover each other
via gossip, but couldn't exchange pub/sub messages. PlumTree's gossip overlay only
routes messages to directly-connected peers (those in the eager set), and the eager
set is populated from `connected_peers()`. Without a direct QUIC connection between
agents, they were invisible to each other's gossip routing.

The existing integration tests worked around this by explicitly adding one agent's
local address to the other's bootstrap peer list — forcing a direct connection at
startup. But this isn't viable in a real network where agents don't know each other's
addresses in advance.

## Decision

When the identity listener receives an announcement from a previously-unknown agent,
it initiates a direct QUIC connection to that agent's advertised address via
`connect_addr()`. The connection attempt is fire-and-forget (spawned as a separate
tokio task) so it doesn't block announcement processing.

Guards prevent redundant connections:
- Skip self-announcements (comparing agent IDs)
- Skip if already connected (checking `is_connected()`)
- Skip if already attempted (tracking agent IDs in a local `HashSet`)
- Skip if no address or transport peer ID in the announcement

Once the QUIC connection is established, the gossip topology refresh loop (running
every 1 second) automatically adds the new peer to PlumTree's eager set for all
topics. No additional wiring is needed — the existing infrastructure handles the
rest.

## Why This Approach

### Consistent with ADR-0001

ADR-0001 establishes that bootstrap peers are seed hints, not a privileged control
plane. Auto-connect extends this philosophy: bootstrap nodes help agents discover
each other, then agents connect directly. The bootstrap's role ends once the
introduction is made.

### Discovery Drives Connectivity

The alternative — a separate peer introduction protocol or explicit connection
management — would add complexity without benefit. The identity announcement already
contains everything needed to connect (address + transport peer ID). Acting on that
information immediately is the simplest path from discovery to connectivity.

### Gossip Handles the Rest

PlumTree's eager peer refresh means we only need to establish the QUIC connection.
Topic routing, message forwarding, and peer management are handled by the existing
1-second refresh loop. This keeps the auto-connect code minimal (~25 lines) and
avoids duplicating gossip overlay logic.

## Trade-offs

- **Connection storms in large networks**: With N agents, each could try to connect
  to all N-1 discovered agents. The `HashSet` deduplication prevents repeated
  attempts to the same agent, and `is_connected()` prevents redundant connections.
  For larger networks, a connection cap or selective connection strategy may be
  needed — but the current guards are sufficient for the near term.

- **One-directional initiation**: Only the discovering agent initiates the connection.
  If agent A discovers agent B first, A connects to B. B may also discover A and
  attempt to connect, but the `is_connected()` guard skips it since the connection
  already exists. This is efficient — exactly one connection per agent pair.

- **Depends on gossip propagation**: Auto-connect only fires when an identity
  announcement reaches the agent via gossip. If gossip routing is broken (e.g.,
  bootstrap nodes can't forward), auto-connect never fires. This is acceptable
  because if gossip doesn't work, there's nothing useful to do with the connection
  anyway.
