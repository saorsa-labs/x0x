# ADR-0002: Application-Level Keepalive for Direct Connections

## Status

Accepted

## Context

x0x agents discover each other via gossip identity announcements propagated through
bootstrap nodes. When an agent receives another agent's announcement, it automatically
initiates a direct QUIC connection to that agent's advertised address (the auto-connect
mechanism from ADR-0001's design philosophy — bootstrap peers are seed hints, agents
connect directly when possible).

These direct connections enable gossip pub/sub messages to flow between agents without
routing through bootstrap nodes. However, QUIC connections have an idle timeout —
ant-quic configures `max_idle_timeout` to 30 seconds. If no application data flows
on a direct connection for 30 seconds, QUIC closes it.

The existing gossip traffic patterns do not keep direct connections alive:

- **Identity heartbeats** (every 30s) are published to gossip topics and forwarded by
  PlumTree to eager peers. But PlumTree's eager forwarding may route through bootstrap
  nodes rather than the direct path, so the direct connection sees no traffic.

- **HyParView SHUFFLE** (every 30s) is sent to a random peer from the membership
  active view. The active view typically contains only bootstrap peers (the initial
  seed connections), not auto-connected agents. So SHUFFLE traffic never reaches
  direct connections.

- **SWIM failure detection** probes peers in the active view, which again contains
  only bootstrap peers.

The result: direct connections established via auto-connect are reliably closed by
QUIC after ~30 seconds of relative inactivity. NAT traversal testing confirmed this —
Level 4 (burst ping-pong) passes with 20/20 rounds, but Level 6 (sustained transfer
with 10-second intervals) fails after 2 rounds as the direct connection drops.

## Decision

Add an application-level keepalive mechanism in the gossip runtime that sends a
lightweight SWIM Ping to every connected peer every 15 seconds.

The keepalive task:

1. Runs as a background task in `GossipRuntime::start()`
2. Every 15 seconds, queries `connected_peers()` from the transport layer
3. Sends a SWIM `Ping` message to each connected peer
4. The remote peer responds with `Ack` (standard SWIM protocol behaviour)

This keeps both directions of every QUIC connection alive, well within the 30-second
idle timeout.

## Why Application-Level, Not Protocol-Level

QUIC has its own keepalive mechanisms (transport-level PING frames), but deciding
*which* connections to keep alive and how often is an application concern, not a
transport concern. ant-quic provides the transport — x0x decides which connections
matter.

Per the NAT traversal RFC (draft-seemann-quic-nat-traversal-02), connection
establishment is a transport concern, but connection maintenance is left to the
application. The RFC describes how to create NAT bindings via coordinated hole
punching, but keeping those bindings alive (by preventing the router from expiring
the UDP mapping) requires application-level traffic at a frequency determined by
the application's knowledge of NAT binding lifetimes.

## Why SWIM Ping

The SWIM Ping/Ack exchange is the lightest existing message in the gossip protocol
(~3 bytes serialized). It reuses the existing membership protocol — no new message
types needed. The remote peer's `handle_ping` method responds with an Ack and marks
the sender as alive, which is a useful side effect for failure detection.

## Trade-offs

- **Bandwidth**: 3 bytes × N peers × 4 messages/minute = negligible. For a network
  of 100 peers, this is ~1.2 KB/minute of keepalive traffic.

- **CPU**: One serialization + send per peer every 15 seconds. With 4 peers, this is
  trivial.

- **All connections kept alive**: This keeps every QUIC connection alive, including
  bootstrap connections that would survive anyway via other traffic. The overhead is
  minimal and the simplicity of "ping everyone" outweighs the complexity of tracking
  which connections specifically need keepalives.

## Alternatives Considered

1. **Increase QUIC idle timeout in ant-quic**: Would paper over the problem but doesn't
   address NAT binding expiry (home routers expire UDP bindings after 30-120 seconds
   regardless of QUIC settings).

2. **Add auto-connected peers to HyParView active view**: More architecturally pure
   but complex — HyParView's view management has specific invariants about view size
   and peer selection that would need careful integration.

3. **Reduce identity heartbeat interval**: Would increase gossip traffic for all peers,
   not just direct connections. Blunt instrument.

4. **QUIC transport-level PING**: Would require changes to ant-quic's transport
   configuration and doesn't address the application's need to control keepalive
   policy per connection type.
