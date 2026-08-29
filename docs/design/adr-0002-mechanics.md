# ADR-0002 mechanics — Keepalive rationale, alternatives, and NAT-test evidence

> Extracted 2026-08-29 from the immutable [ADR 0002](../adr/0002-application-level-keepalive-for-direct-connections.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the rationale essays, alternatives detail, and NAT-traversal
> test evidence relocated verbatim so this file is their maintained home — future
> updates belong here, not in the ADR.

## NAT Traversal Testing Evidence

The result: direct connections established via auto-connect are reliably closed by
QUIC after ~30 seconds of relative inactivity. NAT traversal testing confirmed this —
Level 4 (burst ping-pong) passes with 20/20 rounds, but Level 6 (sustained transfer
with 10-second intervals) fails after 2 rounds as the direct connection drops.

---

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

---

## Why SWIM Ping

The SWIM Ping/Ack exchange is the lightest existing message in the gossip protocol
(~3 bytes serialized). It reuses the existing membership protocol — no new message
types needed. The remote peer's `handle_ping` method responds with an Ack and marks
the sender as alive, which is a useful side effect for failure detection.

---

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
