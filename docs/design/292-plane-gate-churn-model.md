# Plane-Gate Churn Model — Issue #292 Invariant Set

**Issue:** [#292](https://github.com/saorsa-labs/x0x/issues/292) — cross-plane `PolicyRejection`
tombstone intermittently permits redial  
**Status:** All invariants A–F resolved. This document closes out invariant E (PlaneRefuse).

---

## Overview

The plane-gate churn model is the set of correctness properties that together guarantee
cross-plane peers cannot contaminate the gossip plane, even under scheduling races between
tombstone installation, QUIC disconnect, and inbound reconnect.

The invariants are anchored in `src/network.rs` with `// Issue #292 invariant X:` comments.

---

## Invariant Set

### A — Admission predicate outranks transport truth

`peer_admission` (`src/network.rs:3192`) is the single predicate gossip-affecting code must
consult. A peer with a live `reconnect_suppressions` tombstone returns `Suppressed` regardless of
what the ant-quic transport layer reports; a transient accept-to-close window or an in-flight
dial answered mid-handshake cannot produce an `Admitted` verdict.

**Test:** `tests/gossip_plane_isolation.rs` (causal oracle, all five cases)

### B — Per-frame gate drops suppressed-peer frames

Gossip frames received from a reconnect-suppressed peer are discarded at the receive pump
(`src/network.rs:4335`) before they reach the gossip layer. This closes the accept-to-close
window in which a `PolicyRejection`-tombstoned peer might slip one frame through after the
transport connection is observed but before the QUIC close is delivered.

**Test:** `tests/gossip_plane_isolation.rs` (cross-plane payload non-delivery)

### C — Outbound dial gate pre-socket

The outbound dial choke-point (`src/network.rs:3250`) checks the suppression tombstone before
opening a socket. A suppressed peer is refused with no socket, no `PeerConnected` event, no
cache write, and no tombstone mutation.

**Test:** `tests/gossip_plane_isolation.rs` (stay-down check)

### D — Inbound accept gate (admit-window race)

The inbound accept loop re-checks the tombstone after `accept()` yields
(`src/network.rs:3326`). A `PolicyRejection` tombstone present at accept time closes the
connection without emitting `PeerConnected`, using a plain transport close that must not
refresh the tombstone.

**Unit test:** `network::tests::inbound_admit_emits_no_peer_connected_when_policy_rejection_tombstone_is_live`  
**Integration test:** `tests/gossip_plane_isolation.rs`

### E — PlaneRefuse (CLOSED: subsumed by A + `disconnect_with_reason` ordering contract)

**Property described in #292:** a cross-plane peer whose plane hello mismatches must
receive a permanent `PolicyRejection` tombstone, not merely a transport close, so that the
`PlanePending → Admitted` path is permanently blocked.

**Resolution (2026-09-12):** this property is fully implemented and tested; it requires no
separate code anchor or test beyond what already exists.

The implementation proof:

1. `plane_handle_hello` (`src/network.rs:3483`) detects the plane mismatch and calls
   `disconnect_with_reason(&peer, PolicyRejection)`.
2. `disconnect_with_reason` (`src/network.rs:3128`) calls `self.suppress_reconnect(peer_id.0,
   reason)` at `src/network.rs:3133` **before** `node.disconnect()` — the tombstone is live
   before the QUIC connection is closed.
3. From that moment, `peer_admission` (`src/network.rs:3192`) returns `Suppressed` (invariant
   A), blocking all paths: gossip-frame drops (B), outbound dials (C), and inbound accepts (D).
4. `PolicyRejection` carries a `None` TTL (`src/network.rs:5537`) — the tombstone never expires.

No window exists between mismatch detection and `Suppressed` admission status in which a
PlaneRefuse peer could be treated as `PlanePending` or `Admitted`.

The existing integration test `cross_plane_pair_does_not_exchange_gossip` proves the full
observable chain: authenticated `Established` event, `PolicyRejection` disconnect event,
tombstone installation, transport close, and stay-down across eager-set refresh ticks.

Invariant E is therefore vacuous as an independent property: it is the composition of invariant
A and the ordering contract of `disconnect_with_reason`, both of which are already anchored and
tested. **Tracked in [#632](https://github.com/saorsa-labs/x0x/issues/632).**

### F — Refused dial/accept must not refresh tombstone

A refused outbound dial or inbound accept uses a plain transport close (calling
`close_suppressed_inbound` at `src/network.rs:5647`, never `disconnect_with_reason`) so that
an existing `PolicyRejection` tombstone's `set_at` timestamp is preserved. Refreshing it would
silently extend the suppression window in a way that could mask test-observable timing.

**Test observable:** `NetworkNode::reconnect_suppression_set_at` (test-only accessor);
`inbound_admit_emits_no_peer_connected_when_policy_rejection_tombstone_is_live` verifies the
tombstone timestamp is unchanged.

---

## Summary

| Invariant | Status | Primary anchor | Regression test |
|-----------|--------|----------------|-----------------|
| A | Implemented | `src/network.rs:3192` | `gossip_plane_isolation` |
| B | Implemented | `src/network.rs:4335` | `gossip_plane_isolation` |
| C | Implemented | `src/network.rs:3250` | `gossip_plane_isolation` |
| D | Implemented | `src/network.rs:3326` | unit + `gossip_plane_isolation` |
| **E** | **Subsumed** — see above | A + `src/network.rs:3128,3133,3483` | `gossip_plane_isolation` |
| F | Implemented | `src/network.rs:5647` | unit D companion |
