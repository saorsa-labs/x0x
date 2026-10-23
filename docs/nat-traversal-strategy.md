# NAT Traversal Strategy

x0x builds on `ant-quic`'s native QUIC NAT traversal. This document describes how x0x discovers, classifies, and connects to agents behind NATs.

## Transport Layer

All NAT traversal is performed by `ant-quic` at the QUIC protocol level using extension frames from `draft-seemann-quic-nat-traversal-02`. x0x does **not** use STUN, ICE, or TURN.

The key frames:
- `ADD_ADDRESS` — advertise candidate addresses
- `PUNCH_ME_NOW` — coordinate simultaneous hole-punching
- `OBSERVED_ADDRESS` — report a peer's observed external address

## NAT Classification

When a network node is running, `NetworkNode::node_status()` returns `ant_quic::NodeStatus` which includes the NAT type. x0x maps this to a string in identity announcements:

| NAT Type | `nat_type` string | `likely_direct()` | `needs_coordination()` |
|----------|-------------------|-------------------|------------------------|
| No NAT | `"None"` | true | false |
| Full Cone | `"FullCone"` | true | false |
| Address Restricted | `"AddressRestricted"` | true (optimistic) | false |
| Port Restricted | `"PortRestricted"` | true (optimistic) | false |
| Symmetric | `"Symmetric"` | false | true |
| Unknown | `"Unknown"` or `None` | true (optimistic) | false |

## Reachability Heuristics

`ReachabilityInfo::likely_direct()` decides whether to attempt a direct connection:

```
if no addresses                   → false
if can_receive_direct = Some(true)  → true
if can_receive_direct = Some(false) → false
// Fall back to NAT type:
if "None" or "FullCone"           → true
if "Symmetric"                    → false
else (unknown, restricted, etc.)  → true (optimistic)
```

`needs_coordination()` decides whether NAT traversal coordination may be required:

```
if can_receive_direct = Some(false) → true
if nat_type = "Symmetric"           → true
else                                → false
```

## Connection Strategy

`Agent::connect_to_agent(agent_id)` follows this strategy:

```
1. Look up agent_id in discovery cache
   → NotFound if absent

2. Build ReachabilityInfo from DiscoveredAgent

3. If no addresses → Unreachable

4. If network not started → Unreachable

5. If likely_direct():
   for each address:
     try network.connect_addr(addr)
     if OK → Direct(addr), enrich bootstrap cache, return

6. If needs_coordination() OR direct failed:
   for each address:
     try network.connect_addr(addr)  // ant-quic handles NAT traversal
     if OK → Coordinated(addr), enrich bootstrap cache, return

7. → Unreachable
```

The distinction between `Direct` and `Coordinated` outcomes is informational — both indicate a successful QUIC connection. `Coordinated` means NAT traversal assistance was involved.

## Bootstrap Cache Enrichment

Successful connections enrich the bootstrap cache:

```rust
bc.add_from_connection(peer_id, vec![addr], None).await;
```

This improves future peer discovery quality scoring so that well-connected addresses are preferred in subsequent restarts.

## Relay and Coordinator Roles

The `is_relay` and `is_coordinator` fields in announcements are informational only: no hint, join or selection path reads them (David's 20 Oct 2026 #1112 ruling, confirmed 22 Oct 2026, which replaces ADR 0071's community flag tiers). Coordinator and relay assistance comes from the operator tier — peers observed on a direct path from a compiled-in seed listener address — and from `ant-quic`'s deployment-configured bootstrap cache, not from self-assertion.

These roles are set by `ant-quic`'s internal node status and are not controlled by x0x directly.

## NAT Type Population

NAT fields are populated asynchronously:

- **`build_announcement()` (sync)**: Always sets NAT fields to `None` — this function has no access to the async network layer.
- **`HeartbeatContext::announce()` (async)**: Calls `network.node_status()` and populates NAT fields from the current `NodeStatus`. Heartbeats fire every 300 seconds by default.

This means the first self-announcement after a cold start has no NAT information. Subsequent heartbeats carry the correct values once the network layer has had time to detect the NAT environment.

## Connectivity Matrix

| Local \ Remote | No NAT | Full Cone | Address Restricted | Port Restricted | Symmetric |
|----------------|--------|-----------|-------------------|-----------------|-----------|
| No NAT | Direct | Direct | Direct | Direct | Direct |
| Full Cone | Direct | Direct | Direct | Direct | Coordinated |
| Address Restricted | Direct | Direct | Direct | Coordinated | Coordinated |
| Port Restricted | Direct | Direct | Coordinated | Coordinated | Coordinated |
| Symmetric | Direct | Coordinated | Coordinated | Coordinated | Coordinated* |

*Symmetric-to-Symmetric may require relay in extreme cases. The `ant-quic` layer handles this at the QUIC frame level.
