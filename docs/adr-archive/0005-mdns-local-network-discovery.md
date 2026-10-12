# ADR-0005: mDNS Local Network Discovery

## Status
Superseded (2026-04-09)

## Context
x0x agents on the same LAN needed zero-config discovery without depending on remote bootstrap nodes. The first implementation embedded an x0x-specific `mdns-sd` runtime and registered `_x0x._udp.local.` services directly inside the application layer.

## Decision
Retire the x0x-specific mDNS runtime and rely on ant-quic's first-party mDNS implementation instead. LAN discovery, self-filtering, address hygiene, auto-connect, and service advertisement now belong to the transport layer, not the x0x application layer.

### Replacement
- ant-quic advertises and browses mDNS services directly
- x0x no longer exposes `AgentBuilder::with_mdns(bool)` or `Agent::mdns_discovery()`
- `Agent::join_network()` focuses on gossip startup, bootstrap cache reuse, and bootstrap dialing while ant-quic handles LAN discovery concurrently

## Consequences

### Benefits
- Zero-config LAN connectivity — no internet required
- Single transport-layer implementation reused across consumers
- x0x no longer needs to duplicate mDNS lifecycle, filtering, or service-shape logic

### Trade-offs
- x0x no longer controls mDNS behavior directly; transport policy lives in ant-quic
- Debugging LAN discovery now uses ant-quic transport status and events rather than x0x-specific service logs

## Implementation
- Remove `src/mdns.rs` and the `mdns-sd` dependency
- Remove x0x-specific mDNS fields and APIs from `src/lib.rs`
- Depend on ant-quic's built-in first-party mDNS discovery
