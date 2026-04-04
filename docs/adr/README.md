# Architecture Decision Records

This directory contains architecture decision records for x0x.

## Accepted

- [ADR 0002: Application-Level Keepalive](./0002-application-level-keepalive-for-direct-connections.md) — 15s SWIM Ping prevents QUIC idle timeout
- [ADR 0004: QUIC Stream and Channel Limits](./0004-quic-stream-and-channel-limits.md) — 1024 data channels, 10K uni streams
- [ADR 0005: mDNS Local Network Discovery](./0005-mdns-local-network-discovery.md) — zero-config LAN agent discovery

## Accepted (Partial Implementation)

- [ADR 0001: Bootstrap Peers Are Seed Hints Only](./0001-bootstrap-peers-are-seed-hints-only.md) — Phase 1 partially complete

## Superseded

- [ADR 0003: Auto-Connect to Discovered Agents](./0003-auto-connect-to-discovered-agents.md) — problem solved by HyParView membership overlay instead
