# Architecture Decision Records

This directory contains architecture decision records for x0x.

## Accepted

- [ADR 0002: Application-Level Keepalive](./0002-application-level-keepalive-for-direct-connections.md) — 15s SWIM Ping prevents QUIC idle timeout
- [ADR 0003: Auto-Connect to Discovered Agents](./0003-auto-connect-to-discovered-agents.md) — identity listener auto-connects via `connect_addr()`
- [ADR 0004: QUIC Stream and Channel Limits](./0004-quic-stream-and-channel-limits.md) — 1024 data channels, 10K uni streams
- [ADR 0005: mDNS Local Network Discovery](./0005-mdns-local-network-discovery.md) — superseded; LAN discovery now lives in ant-quic
- [ADR 0006: No Global DHT Dependency for User and Group Data](./0006-no-global-dht-for-user-and-group-data.md) — partition-tolerant user/group data follows reachable peers, not a global overlay

## Accepted (Phase 1 Functionally Complete)

- [ADR 0001: Bootstrap Peers Are Seed Hints Only](./0001-bootstrap-peers-are-seed-hints-only.md) — functional Phase 1 complete, nomenclature rename deferred
