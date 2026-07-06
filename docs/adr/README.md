# Architecture Decision Records

This directory contains architecture decision records for x0x.

## Accepted

- [ADR 0002: Application-Level Keepalive](./0002-application-level-keepalive-for-direct-connections.md) — 15s SWIM Ping prevents QUIC idle timeout
- [ADR 0003: Auto-Connect to Discovered Agents](./0003-auto-connect-to-discovered-agents.md) — identity listener auto-connects via `connect_addr()`
- [ADR 0004: QUIC Stream and Channel Limits](./0004-quic-stream-and-channel-limits.md) — 1024 data channels, 10K uni streams
- [ADR 0005: mDNS Local Network Discovery](./0005-mdns-local-network-discovery.md) — superseded; LAN discovery now lives in ant-quic
- [ADR 0006: No Global DHT Dependency for User and Group Data](./0006-no-global-dht-for-user-and-group-data.md) — partition-tolerant user/group data follows reachable peers, not a global overlay
- [ADR 0007: Three-Layer Identity Model](./0007-three-layer-identity-model.md) — machine transport identity, portable agent identity, and optional consent-gated user identity
- [ADR 0008: Trust Evaluation System](./0008-trust-evaluation-system.md) — unified `(AgentId, MachineId)` pair evaluation with orthogonal trust levels and identity types
- [ADR 0009: Receive-Pump Overload Policy](./0009-recv-pump-overload-policy.md) — observable PubSub load-shedding plus receive-pump diagnostics
- [ADR 0010: GSS Before MLS TreeKEM for v1 Secure Groups](./0010-gss-before-mls-treekem-for-v1-secure-groups.md) — `MlsEncrypted` named groups use Group Shared Secret rekey-on-ban in v1, not full MLS TreeKEM. **Superseded (forward path) by ADR 0012** now that saorsa-mls 0.3.6 ships real TreeKEM; still describes the legacy plane grandfathered groups run on
- [ADR 0011: Bootstrap Dual-Listen UDP/443](./0011-bootstrap-dual-listen-udp-443.md) — second root x0xd on :443 per bootstrap host for WARP/full-tunnel-VPN reachability
- [ADR 0013: Priority-Aware PubSub Receive-Pump Shedding](./0013-priority-aware-pubsub-shed.md) — refines ADR 0009 to shed low-priority PubSub control frames first (renumbered from 0010 to resolve a collision)
- [ADR 0012: Real TreeKEM as the Default Secure Group Plane](./0012-treekem-default-secure-groups.md) — private `MlsEncrypted` (`Hidden`) groups run real `saorsa_mls::TreeKemGroup` (FS + PCS) by default; **multi-member convergence implemented and shipped in x0x 0.21.0**; legacy GSS groups grandfathered with owner opt-in upgrade; supersedes ADR 0010's forward path
- [ADR 0014: TreeKEM Self-Leave Is a Roster Removal; PCS Comes From an Owner-Driven Rekey](./0014-treekem-self-leave-owner-driven-rekey.md) — a leaver cannot self-rekey (RFC-9420 / saorsa-mls forbids self-removal), so self-leave is a signed roster removal and the **owner** issues the responsive rekey commit that delivers PCS; owner-only single-writer with lazy catch-up; amends ADR 0012
- [ADR 0015: No App-Layer At-Rest Encryption or Secondary Passwords](./0015-no-app-layer-at-rest-encryption.md) — local state is protected by OS user isolation + full-disk encryption, never a secondary password; best-effort OS-keystore wrapping of identity keys sanctioned as a follow-up

## Accepted (Phase 1 Functionally Complete)

- [ADR 0001: Bootstrap Peers Are Seed Hints Only](./0001-bootstrap-peers-are-seed-hints-only.md) — functional Phase 1 complete, nomenclature rename deferred

## Proposed

- [ADR 0020: Tailnet Phase 1 — per-peer byte-streams + local port-forwarding](./0020-tailnet-phase-1-byte-streams-and-forwarding.md) — PeerStream over `Node::open_bi`/`accept_bi` with the identity gate inside open/accept; `src/forward/` local port-forwarder gated by the connect ACL (#131/ADR-0019) + key lifecycle (#130); loopback-only Phase 1
