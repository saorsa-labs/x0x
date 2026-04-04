# ADR-0005: mDNS Local Network Discovery

## Status
Accepted (2026-04-04)

## Context
x0x agents on the same LAN had no way to discover each other without internet access to reach bootstrap nodes. Users running multiple agents on a home or office network had to rely on remote VPS bootstrap peers for initial connectivity, adding latency and an internet dependency.

## Decision
Register each agent as a `_x0x._udp.local.` DNS-SD service using the `mdns-sd` crate. mDNS discovery runs as the first phase in `join_network()`, before cached peers and bootstrap nodes.

### Service Registration
- Service type: `_x0x._udp.local.`
- Instance name: `x0x-{16-hex-agent-id}-{16-hex-machine-id}` (37 chars, within 63-byte DNS label limit)
- TXT records: `agent_id` (64-char hex), `machine_id` (64-char hex), `words` (4-word identity), `version`
- `enable_addr_auto()` for dynamic address updates

### Discovery Phase
- Runs before Phase 0 (cached coordinators) in `join_network()`
- Polls for up to 3 seconds with 200ms intervals and early exit on first discovery
- Filters loopback (127.x), link-local IPv6 (fe80::), and APIPA (169.254.x.x) addresses
- Deduplicates addresses via HashSet

### Lifecycle
- `AgentBuilder::with_mdns(bool)` — enabled by default
- Idempotent `start_browse()` via atomic CAS with failure rollback
- `Drop` implementation ensures daemon thread cleanup
- Graceful shutdown unregisters service and stops browse task

## Consequences

### Benefits
- Zero-config LAN connectivity — no internet required
- Instant discovery (~2s) vs bootstrap (~30s with retries)
- Works alongside bootstrap — additive, not exclusive

### Trade-offs
- Depends on mDNS multicast working on the LAN (some routers filter multicast)
- Additional dependency: `mdns-sd` crate (~50KB)
- 3-second discovery window adds to startup time even when no LAN peers exist

## Implementation
- `src/mdns.rs` — `MdnsDiscovery` struct
- Integration in `src/lib.rs` — `Agent` struct field, `AgentBuilder`, `join_network()`, `shutdown()`
