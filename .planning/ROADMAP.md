# SOTA Presence System Roadmap

## Overview
Integrate `saorsa-gossip-presence` (v0.5.10, already in Cargo.toml but unused) into x0x to replace the hand-rolled presence system. Closes the integration gap: Bulk stream messages are silently dropped at `runtime.rs:147`, 15-min offline blind spot, no FOAF, no presence events, no privacy. Production-ready SOTA presence that surpasses libp2p and matches/exceeds Tailscale for NAT-aware peer discovery.

## Success Criteria
- All 8 stubbed tests in `tests/presence_foaf_integration.rs` passing (un-ignored)
- FOAF random-walk discovery working with trust-scoped privacy
- Adaptive failure detection (Phi-Accrual lite) replacing fixed 900s TTL
- Bootstrap cache enriched from presence beacons
- Presence events (AgentOnline/AgentOffline) via broadcast channel
- REST API + CLI for all presence operations
- Zero warnings, zero unwrap in production, full doc coverage
- VPS E2E validated across 6 global bootstrap nodes

## Technical Decisions
- Error Handling: `thiserror` (existing `NetworkError` in `src/error.rs`)
- Async Model: `tokio` (all gossip tasks use `tokio::spawn`)
- Testing: Unit + Integration + Property-based (proptest) + VPS E2E
- Wire Format: `postcard` on `GossipStreamType::Bulk` (saorsa-gossip-presence native)
- Signing: ML-DSA-65 via `MlDsaKeyPair` (existing pattern in `pubsub.rs:206`)

---

## Milestone 1: SOTA Presence Integration

### Phase 1.1: Foundation Wiring
- **Focus**: Route `GossipStreamType::Bulk` to `PresenceManager`, create `src/presence.rs` wrapper, wire into Agent lifecycle
- **Deliverables**:
  - `src/presence.rs` (NEW) — PresenceConfig, PresenceEvent, lifecycle mgmt, broadcast peer sync, GroupContext factory
  - `src/gossip/runtime.rs` — Bulk dispatch at line 147, PresenceManager field + accessor + shutdown
  - `src/lib.rs` — Agent struct fields, AgentBuilder wiring, join_network() lifecycle
  - `src/error.rs` — PresenceError variant
  - `Cargo.toml` — postcard dev-dep
- **Dependencies**: saorsa-gossip-presence v0.5.10, saorsa-gossip-groups (both already in Cargo.toml)
- **Key Files**:
  - `src/gossip/runtime.rs:147-149` — Bulk handler insertion point
  - `src/lib.rs:~2912` — PresenceManager creation after gossip runtime
  - `src/gossip/pubsub.rs:206` — MlDsaKeyPair::generate() reuse pattern
- **Estimated Tasks**: 6-8

### Phase 1.2: Public API — FOAF Discovery & Events
- **Focus**: Three APIs from stubbed tests + event emission loop
- **Deliverables**:
  - `Agent::discover_agents_foaf(ttl)` → `Vec<DiscoveredAgent>`
  - `Agent::discover_agent_by_id(agent_id, ttl)` → `Option<DiscoveredAgent>`
  - `Agent::subscribe_presence()` → `Receiver<PresenceEvent>`
  - Event emission loop (10s, diff-based online/offline)
  - PeerId→AgentId mapping via identity_discovery_cache
- **Dependencies**: Phase 1.1
- **Key Files**:
  - `src/lib.rs` — Agent impl block for new methods
  - `src/presence.rs` — event emission, FOAF wrappers, PeerId mapping
  - Reuse: `shard_topic_for_agent()`, `identity_discovery_cache`, `presence.initiate_foaf_query()`
- **Estimated Tasks**: 5-7

### Phase 1.3: REST/CLI + Trust-Scoped Privacy
- **Focus**: REST endpoints, CLI commands, trust-filtered beacons, network vs social presence split
- **Deliverables**:
  - 5 REST endpoints: `/presence/online`, `/presence/foaf`, `/presence/find/:id`, `/presence/status/:id`, `/presence/events`
  - CLI: `x0x presence online|foaf|find|status`
  - Trust-filtered beacon processing (reuse `TrustEvaluator` from `src/trust.rs`)
  - Network vs Social presence split (trust-gated)
  - Selective broadcasting: Trusted/Known proactive, Unknown FOAF-only
- **Dependencies**: Phase 1.2
- **Key Files**:
  - `src/api/mod.rs` — endpoint registry
  - `src/trust.rs` — TrustEvaluator reuse
  - `src/contacts.rs` — ContactStore shared Arc
  - `src/cli/` — presence subcommands
- **Estimated Tasks**: 6-8

### Phase 1.4: Cache Enrichment & Adaptive Detection
- **Focus**: Bootstrap cache feedback loop, Phi-Accrual lite, quality-weighted FOAF routing
- **Deliverables**:
  - Beacon → `bootstrap_cache.add_from_connection()` enrichment
  - Per-peer beacon inter-arrival tracking (window of 10)
  - Adaptive timeout: mean + 3*stddev, floor 180s, ceiling 600s
  - Quality-weighted FOAF peer selection from cache scores
  - Legacy coexistence (both heartbeat systems run)
- **Dependencies**: Phase 1.3
- **Key Files**:
  - `src/presence.rs` — phi-accrual module, cache enrichment
  - `bootstrap_cache.add_from_connection()` — existing method
  - `network.node_status()` — NAT/relay/coordinator flags
- **Estimated Tasks**: 5-6

### Phase 1.5: Comprehensive Tests
- **Focus**: All stubbed tests, new unit/integration/property tests
- **Deliverables**:
  - 8 stubbed tests implemented in `tests/presence_foaf_integration.rs`
  - ~8 unit tests in `src/presence.rs`
  - ~7 integration tests in `tests/presence_integration.rs` (NEW)
  - ~2 property tests (proptest)
  - Full doc coverage, zero warnings
- **Dependencies**: Phase 1.4
- **Estimated Tasks**: 4-6

---

## Milestone 2: VPS E2E & Legacy Deprecation

### Phase 2.1: VPS E2E Validation
- **Focus**: Deploy and verify on live 6-node global network
- **Deliverables**:
  - Cross-region beacon propagation (all 6 nodes)
  - FOAF across NAT partitions
  - Trust-scoped visibility on live network
  - Performance: beacon latency, FOAF query time
- **Dependencies**: Milestone 1, VPS nodes running v0.14.0+
- **Estimated Tasks**: 3-4

### Phase 2.2: Legacy Topic Deprecation
- **Focus**: Remove `x0x.identity.announce.v1` broadcast, presence-only discovery
- **Deliverables**:
  - Remove legacy broadcast publishing
  - Keep shard topics for backward compat
  - Version bump to v0.15.0
  - Updated docs
- **Dependencies**: Phase 2.1
- **Estimated Tasks**: 3-4

---

## Risks & Mitigations
- **PeerId type mismatch**: ant-quic vs gossip newtypes. Mitigation: `PeerId::new(peer.0)` at `runtime.rs:190`
- **Bulk stream dropped**: `runtime.rs:147` silently ignores. Mitigation: Phase 1.1 explicitly routes
- **postcard not in deps**: Mitigation: internal deserialization, add as dev-dep only
- **Legacy compatibility**: Mitigation: coexistence until v0.15.0
- **MlDsaKeyPair construction**: Mitigation: `generate()` pattern in `pubsub.rs:206`

## Out of Scope
- Full MLS encryption of presence beacons (deterministic exporter for now)
- Bloom filter / IBLT summaries (saorsa-gossip-presence says "future")
- SWIM-style detection (Phi-Accrual lite sufficient)
- 1M+ agent scale (design good to ~10K)
