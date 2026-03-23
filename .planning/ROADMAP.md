# x0x Identity Unification, Trust Model & NAT Traversal

## Problem
Machine identity and transport identity are disconnected — x0x generates its own MachineKeypair while ant-quic generates a separate ML-DSA-65 keypair for TLS. Trust doesn't account for which machine an identity runs on. NAT traversal information isn't surfaced in identity announcements.

## Success Criteria
- machine_id == ant-quic PeerId (single key pair for transport + identity)
- Trust evaluated per (identity, machine) pair with machine pinning
- Identity announcements carry NAT type, relay, and coordination capabilities
- connect_to_agent() tries direct -> coordinated -> relay for 100% connectivity
- Comprehensive documentation: SKILLS.md, identity-architecture.md, nat-traversal-strategy.md
- All tests green, CI green, deployed to bootstrap nodes

---

## Milestone 1: Identity & Trust Foundation

### Phase 1.1: Identity Unification
Pass the machine ML-DSA-65 keypair to ant-quic's NodeConfig so that machine_id == ant-quic PeerId. Remove the redundant transport_peer_id field.

**Files**: `src/network.rs`, `src/lib.rs`

### Phase 1.2: Flexible Trust Model
Extend Contact with MachineRecord and IdentityType. Create src/trust.rs for (identity, machine) pair trust evaluation. Update ContactStore, identity listener, and REST API.

**Files**: `src/contacts.rs`, `src/trust.rs` (new), `src/lib.rs`, `src/bin/x0xd.rs`

### Phase 1.3: Enhanced Announcements
Add NAT type, relay capability, and coordination fields to IdentityAnnouncement and DiscoveredAgent. Query NodeStatus in heartbeat to populate them.

**Files**: `src/lib.rs`, `src/network.rs`

---

## Milestone 2: Connectivity & NAT Integration

### Phase 2.1: Connectivity Module
Create src/connectivity.rs with ReachabilityInfo and connect_to_agent() on Agent. Add status() and connect_addr() to NetworkNode. Enrich bootstrap cache from announcements.

**Files**: `src/connectivity.rs` (new), `src/lib.rs`, `src/network.rs`

### Phase 2.2: E2E Integration Tests
Comprehensive tests for identity alignment, trust evaluation, announcement round-trips, and connectivity paths.

**Files**: `tests/identity_unification_test.rs`, `tests/trust_evaluation_test.rs`, `tests/announcement_test.rs`, `tests/connectivity_test.rs`

---

## Milestone 3: Documentation & Release

### Phase 3.1: Technical Documentation
Create SKILLS.md (comprehensive capabilities), identity-architecture.md (deep dive), nat-traversal-strategy.md (connectivity matrix). Update CLAUDE.md and AGENTS.md.

**Files**: `docs/SKILLS.md`, `docs/identity-architecture.md`, `docs/nat-traversal-strategy.md`, `CLAUDE.md`, `AGENTS.md`

### Phase 3.2: Release & Deploy
Version bump, tag, push, ensure CI green across ant-quic/saorsa-gossip/x0x/communitas. Deploy updated bootstrap binaries.
