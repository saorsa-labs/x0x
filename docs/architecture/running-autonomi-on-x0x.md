# Running the Autonomi Network on x0x

**Author:** Saorsa Labs Architecture Team
**Date:** March 2026
**Status:** Proposal / Technical Assessment

---

## Executive Summary

x0x is a production gossip network that's live today — 6 bootstrap nodes across 4 continents, post-quantum encrypted, with tested CLI tooling and REST/WebSocket APIs. The question is whether Autonomi's storage network (saorsa-node, saorsa-core) can run on top of it.

**The answer is yes.** Not by replacing the DHT, but by adding x0x as a gossip layer underneath it. This gives the storage network something it currently lacks: a fast, tested coordination plane for peer discovery, network-wide events, and real-time presence — while keeping Kademlia for what it's good at (structured data routing).

There is no transport barrier. We verified that `saorsa-transport` and `ant-quic` are the **same codebase** — 211 source files, identical file structure, same NAT traversal frames, same bootstrap cache, same MASQUE relay, same PQC. The only differences are the crate name and a handful of function renames. x0x already runs on the same transport that saorsa-core uses. saorsa-core can adopt `ant-quic` directly — it's the actively developed version at 172K lines, tested and deployed.

---

## What We Have Today

### x0x (Live, Tested, on ant-quic)

| Capability | Status | Detail |
|-----------|--------|--------|
| Global bootstrap network | **Live** | 6 nodes: NYC, SFO, Helsinki, Nuremberg, Singapore, Tokyo |
| Post-quantum transport | **Live** | ML-KEM-768 key exchange, ML-DSA-65 signatures (ant-quic) |
| NAT traversal | **Live** | Native QUIC extension frames, no STUN/ICE/TURN |
| MASQUE relay | **Live** | CONNECT-UDP Bind fallback for symmetric NAT |
| Bootstrap cache | **Live** | Epsilon-greedy peer selection with quality scores |
| Gossip pub/sub | **Live** | HyParView membership + PlumTree epidemic broadcast |
| Direct messaging | **Live** | Point-to-point over QUIC |
| Identity system | **Live** | Three-layer: Machine (hardware) → Agent (portable) → User (opt-in) |
| Trust/contacts | **Live** | 4-level whitelist: Blocked → Unknown → Known → Trusted |
| MLS group encryption | **Live** | ChaCha20-Poly1305, epoch-based key rotation |
| CRDT collaboration | **Live** | OR-Set task lists with conflict-free merge |
| CLI tooling | **Live** | `x0x` binary with 55 commands, REST + WebSocket APIs |
| Self-update | **Live** | Signed manifests propagated via gossip |
| Developer surfaces | **Live** | Local daemon (`x0xd`), CLI (`x0x`), REST + WebSocket APIs, and Rust crate |
| LinkTransport trait | **Live** | Overlay abstraction — saorsa-core's interface already exists in ant-quic |

551 tests passing. Zero clippy warnings. Deployed and serving real traffic.

### saorsa-core / saorsa-node (In Development)

| Capability | Status | Detail |
|-----------|--------|--------|
| Kademlia DHT | Built | K=8 replication, geographic routing, close-group selection |
| EigenTrust++ | Built | Decentralised reputation scoring |
| Adaptive routing | Built | Thompson Sampling, Q-Learning, hyperbolic geometry |
| Placement system | Built | Byzantine-tolerant shard selection with geographic diversity |
| Chunk storage | Built | Immutable, SHA-256 addressed, ≤4MB, LMDB backend |
| Payment verification | Built | EVM (Arbitrum One) contract verification |
| Transport | Built | saorsa-transport (renamed ant-quic, same codebase) |

### The Transport Reality

We performed a source-level comparison of `ant-quic v0.22` and `saorsa-transport v0.23`:

| Metric | ant-quic | saorsa-transport | Verdict |
|--------|----------|-----------------|---------|
| Source files | 211 | 211 | **Identical** |
| File paths | Identical | Identical (except binary name) | **Same structure** |
| lib.rs diff | — | 21 lines | **Comments and function renames only** |
| Total lines | 172,269 | 131,716 | **ant-quic is ahead** |
| NAT frames | 7 types | 7 types | **Identical** |
| Bootstrap cache | Epsilon-greedy, persistent, encrypted | Same | **Identical** |
| MASQUE relay | CONNECT-UDP Bind | Same | **Identical** |
| LinkTransport trait | 3,500 lines | Same | **Both have it** |
| PQC | ML-KEM-768 + ML-DSA-65 | Same | **Identical** |
| BLE transport | Yes (feature flag) | Yes (feature flag) | **Identical** |
| Constrained engine | Yes | Yes | **Identical** |
| Connection router | Yes | Yes | **Identical** |

The only API difference: `derive_peer_id_from_public_key()` was renamed to `fingerprint_public_key()`.

**saorsa-transport is a point-in-time snapshot of ant-quic with the crate name changed.** ant-quic is the actively developed version and the one x0x is tested against.

### The Gap

saorsa-node has structured routing (DHT) but no gossip layer. This means:

- **Slow bootstrap**: New nodes must do iterative Kademlia walks to build routing tables. Takes minutes.
- **No real-time presence**: Nodes don't know who's online until they query them individually.
- **No network-wide events**: Emergency messages (key compromise, protocol upgrade, network split) have no fast propagation path.
- **No coordination plane**: Consensus pre-rounds, view changes, and membership events require custom protocols on every occasion.

x0x fills every one of these gaps. It's already built and tested.

---

## The Proposed Architecture

```
┌──────────────────────────────────────────────────┐
│              saorsa-node                          │
│   (chunk storage, payment, application logic)    │
├──────────────────────────────────────────────────┤
│              saorsa-core                          │
│   (Kademlia DHT, EigenTrust, placement, ML)      │
│   DATA PLANE: "find chunk abc123 → route to       │
│   closest node → replicate K=8"                   │
├──────────────────────────────────────────────────┤
│              x0x                                  │
│   (gossip, presence, identity, trust, groups)     │
│   CONTROL PLANE: "node joined → everyone knows    │
│   in seconds, not minutes"                        │
├──────────────────────────────────────────────────┤
│              ant-quic                             │
│   (QUIC, ML-KEM-768, ML-DSA-65, NAT traversal,  │
│    MASQUE relay, bootstrap cache, LinkTransport)  │
└──────────────────────────────────────────────────┘
```

**One transport. Two protocol layers. Each doing what it's best at.**

ant-quic already provides the `LinkTransport` trait that saorsa-core needs. It already provides the `GossipTransport`-compatible `Node` that x0x uses. Both layers can share a single `ant-quic::Node` instance — one set of connections, one NAT traversal, one identity.

---

## What x0x Provides to the Storage Network

### 1. Instant Bootstrap (seconds, not minutes)

**Today (DHT only):**
```
Connect to bootstrap → Kademlia FIND_NODE → iterative walks →
slowly build routing table → 2-5 minutes before fully operational
```

**With x0x:**
```
Connect to x0x bootstrap (instant, 6 live nodes) →
gossip announces you to the network (seconds) →
receive gossip about active nodes and their capabilities →
build DHT routing table from gossip data (seconds) →
fully operational in under 10 seconds
```

The 6 x0x bootstrap nodes are already live and geographically distributed. New storage nodes get a peer view immediately through HyParView, then build their Kademlia tables from that view.

### 2. Real-Time Network Awareness

x0x gossip gives every node a live picture of the network:

| Event | Propagation | Mechanism |
|-------|-------------|-----------|
| Node joins | Seconds | Identity announcement via gossip pub/sub |
| Node departs | Sub-second | SWIM failure detection in HyParView |
| Emergency (key compromise) | Seconds | Signed gossip message, trust-filtered |
| Protocol upgrade available | Seconds | Signed release manifest via gossip |
| Network partition detected | Seconds | HyParView view divergence |

Without gossip, each of these requires either polling (slow) or custom protocol work (expensive).

### 3. Shared Transport, Single Connection Set

Since ant-quic is the same codebase as saorsa-transport, there is no transport barrier:

- **One set of QUIC connections** carries both gossip and DHT traffic
- **One NAT traversal** serves both layers (same frames, same mechanism)
- **One bootstrap cache** with shared epsilon-greedy peer selection
- **One MASQUE relay** for symmetric NAT fallback
- **One identity** (ML-DSA-65 keypair) authenticates everywhere
- **One `LinkTransport`** implementation serves both saorsa-core and x0x

No duplicate connections. No duplicate handshakes. No duplicate NAT hole-punching.

### 4. Trust Convergence

| Layer | Trust System | What It's Good At |
|-------|-------------|-------------------|
| x0x | ContactStore (explicit, 4 levels) | Human/agent intent — "I trust Sarah" |
| saorsa-core | EigenTrust++ (computed, continuous) | Observed behaviour — "this node serves correct data 99.7% of the time" |

These are complementary:

- EigenTrust scores feed into x0x trust decisions → gossip from unreliable nodes gets deprioritized
- x0x trust signals (blocked contacts, revocations) inform EigenTrust initial weights → new nodes from trusted sources start with higher reputation
- MLS groups enable private coordination channels for close-group consensus

### 5. Coordination for Free

x0x's existing features map directly to storage network needs:

| x0x Feature | Storage Network Use |
|------------|---------------------|
| Gossip pub/sub | Membership events, view changes, emergency alerts |
| Direct messaging | DHT RPC (get/put queries between specific nodes) |
| MLS groups | Encrypted close-group consensus rounds |
| CRDT task lists | Coordinated repair/audit tasks across replica groups |
| Presence | Real-time view of which nodes are online |
| Identity announcements | NAT type, reachability, capacity advertisement |

None of this needs to be built. It's tested and deployed.

---

## Transport: No Migration Needed

### The Situation

```
x0x         → ant-quic v0.22.3    (actively developed, 172K lines, tested)
saorsa-core → saorsa-transport v0.23  (renamed ant-quic, 132K lines, snapshot)
```

These are the same codebase. ant-quic is ahead.

### The Path

**saorsa-core should adopt ant-quic directly.** It already has everything saorsa-core needs:

- `LinkTransport` trait (3,500 lines, with `P2pLinkTransport` implementation)
- `BootstrapCache` with epsilon-greedy selection, quality scoring, encrypted persistence
- NAT traversal: 7 QUIC extension frame types (ADD_ADDRESS, PUNCH_ME_NOW, OBSERVED_ADDRESS, REMOVE_ADDRESS)
- MASQUE CONNECT-UDP Bind relay (100% connectivity guarantee for symmetric NAT)
- Connection router (auto-selects QUIC vs Constrained engine based on bandwidth/MTU)
- BLE transport (feature flag)
- `Node` zero-config API (same API surface as saorsa-transport's)

The one rename to handle: `derive_peer_id_from_public_key()` → was renamed to `fingerprint_public_key()` in saorsa-transport. saorsa-core would need to use the ant-quic name, or we add a thin alias.

**Estimated effort:** A Cargo.toml dependency change + a single function rename. The APIs are identical.

---

## What This Does NOT Change

x0x does not replace the DHT. Gossip and DHT solve different problems:

| Operation | Right Tool | Why |
|-----------|-----------|-----|
| "Get chunk `abc123`" | **Kademlia DHT** | Structured routing: O(log n) hops to the responsible node |
| "Store this chunk at K=8 replicas" | **Kademlia DHT** | Close-group selection based on XOR distance |
| "Node X just joined" | **x0x gossip** | Everyone needs to know, epidemic broadcast is ideal |
| "Is node Y still alive?" | **x0x SWIM** | Failure detection in sub-seconds, not timeout-based |
| "Emergency: revoke key Z" | **x0x gossip** | Network-wide, signed, trust-filtered, immediate |
| "Consensus on chunk payment" | **x0x MLS group** | Encrypted channel for close-group members |

DHT for data. Gossip for coordination. Both over one transport.

---

## Integration Path and Timeline

We develop with AI-assisted coding (Claude Code), which compresses implementation timelines significantly. The estimates below reflect this — most phases are bounded by testing and validation, not writing code.

### Phase 1: Unify on ant-quic — 1 day

| Task | Effort | Notes |
|------|--------|-------|
| Change saorsa-core Cargo.toml dependency | Minutes | `saorsa-transport` → `ant-quic` |
| Rename `fingerprint_public_key` → `derive_peer_id_from_public_key` | Minutes | One function, same signature |
| Run saorsa-core test suite | Hours | Validation — the code hasn't changed |
| Run saorsa-node test suite | Hours | Transitive dependency, should just work |

- x0x continues using ant-quic as-is (no changes)
- **Result:** Everyone on the same transport. ant-quic is the canonical crate.
- **Confidence:** Very high. Same codebase, verified identical.

### Phase 2: Identity Alignment — 1 day

| Task | Effort | Notes |
|------|--------|-------|
| Verify PeerId derivation matches MachineId | Hours | Both are SHA-256(ML-DSA-65 pubkey) — write a cross-crate test |
| Shared keypair loading from `~/.x0x/machine.key` | Hours | saorsa-core reads x0x's key format (bincode) |
| Integration test: one key, two systems, same ID | Hours | The gate — doesn't ship until this passes |

- **Result:** A node is the same peer in both the gossip and DHT layers.
- **Confidence:** High. Same algorithm, same derivation — but needs verification test.

### Phase 3: Gossip-Assisted Bootstrap — 2-3 days

| Task | Effort | Notes |
|------|--------|-------|
| Add `x0x` dependency to saorsa-node | Minutes | Cargo.toml |
| Start x0x Agent alongside DHT on node startup | Half day | ~50 lines in saorsa-node's main |
| Gossip → DHT peer seeding (feed HyParView peers into Kademlia) | 1 day | Bridge code: subscribe to x0x presence, insert into DHT routing table |
| Test: new node bootstraps via gossip, serves chunks within 10s | 1 day | Integration test against live bootstrap nodes |

- x0x's 6 live bootstrap nodes serve both layers
- **Result:** Cold-start problem eliminated.
- **Confidence:** High. The gossip layer is tested; the bridge is new code but small.

### Phase 4: Control Plane Integration — 3-4 days

| Task | Effort | Notes |
|------|--------|-------|
| Define gossip topics for network events (`x0x/nodes/join`, `x0x/nodes/leave`) | Half day | Topic schema + message types |
| Membership event propagation via gossip | 1 day | Publish on DHT join/leave, subscribe on all nodes |
| Close-group coordination via MLS groups | 1-2 days | Wire up existing MLS to close-group decisions |
| EigenTrust ↔ ContactStore bridge | 1 day | Bidirectional: scores → trust levels, revocations → initial weights |
| Integration tests: membership events propagate, trust converges | 1 day | Multi-node testnet |

- **Result:** The network has a real-time coordination plane.
- **Confidence:** Medium-high. Individual pieces exist and are tested; the integration is new.

### Phase 5: Unified Node — 2-3 days

| Task | Effort | Notes |
|------|--------|-------|
| Single binary build (saorsa-node embeds x0x) | Half day | Already depends on x0x from Phase 3 |
| Unified CLI: `saorsa-node` commands + `x0x` subcommands | 1 day | Clap subcommand delegation |
| Shared port management (one port range for QUIC) | Half day | Both layers share ant-quic Node instance |
| End-to-end test: chunk store + retrieve through unified node | 1 day | The final gate |
| Documentation and README updates | Half day | Reflect unified architecture |

- **Result:** The complete Autonomi node with gossip coordination.
- **Confidence:** High. Everything is built by this point; this phase is assembly.

### Phase 6: Testnet Validation — 3-5 days

| Task | Effort | Notes |
|------|--------|-------|
| Deploy unified nodes to existing 6 VPS bootstrap nodes | Half day | Same infrastructure x0x already runs on |
| 9-node testnet: bootstrap, store, retrieve, gossip | 1-2 days | Using existing saorsa-testnet infrastructure |
| Performance benchmarks: bootstrap time, chunk latency, gossip propagation | 1 day | Measure what we claimed |
| Failure testing: kill nodes, network partitions, NAT edge cases | 1-2 days | Chaos testing on testnet |
| Fix issues found | Included | Budgeted into each testing phase |

- **Result:** Validated production-ready system.

---

### Total Timeline

| Phase | Duration | Cumulative |
|-------|----------|------------|
| Phase 1: Unify on ant-quic | 1 day | **Day 1** |
| Phase 2: Identity alignment | 1 day | **Day 2** |
| Phase 3: Gossip-assisted bootstrap | 2-3 days | **Day 4-5** |
| Phase 4: Control plane integration | 3-4 days | **Day 8-9** |
| Phase 5: Unified node | 2-3 days | **Day 11-12** |
| Phase 6: Testnet validation | 3-5 days | **Day 14-17** |

**Total: 2-3 weeks to a tested, unified Autonomi node running on x0x.**

This is aggressive but realistic because:
- x0x is already built and tested (551 tests, live infrastructure)
- ant-quic and saorsa-transport are the same codebase (no transport work)
- saorsa-node is thin (~1000 LOC) and delegates to saorsa-core (small integration surface)
- AI-assisted coding handles the boilerplate; human time goes to architecture decisions and testing
- Existing testnet infrastructure (6 VPS nodes) can be reused immediately

---

## Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Transport switch causes regressions in saorsa-core | **Very Low** | Same codebase, one function rename. saorsa-core's test suite validates. |
| Gossip adds overhead to storage nodes | **Low** | HyParView maintains ~30 active peers; PlumTree is lazy-push. Minimal bandwidth. |
| Two routing systems create complexity | **Medium** | Clear boundary: gossip for coordination, DHT for data. No overlap in responsibility. |
| Identity alignment has edge cases | **Low** | Both use SHA-256(ML-DSA-65 pubkey) — same algorithm, same derivation, same output. |
| Bootstrap cache conflicts between layers | **None** | ant-quic's cache is transport-level. Both layers benefit from the same cache. |
| NAT traversal works differently | **None** | Same code. Verified identical: same frames, same coordinator logic, same MASQUE relay. |

---

## Why Now

1. **x0x is production-tested.** 6 bootstrap nodes live, 551 tests, daemon + CLI shipped, and the local API is live. It's not a proposal — it's deployed infrastructure.

2. **The transport is already unified.** We verified: ant-quic and saorsa-transport are the same codebase. There is no migration. saorsa-core can switch its Cargo.toml dependency and everything works.

3. **saorsa-node is still early.** The node is thin (~1000 LOC) and delegates everything to saorsa-core. Adding x0x now means the architecture grows with it, rather than retrofitting later.

4. **The bootstrap problem is real.** Every P2P network struggles with cold-start. x0x solves it today with 6 live nodes across 4 continents. Waiting means building a worse version of the same thing from scratch.

5. **ant-quic already has LinkTransport.** The trait interface saorsa-core depends on (3,500 lines) exists in ant-quic today. The integration path is clear.

---

## Summary

x0x is the gossip layer the Autonomi storage network needs. It's built, tested, and deployed on the same transport (ant-quic) that saorsa-core uses under a different name. The integration is:

- **No transport migration** — same codebase, rename the dependency
- **Additive** — the DHT keeps routing data, x0x adds coordination
- **Already tested** — 551 tests, 6 live bootstrap nodes, production CLI
- **Architecturally clean** — one transport, two protocol layers, one identity

The hardest part — building and testing a gossip network with post-quantum cryptography, NAT traversal, MASQUE relay, identity, trust, group encryption, and CLI tooling — is already done.
