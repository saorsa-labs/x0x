# Phase 1.3: Gossip Overlay Integration

**Status**: Pending
**Estimated Tasks**: 12
**Dependencies**: Phase 1.2 (Network Transport Integration) complete

## Overview

Integrate saorsa-gossip for overlay networking on top of the ant-quic transport layer. This phase establishes the gossip runtime, membership management, pub/sub messaging, presence beacons, peer discovery, and anti-entropy reconciliation.

## Tasks

### Task 1: Add saorsa-gossip Dependencies

**Goal**: Add all required saorsa-gossip crates to Cargo.toml.

**Files**:
- Cargo.toml (modify)

**Implementation**:
- Add saorsa-gossip-runtime dependency (path = "../saorsa-gossip/crates/runtime")
- Add saorsa-gossip-types dependency (path = "../saorsa-gossip/crates/types")
- Add saorsa-gossip-transport dependency (path = "../saorsa-gossip/crates/transport")
- Add saorsa-gossip-membership dependency (path = "../saorsa-gossip/crates/membership")
- Add saorsa-gossip-pubsub dependency (path = "../saorsa-gossip/crates/pubsub")
- Add saorsa-gossip-presence dependency (path = "../saorsa-gossip/crates/presence")
- Add saorsa-gossip-coordinator dependency (path = "../saorsa-gossip/crates/coordinator")
- Add saorsa-gossip-rendezvous dependency (path = "../saorsa-gossip/crates/rendezvous")
- Add blake3 for message deduplication (version = "1.5")
- Run cargo check to verify all dependencies resolve

**Dependencies**: None

**Tests**:
- cargo check passes
- All saorsa-gossip crates compile successfully

---

### Task 2: Create Gossip Module Structure

**Goal**: Create the gossip module and submodule structure.

**Files**:
- src/gossip.rs (create)
- src/gossip/runtime.rs (create)
- src/gossip/config.rs (create)
- src/lib.rs (modify)

**Implementation**:
- Create src/gossip.rs with module declarations (runtime, config)
- Create src/gossip/runtime.rs with placeholder GossipRuntime struct
- Create src/gossip/config.rs with GossipConfig struct
- Add `pub mod gossip;` to src/lib.rs after network module
- Re-export key types: `pub use gossip::{GossipRuntime, GossipConfig};`

**Dependencies**: Task 1

**Tests**:
- cargo check passes
- Module structure compiles

---

### Task 3: Implement GossipConfig

**Goal**: Define configuration for the gossip overlay with sensible defaults.

**Files**:
- src/gossip/config.rs (modify)

**Implementation**:
- Define GossipConfig struct with fields:
  - `active_view_size: usize` (default 10, range 8-12)
  - `passive_view_size: usize` (default 96, range 64-128)
  - `probe_interval: Duration` (default 1s for SWIM)
  - `suspect_timeout: Duration` (default 3s for SWIM)
  - `presence_beacon_ttl: Duration` (default 15min)
  - `anti_entropy_interval: Duration` (default 30s)
  - `foaf_ttl: u8` (default 3 hops)
  - `foaf_fanout: u8` (default 3 peers)
  - `message_cache_size: usize` (default 10000 for dedup)
  - `message_cache_ttl: Duration` (default 5min)
- Implement Default trait with recommended values from ROADMAP
- Derive Debug, Clone, Serialize, Deserialize
- Add doc comments explaining each parameter

**Dependencies**: Task 2

**Tests**:
- Test default config has expected values
- Test config serializes/deserializes correctly

---

### Task 4: Create Transport Adapter

**Goal**: Implement a saorsa-gossip transport adapter that wraps ant-quic NetworkNode.

**Files**:
- src/gossip/transport.rs (create)
- src/gossip.rs (modify to add transport module)
- tests/gossip_transport.rs (create)

**Implementation**:
- Create QuicTransportAdapter struct wrapping NetworkNode
- Implement saorsa_gossip_transport::Transport trait:
  - `async fn send(&self, peer: PeerId, message: Bytes) -> Result<()>`
  - `async fn broadcast(&self, peers: Vec<PeerId>, message: Bytes) -> Result<()>`
  - `fn local_peer_id(&self) -> PeerId`
  - `fn subscribe_events(&self) -> broadcast::Receiver<TransportEvent>`
- Map ant-quic NetworkEvent to TransportEvent
- Handle connection/disconnection events
- Add error type mapping from ant-quic to saorsa-gossip errors

**Dependencies**: Task 2

**Tests**:
- Test transport adapter forwards messages correctly
- Test event subscription receives connection events
- Test local_peer_id returns correct value

---

### Task 5: Initialize GossipRuntime

**Goal**: Create the GossipRuntime that manages all gossip components.

**Files**:
- src/gossip/runtime.rs (modify)
- tests/gossip_runtime.rs (create)

**Implementation**:
- Define GossipRuntime struct with fields:
  - `config: GossipConfig`
  - `transport: Arc<QuicTransportAdapter>`
  - `runtime_handle: Option<saorsa_gossip_runtime::RuntimeHandle>`
- Implement `async fn new(config: GossipConfig, transport: Arc<QuicTransportAdapter>) -> Result<Self>`
- Implement `async fn start(&mut self) -> Result<()>` to initialize runtime
- Implement `async fn shutdown(&mut self) -> Result<()>` for graceful cleanup
- Add `fn is_running(&self) -> bool` to check runtime state
- Return NetworkError for failures

**Dependencies**: Task 3, Task 4

**Tests**:
- Test runtime creation succeeds
- Test runtime starts without errors
- Test runtime shutdown is graceful
- Test is_running reflects correct state

---

### Task 6: Integrate HyParView Membership

**Goal**: Initialize HyParView membership management with SWIM failure detection.

**Files**:
- src/gossip/membership.rs (create)
- src/gossip.rs (modify to add membership module)
- src/gossip/runtime.rs (modify to include membership)
- tests/gossip_membership.rs (create)

**Implementation**:
- Create MembershipManager struct
- Initialize saorsa_gossip_membership::HyParView with GossipConfig parameters
- Configure SWIM failure detection (probe_interval, suspect_timeout)
- Implement `async fn join(&self, bootstrap_peers: Vec<PeerId>) -> Result<()>`
- Implement `async fn active_view(&self) -> Vec<PeerId>` to get active peers
- Implement `async fn passive_view(&self) -> Vec<PeerId>` to get passive peers
- Add membership events subscription (peer joined, peer left, peer suspected)
- Wire into GossipRuntime

**Dependencies**: Task 5

**Tests**:
- Test membership initialization
- Test joining with bootstrap peers
- Test active_view and passive_view return correct sets
- Test SWIM failure detection triggers peer_suspected event

---

### Task 7: Implement Pub/Sub with Plumtree

**Goal**: Integrate Plumtree epidemic broadcast for topic-based messaging.

**Files**:
- src/gossip/pubsub.rs (create)
- src/gossip.rs (modify to add pubsub module)
- src/gossip/runtime.rs (modify to include pubsub)
- tests/gossip_pubsub.rs (create)

**Implementation**:
- Create PubSubManager struct
- Initialize saorsa_gossip_pubsub::Plumtree
- Implement message deduplication using BLAKE3 message IDs + LRU cache
- Implement `async fn subscribe(&self, topic: &str) -> Result<broadcast::Receiver<Message>>`
- Implement `async fn publish(&self, topic: &str, payload: Bytes) -> Result<()>`
- Implement `async fn unsubscribe(&self, topic: &str) -> Result<()>`
- Add message cache (size, TTL from GossipConfig)
- Wire into GossipRuntime

**Dependencies**: Task 6

**Tests**:
- Test subscribe returns receiver for topic
- Test publish sends message to subscribers
- Test message deduplication (same message only received once)
- Test unsubscribe stops receiving messages

---

### Task 8: Implement Presence Beacons

**Goal**: Add encrypted presence beacons for agent online/offline status.

**Files**:
- src/gossip/presence.rs (create)
- src/gossip.rs (modify to add presence module)
- src/gossip/runtime.rs (modify to include presence)
- tests/gossip_presence.rs (create)

**Implementation**:
- Create PresenceManager struct
- Initialize saorsa_gossip_presence::PresenceService
- Configure beacon TTL from GossipConfig (default 15min)
- Implement `async fn broadcast_presence(&self) -> Result<()>` to send beacon
- Implement `async fn get_online_agents(&self) -> Result<Vec<AgentId>>` to query status
- Implement `async fn subscribe_presence(&self) -> broadcast::Receiver<PresenceEvent>`
- Events: AgentOnline(AgentId), AgentOffline(AgentId)
- Start background task to broadcast beacons at TTL/2 interval
- Wire into GossipRuntime

**Dependencies**: Task 7

**Tests**:
- Test broadcast_presence sends beacon
- Test presence events received (online/offline)
- Test beacon TTL expiration removes agent from online list
- Test background beacon task runs at correct interval

---

### Task 9: Implement FOAF Discovery

**Goal**: Add bounded random-walk queries for finding agents by identity.

**Files**:
- src/gossip/discovery.rs (create)
- src/gossip.rs (modify to add discovery module)
- src/gossip/runtime.rs (modify to include discovery)
- tests/gossip_discovery.rs (create)

**Implementation**:
- Create DiscoveryManager struct
- Configure bounded random-walk with TTL and fanout from GossipConfig
- Implement `async fn find_agent(&self, agent_id: AgentId) -> Result<Option<Vec<SocketAddr>>>`
- Implement `async fn advertise_self(&self) -> Result<()>` to make discoverable
- Privacy: ensure no single node sees full query path
- Track query IDs to prevent loops
- Timeout queries after reasonable duration (30s)
- Wire into GossipRuntime

**Dependencies**: Task 8

**Tests**:
- Test find_agent returns addresses when agent found
- Test find_agent respects TTL limit (max 3 hops)
- Test find_agent respects fanout limit (max 3 peers per hop)
- Test advertise_self makes agent discoverable
- Test query timeout prevents infinite loops

---

### Task 10: Implement Rendezvous Shards

**Goal**: Add content-addressed sharding for global agent findability.

**Files**:
- src/gossip/rendezvous.rs (create)
- src/gossip.rs (modify to add rendezvous module)
- src/gossip/runtime.rs (modify to include rendezvous)
- tests/gossip_rendezvous.rs (create)

**Implementation**:
- Create RendezvousManager struct
- Initialize saorsa_gossip_rendezvous with 65,536 shards
- Implement `fn shard_id(agent_id: &AgentId) -> u16` using BLAKE3 hash
- Implement `async fn register(&self, agent_id: AgentId, addrs: Vec<SocketAddr>) -> Result<()>`
- Implement `async fn lookup(&self, agent_id: AgentId) -> Result<Option<Vec<SocketAddr>>>`
- Implement `async fn unregister(&self, agent_id: AgentId) -> Result<()>`
- Calculate shard using: `BLAKE3("saorsa-rendezvous" || agent_id) & 0xFFFF`
- Wire into GossipRuntime

**Dependencies**: Task 9

**Tests**:
- Test shard_id consistently maps same agent_id to same shard
- Test shard_id distributes agents across 65,536 shards
- Test register stores agent addresses in correct shard
- Test lookup finds registered agent
- Test unregister removes agent from shard

---

### Task 11: Implement Coordinator Adverts

**Goal**: Add self-elected public coordinator node advertisements.

**Files**:
- src/gossip/coordinator.rs (create)
- src/gossip.rs (modify to add coordinator module)
- src/gossip/runtime.rs (modify to include coordinator)
- tests/gossip_coordinator.rs (create)

**Implementation**:
- Create CoordinatorManager struct
- Initialize saorsa_gossip_coordinator
- Implement ML-DSA signed adverts on well-known topic "x0x.coordinators"
- Implement `async fn advertise_as_coordinator(&self) -> Result<()>` for public nodes
- Implement `async fn get_coordinators(&self) -> Result<Vec<CoordinatorAdvert>>`
- CoordinatorAdvert includes: peer_id, socket_addrs, signature, timestamp
- Set advert TTL to 24h
- Verify signatures on received adverts
- Wire into GossipRuntime

**Dependencies**: Task 10

**Tests**:
- Test advertise_as_coordinator broadcasts signed advert
- Test get_coordinators returns list of active coordinators
- Test signature verification rejects invalid adverts
- Test TTL expiration removes stale coordinators (24h)

---

### Task 12: Implement Anti-Entropy Reconciliation

**Goal**: Add IBLT reconciliation to repair missed messages and partitions.

**Files**:
- src/gossip/anti_entropy.rs (create)
- src/gossip.rs (modify to add anti_entropy module)
- src/gossip/runtime.rs (modify to include anti_entropy)
- tests/gossip_anti_entropy.rs (create)

**Implementation**:
- Create AntiEntropyManager struct
- Configure reconciliation interval from GossipConfig (default 30s)
- Implement IBLT (Invertible Bloom Lookup Table) for message set comparison
- Implement `async fn reconcile(&self) -> Result<ReconciliationStats>`
- ReconciliationStats includes: messages_recovered, peers_contacted
- Start background task to run reconciliation at configured interval
- Prioritize peers with largest divergence (most missing messages)
- Wire into GossipRuntime
- Integrate with PubSubManager message cache

**Dependencies**: Task 11

**Tests**:
- Test reconciliation recovers missed messages
- Test reconciliation runs at configured interval (30s)
- Test IBLT correctly identifies divergent message sets
- Test reconciliation prioritizes most divergent peers
- Test reconciliation stats are accurate

---

## Integration with Agent

After all tasks complete, integrate GossipRuntime into Agent:

**Files**:
- src/lib.rs (modify Agent struct)
- src/lib.rs (modify Agent::join_network)
- src/lib.rs (modify Agent::subscribe)
- src/lib.rs (modify Agent::publish)

**Changes**:
- Add `gossip: Option<Arc<GossipRuntime>>` field to Agent
- In AgentBuilder::build, initialize GossipRuntime if network configured
- In Agent::join_network, call `gossip.start()` and join via membership
- In Agent::subscribe, delegate to `gossip.pubsub.subscribe(topic)`
- In Agent::publish, delegate to `gossip.pubsub.publish(topic, payload)`
- Update Subscription to wrap pubsub receiver

## Success Criteria

- All 12 tasks complete
- Zero compilation errors or warnings
- All tests pass
- GossipRuntime integrates with NetworkNode from Phase 1.2
- Agent can join gossip network, subscribe/publish messages
- Presence beacons broadcast agent status
- FOAF discovery finds agents within 3 hops
- Rendezvous shards enable global lookup
- Anti-entropy repairs network partitions
