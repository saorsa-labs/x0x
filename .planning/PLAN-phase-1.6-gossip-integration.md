# Phase 1.6: Gossip Integration - Implementation Plan

**Phase**: 1.6
**Name**: Gossip Integration (saorsa-gossip wiring)
**Status**: Planning
**Created**: 2026-02-07
**Priority**: HIGH - Blocks all gossip features
**Estimated Tasks**: 12

---

## Problem Statement

The saorsa-gossip crates (0.4.7) are dependencies, but **NOT actually used**. The `GossipRuntime` is a shell that doesn't initialize any gossip components. This blocks:
- Pub/sub messaging
- CRDT task list synchronization
- Presence announcements
- FOAF discovery
- Anti-entropy sync

## Overview

Wire up the existing saorsa-gossip components into the x0x GossipRuntime to enable all gossip-based features. All crates are already dependencies - this is pure integration work, not new features.

**Existing Dependencies:**
```toml
saorsa-gossip-coordinator = "0.4.7"
saorsa-gossip-crdt-sync = "0.4.7"
saorsa-gossip-membership = "0.4.7"
saorsa-gossip-presence = "0.4.7"
saorsa-gossip-pubsub = "0.4.7"
saorsa-gossip-rendezvous = "0.4.7"
saorsa-gossip-runtime = "0.4.7"
saorsa-gossip-transport = "0.4.7"
saorsa-gossip-types = "0.4.7"
```

---

## Task Breakdown

### Task 1: Initialize saorsa-gossip Runtime
**File**: `src/gossip/runtime.rs`

Replace the placeholder `GossipRuntime` with actual saorsa-gossip-runtime integration:

```rust
use saorsa_gossip_runtime::{GossipRuntime as SaorsaRuntime, RuntimeConfig};

pub struct GossipRuntime {
    config: GossipConfig,
    transport: Arc<QuicTransportAdapter>,
    saorsa_runtime: Arc<RwLock<Option<SaorsaRuntime>>>,
    running: Arc<RwLock<bool>>,
}

impl GossipRuntime {
    pub async fn start(&self) -> NetworkResult<()> {
        let mut running = self.running.write().await;
        if *running {
            return Err(NetworkError::NodeCreation("already running".to_string()));
        }

        // Convert x0x config to saorsa config
        let saorsa_config = RuntimeConfig {
            peer_id: self.transport.node().peer_id(),
            active_view_size: self.config.active_view_size,
            passive_view_size: self.config.passive_view_size,
            // ... map all fields
        };

        // Create saorsa runtime
        let runtime = SaorsaRuntime::new(saorsa_config, self.transport.clone())
            .await
            .map_err(|e| NetworkError::NodeCreation(e.to_string()))?;

        // Start gossip protocols
        runtime.start().await
            .map_err(|e| NetworkError::NodeCreation(e.to_string()))?;

        *self.saorsa_runtime.write().await = Some(runtime);
        *running = true;
        Ok(())
    }
}
```

**Requirements:**
- Use actual saorsa-gossip-runtime
- Proper error handling
- Lifecycle management (start/stop)

**Tests:**
- Runtime creation and startup
- Shutdown cleanup
- Double-start protection

---

### Task 2: Wire Up Pub/Sub
**Files**: `src/lib.rs`, `src/gossip/runtime.rs`

Replace placeholder subscribe/publish with real saorsa-gossip-pubsub:

```rust
impl Agent {
    pub async fn subscribe(&self, topic: &str) -> error::Result<Subscription> {
        let runtime = self.gossip_runtime.as_ref()
            .ok_or(error::IdentityError::Storage(std::io::Error::other("no gossip runtime")))?;

        let saorsa_runtime = runtime.saorsa_runtime.read().await;
        let saorsa = saorsa_runtime.as_ref()
            .ok_or(error::IdentityError::Storage(std::io::Error::other("runtime not started")))?;

        // Subscribe via saorsa-gossip-pubsub
        let rx = saorsa.pubsub()
            .subscribe(topic.to_string())
            .await
            .map_err(|e| error::IdentityError::Storage(std::io::Error::other(e.to_string())))?;

        Ok(Subscription { receiver: rx })
    }

    pub async fn publish(&self, topic: &str, payload: Vec<u8>) -> error::Result<()> {
        let runtime = self.gossip_runtime.as_ref()
            .ok_or(error::IdentityError::Storage(std::io::Error::other("no gossip runtime")))?;

        let saorsa_runtime = runtime.saorsa_runtime.read().await;
        let saorsa = saorsa_runtime.as_ref()
            .ok_or(error::IdentityError::Storage(std::io::Error::other("runtime not started")))?;

        // Publish via saorsa-gossip-pubsub
        saorsa.pubsub()
            .publish(topic.to_string(), payload)
            .await
            .map_err(|e| error::IdentityError::Storage(std::io::Error::other(e.to_string())))?;

        Ok(())
    }
}

pub struct Subscription {
    receiver: tokio::sync::mpsc::Receiver<saorsa_gossip_types::Message>,
}

impl Subscription {
    pub async fn recv(&mut self) -> Option<Message> {
        self.receiver.recv().await.map(|msg| Message {
            origin: msg.sender.to_string(),
            payload: msg.payload,
            topic: msg.topic,
        })
    }
}
```

**Requirements:**
- Real message delivery
- Topic-based routing
- Epidemic broadcast

**Tests:**
- Subscribe to topic
- Publish and receive
- Multiple subscribers
- Cross-node delivery

---

### Task 3: Wire Up HyParView Membership
**File**: `src/gossip/runtime.rs`

Enable HyParView membership protocol:

```rust
pub async fn start(&self) -> NetworkResult<()> {
    // ... (from Task 1)

    // Initialize HyParView membership
    runtime.membership()
        .configure(saorsa_gossip_membership::HyParViewConfig {
            active_view_size: self.config.active_view_size,
            passive_view_size: self.config.passive_view_size,
            shuffle_active_size: self.config.active_view_size / 2,
            shuffle_passive_size: self.config.passive_view_size / 4,
            shuffle_interval: Duration::from_secs(30),
        })
        .await?;

    runtime.membership().start().await?;

    // ... rest of initialization
}
```

**Requirements:**
- Active/passive view management
- Peer shuffling
- Failure detection integration

**Tests:**
- Membership convergence
- Shuffle protocol
- View size limits

---

### Task 4: Wire Up Presence Beacons
**File**: `src/gossip/runtime.rs`

Enable presence announcements:

```rust
pub async fn start(&self) -> NetworkResult<()> {
    // ... (from Tasks 1-3)

    // Start presence beacons
    runtime.presence()
        .configure(saorsa_gossip_presence::PresenceConfig {
            beacon_interval: Duration::from_secs(60),
            expiry_threshold: Duration::from_secs(180),
        })
        .await?;

    runtime.presence().start().await?;

    // ... rest
}
```

**Requirements:**
- Periodic presence announcements
- Peer liveness tracking
- Expiry detection

**Tests:**
- Presence announcement
- Peer discovery via beacons
- Expiry after timeout

---

### Task 5: Wire Up CRDT Task List Sync
**File**: `src/crdt/sync.rs`

Replace TODOs with actual saorsa-gossip-crdt-sync:

```rust
impl TaskListSync {
    pub async fn start(&self) -> Result<()> {
        // Subscribe to topic via gossip runtime
        let mut rx = self.gossip_runtime.pubsub()
            .subscribe(&self.topic)
            .await?;

        // Publish initial state
        self.publish_state().await?;

        // Start sync loop
        let task_list = self.task_list.clone();
        let runtime = self.gossip_runtime.clone();
        let topic = self.topic.clone();

        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                // Deserialize CRDT update
                if let Ok(update) = bincode::deserialize::<TaskListUpdate>(&msg.payload) {
                    // Merge into local replica
                    let mut list = task_list.write().await;
                    if let Err(e) = list.merge(&update.list) {
                        tracing::warn!("Failed to merge CRDT update: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    async fn publish_state(&self) -> Result<()> {
        let list = self.task_list.read().await;
        let update = TaskListUpdate {
            list_id: list.id(),
            list: list.clone(),
        };

        let payload = bincode::serialize(&update)?;
        self.gossip_runtime.pubsub()
            .publish(&self.topic, payload)
            .await?;

        Ok(())
    }
}
```

**Requirements:**
- Real-time CRDT synchronization
- Automatic merge on receive
- Periodic anti-entropy

**Tests:**
- Multi-node convergence
- Concurrent operations
- Network partitions

---

### Task 6: Wire Up Anti-Entropy
**File**: `src/gossip/runtime.rs`

Enable anti-entropy reconciliation:

```rust
pub async fn start(&self) -> NetworkResult<()> {
    // ... (from Tasks 1-5)

    // Start anti-entropy sync
    runtime.crdt_sync()
        .configure(saorsa_gossip_crdt_sync::AntiEntropyConfig {
            sync_interval: Duration::from_secs(120),
            peer_sample_size: 3,
        })
        .await?;

    runtime.crdt_sync().start().await?;

    // ... rest
}
```

**Requirements:**
- Periodic reconciliation
- Random peer sampling
- Delta synchronization

**Tests:**
- Divergence resolution
- Partition healing
- Incremental sync

---

### Task 7: Wire Up FOAF Discovery
**File**: `src/gossip/runtime.rs`

Enable friend-of-a-friend peer discovery:

```rust
pub async fn start(&self) -> NetworkResult<()> {
    // ... (from Tasks 1-6)

    // Start FOAF discovery
    runtime.presence()
        .enable_foaf(saorsa_gossip_presence::FoafConfig {
            hop_limit: 2,
            cache_size: 1000,
            cache_ttl: Duration::from_secs(300),
        })
        .await?;

    // ... rest
}
```

**Requirements:**
- 2-hop peer discovery
- FOAF cache management
- Expired entry eviction

**Tests:**
- FOAF peer discovery
- Cache limits
- TTL expiry

---

### Task 8: Wire Up Rendezvous Coordination
**File**: `src/gossip/runtime.rs`

Enable rendezvous sharding:

```rust
pub async fn start(&self) -> NetworkResult<()> {
    // ... (from Tasks 1-7)

    // Start rendezvous coordination
    runtime.rendezvous()
        .configure(saorsa_gossip_rendezvous::RendezvousConfig {
            shard_count: 256,
            replication_factor: 3,
        })
        .await?;

    runtime.rendezvous().start().await?;

    // ... rest
}
```

**Requirements:**
- Consistent hashing
- Shard assignment
- Replication management

**Tests:**
- Shard distribution
- Replication factor
- Node join/leave

---

### Task 9: Wire Up Coordinator Advertisements
**File**: `src/gossip/runtime.rs`

Enable coordinator role advertisements:

```rust
pub async fn start(&self) -> NetworkResult<()> {
    // ... (from Tasks 1-8)

    // Start coordinator advertisements (if bootstrap node)
    if self.config.is_coordinator {
        runtime.coordinator()
            .advertise(saorsa_gossip_coordinator::CoordinatorInfo {
                capabilities: vec!["bootstrap", "relay", "reflector"],
                endpoint: self.transport.local_addr()?,
            })
            .await?;

        runtime.coordinator().start().await?;
    }

    // ... rest
}
```

**Requirements:**
- Capability advertisement
- Coordinator discovery
- Load distribution

**Tests:**
- Advertisement broadcast
- Coordinator selection
- Capability matching

---

### Task 10: Update Agent Builder
**File**: `src/lib.rs`

Wire gossip runtime into Agent creation:

```rust
impl AgentBuilder {
    pub async fn build(self) -> error::Result<Agent> {
        // ... (existing identity creation)

        // Create network node
        let network = if let Some(config) = self.network_config {
            Some(NetworkNode::new(config).await?)
        } else {
            None
        };

        // Create gossip runtime if network exists
        let gossip_runtime = if let Some(ref net) = network {
            let gossip_config = GossipConfig::default();
            let transport = Arc::new(QuicTransportAdapter::new(Arc::new(net.clone())));
            let runtime = GossipRuntime::new(gossip_config, transport);

            // Auto-start gossip runtime
            runtime.start().await?;

            Some(runtime)
        } else {
            None
        };

        Ok(Agent {
            identity,
            network,
            gossip_runtime,
        })
    }
}
```

**Requirements:**
- Auto-start gossip on build
- Graceful degradation if no network
- Proper lifecycle

**Tests:**
- Agent with gossip
- Agent without network
- Gossip auto-start

---

### Task 11: Update create_task_list/join_task_list
**File**: `src/lib.rs`

Replace "not implemented" errors with real implementation:

```rust
impl Agent {
    pub async fn create_task_list(&self, name: &str, topic: &str) -> error::Result<TaskListHandle> {
        let runtime = self.gossip_runtime.as_ref()
            .ok_or(error::IdentityError::Storage(std::io::Error::other("no gossip")))?;

        // Create task list
        let list_id = TaskListId::from_content(name, self.agent_id(), chrono::Utc::now().timestamp());
        let task_list = TaskList::new(list_id, name.to_string(), self.identity.peer_id());

        // Wrap in sync
        let sync = TaskListSync::new(
            Arc::new(RwLock::new(task_list)),
            topic.to_string(),
            runtime.clone(),
        );

        // Start synchronization
        sync.start().await?;

        Ok(TaskListHandle { sync })
    }

    pub async fn join_task_list(&self, topic: &str) -> error::Result<TaskListHandle> {
        let runtime = self.gossip_runtime.as_ref()
            .ok_or(error::IdentityError::Storage(std::io::Error::other("no gossip")))?;

        // Create empty task list (will sync from network)
        let list_id = TaskListId::zero(); // Temporary - will be replaced on first sync
        let task_list = TaskList::new(list_id, "".to_string(), self.identity.peer_id());

        // Wrap in sync
        let sync = TaskListSync::new(
            Arc::new(RwLock::new(task_list)),
            topic.to_string(),
            runtime.clone(),
        );

        // Start synchronization (will receive updates)
        sync.start().await?;

        Ok(TaskListHandle { sync })
    }
}
```

**Requirements:**
- Actual task list creation/joining
- Real gossip synchronization
- Error handling

**Tests:**
- Create and join
- Multi-node sync
- CRDT convergence

---

### Task 12: Integration Tests
**File**: `tests/gossip_integration.rs`

Create full integration test using real gossip:

```rust
#[tokio::test]
async fn test_full_gossip_stack() {
    // Create 3 agents
    let agent1 = Agent::builder().build().await.unwrap();
    let agent2 = Agent::builder().build().await.unwrap();
    let agent3 = Agent::builder().build().await.unwrap();

    // Join network
    agent1.join_network().await.unwrap();
    agent2.join_network().await.unwrap();
    agent3.join_network().await.unwrap();

    // Wait for membership convergence
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Test pub/sub
    let mut sub1 = agent1.subscribe("test-topic").await.unwrap();
    let mut sub2 = agent2.subscribe("test-topic").await.unwrap();

    agent3.publish("test-topic", b"hello".to_vec()).await.unwrap();

    let msg1 = tokio::time::timeout(Duration::from_secs(5), sub1.recv()).await.unwrap().unwrap();
    let msg2 = tokio::time::timeout(Duration::from_secs(5), sub2.recv()).await.unwrap().unwrap();

    assert_eq!(msg1.payload, b"hello");
    assert_eq!(msg2.payload, b"hello");

    // Test task list sync
    let list1 = agent1.create_task_list("test", "task-topic").await.unwrap();
    let list2 = agent2.join_task_list("task-topic").await.unwrap();

    list1.add_task("Task 1", "").await.unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    let tasks = list2.get_tasks().await.unwrap();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].metadata.title, "Task 1");
}
```

**Requirements:**
- Multi-agent scenarios
- Real network formation
- CRDT convergence validation

**Tests:**
- All features working together
- Cross-feature interactions
- Performance under load

---

## Acceptance Criteria

- [ ] All saorsa-gossip components initialized in GossipRuntime
- [ ] Pub/sub messaging working across nodes
- [ ] CRDT task lists synchronizing in real-time
- [ ] Presence announcements and FOAF discovery functional
- [ ] Anti-entropy reconciliation preventing divergence
- [ ] All integration tests passing
- [ ] Zero warnings, zero unwrap/expect
- [ ] Documentation updated

---

## Testing Strategy

1. **Unit Tests**: Each task's components
2. **Integration Tests**: Multi-node scenarios
3. **VPS Network Tests**: Run on 6-node testnet
4. **Stress Tests**: 100+ concurrent operations
5. **Partition Tests**: Network split/heal scenarios

---

## Success Metrics

- ✅ gossip_integration.rs: All tests passing
- ✅ VPS test scripts: 100% pass rate
- ✅ CRDT convergence: <5 seconds across 6 nodes
- ✅ Message delivery: 100% epidemic broadcast
- ✅ Zero memory leaks (valgrind clean)

---

## Dependencies

- saorsa-gossip crates: Already in Cargo.toml ✅
- VPS testnet: Already deployed ✅
- Test scripts: Already created ✅

---

## Risks

**Low Risk:**
- All saorsa-gossip crates already tested in saorsa-gossip repo
- This is pure integration, not new features
- Clear API boundaries

**Mitigation:**
- Start with pub/sub (simplest)
- Test each component incrementally
- Run VPS tests after each task

---

## Estimated Effort

- **12 tasks × ~2 hours = 24 hours**
- **Buffer for testing/debugging: +8 hours**
- **Total: ~32 hours (4 days)**

---

**Created**: 2026-02-07
**Status**: Ready to Execute
**Priority**: HIGH
