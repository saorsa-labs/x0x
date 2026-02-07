# Phase 1.6: Gossip Integration - REVISED PLAN

**Phase**: 1.6
**Name**: x0x Pub/Sub & Gossip (Direct Implementation)
**Status**: Executing
**Revised**: 2026-02-07
**Original Plan**: PLAN-phase-1.6-gossip-integration.md (assumed saorsa-gossip was functional)
**Revision Reason**: saorsa-gossip crates are placeholder implementations only

---

## Revision Summary

**Discovery**: saorsa-gossip-* crates (0.4.7) are empty placeholders, not functional libraries.

**Decision**: Implement minimal x0x pub/sub directly using Task 1's `GossipTransport` trait foundation.

**Future**: Phase 1.7 will implement proper saorsa-gossip components and migrate x0x to use them.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Agent (src/lib.rs)                                         │
│  ├─ subscribe(topic) → Subscription                         │
│  └─ publish(topic, data) → Result<()>                       │
└─────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────┐
│  PubSubManager (src/gossip/pubsub.rs)                       │
│  ├─ subscriptions: HashMap<Topic, Vec<Sender>>              │
│  ├─ subscribe() → add to local list                         │
│  └─ publish() → broadcast to peers + local subscribers      │
└─────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────┐
│  NetworkNode (src/network.rs) implements GossipTransport    │
│  └─ send_message(peer, stream_type, data)                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Task Breakdown (Revised)

### ✅ Task 1: Implement GossipTransport for NetworkNode

**Status**: COMPLETE
**Commit**: `5a02bca`, `a5ea1f0`
**Files**: `src/network.rs`, `src/gossip.rs`
**Summary**:
- Implemented `saorsa_gossip_transport::GossipTransport` trait on `NetworkNode`
- PeerId conversion helpers (ant-quic ↔ saorsa-gossip)
- Stream type multiplexing via background receiver
- Removed obsolete `QuicTransportAdapter`
- 295 tests passing, zero warnings

---

### 🔄 Task 2: Implement x0x PubSubManager

**File**: `src/gossip/pubsub.rs` (NEW)
**Dependencies**: Task 1

Implement simple epidemic broadcast pub/sub:

```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

pub struct PubSubManager {
    network: Arc<NetworkNode>,
    subscriptions: Arc<RwLock<HashMap<String, Vec<mpsc::Sender<Message>>>>>,
}

impl PubSubManager {
    pub fn new(network: Arc<NetworkNode>) -> Self {
        Self {
            network,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn subscribe(&self, topic: String) -> Subscription {
        let (tx, rx) = mpsc::channel(100);
        self.subscriptions.write().await
            .entry(topic.clone())
            .or_default()
            .push(tx);

        Subscription { topic, receiver: rx }
    }

    pub async fn publish(&self, topic: String, data: Vec<u8>) -> Result<()> {
        // 1. Deliver to local subscribers
        if let Some(subs) = self.subscriptions.read().await.get(&topic) {
            for tx in subs {
                tx.send(Message { topic: topic.clone(), data: data.clone() }).await.ok();
            }
        }

        // 2. Broadcast to all connected peers via GossipTransport
        for peer in self.network.connected_peers().await {
            self.network.send_message(
                peer.peer_id,
                GossipStreamType::PubSub,
                encode_pubsub_message(&topic, &data),
            ).await?;
        }

        Ok(())
    }

    pub async fn handle_incoming(&self, peer: PeerId, data: Bytes) {
        let (topic, message_data) = decode_pubsub_message(data);

        // Deliver to local subscribers
        if let Some(subs) = self.subscriptions.read().await.get(&topic) {
            for tx in subs {
                tx.send(Message { topic: topic.clone(), data: message_data.clone() }).await.ok();
            }
        }

        // Re-broadcast to other peers (epidemic broadcast)
        // TODO: Add seen-message tracking to prevent loops
    }
}
```

**Requirements**:
- Simple topic-based routing
- Local subscriber tracking
- Epidemic broadcast to peers
- Message encoding/decoding

**Tests**:
- Subscribe to topic
- Publish and receive locally
- Multiple subscribers to same topic
- Message encoding/decoding

**Estimated Lines**: ~200 lines

---

### Task 3: Wire Up PubSubManager in Agent

**Files**: `src/lib.rs`, `src/gossip/runtime.rs`

Update Agent to use PubSubManager:

```rust
// src/gossip/runtime.rs
use crate::gossip::pubsub::PubSubManager;

pub struct GossipRuntime {
    network: Arc<NetworkNode>,
    pubsub: Arc<PubSubManager>,
}

impl GossipRuntime {
    pub fn new(network: Arc<NetworkNode>) -> Self {
        let pubsub = Arc::new(PubSubManager::new(network.clone()));
        Self { network, pubsub }
    }

    pub async fn start(&self) -> Result<()> {
        // TODO: Start background task to handle incoming PubSub messages
        Ok(())
    }
}

// src/lib.rs
impl Agent {
    pub async fn subscribe(&self, topic: &str) -> Result<Subscription> {
        self.gossip_runtime.pubsub.subscribe(topic.to_string()).await
    }

    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> Result<()> {
        self.gossip_runtime.pubsub.publish(topic.to_string(), data).await
    }
}
```

**Requirements**:
- Replace placeholder subscribe/publish
- Background task for incoming messages
- Clean error handling

**Tests**:
- Agent.subscribe() returns working subscription
- Agent.publish() delivers to subscribers
- Multiple agents pub/sub integration test

**Estimated Lines**: ~100 lines

---

### Task 4: Background Message Handler

**File**: `src/gossip/runtime.rs`

Start background task to route incoming PubSub messages:

```rust
pub async fn start(&self) -> Result<()> {
    let pubsub = self.pubsub.clone();
    let network = self.network.clone();

    tokio::spawn(async move {
        loop {
            match network.receive_message().await {
                Ok((peer, GossipStreamType::PubSub, data)) => {
                    pubsub.handle_incoming(peer, data).await;
                }
                Ok((peer, other_type, data)) => {
                    // Route to other handlers (membership, etc.)
                }
                Err(e) => {
                    // Handle errors
                    break;
                }
            }
        }
    });

    Ok(())
}
```

**Requirements**:
- Route PubSub stream messages to PubSubManager
- Handle errors gracefully
- Shutdown cleanup

**Tests**:
- Background task routes messages correctly
- Clean shutdown
- Error handling

**Estimated Lines**: ~50 lines

---

### Task 5: Message Deduplication

**File**: `src/gossip/pubsub.rs`

Add seen-message tracking to prevent broadcast loops:

```rust
pub struct PubSubManager {
    // ... existing fields
    seen_messages: Arc<RwLock<LruCache<MessageId, ()>>>,
}

fn message_id(topic: &str, data: &[u8]) -> MessageId {
    blake3::hash(&[topic.as_bytes(), data].concat()).into()
}

pub async fn handle_incoming(&self, peer: PeerId, data: Bytes) {
    let (topic, message_data) = decode_pubsub_message(data);
    let msg_id = message_id(&topic, &message_data);

    // Check if we've seen this message
    {
        let mut seen = self.seen_messages.write().await;
        if seen.contains(&msg_id) {
            return; // Already processed, don't re-broadcast
        }
        seen.put(msg_id, ());
    }

    // Deliver to local subscribers + re-broadcast
    // ... (existing logic)
}
```

**Requirements**:
- LRU cache for seen messages (size: 10,000)
- Message ID from blake3 hash
- Prevent loops in epidemic broadcast

**Tests**:
- Duplicate messages are dropped
- Cache evicts old entries
- No infinite loops in mesh network

**Estimated Lines**: ~50 lines

---

### Task 6: Integration Tests

**File**: `tests/pubsub_integration.rs` (NEW)

Multi-agent pub/sub integration tests:

```rust
#[tokio::test]
async fn test_two_agent_pubsub() {
    let agent1 = Agent::new().await.unwrap();
    let agent2 = Agent::new().await.unwrap();

    // Agent 2 connects to Agent 1
    agent2.join_network(&agent1.listen_addr()).await.unwrap();

    // Agent 2 subscribes to "tasks"
    let mut sub = agent2.subscribe("tasks").await.unwrap();

    // Agent 1 publishes to "tasks"
    agent1.publish("tasks", b"hello").await.unwrap();

    // Agent 2 receives the message
    let msg = sub.recv().await.unwrap();
    assert_eq!(msg.data, b"hello");
}

#[tokio::test]
async fn test_three_agent_mesh() {
    // Test epidemic broadcast through 3-node mesh
}

#[tokio::test]
async fn test_multiple_subscribers_same_topic() {
    // Test fan-out to multiple subscribers
}
```

**Requirements**:
- Multi-agent setup
- Pub/sub message delivery
- Mesh network broadcast
- Multiple subscribers

**Tests**: 5 integration tests

**Estimated Lines**: ~300 lines

---

### Tasks 7-12: DEFERRED

The following tasks from the original plan are **deferred to Phase 1.7** (Saorsa-Gossip Migration):

- ~~Task 7: Wire Up HyParView Membership~~
- ~~Task 8: Wire Up SWIM Failure Detection~~
- ~~Task 9: Wire Up Presence Beacons~~
- ~~Task 10: Wire Up Anti-Entropy Sync~~
- ~~Task 11: Wire Up FOAF Discovery~~
- ~~Task 12: Integration Tests~~

**Rationale**: These require full saorsa-gossip implementation. Current pub/sub implementation is sufficient for Phase 1.6 goals (enable CRDT task list sync).

---

## Phase 1.6 Success Criteria (Revised)

✅ **Task 1**: NetworkNode implements GossipTransport
⬜ **Task 2**: PubSubManager with epidemic broadcast
⬜ **Task 3**: Agent.subscribe/publish working
⬜ **Task 4**: Background message handler
⬜ **Task 5**: Message deduplication
⬜ **Task 6**: Integration tests passing

**Deliverable**: Working pub/sub that enables CRDT task list synchronization between agents.

---

## Phase 1.7 Preview (Future)

**Name**: Saorsa-Gossip Migration
**Objective**: Replace x0x pub/sub with proper gossip protocols

**Tasks**:
1. Implement HyParView membership in saorsa-gossip-membership
2. Implement Plumtree pub/sub in saorsa-gossip-pubsub
3. Implement SWIM failure detection
4. Migrate x0x to use saorsa-gossip components
5. Verify backward compatibility
6. Performance benchmarks

---

## References

- Task 1 Commit: `5a02bca` - GossipTransport implementation
- Architecture Decision: `.planning/ARCHITECTURE_DECISION.md`
- Original Plan: `.planning/PLAN-phase-1.6-gossip-integration.md`
