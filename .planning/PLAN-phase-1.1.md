# Phase 1.1: Foundation Wiring

## Goal
Route `GossipStreamType::Bulk` to `PresenceManager`, create `src/presence.rs` wrapper, wire into Agent lifecycle.

## Tasks

### Task 1: Add PresenceError to error.rs
- **Files**: `src/error.rs`
- **Spec**: Add `PresenceError` enum after `NetworkError` with variants: `NotInitialized`, `BeaconFailed(String)`, `FoafQueryFailed(String)`, `SubscriptionFailed(String)`, `Internal(String)`. Add `pub type PresenceResult<T>`. Add `From<PresenceError> for NetworkError` conversion so presence errors integrate with existing `?` chains. Follow existing `thiserror` pattern.

### Task 2: Create src/presence.rs — PresenceConfig and types
- **Files**: `src/presence.rs` (NEW), `src/lib.rs` (add `pub mod presence;`)
- **Spec**: Create presence module with:
  - `PresenceConfig` struct: `beacon_interval_secs: u64` (default 30), `foaf_default_ttl: u8` (default 2), `foaf_timeout_ms: u64` (default 5000), `enable_beacons: bool` (default true)
  - `PresenceEvent` enum: `AgentOnline { agent_id: AgentId, addresses: Vec<String> }`, `AgentOffline { agent_id: AgentId }`
  - Re-export key types from `saorsa_gossip_presence` as needed
  - Add `pub mod presence;` to `src/lib.rs` module declarations
  - Do NOT create the PresenceWrapper yet (Task 3)

### Task 3: Create PresenceWrapper in src/presence.rs
- **Files**: `src/presence.rs`
- **Spec**: Add `PresenceWrapper` struct that owns:
  - `manager: Arc<saorsa_gossip_presence::PresenceManager>`
  - `config: PresenceConfig`
  - `beacon_handle: tokio::sync::Mutex<Option<JoinHandle<()>>>`
  - `event_tx: tokio::sync::broadcast::Sender<PresenceEvent>`
  - Constructor `new(peer_id, transport, config) -> Result<Self>`: creates `PresenceManager::new_with_identity()` using `MlDsaKeyPair::generate()` pattern from pubsub.rs:206. Creates empty `GroupContext` map. Creates broadcast channel (capacity 256).
  - `manager(&self) -> &Arc<PresenceManager>` accessor
  - `subscribe_events(&self) -> broadcast::Receiver<PresenceEvent>`
  - `shutdown(&self)` — abort beacon handle

### Task 4: Wire Bulk dispatch in gossip/runtime.rs
- **Files**: `src/gossip/runtime.rs`
- **Spec**:
  - Add `presence: Option<Arc<PresenceWrapper>>` field to `GossipRuntime` struct
  - Add `set_presence(&self, p: Arc<PresenceWrapper>)` method (or pass in constructor)
  - In `start()` dispatch loop at line 147, change `other` arm: if `stream_type == GossipStreamType::Bulk`, call `presence.manager().handle_presence_message(peer, &data).await`. Keep `other` fallback for unknown types.
  - Add `presence(&self) -> Option<&Arc<PresenceWrapper>>` accessor
  - Wire membership peer add/remove callbacks to `presence.manager().add_broadcast_peer()` / `remove_broadcast_peer()`

### Task 5: Wire PresenceWrapper into Agent struct and AgentBuilder
- **Files**: `src/lib.rs`
- **Spec**:
  - Add `presence: Option<Arc<presence::PresenceWrapper>>` field to `Agent` struct
  - In `AgentBuilder::build()`: after `gossip_runtime` creation (~line 2933), create `PresenceWrapper::new(peer_id, network.clone(), PresenceConfig::default())`. Store in Agent.
  - Pass presence Arc to `gossip_runtime` via `set_presence()` so Bulk dispatch works.
  - Add `pub fn presence(&self) -> Option<&Arc<presence::PresenceWrapper>>` accessor to Agent
  - Initialize field to `None` in Agent struct literal, set after gossip_runtime creation

### Task 6: Wire presence lifecycle into join_network()
- **Files**: `src/lib.rs`
- **Spec**:
  - In `join_network()`, after HyParView join (~line 1801) and before `announce_identity()`:
    - If `self.presence` is Some, call `presence.manager().start_beacons(config.beacon_interval_secs)`
    - Populate initial broadcast peers from connected peers
    - Set addr hints from `network.node_status()` if available
  - In Agent shutdown/cleanup, call `presence.shutdown()`
  - Ensure the presence manager gets the network's connected peer list via `add_broadcast_peer()` for each initial peer

### Task 7: Integration smoke test
- **Files**: `tests/presence_wiring_test.rs` (NEW)
- **Spec**: Create basic integration test that:
  - Creates an Agent via AgentBuilder
  - Verifies `agent.presence()` returns `Some`
  - Verifies `agent.presence().unwrap().subscribe_events()` returns a receiver
  - Creates a second Agent and verifies both have presence
  - Does NOT test network connectivity (that's Phase 1.2+)
  - Use `tempfile::TempDir` for key isolation
