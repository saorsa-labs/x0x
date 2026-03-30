# Task Specification Review
**Date**: 2026-03-30
**Phase**: 1.1 — Foundation Wiring
**Task**: 7 (all tasks in phase assessed)

## Spec Compliance

### Task 1: Add PresenceError to error.rs
- [x] `PresenceError` enum added with all 5 required variants: `NotInitialized`, `BeaconFailed(String)`, `FoafQueryFailed(String)`, `SubscriptionFailed(String)`, `Internal(String)`
- [x] `pub type PresenceResult<T>` added
- [x] `From<PresenceError> for NetworkError` impl added
- [x] Uses `thiserror` pattern consistent with existing error types

### Task 2: Create src/presence.rs — PresenceConfig and types
- [x] `PresenceConfig` with all 4 fields and correct defaults
- [x] `PresenceEvent` enum with `AgentOnline` and `AgentOffline` variants
- [x] `pub mod presence;` added to src/lib.rs

### Task 3: Create PresenceWrapper
- [x] `PresenceWrapper` struct with `manager`, `config`, `beacon_handle`, `event_tx` fields
- [x] `new(peer_id, transport, config)` constructor using `MlDsaKeyPair::generate()`
- [x] `PresenceManager::new_with_identity()` called correctly
- [x] `manager()` accessor
- [x] `subscribe_events()` broadcast receiver
- [x] `shutdown()` aborts beacon handle

### Task 4: Wire Bulk dispatch in gossip/runtime.rs
- [x] `presence: std::sync::Mutex<Option<Arc<PresenceWrapper>>>` added to `GossipRuntime`
- [x] `set_presence()` method added
- [x] `GossipStreamType::Bulk` arm added in dispatcher, routes to `handle_presence_message()`
- [x] `presence()` accessor added
- [ ] **GAP**: Membership peer add/remove callbacks NOT wired in runtime.rs. Plan spec Task 4 said "Wire membership peer add/remove callbacks to `presence.manager().add_broadcast_peer()` / `remove_broadcast_peer()`". Only initial seed is done in `join_network()` (Task 6 area), not ongoing callbacks.

### Task 5: Wire PresenceWrapper into Agent struct and AgentBuilder
- [x] `presence: Option<Arc<presence::PresenceWrapper>>` field in `Agent`
- [x] `PresenceWrapper::new()` called in `AgentBuilder::build()`
- [x] `rt.set_presence()` called to wire into gossip runtime
- [x] `presence_system()` accessor added (named `presence_system` to avoid clash with existing `presence()` method — acceptable deviation)

### Task 6: Wire presence lifecycle into join_network()
- [x] `start_beacons()` called if `enable_beacons` is true
- [x] Initial broadcast peers seeded from active view
- [x] Addr hints set from `network.node_status()`
- [x] `pw.shutdown()` called in `Agent::shutdown()`

### Task 7: Integration smoke test
- [x] `tests/presence_wiring_test.rs` created with 5 tests
- [x] `agent.presence_system()` returns `Some` with network
- [x] `agent.presence_system()` returns `None` without network
- [x] `subscribe_events()` returns a receiver
- [x] Uses `TempDir` for key isolation
- [ ] **MINOR**: Does not test a "second Agent" instance explicitly (plan said "Creates a second Agent"). The `test_presence_subscribe_events` test only creates one agent. Low priority.

## Overall Spec Compliance
- 6 of 7 tasks fully complete
- Task 4 has one gap: no ongoing membership callbacks (only initial seed)
- Task 7 minor: no two-agent test

## Grade: B+
