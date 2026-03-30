# Phase 1.2 Plan: Public API — FOAF Discovery & Events

## Overview

Implement the three public API methods needed for FOAF discovery and presence events,
plus the PeerId→AgentId mapping layer and the diff-based event emission loop.

## Context (from Phase 1.1)

- `src/presence.rs` exists with `PresenceWrapper`, `PresenceConfig`, `PresenceEvent`
- `PresenceWrapper` wraps `saorsa_gossip_presence::PresenceManager`
- `Agent` has `presence: Option<Arc<PresenceWrapper>>` field
- `Agent` has `identity_discovery_cache: Arc<RwLock<HashMap<AgentId, DiscoveredAgent>>>`
- `PresenceManager::initiate_foaf_query(topic_id, ttl, timeout_ms)` returns `Vec<(PeerId, PresenceRecord)>`
- `PresenceManager::get_online_peers(topic_id)` returns `Vec<PeerId>`
- `PresenceRecord` has `addr_hints: Vec<String>`, `expires: u64`, `presence_tag: [u8; 32]`
- `shard_topic_for_agent()` and `IDENTITY_TTL_SECS` already exist in lib.rs

## Key Design Decisions

### PeerId→AgentId Mapping
FOAF returns `(PeerId, PresenceRecord)` pairs where PeerId is the *machine* PeerId (from ant-quic).
The identity_discovery_cache is keyed by AgentId but includes `machine_id: MachineId`.
Since `MachineId(peer.0)` is the conversion (per CLAUDE.md and existing code patterns),
we can reverse-look up AgentId from MachineId using the cache.

### FOAF Topic
FOAF queries need a TopicId. We use a global presence topic: `x0x.presence.global`.
The PresenceManager uses `TopicId` which is a `[u8; 32]` hash of the topic string.

### Event Emission Loop
A background task runs every 10 seconds, snapshots current `PresenceManager::get_online_peers()`
against the previous snapshot, and emits `AgentOnline`/`AgentOffline` events on the broadcast channel.

---

## Tasks

### Task 1: Add PeerId→AgentId mapping to PresenceWrapper

**Files**: `src/presence.rs`

**Description**:
Add a method to look up AgentId from MachineId using the identity_discovery_cache.

1. Add `peer_to_agent_id(peer_id: PeerId, cache: &HashMap<AgentId, DiscoveredAgent>) -> Option<AgentId>`
   as a free function in `src/presence.rs`.
   - `MachineId` is `MachineId(peer.0)` where `peer.0` is the raw `[u8; 32]`
   - Iterate the cache to find entry where `entry.machine_id.0 == peer_id.0`
2. Add `pub fn global_presence_topic() -> TopicId` helper that hashes `"x0x.presence.global"`
   into a `TopicId`.
   - `TopicId` is a newtype over `[u8; 32]` from `saorsa_gossip_types`
   - Use `sha2::Sha256` (already in deps via saorsa-gossip) or blake3 if available
   - Check Cargo.toml for available hash crates

**Estimated Lines**: ~40

---

### Task 2: Add presence-based DiscoveredAgent conversion

**Files**: `src/presence.rs`

**Description**:
Add a method that converts `(PeerId, PresenceRecord)` + cache-lookup into a `DiscoveredAgent`.

Add to `presence.rs`:

```rust
/// Convert a presence record into a DiscoveredAgent, using the identity
/// cache to resolve PeerId → AgentId → full identity info.
///
/// Returns None if the PeerId has no corresponding AgentId in the cache.
pub fn presence_record_to_discovered_agent(
    peer_id: PeerId,
    record: &saorsa_gossip_types::PresenceRecord,
    cache: &std::collections::HashMap<crate::identity::AgentId, crate::DiscoveredAgent>,
) -> Option<crate::DiscoveredAgent>
```

Logic:
1. Call `peer_to_agent_id(peer_id, cache)` → get AgentId
2. If found in cache, clone the cached entry but update `addresses` from `record.addr_hints`
   (parse each hint as `SocketAddr`)
3. If not in cache, create a minimal `DiscoveredAgent` with agent_id=AgentId(peer.0)
   (MachineId-as-AgentId fallback), addresses from addr_hints, announced_at=record.since

Also add `fn parse_addr_hints(hints: &[String]) -> Vec<std::net::SocketAddr>` helper.

**Estimated Lines**: ~60

---

### Task 3: Add event emission background task to PresenceWrapper

**Files**: `src/presence.rs`

**Description**:
Add a method `start_event_loop` that spawns a background task to emit presence events
every 10 seconds by diffing the current online set against the previous snapshot.

Add to `PresenceWrapper`:

```rust
/// Start the presence event emission loop.
///
/// Spawns a background task that polls `PresenceManager::get_online_peers()`
/// every 10 seconds, diffs against the previous snapshot, and emits
/// `PresenceEvent::AgentOnline` / `PresenceEvent::AgentOffline` on the
/// broadcast channel.
///
/// Returns handle to the spawned task. Abort it to stop the loop.
pub async fn start_event_loop(
    &self,
    cache: std::sync::Arc<tokio::sync::RwLock<
        std::collections::HashMap<crate::identity::AgentId, crate::DiscoveredAgent>
    >>,
) -> tokio::task::JoinHandle<()>
```

Logic:
1. Clone `Arc::clone(&self.manager)` and `self.event_tx.clone()`
2. Spawn a tokio task with 10s interval loop:
   - Call `manager.get_online_peers(global_presence_topic()).await`
   - Read cache
   - For each new PeerId not in previous set → emit `AgentOnline` if resolved to AgentId
   - For each PeerId in previous set but not current → emit `AgentOffline` if resolved
   - Update previous set
3. Store handle in `beacon_handle` (extend `beacon_handle` to hold two handles, or add
   separate `event_handle: Mutex<Option<JoinHandle<()>>>` field)

Add `event_handle: tokio::sync::Mutex<Option<JoinHandle<()>>>` field to `PresenceWrapper`.
Update `shutdown()` to also abort the event handle.

**Estimated Lines**: ~90

---

### Task 4: Add `subscribe_presence()` to Agent

**Files**: `src/lib.rs`

**Description**:
Add the `subscribe_presence()` method to the `Agent` impl block.

```rust
/// Subscribe to presence events (agent online/offline notifications).
///
/// Returns a [`broadcast::Receiver<PresenceEvent>`] that yields events
/// as agents join and leave the network.
///
/// The event loop is started lazily on the first call to this method.
/// Subsequent calls return independent receivers on the same channel.
///
/// # Errors
///
/// Returns [`NetworkError::NotInitialized`] if this agent was built
/// without a network configuration.
pub async fn subscribe_presence(
    &self,
) -> error::NetworkResult<tokio::sync::broadcast::Receiver<presence::PresenceEvent>>
```

Logic:
1. Get `self.presence.as_ref()` — return error if None
2. Start the event loop if not already started (use a flag or check handle existence)
3. Return `presence_wrapper.subscribe_events()`

Add `presence_event_loop_started: std::sync::atomic::AtomicBool` field to Agent struct
OR check `beacon_handle` state. Use `AtomicBool` with `Ordering::SeqCst` for simplicity.

**Estimated Lines**: ~40

---

### Task 5: Add `discover_agents_foaf(ttl)` to Agent

**Files**: `src/lib.rs`

**Description**:
Add FOAF discovery method to Agent.

```rust
/// Discover agents via Friend-of-a-Friend (FOAF) random walk.
///
/// Initiates a FOAF query on the global presence topic with the given TTL,
/// waiting up to `timeout_ms` milliseconds for responses.
///
/// Uses the identity discovery cache to resolve presence PeerIds to AgentIds.
/// Falls back to creating minimal DiscoveredAgent entries for unknown PeerIds.
///
/// # Arguments
///
/// * `ttl` - Maximum hop count for the random walk (1–5). Default: 2.
/// * `timeout_ms` - Query timeout in milliseconds. Default: 5000.
///
/// # Errors
///
/// Returns [`NetworkError::NotInitialized`] if no network config was provided.
pub async fn discover_agents_foaf(
    &self,
    ttl: u8,
    timeout_ms: u64,
) -> error::NetworkResult<Vec<DiscoveredAgent>>
```

Logic:
1. Get presence wrapper — error if None
2. Call `presence_wrapper.manager().initiate_foaf_query(global_presence_topic(), ttl, timeout_ms).await`
3. Lock identity_discovery_cache read
4. For each `(peer_id, record)` in results:
   - Call `presence::presence_record_to_discovered_agent(peer_id, &record, &*cache)`
   - Collect non-None results
5. Return deduplicated Vec (by agent_id)

**Estimated Lines**: ~45

---

### Task 6: Add `discover_agent_by_id(agent_id, ttl)` to Agent

**Files**: `src/lib.rs`

**Description**:
Add targeted FOAF discovery by AgentId.

```rust
/// Discover a specific agent by their AgentId via FOAF random walk.
///
/// Performs a FOAF query, then searches the results for a matching AgentId.
/// Also checks the identity_discovery_cache first (fast path).
///
/// Returns `None` if the agent is not found within the TTL and timeout.
///
/// # Errors
///
/// Returns [`NetworkError::NotInitialized`] if no network config was provided.
pub async fn discover_agent_by_id(
    &self,
    target_id: identity::AgentId,
    ttl: u8,
    timeout_ms: u64,
) -> error::NetworkResult<Option<DiscoveredAgent>>
```

Logic:
1. Fast path: check identity_discovery_cache — return Some if found
2. Perform FOAF discovery: `self.discover_agents_foaf(ttl, timeout_ms).await?`
3. Find the agent with matching agent_id
4. Return first match or None

**Estimated Lines**: ~35

---

### Task 7: Wire event loop start into join_network()

**Files**: `src/lib.rs`

**Description**:
After `join_network()` completes its bootstrap and starts beacons, also start the
presence event loop so that subscribers receive events automatically.

In `Agent::join_network()` (near line 1828 where beacons are started):

1. After starting presence beacons, also call:
   ```rust
   presence_wrapper.start_event_loop(Arc::clone(&self.identity_discovery_cache)).await;
   ```
2. Store the returned handle in `presence_wrapper.event_handle`

Also add a doc comment to `join_network()` mentioning that presence events become
available after this call.

**Estimated Lines**: ~15

---

## Summary

| Task | File(s) | Lines | Status |
|------|---------|-------|--------|
| 1 | presence.rs | ~40 | TODO |
| 2 | presence.rs | ~60 | TODO |
| 3 | presence.rs | ~90 | TODO |
| 4 | lib.rs | ~40 | TODO |
| 5 | lib.rs | ~45 | TODO |
| 6 | lib.rs | ~35 | TODO |
| 7 | lib.rs | ~15 | TODO |

**Total Tasks**: 7
**Total Estimated Lines**: ~325
