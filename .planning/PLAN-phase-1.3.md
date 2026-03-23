# Phase 1.3 Plan: Enhanced Announcements

## Overview

Add NAT type, relay capability, and coordination fields to
`IdentityAnnouncement` and `DiscoveredAgent`. Query `NodeStatus` in the
heartbeat to populate them. This gives receivers rich reachability
information without any external signalling server.

## Files

- `src/lib.rs` — extend `IdentityAnnouncement`, `IdentityAnnouncementUnsigned`,
  `DiscoveredAgent`, heartbeat, listener, and discovery accessors
- `src/network.rs` — add `node_status()` method to `NetworkNode`

---

## Tasks

### Task 1: Add node_status() to NetworkNode

**Files**: `src/network.rs`

Add a method that returns `Option<ant_quic::NodeStatus>`:

```rust
pub async fn node_status(&self) -> Option<ant_quic::NodeStatus> {
    let node = self.node.read().await;
    let node = node.as_ref()?;
    Some(node.status().await)
}
```

**Estimated Lines**: ~10

---

### Task 2: Extend IdentityAnnouncement with NAT/relay/coord fields

**Files**: `src/lib.rs`

Add to both `IdentityAnnouncementUnsigned` and `IdentityAnnouncement`:

```rust
#[serde(default)]
pub nat_type: String,
#[serde(default)]
pub can_receive_direct: bool,
#[serde(default)]
pub is_relay: bool,
#[serde(default)]
pub is_coordinator: bool,
```

Use `#[serde(default)]` so old announcements without these fields still
deserialise correctly (backward-compatible).

**Estimated Lines**: ~30

---

### Task 3: Extend DiscoveredAgent with same fields

**Files**: `src/lib.rs`

Add to `DiscoveredAgent`:

```rust
pub nat_type: String,
pub can_receive_direct: bool,
pub is_relay: bool,
pub is_coordinator: bool,
```

**Estimated Lines**: ~15

---

### Task 4: Populate fields in heartbeat from NodeStatus

**Files**: `src/lib.rs`

In `HeartbeatContext::announce()`, after querying addresses, call
`network.node_status()` and populate the new fields in
`IdentityAnnouncementUnsigned`.

**Estimated Lines**: ~25

---

### Task 5: Copy fields in identity listener to DiscoveredAgent

**Files**: `src/lib.rs`

In the identity listener's `cache.write().await.insert(...)` block,
copy the new fields from `IdentityAnnouncement` to `DiscoveredAgent`.

**Estimated Lines**: ~8

---

### Task 6: Tests and forward/backward compatibility

**Files**: `src/lib.rs`

Add unit tests verifying:
- An `IdentityAnnouncementUnsigned` without NAT fields still deserialises
- An announcement with all fields round-trips through bincode

**Estimated Lines**: ~40

---

## Summary

| Task | File(s) | Lines | Status |
|------|---------|-------|--------|
| 1 | network.rs | ~10 | TODO |
| 2 | lib.rs | ~30 | TODO |
| 3 | lib.rs | ~15 | TODO |
| 4 | lib.rs | ~25 | TODO |
| 5 | lib.rs | ~8 | TODO |
| 6 | lib.rs | ~40 | TODO |

**Total Estimated Lines**: ~128
