# Architecture Decision Required: Phase 1.6 Task 2 Blocked

**Date**: 2026-02-07
**Status**: BLOCKED - Awaiting Decision
**Context**: Phase 1.6 Task 2 (Wire Up Pub/Sub)

---

## Problem Discovery

During Task 2 implementation, the dev-agent discovered that **all saorsa-gossip-* crates are placeholder implementations only**:

```rust
// saorsa-gossip-pubsub-0.1.0/src/lib.rs
pub struct PubSubProtocol;

// saorsa-gossip-membership-0.1.0/src/lib.rs
pub struct MembershipProtocol;

// saorsa-gossip-runtime-0.1.0/src/lib.rs
pub struct GossipRuntime;
```

The crates exist on crates.io at version 0.1.0 but contain no actual functionality.

---

## Impact Assessment

**What This Means:**
- Phase 1.6 plan assumed saorsa-gossip was functional
- Tasks 2-12 all depend on saorsa-gossip components
- Cannot wire up pub/sub, membership, presence, etc. as planned

**What Still Works:**
- Task 1 ✅ - `GossipTransport` trait implementation complete
- `NetworkNode` provides full QUIC transport with NAT traversal
- ant-quic foundation is solid
- Agent identity and network connectivity work

---

## Decision Options

### Option A: Implement x0x Pub/Sub Directly

**Approach**: Build minimal pub/sub on top of `GossipTransport` trait

**Implementation**:
```rust
// src/gossip/pubsub.rs
pub struct PubSubManager {
    network: Arc<NetworkNode>,
    subscriptions: Arc<RwLock<HashMap<Topic, Vec<Sender>>>>,
}

impl PubSubManager {
    pub async fn subscribe(&self, topic: Topic) -> Subscription {
        // Add to local subscriber list
        // Return channel receiver
    }

    pub async fn publish(&self, topic: Topic, data: Vec<u8>) {
        // For each connected peer:
        //   self.network.send_message(peer, topic, data)
        // Trigger local subscribers
    }
}
```

**Pros:**
- Unblocks development immediately
- Full control over implementation
- Can optimize for x0x use case
- Simple epidemic broadcast is straightforward

**Cons:**
- Duplicates effort if saorsa-gossip becomes functional
- May miss optimizations from dedicated gossip library
- Need to implement our own membership, anti-entropy, etc.

**Estimated Effort**: 2-3 tasks to implement basic pub/sub

---

### Option B: Implement Saorsa-Gossip Components

**Approach**: Build out the saorsa-gossip crates ourselves

**Implementation**:
- Fork or contribute to `../saorsa-gossip` repository
- Implement HyParView membership protocol
- Implement Plumtree pub/sub protocol
- Publish working versions to crates.io

**Pros:**
- Creates reusable gossip library
- Proper protocol implementations (HyParView, Plumtree)
- Can be used by other projects
- Aligns with original architecture vision

**Cons:**
- Significant additional scope (weeks of work)
- Blocks x0x progress on saorsa-gossip completion
- More complex than needed for x0x MVP

**Estimated Effort**: 4-6 weeks for full saorsa-gossip implementation

---

### Option C: Hybrid Approach

**Approach**: Minimal x0x pub/sub now, migrate to saorsa-gossip later

**Implementation**:
1. Implement simple x0x pub/sub (Option A)
2. Mark as "Phase 1.6 MVP" with TODO comments
3. Create "Phase 1.7: Migrate to Saorsa-Gossip" for future
4. Abstract pub/sub behind trait for easy swap later

**Pros:**
- Unblocks development immediately
- Leaves door open for future upgrade
- Allows testing/validation of x0x concepts
- Can ship working product while saorsa-gossip develops

**Cons:**
- Some rework when migrating to saorsa-gossip
- Temporary code that may persist longer than intended

**Estimated Effort**: 2-3 tasks now, 3-4 tasks later for migration

---

## Recommendation

**Option C: Hybrid Approach** is recommended:

1. **Immediate Action** (Phase 1.6 revised):
   - Implement minimal x0x pub/sub directly
   - Simple topic routing with `HashMap<Topic, Vec<Subscriber>>`
   - Epidemic broadcast via `NetworkNode.send_message()`
   - Get Agent.subscribe()/publish() working

2. **Future Migration** (Phase 1.7):
   - Implement saorsa-gossip components properly
   - Migrate x0x to use saorsa-gossip
   - Maintain backward compatibility

**Rationale:**
- Aligns with "get stuff done" philosophy
- Unblocks CRDT task list testing (depends on pub/sub)
- Allows validation of x0x architecture
- Provides working product for testing/feedback
- Saorsa-gossip can be developed properly without blocking x0x

---

## Required Decision

**Question**: Which option should we pursue?

- [ ] **Option A**: x0x pub/sub only (no saorsa-gossip)
- [ ] **Option B**: Implement saorsa-gossip first (blocks x0x)
- [ ] **Option C**: Hybrid - x0x pub/sub now, saorsa-gossip later
- [ ] **Option D**: Other approach (specify)

---

## Next Steps (Pending Decision)

**If Option A or C selected:**
1. Revise Phase 1.6 plan to use x0x pub/sub
2. Create `src/gossip/pubsub.rs` with minimal implementation
3. Update Task 2 to wire up x0x pub/sub
4. Continue with Tasks 3-12 using x0x components

**If Option B selected:**
1. Pause x0x development
2. Switch to saorsa-gossip repository
3. Implement HyParView, Plumtree, etc.
4. Publish saorsa-gossip 0.2.0
5. Return to x0x Phase 1.6

---

## References

- Phase 1.6 Plan: `.planning/PLAN-phase-1.6-gossip-integration.md`
- Task 1 Implementation: commit `5a02bca` - GossipTransport trait
- saorsa-gossip crates: `~/.cargo/registry/src/*/saorsa-gossip-*/`
- saorsa-gossip repo: `../saorsa-gossip/`
