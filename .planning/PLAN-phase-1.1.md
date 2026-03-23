# Phase 1.1: Identity Unification

## Goal
Pass the machine ML-DSA-65 keypair to ant-quic's NodeConfig so that machine_id == ant-quic PeerId. Remove the redundant transport_peer_id field.

## Tasks

### Task 1: Accept keypair in NetworkNode::new()
Add an optional `keypair: Option<(MlDsaPublicKey, MlDsaSecretKey)>` parameter to `NetworkNode::new()` in `src/network.rs`. When provided, call `builder.keypair(pk, sk)` on the NodeConfig builder before creating the Node.

**Files**: `src/network.rs` (modify NetworkNode::new signature and body ~line 206-222)
**Test**: Unit test that creates a NetworkNode with a keypair and verifies peer_id matches.

### Task 2: Wire machine keypair through AgentBuilder
In `src/lib.rs` AgentBuilder::build(), extract the machine keypair's public/secret key bytes, reconstruct as ant-quic MlDsaPublicKey/MlDsaSecretKey, and pass them to NetworkNode::new().

**Files**: `src/lib.rs` (modify AgentBuilder::build ~line 2052, where NetworkNode::new is called)
**Verify**: `debug_assert_eq!(network.peer_id().0, identity.machine_id().0)`

### Task 3: Update all other NetworkNode::new() call sites
Search for all callers of NetworkNode::new() in src/bin/*.rs, tests, and gossip modules. Add the `None` keypair parameter to each.

**Files**: `src/bin/x0x-bootstrap.rs`, `src/bin/x0xd.rs`, `src/network.rs` (tests), `src/gossip/runtime.rs` (tests), `src/gossip/pubsub.rs` (tests)

### Task 4: Remove transport_peer_id field
Delete `transport_peer_id` from IdentityAnnouncementUnsigned, IdentityAnnouncement, to_unsigned(), verify(), and HeartbeatContext::announce(). Update start_identity_listener() to use machine_id.0 instead of transport_peer_id for bootstrap cache enrichment.

**Files**: `src/lib.rs` (lines 208-212, 237-239, 243-253, 407-496, 827-840)

### Task 5: Full validation
Run cargo check, cargo clippy, cargo nextest run. Fix any issues. Ensure all 431+ tests pass.

**Files**: all
