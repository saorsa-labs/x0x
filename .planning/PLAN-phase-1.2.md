# Phase 1.2 Plan: Network Transport Integration

## Overview
Integrate ant-quic for QUIC transport and saorsa-gossip for overlay networking. This phase connects the identity system (Phase 1.1) to the network layer, enabling agents to discover peers and communicate via epidemic broadcast.

## Dependencies
- **ant-quic v0.21.2**: QUIC transport with NAT traversal, PQC key exchange
  - Location: `../ant-quic`
- **saorsa-gossip v0.1.0**: Gossip-based overlay networking
  - Location: `../saorsa-gossip`

## Tasks

### Task 1: Add Transport Dependencies
**Files**: `Cargo.toml`
**Status**: COMPLETE (per git commit d714f9f)

### Task 2: Define Network Config
**Files**: `src/network/config.rs`
**Status**: COMPLETE (per git commit d714f9f)

### Task 3: Define Peer struct
**Files**: `src/network/peer.rs`
**Status**: COMPLETE (per git commit d714f9f)

### Task 4: Implement Network struct
**Files**: `src/network/mod.rs`

**Description**: Create the Network struct that wraps ant-quic Node and saorsa-gossip Gossip.

**Implementation**:
```rust
use ant_quic::{Node, NodeConfig};
use saorsa_gossip::{Gossip, GossipConfig};

pub struct Network {
    node: Node,
    gossip: Gossip,
    config: NetworkConfig,
}

impl Network {
    pub async fn new(
        config: NetworkConfig,
        machine_keypair: &MachineKeypair,
    ) -> Result<Self, NetworkError> {
        let node_config = NodeConfig::new()
            .with_listen_addr(config.listen_addr)
            .with_nat_traversal(config.nat_traversal);

        let node = Node::new(node_config, machine_keypair).await?;

        let gossip_config = GossipConfig::default()
            .with_max_peers(config.max_peers);

        let gossip = Gossip::new(gossip_config).await?;

        Ok(Self { node, gossip, config })
    }

    pub async fn start(&mut self) -> Result<(), NetworkError> {
        self.node.start().await?;
        self.gossip.start().await?;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), NetworkError> {
        self.gossip.stop().await?;
        self.node.stop().await?;
        Ok(())
    }
}
```

**Acceptance Criteria**:
- Wraps ant-quic Node and saorsa-gossip Gossip
- Async API with proper error handling
- Start/stop lifecycle management

**Estimated Lines**: ~80

### Task 5: Implement Peer Connection Management
**Files**: `src/network/mod.rs`

**Description**: Add methods for connecting to peers and managing peer state.

**Acceptance Criteria**:
- Connect/disconnect methods work
- Peer list maintained correctly

**Estimated Lines**: ~50

### Task 6: Implement Message Passing
**Files**: `src/network/message.rs`

**Description**: Define message types and implement send/receive functionality.

**Acceptance Criteria**:
- Message type is serializable
- Proper ordering and timestamping

**Estimated Lines**: ~50

### Task 7: Integrate Network with Agent
**Files**: `src/lib.rs`

**Description**: Update Agent struct to include Network and implement join_network(), subscribe(), publish().

**Acceptance Criteria**:
- Agent wraps Network
- join_network() starts gossip
- publish() broadcasts to topic

**Estimated Lines**: ~60

### Task 8: Add Bootstrap Support
**Files**: `src/network/bootstrap.rs`

**Description**: Implement bootstrap node discovery and connection.

**Estimated Lines**: ~40

### Task 9: Write Network Tests
**Files**: `src/network/mod.rs`

**Acceptance Criteria**:
- All tests pass with `cargo nextest run`

**Estimated Lines**: ~80

### Task 10: Integration Test - Agent Network Lifecycle
**Files**: `tests/network_integration.rs`

**Description**: Test complete agent lifecycle with network operations.

**Estimated Lines**: ~80

### Task 11: Documentation Pass
**Files**: `src/network/*.rs`, `README.md`

**Acceptance Criteria**:
- `cargo doc --no-deps` builds with zero warnings

**Estimated Lines**: ~30

---

## Summary

**Total Tasks**: 11
**Current Task**: 4
**Completed Tasks**: 1-3 (per git commit d714f9f)
