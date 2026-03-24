# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What is x0x

Agent-to-agent gossip network for AI systems. Built on `ant-quic` (QUIC transport with post-quantum cryptography and NAT traversal) and `saorsa-gossip` (epidemic broadcast, CRDT sync, pub/sub). Distributed as a Rust crate, npm package (napi-rs), and Python package (`agent-x0x` on PyPI, imported as `from x0x import ...`).

## Build & Test Commands

No justfile exists yet. Use raw cargo commands:

```bash
cargo fmt --all -- --check          # Format check
cargo clippy --all-targets --all-features -- -D warnings  # Lint (zero warnings)
cargo nextest run --all-features --workspace              # Run all tests
cargo nextest run --all-features -E 'test(identity)'      # Run tests matching "identity"
cargo nextest run --all-features --test identity_integration  # Run a specific integration test file
cargo doc --all-features --no-deps  # Build docs (CI uses RUSTDOCFLAGS="-D warnings")
cargo build --all-features          # Build library + x0x-bootstrap binary
```

Cross-compile for Linux (VPS deployment):
```bash
cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin x0x-bootstrap
```

## Local Dependency Setup

`ant-quic` and `saorsa-gossip` are expected as **sibling directories** (path dependencies via `../ant-quic` and `../saorsa-gossip`). CI creates these via symlinks from `.deps/`. Locally, clone them as siblings:

```
projects/
  ant-quic/          # QUIC transport, ML-KEM-768/ML-DSA-65
  saorsa-gossip/     # 11 crates: coordinator, crdt-sync, membership, etc.
  x0x/               # This repo
```

## Architecture

### Three-Layer Identity Model

```
User (optional, human) ──signs──> AgentCertificate
  └─ Agent (portable)             binds agent to user
       └─ Machine (hardware-pinned)
```

- **MachineId/MachineKeypair**: Derived from ML-DSA-65, stored in `~/.x0x/machine.key`. Used for QUIC transport authentication. Auto-generated.
- **AgentId/AgentKeypair**: Portable across machines, stored in `~/.x0x/agent.key`. Can be imported to run the same agent on different hardware. Auto-generated.
- **UserId/UserKeypair**: Optional human identity, stored in `~/.x0x/user.key`. **Never auto-generated** — opt-in only. When present, issues an `AgentCertificate` binding agent to user.

All IDs are SHA-256 hashes of ML-DSA-65 public keys (32 bytes).

### Network Stack (bottom to top)

1. **Transport** (`network.rs`): Wraps `ant-quic::Node`. Implements `saorsa_gossip_transport::GossipTransport` trait. Handles PeerId conversion between ant-quic and gossip type systems.
2. **Bootstrap** (`bootstrap.rs`): 6 hardcoded global nodes (port 12000). 3-round retry with exponential backoff (0s, 10s, 15s). Nodes are in `network.rs::DEFAULT_BOOTSTRAP_PEERS`.
3. **Gossip** (`gossip/`): Thin orchestration over `saorsa-gossip-*` crates. `GossipRuntime` owns `PubSubManager` which provides topic-based pub/sub via epidemic broadcast.
4. **CRDT** (`crdt/`): Collaborative task lists with OR-Set checkboxes (Empty/Claimed/Done), LWW-Register metadata, RGA ordering. Deltas can be encrypted via MLS groups.
5. **MLS** (`mls/`): Group encryption using ChaCha20-Poly1305. `MlsGroup` manages membership, `MlsKeySchedule` derives epoch keys, `MlsWelcome` onboards new members.

### Trust Model

Each agent has a `ContactStore` that maps `AgentId` to `Contact`:
- `TrustLevel`: `Blocked | Unknown | Known | Trusted`
- `IdentityType`: `Anonymous | Known | Trusted | Pinned`
- `machines: Vec<MachineRecord>` — tracks which machine IDs this agent has been seen on

`TrustEvaluator::evaluate(&(agent_id, machine_id), &store)` → `TrustDecision`:
- `RejectBlocked` — agent is blocked
- `RejectMachineMismatch` — agent is pinned and this machine is not in the list
- `Accept` — trusted or pinned to the right machine
- `AcceptWithFlag` — known but not pinned
- `Unknown` — not in store

The identity listener applies trust evaluation to all incoming announcements.

### Connectivity

`ReachabilityInfo::from_discovered(&agent)` summarises NAT traversal options:
- `likely_direct()`: safe to try a direct connection
- `needs_coordination()`: NAT traversal coordination required

`Agent::connect_to_agent(&agent_id).await` → `ConnectOutcome`:
- `Direct(addr)` — connected directly
- `Coordinated(addr)` — connected via NAT traversal
- `Unreachable` — no path found
- `NotFound` — agent not in discovery cache

### Direct Messaging

Point-to-point communication between connected agents, bypassing gossip:

```rust
// Connect to an agent
let outcome = agent.connect_to_agent(&target_agent_id).await?;

// Send data directly
agent.send_direct(&target_agent_id, b"hello".to_vec()).await?;

// Receive direct messages
if let Some(msg) = agent.recv_direct().await {
    println!("From {:?}: {:?}", msg.sender, msg.payload_str());
}

// Or subscribe for concurrent processing
let mut rx = agent.subscribe_direct();
while let Some(msg) = rx.recv().await {
    // Process message
}

// Check connection state
agent.is_agent_connected(&agent_id).await  // bool
agent.connected_agents().await             // Vec<AgentId>
```

Wire format: `[0x10][sender_agent_id: 32 bytes][payload]`
Max payload: 16 MB (`direct::MAX_DIRECT_PAYLOAD_SIZE`)

### Module Dependency Flow

```
lib.rs (Agent, AgentBuilder, TaskListHandle)
  ├── identity.rs    ← Uses ant-quic ML-DSA-65 keypairs
  ├── storage.rs     ← Bincode serialization to ~/.x0x/
  ├── error.rs       ← IdentityError + NetworkError (thiserror)
  ├── network.rs     ← Wraps ant-quic Node, implements GossipTransport
  ├── bootstrap.rs   ← Bootstrap retry logic
  ├── contacts.rs    ← ContactStore: TrustLevel, IdentityType, MachineRecord
  ├── trust.rs       ← TrustEvaluator: (AgentId, MachineId) → TrustDecision
  ├── connectivity.rs ← ReachabilityInfo, ConnectOutcome
  ├── direct.rs      ← DirectMessage, DirectMessaging, DirectMessageReceiver
  ├── gossip/        ← Wraps saorsa-gossip-* crates
  ├── crdt/          ← TaskList, TaskItem, CheckboxState, Delta, Sync
  └── mls/           ← MlsGroup, MlsCipher, MlsKeySchedule, MlsWelcome
```

### Key API Surface

```rust
// Create agent (auto-generates keys, connects to bootstrap)
let agent = Agent::builder()
    .with_machine_key("/custom/path")       // optional
    .with_agent_key(imported_keypair)       // optional
    .with_user_key_path("~/.x0x/user.key") // optional, opt-in
    .build().await?;

agent.join_network().await?;              // Connect to 6 bootstrap nodes
let rx = agent.subscribe("topic").await?; // Gossip pub/sub
agent.publish("topic", payload).await?;

// Identity accessors
agent.machine_id()        // MachineId (== ant-quic PeerId)
agent.agent_id()          // AgentId
agent.user_id()           // Option<UserId>
agent.agent_certificate() // Option<&AgentCertificate>

// Discovery
agent.discovered_agents().await?          // Vec<DiscoveredAgent> (TTL-filtered)

// Direct messaging (point-to-point, bypasses gossip)
agent.connect_to_agent(&agent_id).await?  // ConnectOutcome
agent.send_direct(&agent_id, payload).await?
agent.recv_direct().await                 // Option<DirectMessage>
agent.subscribe_direct()                  // DirectMessageReceiver
agent.is_agent_connected(&agent_id).await // bool
agent.connected_agents().await            // Vec<AgentId>
agent.reachability(&agent_id).await       // Option<ReachabilityInfo>

// Connectivity
agent.connect_to_agent(&agent_id).await?  // ConnectOutcome

// Trust
let store = agent.contacts().read().await;
store.set_trust(&agent_id, TrustLevel::Trusted);
store.pin_machine(&agent_id, &machine_id);
```

### Error Handling

Two error enums in `error.rs`:
- `IdentityError`: Key generation, validation, storage, serialization, certificate verification
- `NetworkError`: Node creation, connections, NAT traversal, protocol violations, resource limits

Type aliases: `error::Result<T>` for identity, `error::NetworkResult<T>` for network.

### Storage Format

Keypairs are serialized with **bincode** (compact binary), not JSON. Manual serialization via `storage.rs` with explicit `public_key`/`secret_key` fields. Default path: `~/.x0x/`.

## Binary: x0x-bootstrap

`src/bin/x0x-bootstrap.rs` — the bootstrap node binary deployed to 6 VPS nodes. Runs as coordinator/reflector/relay for NAT traversal. Config via `--config /etc/x0x/bootstrap.toml`. Health/metrics on `127.0.0.1:12600`. Machine key persisted in `/var/lib/x0x/machine.key`.

Node deployment configs are in `.deployment/*.toml` (one per region).

## FFI Bindings

- **Node.js** (`bindings/nodejs/`): napi-rs v3 with 7 platform packages + WASM fallback. Published as `x0x` on npm.
- **Python** (`bindings/python/`): PyO3 + maturin. Published as `agent-x0x` on PyPI (name `x0x` was taken). Import as `from x0x import ...`.

## CI/CD

Six workflows in `.github/workflows/`:
- **ci.yml**: fmt, clippy, nextest, doc (all jobs symlink `ant-quic` and `saorsa-gossip` from `.deps/`)
- **security.yml**: `cargo audit`
- **release.yml**: Multi-platform builds (7 targets), macOS code signing, publishes to crates.io/npm/PyPI
- **build-bootstrap.yml**: Builds `x0x-bootstrap` for Linux
- **build.yml**: PR validation
- **sign-skill.yml**: GPG-signs `SKILL.md`

## Test Organization

17 integration test files in `tests/`:

| File | Tests |
|------|-------|
| `identity_integration.rs` | Three-layer identity, keypair management, certificates |
| `identity_unification_test.rs` | machine_id == ant-quic PeerId, key derivation |
| `trust_evaluation_test.rs` | TrustEvaluator decisions, machine pinning, ContactStore |
| `announcement_test.rs` | Announcement round-trips, NAT fields, discovery cache |
| `connectivity_test.rs` | ReachabilityInfo heuristics, ConnectOutcome, connect_to_agent |
| `identity_announcement_integration.rs` | Signature verification, TTL expiry, shard topics |
| `direct_messaging_integration.rs` | DirectMessage, send_direct, recv_direct, connection tracking |
| `crdt_integration.rs` | TaskList CRUD, state transitions |
| `crdt_convergence_concurrent.rs` | Concurrent CRDT operations converging |
| `crdt_partition_tolerance.rs` | Network partition and recovery |
| `mls_integration.rs` | Group encryption, key rotation |
| `network_integration.rs` | Bootstrap connection |
| `network_timeout.rs` | Connection timeouts |
| `nat_traversal_integration.rs` | NAT hole-punching |
| `comprehensive_integration.rs` | End-to-end workflows |
| `scale_testing.rs` | Performance with many agents |
| `presence_foaf_integration.rs` | Presence and friend-of-a-friend discovery |

Test pattern: `TempDir` for key isolation, `#[tokio::test]` for async, `tempfile` crate for temp directories.

## Incomplete APIs

`Agent::create_task_list()` and `Agent::join_task_list()` return "not yet implemented" errors. The underlying CRDT types are fully implemented — only the `TaskListHandle` bridge to `GossipRuntime` is pending.

## Crate-Level Lint Suppressions

`lib.rs` has `#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]`. These exist because test code uses unwrap/expect. Production code paths should still avoid panics — use `?` with proper error types.
