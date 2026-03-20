# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

### Self-Update System (`upgrade/`)

Manifest-based decentralized self-update with symmetric gossip propagation:

- **`manifest.rs`**: `ReleaseManifest` and `PlatformAsset` types, length-prefixed wire format (`[4-byte BE len][JSON][ML-DSA-65 sig]`), platform target detection (including musl vs glibc)
- **`signature.rs`**: ML-DSA-65 signing/verification for archives and manifests. Embedded release public key.
- **`monitor.rs`**: `UpgradeMonitor` polls GitHub releases, `fetch_verified_manifest()` downloads and verifies manifest+signature, returns `VerifiedRelease` with pre-encoded gossip payload
- **`apply.rs`**: `apply_upgrade_from_manifest()` — downloads archive, verifies SHA-256 hash, extracts binary, performs atomic replacement with rollback
- **`rollout.rs`**: Staged rollout with deterministic delay based on machine ID hash (configurable window)

**Update flow** (identical for x0xd and x0x-bootstrap):
1. **Startup**: Check GitHub for new release, broadcast manifest to gossip if found
2. **Gossip listener**: Receive manifests on `x0x/releases` topic, verify signature, rebroadcast, apply if newer
3. **GitHub poller**: Periodic fallback poll, broadcast discovered manifests to gossip

All nodes verify and rebroadcast manifests (symmetric propagation — no privileged bootstrap role).

**CI**: `release.yml` generates `release-manifest.json` and `release-manifest.json.sig` via `x0x-keygen manifest` during the release signing job.

### Module Dependency Flow

```
lib.rs (Agent, AgentBuilder, TaskListHandle)
  ├── identity.rs  ← Uses ant-quic ML-DSA-65 keypairs
  ├── storage.rs   ← Bincode serialization to ~/.x0x/
  ├── error.rs     ← IdentityError + NetworkError (thiserror)
  ├── network.rs   ← Wraps ant-quic Node, implements GossipTransport
  ├── bootstrap.rs ← Bootstrap retry logic
  ├── gossip/      ← Wraps saorsa-gossip-* crates
  ├── crdt/        ← TaskList, TaskItem, CheckboxState, Delta, Sync
  ├── mls/         ← MlsGroup, MlsCipher, MlsKeySchedule, MlsWelcome
  └── upgrade/     ← Self-update: manifest, monitor, apply, rollout, signature
```

### Key API Surface

```rust
// Create agent (auto-generates keys, connects to bootstrap)
let agent = Agent::builder()
    .with_machine_key("/custom/path")     // optional
    .with_agent_key(imported_keypair)      // optional
    .with_user_key_path("~/.x0x/user.key") // optional, opt-in
    .build().await?;

agent.join_network().await?;              // Connect to 6 bootstrap nodes
let rx = agent.subscribe("topic").await?; // Gossip pub/sub
agent.publish("topic", payload).await?;

// Identity accessors
agent.machine_id()       // MachineId
agent.agent_id()         // AgentId
agent.user_id()          // Option<UserId>
agent.agent_certificate() // Option<&AgentCertificate>
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

12 integration test files in `tests/`:

| File | Tests |
|------|-------|
| `identity_integration.rs` | Three-layer identity, keypair management, certificates |
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
| `rendezvous_integration.rs` | Rendezvous services |

Test pattern: `TempDir` for key isolation, `#[tokio::test]` for async, `tempfile` crate for temp directories.

## Incomplete APIs

`Agent::create_task_list()` and `Agent::join_task_list()` return "not yet implemented" errors. The underlying CRDT types are fully implemented — only the `TaskListHandle` bridge to `GossipRuntime` is pending.

## Crate-Level Lint Suppressions

`lib.rs` has `#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]`. These exist because test code uses unwrap/expect. Production code paths should still avoid panics — use `?` with proper error types.
