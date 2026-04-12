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
cargo build --all-features          # Build library + x0xd + x0x binaries
```

Cross-compile for Linux (VPS deployment):
```bash
cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin x0xd
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
2. **Connectivity & Discovery** (`network.rs` + ant-quic): ant-quic owns first-party mDNS LAN discovery, additive UPnP port mapping, bootstrap cache management, and unified outbound connection orchestration. x0x consumes those capabilities through `ant_quic::Node` instead of running a separate application-layer mDNS runtime.
3. **Bootstrap** (`bootstrap.rs`): 6 hardcoded global nodes (port 5483). 3-round retry with exponential backoff (0s, 10s, 15s). Nodes are in `network.rs::DEFAULT_BOOTSTRAP_PEERS`.
4. **Gossip** (`gossip/`): Thin orchestration over `saorsa-gossip-*` crates. `GossipRuntime` owns `PubSubManager` which provides topic-based pub/sub via epidemic broadcast.
5. **Presence** (`presence.rs`): SOTA presence system via `saorsa-gossip-presence`. Beacons propagate on `GossipStreamType::Bulk`. Phi-Accrual lite adaptive failure detection (180–600s), FOAF random-walk discovery with trust-scoped privacy (`PresenceVisibility::Network` vs `Social`), bootstrap cache enrichment from beacons, quality-weighted FOAF peer selection. Surpasses libp2p presence; matches Tailscale for NAT-aware discovery.
6. **CRDT** (`crdt/`): Collaborative task lists with OR-Set checkboxes (Empty/Claimed/Done), LWW-Register metadata, RGA ordering. Deltas can be encrypted via MLS groups.
7. **MLS** (`mls/`): Group encryption using ChaCha20-Poly1305. `MlsGroup` manages membership, `MlsKeySchedule` derives epoch keys, `MlsWelcome` onboards new members.
8. **Group Discovery** (`groups/`): DHT-free distributed discovery via three tiers: social propagation (agents share cards in conversation), tag shards (BLAKE3-hashed tags → 65,536 PlumTree topics with CRDT OR-Set anti-entropy), and presence-social browsing (groups nearby agents are in). Path caching on relay nodes provides hot-shard mitigation. Fully partition-tolerant — each network fragment maintains complete shard state independently, merges automatically on reconnection. See `docs/design/named-groups-full-model.md`.

### Self-Update System (`upgrade/`)

Manifest-based decentralized self-update with symmetric gossip propagation:

- **`manifest.rs`**: `ReleaseManifest` and `PlatformAsset` types, length-prefixed wire format (`[4-byte BE len][JSON][ML-DSA-65 sig]`), platform target detection (including musl vs glibc)
- **`signature.rs`**: ML-DSA-65 signing/verification for archives and manifests. Embedded release public key.
- **`monitor.rs`**: `UpgradeMonitor` polls GitHub releases, `fetch_verified_manifest()` downloads and verifies manifest+signature, returns `VerifiedRelease` with pre-encoded gossip payload
- **`apply.rs`**: `apply_upgrade_from_manifest()` — downloads archive, verifies SHA-256 hash, extracts binary, performs atomic replacement with rollback
- **`rollout.rs`**: Staged rollout with deterministic delay based on machine ID hash (configurable window)

**Update flow** (for x0xd):
1. **Startup**: Check GitHub for new release, broadcast manifest to gossip if found
2. **Gossip listener**: Receive manifests on `x0x/releases` topic, verify signature, rebroadcast, apply if newer
3. **GitHub poller**: Periodic fallback poll, broadcast discovered manifests to gossip

All nodes verify and rebroadcast manifests (symmetric propagation — no privileged bootstrap role).

**CI**: `release.yml` generates `release-manifest.json` and `release-manifest.json.sig` via `x0x-keygen manifest` during the release signing job.

### Module Dependency Flow

```
lib.rs (Agent, AgentBuilder, TaskListHandle, KvStoreHandle)
  ├── identity.rs  ← Uses ant-quic ML-DSA-65 keypairs
  ├── storage.rs   ← Bincode serialization to ~/.x0x/
  ├── error.rs     ← IdentityError + NetworkError (thiserror)
  ├── network.rs   ← Wraps ant-quic Node, implements GossipTransport
  ├── bootstrap.rs ← Bootstrap retry logic
  ├── gossip/      ← Wraps saorsa-gossip-* crates
  ├── crdt/        ← TaskList, TaskItem, CheckboxState, Delta, Sync
  ├── kv/          ← KvStore, KvEntry, KvStoreDelta, KvStoreSync, AccessPolicy
  ├── groups/      ← GroupInfo, GroupPolicy, GroupMember, GroupCard, SignedInvite, AgentCard, discovery index
  ├── mls/         ← MlsGroup, MlsCipher, MlsKeySchedule, MlsWelcome
  ├── presence.rs  ← SOTA presence: beacons, FOAF, adaptive detection, trust privacy
  ├── upgrade/     ← Self-update: manifest, monitor, apply, rollout, signature
  └── gui/         ← Embedded HTML GUI (compiled into binary via include_str!)
```

### Key API Surface

```rust
// Create agent (auto-generates keys, seeds transport connectivity)
let agent = Agent::builder()
    .with_machine_key("/custom/path")     // optional
    .with_agent_key(imported_keypair)      // optional
    .with_user_key_path("~/.x0x/user.key") // optional, opt-in
    .build().await?;

agent.join_network().await?;              // ant-quic local discovery + bootstrap orchestration
let rx = agent.subscribe("topic").await?; // Gossip pub/sub
agent.publish("topic", payload).await?;

// Identity accessors
agent.machine_id()       // MachineId
agent.agent_id()         // AgentId
agent.user_id()          // Option<UserId>
agent.agent_certificate() // Option<&AgentCertificate>

// KvStore — replicated key-value with access control
let store = agent.create_kv_store("name", "topic").await?;
store.put("key".into(), b"value".to_vec(), "text/plain".into()).await?;
let entry = store.get("key").await?;
let keys = store.keys().await?;
store.remove("key").await?;

// Presence — SOTA discovery with FOAF and adaptive detection
let rx = agent.subscribe_presence().await?;       // AgentOnline/AgentOffline events
let agents = agent.discover_agents_foaf(2).await?; // FOAF walk, TTL=2
let found = agent.discover_agent_by_id(id, 3).await?; // Find specific agent
let cached = agent.cached_agent(&id).await?;       // Local cache lookup (no network)
let pw = agent.presence_system().unwrap();          // Access PresenceWrapper
let config = pw.config();                           // PresenceConfig

// Local discovery is handled by ant-quic transport connectivity by default.

// Named groups with invite links
// (managed via REST API: POST /groups, POST /groups/:id/invite, etc.)
```

### Error Handling

Three error enums in `error.rs`:
- `IdentityError`: Key generation, validation, storage, serialization, certificate verification
- `NetworkError`: Node creation, connections, NAT traversal, protocol violations, resource limits
- `PresenceError`: NotInitialized, BeaconFailed, FoafQueryFailed, SubscriptionFailed, Internal

Type aliases: `error::Result<T>` for identity, `error::NetworkResult<T>` for network, `error::PresenceResult<T>` for presence.

### Storage Format

Keypairs are serialized with **bincode** (compact binary), not JSON. Manual serialization via `storage.rs` with explicit `public_key`/`secret_key` fields. Default path: `~/.x0x/`.

## Binary: x0x (CLI)

`src/bin/x0x.rs` — unified CLI that controls a running `x0xd` daemon. Every REST endpoint is mapped to a CLI subcommand. Shared endpoint registry in `src/api/mod.rs` ensures routes and CLI commands stay in sync. CLI modules in `src/cli/`.

Key commands: `x0x start`, `x0x health`, `x0x agent`, `x0x contacts`, `x0x publish`, `x0x direct send`, `x0x groups`, `x0x tasks`, `x0x presence online|foaf|find|status`, `x0x routes` (prints all 75+ endpoints).

### x0xd Daemon Flags

```
x0xd [OPTIONS]
  --config <PATH>       Path to config file (TOML)
  --name <NAME>         Instance name for multi-instance support
  --api-port <PORT>               Override API server port (otherwise ephemeral for named instances)
  --no-hard-coded-bootstrap       Skip configured bootstrap peers
  --check                         Check configuration and exit
  --check-updates       Check for updates and exit
  --skip-update-check   Skip update check on startup
  --doctor              Run diagnostics
```

Multi-instance example: `x0xd --name alice --api-port 12701 --no-hard-coded-bootstrap`

## FFI Bindings

- **Node.js** (`bindings/nodejs/`): napi-rs v3 with 7 platform packages + WASM fallback. Published as `x0x` on npm.
- **Python** (`bindings/python/`): PyO3 + maturin. Published as `agent-x0x` on PyPI (name `x0x` was taken). Import as `from x0x import ...`.

## CI/CD

Five workflows in `.github/workflows/`:
- **ci.yml**: fmt, clippy, nextest, doc (all jobs symlink `ant-quic` and `saorsa-gossip` from `.deps/`)
- **security.yml**: `cargo audit`
- **release.yml**: Multi-platform builds (7 targets), macOS code signing, publishes to crates.io/npm/PyPI
- **build.yml**: PR validation
- **sign-skill.yml**: GPG-signs `SKILL.md`

## Trust Model (`contacts.rs`, `trust.rs`)

Each agent maintains a `ContactStore` of known peers with:

- `TrustLevel`: Blocked | Unknown | Known | Trusted
- `IdentityType`: Anonymous | Known | Trusted | Pinned
- `MachineRecord`: Tracks machine IDs an agent has been observed running on

`TrustEvaluator` evaluates `(AgentId, MachineId)` pairs against the store:
1. Blocked → `RejectBlocked`
2. `Pinned` identity type + wrong machine → `RejectMachineMismatch`
3. `Pinned` identity type + right machine → `Accept`
4. `TrustLevel::Trusted` → `Accept`
5. `TrustLevel::Known` → `AcceptWithFlag`
6. Not in store → `Unknown`

The identity listener applies trust evaluation to every incoming announcement. Blocked and machine-mismatched announcements are silently dropped.

## Connectivity (`connectivity.rs`)

`ReachabilityInfo` summarises how reachable a discovered agent is:
- `should_attempt_direct()`: true if we have at least one address AND `can_receive_direct` is not explicitly `false`. Unknown reachability still gets a direct probe.
- `needs_coordination()`: true if `can_receive_direct == Some(false)` (e.g. symmetric NAT)
- `likely_direct()`: true only when `can_receive_direct == Some(true)` — peer has verified direct inbound connectivity

`Agent::connect_to_agent(agent_id)` strategy:
1. Look up agent in discovery cache → `NotFound` if absent
2. No addresses → `Unreachable`
3. `should_attempt_direct()` → try `network.connect_addr()` for each address → `Direct(addr)` on success
4. `needs_coordination()` or direct failed → for each reachable coordinator peer: connect to coordinator, then use `network.connect_peer_via(peer_id, coordinator)` for peer-ID hole-punching (QUIC extension frames, PUNCH_ME_NOW) → `Coordinated(addr)` on success
5. All attempts failed → `Unreachable`

The coordination path uses explicit peer-ID-based NAT traversal via `connect_peer_via` (which calls `connect_to_peer(peer_id, Some(coordinator))`), not raw `connect_addr`. This triggers QUIC extension-frame hole-punching through the coordinator peer (typically a bootstrap node). MASQUE relay fallback is planned but not yet wired in ant-quic.

Successful connections enrich the bootstrap cache via `add_from_connection()`.

## Enhanced Announcements (`lib.rs`, `network.rs`)

`IdentityAnnouncement` and `DiscoveredAgent` carry four optional NAT fields:
- `nat_type: Option<String>` — e.g. "FullCone", "Symmetric", "None"
- `can_receive_direct: Option<bool>` — whether inbound connections are accepted
- `is_relay: Option<bool>` — whether the node is relaying for others
- `is_coordinator: Option<bool>` — whether the node is coordinating NAT punch timing

The sync `build_announcement()` leaves these as `None` (no network access). The async heartbeat queries `NetworkNode::node_status()` to populate them.

**Protocol note**: These fields use bincode 1.x serialization. Old→new messages will fail to decode because bincode 1.x treats every field as required. This is a deliberate protocol version bump.

## Test Organization

29 integration test files in `tests/` (744 tests total):

| File | Tests |
|------|-------|
| `identity_integration.rs` | Three-layer identity, keypair management, certificates |
| `identity_unification_test.rs` | machine_id == ant-quic PeerId, announcement key derivation |
| `trust_evaluation_test.rs` | TrustEvaluator decisions, machine pinning, ContactStore mutations |
| `announcement_test.rs` | Announcement round-trips, NAT fields, discovery cache, reachability |
| `connectivity_test.rs` | ReachabilityInfo heuristics, ConnectOutcome, connect_to_agent() |
| `identity_announcement_integration.rs` | Signature verification, TTL expiry, shard topics |
| `crdt_integration.rs` | TaskList CRUD, state transitions |
| `crdt_convergence_concurrent.rs` | Concurrent CRDT operations converging |
| `crdt_partition_tolerance.rs` | Network partition and recovery |
| `mls_integration.rs` | Group encryption, key rotation |
| `network_integration.rs` | Bootstrap connection |
| `network_timeout.rs` | Connection timeouts |
| `nat_traversal_integration.rs` | NAT hole-punching |
| `comprehensive_integration.rs` | End-to-end workflows |
| `scale_testing.rs` | Performance with many agents |
| `presence_foaf_integration.rs` | Presence beacons, FOAF discovery, trust-scoped visibility |
| `presence_wiring_test.rs` | PresenceWrapper lifecycle, config defaults, shutdown |
| `presence_integration.rs` | Presence API surface: subscribe, cached_agent, foaf_peer_candidates |
| `kv_store_integration.rs` | KV store CRUD, access policies, CRDT sync |
| `named_group_integration.rs` | Named groups, invites, join/leave, display names |
| `bootstrap_cache_integration.rs` | Bootstrap cache persistence, quality scoring |
| `constitution_integration.rs` | Constitution embedding and serving |
| `daemon_api_integration.rs` | Daemon REST API endpoint coverage |
| `direct_messaging_integration.rs` | Direct send/receive, connection lifecycle |
| `file_transfer_integration.rs` | File send, accept, reject, progress |
| `gossip_cache_adapter_integration.rs` | Gossip cache adapter wrapping bootstrap cache |
| `rendezvous_integration.rs` | Rendezvous shard discovery |
| `upgrade_integration.rs` | Self-update manifest signing, verification, rollout |
| `vps_e2e_integration.rs` | VPS bootstrap node end-to-end |

Test pattern: `TempDir` for key isolation, `#[tokio::test]` for async, `tempfile` crate for temp directories.

## E2E Test Scripts

Four bash test scripts in `tests/` for end-to-end validation:

| Script | Scope | Assertions | What it tests |
|--------|-------|-----------|---------------|
| `e2e_comprehensive.sh` | Local (alice+bob+charlie) | ~143 | ALL 75+ endpoints, 18 categories: contacts lifecycle, machine pinning, trust eval (5 paths), MLS full lifecycle (add/remove/re-add), named groups (invite validation, leave/rejoin), KV stores (multi-key, update), presence (all 6 endpoints), seedless bootstrap |
| `e2e_live_network.sh` | Local → live VPS mesh | ~66 | Local node joins real bootstrap network, bidirectional: direct messaging, pub/sub, MLS groups with VPS members, named group invites across network, presence discovery |
| `e2e_vps.sh` | 6 VPS bootstrap nodes | ~102 | All 6 nodes: cross-continent direct messaging (NYC→Tokyo), multi-continent MLS, named groups, KV stores, contact blocking, presence FOAF, constitution on all nodes |
| `e2e_deploy.sh` | Build + deploy to VPS | ~24 | Cross-compile, upload to 6 nodes, verify health/version/mesh, collect API tokens |

### Running E2E Tests

```bash
# 1. Build release binary
cargo build --release

# 2. Local comprehensive test (no VPS needed, ~2 min)
bash tests/e2e_comprehensive.sh

# 3. Live network test (local node joins real bootstrap, ~3 min)
#    Requires: VPS nodes running, SSH access
bash tests/e2e_live_network.sh

# 4. Deploy to VPS (cross-compile + upload, ~5 min)
#    Requires: cargo-zigbuild, SSH access to 6 VPS nodes
bash tests/e2e_deploy.sh

# 5. VPS-only test (test across 6 bootstrap nodes, ~4 min)
#    Requires: tokens in tests/.vps-tokens.env (written by e2e_deploy.sh)
bash tests/e2e_vps.sh

# 6. Health check (quick VPS status)
bash .deployment/health-check.sh              # basic
bash .deployment/health-check.sh --extended   # with peer counts
```

### VPS Port Configuration

| Port | Protocol | Purpose | Binding |
|------|----------|---------|---------|
| **5483** | UDP/QUIC | Transport (gossip network) | `[::]:5483` or `0.0.0.0:5483` |
| **12600** | TCP/HTTP | REST API on VPS nodes | `127.0.0.1:12600` (configured in `/etc/x0x/config.toml`) |
| **12700** | TCP/HTTP | REST API default (local dev) | `127.0.0.1:12700` (default when no config) |

VPS API tokens are at `/root/.local/share/x0x/api-token` on Linux nodes.

### SSH Notes for macOS

When running tests that SSH to multiple VPS nodes sequentially, use `-o ControlMaster=no -o ControlPath=none -o BatchMode=yes` to avoid SSH multiplexing hangs. The health check and VPS test scripts already include these flags.

## API Completeness

75+ REST endpoints, all wired to x0xd and CLI:
- Identity + AgentCard: `GET /agent`, `GET /agent/card`, `POST /agent/card/import`
- Presence: `GET /presence/online`, `GET /presence/foaf`, `GET /presence/find/:id`, `GET /presence/status/:id`, `GET /presence/events` (SSE)
- Named groups: `POST/GET /groups`, `POST /groups/:id/invite`, `POST /groups/join`, policy, roles, join requests, ban/unban
- Group discovery: `GET /groups/discover?q=`, `GET /groups/discover/nearby`, shard subscriptions (Phase C.2, designed not yet implemented)
- KvStore: `POST/GET /stores`, `PUT/GET/DELETE /stores/:id/:key` (with access control)
- Direct messaging: `send_direct()`, `recv_direct()`, `connect_to_agent()`
- MLS groups: `MlsGroup::new()`, `add_member()`, `remove_member()`, `MlsCipher::encrypt/decrypt()`
- Task lists (CRDTs): `create_task_list()`, `join_task_list()` via `TaskListHandle`
- File transfer: `POST /files/send`, `POST /files/accept/:id`
- GUI: `GET /gui` (embedded HTML), `x0x gui` opens browser
- Identity, trust, contacts, gossip pub/sub, WebSocket: all complete

## Crate-Level Lint Suppressions

`lib.rs` has `#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]`. These exist because test code uses unwrap/expect. Production code paths should still avoid panics — use `?` with proper error types.
