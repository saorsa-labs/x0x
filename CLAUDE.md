# CLAUDE.md

These rules apply to every task in this project unless explicitly overridden.
Bias: caution over speed on non-trivial work. Use judgment on trivial tasks.

## Rule 1 — Think Before Coding
State assumptions explicitly. If uncertain, ask rather than guess.
Present multiple interpretations when ambiguity exists.
Push back when a simpler approach exists.
Stop when confused. Name what's unclear.

## Rule 2 — Simplicity First
Minimum code that solves the problem. Nothing speculative.
No features beyond what was asked. No abstractions for single-use code.
Test: would a senior engineer say this is overcomplicated? If yes, simplify.

## Rule 3 — Surgical Changes
Touch only what you must. Clean up only your own mess.
Don't "improve" adjacent code, comments, or formatting.
Don't refactor what isn't broken. Match existing style.

## Rule 4 — Goal-Driven Execution
Define success criteria. Loop until verified.
Don't follow steps. Define success and iterate.
Strong success criteria let you loop independently.

## Rule 5 — Use the model only for judgment calls
Use me for: classification, drafting, summarization, extraction.
Do NOT use me for: routing, retries, deterministic transforms.
If code can answer, code answers.

## Rule 6 — Token budgets are not advisory
Per-task: 4,000 tokens. Per-session: 30,000 tokens.
If approaching budget, summarize and start fresh.
Surface the breach. Do not silently overrun.

## Rule 7 — Surface conflicts, don't average them
If two patterns contradict, pick one (more recent / more tested).
Explain why. Flag the other for cleanup.
Don't blend conflicting patterns.

## Rule 8 — Read before you write
Before adding code, read exports, immediate callers, shared utilities.
"Looks orthogonal" is dangerous. If unsure why code is structured a way, ask.

## Rule 9 — Tests verify intent, not just behavior
Tests must encode WHY behavior matters, not just WHAT it does.
A test that can't fail when business logic changes is wrong.

## Rule 10 — Checkpoint after every significant step
Summarize what was done, what's verified, what's left.
Don't continue from a state you can't describe back.
If you lose track, stop and restate.

## Rule 11 — Match the codebase's conventions, even if you disagree
Conformance > taste inside the codebase.
If you genuinely think a convention is harmful, surface it. Don't fork silently.

## Rule 12 — Fail loud
"Completed" is wrong if anything was skipped silently.
"Tests pass" is wrong if any were skipped.
Default to surfacing uncertainty, not hiding it.

## On-Demand Reference Docs

These are NOT auto-loaded. Read them when the task touches the relevant area.

- Test suite (integration + e2e tables, running e2e, VPS ports, SSH notes):
  `tests/CLAUDE.md` (auto-loaded when working in `tests/`)
- Full REST + WebSocket API: `docs/api-reference.md`
- Self-update system internals: `docs/upgrade-system.md`
- Trust model, connectivity, enhanced announcements: `docs/trust-and-connectivity.md`
- x0x-symphony integration: `docs/symphony-integration.md`
- CI/CD workflows: `docs/cicd.md`
- Remote exec design + ACL: `docs/exec.md`, `docs/design/x0x-exec.md`
- Connect ACL (default-closed connectivity policy, T4 prereq): `docs/connect-acl.md`
- Non-Rust app integration examples: `docs/local-apps.md`
- Named-groups full model: `docs/design/named-groups-full-model.md`

## What is x0x

Agent-to-agent gossip network for AI systems. Built on `ant-quic` (QUIC transport with post-quantum cryptography and NAT traversal) and `saorsa-gossip` (epidemic broadcast, CRDT sync, pub/sub). Distributed as a Rust crate (`x0x`) and a daemon binary (`x0xd`) with a local REST + WebSocket API; non-Rust applications integrate by talking to the daemon over HTTP rather than via FFI bindings.

## Build & Test Commands

Standard `just` recipes are available (see `just --list`). Raw cargo commands:

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
8. **Group Discovery** (`groups/`): DHT-free distributed discovery via three tiers: social propagation (agents share cards in conversation), tag shards (BLAKE3-hashed tags → 65,536 PlumTree topics with CRDT OR-Set anti-entropy), and presence-social browsing (groups nearby agents are in). Path caching on relay nodes provides hot-shard mitigation. Fully partition-tolerant. See `docs/design/named-groups-full-model.md`.

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
  ├── upgrade/     ← Self-update — see docs/upgrade-system.md
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
agent.machine_id()        // MachineId
agent.agent_id()          // AgentId
agent.user_id()           // Option<UserId>
agent.agent_certificate() // Option<&AgentCertificate>

// KvStore — replicated key-value with access control
let store = agent.create_kv_store("name", "topic").await?;
store.put("key".into(), b"value".to_vec(), "text/plain".into()).await?;

// Presence — SOTA discovery with FOAF and adaptive detection
let rx = agent.subscribe_presence().await?;         // AgentOnline/AgentOffline events
let agents = agent.discover_agents_foaf(2).await?;  // FOAF walk, TTL=2
let cached = agent.cached_agent(&id).await?;        // Local cache lookup (no network)
```

Named groups, MLS, file transfer, task lists, and diagnostics are managed via the REST API — see `docs/api-reference.md` when working on those surfaces.

### Error Handling

Three error enums in `error.rs`:
- `IdentityError`: Key generation, validation, storage, serialization, certificate verification
- `NetworkError`: Node creation, connections, NAT traversal, protocol violations, resource limits
- `PresenceError`: NotInitialized, BeaconFailed, FoafQueryFailed, SubscriptionFailed, Internal

Type aliases: `error::Result<T>` for identity, `error::NetworkResult<T>` for network, `error::PresenceResult<T>` for presence.

### Storage Format

Keypairs are serialized with **bincode** (compact binary), not JSON. Manual serialization via `storage.rs` with explicit `public_key`/`secret_key` fields. Default path: `~/.x0x/`.

## Binary: x0x (CLI)

`src/bin/x0x.rs` — unified CLI that controls a running `x0xd` daemon. Every REST endpoint is mapped to a CLI subcommand. Shared endpoint registry in `src/api/mod.rs` keeps routes and CLI commands in sync. CLI modules in `src/cli/`.

Key commands: `x0x start`, `x0x health`, `x0x agent`, `x0x contacts`, `x0x publish`, `x0x direct send`, `x0x exec <agent> -- <argv...>`, `x0x groups`, `x0x tasks`, `x0x presence online|foaf|find|status`, `x0x routes` (prints all endpoints).

`x0x exec` is gated behind an exec ACL (default `/etc/x0x/exec-acl.toml` on Linux, `/usr/local/etc/x0x/exec-acl.toml` on macOS) and disabled unless `[exec].enabled = true`. See `docs/exec.md`.

### x0xd Daemon Flags

```
x0xd [OPTIONS]
  --config <PATH>                 Path to config file (TOML)
  --name <NAME>                   Instance name for multi-instance support
  --api-port <PORT>               Override API server port (otherwise ephemeral for named instances)
  --no-hard-coded-bootstrap       Skip configured bootstrap peers
  --exec-acl <PATH>               Override default exec ACL path
  --check                         Check configuration and exit
  --check-updates                 Check for updates and exit
  --skip-update-check             Skip update check on startup
  --doctor                        Run diagnostics
```

Multi-instance example: `x0xd --name alice --api-port 12701 --no-hard-coded-bootstrap`

## Non-Rust Integration

x0x is daemon-only outside the Rust ecosystem. There are no Node.js or Python FFI bindings — applications start (or connect to) `x0xd` and call the local REST/WebSocket API. See `docs/local-apps.md` for examples in any language.

## Crate-Level Lint Suppressions

`lib.rs` has `#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]`. These exist because test code uses unwrap/expect. Production code paths should still avoid panics — use `?` with proper error types.

## Obsidian Vault

The Saorsa Labs Obsidian vault lives at:
```
~/Library/Mobile Documents/iCloud~md~obsidian/Documents/Ideas/Saorsa Labs/
```

x0x docs are mirrored in the vault under:
```
Saorsa Labs/Projects/x0x/
├── x0x MOC.md              ← Map of Content (index page, LLM reads this first)
├── CHANGELOG.md            ← Mirrored changelog
├── ADRs/                   ← All ADRs as individual wikilinked pages
│   ├── x0x - 0001-bootstrap-peers-are-seed-hints-only.md
│   ├── x0x - 0002-application-level-keepalive-for-direct-connections.md
│   └── ... (0003–0009)
└── Docs/                   ← All repo docs + design docs
    ├── x0x - api-reference.md
    ├── x0x - identity.md
    ├── x0x - groups.md
    ├── x0x - trust.md
    └── design/
        ├── x0x-exec.md
        ├── x0x-terminal.md
        └── ...
```

**Vault conventions:**
- Each page has YAML frontmatter: `title`, `project`, `type` (`adr`/`documentation`/`index`), `source` (repo path), `tags`, `imported` date, `updated` date
- ADRs use type `adr`; docs use type `documentation`; MOC uses type `index`
- Pages link to each other via `[[wikilinks]]`
- The vault is updated manually or via sync scripts — it's a read-only mirror of the repo docs, not a source of truth
- For cross-project context, see the parent MOCs: `Saorsa Labs/Saorsa Labs MOC.md` and sibling project MOCs (ant-quic, communitas, fae, saorsa-gossip, saorsa-mls, saorsa-pqc)
