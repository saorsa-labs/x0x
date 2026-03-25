# Changelog

All notable changes to this project will be documented in this file.

## [v0.7.0] - 2026-03-25

### Added

- **`x0x` CLI binary** — unified command-line tool that controls a running x0xd daemon. Every REST endpoint is available as a subcommand (`x0x health`, `x0x contacts list`, `x0x direct send`, `x0x groups create`, etc.). Supports `--json` output and `--name` for named instances.

- **Shared API endpoint registry** (`src/api/mod.rs`) — 50 endpoint definitions consumed by both x0xd and the CLI. Routes and CLI commands can never drift out of sync.

- **12 new daemon endpoints** closing the library→daemon API gap:
  - `POST /agents/find/:id` — active 3-stage agent search
  - `GET /agents/reachability/:id` — reachability prediction
  - `POST /contacts/:id/revoke` — key revocation
  - `GET /contacts/:id/revocations` — revocation audit trail
  - `POST /contacts/:id/machines/:mid/pin` — machine pinning
  - `DELETE /contacts/:id/machines/:mid/pin` — machine unpinning
  - `POST /trust/evaluate` — trust decision evaluation
  - `POST /mls/groups/:id/welcome` — MLS welcome message
  - `GET /upgrade/check` — update check
  - `GET /network/bootstrap-cache` — peer cache stats
  - `GET /agents/discovered?unfiltered=true` — include stale entries

- **51 daemon API integration tests** — comprehensive test suite covering all routes against a live daemon with real bootstrap node connections.

- **`install-quick.sh`** — single-command installer: `curl -sfL https://x0x.md | sh`. Downloads binary, starts daemon, waits for healthy, prints agent ID.

- **File transfer protocol types** (`src/files/mod.rs`) — types and state management for future file sharing.

### Changed

- 51 routes total (was 39 in v0.6.0)
- `futures` dependency now includes `alloc` feature for WebSocket test support

## [v0.6.0] - 2026-03-24

### Added

- **WebSocket support** — bidirectional real-time communication for multi-app sessions:
  - `GET /ws` — general purpose WebSocket (subscribe, publish, send_direct, ping)
  - `GET /ws/direct` — WebSocket with auto-subscribe to direct messages
  - `GET /ws/sessions` — list active sessions with shared subscription stats
  - Session management with UUID IDs, per-session topic tracking
  - Trust check on WebSocket send_direct (matches REST behavior)
  - 30s server-side keepalive ping

- **Shared subscription fan-out** — multiple WebSocket clients subscribing to the same topic share a single gossip subscription (1 forwarder, 1 broadcast channel) instead of creating N independent subscriptions. Subscription resources are cleaned up when the last session leaves a topic.

- **OpenClaw install array** in SKILL.md — 7 install declarations (5 platform binaries + node + uv) for ClawHub auto-install.

- **agent.json updated to v0.6.0** — added direct-messaging capability, daemon endpoint, 3 new tags.

### Changed

- **SKILL.md restructured** — 913 lines → 343 lines (~1601 tokens). Full API reference, vision, security, diagnostics, ecosystem, SDK docs moved to `docs/`. WebSocket protocol documented.

- **6 new reference docs** — `docs/api-reference.md`, `docs/vision.md`, `docs/security.md`, `docs/diagnostics.md`, `docs/ecosystem.md`, `docs/sdk-quickstart.md`. All linked via GitHub URLs.

- **`docs/api.md` updated** — comprehensive 36+ endpoint reference with WebSocket protocol, replacing old stub table.

## [v0.5.5] - 2026-03-24

### Added

- **`--start` and `--health` flags in install script** — `bash scripts/install.sh --start --health` now actually starts the daemon and waits for it to be healthy. Previously these flags were documented in SKILL.md but silently ignored by the script.

- **Direct binary download instructions in SKILL.md** — agents can now install x0xd with only `curl` and GitHub, no Rust toolchain or install script needed. Platform detection + `curl` + `tar` is all that's required.

### Fixed

- **Install script platform paths** — macOS data directory now correctly uses `~/Library/Application Support/` instead of `~/.local/share/` (matches x0xd's `dirs::data_dir()` behavior).

- **x0x.md dependency clarified** — SKILL.md now explicitly states that x0x.md is optional. All install paths work with only GitHub up.

## [v0.5.4] - 2026-03-24

### Fixed

- **MLS group persistence** — switched from JSON to bincode format. JSON serialization failed because `MlsGroup.members` uses `HashMap<AgentId, ...>` and JSON requires string keys. Bincode handles byte-array keys natively. Groups now correctly survive daemon restarts.

- **Storage path documentation** — SKILL.md now shows correct platform-specific paths (macOS: `~/Library/Application Support/x0x/`, Linux: `~/.local/share/x0x/`).

- **Install script URL** — fixed from `https://x0x.md/install.sh` to `https://x0x.md` (the domain serves the script at the root).

- **Install method references** — SKILL.md now references all three install scripts (`install.sh`, `install.ps1`, `install.py`) and links to `docs/install.md`.

## [v0.5.3] - 2026-03-24

### Added

- **Complete SKILL.md quickstart guide** — an agent can now go from zero to a working daemon using only SKILL.md:
  - Three install methods (curl script, from source, as library)
  - Daemon startup, first-run behavior, key generation explained
  - "Verify it's working" 3-step flow
  - "Your first message" pub/sub walkthrough
  - Full CLI reference (all flags)
  - TOML config reference (all options with defaults)
  - Storage locations for all persisted state
  - Error response format with HTTP status code examples
  - MLS group encryption curl examples (create, add member, encrypt, decrypt)

## [v0.5.2] - 2026-03-24

### Fixed

- **Documentation audit** — all 36 x0xd REST endpoints now documented in SKILL.md API reference (was missing MLS group endpoints and machine management endpoints)
- **Stale "Incomplete APIs" notes removed** — CLAUDE.md and AGENTS.md no longer claim `create_task_list()` is unimplemented (it has been fully wired since v0.4.0)

## [v0.5.1] - 2026-03-24

### Added

- **x0xd REST endpoints for direct messaging** — 4 new endpoints exposing the direct messaging API via the daemon's HTTP interface:
  - `POST /agents/connect` — connect to a discovered agent
  - `POST /direct/send` — send direct message (with trust filtering — blocked agents rejected)
  - `GET /direct/connections` — list connected agents
  - `GET /direct/events` — SSE stream of incoming direct messages (with 15s keepalive)

- **x0xd REST endpoints for MLS group encryption** — 7 new endpoints for managing encrypted groups:
  - `POST /mls/groups` — create a group (random or specified ID)
  - `GET /mls/groups` — list all groups
  - `GET /mls/groups/:id` — get group details and members
  - `POST /mls/groups/:id/members` — add member
  - `DELETE /mls/groups/:id/members/:agent_id` — remove member
  - `POST /mls/groups/:id/encrypt` — encrypt with group key
  - `POST /mls/groups/:id/decrypt` — decrypt with group key

- **MLS group persistence** — groups are saved to `<data_dir>/mls_groups.json` on every mutation and restored on daemon restart.

- **1 MB body-size limit** — `DefaultBodyLimit::max(1MB)` on all endpoints to prevent memory exhaustion.

- **Trust check on direct send** — `POST /direct/send` checks `ContactStore` and rejects messages to blocked agents with HTTP 403.

### Security

- All internal error details are logged with `tracing::error!` but HTTP responses return only generic error messages. No file paths, socket addresses, or cryptographic details are leaked to API consumers.

- Extracted `decode_base64_payload()` and `make_mls_cipher()` helpers to eliminate duplicated error-handling code.

## [v0.5.0] - 2026-03-24

### Added

- **Direct agent-to-agent messaging** (`src/direct.rs`) — Point-to-point communication between connected agents, bypassing gossip for private, efficient, reliable delivery.
  - `agent.send_direct(&agent_id, payload)` — send bytes to a connected agent
  - `agent.recv_direct()` — blocking receive from any agent
  - `agent.recv_direct_filtered()` — receive with trust filtering (drops messages from blocked agents)
  - `agent.subscribe_direct()` — broadcast receiver for concurrent processing
  - `agent.is_agent_connected(&agent_id)` — check connection state
  - `agent.connected_agents()` — list all connected agents
  - Wire format: `[0x10][sender_agent_id: 32 bytes][payload]` — max 16 MB

- **Trust-filtered direct messaging** — `recv_direct_filtered()` checks `ContactStore` before delivering messages. Blocked agents' direct messages are silently dropped, matching gossip pub/sub behavior.

- **Receive-side payload size enforcement** — Network layer drops direct messages exceeding 16 MB + 32 bytes before forwarding to the channel, preventing memory exhaustion from malicious peers.

- **New error variants** — `AgentNotConnected`, `AgentNotFound`, `PayloadTooLarge`, `InvalidMessage` in `NetworkError`.

- **21 new tests** — 8 unit tests in `direct.rs`, 13 integration tests in `tests/direct_messaging_integration.rs` (536 total tests).

- **SKILL.md major update** — Direct messaging API docs, "Build Any Decentralized Application" vision with complete primitive table, human-centric tool replacement guide (GitHub → decentralized git, Zoom → saorsa-webrtc, etc.), sibling project references, plugin creation examples.

### Changed

- `connect_to_agent()` now registers agent mappings in `DirectMessaging` on successful connection, enabling subsequent `send_direct()` calls.

- Network receiver (`spawn_receiver()`) routes `0x10`-tagged messages to a separate direct message channel, distinct from gossip streams.

### Security

- Documented sender spoofing limitation: the `sender` AgentId in direct messages is self-asserted. The `machine_id` IS authenticated via QUIC/ML-DSA-65. See `DirectMessage` docs for guidance.

### Removed

- `NetworkNode::try_recv_direct()` — dead code stub that always returned `None`.

## [v0.4.0] - 2026-03-23

### Added

- **Identity unification** — `MachineId` now equals the `ant-quic` QUIC `PeerId`. The machine ML-DSA-65 keypair is passed directly to `ant-quic::NodeConfig` so that both identity and transport use the same key. No more disconnected transport identity.

- **Flexible trust model** (`src/contacts.rs`, `src/trust.rs`) — Contacts now carry an `IdentityType` (`Anonymous | Known | Trusted | Pinned`) and a list of `MachineRecord` entries. `TrustEvaluator` evaluates `(AgentId, MachineId)` pairs:
  - Machine pinning: `IdentityType::Pinned` accepts only messages from pinned machine IDs
  - `TrustDecision`: `Accept | AcceptWithFlag | RejectMachineMismatch | RejectBlocked | Unknown`
  - Identity listener now rejects blocked and machine-mismatched announcements

- **Enhanced announcements** — `IdentityAnnouncement` and `DiscoveredAgent` now carry four optional NAT fields: `nat_type`, `can_receive_direct`, `is_relay`, `is_coordinator`. The async heartbeat populates them from `ant-quic::NodeStatus`.

- **Connectivity module** (`src/connectivity.rs`) — New `ReachabilityInfo` struct (built from a `DiscoveredAgent`) with `likely_direct()` and `needs_coordination()` heuristics. New `ConnectOutcome` enum: `Direct(addr) | Coordinated(addr) | Unreachable | NotFound`.

- **`Agent::connect_to_agent()`** — Attempts connection using direct-first strategy, falling back to coordinated NAT traversal via `ant-quic`. Enriches the bootstrap cache on success.

- **`Agent::reachability()`** — Returns `Option<ReachabilityInfo>` for a discovered agent.

- **`NetworkNode::node_status()`** — Accessor for the live `ant_quic::NodeStatus`.

- **50 new integration tests** across 4 test files: `identity_unification_test.rs`, `trust_evaluation_test.rs`, `announcement_test.rs`, `connectivity_test.rs` (517 total tests).

- **Technical documentation**: `docs/identity-architecture.md`, `docs/nat-traversal-strategy.md`, `docs/SKILLS.md`.

### Changed

- `ContactStore` gains `IdentityType`, `MachineRecord`, and machine management methods (`add_machine`, `remove_machine`, `pin_machine`, `unpin_machine`, `machines`, `set_identity_type`). The JSON storage format adds `identity_type` and `machines` fields with `#[serde(default)]` for backward compatibility.

- `x0xd` REST API extended: `PATCH /contacts/:id` now accepts optional `identity_type` field; new routes `GET/POST /contacts/:id/machines` and `DELETE /contacts/:id/machines/:mid`.

### Protocol Note

`IdentityAnnouncement` wire format has changed. Messages encoded with v0.3.x cannot be decoded by v0.4.x because bincode 1.x treats all fields as required. Nodes must upgrade together.

## [v0.3.1] - 2026-03-05

### Fixed
- **reqwest now uses rustls-tls** — removed hidden OpenSSL dependency; `reqwest` without `default-features = false` silently pulls `native-tls` (OpenSSL on Linux), contradicting the fully-PQC, no-system-crypto design. Switching to `rustls-tls` makes cross-compilation from macOS work without `OPENSSL_DIR` hacks and keeps the entire dependency chain in pure Rust.

### Added
- **VPS e2e integration test suite** — `tests/vps_e2e_integration.rs` with 4 local tests (no live network required) covering identity announcement, late-join heartbeat discovery, find_agent cache hit, and user identity discovery. Four additional `#[ignore]` variants run against live VPS bootstrap nodes.
- **CLAUDE.md** — project architecture reference for Claude Code

## [v0.3.0] - 2026-03-05

### Added
- **Rendezvous ProviderSummary integration** — `Agent::advertise_identity()` publishes a signed `ProviderSummary` to the rendezvous shard topic enabling global agent findability across gossip overlay partitions
- **`Agent::find_agent_rendezvous()`** — stage-3 lookup that subscribes to the rendezvous shard topic and waits for a matching `ProviderSummary`; addresses decoded from the `extensions` field
- **3-stage `find_agent()`** — upgraded from 2-stage to: cache hit → identity shard subscription (5s) → rendezvous (5s)
- **`rendezvous_shard_topic_for_agent()`** — deterministic `"x0x.rendezvous.shard.<u16>"` topic function
- **`RENDEZVOUS_SHARD_TOPIC_PREFIX`** constant
- **x0xd rendezvous config** — `rendezvous_enabled` (default `true`) and `rendezvous_validity_ms` (default 3,600,000 ms) config fields; initial advertisement at startup + background re-advertisement every `validity_ms / 2`
- **Identity heartbeat** — `Agent::start_identity_heartbeat()` re-announces identity at configurable interval (default 300s) so late-joining peers can discover earlier nodes
- **TTL filtering** — `presence()` and `discovered_agents()` filter entries older than `identity_ttl_secs` (default 900s); `discovered_agents_unfiltered()` returns all cache entries
- **Shard-based identity routing** — `shard_topic_for_agent()` returns `"x0x.identity.shard.<u16>"` derived via BLAKE3; `announce_identity()` dual-publishes to shard + legacy topics; 65,536-shard space
- **Human identity HTTP API** — `GET /users/:user_id/agents`, `GET /agent/user-id`; `?wait=true` query parameter on `GET /agents/discovered/:id` triggers active shard+rendezvous lookup
- **`Agent::find_agents_by_user()`** — discovers all agents in cache claiming a given `UserId`
- **`Agent::local_addr()`** — returns the bound socket address of the network node
- **`Agent::build_announcement()`** — public wrapper for building a signed `IdentityAnnouncement`
- **`AgentBuilder::with_heartbeat_interval()` / `with_identity_ttl()`** — configurable heartbeat and TTL
- **x0xd heartbeat/TTL config** — `heartbeat_interval_secs` and `identity_ttl_secs` fields
- **SKILL.md Discovery & Identity section** — full curl examples, human consent invariant, trust model, `x0x://user/<hex>` URI scheme

### Changed
- `find_agent()` timeout split: 5s for identity shard subscription + 5s for rendezvous (was 10s shard-only)
- `join_network()` now calls `announce_identity()` and `start_identity_heartbeat()` automatically

### Infrastructure
- Updated saorsa-gossip-* crates from 0.5.1 → 0.5.2 (adds `ProviderSummary.extensions`, `sign_raw`/`verify_raw`)
- Removed CI symlink workaround for ant-quic and saorsa-gossip from all 4 workflows (ci.yml, release.yml, build.yml, build-bootstrap.yml) — all deps now resolve from crates.io

## [v0.2.0] - 2026-02-01

### Added
- Signed identity announcements with machine-key attestation
- Contact trust store with `Blocked` / `Unknown` / `Known` / `Trusted` levels
- Trust-filtered pub/sub (blocked senders are dropped)
- Dual-stack IPv6 on all 6 bootstrap nodes
- Axum route improvements
- Production gossip integration
- `x0xd` daemon with full REST API

## [v0.1.0] - 2026-01-01

### Added
- Initial release
- `Agent` with machine + agent + user identity (three-layer model)
- CRDT collaborative task lists (OR-Set checkboxes, LWW-Register metadata, RGA ordering)
- MLS group encryption (ChaCha20-Poly1305)
- Gossip pub/sub via saorsa-gossip epidemic broadcast
- Bootstrap connection to 6 global nodes (NYC, SFO, Helsinki, Nuremberg, Singapore, Tokyo)
- Node.js bindings (napi-rs v3) and Python bindings (PyO3/maturin)
- GPG-signed SKILL.md for agent self-distribution
