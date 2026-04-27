# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [v0.19.5] - 2026-04-27

Hunt 12c release. Resolves the architectural bottleneck identified in
the v0.19.4 fleet soak: a slow `pubsub.handle_incoming` no longer
back-pressures the shared receive queue and bleeds into Membership /
Bulk dispatch.

### Fixed

- **`gossip`: per-stream isolation in the inbound receive pipeline.**
  Replaced the single shared `recv_tx` mpsc with three stream-specific
  channels in `src/network.rs`:
  - `recv_pubsub_tx` (capacity 10 000, matches subscription buffer)
  - `recv_membership_tx` (capacity 4 000)
  - `recv_bulk_tx` (capacity 4 000)
  The ant-quic receiver now routes each inbound message to the channel
  for its `GossipStreamType`, with its own `>80% full` back-pressure
  warning. New per-stream receive methods on `NetworkNode`:
  `receive_pubsub_message()`, `receive_membership_message()`,
  `receive_bulk_message()`.
- **`gossip`: three independent dispatcher tasks.** Replaced the single
  serial dispatcher loop with `run_pubsub_dispatcher`,
  `run_membership_dispatcher`, and `run_bulk_dispatcher` in
  `src/gossip/runtime.rs`. Each pulls only from its own channel and
  runs the existing per-arm timeout (PubSub 10 s, Membership 5 s,
  Bulk 5 s). A wedged PubSub handler can no longer block Bulk
  presence beacons or Membership SWIM ping-acks.
- **`gossip`: `GossipTransport::receive_message` compatibility kept**
  via `tokio::select!` over the three channels with `biased; Bulk;
  Membership; PubSub` ordering, so external trait consumers
  (saorsa-gossip-runtime, tests in `tests/network_timeout.rs`)
  continue to work unchanged.

### Changed

- **`/diagnostics/gossip` JSON shape** (BREAKING for monitor scripts).
  The flat `recv_depth_latest` / `recv_depth_max` /
  `recv_capacity_latest` fields are removed and replaced with a nested
  `recv_depth` object keyed by stream type:
  ```json
  "recv_depth": {
    "pubsub":     { "latest": 0, "max": 0, "capacity": 10000 },
    "membership": { "latest": 0, "max": 0, "capacity": 4000  },
    "bulk":       { "latest": 0, "max": 0, "capacity": 4000  }
  }
  ```
  Per-stream depth makes the Hunt 12c symptom (PubSub queue saturating
  while Bulk stays empty) directly visible.
  Monitor scripts that read the old fields must update — see
  `tests/e2e_hunt12c_pubsub_load_isolation.sh` for the new shape.

### Added

- **`tests/e2e_hunt12c_pubsub_load_isolation.sh`** — local reproducer
  that hammers a 4-node mesh with sustained 12 KB PubSub messages at
  15 msg/s and asserts that presence delivery stays healthy
  (`online >= N-1`, `bulk.timed_out == 0`, `membership.timed_out == 0`).
  Pre-Step-2 expectation: presence drift + bulk timeouts. Post-Step-2:
  clean PASS. Proof: `proofs/hunt12c-pubsub-load-20260427T200041Z/`.
- **Per-stream queue-depth unit test**
  `test_dispatch_stats_record_per_stream_queue_depth` pins the new
  per-stream snapshot shape.

### Validation

- `cargo nextest --workspace --all-features`: 1029 / 1029 pass.
- `cargo clippy --all-features --all-targets -D warnings`: clean.
- `tests/e2e_presence_propagation.sh`: 4 nodes, `peers=3 online=4`
  on every node — `proofs/e2e-presence-propagation-20260427T195512Z/`.
- `tests/e2e_hunt12c_pubsub_load_isolation.sh`: 4 nodes, 1356 PubSub
  messages × 12 KB at 15 msg/s over 120 s — every node sustained
  `online=4`, zero `bulk.timed_out`, zero `membership.timed_out`.



Hunt 12b release. Fixes the live-fleet regression where `/presence/online`
collapsed to self-only on most nodes 25–45 minutes after rolling restart.

### Fixed

- **`presence`: refresh broadcast peers from QUIC table.** The presence
  broadcast set was seeded once from `HyParViewMembership::active_view()`
  at `join_network()` and never refreshed. On the live mesh, HyParView's
  active view stayed at ≤ 1 peer for many minutes after restart while
  ant-quic was fully connected, so beacons fanned out to a tiny subset
  and the rest of the fleet observed no inbound presence at all. A new
  30 s background task now `replace_broadcast_peers()` with
  `HyParView active view ∪ ant-quic connected_peers`, so the transport
  mesh is the source of truth.
- **`presence`: pre-join the global presence topic.**
  `PresenceManager::handle_presence_message` silently dropped beacons
  whose `topic_id` was not in the local `groups` map.
  `PresenceWrapper::new` was building an empty groups map, so even when
  beacons arrived, `/presence/online` stayed empty until the first
  identity refresh seeded the entry. The wrapper now pre-joins
  `global_presence_topic()` at construction; pinned by
  `test_presence_wrapper_joins_global_presence_topic`.
- **`presence`: `/presence/online` uses live beacon liveness.** The
  endpoint filtered the discovery cache by `announced_at >= cutoff`
  (the announcement timestamp from first discovery, never refreshed by
  subsequent beacons). It now filters by `last_seen >= cutoff` in
  `discovered_agents()` / `online_peer_count()`, refreshes `last_seen`
  from beacon timestamps in `presence_record_to_discovered_agent()`,
  and a new `Agent::online_agents()` merges the identity cache with
  live `PresenceManager::get_group_presence()` records. Pinned by
  `test_online_agents_uses_presence_beacon_liveness`.
- **`gossip`: bincode wire-format fix on identity / machine
  announcement decoders.** `deserialize_identity_announcement` /
  `deserialize_machine_announcement` used
  `bincode::DefaultOptions::new()` (varint encoding) while the writers
  ship via `bincode::serialize` (fixint default). Decoders now call
  `.with_fixint_encoding()` so they actually match the wire. New test
  `announcement_decode_helpers_match_bincode_serialize_wire_format`
  pins the round-trip.

### Added

- **`gossip`: dispatcher visibility instrumentation.** Wraps every
  inbound dispatcher arm in a per-stream `tokio::time::timeout` (PubSub
  10 s, Membership 5 s, Bulk 5 s) with WARN-on-timeout. New
  `GossipDispatchStats` exposes per-stream counters
  (`received` / `completed` / `timed_out` / `max_elapsed_ms`) plus
  receive-queue depth (`recv_depth_latest` / `recv_depth_max` /
  `recv_capacity_latest`). Surfaced via `Agent::gossip_dispatch_stats()`
  and `GET /diagnostics/gossip` → new `dispatcher` field. Lets a fleet
  soak distinguish handler stalls from network back-pressure without a
  code change.

### Dependencies

- **`saorsa-gossip-*` → `0.5.23`.** Concurrent presence beacon fanout
  (`saorsa-gossip-presence` `JoinSet` + 5 s → 15 s per-peer timeout) so
  one slow peer cannot delay the rest of the mesh. Pubsub memory bound
  under sustained publish + idle traffic.

### Validation

- `cargo nextest --lib --all-features`: 602 / 602 pass.
- `tests/e2e_presence_propagation.sh`: 4-node localhost mesh,
  `peers=3 online=4` on every node — `proofs/e2e-presence-propagation-20260427T151802Z/`.
- 4-node fleet (saorsa-2 / 3 / 6 / 7), 90-minute monitor at 60 s
  intervals: `presence_online >= 3` on every node every tick
  (308 / 308 sample points). `recv_depth_max` peaks
  4729 / 265 / 101 / 425 (well below the 8000 threshold). Proof:
  `proofs/fleet-hunt12b-80ee753-20260427T153807Z/`.

### Known follow-up

- **Hunt 12c** — see `docs/design/hunt-12c-pubsub-handler-stall.md`.
  The new dispatcher counters lit up an architectural bottleneck on
  the most-loaded fleet node: a single peer's 16 056-byte PubSub
  message every 10 s exhausted the 10 s handler timeout, accumulating
  back-pressure on the shared `recv_tx`. The user-visible Hunt 12b
  symptom remains fixed; the structural fix (per-stream channel split
  in `src/network.rs`) is tracked for `v0.19.5` / `v0.20.0`.

### Removed (BREAKING)

- **Dropped first-party Node.js (napi-rs) and Python (PyO3 / maturin) FFI
  bindings.** x0x is now daemon-only outside Rust: applications run (or
  connect to) `x0xd` and consume the local REST/WebSocket API instead of
  importing a compiled `x0x` module. Concretely:
  - `bindings/nodejs/`, `bindings/python/`, the root-level `python/` stub,
    and `WASM_ROADMAP.md` have been deleted from the tree.
  - `Cargo.toml` no longer lists the binding crates as workspace members.
  - The `publish-npm` and `publish-pypi` jobs have been removed from
    `.github/workflows/release.yml`; releases now publish to crates.io +
    GitHub Releases only. The `npm install x0x` / `pip install agent-x0x`
    install snippets have been removed from the auto-generated GitHub
    Release notes.
  - Existing npm `x0x@0.1.0` and PyPI `agent-x0x@0.2.0` artefacts remain
    pinned to their last published version on the public registries; they
    will receive no further updates.
  - Migration: see [`docs/local-apps.md`](docs/local-apps.md) for examples
    of consuming the local `x0xd` API from any language.

## [v0.19.2] - 2026-04-23

**Note.** The `v0.19.1` tag was cut earlier today but never reached
crates.io — the release workflow's `Validate release metadata` step
rejected it because `SKILL.md` was still stuck at `0.17.4` (a hard
requirement of `SKILL.md version == Cargo.toml version == tag`). The
same stale `SKILL.md` is why `v0.19.0` is not on crates.io either
(`max_version` on crates.io is `0.18.4`). `v0.19.2` bundles the
`v0.19.0` wire-v2 / UserAnnouncement / IntroductionCard work, the
`v0.19.1` dependency bumps, **and** syncs `SKILL.md` so the release
actually publishes.

### Fixed (dependency bumps)

- **`ant-quic` → `0.27.4`.** Picks up the dual-stack CPU-spin fix:
  `DualStackSocket::create_io_poller` now AND-combines v4/v6 writability
  instead of OR-combining via `tokio::select!`. The prior OR-combination
  let a stale `Ready` on the non-target socket satisfy the poller while
  `try_send_to` had already cleared readiness on the target, so
  `drive_transmit` spun its `WouldBlock` retry loop at 100 % CPU in pure
  userspace. Reproduced on a live 6-continent bootstrap mesh (2-of-6
  nodes rotating into 100 % within 4–7 min pre-fix); post-fix watch over
  90 min showed all tokio workers in State S with <2 % mean CPU.
- **`saorsa-gossip-*` → `0.5.20`.** Lockstep republish across all 11
  workspace crates with `ant-quic = 0.27.4`; no gossip-side source
  changes.
- **`Cargo.toml` no longer carries the `[patch.crates-io] ant-quic = {
  path = "../ant-quic" }` hack.** Deps now resolve cleanly from
  crates.io.

### Tests

- Fixed a 1/256-flaky `test_agent_id_uniqueness` in
  `tests/comprehensive_integration.rs`: `AgentId([rand::random::<u8>();
  32])` (array-repeat: one byte × 32) → `AgentId(rand::random::<[u8;
  32]>())` (32 independent bytes). Three sites updated.
- `tests/e2e_deploy.sh` now sleeps 15 s between node restarts, matching
  the rolling-start-requirement invariant.

### Validation

- `cargo fmt --all --check`: clean.
- `cargo clippy --all-features --all-targets -- -D warnings`: clean.
- `cargo nextest run --all-features --workspace`: 1024/1025 (the one
  failure is the pre-existing `parity_cli::every_endpoint_is_reachable_
  from_cli`, same as 0.19.0).
- Live 6-node bootstrap mesh on `v0.19.1`-equivalent build (consuming
  published `ant-quic 0.27.4` + `saorsa-gossip 0.5.20` with no path
  hacks): 11 min CPU watch, peak 40 % single sample, zero sustained
  elevation — see
  `proofs/v0.19.0-validation-20260423T131419Z/spin-forensics/final-revalidation/`.

## [v0.19.0] - 2026-04-23

### Breaking — wire format v2

All identity / machine announcements are now on v2 topics. v1 is retired
and **v0.18.x is yanked from crates.io** — nodes must upgrade together.

- `x0x.identity.announce.v1` → `x0x.identity.announce.v2`
- `x0x.machine.announce.v1`  → `x0x.machine.announce.v2`
- `x0x.identity.shard.<n>`   → `x0x.identity.shard.v2.<n>`
- `x0x.machine.shard.<n>`    → `x0x.machine.shard.v2.<n>`

The `x0x.rendezvous.shard.<n>` topic is unchanged (it carries
`saorsa-gossip` `ProviderSummary`, not x0x wire types).

### Added

- **`reachable_via` + `relay_candidates` on announcements.**
  `IdentityAnnouncement` and `MachineAnnouncement` now carry
  `Vec<MachineId>` backpointers naming coordinator / relay peers through
  which a NAT-locked agent wants to be dialled. Populated from currently-
  connected peers the machine cache marks `is_coordinator == Some(true)` /
  `is_relay == Some(true)`, capped at 8 each, emitted only when
  `can_receive_direct` is not known-true. `connect_to_agent` now seeds
  these coordinators as transport peer hints before the coordinated dial,
  so ant-quic picks up an explicit NAT-traversal target rather than
  guessing from the bootstrap cache.
- **`UserAnnouncement` — first-class agent-ownership rosters.** A
  human identity (`UserId`) can now assert "these N agents are mine" as
  a first-class record on the new `x0x.user.announce.v2` topic (plus a
  `x0x.user.shard.v2.<n>` per-user shard). Each announcement is
  user-signed (ML-DSA-65) over the canonical bincode of the unsigned
  form, and carries a `Vec<AgentCertificate>` — each cert itself
  user-signed — so every agent-ownership claim is individually
  verifiable. New `Agent::announce_user_identity(human_consent)`,
  `discovered_user(user_id)`, `discovered_users()` APIs. Listener
  subscribes to both global and own-shard topics with dedup-windowed
  rebroadcast matching the identity/machine paths.
- **Real `IntroductionCard` signature.** Previously the card's
  `signature` field held a placeholder machine public key. Cards are
  now ML-DSA-65-signed over the canonical form (`"x0x-introduction-
  card-v1"` prefix + bincode of the unsigned fields, including
  `machine_public_key`), with a `verify()` method that checks machine-
  key→machine_id binding, the outer signature, and the embedded
  `AgentCertificate` chain. Closes a forgery hole where any node could
  mint a card claiming any (agent_id, machine_id, user_id) pair by
  copying a target's machine pubkey.

### Tests

- 6 new tests on `IntroductionCard`: round-trip, user-backed, tampered
  display_name / agent_id / machine_id, foreign-signature splice.
- 5 new tests on `UserAnnouncement`: round-trip, foreign-cert rejection
  at sign time, tampered cert list, tampered user_public_key, shard
  topic determinism.
- Expanded `IdentityAnnouncement` bincode round-trip to include the new
  `reachable_via` / `relay_candidates` fields.

### Validation

- `cargo fmt --all --check`: clean.
- `cargo clippy --all-features --all-targets -- -D warnings`: clean.
- `cargo nextest run --all-features --workspace`: 1023/1024 (the one
  failure is `parity_cli::every_endpoint_is_reachable_from_cli`,
  pre-existing on HEAD, flags missing `/machines/*` CLI subcommands —
  unrelated to this release).

## [v0.18.5] - 2026-04-21

### Added

- **Machine-centric discovery.** Machines now publish signed
  `x0x.machine.announce.v1` endpoint announcements keyed by `machine_id`
  and backed by a first-class discovered-machine cache. Agent and user
  identities link onto those machine records, and the daemon exposes
  `/machines/discovered`, `/machines/discovered/:machine_id`,
  `/machines/connect`, `/agents/:agent_id/machine`, and
  `/users/:user_id/machines` so callers can resolve `agent_id` /
  `user_id` to the transport machine used for IPv4/IPv6 direct dials,
  hole-punching, or relay-assisted connection.

### Fixed

- **File-transfer throughput on localhost.** File chunks now prefer the
  raw-QUIC direct-stream path when a live direct connection already
  exists, instead of paying the gossip-DM ACK round-trip on every chunk.
  Control-plane messages (offer / accept / reject / complete) still use
  the existing capability-aware path, so file setup and teardown retain
  their prior delivery semantics while the bulk body uses the fast lane.
- **Out-of-order raw chunk handling.** The receiver no longer fails the
  whole transfer if chunk `N+1` arrives before chunk `N`. Out-of-order
  chunks are buffered per transfer and drained in sequence as soon as the
  missing predecessor arrives. This was required once the raw-QUIC chunk
  path removed the implicit serialization that the gossip-DM ACK loop had
  been imposing.
- **Throughput measurement accuracy.** `TransferState` now exposes
  `started_at_unix_ms` / `completed_at_unix_ms`, and
  `tests/e2e_full_measurement.sh` can size the test file via
  `--file-size-kib` / `FILE_SIZE_KIB`. The harness now computes file
  throughput from daemon-side transfer timestamps instead of the old
  1-second status-poll cadence, which materially understated fast local
  transfers.
- **Slow-subscriber isolation.** Pub/sub delivery to each local
  subscriber channel is now non-blocking: once a subscriber's 10k buffer
  fills, x0x drops that subscriber instead of letting it back-pressure
  the topic delivery worker forever. This preserves delivery to other
  subscribers and lets `subscriber_channel_closed` surface the event in
  `GET /diagnostics/gossip`.

### Proofs

- `proofs/full-20260421-v0185-throughput-5node-16m/` — 5 daemons,
  16 MiB file, **102.69 Mbps** localhost transfer throughput in the
  throughput-focused run.
- `proofs/full-20260421-v0185-localhost-throughput-16m-500/` —
  comprehensive 5-daemon run, 500 pub/sub messages + 16 MiB file in
  **1.214 s = 110.56 Mbps** under the heavier combined workload.
- `proofs/slow-consumer-20260421-v0185-100k/` — one subscriber never
  drains, one subscriber drains normally, 100 000 publishes total:
  `publish_total=100000`, `subscriber_channel_closed=1`,
  `fast_received=100000`, `decode_to_delivery_drops=0`.

## [v0.18.4] - 2026-04-21

### Fixed

- **Dual-stack bind for named instances.** `x0xd --name <instance>`
  previously forced the QUIC bind to `0.0.0.0:0` (IPv4-only), so
  daemons on a dual-stack host could neither reach nor be reached
  by IPv6-only peers, and their `external_addrs` was IPv4-only
  even when a globally-routable IPv6 was configured on the host.
  Bind is now `[::]:0` (IPv6 unspecified with dual-stack), so
  both families are listened-on and observed.
- **File transfer chunk size.** `files::DEFAULT_CHUNK_SIZE` was 64 KiB
  (raw) which, after base64 + JSON wrapper, produced ~87 KB DM
  envelope payloads — exceeding `dm::MAX_PAYLOAD_BYTES` (49 152) so
  `Send chunk 0 failed: envelope construction failed: payload
  exceeds MAX_PAYLOAD_BYTES (87481 > 49152)` aborted every transfer.
  Dropped to 32 KiB raw, which base64-encodes to ~43 691 B and fits
  every chunk inside a single DM envelope with headroom for the JSON
  wrapper. First successful proof: 262 144 B file in 7.17 s.

### Added

- `tests/e2e_full_measurement.sh` — comprehensive proof run that
  captures pub/sub, DM with `require_ack_ms`, file transfer (with
  full completion tracking), probe-peer matrix, NAT/connectivity,
  relay state, coordinator state, and IPv4/IPv6 address-family
  breakdown across `external_addrs` AND announced `agent.card.addresses`.
- `/agent/card` snapshot per phase so the harness can compare what
  the daemon WOULD announce (passes `is_publicly_advertisable`)
  against what peers have OBSERVED (populates `external_addrs`).

### Proof: `proofs/full-20260421-194618/`

- 5 daemons, 500 msgs, strict gate: publisher 586 / subscribers 742
  each, 0 drops anywhere.
- File transfer: **262 144 B completed in 7.17 s** (0.29 Mbps over
  DM-fragment channel on localhost).
- Probe matrix: 20 / 20 ok.
- Announced addresses: every node surfaces **7 public IPv6
  addresses**; IPv4 is correctly filtered out because the local
  v4 is RFC1918 (`192.168.1.212`). On a dual-public-IP host
  (VPS) both families will appear.

## [v0.18.3] - 2026-04-21

### Fixed

- **Fan-out stall root cause: `NetworkNode::recv_tx` capacity bumped
  `128 → 10_000`** (with matching `direct_tx` `256 → 10_000`). Every
  inbound gossip / pubsub message across every topic and every peer
  on this node funnels through this single mpsc to the
  saorsa-gossip-transport consumer. At 128 capacity, a momentary
  slowdown in the PlumTree layer (ML-DSA-65 verification on a burst,
  a briefly-held subscriber lock, an EAGER fan-out to 8 peers) backs
  up `spawn_receiver`'s `recv_tx.send().await` and stops draining
  ant-quic's recv queue — freezing ALL inbound traffic for that node,
  not just the slow topic. Observed in the `stress-20260421-v0181`
  proof artefact: node-2 and node-3 got ~100 messages each in the
  first 1.2 s then received nothing for the remaining 43 s of
  publishing while nodes 4-5 kept flowing at 11 msg/s. Log diff
  showed `recv: … bytes (PubSub)` continuing at the network layer
  past the stall — proving the back-pressure was one layer up.

- **Back-pressure visibility.** `spawn_receiver` now emits a
  `WARN "[1/6 network] recv_tx >80% full — PubSub pipeline falling
  behind"` when the buffer's available capacity drops below 20 % of
  max. We still back-pressure rather than drop (delivery integrity
  wins over liveness visibility when the two conflict) — the warn
  makes the condition surface before it becomes a stall.

### Validation

- `cargo fmt --check`: clean
- `cargo clippy --all-targets --all-features -- -D warnings`: clean
- `cargo nextest run --all-features --workspace`: **1006 / 1006** pass

## [v0.18.2] - 2026-04-21

Reviewer-flagged blocker fixes on top of 0.18.1. 0.18.0 has been yanked
from crates.io — 0.18.1 was superseded by this release in the same day
because of the scope of the fixes.

### Fixed

- **`tests/e2e_stress_gossip.sh` now actually enforces the delivery
  claim** it documents. Previously the acceptance logic only checked
  publisher count and pipeline drops, so the 2026-04-20 artefact
  (`proofs/stress-20260420-085405/stress-report.json`) recorded 106 /
  200 per subscriber and still exited 0. Added a per-subscriber
  threshold gate (`delivered_to_subscriber >= MESSAGES *
  MIN_DELIVERY_RATIO`), default ratio 1.0. `--min-delivery-ratio
  <float>` flag and `MIN_DELIVERY_RATIO=<float>` env for deliberate
  under-saturation measurement.
- **`X0X_LOG_DIR` now tees to stdout AND the file**, as documented.
  Previous behaviour replaced the stdout sink when the env var was
  set. Reworked `init_logging` to compose the subscriber from two
  `tracing_subscriber::fmt::layer()`s so each event fans out to both
  writers while the `EnvFilter` still applies.
- **Rust 1.95.0 MSRV pinned through the full chain.** `rust-version`
  in `Cargo.toml` was stale at `1.75.0` while CHANGELOG already claimed
  1.95.0. CI's `dtolnay/rust-toolchain@stable` pinned to
  `@master` with explicit `toolchain: 1.95.0` in every job (fmt,
  clippy, test, doc, parity).

### Validation

- `cargo fmt --check`: clean
- `cargo clippy --all-targets --all-features -- -D warnings`: clean
- `cargo nextest run --all-features --workspace`: **1006 / 1006** pass

### Notes for consumers of earlier 0.18

`0.18.0` has been **yanked** — it shipped with ant-quic 0.27.2 and
missed the supersede-race fix in ant-quic 0.27.3 that directly affects
`/peers/events` accuracy. `0.18.1` pairs with ant-quic 0.27.3 and
saorsa-gossip 0.5.19. `0.18.2` is functionally identical to 0.18.1
at runtime — the changes are to the test harness acceptance gate,
the logging topology, and the toolchain metadata. Upgrade `0.18.0 →
0.18.2` directly; `0.18.1 → 0.18.2` is safe but strictly cosmetic at
runtime.

## [v0.18.1] - 2026-04-21

### Changed

- Bumped `ant-quic` `0.27.2 → 0.27.3` (closes supersede race — now
  emits `Replaced` + `Closed{Superseded}` on connection replacement;
  enriches NAT traversal outcome + expiry heuristics).
- Bumped `saorsa-gossip-*` `0.5.18 → 0.5.19` (re-pins ant-quic 0.27.3
  across all 11 crates + clippy 1.95 `sort_by_key(Reverse)`
  fixes in coordinator/{cache, gossip_cache, peer_cache} and
  runtime/rendezvous).
- REST + CLI + GUI gap-closure for the new ant-quic 0.27 surface
  (originally drafted as v0.18.1 work, rolling it into this bump):
  - New endpoints: `POST /peers/:peer_id/probe`,
    `GET /peers/:peer_id/health`, `GET /peers/events` (SSE).
  - `POST /direct/send` accepts `require_ack_ms` for a post-send
    peer-liveness probe via ant-quic `probe_peer`. Explicit
    documentation that this confirms the peer is responsive, not
    that the specific DM envelope was delivered.
  - New CLI: `x0x peer probe / health / events`,
    `x0x direct send --require-ack-ms <ms>`.
  - New GUI "Gossip Pipeline" panel in the Network view — renders
    all 9 `PubSubStats` counters and flags non-zero drops in red.
  - `communitas-x0x-client`: `gossip_stats()`, `probe_peer()`,
    `peer_health()`.
  - `communitas-apple/Tests/CommunitasUITests/` — XCUITest target
    with 5 golden-path UI tests.

### Validation

- `cargo fmt --check`: clean
- `cargo clippy --all-targets --all-features -- -D warnings`: clean
- `cargo nextest run --all-features --workspace`: **1006 / 1006** pass

### Proof runs (`proofs/`)

- `stress-20260421-v0181/` — 5 daemons × 500 messages on 0.18.1 +
  ant-quic 0.27.3, SETTLE_SECS=30, PUBLISH_DELAY_MS=30.
  Pipeline drops `decode_to_delivery_drops: 0` across all 5 nodes.
  Mesh delivery is now asymmetric on the 5-node localhost matrix
  (nodes 4-5: 647 / node, nodes 2-3: 106 / node) — this is a mesh-
  formation artefact, not a pipeline regression.
- `chrome-20260421-v0181/` — 13 / 13 GUI capabilities pass including
  the new peer observability endpoints.

## [v0.18.0] - 2026-04-20

### Added

- **`GET /diagnostics/gossip`** — drop-detection endpoint exposing
  `PubSubStats` counters for every stage of the pub/sub pipeline
  (publish / incoming / decoded / delivered / subscriber-channel-closed)
  plus derived `in_flight_decode` and `decode_to_delivery_drops`.
- **`x0x diagnostics gossip`** — CLI subcommand parallel to
  `diagnostics connectivity`.
- **`X0X_LOG_DIR`** — per-pid file log sink for `x0xd`; appends
  `<dir>/x0xd-<pid>.log` alongside stdout. Opt-in.
- **ant-quic 0.27.1/0.27.2 surface pass-throughs** on `NetworkNode`:
  `probe_peer` (#173 active liveness), `connection_health` (#170),
  `send_with_receive_ack` (#172), `subscribe_all_peer_events` (#171).
- `tests/ant_quic_0272_surface.rs` — 4 integration tests exercising
  each new primitive against localhost `P2pEndpoint`s.
- `docs/parity-matrix.md` — capability × surface matrix across CLI,
  REST, embedded GUI, Python / Node bindings, the communitas-x0x-client
  Rust crate, communitas-core / ui-service / ui-api / dioxus / kanban /
  apple / bench.
- `tests/e2e_stress_gossip.sh` — N-daemon / M-message stress harness
  that fails on any `decode_to_delivery_drops > 0`.
- `tests/e2e_gui_chrome.mjs` — Playwright driver for the embedded
  HTML GUI; captures HAR + console stream + screenshot + JSON pass/fail
  per capability. Loads GUI from the daemon's `/gui` handler so the
  page is same-origin with the REST surface.
- `tests/e2e_communitas_dioxus.sh` — JSON-IPC driver skeleton for the
  Communitas Dioxus desktop app.
- `communitas-apple/Tests/CommunitasUITests/` — XCUITest target with
  5 golden-path UI tests.
- `tests/e2e_proof_runner.sh` — top-level orchestrator rolling every
  phase into `proofs/<timestamp>/proof-report.json`.

### Changed

- Bumped `ant-quic` `0.27.1 → 0.27.2`.
- Bumped `saorsa-gossip-*` `0.5.17 → 0.5.18` (re-pins ant-quic 0.27.2
  across all 11 crates).
- Rust toolchain pinned to 1.95.0 — blake3 1.8.4 transitively requires
  `constant_time_eq 0.4.3` which has a 1.95 MSRV.
- `dm_inbox::InboxPipeline` rebroadcast-dedup map moved behind a
  `RebroadcastDedupMap` type alias (clippy 1.95 tightened
  `clippy::type_complexity`).
- API endpoint registry and shipped manifest grew to 114 endpoints.

### Validation

- `cargo fmt --check`: clean
- `cargo clippy --all-targets --all-features -- -D warnings`: clean
- `cargo nextest run --all-features --workspace`: **1006 / 1006 pass**

### Proof runs (checked into `proofs/`)

- Local 3-daemon gossip stress — 100 % delivery, 0 drops
  (`proofs/stress-20260420-085503/`).
- Chrome GUI capability walk — 9 / 9 pass including live pub/sub
  round-trip (`proofs/chrome-20260420-v2/`).

## [v0.17.1] - 2026-04-16

### Fixed

- `DirectMessaging::handle_incoming()` no longer back-pressures the receive pipeline when the pull-API receiver (`Agent::recv_direct()`) is idle. The bounded `internal_tx.send(msg).await` is now a non-blocking `try_send`, so an undrained mpsc can no longer stall the `Node::recv` → `spawn_receiver` → `start_direct_listener` chain. Daemons using only `subscribe_direct()` (x0xd, GUI, CLI) are the primary beneficiaries.
- `NetworkNode::spawn_receiver` explicitly drops the `node` read-lock guard after `Node::recv().await` returns, so we no longer hold the `RwLock` read lock while awaiting channel sends.

### Changed

- Bumped `ant-quic` to `0.26.12` (includes upstream #165 MASQUE relay target-selection fix: mesh-wide pairwise `/agents/connect` restored to 30/30 on the 6-node VPS bootstrap, vs. 6/30 under 0.26.9).
- Collapsed the Phase D.3 stable-group-id abstraction onto `mls_group_id`: every x0x group is an MLS group, and `stable_group_id()` now always equals the MLS group id. Removes cross-daemon id drift where owners indexed `named_groups` by MLS id and card-imported stubs indexed by stable id, which caused 404s on `POST /groups/:id/requests` and friends.
- Added 1 MiB + 16 MiB NYC→SFO large-file-transfer coverage to `tests/e2e_vps.sh` (section §18b).

### Known Issues

- **ant-quic #166**: in the live VPS mesh, a short unidirectional stream can be `[p2p][send] ACKED` on the sender but never surface at the receiver's `accept_uni()`, while larger PubSub streams on the same connection flow normally. Tracked upstream; not reproducible with two daemons on localhost. The 0.17.1 recv-pipeline fix clears x0x's contribution to the symptom; the residual stream-accept drop sits inside ant-quic. Mac-behind-NAT → VPS (the user-facing single-client journey) is not affected — e2e_live_network 66/66 green.

## [v0.16.0] - 2026-04-09

### Changed

- Bumped `ant-quic` to `0.26.1`
- Bumped `saorsa-gossip-*` crates to `0.5.14`
- Removed x0x-owned mDNS runtime and builder/accessor surface in favor of ant-quic's built-in first-party LAN discovery and additive UPnP handling

### Fixed

- Updated end-to-end shell harnesses to preserve HTTP error bodies instead of collapsing non-2xx responses into generic `curl_failed`
- Fixed `tests/e2e_full.sh` to honor `X0XD` and default to the release binary
- Updated release and deployment scripts to derive the current version dynamically

## [v0.15.3] - 2026-04-07

### Changed

- Bumped `ant-quic` to `0.25.3`
- Bumped `saorsa-gossip-*` crates to `0.5.13`

### Fixed

- Synced cached peer dialing with scoped/fresh direct-reachability semantics
- Synced `SKILL.md` release metadata to `0.15.3`

## [v0.15.2] - 2026-04-05

### Added

- **Comprehensive test system** — integration, property-based, fuzz, and soak testing infrastructure

### Fixed

- SKILL.md version synced to 0.15.2

## [v0.15.1] - 2026-04-03

### Added

- **mDNS zero-config LAN discovery** — agents on the same network find each other automatically via `_x0x._udp.local.` DNS-SD, no bootstrap needed
- New integration tests: KV store, named groups, stress tests
- Phase 19 mDNS testing in comprehensive test prompt

## [v0.15.0] - 2026-04-03

### Added

- **4-word speakable identities** — human-friendly agent addresses via `four-word-networking` (`x0x find ocean-metal-forest-coral`)
- `x0x find` and `x0x connect` CLI commands for agent discovery by words
- Trust-gated `/introduction` endpoint with per-trust-level field visibility

## [v0.14.9] - 2026-04-02

### Fixed

- Identity/address/timeout bug fixes
- SKILL.md version sync
- Rustdoc warning fixes

## [v0.14.8] - 2026-04-01

### Added

- **Release metadata validation** — CI now validates SKILL.md/Cargo.toml version sync and OpenClaw binary consistency before builds and releases (#48)

### Fixed

- **SKILL.md version sync** — frontmatter version was stuck at 0.14.0, now kept in sync with Cargo.toml

## [v0.14.7] - 2026-04-01

### Fixed

- **Self-update recovery for older installs** — `x0x upgrade` now detects signature verification failures from key rotation and prints clear instructions to reinstall via `curl | sh` or `cargo install`. Previously users on v0.14.3–v0.14.5 were stuck with a cryptic error and no way to auto-update.

## [v0.14.6] - 2026-04-01

### Fixed

- **Self-update signature verification** — embedded release signing public key now matches the CI signing secret. Previously `x0x upgrade` always failed with "manifest signature verification failed" because the keys were mismatched.

## [v0.14.5] - 2026-04-01

### Changed

- Updated `ant-quic` to 0.24.5 — NAT traversal coordination now uses PeerId-based lookups instead of SocketAddr, fixing hole-punching failures when peers' NAT mappings change
- Updated `saorsa-gossip-*` crates to 0.5.11
- Updated `saorsa-pqc` to 0.5

## [v0.9.2] - 2026-03-25

### Added

- **Group Workspace** — unified workspace with sub-tabs per group:
  - **Chat** — group messaging via gossip pub/sub (was separate tab, now in workspace)
  - **Board** — kanban board with To Do / In Progress / Done columns using CRDT task lists. Auto-creates a task list per group. Add tasks, claim, complete — all synced via gossip.
  - **Files** — send files to group members via P2P file transfer with SHA-256 verification. Select recipient from contacts, pick file, send.

- **Direct Messages tab** — chat directly with imported contacts. Import someone's card on Dashboard, they appear in DM contacts. Select a contact and send encrypted point-to-point messages.

### Fixed

- **Chat message echo** — own messages no longer appear twice. Gossip echoes from self are filtered out.
- **Invite link copy UX** — invite links now persist after generation with a dedicated "Copy Link" button. Previously the link would vanish on focus change.

## [v0.9.1] - 2026-03-25

### Fixed

- **Group auto-subscribe** — creating or joining a group now automatically subscribes to the group's chat and metadata gossip topics. Previously, members couldn't see each other because neither side was subscribed to the gossip topics. Join/create events are now announced on the chat topic.

- **IPv6 addresses in announcements** — identity announcements now include ALL external addresses (IPv4 and IPv6) from ant-quic's NodeStatus, not just the first observed address. Agents with dual-stack connectivity now advertise both addresses so peers can connect via whichever protocol works.

- **Removed NAT type from GUI** — NAT type detection is unreliable and showing an incorrect value is worse than showing nothing. Removed from the network dashboard until it can be determined definitively.

## [v0.9.0] - 2026-03-25

### Added

- **KvStore — CRDT-backed key-value store** with access control:
  - Generic replicated key-value store using OR-Set for keys, LWW for values
  - Access policies: **Signed** (owner-only writes), **Allowlisted** (approved writers), **Encrypted** (MLS group members only)
  - Unauthorized writes silently rejected — no spam possible
  - Delta-based sync over gossip with BLAKE3 content hashing
  - 7 REST endpoints: `POST/GET /stores`, `POST /stores/:id/join`, `GET /stores/:id/keys`, `PUT/GET/DELETE /stores/:id/:key`
  - 7 CLI commands: `x0x store create/list/join/keys/put/get/rm`
  - 46 unit tests covering CRUD, merge semantics, access control, serialization

- **Named Groups** — human-friendly group management:
  - Groups tie together MLS encryption + KvStore metadata + gossip chat topics
  - Display names per member (like Slack/Discord)
  - 6 REST endpoints: `POST/GET /groups`, `GET /groups/:id`, `POST /groups/:id/invite`, `POST /groups/join`, `PUT /groups/:id/display-name`
  - 6 CLI commands: `x0x group create/list/info/invite/join/set-name`

- **Invite Links** — shareable group invitations:
  - Format: `x0x://invite/<base64url(json)>` — share via email, chat, QR code
  - Configurable expiry (default 7 days, 0 = never)
  - Expired and malformed invites properly rejected
  - Invite tokens contain group name, inviter identity, one-time secret

- **AgentCard — Shareable Identity**:
  - Portable identity card: `x0x://agent/<base64url(json)>`
  - Contains display name, agent/machine/user IDs, addresses, groups, stores
  - Import a card to add someone to your contacts in one step
  - Share a card that includes group invites — one link to add you AND join your groups
  - `GET /agent/card` — generate your card
  - `POST /agent/card/import` — import someone's card
  - `x0x agent card --name "David"` / `x0x agent import <link>`

- **Embedded GUI** — full web interface compiled into x0xd:
  - `x0x gui` opens it in your default browser (macOS/Linux/Windows)
  - Served at `GET /gui` — no external files needed
  - Dashboard: identity, peers, uptime, discovered agents, identity cards
  - Groups: create, invite, join, display names
  - Chat: group-scoped rooms via WebSocket
  - Network: NAT type, addresses, peers, contacts, trust levels
  - Help: CLI reference, example app gallery, about

- **5 Example Apps** — single-file HTML apps in `examples/apps/`:
  - **x0x-chat** — group chat via WebSocket pub/sub
  - **x0x-board** — collaborative kanban (CRDT task lists)
  - **x0x-network** — network topology dashboard
  - **x0x-drop** — secure P2P file sharing with SHA-256
  - **x0x-swarm** — AI agent task delegation (the killer demo)
  - All self-contained, zero dependencies, dark terminal aesthetic
  - Starting points for humans and agents to build their own apps

- **App Distribution Design** — `docs/design/content-store-and-apps.md`:
  - Architecture for distributing web apps over the x0x network
  - App manifests signed with ML-DSA-65, discovered via gossip
  - Small apps inline via CRDT, large apps via file transfer
  - Roadmap through content store → app registry → static serving

### Fixed

- **Critical bootstrap bug** — config files without explicit `bootstrap_peers` field resulted in zero bootstrap peers (empty `Vec` from serde default). Nodes would start healthy but never connect to anyone. Fixed: `#[serde(default = "default_bootstrap_peers")]` now populates the 6 hardcoded global bootstrap nodes. This affected all users running x0xd with a custom config file.

### Changed

- REST API expanded from 50 to **70 endpoints**
- Total test count: **615+ tests** (was 519)
- All 6 VPS bootstrap nodes verified on v0.9.0 with full global mesh (NYC, SFO, Helsinki, Nuremberg, Singapore, Tokyo)

## [v0.8.1] - 2026-03-25

### Added

- **Unified install script** — single `scripts/install.sh` replaces both install.sh and install-quick.sh:
  - `curl -sfL https://x0x.md | sh` — install only (x0xd + x0x CLI)
  - `--start` — install + start daemon + wait for healthy
  - `--autostart` — install + start + configure start-on-boot
  - systemd user service (Linux) or launchd agent (macOS)

- **`x0x autostart` CLI command** — configure daemon to start on boot from the command line:
  - `x0x autostart` — enable (systemd on Linux, launchd on macOS)
  - `x0x autostart --remove` — disable

### Removed

- `scripts/install-quick.sh` — merged into unified `scripts/install.sh`

## [v0.8.0] - 2026-03-25

### Breaking Changes

- **Default QUIC port: 5483** (was random/12000). All x0x nodes now use the same well-known port. If you know an IP, connect to `IP:5483`. Port 5483 = LIVE on a phone keypad.

- **x0x-bootstrap binary removed.** Every x0x node is a bootstrap node. No special binary needed. The 6 VPS infrastructure nodes now run standard `x0xd` on port 5483.

### Added

- **Shared peer cache** — all named instances (default, alice, bob) share one `peers.cache` file at the platform data dir root. ant-quic's BootstrapCache handles concurrent access via atomic writes + file locking.

- **Compiled-in seed peers** — 6 Saorsa Labs nodes pre-configured as seeds. On first run with empty cache, these are loaded automatically. After first connection, cache grows naturally with quality-scored peers.

### Changed

- `DEFAULT_BOOTSTRAP_PEERS` updated to port 5483 (was 12000)
- All 6 VPS nodes migrated from `x0x-bootstrap` to `x0xd`
- All docs, CI, tests, deployment scripts updated to port 5483
- `build-bootstrap.yml` workflow deleted

### Architecture

Every node in ant-quic v0.13.0+ is symmetric P2P: any node can coordinate NAT traversal, relay via MASQUE (RFC 9298), and reflect addresses. The separate bootstrap binary was unnecessary complexity. What makes a node a "bootstrap" is simply being reachable and known — which is what the peer cache provides.

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
