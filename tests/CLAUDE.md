# tests/ — Test Suite Reference

Auto-loaded only when Claude is working on files in `tests/`. Root `CLAUDE.md`
covers project-wide rules and architecture.

## Integration Test Organization

33 integration test files in `tests/` (curated core subset; the directory holds more):

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
| `kv_first_join_bootstrap.rs` | Issue #96: cold first-join state bootstrap via state-sync side topic (daemon-backed, `--ignored`) |
| `tasklist_first_join_bootstrap.rs` | Task-list cold first-join bootstrap via state-sync side topic + LWW-clock delta merge (daemon-backed, `--ignored`) |
| `local_topics.rs` | Issue #89: `local:` topics deliver same-daemon only, never gossipped (daemon-backed, `--ignored`) |
| `named_group_integration.rs` | Named groups, invites, join/leave, display names |
| `owner_retirement.rs` | ADR-0016 Slice 2: owner retirement / flat Admin authority at the `GroupInfo` + state-commit layer |
| `membership_authority.rs` | ADR-0016 Slice 3: add/remove/ban authority via library primitives (handler enforcement lives in `src/server/mod.rs` in-crate tests) |
| `last_admin_invariant.rs` | ADR-0016 R2: no commit may leave a live group with zero active admins, enforced at the state-commit choke-point |
| `invite_authority.rs` | ADR-0016 Slice 4: invite-issue authority and creator provenance from base-state |
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

Bash + Python test harnesses in `tests/` for end-to-end validation:

| Script | Scope | Assertions | What it tests |
|--------|-------|-----------|---------------|
| `e2e_comprehensive.sh` | Local (alice+bob+charlie) | ~143 | ALL 75+ endpoints, 18 categories: contacts lifecycle, machine pinning, trust eval (5 paths), MLS full lifecycle (add/remove/re-add), named groups (invite validation, leave/rejoin), KV stores (multi-key, update), presence (all 6 endpoints), seedless bootstrap |
| `e2e_live_network.sh` | Local → live VPS mesh | ~66 | Local node joins real bootstrap network, bidirectional: direct messaging, pub/sub, MLS groups with VPS members, named group invites across network, presence discovery |
| `e2e_vps.sh` | 6 VPS bootstrap nodes (legacy SSH-per-call) | ~102 | All 6 nodes: cross-continent direct messaging (NYC→Sydney), multi-continent MLS, named groups, KV stores, contact blocking, presence FOAF, constitution on all nodes. **Dominated by SSH RTT to Singapore/Sydney — use the dogfood-family harnesses for clean cross-region results.** |
| `e2e_vps_mesh.py` | Phase A — 6 VPS DM matrix (mesh-relay) | 30 directed pairs | All-pairs DM matrix driven through x0x's own DMs via 1 SSH tunnel to an anchor. ~16 s wall-clock, zero harness flakes. See [`TEST_SUITE_GUIDE.md`](../TEST_SUITE_GUIDE.md) §7b. |
| `e2e_vps_groups.py` | Phase B — 6 VPS groups + contacts dogfood | up to 49 | Anchor creates a `public_open` group, DMs invites to all runners, each posts a group message, contacts add/Trust/Block/remove cycle per node. See §7c. |
| `e2e_local_mesh.sh` | Local 3-node Phase A smoke | 6 directed pairs | Boots alice/bob/charlie + a runner each, runs `e2e_vps_mesh.py --no-tunnel` against alice. Proves the protocol without SSH. |
| `e2e_dogfood_groups.sh` | Phase B — local 3-instance groups + contacts | 29 | Same dogfood as §7c but local. ~5 s wall-clock. |
| `e2e_dogfood_local.sh` | Phase D — fast 2-instance pre-commit smoke | 19 | Identity + contacts + DM round-trip + group lifecycle, all via DMs. ~5 s wall-clock; targets every-commit cadence. See §7e. |
| `e2e_deploy.sh` | Build + deploy to VPS (with optional mesh verification) | ~24 | Cross-compile, upload `x0xd` **and** the mesh test runner (`x0x-test-runner.service`) to 6 nodes, verify health/version/mesh, collect API tokens. **`--mesh-verify` flag** chains Phase A + Phase B verification onto the deploy via 1 SSH tunnel. See §7d. |

## Running E2E Tests

```bash
# 1. Build release binary
cargo build --release

# 2. PRE-COMMIT SMOKE (Phase D, ~5 s, no VPS, no SSH)
bash tests/e2e_dogfood_local.sh

# 3. Local 3-instance dogfood (Phase B, contacts + groups, ~5 s)
bash tests/e2e_dogfood_groups.sh

# 4. Local Phase-A DM matrix smoke (3 daemons, no VPS, no SSH)
bash tests/e2e_local_mesh.sh

# 5. Local comprehensive test (legacy curl-driven, ~2 min)
bash tests/e2e_comprehensive.sh

# 6. Live network test (local node joins real bootstrap, ~3 min)
#    Requires: VPS nodes running, SSH access
bash tests/e2e_live_network.sh

# 7. Deploy to VPS — cross-compile + push x0xd + push runner + verify (~5 min)
#    Add --mesh-verify to chain Phase A + B verification via 1 SSH tunnel
bash tests/e2e_deploy.sh                          # SSH-only verification
bash tests/e2e_deploy.sh --mesh-verify            # + Phase A + B mesh checks

# 8a. VPS Phase-A DM matrix (RECOMMENDED for cross-region DM proof, ~16 s)
python3 tests/e2e_vps_mesh.py --anchor nyc --discover-secs 30 --settle-secs 60

# 8b. VPS Phase-B groups + contacts dogfood (up to 49 assertions, ~60 s)
python3 tests/e2e_vps_groups.py --anchor nyc --discover-secs 45

# 8c. VPS legacy SSH-per-call test (still useful for surface coverage, ~4 min)
bash tests/e2e_vps.sh

# 9. Health check (quick VPS status)
bash .deployment/health-check.sh              # basic
bash .deployment/health-check.sh --extended   # with peer counts
```

## VPS Port Configuration

| Port | Protocol | Purpose | Binding |
|------|----------|---------|---------|
| **5483** | UDP/QUIC | Transport (gossip network) | `[::]:5483` or `0.0.0.0:5483` |
| **12600** | TCP/HTTP | REST API on VPS nodes | `127.0.0.1:12600` (configured in `/etc/x0x/config.toml`) |
| **12700** | TCP/HTTP | REST API default (local dev) | `127.0.0.1:12700` (default when no config) |

VPS API tokens are at `/root/.local/share/x0x/api-token` on Linux nodes.

## SSH Notes for macOS

When running tests that SSH to multiple VPS nodes sequentially, use `-o ControlMaster=no -o ControlPath=none -o BatchMode=yes` to avoid SSH multiplexing hangs. The health check and VPS test scripts already include these flags.
