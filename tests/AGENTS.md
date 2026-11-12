# tests/ — Test Suite Reference

Loaded when working on files in `tests/`. The root `AGENTS.md` covers architecture and how to run tests in isolation.

## Network safety

Test daemons join the real network. Some in-process tests also dial real seeds — including `nat_traversal_integration.rs` `--ignored` VPS tests, `vps_e2e_integration.rs`, and `e2e_live_network.sh`. "No daemon started" does not mean "no network". Run all tests via `just test` or `python3 scripts/dev/test-isolated.py` (Linux loopback-only namespace; macOS/Windows fail closed). Plain `cargo nextest run` only for a selector confirmed to open no network.

## Integration tests

A core subset; `tests/` holds many more files.

| File | Coverage |
|------|---------|
| `agent_usability_eval.rs` | Scripted agent: DM, group join, scratch KV on a hermetic pair. `#[ignore]`; fast half runs un-ignored |
| `identity_integration.rs` | Three-layer identity, keypair management, certificates |
| `identity_unification_test.rs` | machine_id == ant-quic PeerId, announcement key derivation |
| `trust_evaluation_test.rs` | TrustEvaluator, machine pinning, ContactStore |
| `announcement_test.rs` | Announcement round-trips, NAT fields, discovery cache |
| `connectivity_test.rs` | ReachabilityInfo, ConnectOutcome, connect_to_agent() |
| `identity_announcement_integration.rs` | Signature verification, TTL expiry, shard topics |
| `crdt_integration.rs` | TaskList CRUD, state transitions |
| `crdt_convergence_concurrent.rs` | Concurrent CRDT convergence |
| `crdt_partition_tolerance.rs` | Partition and recovery |
| `mls_integration.rs` | Group encryption, key rotation |
| `f1_gss_remove_live.rs` | Admin remove rotates GSS secret. `--ignored`; run via `just adr-gates-f1-live` |
| `network_integration.rs` | Bootstrap connection |
| `network_timeout.rs` | Connection timeouts |
| `nat_traversal_integration.rs` | NAT hole-punching |
| `comprehensive_integration.rs` | End-to-end workflows |
| `scale_testing.rs` | Performance with many agents |
| `presence_foaf_integration.rs` | Presence beacons, FOAF, trust-scoped visibility |
| `presence_wiring_test.rs` | PresenceWrapper lifecycle, config defaults, shutdown |
| `presence_integration.rs` | subscribe, cached_agent, foaf_peer_candidates |
| `kv_store_integration.rs` | KV CRUD, access policies, CRDT sync |
| `kv_first_join_bootstrap.rs` | Cold first-join bootstrap. Daemon-backed, `--ignored` |
| `kv_signed_store_auth.rs` | Signed-store local-write enforcement. Daemon-backed, `--ignored` |
| `tasklist_first_join_bootstrap.rs` | Task-list cold first-join + LWW delta merge. Daemon-backed, `--ignored` |
| `local_topics.rs` | `local:` topics same-daemon only. Daemon-backed, `--ignored` |
| `named_group_integration.rs` | Named groups, invites, join/leave, display names |
| `owner_retirement.rs` | Owner retirement / flat Admin authority |
| `membership_authority.rs` | add/remove/ban authority |
| `last_admin_invariant.rs` | No commit leaves zero active admins |
| `invite_authority.rs` | Invite-issue authority and creator provenance |
| `bootstrap_cache_integration.rs` | Bootstrap cache persistence, quality scoring |
| `daemon_api_integration.rs` | Daemon REST API endpoint coverage |
| `direct_messaging_integration.rs` | Direct send/receive, connection lifecycle |
| `upgrade_integration.rs` | Self-update manifest signing, verification, rollout |
| `vps_e2e_integration.rs` | VPS bootstrap node end-to-end |

## E2E scripts

| Script | Scope | Notes |
|--------|-------|-------|
| `e2e_dogfood_local.sh` | 2-instance local | ~20 assertions, ~5 s. Pre-commit smoke |
| `e2e_dogfood_groups.sh` | 3-instance local groups | ~29 assertions, ~5 s |
| `e2e_local_mesh.sh` | 3-instance local DM matrix | 6 directed pairs, no VPS |
| `e2e_comprehensive.sh` | Local alice+bob+charlie | ~2 min |
| `e2e_live_network.sh` | Local node → live VPS mesh | ~66 assertions; needs VPS up and SSH access |
| `e2e_vps_mesh.py` | 6 VPS DM matrix | 30 directed pairs via 1 SSH tunnel, ~16 s |
| `e2e_vps_groups.py` | 6 VPS groups + contacts | up to 49 assertions, ~60 s |
| `e2e_vps.sh` | 6 VPS SSH-per-call | ~102 assertions, ~4 min |
| `e2e_vps_kv.py` | Testnet group-store | Needs `--allow-service-restart`; testnet only |
| `e2e_vps_survivor_rekey.py` | Testnet GSS + TreeKEM rekey | Needs `--nodes` (≥5), `--allow-service-restart` for `restart` variant |
| `e2e_deploy.sh` | Build + deploy to 6 VPS nodes | `--mesh-verify` chains Phase A + B after deploy |

Quick commands:

```bash
bash tests/e2e_dogfood_local.sh
bash tests/e2e_dogfood_groups.sh
python3 tests/e2e_vps_mesh.py --anchor nyc --discover-secs 30 --settle-secs 60
python3 tests/e2e_vps_groups.py --anchor nyc --discover-secs 45
bash tests/e2e_deploy.sh --mesh-verify
bash .deployment/health-check.sh --extended
```

## VPS ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 5483 | UDP/QUIC | Transport (gossip network) |
| 12600 | TCP/HTTP | REST API on VPS nodes (`127.0.0.1:12600`, `/etc/x0x/config.toml`) |
| 12700 | TCP/HTTP | REST API default for local dev |

VPS API tokens: `/root/.local/share/x0x/api-token`.

SSH to multiple nodes: use `-o ControlMaster=no -o ControlPath=none -o BatchMode=yes`.
