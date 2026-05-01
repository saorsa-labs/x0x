# x0x Comprehensive Test Suite Guide

**x0x version:** 0.19.17
**Last updated:** 2026-05-01

This document describes the production test architecture for x0x — Rust
unit/integration tests, end-to-end shell harnesses, GUI parity checks, and
the cross-surface parity proofs against Communitas (Dioxus + Apple).

The capability source of truth is [`docs/parity-matrix.md`](docs/parity-matrix.md):
every capability in x0x must be reachable — and behave identically — from
every supported surface (REST, CLI, embedded GUI, Communitas Dioxus,
Communitas Apple). Each row in the matrix is backed by a test in this
guide.

---

## Test Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  tests/e2e_proof_runner.sh --all     (single-command release proof)  │
└──────────────────────────────────────────────────────────────────────┘
       │
       ├── --rust-tests       cargo nextest (52 integration files, 1006+ tests)
       ├── --comprehensive    tests/e2e_comprehensive.sh          (3 local daemons)
       ├── --stress           tests/e2e_stress_gossip.sh          (drop detection)
       ├── --chrome           tests/e2e_gui_chrome.mjs            (Playwright GUI)
       ├── --dioxus           tests/e2e_communitas_dioxus.sh      (Dioxus IPC)
       ├── --xcuitest         CommunitasGoldenPathsUITests.swift  (Apple UI)
       ├── --vps              tests/e2e_vps.sh                    (6 region matrix, SSH-per-call, legacy)
       ├── --vps-mesh         tests/e2e_vps_mesh.py               (6 region matrix, mesh-relay)
       ├── --vps-groups       tests/e2e_vps_groups.py             (6 region groups + contacts dogfood)
       ├── --dogfood-local    tests/e2e_dogfood_local.sh          (2-instance ~5 s smoke)
       ├── --dogfood-groups   tests/e2e_dogfood_groups.sh         (3-instance groups dogfood)
       └── --lan              tests/e2e_lan.sh                    (Mac Studios)
```

> **Dogfood harness family — Phases A/B/C/D.** A coordinated set of
> harnesses that exercise x0x via x0x's own primitives (DMs, named
> groups, group messages) instead of curl-from-outside. They share a
> single Phase-A wire protocol (`x0xtest|cmd|`/`res|`/`hop|` payload
> prefixes) implemented by `tests/runners/x0x_test_runner.py` deployed
> as a systemd service on every VPS. The Mac harness opens **one** SSH
> tunnel to an anchor node — every assertion thereafter is a real
> protocol round-trip.
>
> | Phase | Harness | Use |
> |---|---|---|
> | A | `e2e_vps_mesh.py` | All-pairs DM matrix (§7b) |
> | B | `e2e_vps_groups.py` / `e2e_dogfood_groups.sh` | Groups + contacts (§7c) |
> | C | `e2e_deploy.sh --mesh-verify` | Deploy + integrated mesh verification (§7d) |
> | D | `e2e_dogfood_local.sh` | Fast 2-instance pre-commit smoke, ~5 s (§7e) |

Every phase writes proof artefacts under `proofs/<timestamp>/` so a release
can be replayed and audited after the fact.

---

## 1. Rust Unit + Integration Tests

**Runner:** `cargo nextest run --all-features --workspace`

**Scope:** 52 integration files in `tests/`, plus inline `#[cfg(test)]`
modules. ~1,006 tests at last release-blocking run.

Highlights (full inventory in `tests/`):

| File | Coverage |
|------|----------|
| `identity_integration.rs` | Three-layer identity, keypair management, certificates |
| `identity_unification_test.rs` | `MachineId == ant-quic PeerId`, announcement key derivation |
| `trust_evaluation_test.rs` | TrustEvaluator decisions, machine pinning, ContactStore mutations |
| `announcement_test.rs` | Announcement round-trips, NAT fields, discovery cache, reachability |
| `connectivity_test.rs` | ReachabilityInfo heuristics, ConnectOutcome, `connect_to_agent()` |
| `peer_lifecycle_integration.rs` | ant-quic 0.27.x lifecycle bus events |
| `crdt_integration.rs` / `crdt_convergence_concurrent.rs` / `crdt_partition_tolerance.rs` | TaskList CRUD, CRDT convergence, partition recovery |
| `kv_store_integration.rs` | KV CRUD, access policies, CRDT sync |
| `mls_integration.rs` | Group encryption, key rotation |
| `named_group_integration.rs` + `named_group_*` | Named groups, invites, policy, public messages, state-commit, C2 live, D4 apply, E live |
| `direct_messaging_integration.rs` | Direct send/receive, connection lifecycle |
| `exec_acl_unit.rs` + inline `src/exec/service.rs` tests | Tier-1 exec ACL parsing, strict argv templates, shell metachar rejection, output cap/drain state, duration cap, concurrency slots, frame prefix routing |
| `file_transfer_integration.rs` | Send / accept / reject / progress |
| `presence_*` | Beacons, FOAF, adaptive failure detection |
| `nat_traversal_integration.rs` | NAT hole-punching |
| `bootstrap_cache_integration.rs` | Cache persistence, quality scoring |
| `gossip_cache_adapter_integration.rs` | Gossip cache adapter wrapping bootstrap cache |
| `rendezvous_integration.rs` | Rendezvous shard discovery |
| `upgrade_integration.rs` | Self-update manifest signing, verification, rollout |
| `vps_e2e_integration.rs` | VPS bootstrap node smoke |
| `api_coverage.rs` + `api_manifest.rs` + `parity_cli.rs` | REST/CLI parity (every endpoint has a CLI command) |
| `gui_smoke.rs` + `gui_named_group_parity.rs` | Embedded GUI smoke + named-group parity |
| `ant_quic_0272_surface.rs` | Pass-through smoke for new ant-quic 0.27.x surfaces |
| `proptest_*` | Property-based tests for connectivity, CRDT, files, groups, KV, direct-msg |

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features --workspace
```

CI builds enforce `RUSTDOCFLAGS="-D warnings"` on `cargo doc --all-features --no-deps`.

---

## 2. Local End-to-End — `e2e_comprehensive.sh`

**Path:** `tests/e2e_comprehensive.sh`
**Scope:** 3 local daemons (`alice`, `bob`, `charlie`) on isolated ports +
identity dirs, exercising **all 75+ REST endpoints** across 19 categories.

What it covers:

- Contacts lifecycle (add / block / trust / forget)
- Machine pinning enforcement
- Trust evaluator — all 5 decision paths
- MLS group full lifecycle (add / remove / re-add / encrypt / decrypt)
- Named groups (invite validation, leave / rejoin, policy, roles, bans)
- KV stores (multi-key, update, access control)
- Presence — every endpoint (`/presence/online`, `/foaf`, `/find/:id`,
  `/status/:id`, `/events` SSE)
- Direct messaging round-trip
- Pub/sub publish + subscribe + WebSocket live feed
- File transfer offer / accept / reject
- Self-update apply (`POST /upgrade/apply` concurrency)
- Diagnostics endpoints (`/diagnostics/connectivity`, `/diagnostics/gossip`, `/diagnostics/dm`, `/diagnostics/exec`)
- Seedless (`charlie` with `--no-hard-coded-bootstrap`) bootstrap

```bash
cargo build --release
bash tests/e2e_comprehensive.sh                  # ~2 min
```

---

## 3. Local Exec End-to-End — `e2e_exec.sh`

**Path:** `tests/e2e_exec.sh`
**Scope:** 2 local daemons with restart-loaded exec ACLs. This is the
Tier-1 SSH-free remote-exec acceptance harness.

What it covers:

- Stable agent/machine identity capture before ACL generation
- Explicit `--exec-acl <PATH>` startup on both daemons
- Trusted card exchange and mesh/gossip-DM delivery
- Successful allowlisted argv over `POST /exec/run`
- Structured `argv_not_allowed` denial for a mismatched argv
- `stdin_b64` to `/bin/cat` with stdout cap truncation and warning frames
- `/exec/sessions`, `/diagnostics/exec`, and JSONL audit events for
  request, denial, warning, and truncated exit

```bash
cargo build --release --bin x0xd
bash tests/e2e_exec.sh
```

---

## 4. Gossip Stress / Drop Detection — `e2e_stress_gossip.sh`

**Path:** `tests/e2e_stress_gossip.sh`
**Scope:** N-daemon stress harness that asserts the delivery claim it
documents. Strictly enforces
`delivered_to_subscriber >= MESSAGES * MIN_DELIVERY_RATIO`
(default 1.0) — i.e. **zero drops on every subscriber**, not just zero
drops on the publisher.

Powered by the `GET /diagnostics/gossip` endpoint introduced in v0.18.0,
which exposes atomic counters at every stage of the pipeline:

```
publish → incoming → decoded → delivered → subscriber-channel-closed
```

The harness fails fast if any subscriber's `decoded → delivered`
delta is non-zero, isolating drops above the wire and below the app.

```bash
MESSAGES=500 SETTLE_SECS=15 PUBLISH_DELAY_MS=20 \
  bash tests/e2e_stress_gossip.sh
```

Related load-isolation harnesses in the same family:

- `tests/e2e_hunt12c_pubsub_load_isolation.sh` — pubsub under load
- `tests/e2e_hunt12e_release_manifest_storm.sh` — release-manifest flood
- `tests/e2e_slow_consumer.sh` — back-pressure handling
- `tests/e2e_soak_3node.sh` — long-running 3-node soak
- `tests/leak_hunt_idle.sh` / `tests/leak_hunt_publisher.sh` — memory leak hunts

---

## 5. GUI Parity — Chrome / Playwright

**Path:** `tests/e2e_gui_chrome.mjs` (driver) + `tests/e2e_gui_chrome.sh`
(wrapper)

Drives `src/gui/x0x-gui.html` via real Chrome and asserts every capability
in [`docs/parity-matrix.md`](docs/parity-matrix.md) round-trips against the
live `x0xd` daemon — same-origin via the daemon's `/gui` route.

Captures rich proof artefacts:

| Artefact | Purpose |
|----------|---------|
| `chrome-gui.har` | Full network HAR |
| `chrome-gui.console.jsonl` | Console log stream |
| `chrome-gui.screenshot.png` | Final-state screenshot |
| `gui-parity-report.json` | Per-capability pass/fail matrix |

Recent runs (e.g. `proofs/chrome-20260421-v0182/`) verify 13/13 GUI
capabilities including live pubsub round-trip, named-group invite/join,
KV CRUD, presence FOAF, and self-upgrade.

```bash
# Prereq (one-off)
npx playwright install chromium

# Run (daemon must be up on http://127.0.0.1:12700)
node tests/e2e_gui_chrome.mjs --proof-dir proofs/chrome-$(date +%s)
```

A complementary fast smoke variant lives in `tests/gui_smoke.rs` and
`tests/gui_named_group_parity.rs` (pure Rust, runs under nextest).

---

## 6. Communitas Dioxus Parity

**Top-level harness:** `tests/e2e_communitas_dioxus.sh` (in this repo)
**Detailed harness:** `../communitas/communitas-dioxus/tests/e2e/` +
`../communitas/communitas-dioxus/tests/e2e.sh`

The Dioxus desktop app consumes `communitas-x0x-client` directly. The
e2e harness drives it with `COMMUNITAS_TEST_MODE=1` and exercises the
golden paths via the app's built-in JSON IPC test hooks, asserting each
capability round-trips against a live `x0xd` daemon.

Per-feature E2E test modules in `communitas-dioxus/tests/e2e/`:

- `identity.rs` — agent ID / card, import, export
- `connectivity.rs` — connect, probe, health snapshot, peer lifecycle
- `groups.rs` — create, invite, join, policy, leave
- `kv_store.rs` — CRUD, access policies
- `presence.rs` — online, FOAF, find, status, SSE
- `trust_contacts.rs` — add / block / trust + machine pinning
- `upgrade.rs` — self-update apply

```bash
# From x0x repo root (daemon must be running on 12700)
bash tests/e2e_communitas_dioxus.sh                # quick smoke

# Full Dioxus parity sweep with proof bundle
cd ../communitas/communitas-dioxus
bash tests/e2e.sh                                  # writes proofs/dioxus-parity-YYYYMMDD/
```

---

## 7. Communitas Apple Parity — XCUITest

**Path:** `../communitas/communitas-apple/Tests/CommunitasUITests/CommunitasGoldenPathsUITests.swift`

UI-level golden-path tests that drive the full macOS app via
`XCUIApplication` and verify every capability in the parity matrix is
reachable from the Apple surface. Intentionally narrow but real — each
test walks one end-to-end flow and asserts on observable UI state, not
private APIs.

**16 golden paths** at v0.19.x:

1. App launches and shows identity
2. Direct-message composer surfaces send result
3. Publish + subscribe topic
4. Create + join named group
5. KV store round-trip
6. Identity export surface reachable
7. Connect-agent surface reachable
8. Discover-agents list present
9. Four-word bootstrap input present
10. Live feed reachable
11. File-transfer send button present
12. Group policy surface reachable
13. Group discover surface reachable
14. Presence FOAF button present
15. Presence status surface reachable
16. Presence SSE toast wiring

```bash
# Prereq: x0xd running on 127.0.0.1:12700, app signed (or ad-hoc) so
# XCUITest can launch it.
cd ../communitas/communitas-apple
xcodebuild \
  -scheme Communitas \
  -destination 'platform=macOS' \
  -only-testing:CommunitasUITests \
  test
```

CI machines without a macOS runner can set `XCUITEST_SKIP=1` to fast-pass.

A complementary live-daemon Swift unit-test layer lives in
`Tests/X0xClientTests/` with `DaemonFixture` (`X0X_LIVE_TESTS=1 swift test`)
covering identity / trust / KV wire-shape decoding.

---

## 8. Multi-Region VPS Test — `e2e_vps.sh`

**Path:** `tests/e2e_vps.sh`
**Scope:** 6 production bootstrap nodes, all-pairs matrix.

| Node | IP | Location | Provider | saorsa- |
|------|-------------|----------|----------|--------|
| NYC | 142.93.199.50 | New York, US | DigitalOcean | saorsa-2 |
| SFO | 147.182.234.192 | San Francisco, US | DigitalOcean | saorsa-3 |
| Helsinki | 65.21.157.229 | Helsinki, FI | Hetzner | saorsa-6 |
| Nuremberg | 116.203.101.172 | Nuremberg, DE | Hetzner | saorsa-7 |
| Singapore | 152.42.210.67 | Singapore, SG | DigitalOcean | saorsa-8 |
| Sydney | 170.64.176.102 | Sydney, AU | DigitalOcean | saorsa-9 |

What it asserts (~102 assertions):

- Health, identity, mesh state on all 6 nodes
- All-pairs direct messaging matrix (**30 directed pairs**)
- Three independent surface proofs per pair: REST API, CLI, GUI (WebSocket)
- MLS group encryption across continents
- Named groups, KV stores, task lists, file transfer
- Presence (FOAF, online, find, status)
- Contacts & trust lifecycle
- Constitution serving, self-upgrade, WebSocket session lifecycle

Every assertion either echoes actual API data or verifies a round-trip with
a unique `PROOF_TOKEN` — no hallucinated test results.

```bash
# 1. Cross-compile + deploy + collect tokens (writes tests/.vps-tokens.env)
bash tests/e2e_deploy.sh                           # ~5 min

# 2. Run multi-region matrix (SSH-per-call; legacy harness)
bash tests/e2e_vps.sh                              # ~4 min, SSH-bound
```

### VPS Port Configuration

| Port | Protocol | Purpose | Binding |
|------|----------|---------|---------|
| **5483** | UDP/QUIC | Transport (gossip network) | `[::]:5483` or `0.0.0.0:5483` |
| **12600** | TCP/HTTP | REST API on VPS nodes | `127.0.0.1:12600` (`/etc/x0x/config.toml`) |
| **12700** | TCP/HTTP | REST API local-dev default | `127.0.0.1:12700` |

API tokens live at `/root/.local/share/x0x/api-token` on the VPS nodes;
`e2e_deploy.sh` collects them into `tests/.vps-tokens.env`.

### SSH Notes for macOS

Sequential multi-host SSH on macOS needs
`-o ControlMaster=no -o ControlPath=none -o BatchMode=yes` to avoid
multiplexing hangs. The harness already passes these flags. Even with
those flags, the legacy `e2e_vps.sh` issues 60+ SSH+curl pairs in tight
loops — Sydney/Singapore have ~4 s SSH RTT from a US/EU laptop, so the
test is dominated by harness startup cost rather than daemon latency.
Use the mesh harness in §7b for clean cross-region results.

### Why send/receive failures in `e2e_vps.sh` are usually harness noise

If a run reports `{"error":"curl_failed"}` on Singapore- or Sydney-targeted
calls, the failure happened at the SSH/curl layer **before** the daemon
ever saw the request. Confirm with a manual probe:

```bash
time ssh -o ControlMaster=no -o ControlPath=none -o BatchMode=yes \
  root@<singapore_ip> "curl -sf http://127.0.0.1:12600/health"
```

A 4 s+ wall-clock here matches the failure pattern. Switch to
`e2e_vps_mesh.py` (§7b) to remove SSH from the per-assertion path.

---

## 7b. Mesh-Driven VPS Test — `e2e_vps_mesh.py` *(recommended)*

**Path:** `tests/e2e_vps_mesh.py` (orchestrator) + `tests/runners/x0x_test_runner.py`
(per-node service) + `tests/runners/x0x-test-runner.service` (systemd unit)

**Scope:** same all-pairs DM matrix as `e2e_vps.sh`, but drives every
remote action through x0x's own pubsub instead of through SSH.

### Architecture

```
Mac orchestrator ──── 1 SSH tunnel ───► NYC daemon ──── QUIC mesh ────► all 6 nodes
       │                                    │
       │ /publish        x0x.test.control.v1│
       │ /events SSE     x0x.test.results.v1│
       │                                    │
       └── publishes commands ──┐           ├── runner on each node:
                                │           │    • subscribes to control topic
                                │           │    • subscribes to /direct/events
                                │           │    • executes targeted commands
                                │           │    • publishes results
                                ▼           ▼
                               <every result/receipt arrives via the same SSE>
```

The orchestrator opens **one** SSH connection (a port-forward), subscribes
to the results topic, fans out 30 directed-pair `send_dm` commands on the
control topic, and tabulates the responses as they stream back. Every
remote action — including the `/direct/send` call on the source node and
the `/direct/events` SSE on the destination node — happens *inside* the
fleet, with no further SSH involved.

### Protocol — Phase A (direct-DM control plane)

Pubsub is used **once**, for the orchestrator's discover announcement.
Every subsequent command and every result envelope flows as a direct
DM. Three payload prefixes keep the routing stateless:

| Prefix | Direction | Payload |
|---|---|---|
| `x0xtest\|cmd\|<b64-json>` | orchestrator → runner | command envelope `{command_id, target_node, action, anchor_aid, params}` |
| `x0xtest\|res\|<b64-json>` | runner → orchestrator | result envelope `{command_id, request_id, node, kind, outcome, agent_id, machine_id, digest_marker, details, ts_ms}` |
| `x0xtest\|hop\|<rid>\|<digest>\|<anchor_aid>\|<payload>` | runner → runner | actual matrix test traffic; receiver DMs a `res` `received_dm` back to the embedded `anchor_aid` |

One-shot pubsub topic:

| Topic | Use |
|---|---|
| `x0x.test.discover.v1` | orchestrator publishes one envelope per harness run carrying the anchor's `agent_id`; runners reply via DM |

Legacy compatibility:

| Topic | Use |
|---|---|
| `x0x.test.control.v1` | runners still subscribed; the orchestrator publishes here when sending a command to its own collocated runner (a self-DM would be refused by the daemon) |
| `x0x.test.results.v1` | the runner falls back to publishing here if a result DM fails irretrievably; the orchestrator subscribes opportunistically |

Actions: `discover`, `send_dm`, `noop_ack`. Result kinds:
`runner_ready`, `discover_reply`, `send_result`, `received_dm`, `ack`,
`error`.

`digest_marker` is a BLAKE3 prefix of the user payload — identical on
the sender and receiver — so the orchestrator can pair every
`send_result` with its `received_dm` independent of timing.

Command, result, and test-hop DMs intentionally **do not** request
`raw_quic_acked` by default — they ride the daemon's default path
(gossip-inbox first, with one retry) so brief raw-QUIC supersedes do not
drop harness control/result traffic. The harness's `send_result` and
`received_dm` envelopes are the application-level delivery proof.

### Deployment

Runners are installed automatically by `e2e_deploy.sh` (after the binary
upload):

```bash
bash tests/e2e_deploy.sh                           # also pushes:
#   /usr/local/bin/x0x-test-runner.py
#   /etc/systemd/system/x0x-test-runner.service
#   /etc/x0x-test-runner.env  (NODE_NAME=…, X0X_API_TOKEN=…)
# and runs:
#   systemctl daemon-reload && systemctl enable --now x0x-test-runner
```

Confirm the runner is healthy on every node:

```bash
for ip in 142.93.199.50 147.182.234.192 65.21.157.229 \
          116.203.101.172 152.42.210.67 170.64.176.102; do
  out=$(ssh -o BatchMode=yes root@$ip \
    "systemctl is-active x0x-test-runner; cat /etc/x0x-test-runner.env" \
    | tr '\n' ' ')
  echo "$ip: $out"
done
# Expect each line to start with "active NODE_NAME=…"
```

### Running the harness

```bash
# Live fleet (any node can be the anchor):
python3 tests/e2e_vps_mesh.py --anchor nyc --discover-secs 30 --settle-secs 60
python3 tests/e2e_vps_mesh.py --anchor sydney --local-port 22601

# Local 3-node smoke (no SSH, no VPS):
bash tests/e2e_local_mesh.sh
```

Reference Phase-A runs (v0.19.17 fleet, fresh deploy):

| Run | Anchor | Sent | Received | Send fails | Receive misses | Wall-clock |
|---|---|---|---|---|---|---|
| 1 | NYC | 29/30 | **30/30** | 1 (real `peer_disconnected`) | 0 | ~70 s |
| 2 | NYC | 29/30 | **30/30** | 1 (real `peer_disconnected`) | 0 | ~70 s |
| 3 | NYC | **30/30** | **30/30** | 0 | 0 | ~28 s |

Phase A's defining property: discover is bulletproof (6/6 every run,
including back-to-back) and **receives are 100%**. The only sends that
ever fail now are those mapped to a real cross-region QUIC supersede;
they surface as the structured `peer_disconnected` error from §6 of
[`docs/design/p2p-timeout-elimination.md`](docs/design/p2p-timeout-elimination.md),
not as harness flakes.

These three back-to-back runs satisfy criterion #1 of
[`docs/design/p2p-timeout-elimination.md`](docs/design/p2p-timeout-elimination.md)
("0/30 send fails and 0/30 receive misses on the live 6-VPS fleet, with no
harness timeout changes") with no harness flakes. The same fleet under
`e2e_vps.sh` reported 11/30 send fails + 14/30 receive misses purely from
SSH-layer noise.

### When to use which

| Scenario | Use |
|---|---|
| Release proof for cross-region DM correctness | **`e2e_vps_mesh.py`** |
| Proving REST/CLI/GUI surfaces all reach every endpoint on the live fleet | `e2e_vps.sh` (covers contacts, MLS, named groups, KV, presence, file transfer, constitution, upgrade — `e2e_vps_mesh.py` only covers the DM matrix at this writing) |
| `/loop`-able recurring fleet health probe | **`e2e_vps_mesh.py`** (~16 s, single SSH tunnel) |
| Investigating SSH-layer / harness flakes themselves | `e2e_vps.sh` |

### Local smoke

`tests/e2e_local_mesh.sh` boots three local daemons (`alice` / `bob` /
`charlie`), spawns a runner per daemon, and runs the orchestrator with
`--no-tunnel` against `alice`'s API. Useful for proving the protocol
without touching the VPS — the full 6-pair matrix completes in ~1 s.

### Extending the protocol

Add new actions in three places:

1. **`tests/runners/x0x_test_runner.py`** — handle the new `action` value
   in `_dispatch_command()` and publish a result with a new `kind`.
2. **`tests/e2e_vps_mesh.py`** — add a queue / route in `ResultsBus` and a
   collector method in the orchestrator.
3. **`docs/parity-matrix.md`** — link the new mesh assertion to its REST
   row so we can see at a glance which capabilities are mesh-tested.

Keep payloads small: every command/result envelope rides the gossip
fabric and counts toward the same drop-detection counters as application
traffic. Tests that need to push large payloads should use
`e2e_stress_gossip.sh` (§3) instead.

---

## 7c. Group + Contacts Dogfood — `e2e_vps_groups.py` / `e2e_dogfood_groups.sh`

**Path:** `tests/e2e_vps_groups.py` (live fleet) +
`tests/e2e_dogfood_groups.sh` (3-instance local) +
`tests/e2e_dogfood_groups.py` (orchestrator shared by both)

Phase B of the dogfood family. Where Phase A (§7b) tests the DM matrix,
Phase B tests **named groups + contacts** entirely through x0x's own
primitives. Every assertion is the result of:

- a direct DM round-trip (orchestrator → runner → orchestrator), or
- a group-message round-trip (anchor posts in a group, members reply
  in the same group, anchor reads `/groups/:id/messages`)

### Scenarios

| Scenario | Assertions per runner |
|---|---|
| Contacts lifecycle | add → list-contains → Trusted → Blocked → remove → list-no-longer-contains (4 assertions) |
| Group create / invite | anchor creates `public_open` group, mints one one-time `x0x://invite/...` link per joiner |
| Group join | each runner joins via its own invite (1/runner) |
| Local roster | each member's own `/groups/:id/members` shows themselves (1/runner) |
| Owner roster convergence | anchor's `/groups/:id/members` includes every joined runner before replies are sent |
| Group send | anchor posts kickoff, each runner posts reply (1+N) |
| Local/owner message cache | each member sees their own body; anchor sees every runner reply |
| Group leave | leaver's `/groups` no longer lists the group (1) |

For 6 fleet runners: up to **50+ blocking assertions per run** depending on
fleet size.

### Cross-member convergence — hard gate

The owner-side convergence check is now blocking. Joiners publish a signed
`MemberJoined` request, the original inviter consumes the one-time invite and
publishes an authority-signed `MemberAdded` commit, and the harness waits for
the anchor roster to converge before replies are sent. The anchor must then see
each member's reply in `/groups/:id/messages`.

### Running

```bash
# Local 3-instance smoke (alice + bob + charlie)
bash tests/e2e_dogfood_groups.sh                   # ~5 s

# Live 6-VPS fleet (after e2e_deploy.sh has installed the runner)
python3 tests/e2e_vps_groups.py --anchor nyc --discover-secs 45
```

### Resilience

Release mode is strict: every expected runner must be discovered and join.
For operational resilience drills, pass `--allow-skips` to validate the
reachable subset while logging skipped nodes distinctly in the JSON report.

---

## 7d. Deploy + Mesh Verification — `e2e_deploy.sh --mesh-verify`

**Path:** `tests/e2e_deploy.sh` (extended with the `--mesh-verify` flag
or `MESH_VERIFY=1` env)

Phase C of the dogfood family. After cross-compiling, uploading the
new `x0xd` binary, restarting the service, and running the existing
24 SSH+curl post-deploy checks, the script optionally fans out into
**both** mesh harnesses sharing a single SSH tunnel:

1. `e2e_vps_mesh.py` — Phase-A 30-pair DM matrix
2. `e2e_vps_groups.py` — Phase-B groups + contacts dogfood

The mesh-verify exit code is added to the deploy fail count, so a
deploy that succeeded at the SSH layer but produces matrix failures
(real cross-region churn) flips the overall result to non-zero.

```bash
# Deploy + integrated mesh verification
bash tests/e2e_deploy.sh --mesh-verify

# Or with a different anchor
MESH_ANCHOR=sydney bash tests/e2e_deploy.sh --mesh-verify

# Skip mesh-verify (default; legacy SSH-only verification)
bash tests/e2e_deploy.sh
```

### What this gives you

- Reduces the deploy verification surface from `4 metrics × 6 nodes = 24
  SSH+curl pairs` to **one** SSH tunnel + protocol DMs
- Turns deploy verification into a real cross-protocol round-trip — DMs,
  named-group create/invite/join/post, contacts CRUD — exercised on the
  freshly-deployed binary
- Surfaces real cross-region issues (e.g. a Helsinki↔Sydney supersede
  burst at deploy time) as the mesh-verify failure rather than as silent
  drift

### What it doesn't yet cover

The binary push itself still needs SSH (cold-start). True
gossip-coordinated rolling deploy is documented in
[`docs/design/x0x-self-update-deploy.md`](docs/design/x0x-self-update-deploy.md)
as a deferred follow-up — it requires daemon-side work (test-mode
trust-key support + an `x0x upgrade publish` CLI verb).

---

## 7e. Fast Pre-Commit Smoke — `e2e_dogfood_local.sh`

**Path:** `tests/e2e_dogfood_local.sh` + `tests/e2e_dogfood_local.py`

Phase D of the dogfood family. The single-fastest end-to-end protocol
test x0x has: boots **two** local daemons (alice + bob), starts one
runner on bob, drives every assertion as a DM via Phase-A protocol.
Targets a ~5 s wall-clock budget so it can run on every commit
without slowing the dev loop.

### Coverage in 19 assertions

- Identity: anchor `/agent` returns 64-hex agent_id
- Contacts: add → list → Trusted → Blocked → remove → list (7 assertions)
- DM round-trip: hop DM `x0xtest|hop|...` from anchor → bob's runner
  echoes `received_dm` back via DM with `digest_marker` preserved
  (2 assertions)
- Named group: create + invite + join + each member posts + each
  member sees own message in cache + leave + list-no-longer-lists
  (10 assertions)

### Running

```bash
# Build + run (pre-commit: cargo build --release && tests/e2e_dogfood_local.sh)
cargo build --release --bin x0xd
bash tests/e2e_dogfood_local.sh                    # ~5 s
```

### Why "Phase D" specifically

The legacy local smoke (`e2e_comprehensive.sh`, §2) takes ~2 minutes
because it walks **every** REST endpoint over curl. Phase D takes ~5 s
because it walks the **protocol** end-to-end with structured DMs and
group operations — the same coverage class real apps exercise. It's
the canonical "did I break the protocol" first-line test.

---

## 9. Live Network Test — `e2e_live_network.sh`

**Path:** `tests/e2e_live_network.sh`
**Scope:** Local node joins the real bootstrap mesh and exercises
bidirectional flows with VPS members (~66 assertions).

Covers:

- Direct messaging local ↔ VPS in both directions
- Pub/sub across the live mesh
- MLS groups with VPS members
- Named-group invites across the network
- Presence discovery from local through VPS

```bash
bash tests/e2e_live_network.sh                     # ~3 min (needs VPS up)
```

---

## 10. LAN Test — `e2e_lan.sh`

**Path:** `tests/e2e_lan.sh`
**Scope:** Two M3 Ultra Mac Studios with RDMA link, used for LAN /
mDNS / cross-host parity testing under realistic-but-controlled conditions.

```bash
bash tests/e2e_lan.sh                              # requires Mac Studio fleet
```

---

## 11. Master Orchestrator — `e2e_proof_runner.sh`

Single-command release proof. Each phase is opt-out-able; `--all`
runs the full battery and produces one machine-readable
`proofs/<timestamp>/proof-report.json` rolling up per-phase status.

```bash
# Full release proof (Mac with VPS + Studios access)
bash tests/e2e_proof_runner.sh --all

# Quick local-only sweep
bash tests/e2e_proof_runner.sh \
  --rust-tests --comprehensive --stress --chrome
```

Phases:

| Flag | Phase |
|------|-------|
| `--rust-tests` | `cargo nextest` workspace |
| `--comprehensive` | `e2e_comprehensive.sh` |
| `--dogfood-local` | `e2e_dogfood_local.sh` (~5 s, §7e) — pre-commit smoke |
| `--dogfood-groups` | `e2e_dogfood_groups.sh` (3-instance, §7c) |
| `--stress` | `e2e_stress_gossip.sh` |
| `--chrome` | `e2e_gui_chrome.mjs` |
| `--dioxus` | `e2e_communitas_dioxus.sh` |
| `--xcuitest` | `xcodebuild ... CommunitasUITests` (macOS only) |
| `--vps` | `e2e_vps.sh` (legacy SSH-per-call) |
| `--vps-mesh` | `e2e_vps_mesh.py` (mesh-relay, §7b — **recommended**) |
| `--vps-groups` | `e2e_vps_groups.py` (mesh groups + contacts, §7c) |
| `--lan` | `e2e_lan.sh` |
| `--all` | everything above |

> VPS phases require deployed runners and `tests/.vps-tokens.env` (or
> `X0X_TOKENS_FILE`). `e2e_vps_groups.py` is strict by default; pass
> `--allow-skips` only for resilience drills where validating a reachable
> subset is intentional.

---

## Health Checks (Quick Status)

```bash
# Quick VPS health
bash .deployment/health-check.sh                   # basic
bash .deployment/health-check.sh --extended        # with peer counts
```

---

## Currently Implemented Capabilities (Tested)

All capabilities below have round-trip coverage in the matrix; see
[`docs/parity-matrix.md`](docs/parity-matrix.md) for per-surface status.

**Network layer**
- QUIC transport (ant-quic 0.27.3 / 0.27.x, ML-DSA-65 / ML-KEM-768)
- ant-quic native first-party LAN discovery + UPnP
- NAT traversal via QUIC extension frames (`draft-seemann-quic-nat-traversal-02`),
  PUNCH_ME_NOW peer-ID hole-punching through coordinator
- MASQUE relay (RFC 9484)
- Address discovery (QUIC extension frames)
- Connection-supersede + lifecycle bus (`/peers/events`)

**Identity**
- MachineID (machine-bound; equals ant-quic PeerId)
- AgentID (portable, importable)
- UserID (optional, opt-in human identity)
- AgentCertificate binding agent ↔ user
- 4-word speakable identities (`four-word-networking`)
- `GET /introduction` with trust-gated service visibility

**Trust & contacts**
- ContactStore with `TrustLevel` and `IdentityType`
- TrustEvaluator (5 decision paths including Pinned)
- Machine pinning enforcement on every announcement

**Bootstrap**
- 6 hardcoded global nodes (port 5483)
- 3-round retry with exponential backoff
- Bootstrap cache enrichment from connections + presence beacons
- Quality-scored cache persistence

**Health & diagnostics**
- `GET /health`, `GET /agent`, `GET /agent/card`
- `GET /diagnostics/connectivity`
- `GET /diagnostics/gossip` (drop-detection counters at every pipeline stage)
- `GET /diagnostics/dm` (DM send/receive counters + per-peer RTT / path / lag state, this release)
- `/peers/events` SSE — connection lifecycle bus (Established / Replaced / Closing / Closed / ReaderExited)
- `dm.trace` correlation log (sender + receiver lines share a BLAKE3 `digest` field)
- 60-second NodeStatus journal snapshots

**Gossip**
- Pub/sub via epidemic broadcast
- CRDT task lists (OR-Set + LWW + RGA)
- CRDT KV stores with access control
- Presence beacons + FOAF discovery (Phi-Accrual lite, trust-scoped)
- Anti-entropy sync

**Encrypted groups**
- MLS group create / add / remove / re-add
- ChaCha20-Poly1305 encrypt / decrypt
- Welcome messages for new members

**Named groups**
- Create / invite / join / leave / rejoin
- Display names
- Policy (roles, bans)
- DHT-free discovery (social, tag shards, presence-social browsing)

**File transfer**
- Send / accept / reject offers
- Progress reporting

**Self-update**
- ML-DSA-65-signed release manifests
- Symmetric gossip propagation on `x0x/releases` topic
- GitHub fallback poll
- Atomic binary replacement with rollback
- Staged deterministic rollout

---

## Future Test Areas

These are **planned**, not yet wired into the proof runner:

- **Performance benchmarks** — message throughput, cross-continent latency,
  CRDT convergence time, memory under load
- **Stress amplification** — 1000s of concurrent tasks, 100s of agents
- **Chaos engineering** — random node failures, latency injection, packet
  loss, clock skew
- **Security testing** — explicit ML-DSA forgery / ML-KEM tamper /
  replay / Sybil suites (currently relies on `cargo audit` + crypto unit
  tests)

---

## Troubleshooting

### Service not running
```bash
ssh root@<IP> 'systemctl status x0xd'
ssh root@<IP> 'journalctl -u x0xd -n 50'
```

### Health endpoint unreachable
```bash
ssh root@<IP> 'curl http://127.0.0.1:12600/health'
ssh root@<IP> 'ss -tlpn | grep 12600'
```

### QUIC port not bound
```bash
ssh root@<IP> 'ss -ulpn | grep 5483'
ssh root@<IP> 'journalctl -u x0xd | grep "Bind address"'
```

### No peer connections
```bash
ssh root@<IP> 'journalctl -u x0xd --since "10 minutes ago" | grep -i connect'
```

### Drop detection
If `e2e_stress_gossip.sh` reports drops, query the live counter directly:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:12700/diagnostics/gossip | jq .
```

The `decode_to_delivery_drops` field localises drops to the
network-recv → subscriber-channel hop. Per-pid logs are produced when
`X0X_LOG_DIR` is set.

For DM-specific issues (matrix-receive misses, unexplained timeouts) query
`/diagnostics/dm` instead — it exposes per-peer counters
(`outgoing_send_total`, `outgoing_send_failed`, `subscriber_channel_lagged`,
`subscriber_channel_closed`) plus per-peer state (`avg_rtt_ms`,
`last_send_ms_ago`, `preferred_path`):

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:12700/diagnostics/dm | jq .
# Or via CLI:
x0x diagnostics dm
```

### Mesh harness troubleshooting

`e2e_vps_mesh.py` reports `discover missing: [...]` — the runner is not
publishing on the results topic. Check, in order:

```bash
# 1. Is the runner alive?
ssh root@<node_ip> 'systemctl is-active x0x-test-runner'

# 2. Is its config pointing at a readable token?
ssh root@<node_ip> 'cat /etc/x0x-test-runner.env'

# 3. Has the runner subscribed to the control topic?
ssh root@<node_ip> 'journalctl -u x0x-test-runner -n 30 --no-pager'
# Expect: "subscribed to x0x.test.control.v1"

# 4. Is gossip flowing?
curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:12600/diagnostics/gossip | jq .stats
```

If discovery works but `send_dm` results don't return, look at
`/diagnostics/dm` on the *sender* side and the receiver's `dm.trace`
INFO log lines (search by `digest_marker` from the orchestrator output to
correlate sender ↔ receiver).

---

## CI Integration

`.github/workflows/`:

- **ci.yml** — fmt, clippy, nextest, doc (symlinks `ant-quic` and
  `saorsa-gossip` from `.deps/`)
- **security.yml** — `cargo audit`
- **release.yml** — multi-platform builds (7 targets), macOS code
  signing, ML-DSA-65 manifest signing, `crates.io` publish
- **build.yml** — PR validation
- **sign-skill.yml** — GPG-signs `SKILL.md`

The XCUITest target imports cleanly on Linux runners (`XCUITEST_SKIP=1`)
and only actually executes on macOS.

---

## Contributing

To add new tests:

1. Pick the right surface — REST/CLI parity goes in
   `tests/api_coverage.rs` or `tests/parity_cli.rs`; GUI in
   `tests/e2e_gui_chrome.mjs`; Dioxus in
   `../communitas/communitas-dioxus/tests/e2e/`; Apple in
   `CommunitasGoldenPathsUITests.swift`; cross-region matrix in
   `tests/e2e_vps_mesh.py` (preferred) or `tests/e2e_vps.sh` (legacy).
2. Update the corresponding row in [`docs/parity-matrix.md`](docs/parity-matrix.md)
   from 🟡 / ❌ to ✅ once the test is green.
3. Wire the test into `e2e_proof_runner.sh` if it should be part of the
   release proof.
4. Document expected behaviour in the test header.
5. Run locally before pushing — every CI green light corresponds to a
   `proofs/<timestamp>/` artefact bundle.

Mesh-harness specific:

6. New protocol commands go through the three-place edit in §7b
   ("Extending the protocol"). Keep result envelopes small.
7. Bumping the runner script means re-running `tests/e2e_deploy.sh`
   (the deploy step pushes both the daemon binary *and* the runner).

---

## Support

- GitHub: https://github.com/saorsa-labs/x0x
- Email: david@saorsalabs.com
- Parity matrix: [`docs/parity-matrix.md`](docs/parity-matrix.md)
- Architecture: [`CLAUDE.md`](CLAUDE.md)
