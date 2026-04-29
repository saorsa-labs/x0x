# x0x Capability Parity Matrix

**Target:** every capability in x0x is reachable — and behaves identically —
from **every surface**. The REST API on `x0xd` is the source of truth; every
other surface is a client of it.

| # | Surface | Transport | Coverage source |
|---|---------|-----------|-----------------|
| 1 | REST API (`x0xd`) | HTTP/JSON + WS + SSE | `tests/api_coverage.rs`, `tests/daemon_api_integration.rs` |
| 2 | CLI (`x0x`) | Wraps REST | `tests/parity_cli.rs` (every endpoint has a CLI command) |
| 3 | Embedded HTML GUI (`src/gui/x0x-gui.html`) | Wraps REST via fetch | `tests/gui_smoke.rs`, `tests/gui_named_group_parity.rs`, `tests/e2e_gui_chrome.mjs` (this release) |
| 4 | `communitas-x0x-client` (Rust) | Wraps REST + WS + SSE | `communitas/communitas-x0x-client/tests/` |
| 5 | `communitas-core` (Rust library) | Wraps `communitas-x0x-client` | `communitas/communitas-core/tests/` |
| 6 | `communitas-ui-api` (Tauri / IPC) | JSON over Tauri bridge | `communitas/communitas-ui-api/tests/` |
| 7 | `communitas-ui-service` (WebRTC signaling etc.) | Wraps `x0x-client` | `communitas/communitas-ui-service/tests/` |
| 8 | `communitas-dioxus` (desktop GUI) | Uses `communitas-ui-service` | `communitas/communitas-dioxus/tests/e2e/` (this release) |
| 9 | `communitas-kanban` (task view) | Uses `communitas-x0x-client` task lists | `communitas/communitas-kanban/tests/` |
| 10 | `communitas-bench` (perf harness) | `communitas-x0x-client` | `communitas/communitas-bench/` |
| 11 | `communitas-apple` (Swift app) | Wraps REST through `X0xClient` Swift lib | `communitas/communitas-apple/Tests/X0xClientTests/`, `communitas/communitas-apple/Tests/CommunitasUITests/` (this release) |

> **Note.** Previous releases shipped first-party Python (PyO3) and Node.js
> (napi-rs) bindings; both were retired in favour of the daemon + REST model
> so that there is exactly one supported surface per host. Non-Rust
> applications consume `x0xd` over HTTP/WebSocket — see
> [`docs/local-apps.md`](local-apps.md).

---

## Capability → surface matrix

Legend: ✅ implemented & tested · 🟡 implemented, test gap · ❌ not yet wired ·
`—` not applicable for this surface.

**Per-column "tested" bar**:
- **REST / CLI / GUI**: round-trip integration test against a live `x0xd`.
- **`x0x-client` (Rust)**: round-trip integration test (REST + WS + SSE).
- **Dioxus**: consumes `communitas-x0x-client` directly — inherits ✅
  whenever the underlying client method has round-trip coverage. No
  Dioxus-specific test layer; UI-driven Dioxus tests would belong in a
  future WebDriver harness.
- **Apple**: Swift X0xClient method exists *and* the wire-shape decoder
  has a Swift unit test. The identity / trust / KV rows additionally
  carry **live round-trip coverage** against a real `x0xd` via the
  Swift `DaemonFixture` helper at
  `communitas/communitas-apple/Tests/X0xClientTests/Helpers/DaemonFixture.swift` —
  run with `X0X_LIVE_TESTS=1 swift test` from `communitas-apple/`. End-to-end
  XCUITest coverage of the Communitas app itself is a future session's
  deliverable.

### Identity
| Capability | REST | CLI | GUI | Py | Node | x0x-client | Dioxus | Apple | Kanban |
|---|---|---|---|---|---|---|---|---|---|
| Get agent id / card | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Import agent card | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Export/backup keypairs | ✅ | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | — |
| User (human) identity (opt-in) | ✅ | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | ✅ | ✅ | — |
| Agent certificate verify | ✅ | ✅ | — | ✅ | ✅ | ✅ | — | — | — |

### Trust & contacts
| Capability | REST | CLI | GUI | Py | Node | x0x-client | Dioxus | Apple | Kanban |
|---|---|---|---|---|---|---|---|---|---|
| Add / block / trust contact | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Machine-pinning enforcement | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Trust evaluator decision read | ✅ | ✅ | ✅ | 🟡 | 🟡 | 🟡 | ✅ | ✅ | — |

### Connectivity / discovery
| Capability | REST | CLI | GUI | Py | Node | x0x-client | Dioxus | Apple | Kanban |
|---|---|---|---|---|---|---|---|---|---|
| Connect to agent (direct / coordinated) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | — |
| Probe peer liveness (**0.27.2 new**) | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | — |
| Connection health snapshot (**0.27.1 new**) | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | — |
| Peer lifecycle subscription (**0.27.1 new**) | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | — |
| Discover agents (cache / FOAF) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | — |
| `GET /diagnostics/connectivity` | ✅ | ✅ | ✅ | — | — | ✅ | — | — | — |
| `GET /diagnostics/gossip` (this release) | ✅ | ✅ | ✅ | — | — | ✅ | — | — | — |
| Four-word network bootstrap | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | — |

### Messaging — pub/sub
| Capability | REST | CLI | GUI | Py | Node | x0x-client | Dioxus | Apple | Kanban |
|---|---|---|---|---|---|---|---|---|---|
| Publish | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Subscribe | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Unsubscribe | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| WebSocket live feed | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | — |

### Messaging — direct (DM-over-gossip)
| Capability | REST | CLI | GUI | Py | Node | x0x-client | Dioxus | Apple | Kanban |
|---|---|---|---|---|---|---|---|---|---|
| Send direct | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Receive direct (annotated) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Epidemic rebroadcast on caps topic | ✅ | — | — | — | — | ✅ | — | — | — |
| Send + receive-ACK (**0.27.1 new**) | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | — |
| File transfer (offer/accept) | ✅ | ✅ | ✅ | 🟡 | 🟡 | ✅ | ✅ | 🟡 | — |

### Groups
| Capability | REST | CLI | GUI | Py | Node | x0x-client | Dioxus | Apple | Kanban |
|---|---|---|---|---|---|---|---|---|---|
| Create named group | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Invite / join / leave | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Policy (roles, bans) | ✅ | ✅ | ✅ | 🟡 | 🟡 | ✅ | ✅ | 🟡 | — |
| Discover groups (tag / nearby) | ✅ | ✅ | ✅ | 🟡 | 🟡 | ✅ | ✅ | 🟡 | — |
| MLS encryption | ✅ | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | — |

### KV store
| Capability | REST | CLI | GUI | Py | Node | x0x-client | Dioxus | Apple | Kanban |
|---|---|---|---|---|---|---|---|---|---|
| Create / list stores | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| PUT / GET / DELETE key | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Access-policy enforcement | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |

### Task lists (CRDT)
| Capability | REST | CLI | GUI | Py | Node | x0x-client | Dioxus | Apple | Kanban |
|---|---|---|---|---|---|---|---|---|---|
| Create / join task list | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Add / update item | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Claim / done transitions | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Concurrent-merge correctness | ✅ | — | — | ✅ | ✅ | ✅ | — | — | — |

### Presence
| Capability | REST | CLI | GUI | Py | Node | x0x-client | Dioxus | Apple | Kanban |
|---|---|---|---|---|---|---|---|---|---|
| Online list | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| FOAF walk | ✅ | ✅ | ✅ | 🟡 | 🟡 | ✅ | ✅ | 🟡 | — |
| Find specific agent | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Status / reachability | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | — |
| Events SSE | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 | — |

### Upgrade / self-update
| Capability | REST | CLI | GUI | Py | Node | x0x-client | Dioxus | Apple | Kanban |
|---|---|---|---|---|---|---|---|---|---|
| Check updates | ✅ | ✅ | ✅ | — | — | ✅ | ✅ | ✅ (Sparkle) | — |
| Apply update | ✅ | ✅ | ✅ | — | — | 🟡 | ✅ | ✅ (Sparkle) | — |
| Gossip manifest propagation | ✅ | — | — | — | — | 🟡 | — | — | — |

---

## Red-cell ticket list (gaps to close in this release)

1. ~~**Probe-peer / connection-health / lifecycle subscription**~~ — closed in
   v0.19.6. REST handlers (`POST /peers/:id/probe`, `GET /peers/:id/health`,
   `GET /peers/events` SSE) + CLI commands (`x0x peers probe|health|events`)
   + x0x-client (`probe_peer`, `peer_health`, `connect_peer_events`) +
   GUI panels (live peer-events feed, probe button on each peer row) all
   wired and round-trip-tested via `tests/peer_lifecycle_integration.rs`.
   v0.19.7 follow-up: `/peers/:id/health` now also emits a structured
   `snapshot` object alongside the legacy `health` Debug string, so GUI
   and `communitas-x0x-client::PeerHealthSnapshot` can act on
   `connected`/`generation`/`idle_ms` programmatically.
2. ~~**`send_with_receive_ack`**~~ — closed in v0.19.6. `POST /direct/send`
   accepts opt-in `require_ack_ms`; CLI exposes `--require-ack-ms`;
   `communitas-x0x-client::send_direct` accepts the option; GUI DM composer
   has an "ACK" toggle that surfaces the round-trip RTT inline. Round-trip
   tested via `direct_send_with_require_ack_round_trips_to_live_peer`.
3. ~~**`/diagnostics/gossip`**~~ — closed in v0.19.6. GUI panel renders the
   per-stream dispatcher stats; `communitas-x0x-client::gossip_stats` ships.
4. **Communitas Apple — 0.27.x peer-lifecycle row** ✅ closed
   2026-04-28. Swift `X0xSseStream` ships with `connectPeerEvents`;
   `PeerHealth.snapshot`, `DirectSendResponse.requireAck`,
   `PeerLifecycleEvent` decode tests live in
   `Tests/X0xClientTests/X0xClientTests.swift` (11 new cases). Rust↔Swift
   parity table extended with `RUST_SSE_TO_SWIFT` so future SSE methods
   can't drift.
5. **Communitas Apple — broad identity/trust/kv 🟡** ✅ closed
   2026-04-28. New Swift `DaemonFixture` helper
   (`communitas/communitas-apple/Tests/X0xClientTests/Helpers/DaemonFixture.swift`)
   mirrors the Rust `tests/harness/src/daemon.rs` shape — boots a real
   `x0xd` against ephemeral ports + temp data dir + isolated identity
   dir, gated behind `X0X_LIVE_TESTS=1` so the existing decoder-only
   `swift test` pass is unaffected. Three new live suites land in
   `Tests/X0xClientTests/`:
   - `IdentityRoundTripTests.swift` — `GET /agent`, `GET /agent/user-id`
     (opt-in null path), agent-card export → import across two daemons,
     `GET /introduction`, distinct agent ids across two fixtures.
   - `TrustRoundTripTests.swift` — `POST /contacts` lifecycle,
     `setTrust` transitions, `evaluateTrust` Allow / RejectBlocked /
     RejectMachineMismatch decision paths, machine-pin enforcement.
   - `KvStoreRoundTripTests.swift` — create / list / PUT / GET /
     DELETE / keys-list / overwrite, plus access-policy negative
     proof (foreign daemon cannot reach a private store id).
   Validation: 14 live tests pass against `x0xd 0.19.6`; full
   `swift test` is 69/69 in both gated and live mode. End-to-end
   XCUITest coverage of the Communitas app remains tracked for a
   future session — see `docs/next-session-communitas-parity.md`.
6. **Communitas Dioxus 🟡** — Dioxus consumes `communitas-x0x-client`
   directly, so client-layer parity transfers automatically. The
   remaining 🟡s reflect the absence of a Dioxus-specific UI test layer.
   Recommended scope-cut: keep these 🟡 until a WebDriver harness is
   in place; do not chase per-cell coverage at the Dioxus level until
   then.
7. **x0x GUI — broad 🟡 cleanup** ✅ closed 2026-04-28. Audit
   established that the matrix's remaining GUI 🟡s mostly reflected
   harness gaps, not missing UI. Closed cells:
   - `Trust & contacts / Machine-pinning enforcement` — wired in
     `renderPeople` detail panel via `togglePin`. Harness assertion
     `gui-machine-pinning` round-trips through
     `POST /contacts/:id/machines`, `…/pin`, asserts `pinned: true`
     from `GET /contacts/:id/machines`, then calls `/trust/evaluate`
     with an unpinned machine and requires `RejectMachineMismatch`.
   - `Trust & contacts / Trust evaluator decision read` — wired in the
     Admin → Trust Evaluation panel via `/trust/evaluate`. Harness
     assertion `gui-trust-evaluator` blocks a contact and asserts the
     decision contains `Reject` / `Blocked` from the GUI page origin.
   - `KV store / Access-policy enforcement` — wired through Spaces/Admin
     KV surfaces. Harness assertion `gui-kv-store-roundtrip` exercises
     CRUD, delete-then-GET 404, and a secondary-daemon negative proof:
     a foreign daemon cannot GET/PUT the primary daemon's private store id.
   - `Groups / Discover groups (tag/nearby)` — wired in
     `renderDiscover`. Harness assertion `gui-group-discover` drives
     both `/groups/discover?q=` and `/groups/discover/nearby`.
   - `Presence / FOAF walk` — already wired ("Run FOAF walk" button
     in `renderPresence`). Harness assertion `gui-presence-foaf`
     calls `/presence/foaf?ttl=2` and asserts the response shape.
   - `Upgrade / Apply update` — endpoint `POST /upgrade/apply` in
     `src/bin/x0xd.rs` honors daemon update config, serializes binary
     replacement with the background update workers, applies without
     immediate `exec()`, returns JSON, then schedules restart after the
     response has a chance to flush. New "Apply update" button in the
     home-view upgrade banner. Harness assertion `gui-upgrade-apply`
     requires HTTP 200 with either `applied: true` + `restart_scheduled`
     or `applied: false` with a `reason` (the wrapper disables updates
     for a safe no-op proof).
   - **Deferral**: `Identity / Export keypairs` left at 🟡 — exporting
     ML-DSA-65 private key material via HTTP needs a design doc on
     confirmation flow and at-rest encryption format. Tracked as a
     follow-up; CLI surface is also 🟡 today.
   - **Deferral**: `Identity / User identity (opt-in)` left at 🟡 in
     non-CLI surfaces — `GET /agent/user-id` exists for read, but
     opt-in is filesystem-based (`~/.x0x/user.key`). A REST opt-in
     surface needs a key-generation + consent design doc.
   New harness wrapper `tests/e2e_gui_chrome.sh` boots temp primary +
   secondary daemons on ephemeral ports and runs `e2e_gui_chrome.mjs`
   end-to-end; proof bundle lands in `proofs/gui-parity-YYYYMMDDTHHMMSSZ/`
   (chrome HAR, console log, screenshot, parity-report JSON, daemon logs).
   Latest fix proof: `proofs/gui-parity-fix-20260428T215315Z/`.
8. **Communitas Dioxus — broad 🟡 cleanup** ✅ closed 2026-04-29 by
   the parallel Dioxus stream. New `tests/e2e/` scaffold in
   `../communitas/communitas-dioxus/` boots two `x0x-test-harness::
   DaemonFixture` instances and launches the real Dioxus binary in
   `e2e-test-mode` (feature-gated, `COMMUNITAS_TEST_MODE=1`); each
   row test drives JSON commands through the binary, which calls the
   typed `communitas-x0x-client` surface used by the UI. Closed Dioxus
   cells (15):
   - Identity: get agent id/card, import agent card, user identity
     (opt-in, read path)
   - Trust & contacts: add/block/trust contact, machine pinning,
     trust evaluator decision read
   - Connectivity: discover agents (cache/FOAF), four-word network
     bootstrap
   - Groups: policy (roles/bans), discover (tag/nearby)
   - KV store: create/list, PUT/GET/DELETE, access-policy
     enforcement (foreign-daemon negative proof)
   - Presence: FOAF walk
   - Upgrade: check updates, apply update (raw `POST /upgrade/apply`
     bridge — typed `X0xClient::apply_upgrade` follow-up tracked in
     `communitas-dioxus/PARITY_EVIDENCE.md`)
   - **Deferral**: `Identity / Export keypairs` left at 🟡 — same
     reason as ticket #7 (no `communitas-x0x-client` method; needs
     consent + at-rest-encryption design doc).
   Run with `just e2e` from `communitas-dioxus/`. Proof bundle:
   `communitas-dioxus/proofs/dioxus-parity-YYYYMMDD/{stdout,stderr}.log`.
   The parallel stream also strengthened this repo's GUI harness:
   `tests/e2e_gui_chrome.sh` now boots a secondary daemon for real
   foreign-daemon negative proofs (machine-pin RejectMachineMismatch,
   KV access-policy denial); `src/bin/x0xd.rs` `apply_upgrade`
   now serializes through a `Mutex` shared with the gossip + GitHub
   apply paths and defers the binary-replacement restart so the HTTP
   response can flush; `src/upgrade/apply.rs` exposes
   `with_restart_on_success(false)` + `restart_current_binary()`.
9. **Bench / kanban** — historical parity gaps; tracked but out of scope
   until usage warrants.

---

## Proof artefacts

Per-run artefacts land in `./proofs/YYYY-MM-DD-HHMM/`:

- `proof-report.json` — machine-readable capability → surface pass/fail
- `logs/` — one JSON log per daemon process (`X0X_LOG_DIR=./proofs/.../logs`)
- `gossip-stats-*.json` — pre/post snapshots of `GET /diagnostics/gossip`
- `connectivity-*.json` — pre/post snapshots of `GET /diagnostics/connectivity`
- `xcuitest.xcresult` — Apple UI tests bundle
- `dioxus-e2e.log` — Dioxus driver transcript
- `chrome-gui.har` — network HAR for GUI run
- `chrome-gui.console.jsonl` — console logs for GUI run

The acceptance gate is `proof-report.json`: every ✅ cell in the matrix
must have `status: "pass"` and every 🟡 cell must have `status: "pending"`
with a follow-up ticket id.
