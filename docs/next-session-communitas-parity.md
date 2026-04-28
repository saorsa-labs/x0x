# Next session — Communitas + Apple parity coverage

**Update 2026-04-28 (evening):** A three-stream comprehensive parity
push kicked off. **Stream 1 (x0x GUI) is complete** — 6 GUI cells
flipped to ✅ via Chrome harness assertions plus a new
`POST /upgrade/apply` endpoint, with two cells deferred behind a
documented design-doc requirement (key export, REST-driven user
identity opt-in). 19/19 capabilities pass in
`tests/e2e_gui_chrome.mjs`; proof bundle at
`proofs/gui-parity-20260428T200557Z/`.

**Streams 2 (Communitas Apple) and 3 (Communitas Dioxus) are out for
external teams** — see the prompts in the chat handover. They write
their evidence to their own repos' `PARITY_EVIDENCE.md`; this repo
merges into `docs/parity-matrix.md` at the end.

The earlier SwiftDaemonFixture work
(`communitas-apple/Tests/X0xClientTests/Helpers/DaemonFixture.swift`
plus the three live round-trip suites) closed Apple identity / trust /
kv. Ticket #5 is closed. Stream 2's job is now the remaining 11 Apple
🟡s — connect-agent UI, discover, four-word, WS feed, file transfer,
group policy, group discover, FOAF, status, events SSE — and getting
`CommunitasGoldenPathsUITests.swift` to actually pass instead of
skipping (requires wiring accessibility ids into `Sources/Communitas/`).
Stream 3's job is scaffolding a Dioxus WebDriver harness from scratch
and closing the 17 Dioxus 🟡s.

**State at hand-off (2026-04-28, end of v0.19.7 session)**

- x0x **v0.19.7** is live on crates.io and GitHub Releases (multi-platform
  assets, ML-DSA-65 signed). Bootstrap fleet still on v0.19.5 — upgrade
  not required for this work since the bootstrap-specific behaviour is
  unchanged.
- `docs/parity-matrix.md` is the source of truth. After v0.19.6 + v0.19.7
  the **REST / CLI / GUI / communitas-x0x-client** columns are entirely
  ✅ for connectivity, messaging, and identity. **Apple + Dioxus columns
  still carry many 🟡 cells** — the underlying Rust client implements the
  surface, but UI-driven round-trip coverage is thin.

## Goal

1. **Audit current parity** for x0x's three GUI surfaces:
   - x0x embedded HTML (`src/gui/x0x-gui.html`) — assumed ✅, spot-check
     against the new fields shipped in v0.19.6/v0.19.7.
   - `communitas-dioxus` (`../communitas/communitas-dioxus`).
   - `communitas-apple` (`../communitas/communitas-apple`).
2. **Close the Apple test coverage gap.** `CommunitasUITests` already
   exists at
   `../communitas/communitas-apple/Tests/CommunitasUITests/CommunitasGoldenPathsUITests.swift`
   with 5 golden paths. Extend it to cover the rows the matrix lists as
   🟡 in the Apple column:
   - identity / agent-card import
   - trust + contacts
   - KV store CRUD
   - presence status, events SSE
   - direct/send + `require_ack_ms` *(new in v0.19.6)*
   - peer-lifecycle SSE *(new in v0.19.6)*
   - peer health structured `snapshot` shape *(new in v0.19.7)*
3. **Confirm Dioxus parity.** `communitas-dioxus/tests/e2e/` is referenced
   in the matrix but does not exist yet — only `accessibility.rs` and
   `offline_ux_integration.rs`. Decide between scaffolding a WebDriver
   harness vs. documenting a deferral with a cell-by-cell scope cut.

## Deliverable

- `docs/parity-matrix.md` updated with cell-by-cell pass/fail evidence
  for every Apple cell, plus a clear decision row on Dioxus.
- Apple XCUITest target green on the newly-added cells; XCResult bundle
  archived under `proofs/apple-parity-YYYYMMDD/`.
- Either a passing Dioxus e2e harness *or* a written deferral note in
  the matrix's red-cell ticket list.

## Already-on-disk landmarks

| Path | Purpose |
|---|---|
| `docs/parity-matrix.md` | The matrix. Read first. |
| `tests/peer_lifecycle_integration.rs` | Pattern for round-trip integration tests at the REST layer. |
| `tests/harness/src/daemon.rs` | `DaemonFixture` — boots a temp x0xd. The `start_with_config` helper takes extra TOML and skips duplicate keys. |
| `../communitas/communitas-apple/Sources/X0xClient/` | Swift X0xClient sources. Needs a Swift `PeerHealthSnapshot` decoder mirror. |
| `../communitas/communitas-apple/Tests/CommunitasUITests/CommunitasGoldenPathsUITests.swift` | Existing UITest target — extend, don't replace. |
| `../communitas/communitas-apple/Tests/X0xClientTests/` | Existing unit-test target for the Swift client. |
| `../communitas/communitas-x0x-client/tests/{client_coverage,swift_parity}.rs` | These already enforce *method existence* parity Rust↔Swift. They do NOT prove round-trip. |
| `../communitas/communitas-x0x-client/src/types.rs` | New since last session: `PeerHealth.snapshot: Option<PeerHealthSnapshot>` — Swift counterpart needed. |
| `../communitas/communitas-dioxus/tests/` | Currently only `accessibility.rs` + `offline_ux_integration.rs`. Plan or scope-cut. |

## Known constraints

- Apple UI tests need a live `x0xd` daemon. Mirror the boot pattern from
  `tests/harness/src/daemon.rs`: temp data dir, ephemeral `bind_address`
  + `api_address`, read `api.port` and `api-token` files, then point the
  Swift client at `127.0.0.1:<port>`.
- `swift_parity.rs` currently maps Rust method → Swift method by name. If
  a new Rust method appears (e.g. `peer_health_snapshot`), the Swift
  side must add a matching method or the test fails — useful as a forcing
  function.
- `release.yml` signs `SKILL.md` and the multi-platform binaries with
  ML-DSA-65; that tooling is unrelated to this work but the v0.19.6
  retro showed `SKILL.md`'s `version:` field is checked by
  `.github/scripts/validate_release_metadata.py`. Keep that in sync if
  any release flows out of this work.

## First moves

1. Re-read `docs/parity-matrix.md` to enumerate every 🟡 in the Apple
   and Dioxus columns.
2. Read `CommunitasGoldenPathsUITests.swift` to understand what golden
   paths already exist and where to slot new tests.
3. Read the Swift `X0xClient` sources to map current Swift surface to
   the Rust surface.
4. Decide: extend `CommunitasGoldenPathsUITests.swift` in place, or add
   a new `Communitas{Identity,Trust,KV,Presence,PeerLifecycle}UITests.swift`
   per cell-group. The matrix's per-row organisation suggests the
   latter.
5. For each Apple cell flipped, write a one-line note in the matrix
   pointing at the test that proves it.

## Out of scope for this session

- `communitas-bench` and `communitas-kanban` — historical 🟡, deferred
  by the matrix until usage warrants.
- Any change to x0xd's REST surface. If a gap is found in REST, file
  it as a follow-up and unblock by stubbing Swift against the existing
  shape.
