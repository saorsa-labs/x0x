# Proof summary — x0x v0.18.0 release gate

**Generated:** 2026-04-20 07:55 (first successful local proof run)

## Dep chain

| Repo | Version | crates.io | Status |
|---|---|---|---|
| `ant-quic` | 0.27.2 | ✅ published | Tag `v0.27.2`, reader-task cooperative cancel + `probe_peer` + `ProbeTimeout` |
| `saorsa-gossip` | 0.5.18 | ✅ published (11 crates) | Tag `v0.5.18`, pins ant-quic 0.27.2 |
| `x0x` | ant-quic 0.27.2 + saorsa-gossip 0.5.18 | committed (a33b0cb) | Ready to cut |
| `rustc` toolchain | 1.95.0 | — | Forced by blake3 1.8.4 MSRV |

## Validation gate (x0x)

| Gate | Result |
|---|---|
| `cargo fmt --check` | ✅ clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | ✅ clean (4.79s incremental) |
| `cargo nextest run --all-features --workspace` | ✅ **1006 / 1006 pass**, 131 skipped |

## Local stress proof — 3-daemon gossip (loopback)

`proofs/stress-20260420-085503/stress-report.json`:

```json
{
  "nodes": 3, "messages": 100, "topic": "gossip-stress-97003",
  "elapsed_seconds": 12,
  "per_node": [
    { "idx": 1, "publish_total": 118, "delivered_to_subscriber": 140, "decode_to_delivery_drops": 0 },
    { "idx": 2, "publish_total": 17,  "delivered_to_subscriber": 102, "decode_to_delivery_drops": 0 },
    { "idx": 3, "publish_total": 17,  "delivered_to_subscriber": 102, "decode_to_delivery_drops": 0 }
  ]
}
```

- **Publisher (node-1)** pushed 100 user messages + ~18 internal
  (presence, rendezvous, capability ads) = `publish_total: 118`.
- **Subscribers (node-2, node-3)** each received `delivered_to_subscriber:
  102` — every one of the 100 stress messages plus a couple of the
  publisher's internal broadcasts.
- **`decode_to_delivery_drops: 0` on every node** → every message that
  entered the local pipeline was handed to the subscriber channel. No
  internal buffer overflow, no silent loss.

Observed settings for 100 % delivery: `SETTLE_SECS=25`,
`PUBLISH_DELAY_MS=50` (i.e. let HyParView converge, then publish below
the stream fan-out rate). At burst rate (`PUBLISH_DELAY_MS=0`, 200
msgs/s) the publisher pipeline still reports zero drops but some
messages are lost at the ant-quic transport layer before reaching the
subscriber pipeline — this is an upstream observation, not a regression
caused by this release.

## ant-quic 0.27.1 / 0.27.2 surface consumer tests

`tests/ant_quic_0272_surface.rs` — **4 / 4 pass**:

- `probe_peer_returns_finite_rtt_on_localhost_connection` — RTT < 1 s
- `connection_health_after_connect_is_observable`
- `send_with_receive_ack_round_trips_on_localhost`
- `subscribe_all_peer_events_fires_established_on_connect`

Each test builds a pair of localhost `P2pEndpoint`s (same config pattern
as ant-quic's own `b_*` tests) and drives one of the new primitives.

## Artefacts this release added

| Path | Purpose |
|---|---|
| `docs/parity-matrix.md` | Capability × surface matrix, per-run proof-artefact layout |
| `tests/ant_quic_0272_surface.rs` | New-surface consumer smoke tests |
| `tests/e2e_stress_gossip.sh` | N-daemon publish/deliver drop proof |
| `tests/e2e_gui_chrome.mjs` | Playwright driver for embedded HTML GUI |
| `tests/e2e_communitas_dioxus.sh` | Dioxus app JSON-IPC driver |
| `tests/e2e_proof_runner.sh` | Top-level orchestrator → `proof-report.json` |
| `communitas-apple/Tests/CommunitasUITests/…` | XCUITest golden paths |
| `x0xd`: `GET /diagnostics/gossip` | Drop-detection counters (publish / incoming / decoded / delivered / decode→delivery drops) |
| `x0xd`: `X0X_LOG_DIR` | Per-pid file log sink, stackable with stdout |
| `x0x`: `diagnostics gossip` | CLI wrapper for the new endpoint |
| `NetworkNode` pass-throughs | `probe_peer` / `connection_health` / `send_with_receive_ack` / `subscribe_all_peer_events` |

## Chrome / Playwright GUI proof

`proofs/chrome-20260420-v2/gui-parity-report.json` — **9 / 9 pass**:

```
[PASS] daemon-health
[PASS] agent-card
[PASS] presence-online
[PASS] diagnostics-connectivity
[PASS] diagnostics-gossip          ← new this release
[PASS] groups-discover
[PASS] stores-list
[PASS] contacts-list
[PASS] pubsub-roundtrip
```

Round-trip proof (`pubsub-roundtrip`) — publish from the page context,
sleep, read `/diagnostics/gossip`, assert counters advanced and drops
are zero:

```json
{
  "publish_total": 13, "publish_failed": 0,
  "incoming_total": 12, "incoming_decoded": 12, "incoming_decode_failed": 0,
  "delivered_to_subscriber": 12, "subscriber_channel_closed": 0,
  "decode_to_delivery_drops": 0, "in_flight_decode": 0
}
```

Artefacts captured per run:

- `chrome-gui.har` — network HAR (every fetch / WebSocket / SSE)
- `chrome-gui.console.jsonl` — browser console stream
- `chrome-gui.screenshot.png` — final full-page screenshot
- `gui-parity-report.json` — per-capability pass/fail JSON

Originally the harness loaded the GUI via `file://` and all page fetches
hit CORS (browser blocked cross-origin to `http://127.0.0.1`). Fix:
load the GUI from the daemon's embedded `/gui` handler so the page
shares origin with the REST surface. The harness accepts `--gui <path>`
to override back to `file://` when a daemon is unavailable.

## Red cells (gaps tracked, not blockers for v0.18.0)

See `docs/parity-matrix.md` "Red-cell ticket list". Summary:

1. REST handlers for the new ant-quic primitives (probe / health /
   lifecycle) — pass-through on `NetworkNode` only.
2. `POST /direct/send` opt-in `require_ack: bool` to switch from
   fire-and-forget to `send_with_receive_ack`.
3. GUI panel + x0x-client method for `/diagnostics/gossip`.
4. XCUITest golden paths exist; CI host running `xcodebuild` still to
   be wired.
5. Dioxus test-mode JSON hook — harness present, app-side receiver to
   implement.
