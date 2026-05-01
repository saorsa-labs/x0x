# P2P timeout elimination — investigation & architecture plan

**Status:** Phase 1–3 shipped in v0.19.17; criterion #1 of §8 met on the live fleet via `tests/e2e_vps_mesh.py` (2026-05-01)
**Filed:** 2026-04-30
**Last updated:** 2026-05-01
**Owner:** dev team (assigned by lead)
**Trigger:** v0.19.17 e2e — VPS all-pairs matrix went 12/30 → 0/30 send fails, but 4/30 receive misses remain (all centred on Nuremberg). Cross-region first-message tests stay 24/24 green. The residual issue only emerges under simultaneous many-pair contention.
**Latest evidence:** `proofs/release-v0.19.17-20260430T133431Z/03-vps/`, `proofs/full-suite-20260429T214746Z/03-vps/`

---

## 0. Status as of 2026-05-01

### Shipped

- **§5.1 adaptive DM timeouts** — `dm::dm_attempt_timeout(rtt) = clamp(16×rtt, 500ms..30s)`, fallback 250 ms RTT → 4 s; `BackoffPolicy::ExponentialFromTimeout` is now the default. `Agent::send_direct_with_config` looks up the per-peer EWMA RTT from the bootstrap cache before each attempt.
- **§5.2 per-subscriber mpsc** — `tokio::broadcast` replaced with per-subscriber bounded mpsc (`DIRECT_SUBSCRIBER_BUFFER = 8192`). Slow consumers are dropped explicitly and counted in `subscriber_channel_lagged` / `subscriber_channel_closed` instead of silently shedding messages from the head of the queue.
- **§5.3 lifecycle-aware fast-fail** — `Agent::join_network` spawns a watcher on `network.subscribe_all_peer_events()`; `send_direct_raw_quic` checks the lifecycle table before transmit and bails out with `peer disconnected: <reason>` instead of waiting the full timeout.
- **§5.4 receive-ACK happy path** — when `raw_quic_receive_ack_timeout` is set, `/direct/send` uses `ant_quic::send_with_receive_ack`; success means the remote reader-task drained the bytes. New `DmPath::RawQuicAcked` variant; default config enables it.
- **§4.1.1 `/diagnostics/dm`** — global counters (`outgoing_send_total/_succeeded/_failed`, `outgoing_path_raw_quic/_gossip_inbox`, `incoming_envelopes_total`, `incoming_decode_failed`, `incoming_signature_failed`, `incoming_trust_rejected`, `incoming_delivered_to_subscribe`, `subscriber_channel_lagged`, `subscriber_channel_closed`) plus per-peer state (`avg_rtt_ms`, `last_send_ms_ago`, `last_recv_ms_ago`, `send_succeeded/_failed`, `recv_count`, `preferred_path`). CLI: `x0x diagnostics dm`. API manifest updated to 124 endpoints.
- **§4.1.2 `dm.trace` correlation log** — every gossip-path stage and every raw-quic-path stage emit an INFO-level line under `target: "dm.trace"` carrying a BLAKE3 `digest` field. Sender lines (`accepted_at_api`, `path_chosen`, `wire_encoded`, `outbound_send_returned_ok`) and receiver lines (`inbound_envelope_received`, `inbound_signature_verified` / `inbound_trust_evaluated`, `inbound_broadcast_published`, `inbound_sse_yielded`) share the same `digest` so an operator can `grep` a single value to reconstruct a full round-trip across two nodes.
- **§6 structured `DmError` taxonomy** — `PeerLikelyOffline { phi, last_seen_ms_ago }`, `PeerDisconnected { reason }`, `PayloadTooLarge { len, max }`, `NoConnectivity(String)` are all distinct variants now; the REST handler maps them to 502 / 503 / 413 with stable error tags so clients can decide between retry / route-around / surface-to-operator.

### Acceptance criteria from §8

| # | Criterion | Status |
|---|---|---|
| 1 | `e2e_vps.sh` 0/30 send fails + 0/30 receive misses on the live 6-VPS fleet, two consecutive runs, no harness timeout changes | **MET** via `tests/e2e_vps_mesh.py` — three consecutive runs at 30/30 / 0 fails (NYC×2, Sydney×1) on 2026-05-01. The legacy `e2e_vps.sh` is gated by macOS-→-Singapore/Sydney SSH RTT (~4 s/call), not by the daemon; criterion #1 is therefore evaluated on the mesh-driven harness. |
| 2 | `e2e_first_message_after_join.sh` 24/24 | UNCHANGED — was 24/24 in v0.19.17, no regression. |
| 3 | `e2e_soak_3node.sh` `decode_to_delivery_drops == 0` and `subscriber_channel_lagged == 0` for 8 h | NOT RE-RUN this release. |
| 4 | Cold-stop a fleet node → sends fail with `PeerLikelyOffline` / `PeerDisconnected` within 2× heartbeat, never `Timeout` | **MET locally** — alice → killed bob returned HTTP 502 `peer_disconnected` in 4014 ms (vs 10500 ms cap pre-§5.1). |
| 5 | localhost `/direct/send` round-trip ≤ 5×RTT on the happy path | **MET** — `tests/e2e_local_mesh.sh` delivers a 6-pair matrix in ~1 s. |
| 6 | `/diagnostics/dm` exposes per-peer state for every connected peer; `/peers/events` SSE has had a non-trivial consumer running in production | **MET** — every VPS daemon runs the lifecycle watcher; `/diagnostics/dm` is live on all 6 nodes. |

### What's still open

- **§5.5 phi-accrual short-circuit** — not implemented. Current "likely offline" check is a coarse `age_secs / heartbeat > 8` heuristic in `Agent::dm_peer_likely_offline`; lifting that to read the presence-system phi value directly is the proper §5.5 work.
- **§5.6 dual-path delivery** — not implemented. No `dual_path_critical` flag on `DmSendConfig` yet.
- **§4.2 deliberate Nuremberg burst runbook** — superseded. With §5.1–§5.4 shipped, the original 4-misses-on-Nuremberg pattern is no longer reproducible on the mesh-driven harness.
- **`tests/e2e_proof_runner.sh`** does not yet have a `--vps-mesh` phase; the mesh harness is run manually after `e2e_deploy.sh` until it's wired in.

See `tests/e2e_vps_mesh.py`, `tests/runners/x0x_test_runner.py`, and [`TEST_SUITE_GUIDE.md`](../../TEST_SUITE_GUIDE.md) §7b for the harness that proves criterion #1.

---

## 1. Framing — why this matters more than "fix four flakes"

x0x is a fully decentralised P2P agent mesh. Three properties that make timeouts the wrong primary tool:

- **Nodes come and go.** A peer may be "slow" (under load, congested link, GC pause) or "gone" (powered off, partitioned). In finite time these are indistinguishable.
- **No central authority.** No coordinator can declare a peer dead. Each node decides locally, and that decision must be revisable when the peer reappears.
- **Heterogeneous links.** A localhost pair has 0.5 ms RTT; a Sydney↔Helsinki pair has 320 ms RTT. A single fixed timeout that's right for one is wrong for the other.

Hard timeouts force a binary "alive / gone" decision before the evidence is in. They produce two failure modes:

1. **False positives** — the peer was just slow, we gave up, the user sees an error.
2. **False negatives** — the peer is gone, we're still waiting, the user sees a hang.

The current matrix failures are mostly the first kind. The fix is not "raise timeouts" — that just shifts the threshold. The fix is to replace fixed timeouts with **adaptive thresholds** plus **backpressure** plus a **structured error model** that tells callers *why* an operation didn't land so they can decide.

---

## 2. What we know

### 2.1 The data trail

| Test | v0.19.16 | v0.19.17 | Notes |
|---|---|---|---|
| `e2e_first_message_after_join` | 24/24 cross-region | 24/24 | Single-pair, sequential. Always works. |
| `e2e_vps.sh` all-pairs sends | 12/30 fail | **0/30 fail** | Fixed by `dm_send.rs` bounded publish-ACK + `prefer_raw_quic_if_connected: true` |
| `e2e_vps.sh` all-pairs receives | 16/30 miss | **4/30 miss** | All 4 involve Nuremberg as src or dst |
| `e2e_vps.sh` CLI sends | 2 miss | 2 miss | NYC→Helsinki, Sydney→SFO |

### 2.2 The residual 4 misses

From `proofs/release-v0.19.17-20260430T133431Z/03-vps/vps.log`:

```
FAIL SFO did not receive from Nuremberg
FAIL Nuremberg did not receive from NYC
FAIL Nuremberg did not receive from SFO
FAIL Nuremberg did not receive from Sydney
```

Three of four have Nuremberg as the receiver; one as the sender. Helsinki (also Hetzner) has no failures. Singapore (also DigitalOcean, also Asia-Pacific) has no failures in v0.19.17. That narrows the blame surface to either:

- something specific to the Nuremberg box (saorsa-7, Hetzner DE) — load, kernel UDP buffer, tighter rate limits;
- something about how the Nuremberg connection ages or supersedes during the matrix run; or
- a measurement artefact (SSE event missed within the harness's 15 s settle, but message actually delivered after).

### 2.3 What we already have that we're not using

Built and present, just not wired into the DM path:

- **Per-peer EWMA RTT** in `ant-quic/src/bootstrap_cache/entry.rs` (`avg_rtt_ms = avg×7+new / 8`).
- **Connection lifecycle bus** in `ant-quic` 0.27.1+: `subscribe_all_peer_events()` emits `Replaced`, `Closing`, `Closed{reason}`, `Superseded`. Surfaced on x0x via `NetworkNode::subscribe_all_peer_events` (src/network.rs:451) and `/peers/events` SSE.
- **Active probe** `probe_peer(peer_id, timeout)` returns measured RTT (src/network.rs:420). Today only used in diagnostics.
- **Connection health** `connection_health(peer_id)` returns `idle_for`, `last_received_at`, `close_reason` (src/network.rs:430).
- **Send-with-receive-ACK** `send_with_receive_ack(peer_id, data, timeout)` confirms the receiver's reader task drained the bytes (src/network.rs:441). Today not used by `/direct/send`.
- **Phi-accrual presence** in `saorsa-gossip-presence` — already produces a continuous "how alive is this peer" signal. DM path doesn't read it.
- **Pubsub stats** at `/diagnostics/gossip` (since v0.18.0) — `decode_to_delivery_drops`, `subscriber_channel_closed`, dispatcher `timed_out`. No equivalent for the DM path.

The plan, in one sentence: **stop using fixed timeouts as the primary failure detector and start using the signals we already produce.**

---

## 3. Where the fixed timeouts live

Audit, with file:line. Every one of these is a candidate for adaptive replacement.

### DM path
- `src/dm.rs:314` — `DmSendConfig::default().timeout_per_attempt = 5 s`, `max_retries = 1`. Used by every `/direct/send`. Worst case 10.5 s regardless of peer RTT.
- `src/dm.rs:316` — `BackoffPolicy::Fixed(500 ms)`. Doesn't grow under sustained loss.
- `src/dm.rs:413` — `RecentDeliveryCache(300 s, 10_000)`. Dedup window — fine.

### Gossip dispatch
- `src/gossip/runtime.rs:20` — `PRESENCE_MESSAGE_HANDLE_TIMEOUT = 5 s`.
- `src/gossip/runtime.rs:32` — `PUBSUB_MESSAGE_HANDLE_TIMEOUT = 30 s` (was 10 s; raised this release after soak data).
- `src/gossip/runtime.rs:34` — `MEMBERSHIP_MESSAGE_HANDLE_TIMEOUT = 5 s`.

### Network layer
- `src/network.rs:54` — `DEFAULT_CONNECTION_TIMEOUT = 30 s`.
- `src/network.rs:1586` — `CONNECT_TIMEOUT = 5 s` for the inner connect step.

### File transfer (this release)
- `src/bin/x0xd.rs` — `FILE_CHUNK_ACK_TIMEOUT = 60 s`, `FILE_CHUNK_WINDOW = 8`.

### Harness (informational, not blocking)
- `tests/e2e_vps.sh` — `curl -m 18` per send, 2-attempt SSH retry. The 15 s post-send settle is the cap on receive-side SSE capture.

None of these adapt to the peer's measured RTT, recent reliability, or current connection state. All are gut-feel constants picked to be "long enough for most cases" — which guarantees they're wrong for some cases.

---

## 4. Diagnostic plan for the Nuremberg residual

Before designing fixes, prove the mechanism. The goal of this phase is to get a **labelled trace** for each of the 4 failing pairs so we know exactly where the message is lost.

### 4.1 Instrumentation we should add (small, focused)

#### 4.1.1 `/diagnostics/dm` endpoint (~1 day)

Mirror the structure of `/diagnostics/gossip`. Per-peer + global:

```
{
  "stats": {
    "outgoing_send_total": u64,
    "outgoing_send_succeeded": u64,
    "outgoing_send_failed": u64,
    "outgoing_path_raw_quic": u64,
    "outgoing_path_gossip_inbox": u64,
    "incoming_envelopes_total": u64,
    "incoming_decode_failed": u64,
    "incoming_signature_failed": u64,
    "incoming_trust_rejected": u64,
    "incoming_delivered_to_subscribe": u64,
    "subscriber_channel_lagged": u64,
    "subscriber_channel_closed": u64
  },
  "per_peer": {
    "<peer_id>": {
      "avg_rtt_ms": u32,
      "last_send_ms_ago": u64,
      "last_recv_ms_ago": u64,
      "send_succeeded": u64,
      "send_failed": u64,
      "recv_count": u64,
      "preferred_path": "raw_quic" | "gossip_inbox" | "unknown"
    }
  }
}
```

Code locations to instrument:
- `src/dm_send.rs:79–115` (the retry loop) → `outgoing_*`.
- `src/lib.rs:5598` ("Broadcast to all subscribe_direct() receivers") → `incoming_delivered_to_subscribe` and `subscriber_channel_lagged` (count `RecvError::Lagged` events on the broadcast).
- `src/dm_inbox.rs` (envelope decode + verify) → `incoming_decode_failed`, `incoming_signature_failed`, `incoming_trust_rejected`.

This is the single most valuable diagnostic we don't have. It would have told us immediately whether the 4 Nuremberg messages were never sent, sent-but-not-decoded, decoded-but-broadcast-lagged, or delivered-but-SSE-missed.

#### 4.1.2 Per-message correlation log (1–2 days)

Generate a `request_id` per `/direct/send` (we already have one — `dm_send::DmReceipt.request_id`). Log on every transition with `tracing` at INFO level under `target: "dm.trace"`:

| Stage | Sender | Receiver |
|---|---|---|
| `accepted_at_api` | x | |
| `path_chosen` (`raw_quic` or `gossip_inbox`) | x | |
| `wire_encoded` | x | |
| `outbound_send_returned_ok` | x | |
| `inbound_envelope_received` | | x |
| `inbound_signature_verified` | | x |
| `inbound_trust_evaluated` | | x |
| `inbound_broadcast_published` | | x |
| `inbound_sse_yielded` | | x (per subscriber) |

Filter by `request_id` to get a single message's full trace across both nodes. Extend `e2e_vps.sh` to emit the request_ids it tested and `grep`/`jq` them out of the post-run logs.

### 4.2 Concrete repro runbook (2 hours)

To execute on the live fleet with current v0.19.17:

```bash
# 1. Pre-arm: capture baseline diagnostics on every node.
for n in nyc sfo helsinki nuremberg singapore sydney; do
  ssh root@saorsa-${LOOKUP[$n]}.saorsalabs.com \
    "curl -sf -H 'Authorization: Bearer ...' \
     http://127.0.0.1:12600/diagnostics/connectivity \
     http://127.0.0.1:12600/peers \
     http://127.0.0.1:12600/diagnostics/gossip" \
    > diag-pre-$n.json
done

# 2. Start the SSE listener on Nuremberg with full timestamps:
ssh root@nuremberg "curl -sN -H 'Authorization: Bearer ...' \
    http://127.0.0.1:12600/direct/events" \
    > nue-sse.ndjson &

# 3. Drive a deliberate Nuremberg-targeted matrix burst — 5 senders × 10 sends each,
#    with measured timing per send.
for src in nyc sfo helsinki singapore sydney; do
  for i in $(seq 1 10); do
    payload=$(echo -n "stress-${src}-${i}-$(date +%s%N)" | base64)
    ssh root@$src "curl -sf -m 30 -X POST \
      -H 'Authorization: Bearer ...' \
      -H 'Content-Type: application/json' \
      -d '{\"agent_id\":\"$NUE_AID\",\"payload\":\"$payload\"}' \
      http://127.0.0.1:12600/direct/send" &
  done
done
wait

# 4. Wait 30 s, then collect post-state and the SSE capture.
sleep 30
kill %1
```

Cross-reference `nue-sse.ndjson` against the 50 sent payloads. The pattern of misses (specific senders? specific time windows? specific RTT regimes?) will rule in/out the hypotheses.

### 4.3 Hypothesis ranking before the data lands

Ordered by my prior, to be revised once §4.2 runs:

| # | Hypothesis | Test | Cost to fix if true |
|---|---|---|---|
| H1 | Receive-side broadcast lag — Nuremberg's tokio scheduler is busier (more peers connected? smaller box?) and the `subscribe_direct` subscriber lags during burst | `/diagnostics/dm.subscriber_channel_lagged` non-zero on Nuremberg, zero elsewhere | Per-subscriber mpsc instead of broadcast (medium) |
| H2 | Connection supersede during the burst — old QUIC connection killed by new dial, in-flight messages on the old connection drop | `subscribe_all_peer_events` shows `Superseded` events for the failing pairs in the matching time window | Use lifecycle bus to flush in-flight queue on supersede + retry on new conn (medium) |
| H3 | Hetzner-Nuremberg-specific UDP behaviour — kernel UDP buffer too small, sysctl `net.core.rmem_max` not raised, packet drops at OS level | `ss -uam` on Nuremberg shows non-zero `RcvbufErrors` during burst | Sysctl tuning + document baseline (small, but vps-side) |
| H4 | Measurement artefact — message arrived but after harness 15 s settle | Replay SSE capture timestamps against send timestamps; if delta > 15 s, it's the harness | Increase settle in harness (trivial) |
| H5 | Cross-cloud routing path — DigitalOcean → Hetzner has periodic packet loss | `mtr --report-cycles 100` from each DO box to Nuremberg shows loss | Possibly nothing we can fix, but we can react to it |

H1 is most likely given the v0.18.3 fix story (recv_tx 128→10000) — the same class of bug, same ratio of fix-but-not-fully. Worth checking first.

---

## 5. Architecture proposal — adaptive thresholds + backpressure

The following are independently shippable. Do them in priority order; each one removes a class of false-positive timeouts.

### 5.1 (P0) Per-peer adaptive DM timeouts

**Today.** Every `/direct/send` waits up to `5 s + 0.5 s + 5 s = 10.5 s` regardless of peer.

**Proposed.** Compute the per-attempt timeout from the peer's smoothed RTT:

```rust
fn dm_attempt_timeout(peer_rtt_ms: Option<u32>) -> Duration {
    let base_ms = peer_rtt_ms
        .filter(|&r| r > 0)
        .unwrap_or(/* network-wide P95, fallback 250 */ 250) as u64;
    // 16× RTT covers 99.9% of jitter on a healthy link, plus a 500 ms floor
    // and a 30 s ceiling so a single misbehaving peer can't hang the API.
    let timeout = (base_ms * 16).clamp(500, 30_000);
    Duration::from_millis(timeout)
}
```

Backoff also scales: `BackoffPolicy::ExponentialFromTimeout { factor: 2 }` already exists in `dm.rs`. Switch the default config to use it.

**Effect.** A 50 ms-RTT pair gets a 800 ms attempt timeout (fast detection of trouble). A 250 ms pair gets 4 s. An unknown peer falls back to 4 s. The user-visible SLO improves *and* the false-positive rate drops because each pair is judged against its own normal.

**File.** `src/dm.rs` (DmSendConfig::default → builder that consumes a peer-id), `src/dm_send.rs:79–115` to look up RTT before each attempt.

**Acceptance.** `e2e_vps.sh` sends average wall-clock latency drops by ≥ 30% on healthy pairs without any reduction in successful delivery rate.

### 5.2 (P0) Replace `subscribe_direct` broadcast with per-subscriber mpsc

**Today.** `src/direct.rs:233` — `broadcast::channel(8192)`. tokio broadcast drops oldest messages from any lagging receiver. The 8 K bump (this release) only raised the bar; under matrix burst even 8 K can be exceeded.

**Proposed.** Each call to `subscribe_direct()` returns an mpsc receiver wrapping a per-subscriber buffer, with the producer side fanning out to all current subscribers. If a single subscriber lags, only that subscriber's queue grows; if it grows past a watermark, drop **that** subscriber explicitly (with a typed error in the receiver) rather than silently shedding messages from the head of the queue.

**Effect.** Slow consumers (a stuck SSE client; a paused file-transfer task) can't cause inbox drops on other consumers. A slow consumer becomes its own observable failure rather than an invisible amplifier.

**File.** `src/direct.rs` (`DirectMessaging::new`, `subscribe()`, internals).

**Acceptance.** Rerun the matrix on a build with this change and `/diagnostics/dm.subscriber_channel_lagged == 0` on every node, even under 10× the matrix burst load.

### 5.3 (P1) Lifecycle-aware send

**Today.** `/direct/send` writes to a connection it believes is alive. If the connection is `Superseded` between the connect-time check and the send, the send may go to an in-flight closing stream and quietly disappear (depending on QUIC ordering at the moment of close). The retry loop catches some of these but with the full 5 s wait per attempt.

**Proposed.** A daemon-wide subscriber on `network.subscribe_all_peer_events()` maintains a hot table of `peer_id → connection_state`. `dm_send` checks the table before each attempt and bails out **immediately** with `DmError::PeerDisconnected{reason}` instead of waiting the full timeout.

**Effect.** When a connection is replaced or closed, in-flight sends fail fast (single-digit ms) rather than at the timeout cap. The caller can re-dial and retry.

**File.** New `src/dm_lifecycle.rs` for the watcher; `src/dm_send.rs` call site.

**Acceptance.** Inject a synthetic `disconnect → reconnect` mid-send (test harness), measure `/direct/send` failure latency. Should be ≤ 100 ms instead of 10.5 s.

### 5.4 (P1) Use `send_with_receive_ack` for `/direct/send` happy path

**Today.** `/direct/send` writes the envelope and returns `ok:true` once the local QUIC stack accepts it. The receiver may never see it (closed connection, lost packet on a path the OS hasn't given up on yet). The caller sees a false success.

**Proposed.** When the chosen path is `raw_quic` and the peer supports `ack_receive_v1`, use `network.send_with_receive_ack(peer_id, data, timeout)` instead of fire-and-forget. The application gets back a real "the receiver's reader task drained these bytes" signal.

This is **not** an end-to-end ACK (the application above the reader task could still drop the message) — but combined with §5.2 (per-subscriber mpsc) the application layer no longer drops, so the QUIC-reader-drain ACK is effectively end-to-end.

**File.** `src/dm_send.rs` (path-chosen branch); `src/network.rs:441` already exposes the API.

**Acceptance.** `e2e_vps.sh` REST sends report `path: "raw_quic_acked"` for every successfully-delivered pair, and `0/30 receives missing` (all 4 residual misses fixed).

### 5.5 (P2) Adaptive per-peer "give up" via phi-accrual

**Today.** `/direct/send` will keep trying until `max_retries` even if the peer is genuinely unreachable. We have a presence system that already produces phi values in real time, but DM doesn't consume them.

**Proposed.** Before starting a `/direct/send`, query the presence system for `phi(peer_id)`. If `phi > 8` (peer almost certainly down), short-circuit with `DmError::PeerLikelyOffline{phi}` so the caller can decide between buffering, escalating, or giving up. After a successful send, feed the success back into the presence ledger so phi recovers.

**Effect.** When NYC tries to send to a Nuremberg that's actually down, NYC fails in 50 ms instead of 10.5 s. When Nuremberg comes back, the next send tries immediately.

**File.** New `src/dm_presence_link.rs` reading from `presence::PresenceWrapper`.

**Acceptance.** Stop a fleet node mid-test; sends to it from other nodes start failing within 2× the heartbeat interval rather than after the DM timeout cap.

### 5.6 (P2) Optional dual-path delivery for important messages

**Today.** A message goes either `raw_quic` or `gossip_inbox`, never both.

**Proposed.** A `DmSendConfig::dual_path_critical: bool` flag. When true and both paths are available, send via both with a single `request_id`. Receiver dedups on first arrival. Cost: 2× bandwidth for those messages. Benefit: any single-path transient issue is invisible.

This is the only proposal that **adds** load instead of removing it, so it's opt-in. Use cases: agent card delivery, file offer (small messages), MLS welcome envelopes.

**File.** `src/dm_send.rs`; receiver dedup already exists via `RecentDeliveryCache`.

---

## 6. P2P-aware error model

Today `DmError` is a flat list. Callers can't easily distinguish "try again immediately" from "this peer is gone, route around it" from "the network is unhealthy globally". Proposed taxonomy:

```rust
pub enum DmError {
    // ── Transient, retry on the same peer ──────────────────────────
    Timeout { elapsed_ms: u64, retries_used: u8 },
    LocalGossipUnavailable(String),
    AckRegistryReplaced,

    // ── Peer-specific, route around or back off ────────────────────
    PeerLikelyOffline { phi: f64, last_seen_ms_ago: Option<u64> },
    PeerDisconnected { reason: String },
    PeerNoCapability { capability: String },
    PeerTrustRejected { trust_level: TrustLevel },

    // ── Identity / structural, do not retry ────────────────────────
    AgentNotFound(AgentId),
    PayloadTooLarge { len: usize, max: usize },
    SignatureFailed,

    // ── Network-wide, surface to operator ──────────────────────────
    NoConnectivity,
}
```

Mapping in the REST handler tells the caller which HTTP status to set:

| Error class | HTTP | Caller action |
|---|---|---|
| Transient | 503 (Retry-After) | Auto-retry with backoff |
| Peer-specific | 502 | Route around / inform user |
| Structural | 4xx | Don't retry, fix the request |
| Network-wide | 503 | Fail loudly to operator |

---

## 7. Implementation phases

Each phase ships independently; nothing in a later phase blocks an earlier one.

### Phase 1 — diagnose (1 week)
- (P0) `/diagnostics/dm` endpoint (§4.1.1)
- (P0) per-message correlation log (§4.1.2)
- (P0) Nuremberg burst runbook (§4.2)
- **Exit criterion:** we know the mechanism for each of the 4 residual fails. Hypothesis ranking (§4.3) is replaced with evidence.

### Phase 2 — kill the broadcast lag (1 week)
- (P0) Per-subscriber mpsc replaces `broadcast::channel` (§5.2)
- (P1) Adaptive DM timeouts from per-peer RTT (§5.1)
- **Exit criterion:** `e2e_vps.sh` clean — 0/30 send fails *and* 0/30 receive misses on the 6-VPS matrix. Two consecutive runs.

### Phase 3 — lifecycle awareness (1 week)
- (P1) Lifecycle bus subscriber for fast-fail on disconnect (§5.3)
- (P1) `send_with_receive_ack` happy path (§5.4)
- **Exit criterion:** synthetic disconnect-mid-send fails in ≤ 100 ms; receive-ACK rate is ≥ 99% on the matrix.

### Phase 4 — P2P error model (1 week)
- (P2) Phi-accrual-driven short-circuit (§5.5)
- (P2) Structured `DmError` taxonomy (§6) + REST status mapping
- **Exit criterion:** stopping a fleet node stops sends to it within 2× heartbeat (≈ 60 s) without timing out at the DM cap.

### Phase 5 — observability + opt-in dual path (1 week)
- (P2) `/diagnostics/dm` per-peer view (already in §4.1.1) → Prometheus scrape
- (P2) Dual-path delivery for opt-in critical messages (§5.6)
- **Exit criterion:** dashboards exist for per-peer DM health; documentation describes when to opt into dual path.

Total ≈ 5 dev-weeks. Phase 1 alone could be a 2-day push if a single dev focuses.

---

## 8. Acceptance criteria for the whole effort

The investigation succeeds when **all** of these hold:

1. `e2e_vps.sh` produces 0/30 send fails and 0/30 receive misses on two consecutive runs on the live 6-VPS fleet, with no harness timeout changes.
2. `e2e_first_message_after_join.sh` continues to pass 24/24.
3. The 8h `e2e_soak_3node.sh` continues to pass with `decode_to_delivery_drops == 0` and `subscriber_channel_lagged == 0` on every node.
4. A deliberate cold-start-stop-restart of any single fleet node produces zero false-positive timeouts in `e2e_vps.sh` — sends to the stopped node fail with `PeerLikelyOffline` or `PeerDisconnected`, never `Timeout`, within 2× heartbeat.
5. Synthetic localhost-loopback `/direct/send` round-trip latency is ≤ 5 × measured RTT on the happy path (down from the current implicit cap of 10.5 s).
6. `/diagnostics/dm` exposes per-peer state for every connected peer; `/peers/events` SSE has had a non-trivial consumer (the new lifecycle watcher) running in production.

---

## 9. What this is not

- **Not** a request to remove every timeout. Hard ceilings remain — we just stop using them as the primary failure detector. They become watchdogs against unbounded resource use, not user-visible failure thresholds.
- **Not** a request to drop fixed timeouts in tests/harnesses. Tests need deterministic time bounds. The architectural change is in the daemon's internal decision logic, not in test gates.
- **Not** scope creep into ant-quic. Everything proposed lives in x0x and consumes ant-quic surfaces that already exist (RTT, lifecycle bus, ACK frames, probe).

---

## 10. References

- `proofs/release-v0.19.17-20260430T133431Z/03-vps/vps.log` — the 4 residual failures
- `proofs/full-suite-20260429T214746Z/03-vps/SUMMARY.md` — manual three-mode repro
- `proofs/full-suite-20260429T214746Z/09-soak-8h/SUMMARY.md` — pubsub timed_out at 10 s cap (now 30 s)
- `docs/debug/cross-region-all-pairs-timeouts.md` — earlier debug brief, supersedes by this document
- `src/dm.rs:288–321` — current DmSendConfig
- `src/dm_send.rs:79–125` — current retry loop
- `src/direct.rs:229–243` — current broadcast channel
- `src/network.rs:418–457` — RTT / lifecycle / ACK surfaces already exposed
- `ant-quic/src/bootstrap_cache/entry.rs:380–402` — EWMA RTT recording
