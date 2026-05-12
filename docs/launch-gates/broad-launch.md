# Broad-launch gate

This is the bar a build of `x0xd` must clear before a fleet-wide launch
push (marketing, public bootstrap recommendation, opening the network
to a large external user base). It is stricter than
[`limited-production.md`](limited-production.md) on dispatcher timeouts,
recv-pump drops, suppression ratio, Phase A delivery, and restart
recovery. Per-peer timeout and suppression handling are intentionally
scale-aware rather than stricter absolute counts.

## Two-layer evaluation model

Broad-launch certification has **two distinct layers** that evaluate
the mesh on different timescales:

1. **`launch_readiness.py` — per-window strict gate.** A single
   15-minute scenario window is treated as an investigation trigger:
   any `dispatcher_timed_out` event, any recv-pump drop, any Phase A
   pair miss, or any `data_tx` high-water event in that window =
   per-window NO-GO. This layer surfaces transient regressions early,
   not certifies the release.

2. **`launch_soak.py` — aggregate multi-burn-rate certification.**
   This is the actual broad-launch certifier. It runs `launch_readiness.py`
   on a 15-minute cadence for hours, then evaluates aggregate SLOs:

   - `dispatcher_noise_policy` (tests/launch_soak.py:211) classifies
     fleet-wide dispatcher noise using normalized rates:
     `legacy-count-ok` (≤5 events in 12h), `adaptive-rate-ok`
     (≤0.01% of completed dispatches), `fleet-rate-high`,
     `window-rate-high`, or `consecutive-anomalies` (>2 windows of
     baseline×4 anomaly).
   - `tolerated_dispatcher_windows` (tests/launch_soak.py:454)
     reclassifies per-window NO-GOs whose **only** violation is
     `dispatcher_timed_out delta` (with Phase A still ≥30 and
     `dropped_full == 0`) as tolerated, so a window that fired the
     per-window investigation trigger doesn't fail the soak unless
     the aggregate policy also flags it.
   - `effective_failed` (tests/launch_soak.py:453) counts only
     windows that fail for reasons beyond dispatcher noise.
   - `overall_pass` (tests/launch_soak.py:468) requires zero
     `effective_failed`, zero missing windows, zero unaccounted
     telemetry gaps, `dispatcher_noise_policy.passed == true`, and
     cumulative `dropped_full == 0`.

   This is the implementation of the X0X-0065 SOTA "Pattern 1"
   multi-burn-rate framework (Google SRE / Datadog / k6). The
   per-window gate is intentionally strict so that the aggregate
   policy has high-signal input to classify; do not relax the
   per-window thresholds to make individual windows pass.

## Run

```
python3 tests/launch_readiness.py --gate broad-launch \
    --scenarios baseline,fanout_burst,restart_storm \
    --allow-restart-storm
```

`restart_storm` is destructive (it issues `systemctl restart x0xd` on
non-anchor nodes), so it requires the explicit
`--allow-restart-storm` flag. Run during a quiet window and verify the
mesh recovers before chaining further work.

The fault-injection scenarios are also destructive and opt-in:

```
python3 tests/launch_readiness.py --gate broad-launch \
    --scenarios high_rtt_peer \
    --allow-netem --target-node sydney

python3 tests/launch_readiness.py --gate broad-launch \
    --scenarios partition_recovery \
    --allow-iptables --partition-pair sfo,sydney
```

Do not run these during a baseline soak. `high_rtt_peer` installs a
temporary `tc netem` delay on the target node and removes it on
completion or interrupt. `partition_recovery` inserts temporary
commented `iptables` DROP rules between the pair and removes them on
completion or interrupt.

The large-topic overlay proof is non-destructive and runs locally:

```
python3 tests/topic_overlay_scale.py \
    --peers 1000,5000,10000 \
    --topic x0x.scale.hot \
    --publish-rate 1 \
    --duration-secs 300 \
    --proof-dir proofs/topic-overlay-scale-<run-id>
```

This proof is about topic-overlay shape, not WAN reachability. It must
show that a hot topic keeps per-node EAGER and LAZY views bounded while
the global aggregate traffic grows with subscriber count.

## Per-window thresholds (`launch_readiness.py`, ~5-10 min)

These are the strict investigation triggers for one 15-minute window.
Each is an "any event = NO-GO for this window" gate. They are the
input to the soak-level aggregate classifier — do not relax them to
make individual windows pass.

| Metric | Threshold | Rationale |
|---|---|---|
| `dispatcher.pubsub.timed_out` delta per node | 0 | At broad-launch scale, a single dispatcher timeout per window is a regression to investigate. The soak-level `dispatcher_noise_policy` decides whether the aggregate pattern is tolerable. |
| `recv_pump.pubsub.dropped_full` delta per node | 0 | Broad-launch must demonstrate the overload policy never engages on the bootstrap mesh. |
| `republish_per_peer_timeout / dispatcher.pubsub.completed` delta ratio per node | ≤ 0.25 | Per-peer timeouts are downstream isolated-send events. The broad-launch gate normalizes them by handled PubSub volume so a busier healthy mesh is not failed for natural RTT variance. |
| `suppressed_peers / known_peer_topic_pairs` at end of run | ≤ 0.12 | Suppression is a bounded cooling set, but the healthy absolute count scales with fleet activity and topic count. The 2026-05-03 12h soak observed 101-134 suppressed entries on the Nuremberg node with roughly 1.3k-1.4k known peer-topic scores, which is healthy but above the old absolute-100 bar. The warmed 2026-05-04 2h soak stayed clean on Phase A, dispatcher timeouts, and drops while the suppression ratio ranged 0.083-0.113, so 0.12 is the calibrated broad-launch ceiling. |
| Phase A directed-pair receives | = 30 | Always. A miss in one window is a per-window NO-GO; soak certification is decided by `effective_failed` after the dispatcher-only tolerated set is applied. |
| Restart-storm recovery | ≤ 30s | Indicates the bootstrap cache and ant-quic re-handshake path are healthy. |
| `data_tx.high_water_count` delta per node | 0 | X0X-0039 + X0X-0063 acceptance — any saturation event signals a real back-pressure regression even at the 50_000 capacity. |

## Soak-level aggregate gate (`launch_soak.py`)

| Metric | Threshold | Source |
|---|---|---|
| `effective_failed` windows | 0 (after `tolerated_dispatcher_windows` + `tolerated_phase_a_windows` removed) | tests/launch_soak.py |
| `missing` windows | 0 | tests/launch_soak.py |
| `unaccounted_gap_windows` | 0 | tests/launch_soak.py |
| Cumulative `dropped_full` | ≤ `SOAK_MAX_RECV_PUMP_DROPPED_FULL_DELTA` (0) | tests/launch_soak.py |
| `dispatcher_noise_policy.passed` | `true` (verdict ∈ {legacy-count-ok, adaptive-rate-ok}) | tests/launch_soak.py |
| Aggregate `dispatcher_timed_out` total | ≤ `SOAK_MAX_DISPATCHER_TIMED_OUT_DELTA_PER_12H` (5) **or** rate ≤ `SOAK_MAX_DISPATCHER_TIMEOUT_RATIO` (0.0001) | tests/launch_soak.py |
| Max per-window dispatcher rate | ≤ `SOAK_MAX_DISPATCHER_TIMEOUT_RATIO_PER_WINDOW` (0.0001) | tests/launch_soak.py |
| Consecutive baseline×4 anomaly windows | ≤ `SOAK_MAX_CONSECUTIVE_DISPATCHER_ANOMALY_WINDOWS` (2) | tests/launch_soak.py |
| Aggregate Phase A `sent / (30 × non-missing windows)` | ≥ `SOAK_MIN_AGGREGATE_PHASE_A_RATIO` (0.98) | tests/launch_soak.py |
| Aggregate Phase A `received / (30 × non-missing windows)` | ≥ `SOAK_MIN_AGGREGATE_PHASE_A_RATIO` (0.98) | tests/launch_soak.py |
| Tolerated dispatcher-only windows | reported, do not fail soak | tests/launch_soak.py |
| Tolerated phase-A tail windows | reported, do not fail soak iff aggregate Phase A SLO holds | tests/launch_soak.py |

### Aggregate Phase A SLO — X0X-0065 Pattern 1

The per-window strict gate (`min_phase_a_pairs = 30`) treats any pair
miss in a 15-min window as an investigation trigger. At cross-region
RTTs (helsinki ↔ singapore/sydney is ~280 ms one-way) a single PTO +
retransmit can exceed the ACK budget on a tail event, costing one of
the 30 pairs in that window — without indicating a sustained
regression.

The aggregate Phase A SLO is the soak-level Pattern 1 application:

- Numerator: `sum(phase_a_sent across windows)` and
  `sum(phase_a_received across windows)`, computed separately.
- Denominator: `SOAK_MIN_PHASE_A_PAIRS × len(non-missing windows)`.
- Tolerance rule: a NO-GO window whose **only** violations are in
  the `dispatcher_timed_out` or `phase_a` family (and where
  `recv_pump.dropped_full == 0` for the window) joins
  `tolerated_phase_a_windows` iff the aggregate ratios are at or
  above `SOAK_MIN_AGGREGATE_PHASE_A_RATIO` once all windows are
  classified.
- Hard floor: `recv_pump.dropped_full`, `per_peer_timeout` ratio
  above gate, and `suppressed_peers` ratio remain strict — none of
  those classes is tolerated by the aggregate SLO. Any non-tail
  violation in a window sends it straight to `effective_failed`.

The 98% bar is the calibrated datum point — it matches the proven
2026-05-11 19:26Z pre-hedge soak (118/120 sent = 98.33%, 120/120
received = 100%) on the released stack (x0x 0.19.41 + ant-quic
0.27.21 without hedging). The X0X-0065 acceptance criterion
originally proposed 99% but ran ~0.67% above what the unmodified
mesh achieves; the X0X-0066 hedging attempt to close that gap
regressed recv-miss and was rolled back. At the 6-node VPS bootstrap
matrix the 98% floor gives ~9 tolerated pair misses per 4h soak
(480 pairs × 2%); deeper deployments scale the denominator
naturally. Future tightening below 98% needs a documented
mechanism-layer change (e.g. lower-level hedging that avoids the
subscribe_direct recv-miss class), explicit acceptance evidence,
and a re-soak.

The harness still reports raw `republish_per_peer_timeout` deltas and
raw `suppressed_peers` counts in `summary.md` and `summary.csv`. Treat a
raw per-peer timeout value above roughly 200 per node per scenario
window, or a raw suppression count that is concentrated on one peer or
region, as an investigation signal. Do not fail broad launch on those
absolute counts alone while `dispatcher.pubsub.timed_out`,
`recv_pump.pubsub.dropped_full`, and the normalized ratios remain inside
the gate.

## Soak-of-record practice

A broad-launch soak should start from a **warmed mesh**, not a cold or
just-rebooted one. The first window after the harness starts can show
elevated `suppressed_peers / known_peer_topic_pairs` ratio while the
cooling state drains from any prior load — this is real and worth
recording as health evidence (cooling visibly draining is itself a good
signal), but it is not the soak-of-record.

Operator practice: before the soak run that you intend to use as
broad-launch evidence, run one `launch_readiness.py` baseline scenario
against the live mesh and confirm the per-node `suppressed/known` ratios
have settled near their natural baseline. Then start
the soak. If the soak's window 1 still clips the gate but windows 2+
drain monotonically with `dispatcher.timed_out=0` and `dropped_full=0`,
discard the run and re-soak from the warmed state — do not loosen the
gate threshold on a single elevated window.

If a warmed soak still clips the gate consistently across windows, the
threshold itself may need revisiting. Until then the gate is doing
exactly what it should: catching the difference between healthy
steady-state and elevated cooling pressure.

Do not tune these bars by repeatedly fitting them to this six-node VPS
mesh. The product has to run on residential, mobile, asymmetric, and
hostile-path networks, so launch evidence must prefer normalized rates,
bounded growth, and adaptive recovery over operator-selected constants.
The fixed bootstrap-mesh numbers are investigation triggers, not a
portable model of all future user connections.

## Required additional evidence (beyond harness)

The harness gives you a snapshot. The broad-launch gate also needs:

- A **12h+ soak** of the full bootstrap mesh with this build, captured
  as a per-node CSV under `proofs/launch-readiness-soak-<run-id>/`.
  The soak summary must use continuous post-to-post diagnostics deltas,
  not only the short scenario pre/post window. Phase A directed pairs
  and `recv_pump.pubsub.dropped_full` remain strict. The current
  dispatcher-only cap is a conservative bootstrap-mesh investigation
  trigger, not the final policy: a raw count above it is acceptable only
  when the adaptive dispatcher-only policy also shows a low normalized
  timeout rate and no sustained anomaly. Do not "fix" a raw count by
  retuning to the VPS fleet without also checking normalized
  `dispatcher.timed_out / dispatcher.completed`, per-node-hour rates,
  telemetry gaps, queue/backlog growth, and whether delivery or drops
  degraded.
- One **high-RTT slow-peer scenario** with `high_rtt_peer` against a
  non-anchor node, writing
  `scenarios/high_rtt_peer/peer-score-trajectory.json` and proving that
  the target peer cools/demotes while the rest of the mesh keeps
  dispatcher timeouts at 0.
- One **partition-recovery scenario** executed against a non-production
  pair (e.g., two of the saorsa-N hosts that are not in active use):
  block `:5483` between the pair for 60s with `iptables`, then unblock,
  and confirm anti-entropy reconciliation completes within 90s. The
  harness writes `scenarios/partition_recovery/recovery.json` and
  verifies that the temporary rules are gone before it reports.
- One **large-topic overlay scale proof** from
  `tests/topic_overlay_scale.py` at 1k, 5k, and 10k virtual subscribers.
  The proof must write
  `proofs/topic-overlay-scale-<run-id>/summary.md` and `metrics.csv`,
  keep p99 EAGER degree inside the PlumTree target envelope, keep p99
  LAZY/topic view below the documented cap, and detect the invalid
  full-view behaviour where every subscriber is retained as a LAZY peer.
- The most recent **codex-task-reviewer** sign-off on the upstream
  `saorsa-gossip` release notes.

## What this gate does NOT cover

- Adversarial (hostile-peer) scenarios. The X0X-0010..14 work makes
  the mesh resilient to slow/stale peers, not to peers actively
  attempting to disrupt PlumTree. Treat hostile-peer hardening as a
  separate launch-readiness track.
