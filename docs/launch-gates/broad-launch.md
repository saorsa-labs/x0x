# Broad-launch gate

This is the bar a build of `x0xd` must clear before a fleet-wide launch
push (marketing, public bootstrap recommendation, opening the network
to a large external user base). It is stricter than
[`limited-production.md`](limited-production.md) on dispatcher timeouts,
recv-pump drops, suppression ratio, Phase A delivery, and restart
recovery. Per-peer timeout and suppression handling are intentionally
scale-aware rather than stricter absolute counts.

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

## Thresholds (per-scenario window, ~5-10 min)

| Metric | Threshold | Rationale |
|---|---|---|
| `dispatcher.pubsub.timed_out` delta per node | 0 | At broad-launch scale, a single dispatcher timeout per window is a regression to investigate. |
| `recv_pump.pubsub.dropped_full` delta per node | 0 | Broad-launch must demonstrate the overload policy never engages on the bootstrap mesh. |
| `republish_per_peer_timeout / dispatcher.pubsub.completed` delta ratio per node | ≤ 0.25 | Per-peer timeouts are downstream isolated-send events. The broad-launch gate normalizes them by handled PubSub volume so a busier healthy mesh is not failed for natural RTT variance. |
| `suppressed_peers / known_peer_topic_pairs` at end of run | ≤ 0.12 | Suppression is a bounded cooling set, but the healthy absolute count scales with fleet activity and topic count. The 2026-05-03 12h soak observed 101-134 suppressed entries on the Nuremberg node with roughly 1.3k-1.4k known peer-topic scores, which is healthy but above the old absolute-100 bar. The warmed 2026-05-04 2h soak stayed clean on Phase A, dispatcher timeouts, and drops while the suppression ratio ranged 0.083-0.113, so 0.12 is the calibrated broad-launch ceiling. |
| Phase A directed-pair receives | = 30 | Always. |
| Restart-storm recovery | ≤ 30s | Indicates the bootstrap cache and ant-quic re-handshake path are healthy. |

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

## Required additional evidence (beyond harness)

The harness gives you a snapshot. The broad-launch gate also needs:

- A **12h+ soak** of the full bootstrap mesh with this build, captured
  as a per-node CSV under `proofs/launch-readiness-soak-<run-id>/`.
  Phase A directed pairs and `recv_pump.pubsub.dropped_full` remain
  strict. A dispatcher-only transient is accepted at the soak level when
  cumulative `dispatcher.pubsub.timed_out` across all nodes is ≤ 5 per
  12h and every affected window is otherwise clean.
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
- The most recent **codex-task-reviewer** sign-off on the upstream
  `saorsa-gossip` release notes.

## What this gate does NOT cover

- Adversarial (hostile-peer) scenarios. The X0X-0010..14 work makes
  the mesh resilient to slow/stale peers, not to peers actively
  attempting to disrupt PlumTree. Treat hostile-peer hardening as a
  separate launch-readiness track.
