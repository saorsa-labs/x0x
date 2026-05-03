# Broad-launch gate

This is the bar a build of `x0xd` must clear before a fleet-wide launch
push (marketing, public bootstrap recommendation, opening the network
to a large external user base). It is stricter than
[`limited-production.md`](limited-production.md) on dispatcher timeouts,
recv-pump drops, suppression size, Phase A delivery, and restart
recovery. Per-peer timeout handling is intentionally scale-aware rather
than a stricter absolute count.

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

## Thresholds (per-scenario window, ~5-10 min)

| Metric | Threshold | Rationale |
|---|---|---|
| `dispatcher.pubsub.timed_out` delta per node | 0 | At broad-launch scale, a single dispatcher timeout per window is a regression to investigate. |
| `recv_pump.pubsub.dropped_full` delta per node | 0 | Broad-launch must demonstrate the overload policy never engages on the bootstrap mesh. |
| `republish_per_peer_timeout / dispatcher.pubsub.completed` delta ratio per node | ≤ 0.25 | Per-peer timeouts are downstream isolated-send events. The broad-launch gate normalizes them by handled PubSub volume so a busier healthy mesh is not failed for natural RTT variance. |
| `suppressed_peers` size at end of run | ≤ 100 | Bounded suppression set across all topics. |
| Phase A directed-pair receives | = 30 | Always. |
| Restart-storm recovery | ≤ 30s | Indicates the bootstrap cache and ant-quic re-handshake path are healthy. |

The harness still reports raw `republish_per_peer_timeout` deltas in
`summary.md` and `summary.csv`. Treat a raw value above roughly 200 per
node per scenario window as an investigation signal, especially if it is
concentrated on one peer or region, but do not fail broad launch on that
absolute count alone while `dispatcher.pubsub.timed_out`,
`recv_pump.pubsub.dropped_full`, and the normalized timeout ratio remain
inside the gate.

## Required additional evidence (beyond harness)

The harness gives you a snapshot. The broad-launch gate also needs:

- A **24h soak** of the full bootstrap mesh with this build, captured
  as a per-node CSV under `proofs/launch-readiness-soak-<run-id>/`,
  showing dispatcher.timed_out flat at 0 and the supervisor staying
  inside its scale-down band.
- One **partition-recovery scenario** executed against a non-production
  pair (e.g., two of the saorsa-N hosts that are not in active use):
  block `:5483` between the pair for 60s with `iptables`, then unblock,
  and confirm anti-entropy reconciliation completes within 90s.
- The most recent **codex-task-reviewer** sign-off on the upstream
  `saorsa-gossip` release notes.

## What this gate does NOT cover

- Adversarial (hostile-peer) scenarios. The X0X-0010..14 work makes
  the mesh resilient to slow/stale peers, not to peers actively
  attempting to disrupt PlumTree. Treat hostile-peer hardening as a
  separate launch-readiness track.
