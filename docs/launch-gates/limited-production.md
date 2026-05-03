# Limited-production launch gate

This is the bar a build of `x0xd` must clear before being recommended to
early adopters or used as the default bootstrap recommendation. It is
deliberately easier to clear than `broad-launch.md`, because limited
deployments tolerate a small amount of degradation while we collect more
operational evidence.

## Run

```
python3 tests/launch_readiness.py --gate limited-production \
    --scenarios baseline,fanout_burst
```

The harness writes a verdict + per-node deltas to
`proofs/launch-readiness-<run-id>/summary.md` and a CSV to
`summary.csv`. The harness exits 0 only if every scenario passes.

## Thresholds (per-scenario window, ~5-10 min)

| Metric | Threshold | Rationale |
|---|---|---|
| `dispatcher.pubsub.timed_out` delta per node | ≤ 5 | Allows a small residual under transient slow peers, but a sustained climb means cooling is failing. |
| `recv_pump.pubsub.dropped_full` delta per node | 0 | Drops indicate the recv-pump overload policy engaged. Even one drop in a clean window is unexpected. |
| `republish_per_peer_timeout` delta per node | ≤ 200 | Slow-peer fanout will fire timeouts; the bar caps how much before cooling has to absorb them. |
| `suppressed_peers` size at end of run | ≤ 200 | Bounded growth — runaway suppression means recovery isn't completing. |
| Phase A directed-pair receives | = 30 | Mesh DM correctness is non-negotiable. |
| Restart-storm recovery (when run) | ≤ 90s | Operator-grade recovery on planned restarts. |

## What the gate does NOT cover

- Long-soak behaviour (≥ 24 h). Run separately; SLO bars from this gate
  apply to each rolling window inside the soak.
- Coordinated partition + heal scenarios that require `iptables` or
  `netem` on the target hosts. These are scaffolded in
  `tests/launch_readiness.py` but not enabled in the default scenario
  list — flip them on after a manual approval gate.
- Update/rollout flow under `release.yml` — covered by the existing
  release smoke tests.

## When to advance to the broad-launch gate

Three consecutive limited-production passes over a 7-day window with no
operator restart, no manual peer suppression, and no upstream
`saorsa-gossip` patch. Then run `broad-launch.md` against the same
build.
