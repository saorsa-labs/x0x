# 20-node scale stress summary

Command:

```bash
bash tests/e2e_stress_gossip.sh --nodes 20 --messages 1000 --proof-dir proofs/stress-20260421-v0185-20x1000
```

Outcome: **strict gate failed**.

## What held

- `decode_to_delivery_drops = 0` on **all 20 nodes**.
- Publisher recorded `publish_total = 1136` for the 1000-message run.
- Most subscribers landed at or above 1000 delivered messages.

## What failed

With `MIN_DELIVERY_RATIO=1.0`, 8 subscribers finished slightly below the strict `1000` threshold:

- node-2: 991
- node-6: 999
- node-11: 992
- node-12: 999
- node-14: 990
- node-18: 993
- node-19: 999
- node-20: 988

## Interpretation

This does **not** look like a pipeline-drop regression (`decode_to_delivery_drops` stayed zero everywhere). It looks more like a convergence / settle-window issue at 20 nodes under the script's default timing, or a fan-out / anti-entropy gap that only appears once the mesh is larger than the 3–5-node proofs used so far.

This item remains open for follow-up debugging.
