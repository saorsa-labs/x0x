# TreeKEM high-churn convergence — investigation CLOSED (degraded-network tail)

**Date:** 2026-06-05
**Outcome:** Not an x0x logic bug. Multi-member TreeKEM converges ~100% under normal
conditions; the low numbers were a degraded-network tail. Closed as a connection-resilience /
infra concern. `welcome.trace` instrumentation left in (on `main`) to capture a real failure
when conditions next degrade.

## What was chased
The v0.21.1 "known limitation": multi-member TreeKEM converged only 78% (daytime) / 47%
(overnight) under sustained churn, failing at `converge_member_*` with `Welcome not processed`.

## What it actually is
A **degraded-network tail**, not a persistent code bug. Evidence:

| run | conditions | convergence | Welcome-transfer failures |
|---|---|---|---|
| overnight retry soak | degraded | 47% | many |
| daytime baseline (A/B Block A) | moderate | 90% (54/60) | 6 |
| instrumented diagnostic (110 iters) | good daytime | **100% (110/110)** | **0** |

- On good conditions the Welcome transfer is flawless (`welcome.trace`: 0 `final_ack_failed`,
  0 `chunk_recv_no_pending` across 110 iters).
- The `Peer not found` flood we kept anchoring on is **background noise**: 2207 in a 2h window
  that converged 100%. It comes from `ant_quic::send_error` (ant-quic-internal / gossip),
  **not** the x0x Welcome send path.
- Convergence does **not** track the `Peer not found` rate cleanly (≈2× more overnight, but
  100% vs 47% convergence) — the tail is dominated by sustained cross-region degradation.

## Fixes tried and rejected (all targeted the background noise, none worked)
1. **Inline-Welcome / defer-fetch** (earlier) — regressed delivery; reverted.
2. **FetchRequest retry within the 90s budget** (`fix/welcome-fetch-retry`, would-be 0.21.2) —
   NO-GO soak (47% vs 78%, confounded by overnight); re-requesting amplifies the anchor's
   re-serves and can't fix a chunk-*delivery* leg. Not merged.
3. **Redial-on-`Peer not found`** (`fix/redial-on-peer-not-found`) — controlled same-day A/B:
   92% vs 90% baseline (noise), `welcome_final_ack_failed` unchanged (4→4). The Welcome path
   doesn't hit `Peer not found` at the x0x send layer; the failure is "chunks sent OK
   (`node.send` Ok) but never ACKed (`last_acked=<none>`)" on a *present* connection, which
   redial can't fix. Not merged.

## What landed
- `welcome.trace` diagnostics on `main` (commit `7090485`, trace-only) — ready to capture a
  real failure end-to-end (anchor sent vs receiver recv vs acks) when conditions degrade.
- CHANGELOG `[Unreleased]` notes the refined understanding.
- The redial + retry branches are kept as records, **unmerged**.

## If revisited
- Capture during a degradation window (overnight) with `welcome.trace=debug` on anchor + m2;
  read per-`welcome_id` hop counts to confirm whether chunks are lost in flight, the receiver
  lacks pending-receive state, or acks don't return.
- The likely lever is connection resilience under cross-region degradation (idle eviction /
  keepalive), partly ant-quic's domain; and saorsa-gossip#24 (Critical vs cooling) for the
  membership-DM leg.
- 0.21.1 (shipped) already carries the real wins: X0X-0074d overflow fix + the TreeKEM
  signed-state-chain (invite base-state) convergence fix.

## Evidence index
- `proofs/treekem-soak-20260604T162134Z/RESULT.md` (0.21.1 baseline soak)
- `proofs/treekem-soak-retry-20260604T233730Z/RESULT.md` (retry NO-GO)
- `proofs/ab-welcome-retry-*/RESULT.md` (redial A/B NO-GO)
- `proofs/welcome-trace-diag-*/` (110/110 instrumented diagnostic)
- `handoff/0212-welcome-fetch-retry-SECOND-OPINION-2026-06-05.md`,
  `handoff/cooling-vs-welcome-fetch-2026-06-04.md`,
  `handoff/treekem-convergence-SECOND-OPINION-2026-06-04.md`
