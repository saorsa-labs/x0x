# ADR 0009: Receive-Pump Overload Policy

## Status

Accepted

## Context

The 6-node VPS bootstrap mesh can saturate x0x's per-peer PubSub receive forward channel (`recv_pubsub_tx`). The 2026-05-01 Phase A/B baseline showed sustained `used=9999..10000` on the long-RTT receivers, with WARN counts:

- nyc: 2
- sfo: 4
- helsinki: 0
- nuremberg: 0
- singapore: 10
- sydney: 21

The previous capacity increase to 10,000 messages is only headroom. It preserves apparent zero drops by awaiting `mpsc::Sender::send()`, but that back-pressures the ant-quic receive task. Under PubSub fanout, this can stall unrelated receive work on the same transport path and delay latency-sensitive control messages.

The immediate production requirement is to make overload visible and stop PubSub saturation from silently stalling ant-quic receive draining.

## Decision

1. Add receive-pump diagnostics to `/diagnostics/gossip` under `recv_pump`:
   - per-stream produced/enqueued/dequeued/drop counters
   - producer and consumer rates since node start
   - latest/max queue depth
   - average/max queue dwell time
   - per-peer produced and full-drop counters by stream type
2. Treat PubSub overload as lossy but observable:
   - PubSub forwarding uses non-blocking `try_send()`.
   - If `recv_pubsub_tx` is full, the frame is dropped and `recv_pump.pubsub.dropped_full` is incremented.
   - Membership and Bulk keep the previous await/send behavior because they carry low-volume control/presence traffic.
3. Keep the >80% WARN and add the >50% INFO trend signal from X0X-0003 so operators can see pressure before drops.

This is a minimal production mitigation. It avoids making the ant-quic receive pump wait behind a saturated PubSub queue while preserving explicit counters for reliability analysis.

## Consequences

Positive:

- A saturated PubSub queue no longer blocks ant-quic receive draining indefinitely.
- Operators can distinguish clean delivery from overload-driven PubSub loss.
- The same diagnostics provide before/after evidence for future parallel recv-pump work.

Negative:

- PubSub can now drop frames under overload. This is intentional and visible, but it may reduce delivery during bursts until PlumTree retransmission or higher-level reconciliation catches up.
- Per-peer diagnostics are best-effort and skip updates if their mutex is contended, to avoid becoming a new hot-path bottleneck.

## Follow-up

If VPS proof runs still show unacceptable PubSub loss or control-plane latency, prototype the next structural option: parallel PubSub decode/verify/fanout workers downstream of `recv_pubsub_rx`, with ordering/duplicate behavior validated against PlumTree semantics.

## X0X-0005 addendum: parallel PubSub dispatch workers

The 2026-05-02 eight-hour VPS saturation event met the follow-up condition above: `recv_pump.pubsub.consumer_per_sec` fell far below producer rate, `dropped_full` exceeded 50% in the saturated window, and `dispatcher.pubsub.timed_out` consumed most dispatcher wall-clock time.

Decision:

- Add `gossip.dispatch_workers` (default `1`, valid range `1..=8`) as the rollback knob for parallel PubSub dispatch.
- When `dispatch_workers > 1`, x0x spawns that many PubSub dispatcher tasks. They share the existing `recv_pubsub_rx` mpsc receiver as a work queue through the receiver mutex; each worker dequeues one frame, applies the existing per-message 30 s timeout, and calls `PubSubManager::handle_incoming` independently.
- PlumTree state remains inside `saorsa-gossip-pubsub` and is protected by its per-topic `RwLock`. Deduplication/cache mutation stays under that lock; network fanout still happens after the lock is released.
- Per-message timeout semantics become per-worker: one stuck EAGER fanout can pin one worker, but the remaining workers continue draining. If every worker is pinned, X0X-0004's `try_send`/`dropped_full` overload policy remains the safety net.
- Subscriber slow-consumer isolation is explicit in diagnostics via `stats.slow_subscriber_dropped`. x0x's local subscriber handoff already uses non-blocking `try_send`; a full subscriber channel is dropped instead of waiting behind a stuck SSE/client path.

Ordering decision:

- Default `dispatch_workers = 1` preserves the previous global FIFO dispatch behavior for one release cycle.
- Operators who raise `dispatch_workers` explicitly accept relaxed completion ordering between PubSub frames from the same sender/topic. Arrival order into `recv_pubsub_rx` is unchanged, but concurrent workers may complete a later frame before an earlier slow frame. x0x PubSub/CRDT payloads are designed to be idempotent and order-independent, and PlumTree duplicate/replay protection is keyed by message ID/payload cache rather than dispatcher completion order.
- If a future payload type requires strict per-(sender, topic) FIFO, it must either stay on `dispatch_workers = 1` or add a keyed ordering layer above this shared work queue.
