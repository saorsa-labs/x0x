# ADR 0013: Priority-Aware PubSub Receive-Pump Shedding

> Renumbered from 0010 → 0013 on 2026-05-30 to resolve a numbering collision with
> ADR-0010 (GSS Before MLS TreeKEM). Content unchanged; references to ADR 0009
> below are to that separate ADR, not self-references.

## Status

Accepted

## Context

ADR 0009 made the per-peer PubSub receive forward channel (`recv_pubsub_tx`)
lossy-but-observable: PubSub frames use non-blocking `try_send()` and are
dropped (incrementing `recv_pump.pubsub.dropped_full`) when the channel is full,
so a saturated PubSub queue cannot stall ant-quic receive draining. Membership
and Bulk keep blocking sends because they are low-volume control/presence
traffic.

A 6-hour VPS soak of x0x 0.19.47 under degraded cross-region (APAC) links hit
`recv_pump.pubsub.dropped_full = 27,560`. The root cause was upstream: the
saorsa-gossip dispatcher worker awaited the full EAGER fan-out (one slow peer
pinned it ~2.5 s per message), so the dispatcher drained the channel far slower
than producers filled it. That is fixed in saorsa-gossip by detaching the
fan-out accounting from the dispatcher worker (see
`saorsa-gossip/docs/design/pubsub-fanout-backpressure.md`).

When the channel *does* fill — transient bursts, or any future slow-drain
condition — ADR 0009's flat policy drops whatever PubSub frame arrives next,
with no regard for kind. PlumTree carries two classes of PubSub frame:

- **Data**: `Eager` (the payload-bearing push along the spanning tree).
- **Recoverable control**: `IHave` / `IWant` / `AntiEntropy`, which exist
  precisely to recover missed data via lazy pull. Dropping these is cheap —
  PlumTree re-advertises and re-requests.

Dropping an `Eager` frame loses a payload until lazy reconciliation catches up;
dropping an `IHave` loses nothing durable. ADR 0009 treats them identically.

## Decision

Refine ADR 0009's PubSub shedding to be **priority-aware**, as defense-in-depth
behind the upstream dispatcher fix:

1. saorsa-gossip exposes `peek_message_kind(frame: &[u8]) -> Option<MessageKind>`,
   which decodes only the `MessageHeader` prefix via `postcard::take_from_bytes`
   — no payload allocation, no signature verification.
2. In the x0x receive pump (`forward_gossip_payload`, PubSub branch), when the
   channel is **more than 90% full** (`channel_pressure_exceeds_shed_threshold`,
   i.e. `available < max/10`), peek
   the kind and proactively shed recoverable control frames
   (`IHave`/`IWant`/`AntiEntropy`) before they consume the last slots,
   preserving room for `Eager`. The peek is **gated on the threshold**, so the
   steady-state hot path keeps ADR 0009's flat `try_send` with zero decode cost.
3. `Eager` (data) and tree-maintenance frames are never shed by this path. When
   the channel is genuinely full, `Eager` hard-drops via the existing
   `try_send`/`dropped_full` path exactly as ADR 0009 specifies.
4. Proactive sheds are counted in a distinct metric,
   `recv_pump.<stream>.shed_priority`, kept separate from `dropped_full` so
   operators and the soak gate can tell intentional, recoverable shedding apart
   from hard data loss. The broad-launch gate keeps `dropped_full → 0`;
   `shed_priority > 0` is acceptable and is a pressure signal, not a failure.
5. Membership and Bulk are unchanged — ADR 0009 §2 still holds; they keep
   blocking sends and never increment `dropped_full` or `shed_priority`.

## Consequences

Positive:

- Under near-overload, payload (`Eager`) delivery is preserved by sacrificing
  only frames PlumTree can recover. Effective goodput degrades more gracefully.
- The new `shed_priority` counter distinguishes graceful shedding from hard
  loss, so the defense-in-depth mechanism can engage without tripping the
  `dropped_full → 0` launch gate.
- The kind-peek is paid only when the channel is already >90% full, so the
  steady-state receive path is unchanged (ADR 0009's lean hot path preserved).

Negative:

- Adds a small wire-format coupling: the recv pump now understands that PubSub
  frames begin with a `MessageHeader` (via the `peek_message_kind` helper).
  Contained to one helper in saorsa-gossip.
- Under sustained near-full pressure, recovery traffic (IHAVE/IWANT/anti-
  entropy) is shed first, which can slow lazy reconciliation of already-missed
  messages. This is the intended trade-off: keep new data flowing, defer
  recovery. If a soak shows reconciliation starvation, revisit the shed set.

## Relationship to ADR 0009

This ADR supersedes ADR 0009 only for the *PubSub overflow discipline*: ADR
0009's "flat try_send, drop-on-full" becomes "priority-aware shed above 90% full,
then flat try_send/drop-on-full at 100%." All other ADR 0009 decisions
(diagnostics, Membership/Bulk blocking sends, the >50% INFO / >80% WARN signals)
remain in force.

## Validation

- Unit: `saorsa-gossip-pubsub::peek_message_kind` decodes kind from the header
  prefix and returns `None` on malformed frames without panicking.
- Unit (x0x): under a near-full channel (>90%), an IHAVE frame is shed (slot preserved,
  `shed_priority += 1`) while an EAGER frame claims the slot
  (`enqueued`), and a subsequent EAGER hard-drops (`dropped_full += 1`) — never
  silently shed. ADR 0009 Membership/Bulk blocking tests still pass.
- Soak: the 6 h healthy-mesh no-regression run must keep `dropped_full = 0` and
  Phase-A delivery ≥ 30 pairs; `shed_priority` is monitored (expected ~0 on a
  healthy mesh). True degraded-network validation rides the next natural APAC
  degradation window with `dropped_full` + `shed_priority` alerting live.
