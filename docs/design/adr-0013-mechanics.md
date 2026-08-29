# ADR-0013 mechanics — Priority-aware PubSub receive-pump shedding

> Extracted 2026-08-29 from the immutable [ADR 0013](../adr/0013-priority-aware-pubsub-shed.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the soak narrative and validation inventory relocated verbatim
> so this file is their maintained home — future updates
> belong here, not in the ADR.

## Soak narrative (Context excerpt; heading editorial)

A 6-hour VPS soak of x0x 0.19.47 under degraded cross-region (APAC) links hit
`recv_pump.pubsub.dropped_full = 27,560`. The root cause was upstream: the
saorsa-gossip dispatcher worker awaited the full EAGER fan-out (one slow peer
pinned it ~2.5 s per message), so the dispatcher drained the channel far slower
than producers filled it. That is fixed in saorsa-gossip by detaching the
fan-out accounting from the dispatcher worker (see
`saorsa-gossip/docs/design/pubsub-fanout-backpressure.md`).

---

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
