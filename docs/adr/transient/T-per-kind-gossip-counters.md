# T-per-kind-gossip-counters: rolling per-kind gossip efficiency meters

- **Status:** Proposed
- **Target slot:** A07
- **Date:** 2026-10-17
- **Decision owners:** David Irvine
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #1170; Track E M1; T-goal-e-rule-5; ADR 0095; ADR 0096
  (R12); docs/diagnostics.md; saorsa-gossip PR #122 (`verify_by_kind_stats`)

## Context

Track E needs per-message-kind attribution for verify CPU, recv-pump bus
pressure, local delivery and outbound publish. Without that split, the E0-b
soak and later efficiency rules cannot name which PlumTree kind drives cost.
Process-wide verify totals already exist (`inner_envelope_verify`,
`pubsub_stages.verify`), and `inbound_by_topic` counts frames by kind, but
they do not expose verify ok/err time, bus dispatch/drop, delivered or
published per kind, and they have no rolling window for rate math.

Adding fields under `GET /diagnostics/gossip` changes the public diagnostics
API surface. That API change serves vision requirement **R12** (x0x is
maintained by its own agents — ADR 0096): agents and soak harnesses need
honest per-kind efficiency meters to keep nodes healthy under owner policy.
Wire format and storage stay the same. The saorsa-gossip dependency gains a
native meter API (PR #122); the crates.io pin bump remains pending David's go.

## Decision Drivers

- Attribute verify and bus pressure to a PlumTree `MessageKind` under
  concurrent receive workers without cross-kind bleed.
- Keep the recv hot path free of full `stage_stats()` snapshots (those take
  topic/peer locks and sort peer-score maps — unsuitable at hundreds of
  frames per second).
- Let consumers compute rates via `since_ts` without a read discarding the
  completed window.
- Flag kinds that exceed a configured share of CPU or bus events (M1 health).

## Considered Options

1. **Native meters in saorsa-gossip** next to `verify_message_signature`,
   exposed as `verify_by_kind_stats()`, then merged into x0x `per_kind`.
   Accurate under concurrency; cheap atomic loads; needs a dependency bump.
2. **x0x-layer meters** that sample the existing verify stage around
   `handle_incoming`, count recv-pump enqueue/shed by peeked kind, and count
   local deliver/publish as Eager. Additive diagnostics only, but
   `stage_stats()` twice per frame is expensive and before/after deltas
   mis-attribute under concurrent workers.
3. **Defer** until a later Track E slice. Blocks E0-b attribution.

## Decision

Choose option 1. Ship `per_kind` on `GET /diagnostics/gossip` with a 60 s
rolling window computed as deltas of cumulative counters (native verify plus
x0x bus/delivered/published). When the window elapses, keep the previous
completed interval so a slow poller still sees the measurement. Default share
thresholds stay 0.40 for verify CPU (`total_ns`) and for bus events
(`bus_dispatched + bus_dropped`). Reject option 2: a goal-E measurement PR
must not add goal-E cost on the recv path, and concurrent stage-delta
sampling makes the health verdict unreliable under load.

## Consequences

- Operators and soak harnesses can rate per-kind verify and bus pressure.
- The M1 health verdict can name a hot kind without co-tenant `%CPU`.
- x0x must not call `stage_stats()` or re-count verifies per inbound frame;
  diagnostics read `verify_by_kind_stats()` (cumulative, never reset by a
  read).
- PR CI cannot compile until saorsa-gossip releases the meter and x0x's
  Cargo pin is bumped (pending David's go).
