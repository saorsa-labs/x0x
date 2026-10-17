# T-per-kind-gossip-counters: rolling per-kind gossip efficiency meters

- **Status:** Proposed
- **Target slot:** A07
- **Date:** 2026-10-17
- **Decision owners:** David Irvine
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #1170; Track E M1; T-goal-e-rule-5; ADR 0095; docs/diagnostics.md

## Context

Track E needs per-message-kind attribution for verify CPU, recv-pump bus
pressure, local delivery and outbound publish. Without that split, the E0-b
soak and later efficiency work cannot name which PlumTree kind drives cost.
Process-wide verify totals already exist (`inner_envelope_verify`,
`pubsub_stages.verify`), and `inbound_by_topic` counts frames by kind, but
they do not expose verify ok/err time, bus dispatch/drop, delivered or
published per kind, and they have no rolling window for rate math.

Adding fields under `GET /diagnostics/gossip` changes the public diagnostics
API surface. Wire format, storage and crate pins stay the same. The change
serves goal E (measurement). T-goal-e-rule-5 says an API change still needs a
transient record that names the requirement; this record does that under
goal E for Track E baselines.

## Decision Drivers

- Attribute verify and bus pressure to a PlumTree `MessageKind`.
- Let consumers compute rates after a rolling reset via `since_ts`.
- Flag kinds that exceed a configured share of CPU or bus events (M1 health).
- Stay inside the issue fence: no `Cargo.toml` / saorsa-gossip bump.

## Considered Options

1. **Native meters in saorsa-gossip** next to `verify_message_signature`, then
   expose them from x0x. Best accuracy; needs a dependency bump (fenced).
2. **x0x-layer meters** that sample the existing verify stage around
   `handle_incoming`, count recv-pump enqueue/shed by peeked kind, and count
   local deliver/publish as Eager. Additive diagnostics only.
3. **Defer** until the Cargo fence lifts. Blocks E0-b attribution.

## Decision

Choose option 2. Ship `per_kind` on `GET /diagnostics/gossip` with a 60 s
rolling window, `since_ts` in unix milliseconds, and default share thresholds
of 0.40 for verify CPU (`total_ns`) and for bus events
(`bus_dispatched + bus_dropped`). The health object lists kinds over those
shares. Document the soft-verify limitation on non-pubsub kinds until option 1
can land.

## Consequences

- Operators and soak harnesses can rate per-kind verify and bus pressure.
- The M1 health verdict can name a hot kind without co-tenant `%CPU`.
- A later saorsa-gossip native meter can replace the stage-delta path without
  changing the JSON field names.
