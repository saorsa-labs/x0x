# ADR 0033: The Receive Pump Never Blocks — All Classes Shed or Spill

- **Status:** Accepted (2026-08-23)
- **Date:** 2026-08-23
- **Decision owners:** Claude + omp (dual investigation), David Irvine (approval)
- **Reviewers:** David Irvine
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** [ADR 0009](./0009-recv-pump-overload-policy.md) §Decision 2 (Membership/Bulk
  "keep the previous await/send behavior")
- **Related:** x0x #378, x0x #380, ant-quic #255 (dual-investigation reports in `.scratch/`)

## Context

ADR 0009 made PubSub forwarding non-blocking but kept Membership and Bulk on
`send().await`, reasoning they "carry low-volume control/presence traffic". The
2026-08 #378/#380 investigation falsified that premise under churn: the single
global `spawn_receiver` task, blocked on one full class channel, stops draining
ant-quic's shared `data_tx`, which stalls **every per-connection reader**,
which lets unread streams pile in the assembler (3.5k streams / 40+ MB
measured), which withholds flow-control credit, which blocks remote senders,
which turns into gossip send-timeouts and peer cooling network-wide. One slow
consumer of any class was a whole-transport head-of-line block. Direct and
relayed DMs used the same blocking sends and are additionally lossless by
contract (ADR 0030 durable retries make drops recoverable but expensive).

## Decision Drivers

- The receive pump is upstream of every transport consumer; its liveness
  outranks any single class's delivery preference.
- SWIM membership and anti-entropy/bulk are retransmitting epidemic protocols:
  a dropped frame is recovered by the protocol; a stalled transport is not.
- DMs must not drop under ordinary pressure, but unbounded queueing converts a
  wedged consumer into an OOM.

## Considered Options

1. **Shed for epidemic classes, byte-capped spill for DM classes (chosen).**
2. Larger channel capacities — headroom only; ADR 0009 already rejected this.
3. Per-class receive pumps — requires demultiplexing before `node.recv()`,
   an ant-quic API change out of scope here.
4. Drop DMs on full like PubSub — violates the lossless intent; durable
   retries would mask real losses at cost.

## Decision

- `forward_gossip_payload` uses non-blocking `try_send` for **every** gossip
  class. Membership/Bulk record `recv_pump.*.dropped_full` and warn
  (rate-limited) instead of awaiting capacity. PubSub's shed-priority policy
  is unchanged.
- Direct (0x10) and relayed (0x11) DMs go through a `DmSpillForwarder`: an
  unbounded queue drained by a dedicated task that alone absorbs the bounded
  consumer channel's backpressure, byte-capped at 64 MiB per class; beyond the
  cap the incoming message is dropped with a loud rate-limited warning and a
  counter (`dropped_over_cap`), and ADR 0030 durable senders retry.
- `spawn_receiver` therefore contains no `.send().await` on any bounded
  channel.

## Consequences

- Positive: transport ingest liveness no longer depends on the slowest
  consumer; the #378 assembler pileup loses its x0x-side sustaining input.
- Negative: Membership/Bulk frames can drop under sustained overload —
  visible in `dropped_full`, recovered by SWIM/anti-entropy retransmission.
- Negative: a DM burst beyond 64 MiB queued drops newest with a counter;
  deliberate — the alternative is unbounded memory during a wedged-consumer
  incident (#384 class).
- The ADR 0009 test asserting Membership blocks ("must never increment
  dropped_full") is inverted by this ADR; its old expectation is the defect.

## Validation

- Unit: a full membership channel returns `DroppedFull` (no stall) and
  increments `dropped_full`; a full `direct_tx` leaves `spawn_receiver`
  unblocked while the spill task delivers after drain; over-cap DM enqueue
  drops with `dropped_over_cap` incremented.
- Live: with fixes A–C (ant-quic #255) deployed, `recv_streams_with_unread`
  stays bounded under gossip bursts and `data_tx` high-water stops correlating
  with DM/membership bursts.
