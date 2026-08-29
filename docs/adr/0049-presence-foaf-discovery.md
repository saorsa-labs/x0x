# ADR 0049: Presence Runs on Signed Beacons over a Global Topic with FOAF Candidate Scoring

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0017 ("DHT-free gossip/FOAF discovery"); ADR-0033 (Membership-class shedding); ADR-0023 (beacons are Ephemeral). Backfill record for shipped behavior.

## Context

`src/presence.rs` implements the presence plane with no deciding ADR. All
agents beacon on one global gossip topic `x0x.presence.global`
(`src/presence.rs:50-54`); beacons must be signed by the sender's machine
keypair — `PeerId::from_pubkey(signer) == sender` is enforced on receipt
(`src/presence.rs:452-465`). Defaults: 30 s beacon interval, FOAF TTL 2,
FOAF timeout 5 s, 10 s poll, 300 s fallback offline timeout
(`src/presence.rs:339-375`).

## Decision Drivers

- Online/offline must be discoverable without a registry or DHT.
- Offline detection must tolerate per-peer beacon jitter, not a fixed
  timeout.
- Presence is per-machine observable state; spoofed beacons must fail.

## Considered Options

1. Fixed-timeout liveness per direct peer.
2. Central presence server.
3. Signed beacons on a global topic + adaptive per-peer timeouts + FOAF candidate scoring (chosen).

## Decision

1. Every agent beacons to `x0x.presence.global` so FOAF random walks work
   across membership shards (`src/presence.rs:50-54`); beacon signatures are machine-key-verified (`src/presence.rs:452-465`).
2. Offline detection as shipped: per-peer inter-arrival samples are recorded in a 10-arrival sliding window (`PeerBeaconStats`,
   `src/presence.rs:243-275`) — but `record()` fires only on a peer's newly-online transition (`src/presence.rs:609-615`), so samples
   measure re-appearance intervals, not steady beacon cadence. A peer
   absent from the poll window is held while `absent_secs` is under its
   adaptive timeout — mean + 3 × stddev clamped to 180–600 s, 300 s fallback (`src/presence.rs:281-327,672-678`) — which suppresses
   spurious `AgentOffline` events on the departure cycle; the loop then
   replaces the tracked set (`previous = current`, `src/presence.rs:697`), so a deferred peer leaves silently (no
   delayed event, no stats eviction). `AgentOffline` with eviction fires
   only when the timeout is already exceeded at departure (`src/presence.rs:657-686`).
3. FOAF quality is `1/(1+stddev)` per peer (0.5 with no observations, `src/presence.rs:224-239`); `foaf_peer_candidates()` returns peers
   sorted by that score as random-walk next-hop preference (`src/presence.rs:538-555`). Query forwarding itself lives in the
   underlying membership layer; this module owns scoring and candidate
   ordering, and exposes TTL/timeout configuration (`src/presence.rs:339-346`).
4. Presence beacons are Ephemeral under ADR-0023's taxonomy — never persisted to history.

## Consequences

### Positive

- Shard-independent discovery; departure suppression is jitter-aware;
  spoofed beacons cannot impersonate a peer.

### Negative / Trade-offs

- One global topic costs every member a Membership-class stream; under
  receive-pump pressure those frames shed with counters per ADR-0033 —
  presence loss under overload is shedding, never backpressure (and the recv pump never blocks).

### Neutral / Operational

- The per-beacon adaptive detector (continuous inter-arrival sampling,
  guaranteed delayed-offline events) is the design intent, not shipped behavior; closing that gap is future work on this module.

## Validation

- Unit tests on window eviction, adaptive-timeout clamping, and signature
  rejection in `src/presence.rs`; `AgentOnline`/`AgentOffline` event emission covered by the event-loop tests.

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
