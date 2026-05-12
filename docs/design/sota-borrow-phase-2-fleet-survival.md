# SOTA-Borrow Phase 2 — Production Fleet Survival Plan

**Status:** Ready for handoff to agent team
**Date:** 2026-05-12 (v2 reframe per reviewer)
**Author:** Coordinator session (post X0X-0066 rollback) + reviewer
**Related:** [X0X-0065](../../issues/issues.jsonl), [X0X-0066](../../issues/issues.jsonl), [X0X-0067](../../issues/issues.jsonl)
**Soak evidence:** `proofs/launch-readiness-soak-20260512T093455Z-4h-v0_19_41-rollback-98pct-certification/`

## v2 reframe — the centrepiece is admission control, not cache size

The v1 of this plan made cache bounding (X0X-0068) the lead lever.
Reviewer feedback recasts the diagnosis: **rising `suppressed_peers`
ratio in the 4h soak is the overlay going defensive**, not just a
cache that's too big. The Hunt 12f follow-up
(`docs/design/hunt-12f-stale-release-fast-drop.md` §147) explicitly
forecasts this fix: *"a real PubSub admission control path for known
low-priority topics (x0x/release, discovery anti-entropy, identity
anti-entropy), preferably before subscriber-channel enqueue."*

Substrate-level admission control + topic priority is now the
**portfolio centrepiece** (X0X-0074). The other six layers are
supporting infrastructure — necessary but each insufficient alone.

The reviewer also flagged two prerequisites:

- **X0X-0075 (per-topic + transport diagnostics)** — we currently
  count suppression but don't know *which topics* are causing it.
  Without that breakdown, we can't tune priorities or validate
  X0X-0074. Blocks X0X-0074.
- **X0X-0076 (split-soak methodology)** — current `launch_soak.py`
  conflates DM/transport failure with overlay failure. Split into
  fixed-roster-DM-only vs PubSub-pressure-only soaks so we can
  isolate the variable. The X0X-0066 hedging mistake came from
  conflating these two failure modes.

The four SOTA reference threads that informed this reframe (all from
reviewer):

1. **Quinn TransportConfig + PathStats** — per-peer RTT, loss/PTO,
   cwnd/in-flight, stream-open blocking, path generation. We don't
   surface this.
2. **iroh architecture lesson** — *separation* of direct connectivity
   health from fallback/control infrastructure. Don't copy DERP, copy
   the separation principle.
3. **libp2p gossipsub v1.1** — peer scoring + pruning + graylisting
   + heartbeat as first-class health mechanisms. Rising suppression
   means the overlay is in a defensive state — not noise.
4. **Google SRE Handling Overload** — reject/drop low-priority work
   early, keep queues bounded, avoid retry/hedge amplification, make
   saturation explicit.
5. **Cloudflare quiche** — metric-heavy production practice (qlog,
   path, congestion evidence) rather than app-level pass/fail counters.

## v2 ticket portfolio (centrepiece + supporting layers)

```
                    ┌────────────────────────────────────────┐
                    │     X0X-0074  Admission Control        │  ← centrepiece (P0)
                    │     (Hunt 12f forecast realised)        │
                    └────────────────────────────────────────┘
                       ▲                            ▲
                       │ blocked by                 │ pairs with
       ┌───────────────┴─────────┐          ┌───────┴───────────────┐
       │  X0X-0075  Diagnostics  │          │  X0X-0068  Bounded    │
       │  (per-topic suppression │          │  Cache (bandwidth     │
       │   + qlog/PathStats)     │          │  reduction lever)     │
       │                P0       │          │                P1     │
       └─────────────────────────┘          └───────────────────────┘
                       ▲
                       │ pairs with
       ┌───────────────┴─────────┐
       │  X0X-0076  Split-Soak   │
       │  Methodology (variants  │
       │  A/B/C — isolation)     │
       │                P1       │
       └─────────────────────────┘

   Supporting infrastructure layers (after centrepiece + diagnostics land):

       X0X-0073  Adaptive cooling (calibrate per-peer p95 timeouts)
       X0X-0069  SWIM suspicion (avoid false-positive cooling)
       X0X-0071  P1-P7 peer scoring (continuous score with decay)
       X0X-0070  Application peer relay (cross-region fallback)
       X0X-0072  QUIC connection pool (state-refresh / idle eviction)
```

**Recommended cadence:**

1. Ship X0X-0075 diagnostics first (no acceptance soak required —
   just instrumentation). Unblocks everything else.
2. Ship X0X-0076 split-soak methodology in parallel. Run Variant A
   and Variant B once X0X-0075 is in. These produce the prerequisite
   evidence for X0X-0074 design decisions.
3. Ship X0X-0068 cache bounding in parallel (smaller diff, bandwidth
   reduction is independently valuable, reuses X0X-0075 telemetry
   infrastructure).
4. Ship X0X-0074 admission control as the centrepiece. **This is the
   ticket that should pass the plateau 4h soak.**
5. Then ship the supporting layers (X0X-0073, 0069, 0071, 0070, 0072)
   in priority order, each with its own 4h soak gate.

The remaining sections of this document describe the supporting
layers in the form they had under v1 of the plan. Read them with the
v2 reframe in mind: each layer is now scoped to "one supporting fix
for the admission-controlled substrate", not "the primary fix".

## Why this plan exists

The 2026-05-12 09:34Z 4h certification soak on the rolled-back release stack
(x0x 0.19.41 + ant-quic 0.27.21, no hedging, calibrated 0.98 SLO) shows a
clear "load grows with state" failure pattern:

| Window | recv/sent | max_pp_to | continuous_max_pp_to | drop_full | suppressed_ratio | verdict |
|---|---|---|---|---|---|---|
| 1  | **30/30** | 2   | 0    | 0    | 0.060 | **GO** ✓ |
| 2  | 30/30 | 0   | 7    | 0    | 0.052 | NO-GO (1 disp) |
| 3  | 30/29 | 6   | 18   | 0    | 0.020 | NO-GO |
| 4  | 27/28 | 12  | 61   | 0    | 0.057 | NO-GO |
| 5  | 28/28 | 172 | 489  | 0    | 0.094 | NO-GO |
| 6  | 27/27 | 166 | 1835 | 0    | 0.094 | NO-GO |
| 7  | 28/28 | 162 | 1848 | 0    | **0.129** | NO-GO (sup>0.12) |
| 8  | 28/28 | 171 | 1914 | 0    | 0.082 | NO-GO |
| 9  | 28/28 | 174 | 1878 | 0    | 0.112 | NO-GO |
| 10 | 20/20 | 115 | 1325 | 0    | 0.107 | NO-GO (runner drop) |
| 11 | 30/29 | 16  | —    | **448** | 0.071 | NO-GO (drop_full>0) |

Window 1 is **clean** — the rolled-back release stack genuinely passes the
98% SLO on a freshly drained mesh. By window 11, `recv_pump.dropped_full`
ticks over zero for the first time — backpressure has propagated all the
way to the receive pipeline. The mesh is in a **degraded steady-state**,
not a transient hiccup.

The root mechanism is a feedback loop:

```
discovery cache grows → anti-entropy load grows
  → cross-Pacific path can't keep up
    → saorsa-gossip cools the peer (120 s)
      → cooling persists across topics
        → fan-out skips cooled peer
          → backpressure builds elsewhere
            → recv_pump drops + runner DM dispatch fails
```

Our current architecture has **no defence layer** against any link in this
chain. The big production p2p systems (libp2p, iroh, Tailscale) all have
multiple layers — bounded caches, suspicion before failure, peer relay,
graceful scoring with decay, connection pool eviction. **We have none of
these.** This plan ships them.

## Architecture: the six defence layers

```
                                                                     │
   Layer 1: Bounded discovery cache (age + bytes + count) ───────────┤  X0X-0068
                                                                     │
   Layer 2: Adaptive cooling (per-peer p95 timeout, decaying cooldown) ─ X0X-0073
                                                                     │
   Layer 3: SWIM Suspicion (k-indirect probes before failure mark) ───── X0X-0069
                                                                     │
   Layer 4: P1-P7 peer scoring with decay (libp2p gossipsub v1.1) ──── X0X-0071
                                                                     │
   Layer 5: Application-level peer relay (Tailscale Peer Relays / iroh DERP) ─ X0X-0070
                                                                     │
   Layer 6: QUIC connection pool with idle eviction (iroh pattern) ────── X0X-0072
                                                                     │
```

Each layer addresses one link in the feedback chain. Implementing them
sequentially **closes the chain one bottleneck at a time**, with soak
evidence after each ticket lands proving the next bottleneck is now the
binding constraint.

## Sequencing & parallelism

**Track A — Gossip foundation (sequential, saorsa-gossip):**
```
X0X-0068 (bounded cache) ─▶ X0X-0073 (adaptive cooling) ─▶ X0X-0069 (suspicion) ─▶ X0X-0071 (P1-P7 scoring)
```

**Track B — Transport & relay (parallel with Track A, x0x):**
```
X0X-0070 (peer relay)     X0X-0072 (connection pool)
```

Track A is sequential because each ticket builds on the abstractions of
the prior one (the scoring system needs the suspicion state machine; the
suspicion machine needs the adaptive cooling primitives; etc.).

Track B is independent — peer relay and connection pool live in x0x's
transport/DM layer and don't touch saorsa-gossip internals.

**Recommended cadence:** ship X0X-0068 first (highest leverage, smallest
diff), validate with 4h soak, then unblock both Track A and Track B in
parallel. Each subsequent ticket gets its own 4h soak before merge.

## Soak evidence requirements (per ticket)

Every ticket must produce **four artefacts** before close:

1. **Unit tests** for the new mechanism — covers logic in isolation.
2. **Integration test** exercising the mechanism end-to-end on loopback
   where possible (some mechanisms require WAN to test fully — document
   the gap explicitly).
3. **1h confirmatory soak** on the post-merge stack — must hit ≥ 98%
   aggregate Phase A sent + received with no `drop_full`.
4. **4h certification soak** on the post-merge stack — must hit ≥ 98%
   aggregate Phase A sent + received with no `drop_full` *and* no growing
   `max_pp_to` trend across windows (specifically: window 16 `max_pp_to`
   should be within 2× window 1's value).

Soak proofs go in `proofs/launch-readiness-soak-<run-id>-...` and the
verdict reference is committed to the ticket addendum.

## What "done" looks like (portfolio acceptance)

After all 6 tickets land:

- **4h cert soak passes ≥ 98%** consistently across multiple runs on
  different days (proves not a one-time fluke).
- **8h soak** as the new long-soak baseline (we've never had one of these
  pass; once 4h is reliable, run the bar higher).
- **`max_pp_to` plateaus** rather than climbs (proves the feedback loop
  is broken).
- **`drop_full` stays 0** across the full soak (proves receive-pipeline
  backpressure no longer cascades).
- **Cross-region pair success rate ≥ 99%** measured separately from the
  intra-region pairs (proves peer relay + suspicion are doing their job).
- **Cooling events are transient** (max duration any single peer spends
  cooled < 30s, vs current 2-minute floor).

Once the portfolio is in, the X0X-0065 SLO can be tightened from 0.98
back toward 0.99 with confidence.

---

## Ticket portfolio

### X0X-0068 — Bounded discovery cache by age + bytes (Layer 1)

**Priority:** 1 — Critical, ships first
**Repos:** `saorsa-gossip` (pubsub crate), `x0x` (diagnostics)
**Estimated effort:** 1-2 days
**SOTA reference:** [High-Scalability gossip protocol guide](https://highscalability.com/gossip-protocol-explained/) — *"as clusters grow, the full state table gets bigger, and sending the entire table every second becomes expensive"*

#### Why

`saorsa-gossip-pubsub` already bounds the per-topic message cache by
**count** (`MAX_CACHE_SIZE = 2_048`), but **not by bytes or age**. With
the observed message sizes on `x0x.discovery.groups` (11-16 KB per
group card), the worst-case per-topic cache is `2048 × 16 KB ≈ 32 MB`.
Multiplied across active topics (discovery, presence, control), the
mesh is anti-entropy-ing ~100 MB+ of state on every reconciliation
cycle. Cross-Pacific paths can't sustain that bandwidth.

The soak shows the signature exactly: window 1 clean (cache empty),
windows 5+ degraded (cache full).

#### Mechanism

Three additional bounds on the LRU message cache:

1. **Age-based eviction**: `MAX_CACHE_AGE_SECS = 600` (10 minutes).
   Messages older than this are evicted on every cache touch, regardless
   of LRU position.
2. **Bytes-based eviction**: `MAX_CACHE_BYTES_PER_TOPIC = 16_000_000`
   (16 MB). Per-topic total bytes capped; LRU eviction when exceeded.
3. **Count-based eviction**: existing `MAX_CACHE_SIZE = 2_048` retained
   as a hard upper bound.

Eviction priority order: **age → bytes → count**. Insertion path:

```
insert(msg):
    prune_expired_by_age()          // O(expired count)
    while total_bytes + msg.bytes > MAX_BYTES:
        evict_lru()                 // O(1) per eviction
    while count + 1 > MAX_COUNT:
        evict_lru()
    cache.insert(msg)
```

#### Files to modify

- `saorsa-gossip/crates/pubsub/src/lib.rs`
  - Add `MAX_CACHE_AGE_SECS`, `MAX_CACHE_BYTES_PER_TOPIC` consts
  - Replace `LruCache<MessageIdType, CachedMessage>` with a custom
    `BoundedMessageCache` struct that enforces all three bounds
  - Track per-topic bytes + oldest entry age for diagnostics
- `saorsa-gossip/crates/pubsub/src/diagnostics.rs` (new or extend)
  - Per-topic stats: `msg_count`, `total_bytes`, `oldest_age_secs`,
    `evicted_by_age`, `evicted_by_bytes`, `evicted_by_count`
- `x0x/src/bin/x0xd.rs` (`/diagnostics/gossip` handler)
  - Surface per-topic cache stats in the existing diagnostics JSON

#### Tests

- **Unit tests** (saorsa-gossip-pubsub):
  - `bounded_cache_evicts_by_age`
  - `bounded_cache_evicts_by_bytes`
  - `bounded_cache_evicts_by_count`
  - `bounded_cache_age_takes_precedence_over_bytes`
  - `bounded_cache_eviction_counters_track_correctly`
- **Integration test** (saorsa-gossip-pubsub):
  - Insert 5000 messages × 5 KB over a 1500 s simulated period; assert
    cache size never exceeds caps and counters reflect eviction
- **Diagnostic test** (x0x):
  - `/diagnostics/gossip` returns the new per-topic fields

#### Soak acceptance

- 1h soak post-merge: aggregate Phase A sent + received ≥ 98%,
  `drop_full = 0`, `max_pp_to` plateaus.
- 4h soak post-merge: aggregate Phase A sent + received ≥ 98%,
  `drop_full = 0`, window 16 `max_pp_to` ≤ 2× window 1 `max_pp_to`,
  per-topic `evicted_by_age` and `evicted_by_bytes` non-zero (proves
  caps are engaging).

#### Dependencies

None. Ships first.

#### Detailed plan

See `docs/design/x0x-0068-bounded-discovery-cache.md` — standalone,
ready for execution in a fresh session.

---

### X0X-0073 — Adaptive cooling calibration (Layer 2)

**Priority:** 2 — High
**Repos:** `saorsa-gossip` (pubsub crate)
**Estimated effort:** 1-2 days
**Blocked by:** X0X-0068 (needs the bounded-cache foundation to isolate
the cooling mechanism's contribution)
**SOTA reference:** [libp2p gossipsub v1.1 spec — backoff durations](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md) — *"recommended duration for the backoff period is 1 minute"* with **0.97/sec decay**

#### Why

Current cooling is fixed and aggressive: `PER_PEER_REPUBLISH_TIMEOUT =
2500 ms` triggers cooling, and `cooldown_ms = 120_000` (2 minutes) is
the recovery period. Both numbers were calibrated for intra-region
paths and the X0X-0061 helsinki helper-load fix.

Cross-Pacific paths (helsinki↔singapore ~280 ms one-way, ~560 ms RTT
plus app-layer overhead) exceed 2500 ms under fanout_burst with high
probability. They get cooled, the 2-min cooldown is too long for
transient WAN slowness, and the soak degrades.

#### Mechanism

Per-peer **observed RTT p95** tracked via EWMA over the last N samples
(N=32). Per-peer timeout becomes:

```
timeout(peer) = max(2.5 × observed_p95(peer), 1500 ms)
```

Cooldown is **adaptive with exponential decay**:

```
on first cool:        cooldown = 30s
on consecutive cool:  cooldown = min(prev × 2, 300s)
on successful send:   cooldown = max(prev × 0.97, 30s) per second
```

This mirrors libp2p's 0.97/sec decay factor. A peer that cools once
recovers in 30s. A peer that consistently fails escalates up to 5 min
but recovers fast once it starts succeeding.

#### Files to modify

- `saorsa-gossip/crates/pubsub/src/timing.rs` (new)
  - `PerPeerRttTracker` (EWMA over observed RTTs)
  - `AdaptiveCooldown` (decay + escalation logic)
- `saorsa-gossip/crates/pubsub/src/lib.rs`
  - Replace `PER_PEER_REPUBLISH_TIMEOUT` constant with
    `tracker.timeout_for(peer)` lookup
  - Replace fixed `cooldown_ms` with `AdaptiveCooldown::on_cool(peer)`
  - Hook successful sends back into `AdaptiveCooldown::on_success(peer)`
    for decay
- Diagnostics: expose current per-peer timeout + cooldown via
  `/diagnostics/gossip`

#### Tests

- **Unit tests**:
  - `rtt_tracker_ewma_converges`
  - `adaptive_cooldown_escalates_on_consecutive_cool`
  - `adaptive_cooldown_decays_on_success`
  - `timeout_floor_at_1500ms`
- **Integration test**:
  - Simulate peer with 4000 ms RTT, observe timeout adapts to 10s
    after 32 samples
  - Simulate peer that cools then recovers, observe cooldown decay

#### Soak acceptance

- 4h soak: cumulative cooling events drop ≥ 5× vs pre-change baseline.
- 4h soak: no single peer is continuously cooled for > 30s.
- 4h soak: aggregate Phase A sent + received ≥ 98%.

#### Dependencies

- **Blocked by:** X0X-0068 (need stable baseline before tuning cooling)
- **Blocks:** X0X-0069 (suspicion mechanism uses the adaptive cooldown
  primitives)

---

### X0X-0069 — SWIM Suspicion before cooling (Layer 3)

**Priority:** 2 — High
**Repos:** `saorsa-gossip` (pubsub + coordinator crates)
**Estimated effort:** 3-4 days
**Blocked by:** X0X-0073
**SOTA reference:** [SWIM paper](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf), [Lifeguard extensions](https://arxiv.org/pdf/1707.00788) — *"sustained packet-loss handling: SWIM+Inf.+Susp. attains 12 stable members vs basic SWIM's 2"*

#### Why

Current cooling is **binary** — first timeout → cool. No retry, no
indirect probe, no transient-vs-failed distinction. A peer that's
momentarily slow under load gets the same treatment as a peer that's
genuinely dead.

SWIM Suspicion (from the original 2002 paper, refined in Lifeguard
2018) separates these: a non-responsive peer is marked *suspect* first,
the local node asks k other peers to indirectly probe it, and only if
all probes fail is the peer marked *failed* (then cooled).

#### Mechanism

Per-peer state machine:

```
        ┌─── timeout ───▶┐
   Alive                Suspect ─── k probes fail ───▶ Failed
        ◀── probe Ok ────┘                                │
        ◀────────── cooldown expires ────────────────────┘
```

When `timeout(peer)` fires:
1. Transition `Alive → Suspect { since: now, k: 3 }`
2. Fire `k` indirect-probe RPCs to randomly chosen other peers,
   asking each to ping the suspect on our behalf and report back
3. Wait up to `SUSPICION_TIMEOUT_MS = 1500` for any probe to confirm
   reachability
4. If any probe reports Ok: `Suspect → Alive` (no cooldown, just clear)
5. If all probes fail or timeout: `Suspect → Failed` (apply adaptive
   cooldown from X0X-0073)

Indirect probes use a lightweight `PingPeer { target, request_id }`
RPC on a dedicated topic (or piggyback on existing gossip if available).

#### Files to modify

- `saorsa-gossip/crates/pubsub/src/peer_state.rs` (new)
  - `PeerState` enum, transition logic, probe coordination
- `saorsa-gossip/crates/coordinator/src/probe.rs` (new)
  - Indirect-probe RPC protocol
- `saorsa-gossip/crates/pubsub/src/lib.rs`
  - Replace direct timeout-to-cool transition with state machine entry
- Diagnostics: per-peer state + probe outcomes via `/diagnostics/gossip`

#### Tests

- **Unit tests**:
  - State machine transitions
  - Probe coordination (k-out-of-k, k-out-of-n+1, etc.)
- **Integration tests** (multi-node, in-process):
  - Simulated transient peer slowness → suspect → cleared
  - Simulated dead peer → suspect → all probes fail → failed
- **Property-based test**: random sequences of timeouts + probes
  converge to a consistent state machine

#### Soak acceptance

- 4h soak: median time-spent-in-suspect ≤ 3s (probes resolve quickly)
- 4h soak: false-positive cool rate < 5% (most suspects clear)
- 4h soak: aggregate Phase A sent + received ≥ 98%

#### Dependencies

- **Blocked by:** X0X-0073
- **Blocks:** X0X-0071 (peer scoring uses the state machine outcomes)

---

### X0X-0070 — Application-level peer relay (Layer 5)

**Priority:** 2 — High
**Repos:** `x0x` (dm + agent + network)
**Estimated effort:** 3-5 days
**SOTA reference:** [Tailscale Peer Relays beta](https://tailscale.com/blog/peer-relays-beta), [iroh DERP](https://www.iroh.computer/blog/what-is-derp) — *"more than nine out of 10 connections between Tailscale nodes end up being direct P2P links"*, the other ~10% need relay

#### Why

Tailscale and iroh both report ~10% of cross-region pairs need relay
to succeed. Our 4h soak shows ~7-17% of cross-region pairs failing
with `command_dispatch_fail` (anchor can't reach the runner DM). We
have **no relay fallback** — those failures stay failed.

#### Mechanism

When direct-path DM to peer P consistently fails (`N` consecutive
failures within `M` seconds, e.g. N=2, M=30):

1. Mark P as `needs_relay` in the DM peer-state table
2. Select relay candidate R such that:
   - `is_connected(R)` and `is_alive(R)` (from suspicion state)
   - `direct_path_health(R → P)` (from P's view of R, learned via
     gossip)
   - R is geographically distinct (avoid same-region relay)
3. Wrap outgoing DM in `RelayHeader { dst: P, payload: dm_envelope }`
4. Send via `direct_path(self → R)` 
5. R's receive handler sees the relay header, decodes, re-sends to P
   via R's `direct_path(R → P)` (no further relay nesting)
6. Relay is stateless per-message (no relay channel held open)
7. Relay role can be refused if R is itself under load (advertised via
   gossip): `relay_capacity = max(0, 1.0 - load_pressure)`

Security: relay envelopes are signed by the original sender and
encrypted end-to-end (existing X0X-0060 ACK-v2 / MLS encryption stays
intact). R only sees the routing header, not the payload.

#### Files to modify

- `x0x/src/dm.rs`
  - Add `RelayHeader { dst, src, request_id, expires_at }`
  - Add `RelayedDm` variant in `DmEnvelope`
- `x0x/src/agent.rs`
  - `send_via_relay(dst, payload, relay)` method
  - Relay selection in `connect_to_agent` fallback path
  - Peer-state tracking for `needs_relay` flag
- `x0x/src/network.rs`
  - Relay forwarding handler in direct-listener
  - Per-peer relay-capacity advertisement via gossip
- Diagnostics: relay counters (`relay_sent`, `relay_received`,
  `relay_refused_load`)

#### Tests

- **Unit tests**:
  - Relay envelope encoding/decoding
  - Relay selection picks healthy candidate
  - Relay loop prevention (relay refuses to relay an already-relayed
    envelope)
- **Integration test** (3-agent loopback):
  - Block direct path A↔C (simulate via mock NetworkNode)
  - Verify A→B→C relay path succeeds
- **Integration test** (3-agent loopback):
  - Verify single delivery on subscribe_direct (not double via direct
    + relay race)

#### Soak acceptance

- 4h soak: cross-region pair success rate ≥ 99% (vs current ~83-93%)
- 4h soak: `relay_sent` counter > 0 on at least one node (proves
  fallback engaged)
- 4h soak: no relay-induced double-delivery (assert via Phase A pair
  counts matching expectations)

#### Dependencies

None (can ship in parallel with Track A)

---

### X0X-0071 — Libp2p P1-P7 peer scoring with decay (Layer 4)

**Priority:** 3 — Medium
**Repos:** `saorsa-gossip` (pubsub crate)
**Estimated effort:** 5-7 days (large rewrite)
**Blocked by:** X0X-0069
**SOTA reference:** [libp2p gossipsub v1.1 spec — peer scoring](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md) — *"behavioral penalty for premature regraft, calculated as the square of the counter"*, **0.97/sec decay**

#### Why

Even with adaptive cooling (X0X-0073) and suspicion (X0X-0069), the
peer-state model is still **categorical** (Alive/Suspect/Failed). A
peer that's marginally bad on one metric can be perfectly fine on
others — categorical state can't capture that.

libp2p's seven-parameter weighted scoring is the production-grade
solution. Each peer has a numeric score that combines time-in-mesh,
delivery rate, invalid-message rate, behavioral penalties, etc., with
each parameter decaying at 0.97/sec so penalties fade if behaviour
improves.

#### Mechanism

Implement (subset of) libp2p P-scoring:

| Parameter | Weight | Decay | What it measures |
|---|---|---|---|
| P1 (time in mesh) | small positive | none | rewards persistent peers |
| P2 (first deliveries) | positive | 0.97/sec | rewards peers who forward fresh msgs |
| P3b (delivery deficit) | negative, **sticky on prune** | 0.97/sec | penalises persistent under-delivery |
| P4 (invalid messages) | heavy negative, **squared** | 0.97/sec | penalises malformed/forged msgs |
| P7 (behavioral penalty) | negative, **squared** | 0.97/sec | counter-based misbehaviour penalty |

(P5 app-specific and P6 IP-colocation deferred — not needed for v1.)

Thresholds:
- `GOSSIP_THRESHOLD = -100` — below: stop sending gossip to peer
- `PUBLISH_THRESHOLD = -1000` — below: stop publishing self-msg to peer
- `GRAYLIST_THRESHOLD = -10000` — below: reject all RPCs from peer

#### Files to modify

- `saorsa-gossip/crates/pubsub/src/peer_score.rs` (new)
  - `PeerScore` struct with P1-P7 fields + decay
  - `ScoreConfig` (weights + thresholds, tunable)
- `saorsa-gossip/crates/pubsub/src/lib.rs`
  - Replace categorical peer state with continuous score
  - Score check before fan-out / publish / RPC accept
- Diagnostics: per-peer score breakdown via `/diagnostics/gossip`

#### Tests

- **Unit tests**: P-parameter math, decay over time, threshold transitions
- **Integration test**: 10-peer simulation with diverse behaviour profiles
  (good, marginal, bad, recovering); assert score evolution matches
  expectations
- **Property test**: random behaviour sequences converge to stable scores

#### Soak acceptance

- 4h soak: score telemetry shows graceful decay (no permanent zero
  scores)
- 4h soak: no single peer crosses GRAYLIST_THRESHOLD during normal
  operation
- 4h soak: aggregate Phase A sent + received ≥ 98%

#### Dependencies

- **Blocked by:** X0X-0069

---

### X0X-0072 — QUIC connection pool with idle eviction (Layer 6)

**Priority:** 2 — High
**Repos:** `x0x` (network) — possibly `ant-quic` if we want this as
infra
**Estimated effort:** 2-3 days
**SOTA reference:** [iroh connection pool — iroh-blobs 0.95](https://www.iroh.computer/blog/iroh-blobs-0-95-new-features) — *"max number of connections to be retained, maximum tolerable duration for connection establishment, max duration connections are kept when idle"*

#### Why

x0x holds every peer connection forever. Quinn streams + ant-quic
connections accumulate retransmit-state, congestion-window state,
RTT estimators, etc. over hours of continuous use. Periodic refresh
drains that state.

iroh's connection pool exposes `get_or_connect(peer)` that returns a
`ConnectionRef` (lifetime-tracked), evicts idle connections after
`max_idle_duration`, and caps concurrent connections at
`max_connections`. We need the same.

#### Mechanism

Add `ConnectionPool` wrapping `ant_quic::Node`:

```rust
struct ConnectionPool {
    inner: HashMap<PeerId, PooledConnection>,
    max_connections: usize,    // 32
    idle_evict_after: Duration, // 300s
    establish_timeout: Duration, // 10s
}

struct PooledConnection {
    conn: ant_quic::Connection,
    last_used: Instant,
    in_use_count: AtomicUsize,
}

impl ConnectionPool {
    async fn get_or_connect(&self, peer: PeerId) -> ConnectionRef { ... }
    async fn evict_idle(&self) { ... }  // called periodically
}
```

Background task evicts idle connections every 60s. Forced reconnect on
next `get_or_connect`.

#### Files to modify

- `x0x/src/network.rs`
  - `ConnectionPool` struct
  - Modify `send_direct`, `send_with_receive_ack*` to route through pool
  - Background eviction task started by `NetworkNode::new`
- Diagnostics: pool stats (`active_count`, `idle_evictions_total`,
  `establish_failures_total`) via `/diagnostics/connectivity`

#### Tests

- **Unit tests**:
  - `pool_evicts_after_idle_threshold`
  - `pool_reconnects_on_get_after_evict`
  - `pool_caps_active_connections_at_max`
  - `pool_lru_eviction_when_at_cap`
- **Integration test**:
  - 2-agent loopback, idle 350s, verify connection evicted
  - 2-agent loopback, send after evict, verify reconnect + delivery
- **Property test**: random get/idle/use sequences maintain invariants

#### Soak acceptance

- 4h soak: `idle_evictions_total > 0` on all nodes (proves eviction
  engaged)
- 4h soak: `establish_failures_total == 0` (proves reconnect is reliable)
- 4h soak: no DM loss attributable to pool eviction (Phase A pairs all
  succeed in the window following an eviction)
- 4h soak: aggregate Phase A sent + received ≥ 98%

#### Dependencies

None (can ship in parallel with Track A)

---

## Risk register

1. **Track A interlock risk** — X0X-0068 → X0X-0073 → X0X-0069 → X0X-0071
   sequential dependency means a P0 regression in any ticket blocks the
   rest. Mitigation: each ticket gets its own 4h soak gate; merge only
   after green.

2. **Soak environment noise (X0X-0067)** — the fleet has shown post-
   multi-deploy degradation that's not code. Mitigation: each soak run
   must include a ≥1h idle drain after the deploy.

3. **Cross-repo coordination** — saorsa-gossip changes require coordinated
   crate publishes. Mitigation: agent team uses path deps for development;
   publish + version bump only when soak passes.

4. **Hard rollback** — if any layer turns out to regress production worse
   than the rolled-back baseline (X0X-0066 was the precedent), revert to
   the pre-merge stack and re-soak to confirm. Don't iterate on a known-
   failing fleet.

5. **Suspicion mechanism amplification** — k-indirect-probes adds 3× RPC
   traffic during transient slowness windows. Mitigation: rate-limit
   probes per-suspect to 1/sec; suspend probes if local node is itself
   under cooling pressure.

## Agent team handoff checklist

Per ticket, the agent should produce:

- [ ] Implementation diff (single PR per ticket, focused scope)
- [ ] Unit tests (per the "Tests" section)
- [ ] Integration test(s) (per the "Tests" section)
- [ ] `cargo fmt --all -- --check` clean
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean
- [ ] `cargo nextest run --all-features --workspace` 100% pass
- [ ] 1h soak proof committed to `proofs/` (with summary.md showing GO)
- [ ] 4h soak proof committed to `proofs/` (with summary.md showing GO)
- [ ] Ticket addendum referencing both proofs + soak verdicts
- [ ] Cross-repo: publish ant-quic / saorsa-gossip crate if touched
- [ ] Version bump + CHANGELOG entry per repo touched

Per portfolio (after all 6 tickets merge):

- [ ] 8h soak under the new stack (the new long-soak baseline)
- [ ] SLO retightening proposal (0.98 → 0.99) with evidence
- [ ] Architecture review of the layered defence design (catch any
      missed interactions between layers)
- [ ] Update `docs/launch-gates/broad-launch.md` with the new
      mechanisms documented and their expected steady-state telemetry

## Related documents

- `docs/design/x0x-0068-bounded-discovery-cache.md` — focused
  implementation plan for ticket 1, ready for fresh-session execution
- `docs/launch-gates/broad-launch.md` — current broad-launch gate
  (will be updated once portfolio lands)
- `issues/issues.jsonl` — X0X-0065 (SLO calibration), X0X-0066 (failed
  hedging attempt — lessons), X0X-0067 (fleet noise after multi-deploy
  — workaround in this plan: idle drain)
