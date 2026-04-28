# Hunt 12d — identity-announcement gossip volume saturates the PubSub channel

## Status
- **Opened:** 2026-04-28
- **Source:** Discovered while preparing the Hunt 12c v0.19.5 4-hour live-fleet soak (`proofs/fleet-soak-4h-20260428T081446Z/`).
- **Severity:** Medium — degrades API responsiveness, doesn't break presence (Hunt 12c isolation holds).
- **Predecessor:** Hunt 12c (per-stream dispatcher isolation) — shipped in `x0x v0.19.5`. Hunt 12c is closed; the underlying load it isolates *against* is what 12d addresses.

## What we observed

When attempting a clean 4-hour soak of the live 6-node bootstrap fleet
(saorsa-2/3/6/7/8/9, all on `x0xd 0.19.5`), the very first
`/diagnostics/gossip` poll showed **every node's PubSub receive
channel pinned at maximum capacity** (`recv_depth.pubsub.max = 10000 /
10000`, i.e. 100 % of the channel's slots filled at some point):

| Node | `pubsub.timed_out` (cumulative) | `bulk.timed_out` | `recv_depth.pubsub.max` |
|------|---:|---:|---:|
| saorsa-2 | 3 600 | **0** | 10 000 (100 %) |
| saorsa-3 | 3 578 | **0** | 10 000 |
| saorsa-6 | 3 578 | **0** | 10 000 |
| saorsa-7 | 3 250 | **0** | 10 000 |
| saorsa-8 | 3 282 | **0** | 10 000 |
| saorsa-9 | 3 290 | **0** | 10 000 |

**The Hunt 12c isolation works correctly** — `bulk.timed_out` and
`membership.timed_out` are flat. The problem is purely in the PubSub
channel: it is sustainedly full. As a downstream symptom,
`tests/e2e_vps.sh` (the ~131-assertion API-surface test) takes
**32 minutes instead of the documented 4 minutes** and reports
**21 / 131 failures** — every failure a `curl_failed` against the
direct-message send endpoint, indicating the API is slow to respond
under the PubSub pressure.

## Diagnosis (the math is the diagnosis)

The "noisy peer" we identified during Hunt 12c (`6a24bdeddd828e1e`,
sending 16 056-byte PubSub messages every ~10 s to saorsa-2) was
saorsa-7 — **one of our own bootstrap nodes**, doing nothing wrong:

- Each node publishes its `IdentityAnnouncement` on
  `x0x.identity.announce.v2` once per `IDENTITY_HEARTBEAT_INTERVAL_SECS`.
  Source default in `src/lib.rs:467` is **60 seconds**, and
  production `/etc/x0x/config.toml` does not override it. Confirmed
  on saorsa-2 — `discovery: publishing identity announcement` fires
  exactly once per minute.
- The serialized announcement is **~10.8 KB** (ML-DSA-65 public key,
  signed AgentCertificate, full address list IPv4 + IPv6 + NAT info,
  capability flags). After the PubSub envelope + signature it is
  **~16 KB** on the wire.
- PlumTree's EAGER fanout pushes each new message to every peer in
  the EAGER set. On the bootstrap mesh this is 5–7 peers per node.
- 6 nodes × 1 announcement / 60 s × 7 EAGER peers = **42 sends per
  minute on the topic, mesh-wide**, which works out to ~1 inbound
  16 KB message per 10 seconds at every node.

That alone is sustainable (~96 KB / minute / node), but combined
with the PubSub handler's per-message work — postcard decode,
ML-DSA-65 signature verification, PlumTree state mutation, fanout to
local subscribers — each handler call takes well into the
hundreds-of-ms range. Under sustained 1-per-10s arrival, the
single PubSub dispatcher backs up; messages queue in `recv_pubsub_rx`
faster than they're drained; `recv_depth.pubsub.max` hits ceiling;
some handler invocations exceed the 10 s `PUBSUB_MESSAGE_HANDLE_TIMEOUT`
and are abandoned.

**Hunt 12c's per-stream channel split is what keeps the rest of the
node healthy under this pressure.** Without it (pre-v0.19.5), the
shared receive queue would be saturated and Bulk presence + Membership
SWIM would collapse — which is exactly what we saw in Hunt 12b. The
isolation is a load-bearing wall; this issue is about the load
itself.

## Goal

Reduce the steady-state PubSub volume on the bootstrap mesh by an
order of magnitude so that:

1. `recv_depth.pubsub.max` stays well below the 10 000 channel
   capacity at steady state on every node.
2. `pubsub.timed_out` stops growing during normal organic operation
   (it should only grow under pathological load, e.g. a real DoS).
3. `tests/e2e_vps.sh` runs in roughly its documented ~4 minutes (not
   30 +) and 0 / 131 failures on a healthy fleet.

## Three candidate levers

### Lever A — Larger heartbeat interval (60 s → 300 s)

**Effect:** 5 × reduction in announcement volume.
**Cost:** Slower convergence on identity changes. But identities
rarely change; a 5-minute lag on agent-card / NAT-status updates is
acceptable for the bootstrap mesh use case.
**Required:** New const in `src/lib.rs`. Optional per-config override
already exists (`heartbeat_interval_secs`).
**Risk:** Low. The `identity_ttl_secs` default is 900 s (15 min) so
heartbeat at 300 s still gives 3 × within-TTL refreshes — well above
the 1 × needed to keep an entry from expiring even on transient loss.

### Lever B — Smaller announcement payload

**Effect:** Approximately linear on PubSub channel pressure.
**Cost:** Engineering work to slim the `IdentityAnnouncement` struct.
Possibilities:

- **Drop the AgentCertificate from the periodic announcement.** Send
  only the bare identity (machine_id, agent_id, current addresses,
  signature) at 60 s; send the full certificate as a separate, less
  frequent (e.g. once per hour, on-demand on first contact) `Card`
  message. New peers would do an explicit `GET /agent/card?id=…` on
  first interaction.
- **Drop redundant address representations.** Currently we ship both
  IPv4 and IPv6, full NAT capability flags, relay candidates, etc.
  Some can be omitted when unchanged — diff against last sent.

**Required:** New compact `IdentityHeartbeat` type in `src/lib.rs`,
new pubsub topic `x0x.identity.heartbeat.v1`, fallback fetch path.
Wire-format change → coordinated rollout.
**Risk:** Medium. Bigger surface area, requires backward
compatibility for older nodes still publishing v2.

### Lever C — Less aggressive PlumTree fanout on bootstrap nodes

**Effect:** Linear on outbound, doesn't help inbound.
**Cost:** Risk of slower mesh convergence; harder to reason about.
Bootstrap nodes are *supposed* to be highly-connected — reducing
their fanout undermines that role.
**Required:** Configurable `eager_fanout_factor` in
`saorsa-gossip-pubsub`, scoped to bootstrap-mode nodes.
**Risk:** Higher. Touches the gossip overlay's invariants.

## Recommendation

**Land Lever A first** as a v0.19.6 / v0.20.0 ship — a single
constant change in `src/lib.rs` plus one CHANGELOG entry. Validate on
the live fleet for 2–4 hours; expect ~5 × drop in PubSub channel
pressure. Likely sufficient on its own.

If Lever A alone doesn't bring `recv_depth.pubsub.max` below 50 % of
capacity at steady state, plan Lever B as a v0.20.0 wire-format
breaking change, with a compatibility window.

Defer Lever C until both A and B are tried — the gossip overlay's
invariants should not be the first lever turned.

## Validation plan

- Unit: existing tests in `src/lib.rs` and `tests/identity_*.rs`
  cover the announcement codec; no new unit work needed for Lever A.
- Local: extend `tests/e2e_hunt12c_pubsub_load_isolation.sh` (the
  reproducer added in v0.19.5) with a "long heartbeat" mode that
  asserts `recv_depth.pubsub.max < 5000` after the same 120-second
  load window.
- Fleet: 2-hour soak after deploy. Pass criteria:
  - `recv_depth.pubsub.max < 5000` (50 % of cap) at steady state on
    every node.
  - `pubsub.timed_out` growth rate < 1 / minute per node.
  - `tests/e2e_vps.sh` returns 0 failures within 8 minutes.

## Linkage to Hunt 12b / 12c

- Hunt 12b (`x0x v0.19.4`) — fixed the user-visible symptom (presence
  collapse) by ensuring presence broadcast peers are refreshed from
  the live QUIC connection table, not the lagging HyParView active
  view.
- Hunt 12c (`x0x v0.19.5`) — fixed the architectural bottleneck (a
  slow PubSub handler back-pressuring the shared recv queue) by
  splitting the receive channel + dispatcher into per-stream lanes.
  Bulk presence and Membership SWIM are now isolated from PubSub
  stalls.
- Hunt 12d (this document) — addresses the *load* that Hunt 12c
  isolates against: the bootstrap mesh's identity-announcement
  gossip volume is high enough to sustainedly fill the PubSub
  channel. Without 12d, 12c keeps the system safe but degraded;
  with 12d, the system runs comfortably under load.

## Estimated effort

- Lever A (heartbeat interval bump): 30 min code + 30 min review +
  30 min CI + 2-h fleet soak = half a day.
- Lever B (compact heartbeat): 1–2 days code + design review + soak.
- Lever C (PlumTree fanout): 2–3 days, gossip-stack reasoning.
