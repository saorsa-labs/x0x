# #504 slice 1: experimental Leaf selection and named egress meters

Implements the x0x portion of [design #534](design/504-leaf-egress-budget.md)
§6.1–6.2. Consumes published crates.io **saorsa-gossip 0.5.76** (sg crate family)
and **ant-quic 0.27.50** so shared types stay on one release line (replacing the
earlier temporary git pin of sg draft #51). The ceiling is configured once before
any topic creation or inbound traffic, including standalone managers; Full / D=0
use stock bounds. **Sustained-cap claim and full #504 acceptance remain held —
this stays experimental framing only.** This is a local implementation candidate,
not the accepted #504 fix.

```toml
[gossip]
leaf_max_eager_degree = 2
leaf_egress_soft_bytes_per_sec = 65536
leaf_egress_hard_bytes_per_sec = 131072
```

Degree accepts 0–12. Zero restores stock sg selection, not zero peers.
Full keeps the entire eligible plane regardless of these Leaf settings.
Invalid degree or enabled hard < soft restores the three budget defaults,
with a startup / `x0xd --check` warning; other config settings are preserved.
Either byte threshold can be disabled independently with zero. Byte limits
are observe-only: no shedding or priority changes.

All four x0x writers share the same policy: deduplicate and sort full PeerIds,
prefer the smallest eligible coordinator, then relay, then pinned bootstrap
ID in slot zero, append the sorted remainder and truncate for Leaf D > 0.
Candidate lists are collected before tie-breaking and filtered for the
advertised helper capability. Each refresh reads the full eligible plane for
replacement candidates. Periodic refresh uses stored topic IDs, including
DM inbox IDs, rather than rehashing the display name.

`GET /diagnostics/gossip` adds:

- `subscribed_topics`: `{name, topic_id_hex8}` rows from stored IDs. Hex8 means
  eight bytes / sixteen hex characters. Local-only IPC topics have no sg ID.
- `outbound_by_topic_named`: `{name, names, topic_id_hex8, outbound}` rows.
  Multiple aliases remain visible; unmapped / unsubscribed rows use
  `unknown-hex`. The existing raw sg meters and participation split remain.
- `egress_budget`: configured limits, observe-only policy, experimental
  status, last sample age, rolling 60-second subscribed outbound byte rate,
  and soft/hard exceed counts. Sampling runs with the runtime's nominal 1s
  peer-refresh tick, independently of API reads. Counts are exceeded samples,
  not crossings, seconds, packets or dropped messages. The denominator is
  always 60 seconds, including startup; sampling has approximately 1s
  resolution and attributes interval deltas by subscription at sampling time.
  These are sg send-attempt bytes, all kinds including repair, not confirmed
  QUIC bytes. sg's bounded per-topic meter can omit overflow topics.
- `egress_budget.repair`: EAGER transport attempts matching authenticated v2
  in-flight IWANT `(peer, topic, message ID)` requests. This separately shows
  cached recovery even though sg includes it in EAGER totals. It is a subset,
  not extra bytes to add to the total. Coincident same-message forwards can
  also match; v1 requests are not classified. Tracking is bounded to 4096
  active keys / IDs per handler with an overflow counter and cancellation
  cleanup. Anti-entropy remains in its own raw outbound kind. Exact causal
  repair provenance requires an sg send-origin hook.

## Acceptance and holds

In-process tests use real sg initialization, refresh, publishing and inbound
handlers with a recording transport. They cover all four writers at D=1/2/12,
Full and D=0, deterministic selection, raw DM IDs, local and selected-peer
inbound delivery, replacements after disconnect, cached IWANT replies,
HTTP fields, thresholds without shedding and window expiry.

The pinned sg integration test sends successive unique EAGER messages from
unlisted peers, serves cached IWANT requests from multiple other peers and
interleaves local publishes before any refresh. It checks actual outbound
fanout and local subscriber delivery. The earlier stock-sg experiment is
superseded by these ceiling assertions.

Additional in-process gates wait through two real 31s timer windows (sg mixes
wall-clock deadlines with Tokio timers), overlap inbound
handlers with local publishes on the Critical DM bus and await detached send
completion, and recover a deliberately missed cached
message through real IHAVE/IWANT handlers after both selected carriers fail.
The recovery fixture supplies the signed IHAVE advertisement; subsequent
request, cache response and local delivery use the actual handlers.

HOLD: sg #51 review/publication; exhaustive GRAFT/scoring/cooling integration
acceptance; full §6.2 acceptance; and external before/after public Leaf soak.
The sibling sg PR has its own maintenance and replacement tests; those are
separate dependency evidence, not x0x integration credit.
PR deferred pending #535 CI fence on main. No push or PR is authorized for
this local checkpoint. No daemon restart or public-mesh test is part of it.
