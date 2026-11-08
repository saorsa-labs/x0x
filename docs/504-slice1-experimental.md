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
leaf_egress_burst_bytes = 4194304
byte_policy = "observe_only"
```

Degree accepts 0–12. Zero restores stock sg selection, not zero peers.
Full keeps the entire eligible plane regardless of these Leaf settings.
Invalid degree, enabled hard < soft, or a burst too small to hold one maximum
frame restores the budget defaults, with a startup / `x0xd --check` warning;
other config settings are preserved. Either byte threshold can be disabled
independently with zero.

**Slice 2 (`byte_policy`).** The thresholds stay a meter by default. Setting
`byte_policy = "shed_normal"` on a **Leaf** with a non-zero hard rate is what
authorizes saorsa-gossip to deny a send; anything else — the default, a
Full/relay node, or a zero hard rate — sheds nothing. A `shed_normal` request
that cannot be honoured is ignored with a warning, never fatal. sg never
sheds Critical-class topics, local-origin publishes, own-inbox delivery or
targeted sends under any policy. Field acceptance for `shed_normal` is still
held; do not enable it on the fleet.

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
- `egress_budget`: configured limits (now including `leaf_egress_burst_bytes`
  and `max_serialized_frame_bytes`), experimental
  status, last sample age, rolling 60-second subscribed outbound byte rate,
  and soft/hard exceed counts. Sampling runs with the runtime's nominal 1s
  peer-refresh tick, independently of API reads. Counts are exceeded samples,
  not crossings, seconds, packets or dropped messages. The denominator is
  always 60 seconds, including startup; sampling has approximately 1s
  resolution and attributes interval deltas by subscription at sampling time.
  These are sg send-attempt bytes, all kinds including repair, not confirmed
  QUIC bytes. sg's bounded per-topic meter can omit overflow topics.
- `egress_budget.byte_policy`: the **effective** policy saorsa-gossip
  accepted, `observe_only` or `shed_normal`. `observe_only` also covers "no
  budget configured at all" (a Full/relay node, or a zero hard rate), because
  neither sheds. `byte_policy_requested` shows what the TOML asked for, so an
  ignored `shed_normal` is diagnosable rather than invisible.
- `egress_budget.leaf_egress`: sg's `LeafEgressSnapshot` — `demanded_bytes`,
  `charged_bytes`, `sent_bytes`, `send_failures`, `data_deferred`,
  `recovery_waited`, `budget_timeouts`, `queue_overflow`,
  `invariant_violations`, `pending_recovery_intents`, per-topic/purpose rows,
  and `shed_suppressed`. The last is the headroom enabling shedding would buy
  and, under the default policy, the only signal the budget is being exceeded
  at all; it is a lower bound, not a shed-count forecast.
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

HOLD: exhaustive GRAFT/scoring/cooling integration acceptance; full §6.2
acceptance; and external before/after public Leaf soak. Sustained public-mesh
cap claims remain out of scope for this experimental framing.

Published dependency line: crates.io saorsa-gossip **0.5.76** + ant-quic
**0.27.50** (CI fence #535 merged to main). Ships via draft release PR #544
(no tag/publish from docs alone). Daemon restart and public-mesh soak are
still not part of this checkpoint.

## Leaf publishing, `observe_only` metering and cooling (#731)

This section states current behaviour. It does not change the holds above.

**`observe_only` never stops a send.** Under the default `byte_policy`, the
Leaf egress budget is a meter only. `leaf_egress.soft_exceeded` and
`leaf_egress.hard_exceeded` count samples above a threshold. They do not feed
eager selection, cooling or admission.
`leaf_egress.leaf_egress_snapshot.shed_suppressed` shows the sends that `shed_normal` would have denied. Under `shed_normal`, sg
still never sheds locally originated publishes or the IWANT replies that serve
them.

**Eager selection does not follow the budget.** `leaf_max_eager_degree` sets
the sg eager-degree ceiling for each topic. Budget use does not change it.
The other connected topic peers are lazy: they get an IHAVE and must send an
IWANT to get the message. On a quiet topic, a subscriber can depend on that
IWANT path to the publisher.

**Cooling is local to the node that sends.** A node cools a peer on a topic
only after its own sends to that peer time out. The `observe_only` budget on
the publisher sends no signal to the subscriber. Thus a publisher over its
budget does not cause the subscriber to cool it. Look for cooling on the node
whose sends failed, in `pubsub_stages.peer_scores_by_topic`
(`suppression_state`, `cooldown_ms`, `outbound_send_timeouts`) and
`pubsub_stages.suppressed_peers_by_topic`.

**A Leaf publisher serves IWANT for its own messages.** The #380 C0 gate drops
EAGER, IHAVE, IWANT and anti-entropy frames on a topic that a Leaf does not
subscribe to. Before #731, this also dropped the IWANTs for a topic that the
Leaf published to but did not subscribe to, so a lazy subscriber did not get
the message. Now a Leaf keeps a bounded record of the topics it published to.
An entry stays for 60 s, the sg message-cache age limit, and the record holds
at most 1024 topics. When it is full, the node removes the oldest entry first.
While a topic is in the record, the gate lets inbound IWANT for that topic
through to PlumTree. The gate still drops EAGER, IHAVE and anti-entropy on
that topic. It also still drops all four kinds on topics that the node did not
publish to. A Full node is not changed.

The exemption is off for 120 s after a topic stops being subscribed. The
reasons are:

- While the node subscribes, its sg cache also holds messages from other
  peers.
- When the last local subscription handle drops, x0x does not empty that
  cache. An explicit unsubscribe empties it, but only after the topic leaves
  the subscribed set.
- sg queues a v3 frame whose signer key it does not know yet. A later
  key-cache response replays that frame without the gate. The replay can come
  up to 5.25 s later and can run for up to 30 s (the receive handler timeout).
- Each cache entry lives for 60 s.

The sum is 95.25 s, and 120 s adds a margin. After 120 s, the cache of an
unsubscribed topic normally holds only the node's own publishes. The 5.25 s
replay limit is best effort: sg does not check the age of a queued frame
before it replays it. That replay already bypassed the gate before #731.

Thus a node that unsubscribes and then publishes again does not serve IWANT
for that topic for the first 120 s. The record of unsubscribed topics also
holds at most 1024 topics. If it is full, the exemption is off for all topics
for 120 s.

To see this on `GET /diagnostics/gossip`:

- `participation.unsubscribed_refused_frames` and
  `participation.unsubscribed_refused_graft_equiv` do not increase for a
  served publisher IWANT. They still count real pass-through refusals.
- `pubsub_stages.message_kinds.iwant` counts the IWANTs that reached PlumTree.
- `inbound_by_topic` counts the IWANT frame before the gate.
- `participation.relay_bytes` counts all outbound bytes on topics that the
  node does not subscribe to. This includes the publisher's own publishes and
  its IWANT replies on such a topic, not only pass-through.
- With `RUST_LOG=x0x::gossip=debug`, the log line `Leaf refused unsubscribed
  PlumTree pass-through frame (#380 C0)` shows each refused frame with its
  topic and kind.

Still open in #731: a per-topic delivery class and a publish outcome on
`POST /publish`. Both change the public API and need a decision first.
