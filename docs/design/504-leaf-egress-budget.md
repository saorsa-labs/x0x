# Design: Leaf gossip egress budget (issue #504)

- **Status:** Draft for review — **source-and-evidence only**. No runtime
  acceptance is claimed.
- **Date:** 2026-09-06
- **Issue:** [#504](https://github.com/saorsa-labs/x0x/issues/504)
- **Related:** ADR 0034 (Leaf default), [#380](https://github.com/saorsa-labs/x0x/issues/380)
  C0 soak (`docs/380-c0-soak-gate.md`), [#501](https://github.com/saorsa-labs/x0x/issues/501)
  (legacy DM bus), [#505](https://github.com/saorsa-labs/x0x/issues/505)
  (ant-quic handshake MTU — **dependency only, not this work**)
- **Verified against:** `0b6515f9` (main, 2026-09-06); saorsa-gossip 0.5.74
  (`crates/membership`, `crates/pubsub` as published on `saorsa-labs/saorsa-gossip`
  `main` at investigation time)

This is a measurement and first-slice plan. It does **not** implement the
budget, does **not** change Leaf/Full behaviour, and does **not** close #504.

## 1. What Winston measured

v0.41.2 Windows Leaf, default config, ~35 min idle on the public mesh, ~25
connected peers, one `public_open` group, one message, no file transfers
(`x0x diagnostics gossip`):

| kind | bytes | msgs | implied rate |
|---|---|---|---|
| eager | 1.54 GB / 97,744 | ~44 MB/min (~733 KiB/s) | ~16 KiB/msg |
| ihave | 118 MB / 20.7k | ~3.4 MB/min | smaller |
| iwant | 75 MB | — | smaller |
| anti_entropy | 5.1 MB | — | noise |

The residential impact is the point: ~6 Mbps sustained uplink on an idle
desktop. #380 C0 already stopped **unsubscribed** pass-through. This leftover
is **subscribed-topic epidemic** — which C0's soak gate explicitly does not
count (`docs/380-c0-soak-gate.md` gates only
`participation.relay_bytes` = non-subscribed forward).

Triage (dirvine, 2026-09-05) asked to confirm whether
`active_view_size` / `passive_view_size` reach membership, which topics
dominate, and then budget egress. The three claims below are checked in-tree.

## 2. View-size knobs are dead

**Verdict: dead. Validated and stored; never applied to HyParView or PlumTree.**

### What operators think they set

`src/gossip/config.rs` documents HyParView knobs and validates them:

| TOML / `GossipConfig` field | default | validation |
|---|---|---|
| `active_view_size` | 6 | must be `> 0` |
| `passive_view_size` | 30 | must be `> 0` |
| `arwl` | 6 | must be `> 0` |
| `prwl` | 3 | must be `> 0` |

`GossipRuntime::new` (`src/gossip/runtime.rs:846–861`) calls
`config.validate()` then **ignores every view-size field**:

```rust
let membership_config = MembershipConfig::default();
let membership = Arc::new(HyParViewMembership::new(
    peer_id,
    membership_config,
    Arc::clone(&network),
));
```

Runtime tests (`src/gossip/runtime.rs:1121–1152`) only assert that
`runtime.config().active_view_size` **echoes the struct**. They never inspect
`membership()`. A zero `active_view_size` fails construction
(`test_runtime_invalid_config`) — so the knob can crash-loop a daemon without
changing overlay degree.

`arwl` / `prwl` have the same fate: validated, never read after
`GossipRuntime::new`.

### The names do not even match saorsa-gossip

`saorsa_gossip_membership::MembershipConfig` (sg 0.5.74) uses a different
schema:

| sg field | sg default | x0x analogue |
|---|---|---|
| `active_degree` | 8 | `active_view_size` (6) — **not wired** |
| `max_active_degree` | 12 | none |
| `max_passive_degree` | 128 | `passive_view_size` (30) — **not wired** |
| shuffle period / sizes | 30s / 3 / 4 | none |
| `adaptive_enabled` | true | none |

Even a mechanical wire would need an explicit mapping. x0x's documented
defaults (6 / 30) are not the values the overlay actually runs (8 / 12 / 128
plus adaptive scaling).

### HyParView view size would not cap Leaf egress anyway

PlumTree eager sets are **not** seeded from `membership.active_view()`.
`PubSubManager::refresh_topic_peers` / `initialize_topic_peers`
(`src/gossip/pubsub.rs:1089–1198`) feed **`network.gossip_plane_peers()`** —
every plane-cleared QUIC peer — into `plumtree.set_topic_peers` every 1 s
(`src/gossip/runtime.rs:1005–1015`).

Winston's ~25 connected peers is that plane set, not HyParView's active view.

### PlumTree eager degree is hardcoded in saorsa-gossip

sg 0.5.74 `crates/pubsub/src/lib.rs`:

```text
const MIN_EAGER_DEGREE: usize = 6;
const MAX_EAGER_DEGREE: usize = 12;
```

`set_topic_peers` (sg current, not the stale x0x diagram) does **not**
promote every lazy peer to eager. It:

1. drops disconnected peers
2. inserts new connected peers as **lazy**
3. calls `maintain_degree_at`, which demotes above 12 and promotes up to 6

So a Leaf with 25 plane peers still eager-forwards each subscribed-topic
payload to **6–12** peers, not 25. That is already enough to explain
Winston's numbers (see §4).

`docs/architecture-gossip-nat.md:250–270` still says the 1 s refresh
"promotes ALL lazy peers back to eager". That was true of an older sg; it is
**false on 0.5.74**. Treat that page as stale (also: identity heartbeat is
600 s now, not 30 s).

**Do not "wire the knobs" as the #504 fix.** Wiring HyParView `active_degree`
does not change PlumTree fan-out. Leave the dead fields in place this slice
(operators already have them in TOML); either map them honestly in a
follow-up or delete them so they stop lying.

## 3. Which topics/paths dominate idle Leaf egress

No live per-topic capture is in this tree. The ranking below is from
**always-on subscribe sites**. A Leaf refuses unsubscribed pass-through
(ADR 0034 / #380 C0) but **eager-forwards every topic it is subscribed to**.
`leaf_still_accepts_subscribed_topic_passthrough_frames`
(`src/gossip/pubsub.rs:2747`) locks that in.

### 3.1 Always-on subscriptions (every desktop daemon)

Started from `Agent::start_identity_listener` (`src/lib.rs:8091–8173`),
unconditional, once per process:

| topic | why it is loud |
|---|---|
| `x0x.identity.announce.v2` | **global** identity flood; every agent publishes; every Leaf forwards |
| `x0x.machine.announce.v2` | **global** machine flood (~12–16 KiB ML-DSA payloads) |
| `x0x.machine.announce.v3` | second global machine topic (ADR-0043) |
| `x0x.user.announce.v2` | **global** user roster flood |
| `x0x.identity.shard.v2.<own>` | own shard only — quieter |
| `x0x.machine.shard.v2.<own>` | own shard only — quieter |
| `x0x.user.shard.v2.<own>` | only if a user key exists |
| `x0x.revocation.v1` / `x0x.revocation.v2` | global, usually idle |
| `x0x.move.activation.v1` | global, usually idle |

Heartbeat cadence is 600 s (`IDENTITY_HEARTBEAT_INTERVAL_SECS`) and receivers
must not re-author a received payload (`src/lib.rs:880–892`). PlumTree still
**epidemic-forwards** each unique beat to the local eager set. N agents ×
(identity + machine v2 + machine v3 + user) / 600 s is already O(N) unique
msgs/min on every Leaf.

DM / capability (started from `start_dm_inbox` +
`start_capability_advert_service`, `src/server/mod.rs:2232`,
`src/lib.rs:9711`, `src/dm_inbox.rs:465–469`,
`src/dm_capability.rs:29–58`):

| topic | why it is loud |
|---|---|
| `x0x/dm/v1/bus` | **#501**: whole-network compat DM bus. Every Leaf subscribes unconditionally and therefore eager-forwards **every gossip DM on the mesh** |
| `x0x/dm/v1/inbox/<self>` | own inbox — should be quiet when idle |
| peer inbox + bus **pre-warm** | `ensure_subscribed_topic_id` on connect/receipt (`src/dm_inbox.rs:779–806`) — joins the bus again and the peer's inbox |
| `x0x/caps/v1` | mesh-wide capability advert, 600 s republish, Bulk |
| `x0x/caps/v2/digest` | digest extension, same cadence |
| `x0x/caps/v1/request/targeted-v2` | Critical; bursty, not idle-dominant |
| `x0x/caps/v1/response/targeted-v2` | Critical; bursty |
| `x0x/announce/v3/blob` | blob responder (`src/announce_blob.rs:54`, spawned from capability start) |

Daemon-only listeners (`src/server/mod.rs:1073–1088`):

| topic | why it is loud |
|---|---|
| `x0x.discovery.groups` | **global** group-card anti-entropy; every daemon |
| `x0x.groups.public.v1` | **global** public-message fallback (Phase E). Winston joined a `public_open` group — this bus carries those messages mesh-wide |
| `x0x.directory.{tag,name,id}.*` | only persisted shard subscriptions (`spawn_directory_resubscribe`) |
| per-group topic | only for locally known groups |
| `x0x/release` | only if the upgrade listener is running (`src/server/routes/upgrade.rs:285`) |

Presence beacons ride `GossipStreamType::Bulk`, not PlumTree EAGER. They are
not Winston's `eager` counter.

### 3.2 Why C0 can be green and wifi still dies

```text
C0 pass:  Δparticipation.relay_bytes / Δt  ≤ 150 KiB/s
#504:     Δparticipation.epidemic_forward_bytes / Δt  ≈ 733 KiB/s
```

`classify_outbound_relay_json` (`src/gossip/participation.rs:110–128`) already
splits those two. Winston's 1.54 GB lives in `epidemic_forward_*` if the node
was a true Leaf (`passthrough_refresh_runs == 0`). The soak gate never looked
at that field.

### 3.3 Back-of-envelope (not a proof)

Assume PlumTree cap 12, ~16 KiB/msg (matches 1.54 GB / 97,744):

```text
unique_msgs/s ≈ 97744 / 35 / 60 / 12  ≈ 3.9
egress        ≈ 3.9 × 16 KiB × 12     ≈ 750 KiB/s
```

~4 unique epidemic messages per second is **far above** local heartbeats
(one node × ~4 announce topics / 600 s ≈ 0.007/s). It is the **mesh publish
rate on the global topics this Leaf is subscribed to**, amplified by eager
degree 6–12.

Likely volume order (source, pending Winston/Ben named-topic capture):

1. **Global announce trio + v3** — every online agent, every Leaf forwards
2. **`x0x/dm/v1/bus`** — #501; dominates if the mesh still uses the compat bus
3. **`x0x.groups.public.v1`** + **`x0x.discovery.groups`** — every daemon; louder
   if anyone is in `public_open`
4. Capability / blob / directory shards — secondary
5. Own inbox / own shards / revocation / move — should be near-zero when idle

`docs/architecture-gossip-nat.md` must not be used to attribute the 44 MB/min
to "full-mesh eager of 25 peers". sg 0.5.74 already caps at 12. The remaining
levers are **topic membership** (stop sitting on global buses) and **eager
degree / byte budget** (stop forwarding 12 copies of each subscribed payload).

## 4. Operator-facing budget

Goal: a default Leaf on residential wifi stays usable. "Safe" here means
idle gossip egress well below a typical shared uplink, not zero delivery.

### 4.1 Target numbers

| role | idle epidemic (eager+ihave+iwant+ae) | eager degree | notes |
|---|---|---|---|
| **Leaf default** | soft 64 KiB/s, hard 128 KiB/s | **2** | ~6× cut vs Winston if unique rate stays; wifi-safe if unique rate also drops (#501) |
| Leaf operator override | any | 1–12 | TOML |
| **Full / `--relay` / seed / `:443` / managed** | **no Leaf budget** | sg 6–12 | backbone; do not starve relays |

64 KiB/s = 3.8 MB/min. Winston's 44 MB/min is ~12× that. Degree 12 → 2 is a
~6× fan-out cut (to ~7 MB/min) **if** unique rate is unchanged. Closing #501
and/or making global announce consume-only on Leaf is what gets the rest.

C0's 150 KiB/s `relay_bytes` gate stays. Add a sibling gate on
`epidemic_forward_bytes` for Leaf only (see §5).

### 4.2 Config surface

Add to `[gossip]` (`src/gossip/config.rs` + daemon TOML). Defaults apply only
when `resolved_participation() == Leaf`. Full ignores them.

```toml
[gossip]
# Existing dead knobs stay (do not imply they work). New live knobs:

# Max peers passed into PlumTree set_topic_peers / initialize_topic_peers
# for a Leaf. 0 = do not truncate (today's sg 6–12). Default 2.
leaf_max_eager_degree = 2

# Rolling 60s epidemic (subscribed-topic) outbound. 0 = disabled.
# Soft: warn + diagnostics. Hard: fail-soft shed (below).
leaf_egress_soft_bytes_per_sec = 65536
leaf_egress_hard_bytes_per_sec = 131072
```

Prefer Full/bootstrap peers at the front of the truncated list. The helper
already exists for ACK topics:
`select_one_full_bootstrap_eager_peer` (`src/gossip/pubsub.rs:1351`). Reuse
it so a Leaf's two eager slots are backbone, not two other Leaves.

Do **not** bind this slice to `skip_legacy_dm_bus` (#501). That is a topic-
membership change with a compat trade-off; keep it on its own PR.

### 4.3 Fail-soft behaviour

When the hard budget is exceeded, in this order, **never** disconnect, **never**
fail `subscribe` / `publish` of local origin, **never** drop the node's own
inbox:

1. Count `egress_budget_soft_exceeded` / `egress_budget_hard_exceeded` on
   `GET /diagnostics/gossip`.
2. Shed **IHAVE flush** and **anti-entropy serve** first (recoverable).
3. Then shed **Bulk-class eager republish** (`classify_x0x_topic` already
   marks announce/shard/directory/caps/release as Bulk —
   `src/gossip/pubsub.rs:1464–1478`).
4. **Do not shed** Critical: `x0x/dm/v1/inbox/<self>`, targeted caps,
   identity announce **local publish** (the node must still be findable).
5. Log at warn with topic hex + name + bytes/s. Rate-limit the log.
6. If sg has no shed hook yet, **cap fan-out first** (this is slice 1) and
   treat the byte budget as observe-only until a later slice. Do not invent
   a silent drop path that we cannot meter.

Invalid TOML (hard < soft, degree 0 with a comment that means "off"):
fail-soft to defaults + a `x0xd --check` warning. Do not refuse process
start for a budget typo (the `active_view_size = 0` restart-loop is the
anti-pattern to avoid).

### 4.4 What we will not do in the first implementation

- Full PlumTree rewrite or a saorsa-gossip API bump unless slice 1 proves
  x0x-side truncation is insufficient (sg already caps at 12; x0x can pass
  fewer peers).
- Consume-only subscribe (deliver locally, do not eager-forward) — needs an
  sg hook or a dangerous x0x-side "accept but don't republish" fork.
  Follow-up, after named-topic evidence.
- Changing identity heartbeat cadence again (already 600 s).
- Fixing #505 (ant-quic MTU / IP fragmentation). Mention only: some
  measurement hosts (OCI) cannot join the public mesh until that lands.

## 5. Measurement recipe (Winston / Ben Mac)

No implementation in this PR can substitute for a live Leaf on the public
mesh. Capture **one idle window** on current main (or the first-slice build)
and attach the JSON.

### 5.1 Setup

- One Leaf: default config, **no** `--relay`, `gossip.relay` unset.
- Confirm `x0x diagnostics gossip` → `participation.mode == "leaf"`,
  `reason == "default_leaf"`, `passthrough_refresh_runs == 0`.
- Same workload as #504 if possible: one `public_open` group, no file
  transfers, no extra `x0x subscribe`.
- Note OS, version (`x0x --version` / `/health`), peer count
  (`/health` `peers`, `/diagnostics/transport`), NAT, and whether #501's
  bus skip is on or off (default off).
- Fixed window: **20 minutes** idle after `peers` has been stable for 2
  minutes. Shorter windows (5 min) are ok as a smoke but the #504 number
  was 35 min.

### 5.2 Commands

```bash
# t0
x0x diagnostics gossip  > /tmp/gossip-t0.json
x0x diagnostics transport > /tmp/transport-t0.json
date -u +%s > /tmp/t0.epoch

# wait 1200s, do not publish, do not open extra subscriptions

# t1
x0x diagnostics gossip  > /tmp/gossip-t1.json
x0x diagnostics transport > /tmp/transport-t1.json
date -u +%s > /tmp/t1.epoch
```

Equivalent HTTP: `GET /diagnostics/gossip`, `GET /diagnostics/transport`.

### 5.3 Counters to delta

From `participation` (already subscription-aware):

| field | meaning |
|---|---|
| `epidemic_forward_bytes` / `_msgs` | subscribed-topic outbound — **#504 primary** |
| `relay_bytes` / `_msgs` | unsubscribed forward — must stay ~0 on Leaf |
| `unsubscribed_refused_frames` | C0 still live |
| `passthrough_refresh_runs` | must stay 0 |

From `pubsub_stages` (sg 0.5.74):

| field | meaning |
|---|---|
| `outbound_kind_*` eager/ihave/iwant/anti_entropy | Winston's four buckets |
| `outbound_by_topic` | **per-topic** msgs/bytes by kind |
| `outbound_publish_origin` | **do not use** for Leaf soak (mis-labels epidemic as relay) |
| `zero_fanout_publishes` / `republish_per_peer_timeout` | delivery vs congestion |

`outbound_by_topic` keys are `TopicId` **first 8 hex bytes**
(`saorsa_gossip_types::TopicId` `Display`), **not** topic names.
`classify_outbound_relay_json` already matches those hex keys to
`subscribed_topic_ids`. Operators cannot tell `x0x/dm/v1/bus` from
`x0x.identity.announce.v2` without a name map.

Until slice 1 ships the map, attach this lookup (compute locally; x0x
already has `TopicId::from_entity`):

```text
x0x.identity.announce.v2
x0x.machine.announce.v2
x0x.machine.announce.v3
x0x.user.announce.v2
x0x.revocation.v1
x0x.revocation.v2
x0x.move.activation.v1
x0x/dm/v1/bus
x0x/caps/v1
x0x/caps/v2/digest
x0x.discovery.groups
x0x.groups.public.v1
x0x/announce/v3/blob
x0x/release
```

plus the node's own identity/machine shard strings and
`x0x/dm/v1/inbox/<self>`. Rank `outbound_by_topic` by `eager.bytes` and
label any hex that matches.

Also record:

- `/health` `peers` at t0 and t1 (Winston: ~25)
- `discovery_cache_entries` from the same gossip payload (agents / machines /
  users) — proxy for announce-topic population
- Whether a `public_open` group is joined (yes for the original report)

### 5.4 Acceptance of the *measurement* (not of a fix)

A capture is usable when:

1. `participation.mode` is `leaf` for the whole window
2. `Δt` is ≥ 300 s (prefer 1200 s)
3. `Δrelay_bytes / Δt` is consistent with C0 (≤ 150 KiB/s; expect ≪ that)
4. `Δepidemic_forward_bytes / Δt` is reported in KiB/s **and** MB/min
5. Top 8 `outbound_by_topic` rows are labelled with names or marked `unknown-hex`
6. Peer count did not collapse to 0 (that would be an #505 / isolation run)

This PR does **not** claim that capture. Platform/soak credit only when
Winston or Ben attach the JSON.

### 5.5 What Ben Mac should add if Winston's host is the only public Leaf

Same recipe on macOS, same window, default Leaf. If both see the same top
topics, the budget can target those names. If they diverge (bus vs announce),
do not ship a Leaf-default `skip_legacy_dm_bus` from this work — keep #501
separate.

## 6. Smallest first implementation slice

**Slice 1 — cap Leaf eager fan-out in x0x + name the meters. No sg bump.**

Why this and not "wire the HyParView knobs": §2. The live amplifier is
`set_topic_peers(plane_peers)` on subscribed topics, degree 6–12. x0x
already chooses that peer list.

### 6.1 Code (surgical)

1. `GossipConfig`: `leaf_max_eager_degree: usize` (default 2),
   `leaf_egress_soft_bytes_per_sec` / `_hard_` (defaults as §4.2). Validate
   degree `== 0 || (1..=12)`. `0` means "do not truncate".
2. `PubSubManager::apply_topic_peers` / `initialize_topic_peers`: if Leaf and
   degree `> 0`, reorder with `select_one_full_bootstrap_eager_peer` (then
   remaining plane peers) and **truncate** before `set_topic_peers`. Full
   unchanged.
3. `GET /diagnostics/gossip`: add
   - `subscribed_topics`: `[{ name, topic_id_hex8 }]`
   - `outbound_by_topic_named`: same rows as `pubsub_stages.outbound_by_topic`
     with `name` filled when known
   - `egress_budget`: configured limits + current 60s rate + exceed counts
     (rate can be observe-only this slice)
4. Do not enforce the hard byte shed yet unless the named capture shows a
   single Bulk topic we can refuse without an sg hook. Fan-out cap is the
   behaviour change.

### 6.2 Acceptance tests (unit / in-process — no public mesh)

Name them for the invariant, not the function.

| test | why |
|---|---|
| `leaf_apply_topic_peers_truncates_to_configured_degree` | A Leaf with 8 plane peers and `leaf_max_eager_degree = 2` calls `set_topic_peers` with ≤ 2 ids. Today's `leaf_refresh_topic_peers_skips_unsubscribed_passthrough_topics` stays green. |
| `leaf_eager_cap_prefers_one_full_bootstrap_peer` | If a coordinator/relay/pinned bootstrap is in the plane, it occupies slot 0. Reuses `select_one_full_bootstrap_eager_peer`. |
| `full_apply_topic_peers_does_not_truncate` | `--relay` / Full still passes the full plane list (sg 6–12 remains). |
| `leaf_max_eager_degree_zero_means_no_truncate` | Escape hatch; 0 must not become "zero peers" (that would isolate). |
| `partial_toml_leaf_budget_falls_back_to_defaults` | Same class as `partial_toml_section_falls_back_to_defaults` — a partial `[gossip]` must not restart-loop. |
| `gossip_diagnostics_maps_outbound_topic_hex_to_subscribed_name` | Hex8 for `x0x/dm/v1/bus` appears with that name. Why: Winston cannot otherwise attribute 44 MB/min. |
| `leaf_epidemic_bytes_are_not_relay_bytes` | Existing `classify_outbound_relay_json` split; keep it as the soak contract so C0 and #504 cannot be confused again. |

Do **not** add a live-mesh soak to CI. Document the §5 recipe as the
external gate (`docs/380-c0-soak-gate.md` style): Leaf,
`Δepidemic_forward_bytes/Δt` after slice 1, same peers.

### 6.3 Later slices (not this one)

| slice | what | depends on |
|---|---|---|
| 2 | Fail-soft Bulk shed at hard byte budget | named capture + a meter we can increment in tests |
| 3 | Consume-only / no-forward for global announce on Leaf | sg API or a carefully metered x0x fork; evidence that announce (not the bus) is the top row |
| 4 | #501 `skip_legacy_dm_bus` default-on-Leaf decision | #501 PR + the same capture |
| 5 | Honest HyParView mapping **or** delete dead knobs | independent cleanup; does not close #504 |
| — | #505 ant-quic MTU | other repo; only blocks some measurement hosts |

## 7. Success criteria for *this* document

- [x] View-size knobs cited as dead, with files
- [x] Dominant idle paths identified from subscribe sites (not from a live run)
- [x] Operator budget + fail-soft + Leaf vs Full defaults
- [x] Concrete capture recipe for Winston / Ben
- [x] Smallest slice with acceptance tests, no rewrite

**Not claimed:** runtime reduction on the public mesh, C0 soak re-run, or
#504 closed.

## 8. Checkpoint

- Confirmed: `GossipRuntime::new` uses `MembershipConfig::default()`;
  `active_view_size` / `passive_view_size` / `arwl` / `prwl` never leave
  `GossipConfig`.
- Confirmed: Leaf still refreshes and eager-forwards **subscribed** system
  topics; C0 only refuses **unsubscribed** ones.
- Confirmed: sg PlumTree eager degree is hardcoded 6–12; x0x's 1 s refresh
  feeds the entire plane into that cap.
- Unverified: which named topic owns Winston's 1.54 GB. Recipe in §5.
- Left alone: ant-quic (#505), DM-bus default (#501), live soak.
