# Design: Leaf gossip egress budget (issue #504)

- **Status:** Draft for review — **source-and-evidence only**. No runtime
  acceptance is claimed. Revised 2026-09-06 after Codex FAIL on
  [#534](https://github.com/saorsa-labs/x0x/pull/534) (B1 P1 degree
  enforcement, B2 P2 executable name-lookup) plus Claude non-hold notes
  (recipe clarity, shed-ladder, §6.1 before Winston capture).
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
3. calls `maintain_degree_at`, which demotes above 12 and **promotes up to 6**

So a Leaf with 25 plane peers still eager-forwards each subscribed-topic
payload to **6–12** peers, not 25. That is already enough to explain
Winston's numbers (see §3.3).

Inbound frames do the same promotion. `handle_eager_admitted` and
`handle_iwant_admitted` (sg `crates/pubsub/src/lib.rs` ~6588 and ~6868)
`add_new_peer_lazy(from)` then `maintain_degree_at` toward **MIN_EAGER_DEGREE
= 6**. The 30 s `spawn_degree_maintainer` repeats that. **This is why
truncating two x0x `set_topic_peers` call sites cannot enforce degree 2**
(see §6.0).

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

Label a live capture with the **precomputed hex map in §5.4** — do not wait
for a Rust name-map to land.

### 3.1 Always-on subscriptions (every desktop daemon)

Started from `Agent::start_identity_listener` (`src/lib.rs:8091–8173`),
unconditional, once per process:

| topic | hex8 (`TopicId` Display) | why it is loud |
|---|---|---|
| `x0x.identity.announce.v2` | `802ee0ebd00757bd` | **global** identity flood; every agent publishes; every Leaf forwards |
| `x0x.machine.announce.v2` | `9087591cb1460b0c` | **global** machine flood (~12–16 KiB ML-DSA payloads) |
| `x0x.machine.announce.v3` | `0fe8dab9818469c5` | second global machine topic (ADR-0043) |
| `x0x.user.announce.v2` | `2f144a8e4595c85f` | **global** user roster flood |
| `x0x.identity.shard.v2.<own>` | compute (§5.4) | own shard only — quieter |
| `x0x.machine.shard.v2.<own>` | compute (§5.4) | own shard only — quieter |
| `x0x.user.shard.v2.<own>` | compute (§5.4) | only if a user key exists |
| `x0x.revocation.v1` | `bd56420e10cce2c8` | global, usually idle |
| `x0x.revocation.v2` | `2041a15425a97c03` | global, usually idle |
| `x0x.move.activation.v1` | `1c024f5cc8369f71` | global, usually idle |

Heartbeat cadence is 600 s (`IDENTITY_HEARTBEAT_INTERVAL_SECS`) and receivers
must not re-author a received payload (`src/lib.rs:880–892`). PlumTree still
**epidemic-forwards** each unique beat to the local eager set. N agents ×
(identity + machine v2 + machine v3 + user) / 600 s is already O(N) unique
msgs/min on every Leaf.

DM / capability (started from `start_dm_inbox` +
`start_capability_advert_service`, `src/server/mod.rs:2232`,
`src/lib.rs:9711`, `src/dm_inbox.rs:465–469`,
`src/dm_capability.rs:29–58`):

| topic | hex8 | why it is loud |
|---|---|---|
| `x0x/dm/v1/bus` | `a746d680e31732d1` | **#501**: whole-network compat DM bus. Every Leaf subscribes unconditionally and therefore eager-forwards **every gossip DM on the mesh** |
| own inbox | **not** `from_entity(name)` — see §5.4 | should be quiet when idle |
| peer inbox + bus **pre-warm** | bus hex above | `ensure_subscribed_topic_id` on connect/receipt (`src/dm_inbox.rs:779–806`) — joins the bus again and the peer's inbox |
| `x0x/caps/v1` | `dc7b2786c9d47788` | mesh-wide capability advert, 600 s republish, Bulk |
| `x0x/caps/v2/digest` | `72e595c2a0f13284` | digest extension, same cadence |
| `x0x/caps/v1/request/targeted-v2` | `143d90e8ad14052e` | Critical; bursty, not idle-dominant |
| `x0x/caps/v1/response/targeted-v2` | `48c7b5c7b6b981ca` | Critical; bursty |
| `x0x/announce/v3/blob` | `29f3042b0b96bc05` | blob responder (`src/announce_blob.rs:54`) |

Daemon-only listeners (`src/server/mod.rs:1073–1088`):

| topic | hex8 | why it is loud |
|---|---|---|
| `x0x.discovery.groups` | `8404a8731fd56b98` | **global** group-card anti-entropy; every daemon |
| `x0x.groups.public.v1` | `76c8448d415e21a8` | **global** public-message fallback. Winston joined a `public_open` group — this bus carries those messages mesh-wide |
| `x0x.directory.{tag,name,id}.*` | compute (§5.4) | only persisted shard subscriptions |
| per-group topic | compute (§5.4) | only for locally known groups |
| `x0x/release` | `378a3991c784ddc5` | only if the upgrade listener is running |

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
2. **`x0x/dm/v1/bus`** (`a746d680e31732d1`) — #501
3. **`x0x.groups.public.v1`** + **`x0x.discovery.groups`**
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
~6× fan-out cut (to ~7 MB/min) **if** unique rate is unchanged **and** the
cap holds after inbound EAGER/IWANT (§6.0). Closing #501 and/or making
global announce consume-only on Leaf is what gets the rest.

C0's 150 KiB/s `relay_bytes` gate stays. Add a sibling **observe** of
`epidemic_forward_bytes` on the §5 capture; do not treat the byte hard-cap
as slice-1 behaviour.

### 4.2 Config surface

Add to `[gossip]` (`src/gossip/config.rs` + daemon TOML). Defaults apply only
when `resolved_participation() == Leaf`. Full ignores them.

```toml
[gossip]
# Existing dead knobs stay (do not imply they work).

# Target PlumTree eager-set size on this Leaf. This is a bound that
# set_topic_peers, initialize_topic_peers, handle_eager, handle_iwant,
# and the 30s degree maintainer must all honor. It is NOT "truncate the
# plane list on two call sites".
# 0 = do not override sg 6–12. Default 2.
leaf_max_eager_degree = 2

# Rolling 60s epidemic (subscribed-topic) outbound. 0 = disabled.
# Slice 1: parse + meter + warn only. Slice 2: fail-soft shed (§4.3).
leaf_egress_soft_bytes_per_sec = 65536
leaf_egress_hard_bytes_per_sec = 131072
```

Prefer Full/bootstrap peers in the eager slots. The helper already exists
for ACK topics: `select_one_full_bootstrap_eager_peer`
(`src/gossip/pubsub.rs:1351`). Reuse it so a Leaf's two eager slots are
backbone, not two other Leaves.

Do **not** bind this slice to `skip_legacy_dm_bus` (#501). That is a topic-
membership change with a compat trade-off; keep it on its own PR.

### 4.3 Fail-soft behaviour (shed ladder)

**Slice 1 does not shed bytes.** It enforces eager degree. Soft/hard byte
fields are parsed, validated, and surfaced on `/diagnostics/gossip` as
observe-only (`current_epidemic_bytes_per_sec`,
`egress_budget_soft_exceeded`, `egress_budget_hard_exceeded` stay 0 unless
the operator is over the observed rate — incrementing those counters is
allowed; dropping frames is not).

**Slice 2** (after named capture) may shed when the hard budget is exceeded,
in this order, **never** disconnect, **never** fail `subscribe` or
**local-origin** `publish`, **never** drop the node's own inbox:

| step | what | why this order |
|---|---|---|
| 0 | Increment `egress_budget_hard_exceeded`; warn with topic hex8 + name + bytes/s (rate-limited) | loud, reversible |
| 1 | Shed **IHAVE flush** (lazy advertisements) | recoverable via IWANT / anti-entropy |
| 2 | Shed **anti-entropy serve** | same; delays catch-up, does not isolate |
| 3 | Shed **Bulk-class eager republish of received** payloads (`classify_x0x_topic` Bulk: announce / shard / directory / caps / release / public discovery — `src/gossip/pubsub.rs:1464–1478`) | this is the wifi burner |
| 4 | **Do not shed** Critical: own `x0x/dm/v1/inbox/<self>`, targeted caps request/response | delivery contract |
| 5 | **Do not shed** local-origin publish, including this node's own identity/machine announce | the node must stay findable |
| 6 | **Do not shed** inbound delivery to local subscribers | consume-only is a later slice, not silent drop |

Identity announce is Bulk **when forwarding someone else's beat** and
must stay unsuppressed **when this node authors a beat**. The shed hook
has to distinguish origin, not just topic name. If sg has no origin-aware
shed, stay on observe-only rather than inventing an unmetered drop.

Invalid TOML (hard < soft, degree outside `0..=12`): fail-soft to defaults
+ a `x0xd --check` warning. Do not refuse process start (the
`active_view_size = 0` restart-loop is the anti-pattern).

### 4.4 What we will not do in the first implementation

- Treat "truncate the `Vec<PeerId>` on `apply_topic_peers` /
  `initialize_topic_peers`" as degree enforcement. Codex FAIL: it is not
  (§6.0).
- Full PlumTree rewrite. An sg **eager-bound API** (or an x0x post-inbound
  clamp that is proven against handle_eager / IWANT / maintainer) is the
  smallest complete lever.
- Consume-only subscribe (deliver locally, do not eager-forward) — later,
  after named-topic evidence.
- Changing identity heartbeat cadence again (already 600 s).
- Fixing #505 (ant-quic MTU / IP fragmentation). Mention only: some
  measurement hosts (OCI) cannot join the public mesh until that lands.
- Asking Winston to recapture **without** a name-lookup. The table +
  scripts in §5.4 are that lookup; they land in this doc, not in a later
  Rust PR.

## 5. Measurement recipe (Winston / Ben Mac)

Capture **on current main / v0.41.x** using this section. Do **not** wait
for slice-1 Rust. The hex map below is the name-lookup. A later
`outbound_by_topic_named` field is convenience, not a gate.

Winston's host is **Windows**. Commands below are given for PowerShell
first, then Unix.

### 5.1 Setup (both)

- One Leaf: default config, **no** `--relay`, `gossip.relay` unset.
- Confirm `participation.mode == "leaf"`, `reason == "default_leaf"`,
  `passthrough_refresh_runs == 0`.
- Same workload as #504 if possible: one `public_open` group, no file
  transfers, no extra `x0x subscribe`.
- Record: OS, `x0x --version` or `/health` `version`, `/health` `peers`,
  NAT, `#501 skip_legacy_dm_bus` (default off).
- Window: **20 minutes** idle after `peers` has been stable for 2 minutes
  (≥300 s is the minimum usable window; #504 was ~35 min).

### 5.2 Windows (Winston) — PowerShell

API port is whatever `x0x health` prints (often `12700`). If `x0x` is on
PATH, the CLI wrappers are enough.

```powershell
# 0) confirm Leaf
x0x diagnostics gossip | Out-File -Encoding utf8 gossip-probe.json
# Open gossip-probe.json and check participation.mode / reason /
# passthrough_refresh_runs. Stop if not leaf / default_leaf / 0.

# 1) t0
x0x diagnostics gossip     | Out-File -Encoding utf8 gossip-t0.json
x0x diagnostics transport  | Out-File -Encoding utf8 transport-t0.json
[DateTimeOffset]::UtcNow.ToUnixTimeSeconds() | Out-File t0.epoch

# 2) wait 20 minutes. Do not publish. Do not extra-subscribe.
Start-Sleep -Seconds 1200

# 3) t1
x0x diagnostics gossip     | Out-File -Encoding utf8 gossip-t1.json
x0x diagnostics transport  | Out-File -Encoding utf8 transport-t1.json
[DateTimeOffset]::UtcNow.ToUnixTimeSeconds() | Out-File t1.epoch
```

Equivalent HTTP if the CLI is not on PATH (replace port / token):

```powershell
$h = @{ Authorization = "Bearer $env:X0X_API_TOKEN" }
Invoke-RestMethod http://127.0.0.1:12700/diagnostics/gossip -Headers $h |
  ConvertTo-Json -Depth 20 | Out-File -Encoding utf8 gossip-t0.json
```

Delta (no `jq` required):

```powershell
$t0 = Get-Content gossip-t0.json -Raw | ConvertFrom-Json
$t1 = Get-Content gossip-t1.json -Raw | ConvertFrom-Json
$dt = [int](Get-Content t1.epoch) - [int](Get-Content t0.epoch)
$epi = [int64]$t1.participation.epidemic_forward_bytes - [int64]$t0.participation.epidemic_forward_bytes
$rel = [int64]$t1.participation.relay_bytes - [int64]$t0.participation.relay_bytes
"dt_s=$dt  epidemic_KiB_s=$([math]::Round($epi/$dt/1024,2))  epidemic_MB_min=$([math]::Round($epi/1MB/($dt/60),2))  relay_KiB_s=$([math]::Round($rel/$dt/1024,2))"
```

Per-topic rank + label (uses the map in §5.4):

```powershell
$map = @{
  '802ee0ebd00757bd'='x0x.identity.announce.v2'
  '9087591cb1460b0c'='x0x.machine.announce.v2'
  '0fe8dab9818469c5'='x0x.machine.announce.v3'
  '2f144a8e4595c85f'='x0x.user.announce.v2'
  'bd56420e10cce2c8'='x0x.revocation.v1'
  '2041a15425a97c03'='x0x.revocation.v2'
  '1c024f5cc8369f71'='x0x.move.activation.v1'
  'a746d680e31732d1'='x0x/dm/v1/bus'
  'dc7b2786c9d47788'='x0x/caps/v1'
  '72e595c2a0f13284'='x0x/caps/v2/digest'
  '143d90e8ad14052e'='x0x/caps/v1/request/targeted-v2'
  '48c7b5c7b6b981ca'='x0x/caps/v1/response/targeted-v2'
  '8404a8731fd56b98'='x0x.discovery.groups'
  '76c8448d415e21a8'='x0x.groups.public.v1'
  '29f3042b0b96bc05'='x0x/announce/v3/blob'
  'c7770a8688e4f8e8'='x0x/announce/v2/blob'
  '378a3991c784ddc5'='x0x/release'
}
$rows = @()
$t1.pubsub_stages.outbound_by_topic.PSObject.Properties | ForEach-Object {
  $hex = $_.Name
  $eagerB = 0; if ($_.Value.eager.bytes) { $eagerB = [int64]$_.Value.eager.bytes }
  $name = $map[$hex]; if (-not $name) { $name = 'unknown-hex' }
  $rows += [pscustomobject]@{ hex8=$hex; name=$name; eager_bytes=$eagerB }
}
$rows | Sort-Object eager_bytes -Descending | Select-Object -First 8 | Format-Table -AutoSize
```

Attach: `gossip-t0.json`, `gossip-t1.json`, `transport-t0.json`,
`transport-t1.json`, the printed delta line, the top-8 table.

### 5.3 Unix / macOS (Ben Mac)

```bash
x0x diagnostics gossip > gossip-t0.json
x0x diagnostics transport > transport-t0.json
date -u +%s > t0.epoch
sleep 1200
x0x diagnostics gossip > gossip-t1.json
x0x diagnostics transport > transport-t1.json
date -u +%s > t1.epoch

python3 - <<'PY'
import json, pathlib
t0=json.loads(pathlib.Path("gossip-t0.json").read_text())
t1=json.loads(pathlib.Path("gossip-t1.json").read_text())
dt=int(pathlib.Path("t1.epoch").read_text())-int(pathlib.Path("t0.epoch").read_text())
epi=int(t1["participation"]["epidemic_forward_bytes"])-int(t0["participation"]["epidemic_forward_bytes"])
rel=int(t1["participation"]["relay_bytes"])-int(t0["participation"]["relay_bytes"])
print(f"dt_s={dt} epidemic_KiB_s={epi/dt/1024:.2f} epidemic_MB_min={epi/1e6/(dt/60):.2f} relay_KiB_s={rel/dt/1024:.2f}")
MAP={
  "802ee0ebd00757bd":"x0x.identity.announce.v2",
  "9087591cb1460b0c":"x0x.machine.announce.v2",
  "0fe8dab9818469c5":"x0x.machine.announce.v3",
  "2f144a8e4595c85f":"x0x.user.announce.v2",
  "bd56420e10cce2c8":"x0x.revocation.v1",
  "2041a15425a97c03":"x0x.revocation.v2",
  "1c024f5cc8369f71":"x0x.move.activation.v1",
  "a746d680e31732d1":"x0x/dm/v1/bus",
  "dc7b2786c9d47788":"x0x/caps/v1",
  "72e595c2a0f13284":"x0x/caps/v2/digest",
  "143d90e8ad14052e":"x0x/caps/v1/request/targeted-v2",
  "48c7b5c7b6b981ca":"x0x/caps/v1/response/targeted-v2",
  "8404a8731fd56b98":"x0x.discovery.groups",
  "76c8448d415e21a8":"x0x.groups.public.v1",
  "29f3042b0b96bc05":"x0x/announce/v3/blob",
  "c7770a8688e4f8e8":"x0x/announce/v2/blob",
  "378a3991c784ddc5":"x0x/release",
}
rows=[]
for hex8, row in (t1.get("pubsub_stages") or {}).get("outbound_by_topic") or {}.items():
    b=int(((row.get("eager") or {}).get("bytes")) or 0)
    rows.append((b, hex8, MAP.get(hex8,"unknown-hex")))
for b,h,n in sorted(rows, reverse=True)[:8]:
    print(f"{h}  {n}  eager_bytes={b}")
PY
```

### 5.4 Executable name-lookup (`TopicId::from_entity`)

sg `TopicId::from_entity(bytes)` is **BLAKE3 of the topic UTF-8 bytes**.
`Display` / `outbound_by_topic` keys are **hex of the first 8 bytes**
(16 hex chars), lowercase (`saorsa_gossip_types::TopicId`).

**Well-known map (precomputed 2026-09-06, python `blake3` == rust `blake3`
crate):**

| hex8 | topic |
|---|---|
| `802ee0ebd00757bd` | `x0x.identity.announce.v2` |
| `9087591cb1460b0c` | `x0x.machine.announce.v2` |
| `0fe8dab9818469c5` | `x0x.machine.announce.v3` |
| `2f144a8e4595c85f` | `x0x.user.announce.v2` |
| `bd56420e10cce2c8` | `x0x.revocation.v1` |
| `2041a15425a97c03` | `x0x.revocation.v2` |
| `1c024f5cc8369f71` | `x0x.move.activation.v1` |
| `a746d680e31732d1` | `x0x/dm/v1/bus` |
| `dc7b2786c9d47788` | `x0x/caps/v1` |
| `72e595c2a0f13284` | `x0x/caps/v2/digest` |
| `143d90e8ad14052e` | `x0x/caps/v1/request/targeted-v2` |
| `48c7b5c7b6b981ca` | `x0x/caps/v1/response/targeted-v2` |
| `8404a8731fd56b98` | `x0x.discovery.groups` |
| `76c8448d415e21a8` | `x0x.groups.public.v1` |
| `29f3042b0b96bc05` | `x0x/announce/v3/blob` |
| `c7770a8688e4f8e8` | `x0x/announce/v2/blob` (legacy; usually absent) |
| `378a3991c784ddc5` | `x0x/release` |

**Not in the table (compute):**

- Own / peer shards: `x0x.identity.shard.v2.<u16>` etc. — still
  `from_entity` of that string.
- Own inbox: **not** `from_entity("x0x/dm/v1/inbox/...")`.
  `dm_inbox_topic` is `blake3(b"x0x/dm/v1/inbox/" || agent_id_bytes)`
  (`src/dm.rs:1068–1072`). The human name embeds the **full 32-byte**
  topic hex (`src/dm_inbox.rs:400–404`). If a hex8 is unknown, check
  whether it is the prefix of that inbox hex.

**Windows — compute one name (Python; PowerShell has no BLAKE3):**

```powershell
pip install blake3
python -c "import blake3,sys; print(blake3.blake3(sys.argv[1].encode()).hexdigest()[:16])" "x0x.identity.shard.v2.0042"
```

**Windows — authoritative check against the same crate x0x uses**
(needs Rust + the repo, optional):

```powershell
# from a checkout that depends on saorsa-gossip-types 0.5.74
cargo test -q -p x0x --lib topic_id_hex8_matches_design_table -- --exact
# (that test is part of slice 1a — until it exists, use the Python line)
```

One-off rustc is also fine:

```rust
// rust-script / cargo-eval sketch — do not add this file until slice 1a
use saorsa_gossip_types::TopicId;
fn main() {
    let t = TopicId::from_entity("x0x/dm/v1/bus".as_bytes());
    println!("{t}"); // must print a746d680e31732d1
}
```

**Unix:**

```bash
python3 -c "import blake3,sys; print(blake3.blake3(sys.argv[1].encode()).hexdigest()[:16])" "x0x/dm/v1/bus"
# expect: a746d680e31732d1
```

If `blake3` is missing: `pip install blake3` (same on Windows). Do not use
SHA-256 — that is a different `TopicId`.

### 5.5 Counters to delta

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
| `outbound_by_topic` | **per-topic** msgs/bytes by kind (keys = hex8) |
| `outbound_publish_origin` | **do not use** for Leaf soak (mis-labels epidemic as relay) |
| `zero_fanout_publishes` / `republish_per_peer_timeout` | delivery vs congestion |

Also record `/health` `peers` at t0 and t1, `discovery_cache_entries`, and
whether a `public_open` group is joined.

### 5.6 Acceptance of the *measurement* (not of a fix)

A capture is usable when:

1. `participation.mode` is `leaf` for the whole window
2. `Δt` is ≥ 300 s (prefer 1200 s)
3. `Δrelay_bytes / Δt` is consistent with C0 (≤ 150 KiB/s; expect ≪ that)
4. `Δepidemic_forward_bytes / Δt` is reported in KiB/s **and** MB/min
5. Top 8 `outbound_by_topic` rows are labelled with §5.4 names or
   `unknown-hex` plus a computed name
6. Peer count did not collapse to 0 (that would be an #505 / isolation run)

This PR does **not** claim that capture. Platform/soak credit only when
Winston or Ben attach the JSON.

### 5.7 What Ben Mac should add if Winston's host is the only public Leaf

Same recipe on macOS, same window, default Leaf, same hex map. If both see
the same top topics, the budget can target those names. If they diverge
(bus vs announce), do not ship a Leaf-default `skip_legacy_dm_bus` from
this work — keep #501 separate.

## 6. Smallest first implementation slice

**Rejected first slice (Codex B1 P1 FAIL):** truncate the peer `Vec` on
`apply_topic_peers` and `initialize_topic_peers` only, then assert
`set_topic_peers` was called with ≤ 2 ids.

That cannot hold `leaf_max_eager_degree = 2`.

### 6.0 Why two-site truncate leaks back to degree 6

x0x writers that touch PlumTree peer sets today
(`src/gossip/pubsub.rs`):

| # | site | what it passes |
|---|---|---|
| W1 | `initialize_topic_peers` (subscribe + publish + refresh_subscribed) | **full** `gossip_plane_peers()` |
| W2 | `apply_topic_peers` (1 s `refresh_topic_peers`) | **full** plane |
| W3 | `refresh_subscribed_topic_id` | W1, then a **second** `plumtree.set_topic_peers(full plane)` that **bypasses** `apply_topic_peers` |
| W4 | `apply_preferred_eager_peer` (C5b ACK: inbox + bus) | preferred Full first, then **the rest of the plane**, via **direct** `plumtree.set_topic_peers` |
| W5 | `subscribe_topic_id` / `publish*` | W1 |

Even if W1–W5 all truncate to 2 ids, sg 0.5.74 **re-grows** the eager set:

| # | site (sg `crates/pubsub/src/lib.rs`) | effect |
|---|---|---|
| S1 | `handle_eager_admitted` ~6588 | `add_new_peer_lazy(from)` + `maintain_degree_at` → promote toward **6** |
| S2 | `handle_iwant_admitted` ~6868 | same, when the requester is served from cache |
| S3 | `spawn_degree_maintainer` (30 s) | `maintain_degree` → **6–12** |
| S4 | `set_topic_peers` / `initialize_topic_peers` themselves | after inserting connected peers as lazy, `maintain_degree_at` promotes toward **6** if more than 2 peers are in the topic's lazy/eager sets |

Passing only 2 ids into `set_topic_peers` keeps S4 at 2 **until the next
inbound EAGER or IWANT from a third peer**, or until S3 runs on a topic
that has accumulated lazy peers from those frames. A Leaf subscribed to
global announce/bus will receive those frames continuously. The cap must
live where `maintain_degree_at` reads its bounds, or be re-applied after
every inbound promotion.

### 6.1 Slice 1a — name-map (before / with Winston capture)

No behaviour change. Unblocks §5 on current binaries via this doc; the
runtime field is so the next capture does not need a side script.

1. Land the §5.4 table (this document — **done**).
2. When Rust is written: `GET /diagnostics/gossip` grows
   `subscribed_topics: [{ name, topic_id_hex8 }]` and
   `outbound_by_topic_named` (same rows as `outbound_by_topic` + `name`).
3. Unit test `topic_id_hex8_matches_design_table` pins every row in §5.4
   so a hash/Display change cannot silently break Winston's labels.
4. Inbox ids use the stored `topic_id_by_name` map, not `from_entity(name)`.

Winston does **not** wait on (2)–(4). Use §5.2 + §5.4 now.

### 6.2 Slice 1b — enforce eager degree on **all** paths

**Required mechanism (pick one; do not ship truncate-only):**

**Preferred — saorsa-gossip eager-bound API (small, complete).**

Add instance bounds on `PlumtreePubSub`, defaulting to today's 6/12:

```rust
pub fn with_eager_degree_bounds(self, min: usize, max: usize) -> Self
```

`maintain_degree_at` / `maintain_degree` / opportunistic graft read those
instead of `MIN_EAGER_DEGREE` / `MAX_EAGER_DEGREE`. Then S1–S4 honor Leaf
`max = 2` (min is a **target**, not a floor that invents peers: if only
one plane peer exists, eager size is 1).

x0x: `PubSubManager::new_with_participation` calls
`with_eager_degree_bounds(1, leaf_max)` when Leaf and `leaf_max > 0`.
Full does not call it.

**Also** funnel W1–W5 through **one** helper
(`apply_eager_peer_set(topic, plane)`) that:

- reorders with `select_one_full_bootstrap_eager_peer`
- passes the full connected set (so disconnects still evict)
- never calls `plumtree.set_topic_peers` / `initialize_topic_peers`
  except through that helper

The helper does **not** replace the sg bound. It only stops W3/W4 from
bypassing policy and keeps bootstrap in the 2 slots when maintenance
promotes.

**Fallback if an sg bump cannot ship with slice 1b:** x0x clamp after
every `handle_incoming` that reached PlumTree **and** at the end of the
1 s refresh, demoting eager > N. Acceptance tests in §6.3 **must still
inject inbound EAGER + IWANT + a maintainer tick** and assert fan-out ≤ N.
A clamp that only runs on the 1 s timer is a FAIL (S1/S2 win between
ticks). Document the race and the sg-API follow-up.

`leaf_max_eager_degree = 0` means "do not override sg" — **not** "eager
set empty".

Byte shed stays observe-only (§4.3).

### 6.3 Acceptance tests (unit / in-process — no public mesh)

Name them for the invariant. **A test that only inspects the `Vec` passed
to `set_topic_peers` is not sufficient** (that was the FAIL).

| test | why |
|---|---|
| `topic_id_hex8_matches_design_table` | Slice 1a: §5.4 hex8 values match `TopicId::from_entity` Display. |
| `gossip_diagnostics_maps_outbound_topic_hex_to_subscribed_name` | Hex8 for `x0x/dm/v1/bus` appears with that name once 1a Rust lands. |
| `leaf_eager_bound_is_installed_on_plumtree_not_only_on_x0x_lists` | Construction with `leaf_max_eager_degree = 2` installs sg max=2 (or the clamp hook). Full does not. |
| `leaf_refresh_and_ack_paths_share_one_peer_helper` | W3 (`refresh_subscribed_topic_id`) and W4 (`apply_preferred_eager_peer`) do not call `plumtree.set_topic_peers` directly. |
| `leaf_publish_fanout_stays_at_degree_after_inbound_eager_from_eight_peers` | **Actual outbound:** subscribe; inject 8 `handle_incoming` EAGER frames from 8 peers on that topic; `publish_with_fanout`; `attempted <= 2`. Why: S1 must not grow the set. |
| `leaf_publish_fanout_stays_at_degree_after_iwant_from_extra_peers` | Same after IWANT serve (S2). |
| `leaf_publish_fanout_stays_at_degree_after_degree_maintainer_tick` | Force or wait a `maintain_degree` pass (S3). |
| `leaf_delivery_survives_selected_peer_failure` | Two eager slots, bootstrap preferred. Disconnect slot 0. A subsequent publish is received by a subscriber behind a remaining connected peer (slot 1 or a promoted replacement). `fan_out >= 1` or, if no replacement exists, `zero_fanout` increments and local subscribe still delivers — no panic, no isolated-forever topic. Why: a 2-peer cap must not make "preferred peer died" into "mesh gone". |
| `leaf_both_selected_peers_failed_is_fail_soft` | Disconnect both selected peers and empty the plane: publish returns Ok, `zero_fanout` + warn path, no process death. |
| `full_eager_degree_remains_sg_default` | `--relay` still allows 6–12 after the same inbound EAGER flood. |
| `leaf_max_eager_degree_zero_means_sg_default` | Escape hatch; 0 must not become "zero peers". |
| `partial_toml_leaf_budget_falls_back_to_defaults` | Same class as `partial_toml_section_falls_back_to_defaults`. |
| `leaf_epidemic_bytes_are_not_relay_bytes` | Keep the C0 vs #504 split. |
| `leaf_refresh_topic_peers_skips_unsubscribed_passthrough_topics` | Existing C0 test stays green. |

Do **not** add a live-mesh soak to CI. Document the §5 recipe as the
external gate: Leaf, `Δepidemic_forward_bytes/Δt` after 1b, same peers.

### 6.4 Later slices (not this one)

| slice | what | depends on |
|---|---|---|
| 2 | Fail-soft Bulk shed at hard byte budget, origin-aware (§4.3) | named capture + a meter we can increment in tests |
| 3 | Consume-only / no-forward for global announce on Leaf | sg API or a carefully metered x0x fork; evidence that announce (not the bus) is the top row |
| 4 | #501 `skip_legacy_dm_bus` default-on-Leaf decision | #501 PR + the same capture |
| 5 | Honest HyParView mapping **or** delete dead knobs | independent cleanup; does not close #504 |
| — | #505 ant-quic MTU | other repo; only blocks some measurement hosts |

If slice 1b shipped the x0x clamp fallback, the sg eager-bound API becomes
a 1b-hotfix, not slice 2.

## 7. Success criteria for *this* document

- [x] View-size knobs cited as dead, with files
- [x] Dominant idle paths identified from subscribe sites (not from a live run)
- [x] Operator budget + fail-soft ladder + Leaf vs Full defaults
- [x] Executable Winston/Ben capture (Windows + Unix + hex map +
      `from_entity` recipe)
- [x] First slice covers **all** peer-update and inbound promotion paths,
      with fan-out and selected-peer-failure tests — no two-site truncate
- [x] Name-lookup available **before** asking for a recapture

**Not claimed:** runtime reduction on the public mesh, C0 soak re-run, or
#504 closed. **Not implemented:** any Rust.

## 8. Checkpoint

- Confirmed: `GossipRuntime::new` uses `MembershipConfig::default()`;
  `active_view_size` / `passive_view_size` / `arwl` / `prwl` never leave
  `GossipConfig`.
- Confirmed: Leaf still refreshes and eager-forwards **subscribed** system
  topics; C0 only refuses **unsubscribed** ones.
- Confirmed: sg PlumTree eager degree is hardcoded 6–12;
  `handle_eager` / `handle_iwant` / 30 s maintainer promote toward 6;
  W3/W4 bypass `apply_topic_peers`.
- Unverified: which named topic owns Winston's 1.54 GB. Recipe in §5
  (executable now).
- Left alone: ant-quic (#505), DM-bus default (#501), live soak, Rust.
