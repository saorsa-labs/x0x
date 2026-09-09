# Design: Leaf gossip egress budget (issue #504)

- **Status:** Draft for review — **source-and-evidence only**. No runtime
  acceptance is claimed. Revised after PR #534 B1/B2 review and reconciled
  with the concurrent documentation revision `ad33b67`.
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
(`x0x diagnostics gossip --json`):

| kind | bytes | msgs | implied rate |
|---|---|---|---|
| eager | 1.54 GB | 97,744 | ~44 MB/min (~716 KiB/s) |
| ihave | 118 MB | ~20.7k | ~3.4 MB/min |
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

Label a live capture with the **precomputed hex map in §5.3** — do not wait
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
| `x0x.identity.shard.v2.<own>` | compute (§5.3) | own shard only — quieter |
| `x0x.machine.shard.v2.<own>` | compute (§5.3) | own shard only — quieter |
| `x0x.user.shard.v2.<own>` | compute (§5.3) | only if a user key exists |
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
| own inbox | **not** `from_entity(name)` — see §5.3 | should be quiet when idle |
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
| `x0x.directory.{tag,name,id}.*` | compute (§5.3) | only persisted shard subscriptions |
| per-group topic | compute (§5.3) | only for locally known groups |
| `x0x/release` | `378a3991c784ddc5` | only if the upgrade listener is running |

Presence beacons ride `GossipStreamType::Bulk`, not PlumTree EAGER. They are
not Winston's `eager` counter.

### 3.2 Why C0 can be green and wifi still dies

```text
C0 pass:  Δparticipation.relay_bytes / Δt  ≤ 150 KiB/s
#504:     Δparticipation.epidemic_forward_bytes / Δt  ≈ 716 KiB/s
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

64 KiB/s ≈ 3.93 MB/min. Winston's 44 MB/min is ~12× that. Degree 12 → 2 is a
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

# Sustained PlumTree eager-set ceiling for a Leaf; requires the sg hook in §6.1.
# 0 = stock sg degree policy (6–12), not zero peers. Default 2.
leaf_max_eager_degree = 2

# Rolling 60s epidemic (subscribed-topic) outbound. 0 = disabled.
# Slice 1: both thresholds observe-only. Later: metered fail-soft shed (§4.3).
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

**Slice 1 is fan-out-first; both byte thresholds are observe-only.** Count
`egress_budget_soft_exceeded` / `egress_budget_hard_exceeded` and rate-limit
warnings with topic hex, name, priority, origin, and bytes/s. No byte shedding
is authorized by this slice.

A later, explicitly metered shedding policy can consider IHAVE flush and
anti-entropy serve first, then eligible forwarded payloads. Recovery traffic
is not free to discard indefinitely: define retry/delivery bounds and count
attempted, sent, deferred and dropped bytes/messages per topic, priority,
origin and reason before enabling any shed hook.

Bulk-only shedding cannot cover the leading suspects. `classify_x0x_topic`
currently classifies `x0x.identity.announce.v2` and `x0x/dm/v1/bus` as
**Critical**, while `x0x.groups.public.v1` and `x0x.machine.announce.v3` are
**Normal**. Shards, directory, caps and release include Bulk topics; do not
generalize that to all announcements. Shedding the top measured topics may
therefore require an explicit Critical/Normal forwarding policy, with its
own delivery/recovery acceptance and meters. Preserve local-origin publish,
local subscriptions, the node's own inbox and targeted control traffic;
never disconnect to meet a byte budget. Do not silently reclassify topics.

Invalid TOML (hard < soft, or degree outside 0–12): fail-soft to defaults +
a `x0xd --check` warning. Degree 0 is a **valid** escape hatch, not a typo.
Do not refuse process start for a budget typo (the `active_view_size = 0`
restart-loop is the anti-pattern to avoid).

### 4.4 What we will not do in the first implementation

- Full PlumTree rewrite. A minimal saorsa-gossip eager-degree configuration
  hook **is required in slice 1** (§6.1); truncate-only cannot prove the cap.
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
- Confirm `x0x diagnostics gossip --json` → `participation.mode == "leaf"`,
  `reason == "default_leaf"`, `passthrough_refresh_runs == 0`.
- Same workload as #504 if possible: one `public_open` group, no file
  transfers, no extra `x0x subscribe`.
- Note OS, version (`x0x --version` / `/health`), peer count
  (`/health` `peers`, `/diagnostics/transport`), NAT, and whether #501's
  bus skip is on or off (default off).
- Fixed window: **20 minutes** idle after `peers` has been stable for 2
  minutes. Shorter windows (5 min) are ok as a smoke but the #504 number
  was 35 min.

If the CLI or HTTP endpoint returns **401**, export the running daemon's
API token as `X0X_API_TOKEN` and retry: POSIX shells use
`export X0X_API_TOKEN='your-daemon-token'`; PowerShell uses
`$env:X0X_API_TOKEN = 'your-daemon-token'`. Keep the token out of attachments.
Direct HTTP requests need `Authorization: Bearer <token>` too.

### 5.2 Commands

The CLI defaults to Text. Every capture must request `--json`; changing
the filename extension does not change the output format. The helper below
runs `x0x diagnostics gossip --json`, `x0x diagnostics transport --json`,
and `x0x health --json` at both endpoints, preserves their responses and
ranks **t1−t0** topic EAGER bytes. It also supplies the name map (§5.3).

This recipe ships in-repo as `scripts/capture-egress.py` (`--window-secs` /
`--out-dir` flags; extra topic names remain positional). Run it from a new
evidence directory. Requires Python 3 and `x0x` on PATH. Install the BLAKE3
helper and run:

```bash
# macOS / Linux
python3 -m venv .venv
.venv/bin/python -m pip install blake3
.venv/bin/python /path/to/x0x/scripts/capture-egress.py
```

```powershell
# Windows PowerShell (no activation or execution-policy change required)
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install blake3
.\.venv\Scripts\python.exe C:\path\to\x0x\scripts\capture-egress.py
```

```python
import json
import subprocess
import sys
import time
from pathlib import Path
from blake3 import blake3

TOPICS = """
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
x0x/caps/v1/request/targeted-v2
x0x/caps/v1/response/targeted-v2
x0x/announce/v2/blob
x0x.discovery.groups
x0x.groups.public.v1
x0x/announce/v3/blob
x0x/release
""".split() + sys.argv[1:]
def topic_hex8(name):
    # DM inbox names already contain the full raw TopicId, not an entity name.
    prefix = "x0x/dm/v1/inbox/"
    if name.startswith(prefix):
        raw_hex = name[len(prefix):]
        if len(raw_hex) != 64 or len(bytes.fromhex(raw_hex)) != 32:
            raise ValueError("Inbox name must end in its full 32-byte topic hex")
        return raw_hex[:16].lower()
    return blake3(name.encode("utf-8")).hexdigest()[:16]


NAMES = {topic_hex8(t): t for t in TOPICS}
Path("topic-names.json").write_text(json.dumps(NAMES, indent=2), encoding="utf-8")


def snapshot(label):
    result = {}
    for name, args in (("gossip", ["diagnostics", "gossip"]),
                       ("transport", ["diagnostics", "transport"]),
                       ("health", ["health"])):
        raw = subprocess.check_output(["x0x", *args, "--json"], encoding="utf-8")
        obj = json.loads(raw)  # Reject errors/Text output rather than treating as zero.
        if obj.get("ok") is False:
            raise RuntimeError(f"{name} failed: {obj}")
        Path(f"{name}-{label}.json").write_text(raw, encoding="utf-8")
        result[name] = obj.get("data", obj)
    result["epoch"] = time.time()
    result["monotonic"] = time.monotonic()
    Path(f"{label}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def checked_delta(before, after, label):
    if after < before:
        raise RuntimeError(f"Counter reset: {label}; reject/restart window")
    return after - before


a = snapshot("t0")
time.sleep(1200)  # Idle: no publishes or extra subscriptions during this interval.
b = snapshot("t1")
dt = b["monotonic"] - a["monotonic"]
uptime_delta = b["health"]["uptime_secs"] - a["health"]["uptime_secs"]
if dt < 300 or abs(uptime_delta - dt) > 5:
    raise RuntimeError("Restart or invalid timing: reject/restart window")
for sample in (a, b):
    p = sample["gossip"]["participation"]
    if (p["mode"] != "leaf" or p["reason"] != "default_leaf"
            or p["passthrough_refresh_runs"] != 0 or sample["health"]["peers"] == 0):
        raise RuntimeError("Not a usable default Leaf window")
for key in ("epidemic_forward_bytes", "epidemic_forward_msgs", "relay_bytes",
            "relay_msgs", "unsubscribed_refused_frames", "passthrough_refresh_runs"):
    d = checked_delta(a["gossip"]["participation"][key],
                      b["gossip"]["participation"][key], key)
    if key.endswith("_bytes"):
        print(f"{key}: {d / dt / 1024:.2f} KiB/s; {d / dt * 60 / 1e6:.2f} MB/min")
old = a["gossip"]["pubsub_stages"]["outbound_by_topic"]
new = b["gossip"]["pubsub_stages"]["outbound_by_topic"]
rows = []
for topic in old.keys() | new.keys():
    before, after = old.get(topic, {}), new.get(topic, {})
    if topic in old and topic not in new:
        raise RuntimeError("Topic counters disappeared: reject/restart window")
    for kind in before.keys() | after.keys():
        for metric in ("bytes", "msgs"):
            checked_delta(before.get(kind, {}).get(metric, 0),
                          after.get(kind, {}).get(metric, 0), f"{topic}/{kind}/{metric}")
    delta = checked_delta(before.get("eager", {}).get("bytes", 0),
                          after.get("eager", {}).get("bytes", 0), topic)
    rows.append((delta, topic, NAMES.get(topic, "unknown-hex")))
for delta, topic, name in sorted(rows, reverse=True)[:8]:
    print(f"{delta:12d} bytes  {delta / dt / 1024:9.2f} KiB/s  {topic}  {name}")
```

Retain the console output with the JSON. Reject and restart the entire
window on daemon restart, any counter reset/disappearance, CLI failure, or
invalid JSON. A restart can grow counters past t0 again, so nonnegative
deltas alone are insufficient: compare uptime progression with elapsed
time (as above) and confirm daemon continuity from service logs. Endpoint
samples cannot establish mode/peer continuity throughout; discard a run if
logs show a mode change or isolation between samples. A newly appearing
topic may use zero at t0 only within a confirmed uninterrupted run.

Equivalent HTTP: `GET /diagnostics/gossip`, `GET /diagnostics/transport`,
`GET /health`, with the same timing and validation rules.

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

`outbound_by_topic` keys are the **first 8 bytes / 16 hex characters** of
`TopicId` (`Display`), not topic names and not eight hex characters.
sg 0.5.74 derives `TopicId` as BLAKE3 of the exact UTF-8 topic string; the
helper's `hexdigest()[:16]` implements that derivation and writes the map
for every fixed topic listed above. `TopicId::from_entity` is a Rust API,
not an operator CLI command.

Pass exact node-specific identity/machine/user shard strings as extra quoted
helper arguments on either OS. DM inbox ids are an exception: `dm_inbox_topic`
hashes `b"x0x/dm/v1/inbox/" || agent_id_bytes` (`src/dm.rs`), while
`DmInboxService::inbox_topic_name` embeds the resulting **full 32-byte topic
hex** in `x0x/dm/v1/inbox/<topic-hex>`. Pass that actual human-readable name;
the helper extracts its first 16 hex characters instead of hashing it again.
Runtime named diagnostics must likewise use stored topic ids, not rehash
names supplied to `subscribe_topic_id`. Unknown keys remain
`unknown-hex`. Rank by **Δeager.bytes = t1.eager.bytes − t0.eager.bytes**,
never the cumulative t1 count; report Δbytes/Δt beside each row.

Precomputed fixed-topic lookup (also generated by the helper):

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
6. No daemon restart or counter reset; uptime advances by Δt and all compared
   counters are monotonic. Otherwise reject/restart, even if t1 totals exceed t0.
7. Peer count did not collapse to 0 (that would be an #505 / isolation run)

This PR does **not** claim that capture. Platform/soak credit only when
Winston or Ben attach the JSON.

### 5.5 What Ben Mac should add if Winston's host is the only public Leaf

Same recipe on macOS, same window, default Leaf. If both see the same top
topics, the budget can target those names. If they diverge (bus vs announce),
do not ship a Leaf-default `skip_legacy_dm_bus` from this work — keep #501
separate.

## 6. Smallest first implementation slice

**Slice 1 — sustained Leaf eager ceiling + named meters, with a minimal sg
dependency. x0x truncate-only is an experiment; its sustained cap is unproven.**

### 6.1 Mechanism and dependency boundary

sg 0.5.74 can add an unlisted inbound EAGER sender as lazy, then
`maintain_degree_at` promotes toward 6 **before forwarding in that handler**.
The cached IWANT path also adds the requester and maintains degree. A
one-second refresh, or truncation after the inbound handler returns, cannot
undo already emitted frames or prevent concurrent publishers seeing the
expanded set. Therefore option (1), an x0x-only sustained cap, is not
established by the available API. Use option (2): a minimal configurable sg
ceiling is a **slice 1 prerequisite**, not a later optional optimization.
Do not wire HyParView `active_view_size` as an egress fix.

1. **sg dependency (separate implementation/review):** expose an eager-degree
   ceiling per PlumTree instance (or equivalent per-topic policy). Leaf uses
   configured degree D; Full and degree 0 retain stock 6–12. Replace the
   effective `MAX_EAGER_DEGREE` with D and clamp the promotion target to
   `min(MIN_EAGER_DEGREE, D)`. Enforce under the topic-state lock on every
   creation, initialization, refresh, inbound EAGER, cached IWANT, GRAFT and
   repair/maintenance path (including the 30s degree maintainer), before the eager recipients are selected. Audit
   direct promotions and scoring-driven replacements too; none may bypass
   the ceiling. A global constant changed to 2 is unacceptable because it
   would also change Full. Publish/pin the compatible sg release before
   x0x claims a sustained Leaf cap; 0.5.74 alone cannot satisfy this gate.
2. **x0x config:** `leaf_max_eager_degree` defaults to 2, validates
   `== 0 || (1..=12)`; 0 restores stock sg policy, never zero peers.
   Soft/hard byte defaults are §4.2 and remain observe-only.
3. **All four full-plane writers** in `src/gossip/pubsub.rs` must use one
   ordered Leaf selection policy: `apply_topic_peers` (periodic refresh),
   `initialize_topic_peers`, `refresh_subscribed_topic_id` (pre-warm/reverse
   ACK), and `apply_preferred_eager_peer` (ACK preference). This includes
   the initializer call as well as all three direct `set_topic_peers`
   call sites. No full-plane overwrite may bypass policy.
4. **Deterministic ordering:** deduplicate plane ids, sort by full 32-byte
   PeerId, select slot 0 via `select_one_full_bootstrap_eager_peer` with
   stable tie-breaking, then append the remaining sorted ids excluding it
   and truncate to D. Sort any candidate inputs whose order affects the
   helper. The plane originates in a HashMap: preserving its iteration
   order makes slot 1 flap. An unchanged eligible peer set must produce
   identical selections at every writer. On selected-peer failure, remove
   the failed id and choose the next live eligible peer deterministically;
   retain access to the full plane as replacement candidates. The sg
   ceiling must survive inbound expansion between x0x refreshes; maintenance
   may replace a selected peer but may never enlarge the eager set past D.
5. **Diagnostics:** add `subscribed_topics: [{name, topic_id_hex8}]`, named
   outbound rows and `egress_budget` limits, current 60s rate and exceed
   counts. Keep repair sends separately identifiable. No hard-byte shedding
   in slice 1, regardless of the top topic's priority.

The degree invariant bounds unsolicited eager publish/epidemic fan-out
per forwarding event to D. Cached IWANT replies are solicited recovery
traffic, including to non-selected peers; a ceiling alone does **not** bound
all outbound bytes or the lifetime recipient count of a message repaired
to multiple requesters. Meter those replies separately and include them in
the §5 total byte window. Do not claim a hard byte budget from a degree cap.

### 6.2 Acceptance tests (unit / in-process — no public mesh)

Use the real sg handlers and an outbound transport recorder; a mock proving
only the vector passed to `set_topic_peers` is insufficient. These are
**required future gates**, not tests run or runtime credit for this document.

| test / scenario | required evidence |
|---|---|
| All four writers, D=2, ≥8 plane peers | Initialization, repeated periodic refresh, DM pre-warm/reverse ACK refresh and preferred ACK refresh all preserve the cap. Record actual eager recipients for local publishes and unique subscribed inbound messages: fan-out ≤ D on every event. |
| EAGER from non-selected peers | Deliver successive unique EAGER payloads from multiple unlisted peers between refreshes and interleave publishers. Real inbound promotion/maintenance must keep eager degree ≤ D and outbound epidemic fan-out ≤ D, including before the next refresh; local subscribed delivery continues. |
| Cached IWANT from non-selected peers | Populate cache, issue IWANT from multiple non-selected peers, observe successful solicited recovery replies separately, then publish/forward new messages before refresh. Actual eager fan-out remains ≤ D despite repair promotion. Repeat after refresh and GRAFT/maintenance. |
| Deterministic remainder | Permute identical HashMap-derived plane/candidate inputs across every writer. Slots 0 and 1 remain identical; prefer an eligible Full/bootstrap in slot 0. Cover no preferred peer, ties and duplicates. |
| Selected-peer failure | Disconnect one selected peer, then both; with other live plane peers available, refresh/repair selects replacements without transient cap escape. Within a declared bounded in-process timeout, local subscribers receive new messages and recover a deliberately missed cached message via IHAVE/IWANT. Record delivery plus outbound sends, not just set size. |
| Full and escape hatch | Full passes the full plane and retains sg 6–12 behavior even with Leaf config present; Leaf D=0 restores stock behavior. Cover D=1, 2, 12 and partial/invalid TOML fallback without isolation or restart-loop. |
| Named diagnostics and participation | Map DM bus hex8 to its name; retain the epidemic-vs-relay split and existing Leaf unsubscribed refusal tests. Exceed byte thresholds without shedding in slice 1. |

If the sg prerequisite or these tests are absent, label any x0x truncation
build **experimental: sustained cap unproven**. Do not call it the #504 fix.
No public-mesh soak in CI: §5 remains the external before/after Leaf gate,
with comparable peers/workload and recovery evidence, distinct from C0.

### 6.3 Later slices (not this one)

| slice | what | depends on |
|---|---|---|
| 2 | Fail-soft byte shedding, including explicit Critical/Normal forwarding policy if needed | named capture + per-topic/origin/priority meters + delivery/recovery gates |
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
