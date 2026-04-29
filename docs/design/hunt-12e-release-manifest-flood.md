# Hunt 12e — `x0x/release` manifest flood saturates the PubSub stream

## Status
- **Opened:** 2026-04-29
- **Source:** Live diagnosis during v0.19.9 → v0.19.10 → v0.19.11 release-train rollout to the 6-node bootstrap fleet
- **Severity:** **High** — produces 10 s timeouts in `pubsub.handle_incoming`, hangs `POST /groups` and other publish-touching request handlers past curl timeout (resolved at the request-handler level by the v0.19.11 fix; the underlying flood is still present)
- **Predecessor:** Hunt 12c (per-stream-channel split, shipped in v0.19.5). The split eliminates **cross-stream** head-of-line blocking — Bulk and Membership now drain regardless of PubSub backlog. But the PubSub stream itself can still saturate, which is what we are seeing now.

## What we observed (2026-04-29 ~14:00 UTC, fleet on v0.19.10)

Direct API call from a workstation:

```
$ ssh root@helsinki "curl -m 60 -X POST .../groups <body>"
curl: (28) Operation timed out after 60002 milliseconds
```

Helsinki `journalctl -u x0xd` during the same window:

```
INFO  x0x::gossip::pubsub: [4/6 pubsub] received from PlumTree, decoding
      topic=x0x/release payload_len=11110
INFO  x0x::gossip::pubsub: [4/6 pubsub] received from PlumTree, decoding
      topic=x0x/release payload_len=11110
... (multiple per second) ...
WARN  x0x::gossip::runtime: Timed out handling gossip message
      from=0b7bb5a3b9951f8a bytes=16446 elapsed_ms=10000
      timeout_secs=10 stream_type="PubSub"
WARN  x0x::network: gossip receive channel >80% full — back-pressure
      active available=0 max=10000 stream=PubSub channel="recv_pubsub_tx"
```

Helsinki `/diagnostics/gossip`:

| dispatcher metric | value |
|---|---:|
| `pubsub.received` | 13 576 |
| `pubsub.completed` | 13 267 |
| `pubsub.timed_out` | **308** |
| `pubsub.max_elapsed_ms` | **10 005** |
| `recv_depth.pubsub.latest` | **10 000** (cap) |
| `recv_depth.pubsub.max` | 10 000 |
| `decode_to_delivery_drops` | 0 |
| `incoming_total` | 17 938 |
| `subscriber_channel_closed` | 0 |

Cross-fleet snapshot (backpressure WARNs in the prior 3 min):

```
NYC:        3 588   ← worst
SFO:           19
NUREMBERG:     20
SINGAPORE:     20
SYDNEY:        22
```

Topic-id occurrence count in 2 min on Helsinki (tied to receive log):

```
167 topic=TopicId(378a3991c784ddc5)   ← x0x/release
121 topic=TopicId(8404a8731fd56b98)   ← discovery shard
121 topic=TopicId(f163bc2b9c91c686)
... (long tail of shards) ...
```

## Diagnosis

`x0x/release` is the gossip topic over which every `x0xd` rebroadcasts the
ML-DSA-signed `ReleaseManifest` it received from a peer (or directly from
GitHub). The current rebroadcast policy in `src/bin/x0xd.rs::run_gossip_update_listener`:

```rust
const REBROADCAST_INTERVAL: Duration = Duration::from_secs(300);
let should_rebroadcast = match rebroadcasted_versions.get(&manifest.version) {
    None => true,
    Some(last) => last.elapsed() >= REBROADCAST_INTERVAL,
};
if should_rebroadcast {
    rebroadcasted_versions.insert(manifest.version.clone(), Instant::now());
    // ...
    agent.publish(RELEASE_TOPIC, msg.payload.to_vec()).await;
}
```

So every 5 min, every node rebroadcasts every release manifest it has seen
*regardless of whether that manifest is for an old or already-applied version*.
With three releases live (v0.19.9, v0.19.10, v0.19.11) and 6 fleet nodes,
each broadcasting on a 5 min cadence to ~5 eager peers, the steady-state
rate of `x0x/release` deliveries is:

```
3 versions × 6 senders × 5 eager peers × (1 / 300 s) = 0.3 msg/s
```

That alone is benign. The real problem is the **rebroadcast happens
unconditionally for stale versions** (no `is_newer(&manifest.version, x0x::VERSION)`
check before rebroadcast at line 2548 — the existing check is *after*, only
gating apply, not rebroadcast). Combined with PlumTree's IHAVE/GRAFT lazy-pull
behaviour and a flow of receives from multiple peers, a single node can see
dozens of received-and-rebroadcast cycles per minute when several versions
churn through the cluster simultaneously, at 11 KB–16 KB per message.

`pubsub.handle_incoming` is then taking >10 s per message. Hunt 12c's
per-stream split kept Bulk + Membership healthy (current data: their
`timed_out` is single-digit), but PubSub is wedged. Each timed-out incoming
holds the dispatcher loop for 10 s, so PubSub throughput collapses to
≤6 messages / minute. With incoming gossip arriving faster than that, the
recv channel stays at capacity, and `agent.publish` calls in request
handlers compete for the same congested runtime.

## Goal

Reduce sustained `x0x/release` traffic to a level where `pubsub.timed_out`
returns to 0 across a 90-minute fleet soak even with multiple new versions
pending in a release train.

## Plan

Five mitigations, ordered by impact-per-effort. (1) and (2) are sufficient
to close the user-visible regression and ought to ship in the next patch
release. (3)–(5) are deeper structural improvements.

### M1 — Suppress rebroadcast of versions ≤ self (high impact, low risk)

In `run_gossip_update_listener`, **before** the rebroadcast block, add:

```rust
if !is_newer(&manifest.version, x0x::VERSION) {
    tracing::debug!(
        version = %manifest.version,
        "Already on v{} or newer, skipping rebroadcast",
        manifest.version
    );
    continue;
}
```

Effect: a node currently running v0.19.11 stops rebroadcasting v0.19.9
and v0.19.10 manifests on every receipt. Once the fleet has converged on
the latest version, rebroadcast traffic for stale versions goes to **zero**.
Today the entire fleet keeps relaying old manifests indefinitely.

**Compatibility**: a node still on v0.19.8 will continue to rebroadcast
upward (because v0.19.11 manifest is *newer* than its own version). New
peers joining a converged fleet rely on the GitHub fallback poll
(48 h default, fast-path on startup) instead. That is an explicit,
documented path.

### M2 — Don't republish your own first-broadcast (low impact, trivial)

The startup-path broadcast already publishes once. The gossip-listener then
receives our own publish back (PlumTree round-trip) and rebroadcasts it,
which is wasted work since nobody who sees our copy could have received an
older one from us. Guard the rebroadcast on `manifest_id ∉ self_published`.
Estimated reduction: ~1 broadcast per version per node.

### M3 — Hard cap aggregate `RELEASE_TOPIC` rebroadcast rate (medium impact)

Even with M1 in place, a fleet straddling multiple in-flight versions
during a release train can still produce burst traffic. Add a token-bucket
limiter in the listener: e.g. ≤2 rebroadcasts / minute / version, ≤4
total / minute. Drop excess (log at DEBUG; legitimate peers will receive
via PlumTree from someone else).

### M4 — Switch `RELEASE_TOPIC` to lazy-only push (medium impact, structural)

Today release manifests propagate via PlumTree's eager set — every receiver
forwards immediately. For a topic that is **infrequent + large + not
latency-sensitive**, lazy push (IHAVE / IWANT) is a better fit. We
advertise that we have manifest `M`; a peer pulls only if it hasn't seen
`M` yet. Saorsa-gossip already supports lazy-only topics; gating
`RELEASE_TOPIC` on lazy push reduces wire bytes by ~Nx (N = eager fan-out
size, currently 5).

This requires either:
- a saorsa-gossip API for "subscribe but never eager-broadcast on this
  topic" (small lib change), or
- x0x-side: subscribe locally, but never call `agent.publish(RELEASE_TOPIC, ...)`
  for incoming manifests (rebroadcast becomes opt-in / lazy-only). This is
  a one-line change in the listener and is an acceptable compromise.

### M5 — Trim manifest size (low impact, cheap)

Each `ReleaseManifest` carries 7 platform asset entries (URL + hash + size
+ flags) — ~1.6 KB JSON each. A receiver only ever consumes the entry
matching its own platform; the rest are dead weight on the wire on every
broadcast.

Replace the wire format with a per-platform manifest **plus** a small
"manifest index" (8–16 platform-id → URL pointers, ~500 bytes). On receive,
the daemon pulls only the matching per-platform manifest from the URL in
the index (small targeted HTTP request). Reduces gossip payload by ~10x.

## Validation

| step | metric | target |
|---|---|---|
| Local: 4-daemon harness, simulate 3 versions in flight via test fixtures | `dispatcher.pubsub.timed_out` | 0 over 30 min |
| Local: re-run `tests/e2e_first_message_after_join.sh` after M1 + M2 | 20 / 20 | (unchanged) |
| Fleet: 90 min soak with 3-version release-train fixture | `dispatcher.pubsub.timed_out` per node | 0 |
| Cross-region: existing `/tmp/x0x-cross-region-first-msg.sh` (or its committed equivalent) | 24 / 24 | required |
| Cross-region under simulated release-train: 3 versions broadcast, then run cross-region test | 24 / 24 | required |

## Risks

- **M1**: a node running an older version that has been kept around for
  testing will no longer rebroadcast newer manifests it sees… wait — that
  is exactly the desired behaviour (newer manifest's version > local
  version, so the check passes). Other direction (older manifest into a
  newer node) is the case we are *suppressing*. Need to confirm the
  `is_newer` semantics one more time during implementation.
- **M3**: a token-bucket drop policy could delay manifest propagation on
  a fast-moving release train. Mitigation: GitHub fallback poll already
  catches whatever gossip misses; cap rate but log every drop.
- **M4 / M5**: structural, larger blast radius, want their own Hunts.

## Estimated effort

| mitigation | dev | review | total |
|---|---|---|---|
| M1 | 30 min | 30 min | 1 h |
| M2 | 30 min | 30 min | 1 h |
| M3 | 1 h | 30 min | 1.5 h |
| M4 | 2 h | 1 h | 3 h |
| M5 | 4 h | 2 h | 6 h |

Recommendation: ship **M1 + M2** as `v0.19.12` (combined, ~2 h work) and
re-validate the cross-region first-message test on the fleet. Open
follow-up Hunts 12f / 12g for M4 and M5.
