# Hunt 12c — PubSub handler stall under sustained fleet load

## Status
- **Opened:** 2026-04-27
- **Source:** Fleet evidence from `proofs/fleet-hunt12b-80ee753-20260427T153807Z/`
- **Severity:** Medium — degrades over hours, does not block Hunt 12b's user-visible fix
- **Predecessor:** Hunt 12b (presence collapse) — fixed in commit `80ee753`, released as `x0x v0.19.4` + `saorsa-gossip v0.5.23`

## What we observed

During the 90-minute fleet validation of `80ee753`, all four nodes
(saorsa-2/3/6/7) started accumulating PubSub-handler timeouts in a
coordinated burst around tick 73 (~85 min into the run).

| Node | Final `ps_timed_out` | Final `ms_timed_out` | `recv_depth_max` peak | Online drift |
|------|---:|---:|---:|---|
| saorsa-2 (NYC, DigitalOcean) | **129** climbing +6/min | 20 | **4729** (47% of 10000-slot cap, holding) | 6 → 4 at tick 73 |
| saorsa-3 (SFO, DigitalOcean) | 26 (last 5 min) | 0 | 265 | 6 → 5 at tick 73 |
| saorsa-6 (Helsinki, Hetzner) | 20 | 3 | 101 | 6 → 5 at tick 75 |
| saorsa-7 (Nuremberg, Hetzner) | 34 (last 5 min) | 0 | 425 | 6 → 5 at tick 73 |

`/presence/online` never dropped below `N-1` during the run, so the
Hunt 12b user-visible regression remains fixed.

## Smoking-gun journal entries (saorsa-2)

```
17:00:06 WARN x0x::gossip::runtime: Timed out handling gossip message
         from=6a24bdeddd828e1e bytes=16056 elapsed_ms=10001
         timeout_secs=10 stream_type="PubSub"
17:00:16 WARN ... from=6a24bdeddd828e1e bytes=16056 elapsed_ms=10001 ... PubSub
17:00:26 WARN ... from=6a24bdeddd828e1e bytes=16056 elapsed_ms=10001 ... PubSub
... (every 10 s, same peer, same byte count, same exhausted timeout) ...
17:02:11 WARN ... from=dc090fd3d05888a3 bytes=2 elapsed_ms=5001 ... Membership
```

Cross-node corroboration:

- **saorsa-7** logs show repeated `WARN saorsa_gossip_pubsub: IWANT for
  unknown message msg_id=...` — its lazy pull is asking for messages
  that have already been evicted from the upstream node's cache.
- **saorsa-3 / saorsa-6** show ant-quic
  `kind="peer_event_tx_lifecycle" error=channel closed` warnings — the
  per-peer event broadcast subscribers are not draining fast enough.
- **saorsa-6** shows NAT traversal phase-sync expiry and 12 s direct-dial
  timeouts — symptoms of upstream coordinator (saorsa-2 in this fleet)
  not responding promptly.

## Diagnosis

The new `GossipDispatchStats` instrumentation in `src/gossip/runtime.rs`
(commit `80ee753`) lit up exactly the architectural bottleneck named
in the original Step 2 plan:

> The gossip runtime dispatcher is a single `tokio::spawn` loop with one
> `recv_rx`. All three stream types (PubSub, Membership, Bulk) are
> handled serially in one `match` arm. If `pubsub.handle_incoming`
> blocks for 10 s on one peer's message, every subsequent message on
> any stream type sits in `recv_tx` until that handler returns. The
> per-arm timeout limits the damage but does not eliminate the
> head-of-line blocking — back-pressure still flows up to the network
> receiver.

Saorsa-2 is the most loaded node (smallest spec, busiest peer set), so
it manifests the symptom first. Once it slows down, IHAVE/IWANT
exchanges with the rest of the fleet degrade because saorsa-2 cannot
serve cached messages fast enough — hence the `IWANT for unknown`
warnings on saorsa-7 and the channel-closed warnings elsewhere.

The single peer `6a24bdeddd828e1e` repeatedly sending 16,056-byte
PubSub messages is a separate diagnostic question (Hunt 12c-prelude)
and may turn out to be a stale daemon, a NAT-traversal probe, or a
specific x0x feature that emits exactly that payload size every 10 s.
**It is not the root cause** — the root cause is that the dispatcher
has no isolation between stream types. A different busy peer would
trigger the same pattern.

## Goal

Eliminate cross-stream head-of-line blocking in the inbound gossip
pipeline so that:

1. A slow `pubsub.handle_incoming` cannot delay `Bulk` presence
   beacons or `Membership` SWIM ping-acks.
2. A single misbehaving peer's PubSub messages do not back-pressure
   the entire `recv_tx` queue and stall the network receiver task.
3. `dispatcher.{pubsub,membership,bulk}.timed_out` stays at 0 over a
   full 90-minute fleet soak under organic load.

## Plan — Step 2 from the original Hunt 12b writeup

Three structural changes in `src/network.rs` and `src/gossip/runtime.rs`:

### 2.1 Split the receive channel by stream type

```rust
// src/network.rs — replace the single recv_tx
recv_pubsub_tx:     mpsc::Sender<(AntPeerId, Bytes)>,  // cap 10_000
recv_membership_tx: mpsc::Sender<(AntPeerId, Bytes)>,  // cap  4_000
recv_bulk_tx:       mpsc::Sender<(AntPeerId, Bytes)>,  // cap  4_000
```

The existing `spawn_receiver` task fans out into the three channels
based on `GossipStreamType`. Each channel gets its own `>80% full`
back-pressure WARN, mirroring the current pattern.

### 2.2 Three independent dispatcher loops

```rust
// src/gossip/runtime.rs — replace the single tokio::spawn loop
let pubsub_handle     = tokio::spawn(pubsub_dispatcher_loop(...));
let membership_handle = tokio::spawn(membership_dispatcher_loop(...));
let bulk_handle       = tokio::spawn(bulk_dispatcher_loop(...));
```

Each loop pulls only from its own channel and runs its handler under
the per-arm timeout already in place. `GossipDispatchStats` continues
to track per-stream counters; new field `recv_depth_*` becomes a
tuple `{pubsub, membership, bulk}`.

### 2.3 `GossipTransport::receive_message` — biased select

The downstream `receive_message` API stays as a single async stream
over all three channels via `tokio::select!`, but with `biased;` and
`Bulk` first so presence beacons drain ahead of PubSub backlog.

## Validation

1. Local: extend `tests/e2e_presence_propagation.sh` to add a
   background PubSub publish load (~10 msg/s on an unrelated topic on
   one node). Pre-fix: presence-online stays healthy (current
   behaviour). Post-fix: `dispatcher.pubsub.timed_out` may climb under
   pathological load on the loaded node, but `bulk.timed_out` and
   `membership.timed_out` stay at 0.
2. Fleet: re-run the 90-min soak from Hunt 12b on saorsa-{2,3,6,7}.
   Pass criterion: `dispatcher.{pubsub,membership,bulk}.timed_out`
   stays at 0 on every node for the full 90 min.

## Risks

- **API surface change**: `GossipDispatchStatsSnapshot.recv_depth_*`
  becomes structured rather than scalar; any external consumer of
  `/diagnostics/gossip` needs to handle both shapes during the
  transition. Likelihood: low (only the x0x CLI consumes this).
- **Back-pressure shape change**: today, a slow PubSub handler
  applies back-pressure to the entire receiver. After the split,
  Membership and Bulk continue to flow even when PubSub is wedged. If
  any code anywhere depends on the cross-stream coupling (it
  shouldn't), this surfaces.

## Pre-fix mitigation

The 6a24bdeddd828e1e/16056-byte/10s pattern smells like a single
misbehaving (or simply slow) peer. As a parallel investigation:

- Identify the peer (cross-reference machine_id with
  `/agent/card` lookups across the fleet).
- Determine what message PubSub topic is producing 16,056-byte
  payloads on a 10s cadence (is it a known x0x publisher, or a
  forwarded message from the wider network?).
- If it is a stale or incompatible peer, blocklist via
  `ContactStore` `TrustLevel::Blocked` until investigated. This is a
  workaround, not a fix — Step 2 is still the right structural
  answer.

## Estimated effort

- Step 2.1 + 2.2 + 2.3: 4–6 hours
- Local soak harness extension: 1 hour
- Fleet re-soak: 90 min wall clock
- Code review + commit: 1 hour

Total: half a day of focused work plus the soak window. Targeted for
x0x v0.19.5 or v0.20.0 depending on size of accompanying changes.
