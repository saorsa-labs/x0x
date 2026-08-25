# #380 Phase C0 soak gate — forwarded KB/s collapse

C0 is **blocking for #380**. It is **not sufficient alone to close durable**
DM (ACK hedge / Direct pre-warm / raw QUIC remain out of scope).

## What C0 changes

A Leaf desktop still skips pass-through `set_topic_peers` (#395). That is
not enough: inbound EAGER / IHAVE / IWANT create PlumTree topic state and
local GRAFT, then eager-forward. C0 refuses those frames for topic ids the
Leaf does not subscribe to. Full / backbone nodes are unchanged.

GRAFT is not a wire `MessageKind`. saorsa-gossip piggybacks tree repair on
EAGER / IHAVE / IWANT. Refusing those frames **is** refusing GRAFT.

## Meter: `relay_bytes` means non-subscribed forward

saorsa-gossip 0.5.74 `pubsub_stages.outbound_publish_origin.relay_bytes` is
an **origin** split: local publish vs everything else. That mis-labels
subscribed-topic epidemic as relay.

C0 soak **must not** use that field. Use `GET /diagnostics/gossip` →
`participation`:

| field | meaning |
|---|---|
| `relay_bytes` | outbound on topics this node does **not** subscribe to |
| `epidemic_forward_bytes` | subscribed-topic epidemic forward |
| `relay_bytes_semantics` | always `"non_subscribed_forward"` |
| `unsubscribed_refused_frames` | inbound GRAFT-equivalent / eager / IHAVE / IWANT / anti-entropy dropped |
| `unsubscribed_refused_graft_equiv` | EAGER / IHAVE / IWANT subset (the GRAFT path) |
| `passthrough_refresh_runs` | still `0` on Leaf |

## Baseline

Exclusive Phase B idle Mac ↔ studio1: **~1500 KB/s** forwarded
(`relay_bytes` under the old origin meter). Almost all of that was
pass-through on ~150 unsubscribed topics.

## Pass (Leaf desktop, ≥5 min idle soak, same peers)

1. `participation.mode == "leaf"`
2. `participation.passthrough_refresh_runs == 0`
3. `participation.unsubscribed_refused_frames` increases (inbound refuse is live)
4. Corrected forwarded rate drops **≥90%** vs the 1500 KB/s baseline:

```text
rate_kB_s = (Δparticipation.relay_bytes / Δt_seconds) / 1024
pass      = rate_kB_s <= 150
```

Sample `/diagnostics/gossip` at t0 and t1 (≥300 s). Use only the
`participation.relay_bytes` delta, not `outbound_publish_origin.relay_bytes`.

Full / `--relay` / seed / `:443` / managed `/opt/x0x/x0xd*` nodes are not
gated; their `relay_bytes` may stay high.
