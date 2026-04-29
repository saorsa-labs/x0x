# Hunt 12f — stale release manifests still back-pressure PubSub after M1/M2

## Status
- **Opened:** 2026-04-29
- **Source:** v0.19.12 live-fleet validation after Hunt 12e M1/M2 shipped
- **Severity:** High — cross-region first-message-after-join remained 0 / 24 on the live 6-node fleet
- **Predecessor:** Hunt 12e (`x0x/release` manifest flood); v0.19.12 stopped rebroadcasting stale manifests but did not drain the subscriber fast enough under an already-saturated fleet.

## What happened on v0.19.12

`tests/e2e_deploy.sh` successfully rolled v0.19.12 to all six bootstrap nodes:

| node | version | connected peers |
|---|---:|---:|
| NYC | 0.19.12 | 8 |
| SFO | 0.19.12 | 7 |
| Helsinki | 0.19.12 | 6 |
| Nuremberg | 0.19.12 | 6 |
| Singapore | 0.19.12 | 9 |
| Sydney | 0.19.12 | 9 |

The cross-region acceptance harness still failed:

```text
/tmp/x0x-cross-region-first-msg.sh
SUMMARY: total=24 pass=0 fail=24
```

Fleet diagnostics before/after that run showed PubSub was still saturated:

| node | pre pubsub timed_out | pre recv_pubsub_latest | post pubsub timed_out | post recv_pubsub_latest |
|---|---:|---:|---:|---:|
| NYC | 0 | 10000 | 0 | 10000 |
| SFO | 24 | 3774 | 101 | 9998 |
| Helsinki | 4 | 10000 | 48 | 10000 |
| Nuremberg | 3 | 10000 | 49 | 10000 |
| Singapore | 1 | 0 | 74 | 10000 |
| Sydney | 0 | 9999 | 3 | 10000 |

## Diagnosis

M1/M2 were correct but incomplete for a fleet that was already wedged:

1. The release listener still decoded, parsed, **verified the ML-DSA signature**, and only then reached the v0.19.12 stale-version skip. Under thousands of queued old manifests (`v0.19.3`, `v0.19.5`, `v0.19.7`, `v0.19.9`), the release subscriber could not drain fast enough, so `pubsub.handle_incoming` still blocked on subscriber delivery and hit the 10 s watchdog.
2. The failed cross-region harness had accumulated many `xreg-*` public groups on the fleet. The daemon's default 15 s discoverable group-card republish loop then added `x0x.discovery.groups` traffic on top of the release backlog. That is not the original Hunt 12e root cause, but it is a live-fleet amplifier.

Recent NYC topic counts over 3 minutes after the failed v0.19.12 run:

```text
348 x0x/release
174 x0x.discovery.groups
144 x0x.machine.announce.v2
 96 x0x.identity.announce.v2
```

## Fixes

### 12f.1 — Fast-drop stale release manifests before signature verification (v0.19.13)

Parse the signed manifest JSON to read the version immediately after length-prefix decode. If `manifest.version <= x0x::VERSION`, return without ML-DSA verification, timestamp validation, rebroadcast, or upgrade apply. Signature verification remains mandatory before acting on any newer manifest.

This preserves the security invariant: unverified stale manifests are ignored, never applied and never rebroadcast.

### 12f.2 — Reduce default discoverable group-card republish cadence (v0.19.13)

Increase the default periodic group-card republish interval from 15 s to 300 s. Group creation/join still publishes immediately on the state-changing path; the periodic loop is only an anti-entropy safety net for late joiners. This reduces fleet PubSub background traffic when test groups accumulate.

### 12f.3 — Delay best-effort group fan-out behind first user messages (v0.19.14)

v0.19.13 improved the live-fleet result from **0 / 24** to **17 / 24**. The
remaining misses were not permanent loss: manual polling minutes later showed
the message cached on every failed joiner. The problem had shifted from
"dropped" to "delayed beyond the 5 s cross-region grace window".

The remaining delay aligned with group create/join background fan-out:

- creator `POST /groups` spawned discovery-card fan-out to the global topic and
  shard topics immediately;
- creator `POST /groups` spawned a chat `created` announcement immediately;
- joiner `POST /groups/join` spawned a chat `joined` announcement immediately;
- then the harness published the first public message and polled 5 s later.

Those discovery/chat publishes are best-effort anti-entropy. They do not need
to precede the first user message. v0.19.14 delays them by 8 s while keeping
local group state and both required listeners installed before the HTTP
response returns.

### 12f.4 — Stop identity/machine announcement feedback loops (v0.19.15)

After v0.19.14 was deployed and the accumulated `xreg-*` test groups were
pruned, fleet diagnostics still saturated within minutes. Topic samples over
two minutes showed the residual pressure had moved to identity anti-entropy,
not release manifests or group cards:

```text
781 x0x.machine.announce.v2
739 x0x.identity.announce.v2
 37 x0x/caps/v1
 11 x0x.discovery.groups
  3 x0x/release
```

Root cause: `start_identity_listener` re-published verified identity, machine,
and user announcements every 20 s for the same `(id, announced_at)` key. PubSub
v2 re-signs each publish with a fresh message ID, so PlumTree's message-ID
dedup cannot suppress the repeat forward. On a six-node bootstrap mesh this
formed a feedback loop: every daemon repeatedly re-forwarded already-forwarded
anti-entropy payloads and pinned `recv_depth.pubsub.latest` at 10 000.

v0.19.15 changes discovery-announcement re-broadcast to **one-shot per
`(id, announced_at)` key per daemon** and restores the default identity
heartbeat interval to 300 s. Heartbeats remain safely inside the 900 s TTL, and
each fresh heartbeat still gets one epidemic re-broadcast for convergence.

### 12f.5 — Stable global fallback for first SignedPublic messages (v0.19.16)

v0.19.15 made the PubSub dispatcher healthy (`pubsub.timed_out = 0`,
`recv_depth.pubsub.latest = 0`) but live acceptance still missed **4 / 24**,
all in the Sydney → Helsinki direction. The misses were permanent: Sydney had
cached each first message locally, while Helsinki's message cache stayed empty.
Helsinki's per-group listener had subscribed several seconds before each send,
so the residual failure was not listener startup or queue drain; it was
asymmetric reachability of brand-new per-group PubSub topics.

v0.19.16 keeps the normal per-group topic (`x0x.groups.public.<group_id>`) and
adds a long-lived fleet-wide fallback topic, `x0x.groups.public.v1`. Every
daemon subscribes to the fallback at startup. Senders publish each SignedPublic
message to both topics; receivers validate/cache only messages whose group is
known locally. This gives first-message delivery a stable PubSub tree while
retaining per-group topics for steady-state fan-out.

## Validation plan

1. Local quality gates:
   - `cargo fmt --all -- --check`
   - `cargo clippy --all-targets --all-features -- -D warnings`
   - `cargo nextest run --all-features --workspace`
   - `bash tests/e2e_first_message_after_join.sh`
   - `bash tests/e2e_comprehensive.sh`
2. Release and deploy v0.19.16.
3. Clean up accumulated `xreg-*` test groups on the fleet (test artefacts, not product state).
4. Confirm `x0x.identity.announce.v2` / `x0x.machine.announce.v2` topic counts stay low-rate, `x0x.groups.public.v1` is present but not saturating, and `recv_depth.pubsub.latest` drains below saturation.
5. Re-run `/tmp/x0x-cross-region-first-msg.sh`; target remains 24 / 24.

## Follow-up if v0.19.16 is still insufficient

If PubSub remains saturated or first-message latency remains above the 5 s grace window after stale-release fast-drop, group fan-out delay, discovery re-broadcast one-shot dedup, stable global SignedPublic fallback, and test-group cleanup, the next mitigation is a real PubSub admission control path for known low-priority topics (`x0x/release`, discovery anti-entropy, identity anti-entropy), preferably before subscriber-channel enqueue. That likely belongs in a separate Hunt because it touches topic prioritisation rather than release-manifest policy.
