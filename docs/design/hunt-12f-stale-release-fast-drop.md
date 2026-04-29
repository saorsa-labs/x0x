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

## Fix for v0.19.13

### 12f.1 — Fast-drop stale release manifests before signature verification

Parse the signed manifest JSON to read the version immediately after length-prefix decode. If `manifest.version <= x0x::VERSION`, return without ML-DSA verification, timestamp validation, rebroadcast, or upgrade apply. Signature verification remains mandatory before acting on any newer manifest.

This preserves the security invariant: unverified stale manifests are ignored, never applied and never rebroadcast.

### 12f.2 — Reduce default discoverable group-card republish cadence

Increase the default periodic group-card republish interval from 15 s to 300 s. Group creation/join still publishes immediately on the state-changing path; the periodic loop is only an anti-entropy safety net for late joiners. This reduces fleet PubSub background traffic when test groups accumulate.

## Validation plan

1. Local quality gates:
   - `cargo fmt --all -- --check`
   - `cargo clippy --all-targets --all-features -- -D warnings`
   - `cargo nextest run --all-features --workspace`
   - `bash tests/e2e_first_message_after_join.sh`
   - `bash tests/e2e_comprehensive.sh`
2. Release and deploy v0.19.13.
3. Clean up accumulated `xreg-*` test groups on the fleet (test artefacts, not product state).
4. Re-run `/tmp/x0x-cross-region-first-msg.sh`; target remains 24 / 24.

## Follow-up if v0.19.13 is still insufficient

If PubSub remains saturated after stale-release fast-drop and test-group cleanup, the next mitigation is a real PubSub admission control path for known low-priority topics (`x0x/release`, discovery anti-entropy, identity anti-entropy), preferably before subscriber-channel enqueue. That likely belongs in a separate Hunt because it touches topic prioritisation rather than release-manifest policy.
