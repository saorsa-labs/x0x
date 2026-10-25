# A14 Health Updates and Recovery

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-21
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These slots remain Proposed (D198, D199). David accepted the archive transfer on 10 October 2026. [docs/adr/README.md](../README.md) and [docs/adr-archive/move.json](../../adr-archive/move.json) record that acceptance. Replacement acceptance and clause-level transfer checks are still open. Use the [index and transition rules](README.md) to interpret their status.

x0x must remain recoverable when an update fails. Agents can help maintain a node, but update safety must also work when no agent is available.

## Context

x0x distributes signed release information and can update the daemon. An update affects executable files, persisted state, process supervision and sometimes several local instances.

A downloaded file, successful process start or healthy API response proves only one part of a safe update.

Today a daemon with updates disabled does not verify or record `x0x/release` manifests. Checked on `main` `125db4c5`. All three gates are in `src/server/mod.rs`: the startup GitHub check (L1883–L1885), the gossip listener (about L1983), and the fallback poll (L2029–L2034). The startup check and the fallback poll stay off unless `self_update_enabled` and `[update] enabled` are both true. The gossip listener also requires `config.update.gossip_updates` (about L1983). The proposed section below starts verify-only listening for notify-only daemons when `[update] gossip_updates` is true. `[update] gossip_updates = false` turns that subscription off. The topic stays `x0x/release`. A failed staging-identity init is a different case. Updates stay enabled, discovery continues, and apply stays off (`docs/upgrade-system.md` L94–L96).

## Decision

We will keep maintenance under owner policy. The owner sets allowed channels, timing, rollout limits and actions. Agents can inspect health, request an allowed update, hold, roll back and report a problem within that policy.

Maintenance agents do not receive release-signing authority. Human-controlled release and authority changes retain their required approvals.

The daemon verifies release evidence before staging an update. The exact tested dependency graph and artifact hashes must identify the released bytes.

A signed release is not proof that its behavior is safe. Verification and deployment evidence are separate gates.

## Health

Health reports must state which services and invariants were checked. Distinguish process alive, API serving, transport connected, group usable and application work ready.

Use typed degraded and blocked states. Do not report healthy merely because one HTTP handler responds.

Diagnostic data for the owner should identify the failed condition and the permitted recovery action. Reports to maintainers are opt-in and must remove secrets and unrelated private data.

## Safe apply

Resolve who owns process restart before changing installed files. The old daemon records the intended executables, paths, arguments, data roots and supervisor behavior.

Use a host-level lock and durable transaction state. Prevent two daemons that share an executable from applying conflicting updates.

Verify and probe the candidate before replacement. Keep the exact old bytes needed for recovery. Record each file replacement and restoration; replacing a daemon and CLI is not one atomic filesystem operation.

Preserve the ability to start the previous release with the supported data state. [A15](A15-r01-compatibility-validation-and-decision-rules.md) owns the compatibility requirement.

After the old process exits, an independent launcher or supervisor must be able to restore service. A broken candidate cannot be the only component responsible for repairing itself.

## Rollout and authority

Separate build, signing, publication, canary deployment and wider rollout. Each step needs its own evidence.

Ring and canary enforcement, recall and wider maintenance policy are separate from local safe apply. Do not claim those features merely because local rollback works.

No automatic action may widen owner policy or bypass a release hold.

## Consequences

Updates can be checked and recovered under owner policy. Independent rollback and exact artifact evidence add release work. A successful publication alone cannot prove that deployed devices are healthy.

## Alternatives

Letting the new binary restore itself is simple, but fails when it cannot start.

Treating a signed manifest as the only release gate protects authenticity but does not establish compatibility or service recovery.

## Current implementation

Signed updates, diagnostics and an unsupervised restart helper exist. Supervised updates request a restart but do not arm automatic rollback. The apply lock is local to one daemon process, not host-wide. M2 safe apply and the complete owner-governed maintenance system remain incomplete.

## Validation

Test corrupt downloads, invalid signatures, failed probes, disk errors, power loss at transaction boundaries, failed boot and supervisor restart.

Verify recovery with shared binaries and retained data. Record the exact build, host, supervisor and test evidence. A local pass does not close the fleet rollout gate.

## Matters to settle

Keep the current M2 work and release authority intact. D182–D195 in the
[design rulings digest](../../design/x0x-direction.md#5-decisions-d01d200)
resolve ADR 0094's open values: manifest clock skew, rollout windows and bypass,
the prerelease ban, probe and boot limits, fault classes, retries, holds,
health checks, recovery material and SKILL.md timing. These rulings govern
M2 code; they neither rewrite immutable ADR 0094 nor prove implementation.
Preserve each ruling in the [transfer map](TRANSFER.md#rulings).

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0026 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0026-managed-x0xd-deployment.md) · [ADR 0045 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0045-decentralized-self-update.md) · [ADR 0053 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0053-api-unserved-watchdog.md) · [ADR 0061 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0061-supervised-upgrade-restart-ownership.md) · [ADR 0094 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0094-m2-safe-apply.md) · [ADR 0096 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0096-r12-x0x-is-maintained-by-its-own-agents.md)

Decision source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Implementation checked on 12 October 2026 at commit `8cb6488331e6c1226913104ddb99ca4ec18bec37`.

## Upgrade delivery and signalling

**Status: Proposed (not accepted). David approved the local API names on 21 Oct 2026, 13:55 BST.**

Date: 2026-10-21. Wire change: none. The `x0x/release` topic, framing, key and signature context stay the same. Owner-sync records stay the same. Release manifests already require `version` (`ReleaseManifest.version` at `src/upgrade/manifest.rs:21`). David's 20 Oct 2026 ruling on #1383 keeps the version and policy digest off signed machine announcements.

The public API change is additive and local. It adds `disposition`, `state` and `cli_status` on `GET /diagnostics/upgrade` and on the local `this_machine` object of `GET /owner/machines`, one `/health` reason, a non-zero `x0x doctor --json` exit where updating is expected, and one local event. Remote census rows stay as they are. David's 20 Oct rulings on #1383 and #1384 cover the local version-policy digest and the still-null embedder minimum. David approved every local API name in this section on 21 Oct 2026, at commit `ea211b23`. The approval covers `cli_status`, the `UpdateState` list including `NotChecked`, `due_in_secs`, `blocked_by`, the `/health` reason `update_behind`, the event `system.update_behind`, and the non-zero `x0x doctor --json` exit on `Behind` where updating is expected.

Checked against `main` commit `125db4c5` on 21 Oct 2026.

### Problem

Daemons run old builds and nobody notices. Worked example: a daemon stays on an older release while a newer signed release exists. `--skip-update-check` has turned self-update off, so the daemon never applies the release. A person notices only by reading the version. Under this design the daemon records `behind_since` from the first signed release manifest it verifies. It stays `Waiting` until `[update] behind_after_days` passes. The default is 14 days. Then it shows `Behind` on its own `/health`, with reason `update_behind`, and `x0x doctor --json` exits non-zero. This daemon is `NotifyOnly(SkippedThisRun)`, so updating was expected.

How releases reach users is mostly settled already:

1. Signed manifests travel over gossip topic `x0x/release` (ADR 0045). GitHub is where releases are first found, with a fallback poll every 48 h by default. That interval is the code default of 2880 minutes in `src/server/state.rs`. The poll comment is `src/server/mod.rs` L2029. ADR 0045 states the topic and the GitHub fallback.
2. Each machine waits a delay salted by MachineId and version, inside a 60-minute window. The version salt is `StagedRollout::calculate_delay_for_version` in `src/upgrade/rollout.rs`. Fleets cannot go below 60 minutes (`FLEET_MINIMUM_MINUTES` in `src/upgrade/fleet_policy.rs`, D183, D184).
3. Probe, hold, retry and recovery limits are set (ADR 0094, D185–D195). An authenticated `now=true` apply skips the wait but not the checks (D185).
4. Recall is specified and waits on M2 (#1176). Owner policy and canary rings are M4.

What is missing is a signal for the machines that do not auto-update. Today an install can stop moving and give no behind signal:

- The default embed path leaves self-update off. `serve()` sets `ServeOptions.self_update_enabled` to false and `skip_update_check` to true (`src/server/mod.rs` L414–L420). While that effective flag is false, the startup GitHub check (L1883–L1885), the `x0x/release` listener (about L1983), and the fallback poll (L2029–L2034) stay off. The gossip listener also requires `config.update.gossip_updates` (about L1983). An embedder opts in through `serve_with_options` by setting `ServeOptions.self_update_enabled` true (README L380; the field is `src/server/state.rs` L131). `effective_self_update_enabled` also requires `skip_update_check` false (`src/server/state.rs` L134–L138). That opt-in already applies like a normal install.
- `update.enabled = false` or `--skip-update-check` turns off apply. The skip flag is not persisted (`ServeOptions::skip_update_check` in `src/server/state.rs`).
- Managed Windows apply is REFUSED under M2 (ADR 0094, Decision).
- A durable hold, an undersized fleet receipt, or an unresolved selection or journal record refuses apply. The old binary keeps running and reports nothing unless asked. Receipts and unresolved selection or journal records are `docs/upgrade-system.md` L54–L86. Durable probe holds are L124–L149.
- A split or package-managed CLI outside the declared install stays outside the upgrade transaction (ADR 0094, host transaction). The daemon can still update itself. That CLI is reported not upgraded, with reinstall guidance.

`GET /diagnostics/upgrade` already exists. It returns the local version, the update policy and the version-policy digest. The body has no `disposition`, `state` or `cli_status` field (`src/server/routes/network.rs`, `upgrade_diagnostics`). The health verdict leaves an available update as `ok` (`src/server/health_verdict.rs` L897–L899). `x0x doctor` reads that route and treats a body with no `update_available` as up to date, so the process exits zero (`src/cli/commands/daemon.rs`, `check_upgrade_state`). `GET /owner/machines` exists. `this_machine` carries this daemon's version and digest (`src/server/routes/owner.rs` L789). Remote rows have no version field (L779).

The silent case is an install that cannot or will not take the update. Auto-update, notify-only and staged rollout are separate choices.

### Options

1. **Status quo.** Auto-update plus the 60-minute stagger, with nothing else. Drift stays silent.
2. **Notify-only everywhere.** Safer against bad releases, but every install drifts until a human acts. That runs against R12 and ADR 0096.
3. **Autonomi-style 24 h window.** ant-node defaults to a 24 h stagger (6 h on beta) to keep its DHT close groups up. x0x keeps user and group data off a global DHT (ADR 0006), and David already set 60 minutes (D183). A longer window slows security fixes and does nothing for installs that never apply.
4. **Advertise running versions to peers** so they can warn each other. David ruled this out on 20 Oct (#1383 option B: local only, no field on the signed machine announcement). Release manifests already carry `version`.
5. **Keep auto-update as decided, and make "not auto-updating" a typed, visible local state** (chosen).

### Decision (proposed)

The daemon gets exactly one update disposition and one update state. Both are derived from facts the daemon already has, and shown on that machine. A companion CLI has its own status.

```rust
enum UpdateDisposition {
    AutoApply { window_minutes: u64, protected: bool }, // protected = ADR 0094 launcher-bound
    NotifyOnly(NotifyReason),
}
enum NotifyReason { Embedder, DisabledByConfig, SkippedThisRun, ManagedWindows }
enum CliStatus {
    InTransaction,
    CannotApply(CliLocation), // ADR 0094: this CLI stays out of the daemon transaction
}
enum CliLocation { SplitPath, PackageManaged }
enum BlockedBy { Hold(HoldCause), Refusal(RefusalReason) }
enum UpdateState {
    NotChecked, // no verified release evidence at all; a stored manifest is evidence
    Current,    // recorded highest verified version is at or below this build, including one loaded from the local record
    Waiting { version: Version, due_in_secs: Option<u64> }, // None for notify-only; Some for a scheduled auto-apply
    Held { version: Version, cause: HoldCause },             // auto-apply only, D188–D190 classes; until behind_since
    Refused { version: Version, reason: RefusalReason },     // auto-apply only: receipt, selection, journal; until behind_since
    Behind { latest: Version, first_seen: Timestamp, blocked_by: Option<BlockedBy> }, // first_seen is behind_since; blocked_by is null from Waiting
}
```

1. **Notify-only daemons still listen.** Notify-only daemons subscribe to `x0x/release` and verify manifests. That set is embedders that leave self-update disabled, `update.enabled = false`, `--skip-update-check`, and managed Windows. When several causes apply, the most lasting cause wins: `Embedder`, then `DisabledByConfig`, then `ManagedWindows`, then `SkippedThisRun`. `NotifyReason::Embedder` applies only when self-update is disabled. That is the default: `serve()` sets `ServeOptions.self_update_enabled` to false and `skip_update_check` to true (`src/server/mod.rs` L414–L420). An embedder that opts in through `serve_with_options` with `ServeOptions.self_update_enabled` true, and `ServeOptions.skip_update_check` false, is `AutoApply` like a normal install (README L380; the field is `src/server/state.rs` L131; `effective_self_update_enabled` is L134–L138). That opt-in stays. There is no compatibility break. The same call with `ServeOptions.self_update_enabled` true and `ServeOptions.skip_update_check` true is `NotifyOnly(SkippedThisRun)` when `Embedder`, `DisabledByConfig`, and `ManagedWindows` do not apply. `Embedder` does not apply, because self-update is enabled. Each notify-only daemon records the highest verified version it has seen and sets `behind_since` from the first version newer than this build. A later higher release raises that highest version and does not move `behind_since`. A manifest older than or equal to the recorded highest never lowers it. A notify-only daemon never stages or applies the release. David ruled on 21 Oct 2026 that notify-only installs and default embedders do subscribe to `x0x/release`. They verify each manifest and eager-forward the topic. `[update] gossip_updates = false` turns that subscription off. The key defaults to true (`DaemonUpdateConfig.gossip_updates`, `src/server/state.rs` L641). `update.enabled = false` and `self_update_enabled` false do not turn it off. The startup GitHub check and the fallback poll stay off for a notify-only daemon. This is a behaviour change on an unchanged topic, framing, key and signature context, so it is not a wire change. Embedders that leave self-update disabled get this through the same daemon code path, with no new embedder API. Subscribing takes part in gossip on that topic, including forwarding. `RelayFanout::verdict` in `src/gossip/relay_fanout.rs` delivers a subscribed topic locally and eager-forwards it while the topic token budget lasts (`ForwardAndDeliver`). An empty budget lazy-forwards. A daemon with no subscription on the topic still lazy-forwards (`LazyForward`). The new cost on a notify-only daemon is the local ML-DSA-65 verify (#656) plus that eager forwarding. Each subscribed daemon also parses a release payload it previously ignored, which is a larger attack surface. The notify-only listener uses a verify-only path that can never stage or apply anything. The implementation PR tests that path. When this is built, the README section "Embedding x0x" (README.md about L378) must say that a default embedder pays that ML-DSA-65 verify and eager-forward cost.
2. **Show it locally.** `GET /diagnostics/upgrade` returns `disposition`, `state` and `cli_status`. Those fields are additive on the route that already returns the version and policy digest. `Current` is allowed when the recorded highest verified version is at or below this build. The daemon persists that highest version. A verified manifest older than or equal to it never lowers it. Stored history counts. After restart, `Current` is reported only when that recorded highest version is at or below this build. A verified manifest at or below this build does not by itself clear `behind_since`. `NotChecked` is only for no verified evidence at all. `due_in_secs` is null for a notify-only daemon, including `NotifyReason::DisabledByConfig`, because that daemon is never due to apply. `due_in_secs` is set for an auto-apply daemon with a scheduled apply. `Held` and `Refused` are how an auto-apply daemon records a hold cause or a refused receipt, selection or journal before the threshold. Every non-`Current` daemon enters `Behind` once `behind_since` passes the threshold, whether the state is `Waiting`, `Held`, or `Refused`. The threshold is `[update] behind_after_days`. The default is 14. A positive value is the day count for entering `Behind`. `0` turns off only the `/health` reason `update_behind` and the non-zero `x0x doctor --json` exit. `state` still reports `Behind` under the normal 14-day rule, and `system.update_behind` still fires once. That `0` value is the opt-out for an operator who sets `update.enabled = false` on purpose, or who runs managed Windows. `behind_since` keeps running across `Waiting`, `Held`, and `Refused` and clears only at `Current`. `Current` means the recorded highest verified version is at or below the running build. A successful apply reaches that when the running build is then at or above the recorded highest. `blocked_by` is null when `Behind` came from `Waiting`. It holds the `HoldCause` or the `RefusalReason` when `Behind` came from `Held` or `Refused`. Entering `Behind` emits `system.update_behind` once for that `behind_since`. Where updating is expected, and `behind_after_days` is not `0`, it also makes `/health` degraded with reason `update_behind` and makes `x0x doctor --json` exit non-zero. That set is `AutoApply`, and the notify-only reasons `DisabledByConfig`, `SkippedThisRun`, and `ManagedWindows`. Those health and doctor signals are the same for every `blocked_by` in that set. A default embedder is `NotifyOnly(Embedder)` from `serve()` with `self_update_enabled` false. That embedder gets a soft warning only. The soft warning is `state` `Behind` on `GET /diagnostics/upgrade` and on local `this_machine`, plus that same `system.update_behind` event. Its `/health` is not degraded for this cause. It does not carry `update_behind`. `x0x doctor --json` does not exit non-zero for this cause. There is no second wait. A later release does not start a new wait. All of this is additive local API. No new field name is added for the soft warning. The implementation that adds `update_behind` changes the comment in `src/server/health_verdict.rs` around L897 and the doctor exit in the same change. That comment says an available update stays `ok`, and doctor exits zero. `update_behind` makes `/health` degraded only where updating is expected, and the doctor exit follows that reason. A default embedder stays off both.
3. **Show the local machine.** `GET /owner/machines` returns `disposition`, `state` and `cli_status` for the local machine only, on `this_machine` (`src/server/routes/owner.rs` L789). Remote rows stay as they are today (L779).
4. **CLI status is separate.** The daemon keeps `AutoApply` or `NotifyOnly` on its own terms. A split or package-managed CLI outside the declared install gets `cli_status` `CannotApply`. ADR 0094 leaves that CLI outside the upgrade transaction, and the daemon can still apply. `NotifyReason` lists daemon reasons only.
5. **Peers on older builds.** Keep feature-level negotiation through ADR 0093 capability bits. Do not infer support from version strings (0093 option 2, rejected). Sends that need a bit the peer lacks fail with `recipient_upgrade_required`, as they do now. Below a hard wire break (saorsa-gossip ADR-014 RejectV1), old peers simply are not supported. A minimum version comes from D35 once census data exists, and D96 ties topic-fetch retirement to it. This proposal sets no number.
6. **Urgent releases.** No signed urgency field, since that would be a wire change. Owners use D185 `now=true`, and later the M4 owner policy.
7. **Warning history is one `behind_since`.** The daemon persists the highest verified release version it has ever seen, `highest_seen_at` (the time that version was first verified), one wall-clock timestamp `behind_since`, and whether `system.update_behind` was already emitted for that timestamp. `behind_since` is set to the `first_seen` of the first verified version newer than the running build. Later higher releases raise the recorded highest version, set `highest_seen_at` to the time that new highest was first verified, and do not move `behind_since`. A verified manifest older than or equal to the recorded highest never lowers it, never moves `highest_seen_at`, never clears `behind_since`, and does not emit `system.update_behind` again. `behind_since` clears only when that recorded highest version is at or below the running build. A successful apply clears it when the running build is then at or above that highest version. That is the same condition as `Current`. A verified manifest at or below this build does not clear `behind_since` while the recorded highest stays newer. On load, and on any rollback or downgrade, if the recorded highest version is above the running build and `behind_since` is unset, set `behind_since` to `highest_seen_at`. A rollback keeps the age of the highest verified version. It does not keep the age of the oldest missed release. There is no `first_missed_at`. If the clock went backwards, age is clamped at zero and the timestamp is not rewritten. A daemon rolled back from V2 to V1 therefore enters `Behind` as soon as V2's age passes the threshold, with no new manifest. `system.update_behind` fires once for that restored episode. Reaching `Current` cleared the emitted flag, so this episode can emit once. Age is wall-clock time since `behind_since`, clamped at zero when the clock goes backwards. Do not count only uptime. A daemon that runs an hour a day must still reach `Behind` in calendar time. A forward clock jump can bring the warning early. That early warning is acceptable. A jump does not rewrite `behind_since` and does not clear the emitted flag. The `Behind` field `first_seen` is this `behind_since`. It is not the sighting time of the newest release, and it is not a new state. Duplicate delivery does not reset it and does not emit again. Restart loads the record, including the recorded highest version and `highest_seen_at`. No stored verified manifest reports `NotChecked`. Restart reports `Current` and clears `behind_since` only when the recorded highest version is at or below this build. A stored manifest older than that highest version does not. If the recorded highest is above this build and `behind_since` is unset, restart sets `behind_since` to `highest_seen_at`. Age already past `[update] behind_after_days` is `Behind`. Age still short stays `Waiting`, `Held`, or `Refused` until that age reaches the threshold, then enters `Behind`. `behind_after_days = 0` does not change that day count. `behind_since` does not restart when the daemon moves among those three states. A restart does not repeat an event already marked emitted for this `behind_since`. Reaching `Current` clears the flag, so a later miss can emit once more. This record is local. `highest_seen_at` stays in that record. It is not a diagnostics field. The record is not an owner-sync value and not a release-manifest field. Notify-only daemons may write it. They still never stage or apply the release.

### Deferred: remote update status

Carrying disposition, state or the running version to other owned machines needs an owner-sync protocol extension. `SyncKind` and `SyncValue` in `src/owner_sync.rs` are closed enums with no update-status payload, and an unknown kind is rejected. That extension is a wire change and needs its own ruling from David. This proposal leaves remote rows unchanged.

### Consequences

- Drift stops being silent. The wire stays the same. Notify-only daemons verify a release and do not apply it.
- Those daemons pay ML-DSA-65 verify CPU on each `x0x/release` manifest (#656) and eager-forward the topic while the relay budget lasts. They also take a larger attack surface, because they parse and verify release payloads.
- Embedders that leave self-update disabled, and other opted-out users, keep control and see when they are behind. An embedder that sets `ServeOptions.self_update_enabled` true and `ServeOptions.skip_update_check` false stays on the normal `AutoApply` path. The same call with `ServeOptions.skip_update_check` true is `NotifyOnly(SkippedThisRun)`.
- A default embedder's soft warning is `state` `Behind` on `GET /diagnostics/upgrade` and on local `this_machine`, plus one `system.update_behind` event. `/health` does not carry `update_behind`. `x0x doctor --json` does not fail for this cause.
- There is more API surface to keep stable. `[update] behind_after_days` defaults to 14. A positive value is the day count. `0` turns off only `update_behind` and the non-zero doctor exit. `state` still follows the 14-day rule, and `system.update_behind` still fires once. When this is built, `docs/upgrade-system.md` must describe that key, including the value `0`.
- When this is built, the README section "Embedding x0x" must mention the ML-DSA-65 verify and eager-forward cost for a default embedder.
- It does not fix drift by itself. Someone still has to act on the signal, either an owner or, later, an M4 policy agent.

### Validation

- A notify-only daemon with `[update] gossip_updates` true receives a newer signed manifest over gossip. It verifies the manifest, eager-forwards `x0x/release` while the topic token budget lasts, records `behind_since` from that first newer version, and never stages or applies the release. Before `[update] behind_after_days` it stays `Waiting` with `due_in_secs` null. At the threshold it enters `Behind`, and `first_seen` equals `behind_since`.
- `[update] gossip_updates = false` turns that subscription off. The notify-only daemon does not verify and does not eager-forward. With no other verified manifest it stays `NotChecked`.
- `[update] behind_after_days` defaults to 14. A newer verified release on day 0 sets `behind_since`. A second newer release on day 5 does not move it. Just before day 14, state is `Waiting`. At day 14, state is `Behind`.
- With `behind_after_days` set to 7 on a daemon where updating is expected, verified releases arrive on day 0 and day 5, both newer than the running build. `behind_since` stays at day 0. Just before day 7, state is `Waiting`, `/health` has no `update_behind` reason, and `x0x doctor --json` does not exit non-zero for this cause. At day 7, state is `Behind`, `/health` is degraded with reason `update_behind`, `system.update_behind` has been emitted once, and `x0x doctor --json` exits non-zero. The day-5 release does not move the timestamp. The same implementation changes `src/server/health_verdict.rs` around L897 and that doctor exit together. The doctor exit follows `update_behind` and stays zero when that reason is absent.
- Startup with no verified release evidence reports `NotChecked`. A failed subscription that stored no manifest does the same. Restart reports `Current` and clears `behind_since` only when the recorded highest verified version is at or below this build. A stored manifest older than that highest version does not. `NotChecked` is only for no verified evidence at all.
- Replaying an older signed manifest while `Waiting` or `Behind` does not reset `behind_since` and does not emit `system.update_behind` again. The recorded highest version stays. The replay does not report `Current`.
- `[update] behind_after_days = 0` on a daemon with `update.enabled = false`, or on managed Windows, leaves the 14-day rule for `state`. At day 14, `state` is `Behind` and `system.update_behind` has fired once. `/health` has no `update_behind` reason, and `x0x doctor --json` does not exit non-zero for this cause.
- An embedder with `update.enabled = false` and `ServeOptions.skip_update_check` true is `NotifyOnly(Embedder)`. A daemon with `update.enabled = false` and managed Windows is `NotifyOnly(DisabledByConfig)`. Managed Windows with `--skip-update-check` is `NotifyOnly(ManagedWindows)`. `SkippedThisRun` applies only when none of those three causes apply.
- A daemon whose winning `NotifyReason` is `DisabledByConfig` still subscribes while `gossip_updates` is true. It is `Waiting` with `due_in_secs` null until `behind_after_days`, then `Behind` with `blocked_by` null. With a positive `behind_after_days`, `/health` is degraded with `update_behind`, and `x0x doctor --json` exits non-zero.
- An auto-apply daemon with a scheduled apply is `Waiting` with `due_in_secs` set. At the threshold it enters `Behind` with `blocked_by` null.
- An embedder that opts in with `serve_with_options` and `ServeOptions.self_update_enabled` true, and `ServeOptions.skip_update_check` false, is `AutoApply`. It stages and applies a verified release the same way a normal install does. It reaches `Behind` only through `Waiting`, `Held`, or `Refused`, once `behind_since` reaches `behind_after_days`. That `Behind` carries `update_behind` and a non-zero doctor exit.
- `serve_with_options` with `ServeOptions.self_update_enabled` true and `ServeOptions.skip_update_check` true is `NotifyOnly(SkippedThisRun)`. It is not `AutoApply` and it is not `Embedder`. It does not stage or apply. At `behind_after_days` it enters `Behind` with `update_behind` and a non-zero doctor exit, because updating was expected. `Embedder`, `DisabledByConfig`, or `ManagedWindows` still wins when that cause also applies.
- The default `serve()` path leaves `self_update_enabled` false and stays `NotifyOnly(Embedder)`. With `gossip_updates` true it subscribes, verifies, and eager-forwards, and it never applies. At `behind_after_days` it enters `Behind`. The soft warning is `state` `Behind` on `GET /diagnostics/upgrade` and on local `this_machine`, plus one `system.update_behind` event. `/health` is not degraded, it has no `update_behind` reason, and `x0x doctor --json` does not exit non-zero for this cause.
- A durable hold is `Held` before the threshold, with `behind_since` still running. At the threshold it enters `Behind` with `blocked_by` holding that `HoldCause`. `/health` is degraded with `update_behind`, `system.update_behind` fires once, and `x0x doctor --json` exits non-zero.
- An undersized rollout receipt is `Refused` before the threshold. At the threshold it enters `Behind` with `blocked_by` holding that `RefusalReason`. The health reason, the single event, and the doctor exit are the same. The refusal does not reset `behind_since`.
- Restart while `Held` keeps `behind_since` and the hold cause. It does not clear the timestamp. Age still short stays `Held` and does not emit `system.update_behind`. Age already past the threshold enters `Behind` with `blocked_by` holding that `HoldCause`. If that event was already emitted for this `behind_since`, restart does not emit it again.
- Restart loads `behind_since`, the recorded highest version, `highest_seen_at`, and the emitted-event flag. If the recorded highest is above this build and `behind_since` is unset, restart sets `behind_since` to `highest_seen_at`. Wall-clock age already past the threshold is `Behind` after restart, and `first_seen` is that `behind_since`. Age still short stays `Waiting`, `Held`, or `Refused` and can still enter `Behind`. A duplicate manifest, or a newer release, or a move between `Waiting`, `Held`, and `Refused`, does not reset `behind_since` and does not emit a second event. A backward clock step clamps age at zero. A forward clock step can enter `Behind` early.
- V2 is verified, applied, and the daemon reaches `Current`, which clears `behind_since`. `highest_seen_at` stays the time V2 was first verified, and that age is already past the threshold. The daemon rolls back to V1 with no new manifest. On load, `behind_since` is set to `highest_seen_at`. That age is the highest verified version's age. There is no `first_missed_at`. State is `Behind`. `system.update_behind` fires once for that episode.
- The same rollback happens when V2 was first verified less than the threshold ago. On load, state is `Waiting` and `behind_since` equals `highest_seen_at`. At the threshold, state is `Behind` and `system.update_behind` fires once. No new manifest arrives.
- V2 is verified, then V3 is verified and applied, and the daemon reaches `Current`. `highest_seen_at` is the time V3 was first verified. `behind_since` is clear. The daemon rolls back to V1 with no new manifest. On load, `behind_since` is V3's `highest_seen_at`, not the time V2 was first verified. There is no `first_missed_at`.
- `GET /owner/machines` shows `disposition`, `state` and `cli_status` on `this_machine`. Remote rows stay unchanged.
- A split or package-managed CLI reports `CannotApply`. The daemon disposition stays `AutoApply` or `NotifyOnly` on the daemon's own terms, and an `AutoApply` daemon can still apply.
- Old released binaries still decode the unchanged manifest.

### Open questions

- Can x0xd tell that a binary was built from source rather than released? There is no evidence that it can.

### Couldn't verify

- ant-node's README says "critical security updates can override with shorter delay windows" and that the network keeps a "minimum online node threshold". Only the README and docs.rs were read, not the code behind them.

[All 15 ADRs](README.md)
