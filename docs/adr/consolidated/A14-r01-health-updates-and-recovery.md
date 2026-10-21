# A14 Health Updates and Recovery

- **Status:** Proposed
- **Revision:** 2
- **Date:** 2026-10-21
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

Changed since revision 1: this revision adds the proposed local upgrade disposition and behind signal, with no wire change.

These slots remain Proposed (D198, D199). David accepted the archive transfer on 10 October 2026. [docs/adr/README.md](../README.md) and [docs/adr-archive/move.json](../../adr-archive/move.json) record that acceptance. Replacement acceptance and clause-level transfer checks are still open. Use the [index and transition rules](README.md) to interpret their status.

x0x must remain recoverable when an update fails. Agents can help maintain a node, but update safety must also work when no agent is available.

## Context

x0x distributes signed release information and can update the daemon. An update affects executable files, persisted state, process supervision and sometimes several local instances.

A downloaded file, successful process start or healthy API response proves only one part of a safe update.

Today a daemon with updates disabled does not verify or record `x0x/release` manifests. Checked on `main` `125db4c5`. All three gates are in `src/server/mod.rs`: the startup GitHub check (L1883–L1885), the gossip listener (L1981–L1985), and the fallback poll (L2029–L2034). Each stays off unless `self_update_enabled` and `[update] enabled` are both true. The proposed section below starts verify-only listening for notify-only daemons. The topic stays `x0x/release`. A failed staging-identity init is a different case. Updates stay enabled, discovery continues, and apply stays off (`docs/upgrade-system.md` L94–L96).

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

**Status: Proposed (not accepted), needs David's ruling on the additive local API fields.**

Date: 2026-10-21. Wire change: none. The `x0x/release` topic, framing, key and signature context stay the same. Owner-sync records stay the same. Release manifests already require `version` (`ReleaseManifest.version` at `src/upgrade/manifest.rs:21`). David's 20 Oct 2026 ruling on #1383 keeps the version and policy digest off signed machine announcements.

The public API change is additive and local. It adds `disposition`, `state` and `cli_status` on `GET /diagnostics/upgrade` and on the local `this_machine` object of `GET /owner/machines`, one `/health` reason, a non-zero `x0x doctor --json` exit, and one local event. Remote census rows stay as they are. David's 20 Oct rulings on #1383 and #1384 cover the local version-policy digest and the still-null embedder minimum. These field and enum names still need his ruling.

Checked against `main` commit `125db4c5` on 21 Oct 2026.

### Problem

Daemons run old builds and nobody notices. Worked example: a daemon stays on an older release while a newer signed release exists. `--skip-update-check` has turned self-update off, so the daemon never applies the release and never says it is behind. A person notices only by reading the version. Under this design that machine would show `Behind` on its own `/health` and `x0x doctor` from the first signed release manifest it verifies.

How releases reach users is mostly settled already:

1. Signed manifests travel over gossip topic `x0x/release` (ADR 0045). GitHub is where releases are first found, with a fallback poll every 48 h by default. That interval is the code default of 2880 minutes in `src/server/state.rs`. The poll comment is `src/server/mod.rs` L2029. ADR 0045 states the topic and the GitHub fallback.
2. Each machine waits a delay salted by MachineId and version, inside a 60-minute window. The version salt is `StagedRollout::calculate_delay_for_version` in `src/upgrade/rollout.rs`. Fleets cannot go below 60 minutes (`FLEET_MINIMUM_MINUTES` in `src/upgrade/fleet_policy.rs`, D183, D184).
3. Probe, hold, retry and recovery limits are set (ADR 0094, D185–D195). An authenticated `now=true` apply skips the wait but not the checks (D185).
4. Recall is specified and waits on M2 (#1176). Owner policy and canary rings are M4.

What is missing is a signal for the machines that do not auto-update. Today an install can stop moving and give no behind signal:

- Embedders never auto-update (D35, #1119). The fallback poll is off when `self_update_enabled` is false (`src/server/mod.rs` L2029–L2034). The startup GitHub check uses the same flag (L1883–L1885). The `x0x/release` listener uses it too (L1981–L1985).
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
enum UpdateState {
    NotChecked, // no verified release evidence at all; a stored manifest is evidence
    Current,    // a verified manifest shows this build is the newest, including one loaded from the local record
    Waiting { version: Version, due_in_secs: Option<u64> }, // None for notify-only; Some for a scheduled auto-apply
    Held { version: Version, cause: HoldCause },             // auto-apply only, D188–D190 classes
    Refused { version: Version, reason: RefusalReason },     // auto-apply only: receipt, selection, journal
    Behind { latest: Version, first_seen: Timestamp },       // first_seen is the persisted behind_since
}
```

1. **Notify-only daemons still listen.** Notify-only daemons subscribe to `x0x/release` and verify manifests. That set is embedders, `update.enabled = false`, `--skip-update-check`, and managed Windows. Each one records the newest verified version and sets `behind_since` from the first version newer than this build. A later release does not move `behind_since`. It never stages or applies the release. This is a behaviour change on an unchanged topic, framing, key and signature context, so it is not a wire change. Embedders get this through the same daemon code path, with no new embedder API. Subscribing takes part in gossip on that topic, including forwarding. `RelayFanout::verdict` in `src/gossip/relay_fanout.rs` delivers a subscribed topic locally and eager-forwards it while the topic token budget lasts (`ForwardAndDeliver`). An empty budget lazy-forwards. A daemon with no subscription on the topic still lazy-forwards (`LazyForward`). The new cost on a notify-only daemon is the local ML-DSA-65 verify (#656) plus that eager forwarding. Each subscribed daemon also parses a release payload it previously ignored, which is a larger attack surface.
2. **Show it locally.** `GET /diagnostics/upgrade` returns `disposition`, `state` and `cli_status`. Those fields are additive on the route that already returns the version and policy digest. `Current` is allowed when a verified manifest shows this build is the newest. Stored history counts. After restart, a newest stored verified manifest at or below this build reports `Current`. `NotChecked` is only for no verified evidence at all. `Waiting` is the only pre-threshold state. `due_in_secs` is null for a notify-only daemon, including `NotifyReason::DisabledByConfig`, because that daemon is never due to apply. `due_in_secs` is set for an auto-apply daemon with a scheduled apply. `Held` and `Refused` are auto-apply states only: a hold cause, or a refused receipt, selection or journal. They are not the path into `Behind`. There is one transition into `Behind`. A notify-only daemon, and an auto-apply daemon still in `Waiting`, stays `Waiting` until the wall-clock age of `behind_since` passes the threshold, then enters `Behind`. Entering `Behind` is what makes `/health` degraded with reason `update_behind`, emits `system.update_behind` once for that `behind_since`, and makes `x0x doctor --json` exit non-zero. There is no second wait. A later release does not start a new wait. All of this is additive local API. The implementation that adds `update_behind` changes the comment in `src/server/health_verdict.rs` around L897 and the doctor exit in the same change. That comment says an available update stays `ok`, and doctor exits zero. `update_behind` makes `/health` degraded, so the exit must follow that reason.
3. **Show the local machine.** `GET /owner/machines` returns `disposition`, `state` and `cli_status` for the local machine only, on `this_machine` (`src/server/routes/owner.rs` L789). Remote rows stay as they are today (L779).
4. **CLI status is separate.** The daemon keeps `AutoApply` or `NotifyOnly` on its own terms. A split or package-managed CLI outside the declared install gets `cli_status` `CannotApply`. ADR 0094 leaves that CLI outside the upgrade transaction, and the daemon can still apply. `NotifyReason` lists daemon reasons only: `Embedder`, `DisabledByConfig`, `SkippedThisRun` and `ManagedWindows`.
5. **Peers on older builds.** Keep feature-level negotiation through ADR 0093 capability bits. Do not infer support from version strings (0093 option 2, rejected). Sends that need a bit the peer lacks fail with `recipient_upgrade_required`, as they do now. Below a hard wire break (saorsa-gossip ADR-014 RejectV1), old peers simply are not supported. A minimum version comes from D35 once census data exists, and D96 ties topic-fetch retirement to it. This proposal sets no number.
6. **Urgent releases.** No signed urgency field, since that would be a wire change. Owners use D185 `now=true`, and later the M4 owner policy.
7. **Warning history is one `behind_since`.** The daemon persists one wall-clock timestamp, `behind_since`, and whether `system.update_behind` was already emitted for it. `behind_since` is set to the `first_seen` of the first verified version newer than the running build. Later verified releases do not move it. It is cleared only when the daemon reaches `Current`, by applying an update or by a verified manifest at or below this build. Age is wall-clock time since `behind_since`, clamped at zero when the clock goes backwards. Do not count only uptime. A daemon that runs an hour a day must still reach `Behind` in calendar time. A forward clock jump can bring the warning early. That early warning is acceptable. A jump does not rewrite `behind_since` and does not clear the emitted flag. The `Behind` field `first_seen` is this `behind_since`. It is not the sighting time of the newest release, and it is not a new state. Duplicate delivery does not reset it and does not emit again. Restart loads the record. No stored verified manifest reports `NotChecked`. A newest stored manifest at or below this build clears `behind_since` and reports `Current`. A newer stored manifest stays `Waiting` until that same age passes the threshold, then enters or stays `Behind`. A restart does not repeat an event already marked emitted for this `behind_since`. Reaching `Current` clears the flag, so a later miss can emit once more. This record is local. It is not an owner-sync value and not a release-manifest field. Notify-only daemons may write it. They still never stage or apply the release.

### Deferred: remote update status

Carrying disposition, state or the running version to other owned machines needs an owner-sync protocol extension. `SyncKind` and `SyncValue` in `src/owner_sync.rs` are closed enums with no update-status payload, and an unknown kind is rejected. That extension is a wire change and needs its own ruling from David. This proposal leaves remote rows unchanged.

### Consequences

- Drift stops being silent. The wire stays the same. Notify-only daemons verify a release and do not apply it.
- Those daemons pay ML-DSA-65 verify CPU on each `x0x/release` manifest (#656) and eager-forward the topic while the relay budget lasts. They also take a larger attack surface, because they parse and verify release payloads.
- Embedders and opted-out users keep control and see when they are behind.
- There is more API surface to keep stable. `Behind` thresholds become one more number to choose.
- It does not fix drift by itself. Someone still has to act on the signal, either an owner or, later, an M4 policy agent.

### Validation

- A notify-only daemon receives a newer signed manifest over gossip. It records `behind_since` from that first newer version and never stages or applies the release. Before the threshold it stays `Waiting` with `due_in_secs` null. At the threshold it enters `Behind`, and `first_seen` equals `behind_since`.
- With a 7-day threshold, verified releases arrive on day 0 and day 5, both newer than the running build. `behind_since` stays at day 0. Just before day 7, state is `Waiting`, `/health` has no `update_behind` reason, and `x0x doctor --json` does not exit non-zero for this cause. At day 7, state is `Behind`, `/health` is degraded with reason `update_behind`, `system.update_behind` has been emitted once, and `x0x doctor --json` exits non-zero. The day-5 release does not move the timestamp. The same implementation changes `src/server/health_verdict.rs` around L897 and that doctor exit together.
- Startup with no verified release evidence reports `NotChecked`. A failed subscription that stored no manifest does the same. Restart with a stored verified manifest at or below this build reports `Current` and clears `behind_since`. `NotChecked` is only for no verified evidence at all.
- `update.enabled = false` is `NotifyOnly(DisabledByConfig)`: `Waiting` with `due_in_secs` null until the threshold, then `Behind`. A hold is `Held`, and a refused receipt, selection or journal is `Refused`. Those two states are auto-apply only.
- An auto-apply daemon with a scheduled apply is `Waiting` with `due_in_secs` set.
- Restart loads `behind_since` and the emitted-event flag. An episode that already emitted `system.update_behind` does not emit again. Wall-clock age already past the threshold is `Behind` after restart, and `first_seen` is still the original `behind_since`. Age still short stays `Waiting` and can still enter `Behind`. A duplicate manifest, or a newer release, does not reset `behind_since` and does not emit a second event. A backward clock step clamps age at zero. A forward clock step can enter `Behind` early.
- `GET /owner/machines` shows `disposition`, `state` and `cli_status` on `this_machine`. Remote rows stay unchanged.
- A split or package-managed CLI reports `CannotApply`. The daemon disposition stays `AutoApply` or `NotifyOnly` on the daemon's own terms, and an `AutoApply` daemon can still apply.
- Old released binaries still decode the unchanged manifest.

### Open questions

- The trigger is wall-clock age from `behind_since`. What is the default number of days, and is that number configurable?
- Can x0xd tell that a binary was built from source rather than released? There is no evidence that it can.
- Does `update.gossip_updates = false` also turn off verify-only listening on `x0x/release`?
- Notify-only installs and embedders would subscribe to `x0x/release`. That subscription takes part in gossip on the topic, including eager forwarding while the relay budget lasts, and pays ML-DSA-65 verify CPU (#656). D35 says embedders do not auto-update. Is that participation acceptable for notify-only installs and for embedders?

### Couldn't verify

- ant-node's README says "critical security updates can override with shorter delay windows" and that the network keeps a "minimum online node threshold". Only the README and docs.rs were read, not the code behind them.

[All 15 ADRs](README.md)
