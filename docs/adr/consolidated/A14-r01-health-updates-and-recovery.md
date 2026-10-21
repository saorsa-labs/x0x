# A14 Health Updates and Recovery

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These slots remain Proposed (D198, D199). David accepted the archive transfer on 10 October 2026. [docs/adr/README.md](../README.md) and [docs/adr-archive/move.json](../../adr-archive/move.json) record that acceptance. Replacement acceptance and clause-level transfer checks are still open. Use the [index and transition rules](README.md) to interpret their status.

x0x must remain recoverable when an update fails. Agents can help maintain a node, but update safety must also work when no agent is available.

## Context

x0x distributes signed release information and can update the daemon. An update affects executable files, persisted state, process supervision and sometimes several local instances.

A downloaded file, successful process start or healthy API response proves only one part of a safe update.

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

Date: 2026-10-21. Wire change: none. Do not add a version field to `x0x/release` announcements. David's 20 Oct 2026 ruling on #1383 keeps that data local.

The public API change is additive and local. It adds fields on `GET /diagnostics/upgrade`, one `/health` reason, a non-zero `x0x doctor --json` exit, one local event, and fields on `GET /owner/machines`. David's 20 Oct rulings on #1383 and #1384 cover the local version-policy digest and the still-null embedder minimum. These field and enum names still need his ruling.

Checked against `main` commit `125db4c5` on 21 Oct 2026.

### Problem

Daemons run old builds and nobody notices. Worked example: David's Mac ran x0xd 0.45.0 while the latest release was v0.48.1 (17 Oct 2026). Self-update had been switched off by a `--skip-update-check` guard, so the daemon never applied a release and never said it was behind. Nobody noticed until a person checked the version by hand. It was upgraded to 0.48.1 on 21 Oct 2026 (PID 35881, same agent_id, 23 peers). Under this design that Mac would have reported `Behind` on `/health`, `x0x doctor` and the owner's `/owner/machines` view from the first signed release announcement it received after 0.45.0.

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
- A CLI outside the managed install, or a package install, is left untouched (ADR 0094 validation, pair/split installs, #1104).

`GET /diagnostics/upgrade` already exists. It returns the local version, the update policy and the version-policy digest. The body has no `disposition` or `state` field (`src/server/routes/network.rs`, `upgrade_diagnostics`). The health verdict leaves an available update as `ok` (`src/server/health_verdict.rs` L897–L899). `x0x doctor` reads that route and treats a body with no `update_available` as up to date, so the process exits zero (`src/cli/commands/daemon.rs`, `check_upgrade_state`). `GET /owner/machines` exists. `this_machine` carries this daemon's version and digest. Remote rows have no version field (`src/server/routes/owner.rs` L745–L751).

The silent case is an install that cannot or will not take the update. Auto-update, notify-only and staged rollout are separate choices.

### Options

1. **Status quo.** Auto-update plus the 60-minute stagger, with nothing else. Drift stays silent.
2. **Notify-only everywhere.** Safer against bad releases, but every install drifts until a human acts. That runs against R12 and ADR 0096.
3. **Autonomi-style 24 h window.** ant-node defaults to a 24 h stagger (6 h on beta) to keep its DHT close groups up. x0x keeps user and group data off a global DHT (ADR 0006), and David already set 60 minutes (D183). A longer window slows security fixes and does nothing for installs that never apply.
4. **Advertise versions to peers** so they can warn each other. David ruled this out on 20 Oct (#1383 B: local only, no announcement field).
5. **Keep auto-update as decided, and make "not auto-updating" a typed, visible local state** (chosen).

### Decision (proposed)

Every install gets exactly one update disposition and one update state. Both are derived from facts the daemon already has, and shown locally and in the owner's census.

```rust
enum UpdateDisposition {
    AutoApply { window_minutes: u64, protected: bool }, // protected = ADR 0094 launcher-bound
    NotifyOnly(NotifyReason),
}
enum NotifyReason { Embedder, DisabledByConfig, SkippedThisRun, ManagedWindows, CliOutsideInstall }
enum UpdateState {
    Current,
    Waiting { version: Version, due_in_secs: u64 },
    Held { version: Version, cause: HoldCause },        // D188–D190 classes
    Refused { version: Version, reason: RefusalReason }, // receipt, selection, journal
    Behind { latest: Version, first_seen: Timestamp },  // NotifyOnly, or Refused for too long
}
```

1. **Notify-only installs still listen.** Every daemon, embedders included, subscribes to `x0x/release` and verifies manifests. It records the newest verified version it has seen and never applies it. This is behaviour only. The topic, framing, key and signature context stay the same.
2. **Show it locally.** `GET /diagnostics/upgrade` returns `disposition` and `state`. Those two fields are additive on the route that already returns the version and policy digest. `/health` reports degraded with reason `update_behind` once `Behind` lasts longer than a set period. `x0x doctor --json` exits non-zero in that case. A local `system.update_behind` event fires once per newly seen version. All of this is additive local API.
3. **Show it to the owner.** The `/owner/machines` census (#1352, over owner-sync, already ruled) carries each machine's disposition and state. Today only `this_machine` carries a version. Remote rows have no version. The proposal sends disposition and state over owner-sync, with no new announcement field and no new capability bit. That is how David would have seen his Mac stuck on 0.45.0 from another machine.
4. **Peers on older builds.** Keep feature-level negotiation through ADR 0093 capability bits. Do not infer support from version strings (0093 option 2, rejected). Sends that need a bit the peer lacks fail with `recipient_upgrade_required`, as they do now. Below a hard wire break (saorsa-gossip ADR-014 RejectV1), old peers simply are not supported. A minimum version comes from D35 once census data exists, and D96 ties topic-fetch retirement to it. This proposal sets no number.
5. **Urgent releases.** No signed urgency field, since that would be a wire change. Owners use D185 `now=true`, and later the M4 owner policy.

### Consequences

- Drift stops being silent without changing the wire or the update path.
- Embedders and opted-out users keep control and see when they are behind.
- There is more API surface to keep stable. `Behind` thresholds become one more number to choose.
- It does not fix drift by itself. Someone still has to act on the signal, either an owner or, later, an M4 policy agent.

### Validation

- A notify-only daemon receives a newer signed manifest over gossip. It records the manifest, never stages or writes files, and reports `Behind`.
- A hold, a refused receipt and a disabled config each map to the right state. The `Behind` threshold flips `/health` and the `doctor` exit code.
- The census shows two owned machines, one of them behind.
- Old released binaries still decode the unchanged manifest.

### Open questions

- Is the `Behind` threshold one release, or N days? Should it vary by disposition?
- Should a repeated `Refused` state escalate to `Behind`, or stay separate?
- Can x0xd tell that a binary was built from source rather than released? There is no evidence that it can.

### Couldn't verify

- Whether a daemon with updates disabled already verifies or records gossip manifests. Checked on `main` `125db4c5`: it does not. The gossip listener, the startup GitHub check and the fallback poll stay off unless `self_update_enabled` and `[update] enabled` are both true (`src/server/mod.rs` L1885, L1984–L1985 and L2031–L2034). A failed staging-identity init is a different case. Updates stay enabled, discovery continues, and apply stays off for that process (`docs/upgrade-system.md` L94–L96).
- ant-node's README says "critical security updates can override with shorter delay windows" and that the network keeps a "minimum online node threshold". Only the README and docs.rs were read, not the code behind them.

[All 15 ADRs](README.md)
