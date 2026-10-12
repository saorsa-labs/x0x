# A14 Health Updates and Recovery

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

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

Signed updates and diagnostics exist. M2 safe apply and stronger health reporting are active work. The complete owner-governed maintenance system is not yet shipped.

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

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
