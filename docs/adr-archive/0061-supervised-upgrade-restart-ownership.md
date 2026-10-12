# ADR 0061: Self-Update Must Resolve Restart Ownership Before Replacing Binaries

- **Status:** Accepted
- **Date:** 2026-09-06 (proposed); 2026-09-09 (accepted)
- **Decision owners:** David Irvine
- **Reviewers:** David Irvine (human engineering review, 2026-09-09)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [issue #493](https://github.com/saorsa-labs/x0x/issues/493), [issue #415](https://github.com/saorsa-labs/x0x/issues/415), Accepted [ADR 0023](./0023-durable-local-history.md), [ADR 0025](./0025-required-gates-prove-observation-completeness.md), [ADR 0026](./0026-managed-x0xd-deployment.md), Proposed [ADR 0045](./0045-decentralized-self-update.md), [upgrade mechanics](../upgrade-system.md)

## Context

A self-update has two possible restart owners: an external service manager,
or x0xd's transactional helper. Choosing the helper inside a managed service
can leave two competing daemons on macOS or no running service on Windows.
Issue #493 reports launchd restarting its own child while the helper starts
another; issue #415 includes wrapper logs terminating the detached backup
helper after the tracked daemon exits successfully. History lock contention
and service outages are evidenced; history database corruption is not.

Source basis is main
`e16ba97a9d65022251e67ecc17f6e23d4b75699e`:

- `src/upgrade/restart.rs:104-171` recognizes `INVOCATION_ID`, Linux parent
  `systemd`, or `X0X_SUPERVISED=1`. Even recognized supervision selects a
  helper when `stop_on_upgrade=false`.
- `src/upgrade/apply.rs:216-258,280-329` replaces binaries before resolving
  the restart mode. The supervised branch writes intent best-effort and
  exits 0 on Unix or 100 on Windows; it does not invoke the helper's
  readiness/rollback transaction or the supplied shutdown hook.
- `src/upgrade/restart.rs:319-400` launches the helper and exits 0. Detaching
  from a terminal does not transfer a wrapper's tracked child ownership.
- `src/cli/commands/daemon.rs:278-348` now generates a macOS KeepAlive job
  with the explicit marker. It does not migrate arbitrary existing jobs.
  Windows autostart remains unsupported (`356-359`).

The existing marker is a deployment assertion, not evidence that every
wrapper restarts on the chosen status. PPID 1, launchd/services ancestry,
missing TTY, and service-looking names also do not establish restart policy.
The helper cannot safely compete with a manager that independently respawns.

This ADR changes future behavior. It neither records a completed fix nor
accepts the related Proposed ADR 0045.

## Decision Drivers

- One lifecycle owner must control replacement startup for an instance.
- Reject a known unsafe restart plan while the current binary still serves.
- Preserve effective identity/data roots and exclusive durable history.
- Keep ordinary terminal/nohup transactional restart supported.
- Separate binary replacement, process restart, readiness, and recovery
  evidence; none alone proves the others.

## Considered Options

1. **Extend broad OS/process detection.** Rejected as the contract: ancestry,
   service environment names and noninteractive execution do not prove a
   respawn policy. Exact job/service inspection may aid diagnosis but needs
   platform-specific validation.
2. **Keep current behavior and document the marker only.** Insufficient:
   `stop_on_upgrade=false` still creates a second restart owner, and the
   marker alone does not establish compatible exit/recovery policy.
3. **Make a recognized supervisor override the false setting.** Viable
   alternative, but silently changes the operator's requested restart
   behavior and may strand a service with an incompatible policy.
4. **Validate ownership before replacement; reject conflicting managed
   settings.** Recommended bounded change. The current daemon stays up
   while its deployment contract is corrected. Existing compatible managed
   and genuinely unsupervised paths remain distinct.
5. **Add a supervisor-owned rollback launcher now.** Potential later work,
   not required for this bounded ownership correction. It needs a separate
   startup-health, process-tracking and rollback design; reusing an untracked
   detached helper reproduces the ownership problem.

## Decision

**Accepted 2026-09-09 by David Irvine: option 4**, "validate ownership before
replacement; reject conflicting managed settings". Option 3 (a recognized
supervisor silently overriding the false setting) was considered and
explicitly rejected: it changes the operator's requested restart behavior
without telling them. The accepted consequence is that a managed instance
configured with `stop_on_upgrade = false` stops applying updates until its
configuration is corrected, replacing today's documented and unit-tested
"false always means transactional handoff" behavior for managed runs.

Existing hand-written launchd jobs are migrated with `x0x autostart --repair`,
inside the migration boundary below.

Acceptance of this contract is **not** a claim that all six clauses are
implemented. §3 is **not met** and §5 is **partially met** as of the accepting
change; see *Implementation status at acceptance* under Validation. Read that
section before assuming any clause below is live.

The following contract governs self-update:

1. **Resolve before mutation.** Before replacing either daemon or companion
   binary, resolve and validate the instance's restart owner, intended exit
   behavior, executable/argv and effective identity/data roots. Carry that
   plan through replacement and restart; do not discover a conflicting plan
   after bytes change. Serialize it with the existing update transaction.
   Failure leaves the current process and installed binaries unchanged and
   reports the unresolved contract. Download/staging alone is not restart
   acceptance.
2. **Reject a known conflict.** Recognized supervision combined with
   `stop_on_upgrade=false` must refuse self-update before replacement, rather
   than spawn a helper or silently override the setting. The configuration
   must be corrected or a separately reviewed restart policy selected.
   This deliberately replaces the currently documented and unit-tested
   “false always means transactional handoff” behavior for managed runs.
3. **Bind supported deployments explicitly.** A supported managed install
   identifies its actual service/job, supervisor version where relevant,
   executable/arguments, configuration/root resolution, supervision signal,
   upgrade exit status, restart policy and recovery owner. The initial
   contract uses the existing platform exit statuses: Unix 0, Windows 100.
   Supported launchd jobs must actually restart after 0; supported Windows
   wrappers must be verified to restart after 100. Versioned templates and
   loaded-policy readback establish support, not a marker in isolation.
   Unsupported or conflicting *known-managed* contracts must refuse apply.
4. **Preserve the unsupervised path without pretending detection is
   complete.** Terminal/nohup runs retain the bounded transactional helper.
   Missing markers cannot prove an arbitrary custom job is unsupervised;
   this proposal does not invent such a proof. Existing deployment inventory
   and explicit migration are required before declaring a managed fleet
   compliant. An unrecognized legacy wrapper remains an unresolved gap until
   migrated or given validated integration, not an automatically fixed case.
5. **Keep restart ownership singular.** The managed path requests restart
   through its external owner and must launch no detached replacement helper.
   No overlapping daemon may use the same effective root. A standalone PID
   file, API-port check, or separate history DB path is not proof of this
   invariant. The helper remains responsible for its own genuinely
   unsupervised successor/rollback lifecycle.
6. **State recovery honestly.** Supervised exit is a restart request, not
   health acceptance or automatic rollback. A supported deployment identifies
   who observes the replacement, records failure, and restores service when
   startup fails. The first ownership correction may use a documented,
   platform-tested operator recovery procedure; it must label recovery manual
   and must not advertise automatic supervised rollback. Automated recovery
   requires separately reviewed manager-owned monitoring, preserving the same
   lifecycle owner. Successful apply reporting must distinguish installed
   bytes, pending restart, observed readiness and any failed recovery.

### Existing-install migration and review boundary

Inspect the actual job/service and complete process/root set without changing
service state. Prepare a narrow change preserving its label, executable,
arguments, roots and other environment. Do not install a default job beside
an already running custom job, silently rewrite arbitrary service policies,
or delete history to resolve contention. Back up configuration before an
approved migration and verify the loaded policy afterward.

A generated plist already containing the marker does not prove that an old
loaded custom plist changed. A Windows wrapper example must name its tested
version and policy; it does not establish support for all WinSW, NSSM or SCM
arrangements. Migration and product rollout must retain separate receipts.

Human engineering review resolved the reject-versus-supervisor-override
choice on 2026-09-09: **refuse** (§2), with manual, platform-tested recovery
accepted as the first-stage boundary (§6). The initially supported platform
policy is macOS launchd `KeepAlive: true` jobs carrying the supervision
marker, plus systemd units, both on exit status 0. Windows (#415) has **no**
supported managed policy yet: `x0x autostart` does not generate a Windows
service, and the transactional helper is spawned without
`CREATE_BREAKAWAY_FROM_JOB`, so a job-object wrapper (WinSW, NSSM) terminates
the helper and any daemon it spawns. Windows therefore needs its own
classification and wrapper contract, tracked separately under #415; it is not
closed by this ADR.

## Consequences

### Positive

- Known conflicting restart plans fail before installed bytes change.
- Supported managed updates have one restart owner and attributable roots.
- Platform claims become verifiable independently of generic helper tests.

### Negative / Trade-offs

- Some currently permitted managed updates will be refused until settings
  are corrected; operators need actionable diagnostics and migration guidance.
- Custom services cannot be universally identified or repaired automatically.
- Platform fixtures and explicit support policies require maintenance.

### Neutral / Operational

- Manifest authority, signature verification and release distribution are
  unchanged. Accepted ADRs remain unchanged.
- No new data format, OS detector, supervisor template, locking primitive,
  daemon change or automatic rollback is implemented by this proposal.
- #493 and #415 require separate acceptance; fixing one platform or only
  new-install generation does not close the other or legacy migration.

## Validation

Before implementation is declared conformant, require completed observations
with exact source/binary identities, configuration receipts and process/root
accounting, in accordance with ADR 0025. Missing or skipped platform evidence
is not a pass.

- **Preflight controls:** valid managed configuration chooses external restart
  with no helper; known supervision plus the false setting refuses before
  *either* binary is replaced and preserves the serving process. Independently
  restore the current unsafe behavior and prove this regression fails;
  malformed/unresolved contract input must fail for its own reason.
- **Unsupervised controls:** terminal and nohup still use the real helper and
  prove healthy replacement or unhealthy-target rollback. Orphans, missing
  TTY and one-shot/non-KeepAlive jobs must not be mistaken for a guaranteed
  supervised respawn.
- **Template and migration controls:** parse actual generated job/wrapper
  artifacts; removing the marker or changing the required exit/restart policy
  must fail support validation. Migrate an existing custom job without adding
  a competing default service or changing its effective identity/data root.
- **macOS acceptance:** isolated launchd fixture, old no-marker KeepAlive
  reproduction, then supported migrated policy. Observe exit 0, exactly one
  manager-owned replacement at the expected version, no detached helper or
  DB-lock restart storm, and preserved sentinel history. Include negative
  startup and the specified recovery procedure.
- **Windows acceptance:** isolated Windows VM with the tested wrapper version
  and account. Reproduce descendant-helper termination/Stopped state, then
  prove exit 100 produces Running with one wrapper-tracked replacement and
  preserved roots/history. Exercise two sequential upgrades, failed target
  startup/recovery, and intentional service stop without an update loop.
- **State/readiness controls:** reject same-root concurrent daemons while
  allowing distinct roots. A single HTTP 200 is insufficient: establish the
  expected replacement's ownership/version and durable sentinel data, and
  report the actual manual or automated recovery outcome.

### Implementation status at acceptance

Recorded on the face of this ADR so a reader does not assume the whole
contract is live. The accepting change is PR #612 (issue #493).

| Clause | Status | What is and is not true |
| --- | --- | --- |
| §1 resolve before mutation | **Met** | The restart owner, intended exit behaviour, executable, argv, cwd and data root are resolved and validated before either binary is replaced, and carried through replacement and restart. "Roots" plural is satisfied by validating the data root directly plus pinning argv/cwd pre-swap — the identity root is determined by those, and is deliberately not plumbed as a separate derived field. |
| §2 reject a known conflict | **Met** | Recognized supervision plus `stop_on_upgrade = false` refuses before replacement, naming the signal and the setting to correct. |
| §3 bind supported deployments explicitly | **NOT MET** | Supervision is recognized by marker/signal alone — precisely the "marker in isolation" §3 rules out. There is no versioned template and no loaded-policy readback in the upgrade path. Residual failure: a job carrying the marker whose `KeepAlive` is later removed or made conditional still classifies `SupervisedExit`, exits 0, and nothing restarts it, so the daemon goes down and stays down. `x0x autostart --repair` checks `KeepAlive` at repair time only, not at upgrade time. |
| §4 preserve the unsupervised path | **Met, with the stated gap** | No-signal still classifies as `TransactionalHandoff`. This does not fix any existing unmarked job: the #493 population is repaired by migration, not detection. |
| §5 keep restart ownership singular | **PARTIALLY MET** | The negative half holds and is testable (`RestartPlan::spawns_helper()`): the managed path launches no detached replacement helper. There is **no** positive enforcement that no overlapping daemon uses the same effective root. This ADR rejects a PID file, an API-port check and a separate history-DB path as proof without stating what would suffice, so no criterion was invented. Tracked by issue #601. |
| §6 state recovery honestly | **Partially met** | Recovery is labelled manual, no automatic supervised rollback is advertised, and apply reporting distinguishes installed bytes, pending restart, observed readiness and recovery. The *documented, platform-tested* operator recovery procedure §6 permits has not been written or run. |

No platform acceptance observation below has been executed. §3's "supported
launchd jobs must actually restart after 0" remains unobserved: the migration
evidence is a live macOS run against fixture plists, which proves the plist
edit is correct and narrow, not that a migrated job restarts after an upgrade
exit.

Current `tests/upgrade_handoff_integration.rs:14` is Unix-only and exercises
synthetic helper transactions, not launchd or Windows service acceptance.
Those tests and the classification table remain useful controls but do not
satisfy the platform observations above. None of these new observations has
been executed for this Proposed ADR.

## Notes for AI-assisted work

AI tools drafted this ADR; David Irvine accepted it on 2026-09-09 after human
engineering review, which is what moved it out of Proposed. Now that it is
Accepted it is immutable: create a new superseding ADR rather than editing
this one. A draft PR, green document checks, or a bot review is not human
acceptance or permission to deploy this policy.
