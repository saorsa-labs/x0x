# T-self-update-host-backup-guard: one host keeps one previous binary

- **Status:** Accepted (Claude+Codex consensus, 2026-10-19, under David Irvine's
  19 Oct 2026 rule for transient decisions with no wire or public API change)
- **Target slot:** A14
- **Date:** 2026-10-18
- **Decision owners:** David Irvine
- **Reviewers:** Claude and Codex, both on implementation head
  `8339e66ec10204cbce74e5b2a7a404696f0f7b29` in PR #1462.
- **Acceptance receipts:**
  [Codex explicit ACCEPT vote](https://github.com/saorsa-labs/x0x/pull/1462#issuecomment-6270969308);
  [independent verification of Claude's explicit ACCEPT-ADR-1462 receipt](https://github.com/saorsa-labs/x0x/pull/1462#issuecomment-6272288596).
- **Supersedes:** none
- **Superseded by:** none
- **Related:** x0x #1447; draft #1410 / #1106; Accepted ADR 0094 §2.
  Stays clear of #1373 (versioned backups).

## Context

On a managed host, `x0xd` and `x0xd-443` share one on-disk binary. Concurrent
self-update can copy an already-replaced target into `<target>.backup`, so the
backup holds new bytes. The v0.48.1 rollout on saorsa-3 showed this race.

## Decision Drivers

- Keep one previous binary after a successful multi-unit apply.
- The second unit must not destroy rollback bytes, and must still restart
  into already-installed bytes when it still runs the old image.
- Keep `<target>.backup`; do not take #1373.

## Considered Options

1. Leave the race.
2. Skip backup when on-disk bytes already match, with no lock.
3. Take a host-wide exclusive lock; on match skip backup/replace and keep
   the restart-owner path; otherwise backup then replace.
4. Ship #1373 versioned backups only.

## Decision

Choose option 3. This record (#1447) owns the host-wide exclusive apply lock.
Draft #1410 must reuse it, not add a second lock.

1. Before backup or replace, take an OS exclusive lock on
   `<file-name>.upgrade.lock` beside the target. The OS releases it when the
   holder dies. Reclaim must not unlink a held lock file. The companion `x0x`
   CLI uses the same mechanism with its own lock file.
2. If on-disk bytes match the incoming binary, skip backup and replace only.
   Public `perform_upgrade` still returns `Success` with the requested
   version — the same public result as main for older current / newer
   requested / equal disk and incoming bytes. The restart-on-already-installed
   path is internal: auto-apply uses that `Success` so admission can still
   own restart for an old-running process.
3. If they differ, copy to `<target>.backup`, then replace. Release after that
   replace for this legacy guard. That short hold does not weaken Accepted
   ADR 0094 §2.
4. No versioned backup names. #1373 keeps that scope.
5. Unmanaged Windows uses the same `File::lock`. Managed Windows apply stays
   refused under ADR 0094.
6. After every host lock is held and the async caller is still alive,
   replacement is admitted. From then the blocking worker owns restart.
   Cancel after admission must not leave installed bytes without that owner.
   Pre-admission cancel still refuses mutation. A fallible hand-off of the
   deferred restart owner (for example `Builder::spawn`) must either refuse
   before mutation or keep exactly one continuation or fallback owner; it
   must not report Success with `restart_scheduled: true` after dropping the
   only owner.
7. HTTP apply opts into an explicit crate-internal deferred-restart mode.
   `apply.rs` owns one deferred restart (~750 ms delay, shared planner) that
   survives HTTP-task cancel and Tokio async shutdown. A detached
   `tokio::spawn` alone does not. The route does not schedule a second
   restart. CLI `--check-updates` keeps `restart_on_success=false` with a
   `RestartContext` and never restarts; do not infer HTTP from context.
8. Drop temp-dir custody after replacement I/O and before any continuation
   that may exit without unwinding.

Wire, public API, routes, JSON and schemas stay unchanged under David's rule.

## Consequences

### Positive

- Concurrent applies leave `<target>.backup` as the previous version.
- Cancelled HTTP apply keeps one restart owner; temp dirs do not survive a
  non-returning restart; old-running units still restart via auto-apply.

### Negative / Trade-offs

- One unit waits while another holds the lock.

### Neutral / Operational

- Implementation lives in `src/upgrade/`. The HTTP route only opts in.

## Validation

Two-process barrier tests assert backup and target bytes. RC5 covers HTTP
opt-in versus CLI, cancel in the defer window (one restart), spawn failure
before mutation (refuse, no orphan owner), cleanup before exit continuation,
and public `Success` on matching bytes (unchanged from main) with internal
restart-owner `Success`.

## Notes for AI-assisted work

Do not fold it. Do not expand into #1373.
