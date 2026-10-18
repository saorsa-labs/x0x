# T-self-update-host-backup-guard: one host keeps one previous binary

- **Status:** Proposed
- **Target slot:** A14
- **Date:** 2026-10-18
- **Decision owners:** David Irvine
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** x0x #1447; draft #1410 / #1106; Accepted ADR 0094 §2.
  Stays clear of #1373 (versioned backups).

## Context

On a managed host, `x0xd` and `x0xd-443` share one on-disk binary. Each can
run the self-update apply path, which copies the current target to
`<target>.backup` then replaces it. When two units apply within about one
second, the second copy can read the already-replaced target, so the backup
holds the new bytes. The v0.48.1 rollout on saorsa-3 showed this race.

## Decision Drivers

- Keep one previous binary after a successful multi-unit apply.
- The second unit must not destroy rollback bytes, and must still restart
  into already-installed bytes when it still runs the old image.
- Do not take #1373; keep `<target>.backup`.

## Considered Options

1. Leave the race. Operators upload a binary before rollback on a bad host.
2. Skip backup when the on-disk target already matches, with no lock.
3. Take a host-wide exclusive lock. Under it, when the target already
   matches, skip only backup and replace and keep the restart-owner path;
   otherwise copy to `<target>.backup` then replace.
4. Ship #1373 versioned backups only.

## Decision

Choose option 3. This Proposed record (#1447) owns the host-wide exclusive
apply lock. Draft #1410 (#1106) must reuse it, not add a second lock.
#1410 may lengthen that hold to Accepted ADR 0094 §2.

1. Before backup or replace, take an OS exclusive lock (`flock` / `fcntl`)
   on a persistent lock file beside the target (for example
   `<target>.upgrade.lock`). The OS releases it when the holder dies.
   Reclaim must not unlink a lock file another process still holds. Every
   unit that can replace that target uses that same lock file.
2. While holding the lock, compare on-disk bytes to the incoming binary.
   Distinguish an already-installed artifact (disk matches) from an
   already-running version (this process still maps the old image). If disk
   matches, skip backup and replace only; keep the carried restart-owner
   path so that unit reloads the new bytes. Do not treat that as today's
   `NoUpgrade` (restart stays on `Success` only). Release the lock.
3. If they differ, copy to `<target>.backup`, then replace. For this legacy
   guard only, release after that replace. That short hold does not weaken
   Accepted ADR 0094 §2 (M2 holds through the HTTP response window,
   old-process exit, and unresolved intent).
4. No versioned backup names. #1373 keeps that scope.

A content match without a lock is not enough: both can still decide to back
up. The lock closes that window.

## Consequences

### Positive

- Concurrent applies leave `<target>.backup` as the previous version.
- A second old-running unit skips backup and replace, then still restarts.

### Negative / Trade-offs

- One unit waits while another holds the lock.

### Neutral / Operational

- Implementation lives in `src/upgrade/`. Cursor stays off until the
  Engineer lifts the #1447 upgrade-code fence.

## Validation

A test starts two independent apply attempts on one shared target, forces
both through a barrier, and covers a late second attempt after replacement
plus the two-old-processes / one-shared-target case. After both finish,
assert unconditionally that `<target>.backup` still holds the original
bytes and the target holds the candidate bytes. Record a second-attempt
skip separately; skip must not substitute for preserving the backup.
Single-unit apply still backs up and replaces.

## Notes for AI-assisted work

Do not mark this Accepted. Do not fold it. Do not expand into #1373. If the
fence blocks apply, ask the Engineer.
