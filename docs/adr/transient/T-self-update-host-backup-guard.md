# T-self-update-host-backup-guard: one host keeps one previous binary

- **Status:** Proposed
- **Target slot:** A14
- **Date:** 2026-10-18
- **Decision owners:** David Irvine
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** x0x #1447. Stays clear of #1373 (versioned backups / ADR 0094 §3).

## Context

On a managed host, `x0xd` and `x0xd-443` share one on-disk binary. Each unit
can run the self-update apply path. That path always copies the current
target to `<target>.backup`, then replaces the target. When two units apply
within about one second, the second copy can read the already-replaced
target. The backup then holds the new bytes. The previous version is gone.
The v0.48.1 rollout on saorsa-3 showed this race. Rollback then needs a
fresh upload.

## Decision Drivers

- A host with more than one unit on one binary must keep one previous binary
  after a successful apply.
- The second unit must not destroy rollback bytes.
- This record must not take the #1373 versioned-backup design.
- The guard must work with today's single `<target>.backup` name.

## Considered Options

1. Leave the race. Operators upload a binary before rollback on a bad host.
2. Skip the backup when the on-disk target already matches the incoming
   bytes, with no host lock.
3. Take a host-wide exclusive lock for the shared target. Under that lock,
   skip the whole apply when the target already matches the incoming bytes;
   otherwise copy the current target to `<target>.backup` and then replace.
4. Ship #1373 versioned backups as the only answer to this race.

## Decision

Choose option 3.

1. Before backup or replace, the apply path takes an exclusive lock for the
   shared target. The lock file lives beside the target (for example
   `<target>.upgrade.lock`). Every unit that can replace that target uses
   the same lock file.
2. While the lock is held, compare the on-disk target bytes to the incoming
   binary. If they match, skip backup and replace. Release the lock.
3. If they differ, copy the current target to `<target>.backup`, then replace
   the target. Release the lock after the replace step this process owns.
4. Do not introduce versioned backup names here. #1373 keeps that scope.

A content match without a lock is not enough. Two units can both see the old
target, both decide to back up, and the later copy can still read the new
target. The lock closes that window. The content match stops a second unit
from rewriting a good backup after the first unit has finished.

## Consequences

### Positive

- Two units that share one binary leave `<target>.backup` as the previous
  version after a concurrent apply.
- A late unit that sees an already-updated target does no backup and no
  replace.

### Negative / Trade-offs

- Apply on one unit waits on the lock while another unit applies.
- A stale lock file needs a clear reclaim rule (same-host flock semantics).

### Neutral / Operational

- #1373 may later replace the single backup name. This guard still applies
  until that design ships.
- Implementation lives in `src/upgrade/`. Cursor workers stay off that path
  until the Engineer lifts the upgrade-code fence for #1447.

## Validation

A test starts two apply attempts on one shared target. After both finish,
`<target>.backup` still holds the original bytes, or the second attempt
skips because the target already matches. A single-unit apply still backs
up and replaces as today.

## Notes for AI-assisted work

Do not mark this record Accepted. Do not fold it. Do not expand this into
#1373 versioned backups. If the upgrade-code fence still blocks the apply
path, stop and ask the Engineer.
