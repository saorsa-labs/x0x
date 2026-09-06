# ADR 0062: Recover Ordinary Home Persistence as One Durable Pair

- **Status:** Proposed
- **Date:** 2026-09-06
- **Decision owners:** David Irvine / human engineering review pending
- **Reviewers:** Pending; Codex drafted from the #471 source proof
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [#471](https://github.com/saorsa-labs/x0x/issues/471),
  [ADR 0028](./0028-authenticated-causal-predecessor-delivery.md),
  [ADR 0038](./0038-home-owner-certified-personal-space.md),
  [TOOLING](./TOOLING.md)

## Context

At `e16ba97a9d65022251e67ecc17f6e23d4b75699e`, ordinary saves write
`home-suite-groups.json` before `named_groups.json`. The former is the
owner-certified state; the latter contains inert, legacy-decodable placeholders.
A failed second write returns an unchanged/error outcome, permitting memory
rollback while the sidecar retains the rejected Home mutation.

A local deterministic test of the actual saver and merged loader reproduced
this: old memory was `home-x`, but reload returned `x-renamed-by-mutation`.
Exactly one test failed at that assertion under denied outbound networking and
a disposable test home. This is an I/O-fault/loader witness, not a power-loss
or process-crash test. #471 remains open; this ADR is not implementation evidence.

Source anchors at that commit, all in `src/server/routes/named_groups.rs`:

- `persist_named_groups_mutation_unlocked`, lines 3778–3789: failure triggers
  per-key compare-and-restore, preserving concurrent writers (#470).
- `save_named_groups_checked_unlocked`, lines 26954–27042: the split write;
  `AtomicWriteOutcome`, lines 27062 onward: single-file replacement facts.
- `load_named_groups_merged`, line 24589: sidecar overrides placeholders.
- `TreeKemNamedPersistJournal`, line 22110, and `HomeSuiteJournalTx`, line 23697:
  existing group/snapshot-bound journal formats, not generic map transactions.
- `persist_treekem_and_named_groups_atomic_with_info`, line 22241, and
  `persist_named_group_info`, line 4044: existing transaction owners.
- `src/server/mod.rs`, lines 612–621: paired TreeKEM recovery, orphan-sidecar
  cleanup, then merged load. TreeKEM recovery itself invokes the merged loader.

## Decision Drivers

- A rejected ordinary mutation must not reappear after a recoverable I/O fault.
- Unknown replacement/durability must neither acknowledge success nor trigger
  rollback under a false claim that the named destination is unchanged.
- Preserve pending-join exclusion, #470 CAS, owner-certified state, sidecar-first
  ordering, existing TreeKEM authority and frozen legacy journal bytes.
- Resolve restart behavior explicitly rather than hiding it in error strings.

## Considered Options

1. Restore the sidecar in process, with a distinct recovery-required result and
   retained preimage. Smallest immediate repair; cannot survive process death
   during either the original split write or failed restoration. All callers
   must still handle uncertainty. This is a bounded interim option, not full #471.
2. **Recommended:** a separate durable undo intent for ordinary paired saves,
   exclusive with existing TreeKEM transactions, with recovery before any merged
   load and success only after durable intent removal.
3. Reverse the writes, copy best-effort rollback, or reuse `ReplacedNotDurable`
   for a partial pair. Rejected: these move the failure window, hide rollback
   failure, or contradict callers that rely on the new named file being visible.
4. Extend/fabricate a TreeKEM journal or replace all journal formats. Rejected:
   ordinary saves have no honest snapshot envelope; legacy postcard decoding is
   frozen. A broader storage migration is unnecessary for this decision.

## Decision

### Ordinary transaction and commit point

Recommend one versioned ordinary-pair intent at a fixed, instance-local path
separate from `.journal`/`.hsjournal`; old journal formats remain byte-identical.
It records transaction identity, exact prior bytes or explicit prior absence of
both files, and digests of prior/candidate bytes for validation and diagnostics.
Bind the intent to the exact serialized candidate and captured preimage bytes,
not a reconstructed current map or a group revision/hash. The mutation snapshot
and save snapshot are separate today; this distinction matters for #470 writers.
Paths are fixed by the store, never supplied by the intent. Checksums detect
corruption, not hostile-owner tampering; ordinary OS file protection still applies.
A missing file is a preimage only on NotFound; other read errors refuse preparation.

Under `named_groups_persistence_lock`, with transaction ownership established:

1. Resolve earlier transactions first; capture the pair preimages and the same
   filtered candidate used today (unconfirmed join stubs remain excluded).
2. Durably write the intent before changing either destination. Preparation
   failure changes no destination; uncertain intent durability blocks a new
   transaction until the unchanged-pair intent is resolved.
3. Replace the sidecar, then the legacy view, using the existing file-fsync,
   rename and parent-directory-fsync primitives. Both candidate files must be
   durable before the transaction may reach commit cleanup.
4. Remove the intent and fsync its parent. **Successful completion of this fsync
   is the acknowledged commit point.** Only then return committed, publish
   dependent effects, or clear existing install/recovery markers.

Any ordinary failure before commit cleanup attempts to durably restore BOTH
preimages, including removing files whose preimage was absence and fsyncing the
removal. Keep the intent until restoration and its cleanup are durable.
Recovery must not delete its sole evidence first. Repeating restoration is safe.

Intent removal with failed parent fsync is commit-ambiguous: both new files are
already durable, but a crash can retain or lose the intent. Return recovery
required, withhold all success/effects and block subsequent store transactions.
In the same process, retry commit cleanup/parent fsync while retaining ownership;
never start an unrecorded rollback after the intent has disappeared. After a
crash, a retained valid intent deterministically selects the old pair; absence
selects the completed new pair. Either is allowed for an unacknowledged operation;
never report that ambiguous operation definitively aborted. A committed operation
cannot later be undone by this intent because its removal was acknowledged durable.

### Results and recovery

Keep single-file `AtomicWriteOutcome` unchanged. Ordinary save callers need a
separate result distinguishing **committed**, **aborted with old pair proven
durable** (including failure before any replacement), and **recovery required**
with stage/cause. The last state cannot be flattened into io::Error/NotReplaced
or ReplacedNotDurable. It does not assert either whole pair matches memory.

A startup coordinator checks for an ordinary intent before running ANY existing
journal routine that can load or write this pair. With an ordinary intent alone,
validate it completely, restore both preimages, make both durable, then remove
and durably clear it. Unknown versions, malformed/checksum-invalid data, uncertain
file inspection or failed replay refuse startup with evidence retained. Recovery
must be idempotent, including absence and interrupted cleanup. Only after this
step may legacy paired recovery and orphan cleanup run, then merged state load.

While recovery is required in a running process, fence dependent persistence,
causal replay/publication and mutation success. Resolve the original transaction,
not a new serialization of whatever happens to be in memory. After proven abort,
apply existing per-key CAS to the operation's before/after maps; concurrent updates
must survive, and must receive their own persistence transaction. Reads must not
present uncertain staged state as committed. The exact read/mutation fencing audit
is an implementation prerequisite, not provided by the current durability flag.

### Composition: exactly one recovery owner

Ordinary transactions must not coexist with any pending legacy TreeKEM/HomeSuite
journal that can read or modify this pair, including a retained journal for
another group. Existing journals contain whole-map payloads, but current paired
recovery validates and merges the target group; that safeguard must remain. Under the persistence lock, resolve existing journal work first;
if it cannot be resolved, refuse a new ordinary transaction. Conversely, every
TreeKEM transaction entry must refuse to start while an ordinary intent is pending.
This is instance-wide exclusion, not just group-ID exclusion.

Existing seal/rebind transactions remain the authority for their own sidecar,
named-view and snapshot writes. An internal explicit transaction context must
let those paths use low-level pair writers without creating a nested ordinary
intent. Journal preparation, replay and cleanup belong to that outer owner;
ordinary helpers must not discard, supersede or reinterpret its journal.
Recovery invokes low-level writers, never recursively starts another transaction.

If both journal families are found at startup, fail closed and preserve both;
do not guess an order from timestamps or per-group revisions. This is an invalid
state under the proposed exclusion rule, not permission to guess which recovery
decision wins. Existing paired recovery/tag/fork rules otherwise remain unchanged.

### Human review and implementation gates

This recommendation is **not implementation-ready or Accepted** until review
settles the following explicit boundaries:

- Approve abort-on-retained-intent versus commit-on-intent-absence for an
  unacknowledged operation, and how API/causal callers expose recovery-required.
  Existing callers at lines 3761/3778, 4032, 4062/4162, 7734, 20189 and 26719,
  and server/mod.rs 2776/2889/2960/3168/3259 need explicit handling.
- Audit every pair writer, TreeKEM journal creator, recovery entry and mutation
  bypassing the persistence lock. Existing CAS protects against some unlocked
  writers; the proposed fence must not silently serialize their updates away.
  Mixed-journal states stay fenced until an explicit repair policy is reviewed.
- Decide the exact intent encoding, size cap and version migration. Validate
  before mutation and fail closed on unsupported state; no fabricated snapshots.
- Decide downgrade/rollback policy. Old binaries ignore a new intent and cannot
  honor its recovery fence. Managed rollback must resolve transactions before
  handing the directory to an old binary, or refuse that handoff. Arbitrary manual
  old-binary access during recovery is not made transaction-safe by this ADR.
  Inert placeholders/legacy decoding alone are not a crash-consistency guarantee.

## Consequences

### Positive

- Ordinary rejection and restart recovery use one explicit authoritative decision.
- Single-file outcomes and existing cryptographic journal formats stay truthful.

### Negative / Trade-offs

- Extra durable writes and full-pair preimages increase I/O and temporary disk use.
- An unresolved transaction fences the store; availability yields to consistency.
- Caller integration and downgrade fencing are required work, not a local catch
  block. Existing ambiguous disk states cannot be repaired by inventing intent.

### Neutral / Operational

No membership, placement, encryption, network or Home election policy changes.
No Accepted ADR is edited. #471 stays open until implementation and fault/restart
acceptance; this proposal neither releases v0.41.4 nor implements supervision.

## Validation

Keep the exact baseline regression as a required failing negative control.
After implementation, its old-memory/old-merged-disk/exact-preimage assertions
must pass; a successful Home rename must survive a fresh merged load.

| Injected boundary | Required observation |
|---|---|
| Preimage read / intent create, write, file-fsync, rename, directory-fsync | No candidate destination written before durable intent; uncertain preparation remains fenced. |
| Sidecar or named create/write/file-fsync/rename failure | Old pair durably restored or recovery-required; never false success/unchanged. |
| Either destination directory-fsync failure | No commit acknowledgement; recovery retains a truthful stage. |
| Undo write/rename/fsync; prior-absence remove/fsync | Evidence retained until old pair durable; restart repeats safely. |
| Intent unlink failure | Durable candidate, pending cleanup; no success. |
| Intent unlink succeeded, directory-fsync failed | Both candidate files durable; no success; test retained-intent and absent-intent crash outcomes. |
| Process stops after each stage; recovery interrupted twice | Same selected pair after repeated recovery; no partial merged load. |
| Concurrent same-key/cross-key update, pending join stub | #470 CAS preserves newer updates; no stub leakage or lost independent mutation. |
| Existing rebind/seal journal, orphan sidecar half, mixed families | One owner; valid existing recovery succeeds; invalid coexistence fails before merged load or mutation, preserving evidence and avoiding snapshot/roster drift. |
| Corrupt/unknown/oversize intent; absent preimages; downgrade attempt | Fail closed or exact absence recovery; no undocumented data loss/handoff. |

Exercise a later save after an ambiguous cleanup and restart twice: a stale
preimage must never overwrite a later acknowledged save. Include an unrelated-key
insert and same-key serde-skipped-field update between mutation snapshot, save
snapshot and rollback. A torn ordinary candidate must not be inspected by legacy
recovery and spuriously classify a valid rebind as stale/forked. Mixed-family
crash images must not replay either side before the conflict is resolved.

Verify no success, relay, queue removal or marker clear precedes durable commit.
Tests must call real persistence/recovery entry points with disposable roots and
outbound network denied. Crash simulation and platform power-loss evidence must
be labelled separately. Existing valid TreeKEM recovery, inert old-decoder
placeholders and positive ordinary saves remain required controls.

## Notes for AI-assisted work

AI tools may draft this ADR, but must not mark it Accepted without human review.
Accepted ADRs are immutable. Storage-format implementation waits for review under
TOOLING; the unresolved boundaries above are not discretionary shortcuts.
