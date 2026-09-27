# ADR-0081 Notes Store Slice: Review Notes

- **Issue:** #965 (the "Notes store" slice of ADR 0081)
- **Branch:** `feat/965-notes-store`
- **Kind:** notes for the PR and for cross-model review. They record
  points the ADR does not settle, and how this slice handles them.

## 1. Record keys are write-once in the KV layer

**Problem.** ADR 0081 §5 keys each record `n/<note_id>/u/<author_hex>/<seq>`
and makes the receiver reject a record whose signature does not verify
under the key's author. That check runs when the notes layer imports a
record. It does not protect the KV entry. The 0047 store merges entries
last-writer-wins, and a delta's authenticated KV writer is its
*publisher* (the serving member after a full-state or retained serve).
So any current writer could put a newer value under another author's
record key, or delete it:

- Every replica would replace the author's value with the forgery.
- The receiver rule would then reject the forgery.
- The author's save would be gone everywhere, for good.

**Why the KV layer cannot enforce ownership by writer.** A `KvEntry`
carries no per-entry signature, and `SignedKvMutation.author_id` is the
publisher. After a serve, that is not the record's author. The only
authentication bound to the author is the record's own signature inside
the value.

**Fix (option b of the review request).** In a group store named `notes`,
`KvStore` treats every key that parses as a record key as write-once. The
guard sits in `notes_record_guarded`, `merge_entry_guarded` and
`notes_record_incoming_wins` in `src/kv/store.rs`:

- **Conflicting values.** When two different values meet under one record
  key (a delta merge, a retained-image merge or a local put), the winner
  is chosen by a fixed order, not by timestamp:
  1. A value whose author signature verifies (`record_value_verifies`)
     beats one that does not. A forgery can never verify, because it would
     need the key author's secret key.
  2. Otherwise the value with the lower BLAKE3 hash wins.

  Every replica applies the same order, so they converge, and a verified
  record is never replaced by a forged one.
- **Removal.** Record keys are never removed:
  - A delta's `removed` entry for a record key is skipped.
  - A local `remove` returns `ImmutableKey`.
  - If a retained image's OR-Set tombstones a record key that was active
    locally, the key is re-added under a fresh local tag (add wins).
- **Checkpoints.** A `notes` store never adopts a full-replacement owner
  checkpoint.
- **Cost.** Signatures are checked only when two different values meet
  under one record key. The normal case (a new key) costs nothing extra.

**Test.** `notes_record_key_survives_another_members_overwrite` in
`src/kv/sync.rs`:

- **Attack.** Member B overwrites A's seq-0 record with a newer, B-signed
  value and deletes it. Across four replicas, delivery covers both orders
  (forgery first and genuine first) and serves in both directions.
- **Result.** A's genuine value is the one present on every replica.
  Local put and remove of the key are refused.
- **Control.** `record_overwrite_attack_control_loses_the_record_without_the_guard`
  runs the same attack on a store named `wiki`, where the guard does not
  apply, and asserts that A's record is lost.
- **Checked by hand.** Turning the guard off makes the main test fail
  ("replica 0 lost A's record").

**Remaining limits.**
- **Two values from the same author.** The same agent on two machines can
  save two different signed values under one key. Both verify, so the
  lower hash wins and the other save is lost. This is deterministic, and
  only the author themselves can cause it. The notes layer checks that a
  key is free before writing, which narrows the window.
- **Late serve.** A replica that first sees a record key already
  tombstoned (for example a fresh replica served by B) recovers only when
  a replica holding the record serves it again with a newer tag.
  Replicas re-add on receiving the tombstone, so the next serve from any
  holder heals it.

## 2. A writer removed while their records are in flight (Assumption 5)

ADR 0081 §3 and §5 require a record's author to be a *current* writer
before its bytes reach loro. This slice checks that on every sync.

**What happens.** A record from author A that a replica has not imported
by the time A is removed is held there, not imported. A replica that
imported it earlier keeps it. The two replicas then diverge on A's late
edits, and on every later op that depends on them: loro parks those
dependent ops as pending on the replica that lacks A's edits. This does
**not** converge eventually while A stays removed. It heals only if A is
re-added, because held records are retried on every sync.

**How big the gap can get.** The divergence is bounded by A's records
that were not yet imported on each replica when A was removed, plus the
ops that depend on them. There is a sharper consequence:

- **Restart.** Actors live in memory. A rebuild after an engine fault
  reuses the records the actor already holds, but a daemon restart
  reopens the note and runs the writer check again on every record in
  the store.
- **Loss.** A restarted replica then drops all of A's history, including
  edits A made legitimately while a member, and parks every op that
  depends on them.

Removing a member therefore erases their past contributions on every
replica that restarts.

**Proposed change (needs David).** Fixing this means binding each record
to the roster epoch it was written in, and accepting any record whose
author was a writer at that epoch. That changes the ADR's "current
writer" rule, so this slice does not do it. The code follows the ADR as
written; this is a question for David.

**Resolution (2026-09-27).** David chose an epoch-bound writer rule, proposed
as ADR 0082 (PR #1020, awaiting acceptance). This branch now implements it:

- **Records.** Records are `NoteUpdateRecordV2`, signing the
  `(state_revision, state_hash)` they were written under.
- **Verification.** A replica judges each record against its retained roster
  at that epoch (`commit_log`). Records naming a future, forked or
  pre-history epoch it cannot verify are held.
- **Dependencies.** A record whose epoch is lower than an epoch it depends on
  is refused. Every record's ops must belong to its own `loro_peer`, so a
  record cannot re-date other writers' ops.

Tests:

- `removed_writers_earlier_records_survive_everywhere_including_restart`
- `post_removal_record_is_refused`
- `later_edit_depending_on_removed_writers_text_is_not_held`
- `unknown_epoch_record_is_held_then_accepted`
- `backdated_record_is_refused_only_when_it_builds_on_later_epochs`

Each epoch-rule test has a control: under the old rule it would fail, or it
fails with the relevant check disabled.

## 3. Saves above 256 KiB do not use `update_by_line` (#1029)

ADR 0081 §8 says a save above 256 KiB uses `LoroText::update_by_line`.

**Problem.** In loro 1.16.2 `update_by_line` diffs whole lines. It deletes
each changed line and inserts the new version as new ops, including the
characters the user did not change. A concurrent delete of those characters
cannot remove the new copies:

- A deletes part of a line and B edits another part of it. After the merge
  the text A deleted is back, and the line appears twice.
- On the concurrent-delete scenario below, `update_by_line` fails 175 of
  512 seeds (scratch run). It also emits about 4× the ops of the edit, and
  took 56 s on a 4 MiB note in which every line changed.

**Change.** `src/notes/text_diff.rs` computes the edit script itself and
applies it as explicit `insert`/`delete` ops. It never calls `update` or
`update_by_line`.

1. Trim the common prefix and suffix, cut back to whole lines.
2. Myers diff over line ids.
3. Widen each changed run of lines to the nearest anchor. An anchor is a
   non-blank line that occurs exactly once in each text; blank or repeated
   lines can match the wrong occurrence.
4. Myers diff over the characters of each widened run.

The line diff, the 256 KiB threshold and "no diff crate" are kept. The
<256 KiB path (`update` with `use_refined_diff: false`) is unchanged.

**Bounds.**
- **Work budget.** The line and character diffs share a work budget of
  16 M units (about 100 ms if all of it is spent). A region still
  unresolved when it runs out is replaced whole, as `update_by_line` would
  replace it; `EditScript::replaced_chars` counts it. Only rewrites run
  out: 500 scattered edits on 4 MiB spend 1.7 M.
- **Ties.** Like loro's character diff below the threshold, Myers picks
  one of several minimal scripts. If one edit both deletes and inserts a
  newline, a minimal script can re-insert a neighbouring character
  instead.

**Measured** (loro 1.16.2, release, Apple silicon; 4 MiB of word lines;
time and peak RSS growth):

| Save | edit script | `update_by_line` | `update` (char) |
|---|---|---|---|
| 1 edit | 3.4 ms, +0.1 MiB | 17 ms, +6.9 MiB | 7.1 ms, +32 MiB |
| 3 edits | 8.1 ms, +1.8 MiB | 20 ms, +5.5 MiB | 8.6 ms, +32 MiB |
| 50 edits | 15 ms, +1.2 MiB | 35 ms, +5.6 MiB | 28 ms, +32 MiB |
| 500 edits | 18 ms, +1.8 MiB | 90 ms, +7.1 MiB | 223 ms, +33 MiB |
| 500 pure deletes | 446 ms, +1.8 MiB | 100 ms, +6.5 MiB | 520 ms, +37 MiB |
| every line changed | 103 ms, +29 MiB (budget spent, replaced whole) | 56 s | not measured |

Consecutive deletes in one transaction cost loro about 0.8 ms each on a
4 MiB note; each insert is applied before its paired delete for that
reason. Many pure deletes cost the same as loro's own character diff.

**Tests** (`src/notes/engine_tests.rs`):
- `large_save_never_resurrects_a_concurrent_delete`: a property test over
  the real save path. A deletes a region (1–300 characters) of a >256 KiB
  note. B concurrently saves one to three edits elsewhere, mostly on the
  lines A's region touches. Every replica and a reversed-order observer
  must end with exactly both edits applied.
- `update_by_line_control_resurrects_deleted_text`: the same scenarios
  and checker with `update_by_line` fail (seeds 4 and 11 of 0..16).
- `large_save_regression_seeds_converge`, `large_save_emits_only_edited_characters`
  (op count equals edited characters; `update_by_line` emits more),
  `edit_script_reproduces_text_under_any_budget`,
  `spent_budget_replaces_the_region_whole`.

**Question for David.** ADR 0081 §8 names `update_by_line`. This keeps the
threshold and the line-first diff, but not that call. It is an
implementation change within the ADR's intent; say if you want it recorded
in an ADR.
