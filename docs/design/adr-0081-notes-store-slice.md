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
2. Split the rest into hunks at anchors. An anchor is a non-blank line that
   occurs exactly once in each text; blank or repeated lines can match the
   wrong occurrence. Anchors are matched by patience diff (longest
   increasing run, `O(n log n)`, no budget). A hunk is the text between two
   matched anchors where old and new differ.
3. Diff each hunk down a ladder of rungs. A whole region is never replaced
   because a budget ran out (Codex review of c85eb5e, P1).
   - **Exact.** Myers over the hunk's characters, within the shared
     `EXACT_WORK_BUDGET` (16 M units). This gives a minimal character
     script.
   - **Line-paired.** Used only for a hunk the exact rung could not finish.
     The hunk's lines are aligned by Myers over line ids, spending at most
     `LINE_ALIGN_WORK` (4 M units). If that runs out and old and new have
     the same number of lines, they are paired by position. Each aligned
     span is then diffed by character, line against line when the counts
     match, within the shared `LINE_WORK_BUDGET` (16 M units). A line whose
     character diff still runs out is replaced whole and counted.
   - **Refuse.** The line alignment ran out and the line counts differ.
     The save fails with `NoteError::EditTooLargeToMergeSafely`, and REST
     returns 422 `note_edit_too_large_to_merge_safely` ("save the change in
     smaller steps"). Nothing is applied, and nothing is written.

The line-first diff, the 256 KiB threshold and "no diff crate" are kept.
The <256 KiB path (`update` with `use_refined_diff: false`) is unchanged.

**Loss bound.** A character the user did not change is deleted and
re-inserted, which lets it survive a concurrent delete of it, only in one
of two cases:
- **(a) Ties.** Myers breaks a tie between equal minimal scripts that way.
  This is the same tie loro's character diff has below the threshold, and
  it needs an edit that deletes and inserts a repeated character such as a
  newline.
- **(b) Replaced lines.** The character is on an old line that the
  line-paired rung replaced whole. Such a line is always changed, moved,
  blank or repeated (an unchanged unique line would have been an anchor).
  No replacement ever spans more than one aligned span of changed lines.

Case (b) is reported on every save as `large_save: {rung, replaced_lines,
replaced_chars}` in the PUT response. `/diagnostics/groups` counts it
under `notes`: `large_saves`, `large_saves_line_paired`,
`large_save_replaced_lines` and `large_saves_refused`.

**Measured** (loro 1.16.2, release, Apple silicon; 4 MiB of word lines;
time and peak RSS growth; the 3,000-line row is a 423 KB note):

| Save | edit script | `update_by_line` | `update` (char) |
|---|---|---|---|
| 1 edit | 4.2 ms, +0.1 MiB | 17 ms, +6.9 MiB | 7.1 ms, +32 MiB |
| 50 edits | 19 ms, +1.2 MiB | 35 ms, +5.6 MiB | 28 ms, +32 MiB |
| 500 edits | 18 ms, +1.8 MiB | 90 ms, +7.1 MiB | 223 ms, +33 MiB |
| 500 pure deletes | 446 ms, +1.8 MiB | 100 ms, +6.5 MiB | 520 ms, +37 MiB |
| 3,000 one-char edits (Codex) | 80 ms, line-paired, 0 lines replaced | — | — |
| every line changed (`a`→`A`) | 274 ms, line-paired, 79,970 changed lines replaced and reported | 56 s | not measured |

Consecutive deletes in one transaction cost loro about 0.8 ms each on a
4 MiB note, so each insert is applied before its paired delete. Many pure
deletes cost the same as loro's own character diff. In a debug build, the
3,000-edit save takes about 2.5 s.

**Tests** (`src/notes/engine_tests.rs`):
- `large_save_never_resurrects_a_concurrent_delete`: a property test over
  the real save path. A deletes a region (1–300 characters) of a >256 KiB
  note. B concurrently saves one to three edits elsewhere, mostly on the
  lines A's region touches. Every replica and a reversed-order observer
  must end with exactly both edits applied.
- `update_by_line_control_resurrects_deleted_text`: the same scenarios and
  checker with `update_by_line` fail (seeds 4 and 11 of 0..16).
- `scattered_edits_never_resurrect_a_concurrent_delete`: a property test
  with 200–3,000 one-token edits (a contiguous block plus scattered lines)
  on a >256 KiB note, with a concurrent delete, through the save path.
- `codex_3000_edit_save_keeps_a_concurrent_delete`: Codex's exact case
  (3,000 lines of 141 bytes, 423,000 bytes, one character changed per
  line) with A concurrently deleting 50 characters of line 1,500. It is red
  on c85eb5e and green on the ladder.
- `unmergeable_large_save_fails_closed_with_a_typed_error`: the same edit
  plus one inserted line is refused with `EditTooLargeToMergeSafely`. The
  text is unchanged, and the refusal is counted and is not a fault.
- `spent_budgets_replace_only_the_changed_lines`,
  `unalignable_save_is_refused_not_replaced`,
  `scattered_edits_use_the_line_rung_without_replacing_lines`,
  `large_save_regression_seeds_converge`,
  `large_save_emits_only_edited_characters`,
  `edit_script_reproduces_text_under_any_budget`.
- The route test `note_errors_map_to_the_adr_statuses` covers the 422. The
  CLI test `error_with_message_prints_the_code_and_the_sentence` checks that
  the CLI prints the code and the "save in smaller steps" sentence.

**Question for David.** ADR 0081 §8 names `update_by_line`. This keeps the
threshold and the line-first diff, but not that call. It is an
implementation change within the ADR's intent; say if you want it recorded
in an ADR.
