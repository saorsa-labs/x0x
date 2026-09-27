# ADR-0081 Notes Store Slice: Review Notes

- **Issue:** #965 (the "Notes store" slice of ADR 0081)
- **Branch:** `feat/965-notes-store`
- **Kind:** notes for the PR and for cross-model review. They record two
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
