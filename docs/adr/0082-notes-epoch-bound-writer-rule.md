# ADR 0082: Note Records Are Accepted Under the Roster Epoch They Were Written At

<!-- File name: docs/adr/0082-notes-epoch-bound-writer-rule.md -->

- **Status:** Accepted
- **Accepted:** 2026-09-27 by David Irvine (epoch-bound writer rule; bounded backdating limit accepted; status change applied by Claude at his instruction)
- **Date:** 2026-09-27
- **Decision owners:** David Irvine (chose the epoch-bound rule, 2026-09-27; only David may accept); Claude (drafting)
- **Reviewers:** pending (cross-model review required before acceptance)
- **Supersedes:** none. **Amends ADR 0081** in one respect: its "current writer" rule
  (§3 "its author must be a current group writer" and §5 "The author is a current
  writer"). ADR 0081 itself is not edited, and everything else in it stands.
- **Superseded by:** none
- **Serves:** vision **R9** (concurrent notes that never silently lose an edit)
- **Related:** #965 (ADR 0075/0081 notes implementation, branch
  `feat/965-notes-store`); `docs/design/adr-0081-notes-store-slice.md` §2 (the
  analysis that raised this); ADR 0016 and Phase D.3 (the signed group state-commit
  chain); #111 (retained state-commit history); ADR 0064/0066 (fork quarantine);
  ADR 0072 (scope freeze)

## Context

ADR 0081 accepts a note update record only if its author is a **current** writer of
the group. The #965 implementation showed what that means once membership changes.
The analysis is in `docs/design/adr-0081-notes-store-slice.md` §2:

- **Replicas disagree.** If a writer A is removed while some of A's records are
  still in flight, replicas that imported them keep A's edits. Replicas that had not
  imported them hold them back, along with every later op that depends on them.
  This does not converge while A stays removed.
- **History is erased.** A replica that re-verifies records re-checks every one of
  A's records against the current roster, for example after a restart. It then
  drops A's whole history, including edits A made legitimately while a member.

That breaks R9's promise that nothing is lost silently. On 2026-09-27 David Irvine
chose an **epoch-bound** rule: a record is accepted if its author was a writer at
the roster epoch the record was written under. Records written after the author's
removal are refused, earlier history is kept, and replicas converge.

The group already has a roster epoch:

- **The chain.** Every privileged group change produces an authority-signed
  `GroupStateCommit` (ADR 0016, Phase D.3, `src/groups/state_commit.rs`). It has a
  monotonic `revision` and a `state_hash` that commits to the `roster_root`,
  `prev_state_hash`, policy hash, public-metadata hash and security binding.
- **Retained history.** Each daemon retains the commits it applied, each with the
  roster projection it sealed over, in `GroupInfo.commit_log` (#111,
  `RetainedCommit { commit, roster, meta }`). The log is capped at
  `COMMIT_LOG_CAP = 4096` entries.
- **Current state.** The group's current `(state_revision, state_hash, members_v2)`
  is the head.

## Decision Drivers

- R9: a member's edits made while they were a writer are kept, on every replica,
  including after restarts. Replicas converge.
- Removal must still mean something: a removed member cannot add new text.
- There are no new authorities. The epoch and roster come from the existing signed
  state-commit chain.
- Fail closed where the evidence is missing: hold a record rather than guess.
- State honestly what cryptography cannot prevent, which is backdating.

## Considered Options

1. **Keep "current writer"** (ADR 0081 as written). Rejected by David: it erases
   removed members' history and diverges.
2. **Accept any record by any author who was ever a member.** It is simple and it
   converges. But removal would not stop a removed member adding text, now or ever.
   Rejected.
3. **Epoch-bound writer rule, backdating accepted as a limit.** Correct for honest
   writers. But a removed member can sign new records against any old epoch without
   limit.
4. **Epoch-bound writer rule plus causal epoch monotonicity** (chosen). As option 3,
   and in addition a record's epoch must be at least the epoch of every record its
   ops depend on. A backdated record can then never build on anything written after
   the removal. What remains of backdating is bounded and stated below.
5. **Timestamp-bound rule** (compare the record's wall-clock time with the removal
   commit's time). Rejected: timestamps are self-asserted and unsigned by the
   roster.

## Decision

### 1. Epoch source

- **Definition.** A note record's **epoch** is a pair `(revision, state_hash)` from
  the group's signed state-commit chain: the ADR-0016 / Phase D.3 `state_revision`
  and the 32-byte `state_hash` (hex in `GroupInfo`, raw bytes in the record).
- **Roster at an epoch.** The roster at an epoch is either:
  - the `roster` projection of the retained commit in `GroupInfo.commit_log` with
    that `revision` **and** that `state_hash`; or
  - for the head, the current `members_v2`. This covers revision 0, which has no
    retained commit.
- **Why the hash.** Binding the hash, not just the revision number, means a record
  can only name a state that is actually on this replica's chain. A forked chain
  (ADR 0064) never matches.

### 2. Binding the epoch into the signed record

- **New record version.** ADR 0081's `NoteUpdateRecordV1` becomes
  `NoteUpdateRecordV2`. V1 has never shipped, so there is no V1 compatibility.

  ```rust
  pub struct NoteUpdateRecordV2 {
      pub author: [u8; 32],
      pub seq: u64,
      pub loro_peer: u64,
      pub roster_epoch: u64,           // state_revision the author wrote under
      pub roster_state_hash: [u8; 32], // state_hash of that revision
      pub update: Vec<u8>,
      pub author_pubkey: Option<Vec<u8>>,
      pub author_sig: Vec<u8>,         // ML-DSA-65 over "x0x.notes.update-record.v2"
                                       //   || store_id || key || blake3(bincode(fields above))
  }
  ```

- **Unchanged from ADR 0081 §5:** the key layout, the signature construction apart
  from the domain and the two new signed fields, and the author and seq checks.
- **Choosing the epoch.** A writer signs under the latest epoch it knows. That is
  the higher-revision of:
  - its group head; and
  - the highest epoch of any record its update depends on (§4).

  If two candidate epochs have the same revision but different hashes (a fork), the
  save is refused.

### 3. Verifying "author was a writer at epoch E"

A record that passes ADR 0081's decode and signature checks is then classified
against the replica's roster history:

| Case | Result |
|---|---|
| `E.revision` ≤ head, and a retained commit (or the head) has `E.revision` and `E.state_hash` | **Writer** if the author is `Active` in that roster, else **refused** |
| `E.revision` > head revision (a future epoch) | **held** |
| `E.revision` ≤ head but the retained commit at that revision has a different `state_hash` (a fork, or a chain this replica has not adopted) | **held** |
| `E.revision` < the earliest retained commit (pre-history: a late joiner, or `COMMIT_LOG_CAP` truncation) | **Writer** if the author is `Active` in the **earliest** roster this replica holds, else **held** |

- **Held records** stay in the store. They are re-evaluated on every sync and
  accepted as soon as the epoch becomes known, for example when the group state
  reaches that revision. They never reach loro while held.
- **Refused** means the author was provably not a writer at that epoch. It is
  permanent for those bytes.
- **Role.** "Writer at E" means an `Active` member at E. Policy history is not
  retained per commit, so a stricter current `write_access` (`AdminOnly`,
  `ModeratedPublic`) is enforced where records enter the store, not at import. The
  0047 KV layer only merges deltas published by a current writer. Retaining the
  policy per commit, so the role can be checked at E, is a follow-up.
- **Sticky verdicts.** Once a replica has accepted a record, that decision is fixed
  for those bytes. Re-verification after a restart must reach the same verdict:
  either from the retained history, or, where truncation has removed the epoch,
  from a persisted list of accepted record ids. That list is additive and
  diagnostic, like ADR 0081 §4's retired set.
- **Pre-history evidence (follow-up).** A replica whose history starts after E
  cannot see a roster at E. It accepts E-records from authors who are writers at its
  earliest roster, and holds the rest. So one gap remains: records by authors
  removed before a replica's history began stay held on that replica. The gap
  closes with store-carried roster evidence:
  - **Evidence entries.** Write-once entries `n/_roster/<revision>/<state_hash_hex>`
    in the `notes` store, holding the `RetainedCommit` plus the commit headers that
    hash-link it to the replica's earliest retained commit.
  - **Verification.** The replica recomputes the `state_hash` of each header and
    follows the `prev_state_hash` links to a commit it already trusts, so no new
    trust root is needed.

  This is a later slice. Until it ships, the gap is a documented limit.

### 4. Causal epoch monotonicity (the backdating bound)

- **The rule.** A record's epoch must be at least the epoch of every record that
  holds an op its update depends on.
  - **Finding the dependencies.** The update's external dependencies are the loro
    `ImportBlobMetadata.start_frontiers` of the update, decoded inside the ADR 0081
    §3 isolation.
  - **Mapping them to records.** Each dependency op is mapped to the accepted
    record whose op span (`partial_start_vv`..`partial_end_vv`) contains it.
  - **Dependency not yet accepted:** the record is **held**.
  - **Dependency with a higher epoch:** the record is **refused** (permanent).
  - **One peer per record.** Every op in a record's update must belong to the
    record's own `loro_peer`. Otherwise a record could carry, and so re-date,
    another writer's later ops; a record that breaks this is refused as
    malformed.
- **Honest writers are never refused by this.** A writer's epoch is chosen as the
  maximum over its dependencies (§2).
- **What backdating can still do (the honest limit).** A removed member A still
  holds A's signing key. A can sign a new record under any epoch at which A was a
  writer, and no signature scheme can tell that apart from a record written then.
  - **What the rule prevents.** A backdated record can depend only on ops from
    epochs at or before its claimed epoch. So it can never edit, delete or anchor on
    anything written after that epoch.
  - **What A can still do.** A can insert new text, or delete text, only relative to
    the note as it stood at the claimed epoch. Because loro merges concurrent edits,
    such an insert still lands in the current text, positioned against pre-epoch
    content.
  - **Bounds.**
    - Only A's own `n/<note>/u/<A>/<seq>` keys can carry it; the ADR 0081 author
      binding is unchanged.
    - It is attributable to A, because every record is signed.
    - It counts against the 4 MiB note cap and the 12 MiB store budget.
    - It needs a sealed-store publish by a current writer: the 0047 KV layer only
      merges deltas from current writers, so A needs a current writer to relay A's
      record.
  - **Closing it fully** needs a non-cryptographic signal: for example, members
    refuse to relay post-removal publications from A, or an authority-signed "last
    accepted seq per author" is written at removal time. That is deliberately out of
    scope; **David to confirm** that this bound is acceptable.

### 5. What does not change

ADR 0081's containment, peer-id, budget, version and merge rules, the record key
layout, and ADR 0075's Q2–Q7 all stand unchanged.

## Consequences

### Positive

- A removed member's edits made while they were a writer are kept, on every replica
  that holds the roster evidence, including across restarts. Replicas converge.
- Removal is enforced: records claiming an epoch after the removal are refused
  everywhere, deterministically.
- Records never wait on "current state" races. A record for an epoch the replica
  has not seen yet is held and then accepted, with no loss.

### Negative / Trade-offs

- Backdating by a removed member remains possible, within the §4 bound.
- Two fields grow each record by 40 B, and verification needs the retained commit
  log.
- Until store-carried roster evidence ships, a late joiner (or a replica whose log
  was truncated) holds records by authors who were removed before its history began.
- Verdicts must be made sticky (persisted) to survive `COMMIT_LOG_CAP` truncation.
- Policy (`write_access`) at E is not checked at import (§3 Role).

### Neutral / Operational

- `/diagnostics` notes counters gain `held_future_epoch`, `held_unknown_epoch` and
  `refused_not_writer_at_epoch`.

## Validation

- **Earlier records survive removal.** Writer A writes, and A is then removed (a
  new commit). A's earlier records are present on every replica, including a
  replica that first sees them after the removal and one that restarts.
  - Control: the "current writer" rule holds them.
- **Post-removal records are refused.** A record by A under an epoch at which A is
  no longer `Active` is refused.
  - Control: it is accepted when A is still a writer at that epoch.
- **Dependents are not held.** B's edit, made after A's removal and depending on A's
  earlier text, is accepted and applies.
- **Unknown epochs are held, then accepted.** A record naming a future revision (or
  a revision whose hash this replica does not hold) is held. It is accepted after
  the group state reaches that revision.
- **Backdating (§4).**
  - A removed A signs a record under an old epoch that depends on B's post-removal
    edit: refused.
  - Control: the same record without the monotonicity rule would be accepted.
  - The same kind of record depending only on pre-removal state is **accepted**;
    this test pins the stated limit.
- **Review triggers:**
  - The store-carried roster evidence slice.
  - Retaining the policy per commit.
  - Any report of backdated text.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
