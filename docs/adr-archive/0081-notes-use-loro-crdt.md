# ADR 0081: Notes Use the loro Text CRDT (Supersedes the ADR-0075 CRDT Choice)

<!-- File name: docs/adr/0081-notes-use-loro-crdt.md -->

- **Status:** Accepted
- **Accepted:** 2026-09-27 by David Irvine (loro chosen over yrs+gate; 12 MiB store budget and bounded poisoned-doc leak accepted; status change applied by Claude at his instruction)
- **Date:** 2026-09-27
- **Decision owners:** David Irvine (chose loro, 2026-09-27; only David may accept); Claude (drafting)
- **Reviewers:** pending (cross-model review required before acceptance)
- **Supersedes:** **ADR 0075 in part.** Only the parts listed under
  [Supersession scope](#supersession-scope) change. ADR 0075 itself is not edited, and every
  other ADR-0075 decision carries over.
- **Superseded by:** none
- **Serves:** vision **R9** (concurrent notes that never silently lose an edit; agent
  scratchpads), plus **R6** (cross-machine scratchpads) and **R10** (#893 deep links to a note)
- **Related:** #965 (ADR-0075 implementation);
  `docs/design/adr-0075-slice1-spike.md` (Slice 1 spike);
  `docs/design/adr-0075-crdt-comparison.md` (yrs, automerge, loro and diamond-types
  comparison); PR #914 (sealed group task lists); ADR 0047 (KV store); ADR 0039 (rider
  boundary); ADR 0072 (scope freeze); upstream loro-dev/loro #1118, #1068 and #793

## Context

ADR 0075 (Accepted 2026-09-25) chose `yrs` as the notes CRDT (option A1). Slice 1 of
#965 tested that choice and compared it with the alternatives. Two documents record the
evidence: `docs/design/adr-0075-slice1-spike.md` and
`docs/design/adr-0075-crdt-comparison.md`.

**Findings that contradict ADR 0075:**

1. **Convergence.** ADR 0075 says "updates are commutative and idempotent, so replicas
   holding the same key set derive the same text". For yrs 0.28.0 this is false when records
   arrive out of order.
   - With no gate, 230 of 2,000 shuffled single-author trials and 162 of 200 cross-author
     trials diverge.
   - The failing doc stays stuck in yrs's pending state, and encoding it can panic.
   - This is an open upstream bug class. A causal apply gate fixes it (0/200).
2. **Author binding.** The ADR checks the "sealed inner author". That is the *publisher*
   of a KV delta. After a `FullState` or `RetainedState` serve, the publisher is the
   serving member, not the author, so the check needs a signature on every record.
3. **Size bound.** "The 4 MiB cap keeps the retained serve under 16 MiB" confuses scopes.
   The cap is per note, but `MAX_RETAINED_IMAGE_BYTES = 16 MiB` applies per store, and
   one `notes` store holds every note in the group.
4. **Version token.** `version` as an encoded yrs snapshot grows with history (5.3 KB
   after about 3k edits). Restoring it on a replica missing records returns wrong text
   silently.
5. **Import id.** The Wiki-import client id `hash(...)` must fit in 53 bits for yrs.

**Comparison** (same harness and seeds; 4 MiB note, 3 replicas × 1,000 random edits;
x0xd linux x86_64 release built with `cargo zigbuild`, baseline 59,924,552 B):

| | yrs 0.28.0 | automerge 0.12.0 | **loro 1.16.2** | diamond-types 1.0.0 |
|---|---|---|---|---|
| Out-of-order, duplicate and partitioned delivery, **no gate** (2,000 single-author / 200 cross-author) | 230 / 162 diverged | 0 / 0 | **0 / 0** | rejects the record; converges only with retry |
| Heap per replica, 4 MiB note, after all records | 5.2 MiB | ≈1.3 GiB | **17.9 MiB** | 7.8 MiB |
| Per-edit update, median | 28 B | 136 B | **109 B** | ≈1.8 MB (whole doc) |
| Full state after edits (text 4,219,374 B) | 4,284,669 B | 783,198 B | **3,709,075 B** | 1,840,124 B |
| Restore the pre-edit version | 5.6–6.1 s | 0.20 s | **0.04 s** | 0.003 s |
| Same-sentence three-way merge | ✓ | ✓ | **✓ (built-in `LoroText::update`)** | ✓ |
| Merge PUT on the 4 MiB note | 23 ms | 4.4 s, +3.5 GiB | **0.59 s, +51 MiB** | 0.19 s, 1.8 MB record |
| x0xd size delta | +0.58 MiB | +2.33 MiB | **+3.57 MiB (+6.11 %)** | +0.20 MiB |
| Last release | 2026-09-17 | 2026-09-16 | **2026-09-21** | 2022-08-25 |
| License (crate / transitive) | MIT / permissive | MIT / permissive | **MIT / permissive + MPL-2.0 (`im`, `bitmaps`, `sized-chunks`)** | ISC / + MPL-2.0 |

The spike recommended yrs with a mandatory causal gate, with loro as the fallback. On
2026-09-27 David Irvine chose **loro**. His reason: it converges under any delivery order
with no gate, so correctness does not depend on x0x getting a delivery gate right.

## Decision Drivers

- **R9:** concurrent edits converge, and nothing is lost silently, under any delivery order,
  duplication or partition. Correctness must not depend on a gate we could get wrong.
- A CRDT library bug must never take down `x0xd`, and one bad record must never poison other
  notes.
- Confidentiality equal to #914: same envelope, no new crypto, and nothing readable on the wire.
- Records must stay attributable to their author after full-state and retained serves.
- Stay inside the existing 0047 KV replication, including its 16 MiB retained-image limit.
- Keep the binary-growth cost bounded and explicit.

## Considered Options

1. **yrs 0.28.0 with a mandatory causal apply gate** (the spike's recommendation). It is the
   smallest option (+0.58 MiB, 5.2 MiB heap, 28 B per edit) and the fastest to merge, but
   correctness depends on x0x's gate. Without the gate, yrs goes stuck and can panic on an
   open upstream bug class, and a gate regression would silently diverge notes. Restoring an
   old version takes seconds. **Rejected** by David Irvine in favour of robustness with no gate.
2. **automerge 0.12.0.** Converges with no gate. But it adds +2.33 MiB, needs about 650 MiB
   of heap to hold a 4 MiB note, and took 4.4 s and +3.5 GiB of transient heap for one
   `update_text` merge. **Rejected** on memory and merge cost.
3. **diamond-types 1.0.0.** Its only crates.io release is from 2022, and 2.0 exists only in
   git, which x0x cannot depend on because it is published to crates.io. `encode_from` emits
   the whole document per edit (≈1.8 MB), far above the 64 KiB inline cap. It also rejects
   out-of-order records rather than queueing them. **Rejected.**
4. **loro 1.16.2.** Converges with no gate (0/2,000 and 0/200), restores old versions fast
   (0.04 s), and has a built-in text diff, so the merge needs no diff crate. It is released
   actively. Its costs:
   - +3.57 MiB of binary, which breaks ADR 0075's 2 MiB rule.
   - About 3.4× the heap of yrs.
   - MPL-2.0 transitive crates.
   - Open import-panic issues (#1118, #1068, #793).

   **Chosen**, with the containment below.

## Decision

We will use **loro** as the text CRDT for notes, inside the ADR-0075 architecture: the sealed
group `notes` store, write-once per-author records, the daemon-side merge and the Wiki
import. The specifics follow.

### 1. Library and pinning

- Use `loro = "=1.16.2"`. Also exact-pin the loro crates that loro itself only pins with a
  caret: `loro-internal`, `loro-common`, `loro-delta` and `loro-kv-store`. They become direct
  `=` dependencies. `Cargo.lock` is gitignored, so a caret would let a fresh resolve change
  the CRDT under us.
- Use default features, and only the text container. Do not use shallow snapshots, the
  "state-only" export, movable lists or trees. The first two are the #1068 surface; the last
  two carry other open panic reports.
- **Upgrade policy.** A loro version change is its own PR, never bundled with other work. It
  must pass all of the following before merge:
  - The Validation suite below.
  - A **mixed-version interop test**: records from the old pin imported by the new pin and
    back, and one note edited by both.
  - A re-measure of the binary delta against the ceiling in §2.
  - A changelog review for encoding or diff-algorithm changes. These matter because
    import records are deterministic (§8).

  Security fixes follow the same gate, fast-tracked. A major-version change needs a new ADR.

### 2. Binary-size ceiling (replaces ADR 0075's 2 MiB rule)

- ADR 0075's rule was: "if release `x0xd` grows by more than 2 MiB, re-evaluate". It is
  replaced by a **ceiling of 4.5 MiB (4,718,592 B)** of stripped linux x86_64 release `x0xd`
  growth, attributable to the notes CRDT and its dependencies.
  - The measured cost is **+3,659,736 B (+6.11 %)**.
  - The headroom of about 1 MiB absorbs pinned upgrades within 1.x.
- **Reason:** David chose convergence with no gate over size. At about 60 MB, x0xd absorbs
  6–8 % without affecting distribution; self-update ships the full binary either way.
- Exceeding the ceiling on an upgrade blocks that upgrade and triggers a review of this ADR.
  The measurement method is the one in `adr-0075-crdt-comparison.md` §(e).

### 3. Panic containment

Every loro call that consumes bytes not produced locally in this process runs isolated. This
covers `import`, `import_batch`, `fork_at`, `checkout`, decoding `Frontiers` and loading a
cached snapshot. Loro calls that follow such an import, on the same doc, are covered too.

- **Isolation.**
  - Each open note is owned by one note actor. Every loro operation on it runs inside
    `tokio::task::spawn_blocking`, with `std::panic::catch_unwind` inside the closure.
  - Both a caught panic and a `JoinError::is_panic()` map to a typed
    `NoteError::EngineFault { note_id, op }`. They are logged with the record key and counted
    in `/diagnostics`.
  - No loro object crosses into async code outside the actor.
  - The release profile must stay `panic = "unwind"`. A build-time assertion (a `cfg(panic)`
    check in the notes module) fails the build if it is ever set to `abort`.
- **Poisoned doc.** After an `EngineFault` the doc is treated as poisoned: loro's internal
  mutex may be poisoned (#1118, #1068). The actor then does four things:
  1. It **does not drop** the poisoned `LoroDoc`. #1118 reports that dropping a poisoned doc
     can abort the process, and an abort cannot be caught. The doc is moved into a bounded
     quarantine list and released with `std::mem::forget` once the list is full, as a
     counted, bounded leak that a restart reclaims.
  2. It **rebuilds** the note from the store's records into a fresh `LoroDoc` with a fresh
     peer id (§4). The rebuild also runs inside the isolation.
  3. It **skips and quarantines** the record that triggered the fault. That record key is
     recorded, and later imports skip it.
  4. After three consecutive faults on one note, it marks the note `degraded`. Reads return
     the last good text, writes return 503 `note_engine_fault`, and other notes are unaffected.
- **Nothing reaches loro before authentication.** A record is decoded with bincode (with size
  limits). Its author signature (§5) is verified, and its author must be a current group
  writer, before its bytes reach `import`. The remaining exposure is a malicious or buggy
  *member*, which is why containment is still required.
- **Upstream references.** loro-dev/loro #1118 (import with a reused peer id panics and
  poisons the doc; drop can abort), #1068 (import panic after a shallow snapshot; poisons the
  doc mutex) and #793 (import errors should not panic).

### 4. Peer-id allocation (never reused)

A loro `PeerID` is a `u64`. It must be unique for each writing replica session and **never
reused** (#1118).

- **Sessions.**
  - Every time a daemon opens a note doc for writing, whether at start, after a rebuild, or
    after an eviction and reload, it draws a fresh `PeerID` from the OS CSPRNG.
  - It rejects and redraws any id that already appears in the loaded doc's `oplog_vv()`. This
    check is exact, because every op any replica has published is in the store and so in
    the doc.
  - The id is fixed with `set_peer_id` **before** any local op.
  - A session never outlives the doc object.
- **Persistence.** Session ids are not persisted as reusable state: a restart always draws a
  new one. Each note's local cache records the peer ids this daemon has used (the "retired
  set"). The redraw check also consults that set, which covers ops that were written locally
  but crashed before publication. The set is diagnostic and additive, never an allocation
  source.
- **Cost.** Each session adds one version-vector entry (about 10 B). That is accepted until
  compaction.
- **Import ids (§8)** are the one deterministic exception.

### 5. Records, author signatures, one record per save

- **Key.** `n/<note_id>/u/<author_agent_hex>/<seq>` (unchanged from ADR 0075), written once
  by its author into the sealed `notes` store. The note's title and creator stay at
  `n/<note_id>/meta` as an LWW value.
- **Value.** The KV entry value is:

  ```rust
  pub struct NoteUpdateRecordV1 {
      pub author: [u8; 32],               // must equal the key's author segment
      pub seq: u64,                       // must equal the key's seq segment
      pub loro_peer: u64,                 // session PeerID that produced `update`
      pub update: Vec<u8>,                // loro export(ExportMode::updates(vv_before_save))
      pub author_pubkey: Option<Vec<u8>>, // ML-DSA-65 key; present only when seq == 0
      pub author_sig: Vec<u8>,            // ML-DSA-65 over "x0x.notes.update-record.v1"
                                          //   || store_id || key || blake3(bincode(fields above))
  }
  ```

  It lives only inside `KvEntry.value`, inside the #914 AEAD ciphertext. No outer field is
  added.
- **Receiver rule.** Reject the record unless all of the following hold:
  - The signature verifies under the author's key: the seq-0 key, or a key from the roster
    or certificate.
  - `AgentId(key)` equals `author`, which in turn equals the key segment.
  - The author is a current writer.

  This holds regardless of who published the delta.
- **Granularity.** One record per save: one PUT, one editor save or one import page. There
  is never a record per keystroke. The measured costs:
  - The signature adds **+3,375 B** per record, plus 1,952 B for the public key once per
    author per note.
  - A loro update is about 109 B for a small edit and about 20 KB for 1,000 edits.
  - A single-edit record is therefore about 3.5 KB sealed; about 9.4 KB on the wire for
    seq > 0 and about 11.3 KB for seq 0.
- **Size.** Updates larger than about 62 KiB are split across consecutive seqs, so that
  record plus mark stays under the 64 KiB inline cap.

### 6. Store budget (the 16 MiB retained image)

- **Per-store budget.** The `notes` store's retained image is capped at **12 MiB**
  (12,582,912 B), counted as the encoded 0047 retained image: every KV entry, record values,
  signatures and OR-Set overhead. The remaining 4 MiB below `MAX_RETAINED_IMAGE_BYTES`
  (16 MiB) is headroom for concurrent writers who each pass the check locally, and for
  serve framing.
- **Per-note cap (Q6, unchanged).** 4 MiB per note, measured as the sum of that note's
  record values in the store. The store-level measurement is deterministic on every node;
  the loro state size is not.
- **At the limit:**
  - A write that would take the note past 4 MiB returns **413 `note_too_large`**.
  - A write that would take the store past 12 MiB returns **413 `notes_store_full`**, with
    the current and budget byte counts.
  - Reads, and writes that fit within both limits, are unaffected.
  - The GUI keeps the unsaved draft, as it does today on a failed save.
  - A Wiki import (§8) pre-computes its total. If the import would exceed the budget it does
    **not** start: no marker is written, the legacy Wiki stays writable, and the result
    reports `wiki_import_exceeds_budget`.
  - Compaction (still deferred, as in ADR 0075) is the only way to reclaim space.
    Implementing compaction must not use loro shallow snapshots until #1068 is resolved.
- **Practical effect.** About three notes at the cap, or many small ones, per group. Planning
  compaction becomes a prerequisite for raising either number.

### 7. Version and restore

- **`version`** is the note's loro `Frontiers`, encoded with `Frontiers::encode` and sent as
  base64url. It measured 6–13 B for 3–4 peers, and grows with the number of concurrent heads,
  not with history. The API shape stays `{title, text, version}`.
- **Restore** (the merge base, and any future history view). Inside the isolation, decode the
  frontiers and `fork_at(frontiers)`, then read the text. If the frontiers name ops this
  replica does not hold, return **409 `base_version_unknown`**; never merge against a
  partial base. Full history is always kept (no shallow snapshots). Restore of the pre-edit
  version of a 4 MiB note measured 0.04 s.

### 8. Three-way merge and Wiki import mechanics (Q2 and Q3 unchanged; mechanics changed)

- **Merge PUT.**
  1. `fork_at(base_version)`, then `set_peer_id(fresh)`.
  2. `LoroText::update(submitted)`, or `update_by_line` above 256 KiB of text.
  3. `commit`, then `export(ExportMode::updates(vv_at_fork))`.
  4. Wrap the export in one `NoteUpdateRecordV1`, write it, and import it into the live doc
     (inside the isolation).

  No external diff crate is used. The response carries the merged text and the new version.
- **Deterministic import.**
  - The Wiki-import peer id is
    `u64::from_le_bytes(blake3("x0x.notes.import-peer.v1" ‖ note_id ‖ page_digest ‖ base_version ‖ LORO_VERSION)[..8])`.
  - The record key is `n/<note_id>/u/import/<page_digest>/<loro_version>`.
  - Two daemons with the same pin produce byte-identical records under the same key:
    idempotent, with no duplicate text.
  - Daemons on different pins use different peer ids and keys, so a peer id is never reused
    with different content (#1118). The worst case is a duplicated page body, which is
    detected and reported as `duplicate_import` in the migration receipt.

### 9. Unchanged from ADR 0075 (carried over as-is)

- **Q2 — plain-text editing:** the daemon performs the three-way merge from `base_version`.
  Unchanged as a decision; mechanics in §8.
- **Q3 — Wiki:** one-time import of each legacy page as a note, idempotent under retries and
  concurrent imports; the old store is kept read-only. Unchanged as a decision; the
  deterministic id and key follow §8.
- **Q4 — riders:** scratchpads only; per-group `scratch: none | read | read_write`, default
  `none`; no note access. **Unchanged**, including the exact ADR-0039 allow-list change in
  ADR 0075 Decision 5.
- **Q5 — scratchpads:** plain 0047 LWW KV (`scratch` store), sealed like other group stores.
  **Unchanged.** For rider provenance inside the sealed value, the compact
  `RiderMarkV1 {sub_agent_id, rider_token_id, delegation_digest}` (72 B) is recommended, with
  the full `RiderProvenance` written once per rider.
- **Q6 — note size:** 4 MiB per note, 413 beyond it; compaction deferred. **Unchanged**;
  §6 adds the store budget and defines the measurement.
- **Q7 — legacy Wiki writes after migration:** upgraded nodes answer 409
  `wiki_migrated_to_notes`; pre-upgrade legacy changes are imported exactly once, keyed by
  source digest. **Unchanged.**
- Also unchanged: the note REST API shape; the CLI `x0x notes …`; GUI deep links
  `#/note/<group_id>/<note_id>` and `#/scratch/<group_id>` (R10, #893); and ADR 0075's
  non-goals (live cursors, rich embeds, history UI).

### Supersession scope

This ADR replaces exactly these ADR-0075 text elements:

- Option A1 and the Decision's "adopt A1 (`yrs`)".
- The Decision 1 record encoding ("one `yrs` v1 update"), the author-binding sentence, and
  the size-bound sentence about the retained serve.
- Decision 2's "`version` is an encoded `yrs` snapshot … `skip_gc` … character diff".
- Decision 3's import client-id derivation.
- The Consequences item "measure binary growth … 2 MiB".
- The Validation "Author binding" and "Convergence property test" wording, now stronger here.

Everything else in ADR 0075 stands.

## Consequences

### Positive

- Convergence does not depend on x0x delivery order or a gate: 0 divergences in 2,200
  shuffled, duplicated and partitioned trials, with no gate.
- A fast historical restore (0.04 s on 4 MiB) makes `base_version` merges cheap even from
  old bases.
- A built-in text diff (`LoroText::update`) removes the external diff crate and the
  offset-unit mismatch risk the yrs design had.
- Per-record signatures make author binding hold across serves, which ADR 0075's check did
  not.

### Negative / Trade-offs

- +3.57 MiB of binary against yrs's +0.58 MiB (this ADR raises the ceiling to 4.5 MiB).
- About 3.4× the heap of yrs per open note: 17.9 MiB against 5.2 MiB at 4 MiB of text. The
  note actor should close idle docs.
- Open upstream panic issues. The containment in §3 is mandatory complexity, and a panic
  still costs a note rebuild and a bounded leak.
- Three MPL-2.0 transitive crates. MPL-2.0 is compatible with x0x's `MIT OR Apache-2.0`
  distribution (file-level copyleft; x0x already ships MPL-2.0 `attohttpc` and
  `option-ext`), but it must appear in the third-party notices.
- Losing Yjs wire compatibility for a future browser editor; that path would use loro's
  JS/WASM package instead.
- Each writing session adds a version-vector entry until compaction.
- The per-store budget limits a group to about 12 MiB of note records until compaction
  ships.

### Neutral / Operational

- `/diagnostics` gains notes engine counters: `engine_faults`, `quarantined_records`,
  `leaked_poisoned_docs`, `degraded_notes`, `store_bytes`/`budget`.
- Slice plan and effort from ADR 0075 stand. Slice 1's remaining work becomes the loro note
  model plus the containment harness.
- `MlsEncrypted` notes are sealed and `SignedPublic` notes are public by policy, as in #914.

## Validation

- **Convergence property test, no gate.**
  - N ∈ 2..6 replicas make random concurrent inserts and deletes, then exchange records in
    random order, with 20 % duplicates and partitions.
  - All replicas end with identical text, and every surviving inserted token is present.
  - The receiver has **no delivery gate**. The test must also run its records in a fully
    reversed order.
  - Control: the old whole-value LWW path fails the test.
- **Panic containment.**
  - Feed the import path a corpus: truncated, bit-flipped and random bytes; a valid update
    re-signed under a reused peer id (the #1118 shape); a shallow-snapshot-dependent update
    (the #1068 shape); oversized length prefixes.
  - Assert, for every input:
    - The daemon stays up.
    - `EngineFault` or a decode error is returned.
    - The note rebuilds, and the next valid record applies.
    - Other notes on the same daemon are unaffected.
    - A panicking closure maps to `JoinError::is_panic()` and then to the typed error.
  - A CI check asserts `panic = "unwind"` for the release profile.
- **Peer-id uniqueness across restart.**
  - Open, edit, save, then kill the daemon without a clean shutdown. Restart, open and edit.
  - Assert the new session peer id differs from every id in the doc's version vector and in
    the retired set, and that no record from the two sessions shares a `(loro_peer,
    counter)` pair.
  - Repeat 1,000 times in a loop, with an injected RNG that returns a colliding value first
    to prove the redraw.
- **Wire test (ciphertext only).**
  - Capture the exact bytes handed to `pubsub.publish` for a note record, and for a
    retained-image serve, in an `MlsEncrypted` group.
  - Assert that no note text, key, author id, public key, signature or loro peer id appears.
  - Control: a member opens the record, and its author signature verifies.
- **Author binding across serves.** A record served by member B under member A's key segment
  with B's signature is rejected. A's genuine record relayed by B is accepted.
- **Budget.**
  - A write past 4 MiB per note returns 413 `note_too_large`, and a write past 12 MiB per
    store returns 413 `notes_store_full`. Neither changes the store.
  - An over-budget Wiki import writes no marker.
- **Restore.** `base_version` naming unknown ops returns 409 `base_version_unknown`.
- **Mixed-version import.** Two pins importing the same page produce distinct keys and no
  peer-id reuse; the same pin produces one record.
- **Carried over from ADR 0075, unchanged:** the three-way merge test (same-paragraph PUTs
  both survive), the rider scope matrix, the legacy write refused test (Q7), the
  pre-upgrade-change-imported-once test (Q7), and the cross-machine scratch e2e (R6).
- **Review triggers:**
  - A loro release that fixes #1118, #1068 or #793. Re-check the containment corpus;
    containment stays in place.
  - The binary delta approaching 4.5 MiB.
  - A group reaching 75 % of the store budget.
  - A live-cursor editor being scheduled.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
