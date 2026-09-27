# ADR-0075 Slice 1 Spike: yrs Snapshots, Binary Size, Provenance Mark

- **Issue:** #965 (Slice 1 of ADR-0075, "Collaborative notes (yrs) and agent scratchpads")
- **Date:** 2026-09-27
- **Kind:** measure-and-report spike. No feature code ships. `yrs` is **not** added to x0x's `Cargo.toml`.
- **Baselines:** `origin/main` @ `b217215` (binary size); `origin/codex/final-acceptance-candidate` @ `5fb54d6` (#914 sealed envelope).
- **Machine:** Apple M5 Max, 128 GiB, macOS (Darwin 25.6), rustc 1.95.0, cargo-zigbuild with zig from Homebrew.

## Summary

| # | Question | Verdict |
|---|----------|---------|
| 1 | yrs snapshots and `skip_gc`; a 4 MiB note with 3 replicas × 1k edits | **CHANGES-NEEDED.** Snapshots and `skip_gc` work as the ADR needs. But yrs 0.28.0 does **not** converge when update records arrive out of order, so records must be applied in causal order. |
| 2 | Binary-size delta of `x0xd` (linux x86_64 release) | **GO.** yrs adds **+553 KiB (+0.94 %)**. With a diff crate for the merge it adds **+640 KiB (+1.09 %)**. Both are well under the ADR's 2 MiB stop rule. |
| 3 | Does the author/rider provenance mark fit inside the #914 sealed value? | **GO on fit, CHANGES-NEEDED on the ADR text.** The mark fits in `KvEntry.value`, needs no new outer field and leaks nothing on the wire. But "the sealed inner author" does not identify a record's author after a full-state or retained serve, so each record needs its own author signature. |

Five ADR statements are contradicted by the evidence. They are listed under [ADR points the evidence contradicts](#adr-points-the-evidence-contradicts).

## Method

This is throwaway code, run outside the repository and then deleted. Build products went to separate `CARGO_TARGET_DIR`s, which were also deleted.

| Crate | What it does |
|-------|--------------|
| `spike965-yrs` | Parts A (snapshots and GC), B (three-way merge) and C (4 MiB × 3 replicas × 1k edits). `yrs = "=0.28.0"`, `similar = "2"` (2.7.0), `rand 0.8`. A counting global allocator measures live and transient heap. |
| `spike965-yrs --bin repro` | Minimal out-of-order repro: 2,000 seeds, one author, 2–9 update records applied in shuffled order. |
| `spike965-yrs --bin causal` | Three authors, 15 rounds of partial causal sync, then a fresh observer applies all records in random order under three policies: no gate, a per-author sequence gate, and a causal (state-vector) gate. |
| `spike965-env` | Path-depends on an unmodified `git archive` of the candidate branch. It builds a real #914 record: `GroupInfo` → `GssKvSecureContext` → `seal_mutation` → `(PeerId, EncryptedKvStoreRecordV1)` wire bytes. Then it measures sizes and scans the wire bytes for plaintext. |
| `x0x-bin` | `git archive origin/main` plus an optional `yrs` dependency, a `notes-spike` feature and a feature-gated `X0X_YRS_SPIKE` path in `x0xd` `main()`. That path makes the yrs APIs reachable: `Doc`, `Text`, snapshot, `encode_state_from_snapshot`, `apply_update`, `diff`. |

The yrs API was checked against the current docs (Context7 `/y-crdt/y-crdt`) and the 0.28.0 source (`store.rs:152`, `doc.rs:470-495`, `block.rs:81`, `transaction.rs:862`). `cargo search yrs` shows 0.28.0 is the latest release, which matches the version the ADR cites.

Commands:

```sh
# Q1
CARGO_TARGET_DIR=$SCRATCH/target-spike965 cargo build --release        # in spike965-yrs
MODE={inorder|dups|shuffle|full|seqgate|merged} target-spike965/release/spike965-yrs
target-spike965/release/repro ; RECOVER=1 …/repro ; INSERTS_ONLY=1 …/repro ; SVDIFF=1 …/repro
target-spike965/release/causal
# Q2 (in x0x-bin; identical toolchain and lock for all variants)
CARGO_TARGET_DIR=$SCRATCH/target-spike965-bin cargo zigbuild --release \
  --target x86_64-unknown-linux-gnu --bin x0xd [--features notes-spike | notes-spike-diff]
# Q3
CARGO_TARGET_DIR=$SCRATCH/target-spike965 cargo run --release          # in spike965-env
```

## Q1: yrs snapshots, `skip_gc`, convergence, memory

### Snapshots and `skip_gc`: GO

| Check | Result |
|-------|--------|
| `skip_gc = true`: snapshot, then delete and insert, then `Snapshot::decode_v1` → `encode_state_from_snapshot` → fresh doc | Restores the exact pre-edit text. |
| `skip_gc = false` (the yrs default) | `encode_state_from_snapshot` returns `Err(Error::Gc)`. The check is hard-coded (`store.rs:157`). |
| A snapshot taken on replica A, restored on replica B after B received A's records | Identical text. |
| A snapshot restored on a replica that **lacks** some of the snapshot's records | Returns **silently incomplete** text (`"two one "` instead of `"four three two one "`) with no error. `write_blocks_to` skips clients it does not know about. |
| A `skip_gc` receiver fed a full-state blob that a **GC'ing** doc encoded | History is lost: the pre-delete snapshot restores as `"keep keep"`, and the blob no longer contains the deleted bytes. |
| A `skip_gc` doc's own state blob | Retains the deleted text, so history is kept. |

`skip_gc` therefore behaves as the ADR needs, under three conditions:

1. Every `Doc` that ever encodes state (serve, compaction, import) is created with `skip_gc: true`.
2. The daemon never ingests a state blob produced elsewhere. Only per-edit update records are ingested.
3. Before restoring `base_version`, the daemon checks that its local state vector covers the snapshot's state vector. If it does not, it answers 409 or retries; it must not merge against incomplete text.

### Three-way merge (Decision 2): GO, with two implementation constraints

- Two PUTs from the same `base_version` that edit the **same sentence** both survive: `"…on Tuesday at 3pm in room 4."`. Each produces one record, of 41 B and 87 B. A replica that applies the two records in reverse order converges.
- **The merge doc must use a fresh yrs client id.** If it reuses the note's live client id after that client has moved past the base, the new ops reuse existing clocks. yrs then treats them as already known and drops them **silently**: `"abcXYZ"` merged to `"abcDEF"`. One fresh 53-bit id per PUT is safe. It does add one state-vector entry per PUT.
- The deterministic Wiki import (Decision 3) works. The same client id, base and page produce byte-identical records, and applying both yields a single copy. The derived id must be masked to 53 bits: `ClientID::new` only `debug_assert`s the range, so a release build would silently mis-encode a wider id.
- **Diff cost on a 4 MiB note.** A whole-text char diff (`similar::TextDiff::from_chars`) took **114 ms and +339 MiB of transient heap**. Diffing lines first, then char-diffing only the changed hunks, took **24 ms and +29 MiB** and produced an identical merged text. Use line-then-char diffing.
- Offsets: yrs defaults to `OffsetKind::Bytes`, and the diff must use the same unit. A future Yjs browser editor uses UTF-16. The spike used ASCII only; **non-ASCII merge positions are untested**.

### Convergence: CHANGES-NEEDED (yrs 0.28.0 out-of-order bug)

The workload is a 4 MiB (4,194,304 B) note. Author 0 loads it as 69 records of ≤ 61,457 B each, which keeps every record under the 64 KiB inline cap. Three replicas load it, and each then makes 1,000 random edits with no sync in between. 60 % of edits insert a unique token of 7–30 B; 40 % delete 1–16 B. Each edit is one transaction and one record. The replicas then exchange records.

| Exchange mode | Pending updates stuck | Texts equal | State byte-identical | Surviving tokens lost |
|---------------|:--:|:--:|:--:|:--:|
| in order | no | yes | yes | 0 / 1,800 |
| in order, 20 % duplicates | no | yes | yes | 0 |
| **shuffled** | **yes (2 of 3 replicas)** | **no** | encode **panics** | 1 |
| **shuffled, 20 % duplicates, 2-round partition** (the ADR's Validation test) | **yes (3 of 3)** | **no** | encode **panics** | 1 |
| shuffled + duplicates, **per-author seq gate** (apply `u/<author>/<seq>` only when `seq-1` is applied; dedup by key) | no | **yes** | **yes** | **0** |
| shuffled + duplicates, merged with `yrs::merge_updates_v1` then applied once | no | yes | yes | 0 |

Minimal repro (`repro`, 2,000 seeds, one author, 2–9 records, shuffled). Every one of these runs should converge:

- **243 / 2,000** diverge. The doc keeps `has_missing_updates() == true` after every record has arrived.
- With inserts only, **579 / 2,000** diverge.
- Re-applying all records in order afterwards still leaves **129 / 2,000** wedged. A wedged doc does not heal.
- Building records from a post-commit state-vector diff (`SVDIFF`) instead of `encode_update_v1` gives the same 243 failures, so the record encoding is not the cause.
- Calling `encode_state_as_update_v1` on a wedged doc **panics inside yrs** (`transaction.rs:408`, `merge_updates_v1(...).unwrap()` → `EndOfBuffer(1)`). A daemon would crash.

This matches open upstream issues y-crdt#670 ("Pending update is never applied after a skipped range is filled"), #582 and #673.

Cross-author causality (`causal`, 200 trials):

| Delivery policy | Diverged |
|-----------------|:--:|
| no gate | **157 / 200** |
| per-author seq gate | 0 / 200 |
| causal gate on a per-record dependency state vector | 0 / 200 |

The dependency state vector encodes to 7 B at the median and 10 B at the maximum.

What is required:

- Each record carries `deps`, the author doc's yrs state vector before the edit (≤ 10 B here).
- The notes store applies a record to yrs only when the local state vector covers `deps` and the author's `seq-1` is applied. Held records wait in a local buffer. yrs's internal pending path must never be used.
- After every apply, assert `!has_missing_updates()`. If it fails, rebuild the doc from the stored records in causal order rather than encoding state.

The ADR's convergence property test is the right test: it fails without the gate and passes with it.

### Sizes, memory and time (4 MiB × 3 replicas × 1k edits, seq-gated run)

| Metric | Value |
|--------|-------|
| Load | 69 records, 4,195,404 B total, ≤ 61,457 B each, 54 ms |
| Encoded state at base | v1 4,194,317 B; v2 4,194,334 B |
| Per-edit record size | median **29 B**, p99 49 B, max 49 B; 3,000 records = 75,952 B |
| 1,000 edits batched into one record (per-PUT granularity) | 19,601 / 20,509 / 20,322 B |
| Replica heap after load | 4.00 MiB (4,196,016 B) |
| Replica heap after all 3,069 records | **5.21 MiB** (5,457,968 B), for a skip_gc doc |
| Authoring doc heap (includes its 4 MiB of emitted records) | 12.01 MiB |
| Same records in a GC'ing doc | 5.20 MiB; state 4,274,398 B. The difference from `skip_gc` is small because only ~3k short ranges were deleted; the history cost grows with deleted bytes. |
| Exchange and apply time, 3 replicas | 19 ms; transient heap +2.6 MiB |
| Final text / encoded state | 4,219,224 B / **v1 4,284,669 B (over the 4 MiB cap)**; v2 4,262,839 B |
| `base_version` snapshot, encoded (4 clients, ~1.2k deletes) | **5,395 B** |
| Restore at a snapshot on another replica | 3.6 ms |
| Three-way PUT on the 4 MiB note | char diff 114 ms / +339 MiB; line-then-char diff 24 ms / +29 MiB; record 97 B |

## Q2: Binary-size delta: GO

Every variant was built with `cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin x0xd`: native linux x86_64 ELF, the default release profile and the default features the release workflow uses. The output ELF is already stripped (`llvm-strip` removes 0–192 B), matching the release job's `strip` step. The baseline was built twice with byte-identical sizes. yrs is confirmed linked: the strings `yrs-0.28.0` appear 12 times in the yrs binary and 0 times in the baseline.

| Variant | ELF bytes | Δ vs base | Δ % | gzip -9 bytes | Δ gzip |
|---------|----------:|----------:|----:|--------------:|-------:|
| base (`origin/main` b217215) | 59,923,720 | — | — | 23,254,017 | — |
| + yrs 0.28.0 (reachable) | 60,489,992 | **+566,272 (553 KiB)** | **+0.94 %** | 23,497,189 | +243,172 (+1.05 %) |
| + yrs + similar 2.7.0 (merge diff) | 60,578,888 | **+655,168 (640 KiB)** | **+1.09 %** | 23,548,282 | +294,265 (+1.27 %) |

The only new crates are `yrs`, `smallstr`, `arc-swap`, `async-lock`, `event-listener`, `event-listener-strategy`, `parking`, plus `similar` for the diff. This is far below the ADR's 2 MiB re-evaluation trigger, so there is no reason to revisit A2 (automerge).

## Q3: Provenance mark inside the sealed value

### Where the mark sits in the #914 envelope

```
gossip wire: bincode (PeerId, EncryptedKvStoreRecordV1)                                   plaintext
  EncryptedKvStoreRecordV1 { group_id, store_id[32], epoch u64, nonce[24], ciphertext }   plaintext
    ciphertext = XChaCha20-Poly1305( bincode SignedKvMutation )                           SEALED
      SignedKvMutation { group_id, store_id, epoch, author_id, author_pubkey(1952),
                         algorithm, kind, payload, signature(3309) }
        payload = bincode KvStoreDelta { added: { key -> (KvEntry, tag) }, … }
          KvEntry { key, value, content_hash, content_type, metadata, created_at, updated_at }
            value = NoteUpdateRecordV1 / ScratchValueV1   <- the mark goes here
```

The record key (`n/<note>/u/<author_hex>/<seq>`), the value and the entry metadata all sit inside the AEAD ciphertext. The mark needs **no new outer field**. The outer envelope is 84 B plus the length of `stable_group_id` beyond 4 B (the test group id was 4 B).

The wire-leak check scanned the exact bytes handed to publish, for a note record at seq 0 and at seq > 0 and for a rider scratch write. **None** of these appear: the note text, the note key, the author agent id (hex or raw), the author public key, the author signature, the scratch key or value, the `sub_agent_id` (hex or raw), and the rider token hash. As a control, a member opens each record: the record author matches the key segment, and the embedded `RiderProvenance` verifies with `verify_rider_provenance`.

Metadata that remains visible, as in #914 today:

- The topic `x0x/group/<gid>/kv/<store_id>`. Anyone who knows `gid` can compute which topic is `notes` and which is `scratch`.
- The epoch.
- The sender `PeerId`.
- **Ciphertext length.** A full `RiderProvenance` makes rider writes about 16 KB larger, and so identifiable by size. The compact mark avoids that.

### Why a per-record author signature is needed

`SignedKvMutation.author_id` is the **publisher** of a delta, not the author of each entry inside it. For `FullState` and `RetainedState` serves, the publisher is whichever writer serves. The candidate's `src/kv/sync.rs` merges a served delta with `Some(&mutation.author_id)` of the server (around L1654 and L4392). So "reject a record whose sealed inner author is not `<author_agent_hex>`" can only be checked on `Delta` publishes. After a serve, any current writer could place a record under another member's `u/<victim>/<seq>` key and take that seq, which loses the victim's real record under LWW.

The fix is a signature over the record, inside the value. The group roster (`GroupMember`) carries no ML-DSA public key, except `OwnerCertified` certificates. So the author's key travels once, in their seq-0 record for each note. The seq gate guarantees seq 0 is applied first.

### Proposed structs

```rust
/// VALUE of key `n/<note_id>/u/<author_agent_hex>/<seq>` in the group's `notes` store.
/// Lives only inside the sealed KvEntry.value.
#[derive(Serialize, Deserialize)]
pub struct NoteUpdateRecordV1 {
    pub author: [u8; 32],                 // == key segment, else reject
    pub seq: u64,                         // == key segment, else reject
    pub yrs_client: u64,                  // fresh 53-bit id per PUT/merge
    pub deps: Vec<u8>,                    // yrs v1 StateVector before the edit (causal gate)
    pub update: Vec<u8>,                  // yrs v1 update
    pub author_pubkey: Option<Vec<u8>>,   // ML-DSA-65 key, only when seq == 0
    pub author_sig: Vec<u8>,              // ML-DSA-65 over "x0x.notes.update-record.v1"
                                          //   || store_id || key || blake3(bincode(fields above))
}

/// Rider mark for `scratch` writes (riders never reach notes, Q4).
#[derive(Serialize, Deserialize)]
pub struct RiderMarkV1 {
    pub sub_agent_id: [u8; 32],
    pub rider_token_id: u64,
    pub delegation_digest: [u8; 32],      // blake3 of the sub-agent-signed delegation payload
}

/// VALUE of a key in the group's `scratch` store.
#[derive(Serialize, Deserialize)]
pub struct ScratchValueV1 {
    pub data: Vec<u8>,
    pub rider: Option<RiderMarkV1>,
}
```

For scratch, the full verifiable `RiderProvenance` should be written **once per rider** as a write-once key `r/<sub_agent_hex>/<digest>` in the same store. `delegation_digest` points to it, and receivers verify and cache it. If attribution must survive a serve (the same publisher-versus-author issue as notes), the member daemon adds a `writer_sig` over `(key, blake3(data), mark)`. That is computed at 3,421 B for the mark; it was not measured.

### Byte sizes (bincode, measured)

| Item | Bytes |
|------|------:|
| ML-DSA-65 public key / signature | 1,952 / 3,309 |
| yrs update (one 60-char insert) / `deps` | 67 / 1 (≤ 10 with 3 authors) |
| `NoteUpdateRecordV1`, seq 0 (with pubkey) / seq > 0 | 5,410 / 3,450 |
| Mark overhead over a bare update, seq 0 / seq > 0 | +5,335 / **+3,375** |
| Wire record, bare update (ADR as written) | 5,967 (sealed delta payload 461 B; ciphertext 5,851 B) |
| Wire record, `NoteUpdateRecordV1` seq > 0 / seq 0 | 9,355 / 11,315 |
| Largest yrs update that fits the 64 KiB inline cap with the mark | 62,153 (65,536 bare) |
| `RiderProvenance`, full (base64 cert + hex sig) | **16,706** |
| `RiderMarkV1`, compact | **72** |
| `ScratchValueV1` with 41 B of data: no rider / compact / full | 50 / 122 / 16,756 |
| Scratch wire record with a full inline `RiderProvenance` | 22,483 |

**Verdict:** the mark fits and stays confidential (**GO**). The per-record signature costs about 3.4 KB per record, so records must stay at per-PUT granularity (one record per merge, 97 B to 20 KB of update), not per keystroke. At 29 B per keystroke the signature would be about 116× the payload.

## ADR points the evidence contradicts

1. **"Updates are commutative and idempotent, so replicas holding the same key set derive the same text"** (Decision 1). This is false for yrs 0.28.0 when records are applied in arrival order. 12–29 % of shuffled single-author sequences wedge, and the ADR's own convergence test diverges. It is true only under causal delivery. The ADR needs a `deps` state vector in each record and a causal apply gate.
2. **"A receiver rejects an update record whose sealed inner author is not `<author_agent_hex>`"** (Decision 1). The sealed inner author is the publisher, and after a full-state or retained serve that is the server. The check needs a per-record author signature inside the value (≈ 3.4 KB, plus 1.95 KB once per author per note).
3. **"the cap keeps the retained serve under 16 MiB"** (Decision 1). The cap is per note, but a group has **one** `notes` store for all its notes, and the retained image limit (`MAX_RETAINED_IMAGE_BYTES = 16 MiB`, `src/kv/retained_paging.rs:14`) is per store. The image also holds every record (with per-record signatures and KV entry overhead), not compacted state. Four notes near the cap already exceed it. The ADR needs a per-store budget, per-note stores, or compaction first.
4. **"`version` is an encoded `yrs` snapshot"** (Decision 2). It works, but:
   - The token grows with the delete set and with one client id per PUT (5,395 B after ~3k edits).
   - Restoring it on a replica that lacks records returns silently wrong text.
   - The ADR should say the daemon checks coverage (409 otherwise). It should consider an opaque short `version` that maps to a daemon-held snapshot, or a per-author max-seq vector that the gate makes exact.
5. **Import client id `hash(note_id ‖ page digest ‖ base version)`** (Decision 3) must be truncated to 53 bits. yrs does not enforce this in release builds.

These points do not contradict the ADR and should carry into Slice 2:

- Use line-then-char diffing for the merge.
- Use a fresh client id per merge.
- Create every doc with `skip_gc: true`, and never ingest foreign state blobs.
- Note that a note at the 4 MiB cap exceeds it after about 3k small edits (4,284,669 B). The 413 will fire on history growth, not only on visible text.

## Artefacts

The spike crates and build directories lived in the session scratchpad and have been deleted. No measurement code is committed. The 60-line `repro` for the yrs out-of-order bug is the only piece worth keeping, perhaps as an upstream bug report or a future regression test. It will be added only if asked.
