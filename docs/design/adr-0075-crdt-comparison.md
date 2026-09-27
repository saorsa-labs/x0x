# ADR-0075 CRDT Comparison: yrs, automerge, loro, diamond-types

- **Issue:** #965 (ADR-0075 Slice 1, follow-up to `adr-0075-slice1-spike.md`)
- **Date:** 2026-09-27
- **Why:** after the Slice 1 spike found that yrs 0.28.0 fails to converge when records arrive out of order, David Irvine asked for yrs to be reconsidered against the alternatives before anything is committed. The yrs repro stays internal; nothing was posted upstream.
- **Kind:** measure-and-report spike. No dependency was added to x0x's `Cargo.toml` on any pushed branch.
- **Machine and toolchain:** Apple M5 Max, 128 GiB, rustc 1.95.0, `cargo zigbuild` for linux x86_64. Size baseline is `origin/main` @ `b217215`.

## Recommendation

**Stay with yrs, and make the causal apply gate a mandatory part of the notes store.** Keep **loro** as the named fallback if the gate proves fragile in Slice 2. Reject automerge and diamond-types.

The reasoning:

1. **The ADR's own stop rule excludes two of the three alternatives.** ADR-0075 says to re-evaluate if `x0xd` grows by more than 2 MiB. Measured growth: automerge +2.33 MiB, loro +3.57 MiB. yrs is +0.58 MiB and diamond-types +0.20 MiB.
2. **automerge and loro are the only engines that converge with no gate.** Both scored 0 of 2,000 single-author and 0 of 200 cross-author divergences, with no panics. That is their real advantage over yrs.
3. **The yrs gate works and is cheap.** With it, yrs had 0 of 200 cross-author divergences, the same as automerge and loro. It costs about 10 B per record, and the notes store already needs a per-record struct for author signatures.
   - The gate keeps yrs off its broken pending-update path entirely. yrs only ever integrates updates whose dependencies are already present, which is the path every Yjs sync provider uses.
   - Without the gate, yrs diverges in 230 of 2,000 single-author and 162 of 200 cross-author trials.
4. **yrs wins every resource measurement on a 4 MiB note:**
   - Heap: 5.2 MiB, against 18 MiB for loro and about 1.3 GiB for automerge.
   - Per-edit record: 28 B, against 109 B for loro and 136 B for automerge.
   - Three-way merge on a PUT: 23 ms, against 594 ms for loro and 4.4 s for automerge.
5. **diamond-types is not viable as published.**
   - Its only crates.io release, 1.0.0, dates from 2022-08-25. Active development is on an unreleased 2.0 in git, and x0x is published to crates.io, so it cannot take a git dependency.
   - In 1.0.0, `encode_from(version)` emits the whole document's inserted content: each one-edit record on the 4 MiB note is about 1.8 MB, far above the 64 KiB inline cap.
6. **automerge fails on cost:**
   - About 648 MiB of heap per replica just to hold the loaded 4 MiB note, and +3.5 GiB of transient heap for one `update_text` merge.
   - Rebuilding a replica from all 3,069 records in author order did not finish in 25 minutes.
   - Its binary delta already exceeds the stop rule.

yrs's weaknesses remain, and the implementation must own them:

- **An open, unfixed upstream bug class in pending updates.** The gate avoids it, but a regression test must prove the gate never lets yrs reach the pending state.
- **Slow restore of old versions.** Restoring the pre-edit version of the 4 MiB note took 5.6–6.1 s, against 38 ms for loro. Merges against a recent `base_version` are fast (23 ms).
- **No built-in text diff.** We supply one (`similar`, Apache-2.0, +87 KiB).

**Switch to loro** if David prefers "robust with no gate" over binary size and memory. That means accepting +3.6 MiB of binary, about 3.4× the heap, MPL-2.0 transitive crates, and loro's open import-panic issues (see Q-f).

## Comparison table

| | **yrs 0.28.0** | **automerge 0.12.0** | **loro 1.16.2** | **diamond-types 1.0.0** |
|---|---|---|---|---|
| **(a) No gate: single-author, 2,000 shuffled + dup + partition** | **230 diverged**, 245 stuck | 0 | 0 | 1,788 diverged (rejects with an error, drops) |
| **(a) No gate: cross-author, 200** | **162 diverged** | 0 | 0 | 200 diverged (rejects) |
| (a) With a minimal policy | causal gate: **0 / 200** | not needed | not needed | retry-on-error: 0 / 2,000, 0 / 200 |
| (a) Panics (small trials) | 0 (but `encode_state` on a wedged 4 MiB doc panicked in the first spike) | 0 | 0 | 0 |
| **(b) 4 MiB, 3 × 1k edits: converged** | yes with gate (no without) | yes, no gate | yes, no gate | yes with seq gate |
| (b) Heap per replica, loaded → after 3,069 records | **4.0 → 5.2 MiB** | 648 MiB → ≈1.3 GiB | 8.3 → 17.9 MiB | 7.5 → 7.8 MiB |
| (b) Per-edit record, median / p99 | **28 / 49 B** | 136 / 156 B | 109 / 119 B | **≈1.8 MB** (whole doc) |
| (b) Full state after edits (text 4,219,374 B) | 4,284,669 B (uncompressed) | **783,198 B** (compressed) | 3,709,075 B | 1,840,124 B |
| (b) Exchange of 2,000 records per replica | 0.08 s | 23 s | 0.68 s | 30 s |
| (b) Authoring the 69 × 60 KiB load records | 0.07 s | 1.7 s | 0.009 s | 0.35 s |
| (b) 3 replicas applying the load records | not timed separately (whole run ≈ 8 s) | **≈ 51 s** | not timed separately (whole run ≈ 8 s) | 0.5 s |
| **(c) Restore an earlier version** | yes, needs `skip_gc`; **5.6–6.1 s** for the pre-edit 4 MiB version; token 5,326 B | yes (`text_at(heads)`), 0.20 s; token 32 B per head | yes (`checkout`), **0.04 s**; token 6–13 B | yes (`checkout`), 0.003 s; token 11–36 B |
| (c) History cost | all history kept; state +1.5 % over the text | all history kept (compressed) | all history kept; shallow and state-only exports exist | all history kept |
| **(d) Same-sentence three-way merge** | both survive (external diff) | both survive (`fork_at` + `update_text`) | both survive (`fork_at` + `LoroText::update`) | both survive (`checkout` branch + external diff) |
| (d) Merge PUT on the 4 MiB note | **23 ms**, +20 MiB transient | 4.4 s, **+3.5 GiB** transient | 0.59 s, +51 MiB (`update_by_line`) | 0.19 s, +29 MiB; record 1.8 MB |
| **(e) x0xd linux x86_64 delta** | **+589,824 B (+0.98 %)** | **+2,388,272 B (+3.99 %) — over 2 MiB** | **+3,659,736 B (+6.11 %) — over 2 MiB** | +203,936 B (+0.34 %) |
| **(f) Last release** | 2026-09-17 (0.28.0) | 2026-09-16 (0.12.0) | 2026-09-21 (1.16.2) | **2022-08-25 (1.0.0)**; 2.0 unreleased |
| (f) Relevant open correctness issues | #670, #582, #673 (pending and out-of-order); 12 bug-labelled | #1187 (panic after `migrate_actors`), #1351 (decode panic at ≥2^23 B of string data in a change, WASM) | #1118 (reused peer id panics and poisons the doc), #1068 (import panic after a shallow snapshot), #1046, #793 | #50 (`load_from` panics on malformed bytes) |
| (f) License (crate / transitive) | MIT / all permissive | MIT / all permissive (Zlib included); depends on `hexane 1.0.0-alpha.5` | MIT / **MPL-2.0** in `im`, `bitmaps`, `sized-chunks` | ISC / **MPL-2.0** in `smartstring` |
| (f) License gate | **pass** | **pass** | **pass** (MPL-2.0 is file-level, AGPL/GPL-compatible, permits proprietary larger works) | **pass** |
| **Verdict** | **Recommend (with gate)** | Reject: size, memory, merge cost | Fallback: robust, but over the size rule and 3.4× heap | Reject: stale crates.io release, 1.8 MB records |

## Method

The harness is the same one used in the first spike, generalised behind a trait with one implementation per engine. Each engine exposes the same operations:

- `ins` / `del`: one edit, returning one record.
- `apply`, `text`, `full`, `version`, `text_at`.
- `merge_put`: rebuild the text at a version and apply a plain-text writer's new text.

All engines ran the identical workload with the same seeds. Heap was measured with a counting global allocator.

- **(a) Delivery.** Records are shuffled, 20 % are duplicated, and they are delivered in two partitions. This is the ADR's Validation test.
  - The 2,000 single-author trials each apply 2–9 records onto a base text.
  - The 200 cross-author trials have 3 authors doing 15 rounds of edits. Authors sync pairwise by pulling each other's full state. A fresh observer then receives every per-edit record in random order.
  - "No gate" means records are applied in arrival order.
  - "Retry-on-error" keeps any rejected record and retries it after each successful apply. It needs no metadata.
  - "Causal gate" is the yrs gate from the first spike: each record carries a dependency state vector and is applied only once its dependencies are present.
  - Every trial runs inside `catch_unwind` and also calls the full-state encode, as a serving daemon would.
- **(b) The 4 MiB workload is identical to the first spike.**
  - Author 0 loads the note as 69 records of 60 KiB each.
  - Three replicas each make 1,000 random edits: 60 % token inserts and 40 % deletes of 1–16 characters.
  - The replicas then exchange records with shuffling, duplicates and partitions.
  - For diamond-types, the 4 MiB run used the per-author sequence gate. Without it, the reject-and-retry exchange had not finished after 20 minutes and held 19–21 GB of RSS.
- **(c)** `text_at` of the pre-edit base version on a replica that had not taken that version itself.
- **(d)** Two PUTs from the same base edit the same sentence; the check is that both edits survive. Then one PUT against the current version of the 4 MiB note is timed.
- **(e)** `cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin x0xd`, with each engine as an optional dependency behind its own feature. A feature-gated code path in `x0xd` `main()` makes create, edit, export, import, time-travel and merge reachable. Linking was confirmed by crate-path strings in each binary: yrs 12, automerge 70, loro 115, diamond-types 20, baseline 0.
  - The binaries are already stripped (see the first spike).
  - The baseline was rebuilt for this comparison: 59,924,552 B, against 59,923,720 B an hour earlier, because the lockfile is gitignored and re-resolves.
  - Gzip -9 deltas: yrs +1.12 %, automerge +4.11 %, loro +6.62 %, diamond-types +0.45 %.
- **(f)** Sources:
  - crates.io API: release dates and licenses.
  - GitHub API: last push and open issues.
  - `cargo tree -f '{p}|{l}'` over each engine's normal dependencies.
  - API usage checked against Context7 (`/y-crdt/y-crdt`, `/automerge/automerge`, `/loro-dev/loro`, `/websites/rs_diamond-types`) and each crate's 0.28.0 / 0.12.0 / 1.16.2 / 1.0.0 source.

**License note.** x0x's crate manifest currently declares `MIT OR Apache-2.0`; the brief asked about AGPL-3.0 plus commercial dual licensing.

- Every engine and every transitive crate is permissive, except the MPL-2.0 crates noted in the table.
- MPL-2.0 is compatible with (A)GPL-3.0 under its §3.3 secondary-license clause, and it allows proprietary distribution of a larger work, provided the MPL-covered source files are made available.
- x0x already ships MPL-2.0 dependencies today (`attohttpc`, `option-ext`), so no candidate fails the license gate.

**Caveats.**

- Timings come from one run on a fast desktop.
- For automerge, "after all records" heap is an estimate: load heap plus measured growth during the exchange. The fresh-replica rebuild used for the other engines had not finished after 25 minutes; this was not root-caused.
- All text was ASCII, so position-unit differences between engines (bytes, code points, UTF-16) were not exercised.

## What each choice changes in ADR-0075

### yrs with the causal gate (recommended)

Decision A1 stands, with these changes. These are the corrections already listed in `adr-0075-slice1-spike.md`.

- **Decision 1.** Each record's sealed value is `NoteUpdateRecordV1`: author, sequence number, yrs client id, dependency state vector, the update, and a per-record ML-DSA-65 signature. The daemon applies a record only when its dependencies are covered, and asserts `!has_missing_updates()` after every apply, rebuilding the doc from records on failure. "Updates are commutative and idempotent" becomes "…under causal delivery".
- **Decision 2.** The merge doc uses a fresh client id. Diffing is line-then-char, with `similar` as a dependency. Restoring a snapshot requires the local state vector to cover it (409 otherwise). All docs are `skip_gc`.
- **Validation.** Add a regression test that the gate never lets yrs reach its pending state, using shuffled, duplicated and partitioned delivery.
- **Consequences.** Binary size is +0.58 MiB for yrs, plus 0.09 MiB for the diff crate. Restoring an old base version is slow (seconds on a 4 MiB note), so keep `base_version` recent. Consider an opaque short version that maps to a daemon-held snapshot.

### loro (fallback)

This replaces A1 with a new option that needs a superseding decision, because loro breaks the ADR's own 2 MiB stop rule (+3.57 MiB).

- **Decision 1.** The record carries a loro update (`export(ExportMode::updates(vv))`). No causal gate is needed, since loro queues and heals pending changes itself. The author signature, per-record struct and store layout are unchanged.
- **Decision 2.** `version` becomes encoded `Frontiers` (6–13 B). The merge becomes `fork_at(base)` → `set_peer_id(fresh)` → `LoroText::update` / `update_by_line` → export. There is no external diff crate, and no `skip_gc` precondition.
- **Decision 3.** The deterministic import client id becomes a deterministic loro `PeerID`, a 64-bit hash. Peer ids must never be reused, or #1118 panics and poisons the doc, so the daemon must treat peer-id allocation as a hard invariant.
- **Consequences.** About 3.4× the heap of yrs per open note (18 MiB at 4 MiB of text), 109 B per-edit records, and MPL-2.0 transitive crates to list in the notice file. Yjs wire compatibility for a future browser editor is lost; loro has its own JS/WASM package instead.
- **Negative.** Loro's import path has open panic issues (#1118, #1068, #793). The daemon would need to wrap imports in `catch_unwind` and rebuild on poison.

### automerge (not recommended)

This would also need a superseding decision; the ADR already listed it as A2.

- Record = `save_after(heads)` (136 B per edit). Version = the change hashes (32 B each). Merge = `fork_at` + `update_text`. No gate is needed.
- The costs rule it out:
  - +2.33 MiB of binary, over the stop rule.
  - About 648 MiB of heap to hold a 4 MiB note, and +3.5 GiB transient for one merge.
  - About 17 s to load each replica from the 69 load records.
- The 4 MiB cap would have to fall by more than an order of magnitude to be safe. automerge's full state is the smallest, though (783 KB compressed), which would help the retained-serve budget.

### diamond-types (not viable)

- The crates.io release is four years old, and 2.0 is git-only; x0x cannot publish with a git dependency.
- 1.0.0 records carry the whole document (about 1.8 MB per edit on a 4 MiB note), which breaks the 64 KiB inline cap.
- Reconsider only if 2.x is published to crates.io with bounded incremental patches.

## Artefacts

The harness (`cmp965`), the size-build copy of x0x and every target directory lived in the session scratchpad and have been deleted. The yrs out-of-order repro is kept internal: it is not posted upstream and not committed.
