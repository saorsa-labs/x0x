# ADR 0075: Collaborative Notes Use a yrs Text CRDT in the Group Store; Agent Scratchpads Are a Rider-Reachable Group Store

- **Status:** Accepted
- **Accepted:** 2026-09-25 by David Irvine (decisions Q1–Q6; status change applied by Claude at his instruction)
- **Date:** 2026-09-25
- **Decision owners:** David Irvine (acceptance); Claude (drafting)
- **Reviewers:** cross-model (omp) review required; acceptance by David Irvine only
- **Supersedes:** none
- **Superseded by:** none
- **Extends:** ADR 0047 (KV store) and ADR 0039 (rider boundary). It edits neither: it adds
  a value encoding on top of 0047 and one named allow-list entry to 0039.
- **Vision requirement:** R9 (CRDT shared notes for humans, scratchpads for agents);
  also R6 (cross-machine scratchpads) and R10 (#893 deep links to a note).
- **Related:** #895 / PR #914 (sealed group task lists), #893 (GUI deep links), ADR 0010
  (GSS plane), 0048 (task lists), 0052 (embedded GUI), 0072 (scope freeze);
  `docs/design/encrypted-kvstore.md`; `.planning/adr-vision-alignment-2026-09-25.md`

## Context

On `origin/main` today:

- **Notes lose concurrent edits.** The GUI Wiki (`saveWikiPage`, `src/gui/x0x-gui.html`)
  PUTs the whole page as one value (`PUT /stores/:id/:slug`). ADR 0047 makes each key an
  LWW register, so when two members edit one page, one edit is discarded without notice.
- **There is no sequence or text CRDT.** saorsa-gossip `crdt-sync` (pinned `=0.5.84`)
  ships `OrSet`, `LwwRegister` and `VectorClock`; `CrdtType::Rga` is an unimplemented
  enum tag (`src/crdt/task_list.rs` says so). Neither `yrs` nor `automerge` is a dependency.
- **Group stores are already sealed.** `POST /groups/:id/stores {name}` stores in
  `MlsEncrypted` groups sign-then-encrypt every publication (`src/kv/encrypted.rs`, GSS
  and TreeKEM); PR #914 reuses these envelopes for task lists. `SignedPublic` stores are
  plaintext by policy. Values cap at 64 KiB inline; a retained full-state serve at 16 MiB.
- **No scratchpad; riders cannot reach stores.** `rider_route_allowed` allows only
  group send, secure encrypt and `GET /history`; store handlers check `rider_allows_group`,
  but the middleware returns 403 first.

## Decision Drivers

- R9: concurrent edits converge **with no silent loss**, even within one paragraph.
- Confidentiality must match group stores and #914: same envelope, no new crypto.
- Reuse the shipped 0047 replication; do not build a second sync engine.
- Keep ADR 0039 deny-by-default. Any rider widening must be named, scoped and testable.
- Keep the embedded GUI a single file with no JS bundler (ADR 0052).

## Considered Options

**Text for notes and wiki pages**

1. **(A1) `yrs` (Rust Yjs, MIT, 0.28.0).** Mature sequence CRDT; Yjs-compatible updates
   for a later browser editor; snapshots give the "state at version X" a merge needs.
2. **(A2) `automerge` (MIT, 0.12.0).** Mature, larger (410 KB vs 286 KB source), a JSON
   document model notes do not need, and no match for a future Yjs editor.
3. **(A3) In-house RGA in saorsa-gossip.** Proving a sequence CRDT is the costly, risky
   part, and we would own every interleaving bug.
4. **(B) Per-paragraph LWW.** Simple, but same-paragraph edits still lose one side.
5. **(C) Keep LWW and add conflict copies.** Nothing is lost, but humans merge by hand,
   agents multiply the copies, and the text never converges to one version.

**Scratchpads:** (S1) a dedicated `scratch` group store that riders can reach with a new
per-group scope; (S2) riders reach any store of a granted group (exposes the human Wiki
and notes); (S3) a new non-KV scratchpad type (duplicates 0047).

## Decision

We will adopt **A1 (`yrs`) for notes, carried inside the existing encrypted group
store, and S1 for scratchpads.**

1. **Note storage.** Each group has one note store, `name = "notes"`, opened through the
   existing group-store path and therefore sealed exactly like the Wiki store and #914.
   A note is a `yrs` `Doc` with one `Text` root, stored as **write-once update records**:
   - `n/<note_id>/meta`: title and creator, as an LWW value (a rename race is acceptable).
   - `n/<note_id>/u/<author_agent_hex>/<seq>`: one `yrs` v1 update (≤ 64 KiB; larger
     ones are split). Each key is written once by its author, so the 0047 OR-Set
     **unions** the records and no edit is overwritten. Updates are commutative and
     idempotent, so replicas holding the same key set derive the same text.
   - **Author binding:** a receiver rejects an update record whose sealed inner author
     is not `<author_agent_hex>` (the group write rule alone does not prevent this).
   - **Size bound:** a note's encoded state is capped at 4 MiB. Past the cap, writes
     return 413. Compaction (a covering snapshot and author-deleted records) is deferred
     to a later slice; the cap keeps the retained serve under 16 MiB.
2. **Note API** (owner token; existing membership and write-policy checks):
   `GET|POST /groups/:id/notes`, `GET /groups/:id/notes/:note` → `{title, text, version}`,
   `PUT /groups/:id/notes/:note {text, base_version}`. `version` is an encoded `yrs`
   snapshot. On PUT, the daemon rebuilds the text at `base_version` (history is kept, i.e.
   `skip_gc`), computes a character diff from that text to the submitted text, applies
   the diff as `yrs` ops on the base state, and merges the result into the current doc.
   Plain-text clients (GUI, `curl`, agents) get a real three-way merge without running a
   CRDT. The response carries the merged text and new version. CLI: `x0x notes …`.
3. **Wiki.** The Space Wiki moves to notes, following #914's board move and the
   legacy-page import precedent (`src/server/legacy_store_migration.rs:180-197`). Each
   upgraded daemon with write permission imports its **local** legacy copy under an
   idempotency key bound to `(group, source store, source digest)`, with a durable
   intent snapshot and receipt. A matching receipt makes a retry a no-op; a changed
   digest imports **once more**, three-way merging each changed page onto its
   previously imported text. Import updates use a `yrs` client id derived from
   `hash(note_id ‖ page digest ‖ base version)` under key `n/<note>/u/import/<page
   digest>`, so two daemons importing the same page state emit identical records and
   the text is not duplicated. The legacy store is kept, never deleted. After the
   marker, an upgraded daemon refuses writes to it (Q7): `PUT`/`DELETE
   /stores/:id/:key` on a migrated Wiki store return **409 Conflict**
   `{"error":"wiki_migrated_to_notes","message":"this wiki was migrated to notes;
   upgrade to edit"}`. The GUI already keeps the draft on a failed save.
4. **Scratchpads.** Each group has one scratch store, `name = "scratch"`. It is ordinary
   0047 KV (LWW per key, sealed), because agents use it for keyed working state. Agents
   that need merged text use notes. Scratchpads replicate to every member's daemon, so an
   agent on machine A and a rider on machine B (through its own owner's daemon)
   share it (R6).
5. **ADR 0039 allow-list change (exact).** Rider tokens gain an optional per-group scope,
   `scratch: none | read | read_write`, which defaults to `none`, so existing tokens are
   unchanged. `rider_route_allowed` admits these routes, and nothing else:
   - `POST /groups/:id/stores`: the handler accepts only `name == "scratch"` from a rider.
   - `GET /stores/:id/keys` and `GET /stores/:id/:key`: need `read` or higher.
   - `PUT /stores/:id/:key` and `DELETE /stores/:id/:key`: need `read_write`.

   Each `/stores/:id/*` handler resolves `:id` and returns 403 unless the store is the
   `scratch` store of a granted group and the scope suffices. A rider never reaches
   `notes`, `wiki`, `web`, personal stores or task lists. The daemon writes as its member
   agent with the rider provenance mark (`sub_agent_id`) inside the sealed value.
6. **GUI deep links (R10).** The GUI routes `#/note/<group_id>/<note_id>` and
   `#/scratch/<group_id>`, so #893's `POST /gui/show` / `x0x show note/<g>/<n>` can
   show a note to the human. The editor keeps the textarea. It sends `base_version`, and
   after a save it shows the merged text with an "updated by others" notice when the
   merged text differs from what the user typed.

**Non-goals now:** live cursors, presence and keystroke streaming (later, once a browser
Yjs binding can be vendored without a bundler); rich media embeds (later, ADR 0055
transfers referenced by hash); compaction and history UI (later, before any note nears
the cap); rider access to notes (not granted; Q4).

## Consequences

### Positive

- Concurrent note edits converge and nothing is dropped silently (the R9 audit gap).
- No new transport, sync engine or crypto; notes inherit #914's epoch/rekey behaviour.
- Scratchpads give agents a cross-machine working area under an explicit, revocable scope.

### Negative / Trade-offs

- New dependency (`yrs` and transitive crates). Measure binary growth in slice 1; if
  release `x0xd` grows by more than 2 MiB, re-evaluate A2 before continuing.
- Diff-based merge can place an ambiguous insert (e.g. inside repeated characters)
  away from where the user meant. The text is preserved; the position may surprise.
- Full history grows notes until compaction ships; the 4 MiB cap makes this an explicit error.
- First rider allow-list widening since ADR 0039; a store-name check bug would expose
  human stores, so the scope matrix test is mandatory.
- **Mixed versions (Q7):** an **old** node has no check and can still write its local
  legacy Wiki copy. Those writes are visible only to other old nodes until they upgrade;
  upgraded nodes neither show nor accept legacy writes. On upgrade, the digest-keyed
  import (Decision 3) picks up post-marker legacy changes in that node's copy exactly
  once, so they are imported rather than lost. A change that never reaches an upgrading
  node's copy stays in the kept legacy store, readable but not merged.

### Neutral / Operational

- `MlsEncrypted` notes are sealed; `SignedPublic` notes are public by policy (as #914).
- **Effort (honest):** about 5–7 agent-weeks. Slice 1: `yrs` spike, size check, note
  model and property tests (1.5–2 wk). Slice 2: note REST/CLI and merge (1–1.5 wk).
  Slice 3: Wiki migration, legacy write refusal, GUI notes and deep links (1–1.5 wk).
  Slice 4: scratch store and rider scope (1 wk). Slice 5: e2e and docs (0.5–1 wk).
  Slices 1–2 and 4 are independent. All wait for the R17 freeze to lift.

## Validation

- **Convergence property test (slice 1):** N ∈ 2..6 replicas apply random concurrent
  insert and delete sequences, then exchange update records in random order with
  duplicates and partitions. All replicas end byte-identical, and every character not
  explicitly deleted is present. Control: the old whole-value LWW path must fail it.
- **Three-way merge test:** two PUTs from the same `base_version` that edit the **same
  paragraph** must both survive in the merged text.
- **Author binding:** a record under another member's author segment is rejected.
- **Wire test (ciphertext only):** capture the exact bytes handed to `pubsub.publish` for
  a note update and a scratch write in an `MlsEncrypted` group: no note text, key or
  value appears; a member opens the record as control (as #914's wire test).
- **Rider scope matrix:** `none`, `read` and `read_write` × `scratch`, `notes`, `wiki`,
  a personal store and an ungranted group's scratch; only granted cells pass, the rest
  return 403 (extends `rider_routes_allow_exactly_send_secure_encrypt_and_history`).
- **Legacy write refused (Q7):** after the marker, an upgraded node's `PUT` to the Wiki
  store returns 409 `wiki_migrated_to_notes` and the store is unchanged.
- **Pre-upgrade change imported once (Q7):** a legacy page edited after another node's
  marker is imported on this node's upgrade; a retry and a second node importing the
  same state leave exactly one copy of the edit in the note.
- **Cross-machine e2e (R6):** a rider on machine B writes scratch; an agent on A reads it.
- **Review trigger:** a live-cursor editor is scheduled, or a note reaches the cap.

## Decisions (David Irvine, 2026-09-25)

These answers settle the open questions; David accepted the ADR with Q1–Q6.
1. **Text CRDT:** `yrs` (with the 2 MiB binary-growth stop rule).
2. **Plain-text editing:** the daemon performs the three-way merge from `base_version`.
3. **Wiki:** one-time import of each legacy page as a note; the old store stays read-only.
4. **Riders:** scratchpads only, per-group scope defaulting to `none`; no note access.
5. **Scratchpad model:** plain LWW KV (0047).
6. **Note size:** 4 MiB cap (413 beyond it); compaction deferred to a later slice.
7. **Q7 (David Irvine, 2026-09-26) — legacy Wiki writes:** "Reject old writes with upgrade
   message." After migration, upgraded nodes return 409 `wiki_migrated_to_notes`; old
   nodes' writes are imported once on their upgrade (Decision 3). Nothing is silently lost.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
