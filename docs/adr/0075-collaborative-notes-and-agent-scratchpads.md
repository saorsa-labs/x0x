# ADR 0075: Collaborative Notes Use a yrs Text CRDT in the Group Store; Agent Scratchpads Are a Rider-Reachable Group Store

- **Status:** Proposed
- **Date:** 2026-09-25
- **Decision owners:** David Irvine (acceptance); Claude (drafting)
- **Reviewers:** cross-model (omp) review required; acceptance by David Irvine only
- **Supersedes:** none
- **Superseded by:** none
- **Extends:** ADR 0047 (KV store) and ADR 0039 (rider boundary). It edits neither: it adds
  a value encoding on top of 0047 and one named allow-list entry to 0039.
- **Vision requirement:** R9, "CRDT data sharing works, for humans to have shared
  notes/projects etc and agents have scratchpads for collaboration". Also R6 (agents
  collaborate across machines, via scratchpads) and R10 (an agent shows a note to its
  human, via #893 deep links).
- **Related:** #895 / PR #914 (sealed group task lists), #893 (GUI deep links), ADR 0010
  (GSS plane), 0048 (task lists), 0052 (embedded GUI), 0072 (scope freeze);
  `docs/design/encrypted-kvstore.md`; `.planning/adr-vision-alignment-2026-09-25.md`

## Context

On `origin/main` today:

- **Notes lose concurrent edits.** The GUI Wiki (`saveWikiPage`, `src/gui/x0x-gui.html`)
  PUTs the whole page as one value (`PUT /stores/:id/:slug`, `text/markdown`). ADR 0047
  makes each key an LWW register (highest `updated_at`, hash tie-break), so when two
  members edit the same page, one member's edit is discarded without notice. ADR 0047
  names this as a trade-off.
- **There is no sequence or text CRDT.** saorsa-gossip `crdt-sync` (pinned `=0.5.84`)
  ships `OrSet`, `LwwRegister` and `VectorClock`. `CrdtType::Rga` is an enum tag with no
  implementation. `src/crdt/task_list.rs` says so and orders tasks with
  `LwwRegister<Vec<TaskId>>`. Neither `yrs` nor `automerge` is in the lock file.
- **Group stores are already sealed.** `POST /groups/:id/stores {name}` opens a group
  store. For `MlsEncrypted` groups, every publication is sign-then-encrypt
  (`EncryptedKvStoreRecordV1` on GSS, `TreeKemGroupStoreProtector` on TreeKEM; see
  `src/kv/encrypted.rs`). PR #914 reuses these same envelopes for task lists.
  `SignedPublic` groups use plaintext public stores by policy. Inline values are capped at
  64 KiB (`MAX_INLINE_SIZE`), and a retained full-state serve at 16 MiB.
- **There is no scratchpad, and riders cannot reach stores.** `rider_route_allowed`
  (`src/server/rider_auth.rs`) allows exactly `POST /groups/:id/send`,
  `POST /groups/:id/secure/encrypt` and `GET /history`. The store handlers already check
  `rider_allows_group`, but the middleware returns 403 before they run.

## Decision Drivers

- R9: concurrent edits to one note must converge **with no silent loss**, including
  edits inside the same paragraph.
- Confidentiality must match group stores and #914: same envelope, same epoch rules,
  no new crypto.
- Reuse the shipped replication (0047 OR-Set + delta gossip + state-sync). Do not build a
  second sync engine during the R17 freeze aftermath.
- Keep ADR 0039 deny-by-default. Any rider widening must be named, scoped and testable.
- Keep the embedded GUI a single file with no JS bundler (ADR 0052).

## Considered Options

**Text for notes and wiki pages**

1. **(A1) `yrs` (Rust port of Yjs, MIT, 0.28.0).** A mature sequence CRDT (YATA). Its
   update format is Yjs-compatible, so a later browser editor could speak it natively.
   Snapshots support "state as of version X", which a three-way merge needs.
2. **(A2) `automerge` (MIT, 0.12.0).** Also mature, with a larger crate (410 KB source vs
   286 KB) and a whole-document JSON model that notes do not need. It has no
   off-the-shelf match for a future Yjs-based editor.
3. **(A3) An in-house RGA in saorsa-gossip.** It would fill the empty `CrdtType::Rga`,
   but writing and proving a sequence CRDT is the expensive, risky part, and we would
   own every interleaving bug.
4. **(B) Per-paragraph LWW.** This is simple, but two edits to the same paragraph still
   lose one of them. It fails the driver.
5. **(C) Keep LWW and add conflict copies.** Nothing is lost, but a human must merge by
   hand, and agents writing often would multiply the copies. Convergence to one text is
   not achieved.

**Scratchpads:** (S1) a dedicated `scratch` group store that riders can reach with a new
per-group scope; (S2) let riders reach any group store of a granted group; (S3) a new
non-KV scratchpad type. S2 would expose the human Wiki and Notes to every rider. S3
duplicates 0047.

## Decision

We will adopt **A1 (`yrs`) for notes, carried inside the existing encrypted group
store, and S1 for scratchpads.**

1. **Note storage.** Each group has one note store, `name = "notes"`, opened through the
   existing group-store path and therefore sealed exactly like the Wiki store and #914.
   A note is a `yrs` `Doc` with one `Text` root, stored as **write-once update records**:
   - `n/<note_id>/meta`: title and creator, as an LWW value (a rename race is acceptable).
   - `n/<note_id>/u/<author_agent_hex>/<seq>`: one `yrs` v1 update (at most 64 KiB; the
     writer splits larger ones). Each key is written once by its author, so the 0047
     OR-Set **unions** the records and no edit is ever overwritten. Applying the updates
     is commutative and idempotent, so every replica holding the same key set derives
     the same text.
   - **Author binding:** a receiver rejects an update record whose sealed inner author
     is not `<author_agent_hex>`. This closes "one member overwrites another member's
     record", which the group write rule alone does not prevent.
   - **Size bound:** a note's encoded state is capped at 4 MiB. Past the cap, writes
     return 413. Compaction (a covering snapshot and author-deleted records) is deferred
     to a later slice; the cap keeps the retained serve under 16 MiB.
2. **Note API** (owner token; the handlers keep the existing group-membership and
   write-policy checks):
   `GET|POST /groups/:id/notes`, `GET /groups/:id/notes/:note` → `{title, text, version}`,
   `PUT /groups/:id/notes/:note {text, base_version}`. `version` is an encoded `yrs`
   snapshot. On PUT, the daemon rebuilds the text at `base_version` (history is kept, i.e.
   `skip_gc`), computes a character diff from that text to the submitted text, applies
   the diff as `yrs` ops on the base state, and merges the result into the current doc.
   Plain-text clients (the GUI, `curl`, agents) therefore get a real three-way merge
   without running a CRDT themselves. The response returns the merged text and the new
   version. CLI: `x0x notes list|show|edit|put`.
3. **Wiki.** The Space Wiki moves to notes. The migration mirrors #914's board move: the
   first member with write permission imports each legacy LWW page once as a note's
   initial text and writes a durable marker. The legacy store is left read-only, not
   deleted.
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

   For every `/stores/:id/*` route, the handler resolves `:id` to a group store and
   returns 403 unless the store's name is `scratch`, its group is in the token's grant
   list, and the scope level is sufficient. A rider can never reach `notes`, `wiki`,
   `web`, personal stores or task lists. The daemon writes as its member agent and adds
   the rider provenance mark (`sub_agent_id`) inside the sealed value, the same pattern
   as rider sends.
6. **GUI deep links (R10).** The GUI routes `#/note/<group_id>/<note_id>` and
   `#/scratch/<group_id>`, so #893's `POST /gui/show` / `x0x show note/<g>/<n>` can
   show a note to the human. The editor keeps the textarea. It sends `base_version`, and
   after a save it shows the merged text with an "updated by others" notice when the
   merged text differs from what the user typed.

**Non-goals now:** live collaborative cursors, presence and keystroke streaming (later:
once a browser `yrs`/Yjs binding can be vendored without a bundler, over the update
records defined here); rich media embeds (later: reference ADR 0055 file transfers by
hash, never inline); note compaction and history UI (later, before any note nears the
cap); rider access to notes (an open question for David).

## Consequences

### Positive

- Concurrent note edits converge and nothing is dropped silently. This closes the R9 gap
  the audit found.
- There is no new transport, sync engine or crypto: the change is a value encoding and
  some routes on shipped stores, and it inherits #914's epoch and rekey behaviour.
- Scratchpads give agents a shared, cross-machine working area under an explicit,
  revocable, per-group scope.

### Negative / Trade-offs

- It adds a new dependency (`yrs` and its transitive crates). The binary-size increase
  must be measured in slice 1, with a stop rule: if release `x0xd` grows by more than
  2 MiB, re-evaluate A2 before continuing.
- Diff-based merge can place an ambiguous insert (for example, inside repeated
  characters) differently from where the user meant. The text is preserved, but the
  position may be surprising.
- Keeping full history grows notes until compaction ships. The 4 MiB cap turns this into
  an explicit error, not a silent failure.
- This is the first widening of the rider allow-list since ADR 0039. A bug in the
  store-name check would expose human stores, so the scope test below is mandatory.
- Wiki migration has a mixed-version window: old GUIs still write the legacy LWW store.

### Neutral / Operational

- Notes exist only in groups that have group stores. `MlsEncrypted` notes are sealed, and
  `SignedPublic` notes are public by policy, the same split as #914.
- **Effort estimate (honest):** about 5–7 agent-weeks in total. Slice 1: `yrs` spike,
  size measurement and note model with property tests, 1.5–2 weeks. Slice 2: note REST,
  CLI and three-way merge, 1–1.5 weeks. Slice 3: Wiki migration, GUI notes and deep-link
  routes, 1–1.5 weeks. Slice 4: scratch store, rider scope and allow-list, 1 week.
  Slice 5: e2e and docs (`api-reference.md`, SKILL.md), 0.5–1 week. Slices 1–2 and 4
  are independent. All of them wait for the R17 freeze to lift.

## Validation

- **Convergence property test (slice 1):** N ∈ 2..6 replicas apply random concurrent
  insert and delete sequences, then exchange update records in random order with
  duplicates and partitions. Every replica must end with byte-identical text, and every
  character inserted and not explicitly deleted must be present. It must fail if records
  are merged LWW (control: swap in the old whole-value path and see the test fail).
- **Three-way merge test:** two PUTs from the same `base_version` that edit the **same
  paragraph** must both survive in the merged text.
- **Author binding:** a record under another member's author segment is rejected.
- **Wire test (ciphertext only):** capture the exact bytes handed to `pubsub.publish` for
  a note update and a scratch write in an `MlsEncrypted` group. Neither the note text nor
  the key or value appears in them. A member opens the record as the control, following
  #914's `group_list_publish_hands_gossip_only_sealed_bytes`.
- **Rider scope matrix:** `none`, `read` and `read_write` × `scratch`, `notes`, `wiki`,
  a personal store and an ungranted group's scratch store. Only the granted cells are
  allowed, and every other cell returns 403. This extends
  `rider_routes_allow_exactly_send_secure_encrypt_and_history`.
- **Cross-machine e2e (R6):** a rider on machine B writes scratch; an agent on A reads it.
- **Review trigger:** a live-cursor editor is scheduled, or a note reaches the cap.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
