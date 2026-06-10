# Code-Simplifier Review — Data-Structures Slice

Scope: `src/crdt/`, `src/kv/`, `src/mls/`, `src/groups/`.
Date: 2026-06-10. Findings only — no code changed.

Constraints honored:
- Group-admin flows (invite issuance/consumption, ban, role changes, KeyPackage handling) → marked **DEFERRED** (#106/#107).
- `mls/` crypto → structural/clarity only, marked **risk=high**, no wire-format change proposed.

---

## Top 10 highest-value findings

### 1. `crdt/` and `kv/` are near-duplicate delta/sync stacks that should share a generic CRDT-store scaffold
**Location:** `src/crdt/{delta.rs,sync.rs,task_list.rs}` vs `src/kv/{delta.rs,sync.rs,store.rs}`
**What's wrong:** The two modules are structural mirror images:
- Both back a collection with `OrSet<K>` (membership) + `HashMap<K,V>` (content) + `LwwRegister` (metadata) + a `version: u64` + `seq_counter: Arc<AtomicU64>`.
- Both define a `*Delta` struct with `added`/`removed`/`updated`/`name_update`/`version` and constructor helpers (`for_add`/`for_put`, `for_state_change`/`for_update`, `new`, `is_empty`).
- Both define a `*Sync` wrapper holding `Arc<RwLock<T>>`, a `PubSubManager`, a `topic`, an unused `AntiEntropyManager` (see #3), and a `tokio::spawn` recv loop that does the identical bincode decode (`with_fixint_encoding().with_limit(MAX_MESSAGE_DESERIALIZE_SIZE).allow_trailing_bytes().deserialize::<(PeerId, Delta)>`), `merge_delta`, warn-on-error.
- Both implement `DeltaCrdt` with the same `delta()` = "full_delta if version moved" body and a `version()` accessor.
**Proposed fix:** Extract a generic `CrdtStore` scaffold (the OrSet+HashMap+Lww+version+seq pattern) and a generic `GossipSync<T: DeltaCrdt>` wrapper that owns the `Arc<RwLock<T>>`, topic, decode loop, and publish path. KvStore adds only the access-control/allowlist hook; TaskList adds only ordering. Start by unifying the *sync* layer (lowest risk — the decode/merge/publish loop is byte-identical) before the store layer.
**Risk:** medium (touches replication hot path; must keep wire format `(PeerId, Delta)` and bincode options byte-identical — KvStore and TaskList deltas stay distinct types).
**Impact:** high — removes ~2 of the largest near-duplicated files; one decode/merge loop to test and harden instead of two.

### 2. `TaskList::delta(since_version)` is a dead, misleading abstraction (production never calls it)
**Location:** `src/crdt/delta.rs:140-167` (`delta`), `:253-269` (`DeltaCrdt for TaskList`)
**What's wrong:** `delta()` claims to produce changes "since a version" but always emits a **full-state** delta with **placeholder OR-Set tags** `(PeerId::new([0u8;32]), 0)` and self-admits via comments ("Note: placeholder implementation", "In a real implementation, we'd only include tasks added since the version"). Production code (`lib.rs:8153/8192/8228/8280`) exclusively uses `for_add`/`for_state_change`/`for_reorder`. The only callers of `delta()`/`DeltaCrdt::delta` are tests.
**Proposed fix:** Either (a) delete `TaskList::delta()` + the `DeltaCrdt for TaskList` impl if the gossip infra doesn't actually invoke the trait at runtime (confirm `AntiEntropyManager`/`DeltaCrdt` is never driven — see #3), or (b) if the trait must stay for type bounds, rename to `full_delta()` to match `KvStore` and drop the false "since_version" semantics and placeholder-tag comments. Do NOT leave a method whose doc contradicts its body.
**Risk:** low (dead in production; verify no trait-object dispatch first).
**Impact:** high — removes a self-described fake implementation that misleads every future reader of the CRDT layer.

### 3. `AntiEntropyManager` is dead weight in both sync wrappers
**Location:** `src/crdt/sync.rs:32-33,81-85` and `src/kv/sync.rs` (`anti_entropy` field, both `#[allow(dead_code)]`)
**What's wrong:** Both `*Sync` structs construct and store an `AntiEntropyManager<T>` that is never started, polled, or read — explicitly silenced with `#[allow(dead_code)]`. The constructors take a `sync_interval_secs` param purely to feed this dead manager. Actual convergence comes from the gossip recv loop + (in kv) the `StateRequest` side channel, not from `AntiEntropyManager`.
**Proposed fix:** Remove the `anti_entropy` field, the `AntiEntropyManager` import, and the `sync_interval_secs` constructor parameter from both sync wrappers (update the 1-2 call sites). If periodic anti-entropy is genuinely planned, leave a single `// TODO(anti-entropy)` rather than a half-wired field.
**Risk:** low (field is provably unused).
**Impact:** medium — removes a misleading "we do anti-entropy" signal and a vestigial constructor arg from the public-ish sync API.

### 4. kv has a `StateRequest` first-join catch-up path that crdt lacks — divergence, not deduplication
**Location:** `src/kv/sync.rs:18-45` (`STATE_SYNC_TOPIC_SUFFIX`, `STATE_REQUEST_RETRY_SECS`, `KvSyncMessage::StateRequest`, responder loop ~`:140-160`); absent in `src/crdt/sync.rs`.
**What's wrong:** KvStoreSync gained a state-sync side channel so empty first-time joiners converge; TaskListSync has no equivalent, so a fresh TaskList subscriber only converges on the next publish. This is a real behavioral gap masked by the otherwise-parallel structure. (Relevant if #1 is done — the catch-up belongs in the shared layer.)
**Proposed fix:** When unifying sync (#1), lift the `StateRequest`/responder pattern into the generic `GossipSync` so both task lists and kv stores get first-join catch-up. If not unifying, at minimum document on `TaskListSync` that it has no cold-start catch-up.
**Risk:** low-medium (adds a side topic to the task-list path; CRDT merge idempotency makes duplicate responses safe, as the kv comment already notes).
**Impact:** medium — closes a silent convergence gap and removes the "why does kv have this and crdt doesn't" puzzle.

### 5. Two live `MlsGroup` planes (`group.rs` GSS vs `treekem.rs`) — legacy plane still wired into 4 daemon paths
**Location:** `src/mls/group.rs` (`MlsGroup`, GSS) vs `src/mls/treekem.rs` (`TreeKemMlsGroup`); legacy used at `bin/x0xd.rs:459,1526,9875,10880,15781,18187`, `crdt/encrypted.rs`, `mls/keys.rs`.
**What's wrong:** `mls/group.rs::MlsGroup` is the legacy Group-Shared-Secret plane (no FS/PCS) and is still the default for several daemon endpoints and the entire `crdt/encrypted.rs` delta-encryption path, while `TreeKemMlsGroup` is the real RFC-9420 default for new groups (ADR-0012). Two parallel group APIs (`add_member`/`remove_member`/`commit`/`encrypt_message`) with overlapping names is a clarity hazard and a migration risk.
**Proposed fix:** **Observation only — DEFERRED + risk=high.** Do not collapse the planes here. The right vehicle is the ADR-0012 migration, not a simplification pass. Action item for that work: make every daemon call site name the plane explicitly (e.g. via `SecureGroupPlane`) so no path silently constructs a GSS group; audit whether `crdt/encrypted.rs` should move to `TreeKemMlsGroup`.
**Risk:** high (crypto semantics + persisted plane discriminator + wire/welcome formats).
**Impact:** high if/when addressed under ADR-0012; flagged so it isn't mistaken for dead code and deleted.

### 6. `KvStore::merge_delta` mixes access-control, allowlist mutation, and three apply loops in one 90-line function
**Location:** `src/kv/store.rs:357-443`
**What's wrong:** One function does: (a) writer authorization with a nested `match` on policy for the anonymous case, (b) allowlist add/remove gated on owner check (duplicated `writer.is_some_and(|w| self.owner.as_ref().is_some_and(|o| o == w))` twice), (c) added-entries loop, (d) removed-keys loop, (e) updated-entries upsert loop, (f) name LWW. High cyclomatic complexity for a security-sensitive path.
**Proposed fix:** Extract `fn authorize_writer(&self, writer) -> bool` (collapses a/the anonymous-`match`), `fn is_owner(&self, w) -> bool` (kills the duplicated owner predicate), and `fn apply_allowlist_changes(&mut self, delta, writer)`. Leave the three apply loops inline but after the gate. Keeps behavior identical, makes the security gate independently testable.
**Risk:** low-medium (security path — keep the silent-Ok rejection semantics exactly).
**Impact:** medium — the access-control decision becomes one named, unit-testable predicate instead of inline boolean soup.

### 7. `full_delta()` / `delta()` re-derive the active-key set and clone every entry on every cold-start response
**Location:** `src/kv/store.rs:475-494` (`full_delta`), `src/crdt/delta.rs:148-166`; called from `kv/sync.rs:155` responder loop per `StateRequest`.
**What's wrong:** `full_delta` builds `let active: HashSet<String> = self.keys.elements().into_iter().cloned().collect();` (clones every key) then clones every `KvEntry` (incl. its `Vec<u8>` value) into the delta. The crdt `delta()` similarly `task.clone()`s every item and walks `tasks_ordered()` **twice**. Under repeated `StateRequest`s from multiple joiners this is O(state) allocation churn per request with no caching.
**Proposed fix:** (a) In `full_delta`, iterate `self.keys.elements()` directly and look up entries instead of building an intermediate `HashSet` clone of all keys. (b) In crdt `delta()`, compute `tasks_ordered()` once and reuse for both the `added_tasks` and `ordering_update`. (c) Optional: cache the serialized full-state bytes keyed by `version` in the responder so N concurrent joiners share one serialization (idempotent today, so safe).
**Risk:** low (pure refactor of a producer; output unchanged).
**Impact:** medium — removes per-request whole-state re-clone + double traversal on the cold-start hot path.

### 8. `KvStore::get` does a redundant `String` allocation and an O(n) `elements()` scan per read
**Location:** `src/kv/store.rs:306-313`
**What's wrong:** `get` allocates `key.to_string()`, then calls `self.keys.elements().contains(&&key_string)` — `elements()` materializes the whole active set and scans it linearly, just to gate a `HashMap` lookup. Every read pays an allocation + O(active-keys) scan.
**Proposed fix:** Gate on the `HashMap` directly: `self.entries.get(key)` already returns `None` for absent keys; if tombstone-hiding is required, check membership via an OR-Set `contains(&str)` if available, or keep an `active_keys: HashSet` invariant updated on put/remove. At minimum drop the `to_string()` and use a borrowed lookup.
**Risk:** low (verify OR-Set tombstone semantics: a removed-then-present entry must still be hidden — confirm `entries.remove` already runs on remove, which `remove()` at `:324` does, so `entries.get` alone is likely sufficient).
**Impact:** medium — `get` is the most-called KvStore method; removes alloc + linear scan from every read.

### 9. Duplicated bincode-decode incantation repeated verbatim across sync paths
**Location:** `src/crdt/sync.rs:~115-122`, `src/kv/sync.rs:~110-119`, mirrored by the publish-side `bincode::serialize(&(peer,delta))` in both.
**What's wrong:** The exact builder chain `bincode::options().with_fixint_encoding().with_limit(MAX_MESSAGE_DESERIALIZE_SIZE).allow_trailing_bytes().deserialize::<(PeerId, Delta)>(&payload)` and its serialize counterpart are copy-pasted. A future change to limits/encoding must be made in ≥3 places consistently or the wire format silently forks.
**Proposed fix:** Add `fn decode_delta<D: DeserializeOwned>(payload: &[u8]) -> Result<(PeerId, D)>` and `fn encode_delta<D: Serialize>(peer, &D) -> Result<Bytes>` in a shared module (e.g. `network` or a new `gossip::wire`), used by both sync loops. Folds naturally into #1.
**Risk:** low (mechanical; must keep the option chain byte-identical).
**Impact:** medium — single source of truth for the on-wire delta envelope.

### 10. `tasks_ordered()` builds a full `HashSet` clone and does a linear `current_order.contains` per task
**Location:** `src/crdt/task_list.rs:349-372`
**What's wrong:** Allocates `or_set_tasks: HashSet<TaskId>` from `elements()` every call, then for the append phase does `current_order.contains(task_id)` — an O(n) `Vec::contains` inside a loop over the set, i.e. O(n·m). Called on every render/read and twice inside `delta()`.
**Proposed fix:** Build one `ordered_set: HashSet<&TaskId>` from `current_order` once and use it for the "already placed" check, replacing the per-iteration `Vec::contains`. Keeps the single `or_set_tasks` allocation but drops the quadratic term. Cache nothing; just fix the inner scan.
**Risk:** low (pure read-path refactor; ordering result identical).
**Impact:** medium — removes quadratic behavior on a frequently-called accessor.

---

## Tail (lower-value but worth noting)

### T1. `KvStoreId`/`TaskListId`/`AgentId`-style newtype boilerplate is copy-pasted
**Location:** `kv/store.rs:59-93`, `crdt/task_list.rs:~30-60`, `crdt/task_item.rs` (`TaskId`).
Each 32-byte newtype re-implements `new`/`as_bytes`/`Display(hex)`/`from_content(blake3)`. A small `id_newtype!` declarative macro (or shared `Hash32` wrapper) would remove ~4 identical blocks.
Risk: low. Impact: low-medium (cosmetic, but removes real duplication).

### T2. `default_seq_counter()` + `#[serde(skip, default=...)]` pattern duplicated
**Location:** `kv/store.rs:97` and `crdt/task_list.rs:71`. Same free function, same skip-serialize `Arc<AtomicU64>` field. Folds into the shared scaffold of #1.
Risk: low. Impact: low.

### T3. `merge_delta` "updated" upsert uses placeholder seq `(peer_id, 0)` in both kv and crdt
**Location:** `kv/store.rs:429-431`, `crdt/delta.rs:222`. Both insert a synthetic OR-Set tag with seq `0` for out-of-order upserts. The reasoning is sound and commented, but the magic `0` and the two near-identical upsert branches are another shared-scaffold candidate. Note only.
Risk: low (CRDT semantics — leave behavior). Impact: low.

### T4. `KvEntry::merge` LWW tiebreak by `content_hash >` is subtle and undocumented at the field
**Location:** `kv/entry.rs:89-95`. Tie-break on `updated_at` equal → higher `content_hash` wins. Correct and deterministic, but the rule lives only in the struct doc-comment, not at `merge`. Add a one-line comment at the comparison so the next reader doesn't think it's arbitrary.
Risk: low. Impact: low (clarity).

### T5. `get`-style "to_string then contains(&&x)" double-reference pattern
**Location:** `kv/store.rs:308` `contains(&&key_string)`. The `&&` is a readability snag. Resolved by #8's borrowed-lookup fix.
Risk: low. Impact: low.

### T6. `groups/` administration code — DEFERRED
**Location:** `groups/mod.rs` (`record_issued_invite`, `consume_issued_invite`, `add_member*`, `ban_member`, `set_member_role`, `set_member_treekem_key_package`, `kem_envelope.rs`, `invite.rs`).
Per instructions these are being reworked under #106/#107. Observation: `GroupInfo` in `mod.rs` (1,152 lines) carries both the state-commit/roster machinery and the invite/ban/role mutators in one struct — when #106/#107 lands, consider splitting roster-mutation from discovery/card projection. **No refactor proposed now.**
Risk: n/a. Impact: deferred.

### T7. `groups/state_commit.rs` hashing helpers are well-factored — note, no action
**Location:** `state_commit.rs:63-186` (`blake3_hex`, `compute_roster_root`, `push_len_prefixed`, `role_byte`, `state_byte`). This module is the *good* pattern (length-prefixed canonical encoding, per-component hashes). Flagged as a positive reference for how the crdt/kv hashing could be organized. The signable-bytes/sign/verify path is crypto — risk=high, no change proposed.
Risk: high (crypto). Impact: none (commendation).

### T8. `mls/group.rs` `add_member`/`remove_member`/`commit` clone `group_id` + both tree hashes repeatedly
**Location:** `mls/group.rs:375-379,433-437,475-482,532-533`. Multiple `.clone()` of `group_id`/`new_tree_hash`/`new_transcript_hash` per commit. Structural only.
**Risk:** high (crypto path — do NOT alter what gets hashed/signed). Observation only; if touched, confirm clones aren't load-bearing for the borrow checker before removing.
Impact: low.

---

## Summary of dependencies between findings
- #1 is the umbrella; #3, #4, #9, T2, T3 all fold into it naturally.
- #2 and #3 should be verified together (is `DeltaCrdt` ever dispatched at runtime? If not, both the trait impl and the manager are removable).
- #7, #8, #10 are independent, low-risk efficiency wins doable today without the #1 refactor.
- #5 and T6 are explicitly DEFERRED (crypto / #106-#107).
