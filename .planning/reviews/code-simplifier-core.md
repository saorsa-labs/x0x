# Core Library Simplification Review

Scope: `src/lib.rs` (9,980 lines), `src/identity.rs` (1,232), `src/storage.rs` (682),
`src/error.rs` (540), `src/bootstrap.rs` (247), `src/connectivity.rs` (701),
`src/contacts.rs` (1,040).

Findings only — no code changes made. Severity/risk per CLAUDE.md Rule 2 (Simplicity
First) and Rule 3 (Surgical Changes). Each fix below is independently shippable; none
require a behavioural change. Verify with `just check` after any applied fix.

---

## Structural overview

`lib.rs` is dominated by a single `impl Agent` block spanning **lines 1980–7516
(~5,500 lines, 94 methods)**. The `Agent` struct has **27 fields**. This is the
central readability problem: a new reader cannot form a mental model of the public API
because connection management, identity announcement/discovery, direct messaging,
gossip pub/sub, presence, and lifecycle are all flattened into one impl block with no
visual or module seam between them.

The five largest methods alone account for ~2,080 lines:

| Method | Line | Approx length |
|---|---|---|
| `connect_to_agent` | 2381 | 603 |
| `start_identity_listener` | 5161 | 501 |
| `connect_to_machine` | 2996 | 344 |
| `send_direct_raw_quic` | 3794 | 324 |
| `join_network` | 5799 | 308 |

---

## Top 10 highest-value findings

### 1. `impl Agent` is a 5,500-line god-object with no module seams
- **Location:** `src/lib.rs:1980–7516`
- **What's wrong:** 94 methods in one impl block, 27 struct fields. Six clearly
  separable concern-clusters share no organizational boundary: (a) identity accessors
  + builder glue, (b) connection establishment (`connect_to_agent`,
  `connect_to_machine`, `reachability`, `seed_transport_peer_hints_for_target`),
  (c) direct messaging (`send_direct*`, `recv_direct*`, DM inbox lifecycle), (d)
  identity announcement + discovery cache (`announce_identity`, `discovered_*`,
  `find_*`, `start_identity_listener`), (e) gossip pub/sub (`subscribe`, `publish`,
  `peers`), (f) presence + FOAF.
- **Proposed fix:** Split `impl Agent` across `agent/` submodules using the multiple-
  `impl Agent` blocks Rust allows: `agent/connect.rs`, `agent/direct.rs`,
  `agent/discovery.rs`, `agent/announce.rs`, `agent/gossip.rs`, `agent/lifecycle.rs`.
  The struct definition stays in one place; each module carries one `impl Agent { … }`.
  No API changes, purely file-level moves. This is the single biggest clarity win.
- **Risk:** Low (mechanical move; private helpers may need `pub(crate)`).
- **Impact:** Major readability gain; no efficiency change.

### 2. `connect_to_agent` is 603 lines in a single method
- **Location:** `src/lib.rs:2381` (603 lines)
- **What's wrong:** Single method orchestrating cache lookup, address resolution,
  multi-stage discovery, coordinator selection, hole-punch, and raw-QUIC fallback. Far
  past the "senior engineer would call this overcomplicated" bar (Rule 2).
- **Proposed fix:** Extract named private stages: `resolve_agent_endpoint`,
  `attempt_direct_dial`, `attempt_coordinated_dial`, `attempt_relay_dial`. The public
  method becomes a readable strategy sequence. Mirror the same decomposition in
  `connect_to_machine` (344 lines, 2996) which shares the structure.
- **Risk:** Medium (control-flow heavy; needs the existing tests green to verify).
- **Impact:** Large readability gain; no efficiency change.

### 3. Three `Id` types have byte-identical impls
- **Location:** `src/identity.rs:44–133` (`MachineId`, `AgentId`, `UserId`)
- **What's wrong:** `from_public_key`, `as_bytes`, `to_vec`, `verify`, and `Display`
  are copy-pasted three times. ~90 lines of pure duplication that drift independently.
- **Proposed fix:** A declarative macro `peer_id_newtype!(MachineId);` emitting the
  newtype + the five identical methods + `Display`. Keeps each type nominally distinct
  (the type-safety reason they're separate) while removing the triplication. Document
  the macro once.
- **Risk:** Low (identical bodies; macro is a faithful expansion).
- **Impact:** ~60-line reduction; eliminates drift risk.

### 4. Three keypair serialize/deserialize fn pairs are identical
- **Location:** `src/storage.rs:36–101` and `383–417`
  (`serialize_machine_keypair`/`deserialize_*` for machine/agent/user)
- **What's wrong:** Six functions, all with the identical body
  `SerializedKeypair { public_key, secret_key } → bincode`. Only the keypair type
  name differs.
- **Proposed fix:** Generic over a small trait, e.g.
  `fn serialize_keypair<K: KeypairBytes>(kp: &K) -> Result<Vec<u8>>` plus
  `deserialize_keypair<K: KeypairBytes>(bytes) -> Result<K>`, where `KeypairBytes`
  exposes `public_key().as_bytes()` / `from_bytes(...)`. Keep the named wrappers only
  if external callers depend on the exact symbol names; otherwise drop them.
- **Risk:** Low (the three keypair types already share the same accessor shape).
- **Impact:** ~80-line reduction; one serialization codepath to test.

### 5. Announcement Unsigned/signed struct pairs duplicate every field + `to_unsigned`
- **Location:** `src/lib.rs:679–770` (IdentityAnnouncement), `855–970`
  (MachineAnnouncement), `972–1136` (UserAnnouncement); 6 `to_unsigned` sites total
- **What's wrong:** Each announcement defines an `…Unsigned` struct mirroring the signed
  struct (14 fields for identity), plus a hand-written `to_unsigned()` that copies and
  clones every field. The signed struct then re-declares the same fields with longer
  doc comments. The sign-payload is `bincode::serialize(&self.to_unsigned())`.
- **Proposed fix:** Flatten to one struct holding the payload fields plus
  `machine_signature: Vec<u8>`, and serialize the payload by serializing the struct
  with the signature field skipped via `#[serde(skip)]` during the canonical pass — or
  factor a shared `SignedAnnouncement<T>` wrapper `{ payload: T, machine_signature }`
  so the Unsigned/signed split exists once, generically. Removes 3 mirror structs and 3
  hand-copied `to_unsigned` bodies.
- **Risk:** Medium (touches the wire/signing format — must keep the serialized bytes
  bit-identical so existing announcements still verify; gate behind the announcement
  round-trip tests).
- **Impact:** ~150-line reduction; removes a whole class of "added a field to one
  struct but not its mirror" bugs.

### 6. Crypto verify boilerplate repeated across 3 announcements + IntroductionCard
- **Location:** `src/lib.rs:788–854` plus the Machine/User `verify` bodies;
  `MlDsaPublicKey::from_bytes` ×4, `MlDsaSignature::from_bytes` ×3,
  `verify_with_ml_dsa` ×3
- **What's wrong:** Each `verify()` repeats: parse machine pubkey → derive id → compare
  → serialize unsigned → parse signature → `verify_with_ml_dsa` → map 4 distinct error
  strings. ~40 lines duplicated per announcement type.
- **Proposed fix:** A free helper
  `fn verify_ml_dsa_attestation(pubkey_bytes, expected_machine_id, unsigned_bytes,
  signature_bytes) -> error::Result<()>` consolidating the parse/derive/compare/verify
  chain. Each announcement's `verify()` calls it then does only its type-specific cert
  checks.
- **Risk:** Low–medium (security-sensitive path; keep error variants identical and add
  a test that a tampered signature still fails).
- **Impact:** ~90-line reduction; single audited verification routine.

### 7. Discovery accessors duplicate the "read cache → TTL filter → clone → sort" shape
- **Location:** `src/lib.rs:4815–4960` (`discovered_agents`,
  `discovered_agents_unfiltered`, `discovered_machines`,
  `discovered_machines_unfiltered`) + `find_agents_by_user` (6777)
- **What's wrong:** Five+ methods repeat `start_identity_listener().await?` →
  `cache.read().await.values()` → optional `discovery_record_is_live` filter →
  `.cloned().collect()` → `sort_by_key`. The agent and machine variants are structurally
  identical over different caches.
- **Proposed fix:** A generic private helper
  `async fn snapshot_cache<K, V: Clone>(cache, ttl_filter, sort_key) -> Vec<V>` (or two
  thin helpers `live_records` / `all_records`). The public methods shrink to one call
  each. Note: `start_identity_listener().await?` is repeated **18 times** across the
  impl — see finding #9.
- **Risk:** Low.
- **Impact:** ~80-line reduction; the cache-access policy lives in one place.

### 8. `start_identity_listener` is a 501-line method
- **Location:** `src/lib.rs:5161` (501 lines)
- **What's wrong:** Single method spawns the listener and inlines all
  per-announcement-type handling (identity/machine/user decode, verify, trust-gate,
  cache upsert). Hard to follow and the `AtomicBool` once-guard + spawn boilerplate is
  buried in it.
- **Proposed fix:** Extract `handle_identity_announcement`, `handle_machine_announcement`,
  `handle_user_announcement` as free functions taking the relevant `Arc<RwLock<…>>`
  caches; the listener loop dispatches by message kind. The `upsert_discovered_agent`
  helper (already exists, used 16×) shows the pattern is amenable to extraction.
- **Risk:** Medium (background task; verify discovery integration tests).
- **Impact:** Large readability gain.

### 9. `start_identity_listener().await?` guard repeated 18×; `gossip_runtime.as_ref()` 19×
- **Location:** throughout `impl Agent`
- **What's wrong:** Nearly every discovery/find method opens with
  `self.start_identity_listener().await?;` and many re-implement the
  `match self.gossip_runtime.as_ref() { Some(r) => r, None => return … }` guard inline.
- **Proposed fix:** (a) Keep the `start_identity_listener` call but make the lazy-start
  idempotent guard cheaper to read by giving it a `ensure_discovery_started()` alias
  used consistently. (b) Add `fn runtime(&self) -> error::Result<&Arc<GossipRuntime>>`
  returning the "not initialized" error once, replacing the 19 inline matches.
- **Risk:** Low.
- **Impact:** Removes ~19 repeated guard blocks; intent ("requires runtime") becomes
  explicit in one place.

### 10. Inline UNIX-timestamp computation duplicated alongside an existing helper
- **Location:** `src/lib.rs:5310, 5390, 5500, 6628, 6665, 6741` (7 inline
  `SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())` sites),
  while `Self::unix_timestamp_secs()` (5663) already exists and is referenced 18×
- **What's wrong:** Two ways to get "now in seconds" coexist; the inline form is copied
  6–7 times.
- **Proposed fix:** Replace every inline `SystemTime::now()…as_secs()` with
  `Self::unix_timestamp_secs()` (or a free `unix_timestamp_secs()` fn so non-method
  callers/free helpers can use it too).
- **Risk:** Low (pure substitution).
- **Impact:** Small but removes a copy-paste hazard; one definition of "now".

---

## Longer tail

### 11. `NetworkError` has ~30 variants with heavy overlap
- **Location:** `src/error.rs:169–318`
- **What's wrong:** Variants like `ConnectionFailed`, `ConnectionClosed`,
  `ConnectionReset`, `ConnectionError`, `NotConnected`, `AlreadyConnected`,
  `AgentNotConnected`, plus duplicated `Serialization`/`SerializationError` and
  `ConfigError`/`ConfigError`-style string variants. Several carry `[u8; 32]` peer ids
  and overlap semantically.
- **Proposed fix:** Audit which variants are actually constructed and matched-on
  distinctly (grep for each). Collapse the string-wrapping near-duplicates
  (`Serialization` vs `SerializationError`, `ConnectionError` vs `ConnectionFailed`)
  into one each. Don't over-merge variants that callers branch on.
- **Risk:** Medium (callers may match specific variants; check `map_raw_quic_dm_error`
  and CLI/API error mapping first — Rule 8).
- **Impact:** Smaller, clearer error surface.

### 12. `Agent` struct's 27 fields mix lifecycle handles, caches, and config
- **Location:** `src/lib.rs:201–272`
- **What's wrong:** Three `Arc<RwLock<HashMap…>>` discovery caches, four `AtomicBool`
  once-guards, two `Mutex<Option<JoinHandle>>`, and DM/capability infra all sit flat.
  The three discovery caches in particular are always used together.
- **Proposed fix:** Group the three discovery caches into a `DiscoveryCaches` struct
  (identity/machine/user), and the once-guards into a small `ListenerGuards` struct.
  Reduces the top-level field count and makes the "discovery subsystem" legible.
- **Risk:** Low–medium (field accesses change `self.x` → `self.discovery.x`).
- **Impact:** Struct becomes scannable; supports the #1 module split.

### 13. `Drop for Agent` only aborts two of several background tasks
- **Location:** `src/lib.rs:286–298`
- **What's wrong:** `Drop` aborts `heartbeat_handle` and
  `discovery_cache_reaper_handle`, but the capability advert service, DM inbox service,
  and listener spawns are not handled here. Either they're owned elsewhere (then the
  asymmetry is confusing) or they leak. Worth a comment or consolidation.
- **Proposed fix:** Collect all abortable `JoinHandle`s into one
  `Vec<JoinHandle<()>>`/struct and abort uniformly in `Drop`; or document why only two
  need explicit abort.
- **Risk:** Low (verify shutdown tests).
- **Impact:** Clarifies lifecycle ownership.

### 14. `find_agent` / `find_machine` / `find_agent_rendezvous` share a multi-stage
  cache→subscribe→timeout shape
- **Location:** `src/lib.rs:6587 (find_agent), 6701 (find_machine), 7288
  (find_agent_rendezvous)`
- **What's wrong:** Each does "stage 1 cache hit; stage 2 subscribe to shard topic and
  `tokio::select!` against a 5s deadline; stage 3 cache result." The deadline-loop +
  verify + upsert block is near-identical.
- **Proposed fix:** Extract `wait_for_announcement_on(topic, deadline, predicate)`
  returning the first verified matching announcement. Each `find_*` keeps only its
  cache lookup + predicate.
- **Risk:** Medium (async select / timeout semantics must be preserved exactly).
- **Impact:** Removes a substantial duplicated async block.

### 15. `discovered_agent`/`discovered_machine`/`discovered_user` single-key lookups
  are identical
- **Location:** `src/lib.rs:4904, 4970, 5112`
- **What's wrong:** All three are
  `start_listener; Ok(cache.read().await.get(&id).cloned())`.
- **Proposed fix:** Folds out naturally once #7's `snapshot_cache`/lookup helper exists;
  add a `get_record(cache, id)` one-liner helper.
- **Risk:** Low.
- **Impact:** Minor.

### 16. `connectivity.rs` `ReachabilityInfo` re-declares fields already on
  `DiscoveredAgent` and clones them
- **Location:** `src/connectivity.rs` `ReachabilityInfo` + `from_discovered`
- **What's wrong:** `ReachabilityInfo` mirrors `addresses`, `nat_type`,
  `can_receive_direct`, `is_relay`, `is_coordinator`, `reachable_via`,
  `relay_candidates` from `DiscoveredAgent`, and `from_discovered` clones each. It's a
  near-copy of the same field set that also appears on the announcement structs
  (finding #5).
- **Proposed fix:** Either make `ReachabilityInfo<'a>` borrow from `&DiscoveredAgent`
  (no clones) if its lifetime allows, or have `DiscoveredAgent` expose a
  `reachability(&self) -> ReachabilityView<'_>` that borrows. If a separate owned type
  is genuinely needed, derive it via `From<&DiscoveredAgent>` and document why the copy
  exists.
- **Risk:** Low–medium (lifetime threading if borrowed).
- **Impact:** Removes a 7-field clone per reachability decision.

### 17. Repeated `.read().await` / `.write().await` (34 / 23 sites) — verify no
  lock-held-across-await hazards and no double-lock
- **Location:** throughout `impl Agent`
- **What's wrong:** Not a duplication bug per se, but several discovery methods take a
  read lock, clone out, then in `machine_for_agent` take a second lock — re-locking
  patterns are easy to get subtly wrong, and a few methods clone the whole cache value
  set under the lock.
- **Proposed fix:** Audit each `.write().await` site for "compute under lock then drop";
  prefer cloning the minimal key/value out and releasing before further awaits. Confirm
  `online_agents` (holds `cache` read guard across an `await` on
  `pw.manager().get_group_presence`) doesn't risk reader starvation — consider dropping
  the guard before the presence await and re-reading, or snapshotting first.
- **Risk:** Medium (concurrency semantics — needs care + the existing soak tests).
- **Impact:** Efficiency + correctness clarity; `online_agents` at 4840 is the specific
  one holding a read guard across an await.

### 18. 120 `.clone()` sites in lib.rs — several are avoidable
- **Location:** lib.rs broadly; notably the announcement `to_unsigned` bodies (#5), the
  discovery `from_discovered` (#16), and `find_agent` stage-1 `addresses.clone()`
- **What's wrong:** Many clones are structurally forced by the duplicated types above;
  removing the duplication (#5, #16) removes the clones for free.
- **Proposed fix:** Treat as a follow-on benefit of #5/#7/#16 rather than a standalone
  pass. For the remainder, prefer returning references or `Arc` clones over deep
  `Vec`/`String` clones where the caller only reads.
- **Risk:** Low.
- **Impact:** Modest allocation reduction on hot discovery/announce paths.

### 19. `bincode::serialize` appears 22× with the same error-map closure
- **Location:** lib.rs (announcement signing/verifying), storage.rs, others
- **What's wrong:** `bincode::serialize(&x).map_err(|e| Error::Serialization(
  format!("…: {e}")))` is copied repeatedly with slightly varying messages.
- **Proposed fix:** A small `fn ser<T: Serialize>(t: &T, ctx: &str) -> Result<Vec<u8>>`
  and matching `de` helper in a `wire`/`codec` module. Centralizes the error mapping.
- **Risk:** Low.
- **Impact:** ~1 line per call site removed; consistent error messages.

### 20. Snapshot types (`KvEntrySnapshot`, `TaskSnapshot`) and handles
  (`TaskListHandle`, `KvStoreHandle`) sit at the bottom of lib.rs and belong in their
  modules
- **Location:** `src/lib.rs:8104 (TaskListHandle), 8407 (KvStoreHandle), 8604
  (KvEntrySnapshot), 8626 (TaskSnapshot)`, plus the `impl Agent` blocks at 8293 that
  create them
- **What's wrong:** `TaskListHandle`/`KvStoreHandle` are thin wrappers over `crdt`/`kv`
  yet live in the top-level crate file, inflating lib.rs and splitting their logic from
  the modules they wrap.
- **Proposed fix:** Move `TaskListHandle` into `crdt/` (or a `handles` module) and
  `KvStoreHandle` into `kv/`; re-export from lib.rs so the public path is unchanged.
  The `create_task_list`/`join_task_list`/KV `impl Agent` methods move with #1's split.
- **Risk:** Low (move + `pub use` re-export keeps API stable).
- **Impact:** ~600 lines out of lib.rs; handles colocate with their backing types.

---

## Counts summary

- **Top findings:** 10 (1 god-object split, 2 oversized methods, 4 duplication
  families, plus guards/timestamps).
- **Tail findings:** 10 (#11–#20).
- **Total:** 20 findings.
- **Largest single win:** #1 (split the 5,500-line `impl Agent`), enabling #2, #8, #12,
  #20.
- **Lowest-risk quick wins:** #3 (Id macro), #4 (keypair serde generic), #9 (runtime
  guard helper), #10 (timestamp helper), #19 (bincode codec helpers).
- **Risk-flagged (touch wire/security/concurrency — gate behind tests):** #5
  (announcement format), #6 (verify path), #11 (error variants), #14 (async find),
  #17 (lock-across-await).

### Public-API coherence verdict
The public surface is *capable* but not *legible*: a new user faces 94 methods on one
`Agent` type with overlapping names (`discovered_agents` vs `discovered_agents_unfiltered`
vs `online_agents`; `find_agent` vs `discovered_agent` vs `cached_agent`). The biggest
new-user clarity improvements are (a) the module split (#1/#20) so methods cluster by
concern, and (b) a short doc note distinguishing the three "get an agent" families
(live-filtered cache view / unfiltered cache view / single lookup) — they currently look
interchangeable but differ in TTL and network behaviour.
