# GSS Future-Epoch Hold for Encrypted KV Deltas

- **Status:** Draft (branch `fix/gss-future-epoch-hold`, based on the R19 pin `41d1759`)
- **Scope:** GSS-encrypted group KV stores (`AccessPolicy::Encrypted`, `src/kv/sync.rs`)
- **Trigger:** R19 legacy-a1 `valid barrier converges` timeout
  (`omp-reports/takeover-20260921/x0x32-r19-legacy.md`)
- **Wire impact:** none. No message, envelope or topic changes. The change is
  purely local receive-side buffering, plus one extra use of the existing sealed
  `StateRequest`.

Unless stated otherwise, citations resolve at `41d1759`.

## 1. Premise check

The premise holds: a future-epoch sealed delta is dropped today.

- `src/kv/encrypted.rs:612` `open_mutation` returns
  `SecureRecord("record epoch N is ahead of local group epoch M — waiting for group secret sync")`
  before the AEAD open. The GSS context would say `no group secret for epoch`
  (`src/groups/kv_context.rs:807`), but `open_mutation` never reaches it for
  future epochs.
- `src/kv/sync.rs:1729` `merge_encrypted_record` logs
  `rejected sealed record before author verification` and returns `false`. The
  listener (`sync.rs:2497`) continues to the next message. Nothing retains the
  payload.
- Nothing pushes an epoch change into a store's context. The context refreshes
  only when a sync loop calls the refresh hook, which happens before a seal or
  open (`stores.rs:1470` `gss_kv_refresh`). The rekey commit
  (`named_groups.rs:5825`, under G write) updates only `named_groups`.
- Recovery after a drop needs one of two things: a later record at E+1 (which
  does not bring back the dropped one), or a state serve at E+1. For an
  encrypted store, the bootstrap requester exits once it has converged
  (`RequestSlotScheduler::next_slot` returns `false` when `changes` is `None`).
  It re-arms only for a previously *denied* requester
  (`waiting_for_membership`). So a converged observer never asks again, and the
  barrier write is lost until some unrelated full serve happens.

One part of the brief does not hold: an immediate state request at the moment
of `no key for epoch` cannot help. See §5.

## 1a. Premise check: is "no key for epoch" actually observed in R19?

**Not yet shown.** §1 proves only that the code *would* drop a future-epoch
record. It does not prove that R19's barrier reached the observer at all.

A competing explanation fits the same symptom: open issue **#890**. On Full
nodes, the eager fanout for a group-store topic ignores the group roster. So a
write to a small group can reach the other member only through lazy IHAVE, and
IHAVE is shed under load. The R19 testnet nodes run in Full mode.

The two causes fail at different layers:

| Cause | Where the barrier is lost | Does this hold fix it? |
|-------|---------------------------|------------------------|
| Future-epoch drop | Delivered, then rejected by `open_mutation` | Yes |
| #890 fanout/IHAVE shed | Never delivered to the observer | No: nothing reaches the hold, and no catch-up fires because no future epoch was observed |

They can also co-occur.

**Evidence that would confirm the future-epoch drop**, all from the R19 run
(legacy-a1, head `41d1759`) or a rerun of it:

1. **Observer log.** A `WARN` from the observer's `x0x::kv` target for the
   barrier store id, inside the 120 s poll window:
   `rejected sealed record before author verification`, with
   `reason = record epoch N is ahead of local group epoch M — waiting for group secret sync`.
   Note that the literal string is **not** "no key for epoch". That text comes
   from test fixtures and `GssKvSecureContext::open`, which a future epoch never
   reaches.
2. **Epochs at barrier time.** `GET /groups/:id` `secret_epoch` on the writer
   and the observer, sampled at the barrier PUT. The drop needs writer = E+1
   and observer = E. The same sample repeated during the poll shows whether,
   and when, the observer reached E+1.
3. **Counter delta.** The observer's `/diagnostics/state-sync`
   `incoming_record_merges` for the destination topic across the barrier
   window. If rejected records were logged but no merge happened, the record
   was dropped rather than never delivered.

**Evidence that would point at #890 instead:**

1. The observer logs nothing at all for the barrier store topic in the window:
   no merge and no rejection.
2. The observer's `incoming_record_merges` for the topic does not move.
3. The writer's eager peer set for the store topic excludes the observer, and
   the gossip IHAVE/IWANT shed counters rise during the window (see the #890
   diagnostics).
4. The observer is already at E+1 at barrier time (evidence item 2 above). In
   that case the hold's premise is false for R19.

**After this branch.** The new counters answer the question directly: on the
observer, `future_epoch_held + future_epoch_refused` is non-zero if and only
if a future-epoch record arrived.

**Decision point.** Root decides between #890 and this hold, or both, based on
that evidence. The branch stays as implemented and is not proposed for merge
until then.

## 2. What is held (a)

A main-topic payload enters the hold only if **every** check below passes. All
of them run without the E+1 key.

| # | Check | Where |
|---|-------|-------|
| 1 | Pub/sub envelope is signed (v2/v3) and its ML-DSA-65 signature verified; the sender is not in the gossiped `RevocationSet`. | Already enforced by `decode_for_delivery` (`src/gossip/pubsub.rs:2955`), which drops invalid signed payloads. The hold additionally requires `msg.sender.is_some()`, so unsigned v1 payloads are never held. |
| 2 | Payload decodes as `(PeerId, EncryptedKvStoreRecordV1)`. | `decode_delta` |
| 3 | `record.group_id == ctx.group_id()` and `record.store_id == local store id`. | Same comparison `open_mutation` does first. |
| 4 | `ctx.current_epoch() < record.epoch <= ctx.current_epoch() + MAX_EPOCH_LOOKAHEAD`. | New |
| 5 | The pub/sub-verified sender is an **authorized writer in the local current roster** (`ctx.is_authorized_writer(sender)`). This also requires the local context to hold a secret, so an invalidated or quarantined context holds nothing. | New |
| 6 | Payload size ≤ `MAX_HELD_BYTES_PER_SENDER`, and it is not a byte-identical duplicate of a held payload. | New |

These checks **cannot** run before decryption, and are deferred to release:
inner-mutation binding (group/store/epoch), the `author_id`-to-public-key
derivation, the ML-DSA-65 inner signature, the mutation kind, the writer check
against the **new** roster, the generation-guarded apply and content admission.
Release runs the unchanged `merge_encrypted_record`, so a held record gets
exactly the checks a live record gets, and none are weakened.

Everything else is never held: past-epoch (stale) records, records beyond the
lookahead, records from senders outside the local writer roster, unsigned
payloads, cross-group or cross-store envelopes, TreeKEM records, group-signed
public records and plaintext deltas.

## 3. Bounds (b)

| Constant | Value | Rationale |
|----------|-------|-----------|
| `HOLD_TTL` | 300 s | R19 showed 8.6 s removal propagation. #973's `GSS_PUBLISH_DEADLINE` lets one stalled publication delay a roster install by up to 30 s per node. 300 s is 10× that single-gate worst case and equals `STATE_REQUEST_TAIL_CAP_SECS`. After 300 s the catch-up request (§5) is the recovery path. |
| `MAX_HELD_PER_SENDER` | 32 records | Covers a burst of writes from one member across a rekey window. |
| `MAX_HELD_BYTES_PER_SENDER` | 1 MiB | One maximal delta is ≤ 64 KiB inline value (`MAX_INLINE_SIZE`) plus about 5.3 KiB of ML-DSA-65 key and signature, so this holds ≥ 14 maximal deltas. It also equals the v3 pub/sub envelope cap (`MAX_V3_ENVELOPE_BYTES`), so any single deliverable record fits. |
| `MAX_HELD_PER_STORE` | 128 records | Four senders at full quota. |
| `MAX_HELD_BYTES_PER_STORE` | 4 MiB | Four senders at full byte quota. Worst case per open encrypted store; stores are opened only for groups this agent belongs to. |
| `MAX_EPOCH_LOOKAHEAD` | 4 | Rotation increments the epoch by one (`GroupInfo::rotate_shared_secret`). Four covers back-to-back removals, and rejects forged `u64::MAX` epochs outright. |
| `HOLD_TICK` | 1 s | Maintenance cadence, active only while the hold is non-empty (§4). |

**Eviction** runs in this order on every insert, after expiry:

1. **Expire first.** Drop every entry older than `HOLD_TTL`.
2. **Per-sender quota.** If the incoming record would exceed its sender's count
   or byte quota, evict **that sender's own** oldest entries until it fits. A
   sender can only ever displace itself.
3. **Per-store quota.** If the store would overflow, evict the oldest entry of
   the sender currently holding the **most bytes** (ties go to the sender with
   the most entries, then to the oldest entry). Repeat until it fits. A
   flooding member therefore loses its own records first. A sender with a
   single small record is displaced only after every larger holder is at or
   below its own size.

The hold is a separate buffer of ciphertext. It never touches `KvStore`
contents, so it can never evict or overwrite a verified record of any epoch.

**Diagnostics.** New fields in `StateSyncSnapshot`, cumulative per open store:

- `future_epoch_held`, `future_epoch_released`, `future_epoch_release_rejected`
- `future_epoch_superseded` (the local epoch jumped past the held epoch)
- `future_epoch_expired`, `future_epoch_evicted`, `future_epoch_refused`
  (failed a §2 check that applies only to future-epoch records)
- `future_epoch_catchup_requests`
- the gauges `future_epoch_held_records` and `future_epoch_held_bytes`

## 4. Release (c)

**Triggers.** All three run in the main-topic listener loop, under the
per-sync lifecycle lock that already serializes every merge:

1. After each live encrypted record is processed. That record's refresh has
   just run, so this costs one epoch comparison.
2. When the context's `encrypted_authorization_changes()` watch fires, which it
   does on every snapshot change.
3. A `HOLD_TICK` interval, polled only while the hold is non-empty. It calls
   the refresh hook, which is what makes the rekey installed under G visible to
   the context without any daemon change. It then expires and releases entries.

**Procedure** (`release_future_epoch_hold`):

1. Call the refresh hook once, then read `cur = ctx.current_epoch()`.
2. If the local agent is not an authorized reader, release nothing: entries
   stay until the TTL removes them (§6).
3. Take the hold's `std::sync::Mutex`. Remove every entry with `epoch <= cur`,
   sorted by `(epoch, arrival sequence)`, and drop the mutex. The mutex is
   never held across an `.await`.
4. For each removed entry:
   - if `epoch < cur`, count it as `superseded` and do not open it (the
     receiver has moved past it; §5 fetches current state);
   - otherwise call the unchanged `merge_encrypted_record(ctx, None, …)` on the
     original payload bytes. The refresh already ran, and the per-record
     generation guard (`apply_if_encrypted_authorized`) still rejects a roster
     that moves mid-release.
5. Persist the snapshot once if anything merged.

**Lock order.** Release never takes G.

| Path | Order |
|------|-------|
| Rekey commit (`persist_named_group_info_inner`) | `named_groups_persistence_lock` → **G.write** → `named_groups.write` (synchronous block) |
| Encrypted publish (`publish_delta`) | **G.read** → refresh (`named_groups.read` → ctx state) → seal → publish |
| Release (new) | sync lifecycle mutex → refresh (`named_groups.read` → ctx state write) → hold mutex (no await) → `store.write` → ctx state read (inside apply) |
| Catch-up request (new, own task) | **G.read** → refresh → seal → publish; it never takes the lifecycle lock or the store lock |

There is no cycle. Release waits on nothing that a G holder waits on, because
it never requests G, and the rekey commit holds `named_groups.write` only
across a synchronous block. Release completes while another task holds G read
or G write. A test holds `G.write` and asserts that the release completes
(§8).

## 5. Catch-up state request (d)

**Why not at receipt.** The brief asks for a state request on "no key for
epoch". That request cannot help:

- An observer at E seals its `StateRequest` under E.
- Every E+1 holder rejects it as stale material (`open_mutation` epoch gate,
  called from `open_control_message_classified`).
- E-holders cannot possess E+1 content.

A request at receipt is therefore pure chatter.

**What happens instead.** The hold records `catchup_epoch = max(future epoch
observed)`, including epochs refused by a bound, lookahead or eviction. When a
release sees `cur >= catchup_epoch`, it signals a dedicated catch-up task
through a `Notify` and clears `catchup_epoch`. The task:

- enforces a per-store minimum spacing of `STATE_RESPONSE_COOLDOWN_SECS` (15 s),
  because a request inside a responder's cooldown is suppressed anyway;
- takes **G.read** like the bootstrap requester;
- seals the `StateRequest` at the new epoch with `seal_control_message` (which
  requires `is_authorized_reader(local)`);
- publishes it on the side topic under `within_gss_deadline`.

This recovers anything the hold could not keep: evicted, refused or oversized
records, and multi-page retained serves that exceed the byte budget.

**Per-peer rate limiting.** A `StateRequest` is a topic broadcast, not
addressed to a peer, so a per-peer limit on the request itself has no meaning.
What one peer can make this node do is bounded by that sender's hold quota
(§3). Only records from local-roster writers count toward `catchup_epoch`
(§2 check 5 runs before recording). At most one request is sent per store per
15 s.

## 6. Revoked-member safety (e)

- **No key acquisition.** The hold never requests keys and never sends a
  message carrying held content. The only emission is the catch-up
  `StateRequest`, sealed under the requester's own current epoch after
  `is_authorized_reader(local)`. Its content is the requester's `PeerId`, as
  today.
- **A removed node never releases.** It does not receive the E+1 secret, so its
  `current_epoch()` stays at E and no held E+1 entry reaches `epoch <= cur`.
  Once the removal lands locally, `refresh` invalidates the context: there is
  no secret and an empty roster. Check 5 then refuses new entries, the
  authorized-reader guard blocks release, and the TTL removes what is left.
  The catch-up task needs `is_authorized_reader(local)` to seal, so it cannot
  fire either.
- **Nothing is learned.** Held bytes are ciphertext the node already received
  over gossip. The only observable outputs of holding are local counters.
- **Flooding by a malicious member** (still in the local roster at E):
  - Forged future-epoch envelopes cost at most that member's 32 records or
    1 MiB, and eviction takes that member's own entries first (§3).
  - At release, forged ciphertext fails AEAD and is counted as
    `release_rejected`.
  - A genuine E+1 record from a member removed at E+1 fails the writer check
    against the new roster.
  - Verified records of the current epoch live in `KvStore`, which the hold
    never touches.
- **A removed member writing at E+1.** It has no E+1 key, so it cannot produce
  an envelope that opens.

## 7. Other sealed paths (f)

- **TreeKEM KV.** Same class: `TreeKemGroupStoreProtector::open_record`
  (`src/server/routes/stores.rs:1085`) returns "TreeKEM record epoch is stale
  or ahead", and `merge_treekem_record_counted` drops the record. It is **not**
  covered here, for three reasons:
  - `TreeKemKvProtector` has no synchronous epoch accessor, so check 4 needs a
    trait addition.
  - Opening advances and persists the receive ratchet under the group
    membership lock, so the release ordering must be reasoned about against
    commit processing.
  - Encrypted KV v1 is specified for GSS (the `kv_context.rs` header).

  The hold container (`src/kv/epoch_hold.rs`) is payload-agnostic, so the
  follow-up is wiring, not a new design.
- **Sealed task lists** (`src/crdt/sealed.rs`). Same class:
  `open_gss_task_record` fails closed on any non-current epoch, and
  `crdt/sync.rs` counts `TaskSealRejection::OpenFailed` and drops the record.
  Task lists have the same `StateRequest` anti-entropy and the same
  converged-requester gap. It is a follow-up, reusing the container.

Neither follow-up is needed for the R19 legacy-a1 fixture, which uses a GSS
destination store.

## 8. Tests (g)

All tests are socket-free, use no sleeps, and fail if the mechanism is removed.
Pure-container tests take an explicit `now: Instant`.

1. `future_epoch_delta_held_then_applied_after_rekey_install`: the observer is
   at E, the writer seals at E+1, and the record is held rather than merged.
   After `update_from_group(E+1)`, release merges it.
2. `future_epoch_hold_expires_after_ttl`: entries at `now + TTL` are expired
   and counted, and none are released.
3. `future_epoch_hold_flood_is_bounded_and_per_sender_fair`: a flooder fills
   past both quotas. Its own oldest entries are evicted, an honest sender's
   single record survives, and the totals never exceed the bounds.
4. `removed_member_never_releases_held_records`: the removed observer's
   context moves to the post-removal state without the new secret. Nothing
   releases, and TTL expiry clears the hold.
5. `release_completes_while_publication_holds_g`: hold `G.write` (the rekey
   commit shape), then separately a `G.read` with a queued `G.write` (the #973
   shape). Run release, with a refresh hook reading a mock group map, under a
   10 s `tokio::time::timeout`. It completes and merges in both phases.
6. `catchup_state_request_fires_once_per_window`: two epoch advances inside one
   window produce one signal. After the window, the next advance produces
   another. The limiter takes an injected clock.
7. `r19_barrier_converges_after_observer_installs_next_epoch`: the writer at
   E+1 (after a member removal) writes a barrier. The observer at E processes
   the live payload through the same path the listener uses, then installs
   E+1. The barrier becomes readable, and a removed member's forged
   E+1-epoch envelope is released-rejected.

Plus `future_epoch_hold_refuses_records_failing_pre_decrypt_checks`: a stale epoch, beyond-lookahead, a non-roster sender,
an unsigned payload and a foreign store are never held.

## 9. Open questions

1. **Key delivery itself.** The hold turns "record before key" into a delay
   instead of a loss. It does nothing if the E+1 secret never arrives, which is
   the suspected R19-private shape ("a node never gets the wiki owner key").
   That remains a named-groups delivery bug, and #973's G stall is the leading
   candidate for the slowdown.
2. **New members at E+1.** A member added in the same rotation is not in the
   observer's E roster, so check 5 refuses its records. They are recovered only
   through the catch-up request. Relaxing check 5 would let any mesh
   participant use the hold.
3. **ADR.** This amends step 8 of the receive flow in
   `docs/design/encrypted-kvstore.md` ("drop undecryptable … records") to "hold
   future-epoch records, bounded". There is no wire or storage change, so a
   design-doc amendment seems sufficient. A human should decide whether a
   Proposed ADR (R6/R9) is wanted.
