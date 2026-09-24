# ADR 0069: Home Auto-Provisioning Waits for Owner Sync

- **Status:** Proposed
- **Date:** 2026-09-24
- **Decision owners:** David Irvine (product decision on PR #826: wait for sync
  before auto-provisioning), Claude (drafting)
- **Reviewers:** — (human review pending; the implementation had cross-model
  review on PR #826: OMP/GLM-5.3 review #10 on `245196f`, GLM task-reviewer
  APPROVE on `ec27fd7`)
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** [ADR 0038](./0038-home-owner-certified-personal-space.md) (Accepted,
  not edited) — its "every install with an owner auto-creates one **Home** space
  at first run" no longer holds as written: an owned device with owner sync
  available creates a Home only after it has waited for the owner's canonical
  pointer, and does not create one at all when a pointer arrives. Refines
  [ADR 0060](./0060-one-home-per-owner.md) (Proposed, not edited) — its
  optimistic provisioning ("a device provisions only when no owner device has
  advertised a Home") is kept, but at startup "no pointer known" now triggers a
  bounded wait instead of an immediate create. The election, the `!withdrawn`
  predicate, and the retired-pointer exception in ADR 0060 are unchanged.
- **Related:** issue #824; PR #826 (merged into the #802 candidate,
  `codex/final-acceptance-candidate`, merge `71cb954`); commits `2d55d40`,
  `245196f`, `ec27fd7`; #449; [ADR 0065](./0065-duplicate-home-inventory-retirement-deferred.md)
  (duplicates are inventoried, not retired); `docs/api-reference.md` (`GET /home`,
  `POST /home/seat`)

## Context

ADR 0060 made Home provisioning optimistic: a device creates a Home unless an
owner device has already advertised one on the Tier-1 `(HomePointer, "home")`
register. It says "absence of a register value means unknown, never none", but
at startup the code still treated unknown as "create".

Issue #824 showed the result in the R11 synthetic Home e2e (reproduced 2/2).
The owner key was copied to a second device, and the device restarted with
`user.key` and a certificate. Its owner-sync store was empty.
`provision_home` runs at startup before any sync round, so it found no
pointer and created a **second Home**. The device was later seated in the
owner's real Home as well. It then belonged to two Home-shaped groups and still
had no pointer. `resolve_home` fell back to `find_home`'s smallest-stable-id
rule and picked the duplicate. `POST /home/seat` minted an addressed invite into
the duplicate and returned **200 ok**. The owner saw no error, and the invite
led into the wrong Home.

The per-machine marker (#435) could not prevent this. It lives in each
device's own data dir, a fresh device has none, and it is advisory. Only the
pointer suppresses provisioning, and the pointer arrives after startup.

At startup a daemon cannot tell "the owner's first device" from "the Nth
device that has not synced yet". This ADR decides how provisioning behaves
while that is unknown.

## Decision Drivers

- ADR 0060's promise: the unit of Home is the owner, not the install.
  Duplicates are never retired automatically (ADR 0065), so every duplicate
  created at startup is permanent residue.
- A device must never hand out a seat in a Home that is not canonical, and it
  must never report success when it does.
- A first or offline device must still end up with a working Home. An owner
  device that cannot be reached must not leave a device without one.
- No change to the wire protocol or to signed state. The Tier-1 surface stays
  at four kinds (ADR 0041), and no signed value changes shape (see ADR 0060,
  *Deliberately not decided here*).
- Waiting must be bounded, and the API must answer honestly while it waits.

## Considered Options

1. **Defer provisioning until owner sync has had a chance to deliver the
   pointer**, with a bounded fallback (chosen).
2. **Enrollment hands over the Home.** The device that issues the certificate
   or copies the key writes the canonical Home id, or a "join, don't
   provision" marker, into the new device's data dir, and provisioning yields
   to it. This is precise and needs no wait. It needs a product enrollment
   path, though, and today the key copy happens out of band. It also adds a
   second source of canonical-Home truth next to the register.
3. **Accept duplicates.** Keep optimistic creation and rely on the seat guard
   (below), owner-driven seating (ADR 0060, 2026-09-07), and inventory (ADR
   0065). This was the status quo. Every late device would add a permanent
   duplicate, which is the fork that ADR 0060 exists to prevent.

## Decision

We adopt option 1, together with a seat guard that stays in force under any
option.

### 1. An owned device with owner sync and no canonical pointer defers Home creation

At startup (`provision_home_at_startup`, called from `src/server/mod.rs`) every
step that needs no network runs at once. These are the restore verification,
repair or reseal of an existing Home, crash-recovery adoption of an unstamped
Home-shaped group, and yielding to a known canonical pointer. Only step 4,
**creating a fresh Home**, is deferred. It is deferred when all of the
following hold:

- the device holds a live owner user key AND an agent certificate (an owned,
  owner-certified install; unowned installs are unchanged and never provision);
- owner sync is available (`state.owner_sync` is present);
- no effective canonical pointer is known.

The deferral applies **whether or not other machines are already enrolled**.
A new device is typically enrolled only once it is running with the owner key,
which happens during this wait. The deferred task is a background task that
ends on shutdown. When it is released, it re-runs `provision_home` from the
top. If a pointer arrived, the device yields (`elsewhere`). Otherwise it creates.

### 2. Deterministic creator rank and a `rank × 90 s` fallback

`home_creator_rank` is the number of OTHER machines, enrolled for this owner,
whose machine id is smaller than this device's. Every device computes the same
order, so among a set of mutually enrolled devices with no pointer at most one
has rank 0. The wait (`wait_for_owner_sync_round`) ends on the first of:

- a committed record makes a canonical Home known (the device then yields);
- an owner-sync session **completes successfully** and this device has rank 0.
  That session either delivered the pointer or showed that the device it
  reached advertises none. A pass that reached nobody never counts;
- `(rank + 1) × HOME_POINTER_SYNC_WAIT` has elapsed since the wait began, with
  `HOME_POINTER_SYNC_WAIT = 90 s`. That is one 60 s `DEFAULT_SYNC_INTERVAL` pass
  plus 30 s for its session to deliver.

A completed session with no pointer releases **only** the rank-0 device.
Otherwise two fresh, mutually enrolled devices would both wake on the same
empty session and both create a Home. A device of rank *r* creates on its
timer only if every lower-ranked device failed to publish within its own
window, which happens with an offline leader or a partition. Enrollment or a
merged record re-evaluates both the pointer and the rank.

### 3. Creation is linearised against pointer arrival

Once the wait ends, the create path (step 3a) does the following in order:

1. **Quiesce owner sync.** `OwnerSyncService::quiesce_sessions` acquires every
   session slot, which waits out in-flight sessions and holds off new ones.
   Remote records, including a canonical pointer, arrive only inside sessions.
   Queued outbound sessions resume after creation. Inbound streams are dropped
   and the peer retries on its next pass. The wait is bounded by
   `SESSION_TIMEOUT` (60 s) + 30 s. If sessions do not drain in time, the device
   logs a warning and relies on the gate alone.
2. **Hold `canonical_home_gate` for read** from the final pointer check through
   creation and stamping. Every writer of the `("home")` register (`commit_batch`,
   and so `merge_record`, and `mint`) takes the gate for write. No pointer can
   therefore commit locally between the check and the create.
3. Re-check the effective canonical pointer. If one is known, yield.
   Otherwise create and stamp.

The lock order is: session slots, then `canonical_home_gate`, then per-group
membership lock, then `named_groups` and persistence. Sessions take a slot
before the gate, and owner-sync writers never take a membership lock, so no
cycle exists. This is a **local** linearisation boundary. It claims nothing
about cross-device election ordering, which stays with ADR 0060.

### 4. `GET /home` reports `provisioning_pending`

While the deferred task is outstanding and no Home resolves, `GET /home`
returns **200** with `state: "provisioning_pending"`, `canonical_group_id:
null`, `local_group_id: null`. A 404 would read as "Home-less", which is the
same misreading that ADR 0060's `elsewhere` state avoids. The state is
transient. Clients poll until it becomes `local`, `elsewhere` or
`adoption_pending`. It lasts at most `(rank + 1) × 90 s` plus the bounded
quiesce, and possibly longer if persistence itself hangs (see Negative).

### 5. `POST /home/seat` refuses an ambiguous Home with 409 `ambiguous_home`

`seat_home` holds `canonical_home_gate` across resolution and mint (as it did
since #449 r3). If this device is seated in more than one Home-shaped group
(`home_duplicates` is non-empty), it mints only when the effective canonical
pointer names exactly the group it resolved. Otherwise it returns **409**
`reason: "ambiguous_home"` in the existing `seat_conflict` shape with a nullable
`canonical_group_id`, and it mints nothing. A pointer that names one of the held
Homes still seats into exactly that Home, even when `find_home` would have
picked the other. This guard is **independent of the deferral**. It protects
against duplicates the deferral cannot prevent (see Negative).

## Consequences

### Positive

- An enrolled late device no longer forks the owner's Home at startup. It
  waits, receives the pointer, and yields.
- Two fresh, mutually enrolled devices create exactly one Home between them,
  because only one of them can have rank 0.
- A seat can no longer land in a non-canonical Home with a 200. Any ambiguity
  becomes a typed 409 that the CLI and GUI branch on.
- The API stays up throughout and reports a truthful state instead of 404.
- The change is wire-compatible. It adds no record kind, no signed-value
  change and no protocol version change.

### Negative / Trade-offs

- **A first or offline device waits for its Home.** A genuinely first owner
  device, or one that reaches no owner device, gets no Home until its deadline:
  90 s at rank 0, and `(rank + 1) × 90 s` in general. This is the accepted cost
  of option 1.
- **Enrollment is a precondition.** Owner sync refuses unenrolled peers in both
  directions. A device that has only a copied `user.key` and is never enrolled
  (`/sync/devices/enroll`) cannot receive the pointer. After its wait it creates
  a duplicate, just later. The R11 fixture had to be changed to pair devices
  (`245196f`). The `ambiguous_home` guard is what protects seating in this case.
- **Residual: an empty session releases rank 0 early.** The rank-0 device is
  released by any successful session. If that session is with an owner device
  that holds a Home but has not yet minted its pointer (inbound sessions do not
  publish the serving device's pointer first), the new device can still create
  a duplicate. The pointer is minted on the holder's own sync pass, so the
  window is limited to Homes created or changed within the last pass. This was
  raised by Greptile on PR #826 and is not closed here.
- **The fallback trusts the timer, not proof.** A partitioned leader and a
  timed-out follower can each create a Home. ADR 0060's election still resolves
  which one is canonical. The loser is inventoried by ADR 0065, not retired.
- **`provisioning_pending` has no hard ceiling.** The create and seal after
  the wait are deliberately not cancelled, because cancelling a half-persisted
  create is less safe than a slow one. If persistence hangs, the state can
  outlive its bound. Follow-up: surface this as a health warning.
- **A pointer to a semantically invalid Home suppresses provisioning.**
  `effective_canonical_home` validates only the group id plus locally proven
  withdrawal, so such a device reports `elsewhere` indefinitely. Follow-up: an
  owner-facing override, or validation against the synced `HomePointer.policy`.
- **Quiescing drops inbound sessions briefly.** Peers retry on their next pass,
  so unrelated Tier-1 sync (names, profiles, journal) can lag by one interval
  around a Home creation.

### Neutral / Operational

- The `ambiguous_home` guard is a local guarantee, not a distributed invariant.
  A Home enrolled after the duplicate scan but before the invite is written is
  not fenced (`docs/api-reference.md`).
- The live fixture's `--poll-timeout` default (120 s) is below the product
  bound for rank ≥ 1. The latency contract is proven by injected-timeout unit
  tests, not by the live fixture.
- Unowned installs, and owned installs without owner sync, behave exactly as
  before.
- #824 is fixed for enrolled devices. Option 2 (enrollment hands over Home)
  remains open as a future refinement if a product enrollment path is built.
  It would replace the timer with proof for that path.

## Validation

In-process, inert tests (offline agent, no listeners, `HOME`/`X0X_HOME` set to
temp dirs) in `src/server/routes/home.rs`:

- `startup_waits_for_owner_sync_and_never_duplicates_an_arriving_home`: a
  pointer that arrives during the wait means no Home is created. Confirmed to
  fail with the deferral disabled (`left: 1, right: 0`).
- `startup_provisions_exactly_one_home_when_the_sync_wait_expires`: the
  fallback creates exactly one Home, so an offline device is not left Home-less.
- `two_fresh_devices_sharing_an_empty_session_create_exactly_one_home` and
  `only_a_successful_session_releases_the_designated_creator`: the rank rule.
- `a_pointer_landing_while_creation_waits_is_honoured` and
  `timer_expiry_during_an_in_flight_session_creates_no_duplicate`: the
  quiesce plus gate linearisation.
- `startup_on_an_unowned_install_is_unchanged`: the owner layer stays opt-in.
- `home_seat_refuses_ambiguous_duplicate_without_canonical_pointer`: confirmed
  to return 200 into the duplicate with the guard removed.
  `home_seat_with_duplicates_mints_only_into_the_canonical_home` guards
  against over-refusal.

PR #826's CI mirror (#827 at `012ed3c`) was 27/27 green.

**Not yet validated:** a multi-device live run in which an enrolled late device
receives the pointer within its wait and never creates a Home. The R11 fixture
must pair devices for owner sync, and its poll timeout must cover
`(rank + 1) × 90 s`. The empty-session residual above has no regression test.

Review triggers: any change to `HOME_POINTER_SYNC_WAIT`, `DEFAULT_SYNC_INTERVAL`
or `SESSION_TIMEOUT`; any new writer of the `("home")` register (it must take
`canonical_home_gate` for write); a product enrollment flow (reconsider
option 2).

## Notes for AI-assisted work

Drafted by Claude from PR #826, issue #824 and the code at `a926575`. It must not
be marked Accepted without human review. ADR 0038 is Accepted and is amended
only by reference here. Its body is not edited.
