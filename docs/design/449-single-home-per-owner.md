# Fix design: one Home per owner (issue #449)

- **Status:** Draft for review
- **Date:** 2026-09-05
- **Issue:** [#449](https://github.com/saorsa-labs/x0x/issues/449)
- **Related:** ADR 0038 (Home), ADR 0041 (Tier-1 cross-machine sync),
  ADR 0036 (owner singleton), ADR 0037 (placement), ADR 0043 (agent key move);
  issues #435 (the per-machine marker), #446, #447 (certified join needs a
  second announce), #448
- **Verified against:** `f3080c3` (main, 2026-09-05)

## 1. Confirmed behaviour

An owner with N devices gets N competing "Home" groups, permanently.

`provision_home()` (`src/server/routes/home.rs:399`) decides whether a Home
already exists using `find_home()` (`home.rs:79`), which scans **only the
local roster** and requires `info.home.is_some() && is_home_policy(..) &&
info.has_active_member(<local agent>)`. A second owner device has none of
those, so it falls through to fresh provisioning (`home.rs:530`).

Nothing consults the owner's other devices. The `home.json` marker
(`home.rs:42`) is per-instance `data_dir` and is explicitly **advisory** —
`home.rs:10-14` says the roster scan is authoritative — so it is not the
gate and making it owner-keyed alone fixes nothing.

The transport that *could* carry the answer is inert: `SyncValue::HomePointer`
is received, verified, stored — and dropped on the floor
(`src/owner_sync.rs:2294-2299`, "cross-machine Home adoption … deliberately
out of Tier-1 scope (gapcheck blocker 32)").

Sharpest symptom for acceptance criteria: `GET /home` (`home.rs:659`)
resolves through the same `find_home`, so device B does **not** report "no
Home" — it confidently returns its **own** duplicate as the owner's Home.
Two devices, one `user.key`, two different authoritative answers, no error
anywhere.

## 2. Defects found beyond the report

These were not in the issue and change what the fix must contain.

### D3 — the `"home"` register oscillates unboundedly (write amplification)

`HomePointer` is minted under the **constant key `"home"`**
(`owner_sync.rs:2212-2220`) — a single LWW register per owner, ordered by
`RecordClock` (version, signed_at_ms, writer_machine; `owner_sync.rs:260-273`).

`mint()` short-circuits only when the stored value **equals** the desired
value; otherwise it takes the register with `version = stored.version + 1`
(`owner_sync.rs:1348-1351`). `reconcile_local_state()` runs at the head of
**every** `sync_all()` (`owner_sync.rs:2151-2180`) on a 60s ticker
(`DEFAULT_SYNC_INTERVAL`, `owner_sync.rs:1851`, `:2360`).

So two enrolled owner devices holding different Homes fight over the register
forever: each pass bumps the version, flips the canonical pointer, re-signs a
record and re-persists the store — ~1 mint/device/minute, without end.

Latent today only because enrollment is manual (C3). **It goes live the moment
an owner enrolls a second device.** Shipping enrollment without fixing #449
introduces a permanent write-amplification loop.

The value-convergence fix also fixes this: once every device desires the same
`group_id`, `mint()`'s equality check makes the register stable by
construction.

### D4 — the published pointer is nondeterministic

`home_pointer()` (`src/server/routes/sync.rs:74-88`) uses a **weaker
predicate** than `find_home`: only `home.is_some()` plus owner-certified
admission — no full policy match, no `has_active_member(local)` — and selects
with `.find()` over an **unordered** map. Once a device knows more than one
Home-stamped group for the owner (exactly what adoption creates), it can
publish a different `group_id` on each pass. A second oscillation source,
independent of D3.

### D5 — retiring a Home through today's delete path wedges the daemon

`find_home` has **no `!withdrawn` filter** (`home.rs:97-101`), and withdrawal
keeps `members_v2` and `home` populated (`src/groups/mod.rs:1413`, `:1420`).
So a Home retired via `DELETE /groups/:id` still matches: `GET /home` returns
the tombstone, `provision_home` returns early forever, and every Home mutation
409s. `is_home_candidate` has the same gap (`home.rs:135`).

**The naive fix — "delete the duplicate" — bricks Home permanently.**

### D6 — retiring a Hidden Home publishes it to public discovery

The card-publish gate is `info.withdrawn || policy != Hidden`
(`src/server/routes/named_groups.rs:4694-4697`) and `to_group_card` returns
`Some` when withdrawn (`groups/mod.rs:2248`). Withdrawing a Hidden Home
therefore emits a public card carrying its name, description, tags, owner and
member count. The comment at `named_groups.rs:17313-17315` claiming otherwise
is stale.

This is a standalone privacy defect — worth filing separately — and it is
directly adverse to the privacy posture the jams-ecosystem comment describes.

### D7 — retirement orphans history, delegations and task lists

`withdraw_named_group_terminal` (`named_groups.rs:17243`) cleans **crypto
only**: `clear_group_info_key_material` clears exactly `shared_secret`
(`:15802-15804`). Left behind, keyed by the dead group id:

| Data | Location |
|---|---|
| Durable history | `history.db`, `(scope_kind=1, scope_id=<stable group id>)` (`history/store.rs:823`) |
| Group delegations | history.db under `Scope::Group`, rebuilt by full rescan (`server/delegations.rs:128,149,201`) |
| Task lists | naming convention only: `x0x.group.<gid>.symphony.<list>` (`routes/tasks.rs:41-66`) |
| Rider-token grants | raw group ids in `rider-tokens.json` (`rider_auth.rs:78,87`) |
| TreeKEM files | `treekem/<gid>.snap\|.journal\|.hsjournal` |

`Store::purge(&Scope)` exists (`history/store.rs:434`) but its only caller is
`DELETE /history` (`routes/history.rs:352`).

Not at risk: KV stores (`kv/store.rs:51-64` — `Encrypted{group_id}` is
unconstructible/fail-closed) and file transfers (no group refs).

## 3. Constraints that bound the design

**C1 — MLS state cannot be merged.** Groups use real TreeKEM with
Commit/Welcome (`named_groups.rs:1131-1137`, `:1250-1267`). Two independently
created groups have incompatible key schedules. **There is no merge — only
join-one-and-retire-the-other.**

**C2 — `group_id` is 32 random bytes minted at the daemon.**
`named_groups.rs:10668-10672` fills 32 bytes from `thread_rng()`; that hex is
simultaneously the roster map key, `mls_group_id`, and the raw TreeKEM group
id. `stable_group_id()` (`groups/mod.rs:685-690`) returns `genesis.group_id`
else `mls_group_id`, and today they are identical because `with_policy` pins
genesis to the mls id (`groups/mod.rs:600-605`) — a previously separate
BLAKE3-derived genesis id "caused cross-daemon lookup drift". A deterministic
derivation helper does exist (`state_commit.rs:414-419`), which is why O2
below has to be rejected on its merits rather than on feasibility.

**C3 — owner-device sync requires explicit, manual enrollment.** `sync_all()`
only dials `enrolled_devices()` (`owner_sync.rs:2159-2172`); the sole
production path is `POST /sync/devices/enroll` (`server/mod.rs:1739`,
`routes/sync.rs:276`), gated on `actor.is_durable_owner()` (`sync.rs:288`).
There is no auto-enrollment.

Consequence for the repro: three daemons that merely *share* `user.key` were
never enrolled, so no sync ever ran and no pointer could ever have been seen.
Enrollment is the owner's explicit "these machines are mine" assertion — and
it is the correct trust anchor for dedup.

**C4 — B can be admitted on merit, but needs a seat.** Home admission is
`OwnerCertified(owner)` and B already holds an owner-chained cert, so
admission passes cryptographically. What B lacks is a TreeKEM seat: a seated
member must run the Add commit and emit the Welcome. `welcome_ref` is
content-addressed, so B can pull it asynchronously after the winner publishes.

**C5 — Home mutations are already privileged.** `home_mutation_requires_durable`
guards leave/delete (`named_groups.rs:17363`).

**C6 — "known but not joined" is already representable.** `find_home` requires
`has_active_member(local)`; a group that is Home-stamped and Home-policy but
does not contain us *is* "Home lives on another device". No schema change
needed to express the state the issue asks for.

## 4. Options considered and rejected

**O1 — Suppress provisioning when a peer Home is known.** Necessary but not
sufficient, and alone it does not fix the reported repro: an un-enrolled fresh
device knows nothing and still provisions. As the *only* mechanism it also
leaves an unreachable device with no Home at all — worse than a duplicate.
Kept as an optimization, not as the fix.

**O2 — Deterministic owner-derived `group_id`** (`H(owner_pk)`), so every
device "creates" the same Home. Mechanically easy (C2) and superficially
attractive — it is literally "dedup keyed to the owner". **Rejected on two
independent grounds.**

*It converts a duplicate into a fork.* Home is Hidden + MlsEncrypted, which
routes to real TreeKEM rather than the GSS shared-secret plane
(`named_groups.rs:10750-10752`). Epoch-0 is
`TreeKemMlsGroup::create(group_id, agent_id, &seed)` with
`seed = derive_identity_seed(agent_secret, group_id)`
(`named_groups.rs:21716-21719`) — deterministic, but folded with *the creating
agent's own secret*, and `TreeKemGroup::create` mints fresh epoch/init/commit
secrets regardless. The only entries into a tree are `create` (sole leaf 0)
and `join_from_welcome` (`mls/treekem.rs:211, 252, ~300`); **there is no merge
path anywhere in the codebase.** Two devices deriving the same id would build
two epoch-0 ratchet trees with no common ancestor, colliding on one
`metadata_topic` and both claiming `state_revision` authority over the same
id. That is strictly worse than two ids, because every roster/seal/dedup path
assumes one id means one group.

*It also weakens the Hidden guarantee.* `metadata_topic`,
`chat_topic_prefix` and `discovery_card_topic` are derived from
`mls_group_id[..16]` (`groups/mod.rs:559-572`). An owner-derived id makes the
Home's metadata topic **computable by anyone holding the owner's public user
key**. Reads stay gated (MembersOnly + MLS), but topic-level traffic analysis
and join-spam become possible against a group whose entire point is being
Hidden — and that is precisely the cross-device-linkage exposure the
jams-ecosystem comment objects to.

**The fix has to be a rendezvous, not an id scheme.**

**O3 — Never auto-provision; make the owner create Home explicitly.**
Rejected: breaks ADR-0038's first-run promise and regresses single-device UX
for everyone to fix a multi-device case.

**O4 — One agent key on every device (ADR-0043 key move).** Rejected as the
general answer: collapses per-device identity and makes ADR-0037 placement
(Roaming vs Pinned) meaningless. Remains a legitimate *user choice*, not a fix.

## 5. The design

**Optimistic local provisioning + owner-authoritative election on the existing
`"home"` register + winner-driven adoption + gated retirement.**

Optimistic provisioning is retained deliberately: a device that cannot reach a
peer still gets a working Home immediately, and nothing is ever destroyed
before a real seat in the canonical Home exists.

### 5.1 States, surfaced by `GET /home`

| State | Meaning |
|---|---|
| `local` | We are an active member of the owner's canonical Home (today's only success state) |
| `elsewhere` | We know the canonical `group_id`; we are not a member (C6 already expresses this) |
| `adoption_pending` | We hold a local Home that lost the election; adoption in flight |
| `conflict` | We lost, but our local Home is **not** safe to retire. Owner must choose. Never auto-resolved |

`elsewhere` and `adoption_pending` must return **200 with a state**, not the
current 404 — the 404 is what makes a duplicate invisible today.

### 5.2 Election

The canonical Home is the value of the ADR-0041 `("home")` register under the
existing `RecordClock` rule. One rule change:

> A device mints its own `group_id` into `"home"` only when the register is
> empty, or names a group it cannot see. It never mints to replace a peer's
> pointer to a group it can see.

That ends D3 and converges the register. A genuine simultaneous genesis (both
mint version 1) is already totally ordered by `RecordClock`
(signed_at_ms, then `writer_machine`), so both sides compute the same winner.

Fix D4 in the same change: `home_pointer()` must share `find_home`'s predicate
so what we publish is exactly what we consider our Home, deterministically.

### 5.3 Adoption (winner-driven)

**A `group_id` alone is not enough to join.** Hidden groups publish no card
(`discovery_card_topic = None`, `may_publish_to_public_shards(Hidden) == false`),
and the join path requires a **v4 `SignedInvite`** carrying
`stable_group_id`, `policy`, `genesis_creation_nonce`, `base_state_revision`,
`base_state_hash`, `base_home` and a roster projection
(`populate_invite_base_state_v4`, `routes/identity.rs:382-400`).
`SyncValue::HomePointer` carries only id + policy + roster + primary_agent +
`provisioned_at_ms` — enough to *elect*, **not** enough to *join*. Closing
that gap is the one genuinely new mechanism this fix needs (see §5.4).

Given an invite, the existing sequence is:

1. **Winner** `POST /groups/:id/invite` → `create_group_invite`
   (`named_groups.rs:12998 / 13266`), Admin+.
2. **Loser** `POST /groups/join` → `join_group_via_invite`
   (`named_groups.rs:13626`) with `mode: "home"` and
   `expected_owner_user_id` (fail-closed matrix at `~13817-13847`). It installs
   a pending stub and publishes a joiner-signed `MemberJoined` carrying
   `treekem_key_package_b64`.
3. **Winner** runs `owner_certified_admission_check`, then `add_member`
   (epoch + 1), then publishes `MemberAdded` (`named_groups.rs:1122-1163`)
   with `treekem_commit_b64`, `welcome_ref`, `treekem_epoch`,
   `certificate_b64` and the signed commit.
4. **Loser** pulls the Welcome (`pending_welcome_waiters`, `state.rs:780-782`),
   runs `join_from_welcome`, adopts the chain. `GET /groups/:id/join-status`
   reports the outcome. `find_home` now resolves to the canonical Home; state
   → `local`.
5. Only then does the loser retire its duplicate (§5.5).

**The winner must be online.** The Welcome comes from a live TreeKEM instance
at the current epoch, and only an Admin can seal `MemberAdded`; in a fresh
Home the winner is the sole Admin. There is no offline or pre-issued path.
Until the winner appears, the loser sits in `adoption_pending` **with its
local Home fully usable** — which is the whole reason provisioning stays
optimistic.

**#447 interaction — the load-bearing rule.** #447 is the async cert-blob
race: the winner cannot verify the loser's owner cert until the blob lands
(mitigated by `lib.rs:2301-2364` and `owner_cert_pending_joins`,
`state.rs:787-793`). It *delays* admission rather than blocking it, but a
freshly booted loser is exactly the worst case. Therefore:

> A refused or deferred admission MUST retry. It must never fall back to
> minting a new Home.

Without that rule the fix reintroduces the bug under a race.

Note also that the roster is **not** a CRDT: it is a signed commit chain where
the higher revision wins (`state_commit.rs:444-448`), co-committed with the
TreeKEM epoch. Election therefore cannot lean on roster merge — it has to come
from the `"home"` register (§5.2).

### 5.4 Invite delivery — decision required

The winner must get a `SignedInvite` to the loser. Three options:

1. **New `SyncKind::HomeInvite`** on the SyncV1 stream. Clean and already
   authenticated between enrolled devices, but `SyncKind` is a deny-by-default
   structural allowlist of exactly four kinds (`owner_sync.rs:165-190`), so a
   fifth kind is an ADR-0041 amendment.
2. **Extend `HomePointer`** with the v4 base-state fields so it becomes
   self-sufficient. Smallest wire change, but it puts `base_state_hash` and
   the genesis nonce into a record that every enrolled device stores at rest.
3. **Sealed DM** between the owner's agents, out of band of SyncV1. No ADR
   change, but a second delivery path to make reliable and reason about.

Recommendation: **(1)**. It keeps the owner-device channel the single
authenticated rendezvous and makes the amendment explicit rather than
smuggling join material into a pointer record.

### 5.5 Retirement gate

Order is **join-then-retire, never retire-then-join.** Auto-retire only when
every condition holds (all evaluable in-process):

```
info.home.is_some()
&& !info.withdrawn                                   // groups/mod.rs:321
&& is_home_policy(&info.policy, &owner)              // home.rs:70
&& info.active_members().count() == 1                // groups/mod.rs:2204
&& that member == local agent hex
&& info.join_requests.is_empty() && info.issued_invites.is_empty()
&& history.query(Scope::Group(stable_id), limit=1).is_empty()
&& no crdt subscription with prefix "x0x.group.<id>." or "<stable_id>."
&& no rider-tokens.json grant naming <id> or <stable_id>
&& adoption to the canonical Home has COMPLETED (we are an active member there)
```

Anything else → `conflict`; keep both, surface to the owner, never delete.

Retirement must additionally, per D5–D7:

- add the `!withdrawn` guard to `find_home` and `is_home_candidate`, or use a
  non-terminal retire path (a tombstone that still matches `find_home` is a
  permanent wedge);
- suppress the withdrawn-card publish for Hidden groups;
- explicitly purge or repoint history, delegations, group-scoped task lists
  and rider grants — today all four are silently orphaned.

A freshly auto-provisioned, untouched Home is genuinely empty (1 member, Home
metadata, genesis + stamp commits, one `.snap`, marker, listener; no card, no
history rows, no KV, no tasks), so the common case retires cleanly.

## 6. API and CLI surface

- `GET /home` — add `state`, `canonical_group_id`, and `duplicates[]` on
  conflict. The `local` success shape is unchanged, so the GUI does not break.
- `POST /home/adopt {group_id}` — owner-forced adoption (durable token).
- `POST /home/retire {group_id}` — owner-forced retirement; the only exit from
  `conflict` (durable token).
- CLI: `x0x home`, `x0x home adopt`, `x0x home retire`.

## 7. Phasing

| Phase | Content | Depends on |
|---|---|---|
| **P0** ✅ | D3 + D4: stop the register war, make the published pointer deterministic | — |
| **P1** ✅ | Election + `GET /home` states + suppression at provisioning | P0 |
| **P2** ⛔ | Invite delivery channel (§5.4) — WITHDRAWN, see below | P1 |
| **P3** ⛔ | Winner-driven adoption — WITHDRAWN. D5 (`!withdrawn` filter) landed with P1 | P2, #447 |
| **P4** | Retirement gate + D6/D7 cleanup; `conflict` state and forced adopt/retire endpoints | P3 |

P0 is small, independently shippable, and blocks a regression that lands the
moment anyone enrolls a second device. After P1 a second device *reports* the
truth instead of silently forking, which is most of the user-visible harm.

**P0 as implemented** (`owner_sync::home_pointer_mint_decision`,
`DaemonView::home_pointer`): the election rule is extracted as a pure function
so the convergence property is unit-testable without a daemon. One refinement
came out of writing the test — the primary-agent refresh branch must also
require that the value **actually changed**. Entitlement alone re-fires every
pass; `mint()` would no-op on the unchanged value, but then quiescence is not
observable at the decision level and the regression test cannot assert
termination. The contract is therefore "a write would change something", not
"we are allowed to write".

**P1–P3 as implemented.** `HomeResolution` / `resolve_home` (`home.rs`) is the
state machine; `provision_home` yields when the register already names a Home;
`GET /home` answers `local` / `adoption_pending` / `elsewhere` with 200 instead
of a bare 404. `find_home` gained the `!withdrawn` filter (D5) and deterministic
`min_by(stable_group_id)` selection — without the latter, a device seated in
both its old duplicate and the canonical Home during adoption could answer with
either. `resolve_home` additionally prefers the canonical Home whenever we are
seated in it, so the transition settles deterministically.

**P2/P3 WITHDRAWN after review of `4629117`.** An implementation of §5.4 as a
fifth Tier-1 kind (`SyncKind::HomeInvite`) plus a `CertMode::Acp` filter was
written, reviewed, and removed. Three blocking defects, all properties of the
mechanism rather than bugs in it:

1. **Signed-record compatibility.** The new variant was inserted ahead of
   `IssuanceJournal`, shifting its bincode discriminant so `verify()`
   reconstructed different signed bytes and invalidated pre-upgrade issuance
   signatures. Appending fixes the ordering, but any change to a signed value's
   shape sits in this hazard class and needs an old-record fixture.
2. **Protocol compatibility.** A fifth closed-enum kind under an unchanged
   protocol version 2 cannot be decoded by older peers, aborting the entire
   owner-sync session — including unrelated names, profile and journal sync.
   The kind needs negotiation or a staged rollout.
3. **No trustworthy cross-device device/rider signal.** `apply_journal_line`
   materializes synced issuance records with `mode: Acp`
   (`owner_sync.rs:2567-2577`), and `owner_issued_certificates()` treats
   journal records as authoritative on ties. A Rider issued on device A
   therefore arrives on device B indistinguishable from a device agent, so the
   filter was defeated in exactly the multi-device case it existed for. The
   certificate does not carry hosting mode either. Inventing a device-only
   rule in the implementation would have silently amended ADR-0039's
   mode-agnostic Home eligibility and deny-by-default rider scope.

So adoption, retirement, and any device-vs-rider Home eligibility rule are
deferred and must be decided explicitly — with ADR-0039 reconciled, not
bypassed. **#449 remains open.**

Known limitation carried into P1: because a yielding device publishes nothing
and only strict improvements take the slot, a register naming a Home whose
only member has permanently gone (device lost, Home deleted) is **sticky** —
no surviving device can lower it. P1's `elsewhere` state makes that visible
and P4's `POST /home/adopt` is the manual override; until then the failure
mode is a stale pointer, not a wedge, because the apply arm is still a no-op.

D6 (Hidden-Home card leak) should be filed and fixed on its own timeline — it
is a privacy bug that exists independently of #449.

## 8. Test plan

Tests encode *why* (Rule 9), asserting invariants rather than mechanics.

- **One Home per owner.** Two-device fixture, same owner key, cross-enrolled:
  after convergence exactly one `group_id` is Home-stamped-and-joined on both.
  Assert the invariant, not which id won.
- **Register stability (would have caught D3).** Two devices holding different
  Homes, N sync passes: the `"home"` record `version` must stop advancing once
  converged. Today it grows unbounded.
- **Ordering safety.** Kill the winner mid-adoption: the loser still has a
  working local Home and has retired nothing.
- **Refusal never mints (#447 rule).** Make the winner defer admission (cert
  blob not yet landed): the loser retries and must **not** provision a second
  Home. This is the test that stops the fix reintroducing the bug under a race.
- **No wedge after retirement (D5).** Retire a duplicate, restart: `GET /home`
  resolves to the canonical Home, not a tombstone, and mutations do not 409.
- **Hidden stays hidden (D6).** Retiring a Home publishes no discovery card.
- **Opt-in preserved (jams-ecosystem ask 1).** No `user.key` ⇒ no Home
  provisioned, no owner-sync records minted, `GET /home` reports the un-owned
  state. Regression-locks the property they depend on.
- **Owner-keyed dedup (ask 2).** Two owners on one machine (separate
  instances) never collide; the marker is owner-scoped.
- **Conflict path.** Give the loser content: it is not auto-retired and
  reports `conflict`.

## 9. ADR impact

ADR-0038 carries the contradiction directly:

> "Every install with an owner auto-creates one **Home** space at first run"

versus

> "Home always contains ≥1 `Roaming` agent (ADR 0037), so it follows the user
> across machines."

The first sentence specifies the bug; the second states the promise #449 says
is broken. This needs **ADR-0060** amending ADR-0038: the unit of Home is the
**owner**, not the install; auto-provisioning is optimistic and subject to
election; the `"home"` register is the canonical pointer; adoption is
winner-driven and retirement is gated.

ADR-0041's "gapcheck blocker 32" deferral also needs updating, since
cross-machine Home adoption stops being out of scope.

## 10. Response to the jams-ecosystem comment (#449)

- **Ask 1 (owner layer stays strictly opt-in): already true, and structurally
  so.** `provision_home` returns at `home.rs:410` when no user key is present;
  no Home, no nudge. Section 8 adds a regression test so this fix cannot erode
  it.
- **Ask 2 (dedup keys to the owner, not the machine): adopted** — it is the
  core of this design. Their stated *symptom* is however wrong against current
  code: `read_verified_marker` already rejects a marker naming a different
  owner (`home.rs:160-167`), and the marker never suppresses provisioning, so
  "the second owner on a machine gets no Home" does not occur today.
- **Q3 (scoped/non-public owner certs):** out of scope here — an
  identity-privacy decision, not a dedup one, and it deserves its own ADR.
  Note D6 above is adjacent and real: retiring a Hidden Home currently leaks a
  public card.

## 11. Open questions

1. Is enrollment the right prerequisite for dedup? This design assumes yes —
   it is the owner's explicit assertion and the correct trust anchor.
   Deduping between devices that merely share `user.key` would need a
   discovery path that does not exist.
2. **Invite delivery (§5.4)** — new `SyncKind::HomeInvite` (recommended,
   costs an ADR-0041 amendment), extend `HomePointer`, or a sealed DM? This is
   the only genuinely new mechanism in the fix and it gates P2.
3. #447 *delays* rather than blocks admission, so P3 does not strictly need it
   fixed first — but the "retry, never fall back to minting" rule (§5.3) has
   to hold regardless. Fix #447 first, or ship the retry rule and let #447
   land separately?
4. Should D6 (Hidden-Home card leak) block this work, or ship as its own fix?
