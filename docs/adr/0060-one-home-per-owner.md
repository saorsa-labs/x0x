# ADR 0060: One Home Per Owner — Cross-Device Election and Adoption

- **Status:** Proposed
- **Date:** 2026-09-05
- **Decision owners:** David Irvine (direction), Claude (drafting)
- **Reviewers:** —
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** [ADR 0038](./0038-home-owner-certified-personal-space.md)
  (the unit of Home), [ADR 0041](./0041-cross-machine-state-sync-tiers.md)
  (Tier-1 surface widened to five kinds)
- **Related:** issue #449; #435 (the per-machine dedup marker), #447
  (certified join needs a second announce), #446;
  `docs/design/449-single-home-per-owner.md`

## Context

ADR 0038 says two things that cannot both hold:

> "Every install with an owner auto-creates one **Home** space at first run"

> "Home always contains ≥1 `Roaming` agent (ADR 0037), so it follows the user
> across machines."

The first sentence makes Home a property of the *install*; the second promises
it is a property of the *user*. Issue #449 is that contradiction reaching
production: three daemons sharing one owner `user.key` each auto-provisioned
their own Home, because dedup was a marker file in the instance data dir plus
a scan of the LOCAL roster (`find_home`). Nothing consulted the owner's other
devices, so an owner with N devices got N competing Homes, and `GET /home` on
each device confidently returned its own duplicate — two authoritative answers,
no error anywhere.

The transport that could have carried the answer already existed and was
inert: ADR 0041 Tier-1 replicates a `HomePointer` record between enrolled owner
devices, but its apply arm was a documented no-op ("cross-machine Home adoption
… deliberately out of Tier-1 scope (gapcheck blocker 32)").

Confirming #449 surfaced three further defects. The `HomePointer` register is
keyed by the constant `"home"` — one LWW slot per owner — and `mint()` takes
the slot at `version + 1` whenever the value differs, on a 60s reconcile tick.
Two enrolled devices with different Homes therefore fought over that slot
without end, re-signing and re-persisting a record every minute each. The
published pointer was also selected with `.find()` over an unordered map using
a weaker predicate than `find_home`, so a device could advertise a Home it was
not even a member of. And `find_home` had no `!withdrawn` filter while
withdrawal keeps `members_v2` and `home` populated, so retiring a Home through
the existing delete path would have wedged `GET /home` and re-provisioning
permanently.

## Decision Drivers

- The ADR 0038 promise is per-OWNER; the implementation was per-install.
- MLS state cannot be merged. Home is Hidden + MlsEncrypted, which routes to
  real TreeKEM; the only entries into a tree are `create` and
  `join_from_welcome`. There is no merge path, so the answer is
  join-one-and-retire-the-other, never reconcile-two.
- An offline or un-synced device must still get a working Home. Suppression
  alone would leave an unreachable device with none, which is worse than a
  duplicate.
- Nothing may be destroyed before a real seat in the canonical Home exists.
- The owner layer must stay strictly opt-in: an install with no `user.key`
  provisions no Home and mints no owner-sync records.

## Considered Options

1. **Suppress provisioning when a peer Home is known.** Necessary but not
   sufficient — an un-synced device knows nothing and still provisions.
2. **Deterministic owner-derived `group_id`** (`H(owner_pk)`) so every device
   "creates" the same Home.
3. **Never auto-provision**; require the owner to create Home explicitly.
4. **One agent key on every device** (ADR 0043 key move), so there is only one
   agent and therefore one Home.
5. **Optimistic provisioning + election + winner-driven adoption.**

## Decision

We will adopt option 5: **the unit of Home is the owner, not the install.**

- Auto-provisioning stays, but is **optimistic and subject to election**. A
  device provisions only when no owner device has advertised a Home; absence
  of a register value means "unknown", never "none exists".
- The Tier-1 `(HomePointer, "home")` register is the **canonical pointer**. A
  device mints into it only when the register is empty, when it is that Home's
  designated primary agent and the value changed, or when its own Home is
  strictly preferable under `(provisioned_at_ms, group_id)` — oldest wins, id
  breaks ties. Both devices compare the same tuples, so they elect the same
  winner; the value strictly decreases, so the register converges.
- `GET /home` reports a **state** — `local`, `adoption_pending`, `elsewhere` —
  with 200. "The Home is on another device" is an answer, not a 404.
- **Adoption is winner-driven.** Only a device seated in the canonical Home can
  seal `MemberAdded`, so it issues the invites. Tier-1 gains a fifth kind,
  `SyncKind::HomeInvite` (0x05), keyed by joiner agent hex, carrying an
  addressed v4 `SignedInvite`. A group id alone cannot admit a device: the join
  path needs the invite's `genesis_creation_nonce`, `base_state_revision` and
  `base_state_hash`, which `HomePointer` does not carry.
- **A refused or deferred admission retries and never falls back to minting a
  new Home.** #447's cert-blob race delays admission; without this rule the fix
  reintroduces the bug under a race.
- Retirement of the losing duplicate is **gated**: join first, retire second,
  and only when the duplicate is provably empty. Anything else stays as a
  `conflict` for the owner to resolve.

## Consequences

### Positive

- An owner with N devices converges on one Home, and a device that has not yet
  joined says so instead of forking.
- The register war ends by construction: once every device desires the same
  value, `mint()`'s equality check holds the slot stable.
- `find_home` becomes deterministic and withdrawal-aware, closing the wedge
  that any retire-based fix would otherwise have hit.

### Negative / Trade-offs

- Tier-1 is no longer four kinds. The deny-by-default allowlist is a
  deliberate structural guarantee, so widening it is a real cost, paid here
  because no existing kind can carry join material.
- Adoption requires the winning device online at least once; until then the
  loser holds a usable but non-canonical Home.
- A register naming a Home whose only member is permanently gone is sticky —
  no surviving device can lower it. The manual override is `POST /home/adopt`.
- Dedup only reaches ENROLLED devices. Devices that merely share a `user.key`
  never sync, so they cannot be deduplicated; enrollment
  (`POST /sync/devices/enroll`) is the owner's explicit assertion that two
  machines are theirs, and is the trust anchor for this whole mechanism.

### Neutral / Operational

- The owner layer stays opt-in and is regression-tested as such.
- Mixed fleets: an old daemon keeps writing the `"home"` slot unconditionally;
  a new daemon simply declines to fight it.

## Validation

- Two devices sharing an owner key, cross-enrolled, converge on exactly one
  Home; the assertion is the invariant, not which id won.
- The `"home"` record's `version` stops advancing once converged (pre-fix it
  grew once per device per minute, without end).
- A second device with the owner's Home advertised provisions nothing, and
  `GET /home` reports `elsewhere` with 200.
- A withdrawn Home never resolves as a device's Home.
- An invite addressed to another agent, or expired, is refused rather than
  redeemed.
- A daemon with no `user.key` provisions no Home and mints no records.
