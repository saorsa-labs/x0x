# ADR 0060: The Owner's Home Is Elected, Not Per-Install

- **Status:** Proposed
- **Date:** 2026-09-05
- **Decision owners:** David Irvine (direction), Claude (drafting)
- **Reviewers:** — (Codex review of PR #507 at `4629117`; Jarvis Senior Engineer ADR conformance pending)
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** [ADR 0038](./0038-home-owner-certified-personal-space.md) — the unit of
  Home. **No amendment to [ADR 0041](./0041-cross-machine-state-sync-tiers.md)**
  (the Tier-1 surface stays at four kinds) and **none to
  [ADR 0039](./0039-agent-harness-boundary.md)** (Home eligibility stays
  mode-agnostic) — see *Deliberately not decided here*.
- **Related:** issue #449; #435, #447, #446, #506;
  `docs/design/449-single-home-per-owner.md`

## Context

ADR 0038 says two things that cannot both hold:

> "Every install with an owner auto-creates one **Home** space at first run"

> "Home always contains ≥1 `Roaming` agent (ADR 0037), so it follows the user
> across machines."

The first sentence makes Home a property of the *install*; the second promises
it is a property of the *user*. Issue #449 is that contradiction reaching
production: daemons sharing one owner `user.key` each auto-provisioned their
own Home, because dedup was a marker file in the instance data dir plus a scan
of the LOCAL roster. `GET /home` on each device then returned its own duplicate
as authoritative — several answers, no error anywhere.

Confirming #449 surfaced three further defects: the constant-key `("home")`
Tier-1 register oscillated forever between devices holding different Homes
(each 60s pass re-signing and re-persisting a record); the published pointer
was selected nondeterministically with a weaker predicate than `find_home`; and
`find_home` had no `!withdrawn` filter, so retiring a Home through the existing
delete path would have wedged `GET /home` and re-provisioning permanently.

## Decision Drivers

- ADR 0038's promise is per-OWNER; the implementation was per-install.
- An offline or un-synced device must still get a working Home; suppression
  alone would leave an unreachable device with none, which is worse than a
  duplicate.
- Nothing may be destroyed before a real seat in the canonical Home exists.
- The owner layer must stay strictly opt-in: no `user.key`, no Home, no records.
- **Old-version compatibility is a hard constraint.** Owner-sync records are
  owner-signed and their signatures cover serialized bytes.

## Considered Options

1. Suppress provisioning when a peer Home is known.
2. Deterministic owner-derived `group_id` so every device "creates" the same Home.
3. Never auto-provision; require the owner to create Home explicitly.
4. One agent key on every device (ADR 0043 key move).
5. Optimistic provisioning + election on the existing register, with adoption
   of the losing device deferred to a follow-up.

## Decision

We will adopt option 5: **the unit of Home is the owner, not the install, and
the owner's canonical Home is elected on the existing Tier-1 register.**

- Auto-provisioning stays, but is **optimistic and subject to election**. A
  device provisions only when no owner device has advertised a Home. Absence of
  a register value means "unknown", never "none exists".
- The Tier-1 `(HomePointer, "home")` register is the **canonical pointer**. A
  device mints into it only when the register is empty, when it is that Home's
  designated primary agent and the value changed, or when its own Home is
  strictly preferable under `(provisioned_at_ms, group_id)` — oldest wins, id
  breaks ties. Both devices compare the same tuples, so they elect the same
  winner; the value strictly decreases, so the register converges.
- The publisher and the resolver share one predicate, including `!withdrawn`:
  a retired Home is never advertised as canonical and never resolves locally.
- `GET /home` reports a **state** — `local`, `adoption_pending`, `elsewhere` —
  with 200. "The Home is on another device" is an answer, not a 404.

**This ADR does not decide how a losing device joins the winner's Home.** That
mechanism is deferred (see below), so a second device today converges on the
correct *answer* and reports it honestly, but does not yet become a member.

## Deliberately not decided here

A first implementation added a fifth Tier-1 record kind carrying an addressed
invite, plus a filter excluding ADR-0039 `Rider` agents from automatic Home
invites. Independent review of `4629117` found three blocking defects, and all
three are properties of that mechanism rather than bugs in it:

1. **Signed-record compatibility.** Inserting a variant ahead of
   `IssuanceJournal` shifted its bincode discriminant, so `verify()`
   reconstructed different signed bytes and invalidated pre-upgrade issuance
   signatures. Appending fixes the ordering, but any change to a signed value's
   shape is in this hazard class.
2. **Protocol compatibility.** A fifth closed-enum kind under an unchanged
   protocol version cannot be decoded by older peers, aborting the whole
   owner-sync session — including unrelated names, profile and journal sync.
   The new kind needs negotiation or a staged rollout.
3. **No trustworthy cross-device device/rider signal.** `apply_journal_line`
   materializes synced issuance records with `mode: Acp`, and
   `owner_issued_certificates()` treats journal records as authoritative on
   ties. A Rider issued on device A therefore arrives on device B indis-
   tinguishable from a device agent. The certificate does not carry hosting
   mode either, so **no sound basis exists today for a device-only
   auto-invite** — and inventing one in the implementation would have silently
   amended ADR-0039's mode-agnostic Home eligibility and its deny-by-default
   rider scope.

Consequently, adoption, retirement and any device-vs-rider Home eligibility
rule are **out of scope for this ADR** and must be decided explicitly — with
ADR-0039 reconciled rather than bypassed — before implementation.

## Consequences

### Positive

- An owner with N devices converges on one canonical *answer*, and a device
  that is not a member says so instead of forking.
- The register war ends by construction: once every device desires the same
  value, the store's equality check holds the slot stable.
- `find_home` becomes deterministic and withdrawal-aware, closing the wedge any
  retire-based fix would otherwise hit.
- Wire-compatible: no new record kind, no change to any signed value's shape,
  no protocol version change.

### Negative / Trade-offs

- **#449 is not fully fixed.** A second device still holds its own Home and
  reports `adoption_pending`; it does not join the owner's Home. The duplicate
  persists.
- A register naming a Home whose only member is permanently gone is sticky —
  no surviving device can lower it, and no manual override exists yet.
- Election only reaches ENROLLED devices; devices merely sharing a `user.key`
  never sync and are unaffected.

### Neutral / Operational

- The owner layer stays opt-in and is regression-tested as such.
- Mixed fleets: an old daemon keeps writing the register unconditionally; a new
  daemon declines to fight it.

## Validation

- The `"home"` record's version stops advancing once devices agree (pre-fix it
  grew once per device per minute, without end).
- Two daemons holding the same two Homes publish the same pointer — a property
  the previous unordered-map selection could not provide.
- A second device with the owner's Home advertised provisions nothing and
  `GET /home` reports `elsewhere` with 200.
- A withdrawn Home neither resolves locally nor is advertised as canonical.
- A daemon with no `user.key` provisions no Home and mints no records.
- `SyncKind::ALL.len() == 4` — the Tier-1 tripwire remains untripped.
