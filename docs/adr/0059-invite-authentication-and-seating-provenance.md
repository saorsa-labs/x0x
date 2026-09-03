# ADR 0059: Invite Authentication and Seating Provenance

- **Status:** Proposed (acceptance follows in a docs PR after v0.41.0 ships)
- **Date:** 2026-09-02
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** hs-FU-A independent review (Fable r1, Codex r1/r2)
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** ADR 0016 §7
- **Related:** issues #468, #469, #472, #458, #447; `docs/design/hs-followups-design-2026-09-02-v4.md` (+v5/v6/v7 deltas); PR #474

## Context

ADR 0016 §7 documents the equal-revision fork-choice limitation of the flat-admin
state-commit chain: a joiner whose local view sits at revision N cannot
distinguish an admin's internally-consistent alternate N+1 from the canonical
chain. The round-7 review of #467 additionally found (#469) that invites were
unauthenticated on the wire — the inviter-supplied policy and base roster seeded
the joiner's admission tier and trust root with only the invite-secret handshake
guarding admission, and the vestigial `signature` field was never validated.

v0.41.0 ships a hardening subset (PR #474). The full protocol response —
pre-commit owner mandates, alternate-chain authority validation, quarantine, and
content-addressed base snapshots — is deliberately deferred to #472.

## Decision

### 1. Authenticated invites — InviteV4 (#469)

Invites are signed artifacts. The signed view is the whole `SignedInvite` minus
the three signature outputs and the legacy fat roster, canonically encoded as
`x0x.invite.v4\0 ‖ postcard(view)`; a compile-time exhaustiveness guard
(destructuring every field by name into the view constructor) makes any future
field ride signed or fail to build. Option fields are Option-preserving (None
and `Some("")` are distinct signed states). Signatures: ML-DSA-65 by the inviter
AGENT key (`x0x.invite.v4.inviter\0`) and, for policies carrying an
OwnerCertified axis, a countersignature by the owner USER key
(`x0x.invite.v4.owner\0`). Both public keys travel INLINE and are
self-authenticating: the domain-separated `AgentId::from_public_key` /
`UserId::from_public_key` derivation must equal the claimed ids (the id IS the
hash of the key), then the revocation set is checked, then the signatures.

The joiner verifies everything BEFORE any stub, listener, or duplicate
handling: version, empty legacy signature, expiry, stable-id equality,
duplicated-metadata and home-digest preimage equality, inviter binding +
revocation + signature, base-consistency (the base state hash is re-derived
from the carried roster projection and public-meta snapshot), the owner
countersignature, and the intended-joiner address. Typed refusals surface as
`invites_refused{reason}` diagnostics. An inviter can therefore no longer
silently select the joiner's admission tier or trust root.

**Owner user-key revocation has no subject today** (the revocation set covers
Agent, Machine, and Agent–Machine bindings only) — deliberately out of scope;
#472 may add a `User` subject.

### 2. Home-join mode (#469)

`POST /groups/join` gains `mode: "home"` + `expected_owner_user_id` with a
fail-closed matrix (`use_home_mode`, `pin_requires_home_mode`,
`home_mode_requires_pin`, `invite_downgraded`, `owner_mismatch`). A Home join
pins the exact admission owner the invite's verified countersignature covers.
The durable-owner mutation fence keys on the POLICY OWNER AXIS (any
OwnerCertified-capable group), not just Home metadata.

### 3. Seating tiers and provenance

Seating keeps ADR 0016's two adoption tiers, now instrumented:

- **Tier 1** — across-gap adoption corroborated by a VERIFIED owner head
  attestation under an OwnerCertified policy.
- **Tier 2** — round-4 reconstruction from the invite base (no weaker than the
  direct gapless apply path; both trust the invite base and the admins it
  seats).

Every invite-derived seat records an `invite_lineage` (base revision/hash/
roster-root, seat revision, corroboration flag, first complete fork evidence).
Lineage is strictly LOCAL: stripped from every outbound bootstrap snapshot,
rejected wholesale inbound, never inside the state hash. It is created as a
PENDING marker at stub creation so intermediate commits before the seat cannot
lose the base, and finalized on gapless seat, across-gap seat, and
base-already-seated self-rejoin paths.

### 4. Fork evidence (#468)

A central hook evaluates every rejected state commit routed through the
shared apply wrapper (see the Validation section for the covered variant
matrix):
`PrevHashMismatch` is a candidate; `StaleRevision` only when a retained local
commit exists at that exact revision with a DIFFERENT state hash (identical
hash = duplicate replay; outside retained history = unclassifiable). A
candidate becomes ONE recorded `ForkEvidence` only when its signature verifies
and its committer was an active admin in the retained predecessor roster;
evidence is identity-deduplicated `(revision, state_hash, committed_by)`, first
complete evidence wins, and it is durably persisted. Unauthenticated candidates
increment a WINDOWED `conflict_unauthenticated` rate-limit counter — one
increment per group per second, because unauthenticated conflict packets are
freely replayable and the counter must observe conflict PRESSURE, not the
attacker's packet rate. **No state change,
eviction, or quarantine follows from evidence** — observability only.

### 5. The stale-base residual and the old-admin-key caveat (#468)

The Decision-7 limitation stands: with the joiner at N, an admin valid at N but
canonically removed at N+1 can still serve an internally consistent fork that
every check passes; the joiner adopts it and the next canonical commit
`PrevHashMismatch`es. Evidence now makes this observable (the canonical commit
arrives as authenticated fork evidence), but distinguishing forks at adoption
time requires an authority anchor the chain itself cannot provide. The full
fix — pre-commit owner mandate on `MemberAdded`, alternate-chain authority
validation from the common ancestor anchored on an independent owner/head key,
persistent route-complete quarantine, and content-addressed base snapshots for
over-budget rosters — is DEFERRED TO #472. The old-key availability attack on
any future fork/eviction decision (deciding with a canonically-removed admin's
key, or rejecting an admin promoted after the base) is called out there.

## Consequences

- Unsigned legacy invites are refused with a typed `invite_unsigned`; rollout
  must upgrade inviters/authorities before joiners and re-mint invites.
- v4 invites carry the roster projection (no certificate bytes): digest-only
  members hash identically to their byte-bearing form, and certificates
  hydrate from the authenticated announce/discovery cache (digest-matched;
  mismatches are never silently installed).
- Minting is bounded: per-field caps (including the Home-metadata caps
  the join side enforces — 64-hex primary agent, placements bounded by
  the roster cap), a derived roster cap (pinned by a
  worst-case final-encoder fixture against the 40,960-byte link budget and the
  49,152-byte DM ceiling), 64 live unconsumed records per group, and the final
  encoded size as the authoritative gate — all before any secret is recorded.

## Validation
- `src/groups/invite.rs` unit suite (28 tests at round-5): canonical-bytes vector
  (blake3-pinned), missing-field → typed-refusal matrix, sign/verify
  tamper matrix incl. None↔Some("") signed-state flips, D1 equality
  rules + non-default meta round-trip, the D5 caps matrix (incl. the
  round-4 Home-metadata caps, enforced at mint exactly as at join), and
  the F4 worst-case final-encoder fixture — an EQUALITY pin: the roster
  cap IS the derived maximum (20 entries, worst-case Home included,
  against BOTH the 40,960-byte link budget and the 49,152-byte cmd-DM
  envelope; the link-only budget would admit 30), so the test fails if
  the constant is raised OR lowered — plus the v0.40.4 tag-copied
  cross-version replica fixtures (old→new parse-then-refuse, new→old
  ordinary parse, owner-axis fail-closed).
- Joiner validation/mode matrix, card reuse-or-mint, evidence dedup,
  and the F1 hydration surfaces are pinned by the server-route suites
  and `member_certificate_bridge_tests` (3 tests: pre-populated-cache
  startup reconcile, deterministic event-ring-overflow lag recovery via
  full reconcile, idempotent re-run hydrating nothing).
- Full workspace: 3 228 tests green at the pre-round-4 PR head; the
  round-4 additions are verified per-suite above, and the parent re-runs
  the full workspace before merge (the number only grows).
