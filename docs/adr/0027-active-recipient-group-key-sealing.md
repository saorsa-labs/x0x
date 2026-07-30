# ADR 0027: Active-Recipient Group-Key Sealing

- **Status:** Proposed
- **Date:** 2026-07-30
- **Decision owners:** David Irvine
- **Reviewers:** Sam (author); Dario; Watson. Watson made Kimi's reserved
  cleanup rulings under David Irvine's delegation (Buzz event `eb6a888a`);
  Kimi's independent design review of this authored decision is pending
  before implementation.
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR 0024; ADR 0025;
  `docs/design/active-recipient-group-key-sealing.md`

## Summary

A production call path that chooses a named recipient for current-epoch group
key material verifies that the recipient is an active member before sealing.
A recipient-selecting call path may omit that check only when the path itself
is excluded from production builds at compile time and the record carries
evidence of that boundary.

## Context

Removal marks a member's `members_v2` roster entry `Removed` but retains the
entry and its KEM public key. The production manual reseal handler verifies
that its caller is active, then selects the recipient with a bare roster
lookup. It can therefore re-wrap its locally present current-epoch group secret
to a removed recipient.

The handler's function comment says the recipient must be a "known member,"
while the request-field comment says "active member." Those comments conflict
and cannot establish product intent. ADR 0024 governs fail-closed rotation and
survivor resealing on administrative removal, but deliberately leaves
recipient-selection reachability unresolved. ADR 0025 governs whether required
gates observe what they claim. Neither decides the product rule for all
current-epoch recipient-selecting paths.

The decision must bind the authority-bearing path that chooses the recipient,
not the roster-agnostic cryptographic primitive. It must also state its
current-epoch and threat boundaries without claiming historical entitlement,
global epoch currency, or containment after raw-key or daemon/host compromise.

## Decision Drivers

- Removed, pending, and otherwise inactive roster entries must not receive
  current-epoch group key material through production recipient selection.
- The guard must sit before sealing in the path that holds roster authority.
- Shared roster-agnostic cryptographic primitives must remain reusable.
- Test-only recipient selection must have a compile-time, not reachability-only,
  production exclusion.
- Current-epoch entitlement must not silently become historical-epoch policy.
- The decision's threat claim must match the authenticated route boundary.

## Considered Options

1. **Treat any retained roster entry as eligible.** Rejected. Removal retains
   the entry and KEM key, so presence is not active membership.
2. **Put roster policy inside the sealing primitive.** Rejected. The public
   primitive has no group or roster input and is intentionally reusable; the
   authority-bearing caller must make the policy decision.
3. **Rely on comments or a non-success response from any later handler
   failure.** Rejected. The comments conflict, and a later missing-key or
   missing-secret failure does not prove the active-recipient predicate ran.
4. **Require active membership in every production recipient-selecting path,
   with an evidenced compile-time exception for a non-production path.**
   Chosen.

## Decision

> Every call path that chooses a named recipient for current-epoch group key
> material must establish that the recipient is an active member before
> invoking a sealing mechanism. A call path may omit that check only if the
> path itself is excluded from production builds at compile time, and the
> record must carry evidence of that exclusion.

This decision governs current-epoch recipient selection. It neither authorizes
nor defines historical-epoch resealing; a product path that distributes
historical key material requires an epoch-relative entitlement rule.

The quantified object is the authority-bearing recipient-selection call path,
not the roster-agnostic cryptographic primitive it invokes.

## Consequences

### Positive

- Production recipient selection fails closed before sealing for a removed,
  pending, or otherwise inactive member.
- The shared sealing primitive remains usable by production and structurally
  non-production callers.
- The compile-time exception names the excluded call path rather than
  incorrectly claiming that a production-compiled primitive is excluded.

### Negative / Trade-offs

- Every present and future production call path that chooses a named recipient
  must carry and maintain the active-membership predicate.
- The implementation needs a designated inactive-recipient wire identity and a
  condition-specific mutation control; a generic non-success response is
  insufficient.
- Current local state may be stale relative to another daemon. This decision
  does not create a global-current oracle or settle locally
  stale-but-present-pair policy.

### Neutral / Deferred

- Exact status codes, machine-readable error schema, predicate placement,
  controls, and exception evidence live in the governed design chapter.
- The production `/groups/secure/open-envelope` endpoint is deferred to a
  follow-up product ADR that chooses keep, restrict, or compile-time-excluded
  test-only disposition after tracing its authentication boundary. The
  sealing-side guard closes the reported hole, and validation of this decision
  must not depend on that endpoint.
- ADR 0024 and Accepted ADR 0025 remain unchanged.

## Validation

Acceptance requires independent controls showing that:

- a production recipient-selecting path succeeds for an active recipient and
  reaches its designated inactive-recipient rejection before sealing for an
  existing inactive roster entry;
- an absent roster entry remains observably distinct from an existing inactive
  entry;
- changing only the recipient predicate back to bare roster-entry presence
  makes the product-rule gate fail and attributes failure to the
  active-membership condition;
- at the acceptance commit, recorded evidence names the enumeration method and
  the complete sealing-mechanism set it searches, lists every discovered
  production call path that chooses a named recipient for current-epoch group
  key material, and accounts for each path exactly once as carrying the
  active-membership predicate or an evidenced compile-time exclusion;
- adding an otherwise valid production recipient-selecting path through any
  named sealing mechanism without the predicate or an evidenced exclusion
  makes validation fail and attributes the uncovered path;
- every exception identifies the recipient-selecting call path and proves that
  path is excluded from production builds at compile time;
- the shared roster-agnostic sealing primitive remains outside the exception
  and may remain production-compiled; and
- no control depends on `/groups/secure/open-envelope` or claims
  historical-epoch entitlement, global epoch currency, or containment after
  raw-secret or daemon/host compromise.

A new or changed recipient-selecting path, or a new source of group key
material through request input, persistence, cache, derivation, or otherwise,
requires review of this decision. A `GroupInfo` schema change is one trigger,
not the trigger.

## Grounding

### G-001 — Manual reseal selects a retained inactive roster entry

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: Context and Decision.

Removal marks Bob's `members_v2` entry `Removed` but retains the entry and KEM
key (`src/groups/mod.rs:972-978`). `secure_group_reseal` requires the caller
to be active but selects the recipient with a bare `members_v2.get`
(`src/server/routes/named_groups.rs:12459-12466`). At this pin, Alice can
therefore reseal her locally present current-epoch secret to removed Bob.

The production `secure/open-envelope` route has no roster lookup and rejects
only a withdrawn-group conflict before and after crypto
(`src/server/routes/named_groups.rs:10107-10113,10159-10173,12548-12598`).
An absent removed-self record is not withdrawn, so Bob can open that envelope
after terminal 404 and use the recovered key against survivor content. This
observation grounds the defect; the endpoint's product disposition remains
deferred.

### G-002 — Current local state retains one logical secret and epoch pair

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: the current-epoch scope.

`GroupInfo` retains one logical `shared_secret` / `secret_epoch` pair, not a
previous-secret collection; `rotate_shared_secret` replaces that pair with
the newly generated secret and incremented epoch
(`src/groups/mod.rs:143-149,418-436`).

Separately, the surveyed production GSS envelope producers expose no explicit
previous-epoch selection surface: the admin-remove and ban producers seal a
freshly rotated pair, while the approval and manual-reseal producers seal the
daemon's one locally present pair
(`src/server/routes/named_groups.rs:8595-8642,10499-10560,11050-11087,12472-12504`).
None of those surveyed producers accepts a caller-selected secret or epoch or
reads a historical-key source.

Re-review this boundary for every new or changed recipient-selecting path and
every new source of group key material, whether request input, persistence,
cache, derivation, or otherwise. A `GroupInfo` schema change is one trigger,
not the trigger.

### G-003 — The bounded survey does not establish global epoch currency

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: the current-epoch scope and Consequences.

`secure_group_reseal` reads one daemon's local record under its local lock and
does not consult a global-current oracle
(`src/server/routes/named_groups.rs:12451-12480`). In an asynchronous
multi-daemon system, its locally present pair may be older than another
daemon's accepted state.

A future explicit previous-epoch selector triggers the need for an
epoch-relative entitlement decision. Policy for a locally
stale-but-present pair is a separate consistency question that this
active-member rule does not answer.

### G-004 — The call path, not the primitive, holds recipient authority

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: Decision and the compile-time exception.

Public `seal_group_secret_to_recipient` has no group or roster input
(`src/groups/kem_envelope.rs:133-167`) and is called by the production manual
reseal handler
(`src/server/routes/named_groups.rs:12498-12504`). The primitive may therefore
remain shared and compiled into production; each production call path that
chooses its named recipient must establish active membership first.

### G-005 — Authentication does not erase the recipient-selection threat

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: Context, Decision Drivers, and the threat boundary in Validation.

The route sits behind router-wide authentication
(`src/server/mod.rs:1252-1259,1370-1374`), which accepts a durable bearer or
session token without a per-request agent identity
(`src/server/auth.rs:54-73`; `src/server/routes/tasks.rs:24-31`). The reseal
handler instead derives the acting member from the daemon's own agent
identity.

The guard therefore fails closed against accidental, buggy, and malicious
authenticated product requests that try to select an inactive recipient,
including an API client that does not possess the raw group secret. It does
not contain daemon/host compromise or any principal able to extract the secret
and invoke the roster-agnostic sealing primitive outside the guarded call
path, as the current handler documentation acknowledges
(`src/server/routes/named_groups.rs:12421-12424`).

The function comment says "known member" and matches the current code, while
the request-field comment says "active member." The implementation must remove
that contradictory contract when this decision lands.

## Notes for AI-assisted work

AI tools may help draft this ADR, but must not mark it Accepted without human
review. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
