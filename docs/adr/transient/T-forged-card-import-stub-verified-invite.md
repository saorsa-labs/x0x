# T-forged-card-import-stub-verified-invite: verified invite displaces forged inert stub

- **Status:** Proposed
- **Date:** 2026-10-19
- **Target slot:** A08
- **Decision owners:** David Irvine
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #1471; PR #1463 / issue #1161 inert card-import stub clear; A08 groups membership and repair

## Context

`import_card_into_groups` stores an inert local row for a discoverable card. The card owner field is not authenticated. An attacker can name themselves as owner and reuse a real group id. The joiner then holds an `InertCardImportStub` for that id.

PR #1463 cleared that stub only when a fully verified invite matched both the stub genesis group id and the stub genesis creator. A forged creator failed that match. The join then returned `JoinFailed` / 409 "fresh invite cannot replace". No API route cleared the row. The real owner's verified invite was blocked for good.

Seated, keyed, lineage-bearing and quarantined rows are outside the inert-stub shape. This record does not change their refusal rules.

## Decision Drivers

Unauthenticated card text must not outrank a verified invite for the same group id. Real membership state must stay uncleared. The fix must stay on the verified-invite path and must not add a new public clear route.

## Considered Options

1. Drop the stub-creator match. Clear an inert stub when the verified invite's stable group id matches the stub genesis `group_id`, and the existing inert-shape, alias and keyed-material checks still pass.
2. Stop storing card imports under the claimed group id when the owner is unverified.
3. Add a public API route that deletes a stuck card-import stub.

## Decision

We will take option 1.

`inert_stub_matches_verified_invite` compares only the stub genesis `group_id` to the verified invite's stable group id. It does not compare card owner or genesis `creator_agent_id` to the invite's signed creator. The invite's signed creator is still checked on the ordinary verified-invite path before this gate.

The #1161 inert-shape predicate stays. TreeKEM / MLS keyed material still refuses replacement. Conflicting same-stable aliases still refuse. Stable-id mismatch still returns today's `JoinFailed` refusal. Clearing still grants no seat and no key. The ordinary first-join path installs lineage and seating after the clear.

Options 2 and 3 need a storage or public-API change. This record does not take them. Wire format and public API stay unchanged.

## Consequences

A forged inert stub for group G no longer blocks a verified invite for G. An inert stub whose genesis group id differs from the invite still blocks. Real seated or keyed rows stay protected by the inert-shape and keyed-material gates. Operators do not need a new clear route for this case.

## Validation

Unit tests show stable-id match without card-owner match, and stable-id mismatch refusal. Regression `inert_stub_forged_owner_replaced_by_verified_invite` reproduces the #1471 forged-owner block on the pre-fix gate and expects a successful verified join after the clear. Existing #1161 / #1463 inert-stub tests keep covering matching-owner replace, keyed refusal, alias refusal and remnant rules.
