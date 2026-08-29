# ADR-0018 mechanics — revocation enforcement test inventory

> Extracted 2026-08-29 from the immutable [ADR 0018](../adr/0018-key-lifecycle-expiry-renewal-revocation.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the validation inventory
> relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

## Validation

The enforcement is proven by automated tests that exercise genuine denial (not
just API contracts):

- **EP2 — verified gate** (`src/lib.rs::revoked_agent_fails_machine_verification_even_when_cached`):
  `is_agent_machine_verified` goes `true → false` after a self-revocation is
  applied via the real `verify_and_insert` receive path, with the identity
  still cached.
- **EP3 — DM inbox** (`src/dm_inbox.rs::revoked_sender_dm_is_dropped_and_counted`):
  a DM from a revoked sender is dropped and increments
  `incoming_dropped_revoked`; a non-revoked sender passes and does not move the
  counter. The gate decision is a pure `drop_if_sender_revoked` helper so the
  counter side-effect cannot silently regress.
- **EP4 — group metadata gate**
  (`src/server/mod.rs::metadata_revoked_sender_denied_even_for_bypass_verified_event`):
  a revoked committer's self-authenticating `GroupDeleted{commit:Some}` is
  denied *before* `bypass_verified` (the group is left intact), while a
  non-revoked but unverified committer's identical event still applies
  (#99 non-regression).
- **End-to-end through a real daemon**
  (`tests/revocation_integration.rs::revocation_denies_verified_binding_end_to_end`):
  `GET /agents/:id/machine` transitions `200 → 404` purely by applying a
  self-revocation via `POST /identity/revoke`, plus the REST contract tests for
  `/identity/revoke` and `/identity/revocations`.
- Cross-daemon gossip propagation of records is exercised by the e2e scripts.
