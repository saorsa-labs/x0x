# T-installed-catchup-admin-consent: installed catch-up consent

- **Status:** Accepted (David, D272, 17:12 London, 13 Oct 2026, slot A08, PR #1401)
- **Target slot:** A08
- **Date:** 2026-10-13
- **Decision owners:** David (D270). Only David accepts this record.
- **Reviewers:** David
- **Supersedes:** none
- **Superseded by:** none
- **Related:** #1105, #1329 (`ec9fb505`), `T-signed-public-kv-revision-catchup`, ADR-0070 §2, `T-goal-e-rule-5`

## Context

#1329 (`ec9fb505`) partly fixes #1105. Before D272, the invite-only W3-H arm was RED.

Consent requires no local revocation, then a Known contact or a current `GroupInvite` grant on the authenticated machine. Blocked still wins. The bootstrap roster is not consent. The same gate covers catch-up. The Accepted record requires the signing admin and one linked revision. Its bytes stay unchanged (D258).

## Decision Drivers

- An installed invite-only member cannot catch up one revision.
- A stranger must stay unable to install a new group.
- Consent must use the stored local roster.

## Considered Options

1. Keep today's gate on every bootstrap.
2. On an installed group, an active local admin who signed the retained head is catch-up consent. New installs keep today's gate (D270).
3. Any active member, or a Known contact who is not that admin. Rejected.

## Decision

Use option 2. Each check must hold.

1. `is_agent_revoked` runs first. Error: `public-group bootstrap sender is revoked`.
2. The shared resolver, alias included, finds an installed group. Otherwise today's gate applies. Error: `public-group bootstrap sender is not a known contact`.
3. Catch-up only: active local member; `caller_role` at least Admin (Owner or Admin; not Moderator, Member, or Guest); `commit.committed_by` is that sender; one retained head.
4. Apply still passes: SignedPublic; not withdrawn; not quarantined; no shared secret, security binding, invite lineage, or mandate map; same stable id; local revision plus one; `prev_state_hash` equals the local hash; one consistent link passes `verify_structure`; the commit binds group id, revision, both hashes, withdrawn, security binding, roster root, policy hash, and public metadata hash; sender and local agent stay active; last-admin holds; OwnerCertified owner unchanged; no `RevokedNewcomer`; no `RosterChange` of ids or roles; local invite, lineage, quarantine, mandate, and keys stay local; clocks clamp +1; Inserted only after a durable write.

A failed check leaves the group unchanged and withholds the ACK.

Bound: one revision; no outbox; lock held from selection through delivery; 1 second send; 30 second failure backoff; 5 second throttle; cache 64; queue 32; installed wait 50 milliseconds, then withhold the ACK; a new install still waits.

This is no weaker than the Known-contact path. Apply already requires this active local admin and this linked head, so a Known contact who fails that cannot catch up. This adds no such sender, and only on an installed group. Consent is the local roster, not the snapshot.

## Optional goal E

Do not offer an owner-axis roster head that every receiver at this version refuses. The sender still offers those heads and can hold the lock for 1 second. Not implemented, and separate from consent. `T-goal-e-rule-5` lets goal E stand in for an R when wire, API, stored format, and dependencies stay unchanged and rule 21 shows no loss.

## Consequences

### Positive

- That admin can be catch-up consent.

### Negative / Trade-offs

- The file is not folded.

### Neutral / Operational

- The Accepted catch-up record stays unchanged. This file is not folded.

## Validation

`w3h_1105_invite_only_restart_obtains_n_plus_one_from_local_admin` is the invite-only arm. A later change must still refuse an unknown install, a non-admin, a non-committer, a larger gap, a roster change, and a revoked newcomer.

## Notes for AI-assisted work

Fold only when David asks (D258).
