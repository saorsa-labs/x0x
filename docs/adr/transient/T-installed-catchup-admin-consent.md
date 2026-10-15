# T-installed-catchup-admin-consent: installed catch-up consent

- **Status:** Accepted (David, D272, 13 Oct 2026; corrected text re-accepted D280, 14 Oct 2026, slot A08)
- **Target slot:** A08
- **Date:** 2026-10-13
- **Decision owners:** David (D270). Only David accepts this record.
- **Reviewers:** David
- **Supersedes:** none
- **Superseded by:** none
- **Related:** #1105, #1329 (`ec9fb505`), `T-signed-public-kv-revision-catchup`, ADR-0070 §2

## Context

#1329 (`ec9fb505`) partly fixes #1105. #1105 stays open. The consent gate for a new install is unchanged.

Consent requires no local revocation, then a Known contact or a current `GroupInvite` grant on the authenticated machine. Blocked still wins. The bootstrap roster is not consent. The same gate covers catch-up of a group that is not installed. The Accepted record requires the signing admin and one linked revision. Its bytes stay unchanged (D258).

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

1. `is_agent_revoked` runs first. Error: `public-group bootstrap sender is revoked`. The installed-admin branch also requires that the sender is not Blocked.
2. The shared resolver, alias included, finds an installed group. Otherwise today's gate applies. Error: `public-group bootstrap sender is not a known contact`.
3. Catch-up only: active local member; `caller_role` at least Admin (Owner or Admin; not Moderator, Member, or Guest); `commit.committed_by` is that sender; one retained head.
4. Apply still passes: SignedPublic; not withdrawn; not quarantined; no shared secret, security binding, invite lineage, or mandate map; same stable id; local revision plus one; `prev_state_hash` equals the local hash; one consistent link passes `verify_structure`; the commit binds group id, revision, both hashes, withdrawn, security binding, roster root, policy hash, and public metadata hash; sender and local agent stay active; last-admin holds; OwnerCertified owner unchanged; on an OwnerCertified group, no `RevokedNewcomer` and no `RosterChange` of ids or roles; local invite, lineage, quarantine, mandate, and keys stay local; clocks clamp +1; Inserted only after a durable write.

A failed check leaves the group unchanged and withholds the ACK.

Bound: one revision; no outbox; lock held from selection through delivery; 1 second send; 30 second failure backoff; 5 second throttle; cache 64; queue 32; installed wait 50 milliseconds, then withhold the ACK; a new install still waits.

This is no weaker than the Known-contact path. Apply already requires this active local admin and this linked head, so a Known contact who fails that cannot catch up. This adds no such sender, and only on an installed group. Consent is the local roster, not the snapshot. A Blocked sender still fails, including when that sender is an active local admin.

## Consequences

### Positive

- That admin can be catch-up consent when the sender is not Blocked.

### Negative / Trade-offs

- #1105 stays open until the implementation lands.

### Neutral / Operational

- The Accepted catch-up record stays unchanged. This file is not folded.

## Validation

A later change must still refuse an unknown install, a non-admin, a non-committer, and a larger gap. On an OwnerCertified group it must still refuse a roster change and a revoked newcomer. It must also refuse a Blocked sender.

## Notes for AI-assisted work

Fold only when David asks (D258).
