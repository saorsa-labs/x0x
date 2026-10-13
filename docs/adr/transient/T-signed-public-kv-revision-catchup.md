# T-signed-public-kv-revision-catchup: one-revision SignedPublic catch-up

- **Status:** Accepted (David, 13:08 London, 12 Oct 2026, slot A08, PR #1329)
- **Target slot:** A08
- **Date:** 2026-10-12
- **Decision owners:** implementation for #1105
- **Reviewers:** David
- **Supersedes:** none
- **Superseded by:** none
- **Related:** #1105, #1088, ADR 0030 bootstrap, A10 shared-data sync

## Context

After a restart, two SignedPublic replicas can hold group states one `state_revision` apart. Each KV `StateRequest` is signed at the sender's revision. `open_signed_mutation_bound` admits a request only when the group, the store and the epoch match. The public epoch is `state_revision`. A mismatch becomes `rejected_verify`. `requests_received` stays 0 on both sides. The KV repair channel uses the same epoch as the data, so it cannot fetch the missing group commit.

The public authorization watch already restarts the requester after `update_from_group` advances the local context. The missing step is that nothing asks the group layer for that commit. TreeKEM already requests a gap fill. SignedPublic bootstrap seeds a new group and refuses to overwrite an installed one.

It is not the #1117 digest beacon and it does not change ADR 0092.

## Decision

Keep the exact epoch binding. Do not admit a mismatched `StateRequest`, and do not change its wire shape.

When a public control record matches the group and the store, the author signature verifies, and the signed revision is not local, the context reports the skew. The record stays rejected.

If the local group is exactly one revision ahead, the local agent signed that head, and the author is an active member, the daemon sends the existing signed-public bootstrap snapshot to that author. The sender takes the per-group membership lock before it selects that snapshot. It withholds the send when the group is fork-quarantined, and it holds the lock through delivery. The send is throttled. It does not create an outbox obligation.

The receiver applies that snapshot only when all of these hold:

- The group is already installed, SignedPublic, and not fork-quarantined.
- The sender is the admin who signed the single retained head.
- The head revision is the local revision plus one, and `prev_state_hash` is the local hash.
- The roster root, policy hash, metadata hash and recomputed state hash match the commit.
- The local agent remains an active member.
- An installed OwnerCertified owner stays unchanged. A head that changes or removes that owner is refused.
- Local invite secrets, lineage, mandate observations and key material stay on the local record.

A larger gap, a non-committer sender, or a hash mismatch leaves the installed group unchanged. The receiver then still withholds the bootstrap ACK. A durable apply returns the existing inserted completion.

## Consequences

A one-revision restart skew can converge without a new KV message. The ahead committer pushes the head it already signed. A replica that holds a newer commit it did not sign does not mint a bootstrap. Gaps larger than one still need the ordinary metadata path.

Display names and other fields outside the state hash keep the same trust as a new-group bootstrap: the committer is the sender. Local-only state is not taken from the snapshot.

## Validation

`public_revision_skew_rejects_until_the_lagging_commit` shows both sides reject while the revisions differ, then receive requests after the lagging context applies the commit. `public_revision_skew_hook_applies_the_lagging_commit` shows the skew report is what applies that commit. `one_revision_bootstrap_advances_the_installed_group` and `a_two_revision_gap_is_not_a_catchup` lock the group-layer rule. `catchup_keeps_an_installed_owner_certified_axis` refuses an owner change. `catchup_send_holds_the_membership_lock_through_delivery` holds the membership lock through delivery.

## Notes for AI-assisted work

David accepted this record at 13:08 London on 12 Oct 2026. Do not edit the #1187 journal, snapshot, or seal paths to extend this catch-up.
