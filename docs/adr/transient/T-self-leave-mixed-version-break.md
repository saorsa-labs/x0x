# T-self-leave-mixed-version-break: a v0.48 peer leaves at a digest-bound rekey

- **Status:** Accepted (David, 16 Oct 2026, slot A15, PR #1337).
- **Date:** 2026-10-16
- **Target slot:** A15
- **Decision owners:** David Irvine
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #1113; PR #1337; `T-self-leave-rekey-committer` (Accepted, D274, slot A09); `T-self-leave-relay-commit-binding` (Accepted, 16 Oct 2026, slot A15); `T-self-leave-catchup-author` (Accepted, 16 Oct 2026, slot A09)

David accepted the documented mixed-version break on 16 Oct 2026. This file is not folded into slot A15.

## Context

A self-leave rekey seals `treekem:epoch=<n>:commit=<blake3>` in the existing `security_binding` field. The state hash includes that string. The seal is `treekem_commit_binding`.

A v0.48 receiver rebuilds `treekem:epoch=<n>` during `MemberRemoved` apply. `finalize_applied_commit` returns `StateHashMismatch`. The daemon keeps the parent hash and does not install the TreeKEM bytes. A later commit then fails `PrevHashMismatch`. That peer leaves a group that contains an upgraded member. `verify_structure` still succeeds, because it hashes the stored binding.

Admin removal seals `treekem:epoch=<n>`. A v0.48 receiver applies that removal. A third party applies TreeKEM bytes only when the signed binding names those exact bytes. The author may still deliver the short form. `MemberRemoved` gains no field.

## Decision Drivers

- The digest must stay inside the signed binding, so a relay cannot swap the TreeKEM bytes.
- A v0.48 receiver cannot rebuild the digest string. One commit has one state hash.
- Admin removal already uses the short form, and that path must keep working.
- David accepted the break on 16 Oct 2026. The leaf removal does not wait for a capability bit.

## Considered Options

1. Compatibility gate. Seal the digest form only after every active member advertises the copy behaviour. David did not choose this.
2. Transition. Seal the short form first, with author-only delivery, then the digest form after that same advert. David did not choose this.
3. Documented mixed-version break. Keep the digest seal. A v0.48 peer hits `StateHashMismatch` and leaves a group that contains an upgraded member until it upgrades and applies the same event.

## Decision

We will keep option 3. A self-leave rekey binds `treekem:epoch=<n>:commit=<blake3>`. A v0.48 peer hits `StateHashMismatch` and leaves a group that contains an upgraded member. Admin removal keeps `treekem:epoch=<n>`.

`catchup_may_apply_removed_as_author` stays. A third party applies TreeKEM bytes only when the signature names those bytes.

This record does not fold. It does not allocate a capability bit. It does not add a numbered ADR. The A09 committer decision stays. One claim in that file now states this binding value and this break.

## Consequences

### Positive

- The leaver cannot derive the next epoch. The digest names the bytes a survivor may relay.
- An upgraded member stays on the chain. Apply copies `commit.security_binding`.

### Negative / Trade-offs

- A v0.48 member stops at the parent of the rekey in a group that contains an upgraded member. Later commits wait until that member upgrades and catch-up serves this event.
- `StateHashMismatch` is not fork evidence. A later `PrevHashMismatch` can enter fork-evidence evaluation.

### Neutral / Operational

- The outbox still saves the rekey for catch-up.
- The committer, relay-binding, and catch-up author records stay unfolder.

## Validation

`relayed_removal_rejects_another_members_treekem_commit` rejects swapped bytes. `catchup_legacy_binding_stays_with_the_author` keeps the short form on the author path. `catchup_third_party_relays_a_digest_bound_rekey` lets a third party relay only the named bytes. The admin remove route still seals `treekem:epoch=<n>`.

## Notes for AI-assisted work

AI tools may help draft this ADR, but must not mark it Accepted without human review. David accepted this record on 16 Oct 2026. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
