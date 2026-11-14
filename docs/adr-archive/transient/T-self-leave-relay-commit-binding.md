# T-self-leave-relay-commit-binding: authenticate a relayed TreeKEM commit

- **Status:** Accepted (David, 16 Oct 2026, slot A15, PR #1337).
- **Date:** 2026-10-15
- **Target slot:** A15
- **Decision owners:** David Irvine
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** T-self-leave-rekey-committer (Accepted, D274, slot A09, PR #1337); T-self-leave-catchup-author (Proposed, slot A09); issue #1113

## Context

A09 holds the Accepted committer record. This record does not change those bytes and does not target A09. A15 owns the compatibility rule for an old binding.

Catch-up applies a `MemberRemoved` as its verified signer. That check covers the roster commit. The shipped admin removal seals `treekem:epoch=<n>`. That string does not name the TreeKEM commit bytes. A self-leave rekey seals `treekem:epoch=<n>:commit=<blake3>`. The digest sits inside the signed binding.

A third party can relay a genuine admin removal and substitute other TreeKEM bytes for the same epoch. The roster hash still matches. The receiver installs the attacker's tree. No quarantine is set. A later genuine event does not restore agreement. The direct path already refuses that member. The catch-up author substitution is the open path.

## Decision Drivers

The roster signature must not authorize bytes it does not cover. Shipped admin removals must still apply. A survivor must still relay a digest-bound rekey.

## Considered Options

1. Require the digest binding before a third party may apply TreeKEM bytes. Keep the legacy form for the authenticated author.
2. Accept every legacy relay and trust the sender not to swap bytes.
3. Reject the legacy form on the author path as well.

## Decision

A third-party catch-up relay may apply TreeKEM removal bytes only when the signed binding equals `treekem:epoch=<n>:commit=<digest>` for those exact bytes. The transport sender stays an active member. `verify_structure` still has to succeed. The actor still has to equal `committed_by`.

The legacy form `treekem:epoch=<n>` stays valid when the authenticated author delivers the event. The author is the commit signer. Delivery is the direct remove route, or a catch-up response whose transport sender is that signer. A third party cannot use the legacy form. The receiver does not install the roster commit or the TreeKEM bytes from that relay.

A roster-only self-leave has no TreeKEM payload. The signature covers that commit. A third party may still relay it.

The admin remove route keeps sealing the legacy form. Old peers keep that form. This record adds no wire field and no second committer. The Accepted A09 record stays unchanged. This record stays Proposed until David accepts it.

## Consequences

A relayed admin removal with substituted TreeKEM bytes does not install. The author can still deliver the same legacy event, and the genuine tree then matches. A digest-bound self-leave rekey can still be relayed by a survivor. No quarantine is set by the rejected relay.

## Validation

One test calls `remove_named_group_member`, then `handle_treekem_catchup_response`. A third party relays substituted legacy bytes. The epoch stays and no quarantine is set. The same third party then relays the genuine legacy bytes. The epoch stays. The author then delivers the genuine event. The survivor reads the authority ciphertext and the removed member does not. A second test relays a digest-bound rekey through the same handler. Substituted bytes do not install. The genuine bytes do.
