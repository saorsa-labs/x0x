# Transient decisions

## Current authoring rule (19 Oct 2026)

Do not add ADR files, including transient `T-*.md` records or folded overlays.
David keeps the current ADR pack at 15. This ruling replaces the earlier
instruction to create a transient record for a new or changed decision.
See [Engineer’s record of David’s ruling](https://github.com/saorsa-labs/x0x/pull/1469#issuecomment-6276825624).

Put the rationale in the PR body and existing documentation or code doc
comments. If a change touches the wire format or public API, write a
`FOR ENGINEER:` line for David's decision. Record his approval in the PR body
or comment. An approved additive API does not need a new ADR. Follow
[the style guide](../../documentation-style.md).

## Reconciliation of 7 November 2026

David's course-correction directive (ruling 2) folded the 17 Accepted
transient records into their target slots in
[the accepted 15 ADR set](../consolidated/README.md) and archived their
bodies in [docs/adr-archive/transient](../../adr-archive/ARCHIVE.md).
Each `T-<slug>.md` path here remains a link to the same bytes, recorded in
`docs/adr-archive/move.json`. The accepted bytes are unchanged. Each target
slot names its archived records where it folds them.

## Open proposals

These 6 records stay Proposed. They are not folded and not archived. They
wait for David's acceptance, or Claude and Codex consensus under David's
standing rule of 19 Oct 2026, 13:29 BST. Consensus may accept a record only
when it changes neither the wire format nor the public API, and never when
the record reserves acceptance to David. For consensus acceptance, Claude and
Codex must each record `ACCEPT` for the same full head commit SHA, each
review must name the reviewer and confirm that the decision changes neither
the wire format nor the public API, and the record cites both reviews and
their reviewed head when marked Accepted.

| Record | Target slot |
|---|---|
| [T-one-sided-peer-link](T-one-sided-peer-link.md) | A05 |
| [T-open-envelope-actor](T-open-envelope-actor.md) | A03 |
| [T-pubsub-required-signing-context](T-pubsub-required-signing-context.md) | A06 |
| [T-revocation-snapshot-authority](T-revocation-snapshot-authority.md) | A02 |
| [T-self-leave-catchup-before-seal](T-self-leave-catchup-before-seal.md) | A07 |
| [T-self-leave-fork-quarantine-clear](T-self-leave-fork-quarantine-clear.md) | A14 |

When David accepts one of these records, fold it into its target slot and
archive the body the same way, on his instruction. Accepted bytes stay
unchanged. This directory does not count toward the 15 current ADRs.
