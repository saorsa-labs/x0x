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

Preserve Accepted records and frozen evidence. Do not create a successor
record or change an acceptance status to bypass this rule. Removal or
reconciliation of an existing record follows an explicit instruction.

## Retained records and historical lifecycle

The following rules describe existing records; they do not authorize new
files. The earlier D242 format named one target slot from A01 to A15 and
used 300 to 600 words.

The status stays Proposed until David accepts it or Claude and Codex accept it by consensus under David's standing rule of 19 Oct 2026, 13:29 BST. Consensus may accept a transient ADR only if it changes neither the wire format nor the public API. David's acceptance is not required in that case. A change to either still needs David's acceptance. If the text of a record reserves acceptance to David (for example, "Only David accepts this record"), only David can accept it, and Claude and Codex consensus under the 19 Oct 2026 rule never overrides that reservation.

For consensus acceptance, Claude and Codex must each record `ACCEPT` for the same full head commit SHA. Each review must name the reviewer and confirm that the decision changes neither the wire format nor the public API. When marking the record Accepted, cite both reviews and their reviewed head in its Status or Reviewers metadata.

David directs any reconciliation with a target slot. Accepted bytes stay unchanged. Existing `T-<slug>.folded.md` overlays record Folded status and name the same target slot and Accepted record. The historical lifecycle is Proposed, then Accepted, then Folded. It does not grant permission to add an overlay now.

This directory does not count toward the 15 current ADRs.
