# Transient decisions

A new or changed decision goes in `T-<slug>.md` in this directory.

Name one target slot from A01 to A15. Write 300 to 600 words. Use about 80% ASD-STE100 style. Follow [the style guide](../../documentation-style.md).

The status stays Proposed until David accepts it or Claude and Codex accept it by consensus under David's standing rule of 19 Oct 2026, 13:29 BST. Consensus may accept a transient ADR only if it changes neither the wire format nor the public API. David's acceptance is not required in that case. A change to either still needs David's acceptance.

For consensus acceptance, Claude and Codex must each record `ACCEPT` for the same full head commit SHA. Each review must name the reviewer and confirm that the decision changes neither the wire format nor the public API. When marking the record Accepted, cite both reviews and their reviewed head in its Status or Reviewers metadata.

David folds the record into its target slot only when he asks. After acceptance, its bytes stay the same. Folding does not edit that file. Add `T-<slug>.folded.md` beside it. The overlay status is Folded. It names the same target slot and the Accepted record. The lifecycle is Proposed, then Accepted, then Folded.

This directory does not count toward the 15 current ADRs.
