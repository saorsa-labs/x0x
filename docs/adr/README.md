# Architecture Decision Records

## The live authority: the accepted 15 ADR set

David accepted A01 through A15 at their current revisions on 7 November 2026
(course-correction directive, ruling 2). **The [15 accepted slots](consolidated/README.md)
are the live decision authority.** Read them first. [A15](consolidated/A15-r01-compatibility-validation-and-decision-rules.md)
carries the decision rules: the 15-record limit, the writing target, and the
repository and release governance rules retained from archived ADR 0087.

David's 19 Oct 2026 ruling stays in force: **do not add ADR files**, including
numbered records, transient `T-*.md` records and folded overlays. Keep the
pack at 15. Put rationale in the PR body and existing docs or code doc
comments. A wire-format or public-API change needs a `FOR ENGINEER:` line for
David's decision; record approval in the PR body or comment. An approved
additive API needs no new ADR. See the
[current authoring rule](transient/README.md) and the
[style guide](../documentation-style.md).

## The historical archive

The numbered records (ADR 0001–0116) are the historical archive. Each
`docs/adr/NNNN-*.md` path is a link; the bytes live in
[docs/adr-archive](../adr-archive/ARCHIVE.md), unchanged, with the path, link
and sha256 recorded in `move.json`. The [transfer map](consolidated/TRANSFER.md)
assigns every archived record and ruling to its slot. Where a slot is silent
on a detail an archived accepted record settles, that archived record still
answers it. Accepted archive bytes stay immutable; `scripts/adr-governance.py`
enforces that.

The old index and its status overlay (rulings 2026-09-28..30, errata, and the
per-record status tags) were retired on 7 November 2026 and archived as
[legacy-index-and-status-overlay.md](../adr-archive/legacy-index-and-status-overlay.md).
Its parks, freezes and holds reached the slots through the rulings digest and
the transfer map; the slots now carry that status. The
[rulings digest](../design/x0x-direction.md) remains the reference for
D01–D200 and E-D1–E-D17.

## Transient records

The 17 Accepted transient records were folded into their target slots on
7 November 2026 and archived in
[docs/adr-archive/transient](../adr-archive/ARCHIVE.md). Six records stay
Proposed as open proposals; the [transient index](transient/README.md) lists
them with their target slots.

## Checks

- `python3 scripts/check-adr-consolidation.py` — exactly 15 Accepted slots,
  no A16, no extra revision file.
- `python3 scripts/check-adr-count.py` — the current count stays at 15;
  archive links must be recorded moves.
- `python3 scripts/adr-governance.py` — archived Accepted bytes and frozen
  evidence stay unchanged.

Tooling notes are in [TOOLING.md](TOOLING.md). New docs follow the
[style guide](../documentation-style.md).
