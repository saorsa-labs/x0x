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
comments. A wire-format or public-API change carries a `FOR ENGINEER:` line in the PR body that states the change; under A15 (amendment of 12 Nov 2026) it needs no separate ruling. An approved
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

## Capability registry

This table is the live allocation table for capability bits. Allocate the next bit here.

**ADR 0093 capability registry** (the canonical allocation table since ADR 0089, accepted 2026-09-30, amended 0093's allocation procedure; ADR 0093 itself is immutable):

| Bit | Name | Meaning | Allocated by |
| --- | --- | --- | --- |
| 0 | `share_grant_v1` | Understands and validates the ShareGrant v1 typed DM | ADR 0093 |
| 1 | `predecessor_offer_v1` | Understands the predecessor/requester offer route and its application handling | ADR 0093 |
| 2 | `peer_evidence_v1` | Accepts `EvidenceV1` (stream protocol 0x06) evidence Hello/Lookup streams | ADR 0089 (accepted 2026-09-30; advertised since the S5 slice) |
| 3 | `file_control_ack_v1` | Sends and expects `file-control-ack` for file offer, accept, and reject | Accepted transient [T-file-control-ack](./transient/T-file-control-ack.md), slot A10, 2026-10-12 |
| 4 | `eviction_handoff_v1` | Understands typed authenticated `EvictionHandoffV1` revocation-eviction hand-off evidence | ADR 0110 §4 (accepted 2026-10-20) |
| 5 | `crypto_exclusion_v1` | Verifies and applies `CryptoExclusionV1` for an already-Removed target | ADR 0110 §4 (accepted 2026-10-20) |
| 6 | `certificate_rebind_v1` | Verifies and applies `CertificateRebindV1` seat rebinding commits | ADR 0110 §4a (accepted 2026-10-20) |
| 7 | `owner_recovery_v1` | Verifies and applies `OwnerRecoveryV1` commits | ADR 0110 §4b (accepted 2026-10-20) |
| 8 | `group_terminal_attest_v1` | Issues and verifies admin terminal attestations, answers `group_attest_request`, consumes re-seat authorisations | ADR 0109 §5 (accepted 2026-10-20) |
| 9 | `group_reseat_mandate_v1` | Verifies and applies promoted-admin `ReseatMandateV1` commits | ADR 0109 §3a (accepted 2026-10-20) |
| 10 | `gui_show_v1` | Understands remote GUI show typed direct messages | ADR 0083 slice 3 (lowest free bit on 2026-10-23) |
| 11 | `join_pending_notice_v1` | Serves and understands `JoinPendingNotice` on the join-result poll | ADR 0108 §8 (accepted 2026-10-05; wire half ruled by David 2026-10-25, D-ruling 05:14 GMT; next free bit in acceptance order) |
| 12 | `key_republish_v1` | Verifies and seats signed `MemberKeyRepublishV1` (`X0XKR1`) key republications on an Active seat | #1663 (David's ruling, 28 Oct 2026 02:25 GMT; lowest free bit) |
| 13 | `treekem_catchup_refusal_v1` | Sends and understands the typed `treekem_catchup_refusal` that answers a machine- or binding-revoked TreeKEM catch-up request ONLY — never sent on another lane: a machine- or binding-revoked control-blob fetch gets no answer at all (blob withheld, no frame; #1664) | #1657 (David's approval, 28 Oct 2026 02:08 GMT; bit ruled by the Engineer 29 Oct 2026 22:14 GMT; lane boundary ruled by the Engineer 31 Oct 2026 03:40 GMT — bit 13 is catch-up only, as on main since #1714, unreleased; a typed control-blob refusal would be a separate wire question; next free bit) |
| 14 | `share_grant_names_v1` | Understands the `x0x-sharegrant-v2\0` typed route: the v1 grant plus an owner-signed names section (grant-carried name defaults). Senders use the v2 envelope only toward a grantee whose verified advert sets this bit | ADR 0079 (accepted 2026-09-27; next free bit) |
| 15 | `grant_revocation_push_v1` | Accepts the single-record grant revocation push (`x0x-grant-revocation-push-v1`) and ingests it through the shared v3 revocation path; the sender needs POSITIVE evidence (push only to a current verified advert that has the bit) | #1003 (course-correction directive ruling 3e, 7 Nov 2026; design: archived ADR 0080 under slot A03; bit 15 per David's wire approval — bit 14 was concurrently claimed by PR #1826, which pushed first) |
| 16–63 | unallocated | Must not be advertised until allocated | — |

## Checks

- `python3 scripts/check-adr-consolidation.py` — exactly 15 Accepted slots,
  no A16, no extra revision file; each slot's bytes must match the sha256
  recorded in `consolidated/index.json`, so a slot change needs a visible
  index update in the same PR (A15, amendment of 12 Nov 2026).
- `python3 scripts/check-adr-count.py` — the current count stays at 15;
  archive links must be recorded moves.
- `python3 scripts/adr-governance.py` — archived Accepted bytes and frozen
  evidence stay unchanged.

Tooling notes are in [TOOLING.md](TOOLING.md). New docs follow the
[style guide](../documentation-style.md).
