# The 15 ADR set

David accepted A01 through A15 at their current revisions on 7 November 2026
(course-correction directive, ruling 2). **The 15 accepted slots are the live
decision authority.** The numbered records in the [transfer map](TRANSFER.md)
are the historical archive. Start with A01, A04, A07 and A15.

Acceptance of a slot is not a completion claim. Each slot separates accepted
guarantees from its current implementation state. Active issue gates, frozen
evidence and team gates still govern implementation.

## Read the decisions

| ID | Decision | Status |
|---|---|---|
| A01 | [Purpose and Product Limits](A01-r01-purpose-and-product-limits.md) | Accepted |
| A02 | [Identity Keys and Device Enrollment](A02-r01-identity-keys-and-device-enrollment.md) | Accepted |
| A03 | [Trust Permissions Sharing and Revocation](A03-r01-trust-permissions-sharing-and-revocation.md) | Accepted |
| A04 | [Agent Attachment and Inbound Events](A04-r01-agent-attachment-and-inbound-events.md) | Accepted |
| A05 | [Connectivity Discovery and Names](A05-r01-connectivity-discovery-and-names.md) | Accepted |
| A06 | [Gossip Relay Roles and Resource Limits](A06-r01-gossip-relay-roles-and-resource-limits.md) | Accepted |
| A07 | [Messages Receipts History and Retry](A07-r01-messages-receipts-history-and-retry.md) | Accepted |
| A08 | [Groups Home Membership and Repair](A08-r01-groups-home-membership-and-repair.md) | Accepted |
| A09 | [Group Encryption and Key Changes](A09-r01-group-encryption-and-key-changes.md) | Accepted |
| A10 | [Shared Data Files and Synchronization](A10-r01-shared-data-files-and-synchronization.md) | Accepted |
| A11 | [Local API Applications and Human Interface](A11-r01-local-api-applications-and-human-interface.md) | Accepted |
| A12 | [Agent Teams Delegation and Task Coordination](A12-r01-agent-teams-delegation-and-task-coordination.md) | Accepted |
| A13 | [Voice and Video](A13-r01-voice-and-video.md) | Accepted |
| A14 | [Health Updates and Recovery](A14-r01-health-updates-and-recovery.md) | Accepted |
| A15 | [Compatibility Validation and Decision Rules](A15-r01-compatibility-validation-and-decision-rules.md) | Accepted |

## Keep no more than 15 current ADRs

1. Use only A01 through A15 for the consolidated set. Do not create A16.
2. Preserve accepted revisions as exact historical records. Never rewrite
   an accepted record to make room for a new decision. A change to an
   accepted slot needs David's ruling.
3. Keep wire layouts, full state machines and detailed test plans in linked
   specifications. A specification cannot change an accepted guarantee.
4. Target 500 to 1,000 words in each ADR. Review a record above 1,500 words.
5. Use the [documentation style guide](../../documentation-style.md), including
   the approximately 80% ASD-STE100 style target.

The limit applies to current decisions. Archived records and past accepted
revisions do not count. David's 19 Oct 2026 ruling prohibits new ADR files,
including transient records, folded overlays and extra slot revisions. Put
rationale in the PR body and existing docs or code comments. Route
wire-format or public-API questions with a `FOR ENGINEER:` line for David's
decision. Record approval in the PR; an approved additive API needs no new
ADR. See the [current authoring rule](../transient/README.md).

`python3 scripts/check-adr-count.py` counts the current records; the limit is
15. `python3 scripts/check-adr-consolidation.py` keeps the set at exactly 15
Accepted slots, and each slot's bytes must match the sha256 recorded in
`index.json`: a change to an accepted slot needs David's ruling and the
updated hash in the same PR. A numbered ADR in the [transfer map](TRANSFER.md) keeps its
`docs/adr/` path as a link; its bytes live in `docs/adr-archive/` and stay
outside the count. Files under `docs/adr/transient/` do not count (D242).
Another numbered ADR outside that directory, or an A16 record, makes the
count exceed 15 and the check fails.

## Folded transient records and open proposals

On 7 November 2026 the 17 Accepted transient records were folded into their
target slots and their bodies archived in
[docs/adr-archive/transient](../../adr-archive/ARCHIVE.md). Each slot names
its archived records where it folds them.

These 6 transient records stay **Proposed**, as open proposals pending
David's decision (see [the transient index](../transient/README.md)):

| Record | Target slot |
|---|---|
| [T-one-sided-peer-link](../transient/T-one-sided-peer-link.md) | A05 |
| [T-open-envelope-actor](../transient/T-open-envelope-actor.md) | A03 |
| [T-pubsub-required-signing-context](../transient/T-pubsub-required-signing-context.md) | A06 |
| [T-revocation-snapshot-authority](../transient/T-revocation-snapshot-authority.md) | A02 |
| [T-self-leave-catchup-before-seal](../transient/T-self-leave-catchup-before-seal.md) | A07 |
| [T-self-leave-fork-quarantine-clear](../transient/T-self-leave-fork-quarantine-clear.md) | A14 |

## History of the transfer

The 15-slot direction was confirmed by David (D198) on 5 October 2026. He
accepted the archive transfer on 10 October 2026: the 100 source ADRs plus
ADR 0115 and ADR 0116 moved to `docs/adr-archive/`, each old path kept as a
link recorded in `move.json`. David placed ADR 0115 in A02 and ADR 0116 in
A07 on 10 Oct 2026; 0115 also touches A03, and 0116 also touches A08 — those
are secondary links, not second placements. He accepted the 15 slots on
7 November 2026.

The [record map](TRANSFER.md) assigns every source ADR and ruling to a
primary slot. Its clause-level review columns remain open as documentation
work; they verify coverage and no longer gate slot acceptance. Where a slot
is silent on a detail an archived accepted record settles, that archived
record still answers it. Do not use this consolidation to remove a release,
security, compatibility or active-team gate.

## Review material and checks

- [Architecture review and research](../../reviews/2026-10-05-architecture/README.md)
- [Original HTML review](../../reviews/2026-10-05-architecture/x0x-review.html)
- [GitHub-readable review](../../reviews/2026-10-05-architecture/x0x-review.md)
- [Machine-readable slot index](index.json)
- [Retired legacy index and status overlay](../../adr-archive/legacy-index-and-status-overlay.md)

Run `python3 scripts/check-adr-consolidation.py` for the 15-slot checks.
Run `python3 scripts/adr-governance.py` for the archived-record protections.
The language target requires editorial review; it is not a mechanical score.
