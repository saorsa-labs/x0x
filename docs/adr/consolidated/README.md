# The 15 ADR set

The 15-slot direction is confirmed by David (D198), as is the approximately
80% ASD-STE100 writing target. This set records that direction for team review.
Start with A01, A04, A07 and A15.

The 15 records are **Proposed replacements**. Their transfer checks remain
open. Confirmation of the direction does not declare every unresolved detail
accepted or every feature shipped. The existing accepted ADRs, status overlay,
frozen evidence and active issue gates still govern implementation.

## Read the decisions

| ID | Decision | Replacement status |
|---|---|---|
| A01 | [Purpose and Product Limits](A01-r01-purpose-and-product-limits.md) | Proposed |
| A02 | [Identity Keys and Device Enrollment](A02-r01-identity-keys-and-device-enrollment.md) | Proposed |
| A03 | [Trust Permissions Sharing and Revocation](A03-r01-trust-permissions-sharing-and-revocation.md) | Proposed |
| A04 | [Agent Attachment and Inbound Events](A04-r01-agent-attachment-and-inbound-events.md) | Proposed |
| A05 | [Connectivity Discovery and Names](A05-r01-connectivity-discovery-and-names.md) | Proposed |
| A06 | [Gossip Relay Roles and Resource Limits](A06-r01-gossip-relay-roles-and-resource-limits.md) | Proposed |
| A07 | [Messages Receipts History and Retry](A07-r01-messages-receipts-history-and-retry.md) | Proposed |
| A08 | [Groups Home Membership and Repair](A08-r01-groups-home-membership-and-repair.md) | Proposed |
| A09 | [Group Encryption and Key Changes](A09-r01-group-encryption-and-key-changes.md) | Proposed |
| A10 | [Shared Data Files and Synchronization](A10-r01-shared-data-files-and-synchronization.md) | Proposed |
| A11 | [Local API Applications and Human Interface](A11-r01-local-api-applications-and-human-interface.md) | Proposed |
| A12 | [Agent Teams Delegation and Task Coordination](A12-r01-agent-teams-delegation-and-task-coordination.md) | Proposed |
| A13 | [Voice and Video](A13-r01-voice-and-video.md) | Proposed |
| A14 | [Health Updates and Recovery](A14-r01-health-updates-and-recovery.md) | Proposed |
| A15 | [Compatibility Validation and Decision Rules](A15-r01-compatibility-validation-and-decision-rules.md) | Proposed |

## Keep no more than 15 current ADRs

1. Use only A01 through A15 for the consolidated set. Do not create A16.
2. Preserve accepted revisions as exact historical records. Never rewrite
   an accepted record to make room for a new decision.
3. Keep wire layouts, full state machines and detailed test plans in linked
   specifications. A specification cannot change an accepted guarantee.
4. Target 500 to 1,000 words in each ADR. Review a record above 1,500 words.
5. Use the [documentation style guide](../../documentation-style.md), including
   the approximately 80% ASD-STE100 style target.

The limit applies to current decisions after transfer. Archived records and
past accepted revisions do not count. During transfer, new or changed
decisions use the numbered ADR series only, through ADR 0087 (D199). Slot
revisions stay Proposed. The transition check rejects an Accepted slot.
Keep reserved numbers
0090/0091 (D18), 0097 (D20), 0098 (D35), and 0084–0105 (D63).
Slices 0109–0114 continue to acceptance as numbered ADRs. Map their rulings
to the slots without changing that decision path. The transition check does
not yet support multiple revision files per slot; see [coverage gaps](../TOOLING.md#transition-check-coverage).

`python3 scripts/check-adr-count.py` counts the current records. The limit
is 15. This file is the plan. David accepted the transfer on 10 Oct 2026.
A numbered ADR in the [transfer map](TRANSFER.md) keeps its `docs/adr/` path
as a link. Its bytes live in `docs/adr-archive/` and stay outside the count.
David placed ADR 0115 in A02 and ADR 0116 in A07 on 10 Oct 2026. They are
in that map. ADR 0115 also touches A03. ADR 0116 also touches A08 and cites
ADR 0030. Those are secondary links, not second placements. Files under
`docs/adr/transient/` do not count (D242). Another numbered ADR outside
that directory, or an A16 record, makes the count exceed 15 and the check fails.

## Transfer before activation

The [record map](TRANSFER.md) assigns all 100 source ADRs to a primary slot.
It is not a claim that every clause has been transferred.

- Record each important old rule as retained, changed by an accepted decision,
  retired by a human decision, or unresolved. Keep its evidence and test owner.
- Reconcile open design work with its owners and current GitHub state.
- Keep Proposed source decisions visibly unresolved until they are accepted.
- Add revision-aware acceptance and immutable-history checks before any
  consolidated record becomes Accepted. The transition check rejects early
  acceptance. The existing governance checks continue to protect old records.
- Let David accept the replacement revision and its transfer record. Record
  the exact old decisions it supersedes and when that takes effect.
- Update the index, code references, governance rules and documentation mirror
  together. Move old files only after link and frozen-evidence checks pass.

Do not use this consolidation to remove a release, security, compatibility or
active-team gate. Do not combine the archive move with a protocol change.

## Review material and checks

- [Architecture review and research](../../reviews/2026-10-05-architecture/README.md)
- [Original HTML review](../../reviews/2026-10-05-architecture/x0x-review.html)
- [GitHub-readable review](../../reviews/2026-10-05-architecture/x0x-review.md)
- [Machine-readable slot index](index.json)
- [Legacy decision index and status overlay](../README.md)

Run `python3 scripts/check-adr-consolidation.py` for the 15-slot transition
check. Run `python3 scripts/adr-governance.py` for the existing ADR protections.
The language target requires editorial review; it is not a mechanical score.
