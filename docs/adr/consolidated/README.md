# The 15 ADR set

David accepted A01 through A15 on 7 November 2026. The numbered source records are in `docs/adr-archive/` with their old `docs/adr/` paths kept as links recorded in `move.json`.

## Slots

| ID | Decision | File |
|---|---|---|
| A01 | Purpose and Product Limits | [A01-r01-purpose-and-product-limits.md](A01-r01-purpose-and-product-limits.md) |
| A02 | Identity Keys and Device Enrollment | [A02-r01-identity-keys-and-device-enrollment.md](A02-r01-identity-keys-and-device-enrollment.md) |
| A03 | Trust Permissions Sharing and Revocation | [A03-r01-trust-permissions-sharing-and-revocation.md](A03-r01-trust-permissions-sharing-and-revocation.md) |
| A04 | Agent Attachment and Inbound Events | [A04-r01-agent-attachment-and-inbound-events.md](A04-r01-agent-attachment-and-inbound-events.md) |
| A05 | Connectivity Discovery and Names | [A05-r01-connectivity-discovery-and-names.md](A05-r01-connectivity-discovery-and-names.md) |
| A06 | Gossip Relay Roles and Resource Limits | [A06-r01-gossip-relay-roles-and-resource-limits.md](A06-r01-gossip-relay-roles-and-resource-limits.md) |
| A07 | Messages Receipts History and Retry | [A07-r01-messages-receipts-history-and-retry.md](A07-r01-messages-receipts-history-and-retry.md) |
| A08 | Groups Home Membership and Repair | [A08-r01-groups-home-membership-and-repair.md](A08-r01-groups-home-membership-and-repair.md) |
| A09 | Group Encryption and Key Changes | [A09-r01-group-encryption-and-key-changes.md](A09-r01-group-encryption-and-key-changes.md) |
| A10 | Shared Data Files and Synchronization | [A10-r01-shared-data-files-and-synchronization.md](A10-r01-shared-data-files-and-synchronization.md) |
| A11 | Local API Applications and Human Interface | [A11-r01-local-api-applications-and-human-interface.md](A11-r01-local-api-applications-and-human-interface.md) |
| A12 | Agent Teams Delegation and Task Coordination | [A12-r01-agent-teams-delegation-and-task-coordination.md](A12-r01-agent-teams-delegation-and-task-coordination.md) |
| A13 | Voice and Video | [A13-r01-voice-and-video.md](A13-r01-voice-and-video.md) |
| A14 | Health Updates and Recovery | [A14-r01-health-updates-and-recovery.md](A14-r01-health-updates-and-recovery.md) |
| A15 | Compatibility Validation and Decision Rules | [A15-r01-compatibility-validation-and-decision-rules.md](A15-r01-compatibility-validation-and-decision-rules.md) |

File naming: `Axx-rNN-title.md`. Each slot's sha256 is pinned in `index.json`; the slot content must match.

## Limits

- Use only A01–A15. Do not create A16 or any new ADR files.
- Files under `docs/adr/transient/` do not count toward the limit (D242).
- Archived records in `docs/adr-archive/` do not count.
- David delegated design decisions on 10 Nov 2026. A slot change made under that delegation is a dated paragraph in the slot that says so, with the `index.json` pin updated. A PR that changes a slot says so in its body.
- A wire-format or public-API change carries a `FOR ENGINEER:` line in the PR body that states the change; under A15 (amendment of 12 Nov 2026) it needs no separate ruling.

## Open proposals

These 6 transient records are Proposed, pending a decision:

| Record | Target slot |
|---|---|
| [T-one-sided-peer-link](../transient/T-one-sided-peer-link.md) | A05 |
| [T-open-envelope-actor](../transient/T-open-envelope-actor.md) | A03 |
| [T-pubsub-required-signing-context](../transient/T-pubsub-required-signing-context.md) | A06 |
| [T-revocation-snapshot-authority](../transient/T-revocation-snapshot-authority.md) | A02 |
| [T-self-leave-catchup-before-seal](../transient/T-self-leave-catchup-before-seal.md) | A07 |
| [T-self-leave-fork-quarantine-clear](../transient/T-self-leave-fork-quarantine-clear.md) | A14 |

## Checks

- `python3 scripts/check-adr-consolidation.py`: verifies exactly 15 Accepted slots; each slot file's bytes must match the sha256 in `index.json`.
- `python3 scripts/check-adr-count.py`: counts current records; fails if the total exceeds 15.
- `python3 scripts/adr-governance.py`: protects the archived numbered and transient records; CI runs it on `docs/adr/**` changes.
