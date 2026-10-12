# A10 Shared Data Files and Synchronization

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

x0x stores and shares data through authorized peers. It must state who holds the data, how changes merge, and what happens when a peer is offline.

## Context

The product contains key-value stores, task data, local history, file transfer and owner synchronization. Scratchpads are core planned work. Rich collaborative text has a separate parked design.

These data types do not have the same merge, retention or authority rules.

## Decision

We will keep data with explicit holders and scopes. Existing relationships must not depend on a global DHT for user or group data.

Each shared data type must specify its identity, author, permission, merge rule, retention rule and recovery source. Applications must not infer durability from a successful live notification.

Replicated key-value data uses its defined CRDT policy. Last-writer selection can discard a concurrent value. It is not a general collaborative text editor or a transaction service.

Task state follows [A12](A12-r01-agent-teams-delegation-and-task-coordination.md). Membership and key state follow [A08](A08-r01-groups-home-membership-and-repair.md) and [A09](A09-r01-group-encryption-and-key-changes.md). They must not use a data-merge shortcut that changes security authority.

## Synchronization and repair

Use change exchange for prompt updates and a bounded state-repair path for missed updates. The receiver must verify authorship and access before applying data.

A node that returns after an outage must be able to detect missing state. A digest or version comparison may trigger repair. The exact beacon and transfer format require a reviewed specification.

A holder can serve retained data only when the requester is currently entitled to it. The holder must also be entitled to serve it.

A new member does not gain all historical data by default. Each group data type must define the history available at admission and after a key change.

## Owner state and scratchpads

Owner synchronization is limited to its declared state classes. Enrollment, names, profile and group pointers do not imply that all direct-message history or private group data is copied between devices.

Scoped scratchpads will use the group's data and encryption rules. Rider and shared-agent access must be explicit. Scratch access must not expose unrelated stores or daemon state.

Rich-text notes remain parked. If that work resumes, use the accepted Loro direction unless a reviewed revision changes it. Text operations need causal and author checks in addition to group encryption.

## File transfer and retention

A file transfer must bind the declared content identity, size and recipient. Check the complete content hash before reporting verified completion.

Bound transfer size, concurrency, temporary storage and retained content. An interrupted transfer must have a clear retry or cleanup result.

Deletion has a defined local or replicated meaning. It does not promise erasure from another participant's backups or previously exported plaintext.

A local acknowledgment must state what was saved. It must not imply that a remote replica or backup exists.

## Consequences

Each data type has an explicit merge and retention contract. Peers can work during a partition, but availability still depends on authorized holders. Applications must expose conflicts, replica state and storage limits.

## Alternatives

A global storage layer could offer broader availability, but would change custody, cost and trust assumptions.

Using one whole-document last-writer value for every data type is simple, but can discard edits that users expect to merge.

## Current implementation

KV stores, task lists, file transfer and scoped owner sync exist. The full scratch-store surface and several any-holder recovery paths remain work in progress. Rich-text work remains parked.

## Validation

Test concurrent edits, missed updates, restart, owner-offline repair, corrupted files and storage limits. Verify deterministic merge behavior and author checks.

Test removal during fetch and key delivery. Confirm that an unauthorized rider cannot recover another scope through a history or repair endpoint.

## Matters to settle

Set retention and storage budgets per data class. Define which authorized peers must hold a copy before the product reports replicated durability.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0006 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0006-no-global-dht-for-user-and-group-data.md) · [ADR 0041 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0041-cross-machine-state-sync-tiers.md) · [ADR 0047 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0047-crdt-kv-store-delta-gossip.md) · [ADR 0055 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0055-dm-file-transfer-protocol.md) · [ADR 0075 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0075-collaborative-notes-and-agent-scratchpads.md) · [ADR 0081 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0081-notes-use-loro-crdt.md) · [ADR 0082 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0082-notes-epoch-bound-writer-rule.md)

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
