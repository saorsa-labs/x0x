# A02 Identity Keys and Device Enrollment

- **Status:** Accepted (David, course-correction directive, 7 Nov 2026, ruling 2)
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Active since 7 November 2026. The 15 accepted slots are the live decision authority.
- **Supersedes:** The archived numbered records mapped to this slot in [TRANSFER.md](TRANSFER.md). The archive stays the historical record. Existing implementation gates remain in force.

David accepted the 15 slots at their current revisions on 7 November 2026 (course-correction directive, ruling 2). They are the live decision authority. The numbered records stay in [docs/adr-archive](../../adr-archive/ARCHIVE.md) as the historical record. [docs/adr-archive/move.json](../../adr-archive/move.json) records the archive transfer David accepted on 10 October 2026. Use the [index](README.md) for the current rules.

x0x uses separate identities for a human owner, an agent and a machine. This separation lets the owner grant authority to an agent without giving that agent the owner's key.

## Context

A machine can run several agents. An agent can represent work for a person. A model name, a process ID and an agent identity are not interchangeable. Permission checks must use verified identity evidence.

## Decision

We will retain three identity layers:

- A machine identity authenticates a transport endpoint.
- An agent identity identifies a participant and its signed actions.
- An optional user identity represents the human owner.

The current identities are derived from ML-DSA-65 public keys using SHA-256. Any future change to identity derivation requires a versioned migration under [A15](A15-r01-compatibility-validation-and-decision-rules.md).

Machine and agent keys may be created for a new installation. A user key must never be created without an explicit owner action. An AgentCertificate binds an agent key to its owner. Device enrollment establishes which machines belong to that owner's device set.

Authentication must prove the relevant agent and machine binding. A transport signature alone must not turn an unverified agent name into an authenticated sender.

Device enrollment is a Tier-1 owner-sync record (decided 13 Nov 2026 by Claude under David's delegation of design decisions of 10 Nov 2026; [#1107](https://github.com/saorsa-labs/x0x/issues/1107)). Before this, an `OwnerEnrollment` stayed in the local device store of the device that made it, so another device of the same owner did not learn that a machine is enrolled, and a removal stayed local. These rules apply:

1. The new kind is `DeviceEnrollment` (tag 0x05). The key is the machine ID in lowercase hex. The value is `Enrolled` with the original owner-signed `OwnerEnrollment`, or `Removed` with the removal time `deleted_at_ms`. The new kind and the new value variant come last, so the encoding of the four older kinds does not change. A device keeps kind 0x05 records in their own file (`sync/enrollment_records.json`), so `sync/records.json` holds only the four older kinds and a binary built before kind 0x05 still starts after a rollback. No file that such a binary reads ever holds a kind 0x05 record: not `sync/records.json`, not `sync/journal-intent.json`, and not `sync/apply-pending.json` (which holds only name records). A commit writes its kind 0x05 records to their own file first, and the journal intent holds only the records of the four older kinds, so the all-or-none recovery of an interrupted journal commit covers that part only. In memory the two files are one register: one version vector, one session record set and one limit. When a key is in both files, the device keeps the record that wins under the merge rule.
2. The owner key signs the record, as for every Tier-1 record.
3. The record version is `2·t + 1` for `Removed` and `2·t` for `Enrolled`, where `t` is `deleted_at_ms` or `enrolled_at_ms`. The standard Tier-1 rule (highest version wins) is not changed. Thus a later time wins, a removal wins at the same millisecond, and a re-enrollment needs a newer time than the removal. A record whose version does not follow this rule, or whose `Enrolled` value names another machine than its key, is refused. A device does not store a received record whose time is more than 300 seconds in the future (the enrollment clock skew bound of owner sync, the same as `EXPIRY_CLOCK_SKEW_SECS`), because its version would outrank every honest record for that machine until then; the other records of the batch still commit.
4. Removals sync as signed records. Without them, a machine removed on one device stays trusted on the other devices.
5. A receiving device applies `Enrolled` through the existing enrollment path, so the tombstone and signature checks stay. It applies `Removed` through an unenroll step that only moves the tombstone forward and removes the device row only when its enrollment is not newer than the removal. A device applies a record only after the session commit is durable. It does not apply an `Enrolled` record whose enrollment is expired, is not signed by the owner, or names another machine; such a record stays in the register. A device ignores records about its own machine. ADR-0018 machine revocation stays separate and still overrides enrollment. Expiry is still checked on every read.
6. SyncV1 moves to protocol 3. A device accepts a `Hello` of version 2 or 3, and the session runs at the lower version. A protocol-2 session never sends or accepts kind 0x05, so a mixed-version fleet keeps syncing the four older kinds. A protocol-2 node refuses a `Hello` of any other version. Thus a device remembers, in memory, the version to send to each peer, and opens the next session with it. A received `Hello` lowers this version only when the peer sent a lower version than this device sent. A session whose commit is durable raises it to at least the higher of the two versions, because the peer accepted the version this device sent, and never lowers it. A session whose commit fails does not raise it. So two sessions that run at the same time cannot leave both devices at protocol 2. After a restart of a protocol-3 device, the first session that it opens to a released protocol-2 device can fail; the next session runs at protocol 2.
7. An enrollment learned this way admits SyncV1 from that machine, because it is owner-signed.
8. At start, and in each reconcile pass of the sync service, a device mints a record for each local enrollment and each local tombstone. An enroll or an unenroll starts a pass. This is safe to repeat, because the version comes from the timestamps. It does not mint a record when the register already holds a record with the same version for that machine, so a restart causes no new records. Also at start, it verifies again and applies every stored kind 0x05 record. A device that ran the first pull request stored received kind 0x05 records without applying them, and a peer does not send a record of an equal version again.
9. `Removed` records are not pruned for now. They count toward the store limit of 4096 records.

Accepted risk: a device that holds the owner key can now enroll a machine for all the owner's devices. That device can already write every other Tier-1 kind. [A10](A10-r01-shared-data-files-and-synchronization.md) already lists enrollment as owner-sync state. The work is in three pull requests: (1) the kind, the value, the version rule and the protocol-3 negotiation; (2) minting, applying, the unenroll step and the start-up migration; (3) documentation and the record source in `/sync/devices`.

## Key custody and placement

A key-owning harness keeps its own agent key. An API rider uses a scoped delegation through a daemon, as defined in [A04](A04-r01-agent-attachment-and-inbound-events.md). Both forms retain clear attribution.

Pinned agents remain bound to their approved machine. Existing placement records and denials remain effective. This draft does not activate roaming or the key-move ceremony. D27 retired that ceremony. Removal is pending. The code still has an off-by-default switch.

Enrollment and certificate issuance must require owner authority. Discovery provides possible addresses; it does not grant ownership or permission.

Names are labels for verified identities. Changing a display name must not change the identity or silently replace a pinned target.

## Local protection and recovery

The current local-state policy uses operating-system permissions and disk encryption. Network encryption does not protect plaintext in a member's local files or backups.

We retain that baseline. Platform key storage for the owner root is a separate proposed enhancement. It must define headless operation, recovery and migration before it becomes a product requirement.

A lost-device procedure must distinguish a lost machine key, a lost agent key and a lost owner key. Recovery must use approved authority evidence. An agent cannot repair an authority failure by deleting a denial record or creating a replacement owner.

No recovery procedure can erase data that another device already received. The product must state this limit.

## Consequences

Separate keys keep transport identity distinct from the agent and owner. Enrollment and recovery must preserve these bindings. Operators must manage more than one key and understand which authority each key carries.

## Alternatives

One identity per machine would make it difficult to give different agents different permissions.

One shared owner key in every harness would make each harness an owner-level security boundary. Scoped identities and delegation provide a smaller boundary.

Automatic key movement would make placement easier, but would require a complete transfer and revocation protocol. It remains outside this draft.

## Current implementation

The three identity types, certificates, enrollment and placement checks exist. D27 retired the key-move ceremony. Removal is pending. The code still has an off-by-default switch (`[key_move] ceremony_enabled`). While that switch is off, the ceremony endpoints return HTTP 501. The archive map must retain the distinction between this retired ceremony and the always-on enrollment and placement checks.

[A03](A03-r01-trust-permissions-sharing-and-revocation.md) owns revocation effects. [A05](A05-r01-connectivity-discovery-and-names.md) owns name resolution and reachability. [A15](A15-r01-compatibility-validation-and-decision-rules.md) owns format compatibility.

## Validation

Tests must reject a forged owner chain, a mismatched machine binding, an expired certificate and an unauthorized placement change. Restart must preserve identity and enrollment.

The owner must be able to identify which keys exist, which process holds them, and what recovery can and cannot do.

## Matters to settle

Choose the owner-key storage and recovery policy before replacing the current operating-system protection rule. Do not reopen roaming as part of this documentation reset.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0007 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0007-three-layer-identity-model.md) · [ADR 0015 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0015-no-app-layer-at-rest-encryption.md) · [ADR 0036 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0036-owner-singleton-and-naming-registry.md) · [ADR 0037 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0037-agent-placement-and-key-custody.md) · [ADR 0043 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0043-agent-key-move-protocol.md) · [ADR 0054 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0054-external-agent-signing-dst.md) · [ADR 0084 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0084-enrolled-owner-sync-admission.md)

David placed [ADR 0115](../0115-identity-discovery-authority.md) in A02 on 10 Oct 2026. It amends ADR 0043. It also touches [A03](A03-r01-trust-permissions-sharing-and-revocation.md). That touch is not a second placement.

Decision source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Implementation checked on 12 October 2026 at commit `8cb6488331e6c1226913104ddb99ca4ec18bec37`.

[All 15 ADRs](README.md)
