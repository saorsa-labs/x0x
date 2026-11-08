# A09 Group Encryption and Key Changes

- **Status:** Accepted (David, course-correction directive, 7 Nov 2026, ruling 2)
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Active since 7 November 2026. The 15 accepted slots are the live decision authority.
- **Supersedes:** The archived numbered records mapped to this slot in [TRANSFER.md](TRANSFER.md). The archive stays the historical record. Existing implementation gates remain in force.

David accepted the 15 slots at their current revisions on 7 November 2026 (course-correction directive, ruling 2). They are the live decision authority. The numbered records stay in [docs/adr-archive](../../adr-archive/ARCHIVE.md) as the historical record. [docs/adr-archive/move.json](../../adr-archive/move.json) records the archive transfer David accepted on 10 October 2026. Use the [index](README.md) for the current rules.

Group encryption must follow committed membership. A roster change alone does not prove that a departed member can no longer decrypt later traffic.

## Context

x0x has TreeKEM and legacy GSS paths. Group messages, key-value data and task data must apply compatible access rules. Self-leave, revocation and certificate expiry also require cryptographic handling.

## Decision

We will use one target group-encryption model based on TreeKEM. Legacy GSS remains supported only for the approved transition and maintenance needs.

Do not stop GSS creation or remove a legacy path until the replacement supports the required admission and recovery operations. Use signed capability checks and a tested compatibility plan.

A cryptographic epoch identifies the key state for protected content. Bind group identity and epoch into encryption and verification. Seal new content only under the currently committed usable epoch.

Signed-public groups remain a separate explicit policy. Their signatures provide authenticity; they do not make the content private.

## Membership and key release

Release current key material only to a currently eligible recipient. Check membership, certificate rules, revocation, group state and the secret epoch at the time of each delivery or resend.

A previous eligibility check does not authorize a later resend after removal or revocation.

Keep historical access separate. A current member is not automatically entitled to every previous key or retained content object.

Every departure that requires exclusion must cause a key transition. This includes admin removal, verified revocation, applicable certificate expiry and signed self-leave.

The remaining authorized participants perform the key transition. A leaver cannot prove its own exclusion by removing itself only from the visible roster.

## Ordering and recovery

Coordinate membership state, key state and their durable records. On restart, complete or safely refuse an unfinished transition. Do not publish content from an uncommitted or stale state.

### TreeKEM self-leave

Two accepted records govern the rekey after a TreeKEM self-leave (D274, 14 Oct 2026, and 16 Oct 2026, PR #1337; archived as [T-self-leave-rekey-committer](../../adr-archive/transient/T-self-leave-rekey-committer.md) and [T-self-leave-catchup-author](../../adr-archive/transient/T-self-leave-catchup-author.md)).

The committer election stays ADR 0016 decision 6: the lowest active admin by raw agent id commits the responsive rekey, every active admin stays eligible, and other admins hold off until a capability bit that rides an existing signed advertisement is accepted. A mixed group waits until the lowest admin runs this code or is removed. This election governs the self-leave rekey only; the rekey after a revocation eviction follows ADR 0110's measured wait and ranked fallback, described below. One JSON file per group at `data_dir/treekem-self-leave-outbox/<blake3 of the group key>.json` records the roster-only self-leave, unpublished rekeys and published rekeys, so a restart can serve them on catch-up; it is not the TreeKEM journal. The rekey is saved with its commit bytes before the epoch is durable, a published rekey is kept for catch-up and not sent again, and a retry that finds a pending record for the current head restores that record's saved post-commit tree rather than minting a second commit. D274's acceptance includes the consequence that a node that seals while it does not know it is behind can quarantine the group; no seal timeout and no second committer are added.

On the catch-up recovery path only, a `MemberRemoved` applies as its verified signer when the transport sender is an active member, `verify_structure` succeeds and the event actor equals `committed_by`; the roster checks then run against that signer. A self-leave still requires the signer to be the removed member, and an admin removal still requires the signer to be an active admin. The direct path does not change: a transport sender who is not the signer cannot apply a `MemberRemoved` by writing the actor field. A truncated membership page opens a catch-up fence for that peer only; a later page from another peer or a member-keyed KeyPackage reply does not close it, and the fence closes when that peer returns a non-truncated membership page. [A15](A15-r01-compatibility-validation-and-decision-rules.md) carries the relay commit-binding rule and the accepted v0.48 mixed-version break for the digest-bound rekey seal.

Future-epoch content may be held under defined size and time limits while the required state arrives. Report expiry and recovery failure. Do not silently present such content as applied.

D34 rules automatic revocation eviction and rekeying within a bound. D40
specifies designated-first, with fallback after the bound; D74 refines the
selection to the lowest roster admin, without reachability data. David
accepted ADR 0110 on 20 Oct 2026 (Group 2, #1357, option B). The timing
values are the W3-H p99.9 measured numbers (D69/D73). The implementing PR
body records them before any timing-dependent code merges. The fixed 2 s /
5 s values stay rejected (D69). This draft does not choose new bounds.

On 7 Nov 2026 03:46 GMT David approved a change to ADR 0110 §2 head
sync (#1597 item 5b): "Yes, stop counting those older revisions as
conflicting-head evidence and allow responder_state_revision with a
compatibility default." The TreeKEM catch-up answer gets the optional
field `responder_state_revision`; old peers omit it and keep the old
rule. A holder is far behind when this node cannot link its head through
the retained commit log and its revision is below the retained floor.
Such a holder adds no conflicting-head evidence. It does not confirm the
round. A sibling fork that split below the window is not detected. ADR
0110 stays Accepted and its text is unchanged. The code and this slot
carry the change.

[A08](A08-r01-groups-home-membership-and-repair.md) defines valid group-state and fork recovery. A09 must not bypass that authority to obtain keys faster.

## Security claims

State the exact properties of each released path. Post-quantum signatures and key encapsulation do not alone prove forward secrecy or recovery after key compromise.

Do not claim RFC 9420 wire interoperability merely because a component is called MLS or uses TreeKEM. Such a claim requires the applicable protocol and interoperability evidence.

Members can retain plaintext already received. Revocation can stop future access; it cannot erase those copies.

Local files and backups follow [A02](A02-r01-identity-keys-and-device-enrollment.md)'s local protection policy.

## Consequences

Removed members lose access to future protected content after the required key change. Key changes and crash recovery require strict ordering. Old copies of plaintext cannot be recalled.

## Alternatives

Keeping two permanent crypto systems increases the number of permission and recovery paths.

Immediate removal of the legacy system can strand supported peers. We choose a controlled transition with clear release gates.

## Current implementation

Both group crypto paths exist. With members remaining, self-leave updates the roster and removes local key state, but does not rotate the remaining members' keys. Full automatic revocation eviction and rekeying remain incomplete. Old ADR 0110 (Accepted 20 Oct 2026; S4 code not yet merged) contains important mechanics that this summary must preserve or explicitly supersede.

## Validation

Verify that a removed member cannot decrypt newly protected content after the exclusion transition. Cover key resend, restart, cold catch-up, stale certificates and concurrent admins.

Test old and new peers across activation. Check both confidentiality and progress.

## Matters to settle

Complete the legacy exit criteria and exact exclusion bounds. Reconcile the new record with the accepted and proposed membership rules before acceptance.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0010 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0010-gss-before-mls-treekem-for-v1-secure-groups.md) · [ADR 0012 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0012-treekem-default-secure-groups.md) · [ADR 0014 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0014-treekem-self-leave-owner-driven-rekey.md) · [ADR 0024 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0024-gss-rotation-on-admin-remove-fail-closed.md) · [ADR 0027 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0027-active-recipient-group-key-sealing.md) · [ADR 0110 Proposed](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0110-revocation-eviction-designated-first.md)

Decision source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Implementation checked on 12 October 2026 at commit `8cb6488331e6c1226913104ddb99ca4ec18bec37`.

[All 15 ADRs](README.md)
