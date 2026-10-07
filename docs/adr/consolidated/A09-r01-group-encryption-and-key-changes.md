# A09 Group Encryption and Key Changes

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

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

Future-epoch content may be held under defined size and time limits while the required state arrives. Report expiry and recovery failure. Do not silently present such content as applied.

D34 rules automatic revocation eviction and rekeying within a bound. D40
specifies designated-first, with fallback after the bound; D74 refines the
selection to the lowest roster admin, without reachability data. ADR 0110
remains **Proposed**: the ruling does not accept its full protocol. D69/D73
require harness measurements for its timing values. This draft does not
choose new bounds or waive numbered acceptance.

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

Both group crypto paths exist. The self-leave and full revocation-eviction work remain incomplete. Proposed old ADR 0110 contains important mechanics that this summary must preserve or explicitly supersede.

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

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
