# A08 Groups Home Membership and Repair

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

A group defines who can act and which shared state is valid. Home is a private group for one owner. Group operation must not depend on an unnecessary fixed device.

## Context

Current group work includes signed membership, invites, owner certificates, forks, Home selection and several recovery paths. Some operations still depend on the owner, original sealer or a warm evidence cache.

A simple availability promise can hide an authority change. Recovery must preserve both liveness and proof of permission.

## Decision

We will use committed, signed group state as the authority for membership and roles. A transport sender cannot substitute for the original author of a relayed membership action.

The normal role model remains Admin and Member. Admin authority is substantial: promotion into that role is a security decision.

Home remains an owner-certified private group. Sharing an agent does not admit another owner to Home.

The target Home model uses explicit owner setup and a durable binding to one group. An existing device must not move to a different Home because a later register value wins a background election. This is a target from the proposed Home work, not a description of current startup behavior.

## Liveness

A reachable eligible admin with the required evidence should be able to complete authorized admission and repair. A reachable eligible holder should be able to supply retained state that the requester may access.

The protocol must not wait for the original author when another authorized source can provide the same verifiable object.

These promises remain conditional. All holders can be offline. Required evidence can be missing. A group can have no eligible admin. A fork can lack an authorized recovery anchor.

Each waiting or refused operation must report a typed cause, the missing condition and the permitted recovery action. A timeout alone is not a sufficient product explanation.

## Admission and state repair

Invites must bind their group, authority, intended scope and expiry. Secrets must travel through an authenticated private path.

Any-admin redemption must preserve single-use and replay rules. If a previous attempt may have committed, another admin must not create a second conflicting admission merely to avoid waiting.

Fetched certificates, membership events and data images must be checked against their signed digest, authority and applicable group state. A holder supplies evidence; it does not gain authority by serving it.

Private repair and pre-member fetch must disclose only the information required by the approved admission rule. Historical access is not automatic.

## Forks and persistence

Do not merge conflicting security membership by a generic CRDT rule. Detect an invalid or conflicting chain and apply the approved quarantine or recovery rule.

Recovery must preserve the owner's or group's legitimate authority. It must not invent a new admin, delete a denial, or distribute keys to force progress.

Persist membership, key transitions and incomplete work in a recoverable order. Keep old release-readable state where rollback requires it. [A09](A09-r01-group-encryption-and-key-changes.md) governs cryptographic exclusion.

## Consequences

Repair can use reachable authorized peers instead of one original process. Some cases must wait for valid evidence or human recovery. Typed states and persisted repair records add implementation work.

## Alternatives

A permanent owner-only writer simplifies some ordering but makes owner availability a product dependency.

Allowing every admin to act immediately improves local progress but can create conflicting commits. The detailed protocol must control these races without weakening authorization.

## Current implementation

The group foundation exists. The full liveness contract, scoped certificate work, any-holder repair, any-admin redemption and explicit Home transition span accepted and proposed old records. They are not one completed feature.

D63 keeps separate numbered slice acceptance in this order:
**S2 & S8 → S4 & S3 → S5 → S6 → S7**. D65 clarifies that S8 here means
S8(a); S8(b) also waits for S4. The bindings are S1=0106, S2=0108, S3=0109,
S4=0110, S5=0111, S6=0112, S7=0113, S8(a)=0107, and S8(b)=0114.
D57 accepted 0107; D58 accepted 0088 with its conditional supersessions;
D178 accepted 0108. Those acceptances do not waive the slice-code harness gate.
Slices 0109–0114 continue through numbered acceptance (D199).

## Validation

D16/D54 require each failure to be reproduced first in the W3-H harness
(#1164), shown red on main in CI (D181), before its ADR 0088 slice code or
group/Home liveness fix merges. Standalone in-process red tests do not count.
D55's exception applies only to #1150 (a).

D196 sets the W3-H harness gate verbatim:

> A harness case lands (and satisfies harness-first, D181) when all 20 CI reruns give the same verdict with complete structured receipts (setup, evidence, delivered request, exact cause for RED; every precondition for GREEN). Byte-identical canonical traces across reruns are reported but non-blocking; determinism work (same-instant ordering, per-task entropy) continues as a follow-up.

Exercise owner-offline admission, cold evidence, delayed and reordered messages,
concurrent admins, restart and retention gaps.

Every test must verify both progress and refusal. A group that repairs itself must still reject a revoked participant.

## Matters to settle

Complete the clause transfer from old ADRs 0088 and 0106–0114. Keep their unresolved decisions open. This short ADR must not silently choose a different fork, invite or recovery protocol.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0016 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0016-role-based-group-authority-flat-admin.md) · [ADR 0031 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0031-sole-member-self-leave-deletes-group.md) · [ADR 0038 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0038-home-owner-certified-personal-space.md) · [ADR 0059 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0059-invite-authentication-and-seating-provenance.md) · [ADR 0060 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0060-one-home-per-owner.md) · [ADR 0062 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0062-home-persistence-pair-recovery.md) · [ADR 0064 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0064-owner-anchored-fork-authority.md) · [ADR 0065 Superseded](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0065-duplicate-home-inventory-retirement-deferred.md) · [ADR 0066 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0066-ordinary-group-fork-anchors-and-data-plane-quarantine-coverage.md) · [ADR 0067 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0067-lifecycle-epoch-token-is-derived-marker-identity.md) · [ADR 0068 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0068-quarantine-pinned-history-retention-and-buffered-task-deltas.md) · [ADR 0069 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0069-home-wait-for-sync-before-auto-provisioning.md) · [ADR 0088 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0088-group-liveness-contract.md) · [ADR 0106 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0106-join-result-carries-intervening-membership-events.md) · [ADR 0107 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0107-stuck-join-rearm-and-serving-guard.md) · [ADR 0108 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0108-home-scoped-owner-certificate.md) · [ADR 0109 Proposed](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0109-ownerless-attestation-self-recovery.md) · [ADR 0111 Proposed](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0111-evidence-size-k-and-fetch-by-hash.md) · [ADR 0112 Proposed](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0112-any-admin-invite-redemption.md) · [ADR 0113 Proposed](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0113-home-is-an-explicit-owner-group-adopted-in-place.md) · [ADR 0114 Proposed](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0114-authority-re-welcome.md)

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
