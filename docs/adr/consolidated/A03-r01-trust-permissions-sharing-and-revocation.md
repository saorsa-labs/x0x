# A03 Trust Permissions Sharing and Revocation

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

x0x grants access through verified authority and limited permissions. Possession of a network connection, a message, or an agent name does not grant authority.

## Context

The current system has contact trust, owner trust, group roles, grants, local tokens and service ACLs. A decision can become inconsistent when different routes apply different checks or depend on a warm cache.

## Decision

We will use one authority model, with shared checks for each protected operation. Each decision must identify the caller, requested action, target, applicable scope and verified evidence.

Authority checks will use evidence carried with the request and trusted persisted state. Discovery and cached hints can help obtain evidence. They cannot replace it.

D197 confirms ADR 0089 decision 2 for EvidenceV1 admission: relationship peers
(same group roster, same owner, or grant counterparty) may send at Unknown
trust. Not-Blocked suffices for admission; Blocked remains refused, and the
evidence must still verify. This does not grant the sender service authority.

Owner trust applies only when the certificate, machine binding, enrollment and current revocation checks required for that operation succeed.

A ShareGrant gives selected agents limited access. It must state the recipient, actions, targets and expiry. It does not expose Home or grant control of the owner's other agents. Re-sharing is denied unless an accepted design explicitly permits it.

## Service and token permissions

Remote command execution remains off unless the local ACL enables it. The allowed command, arguments and target must pass that ACL. A message that asks for execution is not an execution grant.

Forwarding is limited by the connect policy. The local service and destination remain part of the permission decision.

The durable owner token has broad local authority. Rider and GUI session credentials must have explicit scopes. Each route must state which token classes it accepts. New routes deny unlisted classes by default.

Long-lived subscriptions must apply current permission rules. A revoked credential must not retain access merely because it opened the connection earlier.

## Revocation

A verified revocation must survive restart. A corrupt existing revocation store must not be treated as evidence that no revocations exist. First-run absence and damaged persisted state are different cases.

Keep revocation records for as long as the revoked credential could otherwise verify. Do not use a fixed cleanup age that can restore valid access.

Revocation must reach every applicable gate, including group key delivery and live sessions. A measured local enforcement bound starts when a host receives and verifies the record. An offline or partitioned host cannot promise immediate knowledge of a new revocation.

A lost-device action must revoke the applicable machine or agent authority, end live access, and create any required group exclusion work under [A09](A09-r01-group-encryption-and-key-changes.md).

## Consequences

Applications share one permission model. They must handle denial and revocation during long operations. A network partition can delay delivery of a revocation; it does not justify a claim of instant global removal.

## Alternatives

Per-route permission code is easy to add but difficult to keep consistent. Shared checks provide one place to enforce and test the rule.

A network-wide reputation score cannot replace an owner's explicit grant or a group's committed authority.

## Current implementation

Many trust, grant and ACL surfaces exist. Unified authority, complete revocation coverage and corruption recovery remain active work. This draft must not describe those gaps as repaired.

## Validation

Exercise the same denial through REST, live streams, history replay, direct messages, group operations, forwarding and exec. Repeat after restart and during an active session.

Tests must preserve denials when evidence is absent, damaged, stale or revoked. A retry must not use a weaker permission path.

## Matters to settle

The supporting specification must state revocation lifetimes, enforcement bounds and recovery exits. These limits must fit current group-recovery and update-compatibility work.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0008 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0008-trust-evaluation-system.md) · [ADR 0018 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0018-key-lifecycle-expiry-renewal-revocation.md) · [ADR 0019 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0019-connect-acl-default-closed.md) · [ADR 0046 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0046-exec-service-fail-closed-acl.md) · [ADR 0070 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0070-owner-trust-and-share-grants.md) · [ADR 0079 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0079-grant-carried-owner-and-machine-names.md) · [ADR 0080 Proposed](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0080-grant-revocation-direct-push.md) · [ADR 0089 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0089-relationship-peer-evidence-survives-restart.md)

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
