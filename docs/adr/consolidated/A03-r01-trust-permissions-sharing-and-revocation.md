# A03 Trust Permissions Sharing and Revocation

- **Status:** Accepted (David, course-correction directive, 7 Nov 2026, ruling 2)
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Active since 7 November 2026. The 15 accepted slots are the live decision authority.
- **Supersedes:** The archived numbered records mapped to this slot in [TRANSFER.md](TRANSFER.md). The archive stays the historical record. Existing implementation gates remain in force.

David accepted the 15 slots at their current revisions on 7 November 2026 (course-correction directive, ruling 2). They are the live decision authority. The numbered records stay in [docs/adr-archive](../../adr-archive/ARCHIVE.md) as the historical record. [docs/adr-archive/move.json](../../adr-archive/move.json) records the archive transfer David accepted on 10 October 2026. Use the [index](README.md) for the current rules.

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

Evidence loading is bounded at startup (accepted 19 Oct 2026; archived as [T-0089-ordinary-send-load-barrier-fallback](../../adr-archive/transient/T-0089-ordinary-send-load-barrier-fallback.md)). On a startup load-barrier timeout or overflow, strict durable-ACK sends return retryable `RecipientUndiscovered`; an unbound contact card cannot satisfy the strict evidence requirement. Ordinary sends treat the barrier failure as no evidence and take the existing no-evidence path: contact-card selection, then the existing gossip or raw-QUIC fallback, which returns its actual result with the preserved fallback errors. The barrier wait fits the send's existing evidence budget. This refines ADR 0089 §5's blanket send-result statement; it changes neither incoming-frame handling nor the barrier's queue limits, counters or recovery guarantee.

A ShareGrant gives selected agents limited access. It must state the recipient, actions, targets and expiry. It does not expose Home or grant control of the owner's other agents. Re-sharing is denied unless an accepted design explicitly permits it.

## Service and token permissions

Remote command execution remains off unless the local ACL enables it. The allowed command, arguments and target must pass that ACL. A message that asks for execution is not an execution grant.

Forwarding is limited by the connect policy. The local service and destination remain part of the permission decision.

The durable owner token has broad local authority. Rider and GUI session credentials must have explicit scopes. Each route must state which token classes it accepts. New routes deny unlisted classes by default.

Long-lived subscriptions must apply current permission rules. A revoked credential must not retain access merely because it opened the connection earlier.

## Revocation

A verified revocation must survive restart. A corrupt existing revocation store must not be treated as evidence that no revocations exist. First-run absence and damaged persisted state are different cases.

When a revocation file is present and x0xd cannot decode it, x0xd does four things (accepted by David 13 Oct 2026; archived as [T-revocation-store-corrupt](../../adr-archive/transient/T-revocation-store-corrupt.md)):

1. It moves the bad bytes to a quarantine file (`<file>.quarantined-<unix-ms>`, `-<seq>` on a taken name). The live path does not hold the payload, and the next start does not read it. A readable file placed on the live path is a rebuild.
2. It starts and keeps running. A corrupt revocation store must not refuse startup; D266's refuse-to-start design is stopped.
3. It writes one error log line and emits a status event. `GET /status` and `x0x status` set `revocation_resync_required` and carry the same sentence in `warnings`; the first status read also sends one `status` event on `/events`.
4. Until revocation state is rebuilt or resynced from the group, membership fails closed. Any member whose non-revocation cannot be verified is treated as revoked. The hold is not a revocation record, an empty snapshot does not open membership, a carrier opens only when every record in its snapshot has verified, and a missing live file with a quarantine sibling stays closed. A bad signature on a valid structure does not close membership.

Keep revocation records for as long as the revoked credential could otherwise verify. Do not use a fixed cleanup age that can restore valid access.

Revocation must reach every applicable gate, including group key delivery and live sessions. A measured local enforcement bound starts when a host receives and verifies the record. An offline or partitioned host cannot promise immediate knowledge of a new revocation.

A lost-device action must revoke the applicable machine or agent authority, end live access, and create any required group exclusion work under [A09](A09-r01-group-encryption-and-key-changes.md).

## Consequences

Applications share one permission model. They must handle denial and revocation during long operations. A network partition can delay delivery of a revocation; it does not justify a claim of instant global removal.

## Alternatives

Per-route permission code is easy to add but difficult to keep consistent. Shared checks provide one place to enforce and test the rule.

A network-wide reputation score cannot replace an owner's explicit grant or a group's committed authority.

## Current implementation

Many trust, grant and ACL surfaces exist. Unified authority and complete revocation coverage remain incomplete. The corrupt-store quarantine rule above entered the tree with PR #1336. The heartbeat removes agent and machine revocation records after 90 days, without checking credential expiry. Binding tombstones are permanent; grant revocations follow the grant expiry. The corruption and lifetime requirements above are not fully implemented.

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

Decision source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Implementation checked on 12 October 2026 at commit `8cb6488331e6c1226913104ddb99ca4ec18bec37`.

[All 15 ADRs](README.md)
