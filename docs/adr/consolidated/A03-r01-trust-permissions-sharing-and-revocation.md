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

Forward openers known only from evidence (amendment of 11 Nov 2026, #1107). When the discovery cache has no entry for a `ForwardV2` opener, the forward gate may read a usable ADR 0089 evidence record for that agent on the transport-authenticated machine. All of these must hold: the signed `ForwardV2` header proves the agent key over fresh bytes bound to this recipient; the record names the transport machine; the certificate verifies, is current, chains to the local owner, and no agent, machine or owner revocation applies; the record came through EvidenceV1 admission. Such an opener is admitted only by a `principal = "owner"` connect ACL entry that lists the target. An exact-pair entry or a `principal = "grant"` entry does not admit it, at admission or at the re-check of a live stream. The gate writes nothing to the discovery, binding or capability registries, and does not cache the result. An enrolled owner machine with no known agent may open `ForwardV2` to reach this gate. The re-check of a live stream (archived ADR 0074 §4) uses the same lookup when the machine has no agent in the discovery cache, and tears the stream down when the record stops being usable or a revocation applies. `SyncV1` does not use this rule, because its `Proof` is an owner-key signature, not an agent-key signature. The opener needs no new message: its EvidenceV1 Hello on each new connection to a related peer, with the certificate after a reported miss, supplies the record. The Hello is limited to one per peer per 60 s (`HELLO_INTERVAL`), not once per certificate. Authority: David delegated the decision to Claude, chat 10 Nov 2026; the coordinating Claude session chose this rule on 11 Nov 2026. Design note: [1107-forward-opener-evidence](../../design/1107-forward-opener-evidence.md).

Owner sync on an enrolled machine with untrusted known agents (amendment of 12 Nov 2026, #1107). `SyncV1` enrollment admission required no known agent (archived ADR 0084 §5). An owner device announcing without its user identity is a known agent with no trust, so owner sync stopped in both directions. For `SyncV1` only, an enrolled and unrevoked owner machine is now admitted when every known agent fails the shared gate solely for lack of trust; blocked contacts, revocations, machine-pin mismatches, expired certificates, retired bindings, and other explicit denials still refuse. The outbound sync pass dials under the same condition; the session still needs the mutual owner-key proof; `ForwardV2` keeps the evidence rule above; no wire or API change. Authority: Claude under David's delegation, 10 Nov 2026 (ruling c). Design note: [1107-forward-opener-evidence](../../design/1107-forward-opener-evidence.md).

Evidence records keep the stored certificate across a same-digest announcement (amendment of 12 Nov 2026, #1107). A V3 identity announcement carries only the digest of the owner certificate; the bytes come by a separate fetch. When an ingest into the ADR 0089 evidence store (Hello, gossip or fetch) has no certificate bytes, the store keeps the certificate it holds if and only if all of these hold: the announcement names a certificate (its `cert_digest` is not the anonymous digest); the store holds a verified record for the same agent; that record names the same machine; that agent is not suspended by a move in progress; the stored certificate is current; and the digest of the stored certificate equals the announcement's signed `cert_digest`. The kept bytes are the stored bytes, and the record is verified again with them, certificate included. The store decides this again under its mutation lock when it stores the record, so an announcement stored in between (for example an anonymous one after consent is withdrawn) wins. An anonymous announcement or a different digest drops the stored certificate, as before; a fetch brings a new one. An announcement from another machine, or for another agent, cannot take the stored certificate. This grants no new trust: revocation, expiry, machine binding and owner chaining are still checked at each use. Without this rule the first announcement of an owner device after a restart of the receiver replaced the stored record with one without a certificate, and owner-trusted requests from that device were refused until the fetch completed. Authority: David delegated the decision to Claude, chat 10 Nov 2026; the coordinating Claude session chose this rule on 12 Nov 2026 and flagged it to David.

Evidence loading is bounded at startup (accepted 19 Oct 2026; archived as [T-0089-ordinary-send-load-barrier-fallback](../../adr-archive/transient/T-0089-ordinary-send-load-barrier-fallback.md)). On a startup load-barrier timeout or overflow, strict durable-ACK sends return retryable `RecipientUndiscovered`; an unbound contact card cannot satisfy the strict evidence requirement. Ordinary sends treat the barrier failure as no evidence and take the existing no-evidence path: contact-card selection, then the existing gossip or raw-QUIC fallback, which returns its actual result with the preserved fallback errors. The barrier wait fits the send's existing evidence budget. This refines ADR 0089 §5's blanket send-result statement; it changes neither incoming-frame handling nor the barrier's queue limits, counters or recovery guarantee.

A ShareGrant gives selected agents limited access. It must state the recipient, actions, targets and expiry. It does not expose Home or grant control of the owner's other agents. Re-sharing is denied unless an accepted design explicitly permits it.

A grant that carries names (archived ADR 0079) names each machine that hosts a granted agent. The issuing daemon's own machine hosts its own agent; each other machine hosts an agent by its current announcements. The issuing daemon names its own machine from its live local profile `machine_name`. Its own machine needs no enrollment record and no synced name record, and the daemon ignores a synced name record for it. The owner key that signs the names section vouches for this name directly. Each other machine must have a current, owner-verified ADR 0041 enrollment and an owner-signed synced `machine_name`. The daemon omits a machine whose name is not valid and keeps the other machines. This amends the `machines` rule of archived ADR 0079 §1, which required a synced `machine_name` and an enrollment for every listed machine (David's ruling, 10 Nov 2026, which accepts PR #1831 as built). This records existing behavior.

## Service and token permissions

Remote command execution remains off unless the local ACL enables it. The allowed command, arguments and target must pass that ACL. A message that asks for execution is not an execution grant.

Forwarding is limited by the connect policy. The local service and destination remain part of the permission decision.

The durable owner token has broad local authority. Rider and GUI session credentials must have explicit scopes. Each route must state which token classes it accepts. New routes deny unlisted classes by default.

Long-lived subscriptions must apply current permission rules. A revoked credential must not retain access merely because it opened the connection earlier.

## Revocation

A verified revocation must survive restart. A corrupt existing revocation store must not be treated as evidence that no revocations exist. First-run absence and damaged persisted state are different cases.

A revocation record stays in force until the revoked credential can no longer be used (David's ruling A on [#1108](https://github.com/saorsa-labs/x0x/issues/1108), 20 Oct 2026). The age of a record is never a reason to remove it. An agent or machine record names a key, and a key has no expiry, so x0xd keeps these records for good. A binding tombstone is permanent. A share-grant record goes when the grant is past its signed expiry plus the clock allowance. An expired certificate does not end an agent revocation: the same key can hold a later certificate or announce with no certificate.

A revocation set that does not fit in one gossip batch is sent as a round of batches (decided 11 Nov 2026 by Claude under David's delegation of 10 Nov 2026; fixes [#1857](https://github.com/saorsa-labs/x0x/issues/1857)). Each batch of a round ends with one round-marker record, which names the round, the batch count and the batch index, and which can never verify as a revocation. A set that fits in one batch has no marker and keeps its earlier bytes. A marker is never stored, listed or counted. A daemon that waits for a resync opens only on a single unmarked batch, or on every batch of one round whose record hashes match the round's digest; a part of a round never opens it. The layout is in [`docs/design/revocation-batches.md`](../../design/revocation-batches.md).

A daemon does not publish the self-revocation of a subject it has not seen (decided 11 Nov 2026 by Claude under David's delegation of 10 Nov 2026; fixes [#1863](https://github.com/saorsa-labs/x0x/issues/1863)). The record stays in force and in the store; pubsub spreads it once. A subject is seen only through a relationship that a peer cannot create alone for a fresh key: this daemon itself, a Known or Trusted contact (or a machine listed on one), an agent or enrolled machine of this owner, or an active member of an approval-only named group that this node is in. Discovery caches, Unknown or Blocked contacts, and pending, removed or banned group rows do not count (#1868 review, 11 Nov 2026). A daemon that waits for a resync does not let a held self-revocation block opening when the sender's set has no record of the same subject and issuer; every other held record keeps the exact rule. The details and the known limit are in [`docs/design/revocation-batches.md`](../../design/revocation-batches.md).

A daemon whose published set for a carrier is empty sends an explicit empty-set statement on that topic (decided 12 Nov 2026 by Claude under David's delegation of 10 Nov 2026; [#1867](https://github.com/saorsa-labs/x0x/issues/1867)). The statement is one batch with one round-marker record where n=1, i=0 and `set` is BLAKE3 over the bytes `x0x-revocation-round-set-v1` only (no record hashes). A daemon does not send the statement while its own carrier is closed; a set that holds only an oversize legacy record is not empty and sends no statement. A trusted authority's statement counts as that sender's snapshot of the empty set; the carrier opens when every held record is covered, so a waiter with no held record opens, a waiter with only self-revocations for which the sender has no record opens and keeps them in force, and a waiter with any other held record stays closed. The rebuild rules of item 4 do not change, so unreadable quarantine bytes still keep the carrier closed. A trusted authority that is behind and has an empty set can now open a waiter that holds no record; before, it needed one published record to do so. This replaces the words "an empty snapshot does not open membership" in item 4 below for an explicit statement from a trusted authority only; an unmarked empty batch and silence still do not open. A named-subject request (a waiting daemon asks an authority for every record it holds on named subjects) was decided against on the same date: an authority holds a stranger's self-revocation only if it was online at the one pubsub spread, so an answer with no record cannot show that no record exists, and the request names the waiter's contacts and group members to another party. A waiting daemon that lost the self-revocation of a subject that only it knows opens without that record; this is a known limit. The design and the reasons are in [`docs/design/revocation-batches.md`](../../design/revocation-batches.md).

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

Many trust, grant and ACL surfaces exist. Unified authority and complete revocation coverage remain incomplete. The corrupt-store quarantine rule above entered the tree with PR #1336. The heartbeat sweep removes only the records of dead share grants; agent, machine and binding records stay (#1108). A daemon older than this change still removes agent and machine records 90 days after `revoked_at`. The set holds one record for each subject and issuer of an agent, machine or binding revocation (the earlier `revoked_at`, then the lower record hash), and a new record's `reason` is at most 1024 bytes (#1857). A daemon sends each revocation carrier as one batch when the set fits (2 MiB less 64 KiB, about 370 records), and as a round of marked batches when it does not; a receiver ignores a batch above 2 MiB. The number of different subjects has no upper limit: any key can revoke itself. The corruption requirements above are not fully implemented.

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
