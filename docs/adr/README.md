# Architecture Decision Records

## Consolidation review

Read the [15 ADR set](consolidated/README.md) for the direction confirmed by
David (D198) on 5 October 2026. Its records remain Proposed replacements while the transfer
checks are open. This index, its status overlay and accepted records continue
to govern existing work. New docs follow the [style guide](../documentation-style.md).
The numbered records in the [transfer map](consolidated/TRANSFER.md) keep
these paths and stay outside the limit of 15. ADR 0115 and ADR 0116 are
outside that map. They stay in force outside the count.
`python3 scripts/check-adr-count.py` fails when the current count exceeds 15.
The plan is the [15 ADR set](consolidated/README.md).

This directory contains architecture decision records for x0x.

## Transfer rulings (2026-10-05)

D198 confirms the consolidation direction and writing target; the drafts stay
Proposed until David accepts the transfer. D199 keeps new or changed decisions
in the numbered ADR series only, under ADR 0087. The reserved numbers and
0109–0114 acceptance lanes stand; slot revisions are drafts.

D200 confirms ADR 0040's `owner_agent` and current-owner-signed transfers;
implementation status does not defer that decision. D197 confirms that
EvidenceV1 from relationship peers needs not-Blocked trust, with verified
evidence (ADR 0089 decision 2).

D196 refines D16/D54/D181: W3-H requires 20 CI reruns with the same verdict
and complete structured receipts. Byte-identical traces are non-blocking.
The red-on-main harness-first gate remains. See the
[updated rulings digest](../design/x0x-direction.md#5-decisions-d01d200)
and [Pending transfer map](consolidated/TRANSFER.md#rulings).

## Status overlay (rulings 2026-09-28..30)

Accepted ADRs are immutable, so their text can lag behind the rulings David
Irvine made from 2026-09-28 to 2026-09-30. This overlay lists every ADR whose
practical status differs from its text. **Where this overlay and an ADR body
disagree, new work follows the overlay** until the named successor ADR is
decided. The rulings (D01–D36, E-D1–E-D17), the scope, the goals and the wave
plan are summarised in
[`docs/design/x0x-direction.md`](../design/x0x-direction.md). ADR numbers
marked (prov.) are provisional and are allocated when the ADR PR is opened.
Index entries below that carry an **[overlay: …]** tag are covered here.

- **Parked:** lower priority and not in scope now (D19). Shipped code stays
  and gets bug and security fixes only. No new slices.
- **Frozen:** bug and security fixes only, in the ADR 0072 sense.
- **Held:** the ADR stays Accepted, but no new implementation slices until
  the stated condition is met (D28). A hold is not a status change.
- **Retire, reject, withdraw:** do not build on it. Removal follows v0.46 in
  removal-only PRs (D27).
- **To be superseded or amended:** the direction is ruled, but the successor
  ADR is not Accepted yet. The existing ADR still describes shipped
  behaviour; new work follows the ruling.

### Do not start new work: parked, retired, rejected, withdrawn or held

| ADR | The text says | Ruling | In practice now | Instrument |
|---|---|---|---|---|
| [0073](./0073-audio-and-video-calling.md) Audio and video calling | Audio and video ship together through the daemon-side browser gateway (R8) | D19 (revised 2026-09-29): R8 media calling is lower priority and not in scope now | **Parked.** No media work. The `/calls` signalling lifecycle stays, labelled experimental: no media, and release builds lack `voice` (D09). #892 is parked | [ADR 0095](./0095-scope-x0x-is-glue.md) (Accepted, Scope) |
| [0042](./0042-voice-media-over-tailnet-streams.md) Voice media over tailnet streams | Voice media over `WebRtcV1` streams | D19 | **Frozen and parked** with R8 | [ADR 0095](./0095-scope-x0x-is-glue.md) (Accepted) |
| [0075](./0075-collaborative-notes-and-agent-scratchpads.md) Notes and scratchpads | Notes are a `yrs` text CRDT (the CRDT choice is already superseded by 0081); scratchpads are a rider-reachable group store | D19: the rich-text notes merge path is lower priority, and shared places (scratchpads, boards, project data) are core. D36: the scratch store comes right after M3 in W4 | **Split.** The notes half is parked. The scratchpad half is core and is re-specified as a sealed scratch store with rider and grant scope. #965 is split: #1094 is the scratch store (core) and #965 keeps the notes (parked) | ADR 0103 (prov.) supersedes the scratchpad half; [ADR 0095](./0095-scope-x0x-is-glue.md) (Accepted) parks the notes half |
| [0081](./0081-notes-use-loro-crdt.md) Notes use loro | Notes use loro `=1.16.2` | D19 | **Parked** with the notes merge path. The paused notes branches stay paused; #1029 and PR #1035 are parked with it | [ADR 0095](./0095-scope-x0x-is-glue.md) (Accepted) |
| [0082](./0082-notes-epoch-bound-writer-rule.md) Note records under the roster epoch | The epoch-bound note writer rule | D19 | **Parked** with the notes merge path | [ADR 0095](./0095-scope-x0x-is-glue.md) (Accepted) |
| [0037](./0037-agent-placement-and-key-custody.md) Agent placement and key custody | Pinned and Roaming agents, a placement ledger, key custody | D27: roaming is cut | **Retire.** Placement labels are frozen and there is no new roaming work. The key-move ceremony is removed after v0.46. #443 is won't-do | ADR 0102 (prov.) |
| [0043](./0043-agent-key-move-protocol.md) Agent key-move protocol | Machine KEM enrollment, commit-then-activate moves, binding revocation | D27 | **Retire.** The key-move ceremony and `/agent/move*` are cut after v0.46. Owner-sync machine enrollment (ADR 0084) is not part of the cut. ADR 0102 states which of this ADR's wire pieces (the v3 machine announcement, binding revocation records) stay for compatibility | ADR 0102 (prov.) |
| [0051](./0051-application-level-peer-relay.md) Peer relay (X0X-0070), **Proposed** | A default-off, one-hop DM fallback | D27: reject | **Rejected in practice.** Do not extend it. The peer relay is cut at ADR 0071's exit; #442 is won't-do | Status change to Rejected (W4) |
| [0083](./0083-agent-initiated-gui-show.md) GUI show | Local and remote GUI show, in slices | D28 | **Held** after slice 1 until a cross-model review is recorded. Changing the remote-show default needs a superseding ADR | – |
| [0070](./0070-owner-trust-and-share-grants.md) Owner trust and share grants | Owner trust, ShareGrant, ACL management, in slices | D28 | **Held:** no new slices until its review is recorded. §1 and §2 are also to be superseded in part (next table) | – |
| [0077](./0077-share-grant-owner-side-redelivery-outbox.md) Share-grant redelivery outbox | An owner-side durable outbox for grants | D28, D18 | **Held:** behaviour kept, no new slices until its review is recorded. The implementation moves onto one `Outbox<T>` | ADR 0090 (prov.) |
| [0079](./0079-grant-carried-owner-and-machine-names.md) Grant-carried names | Names carried in a v2 grant | D28 | **Held:** no new slices until its review is recorded. #1015 follows ADR 0074 slices 1 and 2 | – |

### Direction ruled, successor pending: new work follows the ruling

| ADR | The text says | Ruling | In practice now | Instrument |
|---|---|---|---|---|
| [0038](./0038-home-owner-certified-personal-space.md) Home | Home is an auto-provisioned, owner-certified personal space; seals re-check owner certificates; Home always contains at least one Roaming agent (ADR 0037) | D16 and D34. D27 cuts roaming, so the Roaming-agent invariant falls | **To be superseded.** Home becomes an explicit owner group: OwnerCertified is checked at admission, revoke is by eviction, and a promoted admin with carried evidence may admit while the owner is offline. Until then Home is frozen; after v0.46.0 is promoted, Home failures are known limitations unless they are security defects | [ADR 0088](./0088-group-liveness-contract.md) (Accepted), W3 |
| [0060](./0060-one-home-per-owner.md) Home is elected | The owner's Home is elected on the Tier-1 register | D16 | **To be superseded** with ADR 0038. Election is frozen | [ADR 0088](./0088-group-liveness-contract.md) (Accepted) |
| [0069](./0069-home-wait-for-sync-before-auto-provisioning.md) Home waits for owner sync | Auto-provisioning defers to owner sync | D11 | Accepted as a record of shipped behaviour; to be superseded | [ADR 0088](./0088-group-liveness-contract.md) (Accepted) |
| [0064](./0064-owner-anchored-fork-authority.md) §3 | Persistent per-node quarantine with local containment; a marker clears only through an owner-anchored commit, the owner's seal route or a manual clear | D16, D34 | **§3 to be superseded in part**, so that a forked node has a re-seat path (#871) and stale-base gaps catch up under an attesting admin instead of staying quarantined. The rest of ADR 0064 is frozen | [ADR 0088](./0088-group-liveness-contract.md) (Accepted) |
| [0066](./0066-ordinary-group-fork-anchors-and-data-plane-quarantine-coverage.md) §2 | Ordinary groups get the quarantine marker with `no_anchor: true`, cleared only manually | D16, D34 (1) | **§2 to be superseded in part.** In ownerless groups, an active admin's signed terminal snapshot attests stale-base catch-up (#818): a mandate layer above ADR 0016, not a rank. The rest of ADR 0066 is frozen | [ADR 0088](./0088-group-liveness-contract.md) (Accepted) |
| [0070](./0070-owner-trust-and-share-grants.md) §1 | Owner trust applies at trust evaluation and the stream gate | D17, D29, D33 | **§1 to be superseded in part.** Every trust gate decides through one `Authority::decide`, from evidence presented in-band plus persisted state, never from a TTL'd gossip cache. Owner trust missing at 4 of the 8 peer-facing gates is a bug against §1 that this fixes. Pulled into v0.46 (D29): persisted verified agent→machine bindings and KEM keys for relationship peers, an on-connect evidence exchange and a pull lookup. ADR 0089 must be Accepted before that code merges | ADR 0089 (prov.) |
| [0070](./0070-owner-trust-and-share-grants.md) §2 | ShareGrant semantics | D24, D25, D35 | **§2 to be superseded in part:** a protocol-aware stream gate, an inbox policy (default open), a scoped exec grant, and a 90-day maximum grant lifetime with renewal | ADR 0099 (prov.); the lifetime in ADR 0098 (prov.) |
| [0007](./0007-three-layer-identity-model.md), [0008](./0008-trust-evaluation-system.md) Identity and trust evaluation | Consent-gated user identity; `(AgentId, MachineId)` pair evaluation | D17 | **To be superseded in part:** consent is persisted, certificates are presented in-band, and one decision function decides. In Home, ADR 0108 (S2) makes owner-certificate disclosure members-only (D38), with two ruled, time-limited exceptions to non-members (D124): the joiner's own certificate on Home gossip until every seat has S5's capability (D68), and #946 topic answers to legacy peers until D35's minimum supported version (D96) | ADR 0089 (prov.); ADR 0108 |
| [0021](./0021-dm-origin-machine-attestation.md) DM origin-machine attestation | Origin authentication with zero prior cache state; a persistent binding cache is rejected (considered option 2) | D29 and D33 (the cache); D23 (hard-require) | **Amended in part (the cache) by ADR 0089, accepted 2026-09-30:** mutual signed evidence may be persisted for relationship peers only (enrolled devices, grant parties, group members); strangers stay in TTL-bounded caches (E-D10). **Still to be amended:** attestation becomes hard-required behind a capability bit | [ADR 0089](./0089-relationship-peer-evidence-survives-restart.md) (accepted) for the cache; ADR 0098 (prov.) for hard-require |
| [0018](./0018-key-lifecycle-expiry-renewal-revocation.md) Key lifecycle | Expiry, renewal and revocation as shipped | D23, D35 | **To be superseded:** no revocation sweep before `not_after`, a Machine issuer path, Critical carriers for revocation topics, a fail-closed store, one listing, a lost-device response, and a 90-day maximum ShareGrant lifetime with renewal | ADR 0098 (prov.), W4 |
| [0017](./0017-x0x-as-agent-transport-layer.md) Positioning | x0x is the agent transport layer beneath MCP/A2A | D19 (revised 2026-09-29) | **Positioning to be superseded in part.** x0x is the glue between people, their machines and their agents; it does not provide agents; shared places, team sharing and efficiency are core. The interop posture stays: serve a signed card, stay beneath MCP/A2A | [ADR 0095](./0095-scope-x0x-is-glue.md) (Accepted) |
| [0045](./0045-decentralized-self-update.md) Self-update | Decentralized self-update with signed manifests | D20, D21 | **To be superseded** by owner-governed self-maintenance (policy, channel, staging, recall, canary). Until then only Track M-safety fixes proceed: M1 health verdict and M2 safe apply with self-rollback | ADR 0094 (prov., supersedes ADR 0061 §6); ADR 0097 (prov.) |
| [0010](./0010-gss-before-mls-treekem-for-v1-secure-groups.md), [0024](./0024-gss-rotation-on-admin-remove-fail-closed.md), [0012](./0012-treekem-default-secure-groups.md) §3 | GSS remains a first-class secure-group plane | D18 | **To be superseded:** TreeKEM is the only group crypto. GSS creation stops once TreeKEM has a request/approve path, and `/mls/groups` is cut. No new GSS features | ADR 0091 (prov.), W3 |
| [0028](./0028-authenticated-causal-predecessor-delivery.md) Causal-predecessor delivery | Its own relay outbox | D18 | Behaviour kept. The implementation folds onto one `Outbox<T>`; fix PRs add no new bespoke queues | ADR 0090 (prov.), W3 |
| [0034](./0034-leaf-participation-default.md) Leaf default | Leaf participation is the desktop default | D26, E-D6, D36 | Kept for now. The Leaf egress default (ADR 0078, Proposed, PR #1005) is decided after v0.46 as one bundle: enforcement never goes first, and revocation topics and named-group fanout are protected first | ADR 0078 decision, W4 |
| [0019](./0019-connect-acl-default-closed.md), [0022](./0022-tailnet-stream-api.md) Connect ACL and stream gate | The connect ACL gates every stream protocol | D24 | **To be amended:** a protocol-aware stream gate. The ACL governs forward and exec targets, owner protocols pass on owner trust, and unregistered protocols are reset | ADR 0099 (prov.), W4 |
| [0015](./0015-no-app-layer-at-rest-encryption.md) At-rest encryption | No app-layer at-rest encryption | D22 | Stands for now, with a rotate/recertify and lost-device runbook. After promotion it is superseded in part, for the owner root key only | ADR 0100 (prov.) |

Later amendments that do not change today's direction: ADR 0001 (seed
authentication, ADR 0105 prov.), ADR 0002 (one transport liveness contract,
ADR 0104 prov.), ADR 0047 and ADR 0048 (a digest beacon, ADR 0092 prov.) and
ADR 0072 (extended by R12,
[ADR 0096](./0096-r12-x0x-is-maintained-by-its-own-agents.md), Accepted;
[ADR 0095](./0095-scope-x0x-is-glue.md), Accepted, records the D19 parks
beside its freezes and leaves any re-tiering as an open question).

**Frozen (bug and security fixes only):** ADR 0029 (public-message
threading), ADR 0035 steps 2–6 (per ADR 0071), ADR 0058 (the constitution),
the fork-quarantine family ADR 0059, 0064, 0066, 0067 and 0068 (apart from
the parts above), ADR 0042 with R8, and Home (ADR 0038, 0060, 0069).

**Amendments already in force:** ADR 0084 amends ADR 0041; ADR 0085 amends
ADR 0047; ADR 0086 amends ADR 0049; ADR 0069 amends ADR 0038 and refines
ADR 0060 as a record; ADR 0093 adds the capability-advert registry (D08);
ADR 0116 amends ADR 0023's local recording and retention policy (D228).

### Reviews never recorded (D28)

26 Accepted ADRs record their reviewers as "pending" or "TBD": 0017, 0018,
0023, 0043, 0044, 0045, 0046, 0047, 0048, 0049, 0050, 0052, 0053, 0054, 0055,
0057, 0058, 0060, 0070, 0071, 0072, 0077, 0079, 0081, 0082 and 0083.

- Most are records of shipped behaviour written in bulk. For those, this entry
  is the erratum: the decision stands and the review is missing.
- D28 blocks new implementation slices only where an ADR still authorises new
  surface: 0070, 0077, 0079 and 0083 (held above). 0045 is covered by its
  planned supersession (D20), 0081 and 0082 by the notes park (D19), and 0072
  is restrictive, so recording its review blocks nothing.
- The Proposed 0051, the Superseded 0056 and 0065, the Accepted (record)
  0062 and the Rejected 0063 also list pending reviewers.
- Noted in this pass, outside the D28 list: 0069, 0073, 0074 and 0075 say a
  cross-model or human review is required but record none. 0069 was accepted
  by David as a record (D11), and 0073 and the notes half of 0075 are parked.

### Process until v0.46.0 is promoted

- Only fix ADRs are admissible: ones that record a fix to shipped or merged
  behaviour, a storage format, or deployment governance. The D29 slice of
  ADR 0089 is the one exception.
- A change to a network behaviour, a storage format, a protocol or a
  security bound has a Proposed ADR on `main` before its code merges to any
  branch, integration branches included.
- [ADR 0087](./0087-repository-and-release-governance.md) (Accepted 2026-09-30) adds to
  that: a wire, protocol or dependency change also needs its ADR Accepted
  before its code merges to `main`, and an ADR that records already-shipped
  behaviour uses the status `Accepted (record)`.

## Accepted
- [ADR 0002: Application-Level Keepalive](./0002-application-level-keepalive-for-direct-connections.md) — 15s SWIM Ping prevents QUIC idle timeout
- [ADR 0003: Auto-Connect to Discovered Agents](./0003-auto-connect-to-discovered-agents.md) — identity listener auto-connects via `connect_addr()`
- [ADR 0004: QUIC Stream and Channel Limits](./0004-quic-stream-and-channel-limits.md) — 50,000 data-channel capacity, 4,096 uni streams
- [ADR 0006: No Global DHT Dependency for User and Group Data](./0006-no-global-dht-for-user-and-group-data.md) — partition-tolerant user/group data follows reachable peers, not a global overlay
- [ADR 0007: Three-Layer Identity Model](./0007-three-layer-identity-model.md) **[overlay: to be superseded in part, D17]** — machine transport identity, portable agent identity, and optional consent-gated user identity
- [ADR 0008: Trust Evaluation System](./0008-trust-evaluation-system.md) **[overlay: to be superseded in part, D17]** — unified `(AgentId, MachineId)` pair evaluation with orthogonal trust levels and identity types
- [ADR 0009: Receive-Pump Overload Policy](./0009-recv-pump-overload-policy.md) — observable PubSub load-shedding plus receive-pump diagnostics
- [ADR 0010: GSS Before MLS TreeKEM for v1 Secure Groups](./0010-gss-before-mls-treekem-for-v1-secure-groups.md) **[overlay: to be superseded, D18]** — `MlsEncrypted` named groups use Group Shared Secret rekey-on-ban in v1, not full MLS TreeKEM. **Superseded (forward path) by ADR 0012** now that saorsa-mls 0.3.6 ships real TreeKEM; still describes the legacy plane grandfathered groups run on
- [ADR 0011: Bootstrap Dual-Listen UDP/443](./0011-bootstrap-dual-listen-udp-443.md) — second root x0xd on :443 per bootstrap host for WARP/full-tunnel-VPN reachability
- [ADR 0012: Real TreeKEM as the Default Secure Group Plane](./0012-treekem-default-secure-groups.md) **[overlay: §3 to be amended, D18]** — private `MlsEncrypted` (`Hidden`) groups run real `saorsa_mls::TreeKemGroup` (FS + PCS) by default; **multi-member convergence implemented and shipped in x0x 0.21.0**; legacy GSS groups grandfathered with owner opt-in upgrade; supersedes ADR 0010's forward path
- [ADR 0013: Priority-Aware PubSub Receive-Pump Shedding](./0013-priority-aware-pubsub-shed.md) — refines ADR 0009 to shed low-priority PubSub control frames first (renumbered from 0010 to resolve a collision)
- [ADR 0014: TreeKEM Self-Leave Is a Roster Removal; PCS Comes From an Owner-Driven Rekey](./0014-treekem-self-leave-owner-driven-rekey.md) — a leaver cannot self-rekey (RFC-9420 / saorsa-mls forbids self-removal), so self-leave is a signed roster removal and the **owner** issues the responsive rekey commit that delivers PCS; owner-only single-writer with lazy catch-up; amends ADR 0012
- [ADR 0015: No App-Layer At-Rest Encryption or Secondary Passwords](./0015-no-app-layer-at-rest-encryption.md) **[overlay: stands; superseded in part after promotion, D22]** — local state is protected by OS user isolation + full-disk encryption, never a secondary password; best-effort OS-keystore wrapping of identity keys sanctioned as a follow-up
- [ADR 0016: Role-Based Group Authority — Flat Admin/Member, Retiring `Owner`](./0016-role-based-group-authority-flat-admin.md) — named groups use a flat Admin/Member model; `Owner` retired (legacy parse-only), last-admin invariant enforced; amends ADR 0014 (accepted 2026-06-11, shipped v0.27.0)
- [ADR 0017: Position x0x as the Agent Transport Layer](./0017-x0x-as-agent-transport-layer.md) **[overlay: positioning to be superseded in part, D19]** — transport spec + A2A interop + PQC/zero-registry positioning; signed `AgentCard` and `/.well-known/agent-card.json` (accepted 2026-06-15)
- [ADR 0018: Key Lifecycle — Expiry, Renewal, and Revocation](./0018-key-lifecycle-expiry-renewal-revocation.md) **[overlay: to be superseded, D23]** — key expiry + renewal plus gossip-propagated revocation sets (`/identity/revoke`, `/identity/revocations`) with revoked-subject eviction (accepted 2026-07-04)
- [ADR 0019: Connect ACL — Default-Closed Connectivity Policy](./0019-connect-acl-default-closed.md) **[overlay: to be amended, D24]** — default-closed connect policy engine (`src/connect/`) with fail-closed load and `/diagnostics/connect` (accepted 2026-07-22)
- [ADR 0020: Tailnet Phase 1 — per-peer byte-streams + local port-forwarding](./0020-tailnet-phase-1-byte-streams-and-forwarding.md) — PeerStream over `Node::open_bi`/`accept_bi` with the identity gate inside open/accept; `src/forward.rs` local port-forwarder gated by the connect ACL (#131/ADR-0019) + key lifecycle (#130); loopback-only Phase 1 (accepted 2026-07-22)
- [ADR 0021: DM Origin-Machine Attestation for Gossip DMs](./0021-dm-origin-machine-attestation.md) **[overlay: to be amended, D29/D33]** (accepted 2026-08-12) — per-DM machine-key attestation (self-certifying key + hash binding + domain-separated ML-DSA-65) verified with zero prior receiver state; present-but-invalid attestations hard-drop; absent attestations keep the #184 retained-binding fallback until a `DmCapabilities` follow-up hard-requires them. Codec scaffolding landed (`DmOriginAttestation` in `src/dm.rs`); enforcement wiring is the implementation follow-up
- [ADR 0022: Tailnet stream API — per-protocol acceptors, connect-ACL gate, bounded backpressure](./0022-tailnet-stream-api.md) **[overlay: to be amended, D24]** — protocol-byte routing to single-owner acceptors (bounded, drop-on-full), stream-layer connect-ACL pair gate after the identity gate, QUIC flow-control backpressure with asserted bounds; issue #132 deliverable 1 (accepted 2026-07-22)
- [ADR 0023: Durable Local History Is a Core x0x Capability](./0023-durable-local-history.md) (accepted 2026-07-22) — default-on SQLite history store in x0xd (durable/replaceable/ephemeral taxonomy, bounded shed-on-full writer, local-only — never served to the network); lifts the nostr-bridge spike's store design; substrate for tic-tac-toe
- [ADR 0025: Required Gates Must Prove Observation Completeness](./0025-required-gates-prove-observation-completeness.md) (accepted 2026-07-28) — a required gate passes only when it accounts for the complete discovered set and proves each required observation completed; default execution is the computed complement of explicit, machine-checkable non-default declarations (no ordinary-test allowlist); one executable authority owns classification and reachability for both local and pull-request CI; non-observation may not resolve to a pass; enforcement is staged and a status becomes a merge gate only after a failing PR is demonstrably refused. Mechanism, schemas and rollout live in [docs/design/required-gates-observation-completeness.md](../design/required-gates-observation-completeness.md)
- [ADR 0026: Managed x0xd Deployment Has Distinct Roots and Closed Resolution](./0026-managed-x0xd-deployment.md) (accepted 2026-07-30) — every concurrent daemon has a distinct effective data root; one repository-identified path binds installation and root resolution, proves the complete running set, and closes controlled transitions. Mechanisms live in [docs/design/managed-x0xd-deployment.md](../design/managed-x0xd-deployment.md)
- [ADR 0027: Active-Recipient Group-Key Sealing](./0027-active-recipient-group-key-sealing.md) (accepted 2026-07-30) — every production call path choosing a named recipient for current-epoch group key material establishes active membership before sealing; only a recipient-selecting call path excluded from production builds at compile time may omit the check. Mechanisms live in [docs/design/active-recipient-group-key-sealing.md](../design/active-recipient-group-key-sealing.md)
- [ADR 0028: Authenticated Causal-Predecessor Delivery](./0028-authenticated-causal-predecessor-delivery.md) **[overlay: implementation moves to Outbox<T>, D18]** (accepted 2026-08-02) — request-access approvals may wait in a durable bounded causal queue, but they mutate roster state only after the matching origin-authenticated requester predecessor applies and the signed state-chain link validates. Its frozen grounding lives in [docs/grounding/0028-authenticated-causal-predecessor-delivery.md](../grounding/0028-authenticated-causal-predecessor-delivery.md); mutable mechanisms live in [docs/design/groups-join-roster-propagation.md](../design/groups-join-roster-propagation.md)
- [ADR 0029: First-Class Threading on Signed Public Group Messages](./0029-public-message-threading.md) **[overlay: frozen]** (accepted 2026-08-12) — `msg_id = BLAKE3(signable_bytes())` plus optional signed `thread_root`/`thread_parent`; non-threaded messages stay byte-identical under the v1 signing domain, threaded messages sign under a v2 domain so old nodes fail closed; orphan replies accepted per ADR 0028. Delivered ahead of acceptance (ratified): v0.36.0 shipped the v2 domain, send-path fields, and `?thread_root=` message filter; v0.37.0 added the `GET /history` thread-field exposure. Remaining follow-up: GUI migration off the deprecated side-topic scheme
- [ADR 0030: DM Protocol v2 — Durable Application ACK, Capability-Gated](./0030-dm-durable-application-ack-v2.md) (accepted 2026-08-13) — `Accepted` under v2 = verified + durably committed (ADR 0023) + dispatched, at-least-once across restart; strict product sends fail closed with 409 `recipient_ack_semantics_unavailable` against v1 peers (never silent downgrade); capability advert `max_protocol_version = 2` iff history enabled; two named send tiers (product REST/CLI durable-by-default, internal/WS/library v1 explicit); bootstrap outbox must be extracted from `named_groups.rs` before merge; DM threading (the campaign's v3) explicitly deferred to its own ADR. Governs landing `wip/codex-durable-app-ack`
- [ADR 0031: Sole-Member Self-Leave Deletes the Group](./0031-sole-member-self-leave-deletes-group.md) (accepted 2026-08-20) — a sole-member `DELETE /groups/:id` routes to the terminal withdrawal flow (`deleted` response, keyless tombstone); pending derived from `join_requests`; rank-blind terminal authority; amends ADR 0016 §3; concurrent last-two-leaves race accepted and tracked in #372
- [ADR 0032: The `:443` Bootstrap Listener Runs Its Own Identity](./0032-x0xd-443-own-identity.md) (accepted 2026-08-23) — the deploy script wrote a non-existent `machine_key_path`, so every `:443` daemon silently shared the prod daemon's identity; now `identity_dir` per instance, and `x0xd` names every ignored config key at startup; amends ADR 0011 ops section
- [ADR 0033: The Receive Pump Never Blocks — All Classes Shed or Spill](./0033-recv-pump-never-blocks.md) (accepted 2026-08-23) — every gossip class try_sends (Membership/Bulk shed with counters; ADR 0009's blocking carve-out falsified by #378), DM classes go through a 64 MiB byte-capped lossless spill forwarder; amends ADR 0009 §2
- [ADR 0034: Leaf Gossip Participation Is the Desktop Default; `--relay` Is One Operator Concept](./0034-leaf-participation-default.md) **[overlay: Leaf egress default decided after v0.46, D26]** (accepted 2026-08-25) — desktops stop pass-through relaying (~444 KB/s idle measured, #380); `--relay`/`X0X_RELAY_OPT_IN=1`/`gossip.relay` selects BOTH Full participation and capability advertisement; backbone = bootstraps + opt-ins per ADR-0011
- [ADR 0035: Relay Decentralization to SOTA — Earned Promotion, Spread Selection, Bootstrap Demotion](./0035-relay-decentralization.md) (accepted 2026-08-27) — relay/coordinator roles earned by sustained reachability + peer-verified inbound dials (self-asserted counts are tie-break hints only); spread selection across ALL advertised relays; budget caps; bootstraps demote to last-resort; orthogonal to 0034 (transport role vs gossip participation)
- [ADR 0036: Owner Singleton and Naming Registry](./0036-owner-singleton-and-naming-registry.md) (accepted 2026-08-27) — an install with an active `user.key` is owned by that `UserId`; daemon-persisted `PUT/GET /profile` (human/agent/machine names), names on V3 announces, `AgentCard.owner_name`, and `GET /owner/agents` authoritative roster; one owner per install (`--rotate-owner` to replace)
- [ADR 0037: Agent Placement and Key Custody](./0037-agent-placement-and-key-custody.md) **[overlay: retire, D27]** (accepted 2026-08-27) — every owned agent is `Pinned(MachineId)` or `Roaming`; a roaming move is an owner-sealed ML-KEM export to the target machine (ADR 0027 primitive) with implicit source-machine revocation (ADR 0018/0021); single-live-copy invariant; ACP-harness agents always Pinned
- [ADR 0038: Home — an Owner-Certified Personal Space](./0038-home-owner-certified-personal-space.md) **[overlay: to be superseded, D16; frozen]** (accepted 2026-08-27) — new `GroupAdmission::OwnerCertified(UserId)` admission verified at invite-accept and every state-commit seal; auto-created renamable Home (`Hidden + OwnerCertified + MlsEncrypted`) containing only the owner's agents incl. ≥1 Roaming; certs resolved via the V3 announce blob-fetch path (#419)
- [ADR 0039: Agent Harness Boundary — ACP-Attached Agents vs API-Key Riders](./0039-agent-harness-boundary.md) (accepted 2026-08-27) — sub-agent identities are owner-certificated harness-generated keypairs; ACP-attached (harness owns key, own instance, Pinned) or API-key rider (scoped deny-by-default token, daemon signs with provenance, Leaf participation per ADR 0034)
- [ADR 0040: Agent-to-Agent Delegation in Spaces](./0040-agent-delegation-in-spaces.md) (accepted 2026-08-27) — signed `Delegation` envelope with bounded `authority_scope` + expiry, depth cap 2; task-list CRDT `owner_agent` with signed transfer; structured `mentions`; sealed per-space credential slot; handoffs ride DM durable-ACK v2 (ADR 0030)
- [ADR 0041: Cross-Machine State Sync — Tiered, Owner-to-Owner Only](./0041-cross-machine-state-sync-tiers.md) (accepted 2026-08-27) — Tier 1 replicates profiles/names/Home roster/sub-agent registry as owner-signed state-commits over ADR 0022 streams; Tier 2 Home history pulls owner-to-owner on demand; Tier 3 (other groups, DMs, exec) never replicates; **amends ADR 0023's cross-node backfill non-goal**
- [ADR 0042: Voice Media over Tailnet Streams (`WebRtcV1`)](./0042-voice-media-over-tailnet-streams.md) **[overlay: frozen, parked with R8, D19]** (accepted 2026-08-27) — ratifies `StreamProtocol::WebRtcV1 = 0x04` nesting (saorsa-webrtc `StreamType` 0x20–0x24, u32-BE framing) under the standard identity/ACL gates; Ephemeral DM signaling; audio to the unreliable datagram lane with reliable fallback; mesh ≤4, SFU/browser gateway deferred
- [ADR 0071: Relay Backbone — What Relays Today and What Is Deferred](./0071-relay-backbone-shipped-truth-and-deferred-work.md) (proposed 2026-09-25; accepted 2026-09-25) — **amends ADR 0020 and ADR 0035**; records shipped relaying (ant-quic MASQUE used via advertised bootstrap/`--relay`/proven-public nodes; Leaf desktops don't forward gossip; peer relay default-off) and freezes ADR 0035 steps 2–6 and ADR 0051 promotion until #807/#731 close with fleet evidence; #132 relayed-forward proof still owed
- [ADR 0072: Scope Freeze — Deferred and Legacy-Maintenance Mechanisms](./0072-scope-freeze-deferred-and-legacy-maintenance.md) (proposed 2026-09-25; accepted 2026-09-25) — **amends ADR 0010, 0037, 0038, 0043, 0063**; roaming/key-move deferred (ceremony off, ≥1-Roaming requirement suspended), GSS legacy-maintenance (still the plane for `public_request_secure`), ADR 0063 frozen at current gates, Home/fork-quarantine no new features; new ADRs must name the vision requirement (R1–R11) they serve
- [ADR 0043: Agent Key-Move Protocol](./0043-agent-key-move-protocol.md) **[overlay: retire, D27]** (proposed 2026-08-28, r5; accepted 2026-08-29) — **amends ADR 0037**; machines enroll ML-KEM-768 keys via a new topic-versioned machine announce (`x0x.machine.announce.v3`); roaming moves are a commit-then-activate ceremony over a predecessor-linked owner-signed per-agent log that folds **totally** to `custodian` / grow-only `retired_bindings` / `placement` — key possession is a gate input (`may_sign = holds_key ∧ custodian`), so partial application is impossible by construction and every crash re-entry is a log re-read; the `ActivationBundle` is self-contained (embedded authorization, cumulative tombstones, certificate) — participant verification is head-CAS, mesh verification is bundle signature + coherence + placement-epoch monotonicity with unconditional tombstone union (no historical revocation lost to out-of-order arrival); `AbortRecord` is its own signed rollback terminator; move tombstones ride bundles on `x0x.move.activation.v1` (historical fetch via blob-v2 `Bundle` kind), ad-hoc tombstones ride `x0x.revocation.v2`, and v1 batches stay byte-identical for old peers; enforcement per `(agent, machine)` pairing at every machine-context gate with equal-epoch placement coherence; mechanics in [docs/design/agent-key-move.md](../design/agent-key-move.md)
- [ADR 0061: Self-Update Must Resolve Restart Ownership Before Replacing Binaries](./0061-supervised-upgrade-restart-ownership.md) (proposed 2026-09-06; accepted 2026-09-09) — reject known supervisor/restart-setting conflicts before replacement; explicit platform policy and migration, separate readiness/recovery acceptance for #493/#415
- [ADR 0064: Owner-Anchored Fork Authority for Invite-Derived Seatings](./0064-owner-anchored-fork-authority.md) **[overlay: frozen; §3 to be superseded in part, D16/D34]** (accepted 2026-09-10) — owner mandate on MemberAdded for OwnerCertified groups, ancestor-walk alternate-chain validation with no automated eviction, persistent per-node quarantine, forensic fork snapshot; closes the ADR 0016 §7 equal-revision gap for #472/#468/#469
- [ADR 0066: Ordinary-Group Fork Anchors and Data-Plane Quarantine Coverage](./0066-ordinary-group-fork-anchors-and-data-plane-quarantine-coverage.md) **[overlay: frozen; §2 to be superseded in part, D16/D34]** (proposed 2026-09-18; accepted 2026-09-19) — completes the ADR 0064 §§2/3 residuals for #732/#472: a normative 26-path data-plane coverage map (12 gated today, 13 ungated, 1 deliberately ungated) with a `file:line` anchor and disposition per path. Ordinary (non-owner-axis) groups receive the persistent marker with `no_anchor: true` and a manual-clear-only exit — the census found `named_groups.rs:3733` returns early for them, so **0 of 26 paths are gated for that population** despite ADR 0064's text. Delegation grant/authorize/send-as, registry indexing, history purge and signed-public bootstrap publication fail closed; history, delegation and WebSocket reads are annotated, never refused; the lifecycle epoch becomes a compound `(state_revision, quarantine_generation)` token re-checked under the persist lock. §2 enumerates the three owner-anchored clear sites that must decline a `no_anchor` marker and the one retry-rollback arm (`named_groups.rs:3536`) that must NOT be gated. No automated eviction, no quorum anchor, no fleet propagation; #639 and #646 not absorbed. Ratified 2026-09-19 (R1–R5) after two rounds of cross-model review: no founder-key anchor, the `invite_lineage` fence widens, history ingest is tag-and-retain, the epoch token is compound — and, **overriding the ADR’s own recommendation**, refusals fail closed immediately with no warn-only window, on condition that every refusal carries an informational message naming the condition, the cause and the manual-clear remedy (§5, via `api_error_with_reason`). Implementation proceeds in eight slices; the §5 message contract is slice 1 and the ordinary-group marker plus the 26-row exhaustiveness fixture is slice 2 — cross-model review found the reverse order would ship permanent unexplained refusals, since a `no_anchor` marker never auto-clears
- [ADR 0067: The Lifecycle Epoch Token Is Derived Marker Identity, Not a Generation Counter](./0067-lifecycle-epoch-token-is-derived-marker-identity.md) **[overlay: frozen]** (accepted 2026-09-20) — supersedes **ADR 0066 §4 token composition and R4 only**; every other ADR 0066 section stands. Slice 7 implementation found ADR 0066 contradicting itself: §4 puts `quarantine_generation` "on the group entry" while R4 forbids "no new #470 full-equality participant", and `GroupInfo` derives `PartialEq` with that full equality deliberately load-bearing for the compare-and-restore rollback (`src/groups/mod.rs:~322`). A census also found three marker writers no process-local counter can reach — the on-disk recovery install (`named_groups.rs:24203`) and the two clears that bypass the persistence lock (`:3562` rollback, `:9633` metadata-apply) — so a counter's completeness rests on an enumeration whose failure mode is **fail-open**. The token therefore becomes `(state_revision, marker_identity)` with `marker_identity = Option<(revision, state_hash, committed_by, observed_at_ms, no_anchor)>` **derived on demand** from the live record: no counter, no new field, nothing that can go stale. Accepted weaknesses recorded: the token is an identity and not monotonic, and ABA is possible only if a byte-identical marker identity recurs while `state_revision` returns to its captured value. ADR 0066 §1 rows 1/2/4/6 (outbound send, TreeKEM encrypt, GSS encrypt, GSS reseal) are deferred to a later slice and held visible by an asserted-exact `PENDING_RECHECK` set so `OPEN_ROWS` can be empty without hiding the gap. Ratified by David Irvine, 2026-09-20, choosing Option C over A and B
- [ADR 0068: Fork Quarantine Pins History Retention and Buffers Inbound Task Deltas](./0068-quarantine-pinned-history-retention-and-buffered-task-deltas.md) **[overlay: frozen]** (accepted 2026-09-20) — **extends ADR 0066, edits nothing in it**: closes the two paths cross-model review found OUTSIDE the §1 census, i.e. runbook known gaps (b) and (c). **D1**: `src/history/reaper.rs` ran ADR 0023 §6 eviction against every scope unconditionally, so a quarantined group's forensic record could be destroyed by age or byte pressure — pressure a flooder can manufacture — which is the same deletion slice 4 refuses at the explicit purge (row 14). The reaper now excludes rows whose `group:<id>` scope has a live marker (both spellings, derived live from `named_groups` via `resolve_group_entry_locked`/`all_quarantine_markers`, no schema change — `SCHEMA_VERSION` stays 4), bounded by a per-group ceiling `min(4 × base, max_bytes/16)` with `base` = the configured per-scope limit or `max_bytes/64`; overshoot evicts oldest **within that group only** and counts `history_quarantine_pinned_evictions`. Worst-case disk `max_bytes × (1 + G/16)`, and `G` is groups this node JOINED and that are forked — attacker-inflatable rows are bounded by the ceiling, `G` is not attacker-inflatable. **D2**: inbound peer task-CRDT deltas applied ungated, so the local operator was refused (row 20) while a peer seated by the **disputed roster** kept moving the CRDT winner. Deltas for a quarantined group's list are now BUFFERED, not applied (1024 deltas / 1 MiB per list, oldest dropped + counter), the `TaskList` stays byte-identical **from the first delta that observes the marker** (the live admission path is deliberately unpinned, so at most one already-admitted delta per listener can still merge just after the marker installs — the accepted residual stated at `crdt/sync.rs::admit_or_buffer`), and the buffer applies in arrival order once the marker is gone — observed by the listener rather than hooked at each of the several clear sites, because an enumeration of clear writers fails open (ADR 0067's lesson). Buffer is process-local; a restart converges by anti-entropy. Group METADATA ingest (row 24) stays ungated so the clearing commit still arrives. Ratified by David Irvine, 2026-09-20 ("I accept the recommendations in 732"): D1 option A over a ceiling-free hard pin (disk DoS) and ops-only advice; D2 option A over drop, apply-and-annotate, and the status quo
- [ADR 0024: GSS Rotation on Admin Remove Is Fail-Closed and Seals Before It Persists](./0024-gss-rotation-on-admin-remove-fail-closed.md) **[overlay: to be superseded, D18]** (accepted 2026-09-25) — the legacy GSS plane (ADR 0010) rotates and reseals on admin remove as it already does on ban; every survivor envelope is built before `seal_commit`, persistence and publication, and any failure aborts the removal outright; records the accepted availability and map-lock contention costs, and the no-drop map-lock rule as conservative policy whose necessity is unproven
- [ADR 0044: The Daemon Exposes a Loopback REST + WebSocket + SSE Control Plane](./0044-daemon-local-rest-ws-sse-control-plane.md) (proposed 2026-08-29; accepted 2026-09-25) — loopback-first axum control plane, default `127.0.0.1:12700`; durable bearer + 10-minute session tokens (query tokens only on `/ws` and `/events`); three channel roles (REST/WS/SSE); in-process reuse via `serve()`
- [ADR 0045: Decentralized Self-Update with Signed Manifests and Transactional Restart](./0045-decentralized-self-update.md) **[overlay: to be superseded, D20]** (proposed 2026-08-29; accepted 2026-09-25) — ML-DSA-65-signed manifests over gossip topic `x0x/release` against a compiled-in key; atomic replace with backup rollback; health-gated transactional handoff restart; GitHub discovery as origin/fallback
- [ADR 0046: Exec Runs Only Exact-Argv Allowlisted Commands, Fail-Closed, Audited](./0046-exec-service-fail-closed-acl.md) (proposed 2026-08-29; accepted 2026-09-25) — exact `(AgentId, MachineId)` + argv-vector matching with typed token templates only; no shell; missing/malformed ACL disables; fsync'd JSONL audit (CRDT mirror is an explicit v1.1 waiver)
- [ADR 0047: The KV Store Is CRDT-Backed with Delta Gossip and a Context-Gated `Encrypted` Policy](./0047-crdt-kv-store-delta-gossip.md) (proposed 2026-08-29; accepted 2026-09-25) — OR-Set keys + LWW entries, `(PeerId, KvStoreDelta)` gossip deltas with `StateRequest` full-state recovery; `Encrypted` reserved fail-closed until secure sync ships; `SelfKeyed` 64-key/256-KiB deterministic quotas
- [ADR 0048: Task Lists Coordinate via Per-Entity CRDTs with Signed Provenance](./0048-crdt-task-list-coordination.md) (proposed 2026-08-29; accepted 2026-09-25) — OR-Set membership/checkbox + LWW metadata; ML-DSA-65 `OpAttestation` under `x0x.task.claim.v2`/`complete.v2` (absent/invalid fails closed); `/state-sync` cold start; encrypted variant exists but unwired
- [ADR 0049: Presence Runs on Signed Beacons over a Global Topic with FOAF Candidate Scoring](./0049-presence-foaf-discovery.md) (proposed 2026-08-29; accepted 2026-09-25) — machine-key-verified beacons on `x0x.presence.global`; adaptive offline timeout mean+3σ clamped 180–600 s; FOAF score `1/(1+stddev)` orders random-walk candidates
- [ADR 0050: Direct Messages Ride a KEM-Sealed, Signed, Replay-Protected Gossip Base](./0050-dm-over-gossip-base-transport.md) (proposed 2026-08-29; accepted 2026-09-25) — signed `DmEnvelope`, ML-KEM-768 + ChaCha20-Poly1305 payload sealing, bounded 10 k-entry/630 s replay cache, explicit `DmAckOutcome`, capability-driven gossip-vs-raw-QUIC path selection; the base ADRs 0021/0030 amend
- [ADR 0052: The GUI Is a Compile-Time-Embedded HTML Asset Served by the Daemon](./0052-embedded-gui-in-daemon-binary.md) (proposed 2026-08-29; accepted 2026-09-25) — single ~323 KB `include_str!` asset served under auth at `GET /gui`; `gui_coverage` binary enforces ≥95 % endpoint coverage with a 16-entry reviewed whitelist
- [ADR 0053: An API-Unserved Watchdog on a Dedicated Thread Aborts a Wedged Daemon](./0053-api-unserved-watchdog.md) (proposed 2026-08-29; accepted 2026-09-25) — std-thread `GET /health` probe (10 s interval / 3 s timeout / 3 misses / 90 s grace), one success resets; supervision-aware abort with synchronous thread-dump evidence; issue #384
- [ADR 0054: External Agent Signing Uses a Canonical Domain-Separated Context, Never Raw Payloads](./0054-external-agent-signing-dst.md) (proposed 2026-08-29; accepted 2026-09-25) — `0xF0 ‖ x0x.external-agent-sign.v1 ‖ len ‖ context ‖ payload` canonical buffer, validated context grammar, 64 KiB cap; ML-DSA-65 with the daemon-held key; stateless verify
- [ADR 0055: File Transfer Is a DM-Chunked, SHA-256-Verified Protocol with a 1 GiB Cap](./0055-dm-file-transfer-protocol.md) (proposed 2026-08-29; accepted 2026-09-25) — `FileOffer`/chunk/ack over the DM plane; 32 KiB chunks (base64 framing fits the 49,152-byte payload limit), window of 8; incremental SHA-256 with mismatch cleanup; receiver-approved
- [ADR 0057: Local Apps Reach the Daemon via REST/WS with Filesystem Discovery; `serve()` Is the Embedded Form](./0057-embedded-serve-library-local-apps.md) (proposed 2026-08-29; accepted 2026-09-25) — `api.port`/`api-token` discovery over the ADR-0044 plane; embedded `server::serve()` disables self-update and hands `ServerHandle` to the caller; `/apps` static hosting remains proposal-only
- [ADR 0058: The Constitution Is Embedded Compile-Time in Every Binary](./0058-compile-time-embedded-constitution.md) **[overlay: frozen]** (proposed 2026-08-29; accepted 2026-09-25) — `include_str!` constants in the shared library surfaced via `GET /constitution`, `GET /constitution/json`, and `x0x constitution`; status constant (currently Draft) is the stage of record
- [ADR 0059: Invite Authentication and Seating Provenance](./0059-invite-authentication-and-seating-provenance.md) **[overlay: frozen]** (proposed 2026-09-02; accepted 2026-09-25) — InviteV4 signs the whole invite minus signatures with inline id-bound inviter/owner keys; Home-join mode pins the admission owner; every invite-derived seat records local, bootstrap-stripped `invite_lineage` with deduplicated authenticated fork evidence (observability only, no eviction); amends ADR 0016 §7; the stale-base residual and old-admin-key caveat are deferred to #472
- [ADR 0060: The Owner's Home Is Elected, Not Per-Install](./0060-one-home-per-owner.md) **[overlay: to be superseded, D16; frozen]** (proposed 2026-09-05; accepted 2026-09-25) — the unit of Home is the OWNER, not the install (#449): auto-provisioning becomes optimistic and subject to election on the Tier-1 `("home")` register, publisher and resolver share one `!withdrawn` predicate, and `GET /home` reports `local`/`adoption_pending`/`elsewhere` instead of a bare 404. Amends ADR 0038 (unit of Home) ONLY — no Tier-1 surface change (ADR 0041 stays at four kinds) and no change to ADR 0039 Home eligibility. How a losing device JOINS the winner's Home, retirement of the duplicate, and any device-vs-rider eligibility rule are explicitly deferred: review of PR #507 showed the first implementation broke signed-record and protocol compatibility and had no trustworthy cross-device device/rider signal. #449 stays open.
- [ADR 0073: Audio and Video Calling Ship Together via the Daemon-Side Browser Gateway](./0073-audio-and-video-calling.md) **[overlay: parked, D19]** (proposed 2026-09-25; accepted 2026-09-25) — serves vision **R8**; extends ADR 0042 by making its (e) gateway the human media path: the GUI captures and encodes (Opus/VP8) and talks WebRTC to its own daemon over loopback only; daemons relay RTP/RTCP over `WebRtcV1` lanes with no transcoding and need no TURN/ICE across the WAN; native daemon capture/encode (Option B) rejected; voice enabled in release builds with `/calls` REST, `call.*` events, `x0x call` CLI (lifecycle only) and GUI call UI; call invites ring only past the existing stream/connect-ACL gates, with a `Call` cap proposed for ADR 0070 `ShareGrant`; 1:1 only, group mesh 0042 (d) deferred; defines the `calling-r8-e2e` cross-NAT acceptance test (#892)
- [ADR 0075: Collaborative Notes and Agent Scratchpads](./0075-collaborative-notes-and-agent-scratchpads.md) **[overlay: notes half parked, scratchpad half core, D19]** (proposed 2026-09-25; accepted 2026-09-25) — R9 (+R6, R10): notes are a `yrs` text CRDT stored as write-once, author-bound update records in the sealed group `notes` store, with a daemon-side three-way merge for plain-text clients; the Wiki migrates to notes via a digest-keyed, retry-safe import, and after migration upgraded nodes refuse legacy Wiki writes with 409 `wiki_migrated_to_notes` (Q7, 2026-09-26); a `scratch` group store becomes rider-reachable under a new per-group `scratch` scope (the only ADR-0039 allow-list widening); GUI deep links for #893.
- [ADR 0074: Tailnet Phase 2 — Names, Persistent Forwards, SOCKS5 and Open-Stream Revocation](./0074-tailnet-phase-2-names-persistent-forwards-socks5.md) (proposed 2026-09-25; accepted 2026-09-25, decisions Q1–Q6) — serves vision **R4** (with R3/R5/R7); extends ADR 0020/0022 and builds on ADR 0070: `<agent>.<owner>` and machine names (`agent:`/`machine:` prefix on collision) resolved locally via certificate chain + local owner petname (fail loud on unknown/ambiguous), forwards persisted by default (`--ephemeral` opts out) in `forwards.json` with pinned `AgentId`+`MachineId` (stream refused if `peer()` ≠ pinned machine), off-until-configured loopback-only SOCKS5 `CONNECT` front-end authenticated by RFC 1929 password = daemon API token (Q7, 2026-09-26) emitting ordinary `ForwardV2` streams, port ranges on own machines only (`SocksV1` stays reserved), open streams torn down ≤5 s after revocation / ≤35 s after grant expiry, machine sharing via `ShareGrant` `Connect{ports}`; TUN/MagicDNS/subnet routers/exit nodes still deferred; CI `tailnet` job + #132 relayed proof first, `tailnet-r4-e2e` cross-NAT acceptance
- [ADR 0070: Owner Trust and Share Grants](./0070-owner-trust-and-share-grants.md) **[overlay: held, D28; §1 and §2 to be superseded in part, D17/D24]** (proposed 2026-09-25; accepted 2026-09-25) — **extends ADR 0019/0046/0018, edits nothing in them**; addresses vision R3/R5/R7: agents+machines certified/enrolled by the same owner `UserId` are implicitly trusted at trust evaluation and the stream gate, and matchable by a `principal = "owner"` connect/exec ACL selector; an owner-signed, expiring `ShareGrant` exposes a subset of agents with caps (`Dm`/`Exec`/`Connect{ports}`/`GroupInvite`) to another human, revoked via a new `RevokedSubject::ShareGrant`; ACLs gain REST/CLI edit + hot reload over the TOML floor. Home (ADR 0038) unaffected; no re-sharing
- [ADR 0077: Share-Grant Redelivery Is an Owner-Side Durable Outbox; Grantee Fetch Deferred](./0077-share-grant-owner-side-redelivery-outbox.md) **[overlay: held, D28]** (proposed 2026-09-26; accepted 2026-09-27) — serves **R5**; records the owner-side outbox (#926, PR #983) as the ADR-0070 §2 mechanism for missed grant deliveries and defers the grantee-attached fetch; would supersede that one §2 sentence if accepted, ADR-0070 itself unedited
- [ADR 0079: Grant-Carried Owner and Machine Names as ADR-0074 §1 Name Defaults](./0079-grant-carried-owner-and-machine-names.md) **[overlay: held, D28]** (proposed 2026-09-27; accepted 2026-09-27) — serves **R4**/**R5**; makes the ADR-0074 §1 defaults computable, grant-only: a new `x0x-sharegrant-v2` typed DM carries the unchanged v1 grant plus an owner-key-signed names section (`owner_name`, machine names of hosts of granted agents), sent only to grantees advertising a `share_grant_names` capability (v1 otherwise; `--no-names` opts out); no network-wide announcement (`X0U3` rejected 2026-09-27); defaults only — pinned at first bind, conflicts reported not applied, strangers' grants yield suggestions; would supersede the ADR-0074 §1 default wording if accepted, ADR-0074 itself unedited
- [ADR 0081: Notes Use the loro Text CRDT (Supersedes the ADR-0075 CRDT Choice)](./0081-notes-use-loro-crdt.md) **[overlay: parked, D19]** (proposed 2026-09-27; accepted 2026-09-27) — serves **R9** (+R6, R10); would supersede ADR 0075 in part if accepted, ADR 0075 itself unedited. Notes use `loro =1.16.2` (loro crates exact-pinned, upgrade in isolated PRs), chosen by David Irvine over the spike's yrs-with-gate recommendation because it converges with no delivery gate. Also: binary ceiling 4.5 MiB (measured +3.57 MiB); every loro import runs in `spawn_blocking` + `catch_unwind` with poisoned docs quarantined, never dropped, and rebuilt from records (loro #1118/#1068/#793); fresh CSPRNG peer id per doc session, never reused; per-record ML-DSA-65 author signatures inside the sealed value, one record per save; `notes` store budget 12 MiB of the 16 MiB retained image (413 `notes_store_full`); `version` = loro `Frontiers`. ADR-0075 Q2–Q7 carry over unchanged.
- [ADR 0082: Note Records Are Accepted Under the Roster Epoch They Were Written At](./0082-notes-epoch-bound-writer-rule.md) **[overlay: parked, D19]** (proposed 2026-09-27; accepted 2026-09-27) — serves **R9**; would amend ADR 0081's "current writer" rule if accepted, ADR 0081 itself unedited. Each note record signs the `(state_revision, state_hash)` of the ADR-0016 state-commit chain it was written under (`NoteUpdateRecordV2`); a replica accepts it if the author was `Active` in the retained roster at that exact epoch (`GroupInfo.commit_log`, #111), holds future/unknown/forked epochs until known, and refuses provable non-writers — so a removed member's earlier history is kept and replicas converge. Backdating by a removed member is bounded, not prevented: causal epoch monotonicity refuses any record that depends on ops from a later epoch, and a removed member needs a current writer to relay its record; store-carried roster evidence for late joiners and per-commit policy retention are follow-ups. Needs David's acceptance.
- [ADR 0083: Agents Show Their Owner a GUI View, Locally or on the Owner's Active Machine](./0083-agent-initiated-gui-show.md) **[overlay: held after slice 1, D28]** (proposed 2026-09-27; accepted 2026-09-28) — serves **R10** (#893 items 2–3); extends ADR 0039/0044/0052/0070, edits nothing in them. `POST /gui/show {view, target_machine}` + `x0x show`: the target validates the route against a Rust grammar mirroring the GUI deep-link allow-list, then navigates a visible GUI in place or opens its OWN loopback GUI with a fresh session — never a URL, host or token from the wire, and the response never carries a token. Remote shows are an `x0x-gui-show-v1` typed DM accepted only from ADR 0070 owner-trusted senders (sharees never); riders need the new `gui:show` scope (default none); "active machine" = most recent visible-GUI activity within 15 min; origin banner, per-agent rate limit and block list, `[gui_show] local_enabled`/`remote_enabled` (proposed defaults local on / remote on, per David 2026-09-28). Needs David's acceptance.
- [ADR 0084: Admit Owner Sync from Enrolled Machines on Verified Enrollment Alone](./0084-enrolled-owner-sync-admission.md) (proposed 2026-09-28, retroactive; accepted 2026-09-28) — #1040/#1044: amends ADR-0041; an enrolled, unrevoked machine with no known agent may open `SyncV1` only, to the owner-sync acceptor, skipping the agent gate and connect ACL; accepted under D06 (#1044 kept); SyncV1-acceptor revocation re-check required before the v0.46.0 rc
- [ADR 0085: Persisted Binary Formats Are Versioned, Read Every Released Layout, and Fail Closed on Downgrade](./0085-persisted-binary-formats-are-versioned.md) (proposed 2026-09-28; accepted 2026-09-28) — #1046/D01: KV snapshots `X0XKVS1`→`X0XKVS2`; frozen decoders for released layouts; fixtures from the released encoder; downgrade leaves files intact but unreadable
- [ADR 0086: Gossip Send Targets Are Bounded by Transport Connectivity](./0086-gossip-send-targets-bounded-by-transport-connectivity.md) (proposed 2026-09-28; accepted 2026-09-28) — serves **R4** (+R3); #1036 syslog flood; amends ADR 0049, ADR 0049 itself unedited. HyParView active-view peers absent from `send_ready_peers()` for 60 s are pruned (`remove_active`) on the 15 s keepalive pass and restored on reconnect; presence beacon/FOAF targets are connected peers only; plane-pending and closing-tombstoned peers count as connected (transport, not admission); PlumTree planes untouched; tracker capped at 4,096 peers. Depends on ant-quic `=0.27.54` bounded `Peer not found` logging (DEBUG, one line per peer per 60 s, aggregate overflow past 4,096). The rsyslog filter, logrotate cap and `RUST_LOG` drop-ins stay in place. Needs David's acceptance.
- [ADR 0069: Home Auto-Provisioning Waits for Owner Sync](./0069-home-wait-for-sync-before-auto-provisioning.md) **[overlay: record; to be superseded, D11]** (proposed 2026-09-24; accepted 2026-09-29 as a record of shipped behaviour, to be superseded by ADR 0088 — D11) — **amends ADR 0038 by reference** and refines ADR 0060 (#824, PR #826, shipped via #802). An owned device with owner sync and no known canonical `("home")` pointer defers creating a Home; `GET /home` reports `provisioning_pending`; only the rank-0 device is released by a successful session, others fall back after `(rank + 1) × 90 s`; creation is linearised by `quiesce_sessions` + `canonical_home_gate`; `POST /home/seat` returns 409 `ambiguous_home`. #863 (PR #884) closed the empty-session residual by publishing the local pointer before every session; #1040 (PR #1044, ADR 0084) lets a restarted device reach its enrolled owner machines without waiting for gossip.
- [ADR 0093: Capability Advertisement Registry](./0093-capability-advert-registry.md) (proposed 2026-09-29; accepted 2026-09-29 — D08, v0.46.0 must-land) — R5/R6/R11; signed compatibility bits (`share_grant_v1`, `predecessor_offer_v1`) in DmCapabilities; a peer whose current verified advert **lacks** a bit gets ShareGrant/predecessor-offer sends held as `recipient_upgrade_required` (no 0.45 false ACK); unknown/expired/card-only capabilities send as before; gate row 4b (#1064).
- [ADR 0087: Repository and Release Governance](./0087-repository-and-release-governance.md) (proposed 2026-09-30; accepted 2026-09-30) — D04/D05/D15/D36 and the ADR-before-code rule; amends ADR 0025's merge-gate enforcement. CI on every PR base; a `main` ruleset with five required checks and no bypass; admin-only `v*` tags; no bot identity, so identity-keyed gates are procedural; build/sign/create/publish and SKILL.md signing in the protected `release` environment (David as required reviewer, `v*` only); the tracked `Cargo.lock` consumed by `release.yml` and prerelease tags refused; a Proposed ADR on main before any merge of ADR-governed code, plus an Accepted ADR before wire, protocol and dependency changes merge to main, with `Accepted (record)` for retroactive records; review findings on merged PRs become an issue or written dismissal within 24 h
- [ADR 0089: Relationship-Peer Evidence Survives Restart (Evidence Rule, Slice 1)](./0089-relationship-peer-evidence-survives-restart.md) (accepted 2026-09-30; charter D29, pulled into v0.46) — persists mutual signed evidence (machine-signed V3 announcement + agent-signed DM advert with KEM key + optional cert) for relationship peers only (enrolled devices, grant parties, group members; contacts excluded); per-component freshness W = 15 min ingest, L = 7 days stored authority re-validated by any fresh Hello; persisted move watermark, moves durable before use; consulted at the point of use via `usable()` (never seeded); `EvidenceV1 = 0x06` Hello (own evidence) + responder-authorized, budgeted, ingest-fresh `Lookup`; ADR 0093 bit 2 `peer_evidence_v1` (canonical table below); `peer-evidence.bin` `X0PEV1` (≤ 16 MiB, never overwrites an unreadable file); amends ADR 0021 option 2 for relationship peers and ADR 0093's allocation procedure; replaces the #1092 stopgap
- [ADR 0106: Join Results Carry the Intervening Membership Events](./0106-join-result-carries-intervening-membership-events.md) (accepted 2026-10-01; a slice of [ADR 0088](./0088-group-liveness-contract.md) (Accepted), D16 hole (a); #1139, v0.46 Home-freeze exception) — R3. `JoinResultMessage::Result` gains serde-default `intervening_events`: the authority's own logged `MemberAdded` events strictly between the fetcher's `from_revision` and the carried commit. They are sent only to a blob-capable, bound fetch, and only when they cover the whole gap, at most 8. The joiner requires a bound attempt, preflights the whole list before any mutation, and applies it in order through the ordinary bound apply (currency re-checked under the membership lock) before its own event. A later refusal keeps the accepted prefix. No new acceptance rule, TreeKEM adoption exclusion kept; either side on 0.45 is today's behaviour. ADR 0087 rule 8: Accepted before the code (PR #1140) merges to `main`.
- [ADR 0062: Recover Ordinary Home Persistence as One Durable Pair](./0062-home-persistence-pair-recovery.md) (proposed 2026-09-06; accepted 2026-10-03 as a record of Considered Option 1, shipped by PR #617 — D54; its recommended option 2 is not accepted) — #471: the in-process restore of the ordinary Home pair that PR #617 shipped. On a failed paired save it restores in process; a failed restoration is only logged, and the saver returns the original error or `NotReplaced`. A distinct recovery-required result is NOT part of the accepted record (see Errata). Recorded by [ADR 0088](./0088-group-liveness-contract.md) (group liveness, Proposed).

## Accepted (Phase 1 Functionally Complete)

- [ADR 0001: Bootstrap Peers Are Seed Hints Only](./0001-bootstrap-peers-are-seed-hints-only.md) — functional Phase 1 complete, nomenclature rename deferred

## Superseded

- [ADR 0005: mDNS Local Network Discovery](./0005-mdns-local-network-discovery.md) — superseded; LAN discovery now lives in ant-quic
- [ADR 0056: Voice Link Transport and Signaling (Historical Record)](./0056-voice-link-transport-and-signaling.md) (proposed 2026-08-29; superseded by ADR 0042 2026-09-25) — records the pre-0042 shipped design: WebRtcV1 lane framing with `u32`-BE records, no voice-specific gate bypass, negotiated datagram lane with reliable fallback, `x0x-voice-sig-v1` DM signaling; media nesting ratified by ADR-0042
- [ADR 0065: Duplicate Homes Are Inventoried, Not Retired](./0065-duplicate-home-inventory-retirement-deferred.md) (proposed 2026-09-06; superseded by ADR 0060 2026-09-25) — interim position for #449 P4: duplicate Homes left by the ADR-0060 election are reported read-only via `GET /home` `duplicates[]` with `evidence_against_deletion[]`, and **nothing is deleted automatically**. An earlier provable-emptiness gate was withdrawn after independent review found the proof unsound — the startup pass ran before the CRDT manifest loaded, the proof was neither held nor revalidated through the terminal withdrawal, and the manifest/rider loaders map read failure to empty. Evidence probes now fail closed; `safe_to_retire` is deliberately not reported. Conditions for a safe fence: `docs/design/449-p4-retirement-fence.md`

## Proposed
- [ADR 0051: Peer Relay (X0X-0070) Is a Default-Off, One-Hop DM Fallback](./0051-application-level-peer-relay.md) **[overlay: rejected in practice, D27]** (proposed 2026-08-29) — signed `RelayHeader` routing (version/dst/src/pubkey/timestamp — no inner-envelope digest, substitution tracked as #437), inner `DmEnvelope` sealed end-to-end, one hop; policy default disabled, contact-required, rate/byte caps; first-eligible selection pending ADR-0035's spread model
- [ADR 0107: Stuck Join Re-arm and Current-Roster Serving Guard (0088 S8 (a))](./0107-stuck-join-rearm-and-serving-guard.md) (accepted 2026-10-03, D57; #1150, #1149; amended by ADR 0108 §8, "pre-admission signed replies", D145/D178) — carry-remnant re-arm skips #1148's clear and the base-seat shortcut only when the invite base seats the joiner; current-roster guards using roster-embedded certificates for OwnerCertified result/Welcome serving and purge on removal/ban/revocation; original-sealer/inviter and 10-minute volatile-cache limits, no-carry out of scope, owner remove-member + re-invite exit. Proposed on main, then Accepted before S8 (a) code merges; D55 committed in-process red test exception, W3-H follows. Authority re-Welcome is future work in a separate ADR filed after S4 is Accepted.
- [ADR 0088: Group Liveness Contract (I8)](./0088-group-liveness-contract.md) (accepted 2026-10-03, D58; W3-0, D16/D34/D37; G7 ruled 2026-10-04, D64: L3 binds every slice, so every block a slice adds or touches ends in a typed refusal or a typed wait) — **group liveness (0088)**, not the transport liveness ADR 0104 (prov.). The short contract ADR (D37): admission and eviction complete with any one active admin online, catch-up and repair with any one holder online (L1); only an enumerated may-block-forever list may block without bound (L2); under L3 (binding status pending G7), a definitive listed block ends in a typed terminal refusal, and a waiting one (no admin or holder online, an unanchored fork) stays a visible, typed, retryable wait; no safety rule is traded (L4). It holds the supersession table: 0038, 0060 and 0069 are superseded, and 0064 Decision §3 and 0066 §2 are superseded in part, each when its slice is Accepted; 0062 is decided by D54 (Accepted (record) of option 1, no S7 dependency); 0016 §6, 0007 consent, 0059 and 0064 §1a are amended by slices. It lists slices S1–S8 (S1 = ADR 0106, Accepted). Ruled 2026-10-03 (D54, D55): the list has 8 entries; catch-up is fetch-by-hash from any holder (S5), not a persisted log; the W3-H harness reproduces first, with the one exception S8 (a) for #1150 (D55); 0062 is Accepted (record) of option 1; per-case cert-carry patches stop. Still open: whether L3 binds every slice (G7).
- [ADR 0095: Scope — x0x Is Glue Between People, Their Machines and Their Agents](./0095-scope-x0x-is-glue.md) (accepted 2026-10-03, D58; D19, after promotion) — all goals. x0x is the glue between people, their machines and their agents, and does not provide agents; the primary user is an AI agent acting for one owner with 2–5 machines. **Supersedes ADR 0017 in part (positioning text only)**: the interop posture (serve a signed card, stay beneath MCP/A2A) and 0017's three workstreams stay, the Internet-Draft commitment included until David rules. Core: identity, reach, sharing of agents and whole teams, coordination, shared places (scratch store, boards, project data), R10, R11, self-maintenance (R12) and efficiency (goal E, with the E-D15 checklist on every PR and ADR). **Parks** R8 media calling (ADR 0042, 0073, #892; `/calls` signalling stays experimental, no media, release builds without `voice`) and the R9 rich-text notes merge path (ADR 0075 notes half, 0081, 0082, #965, #1029, PR #1035). The ADR 0075 scratchpad half stays core (ADR 0103, prov.). ADR 0072 is unchanged: its freezes, rule 5 (R1–R12 once ADR 0096 adds R12; correctness and security fix exception as written) and rule 6 stand. Open questions for David: scope tiers, lifting a park, goal E under rule 5, parked-requirement ADRs and a placement rule
- [ADR 0096: R12 — x0x Is Maintained by Its Own Agents](./0096-r12-x0x-is-maintained-by-its-own-agents.md) (accepted 2026-10-03, D58; D20, after promotion) — goal M. **Extends ADR 0072 with R12**: the owner's agents keep each of the owner's nodes healthy and upgraded under owner policy, with no human SSH for routine maintenance. Rule 5 accepts R1–R12; nothing else in ADR 0072 changes. The owner sets policy and approves authority changes; agents act within it; deployed maintenance agents gain no release-signing authority (protected release operations stay under David's authorization per ADR 0087, D05 and D47; custody is decided before M4); the daemon keeps apply safety alone (M2). Every maintenance action is a JSON API with a typed error and an event; x0x ships the surface, not an agent. **Gates M3–M6** (recall, owner policy and canary, problem reports, install and upgrade help) and ADR 0097 (prov., supersedes ADR 0045); rings and canary belong to M4/0097. M1/M2 (Track M-safety, ADR 0094 prov.) are correctness and security fixes within ADR 0094's safety scope and do not need R12
- [ADR 0094: M2 safe apply with supervised self-rollback](./0094-m2-safe-apply.md) (accepted 2026-10-03, D58; open questions ruled 2026-10-05, D182–D195) — Track M-safety, goal M; signed channel, exec probe, boot counter and stable supervisor-owned recovery; staged host transaction and daemon/CLI rollback; supersedes ADR 0061 Decision §6 upon acceptance
- [ADR 0080: A Grant Revocation Is Also Pushed as One Signed Record to Capable Recipients; Gossip Remains the Backstop](./0080-grant-revocation-direct-push.md) (proposed 2026-09-27; revised 2026-10-04 under D63) — goal A, **R5**, I7/I9; #1003. Extends ADR 0077 (unedited). After `DELETE /grants/:id` is durable, the owner pushes the ONE signed `ShareGrant` revocation record (`x0x-grant-revocation-push-v1\0` ‖ bincode record, ≤ 8 KiB) to each recipient of that grant whose current verified advert sets the ADR 0093 bit `grant_revocation_push_v1` (number allocated at acceptance, in acceptance order); unknown capability waits at most one advert period (D35), then skips. No ACK, ≤ 3 send attempts on a local error, no new durable state. The prefix is owned unconditionally (verified frames before inbox readiness included). Receivers dedupe on record hash, then verify once in the shared v3 ingest, which merges the latest horizon. A shared store-failure latch stops every v3 writer replacing an undecodable file (#1116); persists are coalesced and bounded. Gossip v3 stays the backstop. Consistent with ADR 0098 (prov., D23); open questions for David on lost device, renewal, holds, `deliver_to` and the D28 hold. Related #1108, #1111, #1116
- [ADR 0111: Evidence Size K and Fetch-by-Hash from Any Holder (0088 S5)](./0111-evidence-size-k-and-fetch-by-hash.md) (proposed 2026-10-04; slice S5 of 0088) — R3, shared places; the single carry rule (D54, G6): live `MemberAdded`/`JoinResult` carry at most K = 4 certificates inline (proposed) in ordinary groups, while in Home groups certificates leave a node only by S5 fetch or S2's direct Put, never on gossip (D38); certificates, missed commit events (catch-up as control blobs, with authenticated head discovery) and root-covered roster projections are fetched by hash from any current member holder through a single-exchange, freshly admitted direct send under the ADR 0107/D60 serving guard, behind a new ADR 0093 bit `group_object_fetch_v1` (number allocated at acceptance); one acceptance rule changes, stated under L4: a fetched event's authorship is proven by an author signature over an RFC 8785 JCS digest (`author_evidence`) instead of the transport sender; a per-member event store written before the roster commit and reconciled on restart (`X0GHE1`, ADR 0085), not an authority log; evidence waits stay retryable (§2 item 8); #946, #818 and legacy sidecars stay for old peers. Accepted after S2, S4 and S3 and after David rules Q5 (retention exhaustion); harness red cases first. Open: K, KV history (#811), pre-member roster fetch (#646), #946 retirement, retention exhaustion, operational values, "S8" in the acceptance order, the subject's certificate on Home gossip
- [ADR 0113: Home Is an Explicit Owner Group, Adopted in Place (0088 S7)](./0113-home-is-an-explicit-owner-group-adopted-in-place.md) (proposed 2026-10-04; slice S7 of 0088) — R3, D16, D42. Auto-provisioning and election stop; each device persists a versioned `home-binding.json` that adopts the canonical Home in place (same group, roster and data), and the register stays published for old peers but never moves a bound device; `POST /home` creates a Home explicitly and seats mint only into the bound Home (#824 residual). All binding writers share one gate, with durable intents for crash recovery; an unreadable binding blocks every writer. Once S4, ADR 0107's serving guard and D60's delivery checks have all shipped, seals stop re-checking seats this node has already verified since load (wholesale installs and policy opt-ins still get the full verdict; a known-revoked seat still blocks until S4 evicts), which removes #1023's structure. No wire change and no 0093 bit; supersedes ADR 0060, ADR 0069 and ADR 0038 in part upon acceptance
- [ADR 0108: Home-Scoped Owner Certificate and Seal Verdict (0088 S2)](./0108-home-scoped-owner-certificate.md) (accepted 2026-10-05, D178; slice S2 of 0088) — R3 and shared places: direct Home-member-only owner-certificate disclosure on capability-gated EvidenceV1; anonymous public announces cannot invalidate scoped evidence, seal checks remain until S7; amends 0038 and 0007 upon acceptance, with versioned scoped storage and W3-H-first validation.
- [ADR 0110: Revocation Eviction, Designated First](./0110-revocation-eviction-designated-first.md) (proposed 2026-10-04; slice S4 of 0088) — durable revocation and self-leave exclusion in a separate sidecar; designated-first hand-off and staggered fallback, with tail-latency bounds open for acceptance; amends 0016 §6 and supersedes 0038's evict-at-next-seal rule in part upon acceptance.
- [ADR 0112: Any-Admin Invite Redemption (0088 S6)](./0112-any-admin-invite-redemption.md) (proposed 2026-10-04; slice S6 of 0088) — portable signed invites, delegated owner authorization and committed consumption permit redemption by a current active admin while the inviter is offline; capability-gated wire and versioned persistence, with partition single-use and legacy-group migration policy open.
- [ADR 0109: Ownerless Attestation: Stale-Base Self-Recovery and Manual Re-seat (0088 S3)](./0109-ownerless-attestation-self-recovery.md) (proposed 2026-10-04; slice S3 of 0088; D34(1), D41; #818 part 2, #871) — R3. An active admin's signed terminal attestation, naming one node, lets a stale-base node catch up link by link under the #846 gate and retire its own marker; the gap record retires only at its exact terminal; a forked node is re-seated only by an admin's manual authorisation, journalled and contained until the replacement holds keys; state lives in its own versioned sidecar (`group-recovery/*.grecov`), legacy JSON unchanged; capability `group_terminal_attest_v1` (number allocated at acceptance); supersedes in part ADR 0064 Decision §3 and ADR 0066 §2 upon acceptance
- [ADR 0114: Authority Re-Welcome for Unconfirmed Join Rows](./0114-authority-re-welcome.md) (proposed 2026-10-04; slice S8 (b) of 0088) — R3 and shared places; current-authority confirmation, inert unconfirmed entries in both legacy stores, staged delivery through the designated admin, and chain-carried atomic repair with a bound mandate; acceptance follows S4, preserving ADR 0107/D60 serving guards and W3-H harness-first gates for #1150, #1149, #1146 and #1191.
- [ADR 0115: Identity Discovery Authority Comes Only From Agent-Authenticated Evidence](./0115-identity-discovery-authority.md) (accepted 2026-10-07, D212–D215; advisory GHSA-rr9m-cvx5-pmv9; fix shipped in v0.46.5, ADR and tests landed after the advisory (D218)) — I3, I7, I9. Only an agent-authenticated announcement, or one from the agent's authenticated machine, may set a discovery entry's machine, certificate, digest, user, name or agent key; every other valid announcement changes no authority field. Security readers use authority stores, not the routing `machine_id`. Revocation certificates need authenticated provenance, ADR 0043 bundles need the subject's authenticated owner, and `revoked_at` gets a future bound. No wire change; amends ADR 0043 Decisions 2 and 4. D214 quarantines pre-upgrade issuer revocations and bundle tombstones until authenticated evidence confirms the issuer (7-day lapse).

- [ADR 0116: Local History Retention by Class and Topic](./0116-local-history-retention-policy.md) (accepted 2026-10-09, D228–D229; #1264 part 2) — local class and longest-prefix retention limits, receiver-local Ephemeral for ordinary DMs and opted-in topics, and a bounded bearer-authenticated runtime trim API; defaults, ADR 0068 pins and ADR 0030 receipts stay protected. No wire or schema change; downgrade loses new policy enforcement. Amends ADR 0023. D229: an explicit matching opt-in limit may expire Replaceable history.


**ADR 0093 capability registry** (the canonical allocation table since ADR 0089, accepted 2026-09-30, amended 0093's allocation procedure; ADR 0093 itself is immutable):

| Bit | Name | Meaning | Allocated by |
| --- | --- | --- | --- |
| 0 | `share_grant_v1` | Understands and validates the ShareGrant v1 typed DM | ADR 0093 |
| 1 | `predecessor_offer_v1` | Understands the predecessor/requester offer route and its application handling | ADR 0093 |
| 2 | `peer_evidence_v1` | Accepts `EvidenceV1` (stream protocol 0x06) evidence Hello/Lookup streams | ADR 0089 (accepted 2026-09-30; advertised since the S5 slice) |
| 3–63 | unallocated | Must not be advertised until allocated | — |

## Rejected

- [ADR 0063: Signed KV legacy gossip compatibility adoption boundary](./0063-signed-kv-legacy-gossip-compatibility-adoption-boundary.md) (draft 2026-09-06; rejected 2026-10-03 — D27 "withdraw", mapped to Rejected by D54) — V3 pairing preparation only; do not build on it. The V3 publish preparation is removed as dead code.

## Errata (Accepted ADRs are immutable; corrections recorded here)

- **ADR 0062** (accepted 2026-10-03 as a record, D54): the accepted record is the in-process restore that PR #617 shipped. Considered Option 1 also describes "a distinct recovery-required result"; #617 did not ship that, so it is **not** part of the accepted record. A failed restoration is only logged, and the saver returns the original error or `NotReplaced`.

Documentation-audit corrections, 2026-07-19. The ADR files themselves are
unchanged per the immutability policy; the decisions stand — these entries
correct stale facts and pointers:

- **ADR 0004** — the Decision text says `max_concurrent_uni_streams: 50,000`;
  the shipped value is **4,096** (`src/network.rs:1581`, deliberately reduced
  during the ant-quic#210 memory investigation: ~130 KB vs ~1.6 MB per
  connection). `data_channel_capacity: 50,000` is correct as written.
- **ADR 0012** — the status paragraph's "see ADR-0011 scope note" should read
  **ADR-0010** (GSS plane); the `src/bin/x0xd.rs` line references predate the
  routes extraction — that logic now lives in
  `src/server/routes/named_groups.rs`; the "0.21.0 known limitation"
  (joiner's `MemberAdded`+`Welcome` not delivered) is **resolved** and covered
  by `tests/e2e_treekem_membership.py`.
- **ADR 0014** — `leave_treekem_group` no longer lives in `src/bin/x0xd.rs`;
  it is in `src/server/routes/named_groups.rs` (apply-side auth:
  `self_leave_auth`, same file).
- **ADR 0017** — the Related link `./0011-multi-port-bootstrap.md` should be
  `./0011-bootstrap-dual-listen-udp-443.md`.
- **ADR 0040** — v1 ships **without** the signed task-ownership transfer
  the ADR describes (decision bullet 2); every equivocation-resolution
  scheme tried in review proved grindable. Deferred pending a
  non-grindable scheme — see
  [`docs/design/adr-0040-mechanics.md`](../design/adr-0040-mechanics.md).

Vision-alignment corrections, 2026-09-25. These were recorded at David
Irvine's direction ("errata + short superseding ADRs"). The ADR files stay
unchanged:

- **ADR 0004**: this corrects the 2026-07-19 entry above. The shipped
  `max_concurrent_uni_streams` is now **256** (`src/network.rs:1873`), not
  4,096.
- **ADR 0020**: the note that the `src/api/mod.rs` endpoint registry is not
  extended is out of date. The registry carries `/forwards` and
  `/forwards/:local_addr` (`src/api/mod.rs:1706-1722`).
- **ADR 0064**: it builds on ADR 0059, which was still Proposed when 0064 was
  accepted. That is resolved: ADR 0059 was Accepted on 2026-09-25.
- **ADR 0048**: decision item 4 says "encrypted variant exists but
  unwired". Once #914 (#895) lands, group-scoped task-list deltas and
  `/state-sync` payloads are sealed with the group's current key, using the
  same GSS/TreeKEM envelopes as group KV stores. Plaintext deltas for an
  encrypted group list are rejected and counted. Group task lists follow the
  group's write policy (David Irvine, 2026-09-25). The unwired
  `EncryptedTaskListDelta` type is not used.
- **ADR 0022** (2026-09-26): the validation bullet for
  `connect_acl_refuses_unlisted_peer_stream` says a refused stream's I/O fails
  with "EOF + STOP_SENDING". What actually happens is that the gate drops the
  stream halves (`src/lib.rs` accept loop), so ant-quic resets the stream
  (`0xA17C0244`). The opener's read fails with **reset code `0xA17C0244`
  and zero application bytes**, not a clean EOF; its writes fail once the
  peer's STOP_SENDING arrives. This matches ADR 0020's "refused/reset with zero
  application bytes" and ADR 0022's own decision text; only the validation
  wording was wrong. Found during the #936 tailnet CI work.
- **Design contradictions.** Three contradictions are not fixed here, because
  each needs a new decision rather than an erratum:
  - ADR 0020 and ADR 0035 describe the relay story differently.
  - ADRs 0037, 0038 and 0043 describe agent roaming, and roaming is disabled
    in code.
  - ADR 0010 calls GSS superseded, yet it is still a first-class plane.

  Short superseding ADRs are proposed alongside this PR.

Audit-trim relocations, 2026-08-29. Per the 2026-08-23 ADR audit, the
mutable mechanics named below were relocated **verbatim** from the
immutable ADR bodies into maintained design-doc homes (new
`docs/design/adr-NNNN-mechanics.md` files, or `## Extracted from ADR-NNNN`
appendices in the already-governed chapters the audit named). The ADR
bodies are byte-identical to their accepted snapshots — this README is
the only place the relocations are recorded (the governance gate rejects
any added body line in an Accepted ADR, so no in-file pointers):

- **ADR 0001** — Phases 2–5 roadmap and acceptance criteria → `docs/design/adr-0001-mechanics.md`
- **ADR 0002** — keepalive rationale essays, alternatives, NAT-test evidence → `docs/design/adr-0002-mechanics.md`
- **ADR 0003** — "Why This Approach" narrative and trade-offs → `docs/design/adr-0003-mechanics.md`
- **ADR 0004** — limit-sizing arithmetic and alternatives → `docs/design/adr-0004-mechanics.md`
- **ADR 0006** — practical-effects narrative, follow-up work, acceptance criteria → `docs/design/adr-0006-mechanics.md`
- **ADR 0007** — Operational Rules file layout and acceptance criteria → `docs/design/adr-0007-mechanics.md`
- **ADR 0008** — Pinned/AcceptWithFlag rationale essays and acceptance criteria → `docs/design/adr-0008-mechanics.md`
- **ADR 0011** — implementation-note blockquote and ops/self-update caveats → `docs/design/adr-0011-mechanics.md`
- **ADR 0012** — six-phase staged plan and review-finding call-sites → `docs/design/adr-0012-mechanics.md`
- **ADR 0013** — APAC soak narrative and validation inventory → `docs/design/adr-0013-mechanics.md`
- **ADR 0014** — Implementation section and acceptance criteria → `docs/design/adr-0014-mechanics.md`
- **ADR 0015** — considered options, validation checklist, AI-work notes → `docs/design/adr-0015-mechanics.md`
- **ADR 0016** — implementation phases and validation lists → `docs/design/adr-0016-mechanics.md`
- **ADR 0017** — implementation status and alternatives record → `docs/design/adr-0017-mechanics.md`
- **ADR 0018** — revocation-enforcement validation test inventory → `docs/design/adr-0018-mechanics.md`
- **ADR 0019** — considered options and validation test matrices → `docs/design/adr-0019-mechanics.md`
- **ADR 0020** — considered options, validation tests, Phase-2 deferrals → `docs/design/adr-0020-mechanics.md`
- **ADR 0021** — attestation field table, signed bytes, verification, move policy → `docs/design/adr-0021-mechanics.md`
- **ADR 0022** — validation test inventory and Phase-1 deferrals → `docs/design/adr-0022-mechanics.md`
- **ADR 0023** — considered-options rationale and validation inventory → `docs/design/adr-0023-mechanics.md`
- **ADR 0024** — validation break-disclosure essay and grounding G-001–G-003, G-005 → `docs/design/gss-admin-remove-fail-closed.md` (Extracted section)
- **ADR 0025** — grounding G-001–G-006 → `docs/design/required-gates-observation-completeness.md` (Extracted section)
- **ADR 0026** — grounding G-001–G-006 → `docs/design/managed-x0xd-deployment.md` (Extracted section)
- **ADR 0027** — grounding G-001–G-005 → `docs/design/active-recipient-group-key-sealing.md` (Extracted section)
- **ADR 0029** — ingest/read-surface/bridge-mapping detail and validation → `docs/design/adr-0029-mechanics.md`
- **ADR 0030** — key-implementation-facts block and validation matrix → `docs/design/adr-0030-mechanics.md`
- **ADR 0031** — validation/property-test inventory → `docs/design/adr-0031-mechanics.md`

Post-acceptance correction, 2026-08-29:

- **ADR 0051** — RESOLVED by #437: the header now binds the inner
  envelope via `inner_digest` (blake3 over the canonical postcard bytes,
  signed under the `x0x-relay-hdr-v2` domain and enforced by
  `disposition_for` before any sender gating or accounting). The ADR's
  "signs no digest of the inner envelope / substitution tracked as #437"
  limitation no longer describes shipped behavior for #437+ senders;
  legacy digest-less headers remain accepted per the documented
  transition. Details:
  [`docs/design/adr-0051-mechanics.md`](../design/adr-0051-mechanics.md).

Post-acceptance decisions and corrections, 2026-09-10/11 (ADR 0064; every
maintainer decision from #472 during slice implementation, PRs #635/#636/
#637/#640; the ADR body is immutable, so the shipped deltas are recorded
here — [`docs/trust-and-connectivity.md`](../trust-and-connectivity.md)
ADR-0064 sections are the maintained mechanics, and
[`docs/runbooks/fork-quarantine.md`](../runbooks/fork-quarantine.md) is the
operator runbook):

- **Manual clear surface (decision 1, refined in the slice-3 review)** —
  `POST /groups/:id/quarantine/clear` (CLI `x0x groups quarantine clear
  <id>`) clears the LOCAL marker. Without `force` it clears only on a node
  holding the group's owner USER key: the endpoint MINTS a fresh
  quarantine-clear attestation over the current head under the dedicated
  `x0x.quarantine-clear-attest.v1` domain (never the join-attestation
  domain, so a join attestation cannot double as a clear) and verifies it
  before clearing. Otherwise `force: true` + non-empty `reason` is
  required. Remote-owner attestation submission is out of scope. Per-node
  only; logged and counted (`fork_quarantine_manual_clears`).
- **Non-owner-axis (ordinary) groups are NOT gated (decision 2)** —
  fork evidence is recorded and exposed in diagnostics only. Indefinite
  quarantine with no recovery path would brick ordinary groups in the
  wild, worse than the ADR-0016 equal-revision fork risk it prevents;
  the marker type's `no_anchor` flag stays reserved (`false`). Gating
  waits for an ADR defining their anchor. Operator procedure:
  runbook §5.
- **Signer-only classification + chain-fetch follow-up (decision 3)** —
  slice 4 ships signer-only classification for full members (`signer_only`
  / `unauthorized_signer` / `owner_anchored_conflict` labels on the
  forensic snapshot); a chain-fetch surface is follow-up issue #639 —
  gossip carries none, so only the first link is anchored and the
  implementation deliberately does not fake a chain it cannot see.
- **Item 4 split (decision 4)** — the content-addressed base snapshot for
  rosters over the DM budget is NOT part of ADR-0064 and was split out at
  slice-2 landing; the dedicated issue is not yet filed as of 2026-09-11
  (tracked on the #472 residual list).
- **Route coverage + ratchet epoch token deferral (decision 5)** —
  history/delegations/kv route gating and the ratchet lifecycle epoch
  token are deferred to a future ADR; #472 stays open as the tracker.
- **Sidecar mirroring (decision 6, corrected twice)** — for owner-axis
  groups the authoritative persisted record is the `home-suite-groups.json`
  sidecar (`named_groups.json` holds the legacy placeholder; both carry
  `fork_quarantine` and `mandate_capability` through the #451 split
  write). No new code was needed: `merge_home_suite_groups` already
  replaces whole owner-axis entries, and the fields were serde-default
  persisted since slices 1–2; slice 4 pins it by test. Caveat: an OLD
  SIDECAR-AWARE binary rewriting the sidecar drops both fields (a
  downgrade across a sidecar-aware version loses containment, never
  bricks).
- **§1b ratified (decision 7)** — the never-observed-admin boundary
  stands as written: the grace clock starts at first PROVEN capability;
  forcing mandates from never-observed admins would break mixed-version
  fleets (the keyless tier warn-accepts indefinitely).
- **OwnerMandate v2 preimage (slice-2 reviews)** — the implemented
  canonical preimage signs the §1a members PLUS `version`,
  `authority_agent_id`, and `issued_at_ms` (13 bound fields total, also
  including `joiner_agent_id`, `invite_secret_hash`,
  `admission_cert_digest`), domain `x0x.owner-mandate.v2\0`, signed by
  the owner USER key over the blake3 digest, domain-separated from
  HeadAttestation / GroupStateCommit / invite signatures. Every later
  implementation must diff against this v2 shape, not the §1a formula
  alone.
- **Clear-rule clarifications (slice-1 and slice-4 reviews)** — a marker
  clears ONLY when this node APPLIES an owner-anchored commit at strictly
  greater revision (tier-1 attestation-verified adoption, or a
  mandate-carrying `MemberAdded` whose mandate verifies on the apply
  path), or through the explicit seal route on an owner-key node (both
  arms, including the eviction arm, with the clear inside the persist
  transaction), or the manual endpoint. The conflict path NEVER clears —
  the slice-4 task text's clear-on-anchored-conflicting-commit was
  withdrawn before merge (it would un-quarantine a node still holding
  the disowned sibling and re-quarantine on the next canonical commit);
  such commits are recorded as `owner_anchored_conflict` evidence.
  Every clear re-arms the stored fork-evidence silence gate.

Not actioned from the audit, deliberately: ADR 0010's verdict is
SUPERSEDED-BY-0012 (tombstone retained, nothing to relocate); the optional
merges (0013 into 0009, 0022 into 0020) are forbidden as literal edits by
the immutability policy and remain superseding-ADR candidates. The audit's
"0026/0027 listed under Proposed" staleness had already been corrected
before this pass; the duplicate 0036 index entry and date-ordered index
inconsistencies are fixed in this README (numeric ordering throughout).
