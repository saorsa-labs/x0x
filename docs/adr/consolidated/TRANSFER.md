# Transfer map for the 15 ADR set

Source commit: `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. The source set contains 100 numbered ADRs.

Every row has one primary home. Related ADRs can cite other slots.
**All clause reviews remain pending.** A mapping is not formal supersession.

| Source ADR | Status at source | Primary home | Clause review |
|---|---|---|---|
| [ADR 0001: Bootstrap Peers Are Seed Hints Only](../0001-bootstrap-peers-are-seed-hints-only.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR-0002: Application-Level Keepalive for Direct Connections](../0002-application-level-keepalive-for-direct-connections.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR-0003: Auto-Connect to Discovered Agents](../0003-auto-connect-to-discovered-agents.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR-0004: QUIC Stream and Channel Limits for Gossip Workloads](../0004-quic-stream-and-channel-limits.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR-0005: mDNS Local Network Discovery](../0005-mdns-local-network-discovery.md) | Superseded | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0006: No Global DHT Dependency for User and Group Data](../0006-no-global-dht-for-user-and-group-data.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0007: Three-Layer Identity Model](../0007-three-layer-identity-model.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0008: Trust Evaluation System](../0008-trust-evaluation-system.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0009: Receive-Pump Overload Policy](../0009-recv-pump-overload-policy.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0010: GSS Before MLS TreeKEM for v1 Secure Groups](../0010-gss-before-mls-treekem-for-v1-secure-groups.md) | Accepted | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| [0011 — Bootstrap nodes dual-listen on UDP/443; clients dial 443 first and never bind privileged ports](../0011-bootstrap-dual-listen-udp-443.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0012: Real TreeKEM as the Default Secure Group Plane](../0012-treekem-default-secure-groups.md) | Accepted | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| [ADR 0013: Priority-Aware PubSub Receive-Pump Shedding](../0013-priority-aware-pubsub-shed.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0014: TreeKEM Self-Leave Is a Roster Removal; PCS Comes From an Owner-Driven Rekey](../0014-treekem-self-leave-owner-driven-rekey.md) | Accepted | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| [ADR 0015: No App-Layer At-Rest Encryption or Secondary Passwords](../0015-no-app-layer-at-rest-encryption.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0016: Role-Based Group Authority — Flat Admin/Member, Retiring `Owner`](../0016-role-based-group-authority-flat-admin.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0017: Position x0x as the agent transport layer (spec + A2A interop + PQC/zero-registry positioning)](../0017-x0x-as-agent-transport-layer.md) | Accepted | [A01](A01-r01-purpose-and-product-limits.md) | Pending |
| [ADR-0018 — Key Lifecycle: Expiry, Renewal, and Revocation](../0018-key-lifecycle-expiry-renewal-revocation.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0019: Connect ACL — default-closed connectivity policy](../0019-connect-acl-default-closed.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0020: Tailnet Phase 1 — per-peer byte-streams + local port-forwarding](../0020-tailnet-phase-1-byte-streams-and-forwarding.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0021: DM origin-machine attestation for gossip DMs](../0021-dm-origin-machine-attestation.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0022: Tailnet stream API — per-protocol acceptors, connect-ACL gate, bounded backpressure](../0022-tailnet-stream-api.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0023: Durable Local History Is a Core x0x Capability](../0023-durable-local-history.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0024: GSS Rotation on Admin Remove Is Fail-Closed and Seals Before It Persists](../0024-gss-rotation-on-admin-remove-fail-closed.md) | Accepted | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| [ADR 0025: Required Gates Must Prove Observation Completeness](../0025-required-gates-prove-observation-completeness.md) | Accepted | [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| [ADR 0026: Managed x0xd Deployment Has Distinct Roots and Closed Resolution](../0026-managed-x0xd-deployment.md) | Accepted | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| [ADR 0027: Active-Recipient Group-Key Sealing](../0027-active-recipient-group-key-sealing.md) | Accepted | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| [ADR 0028: Authenticated Causal-Predecessor Delivery](../0028-authenticated-causal-predecessor-delivery.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0029: First-Class Threading on Signed Public Group Messages](../0029-public-message-threading.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0030: DM Protocol v2 — Durable Application ACK, Capability-Gated](../0030-dm-durable-application-ack-v2.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0031: Sole-Member Self-Leave Deletes the Group](../0031-sole-member-self-leave-deletes-group.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0032: The `:443` Bootstrap Listener Runs Its Own Identity](../0032-x0xd-443-own-identity.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0033: The Receive Pump Never Blocks — All Classes Shed or Spill](../0033-recv-pump-never-blocks.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0034: Leaf Gossip Participation Is the Desktop Default; `--relay` Is One Operator Concept](../0034-leaf-participation-default.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0035: Relay Decentralization to SOTA — Earned Promotion, Spread Selection, Bootstrap Demotion](../0035-relay-decentralization.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0036: Owner Singleton and Naming Registry](../0036-owner-singleton-and-naming-registry.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0037: Agent Placement and Key Custody](../0037-agent-placement-and-key-custody.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0038: Home — an Owner-Certified Personal Space](../0038-home-owner-certified-personal-space.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0039: Agent Harness Boundary — ACP-Attached Agents vs API-Key Riders](../0039-agent-harness-boundary.md) | Accepted | [A04](A04-r01-agent-attachment-and-inbound-events.md) | Pending |
| [ADR 0040: Agent-to-Agent Delegation in Spaces](../0040-agent-delegation-in-spaces.md) | Accepted | [A12](A12-r01-agent-teams-delegation-and-task-coordination.md) | Pending |
| [ADR 0041: Cross-Machine State Sync — Tiered, Owner-to-Owner Only](../0041-cross-machine-state-sync-tiers.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0042: Voice Media over Tailnet Streams (`WebRtcV1`)](../0042-voice-media-over-tailnet-streams.md) | Accepted | [A13](A13-r01-voice-and-video.md) | Pending |
| [ADR 0043: Agent Key-Move Protocol — Machine KEM Enrollment, Commit-then-Activate Moves, Binding Revocation](../0043-agent-key-move-protocol.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0044: The Daemon Exposes a Loopback REST + WebSocket + SSE Control Plane](../0044-daemon-local-rest-ws-sse-control-plane.md) | Accepted | [A11](A11-r01-local-api-applications-and-human-interface.md) | Pending |
| [ADR 0045: Decentralized Self-Update with Signed Manifests and Transactional Restart](../0045-decentralized-self-update.md) | Accepted | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| [ADR 0046: Exec Runs Only Exact-Argv Allowlisted Commands, Fail-Closed, Audited](../0046-exec-service-fail-closed-acl.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0047: The KV Store Is CRDT-Backed with Delta Gossip and a Context-Gated `Encrypted` Policy](../0047-crdt-kv-store-delta-gossip.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0048: Task Lists Coordinate via Per-Entity CRDTs with Signed Provenance](../0048-crdt-task-list-coordination.md) | Accepted | [A12](A12-r01-agent-teams-delegation-and-task-coordination.md) | Pending |
| [ADR 0049: Presence Runs on Signed Beacons over a Global Topic with FOAF Candidate Scoring](../0049-presence-foaf-discovery.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0050: Direct Messages Ride a KEM-Sealed, Signed, Replay-Protected Gossip Base](../0050-dm-over-gossip-base-transport.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0051: Peer Relay (X0X-0070) Is a Default-Off, One-Hop DM Fallback](../0051-application-level-peer-relay.md) | Proposed | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0052: The GUI Is a Compile-Time-Embedded HTML Asset Served by the Daemon](../0052-embedded-gui-in-daemon-binary.md) | Accepted | [A11](A11-r01-local-api-applications-and-human-interface.md) | Pending |
| [ADR 0053: An API-Unserved Watchdog on a Dedicated Thread Aborts a Wedged Daemon](../0053-api-unserved-watchdog.md) | Accepted | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| [ADR 0054: External Agent Signing Uses a Canonical Domain-Separated Context, Never Raw Payloads](../0054-external-agent-signing-dst.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0055: File Transfer Is a DM-Chunked, SHA-256-Verified Protocol with a 1 GiB Cap](../0055-dm-file-transfer-protocol.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0056: Voice Link Transport and Signaling (Historical Record; Media Ratified by ADR-0042)](../0056-voice-link-transport-and-signaling.md) | Superseded | [A13](A13-r01-voice-and-video.md) | Pending |
| [ADR 0057: Local Apps Reach the Daemon via REST/WS with Filesystem Discovery; `serve()` Is the Embedded Form](../0057-embedded-serve-library-local-apps.md) | Accepted | [A11](A11-r01-local-api-applications-and-human-interface.md) | Pending |
| [ADR 0058: The Constitution Is Embedded Compile-Time in Every Binary](../0058-compile-time-embedded-constitution.md) | Accepted | [A01](A01-r01-purpose-and-product-limits.md) | Pending |
| [ADR 0059: Invite Authentication and Seating Provenance](../0059-invite-authentication-and-seating-provenance.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0060: The Owner's Home Is Elected, Not Per-Install](../0060-one-home-per-owner.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0061: Self-Update Must Resolve Restart Ownership Before Replacing Binaries](../0061-supervised-upgrade-restart-ownership.md) | Accepted | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| [ADR 0062: Recover Ordinary Home Persistence as One Durable Pair](../0062-home-persistence-pair-recovery.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0063: Signed KV legacy gossip compatibility adoption boundary](../0063-signed-kv-legacy-gossip-compatibility-adoption-boundary.md) | Rejected | [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| [ADR 0064: Owner-Anchored Fork Authority for Invite-Derived Seatings](../0064-owner-anchored-fork-authority.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0065: Duplicate Homes Are Inventoried, Not Retired](../0065-duplicate-home-inventory-retirement-deferred.md) | Superseded | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0066: Ordinary-Group Fork Anchors and Data-Plane Quarantine Coverage](../0066-ordinary-group-fork-anchors-and-data-plane-quarantine-coverage.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0067: The Lifecycle Epoch Token Is Derived Marker Identity, Not a Generation Counter](../0067-lifecycle-epoch-token-is-derived-marker-identity.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0068: Fork Quarantine Pins History Retention and Buffers Inbound Task Deltas](../0068-quarantine-pinned-history-retention-and-buffered-task-deltas.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0069: Home Auto-Provisioning Waits for Owner Sync](../0069-home-wait-for-sync-before-auto-provisioning.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0070: Owner Trust and Share Grants](../0070-owner-trust-and-share-grants.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0071: Relay Backbone — What Relays Today and What Is Deferred](../0071-relay-backbone-shipped-truth-and-deferred-work.md) | Accepted | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| [ADR 0072: Scope Freeze — Deferred and Legacy-Maintenance Mechanisms (2026-09-25)](../0072-scope-freeze-deferred-and-legacy-maintenance.md) | Accepted | [A01](A01-r01-purpose-and-product-limits.md) | Pending |
| [ADR 0073: Audio and Video Calling Ship Together via the Daemon-Side Browser Gateway](../0073-audio-and-video-calling.md) | Accepted | [A13](A13-r01-voice-and-video.md) | Pending |
| [ADR 0074: Tailnet Phase 2 — Names, Persistent Forwards, SOCKS5 and Open-Stream Revocation](../0074-tailnet-phase-2-names-persistent-forwards-socks5.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0075: Collaborative Notes Use a yrs Text CRDT in the Group Store; Agent Scratchpads Are a Rider-Reachable Group Store](../0075-collaborative-notes-and-agent-scratchpads.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0077: Share-Grant Redelivery Is an Owner-Side Durable Outbox; Grantee Fetch Deferred](../0077-share-grant-owner-side-redelivery-outbox.md) | Accepted | [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| [ADR 0079: Grant-Carried Owner and Machine Names as ADR-0074 §1 Name Defaults](../0079-grant-carried-owner-and-machine-names.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0080: A Grant Revocation Is Also Pushed as One Signed Record to Capable Recipients; Gossip Remains the Backstop](../0080-grant-revocation-direct-push.md) | Proposed | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0081: Notes Use the loro Text CRDT (Supersedes the ADR-0075 CRDT Choice)](../0081-notes-use-loro-crdt.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0082: Note Records Are Accepted Under the Roster Epoch They Were Written At](../0082-notes-epoch-bound-writer-rule.md) | Accepted | [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| [ADR 0083: Agents Show Their Owner a GUI View, Locally or on the Owner's Active Machine](../0083-agent-initiated-gui-show.md) | Accepted | [A11](A11-r01-local-api-applications-and-human-interface.md) | Pending |
| [ADR 0084: Admit Owner Sync from Enrolled Machines on Verified Enrollment Alone](../0084-enrolled-owner-sync-admission.md) | Accepted | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| [ADR 0085: Persisted Binary Formats Are Versioned, Read Every Released Layout, and Fail Closed on Downgrade](../0085-persisted-binary-formats-are-versioned.md) | Accepted | [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| [ADR 0086: Gossip Send Targets Are Bounded by Transport Connectivity](../0086-gossip-send-targets-bounded-by-transport-connectivity.md) | Accepted | [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| [ADR 0087: Repository and Release Governance: Protected Main, Admin-Only Release Tags, a Reviewed Release Environment, and ADRs Before Code](../0087-repository-and-release-governance.md) | Accepted | [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| [ADR 0088: Group Liveness Contract (I8)](../0088-group-liveness-contract.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0089: Relationship-Peer Evidence Survives Restart (Evidence Rule, Slice 1)](../0089-relationship-peer-evidence-survives-restart.md) | Accepted | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| [ADR 0093: Capability Advertisement Registry](../0093-capability-advert-registry.md) | Accepted | [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| [ADR 0094: M2 safe apply with launcher-owned rollback](../0094-m2-safe-apply.md) | Accepted | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| [ADR 0095: Scope — x0x Is Glue Between People, Their Machines and Their Agents](../0095-scope-x0x-is-glue.md) | Accepted | [A01](A01-r01-purpose-and-product-limits.md) | Pending |
| [ADR 0096: R12 — x0x Is Maintained by Its Own Agents](../0096-r12-x0x-is-maintained-by-its-own-agents.md) | Accepted | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| [ADR 0106: Join Results Carry the Intervening Membership Events](../0106-join-result-carries-intervening-membership-events.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0107: Stuck Join Re-arm and Current-Roster Serving Guard (0088 S8 (a))](../0107-stuck-join-rearm-and-serving-guard.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0108: Home-Scoped Owner Certificate and Seal Verdict (0088 S2)](../0108-home-scoped-owner-certificate.md) | Accepted | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0109: Ownerless Attestation: Stale-Base Self-Recovery and Manual Re-seat (0088 S3)](../0109-ownerless-attestation-self-recovery.md) | Proposed | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0110: Revocation Eviction, Designated First](../0110-revocation-eviction-designated-first.md) | Proposed | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| [ADR 0111: Evidence Size K and Fetch-by-Hash from Any Holder (0088 S5)](../0111-evidence-size-k-and-fetch-by-hash.md) | Proposed | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0112: Any-Admin Invite Redemption (0088 S6)](../0112-any-admin-invite-redemption.md) | Proposed | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0113: Home Is an Explicit Owner Group, Adopted in Place (0088 S7)](../0113-home-is-an-explicit-owner-group-adopted-in-place.md) | Proposed | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| [ADR 0114: Authority Re-Welcome for Unconfirmed Join Rows](../0114-authority-re-welcome.md) | Proposed | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |

## Rulings

These rows map the rulings in [docs/design/x0x-direction.md](../../design/x0x-direction.md)
to their destination slots. D196–D200 were checked against the charter and the
[controller review on PR #1244](https://github.com/saorsa-labs/x0x/pull/1244)
on 5 October 2026. The digest holds the ruling text; the topic column below is
only a locator. Ruling ranges include every D-row in that range.

**Pending means the clause transfer remains open, not that David has not
ruled.** An accepted source ADR or a ruled value does not accept a replacement
slot. A01–A15 in a row means every slot. Retain the named source gates until
David accepts the transfer. See A08 for the exact D196 gate and D63 order.

| Ruling | Topic to retain | Destination slots | Transfer status |
|---|---|---|---|
| D01 | Released-layout reads and intact fail-closed downgrade | [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D03 | Canary, restart rehearsal and prerelease ban | [A14](A14-r01-health-updates-and-recovery.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D04 | Tracked lock and tested release graph | [A14](A14-r01-health-updates-and-recovery.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D05 | Human release and signing approval | [A14](A14-r01-health-updates-and-recovery.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D06 | Enrollment-only owner-sync admission | [A02](A02-r01-identity-keys-and-device-enrollment.md), [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| D08 | Verified grant capability evidence | [A03](A03-r01-trust-permissions-sharing-and-revocation.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D09 | Known limitations, downgrade and experimental calls | [A13](A13-r01-voice-and-video.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D11 | Historical Home rule accepted as a record | [A08](A08-r01-groups-home-membership-and-repair.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D13 | Invites stop past 20 Active+Banned members; #646 is a product limit, not parked; fix in W4 | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D14 | Testnet isolation | [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D15 | PR checks, protected main and release tags; no bot identity | [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D16 | Offline-admin liveness, explicit Home and harness-first | [A08](A08-r01-groups-home-membership-and-repair.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D17 | Shared authority from in-band evidence and persisted state | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| D18 | One Outbox and TreeKEM; reserved 0090/0091 | [A07](A07-r01-messages-receipts-history-and-retry.md), [A09](A09-r01-group-encryption-and-key-changes.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D19 | Scope, shared teams, efficiency; media and rich-text park | [A01](A01-r01-purpose-and-product-limits.md), [A04](A04-r01-agent-attachment-and-inbound-events.md), [A06](A06-r01-gossip-relay-roles-and-resource-limits.md), [A10](A10-r01-shared-data-files-and-synchronization.md), [A11](A11-r01-local-api-applications-and-human-interface.md), [A12](A12-r01-agent-teams-delegation-and-task-coordination.md), [A13](A13-r01-voice-and-video.md) | Pending |
| D20 | Owner-governed agent maintenance; reserved 0097 | [A14](A14-r01-health-updates-and-recovery.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D21 | M-safety parallel with W3; work order remains | [A08](A08-r01-groups-home-membership-and-repair.md), [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D22 | Owner-key custody and recovery | [A02](A02-r01-identity-keys-and-device-enrollment.md) | Pending |
| D23 | Revocation permanence, fail-closed storage and live gates | [A03](A03-r01-trust-permissions-sharing-and-revocation.md), [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| D24 | Protocol-aware stream permissions | [A03](A03-r01-trust-permissions-sharing-and-revocation.md), [A05](A05-r01-connectivity-discovery-and-names.md) | Pending |
| D25 | Inbox policy | [A03](A03-r01-trust-permissions-sharing-and-revocation.md), [A04](A04-r01-agent-attachment-and-inbound-events.md), [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| D26 | Leaf egress sequence and protected revocation traffic | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D27 | Roaming and legacy cuts; no silent reactivation | [A01](A01-r01-purpose-and-product-limits.md), [A02](A02-r01-identity-keys-and-device-enrollment.md), [A06](A06-r01-gossip-relay-roles-and-resource-limits.md), [A07](A07-r01-messages-receipts-history-and-retry.md), [A09](A09-r01-group-encryption-and-key-changes.md), [A10](A10-r01-shared-data-files-and-synchronization.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D28 | Implementation holds and cross-model review | [A03](A03-r01-trust-permissions-sharing-and-revocation.md), [A07](A07-r01-messages-receipts-history-and-retry.md), [A11](A11-r01-local-api-applications-and-human-interface.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D29 | Persisted relationship-peer evidence and cold exchange | [A03](A03-r01-trust-permissions-sharing-and-revocation.md), [A07](A07-r01-messages-receipts-history-and-retry.md) | Pending |
| D30 | Restart-cold and mixed-version evidence | [A07](A07-r01-messages-receipts-history-and-retry.md), [A08](A08-r01-groups-home-membership-and-repair.md), [A10](A10-r01-shared-data-files-and-synchronization.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D33 | Relationship-peer evidence scope | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| D34 | Ownerless attestation, bounded revocation eviction and fetch-by-hash | [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D35 | Grant lifetime, unknown-capability wait, version floor; reserved 0098 | [A03](A03-r01-trust-permissions-sharing-and-revocation.md), [A07](A07-r01-messages-receipts-history-and-retry.md), [A14](A14-r01-health-updates-and-recovery.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D36 | Team/scratch-store order, protected fanout and tracked findings | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md), [A10](A10-r01-shared-data-files-and-synchronization.md), [A12](A12-r01-agent-teams-delegation-and-task-coordination.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D37 | Separate numbered liveness slices and acceptance | [A08](A08-r01-groups-home-membership-and-repair.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D38 | Home-scoped owner certificate; public anonymity | [A02](A02-r01-identity-keys-and-device-enrollment.md), [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D39(A) | Revised ruling: known limitation for v0.46, workaround verified first; joiner re-arm and authority re-Welcome in v0.46.x | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D40 | Designated-first refinement of D34 revocation eviction | [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D41 | Attestation repairs only the receiving node | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D42 | Adopt Home in place; user retires duplicates | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D54 | Any-holder repair, may-block list, and W3-H harness-first | [A08](A08-r01-groups-home-membership-and-repair.md), [A10](A10-r01-shared-data-files-and-synchronization.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D55 | Harness-first exception for #1150 (a) only | [A08](A08-r01-groups-home-membership-and-repair.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D57 | 0107 accepted as written; code conforms | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D58 | 0088/0094/0095/0096 accepted; conditional supersessions remain | [A01](A01-r01-purpose-and-product-limits.md), [A08](A08-r01-groups-home-membership-and-repair.md), [A14](A14-r01-health-updates-and-recovery.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D60 | Current recipient eligibility and secret epoch on every resend | [A03](A03-r01-trust-permissions-sharing-and-revocation.md), [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D63 | Numbered slice bindings and acceptance order; 0084–0105 reserved; ADR 0080 capability-gated single-record push clause belongs in [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | [A08](A08-r01-groups-home-membership-and-repair.md), [A06](A06-r01-gossip-relay-roles-and-resource-limits.md), [A09](A09-r01-group-encryption-and-key-changes.md), [A10](A10-r01-shared-data-files-and-synchronization.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D64 | Typed refusals and waits for every slice | [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D65 | S8 in the acceptance order means S8(a) | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D66–D68 | Home certificate delivery and disclosure limits | [A02](A02-r01-identity-keys-and-device-enrollment.md), [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D69 | Measure designated window and completion bound | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D70–D72 | Machine revocation, certificate expiry and eviction retention | [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D73 | Measure fallback stagger and restart wait | [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D74 | Lowest roster admin, without reachability data | [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D75–D76 | No-admin waits and legacy survivor handling | [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D77–D83 | Ownerless attestation and Home activation conditions | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D84–D92 | Authority re-Welcome, repair bounds and exclusions | [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D93–D98 | Any-holder fetch, retention, and legacy disclosure exceptions | [A08](A08-r01-groups-home-membership-and-repair.md), [A10](A10-r01-shared-data-files-and-synchronization.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D99–D105 | Any-admin invite admission and activation | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D106–D107 | Home setup and old-binary limitations | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D108–D114 | Revocation push, horizon, capabilities and review hold | [A03](A03-r01-trust-permissions-sharing-and-revocation.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D117–D125 | Slice-wide limits, authority, recovery and disclosure exceptions | [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D126–D129 | Eviction recovery, expiry and rebinding | [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D130–D133 | Invite fork prevention, bounds and disclosure | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D134–D135 | Home setup exception and certificate rebinding | [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D136–D138 | Re-Welcome markers, budgets and manual exits | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D139–D143 | Revocation ingestion, delivery records and diagnostics | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| D145–D148 | Slice authority amendments and corrupt-state handling | [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D149–D150 | Home join notice and withdrawal | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D151–D155 | Rebinding, recovery, legacy holds and eligibility | [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D156–D165 | Re-seat, any-holder fetch and invite replay | [A08](A08-r01-groups-home-membership-and-repair.md), [A10](A10-r01-shared-data-files-and-synchronization.md) | Pending |
| D166–D168 | Re-Welcome retention proof and history gaps | [A08](A08-r01-groups-home-membership-and-repair.md), [A09](A09-r01-group-encryption-and-key-changes.md) | Pending |
| D169 | Lost revocation delivery lists remain typed | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| D170–D173 | Re-seat authority and Home certificate timing | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D178 | 0108 accepted; S2 code still needs W3-H | [A08](A08-r01-groups-home-membership-and-repair.md) | Pending |
| D181 | W3-H case red on main in CI; standalone in-process tests do not count | [A08](A08-r01-groups-home-membership-and-repair.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D182 | Manifest future-clock tolerance: 5 minutes | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D183 | Compiled rollout window: 60 minutes | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D184 | Fleet window default/minimum 60 minutes; test-key rehearsal may use zero | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D185 | Explicit now=true bypasses only the wait | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D186 | Prerelease ban stays; a later accepted ADR defines any lift | [A14](A14-r01-health-updates-and-recovery.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D187 | Probe limit: 90 seconds | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D188 | Interrupted host faults by phase; recovery-failed barriers | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D189 | Three retries at 30, 60 and 120 minutes, then hold | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D190 | Newer release or authenticated local clear; recovery-failed stays held | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D191 | Shutdown flush limit: 30 seconds | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D192 | Three launches within an 11-minute trial; bounded restoration | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D193 | Local health plus peer continuity when previously connected | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D194 | Keep previous committed binary pair; reserve 1 GiB | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D195 | Install SKILL.md after candidate health holds; retain prior guide | [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| D196 | 20 verdict-stable CI reruns with complete receipts; exact traces non-blocking | [A08](A08-r01-groups-home-membership-and-repair.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| D197 | EvidenceV1: Unknown relationship peers admitted, Blocked refused, evidence verified | [A03](A03-r01-trust-permissions-sharing-and-revocation.md) | Pending |
| D198 | 15-slot direction and writing target confirmed; transfer stays Proposed | A01–A15 | Pending |
| D199 | Numbered decisions only during transfer; slots are drafts | A01–A15 | Pending |
| D200 | 0040 stands: owner_agent and current-owner-signed transfers | [A12](A12-r01-agent-teams-delegation-and-task-coordination.md) | Pending |
| E-D1–E-D2 | Measured efficiency budgets and release targets | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| E-D6 | Leaf egress order with protected delivery | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| E-D9 | Capability-gated direct-first durable DM | [A07](A07-r01-messages-receipts-history-and-retry.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| E-D11 | Metered/edge limits and power lifecycle | [A05](A05-r01-connectivity-discovery-and-names.md), [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) | Pending |
| E-D12 | Compact agent instructions and topic pages | [A04](A04-r01-agent-attachment-and-inbound-events.md), [A11](A11-r01-local-api-applications-and-human-interface.md), [A14](A14-r01-health-updates-and-recovery.md) | Pending |
| E-D13 | Binary size evidence and David merges release-workflow changes | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md), [A14](A14-r01-health-updates-and-recovery.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |
| E-D15–E-D17 | Efficiency review, measurement and no delivery loss | [A06](A06-r01-gossip-relay-roles-and-resource-limits.md), [A15](A15-r01-compatibility-validation-and-decision-rules.md) | Pending |

## Required transfer evidence

For each important clause, record the source section, destination section,
disposition, reason, human decision where needed, and owning test or evidence.
Preserve frozen grounding files with their accepted records. Recheck the map
against main before activation; source records can change while teams work.

An old Proposed, Rejected or Superseded record does not become Accepted
because this map links to it. Read the existing status overlay as well.
