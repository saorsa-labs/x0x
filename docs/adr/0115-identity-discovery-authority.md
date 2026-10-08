# ADR 0115: Identity Discovery Authority Comes Only From Agent-Authenticated Evidence

- **Status:** Accepted
- **Accepted:** 2026-10-07 by David Irvine (D212, as written: the Proposed text at efb871e; D213–D215 answer its open questions and are recorded below). David's rulings were relayed by the controller (Claude); the status change was applied by Claude at that relayed instruction.
- **Date:** 2026-10-06
- **Decision owners:** David Irvine (decision)
- **Author:** Claude (drafting)
- **Reviewers:** OMP (cross-family review of the Proposed text, APPROVE-WITH-NITS, fixes in efb871e); David Irvine (acceptance)
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** [ADR 0043](./0043-agent-key-move-protocol.md) (Accepted, not edited), Decision 2 and 4: a mesh peer accepts an `ActivationBundle`, and its tombstones, only when the bundle owner is the subject's authenticated owner (§4 below).
- **Corrects a premise of:** [ADR 0108](./0108-home-scoped-owner-certificate.md) (Accepted, not edited), §4: "Only the subject agent's authenticated bound machine can sign its announce". Today that holds only inside the #1247 check. This ADR makes it hold for every reader of the discovery cache.
- **Related:** advisory GHSA-rr9m-cvx5-pmv9 (fixed in v0.46.5); [ADR 0007](./0007-three-layer-identity-model.md); [ADR 0018](./0018-key-lifecycle-expiry-renewal-revocation.md); [ADR 0021](./0021-dm-origin-machine-attestation.md); [ADR 0039](./0039-agent-harness-boundary.md); [ADR 0085](./0085-persisted-binary-formats-are-versioned.md); [ADR 0087](./0087-repository-and-release-governance.md); [ADR 0089](./0089-relationship-peer-evidence-survives-restart.md) §1 and §9; #1247.
- **Invariants and goals:** **I3** (authenticity at ingress), **I7** (revocation), **I9** (upgrade continuity); **R3**, **R5**, **R6** and **R7** all rely on a correct agent → machine binding.

<!-- Line references are to main at 3e5f538 (v0.46.4) unless marked. -->

## Context

**The problem.** Any node can make other nodes believe that agent X lives on the attacker's machine and has the attacker's owner. The attacker needs only X's public key, its own machine key, and its own agent key to sign the pubsub envelope. It does not need any secret of X.

**Why this is possible.**

1. **Announcements are machine-signed only.** `IdentityAnnouncement::verify` (V2, `X0A2`, `src/lib.rs:1836`) and `IdentityAnnouncementV3::verify` (V3, `X0A3`/`X0A4`, `src/announce_v3.rs:373`) check the key hashes and the machine signature. Neither proves that agent X authorized the machine or the announcement.
2. **A certificate has no agent consent.** An `AgentCertificate` is a user signature over an agent public key. `AgentCertificate::issue_for_public_key` (`src/identity.rs:620`) issues one without the agent's secret key. Any user can certify any agent.
3. **The discovery cache accepts every valid announcement as authority.** The identity listener (`src/lib.rs:11102`) checks the timestamp, Blocked and pinned contacts, revocation, ADR 0043 pairing and certificate expiry. Then it caches the announcement unconditionally (`src/lib.rs:12153`). `upsert_discovered_agent` (`src/lib.rs:2818`) lets any equal-or-newer announcement replace the machine, the certificate, the digest, the user and the name. The attacker can always be newer: the future-skew bound is 30 s (`src/lib.rs:1903`).
4. **The provenance check exists but decides too little.** `identity_announcement_has_direct_agent_origin` (`src/lib.rs:1956`) proves that the pubsub author is the announced agent. Today it only decides whether the separate authenticated-binding store is written (`src/lib.rs:12141`).

**What reads the poisoned fields.** The audit of 2026-10-05 and its adversarial verification found these confirmed effects (full list in §5):

- **Revocation authority (critical).** `collect_subject_certs` (`src/lib.rs:2645`) gives the cached certificate to `RevocationRecord::verify_authority` (`src/revocation.rs:284`). An attacker-issued certificate makes an attacker-signed revocation of X valid: X is evicted, marked Blocked in `contacts.json`, and its traffic is dropped. A binding tombstone for X's real machine never expires (`src/revocation.rs:643`).
- **No future bound on `revoked_at`.** `verify_authority` does not bound `revoked_at`. A record with `revoked_at = u64::MAX` survives every TTL sweep (`src/revocation.rs:645`).
- **Raw frames verified as X.** `raw_delivery_binding` (`src/lib.rs:4591`) lets discovery win unless the authenticated binding is strictly newer, and treats a cache match as verification. Raw DMs and KV deltas from the attacker's machine count as X's.
- **Raw-first sends go to the attacker.** `resolve_raw_quic_target` (`src/lib.rs:9219`) and the pinned selector (`src/lib.rs:290`) pick the poisoned machine. `POST /direct/send` and file transfer send plaintext payloads to it.
- **Stream and datagram gates** (`src/lib.rs:16284`, `16370`) admit the attacker's machine for a Trusted, unpinned X.
- **OwnerCertified verdicts** (`src/server/routes/named_groups.rs:22914`) read the cached certificate and digest. A wrong-owner certificate is a definitive failure, so seals are refused and admins evict X.

**A second path with the same root.** The ADR 0043 mesh rule accepts an `ActivationBundle` when the bundle's embedded certificate names X and is issued by the bundle signer (`src/key_move.rs:1022-1037`). Its tombstones then union in unconditionally (`src/key_move.rs:1422`), and its placement is cached (`src/key_move.rs:1427`). An attacker-issued certificate passes this check. No forged announcement is needed. The attacker can retire X's real binding for ever and pin X to the attacker's machine, after which X's own announcements are dropped at ingest. This path was not in the audit. Test T6 covers it.

**What already holds.** ADR 0089's stored evidence pairs a machine-signed announcement with an agent-signed advert (§1), so it is mutual. ADR 0021 origin attestation is agent-signed. Exec needs an exact pair or owner authority. Agent-signed inner protocols (gossip DMs, ACKs, ForwardV2, signed evidence) are not forgeable by this poison. ADR 0089 §9 point 1 states the rule this ADR restores for the live path: nothing becomes `verified` without mutual evidence for the transport-authenticated machine.

## Decision Drivers

- **I3:** an unverified claim must never reach a consumer as authenticated. An agent → machine or agent → owner claim needs the agent's own authentication.
- **I7:** only the subject's real owner (or the subject) can revoke; a revocation must have a bounded, honest lifetime.
- **No flag day.** Current and older genuine announcements must keep working without a wire change.
- **One rule at one chokepoint.** Patching each late reader is not enough: a poisoned update has already erased the trusted certificate, filled routing fallbacks or written a durable record before the reader runs.

## Considered Options

1. **Patch the late readers only** (compare `entry.machine_id` with the authenticated binding at each use). Rejected: it misses certificate erasure, the DM registry, durable revocation records and every reader not yet found.
2. **Gate discovery authority at ingest by provenance, then make the authority readers read only authority stores, and give revocation certificates authenticated provenance.** Chosen. No wire change.
3. **A new agent-signed announcement version now.** Cleaner, because the authority would survive extraction, caching and republication. It needs a new wire, a capability bit, dual publishing and ADR 0087 acceptance before merge, and old versions would still need this ADR's rule. Deferred (§7).
4. **Add an agent countersignature to `AgentCertificate`.** It fixes consent at the source. It changes a persisted and wire format, and every existing certificate lacks it, so a transition policy is still needed. Deferred with option 3.

## Decision

### 1. Authority fields and provenance classes

The **authority fields** of a discovery entry are `machine_id` with `machine_public_key`, `cert_digest` with `agent_certificate` and `cert_not_after`, `user_id`, `self_name`, and `agent_public_key`. Today a V2 body replaces `agent_public_key` last-writer-wins (`src/lib.rs:2901-2905`); a key that a class A or B announcement sets must also hash to the agent id. The derived **authority stores** are the announced-binding store (`announced_machine_bindings`), the DM registry entry (`register_agent`, `mark_connected`), the contact machine record, and the `DiscoveredMachine` agent and user projections. Addresses, NAT and relay flags, `reachable_via`, `relay_candidates` and `last_seen` are **hints**.

An agent X has an **authenticated pairing** with machine M when one of these holds now:
- X's entry in the authenticated-binding store names M. Only class A announcements (below) and ADR 0021 origin attestations write that store. Its certificate expiry has not passed, and neither M nor the (X, M) binding is revoked.
- A usable ADR 0089 evidence record exists for exactly (X, M) (`peer_evidence.usable`).

The listener classifies every valid identity announcement for X, signed by machine M:

| Class | Condition | Effect |
|---|---|---|
| **A — agent-authenticated** | the pubsub envelope is verified and its author is X (`identity_announcement_has_direct_agent_origin`) | It may set or replace every authority field and hint, as today. It records the authenticated binding, as today. |
| **B — bound machine** | not class A, and (X, M) is an authenticated pairing | It may set or replace the authority fields other than the pairing (the certificate pair, user, name and agent key), and the hints. It never moves X to another machine. |
| **C — other** | neither | It sets or replaces no authority field and writes no authority store. It is at most an address hint for an already-authenticated pairing; because M is not X's authenticated machine, it changes nothing for X. The listener counts it (`identity_announce_unauthenticated`). |

The rule applies to V2 and V3 alike, to every ingest path that writes the discovery cache (the identity listener, the shard lookup in `find_agent` at `src/lib.rs:15088-15146`, the rendezvous upsert in `find_agent` stage 3 at `src/lib.rs:15157-15185`, FOAF and presence merges), and to blob hydration. The rendezvous upsert carries a zero machine and `announced_at = now`, so it must never out-rank a signed beat or write an authority field. For blob hydration, a certificate that lands by digest takes the class of the announcement that committed to the digest.

Freshness keeps its current meaning inside classes A and B: an equal-or-newer `announced_at` replaces. A class C announcement never counts as newer.

### 2. Readers read authority, not routing

`DiscoveredAgent.machine_id` stays routing state; the connector may still rewrite it to the machine it reached. A security reader must read the agent → machine binding from the authenticated-binding store or the announced-binding store (class A or B only), and never from `DiscoveredAgent.machine_id` or the DM registry alone. This covers raw delivery verification, `Agent::is_agent_machine_verified`, raw and pinned recipient resolution, the stream and datagram gates, EvidenceV1 Lookup peers, placement minting and owner-sync candidate choice (§5).

### 3. Certificates used as revocation authority need authenticated provenance

A certificate gives issuer-revocation authority (an `Agent` revocation, an `AgentMachineBinding` tombstone, or an ADR 0043 bundle) only when it has **authenticated provenance** for its subject:
- it arrived in, or its digest was committed by, a class A or B announcement for the subject; or
- it is the certificate of a usable ADR 0089 evidence record for the subject; or
- the local owner issued it (the local certificate journal).

The node records the provenance of each cached certificate. `collect_subject_certs` returns only certificates with authenticated provenance. Without one, an issuer-revocation is rejected, fail closed, as today when no certificate is known.

### 4. ADR 0043 bundles need the subject's authenticated owner

A mesh peer accepts an `ActivationBundle`, and unions its tombstones and caches its placement, only when the bundle's embedded certificate has the same owner (`UserId`) as a certificate for the subject with authenticated provenance (§3). The coherence clauses of ADR 0043 still apply. Without such a certificate the bundle is rejected, fail closed. Participants that hold the full log keep the ADR 0043 participant rule. This amends ADR 0043 Decision 2 ("cumulative tombstones union in unconditionally") upon acceptance.

### 5. Bound `revoked_at`

Every revocation carrier (v1, v2, v3) rejects a record whose `revoked_at` is more than `REVOCATION_MAX_FUTURE_SKEW_SECS` ahead of local time. The bound is **300 s** (D213), the certificate clock-skew tolerance (`identity::is_expired`) and the storm-control future bound (`src/storm_control.rs:51`). At load, a persisted record beyond the bound is dropped and counted (`revocation_future_dropped`). A rejected genuine record is not lost: issuers republish their record sets on change and on every 12th heartbeat (`REVOCATION_FALLBACK_TICKS`, `src/lib.rs:4263`). At the default heartbeat of 600 s (`IDENTITY_HEARTBEAT_INTERVAL_SECS`, `src/lib.rs:1523`) that is every 2 h. The code comment at `src/lib.rs:4254` ("300 s × 12 = 1 h") is stale.

### 6. Consumers and how each is closed

Rule numbers refer to the sections above. "Root" means that the consumer is safe once §1 holds, because it reads only fields that class C can no longer write.

| Consumer (main at 3e5f538) | Today | Closed by |
|---|---|---|
| Issuer-revocation authority: `collect_subject_certs` `src/lib.rs:2645`; v1 and v2 listeners `11467`, `11647` | cached attacker certificate authorizes the attacker | §1 root; §3 provenance filter |
| ADR 0043 bundle mesh rule `src/key_move.rs:1005-1037`, `1401-1430`; load path `1880-1900` | any certifier of X's public key can retire and pin X | §4 |
| Revocation lifetime `src/revocation.rs:284`, `632-646` | unbounded `revoked_at` | §5 |
| Raw delivery: `raw_delivery_binding` `src/lib.rs:4591`, `raw_delivery_verified` `4617`, receiver `15909-15918`, typed dispatch `4724`, connected marking | cache match is verification | §1 root; §2 |
| `Agent::is_agent_machine_verified` `src/lib.rs:13378` (public API) | cache match is verification | §2 |
| Raw-first sends: `resolve_raw_quic_target` `src/lib.rs:9219-9276`, `connected_direct_machine` `8274`; DM registry `register_agent` `12189`, `mark_connected` `12219` | cached or registered attacker machine | §1 (no registry write from class C); §2 |
| Pinned sends: announced-binding store `src/lib.rs:3184`, `3374`; `select_pinned_binding` `290`; `pinned_binding_now` `8739`; seam `9051` | every verified announcement writes the store | §1 (class A or B only) |
| Stream and datagram gates `src/lib.rs:16284`, `16370-16465`; calls `src/calls.rs:814-841`; voice `src/voice/link_transport.rs:577`, `760` | cached machine and occupants | §2 |
| EvidenceV1 Lookup `src/evidence_wire/lookup.rs:129`, `221`, `238`, `281`; `src/evidence_wire.rs:604`, `663`, `761`, `1175` | newer discovery machine wins | §2 |
| Lazy placement mint `move_mint_placements` `src/lib.rs:13765` | discovery machine signed into owner placement | §2 (authenticated pairing required) |
| OwnerCertified verdicts `owner_cert_evidence_for` `src/server/routes/named_groups.rs:22914`; `GroupInfo::owner_cert_verdict` `src/groups/mod.rs:1569` | attacker certificate or digest | §1 root |
| Owner trust `src/owner_trust.rs:382`, `418`; share grants `src/share_grant.rs:934`, `963`, `1369`; move and revocation operations that prefer the discovery certificate (audit: `src/lib.rs:14380`, `14760`, `14815` at 601840f) | certificate deleted or replaced | §1 root |
| ForwardV2 expiry and key seeding `src/forward.rs:574-697`; direct ACK key lookup | expiry cleared, key seeded | §1 root (signatures already protect forgery) |
| Recipient pairing denial `src/lib.rs:7633`; rendezvous `ProviderSummary` key `src/lib.rs:17384` | poisoned machine or machine key | §1 root |
| Owner-sync candidate choice `src/lib.rs:16833`; `src/owner_sync.rs:2612` | cached associations | §2 |
| Dial and helper hints, relay mapping, connectivity, presence, FOAF, discovery REST and SSE, GUI names (audit low rows) | false hints and names | §1 root; display reads class A or B names only |
| Owner-roster projection `Agent::owner_issued_certificates` `src/lib.rs:15310` (reads cached certificates at `15350`) | cached certificates removed or replayed; the local-issuer filter already stops a foreign owner's certificate | §1 root; §3 provenance for every certificate it reads from discovery |
| Home anonymous-digest exception `src/server/routes/named_groups.rs:23061` (#1247) | already checks the bound machine | unchanged; its premise now holds everywhere |

### 7. Mixed versions and compatibility

**No wire change, no capability bit, no flag day.** Classification is local to each receiver.

- **Genuine publishers stay class A.** In-tree, every daemon publishes only its own agent's announcement, signed by that agent's pubsub key: the heartbeat (`src/lib.rs:4030-4113`) and `Agent::announce_identity` (`src/lib.rs:10418`; its publishes are at `10631`, `10665` and `10688`). Released versions do the same. PlumTree forwards the original envelope, so the beat stays class A after any number of hops.
- **Riders (ADR 0039)** act through the owner's daemon and publish no identity announcement of their own (`src/lib.rs:13812`). No change.
- **ACP agents and named instances** (`x0xd --name`) run their own key and publish their own beats. They stay class A.
- **Legacy republishers.** Older builds re-published received bodies under their own envelope with fresh message ids (the storm-control case). Such a copy is class B when the receiver already holds X's authenticated pairing (it then refreshes as before) and class C otherwise. A cold receiver that hears only republished copies learns X when the original arrives. That is at most one heartbeat (600 s), and PlumTree repair usually delivers the original sooner. This is the main compatibility cost.
- **Old receivers stay vulnerable.** The fix protects upgraded receivers only. Release notes must say so once the advisory is public.
- **Revocations.** Genuine issuers sign with the current time (`Agent::revoke`), so §5 rejects nothing they send unless their clock is more than 300 s fast. Their periodic republication (every 2 h at the default heartbeat, §5) delivers the record once the skew passes.
- **Bundles.** A genuine owner's bundle passes §4 at every peer that has seen one authenticated announcement or evidence record for the subject. A peer that has none rejects the bundle until it has one. Nodes republish their stored bundles on change and on a periodic fallback (`src/lib.rs:4219-4240`), so a later copy reaches that peer after it authenticates the subject. There is no pending set (D215). Today that republication also spreads an attacker's accepted bundle under each republisher's envelope; upgraded receivers reject those copies by §4.
- **State poisoned before the upgrade** (issuer revocations in `revocations.bin`, tombstones in `revocations-v2.bin`, `move-bundles.bin`, `placement-blobs.bin`, Blocked flags in `contacts.json`) survives the upgrade, because the authorizing certificate's provenance was never recorded. A load-time re-check cannot tell genuine from poisoned records, so D214 quarantines them (below).

### 8. Deferred: an agent-signed announcement version

A later ADR may add an agent-signed announcement (for example `X0A5`). It binds agent, machine, addresses, certificate digest, name, flags, `announced_at` and version under X's agent signature, and keeps the machine signature as proof of machine ownership. Such a beat is class A wherever it travels: stored as evidence, served by Lookup, read from a shard, or republished. That ADR must also state the trust policy for V2 and V3 beats, which keep this ADR's classes and never become full authority on their own.

## Consequences

### Positive

- One rule at ingest closes every confirmed consumer: the readers listed in §6 can no longer read an attacker's machine, certificate or digest for an agent that the attacker does not control.
- Revocation and bundle authority require the subject's real owner; a permanent tombstone needs that owner's key.
- No wire change; old and new genuine publishers keep working.

### Negative / Trade-offs

- Discovery from republished bodies alone stops for receivers with no authenticated pairing (§7).
- A peer that never authenticated X cannot accept X's genuine bundle or issuer revocation until it does.
- `Agent::is_agent_machine_verified` changes meaning for library users: it reads authenticated authority, not the cache.
- The D214 quarantine repairs state poisoned before the upgrade, but a genuine pre-upgrade issuer revocation or bundle tombstone is not enforced until authenticated evidence confirms its issuer, and it lapses if that never happens within 7 days.

### Neutral / Operational

- New counters: `identity_announce_unauthenticated` (class C), `revocation_future_dropped`, `activation_bundle_owner_unauthenticated`.
- The node keeps certificate provenance in memory, in a side table, because `DiscoveredAgent` is a public struct with public fields and a new field would break library users. If phase 2 persists provenance, the format follows ADR 0085.

## Validation

- **RED tests on main** (`src/server/identity_ingest_authority_tests.rs`): each drives the real identity listener through the real `PubSubManager`, runs the genuine agent-authenticated path as a control, and fails on main with `VECTOR OPEN`:
  - T1 attacker certificate authorizes revocation of X (v1 agent, v2 binding; warm and cold X);
  - T2 raw frames from the attacker machine verify as X (V2 and V3);
  - T3 raw-first and pinned resolution pick the attacker machine;
  - T4 a far-future `revoked_at` is accepted and outlives the TTL;
  - T5 a forged certificate or digest changes an OwnerCertified verdict;
  - T6 an attacker-signed ADR 0043 bundle retires and pins X.
- **Gate (RED proof):** CI on the private fork must run all six tests on unfixed main and record six `VECTOR OPEN` failures, with no `HARNESS` or `CONTROL FAILED` panic, before any phase-2 commit lands. Reason: the sentinel barriers depend on in-order local delivery inside the pinned saorsa-gossip PlumTree (`handle_message`, reached from `src/gossip/pubsub.rs:2379`), which this repository cannot prove. If that order ever broke, a vector could read closed on main, which is a false GREEN.
- All six must turn green after phase 2 with their controls still green, in CI on the private fork.
- **Test seam:** `Agent::insert_discovered_agent_for_testing` (`src/lib.rs:17485`, about 65 uses in `src/` and `tests/`) stays a test-only class A seed: it writes the discovery entry and the announced-binding store as an agent-authenticated announcement would. It is not a production authority writer, and phase 2 must not route any production path through it.
- **Phase 2 adds** tests for equal timestamps, a class B republished body that refreshes an authenticated pairing, the `find_agent` shard path, blob hydration provenance, revocation load-time bounds, restart with persisted records, and a mixed-version fixture with a v0.46.4 publisher.
- **Review trigger:** any new writer of a discovery authority field, or any new reader of `DiscoveredAgent.machine_id` or `agent_certificate` for a security decision, must name its class (A, B) or its authority store.

## Rulings at acceptance (David, 2026-10-07)

These answer the four open questions of the Proposed text.

1. **D212 (process, was question 4).** Accepted. The ADR lands on `main` together with the fix at disclosure.
2. **D213 (bound, was question 1).** `REVOCATION_MAX_FUTURE_SKEW_SECS` is 300 s.
3. **D214 (poisoned state, was question 2).** Quarantine pre-upgrade issuer revocations and bundle tombstones:
   - a quarantined record is kept but not enforced;
   - it is enforced again once authenticated evidence (§3) confirms its issuer, that is, a certificate for the subject with authenticated provenance has the record's issuer as its owner;
   - a record that is still unconfirmed 7 days after the quarantine starts lapses: it is removed;
   - Blocked flags that such a revocation set in `contacts.json` follow the same rule.
4. **D215 (bundles, was question 3).** A bundle whose subject has no authenticated owner yet is rejected. Peers rely on bundle republication. There is no pending set.

**RED proof (the Validation gate).** A private CI run on unfixed main at 3e5f538 recorded `VECTOR OPEN` for all six tests (T1 to T6) and no `HARNESS` or `CONTROL FAILED` panic.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
