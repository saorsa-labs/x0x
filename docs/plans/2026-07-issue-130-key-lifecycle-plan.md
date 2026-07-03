# Implementation Plan — Issue #130: Key lifecycle (expiry, renewal, revocation)
(Produced by plan-130 read-only planning agent, 2026-07-03. Hand verbatim to the implementation agent.)

## 0. Context and investigated facts

All paths relative to /Users/davidirvine/Desktop/Devel/projects/x0x.

**The "verified" gates (four consumers, one annotation source per transport path):**

1. **PubSub signature verification** — src/gossip/pubsub.rs:1044-1064: incoming v2 pubsub messages carry the sender's ML-DSA-65 public key; `verify_signature` checks it and sets `PubSubMessage.verified` (struct at src/gossip/pubsub.rs:162-178, also carries `trust_level`). Self-authenticating (AgentId = SHA-256 of pubkey) — needs no identity cache.
2. **Gossip-DM inbox** — src/dm_inbox.rs `InboxPipeline::handle_incoming` (~line 195): requires `msg.verified`, decodes the `DmEnvelope`, verifies envelope signature, checks `envelope.sender_agent_id == pubsub_sender`, then builds `DmTypedPayload { verified: true, trust_decision, .. }` (src/dm_inbox.rs:429). This payload is what exec gates on.
3. **Exec service** — src/exec/service.rs:767-778: denies `!inbound.verified` (DenialReason::UnverifiedSender) then `trust_decision != Some(TrustDecision::Accept)`. Gate order pinned by tests at service.rs:2438-2699.
4. **Group metadata apply gate** — src/server/mod.rs:7678-7688: `bypass_verified = matches!(...)` for MemberRemoved{commit: Some} / GroupDeleted (self-authenticating signed commits, delivery-critical for the removed peer); `if !verified && !bypass_verified { reject }`.

Cache backing the annotations: `Agent::is_agent_machine_verified` (src/lib.rs:6677) reads `identity_discovery_cache` (`DiscoveredAgent` entries); populated from `IdentityAnnouncement`s (IDENTITY_ANNOUNCE_TOPIC = "x0x.identity.announce.v2", src/lib.rs:345) which optionally embed an `AgentCertificate`.

**Identity types** (src/identity.rs): MachineKeypair, AgentKeypair (:228), UserKeypair (:307), AgentCertificate (:419) with fields user_public_key, agent_public_key, signature, issued_at; signed message `b"x0x-agent-cert-v1" || user_pubkey || agent_pubkey || issued_at` (CERT_PREFIX :431, build_message ~:538, verify() :477). **No revocation or expiry concept exists anywhere today.**

**Storage** (src/storage.rs): `SerializedKeypair { public_key: Vec<u8>, secret_key: Vec<u8> }` (:19-26) via plain bincode; files ~/.x0x/machine.key, agent.key, user.key, agent.cert (AGENT_CERT_FILE :104, cert save/load :452-491, path-scoped variants e.g. save_agent_certificate_to :479). **bincode 1.x cannot skip a missing trailing Option field — old files fail to decode as a grown struct** (behavior documented by existing test identity_announcement_backward_compat_no_nat_fields, src/lib.rs:9782-9830).

**Announcement wire**: IdentityAnnouncement/UserAnnouncement/MachineAnnouncement are bincode with reject_trailing_bytes() (src/lib.rs:1505-1537). UserAnnouncement (src/lib.rs:1021) is a user-signed list of AgentCertificates. Precedent: the NAT-fields change was a documented non-transparent protocol evolution ("nodes must upgrade together"; fleet self-updates).

**Propagation patterns**: well-known topic consts (src/lib.rs:345-359, src/upgrade/manifest.rs:11 RELEASE_TOPIC), periodic identity heartbeat re-announce (interval const near src/lib.rs:656), groups OR-Set anti-entropy (src/groups/).

**Surfaces**: routes still live in src/server/mod.rs (identity block :1582-1610) — the routes/ extraction is in flight; place handlers wherever identity routes live at implementation time. Registry: src/api/mod.rs EndpointDef entries (category "identity"). CLI: src/bin/x0x.rs Commands enum (:57) + src/cli/commands/identity.rs. Daemon config: src/server/state.rs DaemonConfig (:138, identity_dir at :229). ADRs: docs/adr/, **next number is 0018**.

---

## 1. Design decisions

### D1 — What v1 renews, expires, revokes

| Layer | Expiry | Renewal | Revocation |
|---|---|---|---|
| AgentCertificate | `not_after: Option<u64>` — the only network-enforced expiry | `x0x identity renew` re-issues cert (user key), no downtime | implied by agent/user revocation |
| Agent key | not_after on the key file (local record only) | out of scope v1 (new AgentId = new identity) — ADR "future work" | RevokedSubject::Agent(AgentId) |
| Machine key | not_after on the key file (local record only) | out of scope v1 (new MachineId = new QUIC PeerId ⇒ inherently a reconnect) — ADR | RevokedSubject::Machine(MachineId) |

Rationale: machine key is the QUIC transport identity — rotating it IS downtime by definition; agent key is the addressable identity — rotating it orphans contacts/groups. The AgentCertificate is the only credential re-issuable transparently (peers already handle cert updates via re-announcement). This satisfies "renewal round-trips without downtime" honestly.

### D2 — Key-file format versioning (the no-breaking-change requirement)

New container: `magic b"X0XK" (4 bytes) || version u8 (=2) || bincode(SerializedKeypairV2 { public_key, secret_key, not_after: Option<u64> })`. Cert file gets magic b"X0XC" similarly.

- **Read**: file starts with magic → parse V2; otherwise → legacy bincode(SerializedKeypair). Unambiguous: a legacy file's first 8 bytes are the LE u64 length of the ML-DSA-65 public key (1952 = A0 07 00 00 00 00 00 00); it can never begin with 'X' (0x58).
- **Write**: **legacy format when not_after is None; V2 only when Some.** Preserves DOWNGRADE compatibility too (an older x0xd after rollback still reads keys of users who never set expiry) — important given the self-update/rollback system.
- Rejected alternatives: enum-wrapping (u32 variant tag could collide with legacy length prefixes, forces rewriting every existing file); trailing-Option reliance (bincode 1.x hard-fails, per src/lib.rs:9782 test).

### D3 — AgentCertificate expiry without breaking old certs

Add trailing `not_after: Option<u64>` to AgentCertificate + new constructor `issue_with_expiry(user_kp, agent_kp, not_after)`. **Signature compatibility rule**: when not_after is None, the signed message is byte-identical to v1 (x0x-agent-cert-v1 prefix, no extra bytes); when Some, use prefix b"x0x-agent-cert-v2" and append not_after LE bytes. verify() (src/identity.rs:477) reconstructs based on presence. Consequences:

- Old certs loaded from legacy files (decoded via a private AgentCertificateV1Disk shape, mapped with not_after: None) verify unchanged. **Absence of expiry = valid, forever** (default-safe).
- not_after is signature-covered when present — a stripped/tampered expiry fails verification (pin with a test).
- **Wire impact**: announcements embedding a cert change encoding (bincode is positional). Mitigating facts: (a) announcements WITHOUT a user identity carry agent_certificate: None (a single 0x00 byte) — those stay byte-compatible across versions; (b) the codebase's blessed stance for cert-carrying announcements is coordinated fleet upgrade (src/lib.rs:9816-9830; fleet self-updates). Document in ADR. Alternative (bump topics to .v3, dual-publish) is heavier and not required — flag in ADR as escape hatch.

### D4 — Revocation record

New module src/revocation.rs:

```rust
pub enum RevokedSubject { Agent(AgentId), Machine(MachineId) }
pub struct RevocationRecord {
    pub subject: RevokedSubject,
    pub issuer_public_key: Vec<u8>,   // ML-DSA-65
    pub revoked_at: u64,              // informational
    pub reason: Option<String>,
    pub signature: Vec<u8>,           // over b"x0x-revocation-v1" || subject tag+id || issuer_pubkey || revoked_at || reason
}
```

**Who may revoke — exactly two rules, both verifiable without trust state:**
1. **Self-revocation**: issuer key IS the subject (hash of issuer_public_key == the AgentId, or == the MachineId). Always valid — an attacker "revoking" a stolen key only helps the victim.
2. **Issuer revocation**: for Agent subjects, issuer key hashes to the UserId appearing in a known AgentCertificate for that agent (check discovery cache / cert carried in the same gossip batch). The user who vouched can un-vouch.

No third-party revocation in v1. **No un-revocation in v1** — the set is grow-only (G-Set), which eliminates the entire replay/rollback class: replaying a revocation is idempotent and there is no "restore" message to replay. Dedupe by BLAKE3 hash of canonical record bytes. State the no-un-revoke rule explicitly in the ADR.

**Storage**: in-memory RevocationSet (HashSet<AgentId> + HashSet<MachineId> for O(1) gate checks + HashMap<[u8;32], RevocationRecord> for rebroadcast) as Arc<RwLock<RevocationSet>> on Agent. Persisted to <identity_dir>/revocations.bin (magic b"X0XR" + bincode Vec<RevocationRecord>) via the existing write_private_file pattern; loaded at agent build. Use identity_dir scoping (multi-instance daemons already scope identity there per the #97 agent.cert fix; DaemonConfig.identity_dir src/server/state.rs:229). Not KvStore — the gate must be consultable synchronously at agent-layer with zero daemon dependency.

**Propagation**: new const `REVOCATION_TOPIC: &str = "x0x.revocation.v1"` next to the announce topics (src/lib.rs:345-359). Payload = bincode Vec<RevocationRecord> (reject_trailing_bytes + size limit like deserialize_machine_announcement, src/lib.rs:1503).
- On issue: persist, apply locally, publish immediately.
- On receipt: verify each unknown record against rules 1/2, merge, persist, enforce (D5).
- **Anti-entropy**: piggyback on the identity heartbeat cadence (interval const near src/lib.rs:656) — every heartbeat, publish the full local revocation set; also once after join_network. Records are rare and ~5.3 KB each (pubkey 1952 B + sig 3309 B); full-set periodic broadcast is fine for v1 and is what makes it partition-tolerant (a daemon offline during the revocation learns from any peer's next rebroadcast). Known records are hash-deduped before re-verification. ADR flags digest-exchange (OR-Set style like groups tag shards) as the scale-up path — not needed now.

### D5 — Enforcement points (fail closed on revocation; absence of expiry = valid)

Do NOT thread state into src/gossip/pubsub.rs — enforce at consumers, which all have Agent/AppState access:

1. **Announcement ingest** (identity announce handler in src/lib.rs populating identity_discovery_cache): drop announcements from revoked agents/machines; drop (or cache without user attestation) announcements whose embedded cert is expired (now > not_after + skew) or fails verify. Starves the verified annotation for revoked peers at the source.
2. **is_agent_machine_verified** (src/lib.rs:6677): read-time checks — return false if agent or bound machine is revoked, or if the cached cert is expired. Store `cert_not_after: Option<u64>` on DiscoveredAgent at ingest so this is a field compare (REST responses are serde_json — additive field safe).
3. **DM inbox** (src/dm_inbox.rs handle_incoming, right after the envelope-signature check ~line 268): drop when envelope.sender_agent_id is revoked (add a `dropped_revoked` counter beside record_incoming_signature_failed). Kills DMs AND exec (exec rides typed DM payloads) in one place; src/exec/service.rs:767-778 needs no change and inherits the denial.
4. **Group metadata gate** (src/server/mod.rs:7678-7688): insert the revocation check BEFORE the bypass_verified branch — a revoked sender fails closed even for self-authenticating events. This does NOT regress #99/MemberRemoved semantics: bypass_verified exists because ABSENCE of a cache entry is racy; revocation is POSITIVE knowledge and is exactly what must not be bypassed. Pin with a test that a merely-unverified (not revoked) sender's MemberRemoved{commit: Some} still applies.
5. **Active drop on receipt**: when a revocation is applied — (a) evict subject from identity_discovery_cache, machine cache, bootstrap cache; (b) close any live connection to the revoked MachineId — implementer: check NetworkNode/ant_quic::Node for a disconnect/close API (src/network.rs); if none exposed, message-layer denial + cache eviction (no re-dial) is v1 behavior and the ADR notes the QUIC connection lingers until idle timeout; (c) mark the contact Blocked-equivalent — TrustEvaluator::evaluate (src/trust.rs:106) already rejects Blocked first, which is how "cached-peer trust honors it on receipt" is satisfied.

### D6 — Expiry check + clock skew

One helper, one constant, used everywhere:

```rust
// src/identity.rs
pub const EXPIRY_CLOCK_SKEW_SECS: u64 = 300;
pub fn is_expired(not_after: Option<u64>, now_unix: u64) -> bool {
    match not_after { None => false, Some(t) => now_unix > t.saturating_add(EXPIRY_CLOCK_SKEW_SECS) }
}
```

None ⇒ never expired (default-safe; existing deployments unaffected). Optional hardening: reject certs with issued_at > now + EXPIRY_CLOCK_SKEW_SECS (future-dated).

### D7 — Renewal without downtime

POST /identity/renew (body { "ttl_secs": Option<u64> } or { "not_after": Option<u64> }; both null ⇒ non-expiring cert):
1. Load user keypair (storage::load_user_keypair); 409 if no user identity (cert renewal requires the issuing user key — opt-in identity, never auto-generated).
2. AgentCertificate::issue_with_expiry(&user_kp, &agent_kp, not_after).
3. Persist via path-scoped save_agent_certificate_to (src/storage.rs:479) using the daemon's scoped cert path.
4. Swap in memory: today the cert sits immutably in Identity/Agent (src/identity.rs:563) — refactor the agent-held cert slot to Arc<RwLock<Option<AgentCertificate>>> (or add Agent::replace_agent_certificate), auditing readers (announcement build src/lib.rs:5869-5943, UserAnnouncement::sign path :5229, /agent handler).
5. Trigger immediate identity re-announce (+ user announce) so peers refresh the cached cert.

Machine key, agent key, QUIC connections, gossip sessions: untouched ⇒ zero interruption.

---

## 2. REST / CLI surface

src/api/mod.rs registry additions (category "identity", alongside the /agent/* block at :84-136):

| Method | Path | cli_name | Description |
|---|---|---|---|
| POST | /identity/renew | identity renew | Re-issue AgentCertificate (user key), optional expiry |
| POST | /identity/revoke | identity revoke | Sign + publish + persist a revocation (self or issued-agent) |
| GET | /identity/revocations | identity revocations | List known revocation records |

Routes: register in the identity block of src/server/mod.rs (:1582-1610) OR the extracted identity routes file if the routes/ extraction has landed — check before implementing. Handlers follow the agent_verify pattern. CLI: new `Identity { sub: IdentitySub }` variant in Commands (src/bin/x0x.rs:57), handlers in src/cli/commands/identity.rs (thin DaemonClient wrappers — see `announce` there for the shape). /identity/revoke body: { "subject": "agent"|"machine", "id": "<hex64>", "reason": "..." }; self-revocation when the id is the daemon's own.

---

## 3. Test plan

| Test | Tier | Pins |
|---|---|---|
| cert_v1_without_not_after_still_verifies | unit src/identity.rs | old certs (no field) verify forever — the no-break guarantee |
| cert_with_not_after_signs_and_verifies | unit | v2 message construction round-trip |
| cert_not_after_tamper_fails_verification | unit | expiry is signature-covered; stripping ≠ extending validity |
| legacy_keyfile_bytes_load_via_new_loader (serialize with a literal old-shape struct) | unit src/storage.rs | old ~/.x0x/*.key files keep working — acceptance criterion |
| keyfile_without_expiry_writes_legacy_format | unit | downgrade compatibility is intentional, not accidental |
| v2_keyfile_roundtrip_preserves_not_after | unit | new format works |
| expiry_allows_within_skew / expiry_rejects_beyond_skew (now−120 s OK; now−600 s refused) | unit | the 5-min tolerance is load-bearing |
| revocation_self_signed_verifies / revocation_user_signed_for_certified_agent_verifies / revocation_unrelated_key_rejected | unit src/revocation.rs | the two authority rules and nothing more |
| revocation_set_merge_grow_only_idempotent + revocation_set_persists_and_reloads | unit | partition-tolerance building blocks |
| expired_cert_announcement_not_trusted | integration (announcement ingest) | expired credential refused at the gate feeding `verified` |
| dm_from_revoked_sender_dropped | integration (dm_inbox pipeline, injected set) | acceptance: DM from revoked peer denied |
| exec_request_from_revoked_peer_denied | integration (mirror src/exec/service.rs:2438+ style) | acceptance: exec from revoked peer denied |
| member_removed_bypass_survives_revocation_checks | integration (server gate) | revocation must not break the #99 self-authenticating paths |
| revocation_propagates_two_daemons_drops_peer | e2e (tests/daemon_api_integration.rs pattern) | B self-revokes → A refuses B's DM after propagation; A's cache evicted |
| revocation_learned_after_restart (daemon offline during publish, learns via heartbeat rebroadcast) | e2e | partition tolerance / eventual propagation |
| renew_no_interruption (continuous DM ping during renew; zero failures; peer sees new issued_at) | e2e | acceptance: renewal round-trips without downtime |

---

## 4. Stepwise task breakdown (one reviewable commit each; [SEC] = security-critical, needs independent review)

1. **Versioned key/cert file container** — src/storage.rs: magic+version container, legacy fallback read, write-legacy-when-no-expiry. Tests: legacy-bytes load, format-choice, v2 round-trip. Accept: all existing storage tests green; new tests pin both directions. [SEC]
2. **AgentCertificate.not_after + v2 signed message** — src/identity.rs: field, issue_with_expiry, conditional build_message, verify() update, is_expired + EXPIRY_CLOCK_SKEW_SECS. Accept: v1 certs verify; tamper test red-before/green-after. [SEC]
3. **Revocation module** — new src/revocation.rs: record, sign/verify, authority rules, RevocationSet, persistence. Pure, no wiring. Accept: unit tests green; no .unwrap() in production paths. [SEC]
4. **Gossip propagation** — REVOCATION_TOPIC const, subscribe task in Agent startup, publish-on-issue, heartbeat piggyback rebroadcast, startup load, size-limited decode. Accept: two-agent in-process test shows merge.
5. **Enforcement wiring** — the five points in D5: announcement ingest, is_agent_machine_verified + DiscoveredAgent.cert_not_after, dm_inbox drop + counter, server gate ordering vs bypass_verified, cache eviction/contact-block/disconnect-on-receipt. Accept: integration tests green; exec tests at service.rs:2438+ untouched and green. [SEC — the heart of the issue; gate must be fail-closed on revocation, fail-open on absent expiry]
6. **Renew flow** — mutable cert slot on Agent, POST /identity/renew handler, re-announce trigger. Accept: renew round-trips in a single-daemon test; readers audited (src/lib.rs:5869, :5229).
7. **Revoke + list REST/CLI + registry** — endpoints, EndpointDef entries, Commands::Identity subtree. Accept: tests/api_coverage.rs / api_manifest.rs pass (registry and router in sync).
8. **Two-daemon e2e** — the three e2e tests above in tests/, following daemon_api_integration.rs conventions (X0X_TEST_BINARY override, --name/--api-port/--no-hard-coded-bootstrap).
9. **ADR-0018 + docs** — docs/adr/0018-key-lifecycle-expiry-renewal-revocation.md (expiry semantics incl. absence=valid, v1/v2 cert message rule, revocation authority rules, grow-only/no-un-revoke, propagation + heartbeat anti-entropy, 300 s skew, wire-compat stance for cert-carrying announcements, QUIC-connection-linger limitation, deferred: key rotation, un-revocation, digest anti-entropy). Update docs/api-reference.md, CHANGELOG; mirror to Obsidian vault per repo convention.

**Sequencing**: 1→2→3 (2 and 3 independent after 1); 4-5 depend on 3; 6-7 depend on 2; 8 last. Every step keeps `just check` green (fmt, clippy -D warnings, nextest --all-features --workspace).

**Known risks**: (a) the cert-slot refactor in step 6 touches the announcement build path — the ML-DSA announce-signature area has prior transport-level bug history (ant-quic zero-gap reassembly), so any new sig failures there are likely transport, not this change; (b) identity_discovery_cache writes race the verified annotation (the original reason for bypass_verified) — keep revocation checks read-only against the RwLock and never hold it across .await in the DM inbox loop (that loop also publishes ACKs and must not stall — see the non-blocking comment at src/dm_inbox.rs:429+); (c) step 5's gate-order test must prove revocation beats bypass_verified while plain-unverified does not regress.
