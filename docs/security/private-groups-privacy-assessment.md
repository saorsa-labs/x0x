# Private Groups — Privacy Assessment

**Date:** 2026-03-19
**Branch:** `feat/mls-private-groups`
**Status:** Pre-submission assessment

---

## 1. MVP Privacy Claims

These are the exact claims this PR makes.

### What this PR claims

1. **Content confidentiality** — only invited group members can read task titles, descriptions, and state. Non-members who observe gossip traffic see only ciphertext.

2. **Write exclusion** — only group members can produce encrypted deltas that other members accept. Non-member payloads fail decryption and are dropped.

3. **Explicit opt-in** — group membership requires explicit invite acceptance. Unsigned, unverified, or wrong-recipient invites are rejected.

4. **No plaintext leakage in private-group code paths** — code introduced or modified in this PR does not log task content, decrypted payloads, key material, or unnecessary group lifecycle details at any log level in normal runtime operation.

### What "private" means in this PR

Content-confidential to invited members. Not metadata-hidden, not anonymous, not traffic-analysis resistant.

> "Private groups in this PR provide content confidentiality for members. They do not yet hide group/topic metadata from network observers."

### What this PR does not claim

- **No metadata hiding** — topic names, message timing/sizes, membership signals, and peer identities are observable.
- **No anonymity** — AgentId and MachineId are visible on the network.
- **No persistence guarantees** — group state is in-memory; process restart loses membership.
- **No multi-epoch lifecycle hardening** — epoch transitions work but are not tested under adversarial timing.
- **No replay protection across groups** — expected to fail (different keys) but not explicitly tested.
- **No production-grade observability hygiene** — the broader codebase may have logging patterns that expose metadata in ways that wouldn't meet a strict production standard. Hardening is a follow-on.

---

## 2. Known Metadata Exposures

### 2.1 Topic name visibility

**Exposure:** Group traffic uses stable, visible topic identifiers. An observer can learn that a private group exists, that it is active, and that activity is recurring over time.

**Conclusion for MVP:** Does not contradict the stated content-confidentiality claim. Follow-on work should introduce opaque topic identifiers derived from shared group material, potentially rotating by epoch to reduce long-term linkability.

### 2.2 Message timing correlation

**Exposure:** An observer watching two peers' traffic can infer they are in the same group from synchronised message bursts.

**Conclusion for MVP:** Does not contradict the stated content-confidentiality claim. Mitigation would require message batching, jitter, or cover traffic — significant protocol changes beyond this PR's scope.

### 2.3 Message size patterns

**Exposure:** Encrypted deltas have somewhat predictable size patterns. An "add task" delta is likely larger than a "claim" or "complete" delta. An observer could infer operation types from payload sizes.

**Conclusion for MVP:** Does not contradict the stated content-confidentiality claim. Mitigation would require padding encrypted payloads to a fixed size.

### 2.4 Membership signals

**Exposure:** The invite/accept handshake is a distinct message pattern — different message types, different sizes, different timing from normal task sync. An observer could detect when new members are joining a group.

**Conclusion for MVP:** Does not contradict the stated content-confidentiality claim. Could be partially mitigated by making invite/accept traffic indistinguishable from normal sync traffic.

### 2.5 Peer identity visibility

**Exposure:** AgentId and MachineId are visible at the transport layer. An observer can identify which agents are communicating, even if they cannot read the content.

**Conclusion for MVP:** Does not contradict the stated content-confidentiality claim. Anonymity is explicitly a non-claim.

---

## 3. Go/No-Go Judgement

None of the identified metadata exposures contradict the stated MVP claim of content confidentiality for group members. The PR explicitly does not claim metadata privacy, anonymity, or traffic-analysis resistance. Each exposure is understood and classified.

**Judgement: GO** — contingent on all automated tests passing and logging audit clean.

---

## 4. Automated Test Coverage

### Existing tests (pre-validation)

| Test | Claim covered |
|------|--------------|
| `test_non_member_cannot_decrypt` | Content confidentiality — cryptographic boundary between groups |
| `test_non_member_encrypted_mutation_rejected` | Write exclusion — non-member deltas rejected |
| `test_wrong_agent_cannot_accept_welcome` | Explicit opt-in — wrong-recipient rejection |
| `test_end_to_end_create_invite_accept_encrypted_sync` | Full invite→accept→encrypted sync lifecycle |
| `test_nonce_counter_increments` | Each encryption uses a unique nonce |
| `test_group_collaboration_via_rest` | **Release-blocking** — A creates task → B sees → B claims → A sees → B completes → A sees |
| `test_non_member_excluded_via_rest` | C cannot access A's group via REST — all return 404 |
| `test_reject_invite_via_rest` | B receives invite, rejects, doesn't join group |

### New privacy validation tests

| Test | Claim covered | Result |
|------|--------------|--------|
| `test_ciphertext_does_not_contain_plaintext_marker` (Test A) | Content confidentiality — canary string not present in encrypted output | PASS |
| `test_tampered_welcome_payload_rejected` (Test B) | Explicit opt-in — tampered welcome bytes cause rejection | PASS |
| `test_malformed_payloads_do_not_alter_state` (Test C) | Robustness — garbage/corrupted/invalid payloads don't crash or alter state | PASS |
| `test_logging_does_not_expose_plaintext_canary` (Test D) | No plaintext leakage — canary not found in tracing output | PASS |

---

## 5. Logging Audit

**Date performed:** 2026-03-19

**Files reviewed:**
- `src/crdt/sync.rs` — logs error categories only ("decryption failed", "merge failed"), not content
- `src/crdt/encrypted.rs` — no logging
- `src/mls/group.rs` — no logging
- `src/mls/cipher.rs` — no logging
- `src/mls/welcome.rs` — no logging
- `src/mls/keys.rs` — no logging
- `src/gossip/pubsub.rs` — logs message types, auth failures, and sender AgentIds; no payload content
- `src/gossip/runtime.rs` — logs stream types and dispatch errors; no content
- `src/bin/x0xd.rs` — logs operation failure categories (e.g. "failed to publish encrypted add_task delta: {e}"); no task content, keys, or group membership details

**Findings:** No plaintext task content, decrypted payloads, or key material logged in any privacy-sensitive code path. AgentId/MachineId are logged at startup (informational, consistent with non-anonymity non-claim). Topic names appear at debug level in pubsub (consistent with metadata visibility non-claim).

**Two test-only `eprintln!` calls** remain in `src/network.rs` (test `test_mesh_connections_are_bidirectional`). These are test diagnostic output, not production paths, and do not affect the privacy claim.

**Result:** Clean — no issues requiring remediation.

---

## 6. Recommended Follow-On Work

1. **Opaque topic identifiers** — replace readable topic names with identifiers derived from group secret/context. Only group members should be able to derive the topic identifier. Consider epoch-based rotation.
2. **Message padding** — pad encrypted payloads to fixed sizes to prevent operation-type inference.
3. **Invite traffic normalisation** — make invite/accept handshake traffic indistinguishable from normal sync traffic.
4. **Production observability hardening** — review broader codebase logging against a stricter production standard.
5. **Security review gate process** — lightweight review checklist for future PRs touching private-group code.
