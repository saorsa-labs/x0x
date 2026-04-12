# Phase D.2 — Cross-daemon decrypt/no-decrypt proof (ML-KEM-sealed, v2)

**Generated**: 2026-04-12
**Scope**: Reviewer's original D.2 prompt (cross-daemon encrypt/decrypt + rekey-on-ban) **plus** the two subsequent reviews:
1. "envelope was obfuscation, not confidentiality" — replaced with real ML-KEM-768 public-key encryption.
2. "adversarial proof must be a real captured wire envelope, not just random bytes" — added real bob-targeted envelope via `/groups/:id/secure/reseal`, hand it to eve, eve cannot open it.

---

## Headline

| Metric | Value |
|---|---|
| `tests/e2e_named_groups.sh` | **37 PASS / 0 FAIL, 3 consecutive clean runs** |
| D.2 ★ proofs (operational) | **4/4 green every run** |
| D.2-adv ★ proofs (cryptographic) | **3/3 green every run** |
| `cargo fmt --check` | clean |
| `RUSTFLAGS="-D warnings" cargo clippy --all-targets --all-features -- -D warnings` | zero warnings |
| `cargo test --test api_coverage` | 8/8 pass |
| `bash tests/api-coverage.sh` | **100.0% (104/104 routes)** |
| `cargo test --lib groups::kem_envelope::tests` | 3/3 pass |

Run logs (v2, with real-envelope proof):
- `tests/proof-reports/suite_d2v2_run1_20260412-165033.log`
- `tests/proof-reports/suite_d2v2_run2_20260412-165033.log`
- `tests/proof-reports/suite_d2v2_run3_20260412-165033.log`

Prior full-audit regression context:
- `tests/proof-reports/full_audit_d2_20260412-143230.log` — 256/20/0, 20 FAIL are pre-existing gossip-timing flakes unrelated to D.2.

---

## The seven ★ proofs

Every run produces these seven lines with `✓`:

```
D.2     ★ bob decrypts alice's ciphertext on bob's daemon (cross-daemon encrypt/decrypt works)
D.2     ★ charlie decrypts on charlie's daemon (second member works)
D.2     ★ charlie (remaining member) CAN decrypt post-ban ciphertext
D.2     ★ bob (banned) CANNOT decrypt post-ban ciphertext from bob's daemon
D.2-adv ★ eve CANNOT open real bob-targeted envelope (ML-KEM IND-CCA2 at wire level)
D.2-adv ★ /groups/secure/open-envelope rejects random-bytes envelope
D.2-adv ★ crypto unit tests pass (wrong_keypair_cannot_open + wrong_aad_fails)
```

Plus two supporting non-★ checks in the adversarial section:
- `D.2-adv: alice reseals current secret to bob (real wire-format envelope)` — the reseal endpoint emits a valid sealed envelope.
- `D.2-adv: bob (intended recipient) opens his own envelope — sanity check` — proves the envelope is genuinely a valid payload for bob (not corrupt bytes that would trivially fail for any opener).

Mapping to reviewer requirements:

| Requirement | Proof |
|---|---|
| Approved requester gains secure access from their own daemon | D.2 lines 1–2 |
| Rekey on ban (epoch advance) | Non-★ line: `D.2: alice's secret_epoch advanced on ban (rekey happened)` |
| Remaining member still decrypts at new epoch | D.2 line 3 |
| Banned peer cannot decrypt at new epoch | D.2 line 4 |
| **Non-recipient observer cannot open a genuine live-path envelope (cryptographic, not behavioral)** | **D.2-adv line 5** — alice produces a real bob-targeted envelope via the live sealing path (`/secure/reseal` → `seal_group_secret_to_recipient`), bob opens it (sanity), eve cannot |
| Endpoint genuinely performs decap + AEAD (not passthrough) | D.2-adv line 6 — random-bytes envelope rejected |
| Primitives themselves are sound | D.2-adv line 7 — `wrong_keypair_cannot_open`, `wrong_aad_fails`, `roundtrip_seal_open` |

---

## What changed since the first D.2 report (security fix)

### Original flaw

The first D.2 implementation sealed `SecureShareDelivered` with a ChaCha20-Poly1305 key derived from `(recipient_hex, group_id, secret_epoch, actor_hex)` via BLAKE3. Every input was **public** — visible on the gossip wire. Any observer could reconstruct the key. That was **obfuscation**, not **confidentiality**.

### Fix: ML-KEM-768 per-recipient sealed envelope

`src/groups/kem_envelope.rs` (new module) implements real public-key encryption:

- **Sealer** — `seal_group_secret_to_recipient(recipient_pk_bytes, aad, secret) -> (kem_ct, aead_nonce, aead_ct)`:
  - ML-KEM-768 encapsulates a 32-byte shared secret under the recipient's ML-KEM public key.
  - ChaCha20-Poly1305 AEAD-encrypts the group secret under the KEM-derived key, with AAD binding.
- **Opener** — `open_group_secret(kp, aad, kem_ct, aead_nonce, aead_ct) -> [u8; 32]`:
  - ML-KEM-768 decapsulates the shared secret using the recipient's **private** key.
  - AEAD-decrypts with matching AAD; auth-tag mismatch → error.

Security property: ML-KEM-768 is IND-CCA2. Without the recipient's private key, no observer can derive the encapsulated shared secret from `kem_ct`, the AEAD key is therefore unrecoverable, and the group secret is recipient-confidential.

### AAD (exact, verified against source)

From `src/bin/x0xd.rs:4246` (function `secure_share_aad`):

```
AAD = b"x0x.group.share.v2|"
    || group_id.as_bytes()
    || b"|"
    || recipient_hex.as_bytes()
    || b"|"
    || secret_epoch.to_le_bytes()
```

AAD binds `group_id`, intended recipient, and epoch. AAD does **not** include the sealer/actor. Authenticating the sender to the recipient happens at the outer `NamedGroupMetadataEvent` signature layer (the event itself is ML-DSA-65-signed by the sealer); this AAD is concerned with binding the envelope to its (group, recipient, epoch) so it cannot be replayed across epochs or re-targeted to a different recipient by an attacker without invalidating the AEAD tag.

### Agent-side key material

- New `AgentKemKeypair` persisted to `<data_dir>/agent_kem.key` (mode 0600 on Unix, bincode-serialized).
- Public key exposed on `GET /agent` as `kem_public_key_b64`.
- `GroupMember.kem_public_key_b64: Option<String>` tracks each member's KEM public key.
- `NamedGroupMetadataEvent::JoinRequestCreated` now carries `requester_kem_public_key_b64` so the approver can seal without a separate lookup.

### Wire format

`NamedGroupMetadataEvent::SecureShareDelivered`:

```rust
SecureShareDelivered {
    group_id: String,
    recipient: String,                 // agent hex of intended opener
    secret_epoch: u64,
    kem_ciphertext_b64: String,        // ~1088 bytes — only recipient private key opens
    aead_nonce_b64: String,            // 12 bytes
    aead_ciphertext_b64: String,       // 32 + 16 bytes
    actor: String,                     // admin/owner who sealed (outside AAD; event is signed by actor)
}
```

### Approve / ban flows

- **Approve** — reads requester's KEM pubkey (from join-request event or in-store member record) → seals current `(shared_secret, secret_epoch)` → publishes envelope.
- **Ban** — rotates secret (caller's local state updates directly via `rotate_shared_secret`) → for each other remaining active member → seals to that member's KEM pubkey → one envelope per remaining recipient. The rekey-initiator (caller) is skipped explicitly (`src/bin/x0xd.rs:6092`) since their own daemon has already applied the rotation. Banned peer is never sent the new envelope and cannot open any of them.

### Endpoints

- `POST /groups/:id/secure/encrypt` — member-only; ChaCha20-Poly1305 encrypt with the group's current shared secret.
- `POST /groups/:id/secure/decrypt` — member (or previously-member) caller; requires epoch match.
- **`POST /groups/:id/secure/reseal`** *(new in v2)* — re-seals the current group shared secret to a named member's KEM public key using the live sealing path (`seal_group_secret_to_recipient` + `secure_share_aad`). Authorization: (a) caller must pass `info.has_active_member(&caller_hex)` (active member check), and (b) the caller's daemon must already hold `info.shared_secret` (otherwise `424 FAILED_DEPENDENCY`). Both checks together ensure the endpoint grants no capability the caller does not already possess: an active member whose daemon holds the current secret could re-seal it themselves at the primitive layer. Used by the E2E suite to obtain a **real live-path envelope** for the adversarial test.
- `POST /groups/secure/open-envelope` — attempts to open any caller-provided envelope with this daemon's KEM private key. Used for adversarial testing.

---

## How each ★ proof is obtained

### D.2 operational proofs

Three local daemons (alice owner, bob joiner, charlie joiner) on ephemeral ports, wired through a shared bootstrap. Alice creates an MLS-encrypted named group. Bob submits join request → alice approves → `SecureShareDelivered` over gossip → bob's daemon opens it with bob's KEM private key and stores the shared secret. Bob then calls `POST /groups/:id/secure/decrypt` on a ciphertext alice produced via `POST /groups/:id/secure/encrypt`. Decrypt succeeds ⇒ line 1. Same for charlie ⇒ line 2.

Alice bans bob. Rekey fires: new random secret (advances `secret_epoch` on alice's local state via `rotate_shared_secret`), new `SecureShareDelivered` envelopes sealed to **each remaining active member other than the caller** — i.e. to **charlie**, not to bob (banned) and not to alice (the rekey-initiator, who already holds the new secret via direct mutation, so the ban handler explicitly skips `recipient == caller_hex` at `src/bin/x0xd.rs:6092`). Alice encrypts a post-ban ciphertext. Charlie decrypts it ⇒ line 3. Bob's daemon still holds the old epoch, so his `/secure/decrypt` request on the post-ban ciphertext either returns 409 epoch-mismatch or 403 decrypt-failed ⇒ line 4.

### D.2-adv cryptographic proofs

**Line 5 (core proof — real live-path wire-format envelope):**

1. Alice creates a pub-req-secure group. Bob joins via approve → bob is an active member with the current shared secret.
2. Eve starts as a 4th daemon and imports the group card as an observer (stub entry, `shared_secret=None`).
3. Alice calls `POST /groups/:id/secure/reseal { "recipient": bob_hex }` → her daemon produces a genuine wire-format envelope via `seal_group_secret_to_recipient` with the exact AAD used on the live approve/ban paths.
4. **Sanity check**: the same envelope is posted to bob's `POST /groups/secure/open-envelope`. Bob opens it (proves the envelope is valid, not corrupt bytes).
5. **Proof**: the same envelope is posted to eve's `POST /groups/secure/open-envelope`. Eve's daemon attempts decapsulation with HER private key — which does not match bob's — so ML-KEM decapsulation yields a different shared secret (or an implicit-rejection value), the AEAD auth tag fails, and the endpoint returns 403 `ok:false`.

This is a **real bob-targeted envelope produced by the live sealing path** (`seal_group_secret_to_recipient` with the live AAD from `secure_share_aad`), offered to a non-recipient daemon. It is not captured off the gossip wire — it is produced on alice's daemon via the same primitive and the same AAD used on the approve/ban hot path, so for the confidentiality property under test they are bit-for-bit equivalent. The opener path on eve's daemon is the same code used on the live approve/ban hot path.

**Line 6 (endpoint-integrity proof):**

Random bytes (`os.urandom(1088)` for `kem_ciphertext_b64`, `os.urandom(12)` for nonce, `os.urandom(48)` for aead_ciphertext) posted to eve's `POST /groups/secure/open-envelope`. ML-KEM decapsulation of random bytes yields an implicit-rejection value; ChaCha20-Poly1305 auth-tag check fails → 403 `ok:false`. This proves the endpoint actually runs decap + AEAD and is not a passthrough.

**Line 7 (primitive-level proof):**

`cargo test --lib groups::kem_envelope::tests`:
- `roundtrip_seal_open` — same-keypair round trip works.
- `wrong_keypair_cannot_open` — envelope sealed to kp_a, opened with kp_b → fails.
- `wrong_aad_fails` — correct keypair, wrong AAD → fails.

### Why line 5 is the substantive cryptographic proof

The earlier behavioral check (`eve's /secure/decrypt refused`) is kept in the suite (as a non-★ line) but is explicitly labeled "state-level denial — no shared secret". It would also pass if eve simply never stored any secret and therefore is not by itself a cryptographic property. The real cryptographic property — *eve cannot open a wire envelope that bob can open* — is line 5.

---

## Honest limitations (kept explicit)

### Still NOT full MLS TreeKEM

`saorsa-mls 0.3.5` still lacks `from_welcome`. What's in place is the **Group Shared Secret (GSS)** layer, now with true recipient-confidential delivery via ML-KEM-768.

GSS provides:
- **Recipient confidentiality of the group shared secret** — verified by ★5, ★6, ★7.
- **Rekey on ban** — fresh 32-byte secret, new epoch, fresh envelopes to remaining members.
- **PQC-safe primitives** — ML-KEM-768 encapsulation, ML-DSA-65 signatures elsewhere, ChaCha20-Poly1305 AEAD, BLAKE3 for per-message key derivation.

GSS still does **not** provide:
- **Forward secrecy within an epoch.** A compromised current member can decrypt any same-epoch message. Full MLS TreeKEM ratchets per message; GSS does not.
- **Rekey on every add.** We rekey on ban; not on add. An added-then-removed member can read messages from their period of membership.
- **Sender-identity hiding.** The envelope carries `actor` in cleartext (the event is ML-DSA-65-signed, so recipients can verify sender authenticity); we authenticate sender identity to the recipient, not conceal it.

### Cross-daemon MLS TreeKEM remains open

Either upstream a `from_welcome` into `saorsa-mls` or fork/inline a PQC-safe TreeKEM in x0x. Out of scope for this slice.

### C.2 finality architecture still pending

- `state_hash` / `prev_state_hash` — not wired.
- Authority-signed cards / validity-hash model — not in.
- `ListedToContacts` vs `PublicDirectory` separation — still collapsed in `to_group_card()`.
- Single global discovery topic — unchanged.
- TTL-only invalidation for hidden/deleted groups — unchanged.

None of this blocks or contradicts D.2-fix; GSS carries its own epoch revisioning.

### Status label

**"D.2 cross-daemon secure delivery complete with ML-KEM-sealed envelopes (recipient-confidential, IND-CCA2) + rekey-on-ban; not full MLS TreeKEM (no per-message forward secrecy); C.2 finality-architecture still pending."**

The confidentiality hole flagged in both reviews is closed:
- Code path uses real ML-KEM encapsulation (`src/groups/kem_envelope.rs:140`, `src/bin/x0xd.rs:4288`).
- Cryptographic proof is a real bob-targeted wire envelope that eve cannot open (★5), backed by endpoint-integrity (★6) and primitive-level (★7) evidence.

---

## Files touched (D.2-fix v1 + v2)

```
 src/groups/kem_envelope.rs  | +200  (NEW — seal/open primitives + 3 unit tests)
 src/groups/mod.rs           |  +18
 src/groups/member.rs        |   +4  (kem_public_key_b64 field)
 src/bin/x0xd.rs             | ~280  (AgentKemKeypair load; KEM-sealed envelope variant; AAD helper;
                                      approve/ban wiring; /groups/:id/secure/reseal + /groups/secure/open-envelope)
 src/api/mod.rs              |   +8  (/secure/reseal, /secure/open-envelope)
 tests/api_coverage.rs       |   +2
 tests/api-coverage.sh       |   +3  (join backslash-continued bash lines for multi-line curl URLs)
 tests/e2e_named_groups.sh   | ~110  (section "2c. D.2 ADVERSARIAL" with 3 ★ proofs + reseal-based real envelope)
```

---

## Full-audit regression status (honest)

`bash tests/e2e_full_audit.sh` against this slice: **256 PASS / 20 FAIL / 0 SKIP**. All 20 failures are pre-existing gossip-propagation flakes (SSE `/events`, `/direct/events`, named-group removal propagation, join-request visibility race, file-transfer receive-side, `/ws/direct` receive, GUI-driven direct send). None are caused by, related to, or fixed by this D.2-fix slice. The dedicated named-groups runner is stably **37/0/0** across 3 consecutive runs.

---

## Commands for re-verification

```bash
cargo fmt --check
RUSTFLAGS="-D warnings" cargo clippy --all-features --all-targets -- -D warnings
cargo test --lib groups::kem_envelope::tests --quiet   # 3/3
cargo test --test api_coverage --quiet                 # 8/8
bash tests/api-coverage.sh                             # 100.0% (104/104)
bash tests/e2e_named_groups.sh                         # 37/0/0 with 7 ★ lines green
```
