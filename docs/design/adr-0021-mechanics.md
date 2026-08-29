# ADR-0021 mechanics — DM origin-machine attestation mechanics

> Extracted 2026-08-29 from the immutable [ADR 0021](../adr/0021-dm-origin-machine-attestation.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the attestation format, verification, and move-policy
> mechanics relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

### Signed material

`DmOriginAttestation` (new struct in `src/dm.rs`):

| field | purpose |
|---|---|
| `attestation_version: u16` | format version (1); unknown versions fail closed |
| `protocol_version: u16` | mirrors the envelope's DM protocol version |
| `sender_agent_id: [u8; 32]` | the DM principal |
| `sender_machine_id: [u8; 32]` | claimed origin machine |
| `machine_public_key: Vec<u8>` | self-certifying ML-DSA-65 machine key |
| `recipient_agent_id: [u8; 32]` | replay scope |
| `request_id: [u8; 16]` | binds the attestation to one logical DM (retries reuse it) |
| `created_at_unix_ms / expires_at_unix_ms: u64` | freshness/expiry window (mirrors envelope) |
| `signature: Vec<u8>` | ML-DSA-65 over the bytes below, by the machine secret key |

Signed bytes (deterministic, domain-separated — mirrors
`ForwardV2Header::signable_bytes`):

```
"x0x-dm-origin-attestation.v1"
|| attestation_version.be || protocol_version.be
|| request_id || sender_agent_id || sender_machine_id
|| len32be(machine_public_key) || machine_public_key
|| recipient_agent_id
|| created_at_unix_ms.be || expires_at_unix_ms.be
```

---

### Verification (receiver, zero prior state)

In `InboxPipeline::handle_incoming`, after the existing envelope-signature
and sender-match checks:

1. **Attestation present and valid** → the attested `MachineId` wins.
   Verification is self-contained: `machine_public_key` parses;
   `MachineId::from_public_key(key) == sender_machine_id` (hash binding);
   every mirrored field equals the envelope's; the ML-DSA-65 signature
   verifies. The retained #184 binding is **refreshed** with the attested
   machine (`created_at_unix_ms / 1000`, keeping the cache's
   seconds-granularity ordering coherent with announcement-sourced
   bindings).
2. **Attestation present but invalid** (any check fails, including unknown
   `attestation_version`) → **hard drop**. No fallback: a present-but-bad
   attestation is an attack or corruption signal, never a legacy peer.
3. **Attestation absent** (legacy peer) → the existing #184 path:
   retained-binding match enforced when a binding exists; claimed-machine
   fallback otherwise.

The EP3 revocation gate then runs against the **resolved** machine id, so a
revoked origin A fails even when the envelope claims unrevoked B: claiming B
requires B's machine signature (unforgeable), and carrying A's valid
attestation names A, which EP3 rejects.

---

### Portable-agent move policy (A → B)

A move is legitimate when the agent keyholder starts sending from machine B.

- **Per-DM authentication.** Each DM authenticates its own origin machine;
  there is no session or registration step. B's first attested DM is
  accepted immediately, even with zero receiver state and even while the
  retained binding still says A — the valid fresh attestation supersedes
  (and refreshes) the stale binding.
- **Freshness and order.** The attestation mirrors the envelope's
  `created_at/expires_at`, already window-validated (30 s future skew;
  ≤ 10 min lifetime). The retained-binding cache orders updates by
  timestamp (seconds): a later announcement or attestation may move the
  binding; an older one cannot roll it back.
- **Overlap.** During a move, DMs may briefly arrive from both A and B.
  Both verify independently; delivery is per-DM, so overlap is benign.
- **Revocation interaction.** Revoking A after a valid move does not affect
  B-attested DMs (EP3 checks the resolved machine, B). A-attested DMs in
  flight when A is revoked are dropped by EP3 — intended fail-closed.
