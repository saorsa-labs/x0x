# ADR 0021: DM origin-machine attestation for gossip DMs

- **Status:** Proposed
- **Date:** 2026-07-17
- **Decision owners:** x0x maintainers
- **Reviewers:** (pending)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #213; issue #184 (retained-binding mitigation); #204 ForwardV2 attestation (`src/forward.rs`); ADR 0018 (key lifecycle / revocation)

## Context

Gossip DM envelopes (`DmEnvelope`) are signed by the sender's portable
**agent** key and carry a sender-controlled `sender_machine_id` claim. The
#184 mitigation retains the latest authenticated AgentId→MachineId binding
from verified `IdentityAnnouncement`s and rejects envelope claims that
disagree with it — but only when a binding exists. Three states leave the
receiver with nothing but the sender's claim:

1. **Never observed** — the sender is a Trusted contact whose announcement
   never propagated to this receiver.
2. **Restart** — the retained-binding LRU is intentionally in-memory; a
   process restart empties it before announcements repopulate it.
3. **Bounded-LRU eviction** — capacity pressure evicts the binding.

In all three, a holder of a stolen agent key operating on a **revoked**
machine A can place an unrevoked machine B in `sender_machine_id` and bypass
revocation of the true origin machine (the EP3 gate checks only the claim).
The receiver cannot authenticate the physical origin machine from its own
state because no per-message proof from the origin machine exists.

## Decision Drivers

- Origin authentication MUST work with **zero prior discovery-cache state**
  (cold receiver, restart, LRU eviction, offline-then-online delivery).
- A revoked origin machine MUST fail verification even when the envelope
  claims an unrevoked machine.
- Portable agents (same agent key, new machine) MUST keep working under an
  explicit, testable policy.
- Wire changes MUST be additive: old receivers skip the new field; new
  receivers tolerate its absence.
- Reuse the established attestation pattern (ForwardV2 #204, CRDT
  provenance): self-certifying public key + `from_public_key` hash binding +
  domain-separated ML-DSA-65 signature. No new cryptography.

## Considered Options

1. **Per-DM machine-key attestation embedded in the envelope (chosen).**
   The origin machine signs a small struct riding inside every DM envelope;
   the machine public key travels with it and is self-certifying via
   `MachineId::from_public_key == sender_machine_id`.
2. **Rely on identity announcements + persistent binding cache.** Rejected:
   propagation timing and restart amnesia are exactly the gap; persisting
   bindings helps restarts but not the never-observed case, and adds disk
   state to a security boundary that can instead be stateless.
3. **Sign the envelope with the machine key instead of the agent key.**
   Rejected: breaks the portable-agent model (the agent identity is the DM
   principal) and every existing verifier; also machine keys are not
   portable so contact trust (keyed by agent) could not be evaluated.
4. **Hard-require attestations immediately (reject all unattested DMs).**
   Rejected for this release: no capability negotiation exists on the DM
   wire path, so every pre-#213 peer — including mid-rolling-upgrade
   daemons and the legacy DM bus — would be silently cut off. See
   Downgrade policy below.

## Decision

We will bind a fresh **machine-key attestation** into every gossip DM
envelope, verified by receivers with zero prior cache state.

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

### Envelope placement and codec tolerance

The attestation rides as a **trailing optional field** on `DmEnvelope`:

```rust
#[serde(default, deserialize_with = "deserialize_origin_attestation")]
pub origin_attestation: Option<DmOriginAttestation>,
```

postcard is positional: old receivers stop after `signature` and ignore
trailing bytes (verified by a mixed-version test decoding new bytes with the
old struct shape); new receivers tolerate EOF via the `deserialize_with`
fallback (`None`). The agent signature scope (`build_signed_bytes`) is
**unchanged**, so old receivers verify new envelopes and vice versa.

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

### Replay, relay substitution, downgrade, offline receivers

- **Replay.** The attestation binds `request_id` + `recipient` + expiry.
  Re-presenting it inside a re-signed envelope with a different
  `request_id` fails the field-match check; re-presenting the identical
  envelope is absorbed by the existing dedupe cache (keyed on
  `(sender, request_id)`, 630 s TTL ≥ 600 s max envelope lifetime + 30 s
  accepted skew); past-expiry
  replays die at the timestamp window.
- **Relay substitution.** A relay (X0X-0070b) forwards the sealed envelope
  verbatim; it cannot retarget the attestation (recipient + request_id are
  signed) nor swap it for another DM's (field match fails).
- **Downgrade / mixed-version (transition window).** Receivers
  **accept-with-binding-fallback** for unattested DMs (option 4 rejected
  above). Justification: there is no capability negotiation on the DM path,
  so hard-require would silently sever every pre-#213 peer; the transition
  policy is strictly monotonic — every #213+ sender is authenticated
  per-message, and unattested senders keep exactly the #184 guarantees, no
  worse. Residual (documented, pre-existing): an agent-key holder can
  *strip* the attestation and fall back to the claim path when the receiver
  has no retained binding — the same exposure #213 sets out to close,
  narrowed to unattested senders only. End-state: once attestation support
  is ubiquitous (advertised via `DmCapabilities` in a follow-up), receivers
  hard-require attestations and the residual closes.
- **Offline receivers.** Verification needs only envelope-carried material
  (self-certifying machine key + hash binding + signature). A receiver that
  was offline through every announcement and cache window authenticates the
  origin identically to a warm receiver.

## Consequences

### Positive

- Acceptance criteria: cold-cache origin authentication; revoked origin
  cannot hide behind an unrevoked claim; explicit move policy; restart and
  eviction do not degrade attested senders; old receivers skip the field.
- Stateless verification — no new disk state on the security boundary.
- Pattern reuse: hash binding + domain-separated ML-DSA-65, as in #204 and
  CRDT provenance; `saorsa-pqc` wrappers only.

### Negative / Trade-offs

- ~5.3 KB per envelope (ML-DSA-65 machine pubkey 1952 B + signature 3293 B
  plus struct overhead) added to every DM and ACK; under `MAX_ENVELOPE_BYTES` (64 KiB) but real
  gossip bandwidth. Accepted: security property requires the key travel
  with the message (zero-state requirement).
- Transition-window strip residual (above) until hard-require lands.
- Scope: the attestation does NOT cover the DM body — body integrity is
  the agent signature's job (`build_signed_bytes` covers `postcard(body)`).
  Post-TTL body substitution requires a stolen agent key, and even then the
  swapped body fails AEAD decryption (AAD + KEM-sealed content key).

### Neutral / Operational

- `EnvelopeBuilder::build_payload_envelope` now requires the sender's
  `MachineKeypair`; ACK envelopes are attested too (fake `Accepted` ACKs
  from a revoked machine would otherwise forge delivery receipts).
- New drop counters/logs: attestation-invalid drops count as trust
  rejections; verified attestations refresh the retained binding.

## Validation

- In-process two-agent integration tests (`src/dm_inbox.rs`): spoof (agent
  key without machine key claims unrevoked machine → rejected), replay
  (captured attestation, wrong request id / expired → rejected), revocation
  (origin revoked mid-flight → rejected), offline receiver (cold pipeline,
  no cache → verifies and delivers), A→B move (fresh B attestation accepted
  over stale A binding; revoked-A attestation rejected).
- Mixed-version codec tests (`src/dm.rs`): new bytes decode with the old
  struct shape (field skipped, signature verifies); old bytes decode with
  `origin_attestation == None`.
- Re-run triggers: any change to `DmEnvelope` shape, `build_signed_bytes`,
  or the inbox pipeline order.

## Notes for AI-assisted work

Drafted with AI assistance; must not be marked Accepted without human
review.
