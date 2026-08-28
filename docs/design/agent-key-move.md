# Agent Key-Move Protocol — Design Mechanics

Companion to [ADR 0043](../adr/0043-agent-key-move-protocol.md), which
**amends [ADR 0037](../adr/0037-agent-placement-and-key-custody.md)**.
This document carries the mechanics; the ADR carries the decision. Every
mechanism below is cross-checked against code on `origin/main` (`e884b21`)
with `file:line` citations.

Gapcheck findings addressed (Codex gapcheck 2026-08-27): #1 (revoke route
cannot issue machine revocations), #2 (machine subject too coarse), #3
(revocation not permanent), #4 (no machine KEM key to seal to), #5 (no
safe move protocol / retained-copy resurrection), #6 (roaming vs Home
invariant), #7 (placement descriptive).

## 1. What exists today (inventory)

| Mechanism | Status | Where |
|---|---|---|
| V3 identity announce (`X0A3`), machine-ML-DSA-signed | shipped | `src/announce_v3.rs:28`, `verify` at `:180` |
| Cert blob fetch-on-miss, verify-before-cache | shipped | `src/announce_blob.rs` (`verify_fetched_blob` at `:506`) |
| ML-KEM-768 keypair type (`AgentKemKeypair`) | shipped (used for group secrets) | `src/groups/kem_envelope.rs:41` |
| KEM seal/open (`seal_group_secret_to_recipient` / `open_group_secret`) | shipped, **32-byte plaintext only** | `src/groups/kem_envelope.rs:140`, `:176` |
| Revocation records, grow-only set, gossip publish | shipped | `src/revocation.rs:47`, `:164`, `:398`; `src/lib.rs:9042` |
| Revocation enforcement: DM inbound, pubsub delivery, announce cache eviction, connect, streams | shipped | `src/dm_inbox.rs:1301`, `src/gossip/pubsub.rs:1397`, `src/lib.rs:7721`, `src/lib.rs:3677`, `src/forward.rs:757` |
| DM origin-machine attestation (per-DM, machine-signed) | shipped | `src/dm.rs:318`, verified at `src/dm_inbox.rs:1231` |
| Connect-ACL pair gate (every announced agent on the machine) | shipped | `src/streams.rs:466-473`, `src/connect/gate.rs` |
| `AgentKeypair::to_bytes/from_bytes` serialization | shipped | `src/identity.rs:294`, `:277` |
| Owner singleton (`user.key` per install) | ADR 0036 accepted, partially shipped | `docs/adr/0036-owner-singleton-and-naming-registry.md` |

What does **not** exist and is added by this design: a machine ML-KEM
keypair and its announcement path; the X0A4 envelope; the
`AgentMachineBinding` revocation subject; the move-record chain and move
log; the `PlacementRecord` and its gate wiring.

## 2. Machine KEM enrollment (fixes finding #4)

### 2.1 Keypair

Each machine generates an ML-KEM-768 keypair at first start (or lazily at
first move ceremony that names it as a target), stored beside the machine
ML-DSA-65 key under the instance identity dir. Reuse the shipped
primitive: `AgentKemKeypair` (`src/groups/kem_envelope.rs:41-48`) is a
bare ML-KEM-768 keypair with serde + decapsulate; introduce
`MachineKemKeypair` as the same construction (or a type alias plus a
`from_bytes` loader) rather than new cryptography. `KEM_VARIANT` is
already pinned to ML-KEM-768 (`src/groups/kem_envelope.rs:35`).

### 2.2 Announcement: X0A4

The V3 wire **cannot grow a field**: it is positional bincode with
`reject_trailing_bytes` (`src/announce_v3.rs:288-292`), and gapcheck #17
already flags `serde(default)` as ineffective there. Therefore:

- New envelope `IdentityAnnouncementV4`, magic `X0A4`, carrying every
  `IdentityAnnouncementV3Unsigned` field (`src/announce_v3.rs:35-50`)
  **plus**:
  - `machine_kem_public_key: Vec<u8>` — raw ML-KEM-768 public key
    (~1184 B);
  - `placement_digest: [u8; 32]` — digest of the owner-signed
    `PlacementRecord` (§6), `blake3(placement_record_bytes)`; the
    anonymous constant when the agent has no owner (uncertified agents
    cannot be moved by this protocol anyway).
- Signed by the machine ML-DSA-65 key over its own canonical bytes, same
  construction as `build_from_v2`/`verify` (`src/announce_v3.rs:136`,
  `:180`). Verification additionally checks that
  `machine_kem_public_key` parses as ML-KEM-768 and belongs to the
  signing machine — enforced by being inside the machine-signed struct.
- **Transition mirrors V2→V3** (`src/announce_v3.rs:18-21`): V4 is
  published alongside V3; old nodes see unknown magic, fail the legacy
  decode, and drop it; they lose nothing because V3 keeps flowing. The
  dual-publish window ends when fleet telemetry shows V4-capable
  heartbeats ≥ threshold (same operational rule PR #419 used for V3).

Why inline rather than a fetched blob: the KEM public key is needed
**synchronously** by the exporter to seal, and the V3 design principle
"both public keys stay inline — a receiver can always check … without
fetching anything" (`src/announce_v3.rs:10-11`) applies with equal force
to the key that guards key custody. Cost: ~1.2 KB on an envelope that V3
already trimmed to ≤8 KB, and only on the V4 wire.

### 2.3 Receiver side

`DiscoveredMachine` (`src/lib.rs:1662-1691`) gains
`machine_kem_public_key: Option<Vec<u8>>` (in-memory cache only — no
wire compat concern). `DiscoveredAgent` is unchanged. The discovery arm
that today branches on `is_v3_payload` (`src/lib.rs:7590`) gains an
`X0A4` branch ahead of it: decode → `verify()` → convert to the shared
announcement shape (mirroring `into_announcement`,
`src/announce_v3.rs:238`) → merge, additionally caching the KEM key.

## 3. Export envelope (fixes finding #4, prerequisite for #5)

### 3.1 Widening the seal primitive

`seal_group_secret_to_recipient` takes `secret: &[u8; 32]` and
`open_group_secret` asserts a 32-byte plaintext
(`src/groups/kem_envelope.rs:143`, `:195-199`). An ML-DSA-65 **secret key
is 4032 bytes** (serialized via `AgentKeypair::to_bytes`,
`src/identity.rs:294`). The AEAD construction underneath already
encrypts arbitrary-length messages — ChaCha20Poly1305 over
`(msg, aad)` with the KEM shared secret as key (`:156-166`) — so the
32-byte constraint is purely the parameter type. Add sibling functions in
the same module:

```rust
pub fn seal_bytes_to_recipient(recipient_public_bytes: &[u8], aad: &[u8],
    plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12], Vec<u8>)>;
pub fn open_sealed_bytes(kp: &AgentKemKeypair, aad: &[u8],
    kem_ciphertext: &[u8], aead_nonce: &[u8; 12],
    aead_ciphertext: &[u8]) -> Result<Vec<u8>>;
```

Identical KEM→AEAD construction; no new cryptography; the existing 32-byte
pair remains untouched for group secrets (ADR 0027 callers unchanged).

### 3.2 Envelope contents and AAD

Export payload: `bincode(AgentKeypair::to_bytes())` — both halves, so the
target can verify `SHA-256(public) == agent_id` before trusting anything
(binding rule already used everywhere, e.g. `src/announce_v3.rs:198`).

AAD = the owner-signed `MoveRecord` for the Exported state (§4). This
binds the envelope to `(agent_id, move_epoch, from_machine, to_machine)`,
so:

- an envelope cannot be replayed into a *different* move (epoch mismatch
  fails AEAD),
- cannot be re-targeted (to_machine is in the AAD),
- and a substituted envelope under a valid move record fails because the
  AAD is covered by the AEAD tag (`src/groups/kem_envelope.rs:161-166`).

Freshness: `MoveRecord.issued_at` is in the AAD, so each export epoch has
a distinct envelope; re-export after `Abort` (§4.6) re-seals under the
new record.

## 4. The move ceremony (fixes findings #5, #6)

### 4.1 Records and epochs

A move is an append-only chain of owner-signed records:

```rust
struct MoveRecord {
    agent_id: AgentId,
    move_epoch: u64,            // per-agent monotonic; = placement_epoch
    from_machine: MachineId,
    to_machine: MachineId,
    state: MoveState,           // Exported | Imported | Activated | SourceRetired
    envelope_digest: [u8; 32],  // blake3 of the sealed envelope (Exported+)
    issued_at: u64,
    owner_signature: Vec<u8>,   // ML-DSA-65 user key (the OWNER, ADR 0036)
    machine_countersignature: Option<Vec<u8>>, // source (Exported) / target (Imported, SourceRetired-receipt)
}
```

Domain-separated signed bytes with a new prefix
`b"x0x-agent-move.v1"`, mirroring `REVOCATION_MSG_PREFIX`
(`src/revocation.rs:40`) and `DM_ORIGIN_ATTESTATION_DOMAIN`
(`src/dm.rs:318`). Records are content-addressed by BLAKE3 of their
canonical bytes for dedup — the same idempotent-merge property as
`RevocationRecord::record_hash` (`src/revocation.rs:260`), proven
idempotent by the grow-only merge tests (`src/revocation.rs:722`).

**Ownership of signing**: every state transition record is signed by the
owner key (`user.key`, ADR 0036 — the install that certified the agent,
`AgentCertificate::issue`, `src/identity.rs:514`). The moving agent key
never signs a move record: it is the artifact being moved and may be the
stolen object. Machine keys only countersign receipts about their own
actions (I sealed / I imported / I deleted). This directly answers
gapcheck #1: nothing in the ceremony depends on the agent or source
machine being willing or honest.

`move_epoch` for an agent = the `placement_epoch` of the placement
record; first move is epoch 1. Monotonicity is enforced by receivers:
a record with epoch ≤ the highest seen (or revoked) epoch for that agent
is rejected (§6.3).

### 4.2 State machine

```
             owner signs            target countersigns,
 ──────────► Exported ──────────► Imported ──────────► Activated ──────► SourceRetired
 (source      │   source quiesces      │  target holds        │  owner issues    │ source observes,
  quiesces)   │   (no signing)         │  QUARANTINED key     │  binding-revoked │ secure-deletes,
              │                        │  (no signing)        │  placement rec   │ countersigns
              ▼                        ▼                      ▼                  ▼
           Abort (owner)          crash → re-import       crash → re-activate  crash → re-retire
           source un-quiesces     (idempotent)            (idempotent)         (idempotent)
```

**Exported.** Owner key authorizes; source machine seals
(`seal_bytes_to_recipient`, target's announced ML-KEM-768 key from the
X0A4 cache) and **quiesces**: the daemon flips a durable per-agent flag
and refuses every signing path (DM envelopes, ACK attestations
`src/dm_inbox.rs:2098`, stream forward headers `src/forward.rs:195`,
announce publish) for that agent. Key bytes stay on source disk solely so
`Abort` can restore service. The envelope is written to operator-chosen
media (scp/file transfer — out of band by design; it is ciphertext keyed
to the target machine).

**Imported.** Target decapsulates (`open_sealed_bytes` with its machine
KEM secret — possession of the KEM secret is itself machine
authentication), checks `SHA-256(pub) == agent_id`, verifies the owner
signature on the Exported record and that `to_machine` is itself, and
stores the keypair **quarantined**: present on disk, refused for all
signing until an owner-signed `Activated` record is held. The target
machine-key countersigns an import receipt; the owner verifies and signs
`Imported`.

**Activated** — the commit point, and the only irreversible one. Owner
signs `Activated` and in the same operation:
1. issues `RevocationRecord` with subject
   `AgentMachineBinding(agent_id, from_machine)` (§5), published on the
   existing revocation gossip topic (`REVOCATION_TOPIC` publish already
   in `apply_and_publish_revocation`, `src/lib.rs:9091-9102`);
2. issues the successor `PlacementRecord { placement: Pinned(to_machine)
   | Roaming-at-target, placement_epoch: move_epoch }` (§6);
3. gossips the `Activated` move record.

The target un-quarantines and begins announcing (X0A4) and signing.
Rollback is now impossible **by construction**: the revocation set is
grow-only (`src/revocation.rs:22-26`) — this is deliberate; activation is
the point of commitment.

**SourceRetired.** The source observes `Activated` via gossip or operator
ack, secure-deletes the agent keypair and quiesce flag, countersigns a
retirement receipt; the owner logs `SourceRetired`. Until then the source
holds a live copy that **never signs** — harmless to the network (every
upgraded receiver drops its binding, §5/§6) and recoverable for the
operator.

### 4.3 Who stores state; re-entry

- **Owner machine** — the authoritative append-only **move log**
  (`moves.bin` + per-record gossip cache), persisted with the same
  atomic-write pattern as `revocations.bin` (`src/storage.rs:693`,
  `:711`). The owner is the ceremony driver; a move cannot proceed past
  any state boundary without an owner signature, so the owner's log is
  always the latest truth.
- **Source / target machines** — durable per-move state files
  (`{agent_id}.{epoch}.state`: quiesced / quarantined / retired) so a
  crashed daemon re-enters correctly at startup.
- **Mesh** — `Activated` records, binding revocations, and placement
  records are gossipped and cached; they are *evidence*, not state.

**Re-entry rule**: every CLI/API step takes `(agent_id, move_epoch)` and
is idempotent — re-running it reads the move log and no-ops or resumes at
the recorded state. Re-export under the same epoch **reuses the stored
envelope** (ML-KEM encapsulation is randomized; re-sealing would break
the recorded `envelope_digest`). New epoch = new ceremony.

### 4.4 Crash matrix (never-two-live-signers, never-lost)

| Crash after | State | Source signs? | Target signs? | Key recoverable from | Recovery |
|---|---|---|---|---|---|
| owner signs Exported (before seal) | — | yes (not yet quiesced) | no | source disk | re-run export |
| seal, before operator transfers envelope | Exported | **no** (quiesced) | no | source disk + envelope on source/export media | re-transfer; or `Abort` |
| transfer, before import | Exported | no | no | envelope | import at leisure |
| import, before owner signs Imported | Exported→Imported | no | no (quarantined) | envelope + target disk | owner re-verifies receipt |
| Activated signature, before gossip lands | Activated | no | yes | — (committed) | re-publish (gossip retry) |
| Activated, before source deletes | Activated | no | yes | — | source `Retire` whenever |
| source delete, before receipt | SourceRetired (pending) | no (deleted) | yes | envelope may be purged by operator only after receipt | owner marks complete |

Loss window: the key exists in exactly one *live-signing-capable* place
at every instant — source until Export, target from Activated, with a
gap of zero signing in between (both quiesced/quarantined). The key is
never *only* on a machine that has acknowledged deletion, because the
envelope is retained until `SourceRetired` and source deletion happens
after `Activated` is durable. Losing both machines and the envelope media
still loses the `AgentId` — unchanged from ADR 0037 (ADR 0007 non-goal).

### 4.5 Two-signer analysis for dishonest holders

An honest source cannot sign after Export (quiesce). A **stolen** source
copy (disk image) can: it signs with a perfectly valid agent signature
and a fresh, valid machine attestation — ADR 0021 attestation alone
cannot stop it (gapcheck #5). What stops it at every upgraded receiver:
the binding revocation (fail-closed, gossipped, §5) and the placement
record epoch check (§6). The stolen copy cannot forge either: both are
owner-key-signed, and the owner key never left the owner machine.

### 4.6 Abort

Before `Activated`, the owner may sign `Abort{epoch}`: source un-quiesces,
target discards the quarantined key, epoch is burned (never reused).
After `Activated` there is no abort — grow-only revocation makes the old
binding permanently dead; undoing a move is a *new* move at epoch+1.

### 4.7 Home invariant (fixes finding #6)

`Activate` validates the owner roster before committing: if the moving
agent is Home's (ADR 0038) last Roaming member and the target placement
is `Pinned`, activation refuses with a named error, exactly like other
fail-closed owner checks. Moving a Home agent *to* another owner machine
keeps it Roaming (placement records name the machine; `Roaming` is the
policy, `placement_epoch` the version). This is checked at the owner —
the single writer of both the move log and the roster — so no distributed
consensus is needed.

## 5. Binding revocation (fixes findings #1, #2, #3)

### 5.1 Subject

```rust
pub enum RevokedSubject {
    Agent(AgentId),                       // 0x01 — unchanged
    Machine(MachineId),                   // 0x02 — unchanged
    AgentMachineBinding(AgentId, MachineId), // 0x03 — NEW
}
```

`tag()` (`src/revocation.rs:56-61`) gains `0x03`; `id_bytes()` returns
agent‖machine for the canonical message (`src/revocation.rs:94-118`,
length-fixed: two 32-byte ids, no boundary ambiguity).

Semantics: the *(agent, machine)* pair is dead. The agent remains valid
elsewhere (a move target, or another binding if Roaming permits); the
machine's other agents are untouched. This is the granularity ADR 0037's
`Machine(MachineId)` subject could not express (gapcheck #2).

### 5.2 Authority — owner key only

`verify_authority` (`src/revocation.rs:164-211`) today accepts
self-revocation (issuer key hashes to the subject id, `:183-187`) or
issuer-revocation (agent subjects, issuer = certifying user, `:189-205`).
For the new subject:

- **Self-revocation is impossible by construction**: the issuer key
  hashes to exactly one 32-byte id, and the subject is the concatenation
  of two — the equality check can never hold. No code change needed to
  exclude it; it falls out.
- **Issuer-revocation extended**: for a binding subject, the issuer must
  be the user key that signed the subject agent's `AgentCertificate`
  (cert looked up from the discovery cache or carried alongside, exactly
  as today — `verify_and_insert` already threads `subject_cert`,
  `src/revocation.rs:359-376`; the retained cert on `DiscoveredAgent`
  exists for precisely this, `src/lib.rs:1639-1646`). This is the OWNER
  (ADR 0036): neither the moving agent key nor either machine key can
  issue or block it (gapcheck #1).
- A third user's key fails the certifier check (`:198-201`) — rejected.

### 5.3 Permanence (fixes finding #3)

`expire_records_older_than` (`src/revocation.rs:398-423`), driven by the
90-day sweep in the heartbeat loop (`src/lib.rs:2759-2770`,
`REVOCATION_RECORD_TTL_SECS`), drops old records and thereby "unrevokes"
them (test at `src/revocation.rs:534`). For binding records this is
exactly the resurrection gapcheck #3 flags: a retired source machine's
copy becomes valid again after 90 days of quiet.

Change: `expire_records_older_than` skips `AgentMachineBinding` records
(the match arms at `:411-418` simply don't collect them); they are
permanent, honoring ADR 0018's grow-only rule. Bandwidth cost is bounded
and small: one record (~2 KB with ML-DSA signature and cert) per move,
gossipped on change + periodic fallback piggyback
(`src/lib.rs:2786-2790`) — the motivating 2026-07 stale-fleet case
(`src/revocation.rs:392-397`) was about *inactive* subjects; a moved-away
agent's old binding stays security-relevant forever.

### 5.4 Issuance path

`Agent::revoke` (`src/lib.rs:9042-9060`) takes an `AgentKeypair` issuer —
wrong key class for owner-issued bindings. Add:

```rust
pub async fn revoke_binding(&self, user_kp: &identity::UserKeypair,
    agent: AgentId, machine: MachineId, reason: Option<String>)
    -> error::Result<revocation::RevocationRecord>
```

which signs with the **user** key and reuses
`apply_and_publish_revocation` (`src/lib.rs:9066`) verbatim — insert,
persist, evict, gossip. `POST /identity/revoke`
(`src/server/routes/identity.rs:1141-1204`) gains a request form where
`agent_id` and `machine_id` are **both** present (today "exactly one of"
is enforced at `:1147-1170`) → binding subject, signed with the owner
key loaded from the install's `user.key` (ADR 0036 owner singleton).
Single-field forms keep their existing semantics untouched.

### 5.5 Enforcement

New set accessor `is_binding_revoked(&AgentId, &MachineId)` beside
`is_agent_revoked`/`is_machine_revoked` (`src/revocation.rs:318`,
`:324`), consulted at the pair gates:

- **DM inbound**: extend `drop_if_sender_revoked`
  (`src/dm_inbox.rs:2176-2180`, called at `:1301-1302`) to also check the
  binding of the *attested* machine (`sender_machine_id` there is already
  the attestation-resolved value, `src/dm_inbox.rs:1231-1252`).
- **Gossip pubsub delivery**: the sender gate
  (`src/gossip/pubsub.rs:1397-1401`) checks agent only (sender id); the
  binding check belongs at the DM/stream layers above, which know the
  machine.
- **Streams/forward**: the mid-flight re-check
  (`src/forward.rs:757-760`) and connect gate add the binding pair check
  for each `(agent, machine)` in `peer_agents` (`src/streams.rs:466`).
- **Announce cache**: the eviction arm that drops revoked
  agents/machines (`src/lib.rs:7721-7733`) also drops an announce whose
  `(agent_id, machine_id)` binding is revoked — the stale source
  heartbeat disappears from discovery caches fleet-wide.

## 6. Placement records and gate wiring (fixes finding #7)

### 6.1 Record

```rust
pub struct PlacementRecord {
    agent_id: AgentId,
    owner_public_key: Vec<u8>,     // = AgentCertificate issuer
    placement: Placement,          // Pinned(MachineId) | Roaming
    placement_epoch: u64,          // = move_epoch that produced it
    issued_at: u64,
    signature: Vec<u8>,            // owner ML-DSA-65 over domain-separated bytes
}
```

Signed with domain prefix `b"x0x-placement.v1"` (mirrors
`AgentCertificate` prefixes, `src/identity.rs:498-501`). Initial records
(epoch 0) are minted lazily: first time the owner roster (ADR 0036
`GET /owner/agents`) is consulted for a move, each owned agent gets
`Pinned(current machine), epoch 0` — making ADR 0037's "default Pinned
to this machine" a signed fact instead of a description.

### 6.2 Distribution

Digest on the X0A4 announce (§2.2) → fetch via the blob path: a second
blob kind in `AnnounceBlobCache` (`src/announce_blob.rs:147`) keyed by
`blake3(placement_record_bytes)`, served by the same responder
(`spawn_blob_responder`, `src/announce_blob.rs:625`) and admitted through
the same verify-before-cache gate extended to validate the placement
signature, owner↔cert-issuer match, and `agent_id` binding
(`verify_fetched_blob` pattern, `src/announce_blob.rs:506`). Anonymous
digest constant when no record exists (no fetch — the
`fetch_warranted` rule, `src/announce_blob.rs:82`).

### 6.3 Gate checks (epoch-aware, fail-closed only when evidence exists)

At the DM gate, after attestation resolves `(agent, machine)`
(`src/dm_inbox.rs:1231`):

1. binding revoked → hard drop (fail-closed, §5.5);
2. cached `PlacementRecord` for the agent whose `placement_epoch` > the
   highest revoked binding epoch for that agent, and placement is
   `Pinned(X)` with `X ≠ attested_machine` → drop;
3. no cached record (never fetched, evicted, or pre-0043 peer) →
   **accept** (fail-open, documented below).

Same ordering in the stream/connect gate (`src/streams.rs:466-473`) and
the announce cache-merge step. `IdentityAnnouncementV4::verify` stays
**stateless** — self-certification only, like V3 (`src/announce_v3.rs:177`)
— because gapcheck #13 correctly bars the blob cache from being an
admission oracle: a fetch miss must never block traffic.

Epoch comparison is what defeats replay: after a move to epoch *n*, a
stolen copy presenting the old epoch *n−1* record pinned to the source
machine loses every comparison against the cached epoch-*n* record, and a
*newer* forged record fails the owner signature.

### 6.4 Old peers (fail-open, documented)

Pre-0043 peers: (a) drop X0A4 envelopes harmlessly (§2.2), so they never
see placement digests; (b) cannot decode `AgentMachineBinding` — bincode
enum variant `0x03` fails their `RevokedSubject` decode, and the
whole-record-batch gossip payload (`Vec<PersistedRevocation>` → today
`Vec<RevocationRecord>` at `src/lib.rs:9093`) fails to deserialize, so
they discard the batch and keep their prior set — fail-open, no crash.

This is accepted and bounded:

- The window is the fleet-upgrade period, the same one V2∥V3 rode out.
- Capability adverts (the `DmCapabilities` pattern behind ADR 0030's
  `max_protocol_version`) gain a `move_protocol: 1` marker; the owner's
  daemon, at `Export` and `Activate`, warns with a concrete peer list if
  any frequent contact still lacks it, so the operator knows the
  residual exposure instead of assuming safety.
- If an operator needs immediate closure against old peers during the
  window, the coarse `Machine(from_machine)` revocation remains
  available as a manual backstop — at the documented cost of killing
  co-resident agents (the exact trade ADR 0043 exists to remove).

## 7. API surface (summary)

| Endpoint | Change |
|---|---|
| `POST /identity/revoke` | new `{agent_id, machine_id}` both-set form → owner-signed binding revocation (§5.4) |
| `POST /agent/move` | new: `{agent_id, to_machine}` → owner signs Exported, returns envelope (base64) for out-of-band transfer |
| `POST /agent/move/import` | new (target): `{record_b64, envelope_b64}` → quarantine + receipt |
| `POST /agent/move/activate` | new (owner): `{agent_id, move_epoch}` → Activated + binding revocation + placement record, atomically |
| `POST /agent/move/abort` / `/retire` | new: pre-Activate rollback / post-Activate source cleanup |
| `GET /agent/moves` | new: move log view |
| `GET /owner/agents` | gains `placement` + `placement_epoch` (signed record digest) |

All state-mutating handlers are owner-key-gated at the daemon (the ADR
0036 owner singleton); rider credentials (ADR 0039) are denied by the
existing deny-by-default rider scope.

## 8. Compatibility summary

- V3 announce, V2 announce: unchanged bytes, unchanged verification.
- X0A4: additive envelope; old peers drop by magic (V2→V3 precedent,
  `src/announce_v3.rs:18-21`).
- `RevokedSubject`: additive variant `0x03`; old peers reject the gossip
  batch (fail-open, §6.4); new peers decode all three.
- `seal_group_secret_to_recipient`/`open_group_secret`: untouched; new
  `seal_bytes_to_recipient`/`open_sealed_bytes` siblings.
- On-disk: `agent.key`, `agent.cert`, `machine_key`, `revocations.bin`
  formats unchanged; new files: machine KEM key, `moves.bin`, per-move
  state files.

## 9. Test plan

**Unit**

1. Binding authority matrix: owner key ✓; agent key ✗; source/target
   machine key ✗; unrelated user key ✗; self-revocation structurally
   impossible (issuer id ≠ concatenated subject).
2. TTL sweep: binding records survive `expire_records_older_than`;
   agent/machine records still expire (existing behavior,
   `src/revocation.rs:534` test pattern).
3. `seal_bytes_to_recipient`/`open_sealed_bytes`: round-trip; wrong AAD
   (different move record) fails; wrong machine KEM key fails; tampered
   ciphertext fails.
4. X0A4: `verify` passes with valid machine signature + parseable KEM
   key; rejects swapped KEM key (outside signature), bad magic handling
   by V3-era decoder (drops, no panic), placement digest committed.
5. Placement epoch: epoch *n* record beats *n−1*; forged *n+1* fails
   owner signature; revoked-epoch record ignored.
6. Move log: replay of any record batch is idempotent (record-hash dedup,
   `src/revocation.rs:722` pattern).

**Integration / E2E** (extend `tests/` harness style)

7. Full move: source quiesces at Export (DM send, ACK attestation,
   forward header all refuse); target quarantined until Activated;
   after Activate, target's first attested DM accepted.
8. Crash injection at each of the seven matrix rows (§4.4): re-entry
   converges; exactly one signer observed at every sampled instant.
9. Stolen-copy attack: source disk image re-signs; upgraded receiver
   drops on binding revocation (fresh valid attestation notwithstanding);
   co-resident agent on the source machine continues to pass.
10. Home invariant: move refusing to strand Home with zero Roaming.
11. Mixed fleet: pre-0043 peer receives V3 + old-format revocations
    only; move completes; operator warning lists the old peer.
