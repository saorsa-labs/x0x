# Agent Key-Move Protocol — Design Mechanics (r5)

Companion to [ADR 0043](../adr/0043-agent-key-move-protocol.md), which
**amends [ADR 0037](../adr/0037-agent-placement-and-key-custody.md)**.
r5 completes the round-3 construction per the round-4 review; r4 adopted
derived state; r3/r2 answered earlier rounds. Citations verified against
`origin/main@ccb288e` in the worktree.

Round-4 findings → sections:

| Finding | Section |
|---|---|
| 1. Predicates must be a single total fold over every legal log shape; key possession is gate input, not log state; quiesce must hold through activation; initial signer and post-abort restoration must be defined | §3.2 (fold), §5.3, §6 |
| 2. ActivationBundle must EMBED the canonical MoveAuthorization — mesh coherence checks reference in-record fields only | §3.1, §7.5 |
| 3. Mesh tombstone loss on out-of-order arrival — cumulative tombstones per bundle; monotonicity applies to placement only; transport aligned with blob-v2 (Bundle kind) | §3.3, §7.5, §8.2 |

Round-3 findings → sections:

| Finding | Section |
|---|---|
| Three separately-ordered mutations create observable partial states; make the bundle the only durable record, all else derived | §3.2 (construction), §5 (crash = log contents), §7.5 |
| (a) Mesh peers cannot head-CAS records they never see — split participant vs mesh verification; carry the bundle | §3.3 |
| (b) Un-quarantine = local bundle verification, one rule; delete "live at append" | §3.2, §6 |
| (c) Cross-field coherence of one bundle's fields | §7.5 |
| (d) Abort as its own signed terminator, same derived treatment | §3.1, §5.3 |

Earlier rounds → sections: r2-1 `X0A4`/blob/machine-announce → §2, §8.2;
r2-2 export cycle → §3.1, §4; r2-3 chain/orderings → §3, §5; r2-4 signing
paths → §6; r2-5 gates/epoch/`Roaming`/Home → §7–§9; r2-6 v1 batch
poisoning → §7.4.

## 1. What exists today (re-verified at `ccb288e`)

| Mechanism | Status | Where |
|---|---|---|
| Identity announce V3 `X0A3` + V3.1 **`X0A4`** (self_name, dual-published) | shipped (ADR-0036, #430) | `src/announce_v3.rs:37`, `:43`, `:503` |
| Machine announce on topic `x0x.machine.announce.v2`, machine-signed, feeds `DiscoveredMachine` | shipped | `src/lib.rs:468`, `:1330`, `:1774`, decoder `:2291-2297` |
| Cert blob fetch-on-miss — **certificate-specific**: `CachedBlob` is the `(UserId, AgentCertificate)` pair; request/response/domains/cache/disk all assume it | shipped | `src/announce_blob.rs:49`, `:54`, `:98`, `:506` |
| ML-KEM-768 `AgentKemKeypair` (serde, decapsulate) | shipped | `src/groups/kem_envelope.rs:41` |
| KEM seal/open — **32-byte plaintext only** | shipped | `src/groups/kem_envelope.rs:140`, `:176` |
| Revocation records + grow-only set; whole-`Vec` v1 wire (publish + receive) | shipped | `src/revocation.rs:47`, `:164`; `src/lib.rs:2951-2958`, `:7689-7695`, topic `:484` |
| 90-day revocation TTL sweep | shipped | `src/revocation.rs:398`, driven `src/lib.rs:2761` |
| Stream gates: `Agent::gate_peer_outbound`, `Agent::gate_peer_machine_inbound`, shared `streams::stream_gate` | shipped | `src/lib.rs:10497`, `:10557` |
| Gossip-DM gate: origin attestation resolve + revoked-sender drop | shipped | `src/dm_inbox.rs:1231`, `:1302`, `:2171` |
| Direct-QUIC DM delivery gate (`direct::inbound_peer_revoked`) | shipped | `src/lib.rs:10313-10327`, `src/direct.rs:128` |
| Forward mid-flight revocation re-check | shipped | `src/forward.rs:757-760` |
| Announce ingest eviction of revoked agents/machines | shipped | `src/lib.rs:7952`, `:7960` |
| Signing paths hold the raw key: `/agent/sign` uses `keypair.secret_key()` directly; `Identity::agent_keypair()` hands out `&AgentKeypair` | shipped | `src/server/routes/identity.rs:905-911`, `src/identity.rs:879` |
| `GET /owner/agents` — cert-journal roster (`owner-cert-journal.jsonl`) + discovery enrichment; **no Pinned/Roaming state exists in production** | shipped (ADR-0036) | `src/server/routes/profile.rs:130-200` |
| Home (ADR-0038): only the `OwnerCertified` admission core has shipped (#432); no Home designation, no roaming roster | shipped core only | `src/server/routes/named_groups.rs` |

New in this design: `MachineAnnouncementV3` (machine KEM key + placement
digests), byte-wise KEM seal/open siblings, the per-agent signed move
log, `AgentMachineBinding` revocation + v2 carrier, the placement mint,
the `AgentSigningGate`.

## 2. Machine KEM enrollment

### 2.1 Carrier: version the machine announcement, not the identity announce

The machine KEM public key is machine-scoped data; it belongs in the
machine announcement, not duplicated into every resident agent beat. The
shipped machine announce is topic-versioned already (`x0x.machine.announce.
v2` versioned v1 away, `src/lib.rs:468`) and its body is positional
bincode with `reject_trailing_bytes` (`src/lib.rs:2296`) — so the version
boundary is the **topic**, exactly the precedent the fleet has exercised:

- New topic `x0x.machine.announce.v3`. New payload `MachineAnnouncementV3`
  = every `MachineAnnouncement` field (`src/lib.rs:1330`) plus:
  - `machine_kem_public_key: Vec<u8>` — ML-KEM-768 public key (~1184 B),
    inside the machine signature;
  - `placement_digests: Vec<(AgentId, [u8; 32])>` — the current placement
    record digest per resident agent (§8.2). The machine is not the
    placement authority (the owner is); it advertises pointers, and every
    fetched record is owner-verified before caching. Stale digests cause
    only the documented fail-open of "no record" (§9.3).
- Old peers are not subscribed to the v3 topic and never decode it — zero
  interaction with `X0A3`/`X0A4` identity traffic (r1's `X0A4` collision
  is moot: this design adds **no** identity-announce envelope).
- `DiscoveredMachine` (`src/lib.rs:1662`) gains
  `machine_kem_public_key: Option<Vec<u8>>` and
  `placement_digests: Vec<(AgentId, [u8; 32])>` (in-memory cache; merge
  never erases a known KEM key with an absent one).
- Keypair: ML-KEM-768, generated at first start, persisted beside the
  machine key; reuse the `AgentKemKeypair` construction
  (`src/groups/kem_envelope.rs:41`) under a `MachineKemKeypair` name.

### 2.2 Sealing primitive

`seal_group_secret_to_recipient` takes `secret: &[u8; 32]` and its opener
asserts 32 bytes (`src/groups/kem_envelope.rs:143`, `:195-199`); an
ML-DSA-65 secret key is 4032 B (`AgentKeypair::to_bytes`,
`src/identity.rs:294`). The AEAD underneath already handles
arbitrary-length plaintext (ChaCha20Poly1305 `Payload {msg, aad}`,
`:156-166`). Add siblings in the same module — same construction, no new
cryptography, existing pair untouched for ADR-0027 callers:

```rust
pub fn seal_bytes_to_recipient(recipient_public_bytes: &[u8], aad: &[u8],
    plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12], Vec<u8>)>;
pub fn open_sealed_bytes(kp: &AgentKemKeypair, aad: &[u8],
    kem_ciphertext: &[u8], aead_nonce: &[u8; 12],
    aead_ciphertext: &[u8]) -> Result<Vec<u8>>;
```

## 3. The move log (findings r2-2/3, r3 a/b/d)

### 3.1 Record kinds — acyclic, terminators included

```rust
enum MoveRecord {
    // genesis: owner-signed epoch-0 placement + initial custodian (§8)
    PlacementMint   { agent_id, placement: Placement,
                      custodian_machine: MachineId, issued_at },
    // owner-signed; authorizes ONE move; contains NO envelope digest
    MoveAuthorization { agent_id, move_epoch: u64, from_machine,
                        to_machine, placement: Placement, issued_at },
    // source-machine-signed, owner-countersigned; commits to ciphertext
    ExportReceipt   { auth_hash: [u8;32], envelope_digest: [u8;32], sealed_at },
    // target-machine-signed, owner-countersigned
    ImportReceipt   { auth_hash: [u8;32], imported_at },
    // owner-signed; COMMIT-terminator of a move. SELF-CONTAINED (r4-2):
    // the canonical MoveAuthorization rides INSIDE — mesh peers never
    // see pre-activation records, so every field coherence checks must
    // live in the signed bundle. retired_bindings is CUMULATIVE (r4-3):
    // every binding retired by moves 1..n — grow-only at the owner, so
    // any single later bundle reconstructs the full history.
    ActivationBundle { authorization: MoveAuthorization,   // canonical, embedded
                       retired_bindings: Vec<AgentMachineBinding>, // §7, cumulative
                       placement_record: PlacementRecord,      // §8
                       agent_certificate: AgentCertificate },  // §7.2
    // source-machine-signed, owner-countersigned; bookkeeping only
    RetireReceipt   { auth_hash: [u8;32], retired_at },
    // owner-signed; ROLLBACK-terminator — legal from ANY pre-activation
    // head (MoveAuthorization | ExportReceipt | ImportReceipt)
    AbortRecord     { auth_hash: [u8;32], reason },
}
struct ChainedRecord { prev: [u8; 32], record: MoveRecord,
                       owner_signature: Vec<u8> };  // machine sigs inside variants
```

Dependency graph is a DAG: `MoveAuthorization` → envelope (AAD = auth
canonical bytes, §4) → `ExportReceipt {auth_hash, envelope_digest}` → …
The authorization never names the envelope; the receipt never enters the
AAD. Domain separation: owner signatures cover
`b"x0x-agent-move.v1" || prev || kind-tag || variant-bytes` (mirrors
`REVOCATION_MSG_PREFIX`, `src/revocation.rs:40`).

Terminators: `ActivationBundle` commits a move; `AbortRecord` rolls one
back and burns its epoch. `RetireReceipt` is bookkeeping after commitment
— it changes no derived security state.

The log folds to THREE total values — defined for **every legal log
shape** (initial, mid-move, post-activation, post-abort), never
undefined (r4-1):

```rust
// ONE total fold over the participant-verified local log for agent A:
fold(log(A)) = {
  custodian(A): MachineId,          // who is authorized to sign as A
  retired_bindings(A): Set<(MachineId, u64)>,  // grow-only, never pruned
  placement(A): (Placement, u64),   // current placement + epoch
  phase(A): Idle                     // no move in flight, no retire pending
          | MidMove   { from, to }   // auth/export/import seen, no terminator
          | RetirePending { from },  // ActivationBundle seen, RetireReceipt not
}
// fold rules, applied in log order; total by cases on the LAST record:
//   log = PlacementMint only                      → custodian = mint.custodian_machine
//                                                    placement = (mint.placement, 0)
//   last = MoveAuthorization|ExportReceipt|
//          ImportReceipt  (active move, no
//          terminator yet)                         → custodian = ⊥  (NOBODY may sign —
//                                                    zero live signers during transfer)
//                                                    retired/placement unchanged
//   last = ActivationBundle (terminating move n)   → custodian = bundle.authorization.to_machine
//                                                    retired ∪= bundle.retired_bindings (cumulative)
//                                                    placement = (bundle.placement_record, epoch n)
//   last = AbortRecord (terminated move n)         → custodian = that move's from_machine
//                                                    retired/placement unchanged
//   last = RetireReceipt (post-bundle bookkeeping) → all values unchanged
// phase, by the same cases: mint/AbortRecord/RetireReceipt → Idle;
// MoveAuthorization|ExportReceipt|ImportReceipt → MidMove{from,to};
// ActivationBundle → RetirePending{from}. Total: one arm per record kind.
```

**Key possession is an INPUT, not part of the fold** (r4-1): `holds_key(M, A)`
is machine-local durable fact (the key file exists). The signing gate is
exactly:

```rust
may_sign(M, A)    = holds_key(M, A) ∧ custodian(A) == M
quiesced(M, A)    = holds_key(M, A) ∧ (phase(A) == MidMove{from: M, ..}
                                     ∨ phase(A) == RetirePending{from: M})
quarantined(M, A) = holds_key(M, A) ∧ phase(A) == MidMove{to: M, ..}
```

All four predicates are pure functions of the SAME two inputs — the
four-value fold and `holds_key` — with no reference to any state outside
them; "active move" appears nowhere as a free-standing notion. The
post-activation source is `RetirePending{from}` and therefore *quiesced*
exactly as the crash matrix (§5.3) tabulates, until `RetireReceipt`
deletes the key (`holds_key` false → no label applies).

`quiesced`/`quarantined` derive from the fold's `phase` — never
independent state. Every crash matrix
row in §5.3 is one row of this table: initial state (mint custodian
signs), mid-move (custodian = ⊥ — source and target both hold but
neither signs), post-activation (target), post-abort (source restored).

Consequences, all by construction rather than by argued ordering:

- **No ordered mutations exist to crash between.** A receiver of a bundle
  durably stores the verified record — one append — and every gate reads
  the fold (memoization is an optimization; a stale cache can only lag
  the log, never diverge from it).
- **Partial application is impossible, not merely mitigated**: there is
  no "tombstone known but placement not" state, because both are the
  same function of the same stored records. r2/r3 ordered-mutation
  arguments (including the "tombstone-first" apply order) are deleted.
- **Replay is trivially idempotent**: re-delivering a record changes
  nothing (identical bytes → identical fold).
- **Un-quarantine is one rule (r3 b)**: the target may sign as A exactly
  when it holds the key and its local log's `custodian(A)` is it. No
  separate "flip the gate" transition exists to crash before/after.
- **Abort (r3 d)**: an `AbortRecord` restores `custodian(A)` to the
  move's `from_machine`; `retired_bindings` and `placement` are
  untouched. Rollback = append one record.

### 3.3 Verification rules: participants vs mesh (r3 a)

Participants (source, target, owner devices) hold the full per-agent log;
ordinary mesh peers never see pre-activation records (they are carried
operator-side, §5.4) and therefore **cannot CAS against a move head**.
Two rules, one derivation:

**Participant rule** (the only writer path): a record is accepted iff
(1) all signatures verify (owner + machine countersignatures),
(2) `record.prev == head_hash(agent)` — compare-and-swap,
(3) the kind is a legal successor of the head's kind (§5.1),
(4) for `ActivationBundle`: the cross-field coherence list (§7.5).
Forks (two records claiming one `prev`) keep the first-valid and
drop-and-alert the challenger. r1's "reject epoch ≤ highest seen" rule is
gone — ordering is the chain.

**Mesh rule** (no head, no pre-activation records): an
`ActivationBundle` is accepted for agent A iff
(1) the owner signature over the whole record verifies;
(2) cross-field coherence holds (§7.5 — the embedded authorization makes
the record self-contained; nothing is recomputed from elsewhere);
(3) **placement epoch monotonicity**: the bundle's `move_epoch` ≥ the
epoch of the peer's current `placement(A)` (equal epoch with identical
digest is a replay no-op; a lower-epoch bundle's PLACEMENT is stale).

**Tombstone accumulation is a separate, order-independent union (r4-3):**
every accepted bundle merges its `retired_bindings` into the peer's
grow-only set — REGARDLESS of epoch. Because the owner's set is
cumulative, any single bundle (and a fortiori the highest-epoch one)
reconstructs the full history: a peer that first sees epoch 2 still
learns epoch 1's retired binding from epoch 2's embedded set. Dropping a
lower-epoch bundle's placement therefore never discards an unseen
historical revocation. `PlacementMint` records ride the blob path
(§8.2) under the same signature + coherence rule with epoch 0.

The peer durably stores verified bundles; its fold reads them. Transport
(aligned with blob-v2's actual capabilities, §8.2): the activation topic
`x0x.move.activation.v1` carries each bundle on-change + periodic
republish (heartbeat piggyback pattern, `src/lib.rs:2937-2965`) — the
latest bundle alone suffices for both tombstones and placement — and
blob-v2's `Bundle` kind fetches any specific historical bundle by digest
on demand (e.g. audit).

Both rules feed the same fold; a participant's view is strictly more
informed (it also knows pre-activation state), never contradictory.

### 3.4 Chain growth

`move_epoch` increments only on a new `MoveAuthorization`, whose `prev`
must be the record that terminally ended the previous move
(`ActivationBundle`/`RetireReceipt`, or `AbortRecord` after a rollback);
a burned epoch can never reappear because every future record must chain
past the record that ended it.

## 4. Export envelope

Payload: `bincode(AgentKeypair::to_bytes())` (both halves; the target
verifies `SHA-256(pub) == agent_id` before trusting anything). Sealed
with `seal_bytes_to_recipient(target machine KEM key, aad = auth_bytes,
keypair_bytes)`.

AAD = the **MoveAuthorization canonical bytes**: the envelope is bound to
`(agent, epoch, from, to)` — cross-move replay, re-targeting, and
envelope substitution all fail the AEAD tag (`src/groups/kem_envelope.rs:161-166`).
`envelope_digest = blake3(kem_ct ‖ nonce ‖ aead_ct)` is committed only in
the `ExportReceipt` — never in the auth — keeping §3.1 acyclic.

## 5. The ceremony: appends and derivations (r3 core)

### 5.1 Legal transitions

```
PlacementMint → MoveAuthorization → ExportReceipt → ImportReceipt → ActivationBundle → RetireReceipt
                       │                 │                │
                       └──── AbortRecord ┴────────────────┘   (pre-activation terminator; epoch burned)
```

### 5.2 The only durable writes

1. **Log appends** — one `ChainedRecord` per append, length-framed,
   fsynced; a torn final frame is discarded on load (the atomic-write +
   tail-tolerance pattern of `revocations.bin`, `src/storage.rs:693`).
2. **The envelope file** on the source until retirement (operator
   transfer media in between).
3. **Secure deletion** of the source's key material at retirement.

There are **no durable flags left to order**: r2/r3's intent marker,
quiesce flag, quarantine flag, and retire-pending marker are all
replaced by the §3.2 derivations — the signing gate reads the log
(§6), so "crashed between setting the flag and sealing" cannot occur;
either the authorization is in the log (⇒ quiesced, by derivation) or no
envelope exists yet.

### 5.3 Crash matrix — every state IS the log; re-entry IS a re-read (r3 core)

| Log state for the agent (participant view) | Source derives | Target derives | Mesh derives | Re-entry |
|---|---|---|---|---|
| `PlacementMint` (genesis) | `custodian` = mint machine — may sign | — | mint placement (via blob) | begin a move |
| + `MoveAuthorization` (no terminator) | holds key, **quiesced** (`custodian`=⊥); seal (or abort) | — | nothing (not replicated) | seal; or abort |
| + `ExportReceipt` | quiesced; envelope durable | — | nothing | transfer envelope |
| + `ImportReceipt` | quiesced | holds key, **quarantined** (`custodian`=⊥) | nothing | owner verifies, then activate; or abort |
| + `ActivationBundle` | quiesced, retire-pending (holds dead key) | **`custodian`** — may sign (same verified record) | `retired_bindings` ∪= cumulative set; placement (mesh rule) | source retires |
| + `RetireReceipt` | move closed (key deleted → `holds_key`=false) | may sign | unchanged | none |
| `AbortRecord` from any pre-activation head | **`custodian` restored** — may sign again | discards key | unchanged (abort is not mesh-carried) | next move = epoch+1 |

Operator/file-level states (not log states): crash before the envelope
reaches the operator → re-transfer (envelope + receipt are on the source
disk); crash before import → import at leisure; the bundle handed to the
operator is self-contained. Torn log tail → discarded, re-append.

The signer invariant: **at most one** live signer at every instant —
zero during transfer (`custodian` = ⊥), exactly one after completion or
abort — because `custodian(A)` is single-valued at every legal log shape
and the gate conjoins it with key possession (§3.2).

The key never exists solely on a machine that acknowledged deletion: the
envelope persists until `RetireReceipt`, and deletion follows the bundle.

### 5.4 Who stores what

- **Owner machine**: the per-agent logs (append-only `moves.bin`) — the
  ceremony driver. Pre-activation records are **not** mesh-replicated;
  the operator CLI carries them between participants.
- **Source/target**: the same logs (participant rule) + the envelope
  file + the imported key material. Re-entry on startup = re-read log,
  derive, continue.
- **Mesh peers**: durably stored, mesh-rule-verified bundles (and mint
  placement records via blob-v2) — `move-bundles.bin`; derivations read
  them. Post-activation republication on the bundle topic serves late
  joiners; the ad-hoc tombstone carrier (§7.4) serves non-move
  revocations.
- Every command takes `(agent_id, move_epoch)` and resumes/no-ops
  against the log — idempotent because state IS the log.

## 6. AgentSigningGate (r2-4, r3 b)

The shipped architecture hands out `&AgentKeypair` (`src/identity.rs:879`)
and production paths sign directly — `/agent/sign`
(`src/server/routes/identity.rs:905-911`), DM envelopes and ACK
attestations (`src/dm_send.rs:53-56`, `src/dm_inbox.rs:2098` region),
forward headers (`src/forward.rs:195` region), gossip signing contexts,
group operations, announce building. Therefore:

- One `AgentSigningGate` service owns all agent signing. Every production
  path calls `gate.sign(agent_id, bytes)`; the gate evaluates exactly
  `may_sign` (§3.2) = `holds_key(this machine, agent) ∧ custodian(agent)
  == this machine` — the log fold and local key possession, nothing
  else — and signs through the existing ML-DSA call. Direct
  `agent_keypair()` access moves behind the gate for signing callers
  (read-only public-key access stays). There is no separate gate-state
  to maintain or crash between.
- Scope, honestly: single-live-signer **among cooperating daemons**. An
  offline copy of a stolen key still produces cryptographically valid
  agent signatures; those are rejected only at gates that carry machine
  context (§9) and only at receivers holding the tombstone.
  Cryptographic single-signer semantics need key rotation — out of
  scope because `AgentId` IS the key hash (ADR-0007).

## 7. Binding revocation

### 7.1 Subject — epoch-carrying

```rust
pub enum RevokedSubject {
    Agent(AgentId),                                 // 0x01 — unchanged
    Machine(MachineId),                             // 0x02 — unchanged
    AgentMachineBinding { agent: AgentId,           // 0x03 — NEW
                          machine: MachineId,
                          move_epoch: u64 },        // in signed bytes
}
```

Canonical message: `prefix ‖ 0x03 ‖ agent ‖ machine ‖ epoch_le` (fixed
widths — no boundary ambiguity, `src/revocation.rs:94-118` pattern). The
epoch orders tombstones against placement records (§9) and rides in the
signed bytes.

### 7.2 Authority — owner key only

`verify_authority` (`src/revocation.rs:164-211`) extended: for a binding
subject, the issuer must be the user key that signed the subject agent's
`AgentCertificate` — the certificate travels INSIDE the
`ActivationBundle` (§3.1), because shipped authority verification
**rejects issuer-revocations that present no subject cert**
(`verify_and_insert` threads `subject_cert`, `src/revocation.rs:359-376`;
the gossip arm resolves it the same way, `src/lib.rs:7698-7705`); the
discovery cache is the fallback source (`DiscoveredAgent.agent_certificate`,
`src/lib.rs:1646`). Self-revocation cannot apply: the issuer key hashes
to one 32-byte id; the subject contains two ids plus an epoch. Neither
the moving agent key nor either machine key can issue or suppress a
tombstone.

### 7.3 Permanence

`expire_records_older_than` (`src/revocation.rs:398-423`, driven at
`src/lib.rs:2761`) skips binding records. Permanent, grow-only —
ADR-0018's original rule, restored for the subject class where
resurrection is a security hole. In the derived view this is literal:
`ActivationBundle` records are never garbage-collected from
`move-bundles.bin`; the tombstone set only grows.

### 7.4 Carrier — v1 untouched (r2-6)

The v1 wire publishes the **entire set as one `Vec<RevocationRecord>`**
(`src/lib.rs:2951-2958`) and receivers deserialize the whole vector
(`:7689-7695`). A batch containing variant `0x03` would poison every
legacy record in it for old peers. Therefore:

- **Move tombstones ride inside `ActivationBundle`s** on the activation
  topic (§7.5) — the bundle is the mesh carrier.
- **Ad-hoc tombstones** (an owner revoking a binding outside any move —
  e.g. a stolen machine discovered later) ride a new topic
  `x0x.revocation.v2` (`v1` is `src/lib.rs:484`), payload
  `Vec<RevocationRecord>` of binding records only, epoch = the current
  derived placement epoch.
- v1 publication **filters to Agent/Machine records only** — byte-identical
  to today; the coarse machine-revocation backstop keeps working for old
  peers.
- Persistence: v1 `revocations.bin` (magic `X0XR`) unchanged; mesh bundle
  store `move-bundles.bin`; ad-hoc store `revocations-v2.bin` (magic
  `X0R2`); all three feed the same in-memory derivation.
- Issuance: `Agent::revoke_binding(&UserKeypair, agent, machine, epoch,
  reason)` reusing `apply_and_publish_revocation` (`src/lib.rs:9066`)
  semantics; `POST /identity/revoke` gains the both-fields form
  (owner-key signed), single-field forms unchanged
  (`src/server/routes/identity.rs:1147-1170`).
- Accessors: `is_binding_revoked(&AgentId, &MachineId) -> bool` and
  `max_revoked_binding_epoch(&AgentId) -> Option<u64>` beside
  `is_agent_revoked`/`is_machine_revoked` (`src/revocation.rs:318`,
  `:324`) — thin reads over the derived tombstone set.

### 7.5 The ActivationBundle on the mesh — self-contained and cumulative (r4-2/3)

- **Self-contained (r4-2):** the canonical `MoveAuthorization` rides
  INSIDE the signed bundle (`authorization` field, §3.1) — mesh peers
  never see pre-activation records, so nothing is recomputed from
  elsewhere: `agent_id`, `move_epoch`, `from_machine`, `to_machine`, and
  the declared placement are all in-record. Participants additionally
  check the embedded authorization equals their log's record (the chain
  already links them; the embedding makes the bundle verifiable
  standalone).
- **Topic** `x0x.move.activation.v1`. **Payload:** exactly one
  `ChainedRecord { prev, ActivationBundle }`, republished on-change and
  periodically for late joiners; blob-v2's `Bundle` kind fetches any
  specific historical bundle by digest (§8.2).
- **Verification** is §3.3's mesh rule: whole-record owner signature,
  cross-field coherence, placement-epoch monotonicity, cumulative
  tombstone union. Accepted bundles are durably stored; nothing is
  "applied" — gates read the fold.
- **Cross-field coherence (r3 c)** — one record, one move, checked as a
  unit against the EMBEDDED authorization `auth` (all fields in-record):
  1. owner signature over the whole chained record verifies;
  2. `agent_certificate.verify()` ∧ `cert.agent_id() == auth.agent_id` ∧
     the certificate's issuer (user key) == the record's owner signer;
  3. `retired_bindings` is non-empty, contains `AgentMachineBinding {
     auth.agent_id, auth.from_machine, auth.move_epoch }` (this move's
     tombstone), and every entry is owner-covered by the bundle
     signature. Cumulative completeness (superset of every earlier
     committed bundle's set) is a CONSTRUCTION invariant: the owner
     builds the set by folding its own full log and participants —
     which hold the full log — verify it at signing time. Mesh peers
     do NOT check supersetness (they may lack earlier bundles and must
     accept out-of-order arrivals); they union every verified bundle's
     set regardless of order, so a peer seeing epoch 2 first still
     gains epoch 1's tombstones from the cumulative set, and a
     later-arriving epoch-1 bundle only ever adds entries;
  4. `placement_record.agent_id == auth.agent_id` ∧
     `placement_record.placement_epoch == auth.move_epoch` ∧ placement
     is `Pinned(auth.to_machine)` or `Roaming` (matching the declared
     placement) ∧ same owner issuer;
  5. for a `Pinned` authorization: `auth.to_machine` equals the
     placement pin (a move may only pin to its target).
  A record failing any clause is dropped whole; there is no partially
  accepted bundle because there is no application step — only
  store-if-coherent. Clause 3's supersets are monotone by construction
  at the owner (the owner folds its own log to build the set), so
  accepting an older owner-signed bundle's set is the same trust as
  accepting any owner-signed revocation — union is safe in any order.

## 8. Placement ledger

### 8.1 Record

```rust
pub struct PlacementRecord {
    agent_id: AgentId,
    owner_public_key: Vec<u8>,   // = AgentCertificate issuer
    placement: Placement,        // Pinned(MachineId) | Roaming (unpinned)
    placement_epoch: u64,        // = move_epoch that produced it (0 = mint)
    issued_at: u64,
    signature: Vec<u8>,          // owner ML-DSA-65, domain "x0x-placement.v1"
}
```

`Roaming` names **no machine**: a roamer's per-machine authorization is
exactly the derived tombstone set; `Pinned(MachineId)` carries the pin
compared at gates.

### 8.2 Shipped-Home reality and the mint (explicit reconciliation)

Production main has **no** Pinned/Roaming state: `GET /owner/agents` is
the certificate journal (`owner-cert-journal.jsonl`,
`src/server/routes/profile.rs:150-157`) and ADR-0038 shipped only the
`OwnerCertified` admission core (#432). Placement is therefore **new
state introduced by this ADR**, owner-key-signed, living in the log:

- **Mint**: the per-agent log's genesis record is a `PlacementMint`
  (epoch 0), lazily appended at first move or first
  `GET /owner/placement`. Default `Pinned(machine where last
  certified/seen)` with `custodian_machine` = that machine. **Exception:**
  the mint must satisfy ADR-0038's ≥1-Roaming Home requirement from
  birth — the mint designates the install's local agent (or an explicit
  operator choice) as `Roaming` (custodian = its generating machine)
  and refuses to mint all-Pinned.
- **Ongoing rule:** activation refuses any move whose placement outcome
  would leave zero `Roaming` among the owner's certificated agents.
  When Home-as-group ships, its roster reads this derivation; until then
  the log is the single source of truth, replicated owner-to-owner per
  ADR-0041 Tier 1.
- **Current placement is derived**: the payload of the last
  placement-bearing record (mint or newest committed bundle, §3.2).
- Distribution: mint and bundle placement digests ride
  `MachineAnnouncementV3.placement_digests` (§2.1); records fetch via
  `AnnounceBlobRequestV2 {kind: CertPair|Placement|Bundle, digest,
  requester}` on `x0x/announce/v2/blob` with v2 response domains — the
  `Bundle` kind (r4-3) fetches a specific historical
  `ActivationBundle` by `blake3(chained-record bytes)` on demand, so
  mesh history is fetchable and verifiable, not just push-replicated.
  The shipped v1 cert path (`src/announce_blob.rs:49-54`, `:98`, `:506`) is untouched.
  The v2 placement cache has its own disk file and verify-before-cache
  gate (owner signature, owner = cert issuer, `agent_id` match, digest
  match, mesh-rule epoch monotonicity). Old peers keep serving v1 cert
  blobs; placement fetches run 0043-peer-to-0043-peer only.

## 9. Enforcement — every live path

Two checks, evaluated wherever `(agent, machine)` is known, both reading
the derived state:

- **B** — `is_binding_revoked(agent, machine)` reads the grow-only
  union of cumulative bundle `retired_bindings` + ad-hoc v2 tombstones;
- **P** — if a placement record is cached for the agent and
  `placement_epoch >= max_revoked_binding_epoch(agent)` (vacuously true
  when no tombstone exists) and placement is `Pinned(X)` with
  `X ≠ machine` → deny. **Equality is the coherent activation case**: the
  tombstone and successor placement record carry the same epoch because
  one bundle mints both; only strictly older records are stale; an absent
  record allows (fail-open, §9.3). A forged equal-epoch record with a
  different pin fails the owner signature.

| Gate (shipped) | Where | Check |
|---|---|---|
| Outbound streams | `Agent::gate_peer_outbound` `src/lib.rs:10497` | B, P for `(agent, resolved machine)` — per pairing, including stale cached source pairings during the transition window |
| Inbound streams + datagram lanes | `Agent::gate_peer_machine_inbound` `src/lib.rs:10557` (per resolved agent, fail-closed multi-agent) | B, P per `(agent, machine)` |
| Gossip DMs | attestation resolve `src/dm_inbox.rs:1231` then revoked-sender drop `:1302`/`:2171` | B, P on `(sender, attested machine)` |
| Direct-QUIC DMs | `src/lib.rs:10313-10327` (`direct::inbound_peer_revoked`) | B, P |
| Forward mid-flight | `src/forward.rs:757-760` | B, P for **every** `(agent, machine)` pairing the lane resolves — both machines during the transition window, never per agent |
| Announce ingest/eviction | `src/lib.rs:7952`, `:7960` | drop announces whose binding is revoked; **and** a cached placement record satisfying the P epoch rule with `Pinned(X)`, `X ≠ announce.machine_id` ⇒ drop — a pinned agent announcing from a non-pinned machine is rejected at ingest; stale P beats evicted on newer placement epoch |
| Pubsub delivery sender-gate | `src/gossip/pubsub.rs:1397` | B impossible — no machine context; enforced one layer up (DM/stream). Documented, not silent. |

**Transition window** (bundle observed … `RetireReceipt`): discovery can
hold the agent on **both** machines; every gate evaluates B/P per
pairing — source pairings fail B, target pairings pass B and P.

Announce **signature verification** stays stateless (self-certification
only, `src/announce_v3.rs:180` region). The **ingest/cache-merge step**
additionally applies B and P from already-local derived state; the check
triggers no fetch, so gapcheck #13's blob-miss-as-admission-oracle
concern does not apply — absent evidence fails open, present evidence
fails closed.

### 9.3 Old peers

Pre-0043 peers: not on machine-announce v3, activation, revocation-v2,
or blob-v2 topics — they never see bundles/tombstones/placements and
fail open (unchanged traffic, no decode risk). Mitigations:
`move_protocol: 1` capability advert makes them visible during
`Export`/`Activate` (concrete peer list warning); the coarse
`Machine(from)` revocation on **v1** remains a real manual backstop. The
window closes by fleet upgrade, same as V2∥V3∥X0A4.

## 10. Compatibility summary

- Identity announces (`X0A3`/`X0A4`): untouched bytes, untouched magic.
- Machine announce: v2 untouched; v3 is a new topic (no in-place growth;
  decoder is `reject_trailing_bytes`, `src/lib.rs:2296`).
- Revocations: v1 topic/payload byte-identical (legacy subjects only);
  move tombstones ride bundles on `x0x.move.activation.v1`; ad-hoc
  tombstones ride `x0x.revocation.v2`; the struct gains a variant that
  v1 never carries.
- Blob protocol: v1 cert path untouched; v2 is kind-tagged and separate.
- On-disk: no existing format changes; new files: machine KEM key,
  `moves.bin` (participants), `move-bundles.bin` (mesh),
  `placement-blobs.bin`, `revocations-v2.bin` (ad-hoc).

## 11. API surface

| Endpoint | Change |
|---|---|
| `POST /agent/move` | new (owner): `{agent_id, to_machine, placement}` → chain `MoveAuthorization`; source seals, returns bundle (auth ‖ receipt ‖ envelope, base64) |
| `POST /agent/move/import` | new (target): bundle in → verify, store key, countersign `ImportReceipt` (quarantine is derived) |
| `POST /agent/move/activate` | new (owner): `{agent_id, move_epoch}` → verify coherence (§7.5), append `ActivationBundle`, publish on the activation topic |
| `POST /agent/move/abort` / `/retire` | new: append rollback terminator / retirement receipt |
| `GET /agent/moves` | new: log view + derived state (quiesced/quarantined/live signer, current placement) |
| `GET /owner/placement` | new: derived ledger view + mint status |
| `POST /identity/revoke` | new both-fields form → owner-signed ad-hoc binding revocation (v2 carrier) |
| `GET /owner/agents` | unchanged output + `placement_epoch` digest enrichment |

Owner-key-gated throughout; rider credentials (ADR-0039) denied by their
deny-by-default scope.

## 12. Test plan

**Unit**

1. Participant chain CAS: legal orderings accepted; illegal kinds
   rejected; fork challenger dropped; replay no-op; burned epoch never
   re-extendable.
2. Total fold (§3.2): for EVERY legal log shape — mint-only (initial
   signer), mid-move (custodian = ⊥), post-bundle, post-abort (source
   restored), post-retire — `custodian`, `retired_bindings`,
   `placement`, and `phase` take exactly the tabulated values and are
   never undefined; `may_sign` = `holds_key ∧ custodian==M` with `holds_key`
   supplied as an input, including the cases key-present-but-not-
   custodian (quiesced/quarantined) and custodian-but-key-deleted.
3. Mesh rule: placement accepted on ≥ epoch, no-op on equal digest,
   stale placement dropped on lower epoch; **tombstones union in every
   acceptance order** — a peer seeing epoch 2 first still holds epoch
   1's retired binding from the cumulative set; no head required.
4. Cross-field coherence (§7.5): each clause violated in isolation
   (swapped cert, mismatched from/to/epoch, non-cumulative
   `retired_bindings`, foreign placement payload, pin ≠ target) drops
   the record whole.
5. Acyclicity: `ExportReceipt` verifies only against the auth in its
   `auth_hash`; envelope AAD substitution (other move, other target)
   fails AEAD.
6. Binding authority matrix: owner ✓; agent ✗; source/target machine ✗;
   third user ✗; self-revocation structurally unreachable; bundle
   without the certificate fails authority (shipped rule,
   `src/revocation.rs:359-376`).
7. Carrier split: v1 batch never contains `0x03`; v1-only decoder
   accepts every v1 publication; ad-hoc v2 round-trips; old peers' v1
   enforcement intact.
8. TTL sweep exemption: binding/bundle records survive; agent/machine
   records still expire (`src/revocation.rs:534` pattern).
9. Placement: **equal** epoch enforces (coherent activation case),
   strictly-older ignored, absent fails open; forged equal-epoch pin
   fails the owner signature; mint always yields ≥1 Roaming; all-Pinned
   mint rejected.
10. Signing gate: quiesced and quarantined agents refused on
    `/agent/sign`, DM sign, forward sign; public-key reads unaffected;
    un-quarantine occurs exactly when the local fold's custodian is this
    machine and the key is held.
11. Blob v2: kind framing (CertPair/Placement/Bundle); placement
    verify-before-cache rejects wrong-owner, wrong-agent,
    digest-mismatch, stale-epoch; Bundle fetch returns a historical
    bundle that verifies standalone (embedded authorization) and merges
    its cumulative tombstones; v1 cert path byte-identical.

**Integration / E2E**

12. Crash recovery = log re-read: for every §5.3 row, kill the process
    mid-ceremony and restart — derived state matches the table; **at
    most** one live signer at every sampled instant, exactly one after
    completion or abort; torn-tail append discarded and re-appended.
13. Post-Activate: source traffic (fresh, VALID attestations) drops at
    every enforcing gate on upgraded peers; co-resident source agents
    unaffected; v1-only peer still enforces a legacy machine revocation.
14. Transition window: agent discoverable on BOTH machines — forward
    lane and outbound open per pairing resolve correctly (source pairing
    denied by B, target accepted).
15. Stolen-copy: offline-signed DM from source machine fails B at
    upgraded receivers; offline signature with no machine context still
    verifies (documented residual).
16. Home: mint produces ≥1 Roaming; activation refuses stranding; moving
    a roamer keeps it Roaming.
