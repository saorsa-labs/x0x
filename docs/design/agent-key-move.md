# Agent Key-Move Protocol — Design Mechanics (r3)

Companion to [ADR 0043](../adr/0043-agent-key-move-protocol.md), which
**amends [ADR 0037](../adr/0037-agent-placement-and-key-custody.md)**.
r3 responds to the round-2 Codex review (`codex-r2-wp4.md`); r2
responded to the round-1 review (`codex-review-wp4.md`). Every citation
was re-verified against `origin/main@ccb288e` in the worktree (r1's
baseline read was accidentally taken from a stale checkout — that is how
the shipped `X0A4` collision was missed; later rounds read the worktree
only).

Round-2 findings → sections:

| Finding | Section |
|---|---|
| 1. Equal epochs disable placement enforcement (`>` should treat equality as the coherent activation case) | §9 (P rule), §12.8 |
| 2. No atomic activation carrier; bundle lacked the certificate shipped authority verification requires | §3.1, §7.5 |
| 3. Recovery contradictions: abort legality vs diagram; "exactly one signer" vs zero-signer rows | §3.1, §5.2 (Abort), §5.3 invariant, §12.11 |

Round-1 findings → sections:

| Finding | Section |
|---|---|
| 1. `X0A4` already shipped; cert-specific blob path; machine key belongs in machine announce | §2, §8.2 |
| 2. Export-record cryptographic cycle | §3.1, §4 |
| 3. No transition chain / crash ordering / atomic activation / pre-activation log access | §3, §5 |
| 4. Single-live-signer not enforced by shipped signing paths | §6 |
| 5. Wrong stream-gate citation; missing direct-QUIC gate; no epoch in binding; `Roaming` naming; shipped-Home reality | §7, §8, §9 |
| 6. Unknown variant poisons the whole v1 revocation batch | §7.4 |

## 1. What exists today (re-verified at `ccb288e`)

| Mechanism | Status | Where |
|---|---|---|
| Identity announce V3 `X0A3` + V3.1 **`X0A4`** (self_name, dual-published) | shipped (ADR-0036, #430) | `src/announce_v3.rs:37`, `:43`, `:503` |
| Machine announce on topic `x0x.machine.announce.v2`, machine-signed, feeds `DiscoveredMachine` | shipped | `src/lib.rs:468`, `:1330`, `:1774`, decoder `:2291-2297` |
| Cert blob fetch-on-miss — **certificate-specific**: `CachedBlob` is the `(UserId, AgentCertificate)` pair; request/response/domains/cache/disk all assume it | shipped | `src/announce_blob.rs:49`, `:54`, `:98`, `:506` |
| ML-KEM-768 `AgentKemKeypair` (serde, decapsulate) | shipped | `src/groups/kem_envelope.rs:41` |
| KEM seal/open — **32-byte plaintext only** | shipped | `src/groups/kem_envelope.rs:140`, `:176` |
| Revocation records + grow-only set | shipped | `src/revocation.rs:47`, `:164` |
| Revocation wire: heartbeat publishes the ENTIRE set as one `Vec<RevocationRecord>` on `x0x.revocation.v1`; receive deserializes the whole vector in one op | shipped | `src/lib.rs:2951-2958`, `:7689-7695`, topic `:484` |
| 90-day revocation TTL sweep | shipped | `src/revocation.rs:398`, driven `src/lib.rs:2761` |
| Stream gates: `Agent::gate_peer_outbound`, `Agent::gate_peer_machine_inbound`, shared `streams::stream_gate` (revoked/trust/expired) | shipped | `src/lib.rs:10497`, `:10557` |
| Gossip-DM gate: origin attestation resolve + revoked-sender drop | shipped | `src/dm_inbox.rs:1231`, `:1302`, `:2171` |
| Direct-QUIC DM delivery gate (`direct::inbound_peer_revoked`) | shipped | `src/lib.rs:10313-10327`, `src/direct.rs:128` |
| Forward mid-flight revocation re-check | shipped | `src/forward.rs:757-760` |
| Announce ingest eviction of revoked agents/machines | shipped | `src/lib.rs:7952`, `:7960` |
| Signing paths hold the raw key: `/agent/sign` uses `keypair.secret_key()` directly; `Identity::agent_keypair()` hands out `&AgentKeypair` | shipped | `src/server/routes/identity.rs:905-911`, `src/identity.rs:879` |
| `GET /owner/agents` — cert-journal roster (`owner-cert-journal.jsonl`) + discovery enrichment; **no Pinned/Roaming state exists in production** | shipped (ADR-0036) | `src/server/routes/profile.rs:130-200` |
| Home (ADR-0038): only the `OwnerCertified` admission core has shipped (#432); no Home designation, no roaming roster | shipped core only | `src/server/routes/named_groups.rs` |

New in this design: `MachineAnnouncementV3` (machine KEM key + placement
digests), byte-wise KEM seal/open siblings, the move-record hash chain and
move log, `AgentMachineBinding` revocation + v2 carrier, the placement
ledger, the `AgentSigningGate`.

## 2. Machine KEM enrollment (finding 1)

### 2.1 Carrier: version the machine announcement, not the identity announce

The machine KEM public key is machine-scoped data; it belongs in the
machine announcement, not duplicated into every resident agent beat. The
shipped machine announce is topic-versioned already (`x0x.machine.announce.
v2` versioned v1 away, `src/lib.rs:468`) and its body is positional
bincode with `reject_trailing_bytes` (`src/lib.rs:2296`) — so the version
boundary is the **topic**, exactly the precedent the fleet has already
exercised:

- New topic `x0x.machine.announce.v3`. New payload `MachineAnnouncementV3`
  = every `MachineAnnouncement` field (`src/lib.rs:1330`) plus:
  - `machine_kem_public_key: Vec<u8>` — ML-KEM-768 public key (~1184 B),
    inside the machine signature;
  - `placement_digests: Vec<(AgentId, [u8; 32])>` — the current placement
    record digest per resident agent (§8.2). The machine is not the
    placement authority (the owner is); it merely advertises pointers,
    and every fetched record is owner-verified before caching. A machine
    serving stale digests can only cause the same fail-open as "no
    record" (§9.3).
- Old peers are not subscribed to the v3 topic and never decode it — zero
  interaction with `X0A3`/`X0A4` identity traffic (r1's `X0A4` collision
  is moot: this design adds **no** identity-announce envelope).
- `DiscoveredMachine` (`src/lib.rs:1662`) gains
  `machine_kem_public_key: Option<Vec<u8>>` and
  `placement_digests: Vec<(AgentId, [u8; 32])>` (in-memory cache; merge
  never erases a known KEM key with an absent one).
- The keypair: ML-KEM-768, generated at first start, persisted beside the
  machine key; reuse the `AgentKemKeypair` construction
  (`src/groups/kem_envelope.rs:41`) under a `MachineKemKeypair` name.

Why not the identity announce: one machine key per machine once per beat,
not N copies for N resident agents; and the identity envelope lineage
(`X0A3`→`X0A4`) is already consumed by ADR-0036's name field.

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

## 3. Move records (findings 2, 3)

### 3.1 Record kinds — acyclic by construction

```rust
enum MoveRecord {
    // owner-signed; authorizes ONE move; contains NO envelope digest
    MoveAuthorization { agent_id, move_epoch: u64, from_machine,
                        to_machine, placement: Placement, issued_at },
    // source-machine-signed, owner-countersigned; commits to ciphertext
    ExportReceipt   { auth_hash: [u8;32], envelope_digest: [u8;32], sealed_at },
    // target-machine-signed, owner-countersigned
    ImportReceipt   { auth_hash: [u8;32], imported_at },
    // owner-signed ATOMIC bundle — activation is one record, not three.
    // The certificate is INSIDE the bundle: shipped authority verification
    // rejects issuer-revocations without the subject cert (§7.2).
    ActivationBundle { auth_hash: [u8;32],
                       binding_revocation: RevocationRecord,   // §7
                       placement_record: PlacementRecord,      // §8
                       agent_certificate: AgentCertificate },  // §7.2
    // source-machine-signed, owner-countersigned
    RetireReceipt   { auth_hash: [u8;32], retired_at },
    // owner-signed; legal from ANY pre-activation head —
    // MoveAuthorization | ExportReceipt | ImportReceipt — so an
    // intent+quiesce followed by an unrecoverable seal failure still
    // rolls back (r2 restricted this to post-receipt heads; fixed)
    AbortRecord     { auth_hash: [u8;32], reason },
}
struct ChainedRecord { prev: [u8; 32], record: MoveRecord,
                       owner_signature: Vec<u8> };  // machine sigs inside variants
```

Dependency graph is a DAG: `MoveAuthorization` → envelope (AAD = auth
canonical bytes, §4) → `ExportReceipt {auth_hash, envelope_digest}` →
… — r1's cycle (`envelope → digest inside auth → auth as AAD → envelope`)
is gone because the authorization never names the envelope and the receipt
never enters the AAD.

Domain separation: owner signatures cover
`b"x0x-agent-move.v1" || prev || kind-tag || variant-bytes` (mirrors
`REVOCATION_MSG_PREFIX`, `src/revocation.rs:40`).

### 3.2 Chain acceptance — compare-and-swap, not epoch filtering

Per agent, the move log is a single hash chain; `prev` = BLAKE3 of the
current head record. Acceptance rule (owner machine, and any replica that
later syncs the log):

1. verify all signatures (owner + any machine countersignatures);
2. `record.prev == head_hash(agent)` — else reject;
3. kind-ordering check: the kind must be a legal successor of the head's
   kind (§5.1);
4. on accept, `head(agent) ← record`.

Two records claiming the same `prev` = a fork (owner-key compromise or
operator error): first-valid wins, the challenger is dropped and alerts.
Replay is a no-op (identical bytes hash identically — the dedup property
already proven for revocations, `src/revocation.rs:260`). r1's "reject
epoch ≤ highest seen" rule — which rejected `Imported` after `Exported`
shared its epoch — is deleted; ordering is the chain, epochs are just
labels carried for the placement comparison (§9.2).

`move_epoch` increments only on a new `MoveAuthorization`, whose `prev`
must be the record that terminally ended the previous move
(`ActivationBundle`/`RetireReceipt`, or `AbortRecord` after a rollback);
a burned epoch can never reappear because every future record must chain
past the record that ended it.

## 4. Export envelope

Payload: `bincode(AgentKeypair::to_bytes())` (both halves; the target
verifies `SHA-256(pub) == agent_id` before trusting anything). Sealed with
`seal_bytes_to_recipient(target machine KEM key, aad = auth_bytes,
keypair_bytes)`.

AAD = the **MoveAuthorization canonical bytes**: the envelope is bound to
`(agent, epoch, from, to)` — cross-move replay, re-targeting, and envelope
substitution all fail the AEAD tag (`src/groups/kem_envelope.rs:161-166`).
`envelope_digest = blake3(kem_ct ‖ nonce ‖ aead_ct)` is committed only in
the `ExportReceipt` — never in the auth — keeping §3.1 acyclic.

## 5. The ceremony: states, durable ordering, crash behavior (findings 3, 4)

### 5.1 Legal transitions

```
MoveAuthorization → ExportReceipt → ImportReceipt → ActivationBundle → RetireReceipt
        │                 │                │
        └──── AbortRecord ┴────────────────┘   (pre-activation only; epoch burned)
```

State names (ADR language): Authorized → Sealed → Imported → Activated →
SourceRetired.

### 5.2 Exact durable orderings (fsync between every step)

**Source, export:**
1. persist intent marker `{auth}` → fsync;
2. set durable quiesce flag for the agent (the `AgentSigningGate` refuses
   everything from here) → fsync;
3. seal envelope; write envelope + `ExportReceipt` → fsync;
4. hand the bundle (auth ‖ receipt ‖ envelope) to the operator.

**Target, import:** verify auth + receipt signatures and `to_machine` =
self → decapsulate (`open_sealed_bytes` — possession of the machine KEM
secret is the machine proof) → verify `agent_id` binding → persist
keypair + durable **quarantine** flag → fsync → countersign
`ImportReceipt` (owner countersigns on receipt).

**Owner, activate:** verify head is `ImportReceipt` → check Home/roaming
invariant (§8.3) → build `ActivationBundle` (tombstone + successor
placement + the agent certificate, §7.5) → append to move log → fsync →
publish ONE message on the activation carrier (§7.5). Activation commits:
the chain now makes rollback structurally impossible (an abort can no
longer chain past `ActivationBundle`). The target's `AgentSigningGate`
un-quarantines the agent **only** on local verification of this bundle —
no component alone flips the gate.

**Source, retire:** observe the bundle (gossip or operator-carried) →
persist retire-pending → fsync → secure-delete key material → clear
quiesce state, persist retired → fsync → countersign `RetireReceipt`.

**Abort:** owner signs `AbortRecord` chaining from the current
pre-activation head — including straight from `MoveAuthorization`, which
covers crash-after-quiesce-before-seal (r2's text contradicted the
diagram here; the diagram was right); source un-quiesces and deletes the
envelope; target (if it imported) discards the quarantined key; epoch
burned either way.

### 5.3 Crash matrix

| Crash after | Startup behavior | Signers live |
|---|---|---|
| intent, before quiesce | intent present ⇒ quiesce immediately (fail-quiesced) | source (about to stop) — no envelope exists yet, nothing to lose |
| quiesce, before seal | re-run seal | none |
| seal, before receipt | re-seal; new receipt supersedes (import validates AAD=auth, any valid envelope opens) | none |
| receipt, before operator transfer | envelope + receipt on source disk; re-transfer | none |
| transfer, before import | import at leisure (bundle is self-contained) | none |
| import, before owner countersign | quarantine durable; owner re-verifies receipt | none (quarantined) |
| activation append, before gossip | log head is the bundle; re-publish | target (legitimately — committed) |
| gossip, before source sees it | source still quiesced + holding; operator or next gossip triggers retire | target only |
| retire-pending, before delete | re-run deletion (idempotent) | target only |
| delete, before receipt | re-emit receipt from retired marker | target only |

The invariant is **at most one** live signer at every instant — zero is
the transfer norm (r2 prose claimed "exactly one", contradicting the
zero-signer rows above); after a completed move **or** an abort exactly
one signer is restored. The key never exists solely on a machine that
acknowledged deletion — the operator-held envelope persists until
`RetireReceipt`.

### 5.4 Who stores what; re-entry without mesh access

- **Owner machine**: the move log (append-only `moves.bin`, atomic-write
  pattern of `revocations.bin`, `src/storage.rs:693`) + placement ledger.
  Pre-activation records are **not** mesh-replicated — the operator CLI
  carries them between machines (r1 implied daemons could read the
  owner's log remotely; withdrawn). Activation is mesh-replicated as the
  single bundle message on the activation carrier (§7.5); afterwards the
  embedded tombstone and placement record are also re-published on their
  steady-state carriers (§7.4, §8.2) for late joiners — republication,
  not the activation mechanism.
- **Source/target**: durable per-move markers (intent, quiesce,
  quarantine, retire-pending/retired) — startup re-entry per §5.3.
- Every command takes `(agent_id, move_epoch)` and is idempotent against
  the chain head: re-running reads the head and resumes or no-ops.

## 6. AgentSigningGate (finding 4)

The shipped architecture hands out `&AgentKeypair`
(`src/identity.rs:879`) and production paths sign directly — `/agent/sign`
(`src/server/routes/identity.rs:905-911`), DM envelopes and ACK
attestations (`src/dm_send.rs:53-56`, `src/dm_inbox.rs:2098` region),
forward headers (`src/forward.rs:195` region), gossip signing contexts,
group operations, announce building. A quiesce flag nobody consults is
not enforcement. Therefore:

- One `AgentSigningGate` service owns all agent signing. Every production
  path requests `gate.sign(agent_id, bytes)`; the gate refuses when the
  agent is quiesced (move in flight on this machine) or quarantined
  (imported, not yet activated) and otherwise signs through the existing
  ML-DSA call. Direct `agent_keypair()` access moves behind the gate for
  signing callers (read-only public-key access stays).
- Scope, stated honestly: this enforces single-live-signer **among
  cooperating daemons**. An offline copy of a stolen key still produces
  cryptographically valid agent signatures; those are rejected only at
  gates that carry machine context (§9) and only at receivers holding the
  tombstone. Cryptographic single-signer semantics require key rotation
  or HSM custody — out of scope because `AgentId` IS the key hash
  (ADR-0007): rotation is a new identity, i.e. a move-and-reissue, which
  this protocol makes safe.

## 7. Binding revocation (findings 1, 3, 6)

### 7.1 Subject — now epoch-carrying

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
epoch lets receivers order tombstones against placement records (§9.2)
and is carried **in the signed bytes**, not inferred.

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
to one 32-byte id; the subject contains two ids plus an epoch — equality
is structurally unreachable. Neither the moving agent key nor either
machine key can issue or suppress a tombstone.

### 7.3 Permanence

`expire_records_older_than` (`src/revocation.rs:398-423`, driven at
`src/lib.rs:2761`) skips binding records (match arms at `:411-418` stop
collecting them). Permanent, grow-only — ADR-0018's original rule,
restored for the subject class where resurrection is a security hole.
Bandwidth: one record per move on the v2 carrier, on-change + periodic
fallback (the heartbeat piggyback pattern, `src/lib.rs:2937-2965`).

### 7.4 Carrier — v2 topic, v1 untouched (finding 6)

The v1 wire publishes the **entire set as one `Vec<RevocationRecord>`**
(`src/lib.rs:2951-2958`) and receivers deserialize the whole vector
(`:7689-7695`). A batch containing variant `0x03` fails the old
`RevokedSubject` decode, so an old peer discards the batch **including
every legacy Agent/Machine record in it** — r1's "coarse machine
revocation as manual backstop" would never reach old peers from an
upgraded publisher. Fix:

- New topic `x0x.revocation.v2` (naming follows `x0x.revocation.v1`,
  `src/lib.rs:484`). Payload: `Vec<RevocationRecord>` containing only
  binding records (the same struct — old peers never subscribe to v2).
- v1 publication **filters to Agent/Machine records only** — byte-identical
  to today for old peers; the coarse backstop works again.
- Persistence: `revocations.bin` (magic `X0XR`, `src/revocation.rs:43`)
  keeps v1 records; bindings persist in `revocations-v2.bin` (magic
  `X0R2`); both load into one in-memory `RevocationSet`.
- Issuance: `Agent::revoke_binding(&UserKeypair, agent, machine, epoch,
  reason)` reusing `apply_and_publish_revocation` (`src/lib.rs:9066`) for
  local apply, publishing to **both** carriers (v2 always; v1 never —
  bindings are v2-only). `POST /identity/revoke` gains the
  both-fields form (owner-key signed), single-field forms unchanged
  (`src/server/routes/identity.rs:1147-1170`).
- New accessors: `is_binding_revoked(&AgentId, &MachineId) -> bool` and
  `max_revoked_binding_epoch(&AgentId) -> Option<u64>` beside
  `is_agent_revoked`/`is_machine_revoked` (`src/revocation.rs:318`,
  `:324`), backed by a `HashMap<AgentId, u64>` index updated on insert.


### 7.5 Activation carrier — the atomic artifact (round-2 finding 2)

Activation is carried by ONE message, not by its components:

- **Topic** `x0x.move.activation.v1`. **Payload:** exactly one
  `ChainedRecord { prev, ActivationBundle {auth_hash,
  binding_revocation, placement_record, agent_certificate} }` — the
  r2 draft claimed atomicity but then shipped the tombstone on
  revocation-v2 and the placement record through blob-v2 as separate
  objects; those carriers re-publish for late joiners (§5.4) and never
  carry activation itself.
- **Who verifies what, where.** Every 0043 peer subscribed to the topic
  runs one handler: (1) verify the owner signature over the whole
  chained record; (2) verify the embedded tombstone's authority with the
  embedded certificate (`verify_authority(Some(&cert))`, §7.2); (3)
  verify the embedded placement record's owner signature and that its
  issuer equals the certificate's issuer; (4) chain CAS — `prev` must
  equal the local head for that agent. The **target** additionally uses
  the same verified bundle as the only key that flips its
  `AgentSigningGate` out of quarantine (delivered by gossip or operator
  import — identical bytes, identical verification).
- **Why partial application is impossible.** All verification precedes
  any mutation, and the three mutations are each idempotent in a fixed
  fail-closed order: tombstone insert (record-hash dedup,
  `src/revocation.rs:425-441`) → placement cache insert (digest-keyed) →
  head advance (CAS). A crash mid-apply leaves a prefix in which the
  tombstone — the only security-relevant component — is already present;
  a missing placement merely fails open for the target until gossip
  at-least-once re-delivery re-runs the handler to convergence. No
  ordering of crashes can produce "placement applied, tombstone missing",
  because the tombstone is applied first.

## 8. Placement ledger (finding 5)

### 8.1 Record

```rust
pub struct PlacementRecord {
    agent_id: AgentId,
    owner_public_key: Vec<u8>,   // = AgentCertificate issuer
    placement: Placement,        // Pinned(MachineId) | Roaming (unpinned)
    placement_epoch: u64,        // = move_epoch that produced it
    issued_at: u64,
    signature: Vec<u8>,          // owner ML-DSA-65, domain "x0x-placement.v1"
}
```

`Roaming` names **no machine** (r1 prose said it did — corrected): a
roamer's per-machine authorization is exactly the binding-tombstone set;
`Pinned(MachineId)` carries the pin compared at gates.

### 8.2 Shipped-Home reality and the mint (finding 5, explicit reconciliation)

Production main has **no** Pinned/Roaming state: `GET /owner/agents` is
the certificate journal (`owner-cert-journal.jsonl`,
`src/server/routes/profile.rs:150-157`) and ADR-0038 shipped only the
`OwnerCertified` admission core (#432) — no Home designation exists.
Placement is therefore **new state introduced by this ADR**, an
owner-key-signed ledger (not group-CRDT state, not the named-group model):

- **Mint** (lazy, at first move or first `GET /owner/placement`): one
  epoch-0 record per journaled agent. Default `Pinned(machine where last
  certified/seen)`. **Exception:** the ledger must satisfy ADR-0038's
  ≥1-Roaming Home requirement from birth — the mint designates the
  install's local agent (or an explicit operator choice) as `Roaming`,
  and refuses to mint all-Pinned. The invariant is thus satisfied *by the
  mint*, not retro-fitted.
- **Ongoing rule:** `Activate` refuses any move whose placement outcome
  would leave zero `Roaming` among the owner's certificated agents
  (moving the last roamer to a `Pinned` placement is rejected with a
  named error). When Home-as-group ships, its roster reads this ledger;
  until then the ledger is the single source of truth, owner-key-signed,
  replicated owner-to-owner per ADR-0041 Tier 1.
- Distribution: digests in `MachineAnnouncementV3.placement_digests`
  (§2.1); fetch via **blob protocol v2** — kind-tagged
  `AnnounceBlobRequestV2 {kind: CertPair|Placement, digest, requester}`
  on `x0x/announce/v2/blob` with v2 response domains. The shipped v1 path
  (`x0x/announce/v3/blob`, cert-pair-only cache/responder/gate,
  `src/announce_blob.rs:49-54`, `:98`, `:506`) is untouched. The v2
  placement cache has its own disk file and verify-before-cache gate
  (owner signature, owner = cert issuer, `agent_id` match, digest match).
  Old peers keep serving v1 cert blobs; placement fetches run
  0043-peer-to-0043-peer only.

## 9. Enforcement — every live path (finding 5)

Two checks, evaluated wherever `(agent, machine)` is known:

- **B** — `is_binding_revoked(agent, machine)`;
- **P** — if a placement record is cached for the agent and
  `record.placement_epoch >= max_revoked_binding_epoch(agent)`
  (vacuously true when no tombstone exists) and placement is `Pinned(X)`
  with `X ≠ machine` → deny. **Equality is the coherent activation
  case** (round-2 finding 1): the tombstone and the successor placement
  record carry the SAME move epoch because one `ActivationBundle` mints
  both (§7.5); the r2 `>` rule made `n > n` false and silently disabled
  enforcement of the record a move had just produced. Only strictly
  older records (`placement_epoch < max_revoked_binding_epoch`) are
  ignored as stale; an absent record allows (fail-open, §9.3). A forged
  equal-epoch record with a different pin fails the owner signature, so
  equality cannot be exploited.

| Gate (shipped) | Where | Check |
|---|---|---|
| Outbound streams | `Agent::gate_peer_outbound` `src/lib.rs:10497` | B, P for `(agent, resolved machine)` — per pairing, including a stale cached source pairing during the transition window (below) |
| Inbound streams + datagram lanes | `Agent::gate_peer_machine_inbound` `src/lib.rs:10557` (per resolved agent, fail-closed multi-agent) | B, P per `(agent, machine)` |
| Gossip DMs | attestation resolve `src/dm_inbox.rs:1231` then revoked-sender drop `:1302`/`:2171` | B, P on `(sender, attested machine)` |
| Direct-QUIC DMs | `src/lib.rs:10313-10327` (`direct::inbound_peer_revoked`) | B, P |
| Forward mid-flight | `src/forward.rs:757-760` | B, P for **every** `(agent, machine)` pairing the lane resolves — during the transition window the agent is discoverable on BOTH machines, so the check must run per pairing, never per agent |
| Announce ingest/eviction | `src/lib.rs:7952`, `:7960` | drop announces whose binding is revoked (source heartbeats vanish fleet-wide); **and** a cached placement record satisfying the P epoch rule with `Pinned(X)`, `X ≠ announce.machine_id` ⇒ drop — an announce placing a pinned agent on a non-pinned machine is rejected at ingest, not only at the live gates; stale P beats evicted on newer placement epoch |
| Pubsub delivery sender-gate | `src/gossip/pubsub.rs:1397` | B impossible — no machine context on that path; enforced one layer up (DM/stream). Documented, not silent. |

**Transition window** (`ActivationBundle` observed … `RetireReceipt`):
discovery can hold the agent on **both** machines — the target announces,
the source entry lingers until eviction. Every gate above evaluates B/P
per `(agent, machine)` pairing: source pairings fail B (tombstone),
target pairings pass B and P (equal epoch, §P rule). Outbound opens
toward a stale cached source address die at `gate_peer_outbound`; the
forward re-check must iterate both machines' pairings (round-2 finding
2's forward note).

Announce **signature verification** stays stateless (self-certification
only, `src/announce_v3.rs:180` region). The **ingest/cache-merge step**
additionally applies B and P from already-local state (tombstone set +
placement cache); the check triggers no fetch, so gapcheck #13's
blob-miss-as-admission-oracle concern does not apply — absent evidence
fails open, present evidence fails closed.

### 9.3 Old peers

Pre-0043 peers: not on machine-announce v3 or revocation/blob v2 topics —
they never see bindings or placements and fail open (unchanged traffic,
no decode risk). Mitigations: `move_protocol: 1` capability advert makes
them visible during `Export`/`Activate` (concrete peer list warning); the
coarse `Machine(from)` revocation on **v1** remains a real manual
backstop now that v1 publication stays legacy-only (§7.4). The window
closes by fleet upgrade, same as V2∥V3∥X0A4.

## 10. Compatibility summary

- Identity announces (`X0A3`/`X0A4`): untouched bytes, untouched magic —
  r1's collision eliminated by moving machine KEM data to the machine
  announce lineage.
- Machine announce: v2 untouched; v3 is a new topic (no in-place growth;
  decoder is `reject_trailing_bytes`, `src/lib.rs:2296`).
- Revocations: v1 topic/payload byte-identical (legacy subjects only);
  bindings on v2 topic + `X0R2` store; `RevocationRecord` struct gains a
  variant — v1 wire never carries it.
- Blob protocol: v1 cert path untouched; v2 is kind-tagged and separate.
- Activation: new topic `x0x.move.activation.v1` carrying exactly one
  chained bundle per activation (§7.5); no existing topic changes.
- On-disk: no existing format changes; new files: machine KEM key,
  `moves.bin`, placement ledger, `placement-blobs.bin`, `revocations-v2.bin`.

## 11. API surface

| Endpoint | Change |
|---|---|
| `POST /agent/move` | new (owner): `{agent_id, to_machine, placement}` → chain `MoveAuthorization`, return bundle (auth ‖ receipt ‖ envelope, base64) after source sealing |
| `POST /agent/move/import` | new (target): bundle in → quarantine + `ImportReceipt` countersign |
| `POST /agent/move/activate` | new (owner): `{agent_id, move_epoch}` → `ActivationBundle` append + gossip |
| `POST /agent/move/abort` / `/retire` | new: pre-activation rollback / source retirement receipt |
| `GET /agent/moves` | new: chain view (head, per-epoch records) |
| `GET /owner/placement` | new: ledger view + mint status |
| `POST /identity/revoke` | new both-fields form → owner-signed binding revocation (v2 carrier) |
| `GET /owner/agents` | unchanged output + `placement_epoch` digest enrichment |

Owner-key-gated throughout; rider credentials (ADR-0039) denied by their
deny-by-default scope.

## 12. Test plan

**Unit**

1. Chain CAS: legal orderings accepted; illegal kinds rejected; fork
   challenger dropped; replay no-op; burned epoch never re-extendable.
2. Acyclicity: `ExportReceipt` verifies only against the auth in its
   `auth_hash`; forged/alternate envelope digest fails; envelope AAD
   substitution (other move, other target) fails AEAD.
3. Binding authority matrix: owner ✓; agent ✗; source/target machine ✗;
   third user ✗; self-revocation structurally unreachable.
4. Carrier split: v1 batch never contains `0x03`; v1-only decoder accepts
   every v1 publication; v2 round-trips bindings; mixed-set publish keeps
   old peers' v1 enforcement intact (regression test for finding 6).
5. TTL sweep exemption: bindings survive; agent/machine records still
   expire (`src/revocation.rs:534` pattern).
6. Blob v2: kind framing; placement verify-before-cache rejects
   wrong-owner, wrong-agent, digest-mismatch; v1 cert path byte-identical.
7. Signing gate: quiesced and quarantined agents refused on `/agent/sign`,
   DM sign, forward sign; public-key reads unaffected.
8. Placement: epoch comparisons — **equal** epoch enforces (the
   activation successor record is coherent with its own tombstone),
   strictly-older record ignored, absent record fails open; forged
   equal-epoch pin fails the owner signature; mint always yields
   ≥1 Roaming; all-Pinned mint rejected.
9. Activation carrier (§7.5): tampered inner tombstone fails the bundle;
   bundle without the certificate fails authority (shipped rule,
   `src/revocation.rs:359-376`); crash between the three idempotent
   mutations converges on re-delivery with the tombstone-first ordering
   preserved; no component alone flips the target signing gate.
10. Announce ingest: a pinned-agent announce from a non-pinned machine is
    dropped when a qualifying placement record is cached; passes when no
    record is cached (fail-open).

**Integration / E2E**

11. Full move with crash injection at every row of §5.3: re-entry
    converges; **at most** one live signer at every sampled instant and
    exactly one after completion or abort (gate counters prove refusals).
12. Post-Activate: source traffic (fresh, VALID attestations) drops at
    all enforcing gates on upgraded peers; co-resident source agents
    unaffected; v1-only peer still enforces a legacy machine revocation.
13. Transition window: with the agent discoverable on BOTH machines, a
    forward lane and an outbound open toward each pairing resolve
    correctly (source pairing denied by B, target pairing accepted).
14. Stolen-copy: offline-signed DM from source machine fails B at
    upgraded receivers; offline signature with no machine context still
    verifies (documented residual — assert it stays out of
    machine-context paths).
15. Home: mint produces ≥1 Roaming; activate refuses stranding; move of a
    roamer to another machine keeps it Roaming.
