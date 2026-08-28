# ADR 0043: Agent Key-Move Protocol — Machine KEM Enrollment, Commit-then-Activate Moves, Binding Revocation

- **Status:** Proposed
- **Date:** 2026-08-28 (r2)
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending human review
- **Supersedes:** none
- **Superseded by:** none
- **Related:** **Amends** [ADR 0037](./0037-agent-placement-and-key-custody.md); [ADR 0018](./0018-key-lifecycle-expiry-renewal-revocation.md); [ADR 0021](./0021-dm-origin-machine-attestation.md); [ADR 0027](./0027-active-recipient-group-key-sealing.md); [ADR 0036](./0036-owner-singleton-and-naming-registry.md); [ADR 0038](./0038-home-owner-certified-personal-space.md)

## Context

ADR 0037 names cryptography that cannot run and enforcement that does not exist (Codex gapcheck 2026-08-27, findings 1–7): machines announce only an ML-DSA-65 signing key, so `seal_group_secret_to_recipient` (`src/groups/kem_envelope.rs:140`) has no machine KEM key to seal an export to; the move's implicit machine revocation cannot be issued (`POST /identity/revoke` signs with the agent key, `src/server/routes/identity.rs:1172`), kills every co-resident agent (`src/revocation.rs:47`), and expires after 90 days (`src/revocation.rs:398`); there is no crash protocol; no gate consults `Pinned/Roaming`. The announce-blob path is certificate-specific (`src/announce_blob.rs:98`), and `X0A4` already names the shipped V3.1 self-name envelope (`src/announce_v3.rs:43`).

## Decision Drivers

- Crash at any point is recoverable and never leaves two live signers.
- Moving one agent must not revoke co-resident agents; retired bindings never resurrect.
- Only the owner key authorizes irreversible steps — not the moving agent key, not either machine.
- Every wire change is decodable by today's fleet (topic-versioned, never in-place field growth).

## Considered Options

1. ADR 0037 as written — fails every driver above.
2. Delete-then-import transfer certificates — loses the key on a crash between delete and ack.
3. Commit-then-activate ceremony over a predecessor-linked record chain, carried by versioned machine-announce and revocation-v2 carriers — chosen.

## Decision

1. **Machine KEM enrollment.** Each machine generates an ML-KEM-768 keypair (the shipped `AgentKemKeypair` primitive, `src/groups/kem_envelope.rs:41`) and publishes the public half in a **`MachineAnnouncementV3`** on a new topic `x0x.machine.announce.v3` — topic-versioned exactly as `x0x.machine.announce.v2` versioned v1 (`src/lib.rs:468`); old peers are simply not subscribed and decode nothing. Receivers cache it on `DiscoveredMachine` (`src/lib.rs:1662`). Export seals the serialized agent keypair with the ADR 0027 construction (plaintext widened from `[u8; 32]` to bytes — ML-DSA-65 secrets are 4032 B), AAD-bound to the move authorization.
2. **Acyclic move records, predecessor-linked.** An owner-signed `MoveAuthorization {agent_id, move_epoch, from, to, placement}` (no envelope digest — that would be circular); the source machine signs an `ExportReceipt {auth_hash, envelope_digest}` after sealing. Every record carries `prev` = BLAKE3 of the chain head for that agent; a record is accepted iff signatures verify AND `prev` equals the receiver's head (compare-and-swap). Forks (two records claiming one `prev`) keep the first-valid and drop-and-alert the rest; epochs are monotone by chain construction.
3. **Commit-then-activate ceremony.** `Authorized → Sealed → Imported → Activated → SourceRetired`, with `Abort` legal only pre-activation. Exact durable orderings: source writes intent, **then** quiesces, then seals, then receipts; target quarantines the imported key until it holds `Activated`. Activation is ONE owner-signed `ActivationBundle {prev, auth_hash, binding_revocation, placement_record}` — appended and fsynced to the move log as one record, gossiped as one message; receivers apply it atomically or not at all. The source secure-deletes only after observing the bundle; `Abort` burns the epoch. A daemon-wide `AgentSigningGate` brokers every production signing path (`/agent/sign` at `src/server/routes/identity.rs:905`, DM/ACK, forward headers, gossip contexts) and refuses quiesced or quarantined agents — the single-live-signer invariant holds for cooperating daemons; an offline stolen copy still forges valid agent signatures and is only defeated at gates that carry machine context.
4. **Binding revocation on a v2 carrier.** `RevokedSubject` gains `AgentMachineBinding {agent, machine, move_epoch}` — revokes the pair, not the machine; owner-key issued via the issuer-revocation rule extended (`src/revocation.rs:189`); self-revocation is impossible for a two-id subject. Binding records ride a new topic `x0x.revocation.v2` (`v1` is `src/lib.rs:484`) and a versioned store, because today's v1 wire is one whole-`Vec` batch (`src/lib.rs:2953`, `:7689`) that an unknown variant would poison **entirely** for old peers — v1 keeps publishing Agent/Machine records byte-identical, so the coarse machine-revocation backstop keeps working for them. Bindings are exempt from the 90-day sweep: permanent, grow-only.
5. **Placement ledger + enforcement.** Owner-signed `PlacementRecord {agent_id, placement: Pinned(MachineId)|Roaming, placement_epoch}` — new owner-side state minted from the cert journal roster (`GET /owner/agents`, `src/server/routes/profile.rs:150`); the initial mint designates ≥1 agent `Roaming`, reconciling ADR 0038's ≥1-Roaming Home invariant with the all-Pinned default. Digests ride `MachineAnnouncementV3`; records fetch via a kind-tagged blob protocol v2 (the cert blob path stays v1, `src/announce_blob.rs:54`). Enforcement — binding check via `is_binding_revoked(agent, machine)` and placement-epoch check — at: `gate_peer_outbound` (`src/lib.rs:10497`) and `gate_peer_machine_inbound` (`src/lib.rs:10557`) for streams/lanes; the gossip-DM gate after attestation (`src/dm_inbox.rs:1231`, `:1302`); the direct-QUIC DM gate (`src/lib.rs:10313`); the forward mid-flight re-check (`src/forward.rs:758`); announce ingest/eviction (`src/lib.rs:7952`). `RevocationSet` gains a max-revoked-epoch index so placement epochs are comparable. Pre-0043 peers fail open, documented; capability adverts flag them during a move.

Mechanics: [docs/design/agent-key-move.md](../design/agent-key-move.md).

## Consequences

### Positive
- Every mechanism extends shipped carriers (topic-versioned machine announce, ADR 0027 KEM envelope, revocation gossip, blob fetch); no magic collision with shipped `X0A4`.
- Two live signers are impossible among cooperating daemons; an old binding dies at every upgraded machine-context gate, permanently.
- Per-agent moves stop killing co-resident agents; v1 revocation stays decodable fleet-wide.

### Negative / Trade-offs
- Three new topics/wires during transition (machine v3, revocation v2, blob v2), retired by the same fleet-upgrade rule as V2∥V3.
- Owner key must participate at Authorize and Activate; a crash between them parks the agent — recoverable, not signing.
- Offline forgeries from a stolen copy remain valid signatures; only machine-context paths reject them (cryptographic single-signer needs key rotation, out of scope: `AgentId` is the key hash, ADR 0007).

### Neutral / Operational
- New owner-side append-only move log + placement ledger (persistence pattern of `revocations.bin`, `src/storage.rs:693`); mixed fleets lose per-binding protection until upgraded.

## Validation

- E2E: crash at each durable-ordering point resumes to single-live-signer; after Activate, source traffic drops at all five gates while co-resident agents pass; v1-only peers still receive and enforce Agent/Machine revocations; binding records survive the 91-day sweep; placement mint always yields ≥1 Roaming.
- Unit: chain CAS rejects forks and replays; authorization/receipt acyclicity (receipt from forged digest fails); binding authority matrix (owner yes; agent, machine, third user no); blob-v2 kind framing; epoch index comparisons.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
