# ADR 0043: Agent Key-Move Protocol — Machine KEM Keys, Commit-then-Activate Moves, Binding Revocation

- **Status:** Proposed
- **Date:** 2026-08-28
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending human review
- **Supersedes:** none
- **Superseded by:** none
- **Related:** **Amends** [ADR 0037](./0037-agent-placement-and-key-custody.md); [ADR 0018](./0018-key-lifecycle-expiry-renewal-revocation.md); [ADR 0021](./0021-dm-origin-machine-attestation.md); [ADR 0027](./0027-active-recipient-group-key-sealing.md); [ADR 0038](./0038-home-owner-certified-personal-space.md)

## Context

ADR 0037 names cryptography that cannot run and enforcement that does not exist (Codex gapcheck 2026-08-27, findings 1–7): machines announce only an ML-DSA-65 signing key (`src/announce_v3.rs:59-62`), so `seal_group_secret_to_recipient` (`src/groups/kem_envelope.rs:140`) has no machine KEM key to seal an export to; the move's implicit machine revocation cannot be issued (`POST /identity/revoke` signs with the agent key, `src/server/routes/identity.rs:1172`), kills every co-resident agent (`src/revocation.rs:47-52`), and expires after 90 days (`src/revocation.rs:398`); there is no crash protocol, a retained key copy re-signs under a fresh valid machine attestation, and no gate consults `Pinned/Roaming`.

## Decision Drivers

- Crash at any point is recoverable and never leaves two live signers.
- Moving one agent must not revoke co-resident agents; retired bindings never resurrect.
- Only the owner key authorizes irreversible steps — not the moving agent key, not either machine.
- Today's fleet keeps decoding the announce wire (V3 is positional bincode rejecting trailing bytes, `src/announce_v3.rs:288-292`).

## Considered Options

1. ADR 0037 as written — fails every driver above.
2. Delete-then-import transfer certificates — loses the key on a crash between delete and acknowledged import.
3. Commit-then-activate ceremony over a new binding-revocation subject, carried by an additive X0A4 announce — chosen.

## Decision

1. **Machine KEM enrollment.** Each machine generates an ML-KEM-768 keypair (the shipped `AgentKemKeypair` primitive, `src/groups/kem_envelope.rs:35-48`) and publishes the public half in a new **X0A4** announcement — a machine-signed V3 superset published alongside V3, exactly the V2→V3 pattern (`src/announce_v3.rs:18-21`) — cached on `DiscoveredMachine` (`src/lib.rs:1662`). Export seals the serialized agent keypair with the ADR 0027 construction (plaintext widened from `[u8; 32]` to bytes — ML-DSA-65 secrets are 4032 B, `src/identity.rs:294`), AAD-bound to the move record.
2. **Commit-then-activate move.** Owner-signed move records keyed by `(agent_id, move_epoch)`: `Exported → Imported → Activated → SourceRetired`. The source **quiesces** (stops signing) at Export, keeping bytes only for rollback; the target imports into **quarantine** and cannot sign until it holds the owner-signed `Activated` record, which atomically issues the binding revocation and the successor placement record (epoch = move epoch); the source securely deletes only after observing `Activated`. The owner's append-only move log is the state store; steps are idempotent per epoch, so crash re-entry resumes. Activate is the sole irreversible point and validates the ADR 0038 Home ≥1-roaming invariant first.
3. **Binding revocation.** `RevokedSubject` gains `AgentMachineBinding(AgentId, MachineId)` — revokes the pair, not the machine. Only the owner key may issue it, via the issuer-revocation rule extended to binding subjects (`src/revocation.rs:189-205`); self-revocation is impossible for a two-id subject by construction. Binding records are exempt from the 90-day sweep (`src/lib.rs:2761`): permanent, grow-only.
4. **Placement enforcement.** An owner-signed `PlacementRecord {agent_id, placement, placement_epoch}` rides the announce blob path (digest on X0A4; verify-before-cache, `src/announce_blob.rs:506`). The DM gate enforces after attestation resolves `(agent, machine)` (`src/dm_inbox.rs:1231`): a revoked binding hard-drops beside the revoked-sender check (`src/dm_inbox.rs:1301`), and a cached placement record with surviving epoch but mismatched pinned machine drops. The stream/connect gate checks the same pair (`src/streams.rs:466-473`); announce verify stays stateless — the cache-merge/eviction step drops bad bindings (`src/lib.rs:7721-7733`). Pre-0043 peers cannot decode the new variant: they fail open (documented), are visible via capability adverts, and are flagged to the operator during a move.

Mechanics: [docs/design/agent-key-move.md](../design/agent-key-move.md).

## Consequences

### Positive

- Every mechanism extends shipped code (X0A3 transition, ADR 0027 KEM envelope, revocation gossip, blob fetch) — no new cryptography.
- Two live signers are impossible on the honest path and useless off it.
- Per-agent moves stop killing co-resident agents; move revocations never expire.

### Negative / Trade-offs

- X0A4 duplicates the announce wire during transition, bounded by the V2∥V3 upgrade window.
- The owner key must participate at Export and Activate; a crash between them parks the agent (source quiesced, target quarantined) — recoverable, not signing.

### Neutral / Operational

- New owner-side append-only move log (persistence pattern of `revocations.bin`, `src/storage.rs:693`); mixed fleets lose per-binding protection until upgraded.

## Validation

- E2E: crash at each state resumes idempotently; after Activate, source DMs/streams with valid attestations drop at upgraded peers while co-resident agents continue; binding records survive the 91-day sweep; Home never reaches zero roaming agents.
- Unit: binding authority (owner yes; agent, machine, third user no); X0A4 verify including the KEM-key binding; envelope AAD substitution and cross-move replay fail; stale placement epochs reject.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
