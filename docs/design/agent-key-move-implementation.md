# ADR-0043 Implementation Status (b2-0037, 2026-08-30)

Companion to [agent-key-move.md](./agent-key-move.md). Records what
shipped in `feat/adr0037-placement` (branch of the b2-0037 worktree),
the deliberate deltas, and the one recorded gap. ADR bodies are
immutable (governance CI); this file carries implementation notes.

## Shipped (branch `feat/adr0037-placement`)

| § | Mechanism | Where |
|---|---|---|
| 2.1 | `MachineAnnouncementV3` (enrollment ML-KEM-768 key + placement digests + `move_protocol: 1` advert) on `x0x.machine.announce.v3`, dual machine-signed, published every heartbeat, verified + cached on receive; `DiscoveredMachine` gains `machine_kem_public_key`/`placement_digests` (merge never erases a known KEM key) | `src/lib.rs` (topics, struct, publish in `HeartbeatContext::announce`, listener `MachineV3` arm) |
| 2.2 | Byte-wise seal/open siblings over the ADR-0027 construction (4032 B ML-DSA-65 secrets) | `src/groups/kem_envelope.rs` |
| 3 | `MoveRecord` chain (mint/auth/export/import/activation/retire/abort), `ChainedRecord` owner-signature covering `prefix ‖ prev ‖ tag ‖ owner-pubkey ‖ variant`, participant CAS verification, **total fold** (`custodian`/`retired_bindings`/`placement`/`phase`), mesh rule (whole-record signature + §7.5 coherence + epoch monotonicity + unconditional cumulative-tombstone union) | `src/key_move.rs` |
| 4 | Export envelope: ML-KEM seal to the target machine's enrolled key, AAD = `MoveAuthorization` canonical bytes; `envelope_digest` committed only in the `ExportReceipt` | `src/key_move.rs` (`ExportEnvelope`) |
| 5 | Ceremony endpoints + persistence (`moves.bin` X0XM, `move-bundles.bin` X0MB, `placement-blobs.bin` X0PB, `revocations-v2.bin` X0R2 — all re-verified on load) | `Agent::move_*` in `src/lib.rs`; `src/server/routes/key_move.rs` |
| 7 | `RevokedSubject::AgentMachineBinding` (0x03, fixed-width canonical bytes, owner-key-only authority via the embedded/retained certificate, TTL-exempt, self-revocation structurally impossible); v1 wire/file filter to legacy subjects; v2 carrier topic `x0x.revocation.v2` (heartbeat on-change + fallback) | `src/revocation.rs`, `src/lib.rs` |
| 7.5 | `ActivationBundle` self-contained (embedded authorization + cumulative `retired_bindings` + placement record + certificate); published on `x0x.move.activation.v1` on activation + republished on heartbeat; ingested under the mesh rule | `src/key_move.rs`, `src/lib.rs` |
| 8 | Placement mint from the cert-journal roster (lazy at first `GET /owner/placement` or first authorize); local-agent Roaming exception; all-Pinned mint refused; activation refuses zero-Roaming outcomes | `Agent::move_mint_placements`, `Agent::move_activate` |
| 9 | B+P at: outbound stream gate, inbound stream/datagram gate (per pairing), direct-QUIC DM listener, gossip DM inbox (attested machine), forward mid-flight re-check (per pairing), announce ingest (P drop); `AgentSigningGate` (`may_sign`) on `POST /agent/sign` (fail-open for log-less agents) | `src/lib.rs`, `src/dm_inbox.rs`, `src/forward.rs`, `src/server/routes/identity.rs` |
| 11 | REST: `POST /agent/move`, `/agent/move/export`, `/agent/move/import`, `/agent/move/activate`, `/agent/move/abort`, `/agent/move/retire`, `GET /agent/moves`, `GET /owner/placement`, `GET /owner/agents/:id/placement`; `POST /identity/revoke` both-fields binding form; `GET /owner/agents` placement enrichment. CLI: `x0x move …`, `x0x owner placement`, `x0x owner agents placement`. Manifest + api_coverage + parity_cli updated | `src/server/routes/key_move.rs`, `src/api/mod.rs`, `src/bin/x0x.rs`, `src/cli/commands/identity.rs` |

## Recorded gap

- **Blob-v2 fetch-on-miss (§8.2 transport half) is NOT shipped.** The
  `ANNOUNCE_BLOB_V2_TOPIC` constant exists, but no request/responder
  serves Placement/Bundle kinds yet. Consequence: placement records
  reach peers only via (a) activation bundles on the activation topic
  (post-move agents — full P enforcement) and (b) the owner machine's
  local mint. P enforcement for a never-moved, non-owner-peer agent
  fails open until its first move — exactly the §9.3 absent-evidence
  rule, so no security claim regresses; the *distribution* upgrade
  (mint records fetchable fleet-wide) is follow-up work. The v1 cert
  blob path is untouched.

## Deliberate deltas (documented in code)

- `RetireReceipt`/deletion: imported foreign keys are securely deleted at
  retire; the daemon's OWN `agent.key` is NOT deleted (it is the install's
  bootstrap identity — `holds_key` stays true, `may_sign` is already false
  because the fold's custodian moved). Design §5.2 "secure deletion of the
  source's key material" is honored for foreign agent keys; own-key
  deletion is an explicit operator file action.
- `AgentSigningGate` (§6) is wired at the `/agent/sign` route and exposed
  as `Agent::signing_gate_allows` for adopters; the remaining shipped
  signing paths (DM envelopes, forward attestations, gossip contexts)
  still hold the raw key (design lists them). Their enforcement against a
  moved-away source is receiver-side (B/P gates), which is the shipped
  security property; source-side refusal for those paths is follow-up.
- The mint pins roster agents to their last-seen machine (discovery
  fallback: this machine), per §8.2's default; unseen agents therefore
  pin to the minting machine until moved.

## Verification

- `cargo fmt --all` clean; `cargo clippy --all-features --all-targets --
  -D warnings` clean; `cargo check --workspace --all-targets` clean;
  `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps` clean.
- `cargo nextest run --all-features`: green except the pre-existing
  environmental `upgrade::restart::tests::addr_is_free_probes_loopback_
  for_unspecified_bind` (fails on a clean tree of `origin/main` in this
  environment the same way).
- New unit coverage: fold totality across every legal log shape, ≤1 live
  signer at every prefix, participant CAS (forks/replays/illegal
  successors/bad epochs), mesh-rule monotonicity + order-independent
  tombstone union, per-clause coherence drops, envelope AAD binding,
  B+P matrix (equal-epoch enforces, stale ignored, roaming never pins),
  persistence round-trips, binding authority matrix + carrier split +
  TTL permanence, route wiring (owner-gating, lazy mint, typed
  refusals).
