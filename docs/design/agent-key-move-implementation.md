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

## Review round 2 fixes (b2-0037-r2)

All findings from the codex review (3 Critical, 5 High) addressed:

- **C1 (import ceremony):** `move_import` now establishes participant
  state BEFORE storing the secret — the receipt (and any operator-carried
  auth/export records) chain first, failures propagate (no key stored on
  any error path), and the REST response returns the machine-countersigned
  receipt variant + `receipt_chained` for operator carriage to the owner.
  The empty-log signing-gate exception is scoped to the daemon's OWN
  agent: a foreign agent with a key and no log NEVER passes (possession
  without a custodian fold is quarantine). `move_abort` discards a
  locally-held imported key of the aborted move (remote targets: the
  route response instructs the operator to run the abort there).
- **C2 (daemon-wide signing gate):** the gate now covers the raw-key
  paths — `send_direct_with_config_inner` (the single gossip/relay/
  raw-QUIC DM egress funnel; every envelope below signs with the agent
  key) and the `ForwardV2` attestation (refused → documented V1
  fallback, which carries no agent signature).
- **C3 (durability):** `persist_move_state` is fallible and every
  ceremony step propagates (append is idempotent on retry); activation
  persists BEFORE publishing. Startup distinguishes ABSENT `moves.bin`
  (normal pre-0043, fail-open stays) from PRESENT-but-corrupt (latched
  `move_state_load_failed` → signing gate fail-closed for logless
  agents). The `move_protocol: 1` advert no longer claims blob-v2.
- **H4 (retirement):** deletion runs BEFORE the receipt chains and
  deletion failure returns an error (the operator is never told a
  source copy is dead while it remains on disk).
- **H5 (DM enforcement):** outbound DM egress evaluates B+P for the
  resolved recipient pairing before transmitting; inbound machine gate
  treats pairing denials as PER-AGENT exclusions (dead pairings drop
  from the surfaced list; co-resident agents flow; deny only when no
  live pairing survives). Identity-level gates (#192) still deny the
  machine.
- **H6 (session-token oracle):** the binding form of `/identity/revoke`
  requires the durable owner; `revoke_binding` bounds `move_epoch` by
  the derived placement epoch (or highest retired epoch) — `u64::MAX`
  can no longer stale-date every placement.
- **H7 (invariant ordering + abort scoping):** the ≥1-Roaming check runs
  BEFORE the bundle appends (a refusal leaves the move abortable at its
  current head); `move_abort` scopes "already activated" to THE
  REQUESTED epoch (an older committed bundle never blocks a later
  move's rollback) and rejects epochs the log has moved past.
- **H8 (standalone placement authority + equal-epoch forks):**
  `placements_from_bytes` requires the record's owner key to match a
  known issuance-journal certificate (unmatched records drop
  fail-closed); `cache_placement` never overwrites an equal-epoch
  different-digest record (first-valid wins); `ingest_bundle` never
  replaces an equal-epoch bundle (owner-fork challenger warns, keeps
  stored); tombstones still union in every order.

## Review round 4 — scope decision (b2-0037-r4)

**The roaming-move ceremony is experimental in v1 and OFF by default**
(`[key_move] ceremony_enabled = false`). With the flag off:

- every `/agent/move*` endpoint answers `501` — no `MoveAuthorization`
  can ever be chained, so **no agent ever enters MidMove, quiesced, or
  quarantined**; the ceremony-durability and universal-signing-gate
  holes from rounds 2–3 are UNREACHABLE in the shipped posture;
- every agent stays Pinned to its mint machine. (The local agent is
  minted `Roaming` for the ADR-0038 ≥1-Roaming Home invariant — without
  the ceremony that designation is inert: a roamer's per-machine
  authorization is exactly the derived tombstone set, and B is the only
  check that ever fires.)

**Shipped and always-on:** machine ML-KEM enrollment (V3 announce),
owner-signed `PlacementRecord`s + the Pinned/Roaming placement field +
lazy mint, the binding-revocation subject with the v1/v2 carrier split
(durable-owner-gated, epoch-bounded — round-2 H6), and the B/P
ENFORCEMENT gates at every receive path plus the outbound DM egress.

**Round-4 fixes shipped regardless of the gate:**

- **H5** — outbound B/P now evaluates EVERY recipient-machine
  resolution: the discovery cache (first pass at the DM egress funnel
  head), the capability-advert binding (`cap_machine`, before the gossip
  path uses it), and the raw-QUIC/DM-registry resolution (after
  machine resolution, before the dial). A DM cannot reach a retired
  old-source binding through any of them.
- **H8** — `cache_placement` requires the caller-supplied authoritative
  owner key to match (`expected_owner`): the mint passes its own key,
  bundle ingest passes the coherence-verified bundle owner, disk load
  passes the certificate issuer. A self-signed victim placement cannot
  enter the view through ANY path — the API is hardened before blob-v2
  could wire it remotely.

**Follow-up (tracked as a GitHub issue):** the full commit-then-activate
flow + universal signing-gate coverage land behind the flag in a
follow-up — keyless-target participant-log chaining + owner
receipt-ingestion endpoint, abort delivery to the target with key
cleanup, a universal signing gate across DM-ACK envelopes and task-list
claim signing, transactional single-file move-state durability with a
missing-log poison latch (never-moved vs log-lost), idempotent
activation retry after a persist failure, retire own-key deletion, and
the blob-v2 placement fetch-on-miss transport.

Follow-up tracking: saorsa-labs/x0x#443.

## Review round 5 (b2-0037-r5)

- **Rebased onto `origin/main` (`1a09fd8`)** — the branch no longer
  carries the pre-#433 loopback-substitution probe; `restart.rs` keeps
  main's exact-address bind probe verbatim (no diff vs main).
- **H5 closed:** the raw-QUIC path re-runs B/P against the FINAL
  recipient machine immediately before transmission — after EVERY
  reassignment site (initial registry/cache resolution, send-readiness
  repair, discovery redial). A retired or pinned-elsewhere machine
  introduced by any repair/redial is refused at the transmit seam.
- **H8 closed — authority is MANDATORY at the cache boundary:**
  `cache_placement` now takes a [`PlacementAuthority`] constructible only
  from a verified certificate issuer or an already-verified structure's
  owner (a coherence-checked bundle); the `None` bypass no longer exists
  at the type level. `combined_from_bytes` takes the certificate map and
  drops standalone records without a cert-issuer match fail-closed;
  `placements_from_bytes` likewise.
- **Ceremony globally unreachable:** the gate is mirrored on the agent
  (`AgentBuilder::with_move_ceremony`, default `false`, wired from
  `[key_move] ceremony_enabled` in `serve`) — `move_authorize` /
  `move_export` / `move_import` / `move_activate` / `move_abort` /
  `move_retire` each return a typed disabled error before any mutation.
  Startup LOADING of existing move state is unaffected (loading ≠
  executing).
