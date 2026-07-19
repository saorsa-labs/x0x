# ADR 0012: Real TreeKEM as the Default Secure Group Plane

- Status: Accepted — implemented; **single-member private secure groups work end-to-end** (invite → join → Welcome → bidirectional secure → ban/epoch-advance → forward secrecy, verified on testnet). **x0x 0.21.0** (2026-06-03) added owner-side **multi-member roster convergence** (serialized per group by `group_membership_lock`) plus the direct-delivery + bounded pending/replay + catch-up anti-entropy infrastructure. **Resolved (was a 0.21.0 known limitation):** joiner-side `MemberAdded`+`Welcome` delivery landed in the v0.21.x convergence work; multi-member secure participation now works and is covered by `tests/e2e_treekem_membership.py`, which asserts a second member receives and processes its Welcome. Public encrypted presets remain on the GSS plane (see ADR-0010 scope note and the 0.20.2 fix).
- Date: 2026-05-30 (proposed); 2026-06-03 (accepted — shipped in 0.21.0)
- Supersedes: ADR-0010 (GSS Before MLS TreeKEM for v1 Secure Groups) — see "Relationship to ADR-0010".

> Numbering note: a pre-existing collision had TWO `0010-*` files. Resolved
> 2026-05-30 by renumbering the pubsub one to
> [ADR 0013](./0013-priority-aware-pubsub-shed.md); `0010` is now solely the GSS
> ADR this one supersedes.

## Context

ADR-0010 chose a **Group Shared Secret (GSS)** plane for `MlsEncrypted` named
groups because, at the time, no real MLS TreeKEM existed in the stack — a
2026-05-30 source audit confirmed that even `saorsa-mls` ≤0.3.5 was itself
GSS-equivalent (local-random tree-node secrets, only a per-epoch shared secret
on the wire; see saorsa-mls ADR-002). GSS provides cross-daemon encryption and
rekey-on-ban but **no forward secrecy (FS) and no post-compromise security
(PCS)**: compromise of any current member's local state exposes all
current-epoch content, and future rotations do not heal it.

That ceiling is the dominant risk for payloads carrying **personal memory**
(e.g. "the Fae" — networks of personal AI agents sharing memory across
people's devices). FS/PCS is not a nice-to-have for that use case; it is the
point.

**This is now unblocked.** `saorsa-mls 0.3.6` ships real RFC-9420-subset
TreeKEM as `treekem_group::TreeKemGroup` — KEM-keypair-per-node ratchet tree,
UpdatePath/Commit distribution, init→commit→epoch key-schedule chaining,
Welcome carrying the ratchet tree + GroupSecrets, `from_welcome`, and an
encrypt-at-rest snapshot. It is verified (cross-instance wire join +
forward-secrecy-on-leave + adversarial tests pass) and published. The legacy
GSS `MlsGroup` remains in the crate, unchanged, for back-compat.

x0x today has **two** group-crypto surfaces, which is itself a problem:

1. **`/mls/groups`** — wraps the legacy GSS `saorsa_mls::MlsGroup` via
   `src/mls/group.rs`, but is effectively a demo surface: it fabricates MLS
   state (placeholder blake3 tree/transcript hashes), discards the real
   Welcome, and `save_mls_groups` is a no-op ("recreated each session"). Only
   Communitas's `create_mls_group()` (marked *excluded* in its parity matrix)
   touches it.

2. **Named groups** (`src/groups/`) — the real product. `MlsEncrypted` groups
   carry a 32-byte `shared_secret` + monotonic `secret_epoch`, sealed
   per-recipient via ML-KEM-768 (`src/groups/kem_envelope.rs`), with the epoch
   folded into `security_binding` ("gss:epoch=N") inside the signed
   `GroupStateCommit` state hash. This is the GSS plane ADR-0010 describes.

## Decision

**Make real TreeKEM the default, single secure-group plane in x0x.** Concretely:

1. **Secure by default.** `GroupConfidentiality::MlsEncrypted` (already the
   `#[default]`; enum at `src/groups/policy.rs:39`) SHALL, for **newly created**
   groups, resolve to a real `saorsa_mls::TreeKemGroup` (FS + PCS) instead of
   the GSS shared-secret plane. Any app creating a private group via the x0x
   API gets a secure MLS group with no extra opt-in.

2. **Public groups are unchanged.** `GroupConfidentiality::SignedPublic`
   remains integrity-only, readable, and discoverable. "All groups secure"
   means *all confidential groups*; deliberately-public groups are not
   encrypted. (Scope decision: private-only.)

3. **One plane, not three.** The demo `/mls/groups` surface is re-platformed
   onto `TreeKemGroup` and unified with the named-group secure plane so there
   is a single secure-group implementation. The fabricated-hash / no-op-persist
   behavior is removed.

4. **Existing GSS groups are grandfathered, opt-in upgrade.** Groups already
   created on the GSS plane keep working unchanged. A group owner MAY trigger a
   one-time **GSS→TreeKEM upgrade** (a rekey that establishes a TreeKEM group
   from the current roster and retires the shared secret). No automatic,
   forced migration. Both planes coexist during the transition; a group records
   which plane it is on.

5. **Honest crypto labels.** Docstrings/AD that currently call the GSS path
   "real TreeKEM" (e.g. `src/mls/group.rs:1`,`:243`) are corrected: legacy =
   GSS, new default = TreeKEM. No surface claims FS/PCS it does not have.

6. **Snapshots persist at rest with the same protection x0x already gives key
   material.** TreeKEM group snapshots contain private key material.
   **Correction (review finding):** x0x does **not** currently encrypt key
   material at rest — `src/storage.rs` writes keys as plain bincode and relies
   on `write_private_file` (atomic write + Unix `0600`); there is no
   sealed-storage / KEK path to "reuse". `agent_kem.key` (the agent's ML-KEM
   secret) is stored exactly this way (`load_or_generate_api_token` in `src/server/auth.rs`, mode 0600).
   Therefore TreeKEM snapshots SHALL be persisted with the **same `0600`
   plain-bincode model** as existing keys — they are no more sensitive than
   `machine.key`/`agent.key`/`agent_kem.key` already on disk, so this is
   consistent, not a regression. This still replaces the no-op `save_mls_groups`
   (which persists nothing today). Introducing real at-rest encryption
   (passphrase/OS-keychain KEK) is a **separate, whole-identity-dir** decision
   tracked as open question #4 below — it should cover all key material at once,
   not be bolted onto group snapshots alone.

### Relationship to ADR-0010

ADR-0010 is **superseded** for the forward path: its core constraint ("no real
TreeKEM exists, ship GSS, never call it TreeKEM") no longer holds. ADR-0010
remains the accurate description of the **legacy plane** that grandfathered
groups still run on, and its migration-trigger section is the basis for the
opt-in upgrade defined here. ADR-0010's caution — *never present a plane as
stronger than it is* — is retained and extended: GSS groups must keep being
labelled GSS until upgraded.

## Security properties

New (TreeKEM) `MlsEncrypted` groups provide, via saorsa-mls 0.3.6:
- forward secrecy (init-secret chaining across epochs);
- post-compromise security (epoch derived from a fresh commit_secret an
  attacker does not hold, distributed via UpdatePath);
- cross-daemon join via signed Welcome + `from_welcome`;
- removed members cannot derive future-epoch secrets.

Unchanged limits to state honestly:
- no clawback of content a member already received before removal;
- PQ ciphersuite IDs are saorsa-mls "SPEC-2" (`0x0B**`), which diverge from
  `draft-ietf-mls-pq-ciphersuites` codepoints (documented in saorsa-mls
  ADR-002); no IETF wire interop in this release;
- out of scope this release (saorsa-mls 0.3.6 limits): external commits/joins,
  PSK, resumption.

## Consequences

### Positive
- "The Fae" and any app's new private groups get FS/PCS by default.
- Collapses the confusing surfaces (faked-state `/mls/groups` + GSS named
  groups) into one secure plane.
- `/mls/groups` becomes genuinely secure + persistent (kills the no-op).

### Negative / cost
- Security-critical change to the live group runtime; must be staged + reviewed,
  not shipped in one commit.
- Two planes coexist until all groups upgrade → added test surface and a
  per-group "which plane" branch in the secure-content paths.
- The GSS→TreeKEM upgrade is a real protocol step (re-establish a TreeKEM group
  from the GSS roster, deliver Welcomes, retire the shared secret) and needs its
  own tests + a roster-authority check so only the owner can trigger it.
- Snapshot-at-rest wiring is required before `/mls/groups` can be persistent.

## Staged implementation plan (each phase: tests + review gate, no panics in prod)

- **Phase 0 — dep + honesty (low risk).** Bump `saorsa-mls = "0.3.6"` (done;
  x0x builds clean). Correct the over-claiming docstrings. No behavior change.
- **Phase 1 — TreeKEM wrapper.** New `src/mls/treekem.rs` (or re-platform
  `src/mls/group.rs`) wrapping `saorsa_mls::TreeKemGroup` with the existing
  `AgentId`↔`MemberId` bridge; expose create / add_member→Welcome /
  from_welcome / process_commit / encrypt / decrypt / snapshot. Unit + a
  cross-instance wire round-trip test mirroring saorsa-mls's own.
- **Phase 2 — new groups are TreeKEM (prerequisite: KeyPackage in AgentCard).**
  Route `MlsEncrypted` group *creation* to the TreeKEM wrapper; tag the group's
  plane in `GroupInfo`. New private groups get FS/PCS. GSS groups still load +
  run.
  - **Prerequisite (review finding):** TreeKEM `add_member`/`from_welcome` need
    the joiner's ML-KEM **public** key as their KeyPackage. x0x already mints
    and persists a per-agent ML-KEM keypair (`AgentKemKeypair`,
    `src/groups/kem_envelope.rs`, loaded at x0xd startup) and already shares the
    public half over **DM capabilities** (`DmCapabilities::with_kem_public_key`,
    `src/lib.rs:5578`). But `AgentCard` does **not** carry it
    (`src/groups/card.rs:92`: "AgentCard is created without knowing the KEM
    pubkey"). Phase 2 must surface `AgentKemKeypair.public_bytes` in `AgentCard`
    (or otherwise feed the existing DM-capability KEM key into the invite/join
    path) so the inviter has the joiner's KeyPackage. The primitive exists; only
    this plumbing is missing.
- **Phase 3 — secure-content + membership on TreeKEM.** Make the named-group
  secure encrypt/decrypt and add/remove/ban paths dispatch on the group's
  plane: TreeKEM groups use Commit/UpdatePath + AEAD-from-epoch-secret; GSS
  groups keep the shared-secret path. Bind epoch into `security_binding` for
  both. **The plane-branch call sites that must be handled (review finding —
  this list is the Phase-3 checklist):**
  - `src/groups/mod.rs`: `derive_message_key`, `rotate_shared_secret`,
    `seal_commit`, `seal_withdrawal`, `shared_secret`/`secret_epoch` fields,
    `security_binding` derivation.
  - `src/server/routes/named_groups.rs` (moved from `src/bin/x0xd.rs` in the
    routes extraction): the `SecureShareDelivered` gossip-event handler
    (~494-546) that KEM-opens and stores the GSS shared secret + sets
    `secret_epoch`/`security_binding` — TreeKEM has **no** shared secret to
    deliver, so this needs a parallel Commit-delivery path, not a branch inside
    the same handler; `secure_share_aad` and the admin-authorized secret-share
    send path; the `/mls/groups/:id/encrypt`/`decrypt` handlers and
    the named-group secure-content read/write endpoints.
  - Membership: add/remove/ban currently produce a GSS `rotate_shared_secret` +
    per-recipient reseal; the TreeKEM equivalent is a `Commit` (+ `UpdatePath`)
    distributed to all members and a `Welcome` to joiners.
- **Phase 3.5 — Commit/Welcome transport (review finding: do not skip).**
  Define how TreeKEM `Commit`s reach **all** members and `Welcome`s reach
  joiners, and how a member who **misses** a Commit recovers. This is a genuine
  gap vs. GSS: the current `SecureShareDelivered` path is **latest-epoch-wins
  and order-insensitive** (`named_groups.rs` drops any envelope with
  `secret_epoch < info.secret_epoch`), which is safe for a flat shared secret
  but **wrong for TreeKEM**, where epoch N's Commit must be applied before
  N+1's. Decide: per-group ordered Commit delivery (sequence numbers +
  gap detection), and a recovery path (re-request missed Commit, or
  snapshot/`Welcome`-style resync) when a member is behind. Mis-handling this
  reintroduces the kind of drop/stall class that bit the gossip layer in
  X0X-0074. Must be settled before Phase 3 lands membership changes.
- **Phase 4 — persistence at rest (`0600`, matching existing keys).** Replace
  the no-op `save_mls_groups` with persisted TreeKEM snapshots written via the
  same `write_private_file` (`0600`) model x0x already uses for `machine.key` /
  `agent.key` / `agent_kem.key` (see decision #6 — there is no sealed-storage
  path to reuse today). Restore on startup. `/mls/groups` becomes persistent +
  cross-daemon. (Whole-identity-dir at-rest encryption is open question #4, out
  of scope here.)
- **Phase 5 — opt-in GSS→TreeKEM upgrade.** Owner-authorized endpoint that
  re-establishes a TreeKEM group from the current GSS roster, distributes
  Welcomes, flips the plane tag, retires the shared secret. Migration tests
  (incl. a member who misses the upgrade).
- **Phase 6 — adversarial review + release.** Full security review of the x0x
  integration (not just the crate), then version bump + release. Update
  api-reference, trust-and-connectivity docs, and Communitas notes.

## Acceptance criteria

- A newly created `MlsEncrypted` group is a `TreeKemGroup`; two daemons join
  via Welcome over the wire and exchange messages (cross-instance test).
- A removed member provably cannot read the next epoch (FS/PCS regression).
- Existing GSS groups still load, run, and can be upgraded by their owner;
  a non-owner cannot trigger upgrade.
- `SignedPublic` groups are unaffected and still publicly readable.
- TreeKEM group state survives daemon restart, persisted at `0600` (same
  protection as existing key material; see decision #6 + open question #4).
- No production code path uses `unwrap`/`expect`/`panic`; fmt + clippy
  `-D warnings` + full nextest green.
- No docstring/API claims FS/PCS for a GSS group.

## Open questions

1. **Group identity continuity on upgrade.** Does a GSS→TreeKEM upgrade keep
   the same stable `group_id`/`genesis` (preferred, so discovery + history
   survive) with a plane change recorded in the state-commit chain, or mint a
   new group? Lean: keep `group_id`, record the upgrade as a signed commit.
2. **Ciphersuite registry.** Track saorsa-mls's SPEC-2-vs-IETF-draft decision;
   revisit if/when interop with non-saorsa MLS is required.
3. **Roster source for `from_welcome` cross-daemon join.** *Resolved by review:*
   x0x already has the per-agent ML-KEM keypair (`AgentKemKeypair`) and shares
   its public half over DM capabilities; it is simply not in `AgentCard` yet.
   Promoted from open question to a **Phase 2 prerequisite** (see Phase 2).
4. **At-rest encryption of the identity dir.** x0x stores all key material
   (`machine.key`, `agent.key`, `agent_kem.key`, and — after Phase 4 — TreeKEM
   snapshots) as plain bincode at `0600`, with no encryption at rest (review
   finding; `src/storage.rs`). Whether to add a passphrase/OS-keychain KEK is a
   real decision, but it must cover the **whole identity dir** at once, not just
   group snapshots. Out of scope for this ADR; tracked here so the "snapshots
   are sealed" expectation is not silently assumed.
