# ADR-0012 mechanics — TreeKEM default secure groups

> Extracted 2026-08-29 from the immutable [ADR 0012](../adr/0012-treekem-default-secure-groups.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the staged implementation plan and review-finding call-site inventory relocated verbatim
> so this file is their maintained home — future updates
> belong here, not in the ADR.

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
  - `src/bin/x0xd.rs`: the `SecureShareDelivered` gossip-event handler
    (~7300-7382) that KEM-opens and stores the GSS shared secret + sets
    `secret_epoch`/`security_binding` — TreeKEM has **no** shared secret to
    deliver, so this needs a parallel Commit-delivery path, not a branch inside
    the same handler; `secure_share_aad` and the admin-authorized secret-share
    send path (~5601-5690); the `/mls/groups/:id/encrypt`/`decrypt` handlers and
    the named-group secure-content read/write endpoints.
  - Membership: add/remove/ban currently produce a GSS `rotate_shared_secret` +
    per-recipient reseal; the TreeKEM equivalent is a `Commit` (+ `UpdatePath`)
    distributed to all members and a `Welcome` to joiners.
- **Phase 3.5 — Commit/Welcome transport (review finding: do not skip).**
  Define how TreeKEM `Commit`s reach **all** members and `Welcome`s reach
  joiners, and how a member who **misses** a Commit recovers. This is a genuine
  gap vs. GSS: the current `SecureShareDelivered` path is **latest-epoch-wins
  and order-insensitive** (x0xd.rs ~7328 drops any envelope with
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
