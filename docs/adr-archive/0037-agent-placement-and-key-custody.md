# ADR 0037: Agent Placement and Key Custody

- **Status:** Accepted (2026-08-27)
- **Date:** 2026-08-27
- **Decision owners:** David Irvine (direction), omp (drafting), Claude (review)
- **Reviewers:** David Irvine (approved 2026-08-27)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [ADR 0007](./0007-three-layer-identity-model.md);
  [ADR 0018](./0018-key-lifecycle-expiry-renewal-revocation.md);
  [ADR 0021](./0021-dm-origin-machine-attestation.md);
  [ADR 0027](./0027-active-recipient-group-key-sealing.md);
  [ADR 0036](./0036-owner-singleton-and-naming-registry.md);
  [ADR 0038](./0038-home-owner-certified-personal-space.md)

## Context

ADR 0007 makes `AgentId` portable "when the agent key is moved" — today that
is an undocumented file copy of `agent.key` that leaves two live signers, no
revocation of the source machine, and no placement field anywhere in the
daemon's own agent state. Machine pinning exists only as a contact-side
trust constraint (`POST /contacts/:agent_id/machines/:machine_id/pin`,
`src/api/mod.rs:517-521`). ACP-harness agents (buzz-pi-acp model: one key
per harness process under `~/.saorsa-keys/`) are bound to one machine's
process by construction, but x0x has no vocabulary to say so.

## Decision

- Every agent on the owner roster (ADR 0036 `GET /owner/agents`) carries a
  `placement` field: `Pinned(MachineId)` or `Roaming`. Default `Pinned` to
  this machine.
- Roaming move = **export**: the owner key seals `agent.key` into an
  ML-KEM envelope keyed to the *target machine's* public key, reusing the
  ADR 0027-governed sealing primitive (`seal_group_secret_to_recipient`,
  `src/groups/kem_envelope.rs`) — never a raw file copy. Import on the
  target machine unwraps and re-pins.
- Export **implicitly revokes the source machine**: the move issues the
  existing `POST /identity/revoke` machine-id revocation (ADR 0018), so
  ADR 0021 origin attestations make receivers reject any late send from
  the old machine automatically.
- **Single-live-copy invariant:** roaming moves the key, it does not clone
  it. Two simultaneous live signers are a stated non-goal; multi-device
  signing quorum is deferred.
- ACP-harness agents are always `Pinned` — the harness process is the key
  custodian.

## Consequences

- **Positive:** "agent follows the user across machines" becomes a safe,
  one-command flow; the stolen-source-machine window is closed by
  revocation + attestation rather than operator diligence.
- **Negative:** export/import is new UX; losing both machines loses the
  `AgentId` — recovery stays out of scope (ADR 0007 non-goal).
- **Neutral:** Home's ≥1-roaming-agent requirement (ADR 0038) rides on
  this; export reuses vetted KEM machinery, adding no new cryptography.

## Validation

- After a move: source-machine DMs fail ADR 0021 attestation + EP3
  revocation; the target's first attested DM is accepted; exactly one
  machine ever holds a live copy at a time.
