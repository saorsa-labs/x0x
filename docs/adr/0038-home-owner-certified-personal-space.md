# ADR 0038: Home — an Owner-Certified Personal Space

- **Status:** Accepted (2026-08-27)
- **Date:** 2026-08-27
- **Decision owners:** David Irvine (direction), omp (drafting), Claude (review)
- **Reviewers:** David Irvine (approved 2026-08-27)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [ADR 0007](./0007-three-layer-identity-model.md);
  [ADR 0018](./0018-key-lifecycle-expiry-renewal-revocation.md);
  [ADR 0034](./0034-leaf-participation-default.md) (Leaf nodes still serve
  the blob-fetch topic, so cert availability survives the Leaf default);
  [ADR 0036](./0036-owner-singleton-and-naming-registry.md);
  [ADR 0037](./0037-agent-placement-and-key-custody.md);
  PR #419 (V3 announce cert-blob fetch, v0.40.0; `src/announce_blob.rs`)

## Context

Group admission today is `InviteOnly` (default) / `RequestAccess` /
`OpenJoin` (`src/groups/policy.rs:26-34`): any admin can invite any agent,
so "only my human and my agents, forever" is unenforceable — a leaked invite
or compromised admin admits outsiders (content stays MLS-protected;
membership does not). The GUI `home` view is a dashboard, not a space, and
the human types *as* the daemon's agent identity — no human message-sender
exists. Certificates are now mesh-distributable: V3 announces carry a cert
digest and peers fetch the `(user_id, AgentCertificate)` blob on demand
(PR #419, v0.40.0), so an owner-signed cert is verifiable by any peer
without side channels.

## Decision

- New `GroupAdmission::OwnerCertified(UserId)`: a joiner is admitted only
  if it presents a valid, unexpired `AgentCertificate` chaining to the
  group's owner `UserId`.
- Verification runs at invite-accept **and is re-verified at every
  state-commit seal**, so a later-stolen invite or compromised member
  cannot resurrect uncertified membership.
- Every install with an owner auto-creates one **Home** space at first run:
  `Hidden + OwnerCertified + MlsEncrypted + MembersOnly/MembersOnly`;
  renamable via the existing `PUT /groups/:id/display-name`
  (`src/api/mod.rs:726-730`). Membership = the owner's agents only.
- Home always contains ≥1 `Roaming` agent (ADR 0037), so it follows the
  user across machines.
- The owner participates through a designated **primary agent** whose
  certificate binds it to the `UserId`; the GUI renders that agent's panel
  with a "speaking as `<human_name>` (owner)" chip sourced from ADR 0036
  profiles. Group messages stay agent-signed — no new wire signer.
- Admin role is inert for Home admission: enforcement is cryptographic,
  not UI-only.
- Cert distribution is the announce V3 blob-fetch path (PR #419) — verifiers
  resolve certs from the mesh; no side channel.

## Consequences

- **Positive:** "no other human can ever join" becomes a predicate verified
  on every commit; TreeKEM/GSS rekey on membership change evicts stale
  keyholders.
- **Negative:** cert expiry/rotation must be handled or Home locks itself
  out — mitigate with owner-key re-certify on start (ADR 0018 lifecycle).
- **Neutral:** cross-machine Home *history* replication is a separate
  future ADR; ADR 0023's local-only stance is unchanged here.

## Validation

- An uncertified agent holding a valid invite is rejected at accept and at
  the next seal; a revoked cert (ADR 0018) fails re-verification and
  triggers eviction + rekey; a fresh install with an owner provisions a
  renamable Home containing a roaming agent.
