# ADR 0036: Owner Singleton and Naming Registry

- **Status:** Accepted (2026-08-27)
- **Date:** 2026-08-27
- **Decision owners:** David Irvine (direction), omp (drafting), Claude (review)
- **Reviewers:** David Irvine (approved 2026-08-27)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [ADR 0007](./0007-three-layer-identity-model.md);
  [ADR 0037](./0037-agent-placement-and-key-custody.md);
  [ADR 0038](./0038-home-owner-certified-personal-space.md);
  PR #419 (V3 announce + cert-blob fetch, v0.40.0)

## Context

ADR 0007 defines the key hierarchy (`user.key` → `AgentCertificate` →
agent/machine keys) but no install-level authority: nothing marks the local
user key as authoritative for this daemon, and the only "my agents" view is
the discovery-derived `GET /users/:user_id/agents` (`src/api/mod.rs:431-435`).
Names are not daemon state: the agent display name lives in browser
localStorage only (`LS.get('display_name')`, `src/gui/x0x-gui.html:1498`),
injected as a query param when a card is generated (`/agent/card?display_name=`,
`src/server/routes/identity.rs:400-402`). No `/profile` route exists — the
string appears in `src/` only as an internal kv-store key prefix
(`src/lib.rs:15246`). Machine names exist only for contacts' machines.
Announcements carry no names, so peers see bare IDs.

## Decision

- An install with an active `user.key` is **owned** by that `UserId`; the
  daemon records `OwnerProfile { user_id, human_name }` created at
  `x0x user-id create` time (first-run wizard in the GUI).
- One owner per install, enforced at `user-id create`: replacing an owner
  key requires explicit `--rotate-owner` and re-issuing all agent
  certificates.
- New daemon-side self-profile endpoint `PUT/GET /profile`, persisted in the
  instance data dir: `{ human_name }` (owner), `{ display_name }` (agent),
  `{ machine_name }` (this machine); surfaced in `/agent`.
- Identity announcements carry the agent self-name — an additive,
  serde-defaulted field on the V3 announce shape (PR #419) — so peers
  render names without importing cards.
- `AgentCard` gains optional `owner_name` alongside `display_name`
  (`src/groups/card.rs:25-27`).
- New `GET /owner/agents`: the authoritative roster of locally-certificated
  agents, derived from issued `AgentCertificate`s + contact store — the
  "my agents" list ADR 0007 implies but never materialized.
- `/agent/card?display_name=` is deprecated in favour of the stored profile.

## Consequences

- **Positive:** human/agent/machine names become first-class, daemon-trusted
  data announced to peers; Home (ADR 0038) and roaming (ADR 0037) get an
  anchor.
- **Negative:** new persisted state plus migration for existing installs;
  the announce wire grows (additive, serde-defaulted, digest-committed).
- **Neutral:** the owner key becomes the install's crown jewel — ADR 0018
  lifecycle (expiry, issuer revocation via `POST /identity/revoke`) applies
  unchanged.

## Validation

- `GET /profile` round-trips across restart; announcements from a named
  install carry the self-name and still verify under the V3 digest gate;
  `GET /owner/agents` matches the set of issued certificates.
