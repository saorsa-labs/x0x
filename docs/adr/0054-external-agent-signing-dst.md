# ADR 0054: External Agent Signing Uses a Canonical Domain-Separated Context, Never Raw Payloads

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0017 (signed AgentCard, adjacent but distinct); `docs/design/draft-saorsa-x0x-agent-transport-00.md` §4.6. Backfill record for shipped behavior.

## Context

`POST /agent/sign` and `POST /agent/verify` (`src/server/mod.rs:1649-1650`)
let external systems obtain agent signatures without key exposure, with no
deciding ADR. The pure policy/encoding boundary lives in
`src/api/agent_signing.rs`: external payloads are namespaced by reserved
byte `0xF0` (`NAMESPACE_TAG`, `src/api/agent_signing.rs:69`) and signed
under magic `x0x.external-agent-sign.v1`
(`src/api/agent_signing.rs:78`), advertised as scheme
`x0x.agent-sign.v2.ml-dsa-65` (`src/api/agent_signing.rs:86`).

## Decision Drivers

- An agent's ML-DSA key must never leave the daemon, yet external
  protocols need agent signatures.
- A signing oracle must never sign attacker-chosen raw bytes that could
  collide with internal domains (envelopes, attestations, state-commits).
- Verification must be possible offline by third parties.

## Considered Options

1. Export the secret key to callers.
2. Sign raw payload bytes on request.
3. Mandatory validated context + canonical DST buffer, daemon-held key (chosen).

## Decision

1. Sign and verify operate only on canonical bytes `0xF0 ‖ magic ‖ u32be(context_len) ‖ context ‖ payload`
   (`assemble_buffer`, `src/api/agent_signing.rs:168-180`); there is no
   raw-payload signing path (`src/server/routes/identity.rs:900-903`).
2. `context` must match `^[a-z0-9._-]{1,64}$`, be nonempty, and pass an
   internal-domain denylist (`validate_context`,
   `src/api/agent_signing.rs:139-157`); payload is capped at 64 KiB
   (`MAX_PAYLOAD_BYTES`, `src/api/agent_signing.rs:90`).
3. The daemon-held agent keypair signs with ML-DSA-65
   (`src/server/routes/identity.rs:870-910`); the route returns detached
   wire-ready material, never the key. Verify is stateless — no `State`
   extractor, no key access, no identity state
   (`src/server/routes/identity.rs:949-951`), reconstructing canonical
   bytes from caller-supplied public material.
4. Both routes are bearer-token-protected local API endpoints
   (`src/server/routes/identity.rs:829-831`; `src/server/auth.rs:407-408`).

## Consequences

### Positive

- The 0xF0 namespace makes cross-protocol signature confusion
  unconstructible; verification needs only public data.

### Negative / Trade-offs

- Callers cannot get a "bare" signature over arbitrary bytes — by design;
  the 64 KiB bound excludes large-document signing.

### Neutral / Operational

- The transport draft §4.6 specifies this surface; its `src/server/mod.rs`
  line reference is stale (code moved), the endpoint contract unchanged.

## Validation

- `src/api/agent_signing.rs` context-validation/DST tests; route tests for
  sign/verify round-trip and auth rejection.

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
