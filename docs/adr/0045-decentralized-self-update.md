# ADR 0045: Decentralized Self-Update with Signed Manifests and Transactional Restart

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0001 Phase 4 (release-propagation authority only); `docs/upgrade-system.md`; `docs/design/x0x-self-update-deploy.md` (Phase C, not implemented). Backfill record for shipped behavior.

## Context

x0xd updates itself from signed manifests propagated over gossip
(`src/upgrade/`), with no ADR recording the decision. Manifests are
ML-DSA-65-signed under domain context `x0x-release-v1`
(`src/upgrade/signature.rs:11`) against a compiled-in public key
(`RELEASE_SIGNING_KEY`, `src/upgrade/signature.rs:21`). Release CI creates
`release-manifest.json` plus signature (`docs/upgrade-system.md:86`).

## Decision Drivers

- Updates must survive centralized unavailability; propagation must be
  peer-symmetric like every other gossip topic.
- A bad or partial apply must never leave a host without a runnable binary.
- Unsupervised desktop daemons still need a restart that cannot brick them.

## Considered Options

1. OS package manager / deploy pipeline only.
2. Central HTTPS poll-and-replace.
3. Gossip-propagated signed manifests, atomic replace, backup rollback,
   health-gated transactional restart (chosen).

## Decision

1. Releases propagate on gossip topic `x0x/release`
   (`src/upgrade/manifest.rs:10-11`); the daemon — not the monitor —
   subscribes (`src/server/routes/upgrade.rs:276-285`). GitHub polling is
   discovery origin and periodic fallback (`src/upgrade/monitor.rs:50-95`; `src/server/mod.rs:1128-1218`).
2. A gossip manifest must decode, parse, verify against the compiled key,
   and pass timestamp-freshness policy before use
   (`src/server/routes/upgrade.rs:313-355`); archives additionally verify
   SHA-256 hash and detached signature before extraction (`src/upgrade/apply.rs:166-200`).
3. Replacement is same-filesystem atomic rename (`src/upgrade/mod.rs:100-117`) with a pre-made backup; failed
   replacement restores and reports `RolledBack` (`src/upgrade/mod.rs:141-172`).
4. Restart is a transactional handoff: intent file, bounded graceful
   shutdown, wait for port release, start replacement, require bounded
   `/health` success, else restore/restart the backup and write an
   `UPGRADE_FAILED` artifact (`src/upgrade/restart.rs:292-455`).
5. Applies serialize on `upgrade_apply_lock`, apply only newer versions,
   and back off 30 minutes after a failed version (`src/server/routes/upgrade.rs:429-475`). Rollout delay is
   deterministic per machine (`src/upgrade/rollout.rs:1-35`).

## Consequences

### Positive

- Update authority is a compiled-in key, not a server; propagation works
  partitioned; crash-at-any-point recovers to a running binary.

### Negative / Trade-offs

- Key rotation means shipping new binaries anyway; GitHub remains the
  origin of first discovery.

### Neutral / Operational

- `docs/upgrade-system.md:77` says topic `x0x/releases` (plural); the code
  topic is `x0x/release` (singular) — doc drift, code wins.

## Validation

- `src/upgrade/` unit tests over manifest verify/rollback/restart paths;
  `tests/` transactional-handoff coverage per `docs/upgrade-system.md`.

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
