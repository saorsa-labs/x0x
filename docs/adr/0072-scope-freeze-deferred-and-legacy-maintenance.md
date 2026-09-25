# ADR 0072: Scope Freeze — Deferred and Legacy-Maintenance Mechanisms (2026-09-25)

<!-- File name: docs/adr/0072-scope-freeze-deferred-and-legacy-maintenance.md -->

- **Status:** Proposed
- **Date:** 2026-09-25
- **Decision owners:** David Irvine (decision, 2026-09-25 vision-alignment review), Claude (drafting)
- **Reviewers:** pending — David Irvine (acceptance); omp (cross-model review)
- **Supersedes:** none (no ADR is superseded wholesale)
- **Superseded by:** none
- **Amends:** ADR 0010 (status); ADR 0037, ADR 0038, ADR 0043 (roaming); ADR 0063 (gates)
- **Related:** ADR 0012, ADR 0024, ADR 0062, ADR 0064, ADR 0066, ADR 0067, ADR 0068, ADR 0071; PR #897 (ADR hygiene sweep)

## Context

The 2026-09-25 vision-alignment review measured the ADR set against the
product vision and found scope creep: most recent ADR and code effort went
to mechanisms (roaming key moves, Home fork authority/quarantine, legacy
compatibility) that no vision requirement needs next, while user-facing
requirements (R4, R5, R8, R10, R11) barely moved. The vision requirements:

| Id | Requirement |
|----|-------------|
| R1 | A human owner |
| R2 | The human has many agents |
| R3 | All my machines connected |
| R4 | Connectivity better than Tailscale |
| R5 | Share a subset of my agents with other people |
| R6 | Agents collaborate across machines |
| R7 | Machine-resident agents reachable by my agents and sharees |
| R8 | Video/audio calling |
| R9 | CRDT shared notes and agent scratchpads |
| R10 | An agent can open a GUI/browser view for its human |
| R11 | Agents teach others to install and join (easy onboarding) |

Shipped state relevant to the freeze (verified on `main` 2026-09-25):

- **Roaming.** The key-move ceremony (ADR 0043) is off by default:
  `[key_move] ceremony_enabled` defaults to `false` (`src/server/state.rs`),
  wired via `AgentBuilder::with_move_ceremony` (`src/server/mod.rs`); the
  builder default is `move_ceremony_enabled: false` (`src/lib.rs:4052`), and
  every `/agent/move*` path refuses while off. Placement ledgers still label
  the daemon's own agent `Roaming` (custodian = local machine), and the
  ADR 0038 ≥1-Roaming invariant is still checked (mint refusal #459, Home
  roaming warning in `src/server/routes/home.rs`). With the ceremony off a
  `Roaming` label has no operational effect: the key never leaves its machine.
- **GSS vs TreeKEM.** New `Hidden` + `MlsEncrypted` groups (the default
  `private_secure` preset) are created as TreeKEM per ADR 0012. GSS is **not**
  only grandfathered: the `public_request_secure` preset (and any
  `PublicDirectory` + `MlsEncrypted` policy) is still created on the GSS
  plane, deliberately, because its join-request convergence relies on the D4
  signed-commit path (`src/server/routes/named_groups.rs`, create handler).
- **Signed-KV legacy compat (ADR 0063, Proposed draft).** G0 met, G1–G8 open,
  facility disabled.
- **Home / fork authority.** ADR 0064, 0066, 0067, 0068 Accepted with shipped
  slices; ADR 0062 Proposed.

## Decision Drivers

- Close the vision gaps (table above) before extending mechanisms that serve
  none of them directly.
- Keep what shipped working and secure; a freeze is not a removal.
- Make scope decisions checkable: an ADR must say which requirement it serves.

## Considered Options

1. Continue all open mechanism work — rejected: this is the scope creep.
2. Remove the mechanisms — rejected: breaks existing groups/installs and
   discards working code for no user gain.
3. **Freeze: shipped behaviour stays, gets bug and security fixes, no new
   features until a vision requirement needs them** — chosen.

## Decision

We will freeze the following. "Frozen" means: shipped behaviour is kept and
receives bug and security fixes; no new features, slices, flags or protocol
versions are started.

1. **Agent roaming is DEFERRED** (amends ADR 0037, 0038, 0043).
   - The key-move ceremony stays disabled by default; no work to enable it.
   - Pinned operation — each agent's key stays on the machine that holds
     it — is the supported mode. Existing `Roaming` labels and the ≥1-Roaming
     checks are left as shipped; this ADR mandates no code change to them.
   - ADR 0038's "Home contains ≥1 Roaming agent" requirement is **suspended**
     while roaming is deferred: it is not an acceptance or release criterion,
     and no new work is done to satisfy or strengthen it.
2. **GSS is legacy-maintenance** (amends ADR 0010's status; ADR 0024 in scope).
   - Existing GSS groups keep working and receive security fixes.
   - No new GSS features. The default for new private secure groups is
     TreeKEM (ADR 0012), as shipped.
   - GSS creation remains available through the `public_request_secure`
     preset / `PublicDirectory` + `MlsEncrypted` policies, as shipped; it is
     not advertised as a new-group choice in docs or onboarding. Moving those
     presets off GSS needs its own ADR.
3. **Signed-KV legacy compatibility (ADR 0063) is frozen at its current
   gates**: G0 met, G1–G8 open, facility disabled. No further gate work.
4. **Home / fork quarantine (ADR 0062, 0066, 0067, 0068) take no new
   features.** Shipped slices stay and get bug fixes; unshipped slices and
   follow-ups are not started.
5. **Requirement rule.** Every new ADR must name, in its Related or Decision
   Drivers, the requirement(s) R1–R11 it serves. An ADR that serves none is
   rejected unless it is a correctness/security fix to shipped behaviour.
6. **Lifting a freeze** requires a new ADR that names the requirement(s) the
   frozen mechanism is now needed for and why no smaller change serves them.

## Consequences

### Positive

- Effort is directed at the vision gaps (R3–R5, R7–R11) and delivery
  reliability (ADR 0071).
- Scope decisions become reviewable against a fixed yardstick.

### Negative / Trade-offs

- An agent cannot follow its owner across machines; users run a pinned agent
  per machine.
- Public request-access encrypted groups stay on GSS (no TreeKEM FS/PCS).
- The legacy signed-KV interoperability path stays unavailable.
- Ordinary-group fork recovery gaps recorded in ADR 0064/0066 stay open.

### Neutral / Operational

- Code that reads `Roaming` placements or enforces the ≥1-Roaming invariant
  is left as-is; any change to it is a bug fix, justified per issue.
- Open issues and PRs for frozen items should be labelled/parked, not closed
  as rejected.

## Validation

- Review check: a PR adding a feature to a frozen mechanism must cite a
  superseding ADR under Decision item 6, or it is declined.
- Review check: a new ADR without a named R1–R11 requirement is sent back.
- Revisit at each release or when any R-requirement gap closes, whichever is
  first; the code facts in Context are re-verified at acceptance.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
