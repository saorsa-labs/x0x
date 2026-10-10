# ADR 0096: R12 — x0x Is Maintained by Its Own Agents

<!-- File name: docs/adr/0096-r12-x0x-is-maintained-by-its-own-agents.md -->

- **Status:** Accepted
- **Accepted:** 2026-10-03 by David Irvine (D58, as written: the Proposed text merged via #1185, commit 80d448e; his instruction to Claude directly). The Open questions remain open for later rulings. The status change was applied by Claude at his instruction.
- **Date:** 2026-10-03
- **Decision owners:** David Irvine (ruling D20; only David marks this ADR
  Accepted)
- **Author:** Claude (Opus)
- **Reviewers:** Codex (cross-model r1)
- **Supersedes:** none
- **Superseded by:** none
- **Extends:** [ADR 0072](./0072-scope-freeze-deferred-and-legacy-maintenance.md)
  (adds requirement R12 to its requirement table and to rule 5). ADR 0072 is
  not edited.
- **Goal served:** goal **M** (self-sustaining). This ADR defines R12, the
  requirement that goal M's new work names.
- **Related:** [`docs/design/x0x-direction.md`](../design/x0x-direction.md)
  (§2, §4 invariant I10, §7; rulings D05, D20, D21, D47, D51, D52, E-D15);
  [ADR 0095](./0095-scope-x0x-is-glue.md) (scope, drafted with this ADR);
  [ADR 0045](./0045-decentralized-self-update.md) (self-update, to be
  superseded by ADR 0097, prov.);
  [ADR 0061](./0061-supervised-upgrade-restart-ownership.md) §6 (to be
  superseded by ADR 0094, prov.);
  [ADR 0087](./0087-repository-and-release-governance.md) (release
  governance; its considered option 4 on signing custody).

## Context

- ADR 0072's requirement list (R1–R11) has no requirement for goal M. So a
  new goal M feature has no requirement to name under ADR 0072 rule 5. Only
  correctness and security fixes to shipped behaviour are admissible today.
- Today, keeping x0x healthy and current needs humans. Every enabled node
  applies a signed release when it first sees it (ADR 0045). There is no
  owner update policy, no rings across an owner's machines and no recall.
  Invariant I10 (every release can be undone without human SSH, and no
  release passes ring 0 before evidence exists) is violated today.
- The v0.46.0 rollout shows this. Operators ran the signed-update canary on
  two production hosts and held two other hosts by hand (D51).
- D20 agreed R12, "x0x is maintained by its own agents". It deferred this
  ADR until v0.46.0 was promoted. v0.46.0 was published on 2026-10-03 (D52).
- D21 starts Track M-safety right after v0.46.0, in parallel with W3: M1
  (health verdict) and M2 (safe apply with self-rollback). Both fix shipped
  behaviour, so they do not need R12.
- ADR 0095 says we do not provide agents. R12 must work with any agent the
  owner brings.

## Decision Drivers

- An owner with 2–5 machines must not need SSH to keep x0x healthy and
  current (I10).
- The owner keeps authority. Agents act only within the owner's policy.
- Release-signing authority stays where ADR 0087 put it.
- Fixes for unsafe upgrades must not wait for feature ADRs.

## Considered Options

1. **No R12; treat all goal M work as fixes.** Rejected. Recall, owner
   policy, canary and problem reports are new surface. ADR 0072 rule 5
   needs a requirement for new surface.
2. **Fold maintenance into R11 (onboarding).** Rejected. R11 covers install
   and join. It does not cover health, update policy, rollback or recall on
   the owner's own machines.
3. **x0x ships its own maintenance agent.** Rejected. We do not provide
   agents (ADR 0095). x0x provides the surface that the owner's agents use.
4. **Add R12 to ADR 0072, gate M3–M6 on it, and let M1 and M2 proceed as
   fixes.** Chosen.

## Decision

We will add R12 to the ADR 0072 requirement list, with the rules below.

### 1. The requirement

**R12: x0x is maintained by its own agents.** The owner's agents keep each
of the owner's x0x nodes healthy and upgraded, under a policy that the owner
sets. Routine maintenance needs no human SSH. Routine maintenance is: health
checks, upgrade, hold, rollback, recall and problem reports.

### 2. ADR 0072 extended

- ADR 0072's requirement table gains R12. Rule 5 accepts R1–R12.
- Nothing else in ADR 0072 changes. Rule 5's exception for correctness and
  security fixes to shipped behaviour, and rule 6 (lifting a freeze), stay
  as written.

### 3. Who decides what

- **The owner** sets the update policy. The human approves every
  authority-changing step: the owner key, enrolment, grants and the update
  policy.
- **The owner's agents** act within that policy. They read health, apply,
  hold, roll back, report problems, and help other agents install or
  upgrade.
- **Release signing does not move.** Deployed maintenance agents gain no
  release-signing authority. Protected release-workflow operations stay
  under David's authorization (ADR 0087, D05, D47). Future signing custody
  is left to the decision that ADR 0087 requires before M4.
- **The daemon** keeps apply safety with no agent present (M2, ADR 0094):
  it verifies before apply, probes the new binary before the swap, checks
  health at boot and rolls back a failed boot by itself. Ring and canary
  enforcement belong to M4 and ADR 0097, not to M2.

### 4. The agent surface

- Every maintenance action is a JSON API call with a typed error and an
  event. A scripted client exercises each one in CI.
- x0x provides this surface. It does not ship an AI agent.
- Maintenance data goes to the owner's own devices. Reports to the
  maintainers are opt-in and redacted.
- Maintenance work applies the E-D15 efficiency checklist, like every PR
  and ADR.

### 5. What R12 gates

These items need R12, and each needs an ADR that names it:

- **M3 recall:** stop a bad release, refuse to apply it and permit the one
  safe downgrade.
- **M4 owner update policy and canary:** an owner-signed policy with rings
  and canary evidence. M4 also waits for the release-signing custody
  decision (ADR 0087, considered option 4).
- **M5 problem reports:** a redacted diagnostic bundle, sent to the owner
  or, if the owner opts in, to the maintainers.
- **M6 install and upgrade help:** an agent helps another agent or person
  install, join or upgrade. M6 also names R11.
- **ADR 0097 (prov.)**, owner-governed self-maintenance (policy, channel,
  staging, recall and canary), will supersede ADR 0045. It names R12.

### 6. What R12 does not gate

- **M1 health truth** (a `/health` verdict, a census, `x0x doctor --json`)
  and **M2 safe apply** fix shipped behaviour (D21).
- M2 stays within ADR 0094's safety scope: a pre-swap exec probe, a boot
  health check, self-rollback, a channel field, StagedRollout wired up or
  deleted, and a CLI companion rollback. It adds no owner policy, rings or
  canary.
- M1 and M2 proceed now through ADR 0094 (prov.), which supersedes
  ADR 0061 §6, as correctness and security fixes under ADR 0072 rule 5.
  They may cite R12 as the goal they support. They do not wait for this
  ADR. The fix exception does not waive a freeze, an implementation hold
  (D28) or ADR 0087's ADR-before-code ordering.

### 7. Order

M3 comes first in W4, after this ADR and ADR 0095 (digest §7). M4, M5 and
M6 follow later in the W4 order. Each ships behind a default-off flag, one R
at a time.

## Consequences

### Positive

- New goal M work has a requirement to name, so its ADRs are checkable.
- The split between the owner, agents, release signing and the daemon is
  fixed before M3–M6 are designed.
- Upgrade safety (M1, M2) does not wait for this ADR.

### Negative / Trade-offs

- An owner gets more state to hold: a policy record, rings and canary
  attestations. Each costs bytes, and the E-D15 checklist applies.
- An agent can hold or roll back the owner's nodes within policy. A
  compromised agent can therefore delay upgrades on that owner's machines.
  The policy bounds the harm, and only the human changes the policy.
- M4 waits for a signing-custody decision that is still open.

### Neutral / Operational

- R12 covers deployed nodes. The repository's own release process stays
  under ADR 0087. Under D47 a designated release operator, which may be an
  agent, may approve the build, sign and draft-creation environments for
  `v*` tags that David has authorized. Publishing, tag changes, draft
  downloads and production changes still need David's specific approval.
- The goal M exit test (digest §7) is the measure of R12.

## Validation

- **Goal M exit test:** one release is promoted under an owner's policy
  with a ring-0 attestation. One deliberately bad canary is rolled back and
  recalled automatically, with no human SSH.
- **Review check:** an M3–M6 ADR names R12, or it is sent back. An M1 or M2
  PR is not blocked on this ADR.
- **Review check:** each new maintenance action ships with its route, typed
  error, event and test.
- **Review check:** no change gives a deployed maintenance agent
  release-signing authority, or lets it change the owner's update policy
  without the human.
- **Revisit** when ADR 0097 is decided, when M4's signing custody is
  decided, or when a field incident needs human SSH to recover a node.

## Open questions for David

1. **Scope of R12.** Deployed nodes only (this draft)? Or does it also
   cover agents that maintain the x0x code and releases (triage, fix PRs,
   release operations)?
2. **Reference helper.** Should x0x ship a default-off reference maintenance
   helper, or only the surface (this draft)? This depends on the placement
   rule, which is open in ADR 0095 (question 6).
3. **Default policy.** For an owner who sets no policy: keep today's apply
   on first sight, or hold until ring evidence exists? This draft leaves it
   to ADR 0097. Do you want to set the direction now?
4. **Reports to maintainers.** Opt-in and off by default (this draft).
   Confirm?
5. **Agent autonomy.** May an owner's agent hold or roll back within policy
   without asking the human each time (this draft), or must the human
   confirm every rollback?

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
