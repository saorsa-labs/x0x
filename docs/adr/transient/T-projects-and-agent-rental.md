# T-projects-and-agent-rental: a project is a group, shared data and shared agents

- **Status:** Accepted (David, D275, 14 Oct 2026, slot A01, PR #1405)
- **Target slot:** A01
- **Date:** 2026-10-13
- **Decision owners:** David Irvine (direction, 13 Oct 2026)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** A01; A03; A08; A10; ADR 0070; product vision of 13 Oct 2026

## Context

No ADR defines a project. Groups, shared data and shared agents already exist as separate objects. On 13 Oct 2026 David said humans share agents, form projects, and can eventually rent agents to each other.

A named group carries policy and membership (A08). Shared data includes key-value stores, task lists and files (A10). A ShareGrant (ADR 0070, A03) exposes selected agents to another human. Caps are `Dm`, `Exec`, `Connect` and `GroupInvite`. Each grant expires and can be revoked. None of these objects is a project or a rental.

A01 puts billing outside x0xd. Read as a ban on every paid use, that sentence rules out rental. Rental is not model hosting and not a payment platform. The slot is A01 because a project is a product boundary.

## Decision Drivers

- A project reuses the group, the data and the grant.
- Rental must expire and must be revocable.
- x0x still does not host models or define task meaning.
- This tree has no project type. Documents must not claim one.

## Considered Options

1. A new membership object for projects. Rejected. It duplicates the group.
2. Treat every group as a project. Rejected. The vision also requires shared data and shared agents.
3. Put rental billing in x0xd now. Rejected. No price, invoice or settlement path exists.
4. Define the composition below, and define rental as a ShareGrant with expiry and revocation. Chosen. Both stay targets.

## Decision

A project is a group plus the shared data that group may use plus the agents shared into that work. The group supplies membership and authority. The data supplies documents and coordination state. The shared agents supply the workers. A project adds no second identity and no second permission system. This record adds no project identifier, API or store.

Agent rental is time-bounded use of another owner's agent. It builds on ShareGrant. The grant names the recipient, the agent, the actions and the expiry. Revocation ends the rental. Re-sharing stays denied unless a later accepted decision permits it. Rental adds no ledger, price or marketplace to x0xd.

x0x still does not host models, select a runtime, or define what an agent task means. Payment stays outside the daemon until David accepts a decision that places it there.

This record adds no rental cap and does not change ADR 0070. Folding into A01 waits until David asks.

## Consequences

### Positive

- Reviewers can check one project definition.
- The billing exclusion no longer forbids rental.
- Expiry and revocation remain the stop controls.

### Negative / Trade-offs

- No caller can create a project or a rental until a later slice names the API or wire change.

### Neutral / Operational

- Groups, stores, files and grants keep their present meaning.

## Validation

Reject a completion claim while this tree has no project type and no rental cap. A later design is valid only when expiry and revocation still stop access, including after a partition heals.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
