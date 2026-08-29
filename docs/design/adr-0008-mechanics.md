# ADR-0008 mechanics — Trust model rationale

> Extracted 2026-08-29 from the immutable [ADR 0008](../adr/0008-trust-evaluation-system.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the design-rationale essays and acceptance criteria relocated verbatim
> so this file is their maintained home — future updates
> belong here, not in the ADR.

### Why Pinned is an IdentityType, not a TrustLevel

Machine pinning is a constraint on where an identity may operate, not a measure of how much we trust that identity. Separating these concerns allows:

- A Trusted agent to be pinned to specific machines (high trust + high constraint)
- A Known agent to have no machine constraints (moderate trust + no constraint)
- A Blocked agent to remain blocked regardless of machine (unconditional rejection)

If pinning were a trust level, we would lose the ability to express "I trust this agent, but only on these machines."

---

### Why AcceptWithFlag Exists

AcceptWithFlag bridges the gap between unconditional acceptance and rejection. When an agent is Known (not Trusted) and has no machine pinning, the system accepts the message but marks it with a flag. This allows:

- Message delivery to proceed (the agent is not blocked)
- Consumers to apply additional scrutiny (the agent is not fully trusted)
- Audit trails to distinguish "accepted from trusted source" from "accepted from known source"

Without this intermediate state, we would force a binary accept/reject for agents in the "known but not fully trusted" state, which is too coarse for real-world use.

---

## Acceptance Criteria

This ADR is satisfied only when:

- documentation explains the six-rule decision flow
- docs explain why Pinned is an IdentityType rather than a TrustLevel
- docs explain the purpose of AcceptWithFlag
- docs explain where trust evaluation is applied in the system
- docs explain the relationship between TrustLevel and IdentityType
