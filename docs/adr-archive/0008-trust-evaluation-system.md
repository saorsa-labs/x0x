# ADR 0008: Trust Evaluation System

- Status: Accepted
- Date: 2026-04-24

## Context

x0x receives messages and identity announcements from arbitrary peers on the network. Each incoming message carries two identifiers: the sender's AgentId (portable software identity) and MachineId (hardware-pinned transport identity). The system must decide whether to accept, reject, or flag each message based on local policy.

The naive approach — trusting or blocking by AgentId alone — is insufficient because:

1. A compromised agent key could be used from an attacker's machine
2. A trusted agent might migrate to untrusted hardware
3. Users need fine-grained control over which machines a given agent may use
4. Different message types may warrant different trust thresholds

We need a unified trust evaluation system that combines identity trust, machine constraints, and message context into a single decision.

## Decision

x0x SHALL evaluate trust for (AgentId, MachineId) pairs, not either identifier in isolation. The evaluation is performed by TrustEvaluator against a local ContactStore.

### Trust Levels

Each contact has a TrustLevel:

| Level | Meaning |
|---|---|
| Blocked | Explicitly rejected — messages silently dropped |
| Unknown | Default for new senders — messages delivered but flagged |
| Known | Recognized and acceptable — messages delivered normally |
| Trusted | Full trust — messages can trigger actions |

### Identity Types

Separate from trust level, each contact has an IdentityType that controls machine constraints:

| Type | Machine Constraint |
|---|---|
| Anonymous | No machine information — no constraint |
| Known | Machine seen but not pinned — accepted from any known machine |
| Trusted | Trusted identity — accepted from any machine |
| Pinned | Only accept from specific pinned machines |

IdentityType is orthogonal to TrustLevel. A contact can be TrustLevel::Trusted with IdentityType::Pinned, or TrustLevel::Known with IdentityType::Anonymous.

### Trust Decision Outcomes

TrustEvaluator::evaluate() returns one of:

| Decision | Condition |
|---|---|
| Accept | Identity and machine are trusted |
| AcceptWithFlag | Identity is known/trusted, but machine is not pinned |
| RejectMachineMismatch | Contact is pinned to specific machines and this one is not in the list |
| RejectBlocked | Identity is explicitly blocked |
| Unknown | Agent not in contact store — consumer decides |

### Decision Flow

```text
Agent not in ContactStore → Unknown
Agent trust_level == Blocked → RejectBlocked
Agent identity_type == Pinned AND machine NOT in pinned list → RejectMachineMismatch
Agent identity_type == Pinned AND machine IS in pinned list → Accept
Agent trust_level == Trusted → Accept
Agent trust_level == Known → AcceptWithFlag
Agent trust_level == Unknown → Unknown
```

### Why Pinned is an IdentityType, not a TrustLevel

Machine pinning is a constraint on where an identity may operate, not a measure of how much we trust that identity. Separating these concerns allows:

- A Trusted agent to be pinned to specific machines (high trust + high constraint)
- A Known agent to have no machine constraints (moderate trust + no constraint)
- A Blocked agent to remain blocked regardless of machine (unconditional rejection)

If pinning were a trust level, we would lose the ability to express "I trust this agent, but only on these machines."

### Why AcceptWithFlag Exists

AcceptWithFlag bridges the gap between unconditional acceptance and rejection. When an agent is Known (not Trusted) and has no machine pinning, the system accepts the message but marks it with a flag. This allows:

- Message delivery to proceed (the agent is not blocked)
- Consumers to apply additional scrutiny (the agent is not fully trusted)
- Audit trails to distinguish "accepted from trusted source" from "accepted from known source"

Without this intermediate state, we would force a binary accept/reject for agents in the "known but not fully trusted" state, which is too coarse for real-world use.

## Operational Rules

### Where Trust Evaluation Applies

Trust evaluation is applied in the following contexts:

1. **Identity announcement processing** — Every incoming IdentityAnnouncement is evaluated before caching
2. **Direct message receipt** — Every DM envelope is evaluated before payload processing
3. **Gossip message delivery** — Messages from blocked senders are dropped before they become normal app events

### Machine Pinning Rules

- Only machines with pinned: true in the contact's machine list are accepted for Pinned contacts
- Machine pinning check happens AFTER the blocked check (blocked always wins)
- A contact can have multiple pinned machines
- Adding a machine record does not automatically pin it — pinning is explicit

## Consequences

### Positive

- Trust decisions evaluate both identity and machine, preventing compromised keys from being used on attacker hardware
- Machine pinning provides fine-grained control over where trusted agents may operate
- AcceptWithFlag allows graceful handling of agents in the "known but not fully trusted" state
- The orthogonal TrustLevel / IdentityType design enables flexible policy expression
- All trust decisions are local — no network-wide reputation service required

### Negative

- Users must understand both trust levels AND identity types to configure policy correctly
- Machine pinning requires proactive management as agents move between machines
- The AcceptWithFlag state may be confusing — consumers must handle flagged messages appropriately
- No transitive trust — trust is not automatically extended through mutual contacts

## Non-goals

- This ADR does not define global reputation or shared trust graphs
- This ADR does not define automatic trust escalation or decay
- This ADR does not define per-message-type trust policies
- This ADR does not require machine pinning for all contacts

## Acceptance Criteria

This ADR is satisfied only when:

- documentation explains the six-rule decision flow
- docs explain why Pinned is an IdentityType rather than a TrustLevel
- docs explain the purpose of AcceptWithFlag
- docs explain where trust evaluation is applied in the system
- docs explain the relationship between TrustLevel and IdentityType
```