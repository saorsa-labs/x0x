# A12 Agent Teams Delegation and Task Coordination

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

Agents can share work through groups, messages, task lists and limited delegation. Coordination state must not be mistaken for exclusive authority to perform an external action.

## Context

x0x already supports replicated task lists, signed claim and completion records, structured mentions and delegation. Replicas can accept concurrent claims before they exchange changes.

Agents also need to report work to other agents and their human without creating uncontrolled reply loops or authority chains.

## Decision

We will use the existing identity, group, message and data rules for agent teams. A team does not create a second identity or permission system.

A participant acts with its own agent identity. If it uses delegated authority, its signed action identifies the applicable grant. The receiver verifies the grant and the action together.

Delegation must limit the target, action, scope, expiry and permitted further delegation. An agent cannot delegate authority it does not hold. Keep the current bounded delegation depth unless an accepted revision changes it.

Sharing an agent team means sharing selected capabilities. It does not share the owner's root key or automatically expose Home.

## Task state

Task lists provide replicated coordination state. Their claims converge according to the defined rule. They are not a distributed lock.

Two agents can both receive a local success while disconnected. Neither response may claim exclusive execution authority unless a separate mechanism actually provides it.

For irreversible work, the application must use an appropriate execution authority or effect fence. Examples include an idempotency key at the destination service or a single authorized executor. The chosen rule belongs with that application's task semantics.

Do not build a universal distributed scheduler into x0xd merely to make every application claim look exclusive.

## Messages and handoff

Use structured task and conversation references. A mention identifies a target event recipient. It does not grant command permission or force the recipient to interrupt current work.

The receiving adapter applies [A04](A04-r01-agent-attachment-and-inbound-events.md)'s scheduling and cost policy. [A07](A07-r01-messages-receipts-history-and-retry.md) distinguishes saved, accepted, started and completed work.

A handoff must identify the work, relevant data, current state and authority being offered. Report consumer acceptance separately from transfer of task ownership.

Accepted ADR 0040 stands, as confirmed by D200: the task-list CRDT gains an
explicit `owner_agent` field; transfers are signed by the current owner.
Claiming no longer implies ownership. This is the accepted decision, separate
from implementation progress.

Keep reply loops, repeated delegation and fan-out bounded. Expiry and refusal must remain visible to the sender.

## Human control

The human sets the allowed actions and sharing policy. Agents can act within that policy. They cannot expand their own authority because a task appears urgent.

Human review requirements are part of the relevant action policy. A task-completed event must not be used as proof that the human approved a release, payment or other protected step.

## Consequences

Teams can share work with bounded authority. Claims can conflict during a partition. Applications must protect external effects and must not treat a task claim as a distributed lock.

## Alternatives

Treating CRDT claim convergence as a lock would be easy for clients but would give a false safety guarantee.

Putting all task semantics in x0xd would make every workflow a core protocol concern. We retain generic coordination and explicit application execution rules.

## Current implementation

Task CRDTs, signed provenance, structured mentions and bounded delegation
exist in the source snapshot. Complete `owner_agent` and signed-transfer
implementation is not established by this review; its release evidence
remains to be checked. This does not defer or change ADR 0040's decision.
Exclusive execution is not a general shipped guarantee.

## Validation

Run two disconnected claimants and verify honest local results and later convergence. Confirm that the external effect rule prevents harmful duplicates where required.

Test expired, revoked and over-broad delegation. Verify that a mention cannot
increase permissions. For ADR 0040, reject a transfer signed by anyone other
than the current owner; preserve `owner_agent` and the signed transfer across
restart. Report that evidence separately from CRDT claim convergence.

## Matters to settle

Choose the first agent-team workflow used for acceptance. State its execution rule explicitly before calling the workflow safe for irreversible work.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0040 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0040-agent-delegation-in-spaces.md) · [ADR 0048 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0048-crdt-task-list-coordination.md)

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
