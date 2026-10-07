# A01 Purpose and Product Limits

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

x0x connects people, their machines, and their chosen agents. It supplies identity, permissions, communication, shared data, and work coordination. This decision sets the boundary for the other 14 ADRs.

## Context

The current documents describe several products. Some describe an agent transport. Others describe a machine network, shared applications, or a complete collaboration system. Teams need one scope rule when they assess a feature or repair.

## Decision

We will build x0x as an owner-controlled network and collaboration layer. A person can connect their devices and agents, then share selected access with other people.

The product has three supported forms: the x0x Rust library, the x0xd daemon, and the x0x command-line client. The daemon provides a local API and a human interface. Applications can use these services without using Rust.

Core capabilities are:

- Identity, owner authority, trust, enrollment and revocation.
- Peer discovery, connectivity and controlled access to machine services.
- Direct and group messages, durable delivery and recoverable agent inboxes.
- Groups, agent teams, delegated authority and shared work.
- Files, key-value stores, task lists, boards and scoped scratchpads.
- Human control, clear status, and maintenance under owner policy.
- Measured limits for network traffic, CPU, memory, disk and idle cost.

Users bring their own agents. x0x does not select a model, host an AI service, or define the meaning of an agent task. Runtime adapters connect x0x events to the selected agent.

A human owner is the authority for an owned installation. A standalone agent can still operate without a user key. Creating a user identity remains an explicit act.

## Product limits

x0x does not provide a global storage network or a global directory that must be available for existing peers to work. Availability depends on reachable peers, authorized data holders and the retention policy.

Machine connectivity does not mean unrestricted access to the machine. A peer still needs permission for each protected service.

Voice and video remain part of the product direction. Their current parked priority remains in force. Rich collaborative text also remains parked. Existing code continues to receive required security and bug fixes.

New core requirements do not automatically lift a parked work item or an implementation hold.

## Alternatives

A transport-only product would leave identity sharing, durable agent delivery and group recovery to each application. This would duplicate important security work.

A complete hosted agent platform would expand x0x into model operation, billing and application task semantics. We will keep that work outside x0xd.

## Consequences

Each feature must show which core capability it serves. A correctness or security repair to shipped behavior remains valid even when the feature area is parked.

Product documents must separate present features, target behavior, parked work and verified release results. An accepted design is not a completion claim.

## Validation

ADR 0095 already establishes most of this scope. Reliable consumption by API riders is an additional requirement developed in [A04](A04-r01-agent-attachment-and-inbound-events.md) and [A07](A07-r01-messages-receipts-history-and-retry.md).

Before this replacement is accepted, the capability map must identify an owning ADR and an implementation status for each core promise. The current team work keeps its existing gates until the replacement decisions take effect.

## Matters to settle

Confirm that reliable inbound events are part of every supported agent attachment. Confirm that voice/video and rich text retain their current priority.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0017 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0017-x0x-as-agent-transport-layer.md) · [ADR 0058 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0058-compile-time-embedded-constitution.md) · [ADR 0072 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0072-scope-freeze-deferred-and-legacy-maintenance.md) · [ADR 0095 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0095-scope-x0x-is-glue.md)

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
