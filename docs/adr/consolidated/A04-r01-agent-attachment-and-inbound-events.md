# A04 Agent Attachment and Inbound Events

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

Attaching an agent to x0x must let that agent receive authorized work. A credential that can send messages but cannot receive events is not a complete agent attachment.

## Context

x0x supports key-owning harnesses and API riders. The current rider token permits selected group sends and bounded history reads. It cannot subscribe to live WS or SSE routes.

The term ACP-attached currently describes key ownership and placement. It does not mean that x0xd implements the Agent Client Protocol or starts an agent turn.

## Decision

We will give each supported attachment an authenticated agent identity and a recoverable event inbox. The agent can receive live events, recover missed events, and acknowledge acceptance.

We retain two hosting forms:

- A key-owning agent uses its own daemon or library instance.
- An API rider uses a shared daemon with a scoped credential and verifiable attribution.

Both forms use the same permission and receipt model. Their key custody can differ.

The proposed API rider model adds separate permissions for inbox access and, where granted, direct messages. A group grant does not expose every daemon event or all direct messages. The route and scope design must be reviewed before implementation.

## Boundary between daemon and runtime

x0xd verifies identities, applies permissions, saves events and reports delivery state. It does not choose a language model or interpret the task.

A runtime adapter receives the event and selects the correct agent session. It records enough state to resume after a crash before it acknowledges consumer acceptance.

For an ACP runtime, the adapter acts as a client and submits an authorized prompt turn. Agent session updates report runtime activity. They do not replace the x0x inbox.

For a hosted model API, the adapter calls the provider API. The adapter controls credentials, cost limits, parallel work and conversation state.

An MCP tool surface can expose x0x operations. A2A can carry task messages and status through an adapter. Neither protocol removes the need for durable local consumption.

## Delivery and operating rules

A04 uses the durable delivery contract in [A07](A07-r01-messages-receipts-history-and-retry.md). Each agent has a separate consumer position. Shared workers need an explicit rule for assigning one event to one worker.

A connected daemon does not prove that an agent is ready. Status must distinguish daemon reachability, adapter connection, queued work, busy state and runtime failure.

Queue work when the runtime is busy. Interrupt a running turn only when the runtime supports it and the owner policy allows it.

A mention routes an event. It does not grant authority to execute the message. Apply the sender's actual permissions and preserve its source identity.

Cap automatic reply loops, fan-out and model spend. Present remote content as received input, never as higher-priority system instructions.

## Consequences

Every supported runtime needs an adapter and recovery tests. x0xd can report delivery without taking control of the model. Durable inboxes add disk use, retention choices and adapter maintenance.

## Alternatives

Polling history can support an interim integration, but each client then has to build its own recovery logic.

Giving every harness the owner token would make integration easy but would remove the intended permission boundary. We reject that approach.

## Validation

Structured mentions, live streams and bounded backfill exist. The per-rider live inbox and full runtime handoff do not yet exist. A2A streaming and push remain disabled.

Prove delivery with one native API consumer and one real ACP adapter. Stop the adapter, send work, restart it and verify recovery. Crash before acknowledgment and verify redelivery without duplicate work.

Test scope isolation and revocation during replay. A cloud adapter must also demonstrate safe handling of provider rate limits.

## Matters to settle

Confirm that scoped direct inboxes are part of rider support. Select the first supported runtime and agree queue, expiry and cost defaults.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0039 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0039-agent-harness-boundary.md)

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
