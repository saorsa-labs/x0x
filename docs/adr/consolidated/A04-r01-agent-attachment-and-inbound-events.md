# A04 Agent Attachment and Inbound Events

- **Status:** Accepted (David, course-correction directive, 7 Nov 2026, ruling 2)
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Active since 7 November 2026. The 15 accepted slots are the live decision authority.
- **Supersedes:** The archived numbered records mapped to this slot in [TRANSFER.md](TRANSFER.md). The archive stays the historical record. Existing implementation gates remain in force.

David accepted the 15 slots at their current revisions on 7 November 2026 (course-correction directive, ruling 2). They are the live decision authority. The numbered records stay in [docs/adr-archive](../../adr-archive/ARCHIVE.md) as the historical record. [docs/adr-archive/move.json](../../adr-archive/move.json) records the archive transfer David accepted on 10 October 2026. Use the [index](README.md) for the current rules.

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

Roster hosting mode (amendment of 22 Nov 2026, #2158). The owner roster (`GET /owner/agents`, and every reader of `Agent::owner_issued_certificates`, such as placement minting and the `POST /report` target check) takes an agent's hosting mode (`acp` or `rider`) and label from the last line, in journal file order, of the owner's certificate journal that states them: a line written by `POST /owner/agents/issue` (it keeps the certificate bytes, so an unlabelled `--mode acp` issuance states a mode too), or any line in rider mode or with a label. File order, not `issued_at`, decides: only this daemon's issue route writes such lines and it appends them in order (the journal is append-only), so a local clock step back cannot reorder them, and of two issuances in the same second the later line wins. A line written for the daemon's own issuance, on first sight of a live certificate, or by owner sync states no mode, and an agent with no such line is `acp`. The certificate fields of a journal row come from the last line for that agent in file order; a live certificate replaces them only when it was issued strictly later (the journal wins on an equal second), as before. So a renewal or a live-announced certificate replaces the certificate but keeps a rider's mode and label, also after a restart. Before this amendment such a certificate reset a rider to `acp` and dropped its label. A later `POST /owner/agents/issue` for the same agent in the other mode is the owner's intended change and applies in both directions. The journal line format does not change: lines already written by older builds read correctly, and an older build reading a newer journal behaves as before. The `POST /report` target rule of A14 (amendment of 21 Nov 2026) stays as written: an agent that any journal line of this owner records as a rider is refused, even when a later issuance made it `acp`, because `POST /owner/riders` can still mint a rider token from that rider line (it picks the rider line with the greatest `issued_at`, not the last in file order; not changed here). Changed behaviour for a mode set on another owner device: owner sync carries no mode, so the synced line states none. Before this amendment, a rider re-issued as ACP on another owner device showed `acp` here, because the synced bare line reset the mode; now it stays `rider` here until this daemon issues it again. Placement minting then pins it to this machine instead of waiting for discovery of its harness machine, and `POST /report` refuses it (fail closed, as before). Carrying the mode in owner sync is #2182. Authority: decided by the orchestrator session under A15, 22 Nov 2026 (David asked for the fix on 22 Nov 2026; the file-order rule is the orchestrator's ruling of the same date).

Mode set on another owner device (amendment of 24 Nov 2026, [#2182](https://github.com/saorsa-labs/x0x/issues/2182); decided under the A15 amendment of 12 Nov 2026 by the orchestrator session). Owner sync now carries the hosting mode and label of an owner issuance as its own Tier-1 kind (rules in [A02](A02-r01-identity-keys-and-device-enrollment.md), amendment of 24 Nov 2026). The receiving device appends a mode line (`synced_mode: true`) that states the mode and label and repeats the certificate fields of the agent's last line, so the file-order rule of the paragraph above reads it like a local issuance and the certificate the roster shows does not change. Thus a rider re-issued as ACP on another owner device shows `acp` here, and placement minting waits for discovery of its harness machine; an ACP agent re-issued as a rider elsewhere shows `rider` here. Two devices that state different modes converge on the statement of the later issuance (by `issued_at`), whatever order they reconcile in; a re-issue on a device whose clock is behind the issuance it replaces loses, and that device then shows the winner too. The `POST /report` target rule is not changed: a synced rider line is a rider line of this owner, so the agent is refused. `POST /owner/riders` does not use a synced line, because it carries no certificate bytes. A device that runs protocol 3 still keeps the behaviour that the paragraph above states.

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

Decision source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Implementation checked on 12 October 2026 at commit `8cb6488331e6c1226913104ddb99ca4ec18bec37`.

[All 15 ADRs](README.md)
