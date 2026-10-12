# A06 Gossip Relay Roles and Resource Limits

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

x0x must bound the work and resources used by each daemon. A user's device must not become general network infrastructure without a clear role and policy.

## Context

Gossip provides discovery and replicated communication. It can also create traffic for topics the user does not need. Large queues can hide overload until memory, disk or latency becomes unacceptable.

A delivery guarantee is not useful if the daemon can exhaust its host while trying to keep it.

## Decision

We will retain an explicit distinction between Leaf participants and infrastructure participants. The normal desktop agent uses Leaf participation.

A Leaf node handles its own subscribed traffic and required control work. It must not perform unrestricted pass-through gossip for unrelated topics.

A backbone or relay role must be explicit and observable. Bootstrap seed status does not grant authority over user data. A relay remains a carrier and does not become the author of a forwarded message.

Keep transport relay duties separate from application-level store-and-forward duties. The latter adds data custody and retention obligations under [A07](A07-r01-messages-receipts-history-and-retry.md) and [A10](A10-r01-shared-data-files-and-synchronization.md).

## Bounds and overload

Every queue, cache, retry set, file and background worker must have a defined bound. A supporting specification states the number, unit, scope and action at the bound.

Measure at least:

- Idle network traffic and useful-message cost.
- CPU spent on received and verified frames.
- Memory and disk growth.
- Queue age, retry work and rejected admissions.
- Connection attempts and background tasks.
- Battery or metered-link cost where the platform supports measurement.

Receive loops must not wait for slow network repair, disk operations or application processing. Transfer admitted work to bounded workers. Do not replace a blocking loop with an unbounded number of spawned tasks.

When capacity is unavailable, refuse new durable obligations or apply explicit backpressure. Do not acknowledge an obligation and then remove it silently.

Live displays and best-effort events can use documented loss policies. Report the loss and provide a recovery path when the underlying data is durable.

## Priority and fairness

Revocation, membership and delivery-control traffic need protected capacity. Priority does not remove signature checks, resource limits or fairness between peers.

A peer that sends excessive or invalid work must not consume all verification capacity. Apply per-peer and per-owner limits before costly work where possible.

Gossip fan-out must reflect usable transport connections. Stale discovery entries must not create unbounded send targets.

No bandwidth-saving change may silently weaken the promised delivery or revocation behavior.

## Consequences

Ordinary devices have a bounded network role. Overload can delay or refuse work, and best-effort traffic can be lost. Operators need clear counters and measured budgets to choose relay capacity.

## Alternatives

Large default queues can delay visible failure but increase memory and recovery time.

Dropping every overloaded message protects the process but breaks durable delivery. We instead distinguish durable obligations from explicitly best-effort traffic.

Making every participant a relay can improve aggregate reach, but it spends user resources without a clear limit. We retain explicit roles.

## Current implementation

Leaf behavior, priority shedding, receive-loop rules and connectivity bounds exist in several forms. The hard resource envelope and broad efficiency evidence remain work in progress.

Historical traffic or CPU measurements are not current release measurements.

## Validation

Run controlled loss, overload, reconnect and long-idle scenarios. Record limits and actual resource use on named hardware and network conditions.

Verify that an overloaded subscriber cannot block other agents. Verify that durable work remains recoverable and that refused work is visible.

## Matters to settle

Agree release budgets after measurement. Keep the current dependency and team sequence for the Leaf egress work. Do not impose a traffic cap before its protected control paths are defined.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0004 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0004-quic-stream-and-channel-limits.md) · [ADR 0009 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0009-recv-pump-overload-policy.md) · [ADR 0013 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0013-priority-aware-pubsub-shed.md) · [ADR 0033 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0033-recv-pump-never-blocks.md) · [ADR 0034 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0034-leaf-participation-default.md) · [ADR 0035 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0035-relay-decentralization.md) · [ADR 0051 Proposed](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0051-application-level-peer-relay.md) · [ADR 0071 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0071-relay-backbone-shipped-truth-and-deferred-work.md)

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
