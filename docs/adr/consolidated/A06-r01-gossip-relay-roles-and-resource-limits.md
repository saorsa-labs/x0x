# A06 Gossip Relay Roles and Resource Limits

- **Status:** Accepted (David, course-correction directive, 7 Nov 2026, ruling 2)
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Active since 7 November 2026. The 15 accepted slots are the live decision authority.
- **Supersedes:** The archived numbered records mapped to this slot in [TRANSFER.md](TRANSFER.md). The archive stays the historical record. Existing implementation gates remain in force.

David accepted the 15 slots at their current revisions on 7 November 2026 (course-correction directive, ruling 2). They are the live decision authority. The numbered records stay in [docs/adr-archive](../../adr-archive/ARCHIVE.md) as the historical record. [docs/adr-archive/move.json](../../adr-archive/move.json) records the archive transfer David accepted on 10 October 2026. Use the [index](README.md) for the current rules.

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

Relay ingress refuses unsigned inner V1 messages (accepted by David, relayed 17 Oct 2026; archived as [T-relay-refuse-unsigned-inner-v1](../../adr-archive/transient/T-relay-refuse-unsigned-inner-v1.md)). The composite topic validator returns `Drop` when the inner payload decodes as unsigned V1, before content validators and relay fan-out budgets and after the outer signature checks, on normal ingress and on frames replayed after outer-key recovery. A refused message must not reach local delivery, eager forwarding, IHAVE advertisement, IWANT retrieval or anti-entropy serving; the gossip cache may retain its identifier for duplicate suppression, marked as refused. Signed V2/V3 prefixes and unsupported versions never fall back to V1. `relay_fanout.unsigned_inner_v1_dropped` on `GET /diagnostics/gossip` counts these validator refusals.

Gossip fan-out must reflect usable transport connections. Stale discovery entries must not create unbounded send targets.

No bandwidth-saving change may silently weaken the promised delivery or revocation behavior.

A targeted capability answer goes by unicast when the requester asks for it; the response topic stays the fallback (amended 14 Nov 2026 by Claude under David's delegation of design decisions of 10 Nov 2026; [#504](https://github.com/saorsa-labs/x0x/issues/504)). A requester may append its machine id to a request on `x0x/caps/v1/request/targeted-v2` (tag `0x01`, then the 32 bytes); the warm carrier never takes it. A responder that is already connected to that machine sends its signed advert as one direct frame (`x0x/caps/v1/unicast-response\0`, the responder's agent public key, the advert) and skips the topic answer for that requester. With no connection, a failed send, or a request without the machine id, it answers on the topic as before. The receiver accepts the frame only when the key derives to the frame's sender, the advert signature verifies, and the advert names the transport peer as its machine. Capability bit 18 `caps_unicast_response_v1` declares that an agent takes the direct frame. Responders from before this change ignore the trailer and answer on the topic. This does not change any shed or priority rule.

## Consequences

Ordinary devices have a bounded network role. Overload can delay or refuse work, and best-effort traffic can be lost. Operators need clear counters and measured budgets to choose relay capacity.

## Alternatives

Large default queues can delay visible failure but increase memory and recovery time.

Dropping every overloaded message protects the process but breaks durable delivery. We instead distinguish durable obligations from explicitly best-effort traffic.

Making every participant a relay can improve aggregate reach, but it spends user resources without a clear limit. We retain explicit roles.

## Current implementation

Desktop daemons default to `ParticipationMode::Leaf`. A seed listen address, a bind on UDP/443, a managed binary path or an explicit relay setting selects `Full`. Leaf byte shedding exists but is opt-in: `byte_policy` defaults to `observe_only`. Priority shedding and connectivity bounds exist. The complete resource envelope and broad efficiency evidence remain incomplete.

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

Decision source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Implementation checked on 12 October 2026 at commit `8cb6488331e6c1226913104ddb99ca4ec18bec37`.

[All 15 ADRs](README.md)
