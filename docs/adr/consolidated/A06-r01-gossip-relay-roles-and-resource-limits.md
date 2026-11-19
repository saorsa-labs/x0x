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

A targeted capability answer goes by unicast when the requester asks for it; the response topic stays the fallback (amended 14 Nov 2026 by Claude under David's delegation of design decisions of 10 Nov 2026; [#504](https://github.com/saorsa-labs/x0x/issues/504)). A requester may append its machine id to a request on `x0x/caps/v1/request/targeted-v2` (tag `0x01`, then the 32 bytes); the warm carrier never takes it. A responder sends its signed advert as one direct frame only when that machine is the requester's own verified binding (its signed advert in the capability store) and the responder is already connected to it. It then sends it (`x0x/caps/v1/unicast-response\0`, the responder's agent public key, the advert) and skips the topic answer for that requester. A machine id that is not the requester's binding, no binding, no connection, a send not done within 1 s (at most 8 direct answers per cycle, sent concurrently), or a request without the machine id gets the topic answer as before. A verified agent therefore cannot point direct answers at another machine. The receiver accepts the frame only when the key derives to the frame's sender, the advert signature verifies, and the advert names the transport peer as its machine. Capability bit 18 `caps_unicast_response_v1` declares that an agent takes the direct frame. Responders from before this change ignore the trailer and answer on the topic. This does not change any shed or priority rule.

Amendment of 14 Nov 2026 (Claude, under David's delegation of design decisions of 10 Nov 2026; [#504](https://github.com/saorsa-labs/x0x/issues/504) follow-up). A direct frame can be lost where the topic still delivers, and the responder skips its topic answer once it has sent the direct one. So when a request that carried the machine id ends without the flight's own requirement met (a gossip-usable binding, the durable-ACK capability of ADR 0030, or the application bit of ADR 0093; a stale binding that was already stored does not count), the requester omits the machine id from its later requests to that responder for 10 minutes (at most 1024 responders remembered), and the responder answers on the topic. The record is sticky for its 10 minutes: a topic answer proves nothing about the direct path, so a flight that met its requirement on the topic does not clear it. Only expiry, or a later flight that carried the machine id and met its requirement, clears the record. The W3-H #1776 blind-window rows found the gap. No wire format change.

Amendment of 15 Nov 2026 (Claude, under David's delegation of design decisions of 10 Nov 2026; PR #1772). x0x pins all eleven `saorsa-gossip-*` crates at `=0.5.91` (was `=0.5.90`); that release pins ant-quic `=0.27.62`. Network behaviour changes against 0.5.90: a Critical Data send is not held back by peer cooling or suppression or by an in-flight recovery probe at claim time, which matches the admission rule that always admits Critical traffic (saorsa-gossip #24); Critical control traffic (IWANT, GRAFT) stays rate-limited during cooldown. A V3 key-cache retry of a control batch keeps one recovery intent, so a re-signed retry keeps its credit. A stale eager-reply claim (pruned, or its token does not match) gets no send attempts. IWANT re-admission is skipped while the request is `retry_pending`. A local publish is refused when signing returns an empty signature (`msg_id_after_local_sign`). The release also adds per-kind outer verify counters and a subscription that carries the verified `msg_id`; x0x does not use either yet. None of these changes an outbound meter definition, so the #501 controlled-load producer allowlist moves to the crates.io 0.5.91 package by checksum.

Transport bandwidth on `GET /status` (amendment of 17 Nov 2026, Claude, under David's delegation of design decisions of 10 Nov 2026; [#1964](https://github.com/saorsa-labs/x0x/issues/1964) request 5, PR #2000). This adds a measure of idle network traffic and useful-message cost. `GET /status` gains an additive `bandwidth` object: `sent_bytes` and `received_bytes` (process-lifetime application bytes, never cleared by a read) and `up_bps` and `down_bps` (bits per second over `window_secs`), each split into `total`, `gossip`, `direct`, `relay` and `other`. The kinds come from the stream-type byte; the relay-side forward of a relayed DM counts as `relay`. A send counts only after the write succeeds; a received frame counts at the receive demux before any gate or parse. QUIC and UDP overhead, streams and the evidence wire are not counted. A read stores at most one rate sample per second, so the sample window stays bounded. `x0x status` adds human-readable totals in text output only. This is visibility only: no limit, default or relay policy changes. No wire format changes.

Relay serving follows participation (amendment of 18 Nov 2026, Claude, under David's delegation of design decisions of 10 Nov 2026; [#1642](https://github.com/saorsa-labs/x0x/issues/1642)). x0x pins ant-quic `=0.28.0` and all eleven `saorsa-gossip-*` crates at `=0.5.92` (was `=0.27.62` and `=0.5.91`). ant-quic 0.28.0 honours `relay_service_enabled` (ant-quic ADR-019). With the setting off, ant-quic builds no MASQUE relay server and refuses each relay request with `403 "relay service disabled"`; the node still uses relays, coordinates hole punching and observes addresses. `NetworkConfig.relay_service_enabled` passes the setting to ant-quic; its library default is `true`, the ant-quic default. x0xd reads the optional TOML key `relay_service_enabled`. An explicit value wins. When the key is not set, a `Full` daemon serves relay sessions and a `Leaf` daemon does not, so a default desktop daemon stops serving relay sessions after upgrade. `GET /diagnostics/connectivity` `services.relay_enabled` and the `relay_capable` announcement field already read the ant-quic node status, so they now show the true value. A client that gets the refusal skips that relay for one hour; when every relay candidate refuses, the dial fails with `NatTraversalError::AllRelaysRefused`. x0x does not match on that enum. The optional `voice` feature moves to `saorsa-webrtc-core` and `saorsa-webrtc-codecs` 0.6.1. `saorsa-webrtc-core` 0.6.1 uses ant-quic 0.28.0 and the codecs crate does not depend on ant-quic, so the tree has one ant-quic version. The `saorsa-gossip-pubsub` 0.5.92 sources are byte-identical to 0.5.91, so the #501 controlled-load producer allowlist moves to the crates.io 0.5.92 package by checksum. No wire format change.

Sustained egress-budget warning (amendment of 19 Nov 2026, Claude, under David's [#1964](https://github.com/saorsa-labs/x0x/issues/1964) decision of 19 Nov 2026, PR 1 of 2; public API addition decided under A15). The Leaf egress meter already counts one-second samples whose 60 s subscribed-topic rate is above `leaf_egress_hard_bytes_per_sec` (`egress_budget_hard_exceeded`). It now also tracks the current unbroken run of such samples. When the run reaches 60 s (`SUSTAINED_EGRESS_EXCEED_SECS`), `GET /status` sets the additive `egress_budget_warning` object (null otherwise) and adds its `message` to `warnings`, so `x0x status` shows it. The object gives the run length, the 60 s rate, the hard budget, the effective `byte_policy`, bytes per second per wire kind (`eager`, `ihave`, `iwant`, `anti_entropy`) and up to three of the heaviest subscribed topics with their x0x priority class. Under `observe_only` the message says that the budget measures only and defers nothing. Under `shed_normal` it says that only forwarded (not locally originated) traffic on Normal/Bulk topics can be deferred (EAGER relays, IHAVE/IWANT, anti-entropy digests and serves of other nodes' messages), and that local publishes and serves of them, Critical topics, own-inbox delivery and targeted sends are never held back. This matches the saorsa-gossip 0.5.92 `BytePolicy::ShedNormal` contract. The run is measured from its first to its latest sample, and a gap of more than 5 s between samples restarts it, so a stalled sampling tick cannot make it look longer. The first sample back under the budget ends the run and clears the warning. `GET /diagnostics/gossip` `egress_budget.sustained_hard_exceeded` carries the same object. Full nodes and a zero hard budget never warn, because no Leaf budget applies. The existing one-second runtime tick does the sampling; there is no new task. This is visibility only: no cap, throttle, default or shed rule changes, and no wire format change. The cap (`max_upload_mbps`, with protected control classes) is PR 2 of the same decision.

Machine announce v3 forward limit (amendment of 19 Nov 2026, Claude, under David's delegation of design decisions of 10 Nov 2026; [#1964](https://github.com/saorsa-labs/x0x/issues/1964) item P2a). The storm-control content validator already limited `x0x.identity.announce.v2` and `x0x.machine.announce.v2`. It now also covers `x0x.machine.announce.v3`, which carried about 18 new message IDs per second on the live network where under 0.1 per second is expected. The relay decodes each announce exactly as receivers do (trailing bytes accepted) and keys it on its signed machine ID and on a digest of the decoded content without `announced_at` and the signatures, so an appended byte is neither undecodable nor a content change. Only an announce whose signed `announced_at` is strictly newer than the last forwarded announce of that machine can use a forward slot; the relay keeps that time across windows, so a replay of older valid announces, or an older copy that arrives late, is delivered but cannot open a window or take the change slot. In one 60 s window per machine the relay forwards the first announce and one announce whose content changed, so a real address change is not delayed. Every other announce of the window, and every announce whose signed timestamp is more than 900 s old or more than 300 s in the future, is delivered locally but not forwarded. Before an announce uses a forward slot, the relay verifies the machine signatures; an announce that fails, or whose inner envelope is unverified or signed for another topic, is dropped and uses no slot, so a forger cannot use the window of another machine. A payload that does not decode as a V3 announce is forwarded (fail open). The machine table has a hard cap of 32,768 entries (about 3-4 MB); an entry is kept until its window is over and its last forwarded announce is older than 900 s, so a replay after the window still finds it. When the table is still full after that expiry, which is checked at most once per second, an announce of a new machine is forwarded without an entry (fail open, counted as `table_full`), so a full table never blocks a real announce. Such an announce, from a machine without an entry while the table holds 32,768 entries, is forwarded without the guard's signature check; receivers still verify it. A limit remains: a relay that has not yet seen the current announce of a machine can be fed older announces of that machine that are under 900 s old and each strictly newer than the one before; each such announce costs at most one 60 s window of that machine on that relay. No guard is added for revocation, blob, move-activation or capability topics. `GET /diagnostics/gossip` `storm_control.machine_announce_v3` counts each outcome. Old nodes are not affected: the verdict changes only what this relay forwards. No wire format change.

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
