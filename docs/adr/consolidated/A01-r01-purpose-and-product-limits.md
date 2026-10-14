# A01 Purpose and Product Limits

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These slots remain Proposed (D198, D199). David accepted the archive transfer on 10 October 2026. [docs/adr/README.md](../README.md) and [docs/adr-archive/move.json](../../adr-archive/move.json) record that acceptance. Replacement acceptance and clause-level transfer checks are still open. Use the [index and transition rules](README.md) to interpret their status.

x0x connects people, their agents and their machines so they can collaborate. It supplies identity, permissions, communication, shared data and work coordination. This decision sets the boundary for the other 14 ADRs.

## Context

The current documents describe several products. Some describe an agent transport. Others describe a machine network, shared applications, or a complete collaboration system. Teams need one scope rule when they assess a feature or repair.

## Decision

We will build x0x as an owner-controlled network and collaboration layer. A person can connect their devices and agents, then share selected access with other people.

The product has three supported forms: the x0x Rust library, the x0xd daemon, and the x0x command-line client. The daemon provides a local API and a human interface. Applications can use these services without using Rust.

Core capabilities in this tree are:

- Identity, owner authority, trust, enrollment and revocation.
- Peer discovery, connectivity and controlled access to machine services.
- Direct and group messages, durable delivery and recoverable agent inboxes.
- Private, public and discoverable groups, with agent teams, delegated authority and shared work. Home stays private. [A08](A08-r01-groups-home-membership-and-repair.md) records the public and discoverable forms. Liveness and repair stay incomplete.
- Files, key-value stores, task lists and boards.
- Held data during a partition. Peers that can still reach each other keep their messages and the authorized shared data they hold.
- Human control, clear status, and maintenance under owner policy.

Target capabilities are:

- Projects. A project is one group, the shared data that group may use, and the agents shared into that work. The proposed record is [T-projects-and-agent-rental](../transient/T-projects-and-agent-rental.md).
- Agent rental. Rental is time-bounded use of a shared agent through ShareGrant expiry and revocation. This Proposed text would leave rental in scope and would stop the billing exclusion from ruling it out. It adds no price, invoice or marketplace. David has not accepted it.
- Scoped scratchpads.
- The complete resource envelope for network traffic, CPU, memory, disk and idle cost. [A06](A06-r01-gossip-relay-roles-and-resource-limits.md) keeps that envelope incomplete.

Users bring their own agents. x0x does not select a model, host an AI service, or define the meaning of an agent task. Runtime adapters connect x0x events to the selected agent.

A human owner is the authority for an owned installation. A standalone agent can still operate without a user key. Creating a user identity remains an explicit act.

## Product limits

Peers that can still reach each other keep their messages and the authorized shared data they hold. x0x does not provide a global storage network or a global directory that existing peers must reach before they can use that held data. Liveness and repair stay incomplete. Availability still depends on reachable peers, authorized data holders and the retention policy.

Machine connectivity does not mean unrestricted access to the machine. A peer still needs permission for each protected service.

x0x does not host a model, settle payments, or define the meaning of an agent task. Agent rental is a target in the list above. This Proposed text would leave rental in scope. David has not accepted it. Rental would be time-bounded access through an expiring, revocable ShareGrant. It would add no price, invoice or marketplace to x0xd.

Voice and video are a vision target for people and their agents. Checked at commit `86a1d395`, the optional `voice` feature (`src/voice/mod.rs`) is a two-party audio library (`X0xSignaling`, `X0xLinkTransport`). Call routes (`src/server/routes/calls.rs`) cover lifecycle only. Video remains future work. Implementation stays sequenced. The current parked priority remains in force, so this text starts no new media slice. Rich collaborative text remains parked. Existing code continues to receive required security and bug fixes.

New core requirements do not automatically lift a parked work item or an implementation hold.

## Alternatives

A transport-only product would leave identity sharing, durable agent delivery and group recovery to each application. This would duplicate important security work.

A complete hosted agent platform would expand x0x into model operation, payment settlement and application task semantics. We will keep model hosting, payment settlement and task meaning outside x0xd. Under this Proposed text, that limit would leave agent rental in scope. Rental stays a ShareGrant target. David has not accepted this text.

## Consequences

Each feature must show which core capability it serves. A correctness or security repair to shipped behavior remains valid even when the feature area is parked.

Product documents must separate present features, target behavior, parked work and verified release results. An accepted design is not a completion claim.

## Validation

ADR 0095 already establishes most of this scope. Reliable consumption by API riders is an additional requirement developed in [A04](A04-r01-agent-attachment-and-inbound-events.md) and [A07](A07-r01-messages-receipts-history-and-retry.md).

Before this replacement is accepted, the capability map must identify an owning ADR and an implementation status for each core promise. The current team work keeps its existing gates until the replacement decisions take effect.

## Matters to settle

Confirm that reliable inbound events are part of every supported agent attachment. Confirm that voice and video stay a vision target while their implementation stays sequenced. Confirm that rich collaborative text stays parked.

## Open questions

ADR 0095 is Accepted and archived. This draft does not edit its text.

David ruled D246 on 11 Oct 2026. He closed ADR 0095 open question 4 (Goal E under rule 5).

Goal E counts in place of an R under rule 5 when the change keeps the wire format, API, stored format and dependencies unchanged, and the rule-21 delivery matrix shows no loss. The decision states a target gain when Proposed. It is Folded only after a measured before-and-after result that meets E-D15 rule 15. Any wire, protocol, API or dependency change needs a transient ADR (D242) that names an R.

The full record is the transient decision [T-goal-e-rule-5](../transient/T-goal-e-rule-5.md) (D247). David accepted it (D255, 2026-10-12).

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0017 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0017-x0x-as-agent-transport-layer.md) · [ADR 0058 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0058-compile-time-embedded-constitution.md) · [ADR 0072 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0072-scope-freeze-deferred-and-legacy-maintenance.md) · [ADR 0095 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0095-scope-x0x-is-glue.md)

Decision source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Implementation checked on 12 October 2026 at commit `8cb6488331e6c1226913104ddb99ca4ec18bec37`.

Shipped claims in the 13 October 2026 vision text were checked on 14 October 2026 at commit `86a1d395` on `origin/main`. Grant caps are `ShareCap` in `src/share_grant.rs` (`Dm`, `Exec`, `Connect`, `GroupInvite`, `Call`). Presets are `GroupPolicyPreset` in `src/groups/policy.rs` (`private_secure`, `public_request_secure`, `public_open`, `public_announce`). The agent card route is `get_a2a_agent_card` in `src/server/routes/identity.rs`. Voice is `X0xSignaling` and `X0xLinkTransport` in `src/voice/mod.rs`, behind feature `voice`. Call routes in `src/server/routes/calls.rs` cover lifecycle only. Projects, rental and scratchpads stay targets.

[All 15 ADRs](README.md)
