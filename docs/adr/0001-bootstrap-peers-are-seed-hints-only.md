# ADR 0001: Bootstrap Peers Are Seed Hints Only

- Status: Accepted (Phase 1 functionally complete — nomenclature rename deferred, Phases 2–5 future)
- Date: 2026-03-11

## Context

x0x is intended to be a decentralized agent network. That goal is undermined if a fixed operator-managed set of nodes becomes a privileged control plane for:

- joining the network;
- coordinating NAT traversal;
- relaying traffic; or
- propagating release authority.

The underlying transport already supports a symmetric model. In `ant-quic`, any publicly reachable node can coordinate NAT traversal and relay traffic when conditions allow. The centralization pressure comes from x0x policy and wiring:

- hard-coded bootstrap peers are treated as the default authority set for joining the network;
- coordinator selection still bottoms out in configured bootstrap peers;
- ordinary publicly reachable nodes are not promoted into the coordinator or relay pool by x0x policy; and
- release propagation in the current self-update design privileges `x0xd` nodes as the primary broadcasters.

If those properties remain true in steady state, x0x is not meaningfully decentralized. It becomes a network that depends on a designated operator-managed class of nodes.

## Decision

x0x SHALL treat bootstrap peers as seed hints only, never as a privileged control plane.

This means:

1. Static bootstrap addresses MAY exist as a first-contact mechanism for cold start.
2. Static bootstrap addresses MUST NOT remain the default authority set for coordinator or relay selection in steady state.
3. Any ordinary node with suitable public reachability MUST be eligible to become a coordinator or relay candidate.
4. Eligibility for coordination and relay duties MUST be based on signed, expiring capability advertisements plus local validation and scoring, not on operator-maintained allowlists.
5. Release gossip MUST be treated as a hint only. No node, including `x0xd`, is authoritative merely because it broadcast a release notification.
6. A node MUST independently verify release artifacts before applying an update or rebroadcasting a release hint.
7. The `x0xd` binary, if retained, SHALL be understood as optional operator packaging for stable public seeds and observability, not as a protocol role required for correctness or liveness.

## Consequences

### Positive

- Removes forced centralization from the protocol model.
- Aligns x0x policy with the symmetric design already present in `ant-quic`.
- Allows the network to become more resilient as ordinary public nodes join and contribute coordinator and relay capacity.
- Prevents release propagation from becoming an operator-controlled broadcast channel.

### Negative

- Requires additional discovery, validation, and scoring work in x0x.
- Makes coordinator and relay selection more dynamic, which raises implementation complexity.
- Requires clearer signed capability advertisement semantics at the agent layer.

### Non-goals

- This ADR does not require removing all static seed addresses immediately.
- This ADR does not require every node to be publicly reachable.
- This ADR does not prohibit Saorsa Labs from operating stable public seed nodes.

What it prohibits is protocol dependence on a permanently privileged Saorsa-operated node class.

## Required Follow-up Work

### Phase 1: Demote bootstrap peers to seed hints

- Rename the concept in x0x documentation and code from privileged bootstrap peers to seed hints where appropriate.
- Change startup peer selection to merge:
  - configured seed hints;
  - locally cached peers; and
  - previously validated public coordinator candidates.
- Ensure a previously participating node can rejoin without needing the hard-coded seed list to be reachable.

### Phase 2: Signed capability advertisements

- Extend the existing signed rendezvous advertisement flow to carry coordinator and relay capability metadata.
- Publish only expiring, signed advertisements.
- Admit nodes into the local coordinator pool only after signature and freshness validation.

### Phase 3: Dynamic coordinator and relay selection

- Prefer validated dynamic coordinator candidates over static seed hints.
- Use static seed hints only as cold-start or empty-pool fallback.
- Allow ordinary publicly reachable `x0xd` instances to enter the coordinator and relay pool automatically once validated.

### Phase 4: Decentralized release propagation

- Treat `ReleaseNotification` as a discovery hint, not an authority.
- Require each node to independently fetch and verify the canonical release artifact before apply or rebroadcast.
- Allow any verifying node to rebroadcast release hints.

### Phase 5: Re-scope `x0xd`

- Keep `x0xd` only as optional operational packaging for stable public seeds, health endpoints, and managed restarts.
- Do not require `x0xd` for protocol correctness, reachability, or upgrade authority.

## Acceptance Criteria

This ADR is satisfied only when all of the following are true:

- a node can rejoin from cached peers without contacting the default seed list;
- ordinary publicly reachable nodes can advertise signed coordinator and relay capability;
- steady-state coordinator selection prefers validated dynamic peers over static seed hints;
- release propagation does not depend on `x0xd` nodes being the primary broadcasters; and
- loss of the default Saorsa-operated seed set degrades cold-start convenience, not network legitimacy or steady-state operation.
