# T-alternate-bearers: Bluetooth, serial and radio through ant-quic

- **Status:** Proposed
- **Target slot:** A05
- **Date:** 2026-10-13
- **Decision owners:** David Irvine (direction, 13 Oct 2026)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** A05; ADR 0006; product vision of 13 Oct 2026

## Context

On 13 Oct 2026 David said x0x is ready for Bluetooth, serial and radio, and that ant-quic is ready for these bearers. No ADR here names BLE, serial or radio. The x0x sources have no such path.

A05 keeps ant-quic as the transport boundary. ant-quic owns connection setup and path management. x0x supplies identity, policy and application protocols. A second bearer stack would split that boundary.

ADR 0006 says peers who can still reach each other keep their data inside a partition. That rule does not say a radio link can carry every object.

## Decision Drivers

- Bearers stay inside ant-quic.
- A link is not authority. Identity checks stay in x0x.
- A reachable group keeps working across a wide-network partition.
- Bulk bytes need an explicit rule on a slow link.
- These bearers stay a target until x0x tests them.

## Considered Options

1. Add BLE, serial and radio stacks in x0x. Rejected. It duplicates A05.
2. Call the bearers shipped because David says ant-quic is ready. Rejected. This tree does not select, configure or test them.
3. Leave them unnamed. Rejected. Groups then have no slow-path rule.
4. Record them as an ant-quic target and state the group needs. Chosen.

## Decision

Bluetooth Low Energy (BLE), serial and radio are alternate bearers under ant-quic. x0x does not implement them in this record. David's readiness statement is a transport claim. This record does not audit ant-quic and does not change its pin.

When a bearer is in use:

1. The path must prove the expected peer identity. A radio neighbour gains no authority from the link.
2. Members who can reach each other keep the group state they already hold. Loss of the wider network is a partition.
3. The bearer must carry membership actions, messages and small shared-data deltas. Files, media and full state images are bulk. The group must be able to defer or refuse bulk when the path cannot carry it. This record sets no byte budget.
4. Public-group discovery may stop. Members who already hold the group do not need the directory to continue.
5. x0x must not add a BLE, serial or radio stack beside ant-quic.

This is a target. It starts no implementation slice.

## Consequences

### Positive

- The bearer rule matches partition-first operation.
- Bulk traffic is not assumed to fit a slow link.
- The transport boundary stays in ant-quic.

### Negative / Trade-offs

- Behaviour does not change until a later record names a tested bearer and a byte budget.

### Neutral / Operational

- Home, MLS and ShareGrant rules stay as they are. QUIC over IP remains the path this tree runs.

## Validation

Keep the mark at target until a test shows two peers exchange a group message and a small delta on one named bearer while the wide network is down, and shows bulk deferred or refused. A document that calls these bearers shipped in x0x fails the check.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
