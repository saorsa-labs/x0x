# T-alternate-bearers: Bluetooth, serial and radio through ant-quic

- **Status:** Accepted (David, D275, 14 Oct 2026, slot A05, PR #1405)
- **Target slot:** A05
- **Date:** 2026-10-13
- **Decision owners:** David Irvine (direction, 13 Oct 2026)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** A05; ADR 0006; product vision of 13 Oct 2026

## Context

On 13 Oct 2026 David said x0x is ready for Bluetooth, serial and radio, and that ant-quic is ready for these bearers.

ant-quic 0.27.60 (tag `v0.27.60`, commit `ea64efc5`) and master `4c5fde07` share these files. `src/transport/addr.rs` defines `TransportType` and `TransportAddr` for `Ble`, `LoRa`, `Serial`, `Ax25`, `I2p` and `Yggdrasil`, plus `LoRaParams`. `src/transport/capabilities.rs` defines `TransportCapabilities::ble`, `lora_long_range`, `lora_fast`, `serial_115200` and `packet_radio_1200`. Cargo feature `ble` (`ble = ["dep:btleplug"]`) compiles `src/transport/ble.rs`, where `BleTransport` implements `TransportProvider`. `src/transport/mod.rs` includes that module only under `feature = "ble"`.

x0x pins ant-quic 0.27.60 and does not enable `ble`. It matches `TransportAddr::Udp` on the live path and does not call `BleTransport`. `constrained_transport_ready_peer_is_retained_for_gossip` in `src/network.rs` only builds a `TransportAddr::Ble` value.

A05 keeps ant-quic as the transport boundary. A second bearer stack in x0x would split that boundary. ADR 0006 does not say a radio link can carry every object.

## Decision Drivers

- Bearers stay inside ant-quic.
- A link is not authority. Identity checks stay in x0x.
- Members who can reach each other keep held group state across a wide-network partition.
- Bulk bytes need an explicit rule on a slow link.
- x0x wiring stays a target until x0x tests a bearer.

## Considered Options

1. Add BLE, serial and radio stacks in x0x. Rejected. It duplicates A05.
2. Call the bearers shipped in x0x because the scaffolding exists. Rejected. This tree does not select or test them.
3. Leave them unnamed. Rejected. Groups then have no slow-path rule.
4. Record the ant-quic scaffolding and the x0x wiring target. Chosen.

## Decision

BLE, serial and radio are alternate bearers under ant-quic. The scaffolding above is in ant-quic 0.27.60. x0x does not call those modules. This record does not change the pin.

When a bearer is in use:

1. The path must prove the expected peer identity. A radio neighbour gains no authority from the link.
2. Members who can reach each other keep the group state they already hold.
3. The bearer must carry membership actions, messages and small shared-data deltas. Files, media and full state images are bulk. The group must be able to defer or refuse bulk. This record sets no byte budget.
4. Public-group discovery may stop. Members who already hold the group do not need the directory.
5. x0x must not add a BLE, serial or radio stack beside ant-quic.

Wiring into x0x is a target. This record starts no x0x slice.

## Consequences

The bearer rule matches partition-first operation. Bulk traffic is not assumed to fit a slow link. x0x behaviour stays on QUIC over IP until a later record names a tested bearer and a byte budget. Home, MLS and ShareGrant rules stay as they are.

## Validation

Keep the x0x mark at target until a test exchanges a group message and a small delta on one named bearer while the wide network is down, and defers or refuses bulk. Calling these bearers shipped in x0x fails the check. The ant-quic paths named above stay in this record.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
