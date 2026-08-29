# ADR-0006 mechanics — Partition tolerance in practice

> Extracted 2026-08-29 from the immutable [ADR 0006](../adr/0006-no-global-dht-for-user-and-group-data.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the practical guidance, required follow-up work, and acceptance
> criteria relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

## What this means in practice

### Partition tolerance is path-based

If two users can still reach each other, their data should still work.
If a group's members can still reach each other inside a partition, the group's data should still work inside that partition.

That remains true even if:
- the public bootstrap mesh is unavailable;
- one continent cannot reach another;
- the internet is partially down;
- connectivity falls back to smaller scopes such as LAN or any future alternate bearer.

Today x0x's production transport is QUIC over `ant-quic`. The architectural principle is transport-agnostic: if a viable path exists, the data model should continue to function within that partition. The same reasoning applies to future alternate bearers or bridges as well — for example Bluetooth- or LoRa-style connectivity — without claiming those are all first-class transports today.

### Discovery is not the same as data custody

x0x may use gossip, shard subscriptions, local caches, and social propagation to help peers find each other and find groups.

But those mechanisms are **discovery aids**, not the authoritative storage location for user/group data.

If discovery is degraded, already-connected peers and already-replicated group members should still have their data.

### Unreachable peers remain unreachable

This ADR does **not** claim magical availability.

If the only people holding some data are on the other side of a partition and no path exists to them, that data is temporarily unavailable until connectivity returns.

That is acceptable and honest.

What x0x rejects is a design where:
- users can still reach their friends or group peers,
- but the application data is gone anyway because it was placed on arbitrary DHT nodes outside the partition.

---

## Required follow-up work

1. Keep documentation clear that bootstrap peers are seed hints and discovery aids, not data custodians.
2. Keep named-group discovery DHT-free and partition-tolerant.
3. Ensure user/group data replication semantics are defined in terms of participants and explicit replicas.
4. Ensure README and overview docs explain the difference between:
   - discovery degradation; and
   - actual data unavailability.
5. When adding future transports or constrained bearers, preserve this same partition-tolerant data model.

---

## Acceptance criteria

This ADR is satisfied only when all of the following are true:

- x0x documentation explicitly states that user/group data does not depend on a global DHT being healthy;
- bootstrap/discovery failure is described as degraded discovery, not automatic data loss;
- named-group architecture continues to prefer participant-held / explicitly replicated data over arbitrary global placement;
- a network partition that still allows peers or group members to connect inside a fragment is treated as a valid operating mode;
- the product does not claim availability for data whose holders are all unreachable.
