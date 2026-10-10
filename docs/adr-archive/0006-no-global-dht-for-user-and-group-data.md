# ADR 0006: No Global DHT Dependency for User and Group Data

- Status: Accepted
- Date: 2026-04-12

## Context

x0x is designed to remain useful under real-world network failures:
- regional internet outages;
- bootstrap-node outages;
- corporate/firewalled islands;
- LAN-only operation;
- split network partitions where one fragment cannot currently reach another.

For user-to-user and group collaboration, the most important question is not:

> "Is the whole global network up?"

It is:

> "Can the relevant peers still reach each other over *some* transport path?"

If Alice can still reach Bob, then Alice↔Bob direct data should remain available.
If members of a group can still reach one another inside a partition, the group's data should remain available inside that partition.

That is fundamentally different from storing user/group state in a global DHT or any other system that assumes a single, healthy, globally connected overlay.

A DHT is useful for some structured-routing problems, but it creates the wrong failure model for x0x user/group data:
- data may end up placed on arbitrary nodes unrelated to the people who care about it;
- a partition can separate users from the nodes holding their data even when the users can still reach each other;
- loss of the global overlay can become loss of application data availability;
- correctness starts depending on network-wide routing-table health rather than on peer reachability.

For x0x, that tradeoff is unacceptable.

x0x is local-first and relationship-oriented:
- direct user data belongs with the participating peers;
- group data belongs with group members and explicitly chosen replicas;
- discovery can degrade without destroying already-held data;
- partitions should isolate *unreachable* peers, not erase data for peers who can still connect.

## Decision

x0x SHALL NOT require a global DHT, global routing table, or globally healthy overlay for correctness or availability of user-to-user or group data.

Instead:

1. **User-to-user data** MUST remain available whenever the relevant peers can still communicate over any viable path.
2. **Group data** MUST remain available within any partition where enough relevant members or explicit replicas remain reachable.
3. **Discovery and coordination** MAY use gossip, caches, shard indexes, or seed hints, but loss of those mechanisms MUST degrade discovery convenience rather than invalidate already-held user/group data.
4. **Data placement** for user/group collaboration MUST prefer participants and explicitly chosen replicas over arbitrary global storage nodes.
5. **Network partitions** MUST be treated as normal operating conditions, not exceptional correctness failures.
6. **Global unreachability** of some peers MUST NOT be described as data loss if the data remains available within the currently connected partition.

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

## Consequences

### Positive

- Aligns x0x's failure model with what users actually care about: reachable peers and reachable groups.
- Makes bootstrap/discovery outages survivable.
- Preserves usefulness on LANs, isolated meshes, and fragmented networks.
- Avoids coupling user/group data correctness to global routing-table health.
- Matches the named-group design direction: gossip discovery, participant-held data, partition-local convergence.

### Negative

- No guarantee of access to data whose holders are all unreachable.
- Discovery indexes and shard caches still need careful design for convergence and privacy.
- Group replication policy matters more, because availability comes from members/replicas rather than arbitrary network-wide placement.
- Some large-scale search/discovery features become eventually consistent and partition-local rather than globally exact.

## Non-goals

- This ADR does not ban DHT-style mechanisms for other systems built *on top of* x0x.
- This ADR does not prohibit structured indexes for discovery.
- This ADR does not require every node to store every group's data.
- This ADR does not claim support for every possible transport bearer today.

## Required follow-up work

1. Keep documentation clear that bootstrap peers are seed hints and discovery aids, not data custodians.
2. Keep named-group discovery DHT-free and partition-tolerant.
3. Ensure user/group data replication semantics are defined in terms of participants and explicit replicas.
4. Ensure README and overview docs explain the difference between:
   - discovery degradation; and
   - actual data unavailability.
5. When adding future transports or constrained bearers, preserve this same partition-tolerant data model.

## Acceptance criteria

This ADR is satisfied only when all of the following are true:

- x0x documentation explicitly states that user/group data does not depend on a global DHT being healthy;
- bootstrap/discovery failure is described as degraded discovery, not automatic data loss;
- named-group architecture continues to prefer participant-held / explicitly replicated data over arbitrary global placement;
- a network partition that still allows peers or group members to connect inside a fragment is treated as a valid operating mode;
- the product does not claim availability for data whose holders are all unreachable.
