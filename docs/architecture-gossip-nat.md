# x0x Gossip and NAT Traversal Architecture

## Network Topology

### First connection (no cached peers)

When an agent starts for the first time, it uses bootstrap nodes as seed hints
to enter the network. Bootstrap nodes provide coordination (NAT traversal),
reflection (external address discovery), and relay (fallback for symmetric NAT).

```
                         ┌─────────────────────────────────────────────┐
                         │         Bootstrap Nodes (seed hints)        │
                         │                                             │
                         │   ┌──────────┐         ┌──────────┐       │
                         │   │ Boot-1   │◄───────►│ Boot-2   │       │
                         │   └────┬─────┘         └────┬─────┘       │
                         │        │    ┌──────────┐    │             │
                         │        └───►│ Boot-3   │◄───┘             │
                         │             └────┬─────┘                   │
                         └──────────────────┼─────────────────────────┘
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    │                       │                       │
                    ▼                       ▼                       ▼
            ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
            │   Agent A    │       │   Agent B    │       │   Agent C   │
            │              │       │  behind NAT  │       │  behind NAT │
            └──────────────┘       └──────────────┘       └─────────────┘
```

Agents discover each other via gossip identity announcements propagated through
the bootstrap nodes, then auto-connect directly (ADR-0003). Once connected, they
cache each other's addresses in the bootstrap cache for future reconnection.

### Steady state (cached peers)

After initial discovery, agents maintain direct connections and cache peer
addresses. Bootstrap nodes are no longer needed — agents reconnect using cached
addresses. Any agent with a public IP can provide coordination/reflection for
others, consistent with ADR-0001 (bootstrap peers are seed hints only).

```
            ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
            │   Agent A    │       │   Agent B    │       │   Agent C   │
            │              │       │  behind NAT  │       │  behind NAT │
            └──────┬───────┘       └──────┬───────┘       └──────┬──────┘
                   │                      │                      │
                   │◄════════════════════►│                      │
                   │   direct QUIC        │                      │
                   │                      │                      │
                   │◄═══════════════════════════════════════════►│
                   │   direct QUIC        │                      │
                   │                      │                      │
                   │                      │◄════════════════════►│
                   │                      │  direct QUIC (hole   │
                   │                      │  punch coordinated   │
                   │                      │  by Agent A, which   │
                   │                      │  has a public IP)    │
```

In a production network with many agents, the bootstrap nodes handle only initial
entry. The gossip overlay (HyParView + PlumTree) maintains connectivity across the
full mesh, with each agent connected to a small subset of peers. The bootstrap
cache persists known peer addresses across restarts, so returning agents can
rejoin without contacting bootstrap nodes at all.

## Partition tolerance and data locality

This architecture is intentionally designed so that user/group data availability
follows **reachable peers**, not a globally healthy overlay.

- If Alice can still reach Bob, Alice↔Bob data should still work.
- If members of a group can still reach one another inside a partition, that
  group should still function inside the partition.
- Bootstrap loss or degraded discovery should reduce convenience, not erase
  already-held data.

This is why x0x does **not** treat a global DHT as the authoritative location for
user-to-user or group collaboration data. A DHT can place data on arbitrary nodes
outside the currently reachable partition, which means users might still be able
to reach their friends but lose access to their data because the storage/routing
layer is elsewhere.

x0x prefers the opposite tradeoff: keep data with the relevant peers and explicit
replicas, and accept that unreachable peers remain unreachable until connectivity
returns. If a path exists today — over QUIC in the current implementation, or via
future alternate bearers/bridges such as Bluetooth- or LoRa-style links — the
partition-tolerant data model still holds, without claiming those are all native
x0x transports today.

See also [ADR 0006](./adr/0006-no-global-dht-for-user-and-group-data.md).

**Key:**
- `◄════►` Direct agent-to-agent QUIC connections

## Connection Establishment Flow

```
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│  Local   │                    │Bootstrap │                    │  Cloud   │
│  Agent   │                    │  Mesh    │                    │  Agent   │
└────┬─────┘                    └────┬─────┘                    └────┬─────┘
     │                               │                               │
     │  1. Connect (outbound UDP)    │                               │
     │──────────────────────────────►│                               │
     │                               │                               │
     │  2. OBSERVED_ADDRESS          │                               │
     │◄──────────────────────────────│                               │
     │  (learn public IP:port)       │                               │
     │                               │                               │
     │  3. Identity announcement     │  3. Forward EAGER             │
     │  (gossip pub/sub)             │  (pass-through topic)         │
     │──────────────────────────────►│──────────────────────────────►│
     │                               │                               │
     │                               │  4. Cloud announcement        │
     │  4. Forward EAGER             │  (gossip pub/sub)             │
     │◄──────────────────────────────│◄──────────────────────────────│
     │                               │                               │
     │  5. Auto-connect: connect_addr(cloud_ip:port)                 │
     │══════════════════════════════════════════════════════════════►│
     │                               │                               │
     │  6. Direct gossip pub/sub     │                               │
     │◄════════════════════════════════════════════════════════════►│
     │                               │                               │
```

## Gossip Message Pipeline (per node)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ant-quic Transport                           │
│                                                                     │
│  send(peer, data)              recv() → (peer, data)                │
│  ┌─────────────┐              ┌─────────────┐                      │
│  │ open_uni()  │              │ accept_uni()│                      │
│  │ write_all() │              │ read_to_end │                      │
│  │ finish()    │              │ → data_tx   │                      │
│  └─────────────┘              └──────┬──────┘                      │
│        ▲                             │                              │
│        │                             ▼                              │
│  [1/6 network]                 [1/6 network]                       │
│  send: N bytes                 recv: N bytes                        │
│  to peer X                     from peer X                          │
└────────┬─────────────────────────────┬──────────────────────────────┘
         │                             │
         │                             ▼
         │                    ┌─────────────────┐
         │                    │  [2/6 runtime]  │
         │                    │  GossipRuntime  │
         │                    │  dispatch loop  │
         │                    │                 │
         │                    │  PubSub ──────► handle_incoming()
         │                    │  Membership ──► dispatch_message()
         │                    └────────┬────────┘
         │                             │
         │                             ▼
         │                    ┌─────────────────┐
         │                    │ [3/6 plumtree]  │
         │                    │ PlumtreePubSub  │
         │                    │                 │
         │                    │ handle_eager:   │
         │                    │  • verify sig   │
         │                    │  • dedup check  │
         │                    │  • deliver to   │
         │                    │    subscribers  │
         │                    │  • forward to   │
         │                    │    eager peers  │
         │                    └────────┬────────┘
         │                             │
         ▲                             ▼
┌────────┴────────┐           ┌─────────────────┐
│  publish_local  │           │ [4/6 pubsub]    │
│                 │           │ PubSubManager    │
│ encode v1/v2   │           │                 │
│ → PlumTree     │           │ decode payload  │
│ → send EAGER   │           │ verify sender   │
│   to eager     │           │ check trust     │
│   peers        │           │ → subscriber tx │
└─────────────────┘           └────────┬────────┘
                                       │
                                       ▼
                              ┌─────────────────┐
                              │ [5/6 x0xd]      │
                              │ Subscribe task   │
                              │                  │
                              │ recv from sub    │
                              │ → broadcast_tx   │
                              └────────┬─────────┘
                                       │
                                       ▼
                              ┌─────────────────┐
                              │ [6/6 x0xd]      │
                              │ SSE endpoint     │
                              │                  │
                              │ /events stream   │
                              │ → HTTP client    │
                              └──────────────────┘
```

## Background Tasks

```
┌─────────────────────────────────────────────────────────────┐
│                    GossipRuntime Tasks                       │
│                                                             │
│  ┌─────────────────────┐  ┌──────────────────────────────┐ │
│  │ Message Dispatcher  │  │ Topic Peer Refresh           │ │
│  │ (continuous)        │  │ (every 1s)                   │ │
│  │                     │  │                              │ │
│  │ receive_message()   │  │ connected_peers()            │ │
│  │ → dispatch to       │  │ → set_topic_peers() for:    │ │
│  │   PubSub or         │  │   • subscribed topics       │ │
│  │   Membership        │  │   • pass-through topics     │ │
│  └─────────────────────┘  │   (via all_topic_ids())     │ │
│                           │                              │ │
│  ┌─────────────────────┐  │ Promotes lazy → eager        │ │
│  │ Keepalive Pinger    │  │ Removes disconnected peers   │ │
│  │ (every 15s)         │  └──────────────────────────────┘ │
│  │                     │                                    │
│  │ connected_peers()   │  ┌──────────────────────────────┐ │
│  │ → SWIM Ping to      │  │ Identity Heartbeat           │ │
│  │   every peer        │  │ (every 30s)                  │ │
│  │                     │  │                              │ │
│  │ Prevents QUIC idle  │  │ announce_identity()          │ │
│  │ timeout (30s)       │  │ → publish to gossip          │ │
│  │ [ADR-0002]          │  │ → enables peer discovery     │ │
│  └─────────────────────┘  └──────────────────────────────┘ │
│                                                             │
│  ┌─────────────────────┐  ┌──────────────────────────────┐ │
│  │ PlumTree Cache      │  │ PlumTree Degree Maintainer   │ │
│  │ Cleaner (every 60s) │  │ (every 30s)                  │ │
│  │                     │  │                              │ │
│  │ Expires messages    │  │ Promotes lazy → eager if     │ │
│  │ older than 5 min    │  │ eager_count < 6              │ │
│  │ Cleans peer scores  │  │ Demotes eager → lazy if      │ │
│  │ older than 10 min   │  │ eager_count > 12             │ │
│  └─────────────────────┘  └──────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## PlumTree Peer Management

```
For each topic, PlumTree maintains two peer sets:

  EAGER peers: receive full messages immediately (spanning tree)
  LAZY peers:  receive only message IDs (IHAVE digests)

          set_topic_peers() runs every 1 second
          ┌─────────────────────────────────────┐
          │                                     │
          ▼                                     │
  ┌───────────────┐                    ┌────────┴───────┐
  │  EAGER peers  │───── PRUNE ──────►│  LAZY peers    │
  │               │  (duplicate msg    │                │
  │  Full EAGER   │   detected)        │  IHAVE digests │
  │  forwarding   │                    │  only          │
  │               │◄──── GRAFT ────────│                │
  │               │  (IWANT response   │                │
  └───────────────┘   needed)          └────────────────┘
          ▲                                     │
          │                                     │
          └─────── set_topic_peers() ───────────┘
                   promotes ALL lazy peers
                   back to eager (every 1s)

  This override ensures that PRUNE optimisations from message bursts
  don't permanently break gossip routing. The 1-second refresh is
  authoritative and restores full eager connectivity.
```

## NAT Traversal (ant-quic layer)

```
┌──────────────┐                              ┌──────────────┐
│  Local Agent │                              │  Bootstrap   │
│  (behind NAT)│                              │  (public IP) │
│              │                              │              │
│  Private:    │    Home Router               │              │
│  192.168.x.x │   ┌──────────┐              │              │
│  :random     ├───►│   NAT    │──────────────►  :5483     │
│              │    │          │  UDP outbound │              │
│              │    │ Maps:    │  always works │              │
│              │    │ priv:port│              │              │
│              │    │ → pub:port              │              │
│              │    └──────────┘              │              │
│              │                              │              │
│              │    OBSERVED_ADDRESS frame:    │              │
│              │◄─────────────────────────────│              │
│              │    "You are 80.46.x.x:pub"  │              │
│              │                              │              │
│  Learns:     │                              │              │
│  external_addr│                              │              │
│  nat_type    │                              │              │
└──────────────┘                              └──────────────┘

NAT types detected:
  FullCone         → Any external host can send to mapped port
  PortRestricted   → Only hosts we've sent to can reply
  Symmetric        → Different mapping per destination (hard)

For FullCone/PortRestricted (most home routers):
  Auto-connect works directly — cloud agent connects to
  the local agent's observed external address.

For Symmetric NAT:
  Hole punching via bootstrap coordination (PUNCH_ME_NOW)
  or MASQUE relay fallback through bootstrap nodes.
```
