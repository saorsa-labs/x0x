# Trust Model & Connectivity

Reference notes for `contacts.rs`, `trust.rs`, `connectivity.rs`, and the NAT
fields on `IdentityAnnouncement` / `DiscoveredAgent`.

## Trust Model (`contacts.rs`, `trust.rs`)

Each agent maintains a `ContactStore` of known peers with:

- `TrustLevel`: Blocked | Unknown | Known | Trusted
- `IdentityType`: Anonymous | Known | Trusted | Pinned
- `MachineRecord`: Tracks machine IDs an agent has been observed running on

`TrustEvaluator` evaluates `(AgentId, MachineId)` pairs against the store:
1. Blocked → `RejectBlocked`
2. `Pinned` identity type + wrong machine → `RejectMachineMismatch`
3. `Pinned` identity type + right machine → `Accept`
4. `TrustLevel::Trusted` → `Accept`
5. `TrustLevel::Known` → `AcceptWithFlag`
6. Not in store → `Unknown`

The identity listener applies trust evaluation to every incoming announcement. Blocked and machine-mismatched announcements are silently dropped.

## Connectivity (`connectivity.rs`)

`ReachabilityInfo` summarises how reachable a discovered agent is:
- `should_attempt_direct()`: true if we have at least one address AND `can_receive_direct` is not explicitly `false`. Unknown reachability still gets a direct probe.
- `needs_coordination()`: true if `can_receive_direct == Some(false)` (e.g. symmetric NAT)
- `likely_direct()`: true only when `can_receive_direct == Some(true)` — peer has verified direct inbound connectivity

`Agent::connect_to_agent(agent_id)` strategy:
1. Look up agent in discovery cache → `NotFound` if absent
2. No addresses → `Unreachable`
3. `should_attempt_direct()` → try `network.connect_addr()` for each address → `Direct(addr)` on success
4. `needs_coordination()` or direct failed → for each reachable coordinator peer: connect to coordinator, then use `network.connect_peer_via(peer_id, coordinator)` for peer-ID hole-punching (QUIC extension frames, PUNCH_ME_NOW) → `Coordinated(addr)` on success
5. All attempts failed → `Unreachable`

The coordination path uses explicit peer-ID-based NAT traversal via `connect_peer_via` (which calls `connect_to_peer(peer_id, Some(coordinator))`), not raw `connect_addr`. This triggers QUIC extension-frame hole-punching through the coordinator peer (typically a bootstrap node). MASQUE relay fallback is planned but not yet wired in ant-quic.

Successful connections enrich the bootstrap cache via `add_from_connection()`.

## Enhanced Announcements (`lib.rs`, `network.rs`)

`IdentityAnnouncement` and `DiscoveredAgent` carry four optional NAT fields:
- `nat_type: Option<String>` — e.g. "FullCone", "Symmetric", "None"
- `can_receive_direct: Option<bool>` — whether inbound connections are accepted
- `is_relay: Option<bool>` — whether the node is relaying for others
- `is_coordinator: Option<bool>` — whether the node is coordinating NAT punch timing

The sync `build_announcement()` leaves these as `None` (no network access). The async heartbeat queries `NetworkNode::node_status()` to populate them.

**Protocol note**: These fields use bincode 1.x serialization. Old→new messages will fail to decode because bincode 1.x treats every field as required. This is a deliberate protocol version bump.

## Peer Relay (`peer_relay.rs`, X0X-0070b + #193)

When a direct DM to peer `P` fails `fail_threshold` times within `fail_window`,
`P` is marked `needs_relay` and the sender wraps the (end-to-end encrypted,
origin-signed) `DmEnvelope` inside a `RelayedDm`. A relay candidate `R` verifies
the `RelayHeader` signature and forwards `inner` directly to `dst` — one hop
only, no re-wrapping.

**Default-off.** `enabled = false` ships in code; the relay path only engages
when a runtime explicitly opts in via `[peer_relay] enabled = true`.

### Forward-path hardening (#193)

Enabling the relay no longer opens an unbounded relay. The forward arm is
gated and bounded — all enforced in `PeerRelay::disposition_for`, fail-closed,
before any byte is forwarded:

| Knob (`[peer_relay]`) | Default | Refusal | Effect |
|---|---|---|---|
| `require_contact_to_relay` | `true` | `NotAContact` | Refuse to forward on behalf of any sender that is not an **explicitly-trusted** contact (`Known`/`Trusted`). A merely-discovered `Unknown` entry does **not** pass, so the gate means "my contacts", not "anyone I've seen". Set `false` only for an explicitly-open relay. |
| — (always on) | — | `Blocked` | A `Blocked` contact is refused on the forward arm **unconditionally** — even on an open relay and before rate/bandwidth caps. The operator's blocklist always wins. |
| `max_forwards_per_sender` | `10` | `RateLimited` | Per-sender forward cap over `limit_window_ms`. |
| `max_total_forwards` | `100` | `RateLimited` | Global forward cap (all senders) over `limit_window_ms` — the concurrent-forward budget. |
| `max_forward_bytes_per_window` | `1048576` (~1 MiB) | `BandwidthExceeded` | Total forwarded bytes per window. |
| `limit_window_ms` | `60000` (60 s) | — | Sliding window for the three caps above. |

The listener resolves the sender's trust level from `ContactStore` (async) per
relay frame and passes it to the sync `disposition_for`. Membership is
snapshotted per message: a contact removed/blocked mid-flight can have one
forward slip through before the next frame re-snapshots — acceptable, since the
inner `DmEnvelope` is end-to-end encrypted and origin-signed. The origin
revocation gate (PR #177) still runs after classification for both arms.

### `DeliverLocally` is not rate-limited

A relayed DM addressed to this node (`DeliverLocally`, i.e. `dst == local`) is
**receiving**, not relaying — it spends no uplink. It therefore intentionally
**bypasses** the contact gate, the Blocked gate, and all rate/bandwidth caps. It
still requires `enabled = true`, a valid `RelayHeader` signature, and freshness
(within `freshness` / clock-skew bounds), and the origin revocation gate still
applies. Inbound local-delivery is consequently **not** bounded by the knobs
above; operators who want to suppress a specific inbound sender should block or
revoke that agent.

### Observability

`RelayStatsSnapshot` exposes per-refusal-reason counters
(`relay_refused_not_a_contact`, `relay_refused_blocked`, `relay_refused_rate_limited`,
`relay_refused_bandwidth_exceeded`) plus `relay_forward_bytes` (total bytes
committed to forward) so operators can see and alert on refusals.

## Gossip-plane isolation (#206)

Co-located daemons (prod + testnet on one host) discovered each other via
ant-quic's first-party mDNS (`_ant-quic._udp.local.`, no namespace) and
auto-connected, regardless of `--no-hard-coded-bootstrap`. Every transport
connection became a gossip carrier — PlumTree eager sets are seeded from
the live connection table — so revocations and CRDT state crossed planes,
and the cross-plane peer persisted in each plane's bootstrap cache, making
the contamination survive restarts.

### The plane hello

`NetworkConfig.network_id = Some(id)` puts a node on a named gossip plane.
Every new connection (any source: mDNS auto-connect, bootstrap dial, cache
redial, inbound accept) then exchanges a one-frame plane hello
(`[0x20][len][plane_id]` on the gossip data channel; unknown to older
peers, who drop it harmlessly):

- **Matching plane** → the peer is *cleared* and becomes gossip-eligible.
- **Mismatched plane** → the peer is evicted from the bootstrap cache and
  disconnected with a `PolicyRejection` tombstone (never proactively
  redialed). Hard refusal.
- **No hello** (pre-#206 code, open-plane embedders) → the peer is held
  out of gossip sets for a 10 s legacy grace window, then admitted. This
  keeps rolling upgrades from partitioning the fleet; full isolation
  requires both sides on the new code.

Until cleared, a peer is excluded from eager sets, membership keepalives,
and CRDT sync targets, and its inbound gossip frames are dropped — the
handshake window carries no gossip in either direction. The DM bytes
(0x10/0x11) deliberately bypass the gate: direct messaging is
authenticated agent-to-agent traffic, and an agent deliberately bridging
planes is operator behaviour, not a discovery bug.

### Configuration

| TOML `network_id` | Effective plane |
|---|---|
| unset | `x0x.prod` (well-known default; prod, `x0xd-443`, and personal named instances all land here and keep meshing) |
| `""` (empty) | open — no isolation (embedders/legacy rigs that deliberately bridge) |
| any valid id | that plane, e.g. `"x0x.testnet"` |

Plane ids are ≤64 bytes of ASCII alphanumerics plus `.`, `-`, `_`
(`x0x::network::validate_plane_id`). The library default
(`NetworkConfig::default()`) is open; the daemon maps unset to
`x0x.prod`, so **planes are isolated by default once each declares its
id** — the co-located testnet needs one line in
`/etc/x0x/config-testnet.toml`:

```toml
network_id = "x0x.testnet"
```

The bootstrap peer cache is now strictly per-data-dir
(`<data_dir>/peers`); the former shared-default arm (the #189 shape) is
removed.

### Downstream (ant-quic) need

x0x cannot disable ant-quic's mDNS or set its namespace today:
`ant-quic` 0.27.33's `NodeConfig` (the API x0x uses) exposes no mDNS
knob — `MdnsConfig` (enabled / service / namespace / auto_connect) only
exists on `P2pConfig`, which `Node::with_config` fills with
`DiscoveryPolicy::current_default()` (mDNS on, `namespace: None`,
auto-connect on). The gossip-layer plane hello above is therefore the
enforcement point, and cross-plane mDNS auto-connects still happen and
are refused after one frame (small connect/refuse churn per mDNS
re-resolution). The proper downstream fix is a `NodeConfig` mDNS knob so
x0x can map `network_id` → mDNS namespace (cross-plane peers are then
never dial candidates at all) and/or disable mDNS entirely for
server-class daemons. Filed as a doc note here until an ant-quic release
ships the surface.
## Observed-Origin Token (issue #120, `connectivity.rs`, opt-in)

The transport already observes every connected peer's remote address (the same
live connection-table data `connected_peer_snapshot()` reads and
`add_from_connection()` enriches the bootstrap cache from). Issue #120 surfaces
that observation as a coarse, masked *origin token* on **point-to-point DM
surfaces only**:

```json
{ "observed_prefix": "203.0.113.0/24", "direct": true, "cgnat": false }
```

- `observed_prefix` — the observed IP with host bits zeroed at a fixed mask
  (`/24` IPv4, `/48` IPv6). Never a raw IP; no GeoIP; no new dependencies.
  Loopback/unspecified observations yield no token at all.
- `direct` — `false` marks a relayed observation (the connection is via a
  relay, per the transport's `TraversalMethod`).
- `cgnat` — the observed address is in the RFC 6598 range (100.64.0.0/10),
  reusing the existing `connectivity.rs` check.

**Default-off.** Set `observed_prefix_enabled = true` in the daemon TOML to
opt in (no CLI flag — same pattern as `[peer_relay]`). When disabled the
token is never computed and every surface is byte-identical to before.

**Surfaces** (each carries the token as an optional field, entirely absent —
not `null` — when disabled or unobserved):

- DM-receive WS (`/ws`, `/ws/direct`) and SSE (`/direct/events`)
  `direct_message` events, as `observed_origin` — populated only for
  messages that arrived over the live point-to-point transport connection
  (gossip-inbox, relay-injected, and loopback deliveries never carry it).
- Per-peer rows of `GET /diagnostics/dm`, as `observed_origin` (latest
  captured token per sender agent).

The token is **never gossiped, never announced, and never on `/peers`**: it
is populated only in the raw-QUIC DM receive path and serialized only on the
DM surfaces above.
