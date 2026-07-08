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
| `require_contact_to_relay` | `true` | `NotAContact` | Refuse to forward on behalf of any sender whose authenticated `sender_agent_id` is not in the local `ContactStore`. Set `false` only for an explicitly-open relay (e.g. a public DERP). |
| `max_forwards_per_sender` | `10` | `RateLimited` | Per-sender forward cap over `limit_window_ms`. |
| `max_total_forwards` | `100` | `RateLimited` | Global forward cap (all senders) over `limit_window_ms` — the concurrent-forward budget. |
| `max_forward_bytes_per_window` | `1048576` (~1 MiB) | `BandwidthExceeded` | Total forwarded bytes per window. |
| `limit_window_ms` | `60000` (60 s) | — | Sliding window for the three caps above. |

The contact gate applies **only to the forward arm** — a relayed DM addressed to
this node (`DeliverLocally`) is still received; receiving is not relaying. The
rate/bandwidth caps still apply when the contact gate is off, so an explicitly
open relay is never unbounded.

The listener resolves the contact membership from `ContactStore` (async) before
calling the sync `disposition_for`; the origin revocation gate (PR #177) still
runs after classification for both the deliver and forward arms.

### Observability

`RelayStatsSnapshot` exposes per-refusal-reason counters
(`relay_refused_not_a_contact`, `relay_refused_rate_limited`,
`relay_refused_bandwidth_exceeded`) plus `relay_forward_bytes` (total bytes
committed to forward) so operators can see and alert on refusals.
