# ADR 0022: Tailnet stream API — per-protocol acceptors, connect-ACL gate, bounded backpressure

<!-- File name: docs/adr/0022-tailnet-stream-api.md -->

- **Status:** Proposed — implementation landed and verified against code (2026-07-19); awaiting human acceptance review
- **Date:** 2026-07-17
- **Decision owners:** David Irvine
- **Reviewers:** x0x core team (independent adversarial review required before Accepted)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0020 (tailnet Phase 1 epic), ADR-0019 (connect ACL), issue #132 (deliverable 1), #131 (connect ACL), #192 (multi-agent fail-closed), ant-quic #180 (`Node::open_bi`/`accept_bi`)

## Context

ADR-0020 shipped the first tailnet byte-stream slice (#132 T1): `Agent::open_peer_stream` /
`Agent::next_incoming_stream` over ant-quic `open_bi`/`accept_bi`, a single-byte protocol
prefix for stream typing, and the fail-closed identity gate (verified → revoked → trust
`Accept`). That left three foundational gaps for everything else the epic builds on top
(port-forwarder T4, SOCKS5 T5, and any future protocol):

1. **One undifferentiated inbound channel.** Every protocol's streams landed in a single
   bounded channel drained by `next_incoming_stream`; the consumer had to demux by
   `stream.protocol()` and *drop* protocols it did not own. Two independent consumers
   (e.g. forwarder + SOCKS5 listener) could not coexist without an extra in-process demux
   layer — and a consumer ignoring a protocol silently absorbed its streams.
2. **No connect-ACL hook at the stream layer.** The #131 per-flow connectivity ACL only
   ran inside the T4 forwarder, after the forward header was read. A verified + trusted
   but ACL-unlisted peer could open arbitrary streams to any future protocol listener and
   only be refused later, per-protocol, if that protocol remembered to gate.
3. **Backpressure claimed, not proven.** QUIC-native flow control bounds in-flight bytes,
   and the surfacing channel was bounded — but nothing pinned those bounds to observable
   test assertions.

This ADR records the as-built design that closes those gaps (issue #132, deliverable 1).

## Decision Drivers

- **Default-closed, fail-closed.** Streams only flow between transport-verified,
  trust-accepted, non-revoked peers; with an `Enabled` connect ACL, an unlisted peer's
  stream open is refused. Mirrors the project posture (ADR-0019, exec ACL, EP3/EP4).
- **No second convention.** One routing mechanism for inbound streams — the protocol
  byte — used by every consumer, not a per-consumer filter layered on a shared queue.
- **Backpressure must propagate, never hide.** Bounded channels everywhere; a stalled
  consumer causes streams to be *reset*, not buffered; byte flow rides QUIC flow control.
- **Deterministic, network-free unit tests** for every gate decision, plus in-process
  two-agent integration proofs for the wiring.

## Considered Options

1. **Per-protocol acceptors + stream-layer ACL pair gate (chosen).** The accept loop
   routes each gated stream by its protocol byte to the single registered acceptor for
   that protocol (bounded channel, drop-on-full); unregistered protocols fall back to the
   existing default channel. The accept loop also evaluates a new pure gate,
   `stream_acl_gate`, after the identity gate: with `ConnectPolicy::Enabled`, every
   announced agent on the peer machine must be `(AgentId, MachineId)`-listed, else the
   stream is reset (`PeerNotInConnectAcl`) with zero application bytes exchanged.
2. **Keep the single channel, add per-consumer filters.** Rejected: every consumer must
   then correctly drop foreign protocols (a convention, not a boundary), a forgotten
   filter stalls or absorbs traffic, and boundedness reasoning gets harder per added
   consumer.
3. **Push the ACL check into each protocol handler (like T4 does today).** Rejected as
   the *only* layer: it duplicates the gate per protocol and invites a future protocol to
   skip it. (It remains correct as an *additional*, target-aware layer — the forwarder
   keeps its `evaluate_connect_gate` target check.)
4. **Apply the connect ACL to outbound opens too.** Rejected for Phase 1: the #131 ACL
   models *inbound* reachability ("who may connect to my loopback targets"). Outbound
   opens are already verified + trust-gated; reusing the inbound ACL outbound would
   conflate two policy directions. A dedicated egress policy is a Phase 2 question.

## Decision

### Per-protocol acceptor routing (`src/streams.rs`, `src/lib.rs`)

- `Agent::register_stream_acceptor(protocol) -> NetworkResult<StreamAcceptor>` installs
  the **single** consumer for a `StreamProtocol`. Duplicate registration fails with
  `NetworkError::StreamAcceptorConflict`. Dropping the `StreamAcceptor` deregisters it
  (guard compares channel identity so a stale drop cannot clobber a re-registered
  successor).
- The accept loop's per-stream dispatch task routes by the protocol byte **at dispatch
  time** to the registered acceptor, else to the default channel drained by
  `Agent::next_incoming_stream` (unchanged for unregistered protocols).
- Every channel is bounded (`STREAM_ACCEPTOR_CAPACITY = 64` per acceptor; 256 for the
  default sink) and written with `try_send`: a full channel drops (resets) the stream.
  Accepted streams are never buffered unboundedly.
- `ForwardService` is the flagship consumer: it registers `ForwardV1` + `ForwardV2`
  acceptors at construction (`ForwardService::new` now returns `NetworkResult<Self>` so a
  registration conflict is visible), and `spawn_inbound` runs one drain loop per acceptor.
  The old "consume the shared channel and filter by protocol" code is deleted.

### Connect-ACL gate at the stream layer (#131 × #132)

- `Agent::set_connect_policy(Arc<ConnectPolicy>)` installs the loaded policy (the daemon
  calls it once at startup; default is `Disabled`).
- The inbound accept loop evaluates `stream_acl_gate(policy, agents, machine_id)` **after
  the identity gate** (so unverified/untrusted peers learn nothing about the ACL):
  - `Disabled` ⇒ no constraint (backwards-compatible; the identity gate remains the sole
    stream boundary, and connect-forwarding stays default-deny at the T4 forwarder).
  - `Enabled` ⇒ **every** announced agent on the peer machine must be pair-listed, else
    `PeerNotInConnectAcl` and the stream is reset. The every-agent rule mirrors
    `forward::decide_inbound` (#192): the QUIC transport authenticates the machine, not
    the individual agent.
  - Target membership is *not* checked here — raw streams carry no target. Per-target
    enforcement stays with the forwarder's `evaluate_connect_gate` call.
- Outbound `open_peer_stream` is unchanged (identity gate only; see option 4).

### Backpressure contract

- Byte flow: QUIC-native flow control. ant-quic's initial per-stream credit is
  1 250 000 bytes (`STREAM_RWND`); a writer whose peer stops reading throttles there —
  it neither completes nor buffers beyond the window (+ in-flight slack).
- Surfacing: bounded channels with drop-on-full at every hop (ant-quic's app-stream
  queue, the x0x default sink, each acceptor).
- Copy loops (`tokio::io::copy` in the forwarder) carry no intermediate buffers beyond
  their fixed 8 KiB user-space chunk; backpressure propagates end to end.

## Consequences

### Positive

- Multiple independent protocol consumers coexist with no in-process demux layer and no
  cross-protocol absorption: each owns exactly its protocol's streams.
- An ACL-unlisted peer's stream open is refused at one unavoidable seam (the accept
  loop), protecting every current *and future* protocol — a protocol can no longer forget
  to gate.
- `PeerNotInConnectAcl` / `StreamAcceptorConflict` are typed errors: testable, loggable,
  no stringly-typed matches.
- Boundedness is asserted, not assumed: the acceptor channel depth is pinned to exactly
  `STREAM_ACCEPTOR_CAPACITY` under surplus, and a stalled reader provably throttles the
  writer at the flow-control window.

### Negative / Trade-offs

- `ForwardService::new` changed signature (`Self` → `NetworkResult<Self>`) — acceptable:
  the only constructor caller is the daemon wiring.
- A consumer that registers an acceptor and stops draining now causes *resets* of new
  streams rather than queueing them — intended (fail-fast, bounded memory), but operators
  should know a wedged listener manifests as refused streams, not backlog.
- The ACL gate checks pair membership, not targets: an `(agent, machine)` listed for one
  loopback target may open raw streams for any protocol. Rationale: streams have no
  target semantics; the forwarder still enforces targets per flow. Documented here so the
  relaxation is explicit.
- Registration/deregistration uses a `std::sync::Mutex` in the accept-loop dispatch path
  (route lookup per stream). Critical sections are a few pointer copies and never await —
  negligible, but noted.

### Neutral / Operational

- `Agent::next_incoming_stream` remains for protocols with no registered acceptor; the
  existing T1 echo + no-stall integration tests run unchanged against it.
- Deny telemetry: the accept loop logs `outcome = "deny_acl"` with machine + agent count
  (no ACL contents) at `info`, matching the existing `deny_gate`/`deny_protocol` lines.

## Validation

- **Unit (`src/streams.rs`)**: `stream_acl_gate_matrix` (Disabled pass-through, listed,
  unlisted, multi-agent fail-closed, wrong-machine); `acceptor_registration_lifecycle`
  (conflict, drop-reregister, stale-drop guard, routing fallback, bounded capacity).
- **Integration (`tests/tailnet_streams_integration.rs`, `#[ignore]` integration tier)**:
  - `peer_stream_echoes_1mib_both_directions` (pre-existing): open/echo round trip.
  - `multiplexed_protocols_do_not_interleave`: two protocols over one connection, each
    acceptor gets only its own stream, default sink stays empty, 1 MiB patterns intact.
  - `connect_acl_refuses_unlisted_peer_stream`: unlisted (but verified + trusted) peer's
    stream is never surfaced and its I/O fails (EOF + STOP_SENDING); the listed peer
    still streams.
  - `acceptor_channel_is_bounded`: capacity+8 opens surface exactly the capacity; no
    queued surplus afterwards.
  - `backpressure_throttles_writer_with_bounded_buffering`: 3 s stalled reader ⇒ writer
    incomplete **and** ≤ 8 MiB accepted (flow-control bound); drain ⇒ 32 MiB SHA-256
    intact.
  - `large_transfer_integrity_8mib`: 8 MiB pattern each direction, SHA-256 verified.
  - `accept_loop_not_stalled_by_missing_prefix` (pre-existing): accept-loop liveness.

## Phase 1 deferrals (unchanged from ADR-0020)

- SOCKS5 listener (protocol byte `0x02` reserved).
- Per-target / per-protocol ACL grammar at the stream layer; egress policy for outbound
  opens (option 4).
- Mid-stream revocation teardown of long-lived streams (per-accept gate only).
- LAN / subnet-router / exit-node (non-loopback) targets; device enrollment UX; MagicDNS.

## Notes for AI-assisted work

AI tools may draft this ADR but **must not mark it Accepted without human review**. The
security invariants — gate order (identity gate, then ACL gate, then protocol handshake,
then routing), every-agent fail-closed for multi-agent machines, bounded-or-reset
buffering — must not be softened without a new ADR and adversarial review.
