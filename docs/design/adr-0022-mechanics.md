# ADR-0022 mechanics — Tailnet stream API validation inventory

> Extracted 2026-08-29 from the immutable [ADR 0022](../adr/0022-tailnet-stream-api.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the validation inventory and Phase 1 deferrals
> relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

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

---

## Phase 1 deferrals (unchanged from ADR-0020)

- SOCKS5 listener (protocol byte `0x02` reserved).
- Per-target / per-protocol ACL grammar at the stream layer; egress policy for outbound
  opens (option 4).
- Mid-stream revocation teardown of long-lived streams (per-accept gate only).
- LAN / subnet-router / exit-node (non-loopback) targets; device enrollment UX; MagicDNS.
