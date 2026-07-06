# ADR 0020: Tailnet Phase 1 — per-peer byte-streams + local port-forwarding

<!-- File name: docs/adr/0020-tailnet-phase-1-byte-streams-and-forwarding.md -->

- **Status:** Proposed
- **Date:** 2026-07-06
- **Decision owners:** David Irvine
- **Reviewers:** x0x core team (independent adversarial review required before Accepted)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #132 (T1–T8), ant-quic #180 (`Node::open_bi`/`accept_bi`), #130 (key lifecycle), #131/ADR-0019 (connect ACL), #158/#177 (PeerRelay), #179 (direct-DM revocation gate)

## Context

x0x v0.28.0 carries the two hardest Tailscale pieces in the transport — native
QUIC NAT traversal and an always-on symmetric MASQUE relay fallback — but above
the wire it spoke only message-level `Node::send`/`recv`. There was no way for a
user to reach a service on their other machine. ant-quic 0.27.28 (#180) shipped
`Node::open_bi(&peer)` / `Node::accept_bi()` — bidirectional, backpressure-correct
byte-streams, demultiplexed from internal transport by an `ANQAppB1` prefix so
`accept_bi` never yields an internal stream. This was the single blocker for the
whole sprint (#132); it is now cleared.

Phase 1 is the plumbing + product around those streams: a `PeerStream` API with
the identity gate inside open/accept, an `ssh -L`-style local port-forwarder
gated by the connect ACL (#131/ADR-0019) and the key lifecycle (#130), and a
REST/CLI surface. Tailscale-like reachability over any NAT, end-to-end
post-quantum (ML-KEM-768 / ML-DSA-65); relays forward ciphertext only.

## Decision Drivers

- **Default-closed, fail-closed everywhere.** A stream is only ever established
  between transport-verified, trust-accepted, non-revoked peers; an inbound
  forward only ever reaches a loopback target the connect ACL explicitly allows.
  This mirrors the project posture on revocation ("a valid revocation always
  fails closed") and the exec ACL.
- **Identity gate as an unavoidable chokepoint.** `NetworkNode::open_bi`/
  `accept_bi` are `pub(crate)` and reachable ONLY through `Agent::open_peer_stream`
  (outbound) and the Agent-owned accept loop (inbound). Both run the same
  `stream_gate` before any application byte. No bypass path.
- **Connect ACL is the second layer, not the first.** The T1 identity gate
  already ensured verified + trust + not-revoked; the T4 inbound forwarder then
  calls `evaluate_connect_gate(verified=true, trust=Accept, policy, …)` whose real
  job is the ACL target-match + loopback re-check. Two layers, fixed order.
- **Loopback-only in Phase 1.** Firewall-bypass risk, matcher complexity, and
  DNS rebinding all argue for numeric loopback IPs only — the same invariant
  ADR-0019 chose for the ACL loader, enforced again at the runtime seam.
- **Relayed parity.** `open_bi`/`accept_bi` are connection-agnostic, so streams
  work identically over direct and MASQUE-relayed connections. Phase 1 must prove
  the relayed forward on real NAT (loopback cannot force the relay path).

## Considered Options

1. **Streams + forwarder with the identity gate inside open/accept, connect ACL
   at the inbound accept seam, loopback-only** ← chosen.
2. **Gate at the forwarder only, raw streams unbypassable-by-convention.**
   Rejected: a convention is not a security boundary; the gate must be
   structurally unavoidable (sole caller of the stream primitives).
3. **Per-byte revocation on long-lived streams.** Rejected for Phase 1: a stream
   is a long-lived connection; the gate is per-accept (like a TCP accept). New
   streams from a revoked peer are refused; tearing down an already-accepted
   stream mid-flight on revocation is Phase-2 hardening (see Consequences).
4. **Hostname/DNS targets.** Rejected (ADR-0019): numeric-IP-only removes the
   resolver from the trusted computing base.
5. **SOCKS5 in Phase 1.** Deferred behind a default-off flag (0x02 protocol byte
   reserved); Phase 1 ships on the T4 forwarder alone.

## Decision

### Stream protocol namespace (`src/streams.rs`)

- `0x00` reserved (rejected as unknown); `0x01 = ForwardV1`; `0x02 = SocksV1`
  (reserved for T5). The first application byte on any stream is the protocol
  prefix; the accept loop validates it after the identity gate and resets
  unknown protocols.
- `PeerStream` wraps ant-quic's send (AsyncWrite) + recv (AsyncRead) halves with
  the peer `AgentId` + `MachineId` + protocol, fixed at open/accept.

### Identity gate — fail-closed, fixed order (T1)

Both `Agent::open_peer_stream` (outbound) and the inbound accept loop run
`streams::stream_gate` before any application byte:

1. **transport-verified** — ant-quic authenticates the machine at the QUIC/TLS
   layer; outbound additionally requires the AgentId→MachineId binding in the
   identity discovery cache (the same `verified` annotation the direct-DM path
   uses).
2. **not revoked** — agent OR machine in the local revocation set ⇒ `PeerRevoked`.
   Checked before trust so a revoked-but-trusted peer is refused without leaking
   its trust state.
3. **trust `Accept`** — `AcceptWithFlag`/`None`/`Reject*` all deny (mirrors exec
   + the connect gate).

A denial yields a typed `NetworkError` (`PeerNotVerified` / `PeerRevoked` /
`PeerTrustRejected`) and the stream is refused/reset with zero application bytes.

### Forwarder (`src/forward.rs`)

- **Outbound** (`forward add`): local loopback TCP listener → `open_peer_stream`
  → length-prefixed bincode `ForwardHeader{target_host,target_port}` → read the
  peer's response → `tokio::io::copy` both directions on connected.
- **Inbound** (security-critical): read header → resolve numeric loopback →
  `evaluate_connect_gate(true, Some(Accept), policy, agent, machine, target)`
  BEFORE any `TcpStream::connect`. On deny: typed `ConnectDenialReason` frame
  back + `ConnectDiagnostics::record_denied`, stream closed, zero bytes to
  target. On allow: re-check loopback (defense in depth) → connect (10s timeout)
  → bridge. `ConnectPolicy::Disabled` denies everything by default.

### #179 — direct-DM per-message revocation

The same verified/direct path the streams ride had a gap: the raw-QUIC direct
listener annotated `verified`/`trust` and delivered to subscribers WITHOUT
checking revocation, and EP5 (`evict_revoked_subject`) does not close the live
connection. #179 added a per-message revocation gate in the direct listener
mirroring EP3, so the inbound identity gate T1 relies on is sound.

## Consequences

### Positive

- **Reachability over any NAT**, PQC end-to-end, with relay parity — the product
  wedge WireGuard/Tailscale don't have.
- **Two fail-closed layers** (identity gate + connect ACL), structurally
  unavoidable, mirroring exec/revocation precedents.
- **Deterministic gate tests.** `stream_gate` (revoked/trust matrix) and
  `decide_inbound` (ACL matrix) are pure + unit-tested without a live QUIC pair.

### Negative / Trade-offs

- **No mid-stream revocation teardown (Phase 1).** A stream accepted just before
  a revocation stays open until it ends. Mitigations: the connect gate is
  per-accept (new flows refused); per-flow teardown is Phase-2 (tracked here).
- **Loopback-only.** No LAN/subnet/exit targets in Phase 1 (Phase 2).
- **Relayed forward needs real NAT to prove.** Loopback e2e proves the DIRECT
  path only; the relayed case runs on the VPS testnet (ant-quic cannot force the
  relay path on loopback).

### Neutral / Operational

- `StreamProtocol` is a u8 namespace; new protocols extend `from_u8`/`as_u8`.
- `/forwards` (add/list/rm), `/streams`, `/diagnostics/connect` (pre-existing) —
  bearer-authed. CLI: `x0x forward add|list|rm`, `x0x streams`.
- The shared endpoint registry (`src/api/mod.rs`) is intentionally not extended
  yet — its parity gate needs daemon-test markers per endpoint, which land with
  the T7 two-machine REST proof.

## Validation

- **T1 unit tests:** `stream_gate` matrix, protocol-prefix round-trip,
  reserved/unassigned-byte rejection. Integration: two-agent loopback 1 MiB echo
  both directions (`tests/tailnet_streams_integration.rs`, `#[ignore]`).
- **T4 unit tests:** header codec round-trip + truncated/oversize rejection,
  `resolve_loopback_target` (hostname/non-loopback refused), `decide_inbound`
  ACL matrix (disabled / unknown-pair / wrong-target / allow / non-loopback),
  response-frame shape.
- **T7 (real-NAT):** direct forward over the VPS testnet + relayed forward; the
  four negative security cases (deny-without-ACL, revoked/expired refused,
  non-loopback refused, unverified refused) enforced by the harness. Cannot run
  in-process; loopback proves the direct path only.

## Phase 2 deferrals (separate scoped issues, not built unprompted)

- Per-flow revocation teardown of long-lived streams.
- LAN / subnet-router / exit-node targets (non-loopback ACL grammar).
- Device enrollment UX with expiry-by-default.
- MagicDNS-style naming.
- SOCKS5 listener (T5) ship decision — protocol byte reserved.

## Notes for AI-assisted work

AI tools may draft this ADR but **must not mark it Accepted without human
review**. The security invariants here — gate inside open/accept as the sole
caller of the stream primitives, loopback-only, two fail-closed layers in fixed
order — must not be softened without a new ADR and adversarial review. The #179
direct-DM revocation gate and the T1/T4 gates must be verified against the REAL
merged code path, not a mirror test.
