# ADR-0020 mechanics — Tailnet Phase 1 options, tests, and Phase-2 deferrals

> Extracted 2026-08-29 from the immutable [ADR 0020](../adr/0020-tailnet-phase-1-byte-streams-and-forwarding.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the considered-options rationale, validation inventory, and Phase-2 deferral list
> relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

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

---

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

---

## Phase 2 deferrals (separate scoped issues, not built unprompted)

- Per-flow revocation teardown of long-lived streams.
- LAN / subnet-router / exit-node targets (non-loopback ACL grammar).
- Device enrollment UX with expiry-by-default.
- MagicDNS-style naming.
- SOCKS5 listener (T5) ship decision — protocol byte reserved.
