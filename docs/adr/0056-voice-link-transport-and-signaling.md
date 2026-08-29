# ADR 0056: Voice Link Transport and Signaling (Historical Record; Media Ratified by ADR-0042)

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** **ADR-0042** (ratifies the `WebRtcV1` media nesting and DM signaling this record predates); ADR-0019/0020/0022 (gates and streams). Backfill: historical record of the shipped design ADR-0042 later ratified.

## Context

Voice shipped as adapters without a design ADR — ADR-0042's own Context
says the "voice feature shipped media adapters without a recorded ADR"
(`docs/adr/0042-voice-media-over-tailnet-streams.md:11-15`). This record
fills that gap for the two layers under ADR-0042's decision:
`src/voice/link_transport.rs` (media lanes) and `src/voice/signaling.rs`
(call setup).

## Decision Drivers

- Media framing must sit inside the standard gated stream machinery — no
  voice-specific bypass.
- Signaling must reach peers regardless of connectivity, leaving no
  history residue.
- Loss-tolerant audio needs an unreliable lane with a safe fallback.

## Considered Options

1. Standalone RTP/ICE stack outside x0x streams.
2. Everything over one reliable stream.
3. WebRtcV1 nesting over ADR-0022 streams + DM-borne signaling (chosen; ratified by ADR-0042).

## Decision (historical, as shipped)

1. Media lanes use `StreamProtocol::WebRtcV1 = 0x04`
   (`src/streams.rs:377-384`); inside that prefix the link transport owns
   the first application byte (saorsa-webrtc `StreamType` 0x20–0x24) and
   repeated `u32`-BE length ‖ payload frames (`src/voice/link_transport.rs:1-12,382-414,773-829`), one stream per
   (direction, lane) (`start_lane`, `src/voice/link_transport.rs:335-360`).
   Identity/trust/revocation/ACL gates apply with no voice bypass (`src/voice/link_transport.rs:20-31`).
2. Audio may use the unreliable datagram lane when both peers advertise
   `x0x_datagram_cap` (old peers simply don't advertise,
   `src/voice/link_transport.rs:60-71`); one encoded frame per datagram,
   with immediate reliable-stream fallback on failure
   (`src/voice/link_transport.rs:835-875,1010-1025`). (ADR-0042
   documented this as follow-up; it is now implemented conservatively — mutual advert/proof required.)
3. Signaling is DM-borne, not stream-nested: a three-message setup flow
   `CapabilityExchange → ConnectionConfirm → ConnectionReady` over
   signed/sealed gated DMs (`src/voice/signaling.rs:1-8`) with the typed
   `x0x-voice-sig-v1\n` prefix (`src/voice/signaling.rs:133-148`); unknown extension frames are silently skipped
   (`src/voice/signaling.rs:64-102`). Endpoint discovery returns `None` —
   ant-quic owns traversal/addressing (`src/voice/signaling.rs:153-162`).

## Consequences

### Positive

- Voice inherits the full gate stack; calls work behind NAT via DM
  signaling; loss-tolerant audio without abandoning the reliable lane.

### Negative / Trade-offs

- ADR-0042's SFU/mesh>4 and browser-gateway deferrals stand.

### Neutral / Operational

- Adapter labels "V1.2" (transport) and "V1.1" (signaling header) are
  independent version labels — do not conflate.

## Validation

- `tests/voice_adapters.rs` and `tests/voice_e2e.rs` (per ADR-0042
  Validation); datagram loss-injection gate ≥96% frames.

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
