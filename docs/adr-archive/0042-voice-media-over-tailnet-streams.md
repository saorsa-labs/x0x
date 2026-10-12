# ADR 0042: Voice Media over Tailnet Streams (`WebRtcV1`)

- **Status:** Accepted (2026-08-27)
- **Date:** 2026-08-27
- **Decision owners:** David Irvine (direction), omp (drafting), Claude (review)
- **Reviewers:** David Irvine (approved 2026-08-27)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0019, ADR-0020, ADR-0022 (stream API), ADR-0023 (Ephemeral class), ADR-0038 (Home); `src/streams.rs:381`, `src/voice/`, saorsa-webrtc 0.5.x

## Context

The `voice` feature shipped media adapters without a recorded ADR:
signaling over real DMs, Opus audio over ADR-0022 streams. Re-verified
2026-08-27: `StreamProtocol::WebRtcV1 = 0x04` at `src/streams.rs:381` with
the nesting documented on the enum, and `git log v0.39.3..HEAD` shows no
voice/webrtc/audio/datagram commits since v0.39.3 — the 2026-08-23 survey
(x0x-webrtc-20260823-report.md) still describes current behavior.

## Decision Drivers

- Media deserves the same gate posture as every other stream protocol.
- Reliable-only audio degrades under loss (head-of-line blocking).
- Browser WebRTC cannot speak the QUIC-native lanes directly.

## Decision

(a) **Ratify `WebRtcV1` 0x04 nesting as the permanent media protocol
byte.** The first app byte after the prefix is the saorsa-webrtc
`StreamType` (0x20–0x24: audio/video/screen/rtcp/data), then `u32`-BE
length ‖ payload; one x0x stream per (direction, lane). The identity gate
and connect-ACL pair gate apply exactly as for every other protocol —
there is no voice-specific bypass.
(b) **Signaling stays DM-borne** with the typed `x0x-voice-sig-v1\n`
prefix, classified Ephemeral — never recorded to history (ADR-0023
taxonomy).
(c) **Audio moves to the unreliable datagram lane** (ant-quic
`high_level::Connection` datagram API; Node/x0x adapter plumbing is the
follow-up) with the reliable stream as fallback; the jitter buffer stays
mandatory.
(d) **Groups: mesh ≤4** over the same lanes (N-way signaling + mesh lane
manager); an SFU for 5+ is deferred and requires its own ADR.
(e) **Browsers reach calls only via a daemon-side gateway** (WebRTC or
WebTransport ↔ WebRtcV1 bridge) — never raw lane access.

## Consequences

### Positive

- One gated stream namespace for all media; security is inherited from
  the existing gates rather than re-invented per protocol.
- Signaling leaves no history residue; calls are private by default.

### Negative / Trade-offs

- Datagram-lane plumbing must land before loss-tolerant audio is real;
  until then audio rides the reliable lane and degrades under loss.
- Browser support is a gateway project (2–4 wks+), not a config flag.

### Neutral / Operational

- Group mesh, SFU, gateway, and H264 (feature-gated pending licensing)
  are explicit follow-ups with effort estimates recorded in the survey.

## Validation

- Existing gates keep passing unchanged: `tests/voice_adapters.rs`
  (signaling over real DMs, lanes, ACL negative path) and
  `tests/voice_e2e.rs` (Opus pipeline, ≥99 % post-jitter, p95 < 100 ms).
- Datagram follow-up: loss-injection test ≥96 % frames delivered (the
  saorsa-webrtc `e2e_datagram_lane.rs` gate).
- Ratification check: `StreamProtocol::from_u8(0x04)` round-trips
  (`src/streams.rs:388-393`).

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
