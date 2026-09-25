# ADR 0073: Audio and Video Calling Ship Together via the Daemon-Side Browser Gateway

- **Status:** Proposed
- **Date:** 2026-09-25
- **Decision owners:** David Irvine (direction: voice and video ship together in the next
  milestone, 2026-09-25); Claude (drafting)
- **Reviewers:** cross-model (omp) review required; acceptance by David Irvine only
- **Supersedes:** none
- **Superseded by:** none
- **Extends:** ADR 0042 (does not edit it). It selects 0042 (e), the daemon-side browser
  gateway, as the only human media path and states the details 0042 left open. 0042 (a)–(c)
  stand unchanged. 0042 (d) group mesh stays deferred.
- **Vision requirement:** R8, "video/audio calling works" between humans, across their
  machines and NATs.
- **Related:** #892; ADR 0019, 0020, 0022 (stream gates, connect ACL), 0023 (Ephemeral
  class), 0044 (REST/WS/SSE control plane), 0052 (embedded GUI), 0056 (voice lane record),
  ADR 0070 / PR #896 (Proposed, `ShareGrant` caps); `src/voice/`, `src/streams.rs`

## Context

On `origin/main` today:

- **Voice exists only as a library.** `src/voice/` (about 1.8k LOC, feature `voice`, off by
  default) has adapters for saorsa-webrtc 0.6. `X0xSignaling` sends the
  `CapabilityExchange → ConnectionConfirm → ConnectionReady` handshake over DMs with the
  `x0x-voice-sig-v1` prefix. `X0xLinkTransport` carries media on `WebRtcV1` (0x04) lanes,
  plus the 0042 (c) datagram lane for audio. This is QUIC-native saorsa-webrtc, not
  browser WebRTC: there is no ICE, DTLS or SDP. The codec is Opus
  (`saorsa-webrtc-codecs` default features). The tests (`tests/voice_*.rs`, CI
  `voice-pipeline-acceptance`) feed synthetic PCM. x0x has no dependency that captures
  audio or plays it out.
- **Users cannot reach it.** `src/api/mod.rs` has no call routes. There is no `x0x call`
  command and no GUI call UI. The GUI still says calling comes "after v1.0". Release
  builds do not enable `voice`.
- **Video is absent.** Only the `StreamType::Video` (0x21) lane byte is reserved.
  `saorsa-webrtc-codecs` has an optional `h264` feature (openh264), which x0x does not
  enable. No crate in the dependency graph captures from a camera.
- The daemon has **no display surface**. Its only human UI is the browser GUI, served at
  `GET /gui` on loopback (ADR 0052).

## Decision Drivers

- R8 names video and audio together. A voice-only release does not meet it.
- Reuse what 0042 already ratified: `WebRtcV1` lanes, DM signaling, and no gate bypass.
- Video that is decoded somewhere must be shown to a human. The browser is the only
  display x0x has.
- Keep the daemon's binary size, platform-specific code and codec licensing exposure
  small.
- Camera and microphone permission prompts must work on macOS, Windows and Linux without
  a signed app bundle.

## Considered Options

1. **(A) The browser handles media, and x0x does signaling and transport (the 0042 (e)
   gateway).** The GUI captures with `getUserMedia` and opens an `RTCPeerConnection` to
   its **own local daemon** over loopback only. The daemon terminates the loopback leg
   and relays encoded RTP to the remote daemon over `WebRtcV1` lanes, without
   transcoding. The remote daemon hands the RTP to its own browser. In effect each
   daemon is a one-participant SFU whose far leg is an x0x lane. The browsers own
   capture, echo cancellation, encoding, the jitter buffer, rendering and permission
   prompts. No TURN or ICE is needed across the WAN, because ant-quic already provides
   the NAT-traversed path.
2. **(B) Native capture and encoding in the daemon.** This needs per-platform camera
   capture (AVFoundation, Media Foundation, V4L2/PipeWire) and microphone capture
   (cpal). It also needs a video encoder, either openh264 or libvpx, both C
   dependencies. The decoded frames would still have to reach a browser or a new native
   window to be seen.
3. **(C) Browser WebCodecs, with encoded frames sent to the daemon over `/ws` or
   WebTransport.** This avoids a WebRTC stack in the daemon. The cost is hand-written JS
   jitter buffering, A/V sync, playout and congestion control, and Safari's WebCodecs
   and WebTransport coverage is uncertain.

## Decision

We will ship **1:1 audio and video calling together via Option A**, as follows.

1. **Media path (Option A).** The daemon gains a loopback-only WebRTC endpoint that
   relays browser media. It uses ICE-lite with host candidates on `127.0.0.1`. SDP is
   exchanged over the authenticated control plane, not over DMs. The daemon offers only
   **Opus and VP8**. VP8 is royalty-free and mandatory-to-implement in browsers
   (RFC 7742). Pinning both ends to Opus and VP8 lets the daemons forward packets
   instead of transcoding. RTP packets ride `WebRtcV1` lanes: audio on 0x20 and video
   on 0x21, using the datagram lane when both sides advertise it and the reliable stream
   otherwise. RTCP (0x23) is relayed end to end, so the receiving browser's
   keyframe requests (PLI/FIR) and bandwidth feedback reach the sender. The payload
   contract for the video lane is specified in saorsa-webrtc by the implementing
   design, not here. The Rust WebRTC stack is chosen in that design. Candidates are
   str0m (sans-IO) and webrtc-rs. The selection criteria are binary size, the DTLS
   backend (no new OpenSSL runtime dependency), and forwarding/RTCP support.
   **Option B is rejected.** The daemon cannot show video. Capture code would be
   per-platform. H.264 via openh264 is only royalty-covered as Cisco's downloaded
   binary. A background daemon cannot reliably raise macOS camera or microphone
   permission (TCC) prompts. **Option C is rejected** because it re-implements in JS
   what the browser's WebRTC stack already does.
2. **Signaling reuses the voice DM channel.** Call lifecycle is added as additive
   `x0x_call_*` extension frames (invite, accept, reject, hangup, each carrying
   `call_id` and media kinds). They use the same mechanism as the existing datagram
   advert, keep the `x0x-voice-sig-v1` prefix, and stay Ephemeral under ADR 0023. The
   existing capability handshake is not changed.
3. **Shipping to users.**
   - The release workflow enables `voice` for `x0xd` and `x0x`.
   - REST routes are added to the shared registry: `POST /calls` (`agent_id`, `video`),
     `GET /calls`, `GET /calls/{id}`, `POST /calls/{id}/accept`, `.../reject`,
     `.../hangup`, and `POST /calls/{id}/media` (loopback SDP offer in, answer out).
   - Events `call.incoming` and `call.state` (`ringing`, `connecting`, `active`,
     `ended{reason}`) go on the existing `/events` SSE and `/ws` channels (ADR 0044).
   - CLI: `x0x call <agent> [--video]` and `x0x call list|accept|reject|hangup <id>`.
     The CLI controls the call lifecycle only; media plays in the GUI, whose URL the
     CLI prints.
   - The GUI gains a call button, an incoming-call ring, an in-call view (mute, camera
     off, hang up), and replaces the "after v1.0" copy. The `gui_coverage` gate
     (ADR 0052) applies.
   - Unanswered invites end as `missed` after 30 s.
4. **Access control, today.** A call invite rings only if the caller would pass the
   gates its media will hit: `stream_gate` must return `Accept` (not revoked, not
   expired, trust decision Accept), and the `stream_acl_gate` pair check must pass when
   the connect ACL is Enabled. Anything else is refused without ringing, counted, and
   emitted locally as `call.state{ended: refused}`. No bypass is added for media or
   signaling. The outbound side checks the callee against the same gates before
   inviting.
   **Dependency on ADR 0070.** If 0070 is accepted, a `Call` cap is added to
   `ShareCap`. A human who holds a live `ShareGrant` carrying `Call` may then ring the
   granted agents without being a Trusted contact, and 0070's owner-implicit trust
   lets a person's own devices call each other. This ADR does not redesign 0070. Until
   0070 is accepted, contact trust is the only way to be admitted.
5. **Scope.** The scope is 1:1 audio+video between humans in the GUI. Two things are
   **deferred**: 0042 (d) group calls (which need their own ADR), and screen share
   (0x22). Two more are **open**: native Rust agents interoperating with browser calls
   (see Validation Q2), and daemon-blind media via SFrame/insertable streams. Today the
   daemon sees plaintext media, just as it sees plaintext DMs.

## Consequences

### Positive

- R8 is met with video. No codec, capture or rendering code is added to the daemon, and
  there are no codec royalties.
- The browser supplies echo cancellation, noise suppression, jitter buffering and A/V
  sync, all well tested. The x0x lanes, gates and NAT traversal are reused unchanged.
- Permission prompts come from the browser, per origin, on every OS. The daemon never
  needs camera or microphone access.

### Negative / Trade-offs

- **Binary size.** The daemon gains a WebRTC stack (DTLS, SRTP, ICE-lite, RTP) plus
  libopus via `voice`. The size delta is **unknown until measured**. The implementing
  PR reports the `x0xd` delta per release target, and a delta over +5 MB needs David's
  sign-off.
- Calls need a GUI tab open to ring or to carry media. The CLI only controls the
  lifecycle, so a human with no GUI open misses the call.
- A relay-then-forward design means bandwidth estimation runs end to end through two
  daemons. Whether browser congestion control behaves well over ant-quic datagrams is
  **unproven**, and the acceptance test measures it.
- Browsers differ in their secure-context and permission rules for
  `http://127.0.0.1:<port>`. Named instances with ephemeral ports re-prompt for
  permission. Safari behaviour is **unverified**.

### Neutral / Operational

- CI gains a browser e2e job: headless Chromium with
  `--use-fake-device-for-media-stream` and two daemons, run through
  `scripts/dev/test-isolated.py`. The isolation launcher is Linux-only, so Safari and
  Firefox are covered only by manual acceptance.
- The `--all-features` jobs already compile `voice`. `release.yml` adds it to the
  shipped feature set.
- Peers that predate this ADR ignore `x0x_call_*` frames. That must be verified, because
  an older peer that errors on an unknown extension frame would break the voice channel.

## Validation

**Acceptance test `calling-r8-e2e`** (defined here, not run now):

- Setup: two physical machines on **different NATs**, neither of them a VPS, with at
  least one behind a home or CGNAT router. Both run the shipped release binaries.
  Chrome is on one machine and Safari or Firefox on the other. The two humans are
  mutual Trusted contacts.
- Pass requires all of:
  - (a) 10 of 10 calls connect;
  - (b) `POST /calls` to remote `call.incoming`: p95 ≤ 3 s;
  - (c) accept to the first decoded remote video frame (`getStats` `framesDecoded > 0`):
    p95 ≤ 5 s;
  - (d) over a 5-minute call, video ≥ 15 fps at ≥ 640×360 for ≥ 95 % of seconds,
    audio `concealedSamples / totalSamplesReceived` ≤ 2 %, and no drop;
  - (e) an Unknown-trust caller never rings (the refusal is counted);
  - (f) hangup reaches `ended` on both sides within 2 s.
- Evidence to record: per-call `getStats` dumps, daemon lane counters, the versions
  used, and the NAT types observed.

**Unit/integration:**

- The invite gate matrix mirrors `stream_gate_matrix`.
- A frame-compatibility test: an old peer plus `x0x_call_*` frames keeps the voice
  handshake working.
- An SDP test: the loopback answer contains only Opus and VP8.

**Review triggers:** a binary delta over +5 MB; test (d) failing due to congestion
behaviour; ADR 0070 being rejected or changing `ShareCap`.

**Open questions for David:**

- Q1: Is the WebRTC-stack choice (str0m or webrtc-rs) delegated to the implementing
  design?
- Q2: Must native `x0x::voice` agents talk to browser humans in this milestone? That
  needs the gateway to map RTP Opus to and from the `AudioDatagram` framing, without
  transcoding.
- Q3: Is the +5 MB budget right?
- Q4: Is the GUI-only media path acceptable, or is native CLI audio (cpal in the CLI
  process) required?

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
