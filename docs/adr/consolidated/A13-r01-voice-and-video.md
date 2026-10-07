# A13 Voice and Video

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

x0x will use its identities, permissions and connectivity for voice and video between people and agents. Media delivery has different timing needs from durable work messages.

## Context

The repository contains voice library work and an experimental call-signaling lifecycle. Release builds do not provide a complete voice/video calling product. The current scope decision parks further media work.

## Decision

We retain voice and video in the product direction, with the existing parked priority. Security and bug fixes to shipped code can continue under the normal rules.

When media work resumes, separate the call control path from the media path.

Call control identifies participants, invitations, acceptance, refusal and termination. It uses authenticated identities and the relevant group or direct-call permissions.

The media path carries time-sensitive frames. It must support bounded latency, loss handling and congestion control. It must not place each media frame into the durable agent inbox.

## Permission and privacy

A participant must authorize microphone, camera or screen capture through the application and operating-system controls. An agent message is not permission to activate capture.

The interface must make active capture visible. End capture when the authorized call ends or the applicable permission is revoked.

Use end-to-end content encryption where the call requires private media. A transport-encrypted link to a forwarding server alone does not establish end-to-end media confidentiality.

For group calls, the key policy must follow participant changes. [A09](A09-r01-group-encryption-and-key-changes.md) owns membership-related key exclusion. The media design must state which metadata remains visible to forwarding infrastructure.

Recording and retention require a separate application policy. A call does not imply permission to retain a transcript or media recording indefinitely.

## Transport and browser support

Retain the existing QUIC-native work as a possible transport path. Browser support requires a tested browser-compatible media integration.

Small peer meshes and a selective forwarding unit have different bandwidth and infrastructure costs. The supported participant count and topology must be explicit.

If a forwarding unit is used, assess SFrame or an equivalent reviewed content-encryption scheme. Media over QUIC remains an evolving standard; a draft protocol must be identified by its exact version.

Do not claim that a signaling route proves audio or video is flowing. Report signaling state and media readiness separately.

## Consequences

The product retains a route to voice and video without changing the current priority. Media work will require platform, privacy and network tests. A forwarding service adds operating cost and metadata exposure.

## Alternatives

A full peer mesh is simple for small calls but can make each endpoint send several copies.

A forwarding unit can reduce endpoint upload cost, but adds infrastructure and metadata exposure.

Reliable streams can simplify delivery but can delay fresh media behind lost data. An unreliable lane needs its own recovery and quality policy.

## Current implementation

Some two-party voice work exists behind the voice feature. The call API is experimental. Multi-party media and browser integration remain future work under the current park.

A fresh ADR must not turn those targets into a release claim.

## Validation

Test real audio and video between supported applications. Cover packet loss, constrained upload, relay paths, device changes and participant removal.

Measure call setup, latency, quality and resource use. Confirm capture stops correctly and removed participants lose future protected media access.

## Matters to settle

David must explicitly change the current priority before new media implementation starts. Then select the first supported platforms, codecs, topology and participant limit.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0042 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0042-voice-media-over-tailnet-streams.md) · [ADR 0056 Superseded](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0056-voice-link-transport-and-signaling.md) · [ADR 0073 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0073-audio-and-video-calling.md)

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
