# ACK-v2 vs IETF ACK Frequency

Status: X0X-0044 decision spike
Date: 2026-05-09
Recommendation: hybrid, not replacement

## Decision

Do not replace ant-quic ACK-v2 with IETF ACK_FREQUENCY / IMMEDIATE_ACK.

Keep ACK-v2 as the correctness surface for `P2pEndpoint::send_with_receive_ack`.
Use IETF ACK Frequency only as a transport-level latency and ACK-rate control
mechanism around selected QUIC packets, if a later implementation ticket shows
that doing so improves tail latency without raising return-path pressure.

The reason is simple: these mechanisms acknowledge different things.

ACK-v2 is an application/endpoint receive-pipeline protocol. It says that the
remote ant-quic reader decoded the B3 envelope, admitted the payload to the
receive path, and returned an explicit `Accepted`, `Rejected(reason)`, or
`Closed(reason)` result. It also carries a 16-byte request id and has receiver
side dedupe, so a timeout retry can be duplicate-safe.

IETF ACK_FREQUENCY and IMMEDIATE_ACK are QUIC transport controls. They affect
when a peer sends QUIC ACK frames for packets. A fast QUIC ACK can speed loss
detection, RTT sampling, and PTO recovery, but it cannot prove that stream data
was drained by ant-quic's reader task, admitted past backpressure, or accepted by
the endpoint receive path.

## Local State

Relevant ant-quic code, as of ant-quic `v0.27.14`:

- `ant-quic/src/ack_frame.rs` defines ACK-v2 envelopes:
  `ANQAckB3` request, 16-byte request id, `ANQAckR2` response, and
  `AckControlOutcome`.
- `ant-quic/src/p2p_endpoint.rs` uses that request id in
  `AckRequestDedupeCache` and documents `send_with_receive_ack` as success only
  after the remote reader decoded and enqueued the payload.
- `ant-quic/src/frame.rs` already has `ACK_FREQUENCY = 0xaf` and
  `IMMEDIATE_ACK = 0x1f`.
- `ant-quic/src/config/transport.rs` has `AckFrequencyConfig`, but
  `TransportConfig` defaults `ack_frequency_config` to `None`.
- `ant-quic/src/transport_parameters.rs` advertises `min_ack_delay` using
  `0xFF04DE1B`, so peers can discover support for the ACK Frequency extension.

One local mismatch is worth fixing separately: `AckFrequencyConfig` docs still
say Quinn follows draft-04, but ant-quic's code is no longer pure draft-04. The
current code uses `IMMEDIATE_ACK = 0x1f` and `min_ack_delay = 0xFF04DE1B`, which
match the newer active draft line rather than draft-04's older values.

## Decision Matrix

| Criterion | ACK-v2 status quo | IMMEDIATE_ACK + AckFrequency | Hybrid |
|---|---|---|---|
| Receiver-drained semantic | Yes. The receiver sends an endpoint-level outcome after decode/admission. | No. A QUIC ACK only proves packet receipt and can arrive before endpoint receive-path admission. | Yes. ACK-v2 remains the receive-drained semantic. |
| App-level idempotency | Yes. Request id plus payload hash dedupe makes retry duplicate-safe. | No. QUIC ACKs have no app request id and no payload-level conflict detection. | Yes. Keep ACK-v2 dedupe. |
| Backpressure / rejection signal | Yes. `Rejected(Backpressured)`, `Rejected(ConsumerGone)`, and close reasons are explicit. | No. Transport ACKs do not carry endpoint admission state. | Yes. ACK-v2 remains authoritative. |
| Maintenance surface | High. Custom envelope, waiter, dedupe, diagnostics, retry logic. | Low for transport behavior, but only because it solves a smaller problem. Replacing ACK-v2 would require rebuilding app semantics elsewhere. | Medium. Keep custom correctness layer; use standards-track transport controls narrowly. |
| Spec / interop posture | ant-quic private protocol, useful only between ant-quic peers. | Standards-track extension, but still active draft and local docs need updating to match current code/spec. | Best fit. Standards-track where it applies; private envelope only where ant-quic needs stronger semantics. |
| Soak risk | Known current behavior. | High if used as replacement; likely reopens false success/timeout ambiguity. | Low-to-medium. Any transport ACK tuning can be tested independently without weakening ACK-v2 correctness. |

## Why Full Migration Is Not Correct

Setting `ack_eliciting_threshold = 0` asks the peer to immediately acknowledge
every ack-eliciting packet. Sending `IMMEDIATE_ACK` asks for an ACK now. Neither
one says the peer's stream reader has consumed a B3 request, passed the payload
through the receive admission path, or replayed a duplicate request outcome.

That distinction matters because ACK-v2 was added to close an endpoint-level
race: the sender needs to know whether the remote receive pipeline accepted the
payload, not just whether QUIC delivered encrypted bytes to the peer. Replacing
ACK-v2 with transport ACKs would collapse those two layers and remove the
duplicate-safe retry behavior added by X0X-0037.

## What Hybrid Means

Hybrid does not mean two competing ACK protocols for the same correctness
contract.

It means:

1. ACK-v2 remains the success/failure contract for `send_with_receive_ack`.
2. IETF ACK Frequency remains a QUIC transport feature.
3. Future tuning may add targeted `IMMEDIATE_ACK` or ACK_FREQUENCY use around
   ACK-v2 traffic, PTO probes, or liveness probes, but only to improve transport
   feedback latency.
4. Global `ack_eliciting_threshold = 0` should not become the default without
   soak evidence, because it deliberately increases ACK traffic and can work
   against the extension's CPU/return-path motivation.

## Follow-up

File a follow-up implementation ticket for a narrow hybrid experiment:

- Update ant-quic ACK Frequency comments/docs to match the active draft values
  currently used in code.
- Add an opt-in ACK-v2 transport acceleration experiment, likely by queuing
  `IMMEDIATE_ACK` only on ACK-v2 request/probe paths where the peer advertised
  `min_ack_delay`.
- Measure whether ACK-v2 timeout tail latency improves under the launch
  readiness soak without increasing ACK/control packet pressure.

Do not fold this into X0X-0044. This ticket is decision-only.

## References

- IETF QUIC Acknowledgment Frequency draft-14, active on 2026-05-09:
  https://datatracker.ietf.org/doc/draft-ietf-quic-ack-frequency/
- IETF draft-04, the version named by the local Quinn-derived docs:
  https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency-04
- RFC 9000 section 13.2 acknowledgment behavior:
  https://www.rfc-editor.org/rfc/rfc9000.html#section-13.2
- Quinn `AckFrequencyConfig` docs:
  https://docs.rs/quinn/latest/quinn/struct.AckFrequencyConfig.html
