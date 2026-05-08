# GSO bundle tail-drop as alternative root cause for X0X-0030

**Status:** INCONCLUSIVE — pending soak data
**Hypothesis:** Quinn issue [#2627](https://github.com/quinn-rs/quinn/issues/2627)
**Filed under:** SOTA-Borrow Phase A / X0X-0043
**Created:** 2026-05-08

---

## 1. Hypothesis

X0X-0030 records 12 s send timeouts on x0x's VPS mesh after roughly 28 minutes
of idle. The accepted explanation has been "idle-rot" — kernel state
(conntrack, NAT bindings, congestion controller assumptions) decaying during
the idle window so that the first burst on resumption misbehaves until
recovery primitives kick in.

Quinn issue #2627 (open, no maintainer reply at the time of writing) reports
a different shape that is observationally indistinguishable from idle-rot
on a soak metric:

> Quinn's pacer paces *between* `sendmsg` calls, not *within* a GSO bundle.
> A GSO bundle of up to 10 datagrams is therefore submitted to the kernel
> in roughly 12 µs — about 5.8 Gbps at the wire. CDN / CGNAT rate-limiters
> sitting in the path tail-drop the bundle.

Apply this to x0x: every VPS in the mesh sits behind some provider-side
network gear (DigitalOcean / Hetzner internal fabric, possibly mid-path
CGNAT). If any of that gear shapes traffic by short-window byte rate, the
first burst-resume after a long idle is a worst-case wire spike. The 12 s
timeout would then be tail-drop on the bundle, not idle-rot.

The two failure modes diverge only at the wire. A purely metric-level
view of x0xd cannot tell them apart — both look like "send took the full
timeout, then succeeded on retry."

## 2. What the new counters measure

[X0X-0039](../design/sota-borrow-plan.md) added the `data_tx` saturation
counters; X0X-0043 adds two GSO-bundle counters in the same shape:

| Counter | Lives in | Surfaces as |
|---|---|---|
| `gso_bundle_send_total` | `ant-quic::diagnostics::gso` (process-global atomic) | `/diagnostics/connectivity.transport.gso.bundle_send_total` |
| `gso_bundle_partial_send` | same | `/diagnostics/connectivity.transport.gso.bundle_partial_send` |

`bundle_send_total` increments **once per multi-segment bundle submitted to
the kernel send path**, regardless of segment count. Single-datagram sends
are not GSO bundles by definition and are not counted.

`bundle_partial_send` increments when the kernel send call returns an error
*after* the bundle was already accounted as submitted (the closest measurable
proxy under ant-quic's current `try_send_to`-based runtime — see §4 below
for why this matters for interpretation).

The hook lives in `ant-quic/src/high_level/connection.rs`'s `drive_transmit`
loop, immediately after `quinn-proto::poll_transmit` returns a `Transmit`
and right around the `socket.try_send` call that hands it to the kernel.

## 3. How to interpret a soak result

Read the per-window per-node counters from the soak proof artefact alongside
the existing X0X-0030 timeout signal:

| Pattern | Interpretation |
|---|---|
| `bundle_send_total = 0` cluster-wide for the entire soak | GSO bundles are not being produced by ant-quic at all. The hypothesis is **falsified for the current build** — see §4 for why this is the expected reading today. |
| `bundle_send_total > 0`, `bundle_partial_send = 0`, X0X-0030 timeouts persist | GSO is firing but the kernel is accepting every bundle. Hypothesis is **not the cause** — investigate other tail behaviours. |
| `bundle_send_total > 0`, `bundle_partial_send > 0`, partial-send spikes correlate (within a window) with X0X-0030 timeouts | Hypothesis is **confirmed**. Fix path forks: deploy `max_outgoing_bytes_per_second` (Quinn PR [#2556](https://github.com/quinn-rs/quinn/pull/2556)) or pace within-bundle. File the implementation ticket. |
| `bundle_send_total > 0`, `bundle_partial_send > 0`, no temporal correlation with X0X-0030 | Two independent failure modes. Treat partial-send as its own ticket. |

The soak gate runner (`tests/launch_readiness.py`) already collects
`/diagnostics/connectivity` per-window per-node, so the artefact will carry
these fields automatically once the ant-quic pin bumps past 0.27.12.

## 4. Limitation that frames the current expected reading

ant-quic's `AsyncUdpSocket` trait
(`ant-quic/src/high_level/runtime.rs`) defaults `max_transmit_segments()`
to `1`. Both in-tree implementations — `TokioRuntime`'s `UdpSocket`
(`ant-quic/src/high_level/runtime/tokio.rs`) and the dual-stack socket
(`ant-quic/src/high_level/runtime/dual_stack.rs`) — leave that default
in place and call `try_send_to(transmit.contents, destination)` rather
than `quinn_udp::UdpSocketState::send`.

Consequences:

1. `quinn-proto::poll_transmit` is invoked with `max_datagrams = 1` and
   therefore returns `Transmit { segment_size: None, .. }` for every
   outbound packet under the current build.
2. The `is_gso_bundle` check in `drive_transmit` is therefore
   structurally `false`, and `bundle_send_total` will read `0` for the
   first soak we run with these counters wired.

This is informative, not a bug. **A soak result of all-zeros falsifies
the GSO-tail-drop hypothesis under current ant-quic** — no GSO bundles
are leaving the host, so the wire-side rate-limit story cannot be the
cause of X0X-0030 in this build. That answer ships the ticket as
`not-the-cause` for the current code path, even though the broader
hypothesis remains open for any future build that wires kernel GSO.

If a future change overrides `AsyncUdpSocket::max_transmit_segments`
or rewrites `try_send` to call `quinn_udp::UdpSocketState::send`, the
counters surface real signal without further code changes here. The
partial-send heuristic should also be revisited at that time — that
API exposes `Result<usize, io::Error>` where `usize` is segments
accepted, which is a strictly better signal than the current
"error after submission" proxy.

## 5. Findings

**INCONCLUSIVE — pending soak data.**

The Phase A 30-min and Phase B 4 h soak gates collect the per-window
counters. The first soak proof artefact carrying populated values
(post-pin-bump) determines the final status. Until then this doc is the
record of:

- the hypothesis,
- the observability path that tests it,
- the pre-soak prediction (zeros under current ant-quic build, which
  itself constitutes a falsification of the hypothesis for this build).

Update this section with the soak-of-record values when they land. The
ticket's acceptance vocabulary is `confirmed` / `not-the-cause` /
`inconclusive`; choose one and cite the proof artefact path.

## 6. References

- [Plan: SOTA-Borrow §4 X0X-0043](../design/sota-borrow-plan.md)
- [Quinn issue #2627 — GSO-bundle tail-drop](https://github.com/quinn-rs/quinn/issues/2627)
- [Quinn PR #2556 — `max_outgoing_bytes_per_second`](https://github.com/quinn-rs/quinn/pull/2556)
- ant-quic instrumentation: `ant-quic/src/diagnostics/gso.rs`,
  `ant-quic/src/high_level/connection.rs::drive_transmit`
- x0x surface: `x0x/src/bin/x0xd.rs::connectivity_diagnostics`
- Related: X0X-0030 idle-rot timeouts;
  [X0X-0039 data_tx capacity audit](../design/sota-borrow-plan.md)
  for the matching diagnostic-counter pattern.
