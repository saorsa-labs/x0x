# Quinn PR #2616 vs ant-quic X0X-0034 — supersede-race comparison

**Date:** 2026-05-08
**Ticket:** X0X-0042 (sota-borrow phase A)
**Conclusion (TL;DR):** Different layer, same bug shape. ant-quic's gate is mature
and arguably stricter. **No follow-up ticket required.**

This document compares Quinn's PR #2616 (Ralith, 2026-04-27, "Improve 0-RTT
Usability") with ant-quic's X0X-0034 fix shipped in 0.27.8 (commit
`f6a2ada8`, 2026-05-07). Both targets the same conceptual bug class —
removing a racy lifecycle signal in favour of a stronger one — but they
land at very different layers of the QUIC stack.

## 1. Quinn PR #2616 summary

**Where:** high-level `quinn` crate user-facing API.

- `quinn/src/connection.rs`
- `quinn/src/recv_stream.rs`

**What it removed:** the `ZeroRttAccepted` future. Callers were branching on
its boolean to decide whether their 0-RTT-opened streams had survived the
handshake. The boolean had two problems:

1. Racy with concurrent stream-opening logic — callers opening more streams
   while polling `ZeroRttAccepted` could observe stale or interleaved state.
2. Semantics differed between client and server, so the same code didn't
   port across roles.

**What it added:**

- `Connection::authenticated()` — a strong, monotonic signal that the
  handshake has completed and the peer's identity is known.
- Documented `SendStream::stopped()` as the per-stream way to detect 0-RTT
  rejection in the presence of concurrent stream creation.

**Layer of the fix:** **application-API.** The state machine
(`quinn-proto`) was not modified. The fix is a contract change: "don't
branch on this racy boolean; gate on the post-handshake signal we already
expose, and use per-stream `stopped()` for stream-level decisions." The
underlying transport state machine was already correct; the public API was
what made it easy to write racy code.

**Timeline:** opened 2026-04-21, merged 2026-04-27, 5 commits.

## 2. ant-quic X0X-0034 fix summary

**Commit:** `f6a2ada8` — "release: ant-quic 0.27.8 — bidi ACK protocol +
supersede-race fix (X0X-0034)".
**Where:** `ant-quic/src/p2p_endpoint.rs` (with supporting changes to
`ack_frame.rs`, `transport_parameters.rs`, `connection/mod.rs`,
`high_level/connection.rs`).

**Symptoms that drove the fix** (from the X0X-0034 ticket):

- 6 × `Timed out waiting for remote receive acknowledgement` and 2 ×
  `Connection closed: ReaderExit` per Phase A run on x0x 0.19.26's fleet
  pre-warms.
- `receiver_backpressured` never fired, so the X0X-0032 bounded-admission
  path was healthy. The data was either never ACKed or the connection
  closed mid-flight.
- Hypothesised root cause: when `ensure_peer_send_ready` repaired a
  disconnected peer with a fresh connection, the new connection
  **superseded** an old one that was still draining in-flight `send_with_receive_ack`
  payloads. Concurrent senders on the old generation saw `ReaderExit` (if
  the supersede notification propagated first) or ACK-timeout (if the ACK
  control frame was on the old stream and the old reader had already exited).

**What the fix did:**

1. **Protocol migration (uni → bidi).** The 0.27.7 protocol used two
   uni-streams: `ANQAckP1` for the payload, `ANQAckC1` for the ACK control
   frame. A supersede racing between the two left the sender's ACK waiter
   orphaned. 0.27.8 collapses these into a single bidirectional stream:
   `ANQAckB2` (request) + `ANQAckR2` (response). Request and response are
   now correlated on the same stream lifetime. Negotiated via the
   `ack_receive_v2` transport parameter; mixed-version meshes return
   `NotSupported` and callers fall back to the non-ACK path.
2. **`SUPERSEDED_READER_DRAIN_GRACE = 5s`.** New constant in
   `p2p_endpoint.rs:128`. Three call sites previously called
   `cancel_reader_generation(...)` synchronously when registering a
   replacement connection; all three now call
   `schedule_reader_generation_cancel(peer, generation, SUPERSEDED_READER_DRAIN_GRACE)`
   instead. The implementation (`p2p_endpoint.rs:7598`) spawns a task that
   sleeps 5 s then cancels — letting the superseded reader complete any
   in-flight bidi `accept_bi()` + `read_to_end()` on the old connection
   before its cooperative-cancel token is signalled.
3. **Reader task accepts both uni and bidi streams.** `tokio::select!` on
   `accept_uni()` + `accept_bi()`. Backwards-compatible with peers still on
   ACK-v1.

**Layer of the fix:** **endpoint orchestration / reader-task layer.** This
is *above* the vendored `quinn-proto` state machine but *below* the
`high_level::Connection` API. The fix is structural — protocol redesign
plus a new lifecycle phase (drain grace) inserted between "registered as
superseded" and "reader cancelled."

**Statistics:**

```
src/ack_frame.rs                 | 159 ++++++++++++---
src/connection/mod.rs            |   4 +-
src/high_level/connection.rs     |   6 +-
src/p2p_endpoint.rs              | 428 ++++++++++++++++++++++-----------------
src/transport_parameters.rs      |  34 ++--
tests/b_send_with_receive_ack.rs |   4 +-
8 files changed, 456 insertions(+), 240 deletions(-)
```

The bulk (`p2p_endpoint.rs`, +428 lines) is the reader-task and protocol
rewrite, not state-machine work.

## 3. Same layer? Different layer

**Different layer. Same bug shape.** Both fixes follow the pattern "kill
the racy signal, gate on a stronger one." But the layers don't overlap:

| Aspect | Quinn PR #2616 | ant-quic X0X-0034 |
|---|---|---|
| Layer | High-level `quinn` user API | ant-quic endpoint orchestration |
| Module | `quinn/src/connection.rs`, `recv_stream.rs` | `ant-quic/src/p2p_endpoint.rs` |
| Racy signal removed | `ZeroRttAccepted` future (boolean branch) | `cancel_reader_generation(...)` synchronous on supersede |
| Strong signal added | `Connection::authenticated()` + `SendStream::stopped()` | `schedule_reader_generation_cancel(... 5s grace)` + bidi ACK protocol |
| Trigger | 0-RTT acceptance race vs. concurrent stream open | Connection supersede race vs. in-flight bidi ACK exchange |
| State-machine touched? | No — pure API contract change | No — endpoint glue + wire protocol |
| Wire protocol changed? | No | Yes (`ack_receive_v1` → `ack_receive_v2`) |

These two fixes do **not** target the same code path or even adjacent code
paths. Quinn's race is about how an application gates *its own* stream
opens against a global handshake-acceptance state. ant-quic's race is about
how the endpoint sequences *reader-task cancellation* against in-flight
bidi stream exchanges on the connection being torn down.

**Why "same bug shape" still matters:** both teams arrived at the same
remediation pattern — identify a signal that downstream code is gating on,
find that the signal can fire mid-race, and replace it with a signal that
either cannot fire mid-race (Quinn's `authenticated()` is monotonic) or
defers until the race is provably over (ant-quic's 5 s drain grace before
cancellation, plus single-stream bidi protocol that ties request and
response together).

**Why ant-quic does not need to mirror Quinn's API change:** ant-quic does
not expose `ZeroRttAccepted` or any equivalent. ant-quic's `high_level::Connection`
is a thin wrapper over the vendored quinn-proto state machine plus
ant-quic's own NAT-traversal and `send_with_receive_ack` extensions — it
does not surface a racy 0-RTT acceptance future. Importing Quinn's API
change here would be importing a fix for a bug ant-quic doesn't have.

**Why Quinn's PR doesn't help with X0X-0034:** Quinn #2616 is at a higher
layer than where the supersede-race lives. Even if ant-quic adopted
`Connection::authenticated()` verbatim, the X0X-0034 race — between
`P2pEndpoint::register_replacement_connection` and an old reader still
draining a bidi ACK exchange — would be untouched. The fix has to live in
the endpoint layer, where reader-task lifetimes and connection generations
are coordinated.

## 4. Follow-up

None. The two fixes target genuinely different layers and ant-quic's
X0X-0034 fix is at the right layer for the bug ant-quic was hitting.
Specifically:

- The Quinn fix is an API ergonomics / race-prevention contract change at
  the user-facing layer. ant-quic does not have an equivalent racy API
  surface to remove.
- ant-quic's fix is at the endpoint orchestration layer where its supersede
  race actually lives. Adopting Quinn's pattern at that layer would not
  address the bug.
- D1 (selective port from noq, no fork) and D3 (cherry-pick from
  `quinn-rs/quinn` `main` only when warranted) both apply: there is nothing
  in #2616 worth cherry-picking into ant-quic's vendored quinn-proto for
  this issue.

If a future audit identifies a *different* racy lifecycle signal in
ant-quic's high-level API surface that *is* the same shape as Quinn's
`ZeroRttAccepted`, that would warrant a fresh ticket — but X0X-0034 itself
is closed by 0.27.8 and the fleet evidence (X0X-0036/0037 follow-up work
on adjacent ACK-v2 timeout retry behaviour) corroborates that the
supersede race itself is gone.

## 5. References

- Quinn PR #2616: https://github.com/quinn-rs/quinn/pull/2616
- ant-quic 0.27.8 release commit: `f6a2ada8` (`ant-quic/src/p2p_endpoint.rs`,
  `ant-quic/src/ack_frame.rs`, `ant-quic/src/transport_parameters.rs`)
- ant-quic supersede event commit: `f8f3a8e7` ("fix(nat): emit Replaced +
  Closed{Superseded} on connection supersede race") — preceding diagnostics
  work that surfaced the race shape.
- X0X-0034 ticket: `issues/issues.jsonl` (id `X0X-0034`).
- SOTA-Borrow plan: [`sota-borrow-plan.md`](sota-borrow-plan.md) §4 X0X-0042.

## D2 / D1 alignment

- D1 (no noq fork): respected — this comparison validates ant-quic's
  in-tree gate; no recommendation to vendor noq.
- D2 (stay on draft-seemann frame range `0x3d7e9x`): respected — this doc
  references the ant-quic `0x3d7e9x` allocation only by contrast; noq's
  divergent `0x3d7f9` numbering is not relevant to the supersede-race
  layer comparison and is not adopted.
