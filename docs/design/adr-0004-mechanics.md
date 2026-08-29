# ADR-0004 mechanics — Limit-sizing arithmetic and alternatives

> Extracted 2026-08-29 from the immutable [ADR 0004](../adr/0004-quic-stream-and-channel-limits.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the sizing arithmetic and alternatives detail relocated
> verbatim so this file is their maintained home — future updates belong here,
> not in the ADR.

## Why These Values

### 50,000 concurrent streams (originally 10,000)

At x0x's typical gossip rate of 1-2 messages per second per peer, with 10 connected
peers, that's ~20 messages/second or ~1,200 messages/minute. Each stream is
short-lived (open, write, finish), so the concurrent count is much lower than the
total count. The original design used 10,000 which provides several hours of headroom even in worst-case burst
scenarios, without meaningful memory cost (~100 bytes per stream entry = ~1 MB total).
This was later increased to 50,000 for additional margin.

### 50,000 channel capacity (originally 1,024)

The data channel sits between ant-quic's per-connection reader tasks and the
application's `recv()` call. With multiple connections each producing messages,
the channel can accumulate messages faster than the single-threaded gossip dispatch
loop processes them. The original design used 1,024 which provides 4x the default headroom, reducing the
probability of reader task backpressure to near zero for x0x's workload.
This was later increased to 50,000 for additional margin.

---

## Alternatives Considered

1. **Message batching**: Send multiple gossip messages on a single QUIC stream with
   length-prefix framing. This would dramatically reduce stream consumption but
   requires a wire protocol change and coordinated rollout. Worth pursuing long-term
   but not needed now that the stream limit provides sufficient headroom.

2. **Bidirectional streams**: Use bidirectional streams for request/response patterns
   like SWIM Ping/Ack. This halves stream consumption for keepalive traffic but
   requires changes to both ant-quic's send/recv API and the gossip layer's message
   handling. Lower priority since the stream limit fix resolves the immediate issue.

3. **Unbounded streams**: Set `max_concurrent_uni_streams` to `VarInt::MAX`. This
   removes the limit entirely but could mask resource leaks or misbehaving peers.
   A high-but-finite limit (originally 10,000, later increased to 50,000) is more defensible.
