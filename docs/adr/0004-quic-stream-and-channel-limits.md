# ADR-0004: QUIC Stream and Channel Limits for Gossip Workloads

## Status

Accepted

## Context

ant-quic opens a new QUIC unidirectional stream for every `send()` call. This is a
clean abstraction — each message gets its own stream with independent flow control
and ordering. However, QUIC limits the number of concurrent unidirectional streams
per connection. ant-quic's default is 100 streams, inherited from conservative QUIC
defaults suitable for request/response protocols like HTTP/3.

x0x's gossip workload has a fundamentally different traffic pattern. During the
startup phase, each agent:

- Announces its identity on a broadcast topic and a shard-specific topic
- Receives identity announcements from every other agent via multiple bootstrap paths
- Each announcement is ~10KB (ML-DSA-65 public key + signature)
- The gossip layer forwards messages to all eager peers, creating fan-out
- Heartbeats repeat announcements every 30 seconds

With 4-5 connected peers and multiple gossip topics, an agent easily sends 30-40
messages in the first 30 seconds. Each message consumes one stream from each peer
connection's budget. At the default limit of 100 concurrent streams, the budget is
exhausted within the first minute.

When the stream budget is exhausted, `connection.open_uni()` blocks waiting for the
peer to send `MAX_STREAMS` frames to replenish the budget. The peer replenishes
budget when its reader task finishes processing a stream and drops the `RecvStream`.
But the reader task forwards data through a bounded channel (default capacity 256).
If the application's `recv()` call is slow to drain this channel, the reader task
blocks on `channel.send()`, which prevents it from accepting new streams, which
prevents it from freeing stream budget.

The result is a deadlock-like condition: the sender blocks on `open_uni` (no stream
budget), the receiver blocks on `channel.send` (channel full), and application data
stops flowing. The connection remains alive (QUIC keepalive works at the transport
level) but no application messages are delivered.

This was observed during NAT traversal testing: all 7 test levels initially failed
intermittently because data delivery would stop after the identity announcement
burst, even though QUIC connections appeared healthy.

## Decision

Configure x0x's ant-quic node with:
- `max_concurrent_uni_streams`: 10,000 (up from default 100)
- `data_channel_capacity`: 1,024 (up from default 256)

These values are set in `NetworkNode::new()` via ant-quic's `NodeConfig::builder()`.
ant-quic's defaults are unchanged — this is an application-level configuration
choice specific to x0x's gossip workload.

## Why These Values

### 10,000 concurrent streams

At x0x's typical gossip rate of 1-2 messages per second per peer, with 10 connected
peers, that's ~20 messages/second or ~1,200 messages/minute. Each stream is
short-lived (open, write, finish), so the concurrent count is much lower than the
total count. 10,000 provides several hours of headroom even in worst-case burst
scenarios, without meaningful memory cost (~100 bytes per stream entry = ~1 MB total).

### 1,024 channel capacity

The data channel sits between ant-quic's per-connection reader tasks and the
application's `recv()` call. With multiple connections each producing messages,
the channel can accumulate messages faster than the single-threaded gossip dispatch
loop processes them. 1,024 entries provides 4x the default headroom, reducing the
probability of reader task backpressure to near zero for x0x's workload.

## Why Not Change ant-quic Defaults

ant-quic is a generic QUIC transport library. Its defaults (100 streams, 256 channel
capacity) are appropriate for request/response protocols and constrained environments
(BLE, LoRa). Changing the defaults would affect all consumers. Instead, we exposed
these as configurable parameters in ant-quic's builder API so each application can
tune them for its specific workload.

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
   A high-but-finite limit (10,000) is more defensible.
