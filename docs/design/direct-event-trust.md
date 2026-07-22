# Design: Trust Annotations on Direct Message Events

## Status

Implemented — direct message events now carry `verified` and `trust_level` annotations (`src/server/routes/messaging.rs`, `src/server/ws.rs`; status updated 2026-07-19).

## Problem

Gossip events include `verified` and `trust_level`:

```json
{
  "topic": "ops.alerts",
  "sender": "ab01...",
  "verified": true,
  "trust_level": "trusted"
}
```

Direct message events do not:

```json
{
  "sender": "ab01...",
  "machine_id": "cd02...",
  "payload": "...",
  "received_at": 1711612800000
}
```

This forces every consumer to make a separate `/contacts/:agent_id` call to check trust.

## Proposed Change

Add `verified` and `trust_level` to direct message events at the **daemon level** (x0xd), not in the library `DirectMessage` struct.

### Why daemon level, not library level

`DirectMessage` in `src/direct.rs` is a transport-layer type. It doesn't depend on `ContactStore`. Adding trust there would tangle transport and trust layers. The gossip layer gets away with it because `PubSubMessage` is a higher-level type.

The cleaner approach: look up trust where x0xd serializes events for SSE/WebSocket. The `ContactStore` is already available via `state.contacts`.

### What `verified` means for direct messages

- `verified: true` — the `(AgentId, MachineId)` pair is consistent with a previously seen signed identity announcement in the discovery cache.
- `verified: false` — no cached announcement confirming this binding.

### Specific changes

**1. `src/bin/x0xd.rs` — `direct_events_sse` handler (line ~4039)**

After receiving `msg`, look up trust before serializing:

```rust
let contacts = state.contacts.read().await;
let trust_level = contacts.get(&msg.sender).map(|c| c.trust_level);
let verified = state.agent
    .is_agent_machine_verified(&msg.sender, &msg.machine_id)
    .await;

let data = serde_json::json!({
    "sender": hex::encode(msg.sender.as_bytes()),
    "machine_id": hex::encode(msg.machine_id.as_bytes()),
    "payload": base64::encode(&msg.payload),
    "received_at": msg.received_at,
    "verified": verified,                              // NEW
    "trust_level": trust_level.map(|t| t.to_string()), // NEW
});
```

**2. `src/bin/x0xd.rs` — `WsOutbound::DirectMessage` variant**

Add `verified: bool` and `trust_level: Option<String>` fields.

**3. `src/bin/x0xd.rs` — WebSocket direct message forwarder**

Same lookup pattern as SSE handler.

**4. `src/lib.rs` — new `is_agent_machine_verified` method on `Agent`**

```rust
pub async fn is_agent_machine_verified(
    &self,
    agent_id: &AgentId,
    machine_id: &MachineId,
) -> bool
```

Checks the discovery cache for a matching AgentId→MachineId binding.

### Files to modify

| File | Change |
|------|--------|
| `src/bin/x0xd.rs` | Three sites: `WsOutbound` enum, SSE handler, WS forwarder |
| `src/lib.rs` | Add `is_agent_machine_verified()` to `Agent` |

No changes to `src/direct.rs`, `src/contacts.rs`, or `src/trust.rs`.

## Backward Compatibility

- SSE: additive JSON fields — existing consumers ignore extra keys.
- WebSocket: additive fields on tagged JSON variant — same reasoning.
- Library: `DirectMessage` struct unchanged. No breaking change.

## What This Does NOT Do

- Does not add trust-based filtering (trust annotations via `recv_direct_annotated()`).
- Does not change the `DirectMessage` wire format.
- Does not use full `TrustEvaluator` with machine-pinning decisions — reports raw trust level from contact store. Consumers needing the full decision can combine `verified` + `trust_level` or call `/trust/evaluate`.

## Test Plan

1. Send direct message between agents, verify SSE event includes `verified` and `trust_level`.
2. Test each trust level (Blocked, Unknown, Known, Trusted) — verify correct string.
3. Test unknown sender — verify `trust_level: null`.
4. Test `verified: true` when AgentId→MachineId is in discovery cache.
5. Test `verified: false` when sender is unknown.
