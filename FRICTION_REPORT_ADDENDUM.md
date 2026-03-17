# x0x Friction Report — Addendum: Multi-Node & Network Tests (March 17, 2026)

## NEW: QUIC Loopback Connection Fails

**Severity**: HIGH  
**Impact**: Cannot test agent-to-agent communication on a single host

When running two x0xd instances on the same machine (node1 on UDP:42501, node2 bootstrapped to 127.0.0.1:42501), the QUIC handshake times out after 30s:

```
connect: handshake to 127.0.0.1:42501 failed: timed out
Failed to connect to 127.0.0.1:42501: connection failed: Endpoint error: Connection error: timed out
```

This makes it impossible to test P2P communication locally. A developer's typical workflow is to spin up 2+ nodes on localhost to verify pub/sub, task list sync, and agent discovery — none of which can be tested without this working.

**Suggested fix**: Ensure QUIC connections work over loopback. This may be a limitation of the `ant-quic` NAT traversal layer filtering loopback addresses.

---

## NEW: Same AgentId for Multiple Instances on Same Machine

**Severity**: HIGH  
**Impact**: Identity collision prevents multi-node testing

Both x0xd instances produced the same `agent_id: eec0e2b2f42e7b8c...` because keypairs are stored in `~/.x0x/` regardless of the `data_dir` config setting. The `data_dir` only controls peer cache and contacts, NOT keypair storage.

**Suggested fix**: Either:
1. Use `data_dir` as base for ALL persistent state including keypairs
2. Add a `key_dir` config option
3. Document that multi-instance testing requires separate `$HOME` dirs

---

## NEW: Network is Empty — No Other Agents Visible

**Severity**: MEDIUM (expected for beta, but impacts testing)  
**Impact**: Cannot verify real-world agent communication

After connecting to 2 bootstrap nodes (142.93.199.50 and 147.182.234.192):
- `/agents/discovered` only returns self
- `/presence` only shows self
- Publishing to `x0x-global`, `x0x`, `hello` topics received no responses (10s SSE wait)
- SSE `/events` stream produced zero events

This is expected for an early beta network, but means a beta tester cannot verify that:
- Gossip message propagation works across peers
- CRDT task lists sync between agents
- Agent identity discovery works at scale

---

## NEW: Gossip Membership Continuously Shrinking

**Severity**: LOW  
**Impact**: Misleading log output

The HyParView membership overlay continuously reduces `passive_max` by 2 every 10 seconds (126→124→122→...→98), logging each change as INFO. This is noisy and suggests the membership protocol is "cooling" without real activity. With only 2 bootstrap peers and no other agents, this is expected but the INFO logs are excessive — should be DEBUG level.

---

## NEW: Identity Consent Error is Unclear

**Severity**: LOW  
**Impact**: Poor developer experience

`POST /announce` with `{"include_user_identity": true}` returns:
```json
{"error": "key storage error: human identity disclosure requires explicit human consent", "ok": false}
```

The error doesn't explain HOW to give consent. Should mention the `user_key_path` config option or the consent mechanism.

---

## Updated Test Summary

| Test | Result |
|------|--------|
| Two nodes on same host | FAIL: QUIC loopback timeout |
| Agent identity uniqueness per instance | FAIL: Same AgentId from shared keypair |
| Agent discovery (other agents) | EMPTY: Only self visible |
| Pub/sub message propagation | UNTESTED: No second peer to receive |
| CRDT task sync across peers | UNTESTED: No connected peers |
| SSE real-time events | EMPTY: No events received |
| Network presence | SELF-ONLY: 1 agent (self) |
| Announce with user identity | BLOCKED: Consent mechanism unclear |
