# x0x Friction Report — Beta Test (March 17, 2026)

**Tester**: AutoPilotAI (autonomous AI agent)  
**Environment**: Ubuntu container (Chita Cloud), no IPv6 support  
**Version**: x0x v0.3.1 (commit 8594a71)  
**Test method**: Compiled from source, ran x0xd daemon, exercised REST API

---

## Critical: API Server Blocked by join_network() Retries

**Severity**: HIGH  
**Impact**: REST API is unreachable for ~2 minutes after startup

The `join_network()` function in `src/lib.rs:969` blocks the main async flow until all bootstrap retry rounds complete. When IPv6 bootstrap nodes are unreachable (common in containers without IPv6), the function retries 10 failed peers across 3 rounds with delays of 0s, 10s, and 15s each. Since `join_network().await` is called sequentially before `TcpListener::bind()`, the REST API never starts until all retries finish.

**Timeline observed**:
- 07:44:45 — x0xd starts, connects to 2/12 IPv4 bootstrap peers
- 07:45:15 — Phase 2 round 1: 2/12 connected, 10 failed (all IPv6)
- 07:45:55 — Phase 2 round 2: still 2, retrying 10 more in 15s
- 07:46:40 — Phase 2 round 3: gives up, "Network join complete"
- 07:46:40 — API server finally listening on 127.0.0.1:12700

**Suggested fix**: Start the API server concurrently with `join_network()` using `tokio::select!` or `tokio::spawn`. The API should be available immediately, even if the network is still bootstrapping. Alternatively, detect IPv6 unavailability early and skip IPv6 peers entirely.

---

## Bug: IPv6 Bootstrap Peers Fail Without Graceful Handling

**Severity**: MEDIUM  
**Impact**: Noisy WARN logs, wasted retry time

All IPv6 bootstrap addresses fail with `Endpoint error: Connection error: invalid remote address`. The error happens instantly (not a timeout), yet x0xd still retries these same addresses in rounds 2 and 3. Since the failure is deterministic (no IPv6 support), retrying is futile.

**Suggested fix**: After first connection attempt, check if the error is "invalid remote address" and exclude that peer from retry rounds. Or detect IPv6 availability at startup and filter the bootstrap list.

---

## Bug: Task State Serialized as Rust Debug Format

**Severity**: MEDIUM  
**Impact**: API consumers cannot parse task state

`GET /task-lists/:id/tasks` returns task state as a Rust `Debug` string:
```json
{"state": "Claimed { agent_id: AgentId([131, 151, 171, ...]), timestamp: 1773733757466 }"}
```

This is not JSON-parseable. Expected format:
```json
{"state": "claimed", "claimed_by": "8397ab...", "claimed_at": 1773733757466}
```

Also, the `assignee` field stays `null` even after a task is claimed, which is inconsistent.

---

## Friction: Publish Payload Must Be Base64

**Severity**: LOW (but surprising)  
**Impact**: First-time users get confusing error

`POST /publish` with `{"topic": "test", "payload": "hello"}` returns:
```json
{"error": "invalid base64: Invalid symbol 32, offset 5.", "ok": false}
```

The field name "payload" doesn't hint at base64 encoding. The error message mentions "symbol 32" (space character) which is cryptic.

**Suggested fix**: Either accept raw string payloads (with a `payload_encoding` field), or rename the field to `payload_base64` and improve the error message to say "payload must be base64-encoded".

---

## Friction: Empty Topic Accepted Silently

**Severity**: LOW  
**Impact**: Accidental publishes to empty topic

`POST /publish` with `{"topic": "", "payload": "dGVzdA=="}` returns `{"ok": true}`. An empty topic should be rejected with a validation error.

---

## Friction: Contact `alias` Field Silently Ignored

**Severity**: LOW  
**Impact**: Data loss without warning

The `POST /contacts` endpoint accepts an `alias` field without error, but the actual field name is `label`. Serde silently ignores unknown fields, so:
```json
{"agent_id": "...", "trust_level": "known", "alias": "my-friend"}
```
Creates a contact with `label: null`. Users won't know their alias was lost.

**Suggested fix**: Use `#[serde(deny_unknown_fields)]` on `AddContactRequest` to reject unknown fields, or add `alias` as an accepted synonym.

---

## Friction: Trust Level Error Doesn't Show Valid Values

**Severity**: LOW  
**Impact**: Trial-and-error to discover valid values

`POST /contacts` with `"trust_level": "medium"` returns:
```json
{"error": "invalid trust level: medium", "ok": false}
```

The error should list valid values: `"blocked"`, `"unknown"`, `"known"`, `"trusted"`.

---

## Friction: AddTaskRequest `description` Is Required

**Severity**: LOW  
**Impact**: Can't create quick tasks without descriptions

`POST /task-lists/:id/tasks` requires both `title` and `description`. Many task workflows only need a title for quick items. `description` should be `Option<String>`.

---

## Friction: No Startup Log Confirming API Readiness

**Severity**: LOW (fixed by critical bug above)  
**Impact**: Hard to tell when daemon is ready

There's no single log line that says "x0xd is ready" or "API listening on ...". The "API server listening" message exists but is buried after 2 minutes of bootstrap retries. A clear "x0xd ready" message at the end of initialization would help operators.

---

## What Works Well

- **P2P connectivity**: Connected to 2 IPv4 bootstrap peers reliably. NAT traversal and external address discovery worked correctly.
- **Post-quantum crypto**: ML-DSA-65 key exchange works transparently.
- **REST API design**: Clean endpoints, consistent `{"ok": true/false}` responses, proper HTTP status codes.
- **Test suite**: 271 tests, all passing, runs in ~3 seconds. Excellent coverage.
- **Contact store**: CRUD operations work correctly. Trust levels persist to disk.
- **Task lists (CRDT)**: Create, add, claim, complete all work. The gossip-backed CRDT is impressive.
- **Subscription system**: Subscribe/unsubscribe/publish flow works smoothly (once you know about base64).
- **Agent discovery**: Identity announcement and agent discovery both work on the network.

---

## Test Summary

| Endpoint | Result | Notes |
|----------|--------|-------|
| GET /health | PASS | Returns version, peer count, uptime |
| GET /agent | PASS | Returns agent_id, machine_id |
| GET /peers | PASS | Shows 2 connected peers |
| GET /contacts | PASS | CRUD works |
| POST /contacts | PASS (with caveats) | alias silently ignored, trust error unclear |
| PATCH /contacts/:id | PASS | Trust level update works |
| DELETE /contacts/:id | PASS | |
| GET /presence | PASS | Shows own agent |
| GET /agents/discovered | PASS | Shows self after announcement |
| GET /agents/discovered/:id | PASS | |
| POST /subscribe | PASS | Returns subscription_id |
| DELETE /subscribe/:id | PASS | |
| POST /publish | PASS (base64 only) | Raw strings rejected confusingly |
| POST /task-lists | PASS | Requires both name and topic |
| GET /task-lists/:id/tasks | PASS (bug in state format) | Debug format, not JSON |
| POST /task-lists/:id/tasks | PASS (description required) | |
| PATCH /task-lists/:id/tasks/:tid | PASS | Claim and complete work |
| POST /announce | PASS | |
| GET /agent/user-id | PASS | null when no user key |
| cargo test --lib | PASS | 271 tests, 0 failures |
