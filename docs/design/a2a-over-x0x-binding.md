# A2A-over-x0x Transport Binding

> **Status:** Unary packet 1 implemented; streaming, push and large-artifact
> sections remain design sketches, not implemented binding guarantees.
> **Date:** 2026-06-15
> **Relates to:** A2A spec §5 (Protocol Binding Requirements) and §12 (Custom
> Binding Guidelines); `x0x-transport-protocol-id.md`; `a2a-agent-card-adapter.md`.

## 1. Purpose

A2A standardizes *what* agents exchange (Task / Message / Part / Artifact) and
ships three transports: JSON-RPC, gRPC, HTTP+JSON/REST. A2A §12 explicitly
permits **custom bindings**. This document defines a custom binding that carries
A2A's data model over **x0x** instead of HTTP — giving A2A peers post-quantum,
NAT-traversing, registry-free delivery while keeping A2A application semantics
unchanged.

Tagline: **"A2A semantics, x0x delivery."**

## 2. What the binding replaces vs keeps

| A2A concern | Standard HTTP binding | A2A-over-x0x binding |
|-------------|----------------------|----------------------|
| Endpoint identity | HTTPS URL | x0x `AgentId` (32-byte) |
| Transport | HTTP/SSE | x0x QUIC DM (`RawQuicAcked`) + gossip |
| Connection auth | TLS + OAuth2/OIDC/mTLS/API key | QUIC ML-DSA-65 handshake + `AgentCertificate` |
| Request/response | HTTP req/resp | Request/response correlation over DM (§4) |
| Streaming (`message/stream`) | SSE | DM stream / `RawQuicAcked` chunks (§5) |
| Push notifications | webhook POST | x0x gossip topic the client subscribes to (§6) |
| **Data model (Task/Message/Part/Artifact)** | unchanged | **unchanged** |

The A2A data model is carried inside a JSON-RPC envelope. Unary packet 1 sets
the JSON-RPC `id` to the same opaque string as the binding `corrId`; response
admission requires an exact echo (§4). Later capabilities in the table are
design targets, not a claim of complete binding conformance.

## 3. Addressing & Discovery

- An A2A-over-x0x agent is addressed by its `AgentId`, expressed as
  `x0x://agent/<base64url-card>` (the existing `AgentCard.to_link()`).
- The agent advertises this binding in its A2A Agent Card via
  `supportedInterfaces` (see `a2a-agent-card-adapter.md`), with a transport
  token such as `transport: "x0x"` and `url: "x0x://agent/<id>"`.
- Discovery uses x0x's existing mechanisms (`/agents/find/:agent_id` FOAF,
  social card exchange) — no registry, no DNS.

## 4. Unary methods (message/send, tasks/get, tasks/cancel, …)

Packet 1 carries unary request/response through `send_direct_with_config`,
preferring `RawQuicAcked` and retaining the configured delivery fallback:

```
A2A client                                   A2A server (x0x agent)
   │  DM payload = {                              │
   │    "x0xBinding": "a2a/1",                    │
   │    "corrId": "<opaque-corr-id>",                       │
   │    "kind": "request",                        │
   │    "jsonrpc": { "id": "<opaque-corr-id>", ... }│
   │  }                                           │
   ├─────── send_direct(serverAgentId) ──────────▶
   │                                              │ process; produce A2A result
   ◀────── DM { corrId, kind:"response", jsonrpc:{result|error} } ─┤
```

- Correlation: `corrId` is opaque. Peers echo it verbatim and must not parse it
  as a bare UUID. `BindingSession::call` emits `<uuid>-<call-token>` and uses
  that exact string as the JSON-RPC `id`. Every public `call` allocates a fresh
  ID; the API does not accept a caller-supplied ID for retries.
- Response admission: a pending call accepts only a response with verified
  provenance from the expected peer, literal `"jsonrpc": "2.0"`, the exact
  echoed JSON-RPC `id`, and exactly one of `result` or a well-formed `error`.
  JSON `null` is a valid result. A refused response leaves the waiter pending;
  an unverified response cannot complete a call even from the claimed peer.
  A legitimate raw response from an as-yet-unlearned peer can carry
  `verified=false` and leave the call to time out until real authenticated
  AgentId→MachineId identity evidence is available. A successful connection
  or a connected-registry route alone does not establish that evidence.
  Later discovery does not retroactively admit an already discarded response;
  the handler may already have run, so retrying can duplicate side effects.
- Lifetime: the waiter is registered before sending and removed on completion,
  send failure, timeout or cancellation. A late response without a pending
  call is ignored. This is in-flight correlation, not a durable replay cache.
- Delivery and retries: a DM ACK is not proof that the A2A handler completed.
  A timeout leaves the application outcome unknown: the request may be
  unapplied, or its side effects may already have happened without an admitted
  response. Packet 1 provides no server-side durable deduplication or
  idempotency guarantee by `corrId`; a new call, or a replayed request with the
  same ID, can duplicate side effects. Applications must decide whether an
  operation is safe to retry or provide their own idempotency mechanism.
- Max payload: 16 MB per `MAX_DIRECT_PAYLOAD_SIZE`; the larger-artifact mapping
  in §7 remains a future binding design.

## 5. Streaming (message/stream) — future increment

A2A streaming yields a sequence of `Task` / `statusUpdate` / `artifactUpdate`
events. Over x0x:

- Open with a `request` DM carrying the A2A `message/stream` call and
  `"stream": true`.
- Server emits a sequence of `RawQuicAcked` DMs, each
  `{ corrId, kind:"stream", seq:N, jsonrpc:{ <event> } }`, terminated by
  `{ corrId, kind:"stream-end", seq:N+1 }`.
- `seq` gives ordering/gap detection; `RawQuicAcked` gives reliability. This is
  the x0x equivalent of A2A's SSE event stream.

## 6. Push notifications (long-running tasks, disconnected client) — future increment

A2A push config (`CreateTaskPushNotificationConfig`, …) maps to a **gossip
topic** instead of a webhook URL:

- Client creates a config whose "endpoint" is an x0x topic
  `a2a.push.<taskId>` (and optionally an `AgentId` to DM).
- Server publishes `statusUpdate`/`artifactUpdate` to that topic; the client
  `subscribe()`s. Works even when the client is behind NAT and not directly
  reachable — the gossip mesh delivers.
- Authenticity: push events are signed by the server agent; client verifies via
  `/agent/verify`.

## 7. Large artifacts — future increment

Artifacts exceeding the DM cap are published to a KvStore topic (`/stores`,
existing CardStore mechanism) and referenced from the A2A `Artifact` as a
`FilePart` whose URI is `x0x://store/<topic>/<key>`. Recipient fetches via the
KvStore API. Keeps the control path small and reuses replicated storage.

## 8. Intended conformance to A2A §5

- **Method coverage:** all A2A core methods (`message/send`, `message/stream`,
  `tasks/get`, `tasks/cancel`, push-config CRUD) are representable (§4-6).
- **Functional equivalence:** identical Task lifecycle and Artifact semantics;
  only carriage differs, as §5 requires for interoperable bindings.
- **Transport declaration:** advertised in the Agent Card `supportedInterfaces`
  (adapter doc), so an A2A client that lacks the x0x binding can fall back to a
  declared HTTP interface if the agent also exposes one (dual-stack agents).

## 9. Implementation surface

| Need | Existing x0x surface |
|------|----------------------|
| Send request/response/stream | `POST /direct/send` (`recipient_id`, `payload`), `RawQuicAcked` path |
| Receive | `GET /direct/events` (SSE) / `recv_direct_annotated()` |
| Push fan-out | gossip `publish`/`subscribe` |
| Large artifacts | KvStore (`/stores`, CardStore) |
| Sender authenticity | `DirectMessage.verified` + `trust_decision`; `/agent/verify` |
| Connection | `POST /agents/connect` |

`src/a2a/binding.rs` implements the envelope codec and unary correlation in
§4. Streaming/sequence bookkeeping, push notifications and large-artifact
transfer in §5-7 are not implemented by packet 1; its served Agent Card keeps
`streaming` and `pushNotifications` false. The existing transport surfaces in
the table do not themselves establish those later binding contracts.

## 10. Open questions

1. Registering the transport token (`"x0x"`) and `x0x://` URI scheme with the
   A2A community (custom-binding registry, if one emerges).
2. Whether to also expose a thin HTTP shim so unmodified A2A clients reach x0x
   agents via a local gateway (`x0xd` already runs a local REST server).
3. Backpressure/flow-control mapping for very chatty streams.
