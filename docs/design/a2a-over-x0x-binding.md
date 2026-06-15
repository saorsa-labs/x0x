# A2A-over-x0x Transport Binding

> **Status:** Design sketch.
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

The A2A JSON-RPC envelope is reused verbatim as the payload; only the carriage
changes. This keeps the binding thin and conformant.

## 3. Addressing & Discovery

- An A2A-over-x0x agent is addressed by its `AgentId`, expressed as
  `x0x://agent/<base64url-card>` (the existing `AgentCard.to_link()`).
- The agent advertises this binding in its A2A Agent Card via
  `supportedInterfaces` (see `a2a-agent-card-adapter.md`), with a transport
  token such as `transport: "x0x"` and `url: "x0x://agent/<id>"`.
- Discovery uses x0x's existing mechanisms (`/agents/find/:agent_id` FOAF,
  social card exchange) — no registry, no DNS.

## 4. Unary methods (message/send, tasks/get, tasks/cancel, …)

Carried as request/response over a `RawQuicAcked` direct message:

```
A2A client                                   A2A server (x0x agent)
   │  DM payload = {                              │
   │    "x0xBinding": "a2a/1",                    │
   │    "corrId": "<uuid>",                       │
   │    "kind": "request",                        │
   │    "jsonrpc": { ...verbatim A2A JSON-RPC... }│
   │  }                                           │
   ├─────── send_direct(serverAgentId) ──────────▶
   │                                              │ process; produce A2A result
   ◀────── DM { corrId, kind:"response", jsonrpc:{result|error} } ─┤
```

- Correlation: `corrId` ties response to request (DM has no native req/resp).
- Delivery proof: `RawQuicAcked` provides application-layer ACK; on timeout the
  client MAY retry with the same `corrId` (idempotent on the server by `corrId`).
- Max payload: 16 MB per `MAX_DIRECT_PAYLOAD_SIZE`. Larger artifacts use §7.

## 5. Streaming (message/stream)

A2A streaming yields a sequence of `Task` / `statusUpdate` / `artifactUpdate`
events. Over x0x:

- Open with a `request` DM carrying the A2A `message/stream` call and
  `"stream": true`.
- Server emits a sequence of `RawQuicAcked` DMs, each
  `{ corrId, kind:"stream", seq:N, jsonrpc:{ <event> } }`, terminated by
  `{ corrId, kind:"stream-end", seq:N+1 }`.
- `seq` gives ordering/gap detection; `RawQuicAcked` gives reliability. This is
  the x0x equivalent of A2A's SSE event stream.

## 6. Push notifications (long-running tasks, disconnected client)

A2A push config (`CreateTaskPushNotificationConfig`, …) maps to a **gossip
topic** instead of a webhook URL:

- Client creates a config whose "endpoint" is an x0x topic
  `a2a.push.<taskId>` (and optionally an `AgentId` to DM).
- Server publishes `statusUpdate`/`artifactUpdate` to that topic; the client
  `subscribe()`s. Works even when the client is behind NAT and not directly
  reachable — the gossip mesh delivers.
- Authenticity: push events are signed by the server agent; client verifies via
  `/agent/verify`.

## 7. Large artifacts

Artifacts exceeding the DM cap are published to a KvStore topic (`/stores`,
existing CardStore mechanism) and referenced from the A2A `Artifact` as a
`FilePart` whose URI is `x0x://store/<topic>/<key>`. Recipient fetches via the
KvStore API. Keeps the control path small and reuses replicated storage.

## 8. Conformance to A2A §5

- **Method coverage:** all A2A core methods (`message/send`, `message/stream`,
  `tasks/get`, `tasks/cancel`, push-config CRUD) are representable (§4-6).
- **Functional equivalence:** identical Task lifecycle and Artifact semantics;
  only carriage differs, as §5 requires for interoperable bindings.
- **Transport declaration:** advertised in the Agent Card `supportedInterfaces`
  (adapter doc), so an A2A client that lacks the x0x binding can fall back to a
  declared HTTP interface if the agent also exposes one (dual-stack agents).

## 9. Implementation surface (reuse, don't add)

| Need | Existing x0x surface |
|------|----------------------|
| Send request/response/stream | `POST /direct/send` (`recipient_id`, `payload`), `RawQuicAcked` path |
| Receive | `GET /direct/events` (SSE) / `recv_direct_annotated()` |
| Push fan-out | gossip `publish`/`subscribe` |
| Large artifacts | KvStore (`/stores`, CardStore) |
| Sender authenticity | `DirectMessage.verified` + `trust_decision`; `/agent/verify` |
| Connection | `POST /agents/connect` |

A reference implementation is mostly an A2A JSON-RPC envelope codec plus the
correlation/seq bookkeeping in §4-6 — no new transport machinery.

## 10. Open questions

1. Registering the transport token (`"x0x"`) and `x0x://` URI scheme with the
   A2A community (custom-binding registry, if one emerges).
2. Whether to also expose a thin HTTP shim so unmodified A2A clients reach x0x
   agents via a local gateway (`x0xd` already runs a local REST server).
3. Backpressure/flow-control mapping for very chatty streams.
