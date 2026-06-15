# A2A Agent Card Adapter

> **Status:** Design sketch.
> **Date:** 2026-06-15
> **Relates to:** A2A spec §8 (Agent Discovery / Agent Card), §4.4 (AgentSkill);
> `a2a-over-x0x-binding.md`; x0x `AgentCard` at `src/groups/card.rs:17-54`.

## 1. Purpose

Make an x0x agent **discoverable by the A2A ecosystem** (150+ orgs) by serving
an A2A-conformant Agent Card derived from x0x's existing `AgentCard`. This is
the *discovery* half of A2A interop; the `a2a-over-x0x-binding.md` is the
*delivery* half. The adapter is a serialization shim over data the daemon
already holds — no new identity or storage.

## 2. Discovery endpoint (new route)

x0x has **no `/.well-known/` route today**. Add one:

```
GET /.well-known/agent-card.json   →  A2A AgentCard (application/json)
```

This is the A2A §8.2 "Well-Known URI" mechanism. For agents reachable only over
x0x (no public HTTPS), the same JSON is also retrievable via the existing
`GET /agent/card` (which returns the x0x card link) by content negotiation or a
sibling `GET /agent/card/a2a` route. Registries (§8.2) can index the card.

## 3. Field mapping: x0x `AgentCard` → A2A `AgentCard`

| A2A field | Source from x0x | Notes |
|-----------|-----------------|-------|
| `name` | `display_name` | direct |
| `description` | derived | from groups/stores summary or static config |
| `version` | x0xd build version | |
| `url` / `supportedInterfaces[].url` | `x0x://agent/<base64url card>` | from `AgentCard.to_link()` |
| `supportedInterfaces[].transport` | `"x0x"` | declares the A2A-over-x0x binding (binding doc) |
| `provider` | `user_id` (if present) → org/name | optional human identity |
| `skills[]` | `stores`, `groups`, exec capability | see §4 |
| `securitySchemes` | x0x QUIC ML-DSA + AgentCertificate | see §5 |
| `capabilities.streaming` | `true` | x0x supports stream DMs |
| `capabilities.pushNotifications` | `true` | via gossip topic (binding §6) |
| `defaultInputModes` / `defaultOutputModes` | `["text/plain","application/json"]` | configurable |
| (x0x extension) `x0xAgentId` | `agent_id` | 32-byte hex; the real address |
| (x0x extension) `x0xMachineId` | `machine_id` | hex |
| (x0x extension) `x0xUserId` | `user_id` | hex, optional |
| (x0x extension) `x0xCertificate` | `AgentCertificate` (b64) | proves Agent→User binding |

A2A's `AgentCard` is open to vendor extensions; x0x-native fields live under an
`x0x`-prefixed namespace so generic A2A clients ignore them while x0x-aware
clients get the self-authenticating identity.

## 4. Deriving A2A `AgentSkill[]`

A2A `AgentSkill` requires `id`, `name`, `description`, `tags` (§4.4). Map x0x
capabilities to skills:

- **Each `CardStore`** → a skill `{ id: "kv:<topic>", name, description:"Replicated KV store", tags:["storage","x0x-kvstore"] }`.
- **Each `CardGroup`** → a skill `{ id:"group:<group_id>", tags:["collaboration","x0x-group"] }` (only public/discoverable groups).
- **Exec (if `[exec].enabled`)** → skill `{ id:"exec", tags:["compute"], securityRequirements:[exec-acl] }` — but gate disclosure behind ACL (do not advertise exec to unauthenticated callers).
- **Static skills** → from daemon config for app-specific agent capabilities.

## 5. Security schemes (A2A §4.5)

A2A expresses auth as a discriminated `SecurityScheme` (apiKey / http / oauth2 /
openIdConnect / mtls). x0x's native auth doesn't fit those, so:

- Declare a **custom/extension scheme** `x0x-agent-identity` documenting that the
  binding authenticates via the QUIC ML-DSA-65 handshake + `AgentCertificate`,
  verifiable through `/agent/verify`.
- For **dual-stack** agents that also expose HTTP A2A, additionally declare the
  real HTTP scheme (e.g. `oauth2`) so non-x0x clients can authenticate the
  classical way.

## 6. Signing the card (dependency on the I-D's open item)

Today x0x `AgentCard` is **unsigned** (unlike `GroupCard`, which carries an
ML-DSA-65 authority signature). For the served A2A card to be tamper-evident,
add an `x0xSignature` field over the canonical card bytes, signed by the agent
key (reuse `/agent/sign`, verify via `/agent/verify`). This is the same open
item flagged in `x0x-transport-protocol-id.md` §10.1 — do it once, both consume
it.

## 7. Implementation surface

| Need | Existing surface |
|------|------------------|
| Source card data | `GET /agent/card`, `GET /agent` (`src/groups/card.rs`, `src/api/mod.rs`) |
| Identity fields | `agent_id()`, `machine_id()`, `user_id()`, `agent_certificate()` |
| Sign / verify | `POST /agent/sign`, `POST /agent/verify` |
| New work | one route (`/.well-known/agent-card.json`) + a pure `AgentCard → A2AAgentCard` mapping function + the card-signing field (§6) |

## 8. Open questions

1. Exact A2A schema version to target (track the `a2a-protocol.org` spec; it has
   moved fast since April 2025).
2. How much of `groups`/`stores` to expose publicly vs behind trust scope
   (privacy — mirror presence `Network` vs `Social` visibility).
3. Whether the well-known route should require the daemon to be intentionally
   "published" (opt-in), to avoid leaking private agents.
