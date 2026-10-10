# ADR 0017: Position x0x as the agent transport layer (spec + A2A interop + PQC/zero-registry positioning)

<!-- File name: docs/adr/0017-x0x-as-agent-transport-layer.md -->

- **Status:** Accepted (2026-06-15) — foundation implemented
- **Date:** 2026-06-15
- **Decision owners:** David Irvine
- **Reviewers:** TBD
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [ADR 0001](./0001-bootstrap-peers-are-seed-hints-only.md) (bootstrap = hints, not authority); [ADR 0011](./0011-multi-port-bootstrap.md) (UDP/443 strategy); `docs/design/x0x-transport-protocol-id.md`; `docs/design/a2a-over-x0x-binding.md`; `docs/design/a2a-agent-card-adapter.md`
- **Follow-up issues:** [#112](https://github.com/saorsa-labs/x0x/issues/112) (A2A-over-x0x message binding, workstream #3); [#113](https://github.com/saorsa-labs/x0x/issues/113) (publish transport+identity Internet-Draft, workstream #1)
- **Shipped in:** v0.24.0 (signed AgentCard + A2A discovery card)

## Context

The AI-agent protocol stack is mid-proliferation and is settling into distinct
**layers**, not competitors for one slot:

- **MCP** (Anthropic, late 2024) won the **tool-calling** layer (10k+ public
  servers, 164M monthly Python SDK downloads by Apr 2026).
- **A2A** (Google, Apr 2025; Linux Foundation since Jun 2025; 150+ orgs) won the
  **task-coordination** layer.
- The **transport** layer — how agents find and reach each other across NAT,
  ephemerality, and org boundaries — is ~18–24 months behind and still open.
  (Framing: VentureBeat, "MCP solved tool calling. A2A solved coordination. What
  solves transport?", Jun 2026.)

MCP, A2A, and ANP all assume the peer is a reachable HTTP server. The named
transport-layer candidates are:

- **Pilot Protocol** (`draft-teodor-pilot-protocol-01`, Experimental, expires
  Oct 2026): an overlay with a **central registry** that issues Ed25519
  identities + 48-bit virtual addresses and resolves locators; **classical**
  crypto (X25519/AES-GCM/Ed25519) with a **plaintext downgrade**; TCP
  reimplemented over UDP. Its own §19.5 admits the registry is a single trusted
  third party (address hijack / locator spoof / pubkey substitution on
  compromise).
- **libp2p**: battle-tested incumbent with large ecosystem gravity, classical
  crypto.
- **ANP**: decentralized identity via `did:wba`, but anchored to a DNS/HTTPS-
  hosted `did.json`.

x0x already *is* a transport-layer system — `ant-quic` QUIC with native NAT
traversal (no STUN/ICE/TURN), DHT-free gossip/FOAF discovery, and
**self-authenticating post-quantum identity** (SHA-256 of ML-DSA-65 keys; no
registry, no DNS, no hosted document). On the axes these candidates compete on,
x0x is the most decentralized and the only post-quantum option.

But standards slots consolidate around **published, citable specs** (REST won
partly by being a legible HTTP-native spec). Pilot has a (weak, centralized)
Internet-Draft; **x0x has strong running code and no published spec.** A weaker
design with an I-D can capture mindshare before a stronger implementation that
never wrote one.

## Decision

Position x0x explicitly as the **transport layer beneath** MCP/A2A — not as a
rival full-stack agent protocol — and pursue three workstreams:

1. **Publish a spec.** Author an Independent-Submission Internet-Draft for x0x's
   transport + identity model, PQC-native and structured to diff directly
   against Pilot Protocol. Skeleton: `docs/design/x0x-transport-protocol-id.md`.
2. **Ship A2A interop** so x0x agents are first-class A2A citizens:
   - *Delivery:* the A2A-over-x0x custom transport binding (A2A §12) —
     `docs/design/a2a-over-x0x-binding.md`.
   - *Discovery:* the A2A Agent Card adapter served at
     `/.well-known/agent-card.json` — `docs/design/a2a-agent-card-adapter.md`.
3. **Lead the narrative with the two differentiators no candidate has:**
   **post-quantum** crypto and **zero-registry, self-authenticating
   decentralization** (directly answering Pilot's admitted registry SPOF and
   ANP's DNS dependency).

Decentralization ranking we will assert and defend:
**Pilot (central registry) < ANP (web-hosted did:wba) < x0x (self-authenticating, no host/registry/DNS).**

## Implementation status (2026-06-15)

Foundation shipped on branch `feat/adr-0017-agentcard-signing-a2a-card`:

- **Signed AgentCard** — `AgentCard` now carries `agent_public_key` + `signature`
  (`src/groups/card.rs`), signed with the agent's ML-DSA-65 key over canonical
  length-prefixed bytes, mirroring the `GroupCard` scheme. `GET /agent/card`
  signs; `POST /agent/card/import` verifies and rejects tampered signed cards;
  legacy unsigned cards still parse.
- **A2A Agent Card adapter** — `src/a2a/mod.rs` maps `AgentCard` → A2A Agent Card
  (skills from stores/groups, exec gated on config, x0x-namespaced extensions),
  served at `GET /.well-known/agent-card.json`.
- **Verification:** `fmt` clean, `clippy --all-features --all-targets -D warnings`
  clean, full workspace suite green (9 new tests: 5 card-signing + 4 adapter).

Deferred (tracked follow-up): workstream #3, the A2A-over-x0x message binding
(`docs/design/a2a-over-x0x-binding.md`, [#112](https://github.com/saorsa-labs/x0x/issues/112))
— it needs a live A2A peer for true cross-client validation. The I-D
(`docs/design/x0x-transport-protocol-id.md`,
[#113](https://github.com/saorsa-labs/x0x/issues/113)) remains a skeleton
pending standards engagement.

## Consequences

**Positive**
- Converts x0x's engineering lead into the artifact (a spec) that actually wins
  consolidation, while the slot is still open and Pilot's draft is expiring.
- Riding A2A (the won coordination layer) instead of fighting it is the
  lowest-risk adoption path; the binding + adapter reuse existing x0x surfaces
  (`/direct/send`, `/direct/events`, gossip, KvStore, `/agent/verify`) — little
  new machinery (Rule 2: simplicity).
- A clear, defensible PQC + zero-registry story differentiates from libp2p's
  ecosystem gravity.

**Negative / risks**
- Spec authoring + standards engagement is sustained effort outside the codebase.
- Scope discipline required: the transport story must be **cleanly separable**
  from x0x's discovery/group/CRDT layers, or adopters won't recognize x0x as
  "just transport" and we risk being the over-complete CORBA of agent transport.
- A2A schema moves fast; the adapter/binding must track `a2a-protocol.org`.

**Required follow-up work surfaced by the design docs**
- **Sign the `AgentCard`.** It is currently unsigned (`src/groups/card.rs`),
  unlike the signed `GroupCard`. Both the I-D (§10.1) and the Agent Card adapter
  (§6) depend on a tamper-evident card. This is the first concrete code task.
- Decide alignment posture toward Pilot Protocol (align / contribute /
  differentiate) before -00 submission.
- IANA/registry items: media types, ALPN, `x0x://` URI scheme, well-known URI.

## Alternatives considered

- **(A) x0x as a complete decentralized agent mesh / full-stack rival.**
  Rejected: competes with MCP+A2+everything, loses consolidation on simplicity,
  and fights libp2p head-on with no spec.
- **(B) Do nothing / stay code-only.** Rejected: cedes the standards slot to a
  weaker but *published* design (Pilot) or a libp2p-derived effort.
- **(C, chosen) Transport-layer positioning + published spec + A2A interop +
  PQC/zero-registry narrative.**
