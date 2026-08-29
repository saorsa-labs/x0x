# ADR-0017 mechanics — implementation status & alternatives detail

> Extracted 2026-08-29 from the immutable [ADR 0017](../adr/0017-x0x-as-agent-transport-layer.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the implementation status (mutable tracking, not
> decision) and alternatives record relocated verbatim so this file is their
> maintained home — future updates belong here, not in the ADR.

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

---

## Alternatives considered

- **(A) x0x as a complete decentralized agent mesh / full-stack rival.**
  Rejected: competes with MCP+A2+everything, loses consolidation on simplicity,
  and fights libp2p head-on with no spec.
- **(B) Do nothing / stay code-only.** Rejected: cedes the standards slot to a
  weaker but *published* design (Pilot) or a libp2p-derived effort.
- **(C, chosen) Transport-layer positioning + published spec + A2A interop +
  PQC/zero-registry narrative.**
