# ADR-0001 mechanics — Decentralization follow-up plan and acceptance criteria

> Extracted 2026-08-29 from the immutable [ADR 0001](../adr/0001-bootstrap-peers-are-seed-hints-only.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the staged plan (Phases 2–5) and acceptance criteria
> relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

### Phase 2: Signed capability advertisements

- Extend the existing signed rendezvous advertisement flow to carry coordinator and relay capability metadata.
- Publish only expiring, signed advertisements.
- Admit nodes into the local coordinator pool only after signature and freshness validation.

---

### Phase 3: Dynamic coordinator and relay selection

- Prefer validated dynamic coordinator candidates over static seed hints.
- Use static seed hints only as cold-start or empty-pool fallback.
- Allow ordinary publicly reachable `x0xd` instances to enter the coordinator and relay pool automatically once validated.

---

### Phase 4: Decentralized release propagation

- Treat `ReleaseNotification` as a discovery hint, not an authority.
- Require each node to independently fetch and verify the canonical release artifact before apply or rebroadcast.
- Allow any verifying node to rebroadcast release hints.

---

### Phase 5: Re-scope `x0xd`

- Keep `x0xd` only as optional operational packaging for stable public seeds, health endpoints, and managed restarts.
- Do not require `x0xd` for protocol correctness, reachability, or upgrade authority.

---

## Acceptance Criteria

This ADR is satisfied only when all of the following are true:

- a node can rejoin from cached peers without contacting the default seed list;
- ordinary publicly reachable nodes can advertise signed coordinator and relay capability;
- steady-state coordinator selection prefers validated dynamic peers over static seed hints;
- release propagation does not depend on `x0xd` nodes being the primary broadcasters; and
- loss of the default Saorsa-operated seed set degrades cold-start convenience, not network legitimacy or steady-state operation.
