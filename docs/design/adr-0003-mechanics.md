# ADR-0003 mechanics — Approach rationale and trade-offs

> Extracted 2026-08-29 from the immutable [ADR 0003](../adr/0003-auto-connect-to-discovered-agents.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the rationale narrative and trade-off detail relocated
> verbatim so this file is their maintained home — future updates belong here,
> not in the ADR.

## Why This Approach

### Consistent with ADR-0001

ADR-0001 establishes that bootstrap peers are seed hints, not a privileged control
plane. Auto-connect extends this philosophy: bootstrap nodes help agents discover
each other, then agents connect directly. The bootstrap's role ends once the
introduction is made.

### Discovery Drives Connectivity

The alternative — a separate peer introduction protocol or explicit connection
management — would add complexity without benefit. The identity announcement already
contains everything needed to connect (address + transport peer ID). Acting on that
information immediately is the simplest path from discovery to connectivity.

### Gossip Handles the Rest

PlumTree's eager peer refresh means we only need to establish the QUIC connection.
Topic routing, message forwarding, and peer management are handled by the existing
1-second refresh loop. This keeps the auto-connect code minimal (~25 lines) and
avoids duplicating gossip overlay logic.

---

## Trade-offs

- **Connection storms in large networks**: With N agents, each could try to connect
  to all N-1 discovered agents. The `HashSet` deduplication prevents repeated
  attempts to the same agent, and `is_connected()` prevents redundant connections.
  For larger networks, a connection cap or selective connection strategy may be
  needed — but the current guards are sufficient for the near term.

- **One-directional initiation**: Only the discovering agent initiates the connection.
  If agent A discovers agent B first, A connects to B. B may also discover A and
  attempt to connect, but the `is_connected()` guard skips it since the connection
  already exists. This is efficient — exactly one connection per agent pair.

- **Depends on gossip propagation**: Auto-connect only fires when an identity
  announcement reaches the agent via gossip. If gossip routing is broken (e.g.,
  bootstrap nodes can't forward), auto-connect never fires. This is acceptable
  because if gossip doesn't work, there's nothing useful to do with the connection
  anyway.
