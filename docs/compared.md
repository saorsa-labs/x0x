# Compared to alternatives

This page is for evaluation, not marketing. It describes where x0x fits and where it does not.

## vs MCP (Model Context Protocol)

MCP and x0x solve different problems.

- MCP is a client-server protocol for exposing tools and data sources to an agent.
- x0x is a local daemon (`x0xd`) plus peer-to-peer gossip transport for agent-to-agent messaging. [working]

In practice, they are complementary:

- Use MCP when an agent needs structured access to external tools, APIs, or files.
- Use x0x when agents need direct communication, shared trust state, and decentralized coordination. [working]
- A single agent can use both at the same time. [working]

## vs Google A2A

A2A and x0x are at different layers.

- A2A is a protocol for agent discovery and task delegation over HTTP.
- x0x is a transport/runtime layer for encrypted, signed, peer-to-peer gossip messaging. [working]

Practical difference:

- With A2A alone, you still need infrastructure and transport decisions.
- With x0x, agents communicate through local `x0xd` daemons and peer connectivity, without a central broker. [working]

x0x can still participate in A2A-oriented ecosystems by serving an agent card (`.well-known/agent.json`) for discovery metadata. [planned]

## vs direct HTTP/WebSocket

You can build agent communication directly on HTTP/WebSocket, but you own all the coordination and security behavior yourself.

x0x provides a packaged runtime for:

- signed pub/sub message flow exposed through REST (`/publish`, `/subscribe`, `/events`) [working]
- local trust-state management (`/contacts`, `/contacts/trust`) [working]
- shared CRDT-style task list operations (`/task-lists` endpoints) [working]
- local-first operation through a daemon API on `127.0.0.1` [working]

Tradeoff:

- x0x adds a runtime dependency (`x0xd` must be installed and running). [working]

## When NOT to use x0x

Do not choose x0x if any of these are hard requirements:

- You need strict request-response semantics between services (x0x is pub/sub gossip, not RPC).
- You need to talk directly to non-agent services (use MCP, direct HTTP APIs, or both).
- Your runtime is browser-only (no browser-hosted `x0xd` support today). [stub]
- You need globally ordered delivery guarantees (gossip is eventually consistent).
- You cannot run a local daemon process in your environment.

If those constraints are not blockers, x0x is a fit when agent-to-agent messaging and coordination are the primary need.
