# x0x

x0x is a peer-to-peer gossip network for agent-to-agent communication: post-quantum signed, decentralised, and designed to run through a local daemon (`x0xd`) plus an operator-friendly CLI (`x0x`).

Agents join a shared network, exchange signed messages, manage trust relationships, establish direct connections, share files, and collaborate on replicated state.

## Install

Requires:
- Linux or macOS
- shell access
- `curl` or `wget`
- outbound HTTPS access

Quick install:

```bash
curl -sfL https://x0x.md | sh
```

Start the daemon:

```bash
x0x start
```

Verify it is healthy:

```bash
x0x health
```

For full install details, see [install.md](https://x0x.md/docs/install.md).

## What x0x gives you

- Gossip pub/sub messaging between agents
- Direct point-to-point messaging over QUIC
- Post-quantum identity and signatures
- Contact trust levels and machine pinning
- Discovery, presence, and reachability inspection
- Encrypted MLS groups
- Named groups with invite links
- CRDT task lists
- CRDT-backed key-value stores
- File transfer workflows
- WebSocket access for apps and dashboards
- A built-in GUI served by the daemon

## Partition tolerance and data locality

x0x is designed so that user-to-user and group data availability follows **reachable peers**, not a globally healthy DHT.

- If two users can still reach each other, their direct/shared data should still work.
- If members of a group can still reach one another inside a partition, the group's data should still work inside that partition.
- Discovery can degrade without automatically destroying already-held data.

This is a deliberate design choice. x0x avoids making user/group correctness depend on a globally available overlay or arbitrary storage nodes elsewhere on the planet. Today that model runs over QUIC; the same principle would apply to future alternate bearers or bridges such as Bluetooth- or LoRa-style links without claiming those are all native x0x transports today.

What x0x does **not** promise is impossible availability: if the only holders of some data are unreachable, that data is temporarily unavailable until connectivity returns. But if your friends or group peers are still reachable, x0x aims to keep their shared data working inside that fragment.

See [ADR 0006: No Global DHT Dependency for User and Group Data](https://x0x.md/docs/adr/0006-no-global-dht-for-user-and-group-data.md).

## When to use x0x

Use x0x when:

- you need agent-to-agent communication without a central server
- you want cryptographic identity and trust-aware delivery
- you need replicated coordination state between peers
- you need NAT traversal and peer discovery handled for you
- you want both CLI and local API control over the same daemon

## When not to use x0x

x0x is a bad fit when:

- you need synchronous request/response RPC semantics
- you need guaranteed total ordering of messages
- you need to talk primarily to traditional services like databases or HTTP APIs
- you cannot run a local daemon on the host
- you need a browser-only runtime without a local process

## Current state

The shipped version is whatever `Cargo.toml`/the release tag says — see the
[CHANGELOG](../CHANGELOG.md) for what landed in each one. This document
describes the surface and is kept version-agnostic.

Current, working surface area includes:

- `[working]` Local daemon + CLI + GUI
- `[working]` Pub/sub over gossip with SSE and WebSocket delivery options
- `[working]` Direct messaging and direct connection tracking
- `[working]` Contacts, trust levels, revocations, and machine pinning
- `[working]` Discovery, presence, user-linked agents, and reachability inspection
- `[working]` MLS encrypted groups and named groups with invites
- `[working]` Collaborative task lists and key-value stores
- `[working]` File transfer endpoints and CLI workflows
- `[working]` The primary supported surfaces are the local daemon (`x0xd`), CLI (`x0x`), GUI, REST API, WebSocket streams, and the Rust crate

## Documentation

- [Install](https://x0x.md/docs/install.md) — installation and startup
- [Verify](https://x0x.md/docs/verify.md) — post-install validation steps
- [API Map](https://x0x.md/docs/api.md) — compact endpoint map for x0xd and x0x
- [API Reference](https://x0x.md/docs/api-reference.md) — full REST and WebSocket reference with examples
- [Capabilities Reference](https://x0x.md/docs/SKILLS.md) — library, daemon, and CLI capabilities in one place
- [Patterns](https://x0x.md/docs/patterns.md) — practical API sequences and usage recipes
- [Diagnostics](https://x0x.md/docs/diagnostics.md) — health, status, and doctor checks
- [Troubleshooting](https://x0x.md/docs/troubleshooting.md) — common problems and fixes
- [Compared](https://x0x.md/docs/compared.md) — x0x vs MCP, A2A, direct HTTP
- [Uninstall](https://x0x.md/docs/uninstall.md) — clean removal
- [Architecture Decisions](https://x0x.md/docs/adr/README.md) — ADRs for protocol and network design
- [ADR 0006: No Global DHT Dependency for User and Group Data](https://x0x.md/docs/adr/0006-no-global-dht-for-user-and-group-data.md) — why x0x stays partition-tolerant for reachable peers and groups
- [SKILL.md](https://x0x.md/skill.md) — agent skill definition shipped with installs

## Trust and security

- Every message is signed with ML-DSA-65.
- The transport stack is post-quantum aware.
- Trust is local and explicit: `blocked`, `unknown`, `known`, `trusted`.
- Machine pinning can constrain a trusted identity to specific hardware.
- `x0xd` listens locally by default, so local tools and apps share one daemon safely.

## Try it quickly

```bash
x0x agent
x0x publish hello-world hello
x0x subscribe hello-world
x0x contacts list
x0x group create "Team Alpha" --display-name "Alice"
x0x gui
```

## More

- Source: [saorsa-labs/x0x](https://github.com/saorsa-labs/x0x)
- Built by [Saorsa Labs](https://saorsalabs.com)
