# A05 Connectivity Discovery and Names

- **Status:** Proposed
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Pending the transfer and acceptance checks in A15.
- **Supersedes:** None yet. Existing decisions and implementation gates remain in force.

These drafts remain Proposed until David accepts the transfer (D198, D199).
Use the [index and transition rules](README.md) to interpret their status.

x0x connects verified peers and gives applications controlled byte streams and machine-service access. A working network path does not itself grant access to a service.

## Context

Devices can change address, sit behind NAT, sleep, or lose access to UDP. Users need clear connection results. Applications must not depend on one fixed bootstrap server or confuse a discovered name with verified identity.

## Decision

We will retain ant-quic as the transport boundary. It owns transport connection setup, NAT traversal and transport path management. x0x supplies identity evidence, application policy and the required application protocols.

Bootstrap nodes are seed hints. A peer with usable saved or discovered contacts must not require a global directory to communicate with those contacts.

Discovery uses authenticated information where authority is required. Unverified address hints can be tried under resource limits, but a successful connection must still prove the expected identity.

mDNS and local discovery belong in the transport layer. Avoid a second independent discovery system with conflicting peer state.

## Paths and status

Prefer a usable direct path. Use an allowed relay path when required and supported. Report which path is active, why a connection is waiting, and whether the wait can be retried.

UDP on port 443 remains UDP. It is not an HTTPS fallback and does not guarantee access through a network that blocks UDP.

A connection failure must have a bounded attempt and a queryable reason. Retry policy must avoid endless work on revoked or permanently denied peers.

The connectivity target is reliable operation across the owner's devices. Claims of better reach or lower cost than another network require measured evidence.

## Streams and machine services

Use the existing stream boundary for application byte streams. Register each protocol and apply its required authority rule.

Forwarding reaches explicitly allowed services. It does not create a general IP VPN, subnet router or exit node. Loopback target limits remain in force unless a separate accepted revision changes them.

Persistent forwards must retain their target identity. If a name later resolves to a different identity, keep the forward down until the owner approves the new binding.

An optional SOCKS interface must apply the same target restrictions and authentication. It must not silently provide arbitrary internet or local-network access.

## Names

Use owner-approved local names as labels for cryptographic identities. A display name received from the network is not a global registration.

Name resolution must show the identity selected. Stored owner and device bindings prevent a name change from redirecting access to an unrelated peer.

## Consequences

Existing peers can continue without a global directory. Discovery can still fail when no useful contact is reachable. Applications must explain path failures and keep service permissions separate from connectivity.

## Alternatives

A central coordinator can simplify discovery, but it creates a service dependency for the relationships x0x is intended to preserve.

A full IP overlay can support more applications, but it expands routing, operating-system and permission scope. We retain controlled application streams and service access.

## Current implementation

QUIC transport, discovery, streams and loopback forwarding exist. Friendly names, persistent forwards and SOCKS are a separate Phase 2 design. They must not be described as a complete shipped tailnet.

[A06](A06-r01-gossip-relay-roles-and-resource-limits.md) owns relay duties and resource limits. [A03](A03-r01-trust-permissions-sharing-and-revocation.md) owns service authority.

## Validation

Test a cold start, saved-peer start, NAT changes, packet loss, a relay path and a network that blocks UDP. Report unsupported cases clearly.

Restart a persistent forward and verify the same target identity. Change the name binding and confirm that the forward refuses the new target.

## Matters to settle

Set the supported network matrix and connection-time budgets. Decide any new relay or blocked-UDP fallback through the transport design, not a workaround in each application.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0001 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0001-bootstrap-peers-are-seed-hints-only.md) · [ADR 0002 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0002-application-level-keepalive-for-direct-connections.md) · [ADR 0003 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0003-auto-connect-to-discovered-agents.md) · [ADR 0005 Superseded](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0005-mdns-local-network-discovery.md) · [ADR 0011 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0011-bootstrap-dual-listen-udp-443.md) · [ADR 0020 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0020-tailnet-phase-1-byte-streams-and-forwarding.md) · [ADR 0022 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0022-tailnet-stream-api.md) · [ADR 0032 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0032-x0xd-443-own-identity.md) · [ADR 0049 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0049-presence-foaf-discovery.md) · [ADR 0074 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0074-tailnet-phase-2-names-persistent-forwards-socks5.md) · [ADR 0086 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0086-gossip-send-targets-bounded-by-transport-connectivity.md)

Source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Current implementation statements refer to that snapshot.

[All 15 ADRs](README.md)
