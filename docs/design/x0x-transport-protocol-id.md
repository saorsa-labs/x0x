# x0x Transport & Identity Protocol — Internet-Draft Skeleton

> **Status:** Draft skeleton for an Independent Submission Internet-Draft.
> **Intended filename:** `draft-saorsa-x0x-agent-transport-00`
> **Date:** 2026-06-15
> **Authors:** Saorsa Labs
> **Intended status:** Experimental
>
> This document is a *working skeleton*, not the final I-D. It is structured
> section-for-section against `draft-teodor-pilot-protocol-01` ("Pilot Protocol")
> so reviewers can diff the two designs directly. Where Pilot makes a centralized
> or classical-crypto choice, the corresponding x0x section states the
> decentralized / post-quantum alternative and why.

---

## Abstract

This document specifies the x0x agent transport and identity layer: a
**decentralized, post-quantum** overlay that gives autonomous AI agents
**self-authenticating identities**, NAT-traversing reachability, and
authenticated transport primitives **without any registry, name authority, or
hosted identity document**. x0x operates as a network/transport layer beneath
application-layer agent protocols such as A2A and MCP. Unlike registry-anchored
overlays, an x0x identity is the cryptographic hash of the agent's own
ML-DSA-65 public key — there is nothing to assign, host, or revoke centrally.

## Status of This Memo

(Standard IETF boilerplate — Experimental, Independent Submission, BCP 78/79.)

---

## 1. Introduction

AI agents must communicate across cloud, edge, NAT, and organizational
boundaries. Application-layer agent protocols (MCP, A2A) standardize *tool
calling* and *task coordination* respectively, but assume the counterpart is a
reachable HTTP server. They do not standardize how agents **find and reach each
other** when they are ephemeral, mobile, behind NAT, or peer-to-peer. This is
the open "transport layer" for agents.

Two design philosophies exist for filling it:

1. **Registry-anchored overlays** (e.g. Pilot Protocol): a central registry
   issues identities and virtual addresses and resolves locators. Simple to
   bootstrap; a single trusted third party (the registry's own
   §19.5 acknowledges address-hijack, locator-spoof, and pubkey-substitution
   risk on compromise).
2. **Self-authenticating overlays** (this document): identity is derived from
   the agent's own key material; discovery is decentralized; there is no
   trusted third party to compromise.

x0x takes approach (2) and additionally is **post-quantum** end-to-end
(ML-KEM-768 key agreement, ML-DSA-65 signatures), which none of Pilot,
libp2p, A2A, or ANP currently are.

### 1.1. Relationship to Other Protocols

- **Below** A2A / MCP — x0x carries their messages; see the companion
  `a2a-over-x0x-binding.md`.
- **Comparable layer to** Pilot Protocol and libp2p.
- **Comparable identity goal to** ANP's `did:wba`, but with no DNS/HTTPS-hosted
  DID document — x0x identities are self-resolving.

## 2. Terminology

| Term | Definition |
|------|------------|
| **MachineId** | 32-byte SHA-256 of a machine's ML-DSA-65 public key. Equals the ant-quic PeerId; authenticates the QUIC transport. |
| **AgentId** | 32-byte SHA-256 of a portable agent's ML-DSA-65 public key. Stable across machines. |
| **UserId** | 32-byte SHA-256 of an optional human ML-DSA-65 public key. |
| **AgentCertificate** | A user-signed binding of AgentId → UserId (see §4.3). |
| **PeerId** | 32-byte transport identifier (== MachineId). |
| **Bootstrap peer** | A seed node used only as a connection hint (ADR-0001); NOT an identity authority. |

## 3. Architecture

Three-layer identity, one transport:

```
User (optional human) ──signs AgentCertificate──▶ binds Agent to User
   └─ Agent (portable, AgentId)
        └─ Machine (hardware-pinned, MachineId == QUIC PeerId)
Transport: QUIC (ant-quic) with native NAT traversal, PQC handshake.
Discovery: DHT-free gossip + FOAF (no registry).
```

Contrast with Pilot's single-tier registry-issued Ed25519 node identity.

## 4. Identity (vs Pilot §10.1, ANP did:wba)

### 4.1. Self-Authenticating Identifiers

Every identifier is `SHA-256(ML-DSA-65 public key)`, 32 bytes, computed by the
holder via `ant_quic::derive_peer_id_from_public_key()`. No registry issues it;
possession of the private key *is* the proof of the identifier. An observer
verifies an identifier by hashing the presented public key — no third party,
no DID document fetch, no DNS.

> **Diff vs Pilot:** Pilot's registry issues an Ed25519 keypair and holds all
> public keys. x0x has no issuer and no central public-key store.

### 4.2. Three Layers

`MachineId` / `AgentId` / `UserId` (`src/identity.rs:28-42`). Machine pins
hardware and authenticates QUIC; Agent is portable across machines; User is
optional and opt-in (never auto-generated).

### 4.3. Agent ↔ User Binding: AgentCertificate

(`src/identity.rs:410-428`.) An `AgentCertificate` binds an AgentId to a UserId.
Signed message: `b"x0x-agent-cert-v1" || user_pubkey || agent_pubkey || timestamp`,
signed by the **user's** ML-DSA-65 secret key. Fields: `user_public_key`,
`agent_public_key`, `signature`, `issued_at`. Verified with `cert.verify()`.
This is x0x's answer to "who runs this agent" without a registry record.

### 4.4. Detached Signature Verification

x0x exposes a stateless signature primitive (`POST /agent/verify`):
`algorithm = "x0x.agent-sign.v1.ml-dsa-65"`, domain framing `domain || 0x00 || payload`.
This is the building block any application uses to verify an agent's claims
offline.

## 5. Addressing (vs Pilot §4)

There is no separate virtual-address space. **The AgentId/MachineId IS the
address.** Reachability *hints* (`addresses: Vec<String>` of `IP:port`) travel
in the AgentCard (`src/groups/card.rs`) and in gossip beacons, but they are
hints, not authoritative locators — losing them does not lose the identity.

> **Diff vs Pilot:** Pilot assigns a 48-bit virtual address (16-bit Network +
> 32-bit Node) from the registry. x0x derives the address from the key; the
> 32-byte PeerId space needs no allocator.

## 6. Transport (vs Pilot §7-8)

x0x uses **QUIC** via `ant-quic`, not a hand-rolled overlay transport:

- Mature loss recovery, congestion control, and stream multiplexing (avoids
  Pilot's reimplemented TCP-style CC over UDP and the "double congestion
  control" problem Pilot's own §19.8 flags).
- PQC handshake: ML-KEM-768 key agreement, ML-DSA-65 authentication.
- Direct-message wire format on a dedicated stream type: `[0x10][sender AgentId:32][payload]`
  (`src/direct.rs`), with paths `Loopback | GossipInbox | RawQuic | RawQuicAcked`.

> **Diff vs Pilot:** Pilot encrypts with X25519/HKDF/AES-256-GCM and permits a
> **plaintext (PILT) downgrade** when key exchange is unanswered. x0x has no
> plaintext fallback and uses post-quantum primitives throughout.

## 7. NAT Traversal (vs Pilot §9)

QUIC-native NAT traversal via ant-quic (`draft-seemann-quic-nat-traversal-02`):
no STUN/ICE/TURN. NAT type is auto-detected (`node_status().nat_type()`);
bootstrap peers act as coordinators/reflectors for hole-punching, and relay is a
fallback — but coordination is over authenticated QUIC, and bootstrap peers are
seed *hints* (ADR-0001), not a trusted registry.

> **Diff vs Pilot:** Pilot uses STUN-style discovery + beacon relay keyed by the
> registry's locator lookup. x0x coordinates through interchangeable bootstrap
> hints and treats no node as authoritative.

## 8. Discovery (vs Pilot registry, ANP semantic web)

DHT-free, registry-free, partition-tolerant:

- **Social propagation** — agents share signed AgentCards in conversation.
- **Tag shards** — BLAKE3-hashed tags → PlumTree topics with CRDT OR-Set
  anti-entropy.
- **Presence + FOAF** — `POST /agents/find/:agent_id` random-walk; quality-
  weighted peer selection; trust-scoped privacy.

> **Diff vs Pilot/ANP:** Pilot resolves Node ID → endpoint at a central
> registry; ANP resolves a DID to a web-hosted `did.json`. x0x resolves through
> the mesh itself and keeps working under partition.

## 9. Security Considerations

- **No trusted third party.** The class of registry-compromise attacks Pilot
  enumerates (§19.5: address hijack, locator spoof, pubkey substitution,
  metadata harvest) does not apply — there is no registry to compromise.
- **Sender authenticity.** Transport sender (MachineId) is QUIC-authenticated;
  application sender (AgentId) is cross-checked against the identity cache and
  surfaced as `verified` + `trust_decision` on each `DirectMessage`.
- **Post-quantum.** Forward security against harvest-now-decrypt-later.
- **Open items to specify fully:** beacon-relay metadata exposure, AgentCard
  signing (currently unsigned — see §10), replay windows on `/agent/verify`.

## 10. Open Questions / TODO Before -00 Submission

1. **Sign the AgentCard.** Today `AgentCard` (`src/groups/card.rs`) is
   unsigned, unlike `GroupCard` (which carries an ML-DSA-65 authority
   signature). The I-D should require an AgentCard signature so reachability
   hints and capabilities are tamper-evident.
2. Wire-format ABNF for AgentCard, AgentCertificate, and the DM frame.
3. Canonical bytes + domain separators for every signed object.
4. IANA: media types (`application/x0x-agent-card+json`), ALPN, well-known URI
   registration (`/.well-known/x0x-agent`).
5. Decide alignment posture vs Pilot Protocol (align / contribute / differentiate)
   — see ADR-0017.

## Appendix A. Comparison Matrix

| Axis | Pilot Protocol | ANP | x0x (this doc) |
|------|----------------|-----|----------------|
| Identity | Ed25519 issued by registry | did:wba (web-hosted did.json) | SHA-256(ML-DSA-65 pubkey), self-derived |
| Address | 48-bit, registry-assigned | DID | PeerId == identity |
| Discovery | Central registry | DID resolution (DNS/HTTPS) | DHT-free gossip + FOAF |
| Transport | TCP-over-UDP overlay | HTTPS | QUIC (ant-quic) |
| NAT | STUN + beacon relay | — | QUIC-native, no STUN |
| Crypto | X25519/AES-GCM/Ed25519, plaintext fallback | classical | **PQC** ML-KEM-768/ML-DSA-65 |
| Trusted third party | Yes (registry) | Yes (DID host/DNS) | **None** |
