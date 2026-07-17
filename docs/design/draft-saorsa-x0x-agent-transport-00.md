# x0x Agent Transport and Identity Protocol

## draft-saorsa-x0x-agent-transport-00

| | |
|---|---|
| **Submission** | Independent Submission |
| **Intended status** | Experimental |
| **Date** | 2026-07-17 |
| **Expires** | 2027-01-18 |
| **Authors** | Saorsa Labs |
| **Implementation** | `x0x` (Rust), <https://github.com/saorsa-labs/x0x>, commit `a939f47` (`origin/main`, 2026-07) |

> This document is the submission candidate produced for GitHub issue #113
> (ADR-0017 workstream #1). Every byte layout, length prefix, endianness,
> domain separator, and version constant below was transcribed from the
> reference implementation source; Appendix A maps each specified object to
> its defining `file:line`. Where this document and the code disagree, the
> code is authoritative and this document is wrong — please file an issue.

---

## Abstract

This document specifies the x0x agent transport and identity layer: a
decentralized, post-quantum overlay that gives autonomous AI agents
self-authenticating identities, NAT-traversing reachability, and
authenticated transport primitives without any registry, name authority, or
hosted identity document. An x0x identifier is the SHA-256 hash of the
holder's own ML-DSA-65 public key (FIPS 204); there is nothing to assign,
host, or revoke centrally. Transport confidentiality and authenticity are
post-quantum end to end: the QUIC handshake uses ML-KEM-768 (FIPS 203) key
encapsulation with ML-DSA-65 raw-public-key authentication, and every
application-layer signed object (identity cards, certificates, direct
messages, gossip frames) is signed with ML-DSA-65 over domain-separated
canonical bytes. x0x operates as a network/transport layer beneath
application-layer agent protocols such as A2A and MCP. This document
specifies the identity model, the transport, the wire formats with ABNF,
the canonical bytes and domain separators for every signed object, the NAT
traversal design, and the security and IANA considerations, and it diffs
the design against draft-teodor-pilot-protocol-01.

## Status of This Memo

This document is not an Internet Standards Track specification; it is
published for examination, experimental implementation, and evaluation.

This document is an Independent Submission to the RFC Editor. It does not
define an Internet standard of any kind and does not represent IETF
consensus.

Internet-Drafts are working documents valid for a maximum of six months
and may be updated, replaced, or obsoleted at any time. It is
inappropriate to use Internet-Drafts as reference material or to cite them
other than as "work in progress."

This Internet-Draft will expire on 18 January 2027.

## Copyright Notice

Copyright (c) 2026 IETF Trust and the persons identified as the document
authors. All rights reserved.

This document is subject to BCP 78 and the IETF Trust's Legal Provisions
Relating to IETF Documents (<https://trustee.ietf.org/license-info>) in
effect on the date of publication of this document.

---

## 1. Introduction

AI agents must communicate across cloud, edge, NAT, and organizational
boundaries. Application-layer agent protocols — MCP for tool calling, A2A
for task coordination — standardize what agents say, but both assume the
counterpart is a reachable HTTP server. They do not standardize how agents
*find and reach each other* when they are ephemeral, mobile, behind NAT,
or peer-to-peer. That transport layer is the open slot in the agent
protocol stack. This document fills it.

### 1.1. Design Differentiators

Two properties define x0x and are stated first because every later section
depends on them:

1. **Post-quantum end to end.** All key establishment is ML-KEM-768
   (FIPS 203) and all signatures are ML-DSA-65 (FIPS 204) — in the QUIC
   handshake, in application-layer signed objects, and in direct-message
   payload encryption. There is no classical algorithm suite and no
   plaintext downgrade path anywhere in the protocol.
2. **Zero-registry, self-authenticating identity.** An x0x identifier is
   derived by hashing the holder's own ML-DSA-65 public key (Section
   4.1). No registry issues identifiers, no DNS name or hosted document
   anchors them, and possession of the private key *is* the proof of the
   identifier. There is no trusted third party whose compromise could
   hijack addresses, spoof locators, or substitute public keys.

No other published candidate for the agent transport layer — Pilot
Protocol [PILOT], libp2p, ANP — has either property today; none has both.

### 1.2. Alignment Posture Toward Pilot Protocol

ADR-0017 (docs/adr/0017-x0x-as-agent-transport-layer.md) requires an
explicit align / contribute / differentiate decision before -00
submission. **Decision: differentiate at the trust and cryptographic
architecture; align at the layer definition; contribute through
publication and interop.** Rationale:

- **Alignment of wire or trust models is not possible.** Pilot's
  identifiers and 48-bit virtual addresses are *issued by a central
  registry* ([PILOT] §10.1); x0x identifiers are *derived from the
  holder's key* (Section 4.1). These are mutually exclusive trust roots.
  Adopting Pilot's formats would import the single trusted third party
  that x0x exists to eliminate; adopting x0x's would dissolve Pilot's
  registry. No middle wire format exists.
- **There is no cryptographic intersection.** Pilot encrypts with
  X25519/HKDF/AES-256-GCM, signs with Ed25519, and permits a plaintext
  (PILT) fallback when key exchange is unanswered ([PILOT] §7.1, §10.2).
  x0x negotiates ML-KEM-768/ML-DSA-65 exclusively and has no plaintext
  mode. Two endpoints cannot interop without a gateway that terminates
  both security domains.
- **The transport substrates differ.** Pilot reimplements TCP (handshake,
  RTO, SACK, congestion control, TIME_WAIT) over UDP datagrams and flags
  the resulting double congestion control as a known issue ([PILOT]
  §8, §19.8). x0x runs QUIC [RFC9000] via ant-quic and gets loss
  recovery, congestion control, and stream multiplexing from the
  transport itself.
- **What is shared is the layer.** Both protocols position themselves as
  the transport beneath A2A and MCP, and both state that application-
  layer protocols remain unchanged above them. x0x aligns on exactly
  this: terminology ("agent transport layer"), the layering claim, and
  A2A/MCP compatibility (Section 3.2). x0x's A2A Agent Card adapter and
  A2A-over-x0x binding (docs/design/a2a-agent-card-adapter.md,
  docs/design/a2a-over-x0x-binding.md; issue #112) make x0x agents
  first-class A2A citizens — the same ecosystem Pilot targets.
- **Contribution is via publication.** Pilot's own security
  considerations name distributed-registry designs as future work
  ([PILOT] §19.5). This document publishes a complete, implemented,
  self-authenticating alternative; it is offered as prior art and input
  to any future standardization of the agent transport layer. Section 12
  is the factual diff.

This document is therefore structured section-for-section so reviewers
can diff it against [PILOT] directly.

### 1.3. Relationship to Other Protocols

- **Below A2A / MCP.** x0x carries their messages; it defines no task or
  tool semantics.
- **Same layer as** Pilot Protocol [PILOT] and libp2p.
- **Same identity goal as** ANP's `did:wba`, but with no DNS/HTTPS-hosted
  DID document: x0x identifiers are self-resolving (Section 4.1).

## 2. Conventions and Terminology

### 2.1. Requirements Language

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**",
"**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**",
"**NOT RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document are
to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and
only when, they appear in all capitals, as shown here.

### 2.2. Notation

Byte strings are written `b"..."`. `||` is concatenation. Wire grammars
use ABNF [RFC5234] extended with these terminal rules:

```abnf
octet        =  %x00-FF
u16be        =  2OCTET          ; unsigned 16-bit, big-endian
u32be        =  4OCTET          ; unsigned 32-bit, big-endian
u32le        =  4OCTET          ; unsigned 32-bit, little-endian
u64be        =  8OCTET          ; unsigned 64-bit, big-endian
u64le        =  8OCTET          ; unsigned 64-bit, little-endian
lp32le(B)    =  u32le B         ; u32le length of B in bytes, then B
lp64le(B)    =  u64le B         ; u64le length of B in bytes, then B
varint       =  1*10OCTET       ; LEB128: 7 payload bits/byte,
                                ; high bit = continuation
postcard-var-len(B) = varint B  ; postcard varint length, then B
```

Three serialization codes appear in this document; every object states
which it uses:

- **Explicit layout** — fields appended in a stated order with the
  stated fixed encodings (used for all signature inputs).
- **bincode 1.3** (default options: little-endian, fixint) —
  `Vec<T>`/`String` as `lp64le`, `Option<T>` as one tag octet
  (%x00 = None, %x01 = Some) followed by `T` when present, `bool` as one
  octet, enum discriminant as `u32le`, fixed arrays raw, integers
  little-endian. Used for `AgentCertificate` storage/gossip encoding and
  announcement signed bytes.
- **postcard 1.x** — integers (`u16`/`u32`/`u64`/`usize`) and enum
  discriminants as `varint`, `Vec<u8>`/`String` as
  `postcard-var-len`, fixed arrays raw, `Option<T>` as one tag octet
  (%x00/%x01), `bool` as one octet. Used for the DM envelope and
  capability adverts.

### 2.3. Terminology

| Term | Definition |
|------|------------|
| **MachineId** | 32-byte identifier derived from a machine's ML-DSA-65 public key (Section 4.1). Equals the ant-quic PeerId; authenticates the QUIC transport. |
| **AgentId** | 32-byte identifier derived from a portable agent's ML-DSA-65 public key. Stable across machines. |
| **UserId** | 32-byte identifier derived from an optional human operator's ML-DSA-65 public key. |
| **AgentCertificate** | A user-signed binding of an AgentId to a UserId (Section 4.4). |
| **AgentCard** | A signed, portable JSON identity card for an agent (Section 7.1). |
| **PeerId** | The ant-quic transport identifier; identical to MachineId. |
| **Bootstrap peer** | A seed node used only as a connection hint (ADR-0001); never an identity authority. |
| **DM** | Direct message between two agents (Sections 5.4–5.6). |
| **DST** | Domain-separation tag: a fixed byte string prepended to every signature input. |

## 3. Protocol Overview

### 3.1. Architecture

Three identity layers over one transport, registry-free discovery:

```
User (optional human operator)
  │  signs AgentCertificate  ─────► binds AgentId to UserId
  ▼
Agent (portable; AgentId derives from agent ML-DSA-65 key)
  │  runs on; signed announcements bind Agent to Machine
  ▼
Machine (hardware-pinned; MachineId == QUIC PeerId)

Transport:  QUIC [RFC9000] via ant-quic, raw-public-key PQC handshake,
            QUIC-native NAT traversal (no STUN/ICE/TURN).
Discovery:  DHT-free gossip (PlumTree) with signed announcements,
            tag shards, presence + FOAF random-walk lookup.
```

The reference implementation exposes the transport through a per-daemon
HTTP API; the daemon default QUIC port is UDP 5483 (private default, not
an IANA assignment; src/server/state.rs:333-334).

### 3.2. Layering Beneath A2A and MCP

x0x defines reachability, identity, confidentiality, and authenticity. It
defines no task, tool, or message semantics above framing. A2A and MCP
payloads are carried as opaque DM payloads or gossip payloads; an A2A
Agent Card for a local x0x agent is served at
`GET /.well-known/agent-card.json` (src/server/mod.rs:1547, src/a2a/mod.rs).
The layering claim is identical to [PILOT] §1.2: A2A defines what agents
say; this layer defines how they reach each other.

## 4. Identity Model

### 4.1. Self-Authenticating Identifiers

Every x0x identifier is 32 bytes
(src/identity.rs:22, `PEER_ID_LENGTH = 32`) computed as:

```
id = SHA-256( b"AUTONOMI_PEER_ID_V2:" || ml-dsa-65-public-key )
```

where `ml-dsa-65-public-key` is the 1952-byte FIPS 204 encoding. This is
exactly ant-quic's `derive_peer_id_from_public_key`
(ant-quic-0.27.33, src/crypto/raw_public_keys/pqc.rs:72-96): SHA-256 over
the fixed domain prefix `b"AUTONOMI_PEER_ID_V2:"` concatenated with the
raw public-key bytes. The same derivation serves MachineId, AgentId, and
UserId (src/identity.rs:47-49, 77-79, 107-109).

Consequences:

- **No issuance.** Any holder of an ML-DSA-65 keypair computes its own
  identifier. No registry, allocator, or naming authority participates.
- **Self-certification.** A presenter proves an identifier by revealing
  the public key; a verifier recomputes the hash. No third party, DID
  document, or DNS lookup is involved.
- **Binding check.** Every signed object that carries a public key
  alongside an identifier MUST be rejected unless
  `SHA-256("AUTONOMI_PEER_ID_V2:" || key)` equals the identifier. The
  implementation enforces this on AgentCard import
  (src/groups/card.rs:236-241), identity announcements
  (src/lib.rs:906-916), and forward attestations (src/forward.rs:280-287).

> Note for reviewers diffing earlier x0x documentation: older design
> notes describe identifiers as "SHA-256 of the public key" without
> naming the `AUTONOMI_PEER_ID_V2` domain prefix. The prefix is part of
> the derivation in the reference implementation (ant-quic 0.27.x);
> this document is the first x0x document to write it down.

### 4.2. Three Identity Layers

- **MachineId** pins a physical/virtual host and authenticates the QUIC
  transport (it *is* the ant-quic PeerId; the TLS handshake's raw public
  key hashes to it).
- **AgentId** is portable across machines; an agent keeps its identity
  when migrated.
- **UserId** is optional and opt-in (never auto-generated); it binds
  agents to a human operator via AgentCertificate.

(src/identity.rs:28-42; hierarchy documented at src/identity.rs:752-762.)

### 4.3. Algorithms and Key Sizes

| Primitive | Standard | Public key | Secret key | Signature / ciphertext |
|---|---|---|---|---|
| ML-DSA-65 | FIPS 204 | 1952 B | 4032 B | 3309 B signature |
| ML-KEM-768 | FIPS 203 | 1184 B | 2400 B | 1088 B ciphertext, 32 B shared secret |
| SHA-256 | FIPS 180-4 | — | — | 32 B digest |
| BLAKE3 | [BLAKE3] | — | — | 32 B digest (topic derivation only) |
| ChaCha20-Poly1305 | RFC 8439 | — | 32 B key | 12 B nonce, 16 B tag |

ML-DSA and ML-KEM operations are performed via `saorsa-pqc` (used by
both x0x and ant-quic; x0x Cargo.toml: `saorsa-pqc = "0.5"`,
`fips204 = { version = "0.4.6", features = ["ml-dsa-65"] }`). Signing
keys and KEM keys are **separate keypairs**: ML-DSA-65 for authenticity,
ML-KEM-768 for confidentiality (src/groups/kem_envelope.rs:35-47,
`KEM_VARIANT = MlKemVariant::MlKem768`).

### 4.4. AgentCertificate

An `AgentCertificate` binds an AgentId to a UserId, signed by the
**user's** ML-DSA-65 secret key (src/identity.rs:453-472, 514-568):

```text
AgentCertificate ::= {
  user_public_key:  Vec<u8>,   ; 1952 bytes
  agent_public_key: Vec<u8>,   ; 1952 bytes
  signature:        Vec<u8>,   ; 3309 bytes
  issued_at:        u64,       ; Unix seconds
  not_after:        Option<u64>; Unix seconds; None = never expires
}
```

Signed message (src/identity.rs:497-501, 722-749):

```text
not_after = None:  b"x0x-agent-cert-v1" || user_public_key || agent_public_key
                   || issued_at:u64le
not_after = Some:  b"x0x-agent-cert-v2" || user_public_key || agent_public_key
                   || issued_at:u64le || not_after:u64le
```

The two domain prefixes make expiry unforgeable: stripping a `not_after`
moves verification from the v2 to the v1 domain and fails. Verification
reconstructs the message and verifies the ML-DSA-65 signature against the
embedded user public key, then derives UserId/AgentId from the embedded
keys (src/identity.rs:573-606, 609-630). On disk, expiry-carrying
certificates are preceded by the 4-byte magic `b"X0C2"`; legacy files
begin with the bincode length prefix of the 1952-byte user key
(`%xA0.07…`) and cannot collide (src/identity.rs:503-508).

### 4.5. Identity Announcements

Agents and machines announce themselves on reserved gossip topics
(src/lib.rs:390, 396, 404):

- `x0x.identity.announce.v2` — signed `IdentityAnnouncement`
- `x0x.machine.announce.v2` — signed `MachineAnnouncement`
- `x0x.user.announce.v2` — signed `UserAnnouncement`

On the gossip wire the identity announcement is wrapped as
`b"X0A2" || bincode(IdentityAnnouncement)`; the `X0A2` magic
distinguishes the v2 envelope (which carries the agent public key for
attestation verification) from the legacy bincode form
(src/lib.rs:1704-1724). The announcement payload itself is
machine-signed over `bincode(IdentityAnnouncementUnsigned)` — the same
field list minus `machine_signature` and `agent_public_key`
(src/lib.rs:785-816, 1882-1916). Machine and user announcements sign the
same way over their unsigned structs (src/lib.rs:1031-1055, 1148-1167).
Verification checks the key→identifier binding, the machine signature,
and, when a user identity is disclosed, the embedded AgentCertificate
(src/lib.rs:899-968). Announcements carry reachability hints
(`addresses`, `nat_type`, `can_receive_direct`, `is_relay`,
`is_coordinator`, `reachable_via`, `relay_candidates`) used by discovery
and NAT traversal (Sections 6 and 9).

Note: announcement signature inputs are bare bincode with no DST octet
string (Section 8.6). This is the only signed-object family without an
ASCII domain prefix; see Section 10 for the collision analysis.

### 4.6. External Detached Signatures

Applications sign and verify arbitrary bytes through the daemon
(`POST /agent/sign`, `POST /agent/verify`; src/server/mod.rs:1549-1550)
using scheme identifier `x0x.agent-sign.v2.ml-dsa-65`
(src/api/agent_signing.rs:86). The signature input is
(src/api/agent_signing.rs:69, 78, 168-180):

```text
[0xF0] || b"x0x.external-agent-sign.v1" || u32be(len(context)) || context || payload
```

`context` is a REQUIRED caller-chosen ASCII string matching
`^[a-z0-9._-]{1,64}$` and not on an internal-domain denylist
(src/api/agent_signing.rs:90-93, 99-158). Payloads are limited to
64 KiB (src/api/agent_signing.rs:90). No internal x0x signing input
begins with octet `%xF0`, so the leading byte alone is a sufficient
witness that a signature belongs to the external namespace
(src/api/agent_signing.rs:16-66); the denylist is defense in depth.

## 5. Transport

### 5.1. QUIC with Raw Public Keys

x0x transports everything over QUIC [RFC9000] as implemented by ant-quic
0.27.33, using raw ML-DSA-65 public keys in place of X.509 certificates.
The TLS handshake authenticates each peer's key, and the peer's MachineId
(PeerId) is the key-derived identifier of Section 4.1 — the transport
identity *is* the self-authenticating identity, with no certificate
chain, CA, or registry lookup. ant-quic's advertised ALPN list is empty;
see Section 11.4.

### 5.2. Post-Quantum Handshake

The QUIC/TLS key schedule is pure PQC (ant-quic-0.27.33
src/crypto/pqc/mod.rs, crate documentation: "v0.2: Pure PQC - NO hybrid
or classical algorithms"):

- **Key establishment:** ML-KEM-768 (FIPS 203), TLS NamedGroup codepoint
  0x0201.
- **Authentication:** ML-DSA-65 (FIPS 204), TLS SignatureScheme
  codepoint 0x0905.

There is no classical or hybrid cipher suite to negotiate, and no
plaintext mode. A peer that cannot do ML-KEM-768/ML-DSA-65 cannot speak
x0x. Traffic keys are established fresh per QUIC connection by the TLS
stack; loss recovery, congestion control, and stream multiplexing are
QUIC's own ([RFC9000], [RFC9002]).

### 5.3. Stream Discrimination

The first octet of a stream's data discriminates the protocol:

- `%x10` — direct-message frame (Section 5.4)
  (src/direct.rs:79-80, `DIRECT_MESSAGE_STREAM_TYPE = 0x10`)
- Gossip/pubsub frames use their own stream types (0, 1, 2) inside the
  saorsa-gossip runtime (src/direct.rs:79 comment).

### 5.4. Direct Message Frame (Raw QUIC Path)

The legacy/raw delivery path carries one DM per stream
(src/direct.rs:1324-1367):

```abnf
dm-frame      =  %x10 sender-agent-id payload
sender-agent-id = 32OCTET          ; sender AgentId
payload       =  *OCTET            ; up to 16777216 octets (16 MiB)
```

Payloads above 16 MiB are rejected before encoding
(src/direct.rs:82-83, `MAX_DIRECT_PAYLOAD_SIZE`). The sender AgentId is
self-asserted at this layer; receivers cross-check it against the
identity cache before surfacing the message as verified
(src/direct.rs:197-210). Maximum frame = 33 + 16,777,216 octets.

### 5.5. Direct Message Envelope (Gossip Inbox Path)

Since x0x 0.18 the primary DM path publishes a signed, encrypted
`DmEnvelope` to the recipient's gossip inbox topic (src/dm.rs; design:
docs/design/dm-over-gossip.md).

**Inbox topic.** Each agent subscribes to
`BLAKE3( b"x0x/dm/v1/inbox/" || agent_id )` as a 32-byte gossip TopicId
(src/dm.rs:46, 484-488). Senders publish the envelope to that topic; in
normal daemon operation (signing context configured) the outer gossip
frame is itself v2-signed (Section 6.1), so the envelope is doubly
authenticated.

**Envelope.** Wire form is `postcard(DmEnvelope)`
(src/dm.rs:124-155, 825-841):

```text
DmEnvelope ::= {
  protocol_version:   u16,        ; = 1 (DM_PROTOCOL_VERSION, src/dm.rs:22)
  request_id:         [u8; 16],   ; random; reused across retries for dedupe
  sender_agent_id:    [u8; 32],
  sender_machine_id:  [u8; 32],
  recipient_agent_id: [u8; 32],
  created_at_unix_ms: u64,
  expires_at_unix_ms: u64,
  body:               DmBody,     ; Payload | Ack
  signature:          Vec<u8>     ; 3309-byte ML-DSA-65 signature
}
```

Receivers drop envelopes over 65,536 postcard bytes without processing
(src/dm.rs:26, 831-841), envelopes whose `protocol_version` exceeds the
receiver's maximum, and envelopes failing the freshness window:
`created_at` no more than 30,000 ms in the future, `expires_at` in the
future, and `expires_at - created_at <= 600,000 ms`
(src/dm.rs:29-37, 641-653).

**Payload encryption.** For `Payload` bodies the sender encapsulates a
32-byte content key to the recipient's ML-KEM-768 public key (published
in the recipient's `DmCapabilities`, Section 6.2), then encrypts
`postcard(DmPlaintext)` with ChaCha20-Poly1305 under a random 12-byte
nonce (src/dm.rs:731-767):

```text
DmPayload ::= {
  kem_ciphertext:  Vec<u8>,   ; 1088-byte ML-KEM-768 ciphertext
  body_nonce:      [u8; 12],
  body_ciphertext: Vec<u8>    ; postcard(DmPlaintext) + 16-byte AEAD tag
}
DmPlaintext ::= {
  request_id:   [u8; 16],     ; repeats envelope request_id (binds metadata)
  payload:      Vec<u8>,      ; up to 49152 octets (MAX_PAYLOAD_BYTES, src/dm.rs:29)
  content_type: Option<String>; free-form, e.g. "application/json"
}
```

The AEAD additional authenticated data binds the ciphertext to the
envelope metadata (src/dm.rs:43, 714-728):

```text
aad = b"x0x-dm-payload-v1" || request_id || sender_agent_id
      || recipient_agent_id || created_at_unix_ms:u64be
```

**Acknowledgement.** `Ack` bodies carry `{ acks_request_id: [u8;16],
outcome }` where `outcome` is `Accepted` or `RejectedByPolicy { reason }`
(src/dm.rs:160-225). Ack semantics are "recipient agent accepted" or
"policy rejected" — never durable storage or user read.

### 5.6. Delivery Path Selection

A send resolves to one of: `Loopback` (self), `GossipInbox` (Section
5.5), `RawQuic` (Section 5.4), `RawQuicAcked` (raw path with transport
ACK confirmation), or `Relayed { via }` (application-level peer relay
after repeated direct failures) (src/dm.rs:334-352). Per-attempt timeouts
adapt to measured RTT: `clamp(16 × rtt, 500 ms, 30 s)`, falling back to a
250 ms base when no RTT sample exists (src/dm.rs:355-377). Retries reuse
`request_id` so recipients dedupe.

## 6. Discovery

Discovery is DHT-free and registry-free:

- **Social propagation.** Agents exchange signed AgentCards out of band
  (Section 7.1) and import them into a local contact store.
- **Announcements.** Signed machine/agent/user announcements (Section
  4.5) propagate reachability hints over gossip.
- **Gossip frames.** All pubsub messages published with a signing
  context (always configured in the x0x daemon) are ML-DSA-65 signed
  (Section 6.1); the unsigned v1 format remains for legacy operation
  (src/gossip/pubsub.rs:547-554).
- **Capability adverts.** DM receive capabilities are signed and cached
  (Section 6.2).
- **Presence + FOAF.** `POST /agents/find/:agent_id` performs a
  trust-scoped random-walk lookup; quality-weighted peer selection keeps
  the mesh connected under partition. Tag shards map BLAKE3-hashed tags
  to PlumTree topics with CRDT OR-Set anti-entropy
  (src/groups/discovery.rs:38-48).

### 6.1. Gossip PubSub Frames

Two coexisting wire formats (src/gossip/pubsub.rs:7-9, 963-1049):

```abnf
; V1 (legacy, unsigned)
gossip-frame-v1 =  topic-len topic payload
topic-len       =  u16be
topic           =  1*OCTET
payload         =  *OCTET

; V2 (signed)
gossip-frame-v2 =  %x02 agent-id
                   pk-len sender-public-key
                   sig-len signature
                   topic-len topic
                   payload
agent-id        =  32OCTET
pk-len          =  u16be
sender-public-key = *OCTET        ; 1952 octets for ML-DSA-65
sig-len         =  u16be
signature       =  *OCTET         ; 3309 octets for ML-DSA-65
```

All three length prefixes are u16 **big-endian**
(src/gossip/pubsub.rs:1015-1049, 1053-1076; decode at 1080+). The v2
signature input is (src/gossip/pubsub.rs:104, 107, 1161-1166):

```text
b"x0x-msg-v2" || agent_id || topic || payload
```

### 6.2. DM Capability Adverts

Agents publish and republish (every 300 s) a signed `CapabilityAdvert`
(src/dm_capability.rs:34-37, 51-57) whose signature input is
(src/dm_capability.rs:77-87):

```text
b"x0x-caps-v1" || protocol_version:u16be || agent_id(32) || machine_id(32)
               || created_at_unix_ms:u64be || postcard(DmCapabilities)
```

`DmCapabilities` (src/dm.rs:54-80) carries `max_protocol_version`, a
`gossip_inbox` flag, `kem_algorithm` (always `"ML-KEM-768"` for v1),
`max_envelope_bytes`, and the agent's ML-KEM-768 public key. The same
structure rides on `AgentCard.dm_capabilities` (Section 7.1); cards
predating 0.18 carry `None`, interpreted as "raw-QUIC / legacy only".

## 7. Wire Formats

### 7.1. AgentCard

An `AgentCard` is a UTF-8 JSON object (src/groups/card.rs:24-77):

| Member | Type | Req | Meaning |
|---|---|---|---|
| `display_name` | string | ✔ | Human-readable name |
| `agent_id` | string | ✔ | 64 lowercase hex chars (32-byte AgentId) |
| `machine_id` | string | ✔ | 64 lowercase hex chars (32-byte MachineId) |
| `user_id` | string | opt | 64 hex chars; omitted unless the agent has a user identity and chooses to include it |
| `addresses` | string[] | ✔ | Reachability *hints* (`IP:port`); may be empty |
| `groups` | object[] | opt | `{name, invite_link}` entries; omitted when empty |
| `stores` | object[] | opt | `{name, topic}` entries; omitted when empty |
| `created_at` | number | ✔ | Unix seconds |
| `dm_capabilities` | object | opt | `DmCapabilities` (Section 6.2); absent pre-0.18 |
| `agent_public_key` | string | sig | 3904 hex chars (1952-byte ML-DSA-65 key) |
| `signature` | string | sig | 6618 hex chars (3309-byte ML-DSA-65 signature) |

`sig` = present on signed cards (x0x ≥ 0.24, ADR-0017); legacy unsigned
cards omit both members and still parse. `serde` skips `None` members and
empty vectors when serializing (src/groups/card.rs:34-77).

**Link form** (src/groups/card.rs:121-148):

```abnf
agent-card-link =  "x0x://agent/" b64url-json
b64url-json     =  *( ALPHA / DIGIT / "-" / "_" )
                   ; base64url (no padding) of the UTF-8 JSON, RFC 4648 §5
```

Parsers MUST also accept the bare base64url payload without the scheme
prefix (src/groups/card.rs:137-138). Signed cards MUST be verified on
import: the embedded `agent_public_key` MUST hash (Section 4.1) to
`agent_id`, and `signature` MUST verify over the canonical bytes of
Section 8.1; verification failure MUST reject the card
(src/groups/card.rs:224-251).

### 7.2. AgentCertificate (bincode wire form)

Gossip-embedded certificates serialize positionally with bincode 1.3
(Section 2.2); on disk, expiry-carrying certificates are preceded by
`b"X0C2"` (src/identity.rs:503-508):

```abnf
agent-certificate =  lp64le(user-public-key)
                     lp64le(agent-public-key)
                     lp64le(signature)
                     issued-at
                     not-after
user-public-key  =  1952OCTET
agent-public-key =  1952OCTET
signature        =  3309OCTET
issued-at        =  u64le         ; Unix seconds
not-after        =  %x00 / (%x01 u64le)   ; bincode Option<u64>
```

Signed message ABNF (src/identity.rs:497-501, 722-749):

```abnf
cert-msg-v1 =  "x0x-agent-cert-v1" user-public-key agent-public-key issued-at
cert-msg-v2 =  "x0x-agent-cert-v2" user-public-key agent-public-key issued-at
               not-after-value
not-after-value = u64le
```

### 7.3. Gossip Frames

Defined in Section 6.1 with ABNF.

### 7.4. DM Frame and Envelope

The raw frame is defined in Section 5.4. The postcard envelope
(Section 5.5) expands as:

```abnf
dm-envelope       =  version request-id sender-agent sender-machine
                     recipient-agent created-at expires-at body signature
version           =  varint           ; u16, = 1
request-id        =  16OCTET
sender-agent      =  32OCTET
sender-machine    =  32OCTET
recipient-agent   =  32OCTET
created-at        =  varint           ; u64, Unix milliseconds
expires-at        =  varint           ; u64, Unix milliseconds
body              =  %x00 dm-payload / %x01 dm-ack   ; postcard discriminant
signature         =  postcard-var-len(3309OCTET)

dm-payload        =  kem-ct body-nonce body-ct
kem-ct            =  postcard-var-len(1088OCTET)
body-nonce        =  12OCTET
body-ct           =  postcard-var-len(*OCTET)

dm-ack            =  acks-request-id outcome
acks-request-id   =  16OCTET
outcome           =  %x00 / (%x01 reason)   ; Accepted / RejectedByPolicy
reason            =  postcard-var-len(*OCTET) ; UTF-8 string

dm-plaintext      =  request-id user-payload content-type
                     ; inside body-ct after AEAD open
user-payload      =  postcard-var-len(*OCTET)   ; ≤ 49152 octets
content-type      =  %x00 / (%x01 postcard-var-len(*OCTET))
```

(Discriminants shown as single octets hold because these enums have ≤ 3
variants; postcard encodes them as `varint`. Struct fields have no tags —
postcard is positional.)

Signed-bytes and AAD layouts are in Sections 8.3.

## 8. Signed Objects and Canonicalization

Every signed object in x0x signs a domain-separated canonical byte
string. This section is the complete inventory; Appendix B tabulates it.
Two endianness regimes exist by construction and MUST be reproduced
exactly: certificate timestamps are little-endian; DM/advert protocol
fields are big-endian; AgentCard length prefixes are u32 little-endian.

### 8.1. AgentCard Canonical Bytes

`AgentCard::signable_bytes` (src/groups/card.rs:167-196; helper
`push_len_prefixed` at 254-257 — every `lp32le` below):

```abnf
card-canonical =  card-domain
                  lp32le(display-name)     ; UTF-8 bytes
                  lp32le(agent-id)         ; 64 ASCII hex chars
                  lp32le(machine-id)       ; 64 ASCII hex chars
                  lp32le(user-id)          ; 64 hex chars, or EMPTY when None
                  addr-count *lp32le(address)
                  group-count *( lp32le(group-name) lp32le(invite-link) )
                  store-count *( lp32le(store-name) lp32le(store-topic) )
                  created-at
                  lp32le(dm-capabilities-bincode)
                  lp32le(agent-public-key-hex)  ; hex string, or EMPTY when None
card-domain    =  "x0x-agent-card-v1"          ; src/groups/card.rs:19
addr-count     =  u32le
group-count    =  u32le
store-count    =  u32le
created-at     =  u64le                          ; Unix seconds
```

`dm-capabilities-bincode` is `bincode(Option<DmCapabilities>)` (tag octet
%x00/%x01, then u16le, bool octet, `lp64le` kem-algorithm string, u64le
max-envelope-bytes, `lp64le` kem public key). `signature` itself is
excluded; all other members — including `agent_public_key` — are covered,
so swapping the embedded key invalidates the signature
(src/groups/card.rs:206-217 comment, 224-251).

### 8.2. AgentCertificate Canonical Bytes

Specified in Section 7.2 (`cert-msg-v1` / `cert-msg-v2`).

### 8.3. DM Envelope Signed Bytes and AEAD AAD

(src/dm.rs:40, 686-710):

```abnf
dm-signed-bytes =  "x0x-dm-v1"
                   version-be request-id sender-agent sender-machine
                   recipient-agent created-at-be expires-at-be
                   postcard-body
version-be        =  u16be
created-at-be     =  u64be
expires-at-be     =  u64be
postcard-body     =  body           ; postcard DmBody, Section 7.4
```

AEAD AAD (src/dm.rs:43, 714-728):

```abnf
dm-aead-aad =  "x0x-dm-payload-v1" request-id sender-agent
               recipient-agent created-at-be
```

### 8.4. Gossip V2 Signed Bytes

```abnf
gossip-v2-signed =  "x0x-msg-v2" agent-id topic payload
```

(src/gossip/pubsub.rs:104, 1161-1166 — note: no length prefixes; the
32-octet `agent-id` fixes the first boundary, and `topic`/`payload`
concatenation is safe because verification recomputes over the exact wire
slices, never re-parses the concatenation.)

### 8.5. Capability Advert Signed Bytes

```abnf
caps-signed =  "x0x-caps-v1" version-be agent-id machine-id
               created-at-be dm-caps-postcard
machine-id  =  32OCTET
```

(src/dm_capability.rs:34, 77-87; `created-at-be` is u64be Unix ms.
`dm-caps-postcard` is the bare postcard encoding of `DmCapabilities` —
varint u16 `max_protocol_version`, one-octet `gossip_inbox`, varint-len
UTF-8 `kem_algorithm`, varint usize `max_envelope_bytes`, varint-len
`kem_public_key` — with no additional outer length prefix.)

### 8.6. Announcement Signed Bytes

Identity/machine/user announcements sign
`bincode(<Type>AnnouncementUnsigned)` — the announcement struct minus its
signature field(s) — with **no ASCII domain prefix**
(src/lib.rs:785-816, 899-940, 1031-1055, 1882-1916). The wire envelope
carries a magic prefix instead (`b"X0A2"` for identity announcements,
src/lib.rs:1704-1724), but that prefix is *not* part of the signature
input. Cross-protocol signature reuse is bounded structurally: a
signature commits to the exact bincode bytes, and no two x0x signed
objects share the same bincode field shape; a hardening item to add a
DST to announcement inputs is tracked as future work (Section 10).

### 8.7. External Signature Buffer

```abnf
external-signed =  %xF0 "x0x.external-agent-sign.v1"
                   context-len context payload
context-len     =  u32be
context         =  1*64( %x30-39 / %x61-7A / "." / "_" / "-" )
payload         =  *65536OCTET
```

(src/api/agent_signing.rs:69, 78, 90-93, 139-180.)

## 9. NAT Traversal

x0x performs QUIC-native NAT traversal via ant-quic; it does not use
STUN, ICE, or TURN. The approach follows the QUIC NAT traversal design
family of [QUIC-NAT]: QUIC's own path-validation frames test address-
candidate pairs while simultaneously creating the NAT bindings a direct
connection needs, so traversal reuses the authenticated transport rather
than a parallel cleartext protocol.

- **Detection.** The transport reports an auto-detected NAT class
  (`nat_type`, e.g. "FullCone", "PortRestricted", "Symmetric") and
  observed external addresses; the daemon surfaces them in node status
  and in signed announcements (src/server/mod.rs:3196-3262,
  src/lib.rs:793-797).
- **Coordination.** Bootstrap peers are seed *hints* (ADR-0001), never
  authorities: they act as coordinators for hole punching, and any
  reachable peer advertising `is_coordinator` can fill the role.
  NAT-locked agents publish `reachable_via` coordinator and
  `relay_candidates` relay hints in their signed announcements
  (src/lib.rs:805-816, 858-872).
- **Fallback.** When hole punching fails (e.g. symmetric NAT), delivery
  falls back to an application-level peer relay (`DmPath::Relayed`,
  src/dm.rs:345-351) and to the gossip inbox path (Section 5.5), which
  needs no inbound connectivity at all.

Diff against [PILOT] §9: Pilot uses STUN-style endpoint discovery
against a central beacon, beacon-coordinated punching, and beacon relay
— all keyed by the registry's locator lookup. x0x coordinates through
interchangeable, authenticated peers and treats no node as
authoritative.

## 10. Security Considerations

- **No trusted third party.** The registry-compromise class [PILOT]
  §19.5 enumerates — address hijacking, locator spoofing, public-key
  substitution, metadata harvesting — has no target here: there is no
  registry, address allocator, or locator database to compromise.
  Identifiers are key-derived (Section 4.1); locators are *hints*
  attached to signed objects, never authoritative resolutions.
- **Downgrade surface.** There is no plaintext mode. Contrast [PILOT]
  §10.2, which falls back to cleartext PILT frames when key exchange is
  unanswered.
- **Harvest-now-decrypt-later.** All confidentiality (transport
  handshake, DM payloads, group secret delivery) is ML-KEM-768; all
  authenticity is ML-DSA-65. Recorded x0x traffic does not become
  decryptable by a future cryptanalytically relevant quantum computer
  attacking classical ECDH.
- **Key→identifier binding.** Every object carrying a public key beside
  an identifier MUST be rejected on mismatch (Section 4.1); the
  implementation enforces this at every ingest point listed there.
- **Replay and freshness.** DM envelopes enforce the 30 s skew / 10 min
  lifetime window (Section 5.5); identity announcements accepted as
  security bindings apply the same skew bound (src/lib.rs:971-976).
  Retried DMs reuse `request_id` for dedupe (Section 5.6).
- **Announcement signature inputs lack a DST** (Section 8.6). A
  signature verifies only over the exact bincode struct bytes, and no
  other signed object shares that byte shape, so cross-protocol
  confusion requires a bincode-identical struct; adding an explicit DST
  to announcement inputs is RECOMMENDED for a future revision.
- **Metadata exposure.** Gossip inbox topics are recipient-derived
  hashes (Section 5.5), so passive observers see topic IDs, not
  identifiers; relay and coordinator peers learn sender/recipient
  envelope metadata for the DMs they carry. Deployments requiring
  stronger unlinkability should treat relay selection as a trust
  decision.
- **KEM key rotation.** DM payload confidentiality depends on the
  recipient's published ML-KEM-768 key (Sections 5.5, 6.2); recipients
  SHOULD rotate KEM keys on compromise and republish a fresh signed
  capability advert and AgentCard.
- **Self-asserted sender on the raw DM path** (Section 5.4): the 0x10
  frame's AgentId is authenticated only after identity-cache
  cross-check; applications MUST NOT act on unverified senders
  (src/direct.rs:197-210).

## 11. IANA Considerations

### 11.1. Media Type `application/x0x-agent-card+json`

Registration request per RFC 6838 / RFC 7595 procedures for the media
type of a signed AgentCard (Section 7.1) when transferred as a document
rather than as an `x0x://agent/` link:

```text
Type name:           application
Subtype name:        x0x-agent-card+json
Required parameters: none
Optional parameters: none
Encoding:            binary (UTF-8 JSON)
Security:            consumers MUST verify the embedded ML-DSA-65
                     signature (Sections 7.1, 8.1) before trusting
                     addresses, capabilities, or group/store references;
                     unsigned cards carry no authenticity.
Interoperability:    JSON per RFC 8259; member order insignificant;
                     unknown members MUST be ignored.
Published spec:      this document, Section 7.1.
Fragment identifier: none
Contact:             Saorsa Labs (x0x repository, github.com/saorsa-labs/x0x)
Intended usage:      COMMON (Experimental)
```

If IANA policy requires a vendor-tree name for an Independent
Submission, the equivalent registration is
`application/vnd.x0x.agent-card+json` with identical contents.

### 11.2. URI Scheme `x0x`

Provisional registration per RFC 7595:

```text
Scheme name:    x0x
Status:         provisional
Syntax:         x0x://agent/<base64url-no-pad JSON AgentCard>  (Section 7.1)
                x0x://invite/<base64url-no-pad JSON SignedInvite>
                (src/groups/invite.rs:36, 308-346)
Semantics:      agent — a signed identity card for one agent;
                invite — a single-use group invitation token.
Encoding:       base64url without padding (RFC 4648 §5) of UTF-8 JSON.
Security:       card payloads MUST be signature-verified before use
                (Section 7.1); invite tokens are bearer secrets and MUST
                be treated as such.
Contact:        Saorsa Labs
```

### 11.3. Well-Known URI `x0x-agent`

Registration request per RFC 8615:

```text
URI suffix:  x0x-agent
Change controller: Saorsa Labs
Specification: this document
Related:       returns the node's signed AgentCard as
               application/x0x-agent-card+json
```

(The A2A-shaped discovery card already served at
`/.well-known/agent-card.json` is specified by the A2A protocol, not by
this document; src/server/mod.rs:1547.)

### 11.4. ALPN

Registration request per RFC 7301 for the identification sequence
`x0x` ("x0x Agent Transport") in the TLS ALPN registry. The ant-quic
0.27.33 reference transport negotiates **no** ALPN today (verified: x0x
configures no ALPN; the crate's only ALPN use is an HTTP/3 test binary); this registration reserves the
identifier so future revisions can discriminate x0x traffic co-resident
with other QUIC protocols on shared ports. Implementations of this
revision MUST NOT require an ALPN match.

### 11.5. Port Numbers

This document requests no port assignment. The reference implementation
defaults to UDP 5483 in private use (src/server/state.rs:333-334).

## 12. Comparison to Pilot Protocol

Factual diff against [PILOT] (draft-teodor-pilot-protocol-01, 2026-04-06,
expires 2026-10-08). Citations are to that document.

| Axis | Pilot Protocol | x0x (this document) |
|---|---|---|
| Identity issuance | Ed25519 keypair **issued by central registry**; registry holds all public keys (§10.1) | ML-DSA-65 keypair self-generated; identifier = hash of own key (§4.1); no issuer |
| Address space | 48-bit virtual address (16-bit Network ID + 32-bit Node ID), registry-assigned (§4.1) | 256-bit identifier *is* the address; no allocator (§4.1, §5.4) |
| Locator resolution | Registry lookup of Node ID → endpoint (§4, §9) | Reachability hints on signed cards/announcements; gossip + FOAF; hints are non-authoritative (§6) |
| Transport substrate | TCP reimplemented over UDP: handshake, RTO, SACK, Nagle, TIME_WAIT (§8); author flags double congestion control (§19.8) | QUIC [RFC9000]: loss recovery, CC, and stream multiplexing from the transport (§5.1–5.2) |
| NAT traversal | STUN-style discovery + central-beacon-coordinated punching + beacon relay (§9) | QUIC-native hole punching via path validation; interchangeable coordinators; relay + gossip-inbox fallback (§9) |
| Key exchange | X25519 ECDH → HKDF → AES-256-GCM (§7.2–7.4, §10.2–10.3) | ML-KEM-768 encapsulation in QUIC/TLS handshake (§5.2) |
| Signatures | Ed25519, verified against registry-held keys (§7.4, §10.1) | ML-DSA-65 over domain-separated canonical bytes, verified against key-derived identifiers (§8) |
| Plaintext mode | PILT cleartext fallback when key exchange unanswered (§7.1, §10.2) | None (§5.2) |
| Trusted third party | Registry is an admitted TTP: address hijack, locator spoof, key substitution, metadata harvest on compromise (§19.5) | None (§10) |
| Quantum resistance | Classical algorithms throughout | PQC throughout (§4.3) |
| Versioning | 4-bit packet Version field; RST on mismatch (§12) | `protocol_version` per envelope + `DmCapabilities.max_protocol_version` negotiation (§5.5, §6.2) |

Three statements of fact, not of ranking:

1. **Pilot's security model has a single point of compromise; x0x's does
   not have that point.** Every attack [PILOT] §19.5 lists is an attack
   on the registry. x0x removes the registry rather than mitigating it.
2. **Pilot's confidentiality is classical; x0x's is post-quantum.**
   X25519 falls to Shor's algorithm on a cryptanalytically relevant
   quantum computer; ML-KEM-768 is the NIST-standardized KEM (FIPS 203).
3. **Pilot carries a plaintext downgrade path; x0x has none.** An active
   attacker who can suppress key-exchange frames forces PILT cleartext
   ([PILOT] §10.2); there is no equivalent x0x behavior to force.

Pilot properties x0x does not replicate: port-based service multiplexing
with well-known ports (§5, §14), gateway bridging to TCP/IP (§15), and
enterprise RBAC/audit extensions (§18). x0x deliberately scopes itself to
identity + transport + discovery; application protocols (A2A/MCP) provide
service semantics above it.

## 13. References

### 13.1. Normative References

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119
  Key Words", BCP 14, RFC 8174, May 2017.
- [RFC5234] Crocker, D., Ed. and Overell, P., "Augmented BNF for Syntax
  Specifications: ABNF", STD 68, RFC 5234, January 2008.
- [RFC9000] Iyengar, J., Ed. and Thomson, M., Ed., "QUIC: A UDP-Based
  Multiplexed and Secure Transport", RFC 9000, May 2021.
- [RFC9002] Iyengar, J., Ed. and Swett, I., Ed., "QUIC Loss Detection
  and Congestion Control", RFC 9002, May 2021.
- [FIPS203] NIST, "Module-Lattice-Based Key-Encapsulation Mechanism
  Standard", FIPS 203, August 2024.
- [FIPS204] NIST, "Module-Lattice-Based Digital Signature Standard",
  FIPS 204, August 2024.
- [RFC8439] Nir, Y. and Langley, A., "ChaCha20 and Poly1305 for IETF
  Protocols", RFC 8439, June 2018.
- [RFC4648] Josefsson, S., "The Base16, Base32, and Base64 Data
  Encodings", RFC 4648, October 2006.
- [RFC8259] Bray, T., Ed., "The JavaScript Object Notation (JSON) Data
  Interchange Format", RFC 8259, December 2017.

### 13.2. Informative References

- [PILOT] Calin, T.-I., "Pilot Protocol: An Overlay Network for
  Autonomous Agent Communication", draft-teodor-pilot-protocol-01
  (work in progress), April 2026.
  <https://datatracker.ietf.org/doc/draft-teodor-pilot-protocol/>
- [QUIC-NAT] Seemann, M., "QUIC NAT Traversal",
  draft-seemann-quic-nat-traversal (work in progress).
  <https://datatracker.ietf.org/doc/draft-seemann-quic-nat-traversal/>
- [BLAKE3] O'Connor, J., Aumasson, J.-P., Neves, S., Wilcox-O'Hearn, Z.,
  "BLAKE3: one function, fast everywhere", 2020.
- [A2A] "Agent2Agent (A2A) Protocol Specification", Linux Foundation.
  <https://a2a-protocol.org/>
- [ADR-0017] Irvine, D., "ADR 0017: Position x0x as the agent transport
  layer", x0x repository, docs/adr/0017-x0x-as-agent-transport-layer.md,
  June 2026.

## Appendix A. Implementation Citation Index

Normative claims → reference implementation source (x0x @ a939f47 unless
noted; ant-quic 0.27.33 from crates.io).

| Object / constant | Definition | Source |
|---|---|---|
| Identifier derivation `SHA-256("AUTONOMI_PEER_ID_V2:" ‖ key)` | §4.1 | ant-quic `src/crypto/raw_public_keys/pqc.rs:72-96`; called from x0x `src/identity.rs:47,77,107` |
| Identifier length 32 B | §4.1 | `src/identity.rs:22` |
| Three-layer identity | §4.2 | `src/identity.rs:28-42` |
| ML-KEM-768 variant constant | §4.3 | `src/groups/kem_envelope.rs:35` |
| KEM key sizes 1184/2400 B | §4.3 | `src/groups/kem_envelope.rs:42-46` |
| AgentCard struct + serde rules | §7.1 | `src/groups/card.rs:24-77` |
| AgentCard link form | §7.1 | `src/groups/card.rs:121-148` |
| AgentCard DST `x0x-agent-card-v1` | §8.1 | `src/groups/card.rs:19` |
| AgentCard canonical bytes | §8.1 | `src/groups/card.rs:167-196` |
| `lp32le` helper | §8.1 | `src/groups/card.rs:254-257` |
| AgentCard verify + key binding | §7.1 | `src/groups/card.rs:224-251` |
| AgentCertificate struct | §4.4 | `src/identity.rs:453-472` |
| Cert DSTs `x0x-agent-cert-v1`/`-v2` | §7.2 | `src/identity.rs:497-501` |
| Cert signed message build | §7.2 | `src/identity.rs:722-749` |
| Cert issue/verify | §4.4 | `src/identity.rs:514-568, 573-606` |
| Cert disk magic `X0C2` | §7.2 | `src/identity.rs:503-508` |
| Announcement topics | §4.5 | `src/lib.rs:390, 396, 404` |
| `X0A2` announcement envelope | §4.5 | `src/lib.rs:1704-1724` |
| Announcement signed bytes (bincode) | §8.6 | `src/lib.rs:785-816, 899-940, 1882-1916` |
| External signing DST + `0xF0` tag | §4.6 | `src/api/agent_signing.rs:69, 78, 168-180` |
| External scheme id | §4.6 | `src/api/agent_signing.rs:86` |
| Context regex + denylist | §4.6 | `src/api/agent_signing.rs:99-158` |
| External payload cap 64 KiB | §4.6 | `src/api/agent_signing.rs:90` |
| PQC-only handshake (ML-KEM-768 0x0201, ML-DSA-65 0x0905) | §5.2 | ant-quic `src/crypto/pqc/mod.rs` module docs |
| DM stream type 0x10 | §5.4 | `src/direct.rs:79-80` |
| DM frame format + 16 MiB cap | §5.4 | `src/direct.rs:82-83, 1324-1367` |
| DM protocol version 1 | §5.5 | `src/dm.rs:22` |
| Envelope cap 65,536 B / payload cap 49,152 B | §5.5 | `src/dm.rs:26, 29` |
| DM lifetime 600 s / skew 30 s | §5.5 | `src/dm.rs:34, 37, 641-653` |
| DM DSTs `x0x-dm-v1`, `x0x-dm-payload-v1` | §8.3 | `src/dm.rs:40, 43` |
| DM signed bytes | §8.3 | `src/dm.rs:686-710` |
| DM AEAD AAD | §8.3 | `src/dm.rs:714-728` |
| DM payload encrypt/decrypt | §5.5 | `src/dm.rs:731-767, 770-791` |
| Envelope wire (postcard) | §7.4 | `src/dm.rs:825-841` |
| DM inbox topic `BLAKE3("x0x/dm/v1/inbox/" ‖ id)` | §5.5 | `src/dm.rs:46, 484-488` |
| `DmEnvelope`/`DmBody`/`DmPayload`/`DmPlaintext`/`DmAck*` | §5.5 | `src/dm.rs:124-225` |
| `DmPath` variants | §5.6 | `src/dm.rs:334-352` |
| Adaptive DM timeout | §5.6 | `src/dm.rs:355-377` |
| Gossip v1/v2 frames | §6.1 | `src/gossip/pubsub.rs:963-1049, 1080+` |
| Gossip v2 version byte 0x02 + DST `x0x-msg-v2` | §6.1 | `src/gossip/pubsub.rs:104, 107` |
| Gossip v2 signed bytes | §8.4 | `src/gossip/pubsub.rs:1161-1166` |
| Capability advert DST `x0x-caps-v1` + signed bytes | §6.2, §8.5 | `src/dm_capability.rs:34, 77-87` |
| Advert republish 300 s | §6.2 | `src/dm_capability.rs:37` |
| `DmCapabilities` struct | §6.2 | `src/dm.rs:54-80` |
| Default QUIC port 5483 | §3.1, §11.5 | `src/server/state.rs:333-334` |
| HTTP routes (card, well-known, sign/verify) | §3.2, §4.6, §11.3 | `src/server/mod.rs:1546-1550` |
| `x0x://invite/` form | §11.2 | `src/groups/invite.rs:36, 308-346` |
| NAT status surfacing | §9 | `src/server/mod.rs:3196-3262` |

## Appendix B. Domain Separator Inventory

| DST / constant | Bytes | Used for | Endianness of appended fields |
|---|---|---|---|
| `AUTONOMI_PEER_ID_V2:` | 20 ASCII | identifier derivation hash input | n/a (hash input) |
| `x0x-agent-card-v1` | 17 ASCII | AgentCard signature | u32le prefixes, u64le time |
| `x0x-agent-cert-v1` | 17 ASCII | AgentCertificate, no expiry | u64le |
| `x0x-agent-cert-v2` | 17 ASCII | AgentCertificate, with expiry | u64le |
| `x0x-dm-v1` | 9 ASCII | DmEnvelope signature | u16be/u64be |
| `x0x-dm-payload-v1` | 17 ASCII | DM payload AEAD AAD | u64be |
| `x0x-msg-v2` | 10 ASCII | gossip v2 frame signature | raw concatenation |
| `x0x-caps-v1` | 11 ASCII | capability advert signature | u16be/u64be |
| `0xF0 ‖ x0x.external-agent-sign.v1` | 1 + 26 B | external detached signatures | u32be context length |
| `x0x/dm/v1/inbox/` | 16 ASCII | BLAKE3 inbox-topic derivation | raw |
| `X0A2` | 4 B | identity-announcement gossip envelope magic | n/a (not signed) |
| `X0C2` | 4 B | on-disk v2 certificate magic | n/a (not signed) |
| `x0x.agent-sign.v2.ml-dsa-65` | 27 ASCII | external scheme identifier (API string, not a byte prefix) | n/a |

Non-DST signed inputs: identity/machine/user announcements sign bare
`bincode(unsigned struct)` (Section 8.6).

## Appendix C. Implementation Status (RFC 7942)

This document describes x0x as of commit `a939f47` on `origin/main`
(2026-07). Known deltas between long-term intent and current code:

- Signed AgentCards ship since v0.24 (ADR-0017); legacy unsigned cards
  still parse and MUST be treated as unauthenticated (§7.1).
- The `/.well-known/x0x-agent` endpoint of §11.3 is a registration
  request; the implementation today serves the A2A-specified
  `/.well-known/agent-card.json`.
- No ALPN is negotiated by the current transport (§11.4).
- Announcement signature inputs carry no DST (§8.6); adding one is
  future hardening.

## Authors' Addresses

Saorsa Labs
x0x project — <https://github.com/saorsa-labs/x0x>
