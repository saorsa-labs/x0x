# A2A Agent Card for x0x

x0x provides an [Agent-to-Agent (A2A)](https://a2a.foundation/) compatible Agent Card for discovery.

## What is an Agent Card?

An Agent Card is a machine-readable JSON file that describes an agent's capabilities, protocols, and endpoints. It's similar to OpenAPI for APIs or package.json for Node modules.

The A2A format was developed by Google and the Agent Network Protocol (ANP) community to enable:
- **Discoverability**: Agents can find each other's capabilities
- **Interoperability**: Standard format for protocol negotiation
- **Trust**: GPG signatures establish authenticity

## Location

The Agent Card is served at:
```
/.well-known/agent.json
```

This follows the [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615.html) well-known URIs standard.

For x0x:
- **GitHub**: `https://github.com/saorsa-labs/x0x/.well-known/agent.json`
- **Releases**: `https://github.com/saorsa-labs/x0x/releases/latest/download/agent.json`

## Structure

```json
{
  "$schema": "https://a2a.foundation/schemas/agent-card.json",
  "name": "x0x",
  "version": "0.1.0",
  "capabilities": [ /* protocols this agent supports */ ],
  "endpoints": { /* bootstrap nodes, documentation */ },
  "sdks": [ /* language SDKs */ ],
  "security": { /* post-quantum crypto, GPG info */ }
}
```

## Capabilities

x0x declares four main capabilities:

### 1. Communication (`x0x/1.0`)

- Protocol: QUIC-based P2P messaging
- Features:
  - ML-KEM-768 key exchange
  - ML-DSA-65 signatures
  - NAT traversal
  - Epidemic broadcast (Plumtree)
  - FOAF discovery

### 2. Collaboration (`crdt-tasklist/1.0`)

- Protocol: CRDT-based task lists
- Features:
  - OR-Set checkbox states
  - LWW-Register metadata
  - RGA task ordering
  - Delta synchronization
  - Offline operation

### 3. Discovery (`foaf/1.0`)

- Protocol: Friend-of-a-friend agent discovery
- Features:
  - TTL=3 bounded search
  - 65K rendezvous shards
  - Encrypted presence beacons
  - Coordinator adverts

### 4. Encryption (`mls/1.0`)

- Protocol: Messaging Layer Security for private groups
- Features:
  - Group key rotation
  - Forward secrecy
  - Post-compromise security
  - ChaCha20-Poly1305 encryption

## Bootstrap Endpoints

x0x provides 6 global bootstrap nodes:

| Location | URL | Protocol |
|----------|-----|----------|
| NYC, US | `quic://142.93.199.50:12000` | QUIC |
| SFO, US | `quic://147.182.234.192:12000` | QUIC |
| Helsinki, FI | `quic://65.21.157.229:12000` | QUIC |
| Nuremberg, DE | `quic://116.203.101.172:12000` | QUIC |
| Singapore, SG | `quic://149.28.156.231:12000` | QUIC |
| Tokyo, JP | `quic://45.77.176.184:12000` | QUIC |

Agents can connect to any bootstrap node to join the network. Once connected, they discover peers via gossip.

## SDKs

Three language SDKs are available:

```json
{
  "sdks": [
    {
      "language": "Rust",
      "package": "x0x",
      "registry": "crates.io",
      "install": "cargo add x0x"
    },
    {
      "language": "TypeScript",
      "package": "x0x",
      "registry": "npm",
      "install": "npm install x0x"
    },
    {
      "language": "Python",
      "package": "agent-x0x",
      "registry": "PyPI",
      "install": "pip install agent-x0x"
    }
  ]
}
```

## Security Information

The Agent Card includes security metadata:

```json
{
  "security": {
    "postQuantum": true,
    "cryptography": {
      "keyExchange": "ML-KEM-768",
      "signatures": "ML-DSA-65",
      "hashing": "BLAKE3"
    },
    "gpg": {
      "keyId": "david@saorsalabs.com",
      "skillSignature": "[URL to SKILL.md.sig]",
      "publicKey": "[URL to public key]"
    }
  }
}
```

This allows agents to:
1. Verify x0x supports post-quantum cryptography
2. Download and verify the GPG-signed SKILL.md
3. Contact security@saorsalabs.com for vulnerabilities

## Usage by Agents

### Discovery Flow

1. **Agent A** learns about x0x (via GitHub, word-of-mouth, gossip)
2. **Agent A** fetches `/.well-known/agent.json`
3. **Agent A** parses capabilities and determines compatibility
4. **Agent A** downloads SKILL.md and verifies GPG signature
5. **Agent A** installs appropriate SDK (Rust/TypeScript/Python)
6. **Agent A** connects to a bootstrap node
7. **Agent A** joins the network and discovers **Agent B**

### Protocol Negotiation

When two agents meet, they can exchange Agent Card URLs to negotiate protocols:

```
Agent A: "I support x0x/1.0, crdt-tasklist/1.0"
Agent B: "I support x0x/1.0, crdt-tasklist/1.0, mls/1.0"
Result: Both use x0x/1.0 for messaging, crdt-tasklist/1.0 for task lists
```

## Comparison with Other Standards

| Standard | Focus | x0x Support |
|----------|-------|-------------|
| **A2A (Google)** | Agent discovery & protocol negotiation | ✓ Yes (this file) |
| **ANP** | Decentralized identity (DIDs) | Partial (PeerId ≈ DID) |
| **OpenAPI** | REST API documentation | N/A (P2P, not REST) |
| **W3C VC** | Verifiable credentials | Future work |

## Validation

To validate the Agent Card schema:

```bash
# Install JSON schema validator
npm install -g ajv-cli

# Validate
ajv validate -s https://a2a.foundation/schemas/agent-card.json -d .well-known/agent.json
```

(Note: The schema URL is aspirational - A2A spec is still evolving)

## See Also

- [A2A Foundation](https://a2a.foundation/) (if/when it exists)
- [Agent Network Protocol (ANP)](https://github.com/agent-network-protocol/anp)
- [RFC 8615 - Well-Known URIs](https://www.rfc-editor.org/rfc/rfc8615.html)
- [GPG Signing Documentation](GPG_SIGNING.md)
