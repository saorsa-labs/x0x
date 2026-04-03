# Ecosystem — Saorsa Labs Projects

> Back to [SKILL.md](https://github.com/saorsa-labs/x0x/blob/main/SKILL.md)

x0x is the network layer of the Saorsa Labs ecosystem. Applications build on x0x; infrastructure libraries build under it.

## Applications Built on x0x

| Project | What It Is | How It Uses x0x |
|---------|-----------|-----------------|
| **communitas** | Decentralized collaboration platform (Dioxus + Tauri) | Reference app — messaging, kanban, file sharing, presence all via `communitas-x0x-client` (REST + WebSocket to x0xd) |
| **fae** | Voice-first AI companion (Swift, on-device MLX) | Planned — will join as an agent, discover peers, collaborate with other AI agents via gossip |

## Infrastructure Under x0x

| Project | What It Does | Relationship |
|---------|-------------|--------------|
| **saorsa-pqc** | Post-quantum cryptography (ML-KEM-768, ML-DSA-65) | Foundation — all x0x keys and signatures use PQC |
| **ant-quic** | QUIC transport with native NAT traversal | Integrated — the transport layer under x0x |
| **saorsa-gossip** | 11-crate gossip overlay (HyParView, SWIM, Plumtree) | Integrated — pub/sub, CRDTs, presence, membership |
| **saorsa-mls** | RFC 9420 group encryption (TreeKEM) | Integrated — MLS encrypted groups in x0x |
| **four-word-networking** | Human-readable addresses (IP+port → 4 words) | Integrated — for verbal address sharing |
| **saorsa-webrtc** | WebRTC with pluggable signaling | Available — video/audio calls using x0x for signaling |

## Links

- **Repository**: https://github.com/saorsa-labs/x0x
- **communitas**: https://github.com/saorsa-labs/communitas
- **ant-quic** (transport): https://github.com/saorsa-labs/ant-quic
- **saorsa-gossip** (overlay): https://github.com/saorsa-labs/saorsa-gossip
- **saorsa-pqc** (crypto): https://crates.io/crates/saorsa-pqc
- **All projects**: [github.com/saorsa-labs](https://github.com/saorsa-labs)
- **Contact**: david@saorsalabs.com
- **License**: MIT OR Apache-2.0
