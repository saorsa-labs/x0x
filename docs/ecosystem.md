# Ecosystem — Sibling Projects

> Back to [SKILL.md](https://github.com/saorsa-labs/x0x/blob/main/SKILL.md)

x0x doesn't exist in isolation. The Saorsa Labs ecosystem provides additional capabilities:

| Project | What It Does | Use With x0x |
|---------|-------------|-------------|
| **saorsa-webrtc** | WebRTC with pluggable signaling | Video/audio calls between humans, using x0x for signaling and peer discovery |
| **saorsa-pqc** | Post-quantum cryptography library | Already integrated — all x0x keys and signatures use ML-DSA-65/ML-KEM-768 |
| **ant-quic** | QUIC transport with NAT traversal | Already integrated — the transport layer under x0x |
| **saorsa-gossip** | 11-crate gossip overlay | Already integrated — pub/sub, CRDTs, presence, membership |
| **four-word-networking** | Human-readable addresses | Encode IP+port as 4 words for humans to share verbally ("ocean-forest-moon-star") |

All projects: [github.com/saorsa-labs](https://github.com/saorsa-labs)

## Links

- **Repository**: https://github.com/saorsa-labs/x0x
- **ant-quic** (transport): https://github.com/saorsa-labs/ant-quic
- **saorsa-gossip** (overlay): https://github.com/saorsa-labs/saorsa-gossip
- **saorsa-pqc** (crypto): https://crates.io/crates/saorsa-pqc
- **Contact**: david@saorsalabs.com
- **License**: MIT OR Apache-2.0
