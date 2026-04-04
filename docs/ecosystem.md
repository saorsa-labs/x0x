# Saorsa Labs Ecosystem Architecture

> **Last updated**: 2026-04-03
> **Source of truth**: This document describes what the code actually implements, not aspirations.

## Vision

**x0x is the network** — a true decentralized, post-quantum encrypted internet for agents and humans. No servers, no gatekeepers, no single point of failure. Every participant is a peer. Every connection is quantum-secure.

**communitas is the proof** — a fully-featured collaboration platform (messaging, kanban, files, canvas) built entirely on x0x. It demonstrates that real applications can run on a decentralized network without compromising on UX. If communitas works, any application can.

**fae is the intelligence** — an AI companion that will live on the x0x network, discover other agents, collaborate on tasks, and create applications. Fae doesn't just use the network; she's a first-class citizen of it — speaking to other agents via gossip, forming encrypted groups, and evolving through self-improvement.

The supporting libraries (saorsa-pqc, saorsa-gossip, saorsa-mls, ant-quic) are the building blocks that make this possible. They're published independently so anyone can build on the same foundation.

## Overview

The ecosystem is a layered stack where each project has a single clear responsibility.

## The Stack

```
┌─────────────────────────────────────────────────────────┐
│                    APPLICATIONS                          │
│                                                         │
│  fae (v0.8)                 communitas (v0.11)          │
│  Swift macOS app            Rust desktop app            │
│  Voice-first AI companion   P2P collaboration platform  │
│  MLX local inference        Dioxus 0.7 + Tauri 2       │
│  Self-improving             CRDTs, Kanban, Messaging    │
│                                                         │
│  Connects to x0x: planned   Connects to x0x: REST/WS   │
│  via communitas-x0x-client                              │
├─────────────────────────────────────────────────────────┤
│                    AGENT LAYER                           │
│                                                         │
│  x0x (v0.15)                                            │
│  Post-quantum encrypted gossip network for AI agents    │
│  Rust crate + npm + PyPI + CLI + REST API + GUI         │
│  33K LoC · 704 tests · 75+ REST endpoints               │
│                                                         │
│  Provides: pub/sub, direct messaging, presence/FOAF,    │
│  CRDT task lists, MLS groups, file transfer, trust,     │
│  self-update, three-layer identity (Machine/Agent/User) │
├─────────────────────────────────────────────────────────┤
│                 INFRASTRUCTURE LAYER                     │
│                                                         │
│  saorsa-gossip (v0.5.12)    ant-quic (v0.25)            │
│  11-crate workspace         QUIC transport + PQC        │
│  HyParView + SWIM +         Native NAT traversal        │
│  Plumtree protocols         No STUN/ICE/TURN            │
│  OR-Set & LWW CRDTs         ML-KEM-768 key exchange     │
│  Rendezvous shards          Connection migration        │
│  404 tests                                              │
│                                                         │
│  saorsa-mls (v0.3.5)                                    │
│  RFC 9420 MLS group encryption                          │
│  TreeKEM key agreement                                  │
│  ChaCha20-Poly1305 AEAD                                 │
│  6K LoC · Post-quantum ready                            │
├─────────────────────────────────────────────────────────┤
│              CRYPTOGRAPHIC FOUNDATION                    │
│                                                         │
│  saorsa-pqc (v0.5.1)                                    │
│  Pure post-quantum cryptography · No classical crypto    │
│  ML-KEM-768 (FIPS 203) · ML-DSA-65 (FIPS 204)          │
│  SLH-DSA (FIPS 205) · BLAKE3 · ChaCha20-Poly1305       │
│  14K LoC · Used by every project in the stack           │
└─────────────────────────────────────────────────────────┘
```

## Dependency Graph

```
saorsa-pqc ◄── saorsa-mls
     ▲               │
     │               │ (used by x0x for group encryption)
     │               ▼
     ├────── ant-quic ◄── saorsa-gossip (11 crates)
     │                          │
     │                          │ (all consumed by x0x)
     │                          ▼
     └──────────────────── x0x
                             ▲
                             │ REST + WebSocket
                             │
                    communitas-x0x-client
                             │
                        communitas
```

**Key relationships**:
- `saorsa-pqc` is the foundation — every other project depends on it
- `ant-quic` provides QUIC transport with PQC — used by saorsa-gossip and x0x
- `saorsa-gossip` provides gossip overlay protocols — consumed by x0x as 11 individual crates
- `saorsa-mls` provides MLS group encryption — consumed by x0x
- `x0x` assembles all infrastructure into a single agent API
- `communitas` talks to x0x via HTTP/WebSocket (not embedded)
- `fae` is a standalone Swift app — x0x integration is planned but not yet implemented

## Project Details

### saorsa-pqc — Cryptographic Foundation

| Attribute | Value |
|-----------|-------|
| Language | Rust |
| Version | 0.5.1 |
| LoC | ~14,600 |
| License | MIT OR Apache-2.0 |
| Published | crates.io |
| Dependents | ant-quic, saorsa-gossip, saorsa-mls, x0x, saorsa-node, saorsa-fec, saorsa-seal, saorsa-webrtc |

**What it does**: Pure post-quantum cryptography. ML-KEM for key exchange, ML-DSA for signatures, SLH-DSA for hash-based signatures, plus symmetric primitives (ChaCha20-Poly1305, AES-256-GCM, BLAKE3, HKDF). Two-tier API: high-level (`api::`) for simplicity, trait-based (`pqc::`) for algorithm agility.

**What it doesn't do**: No classical crypto (Ed25519/X25519 removed in v0.5). No networking, no storage.

### ant-quic — QUIC Transport

| Attribute | Value |
|-----------|-------|
| Language | Rust |
| Version | 0.25.2 |
| License | MIT OR Apache-2.0 |
| Published | crates.io |

**What it does**: QUIC transport with post-quantum key exchange (ML-KEM-768). Native NAT traversal via QUIC extension frames (draft-seemann-quic-nat-traversal-02). No STUN, ICE, or TURN servers required. Epsilon-greedy bootstrap cache. LinkTransport trait abstraction.

### saorsa-mls — Group Encryption

| Attribute | Value |
|-----------|-------|
| Language | Rust |
| Version | 0.3.5 |
| LoC | ~6,000 |
| License | AGPL-3.0 |
| Published | crates.io |
| Depends on | saorsa-pqc 0.4 |

**What it does**: RFC 9420 Messaging Layer Security with post-quantum crypto. TreeKEM group key agreement, epoch-based forward secrecy, post-compromise security, welcome messages for async member addition. ChaCha20-Poly1305 AEAD.

**Known limitations**: TreeKEM path secrets use placeholder logic (not full RFC 9420). Wire format uses postcard with no versioning.

### saorsa-gossip — Gossip Overlay Network

| Attribute | Value |
|-----------|-------|
| Language | Rust |
| Version | 0.5.12 |
| Structure | 11-crate workspace |
| License | MIT OR Apache-2.0 |
| Published | 10/11 crates on crates.io |
| Depends on | saorsa-pqc 0.5, ant-quic 0.25.2 |
| Tests | 404 |

**Crates**: types, identity, transport, membership, pubsub, groups, presence, crdt-sync, coordinator, rendezvous, runtime

**What it does**: Complete gossip overlay implementation. HyParView for partial-view topology, SWIM for failure detection, Plumtree for epidemic broadcast. OR-Set and LWW-Register CRDTs with delta sync. 65,536 rendezvous shards for content discovery without DHT. FOAF friend-of-a-friend queries. Coordinator adverts for seedless bootstrap.

**Stability**: types/identity/transport/membership/pubsub/coordinator/rendezvous/crdt-sync are stable. presence and runtime are alpha.

### x0x — The Decentralized Network

**Role in ecosystem**: x0x IS the network. It's a post-quantum encrypted internet for agents — any AI, any application, any human can join as a peer with a single API call. There's no server to provision, no account to create, no company in the middle. x0x assembles all the infrastructure libraries (transport, gossip, crypto, group encryption) into one simple interface: `Agent::new().join_network()`.

| Attribute | Value |
|-----------|-------|
| Language | Rust |
| Version | 0.15.1 |
| LoC | ~33,600 |
| License | MIT OR Apache-2.0 |
| Published | crates.io, npm, PyPI |
| Tests | 744 |
| Depends on | saorsa-pqc, saorsa-mls, ant-quic, all 11 saorsa-gossip crates |

**What it provides**:
- **Identity**: Three layers — MachineId (hardware-pinned), AgentId (portable), UserId (opt-in human)
- **Messaging**: Gossip pub/sub (epidemic broadcast) + direct QUIC (point-to-point)
- **Discovery**: mDNS zero-config LAN, presence beacons, FOAF friend-of-a-friend walk, rendezvous shards
- **Collaboration**: CRDT task lists (OR-Set + LWW-Register), KV store with access control
- **Security**: MLS encrypted groups (RFC 9420), trust/contacts with whitelist-by-default
- **Operations**: Self-update with ML-DSA-65 signed releases, file transfer with SHA-256 integrity

**Surfaces**: Rust crate (`use x0x::Agent`), npm package (`import { Agent } from 'x0x'`), Python package (`from x0x import Agent`), CLI (`x0x`), daemon with REST/WS API (`x0xd`), embedded GUI.

**6 global bootstrap nodes**: NYC, SFO, Helsinki, Nuremberg, Singapore, Tokyo.

### communitas — The Example Application

**Role in ecosystem**: Communitas is the reference application for x0x. It proves that a real-world collaboration platform — with the UX expectations of Slack or Notion — can run on a fully decentralized, post-quantum network. Every feature in communitas exercises a different capability of x0x.

| Attribute | Value |
|-----------|-------|
| Language | Rust |
| Version | 0.11.5 |
| LoC | ~256,000 |
| Structure | 8-crate workspace |
| License | MIT OR Apache-2.0 |
| UI | Dioxus 0.7 + Tauri 2 |

**Crates**: core, dioxus, ui-service, ui-api, kanban, x0x-client, bench, workspace-hack

**What it demonstrates**:
- **Messaging** (threads, reactions, mentions, search) → x0x gossip pub/sub + direct messaging
- **Kanban boards** (CRDT drag-drop collaboration) → x0x CRDT task lists
- **File sharing** (virtual disks, chunked uploads) → x0x file transfer
- **Identity** (ML-DSA signing, BIP-39 recovery) → x0x three-layer identity
- **Presence** (typing indicators, online badges) → x0x presence beacons + FOAF
- **Groups** (spaces, channels, invites) → x0x MLS encrypted groups

**How it connects to x0x**: Via `communitas-x0x-client` crate — HTTP REST + WebSocket to a local x0xd daemon. Communitas does NOT embed the networking stack directly; it trusts x0x to handle all P2P complexity.

**What's scaffolding**: Calls/WebRTC (multimedia incomplete), advanced canvas (integrated but not fully wired), policy kernel and capability tokens (designed, not shipped).

### fae — The Intelligence on the Network

**Role in ecosystem**: Fae is the AI that will live on x0x. She'll discover other agents via gossip, form encrypted groups for collaboration, create applications on the fly, and delegate tasks to other agents. Fae represents the future where AI companions aren't trapped in cloud silos — they're sovereign entities on a decentralized network, communicating peer-to-peer with post-quantum security.

| Attribute | Value |
|-----------|-------|
| Language | Swift |
| Version | 0.8.189 |
| LoC | ~23,000 |
| License | AGPL-3.0 |
| UI | SwiftUI + AppKit |
| ML | MLX (Apple Silicon) |

**What she does today**: Voice-first personal AI companion running entirely on-device. Cascaded pipeline: VAD (Silero) → Speaker ID (ECAPA-TDNN) → STT (Qwen3-ASR) → LLM (Qwen3.5) → TTS (Kokoro-82M). 37 built-in tools, 22 skills, memory system (SQLite + ANN + FTS5), autonomous self-improvement (LoRA training from conversation corrections). Agent delegation to Claude Code, Codex, Gemini. Channels: Discord, WhatsApp, iMessage.

**x0x integration (planned)**: Fae will join the x0x network as an agent, gaining the ability to discover and communicate with other Fae instances and any x0x-connected agent. This transforms her from a single-device companion into a networked intelligence. The "Powered by x0x" branding is in the codebase but the network integration is not yet wired.

## Bootstrap Infrastructure

6 VPS nodes run x0x-bootstrap, hardcoded into the x0x binary:

| Node | IP | Region | Provider |
|------|-----|--------|----------|
| saorsa-2 | 142.93.199.50 | NYC, US | DigitalOcean |
| saorsa-3 | 147.182.234.192 | SFO, US | DigitalOcean |
| saorsa-6 | 65.21.157.229 | Helsinki, FI | Hetzner |
| saorsa-7 | 116.203.101.172 | Nuremberg, DE | Hetzner |
| saorsa-8 | 149.28.156.231 | Singapore, SG | Vultr |
| saorsa-9 | 45.77.176.184 | Tokyo, JP | Vultr |

These nodes are critical infrastructure — every x0x user worldwide connects to them on first join.
