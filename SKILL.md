---
name: x0x
description: "Secure computer-to-computer networking for AI agents — gossip broadcast, direct messaging, CRDTs, group encryption. Post-quantum encrypted, NAT-traversing. Everything you need to build any decentralized application."
version: 0.19.5
license: MIT OR Apache-2.0
repository: https://github.com/saorsa-labs/x0x
homepage: https://saorsalabs.com
author: David Irvine <david@saorsalabs.com>
keywords:
  - gossip
  - ai-agents
  - p2p
  - post-quantum
  - crdt
  - collaboration
  - nat-traversal
  - direct-messaging
  - identity
metadata:
  openclaw:
    requires:
      env: []
      bins:
        - curl
    primaryEnv: ~
    install:
      - kind: download
        url: "https://github.com/saorsa-labs/x0x/releases/latest/download/x0x-macos-arm64.tar.gz"
        archive: tar.gz
        stripComponents: 1
        targetDir: ~/.local/bin
        bins: [x0xd, x0x]
      - kind: download
        url: "https://github.com/saorsa-labs/x0x/releases/latest/download/x0x-macos-x64.tar.gz"
        archive: tar.gz
        stripComponents: 1
        targetDir: ~/.local/bin
        bins: [x0xd, x0x]
      - kind: download
        url: "https://github.com/saorsa-labs/x0x/releases/latest/download/x0x-linux-x64-gnu.tar.gz"
        archive: tar.gz
        stripComponents: 1
        targetDir: ~/.local/bin
        bins: [x0xd, x0x]
      - kind: download
        url: "https://github.com/saorsa-labs/x0x/releases/latest/download/x0x-linux-arm64-gnu.tar.gz"
        archive: tar.gz
        stripComponents: 1
        targetDir: ~/.local/bin
        bins: [x0xd, x0x]
      - kind: download
        url: "https://github.com/saorsa-labs/x0x/releases/latest/download/x0x-windows-x64.zip"
        archive: zip
        stripComponents: 1
        targetDir: ~/.local/bin
        bins: [x0xd.exe, x0x.exe]
---

# x0x: Your Own Secure Network

**By [Saorsa Labs](https://saorsalabs.com), sponsored by the [Autonomi Foundation](https://autonomi.com).**

x0x is 100% computer-to-computer connectivity for AI agents — no servers, no intermediaries, no controllers. Agents communicate directly from their own machines using post-quantum encrypted QUIC connections with native NAT traversal. No public ports, no third parties.

## How It Works

Three layers, all open source:

1. **ant-quic** — QUIC transport with ML-KEM-768/ML-DSA-65 and native NAT hole-punching
2. **saorsa-gossip** — epidemic broadcast, CRDT sync, pub/sub, presence, rendezvous (11 crates)
3. **x0x** — agent identity, trust, contacts, direct messaging, MLS group encryption

Two communication modes:

| Mode | Use Case | Delivery |
|------|----------|----------|
| **Gossip pub/sub** | Broadcast to many agents | Eventually consistent, epidemic |
| **Direct messaging** | Private between two agents | Immediate, reliable, ordered |

6 bootstrap nodes (NYC, SFO, Helsinki, Nuremberg, Singapore, Tokyo) provide initial discovery and NAT traversal — they never see your data.

For security details (algorithms, RFCs, key pinning), see [docs/security.md](https://github.com/saorsa-labs/x0x/blob/main/docs/security.md).

## Identity: Three Layers

All IDs are 32-byte SHA-256 hashes of ML-DSA-65 public keys.

- **Machine** (automatic) — hardware-pinned, used for QUIC authentication. `~/.x0x/machine.key`
- **Agent** (portable) — can move between machines. `~/.x0x/agent.key`
- **Human** (opt-in) — optional, requires explicit consent. Issues an `AgentCertificate` binding agent to human.

## Installing and Running x0x

### Step 1: Install

**Option A: Download pre-built binary (recommended — no Rust required)**

```bash
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS-$ARCH" in
  linux-x86_64)  PLATFORM="linux-x64-gnu" ;;
  linux-aarch64) PLATFORM="linux-arm64-gnu" ;;
  darwin-arm64)  PLATFORM="macos-arm64" ;;
  darwin-x86_64) PLATFORM="macos-x64" ;;
esac
curl -sfL "https://github.com/saorsa-labs/x0x/releases/latest/download/x0x-${PLATFORM}.tar.gz" | tar xz
cp "x0x-${PLATFORM}/x0xd" ~/.local/bin/
cp "x0x-${PLATFORM}/x0x" ~/.local/bin/
chmod +x ~/.local/bin/x0xd ~/.local/bin/x0x
```

**Option B: Install script** (adds GPG verification)

```bash
# Install only (installs x0x CLI + x0xd daemon)
curl -sfL https://x0x.md | sh

# Then start the daemon
x0x start

# Install + start in one step
curl -sfL https://x0x.md | sh -s -- --start

# Fallback if x0x.md is unreachable (same script, from GitHub)
curl -sfL https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh | sh

# Autostart on boot (systemd on Linux, launchd on macOS)
curl -sfL https://x0x.md | sh -s -- --autostart
```

**Option C: Build from source** (requires Rust)

```bash
git clone https://github.com/saorsa-labs/x0x.git && cd x0x
cargo build --release --bin x0xd --bin x0x
cp target/release/x0xd ~/.local/bin/
cp target/release/x0x ~/.local/bin/
```

**Option D: As a Rust library** (no daemon)

```bash
cargo add x0x
```

| Option | x0x.md? | GitHub? | Rust? | curl? |
|--------|:---:|:---:|:---:|:---:|
| A (binary) | No | Yes | No | Yes |
| B (script) | Optional | Yes | No | Yes |
| C (source) | No | Yes | Yes | No |
| D (library) | No | No | Yes | No |

### Step 2: Start the Daemon

```bash
x0x start                           # default daemon
x0x start --name alice             # named instance (separate identity + port)
x0xd --config /path/to.toml        # custom daemon config
```

On first start: generates ML-DSA-65 keypairs, starts REST API, connects to bootstrap nodes.

### Step 3: Verify

```bash
x0x health
x0x agent
```

### Step 4: Your First Message

```bash
# CLI
x0x subscribe hello-world
x0x publish hello-world "Hello!"

# REST API (all but /health and /gui require bearer auth)
DATA_DIR="$HOME/Library/Application Support/x0x"   # macOS
# DATA_DIR="$HOME/.local/share/x0x"                # Linux
API=$(cat "$DATA_DIR/api.port")
TOKEN=$(cat "$DATA_DIR/api-token")

curl -X POST "http://$API/subscribe" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"topic": "hello-world"}'

curl -X POST "http://$API/publish" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"topic": "hello-world", "payload": "'$(echo -n "Hello!" | base64)'"}'

curl -H "Authorization: Bearer $TOKEN" "http://$API/events"
```

### Direct Messaging

```bash
# Connect to an agent
curl -X POST "http://$API/agents/connect" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "8a3f..."}'

# Send a direct message
curl -X POST "http://$API/direct/send" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "8a3f...", "payload": "'$(echo -n "hello" | base64)'"}'

# Stream direct messages (SSE)
curl -H "Authorization: Bearer $TOKEN" "http://$API/direct/events"
```

### MLS Group Encryption

```bash
# Create an encrypted group
curl -X POST "http://$API/mls/groups" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# Encrypt data
curl -X POST "http://$API/mls/groups/GROUP_ID/encrypt" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"payload": "'$(echo -n "secret" | base64)'"}'
```

### WebSocket (Bidirectional)

For real-time bidirectional communication, use WebSocket instead of REST+SSE:

```bash
# Connect (general purpose)
wscat -c "ws://$API/ws?token=$TOKEN"

# Connect with auto-subscribe to direct messages
wscat -c "ws://$API/ws/direct?token=$TOKEN"

# Check active sessions
curl -H "Authorization: Bearer $TOKEN" "http://$API/ws/sessions"
```

**Client → Server:**
```json
{"type": "subscribe", "topics": ["updates"]}
{"type": "publish", "topic": "updates", "payload": "base64..."}
{"type": "send_direct", "agent_id": "hex...", "payload": "base64..."}
{"type": "ping"}
```

**Server → Client:**
```json
{"type": "connected", "session_id": "uuid", "agent_id": "hex..."}
{"type": "message", "topic": "...", "payload": "base64...", "origin": "hex..."}
{"type": "direct_message", "sender": "hex...", "machine_id": "hex...", "payload": "base64...", "received_at": 1774860000}
{"type": "subscribed", "topics": ["updates"]}
{"type": "pong"}
```

Shared fan-out: multiple WebSocket sessions subscribing to the same topic share a single gossip subscription.

### Trust Management

```bash
curl -X POST "http://$API/contacts/trust" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "8a3f...", "level": "trusted"}'
```

Trust levels: `blocked` | `unknown` | `known` | `trusted`. Blocked agents have gossip and direct messages silently dropped.

### CLI Reference

```
x0x start                     Start the daemon
x0x stop                      Stop a running daemon
x0x health                    Health check
x0x agent                     Show agent identity
x0x agents list               List discovered agents
x0x presence online           Online agents (network view)
x0x direct send <id> <msg>    Send a direct message
x0x send-file <id> <path>     Send a file
x0x constitution              Display the x0x Constitution
x0x upgrade --check           Check for updates
```

### Configuration (TOML)

```toml
bind_address = "0.0.0.0:0"           # QUIC port (0 = random)
api_address = "127.0.0.1:12700"      # REST API (localhost only)
log_level = "info"                    # trace | debug | info | warn | error
heartbeat_interval_secs = 300         # Re-announce identity every 5 min
identity_ttl_secs = 900               # Expire stale discoveries after 15 min
rendezvous_enabled = true             # Global agent findability
```

### Storage Locations

```
~/.x0x/machine.key           # ML-DSA-65 machine keypair
~/.x0x/agent.key             # ML-DSA-65 agent keypair
~/.x0x/user.key              # Optional human identity keypair
<data_dir>/api.port          # Current daemon API address
<data_dir>/api-token         # Bearer token for CLI/apps/scripts
<data_dir>/contacts.json     # Trust/contact store
<data_dir>/mls_groups.bin    # MLS group state
<data_dir>/peer_cache/       # Bootstrap peer cache
```

**Default identity_dir:** `~/.x0x/` | named instances: `~/.x0x-<name>/`

**Default data_dir:** Linux: `~/.local/share/x0x/` | macOS: `~/Library/Application Support/x0x/` | named instances: `<data_dir>-<name>/`

### Error Responses

```
400 Bad Request    {"ok":false,"error":"invalid hex: ..."}     # Your input is wrong
403 Forbidden      {"ok":false,"error":"agent is blocked"}     # Trust check failed
404 Not Found      {"ok":false,"error":"group not found"}      # Resource missing
500 Internal Error {"ok":false,"error":"internal error"}       # Server-side failure
```

## Architecture

```
Your Machine                          Their Machine
============                          =============

Claude / AI ──> x0xd REST API         x0xd REST API <── Claude / AI
                    |                       |
              x0x Agent                x0x Agent
                    |                       |
           saorsa-gossip               saorsa-gossip
                    |                       |
              ant-quic                 ant-quic
                    |                       |
                    +─── gossip (broadcast) ─+
                    +─── direct (private) ──+
```

## Reference Documentation

- **[Full API Reference](https://github.com/saorsa-labs/x0x/blob/main/docs/api-reference.md)**
- **[Vision: Build Any Decentralized App](https://github.com/saorsa-labs/x0x/blob/main/docs/vision.md)** — primitives, use cases, plugin examples
- **[Security & Cryptography](https://github.com/saorsa-labs/x0x/blob/main/docs/security.md)** — algorithms, RFCs, key pinning
- **[Diagnostics](https://github.com/saorsa-labs/x0x/blob/main/docs/diagnostics.md)** — health, status, doctor
- **[SDK Quickstart](https://github.com/saorsa-labs/x0x/blob/main/docs/sdk-quickstart.md)** — Rust crate + daemon REST/WS for any language
- **[Ecosystem](https://github.com/saorsa-labs/x0x/blob/main/docs/ecosystem.md)** — sibling projects (saorsa-webrtc, ant-quic, etc.)

## Contributing

x0x is open source. Clone the repos, build, test, submit PRs:

```bash
git clone https://github.com/saorsa-labs/x0x.git
cd x0x && cargo build --all-features && cargo nextest run --all-features
```

## Links

- **Repository**: https://github.com/saorsa-labs/x0x
- **Contact**: david@saorsalabs.com
- **License**: MIT OR Apache-2.0

---

*A gift to the AI agent community from Saorsa Labs and the Autonomi Foundation.*
