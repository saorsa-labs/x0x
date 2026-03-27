# Building Local Apps on x0x

x0x is designed as an open platform. Any local application — native, web, or script — can use x0xd as a communication substrate via its REST API and WebSocket interface.

## Discovery

x0xd writes two files on startup that local apps need:

| File | Contents | Purpose |
|------|----------|---------|
| `<data_dir>/api.port` | `127.0.0.1:12700` | API address |
| `<data_dir>/api-token` | 64-char hex string | Bearer token |

**Data directory locations:**

| Platform | Default path |
|----------|-------------|
| macOS | `~/Library/Application Support/x0x/` |
| Linux | `~/.local/share/x0x/` |

For named instances (`x0xd --name alice`), the directory is `x0x-alice/` instead of `x0x/`.

## Authentication

All API endpoints (except `/health` and `/gui`) require a bearer token:

```
Authorization: Bearer <token>
```

The token is generated once on first daemon startup and persists across restarts. It's stored at `<data_dir>/api-token` with 0600 permissions (owner read/write only).

WebSocket connections pass the token as a query parameter since browsers cannot set custom headers on WebSocket upgrades:

```
ws://127.0.0.1:12700/ws?token=<token>
```

## Quick Start Examples

### curl

```bash
# Read the connection details
API=$(cat ~/Library/Application\ Support/x0x/api.port)
TOKEN=$(cat ~/Library/Application\ Support/x0x/api-token)

# Health check (no auth required)
curl http://$API/health

# Get agent identity
curl -H "Authorization: Bearer $TOKEN" http://$API/agent

# List contacts
curl -H "Authorization: Bearer $TOKEN" http://$API/contacts

# Publish a message to a topic
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"topic":"my-app/events","payload":"eyJ0ZXh0IjoiaGVsbG8ifQ=="}' \
  http://$API/publish
```

### Python

```python
import json
from pathlib import Path
import requests

# Discover daemon
data_dir = Path.home() / "Library/Application Support/x0x"  # macOS
# data_dir = Path.home() / ".local/share/x0x"                # Linux

api_addr = (data_dir / "api.port").read_text().strip()
api_token = (data_dir / "api-token").read_text().strip()

base = f"http://{api_addr}"
headers = {"Authorization": f"Bearer {api_token}"}

# Get agent info
agent = requests.get(f"{base}/agent", headers=headers).json()
print(f"Agent ID: {agent['agent_id']}")

# List groups
groups = requests.get(f"{base}/groups", headers=headers).json()
for g in groups.get("groups", []):
    print(f"  {g['name']} ({g['group_id'][:12]}...)")
```

### Node.js

```javascript
import { readFileSync } from "fs";
import { join } from "path";
import { homedir } from "os";

// Discover daemon
const dataDir = join(homedir(), "Library/Application Support/x0x"); // macOS
// const dataDir = join(homedir(), ".local/share/x0x");              // Linux

const apiAddr = readFileSync(join(dataDir, "api.port"), "utf-8").trim();
const apiToken = readFileSync(join(dataDir, "api-token"), "utf-8").trim();

const base = `http://${apiAddr}`;
const headers = { Authorization: `Bearer ${apiToken}` };

// Get agent info
const agent = await fetch(`${base}/agent`, { headers }).then((r) => r.json());
console.log(`Agent ID: ${agent.agent_id}`);

// WebSocket with token
const ws = new WebSocket(`ws://${apiAddr}/ws?token=${apiToken}`);
ws.onmessage = (e) => console.log(JSON.parse(e.data));
ws.onopen = () => {
  ws.send(JSON.stringify({ type: "subscribe", topics: ["my-app/events"] }));
};
```

### Rust

```rust
use std::path::PathBuf;

fn discover_x0x() -> (String, String) {
    let data_dir = dirs::data_dir()
        .expect("data dir")
        .join("x0x");
    let addr = std::fs::read_to_string(data_dir.join("api.port"))
        .expect("api.port")
        .trim()
        .to_string();
    let token = std::fs::read_to_string(data_dir.join("api-token"))
        .expect("api-token")
        .trim()
        .to_string();
    (format!("http://{addr}"), token)
}

#[tokio::main]
async fn main() {
    let (base, token) = discover_x0x();
    let client = reqwest::Client::new();

    let agent: serde_json::Value = client
        .get(format!("{base}/agent"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    println!("Agent: {}", agent["agent_id"]);
}
```

## Available Endpoints

x0xd exposes 71 REST endpoints. Key categories:

| Category | Endpoints | What you can do |
|----------|-----------|-----------------|
| Identity | `/agent`, `/agent/card` | Read agent/machine/user IDs, export identity card |
| Messaging | `/publish`, `/subscribe`, `/events` | Gossip pub/sub, SSE event stream |
| Direct | `/direct/send`, `/direct/events` | Point-to-point encrypted messages |
| Groups | `/groups`, `/groups/:id/invite` | Named groups with invite links |
| KvStore | `/stores`, `/stores/:id/:key` | Replicated key-value storage |
| Contacts | `/contacts`, `/contacts/trust` | Contact management, trust levels |
| Discovery | `/agents/discovered`, `/agents/find/:id` | Find agents on the network |
| Files | `/files/send`, `/files/accept/:id` | File transfers between agents |
| WebSocket | `/ws`, `/ws/direct` | Real-time events and direct messages |

Full API reference: [api-reference.md](api-reference.md)

Use `x0x routes` to print all endpoints from a running daemon.

## Named Instances

One daemon is the recommended setup. Named instances exist for development and advanced use cases (pseudonymous personas):

```bash
# Start a named instance
x0xd --name dev

# CLI commands target it
x0x --name dev health

# Separate data directory
# macOS: ~/Library/Application Support/x0x-dev/
# Linux: ~/.local/share/x0x-dev/

# List running instances
x0x instances
```

Each named instance has its own identity (machine key, agent key), contacts, groups, and API token. They appear as completely separate agents on the network.

## Security Model

The API token protects against:
- **Supply chain attacks**: A compromised npm/pip dependency cannot call `fetch('http://127.0.0.1:12700/contacts')` — it doesn't have the token
- **Rogue browser extensions**: Blocked by both CORS (localhost-only) and missing token
- **Cross-process snooping**: Random local processes cannot access the API without reading the token file

The token does **not** protect against malware running as your OS user with filesystem access — such malware can read `~/.x0x/agent.key` directly. The token is defense-in-depth, not a security boundary.

The token file has 0600 permissions (owner-only). On shared systems, this prevents other users from accessing your daemon.
