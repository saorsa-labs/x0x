# Phase 1.3 Plan: REST/CLI + Trust-Scoped Privacy

## Overview

Wire up the 5 presence REST endpoints in `x0xd`, add the matching CLI subcommands,
filter incoming beacons through `TrustEvaluator`, and split presence visibility into
"network" (all reachable) vs "social" (trusted/known only).

Builds on the `Agent::discover_agents_foaf()`, `Agent::discover_agent_by_id()`, and
`Agent::subscribe_presence()` APIs added in Phase 1.2.

## Files

- `src/api/mod.rs`          — 5 new endpoint definitions in ENDPOINTS registry
- `src/bin/x0xd.rs`         — 5 route handlers + trust-scoped AppState helper
- `src/bin/x0x.rs`          — `x0x presence` subcommand with online|foaf|find|status
- `src/presence.rs`         — trust-filtered beacon gate + social/network split
- `src/cli/commands/mod.rs` — presence module export
- `src/cli/commands/presence.rs` (NEW) — presence CLI helpers

---

## Tasks

### Task 1: Register 5 presence endpoints in API registry

**File**: `src/api/mod.rs`

Add these 5 entries to the `ENDPOINTS` constant (after the existing `/presence` entry):

```rust
EndpointDef { method: Method::Get,  path: "/presence/online",       cli_name: "presence online",  description: "List all currently online agents", category: "presence" },
EndpointDef { method: Method::Get,  path: "/presence/foaf",         cli_name: "presence foaf",    description: "FOAF discovery of nearby agents",  category: "presence" },
EndpointDef { method: Method::Get,  path: "/presence/find/:id",     cli_name: "presence find",    description: "Find a specific agent by ID",      category: "presence" },
EndpointDef { method: Method::Get,  path: "/presence/status/:id",   cli_name: "presence status",  description: "Get presence status for an agent", category: "presence" },
EndpointDef { method: Method::Get,  path: "/presence/events",       cli_name: "presence events",  description: "SSE stream of presence events",    category: "presence" },
```

Also rename/replace the old single `/presence` entry with `/presence/online` so the
registry is canonical (the old handler in x0xd can still live but routes to the new
path).

**Estimated Lines**: ~25

---

### Task 2: Trust-scoped presence filter in presence.rs

**File**: `src/presence.rs`

Add a `PresenceVisibility` enum and a `TrustScope` filter function:

```rust
/// Controls which agents are included in a presence response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceVisibility {
    /// Return all reachable agents regardless of trust (network view).
    Network,
    /// Return only Trusted and Known agents (social view).
    Social,
}
```

Add a free function `filter_by_trust`:
```rust
pub fn filter_by_trust(
    agents: Vec<DiscoveredAgent>,
    store: &contacts::ContactStore,
    visibility: PresenceVisibility,
) -> Vec<DiscoveredAgent>
```

- `Network`: return all agents where `TrustDecision` is not `RejectBlocked`
- `Social`: return only agents where `TrustDecision` is `Accept` or `AcceptWithFlag`

Uses `TrustEvaluator::evaluate()` — already in `src/trust.rs`.

**Estimated Lines**: ~60

---

### Task 3: Add x0xd route handlers for presence endpoints

**File**: `src/bin/x0xd.rs`

Add 5 new axum handler functions and wire them into the router:

1. `presence_online` — GET /presence/online
   - Calls `state.agent.presence()` (existing list-online)
   - Applies `Network` visibility (non-blocked)
   - Returns `{ ok: true, agents: [...DiscoveredAgentEntry] }`

2. `presence_foaf` — GET /presence/foaf?ttl=3&timeout_ms=5000
   - Calls `agent.discover_agents_foaf(ttl, timeout_ms).await`
   - Optional query params: `ttl` (u8, default 3), `timeout_ms` (u64, default 5000)
   - Applies `Social` visibility filter

3. `presence_find` — GET /presence/find/:id
   - Path param `:id` is hex-encoded AgentId (64 chars)
   - Calls `agent.discover_agent_by_id(agent_id, ttl, timeout_ms).await`
   - Query params: `ttl` (default 3), `timeout_ms` (default 5000)
   - Returns `{ ok: true, agent: DiscoveredAgentEntry | null }`

4. `presence_status` — GET /presence/status/:id
   - Looks up agent in local discovery cache: `agent.discovered_agents()`
   - Returns `{ ok: true, online: bool, agent: DiscoveredAgentEntry | null }`
   - No network I/O; only local cache lookup

5. `presence_events` — GET /presence/events
   - Subscribes via `agent.subscribe_presence().await`
   - Returns `text/event-stream` SSE response
   - Each `PresenceEvent::AgentOnline` → `data: {"event":"online","agent_id":"..."}\n\n`
   - Each `PresenceEvent::AgentOffline` → `data: {"event":"offline","agent_id":"..."}\n\n`
   - Streams until client disconnects (axum `Body::from_stream`)

Wire into router at line matching the existing `/presence` route.

**Estimated Lines**: ~150

---

### Task 4: presence CLI subcommand (presence.rs)

**Files**: `src/cli/commands/presence.rs` (NEW), `src/cli/commands/mod.rs`

Create `src/cli/commands/presence.rs` with:

```rust
pub async fn online(client: &reqwest::Client) -> anyhow::Result<()>
pub async fn foaf(client: &reqwest::Client, ttl: u8, timeout_ms: u64) -> anyhow::Result<()>
pub async fn find(client: &reqwest::Client, id: &str, ttl: u8, timeout_ms: u64) -> anyhow::Result<()>
pub async fn status(client: &reqwest::Client, id: &str) -> anyhow::Result<()>
```

Each calls the corresponding REST endpoint and prints a human-readable table
(reuse the `tabulate!` pattern from `contacts.rs` in the same directory).

Add `pub mod presence;` to `src/cli/commands/mod.rs`.

**Estimated Lines**: ~100

---

### Task 5: Wire presence subcommand into x0x CLI binary

**File**: `src/bin/x0x.rs`

Add to the `Commands` enum:
```rust
/// Presence operations.
#[command(subcommand)]
Presence(PresenceCommands),
```

Add `PresenceCommands` enum:
```rust
#[derive(Subcommand)]
enum PresenceCommands {
    /// List online agents.
    Online,
    /// FOAF random-walk discovery.
    Foaf {
        #[arg(long, default_value = "3")] ttl: u8,
        #[arg(long, default_value = "5000")] timeout_ms: u64,
    },
    /// Find a specific agent.
    Find {
        id: String,
        #[arg(long, default_value = "3")] ttl: u8,
        #[arg(long, default_value = "5000")] timeout_ms: u64,
    },
    /// Local cache status for an agent.
    Status { id: String },
}
```

Dispatch in the `match commands` block:
```rust
Commands::Presence(cmd) => match cmd {
    PresenceCommands::Online => commands::presence::online(&client).await,
    PresenceCommands::Foaf { ttl, timeout_ms } => commands::presence::foaf(&client, ttl, timeout_ms).await,
    PresenceCommands::Find { id, ttl, timeout_ms } => commands::presence::find(&client, &id, ttl, timeout_ms).await,
    PresenceCommands::Status { id } => commands::presence::status(&client, &id).await,
},
```

Update the `x0x routes` help text block to include the new presence routes.

**Estimated Lines**: ~50

---

### Task 6: Add discovered_agents() accessor to Agent

**File**: `src/lib.rs`

Add a method that exposes the local discovery cache for the `presence_status` endpoint
(no-network, read-only):

```rust
/// Return all currently cached discovered agents.
pub async fn discovered_agents(&self) -> Vec<DiscoveredAgent> {
    self.identity_discovery_cache.read().await.values().cloned().collect()
}
```

Also expose a single-agent lookup:
```rust
/// Look up a specific agent in the local discovery cache.
pub async fn cached_agent(&self, id: &AgentId) -> Option<DiscoveredAgent> {
    self.identity_discovery_cache.read().await.get(id).cloned()
}
```

**Estimated Lines**: ~20

---

## Summary

| Task | File(s) | Lines | Status |
|------|---------|-------|--------|
| 1 | api/mod.rs | ~25 | TODO |
| 2 | presence.rs | ~60 | TODO |
| 3 | bin/x0xd.rs | ~150 | TODO |
| 4 | cli/commands/presence.rs (NEW), cli/commands/mod.rs | ~100 | TODO |
| 5 | bin/x0x.rs | ~50 | TODO |
| 6 | lib.rs | ~20 | TODO |

**Total Estimated Lines**: ~405
