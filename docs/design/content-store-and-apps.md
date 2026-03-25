# Design: Content Store & App Distribution

**Status**: Proposal
**Author**: David Irvine
**Date**: 2026-03-25

## Summary

Add a content store (CRDT-backed key-value storage) and app distribution system to x0x, enabling agents to create, publish, discover, and run web applications over the gossip network.

## Motivation

x0x has a complete REST API and WebSocket interface. Any HTML file can be an x0x app — just open it in a browser and it talks to x0xd on localhost. But today there's no way to:

1. Store content on the network (gossip is ephemeral)
2. Discover what apps exist
3. Download an app from another agent
4. Serve installed apps from x0xd

This design adds three components that close the loop: a content store for persistent replicated data, an app manifest format for distribution, and static file serving in x0xd.

## Architecture

```
                    ┌──────────────────────────────┐
                    │  Browser: x0x-chat.html       │
                    │  fetch("http://localhost:12700/...") │
                    └──────────┬───────────────────┘
                               │
                    ┌──────────▼───────────────────┐
                    │  x0xd (localhost:12700)        │
                    │  ├── REST API (50 endpoints)   │
                    │  ├── WebSocket (/ws)           │
                    │  ├── Static serving (/apps/)   │  ← NEW
                    │  └── Content Store             │  ← NEW
                    └──────────┬───────────────────┘
                               │ gossip
                    ┌──────────▼───────────────────┐
                    │  x0x Network                   │
                    │  ├── KvStore CRDT sync         │  ← NEW
                    │  ├── App Registry              │  ← NEW
                    │  ├── Rendezvous (who has X?)   │
                    │  └── File Transfer (bulk data) │
                    └──────────────────────────────┘
```

---

## Phase 1: KvStore CRDT

### Overview

A generic CRDT-backed key-value store replicated via gossip. Follows the exact same architectural pattern as the existing `TaskList` CRDT: OR-Set for key membership, HashMap for values, LWW-Register for metadata, delta-based sync over gossip topics.

### Data Structures

```rust
/// A replicated key-value store
pub struct KvStore {
    /// Unique store identifier
    id: KvStoreId,
    /// Key membership — OR-Set ensures adds win over removes
    keys: OrSet<String>,
    /// Key-value content
    entries: HashMap<String, KvEntry>,
    /// Store metadata (name, description)
    name: LwwRegister<String>,
    /// Monotonic sequence counter for unique tags
    seq: Arc<AtomicU64>,
    /// Current version for delta tracking
    version: u64,
    /// Per-version changelog for delta generation
    changelog: HashMap<u64, ChangeSet>,
}

/// A single key-value entry
pub struct KvEntry {
    /// The value (raw bytes)
    value: Vec<u8>,
    /// BLAKE3 hash of value
    content_hash: [u8; 32],
    /// Content type hint (e.g., "text/html", "application/json")
    content_type: String,
    /// Arbitrary metadata
    metadata: HashMap<String, String>,
    /// Who wrote this entry
    author: AgentId,
    /// ML-DSA-65 signature over (key || value || content_hash)
    signature: Vec<u8>,
    /// When created
    created_at: u64,
    /// When last updated (LWW semantics)
    updated_at: LwwRegister<u64>,
}

pub type KvStoreId = [u8; 32]; // BLAKE3("x0x.store" || name)
```

### Size Policy

The KvStore is designed for **small content** that can propagate via gossip deltas:

| Content size | Strategy |
|---|---|
| ≤ 64 KB | Inline in CRDT delta, replicated to all subscribers |
| 64 KB – 1 MB | Metadata in CRDT, content via file transfer on demand |
| > 1 MB | Not supported — use file transfer directly |

Entries exceeding 64 KB store a `content_hash` in the CRDT with `value: vec![]`. Peers that want the content request it via file transfer from any peer that has it (discovered via rendezvous).

### Delta Sync

```rust
pub struct KvStoreDelta {
    /// Keys added since version
    added: HashMap<String, (KvEntry, UniqueTag)>,
    /// Keys removed since version (tombstones)
    removed: HashMap<String, HashSet<UniqueTag>>,
    /// Value updates to existing keys
    updated: HashMap<String, KvEntry>,
    /// Metadata updates
    name_update: Option<String>,
    /// Delta version
    version: u64,
}
```

**Gossip topic**: `x0x.store.<hex(store_id)>`

**Sync protocol**: Identical to TaskListSync:
1. Local writes generate a delta, published to the gossip topic
2. Remote deltas received via subscription, merged via `merge_delta()`
3. Anti-entropy recovers missed deltas after partition

### Merge Semantics

- **Key membership**: OR-Set (adds win over concurrent removes)
- **Value conflicts**: LWW by `updated_at` timestamp, deterministic tiebreak by BLAKE3(value)
- **Metadata**: LWW-Register
- **Signature verification**: Entries are only accepted if the ML-DSA-65 signature verifies against the author's public key. This prevents forgery — only the original author can update their entries.

### REST Endpoints

```
POST   /stores                      Create a new store
GET    /stores                      List stores
GET    /stores/:id                  Get store info
POST   /stores/:id/join             Join an existing store by topic
PUT    /stores/:id/:key             Put a value
GET    /stores/:id/:key             Get a value
DELETE /stores/:id/:key             Remove a key
GET    /stores/:id/keys             List all keys with metadata
```

### CLI Commands

```bash
x0x store create "My Store"         # Create a new store
x0x store list                      # List local stores
x0x store join <topic>              # Join a remote store
x0x store put <store> <key> <value> # Put a value (reads stdin for large values)
x0x store get <store> <key>         # Get a value (writes to stdout)
x0x store keys <store>              # List keys
x0x store rm <store> <key>          # Remove a key
```

### Implementation Estimate

~800–1000 lines of Rust, structured as:
- `src/kv/mod.rs` — module exports
- `src/kv/store.rs` — KvStore CRDT (~300 lines, mirrors task_list.rs)
- `src/kv/entry.rs` — KvEntry type (~100 lines)
- `src/kv/delta.rs` — KvStoreDelta + merge (~250 lines, mirrors crdt/delta.rs)
- `src/kv/sync.rs` — KvStoreSync + gossip integration (~200 lines, mirrors crdt/sync.rs)
- `src/kv/error.rs` — KvError types (~50 lines)

---

## Phase 2: App Manifest & Registry

### App Manifest

```rust
pub struct AppManifest {
    /// App name (unique within the registry)
    name: String,
    /// Semantic version
    version: String,
    /// Publisher's agent identity
    author: AgentId,
    /// Human-readable description
    description: String,
    /// Entry point filename (default: "index.html")
    entry: String,
    /// All files in the app bundle
    files: Vec<AppFile>,
    /// BLAKE3 hash of the complete bundle (tar.gz of all files)
    bundle_hash: [u8; 32],
    /// ML-DSA-65 signature over the manifest (excluding this field)
    signature: Vec<u8>,
    /// Publication timestamp
    published_at: u64,
    /// Minimum x0x version required
    min_version: Option<String>,
    /// Which API endpoints the app uses (informational)
    permissions: Vec<String>,
    /// Optional icon (base64-encoded small PNG, ≤8KB)
    icon: Option<String>,
}

pub struct AppFile {
    /// Relative path within the app (e.g., "index.html", "style.css")
    path: String,
    /// BLAKE3 hash of this file
    hash: [u8; 32],
    /// File size in bytes
    size: u64,
}
```

### App Registry

The app registry is a well-known KvStore with a deterministic ID:

```rust
const APP_REGISTRY_ID: KvStoreId = blake3("x0x.apps.registry");
```

- **Key**: app name (e.g., `"x0x-chat"`)
- **Value**: serialized `AppManifest` (JSON)
- **Author verification**: Only the original author can update their app's manifest (signature check)

All nodes that opt in to the registry automatically replicate it via CRDT sync. The registry contains only manifests (~1-5 KB each), not app bundles.

### Bundle Distribution

App bundles (the actual HTML/CSS/JS files) are distributed via two mechanisms:

1. **Small apps (≤64 KB total)**: Bundle is inline in a secondary KvStore keyed by `bundle_hash`. Single HTML files typically fit here.

2. **Larger apps**: Bundle stored locally by seeding nodes. Seekers discover seeders via rendezvous shards and download via file transfer.

```
Publish flow:
  1. Author creates app files
  2. Compute BLAKE3 hash of each file and the bundle
  3. Create AppManifest, sign with ML-DSA-65
  4. Put manifest into app registry KvStore
  5. If small: put bundle into content KvStore
  6. If large: announce on rendezvous shard, serve via file transfer

Install flow:
  1. User runs `x0x apps list` → reads app registry KvStore
  2. User runs `x0x apps install x0x-chat`
  3. Fetch manifest from registry
  4. If small: fetch bundle from content KvStore
  5. If large: find seeder via rendezvous, download via file transfer
  6. Verify BLAKE3 hashes of every file
  7. Verify ML-DSA-65 signature on manifest
  8. Store to ~/.x0x/apps/<name>/
  9. Done — accessible at http://localhost:12700/apps/<name>/
```

### REST Endpoints

```
GET    /apps                        List installed apps
GET    /apps/available              List apps from registry
POST   /apps/install                Install an app {"name": "x0x-chat"}
POST   /apps/publish                Publish an app from local directory
DELETE /apps/:name                  Uninstall an app
GET    /apps/:name/manifest         Get manifest for an installed app
```

### CLI Commands

```bash
x0x apps list                       # List installed apps
x0x apps available                  # List apps from network registry
x0x apps install <name>             # Install from network
x0x apps publish <dir>              # Publish local app directory
x0x apps remove <name>              # Uninstall
x0x apps open <name>                # Open in browser
x0x apps info <name>                # Show manifest details
```

---

## Phase 3: Static File Serving in x0xd

### Route

```
GET /apps/<name>/<path..>
```

Serves files from `~/.x0x/apps/<name>/` with proper MIME types.

### Implementation

Add `tower_http::services::ServeDir` to the axum router, mounted at `/apps/`. Each installed app is a subdirectory.

```rust
// In x0xd router setup
let apps_dir = data_dir.join("apps");
let app = Router::new()
    // ... existing API routes ...
    .nest_service("/apps", ServeDir::new(apps_dir))
    .layer(CorsLayer::permissive());
```

### MIME Types

Standard web MIME types: `.html` → `text/html`, `.css` → `text/css`, `.js` → `application/javascript`, `.json` → `application/json`, `.png` → `image/png`, etc.

### Security

- Apps are sandboxed by the browser's same-origin policy
- Apps can only access `localhost:12700` (x0xd API) — no cross-origin access to other services
- Manifest signatures verified at install time
- BLAKE3 hashes verified at install time
- x0xd never executes app code server-side

### Implementation Estimate

~50 lines to add `ServeDir` to x0xd, ~300 lines for install/publish/remove logic.

---

## Phase 4: Example Apps (ships first)

Five example apps ship in `examples/apps/` as standalone HTML files. These work today without any infrastructure changes — users open them directly in a browser while x0xd runs.

| App | Features demonstrated | Lines |
|---|---|---|
| x0x-chat | WebSocket pub/sub, identity, rooms | ~350 |
| x0x-board | CRDT task lists, real-time sync | ~400 |
| x0x-network | Discovery, peers, NAT, trust | ~450 |
| x0x-drop | File transfer, SHA-256, trust | ~350 |
| x0x-swarm | Pub/sub + CRDTs, task delegation | ~500 |

Once Phase 3 lands, these same apps can be installed via `x0x apps install` and served from x0xd.

---

## Implementation Order

```
Phase 4a: Ship example apps (NOW)
  └── HTML files in examples/apps/, work with current x0xd

Phase 1: KvStore CRDT
  ├── src/kv/ module (store, entry, delta, sync, error)
  ├── REST endpoints in x0xd
  ├── CLI commands
  └── Integration tests

Phase 2: App Manifest & Registry
  ├── AppManifest type + signature verification
  ├── Well-known registry store
  ├── Publish + install logic
  ├── REST endpoints
  └── CLI commands

Phase 3: Static file serving
  ├── ServeDir in x0xd
  ├── MIME type handling
  └── App lifecycle (install/remove/update)

Phase 4b: Migrate example apps to app registry
  └── Publish example apps, test end-to-end flow
```

---

## Security Considerations

1. **Signature verification**: Every app manifest is ML-DSA-65 signed. Tampering is detected.
2. **Content integrity**: Every file is BLAKE3 hashed. Corruption is detected.
3. **Trust filtering**: The app registry uses the same trust system as gossip. Blocked agents' apps are hidden.
4. **Browser sandboxing**: Apps run in the browser, sandboxed by same-origin policy. They can only access x0xd's API.
5. **No server-side execution**: x0xd serves static files only. No CGI, no server-side rendering, no eval.
6. **Size limits**: KvStore entries capped at 64 KB inline, 1 MB max. Prevents network abuse.
7. **Author pinning**: Only the original author can update their app in the registry (verified by signature).

## Open Questions

1. **App updates**: Should x0xd auto-update installed apps when a new version appears in the registry? Or require explicit `x0x apps update`?
2. **App ratings/reviews**: Should the registry support ratings? Could be done as a separate KvStore keyed by `(app_name, reviewer_agent_id)`.
3. **Private apps**: Should MLS-encrypted app manifests be supported for private distribution to group members?
4. **App sandboxing**: Should we add a permissions model where apps declare which endpoints they use, and x0xd enforces it? (Probably not needed for v1.)
5. **Offline apps**: Should apps be service-worker capable so they work even when x0xd is temporarily down?

## Future Possibilities

- **AI-generated apps**: An agent generates an HTML app, publishes it, and other agents discover and use it. The app itself is the agent's "UI".
- **App composition**: Apps that embed other apps (iframes to other `/apps/` paths).
- **App marketplace**: A web UI for browsing, installing, and reviewing apps — itself distributed as an x0x app.
- **Webhooks**: x0xd pushes events to installed apps via their declared webhook URLs.
- **Shared state**: Multiple apps sharing a KvStore for cross-app data (e.g., user preferences).
