# Identity Deep Dive: What Exists, What's Missing, What's Confusing

*Generated 2026-04-03 from codebase analysis of x0x, four-word-networking, and communitas.*

---

## 1. MachineId

### Definition

```rust
// src/identity.rs:27
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MachineId(pub [u8; 32]);
```

- 32 bytes = SHA-256 of an ML-DSA-65 public key
- Display: `MachineId(0x<first 8 bytes hex>)` (16 hex chars)

### Generation & Storage

- **Generated** in `MachineKeypair::generate()` via `ant_quic::generate_ml_dsa_keypair()`
- **Stored** at `~/.x0x/machine.key` (bincode, 0o600 permissions)
- **Auto-created** on first run if missing; never leaves the machine
- Custom path via `AgentBuilder::with_machine_key(path)`

### How It Acts as a TLS Certificate

The machine keypair is passed directly to ant-quic for QUIC TLS authentication:

```rust
// src/network.rs:273-276
// Pass the machine keypair to ant-quic so that transport PeerId == MachineId
if let Some((pk, sk)) = keypair {
    builder = builder.keypair(pk, sk);
}
```

This implements **RFC 7250 (Raw Public Keys in TLS)** -- no X.509 certificates, no CAs. The ML-DSA-65 public key IS the credential. The ant-quic PeerId is derived from the same key, so `PeerId == MachineId` at the transport layer.

In `src/presence.rs:81`, this equivalence is used directly:
```rust
let machine = MachineId(*peer_id.as_bytes());
```

### Signing Role

Every `IdentityAnnouncement` carries:
- `machine_public_key: Vec<u8>` -- the full ML-DSA-65 public key
- `machine_signature: Vec<u8>` -- ML-DSA-65 signature over all unsigned fields

Verification (`lib.rs:371-409`):
1. Parse `machine_public_key` as ML-DSA-65
2. Derive `SHA-256(pubkey)`, check it matches `machine_id`
3. Verify `machine_signature` over serialized unsigned fields

### Where It Appears

| Surface | What's Shown | File |
|---------|-------------|------|
| `x0x agent` (CLI) | Full 64-char hex | `src/cli/commands/identity.rs:40-46` |
| `x0xd` startup log | `MachineId(0x...)` (16 hex chars) | `src/bin/x0xd.rs:890` |
| GUI sidebar | Chain text: "Agent . Machine" | `src/gui/x0x-gui.html:1358` |
| GUI identity card | 20-char truncated hex | `src/gui/x0x-gui.html:1480` |
| Introduction card | Only at Known+ trust | `src/bin/x0xd.rs:2555-2610` |
| Contacts system | `MachineRecord` with pinning | `src/contacts.rs:140-172` |

### Trust & Pinning

Contacts can pin specific machines (`src/contacts.rs`, `src/trust.rs`):
- `IdentityType::Pinned` + wrong machine = `RejectMachineMismatch`
- CLI: `x0x machines add/remove/pin/unpin <agent_id> <machine_id>`

---

## 2. AgentId

### Definition

```rust
// src/identity.rs:32
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub [u8; 32]);
```

- 32 bytes = SHA-256 of a *different* ML-DSA-65 public key than the machine key
- Display: `AgentId(0x<first 8 bytes hex>)` (16 hex chars)

### Generation & Storage

- **Generated** in `AgentKeypair::generate()` via `ant_quic::generate_ml_dsa_keypair()`
- **Stored** at `~/.x0x/agent.key` (bincode, 0o600 permissions)
- **Portable** -- can be copied to another machine (unlike machine.key)
- Custom path via `AgentBuilder::with_agent_key_path(path)`

### Relationship to MachineId

The `Identity` struct (`src/identity.rs:511-516`) holds both:

```rust
pub struct Identity {
    machine_keypair: MachineKeypair,   // Layer 0: hardware-pinned
    agent_keypair: AgentKeypair,       // Layer 1: portable
    user_keypair: Option<UserKeypair>, // Layer 2: optional human
    agent_certificate: Option<AgentCertificate>,
}
```

Key distinction: **AgentId is the primary identity** used for contacts, trust, discovery, and gossip topics. MachineId is the transport-layer credential. An agent can move between machines and keep its AgentId.

### Gossip & Discovery

AgentId drives the pub/sub topology:
- Broadcast topic: `x0x.identity.announce.v1`
- Shard topic: `x0x.identity.shard.<BLAKE3(agent_id) & 0xFFFF>` (65,536 shards)
- Rendezvous topic: `x0x.rendezvous.shard.<same_shard>`
- Discovery cache: `HashMap<AgentId, DiscoveredAgent>`

### Where It Appears

| Surface | What's Shown | File |
|---------|-------------|------|
| `x0x agent` (CLI) | Full 64-char hex + `identity_words` (4 words) | `src/cli/commands/identity.rs` |
| `x0x status` (CLI) | Full hex + `identity_words` | `src/cli/commands/network.rs` |
| `x0x find` (CLI) | 4-word prefix search | `src/cli/commands/find.rs` |
| GUI sidebar | 12-char hex truncation | `src/gui/x0x-gui.html:1357` |
| GUI status bar | 8-char hex truncation | `src/gui/x0x-gui.html:1423` |
| GUI agents table | 10-char default truncation | `src/gui/x0x-gui.html:1552` |
| Discovered agents API | Full hex + optional `identity_words` | `src/bin/x0xd.rs:635-644` |
| Contacts | Primary key for trust | `src/contacts.rs:176-193` |

### Four-Word Identity

Since the feature/identity-words branch, AgentId is encoded to 4 speakable words via `IdentityEncoder` from four-word-networking:
- Takes first 6 bytes (48 bits) of the 32-byte hash
- Encodes as 4 words from the 4,096-word dictionary (12 bits each)
- Injected client-side by CLI commands (`inject_identity_words`)
- Also stored in beacons as `identity_words: Option<String>`

---

## 3. UserId (Human ID)

### Definition

```rust
// src/identity.rs:35
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub [u8; 32]);
```

- 32 bytes = SHA-256 of a human's ML-DSA-65 public key
- Display: `UserId(0x<first 8 bytes hex>)`
- **Fully implemented and working** -- not a stub

### Generation & Storage

- `UserKeypair::generate()` -- same ML-DSA-65 mechanism
- Stored at `~/.x0x/user.key` (bincode, 0o600 permissions)
- **Never auto-generated** -- creating a human identity is an intentional act
- Set via `AgentBuilder::with_user_key(keypair)` or `with_user_key_path(path)`

Comment in `src/identity.rs:556-558`:
> User keys are not auto-generated -- creating a human identity is an intentional act via `AgentBuilder::with_user_key`.

### AgentCertificate (Binding AgentId to UserId)

```rust
// src/identity.rs:362-380
pub struct AgentCertificate {
    user_public_key: Vec<u8>,    // User's ML-DSA-65 public key
    agent_public_key: Vec<u8>,   // Agent's ML-DSA-65 public key
    signature: Vec<u8>,          // User signs: "x0x-agent-cert-v1" || user_pk || agent_pk || timestamp
    issued_at: u64,
}
```

- **Issuance** (`identity.rs:386-423`): User's secret key signs the concatenated message
- **Verification** (`identity.rs:425-462`): Anyone can verify using the embedded user public key
- **ID extraction**: `cert.user_id()` and `cert.agent_id()` derive IDs from the embedded keys
- Fully tested with tamper detection

### Opt-In / Ex-Directory Model

Announcements are **silent about user identity by default**:

```rust
// lib.rs:1745-1748
if include_user_identity && !human_consent {
    return Err("human identity disclosure requires explicit human consent")
}
```

Two boolean gates:
1. `include_user` -- whether to include UserId and certificate
2. `consent` -- explicit human consent required (belt-and-suspenders)

CLI: `x0x announce --include-user --consent`
API: `POST /announce { "include_user_identity": true, "human_consent": true }`

When opted out (default), the announcement has `user_id: None, agent_certificate: None`. The agent is effectively autonomous/anonymous -- no way to link it to a human.

### Where It Appears

| Surface | What's Shown | File |
|---------|-------------|------|
| `x0x agent` (CLI) | Full hex (if set) + `user_words` (4 words) | `src/cli/commands/identity.rs` |
| `x0x agent user-id` | Hex or null | `src/bin/x0xd.rs` |
| `x0x agents by-user <id>` | List of agents linked to user | `src/cli/commands/discovery.rs` |
| GUI agents table | 8-char hex, lavender color | `src/gui/x0x-gui.html:1557` |
| Introduction card | Only at Known+ trust | `src/bin/x0xd.rs:2555-2610` |
| Discovery cache | `user_id: Option<UserId>` | `src/lib.rs:437-472` |

---

## 4. Relationships: Code vs Spec

### FUTURE_PATH Describes

```
One Human (UserId)
  has many Agents (AgentId)
    each agent runs on many Machines (MachineId)
```

8-word identity: `[4 agent words] @ [4 user words]`
- 4 words = autonomous agent (no human)
- 8 words = human-backed agent with cryptographic accountability

### Code Implements

The hierarchy is **correctly modelled**:

```rust
// src/identity.rs:503-516
// User (human, long-lived, owns many agents)
//   +-- Agent (portable, runs on many machines)
//        +-- Machine (hardware-pinned)
pub struct Identity {
    machine_keypair: MachineKeypair,        // always present
    agent_keypair: AgentKeypair,            // always present
    user_keypair: Option<UserKeypair>,      // opt-in
    agent_certificate: Option<AgentCertificate>, // binds user->agent
}
```

### What's Correctly Implemented

| Spec Feature | Code Status |
|-------------|-------------|
| Three-layer identity hierarchy | Complete (`Identity` struct) |
| ML-DSA-65 for all three layers | Complete (via ant-quic) |
| SHA-256 derivation for all IDs | Complete |
| AgentCertificate binding | Complete with signing + verification |
| Machine key = QUIC TLS credential | Complete (RFC 7250 raw keys) |
| Opt-in user disclosure with consent | Complete |
| 4-word agent identity words | Complete (feature branch) |
| 4-word location words | Complete (feature branch) |
| identity_words in presence beacons | Complete (feature branch) |
| Trust levels + machine pinning | Complete |
| Introduction card | Complete (trust-gated) |

### What's Missing vs Spec

| Spec Feature | Status |
|-------------|--------|
| **8-word format (`agent @ user`)** | Not implemented. CLI find accepts 9 tokens (4 @ 4) but display never shows the combined format |
| **Word count semantics** (4 = autonomous, 8 = human-backed) | Not surfaced in UI. No visual distinction between autonomous and human-backed agents |
| **IntroductionCard ML-DSA-65 signature** | Placeholder -- uses `machine_public_key` bytes, not a real signature (`identity.rs` TODO) |
| **"One human, many agents" discovery** | Partial -- `find_agents_by_user()` works but only on local cache; no network-wide user lookup |
| **Agent certificate revocation** | `RevocationRecord` exists but no certificate-specific revocation |
| **Multi-language dictionaries** | Not started |

---

## 5. Current UX Problems

### Problem 1: Hex Soup

The primary identifier shown everywhere is a 64-character hex string. Users see:

```
agent_id: "da2233d6ba2f95696e5f5ba3bc4db193be1aa53d7ce1c048a8e8a67639337b75"
```

Even truncated, hex is meaningless to humans:
- GUI sidebar: `da2233d6ba2f` (12 chars)
- GUI status bar: `da2233d6` (8 chars)
- GUI agents table: `da2233d6ba` (10 chars)

Four-word identity words exist but are **injected client-side by the CLI only** -- the GUI doesn't show them at all.

### Problem 2: GUI Has No Four-Word Support

The GUI (`src/gui/x0x-gui.html`) was written before four-word-networking integration:
- Sidebar shows truncated hex, never identity words
- Agents table shows truncated hex, no `identity_words` column
- Status bar shows `agent:<8 hex chars>`
- No location words displayed for addresses
- The `identity_words` field in `DiscoveredAgentEntry` is returned by the API but never rendered

### Problem 3: Three IDs Shown Without Explanation

The GUI identity card shows all three IDs but with no context:
```
Agent ID: da2233d6ba2f95696e5f...
Machine ID: 7a1b2c3d4e5f6789ab...
User ID: (optional, sometimes present)
```

There's a chain label ("User . Agent . Machine" or "Agent . Machine") but no explanation of what each means or why there are three.

### Problem 4: Inconsistent Truncation

Different surfaces truncate hex IDs to different lengths with no rationale:
- Display trait: 16 hex chars (8 bytes)
- GUI sidebar: 12 hex chars
- GUI status bar: 8 hex chars
- GUI agents table: 10 hex chars (agent_id) vs 8 (user_id)
- CLI API: full 64 chars
- CLI compact: 8 hex chars (4 bytes)

### Problem 5: MachineId vs AgentId Confusion

Both are 32-byte SHA-256 hashes of ML-DSA-65 keys. Without four-word differentiation, they look identical in format. The relationship (agent is portable, machine is hardware-pinned) is not explained anywhere in the UI.

A user seeing both `da2233d6...` (agent) and `7a1b2c3d...` (machine) has no idea which is which or why both exist.

### Problem 6: No Visual Distinction Between Autonomous and Human-Backed Agents

FUTURE_PATH specifies a key UX signal: 4 words = autonomous, 8 words = human-backed. Currently:
- Both types show the same fields
- `user_id` is just another optional hex string
- No "this agent has a human behind it" indicator
- No "4 @ 4" combined format anywhere

### Problem 7: Location Words Not in GUI

`x0x status` (CLI) shows location words for addresses, but the GUI status panel doesn't. Addresses appear as raw `IP:port` strings.

### Problem 8: Introduction Card Signature is a Placeholder

```rust
// src/identity.rs - IntroductionCard
pub signature: Vec<u8>, // TODO: placeholder, machine pubkey for now
```

The `from_identity()` method stores `machine_keypair.public_key().as_bytes()` as the "signature" -- this is not actually signed content. Needs proper ML-DSA-65 signing.

### Problem 9: Communitas Divergence

Communitas (the companion app) has its own identity model documented in ADR-001 with a WHO/WHERE/SHOWN separation:
- **WHO**: pubkey_hex (3904 chars) -- the identity
- **WHERE**: four-word connection address -- ephemeral
- **SHOWN**: display_name -- human-friendly

This is a cleaner mental model than what x0x currently presents. But communitas doesn't use x0x's `IdentityEncoder` for agent identity words -- it only uses `FourWordAdaptiveEncoder` for connection addresses. The x0x four-word identity encoding (hash-to-words) is a separate concept that communitas hasn't adopted yet.

Key tension: communitas ADR-001 says "four words are ONLY for connection addresses, NOT identity" -- but x0x FUTURE_PATH says "4 words for agent identity, 8 words for full identity." These need reconciliation.

---

## 6. Communitas Identity Presentation

### Dioxus (Desktop) App

- **People view** (`communitas-dioxus/src/components/people_view.rs`): Shows contacts with trust-level colored dots, labels, truncated agent_id hex, last seen
- **Local profile** (`communitas-dioxus/src/components/local_x0x_profile_view.rs`): Shows display_name, full agent_id hex, machine_id hex, optional user_id
- **Sidebar** (`communitas-dioxus/src/components/sidebar/contact_list_section.rs`): Contacts by display_name with presence status

### Swift (Apple) App

- `AgentIdentity` struct: `agentId`, `machineId`, optional `userId` (all hex strings)
- `Contact` struct: `agentId` as primary key, `label`, `trustLevel`
- `AppState`: Falls back to first 8 chars of agentId as displayName

### Key Types

```rust
// communitas-ui-api/src/lib.rs
pub struct UnifiedIdentity {
    pub display_name: String,
    pub four_words: String,     // Should be renamed to `location_words`
}

// communitas-ui-service/src/auth.rs
pub struct AuthSession {
    pub pubkey_hex: String,
    pub four_words: String,     // Should be renamed to `location_words`
    pub display_name: String,
    pub device_name: String,
    pub expires_at: u64,
}
```

### What's Missing in Communitas

- No `IdentityEncoder` integration (agent hash-to-words)
- No 8-word identity format
- No distinction between 4-word identity (permanent) and 4-word location (ephemeral)
- Display falls back to truncated hex when no display_name is set
- Trust UI exists but doesn't show identity words

---

## Summary: What Exists, What's Missing, What's Confusing

### Exists and Working Well

- Three-layer identity hierarchy with ML-DSA-65 post-quantum crypto
- RFC 7250 raw public key TLS via ant-quic
- AgentCertificate binding with proper signing and verification
- Opt-in user identity with consent gate
- Trust levels, machine pinning, revocation
- 4-word agent identity words (CLI only, feature branch)
- 4-word location words (CLI only, feature branch)
- identity_words in presence beacons (feature branch)
- Trust-gated introduction cards

### Missing

1. **GUI four-word support** -- the GUI shows no identity words or location words at all
2. **8-word combined format** (`agent @ user`) -- not displayed anywhere
3. **Visual autonomous vs human-backed distinction** -- no UI signal for the word-count semantics
4. **IntroductionCard real signature** -- placeholder using pubkey bytes
5. **Communitas IdentityEncoder integration** -- doesn't use hash-to-words yet
6. **Network-wide user lookup** -- `find_agents_by_user` only searches local cache
7. **Consistent truncation/display strategy** -- no standard for how IDs are shortened

### Confusing

1. **Three hex strings** shown with no explanation of the hierarchy
2. **Communitas says "four words = connection only"** while x0x says "four words = identity too" -- needs reconciliation
3. **MachineId vs AgentId** look identical (both 64-char hex) with no visual/verbal distinction
4. **Inconsistent ID truncation** across surfaces (8, 10, 12, 16, 20, 64 chars)
5. **`identity_words` field exists in API but GUI ignores it** -- partial integration
6. **"Identity words" vs "location words" vs "connection words"** -- three names for two concepts across two repos (now standardized in x0x; communitas still uses `four_words`)

---

## 7. Terminology Standardization (April 2026)

The codebase now uses exactly two terms for the two word-encoding concepts:

| Term | Meaning | Encoder | Derived From | Lifetime |
|------|---------|---------|-------------|----------|
| **identity_words** | Permanent 4-word name | `IdentityEncoder` | First 48 bits of SHA-256(public key) | Permanent (tied to keypair) |
| **location_words** | Ephemeral 4-word address | `FourWordAdaptiveEncoder` | IP:port | Ephemeral (changes with network) |

### Deprecated terms (no longer in x0x codebase)
- `four_words` -- ambiguous; previously used for both concepts
- `connection_words` -- informal synonym for location_words
- `speakable identity` / `speakable name` -- replaced by "identity words"

### Format conventions
- **identity_words**: lowercase, dot-separated (`alpha.beta.gamma.delta`) or space-separated
- **location_words**: lowercase, dot-separated or space-separated
- **Combined human-backed format**: `[4 agent words] @ [4 user words]`

### Where each appears
- `IdentityAnnouncementUnsigned.identity_words` -- presence beacons
- `DiscoveredAgent.identity_words` -- discovery cache
- REST API: `identity_words` and `user_words` fields on agent/status/discovered endpoints
- GUI: identity words shown as primary label; location words for addresses
- CLI: `x0x find` searches by identity words; `x0x status` shows location words
