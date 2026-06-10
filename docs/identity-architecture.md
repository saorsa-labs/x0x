# Identity Architecture

x0x uses a three-layer identity model. The layers are separate keys with different operational roles:

- machine identity authenticates transport;
- agent identity names the logical agent;
- user identity optionally binds a human operator to one or more agents.

## Layer 0: Machine Identity

A `MachineId` is derived from an ML-DSA-65 public key:

```
MachineId = SHA-256(ML-DSA-65 public key bytes)
```

The key pair is stored in `~/.x0x/machine.key` (bincode format). It is auto-generated on first run and should not leave the machine during normal operation. The `MachineId` is used as the QUIC transport identity — the same key pair is passed to `ant-quic::NodeConfig` so that the QUIC `PeerId` equals the `MachineId`.

**Purpose**: Hardware-pinned identity for NAT traversal and transport authentication.

## Layer 1: Agent Identity

An `AgentId` is derived from a separate ML-DSA-65 key pair:

```
AgentId = SHA-256(ML-DSA-65 public key bytes)
```

Stored in `~/.x0x/agent.key`. Portable — can be copied to another machine to run the same logical agent on different hardware. Moving only this key preserves `agent_id` but normally changes `machine_id`.

**Purpose**: Persistent agent identity that survives hardware changes.

## Layer 2: User Identity (optional)

A `UserId` is derived from a user key and can bind a human identity to an agent via an `AgentCertificate`:

```
AgentCertificate = sign(UserKeypair, context || user_public_key || agent_public_key || issued_at)
```

Never auto-generated. Opt-in only (`with_user_key()` or `with_user_key_path()`). When included in an announcement, both the certificate and user ID are present or neither is. Announcement APIs also require explicit human consent before disclosing `user_id`.

Create a user identity explicitly with `x0x user-id create [PATH]`. Without `PATH`, the command writes `~/.x0x/user.key`; with `PATH`, it writes there instead. Restart `x0xd`, or set `user_key_path` in `config.toml`, for the daemon to load it. The command overwrites an existing file at the target path, so back up an existing `user.key` first if you want to keep that identity.

The standalone `x0x-user-keygen` binary remains buildable from source as a deprecated compatibility shim, but the canonical user-facing path is `x0x user-id create`.

**Purpose**: Optional human accountability layer.

## Identity Unification

Before Milestone 1, x0x generated separate key pairs for transport (ant-quic) and identity (x0x). After unification, they share the same ML-DSA-65 key pair:

```
machine.key → MachineKeypair → ML-DSA-65 key pair
                              ├── MachineId = SHA-256(public key)
                              └── ant-quic PeerId = SHA-256(public key)
```

This means `agent.machine_id() == ant-quic PeerId` — verified by `identity_unification_test.rs`.

## Identity Announcements

An `IdentityAnnouncement` is broadcast by agents when they join or heartbeat. It carries:

| Field | Purpose |
|-------|---------|
| `agent_id` | Portable agent identity |
| `machine_id` | Hardware identity (= QUIC PeerId) |
| `user_id` | Optional human identity |
| `machine_public_key` | Full ML-DSA-65 public key bytes (for signature verification) |
| `machine_signature` | ML-DSA-65 signature over all unsigned fields |
| `agent_certificate` | Optional user→agent binding certificate |
| `addresses` | Reachability hints |
| `announced_at` | Unix timestamp |
| `nat_type` | NAT classification from network layer |
| `can_receive_direct` | Whether direct inbound connections work |
| `is_relay` | Whether node is relaying for others |
| `is_coordinator` | Whether node is coordinating NAT timing |

The announcement is signed by the machine key to bind the portable agent identity to this specific machine. Verification:

1. Parse `machine_public_key` as ML-DSA-65 public key
2. Derive `machine_id = SHA-256(machine_public_key)` and check it matches `announcement.machine_id`
3. Verify `machine_signature` over the serialized unsigned fields
4. If `user_id` is present, verify `agent_certificate` and check its `agent_id` and `user_id` match

This split is intentional: QUIC authenticates the machine, while identity announcements bind that authenticated machine to a portable agent. Direct-message receivers treat a claimed `AgentId` as verified only when discovery already contains a matching `AgentId -> MachineId` binding.

## Trust Evaluation

The identity listener applies `TrustEvaluator` to every incoming announcement:

```
TrustDecision = evaluate((agent_id, machine_id), ContactStore)
```

Decision flow:
1. Agent not in store → `Unknown` (cache but don't trust)
2. `TrustLevel::Blocked` → `RejectBlocked` (drop, don't cache)
3. `IdentityType::Pinned` + machine not in pinned list → `RejectMachineMismatch` (drop)
4. `IdentityType::Pinned` + machine in pinned list → `Accept`
5. `TrustLevel::Trusted` → `Accept`
6. `TrustLevel::Known` → `AcceptWithFlag`
7. `TrustLevel::Unknown` → cache with unknown tag

Rejected announcements (`RejectBlocked`, `RejectMachineMismatch`) are silently dropped and not added to the discovery cache.

## Identity Announcement Processing

The identity listener processes incoming identity announcements from the gossip network. It performs verification, trust evaluation, caching, epidemic rebroadcast, and auto-connect for each announcement.

### Verification Pipeline

1. Deserialize the announcement payload
2. Check if the payload has been recently verified (blake3 hash deduplication, 60-second window)
3. If not already verified, verify the machine signature
4. Remember verified payloads to avoid redundant signature checks

### Trust Evaluation

5. Apply `TrustEvaluator` to the `(agent_id, machine_id)` pair
6. `RejectBlocked` and `RejectMachineMismatch` announcements are silently dropped

### Caching and Rebroadcast

7. Filter addresses to globally-advertisable scope only
8. Update the discovery cache with the verified announcement
9. Update machine records in the contact store
10. Register the agent→machine mapping in the direct messaging system
11. Re-publish non-self announcements to the gossip topic with a 20-second dedup window

### Auto-Connect

12. If addresses are present and not already connected, spawn a background task to attempt QUIC connection
13. This ensures pub/sub messages can route between peers that share bootstrap nodes

## Discovery Cache and Contact Store

x0x maintains two separate data structures for managing peer identity. The discovery cache is ephemeral and populated from announcements. The contact store is persistent and contains trust policy.

### Discovery Cache (Ephemeral)

- `identity_discovery_cache`: `HashMap<AgentId, DiscoveredAgent>`
- `machine_discovery_cache`: `HashMap<MachineId, DiscoveredMachine>`
- Populated from verified identity announcements
- Entries include: addresses, NAT type, relay capability, timestamps
- No TTL or eviction — entries are updated on new announcements
- Used for connection establishment and reachability queries

### Contact Store (Persistent)

- Stored in `~/.x0x/contacts.json`
- Contains trust levels, identity types, and machine records
- Updated via REST API (`/contacts/*` endpoints)
- Trust decisions are persistent across restarts
- Machine pinning constraints are stored here

### Interaction

- **Discovery → Contacts**: New discovered agents can be added to contacts via `POST /contacts`
- **Contacts → Discovery**: Trust evaluation filters which announcements enter the discovery cache
- **Discovery cache is permissive**: Even `Unknown` trust level announcements are cached
- **Contact store is restrictive**: Only explicitly added/trusted agents have persistent records

## Key Storage

All key files use bincode 1.x format:

```
~/.x0x/
  machine.key   # MachineKeypair: {public_key: [u8], secret_key: [u8]}
  agent.key     # AgentKeypair:   {public_key: [u8], secret_key: [u8]}
  user.key      # UserKeypair:    {public_key: [u8], secret_key: [u8]}, optional
  agent.cert    # AgentCertificate binding user_public_key to agent_public_key, optional
  contacts.json # ContactStore:   JSON with contacts array
```

The contacts file uses JSON (not bincode) for human readability and editability.

The default unnamed daemon uses `~/.x0x` for identity keys. Named instances use matching identity directories such as `~/.x0x-alice`, keeping their machine and agent identities separate from the default instance.

## Announcement Types

x0x uses three distinct announcement types:

### IdentityAnnouncement

- **Purpose**: Binds AgentId to MachineId with optional UserId
- **Signed by**: Machine key
- **Fields**: agent_id, machine_id, user_id, machine_public_key, machine_signature, addresses, announced_at, nat_type, capabilities
- **Topic**: `x0x.identity.announce.v1` + shard topic
- **Rebroadcast**: Yes, epidemic flood with 20-second dedup

### MachineAnnouncement

- **Purpose**: Advertises machine capabilities and reachability
- **Signed by**: Machine key
- **Fields**: machine_id, machine_public_key, machine_signature, addresses, announced_at, nat_type, is_relay, is_coordinator, reachable_via, relay_candidates
- **Topic**: `x0x.machine.announce.v1` + shard topic
- **Rebroadcast**: Yes, with dedup

### UserAnnouncement

- **Purpose**: Binds UserId to multiple AgentCertificates
- **Signed by**: User key
- **Fields**: user_id, user_public_key, agent_certificates, agent_ids, user_signature, announced_at
- **Topic**: `x0x.user.announce.v1` + shard topic
- **Rebroadcast**: Yes, with dedup

## Shard Topic Routing

To scale gossip propagation, x0x uses shard topics derived from identity hashes:

- **Agent shard**: `blake3("x0x/agent/shard/v1/" + agent_id)`
- **Machine shard**: `blake3("x0x/machine/shard/v1/" + machine_id)`
- **User shard**: `blake3("x0x/user/shard/v1/" + user_id)`

The identity listener subscribes to both legacy broadcast topics and shard topics specific to the local agent/machine/user.

## Consent Mechanism

User identity disclosure is strictly opt-in:

- `user.key` is NEVER auto-generated
- The `announce_identity()` API requires `human_consent: true` to include `user_id`
- A `user_identity_consented` AtomicBool makes consent "sticky" across heartbeats
- Once given, subsequent heartbeats continue to include `user_id` until daemon restart
- `agent.cert` is validated against current keys at announcement time, not just at creation

## Architecture Decision

See [ADR 0007: Three-Layer Identity Model](./adr/0007-three-layer-identity-model.md) for the accepted decision and operational rules.

See [ADR 0008: Trust Evaluation System](./adr/0008-trust-evaluation-system.md) for trust decision rules and machine pinning.
