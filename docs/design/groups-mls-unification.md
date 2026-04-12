# Design: Unified Group Surface

## Status

Proposal — design doc only, not yet implemented.

Note: for the fuller long-term architecture covering private secure groups, public discoverable groups, request-access flows, roles, and policy presets, see `docs/design/named-groups-full-model.md`. This document captures the earlier/narrower unification step.

## Problem Statement

x0x currently exposes two parallel group surfaces that operate on the same underlying group ID but through disconnected APIs:

1. **`x0x group` (named groups)** — REST at `/groups`, CLI as `group {create,list,info,invite,join,set-name,leave}`. Manages `GroupInfo` metadata (name, description, display names, chat topic prefix). On creation, it also creates an MLS group internally, but provides no way to encrypt/decrypt messages or manage MLS membership directly.

2. **`x0x groups` (MLS helpers)** — REST at `/mls/groups`, CLI as `groups {create,list,get,add-member,remove-member,encrypt,decrypt,welcome}`. Manages `MlsGroup` cryptographic state (epochs, membership, key schedule). No concept of group name, description, display names, invite links, or gossip topics.

The consequences:

- **Confusing naming**: `x0x group` vs `x0x groups` (singular vs plural) for two different things.
- **Split operations**: To send an encrypted message to a named group, a user must: (a) look up the group ID via `group info`, (b) encrypt via `groups encrypt`, (c) publish to the chat topic via `publish`. Three commands, two mental models.
- **Duplicated state**: `create_named_group` in x0xd already creates an MLS group behind the scenes and stores it in `mls_groups`. But `list_mls_groups` shows orphaned MLS groups that have no named-group counterpart.
- **No send/receive path**: Neither surface provides a `send` or `receive` command for group messaging.

## Current Architecture

`AppState` holds both maps:
- `named_groups: RwLock<HashMap<String, GroupInfo>>` — keyed by group_id hex
- `mls_groups: RwLock<HashMap<String, MlsGroup>>` — keyed by the same group_id hex

`create_named_group` (POST `/groups`) already:
1. Generates a random 32-byte group ID
2. Creates an `MlsGroup` and inserts into `mls_groups`
3. Creates a `GroupInfo` and inserts into `named_groups`
4. Subscribes to chat and metadata gossip topics
5. Publishes a `group_event` announcement

The two are already coupled in practice. The MLS surface is a lower-level escape hatch.

## Proposed Design

### Principle: One primary surface, MLS as opt-in detail

Merge both surfaces under `x0x group` (singular). The MLS encryption layer becomes an optional capability of a named group. Raw MLS primitives remain available under `x0x mls` for power users.

### 1. Add `encrypted` flag to GroupInfo

```rust
pub struct GroupInfo {
    // ... existing fields ...
    pub encrypted: bool,  // whether MLS encryption is active
}
```

Default: `true` (encryption on). A `--no-encrypt` flag on creation opts out.

### 2. Unified CLI

Retire `x0x groups` (plural). All operations move to `x0x group`:

| Current | Proposed | Notes |
|---------|----------|-------|
| `x0x group create <name>` | `x0x group create <name> [--no-encrypt]` | + encryption opt-out |
| `x0x group list` | `x0x group list` | Shows encryption status |
| `x0x group info <id>` | `x0x group info <id>` | Shows MLS epoch, member count |
| `x0x group invite <id>` | `x0x group invite <id>` | Unchanged |
| `x0x group join <link>` | `x0x group join <link>` | Unchanged |
| `x0x groups add-member` | `x0x group add-member <id> <agent>` | Moved |
| `x0x groups remove-member` | `x0x group remove-member <id> <agent>` | Moved |
| `x0x groups encrypt` | `x0x group encrypt <id> <payload>` | Moved |
| `x0x groups decrypt` | `x0x group decrypt <id> <ct> --epoch N` | Moved |
| (none) | `x0x group send <id> <message>` | **New**: encrypt + publish |
| (none) | `x0x group messages <id>` | **New**: subscribe + decrypt |

`x0x groups` is deprecated but kept as alias for one release, printing a warning.

### 3. Unified REST API

Primary surface at `/groups`:

| Method | Path | New? | Description |
|--------|------|------|-------------|
| POST | `/groups` | existing | Create (add `encrypted` field) |
| GET | `/groups` | existing | List (add encryption status) |
| GET | `/groups/:id` | existing | Info (add MLS details) |
| POST | `/groups/:id/send` | **new** | Encrypt + publish to chat topic |
| GET | `/groups/:id/messages` | **new** | SSE stream of decrypted messages |
| POST | `/groups/:id/members` | **new** | Add member |
| DELETE | `/groups/:id/members/:agent_id` | **new** | Remove member |
| POST | `/groups/:id/encrypt` | **new** | Raw encrypt |
| POST | `/groups/:id/decrypt` | **new** | Raw decrypt |

Low-level `/mls/groups` stays for power users. Not advertised in `x0x routes` by default.

### 4. The send/messages path

**`POST /groups/:id/send`**: Look up GroupInfo, build message envelope, encrypt if `encrypted`, publish to `{chat_topic_prefix}/general` (or specified channel).

**`GET /groups/:id/messages`** (SSE): Subscribe to chat topic, decrypt incoming if encrypted, stream decrypted events.

### 5. Files to modify

| File | Change |
|------|--------|
| `src/groups/mod.rs` | Add `encrypted` field to `GroupInfo` |
| `src/bin/x0xd.rs` | Add send/messages/members/encrypt/decrypt handlers |
| `src/bin/x0x.rs` | Merge `GroupsSub` into `GroupSub` |
| `src/cli/commands/group.rs` | Add send, messages, add-member, etc. |
| `src/api/mod.rs` | Update endpoint registry |

### 6. Backward compatibility

- All existing `/mls/groups/*` and `/groups/*` endpoints continue unchanged.
- `encrypted` defaults to `true` via serde default, matching current behavior.
- CLI `x0x groups` kept as alias for one release.

### 7. What this does NOT do

- Does not implement a real MLS tree ratchet.
- Does not add group message persistence or history.
- Does not remove the MLS REST endpoints.
- Does not change the gossip transport layer.

## Open Questions

1. Should `group send` auto-resubscribe if the daemon restarted?
2. Message format standardization for the send/messages path.
3. Should `remove_member` auto-rotate keys (forward secrecy)?
