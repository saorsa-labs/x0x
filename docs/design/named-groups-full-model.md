# Design: Full Named Group Model

## Status

Design source of truth — active and evolving.

This document expands and effectively supersedes the narrower ideas in `docs/design/groups-mls-unification.md`.

Implementation is in progress across multiple phases and branches. This document is the architecture target, not proof that the target has been reached. Signoff requires the implementation and review gates described below.

### Execution phases

| Phase | Scope | Purpose |
|-------|-------|---------|
| Phase A | Policy + roles | Establish named groups as first-class policy-governed spaces |
| Phase B | Join requests | Add request-access lifecycle and admin approval/rejection |
| Phase C | Discovery cards | Define public/contact-scoped discovery objects and manual import/bootstrap |
| Phase C.2 | Distributed discovery index | Partition-tolerant gossip discovery without DHT or special nodes |
| Phase D | Secure enforcement | Bind roster/policy changes to MLS state and future-access revocation |
| Phase E | Public group behavior | Open/public send-receive, moderation, and announcement semantics |
| Phase F | Review hardening | Repeatable proof, privacy validation, negative-path authz, convergence |

## Why this exists

x0x currently has the beginnings of a real named-space model, but it is not yet the complete product surface we want.

Today we have:
- human-friendly named groups via `/groups`
- invite join flow
- local + creator-authored roster convergence via metadata events
- low-level MLS helpers via `/mls/groups`
- per-group chat and metadata gossip topics

What we do **not** yet have is a complete, first-class group model that supports:
- truly private secure spaces
- publicly discoverable groups
- request-access groups
- open/public groups
- authoritative roles and moderation
- access enforcement across all group-bound apps

## Product goal

A **named group** should be the primary collaboration primitive in x0x.

A group should support all of these modes under one unified model:

1. **Private secure group**
   - hidden
   - invite-only
   - encrypted
   - members-only read/write

2. **Public discoverable secure group with request access**
   - public listing/card
   - anyone can discover and request access
   - private encrypted content remains hidden from non-members
   - admins can approve or reject requests

3. **Public open community group**
   - publicly discoverable
   - open join or moderated join
   - signed public content
   - moderation / ban / role controls

4. **Public announcement group**
   - discoverable
   - public read
   - admin-only write

## Core design principle

Do **not** model "public" and "private" as separate subsystems.

Instead, every group has a policy made from independent axes:
- discoverability
- admission
- confidentiality
- read policy
- write policy
- role model

This is the only way to cleanly support:
- public but encrypted groups
- request-access private groups
- open public communities
- announcement/broadcast spaces

## Non-goals for the first implementation slices

This design intentionally does **not** require all of these on day one:
- historical message backfill for every group app
- perfect cryptographic revocation for already-downloaded old plaintext
- federation with external directory servers
- anonymous posting
- complex per-channel ACLs before group-level policy exists

## Current state and gaps

Different branches may partially land pieces of Phases A-C, but the design requirements below remain the source of truth.

What matters for signoff is not merely that endpoints exist, but that the following invariants hold:
- stable group identity with evolving, cryptographically committed state validity
- real partition-local discovery for discoverable groups without DHT
- no leakage of hidden or contact-scoped groups through public discovery or presence
- request approval that grants real secure access when confidentiality is MLS-backed
- remove/ban that revokes **future** secure access, not just local roster display
- authority-signed public cards/manifests with immediate supersession of stale revisions
- digest-based anti-entropy and convergence across the reachable partition
- clear separation between the discovery/index plane and the data-transfer plane

## Architecture overview

A named group becomes a **policy-governed space** with three layers:

1. **Identity and control plane**
   - group policy
   - roster
   - roles
   - requests
   - moderation state
   - revisioned metadata

2. **Security plane**
   - MLS for encrypted/member-only groups
   - signed public envelopes for public groups
   - rekey/member removal hooks

3. **App plane**
   - chat
   - files
   - tasks
   - kv/wiki/store
   - presence
   - future apps

All app-plane surfaces inherit the group policy.

## Group policy model

```rust
pub enum GroupDiscoverability {
    Hidden,
    ListedToContacts,
    PublicDirectory,
}

pub enum GroupAdmission {
    InviteOnly,
    RequestAccess,
    OpenJoin,
}

pub enum GroupConfidentiality {
    MlsEncrypted,
    SignedPublic,
}

pub enum GroupReadAccess {
    MembersOnly,
    Public,
}

pub enum GroupWriteAccess {
    MembersOnly,
    ModeratedPublic,
    AdminOnly,
}

pub struct GroupPolicy {
    pub discoverability: GroupDiscoverability,
    pub admission: GroupAdmission,
    pub confidentiality: GroupConfidentiality,
    pub read_access: GroupReadAccess,
    pub write_access: GroupWriteAccess,
}
```

### Recommended presets

#### `private_secure` (default)
- discoverability: `Hidden`
- admission: `InviteOnly`
- confidentiality: `MlsEncrypted`
- read: `MembersOnly`
- write: `MembersOnly`

#### `public_request_secure`
- discoverability: `PublicDirectory`
- admission: `RequestAccess`
- confidentiality: `MlsEncrypted`
- read: `MembersOnly`
- write: `MembersOnly`

#### `public_open`
- discoverability: `PublicDirectory`
- admission: `OpenJoin`
- confidentiality: `SignedPublic`
- read: `Public`
- write: `MembersOnly` or `ModeratedPublic`

#### `public_announce`
- discoverability: `PublicDirectory`
- admission: `OpenJoin` or follow-only
- confidentiality: `SignedPublic`
- read: `Public`
- write: `AdminOnly`

## Membership and roles

A roster entry must be explicit, revisioned, and authoritative.

```rust
pub enum GroupRole {
    Owner,
    Admin,
    Moderator,
    Member,
    Guest,
}

pub enum GroupMemberState {
    Active,
    Pending,
    Removed,
    Banned,
}

pub struct GroupMember {
    pub agent_id: String,
    pub user_id: Option<String>,
    pub role: GroupRole,
    pub state: GroupMemberState,
    pub display_name: Option<String>,
    pub joined_at: u64,
    pub updated_at: u64,
    pub added_by: Option<String>,
    pub removed_by: Option<String>,
}
```

### Rules

- Every group has exactly one `Owner` initially.
- Owners can appoint admins.
- Admins can manage requests and membership according to policy.
- Moderators are mainly useful in public groups.
- `Banned` is distinct from `Removed`.
- Pending access belongs in requests, but pending member-state may still be useful for synchronization.

## Join requests

Public request-access groups require a first-class request object.

```rust
pub enum JoinRequestStatus {
    Pending,
    Approved,
    Rejected,
    Cancelled,
}

pub struct JoinRequest {
    pub request_id: String,
    pub group_id: String,
    pub requester_agent_id: String,
    pub requester_user_id: Option<String>,
    pub requested_role: GroupRole,
    pub message: Option<String>,
    pub created_at: u64,
    pub reviewed_at: Option<u64>,
    pub reviewed_by: Option<String>,
    pub status: JoinRequestStatus,
}
```

## Discovery vs access

This is the most important product distinction.

### Public discovery does not imply public content

A group may be:
- publicly discoverable
- but still private and encrypted internally

That means a non-member can see:
- group card
- description
- tags
- rules
- maybe member count
- request-access affordance

But a non-member cannot see:
- group chat
- files
- tasks
- kv/docs
- secure presence
- private app state

This is essential for a secure public-request-access group.

## Group card / directory model

Groups that are discoverable publish small signed **cards/manifests**, not raw payloads.

Important distinction:
- **Gossip is the discovery plane** — cards, manifests, shard indexes, presence hints, public metadata.
- **Direct transfer / MLS replication / app sync is the data plane** — chat payloads, files, CRDT state, private documents, secure presence details.

Directory topics must carry only the information needed to find and evaluate a group. They must never carry private payload data.

```rust
pub struct GroupCard {
    pub group_id: String,                 // stable forever
    pub revision: u64,                    // monotonic public card/state revision
    pub state_hash: String,               // commitment to current valid group state
    pub prev_state_hash: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub name: String,
    pub description: String,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub tags: Vec<String>,
    pub policy_summary: GroupPolicySummary,
    pub owner_agent_id: String,
    pub admin_count: u32,
    pub member_count: u32,
    pub request_access_enabled: bool,
    pub authority_agent_id: String,
    pub signature: String,
}
```

Important: for the final design, `GroupPolicySummary` must expose enough public semantics to distinguish public modes. A summary that only includes discoverability, admission, and confidentiality is not sufficient for `public_open` vs `public_announce`; at minimum, public read/write semantics must also be derivable.

## Stable identity vs evolving validity

A named group has two identifiers:

1. **Stable identity** — `group_id`
   - created once at group genesis
   - used by invites, links, channels, files, stores, tasks, references
   - does **not** change when the name changes or the roster changes

2. **Evolving validity** — `state_hash`
   - cryptographic commitment to the **current valid group state**
   - changes when authoritative membership, roles, bans, policy, public metadata, or bound security state changes
   - used to supersede stale cards and invalidate stale control-plane actions

Do **not** derive the stable identity from `name + sorted members`. Renames and normal membership churn must not create a brand-new group reference.

```rust
pub struct GroupGenesis {
    pub group_id: String,
    pub creator_agent_id: String,
    pub created_at: u64,
    pub creation_nonce: String,
}

pub struct GroupStateCommit {
    pub group_id: String,
    pub revision: u64,
    pub prev_state_hash: Option<String>,
    pub roster_root: String,
    pub policy_hash: String,
    pub public_meta_hash: String,
    pub security_binding: Option<String>,   // MLS epoch or group-context hash
    pub state_hash: String,
    pub committed_by: String,
    pub signature: String,
}
```

Minimum ingredients of `state_hash`:
- stable `group_id`
- monotonic revision
- previous state hash
- active-membership + role + banned-set commitment
- policy commitment
- public metadata commitment (name/description/tags/avatar/banner)
- security binding for secure groups (MLS epoch or group-context hash)

Rules:
- cards and privileged actions must reference `group_id` and the expected current `state_hash` / `prev_state_hash`
- stale actions are rejected when they do not chain from the current valid state
- pending join requests do **not** have to perturb the main membership/policy validity hash until they change effective access
- TTL is cache cleanup, **not** the primary validity mechanism
- higher signed revisions supersede lower ones immediately

### Discovery surfaces
- local cache of discovered cards/manifests
- public tag/name shard topics for `PublicDirectory` groups
- presence-social browsing for groups whose discoverability allows it
- social propagation (agents share cards and invites in conversation)
- contact-scoped listing for `ListedToContacts` groups
- see [Distributed Discovery Index](#distributed-discovery-index) for full design

## Security model

## Secure groups

For `MlsEncrypted` groups:
- the roster is authoritative for who should have access
- MLS membership enforces future encrypted access
- add/remove operations must drive MLS changes
- removal should trigger epoch change / rekey
- all secure app payloads must be encrypted to current members

This includes:
- group chat
- files
- tasks if group-scoped private
- kv/wiki/docs if group-scoped private
- any future private app data

### Honest limitation to document

Removal can prevent access to **future** encrypted material.
It cannot make a removed peer forget plaintext or ciphertext already received.

## Public groups

For `SignedPublic` groups:
- content is visible according to `read_access`
- all writes are signed by agent identity
- moderation rules determine who may write
- bans and role changes must be enforced on ingest and UI/API surfaces

We should not support anonymous posting as a default mode.
Public should still be accountable.

## Authorization rules

A minimal first ruleset:

- `Owner`
  - change policy
  - appoint/remove admins
  - delete group
  - approve/reject requests
  - add/remove members

- `Admin`
  - approve/reject requests
  - add/remove members except owner
  - manage moderators/member roles
  - moderate public spaces

- `Moderator`
  - remove public posts where applicable
  - mute/ban in public or moderated spaces

- `Member`
  - normal access

### Explicit rejects
- non-admin cannot approve requests
- non-admin cannot remove other members
- banned peer cannot rejoin through open-join alone
- invite creation must follow policy and role checks

## Unifying named groups and MLS

User-facing surface should be `x0x group`.

MLS remains:
- internal mechanism for encrypted groups
- advanced/power-user escape hatch if needed

But the normal product should feel like:
- `x0x group create --preset private_secure`
- `x0x group create --preset public_request_secure`
- `x0x group request-access <group_id>`
- `x0x group approve-request <group_id> <request_id>`
- `x0x group send <group_id> ...`

Not:
- create a named group here
- manage crypto with a different command family there
- publish manually elsewhere

## API proposal

### Group core
- `POST /groups`
- `GET /groups`
- `GET /groups/:id`
- `PATCH /groups/:id`
- `PATCH /groups/:id/policy`
- `DELETE /groups/:id`

### Discovery
- `GET /groups/discover`
- `GET /groups/cards/:id`
- `POST /groups/cards/import`

### Membership
- `GET /groups/:id/members`
- `POST /groups/:id/members`
- `DELETE /groups/:id/members/:agent_id`
- `PATCH /groups/:id/members/:agent_id/role`
- `POST /groups/:id/ban/:agent_id`
- `DELETE /groups/:id/ban/:agent_id`

### Join request flow
- `GET /groups/:id/requests`
- `POST /groups/:id/requests`
- `POST /groups/:id/requests/:request_id/approve`
- `POST /groups/:id/requests/:request_id/reject`
- `DELETE /groups/:id/requests/:request_id`

### Invite flow
- `POST /groups/:id/invite`
- `POST /groups/join`

### Messaging and apps
- `POST /groups/:id/send`
- `GET /groups/:id/messages`
- future:
  - `/groups/:id/files/...`
  - `/groups/:id/tasks/...`
  - `/groups/:id/store/...`

## Metadata event model

The current metadata-event path should evolve into a linear, validity-checked control plane.

Every privileged state-changing action or commit should carry at least:
- `group_id`
- `actor`
- `revision` or expected revision
- `prev_state_hash`
- action payload
- signature

Receivers apply an action or commit only if all of the following hold:
- the signer is authorized for that action
- the action chains from the current valid state
- revision monotonicity holds
- policy-specific invariants still hold at apply time
- the action does not attempt to resurrect superseded state

Cards are a **derived public projection** of the latest committed state. They are not the sole source of truth.

Possible event families:
- `policy_updated`
- `member_added`
- `member_removed`
- `member_role_updated`
- `member_banned`
- `member_unbanned`
- `join_request_created`
- `join_request_approved`
- `join_request_rejected`
- `join_request_cancelled`
- `group_deleted`
- `card_republished`
- `state_withdrawn` / hidden supersession tombstone

### Important note
For v1, prefer a **single canonical state-commit chain** even if multiple admins exist socially. Admins may authorize or propose actions, but accepted public state must linearize into one revision stream. This is simpler and safer than multi-writer conflict resolution for security-sensitive state.

## Data model evolution

`GroupInfo` should evolve from lightweight metadata into a real group envelope with stable identity plus current validity.

Suggested direction:

```rust
pub struct GroupInfo {
    pub group_id: String,
    pub name: String,
    pub description: String,
    pub creator: AgentId,
    pub created_at: u64,
    pub updated_at: u64,

    pub policy: GroupPolicy,
    pub state_revision: u64,
    pub state_hash: String,
    pub prev_state_hash: Option<String>,
    pub roster_revision: u64,
    pub policy_revision: u64,

    pub members: BTreeMap<String, GroupMember>,
    pub join_requests: BTreeMap<String, JoinRequest>,

    pub mls_group_id: Option<String>,
    pub security_binding: Option<String>,
    pub metadata_topic: String,
    pub chat_topic_prefix: String,
    pub discovery_card_topic: Option<String>,
}
```

Notes:
- current `members: BTreeSet<String>` is too weak for the final product
- current `display_names` map should fold into `GroupMember`
- the main `state_hash` should cover **effective access state**; pending requests may live beside it until they affect access
- `security_binding` should track MLS epoch or equivalent secure-group state for `MlsEncrypted` groups
- public cards must be derivable from `GroupInfo` + the latest committed state

## Behavior by preset

### `private_secure`
- hidden from public discovery
- invite-only
- MLS mandatory
- all app surfaces require membership
- remove member => roster update + MLS rekey + future access blocked

### `public_request_secure`
- group card is discoverable
- request objects allowed
- non-members cannot read member content
- approval triggers roster add + MLS welcome/rekey

### `public_open`
- discoverable
- open join or immediate follower/member join
- public read
- signed content
- moderation/bans required

### `public_announce`
- discoverable
- public read
- only owner/admin may publish
- useful for release channels, project updates, public notices

## Migration plan from current state

### Phase A — model hardening
- add `GroupPolicy`
- replace bare member set with structured `GroupMember`
- add role support
- keep current creator-authoritative propagation while evolving schema

### Phase B — request objects
- add `JoinRequest`
- implement request create/list/approve/reject
- support `public_request_secure`

### Phase C — discovery cards / local bootstrap
- add group cards
- add discover/list/import APIs
- support hidden vs listed vs public
- card-import stub creation so non-members can submit join requests
- note: this phase alone is **not** sufficient for real public discovery; Phase C.2 completes that story

### Phase C.2 — distributed discovery index

Partition-tolerant, DHT-free group discovery using existing gossip primitives.
No special node roles — all nodes are equal peers.

See [Distributed Discovery Index](#distributed-discovery-index) below for full design.

### Phase D — secure enforcement
- make secure named-group operations drive MLS membership and rekey semantics
- make group chat/files/tasks/store obey group policy

### Phase E — public group behavior
- add public send/receive path
- add moderation and ban enforcement
- add announcement semantics

## Recommended first implementation slice

The best next coding slice is:

1. add `GroupPolicy` with presets
2. add structured `GroupMember` roles/state
3. add request-access objects and endpoints
4. implement `public_request_secure`

Why this slice first:
- it directly unlocks the critical user need
- it preserves the secure/private direction
- it avoids prematurely optimizing public-open chat before access control exists

## Proof plan / E2E requirements

We should not claim this product is done until all of these are proven.

### Private secure group
- create group
- invite join
- member can read/send
- non-member cannot read/send
- remove member propagates
- removed member loses future secure access
- hidden group does **not** leak through public discovery or public presence/social browse

### Public request secure group
- group appears in discovery **without manual card import** when `discoverability = PublicDirectory`
- non-member can view public card
- non-member cannot read secure content
- non-member can submit request
- admin sees request
- admin approves
- requester gains real secure access
- admin rejects another request
- rejected requester remains blocked

### Public open group
- discoverable
- open join works
- public read works if configured
- moderated/public write policy enforced
- banned peer cannot post

### Public announce group
- public read works
- non-admin write denied
- admin write succeeds

### Authorization negative-path proof
- non-admin cannot change policy
- non-admin cannot approve requests
- non-admin cannot remove owner/admin improperly
- banned peer cannot rejoin improperly
- stale actions referencing old `state_hash` are rejected

### Convergence proof
- roster converges across peers
- request status converges across peers
- policy changes converge across peers
- card supersession converges across peers
- deletion / hidden withdrawal converges across peers

## Review and signoff requirements

Before claiming “full named-group support,” implementation review must verify all of the following:

1. **Stable identity + evolving validity**
   - stable `group_id`
   - authoritative `state_hash`
   - higher revisions supersede lower ones immediately

2. **Real discovery**
   - `PublicDirectory` groups become discoverable without manual import
   - `ListedToContacts` groups do **not** leak to public shards
   - `Hidden` groups do **not** leak through public discovery or presence

3. **Policy fidelity**
   - create, invite, discover, import, restart, and convergence all preserve the intended policy
   - public-card summaries expose enough public semantics to distinguish public modes

4. **Secure enforcement**
   - request approval grants actual MLS-backed access for `MlsEncrypted` groups
   - remove/ban revokes **future** secure access
   - named-group state and MLS state cannot silently drift

5. **Apply-side validation**
   - apply-time authorization/invariant checks are at least as strict as endpoint-time checks
   - invalid or stale actions do not resurrect superseded state

6. **Metadata and card convergence**
   - name/description/tags/policy changes converge across the reachable partition
   - public cards are refreshed and superseded correctly

7. **Strict API semantics**
   - missing targets do not return false success
   - error codes are deliberate and deterministic for critical authz paths

8. **Repeatable proof**
   - correct-peer proofs (not just owner-side view)
   - strong negative-path coverage
   - repeatable clean runs for named-group proof sections before signoff

## Distributed Discovery Index

### Design principles

1. **No DHT** — no global routing table, no Kademlia. The network must survive arbitrary partitions (power outages, geopolitical fragmentation) and keep working within each fragment.
2. **No special node roles** — every node can bootstrap, relay, coordinate, run GUI. Discovery does not depend on designated directory servers.
3. **Eventual completeness within the reachable partition** — search is partition-local and convergent for the shards an agent subscribes to. It is not instant global lookup.
4. **Discovery plane vs data plane** — shard gossip finds cards/manifests/hints. It does not move the underlying large or private payloads.
5. **Scale target** — millions of groups without overloading any individual node.

### Three discovery tiers

Discovery uses three complementary mechanisms. No single tier is required — they reinforce each other.

#### Tier 1: Social propagation (organic)

Agents share group information naturally through conversation:
- `GroupCard` and invite links exchanged in direct messages and group chats
- agents may forward cards to contacts who might be interested
- contact-scoped listings can be shared directly without touching public shards

Important privacy rule: only groups whose discoverability permits it may be propagated this way in reusable/public metadata surfaces.
- `Hidden` groups must never appear in public discovery or public presence/social browse.
- `ListedToContacts` groups may be shared only through direct/contact-scoped mechanisms.
- `PublicDirectory` groups may be reshared openly.

This is the primary discovery channel for many groups. It is naturally partition-proof and infrastructure-free.

#### Tier 2: Shard-based public directory search

Structured search uses deterministic topic sharding over PlumTree gossip.

**Publishing for `PublicDirectory`:**

When a group's discoverability is `PublicDirectory`, it publishes its signed `GroupCard` to tag shard topics:

```
shard = BLAKE3("x0x-group-tag" || lowercase(tag)) % 65536
topic = "x0x.directory.tag.{shard}"
```

One topic per tag. A group with tags `["ai", "quantum", "research"]` publishes to three shard topics.

For name-based search, each whitespace-delimited name word maps to a shard:

```
shard = BLAKE3("x0x-group-name" || lowercase(word)) % 65536
topic = "x0x.directory.name.{shard}"
```

Recommended extension: add an exact-ID shard for known-`group_id` lookup without a DHT:

```
shard = BLAKE3("x0x-group-id" || group_id) % 65536
topic = "x0x.directory.id.{shard}"
```

**`ListedToContacts` is different:**
- do **not** publish it to public tag/name shards
- share it through contact-scoped encrypted topics, direct messages, or trusted contact exchange
- treat it as intentionally narrower than `PublicDirectory`

**Searching:**

An agent searching for "quantum":
1. Computes the relevant tag/name shard IDs
2. Subscribes to those shard topics
3. Digest-based anti-entropy reconciles the local shard index against reachable peers
4. The agent obtains every currently reachable card revision for those shards within its connected partition
5. Results are filtered and ranked locally

Multi-word search unions results from all relevant shards and ranks by match quality.

### Shard state and anti-entropy

Operationally, a shard should behave like a bounded map from `group_id` to the **highest valid signed revision** currently known, plus enough metadata to reconcile.

Anti-entropy must exchange summaries/digests, not naive full replay. The minimum useful digest per entry is:
- `group_id`
- `revision`
- `state_hash`
- `expires_at`

This lets peers quickly determine:
- which revisions are newer
- which cards are stale
- which payloads must be fetched

A logical CRDT model is still acceptable, but the implementation must optimize around the fact that consumers usually only need the latest valid card per `group_id`.

### Authority and supersession

This is the critical validity rule.

A discoverable card has two signatures in play:
1. **Outer transport signature** — the gossip message is signed by the node relaying/publishing it on the mesh.
2. **Inner authority signature** — the `GroupCard` itself is signed by the owner/admin/canonical state authority over canonical card fields.

Rules:
- any node may relay or republish the **exact signed card blob**
- relays do **not** mint new card revisions unless they are also authorized group state authorities
- receivers accept only the newest valid revision for a `group_id`
- lower signed revisions are superseded immediately
- TTL is only cache cleanup, not primary validity

A `Hidden`/withdrawn/deleted group should publish a **higher signed revision** that supersedes the last public card. Do not rely on TTL alone to make stale public cards disappear.

### Tier 3: Presence-social browsing

Presence can be used as a zero-cost browsing signal, but only under strict privacy rules.

Allowed behavior:
- `PublicDirectory` groups may appear in public nearby-browse surfaces
- `ListedToContacts` groups may appear only to authorized contacts / trusted views
- `Hidden` groups must never appear in public presence or public agent-card membership lists

Presence-social browsing is useful for:
- “groups nearby agents are in”
- surfacing active communities inside the current partition
- weighting discovery toward groups with live members

It must never become a side-channel that leaks private memberships.

### Hot-shard mitigation: path caching

Popular tags (e.g. `social`, `general`, `ai`) will create hot shards. Path caching is useful, but its semantics must be concrete:

- relay nodes cache the exact signed cards/manifests they forward
- cache holders participate in neighbor anti-entropy summaries for connected peers
- cache holders are read-through/serve-through helpers, not alternate authorities
- caches are bounded (LRU or similar) and cleaned up by expiry policy

This gives popular shards natural load spreading without introducing special node roles.

### Card lifecycle

```
Group created (PublicDirectory)
  │
  ├─ Issue signed GroupCard revision N with state_hash S
  ├─ Publish card to tag shards, name shards, and optionally id shard
  │
  │  ... refresh / metadata changes / roster changes ...
  │
  ├─ Issue higher signed GroupCard revision N+1 with new state_hash S'
  ├─ Republish newer revision
  │
  │  ... group becomes Hidden / deleted ...
  │
  └─ Issue higher signed withdrawal/hidden revision
```

Meaning:
- active members may help **relay** or **refresh** the latest valid card blob
- only authorized state authorities issue new revisions
- stale cards are superseded immediately by higher revisions
- expiry cleans up dead state from caches over time

### Wire format

Directory traffic should carry small signed manifests, not raw app payloads.

```
topic:   "x0x.directory.tag.{shard}" | "x0x.directory.name.{shard}" | "x0x.directory.id.{shard}"
payload: bincode/json-encoded GroupCard or signed directory manifest
outer:   signed by transport publisher/relay
inner:   signed by group state authority
```

Receivers must verify both:
- the outer message is valid mesh traffic
- the inner card/manifest is valid for the advertised `group_id`, `revision`, and `state_hash`

Unsigned or invalid manifests are dropped silently.

### Spam and abuse controls

Public discovery needs explicit guardrails:
- normalized tags
- max tags per group
- stop-word filtering / heuristics for hot name shards
- max card size
- refresh-rate throttling
- per-identity publish/relay rate limiting
- local ranking penalties for spammy publishers or noisy tags

The average-shard table is useful, but the implementation must optimize for skewed, hot-tag reality rather than uniform distribution.

### API additions for Phase C.2

```
GET  /groups/discover?q=<query>             Search by tag/name across local shard indexes
GET  /groups/discover/nearby                Presence-social browse (privacy-filtered)
GET  /groups/discover/subscriptions         List active shard subscriptions
POST /groups/discover/subscribe             Subscribe to a tag/name/id shard
DELETE /groups/discover/subscribe/{shard}   Unsubscribe from a shard
```

CLI:
```
x0x group discover <query>
x0x group discover --nearby
x0x group discover --subscribe <tag>
```

### Partition behavior

Within a connected partition, subscribed shards should converge eventually via digest-based anti-entropy. Unreachable partitions remain invisible until connectivity returns.

When partitions heal:
- higher card revisions supersede lower ones
- matching revisions with the same `state_hash` deduplicate naturally
- public directory views merge without requiring a global overlay or central coordinator

### What this does NOT do

- Does not provide full-text search across descriptions (only tags, name words, and optional exact ID)
- Does not rank by global popularity beyond what the local partition can observe
- Does not guarantee real-time consistency across partitions (eventual via anti-entropy)
- Does not require any node to hold the complete directory
- Does not gossip raw large payloads or private app state on directory topics

## Open questions

### Resolved

1. ~~Do we want one roster authority initially (owner/admin authored) or full multi-writer conflict resolution immediately?~~ — Prefer a **single canonical state-commit chain** for v1. Admins may propose/authorize actions socially, but accepted public state should linearize into one revision stream.
2. ~~Should discoverability use gossip-only, DHT indexing, or both?~~ — **Gossip-only, no DHT.** Tag/name shards over PlumTree + presence-social browsing. DHT was rejected because it assumes a global overlay and degrades badly under large partitions.

### Open

3. Do public open groups need read-only followers distinct from members in v1?
4. Should files/tasks/store inherit group policy automatically or allow app-specific stricter overlays later?
5. How much historical sync is required before we call the group product complete?
6. Should the path cache have a global size limit or per-shard limit?
7. Should shard subscriptions persist across daemon restarts, or require re-subscription?
8. Do we add the exact-ID shard in the first discovery implementation, or stage it after tag/name shards?

## Recommendation

We should commit to this product direction explicitly:

> x0x will have one first-class named-group system that supports private secure spaces, public request-access secure spaces, open public communities, and announcement channels under one policy-driven architecture, with stable `group_id`s, authority-signed `state_hash` commits, and partition-tolerant gossip discovery instead of a DHT.

That is the right long-term model, and it gives us a sane path from the current named-group + MLS split to a real product.
