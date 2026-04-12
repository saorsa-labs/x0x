I now have a thorough understanding of the entire codebase. Let me produce the complete implementation blueprint.

---

# Named Groups Full Model — Implementation Blueprint

## Patterns and Conventions Found

**Persistence**: `named_groups.json` (JSON via `serde_json`) at `state.named_groups_path`. Contrast with the stub `save_mls_groups` which does nothing — named groups are the primary persistent layer. Format is `HashMap<String, GroupInfo>` keyed by `mls_group_id` hex.

**Metadata propagation**: `NamedGroupMetadataEvent` is a serde-tagged enum, published as JSON bytes on the group's `metadata_topic`. Received by `ensure_named_group_metadata_listener` / `apply_named_group_metadata_event`. The authority model is currently single-authority (only the creator can publish accepted events). This is the model we extend, not replace.

**Auth check pattern**: All handlers check `local_agent != info.creator` and return `StatusCode::FORBIDDEN`. We extend this into a role-based check helper.

**Response pattern**: `(StatusCode, Json(serde_json::json!({...})))` everywhere. No typed response structs — stay consistent.

**`named_group_member_values` helper** (`x0xd.rs:4032`): produces the JSON member list from `GroupInfo`. This must be updated when the member storage changes.

**All group references to `info.members` (the BTreeSet)** — complete list:
- `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/mod.rs:37` — field declaration
- `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/mod.rs:59` — `GroupInfo::new()` creates BTreeSet and inserts creator
- `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/mod.rs:77` — `add_member()` inserts into BTreeSet
- `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/mod.rs:82` — `remove_member()` removes from BTreeSet, removes from `display_names`
- `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/mod.rs:89` — `has_member()` calls `contains`
- `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/mod.rs:95` — `set_display_name()` inserts to both BTreeSet AND `display_names`
- `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/mod.rs:44` — `display_names: HashMap<String, String>` field declaration
- `/Users/davidirvine/Desktop/Devel/projects/x0x/src/bin/x0xd.rs:4033–4051` — `named_group_member_values()` iterates `info.members` and `info.display_names`
- `/Users/davidirvine/Desktop/Devel/projects/x0x/src/bin/x0xd.rs:4114–4118` — `apply_named_group_metadata_event` MemberAdded calls `info.add_member` / `info.set_display_name`
- `/Users/davidirvine/Desktop/Devel/projects/x0x/src/bin/x0xd.rs:4144–4145` — `apply_named_group_metadata_event` MemberRemoved calls `info.remove_member`
- `/Users/davidirvine/Desktop/Devel/projects/x0x/src/bin/x0xd.rs:4644–4656` — `add_named_group_member` calls `info.has_member`, `info.membership_revision`, `info.add_member`, `info.set_display_name`
- `/Users/davidirvine/Desktop/Devel/projects/x0x/src/bin/x0xd.rs:4743–4752` — `remove_named_group_member` calls `info.has_member`, `info.membership_revision`, `info.remove_member`
- `/Users/davidirvine/Desktop/Devel/projects/x0x/src/bin/x0xd.rs:4811` — `leave_group` uses `info.membership_revision`

---

## Architecture Decision

The migration uses a **dual-representation serde approach**: `GroupInfo` gains a `#[serde(default)]` tagged `members_v2: BTreeMap<String, GroupMember>` field alongside the old `members: BTreeSet<String>` and `display_names: HashMap<String,String>` which are kept with `#[serde(default, skip_serializing)]`. A `fn migrate_from_v1(&mut self)` method is called once at load time to convert any old-format entries into `GroupMember` structs. This makes the old JSON loadable without a separate migration pass, satisfies the bincode note in the brief (there is no bincode here — storage is JSON), and requires zero schema version tracking.

The `group_card_cache` is a new top-level field in `AppState`: `RwLock<HashMap<String, GroupCard>>`.

Authorization is enforced via a single helper `fn caller_role(info: &GroupInfo, caller_hex: &str) -> Option<GroupRole>` that returns the role from `members_v2`, and a companion `fn require_role(role: GroupRole, minimum: GroupRole) -> bool`.

---

## Component Design

### Step 1 — `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/policy.rs` (new file)

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupDiscoverability { Hidden, ListedToContacts, PublicDirectory }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupAdmission { InviteOnly, RequestAccess, OpenJoin }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupConfidentiality { MlsEncrypted, SignedPublic }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupReadAccess { MembersOnly, Public }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupWriteAccess { MembersOnly, ModeratedPublic, AdminOnly }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPolicy {
    pub discoverability: GroupDiscoverability,
    pub admission: GroupAdmission,
    pub confidentiality: GroupConfidentiality,
    pub read_access: GroupReadAccess,
    pub write_access: GroupWriteAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupPolicyPreset { PrivateSecure, PublicRequestSecure, PublicOpen, PublicAnnounce }

impl GroupPolicyPreset {
    pub fn to_policy(&self) -> GroupPolicy { ... }
}

impl Default for GroupPolicy {
    fn default() -> Self { GroupPolicyPreset::PrivateSecure.to_policy() }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPolicySummary {
    pub discoverability: GroupDiscoverability,
    pub admission: GroupAdmission,
    pub confidentiality: GroupConfidentiality,
}

impl From<&GroupPolicy> for GroupPolicySummary { ... }
```

All enums implement `Default`: `GroupDiscoverability::Hidden`, `GroupAdmission::InviteOnly`, `GroupConfidentiality::MlsEncrypted`, `GroupReadAccess::MembersOnly`, `GroupWriteAccess::MembersOnly`.

### Step 2 — `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/member.rs` (new file)

```rust
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupRole { Owner, Admin, Moderator, Member, Guest }

impl GroupRole {
    /// Returns true if self >= minimum (Owner > Admin > Moderator > Member > Guest)
    pub fn at_least(&self, minimum: &GroupRole) -> bool { ... }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupMemberState { Active, Removed, Banned }

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl GroupMember {
    pub fn new_owner(agent_id: String, display_name: Option<String>, now: u64) -> Self { ... }
    pub fn new_member(agent_id: String, display_name: Option<String>, added_by: Option<String>, now: u64) -> Self { ... }
    pub fn is_active(&self) -> bool { self.state == GroupMemberState::Active }
    pub fn is_banned(&self) -> bool { self.state == GroupMemberState::Banned }
}
```

### Step 3 — `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/request.rs` (new file)

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinRequestStatus { Pending, Approved, Rejected, Cancelled }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub request_id: String,           // UUID v4 hex
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

impl JoinRequest {
    pub fn new(group_id: String, requester_agent_id: String, message: Option<String>, now: u64) -> Self { ... }
}
```

### Step 4 — `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/directory.rs` (new file)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCard {
    pub group_id: String,
    pub name: String,
    pub description: String,
    pub avatar_url: Option<String>,
    pub tags: Vec<String>,
    pub policy_summary: GroupPolicySummary,
    pub owner_agent_id: String,
    pub admin_count: u32,
    pub member_count: u32,
    pub created_at: u64,
    pub updated_at: u64,
    pub request_access_enabled: bool,
}

impl GroupCard {
    pub fn from_group_info(info: &GroupInfo) -> Self { ... }
}
```

### Step 5 — Evolve `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/mod.rs`

The new `GroupInfo` struct:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    // --- v1 fields (kept for migration; skip_serializing once migrated) ---
    #[serde(default, skip_serializing)]
    pub members: BTreeSet<String>,
    #[serde(default, skip_serializing)]
    pub display_names: HashMap<String, String>,
    #[serde(default, skip_serializing)]
    pub membership_revision: u64,

    // --- v2 fields ---
    pub name: String,
    pub description: String,
    pub creator: AgentId,
    pub created_at: u64,
    pub updated_at: u64,
    pub mls_group_id: String,
    pub metadata_topic: String,
    pub chat_topic_prefix: String,
    pub policy: GroupPolicy,
    pub policy_revision: u64,
    pub roster_revision: u64,
    #[serde(default)]
    pub members_v2: BTreeMap<String, GroupMember>,
    #[serde(default)]
    pub join_requests: BTreeMap<String, JoinRequest>,
    pub discovery_card_topic: Option<String>,
}
```

Migration method — called at load time on each entry:

```rust
impl GroupInfo {
    /// Migrate v1 (BTreeSet + display_names) to v2 (BTreeMap<String, GroupMember>).
    /// Idempotent: no-op if members_v2 already populated.
    pub fn migrate_from_v1(&mut self) {
        if !self.members_v2.is_empty() {
            return;
        }
        let now = now_millis();
        let creator_hex = hex::encode(self.creator.as_bytes());
        let all_ids: BTreeSet<String> = self.members
            .iter()
            .chain(self.display_names.keys())
            .cloned()
            .collect();
        for id in all_ids {
            let dn = self.display_names.get(&id).cloned();
            let role = if id == creator_hex { GroupRole::Owner } else { GroupRole::Member };
            let member = if role == GroupRole::Owner {
                GroupMember::new_owner(id.clone(), dn, now)
            } else {
                GroupMember::new_member(id.clone(), dn, Some(creator_hex.clone()), now)
            };
            self.members_v2.insert(id, member);
        }
        self.roster_revision = self.membership_revision;
    }

    pub fn caller_role(&self, agent_hex: &str) -> Option<&GroupRole> {
        self.members_v2.get(agent_hex)
            .filter(|m| m.is_active())
            .map(|m| &m.role)
    }

    // Updated versions of v1 surface methods, now operating on members_v2:
    pub fn add_member(&mut self, agent_id_hex: String, role: GroupRole, added_by: Option<String>, display_name: Option<String>)
    pub fn remove_member(&mut self, agent_id_hex: &str, removed_by: Option<String>)
    pub fn ban_member(&mut self, agent_id_hex: &str, banned_by: Option<String>)
    pub fn has_active_member(&self, agent_id_hex: &str) -> bool
    pub fn set_display_name(&mut self, agent_id_hex: &str, name: String)
    pub fn display_name(&self, agent_id_hex: &str) -> String
    pub fn active_members(&self) -> impl Iterator<Item = &GroupMember>
    pub fn owner_agent_id(&self) -> Option<String>
}
```

The old `has_member()` becomes `has_active_member()`. The old `add_member(agent_id_hex: String)` signature changes — all callers in x0xd.rs must be updated.

### Step 6 — Update `pub mod` declarations in `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/mod.rs`

Add:
```rust
pub mod directory;
pub mod member;
pub mod policy;
pub mod request;
```

### Step 7 — Extend `NamedGroupMetadataEvent` in `x0xd.rs`

Add new variants to the enum (in addition to the existing three):

```rust
PolicyUpdated {
    group_id: String,
    revision: u64,
    actor: String,
    policy: GroupPolicy,
},
MemberRoleUpdated {
    group_id: String,
    revision: u64,
    actor: String,
    agent_id: String,
    role: GroupRole,
},
MemberBanned {
    group_id: String,
    revision: u64,
    actor: String,
    agent_id: String,
},
MemberUnbanned {
    group_id: String,
    revision: u64,
    actor: String,
    agent_id: String,
},
JoinRequestCreated {
    group_id: String,
    request_id: String,
    requester_agent_id: String,
    message: Option<String>,
    ts: u64,
},
JoinRequestApproved {
    group_id: String,
    request_id: String,
    revision: u64,
    actor: String,
    requester_agent_id: String,
},
JoinRequestRejected {
    group_id: String,
    request_id: String,
    actor: String,
    requester_agent_id: String,
},
JoinRequestCancelled {
    group_id: String,
    request_id: String,
    requester_agent_id: String,
},
GroupCardPublished {
    group_id: String,
    card: GroupCard,
},
```

`apply_named_group_metadata_event` must handle each new variant.

### Step 8 — Authorization helper in `x0xd.rs`

Add near the top of the named-group handler section:

```rust
fn require_admin_or_above(info: &x0x::groups::GroupInfo, caller_hex: &str)
    -> Result<(), (StatusCode, Json<serde_json::Value>)>

fn require_owner(info: &x0x::groups::GroupInfo, caller_hex: &str)
    -> Result<(), (StatusCode, Json<serde_json::Value>)>

fn require_can_change_role(
    info: &x0x::groups::GroupInfo,
    actor_hex: &str,
    target_hex: &str,
    new_role: &x0x::groups::member::GroupRole,
) -> Result<(), (StatusCode, Json<serde_json::Value>)>
```

These all return `Err((StatusCode::FORBIDDEN, Json(...)))` on failure. Callers use `require_admin_or_above(&info, &caller_hex)?;` with early return.

---

## Complete Implementation Map

### Phase 1 — New module files (no callers yet, compiles in isolation)

**1a. Create `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/policy.rs`**

Complete implementation. Derive `Default` for `GroupPolicy` returning `PrivateSecure` preset. Implement all four presets in `GroupPolicyPreset::to_policy()`. Add `#[cfg(test)]` for each preset's field values.

**1b. Create `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/member.rs`**

Complete implementation. `GroupRole` ordering: Owner=4, Admin=3, Moderator=2, Member=1, Guest=0. Implement `at_least` via `>=`. Add `#[cfg(test)]` for ordering and `new_owner`/`new_member`.

**1c. Create `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/request.rs`**

Complete implementation. `request_id` generated with `uuid::Uuid::new_v4().to_string()` — check if `uuid` crate is available; if not, use `hex::encode(rand 16 bytes)`.

**1d. Create `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/directory.rs`**

Complete implementation of `GroupCard` and `GroupCard::from_group_info(info: &GroupInfo) -> GroupCard`. This compiles after `mod.rs` is updated.

### Phase 2 — Evolve `src/groups/mod.rs`

**2a.** Add `pub mod` declarations for the four new modules.

**2b.** Add imports: `use crate::groups::member::{GroupMember, GroupRole, GroupMemberState}; use crate::groups::policy::{GroupPolicy, GroupPolicySummary}; use crate::groups::request::JoinRequest; use std::collections::BTreeMap;`

**2c.** Rewrite `GroupInfo` struct with v1 skip_serializing fields and v2 fields as shown above.

**2d.** Rewrite `GroupInfo::new()`. It now:
1. Creates `members_v2` as `BTreeMap::new()`
2. Inserts the creator as a `GroupMember::new_owner(creator_hex, display_name, now)`
3. Sets `roster_revision: 0`, `policy_revision: 0`, `policy: GroupPolicy::default()`
4. Sets `updated_at: now`, `join_requests: BTreeMap::new()`, `discovery_card_topic: None`
5. Sets `membership_revision: 0` (v1 compat), `members: BTreeSet::new()` (empty — skip_serializing), `display_names: HashMap::new()` (empty)

**2e.** Update all methods:
- `add_member(&mut self, agent_id_hex: String, role: GroupRole, added_by: Option<String>, display_name: Option<String>)` — inserts/updates `members_v2`
- `remove_member(&mut self, agent_id_hex: &str, removed_by: Option<String>)` — sets `state = Removed`, sets `removed_by`
- `ban_member(&mut self, agent_id_hex: &str, banned_by: Option<String>)` — sets `state = Banned`
- `unban_member(&mut self, agent_id_hex: &str)` — sets `state = Active`
- `has_active_member(&self, agent_id_hex: &str) -> bool`
- `has_member(&self, agent_id_hex: &str) -> bool` — keep for compatibility; delegates to `has_active_member`
- `set_display_name(&mut self, agent_id_hex: &str, name: String)` — updates `members_v2` entry only
- `display_name(&self, agent_id_hex: &str) -> String` — reads from `members_v2`
- `active_members(&self) -> impl Iterator<Item = &GroupMember>` — filters `Active` state
- `owner_agent_id(&self) -> Option<String>`
- `migrate_from_v1(&mut self)` as described above

**2f.** Keep the existing `#[cfg(test)]` block. Add tests for `migrate_from_v1`, `ban_member`, `caller_role`.

**Important note on `uuid`**: Check `Cargo.toml` for `uuid` dependency. If absent, generate request_id as `hex::encode` of 16 rand bytes.

### Phase 3 — Update `x0xd.rs` callers of `GroupInfo` methods

**3a.** Update `named_group_member_values(info: &GroupInfo)`:

```rust
fn named_group_member_values(info: &x0x::groups::GroupInfo) -> Vec<serde_json::Value> {
    let mut members: Vec<&x0x::groups::member::GroupMember> = info.active_members().collect();
    members.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
    members.iter().map(|m| serde_json::json!({
        "agent_id": m.agent_id,
        "role": m.role,
        "display_name": m.display_name,
        "joined_at": m.joined_at,
        "added_by": m.added_by,
    })).collect()
}
```

**3b.** Update `create_named_group` handler:
- Add `preset: Option<String>` to `CreateGroupRequest`
- Parse preset string → `GroupPolicyPreset` → `GroupPolicy`. Default to `PrivateSecure`.
- Pass `None` display_name to `GroupInfo::new()` (then call `set_display_name` separately if present)
- Change `info.add_member(...)` calls to the new 4-arg signature

**3c.** Update `join_group_via_invite` handler:
- Change `info.add_member(joiner_hex)` to `info.add_member(joiner_hex, GroupRole::Member, Some(invite.inviter.clone()), display_name)`

**3d.** Update `add_named_group_member` handler:
- Replace `local_agent != info.creator` guard with `require_admin_or_above(&info, &caller_hex)?`
- Change `info.add_member(agent_hex.clone())` to new signature
- Update `info.membership_revision` → `info.roster_revision`

**3e.** Update `remove_named_group_member` handler:
- Replace `local_agent != info.creator` guard with `require_admin_or_above(&info, &caller_hex)?` plus check that target is not Owner
- Change `info.remove_member(&agent_id_hex)` to `info.remove_member(&agent_id_hex, Some(caller_hex))`
- Update `info.membership_revision` → `info.roster_revision`

**3f.** Update `apply_named_group_metadata_event` function:
- Replace `info.membership_revision` with `info.roster_revision` throughout
- Change `info.add_member(agent_id.clone())` calls to new 4-arg signature
- Add handling for all new event variants
- The authority check for new events: `PolicyUpdated`, `MemberRoleUpdated`, `MemberBanned`, `MemberUnbanned` — accept from any active admin+. `JoinRequest*` events accept from the requester (JoinRequestCreated/Cancelled) or admin+ (Approved/Rejected). `GroupCardPublished` accepted from group owner.

**3g.** Update `leave_group` handler:
- Change `info.membership_revision` → `info.roster_revision`

**3h.** Update `set_group_display_name` handler:
- Change `info.set_display_name(agent_hex, req.name.clone())` — new signature is `set_display_name(&str, String)`

**3i.** Update `create_group_invite` handler:
- Replace `agent_id != info.creator` check with `require_admin_or_above(&info, &caller_hex)?`

**3j.** Update `create_named_group` display_names reference at line 4299:
- Change `info.display_names.get(&agent_hex)` to `info.display_name(&agent_hex)` (method call)

**3k.** Update `join_group_via_invite` display_names reference at line 4549:
- Change `info.display_names.get(&agent_hex)` to `info.display_name(&agent_hex)`

**3l.** Update load-time migration in `x0xd.rs` (around line 1051):

```rust
let named_groups = match serde_json::from_str::<HashMap<String, x0x::groups::GroupInfo>>(&json) {
    Ok(mut groups) => {
        for info in groups.values_mut() {
            info.migrate_from_v1();
        }
        groups
    }
    ...
}
```

### Phase 4 — New state field

**4a.** In `AppState` struct (around line 339), add:
```rust
group_card_cache: RwLock<HashMap<String, x0x::groups::directory::GroupCard>>,
```

**4b.** In `AppState` initialization (around line 1088), add:
```rust
group_card_cache: RwLock::new(HashMap::new()),
```

### Phase 5 — New handlers in `x0xd.rs`

All handlers are added after `leave_group` (around line 4841), before the task list section.

**5a. Request structs** (add to the group handler request structs section ~3954):

```rust
struct UpdateGroupRequest {
    name: Option<String>,
    description: Option<String>,
}

struct UpdateGroupPolicyRequest {
    preset: Option<String>,
    discoverability: Option<GroupDiscoverability>,
    admission: Option<GroupAdmission>,
    confidentiality: Option<GroupConfidentiality>,
    read_access: Option<GroupReadAccess>,
    write_access: Option<GroupWriteAccess>,
}

struct UpdateMemberRoleRequest {
    role: String,   // "owner"|"admin"|"moderator"|"member"|"guest"
}

struct CreateJoinRequestBody {
    message: Option<String>,
}
```

**5b. `PATCH /groups/:id` — update_named_group handler**

Check that caller is active member (any role for name/description? Or Owner+? Design doc is silent — Owner or Admin can update name/description). Require `Admin` or above. Update `info.name` and/or `info.description`. Set `info.updated_at`. Increment `info.roster_revision` (or a separate `metadata_revision` — use `roster_revision` for simplicity). Save and return updated info.

**5c. `PATCH /groups/:id/policy` — update_group_policy handler**

Require Owner. Parse either `preset` → full policy override, or partial field updates. Increment `info.policy_revision`. Set `info.updated_at`. Publish `PolicyUpdated` event. Save and return.

**5d. `PATCH /groups/:id/members/:agent_id/role` — update_member_role handler**

Parse new role. Call `require_can_change_role(&info, caller, target, &new_role)`. Update `members_v2[target].role` and `.updated_at`. Increment `roster_revision`. Publish `MemberRoleUpdated`. Save and return. Note in comment: Phase D will trigger MLS rekey here.

**5e. `POST /groups/:id/ban/:agent_id` — ban_group_member handler**

Require Admin+. Target must not be Owner. Call `info.ban_member(target, Some(caller))`. Increment `roster_revision`. Publish `MemberBanned`. Also trigger MLS `remove_member` (same pattern as current `remove_named_group_member`). Save and return.

**5f. `DELETE /groups/:id/ban/:agent_id` — unban_group_member handler**

Require Admin+. Target must be Banned. Call `info.unban_member(target)`. Increment `roster_revision`. Publish `MemberUnbanned`. Save and return.

**5g. `GET /groups/:id/requests` — list_join_requests handler**

Require Admin+ (or Owner). Return `info.join_requests.values()` filtered to `Pending` (optionally all with `?include_resolved=true` query param). Map to JSON.

**5h. `POST /groups/:id/requests` — create_join_request handler**

Check `info.policy.admission == GroupAdmission::RequestAccess` — return 403 if group is InviteOnly with message "group is invite-only". Check caller is NOT already an active member. Check no existing Pending request for caller. Create `JoinRequest::new(...)`. Insert into `info.join_requests`. Save. Publish `JoinRequestCreated` event to `info.metadata_topic`. Return `{ ok: true, request_id, group_id }`.

**5i. `POST /groups/:id/requests/:request_id/approve` — approve_join_request handler**

Require Admin+. Look up request, must be Pending. Set `status = Approved`, `reviewed_by`, `reviewed_at`. Call `info.add_member(requester, GroupRole::Member, Some(caller), None)`. Increment `roster_revision`. Publish `JoinRequestApproved`. Trigger MLS `add_member` (same pattern as current `add_named_group_member`). Save and return.

**5j. `POST /groups/:id/requests/:request_id/reject` — reject_join_request handler**

Require Admin+. Look up request, must be Pending. Set `status = Rejected`, `reviewed_by`, `reviewed_at`. Publish `JoinRequestRejected`. Save and return.

**5k. `DELETE /groups/:id/requests/:request_id` — cancel_join_request handler**

Require that caller == request.requester_agent_id. Status must be Pending. Set `status = Cancelled`. Publish `JoinRequestCancelled`. Save and return.

**5l. `GET /groups/discover` — discover_groups handler**

Read `state.group_card_cache`. Also scan `state.named_groups` for any groups with `policy.discoverability != Hidden` owned by this agent and synthesize their cards. Merge, deduplicate by group_id. Return JSON array of `GroupCard`.

**5m. `GET /groups/cards/:id` — get_group_card handler**

Check `state.group_card_cache` first. If not found, check `state.named_groups` if this agent is the owner and group is discoverable. Return 404 if neither. Return JSON `GroupCard`.

**5n. `POST /groups/cards/import` — import_group_card handler**

Parse `GroupCard` from request body. If `policy_summary.discoverability == PublicDirectory`, insert into `state.group_card_cache`. Return `{ ok: true, group_id }`.

### Phase 6 — Router additions in `x0xd.rs` (around line 1274)

Add after existing group routes:

```rust
.route("/groups/:id", patch(update_named_group))
.route("/groups/:id/policy", patch(update_group_policy))
.route("/groups/:id/members/:agent_id/role", patch(update_member_role))
.route("/groups/:id/ban/:agent_id", post(ban_group_member))
.route("/groups/:id/ban/:agent_id", delete(unban_group_member))
.route("/groups/:id/requests", get(list_join_requests))
.route("/groups/:id/requests", post(create_join_request))
.route("/groups/:id/requests/:request_id/approve", post(approve_join_request))
.route("/groups/:id/requests/:request_id/reject", post(reject_join_request))
.route("/groups/:id/requests/:request_id", delete(cancel_join_request))
.route("/groups/discover", get(discover_groups))
.route("/groups/cards/:id", get(get_group_card))
.route("/groups/cards/import", post(import_group_card))
```

**Axum route ordering note**: `/groups/discover` and `/groups/cards/:id` are static prefixes that must be registered BEFORE `/groups/:id` in the router, or they will be shadowed. Check the existing order — `join` (`/groups/join`) already exists and works, so the same pattern applies. The current line 1272 shows `.route("/groups/join", post(...))` before `.route("/groups/:id", delete(...))` — same approach needed.

Concretely, insert the new static-prefix routes (`/groups/discover`, `/groups/cards/:id`, `/groups/cards/import`) before `.route("/groups/:id", get(get_named_group))`.

### Phase 7 — `src/api/mod.rs` additions

Add 13 new `EndpointDef` entries in the `// ── Named groups` section:

```rust
EndpointDef { method: Method::Patch, path: "/groups/:id",
    cli_name: "group update", description: "Update group name/description", category: "named-groups" },
EndpointDef { method: Method::Patch, path: "/groups/:id/policy",
    cli_name: "group policy", description: "Update group policy (owner only)", category: "named-groups" },
EndpointDef { method: Method::Patch, path: "/groups/:id/members/:agent_id/role",
    cli_name: "group set-role", description: "Change member role", category: "named-groups" },
EndpointDef { method: Method::Post, path: "/groups/:id/ban/:agent_id",
    cli_name: "group ban", description: "Ban member", category: "named-groups" },
EndpointDef { method: Method::Delete, path: "/groups/:id/ban/:agent_id",
    cli_name: "group unban", description: "Unban member", category: "named-groups" },
EndpointDef { method: Method::Get, path: "/groups/:id/requests",
    cli_name: "group requests", description: "List join requests", category: "named-groups" },
EndpointDef { method: Method::Post, path: "/groups/:id/requests",
    cli_name: "group request-access", description: "Submit join request", category: "named-groups" },
EndpointDef { method: Method::Post, path: "/groups/:id/requests/:request_id/approve",
    cli_name: "group approve-request", description: "Approve join request", category: "named-groups" },
EndpointDef { method: Method::Post, path: "/groups/:id/requests/:request_id/reject",
    cli_name: "group reject-request", description: "Reject join request", category: "named-groups" },
EndpointDef { method: Method::Delete, path: "/groups/:id/requests/:request_id",
    cli_name: "group cancel-request", description: "Cancel own join request", category: "named-groups" },
EndpointDef { method: Method::Get, path: "/groups/discover",
    cli_name: "group discover", description: "List discoverable groups", category: "named-groups" },
EndpointDef { method: Method::Get, path: "/groups/cards/:id",
    cli_name: "group card", description: "Fetch group card", category: "named-groups" },
EndpointDef { method: Method::Post, path: "/groups/cards/import",
    cli_name: "group card-import", description: "Import a group card", category: "named-groups" },
```

---

## Migration Strategy (Detailed)

The storage format is **JSON** (not bincode, despite the design doc's note — `save_named_groups` and `named_groups.json` confirm this). The migration strategy:

1. Old format fields (`members: BTreeSet<String>`, `display_names: HashMap<String,String>`, `membership_revision: u64`) are kept on the struct with `#[serde(default, skip_serializing)]`. This means they deserialize from old JSON (because `default` handles missing fields, and old JSON will have `members` present) but never write back.

2. New fields (`members_v2`, `join_requests`, `roster_revision`, `policy_revision`, `policy`, `updated_at`, `discovery_card_topic`) all get `#[serde(default)]` so old JSON that lacks them deserializes to empty/zero/None.

3. At startup load (x0xd.rs ~line 1051), after parsing the `HashMap`, iterate and call `info.migrate_from_v1()` on each entry. This converts the `BTreeSet + display_names` into `BTreeMap<String, GroupMember>` if `members_v2` is empty.

4. First save after migration writes back only the v2 fields (since v1 fields are `skip_serializing`). From that point, v2 is authoritative.

5. `migrate_from_v1` is idempotent: if `members_v2` is non-empty, it returns immediately. So hot reload with already-migrated data is safe.

6. Edge case: creator hex may not appear in the old `members` BTreeSet if `GroupInfo::new()` was called before the BTreeSet insert bug was fixed. The migration always inserts the creator from `info.creator` regardless.

---

## Metadata Event Schema (Exact JSON)

All events use `serde(tag = "event", rename_all = "snake_case")` so the `event` field is the discriminant.

**policy_updated**
```json
{
  "event": "policy_updated",
  "group_id": "<hex>",
  "revision": 5,
  "actor": "<hex>",
  "policy": {
    "discoverability": "public_directory",
    "admission": "request_access",
    "confidentiality": "mls_encrypted",
    "read_access": "members_only",
    "write_access": "members_only"
  }
}
```

**member_role_updated**
```json
{
  "event": "member_role_updated",
  "group_id": "<hex>",
  "revision": 6,
  "actor": "<hex>",
  "agent_id": "<hex>",
  "role": "admin"
}
```

**member_banned**
```json
{
  "event": "member_banned",
  "group_id": "<hex>",
  "revision": 7,
  "actor": "<hex>",
  "agent_id": "<hex>"
}
```

**member_unbanned**
```json
{
  "event": "member_unbanned",
  "group_id": "<hex>",
  "revision": 8,
  "actor": "<hex>",
  "agent_id": "<hex>"
}
```

**join_request_created**
```json
{
  "event": "join_request_created",
  "group_id": "<hex>",
  "request_id": "<uuid-hex>",
  "requester_agent_id": "<hex>",
  "message": "Please let me in",
  "ts": 1712870000000
}
```

**join_request_approved**
```json
{
  "event": "join_request_approved",
  "group_id": "<hex>",
  "request_id": "<uuid-hex>",
  "revision": 9,
  "actor": "<hex>",
  "requester_agent_id": "<hex>"
}
```

**join_request_rejected**
```json
{
  "event": "join_request_rejected",
  "group_id": "<hex>",
  "request_id": "<uuid-hex>",
  "actor": "<hex>",
  "requester_agent_id": "<hex>"
}
```

**join_request_cancelled**
```json
{
  "event": "join_request_cancelled",
  "group_id": "<hex>",
  "request_id": "<uuid-hex>",
  "requester_agent_id": "<hex>"
}
```

**group_card_published**
```json
{
  "event": "group_card_published",
  "group_id": "<hex>",
  "card": {
    "group_id": "<hex>",
    "name": "My Public Group",
    "description": "...",
    "avatar_url": null,
    "tags": [],
    "policy_summary": {
      "discoverability": "public_directory",
      "admission": "request_access",
      "confidentiality": "mls_encrypted"
    },
    "owner_agent_id": "<hex>",
    "admin_count": 1,
    "member_count": 5,
    "created_at": 1712800000000,
    "updated_at": 1712870000000,
    "request_access_enabled": true
  }
}
```

---

## Authorization Matrix

| Operation | Guest | Member | Moderator | Admin | Owner |
|---|---|---|---|---|---|
| View group info (if member) | Y | Y | Y | Y | Y |
| Set own display name | Y | Y | Y | Y | Y |
| Submit join request | Y (non-member) | — | — | — | — |
| Cancel own request | Y (own) | Y (own) | — | — | Y |
| Generate invite link | N | N | N | Y | Y |
| Add member | N | N | N | Y | Y |
| Remove member (non-owner) | N | N | N | Y | Y |
| Remove Admin | N | N | N | N | Y |
| Remove Owner | N | N | N | N | N (use delete group) |
| Update name/description | N | N | N | Y | Y |
| Update policy | N | N | N | N | Y |
| Change role (target < caller) | N | N | N | Y | Y |
| Change role (target == caller's rank) | N | N | N | N | Y |
| Promote to Owner | N | N | N | N | N (Phase D) |
| Approve/reject join request | N | N | N | Y | Y |
| Ban member (non-owner) | N | N | N | Y | Y |
| Unban member | N | N | N | Y | Y |
| Delete group | N | N | N | N | Y |
| Publish group card | N | N | N | N | Y |

**`require_can_change_role` logic**:
```
actor_role = caller_role(info, actor)
target_role = caller_role(info, target).current_role
if new_role == Owner: deny (ownership transfer not in this phase)
if actor_role < Admin: deny
if actor_role == Admin AND target_role >= Admin: deny (Admin cannot touch another Admin's role)
if actor_role == Owner: allow any role change except promote to Owner
```

---

## Build Sequence Checklist

- [ ] **1.** Check `Cargo.toml` for `uuid` crate. If absent, add `uuid = { version = "1", features = ["v4"] }` or plan `hex::encode(rand_bytes)` alternative for `request_id` generation.
- [ ] **2.** Create `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/policy.rs` — all enums, `GroupPolicy`, `GroupPolicyPreset`, `GroupPolicySummary`. `cargo check` must pass.
- [ ] **3.** Create `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/member.rs` — `GroupRole`, `GroupMemberState`, `GroupMember`. `cargo check` must pass.
- [ ] **4.** Create `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/request.rs` — `JoinRequestStatus`, `JoinRequest`. `cargo check` must pass.
- [ ] **5.** Add `pub mod policy; pub mod member; pub mod request; pub mod directory;` to `src/groups/mod.rs`.
- [ ] **6.** Add import block to `src/groups/mod.rs`: `BTreeMap`, `GroupMember`, `GroupRole`, `GroupMemberState`, `GroupPolicy`, `JoinRequest`.
- [ ] **7.** Rewrite `GroupInfo` struct in `src/groups/mod.rs` with dual v1/v2 fields as specified.
- [ ] **8.** Rewrite all `GroupInfo` methods with new signatures (`add_member`, `remove_member`, `has_active_member`, `has_member`, `set_display_name`, `display_name`, `active_members`, `owner_agent_id`, `ban_member`, `unban_member`, `migrate_from_v1`, `caller_role`). `cargo check` src/groups must pass.
- [ ] **9.** Create `/Users/davidirvine/Desktop/Devel/projects/x0x/src/groups/directory.rs` — `GroupCard`, `GroupCard::from_group_info`. This depends on `GroupInfo` from step 8. `cargo check` must pass.
- [ ] **10.** Update `named_group_member_values` in `x0xd.rs` — new implementation using `active_members()`.
- [ ] **11.** Update all v1-field references in `x0xd.rs`: `info.members`, `info.display_names`, `info.membership_revision` → v2 equivalents. Enumerate all sites from the "Integration touchpoints" list.
- [ ] **12.** Fix method call signatures in `x0xd.rs` for `add_member` (4 args), `remove_member` (2 args), `set_display_name` (2 args).
- [ ] **13.** Add auth helper functions `require_owner`, `require_admin_or_above`, `require_can_change_role` near the group handler section.
- [ ] **14.** Replace creator-only checks in existing handlers with role checks: `create_group_invite`, `add_named_group_member`, `remove_named_group_member`.
- [ ] **15.** Add `preset: Option<String>` to `CreateGroupRequest`; update `create_named_group` to parse preset and set `info.policy`.
- [ ] **16.** Update `apply_named_group_metadata_event` to handle new event variants and use v2 field names.
- [ ] **17.** Extend `NamedGroupMetadataEvent` enum with 9 new variants.
- [ ] **18.** Add `group_card_cache: RwLock<HashMap<String, GroupCard>>` to `AppState` struct and initialization.
- [ ] **19.** Update startup named groups load to call `migrate_from_v1()` on each loaded entry.
- [ ] **20.** `cargo check --all-features` must pass at this point with zero errors.
- [ ] **21.** Add all new handler functions (`update_named_group`, `update_group_policy`, `update_member_role`, `ban_group_member`, `unban_group_member`, `list_join_requests`, `create_join_request`, `approve_join_request`, `reject_join_request`, `cancel_join_request`, `discover_groups`, `get_group_card`, `import_group_card`).
- [ ] **22.** Add new request structs (`UpdateGroupRequest`, `UpdateGroupPolicyRequest`, `UpdateMemberRoleRequest`, `CreateJoinRequestBody`).
- [ ] **23.** Add new routes to the router, ensuring static-prefix routes come before parameterized routes.
- [ ] **24.** Add 13 new `EndpointDef` entries to `src/api/mod.rs`.
- [ ] **25.** `cargo clippy --all-features --all-targets -- -D warnings` — zero violations.
- [ ] **26.** `cargo nextest run --all-features` — all 744+ tests pass.
- [ ] **27.** Add integration tests for new functionality (see test plan below).
- [ ] **28.** Run `bash tests/e2e_full_audit.sh` (after updating with new group scenarios).

---

## E2E Test Plan for `tests/e2e_full_audit.sh`

The script uses Alice (port 19811), Bob (19812), Charlie (19813). Add the following test sections after the existing named-group tests.

### Section: `private_secure` lifecycle (preset default)

```bash
# NG-PS-1: Create group with explicit preset
GROUP_ID=$(curl -sf -X POST "$AA/groups" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' \
  -d '{"name":"PrivateGroup","preset":"private_secure"}' | jq -r .group_id)
assert_eq "NG-PS-1 group created" "$GROUP_ID" "$(echo $GROUP_ID)" # non-empty check

# NG-PS-2: Verify policy is private_secure
POLICY=$(curl -sf "$AA/groups/$GROUP_ID" -H "Authorization: Bearer $AT" | jq -r .policy.discoverability)
assert_eq "NG-PS-2 discoverability=hidden" "hidden" "$POLICY"

# NG-PS-3: Non-member (Bob) cannot see group in discover
DISCOVER=$(curl -sf "$BA/groups/discover" -H "Authorization: Bearer $BT" | jq -r '.groups | length')
assert_eq "NG-PS-3 private group not discoverable" "0" "$DISCOVER"

# NG-PS-4: Alice invites Bob
INVITE=$(curl -sf -X POST "$AA/groups/$GROUP_ID/invite" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d '{}' | jq -r .invite_link)
assert_nonempty "NG-PS-4 invite link" "$INVITE"

# NG-PS-5: Bob joins via invite
JOIN_R=$(curl -sf -X POST "$BA/groups/join" -H "Authorization: Bearer $BT" \
  -H 'Content-Type: application/json' -d "{\"invite\":\"$INVITE\"}" | jq -r .ok)
assert_eq "NG-PS-5 join ok" "true" "$JOIN_R"

# NG-PS-6: Alice adds Bob as member via API (admin path)
ADD_R=$(curl -sf -X POST "$AA/groups/$GROUP_ID/members" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d "{\"agent_id\":\"$BOB_ID\"}" | jq -r .ok)
assert_eq "NG-PS-6 add member ok" "true" "$ADD_R"

# NG-PS-7: Alice promotes Bob to Admin
ROLE_R=$(curl -sf -X PATCH "$AA/groups/$GROUP_ID/members/$BOB_ID/role" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
  -d '{"role":"admin"}' | jq -r .ok)
assert_eq "NG-PS-7 role update ok" "true" "$ROLE_R"

# NG-PS-8: Alice removes Bob
REMOVE_R=$(curl -sf -X DELETE "$AA/groups/$GROUP_ID/members/$BOB_ID" \
  -H "Authorization: Bearer $AT" | jq -r .ok)
assert_eq "NG-PS-8 remove ok" "true" "$REMOVE_R"

# Cleanup
curl -sf -X DELETE "$AA/groups/$GROUP_ID" -H "Authorization: Bearer $AT" >/dev/null
```

### Section: `public_request_secure` full flow

```bash
# NG-PRS-1: Alice creates public_request_secure group
GROUP_ID=$(curl -sf -X POST "$AA/groups" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' \
  -d '{"name":"PublicReqGroup","preset":"public_request_secure"}' | jq -r .group_id)

# NG-PRS-2: Group appears in Alice's discover listing (she's owner)
DISC=$(curl -sf "$AA/groups/discover" -H "Authorization: Bearer $AT" | jq '[.groups[] | select(.group_id=="'$GROUP_ID'")]|length')
assert_eq "NG-PRS-2 discoverable by owner" "1" "$DISC"

# NG-PRS-3: Alice publishes group card
CARD_R=$(curl -sf -X POST "$AA/groups/$GROUP_ID/policy" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d '{"preset":"public_request_secure"}' | jq -r .ok)
assert_eq "NG-PRS-3 policy set ok" "true" "$CARD_R"

# NG-PRS-4: Bob imports Alice's card
CARD=$(curl -sf "$AA/groups/cards/$GROUP_ID" -H "Authorization: Bearer $AT")
IMP_R=$(curl -sf -X POST "$BA/groups/cards/import" -H "Authorization: Bearer $BT" \
  -H 'Content-Type: application/json' -d "$CARD" | jq -r .ok)
assert_eq "NG-PRS-4 card import ok" "true" "$IMP_R"

# NG-PRS-5: Bob submits join request
REQ_ID=$(curl -sf -X POST "$BA/groups/$GROUP_ID/requests" -H "Authorization: Bearer $BT" \
  -H 'Content-Type: application/json' -d '{"message":"Let me in"}' | jq -r .request_id)
assert_nonempty "NG-PRS-5 request_id" "$REQ_ID"

# NG-PRS-6: Alice sees Bob's request
PENDING=$(curl -sf "$AA/groups/$GROUP_ID/requests" -H "Authorization: Bearer $AT" | \
  jq '[.requests[] | select(.status=="pending")]|length')
assert_eq "NG-PRS-6 one pending request" "1" "$PENDING"

# NG-PRS-7: Alice approves Bob's request
APPROVE_R=$(curl -sf -X POST "$AA/groups/$GROUP_ID/requests/$REQ_ID/approve" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' -d '{}' | jq -r .ok)
assert_eq "NG-PRS-7 approve ok" "true" "$APPROVE_R"

# NG-PRS-8: Bob is now an active member
MEMBERS=$(curl -sf "$AA/groups/$GROUP_ID/members" -H "Authorization: Bearer $AT" | \
  jq '[.members[] | select(.agent_id=="'$BOB_ID'" and .state=="active")]|length')
assert_eq "NG-PRS-8 Bob is active member" "1" "$MEMBERS"

# NG-PRS-9: Charlie submits request, Alice rejects
CREQ_ID=$(curl -sf -X POST "$CA/groups/$GROUP_ID/requests" -H "Authorization: Bearer $CT" \
  -H 'Content-Type: application/json' -d '{}' | jq -r .request_id)
REJ_R=$(curl -sf -X POST "$AA/groups/$GROUP_ID/requests/$CREQ_ID/reject" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' -d '{}' | jq -r .ok)
assert_eq "NG-PRS-9 reject ok" "true" "$REJ_R"

# NG-PRS-10: Charlie is not a member
C_MEMBER=$(curl -sf "$AA/groups/$GROUP_ID/members" -H "Authorization: Bearer $AT" | \
  jq '[.members[] | select(.agent_id=="'$CHARLIE_ID'")]|length')
assert_eq "NG-PRS-10 Charlie not a member" "0" "$C_MEMBER"

# Cleanup
curl -sf -X DELETE "$AA/groups/$GROUP_ID" -H "Authorization: Bearer $AT" >/dev/null
```

### Section: Authorization negative paths

```bash
# NG-AUTH-1: Bob (non-member) cannot change policy
GROUP_ID=$(curl -sf -X POST "$AA/groups" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d '{"name":"AuthTest"}' | jq -r .group_id)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PATCH "$BA/groups/$GROUP_ID/policy" \
  -H "Authorization: Bearer $BT" -H 'Content-Type: application/json' -d '{"preset":"public_open"}')
assert_eq "NG-AUTH-1 non-member cannot change policy" "403" "$STATUS"

# NG-AUTH-2: Add Bob as plain Member, then Bob cannot change policy
curl -sf -X POST "$AA/groups/$GROUP_ID/members" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d "{\"agent_id\":\"$BOB_ID\"}" >/dev/null
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PATCH "$BA/groups/$GROUP_ID/policy" \
  -H "Authorization: Bearer $BT" -H 'Content-Type: application/json' -d '{"preset":"public_open"}')
assert_eq "NG-AUTH-2 member cannot change policy" "403" "$STATUS"

# NG-AUTH-3: Bob (Member) cannot approve requests (even if group is request-access)
curl -sf -X PATCH "$AA/groups/$GROUP_ID/policy" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d '{"preset":"public_request_secure"}' >/dev/null
CREQ_ID=$(curl -sf -X POST "$CA/groups/$GROUP_ID/requests" -H "Authorization: Bearer $CT" \
  -H 'Content-Type: application/json' -d '{}' | jq -r .request_id)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BA/groups/$GROUP_ID/requests/$CREQ_ID/approve" \
  -H "Authorization: Bearer $BT" -H 'Content-Type: application/json' -d '{}')
assert_eq "NG-AUTH-3 member cannot approve request" "403" "$STATUS"

# NG-AUTH-4: Bob (Member) cannot remove Alice (Owner)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BA/groups/$GROUP_ID/members/$ALICE_ID" \
  -H "Authorization: Bearer $BT")
assert_eq "NG-AUTH-4 member cannot remove owner" "403" "$STATUS"

# NG-AUTH-5: Banned member cannot rejoin via join request
curl -sf -X POST "$AA/groups/$GROUP_ID/ban/$BOB_ID" -H "Authorization: Bearer $AT" >/dev/null
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BA/groups/$GROUP_ID/requests" \
  -H "Authorization: Bearer $BT" -H 'Content-Type: application/json' -d '{}')
assert_eq "NG-AUTH-5 banned cannot request" "403" "$STATUS"

# Cleanup
curl -sf -X DELETE "$AA/groups/$GROUP_ID" -H "Authorization: Bearer $AT" >/dev/null
```

### Section: Convergence

```bash
# NG-CONV-1: Roster convergence — Alice creates, adds Bob; Bob waits for propagation
GROUP_ID=$(curl -sf -X POST "$AA/groups" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d '{"name":"ConvergenceTest"}' | jq -r .group_id)
INVITE=$(curl -sf -X POST "$AA/groups/$GROUP_ID/invite" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d '{}' | jq -r .invite_link)
curl -sf -X POST "$BA/groups/join" -H "Authorization: Bearer $BT" \
  -H 'Content-Type: application/json' -d "{\"invite\":\"$INVITE\"}" >/dev/null
curl -sf -X POST "$AA/groups/$GROUP_ID/members" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d "{\"agent_id\":\"$BOB_ID\"}" >/dev/null
sleep 3  # allow metadata event propagation
# Bob should see himself as member on his local view
BOB_VIEW=$(curl -sf "$BA/groups/$GROUP_ID/members" -H "Authorization: Bearer $BT" | \
  jq '[.members[] | select(.agent_id=="'$BOB_ID'")]|length')
assert_eq "NG-CONV-1 Bob sees self as member" "1" "$BOB_VIEW"

# NG-CONV-2: Policy update convergence
curl -sf -X PATCH "$AA/groups/$GROUP_ID/policy" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d '{"preset":"public_request_secure"}' >/dev/null
sleep 3
# Bob's local view of group should reflect updated policy (if metadata propagation works)
# NOTE: Full convergence of policy to peers not yet implemented in Phase A/B — this
# tests that Alice's own node reflects the policy change immediately.
POL=$(curl -sf "$AA/groups/$GROUP_ID" -H "Authorization: Bearer $AT" | jq -r .policy.admission)
assert_eq "NG-CONV-2 policy admission converged" "request_access" "$POL"

# NG-CONV-3: Delete convergence — Alice deletes, Bob's group should disappear
curl -sf -X DELETE "$AA/groups/$GROUP_ID" -H "Authorization: Bearer $AT" >/dev/null
sleep 3
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BA/groups/$GROUP_ID" -H "Authorization: Bearer $BT")
assert_eq "NG-CONV-3 deleted group gone from Bob" "404" "$STATUS"
```

### Section: Ban/unban lifecycle

```bash
# NG-BAN-1 through NG-BAN-4 (add after convergence section)
GROUP_ID=$(curl -sf -X POST "$AA/groups" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d '{"name":"BanTest","preset":"public_request_secure"}' | jq -r .group_id)
curl -sf -X POST "$AA/groups/$GROUP_ID/members" -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d "{\"agent_id\":\"$BOB_ID\"}" >/dev/null

BAN_R=$(curl -sf -X POST "$AA/groups/$GROUP_ID/ban/$BOB_ID" -H "Authorization: Bearer $AT" | jq -r .ok)
assert_eq "NG-BAN-1 ban ok" "true" "$BAN_R"
BOB_STATE=$(curl -sf "$AA/groups/$GROUP_ID/members" -H "Authorization: Bearer $AT" | \
  jq -r '[.members[] | select(.agent_id=="'$BOB_ID'")][0].state')
assert_eq "NG-BAN-2 Bob state=banned" "banned" "$BOB_STATE"

UNBAN_R=$(curl -sf -X DELETE "$AA/groups/$GROUP_ID/ban/$BOB_ID" -H "Authorization: Bearer $AT" | jq -r .ok)
assert_eq "NG-BAN-3 unban ok" "true" "$UNBAN_R"
BOB_STATE2=$(curl -sf "$AA/groups/$GROUP_ID/members" -H "Authorization: Bearer $AT" | \
  jq -r '[.members[] | select(.agent_id=="'$BOB_ID'")][0].state')
assert_eq "NG-BAN-4 Bob state=active after unban" "active" "$BOB_STATE2"

curl -sf -X DELETE "$AA/groups/$GROUP_ID" -H "Authorization: Bearer $AT" >/dev/null
```

The `assert_eq` and `assert_nonempty` helper pattern is already present in `tests/e2e_full_audit.sh` (the existing pass/fail counter uses `P`, `F`, `S` variables). Use the same pattern. `ALICE_ID`, `BOB_ID`, `CHARLIE_ID` should be captured at daemon startup using `curl "$AA/agent" | jq -r .agent_id` and stored in variables early in the script.

---

## Critical Details

**No unwrap/expect in production paths**: All new handlers use `?` with early-return error tuples. The new module files must not have any `unwrap()` or `expect()` outside `#[cfg(test)]` blocks.

**Thread safety**: All handlers take `State(state): State<Arc<AppState>>`. The `RwLock<HashMap>` pattern is consistent. For the join-request handlers, acquire write lock, mutate, drop lock before publishing gossip event (same pattern as `add_named_group_member`).

**`members_v2` naming**: This is an internal field name change. The JSON API response should use `members` (not `members_v2`) by adding `#[serde(rename = "members")]` to `members_v2`, but only in the serialized JSON response structs built in `named_group_member_values`. The struct field remains `members_v2` to avoid name collision. Alternatively, after migration is complete (no old clients), rename back to `members` — but that is a future cleanup. For now, the JSON API response is assembled manually via `named_group_member_values`, so the field name in the response is controlled there, not by the struct serialization.

**Route precedence for `/groups/discover`**: Axum uses first-match for static vs. parameterized routes when they share a prefix. Verify that `get(discover_groups)` is registered before `get(get_named_group)` with `/:id`. Look at the existing `/groups/join` route — it works because it is registered at line 1272 before `/groups/:id` delete at line 1274. Apply the same ordering for all new static-suffix group routes.

**Phase D note in code**: Every place where MLS rekey should happen on role change or ban, add:
```rust
// Phase D: trigger MLS epoch advance/rekey here when member privilege changes.
// See docs/design/named-groups-full-model.md Phase D.
```

**`uuid` dependency**: Check `/Users/davidirvine/Desktop/Devel/projects/x0x/Cargo.toml` for `uuid`. If absent, generate request IDs as `hex::encode({16 random bytes from rand::thread_rng()})` — this is already used elsewhere in x0xd.rs for group IDs.

**Existing test backward compatibility**: The test at `tests/named_group_integration.rs:238` (`named_group_add_remove_member_local`) currently calls `POST /groups/:id/members` which will now require Admin+. Since the caller is the creator/owner, this is still satisfied — the check `require_admin_or_above` will see `Owner` role, which is `at_least(Admin)`. No test changes needed for existing tests. However, the member list response JSON shape changes (adds `role`, `joined_at`, `added_by`). Tests that assert exact JSON structure of member list entries must be updated.