//! Named-group route handlers (`category: "named-groups"` in `src/api/mod.rs`):
//! `/groups` CRUD, membership, invites, join requests, discovery, cards,
//! secure encrypt/decrypt/reseal, state commits, and the TreeKEM metadata /
//! recovery / persistence machinery behind them.
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use super::super::state::AppState;
use super::super::{
    api_error, bad_request, forbidden, not_found, parse_agent_id_hex, parse_optional_json,
};
use super::direct::direct_message_send_config;
use super::files::{
    file_transfer_send_config, wait_for_chunk_window, wait_for_final_acks, FileChunkAckSlot,
};
use super::groups::save_mls_groups;
use super::identity::populate_invite_base_state_from_group_info;
use crate as x0x;
use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Mutex, RwLock};
use x0x::contacts::TrustLevel;
use x0x::identity::AgentId;
use x0x::logging::LogHexId;
use x0x::Agent;

pub(in crate::server) const GROUP_BACKGROUND_PUBLISH_DELAY: Duration = Duration::from_secs(8);

const NAMED_GROUP_METADATA_PUBLISH_TIMEOUT: Duration = Duration::from_secs(5);

const TREEKEM_PENDING_EVENTS_PER_GROUP_CAP: usize = 64;

const TREEKEM_EVENT_LOG_PER_GROUP_CAP: usize = 128;

// TreeKEM MemberAdded events carry signed state commits plus commit/welcome
// references and are ~35-40 KiB each on the wire. Two events in one catch-up
// response exceed the direct-message payload cap, so paginate one event at a
// time and rely on the existing `truncated` next-page loop.
const TREEKEM_CATCHUP_RESPONSE_EVENT_CAP: usize = 1;

const TREEKEM_PROVISIONAL_RECOVERY_PER_GROUP_CAP: usize = 64;

const TREEKEM_CATCHUP_THROTTLE: Duration = Duration::from_secs(5);

/// Recovery records are large signed events (~15.7 KiB each). Bound the
/// compact snapshot to 512 active-member records and 8 MiB encoded JSON.
/// Both limits are enforced after every mutation and during startup load.
const TREEKEM_MEMBER_KEY_PACKAGE_CACHE_MAX_ENTRIES: usize = 512;

const TREEKEM_MEMBER_KEY_PACKAGE_CACHE_MAX_BYTES: usize = 8 * 1024 * 1024;

pub(in crate::server) struct TreeKemMemberKeyPackageCacheEntry {
    event: NamedGroupMetadataEvent,
    encoded_bytes: usize,
}

pub(in crate::server) struct TreeKemMemberKeyPackageCacheState {
    entries: BTreeMap<String, TreeKemMemberKeyPackageCacheEntry>,
    encoded_bytes: usize,
    revision: u64,
    persisted_revision: u64,
    dirty: bool,
    write_failures: u64,
    last_error: Option<String>,
}

#[derive(Clone)]
pub(in crate::server) struct TreeKemMemberKeyPackageCache {
    path: PathBuf,
    state: Arc<RwLock<TreeKemMemberKeyPackageCacheState>>,
    persistence: Arc<Mutex<()>>,
    retry_scheduled: Arc<AtomicBool>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(in crate::server) enum TreeKemCachePersistenceStatus {
    Durable { revision: u64 },
    Dirty { revision: u64, error: String },
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(in crate::server) struct TreeKemCacheDiagnostics {
    pub(in crate::server) entries: usize,
    pub(in crate::server) encoded_bytes: usize,
    pub(in crate::server) max_entries: usize,
    pub(in crate::server) max_encoded_bytes: usize,
    pub(in crate::server) revision: u64,
    pub(in crate::server) persisted_revision: u64,
    pub(in crate::server) dirty: bool,
    pub(in crate::server) write_failures: u64,
    pub(in crate::server) last_error: Option<String>,
}

pub(in crate::server) struct TreeKemCacheMutation {
    persistence: TreeKemCachePersistenceStatus,
    evicted: usize,
}

#[cfg(test)]
static NAMED_GROUP_METADATA_PUBLISH_ATTEMPTS_FOR_TEST: StdMutex<Vec<(String, String)>> =
    StdMutex::new(Vec::new());

#[cfg(test)]
static TREEKEM_FINAL_INSTALL_BEFORE_MAP_WRITE_NOTIFY: StdMutex<
    Option<(String, Arc<tokio::sync::Notify>)>,
> = StdMutex::new(None);

#[cfg(test)]
static RECOVERED_KP_BEFORE_MEMBERSHIP_LOCK_NOTIFY: StdMutex<
    Option<(String, Arc<tokio::sync::Notify>)>,
> = StdMutex::new(None);

#[cfg(test)]
static NAMED_GROUP_SAVE_AFTER_SNAPSHOT_NOTIFY: StdMutex<
    Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
> = StdMutex::new(None);

#[cfg(test)]
pub(in crate::server) struct TreeKemCacheWriterHookControl {
    // Signalled with a stored permit once the writer has entered the hook, so a
    // test can deterministically observe that the write is in flight regardless
    // of await ordering.
    entered: Arc<tokio::sync::Notify>,
    // When present, the writer parks here until signalled (slow-disk simulation).
    release: Option<Arc<tokio::sync::Notify>>,
    // When present, the write returns this error instead of touching the disk.
    force_error: Option<std::io::Error>,
}

// Test-only, path-scoped, one-shot writer seam for the TreeKEM recovery cache.
// Keyed by the cache's on-disk path so tests over distinct temp directories can
// never cross-talk. A hook is consumed the first time the writer fires it
// (`take_*` removes it), and the owning guard removes any still-pending entry
// on drop, so cleanup is RAII-safe even on panic. Production code only reaches
// this through the `#[cfg(test)]` block in `write_treekem_cache_json_atomic`.
#[cfg(test)]
static TREEKEM_CACHE_WRITER_HOOKS: std::sync::LazyLock<
    StdMutex<std::collections::HashMap<PathBuf, TreeKemCacheWriterHookControl>>,
> = std::sync::LazyLock::new(|| StdMutex::new(std::collections::HashMap::new()));

#[cfg(test)]
fn take_treekem_cache_writer_hook_for_test(path: &FsPath) -> Option<TreeKemCacheWriterHookControl> {
    TREEKEM_CACHE_WRITER_HOOKS
        .lock()
        .expect("TreeKEM cache writer hook poisoned")
        .remove(path)
}

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// Hard upper bound for the discoverable group-card bridge cache. This cache
/// is populated from untrusted discovery surfaces, so it must not grow without
/// bound even if every incoming card is syntactically valid.
const GROUP_CARD_CACHE_CAP: usize = 8_192;

fn group_card_expiry_millis(card: &x0x::groups::GroupCard) -> u64 {
    if card.expires_at > card.issued_at {
        card.expires_at
    } else {
        card.issued_at
            .saturating_add(x0x::groups::GroupCard::default_ttl_secs().saturating_mul(1_000))
    }
}

fn group_card_is_expired(card: &x0x::groups::GroupCard, now_ms: u64) -> bool {
    group_card_expiry_millis(card) < now_ms
}

fn prune_expired_group_cards(cache: &mut HashMap<String, x0x::groups::GroupCard>, now_ms: u64) {
    cache.retain(|_, card| !group_card_is_expired(card, now_ms));
}

fn enforce_group_card_cache_cap(cache: &mut HashMap<String, x0x::groups::GroupCard>) {
    if cache.len() <= GROUP_CARD_CACHE_CAP {
        return;
    }

    let remove_count = cache.len().saturating_sub(GROUP_CARD_CACHE_CAP);
    let mut victims: Vec<(String, u64, u64, u64)> = cache
        .iter()
        .map(|(key, card)| {
            (
                key.clone(),
                group_card_expiry_millis(card),
                card.issued_at,
                card.revision,
            )
        })
        .collect();
    victims.sort_by(|left, right| {
        left.1
            .cmp(&right.1)
            .then_with(|| left.2.cmp(&right.2))
            .then_with(|| left.3.cmp(&right.3))
            .then_with(|| left.0.cmp(&right.0))
    });
    for (key, _, _, _) in victims.into_iter().take(remove_count) {
        cache.remove(&key);
    }
}

fn prune_and_bound_group_card_cache(
    cache: &mut HashMap<String, x0x::groups::GroupCard>,
    now_ms: u64,
) {
    prune_expired_group_cards(cache, now_ms);
    enforce_group_card_cache_cap(cache);
}

fn cache_group_card_if_newer(
    cache: &mut HashMap<String, x0x::groups::GroupCard>,
    key: String,
    card: x0x::groups::GroupCard,
) -> bool {
    let should_insert = match cache.get(&key) {
        Some(existing) => card.supersedes(existing),
        None => true,
    };
    if should_insert {
        cache.insert(key, card);
    }
    should_insert
}

fn remove_group_card_if_not_stale(
    cache: &mut HashMap<String, x0x::groups::GroupCard>,
    card: &x0x::groups::GroupCard,
) -> bool {
    let should_remove = match cache.get(&card.group_id) {
        Some(existing) => {
            card.revision > existing.revision
                || (card.revision == existing.revision && card.issued_at >= existing.issued_at)
        }
        None => false,
    };
    if should_remove {
        cache.remove(&card.group_id);
    }
    should_remove
}

fn group_card_supersedes_group_info(
    card: &x0x::groups::GroupCard,
    info: &x0x::groups::GroupInfo,
) -> bool {
    card.revision > info.state_revision
        || (card.revision == info.state_revision && card.updated_at >= info.updated_at)
}

fn apply_withdrawn_group_card_to_group_info(
    info: &mut x0x::groups::GroupInfo,
    card: &x0x::groups::GroupCard,
) -> bool {
    if !card.withdrawn || !group_card_supersedes_group_info(card, info) {
        return false;
    }

    info.name = card.name.clone();
    info.description = card.description.clone();
    info.policy = x0x::groups::GroupPolicy::from(&card.policy_summary);
    info.created_at = card.created_at;
    info.updated_at = card.updated_at;
    if let Some(metadata_topic) = card.metadata_topic.clone() {
        info.metadata_topic = metadata_topic;
    }
    info.state_revision = card.revision;
    if !card.state_hash.is_empty() {
        info.state_hash = card.state_hash.clone();
    }
    info.prev_state_hash = card.prev_state_hash.clone();
    info.withdrawn = true;
    clear_group_info_key_material(info);
    if info
        .genesis
        .as_ref()
        .is_none_or(|genesis| genesis.group_id != card.group_id)
    {
        info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            card.group_id.clone(),
            card.owner_agent_id.clone(),
            card.created_at,
            String::new(),
        ));
    }
    info.members_v2
        .entry(card.owner_agent_id.clone())
        .or_insert_with(|| {
            x0x::groups::GroupMember::new_admin(card.owner_agent_id.clone(), None, card.created_at)
        });
    true
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

fn named_group_direct_delivery_config() -> x0x::dm::DmSendConfig {
    // Named-group metadata applies require `DirectMessage::verified == true`.
    // The gossip-inbox DM path verifies the signed DM envelope and marks the
    // bridged direct message verified. Raw QUIC can only mark messages
    // verified when the receiver already has a fresh AgentId -> MachineId
    // binding, so keep it as the fallback for peers whose gossip-inbox
    // capability advert has not converged yet. Terminal signed commits (for
    // example admin delete) are self-authenticating and explicitly re-check
    // authority on apply, so dropping the raw fallback can strand members after
    // their metadata listener exits.
    let mut config = direct_message_send_config();
    config.raw_quic_receive_ack_timeout = Some(Duration::from_secs(8));
    config.require_gossip_ack = true;
    config
}

/// Request body for POST /groups.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct CreateGroupRequest {
    name: String,
    #[serde(default)]
    description: String,
    /// Optional display name for the creator in this group.
    #[serde(default)]
    display_name: Option<String>,
    /// Policy preset name (private_secure / public_request_secure / public_open /
    /// public_announce). Defaults to `private_secure`.
    #[serde(default)]
    preset: Option<String>,
}

/// Request body for POST /groups/join.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct JoinGroupRequest {
    /// Invite link or raw base64 invite token.
    invite: String,
    /// Optional display name for the joiner.
    #[serde(default)]
    display_name: Option<String>,
}

/// Request body for POST /groups/:id/invite.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct CreateInviteRequest {
    /// Seconds until expiry (default: 7 days, 0 = never).
    #[serde(default = "default_expiry")]
    expiry_secs: u64,
}

impl Default for CreateInviteRequest {
    fn default() -> Self {
        Self {
            expiry_secs: default_expiry(),
        }
    }
}

fn default_expiry() -> u64 {
    x0x::groups::invite::DEFAULT_EXPIRY_SECS
}

/// Request body for PUT /groups/:id/display-name.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct SetDisplayNameRequest {
    name: String,
}

/// Request body for POST /groups/:id/members.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct AddNamedGroupMemberRequest {
    agent_id: String,
    #[serde(default)]
    display_name: Option<String>,
    /// Base64 postcard-encoded TreeKEM KeyPackage supplied by the target.
    /// Required when directly adding to a TreeKEM group.
    #[serde(default)]
    treekem_key_package_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::server) struct WelcomeRef {
    welcome_id: String,
    byte_len: u64,
    source: String,
}

#[derive(Debug, Clone)]
pub(in crate::server) struct PendingJoinResult {
    event: NamedGroupMetadataEvent,
    created_at: Instant,
}

#[derive(Debug, Clone)]
pub(in crate::server) struct ExpectedJoinResultInviter {
    inviter_agent_id: String,
    created_at: Instant,
}

#[derive(Debug, Clone)]
pub(in crate::server) struct PendingWelcome {
    group_id: String,
    joiner_agent: String,
    bytes: Vec<u8>,
    created_at: Instant,
}

pub(in crate::server) struct PendingWelcomeReceive {
    group_id: String,
    source: String,
    byte_len: u64,
    total_chunks: u64,
    chunks: BTreeMap<u64, Vec<u8>>,
    received_bytes: u64,
}

#[derive(Debug, Clone)]
pub(in crate::server) struct PendingTreeKemMetadataEvent {
    event: NamedGroupMetadataEvent,
    sender: AgentId,
    queued_at: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::server) struct TreeKemCatchupRequest {
    pub(in crate::server) message_type: String,
    group_id: String,
    requester_agent_id: String,
    from_revision: u64,
    from_treekem_epoch: u64,
    current_state_hash: String,
    missing_prev_state_hash: Option<String>,
    /// Issue #205: when set, this is a member-keyed key-package fetch — the
    /// responder returns the cached, self-signed `MemberJoined` for this member
    /// (carrying its TreeKEM KeyPackage) instead of the revision-gap frontier.
    /// Backward compatible: old daemons ignore the field and serve the normal
    /// frontier; `#[serde(default)]` lets new daemons parse old requests.
    #[serde(default)]
    target_member_id: Option<String>,
    limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::server) struct TreeKemCatchupResponse {
    pub(in crate::server) message_type: String,
    group_id: String,
    events: Vec<NamedGroupMetadataEvent>,
    truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(in crate::server) enum JoinResultMessage {
    FetchRequest {
        group_id: String,
        member_agent_id: String,
    },
    Result {
        event: Box<NamedGroupMetadataEvent>,
    },
}

pub(in crate::server) fn named_group_metadata_event_kind(
    event: &NamedGroupMetadataEvent,
) -> &'static str {
    match event {
        NamedGroupMetadataEvent::MemberAdded { .. } => "member_added",
        NamedGroupMetadataEvent::MemberRemoved { .. } => "member_removed",
        NamedGroupMetadataEvent::GroupDeleted { .. } => "group_deleted",
        NamedGroupMetadataEvent::PolicyUpdated { .. } => "policy_updated",
        NamedGroupMetadataEvent::MemberRoleUpdated { .. } => "member_role_updated",
        NamedGroupMetadataEvent::MemberBanned { .. } => "member_banned",
        NamedGroupMetadataEvent::MemberUnbanned { .. } => "member_unbanned",
        NamedGroupMetadataEvent::JoinRequestCreated { .. } => "join_request_created",
        NamedGroupMetadataEvent::JoinRequestApproved { .. } => "join_request_approved",
        NamedGroupMetadataEvent::JoinRequestRejected { .. } => "join_request_rejected",
        NamedGroupMetadataEvent::JoinRequestCancelled { .. } => "join_request_cancelled",
        NamedGroupMetadataEvent::GroupCardPublished { .. } => "group_card_published",
        NamedGroupMetadataEvent::GroupMetadataUpdated { .. } => "group_metadata_updated",
        NamedGroupMetadataEvent::MemberJoined { .. } => "member_joined",
        NamedGroupMetadataEvent::SecureShareDelivered { .. } => "secure_share_delivered",
    }
}

fn named_group_metadata_event_group_id(event: &NamedGroupMetadataEvent) -> &str {
    match event {
        NamedGroupMetadataEvent::MemberAdded { group_id, .. }
        | NamedGroupMetadataEvent::MemberRemoved { group_id, .. }
        | NamedGroupMetadataEvent::GroupDeleted { group_id, .. }
        | NamedGroupMetadataEvent::PolicyUpdated { group_id, .. }
        | NamedGroupMetadataEvent::MemberRoleUpdated { group_id, .. }
        | NamedGroupMetadataEvent::MemberBanned { group_id, .. }
        | NamedGroupMetadataEvent::MemberUnbanned { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestCreated { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestApproved { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestRejected { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestCancelled { group_id, .. }
        | NamedGroupMetadataEvent::GroupCardPublished { group_id, .. }
        | NamedGroupMetadataEvent::GroupMetadataUpdated { group_id, .. }
        | NamedGroupMetadataEvent::MemberJoined { group_id, .. }
        | NamedGroupMetadataEvent::SecureShareDelivered { group_id, .. } => group_id,
    }
}

fn withdrawn_group_allows_metadata_event(event: &NamedGroupMetadataEvent) -> bool {
    matches!(
        event,
        NamedGroupMetadataEvent::GroupDeleted {
            commit: Some(commit),
            ..
        } if commit.withdrawn
    )
}

fn named_group_metadata_event_commit(
    event: &NamedGroupMetadataEvent,
) -> Option<&x0x::groups::GroupStateCommit> {
    match event {
        NamedGroupMetadataEvent::MemberAdded { commit, .. }
        | NamedGroupMetadataEvent::MemberRemoved { commit, .. }
        | NamedGroupMetadataEvent::GroupDeleted { commit, .. }
        | NamedGroupMetadataEvent::PolicyUpdated { commit, .. }
        | NamedGroupMetadataEvent::MemberRoleUpdated { commit, .. }
        | NamedGroupMetadataEvent::MemberBanned { commit, .. }
        | NamedGroupMetadataEvent::MemberUnbanned { commit, .. }
        | NamedGroupMetadataEvent::JoinRequestCreated { commit, .. }
        | NamedGroupMetadataEvent::JoinRequestApproved { commit, .. }
        | NamedGroupMetadataEvent::JoinRequestRejected { commit, .. }
        | NamedGroupMetadataEvent::JoinRequestCancelled { commit, .. }
        | NamedGroupMetadataEvent::GroupMetadataUpdated { commit, .. } => commit.as_ref(),
        NamedGroupMetadataEvent::GroupCardPublished { .. }
        | NamedGroupMetadataEvent::MemberJoined { .. }
        | NamedGroupMetadataEvent::SecureShareDelivered { .. } => None,
    }
}

fn live_group_allows_metadata_withdrawal_commit(event: &NamedGroupMetadataEvent) -> bool {
    match named_group_metadata_event_commit(event) {
        Some(commit) if commit.withdrawn => withdrawn_group_allows_metadata_event(event),
        _ => true,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(in crate::server) enum WelcomeBlobMessage {
    FetchRequest {
        group_id: String,
        welcome_id: String,
    },
    Offer {
        group_id: String,
        welcome_id: String,
        byte_len: u64,
        chunk_size: usize,
        total_chunks: u64,
        blake3_hex: String,
    },
    Chunk {
        welcome_id: String,
        sequence: u64,
        data: String,
    },
    ChunkAck {
        welcome_id: String,
        sequence: u64,
    },
    Complete {
        welcome_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
// Phase D.3 enlarged GroupCard with a ~6 KB authority signature and a
// long ML-KEM envelope. Boxing any one variant would force serde-boxed
// wire format breaks; the in-memory size delta is irrelevant compared
// to the gossip plumbing cost.
#[allow(clippy::large_enum_variant)]
pub(in crate::server) enum NamedGroupMetadataEvent {
    MemberAdded {
        group_id: String,
        revision: u64,
        actor: String,
        agent_id: String,
        display_name: Option<String>,
        /// Base64 postcard-encoded TreeKEM Commit for existing members.
        #[serde(default)]
        treekem_commit_b64: Option<String>,
        /// Base64 postcard-encoded TreeKEM Welcome for the added member.
        /// Legacy fallback; new events carry `welcome_ref` instead.
        #[serde(default)]
        treekem_welcome_b64: Option<String>,
        /// Content-addressed pull reference for the added member's TreeKEM Welcome.
        #[serde(default)]
        welcome_ref: Option<WelcomeRef>,
        /// TreeKEM epoch after applying `treekem_commit_b64`.
        #[serde(default)]
        treekem_epoch: Option<u64>,
        /// Hash of the admitted KeyPackage committed in the roster root.
        #[serde(default)]
        treekem_key_package_hash: Option<String>,
        /// Original member-signed join event, countersigned by the inviter
        /// after the TreeKEM add succeeds. This binds recovery to the accepted
        /// leaf instead of any later package the member can self-sign.
        #[serde(default)]
        member_joined_recovery: Option<Box<NamedGroupMetadataEvent>>,
        /// Authority-attested records for members already in the roster. A
        /// later joiner receives these with its own MemberAdded/Welcome, so a
        /// future removal does not depend on the original inviter or target.
        #[serde(default)]
        member_recovery_history: Vec<NamedGroupMetadataEvent>,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    MemberRemoved {
        group_id: String,
        revision: u64,
        actor: String,
        agent_id: String,
        /// Base64 postcard-encoded TreeKEM Commit for remaining members.
        #[serde(default)]
        treekem_commit_b64: Option<String>,
        /// TreeKEM epoch after applying `treekem_commit_b64`.
        #[serde(default)]
        treekem_epoch: Option<u64>,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    GroupDeleted {
        group_id: String,
        revision: u64,
        actor: String,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    PolicyUpdated {
        group_id: String,
        revision: u64,
        actor: String,
        policy: x0x::groups::GroupPolicy,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    MemberRoleUpdated {
        group_id: String,
        revision: u64,
        actor: String,
        agent_id: String,
        role: x0x::groups::GroupRole,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    MemberBanned {
        group_id: String,
        revision: u64,
        actor: String,
        agent_id: String,
        /// For MlsEncrypted groups, the new secret epoch committed into the
        /// signed state hash. Receivers use this to update the security binding
        /// before `finalize_applied_commit`, avoiding dependence on the later
        /// `SecureShareDelivered` arrival order.
        #[serde(default)]
        secret_epoch: Option<u64>,
        /// Base64 postcard-encoded TreeKEM Commit for remaining members.
        #[serde(default)]
        treekem_commit_b64: Option<String>,
        /// TreeKEM epoch after applying `treekem_commit_b64`.
        #[serde(default)]
        treekem_epoch: Option<u64>,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    MemberUnbanned {
        group_id: String,
        revision: u64,
        actor: String,
        agent_id: String,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    JoinRequestCreated {
        group_id: String,
        request_id: String,
        requester_agent_id: String,
        message: Option<String>,
        ts: u64,
        /// Base64 of the requester's ML-KEM-768 public key, sent so the
        /// approver can later seal a `SecureShareDelivered` envelope to them.
        /// Required for MlsEncrypted groups; optional for others.
        #[serde(default)]
        requester_kem_public_key_b64: Option<String>,
        /// Base64 postcard-encoded TreeKEM KeyPackage for ADR-0012 Phase 3
        /// joins. Present for TreeKEM groups so an approver can produce the
        /// real Commit/Welcome pair; absent for legacy GSS groups and old
        /// requests.
        #[serde(default)]
        treekem_key_package_b64: Option<String>,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    JoinRequestApproved {
        group_id: String,
        request_id: String,
        revision: u64,
        actor: String,
        requester_agent_id: String,
        /// Base64 postcard-encoded TreeKEM Commit for existing members.
        #[serde(default)]
        treekem_commit_b64: Option<String>,
        /// Base64 postcard-encoded TreeKEM Welcome for the requester.
        /// Legacy fallback; new events carry `welcome_ref` instead.
        #[serde(default)]
        treekem_welcome_b64: Option<String>,
        /// Content-addressed pull reference for the requester's TreeKEM Welcome.
        #[serde(default)]
        welcome_ref: Option<WelcomeRef>,
        /// Hash of the KeyPackage accepted by the approving authority.
        #[serde(default)]
        treekem_key_package_hash: Option<String>,
        /// TreeKEM epoch after applying `treekem_commit_b64`.
        #[serde(default)]
        treekem_epoch: Option<u64>,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    JoinRequestRejected {
        group_id: String,
        request_id: String,
        actor: String,
        requester_agent_id: String,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    JoinRequestCancelled {
        group_id: String,
        request_id: String,
        requester_agent_id: String,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    GroupCardPublished {
        group_id: String,
        card: x0x::groups::GroupCard,
    },
    GroupMetadataUpdated {
        group_id: String,
        revision: u64,
        actor: String,
        name: Option<String>,
        description: Option<String>,
        #[serde(default)]
        commit: Option<x0x::groups::GroupStateCommit>,
    },
    /// Joiner-authored membership announcement on `info.metadata_topic`.
    ///
    /// Emitted by `join_group_via_invite` immediately after the joiner's
    /// local `members_v2.insert`. The original inviter's
    /// `apply_named_group_metadata_event` verifies the joiner's ML-DSA-65
    /// signature, consumes the locally-issued one-time invite record,
    /// rejects any role other than `Member`, then publishes an
    /// authority-signed `MemberAdded` commit. Third-party receivers retain the
    /// validated signed event as recovery evidence but apply only the signed
    /// commit, keeping durable roster and `state_hash` mutations inside the D.3
    /// commit chain. This is the
    /// gossip-layer fix for the `WritePolicyViolation { policy:
    /// MembersOnly }` cascade documented in
    /// `docs/design/groups-join-roster-propagation.md`.
    MemberJoined {
        group_id: String,
        /// Stable D.3 group_id, if the joiner already knows it. Receivers
        /// resolve the local group via `mls_group_id` first, then fall
        /// back to this.
        #[serde(default)]
        stable_group_id: Option<String>,
        /// Hex agent_id of the joiner (always equals `sender`).
        member_agent_id: String,
        /// Base64 ML-DSA-65 public key of the joiner. Receivers use this
        /// to verify `signature_b64` and to recompute the AgentId.
        member_public_key_b64: String,
        /// Joiner's requested role on entry. Invite-join v1 accepts only
        /// `Member`; higher roles require a future authority-signed flow.
        role: x0x::groups::GroupRole,
        /// Optional display name carried in the join request body.
        #[serde(default)]
        display_name: Option<String>,
        /// Hex agent_id of the inviter (matches `SignedInvite::inviter`).
        inviter_agent_id: String,
        /// Hex one-time invite secret carried by the join handshake. The
        /// original inviter checks this against `info.issued_invites` and
        /// consumes it before publishing the authoritative `MemberAdded`
        /// commit. Third-party receivers never apply this secret directly.
        invite_secret: String,
        /// Unix-millis timestamp at the joiner.
        ts_ms: u64,
        /// Base64 postcard-encoded TreeKEM KeyPackage for invite joins.
        #[serde(default)]
        treekem_key_package_b64: Option<String>,
        /// Inviter countersignature added only after authoritative acceptance.
        #[serde(default)]
        recovery_authority_agent_id: Option<String>,
        #[serde(default)]
        recovery_authority_public_key_b64: Option<String>,
        #[serde(default)]
        recovery_authority_signature_b64: Option<String>,
        /// The accepted MemberAdded state commit that established historical
        /// inviter authority; its structural signature remains verifiable even
        /// if the inviter is later demoted or removed.
        #[serde(default)]
        recovery_authority_commit: Option<x0x::groups::GroupStateCommit>,
        /// Base64 ML-DSA-65 signature over `canonical_member_joined_bytes`.
        signature_b64: String,
    },
    /// Phase D.2 (fixed): Cross-daemon delivery of the group's shared secret,
    /// sealed with ML-KEM-768 to the recipient's published public key.
    ///
    /// **Confidentiality**: a gossip observer who does NOT hold the recipient's
    /// ML-KEM-768 private key cannot recover `shared_secret`, by ML-KEM
    /// IND-CCA2 security. The adversarial E2E proof in
    /// `tests/e2e_named_groups.sh` section 2c verifies this behaviorally.
    ///
    /// Fields (all base64):
    /// - `kem_ciphertext_b64`: ML-KEM-768 encapsulated ciphertext (~1088 bytes).
    /// - `aead_nonce_b64`: 12-byte ChaCha20-Poly1305 nonce.
    /// - `aead_ciphertext_b64`: 48-byte AEAD-encrypted 32-byte secret.
    SecureShareDelivered {
        group_id: String,
        /// Hex agent_id of the intended recipient.
        recipient: String,
        /// New epoch of the shared secret.
        secret_epoch: u64,
        /// Base64 ML-KEM-768 encapsulated ciphertext.
        kem_ciphertext_b64: String,
        /// Base64 12-byte AEAD nonce.
        aead_nonce_b64: String,
        /// Base64 AEAD ciphertext of the 32-byte shared secret (tag included).
        aead_ciphertext_b64: String,
        /// Hex agent_id of the distributor (actor) — for authority checks.
        actor: String,
    },
}

/// Construct the AEAD additional-authenticated-data binding for a
/// `SecureShareDelivered` envelope. Must match exactly between sealer and
/// opener.
fn secure_share_aad(group_id: &str, recipient_hex: &str, secret_epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(128);
    aad.extend_from_slice(b"x0x.group.share.v2|");
    aad.extend_from_slice(group_id.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(recipient_hex.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(&secret_epoch.to_le_bytes());
    aad
}

/// Build and publish a `SecureShareDelivered` envelope sealed to the named
/// recipient's ML-KEM-768 public key. Used by approval (new member) and
/// ban-rekey (remaining members). Returns true iff the envelope was sealed
/// and broadcast. Returns false if the recipient's KEM pubkey is unknown
/// locally — in that case the caller should log and proceed without the
/// envelope rather than crashing.
#[allow(clippy::too_many_arguments)]
async fn publish_secure_share(
    state: &AppState,
    metadata_topic: &str,
    group_id: &str,
    recipient_hex: &str,
    recipient_kem_public_b64: &str,
    actor_hex: &str,
    secret: &[u8; 32],
    secret_epoch: u64,
) -> bool {
    use base64::Engine as _;
    let recipient_kem_public = match BASE64.decode(recipient_kem_public_b64) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                recipient = %LogHexId::agent(&recipient_hex),
                "publish_secure_share: recipient KEM public key not valid base64: {e}"
            );
            return false;
        }
    };
    let aad = secure_share_aad(group_id, recipient_hex, secret_epoch);
    let (kem_ct, aead_nonce, aead_ct) =
        match x0x::groups::kem_envelope::seal_group_secret_to_recipient(
            &recipient_kem_public,
            &aad,
            secret,
        ) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(recipient = %LogHexId::agent(&recipient_hex), "KEM seal failed: {e}");
                return false;
            }
        };
    let event = NamedGroupMetadataEvent::SecureShareDelivered {
        group_id: group_id.to_string(),
        recipient: recipient_hex.to_string(),
        secret_epoch,
        kem_ciphertext_b64: BASE64.encode(&kem_ct),
        aead_nonce_b64: BASE64.encode(aead_nonce),
        aead_ciphertext_b64: BASE64.encode(&aead_ct),
        actor: actor_hex.to_string(),
    };
    publish_named_group_metadata_event(state, metadata_topic, &event).await;
    spawn_named_group_event_delivery(state, recipient_hex, &event);
    spawn_named_group_event_delivery_after(
        state,
        recipient_hex,
        &event,
        GROUP_BACKGROUND_PUBLISH_DELAY,
    );
    true
}

fn named_group_member_values(info: &x0x::groups::GroupInfo) -> Vec<serde_json::Value> {
    // Include active + banned (banned members still appear in the roster for
    // audit / admin view). Removed members are dropped.
    let mut members: Vec<&x0x::groups::GroupMember> = info
        .members_v2
        .values()
        .filter(|m| !m.is_removed())
        .collect();
    members.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
    members
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "agent_id": m.agent_id,
                "role": m.role,
                "state": m.state,
                "display_name": m.display_name.clone().unwrap_or_else(|| info.display_name(&m.agent_id)),
                "joined_at": m.joined_at,
                "added_by": m.added_by,
            })
        })
        .collect()
}

#[allow(dead_code)]
fn named_group_member_values_all(info: &x0x::groups::GroupInfo) -> Vec<serde_json::Value> {
    let mut members: Vec<&x0x::groups::GroupMember> = info.members_v2.values().collect();
    members.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
    members
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "agent_id": m.agent_id,
                "role": m.role,
                "state": m.state,
                "display_name": m.display_name.clone().unwrap_or_else(|| info.display_name(&m.agent_id)),
                "joined_at": m.joined_at,
                "added_by": m.added_by,
                "removed_by": m.removed_by,
                "updated_at": m.updated_at,
            })
        })
        .collect()
}

/// Well-known gossip topic that every daemon subscribes to for public group card
/// discovery. Publishing a `GroupCardPublished` event here makes the group
/// visible in any peer's `/groups/discover` without requiring manual card import.
const GLOBAL_GROUP_DISCOVERY_TOPIC: &str = "x0x.discovery.groups";

/// Publish a group's card to the global discovery topic when it is discoverable.
/// No-op if the group is Hidden and not withdrawn.
///
/// Phase D.3: the card carries the current committed `state_hash` and is
/// signed with the local agent's ML-DSA-65 key so peers can verify
/// authority and apply higher-revision supersession deterministically.
/// If `reseal=true`, this call also advances the state-commit chain
/// (bumps revision, updates `prev_state_hash`) before signing the card —
/// used by explicit `/state/seal` and `/state/withdraw` endpoints. When
/// `reseal=false`, the card reflects the current already-sealed state.
pub(in crate::server) async fn publish_group_card_to_discovery(state: &AppState, group_id: &str) {
    publish_group_card_to_discovery_inner(state, group_id, false).await;
}

/// Like `publish_group_card_to_discovery` but advances the D.3 state
/// commit chain first. Returns the newly-sealed commit on success.
async fn publish_group_card_with_reseal(
    state: &AppState,
    group_id: &str,
) -> Option<x0x::groups::GroupStateCommit> {
    let membership_lock = group_membership_lock(state, group_id).await;
    let _membership_guard = membership_lock.lock().await;
    publish_group_card_to_discovery_inner(state, group_id, true).await
}

async fn publish_group_card_to_discovery_inner(
    state: &AppState,
    group_id: &str,
    reseal: bool,
) -> Option<x0x::groups::GroupStateCommit> {
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let (signed_card, commit) = {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(group_id)?;
        // Reseal bumps the commit chain; non-reseal republishes the
        // currently-sealed state (idempotent refresh).
        let commit = if reseal {
            if info.withdrawn {
                tracing::warn!(group_id, "refusing to reseal withdrawn group");
                return None;
            }
            match info.seal_commit(signing_kp, now_ms) {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!(group_id, "seal_commit failed: {e}");
                    return None;
                }
            }
        } else {
            None
        };
        let mut card = info.to_group_card()?;
        if let Err(e) = card.sign(signing_kp) {
            tracing::warn!(group_id, "card sign failed: {e}");
            return None;
        }
        (card, commit)
    };

    if reseal {
        save_named_groups(state).await;
    }

    // Phase C.2 privacy guard. Hidden and ListedToContacts MUST NEVER reach
    // any public discovery surface — neither the legacy bridge topic nor the
    // tag/name/id shard fan-out. ListedToContacts uses only the contact-scoped
    // direct-message path below.
    if !x0x::groups::may_publish_to_public_shards(signed_card.policy_summary.discoverability) {
        if signed_card.policy_summary.discoverability
            == x0x::groups::GroupDiscoverability::ListedToContacts
        {
            // Contact-scoped pairwise delivery: push the signed card via
            // direct-message to each Trusted/Known contact. No public
            // topic is touched.
            publish_listed_to_contacts_card(state, signed_card.clone()).await;
        } else {
            tracing::debug!(
                group_id,
                discoverability = ?signed_card.policy_summary.discoverability,
                "C.2: skipping fan-out (Hidden — stays local)"
            );
        }
        return commit;
    }

    // Bridge-topic publish (kept for backward compat with older peers that
    // haven't migrated to shard subscriptions yet). Only PublicDirectory cards
    // are allowed onto this public topic.
    let event = NamedGroupMetadataEvent::GroupCardPublished {
        group_id: group_id.to_string(),
        card: signed_card.clone(),
    };
    match serde_json::to_vec(&event) {
        Ok(bytes) => match state
            .agent
            .publish(GLOBAL_GROUP_DISCOVERY_TOPIC, bytes)
            .await
        {
            Ok(()) => {
                tracing::info!(
                    group_id,
                    topic = GLOBAL_GROUP_DISCOVERY_TOPIC,
                    reseal,
                    "D.3: published signed card to global discovery topic"
                );
            }
            Err(e) => {
                tracing::warn!(
                    topic = GLOBAL_GROUP_DISCOVERY_TOPIC,
                    "failed to publish card: {e}"
                );
            }
        },
        Err(e) => tracing::debug!("failed to serialize discovery card: {e}"),
    }

    let shards =
        x0x::groups::shards_for_public(&signed_card.tags, &signed_card.name, &signed_card.group_id);
    {
        let mut cache = state.directory_cache.write().await;
        for (kind, shard, _) in &shards {
            let _ = cache.insert(*kind, *shard, signed_card.clone());
        }
    }
    for (kind, shard, key) in shards {
        let topic = x0x::groups::topic_for(kind, shard);
        let msg = x0x::groups::DirectoryMessage::Card {
            card: Box::new(signed_card.clone()),
        };
        match state.agent.publish(&topic, msg.encode()).await {
            Ok(()) => tracing::info!(
                group_id = %signed_card.group_id,
                topic = %topic,
                %key,
                "C.2: published signed card to shard"
            ),
            Err(e) => tracing::warn!(
                topic = %LogHexId::topic(&topic),
                "C.2: shard publish failed: {e}"
            ),
        }
    }

    commit
}

/// Subscribe to the global discovery topic and insert incoming cards into the cache.
/// Listener lives for the daemon's lifetime.
pub(in crate::server) async fn spawn_global_discovery_listener(
    state: Arc<AppState>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut sub = match state.agent.subscribe(GLOBAL_GROUP_DISCOVERY_TOPIC).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("failed to subscribe to discovery topic: {e}");
            return Vec::new();
        }
    };
    tracing::info!(
        topic = GLOBAL_GROUP_DISCOVERY_TOPIC,
        "P0-1: global group discovery listener subscribed"
    );
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    vec![tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                maybe_msg = sub.recv() => {
                    let Some(msg) = maybe_msg else { break; };
                    tracing::info!(
                        topic = GLOBAL_GROUP_DISCOVERY_TOPIC,
                        "P0-1: received discovery gossip msg ({} bytes)",
                        msg.payload.len()
                    );
                    let Ok(event) = serde_json::from_slice::<NamedGroupMetadataEvent>(&msg.payload) else { continue; };
                    if let NamedGroupMetadataEvent::GroupCardPublished { card, .. } = event {
                        // Phase D.3: verify authority signature on signed
                        // cards. Unsigned cards (pre-D.3 legacy peers) are
                        // accepted for backward compatibility; signed cards
                        // with a bad signature are dropped silently.
                        if !card.signature.is_empty() {
                            if let Err(e) = card.verify_signature() {
                                tracing::warn!(
                                    group_id = %card.group_id,
                                    "D.3: dropped card with invalid signature: {e}"
                                );
                                continue;
                            }
                        }

                        // Phase D.3: withdrawal supersession. A signed
                        // withdrawal card evicts any existing cache entry
                        // regardless of prior revision (it is, by
                        // construction, a higher revision than anything
                        // local since apply_commit enforced that at the
                        // authority).
                        if card.withdrawn {
                            let mut cache = state.group_card_cache.write().await;
                            prune_expired_group_cards(&mut cache, now_millis_u64());
                            if remove_group_card_if_not_stale(&mut cache, &card) {
                                tracing::info!(
                                    group_id = %card.group_id,
                                    revision = card.revision,
                                    "D.3: withdrawal card superseded prior listing"
                                );
                            }
                            continue;
                        }

                        let local_group_withdrawn = {
                            let groups = state.named_groups.read().await;
                            has_withdrawn_group_record(&groups, &card.group_id)
                        };
                        if local_group_withdrawn {
                            tracing::debug!(
                                group_id = %card.group_id,
                                "D.3: dropped stale non-withdrawn card for withdrawn group"
                            );
                            continue;
                        }

                        // Only accept cards that are allowed on a public
                        // discovery surface. Hidden and ListedToContacts must
                        // never be cached from the global discovery topic.
                        if !x0x::groups::may_publish_to_public_shards(
                            card.policy_summary.discoverability,
                        ) {
                            continue;
                        }

                        // Phase D.3: higher revision supersedes lower
                        // immediately (independent of TTL). On ties, higher
                        // issued_at wins.
                        let mut cache = state.group_card_cache.write().await;
                        prune_expired_group_cards(&mut cache, now_millis_u64());
                        let should_insert = cache_group_card_if_newer(
                            &mut cache,
                            card.group_id.clone(),
                            card.clone(),
                        );
                        if should_insert {
                            tracing::info!(
                                group_id = %card.group_id,
                                name = %card.name,
                                revision = card.revision,
                                "D.3: caching discovered group card (signed={})",
                                !card.signature.is_empty()
                            );
                            enforce_group_card_cache_cap(&mut cache);
                        } else {
                            tracing::debug!(
                                group_id = %card.group_id,
                                revision = card.revision,
                                "D.3: dropped stale card (already have higher rev)"
                            );
                        }
                    }
                }
            }
        }
    })]
}

// ────────────────────────── Phase C.2: shard subscriptions ──────────────

/// Staggered-resubscribe jitter window, in milliseconds. Startup resubscribe
/// picks a random delay in `[0, JITTER_MS)` per shard to avoid AE storms.
pub(in crate::server) const DIRECTORY_RESUBSCRIBE_JITTER_MS: u64 = 30_000;

/// Interval between proactive digest emissions per subscribed shard, in
/// seconds. Peers use these digests for AE reconciliation.
pub(in crate::server) const DIRECTORY_DIGEST_INTERVAL_SECS: u64 = 60;

/// Load persisted directory subscriptions from disk (best-effort).
async fn load_directory_subscriptions(state: &AppState) {
    let path = &state.directory_subscriptions_path;
    match tokio::fs::read(path).await {
        Ok(bytes) => match serde_json::from_slice::<x0x::groups::SubscriptionSet>(&bytes) {
            Ok(set) => {
                let n = set.len();
                *state.directory_subscriptions.write().await = set;
                tracing::info!(
                    "C.2: loaded {n} persisted directory subscriptions from {}",
                    path.display()
                );
            }
            Err(e) => tracing::warn!(
                "C.2: failed to parse directory subscriptions file {}: {e}",
                path.display()
            ),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(
                "C.2: no persisted directory subscriptions at {}",
                path.display()
            );
        }
        Err(e) => tracing::warn!(
            "C.2: failed to read directory subscriptions file {}: {e}",
            path.display()
        ),
    }
}

/// Save the current subscription set to disk.
async fn save_directory_subscriptions(state: &AppState) {
    let set = state.directory_subscriptions.read().await.clone();
    let path = state.directory_subscriptions_path.clone();
    match serde_json::to_vec_pretty(&set) {
        Ok(bytes) => {
            if let Some(parent) = path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            if let Err(e) = tokio::fs::write(&path, &bytes).await {
                tracing::warn!(
                    "C.2: failed to persist directory subscriptions to {}: {e}",
                    path.display()
                );
            }
        }
        Err(e) => tracing::warn!("C.2: failed to serialise directory subscriptions: {e}"),
    }
}

/// Subscribe to a single shard topic and spawn a listener. Idempotent:
/// re-subscribing to an already-active shard is a no-op. Does not persist
/// on its own — callers must call `save_directory_subscriptions` after
/// mutating the subscription set.
async fn subscribe_shard(state: Arc<AppState>, kind: x0x::groups::ShardKind, shard: u32) {
    {
        let tasks = state.directory_tasks.read().await;
        if tasks.contains_key(&(kind, shard)) {
            return;
        }
    }
    let topic = x0x::groups::topic_for(kind, shard);
    let mut sub = match state.agent.subscribe(&topic).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(topic = %LogHexId::topic(&topic), "C.2: failed to subscribe to shard: {e}");
            return;
        }
    };
    let state_for_listener = Arc::clone(&state);
    let topic_for_log = topic.clone();
    let digest_interval_secs = state.directory_digest_interval_secs.max(1);
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    let handle = tokio::spawn(async move {
        // Emit an initial digest on startup so peers can reciprocate.
        emit_shard_digest(&state_for_listener, kind, shard).await;
        let mut digest_ticker =
            tokio::time::interval(std::time::Duration::from_secs(digest_interval_secs));
        digest_ticker.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                _ = digest_ticker.tick() => {
                    emit_shard_digest(&state_for_listener, kind, shard).await;
                }
                maybe_msg = sub.recv() => {
                    let Some(msg) = maybe_msg else { break; };
                    handle_directory_message(&state_for_listener, kind, shard, &msg.payload).await;
                }
            }
        }
        tracing::info!(topic = %topic_for_log, "C.2: shard listener shut down");
    });
    state
        .directory_tasks
        .write()
        .await
        .insert((kind, shard), handle);
    tracing::info!(topic = %topic, "C.2: subscribed to directory shard");
}

/// Unsubscribe from a shard (abort the listener task).
async fn unsubscribe_shard(state: &AppState, kind: x0x::groups::ShardKind, shard: u32) {
    if let Some(handle) = state.directory_tasks.write().await.remove(&(kind, shard)) {
        handle.abort();
        tracing::info!(
            kind = ?kind,
            shard,
            "C.2: unsubscribed from directory shard"
        );
    }
}

/// Publish a digest of our known entries in a shard (AE summary).
async fn emit_shard_digest(state: &AppState, kind: x0x::groups::ShardKind, shard: u32) {
    let entries = state.directory_cache.read().await.shard_digest(kind, shard);
    if entries.is_empty() {
        return; // nothing to advertise yet
    }
    let msg = x0x::groups::DirectoryMessage::Digest {
        shard,
        kind,
        entries,
    };
    let topic = x0x::groups::topic_for(kind, shard);
    if let Err(e) = state.agent.publish(&topic, msg.encode()).await {
        tracing::debug!(topic = %topic, "C.2: digest publish failed: {e}");
    }
}

/// Re-publish our own signed cards for groups listed in a Pull request.
async fn respond_to_pull(
    state: &AppState,
    kind: x0x::groups::ShardKind,
    shard: u32,
    group_ids: &[String],
) {
    let signing_kp = state.agent.identity().agent_keypair();
    let topic = x0x::groups::topic_for(kind, shard);
    let groups = state.named_groups.read().await;
    for gid in group_ids {
        // We only re-publish cards for groups we *own* / manage locally,
        // not arbitrary cards from our cache (relays may re-publish cached
        // blobs but cannot re-sign them). Pull requests use stable `group_id`,
        // so resolve by either the local routing key or the D.3 stable id.
        let owned_info = groups.get(gid.as_str()).or_else(|| {
            groups
                .values()
                .find(|info| info.stable_group_id() == gid.as_str())
        });
        if let Some(info) = owned_info {
            if !x0x::groups::may_publish_to_public_shards(info.policy.discoverability) {
                continue;
            }
            if let Ok(Some(card)) = info.to_signed_group_card(signing_kp) {
                let msg = x0x::groups::DirectoryMessage::Card {
                    card: Box::new(card),
                };
                let _ = state.agent.publish(&topic, msg.encode()).await;
                continue;
            }
        }
        // Fall back to re-broadcasting a cached card verbatim if we have one
        // (relay-forward semantics).
        if let Some(cached) = state.directory_cache.read().await.get(gid) {
            let msg = x0x::groups::DirectoryMessage::Card {
                card: Box::new(cached.clone()),
            };
            let _ = state.agent.publish(&topic, msg.encode()).await;
        }
    }
}

/// Handle one message arriving on a shard topic: Card / Digest / Pull.
async fn handle_directory_message(
    state: &AppState,
    kind: x0x::groups::ShardKind,
    shard: u32,
    payload: &[u8],
) {
    let msg = match x0x::groups::DirectoryMessage::decode(payload) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(shard, ?kind, "C.2: dropped malformed directory msg: {e}");
            return;
        }
    };
    match msg {
        x0x::groups::DirectoryMessage::Card { card } => {
            // Require a signature on shard-delivered cards. Unsigned cards on
            // a directory shard are treated as malformed (directory plane is
            // authority-signed by construction) and dropped.
            if card.signature.is_empty() {
                tracing::debug!(
                    group_id = %card.group_id,
                    "C.2: dropped unsigned card on shard topic"
                );
                return;
            }
            if let Err(e) = card.verify_signature() {
                tracing::warn!(
                    group_id = %card.group_id,
                    "C.2: dropped card with invalid signature: {e}"
                );
                return;
            }
            // Defensive privacy guard: a Hidden or ListedToContacts card must
            // never appear on a public shard topic. Drop if seen.
            if !x0x::groups::may_publish_to_public_shards(card.policy_summary.discoverability) {
                tracing::warn!(
                    group_id = %card.group_id,
                    discoverability = ?card.policy_summary.discoverability,
                    "C.2: dropped privacy-restricted card that leaked to public shard"
                );
                return;
            }
            let local_group_withdrawn = {
                let groups = state.named_groups.read().await;
                has_withdrawn_group_record(&groups, &card.group_id)
            };
            if !card.withdrawn && local_group_withdrawn {
                tracing::debug!(
                    group_id = %card.group_id,
                    "C.2: dropped stale non-withdrawn card for withdrawn group"
                );
                return;
            }
            let accepted = state
                .directory_cache
                .write()
                .await
                .insert(kind, shard, (*card).clone());
            if accepted {
                // Also update the legacy bridge cache so existing
                // /groups/discover responses continue to reflect shard
                // discoveries until D.4 deprecates that path.
                if card.withdrawn {
                    let mut cache = state.group_card_cache.write().await;
                    prune_expired_group_cards(&mut cache, now_millis_u64());
                    remove_group_card_if_not_stale(&mut cache, &card);
                } else if card.policy_summary.discoverability
                    != x0x::groups::GroupDiscoverability::Hidden
                {
                    let mut cache = state.group_card_cache.write().await;
                    prune_expired_group_cards(&mut cache, now_millis_u64());
                    if cache_group_card_if_newer(&mut cache, card.group_id.clone(), (*card).clone())
                    {
                        enforce_group_card_cache_cap(&mut cache);
                    }
                }
                tracing::info!(
                    group_id = %card.group_id,
                    kind = ?kind,
                    shard,
                    revision = card.revision,
                    "C.2: cached shard-delivered signed card"
                );
            }
        }
        x0x::groups::DirectoryMessage::Digest {
            shard: peer_shard,
            kind: peer_kind,
            entries,
        } => {
            if peer_shard != shard || peer_kind != kind {
                return;
            }
            let pulls = state
                .directory_cache
                .read()
                .await
                .pull_targets(kind, shard, &entries);
            if !pulls.is_empty() {
                let req = x0x::groups::DirectoryMessage::Pull {
                    shard,
                    kind,
                    group_ids: pulls,
                };
                let topic = x0x::groups::topic_for(kind, shard);
                let _ = state.agent.publish(&topic, req.encode()).await;
            }
        }
        x0x::groups::DirectoryMessage::Pull {
            shard: peer_shard,
            kind: peer_kind,
            group_ids,
        } => {
            if peer_shard != shard || peer_kind != kind {
                return;
            }
            respond_to_pull(state, kind, shard, &group_ids).await;
        }
    }
}

/// Spawn all persisted shard subscriptions at startup, with jitter so the
/// mesh doesn't storm on restart.
pub(in crate::server) async fn spawn_directory_resubscribe(
    state: Arc<AppState>,
) -> Vec<tokio::task::JoinHandle<()>> {
    load_directory_subscriptions(&state).await;
    let subs = state.directory_subscriptions.read().await.clone();
    if subs.is_empty() {
        return Vec::new();
    }
    use rand::Rng;
    let jitter_ms = state.directory_resubscribe_jitter_ms.max(1);
    let mut handles = Vec::new();
    for rec in subs.subscriptions {
        let delay_ms = {
            let mut rng = rand::thread_rng();
            rng.gen_range(0..jitter_ms)
        };
        let state_for_spawn = Arc::clone(&state);
        handles.push(tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            subscribe_shard(state_for_spawn, rec.kind, rec.shard).await;
        }));
    }
    handles
}

// ────────────────────── Phase C.2: ListedToContacts pairwise sync ───────

/// Wire-framing prefix for a ListedToContacts card delivered over the
/// direct-message channel. 16 bytes so receivers can do a single
/// constant-length prefix match. Payload after the prefix is the JSON
/// encoding of a signed [`x0x::groups::GroupCard`].
const LTC_CARD_FRAME_PREFIX: &[u8; 16] = b"X0X-LTC-CARD-V1\n";

/// Push a signed `ListedToContacts` `GroupCard` to each Trusted/Known
/// contact via direct-message. Skips contacts we have no record of, any
/// Blocked contacts, and the sender itself.
///
/// This is the privacy-correct distribution path for
/// `ListedToContacts` groups: no public topic is touched. Delivery is
/// O(N contacts), acceptable for the cardinality of this feature.
async fn publish_listed_to_contacts_card(state: &AppState, card: x0x::groups::GroupCard) {
    let contacts = state.contacts.read().await;
    let my_hex = hex::encode(state.agent.agent_id().as_bytes());
    let json = match serde_json::to_vec(&card) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(group_id = %card.group_id, "C.2/LTC: card serialize failed: {e}");
            return;
        }
    };
    let mut payload = Vec::with_capacity(LTC_CARD_FRAME_PREFIX.len() + json.len());
    payload.extend_from_slice(LTC_CARD_FRAME_PREFIX);
    payload.extend_from_slice(&json);

    // Enumerate Trusted + Known contacts. Blocked and Unknown are skipped.
    for contact in contacts.list() {
        if contact.trust_level == TrustLevel::Blocked || contact.trust_level == TrustLevel::Unknown
        {
            continue;
        }
        let hex_id = hex::encode(contact.agent_id.as_bytes());
        if hex_id == my_hex {
            continue;
        }
        match state
            .agent
            .send_direct_with_config(
                &contact.agent_id,
                payload.clone(),
                direct_message_send_config(),
            )
            .await
        {
            Ok(receipt) => tracing::info!(
                group_id = %card.group_id,
                recipient = %hex_id,
                trust = ?contact.trust_level,
                path = ?receipt.path,
                retries = receipt.retries_used,
                "C.2/LTC: delivered signed card to contact"
            ),
            Err(e) => tracing::debug!(
                group_id = %card.group_id,
                recipient = %hex_id,
                "C.2/LTC: contact delivery failed: {e}"
            ),
        }
    }
}

/// Background listener that consumes inbound direct messages and, when it
/// sees an LTC-framed envelope, verifies the card signature and caches it
/// in `group_card_cache` (never on public shards).
pub(in crate::server) async fn spawn_listed_to_contacts_listener(
    state: Arc<AppState>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut direct_rx = state.agent.subscribe_direct();
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    vec![tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                maybe = direct_rx.recv() => {
                    let Some(msg) = maybe else { break; };
                    if msg.payload.len() < LTC_CARD_FRAME_PREFIX.len() {
                        continue;
                    }
                    if &msg.payload[..LTC_CARD_FRAME_PREFIX.len()] != LTC_CARD_FRAME_PREFIX {
                        continue;
                    }
                    let json = &msg.payload[LTC_CARD_FRAME_PREFIX.len()..];
                    let card: x0x::groups::GroupCard = match serde_json::from_slice(json) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::debug!("C.2/LTC: malformed card JSON: {e}");
                            continue;
                        }
                    };
                    // Require a signature; unsigned LTC cards are dropped.
                    if card.signature.is_empty() {
                        continue;
                    }
                    if let Err(e) = card.verify_signature() {
                        tracing::warn!(
                            group_id = %card.group_id,
                            "C.2/LTC: dropped card with invalid signature: {e}"
                        );
                        continue;
                    }
                    // Defensive privacy guard: even via LTC delivery, a
                    // card whose discoverability is not ListedToContacts
                    // should not be cached as if it were. Accept only
                    // ListedToContacts cards on this path.
                    if card.policy_summary.discoverability
                        != x0x::groups::GroupDiscoverability::ListedToContacts
                    {
                        tracing::warn!(
                            group_id = %card.group_id,
                            "C.2/LTC: dropped non-LTC card on contact channel"
                        );
                        continue;
                    }
                    if card.withdrawn {
                        let mut cache = state.group_card_cache.write().await;
                        prune_expired_group_cards(&mut cache, now_millis_u64());
                        if remove_group_card_if_not_stale(&mut cache, &card) {
                            tracing::info!(
                                group_id = %card.group_id,
                                "C.2/LTC: evicted withdrawn card from contact cache"
                            );
                        }
                        continue;
                    }
                    let local_group_withdrawn = {
                        let groups = state.named_groups.read().await;
                        has_withdrawn_group_record(&groups, &card.group_id)
                    };
                    if local_group_withdrawn {
                        tracing::debug!(
                            group_id = %card.group_id,
                            "C.2/LTC: dropped stale non-withdrawn card for withdrawn group"
                        );
                        continue;
                    }
                    let mut cache = state.group_card_cache.write().await;
                    prune_expired_group_cards(&mut cache, now_millis_u64());
                    let insert =
                        cache_group_card_if_newer(&mut cache, card.group_id.clone(), card.clone());
                    if insert {
                        tracing::info!(
                            group_id = %card.group_id,
                            sender = %hex::encode(msg.sender.as_bytes()),
                            revision = card.revision,
                            "C.2/LTC: cached ListedToContacts card from contact"
                        );
                        enforce_group_card_cache_cap(&mut cache);
                    }
                }
            }
        }
    })]
}

/// Domain-separation tag for the `MemberJoined` metadata event signature.
///
/// Bumping this string is a protocol break — receivers verify against the
/// exact byte sequence below.
const MEMBER_JOINED_DOMAIN: &[u8] = b"x0x.named_group.member_joined.v2";

/// Build the canonical bytes signed by the joiner for a `MemberJoined`
/// metadata event.
///
/// Layout (all length-prefixed string fields use a u32 big-endian length
/// followed by the raw bytes; primitives use big-endian):
///
/// ```text
/// MEMBER_JOINED_DOMAIN
/// u32 len + group_id
/// u32 len + stable_group_id (empty string if None)
/// u32 len + member_agent_id
/// u32 len + member_public_key_b64
/// u8 role.as_u8()
/// u32 len + display_name (empty string if None)
/// u32 len + inviter_agent_id
/// u32 len + invite_secret
/// u64 BE  ts_ms
/// u32 len + treekem_key_package_b64 (empty string if None)
/// ```
#[allow(clippy::too_many_arguments)]
fn canonical_member_joined_bytes(
    group_id: &str,
    stable_group_id: Option<&str>,
    member_agent_id: &str,
    member_public_key_b64: &str,
    role: x0x::groups::GroupRole,
    display_name: Option<&str>,
    inviter_agent_id: &str,
    invite_secret: &str,
    ts_ms: u64,
    treekem_key_package_b64: Option<&str>,
) -> Vec<u8> {
    fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }
    let mut buf = Vec::with_capacity(MEMBER_JOINED_DOMAIN.len() + 256);
    buf.extend_from_slice(MEMBER_JOINED_DOMAIN);
    push_lp(&mut buf, group_id.as_bytes());
    push_lp(&mut buf, stable_group_id.unwrap_or("").as_bytes());
    push_lp(&mut buf, member_agent_id.as_bytes());
    push_lp(&mut buf, member_public_key_b64.as_bytes());
    buf.push(role.as_u8());
    push_lp(&mut buf, display_name.unwrap_or("").as_bytes());
    push_lp(&mut buf, inviter_agent_id.as_bytes());
    push_lp(&mut buf, invite_secret.as_bytes());
    buf.extend_from_slice(&ts_ms.to_be_bytes());
    push_lp(&mut buf, treekem_key_package_b64.unwrap_or("").as_bytes());
    buf
}

async fn publish_named_group_metadata_event(
    state: &AppState,
    metadata_topic: &str,
    event: &NamedGroupMetadataEvent,
) {
    #[cfg(test)]
    if let Ok(mut attempts) = NAMED_GROUP_METADATA_PUBLISH_ATTEMPTS_FOR_TEST.lock() {
        attempts.push((
            metadata_topic.to_string(),
            named_group_metadata_event_group_id(event).to_string(),
        ));
    }

    match serde_json::to_vec(event) {
        Ok(bytes) => {
            match tokio::time::timeout(
                NAMED_GROUP_METADATA_PUBLISH_TIMEOUT,
                state.agent.publish(metadata_topic, bytes),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!(topic = %LogHexId::topic(&metadata_topic), "failed to publish named-group metadata event: {e}");
                }
                Err(_) => {
                    tracing::warn!(
                        topic = %LogHexId::topic(&metadata_topic),
                        timeout_ms = NAMED_GROUP_METADATA_PUBLISH_TIMEOUT.as_millis() as u64,
                        "timed out publishing named-group metadata event"
                    );
                }
            }
        }
        Err(e) => tracing::warn!("failed to serialize named-group metadata event: {e}"),
    }
}

/// Schedule best-effort delivery of a named-group metadata event directly to a
/// single recipient over the authenticated direct-message channel, in addition
/// to the metadata-topic gossip publish.
///
/// Review decisions (approve / reject) target a requester who has only just
/// imported the group card and is not yet grafted into the authority's
/// PlumTree eager-push mesh for the metadata topic. Gossip cannot backfill a
/// message published before the receiver is in the eager set, so the
/// authority-authored, chain-linked commit can fail to reach the one peer that
/// must converge. The direct path closes that gap. The receiver applies the
/// event through the same [`apply_named_group_metadata_event`] path used for
/// gossip, which re-validates the signed commit, enforces the same
/// authorization, and is idempotent — so this is an additive delivery channel
/// that neither weakens authorization nor risks a double apply.
///
/// Direct delivery is intentionally spawned in the background: failures are
/// logged by the task and must not block metadata application, follow-up
/// side-effects, or HTTP responses.
pub(in crate::server) fn spawn_named_group_event_delivery(
    state: &AppState,
    recipient_hex: &str,
    event: &NamedGroupMetadataEvent,
) {
    let recipient = match parse_agent_id_hex(recipient_hex) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(
                requester = %LogHexId::agent(&recipient_hex),
                "cannot direct-deliver named-group event: invalid requester id: {e}"
            );
            return;
        }
    };
    let payload = match serde_json::to_vec(event) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!("failed to serialize named-group event for direct delivery: {e}");
            return;
        }
    };
    let agent = Arc::clone(&state.agent);
    let requester = recipient_hex.to_string();
    tokio::spawn(async move {
        if let Err(e) = agent
            .send_direct_with_config(&recipient, payload, named_group_direct_delivery_config())
            .await
        {
            tracing::warn!(
                requester = %LogHexId::agent(&requester),
                "failed to direct-deliver named-group review event: {e}"
            );
        }
    });
}

fn spawn_named_group_event_delivery_after(
    state: &AppState,
    recipient_hex: &str,
    event: &NamedGroupMetadataEvent,
    delay: Duration,
) {
    let recipient = match parse_agent_id_hex(recipient_hex) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(
                requester = %LogHexId::agent(&recipient_hex),
                "cannot delayed-direct-deliver named-group event: invalid requester id: {e}"
            );
            return;
        }
    };
    let payload = match serde_json::to_vec(event) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                "failed to serialize named-group event for delayed direct delivery: {e}"
            );
            return;
        }
    };
    let agent = Arc::clone(&state.agent);
    let requester = recipient_hex.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        if let Err(e) = agent
            .send_direct_with_config(&recipient, payload, named_group_direct_delivery_config())
            .await
        {
            tracing::warn!(
                requester = %LogHexId::agent(&requester),
                "failed to delayed-direct-deliver named-group event: {e}"
            );
        }
    });
}

fn spawn_named_group_event_delivery_to_active_members(
    state: &AppState,
    info: &x0x::groups::GroupInfo,
    event: &NamedGroupMetadataEvent,
    extra_recipients: &[String],
) {
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let mut recipients = HashSet::new();
    for member in info.active_members() {
        if !member.agent_id.eq_ignore_ascii_case(&local_agent_hex) {
            recipients.insert(member.agent_id.clone());
        }
    }
    for recipient in extra_recipients {
        if !recipient.eq_ignore_ascii_case(&local_agent_hex) {
            recipients.insert(recipient.clone());
        }
    }
    for recipient in recipients {
        spawn_named_group_event_delivery(state, &recipient, event);
        spawn_named_group_event_delivery_after(
            state,
            &recipient,
            event,
            GROUP_BACKGROUND_PUBLISH_DELAY,
        );
    }
}

async fn stop_named_group_metadata_listener(state: &AppState, group_id: &str) {
    let handle = state.group_metadata_tasks.write().await.remove(group_id);
    if let Some(handle) = handle {
        handle.abort();
    }
}

fn apply_stateful_event_to_group<F>(
    current: &x0x::groups::GroupInfo,
    commit: &x0x::groups::GroupStateCommit,
    action_kind: x0x::groups::ActionKind,
    mutate: F,
) -> Result<x0x::groups::GroupInfo, x0x::groups::ApplyError>
where
    F: FnOnce(&mut x0x::groups::GroupInfo),
{
    let ctx = x0x::groups::ApplyContext {
        current_state_hash: &current.state_hash,
        current_revision: current.state_revision,
        current_withdrawn: current.withdrawn,
        members_v2: &current.members_v2,
        group_id: current.stable_group_id(),
    };
    x0x::groups::state_commit::validate_apply(&ctx, commit, action_kind)?;
    let mut next = current.clone();
    mutate(&mut next);
    next.finalize_applied_commit(commit)?;
    Ok(next)
}

fn apply_terminal_stateful_event_to_group<F>(
    current: &x0x::groups::GroupInfo,
    commit: &x0x::groups::GroupStateCommit,
    action_kind: x0x::groups::ActionKind,
    mutate: F,
) -> Result<x0x::groups::GroupInfo, x0x::groups::ApplyError>
where
    F: FnOnce(&mut x0x::groups::GroupInfo),
{
    let ctx = x0x::groups::ApplyContext {
        current_state_hash: &current.state_hash,
        current_revision: current.state_revision,
        current_withdrawn: current.withdrawn,
        members_v2: &current.members_v2,
        group_id: current.stable_group_id(),
    };
    x0x::groups::state_commit::validate_apply_terminal(&ctx, commit, action_kind)?;
    let mut next = current.clone();
    mutate(&mut next);
    next.finalize_applied_terminal_commit(commit)?;
    Ok(next)
}

async fn refresh_group_card_cache_from_info(
    state: &AppState,
    key: &str,
    info: &x0x::groups::GroupInfo,
) {
    let mut cache = state.group_card_cache.write().await;
    let now_ms = now_millis_u64();
    prune_expired_group_cards(&mut cache, now_ms);
    let stable_key = info.stable_group_id().to_string();
    match info.to_signed_group_card(state.agent.identity().agent_keypair()) {
        Ok(Some(card)) => {
            cache_group_card_if_newer(&mut cache, key.to_string(), card.clone());
            cache_group_card_if_newer(&mut cache, stable_key, card);
            enforce_group_card_cache_cap(&mut cache);
        }
        Ok(None) => {
            cache.remove(key);
            cache.remove(&stable_key);
        }
        Err(e) => {
            tracing::warn!(group_key = %key, "failed to sign group card for cache refresh: {e}");
            cache.remove(key);
            cache.remove(&stable_key);
        }
    }
}

fn store_named_group_info_locked(
    groups: &mut HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
    info: x0x::groups::GroupInfo,
) -> bool {
    if !info.withdrawn
        && has_withdrawn_same_stable_group_record(groups, group_id, Some(info.stable_group_id()))
    {
        tracing::warn!(
            group_id = %LogHexId::group(group_id),
            stable_group_id = %LogHexId::group(info.stable_group_id()),
            "refusing to overwrite withdrawn named-group terminal record"
        );
        return false;
    }
    let Some(slot) = groups.get_mut(group_id) else {
        return false;
    };
    *slot = info;
    true
}

async fn store_named_group_info(
    state: &AppState,
    group_id: &str,
    info: x0x::groups::GroupInfo,
) -> bool {
    let mut groups = state.named_groups.write().await;
    store_named_group_info_locked(&mut groups, group_id, info)
}

fn restore_local_treekem_group_from_snapshot(
    state: &AppState,
    info: &x0x::groups::GroupInfo,
    snapshot: &[u8],
) -> anyhow::Result<x0x::mls::TreeKemMlsGroup> {
    let group_id_bytes = hex::decode(&info.mls_group_id)
        .map_err(|e| anyhow::anyhow!("invalid TreeKEM group id for rollback: {e}"))?;
    let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    x0x::mls::TreeKemMlsGroup::restore(snapshot, state.agent.agent_id(), &seed)
        .map_err(|e| anyhow::anyhow!("restore TreeKEM rollback snapshot: {e}"))
}

fn rollback_treekem_group_after_failed_install(
    state: &AppState,
    group_id: &str,
    info: &x0x::groups::GroupInfo,
    snapshot: &[u8],
    group: &mut x0x::mls::TreeKemMlsGroup,
    reason: &str,
) {
    match restore_local_treekem_group_from_snapshot(state, info, snapshot) {
        Ok(restored) => {
            *group = restored;
        }
        Err(e) => {
            tracing::error!(
                group_id = %LogHexId::group(group_id),
                reason,
                "failed to rollback TreeKEM group after rejected install: {e}"
            );
        }
    }
}

#[cfg(test)]
fn notify_treekem_final_install_before_map_write_for_test(group_id: &str) {
    let notify = TREEKEM_FINAL_INSTALL_BEFORE_MAP_WRITE_NOTIFY
        .lock()
        .ok()
        .and_then(|guard| {
            guard
                .as_ref()
                .filter(|(target_group_id, _)| target_group_id == group_id)
                .map(|(_, notify)| Arc::clone(notify))
        });
    if let Some(notify) = notify {
        notify.notify_waiters();
    }
}

async fn install_joined_treekem_group_after_crypto_recheck(
    state: &AppState,
    group_id: &str,
    info: x0x::groups::GroupInfo,
    group: x0x::mls::TreeKemMlsGroup,
    reason: &str,
) -> anyhow::Result<()> {
    let stable_group_id = info.stable_group_id().to_string();
    ensure_named_group_key_material_install_allowed(
        state,
        group_id,
        Some(&stable_group_id),
        reason,
    )
    .await?;
    persist_treekem_and_named_groups_atomic_with_info(state, group_id, info, &group).await?;
    ensure_named_group_key_material_install_allowed(
        state,
        group_id,
        Some(&stable_group_id),
        reason,
    )
    .await?;
    #[cfg(test)]
    notify_treekem_final_install_before_map_write_for_test(group_id);

    let mut treekem_groups = state.treekem_groups.write().await;
    let groups = state.named_groups.read().await;
    if has_withdrawn_same_stable_group_record(&groups, group_id, Some(&stable_group_id)) {
        drop(groups);
        drop(treekem_groups);
        if !repair_withdrawn_named_groups_json_and_wipe_key_material(
            state,
            group_id,
            Some(&stable_group_id),
            reason,
        )
        .await?
        {
            remove_treekem_persistence_for_group_id(state, group_id, reason).await;
        }
        anyhow::bail!("refusing to install key material for withdrawn group");
    }
    // Keep the named-groups read guard through the final insert. That removes
    // the post-check/pre-insert window: a withdrawal that already won is
    // observed above; a later withdrawal cannot acquire the named-groups write
    // lock until after this in-memory insert, then its teardown path removes the
    // key material.
    treekem_groups.insert(
        group_id.to_string(),
        Arc::new(tokio::sync::Mutex::new(group)),
    );
    Ok(())
}

async fn process_treekem_commit_after_crypto_recheck(
    state: &AppState,
    group_id: &str,
    info: &x0x::groups::GroupInfo,
    group: Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>,
    commit_bytes: &[u8],
    expected_epoch: u64,
    reason: &str,
) -> anyhow::Result<()> {
    let mut guard = group.lock().await;
    let rollback_snapshot = guard
        .to_snapshot_bytes()
        .map_err(|e| anyhow::anyhow!("snapshot TreeKEM group before commit: {e}"))?;
    if let Err(e) = guard.process_commit(commit_bytes) {
        rollback_treekem_group_after_failed_install(
            state,
            group_id,
            info,
            &rollback_snapshot,
            &mut guard,
            reason,
        );
        return Err(anyhow::anyhow!("process TreeKEM commit: {e}"));
    }
    if guard.epoch() != expected_epoch {
        let actual_epoch = guard.epoch();
        rollback_treekem_group_after_failed_install(
            state,
            group_id,
            info,
            &rollback_snapshot,
            &mut guard,
            reason,
        );
        anyhow::bail!(
            "TreeKEM commit advanced to unexpected epoch {actual_epoch}, expected {expected_epoch}"
        );
    }
    if let Err(e) =
        persist_treekem_and_named_groups_atomic_with_info(state, group_id, info.clone(), &guard)
            .await
    {
        rollback_treekem_group_after_failed_install(
            state,
            group_id,
            info,
            &rollback_snapshot,
            &mut guard,
            reason,
        );
        return Err(e);
    }
    Ok(())
}

async fn maybe_publish_group_card_after_state_change(state: &AppState, group_id: &str) {
    let info = {
        let groups = state.named_groups.read().await;
        groups.get(group_id).cloned()
    };
    if let Some(info) = info {
        refresh_group_card_cache_from_info(state, group_id, &info).await;
        let discoverable = info.withdrawn
            || info.policy.discoverability != x0x::groups::GroupDiscoverability::Hidden;
        if discoverable {
            publish_group_card_to_discovery(state, group_id).await;
        } else {
            let mut cache = state.group_card_cache.write().await;
            prune_expired_group_cards(&mut cache, now_millis_u64());
            cache.remove(group_id);
            cache.remove(info.stable_group_id());
        }
    } else {
        let mut cache = state.group_card_cache.write().await;
        prune_expired_group_cards(&mut cache, now_millis_u64());
        cache.remove(group_id);
    }
}

pub(in crate::server) struct TreeKemMembershipFrontier<'a> {
    group_id: &'a str,
    revision: u64,
    epoch: Option<u64>,
    commit: &'a x0x::groups::GroupStateCommit,
    actor: &'a str,
    target: &'a str,
}

fn treekem_membership_event_frontier(
    event: &NamedGroupMetadataEvent,
) -> Option<TreeKemMembershipFrontier<'_>> {
    match event {
        NamedGroupMetadataEvent::MemberAdded {
            group_id,
            revision,
            actor,
            agent_id,
            treekem_epoch,
            commit: Some(commit),
            ..
        }
        | NamedGroupMetadataEvent::MemberRemoved {
            group_id,
            revision,
            actor,
            agent_id,
            treekem_epoch,
            commit: Some(commit),
            ..
        }
        | NamedGroupMetadataEvent::MemberBanned {
            group_id,
            revision,
            actor,
            agent_id,
            treekem_epoch,
            commit: Some(commit),
            ..
        } => Some(TreeKemMembershipFrontier {
            group_id,
            revision: *revision,
            epoch: *treekem_epoch,
            commit,
            actor,
            target: agent_id,
        }),
        NamedGroupMetadataEvent::JoinRequestApproved {
            group_id,
            revision,
            actor,
            requester_agent_id,
            treekem_epoch,
            commit: Some(commit),
            ..
        } => Some(TreeKemMembershipFrontier {
            group_id,
            revision: *revision,
            epoch: *treekem_epoch,
            commit,
            actor,
            target: requester_agent_id,
        }),
        _ => None,
    }
}

fn treekem_membership_event_key(event: &NamedGroupMetadataEvent) -> Option<String> {
    let frontier = treekem_membership_event_frontier(event)?;
    let kind = match event {
        NamedGroupMetadataEvent::MemberAdded { .. } => "add",
        NamedGroupMetadataEvent::MemberRemoved { .. } => "remove",
        NamedGroupMetadataEvent::MemberBanned { .. } => "ban",
        NamedGroupMetadataEvent::JoinRequestApproved { .. } => "approve",
        _ => return None,
    };
    Some(format!(
        "{}:{kind}:{}:{}:{}:{}",
        frontier.group_id,
        frontier.revision,
        frontier.epoch.unwrap_or_default(),
        frontier.actor,
        frontier.target
    ))
}

fn treekem_membership_event_sort_key(event: &NamedGroupMetadataEvent) -> (u64, u64) {
    treekem_membership_event_frontier(event)
        .map(|frontier| (frontier.revision, frontier.epoch.unwrap_or_default()))
        .unwrap_or_default()
}

fn treekem_event_is_local_welcome(event: &NamedGroupMetadataEvent, local_agent_hex: &str) -> bool {
    match event {
        NamedGroupMetadataEvent::MemberAdded { agent_id, .. } => agent_id == local_agent_hex,
        NamedGroupMetadataEvent::JoinRequestApproved {
            requester_agent_id, ..
        } => requester_agent_id == local_agent_hex,
        _ => false,
    }
}

async fn current_treekem_epoch(state: &AppState, group_id: &str) -> Option<u64> {
    let group = state.treekem_groups.read().await.get(group_id).cloned();
    let group = group?;
    let epoch = group.lock().await.epoch();
    Some(epoch)
}

fn authorized_treekem_membership_event_for_queue(
    info: &x0x::groups::GroupInfo,
    event: &NamedGroupMetadataEvent,
    sender_hex: &str,
) -> bool {
    if info.withdrawn {
        return false;
    }
    match event {
        NamedGroupMetadataEvent::MemberAdded {
            actor,
            commit: Some(_),
            treekem_commit_b64: Some(_),
            treekem_epoch: Some(_),
            ..
        } => {
            actor == sender_hex
                && info
                    .caller_role(actor)
                    .is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin))
        }
        NamedGroupMetadataEvent::MemberRemoved {
            actor,
            agent_id,
            commit: Some(_),
            treekem_commit_b64,
            treekem_epoch,
            ..
        } => {
            let admin_remove = actor == sender_hex
                && info
                    .caller_role(actor)
                    .is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin))
                && treekem_commit_b64.is_some()
                && treekem_epoch.is_some();
            let self_leave = sender_hex == agent_id
                && actor == sender_hex
                && treekem_commit_b64.is_none()
                && treekem_epoch.is_none();
            admin_remove || self_leave
        }
        NamedGroupMetadataEvent::MemberBanned {
            actor,
            commit: Some(_),
            treekem_commit_b64: Some(_),
            treekem_epoch: Some(_),
            ..
        } => {
            actor == sender_hex
                && info
                    .caller_role(actor)
                    .is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin))
        }
        NamedGroupMetadataEvent::JoinRequestApproved {
            actor,
            requester_agent_id,
            request_id,
            commit: Some(_),
            treekem_commit_b64: Some(_),
            treekem_epoch: Some(_),
            ..
        } => {
            actor == sender_hex
                && info
                    .caller_role(actor)
                    .is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin))
                && info.join_requests.get(request_id).is_some_and(|req| {
                    req.is_pending() && req.requester_agent_id == *requester_agent_id
                })
        }
        _ => false,
    }
}

fn treekem_state_frontier_gap_reason(
    info: &x0x::groups::GroupInfo,
    event: &NamedGroupMetadataEvent,
    local_agent_hex: &str,
    local_epoch: Option<u64>,
) -> Option<String> {
    if info.withdrawn {
        return None;
    }
    if info.secure_plane != x0x::mls::SecureGroupPlane::TreeKem {
        return None;
    }
    let frontier = treekem_membership_event_frontier(event)?;
    let is_local_welcome = treekem_event_is_local_welcome(event, local_agent_hex);
    if frontier.commit.revision <= info.state_revision || frontier.revision <= info.roster_revision
    {
        return None;
    }
    if frontier.commit.revision > info.state_revision.saturating_add(1)
        || frontier.revision > info.roster_revision.saturating_add(1)
    {
        return Some("revision_gap".to_string());
    }
    if frontier.commit.prev_state_hash.as_deref() != Some(info.state_hash.as_str()) {
        return Some("state_hash_gap".to_string());
    }
    if let Some(epoch) = frontier.epoch {
        match local_epoch {
            Some(local_epoch) if !is_local_welcome && epoch > local_epoch.saturating_add(1) => {
                return Some("treekem_epoch_gap".to_string());
            }
            None if !is_local_welcome => return Some("treekem_not_ready".to_string()),
            _ => {}
        }
    }
    None
}

async fn should_queue_treekem_membership_event(
    state: &AppState,
    group_id: &str,
    info: &x0x::groups::GroupInfo,
    event: &NamedGroupMetadataEvent,
    local_agent_hex: &str,
) -> Option<String> {
    let local_epoch = current_treekem_epoch(state, group_id).await;
    treekem_state_frontier_gap_reason(info, event, local_agent_hex, local_epoch)
}

async fn remember_treekem_membership_event(state: &AppState, event: &NamedGroupMetadataEvent) {
    let Some(frontier) = treekem_membership_event_frontier(event) else {
        return;
    };
    {
        let groups = state.named_groups.read().await;
        if has_withdrawn_group_record(&groups, frontier.group_id) {
            return;
        }
    }
    let mut logs = state.treekem_event_log.write().await;
    let log = logs.entry(frontier.group_id.to_string()).or_default();
    if let Some(key) = treekem_membership_event_key(event) {
        if log
            .iter()
            .filter_map(treekem_membership_event_key)
            .any(|existing| existing == key)
        {
            return;
        }
    }
    log.push_back(event.clone());
    while log.len() > TREEKEM_EVENT_LOG_PER_GROUP_CAP {
        log.pop_front();
    }
}

/// Extract the member-keyed cache entry (`join_result_key`, event) from a
/// key-package-bearing `MemberJoined`. Returns `None` for non-`MemberJoined`
/// events or those without an embedded key package. Used by
/// [`apply_named_group_metadata_event`] to populate
/// [`AppState::treekem_member_key_packages`] on the inviter side (issue #205).
fn member_joined_kp_cache_entry(
    event: &NamedGroupMetadataEvent,
) -> Option<(String, NamedGroupMetadataEvent)> {
    if let NamedGroupMetadataEvent::MemberJoined {
        group_id,
        member_agent_id,
        treekem_key_package_b64: Some(_),
        ..
    } = event
    {
        Some((join_result_key(group_id, member_agent_id), event.clone()))
    } else {
        None
    }
}

fn member_joined_key_package_relevant_to_groups(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    event: &NamedGroupMetadataEvent,
) -> bool {
    let NamedGroupMetadataEvent::MemberJoined {
        group_id,
        recovery_authority_signature_b64,
        ..
    } = event
    else {
        return false;
    };
    let Some(info) = groups.get(group_id).or_else(|| {
        groups.values().find(|info| {
            info.stable_group_id() == group_id || info.mls_group_id.as_str() == group_id
        })
    }) else {
        return false;
    };
    if info.withdrawn {
        return false;
    }
    if recovery_authority_signature_b64.is_some() {
        verify_authority_attested_member_joined_recovery(info, event)
    } else {
        verify_member_joined_key_package_event(event)
    }
}

/// Verify that a key-package-bearing `MemberJoined` is self-authenticated by
/// the claimed member. This is intentionally independent of inviter and roster
/// state so persisted recovery records can be authenticated during startup.
fn verify_member_joined_key_package_event(event: &NamedGroupMetadataEvent) -> bool {
    use base64::Engine as _;

    let NamedGroupMetadataEvent::MemberJoined {
        group_id,
        stable_group_id,
        member_agent_id,
        member_public_key_b64,
        role,
        display_name,
        inviter_agent_id,
        invite_secret,
        ts_ms,
        treekem_key_package_b64: Some(treekem_key_package_b64),
        signature_b64,
        ..
    } = event
    else {
        return false;
    };
    let Ok(pubkey_bytes) = BASE64.decode(member_public_key_b64) else {
        return false;
    };
    let Ok(pubkey) = ant_quic::MlDsaPublicKey::from_bytes(&pubkey_bytes) else {
        return false;
    };
    let Ok(sig_bytes) = BASE64.decode(signature_b64) else {
        return false;
    };
    let Ok(sig) = ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&sig_bytes)
    else {
        return false;
    };
    let canonical = canonical_member_joined_bytes(
        group_id,
        stable_group_id.as_deref(),
        member_agent_id,
        member_public_key_b64,
        *role,
        display_name.as_deref(),
        inviter_agent_id,
        invite_secret,
        *ts_ms,
        Some(treekem_key_package_b64.as_str()),
    );
    ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(&pubkey, &canonical, &sig).is_ok()
        && hex::encode(ant_quic::derive_peer_id_from_public_key(&pubkey).0)
            .eq_ignore_ascii_case(member_agent_id)
}

const MEMBER_JOINED_RECOVERY_DOMAIN: &[u8] = b"x0x.named_group.member_joined.recovery.v1";

const MEMBER_JOINED_RECOVERY_BINDING_PREFIX: &str = "member-recovery=";

fn member_joined_recovery_record_hash(event: &NamedGroupMetadataEvent) -> Option<String> {
    let NamedGroupMetadataEvent::MemberJoined { signature_b64, .. } = event else {
        return None;
    };
    let member_bytes = canonical_member_joined_recovery_bytes_without_commit(event)?;
    let mut hasher = blake3::Hasher::new_derive_key("x0x MemberJoined recovery record v1");
    hasher.update(&(member_bytes.len() as u64).to_be_bytes());
    hasher.update(&member_bytes);
    hasher.update(&(signature_b64.len() as u64).to_be_bytes());
    hasher.update(signature_b64.as_bytes());
    Some(hasher.finalize().to_hex().to_string())
}

fn canonical_member_joined_recovery_bytes_without_commit(
    event: &NamedGroupMetadataEvent,
) -> Option<Vec<u8>> {
    let NamedGroupMetadataEvent::MemberJoined {
        group_id,
        stable_group_id,
        member_agent_id,
        member_public_key_b64,
        role,
        display_name,
        inviter_agent_id,
        invite_secret,
        ts_ms,
        treekem_key_package_b64: Some(treekem_key_package_b64),
        ..
    } = event
    else {
        return None;
    };
    Some(canonical_member_joined_bytes(
        group_id,
        stable_group_id.as_deref(),
        member_agent_id,
        member_public_key_b64,
        *role,
        display_name.as_deref(),
        inviter_agent_id,
        invite_secret,
        *ts_ms,
        Some(treekem_key_package_b64),
    ))
}

fn treekem_recovery_security_binding(
    epoch: u64,
    event: &NamedGroupMetadataEvent,
) -> Option<String> {
    let hash = member_joined_recovery_record_hash(event)?;
    Some(format!(
        "treekem:epoch={epoch};{MEMBER_JOINED_RECOVERY_BINDING_PREFIX}{hash}"
    ))
}

fn canonical_member_joined_recovery_bytes(
    event: &NamedGroupMetadataEvent,
    authority_agent_id: &str,
    authority_commit: &x0x::groups::GroupStateCommit,
) -> Option<Vec<u8>> {
    let NamedGroupMetadataEvent::MemberJoined {
        group_id,
        stable_group_id,
        member_agent_id,
        member_public_key_b64,
        role,
        display_name,
        inviter_agent_id,
        invite_secret,
        ts_ms,
        treekem_key_package_b64: Some(treekem_key_package_b64),
        signature_b64,
        ..
    } = event
    else {
        return None;
    };
    let member_bytes = canonical_member_joined_bytes(
        group_id,
        stable_group_id.as_deref(),
        member_agent_id,
        member_public_key_b64,
        *role,
        display_name.as_deref(),
        inviter_agent_id,
        invite_secret,
        *ts_ms,
        Some(treekem_key_package_b64),
    );
    let commit_bytes = serde_json::to_vec(authority_commit).ok()?;
    let mut bytes = Vec::with_capacity(
        MEMBER_JOINED_RECOVERY_DOMAIN.len() + member_bytes.len() + commit_bytes.len() + 128,
    );
    bytes.extend_from_slice(MEMBER_JOINED_RECOVERY_DOMAIN);
    for value in [
        member_bytes.as_slice(),
        signature_b64.as_bytes(),
        authority_agent_id.as_bytes(),
        commit_bytes.as_slice(),
    ] {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    Some(bytes)
}

fn attest_member_joined_recovery_event(
    event: &NamedGroupMetadataEvent,
    authority: &x0x::identity::AgentKeypair,
    authority_commit: &x0x::groups::GroupStateCommit,
) -> anyhow::Result<NamedGroupMetadataEvent> {
    use base64::Engine as _;

    let authority_agent_id = hex::encode(authority.agent_id().as_bytes());
    let canonical =
        canonical_member_joined_recovery_bytes(event, &authority_agent_id, authority_commit)
            .ok_or_else(|| {
                anyhow::anyhow!("MemberJoined recovery event is missing a KeyPackage")
            })?;
    let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        authority.secret_key(),
        &canonical,
    )
    .map_err(|e| anyhow::anyhow!("sign MemberJoined recovery attestation: {e:?}"))?;
    let mut attested = event.clone();
    let NamedGroupMetadataEvent::MemberJoined {
        recovery_authority_agent_id,
        recovery_authority_public_key_b64,
        recovery_authority_signature_b64,
        recovery_authority_commit,
        ..
    } = &mut attested
    else {
        return Err(anyhow::anyhow!(
            "recovery attestation requires MemberJoined"
        ));
    };
    *recovery_authority_agent_id = Some(authority_agent_id);
    *recovery_authority_public_key_b64 = Some(BASE64.encode(authority.public_key().as_bytes()));
    *recovery_authority_signature_b64 = Some(BASE64.encode(signature.as_bytes()));
    *recovery_authority_commit = Some(authority_commit.clone());
    Ok(attested)
}

fn verify_recovery_attestation_structure(event: &NamedGroupMetadataEvent) -> bool {
    use base64::Engine as _;

    let NamedGroupMetadataEvent::MemberJoined {
        group_id,
        stable_group_id,
        inviter_agent_id,
        recovery_authority_agent_id: Some(authority_agent_id),
        recovery_authority_public_key_b64: Some(authority_public_key_b64),
        recovery_authority_signature_b64: Some(authority_signature_b64),
        recovery_authority_commit: Some(authority_commit),
        ..
    } = event
    else {
        return false;
    };
    let Some(recovery_hash) = member_joined_recovery_record_hash(event) else {
        return false;
    };
    let expected_binding = format!("{MEMBER_JOINED_RECOVERY_BINDING_PREFIX}{recovery_hash}");
    if !authority_agent_id.eq_ignore_ascii_case(inviter_agent_id)
        || authority_commit.verify_structure().is_err()
        || !authority_commit
            .committed_by
            .eq_ignore_ascii_case(authority_agent_id)
        || !authority_commit
            .security_binding
            .as_deref()
            .is_some_and(|binding| binding.split(';').any(|part| part == expected_binding))
        || !(authority_commit.group_id == *group_id
            || stable_group_id.as_deref() == Some(authority_commit.group_id.as_str()))
    {
        return false;
    }
    let Ok(public_key_bytes) = BASE64.decode(authority_public_key_b64) else {
        return false;
    };
    let Ok(public_key) = ant_quic::MlDsaPublicKey::from_bytes(&public_key_bytes) else {
        return false;
    };
    if !hex::encode(ant_quic::derive_peer_id_from_public_key(&public_key).0)
        .eq_ignore_ascii_case(authority_agent_id)
    {
        return false;
    }
    let Ok(signature_bytes) = BASE64.decode(authority_signature_b64) else {
        return false;
    };
    let Ok(signature) =
        ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&signature_bytes)
    else {
        return false;
    };
    let Some(canonical) =
        canonical_member_joined_recovery_bytes(event, authority_agent_id, authority_commit)
    else {
        return false;
    };
    ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(&public_key, &canonical, &signature)
        .is_ok()
}

fn verify_authority_attested_member_joined_recovery(
    info: &x0x::groups::GroupInfo,
    event: &NamedGroupMetadataEvent,
) -> bool {
    use base64::Engine as _;

    let NamedGroupMetadataEvent::MemberJoined {
        group_id,
        stable_group_id,
        member_agent_id,
        role,
        inviter_agent_id,
        treekem_key_package_b64: Some(treekem_key_package_b64),
        recovery_authority_agent_id: Some(authority_agent_id),
        recovery_authority_public_key_b64: Some(authority_public_key_b64),
        recovery_authority_signature_b64: Some(authority_signature_b64),
        recovery_authority_commit: Some(authority_commit),
        ..
    } = event
    else {
        return false;
    };
    let Some(recovery_hash) = member_joined_recovery_record_hash(event) else {
        return false;
    };
    let expected_binding = format!("{MEMBER_JOINED_RECOVERY_BINDING_PREFIX}{recovery_hash}");
    let member_authenticated = verify_member_joined_key_package_event(event);
    let authority_only_attestation = matches!(
        event,
        NamedGroupMetadataEvent::MemberJoined {
            member_public_key_b64,
            signature_b64,
            ..
        } if member_public_key_b64.is_empty() && signature_b64.is_empty()
    );
    let package_hash = blake3::hash(treekem_key_package_b64.as_bytes())
        .to_hex()
        .to_string();
    let package_matches_current_incarnation = info
        .members_v2
        .get(member_agent_id)
        .and_then(|member| member.treekem_key_package_hash.as_deref())
        == Some(package_hash.as_str());
    let creator_authority = role.at_least(x0x::groups::GroupRole::Admin)
        && member_agent_id.eq_ignore_ascii_case(authority_agent_id)
        && info.genesis.as_ref().is_some_and(|genesis| {
            genesis
                .creator_agent_id
                .eq_ignore_ascii_case(member_agent_id)
        })
        && info
            .members_v2
            .get(member_agent_id)
            .is_some_and(|member| member.added_by.is_none());
    let invited_member_authority = *role == x0x::groups::GroupRole::Member
        && info
            .members_v2
            .get(member_agent_id)
            .and_then(|member| member.added_by.as_deref())
            == Some(authority_agent_id.as_str());
    let authority_commit_is_accepted = info
        .commit_log
        .iter()
        .any(|retained| retained.commit == *authority_commit);
    if (!creator_authority && !invited_member_authority)
        || (!member_authenticated && !authority_only_attestation)
        || !package_matches_current_incarnation
        || !authority_agent_id.eq_ignore_ascii_case(inviter_agent_id)
        || authority_commit.verify_structure().is_err()
        || !authority_commit
            .committed_by
            .eq_ignore_ascii_case(authority_agent_id)
        || !authority_commit
            .security_binding
            .as_deref()
            .is_some_and(|binding| binding.split(';').any(|part| part == expected_binding))
        || authority_commit.group_id != info.stable_group_id()
        || !(group_id == &info.mls_group_id
            || group_id == info.stable_group_id()
            || stable_group_id.as_deref() == Some(info.stable_group_id()))
        || !authority_commit_is_accepted
        || !info.has_active_member(member_agent_id)
    {
        return false;
    }
    let Ok(public_key_bytes) = BASE64.decode(authority_public_key_b64) else {
        return false;
    };
    let Ok(public_key) = ant_quic::MlDsaPublicKey::from_bytes(&public_key_bytes) else {
        return false;
    };
    if !hex::encode(ant_quic::derive_peer_id_from_public_key(&public_key).0)
        .eq_ignore_ascii_case(authority_agent_id)
    {
        return false;
    }
    let Ok(signature_bytes) = BASE64.decode(authority_signature_b64) else {
        return false;
    };
    let Ok(signature) =
        ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&signature_bytes)
    else {
        return false;
    };
    let Some(canonical) =
        canonical_member_joined_recovery_bytes(event, authority_agent_id, authority_commit)
    else {
        return false;
    };
    ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(&public_key, &canonical, &signature)
        .is_ok()
}

fn recovery_cache_group_identity(event: &NamedGroupMetadataEvent) -> &str {
    match event {
        NamedGroupMetadataEvent::MemberJoined {
            group_id,
            stable_group_id,
            ..
        } => stable_group_id.as_deref().unwrap_or(group_id),
        _ => named_group_metadata_event_group_id(event),
    }
}

fn canonical_recovery_cache_group_id(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    event: &NamedGroupMetadataEvent,
) -> String {
    let NamedGroupMetadataEvent::MemberJoined {
        group_id,
        stable_group_id,
        ..
    } = event
    else {
        return named_group_metadata_event_group_id(event).to_string();
    };
    groups
        .get(group_id)
        .or_else(|| {
            stable_group_id
                .as_deref()
                .and_then(|stable| groups.get(stable))
        })
        .or_else(|| {
            groups
                .values()
                .filter(|info| {
                    info.mls_group_id == *group_id
                        || info.stable_group_id() == group_id
                        || stable_group_id.as_deref() == Some(info.mls_group_id.as_str())
                        || stable_group_id.as_deref() == Some(info.stable_group_id())
                })
                .min_by_key(|info| info.stable_group_id())
        })
        .map_or_else(
            || recovery_cache_group_identity(event).to_string(),
            |info| info.stable_group_id().to_string(),
        )
}

fn recovery_cache_storage_group_id<'a>(
    key: &'a str,
    event: &'a NamedGroupMetadataEvent,
) -> &'a str {
    key.split_once(':').map_or_else(
        || recovery_cache_group_identity(event),
        |(group_id, _)| group_id,
    )
}

fn member_joined_event_timestamp(event: &NamedGroupMetadataEvent) -> u64 {
    match event {
        NamedGroupMetadataEvent::MemberJoined { ts_ms, .. } => *ts_ms,
        _ => 0,
    }
}

fn cache_entry_encoded_bytes(
    key: &str,
    event: &NamedGroupMetadataEvent,
) -> serde_json::Result<usize> {
    let key_bytes = serde_json::to_vec(key)?.len();
    let event_bytes = serde_json::to_vec(event)?.len();
    Ok(key_bytes.saturating_add(1).saturating_add(event_bytes))
}

fn cache_snapshot_encoded_bytes(state: &TreeKemMemberKeyPackageCacheState) -> usize {
    2usize
        .saturating_add(state.encoded_bytes)
        .saturating_add(state.entries.len().saturating_sub(1))
}

fn enforce_treekem_member_key_package_cache_bounds(
    state: &mut TreeKemMemberKeyPackageCacheState,
) -> usize {
    let mut evicted = 0usize;
    let mut provisional_by_group = BTreeMap::<String, Vec<(String, u64)>>::new();
    for (key, entry) in &state.entries {
        let NamedGroupMetadataEvent::MemberJoined {
            group_id: _,
            recovery_authority_signature_b64,
            ts_ms,
            ..
        } = &entry.event
        else {
            continue;
        };
        if recovery_authority_signature_b64.is_none() {
            provisional_by_group
                .entry(recovery_cache_storage_group_id(key, &entry.event).to_string())
                .or_default()
                .push((key.clone(), *ts_ms));
        }
    }
    for provisional in provisional_by_group.values_mut() {
        provisional.sort_by(|(left_key, left_ts), (right_key, right_ts)| {
            left_ts.cmp(right_ts).then_with(|| left_key.cmp(right_key))
        });
        let excess = provisional
            .len()
            .saturating_sub(TREEKEM_PROVISIONAL_RECOVERY_PER_GROUP_CAP);
        for (victim, _) in provisional.iter().take(excess) {
            if let Some(removed) = state.entries.remove(victim) {
                state.encoded_bytes = state.encoded_bytes.saturating_sub(removed.encoded_bytes);
                evicted = evicted.saturating_add(1);
            }
        }
    }
    while state.entries.len() > TREEKEM_MEMBER_KEY_PACKAGE_CACHE_MAX_ENTRIES
        || cache_snapshot_encoded_bytes(state) > TREEKEM_MEMBER_KEY_PACKAGE_CACHE_MAX_BYTES
    {
        let victim = state
            .entries
            .iter()
            .min_by(|(left_key, left), (right_key, right)| {
                member_joined_event_timestamp(&left.event)
                    .cmp(&member_joined_event_timestamp(&right.event))
                    .then_with(|| left_key.cmp(right_key))
            })
            .map(|(key, _)| key.clone());
        let Some(victim) = victim else {
            break;
        };
        if let Some(removed) = state.entries.remove(&victim) {
            state.encoded_bytes = state.encoded_bytes.saturating_sub(removed.encoded_bytes);
            evicted = evicted.saturating_add(1);
        }
    }
    evicted
}

fn recovery_event_has_authority_attestation(event: &NamedGroupMetadataEvent) -> bool {
    matches!(
        event,
        NamedGroupMetadataEvent::MemberJoined {
            recovery_authority_signature_b64: Some(_),
            ..
        }
    )
}

fn recovery_attestation_revision(event: &NamedGroupMetadataEvent) -> Option<u64> {
    let NamedGroupMetadataEvent::MemberJoined {
        recovery_authority_signature_b64: Some(_),
        recovery_authority_commit: Some(commit),
        ..
    } = event
    else {
        return None;
    };
    Some(commit.revision)
}

fn should_replace_recovery_cache_entry(
    existing: &NamedGroupMetadataEvent,
    candidate: &NamedGroupMetadataEvent,
    overwrite: bool,
) -> bool {
    if !overwrite {
        return false;
    }
    match (
        recovery_attestation_revision(existing),
        recovery_attestation_revision(candidate),
    ) {
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (Some(existing_revision), Some(candidate_revision)) => {
            candidate_revision > existing_revision
                || (candidate_revision == existing_revision
                    && member_joined_event_timestamp(candidate)
                        > member_joined_event_timestamp(existing))
        }
        (None, None) => {
            member_joined_event_timestamp(candidate) > member_joined_event_timestamp(existing)
        }
    }
}

fn provisional_recovery_cache_victim(
    state: &TreeKemMemberKeyPackageCacheState,
    group_id: &str,
) -> Option<String> {
    let mut provisional = state
        .entries
        .iter()
        .filter_map(|(key, entry)| {
            let NamedGroupMetadataEvent::MemberJoined {
                recovery_authority_signature_b64,
                ts_ms,
                ..
            } = &entry.event
            else {
                return None;
            };
            (recovery_authority_signature_b64.is_none()
                && recovery_cache_storage_group_id(key, &entry.event) == group_id)
                .then_some((key, *ts_ms))
        })
        .collect::<Vec<_>>();
    if provisional.len() < TREEKEM_PROVISIONAL_RECOVERY_PER_GROUP_CAP {
        return None;
    }
    provisional.sort_by(|(left_key, left_ts), (right_key, right_ts)| {
        left_ts.cmp(right_ts).then_with(|| left_key.cmp(right_key))
    });
    provisional.first().map(|(key, _)| (*key).clone())
}

impl TreeKemMemberKeyPackageCache {
    fn from_entries(
        path: PathBuf,
        entries: BTreeMap<String, NamedGroupMetadataEvent>,
        dirty: bool,
    ) -> serde_json::Result<(Self, usize)> {
        let mut state = TreeKemMemberKeyPackageCacheState {
            entries: BTreeMap::new(),
            encoded_bytes: 0,
            revision: u64::from(dirty),
            persisted_revision: 0,
            dirty,
            write_failures: 0,
            last_error: None,
        };
        for (key, event) in entries {
            let encoded_bytes = cache_entry_encoded_bytes(&key, &event)?;
            state.encoded_bytes = state.encoded_bytes.saturating_add(encoded_bytes);
            state.entries.insert(
                key,
                TreeKemMemberKeyPackageCacheEntry {
                    event,
                    encoded_bytes,
                },
            );
        }
        let evicted = enforce_treekem_member_key_package_cache_bounds(&mut state);
        if evicted > 0 && !state.dirty {
            state.revision = 1;
            state.dirty = true;
        }
        Ok((
            Self {
                path,
                state: Arc::new(RwLock::new(state)),
                persistence: Arc::new(Mutex::new(())),
                retry_scheduled: Arc::new(AtomicBool::new(false)),
            },
            evicted,
        ))
    }

    async fn get(&self, key: &str) -> Option<NamedGroupMetadataEvent> {
        let state = self.state.read().await;
        if let Some(entry) = state.entries.get(key) {
            return Some(entry.event.clone());
        }
        state
            .entries
            .values()
            .filter(|entry| {
                member_joined_kp_cache_entry(&entry.event)
                    .is_some_and(|(event_key, _)| event_key == key)
            })
            .map(|entry| &entry.event)
            .max_by(|left, right| {
                recovery_attestation_revision(left)
                    .cmp(&recovery_attestation_revision(right))
                    .then_with(|| {
                        member_joined_event_timestamp(left)
                            .cmp(&member_joined_event_timestamp(right))
                    })
            })
            .cloned()
    }

    async fn find_for_member(
        &self,
        group_ids: &[String],
        member_id: &str,
    ) -> Option<NamedGroupMetadataEvent> {
        let state = self.state.read().await;
        state
            .entries
            .iter()
            .filter(|(key, entry)| {
                let NamedGroupMetadataEvent::MemberJoined {
                    group_id,
                    stable_group_id,
                    member_agent_id,
                    ..
                } = &entry.event
                else {
                    return false;
                };
                member_agent_id.eq_ignore_ascii_case(member_id)
                    && group_ids.iter().any(|candidate| {
                        candidate == recovery_cache_storage_group_id(key, &entry.event)
                            || candidate == group_id
                            || stable_group_id.as_deref() == Some(candidate.as_str())
                    })
            })
            .map(|(_, entry)| &entry.event)
            .max_by(|left, right| {
                recovery_attestation_revision(left)
                    .cmp(&recovery_attestation_revision(right))
                    .then_with(|| {
                        member_joined_event_timestamp(left)
                            .cmp(&member_joined_event_timestamp(right))
                    })
            })
            .cloned()
    }

    async fn events_matching(
        &self,
        mut predicate: impl FnMut(&NamedGroupMetadataEvent) -> bool,
    ) -> Vec<NamedGroupMetadataEvent> {
        self.state
            .read()
            .await
            .entries
            .values()
            .filter(|entry| predicate(&entry.event))
            .map(|entry| entry.event.clone())
            .collect()
    }

    #[cfg(test)]
    async fn insert(
        &self,
        key: String,
        event: NamedGroupMetadataEvent,
        overwrite: bool,
    ) -> Result<TreeKemCacheMutation> {
        self.insert_for_group(key, event, overwrite, None).await
    }

    async fn insert_for_group(
        &self,
        key: String,
        event: NamedGroupMetadataEvent,
        overwrite: bool,
        canonical_group_id: Option<&str>,
    ) -> Result<TreeKemCacheMutation> {
        let expected_key = member_joined_kp_cache_entry(&event)
            .map(|(expected_key, _)| expected_key)
            .context("TreeKEM recovery cache accepts only key-package MemberJoined events")?;
        let signature_valid = if recovery_event_has_authority_attestation(&event) {
            verify_recovery_attestation_structure(&event)
        } else {
            verify_member_joined_key_package_event(&event)
        };
        let signed_stable_key = match &event {
            NamedGroupMetadataEvent::MemberJoined {
                stable_group_id: Some(stable_group_id),
                member_agent_id,
                ..
            } => Some(join_result_key(stable_group_id, member_agent_id)),
            _ => None,
        };
        if (expected_key != key && signed_stable_key.as_deref() != Some(key.as_str()))
            || !signature_valid
        {
            anyhow::bail!("TreeKEM recovery cache rejected invalid key or recovery signature");
        }
        let storage_key = if let Some(canonical_group_id) = canonical_group_id {
            let NamedGroupMetadataEvent::MemberJoined {
                member_agent_id, ..
            } = &event
            else {
                anyhow::bail!("TreeKEM recovery cache accepts only MemberJoined events");
            };
            join_result_key(canonical_group_id, &member_agent_id.to_ascii_lowercase())
        } else {
            key
        };
        let encoded_bytes = cache_entry_encoded_bytes(&storage_key, &event)
            .context("failed to encode TreeKEM member key-package cache entry")?;
        let evicted = {
            let mut state = self.state.write().await;
            if let Some(existing) = state.entries.get(&storage_key) {
                if !should_replace_recovery_cache_entry(&existing.event, &event, overwrite) {
                    drop(state);
                    let persistence = self.persist_latest().await;
                    if matches!(&persistence, TreeKemCachePersistenceStatus::Dirty { .. }) {
                        self.schedule_persistence_retry();
                    }
                    return Ok(TreeKemCacheMutation {
                        persistence,
                        evicted: 0,
                    });
                }
            }

            let mut evicted = 0usize;
            if let Some(previous) = state.entries.remove(&storage_key) {
                state.encoded_bytes = state.encoded_bytes.saturating_sub(previous.encoded_bytes);
            } else if recovery_attestation_revision(&event).is_none() {
                let group_id = recovery_cache_storage_group_id(&storage_key, &event);
                if let Some(victim) = provisional_recovery_cache_victim(&state, group_id) {
                    if let Some(removed) = state.entries.remove(&victim) {
                        state.encoded_bytes =
                            state.encoded_bytes.saturating_sub(removed.encoded_bytes);
                        evicted = evicted.saturating_add(1);
                    }
                }
            }
            state.encoded_bytes = state.encoded_bytes.saturating_add(encoded_bytes);
            state.entries.insert(
                storage_key,
                TreeKemMemberKeyPackageCacheEntry {
                    event,
                    encoded_bytes,
                },
            );
            state.revision = state.revision.saturating_add(1);
            state.dirty = true;
            evicted.saturating_add(enforce_treekem_member_key_package_cache_bounds(&mut state))
        };
        let persistence = self.persist_latest().await;
        if matches!(&persistence, TreeKemCachePersistenceStatus::Dirty { .. }) {
            self.schedule_persistence_retry();
        }
        Ok(TreeKemCacheMutation {
            persistence,
            evicted,
        })
    }

    async fn remove_member(
        &self,
        group_ids: &HashSet<String>,
        member_id: &str,
    ) -> TreeKemCacheMutation {
        self.remove_matching(|key, event| match event {
            NamedGroupMetadataEvent::MemberJoined {
                group_id,
                stable_group_id,
                member_agent_id,
                ..
            } => {
                member_agent_id.eq_ignore_ascii_case(member_id)
                    && (group_ids.contains(group_id)
                        || stable_group_id
                            .as_ref()
                            .is_some_and(|stable| group_ids.contains(stable))
                        || group_ids.contains(recovery_cache_storage_group_id(key, event)))
            }
            _ => false,
        })
        .await
    }

    async fn remove_groups(&self, group_ids: &HashSet<String>) -> TreeKemCacheMutation {
        self.remove_matching(|key, event| match event {
            NamedGroupMetadataEvent::MemberJoined {
                group_id,
                stable_group_id,
                ..
            } => {
                group_ids.contains(group_id)
                    || stable_group_id
                        .as_ref()
                        .is_some_and(|stable| group_ids.contains(stable))
                    || group_ids.contains(recovery_cache_storage_group_id(key, event))
            }
            _ => false,
        })
        .await
    }

    async fn remove_matching(
        &self,
        should_remove: impl Fn(&str, &NamedGroupMetadataEvent) -> bool,
    ) -> TreeKemCacheMutation {
        let removed = {
            let mut state = self.state.write().await;
            let victims: Vec<String> = state
                .entries
                .iter()
                .filter(|(key, entry)| should_remove(key, &entry.event))
                .map(|(key, _)| key.clone())
                .collect();
            for key in &victims {
                if let Some(entry) = state.entries.remove(key) {
                    state.encoded_bytes = state.encoded_bytes.saturating_sub(entry.encoded_bytes);
                }
            }
            if !victims.is_empty() {
                state.revision = state.revision.saturating_add(1);
                state.dirty = true;
            }
            victims.len()
        };
        let persistence = self.persist_latest().await;
        if matches!(&persistence, TreeKemCachePersistenceStatus::Dirty { .. }) {
            self.schedule_persistence_retry();
        }
        TreeKemCacheMutation {
            persistence,
            evicted: removed,
        }
    }

    async fn persist_latest(&self) -> TreeKemCachePersistenceStatus {
        let _persistence = self.persistence.lock().await;
        loop {
            let (revision, snapshot) = {
                let state = self.state.read().await;
                if !state.dirty {
                    return TreeKemCachePersistenceStatus::Durable {
                        revision: state.persisted_revision,
                    };
                }
                let snapshot = state
                    .entries
                    .iter()
                    .map(|(key, entry)| (key.clone(), entry.event.clone()))
                    .collect::<BTreeMap<_, _>>();
                (state.revision, snapshot)
            };
            let json = match serde_json::to_string(&snapshot) {
                Ok(json) => json,
                Err(error) => {
                    return self
                        .record_persistence_failure(
                            revision,
                            format!("serialization failed: {error}"),
                        )
                        .await;
                }
            };
            if let Err(error) = write_treekem_cache_json_atomic(&self.path, &json).await {
                return self
                    .record_persistence_failure(revision, format!("write failed: {error}"))
                    .await;
            }
            let mut state = self.state.write().await;
            state.persisted_revision = state.persisted_revision.max(revision);
            if state.revision == revision {
                state.dirty = false;
                state.last_error = None;
                return TreeKemCachePersistenceStatus::Durable { revision };
            }
        }
    }

    async fn record_persistence_failure(
        &self,
        attempted_revision: u64,
        error: String,
    ) -> TreeKemCachePersistenceStatus {
        let mut state = self.state.write().await;
        state.dirty = true;
        state.write_failures = state.write_failures.saturating_add(1);
        state.last_error = Some(error.clone());
        TreeKemCachePersistenceStatus::Dirty {
            revision: state.revision.max(attempted_revision),
            error,
        }
    }

    fn schedule_persistence_retry(&self) {
        if self.retry_scheduled.swap(true, Ordering::AcqRel) {
            return;
        }
        let cache = self.clone();
        tokio::spawn(async move {
            let mut delay = Duration::from_millis(250);
            loop {
                tokio::time::sleep(delay).await;
                match cache.persist_latest().await {
                    TreeKemCachePersistenceStatus::Durable { .. } => break,
                    TreeKemCachePersistenceStatus::Dirty { .. } => {
                        delay = delay.saturating_mul(2).min(Duration::from_secs(30));
                    }
                }
            }
            cache.retry_scheduled.store(false, Ordering::Release);
            if cache.diagnostics().await.dirty {
                cache.schedule_persistence_retry();
            }
        });
    }

    pub(in crate::server) async fn diagnostics(&self) -> TreeKemCacheDiagnostics {
        let state = self.state.read().await;
        TreeKemCacheDiagnostics {
            entries: state.entries.len(),
            encoded_bytes: cache_snapshot_encoded_bytes(&state),
            max_entries: TREEKEM_MEMBER_KEY_PACKAGE_CACHE_MAX_ENTRIES,
            max_encoded_bytes: TREEKEM_MEMBER_KEY_PACKAGE_CACHE_MAX_BYTES,
            revision: state.revision,
            persisted_revision: state.persisted_revision,
            dirty: state.dirty,
            write_failures: state.write_failures,
            last_error: state.last_error.clone(),
        }
    }
}

fn log_treekem_cache_mutation(context: &str, mutation: &TreeKemCacheMutation) {
    if mutation.evicted > 0 {
        tracing::debug!(
            context,
            removed = mutation.evicted,
            "compacted TreeKEM recovery cache"
        );
    }
    if let TreeKemCachePersistenceStatus::Dirty { revision, error } = &mutation.persistence {
        tracing::error!(
            context,
            revision,
            error,
            "TreeKEM recovery cache remains dirty"
        );
    }
}

async fn cache_treekem_member_key_package(
    state: &AppState,
    key: String,
    event: NamedGroupMetadataEvent,
    overwrite: bool,
) -> TreeKemCachePersistenceStatus {
    let canonical_group_id = {
        let groups = state.named_groups.read().await;
        canonical_recovery_cache_group_id(&groups, &event)
    };
    match state
        .treekem_member_key_packages
        .insert_for_group(key, event, overwrite, Some(&canonical_group_id))
        .await
    {
        Ok(mutation) => {
            log_treekem_cache_mutation("insert", &mutation);
            mutation.persistence
        }
        Err(error) => {
            tracing::error!(%error, "failed to mutate TreeKEM recovery cache");
            TreeKemCachePersistenceStatus::Dirty {
                revision: state
                    .treekem_member_key_packages
                    .diagnostics()
                    .await
                    .revision,
                error: error.to_string(),
            }
        }
    }
}

async fn treekem_cache_group_aliases(state: &AppState, group_id: &str) -> HashSet<String> {
    let groups = state.named_groups.read().await;
    let stable_group_id = groups
        .get(group_id)
        .map(|info| info.stable_group_id())
        .or_else(|| {
            groups
                .values()
                .find(|info| info.stable_group_id() == group_id || info.mls_group_id == group_id)
                .map(x0x::groups::GroupInfo::stable_group_id)
        });
    let mut aliases = collect_same_stable_group_aliases(&groups, group_id, stable_group_id);
    aliases.insert(group_id.to_string());
    aliases
}

async fn prune_treekem_cache_member(
    state: &AppState,
    group_id: &str,
    member_id: &str,
    context: &str,
) -> TreeKemCachePersistenceStatus {
    let aliases = treekem_cache_group_aliases(state, group_id).await;
    let mutation = state
        .treekem_member_key_packages
        .remove_member(&aliases, member_id)
        .await;
    log_treekem_cache_mutation(context, &mutation);
    mutation.persistence
}

async fn prune_treekem_cache_groups(
    state: &AppState,
    aliases: &HashSet<String>,
    context: &str,
) -> TreeKemCachePersistenceStatus {
    let mutation = state
        .treekem_member_key_packages
        .remove_groups(aliases)
        .await;
    log_treekem_cache_mutation(context, &mutation);
    mutation.persistence
}

/// Install a TreeKEM KeyPackage recovered from a member-signed `MemberJoined`
/// that the inviter countersigned after accepting the join. The countersignature
/// binds recovery to the package actually admitted into the TreeKEM tree; a
/// compromised member cannot replace it with a newly self-signed package.
async fn apply_recovered_member_key_package(
    state: &Arc<AppState>,
    event: &NamedGroupMetadataEvent,
) -> bool {
    let NamedGroupMetadataEvent::MemberJoined { group_id, .. } = event else {
        return false;
    };
    let membership_lock = group_membership_lock(state, group_id).await;
    #[cfg(test)]
    {
        let notify = RECOVERED_KP_BEFORE_MEMBERSHIP_LOCK_NOTIFY
            .lock()
            .ok()
            .and_then(|guard| {
                guard
                    .as_ref()
                    .filter(|(target_group_id, _)| target_group_id == group_id)
                    .map(|(_, notify)| Arc::clone(notify))
            });
        if let Some(notify) = notify {
            notify.notify_one();
        }
    }
    let _membership_guard = membership_lock.lock().await;
    apply_recovered_member_key_package_locked(state, event).await
}

fn current_member_treekem_key_package(member: &x0x::groups::GroupMember) -> Option<String> {
    let package = member.treekem_key_package_b64.as_ref()?;
    let expected_hash = member.treekem_key_package_hash.as_deref()?;
    (blake3::hash(package.as_bytes()).to_hex().as_str() == expected_hash).then(|| package.clone())
}

/// Install a recovered KeyPackage while the caller holds this group's
/// [`group_membership_lock`]. Keeping resolution and mutation under the same
/// guard prevents a stale full-`GroupInfo` write-back from erasing the package.
async fn apply_recovered_member_key_package_locked(
    state: &Arc<AppState>,
    event: &NamedGroupMetadataEvent,
) -> bool {
    let NamedGroupMetadataEvent::MemberJoined {
        group_id,
        member_agent_id,
        treekem_key_package_b64,
        ..
    } = event
    else {
        return false;
    };
    let Some(kp_b64) = treekem_key_package_b64.clone() else {
        return false;
    };
    // Resolve the live group only after acquiring the membership guard. A
    // pre-lock resolution would recreate the stale-clone race this guard fixes.
    let storage_key = {
        let groups = state.named_groups.read().await;
        groups
            .get_key_value(group_id)
            .map(|(k, _)| k.clone())
            .or_else(|| {
                groups
                    .iter()
                    .find(|(_, info)| info.stable_group_id() == group_id)
                    .map(|(k, _)| k.clone())
            })
    };
    let Some(storage_key) = storage_key else {
        return false;
    };
    let installed = {
        let mut groups = state.named_groups.write().await;
        let Some(info) = groups.get_mut(&storage_key) else {
            return false;
        };
        if !verify_authority_attested_member_joined_recovery(info, event) {
            tracing::warn!(
                group_id = %LogHexId::group(group_id),
                member = %LogHexId::agent(member_agent_id),
                "recovered MemberJoined key package: inviter attestation did not verify"
            );
            return false;
        }
        if !info.has_member(member_agent_id) {
            return false;
        }
        // Never clobber a package we already hold.
        if info
            .members_v2
            .get(member_agent_id)
            .and_then(current_member_treekem_key_package)
            .is_some()
        {
            return false;
        }
        info.set_member_treekem_key_package(member_agent_id, kp_b64.clone());
        true
    };
    if installed {
        save_named_groups(state).await;
        cache_treekem_member_key_package(
            state,
            join_result_key(group_id, member_agent_id),
            event.clone(),
            true,
        )
        .await;
    }
    installed
}

/// On-demand TreeKEM KeyPackage recovery for a promoted admin missing a
/// member's package (issue #205). If the roster already carries it, this is a
/// no-op success; otherwise it looks up this node's cached, self-signed
/// `MemberJoined` for the member and installs its (signature-verified) package.
/// Returns `true` when the roster now carries the package.
#[cfg(test)]
async fn recover_member_treekem_key_package(
    state: &Arc<AppState>,
    group_id: &str,
    member_agent_id: &str,
) -> bool {
    let membership_lock = group_membership_lock(state, group_id).await;
    let _membership_guard = membership_lock.lock().await;
    recover_member_treekem_key_package_locked(state, group_id, member_agent_id).await
}

async fn recover_member_treekem_key_package_locked(
    state: &Arc<AppState>,
    group_id: &str,
    member_agent_id: &str,
) -> bool {
    {
        let groups = state.named_groups.read().await;
        if let Some(info) = groups.get(group_id) {
            if info
                .members_v2
                .get(member_agent_id)
                .and_then(current_member_treekem_key_package)
                .is_some()
            {
                return true;
            }
        }
    }
    let key = join_result_key(group_id, member_agent_id);
    let cached = state.treekem_member_key_packages.get(&key).await;
    let Some(event) = cached else {
        return false;
    };
    apply_recovered_member_key_package_locked(state, &event).await
}

/// Resolve a target member's TreeKEM KeyPackage (base64) for a verified
/// removal/ban, recovering it on demand (issue #205) when the local roster
/// lacks it. Caller must have already enforced admin authority. On a local
/// recovery miss it fires an async member-keyed catch-up so a client retry
/// succeeds after delivery, and returns `FAILED_DEPENDENCY` with `retry: true`.
#[cfg(test)]
async fn resolve_member_treekem_kp_for_removal(
    state: &Arc<AppState>,
    group_id: &str,
    agent_id_hex: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let membership_lock = group_membership_lock(state, group_id).await;
    let _membership_guard = membership_lock.lock().await;
    resolve_member_treekem_kp_for_removal_locked(state, group_id, agent_id_hex).await
}

/// Resolve a removal KeyPackage while the caller holds this group's
/// [`group_membership_lock`].
async fn resolve_member_treekem_kp_for_removal_locked(
    state: &Arc<AppState>,
    group_id: &str,
    agent_id_hex: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let existing = {
        let groups = state.named_groups.read().await;
        groups
            .get(group_id)
            .or_else(|| {
                groups
                    .values()
                    .find(|info| info.stable_group_id() == group_id)
            })
            .and_then(|info| info.members_v2.get(agent_id_hex))
            .and_then(current_member_treekem_key_package)
    };
    if let Some(kp_b64) = existing {
        return Ok(kp_b64);
    }
    if recover_member_treekem_key_package_locked(state, group_id, agent_id_hex).await {
        let recovered = {
            let groups = state.named_groups.read().await;
            groups
                .get(group_id)
                .or_else(|| {
                    groups
                        .values()
                        .find(|info| info.stable_group_id() == group_id)
                })
                .and_then(|info| info.members_v2.get(agent_id_hex))
                .and_then(current_member_treekem_key_package)
        };
        if let Some(kp_b64) = recovered {
            return Ok(kp_b64);
        }
    }
    // Local recovery miss — request the package from peers that witnessed the
    // join (fire-and-forget) and tell the client to retry once it lands.
    let bg_state = Arc::clone(state);
    let bg_group = group_id.to_string();
    let bg_member = agent_id_hex.to_string();
    tokio::spawn(async move {
        request_member_key_package_catchup(&bg_state, &bg_group, &bg_member).await;
    });
    Err((
        StatusCode::FAILED_DEPENDENCY,
        Json(serde_json::json!({
            "ok": false,
            "error": "member_key_package_pending",
            "detail": "member is missing TreeKEM KeyPackage; on-demand catch-up requested — retry shortly",
            "retry": true,
        })),
    ))
}

async fn queue_treekem_membership_event(
    state: &Arc<AppState>,
    group_id: &str,
    event: NamedGroupMetadataEvent,
    sender: AgentId,
    reason: &str,
) {
    {
        let groups = state.named_groups.read().await;
        if has_withdrawn_group_record(&groups, group_id) {
            tracing::debug!(
                target: "treekem.trace",
                stage = "queue_treekem_membership_event_reject",
                reason = "withdrawn_group",
                group_id = %LogHexId::group(&group_id),
            );
            return;
        }
    }
    let queued = PendingTreeKemMetadataEvent {
        event: event.clone(),
        sender,
        queued_at: Instant::now(),
    };
    let key = treekem_membership_event_key(&event);
    {
        let mut pending = state.treekem_pending_events.write().await;
        let queue = pending.entry(group_id.to_string()).or_default();
        if let Some(key) = key.as_deref() {
            if queue
                .iter()
                .filter_map(|pending| treekem_membership_event_key(&pending.event))
                .any(|existing| existing == key)
            {
                return;
            }
        }
        queue.push_back(queued);
        queue
            .make_contiguous()
            .sort_by_key(|pending| treekem_membership_event_sort_key(&pending.event));
        while queue.len() > TREEKEM_PENDING_EVENTS_PER_GROUP_CAP {
            queue.pop_front();
        }
    }
    tracing::warn!(group_id = %LogHexId::group(&group_id), reason, "queued TreeKEM membership event pending catch-up/replay");
    request_treekem_catchup_for_gap(state, group_id, &event, sender).await;
}

async fn request_treekem_catchup_for_gap(
    state: &Arc<AppState>,
    group_id: &str,
    event: &NamedGroupMetadataEvent,
    sender: AgentId,
) {
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let Some(frontier) = treekem_membership_event_frontier(event) else {
        return;
    };
    let (from_revision, from_epoch, current_state_hash) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(group_id) else {
            return;
        };
        if info.withdrawn {
            return;
        }
        (
            info.state_revision,
            info.secret_epoch,
            info.state_hash.clone(),
        )
    };
    let mut peers = Vec::new();
    if !frontier.actor.eq_ignore_ascii_case(&local_agent_hex) {
        if let Ok(peer) = parse_agent_id_hex(frontier.actor) {
            peers.push(peer);
        }
    }
    let sender_hex = hex::encode(sender.as_bytes());
    if sender_hex != local_agent_hex && !peers.contains(&sender) {
        peers.push(sender);
    }
    for peer in peers {
        let peer_hex = hex::encode(peer.as_bytes());
        let throttle_key = format!("{group_id}:{peer_hex}:{from_revision}:{from_epoch}");
        {
            let mut throttle = state.treekem_catchup_throttle.write().await;
            if throttle
                .get(&throttle_key)
                .is_some_and(|last| last.elapsed() < TREEKEM_CATCHUP_THROTTLE)
            {
                continue;
            }
            throttle.insert(throttle_key, Instant::now());
        }
        let request = TreeKemCatchupRequest {
            message_type: "treekem_catchup_request".to_string(),
            group_id: group_id.to_string(),
            requester_agent_id: local_agent_hex.clone(),
            from_revision,
            from_treekem_epoch: from_epoch,
            current_state_hash: current_state_hash.clone(),
            missing_prev_state_hash: frontier.commit.prev_state_hash.clone(),
            target_member_id: None,
            limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
        };
        let payload = match serde_json::to_vec(&request) {
            Ok(payload) => payload,
            Err(e) => {
                tracing::warn!(group_id = %LogHexId::group(&group_id), "failed to serialize TreeKEM catch-up request: {e}");
                continue;
            }
        };
        if let Err(e) = state
            .agent
            .send_direct_with_config(&peer, payload, direct_message_send_config())
            .await
        {
            tracing::debug!(group_id = %group_id, peer = %peer_hex, "TreeKEM catch-up request failed: {e}");
        }
    }
}

async fn replay_pending_treekem_events(state: &Arc<AppState>, group_id: &str) {
    let entries = {
        let mut pending = state.treekem_pending_events.write().await;
        let Some(queue) = pending.get_mut(group_id) else {
            return;
        };
        let mut entries: Vec<_> = queue.drain(..).collect();
        entries.retain(|pending| pending.queued_at.elapsed() < PENDING_JOIN_RESULT_TTL);
        entries.sort_by_key(|pending| treekem_membership_event_sort_key(&pending.event));
        entries
    };
    let mut still_pending = VecDeque::new();
    for pending in entries {
        let applied = apply_named_group_metadata_event_inner(
            state,
            pending.event.clone(),
            pending.sender,
            true,
            false,
        )
        .await;
        if !applied && treekem_membership_event_frontier(&pending.event).is_some() {
            let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
            let info = {
                let groups = state.named_groups.read().await;
                groups.get(group_id).cloned()
            };
            if let Some(info) = info {
                if should_queue_treekem_membership_event(
                    state,
                    group_id,
                    &info,
                    &pending.event,
                    &local_agent_hex,
                )
                .await
                .is_some()
                {
                    still_pending.push_back(pending);
                }
            }
        }
    }
    if !still_pending.is_empty() {
        let mut pending = state.treekem_pending_events.write().await;
        let queue = pending.entry(group_id.to_string()).or_default();
        for item in still_pending {
            queue.push_back(item);
        }
        while queue.len() > TREEKEM_PENDING_EVENTS_PER_GROUP_CAP {
            queue.pop_front();
        }
    }
}

async fn member_keyed_treekem_catchup_response(
    state: &AppState,
    log_keys: &[String],
    request: &TreeKemCatchupRequest,
) -> Option<TreeKemCatchupResponse> {
    let target_member_id = request.target_member_id.as_ref()?;
    let info = {
        let groups = state.named_groups.read().await;
        groups
            .get(&request.group_id)
            .or_else(|| {
                groups
                    .values()
                    .find(|info| info.stable_group_id() == request.group_id)
            })
            .cloned()
    }?;
    let event = state
        .treekem_member_key_packages
        .find_for_member(log_keys, target_member_id)
        .await
        .filter(|event| verify_authority_attested_member_joined_recovery(&info, event));
    Some(TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: request.group_id.clone(),
        events: event.into_iter().collect(),
        truncated: false,
    })
}

pub(in crate::server) async fn handle_treekem_catchup_request(
    state: &Arc<AppState>,
    sender: &AgentId,
    verified: bool,
    request: TreeKemCatchupRequest,
) {
    if !verified || request.message_type != "treekem_catchup_request" {
        return;
    }
    let sender_hex = hex::encode(sender.as_bytes());
    if sender_hex != request.requester_agent_id {
        return;
    }
    let (authorized, log_keys) = {
        let groups = state.named_groups.read().await;
        if let Some((key, info)) = groups.get_key_value(&request.group_id).or_else(|| {
            groups
                .iter()
                .find(|(_, info)| info.stable_group_id() == request.group_id)
        }) {
            if info.withdrawn {
                return;
            }
            let mut keys = vec![
                request.group_id.clone(),
                key.clone(),
                info.stable_group_id().to_string(),
            ];
            keys.sort();
            keys.dedup();
            (info.has_active_member(&sender_hex), keys)
        } else {
            (false, vec![request.group_id.clone()])
        }
    };
    let target_of_cached_add = {
        let logs = state.treekem_event_log.read().await;
        log_keys.iter().any(|key| {
            logs.get(key).is_some_and(|events| {
                events.iter().any(|event| match event {
                    NamedGroupMetadataEvent::MemberAdded { agent_id, .. } => {
                        agent_id == &sender_hex
                    }
                    NamedGroupMetadataEvent::JoinRequestApproved {
                        requester_agent_id, ..
                    } => requester_agent_id == &sender_hex,
                    _ => false,
                })
            })
        })
    };
    if !authorized && !target_of_cached_add {
        tracing::warn!(group_id = %LogHexId::group(&request.group_id), requester = %sender_hex, "rejecting unauthorized TreeKEM catch-up request");
        return;
    }
    // Issue #205: member-keyed TreeKEM KeyPackage fetch. The requester is a
    // promoted admin missing a member's key package; serve this node's cached,
    // self-signed `MemberJoined` for the target (this node witnessed the join).
    // The same gates apply (verified DM, sender == requester, active member or
    // target-of-cached-add). The requester authenticates the package via the
    // embedded ML-DSA-65 signature in `apply_recovered_member_key_package`.
    if let Some(response) = member_keyed_treekem_catchup_response(state, &log_keys, &request).await
    {
        let payload = match serde_json::to_vec(&response) {
            Ok(payload) => payload,
            Err(e) => {
                tracing::warn!(group_id = %LogHexId::group(&request.group_id), "failed to serialize member-keyed TreeKEM catch-up response: {e}");
                return;
            }
        };
        if let Err(e) = state
            .agent
            .send_direct_with_config(sender, payload, direct_message_send_config())
            .await
        {
            tracing::warn!(group_id = %LogHexId::group(&request.group_id), requester = %sender_hex, "failed to send member-keyed TreeKEM catch-up response: {e}");
        }
        return;
    }
    let mut events = {
        let logs = state.treekem_event_log.read().await;
        let mut events = Vec::new();
        for key in &log_keys {
            if let Some(logged) = logs.get(key) {
                events.extend(logged.iter().cloned());
            }
        }
        events
            .into_iter()
            .filter(|event| {
                treekem_membership_event_frontier(event).is_some_and(|frontier| {
                    frontier.revision > request.from_revision
                        || frontier.epoch.unwrap_or_default() > request.from_treekem_epoch
                })
            })
            .collect::<Vec<_>>()
    };
    events.sort_by_key(treekem_membership_event_sort_key);
    let truncated = events.len() > request.limit.min(TREEKEM_CATCHUP_RESPONSE_EVENT_CAP);
    events.truncate(request.limit.min(TREEKEM_CATCHUP_RESPONSE_EVENT_CAP));
    let response = TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: request.group_id.clone(),
        events,
        truncated,
    };
    let payload = match serde_json::to_vec(&response) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!(group_id = %LogHexId::group(&request.group_id), "failed to serialize TreeKEM catch-up response: {e}");
            return;
        }
    };
    if let Err(e) = state
        .agent
        .send_direct_with_config(sender, payload, direct_message_send_config())
        .await
    {
        tracing::warn!(group_id = %LogHexId::group(&request.group_id), requester = %sender_hex, "failed to send TreeKEM catch-up response: {e}");
    }
}

pub(in crate::server) async fn handle_treekem_catchup_response(
    state: &Arc<AppState>,
    sender: &AgentId,
    verified: bool,
    response: TreeKemCatchupResponse,
) {
    if !verified || response.message_type != "treekem_catchup_response" {
        return;
    }
    let sender_hex = hex::encode(sender.as_bytes());
    {
        let revocation_set = state.agent.revocation_set();
        let revoked = revocation_set.read().await;
        if revoked.is_agent_revoked(sender) {
            return;
        }
    }
    let response_info = {
        let groups = state.named_groups.read().await;
        groups
            .get(&response.group_id)
            .or_else(|| {
                groups
                    .values()
                    .find(|info| info.stable_group_id() == response.group_id)
            })
            .filter(|info| !info.withdrawn && info.has_active_member(&sender_hex))
            .cloned()
    };
    let Some(response_info) = response_info else {
        tracing::warn!(
            group_id = %LogHexId::group(&response.group_id),
            sender = %LogHexId::agent(&sender_hex),
            "rejecting TreeKEM catch-up response from a non-member or withdrawn group"
        );
        return;
    };
    let was_truncated = response.truncated;
    let mut events = response.events;
    events.sort_by_key(treekem_membership_event_sort_key);
    for event in events {
        let recovery_event = member_joined_kp_cache_entry(&event)
            .map(|(_, ev)| ev)
            .filter(|ev| verify_authority_attested_member_joined_recovery(&response_info, ev));
        apply_named_group_metadata_event(state, event, *sender, true).await;
        if let Some(ev) = recovery_event {
            apply_recovered_member_key_package(state, &ev).await;
        }
    }
    replay_pending_treekem_events(state, &response.group_id).await;
    if was_truncated {
        tracing::debug!(
            target: "treekem.trace",
            group_id = %response.group_id,
            sender = %hex::encode(sender.as_bytes()),
            "TreeKEM catch-up response was truncated; requesting next page"
        );
        request_treekem_catchup_page(state, &response.group_id, sender).await;
    }
}

async fn request_treekem_catchup_page(state: &Arc<AppState>, group_id: &str, peer: &AgentId) {
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (from_revision, from_epoch, current_state_hash) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(group_id).or_else(|| {
            groups
                .values()
                .find(|info| info.stable_group_id() == group_id)
        }) else {
            return;
        };
        (
            info.state_revision,
            info.secret_epoch,
            info.state_hash.clone(),
        )
    };
    let request = TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_id.to_string(),
        requester_agent_id: local_agent_hex,
        from_revision,
        from_treekem_epoch: from_epoch,
        current_state_hash,
        missing_prev_state_hash: None,
        target_member_id: None,
        limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
    };
    let payload = match serde_json::to_vec(&request) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!(group_id = %LogHexId::group(&group_id), "failed to serialize paged TreeKEM catch-up request: {e}");
            return;
        }
    };
    if let Err(e) = state
        .agent
        .send_direct_with_config(peer, payload, direct_message_send_config())
        .await
    {
        tracing::debug!(group_id = %group_id, peer = %hex::encode(peer.as_bytes()), "paged TreeKEM catch-up request failed: {e}");
    }
}

/// Issue #205: ask peers that witnessed a member's join for that member's
/// cached, self-signed `MemberJoined` (carrying the TreeKEM KeyPackage) so a
/// promoted admin missing the package can recover it. Candidates are the
/// member's recorded inviter (`added_by`) and the group's other active
/// members; the request is throttled per `{group}:member:{member}:{peer}` with
/// the same 5 s window as the revision-gap catch-up.
async fn request_member_key_package_catchup(
    state: &Arc<AppState>,
    group_id: &str,
    member_agent_id: &str,
) {
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (from_revision, from_epoch, current_state_hash, candidates) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(group_id).or_else(|| {
            groups
                .values()
                .find(|info| info.stable_group_id() == group_id)
        }) else {
            return;
        };
        if info.withdrawn {
            return;
        }
        // Prefer the inviter (it authored the join), then fall back to every
        // other active member — any node that applied the MemberJoined has the
        // cached package.
        let mut candidate_hexes: Vec<String> = info
            .members_v2
            .get(member_agent_id)
            .and_then(|m| m.added_by.clone())
            .into_iter()
            .collect();
        for (aid, m) in &info.members_v2 {
            if !aid.eq_ignore_ascii_case(&local_agent_hex)
                && !candidate_hexes.iter().any(|c| c.eq_ignore_ascii_case(aid))
                && m.state == x0x::groups::GroupMemberState::Active
            {
                candidate_hexes.push(aid.clone());
            }
        }
        (
            info.state_revision,
            info.secret_epoch,
            info.state_hash.clone(),
            candidate_hexes,
        )
    };
    for candidate_hex in candidates {
        if candidate_hex.eq_ignore_ascii_case(&local_agent_hex) {
            continue;
        }
        let Ok(peer) = parse_agent_id_hex(&candidate_hex) else {
            continue;
        };
        let throttle_key = format!("{group_id}:member:{member_agent_id}:{candidate_hex}");
        {
            let mut throttle = state.treekem_catchup_throttle.write().await;
            if throttle
                .get(&throttle_key)
                .is_some_and(|last| last.elapsed() < TREEKEM_CATCHUP_THROTTLE)
            {
                continue;
            }
            throttle.insert(throttle_key, Instant::now());
        }
        let request = TreeKemCatchupRequest {
            message_type: "treekem_catchup_request".to_string(),
            group_id: group_id.to_string(),
            requester_agent_id: local_agent_hex.clone(),
            from_revision,
            from_treekem_epoch: from_epoch,
            current_state_hash: current_state_hash.clone(),
            missing_prev_state_hash: None,
            target_member_id: Some(member_agent_id.to_string()),
            limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
        };
        let payload = match serde_json::to_vec(&request) {
            Ok(payload) => payload,
            Err(e) => {
                tracing::warn!(group_id = %LogHexId::group(&group_id), member = %LogHexId::agent(&member_agent_id), "failed to serialize member-keyed TreeKEM catch-up request: {e}");
                continue;
            }
        };
        if let Err(e) = state
            .agent
            .send_direct_with_config(&peer, payload, direct_message_send_config())
            .await
        {
            tracing::debug!(group_id = %group_id, member = %LogHexId::agent(&member_agent_id), peer = %candidate_hex, "member-keyed TreeKEM catch-up request failed: {e}");
        }
    }
}

/// Get-or-create the per-group membership serialization mutex. See
/// [`AppState::group_membership_locks`] for why membership applies must be
/// serialized per group.
async fn group_membership_lock(state: &AppState, group_key: &str) -> Arc<Mutex<()>> {
    let lock_key = {
        let groups = state.named_groups.read().await;
        groups
            .get(group_key)
            .map(|info| info.stable_group_id().to_string())
            .or_else(|| {
                groups
                    .values()
                    .find(|info| {
                        info.stable_group_id() == group_key || info.mls_group_id == group_key
                    })
                    .map(|info| info.stable_group_id().to_string())
            })
            .unwrap_or_else(|| group_key.to_string())
    };
    {
        let locks = state.group_membership_locks.read().await;
        if let Some(lock) = locks.get(&lock_key) {
            return Arc::clone(lock);
        }
    }
    let mut locks = state.group_membership_locks.write().await;
    Arc::clone(
        locks
            .entry(lock_key)
            .or_insert_with(|| Arc::new(Mutex::new(()))),
    )
}

pub(in crate::server) async fn apply_named_group_metadata_event(
    state: &Arc<AppState>,
    event: NamedGroupMetadataEvent,
    sender: AgentId,
    verified: bool,
) -> bool {
    // A non-inviter may retain the first fully member-authenticated join event
    // as provisional evidence, but it cannot replace an existing entry. The
    // inviter's post-acceptance countersigned event (distributed in MemberAdded)
    // upgrades this cache authoritatively after the roster mutation succeeds.
    apply_named_group_metadata_event_inner_serialized(state, event, sender, verified, true).await
}

async fn apply_named_group_metadata_event_inner(
    state: &Arc<AppState>,
    event: NamedGroupMetadataEvent,
    sender: AgentId,
    verified: bool,
    allow_queue: bool,
) -> bool {
    apply_named_group_metadata_event_inner_serialized(state, event, sender, verified, allow_queue)
        .await
}

async fn apply_named_group_metadata_event_inner_serialized(
    state: &Arc<AppState>,
    event: NamedGroupMetadataEvent,
    sender: AgentId,
    verified: bool,
    allow_queue: bool,
) -> bool {
    let event_kind = named_group_metadata_event_kind(&event);
    let sender_hex = hex::encode(sender.as_bytes());
    tracing::debug!(
        target: "treekem.trace",
        stage = "apply_metadata_event_entry",
        event = event_kind,
        sender = %sender_hex,
        verified,
        allow_queue,
    );
    // Enforcement point 4 — revocation gate.
    // Must precede bypass_verified so a revoked sender fails closed even for
    // self-authenticating MemberRemoved{commit:Some}/GroupDeleted events.
    // bypass_verified exists because ABSENCE of a cache entry is racy;
    // revocation is POSITIVE knowledge and is exactly what must not be bypassed.
    // A merely-unverified (not revoked) sender's MemberRemoved{commit:Some}
    // STILL PASSES through bypass_verified unchanged — #99 non-regression.
    {
        let revocation_set = state.agent.revocation_set();
        let revoked = revocation_set.read().await;
        if revoked.is_agent_revoked(&sender) {
            tracing::info!(
                target: "treekem.trace",
                stage = "apply_metadata_event_reject",
                reason = "sender_revoked",
                event = event_kind,
                sender = %sender_hex,
                "group metadata event dropped: sender is revoked"
            );
            return false;
        }
    }

    // The transport `verified` flag asserts the sender's AgentId→MachineId
    // binding is in our identity-discovery cache — a best-effort annotation
    // populated asynchronously from gossip announcements. `MemberRemoved`
    // carries a self-authenticating ML-DSA-signed state commit and is still
    // delivery-critical for the removed member itself, which may no longer be
    // in the metadata-topic eager mesh. `GroupDeleted` is the current delete
    // propagation event (and remains old-peer/replay compatible), carrying the
    // signed terminal withdrawal commit. The apply arms below re-check
    // authority from the signed commit (GroupDeleted: AdminOrHigher via
    // `commit.committed_by`; MemberRemoved: actor/sender binding plus
    // AdminOrHigher or MemberSelf signed-commit validation). The authenticated
    // DM `sender_hex` is reliable regardless of the cache, so bypassing
    // `verified` does not weaken membership authorization — only the racy cache
    // annotation is skipped.
    let bypass_verified = matches!(
        event,
        NamedGroupMetadataEvent::GroupDeleted {
            commit: Some(_),
            ..
        } | NamedGroupMetadataEvent::MemberRemoved {
            commit: Some(_),
            ..
        }
    );
    if !verified && !bypass_verified {
        tracing::debug!(
            target: "treekem.trace",
            stage = "apply_metadata_event_reject",
            reason = "unverified",
            event = event_kind,
            sender = %sender_hex,
        );
        return false;
    }

    let group_id = match &event {
        NamedGroupMetadataEvent::MemberAdded { group_id, .. }
        | NamedGroupMetadataEvent::MemberRemoved { group_id, .. }
        | NamedGroupMetadataEvent::GroupDeleted { group_id, .. }
        | NamedGroupMetadataEvent::PolicyUpdated { group_id, .. }
        | NamedGroupMetadataEvent::MemberRoleUpdated { group_id, .. }
        | NamedGroupMetadataEvent::MemberBanned { group_id, .. }
        | NamedGroupMetadataEvent::MemberUnbanned { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestCreated { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestApproved { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestRejected { group_id, .. }
        | NamedGroupMetadataEvent::JoinRequestCancelled { group_id, .. }
        | NamedGroupMetadataEvent::GroupCardPublished { group_id, .. }
        | NamedGroupMetadataEvent::GroupMetadataUpdated { group_id, .. }
        | NamedGroupMetadataEvent::MemberJoined { group_id, .. }
        | NamedGroupMetadataEvent::SecureShareDelivered { group_id, .. } => group_id.clone(),
    };

    let resolved_group_key = {
        let groups = state.named_groups.read().await;
        if groups.contains_key(&group_id) {
            group_id.clone()
        } else if let Some((key, _)) = groups
            .iter()
            .find(|(_, info)| info.stable_group_id() == group_id)
        {
            key.clone()
        } else {
            tracing::debug!(
                target: "treekem.trace",
                stage = "apply_metadata_event_reject",
                reason = "unknown_group",
                event = event_kind,
                group_id = %group_id,
                sender = %sender_hex,
            );
            return false;
        }
    };
    // Serialize every membership apply for this group across the concurrent
    // gossip metadata listener and direct-channel listener. Held for the rest
    // of the apply so the load-mutate-commit sequence below cannot interleave
    // with a duplicate of the same event arriving on the other transport. The
    // direct-DM delivery added for reliability means the owner now receives the
    // same `MemberJoined` on two independent tasks at once; without this guard
    // they double-add to the MLS tree and clobber the roster. `info` is loaded
    // *under* the guard so no stale clone from a racing apply is in flight.
    let membership_lock = group_membership_lock(state, &resolved_group_key).await;
    let _membership_guard = membership_lock.lock().await;
    let info = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&resolved_group_key).cloned() else {
            return false;
        };
        info
    };
    if info.withdrawn && !withdrawn_group_allows_metadata_event(&event) {
        tracing::debug!(
            target: "treekem.trace",
            stage = "apply_metadata_event_reject",
            reason = "withdrawn_group",
            event = event_kind,
            group_id = %resolved_group_key,
            sender = %sender_hex,
        );
        return false;
    }
    if !info.withdrawn && !live_group_allows_metadata_withdrawal_commit(&event) {
        tracing::debug!(
            target: "treekem.trace",
            stage = "apply_metadata_event_reject",
            reason = "withdrawn_commit_requires_group_deleted",
            event = event_kind,
            group_id = %resolved_group_key,
            sender = %sender_hex,
        );
        return false;
    }
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem
        && treekem_metadata_event_requires_phase3(&event)
    {
        tracing::warn!(
            group_id = %LogHexId::group(&resolved_group_key),
            "ignoring TreeKEM metadata membership event without Phase 3 Commit/Welcome transport"
        );
        tracing::debug!(
            target: "treekem.trace",
            stage = "apply_metadata_event_reject",
            reason = "missing_phase3_transport",
            event = event_kind,
            group_id = %resolved_group_key,
            sender = %sender_hex,
        );
        return false;
    }

    if allow_queue
        && treekem_membership_event_frontier(&event).is_some()
        && authorized_treekem_membership_event_for_queue(&info, &event, &sender_hex)
    {
        if let Some(reason) = should_queue_treekem_membership_event(
            state,
            &resolved_group_key,
            &info,
            &event,
            &local_agent_hex,
        )
        .await
        {
            tracing::debug!(
                target: "treekem.trace",
                stage = "apply_metadata_event_queued",
                reason = %reason,
                event = event_kind,
                group_id = %resolved_group_key,
                sender = %sender_hex,
            );
            queue_treekem_membership_event(state, &resolved_group_key, event, sender, &reason)
                .await;
            return false;
        }
    }

    let event_for_log = event.clone();

    match event {
        NamedGroupMetadataEvent::MemberAdded {
            revision,
            actor,
            agent_id,
            display_name,
            treekem_commit_b64,
            treekem_welcome_b64,
            welcome_ref,
            treekem_epoch,
            treekem_key_package_hash,
            member_joined_recovery,
            member_recovery_history,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let treekem_payload = if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                let Some(commit_b64) = treekem_commit_b64 else {
                    return false;
                };
                if treekem_welcome_b64.is_none() && welcome_ref.is_none() {
                    return false;
                }
                let Some(epoch) = treekem_epoch else {
                    return false;
                };
                Some((commit_b64, treekem_welcome_b64, welcome_ref, epoch))
            } else {
                None
            };
            let current = info.clone();
            let mut next = match apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    next.add_member(
                        agent_id.clone(),
                        x0x::groups::GroupRole::Member,
                        Some(actor.clone()),
                        display_name.clone(),
                    );
                    if let Some(package_hash) = treekem_key_package_hash.clone() {
                        next.set_member_treekem_key_package_hash(&agent_id, package_hash);
                    }
                    if let Some(name) = display_name.clone() {
                        next.set_display_name(&agent_id, name);
                    }
                    if let Some((_, _, _, epoch)) = treekem_payload.as_ref() {
                        next.secret_epoch = *epoch;
                        next.security_binding = commit.security_binding.clone();
                    }
                },
            ) {
                Ok(next) => next,
                Err(e) => {
                    tracing::debug!(
                        target: "treekem.trace",
                        stage = "apply_metadata_event_reject",
                        reason = "member_added_state_commit_apply_failed",
                        group_id = %resolved_group_key,
                        member = %agent_id,
                        sender = %sender_hex,
                        revision,
                        commit_revision = commit.revision,
                        local_state_revision = current.state_revision,
                        local_roster_revision = current.roster_revision,
                        local_state_hash = %current.state_hash,
                        commit_prev_state_hash = ?commit.prev_state_hash,
                        error = %e,
                    );
                    return false;
                }
            };
            let mut recovery_cache_entries = Vec::new();
            if let Some(recovery) = member_joined_recovery.as_deref() {
                if !verify_authority_attested_member_joined_recovery(&next, recovery) {
                    tracing::warn!(
                        group_id = %LogHexId::group(&resolved_group_key),
                        member = %LogHexId::agent(&agent_id),
                        "MemberAdded carried an invalid inviter recovery attestation"
                    );
                    return false;
                }
                let Some((key, cached)) = member_joined_kp_cache_entry(recovery) else {
                    return false;
                };
                let NamedGroupMetadataEvent::MemberJoined {
                    treekem_key_package_b64: Some(kp_b64),
                    ..
                } = recovery
                else {
                    return false;
                };
                next.set_member_treekem_key_package(&agent_id, kp_b64.clone());
                recovery_cache_entries.push((key, cached));
            }
            for recovery in &member_recovery_history {
                if !verify_authority_attested_member_joined_recovery(&next, recovery) {
                    tracing::warn!(
                        group_id = %LogHexId::group(&resolved_group_key),
                        "MemberAdded carried invalid historical recovery evidence"
                    );
                    return false;
                }
                let Some((key, cached)) = member_joined_kp_cache_entry(recovery) else {
                    return false;
                };
                let NamedGroupMetadataEvent::MemberJoined {
                    member_agent_id: recovered_member,
                    treekem_key_package_b64: Some(kp_b64),
                    ..
                } = recovery
                else {
                    return false;
                };
                next.set_member_treekem_key_package(recovered_member, kp_b64.clone());
                recovery_cache_entries.push((key, cached));
            }
            if let Some((commit_b64, welcome_b64, welcome_ref, epoch)) = treekem_payload {
                use base64::Engine as _;
                let commit_bytes = match BASE64.decode(commit_b64) {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                };
                if agent_id == local_agent_hex {
                    let welcome_bytes = if let Some(welcome_b64) = welcome_b64 {
                        match BASE64.decode(welcome_b64) {
                            Ok(bytes) => bytes,
                            Err(_) => return false,
                        }
                    } else if let Some(welcome_ref) = welcome_ref {
                        match fetch_treekem_welcome_with_retries(state, &group_id, &welcome_ref)
                            .await
                        {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), welcome_id = %welcome_ref.welcome_id, "failed to fetch TreeKEM Welcome blob after retries: {e}");
                                return false;
                            }
                        }
                    } else {
                        return false;
                    };
                    let group_id_bytes = match hex::decode(&next.mls_group_id) {
                        Ok(bytes) => bytes,
                        Err(_) => return false,
                    };
                    let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
                    let prepared = match x0x::mls::TreeKemMlsGroup::prepare_member(
                        state.agent.agent_id(),
                        &seed,
                    ) {
                        Ok(prepared) => prepared,
                        Err(e) => {
                            tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to prepare local TreeKEM identity for MemberAdded Welcome: {e}");
                            return false;
                        }
                    };
                    let tk = match x0x::mls::TreeKemMlsGroup::join_from_welcome(
                        prepared,
                        &welcome_bytes,
                    ) {
                        Ok(group) => group,
                        Err(e) => {
                            tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to join TreeKEM group from MemberAdded Welcome: {e}");
                            return false;
                        }
                    };
                    if tk.epoch() != epoch {
                        return false;
                    }
                    if let Err(e) = install_joined_treekem_group_after_crypto_recheck(
                        state,
                        &resolved_group_key,
                        next.clone(),
                        tk,
                        "member_added_welcome",
                    )
                    .await
                    {
                        tracing::error!(group_id = %LogHexId::group(&resolved_group_key), "failed to install TreeKEM snapshot after MemberAdded Welcome: {e}");
                        return false;
                    }
                } else {
                    let group = {
                        let map = state.treekem_groups.read().await;
                        map.get(&resolved_group_key).cloned()
                    };
                    if let Some(group) = group {
                        if let Err(e) = process_treekem_commit_after_crypto_recheck(
                            state,
                            &resolved_group_key,
                            &next,
                            group,
                            &commit_bytes,
                            epoch,
                            "member_added_commit",
                        )
                        .await
                        {
                            tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to process/install TreeKEM MemberAdded commit: {e}");
                            return false;
                        }
                    } else if !info.has_active_member(&local_agent_hex) {
                        // This daemon is a pre-Welcome joiner catching up on
                        // authority-signed state commits for members who joined
                        // before it. It has no TreeKEM ratchet yet, so it
                        // cannot process their TreeKEM commits. Applying the
                        // signed metadata commit advances the roster/state hash
                        // so the joiner's own later MemberAdded Welcome can
                        // validate against the correct frontier.
                        tracing::debug!(
                            target: "treekem.trace",
                            stage = "member_added_pre_welcome_state_only_apply",
                            group_id = %resolved_group_key,
                            member = %agent_id,
                            local = %local_agent_hex,
                            revision,
                            epoch,
                        );
                    } else {
                        tracing::debug!(
                            target: "treekem.trace",
                            stage = "apply_metadata_event_reject",
                            reason = "member_added_missing_local_treekem_group",
                            group_id = %resolved_group_key,
                            member = %agent_id,
                            local = %local_agent_hex,
                            revision,
                            epoch,
                        );
                        return false;
                    }
                }
            } else {
                let mut mls_groups = state.mls_groups.write().await;
                if let Some(group) = mls_groups.get_mut(&resolved_group_key) {
                    if let Ok(member_id) = parse_agent_id_hex(&agent_id) {
                        if !group.is_member(&member_id) {
                            let _ = group.add_member(member_id).await;
                        }
                    }
                }
                drop(mls_groups);
            }
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            for (key, cached) in recovery_cache_entries {
                cache_treekem_member_key_package(state, key, cached, true).await;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            save_mls_groups(state).await;
            remember_treekem_membership_event(state, &event_for_log).await;
            true
        }
        NamedGroupMetadataEvent::MemberRemoved {
            revision,
            actor,
            agent_id,
            treekem_commit_b64,
            treekem_epoch,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let admin_remove_auth = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            let self_leave_auth = sender_hex == agent_id && actor == sender_hex;
            if !admin_remove_auth && !self_leave_auth {
                return false;
            }
            let action_kind = if self_leave_auth {
                x0x::groups::ActionKind::MemberSelf
            } else {
                x0x::groups::ActionKind::AdminOrHigher
            };
            let treekem_payload = if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                if self_leave_auth {
                    if treekem_commit_b64.is_some() || treekem_epoch.is_some() {
                        return false;
                    }
                    None
                } else {
                    let Some(commit_b64) = treekem_commit_b64 else {
                        return false;
                    };
                    let Some(epoch) = treekem_epoch else {
                        return false;
                    };
                    Some((commit_b64, epoch))
                }
            } else {
                None
            };
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(&current, &commit, action_kind, |next| {
                next.roster_revision = revision.max(next.roster_revision);
                next.remove_member(&agent_id, Some(actor.clone()));
                if let Some((_, epoch)) = treekem_payload.as_ref() {
                    next.secret_epoch = *epoch;
                    next.security_binding = Some(format!("treekem:epoch={epoch}"));
                }
            }) else {
                return false;
            };
            let cache_aliases = treekem_cache_group_aliases(state, &resolved_group_key).await;
            let removed_self = agent_id == local_agent_hex;
            if removed_self {
                state.named_groups.write().await.remove(&resolved_group_key);
            }
            if treekem_payload.is_none() {
                let mut mls_groups = state.mls_groups.write().await;
                if let Some(group) = mls_groups.get_mut(&resolved_group_key) {
                    if let Ok(member_id) = parse_agent_id_hex(&agent_id) {
                        if group.is_member(&member_id) {
                            let _ = group.remove_member(member_id).await;
                        }
                    }
                }
                drop(mls_groups);
            }
            if removed_self {
                state
                    .group_card_cache
                    .write()
                    .await
                    .remove(&resolved_group_key);
                state.mls_groups.write().await.remove(&resolved_group_key);
                state
                    .treekem_groups
                    .write()
                    .await
                    .remove(&resolved_group_key);
                remove_treekem_persistence_for_group_id(
                    state,
                    &resolved_group_key,
                    "member_removed_self",
                )
                .await;
                save_named_groups(state).await;
                save_mls_groups(state).await;
                let _ =
                    prune_treekem_cache_groups(state, &cache_aliases, "member_removed_self").await;
                return true;
            }
            if let Some((commit_b64, _epoch)) = treekem_payload {
                use base64::Engine as _;
                let commit_bytes = match BASE64.decode(commit_b64) {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                };
                let group = {
                    let map = state.treekem_groups.read().await;
                    map.get(&resolved_group_key).cloned()
                };
                let Some(group) = group else {
                    return false;
                };
                if let Err(e) = process_treekem_commit_after_crypto_recheck(
                    state,
                    &resolved_group_key,
                    &next,
                    group,
                    &commit_bytes,
                    _epoch,
                    "member_removed_commit",
                )
                .await
                {
                    tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to process/install TreeKEM remove commit: {e}");
                    return false;
                }
            }
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            save_mls_groups(state).await;
            remember_treekem_membership_event(state, &event_for_log).await;
            let _ =
                prune_treekem_cache_member(state, &resolved_group_key, &agent_id, "member_removed")
                    .await;
            true
        }
        NamedGroupMetadataEvent::GroupDeleted {
            revision,
            actor,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            // Current delete propagation and legacy delete compatibility both
            // use GroupDeleted with a signed terminal withdrawal commit. DELETE
            // /groups/:id now emits MemberRemoved self-leave only. Apply
            // GroupDeleted by the commit signer rather than by the transport
            // sender: terminal apply validation verifies the ML-DSA signature
            // and that `commit.committed_by` held an Admin-or-higher role. The
            // advisory `actor` field must name that verified signer.
            if actor != commit.committed_by {
                return false;
            }
            if !commit.withdrawn {
                return false;
            }
            let current = info.clone();
            let next = match apply_terminal_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    next.updated_at = commit.committed_at;
                },
            ) {
                Ok(next) => next,
                Err(e) => {
                    tracing::debug!(
                        target: "treekem.trace",
                        stage = "apply_metadata_event_reject",
                        reason = "group_deleted_state_commit_apply_failed",
                        error = %e,
                        event = event_kind,
                        group_id = %resolved_group_key,
                        sender = %sender_hex,
                    );
                    return false;
                }
            };
            // Keep the signed terminal record as a keyless withdrawn tombstone.
            // ADR-0012's "leave nothing behind" is interpreted as wiping MLS,
            // TreeKEM snapshots/queues and GSS shared_secret material; the
            // retained GroupInfo is the guard that blocks stale-card imports
            // from recreating a live authoring-capable group.
            retain_withdrawn_group_tombstone(state, &resolved_group_key, next, "group_deleted")
                .await;
            true
        }
        NamedGroupMetadataEvent::PolicyUpdated {
            revision,
            actor: _,
            policy,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.policy_revision = revision.max(next.policy_revision);
                    next.policy = policy.clone();
                    if next.policy.discoverability != x0x::groups::GroupDiscoverability::Hidden
                        && next.discovery_card_topic.is_none()
                    {
                        next.discovery_card_topic = Some(format!(
                            "x0x.group.{}.card",
                            &next.mls_group_id[..16.min(next.mls_group_id.len())]
                        ));
                    }
                    next.updated_at = commit.committed_at;
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::MemberRoleUpdated {
            revision,
            actor,
            agent_id,
            role,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let Some(target) = info.members_v2.get(&agent_id).cloned() else {
                return false;
            };
            if target.is_removed() || target.is_banned() {
                return false;
            }
            // ADR-0016 reserved-role rationale: the REST authoring API rejects
            // Owner/Moderator/Guest assignments. Signed gossip apply rejects only
            // Owner because it is admin-equivalent; Moderator/Guest rank below
            // Admin, grant no control authority, and remain replayable for
            // validly signed legacy/cross-version convergence.
            if role == x0x::groups::GroupRole::Owner {
                return false;
            }
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    next.set_member_role(&agent_id, role);
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::MemberBanned {
            revision,
            actor,
            agent_id,
            secret_epoch,
            treekem_commit_b64,
            treekem_epoch,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let treekem_payload = if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                let Some(commit_b64) = treekem_commit_b64 else {
                    return false;
                };
                let Some(epoch) = treekem_epoch else {
                    return false;
                };
                Some((commit_b64, epoch))
            } else {
                None
            };
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    next.ban_member(&agent_id, Some(actor.clone()));
                    if let Some((_, epoch)) = treekem_payload.as_ref() {
                        next.secret_epoch = *epoch;
                        next.security_binding = Some(format!("treekem:epoch={epoch}"));
                    } else if let Some(secret_epoch) = secret_epoch {
                        let old_epoch = next.secret_epoch;
                        next.secret_epoch = secret_epoch;
                        next.security_binding = Some(format!("gss:epoch={secret_epoch}"));
                        if old_epoch < secret_epoch {
                            next.shared_secret = None;
                        }
                    }
                },
            ) else {
                return false;
            };
            let cache_aliases = treekem_cache_group_aliases(state, &resolved_group_key).await;
            let banned_self = agent_id == local_agent_hex;
            if banned_self {
                state
                    .treekem_groups
                    .write()
                    .await
                    .remove(&resolved_group_key);
                remove_treekem_persistence_for_group_id(
                    state,
                    &resolved_group_key,
                    "member_banned_self",
                )
                .await;
            } else if let Some((commit_b64, epoch)) = treekem_payload {
                use base64::Engine as _;
                let commit_bytes = match BASE64.decode(commit_b64) {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                };
                let group = {
                    let map = state.treekem_groups.read().await;
                    map.get(&resolved_group_key).cloned()
                };
                let Some(group) = group else {
                    return false;
                };
                if let Err(e) = process_treekem_commit_after_crypto_recheck(
                    state,
                    &resolved_group_key,
                    &next,
                    group,
                    &commit_bytes,
                    epoch,
                    "member_banned_commit",
                )
                .await
                {
                    tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to process/install TreeKEM ban commit: {e}");
                    return false;
                }
            }
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            remember_treekem_membership_event(state, &event_for_log).await;
            if banned_self {
                let _ =
                    prune_treekem_cache_groups(state, &cache_aliases, "member_banned_self").await;
            } else {
                let _ = prune_treekem_cache_member(
                    state,
                    &resolved_group_key,
                    &agent_id,
                    "member_banned",
                )
                .await;
            }
            true
        }
        NamedGroupMetadataEvent::MemberUnbanned {
            revision,
            actor,
            agent_id,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    if next.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                        if let Some(member) = next.members_v2.get_mut(&agent_id) {
                            member.state = x0x::groups::GroupMemberState::Removed;
                            member.updated_at = commit.committed_at;
                            member.removed_by = None;
                        }
                    } else {
                        next.unban_member(&agent_id);
                    }
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::JoinRequestCreated {
            request_id,
            requester_agent_id,
            message,
            ts,
            requester_kem_public_key_b64,
            treekem_key_package_b64,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            if sender_hex != requester_agent_id {
                return false;
            }
            if info.policy.admission != x0x::groups::GroupAdmission::RequestAccess {
                return false;
            }
            if info.has_active_member(&requester_agent_id) {
                return false;
            }
            if info.is_banned(&requester_agent_id) {
                return false;
            }
            if info
                .join_requests
                .values()
                .any(|r| r.requester_agent_id == requester_agent_id && r.is_pending())
            {
                return false;
            }
            if info.join_requests.contains_key(&request_id) {
                return false;
            }
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::NonMemberRequest,
                |next| {
                    let req = x0x::groups::JoinRequest {
                        request_id: request_id.clone(),
                        group_id: group_id.clone(),
                        requester_agent_id: requester_agent_id.clone(),
                        requester_user_id: None,
                        requested_role: x0x::groups::GroupRole::Member,
                        message: message.clone(),
                        treekem_key_package_b64: treekem_key_package_b64.clone(),
                        created_at: ts,
                        reviewed_at: None,
                        reviewed_by: None,
                        status: x0x::groups::JoinRequestStatus::Pending,
                    };
                    next.join_requests.insert(request_id.clone(), req);
                    if let Some(kem_b64) = requester_kem_public_key_b64.clone() {
                        next.members_v2
                            .entry(requester_agent_id.clone())
                            .and_modify(|m| {
                                m.kem_public_key_b64 = Some(kem_b64.clone());
                            })
                            .or_insert_with(|| x0x::groups::GroupMember {
                                agent_id: requester_agent_id.clone(),
                                user_id: None,
                                role: x0x::groups::GroupRole::Member,
                                state: x0x::groups::GroupMemberState::Pending,
                                display_name: None,
                                joined_at: ts,
                                updated_at: ts,
                                added_by: None,
                                removed_by: None,
                                kem_public_key_b64: Some(kem_b64),
                                treekem_key_package_b64: treekem_key_package_b64.clone(),
                                treekem_key_package_hash: None,
                            });
                    }
                    if let Some(kp_b64) = treekem_key_package_b64.clone() {
                        next.set_member_treekem_key_package(&requester_agent_id, kp_b64);
                    }
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::JoinRequestApproved {
            request_id,
            revision,
            actor,
            requester_agent_id,
            treekem_commit_b64,
            treekem_welcome_b64,
            welcome_ref,
            treekem_epoch,
            treekem_key_package_hash,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let Some(req_snapshot) = info.join_requests.get(&request_id).cloned() else {
                return false;
            };
            if !req_snapshot.is_pending() {
                return false;
            }
            if req_snapshot.requester_agent_id != requester_agent_id {
                return false;
            }
            if info.is_banned(&requester_agent_id) {
                return false;
            }
            let treekem_payload = if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                let Some(commit_b64) = treekem_commit_b64 else {
                    return false;
                };
                if treekem_welcome_b64.is_none() && welcome_ref.is_none() {
                    return false;
                }
                let Some(epoch) = treekem_epoch else {
                    return false;
                };
                let Some(package_hash) = treekem_key_package_hash else {
                    return false;
                };
                Some((
                    commit_b64,
                    treekem_welcome_b64,
                    welcome_ref,
                    epoch,
                    package_hash,
                ))
            } else {
                None
            };
            let request_key_package_b64 = req_snapshot.treekem_key_package_b64.clone();
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    let now_ms = commit.committed_at;
                    if let Some(req) = next.join_requests.get_mut(&request_id) {
                        req.status = x0x::groups::JoinRequestStatus::Approved;
                        req.reviewed_by = Some(actor.clone());
                        req.reviewed_at = Some(now_ms);
                    }
                    next.roster_revision = revision.max(next.roster_revision);
                    next.add_member(
                        requester_agent_id.clone(),
                        x0x::groups::GroupRole::Member,
                        Some(actor.clone()),
                        None,
                    );
                    if let Some((_, _, _, _, package_hash)) = treekem_payload.as_ref() {
                        next.set_member_treekem_key_package_hash(
                            &requester_agent_id,
                            package_hash.clone(),
                        );
                        if let Some(kp_b64) = request_key_package_b64.clone().filter(|package| {
                            blake3::hash(package.as_bytes()).to_hex().as_str() == package_hash
                        }) {
                            next.set_member_treekem_key_package(&requester_agent_id, kp_b64);
                        }
                    }
                    if let Some((_, _, _, epoch, _)) = treekem_payload.as_ref() {
                        next.secret_epoch = *epoch;
                        next.security_binding = commit.security_binding.clone();
                    }
                },
            ) else {
                return false;
            };
            if let Some((commit_b64, welcome_b64, welcome_ref, _epoch, _package_hash)) =
                treekem_payload
            {
                use base64::Engine as _;
                let commit_bytes = match BASE64.decode(commit_b64) {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                };
                if requester_agent_id == local_agent_hex {
                    let welcome_bytes = if let Some(welcome_b64) = welcome_b64 {
                        match BASE64.decode(welcome_b64) {
                            Ok(bytes) => bytes,
                            Err(_) => return false,
                        }
                    } else if let Some(welcome_ref) = welcome_ref {
                        match fetch_treekem_welcome_with_retries(state, &group_id, &welcome_ref)
                            .await
                        {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), welcome_id = %welcome_ref.welcome_id, "failed to fetch TreeKEM Welcome blob after retries: {e}");
                                return false;
                            }
                        }
                    } else {
                        return false;
                    };
                    let group_id_bytes = match hex::decode(&next.mls_group_id) {
                        Ok(bytes) => bytes,
                        Err(_) => return false,
                    };
                    let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
                    let prepared = match x0x::mls::TreeKemMlsGroup::prepare_member(
                        state.agent.agent_id(),
                        &seed,
                    ) {
                        Ok(prepared) => prepared,
                        Err(e) => {
                            tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to prepare local TreeKEM identity for welcome: {e}");
                            return false;
                        }
                    };
                    let tk = match x0x::mls::TreeKemMlsGroup::join_from_welcome(
                        prepared,
                        &welcome_bytes,
                    ) {
                        Ok(group) => group,
                        Err(e) => {
                            tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to join TreeKEM group from Welcome: {e}");
                            return false;
                        }
                    };
                    if tk.epoch() != _epoch {
                        tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), expected_epoch = _epoch, actual_epoch = tk.epoch(), "TreeKEM Welcome joined at unexpected epoch");
                        return false;
                    }
                    if let Err(e) = install_joined_treekem_group_after_crypto_recheck(
                        state,
                        &resolved_group_key,
                        next.clone(),
                        tk,
                        "join_request_approved_welcome",
                    )
                    .await
                    {
                        tracing::error!(group_id = %LogHexId::group(&resolved_group_key), "failed to install joined TreeKEM snapshot: {e}");
                        return false;
                    }
                } else {
                    let group = {
                        let map = state.treekem_groups.read().await;
                        map.get(&resolved_group_key).cloned()
                    };
                    let Some(group) = group else {
                        return false;
                    };
                    if let Err(e) = process_treekem_commit_after_crypto_recheck(
                        state,
                        &resolved_group_key,
                        &next,
                        group,
                        &commit_bytes,
                        _epoch,
                        "join_request_approved_commit",
                    )
                    .await
                    {
                        tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "failed to process/install TreeKEM add commit: {e}");
                        return false;
                    }
                }
            }
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            remember_treekem_membership_event(state, &event_for_log).await;
            true
        }
        NamedGroupMetadataEvent::JoinRequestRejected {
            request_id,
            actor,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let Some(req_snapshot) = info.join_requests.get(&request_id).cloned() else {
                return false;
            };
            if !req_snapshot.is_pending() {
                return false;
            }
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    if let Some(req) = next.join_requests.get_mut(&request_id) {
                        req.status = x0x::groups::JoinRequestStatus::Rejected;
                        req.reviewed_by = Some(actor.clone());
                        req.reviewed_at = Some(commit.committed_at);
                    }
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::JoinRequestCancelled {
            request_id,
            requester_agent_id,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            if sender_hex != requester_agent_id {
                return false;
            }
            let Some(req_snapshot) = info.join_requests.get(&request_id).cloned() else {
                return false;
            };
            if req_snapshot.requester_agent_id != requester_agent_id || !req_snapshot.is_pending() {
                return false;
            }
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::NonMemberRequest,
                |next| {
                    if let Some(req) = next.join_requests.get_mut(&request_id) {
                        req.status = x0x::groups::JoinRequestStatus::Cancelled;
                    }
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::GroupCardPublished { card, .. } => {
            if info.withdrawn && !card.withdrawn {
                return false;
            }
            let sender_is_admin = info
                .caller_role(&sender_hex)
                .is_some_and(|role| role.at_least(x0x::groups::GroupRole::Admin));
            if !sender_is_admin {
                return false;
            }
            if card.group_id != info.stable_group_id() {
                return false;
            }
            if !card.signature.is_empty() && card.verify_signature().is_err() {
                return false;
            }
            let mut cache = state.group_card_cache.write().await;
            prune_expired_group_cards(&mut cache, now_millis_u64());
            if card.withdrawn {
                remove_group_card_if_not_stale(&mut cache, &card);
            } else if cache_group_card_if_newer(&mut cache, card.group_id.clone(), card) {
                enforce_group_card_cache_cap(&mut cache);
            }
            false
        }
        NamedGroupMetadataEvent::GroupMetadataUpdated {
            revision,
            actor,
            name,
            description,
            commit,
            ..
        } => {
            let Some(commit) = commit else {
                return false;
            };
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            let current = info.clone();
            let Ok(next) = apply_stateful_event_to_group(
                &current,
                &commit,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    if let Some(n) = name.clone() {
                        next.name = n;
                    }
                    if let Some(d) = description.clone() {
                        next.description = d;
                    }
                    next.updated_at = commit.committed_at;
                },
            ) else {
                return false;
            };
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }
            refresh_group_card_cache_from_info(state, &resolved_group_key, &next).await;
            save_named_groups(state).await;
            false
        }
        NamedGroupMetadataEvent::SecureShareDelivered {
            group_id: ref ev_group_id,
            recipient,
            secret_epoch,
            kem_ciphertext_b64,
            aead_nonce_b64,
            aead_ciphertext_b64,
            actor,
        } => {
            // Only process messages addressed to this daemon. A non-recipient
            // daemon CANNOT open the envelope even if it tried — ML-KEM
            // decapsulation with the wrong key yields a random shared secret
            // and the AEAD auth-tag check fails. The early return here is a
            // performance optimisation, not a security boundary.
            let self_hex = hex::encode(state.agent.agent_id().as_bytes());
            if recipient != self_hex {
                return false;
            }
            if info.withdrawn {
                tracing::debug!(
                    group_id = %ev_group_id,
                    "ignoring SecureShareDelivered for withdrawn group"
                );
                return false;
            }
            // Only accept from an active admin+.
            let actor_role = info.caller_role(&actor);
            let actor_authorized = actor == sender_hex
                && actor_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !actor_authorized {
                return false;
            }
            // Ignore stale envelopes. Equal-epoch delivery is still accepted
            // if we only know the epoch/security_binding from a prior
            // MemberBanned commit but have not yet received the actual shared
            // secret material.
            if secret_epoch < info.secret_epoch
                || (secret_epoch == info.secret_epoch && info.shared_secret.is_some())
            {
                return false;
            }
            use base64::Engine as _;
            let kem_ct = match BASE64.decode(&kem_ciphertext_b64) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let aead_nonce = match BASE64.decode(&aead_nonce_b64) {
                Ok(b) => b,
                Err(_) => return false,
            };
            if aead_nonce.len() != 12 {
                return false;
            }
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&aead_nonce);
            let aead_ct = match BASE64.decode(&aead_ciphertext_b64) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let aad = secure_share_aad(ev_group_id, &recipient, secret_epoch);
            let opened = x0x::groups::kem_envelope::open_group_secret(
                &state.agent_kem_keypair,
                &aad,
                &kem_ct,
                &nonce_bytes,
                &aead_ct,
            );
            let secret = match opened {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        group_id = %ev_group_id,
                        "KEM envelope decap/decrypt failed: {e}"
                    );
                    return false;
                }
            };
            if let Err(e) = ensure_named_group_key_material_install_allowed(
                state,
                &resolved_group_key,
                Some(info.stable_group_id()),
                "secure_share_delivered",
            )
            .await
            {
                tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), "rejecting SecureShareDelivered after post-crypto terminality recheck: {e}");
                return false;
            }
            let mut next = info.clone();
            next.shared_secret = Some(secret.to_vec());
            next.secret_epoch = secret_epoch;
            next.security_binding = Some(format!("gss:epoch={secret_epoch}"));
            if !store_named_group_info(state, &resolved_group_key, next).await {
                return false;
            }
            save_named_groups(state).await;
            tracing::info!(
                group_id = %ev_group_id,
                secret_epoch,
                "Phase D.2: stored new group shared secret (epoch {secret_epoch}) via KEM-sealed envelope"
            );
            false
        }
        NamedGroupMetadataEvent::MemberJoined {
            stable_group_id,
            member_agent_id,
            member_public_key_b64,
            role,
            display_name,
            inviter_agent_id,
            invite_secret,
            ts_ms,
            treekem_key_package_b64,
            recovery_authority_signature_b64,
            signature_b64,
            ..
        } => {
            // Original joins are self-delivered. Authority-attested recovery
            // records may be relayed by any active member; package bytes are
            // still checked against the committed roster hash before install.
            let self_delivered = sender_hex.eq_ignore_ascii_case(&member_agent_id);
            let active_recovery_courier =
                recovery_authority_signature_b64.is_some() && info.has_active_member(&sender_hex);
            if !self_delivered && !active_recovery_courier {
                tracing::debug!(
                    group_id = %resolved_group_key,
                    sender = %sender_hex,
                    member = %member_agent_id,
                    "MemberJoined: rejecting unauthorised recovery courier"
                );
                return false;
            }

            if recovery_authority_signature_b64.is_some() {
                if !verify_authority_attested_member_joined_recovery(&info, &event_for_log) {
                    return false;
                }
                if let Some((key, cached)) = member_joined_kp_cache_entry(&event_for_log) {
                    cache_treekem_member_key_package(state, key, cached, true).await;
                }
                return false;
            }

            // 2. Decode the joiner's published public key + signature.
            use base64::Engine as _;
            let pubkey_bytes = match BASE64.decode(&member_public_key_b64) {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(
                        group_id = %resolved_group_key,
                        "MemberJoined: bad public key base64: {e}"
                    );
                    return false;
                }
            };
            let pubkey = match ant_quic::MlDsaPublicKey::from_bytes(&pubkey_bytes) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(
                        group_id = %resolved_group_key,
                        "MemberJoined: bad public key bytes: {e:?}"
                    );
                    return false;
                }
            };
            let sig_bytes = match BASE64.decode(&signature_b64) {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(
                        group_id = %resolved_group_key,
                        "MemberJoined: bad signature base64: {e}"
                    );
                    return false;
                }
            };
            let sig = match ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
                &sig_bytes,
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(
                        group_id = %resolved_group_key,
                        "MemberJoined: bad signature bytes: {e:?}"
                    );
                    return false;
                }
            };

            // 3. Recompute canonical bytes and verify the joiner's signature.
            //    `stable_group_id` is part of the signing input on the
            //    publisher side; we pass it through verbatim here. Bumping
            //    or stripping the field would break verify on the receiver.
            let canonical = canonical_member_joined_bytes(
                &group_id,
                stable_group_id.as_deref(),
                &member_agent_id,
                &member_public_key_b64,
                role,
                display_name.as_deref(),
                &inviter_agent_id,
                &invite_secret,
                ts_ms,
                treekem_key_package_b64.as_deref(),
            );
            if let Err(e) = ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
                &pubkey, &canonical, &sig,
            ) {
                tracing::debug!(
                    group_id = %resolved_group_key,
                    "MemberJoined: signature did not verify: {e:?}"
                );
                return false;
            }

            // 4. Derived AgentId must match the claimed member_agent_id.
            let derived = hex::encode(ant_quic::derive_peer_id_from_public_key(&pubkey).0);
            if !derived.eq_ignore_ascii_case(&member_agent_id) {
                tracing::debug!(
                    group_id = %resolved_group_key,
                    "MemberJoined: derived agent_id {} != claimed {}",
                    derived,
                    member_agent_id
                );
                return false;
            }

            // 5. Invite-join v1 is strictly role-capped. The joiner signs
            //    the role, but the invite itself grants only Member; accepting
            //    an arbitrary wire role would let an invite holder self-promote.
            if role != x0x::groups::GroupRole::Member {
                tracing::debug!(
                    group_id = %resolved_group_key,
                    member = %member_agent_id,
                    role = ?role,
                    "MemberJoined: rejecting non-member role"
                );
                state
                    .groups_diagnostics
                    .record_member_joined_rejected_non_member_role(&resolved_group_key);
                return false;
            }

            // 6. Only the original local inviter can validate and consume the
            //    one-time invite secret. Third-party receivers deliberately do
            //    NOT apply MemberJoined directly; they wait for the inviter's
            //    authority-signed MemberAdded commit below. This keeps all
            //    durable roster/state_hash mutations inside the signed D.3
            //    state-commit chain.
            let local_is_inviter = local_agent_hex.eq_ignore_ascii_case(&inviter_agent_id);
            if !local_is_inviter {
                if let Some((key, cached)) = member_joined_kp_cache_entry(&event_for_log) {
                    // Keep provisional witness insertion inside the same
                    // membership serialization boundary as terminal pruning.
                    // Otherwise leave/delete can prune first and this deferred
                    // insert can resurrect the retired group's package.
                    cache_treekem_member_key_package(state, key, cached, false).await;
                }
                tracing::debug!(
                    group_id = %resolved_group_key,
                    inviter = %inviter_agent_id,
                    local = %local_agent_hex,
                    "MemberJoined: retained authenticated recovery event without applying on non-inviter receiver"
                );
                return false;
            }
            let inviter_role = info.caller_role(&inviter_agent_id);
            let inviter_authorised =
                inviter_role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin));
            if !inviter_authorised {
                tracing::debug!(
                    group_id = %resolved_group_key,
                    inviter = %inviter_agent_id,
                    "MemberJoined: local inviter is not an admin/owner"
                );
                return false;
            }
            if info.withdrawn {
                tracing::debug!(
                    group_id = %resolved_group_key,
                    "MemberJoined: rejecting — group is withdrawn"
                );
                return false;
            }

            // 7. Idempotent — if the joiner is already active, a replayed
            //    MemberJoined after the inviter committed the add is a no-op and
            //    must not consume any fresh invite record.
            if info.has_active_member(&member_agent_id) {
                return false;
            }

            // 8. Build the authoritative committed add on a clone first. If
            //    validation/signing fails, the live group remains unchanged.
            let signing_kp = state.agent.identity().agent_keypair();
            let now_ms = now_millis_u64();
            let mut next = info.clone();
            if let Err(reason) =
                next.consume_issued_invite(&invite_secret, &member_agent_id, role, ts_ms, now_ms)
            {
                if reason == "invite_secret_unknown" {
                    state
                        .groups_diagnostics
                        .record_member_joined_rejected_invite_secret_unknown(&resolved_group_key);
                }
                tracing::debug!(
                    group_id = %resolved_group_key,
                    inviter = %inviter_agent_id,
                    reason,
                    "MemberJoined: invite validation failed"
                );
                return false;
            }
            let treekem_key_package_bytes =
                if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                    let Some(kp_b64) = treekem_key_package_b64.clone() else {
                        return false;
                    };
                    match BASE64.decode(kp_b64) {
                        Ok(bytes) => Some(bytes),
                        Err(_) => return false,
                    }
                } else {
                    None
                };
            let recovery_original =
                treekem_key_package_b64
                    .as_ref()
                    .map(|_| NamedGroupMetadataEvent::MemberJoined {
                        group_id: group_id.clone(),
                        stable_group_id: stable_group_id.clone(),
                        member_agent_id: member_agent_id.clone(),
                        member_public_key_b64: member_public_key_b64.clone(),
                        role,
                        display_name: display_name.clone(),
                        inviter_agent_id: inviter_agent_id.clone(),
                        invite_secret: invite_secret.clone(),
                        ts_ms,
                        treekem_key_package_b64: treekem_key_package_b64.clone(),
                        recovery_authority_agent_id: None,
                        recovery_authority_public_key_b64: None,
                        recovery_authority_signature_b64: None,
                        recovery_authority_commit: None,
                        signature_b64: signature_b64.clone(),
                    });
            let mut treekem_epoch = None;
            let mut treekem_commit = None;
            let mut treekem_welcome = None;
            next.roster_revision = next.roster_revision.saturating_add(1);
            next.add_member_with_kem(
                member_agent_id.clone(),
                x0x::groups::GroupRole::Member,
                Some(inviter_agent_id.clone()),
                display_name.clone(),
                None,
            );
            if let Some(ref dn) = display_name {
                next.set_display_name(&member_agent_id, dn.clone());
            }
            if let Some(kp_b64) = treekem_key_package_b64.clone() {
                next.set_member_treekem_key_package(&member_agent_id, kp_b64);
            }
            let revision = next.roster_revision;
            let commit = if let Some(kp_bytes) = treekem_key_package_bytes.as_ref() {
                let member_id = match parse_agent_id_hex(&member_agent_id) {
                    Ok(id) => id,
                    Err(_) => return false,
                };
                let group = {
                    let map = state.treekem_groups.read().await;
                    map.get(&resolved_group_key).cloned()
                };
                let Some(group) = group else {
                    return false;
                };
                let mut guard = group.lock().await;
                let expected_epoch = guard.epoch().saturating_add(1);
                let Some(binding) = recovery_original
                    .as_ref()
                    .and_then(|event| treekem_recovery_security_binding(expected_epoch, event))
                else {
                    return false;
                };
                next.security_binding = Some(binding);
                next.secret_epoch = expected_epoch;
                let commit = match next.seal_commit(signing_kp, now_ms) {
                    Ok(commit) => commit,
                    Err(e) => {
                        tracing::warn!(
                            group_id = %LogHexId::group(&resolved_group_key),
                            member = %LogHexId::agent(&member_agent_id),
                            "MemberJoined: failed to seal authoritative add: {e}"
                        );
                        return false;
                    }
                };
                let rollback_snapshot = match guard.to_snapshot_bytes() {
                    Ok(snapshot) => snapshot,
                    Err(e) => {
                        tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), member = %LogHexId::agent(&member_agent_id), "MemberJoined: failed to snapshot TreeKEM group before add: {e}");
                        return false;
                    }
                };
                let out = match guard.add_member(member_id, kp_bytes) {
                    Ok(out) => out,
                    Err(e) => {
                        tracing::warn!(group_id = %LogHexId::group(&resolved_group_key), member = %LogHexId::agent(&member_agent_id), "MemberJoined: TreeKEM add_member failed: {e}");
                        return false;
                    }
                };
                if guard.epoch() != expected_epoch {
                    rollback_treekem_group_after_failed_install(
                        state,
                        &resolved_group_key,
                        &info,
                        &rollback_snapshot,
                        &mut guard,
                        "member_joined_add",
                    );
                    return false;
                }
                if let Err(e) = persist_treekem_and_named_groups_atomic_with_info(
                    state,
                    &resolved_group_key,
                    next.clone(),
                    &guard,
                )
                .await
                {
                    rollback_treekem_group_after_failed_install(
                        state,
                        &resolved_group_key,
                        &info,
                        &rollback_snapshot,
                        &mut guard,
                        "member_joined_add",
                    );
                    tracing::error!(group_id = %LogHexId::group(&resolved_group_key), "failed to persist TreeKEM snapshot after invite add: {e}");
                    return false;
                }
                treekem_epoch = Some(expected_epoch);
                treekem_commit = Some(out.commit);
                treekem_welcome = Some(out.welcome);
                commit
            } else {
                match next.seal_commit(signing_kp, now_ms) {
                    Ok(commit) => commit,
                    Err(e) => {
                        tracing::warn!(
                            group_id = %LogHexId::group(&resolved_group_key),
                            member = %LogHexId::agent(&member_agent_id),
                            "MemberJoined: failed to seal authoritative add: {e}"
                        );
                        return false;
                    }
                }
            };
            let metadata_topic = next.metadata_topic.clone();
            let event_group_id = next.stable_group_id().to_string();
            if !store_named_group_info(state, &resolved_group_key, next.clone()).await {
                return false;
            }

            // Persist and expose the committed roster before any slower MLS or
            // discovery-card side effects. Tests and operators poll
            // /groups/:id/members and /diagnostics/groups as the acceptance
            // signal for this path.
            save_named_groups(state).await;
            state
                .groups_diagnostics
                .record_member_joined(&resolved_group_key);

            if treekem_epoch.is_none() {
                if let Ok(member_id) = parse_agent_id_hex(&member_agent_id) {
                    let mut mls_groups = state.mls_groups.write().await;
                    if let Some(group) = mls_groups.get_mut(&resolved_group_key) {
                        if !group.is_member(&member_id) {
                            let _ = group.add_member(member_id).await;
                        }
                    }
                }
                save_mls_groups(state).await;
            }
            let welcome_ref = if let Some(welcome) = treekem_welcome.take() {
                Some(stage_treekem_welcome(state, &event_group_id, &member_agent_id, welcome).await)
            } else {
                None
            };
            let member_joined_recovery = if let Some(original) = recovery_original.as_ref() {
                match attest_member_joined_recovery_event(original, signing_kp, &commit) {
                    Ok(attested) => Some(Box::new(attested)),
                    Err(e) => {
                        tracing::error!(group_id = %LogHexId::group(&resolved_group_key), "failed to attest accepted MemberJoined recovery record: {e}");
                        return false;
                    }
                }
            } else {
                None
            };
            if let Some(recovery) = member_joined_recovery.as_deref() {
                cache_treekem_member_key_package(
                    state,
                    join_result_key(&group_id, &member_agent_id),
                    recovery.clone(),
                    true,
                )
                .await;
            }
            let mut seen = HashSet::new();
            let member_recovery_deliveries = state
                .treekem_member_key_packages
                .events_matching(|recovery| {
                    let NamedGroupMetadataEvent::MemberJoined {
                        member_agent_id: recovered_member,
                        ..
                    } = recovery
                    else {
                        return false;
                    };
                    recovered_member != &member_agent_id
                        && seen.insert(recovered_member.clone())
                        && verify_authority_attested_member_joined_recovery(&next, recovery)
                })
                .await;
            let event = NamedGroupMetadataEvent::MemberAdded {
                group_id: event_group_id.clone(),
                revision,
                actor: inviter_agent_id.clone(),
                agent_id: member_agent_id.clone(),
                display_name: display_name.clone(),
                treekem_commit_b64: treekem_commit.map(|c| BASE64.encode(c)),
                treekem_welcome_b64: None,
                welcome_ref,
                treekem_epoch,
                treekem_key_package_hash: next
                    .members_v2
                    .get(&member_agent_id)
                    .and_then(|member| member.treekem_key_package_hash.clone()),
                member_joined_recovery: None,
                member_recovery_history: Vec::new(),
                commit: Some(commit),
            };
            stage_join_result(state, &event_group_id, &member_agent_id, event.clone()).await;
            publish_named_group_metadata_event(state, &metadata_topic, &event).await;
            remember_treekem_membership_event(state, &event).await;
            spawn_named_group_event_delivery_to_active_members(
                state,
                &next,
                &event,
                std::slice::from_ref(&member_agent_id),
            );
            if let Some(recovery) = member_joined_recovery.as_deref() {
                spawn_named_group_event_delivery_to_active_members(state, &next, recovery, &[]);
            }
            // Deliver each prior recovery record independently. Every payload stays
            // below the DM limit; group size cannot make the Welcome event oversized.
            for recovery in member_recovery_deliveries {
                spawn_named_group_event_delivery(state, &member_agent_id, &recovery);
                spawn_named_group_event_delivery_after(
                    state,
                    &member_agent_id,
                    &recovery,
                    GROUP_BACKGROUND_PUBLISH_DELAY,
                );
            }
            maybe_publish_group_card_after_state_change(state, &resolved_group_key).await;
            tracing::info!(
                group_id = %resolved_group_key,
                member = %member_agent_id,
                inviter = %inviter_agent_id,
                "MemberJoined: accepted and published authoritative MemberAdded commit"
            );
            false
        }
    }
}

async fn ensure_named_group_metadata_listener(state: Arc<AppState>, group_id: &str) {
    if state
        .group_metadata_tasks
        .read()
        .await
        .contains_key(group_id)
    {
        return;
    }

    let metadata_topic = {
        let groups = state.named_groups.read().await;
        groups.get(group_id).and_then(|g| {
            if g.withdrawn {
                None
            } else {
                Some(g.metadata_topic.clone())
            }
        })
    };
    let Some(metadata_topic) = metadata_topic else {
        return;
    };
    let mut sub = match state.agent.subscribe(&metadata_topic).await {
        Ok(sub) => sub,
        Err(e) => {
            tracing::warn!(group_id = %LogHexId::group(&group_id), topic = %LogHexId::topic(&metadata_topic), "failed to subscribe to named-group metadata topic: {e}");
            return;
        }
    };
    let group_id = group_id.to_string();
    let task_group_id = group_id.clone();
    let state_for_task = Arc::clone(&state);
    let handle = tokio::spawn(async move {
        let mut shutdown_rx = state_for_task.shutdown_notify.subscribe();
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                maybe_msg = sub.recv() => {
                    let Some(msg) = maybe_msg else { break; };
                    let Some(sender) = msg.sender else { continue; };
                    let Ok(event) = serde_json::from_slice::<NamedGroupMetadataEvent>(&msg.payload) else { continue; };
                    let should_exit = apply_named_group_metadata_event(&state_for_task, event, sender, msg.verified).await;
                    if should_exit { break; }
                }
            }
        }
        state_for_task
            .group_metadata_tasks
            .write()
            .await
            .remove(&task_group_id);
    });

    state
        .group_metadata_tasks
        .write()
        .await
        .insert(group_id, handle);
}

/// Spawn every gossip listener a member needs for a named group.
///
/// Members must be subscribed to both the metadata topic *and* the
/// public-message topic (`x0x.groups.public.<stable_id>`) before any peer
/// can publish, otherwise the very first signed-public message is silently
/// dropped at the receiver's pubsub layer (Plumtree cannot backfill messages
/// on a topic that had no subscriber at receive time). This helper enforces
/// that invariant in one place — every site that inserts a group into
/// `state.named_groups` must call it.
///
/// Both inner spawners are idempotent, so calling this repeatedly for the
/// same `group_id` is safe. The public-message listener is gated on
/// `confidentiality != MlsEncrypted` to match the convention in
/// `GET /groups/:id/messages`, which rejects MLS-encrypted groups outright.
pub(in crate::server) async fn ensure_named_group_listeners(state: Arc<AppState>, group_id: &str) {
    ensure_named_group_metadata_listener(Arc::clone(&state), group_id).await;
    let public_topic_key = {
        let groups = state.named_groups.read().await;
        groups.get(group_id).and_then(|info| {
            if info.withdrawn
                || info.policy.confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted
            {
                None
            } else {
                Some(info.stable_group_id().to_string())
            }
        })
    };
    if let Some(stable_id) = public_topic_key {
        spawn_public_message_listener(state, stable_id).await;
    }
}

/// POST /groups — create a named group.
pub(in crate::server) async fn create_named_group(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateGroupRequest>,
) -> impl IntoResponse {
    // Generate random MLS group ID
    let mut group_id_bytes = vec![0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut group_id_bytes);
    let group_id_hex = hex::encode(&group_id_bytes);

    let agent_id = state.agent.agent_id();

    // Resolve policy preset (defaults to private_secure).
    let policy = match req.preset.as_deref() {
        Some(name) => match x0x::groups::GroupPolicyPreset::from_name(name) {
            Some(preset) => preset.to_policy(),
            None => {
                return bad_request("unknown preset");
            }
        },
        None => x0x::groups::GroupPolicy::default(),
    };

    // Create the legacy demo MLS group object (kept for the `/mls/groups/:id`
    // surface). `.clone()` because the real-TreeKEM routing below also needs
    // the raw group-id bytes.
    match x0x::mls::MlsGroup::new(group_id_bytes.clone(), agent_id).await {
        Ok(group) => {
            // Create group metadata with explicit policy.
            let mut info = x0x::groups::GroupInfo::with_policy(
                req.name,
                req.description,
                agent_id,
                group_id_hex.clone(),
                policy,
            );
            // Record the owner's ML-KEM-768 public key so the roster knows
            // where to seal future group-shared-secret envelopes.
            {
                use base64::Engine as _;
                let owner_hex = hex::encode(agent_id.as_bytes());
                let owner_kem_b64 = BASE64.encode(&state.agent_kem_keypair.public_bytes);
                info.set_member_kem_public_key(&owner_hex, owner_kem_b64);
            }

            // Set creator's display name if provided
            if let Some(dn) = req.display_name {
                info.set_display_name(&hex::encode(agent_id.as_bytes()), dn);
            }

            // ADR-0012 Phase 2: new PRIVATE (Hidden) MlsEncrypted groups are
            // secure-by-default real TreeKEM (FS/PCS), NOT the legacy GSS
            // shared-secret plane. Public encrypted presets (e.g.
            // `public_request_secure`, PublicDirectory) deliberately stay on the
            // GSS plane — their cross-daemon join-request review converges via
            // the D4 signed-commit path, which the single-committer TreeKEM
            // transport does not provide. This matches ADR-0012's scope ("all
            // new private groups secure-by-default TreeKEM"); gating on
            // MlsEncrypted alone was too broad and swept in public request-secure
            // groups, breaking their join-request convergence.
            // Build the live TreeKEM group (creator = sole leaf 0), persist its
            // snapshot at rest, then relabel `info` so no surface claims GSS for
            // it (drop the GSS shared secret, bind the TreeKEM epoch into the
            // signed state hash). If TreeKEM setup or persistence fails we fail
            // the request rather than store a group mislabelled as secure.
            if info.policy.confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted
                && info.policy.discoverability == x0x::groups::GroupDiscoverability::Hidden
            {
                let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
                let tk = match x0x::mls::TreeKemMlsGroup::create(
                    group_id_bytes.clone(),
                    agent_id,
                    &seed,
                ) {
                    Ok(tk) => tk,
                    Err(e) => {
                        tracing::error!(group_id = %group_id_hex, "failed to create TreeKEM group: {e}");
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("failed to create secure group: {e}"),
                        );
                    }
                };
                let creator_package = match x0x::mls::TreeKemMlsGroup::prepare_member(
                    agent_id, &seed,
                ) {
                    Ok(prepared) => BASE64.encode(prepared.key_package_bytes()),
                    Err(e) => {
                        tracing::error!(group_id = %group_id_hex, "failed to prepare creator recovery package: {e}");
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("failed to prepare creator recovery package: {e}"),
                        );
                    }
                };
                let creator_hex = hex::encode(agent_id.as_bytes());
                info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
                info.shared_secret = None;
                info.secret_epoch = tk.epoch();
                info.set_member_treekem_key_package(&creator_hex, creator_package.clone());
                let creator_recovery_original = NamedGroupMetadataEvent::MemberJoined {
                    group_id: group_id_hex.clone(),
                    stable_group_id: Some(info.stable_group_id().to_string()),
                    member_agent_id: creator_hex.clone(),
                    member_public_key_b64: String::new(),
                    role: info
                        .caller_role(&creator_hex)
                        .unwrap_or(x0x::groups::GroupRole::Admin),
                    display_name: info
                        .members_v2
                        .get(&creator_hex)
                        .and_then(|member| member.display_name.clone()),
                    inviter_agent_id: creator_hex.clone(),
                    invite_secret: String::new(),
                    ts_ms: info
                        .genesis
                        .as_ref()
                        .map_or(info.created_at, |genesis| genesis.created_at),
                    treekem_key_package_b64: Some(creator_package),
                    recovery_authority_agent_id: None,
                    recovery_authority_public_key_b64: None,
                    recovery_authority_signature_b64: None,
                    recovery_authority_commit: None,
                    signature_b64: String::new(),
                };
                let Some(binding) =
                    treekem_recovery_security_binding(tk.epoch(), &creator_recovery_original)
                else {
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to bind creator recovery record",
                    );
                };
                info.security_binding = Some(binding);
                let creator_commit = match info
                    .seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())
                {
                    Ok(commit) => commit,
                    Err(e) => {
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("failed to seal creator recovery commit: {e}"),
                        );
                    }
                };
                let creator_recovery = match attest_member_joined_recovery_event(
                    &creator_recovery_original,
                    state.agent.identity().agent_keypair(),
                    &creator_commit,
                ) {
                    Ok(recovery) => recovery,
                    Err(e) => {
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("failed to attest creator recovery package: {e}"),
                        );
                    }
                };
                cache_treekem_member_key_package(
                    &state,
                    join_result_key(&group_id_hex, &creator_hex),
                    creator_recovery,
                    true,
                )
                .await;
                state
                    .treekem_groups
                    .write()
                    .await
                    .insert(group_id_hex.clone(), Arc::new(tokio::sync::Mutex::new(tk)));
            }

            // Store MLS group
            state
                .mls_groups
                .write()
                .await
                .insert(group_id_hex.clone(), group);
            save_mls_groups(&state).await;

            let chat_topic = info.general_chat_topic();

            // Store group info and persist to disk
            state
                .named_groups
                .write()
                .await
                .insert(group_id_hex.clone(), info.clone());
            if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                let group = {
                    let map = state.treekem_groups.read().await;
                    map.get(&group_id_hex).cloned()
                };
                if let Some(group) = group {
                    let guard = group.lock().await;
                    if let Err(e) =
                        persist_treekem_and_named_groups_atomic(&state, &group_id_hex, &guard).await
                    {
                        tracing::error!(group_id = %group_id_hex, "failed to atomically persist TreeKEM group create: {e}");
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("failed to persist secure group: {e}"),
                        );
                    }
                }
            } else {
                save_named_groups(&state).await;
            }
            ensure_named_group_listeners(Arc::clone(&state), &group_id_hex).await;

            // P0-1: If the group is discoverable, publish its card to the global
            // discovery topic so other daemons find it without manual import.
            //
            // The discovery-card fan-out is a best-effort gossip publish to
            // the global topic plus N tag/name/id shards. Each publish goes
            // through the gossip runtime, which can block tens of seconds
            // under sustained pubsub back-pressure (e.g. release-manifest
            // floods). Spawning the fan-out keeps `POST /groups` sub-second
            // even on a saturated daemon — local state is already committed
            // so the group is fully created from the caller's perspective.
            if info.policy.discoverability != x0x::groups::GroupDiscoverability::Hidden {
                match info.to_signed_group_card(state.agent.identity().agent_keypair()) {
                    Ok(Some(card)) => {
                        let stable_group_id = info.stable_group_id().to_string();
                        let mut cache = state.group_card_cache.write().await;
                        prune_expired_group_cards(&mut cache, now_millis_u64());
                        cache_group_card_if_newer(&mut cache, group_id_hex.clone(), card.clone());
                        cache_group_card_if_newer(&mut cache, stable_group_id, card);
                        enforce_group_card_cache_cap(&mut cache);
                        drop(cache);
                        let state_for_card = Arc::clone(&state);
                        let group_id_for_card = group_id_hex.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(GROUP_BACKGROUND_PUBLISH_DELAY).await;
                            publish_group_card_to_discovery(
                                state_for_card.as_ref(),
                                &group_id_for_card,
                            )
                            .await;
                        });
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(group_id = %group_id_hex, "failed to sign initial group card: {e}");
                    }
                }
            }

            // Announce creation on the chat topic — fire-and-forget. The
            // response did not depend on this completing pre-fix either
            // (the result was already discarded with `let _ = ...`); moving
            // it off the request task keeps the handler unblocked when the
            // gossip publish path is slow.
            let agent_hex = hex::encode(agent_id.as_bytes());
            let display = info
                .display_names
                .get(&agent_hex)
                .cloned()
                .unwrap_or_else(|| agent_hex[..8].to_string());
            let announcement = serde_json::json!({
                "type": "group_event",
                "event": "created",
                "agent_id": agent_hex,
                "display_name": display,
                "group_name": info.name,
                "ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });
            let state_for_chat = Arc::clone(&state);
            let chat_topic_for_chat = chat_topic.clone();
            let announcement_bytes = announcement.to_string().into_bytes();
            tokio::spawn(async move {
                tokio::time::sleep(GROUP_BACKGROUND_PUBLISH_DELAY).await;
                if let Err(e) = state_for_chat
                    .agent
                    .publish(&chat_topic_for_chat, announcement_bytes)
                    .await
                {
                    tracing::debug!(topic = %chat_topic_for_chat, "chat-create publish failed: {e}");
                }
            });

            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "ok": true,
                    "group_id": group_id_hex,
                    "name": info.name,
                    "chat_topic": chat_topic,
                })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /groups — list all named groups.
pub(in crate::server) async fn list_named_groups(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let groups = state.named_groups.read().await;
    let entries: Vec<serde_json::Value> = groups
        .values()
        .map(|info| {
            let member_count = named_group_member_values(info).len();
            serde_json::json!({
                "group_id": info.mls_group_id,
                "name": info.name,
                "description": info.description,
                "creator": hex::encode(info.creator.as_bytes()),
                "created_at": info.created_at,
                "member_count": member_count,
            })
        })
        .collect();
    Json(serde_json::json!({ "ok": true, "groups": entries }))
}

/// GET /groups/:id — get group details.
pub(in crate::server) async fn get_named_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    let members = named_group_member_values(info);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": info.mls_group_id,
            "name": info.name,
            "description": info.description,
            "creator": hex::encode(info.creator.as_bytes()),
            "created_at": info.created_at,
            "updated_at": info.updated_at,
            "chat_topic": info.general_chat_topic(),
            "metadata_topic": info.metadata_topic,
            "policy": info.policy,
            "policy_revision": info.policy_revision,
            "roster_revision": info.roster_revision,
            "member_count": members.len(),
            "members": members,
        })),
    )
}

/// GET /groups/:id/members — list local named-group members.
pub(in crate::server) async fn get_named_group_members(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    let members = named_group_member_values(info);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": id,
            "member_count": members.len(),
            "members": members,
        })),
    )
}

// ──────────────────────── Phase E: public messaging ────────────────────

/// Maximum number of public messages retained per group. Older entries
/// are dropped on insert (ring-buffer style).
const PUBLIC_MESSAGE_HISTORY_CAP: usize = 512;

/// Stable fleet-wide anti-entropy topic for SignedPublic messages.
///
/// Fresh per-group topics can have asymmetric PlumTree reachability during the
/// first seconds after a cross-region join. Publishing each public message to
/// this long-lived topic as well gives already-subscribed daemons a stable
/// fallback path while receivers still validate/cache only messages for groups
/// they know locally.
const GLOBAL_PUBLIC_MESSAGE_TOPIC: &str = "x0x.groups.public.v1";

pub(in crate::server) const GROUP_PUBLIC_MESSAGE_DM_PREFIX: &[u8] = b"X0X-GROUP-PUBLIC-V1\n";

/// Request body for `POST /groups/:id/send`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct SendGroupMessageRequest {
    /// Message body (UTF-8). Required.
    body: String,
    /// Message kind — `"chat"` (default) or `"announcement"`.
    #[serde(default)]
    kind: Option<String>,
}

/// POST /groups/:id/send — publish a message to the group.
///
/// Branches on `policy.confidentiality`:
///
/// - `SignedPublic` — builds a signed `GroupPublicMessage`, publishes
///   to `x0x.groups.public.{group_id}`, and caches it locally.
///   Write-access is enforced at endpoint time (same rules as
///   `x0x::groups::validate_public_message` applies at ingest).
/// - `MlsEncrypted` — not supported on this endpoint yet; callers
///   should use `/groups/:id/secure/encrypt` (Phase D.2).
pub(in crate::server) async fn send_group_public_message(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<SendGroupMessageRequest>,
) -> impl IntoResponse {
    let kind = match req.kind.as_deref().unwrap_or("chat") {
        "chat" => x0x::groups::GroupPublicMessageKind::Chat,
        "announcement" => x0x::groups::GroupPublicMessageKind::Announcement,
        other => {
            return bad_request(format!(
                "unknown kind '{other}' (expected 'chat' or 'announcement')"
            ));
        }
    };

    if req.body.len() > x0x::groups::MAX_PUBLIC_MESSAGE_BYTES {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body exceeds MAX_PUBLIC_MESSAGE_BYTES",
        );
    }

    let signing_kp = state.agent.identity().agent_keypair();
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Build + endpoint-side authz + sign under the write lock so
    // concurrent role changes can't race the check.
    let (msg, direct_recipients) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return not_found("group not found");
        };
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if info.policy.confidentiality != x0x::groups::GroupConfidentiality::SignedPublic {
            return bad_request("group is not SignedPublic — use /groups/:id/secure/encrypt");
        }
        if info.is_banned(&local_hex) {
            return forbidden("you are banned");
        }
        // Endpoint-side write-access enforcement. Mirror the ingest
        // validator so we reject locally rather than trust receivers.
        let caller_role = info.caller_role(&local_hex);
        match info.policy.write_access {
            x0x::groups::GroupWriteAccess::MembersOnly => {
                if caller_role.is_none() {
                    return forbidden("members-only write policy");
                }
            }
            x0x::groups::GroupWriteAccess::ModeratedPublic => { /* any non-banned */ }
            x0x::groups::GroupWriteAccess::AdminOnly => {
                let ok = caller_role
                    .map(|r| r.at_least(x0x::groups::GroupRole::Admin))
                    .unwrap_or(false);
                if !ok {
                    return forbidden("admin-only write policy");
                }
            }
        }
        let direct_recipients = info
            .active_members()
            .filter(|member| !member.agent_id.eq_ignore_ascii_case(&local_hex))
            .map(|member| member.agent_id.clone())
            .collect::<Vec<_>>();

        match x0x::groups::GroupPublicMessage::sign(
            info.stable_group_id().to_string(),
            info.state_hash.clone(),
            info.state_revision,
            signing_kp,
            None,
            kind,
            req.body,
            now_ms,
        ) {
            Ok(m) => (m, direct_recipients),
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("sign failed: {e}"),
                );
            }
        }
    };

    // Subscribe locally before publishing so the sender's pubsub runtime has
    // the topic fully initialised before the first outbound message. This makes
    // reverse-direction cross-daemon receive far more reliable on fresh topics.
    spawn_public_message_listener(Arc::clone(&state), msg.group_id.clone()).await;

    let topic = x0x::groups::public_topic_for(&msg.group_id);
    let bytes = match serde_json::to_vec(&msg) {
        Ok(b) => b,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("serialize failed: {e}"),
            );
        }
    };
    if let Err(e) = state.agent.publish(&topic, bytes.clone()).await {
        tracing::warn!(topic = %LogHexId::topic(&topic), "E: public-send publish failed: {e}");
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("publish failed: {e}"),
        );
    }
    if let Err(e) = state
        .agent
        .publish(GLOBAL_PUBLIC_MESSAGE_TOPIC, bytes)
        .await
    {
        tracing::warn!(
            topic = GLOBAL_PUBLIC_MESSAGE_TOPIC,
            group_id = %msg.group_id,
            "E: global public-send fallback publish failed: {e}"
        );
    }
    // Publish succeeded, so cache locally. The listener was started before the
    // publish above to avoid first-message topic races.
    cache_public_message(&state, msg.clone()).await;
    spawn_group_public_message_delivery_to_active_members(&state, direct_recipients, &msg);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": msg.group_id,
            "topic": topic,
            "fallback_topic": GLOBAL_PUBLIC_MESSAGE_TOPIC,
            "timestamp": msg.timestamp,
        })),
    )
}

/// GET /groups/:id/messages — retrieve cached public messages.
///
/// If `policy.read_access == Public`, any caller with a valid API
/// token receives the history. If `MembersOnly`, only active members
/// receive it. For `MlsEncrypted` groups, returns 400 — encrypted
/// history belongs in a different surface.
pub(in crate::server) async fn get_group_public_messages(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    // Resolve the stable_group_id — the public-message cache and topic
    // are keyed on it, while the URL `:id` is typically the
    // mls_group_id for a locally-owned group.
    let (read_access, confidentiality, is_member, stable_id) = {
        let groups = state.named_groups.read().await;
        if let Some(info) = groups.get(&id) {
            if let Some(resp) = reject_withdrawn_group(info) {
                return resp;
            }
            (
                info.policy.read_access,
                info.policy.confidentiality,
                info.has_active_member(&local_hex),
                info.stable_group_id().to_string(),
            )
        } else {
            // Unknown locally — fall through to cache lookup by the
            // supplied id; this supports non-members reading a
            // discovered Public group whose mls_group_id == stable.
            drop(groups);
            (
                x0x::groups::GroupReadAccess::Public,
                x0x::groups::GroupConfidentiality::SignedPublic,
                false,
                id.clone(),
            )
        }
    };
    if confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted {
        return bad_request("MlsEncrypted groups do not publish a plaintext message history");
    }
    if read_access == x0x::groups::GroupReadAccess::MembersOnly && !is_member {
        return forbidden("members-only read policy");
    }

    // Ensure the listener is live on the stable-id topic.
    spawn_public_message_listener(Arc::clone(&state), stable_id.clone()).await;

    let cached = state
        .public_messages
        .read()
        .await
        .get(&stable_id)
        .cloned()
        .unwrap_or_default();

    // ADR-0023 §7: the durable store is the source of truth beyond the
    // in-memory hot tail — history survives a daemon restart. Store rows
    // carry the signed `GroupPublicMessage` JSON verbatim as their
    // `signed_artifact`, so rows deserialize back to the exact wire form.
    let msgs = match state.agent.history() {
        Some(history) => {
            let store = std::sync::Arc::clone(history.store());
            let stable = stable_id.clone();
            let stored = tokio::task::spawn_blocking(move || {
                let q = x0x::history::HistoryQuery {
                    scope: Some(x0x::history::Scope::Group(stable)),
                    limit: 500,
                    ..Default::default()
                };
                store.query(&q)
            })
            .await;
            match stored {
                Ok(Ok(rows)) => {
                    let mut merged: Vec<x0x::groups::GroupPublicMessage> = rows
                        .iter()
                        .filter_map(|r| r.record.signed_artifact.as_deref())
                        .filter_map(|a| serde_json::from_slice(a).ok())
                        .collect();
                    let mut seen: std::collections::HashSet<String> =
                        merged.iter().map(|m| m.signature.clone()).collect();
                    for m in cached {
                        if seen.insert(m.signature.clone()) {
                            merged.push(m);
                        }
                    }
                    merged.sort_by_key(|m| m.timestamp);
                    merged
                }
                _ => cached,
            }
        }
        None => cached,
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "messages": msgs })),
    )
}

/// Record a validated group public message durably (ADR-0023 §4).
///
/// Called from the single convergence point every delivery path funnels
/// through (`cache_public_message`), so per-group topic, global fallback,
/// and DM direct-push all record exactly once — the store dedupes on
/// `msg_id = BLAKE3(signed JSON)`.
fn record_group_public_history(state: &AppState, msg: &x0x::groups::GroupPublicMessage) {
    let Some(history) = state.agent.history() else {
        return;
    };
    if msg.body.is_empty() {
        return;
    }
    let Ok(artifact) = serde_json::to_vec(msg) else {
        return;
    };
    let self_hex = hex::encode(state.agent.agent_id().as_bytes());
    let outbound = msg.author_agent_id == self_hex;
    let payload = msg.body.as_bytes().to_vec();
    let now = i64::try_from(x0x::dm::now_unix_ms()).unwrap_or(i64::MAX);
    history.record(x0x::history::HistoryRecord {
        msg_id: x0x::history::HistoryRecord::compute_msg_id(Some(&artifact), &payload),
        scope: x0x::history::Scope::Group(msg.group_id.clone()),
        author_agent: Some(msg.author_agent_id.clone()),
        author_machine: None,
        author_pubkey: hex::decode(&msg.author_public_key).ok(),
        sent_at_ms: i64::try_from(msg.timestamp).unwrap_or(i64::MAX),
        seen_at_ms: now,
        direction: if outbound {
            x0x::history::Direction::Outbound
        } else {
            x0x::history::Direction::Inbound
        },
        content_type: "text/plain".to_string(),
        payload,
        signed_artifact: Some(artifact),
        signature: hex::decode(&msg.signature).ok(),
        // Mirrors `groups::public_message::PUBLIC_MESSAGE_DOMAIN`.
        sig_context: Some("x0x.group.public-message.v1".to_string()),
        provenance: if outbound {
            x0x::history::Provenance::LocalSend
        } else {
            x0x::history::Provenance::VerifiedEnvelope
        },
        replace_key: None,
    });
}

/// Record MLS-group plaintext obtained via a local secure-surface call
/// (ADR-0023 §3/§4): unsigned, `provenance = LocalAppDecrypt`, author
/// unattributed — no per-message author signature exists on this plane.
/// `msg_id = BLAKE3(plaintext)` dedupes replays of the same ciphertext.
fn record_mls_history(
    state: &AppState,
    stable_group_id: &str,
    plaintext: &[u8],
    direction: x0x::history::Direction,
    epoch: u64,
) {
    let Some(history) = state.agent.history() else {
        return;
    };
    if plaintext.is_empty() {
        return;
    }
    let content_type = if std::str::from_utf8(plaintext).is_ok() {
        "text/plain"
    } else {
        "application/octet-stream"
    };
    let now = i64::try_from(x0x::dm::now_unix_ms()).unwrap_or(i64::MAX);
    // Epoch-salted id: ciphertext replays within an epoch dedupe, identical
    // plaintext across epochs survives. Identical plaintext *within* one
    // epoch still collapses — per-message MLS identity is a future
    // wire-format change (ADR-0023 §3).
    history.record(x0x::history::HistoryRecord {
        msg_id: x0x::history::HistoryRecord::compute_epoch_msg_id(epoch, plaintext),
        scope: x0x::history::Scope::Group(stable_group_id.to_string()),
        author_agent: None,
        author_machine: None,
        author_pubkey: None,
        sent_at_ms: now,
        seen_at_ms: now,
        direction,
        content_type: content_type.to_string(),
        payload: plaintext.to_vec(),
        signed_artifact: None,
        signature: None,
        sig_context: None,
        provenance: x0x::history::Provenance::LocalAppDecrypt,
        replace_key: None,
    });
}

/// Append a validated message to the per-group ring buffer (capped).
async fn cache_public_message(state: &AppState, msg: x0x::groups::GroupPublicMessage) {
    record_group_public_history(state, &msg);
    let mut all = state.public_messages.write().await;
    let slot = all.entry(msg.group_id.clone()).or_default();
    // Deduplicate by the stable message identity (`signature`) rather
    // than a lossy (author,timestamp,body) tuple so legitimate repeated
    // bodies sent in the same millisecond are still preserved.
    let dup = slot.iter().any(|m| m.signature == msg.signature);
    if !dup {
        slot.push(msg);
        while slot.len() > PUBLIC_MESSAGE_HISTORY_CAP {
            slot.remove(0);
        }
    }
}

fn encode_group_public_message_direct_payload(
    msg: &x0x::groups::GroupPublicMessage,
) -> serde_json::Result<Vec<u8>> {
    let json = serde_json::to_vec(msg)?;
    let mut payload = Vec::with_capacity(GROUP_PUBLIC_MESSAGE_DM_PREFIX.len() + json.len());
    payload.extend_from_slice(GROUP_PUBLIC_MESSAGE_DM_PREFIX);
    payload.extend_from_slice(&json);
    Ok(payload)
}

fn group_public_message_direct_delivery_config() -> x0x::dm::DmSendConfig {
    let mut config = named_group_direct_delivery_config();
    config.require_gossip = true;
    config.require_gossip_ack = true;
    config
}

fn spawn_group_public_message_delivery(
    state: &AppState,
    recipient_hex: &str,
    msg: &x0x::groups::GroupPublicMessage,
    delay: Option<Duration>,
) {
    let recipient = match parse_agent_id_hex(recipient_hex) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(
                recipient = %LogHexId::agent(&recipient_hex),
                "cannot direct-deliver public group message: invalid recipient id: {e}"
            );
            return;
        }
    };
    let payload = match encode_group_public_message_direct_payload(msg) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!("failed to serialize public group message for direct delivery: {e}");
            return;
        }
    };
    let agent = Arc::clone(&state.agent);
    let recipient_label = recipient_hex.to_string();
    let group_id = msg.group_id.clone();
    tokio::spawn(async move {
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        if let Err(e) = agent
            .send_direct_with_config(
                &recipient,
                payload,
                group_public_message_direct_delivery_config(),
            )
            .await
        {
            tracing::warn!(
                group_id = %LogHexId::group(&group_id),
                recipient = %LogHexId::agent(&recipient_label),
                "failed to direct-deliver public group message: {e}"
            );
        }
    });
}

fn spawn_group_public_message_delivery_to_active_members(
    state: &AppState,
    recipients: Vec<String>,
    msg: &x0x::groups::GroupPublicMessage,
) {
    for recipient in recipients {
        spawn_group_public_message_delivery(state, &recipient, msg, None);
        spawn_group_public_message_delivery(
            state,
            &recipient,
            msg,
            Some(GROUP_BACKGROUND_PUBLISH_DELAY),
        );
    }
}

pub(in crate::server) async fn ingest_public_message(
    state: &AppState,
    msg: x0x::groups::GroupPublicMessage,
    group_id_for_log: &str,
) {
    // Validate against current group view at apply-time.
    let message_group_id = msg.group_id.clone();
    let snapshot = {
        let groups = state.named_groups.read().await;
        groups
            .get(group_id_for_log)
            .or_else(|| {
                groups.get(&message_group_id).or_else(|| {
                    groups
                        .values()
                        .find(|info| info.stable_group_id() == message_group_id.as_str())
                })
            })
            .map(|info| {
                (
                    info.policy.clone(),
                    info.members_v2.clone(),
                    info.stable_group_id().to_string(),
                    info.withdrawn,
                )
            })
    };
    let Some((policy, members, stable_id, withdrawn)) = snapshot else {
        // Unknown group — count under the stable id we were given as the
        // logging key. Useful for spotting messages that arrived before the
        // local daemon learned about the group.
        state.groups_diagnostics.record_other_drop(group_id_for_log);
        return;
    };
    if withdrawn {
        state.groups_diagnostics.record_other_drop(&stable_id);
        tracing::debug!(group_id = %group_id_for_log, "E: dropped public message for withdrawn group");
        return;
    }
    let ctx = x0x::groups::PublicIngestContext {
        group_id: &stable_id,
        policy: &policy,
        members_v2: &members,
    };
    match x0x::groups::validate_public_message(&ctx, &msg) {
        Ok(()) => {
            state
                .groups_diagnostics
                .record_message_received(&stable_id, now_millis_u64());
            cache_public_message(state, msg).await;
        }
        Err(e) => {
            // Map ingest errors to diagnostics buckets so /diagnostics/groups
            // reflects the drop fingerprint for the operator.
            match &e {
                x0x::groups::PublicMessageIngestError::AuthorBanned => {
                    state.groups_diagnostics.record_author_banned(&stable_id)
                }
                x0x::groups::PublicMessageIngestError::WritePolicyViolation { .. } => state
                    .groups_diagnostics
                    .record_write_policy_violation(&stable_id),
                x0x::groups::PublicMessageIngestError::InvalidSignature(_) => {
                    state.groups_diagnostics.record_signature_failed(&stable_id)
                }
                _ => state.groups_diagnostics.record_other_drop(&stable_id),
            }
            tracing::warn!(
                group_id = %group_id_for_log,
                author = %msg.author_agent_id,
                "E: dropped public message: {e}"
            );
        }
    }
}

pub(in crate::server) async fn spawn_global_public_message_listener(
    state: Arc<AppState>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    vec![tokio::spawn(async move {
        let mut sub = match state.agent.subscribe(GLOBAL_PUBLIC_MESSAGE_TOPIC).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    topic = GLOBAL_PUBLIC_MESSAGE_TOPIC,
                    "E: failed to subscribe to global public-message fallback: {e}"
                );
                return;
            }
        };
        tracing::info!(
            topic = GLOBAL_PUBLIC_MESSAGE_TOPIC,
            "E: global public-message fallback listener subscribed"
        );
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                maybe = sub.recv() => {
                    let Some(gossip_msg) = maybe else { break; };
                    let msg: x0x::groups::GroupPublicMessage =
                        match serde_json::from_slice(&gossip_msg.payload) {
                            Ok(m) => m,
                            Err(e) => {
                                tracing::debug!("E: dropped malformed global public msg: {e}");
                                // Without a parsed payload we don't know the
                                // group id — bucket as a generic "other"
                                // drop on a sentinel key so we never panic
                                // here. The condition is rare and visible
                                // via the daemon's own debug log too.
                                state.groups_diagnostics.record_decode_failed(
                                    "__global_public__",
                                );
                                continue;
                            }
                        };
                    let group_id_for_log = msg.group_id.clone();
                    ingest_public_message(&state, msg, &group_id_for_log).await;
                }
            }
        }
    })]
}

/// Spawn a listener on `x0x.groups.public.{group_id}`. Idempotent — a
/// duplicate call for the same group_id is a no-op.
///
/// The pubsub subscribe is completed before returning so the first public
/// message published after group creation/join cannot race ahead of the local
/// listener. The spawned task owns only the receive loop.
async fn spawn_public_message_listener(state: Arc<AppState>, group_id: String) {
    {
        let groups = state.named_groups.read().await;
        if groups
            .get(&group_id)
            .or_else(|| {
                groups
                    .values()
                    .find(|info| info.stable_group_id() == group_id.as_str())
            })
            .is_some_and(|info| info.withdrawn)
        {
            return;
        }
    }
    {
        let tasks = state.public_message_tasks.read().await;
        if tasks.contains_key(&group_id) {
            return;
        }
    }
    let topic = x0x::groups::public_topic_for(&group_id);
    let mut sub = match state.agent.subscribe(&topic).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(topic = %LogHexId::topic(&topic), "E: failed to subscribe to public chat: {e}");
            return;
        }
    };
    let state_for_listener = Arc::clone(&state);
    let group_id_for_listener = group_id.clone();
    let topic_for_log = topic.clone();
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    let handle = tokio::spawn(async move {
        tracing::info!(topic = %topic_for_log, "E: public-message listener subscribed");
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                maybe = sub.recv() => {
                    let Some(gossip_msg) = maybe else { break; };
                    let msg: x0x::groups::GroupPublicMessage =
                        match serde_json::from_slice(&gossip_msg.payload) {
                            Ok(m) => m,
                            Err(e) => {
                                tracing::debug!("E: dropped malformed public msg: {e}");
                                state_for_listener
                                    .groups_diagnostics
                                    .record_decode_failed(&group_id_for_listener);
                                continue;
                            }
                        };
                    ingest_public_message(
                        &state_for_listener,
                        msg,
                        &group_id_for_listener,
                    ).await;
                }
            }
        }
    });
    state
        .public_message_tasks
        .write()
        .await
        .insert(group_id, handle);
}

/// POST /groups/:id/invite — generate an invite link (admin+; body optional).
///
/// Authority follows ADR-0016: any active Admin-or-higher member may mint
/// invites (issue #107 — invite minting is an admission/routing act, not a
/// creator-cryptographic one). The route checks the caller's role against
/// its daemon's LOCAL roster view, which may lag convergence (a just-demoted
/// admin can still mint until the demotion applies locally). That is safe,
/// not a bypass: the joiner's `MemberJoined` routes to the minting admin,
/// which authors the authority-signed `MemberAdded` commit, and every
/// receiver's `validate_apply` enforces `AdminOrHigher` against ITS
/// converged roster — a commit signed by a no-longer-admin fails group-wide,
/// so a stale invite never produces unauthorized membership.
pub(in crate::server) async fn create_group_invite(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let req: CreateInviteRequest = match parse_optional_json(&headers, &body) {
        Ok(r) => r,
        Err(resp) => return resp.into_response(),
    };
    // Serialize this group-state mutation against concurrent membership applies
    // and the other API mutators (see `AppState::group_membership_locks`): every
    // read-modify-write of one group's `GroupInfo` must hold this lock, or a
    // stale-clone apply storing afterward overwrites the invite we record here.
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;
    let (link, mls_group_id, group_name, expires_at) = {
        let mut groups = state.named_groups.write().await;
        let Some(info) = groups.get_mut(&id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "ok": false, "error": "group not found" })),
            )
                .into_response();
        };

        let agent_id = state.agent.agent_id();
        let inviter_hex = hex::encode(agent_id.as_bytes());
        if let Err(e) = require_admin_or_above(info, &inviter_hex) {
            return e.into_response();
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp.into_response();
        }
        let mut invite = x0x::groups::invite::SignedInvite::new(
            info.mls_group_id.clone(),
            info.name.clone(),
            &agent_id,
            req.expiry_secs,
        );
        populate_invite_base_state_from_group_info(&mut invite, info);

        // Track this one-time secret on the inviter so a future
        // MemberJoined request carrying it can be authenticated, role-capped,
        // expiry-checked, and consumed locally before the inviter publishes an
        // authority-signed MemberAdded commit.
        info.record_issued_invite(
            invite.invite_secret.clone(),
            invite.created_at,
            invite.expires_at,
            x0x::groups::GroupRole::Member,
        );

        // Issue #205: enforce the DM-safe budget at mint so a roster that
        // would blow the gossip-DM cap fails loudly here, not as an opaque
        // `envelope_construction` rejection at /direct/send later (issue
        // #188; that path now reports `payload_too_large` 413).
        let link = match invite.encode_link() {
            Ok(link) => link,
            Err(e) => {
                tracing::warn!(
                    group_id = %LogHexId::group(&id),
                    actual = e.actual,
                    limit = e.limit,
                    "refusing to mint oversized invite link: {e}"
                );
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(serde_json::json!({
                        "ok": false,
                        "error": "invite_too_large",
                        "detail": e.to_string(),
                        "actual_bytes": e.actual,
                        "limit_bytes": e.limit,
                    })),
                )
                    .into_response();
            }
        };
        let mls_group_id = info.mls_group_id.clone();
        let group_name = info.name.clone();
        let expires_at = invite.expires_at;
        (link, mls_group_id, group_name, expires_at)
    };
    save_named_groups(&state).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "invite_link": link,
            "group_id": mls_group_id,
            "group_name": group_name,
            "expires_at": expires_at,
        })),
    )
        .into_response()
}

fn invite_join_group_info(
    invite: &x0x::groups::invite::SignedInvite,
    creator: AgentId,
    creator_hex: &str,
    group_id_hex: &str,
    joiner_hex: &str,
    display_name: Option<String>,
    treekem_key_package_b64: Option<String>,
) -> x0x::groups::GroupInfo {
    let invite_is_treekem = invite.secure_plane == Some(x0x::mls::SecureGroupPlane::TreeKem);
    let has_authority_base_state = invite.base_state_hash.is_some();

    // Create group info from invite. D.4 requires the joiner to seed
    // the same stable group identity + policy snapshot as the authority
    // so later signed state commits can chain from the same base.
    let mut info = x0x::groups::GroupInfo::with_policy(
        invite.group_name.clone(),
        invite.group_description.clone().unwrap_or_default(),
        creator,
        group_id_hex.to_string(),
        invite.policy.clone().unwrap_or_default(),
    );
    if let Some(group_created_at) = invite.group_created_at {
        info.created_at = group_created_at;
    }
    if let Some(stable_group_id) = invite.stable_group_id.clone() {
        info.genesis = Some(x0x::groups::GroupGenesis::with_existing_id(
            stable_group_id,
            creator_hex.to_string(),
            info.created_at,
            invite
                .genesis_creation_nonce
                .clone()
                .unwrap_or_else(|| hex::encode(blake3::hash(group_id_hex.as_bytes()).as_bytes())),
        ));
    }
    if let Some(secure_plane) = invite.secure_plane {
        info.secure_plane = secure_plane;
    }
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        info.shared_secret = None;
    }
    if let Some(base_secret_epoch) = invite.base_secret_epoch {
        info.secret_epoch = base_secret_epoch;
    }
    if let Some(base_security_binding) = invite.base_security_binding.clone() {
        info.security_binding = Some(base_security_binding);
    } else if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        info.security_binding = Some(format!("treekem:epoch={}", info.secret_epoch));
    }
    if let Some(base_revision) = invite.base_state_revision {
        info.state_revision = base_revision;
        info.roster_revision = base_revision;
    }
    if let Some(base_members) = invite.base_members_v2.clone() {
        info.members_v2 = base_members;
    }
    if let Some(base_state_hash) = invite.base_state_hash.clone() {
        info.state_hash = base_state_hash;
        info.prev_state_hash = invite.base_prev_state_hash.clone();
    }

    if !invite_is_treekem && has_authority_base_state {
        // Modern non-TreeKEM invite stubs keep the committed role/state roster
        // exactly at the invite authority frontier. If that frontier already
        // contains the local joiner (for example single-daemon self-rejoin via
        // an invite minted before leaving), update only non-committed display /
        // key-package metadata for the local REST view. Role/state stay as the
        // authority snapshot recorded them, and `compute_roster_root` ignores
        // these metadata fields, so the base `state_hash` remains coherent.
        if let Some(member) = info.members_v2.get_mut(joiner_hex) {
            if member.is_active() || member.state == x0x::groups::GroupMemberState::Pending {
                if let Some(display_name) = display_name.clone() {
                    member.display_name = Some(display_name);
                }
                if let Some(kp_b64) = treekem_key_package_b64.clone() {
                    member.treekem_key_package_b64 = Some(kp_b64);
                }
                member.updated_at = now_millis_u64();
            }
        }
    }

    if !has_authority_base_state {
        // The REST invite-join path rejects missing base roster snapshots before
        // reaching this helper (`creator_agent_id_from_base_state`). This
        // defensive recompute exists only for direct/helper construction and
        // deliberately does not derive creator/member authority from unsigned
        // `invite.inviter` metadata.
        info.recompute_state_hash();
    }
    info
}

/// POST /groups/join — join a group via invite link.
pub(in crate::server) async fn join_group_via_invite(
    State(state): State<Arc<AppState>>,
    Json(req): Json<JoinGroupRequest>,
) -> impl IntoResponse {
    // Parse invite
    let invite = match x0x::groups::invite::SignedInvite::from_link(&req.invite) {
        Ok(inv) => inv,
        Err(e) => {
            return bad_request(format!("invalid invite: {e}"));
        }
    };

    // Check expiry
    if invite.is_expired() {
        return bad_request("invite has expired");
    }
    let invite_is_treekem = invite.secure_plane == Some(x0x::mls::SecureGroupPlane::TreeKem);

    let agent_id = state.agent.agent_id();
    let group_id_hex = invite.group_id.clone();
    let invite_stable_group_id = invite.stable_group_id.as_deref().unwrap_or(&group_id_hex);
    let membership_lock = group_membership_lock(&state, &group_id_hex).await;
    let membership_guard = membership_lock.lock().await;
    {
        let groups = state.named_groups.read().await;
        if has_withdrawn_group_record(&groups, &group_id_hex)
            || has_withdrawn_group_record(&groups, invite_stable_group_id)
        {
            return api_error(StatusCode::CONFLICT, "group is withdrawn");
        }
        if groups.contains_key(&group_id_hex)
            || groups
                .values()
                .any(|info| info.mls_group_id == group_id_hex)
        {
            // Issue #188: a duplicate/replayed join (retried cmd-DM,
            // redelivered invite) for a group this node already joined — or
            // is mid-join on, since the local stub lands in `named_groups`
            // before TreeKEM convergence completes — is an idempotent
            // success, not an error. No state is mutated and no MemberJoined
            // is re-published; the membership lock above serializes the
            // first-join/replay race.
            let info = groups.get(&group_id_hex).or_else(|| {
                groups
                    .values()
                    .find(|info| info.mls_group_id == group_id_hex)
            });
            if let Some(info) = info {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "ok": true,
                        "already_joined": true,
                        "group_id": group_id_hex,
                        "group_name": info.name,
                        "chat_topic": info.general_chat_topic(),
                    })),
                );
            }
        }
    }
    let inviter = match parse_agent_id_hex(&invite.inviter) {
        Ok(id) => id,
        Err(e) => {
            return bad_request(format!("invalid inviter: {e}"));
        }
    };
    let creator_hex = match invite.creator_agent_id_from_base_state() {
        Ok(creator_hex) => creator_hex,
        Err(e) => {
            return bad_request(e);
        }
    };
    let creator = match parse_agent_id_hex(&creator_hex) {
        Ok(id) => id,
        Err(e) => {
            return bad_request(format!("invalid base-state creator: {e}"));
        }
    };

    // Create the MLS group locally (in a real flow, the inviter would send
    // a Welcome message; for now, we create a local group and the inviter
    // will add us when they see our presence on the group topic)
    let group_id_bytes = match hex::decode(&group_id_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            return bad_request(format!("invalid group_id hex: {e}"));
        }
    };

    let treekem_key_package_b64 = if invite_is_treekem {
        use base64::Engine as _;
        let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let prepared = match x0x::mls::TreeKemMlsGroup::prepare_member(agent_id, &seed) {
            Ok(prepared) => prepared,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to prepare TreeKEM KeyPackage: {e}"),
                );
            }
        };
        Some(BASE64.encode(prepared.key_package_bytes()))
    } else {
        None
    };

    match x0x::mls::MlsGroup::new(group_id_bytes, agent_id).await {
        Ok(group) => {
            if !invite_is_treekem {
                // Store legacy demo MLS group. Real TreeKEM groups are stored
                // only after the authority's Welcome is accepted.
                state
                    .mls_groups
                    .write()
                    .await
                    .insert(group_id_hex.clone(), group);
                save_mls_groups(&state).await;
            }

            let joiner_hex = hex::encode(agent_id.as_bytes());
            let info = invite_join_group_info(
                &invite,
                creator,
                &creator_hex,
                &group_id_hex,
                &joiner_hex,
                req.display_name.clone(),
                treekem_key_package_b64.clone(),
            );

            let chat_topic = info.general_chat_topic();

            state
                .named_groups
                .write()
                .await
                .insert(group_id_hex.clone(), info.clone());
            save_named_groups(&state).await;
            drop(membership_guard);
            ensure_named_group_listeners(Arc::clone(&state), &group_id_hex).await;

            // Publish a signed MemberJoined request on the metadata topic so
            // the original inviter can validate the one-time invite and publish
            // the authority-signed `MemberAdded` commit. Current members apply
            // that commit, not this request, so the committed roster/state_hash
            // advance together; see docs/design/groups-join-roster-propagation.md.
            //
            // Failure here is logged but does not fail the local stub creation;
            // the legacy chat-topic announcement below remains as a
            // defence-in-depth signal.
            let signing_kp = state.agent.identity().agent_keypair();
            let now_ms = now_millis_u64();
            let member_pubkey_b64 = {
                use base64::Engine as _;
                BASE64.encode(signing_kp.public_key().as_bytes())
            };
            let stable_id_for_event = info.stable_group_id().to_string();
            if invite_is_treekem {
                record_expected_join_result_inviter(
                    state.as_ref(),
                    join_result_key(&stable_id_for_event, &joiner_hex),
                    invite.inviter.clone(),
                );
            }
            let display_name_for_event = req.display_name.clone();
            let canonical = canonical_member_joined_bytes(
                &info.mls_group_id,
                Some(&stable_id_for_event),
                &joiner_hex,
                &member_pubkey_b64,
                x0x::groups::GroupRole::Member,
                display_name_for_event.as_deref(),
                &invite.inviter,
                &invite.invite_secret,
                now_ms,
                treekem_key_package_b64.as_deref(),
            );
            match ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
                signing_kp.secret_key(),
                &canonical,
            ) {
                Ok(sig) => {
                    use base64::Engine as _;
                    let signature_b64 = BASE64.encode(sig.as_bytes());
                    let event = NamedGroupMetadataEvent::MemberJoined {
                        group_id: info.mls_group_id.clone(),
                        stable_group_id: Some(stable_id_for_event),
                        member_agent_id: joiner_hex.clone(),
                        member_public_key_b64: member_pubkey_b64,
                        role: x0x::groups::GroupRole::Member,
                        display_name: display_name_for_event,
                        inviter_agent_id: invite.inviter.clone(),
                        invite_secret: invite.invite_secret.clone(),
                        ts_ms: now_ms,
                        treekem_key_package_b64: treekem_key_package_b64.clone(),
                        recovery_authority_agent_id: None,
                        recovery_authority_public_key_b64: None,
                        recovery_authority_signature_b64: None,
                        recovery_authority_commit: None,
                        signature_b64,
                    };
                    tracing::info!(
                        group_id = %group_id_hex,
                        topic = %info.metadata_topic,
                        member = %joiner_hex,
                        inviter = %invite.inviter,
                        "MemberJoined: publishing joiner-authored membership event to metadata topic"
                    );
                    // Publish twice: once immediately so the inviter gets it
                    // as soon as the metadata mesh covers them, then again
                    // after `GROUP_BACKGROUND_PUBLISH_DELAY` so members
                    // whose Plumtree links formed late still pick it up.
                    // The applier is idempotent (re-applying the same
                    // event for an already-active member is a no-op), so
                    // double-publish is safe.
                    publish_named_group_metadata_event(&state, &info.metadata_topic, &event).await;
                    // TreeKEM membership is order-sensitive: gossip remains the
                    // broadcast path, but the join trigger must reach the inviter
                    // reliably so they can produce the authoritative add commit.
                    spawn_named_group_event_delivery(&state, &invite.inviter, &event);
                    spawn_named_group_event_delivery_after(
                        &state,
                        &invite.inviter,
                        &event,
                        GROUP_BACKGROUND_PUBLISH_DELAY,
                    );
                    let state_for_replay = Arc::clone(&state);
                    let topic_for_replay = info.metadata_topic.clone();
                    let inviter_for_replay = invite.inviter.clone();
                    let event_for_replay = event;
                    tokio::spawn(async move {
                        tokio::time::sleep(GROUP_BACKGROUND_PUBLISH_DELAY).await;
                        publish_named_group_metadata_event(
                            &state_for_replay,
                            &topic_for_replay,
                            &event_for_replay,
                        )
                        .await;
                        spawn_named_group_event_delivery(
                            &state_for_replay,
                            &inviter_for_replay,
                            &event_for_replay,
                        );
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        group_id = %group_id_hex,
                        "MemberJoined: failed to sign join announcement: {e:?}"
                    );
                }
            }
            if invite_is_treekem {
                let state_for_poll = Arc::clone(&state);
                let group_id_for_poll = group_id_hex.clone();
                let event_group_id_for_poll = info.stable_group_id().to_string();
                let member_for_poll = joiner_hex.clone();
                tokio::spawn(async move {
                    poll_join_result_until_treekem_ready(
                        state_for_poll,
                        group_id_for_poll,
                        event_group_id_for_poll,
                        inviter,
                        member_for_poll,
                    )
                    .await;
                });
            }

            // Announce join on the chat topic so the inviter sees us —
            // fire-and-forget. The result was already discarded pre-fix,
            // and spawning keeps the handler responsive when the gossip
            // publish path is slow under back-pressure.
            let agent_hex = joiner_hex;
            let display = req
                .display_name
                .clone()
                .unwrap_or_else(|| agent_hex[..8].to_string());
            let announcement = serde_json::json!({
                "type": "group_event",
                "event": "joined",
                "agent_id": agent_hex,
                "display_name": display,
                "group_id": group_id_hex,
                "group_name": invite.group_name,
                "ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });
            let state_for_join = Arc::clone(&state);
            let chat_topic_for_join = chat_topic.clone();
            let announcement_bytes = announcement.to_string().into_bytes();
            tokio::spawn(async move {
                tokio::time::sleep(GROUP_BACKGROUND_PUBLISH_DELAY).await;
                if let Err(e) = state_for_join
                    .agent
                    .publish(&chat_topic_for_join, announcement_bytes)
                    .await
                {
                    tracing::debug!(topic = %chat_topic_for_join, "join announcement publish failed: {e}");
                }
            });

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "group_id": group_id_hex,
                    "group_name": invite.group_name,
                    "chat_topic": chat_topic,
                })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// PUT /groups/:id/display-name — set your display name in a group.
pub(in crate::server) async fn set_group_display_name(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<SetDisplayNameRequest>,
) -> impl IntoResponse {
    let membership_lock = group_membership_lock(&state, &id).await;
    let membership_guard = membership_lock.lock().await;
    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get_mut(&id) else {
        return not_found("group not found");
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }

    let agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    info.set_display_name(&agent_hex, req.name.clone());
    drop(groups); // release write lock before saving
    save_named_groups(&state).await;
    drop(membership_guard);

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "display_name": req.name })),
    )
}

/// POST /groups/:id/members — add a member to the named-group roster.
pub(in crate::server) async fn add_named_group_member(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AddNamedGroupMemberRequest>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };
    let local_agent = state.agent.agent_id();
    let actor_hex = hex::encode(local_agent.as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();

    // Serialize against concurrent membership applies + other API mutators (see
    // `AppState::group_membership_locks`). Held across the delegation to the
    // TreeKEM helper below, which must NOT re-acquire it (single-level lock).
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;

    let (metadata_topic, event, members, epoch) = {
        let mut named_groups = state.named_groups.write().await;
        let Some(info) = named_groups.get(&id) else {
            return not_found("group not found");
        };
        if let Err(e) = require_admin_or_above(info, &actor_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
            drop(named_groups);
            return add_treekem_named_group_member(state, id, agent_id, req).await;
        }

        let agent_hex = hex::encode(agent_id.as_bytes());
        if info.has_member(&agent_hex) {
            return api_error(StatusCode::CONFLICT, "member already present");
        }
        let mut next = info.clone();
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.add_member(
            agent_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(actor_hex.clone()),
            req.display_name.clone(),
        );
        if let Some(display_name) = req.display_name.clone() {
            next.set_display_name(&agent_hex, display_name);
        }
        let revision = next.roster_revision;
        let commit = match next.seal_commit(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };
        let metadata_topic = next.metadata_topic.clone();
        let event_group_id = next.stable_group_id().to_string();
        let members = named_group_member_values(&next);
        named_groups.insert(id.clone(), next);
        drop(named_groups);

        let mut epoch = None;
        let mut mls_groups = state.mls_groups.write().await;
        if let Some(group) = mls_groups.get_mut(&id) {
            if !group.is_member(&agent_id) {
                match group.add_member(agent_id).await {
                    Ok(_) => epoch = Some(group.current_epoch()),
                    Err(e) => {
                        tracing::warn!("named-group add member MLS update failed: {e}");
                    }
                }
            } else {
                epoch = Some(group.current_epoch());
            }
        }
        drop(mls_groups);
        save_named_groups(&state).await;
        save_mls_groups(&state).await;
        let event = NamedGroupMetadataEvent::MemberAdded {
            group_id: event_group_id,
            revision,
            actor: actor_hex,
            agent_id: agent_hex,
            display_name: req.display_name,
            treekem_commit_b64: None,
            treekem_welcome_b64: None,
            welcome_ref: None,
            treekem_epoch: None,
            treekem_key_package_hash: None,
            member_joined_recovery: None,
            member_recovery_history: Vec::new(),
            commit: Some(commit),
        };
        (metadata_topic, event, members, epoch)
    };

    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": id,
            "epoch": epoch,
            "member_count": members.len(),
            "members": members,
        })),
    )
}

async fn add_treekem_named_group_member(
    state: Arc<AppState>,
    id: String,
    agent_id: AgentId,
    req: AddNamedGroupMemberRequest,
) -> (StatusCode, Json<serde_json::Value>) {
    use base64::Engine as _;

    let local_agent = state.agent.agent_id();
    let actor_hex = hex::encode(local_agent.as_bytes());
    let agent_hex = hex::encode(agent_id.as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let Some(kp_b64) = req.treekem_key_package_b64.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "TreeKEM direct add requires treekem_key_package_b64 from the target"
            })),
        );
    };
    let kp_bytes = match base64::engine::general_purpose::STANDARD.decode(&kp_b64) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "treekem_key_package_b64 is not valid base64"
                })),
            );
        }
    };

    let (mut next, metadata_topic, event_group_id) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "ok": false, "error": "group not found" })),
            );
        };
        if let Err(e) = require_admin_or_above(info, &actor_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if info.has_member(&agent_hex) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "ok": false, "error": "member already present" })),
            );
        }
        (
            info.clone(),
            info.metadata_topic.clone(),
            info.stable_group_id().to_string(),
        )
    };

    let group = {
        let map = state.treekem_groups.read().await;
        map.get(&id).cloned()
    };
    let Some(group) = group else {
        return (
            StatusCode::FAILED_DEPENDENCY,
            Json(
                serde_json::json!({ "ok": false, "error": "TreeKEM group not loaded — restart or re-share required" }),
            ),
        );
    };
    let mut guard = group.lock().await;
    let treekem_epoch = guard.epoch().saturating_add(1);
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    next.add_member(
        agent_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(actor_hex.clone()),
        req.display_name.clone(),
    );
    if let Some(display_name) = req.display_name.clone() {
        next.set_display_name(&agent_hex, display_name);
    }
    let direct_recovery_original = NamedGroupMetadataEvent::MemberJoined {
        group_id: id.clone(),
        stable_group_id: Some(event_group_id.clone()),
        member_agent_id: agent_hex.clone(),
        member_public_key_b64: String::new(),
        role: x0x::groups::GroupRole::Member,
        display_name: req.display_name.clone(),
        inviter_agent_id: actor_hex.clone(),
        invite_secret: String::new(),
        ts_ms: now_ms,
        treekem_key_package_b64: Some(kp_b64.clone()),
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: None,
        recovery_authority_commit: None,
        signature_b64: String::new(),
    };
    next.set_member_treekem_key_package(&agent_hex, kp_b64.clone());
    next.secret_epoch = treekem_epoch;
    let Some(binding) = treekem_recovery_security_binding(treekem_epoch, &direct_recovery_original)
    else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": "failed to bind recovery record" })),
        );
    };
    next.security_binding = Some(binding);
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": format!("seal failed: {e}") })),
            );
        }
    };
    let member_joined_recovery = match attest_member_joined_recovery_event(
        &direct_recovery_original,
        signing_kp,
        &commit,
    ) {
        Ok(attested) => attested,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    serde_json::json!({ "ok": false, "error": format!("recovery attestation failed: {e}") }),
                ),
            );
        }
    };
    let out = match guard.add_member(agent_id, &kp_bytes) {
        Ok(out) => out,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                Json(
                    serde_json::json!({ "ok": false, "error": format!("TreeKEM add_member failed: {e}") }),
                ),
            );
        }
    };
    if guard.epoch() != treekem_epoch {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "ok": false, "error": "TreeKEM epoch did not advance as expected" }),
            ),
        );
    }
    if let Err(e) =
        persist_treekem_and_named_groups_atomic_with_info(&state, &id, next.clone(), &guard).await
    {
        tracing::error!(group_id = %LogHexId::group(&id), "failed to persist TreeKEM snapshot after direct add: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "ok": false, "error": "failed to persist secure group state" }),
            ),
        );
    }
    drop(guard);

    let mut groups = state.named_groups.write().await;
    groups.insert(id.clone(), next.clone());
    drop(groups);
    save_named_groups(&state).await;

    let welcome_ref = stage_treekem_welcome(&state, &event_group_id, &agent_hex, out.welcome).await;
    let event = NamedGroupMetadataEvent::MemberAdded {
        group_id: event_group_id,
        revision,
        actor: actor_hex,
        agent_id: agent_hex.clone(),
        display_name: req.display_name,
        treekem_commit_b64: Some(base64::engine::general_purpose::STANDARD.encode(out.commit)),
        treekem_welcome_b64: None,
        welcome_ref: Some(welcome_ref),
        treekem_epoch: Some(treekem_epoch),
        treekem_key_package_hash: next
            .members_v2
            .get(&agent_hex)
            .and_then(|member| member.treekem_key_package_hash.clone()),
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        commit: Some(commit),
    };
    cache_treekem_member_key_package(
        &state,
        join_result_key(&id, &agent_hex),
        member_joined_recovery.clone(),
        true,
    )
    .await;
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    remember_treekem_membership_event(&state, &event).await;
    spawn_named_group_event_delivery_to_active_members(
        &state,
        &next,
        &event,
        std::slice::from_ref(&agent_hex),
    );
    spawn_named_group_event_delivery_to_active_members(&state, &next, &member_joined_recovery, &[]);
    let recovery_deliveries = state
        .treekem_member_key_packages
        .events_matching(|recovery| {
            matches!(
                recovery,
                NamedGroupMetadataEvent::MemberJoined { member_agent_id, .. }
                    if member_agent_id != &agent_hex
            ) && verify_authority_attested_member_joined_recovery(&next, recovery)
        })
        .await;
    for recovery in recovery_deliveries {
        spawn_named_group_event_delivery(&state, &agent_hex, &recovery);
        spawn_named_group_event_delivery_after(
            &state,
            &agent_hex,
            &recovery,
            GROUP_BACKGROUND_PUBLISH_DELAY,
        );
    }
    maybe_publish_group_card_after_state_change(&state, &id).await;

    let members = named_group_member_values(&next);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": id,
            "epoch": treekem_epoch,
            "member_count": members.len(),
            "members": members,
        })),
    )
}

/// DELETE /groups/:id/members/:agent_id — remove a member from the named-group roster.
pub(in crate::server) async fn remove_named_group_member(
    State(state): State<Arc<AppState>>,
    Path((id, agent_id_hex)): Path<(String, String)>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    // Serialize against concurrent membership applies + other API mutators (see
    // `AppState::group_membership_locks`). Held across the delegation to the
    // TreeKEM helper below, which must NOT re-acquire it (single-level lock).
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;
    {
        let groups = state.named_groups.read().await;
        if let Some(info) = groups.get(&id) {
            if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                drop(groups);
                return remove_treekem_named_group_member(state, id, agent_id_hex, local_agent_hex)
                    .await;
            }
        }
    }
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();

    let (metadata_topic, event, members, epoch) = {
        let mut named_groups = state.named_groups.write().await;
        let Some(info) = named_groups.get(&id) else {
            return not_found("group not found");
        };

        if let Err(e) = require_admin_or_above(info, &local_agent_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if !info.has_member(&agent_id_hex) {
            return not_found("member not found");
        }
        // ADR-0016 R2: friendly pre-check before any mutation/side effect.
        if let Some(resp) = last_admin_precheck(info, |g| g.remove_member(&agent_id_hex, None)) {
            return resp;
        }

        let mut next = info.clone();
        next.roster_revision = next.roster_revision.saturating_add(1);
        let revision = next.roster_revision;
        next.remove_member(&agent_id_hex, Some(local_agent_hex.clone()));
        let commit = match next.seal_commit(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };
        let metadata_topic = next.metadata_topic.clone();
        let event_group_id = next.stable_group_id().to_string();
        let members = named_group_member_values(&next);
        named_groups.insert(id.clone(), next);
        drop(named_groups);

        let mut epoch = None;
        let mut mls_groups = state.mls_groups.write().await;
        if let Some(group) = mls_groups.get_mut(&id) {
            if group.is_member(&agent_id) {
                match group.remove_member(agent_id).await {
                    Ok(_) => epoch = Some(group.current_epoch()),
                    Err(e) => tracing::warn!("named-group remove member MLS update failed: {e}"),
                }
            } else {
                epoch = Some(group.current_epoch());
            }
        }
        drop(mls_groups);
        save_named_groups(&state).await;
        save_mls_groups(&state).await;
        let event = NamedGroupMetadataEvent::MemberRemoved {
            group_id: event_group_id,
            revision,
            actor: local_agent_hex,
            agent_id: agent_id_hex.clone(),
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit: Some(commit),
        };
        (metadata_topic, event, members, epoch)
    };

    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": id,
            "removed_member": agent_id_hex,
            "epoch": epoch,
            "member_count": members.len(),
            "members": members,
        })),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum TreeKemLeaveDisposition {
    ActiveMember,
    LocalOnlyDrop,
}

fn treekem_leave_disposition(
    info: &x0x::groups::GroupInfo,
    local_agent_hex: &str,
) -> TreeKemLeaveDisposition {
    if info.has_active_member(local_agent_hex) {
        TreeKemLeaveDisposition::ActiveMember
    } else {
        TreeKemLeaveDisposition::LocalOnlyDrop
    }
}

fn treekem_persistence_file_name_for_drop(group_id: &str, extension: &str) -> Option<String> {
    if group_id.is_empty()
        || !group_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(format!("{group_id}.{extension}"))
}

fn treekem_snapshot_file_name_for_drop(group_id: &str) -> Option<String> {
    treekem_persistence_file_name_for_drop(group_id, "snap")
}

fn treekem_journal_file_name_for_drop(group_id: &str) -> Option<String> {
    treekem_persistence_file_name_for_drop(group_id, "journal")
}

fn treekem_snapshot_path_for_drop_in_dir(
    treekem_dir: &FsPath,
    group_id: &str,
) -> Option<std::path::PathBuf> {
    treekem_snapshot_file_name_for_drop(group_id).map(|name| treekem_dir.join(name))
}

fn treekem_journal_path_for_drop_in_dir(
    treekem_dir: &FsPath,
    group_id: &str,
) -> Option<std::path::PathBuf> {
    treekem_journal_file_name_for_drop(group_id).map(|name| treekem_dir.join(name))
}

fn treekem_snapshot_path_for_drop(state: &AppState, group_id: &str) -> Option<std::path::PathBuf> {
    treekem_snapshot_path_for_drop_in_dir(&state.treekem_dir, group_id)
}

fn treekem_journal_path_for_drop(state: &AppState, group_id: &str) -> Option<std::path::PathBuf> {
    treekem_journal_path_for_drop_in_dir(&state.treekem_dir, group_id)
}

async fn remove_treekem_persistence_file(
    path: &FsPath,
    group_id: &str,
    reason: &str,
    file_kind: &str,
) {
    if let Err(e) = tokio::fs::remove_file(path).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(group_id = %LogHexId::group(group_id), reason = %reason, file_kind, "failed to remove TreeKEM persistence file while dropping local group state: {e}");
        }
    }
}

async fn remove_treekem_persistence_for_group_id_in_dir(
    treekem_dir: &FsPath,
    group_id: &str,
    reason: &str,
) {
    let Some(treekem_snapshot) = treekem_snapshot_path_for_drop_in_dir(treekem_dir, group_id)
    else {
        tracing::warn!(
            group_id = %LogHexId::group(group_id),
            reason = %reason,
            "skipping unsafe TreeKEM persistence id while dropping local group state"
        );
        return;
    };
    let Some(treekem_journal) = treekem_journal_path_for_drop_in_dir(treekem_dir, group_id) else {
        tracing::warn!(
            group_id = %LogHexId::group(group_id),
            reason = %reason,
            "skipping unsafe TreeKEM persistence id while dropping local group state"
        );
        return;
    };
    remove_treekem_persistence_file(&treekem_snapshot, group_id, reason, "snapshot").await;
    remove_treekem_persistence_file(&treekem_journal, group_id, reason, "journal").await;
}

async fn remove_treekem_persistence_for_group_id(state: &AppState, group_id: &str, reason: &str) {
    remove_treekem_persistence_for_group_id_in_dir(&state.treekem_dir, group_id, reason).await;
}

fn collect_same_stable_group_aliases(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    id: &str,
    stable_group_id: Option<&str>,
) -> HashSet<String> {
    let mut stable_ids = HashSet::new();
    if let Some(stable_group_id) = stable_group_id.filter(|stable| !stable.is_empty()) {
        stable_ids.insert(stable_group_id.to_string());
    }
    if let Some(info) = groups.get(id) {
        stable_ids.insert(info.stable_group_id().to_string());
    }
    for info in groups.values() {
        let matches_requested_id = info.stable_group_id() == id || info.mls_group_id == id;
        let matches_requested_stable = stable_group_id
            .is_some_and(|stable| info.stable_group_id() == stable || info.mls_group_id == stable);
        if matches_requested_id || matches_requested_stable {
            stable_ids.insert(info.stable_group_id().to_string());
        }
    }

    let mut aliases = HashSet::new();
    aliases.insert(id.to_string());
    if let Some(stable_group_id) = stable_group_id.filter(|stable| !stable.is_empty()) {
        aliases.insert(stable_group_id.to_string());
    }
    for (key, info) in groups {
        if stable_ids.contains(info.stable_group_id()) {
            aliases.insert(key.clone());
            aliases.insert(info.mls_group_id.clone());
            aliases.insert(info.stable_group_id().to_string());
        }
    }
    aliases
}

fn group_id_matches_any_alias(candidate: &str, aliases: &HashSet<String>) -> bool {
    aliases.contains(candidate)
}

fn join_result_key_matches_any_group_alias(key: &str, aliases: &HashSet<String>) -> bool {
    key.split_once(':')
        .map(|(group_id, _)| group_id_matches_any_alias(group_id, aliases))
        .unwrap_or(false)
}

// Named-group terminality helpers are grouped by the boundary they protect:
// withdrawn-record lookup and aliasing, key-material install guards, journal
// replay filtering, card-terminality checks, local crypto teardown / retained
// tombstones vs local drops, post-crypto race rechecks, and test-only race hooks.
fn has_withdrawn_group_record(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
) -> bool {
    groups.get(group_id).is_some_and(|info| info.withdrawn)
        || groups.values().any(|info| {
            info.withdrawn && (info.stable_group_id() == group_id || info.mls_group_id == group_id)
        })
}

pub(in crate::server) fn has_withdrawn_same_stable_group_record(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
    stable_group_id: Option<&str>,
) -> bool {
    let mut aliases = collect_same_stable_group_aliases(groups, group_id, stable_group_id);
    aliases.insert(group_id.to_string());
    if let Some(stable) = stable_group_id.filter(|stable| !stable.is_empty()) {
        aliases.insert(stable.to_string());
    }
    aliases
        .iter()
        .any(|alias| has_withdrawn_group_record(groups, alias))
}

// Install / commit choke-points: refuse to add crypto material if durable
// named-group state has already crossed terminality.
async fn ensure_named_group_key_material_install_allowed(
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
    reason: &str,
) -> anyhow::Result<()> {
    #[cfg(test)]
    maybe_force_post_crypto_withdrawn_group_for_test(state, group_id, stable_group_id).await;

    if repair_withdrawn_named_groups_json_and_wipe_key_material(
        state,
        group_id,
        stable_group_id,
        reason,
    )
    .await?
    {
        anyhow::bail!("refusing to install key material for withdrawn group");
    }
    Ok(())
}

async fn repair_withdrawn_named_groups_json_and_wipe_key_material(
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
    reason: &str,
) -> anyhow::Result<bool> {
    let _persistence_guard = state.named_groups_persistence_lock.lock().await;
    repair_withdrawn_named_groups_json_and_wipe_key_material_locked(
        state,
        group_id,
        stable_group_id,
        reason,
    )
    .await
}

async fn repair_withdrawn_named_groups_json_and_wipe_key_material_locked(
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
    reason: &str,
) -> anyhow::Result<bool> {
    let repair_json = {
        let groups = state.named_groups.read().await;
        if !has_withdrawn_same_stable_group_record(&groups, group_id, stable_group_id) {
            return Ok(false);
        }
        serde_json::to_string_pretty(&*groups)
            .map_err(|e| anyhow::anyhow!("withdrawn named groups repair encode: {e}"))?
    };

    remove_treekem_persistence_for_group_id(state, group_id, reason).await;
    write_named_groups_json_atomic(&state.named_groups_path, &repair_json)
        .await
        .map_err(|e| anyhow::anyhow!("withdrawn named groups repair write: {e}"))?;
    Ok(true)
}

// Journal-recovery guard: stale TreeKEM journals cannot resurrect a group that
// durable named-group state already records as withdrawn.
fn has_withdrawn_group_record_for_journal_replay(
    durable_groups: &HashMap<String, x0x::groups::GroupInfo>,
    journal_group_id: &str,
    journal_groups: &HashMap<String, x0x::groups::GroupInfo>,
) -> bool {
    let mut aliases = collect_same_stable_group_aliases(durable_groups, journal_group_id, None);
    aliases.insert(journal_group_id.to_string());

    let journal_infos = journal_groups.iter().filter(|(key, info)| {
        key.as_str() == journal_group_id
            || info.stable_group_id() == journal_group_id
            || info.mls_group_id == journal_group_id
    });
    for (key, info) in journal_infos {
        aliases.insert(key.clone());
        aliases.insert(info.mls_group_id.clone());
        aliases.insert(info.stable_group_id().to_string());
        aliases.extend(collect_same_stable_group_aliases(
            durable_groups,
            journal_group_id,
            Some(info.stable_group_id()),
        ));
    }

    aliases
        .iter()
        .any(|alias| has_withdrawn_group_record(durable_groups, alias))
}

fn clear_group_info_key_material(info: &mut x0x::groups::GroupInfo) {
    info.shared_secret = None;
}

// Card-terminality gate: withdrawn discovery cards may mark keyless stubs, but
// must not terminate local keyed state without the signed withdrawal commit.
fn withdrawn_card_can_terminally_mark_local_group(
    info: &x0x::groups::GroupInfo,
    card: &x0x::groups::GroupCard,
    protects_keyed_local_group: bool,
) -> bool {
    card.withdrawn && group_card_supersedes_group_info(card, info) && !protects_keyed_local_group
}

async fn local_group_has_protected_crypto_material(
    state: &AppState,
    info: &x0x::groups::GroupInfo,
    aliases: &HashSet<String>,
) -> bool {
    if !info.withdrawn && info.shared_secret.is_some() {
        return true;
    }
    {
        let groups = state.named_groups.read().await;
        if aliases.iter().any(|alias| {
            groups.get(alias).is_some_and(|alias_info| {
                !alias_info.withdrawn && alias_info.shared_secret.is_some()
            })
        }) {
            return true;
        }
    }
    {
        let mls_groups = state.mls_groups.read().await;
        if aliases.iter().any(|alias| mls_groups.contains_key(alias)) {
            return true;
        }
    }
    {
        let treekem_groups = state.treekem_groups.read().await;
        if aliases
            .iter()
            .any(|alias| treekem_groups.contains_key(alias))
        {
            return true;
        }
    }
    for alias in aliases {
        if let Some(path) = treekem_snapshot_path_for_drop(state, alias) {
            if tokio::fs::try_exists(path).await.unwrap_or(true) {
                return true;
            }
        }
        if let Some(path) = treekem_journal_path_for_drop(state, alias) {
            if tokio::fs::try_exists(path).await.unwrap_or(true) {
                return true;
            }
        }
    }
    false
}

// Local crypto teardown: wipe in-memory and persisted key material; either keep
// a keyless withdrawn tombstone or drop only local, non-terminal state.
async fn wipe_local_group_crypto_material(
    state: &AppState,
    id: &str,
    stable_group_id: Option<&str>,
    reason: &str,
) {
    let aliases = {
        let mut groups = state.named_groups.write().await;
        let aliases = collect_same_stable_group_aliases(&groups, id, stable_group_id);
        for alias in &aliases {
            if let Some(info) = groups.get_mut(alias) {
                clear_group_info_key_material(info);
            }
        }
        aliases
    };
    {
        let mut cache = state.group_card_cache.write().await;
        for alias in &aliases {
            cache.remove(alias);
        }
    }
    {
        let mut mls_groups = state.mls_groups.write().await;
        for alias in &aliases {
            mls_groups.remove(alias);
        }
    }
    {
        let mut treekem_groups = state.treekem_groups.write().await;
        for alias in &aliases {
            treekem_groups.remove(alias);
        }
    }
    {
        let mut pending = state.treekem_pending_events.write().await;
        for alias in &aliases {
            pending.remove(alias);
        }
    }
    {
        let mut event_log = state.treekem_event_log.write().await;
        for alias in &aliases {
            event_log.remove(alias);
        }
    }
    {
        let mut catchup = state.treekem_catchup_throttle.write().await;
        for alias in &aliases {
            catchup.remove(alias);
        }
    }
    {
        let mut messages = state.public_messages.write().await;
        for alias in &aliases {
            messages.remove(alias);
        }
    }
    {
        let mut tasks = state.group_metadata_tasks.write().await;
        for alias in &aliases {
            if let Some(handle) = tasks.remove(alias) {
                handle.abort();
            }
        }
    }
    {
        let mut tasks = state.public_message_tasks.write().await;
        for alias in &aliases {
            if let Some(handle) = tasks.remove(alias) {
                handle.abort();
            }
        }
    }
    {
        let mut join_results = state.pending_join_results.write().await;
        join_results.retain(|key, pending| {
            !join_result_key_matches_any_group_alias(key, &aliases)
                && !group_id_matches_any_alias(
                    named_group_metadata_event_group_id(&pending.event),
                    &aliases,
                )
        });
    }
    if let Ok(mut expected) = state.expected_join_result_inviters.lock() {
        expected.retain(|key, _| !join_result_key_matches_any_group_alias(key, &aliases));
    }

    let _ = prune_treekem_cache_groups(state, &aliases, reason).await;
    let mut welcome_ids = Vec::new();
    {
        let mut welcomes = state.pending_welcomes.write().await;
        welcomes.retain(|welcome_id, pending| {
            let drop = group_id_matches_any_alias(&pending.group_id, &aliases);
            if drop {
                welcome_ids.push(welcome_id.clone());
            }
            !drop
        });
    }
    {
        let mut receives = state.pending_welcome_receives.write().await;
        receives.retain(|welcome_id, pending| {
            let drop = group_id_matches_any_alias(&pending.group_id, &aliases);
            if drop {
                welcome_ids.push(welcome_id.clone());
            }
            !drop
        });
    }
    if !welcome_ids.is_empty() {
        let mut waiters = state.pending_welcome_waiters.write().await;
        let mut acks = state.pending_welcome_acks.write().await;
        for welcome_id in welcome_ids {
            waiters.remove(&welcome_id);
            acks.remove(&welcome_id);
        }
    }

    for alias in &aliases {
        remove_treekem_persistence_for_group_id(state, alias, reason).await;
    }
}

async fn remove_directory_cache_entries_for_group_info(
    state: &AppState,
    info: &x0x::groups::GroupInfo,
) {
    let stable_group_id = info.stable_group_id().to_string();
    let shards = x0x::groups::shards_for_public(&info.tags, &info.name, &stable_group_id);
    let mut cache = state.directory_cache.write().await;
    for (kind, shard, _) in shards {
        cache.remove(kind, shard, &stable_group_id);
    }
}

async fn retain_withdrawn_group_tombstone(
    state: &AppState,
    group_id: &str,
    mut info: x0x::groups::GroupInfo,
    reason: &str,
) {
    let stable_group_id = info.stable_group_id().to_string();
    info.withdrawn = true;
    clear_group_info_key_material(&mut info);
    let aliases = {
        let mut groups = state.named_groups.write().await;
        let mut aliases =
            collect_same_stable_group_aliases(&groups, group_id, Some(&stable_group_id));
        aliases.insert(group_id.to_string());
        aliases.insert(stable_group_id.clone());
        for alias in &aliases {
            groups.insert(alias.clone(), info.clone());
        }
        aliases
    };
    let _ = prune_treekem_cache_groups(state, &aliases, reason).await;
    wipe_local_group_crypto_material(state, group_id, Some(&stable_group_id), reason).await;
    remove_directory_cache_entries_for_group_info(state, &info).await;
    refresh_group_card_cache_from_info(state, group_id, &info).await;
    save_named_groups(state).await;
    save_mls_groups(state).await;
}

async fn drop_local_named_group_state(
    state: &AppState,
    id: &str,
    stable_group_id: Option<&str>,
    reason: &str,
) {
    let cache_aliases = treekem_cache_group_aliases(state, id).await;
    let stable_group_id = stable_group_id.filter(|stable| *stable != id);
    {
        let mut groups = state.named_groups.write().await;
        groups.remove(id);
        if let Some(stable_group_id) = stable_group_id {
            groups.remove(stable_group_id);
        }
    }
    let _ = prune_treekem_cache_groups(state, &cache_aliases, reason).await;
    {
        let mut cache = state.group_card_cache.write().await;
        cache.remove(id);
        if let Some(stable_group_id) = stable_group_id {
            cache.remove(stable_group_id);
        }
    }
    {
        let mut mls_groups = state.mls_groups.write().await;
        mls_groups.remove(id);
        if let Some(stable_group_id) = stable_group_id {
            mls_groups.remove(stable_group_id);
        }
    }
    {
        let mut treekem_groups = state.treekem_groups.write().await;
        treekem_groups.remove(id);
        if let Some(stable_group_id) = stable_group_id {
            treekem_groups.remove(stable_group_id);
        }
    }
    remove_treekem_persistence_for_group_id(state, id, reason).await;
    if let Some(stable_group_id) = stable_group_id {
        remove_treekem_persistence_for_group_id(state, stable_group_id, reason).await;
    }
    save_named_groups(state).await;
    save_mls_groups(state).await;
    stop_named_group_metadata_listener(state, id).await;
    if let Some(stable_group_id) = stable_group_id {
        stop_named_group_metadata_listener(state, stable_group_id).await;
    }
}

async fn leave_treekem_group(
    state: Arc<AppState>,
    id: String,
    local_agent_hex: String,
) -> (StatusCode, Json<serde_json::Value>) {
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let (mut next, metadata_topic, event_group_id, name, disposition) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "ok": false, "error": "group not found" })),
            );
        };
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        let disposition = treekem_leave_disposition(info, &local_agent_hex);
        (
            info.clone(),
            info.metadata_topic.clone(),
            info.stable_group_id().to_string(),
            info.name.clone(),
            disposition,
        )
    };
    match disposition {
        TreeKemLeaveDisposition::LocalOnlyDrop => {
            drop_local_named_group_state(
                &state,
                &id,
                Some(&event_group_id),
                "treekem_non_active_leave",
            )
            .await;
            return (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "left": name, "local_only": true })),
            );
        }
        TreeKemLeaveDisposition::ActiveMember => {}
    }

    if let Some(error) = x0x::groups::last_admin_self_leave_precheck_error(&next, &local_agent_hex)
    {
        return api_error(StatusCode::CONFLICT, error);
    }

    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    next.remove_member(&local_agent_hex, Some(local_agent_hex.clone()));
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": format!("seal failed: {e}") })),
            );
        }
    };

    let cache_aliases = treekem_cache_group_aliases(&state, &id).await;
    let mut groups = state.named_groups.write().await;
    groups.remove(&id);
    drop(groups);
    let _ = prune_treekem_cache_groups(&state, &cache_aliases, "treekem_leave").await;
    state.group_card_cache.write().await.remove(&id);
    state.mls_groups.write().await.remove(&id);
    state.treekem_groups.write().await.remove(&id);
    remove_treekem_persistence_for_group_id(&state, &id, "treekem_leave").await;
    save_named_groups(&state).await;
    save_mls_groups(&state).await;

    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: event_group_id,
        revision,
        actor: local_agent_hex.clone(),
        agent_id: local_agent_hex,
        treekem_commit_b64: None,
        treekem_epoch: None,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    remember_treekem_membership_event(&state, &event).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "left": name })),
    )
}

async fn remove_treekem_named_group_member(
    state: Arc<AppState>,
    id: String,
    agent_id_hex: String,
    local_agent_hex: String,
) -> (StatusCode, Json<serde_json::Value>) {
    use base64::Engine as _;

    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let target_agent = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let (mut next, metadata_topic, event_group_id) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "ok": false, "error": "group not found" })),
            );
        };
        if let Err(e) = require_admin_or_above(info, &local_agent_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if !info.has_member(&agent_id_hex) {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "ok": false, "error": "member not found" })),
            );
        }
        // ADR-0016 R2: friendly pre-check before any TreeKEM work begins.
        if let Some(resp) = last_admin_precheck(info, |g| g.remove_member(&agent_id_hex, None)) {
            return resp;
        }
        (
            info.clone(),
            info.metadata_topic.clone(),
            info.stable_group_id().to_string(),
        )
    };
    // Issue #205: resolve the target's TreeKEM KeyPackage, recovering it on
    // demand (local cache, then async member-keyed catch-up) when the roster
    // lacks it. Mirror it onto the cloned snapshot so a later write-back never
    // clobbers a recovered package.
    let target_kp_b64 =
        match resolve_member_treekem_kp_for_removal_locked(&state, &id, &agent_id_hex).await {
            Ok(kp_b64) => kp_b64,
            Err(resp) => return resp,
        };
    next.set_member_treekem_key_package(&agent_id_hex, target_kp_b64.clone());
    let target_kp_bytes = match base64::engine::general_purpose::STANDARD.decode(&target_kp_b64) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "member TreeKEM KeyPackage is not valid base64"
                })),
            );
        }
    };

    let group = {
        let map = state.treekem_groups.read().await;
        map.get(&id).cloned()
    };
    let Some(group) = group else {
        return (
            StatusCode::FAILED_DEPENDENCY,
            Json(serde_json::json!({
                "ok": false,
                "error": "TreeKEM group not loaded — restart or re-share required"
            })),
        );
    };
    let mut guard = group.lock().await;
    let treekem_epoch = guard.epoch().saturating_add(1);
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    next.remove_member(&agent_id_hex, Some(local_agent_hex.clone()));
    next.secret_epoch = treekem_epoch;
    next.security_binding = Some(format!("treekem:epoch={treekem_epoch}"));
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": format!("seal failed: {e}") })),
            );
        }
    };
    let treekem_commit = match guard.remove_member_verified(target_agent, &target_kp_bytes) {
        Ok(commit) => commit,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!("TreeKEM remove_member failed: {e}")
                })),
            );
        }
    };
    if guard.epoch() != treekem_epoch {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "ok": false,
                "error": "TreeKEM epoch did not advance as expected"
            })),
        );
    }
    if let Err(e) =
        persist_treekem_and_named_groups_atomic_with_info(&state, &id, next.clone(), &guard).await
    {
        tracing::error!(group_id = %LogHexId::group(&id), "failed to persist TreeKEM snapshot after removal: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "ok": false,
                "error": "failed to persist secure group state"
            })),
        );
    }
    drop(guard);

    let mut groups = state.named_groups.write().await;
    groups.insert(id.clone(), next.clone());
    drop(groups);
    save_named_groups(&state).await;
    save_mls_groups(&state).await;
    let _ = prune_treekem_cache_member(&state, &id, &agent_id_hex, "local_member_removed").await;

    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: event_group_id,
        revision,
        actor: local_agent_hex,
        agent_id: agent_id_hex.clone(),
        treekem_commit_b64: Some(base64::engine::general_purpose::STANDARD.encode(treekem_commit)),
        treekem_epoch: Some(treekem_epoch),
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    remember_treekem_membership_event(&state, &event).await;
    spawn_named_group_event_delivery_to_active_members(
        &state,
        &next,
        &event,
        std::slice::from_ref(&agent_id_hex),
    );
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": id,
            "removed_member": agent_id_hex,
            "epoch": treekem_epoch,
            "member_count": named_group_member_values(&next).len(),
            "members": named_group_member_values(&next),
        })),
    )
}

/// GET /groups/:id/state — Phase D.3: inspect the stable-identity +
/// state-commit chain view of a group.
///
/// Returns `{ group_id, genesis, state_revision, state_hash,
/// prev_state_hash, security_binding, withdrawn, roster_root,
/// policy_hash, public_meta_hash }`.
///
/// Available to anyone holding the group stub — active members and
/// non-member card importers alike. Every field returned here is part of
/// the group's **public projection**: it is exactly the data already
/// published in the signed `GroupCard` (state_hash, revision,
/// prev_state_hash) plus derived commitments (roster_root, policy_hash,
/// public_meta_hash) that are hashes, never member content. The named-groups
/// model (`docs/design/named-groups-full-model.md`) requires non-members to
/// be able to view the public card and converge on the authoritative public
/// state of a discoverable group; private member content (chat, files, KV,
/// secure presence) is never exposed here. Non-discoverable groups cannot be
/// stubbed by a non-member (no card to import), so they 404 above for
/// outsiders rather than relying on this gate.
pub(in crate::server) async fn get_group_state(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    let roster_root = x0x::groups::compute_roster_root(&info.members_v2);
    let policy_hash = x0x::groups::compute_policy_hash(&info.policy);
    let public_meta_hash = x0x::groups::compute_public_meta_hash(&info.public_meta());
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": info.stable_group_id(),
            "mls_group_id": info.mls_group_id,
            "genesis": info.genesis,
            "state_revision": info.state_revision,
            "state_hash": info.state_hash,
            "prev_state_hash": info.prev_state_hash,
            "security_binding": info.security_binding,
            "withdrawn": info.withdrawn,
            "roster_root": roster_root,
            "policy_hash": policy_hash,
            "public_meta_hash": public_meta_hash,
        })),
    )
}

/// Query parameters for [`get_group_state_commits`].
#[derive(Debug, Deserialize)]
pub(in crate::server) struct StateCommitsQuery {
    /// Only return retained commits with `revision >= from_revision`.
    #[serde(default)]
    from_revision: u64,
    /// Page size (clamped to `[1, STATE_COMMITS_MAX_LIMIT]`).
    #[serde(default)]
    limit: Option<usize>,
}

/// GET /groups/:id/state/commits — issue #111: paged read over the retained
/// state-commit history (ADR-0016 verification / governance use-cases).
///
/// **Members-only for live groups.** Unlike `/groups/:id/state` (which serves
/// the public projection even to non-member card-importers), retained roster
/// projections are member content, so this endpoint requires the local agent to
/// be an **active member** while the group is live. Withdrawn groups are
/// keyless terminal audit shells after delete; their retained commits
/// remain readable locally so members keep a keyless audit history after key
/// wipe.
///
/// Each entry is `{ commit, roster, roster_root_verified }`, ordered by
/// ascending revision. `roster_root_verified` recomputes the roster root over
/// the retained projection and compares it to the commit's signed
/// `roster_root`, so on-disk corruption surfaces loudly rather than serving
/// silently-wrong history. `first_available_revision` lets callers distinguish
/// a real gap (history began after their `from_revision`, because each daemon
/// retains only the suffix it witnessed) from an empty result.
pub(in crate::server) async fn get_group_state_commits(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<StateCommitsQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    const STATE_COMMITS_DEFAULT_LIMIT: usize = 100;
    const STATE_COMMITS_MAX_LIMIT: usize = 500;
    let limit = q
        .limit
        .unwrap_or(STATE_COMMITS_DEFAULT_LIMIT)
        .clamp(1, STATE_COMMITS_MAX_LIMIT);

    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };

    // Live groups gate retained roster projections to active members. A
    // withdrawn local shell is intentionally keyless but still keeps #111
    // audit history after terminal delete, so keep that history
    // readable from the local daemon after terminality.
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    if !info.withdrawn && !info.has_active_member(&local_agent_hex) {
        return api_error(
            StatusCode::FORBIDDEN,
            "members only: retained state-commit history is member content",
        );
    }

    let matched = info
        .commit_log
        .iter()
        .filter(|rc| rc.commit.revision >= q.from_revision)
        .count();
    let entries: Vec<serde_json::Value> = info
        .commit_log
        .iter()
        .filter(|rc| rc.commit.revision >= q.from_revision)
        .take(limit)
        .map(|rc| {
            serde_json::json!({
                "commit": rc.commit,
                "roster": rc.roster,
                "roster_root_verified": rc.roster_root_consistent(),
            })
        })
        .collect();

    let has_more = matched > entries.len();
    // Cursor for the next page: one past the last returned revision. Safe
    // because the log is monotonic in revision and truncated only from the
    // front, so `last()` is the highest revision on this page.
    let next_from_revision = if has_more {
        info.commit_log
            .iter()
            .filter(|rc| rc.commit.revision >= q.from_revision)
            .nth(entries.len().saturating_sub(1))
            .map(|rc| rc.commit.revision + 1)
    } else {
        None
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": info.stable_group_id(),
            "state_revision": info.state_revision,
            "withdrawn": info.withdrawn,
            "total_retained": info.commit_log.len(),
            "first_available_revision": info.commit_log.first().map(|rc| rc.commit.revision),
            "latest_retained_revision": info.commit_log.last().map(|rc| rc.commit.revision),
            "from_revision": q.from_revision,
            "limit": limit,
            "count": entries.len(),
            "has_more": has_more,
            "next_from_revision": next_from_revision,
            "commits": entries,
        })),
    )
}

/// POST /groups/:id/state/seal — Phase D.3: advance the state-commit
/// chain and republish the signed public card (no-op payload change —
/// used to refresh / repair / force-propagate the chain).
///
/// Admin or higher only.
pub(in crate::server) async fn seal_group_state(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return not_found("group not found");
        };
        let role = info.caller_role(&local_hex);
        if !role
            .map(|r| r.at_least(x0x::groups::GroupRole::Admin))
            .unwrap_or(false)
        {
            return forbidden("admin role required");
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
    }
    let commit = publish_group_card_with_reseal(&state, &id).await;
    let Some(commit) = commit else {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "seal failed");
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "commit": commit,
        })),
    )
}

/// POST /groups/:id/state/withdraw — Phase D.3: seal a terminal withdrawal
/// commit and delete the group. Members receive the signed terminal
/// `GroupDeleted` event over the metadata topic plus direct delivery; the
/// withdrawn card still supersedes public discovery listings where applicable.
///
/// Admin or higher only.
pub(in crate::server) async fn withdraw_group_state(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let signing_kp = state.agent.identity().agent_keypair();

    let membership_lock = group_membership_lock(&state, &id).await;
    let membership_guard = membership_lock.lock().await;
    let (commit, metadata_topic, event_group_id, delivery_roster, event, terminal_info) = {
        let mut groups = state.named_groups.write().await;
        let Some(info) = groups.get_mut(&id) else {
            return not_found("group not found");
        };
        if let Err(e) = require_admin_or_above(info, &local_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        let event_revision = info.roster_revision.saturating_add(1);
        let commit = match info.seal_withdrawal(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("withdrawal seal failed: {e}"),
                );
            }
        };
        // Delete retains a keyless withdrawn tombstone: ADR-0012's "leave
        // nothing behind" means no MLS/TreeKEM/GSS key material survives, not
        // that the terminal metadata record is deleted. Keeping this record is
        // the stale-card reanimation guard for future imports.
        // `seal_withdrawal` already nulls `shared_secret` on success (its
        // documented contract, covered by `seal_withdrawal_success_clears_shared_secret`),
        // so the wipe lives inside the library method and stays atomic with the
        // withdrawn marker — no redundant server-side clear here.
        let metadata_topic = info.metadata_topic.clone();
        let event_group_id = info.stable_group_id().to_string();
        let delivery_roster = info.clone();
        let terminal_info = info.clone();
        let event = NamedGroupMetadataEvent::GroupDeleted {
            group_id: event_group_id.clone(),
            revision: event_revision,
            actor: local_hex.clone(),
            commit: Some(commit.clone()),
        };
        (
            commit,
            metadata_topic,
            event_group_id,
            delivery_roster,
            event,
            terminal_info,
        )
    };
    retain_withdrawn_group_tombstone(&state, &id, terminal_info, "withdraw_delete").await;

    // Refresh the withdrawn-card path for public discovery supersession after
    // stale local cards are gone. Hidden groups still do not publish public
    // cards, so their delete propagation is the signed GroupDeleted
    // metadata/direct event above.
    maybe_publish_group_card_after_state_change(&state, &id).await;
    stop_named_group_metadata_listener(&state, &id).await;
    if event_group_id != id {
        stop_named_group_metadata_listener(&state, &event_group_id).await;
    }

    // Keep the per-group membership lock until local key material is gone and
    // the retained record is visibly withdrawn, so no concurrent API mutator can
    // author a post-withdrawal commit in the narrow terminal window. The
    // network-facing GroupDeleted publish/direct-delivery happens after the lock
    // is released; all required data was captured above.
    drop(membership_guard);

    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    spawn_named_group_event_delivery_to_active_members(&state, &delivery_roster, &event, &[]);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "commit": commit,
        })),
    )
}

/// DELETE /groups/:id — leave a group.
pub(in crate::server) async fn leave_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let local_agent = state.agent.agent_id();
    let local_agent_hex = hex::encode(local_agent.as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();

    // Serialize against concurrent membership applies + other API mutators (see
    // `AppState::group_membership_locks`). Held across the delegation to the
    // TreeKEM helper below, which must NOT re-acquire it (single-level lock).
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;

    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get_mut(&id) else {
        return not_found("group not found");
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }

    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        drop(groups);
        return leave_treekem_group(state, id, local_agent_hex).await;
    }
    let name = info.name.clone();
    let metadata_topic = info.metadata_topic.clone();
    let event_group_id = info.stable_group_id().to_string();
    if let Some(resp) = treekem_membership_unsupported(info) {
        return resp;
    }
    if let Some(error) = x0x::groups::last_admin_self_leave_precheck_error(info, &local_agent_hex) {
        return api_error(StatusCode::CONFLICT, error);
    }
    let mut next = info.clone();
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    next.remove_member(&local_agent_hex, Some(local_agent_hex.clone()));
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seal failed: {e}"),
            );
        }
    };
    *info = next;
    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: event_group_id,
        revision,
        actor: local_agent_hex.clone(),
        agent_id: local_agent_hex.clone(),
        treekem_commit_b64: None,
        treekem_epoch: None,
        commit: Some(commit),
    };
    drop(groups);

    save_named_groups(&state).await;
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;

    let cache_aliases = treekem_cache_group_aliases(&state, &id).await;
    let _ = prune_treekem_cache_groups(&state, &cache_aliases, "leave_group").await;
    state.named_groups.write().await.remove(&id);
    let mut cache = state.group_card_cache.write().await;
    prune_expired_group_cards(&mut cache, now_millis_u64());
    cache.remove(&id);
    state.mls_groups.write().await.remove(&id);
    // ADR-0012: drop the live TreeKEM group and wipe at-rest TreeKEM
    // persistence (snapshot plus replay journal, both containing private key
    // material) so a left secure group leaves nothing behind locally. No-op for
    // GSS groups: no in-memory entry, and the persistence files do not exist
    // (NotFound is ignored).
    state.treekem_groups.write().await.remove(&id);
    remove_treekem_persistence_for_group_id(&state, &id, "leave_group").await;
    save_named_groups(&state).await;
    save_mls_groups(&state).await;
    stop_named_group_metadata_listener(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "left": name })),
    )
}

// ---------------------------------------------------------------------------
// Full named-group model (Phase A/B/C) — policy, roles, join requests, cards
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(in crate::server) struct UpdateGroupRequest {
    name: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(in crate::server) struct UpdateGroupPolicyRequest {
    preset: Option<String>,
    discoverability: Option<x0x::groups::GroupDiscoverability>,
    admission: Option<x0x::groups::GroupAdmission>,
    confidentiality: Option<x0x::groups::GroupConfidentiality>,
    read_access: Option<x0x::groups::GroupReadAccess>,
    write_access: Option<x0x::groups::GroupWriteAccess>,
}

#[derive(Debug, Deserialize)]
pub(in crate::server) struct UpdateMemberRoleRequest {
    role: String,
}

#[derive(Debug, Deserialize, Default)]
pub(in crate::server) struct CreateJoinRequestBody {
    message: Option<String>,
}

fn now_millis_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Require the caller to be an active Admin or higher.
fn require_admin_or_above(
    info: &x0x::groups::GroupInfo,
    caller_hex: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    match info.caller_role(caller_hex) {
        Some(role) if role.at_least(x0x::groups::GroupRole::Admin) => Ok(()),
        _ => Err(forbidden("admin role required")),
    }
}

fn reject_withdrawn_group(
    info: &x0x::groups::GroupInfo,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    info.withdrawn
        .then(|| api_error(StatusCode::CONFLICT, "group is withdrawn"))
}

#[cfg(test)]
static POST_CRYPTO_FORCED_WITHDRAWN_GROUPS: std::sync::LazyLock<StdMutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| StdMutex::new(HashSet::new()));

#[cfg(test)]
static ATOMIC_PERSIST_POST_JSON_FORCED_WITHDRAWN_GROUPS: std::sync::LazyLock<
    StdMutex<HashSet<String>>,
> = std::sync::LazyLock::new(|| StdMutex::new(HashSet::new()));

// Test-only hooks that force the post-crypto race windows exercised by the
// terminality unit tests. Production code never populates these sets.
#[cfg(test)]
fn forced_withdrawn_for_test(
    forced: &StdMutex<HashSet<String>>,
    poison_message: &'static str,
    group_id: &str,
    stable_group_id: Option<&str>,
) -> bool {
    let forced = forced.lock().expect(poison_message);
    forced.contains(group_id)
        || stable_group_id
            .filter(|stable| !stable.is_empty())
            .is_some_and(|stable| forced.contains(stable))
}

#[cfg(test)]
async fn maybe_force_withdrawn_group_for_test(
    forced: &StdMutex<HashSet<String>>,
    poison_message: &'static str,
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
) {
    if !forced_withdrawn_for_test(forced, poison_message, group_id, stable_group_id) {
        return;
    }

    let mut groups = state.named_groups.write().await;
    let mut aliases = collect_same_stable_group_aliases(&groups, group_id, stable_group_id);
    aliases.insert(group_id.to_string());
    if let Some(stable) = stable_group_id.filter(|stable| !stable.is_empty()) {
        aliases.insert(stable.to_string());
    }
    for alias in aliases {
        if let Some(info) = groups.get_mut(&alias) {
            info.withdrawn = true;
            clear_group_info_key_material(info);
        }
    }
}

#[cfg(test)]
async fn maybe_force_post_crypto_withdrawn_group_for_test(
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
) {
    maybe_force_withdrawn_group_for_test(
        &POST_CRYPTO_FORCED_WITHDRAWN_GROUPS,
        "post-crypto forced-withdrawn test hook poisoned",
        state,
        group_id,
        stable_group_id,
    )
    .await;
}

#[cfg(test)]
async fn maybe_force_atomic_persist_post_json_withdrawn_group_for_test(
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
) {
    maybe_force_withdrawn_group_for_test(
        &ATOMIC_PERSIST_POST_JSON_FORCED_WITHDRAWN_GROUPS,
        "atomic-persist forced-withdrawn test hook poisoned",
        state,
        group_id,
        stable_group_id,
    )
    .await;
}

// Post-crypto rechecks: if terminality wins a race after expensive crypto work,
// drop the just-produced effect and report the withdrawn conflict instead.
fn post_crypto_withdrawn_group_conflict(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
    stable_group_id: Option<&str>,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let selected_withdrawn = groups.get(group_id).is_some_and(|info| info.withdrawn);
    let selected_missing = !groups.contains_key(group_id);
    let stable_group_withdrawn = stable_group_id
        .filter(|stable| !stable.is_empty())
        .is_some_and(|stable| {
            if groups.contains_key(stable) {
                groups.get(stable).is_some_and(|info| info.withdrawn) && selected_missing
            } else {
                selected_missing && has_withdrawn_group_record(groups, stable)
            }
        });
    (selected_withdrawn || stable_group_withdrawn)
        .then(|| api_error(StatusCode::CONFLICT, "group is withdrawn"))
}

fn active_same_stable_keyed_alias_exists(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
) -> bool {
    collect_same_stable_group_aliases(groups, group_id, Some(group_id))
        .iter()
        .any(|alias| {
            groups
                .get(alias)
                .is_some_and(|info| !info.withdrawn && info.shared_secret.is_some())
        })
}

fn open_envelope_withdrawn_group_conflict(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    (has_withdrawn_group_record(groups, group_id)
        && !active_same_stable_keyed_alias_exists(groups, group_id))
    .then(|| api_error(StatusCode::CONFLICT, "group is withdrawn"))
}

async fn reject_withdrawn_group_record_after_crypto(
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    #[cfg(test)]
    maybe_force_post_crypto_withdrawn_group_for_test(state, group_id, stable_group_id).await;

    let groups = state.named_groups.read().await;
    post_crypto_withdrawn_group_conflict(&groups, group_id, stable_group_id)
}

fn secure_group_effect_response_after_terminality_recheck_from_groups(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
    stable_group_id: Option<&str>,
    effect: serde_json::Value,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Some(resp) = post_crypto_withdrawn_group_conflict(groups, group_id, stable_group_id) {
        resp
    } else {
        (StatusCode::OK, Json(effect))
    }
}

pub(in crate::server) async fn secure_group_effect_response_after_terminality_recheck(
    state: &AppState,
    group_id: &str,
    stable_group_id: Option<&str>,
    effect: serde_json::Value,
) -> (StatusCode, Json<serde_json::Value>) {
    #[cfg(test)]
    maybe_force_post_crypto_withdrawn_group_for_test(state, group_id, stable_group_id).await;

    let groups = state.named_groups.read().await;
    secure_group_effect_response_after_terminality_recheck_from_groups(
        &groups,
        group_id,
        stable_group_id,
        effect,
    )
}

async fn open_envelope_effect_response_after_terminality_recheck(
    state: &AppState,
    group_id: &str,
    effect: serde_json::Value,
) -> (StatusCode, Json<serde_json::Value>) {
    #[cfg(test)]
    maybe_force_post_crypto_withdrawn_group_for_test(state, group_id, Some(group_id)).await;

    let groups = state.named_groups.read().await;
    if let Some(resp) = open_envelope_withdrawn_group_conflict(&groups, group_id) {
        resp
    } else {
        (StatusCode::OK, Json(effect))
    }
}

/// Friendly REST pre-check for the ADR-0016 last-admin invariant.
///
/// Applies the handler's intended roster mutation to a clone of the group
/// through the shared library helper. Returns the 409 response to send
/// when the act would strip the last active admin (legacy `Owner` counts
/// as Admin). This is UX only — the authoritative enforcement is the same
/// shared check inside
/// `seal_commit` / `finalize_applied_commit` on every delivery path.
fn last_admin_precheck(
    info: &x0x::groups::GroupInfo,
    apply: impl FnOnce(&mut x0x::groups::GroupInfo),
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    x0x::groups::last_admin_precheck_error(info, apply)
        .map(|error| api_error(StatusCode::CONFLICT, error))
}

/// PATCH /groups/:id — update name/description (admin+).
pub(in crate::server) async fn update_named_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateGroupRequest>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    // Serialize against concurrent membership applies + other API mutators (see
    // `AppState::group_membership_locks`).
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;
    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get_mut(&id) else {
        return not_found("group not found");
    };
    if let Err(e) = require_admin_or_above(info, &caller_hex) {
        return e;
    }
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }
    let name_update = req.name.clone();
    let desc_update = req.description.clone();
    if let Some(name) = req.name {
        info.name = name;
    }
    if let Some(desc) = req.description {
        info.description = desc;
    }
    info.updated_at = now_ms;
    info.roster_revision = info.roster_revision.saturating_add(1);
    let revision = info.roster_revision;
    let commit = match info.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seal failed: {e}"),
            );
        }
    };
    let updated_name = info.name.clone();
    let updated_desc = info.description.clone();
    let metadata_topic = info.metadata_topic.clone();
    let event_group_id = info.stable_group_id().to_string();
    let delivery_roster = info.clone();
    drop(groups);
    save_named_groups(&state).await;

    let event = NamedGroupMetadataEvent::GroupMetadataUpdated {
        group_id: event_group_id,
        revision,
        actor: caller_hex,
        name: name_update,
        description: desc_update,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    spawn_named_group_event_delivery_to_active_members(&state, &delivery_roster, &event, &[]);
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "name": updated_name,
            "description": updated_desc,
            "revision": revision,
        })),
    )
}

/// PATCH /groups/:id/policy — update policy (admin+).
pub(in crate::server) async fn update_group_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateGroupPolicyRequest>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let membership_lock = group_membership_lock(&state, &id).await;
    let membership_guard = membership_lock.lock().await;
    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get_mut(&id) else {
        return not_found("group not found");
    };
    if let Err(e) = require_admin_or_above(info, &caller_hex) {
        return e;
    }
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }

    let mut new_policy = info.policy.clone();
    if let Some(preset_name) = req.preset.as_deref() {
        match x0x::groups::GroupPolicyPreset::from_name(preset_name) {
            Some(preset) => new_policy = preset.to_policy(),
            None => {
                return bad_request("unknown preset");
            }
        }
    }
    if let Some(d) = req.discoverability {
        new_policy.discoverability = d;
    }
    if let Some(a) = req.admission {
        new_policy.admission = a;
    }
    if let Some(c) = req.confidentiality {
        new_policy.confidentiality = c;
    }
    if let Some(r) = req.read_access {
        new_policy.read_access = r;
    }
    if let Some(w) = req.write_access {
        new_policy.write_access = w;
    }

    info.policy = new_policy.clone();
    info.policy_revision = info.policy_revision.saturating_add(1);
    let revision = info.policy_revision;
    info.updated_at = now_ms;

    // Establish discovery topic when the group becomes publicly discoverable.
    if info.policy.discoverability != x0x::groups::GroupDiscoverability::Hidden
        && info.discovery_card_topic.is_none()
    {
        info.discovery_card_topic = Some(format!(
            "x0x.group.{}.card",
            &info.mls_group_id[..16.min(info.mls_group_id.len())]
        ));
    }

    let commit = match info.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seal failed: {e}"),
            );
        }
    };
    let metadata_topic = info.metadata_topic.clone();
    let event_group_id = info.stable_group_id().to_string();
    let policy_clone = info.policy.clone();
    let delivery_roster = info.clone();
    drop(groups);
    save_named_groups(&state).await;
    drop(membership_guard);

    let event = NamedGroupMetadataEvent::PolicyUpdated {
        group_id: event_group_id,
        revision,
        actor: caller_hex,
        policy: policy_clone.clone(),
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    spawn_named_group_event_delivery_to_active_members(&state, &delivery_roster, &event, &[]);
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "policy": policy_clone, "revision": revision })),
    )
}

/// PATCH /groups/:id/members/:agent_id/role — change a member's role (admin+).
///
/// Only the flat ADR-0016 vocabulary (`admin`, `member`) is assignable.
/// Ownership transfer is deliberately unsupported: ADR-0016 §4 dissolved
/// the distinct Owner role, so `role=owner` returns a 400 naming the legacy
/// role rather than a partial-transfer stub (issue #107 item (d)).
pub(in crate::server) async fn update_member_role(
    State(state): State<Arc<AppState>>,
    Path((id, agent_id_hex)): Path<(String, String)>,
    Json(req): Json<UpdateMemberRoleRequest>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let new_role = match x0x::groups::GroupRole::assignable_from_name(&req.role) {
        Ok(role) => role,
        Err(error) => return bad_request(error),
    };
    let membership_lock = group_membership_lock(&state, &id).await;
    let membership_guard = membership_lock.lock().await;

    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get_mut(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "group not found" })),
        );
    };

    // P0-7: target must exist in members_v2 (active, banned, or removed — NOT absent).
    let target_entry = info.members_v2.get(&agent_id_hex).cloned();
    let Some(target_entry) = target_entry else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "member not found" })),
        );
    };
    if target_entry.is_removed() || target_entry.is_banned() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "error": "cannot change role of a removed or banned member"
            })),
        );
    }

    if let Err(e) = require_admin_or_above(info, &caller_hex) {
        return e;
    }
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }

    // ADR-0016 R2: friendly pre-check — a demotion must not strip the last
    // active admin (legacy Owner counts as Admin).
    if let Some(resp) = last_admin_precheck(info, |g| g.set_member_role(&agent_id_hex, new_role)) {
        return resp;
    }

    // Role changes are metadata-only: they do not add/remove TreeKEM leaves or
    // require Commit/Welcome transport, so TreeKEM groups may apply them before
    // Phase 3 membership transport lands.
    info.set_member_role(&agent_id_hex, new_role);
    info.roster_revision = info.roster_revision.saturating_add(1);
    let revision = info.roster_revision;
    let commit = match info.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": format!("seal failed: {e}") })),
            );
        }
    };
    let metadata_topic = info.metadata_topic.clone();
    let event_group_id = info.stable_group_id().to_string();
    let delivery_roster = info.clone();
    drop(groups);
    save_named_groups(&state).await;
    drop(membership_guard);

    let event = NamedGroupMetadataEvent::MemberRoleUpdated {
        group_id: event_group_id,
        revision,
        actor: caller_hex,
        agent_id: agent_id_hex,
        role: new_role,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    spawn_named_group_event_delivery_to_active_members(&state, &delivery_roster, &event, &[]);
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "role": new_role, "revision": revision })),
    )
}

/// POST /groups/:id/ban/:agent_id — ban a member (admin+).
pub(in crate::server) async fn ban_group_member(
    State(state): State<Arc<AppState>>,
    Path((id, agent_id_hex)): Path<(String, String)>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    // Serialize against concurrent membership applies + other API mutators (see
    // `AppState::group_membership_locks`). Held across the delegation to the
    // TreeKEM helper below, which must NOT re-acquire it (single-level lock).
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;
    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    if let Err(e) = require_admin_or_above(info, &caller_hex) {
        return e;
    }
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        drop(groups);
        return ban_treekem_group_member(state, id, agent_id_hex, caller_hex).await;
    }
    // ADR-0016 R2: friendly pre-check before any mutation/rekey side effect.
    if let Some(resp) = last_admin_precheck(info, |g| g.ban_member(&agent_id_hex, None)) {
        return resp;
    }
    let mut next = info.clone();
    next.ban_member(&agent_id_hex, Some(caller_hex.clone()));
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    let metadata_topic = next.metadata_topic.clone();
    let event_group_id = next.stable_group_id().to_string();

    // Phase D.2: rotate the group shared secret so banned peer's stale secret
    // cannot decrypt new-epoch content. Capture remaining active members with
    // their KEM pubkeys so we can seal the new secret to each.
    let is_encrypted =
        next.policy.confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted;
    type RekeyBundle = (Option<[u8; 32]>, u64, Vec<(String, Option<String>)>);
    let (new_secret, new_epoch, remaining_targets): RekeyBundle = if is_encrypted {
        let (sec_vec, ep) = next.rotate_shared_secret();
        let mut sec = [0u8; 32];
        if sec_vec.len() == 32 {
            sec.copy_from_slice(&sec_vec);
        }
        let remaining: Vec<(String, Option<String>)> = next
            .active_members()
            .map(|m| (m.agent_id.clone(), m.kem_public_key_b64.clone()))
            .collect();
        (Some(sec), ep, remaining)
    } else {
        (None, 0, Vec::new())
    };
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seal failed: {e}"),
            );
        }
    };
    if !store_named_group_info_locked(&mut groups, &id, next) {
        return api_error(StatusCode::CONFLICT, "group is withdrawn");
    }
    drop(groups);
    save_named_groups(&state).await;

    // Deliver the rotated secret to each remaining member (skip self). Each
    // envelope is sealed to that member's published ML-KEM-768 public key
    // via `seal_group_secret_to_recipient`, so only the recipient's private
    // key can open it.
    if let Some(ref secret) = new_secret {
        for (recipient, recipient_kem_b64) in &remaining_targets {
            if recipient == &caller_hex {
                continue;
            }
            let Some(kem_b64) = recipient_kem_b64 else {
                tracing::warn!(
                    recipient = %LogHexId::agent(&recipient),
                    "rekey: no KEM pubkey on record for remaining member; cannot seal"
                );
                continue;
            };
            publish_secure_share(
                &state,
                &metadata_topic,
                &event_group_id,
                recipient,
                kem_b64,
                &caller_hex,
                secret,
                new_epoch,
            )
            .await;
        }
    }

    // P0-4: drive local MLS remove_member so the banning daemon's MLS state no
    // longer treats the banned peer as a recipient. Cross-daemon rekey
    // propagation to existing members remains Phase D.2.
    if let Ok(target_agent) = parse_agent_id_hex(&agent_id_hex) {
        let mut mls_groups = state.mls_groups.write().await;
        if let Some(group) = mls_groups.get_mut(&id) {
            if group.is_member(&target_agent) {
                match group.remove_member(target_agent).await {
                    Ok(_) => {
                        tracing::debug!(
                            target: "x0x::groups",
                            "banned {} → removed from MLS group {}",
                            &agent_id_hex[..16.min(agent_id_hex.len())],
                            &id[..16.min(id.len())]
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "MLS remove_member on ban failed: {e} — roster banned anyway"
                        );
                    }
                }
            }
        }
    }
    save_mls_groups(&state).await;

    let event = NamedGroupMetadataEvent::MemberBanned {
        group_id: event_group_id,
        revision,
        actor: caller_hex,
        agent_id: agent_id_hex,
        secret_epoch: if is_encrypted { Some(new_epoch) } else { None },
        treekem_commit_b64: None,
        treekem_epoch: None,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "revision": revision })),
    )
}

async fn ban_treekem_group_member(
    state: Arc<AppState>,
    id: String,
    agent_id_hex: String,
    caller_hex: String,
) -> (StatusCode, Json<serde_json::Value>) {
    use base64::Engine as _;

    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let target_agent = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };
    let (mut next, metadata_topic, event_group_id) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "ok": false, "error": "group not found" })),
            );
        };
        if let Err(e) = require_admin_or_above(info, &caller_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        // ADR-0016 R2: friendly pre-check before any TreeKEM work begins.
        if let Some(resp) = last_admin_precheck(info, |g| g.ban_member(&agent_id_hex, None)) {
            return resp;
        }
        (
            info.clone(),
            info.metadata_topic.clone(),
            info.stable_group_id().to_string(),
        )
    };
    // Issue #205: resolve the target's TreeKEM KeyPackage with on-demand
    // recovery, mirroring it onto the cloned snapshot so the banned member's
    // package survives the write-back.
    let target_kp_b64 =
        match resolve_member_treekem_kp_for_removal_locked(&state, &id, &agent_id_hex).await {
            Ok(kp_b64) => kp_b64,
            Err(resp) => return resp,
        };
    next.set_member_treekem_key_package(&agent_id_hex, target_kp_b64.clone());
    let target_kp_bytes = match base64::engine::general_purpose::STANDARD.decode(&target_kp_b64) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "member TreeKEM KeyPackage is not valid base64"
                })),
            );
        }
    };
    let group = {
        let map = state.treekem_groups.read().await;
        map.get(&id).cloned()
    };
    let Some(group) = group else {
        return (
            StatusCode::FAILED_DEPENDENCY,
            Json(
                serde_json::json!({ "ok": false, "error": "TreeKEM group not loaded — restart or re-share required" }),
            ),
        );
    };
    let mut guard = group.lock().await;
    let treekem_epoch = guard.epoch().saturating_add(1);
    next.roster_revision = next.roster_revision.saturating_add(1);
    let revision = next.roster_revision;
    next.ban_member(&agent_id_hex, Some(caller_hex.clone()));
    next.secret_epoch = treekem_epoch;
    next.security_binding = Some(format!("treekem:epoch={treekem_epoch}"));
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": format!("seal failed: {e}") })),
            );
        }
    };
    let treekem_commit = match guard.remove_member_verified(target_agent, &target_kp_bytes) {
        Ok(commit) => commit,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                Json(
                    serde_json::json!({ "ok": false, "error": format!("TreeKEM ban removal failed: {e}") }),
                ),
            );
        }
    };
    if guard.epoch() != treekem_epoch {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "ok": false, "error": "TreeKEM epoch did not advance as expected" }),
            ),
        );
    }
    if let Err(e) =
        persist_treekem_and_named_groups_atomic_with_info(&state, &id, next.clone(), &guard).await
    {
        tracing::error!(group_id = %LogHexId::group(&id), "failed to persist TreeKEM snapshot after ban: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "ok": false, "error": "failed to persist secure group state" }),
            ),
        );
    }
    drop(guard);
    let mut groups = state.named_groups.write().await;
    groups.insert(id.clone(), next.clone());
    drop(groups);
    save_named_groups(&state).await;
    let _ = prune_treekem_cache_member(&state, &id, &agent_id_hex, "local_member_banned").await;

    let event = NamedGroupMetadataEvent::MemberBanned {
        group_id: event_group_id,
        revision,
        actor: caller_hex,
        agent_id: agent_id_hex.clone(),
        secret_epoch: None,
        treekem_commit_b64: Some(base64::engine::general_purpose::STANDARD.encode(treekem_commit)),
        treekem_epoch: Some(treekem_epoch),
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    remember_treekem_membership_event(&state, &event).await;
    spawn_named_group_event_delivery_to_active_members(
        &state,
        &next,
        &event,
        std::slice::from_ref(&agent_id_hex),
    );
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "revision": revision })),
    )
}

/// DELETE /groups/:id/ban/:agent_id — unban a member (admin+).
pub(in crate::server) async fn unban_group_member(
    State(state): State<Arc<AppState>>,
    Path((id, agent_id_hex)): Path<(String, String)>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let membership_lock = group_membership_lock(&state, &id).await;
    let membership_guard = membership_lock.lock().await;
    let mut groups = state.named_groups.write().await;
    let Some(info) = groups.get_mut(&id) else {
        return not_found("group not found");
    };
    if let Err(e) = require_admin_or_above(info, &caller_hex) {
        return e;
    }
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }
    if !info.is_banned(&agent_id_hex) {
        return bad_request("member is not banned");
    }
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        if let Some(member) = info.members_v2.get_mut(&agent_id_hex) {
            member.state = x0x::groups::GroupMemberState::Removed;
            member.updated_at = now_ms;
            member.removed_by = None;
        }
    } else {
        info.unban_member(&agent_id_hex);
    }
    info.roster_revision = info.roster_revision.saturating_add(1);
    let revision = info.roster_revision;
    let commit = match info.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seal failed: {e}"),
            );
        }
    };
    let metadata_topic = info.metadata_topic.clone();
    let event_group_id = info.stable_group_id().to_string();
    drop(groups);
    save_named_groups(&state).await;
    drop(membership_guard);

    let event = NamedGroupMetadataEvent::MemberUnbanned {
        group_id: event_group_id,
        revision,
        actor: caller_hex,
        agent_id: agent_id_hex,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "revision": revision })),
    )
}

/// GET /groups/:id/requests — list join requests (admin+).
pub(in crate::server) async fn list_join_requests(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    if let Err(e) = require_admin_or_above(info, &caller_hex) {
        return e;
    }
    let mut requests: Vec<&x0x::groups::JoinRequest> = info.join_requests.values().collect();
    requests.sort_by_key(|r| r.created_at);
    let list: Vec<serde_json::Value> = requests
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "requests": list })),
    )
}

/// POST /groups/:id/requests — submit a join request (non-member, non-banned).
pub(in crate::server) async fn create_join_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Option<Json<CreateJoinRequestBody>>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let req_body = body.map(|b| b.0).unwrap_or_default();
    let now_ms = now_millis_u64();
    let membership_lock = group_membership_lock(&state, &id).await;
    let membership_guard = membership_lock.lock().await;

    let (metadata_topic, event_group_id, request, creator_hex, commit) = {
        let mut groups = state.named_groups.write().await;
        let Some(info) = groups.get_mut(&id) else {
            return not_found("group not found");
        };
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if info.policy.admission != x0x::groups::GroupAdmission::RequestAccess {
            return forbidden("group admission is not request_access");
        }
        if info.is_banned(&caller_hex) {
            return forbidden("banned");
        }
        if info.has_active_member(&caller_hex) {
            return api_error(StatusCode::CONFLICT, "already a member");
        }
        if info
            .join_requests
            .values()
            .any(|r| r.requester_agent_id == caller_hex && r.is_pending())
        {
            return api_error(StatusCode::CONFLICT, "pending request already exists");
        }

        let mut request = x0x::groups::JoinRequest::new(
            info.mls_group_id.clone(),
            caller_hex.clone(),
            req_body.message.clone(),
            now_ms,
        );
        if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
            use base64::Engine as _;
            let group_id_bytes = match hex::decode(&info.mls_group_id) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("invalid TreeKEM group id: {e}"),
                    );
                }
            };
            let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
            let prepared =
                match x0x::mls::TreeKemMlsGroup::prepare_member(state.agent.agent_id(), &seed) {
                    Ok(prepared) => prepared,
                    Err(e) => {
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("failed to prepare TreeKEM KeyPackage: {e}"),
                        );
                    }
                };
            request.treekem_key_package_b64 = Some(BASE64.encode(prepared.key_package_bytes()));
        }
        info.join_requests
            .insert(request.request_id.clone(), request.clone());
        let commit = match info.seal_commit(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };
        let creator_hex = hex::encode(info.creator.as_bytes());
        let metadata_topic = info.metadata_topic.clone();
        let event_group_id = info.stable_group_id().to_string();
        drop(groups);
        (metadata_topic, event_group_id, request, creator_hex, commit)
    };

    save_named_groups(&state).await;
    drop(membership_guard);

    // Include our ML-KEM-768 public key so the approver can seal the group
    // shared secret directly to us on approval.
    use base64::Engine as _;
    let requester_kem_b64 = BASE64.encode(&state.agent_kem_keypair.public_bytes);
    let event = NamedGroupMetadataEvent::JoinRequestCreated {
        group_id: event_group_id,
        request_id: request.request_id.clone(),
        requester_agent_id: request.requester_agent_id.clone(),
        message: request.message.clone(),
        ts: request.created_at,
        requester_kem_public_key_b64: Some(requester_kem_b64),
        treekem_key_package_b64: request.treekem_key_package_b64.clone(),
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;
    let _ = creator_hex; // reserved for direct-notification future enhancement

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "ok": true,
            "request_id": request.request_id,
            "group_id": id,
        })),
    )
}

/// POST /groups/:id/requests/:request_id/approve — approve request (admin+).
pub(in crate::server) async fn approve_join_request(
    State(state): State<Arc<AppState>>,
    Path((id, request_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    // Serialize against concurrent membership applies + other API mutators (see
    // `AppState::group_membership_locks`). Held across the delegation to the
    // TreeKEM helper below, which must NOT re-acquire it (single-level lock).
    let membership_lock = group_membership_lock(&state, &id).await;
    let _membership_guard = membership_lock.lock().await;
    {
        let groups = state.named_groups.read().await;
        if let Some(info) = groups.get(&id) {
            if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                drop(groups);
                return approve_treekem_join_request(state, id, request_id, caller_hex).await;
            }
        }
    }
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();

    let (metadata_topic, event_group_id, requester_hex, revision, commit) = {
        let mut groups = state.named_groups.write().await;
        let Some(info) = groups.get_mut(&id) else {
            return not_found("group not found");
        };
        if let Err(e) = require_admin_or_above(info, &caller_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        if let Some(resp) = treekem_membership_unsupported(info) {
            return resp;
        }
        let Some(req) = info.join_requests.get_mut(&request_id) else {
            return not_found("request not found");
        };
        if !req.is_pending() {
            return api_error(StatusCode::CONFLICT, "request is not pending");
        }
        req.status = x0x::groups::JoinRequestStatus::Approved;
        req.reviewed_by = Some(caller_hex.clone());
        req.reviewed_at = Some(now_ms);
        let requester_hex = req.requester_agent_id.clone();
        info.add_member(
            requester_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(caller_hex.clone()),
            None,
        );
        info.roster_revision = info.roster_revision.saturating_add(1);
        let commit = match info.seal_commit(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };
        let metadata_topic = info.metadata_topic.clone();
        let event_group_id = info.stable_group_id().to_string();
        let revision = info.roster_revision;
        drop(groups);
        (
            metadata_topic,
            event_group_id,
            requester_hex,
            revision,
            commit,
        )
    };

    save_named_groups(&state).await;

    // Phase D.2: deliver the current group shared secret to the new member
    // via a `SecureShareDelivered` envelope on the group metadata topic,
    // sealed with ML-KEM-768 to the requester's published public key. Only
    // applies to MlsEncrypted groups.
    let (shared_secret_snapshot, secret_epoch_snapshot, is_encrypted, requester_kem_b64) = {
        let groups = state.named_groups.read().await;
        groups
            .get(&id)
            .map(|g| {
                let requester_kem = g
                    .members_v2
                    .get(&requester_hex)
                    .and_then(|m| m.kem_public_key_b64.clone());
                (
                    g.shared_secret.clone(),
                    g.secret_epoch,
                    g.policy.confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted,
                    requester_kem,
                )
            })
            .unwrap_or((None, 0, false, None))
    };
    if is_encrypted {
        match (shared_secret_snapshot.as_ref(), requester_kem_b64.as_ref()) {
            (Some(sec_vec), Some(kem_b64)) if sec_vec.len() == 32 => {
                let mut sec = [0u8; 32];
                sec.copy_from_slice(sec_vec);
                publish_secure_share(
                    &state,
                    &metadata_topic,
                    &event_group_id,
                    &requester_hex,
                    kem_b64,
                    &caller_hex,
                    &sec,
                    secret_epoch_snapshot,
                )
                .await;
            }
            (None, _) => {
                tracing::warn!(
                    group_id = %LogHexId::group(&id),
                    "approval: no group shared secret yet; requester will receive via next rekey"
                );
            }
            (_, None) => {
                tracing::warn!(
                    group_id = %LogHexId::group(&id),
                    requester = %LogHexId::agent(&requester_hex),
                    "approval: requester KEM pubkey unknown; cannot seal secure share"
                );
            }
            _ => {}
        }
    }

    // P0-3: drive local MLS add_member so the approver's MLS state includes the
    // new member. Cross-daemon welcome propagation (Bob's daemon receives the
    // welcome packet and joins the MLS group) is explicit Phase D.2 — tracked
    // below as "welcome propagation gap".
    let requester_bytes = parse_agent_id_hex(&requester_hex);
    {
        let mut mls_groups = state.mls_groups.write().await;
        if let Some(group) = mls_groups.get_mut(&id) {
            if let Ok(member_id) = requester_bytes {
                if !group.is_member(&member_id) {
                    match group.add_member(member_id).await {
                        Ok(_) => {
                            tracing::debug!(
                                target: "x0x::groups",
                                "approved {} → added to MLS group {}",
                                &requester_hex[..16.min(requester_hex.len())],
                                &id[..16.min(id.len())]
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "MLS add_member on approval failed: {e} — roster updated anyway"
                            );
                        }
                    }
                }
            }
        }
    }
    save_mls_groups(&state).await;

    let event = NamedGroupMetadataEvent::JoinRequestApproved {
        group_id: event_group_id,
        request_id,
        revision,
        actor: caller_hex,
        requester_agent_id: requester_hex.clone(),
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: None,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    spawn_named_group_event_delivery(&state, &requester_hex, &event);
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "revision": revision })),
    )
}

async fn approve_treekem_join_request(
    state: Arc<AppState>,
    id: String,
    request_id: String,
    caller_hex: String,
) -> (StatusCode, Json<serde_json::Value>) {
    use base64::Engine as _;

    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();

    let (mut next, metadata_topic, event_group_id, requester_hex, requester_id, kp_bytes) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return not_found("group not found");
        };
        if let Err(e) = require_admin_or_above(info, &caller_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        let Some(req) = info.join_requests.get(&request_id) else {
            return not_found("request not found");
        };
        if !req.is_pending() {
            return api_error(StatusCode::CONFLICT, "request is not pending");
        }
        if info.is_banned(&req.requester_agent_id) {
            return forbidden("requester is banned");
        }
        let requester_id = match parse_agent_id_hex(&req.requester_agent_id) {
            Ok(id) => id,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "ok": false, "error": e })),
                );
            }
        };
        let Some(kp_b64) = req.treekem_key_package_b64.clone() else {
            return api_error(
                StatusCode::FAILED_DEPENDENCY,
                "request is missing TreeKEM KeyPackage",
            );
        };
        let kp_bytes = match BASE64.decode(kp_b64) {
            Ok(bytes) => bytes,
            Err(_) => {
                return bad_request("request TreeKEM KeyPackage is not valid base64");
            }
        };
        (
            info.clone(),
            info.metadata_topic.clone(),
            info.stable_group_id().to_string(),
            req.requester_agent_id.clone(),
            requester_id,
            kp_bytes,
        )
    };

    let group = {
        let map = state.treekem_groups.read().await;
        map.get(&id).cloned()
    };
    let Some(group) = group else {
        return api_error(
            StatusCode::FAILED_DEPENDENCY,
            "TreeKEM group not loaded — restart or re-share required",
        );
    };
    let mut guard = group.lock().await;
    let treekem_epoch = guard.epoch().saturating_add(1);
    next.roster_revision = next.roster_revision.saturating_add(1);
    if let Some(req) = next.join_requests.get_mut(&request_id) {
        req.status = x0x::groups::JoinRequestStatus::Approved;
        req.reviewed_by = Some(caller_hex.clone());
        req.reviewed_at = Some(now_ms);
    }
    next.add_member(
        requester_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(caller_hex.clone()),
        None,
    );
    let approval_recovery_original = NamedGroupMetadataEvent::MemberJoined {
        group_id: id.clone(),
        stable_group_id: Some(event_group_id.clone()),
        member_agent_id: requester_hex.clone(),
        member_public_key_b64: String::new(),
        role: x0x::groups::GroupRole::Member,
        display_name: None,
        inviter_agent_id: caller_hex.clone(),
        invite_secret: String::new(),
        ts_ms: now_ms,
        treekem_key_package_b64: Some(BASE64.encode(&kp_bytes)),
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: None,
        recovery_authority_commit: None,
        signature_b64: String::new(),
    };
    next.set_member_treekem_key_package(&requester_hex, BASE64.encode(&kp_bytes));
    next.secret_epoch = treekem_epoch;
    let Some(binding) =
        treekem_recovery_security_binding(treekem_epoch, &approval_recovery_original)
    else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to bind recovery record",
        );
    };
    next.security_binding = Some(binding);
    let revision = next.roster_revision;
    let commit = match next.seal_commit(signing_kp, now_ms) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seal failed: {e}"),
            );
        }
    };
    let approval_recovery =
        match attest_member_joined_recovery_event(&approval_recovery_original, signing_kp, &commit)
        {
            Ok(recovery) => recovery,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("recovery attestation failed: {e}"),
                );
            }
        };
    let out = match guard.add_member(requester_id, &kp_bytes) {
        Ok(out) => out,
        Err(e) => {
            return api_error(
                StatusCode::CONFLICT,
                format!("TreeKEM add_member failed: {e}"),
            );
        }
    };
    if guard.epoch() != treekem_epoch {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "TreeKEM epoch did not advance as expected",
        );
    }
    if let Err(e) =
        persist_treekem_and_named_groups_atomic_with_info(&state, &id, next.clone(), &guard).await
    {
        tracing::error!(group_id = %LogHexId::group(&id), "failed to persist TreeKEM snapshot after approval: {e}");
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist secure group state",
        );
    }
    let treekem_commit = out.commit;
    let treekem_welcome = out.welcome;
    drop(guard);

    let mut groups = state.named_groups.write().await;
    groups.insert(id.clone(), next.clone());
    drop(groups);
    save_named_groups(&state).await;

    let welcome_ref =
        stage_treekem_welcome(&state, &event_group_id, &requester_hex, treekem_welcome).await;
    let event = NamedGroupMetadataEvent::JoinRequestApproved {
        group_id: event_group_id,
        request_id,
        revision,
        actor: caller_hex,
        requester_agent_id: requester_hex.clone(),
        treekem_commit_b64: Some(BASE64.encode(treekem_commit)),
        treekem_welcome_b64: None,
        welcome_ref: Some(welcome_ref),
        treekem_epoch: Some(treekem_epoch),
        treekem_key_package_hash: next
            .members_v2
            .get(&requester_hex)
            .and_then(|member| member.treekem_key_package_hash.clone()),
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    remember_treekem_membership_event(&state, &event).await;
    spawn_named_group_event_delivery_to_active_members(
        &state,
        &next,
        &event,
        std::slice::from_ref(&requester_hex),
    );
    cache_treekem_member_key_package(
        &state,
        join_result_key(&id, &requester_hex),
        approval_recovery.clone(),
        true,
    )
    .await;
    spawn_named_group_event_delivery_to_active_members(&state, &next, &approval_recovery, &[]);
    let prior_recovery = state
        .treekem_member_key_packages
        .events_matching(|recovery| {
            matches!(
                recovery,
                NamedGroupMetadataEvent::MemberJoined { member_agent_id, .. }
                    if member_agent_id != &requester_hex
            ) && verify_authority_attested_member_joined_recovery(&next, recovery)
        })
        .await;
    for recovery in prior_recovery {
        spawn_named_group_event_delivery(&state, &requester_hex, &recovery);
        spawn_named_group_event_delivery_after(
            &state,
            &requester_hex,
            &recovery,
            GROUP_BACKGROUND_PUBLISH_DELAY,
        );
    }
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "revision": revision })),
    )
}

/// POST /groups/:id/requests/:request_id/reject — reject request (admin+).
pub(in crate::server) async fn reject_join_request(
    State(state): State<Arc<AppState>>,
    Path((id, request_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let membership_lock = group_membership_lock(&state, &id).await;
    let membership_guard = membership_lock.lock().await;

    let (metadata_topic, event_group_id, requester_hex, commit) = {
        let mut groups = state.named_groups.write().await;
        let Some(info) = groups.get_mut(&id) else {
            return not_found("group not found");
        };
        if let Err(e) = require_admin_or_above(info, &caller_hex) {
            return e;
        }
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        let Some(req) = info.join_requests.get_mut(&request_id) else {
            return not_found("request not found");
        };
        if !req.is_pending() {
            return api_error(StatusCode::CONFLICT, "request is not pending");
        }
        req.status = x0x::groups::JoinRequestStatus::Rejected;
        req.reviewed_by = Some(caller_hex.clone());
        req.reviewed_at = Some(now_ms);
        let requester_hex = req.requester_agent_id.clone();
        let commit = match info.seal_commit(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };
        let metadata_topic = info.metadata_topic.clone();
        let event_group_id = info.stable_group_id().to_string();
        drop(groups);
        (metadata_topic, event_group_id, requester_hex, commit)
    };

    save_named_groups(&state).await;
    drop(membership_guard);

    let event = NamedGroupMetadataEvent::JoinRequestRejected {
        group_id: event_group_id,
        request_id,
        actor: caller_hex,
        requester_agent_id: requester_hex.clone(),
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    spawn_named_group_event_delivery(&state, &requester_hex, &event);
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// DELETE /groups/:id/requests/:request_id — cancel own pending request.
pub(in crate::server) async fn cancel_join_request(
    State(state): State<Arc<AppState>>,
    Path((id, request_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = now_millis_u64();
    let membership_lock = group_membership_lock(&state, &id).await;
    let membership_guard = membership_lock.lock().await;

    let (metadata_topic, event_group_id, requester_hex, commit) = {
        let mut groups = state.named_groups.write().await;
        let Some(info) = groups.get_mut(&id) else {
            return not_found("group not found");
        };
        if let Some(resp) = reject_withdrawn_group(info) {
            return resp;
        }
        let Some(req) = info.join_requests.get_mut(&request_id) else {
            return not_found("request not found");
        };
        if req.requester_agent_id != caller_hex {
            return forbidden("not your request");
        }
        if !req.is_pending() {
            return api_error(StatusCode::CONFLICT, "request is not pending");
        }
        req.status = x0x::groups::JoinRequestStatus::Cancelled;
        let requester_hex = req.requester_agent_id.clone();
        let commit = match info.seal_commit(signing_kp, now_ms) {
            Ok(c) => c,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };
        let metadata_topic = info.metadata_topic.clone();
        let event_group_id = info.stable_group_id().to_string();
        drop(groups);
        (metadata_topic, event_group_id, requester_hex, commit)
    };

    save_named_groups(&state).await;
    drop(membership_guard);

    let event = NamedGroupMetadataEvent::JoinRequestCancelled {
        group_id: event_group_id,
        request_id,
        requester_agent_id: requester_hex,
        commit: Some(commit),
    };
    publish_named_group_metadata_event(&state, &metadata_topic, &event).await;
    maybe_publish_group_card_after_state_change(&state, &id).await;

    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// GET /groups/discover — list locally known discoverable groups.
pub(in crate::server) async fn discover_groups(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let mut cards: HashMap<String, x0x::groups::GroupCard> = HashMap::new();
    let mut merge_card = |card: &x0x::groups::GroupCard| {
        let entry = cards.entry(card.group_id.clone());
        match entry {
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(card.clone());
            }
            std::collections::hash_map::Entry::Occupied(mut o) => {
                if card.supersedes(o.get()) {
                    o.insert(card.clone());
                }
            }
        }
    };

    // Phase C.2: merge the local cache by the card's stable public group_id,
    // not by the cache's internal key. The cache may legitimately contain
    // the same signed card under both the local MLS id and the stable group id.
    {
        let mut card_cache = state.group_card_cache.write().await;
        prune_and_bound_group_card_cache(&mut card_cache, now_millis_u64());
        for card in card_cache.values() {
            merge_card(card);
        }
    }
    // Phase C.2: merge in shard-cache contents. Higher-revision wins on collision.
    {
        let shard_cache = state.directory_cache.read().await;
        for card in shard_cache.iter_all() {
            merge_card(card);
        }
    }
    // Also synthesize signed cards for any local groups the caller owns that are discoverable.
    let groups = state.named_groups.read().await;
    let signing_kp = state.agent.identity().agent_keypair();
    for info in groups.values() {
        if let Ok(Some(card)) = info.to_signed_group_card(signing_kp) {
            merge_card(&card);
        }
    }
    let mut list: Vec<x0x::groups::GroupCard> = cards.into_values().collect();
    // Phase C.2: honour `?q=` by filtering cards through the shard-cache
    // search helper (matches tag/name/id case-insensitively).
    if let Some(q) = params.get("q") {
        if !q.trim().is_empty() {
            let q_lc = q.trim().to_lowercase();
            list.retain(|c| {
                c.name.to_lowercase().contains(&q_lc)
                    || c.tags.iter().any(|t| t.to_lowercase().contains(&q_lc))
                    || c.group_id == q_lc
            });
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "groups": list })),
    )
}

/// GET /groups/discover/nearby — Phase C.2 presence-social browse.
///
/// Returns discoverable group cards weighted toward groups that peers
/// reachable in the current partition are actively using. Privacy rules:
/// - `Hidden` never appears.
/// - `ListedToContacts` never appears on this endpoint (only on
///   contact-scoped surfaces).
/// - `PublicDirectory` appears only if it has been observed on the
///   shard discovery plane.
///
/// IMPORTANT: this endpoint is intentionally a **shard-cache-only
/// witness**. It does not merge the legacy bridge cache or locally
/// synthesised cards, so a hit here is attributable to C.2 discovery
/// rather than local ownership or bridge dual-publish. Tighter
/// FOAF-based weighting is follow-up work.
pub(in crate::server) async fn discover_groups_nearby(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let mut seen = std::collections::HashSet::<String>::new();
    let mut out: Vec<x0x::groups::GroupCard> = Vec::new();
    let shard_cache = state.directory_cache.read().await;
    for card in shard_cache.iter_all() {
        if card.withdrawn {
            continue;
        }
        if card.policy_summary.discoverability != x0x::groups::GroupDiscoverability::PublicDirectory
        {
            continue;
        }
        if seen.insert(card.group_id.clone()) {
            out.push(card.clone());
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "groups": out })),
    )
}

/// GET /groups/discover/subscriptions — list active shard subscriptions.
pub(in crate::server) async fn list_discovery_subscriptions(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let subs = state.directory_subscriptions.read().await.clone();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "count": subs.len(),
            "subscriptions": subs.subscriptions,
        })),
    )
}

/// POST /groups/discover/subscribe — subscribe to a shard derived from
/// either `{ "kind": "tag|name|id", "key": "<token>" }` (shard is computed
/// from the normalised key), or `{ "kind": "...", "shard": <u32> }` if
/// the caller already knows the shard id.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct SubscribeDiscoveryRequest {
    kind: String,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    shard: Option<u32>,
}

pub(in crate::server) async fn create_discovery_subscription(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubscribeDiscoveryRequest>,
) -> impl IntoResponse {
    let Some(kind) = x0x::groups::ShardKind::from_str(&req.kind) else {
        return bad_request("kind must be 'tag', 'name', or 'id'");
    };
    let (shard, key) = match (req.shard, req.key.as_deref()) {
        (Some(s), k) => (s, k.map(str::to_string)),
        (None, Some(k)) => {
            let normalised = match kind {
                x0x::groups::ShardKind::Tag => x0x::groups::normalize_tag(k),
                x0x::groups::ShardKind::Name => k.trim().to_lowercase(),
                x0x::groups::ShardKind::Id => k.to_string(),
            };
            (x0x::groups::shard_of(kind, &normalised), Some(normalised))
        }
        (None, None) => {
            return bad_request("either 'shard' or 'key' is required");
        }
    };
    if state.directory_subscriptions.read().await.len() >= x0x::groups::DEFAULT_MAX_SUBSCRIPTIONS {
        return api_error(StatusCode::PAYLOAD_TOO_LARGE, "subscription limit reached");
    }
    let rec = x0x::groups::SubscriptionRecord {
        kind,
        shard,
        key,
        subscribed_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    };
    let newly_added = state.directory_subscriptions.write().await.add(rec);
    save_directory_subscriptions(&state).await;
    subscribe_shard(Arc::clone(&state), kind, shard).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "newly_added": newly_added,
            "kind": kind,
            "shard": shard,
            "topic": x0x::groups::topic_for(kind, shard),
        })),
    )
}

/// DELETE /groups/discover/subscribe/:kind/:shard — unsubscribe from a shard.
pub(in crate::server) async fn delete_discovery_subscription(
    State(state): State<Arc<AppState>>,
    Path((kind_str, shard)): Path<(String, u32)>,
) -> impl IntoResponse {
    let Some(kind) = x0x::groups::ShardKind::from_str(&kind_str) else {
        return bad_request("kind must be 'tag', 'name', or 'id'");
    };
    let existed = state
        .directory_subscriptions
        .write()
        .await
        .remove(kind, shard);
    save_directory_subscriptions(&state).await;
    unsubscribe_shard(&state, kind, shard).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "existed": existed })),
    )
}

/// GET /groups/cards/:id — fetch a single group card.
pub(in crate::server) async fn get_group_card(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Prefer cached card; fall back to synthesising from a locally-owned group.
    {
        let mut cache = state.group_card_cache.write().await;
        prune_and_bound_group_card_cache(&mut cache, now_millis_u64());
        if let Some(card) = cache.get(&id) {
            return Json(serde_json::to_value(card).unwrap_or(serde_json::Value::Null))
                .into_response();
        }
    }
    let groups = state.named_groups.read().await;
    if let Some(info) = groups.get(&id) {
        match info.to_signed_group_card(state.agent.identity().agent_keypair()) {
            Ok(Some(card)) => {
                return Json(serde_json::to_value(&card).unwrap_or(serde_json::Value::Null))
                    .into_response();
            }
            Ok(None) => {}
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("card sign failed: {e}"),
                )
                .into_response();
            }
        }
    }
    not_found("card not found").into_response()
}

/// POST /groups/cards/import — accept a discoverable card into the local cache.
///
/// If no local `GroupInfo` exists for the group_id, creates a minimal "discovered"
/// stub so that the caller can submit join requests. The stub records the policy
/// summary (inferred from the card) but has an empty roster (the caller is not a
/// member yet) and no MLS group. When a `JoinRequestApproved` event arrives, the
/// stub is upgraded via `apply_named_group_metadata_event`.
pub(in crate::server) async fn import_group_card(
    State(state): State<Arc<AppState>>,
    Json(card): Json<x0x::groups::GroupCard>,
) -> impl IntoResponse {
    if card.policy_summary.discoverability == x0x::groups::GroupDiscoverability::Hidden {
        return bad_request("card is hidden");
    }
    if let Err(e) = card.verify_signature() {
        return bad_request(format!("invalid signed card: {e}"));
    }
    let group_id = card.group_id.clone();
    let membership_lock = group_membership_lock(&state, &group_id).await;
    let _membership_guard = membership_lock.lock().await;

    if card.withdrawn {
        let mut cache = state.group_card_cache.write().await;
        prune_expired_group_cards(&mut cache, now_millis_u64());
        remove_group_card_if_not_stale(&mut cache, &card);
        drop(cache);

        let local = {
            let groups = state.named_groups.read().await;
            let local_group_key = groups.get(&group_id).map(|_| group_id.clone()).or_else(|| {
                groups
                    .iter()
                    .find(|(_, info)| info.stable_group_id() == group_id)
                    .map(|(key, _)| key.clone())
            });
            local_group_key.and_then(|key| {
                groups.get(&key).cloned().map(|info| {
                    let aliases = collect_same_stable_group_aliases(&groups, &key, Some(&group_id));
                    (key, info, aliases)
                })
            })
        };
        if let Some((key, info, aliases)) = local {
            let protects_keyed_local_group =
                local_group_has_protected_crypto_material(state.as_ref(), &info, &aliases).await;
            if withdrawn_card_can_terminally_mark_local_group(
                &info,
                &card,
                protects_keyed_local_group,
            ) {
                let mut next = info;
                if apply_withdrawn_group_card_to_group_info(&mut next, &card) {
                    retain_withdrawn_group_tombstone(&state, &key, next, "withdrawn_card_import")
                        .await;
                }
            } else if protects_keyed_local_group && group_card_supersedes_group_info(&card, &info) {
                tracing::warn!(
                    group_id = %LogHexId::group(&group_id),
                    authority = %LogHexId::agent(&card.authority_agent_id),
                    "ignored withdrawn card for live keyed group; signed withdrawal commit required"
                );
            }
        } else {
            let aliases = HashSet::from([group_id.clone()]);
            let _ = prune_treekem_cache_groups(
                state.as_ref(),
                &aliases,
                "withdrawn_card_import_without_local_group",
            )
            .await;
        }
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "group_id": group_id, "withdrawn": true })),
        );
    }

    // Parse owner hex into an AgentId for the stub.
    let creator = match parse_agent_id_hex(&card.owner_agent_id) {
        Ok(id) => id,
        Err(_) => {
            return bad_request("invalid owner_agent_id");
        }
    };

    // Full policy is reconstructed from the card summary — all five axes round-trip.
    let policy = x0x::groups::GroupPolicy::from(&card.policy_summary);

    {
        let groups = state.named_groups.read().await;
        if has_withdrawn_group_record(&groups, &group_id) {
            return api_error(StatusCode::CONFLICT, "group is withdrawn");
        }
    }

    {
        let mut cache = state.group_card_cache.write().await;
        prune_expired_group_cards(&mut cache, now_millis_u64());
        if cache_group_card_if_newer(&mut cache, group_id.clone(), card.clone()) {
            enforce_group_card_cache_cap(&mut cache);
        }
    }

    // ADR-0023 §4: group cards are Replaceable — latest per group id.
    if let Some(history) = state.agent.history() {
        if let Ok(card_json) = serde_json::to_vec(&card) {
            let now = i64::try_from(x0x::dm::now_unix_ms()).unwrap_or(i64::MAX);
            history.record(x0x::history::HistoryRecord {
                msg_id: x0x::history::HistoryRecord::compute_msg_id(None, &card_json),
                scope: x0x::history::Scope::Group(group_id.clone()),
                author_agent: None,
                author_machine: None,
                author_pubkey: None,
                sent_at_ms: now,
                seen_at_ms: now,
                direction: x0x::history::Direction::Inbound,
                content_type: "application/json".to_string(),
                payload: card_json,
                signed_artifact: None,
                signature: None,
                sig_context: None,
                provenance: x0x::history::Provenance::VerifiedEnvelope,
                replace_key: Some(format!("group-card:{group_id}")),
            });
        }
    }

    // Create or refresh a local stub GroupInfo keyed by the authority's
    // stable group id from the card.
    let mut groups = state.named_groups.write().await;
    if !groups.contains_key(&group_id) {
        let mut stub = x0x::groups::GroupInfo::with_policy(
            card.name.clone(),
            card.description.clone(),
            creator,
            group_id.clone(),
            policy.clone(),
        );
        if let Some(metadata_topic) = card.metadata_topic.clone() {
            stub.metadata_topic = metadata_topic;
        }
        // Imported stubs must preserve the authority's stable `group_id`
        // from the card. Recomputing a fresh genesis here would mint a new
        // local-only stable id, breaking public-topic alignment and any
        // state-hash / revision metadata copied from the discovered card.
        stub.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            group_id.clone(),
            card.owner_agent_id.clone(),
            card.created_at,
            String::new(),
        ));
        stub.created_at = card.created_at;
        stub.updated_at = card.updated_at;
        stub.state_revision = card.revision;
        if !card.state_hash.is_empty() {
            stub.state_hash = card.state_hash.clone();
        }
        stub.prev_state_hash = card.prev_state_hash.clone();
        stub.withdrawn = card.withdrawn;
        // The stub should not treat the caller as an admin — reset members_v2
        // and store the authority (from card) as the active Admin.
        stub.members_v2.clear();
        stub.members_v2.insert(
            card.owner_agent_id.clone(),
            x0x::groups::GroupMember::new_admin(card.owner_agent_id.clone(), None, card.created_at),
        );
        // Phase D.2: the importer is NOT a member yet. They must not have a
        // shared secret until a SecureShareDelivered envelope arrives after
        // approval. Clearing the auto-generated stub secret also prevents the
        // apply handler from treating "already have a secret at epoch 0" as
        // a reason to drop alice's delivery.
        stub.shared_secret = None;
        stub.secret_epoch = 0;
        groups.insert(group_id.clone(), stub);
    } else if let Some(existing) = groups.get_mut(&group_id) {
        existing.name = card.name.clone();
        existing.description = card.description.clone();
        existing.policy = policy;
        existing.created_at = card.created_at;
        existing.updated_at = card.updated_at;
        if let Some(metadata_topic) = card.metadata_topic.clone() {
            existing.metadata_topic = metadata_topic;
        }
        existing.state_revision = card.revision;
        if !card.state_hash.is_empty() {
            existing.state_hash = card.state_hash.clone();
        }
        existing.prev_state_hash = card.prev_state_hash.clone();
        existing.withdrawn = card.withdrawn;
        if existing
            .genesis
            .as_ref()
            .is_none_or(|genesis| genesis.group_id != group_id)
        {
            existing.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
                group_id.clone(),
                card.owner_agent_id.clone(),
                card.created_at,
                String::new(),
            ));
        }
        existing
            .members_v2
            .entry(card.owner_agent_id.clone())
            .or_insert_with(|| {
                x0x::groups::GroupMember::new_admin(
                    card.owner_agent_id.clone(),
                    None,
                    card.created_at,
                )
            });
    }
    drop(groups);
    save_named_groups(&state).await;
    ensure_named_group_listeners(Arc::clone(&state), &group_id).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": group_id,
            // P1-9: be explicit about what an imported stub actually is. The
            // importer is not a member; they have no MLS state; admin
            // operations against this group from this daemon will be denied
            // until a JoinRequestApproved event promotes them.
            "stub": true,
            "discovered": true,
            "secure_access": false,
        })),
    )
}

// ---------------------------------------------------------------------------
// Phase D.2 — Group shared-secret encrypted content (GSS)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(in crate::server) struct SecureEncryptRequest {
    /// Base64-encoded plaintext payload.
    payload_b64: String,
}

#[derive(Debug, Deserialize)]
pub(in crate::server) struct SecureDecryptRequest {
    ciphertext_b64: String,
    /// GSS plane only: per-message nonce. Unused for TreeKEM, whose
    /// `ApplicationCiphertext` carries its own nonce.
    #[serde(default)]
    nonce_b64: String,
    /// GSS plane only: ciphertext epoch (checked against the local epoch).
    /// Unused for TreeKEM, whose epoch is embedded in the ciphertext.
    #[serde(default)]
    secret_epoch: u64,
}

/// POST /groups/:id/secure/encrypt — AEAD-encrypt content using the group's
/// current shared secret. Member-only.
///
/// This is a symmetric-key layer alongside the MLS roster: it gives honest
/// cross-daemon encrypt/decrypt with rekey-on-ban, but does NOT provide the
/// per-message forward secrecy that full MLS TreeKEM would. Documented as
/// Phase D.2 scope.
/// Guard for membership-mutating named-group endpoints that still require a
/// TreeKEM-specific transport shape (direct invites/adds and ban/unban).
///
/// Request-access joins and creator removals use real TreeKEM Commit/Welcome or
/// Commit transport. The remaining guarded handlers still run the legacy GSS
/// rekey path (`rotate_shared_secret` + per-recipient reseal), which would
/// silently re-introduce a shared secret and relabel the plane. Refuse those
/// endpoints loudly until they provide KeyPackage/Welcome or removal Commit
/// inputs.
fn treekem_membership_unsupported(
    info: &x0x::groups::GroupInfo,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        Some(api_error(StatusCode::NOT_IMPLEMENTED, "TreeKEM secure-group membership flow is not supported by this endpoint; use request-access approval/removal transport"))
    } else {
        None
    }
}

fn treekem_metadata_event_requires_phase3(_event: &NamedGroupMetadataEvent) -> bool {
    false
}

/// Encrypt `payload_b64` for a real-TreeKEM group (ADR-0012). The live group's
/// send-ratchet advances, so the snapshot is persisted before returning to
/// prevent send-generation (nonce) reuse across a restart. Returns the
/// self-describing `ApplicationCiphertext` as `ciphertext_b64`.
async fn treekem_group_encrypt(
    state: &AppState,
    group_id_hex: &str,
    stable_group_id: Option<&str>,
    payload_b64: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    use base64::Engine as _;
    let plaintext = match BASE64.decode(payload_b64) {
        Ok(p) => p,
        Err(_) => {
            return bad_request("invalid base64 payload");
        }
    };
    let group = {
        let map = state.treekem_groups.read().await;
        match map.get(group_id_hex) {
            Some(g) => Arc::clone(g),
            None => {
                return api_error(
                    StatusCode::FAILED_DEPENDENCY,
                    "TreeKEM group not loaded — restart or re-share required",
                );
            }
        }
    };
    let mut guard = group.lock().await;
    let ciphertext = match guard.encrypt_message(&plaintext) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("treekem encrypt failed: {e}"),
            );
        }
    };
    // Persist the advanced ratchet state before returning. Skipping a burned
    // generation on error is harmless (no reuse); a stale on-disk snapshot is
    // not, so a persist failure fails the request.
    if let Err(e) = persist_treekem_snapshot_bound(state, group_id_hex, &guard).await {
        tracing::error!(group_id = %group_id_hex, "failed to persist TreeKEM snapshot after encrypt: {e}");
        if let Some(resp) =
            reject_withdrawn_group_record_after_crypto(state, group_id_hex, stable_group_id).await
        {
            return resp;
        }
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist secure group state",
        );
    }
    let epoch = guard.epoch();
    drop(guard);
    record_mls_history(
        state,
        stable_group_id.unwrap_or(group_id_hex),
        &plaintext,
        x0x::history::Direction::Outbound,
        epoch,
    );
    secure_group_effect_response_after_terminality_recheck(
        state,
        group_id_hex,
        stable_group_id,
        serde_json::json!({
            "ok": true,
            "ciphertext_b64": BASE64.encode(&ciphertext),
            "secret_epoch": epoch,
            "secure_plane": "treekem",
        }),
    )
    .await
}

/// Decrypt a real-TreeKEM `ApplicationCiphertext` (ADR-0012). The per-sender
/// replay window advances, so the snapshot is persisted to keep replay
/// protection across a restart (best-effort: a persist failure is logged but
/// does not invalidate the already-recovered plaintext).
async fn treekem_group_decrypt(
    state: &AppState,
    group_id_hex: &str,
    stable_group_id: Option<&str>,
    ciphertext_b64: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    use base64::Engine as _;
    let ciphertext = match BASE64.decode(ciphertext_b64) {
        Ok(c) => c,
        Err(_) => {
            return bad_request("invalid base64 ciphertext");
        }
    };
    let group = {
        let map = state.treekem_groups.read().await;
        match map.get(group_id_hex) {
            Some(g) => Arc::clone(g),
            None => {
                return api_error(
                    StatusCode::FAILED_DEPENDENCY,
                    "TreeKEM group not loaded — restart or re-share required",
                );
            }
        }
    };
    let mut guard = group.lock().await;
    let plaintext = match guard.decrypt_message(&ciphertext) {
        Ok(p) => p,
        Err(e) => {
            return bad_request(format!("treekem decrypt failed: {e}"));
        }
    };
    // Persisting the receive replay window is best-effort. A failure here may
    // permit the same ciphertext to be accepted again after restart, but the
    // plaintext has already been validly recovered and retrying in-process would
    // hit the replay guard. Unlike send-side snapshot failure, this is not a
    // nonce-reuse risk, so return the plaintext and surface the persistence
    // problem in logs.
    if let Err(e) = persist_treekem_snapshot_bound(state, group_id_hex, &guard).await {
        tracing::error!(group_id = %group_id_hex, "failed to persist TreeKEM snapshot after decrypt: {e}");
        if let Some(resp) =
            reject_withdrawn_group_record_after_crypto(state, group_id_hex, stable_group_id).await
        {
            return resp;
        }
    }
    let epoch = guard.epoch();
    drop(guard);
    record_mls_history(
        state,
        stable_group_id.unwrap_or(group_id_hex),
        &plaintext,
        x0x::history::Direction::Inbound,
        epoch,
    );
    secure_group_effect_response_after_terminality_recheck(
        state,
        group_id_hex,
        stable_group_id,
        serde_json::json!({
            "ok": true,
            "payload_b64": BASE64.encode(&plaintext),
            "secret_epoch": epoch,
            "secure_plane": "treekem",
        }),
    )
    .await
}

pub(in crate::server) async fn secure_group_encrypt(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<SecureEncryptRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }
    if !info.has_active_member(&caller_hex) {
        return forbidden("not a member");
    }
    if info.policy.confidentiality != x0x::groups::GroupConfidentiality::MlsEncrypted {
        return bad_request("group is not MlsEncrypted — use public send instead");
    }
    // ADR-0012: real-TreeKEM groups encrypt via the live group's ratchet, not
    // the GSS shared secret. Dispatch on the group's plane.
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        let stable_group_id = info.stable_group_id().to_string();
        drop(groups);
        return treekem_group_encrypt(
            state.as_ref(),
            &id,
            Some(&stable_group_id),
            &req.payload_b64,
        )
        .await;
    }
    let Some(key) = info.secure_message_key() else {
        return api_error(
            StatusCode::FAILED_DEPENDENCY,
            "no shared secret available — await welcome or ask admin to re-share",
        );
    };
    let epoch = info.secret_epoch;
    let group_id_clone = info.stable_group_id().to_string();
    drop(groups);

    use base64::Engine as _;
    let plaintext = match BASE64.decode(&req.payload_b64) {
        Ok(p) => p,
        Err(_) => {
            return bad_request("invalid base64 payload");
        }
    };

    // Generate a fresh random nonce per message — epoch-keyed AEAD requires
    // per-message nonce uniqueness.
    use rand::RngCore;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    use chacha20poly1305::aead::{Aead, KeyInit};
    let cipher = match chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "cipher init failed");
        }
    };
    let aad = format!("x0x.group.secure|{}|{}", group_id_clone, epoch);
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    let ciphertext = match cipher.encrypt(
        nonce,
        chacha20poly1305::aead::Payload {
            msg: &plaintext,
            aad: aad.as_bytes(),
        },
    ) {
        Ok(c) => c,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encrypt failed: {e}"),
            );
        }
    };

    record_mls_history(
        state.as_ref(),
        &group_id_clone,
        &plaintext,
        x0x::history::Direction::Outbound,
        epoch,
    );
    secure_group_effect_response_after_terminality_recheck(
        state.as_ref(),
        &id,
        Some(&group_id_clone),
        serde_json::json!({
            "ok": true,
            "ciphertext_b64": BASE64.encode(&ciphertext),
            "nonce_b64": BASE64.encode(nonce_bytes),
            "secret_epoch": epoch,
        }),
    )
    .await
}

/// POST /groups/:id/secure/decrypt — AEAD-decrypt content using the group's
/// shared secret at the given epoch.
///
/// Returns 400 if the caller's local shared-secret epoch differs from the
/// ciphertext epoch (i.e. they've been rekeyed out, or haven't caught up yet).
/// A banned peer with a stale secret cannot decrypt new-epoch messages — that
/// proves the rekey-on-ban semantics.
pub(in crate::server) async fn secure_group_decrypt(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<SecureDecryptRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }
    if !info.has_active_member(&caller_hex) && !info.is_banned(&caller_hex) {
        // Removed/never-member callers can't decrypt.
        return forbidden("not a member");
    }
    // ADR-0012: real-TreeKEM groups decrypt via the live group's ratchet. A
    // removed member's leaf is gone from the live group, so decryption of a
    // post-removal epoch fails there — that is the FS/PCS guarantee.
    if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        let stable_group_id = info.stable_group_id().to_string();
        drop(groups);
        return treekem_group_decrypt(
            state.as_ref(),
            &id,
            Some(&stable_group_id),
            &req.ciphertext_b64,
        )
        .await;
    }
    let Some(local_secret) = info.shared_secret.clone() else {
        return api_error(StatusCode::FAILED_DEPENDENCY, "no shared secret available");
    };
    let local_epoch = info.secret_epoch;
    let group_id_clone = info.stable_group_id().to_string();
    drop(groups);

    // Caller's local epoch must match the ciphertext epoch. A banned member
    // keeps their pre-ban secret; they cannot decrypt ciphertexts at higher
    // epochs because they don't have the new secret.
    if req.secret_epoch != local_epoch {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "error": "epoch mismatch — re-share required",
                "local_epoch": local_epoch,
                "ciphertext_epoch": req.secret_epoch,
            })),
        );
    }

    use base64::Engine as _;
    let ciphertext = match BASE64.decode(&req.ciphertext_b64) {
        Ok(c) => c,
        Err(_) => {
            return bad_request("invalid base64 ciphertext");
        }
    };
    let nonce_bytes = match BASE64.decode(&req.nonce_b64) {
        Ok(n) => n,
        Err(_) => {
            return bad_request("invalid base64 nonce");
        }
    };
    if nonce_bytes.len() != 12 {
        return bad_request("nonce must be 12 bytes");
    }

    let key = x0x::groups::GroupInfo::derive_message_key(
        &local_secret,
        req.secret_epoch,
        &group_id_clone,
    );
    use chacha20poly1305::aead::{Aead, KeyInit};
    let cipher = match chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "cipher init failed");
        }
    };
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    let aad = format!("x0x.group.secure|{}|{}", group_id_clone, req.secret_epoch);
    match cipher.decrypt(
        nonce,
        chacha20poly1305::aead::Payload {
            msg: &ciphertext,
            aad: aad.as_bytes(),
        },
    ) {
        Ok(plaintext) => {
            record_mls_history(
                state.as_ref(),
                &group_id_clone,
                &plaintext,
                x0x::history::Direction::Inbound,
                req.secret_epoch,
            );
            secure_group_effect_response_after_terminality_recheck(
                state.as_ref(),
                &id,
                Some(&group_id_clone),
                serde_json::json!({
                    "ok": true,
                    "payload_b64": BASE64.encode(&plaintext),
                    "secret_epoch": req.secret_epoch,
                }),
            )
            .await
        }
        Err(_) => forbidden("decryption failed"),
    }
}

/// POST /groups/:id/secure/reseal — produce a real `SecureShareDelivered`-
/// format envelope sealing the group's CURRENT shared secret to a named
/// recipient's ML-KEM-768 public key.
///
/// Authorization:
/// - Caller must pass `info.has_active_member(&caller_hex)` (403 otherwise).
/// - The caller's daemon must already hold `info.shared_secret` locally
///   (424 FAILED_DEPENDENCY otherwise).
///
/// These two checks together ensure the endpoint grants no capability the
/// caller does not already possess: an active member whose daemon holds the
/// current secret could re-seal it themselves at the primitive layer using
/// `seal_group_secret_to_recipient`. Note: the active-member check alone is
/// not sufficient — a freshly-approved member is Active before their gossip-
/// delivered envelope arrives; in that window `info.shared_secret` is None
/// and this endpoint returns 424.
///
/// The recipient must be a known member of the group with a published KEM
/// public key (404 / 424 otherwise).
///
/// Used by the D.2 adversarial E2E proof to obtain a **real live-path
/// envelope** (produced via the same `seal_group_secret_to_recipient` +
/// `secure_share_aad` path used on the approve/ban hot path) that can then
/// be posted to another daemon's `POST /groups/secure/open-envelope` to
/// demonstrate that a non-recipient cannot open it — stronger than the
/// "random bytes" adversarial check because the envelope is a genuine
/// sealing-path output bound to the current epoch + AAD.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct ResealRequest {
    /// Agent hex of the recipient whose ML-KEM public key will be used to
    /// seal the envelope. Must be an active member of the group.
    recipient: String,
}

pub(in crate::server) async fn secure_group_reseal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ResealRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&id) else {
        return not_found("group not found");
    };
    if let Some(resp) = reject_withdrawn_group(info) {
        return resp;
    }
    if !info.has_active_member(&caller_hex) {
        return forbidden("not a member");
    }
    // Recipient must be a known member with a KEM pubkey.
    let Some(recipient_member) = info.members_v2.get(&req.recipient) else {
        return not_found("recipient is not a member");
    };
    let Some(recipient_kem_b64) = recipient_member.kem_public_key_b64.clone() else {
        return api_error(
            StatusCode::FAILED_DEPENDENCY,
            "recipient has no published KEM public key",
        );
    };
    let Some(secret_vec) = info.shared_secret.clone() else {
        return api_error(
            StatusCode::FAILED_DEPENDENCY,
            "no shared secret available on this daemon",
        );
    };
    let epoch = info.secret_epoch;
    let group_id_wire = info.stable_group_id().to_string();
    drop(groups);

    if secret_vec.len() != 32 {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "shared secret has unexpected length",
        );
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_vec);

    use base64::Engine as _;
    let recipient_kem_bytes = match BASE64.decode(&recipient_kem_b64) {
        Ok(b) => b,
        Err(_) => {
            return bad_request("recipient KEM public key is not valid base64");
        }
    };
    let aad = secure_share_aad(&group_id_wire, &req.recipient, epoch);
    let (kem_ct, aead_nonce, aead_ct) =
        match x0x::groups::kem_envelope::seal_group_secret_to_recipient(
            &recipient_kem_bytes,
            &aad,
            &secret,
        ) {
            Ok(t) => t,
            Err(e) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("seal failed: {e}"),
                );
            }
        };

    secure_group_effect_response_after_terminality_recheck(
        state.as_ref(),
        &id,
        Some(&group_id_wire),
        serde_json::json!({
            "ok": true,
            "group_id": group_id_wire,
            "recipient": req.recipient,
            "secret_epoch": epoch,
            "kem_ciphertext_b64": BASE64.encode(&kem_ct),
            "aead_nonce_b64": BASE64.encode(aead_nonce),
            "aead_ciphertext_b64": BASE64.encode(&aead_ct),
        }),
    )
    .await
}

/// POST /groups/secure/open-envelope — ADVERSARIAL TEST endpoint.
///
/// Attempt to open a `SecureShareDelivered` envelope using THIS daemon's
/// ML-KEM-768 private key. If the envelope was not sealed to our public
/// key, this MUST fail. Used by `tests/e2e_named_groups.sh` section 2c to
/// prove recipient-confidentiality: an observer (different daemon, different
/// KEM keypair) cannot recover the group secret from a captured envelope.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct OpenEnvelopeRequest {
    group_id: String,
    recipient: String,
    secret_epoch: u64,
    kem_ciphertext_b64: String,
    aead_nonce_b64: String,
    aead_ciphertext_b64: String,
}

pub(in crate::server) async fn secure_open_envelope_adversarial(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OpenEnvelopeRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    {
        let groups = state.named_groups.read().await;
        if let Some(resp) = open_envelope_withdrawn_group_conflict(&groups, &req.group_id) {
            return resp;
        }
    }
    use base64::Engine as _;
    let kem_ct = match BASE64.decode(&req.kem_ciphertext_b64) {
        Ok(b) => b,
        Err(_) => {
            return bad_request("bad kem_ciphertext_b64");
        }
    };
    let nonce = match BASE64.decode(&req.aead_nonce_b64) {
        Ok(b) => b,
        Err(_) => {
            return bad_request("bad aead_nonce_b64");
        }
    };
    if nonce.len() != 12 {
        return bad_request("nonce must be 12 bytes");
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce);
    let aead_ct = match BASE64.decode(&req.aead_ciphertext_b64) {
        Ok(b) => b,
        Err(_) => {
            return bad_request("bad aead_ciphertext_b64");
        }
    };
    let aad = secure_share_aad(&req.group_id, &req.recipient, req.secret_epoch);
    match x0x::groups::kem_envelope::open_group_secret(
        &state.agent_kem_keypair,
        &aad,
        &kem_ct,
        &nonce_bytes,
        &aead_ct,
    ) {
        Ok(secret) => {
            open_envelope_effect_response_after_terminality_recheck(
                state.as_ref(),
                &req.group_id,
                serde_json::json!({
                    "ok": true,
                    "opened": true,
                    "secret_b64": BASE64.encode(secret),
                }),
            )
            .await
        }
        Err(_) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "opened": false,
                "error": "envelope not decryptable by this daemon's key",
            })),
        ),
    }
}

// ---------------------------------------------------------------------------
// Embedded GUI
// ---------------------------------------------------------------------------

/// Derive this agent's per-group TreeKEM identity seed from its long-term
/// ML-DSA secret key and the group's id bytes (ADR-0012). Centralised so the
/// create path and the restore path always agree on the seed (and therefore on
/// the re-derived identity / leaf).
fn agent_treekem_seed(agent: &Agent, group_id_bytes: &[u8]) -> [u8; 32] {
    let (_public, secret) = agent.identity().agent_keypair().to_bytes();
    x0x::mls::treekem::derive_identity_seed(&secret, group_id_bytes)
}

const TREEKEM_DAEMON_SNAPSHOT_MAGIC: &[u8; 4] = b"XTD1";

const TREEKEM_DAEMON_SNAPSHOT_VERSION: u8 = 1;

const TREEKEM_NAMED_JOURNAL_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::server) struct TreeKemSnapshotEnvelope {
    version: u8,
    state_revision: u64,
    state_hash: String,
    security_binding: Option<String>,
    snapshot: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::server) struct TreeKemNamedPersistJournal {
    version: u8,
    group_id_hex: String,
    named_groups_json: String,
    snapshot_envelope: Vec<u8>,
}

fn treekem_snapshot_path(treekem_dir: &FsPath, group_id_hex: &str) -> PathBuf {
    treekem_dir.join(format!("{group_id_hex}.snap"))
}

fn treekem_journal_path(treekem_dir: &FsPath, group_id_hex: &str) -> PathBuf {
    treekem_dir.join(format!("{group_id_hex}.journal"))
}

fn encode_treekem_snapshot_envelope(
    info: &x0x::groups::GroupInfo,
    group: &x0x::mls::TreeKemMlsGroup,
) -> anyhow::Result<Vec<u8>> {
    if info.withdrawn {
        anyhow::bail!("refusing to encode TreeKEM snapshot for withdrawn group");
    }
    let snapshot = group
        .to_snapshot_bytes()
        .map_err(|e| anyhow::anyhow!("treekem snapshot encode: {e}"))?;
    let mut bytes = TREEKEM_DAEMON_SNAPSHOT_MAGIC.to_vec();
    let envelope = TreeKemSnapshotEnvelope {
        version: TREEKEM_DAEMON_SNAPSHOT_VERSION,
        state_revision: info.state_revision,
        state_hash: info.state_hash.clone(),
        security_binding: info.security_binding.clone(),
        snapshot,
    };
    bytes.extend(
        postcard::to_stdvec(&envelope)
            .map_err(|e| anyhow::anyhow!("treekem snapshot envelope encode: {e}"))?,
    );
    Ok(bytes)
}

fn decode_treekem_snapshot_envelope(
    bytes: &[u8],
) -> anyhow::Result<Option<TreeKemSnapshotEnvelope>> {
    let Some(payload) = bytes.strip_prefix(TREEKEM_DAEMON_SNAPSHOT_MAGIC) else {
        return Ok(None);
    };
    let envelope: TreeKemSnapshotEnvelope = postcard::from_bytes(payload)
        .map_err(|e| anyhow::anyhow!("treekem snapshot envelope decode: {e}"))?;
    if envelope.version != TREEKEM_DAEMON_SNAPSHOT_VERSION {
        anyhow::bail!(
            "unsupported TreeKEM snapshot envelope version {}",
            envelope.version
        );
    }
    Ok(Some(envelope))
}

fn treekem_snapshot_envelope_matches_info(
    envelope: &TreeKemSnapshotEnvelope,
    info: &x0x::groups::GroupInfo,
) -> bool {
    envelope.state_revision == info.state_revision
        && envelope.state_hash == info.state_hash
        && envelope.security_binding == info.security_binding
}

async fn persist_treekem_snapshot_bytes(
    treekem_dir: &FsPath,
    group_id_hex: &str,
    bytes: Vec<u8>,
) -> anyhow::Result<()> {
    let path = treekem_snapshot_path(treekem_dir, group_id_hex);
    x0x::storage::write_private_bytes(&path, bytes)
        .await
        .map_err(|e| anyhow::anyhow!("treekem snapshot write: {e}"))?;
    Ok(())
}

/// Persist a TreeKEM snapshot bound to the currently durable named-group state.
async fn persist_treekem_snapshot_bound(
    state: &AppState,
    group_id_hex: &str,
    group: &x0x::mls::TreeKemMlsGroup,
) -> anyhow::Result<()> {
    let info = {
        let groups = state.named_groups.read().await;
        groups
            .get(group_id_hex)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("named group missing for TreeKEM snapshot"))?
    };
    ensure_treekem_persistence_allowed(
        state,
        group_id_hex,
        Some(info.stable_group_id()),
        "withdrawn_snapshot_persist",
    )
    .await?;
    let bytes = encode_treekem_snapshot_envelope(&info, group)?;
    persist_treekem_snapshot_bytes(&state.treekem_dir, group_id_hex, bytes).await?;
    ensure_treekem_persistence_allowed(
        state,
        group_id_hex,
        Some(info.stable_group_id()),
        "withdrawn_snapshot_persist",
    )
    .await
}

async fn ensure_treekem_persistence_allowed(
    state: &AppState,
    group_id_hex: &str,
    stable_group_id: Option<&str>,
    reason: &str,
) -> anyhow::Result<()> {
    ensure_named_group_key_material_install_allowed(state, group_id_hex, stable_group_id, reason)
        .await
}

/// Persist a supplied named-group state and matching TreeKEM snapshot with a
/// replay journal. The matching live map entry is installed before the journal
/// is removed and while the persistence mutex is still held.
async fn persist_treekem_and_named_groups_atomic_with_info(
    state: &AppState,
    group_id_hex: &str,
    info: x0x::groups::GroupInfo,
    group: &x0x::mls::TreeKemMlsGroup,
) -> anyhow::Result<()> {
    let _persistence_guard = state.named_groups_persistence_lock.lock().await;
    let stable_group_id = info.stable_group_id().to_string();
    #[cfg(test)]
    maybe_force_post_crypto_withdrawn_group_for_test(state, group_id_hex, Some(&stable_group_id))
        .await;
    if repair_withdrawn_named_groups_json_and_wipe_key_material_locked(
        state,
        group_id_hex,
        Some(&stable_group_id),
        "withdrawn_atomic_persist",
    )
    .await?
    {
        anyhow::bail!("refusing to persist key material for withdrawn group");
    }
    let named_groups_json = {
        let groups = state.named_groups.read().await;
        let mut next_groups = groups.clone();
        next_groups.insert(group_id_hex.to_string(), info.clone());
        serde_json::to_string_pretty(&next_groups)
            .map_err(|e| anyhow::anyhow!("named groups encode: {e}"))?
    };

    #[cfg(test)]
    maybe_force_atomic_persist_post_json_withdrawn_group_for_test(
        state,
        group_id_hex,
        Some(&stable_group_id),
    )
    .await;

    let snapshot_envelope = encode_treekem_snapshot_envelope(&info, group)?;
    let journal = TreeKemNamedPersistJournal {
        version: TREEKEM_NAMED_JOURNAL_VERSION,
        group_id_hex: group_id_hex.to_string(),
        named_groups_json: named_groups_json.clone(),
        snapshot_envelope: snapshot_envelope.clone(),
    };
    let journal_bytes = postcard::to_stdvec(&journal)
        .map_err(|e| anyhow::anyhow!("TreeKEM journal encode: {e}"))?;
    let journal_path = treekem_journal_path(&state.treekem_dir, group_id_hex);
    x0x::storage::write_private_bytes(&journal_path, journal_bytes)
        .await
        .map_err(|e| anyhow::anyhow!("TreeKEM journal write: {e}"))?;
    persist_treekem_snapshot_bytes(&state.treekem_dir, group_id_hex, snapshot_envelope).await?;
    if repair_withdrawn_named_groups_json_and_wipe_key_material_locked(
        state,
        group_id_hex,
        Some(&stable_group_id),
        "withdrawn_atomic_persist_late",
    )
    .await?
    {
        anyhow::bail!("refusing to persist key material for withdrawn group");
    }
    write_named_groups_json_atomic(&state.named_groups_path, &named_groups_json)
        .await
        .map_err(|e| anyhow::anyhow!("named groups write: {e}"))?;
    state
        .named_groups
        .write()
        .await
        .insert(group_id_hex.to_string(), info);
    if let Err(e) = tokio::fs::remove_file(&journal_path).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(anyhow::anyhow!("TreeKEM journal cleanup: {e}"));
        }
    }
    Ok(())
}

/// Persist current named-group JSON and a matching bound TreeKEM snapshot.
async fn persist_treekem_and_named_groups_atomic(
    state: &AppState,
    group_id_hex: &str,
    group: &x0x::mls::TreeKemMlsGroup,
) -> anyhow::Result<()> {
    let info = {
        let groups = state.named_groups.read().await;
        groups
            .get(group_id_hex)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("named group missing for TreeKEM atomic persist"))?
    };
    persist_treekem_and_named_groups_atomic_with_info(state, group_id_hex, info, group).await
}

pub(in crate::server) async fn recover_treekem_named_journals(
    named_groups_path: &FsPath,
    treekem_dir: &FsPath,
) -> anyhow::Result<()> {
    let mut entries = match tokio::fs::read_dir(treekem_dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(anyhow::anyhow!("read TreeKEM journal dir: {e}")),
    };
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| anyhow::anyhow!("read TreeKEM journal entry: {e}"))?
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("journal") {
            continue;
        }
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| anyhow::anyhow!("read TreeKEM journal {}: {e}", path.display()))?;
        let journal: TreeKemNamedPersistJournal = postcard::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("decode TreeKEM journal {}: {e}", path.display()))?;
        if journal.version != TREEKEM_NAMED_JOURNAL_VERSION {
            tracing::warn!(path = %path.display(), version = journal.version, "ignoring unsupported TreeKEM journal version");
            continue;
        }
        let named_groups: HashMap<String, x0x::groups::GroupInfo> =
            serde_json::from_str(&journal.named_groups_json).map_err(|e| {
                anyhow::anyhow!(
                    "decode named groups JSON in TreeKEM journal {}: {e}",
                    path.display()
                )
            })?;
        if has_withdrawn_group_record(&named_groups, &journal.group_id_hex) {
            remove_treekem_persistence_for_group_id_in_dir(
                treekem_dir,
                &journal.group_id_hex,
                "withdrawn_journal_replay",
            )
            .await;
            if let Err(e) = tokio::fs::remove_file(&path).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(anyhow::anyhow!(
                        "remove withdrawn TreeKEM journal {}: {e}",
                        path.display()
                    ));
                }
            }
            tracing::warn!(group_id = %LogHexId::group(&journal.group_id_hex), "discarded TreeKEM/named-group persistence journal for withdrawn group");
            continue;
        }
        let durable_named_groups: Option<HashMap<String, x0x::groups::GroupInfo>> =
            match tokio::fs::read_to_string(named_groups_path).await {
                Ok(json) => {
                    let mut groups: HashMap<String, x0x::groups::GroupInfo> =
                        serde_json::from_str(&json).with_context(|| {
                            format!(
                            "failed to parse named groups file {} before TreeKEM journal replay",
                            named_groups_path.display()
                        )
                        })?;
                    for info in groups.values_mut() {
                        info.migrate_from_v1();
                    }
                    Some(groups)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!(
                            "failed to read named groups file {} before TreeKEM journal replay",
                            named_groups_path.display()
                        )
                    });
                }
            };
        if durable_named_groups.as_ref().is_some_and(|groups| {
            has_withdrawn_group_record_for_journal_replay(
                groups,
                &journal.group_id_hex,
                &named_groups,
            )
        }) {
            remove_treekem_persistence_for_group_id_in_dir(
                treekem_dir,
                &journal.group_id_hex,
                "withdrawn_durable_journal_replay",
            )
            .await;
            if let Err(e) = tokio::fs::remove_file(&path).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(anyhow::anyhow!(
                        "remove durable-withdrawn TreeKEM journal {}: {e}",
                        path.display()
                    ));
                }
            }
            tracing::warn!(group_id = %LogHexId::group(&journal.group_id_hex), "discarded TreeKEM/named-group persistence journal because durable named groups contain a withdrawn record");
            continue;
        }
        persist_treekem_snapshot_bytes(
            treekem_dir,
            &journal.group_id_hex,
            journal.snapshot_envelope,
        )
        .await?;
        write_named_groups_json_atomic(named_groups_path, &journal.named_groups_json)
            .await
            .map_err(|e| anyhow::anyhow!("replay named groups journal: {e}"))?;
        tokio::fs::remove_file(&path)
            .await
            .map_err(|e| anyhow::anyhow!("remove replayed TreeKEM journal: {e}"))?;
        tracing::warn!(group_id = %journal.group_id_hex, "replayed TreeKEM/named-group persistence journal after prior crash");
    }
    Ok(())
}

/// Rebuild the live TreeKEM group map from on-disk snapshots at startup
/// (ADR-0012 Phase 4). For every named group tagged
/// [`x0x::mls::SecureGroupPlane::TreeKem`], restore its snapshot using the
/// agent's per-group identity seed. A missing or unreadable snapshot is logged
/// and skipped — the group stays unusable for secure content until re-shared,
/// never a crash.
pub(in crate::server) async fn restore_treekem_groups(
    named_groups: &HashMap<String, x0x::groups::GroupInfo>,
    agent: &Agent,
    treekem_dir: &FsPath,
) -> HashMap<String, Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>> {
    let mut restored = HashMap::new();
    let agent_id = agent.agent_id();
    for (group_id_hex, info) in named_groups {
        if info.withdrawn {
            remove_treekem_persistence_for_group_id_in_dir(
                treekem_dir,
                group_id_hex,
                "withdrawn_restore",
            )
            .await;
            continue;
        }
        if info.secure_plane != x0x::mls::SecureGroupPlane::TreeKem {
            continue;
        }
        let path = treekem_snapshot_path(treekem_dir, group_id_hex);
        let snapshot_bytes = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(
                    group_id = %group_id_hex,
                    "TreeKEM group tagged but no snapshot on disk; secure content unavailable until re-shared"
                );
                continue;
            }
            Err(e) => {
                tracing::warn!(group_id = %group_id_hex, "failed to read TreeKEM snapshot: {e}");
                continue;
            }
        };
        let snapshot = match decode_treekem_snapshot_envelope(&snapshot_bytes) {
            Ok(Some(envelope)) => {
                if !treekem_snapshot_envelope_matches_info(&envelope, info) {
                    tracing::warn!(
                        group_id = %group_id_hex,
                        snapshot_revision = envelope.state_revision,
                        named_revision = info.state_revision,
                        "TreeKEM snapshot/named-group binding mismatch; secure content unavailable until repaired"
                    );
                    continue;
                }
                envelope.snapshot
            }
            Ok(None) => {
                tracing::warn!(group_id = %group_id_hex, "restoring legacy unbound TreeKEM snapshot; future writes will bind it to named-group state");
                snapshot_bytes
            }
            Err(e) => {
                tracing::warn!(group_id = %group_id_hex, "failed to decode TreeKEM snapshot envelope: {e}");
                continue;
            }
        };
        let group_id_bytes = match hex::decode(&info.mls_group_id) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    group_id = %group_id_hex,
                    "invalid mls_group_id hex, cannot restore TreeKEM group: {e}"
                );
                continue;
            }
        };
        let seed = agent_treekem_seed(agent, &group_id_bytes);
        match x0x::mls::TreeKemMlsGroup::restore(&snapshot, agent_id, &seed) {
            Ok(g) => {
                tracing::info!(group_id = %group_id_hex, "restored TreeKEM group from snapshot");
                restored.insert(group_id_hex.clone(), Arc::new(tokio::sync::Mutex::new(g)));
            }
            Err(e) => {
                tracing::warn!(
                    group_id = %group_id_hex,
                    "failed to restore TreeKEM group (wrong identity or corrupt snapshot?): {e}"
                );
            }
        }
    }
    restored
}

async fn quarantine_corrupt_treekem_cache(path: &FsPath) -> std::io::Result<PathBuf> {
    let mut quarantine_os = path.as_os_str().to_owned();
    quarantine_os.push(format!(".corrupt-{}", uuid::Uuid::new_v4()));
    let quarantine_path = PathBuf::from(quarantine_os);
    tokio::fs::rename(path, &quarantine_path).await?;
    Ok(quarantine_path)
}

fn canonicalize_loaded_treekem_cache_entries(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    entries: BTreeMap<String, NamedGroupMetadataEvent>,
) -> (BTreeMap<String, NamedGroupMetadataEvent>, bool) {
    let mut canonical = BTreeMap::<String, NamedGroupMetadataEvent>::new();
    let mut changed = false;
    for (persisted_key, event) in entries {
        let NamedGroupMetadataEvent::MemberJoined {
            member_agent_id, ..
        } = &event
        else {
            changed = true;
            continue;
        };
        let canonical_key = join_result_key(
            &canonical_recovery_cache_group_id(groups, &event),
            &member_agent_id.to_ascii_lowercase(),
        );
        changed |= canonical_key != persisted_key;
        if let Some(existing) = canonical.get(&canonical_key) {
            changed = true;
            if !should_replace_recovery_cache_entry(existing, &event, true) {
                continue;
            }
        }
        canonical.insert(canonical_key, event);
    }
    (canonical, changed)
}

fn persisted_treekem_cache_key_is_valid(
    groups: &HashMap<String, x0x::groups::GroupInfo>,
    key: &str,
    event: &NamedGroupMetadataEvent,
) -> bool {
    let Some((expected_key, _)) = member_joined_kp_cache_entry(event) else {
        return false;
    };
    let NamedGroupMetadataEvent::MemberJoined {
        member_agent_id, ..
    } = event
    else {
        return false;
    };
    key == expected_key
        || key
            == join_result_key(
                &canonical_recovery_cache_group_id(groups, event),
                &member_agent_id.to_ascii_lowercase(),
            )
}

pub(in crate::server) async fn load_treekem_member_key_packages(
    path: &FsPath,
    groups: &HashMap<String, x0x::groups::GroupInfo>,
) -> Result<TreeKemMemberKeyPackageCache> {
    let (entries, startup_dirty) = match tokio::fs::read_to_string(path).await {
        Ok(json) => {
            match serde_json::from_str::<BTreeMap<String, NamedGroupMetadataEvent>>(&json) {
                Ok(mut cache) => {
                    let persisted_count = cache.len();
                    cache.retain(|key, event| {
                        persisted_treekem_cache_key_is_valid(groups, key, event)
                            && member_joined_key_package_relevant_to_groups(groups, event)
                    });
                    let (cache, canonicalized) =
                        canonicalize_loaded_treekem_cache_entries(groups, cache);
                    let rejected_count = persisted_count.saturating_sub(cache.len());
                    if rejected_count > 0 {
                        tracing::warn!(
                            path = %path.display(),
                            rejected_count,
                            "pruned invalid or irrelevant TreeKEM recovery-cache records at startup"
                        );
                    }
                    (cache, rejected_count > 0 || canonicalized)
                }
                Err(error) => {
                    let quarantine_path = quarantine_corrupt_treekem_cache(path)
                        .await
                        .with_context(|| {
                            format!(
                                "failed to quarantine corrupt TreeKEM recovery cache {} after parse error: {error}",
                                path.display()
                            )
                        })?;
                    tracing::error!(
                        path = %path.display(),
                        quarantine_path = %quarantine_path.display(),
                        cause = %error,
                        "quarantined corrupt TreeKEM recovery cache; starting empty"
                    );
                    (BTreeMap::new(), true)
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (BTreeMap::new(), false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read TreeKEM member key-package cache {}",
                    path.display()
                )
            });
        }
    };

    let (cache, evicted) =
        TreeKemMemberKeyPackageCache::from_entries(path.to_path_buf(), entries, startup_dirty)
            .context("failed to size TreeKEM member key-package cache")?;
    if evicted > 0 {
        tracing::warn!(
            path = %path.display(),
            evicted,
            "bounded TreeKEM recovery cache during startup compaction"
        );
    }
    if cache.diagnostics().await.dirty {
        let persistence = cache.persist_latest().await;
        if let TreeKemCachePersistenceStatus::Dirty { revision, error } = &persistence {
            tracing::error!(
                path = %path.display(),
                revision,
                error,
                "startup TreeKEM recovery-cache compaction remains dirty"
            );
            cache.schedule_persistence_retry();
        }
    }
    let diagnostics = cache.diagnostics().await;
    tracing::info!(
        path = %path.display(),
        records = diagnostics.entries,
        encoded_bytes = diagnostics.encoded_bytes,
        dirty = diagnostics.dirty,
        "loaded TreeKEM member key-package recovery cache"
    );
    Ok(cache)
}

pub(in crate::server) async fn load_named_groups(
    named_groups_path: &FsPath,
) -> Result<HashMap<String, x0x::groups::GroupInfo>> {
    match tokio::fs::read_to_string(named_groups_path).await {
        Ok(json) => {
            let mut groups = serde_json::from_str::<HashMap<String, x0x::groups::GroupInfo>>(&json)
                .with_context(|| {
                    format!(
                        "failed to parse named groups file {}",
                        named_groups_path.display()
                    )
                })?;
            for info in groups.values_mut() {
                info.migrate_from_v1();
            }
            tracing::info!(
                "Loaded {} named groups from {}",
                groups.len(),
                named_groups_path.display()
            );
            Ok(groups)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("No named groups file found, starting fresh");
            Ok(HashMap::new())
        }
        Err(e) => Err(e).with_context(|| {
            format!(
                "failed to read named groups file {}",
                named_groups_path.display()
            )
        }),
    }
}

async fn save_named_groups(state: &AppState) {
    let _persistence_guard = state.named_groups_persistence_lock.lock().await;
    let json = {
        let groups = state.named_groups.read().await;
        serde_json::to_string(&*groups)
    };
    #[cfg(test)]
    {
        let hook = NAMED_GROUP_SAVE_AFTER_SNAPSHOT_NOTIFY
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().cloned());
        if let Some((reached, release)) = hook {
            reached.notify_one();
            release.notified().await;
        }
    }
    match json {
        Ok(json) => {
            if let Err(e) = write_named_groups_json_atomic(&state.named_groups_path, &json).await {
                tracing::error!("Failed to save named groups: {e}");
            }
        }
        Err(e) => tracing::error!("Failed to serialize named groups: {e}"),
    }
}

async fn write_treekem_cache_json_atomic(path: &FsPath, json: &str) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(control) = take_treekem_cache_writer_hook_for_test(path) {
        // The writer has entered the one-shot hook. Signal entry with a stored
        // permit (notify_one keeps it until awaited, so observation is free of
        // await-ordering races), then either inject a failure or park until the
        // test releases a slow-disk simulation.
        control.entered.notify_one();
        if let Some(error) = control.force_error {
            return Err(error);
        }
        if let Some(release) = control.release {
            release.notified().await;
        }
    }
    write_named_groups_json_atomic(path, json).await
}

async fn write_named_groups_json_atomic(path: &FsPath, json: &str) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut temp_os = path.as_os_str().to_owned();
    temp_os.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let temp_path = PathBuf::from(temp_os);

    let write_result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .await?;
        file.write_all(json.as_bytes()).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temp_path, path).await
    }
    .await;

    if write_result.is_err() {
        let _ = tokio::fs::remove_file(&temp_path).await;
    }

    write_result
}

const PENDING_JOIN_RESULT_TTL: Duration = Duration::from_secs(10 * 60);

const JOIN_RESULT_POLL_TIMEOUT: Duration = Duration::from_secs(120);

const JOIN_RESULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

const PENDING_WELCOME_TTL: Duration = Duration::from_secs(10 * 60);

const WELCOME_FETCH_TIMEOUT: Duration = Duration::from_secs(90);

const WELCOME_FETCH_RETRY_DELAYS: [Duration; 4] = [
    Duration::ZERO,
    Duration::from_secs(5),
    Duration::from_secs(20),
    Duration::from_secs(60),
];

fn welcome_id_for_bytes(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

fn join_result_key(group_id: &str, member_agent_id: &str) -> String {
    format!("{group_id}:{member_agent_id}")
}

fn validate_join_result_inviter(
    expected_inviter: Option<&str>,
    sender_hex: &str,
    member_added_actor: &str,
) -> Result<(), &'static str> {
    let Some(expected_inviter) = expected_inviter else {
        return Err("missing_expected_inviter");
    };
    if sender_hex != expected_inviter {
        return Err("unexpected_sender");
    }
    if member_added_actor != expected_inviter {
        return Err("unexpected_actor");
    }
    Ok(())
}

fn record_expected_join_result_inviter(state: &AppState, key: String, inviter_agent_id: String) {
    let Ok(mut expected) = state.expected_join_result_inviters.lock() else {
        tracing::warn!(
            "expected join-result inviter map is poisoned; join-result response will be rejected"
        );
        return;
    };
    expected.retain(|_, pending| pending.created_at.elapsed() < JOIN_RESULT_POLL_TIMEOUT);
    expected.insert(
        key,
        ExpectedJoinResultInviter {
            inviter_agent_id,
            created_at: Instant::now(),
        },
    );
}

fn expected_join_result_inviter(state: &AppState, key: &str) -> Option<String> {
    let Ok(mut expected) = state.expected_join_result_inviters.lock() else {
        tracing::warn!(
            "expected join-result inviter map is poisoned; rejecting join-result response"
        );
        return None;
    };
    expected.retain(|_, pending| pending.created_at.elapsed() < JOIN_RESULT_POLL_TIMEOUT);
    expected
        .get(key)
        .map(|pending| pending.inviter_agent_id.clone())
}

fn clear_expected_join_result_inviter(state: &AppState, key: &str) {
    if let Ok(mut expected) = state.expected_join_result_inviters.lock() {
        expected.remove(key);
    }
}

async fn stage_join_result(
    state: &AppState,
    group_id: &str,
    member_agent_id: &str,
    event: NamedGroupMetadataEvent,
) {
    let key = join_result_key(group_id, member_agent_id);
    let event_kind = named_group_metadata_event_kind(&event);
    let (has_commit, has_commit_b64, has_inline_welcome, welcome_ref_id, treekem_epoch) =
        match &event {
            NamedGroupMetadataEvent::MemberAdded {
                commit,
                treekem_commit_b64,
                treekem_welcome_b64,
                welcome_ref,
                treekem_epoch,
                ..
            } => (
                commit.is_some(),
                treekem_commit_b64.is_some(),
                treekem_welcome_b64.is_some(),
                welcome_ref.as_ref().map(|w| w.welcome_id.clone()),
                *treekem_epoch,
            ),
            _ => (false, false, false, None, None),
        };
    let mut results = state.pending_join_results.write().await;
    results.retain(|_, pending| pending.created_at.elapsed() < PENDING_JOIN_RESULT_TTL);
    results.insert(
        key.clone(),
        PendingJoinResult {
            event,
            created_at: Instant::now(),
        },
    );
    tracing::debug!(
        target: "treekem.trace",
        stage = "stage_join_result",
        key = %key,
        group_id = %group_id,
        member = %member_agent_id,
        event = event_kind,
        has_commit,
        has_commit_b64,
        has_inline_welcome,
        welcome_ref = ?welcome_ref_id,
        treekem_epoch = ?treekem_epoch,
        pending_count = results.len(),
    );
}

pub(in crate::server) async fn handle_join_result_message(
    state: &Arc<AppState>,
    sender: &AgentId,
    msg: JoinResultMessage,
) {
    match msg {
        JoinResultMessage::FetchRequest {
            group_id,
            member_agent_id,
        } => {
            let sender_hex = hex::encode(sender.as_bytes());
            tracing::debug!(
                target: "treekem.trace",
                stage = "fetch_request_received",
                group_id = %group_id,
                member = %member_agent_id,
                sender = %sender_hex,
            );
            if sender_hex != member_agent_id {
                tracing::warn!(group_id = %LogHexId::group(&group_id), sender = %LogHexId::agent(&sender_hex), member = %LogHexId::agent(&member_agent_id), "ignoring unauthorized join-result fetch");
                return;
            }
            let key = join_result_key(&group_id, &member_agent_id);
            let (event, pending_count) = {
                let mut results = state.pending_join_results.write().await;
                results.retain(|_, pending| pending.created_at.elapsed() < PENDING_JOIN_RESULT_TTL);
                (
                    results.get(&key).map(|pending| pending.event.clone()),
                    results.len(),
                )
            };
            let Some(event) = event else {
                tracing::debug!(
                    target: "treekem.trace",
                    stage = "fetch_request_lookup_miss",
                    key = %key,
                    group_id = %group_id,
                    member = %member_agent_id,
                    pending_count,
                );
                tracing::debug!(group_id = %group_id, member = %member_agent_id, "join-result fetch before result was staged");
                return;
            };
            tracing::debug!(
                target: "treekem.trace",
                stage = "fetch_request_lookup_hit",
                key = %key,
                group_id = %group_id,
                member = %member_agent_id,
                event = named_group_metadata_event_kind(&event),
                pending_count,
            );
            let response = JoinResultMessage::Result {
                event: Box::new(event),
            };
            let payload = match serde_json::to_vec(&response) {
                Ok(payload) => payload,
                Err(e) => {
                    tracing::warn!(group_id = %LogHexId::group(&group_id), "failed to serialize join-result event: {e}");
                    return;
                }
            };
            let payload_len = payload.len();
            let payload_hash = hex::encode(blake3::hash(&payload).as_bytes());
            tracing::debug!(
                target: "treekem.trace",
                stage = "join_result_send_start",
                group_id = %group_id,
                member = %member_agent_id,
                payload_len,
                payload_hash = %payload_hash,
            );
            if let Err(e) = state
                .agent
                .send_direct_with_config(sender, payload, direct_message_send_config())
                .await
            {
                tracing::warn!(group_id = %LogHexId::group(&group_id), member = %LogHexId::agent(&member_agent_id), "failed to send join-result response: {e}");
                tracing::debug!(
                    target: "treekem.trace",
                    stage = "join_result_send_err",
                    group_id = %group_id,
                    member = %member_agent_id,
                    payload_len,
                    payload_hash = %payload_hash,
                    error = %e,
                );
            } else {
                tracing::debug!(
                    target: "treekem.trace",
                    stage = "join_result_send_ok",
                    group_id = %group_id,
                    member = %member_agent_id,
                    payload_len,
                    payload_hash = %payload_hash,
                );
            }
        }
        JoinResultMessage::Result { event } => {
            let event = *event;
            tracing::debug!(
                target: "treekem.trace",
                stage = "join_result_received",
                event = named_group_metadata_event_kind(&event),
                sender = %hex::encode(sender.as_bytes()),
            );
            let (group_id, member_agent_id, inviter_agent_id) = match &event {
                NamedGroupMetadataEvent::MemberAdded {
                    group_id,
                    agent_id,
                    actor,
                    ..
                } => (group_id.clone(), agent_id.clone(), actor.clone()),
                _ => {
                    tracing::warn!("ignoring non-MemberAdded join-result response");
                    return;
                }
            };
            let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
            if member_agent_id != local_agent_hex {
                tracing::warn!(group_id = %LogHexId::group(&group_id), member = %LogHexId::agent(&member_agent_id), local = %LogHexId::agent(&local_agent_hex), "ignoring join-result for different member");
                return;
            }
            let sender_hex = hex::encode(sender.as_bytes());
            let group_exists = {
                let groups = state.named_groups.read().await;
                groups.get(&group_id).is_some()
                    || groups
                        .values()
                        .any(|info| info.stable_group_id() == group_id)
            };
            if !group_exists {
                tracing::warn!(group_id = %LogHexId::group(&group_id), "ignoring join-result for unknown local group");
                return;
            }
            let expected_key = join_result_key(&group_id, &member_agent_id);
            let expected_inviter = expected_join_result_inviter(state.as_ref(), &expected_key);
            if let Err(reason) = validate_join_result_inviter(
                expected_inviter.as_deref(),
                &sender_hex,
                &inviter_agent_id,
            ) {
                tracing::warn!(
                    group_id = %LogHexId::group(&group_id),
                    sender = %LogHexId::agent(&sender_hex),
                    actor = %LogHexId::agent(&inviter_agent_id),
                    expected_inviter = ?expected_inviter.as_deref().map(LogHexId::agent),
                    reason,
                    "ignoring join-result from unexpected inviter"
                );
                return;
            }
            if apply_named_group_metadata_event(state, event, *sender, true).await {
                clear_expected_join_result_inviter(state.as_ref(), &expected_key);
            }
        }
    }
}

async fn poll_join_result_until_treekem_ready(
    state: Arc<AppState>,
    group_id: String,
    event_group_id: String,
    inviter: AgentId,
    member_agent_id: String,
) {
    let deadline = tokio::time::Instant::now() + JOIN_RESULT_POLL_TIMEOUT;
    let expected_key = join_result_key(&event_group_id, &member_agent_id);
    let mut timed_out = true;
    while tokio::time::Instant::now() < deadline {
        if state.treekem_groups.read().await.contains_key(&group_id) {
            timed_out = false;
            break;
        }
        let request = JoinResultMessage::FetchRequest {
            group_id: event_group_id.clone(),
            member_agent_id: member_agent_id.clone(),
        };
        let payload = match serde_json::to_vec(&request) {
            Ok(payload) => payload,
            Err(e) => {
                tracing::warn!(group_id = %LogHexId::group(&group_id), "failed to serialize join-result fetch request: {e}");
                return;
            }
        };
        let payload_len = payload.len();
        let payload_hash = hex::encode(blake3::hash(&payload).as_bytes());
        tracing::debug!(
            target: "treekem.trace",
            stage = "fetch_request_send_start",
            group_id = %group_id,
            event_group_id = %event_group_id,
            member = %member_agent_id,
            payload_len,
            payload_hash = %payload_hash,
        );
        if let Err(e) = state
            .agent
            .send_direct_with_config(&inviter, payload, direct_message_send_config())
            .await
        {
            tracing::debug!(group_id = %group_id, member = %member_agent_id, "join-result fetch attempt failed: {e}");
            tracing::debug!(
                target: "treekem.trace",
                stage = "fetch_request_send_err",
                group_id = %group_id,
                event_group_id = %event_group_id,
                member = %member_agent_id,
                payload_len,
                payload_hash = %payload_hash,
                error = %e,
            );
        } else {
            tracing::debug!(
                target: "treekem.trace",
                stage = "fetch_request_send_ok",
                group_id = %group_id,
                event_group_id = %event_group_id,
                member = %member_agent_id,
                payload_len,
                payload_hash = %payload_hash,
            );
        }
        tokio::time::sleep(JOIN_RESULT_POLL_INTERVAL).await;
    }
    clear_expected_join_result_inviter(state.as_ref(), &expected_key);
    if timed_out {
        tracing::warn!(group_id = %LogHexId::group(&group_id), member = %LogHexId::agent(&member_agent_id), "timed out polling anchor for TreeKEM join result");
    }
}

async fn stage_treekem_welcome(
    state: &AppState,
    group_id: &str,
    joiner_agent: &str,
    bytes: Vec<u8>,
) -> WelcomeRef {
    let welcome_id = welcome_id_for_bytes(&bytes);
    let byte_len = bytes.len() as u64;
    let source = hex::encode(state.agent.agent_id().as_bytes());
    let pending = PendingWelcome {
        group_id: group_id.to_string(),
        joiner_agent: joiner_agent.to_string(),
        bytes,
        created_at: Instant::now(),
    };
    let mut welcomes = state.pending_welcomes.write().await;
    welcomes.retain(|_, pending| pending.created_at.elapsed() < PENDING_WELCOME_TTL);
    welcomes.insert(welcome_id.clone(), pending);
    WelcomeRef {
        welcome_id,
        byte_len,
        source,
    }
}

fn welcome_blob_send_config(msg: &WelcomeBlobMessage) -> x0x::dm::DmSendConfig {
    match msg {
        WelcomeBlobMessage::Chunk { .. } => file_transfer_send_config(),
        WelcomeBlobMessage::FetchRequest { .. }
        | WelcomeBlobMessage::Offer { .. }
        | WelcomeBlobMessage::ChunkAck { .. }
        | WelcomeBlobMessage::Complete { .. } => direct_message_send_config(),
    }
}

async fn send_welcome_blob_message(
    state: &Arc<AppState>,
    agent_id: &AgentId,
    msg: &WelcomeBlobMessage,
) -> std::result::Result<x0x::dm::DmReceipt, String> {
    let payload = serde_json::to_vec(msg).map_err(|e| format!("serialization failed: {e}"))?;
    if payload.len() > x0x::dm::MAX_PAYLOAD_BYTES {
        return Err(format!(
            "welcome blob message exceeds MAX_PAYLOAD_BYTES ({} > {})",
            payload.len(),
            x0x::dm::MAX_PAYLOAD_BYTES
        ));
    }
    state
        .agent
        .send_direct_with_config(agent_id, payload, welcome_blob_send_config(msg))
        .await
        .map_err(|e| e.to_string())
}

async fn notify_welcome_waiters(
    state: &Arc<AppState>,
    welcome_id: &str,
    result: std::result::Result<Vec<u8>, String>,
) {
    let waiters = state
        .pending_welcome_waiters
        .write()
        .await
        .remove(welcome_id);
    if let Some(waiters) = waiters {
        for waiter in waiters {
            let _ = waiter.send(result.clone());
        }
    }
}

async fn cleanup_welcome_fetch_state(state: &Arc<AppState>, welcome_id: &str) {
    state
        .pending_welcome_receives
        .write()
        .await
        .remove(welcome_id);
    state
        .pending_welcome_waiters
        .write()
        .await
        .remove(welcome_id);
}

async fn fetch_treekem_welcome_with_retries(
    state: &Arc<AppState>,
    group_id: &str,
    welcome_ref: &WelcomeRef,
) -> std::result::Result<Vec<u8>, String> {
    let mut last_error = None;
    for (attempt, delay) in WELCOME_FETCH_RETRY_DELAYS.iter().enumerate() {
        if !delay.is_zero() {
            tokio::time::sleep(*delay).await;
        }
        match fetch_treekem_welcome(state, group_id, welcome_ref).await {
            Ok(bytes) => return Ok(bytes),
            Err(e) => {
                tracing::warn!(
                    target: "welcome.trace",
                    stage = "fetch_retry_failed",
                    group_id,
                    welcome_id = %welcome_ref.welcome_id,
                    attempt,
                    next_delay_ms = ?WELCOME_FETCH_RETRY_DELAYS
                        .get(attempt + 1)
                        .map(|d| d.as_millis() as u64),
                    error = %e,
                );
                last_error = Some(e);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| "TreeKEM Welcome fetch did not run".to_string()))
}

async fn fetch_treekem_welcome(
    state: &Arc<AppState>,
    group_id: &str,
    welcome_ref: &WelcomeRef,
) -> std::result::Result<Vec<u8>, String> {
    if welcome_ref.byte_len > x0x::files::MAX_TRANSFER_SIZE {
        return Err("TreeKEM Welcome blob exceeds maximum transfer size".to_string());
    }
    let source = parse_agent_id_hex(&welcome_ref.source)?;
    let total_chunks =
        x0x::files::total_chunks_for_size(welcome_ref.byte_len, x0x::files::DEFAULT_CHUNK_SIZE);
    let (tx, rx) = oneshot::channel();
    let should_send_fetch = {
        let mut receives = state.pending_welcome_receives.write().await;
        let should_send_fetch = match receives.get(&welcome_ref.welcome_id) {
            Some(existing)
                if existing.group_id == group_id
                    && existing.source == welcome_ref.source
                    && existing.byte_len == welcome_ref.byte_len
                    && existing.total_chunks == total_chunks =>
            {
                tracing::debug!(
                    target: "welcome.trace",
                    stage = "fetch_join_inflight",
                    group_id,
                    welcome_id = %welcome_ref.welcome_id,
                );
                false
            }
            Some(_) => {
                return Err("conflicting in-flight TreeKEM Welcome fetch".to_string());
            }
            None => {
                receives.insert(
                    welcome_ref.welcome_id.clone(),
                    PendingWelcomeReceive {
                        group_id: group_id.to_string(),
                        source: welcome_ref.source.clone(),
                        byte_len: welcome_ref.byte_len,
                        total_chunks,
                        chunks: BTreeMap::new(),
                        received_bytes: 0,
                    },
                );
                true
            }
        };
        state
            .pending_welcome_waiters
            .write()
            .await
            .entry(welcome_ref.welcome_id.clone())
            .or_default()
            .push(tx);
        should_send_fetch
    };

    if should_send_fetch {
        let request = WelcomeBlobMessage::FetchRequest {
            group_id: group_id.to_string(),
            welcome_id: welcome_ref.welcome_id.clone(),
        };
        if let Err(e) = send_welcome_blob_message(state, &source, &request).await {
            cleanup_welcome_fetch_state(state, &welcome_ref.welcome_id).await;
            return Err(e);
        }
    }

    let received = match tokio::time::timeout(WELCOME_FETCH_TIMEOUT, rx).await {
        Ok(Ok(result)) => result?,
        Ok(Err(_)) => return Err("TreeKEM Welcome waiter dropped".to_string()),
        Err(_) => {
            cleanup_welcome_fetch_state(state, &welcome_ref.welcome_id).await;
            return Err("timed out waiting for TreeKEM Welcome blob".to_string());
        }
    };
    if received.len() as u64 != welcome_ref.byte_len {
        return Err(format!(
            "TreeKEM Welcome length mismatch: got {}, expected {}",
            received.len(),
            welcome_ref.byte_len
        ));
    }
    let actual = welcome_id_for_bytes(&received);
    if actual != welcome_ref.welcome_id {
        return Err("TreeKEM Welcome blake3 mismatch".to_string());
    }
    Ok(received)
}

pub(in crate::server) async fn handle_welcome_blob_message(
    state: &Arc<AppState>,
    sender: &AgentId,
    msg: WelcomeBlobMessage,
) {
    match msg {
        WelcomeBlobMessage::FetchRequest {
            group_id,
            welcome_id,
        } => handle_welcome_fetch_request(state, sender, group_id, welcome_id).await,
        WelcomeBlobMessage::Offer {
            group_id,
            welcome_id,
            byte_len,
            chunk_size,
            total_chunks,
            blake3_hex,
        } => {
            let source = hex::encode(sender.as_bytes());
            let mismatch = {
                let receives = state.pending_welcome_receives.read().await;
                let Some(receive) = receives.get(&welcome_id) else {
                    tracing::debug!(welcome_id, "ignoring unsolicited Welcome blob offer");
                    return;
                };
                if receive.source != source {
                    tracing::debug!(welcome_id, sender = %source, "ignoring Welcome blob offer from unexpected source");
                    return;
                }
                receive.group_id != group_id
                    || receive.byte_len != byte_len
                    || receive.total_chunks != total_chunks
                    || chunk_size != x0x::files::DEFAULT_CHUNK_SIZE
                    || blake3_hex != welcome_id
            };
            if mismatch {
                state
                    .pending_welcome_receives
                    .write()
                    .await
                    .remove(&welcome_id);
                notify_welcome_waiters(
                    state,
                    &welcome_id,
                    Err("welcome offer did not match requested reference".to_string()),
                )
                .await;
            }
        }
        WelcomeBlobMessage::Chunk {
            welcome_id,
            sequence,
            data,
        } => handle_welcome_blob_chunk(state, sender, welcome_id, sequence, data).await,
        WelcomeBlobMessage::ChunkAck {
            welcome_id,
            sequence,
        } => {
            let matched_pending =
                if let Some(slot) = state.pending_welcome_acks.read().await.get(&welcome_id) {
                    slot.record_ack(sequence);
                    true
                } else {
                    false
                };
            tracing::debug!(target: "welcome.trace", stage = "chunk_ack_recv", welcome_id = %welcome_id, seq = sequence, matched_pending);
        }
        WelcomeBlobMessage::Complete { welcome_id } => {
            handle_welcome_blob_complete(state, sender, &welcome_id).await;
        }
    }
}

async fn handle_welcome_fetch_request(
    state: &Arc<AppState>,
    sender: &AgentId,
    group_id: String,
    welcome_id: String,
) {
    let sender_hex = hex::encode(sender.as_bytes());
    let pending = {
        let welcomes = state.pending_welcomes.read().await;
        welcomes.get(&welcome_id).cloned()
    };
    let Some(pending) = pending else {
        tracing::warn!(welcome_id, "Welcome fetch for unknown blob");
        return;
    };
    if pending.created_at.elapsed() >= PENDING_WELCOME_TTL {
        state.pending_welcomes.write().await.remove(&welcome_id);
        return;
    }
    if pending.group_id != group_id || pending.joiner_agent != sender_hex {
        tracing::warn!(welcome_id = %LogHexId::new("welcome", &welcome_id), sender = %LogHexId::agent(&sender_hex), "unauthorized Welcome fetch request");
        return;
    }
    let state = Arc::clone(state);
    let recipient = *sender;
    tokio::spawn(async move {
        stream_welcome_blob(&state, &recipient, &welcome_id, pending).await;
    });
}

async fn stream_welcome_blob(
    state: &Arc<AppState>,
    recipient: &AgentId,
    welcome_id: &str,
    pending: PendingWelcome,
) {
    let chunk_size = x0x::files::DEFAULT_CHUNK_SIZE;
    let total_chunks = x0x::files::total_chunks_for_size(pending.bytes.len() as u64, chunk_size);
    let ack_slot = Arc::new(FileChunkAckSlot::new());
    {
        let mut acks = state.pending_welcome_acks.write().await;
        if acks.contains_key(welcome_id) {
            tracing::debug!(
                target: "welcome.trace",
                stage = "stream_duplicate_ignored",
                welcome_id,
                recipient = %hex::encode(recipient.as_bytes()),
            );
            return;
        }
        acks.insert(welcome_id.to_string(), Arc::clone(&ack_slot));
    }

    let offer = WelcomeBlobMessage::Offer {
        group_id: pending.group_id.clone(),
        welcome_id: welcome_id.to_string(),
        byte_len: pending.bytes.len() as u64,
        chunk_size,
        total_chunks,
        blake3_hex: welcome_id.to_string(),
    };
    if let Err(e) = send_welcome_blob_message(state, recipient, &offer).await {
        tracing::warn!(welcome_id, "failed to send Welcome blob offer: {e}");
        state.pending_welcome_acks.write().await.remove(welcome_id);
        return;
    }
    tracing::debug!(
        target: "welcome.trace",
        stage = "offer_sent",
        welcome_id,
        recipient = %hex::encode(recipient.as_bytes()),
        total_chunks,
        byte_len = pending.bytes.len() as u64,
    );

    for (sequence, chunk) in pending.bytes.chunks(chunk_size).enumerate() {
        let sequence = sequence as u64;
        if let Err(e) = wait_for_chunk_window(&ack_slot, sequence).await {
            tracing::warn!(welcome_id, "Welcome blob chunk window failed: {e}");
            state.pending_welcome_acks.write().await.remove(welcome_id);
            return;
        }
        let msg = WelcomeBlobMessage::Chunk {
            welcome_id: welcome_id.to_string(),
            sequence,
            data: BASE64.encode(chunk),
        };
        if let Err(e) = send_welcome_blob_message(state, recipient, &msg).await {
            tracing::warn!(
                welcome_id,
                sequence,
                "failed to send Welcome blob chunk: {e}"
            );
            state.pending_welcome_acks.write().await.remove(welcome_id);
            return;
        }
        tracing::debug!(target: "welcome.trace", stage = "chunk_sent", welcome_id, seq = sequence);
    }

    if total_chunks > 0 {
        let last_seq = total_chunks - 1;
        if let Err(e) = wait_for_final_acks(&ack_slot, last_seq).await {
            tracing::warn!(welcome_id, "Welcome blob final ack wait failed: {e}");
            tracing::debug!(target: "welcome.trace", stage = "final_ack_failed", welcome_id, total_chunks, last_acked = ack_slot.highest_acked(), "{e}");
            state.pending_welcome_acks.write().await.remove(welcome_id);
            return;
        }
        tracing::debug!(target: "welcome.trace", stage = "final_ack_ok", welcome_id, total_chunks);
    }
    let complete = WelcomeBlobMessage::Complete {
        welcome_id: welcome_id.to_string(),
    };
    if let Err(e) = send_welcome_blob_message(state, recipient, &complete).await {
        tracing::warn!(welcome_id, "failed to send Welcome blob complete: {e}");
    }
    state.pending_welcome_acks.write().await.remove(welcome_id);
}

async fn handle_welcome_blob_chunk(
    state: &Arc<AppState>,
    sender: &AgentId,
    welcome_id: String,
    sequence: u64,
    data: String,
) {
    let sender_hex = hex::encode(sender.as_bytes());
    let decoded = match BASE64.decode(data) {
        Ok(bytes) => bytes,
        Err(e) => {
            notify_welcome_waiters(
                state,
                &welcome_id,
                Err(format!("Welcome chunk decode failed: {e}")),
            )
            .await;
            return;
        }
    };
    let mut receives = state.pending_welcome_receives.write().await;
    let Some(receive) = receives.get_mut(&welcome_id) else {
        tracing::debug!(target: "welcome.trace", stage = "chunk_recv_no_pending", welcome_id = %welcome_id, seq = sequence);
        return;
    };
    if receive.source != sender_hex {
        tracing::debug!(target: "welcome.trace", stage = "chunk_recv_wrong_source", welcome_id = %welcome_id, seq = sequence);
        return;
    }
    if sequence >= receive.total_chunks {
        return;
    }
    if !receive.chunks.contains_key(&sequence) {
        receive.received_bytes = receive.received_bytes.saturating_add(decoded.len() as u64);
        receive.chunks.insert(sequence, decoded);
    }
    drop(receives);
    tracing::debug!(target: "welcome.trace", stage = "chunk_recv", welcome_id = %welcome_id, seq = sequence);

    let ack = WelcomeBlobMessage::ChunkAck {
        welcome_id: welcome_id.clone(),
        sequence,
    };
    match send_welcome_blob_message(state, sender, &ack).await {
        Ok(_) => {
            tracing::debug!(target: "welcome.trace", stage = "chunk_ack_sent", welcome_id = %welcome_id, seq = sequence);
        }
        Err(e) => {
            tracing::warn!(welcome_id = %LogHexId::new("welcome", &welcome_id), sequence, "failed to ack Welcome blob chunk: {e}");
        }
    }
}

async fn handle_welcome_blob_complete(state: &Arc<AppState>, sender: &AgentId, welcome_id: &str) {
    let sender_hex = hex::encode(sender.as_bytes());
    {
        let receives = state.pending_welcome_receives.read().await;
        let Some(receive) = receives.get(welcome_id) else {
            return;
        };
        if receive.source != sender_hex {
            return;
        }
    }
    let receive = state
        .pending_welcome_receives
        .write()
        .await
        .remove(welcome_id);
    let Some(receive) = receive else {
        return;
    };
    if receive.received_bytes != receive.byte_len
        || receive.chunks.len() as u64 != receive.total_chunks
    {
        notify_welcome_waiters(
            state,
            welcome_id,
            Err("incomplete Welcome blob transfer".to_string()),
        )
        .await;
        return;
    }
    let mut bytes = Vec::with_capacity(receive.byte_len as usize);
    for sequence in 0..receive.total_chunks {
        let Some(chunk) = receive.chunks.get(&sequence) else {
            notify_welcome_waiters(
                state,
                welcome_id,
                Err("missing Welcome blob chunk".to_string()),
            )
            .await;
            return;
        };
        bytes.extend_from_slice(chunk);
    }
    if receive.group_id.is_empty() {
        notify_welcome_waiters(
            state,
            welcome_id,
            Err("Welcome blob missing group id".to_string()),
        )
        .await;
        return;
    }
    let actual = welcome_id_for_bytes(&bytes);
    if actual != welcome_id {
        notify_welcome_waiters(
            state,
            welcome_id,
            Err("Welcome blob blake3 mismatch".to_string()),
        )
        .await;
        return;
    }
    notify_welcome_waiters(state, welcome_id, Ok(bytes)).await;
}

// ---------------------------------------------------------------------------
// File transfer message handling
// ---------------------------------------------------------------------------

pub(in crate::server) type WelcomeFetchWaiter =
    oneshot::Sender<std::result::Result<Vec<u8>, String>>;

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::super::sse::SseEvent;
    use super::super::super::state::DaemonUpdateConfig;
    use super::super::super::ws::WsOutboundStats;
    use super::super::super::{auth, crdt_subscriptions};
    use super::super::contacts::{update_contact, UpdateContactRequest};
    use super::super::direct::{direct_send, DirectSendRequest};
    use super::super::groups::{mls_decrypt, mls_encrypt, MlsDecryptRequest, MlsEncryptRequest};
    use super::super::identity::{get_agent_card, import_agent_card, CardQuery, ImportCardRequest};
    use axum::response::Response;
    use tokio::sync::{broadcast, mpsc, watch};

    mod cache_hardening_followup;

    fn fake_group_state_commit(
        group_id: &str,
        revision: u64,
        committed_by: &str,
    ) -> x0x::groups::GroupStateCommit {
        x0x::groups::GroupStateCommit {
            group_id: group_id.to_string(),
            revision,
            prev_state_hash: Some(format!("state-{}", revision.saturating_sub(1))),
            roster_root: "roster".to_string(),
            policy_hash: "policy".to_string(),
            public_meta_hash: "meta".to_string(),
            security_binding: Some("treekem:epoch=1".to_string()),
            state_hash: format!("state-{revision}"),
            withdrawn: false,
            committed_by: committed_by.to_string(),
            committed_at: revision,
            signer_public_key: "pub".to_string(),
            signature: "sig".to_string(),
        }
    }

    fn sample_group_card(group_id: &str, revision: u64, issued_at: u64) -> x0x::groups::GroupCard {
        x0x::groups::GroupCard {
            group_id: group_id.to_string(),
            name: format!("Group {group_id}"),
            description: String::new(),
            avatar_url: None,
            banner_url: None,
            tags: Vec::new(),
            policy_summary: x0x::groups::GroupPolicySummary {
                discoverability: x0x::groups::GroupDiscoverability::PublicDirectory,
                admission: x0x::groups::GroupAdmission::RequestAccess,
                confidentiality: x0x::groups::GroupConfidentiality::MlsEncrypted,
                read_access: x0x::groups::GroupReadAccess::MembersOnly,
                write_access: x0x::groups::GroupWriteAccess::MembersOnly,
            },
            owner_agent_id: "ff".repeat(32),
            admin_count: 1,
            member_count: 1,
            created_at: issued_at,
            updated_at: issued_at,
            request_access_enabled: true,
            metadata_topic: None,
            revision,
            state_hash: format!("state-{revision}"),
            prev_state_hash: None,
            issued_at,
            expires_at: issued_at + 1_000,
            authority_agent_id: String::new(),
            authority_public_key: String::new(),
            withdrawn: false,
            signature: String::new(),
        }
    }

    fn sole_owner_group() -> (x0x::groups::GroupInfo, String) {
        let kp = x0x::identity::AgentKeypair::generate().expect("keypair");
        let owner_hex = hex::encode(kp.agent_id().as_bytes());
        let info = x0x::groups::GroupInfo::with_policy(
            "G".to_string(),
            "d".to_string(),
            kp.agent_id(),
            "aa".repeat(16),
            x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
        );
        (info, owner_hex)
    }

    /// Why: §3 fixes this error contract verbatim — handlers must return
    /// 409 with exactly this string when an act would strip the last admin.
    #[test]
    fn last_admin_precheck_returns_409_with_exact_spec_string() {
        let (info, owner_hex) = sole_owner_group();
        let (status, body) = last_admin_precheck(&info, |g| {
            g.set_member_role(&owner_hex, x0x::groups::GroupRole::Member)
        })
        .expect("demoting the sole admin must trip the pre-check");
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body.0["error"].as_str(),
            Some("a group must always have at least one admin; make another member an admin first")
        );
    }

    /// Why: the pre-check must evaluate the proposed post-mutation roster —
    /// acts that keep at least one active admin (including a legacy Owner
    /// normalising to Admin) must pass untouched.
    #[test]
    fn last_admin_precheck_passes_when_admins_remain() {
        let (mut info, owner_hex) = sole_owner_group();
        // Owner self-normalising to admin keeps the admin count at 1.
        assert!(last_admin_precheck(&info, |g| {
            g.set_member_role(&owner_hex, x0x::groups::GroupRole::Admin)
        })
        .is_none());
        // Removing or banning a plain member never trips the invariant.
        info.add_member(
            "bb".repeat(32),
            x0x::groups::GroupRole::Member,
            Some(owner_hex.clone()),
            None,
        );
        assert!(last_admin_precheck(&info, |g| g.remove_member(&"bb".repeat(32), None)).is_none());
        assert!(last_admin_precheck(&info, |g| g.ban_member(&"bb".repeat(32), None)).is_none());
    }

    /// Why: withdrawn state is the invariant's exemption (the exit valve) —
    /// the pre-check must never block acts on an already-ended group.
    #[test]
    fn last_admin_precheck_exempts_withdrawn_groups() {
        let (mut info, owner_hex) = sole_owner_group();
        info.withdrawn = true;
        assert!(last_admin_precheck(&info, |g| {
            g.set_member_role(&owner_hex, x0x::groups::GroupRole::Member)
        })
        .is_none());
    }

    #[test]
    fn group_card_cache_prunes_expired_cards() {
        let mut cache = HashMap::new();
        cache.insert(
            "expired".to_string(),
            sample_group_card("expired", 1, 1_000),
        );
        cache.insert("fresh".to_string(), sample_group_card("fresh", 1, 3_000));

        prune_expired_group_cards(&mut cache, 2_001);

        assert!(!cache.contains_key("expired"));
        assert!(cache.contains_key("fresh"));
    }

    #[test]
    fn group_card_cache_cap_evicts_earliest_expiry() {
        let mut cache = HashMap::new();
        cache.insert("earliest".to_string(), sample_group_card("earliest", 1, 1));
        for idx in 0..GROUP_CARD_CACHE_CAP {
            let group_id = format!("group-{idx}");
            cache.insert(
                group_id.clone(),
                sample_group_card(&group_id, 1, 10_000 + idx as u64),
            );
        }

        enforce_group_card_cache_cap(&mut cache);

        assert_eq!(cache.len(), GROUP_CARD_CACHE_CAP);
        assert!(!cache.contains_key("earliest"));
    }

    #[test]
    fn group_card_cache_insert_preserves_higher_revision() {
        let mut cache = HashMap::new();
        let high = sample_group_card("same", 3, 1_000);
        let low = sample_group_card("same", 2, 2_000);

        assert!(cache_group_card_if_newer(
            &mut cache,
            "same".to_string(),
            high.clone()
        ));
        assert!(!cache_group_card_if_newer(
            &mut cache,
            "same".to_string(),
            low
        ));

        assert_eq!(
            cache.get("same").expect("card retained").revision,
            high.revision
        );
    }

    #[test]
    fn group_card_cache_stale_withdrawal_does_not_evict_newer_card() {
        let mut cache = HashMap::new();
        let current = sample_group_card("same", 3, 2_000);
        let mut stale_withdrawal = sample_group_card("same", 2, 3_000);
        stale_withdrawal.withdrawn = true;

        cache.insert("same".to_string(), current.clone());

        assert!(!remove_group_card_if_not_stale(
            &mut cache,
            &stale_withdrawal
        ));
        assert_eq!(
            cache.get("same").expect("newer card retained").revision,
            current.revision
        );
    }

    #[test]
    fn withdrawn_group_card_marks_existing_stub_without_regressing_newer_stub() {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "old".to_string(),
            String::new(),
            AgentId([1; 32]),
            "same".to_string(),
            x0x::groups::GroupPolicy::from(&sample_group_card("same", 1, 1_000).policy_summary),
        );
        info.state_revision = 1;
        info.updated_at = 1_000;
        info.withdrawn = false;
        info.shared_secret = Some(vec![9; 32]);

        let mut withdrawal = sample_group_card("same", 2, 2_000);
        withdrawal.withdrawn = true;

        assert!(apply_withdrawn_group_card_to_group_info(
            &mut info,
            &withdrawal
        ));
        assert!(info.withdrawn);
        assert_eq!(info.state_revision, 2);
        assert_eq!(info.state_hash, "state-2");
        assert_eq!(info.shared_secret, None);

        let mut newer_info = info.clone();
        newer_info.withdrawn = false;
        newer_info.state_revision = 3;
        newer_info.updated_at = 3_000;

        assert!(!apply_withdrawn_group_card_to_group_info(
            &mut newer_info,
            &withdrawal
        ));
        assert!(!newer_info.withdrawn);
        assert_eq!(newer_info.state_revision, 3);
    }

    #[test]
    fn withdrawn_group_record_guard_matches_stable_id_for_stale_card_imports() {
        let mut groups = HashMap::new();
        let mut info = x0x::groups::GroupInfo::with_policy(
            "withdrawn".to_string(),
            String::new(),
            AgentId([2; 32]),
            "local-mls-id".to_string(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            "stable-card-id".to_string(),
            "02".repeat(32),
            info.created_at,
            String::new(),
        ));
        info.withdrawn = true;
        groups.insert("local-mls-id".to_string(), info);

        assert!(has_withdrawn_group_record(&groups, "local-mls-id"));
        assert!(has_withdrawn_group_record(&groups, "stable-card-id"));
        let aliases =
            collect_same_stable_group_aliases(&groups, "local-mls-id", Some("stable-card-id"));
        assert!(join_result_key_matches_any_group_alias(
            "stable-card-id:member",
            &aliases,
        ));
    }

    #[test]
    fn ban_store_guard_allows_active_ban_and_rejects_withdrawn_same_stable_record() {
        let group_id = "ban-local-mls-id";
        let withdrawn_alias = "ban-withdrawn-mls-id";
        let stable_group_id = "ban-stable-card-id";
        let admin_hex = "02".repeat(32);
        let target_hex = "03".repeat(32);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "ban guard".to_string(),
            String::new(),
            AgentId([2; 32]),
            group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            stable_group_id.to_string(),
            admin_hex.clone(),
            info.created_at,
            String::new(),
        ));
        info.add_member(
            target_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.roster_revision = info.roster_revision.saturating_add(1);
        info.recompute_state_hash();

        let mut allowed_groups = HashMap::from([(group_id.to_string(), info.clone())]);
        let mut banned_next = info.clone();
        banned_next.ban_member(&target_hex, Some(admin_hex.clone()));
        banned_next.roster_revision = banned_next.roster_revision.saturating_add(1);

        assert!(store_named_group_info_locked(
            &mut allowed_groups,
            group_id,
            banned_next
        ));
        assert!(allowed_groups[group_id].members_v2[&target_hex].is_banned());

        let mut withdrawn = info.clone();
        withdrawn.mls_group_id = withdrawn_alias.to_string();
        withdrawn.withdrawn = true;
        withdrawn.shared_secret = None;
        let before = info.clone();
        let mut guarded_groups = HashMap::from([
            (group_id.to_string(), info),
            (withdrawn_alias.to_string(), withdrawn),
        ]);
        let mut rejected_next = before.clone();
        rejected_next.ban_member(&target_hex, Some(admin_hex));
        rejected_next.roster_revision = rejected_next.roster_revision.saturating_add(1);

        assert!(!store_named_group_info_locked(
            &mut guarded_groups,
            group_id,
            rejected_next
        ));
        let stored = &guarded_groups[group_id];
        assert_eq!(stored.members_v2, before.members_v2);
        assert_eq!(stored.roster_revision, before.roster_revision);
        assert_eq!(stored.state_hash, before.state_hash);
        assert!(!stored.members_v2[&target_hex].is_banned());
    }

    fn secure_post_crypto_recheck_group(
        group_id: &str,
        stable_group_id: &str,
        secure_plane: x0x::mls::SecureGroupPlane,
        withdrawn: bool,
    ) -> x0x::groups::GroupInfo {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            AgentId([2; 32]),
            group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
        );
        info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            stable_group_id.to_string(),
            "02".repeat(32),
            info.created_at,
            String::new(),
        ));
        info.secure_plane = secure_plane;
        info.secret_epoch = 7;
        info.shared_secret = (!withdrawn).then(|| vec![9; 32]);
        info.withdrawn = withdrawn;
        info
    }

    fn assert_post_crypto_lost_race_drops_secure_effect(
        secure_plane: x0x::mls::SecureGroupPlane,
        effect: serde_json::Value,
        proof_field: &str,
    ) {
        let group_id = "local-mls-id";
        let stable_group_id = "stable-card-id";
        let mut groups = HashMap::from([(
            group_id.to_string(),
            secure_post_crypto_recheck_group(group_id, stable_group_id, secure_plane, false),
        )]);

        let (status, body) = secure_group_effect_response_after_terminality_recheck_from_groups(
            &groups,
            group_id,
            Some(stable_group_id),
            effect.clone(),
        );
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.0.get(proof_field).is_some(),
            "active group should return the computed secure effect field {proof_field}"
        );

        groups.insert(
            group_id.to_string(),
            secure_post_crypto_recheck_group(group_id, stable_group_id, secure_plane, true),
        );
        let (status, body) = secure_group_effect_response_after_terminality_recheck_from_groups(
            &groups,
            group_id,
            Some(stable_group_id),
            effect,
        );

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.0["ok"].as_bool(), Some(false));
        assert_eq!(body.0["error"].as_str(), Some("group is withdrawn"));
        for field in [
            "payload_b64",
            "ciphertext_b64",
            "nonce_b64",
            "secret_b64",
            "kem_ciphertext_b64",
            "aead_nonce_b64",
            "aead_ciphertext_b64",
        ] {
            assert!(
                body.0.get(field).is_none(),
                "withdrawn conflict must not leak secure effect field {field}"
            );
        }
    }

    #[test]
    fn treekem_decrypt_lost_race_drops_plaintext() {
        assert_post_crypto_lost_race_drops_secure_effect(
            x0x::mls::SecureGroupPlane::TreeKem,
            serde_json::json!({
                "ok": true,
                "payload_b64": "c2VjcmV0",
                "secret_epoch": 7,
                "secure_plane": "treekem",
            }),
            "payload_b64",
        );
    }

    #[test]
    fn gss_decrypt_lost_race_drops_plaintext() {
        assert_post_crypto_lost_race_drops_secure_effect(
            x0x::mls::SecureGroupPlane::Gss,
            serde_json::json!({
                "ok": true,
                "payload_b64": "c2VjcmV0",
                "secret_epoch": 7,
            }),
            "payload_b64",
        );
    }

    #[test]
    fn treekem_encrypt_lost_race_drops_ciphertext() {
        assert_post_crypto_lost_race_drops_secure_effect(
            x0x::mls::SecureGroupPlane::TreeKem,
            serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y2lwaGVydGV4dA==",
                "secret_epoch": 7,
                "secure_plane": "treekem",
            }),
            "ciphertext_b64",
        );
    }

    #[test]
    fn gss_encrypt_lost_race_drops_ciphertext() {
        assert_post_crypto_lost_race_drops_secure_effect(
            x0x::mls::SecureGroupPlane::Gss,
            serde_json::json!({
                "ok": true,
                "ciphertext_b64": "Y2lwaGVydGV4dA==",
                "nonce_b64": "bm9uY2U=",
                "secret_epoch": 7,
            }),
            "ciphertext_b64",
        );
    }

    #[test]
    fn gss_reseal_lost_race_drops_secret_envelope() {
        assert_post_crypto_lost_race_drops_secure_effect(
            x0x::mls::SecureGroupPlane::Gss,
            serde_json::json!({
                "ok": true,
                "group_id": "stable-card-id",
                "recipient": "aa",
                "secret_epoch": 7,
                "kem_ciphertext_b64": "a2Vt",
                "aead_nonce_b64": "bm9uY2U=",
                "aead_ciphertext_b64": "YWVhZA==",
            }),
            "kem_ciphertext_b64",
        );
    }

    #[test]
    fn open_envelope_lost_race_drops_opened_secret() {
        assert_post_crypto_lost_race_drops_secure_effect(
            x0x::mls::SecureGroupPlane::Gss,
            serde_json::json!({
                "ok": true,
                "opened": true,
                "secret_b64": "c2VjcmV0",
            }),
            "secret_b64",
        );
    }

    struct PostCryptoForcedWithdrawal {
        ids: Vec<String>,
    }

    struct AtomicPersistPostJsonForcedWithdrawal {
        ids: Vec<String>,
    }

    impl Drop for PostCryptoForcedWithdrawal {
        fn drop(&mut self) {
            let mut forced = POST_CRYPTO_FORCED_WITHDRAWN_GROUPS
                .lock()
                .expect("post-crypto forced-withdrawn test hook poisoned");
            for id in &self.ids {
                forced.remove(id);
            }
        }
    }

    impl Drop for AtomicPersistPostJsonForcedWithdrawal {
        fn drop(&mut self) {
            let mut forced = ATOMIC_PERSIST_POST_JSON_FORCED_WITHDRAWN_GROUPS
                .lock()
                .expect("atomic-persist forced-withdrawn test hook poisoned");
            for id in &self.ids {
                forced.remove(id);
            }
        }
    }

    fn force_post_crypto_withdrawn_ids(ids: &[&str]) -> PostCryptoForcedWithdrawal {
        let ids = ids.iter().map(|id| (*id).to_string()).collect::<Vec<_>>();
        let mut forced = POST_CRYPTO_FORCED_WITHDRAWN_GROUPS
            .lock()
            .expect("post-crypto forced-withdrawn test hook poisoned");
        for id in &ids {
            forced.insert(id.clone());
        }
        PostCryptoForcedWithdrawal { ids }
    }

    fn force_atomic_persist_post_json_withdrawn_ids(
        ids: &[&str],
    ) -> AtomicPersistPostJsonForcedWithdrawal {
        let ids = ids.iter().map(|id| (*id).to_string()).collect::<Vec<_>>();
        let mut forced = ATOMIC_PERSIST_POST_JSON_FORCED_WITHDRAWN_GROUPS
            .lock()
            .expect("atomic-persist forced-withdrawn test hook poisoned");
        for id in &ids {
            forced.insert(id.clone());
        }
        AtomicPersistPostJsonForcedWithdrawal { ids }
    }

    struct TreeKemFinalInstallBeforeMapWriteGuard {
        group_id: String,
    }

    impl Drop for TreeKemFinalInstallBeforeMapWriteGuard {
        fn drop(&mut self) {
            let Ok(mut guard) = TREEKEM_FINAL_INSTALL_BEFORE_MAP_WRITE_NOTIFY.lock() else {
                return;
            };
            if guard
                .as_ref()
                .is_some_and(|(group_id, _)| group_id == &self.group_id)
            {
                *guard = None;
            }
        }
    }

    fn notify_before_treekem_final_install_map_write(
        group_id: &str,
    ) -> (
        Arc<tokio::sync::Notify>,
        TreeKemFinalInstallBeforeMapWriteGuard,
    ) {
        let notify = Arc::new(tokio::sync::Notify::new());
        let mut guard = TREEKEM_FINAL_INSTALL_BEFORE_MAP_WRITE_NOTIFY
            .lock()
            .expect("TreeKEM final install notify hook poisoned");
        *guard = Some((group_id.to_string(), Arc::clone(&notify)));
        (
            notify,
            TreeKemFinalInstallBeforeMapWriteGuard {
                group_id: group_id.to_string(),
            },
        )
    }

    async fn secure_endpoint_test_state() -> Result<(Arc<AppState>, tempfile::TempDir)> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path();
        let agent = Arc::new(
            Agent::builder()
                .with_machine_key(data_dir.join("machine.key"))
                .with_agent_key(x0x::identity::AgentKeypair::generate()?)
                .with_agent_cert_path(data_dir.join("agent.cert"))
                .with_peer_cache_disabled()
                .with_contact_store_path(data_dir.join("contacts.json"))
                .build()
                .await?,
        );
        let state = secure_endpoint_test_state_at(data_dir, agent).await?;
        Ok((state, dir))
    }

    async fn secure_endpoint_test_state_at(
        data_dir: &FsPath,
        agent: Arc<Agent>,
    ) -> Result<Arc<AppState>> {
        let treekem_dir = data_dir.join("treekem");
        tokio::fs::create_dir_all(&treekem_dir).await?;
        let named_groups_path = data_dir.join("named_groups.json");
        let named_groups = load_named_groups(&named_groups_path).await?;
        let treekem_member_key_packages = load_treekem_member_key_packages(
            &treekem_dir.join("member-key-packages.json"),
            &named_groups,
        )
        .await?;
        let contacts = Arc::clone(agent.contacts());
        agent.set_contacts(Arc::clone(&contacts));

        let (broadcast_tx, _) = broadcast::channel::<SseEvent>(16);
        let (shutdown_tx, _) = mpsc::channel::<()>(1);
        let (shutdown_notify, _) = watch::channel(false);
        let (_exec_dm_tx, exec_dm_rx) = mpsc::channel::<x0x::dm_inbox::DmTypedPayload>(1);
        let exec_policy = x0x::exec::ExecPolicy::Disabled {
            path: data_dir.join("exec-acl.toml"),
            reason: "test".to_string(),
            loaded_at_unix_ms: 0,
        };
        let exec_service =
            x0x::exec::ExecService::spawn(Arc::clone(&agent), exec_policy, exec_dm_rx);

        Ok(Arc::new(AppState {
            agent,
            history_record_topics: Vec::new(),
            history_config: x0x::history::HistoryConfig::default(),
            subscriptions: RwLock::new(HashMap::new()),
            task_lists: RwLock::new(HashMap::new()),
            kv_stores: RwLock::new(HashMap::new()),
            crdt_subscriptions: RwLock::new(crdt_subscriptions::CrdtSubscriptionManifest::default()),
            crdt_subscriptions_path: data_dir.join("crdt-subscriptions.json"),
            kv_store_state_dir: data_dir.join("kv-stores"),
            crdt_subscriptions_persistence_lock: Mutex::new(()),
            crdt_handle_locks: RwLock::new(HashMap::new()),
            named_groups: RwLock::new(named_groups),
            named_groups_path,
            named_groups_persistence_lock: Mutex::new(()),
            group_metadata_tasks: RwLock::new(HashMap::new()),
            group_card_cache: RwLock::new(HashMap::new()),
            directory_cache: RwLock::new(x0x::groups::DirectoryShardCache::default()),
            directory_subscriptions: RwLock::new(x0x::groups::SubscriptionSet::default()),
            directory_subscriptions_path: data_dir.join("directory-subscriptions.json"),
            directory_tasks: RwLock::new(HashMap::new()),
            directory_digest_interval_secs: DIRECTORY_DIGEST_INTERVAL_SECS,
            directory_resubscribe_jitter_ms: DIRECTORY_RESUBSCRIBE_JITTER_MS,
            public_messages: RwLock::new(HashMap::new()),
            public_message_tasks: RwLock::new(HashMap::new()),
            agent_kem_keypair: Arc::new(x0x::groups::kem_envelope::AgentKemKeypair::generate()?),
            contacts,
            mls_groups: RwLock::new(HashMap::new()),
            mls_groups_path: data_dir.join("mls_groups.bin"),
            pending_join_results: RwLock::new(HashMap::new()),
            expected_join_result_inviters: StdMutex::new(HashMap::new()),
            pending_welcomes: RwLock::new(HashMap::new()),
            pending_welcome_receives: RwLock::new(HashMap::new()),
            pending_welcome_waiters: RwLock::new(HashMap::new()),
            pending_welcome_acks: RwLock::new(HashMap::new()),
            treekem_pending_events: RwLock::new(HashMap::new()),
            treekem_member_key_packages,
            treekem_event_log: RwLock::new(HashMap::new()),
            treekem_catchup_throttle: RwLock::new(HashMap::new()),
            group_membership_locks: RwLock::new(HashMap::new()),
            treekem_groups: RwLock::new(HashMap::new()),
            treekem_dir,
            ws_sessions: RwLock::new(HashMap::new()),
            ws_topics: RwLock::new(HashMap::new()),
            ws_outbound_stats: Arc::new(WsOutboundStats::default()),
            api_address: "127.0.0.1:0".parse().expect("valid test API address"),
            start_time: Instant::now(),
            broadcast_tx,
            file_transfers: RwLock::new(HashMap::new()),
            receive_hashers: RwLock::new(HashMap::new()),
            pending_file_chunks: RwLock::new(HashMap::new()),
            file_chunk_acks: RwLock::new(HashMap::new()),
            transfers_dir: data_dir.join("transfers"),
            shutdown_tx,
            shutdown_notify,
            update_config: DaemonUpdateConfig::default(),
            self_update_enabled: false,
            upgrade_check_cache: Mutex::new(None),
            upgrade_apply_lock: Arc::new(Mutex::new(())),
            api_token: "test-token".to_string(),
            sessions: auth::SessionStore::new(auth::SESSION_TOKEN_TTL),
            exec_service,
            groups_diagnostics: Arc::new(x0x::groups::GroupsDiagnostics::new()),
            connect_diagnostics: Arc::new(x0x::connect::ConnectDiagnostics::new(
                x0x::connect::ConnectPolicy::default().summary(),
            )),
            forward_service: None,
        }))
    }

    async fn response_json(response: Response) -> Result<(StatusCode, serde_json::Value)> {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .context("read response body")?;
        let body = serde_json::from_slice(&bytes).context("decode response body")?;
        Ok((status, body))
    }

    #[tokio::test]
    async fn agent_card_group_invite_from_get_card_is_accepted_on_join() -> Result<()> {
        let (authority, _authority_dir) = secure_endpoint_test_state().await?;
        let (joiner, _joiner_dir) = secure_endpoint_test_state().await?;
        let group_id = "5c".repeat(32);
        let authority_id = authority.agent.agent_id();
        let mut authority_info = x0x::groups::GroupInfo::with_policy(
            "card invite provenance".to_string(),
            "base-state fields should survive card export".to_string(),
            authority_id,
            group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        authority_info.recompute_state_hash();
        let stable_group_id = authority_info.stable_group_id().to_string();
        let authority_state_hash = authority_info.state_hash.clone();
        let authority_members = authority_info.members_v2.clone();
        authority
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), authority_info);

        let card_response = get_agent_card(
            State(Arc::clone(&authority)),
            Query(CardQuery {
                display_name: Some("authority".to_string()),
                include_groups: Some(true),
                include_local_addresses: false,
            }),
        )
        .await
        .into_response();
        let (card_status, card_body) = response_json(card_response).await?;
        assert_eq!(card_status, StatusCode::OK);
        let card: x0x::groups::card::AgentCard = serde_json::from_value(card_body["card"].clone())
            .context("decode agent card from handler response")?;
        let card_group = card
            .groups
            .iter()
            .find(|group| group.name == "card invite provenance")
            .expect("agent card should include the named group invite");
        let invite = x0x::groups::invite::SignedInvite::from_link(&card_group.invite_link)
            .map_err(|e| anyhow::anyhow!("decode card invite: {e}"))?;

        assert_eq!(
            invite.stable_group_id.as_deref(),
            Some(stable_group_id.as_str())
        );
        assert_eq!(
            invite.base_state_hash.as_deref(),
            Some(authority_state_hash.as_str())
        );
        assert_eq!(invite.base_members_v2.as_ref(), Some(&authority_members));
        assert_eq!(
            invite
                .creator_agent_id_from_base_state()
                .map_err(|e| anyhow::anyhow!("derive creator provenance: {e}"))?,
            hex::encode(authority_id.as_bytes())
        );
        {
            let groups = authority.named_groups.read().await;
            let info = groups.get(&group_id).expect("authority group retained");
            assert!(
                info.issued_invites.is_empty(),
                "GET /agent/card must not record or persist card-generated invite secrets"
            );
        }

        NAMED_GROUP_METADATA_PUBLISH_ATTEMPTS_FOR_TEST
            .lock()
            .expect("publish-attempt recorder poisoned")
            .clear();
        let join_response = join_group_via_invite(
            State(Arc::clone(&joiner)),
            Json(JoinGroupRequest {
                invite: card_group.invite_link.clone(),
                display_name: Some("joiner".to_string()),
            }),
        )
        .await
        .into_response();
        let (join_status, join_body) = response_json(join_response).await?;

        assert_eq!(
            join_status,
            StatusCode::OK,
            "card invite join should be accepted, body: {join_body}"
        );
        assert_ne!(
            join_status,
            StatusCode::BAD_REQUEST,
            "card invite join must not fail with the pre-fix missing-base-state 400"
        );
        let joiner_hex = hex::encode(joiner.agent.agent_id().as_bytes());
        let metadata_topic = {
            let groups = joiner.named_groups.read().await;
            let stub = groups
                .get(&group_id)
                .expect("accepted card invite should create a local join stub");
            assert_eq!(stub.stable_group_id(), stable_group_id.as_str());
            assert_eq!(stub.state_hash, authority_state_hash);
            assert_eq!(stub.members_v2, authority_members);
            assert!(
                !stub.has_active_member(&joiner_hex),
                "card-derived convergence remains Phase 2; this guard only proves accepted join stub formation"
            );
            stub.metadata_topic.clone()
        };
        let publish_attempts = NAMED_GROUP_METADATA_PUBLISH_ATTEMPTS_FOR_TEST
            .lock()
            .expect("publish-attempt recorder poisoned");
        assert!(
            publish_attempts
                .iter()
                .any(|(topic, event_group_id)| topic == &metadata_topic
                    && event_group_id == &stable_group_id),
            "join handler should attempt to publish the joiner-authored MemberJoined request"
        );
        Ok(())
    }

    #[tokio::test]
    async fn agent_card_does_not_export_withdrawn_group_invites() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let active_group_id = "6a".repeat(32);
        let withdrawn_group_id = "6b".repeat(32);
        let stale_active_group_id = "6c".repeat(32);
        let withdrawn_alias_group_id = "6d".repeat(32);
        let agent_id = state.agent.agent_id();
        let mut active = x0x::groups::GroupInfo::with_policy(
            "active card group".to_string(),
            String::new(),
            agent_id,
            active_group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        active.recompute_state_hash();
        let mut withdrawn = x0x::groups::GroupInfo::with_policy(
            "withdrawn card group".to_string(),
            String::new(),
            agent_id,
            withdrawn_group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        withdrawn.withdrawn = true;
        clear_group_info_key_material(&mut withdrawn);
        withdrawn.recompute_state_hash();
        let mut stale_active = x0x::groups::GroupInfo::with_policy(
            "stale active alias".to_string(),
            String::new(),
            agent_id,
            stale_active_group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        stale_active.recompute_state_hash();
        let mut withdrawn_same_stable_alias = stale_active.clone();
        withdrawn_same_stable_alias.name = "withdrawn same-stable alias".to_string();
        withdrawn_same_stable_alias.mls_group_id = withdrawn_alias_group_id.clone();
        withdrawn_same_stable_alias.withdrawn = true;
        clear_group_info_key_material(&mut withdrawn_same_stable_alias);
        withdrawn_same_stable_alias.recompute_state_hash();
        {
            let mut groups = state.named_groups.write().await;
            groups.insert(active_group_id, active);
            groups.insert(withdrawn_group_id, withdrawn);
            groups.insert(stale_active_group_id, stale_active);
            groups.insert(withdrawn_alias_group_id, withdrawn_same_stable_alias);
        }

        let card_response = get_agent_card(
            State(Arc::clone(&state)),
            Query(CardQuery {
                display_name: Some("authority".to_string()),
                include_groups: Some(true),
                include_local_addresses: false,
            }),
        )
        .await
        .into_response();
        let (status, body) = response_json(card_response).await?;
        assert_eq!(status, StatusCode::OK);
        let card: x0x::groups::card::AgentCard = serde_json::from_value(body["card"].clone())
            .context("decode agent card from handler response")?;

        assert!(
            card.groups
                .iter()
                .any(|group| group.name == "active card group"),
            "active groups should still be exported when include_groups=true"
        );
        assert!(
            card.groups
                .iter()
                .all(|group| group.name != "withdrawn card group"),
            "withdrawn tombstones must not be re-advertised as joinable card invites"
        );
        assert!(
            card.groups
                .iter()
                .all(|group| group.name != "stale active alias"),
            "stale active aliases for a withdrawn stable group must not be re-advertised"
        );
        Ok(())
    }

    // ── Card import trust-floor tests ───────────────────────────────────
    //
    // Regression: importing an agent card must never LOWER an existing
    // contact's trust level. A routine re-import (default trust_level:
    // "known") silently downgraded manually-trusted peers, breaking the
    // streams identity gate that requires unflagged `Accept` (Trusted →
    // Accept, Known → AcceptWithFlag).

    fn make_unsigned_card_link(display_name: &str, agent_id: &crate::identity::AgentId) -> String {
        let machine_id = hex::encode([0x11u8; 32]);
        let card =
            x0x::groups::card::AgentCard::new(display_name.to_string(), agent_id, &machine_id);
        card.to_link()
    }

    #[tokio::test]
    async fn card_import_does_not_downgrade_trusted_contact() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let target_kp = crate::identity::AgentKeypair::generate()?;
        let target_id = target_kp.agent_id();

        // Pre-seed: manually trust the contact.
        state
            .contacts
            .write()
            .await
            .set_trust(&target_id, x0x::contacts::TrustLevel::Trusted);

        // Import card with trust_level "known" — must NOT downgrade.
        let card_link = make_unsigned_card_link("Alice", &target_id);
        let req: ImportCardRequest = serde_json::from_value(serde_json::json!({
            "card": card_link,
            "trust_level": "known"
        }))
        .context("deserialize ImportCardRequest")?;
        let response = import_agent_card(State(Arc::clone(&state)), Json(req))
            .await
            .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::OK);

        // Response must show effective trust = Trusted and flag the ignored downgrade.
        assert_eq!(
            body["trust_level"], "Trusted",
            "import must not downgrade a trusted contact"
        );
        assert_eq!(
            body["trust_change_ignored"], true,
            "response must flag that the requested downgrade was ignored"
        );

        // Store must still show Trusted.
        let stored = state.contacts.read().await.trust_level(&target_id);
        assert_eq!(
            stored,
            x0x::contacts::TrustLevel::Trusted,
            "contact store must retain Trusted after card import"
        );
        Ok(())
    }

    #[tokio::test]
    async fn card_import_sets_requested_trust_for_new_contact() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let target_kp = crate::identity::AgentKeypair::generate()?;
        let target_id = target_kp.agent_id();

        // Import card for a brand-new contact with trust_level "known".
        let card_link = make_unsigned_card_link("Bob", &target_id);
        let req: ImportCardRequest = serde_json::from_value(serde_json::json!({
            "card": card_link,
            "trust_level": "known"
        }))
        .context("deserialize ImportCardRequest")?;
        let response = import_agent_card(State(Arc::clone(&state)), Json(req))
            .await
            .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["trust_level"], "Known");
        assert_eq!(body["trust_change_ignored"], false);

        let stored = state.contacts.read().await.trust_level(&target_id);
        assert_eq!(
            stored,
            x0x::contacts::TrustLevel::Known,
            "new contact must get the requested trust level"
        );
        Ok(())
    }

    #[tokio::test]
    async fn explicit_patch_downgrade_still_works() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let target_kp = crate::identity::AgentKeypair::generate()?;
        let target_id = target_kp.agent_id();
        let target_hex = hex::encode(target_id.as_bytes());

        // Start trusted.
        state
            .contacts
            .write()
            .await
            .set_trust(&target_id, x0x::contacts::TrustLevel::Trusted);

        // Explicit PATCH downgrade to Known — unambiguous user intent, MUST work
        // (unlike card import which is floor-protected).
        let req: UpdateContactRequest = serde_json::from_value(serde_json::json!({
            "trust_level": "known"
        }))
        .context("deserialize UpdateContactRequest")?;
        let response = update_contact(State(Arc::clone(&state)), Path(target_hex), Json(req))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let stored = state.contacts.read().await.trust_level(&target_id);
        assert_eq!(
            stored,
            x0x::contacts::TrustLevel::Known,
            "explicit PATCH must be able to downgrade trust"
        );
        Ok(())
    }

    #[tokio::test]
    async fn card_import_does_not_unblock_blocked_contact() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let target_kp = crate::identity::AgentKeypair::generate()?;
        let target_id = target_kp.agent_id();

        // Pre-seed: deliberately block the contact.
        state
            .contacts
            .write()
            .await
            .set_trust(&target_id, x0x::contacts::TrustLevel::Blocked);

        // Import card with trust_level "known" — must NOT un-block.
        let card_link = make_unsigned_card_link("Mallory", &target_id);
        let req: ImportCardRequest = serde_json::from_value(serde_json::json!({
            "card": card_link,
            "trust_level": "known"
        }))
        .context("deserialize ImportCardRequest")?;
        let response = import_agent_card(State(Arc::clone(&state)), Json(req))
            .await
            .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::OK);

        // Response must show Blocked and flag the ignored change.
        assert_eq!(
            body["trust_level"], "Blocked",
            "import must not un-block a deliberately blocked contact"
        );
        assert_eq!(
            body["trust_change_ignored"], true,
            "response must flag that the requested un-block was ignored"
        );

        // Store must still show Blocked.
        let stored = state.contacts.read().await.trust_level(&target_id);
        assert_eq!(
            stored,
            x0x::contacts::TrustLevel::Blocked,
            "contact store must retain Blocked after card import"
        );
        Ok(())
    }

    #[tokio::test]
    async fn explicit_patch_unblock_still_works() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let target_kp = crate::identity::AgentKeypair::generate()?;
        let target_id = target_kp.agent_id();
        let target_hex = hex::encode(target_id.as_bytes());

        // Start blocked.
        state
            .contacts
            .write()
            .await
            .set_trust(&target_id, x0x::contacts::TrustLevel::Blocked);

        // Explicit PATCH un-block to Known — unambiguous user intent, MUST work
        // (unlike card import which is floor-protected and Blocked-sticky).
        let req: UpdateContactRequest = serde_json::from_value(serde_json::json!({
            "trust_level": "known"
        }))
        .context("deserialize UpdateContactRequest")?;
        let response = update_contact(State(Arc::clone(&state)), Path(target_hex), Json(req))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let stored = state.contacts.read().await.trust_level(&target_id);
        assert_eq!(
            stored,
            x0x::contacts::TrustLevel::Known,
            "explicit PATCH must be able to un-block"
        );
        Ok(())
    }

    /// Rule 9: prove the *real* REST handlers enforce admin authority.
    ///
    /// `tests/membership_authority.rs` exercises the library authority
    /// primitives, but it re-implements the handler pre-check shape, so it
    /// cannot catch a handler that silently drops `require_admin_or_above`.
    /// This test invokes the actual handlers with a non-admin local caller and
    /// asserts each rejects with 403 — so deleting an authority gate in any of
    /// the membership handlers fails here, exactly the change class ADR-0016
    /// makes load-bearing.
    #[tokio::test]
    async fn membership_handlers_reject_non_admin_local_caller() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "7c".repeat(32);
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let foreign_admin = crate::identity::AgentKeypair::generate()?;
        let foreign_admin_hex = hex::encode(foreign_admin.agent_id().as_bytes());
        let target_hex = "33".repeat(32);

        // GSS (non-TreeKEM) group whose admin is a *foreign* agent; the local
        // daemon agent is only a plain Member, so it must not be able to
        // remove/ban/role-change anyone.
        let mut info = x0x::groups::GroupInfo::with_policy(
            "authority gate".to_string(),
            String::new(),
            foreign_admin.agent_id(),
            group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        info.add_member(
            local_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(foreign_admin_hex.clone()),
            None,
        );
        info.add_member(
            target_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(foreign_admin_hex),
            None,
        );
        info.roster_revision = info.roster_revision.saturating_add(1);
        info.recompute_state_hash();
        assert_ne!(
            info.secure_plane,
            x0x::mls::SecureGroupPlane::TreeKem,
            "test targets the GSS handler path so the admin gate runs before TreeKEM delegation"
        );
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info);

        let remove = remove_named_group_member(
            State(Arc::clone(&state)),
            Path((group_id.clone(), target_hex.clone())),
        )
        .await
        .into_response();
        let (remove_status, remove_body) = response_json(remove).await?;
        assert_eq!(
            remove_status,
            StatusCode::FORBIDDEN,
            "remove_named_group_member must reject a non-admin caller, body: {remove_body}"
        );

        let ban = ban_group_member(
            State(Arc::clone(&state)),
            Path((group_id.clone(), target_hex.clone())),
        )
        .await
        .into_response();
        let (ban_status, ban_body) = response_json(ban).await?;
        assert_eq!(
            ban_status,
            StatusCode::FORBIDDEN,
            "ban_group_member must reject a non-admin caller, body: {ban_body}"
        );

        let role = update_member_role(
            State(Arc::clone(&state)),
            Path((group_id.clone(), target_hex.clone())),
            Json(UpdateMemberRoleRequest {
                role: "member".to_string(),
            }),
        )
        .await
        .into_response();
        let (role_status, role_body) = response_json(role).await?;
        assert_eq!(
            role_status,
            StatusCode::FORBIDDEN,
            "update_member_role must reject a non-admin caller, body: {role_body}"
        );

        // The rejected calls must not have mutated the roster.
        let groups = state.named_groups.read().await;
        let after = groups.get(&group_id).expect("group retained");
        assert_eq!(
            after.caller_role(&target_hex),
            Some(x0x::groups::GroupRole::Member),
            "forbidden handler calls must leave the target untouched"
        );
        Ok(())
    }

    fn secure_endpoint_group_for_agent(
        agent_id: AgentId,
        group_id: &str,
        stable_group_id: &str,
        secure_plane: x0x::mls::SecureGroupPlane,
    ) -> x0x::groups::GroupInfo {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            agent_id,
            group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
        );
        info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            stable_group_id.to_string(),
            hex::encode(agent_id.as_bytes()),
            info.created_at,
            String::new(),
        ));
        info.secure_plane = secure_plane;
        info.secret_epoch = 7;
        info.shared_secret = Some(vec![9; 32]);
        info
    }

    async fn install_secure_endpoint_group(
        state: &Arc<AppState>,
        group_id: &str,
        stable_group_id: &str,
        secure_plane: x0x::mls::SecureGroupPlane,
    ) {
        let info = secure_endpoint_group_for_agent(
            state.agent.agent_id(),
            group_id,
            stable_group_id,
            secure_plane,
        );
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info);
    }

    fn metadata_terminality_test_group(
        state: &Arc<AppState>,
        group_id: &str,
    ) -> (x0x::groups::GroupInfo, String, String) {
        let admin_hex = hex::encode(state.agent.agent_id().as_bytes());
        let member_hex = "22".repeat(32);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "metadata terminality".to_string(),
            String::new(),
            state.agent.agent_id(),
            group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        info.shared_secret = Some(vec![9; 32]);
        info.add_member(
            member_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.recompute_state_hash();
        (info, admin_hex, member_hex)
    }

    fn sign_metadata_terminality_commit(
        parent: &x0x::groups::GroupInfo,
        scratch: &x0x::groups::GroupInfo,
        state: &Arc<AppState>,
        now_ms: u64,
    ) -> x0x::groups::GroupStateCommit {
        x0x::groups::GroupStateCommit::sign(
            parent.stable_group_id().to_string(),
            parent.state_revision.saturating_add(1),
            Some(parent.state_hash.clone()),
            x0x::groups::compute_roster_root(&scratch.members_v2),
            x0x::groups::compute_policy_hash(&scratch.policy),
            x0x::groups::compute_public_meta_hash(&scratch.public_meta()),
            scratch.security_binding.clone(),
            scratch.withdrawn,
            now_ms,
            state.agent.identity().agent_keypair(),
        )
        .expect("signed terminality commit")
    }

    async fn install_metadata_terminality_group(
        state: &Arc<AppState>,
        group_id: &str,
    ) -> (String, String) {
        let (info, admin_hex, member_hex) = metadata_terminality_test_group(state, group_id);
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info);
        (admin_hex, member_hex)
    }

    #[tokio::test]
    async fn metadata_member_removed_withdrawn_commit_rejected_for_live_group() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "metadata-member-removed-terminality";
        let (admin_hex, member_hex) = install_metadata_terminality_group(&state, group_id).await;
        let parent = state
            .named_groups
            .read()
            .await
            .get(group_id)
            .expect("group installed")
            .clone();
        let mut scratch = parent.clone();
        scratch.remove_member(&member_hex, Some(admin_hex.clone()));
        scratch.withdrawn = true;
        let commit = sign_metadata_terminality_commit(&parent, &scratch, &state, 1_000);
        assert!(commit.withdrawn);

        let event = NamedGroupMetadataEvent::MemberRemoved {
            group_id: parent.stable_group_id().to_string(),
            revision: 1,
            actor: admin_hex.clone(),
            agent_id: member_hex.clone(),
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit: Some(commit),
        };

        let applied = apply_named_group_metadata_event_inner(
            &state,
            event,
            state.agent.agent_id(),
            true,
            true,
        )
        .await;
        assert!(!applied, "non-GroupDeleted withdrawal commit must reject");
        let groups = state.named_groups.read().await;
        let stored = groups.get(group_id).expect("group retained");
        assert!(!stored.withdrawn);
        assert!(stored.has_active_member(&member_hex));
        assert_eq!(stored.shared_secret, Some(vec![9; 32]));
        Ok(())
    }

    #[tokio::test]
    async fn metadata_role_update_withdrawn_commit_rejected_for_live_group() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "metadata-role-update-terminality";
        let (admin_hex, member_hex) = install_metadata_terminality_group(&state, group_id).await;
        let parent = state
            .named_groups
            .read()
            .await
            .get(group_id)
            .expect("group installed")
            .clone();
        let mut scratch = parent.clone();
        scratch.set_member_role(&member_hex, x0x::groups::GroupRole::Admin);
        scratch.withdrawn = true;
        let commit = sign_metadata_terminality_commit(&parent, &scratch, &state, 1_000);
        assert!(commit.withdrawn);

        let event = NamedGroupMetadataEvent::MemberRoleUpdated {
            group_id: parent.stable_group_id().to_string(),
            revision: 1,
            actor: admin_hex.clone(),
            agent_id: member_hex.clone(),
            role: x0x::groups::GroupRole::Admin,
            commit: Some(commit),
        };

        let applied = apply_named_group_metadata_event_inner(
            &state,
            event,
            state.agent.agent_id(),
            true,
            true,
        )
        .await;
        assert!(!applied, "only GroupDeleted may terminalize a live group");
        let groups = state.named_groups.read().await;
        let stored = groups.get(group_id).expect("group retained");
        assert!(!stored.withdrawn);
        assert_eq!(
            stored.members_v2[&member_hex].role,
            x0x::groups::GroupRole::Member
        );
        assert_eq!(stored.shared_secret, Some(vec![9; 32]));
        Ok(())
    }

    #[tokio::test]
    async fn metadata_group_deleted_withdraws_and_wipes_key_material() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "metadata-group-deleted-terminality";
        let (admin_hex, _member_hex) = install_metadata_terminality_group(&state, group_id).await;
        let parent = state
            .named_groups
            .read()
            .await
            .get(group_id)
            .expect("group installed")
            .clone();
        let mut scratch = parent.clone();
        scratch.withdrawn = true;
        let commit = sign_metadata_terminality_commit(&parent, &scratch, &state, 1_000);
        assert!(commit.withdrawn);

        let event = NamedGroupMetadataEvent::GroupDeleted {
            group_id: parent.stable_group_id().to_string(),
            revision: 1,
            actor: admin_hex,
            commit: Some(commit),
        };

        let applied = apply_named_group_metadata_event_inner(
            &state,
            event,
            state.agent.agent_id(),
            true,
            true,
        )
        .await;
        assert!(applied, "GroupDeleted is the terminal withdrawal path");
        let groups = state.named_groups.read().await;
        let stored = groups.get(group_id).expect("terminal tombstone retained");
        assert!(stored.withdrawn);
        assert_eq!(stored.shared_secret, None);
        Ok(())
    }

    /// Enforcement point 4 crown-jewel property (issue #130): the revocation
    /// gate MUST precede `bypass_verified`, so a revoked sender is denied even
    /// for a self-authenticating `GroupDeleted{commit:Some}` /
    /// `MemberRemoved{commit:Some}` event — the exact events that bypass the
    /// `verified` cache annotation (#99). This test fails if a future refactor
    /// moves the revocation check below the `bypass_verified` block.
    ///
    /// It asserts BOTH directions in one place:
    /// - (b) a NON-revoked but UNVERIFIED committer's terminal event STILL
    ///   applies (bypass_verified is intact — #99 non-regression), and
    /// - (a) once that same committer is revoked, the identical terminal event
    ///   for a second live group is DENIED and the group is left untouched.
    #[tokio::test]
    async fn metadata_revoked_sender_denied_even_for_bypass_verified_event() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;

        // Two independent live groups, both committed by this daemon's agent.
        let group_b = "ep4-nonregression-unverified";
        let group_a = "ep4-revoked-denied";
        let (admin_b, _member_b) = install_metadata_terminality_group(&state, group_b).await;
        let (admin_a, _member_a) = install_metadata_terminality_group(&state, group_a).await;

        let committer = state.agent.agent_id();

        // ── (b) #99 non-regression ──────────────────────────────────────
        // An UNVERIFIED committer's GroupDeleted{commit:Some} still applies,
        // because bypass_verified is intact and the signed commit carries its
        // own authority. We pass verified = FALSE to prove the bypass path.
        let parent_b = state
            .named_groups
            .read()
            .await
            .get(group_b)
            .expect("group_b installed")
            .clone();
        let mut scratch_b = parent_b.clone();
        scratch_b.withdrawn = true;
        let commit_b = sign_metadata_terminality_commit(&parent_b, &scratch_b, &state, 1_000);
        let event_b = NamedGroupMetadataEvent::GroupDeleted {
            group_id: parent_b.stable_group_id().to_string(),
            revision: 1,
            actor: admin_b,
            commit: Some(commit_b),
        };
        let applied_b = apply_named_group_metadata_event_inner(
            &state, event_b, committer, /* verified = */ false, true,
        )
        .await;
        assert!(
            applied_b,
            "#99 non-regression: an UNVERIFIED (but not revoked) committer's \
             self-authenticating GroupDeleted must still apply via bypass_verified"
        );

        // ── revoke the committer via the real verify_and_insert path ─────
        // A valid SELF-revocation: the issuer key IS the subject agent-id, so
        // authority verifies from the record alone (no certificate needed).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let record = x0x::revocation::RevocationRecord::sign(
            x0x::revocation::RevokedSubject::Agent(committer),
            state.agent.identity().agent_keypair().public_key(),
            state.agent.identity().agent_keypair().secret_key(),
            now,
            Some("ep4 test: committer compromised".to_string()),
        )
        .expect("sign self-revocation");
        {
            let set = state.agent.revocation_set();
            let mut set = set.write().await;
            set.verify_and_insert(record, None)
                .expect("self-revocation must verify and insert");
        }

        // ── (a) crown jewel: revoked committer is DENIED ────────────────
        // The SAME terminal event, same committer, verified = FALSE. Because
        // the revocation gate runs BEFORE bypass_verified, this returns false
        // and group_a is left completely intact (not withdrawn, key retained).
        let parent_a = state
            .named_groups
            .read()
            .await
            .get(group_a)
            .expect("group_a installed")
            .clone();
        let mut scratch_a = parent_a.clone();
        scratch_a.withdrawn = true;
        let commit_a = sign_metadata_terminality_commit(&parent_a, &scratch_a, &state, 1_000);
        let event_a = NamedGroupMetadataEvent::GroupDeleted {
            group_id: parent_a.stable_group_id().to_string(),
            revision: 1,
            actor: admin_a,
            commit: Some(commit_a),
        };
        let applied_a = apply_named_group_metadata_event_inner(
            &state, event_a, committer, /* verified = */ false, true,
        )
        .await;
        assert!(
            !applied_a,
            "crown jewel: a REVOKED committer's GroupDeleted must be denied \
             BEFORE bypass_verified — otherwise a revoked admin could still \
             terminate groups via the self-authenticating commit path"
        );
        let groups = state.named_groups.read().await;
        let stored = groups.get(group_a).expect("group_a retained");
        assert!(
            !stored.withdrawn,
            "denied-at-the-gate: group_a must be untouched by the revoked event"
        );
        assert_eq!(
            stored.shared_secret,
            Some(vec![9; 32]),
            "denied-at-the-gate: group_a key material must be untouched"
        );
        Ok(())
    }

    fn assert_lost_race_conflict_drops_fields(
        status: StatusCode,
        body: &serde_json::Value,
        leaked_fields: &[&str],
    ) {
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["ok"].as_bool(), Some(false));
        assert_eq!(body["error"].as_str(), Some("group is withdrawn"));
        for field in leaked_fields {
            assert!(
                body.get(*field).is_none(),
                "withdrawn conflict must not leak secure effect field {field}"
            );
        }
    }

    #[tokio::test]
    async fn secure_encrypt_endpoint_gss_lost_race_drops_ciphertext() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "gss-encrypt-local";
        let stable_group_id = "gss-encrypt-stable";
        install_secure_endpoint_group(
            &state,
            group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        )
        .await;

        let _guard = force_post_crypto_withdrawn_ids(&[stable_group_id]);
        let (status, body) = secure_group_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureEncryptRequest {
                payload_b64: BASE64.encode(b"secret"),
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["ciphertext_b64", "nonce_b64"]);
        Ok(())
    }

    #[tokio::test]
    async fn secure_decrypt_endpoint_gss_lost_race_drops_plaintext() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "gss-decrypt-local";
        let stable_group_id = "gss-decrypt-stable";
        install_secure_endpoint_group(
            &state,
            group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        )
        .await;
        let (encrypt_status, encrypted) = secure_group_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureEncryptRequest {
                payload_b64: BASE64.encode(b"secret"),
            }),
        )
        .await;
        assert_eq!(encrypt_status, StatusCode::OK);

        let _guard = force_post_crypto_withdrawn_ids(&[stable_group_id]);
        let (status, body) = secure_group_decrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureDecryptRequest {
                ciphertext_b64: encrypted.0["ciphertext_b64"]
                    .as_str()
                    .expect("ciphertext present")
                    .to_string(),
                nonce_b64: encrypted.0["nonce_b64"]
                    .as_str()
                    .expect("nonce present")
                    .to_string(),
                secret_epoch: encrypted.0["secret_epoch"].as_u64().expect("epoch present"),
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["payload_b64"]);
        Ok(())
    }

    #[tokio::test]
    async fn secure_reseal_endpoint_lost_race_drops_secret_envelope() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "gss-reseal-local";
        let stable_group_id = "gss-reseal-stable";
        install_secure_endpoint_group(
            &state,
            group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        )
        .await;
        let recipient = hex::encode(state.agent.agent_id().as_bytes());
        state
            .named_groups
            .write()
            .await
            .get_mut(group_id)
            .expect("group installed")
            .set_member_kem_public_key(
                &recipient,
                BASE64.encode(&state.agent_kem_keypair.public_bytes),
            );

        let _guard = force_post_crypto_withdrawn_ids(&[stable_group_id]);
        let (status, body) = secure_group_reseal(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(ResealRequest { recipient }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(
            status,
            &body.0,
            &[
                "kem_ciphertext_b64",
                "aead_nonce_b64",
                "aead_ciphertext_b64",
            ],
        );
        Ok(())
    }

    #[tokio::test]
    async fn secure_open_envelope_endpoint_lost_race_drops_opened_secret() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "open-envelope-stable";
        install_secure_endpoint_group(&state, group_id, group_id, x0x::mls::SecureGroupPlane::Gss)
            .await;
        let recipient = hex::encode(state.agent.agent_id().as_bytes());
        let secret = [7_u8; 32];
        let aad = secure_share_aad(group_id, &recipient, 7);
        let (kem_ct, aead_nonce, aead_ct) =
            x0x::groups::kem_envelope::seal_group_secret_to_recipient(
                &state.agent_kem_keypair.public_bytes,
                &aad,
                &secret,
            )?;

        let _guard = force_post_crypto_withdrawn_ids(&[group_id]);
        let (status, body) = secure_open_envelope_adversarial(
            State(Arc::clone(&state)),
            Json(OpenEnvelopeRequest {
                group_id: group_id.to_string(),
                recipient,
                secret_epoch: 7,
                kem_ciphertext_b64: BASE64.encode(&kem_ct),
                aead_nonce_b64: BASE64.encode(aead_nonce),
                aead_ciphertext_b64: BASE64.encode(&aead_ct),
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["secret_b64"]);
        Ok(())
    }

    #[tokio::test]
    async fn metadata_secure_share_lost_race_does_not_install_secret() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "metadata-share-local";
        let stable_group_id = "metadata-share-stable";
        install_secure_endpoint_group(
            &state,
            group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        )
        .await;
        let recipient = hex::encode(state.agent.agent_id().as_bytes());
        let secret_epoch = 8;
        let secret = [8_u8; 32];
        let aad = secure_share_aad(stable_group_id, &recipient, secret_epoch);
        let (kem_ct, aead_nonce, aead_ct) =
            x0x::groups::kem_envelope::seal_group_secret_to_recipient(
                &state.agent_kem_keypair.public_bytes,
                &aad,
                &secret,
            )?;
        let event = NamedGroupMetadataEvent::SecureShareDelivered {
            group_id: stable_group_id.to_string(),
            recipient: recipient.clone(),
            secret_epoch,
            kem_ciphertext_b64: BASE64.encode(&kem_ct),
            aead_nonce_b64: BASE64.encode(aead_nonce),
            aead_ciphertext_b64: BASE64.encode(&aead_ct),
            actor: recipient,
        };

        let _guard = force_post_crypto_withdrawn_ids(&[stable_group_id]);
        let _ = apply_named_group_metadata_event_inner(
            &state,
            event,
            state.agent.agent_id(),
            true,
            true,
        )
        .await;

        let groups = state.named_groups.read().await;
        let info = groups
            .get(group_id)
            .expect("group retained as terminality marker");
        assert!(info.withdrawn, "lost-race withdrawal should win");
        assert_eq!(info.shared_secret, None, "secret must not be installed");
        assert_ne!(info.secret_epoch, secret_epoch, "epoch must not advance");
        Ok(())
    }

    fn treekem_metadata_group_info(
        creator: AgentId,
        group_id: &str,
        stable_group_id: &str,
    ) -> x0x::groups::GroupInfo {
        let creator_hex = hex::encode(creator.as_bytes());
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            creator,
            group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
        );
        info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            stable_group_id.to_string(),
            creator_hex,
            info.created_at,
            String::new(),
        ));
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.shared_secret = None;
        info.secret_epoch = 0;
        info.security_binding = Some("treekem:epoch=0".to_string());
        info.recompute_state_hash();
        info
    }

    struct MemberJoinedTreeKemFixture {
        state: Arc<AppState>,
        _dir: tempfile::TempDir,
        group_id: String,
        stable_group_id: String,
        member_id: AgentId,
        member_hex: String,
        event: NamedGroupMetadataEvent,
        group: Arc<Mutex<x0x::mls::TreeKemMlsGroup>>,
        initial_epoch: u64,
    }

    async fn member_joined_treekem_fixture(
        group_byte: u8,
        stable_byte: u8,
    ) -> Result<MemberJoinedTreeKemFixture> {
        let (state, dir) = secure_endpoint_test_state().await?;
        let group_id = format!("{group_byte:02x}").repeat(32);
        let stable_group_id = format!("{stable_byte:02x}").repeat(32);
        let group_id_bytes = hex::decode(&group_id)?;
        let inviter = state.agent.agent_id();
        let inviter_hex = hex::encode(inviter.as_bytes());
        let creator_seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let live_group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, inviter, &creator_seed)?;
        let initial_epoch = live_group.epoch();
        let group = Arc::new(Mutex::new(live_group));
        state
            .treekem_groups
            .write()
            .await
            .insert(group_id.clone(), Arc::clone(&group));

        let mut info = treekem_metadata_group_info(inviter, &group_id, &stable_group_id);
        let now_ms = now_millis_u64();
        let invite_secret = format!("member-joined-invite-{group_byte:02x}");
        info.record_issued_invite(
            invite_secret.clone(),
            now_ms / 1_000,
            0,
            x0x::groups::GroupRole::Member,
        );
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info);

        let member_keypair = x0x::identity::AgentKeypair::generate()?;
        let member_id = member_keypair.agent_id();
        let member_hex = hex::encode(member_id.as_bytes());
        let member_public_key_b64 = BASE64.encode(member_keypair.public_key().as_bytes());
        let member_seed = [stable_byte; 32];
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_id, &member_seed)?;
        let treekem_key_package_b64 = BASE64.encode(prepared.key_package_bytes());
        let canonical = canonical_member_joined_bytes(
            &group_id,
            Some(&stable_group_id),
            &member_hex,
            &member_public_key_b64,
            x0x::groups::GroupRole::Member,
            None,
            &inviter_hex,
            &invite_secret,
            now_ms,
            Some(&treekem_key_package_b64),
        );
        let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            member_keypair.secret_key(),
            &canonical,
        )
        .map_err(|e| anyhow::anyhow!("sign MemberJoined fixture: {e:?}"))?;
        let event = NamedGroupMetadataEvent::MemberJoined {
            group_id: group_id.clone(),
            stable_group_id: Some(stable_group_id.clone()),
            member_agent_id: member_hex.clone(),
            member_public_key_b64,
            role: x0x::groups::GroupRole::Member,
            display_name: None,
            inviter_agent_id: inviter_hex,
            invite_secret,
            ts_ms: now_ms,
            treekem_key_package_b64: Some(treekem_key_package_b64),
            recovery_authority_agent_id: None,
            recovery_authority_public_key_b64: None,
            recovery_authority_signature_b64: None,
            recovery_authority_commit: None,
            signature_b64: BASE64.encode(signature.as_bytes()),
        };
        let (recovery_commit, retained_commit) = {
            let groups = state.named_groups.read().await;
            let mut accepted = groups.get(&group_id).expect("fixture group exists").clone();
            accepted.roster_revision = accepted.roster_revision.saturating_add(1);
            accepted.add_member(
                member_hex.clone(),
                x0x::groups::GroupRole::Member,
                Some(hex::encode(state.agent.agent_id().as_bytes())),
                None,
            );
            if let NamedGroupMetadataEvent::MemberJoined {
                treekem_key_package_b64: Some(kp_b64),
                ..
            } = &event
            {
                accepted.set_member_treekem_key_package(&member_hex, kp_b64.clone());
            }
            accepted.secret_epoch = initial_epoch.saturating_add(1);
            accepted.security_binding =
                treekem_recovery_security_binding(accepted.secret_epoch, &event);
            let commit = accepted.seal_commit(state.agent.identity().agent_keypair(), now_ms)?;
            let retained = accepted
                .commit_log
                .last()
                .cloned()
                .expect("sealed fixture commit retained");
            (commit, retained)
        };
        state
            .named_groups
            .write()
            .await
            .get_mut(&group_id)
            .expect("fixture group exists")
            .commit_log
            .push(retained_commit);
        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_id).expect("fixture group exists");
            info.add_member(
                member_hex.clone(),
                x0x::groups::GroupRole::Member,
                Some(hex::encode(state.agent.agent_id().as_bytes())),
                None,
            );
            if let NamedGroupMetadataEvent::MemberJoined {
                treekem_key_package_b64: Some(kp_b64),
                ..
            } = &event
            {
                info.set_member_treekem_key_package(&member_hex, kp_b64.clone());
                info.members_v2
                    .get_mut(&member_hex)
                    .expect("fixture member exists")
                    .treekem_key_package_b64 = None;
            }
            info.remove_member(&member_hex, None);
            info.recompute_state_hash();
        }
        let event = attest_member_joined_recovery_event(
            &event,
            state.agent.identity().agent_keypair(),
            &recovery_commit,
        )?;

        Ok(MemberJoinedTreeKemFixture {
            state,
            _dir: dir,
            group_id,
            stable_group_id,
            member_id,
            member_hex,
            event,
            group,
            initial_epoch,
        })
    }

    async fn add_active_witness_to_treekem_fixture(
        fixture: &MemberJoinedTreeKemFixture,
        witness: &Arc<AppState>,
    ) -> Result<()> {
        let group_id_bytes = hex::decode(&fixture.group_id)?;
        let witness_id = witness.agent.agent_id();
        let witness_hex = hex::encode(witness_id.as_bytes());
        let witness_seed = agent_treekem_seed(witness.agent.as_ref(), &group_id_bytes);
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(witness_id, &witness_seed)?;
        let (welcome, epoch) = {
            let mut owner_group = fixture.group.lock().await;
            let add = owner_group.add_member(witness_id, prepared.key_package_bytes())?;
            (add.welcome, owner_group.epoch())
        };
        let witness_group = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &welcome)?;
        let info = {
            let mut groups = fixture.state.named_groups.write().await;
            let info = groups
                .get_mut(&fixture.group_id)
                .expect("owner fixture retains group");
            info.add_member(
                witness_hex,
                x0x::groups::GroupRole::Member,
                Some(hex::encode(fixture.state.agent.agent_id().as_bytes())),
                None,
            );
            info.secret_epoch = epoch;
            info.security_binding = Some(format!("treekem:epoch={epoch}"));
            info.recompute_state_hash();
            info.clone()
        };
        witness
            .named_groups
            .write()
            .await
            .insert(fixture.group_id.clone(), info);
        witness.treekem_groups.write().await.insert(
            fixture.group_id.clone(),
            Arc::new(Mutex::new(witness_group)),
        );
        Ok(())
    }

    fn signed_member_joined_event_for_test(
        keypair: &x0x::identity::AgentKeypair,
        group_id: &str,
        inviter_agent_id: &str,
        invite_secret: &str,
        role: x0x::groups::GroupRole,
    ) -> Result<(AgentId, String, String, NamedGroupMetadataEvent)> {
        let member_id = keypair.agent_id();
        let member_hex = hex::encode(member_id.as_bytes());
        let member_public_key_b64 = BASE64.encode(keypair.public_key().as_bytes());
        let ts_ms = now_millis_u64();
        let canonical = canonical_member_joined_bytes(
            group_id,
            Some(group_id),
            &member_hex,
            &member_public_key_b64,
            role,
            None,
            inviter_agent_id,
            invite_secret,
            ts_ms,
            None,
        );
        let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            keypair.secret_key(),
            &canonical,
        )
        .map_err(|e| anyhow::anyhow!("sign MemberJoined fixture: {e:?}"))?;
        let event = NamedGroupMetadataEvent::MemberJoined {
            group_id: group_id.to_string(),
            stable_group_id: Some(group_id.to_string()),
            member_agent_id: member_hex.clone(),
            member_public_key_b64: member_public_key_b64.clone(),
            role,
            display_name: None,
            inviter_agent_id: inviter_agent_id.to_string(),
            invite_secret: invite_secret.to_string(),
            ts_ms,
            treekem_key_package_b64: None,
            recovery_authority_agent_id: None,
            recovery_authority_public_key_b64: None,
            recovery_authority_signature_b64: None,
            recovery_authority_commit: None,
            signature_b64: BASE64.encode(signature.as_bytes()),
        };
        Ok((member_id, member_hex, member_public_key_b64, event))
    }

    async fn group_counters_for_test(
        state: &Arc<AppState>,
        group_id: &str,
    ) -> x0x::groups::GroupCounters {
        let groups = state.named_groups.read().await;
        let empty_topics = HashSet::new();
        state
            .groups_diagnostics
            .snapshot(&groups, &empty_topics, &empty_topics)
            .groups
            .into_iter()
            .find(|row| row.group_id == group_id)
            .map(|row| row.counters)
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn member_joined_forged_role_and_unknown_secret_rejected_single_app_state() -> Result<()>
    {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "61".repeat(32);
        let inviter = state.agent.agent_id();
        let inviter_hex = hex::encode(inviter.as_bytes());
        let now_ms = now_millis_u64();
        let invite_secret = "single-app-state-member-joined-invite".to_string();
        let mut info = x0x::groups::GroupInfo::with_policy(
            "single-app-state MemberJoined rejection".to_string(),
            String::new(),
            inviter,
            group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        info.record_issued_invite(
            invite_secret.clone(),
            now_ms / 1_000,
            0,
            x0x::groups::GroupRole::Member,
        );
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info);
        save_named_groups(&state).await;

        let forger = x0x::identity::AgentKeypair::generate()?;
        let (forger_id, forger_hex, forger_public_key_b64, forged_admin) =
            signed_member_joined_event_for_test(
                &forger,
                &group_id,
                &inviter_hex,
                &invite_secret,
                x0x::groups::GroupRole::Admin,
            )?;
        let should_exit =
            apply_named_group_metadata_event_inner(&state, forged_admin, forger_id, true, true)
                .await;
        assert!(!should_exit);
        let counters = group_counters_for_test(&state, &group_id).await;
        assert_eq!(
            counters.member_joined_events_rejected_non_member_role, 1,
            "forged admin MemberJoined must be counted as a role-policy rejection"
        );

        let (_, _, _, forged_unknown_secret) = signed_member_joined_event_for_test(
            &forger,
            &group_id,
            &inviter_hex,
            &"00".repeat(32),
            x0x::groups::GroupRole::Member,
        )?;
        let should_exit = apply_named_group_metadata_event_inner(
            &state,
            forged_unknown_secret,
            forger_id,
            true,
            true,
        )
        .await;
        assert!(!should_exit);
        let counters = group_counters_for_test(&state, &group_id).await;
        assert_eq!(
            counters.member_joined_events_rejected_invite_secret_unknown, 1,
            "unknown invite-secret MemberJoined must be counted as an invite-policy rejection"
        );
        assert_eq!(
            counters.member_joined_events_applied, 0,
            "forged MemberJoined events must not apply"
        );

        let groups = state.named_groups.read().await;
        let live = groups.get(&group_id).expect("group retained");
        assert!(
            !live.has_active_member(&forger_hex),
            "forged MemberJoined must not admit the sender"
        );
        drop(groups);
        let persisted = tokio::fs::read_to_string(&state.named_groups_path).await?;
        assert!(
            !persisted.contains(&forger_hex),
            "forged member id must not be persisted after rejection"
        );
        assert!(
            !persisted.contains(&forger_public_key_b64),
            "forged member public key / protected material must not be persisted after rejection"
        );
        Ok(())
    }

    async fn assert_member_joined_treekem_did_not_install(
        fixture: &MemberJoinedTreeKemFixture,
    ) -> Result<()> {
        let guard = fixture.group.lock().await;
        assert_eq!(
            guard.epoch(),
            fixture.initial_epoch,
            "rejected MemberJoined must roll back in-memory TreeKEM epoch"
        );
        assert_eq!(
            guard.member_count(),
            1,
            "rejected MemberJoined must not leave an added TreeKEM leaf"
        );
        drop(guard);
        assert!(
            !tokio::fs::try_exists(treekem_snapshot_path(
                &fixture.state.treekem_dir,
                &fixture.group_id,
            ))
            .await?,
            "rejected MemberJoined must not persist TreeKEM snapshot material"
        );
        let groups = fixture.state.named_groups.read().await;
        let live = groups
            .get(&fixture.group_id)
            .expect("live group record retained");
        assert!(
            !live.has_active_member(&fixture.member_hex),
            "rejected MemberJoined must not store roster/key-state advance"
        );
        Ok(())
    }

    #[tokio::test]
    async fn treekem_welcome_lost_race_does_not_install_tree_state() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id_storage = "51".repeat(32);
        let group_id = group_id_storage.as_str();
        let group_id_bytes = hex::decode(group_id)?;
        let authority = AgentId([0x51; 32]);
        let authority_hex = hex::encode(authority.as_bytes());
        let mut authority_group =
            x0x::mls::TreeKemMlsGroup::create(group_id_bytes.clone(), authority, &[0x51; 32])?;
        let local_seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let prepared =
            x0x::mls::TreeKemMlsGroup::prepare_member(state.agent.agent_id(), &local_seed)?;
        let add =
            authority_group.add_member(state.agent.agent_id(), prepared.key_package_bytes())?;
        let joined = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &add.welcome)?;
        let epoch = joined.epoch();
        let info = treekem_metadata_group_info(authority, group_id, group_id);
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info.clone());
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let mut next = info;
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.add_member(
            local_hex,
            x0x::groups::GroupRole::Member,
            Some(authority_hex),
            None,
        );
        next.secret_epoch = epoch;
        next.security_binding = Some(format!("treekem:epoch={epoch}"));
        next.recompute_state_hash();

        let _guard = force_post_crypto_withdrawn_ids(&[group_id]);
        let result = install_joined_treekem_group_after_crypto_recheck(
            state.as_ref(),
            group_id,
            next,
            joined,
            "test_treekem_welcome_lost_race",
        )
        .await;

        assert!(
            result.is_err(),
            "withdrawn recheck must reject welcome install"
        );
        assert!(
            !state.treekem_groups.read().await.contains_key(group_id),
            "welcome must not install in-memory TreeKEM state"
        );
        assert!(
            !tokio::fs::try_exists(treekem_snapshot_path(&state.treekem_dir, group_id)).await?,
            "welcome must not persist TreeKEM snapshot material"
        );
        let groups = state.named_groups.read().await;
        assert!(groups.get(group_id).is_some_and(|info| info.withdrawn));
        Ok(())
    }

    #[tokio::test]
    async fn treekem_atomic_persist_lost_race_withdrawn_repairs_named_groups() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "56".repeat(32);
        let stable_group_id = "57".repeat(32);
        let group_id_bytes = hex::decode(&group_id)?;
        let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let group =
            x0x::mls::TreeKemMlsGroup::create(group_id_bytes, state.agent.agent_id(), &seed)?;
        let epoch = group.epoch();
        let mut current =
            treekem_metadata_group_info(state.agent.agent_id(), &group_id, &stable_group_id);
        current.secret_epoch = epoch;
        current.security_binding = Some(format!("treekem:epoch={epoch}"));
        current.shared_secret = Some(vec![9; 32]);
        current.recompute_state_hash();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), current.clone());
        save_named_groups(&state).await;

        let added_member = "58".repeat(32);
        let mut next = current;
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.add_member(
            added_member.clone(),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(state.agent.agent_id().as_bytes())),
            None,
        );
        next.recompute_state_hash();

        let _guard = force_atomic_persist_post_json_withdrawn_ids(&[&stable_group_id]);
        let result = install_joined_treekem_group_after_crypto_recheck(
            state.as_ref(),
            &group_id,
            next,
            group,
            "test_treekem_atomic_persist_lost_race",
        )
        .await;

        assert!(
            result.is_err(),
            "late withdrawn recheck must reject durable TreeKEM install"
        );
        assert!(
            !state.treekem_groups.read().await.contains_key(&group_id),
            "rejected install must not leave in-memory TreeKEM state"
        );
        assert!(
            !tokio::fs::try_exists(treekem_snapshot_path(&state.treekem_dir, &group_id)).await?,
            "late withdrawal must wipe snapshot material"
        );
        assert!(
            !tokio::fs::try_exists(treekem_journal_path(&state.treekem_dir, &group_id)).await?,
            "late withdrawal must wipe journal material"
        );
        let durable_groups = load_named_groups(&state.named_groups_path).await?;
        let durable = durable_groups
            .get(&group_id)
            .expect("withdrawn group tombstone remains durable");
        assert!(
            durable.withdrawn,
            "durable named_groups.json must retain withdrawal terminality"
        );
        assert_eq!(
            durable.shared_secret, None,
            "durable withdrawn tombstone must not retain key material"
        );
        assert!(
            !durable.has_active_member(&added_member),
            "durable withdrawn tombstone must not contain the stale TreeKEM roster advance"
        );
        let groups = state.named_groups.read().await;
        let in_memory = groups
            .get(&group_id)
            .expect("withdrawn group tombstone remains in memory");
        assert!(in_memory.withdrawn);
        assert!(!in_memory.has_active_member(&added_member));
        Ok(())
    }

    #[tokio::test]
    async fn treekem_final_install_lock_rechecks_withdrawal_before_insert() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "59".repeat(32);
        let stable_group_id = "5a".repeat(32);
        let group_id_bytes = hex::decode(&group_id)?;
        let seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let group =
            x0x::mls::TreeKemMlsGroup::create(group_id_bytes, state.agent.agent_id(), &seed)?;
        let epoch = group.epoch();
        let mut info =
            treekem_metadata_group_info(state.agent.agent_id(), &group_id, &stable_group_id);
        info.secret_epoch = epoch;
        info.security_binding = Some(format!("treekem:epoch={epoch}"));
        info.recompute_state_hash();

        let map_guard = state.treekem_groups.write().await;
        let (notify, _notify_guard) = notify_before_treekem_final_install_map_write(&group_id);
        let state_for_install = Arc::clone(&state);
        let group_id_for_install = group_id.clone();
        let info_for_install = info.clone();
        let install = tokio::spawn(async move {
            install_joined_treekem_group_after_crypto_recheck(
                state_for_install.as_ref(),
                &group_id_for_install,
                info_for_install,
                group,
                "test_treekem_final_install_lock_recheck",
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(5), notify.notified())
            .await
            .context("install did not reach the final in-memory map write")?;
        {
            let mut groups = state.named_groups.write().await;
            let mut withdrawn = info.clone();
            withdrawn.withdrawn = true;
            clear_group_info_key_material(&mut withdrawn);
            groups.insert(group_id.clone(), withdrawn);
        }
        drop(map_guard);

        let result = install.await.context("install task panicked")?;
        assert!(
            result.is_err(),
            "withdrawal observed under the TreeKEM map lock must reject final install"
        );
        assert!(
            !state.treekem_groups.read().await.contains_key(&group_id),
            "rejected final install must not leave resident TreeKEM key material"
        );
        assert!(
            !tokio::fs::try_exists(treekem_snapshot_path(&state.treekem_dir, &group_id)).await?,
            "rejected final install must wipe the just-persisted TreeKEM snapshot"
        );
        assert!(
            !tokio::fs::try_exists(treekem_journal_path(&state.treekem_dir, &group_id)).await?,
            "rejected final install must wipe the just-persisted TreeKEM journal"
        );
        let durable_groups = load_named_groups(&state.named_groups_path).await?;
        assert!(
            durable_groups
                .get(&group_id)
                .is_some_and(|info| info.withdrawn),
            "final check should leave the withdrawn tombstone durable"
        );
        Ok(())
    }

    #[tokio::test]
    async fn treekem_commit_lost_race_rolls_back_in_memory_tree_state() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id_storage = "52".repeat(32);
        let group_id = group_id_storage.as_str();
        let group_id_bytes = hex::decode(group_id)?;
        let authority = AgentId([0x54; 32]);
        let authority_hex = hex::encode(authority.as_bytes());
        let mut author_group =
            x0x::mls::TreeKemMlsGroup::create(group_id_bytes.clone(), authority, &[0x54; 32])?;
        let local_seed = agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let local_prepared =
            x0x::mls::TreeKemMlsGroup::prepare_member(state.agent.agent_id(), &local_seed)?;
        let local_add =
            author_group.add_member(state.agent.agent_id(), local_prepared.key_package_bytes())?;
        let local_group =
            x0x::mls::TreeKemMlsGroup::join_from_welcome(local_prepared, &local_add.welcome)?;
        let initial_epoch = local_group.epoch();
        let pre_commit_snapshot = local_group.to_snapshot_bytes()?;
        let pre_commit_group = x0x::mls::TreeKemMlsGroup::restore(
            &pre_commit_snapshot,
            state.agent.agent_id(),
            &local_seed,
        )?;
        let member = AgentId([0x53; 32]);
        let member_hex = hex::encode(member.as_bytes());
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member, &[0x53; 32])?;
        let add = author_group.add_member(member, prepared.key_package_bytes())?;
        let expected_epoch = author_group.epoch();
        let mut info = treekem_metadata_group_info(authority, group_id, group_id);
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        info.add_member(
            local_hex,
            x0x::groups::GroupRole::Member,
            Some(authority_hex.clone()),
            None,
        );
        info.secret_epoch = initial_epoch;
        info.security_binding = Some(format!("treekem:epoch={initial_epoch}"));
        info.recompute_state_hash();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info.clone());
        let group = Arc::new(Mutex::new(pre_commit_group));
        state
            .treekem_groups
            .write()
            .await
            .insert(group_id.to_string(), Arc::clone(&group));
        let mut next = info;
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.add_member(
            member_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(authority_hex),
            None,
        );
        next.secret_epoch = expected_epoch;
        next.security_binding = Some(format!("treekem:epoch={expected_epoch}"));
        next.recompute_state_hash();

        let _guard = force_post_crypto_withdrawn_ids(&[group_id]);
        let result = process_treekem_commit_after_crypto_recheck(
            state.as_ref(),
            group_id,
            &next,
            Arc::clone(&group),
            &add.commit,
            expected_epoch,
            "test_treekem_commit_lost_race",
        )
        .await;

        assert!(
            result.is_err(),
            "withdrawn recheck must reject commit install"
        );
        assert_eq!(
            group.lock().await.epoch(),
            initial_epoch,
            "rejected commit must roll back in-memory TreeKEM epoch"
        );
        assert!(
            !tokio::fs::try_exists(treekem_snapshot_path(&state.treekem_dir, group_id)).await?,
            "rejected commit must not persist TreeKEM snapshot material"
        );
        let groups = state.named_groups.read().await;
        let stored = groups.get(group_id).expect("withdrawn tombstone retained");
        assert!(stored.withdrawn);
        assert!(
            !stored.has_active_member(&member_hex),
            "rejected commit must not store roster/key-state advance"
        );
        Ok(())
    }

    #[tokio::test]
    async fn member_joined_treekem_lost_race_rolls_back_in_memory_tree_state() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0x53, 0x53).await?;
        let _guard = force_post_crypto_withdrawn_ids(&[&fixture.stable_group_id]);

        let should_exit = apply_named_group_metadata_event_inner(
            &fixture.state,
            without_recovery_attestation(fixture.event.clone()),
            fixture.member_id,
            true,
            true,
        )
        .await;

        assert!(!should_exit);
        assert_member_joined_treekem_did_not_install(&fixture).await?;
        let groups = fixture.state.named_groups.read().await;
        assert!(
            groups
                .get(&fixture.group_id)
                .is_some_and(|info| info.withdrawn),
            "lost-race withdrawal should win"
        );
        Ok(())
    }

    #[tokio::test]
    async fn member_joined_treekem_withdrawn_same_stable_alias_rolls_back() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0x54, 0x55).await?;
        let mut withdrawn_alias = treekem_metadata_group_info(
            fixture.state.agent.agent_id(),
            &fixture.stable_group_id,
            &fixture.stable_group_id,
        );
        withdrawn_alias.withdrawn = true;
        clear_group_info_key_material(&mut withdrawn_alias);
        fixture
            .state
            .named_groups
            .write()
            .await
            .insert(fixture.stable_group_id.clone(), withdrawn_alias);

        let should_exit = apply_named_group_metadata_event_inner(
            &fixture.state,
            without_recovery_attestation(fixture.event.clone()),
            fixture.member_id,
            true,
            true,
        )
        .await;

        assert!(!should_exit);
        assert_member_joined_treekem_did_not_install(&fixture).await?;
        let groups = fixture.state.named_groups.read().await;
        assert!(
            groups
                .get(&fixture.stable_group_id)
                .is_some_and(|info| info.withdrawn),
            "withdrawn same-stable alias should remain terminal"
        );
        Ok(())
    }

    async fn install_treekem_endpoint_group(
        state: &Arc<AppState>,
        group_id: &str,
        stable_group_id: &str,
    ) -> Result<()> {
        install_secure_endpoint_group(
            state,
            group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::TreeKem,
        )
        .await;
        let group = x0x::mls::TreeKemMlsGroup::create(
            group_id.as_bytes().to_vec(),
            state.agent.agent_id(),
            &[3; 32],
        )?;
        state
            .treekem_groups
            .write()
            .await
            .insert(group_id.to_string(), Arc::new(Mutex::new(group)));
        Ok(())
    }

    #[tokio::test]
    async fn secure_encrypt_endpoint_treekem_lost_race_drops_ciphertext() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = &"ab".repeat(16);
        let stable_group_id = "treekem-encrypt-stable";
        install_treekem_endpoint_group(&state, group_id, stable_group_id).await?;

        let _guard = force_post_crypto_withdrawn_ids(&[stable_group_id]);
        let (status, body) = secure_group_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureEncryptRequest {
                payload_b64: BASE64.encode(b"secret"),
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["ciphertext_b64"]);
        Ok(())
    }

    #[tokio::test]
    async fn secure_decrypt_endpoint_treekem_lost_race_drops_plaintext() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = &"cd".repeat(16);
        let stable_group_id = "treekem-decrypt-stable";
        install_treekem_endpoint_group(&state, group_id, stable_group_id).await?;
        let (encrypt_status, encrypted) = secure_group_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureEncryptRequest {
                payload_b64: BASE64.encode(b"secret"),
            }),
        )
        .await;
        assert_eq!(encrypt_status, StatusCode::OK);

        let _guard = force_post_crypto_withdrawn_ids(&[stable_group_id]);
        let (status, body) = secure_group_decrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureDecryptRequest {
                ciphertext_b64: encrypted.0["ciphertext_b64"]
                    .as_str()
                    .expect("ciphertext present")
                    .to_string(),
                nonce_b64: String::new(),
                secret_epoch: 0,
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["payload_b64"]);
        Ok(())
    }

    async fn install_legacy_mls_endpoint_group(
        state: &Arc<AppState>,
        group_id: &str,
    ) -> Result<()> {
        let group = x0x::mls::MlsGroup::new(hex::decode(group_id)?, state.agent.agent_id()).await?;
        state
            .mls_groups
            .write()
            .await
            .insert(group_id.to_string(), group);
        install_secure_endpoint_group(state, group_id, group_id, x0x::mls::SecureGroupPlane::Gss)
            .await;
        Ok(())
    }

    #[tokio::test]
    async fn legacy_mls_encrypt_lost_race_drops_ciphertext() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = &"ef".repeat(16);
        install_legacy_mls_endpoint_group(&state, group_id).await?;

        let _guard = force_post_crypto_withdrawn_ids(&[group_id]);
        let (status, body) = mls_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(MlsEncryptRequest {
                payload: BASE64.encode(b"secret"),
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["ciphertext"]);
        Ok(())
    }

    #[tokio::test]
    async fn legacy_mls_decrypt_lost_race_drops_plaintext() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = &"01".repeat(16);
        install_legacy_mls_endpoint_group(&state, group_id).await?;
        let (encrypt_status, encrypted) = mls_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(MlsEncryptRequest {
                payload: BASE64.encode(b"secret"),
            }),
        )
        .await;
        assert_eq!(encrypt_status, StatusCode::OK);

        let _guard = force_post_crypto_withdrawn_ids(&[group_id]);
        let (status, body) = mls_decrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(MlsDecryptRequest {
                ciphertext: encrypted.0["ciphertext"]
                    .as_str()
                    .expect("ciphertext present")
                    .to_string(),
                epoch: encrypted.0["epoch"].as_u64().expect("epoch present"),
            }),
        )
        .await;

        assert_lost_race_conflict_drops_fields(status, &body.0, &["payload"]);
        Ok(())
    }

    #[tokio::test]
    async fn secure_encrypt_endpoint_withdrawn_stable_stub_does_not_poison_live_keyed_alias(
    ) -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "live-keyed-local";
        let stable_group_id = "stale-withdrawn-stable";
        install_secure_endpoint_group(
            &state,
            group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        )
        .await;

        let mut stale_stub = secure_endpoint_group_for_agent(
            state.agent.agent_id(),
            stable_group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        );
        stale_stub.shared_secret = None;
        stale_stub.members_v2.clear();
        stale_stub.withdrawn = true;
        state
            .named_groups
            .write()
            .await
            .insert(stable_group_id.to_string(), stale_stub);

        let (status, body) = secure_group_encrypt(
            State(Arc::clone(&state)),
            Path(group_id.to_string()),
            Json(SecureEncryptRequest {
                payload_b64: BASE64.encode(b"secret"),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.0.get("ciphertext_b64").is_some());
        Ok(())
    }

    #[tokio::test]
    async fn open_envelope_withdrawn_stable_stub_does_not_poison_live_keyed_alias() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let stable_group_id = "open-envelope-stale-stable";
        let live_alias = "open-envelope-live-alias";
        install_secure_endpoint_group(
            &state,
            live_alias,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        )
        .await;

        let mut stale_stub = secure_endpoint_group_for_agent(
            state.agent.agent_id(),
            stable_group_id,
            stable_group_id,
            x0x::mls::SecureGroupPlane::Gss,
        );
        stale_stub.shared_secret = None;
        stale_stub.members_v2.clear();
        stale_stub.withdrawn = true;
        state
            .named_groups
            .write()
            .await
            .insert(stable_group_id.to_string(), stale_stub);

        let recipient = hex::encode(state.agent.agent_id().as_bytes());
        let secret = [7_u8; 32];
        let aad = secure_share_aad(stable_group_id, &recipient, 7);
        let (kem_ct, aead_nonce, aead_ct) =
            x0x::groups::kem_envelope::seal_group_secret_to_recipient(
                &state.agent_kem_keypair.public_bytes,
                &aad,
                &secret,
            )?;

        let (status, body) = secure_open_envelope_adversarial(
            State(Arc::clone(&state)),
            Json(OpenEnvelopeRequest {
                group_id: stable_group_id.to_string(),
                recipient,
                secret_epoch: 7,
                kem_ciphertext_b64: BASE64.encode(&kem_ct),
                aead_nonce_b64: BASE64.encode(aead_nonce),
                aead_ciphertext_b64: BASE64.encode(&aead_ct),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.0.get("secret_b64").is_some());
        Ok(())
    }

    #[test]
    fn same_stable_group_aliases_include_all_local_records() {
        let stable_id = "stable-card-id";
        let mut groups = HashMap::new();
        for (key, mls_id) in [
            ("local-mls-id", "local-mls-id"),
            (stable_id, "local-mls-id"),
            ("legacy-alias", "legacy-mls-id"),
        ] {
            let mut info = x0x::groups::GroupInfo::with_policy(
                key.to_string(),
                String::new(),
                AgentId([2; 32]),
                mls_id.to_string(),
                x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
            );
            info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
                stable_id.to_string(),
                "02".repeat(32),
                info.created_at,
                String::new(),
            ));
            info.shared_secret = Some(vec![7; 32]);
            groups.insert(key.to_string(), info);
        }
        let mut other = x0x::groups::GroupInfo::with_policy(
            "other".to_string(),
            String::new(),
            AgentId([3; 32]),
            "other-mls".to_string(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        other.shared_secret = Some(vec![8; 32]);
        groups.insert("other".to_string(), other);

        let aliases = collect_same_stable_group_aliases(&groups, "local-mls-id", Some(stable_id));
        for expected in ["local-mls-id", stable_id, "legacy-alias", "legacy-mls-id"] {
            assert!(aliases.contains(expected), "missing alias {expected}");
        }
        assert!(!aliases.contains("other"));

        for alias in &aliases {
            if let Some(info) = groups.get_mut(alias) {
                info.withdrawn = true;
                clear_group_info_key_material(info);
            }
        }
        for key in ["local-mls-id", stable_id, "legacy-alias"] {
            let info = groups.get(key).expect("same-stable record retained");
            assert!(info.withdrawn, "alias {key} not marked withdrawn");
            assert_eq!(info.shared_secret, None, "alias {key} kept key material");
        }
        let other = groups.get("other").expect("other group retained");
        assert!(!other.withdrawn);
        assert!(other.shared_secret.is_some());
    }

    #[test]
    fn withdrawn_card_non_admin_cannot_terminally_mark_keyed_live_group() {
        let creator = x0x::identity::AgentKeypair::generate().expect("creator keypair");
        let outsider = x0x::identity::AgentKeypair::generate().expect("outsider keypair");
        let mut info = x0x::groups::GroupInfo::with_policy(
            "live".to_string(),
            String::new(),
            creator.agent_id(),
            "aa".repeat(16),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        info.state_revision = 1;
        info.updated_at = 1_000;
        info.shared_secret = Some(vec![9; 32]);

        let mut card = sample_group_card(info.stable_group_id(), 2, 2_000);
        card.withdrawn = true;
        card.authority_agent_id = hex::encode(outsider.agent_id().as_bytes());

        assert!(!withdrawn_card_can_terminally_mark_local_group(
            &info, &card, true,
        ));
    }

    #[tokio::test]
    async fn withdrawn_card_protected_crypto_probe_fails_closed_on_io_error() -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        tokio::fs::remove_dir_all(&state.treekem_dir).await?;
        tokio::fs::write(&state.treekem_dir, b"not a directory").await?;

        let creator = x0x::identity::AgentKeypair::generate()?;
        let mut info = x0x::groups::GroupInfo::with_policy(
            "keyless stub".to_string(),
            String::new(),
            creator.agent_id(),
            "aa".repeat(16),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        info.shared_secret = None;

        let mut aliases = HashSet::new();
        aliases.insert(info.stable_group_id().to_string());

        assert!(
            local_group_has_protected_crypto_material(&state, &info, &aliases).await,
            "TreeKEM persistence probe errors must fail closed as protected"
        );
        Ok(())
    }

    #[test]
    fn withdrawn_card_admin_cannot_terminally_mark_keyed_live_group_without_signed_commit() {
        let creator = x0x::identity::AgentKeypair::generate().expect("creator keypair");
        let admin = x0x::identity::AgentKeypair::generate().expect("admin keypair");
        let creator_hex = hex::encode(creator.agent_id().as_bytes());
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let mut info = x0x::groups::GroupInfo::with_policy(
            "live".to_string(),
            String::new(),
            creator.agent_id(),
            "aa".repeat(16),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        info.add_member(
            admin_hex.clone(),
            x0x::groups::GroupRole::Admin,
            Some(creator_hex),
            None,
        );
        info.state_revision = 1;
        info.updated_at = 1_000;
        info.shared_secret = Some(vec![9; 32]);

        let mut card = sample_group_card(info.stable_group_id(), 2, 2_000);
        card.withdrawn = true;
        card.authority_agent_id = admin_hex;

        assert!(!withdrawn_card_can_terminally_mark_local_group(
            &info, &card, true,
        ));
        assert!(!info.withdrawn);
        assert_eq!(info.shared_secret, Some(vec![9; 32]));
    }

    #[test]
    fn withdrawn_card_can_supersede_keyless_discovery_stub_without_roster_admin() {
        let creator = x0x::identity::AgentKeypair::generate().expect("creator keypair");
        let outsider = x0x::identity::AgentKeypair::generate().expect("outsider keypair");
        let mut stub = x0x::groups::GroupInfo::with_policy(
            "stub".to_string(),
            String::new(),
            creator.agent_id(),
            "aa".repeat(16),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        stub.state_revision = 1;
        stub.updated_at = 1_000;
        stub.shared_secret = None;
        stub.members_v2.clear();

        let mut card = sample_group_card(stub.stable_group_id(), 2, 2_000);
        card.withdrawn = true;
        card.authority_agent_id = hex::encode(outsider.agent_id().as_bytes());

        assert!(withdrawn_card_can_terminally_mark_local_group(
            &stub, &card, false,
        ));
        assert!(apply_withdrawn_group_card_to_group_info(&mut stub, &card));
        assert!(stub.withdrawn);
        assert_eq!(stub.shared_secret, None);
    }

    #[tokio::test]
    async fn withdrawn_card_import_does_not_wipe_same_stable_keyed_alias_via_keyless_stub(
    ) -> Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let stable_group_id = "same-stable-card";
        let keyed_alias = "same-stable-live-alias";
        let creator = x0x::identity::AgentKeypair::generate()?;
        let creator_hex = hex::encode(creator.agent_id().as_bytes());

        let mut keyless_stub = x0x::groups::GroupInfo::with_policy(
            "stub".to_string(),
            String::new(),
            creator.agent_id(),
            stable_group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        keyless_stub.state_revision = 1;
        keyless_stub.updated_at = 1_000;
        keyless_stub.shared_secret = None;
        keyless_stub.members_v2.clear();

        let mut live_keyed = x0x::groups::GroupInfo::with_policy(
            "live".to_string(),
            String::new(),
            creator.agent_id(),
            keyed_alias.to_string(),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        live_keyed.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            stable_group_id.to_string(),
            creator_hex,
            live_keyed.created_at,
            String::new(),
        ));
        live_keyed.state_revision = 1;
        live_keyed.updated_at = 1_000;
        live_keyed.shared_secret = Some(vec![9; 32]);

        {
            let mut groups = state.named_groups.write().await;
            groups.insert(stable_group_id.to_string(), keyless_stub);
            groups.insert(keyed_alias.to_string(), live_keyed);
        }

        let mut card = sample_group_card(stable_group_id, 2, 2_000);
        card.withdrawn = true;
        card.sign(&creator)?;

        let response = import_group_card(State(Arc::clone(&state)), Json(card))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let groups = state.named_groups.read().await;
        let live = groups.get(keyed_alias).expect("live alias retained");
        assert!(!live.withdrawn);
        assert_eq!(live.shared_secret, Some(vec![9; 32]));
        let stub = groups.get(stable_group_id).expect("keyless stub retained");
        assert!(!stub.withdrawn);
        Ok(())
    }

    #[tokio::test]
    async fn withdrawn_card_import_does_not_wipe_keyed_alias_via_stale_withdrawn_stub() -> Result<()>
    {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let stable_group_id = "stale-withdrawn-card";
        let keyed_alias = "stale-withdrawn-live-alias";
        let creator = x0x::identity::AgentKeypair::generate()?;
        let creator_hex = hex::encode(creator.agent_id().as_bytes());

        let mut stale_withdrawn_stub = x0x::groups::GroupInfo::with_policy(
            "stub".to_string(),
            String::new(),
            creator.agent_id(),
            stable_group_id.to_string(),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        stale_withdrawn_stub.state_revision = 1;
        stale_withdrawn_stub.updated_at = 1_000;
        stale_withdrawn_stub.shared_secret = None;
        stale_withdrawn_stub.members_v2.clear();
        stale_withdrawn_stub.withdrawn = true;

        let mut live_keyed = x0x::groups::GroupInfo::with_policy(
            "live".to_string(),
            String::new(),
            creator.agent_id(),
            keyed_alias.to_string(),
            x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
        );
        live_keyed.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            stable_group_id.to_string(),
            creator_hex,
            live_keyed.created_at,
            String::new(),
        ));
        live_keyed.state_revision = 1;
        live_keyed.updated_at = 1_000;
        live_keyed.shared_secret = Some(vec![9; 32]);

        {
            let mut groups = state.named_groups.write().await;
            groups.insert(stable_group_id.to_string(), stale_withdrawn_stub);
            groups.insert(keyed_alias.to_string(), live_keyed);
        }

        let mut card = sample_group_card(stable_group_id, 2, 2_000);
        card.withdrawn = true;
        card.sign(&creator)?;

        let response = import_group_card(State(Arc::clone(&state)), Json(card))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let groups = state.named_groups.read().await;
        let live = groups.get(keyed_alias).expect("live alias retained");
        assert!(!live.withdrawn);
        assert_eq!(live.shared_secret, Some(vec![9; 32]));
        let stub = groups
            .get(stable_group_id)
            .expect("stale withdrawn stub retained");
        assert!(stub.withdrawn);
        Ok(())
    }

    #[tokio::test]
    async fn malformed_named_groups_file_is_rejected_without_replacing_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("named_groups.json");
        let malformed_json = "{\"group\":";
        tokio::fs::write(&path, malformed_json).await?;

        let result = load_named_groups(&path).await;

        assert!(result.is_err());
        assert_eq!(tokio::fs::read_to_string(&path).await?, malformed_json);
        Ok(())
    }

    #[tokio::test]
    async fn named_groups_json_write_replaces_file_without_temp_leftover() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("named_groups.json");

        write_named_groups_json_atomic(&path, "{\"old\":true}").await?;
        write_named_groups_json_atomic(&path, "{\"new\":true}").await?;

        assert_eq!(tokio::fs::read_to_string(&path).await?, "{\"new\":true}");

        let mut entries = tokio::fs::read_dir(dir.path()).await?;
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            names.push(entry.file_name());
        }
        assert_eq!(names, vec![std::ffi::OsString::from("named_groups.json")]);
        Ok(())
    }

    #[test]
    fn treekem_snapshot_drop_file_name_rejects_path_traversal_ids() {
        assert_eq!(
            treekem_snapshot_file_name_for_drop(&"ab".repeat(16)),
            Some(format!("{}.snap", "ab".repeat(16)))
        );
        assert_eq!(
            treekem_journal_file_name_for_drop(&"ab".repeat(16)),
            Some(format!("{}.journal", "ab".repeat(16)))
        );
        assert_eq!(
            treekem_snapshot_file_name_for_drop("group-1_ok").as_deref(),
            Some("group-1_ok.snap")
        );
        assert_eq!(
            treekem_journal_file_name_for_drop("group-1_ok").as_deref(),
            Some("group-1_ok.journal")
        );

        for unsafe_id in ["", "../outside", "a/b", "/absolute", "a\\b", "ümlaut"] {
            assert_eq!(
                treekem_snapshot_file_name_for_drop(unsafe_id),
                None,
                "unsafe id should not become a snapshot filename: {unsafe_id:?}"
            );
            assert_eq!(
                treekem_journal_file_name_for_drop(unsafe_id),
                None,
                "unsafe id should not become a journal filename: {unsafe_id:?}"
            );
        }
    }

    #[tokio::test]
    async fn treekem_persistence_drop_removes_snapshot_and_journal() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let group_id = "ab".repeat(16);
        let snapshot_path = treekem_snapshot_path(dir.path(), &group_id);
        let journal_path = treekem_journal_path(dir.path(), &group_id);
        tokio::fs::write(&snapshot_path, b"snapshot").await?;
        tokio::fs::write(&journal_path, b"journal").await?;

        remove_treekem_persistence_for_group_id_in_dir(dir.path(), &group_id, "test").await;

        assert!(!snapshot_path.exists(), "snapshot material must be wiped");
        assert!(!journal_path.exists(), "journal material must be wiped");
        Ok(())
    }

    fn sample_treekem_group_info(group_id: &str, withdrawn: bool) -> x0x::groups::GroupInfo {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            AgentId([9; 32]),
            group_id.to_string(),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.state_revision = 1;
        info.state_hash = "state".to_string();
        info.security_binding = Some("treekem:epoch=1".to_string());
        info.withdrawn = withdrawn;
        info
    }

    fn sample_treekem_snapshot_envelope() -> Result<Vec<u8>> {
        let mut bytes = TREEKEM_DAEMON_SNAPSHOT_MAGIC.to_vec();
        bytes.extend(postcard::to_stdvec(&TreeKemSnapshotEnvelope {
            version: TREEKEM_DAEMON_SNAPSHOT_VERSION,
            state_revision: 1,
            state_hash: "state".to_string(),
            security_binding: Some("treekem:epoch=1".to_string()),
            snapshot: b"snapshot".to_vec(),
        })?);
        Ok(bytes)
    }

    #[test]
    fn treekem_snapshot_envelope_binding_detects_mismatch() {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            AgentId([9; 32]),
            "aa".repeat(16),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.state_revision = 7;
        info.state_hash = "hash-a".to_string();
        info.security_binding = Some("treekem:epoch=3".to_string());
        let envelope = TreeKemSnapshotEnvelope {
            version: TREEKEM_DAEMON_SNAPSHOT_VERSION,
            state_revision: info.state_revision,
            state_hash: info.state_hash.clone(),
            security_binding: info.security_binding.clone(),
            snapshot: b"snapshot".to_vec(),
        };
        assert!(treekem_snapshot_envelope_matches_info(&envelope, &info));

        info.state_hash = "hash-b".to_string();
        assert!(!treekem_snapshot_envelope_matches_info(&envelope, &info));
    }

    #[test]
    fn treekem_snapshot_envelope_rejects_withdrawn_group_info() -> Result<()> {
        let group_id = "ab".repeat(16);
        let info = sample_treekem_group_info(&group_id, true);
        let group = x0x::mls::TreeKemMlsGroup::create(
            group_id.as_bytes().to_vec(),
            AgentId([9; 32]),
            &[7; 32],
        )?;

        let err =
            encode_treekem_snapshot_envelope(&info, &group).expect_err("withdrawn group rejected");

        assert!(
            err.to_string().contains("withdrawn"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn treekem_journal_replay_writes_snapshot_and_named_groups() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let treekem_dir = dir.path().join("treekem");
        tokio::fs::create_dir_all(&treekem_dir).await?;
        let named_path = dir.path().join("named_groups.json");
        let snapshot_envelope = sample_treekem_snapshot_envelope()?;
        let group_id = "ab".repeat(16);
        let named_groups_json = serde_json::to_string_pretty(&HashMap::from([(
            group_id.clone(),
            sample_treekem_group_info(&group_id, false),
        )]))?;
        let journal = TreeKemNamedPersistJournal {
            version: TREEKEM_NAMED_JOURNAL_VERSION,
            group_id_hex: group_id,
            named_groups_json: named_groups_json.clone(),
            snapshot_envelope: snapshot_envelope.clone(),
        };
        let journal_path = treekem_journal_path(&treekem_dir, &journal.group_id_hex);
        x0x::storage::write_private_bytes(&journal_path, postcard::to_stdvec(&journal)?).await?;

        recover_treekem_named_journals(&named_path, &treekem_dir).await?;

        assert_eq!(
            tokio::fs::read_to_string(&named_path).await?,
            named_groups_json
        );
        assert_eq!(
            tokio::fs::read(treekem_snapshot_path(&treekem_dir, &journal.group_id_hex)).await?,
            snapshot_envelope
        );
        assert!(!journal_path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn treekem_journal_replay_preserves_durable_withdrawn_alias() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let treekem_dir = dir.path().join("treekem");
        tokio::fs::create_dir_all(&treekem_dir).await?;
        let named_path = dir.path().join("named_groups.json");
        let snapshot_envelope = sample_treekem_snapshot_envelope()?;
        let group_id = "ab".repeat(16);
        let alias_mls_id = "cd".repeat(16);

        let mut withdrawn_alias = sample_treekem_group_info(&alias_mls_id, true);
        withdrawn_alias.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            group_id.clone(),
            "02".repeat(32),
            withdrawn_alias.created_at,
            String::new(),
        ));
        let durable_named_groups_json = serde_json::to_string_pretty(&HashMap::from([(
            "withdrawn-alias".to_string(),
            withdrawn_alias,
        )]))?;
        tokio::fs::write(&named_path, &durable_named_groups_json).await?;

        let journal_named_groups_json = serde_json::to_string_pretty(&HashMap::from([(
            group_id.clone(),
            sample_treekem_group_info(&group_id, false),
        )]))?;
        let journal = TreeKemNamedPersistJournal {
            version: TREEKEM_NAMED_JOURNAL_VERSION,
            group_id_hex: group_id.clone(),
            named_groups_json: journal_named_groups_json,
            snapshot_envelope,
        };
        let snapshot_path = treekem_snapshot_path(&treekem_dir, &group_id);
        tokio::fs::write(&snapshot_path, b"stale-snapshot").await?;
        let journal_path = treekem_journal_path(&treekem_dir, &group_id);
        x0x::storage::write_private_bytes(&journal_path, postcard::to_stdvec(&journal)?).await?;

        recover_treekem_named_journals(&named_path, &treekem_dir).await?;

        assert_eq!(
            tokio::fs::read_to_string(&named_path).await?,
            durable_named_groups_json,
            "durable withdrawn named-groups file must not be replaced"
        );
        assert!(
            !snapshot_path.exists(),
            "durable withdrawal must wipe stale snapshot material"
        );
        assert!(
            !journal_path.exists(),
            "durable withdrawal must wipe stale journal material"
        );
        Ok(())
    }

    #[tokio::test]
    async fn treekem_journal_replay_discards_withdrawn_group_material() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let treekem_dir = dir.path().join("treekem");
        tokio::fs::create_dir_all(&treekem_dir).await?;
        let named_path = dir.path().join("named_groups.json");
        let snapshot_envelope = sample_treekem_snapshot_envelope()?;
        let group_id = "ab".repeat(16);
        let named_groups_json = serde_json::to_string_pretty(&HashMap::from([(
            group_id.clone(),
            sample_treekem_group_info(&group_id, true),
        )]))?;
        let journal = TreeKemNamedPersistJournal {
            version: TREEKEM_NAMED_JOURNAL_VERSION,
            group_id_hex: group_id.clone(),
            named_groups_json,
            snapshot_envelope,
        };
        let snapshot_path = treekem_snapshot_path(&treekem_dir, &group_id);
        tokio::fs::write(&snapshot_path, b"stale-snapshot").await?;
        let journal_path = treekem_journal_path(&treekem_dir, &group_id);
        x0x::storage::write_private_bytes(&journal_path, postcard::to_stdvec(&journal)?).await?;

        recover_treekem_named_journals(&named_path, &treekem_dir).await?;

        assert!(
            !named_path.exists(),
            "withdrawn journal must not replay named groups"
        );
        assert!(
            !snapshot_path.exists(),
            "withdrawn journal must wipe snapshot material"
        );
        assert!(
            !journal_path.exists(),
            "withdrawn journal must wipe journal material"
        );
        Ok(())
    }

    #[test]
    fn treekem_metadata_event_phase3_classifier_allows_group_delete() {
        let event = NamedGroupMetadataEvent::MemberRemoved {
            group_id: "aa".repeat(16),
            revision: 1,
            actor: "11".repeat(32),
            agent_id: "22".repeat(32),
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&event));

        let event = NamedGroupMetadataEvent::JoinRequestCreated {
            group_id: "aa".repeat(16),
            request_id: "req".to_string(),
            requester_agent_id: "22".repeat(32),
            message: None,
            ts: 1,
            requester_kem_public_key_b64: None,
            treekem_key_package_b64: Some("a2V5".to_string()),
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&event));

        let event = NamedGroupMetadataEvent::JoinRequestApproved {
            group_id: "aa".repeat(16),
            request_id: "req".to_string(),
            revision: 2,
            actor: "11".repeat(32),
            requester_agent_id: "22".repeat(32),
            treekem_commit_b64: Some("Y29tbWl0".to_string()),
            treekem_welcome_b64: Some("d2VsY29tZQ==".to_string()),
            welcome_ref: None,
            treekem_epoch: Some(1),
            treekem_key_package_hash: None,
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&event));

        let event = NamedGroupMetadataEvent::GroupDeleted {
            group_id: "aa".repeat(16),
            revision: 1,
            actor: "11".repeat(32),
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&event));

        let event = NamedGroupMetadataEvent::MemberRoleUpdated {
            group_id: "aa".repeat(16),
            revision: 1,
            actor: "11".repeat(32),
            agent_id: "22".repeat(32),
            role: x0x::groups::GroupRole::Admin,
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&event));

        let event = NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: "aa".repeat(16),
            revision: 1,
            actor: "11".repeat(32),
            name: Some("name".to_string()),
            description: Some(String::new()),
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&event));
    }

    #[test]
    fn treekem_self_leave_metadata_is_authorized_without_transport_commit() {
        let creator = AgentId([0x11; 32]);
        let creator_hex = hex::encode(creator.as_bytes());
        let member_hex = "22".repeat(32);
        let admin_hex = "33".repeat(32);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            creator,
            "aa".repeat(16),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.add_member(
            admin_hex.clone(),
            x0x::groups::GroupRole::Admin,
            Some(creator_hex.clone()),
            None,
        );
        let group_id = info.stable_group_id().to_string();

        let member_added_by_admin = NamedGroupMetadataEvent::MemberAdded {
            group_id: group_id.clone(),
            revision: 2,
            actor: admin_hex.clone(),
            agent_id: member_hex.clone(),
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: Some("dw==".to_string()),
            welcome_ref: None,
            treekem_epoch: Some(2),
            treekem_key_package_hash: None,
            member_joined_recovery: None,
            member_recovery_history: Vec::new(),
            commit: Some(fake_group_state_commit(&group_id, 2, &admin_hex)),
        };
        assert!(authorized_treekem_membership_event_for_queue(
            &info,
            &member_added_by_admin,
            &admin_hex
        ));
        assert!(!authorized_treekem_membership_event_for_queue(
            &info,
            &member_added_by_admin,
            &creator_hex
        ));

        let self_leave = NamedGroupMetadataEvent::MemberRemoved {
            group_id: group_id.clone(),
            revision: 3,
            actor: member_hex.clone(),
            agent_id: member_hex.clone(),
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit: Some(fake_group_state_commit(&group_id, 3, &member_hex)),
        };

        assert!(authorized_treekem_membership_event_for_queue(
            &info,
            &self_leave,
            &member_hex
        ));
        assert!(!authorized_treekem_membership_event_for_queue(
            &info,
            &self_leave,
            &creator_hex
        ));

        let admin_remove_without_treekem = NamedGroupMetadataEvent::MemberRemoved {
            group_id: group_id.clone(),
            revision: 4,
            actor: creator_hex.clone(),
            agent_id: member_hex.clone(),
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit: Some(fake_group_state_commit(&group_id, 4, &creator_hex)),
        };
        assert!(!authorized_treekem_membership_event_for_queue(
            &info,
            &admin_remove_without_treekem,
            &creator_hex
        ));

        let admin_remove_with_treekem = NamedGroupMetadataEvent::MemberRemoved {
            group_id: group_id.clone(),
            revision: 5,
            actor: admin_hex.clone(),
            agent_id: member_hex.clone(),
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_epoch: Some(2),
            commit: Some(fake_group_state_commit(&group_id, 5, &admin_hex)),
        };
        assert!(authorized_treekem_membership_event_for_queue(
            &info,
            &admin_remove_with_treekem,
            &admin_hex
        ));
        assert!(!authorized_treekem_membership_event_for_queue(
            &info,
            &admin_remove_with_treekem,
            &creator_hex
        ));

        let ban_owner_by_admin = NamedGroupMetadataEvent::MemberBanned {
            group_id: group_id.clone(),
            revision: 6,
            actor: admin_hex.clone(),
            agent_id: creator_hex.clone(),
            secret_epoch: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_epoch: Some(3),
            commit: Some(fake_group_state_commit(&group_id, 6, &admin_hex)),
        };
        assert!(authorized_treekem_membership_event_for_queue(
            &info,
            &ban_owner_by_admin,
            &admin_hex
        ));
        assert!(!authorized_treekem_membership_event_for_queue(
            &info,
            &ban_owner_by_admin,
            &creator_hex
        ));
    }

    #[test]
    fn withdrawn_treekem_group_never_queues_frontier_gap_events() {
        let creator = AgentId([0x11; 32]);
        let creator_hex = hex::encode(creator.as_bytes());
        let member_hex = "22".repeat(32);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            creator,
            "aa".repeat(16),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.withdrawn = true;
        info.state_revision = 1;
        info.roster_revision = 1;
        info.security_binding = Some("treekem:epoch=1".to_string());
        info.recompute_state_hash();
        let group_id = info.stable_group_id().to_string();
        let event = NamedGroupMetadataEvent::MemberAdded {
            group_id: group_id.clone(),
            revision: 3,
            actor: creator_hex.clone(),
            agent_id: member_hex,
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: Some("dw==".to_string()),
            welcome_ref: None,
            treekem_epoch: Some(3),
            treekem_key_package_hash: None,
            member_joined_recovery: None,
            member_recovery_history: Vec::new(),
            commit: Some(fake_group_state_commit(&group_id, 3, &creator_hex)),
        };

        assert_eq!(
            treekem_state_frontier_gap_reason(&info, &event, &creator_hex, Some(1)),
            None,
            "withdrawn groups must short-circuit before TreeKEM queue/catch-up"
        );
        assert!(!authorized_treekem_membership_event_for_queue(
            &info,
            &event,
            &creator_hex,
        ));
        assert!(!withdrawn_group_allows_metadata_event(&event));
    }

    #[test]
    fn treekem_leave_disposition_allows_local_pending_stub_cleanup() {
        let creator = AgentId([0x11; 32]);
        let member = AgentId([0x22; 32]);
        let creator_hex = hex::encode(creator.as_bytes());
        let member_hex = hex::encode(member.as_bytes());
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            creator,
            "aa".repeat(16),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;

        assert_eq!(
            treekem_leave_disposition(&info, &creator_hex),
            TreeKemLeaveDisposition::ActiveMember
        );
        assert_eq!(
            treekem_leave_disposition(&info, &member_hex),
            TreeKemLeaveDisposition::LocalOnlyDrop
        );

        info.add_member(
            member_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(creator_hex.clone()),
            None,
        );
        assert_eq!(
            treekem_leave_disposition(&info, &member_hex),
            TreeKemLeaveDisposition::ActiveMember
        );

        info.remove_member(&member_hex, Some(creator_hex));
        assert_eq!(
            treekem_leave_disposition(&info, &member_hex),
            TreeKemLeaveDisposition::LocalOnlyDrop
        );
    }

    #[test]
    fn treekem_invite_stub_matches_authority_base_hash() {
        let creator = AgentId([7; 32]);
        let group_id = "ab".repeat(32);
        let policy = x0x::groups::GroupPolicy::default();
        let mut authority = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            "desc".to_string(),
            creator,
            group_id.clone(),
            policy.clone(),
        );
        authority.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        authority.shared_secret = None;
        authority.secret_epoch = 1;
        authority.security_binding = Some("treekem:epoch=1".to_string());
        authority.recompute_state_hash();

        let mut invite = x0x::groups::invite::SignedInvite::new(
            authority.mls_group_id.clone(),
            authority.name.clone(),
            &creator,
            0,
        );
        invite.stable_group_id = Some(authority.stable_group_id().to_string());
        invite.group_created_at = Some(authority.created_at);
        invite.group_description = Some(authority.description.clone());
        invite.policy = Some(authority.policy.clone());
        invite.genesis_creation_nonce =
            authority.genesis.as_ref().map(|g| g.creation_nonce.clone());
        invite.base_state_revision = Some(authority.state_revision);
        invite.base_state_hash = Some(authority.state_hash.clone());
        invite.base_members_v2 = Some(authority.members_v2.clone());
        invite.base_prev_state_hash = authority.prev_state_hash.clone();
        invite.secure_plane = Some(authority.secure_plane);
        invite.base_secret_epoch = Some(authority.secret_epoch);
        invite.base_security_binding = authority.security_binding.clone();

        let mut stub = x0x::groups::GroupInfo::with_policy(
            invite.group_name.clone(),
            invite.group_description.clone().unwrap_or_default(),
            creator,
            invite.group_id.clone(),
            invite.policy.clone().unwrap_or_default(),
        );
        if let Some(group_created_at) = invite.group_created_at {
            stub.created_at = group_created_at;
        }
        if let Some(stable_group_id) = invite.stable_group_id.clone() {
            stub.genesis = Some(x0x::groups::GroupGenesis::with_existing_id(
                stable_group_id,
                invite.inviter.clone(),
                stub.created_at,
                invite.genesis_creation_nonce.clone().unwrap_or_default(),
            ));
        }
        stub.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        stub.shared_secret = None;
        stub.secret_epoch = invite.base_secret_epoch.unwrap_or_default();
        stub.security_binding = invite.base_security_binding.clone();
        stub.state_revision = invite.base_state_revision.unwrap_or_default();
        stub.roster_revision = stub.roster_revision.max(stub.state_revision);
        if let Some(base_members) = invite.base_members_v2.clone() {
            stub.members_v2 = base_members;
        }
        if let Some(base_state_hash) = invite.base_state_hash.clone() {
            stub.state_hash = base_state_hash;
            stub.prev_state_hash = invite.base_prev_state_hash.clone();
        } else {
            stub.recompute_state_hash();
        }

        assert_eq!(stub.state_hash, authority.state_hash);
        assert_eq!(stub.state_revision, authority.state_revision);
    }

    #[test]
    fn non_treekem_admin_invite_joiner_validates_member_added_state_chain() {
        let creator_kp = x0x::identity::AgentKeypair::generate().expect("creator keypair");
        let inviter_kp = x0x::identity::AgentKeypair::generate().expect("inviter keypair");
        let joiner_kp = x0x::identity::AgentKeypair::generate().expect("joiner keypair");
        let creator_hex = hex::encode(creator_kp.agent_id().as_bytes());
        let inviter_hex = hex::encode(inviter_kp.agent_id().as_bytes());
        let joiner_hex = hex::encode(joiner_kp.agent_id().as_bytes());
        let group_id = "cd".repeat(32);

        let mut base = x0x::groups::GroupInfo::with_policy(
            "public".to_string(),
            "non-TreeKEM invite".to_string(),
            creator_kp.agent_id(),
            group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        assert_ne!(
            base.secure_plane,
            x0x::mls::SecureGroupPlane::TreeKem,
            "fixture must exercise the non-TreeKEM path"
        );
        base.roster_revision = base.roster_revision.saturating_add(1);
        base.add_member(
            inviter_hex.clone(),
            x0x::groups::GroupRole::Admin,
            Some(creator_hex.clone()),
            Some("inviter-admin".to_string()),
        );
        base.seal_commit(&creator_kp, 1_000)
            .expect("creator promotion commit seals");

        let mut invite = x0x::groups::invite::SignedInvite::new(
            base.mls_group_id.clone(),
            base.name.clone(),
            &inviter_kp.agent_id(),
            0,
        );
        invite.stable_group_id = Some(base.stable_group_id().to_string());
        invite.group_created_at = Some(base.created_at);
        invite.group_description = Some(base.description.clone());
        invite.policy = Some(base.policy.clone());
        invite.genesis_creation_nonce = base.genesis.as_ref().map(|g| g.creation_nonce.clone());
        invite.base_state_revision = Some(base.state_revision);
        invite.base_state_hash = Some(base.state_hash.clone());
        invite.base_members_v2 = Some(base.members_v2.clone());
        invite.base_prev_state_hash = base.prev_state_hash.clone();
        invite.secure_plane = Some(base.secure_plane);
        invite.base_secret_epoch = Some(base.secret_epoch);
        invite.base_security_binding = base.security_binding.clone();

        let display_name = Some("joiner".to_string());
        let joiner_pre_commit = invite_join_group_info(
            &invite,
            creator_kp.agent_id(),
            &creator_hex,
            &group_id,
            &joiner_hex,
            display_name.clone(),
            None,
        );
        assert_eq!(joiner_pre_commit.members_v2, base.members_v2);
        assert_eq!(joiner_pre_commit.state_hash, base.state_hash);
        assert_eq!(joiner_pre_commit.prev_state_hash, base.prev_state_hash);
        assert_eq!(joiner_pre_commit.state_revision, base.state_revision);
        assert_eq!(joiner_pre_commit.roster_revision, base.roster_revision);
        assert!(
            !joiner_pre_commit.members_v2.contains_key(&joiner_hex),
            "joiner stub must not pre-commit the joiner under the authority base hash"
        );

        let mut inviter_after = base.clone();
        inviter_after.roster_revision = inviter_after.roster_revision.saturating_add(1);
        inviter_after.add_member(
            joiner_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(inviter_hex.clone()),
            display_name.clone(),
        );
        let revision = inviter_after.roster_revision;
        let member_added = inviter_after
            .seal_commit(&inviter_kp, 2_000)
            .expect("non-creator admin seals MemberAdded");

        let apply_member_added = |current: &x0x::groups::GroupInfo| {
            apply_stateful_event_to_group(
                current,
                &member_added,
                x0x::groups::ActionKind::AdminOrHigher,
                |next| {
                    next.roster_revision = revision.max(next.roster_revision);
                    next.add_member(
                        joiner_hex.clone(),
                        x0x::groups::GroupRole::Member,
                        Some(inviter_hex.clone()),
                        display_name.clone(),
                    );
                },
            )
        };

        let creator_after = apply_member_added(&base)
            .expect("creator should validate inviter-authored MemberAdded");
        let joiner_after = apply_member_added(&joiner_pre_commit).expect(
            "joiner should validate non-creator inviter MemberAdded against the invite base state",
        );

        let assert_state_hash_coherent = |label: &str, info: &x0x::groups::GroupInfo| {
            let mut recomputed = info.clone();
            recomputed.recompute_state_hash();
            assert_eq!(
                recomputed.state_hash, info.state_hash,
                "{label} state_hash must commit to its current roster/policy/meta/security fields"
            );
        };

        for (label, info) in [
            ("creator", &creator_after),
            ("inviter", &inviter_after),
            ("joiner", &joiner_after),
        ] {
            assert!(
                info.has_active_member(&joiner_hex),
                "{label} roster should contain joiner after MemberAdded"
            );
            assert_eq!(
                info.caller_role(&inviter_hex),
                Some(x0x::groups::GroupRole::Admin),
                "{label} roster should preserve non-creator inviter Admin authority"
            );
            assert_state_hash_coherent(label, info);
        }
        assert_eq!(
            member_added.roster_root,
            x0x::groups::compute_roster_root(&joiner_after.members_v2),
            "MemberAdded commit roster root must match the post-apply joiner roster"
        );
        assert_eq!(creator_after.state_hash, inviter_after.state_hash);
        assert_eq!(joiner_after.state_hash, inviter_after.state_hash);
        assert_eq!(creator_after.state_revision, inviter_after.state_revision);
        assert_eq!(joiner_after.state_revision, inviter_after.state_revision);
    }

    #[test]
    fn non_treekem_invite_stub_refreshes_existing_joiner_display_without_rehash() {
        let creator_kp = x0x::identity::AgentKeypair::generate().expect("creator keypair");
        let joiner_kp = x0x::identity::AgentKeypair::generate().expect("joiner keypair");
        let creator_hex = hex::encode(creator_kp.agent_id().as_bytes());
        let joiner_hex = hex::encode(joiner_kp.agent_id().as_bytes());
        let group_id = "ef".repeat(32);

        let mut base = x0x::groups::GroupInfo::with_policy(
            "public".to_string(),
            "self rejoin invite".to_string(),
            creator_kp.agent_id(),
            group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        base.add_member(
            joiner_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(creator_hex.clone()),
            Some("old display".to_string()),
        );
        base.seal_commit(&creator_kp, 1_000)
            .expect("base member commit seals");

        let mut invite = x0x::groups::invite::SignedInvite::new(
            base.mls_group_id.clone(),
            base.name.clone(),
            &creator_kp.agent_id(),
            0,
        );
        invite.stable_group_id = Some(base.stable_group_id().to_string());
        invite.group_created_at = Some(base.created_at);
        invite.group_description = Some(base.description.clone());
        invite.policy = Some(base.policy.clone());
        invite.genesis_creation_nonce = base.genesis.as_ref().map(|g| g.creation_nonce.clone());
        invite.base_state_revision = Some(base.state_revision);
        invite.base_state_hash = Some(base.state_hash.clone());
        invite.base_members_v2 = Some(base.members_v2.clone());
        invite.base_prev_state_hash = base.prev_state_hash.clone();
        invite.secure_plane = Some(base.secure_plane);
        invite.base_secret_epoch = Some(base.secret_epoch);
        invite.base_security_binding = base.security_binding.clone();

        let stub = invite_join_group_info(
            &invite,
            creator_kp.agent_id(),
            &creator_hex,
            &group_id,
            &joiner_hex,
            Some("new display".to_string()),
            None,
        );

        let joiner = stub
            .members_v2
            .get(&joiner_hex)
            .expect("base-state joiner should still be present");
        assert_eq!(joiner.state, x0x::groups::GroupMemberState::Active);
        assert_eq!(joiner.role, x0x::groups::GroupRole::Member);
        assert_eq!(joiner.display_name.as_deref(), Some("new display"));
        assert_eq!(stub.state_hash, base.state_hash);
        assert_eq!(stub.prev_state_hash, base.prev_state_hash);
        assert_eq!(stub.state_revision, base.state_revision);

        let mut recomputed = stub.clone();
        recomputed.recompute_state_hash();
        assert_eq!(
            recomputed.state_hash, stub.state_hash,
            "display-only refresh must not make the authority base hash incoherent"
        );
    }

    #[test]
    fn local_treekem_welcome_with_state_gap_is_queued() {
        let local_agent_hex = "22".repeat(32);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            AgentId([1; 32]),
            "aa".repeat(32),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.state_revision = 1;
        info.roster_revision = 1;
        info.state_hash = "rev1".to_string();
        let event = NamedGroupMetadataEvent::MemberAdded {
            group_id: info.stable_group_id().to_string(),
            revision: 3,
            actor: "11".repeat(32),
            agent_id: local_agent_hex.clone(),
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: None,
            welcome_ref: Some(WelcomeRef {
                welcome_id: "welcome".to_string(),
                byte_len: 1,
                source: "11".repeat(32),
            }),
            treekem_epoch: Some(3),
            treekem_key_package_hash: None,
            commit: Some(x0x::groups::GroupStateCommit {
                group_id: info.stable_group_id().to_string(),
                revision: 3,
                prev_state_hash: Some("rev2".to_string()),
                roster_root: String::new(),
                policy_hash: String::new(),
                public_meta_hash: String::new(),
                security_binding: Some("treekem:epoch=3".to_string()),
                state_hash: "rev3".to_string(),
                withdrawn: false,
                committed_by: "11".repeat(32),
                committed_at: 1,
                signer_public_key: String::new(),
                signature: String::new(),
            }),
            member_joined_recovery: None,
            member_recovery_history: Vec::new(),
        };

        assert_eq!(
            treekem_state_frontier_gap_reason(&info, &event, &local_agent_hex, None),
            Some("revision_gap".to_string())
        );
    }

    #[test]
    fn join_result_fetch_request_is_small_and_stable() {
        let request = JoinResultMessage::FetchRequest {
            group_id: "aa".repeat(32),
            member_agent_id: "bb".repeat(32),
        };
        let payload = serde_json::to_vec(&request);
        assert!(payload.is_ok(), "join-result fetch request serializes");
        let Ok(payload) = payload else {
            return;
        };
        assert!(payload.len() < x0x::dm::MAX_PAYLOAD_BYTES);
        assert_eq!(
            join_result_key(&"aa".repeat(32), &"bb".repeat(32)),
            format!("{}:{}", "aa".repeat(32), "bb".repeat(32))
        );

        let result = JoinResultMessage::Result {
            event: Box::new(NamedGroupMetadataEvent::MemberAdded {
                group_id: "aa".repeat(32),
                revision: 1,
                actor: "11".repeat(32),
                agent_id: "bb".repeat(32),
                display_name: None,
                treekem_commit_b64: Some("Yw==".to_string()),
                treekem_welcome_b64: None,
                welcome_ref: None,
                treekem_epoch: Some(1),
                treekem_key_package_hash: None,
                member_joined_recovery: None,
                member_recovery_history: Vec::new(),
                commit: None,
            }),
        };
        let result_payload = serde_json::to_vec(&result);
        assert!(result_payload.is_ok(), "join-result response serializes");
        let Ok(result_payload) = result_payload else {
            return;
        };
        assert!(result_payload.len() < x0x::dm::MAX_PAYLOAD_BYTES);
        let parsed = serde_json::from_slice::<JoinResultMessage>(&result_payload);
        assert!(parsed.is_ok(), "join-result response deserializes");
        assert!(matches!(parsed, Ok(JoinResultMessage::Result { .. })));
    }

    #[test]
    fn join_result_requires_stored_expected_inviter() {
        let expected = "11".repeat(32);
        let other = "22".repeat(32);

        assert_eq!(
            validate_join_result_inviter(None, &expected, &expected).unwrap_err(),
            "missing_expected_inviter"
        );
        assert_eq!(
            validate_join_result_inviter(Some(&expected), &other, &expected).unwrap_err(),
            "unexpected_sender"
        );
        assert_eq!(
            validate_join_result_inviter(Some(&expected), &expected, &other).unwrap_err(),
            "unexpected_actor"
        );
        assert!(validate_join_result_inviter(Some(&expected), &expected, &expected).is_ok());
    }

    #[test]
    fn welcome_blob_control_messages_keep_gossip_fallback() {
        let fetch = WelcomeBlobMessage::FetchRequest {
            group_id: "aa".repeat(32),
            welcome_id: "bb".repeat(32),
        };
        let fetch_config = welcome_blob_send_config(&fetch);
        assert!(!fetch_config.prefer_raw_quic_if_connected);
        assert!(!fetch_config.stop_fallback_on_raw_error);

        let chunk = WelcomeBlobMessage::Chunk {
            welcome_id: "bb".repeat(32),
            sequence: 0,
            data: "Yw==".to_string(),
        };
        let chunk_config = welcome_blob_send_config(&chunk);
        assert!(chunk_config.prefer_raw_quic_if_connected);
        // Welcome-blob chunks reuse `file_transfer_send_config()`, which keeps
        // capability-aware gossip fallback enabled (`stop_fallback_on_raw_error
        // == false`) — matching this test's intent ("keep gossip fallback").
        // Issue #110 Phase 1: this assertion was inverted and the test never ran
        // (binary `#[cfg(test)]` mods are skipped by nextest); moving the module
        // into the library activated it and exposed the contradiction. Corrected
        // to reflect the unchanged production behavior; the move itself is verbatim.
        assert!(!chunk_config.stop_fallback_on_raw_error);
    }

    #[test]
    fn named_group_metadata_delivery_prefers_verified_gossip_inbox() {
        let config = named_group_direct_delivery_config();

        assert!(!config.prefer_raw_quic_if_connected);
        assert!(!config.require_gossip);
        assert!(!config.stop_fallback_on_raw_error);
        assert_eq!(
            config.raw_quic_receive_ack_timeout,
            Some(Duration::from_secs(8))
        );
    }

    #[test]
    fn treekem_welcome_ref_is_content_addressed_and_serialized() {
        let bytes = b"large treekem welcome blob";
        let welcome_id = welcome_id_for_bytes(bytes);
        assert_eq!(welcome_id, hex::encode(blake3::hash(bytes).as_bytes()));

        let event = NamedGroupMetadataEvent::MemberAdded {
            group_id: "aa".to_string(),
            revision: 1,
            actor: "11".to_string(),
            agent_id: "22".to_string(),
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: None,
            welcome_ref: Some(WelcomeRef {
                welcome_id: welcome_id.clone(),
                byte_len: bytes.len() as u64,
                source: "11".repeat(32),
            }),
            treekem_epoch: Some(1),
            treekem_key_package_hash: None,
            member_joined_recovery: None,
            member_recovery_history: Vec::new(),
            commit: None,
        };
        let json = serde_json::to_value(event);
        assert!(json.is_ok(), "welcome ref event serializes");
        let Ok(json) = json else {
            return;
        };
        assert_eq!(json["welcome_ref"]["welcome_id"], welcome_id);
        assert_eq!(json["treekem_welcome_b64"], serde_json::Value::Null);
    }

    #[test]
    fn treekem_join_request_events_accept_legacy_json_defaults() {
        let created: NamedGroupMetadataEvent = serde_json::from_value(serde_json::json!({
            "event": "join_request_created",
            "group_id": "aa",
            "request_id": "req",
            "requester_agent_id": "22",
            "message": null,
            "ts": 1
        }))
        .expect("legacy created event should deserialize");
        match created {
            NamedGroupMetadataEvent::JoinRequestCreated {
                treekem_key_package_b64,
                ..
            } => assert_eq!(treekem_key_package_b64, None),
            other => panic!("unexpected event: {other:?}"),
        }

        let approved: NamedGroupMetadataEvent = serde_json::from_value(serde_json::json!({
            "event": "join_request_approved",
            "group_id": "aa",
            "request_id": "req",
            "revision": 2,
            "actor": "11",
            "requester_agent_id": "22"
        }))
        .expect("legacy approved event should deserialize");
        match approved {
            NamedGroupMetadataEvent::JoinRequestApproved {
                treekem_commit_b64,
                treekem_welcome_b64,
                treekem_epoch,
                ..
            } => {
                assert_eq!(treekem_commit_b64, None);
                assert_eq!(treekem_welcome_b64, None);
                assert_eq!(treekem_epoch, None);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn member_joined_canonical_binds_treekem_keypackage() {
        let base = canonical_member_joined_bytes(
            "group",
            Some("stable"),
            &"22".repeat(32),
            "pubkey",
            x0x::groups::GroupRole::Member,
            Some("Alice"),
            &"11".repeat(32),
            "invite-secret",
            42,
            Some("key-package-a"),
        );
        let changed = canonical_member_joined_bytes(
            "group",
            Some("stable"),
            &"22".repeat(32),
            "pubkey",
            x0x::groups::GroupRole::Member,
            Some("Alice"),
            &"11".repeat(32),
            "invite-secret",
            42,
            Some("key-package-b"),
        );
        let legacy = canonical_member_joined_bytes(
            "group",
            Some("stable"),
            &"22".repeat(32),
            "pubkey",
            x0x::groups::GroupRole::Member,
            Some("Alice"),
            &"11".repeat(32),
            "invite-secret",
            42,
            None,
        );

        assert_ne!(base, changed);
        assert_ne!(base, legacy);
    }

    #[test]
    fn direct_add_request_defaults_without_treekem_keypackage() {
        let req: AddNamedGroupMemberRequest = serde_json::from_value(serde_json::json!({
            "agent_id": "22",
            "display_name": "Bob"
        }))
        .expect("request should deserialize");
        assert_eq!(req.agent_id, "22");
        assert_eq!(req.display_name.as_deref(), Some("Bob"));
        assert_eq!(req.treekem_key_package_b64, None);
    }

    #[test]
    fn phase3_metadata_events_accept_legacy_json_defaults() {
        let joined: NamedGroupMetadataEvent = serde_json::from_value(serde_json::json!({
            "event": "member_joined",
            "group_id": "aa",
            "member_agent_id": "22",
            "member_public_key_b64": "cHVi",
            "role": "member",
            "inviter_agent_id": "11",
            "invite_secret": "secret",
            "ts_ms": 1,
            "signature_b64": "c2ln"
        }))
        .expect("legacy member_joined should deserialize");
        match joined {
            NamedGroupMetadataEvent::MemberJoined {
                treekem_key_package_b64,
                ..
            } => assert_eq!(treekem_key_package_b64, None),
            other => panic!("unexpected event: {other:?}"),
        }

        let added: NamedGroupMetadataEvent = serde_json::from_value(serde_json::json!({
            "event": "member_added",
            "group_id": "aa",
            "revision": 1,
            "actor": "11",
            "agent_id": "22",
            "display_name": null
        }))
        .expect("legacy member_added should deserialize");
        match added {
            NamedGroupMetadataEvent::MemberAdded {
                treekem_commit_b64,
                treekem_welcome_b64,
                treekem_epoch,
                ..
            } => {
                assert_eq!(treekem_commit_b64, None);
                assert_eq!(treekem_welcome_b64, None);
                assert_eq!(treekem_epoch, None);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let banned: NamedGroupMetadataEvent = serde_json::from_value(serde_json::json!({
            "event": "member_banned",
            "group_id": "aa",
            "revision": 1,
            "actor": "11",
            "agent_id": "22"
        }))
        .expect("legacy member_banned should deserialize");
        match banned {
            NamedGroupMetadataEvent::MemberBanned {
                treekem_commit_b64,
                treekem_epoch,
                ..
            } => {
                assert_eq!(treekem_commit_b64, None);
                assert_eq!(treekem_epoch, None);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn phase3_metadata_classifier_allows_completed_membership_events() {
        let member_added = NamedGroupMetadataEvent::MemberAdded {
            group_id: "aa".to_string(),
            revision: 1,
            actor: "11".to_string(),
            agent_id: "22".to_string(),
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: Some("dw==".to_string()),
            welcome_ref: None,
            treekem_epoch: Some(1),
            treekem_key_package_hash: None,
            member_joined_recovery: None,
            member_recovery_history: Vec::new(),
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&member_added));

        let member_banned = NamedGroupMetadataEvent::MemberBanned {
            group_id: "aa".to_string(),
            revision: 1,
            actor: "11".to_string(),
            agent_id: "22".to_string(),
            secret_epoch: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_epoch: Some(1),
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&member_banned));

        let member_unbanned = NamedGroupMetadataEvent::MemberUnbanned {
            group_id: "aa".to_string(),
            revision: 1,
            actor: "11".to_string(),
            agent_id: "22".to_string(),
            commit: None,
        };
        assert!(!treekem_metadata_event_requires_phase3(&member_unbanned));
    }

    #[test]
    fn treekem_pending_event_helpers_dedupe_and_sort_by_frontier() {
        fn fake_commit(revision: u64, prev: &str) -> x0x::groups::GroupStateCommit {
            x0x::groups::GroupStateCommit {
                group_id: "aa".to_string(),
                revision,
                prev_state_hash: Some(prev.to_string()),
                roster_root: "roster".to_string(),
                policy_hash: "policy".to_string(),
                public_meta_hash: "meta".to_string(),
                security_binding: Some(format!("treekem:epoch={revision}")),
                state_hash: format!("state-{revision}"),
                withdrawn: false,
                committed_by: "11".to_string(),
                committed_at: revision,
                signer_public_key: "pub".to_string(),
                signature: "sig".to_string(),
            }
        }

        let add_epoch_2 = NamedGroupMetadataEvent::MemberAdded {
            group_id: "aa".to_string(),
            revision: 2,
            actor: "11".to_string(),
            agent_id: "22".to_string(),
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: Some("dw==".to_string()),
            welcome_ref: None,
            treekem_epoch: Some(2),
            treekem_key_package_hash: None,
            member_joined_recovery: None,
            member_recovery_history: Vec::new(),
            commit: Some(fake_commit(2, "state-1")),
        };
        let ban_epoch_3 = NamedGroupMetadataEvent::MemberBanned {
            group_id: "aa".to_string(),
            revision: 3,
            actor: "11".to_string(),
            agent_id: "33".to_string(),
            secret_epoch: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_epoch: Some(3),
            commit: Some(fake_commit(3, "state-2")),
        };

        assert_eq!(treekem_membership_event_sort_key(&ban_epoch_3), (3, 3));
        assert_eq!(treekem_membership_event_sort_key(&add_epoch_2), (2, 2));
        assert_ne!(
            treekem_membership_event_key(&add_epoch_2),
            treekem_membership_event_key(&ban_epoch_3)
        );
        assert_eq!(
            treekem_membership_event_key(&add_epoch_2),
            treekem_membership_event_key(&add_epoch_2.clone())
        );
    }

    #[test]
    fn treekem_local_welcome_queues_on_authority_state_gap() {
        let local_agent_hex = "22".repeat(32);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            AgentId([9; 32]),
            "aa".repeat(16),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.state_revision = 0;
        info.roster_revision = 0;
        info.state_hash = "joiner-stub-hash".to_string();
        let commit = x0x::groups::GroupStateCommit {
            group_id: "aa".to_string(),
            revision: 10,
            prev_state_hash: Some("authority-prev-hash".to_string()),
            roster_root: "roster".to_string(),
            policy_hash: "policy".to_string(),
            public_meta_hash: "meta".to_string(),
            security_binding: Some("treekem:epoch=10".to_string()),
            state_hash: "authority-state-10".to_string(),
            withdrawn: false,
            committed_by: "11".to_string(),
            committed_at: 10,
            signer_public_key: "pub".to_string(),
            signature: "sig".to_string(),
        };
        let event = NamedGroupMetadataEvent::MemberAdded {
            group_id: "aa".to_string(),
            revision: 10,
            actor: "11".to_string(),
            agent_id: local_agent_hex.clone(),
            display_name: None,
            treekem_commit_b64: Some("Yw==".to_string()),
            treekem_welcome_b64: Some("dw==".to_string()),
            welcome_ref: None,
            treekem_epoch: Some(10),
            treekem_key_package_hash: None,
            member_joined_recovery: None,
            member_recovery_history: Vec::new(),
            commit: Some(commit),
        };

        assert_eq!(
            treekem_state_frontier_gap_reason(&info, &event, &local_agent_hex, None),
            Some("revision_gap".to_string())
        );
    }

    #[test]
    fn treekem_catchup_messages_use_explicit_type_tags() {
        let request = TreeKemCatchupRequest {
            message_type: "treekem_catchup_request".to_string(),
            group_id: "aa".to_string(),
            requester_agent_id: "22".to_string(),
            from_revision: 1,
            from_treekem_epoch: 1,
            current_state_hash: "state-1".to_string(),
            missing_prev_state_hash: Some("state-2".to_string()),
            target_member_id: None,
            limit: 8,
        };
        let encoded = serde_json::to_value(&request).expect("catch-up request serializes");
        assert_eq!(encoded["message_type"], "treekem_catchup_request");

        let response = TreeKemCatchupResponse {
            message_type: "treekem_catchup_response".to_string(),
            group_id: "aa".to_string(),
            events: Vec::new(),
            truncated: false,
        };
        let encoded = serde_json::to_value(&response).expect("catch-up response serializes");
        assert_eq!(encoded["message_type"], "treekem_catchup_response");
    }

    #[test]
    fn treekem_membership_guard_returns_501_without_mutating() {
        let creator = AgentId([7; 32]);
        let mut info = x0x::groups::GroupInfo::with_policy(
            "secure".to_string(),
            String::new(),
            creator,
            "aa".repeat(16),
            x0x::groups::GroupPolicy::default(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        let before_revision = info.roster_revision;
        let before_members = info.members_v2.clone();

        let response = treekem_membership_unsupported(&info);
        assert!(
            response.is_some(),
            "legacy-only TreeKEM endpoints must fail loud instead of running GSS rekey logic"
        );
        let status = response.map(|(status, _body)| status);

        assert_eq!(status, Some(StatusCode::NOT_IMPLEMENTED));
        assert_eq!(info.roster_revision, before_revision);
        assert_eq!(info.members_v2, before_members);
    }

    #[test]
    fn group_public_message_direct_payload_is_prefixed_json() {
        let msg = x0x::groups::GroupPublicMessage {
            group_id: "group-1".to_string(),
            state_hash_at_send: "state".to_string(),
            revision_at_send: 7,
            author_agent_id: "aa".repeat(32),
            author_public_key: "bb".repeat(64),
            author_user_id: None,
            kind: x0x::groups::GroupPublicMessageKind::Chat,
            body: "hello".to_string(),
            timestamp: 123,
            signature: "cc".repeat(64),
        };

        let payload =
            encode_group_public_message_direct_payload(&msg).expect("payload should encode");
        assert!(payload.starts_with(GROUP_PUBLIC_MESSAGE_DM_PREFIX));

        let decoded: x0x::groups::GroupPublicMessage =
            serde_json::from_slice(&payload[GROUP_PUBLIC_MESSAGE_DM_PREFIX.len()..])
                .expect("payload JSON should decode");
        assert_eq!(decoded, msg);
    }

    /// Issue #205: minting a `private_secure` invite must strip per-member
    /// TreeKEM KeyPackages + ML-KEM keys (each ~15.7 KiB / ~1.2 KiB) so the
    /// join cmd-DM stays under the 49 152-byte gossip cap. Covers the
    /// growth-curve regression (1/3/10 members), the mint-time budget
    /// assertion, backward compat both directions, and that stripping does not
    /// change `roster_root` (the only thing a joiner validates).
    #[test]
    fn invite_link_strips_key_packages_and_stays_under_dm_budget() {
        use x0x::groups::invite::{SignedInvite, INVITE_LINK_MAX_BYTES};
        use x0x::groups::state_commit::compute_roster_root;
        use x0x::groups::{GroupInfo, GroupMember, GroupPolicyPreset};

        let authority = x0x::identity::AgentKeypair::generate().expect("authority keypair");
        let agent_id = authority.agent_id();
        let owner_hex = hex::encode(agent_id.as_bytes());
        let group_id = "7e".repeat(16);
        // Measured testnet sizes (issue #188): ~15 688 B TreeKEM KeyPackage,
        // ~1 184 B ML-KEM-768 public key.
        let kp_blob = BASE64.encode(vec![0xaau8; 15_688]);
        let kem_blob = BASE64.encode(vec![0xbbu8; 1_184]);

        let build_info = |n_joiners: usize| -> GroupInfo {
            let mut info = GroupInfo::with_policy(
                "growth".to_string(),
                "growth-curve".to_string(),
                agent_id,
                group_id.clone(),
                GroupPolicyPreset::PrivateSecure.to_policy(),
            );
            info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
            info.members_v2.insert(
                owner_hex.clone(),
                GroupMember::new_admin(owner_hex.clone(), None, 1),
            );
            for i in 0..n_joiners {
                let m_hex = format!("{:064x}", i + 1);
                let mut m = GroupMember::new_member(
                    m_hex.clone(),
                    Some(format!("m{i}")),
                    Some(owner_hex.clone()),
                    1,
                );
                m.treekem_key_package_b64 = Some(kp_blob.clone());
                m.kem_public_key_b64 = Some(kem_blob.clone());
                info.members_v2.insert(m_hex, m);
            }
            info.recompute_state_hash();
            info
        };

        for &n_joiners in &[1usize, 3, 10] {
            let info = build_info(n_joiners);
            let full_root = compute_roster_root(&info.members_v2);
            let mut invite =
                SignedInvite::new(group_id.clone(), "growth".to_string(), &agent_id, 3600);
            populate_invite_base_state_from_group_info(&mut invite, &info);

            let roster = invite
                .base_members_v2
                .as_ref()
                .expect("base roster embedded");
            for m in roster.values() {
                assert!(m.treekem_key_package_b64.is_none(), "kp stripped at mint");
                assert!(m.kem_public_key_b64.is_none(), "kem key stripped at mint");
            }
            // Stripping must not change the committed roster root.
            assert_eq!(
                compute_roster_root(roster),
                full_root,
                "roster_root unchanged by strip"
            );

            let link = invite
                .encode_link()
                .expect("stripped invite is under the DM budget")
                .len();
            assert!(
                link <= INVITE_LINK_MAX_BYTES,
                "{n_joiners}-joiner stripped invite too large: {link} B"
            );
            assert!(
                link <= x0x::dm::MAX_PAYLOAD_BYTES,
                "{n_joiners}-joiner stripped invite exceeds DM payload cap: {link} B"
            );
        }

        // Pre-fix regression proof (issue #188 root cause): a 3-joiner invite
        // that EMBEDS key packages crosses both the budget and the DM cap.
        let info3 = build_info(3);
        let mut fat_invite =
            SignedInvite::new(group_id.clone(), "growth".to_string(), &agent_id, 3600);
        fat_invite.base_members_v2 = Some(info3.members_v2.clone());
        let fat_len = fat_invite.to_link().len();
        assert!(
            fat_len > INVITE_LINK_MAX_BYTES,
            "pre-fix 3-joiner invite should exceed budget: {fat_len} B"
        );
        assert!(
            fat_len > x0x::dm::MAX_PAYLOAD_BYTES,
            "pre-fix 3-joiner invite should exceed DM cap: {fat_len} B"
        );
        assert!(
            fat_invite.encode_link().is_err(),
            "budget assertion rejects fat invite"
        );

        // Backward compat both directions: fields are `#[serde(default)]`, so an
        // old (kp-bearing) link still parses and a new (stripped) link degrades
        // gracefully on an old daemon (kp reads as None).
        let mut slim_invite =
            SignedInvite::new(group_id.clone(), "growth".to_string(), &agent_id, 3600);
        populate_invite_base_state_from_group_info(&mut slim_invite, &info3);
        let slim_link = slim_invite.encode_link().expect("slim under budget");
        let parsed_slim = SignedInvite::from_link(&slim_link).expect("slim link round-trips");
        assert!(parsed_slim
            .base_members_v2
            .as_ref()
            .expect("roster")
            .values()
            .all(|m| m.treekem_key_package_b64.is_none()));
        let parsed_fat =
            SignedInvite::from_link(&fat_invite.to_link()).expect("fat link round-trips");
        assert!(parsed_fat
            .base_members_v2
            .as_ref()
            .expect("roster")
            .values()
            .any(|m| m.treekem_key_package_b64.is_some()));
        assert_eq!(
            compute_roster_root(parsed_slim.base_members_v2.as_ref().expect("roster")),
            compute_roster_root(parsed_fat.base_members_v2.as_ref().expect("roster")),
            "roster_root identical across formats"
        );
    }

    /// `member_joined_kp_cache_entry` extracts only key-package-bearing
    /// `MemberJoined` events, keyed by `join_result_key`. This is the helper
    /// the inviter-side apply wrapper uses to populate the recovery cache.
    #[test]
    fn member_joined_kp_cache_entry_extracts_package_bearing_events() {
        let group_id = "71".repeat(32);
        let member = "8a".repeat(32);
        let with_kp = NamedGroupMetadataEvent::MemberJoined {
            group_id: group_id.clone(),
            stable_group_id: Some(group_id.clone()),
            member_agent_id: member.clone(),
            member_public_key_b64: "k".to_string(),
            role: x0x::groups::GroupRole::Member,
            display_name: None,
            inviter_agent_id: "ff".repeat(32),
            invite_secret: "s".to_string(),
            ts_ms: 1,
            treekem_key_package_b64: Some("kp".to_string()),
            recovery_authority_agent_id: None,
            recovery_authority_public_key_b64: None,
            recovery_authority_signature_b64: None,
            recovery_authority_commit: None,
            signature_b64: "sig".to_string(),
        };
        let (key, _) = member_joined_kp_cache_entry(&with_kp).expect("kp-bearing event extracted");
        assert_eq!(key, join_result_key(&group_id, &member));

        let mut no_kp = with_kp.clone();
        if let NamedGroupMetadataEvent::MemberJoined {
            treekem_key_package_b64,
            ..
        } = &mut no_kp
        {
            *treekem_key_package_b64 = None;
        }
        assert!(
            member_joined_kp_cache_entry(&no_kp).is_none(),
            "no package → no cache entry"
        );
        assert!(
            member_joined_kp_cache_entry(&NamedGroupMetadataEvent::GroupDeleted {
                group_id: group_id.clone(),
                revision: 1,
                actor: member.clone(),
                commit: None,
            })
            .is_none(),
            "non-MemberJoined event ignored"
        );
    }

    /// A verified key-package-bearing `MemberJoined` must remain available to
    /// member-keyed catch-up after the inviter's process-local cache is lost.
    #[tokio::test]
    async fn member_keyed_catchup_restores_signed_event_after_restart() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0x8b, 0x8c).await?;
        let state = &fixture.state;
        let _ = apply_named_group_metadata_event(
            state,
            without_recovery_attestation(fixture.event.clone()),
            fixture.member_id,
            true,
        )
        .await;
        assert_eq!(
            state
                .treekem_member_key_packages
                .diagnostics()
                .await
                .entries,
            1
        );
        tokio::fs::metadata(&state.treekem_member_key_packages.path).await?;

        // Model process loss explicitly, then construct a distinct AppState on
        // the same durable directory. Startup must repopulate the empty runtime
        // cache from the authenticated signed-event file.
        let restarted =
            secure_endpoint_test_state_at(fixture._dir.path(), Arc::clone(&state.agent)).await?;
        assert!(!Arc::ptr_eq(state, &restarted));

        let requester_agent_id = hex::encode(restarted.agent.agent_id().as_bytes());
        let request = TreeKemCatchupRequest {
            message_type: "treekem_catchup_request".to_string(),
            group_id: fixture.stable_group_id.clone(),
            requester_agent_id,
            from_revision: 0,
            from_treekem_epoch: 0,
            current_state_hash: String::new(),
            missing_prev_state_hash: None,
            target_member_id: Some(fixture.member_hex.clone()),
            limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
        };
        let log_keys = vec![fixture.group_id.clone(), fixture.stable_group_id.clone()];
        let response = member_keyed_treekem_catchup_response(&restarted, &log_keys, &request)
            .await
            .expect("member-keyed request produces a response");

        assert_eq!(response.events.len(), 1, "persisted event is returned");
        assert!(
            verify_member_joined_key_package_event(&response.events[0]),
            "returned key package retains a valid member signature"
        );
        Ok(())
    }

    /// Issue #205: a promoted admin missing a member's TreeKEM KeyPackage
    /// recovers it from this node's cached, self-signed `MemberJoined` and the
    /// removal-path resolver returns it. The cache mirrors what a node holds
    /// after applying the join (inviter) or receiving a member-keyed catch-up.
    #[tokio::test]
    async fn recovered_member_key_package_installs_from_cache() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0x71, 0x72).await?;
        let state = &fixture.state;
        let group_id = fixture.group_id.clone();
        let member_hex = fixture.member_hex.clone();
        let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());

        // Roster carries the member (Active) WITHOUT a key package — the
        // promoted-admin regression. Seed the recovery cache with the member's
        // self-signed MemberJoined (what the inviter / catch-up would supply).
        insert_active_member_without_kp(state, &group_id, &member_hex, &inviter_hex).await;
        state
            .treekem_member_key_packages
            .insert(
                join_result_key(&group_id, &member_hex),
                fixture.event.clone(),
                true,
            )
            .await?;
        assert!(member_treekem_kp(state, &group_id, &member_hex)
            .await
            .is_none());

        // On-demand recovery signature-verifies the cached event + installs.
        let recovered = recover_member_treekem_key_package(state, &group_id, &member_hex).await;
        assert!(recovered, "kp recovered from cache");
        assert!(member_treekem_kp(state, &group_id, &member_hex)
            .await
            .is_some());

        // The removal-path resolver returns it (fast path: roster now carries it).
        let resolved = resolve_member_treekem_kp_for_removal(state, &group_id, &member_hex).await;
        assert!(resolved.is_ok(), "resolver returns kp after recovery");
        Ok(())
    }

    /// Issue #205: the recovered key-package install is fail-closed — a forged
    /// signature, an unknown member, or an already-present package is refused,
    /// and a member with no cached event surfaces a retryable pending error.
    #[tokio::test]
    async fn recovered_member_key_package_refuses_forgery_and_gates() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0x73, 0x74).await?;
        let state = &fixture.state;
        let group_id = fixture.group_id.clone();
        let member_hex = fixture.member_hex.clone();
        let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
        let valid_event = fixture.event.clone();

        // Roster carries the member (Active) WITHOUT a key package.
        insert_active_member_without_kp(state, &group_id, &member_hex, &inviter_hex).await;

        // Forged signature → refused, roster unchanged.
        let forged = match valid_event.clone() {
            NamedGroupMetadataEvent::MemberJoined {
                group_id,
                stable_group_id,
                member_agent_id,
                member_public_key_b64,
                role,
                display_name,
                inviter_agent_id,
                invite_secret,
                ts_ms,
                treekem_key_package_b64,
                ..
            } => NamedGroupMetadataEvent::MemberJoined {
                group_id,
                stable_group_id,
                member_agent_id,
                member_public_key_b64,
                role,
                display_name,
                inviter_agent_id,
                invite_secret,
                ts_ms,
                treekem_key_package_b64,
                recovery_authority_agent_id: None,
                recovery_authority_public_key_b64: None,
                recovery_authority_signature_b64: None,
                recovery_authority_commit: None,
                signature_b64: BASE64.encode(vec![0xcdu8; 64]),
            },
            _ => unreachable!("fixture is MemberJoined"),
        };
        assert!(
            !apply_recovered_member_key_package(state, &forged).await,
            "forged signature refused"
        );
        assert!(
            member_treekem_kp(state, &group_id, &member_hex)
                .await
                .is_none(),
            "forged event did not install a package"
        );

        // Valid cached event → installs.
        assert!(
            apply_recovered_member_key_package(state, &valid_event).await,
            "valid signature installs"
        );
        // Already-present package → no-op refusal (no clobber).
        assert!(
            !apply_recovered_member_key_package(state, &valid_event).await,
            "already-present package not re-installed"
        );

        // Unknown member (not in roster) → refused even with an otherwise-valid
        // signature for a different agent_id.
        let stranger = format!("{:064x}", 0x9999u64);
        let stranger_event = match valid_event.clone() {
            NamedGroupMetadataEvent::MemberJoined {
                group_id,
                stable_group_id,
                member_public_key_b64,
                role,
                display_name,
                inviter_agent_id,
                invite_secret,
                ts_ms,
                treekem_key_package_b64,
                signature_b64,
                ..
            } => NamedGroupMetadataEvent::MemberJoined {
                group_id,
                stable_group_id,
                member_agent_id: stranger.clone(),
                member_public_key_b64,
                role,
                display_name,
                inviter_agent_id,
                invite_secret,
                ts_ms,
                treekem_key_package_b64,
                recovery_authority_agent_id: None,
                recovery_authority_public_key_b64: None,
                recovery_authority_signature_b64: None,
                recovery_authority_commit: None,
                signature_b64,
            },
            _ => unreachable!("fixture is MemberJoined"),
        };
        assert!(
            !apply_recovered_member_key_package(state, &stranger_event).await,
            "unknown member refused"
        );

        // No cached event for a member → resolver returns a retryable pending error.
        let resolved = resolve_member_treekem_kp_for_removal(state, &group_id, &stranger).await;
        assert!(resolved.is_err(), "missing kp with no cache is pending");
        let (status, body) = resolved.expect_err("pending error");
        assert_eq!(status, StatusCode::FAILED_DEPENDENCY);
        assert_eq!(body["error"], "member_key_package_pending");
        assert_eq!(body["retry"], true);
        Ok(())
    }

    /// Issue #205 review nit: a `MemberJoined` validly signed for member X in
    /// group A must be REFUSED for group B. `canonical_member_joined_bytes`
    /// binds `group_id` (and `stable_group_id`) into the signed payload, so a
    /// replay against a different group fails signature verification even when
    /// the target member exists there. This pins the cross-group forgery guard.
    #[tokio::test]
    async fn recovered_member_key_package_refuses_cross_group_forgery() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0x75, 0x76).await?;
        let state = &fixture.state;
        let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
        let member_hex = fixture.member_hex.clone();

        // Install a SECOND, independent TreeKEM group B in the same state and
        // make the fixture's member a roster member of B (no key package).
        let group_b = "77".repeat(32);
        let stable_b = "78".repeat(32);
        let info_b = treekem_metadata_group_info(state.agent.agent_id(), &group_b, &stable_b);
        state
            .named_groups
            .write()
            .await
            .insert(group_b.clone(), info_b);
        insert_active_member_without_kp(state, &group_b, &member_hex, &inviter_hex).await;

        // Take the member's validly-signed event for group A and tamper only the
        // group id fields to claim group B. The signature stays valid-for-A.
        let cross_group_event = match fixture.event.clone() {
            NamedGroupMetadataEvent::MemberJoined {
                member_agent_id,
                member_public_key_b64,
                role,
                display_name,
                inviter_agent_id,
                invite_secret,
                ts_ms,
                treekem_key_package_b64,
                signature_b64,
                ..
            } => NamedGroupMetadataEvent::MemberJoined {
                group_id: group_b.clone(),
                stable_group_id: Some(stable_b.clone()),
                member_agent_id,
                member_public_key_b64,
                role,
                display_name,
                inviter_agent_id,
                invite_secret,
                ts_ms,
                treekem_key_package_b64,
                recovery_authority_agent_id: None,
                recovery_authority_public_key_b64: None,
                recovery_authority_signature_b64: None,
                recovery_authority_commit: None,
                signature_b64,
            },
            _ => unreachable!("fixture is MemberJoined"),
        };
        assert!(
            !apply_recovered_member_key_package(state, &cross_group_event).await,
            "cross-group forgery refused — group_id is bound into the signed canonical bytes"
        );
        assert!(
            member_treekem_kp(state, &group_b, &member_hex)
                .await
                .is_none(),
            "group B roster untouched by group A's signed event"
        );
        Ok(())
    }

    /// Issue #205 review nit: remove → re-add lifecycle. A cached, self-signed
    /// `MemberJoined` must NOT silently re-key a Removed member, and after a
    /// re-add it may only re-install the SAME package the member would produce
    /// afresh. Safety rests on a load-bearing invariant: `agent_treekem_seed`
    /// derives the TreeKEM seed deterministically from the agent's static
    /// keypair secret + group id, and `prepare_member` is deterministic in that
    /// seed — so for an unchanged AgentId the cached package is byte-identical
    /// to a fresh `prepare_member` output and matches the re-added ratchet leaf.
    /// A re-keyed member has a different AgentId (it is derived from the
    /// ML-DSA public key) and therefore a different cache key, so a stale
    /// package can never cross-contaminate a re-keyed member. If
    /// `prepare_member` ever becomes non-deterministic, a staleness guard must
    /// be added here.
    #[tokio::test]
    async fn recovered_member_key_package_remove_then_readd_reinstalls_same_package() -> Result<()>
    {
        let fixture = member_joined_treekem_fixture(0x79, 0x7a).await?;
        let state = &fixture.state;
        let group_id = fixture.group_id.clone();
        let member_hex = fixture.member_hex.clone();
        let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
        let original_kp = match &fixture.event {
            NamedGroupMetadataEvent::MemberJoined {
                treekem_key_package_b64: Some(kp),
                ..
            } => kp.clone(),
            _ => unreachable!("fixture carries a key package"),
        };

        // Join: roster member (Active, no kp) + cached self-signed event.
        insert_active_member_without_kp(state, &group_id, &member_hex, &inviter_hex).await;
        state
            .treekem_member_key_packages
            .insert(
                join_result_key(&group_id, &member_hex),
                fixture.event.clone(),
                true,
            )
            .await?;
        assert!(
            recover_member_treekem_key_package(state, &group_id, &member_hex).await,
            "first recovery installs"
        );
        assert_eq!(
            member_treekem_kp(state, &group_id, &member_hex)
                .await
                .as_deref(),
            Some(original_kp.as_str()),
            "installed package matches the signed event"
        );

        // Remove: the member is no longer Active. The stale cache must NOT
        // silently re-key a removed member.
        set_member_state(
            state,
            &group_id,
            &member_hex,
            x0x::groups::GroupMemberState::Removed,
        )
        .await;
        assert!(
            !recover_member_treekem_key_package(state, &group_id, &member_hex).await,
            "removed member is not re-keyable from the stale cache"
        );
        assert!(
            member_treekem_kp(state, &group_id, &member_hex)
                .await
                .is_none(),
            "removed member keeps no package"
        );

        // Re-add: fresh Active entry, no package, cache unchanged. Recovery may
        // re-install — and because the seed is deterministic for the same
        // AgentId, the re-installed package is byte-identical to the original
        // (i.e. what a fresh join would publish), so it matches the new leaf.
        set_member_state(
            state,
            &group_id,
            &member_hex,
            x0x::groups::GroupMemberState::Active,
        )
        .await;
        assert!(
            recover_member_treekem_key_package(state, &group_id, &member_hex).await,
            "re-added member recovers the cached package"
        );
        assert_eq!(
            member_treekem_kp(state, &group_id, &member_hex)
                .await
                .as_deref(),
            Some(original_kp.as_str()),
            "re-installed package is the deterministic (same-key) package, not a stale leaf"
        );
        Ok(())
    }

    /// WP-TK1 CRITICAL — TreeKEM witness recovery (issue #205): a non-inviter
    /// third party that independently receives a member's self-signed
    /// `MemberJoined` must NOT mutate the durable roster/state-commit chain
    /// (only the inviter may consume the one-time invite and author the D.3
    /// commit), but it MUST durably cache the authenticated key-package event so
    /// a future admin can recover it when the inviter AND the joiner are both
    /// unavailable. This decouples recovery *availability* from inviter/joiner
    /// liveness without weakening the signed-commit *authoring* invariant: the
    /// witness never admits the member, yet it cannot later deny the
    /// self-authenticated package.
    #[tokio::test]
    async fn non_inviter_witness_caches_signed_member_joined_without_roster_mutation() -> Result<()>
    {
        // O = owner/inviter; B = joining member; the event is signed by B over
        // canonical bytes binding group_id, B's AgentId, and B's TreeKEM
        // KeyPackage.
        let fixture = member_joined_treekem_fixture(0x91, 0x92).await?;
        let group_id = fixture.group_id.clone();
        let stable_group_id = fixture.stable_group_id.clone();
        let member_hex = fixture.member_hex.clone();

        // W = independent witness: a distinct node (different AgentId) that
        // holds the same group membership view (card shared) but is NOT the
        // inviter — so it must take the non-inviter recovery-witness path.
        let (w_state, w_dir) = secure_endpoint_test_state().await?;
        assert_ne!(
            w_state.agent.agent_id(),
            fixture.state.agent.agent_id(),
            "witness W must be a distinct agent from inviter O"
        );
        add_active_witness_to_treekem_fixture(&fixture, &w_state).await?;

        let raw_join_event = without_recovery_attestation(fixture.event.clone());
        // W receives B's signed MemberJoined (sender = B, self-issued, verified).
        let applied = apply_named_group_metadata_event(
            &w_state,
            raw_join_event.clone(),
            fixture.member_id,
            true,
        )
        .await;

        // (1) Non-inviter never consumes the invite nor authors a roster
        // mutation — the durable state-commit chain is untouched.
        assert!(
            !applied,
            "non-inviter witness must not apply — no roster/state-commit mutation"
        );
        {
            let groups = w_state.named_groups.read().await;
            let info = groups.get(&group_id).expect("group retained on witness");
            assert!(
                !info.has_active_member(&member_hex),
                "witness roster must not admit B — only the inviter commits the add"
            );
        }

        // (2) Yet the self-authenticated event is durably cached and survives a
        // process restart on W's directory (recovery availability does not
        // depend on inviter/joiner liveness).
        let cache_key = join_result_key(&group_id, &member_hex);
        assert!(
            w_state
                .treekem_member_key_packages
                .get(&cache_key)
                .await
                .is_some(),
            "witness caches the signed MemberJoined in-memory"
        );
        assert!(
            tokio::fs::try_exists(&w_state.treekem_member_key_packages.path).await?,
            "witness persisted the key-package cache to disk"
        );

        // O accepts B and publishes MemberAdded containing the original event
        // countersigned after the TreeKEM add. W applies that production event:
        // only now does the provisional cache become authority-attested and
        // eligible to serve, while W itself never authors the roster mutation.
        let _ = apply_named_group_metadata_event(
            &fixture.state,
            raw_join_event,
            fixture.member_id,
            true,
        )
        .await;
        let authority_event = {
            let logs = fixture.state.treekem_event_log.read().await;
            logs.get(&stable_group_id)
                .and_then(|events| {
                    events.iter().find(|event| {
                        matches!(
                            event,
                            NamedGroupMetadataEvent::MemberAdded { agent_id, .. }
                                if agent_id == &member_hex
                        )
                    })
                })
                .cloned()
                .expect("O logged authority-attested MemberAdded")
        };
        let authority_recovery = fixture
            .state
            .treekem_member_key_packages
            .get(&cache_key)
            .await
            .expect("O cached the authority-attested recovery event");
        {
            let groups = fixture.state.named_groups.read().await;
            let info = groups.get(&group_id).expect("O retained accepted roster");
            assert!(
                verify_authority_attested_member_joined_recovery(info, &authority_recovery),
                "O's accepted roster verifies its countersigned recovery record"
            );
        }
        assert!(
            apply_named_group_metadata_event(
                &w_state,
                authority_event,
                fixture.state.agent.agent_id(),
                true,
            )
            .await,
            "W applies O's compact authority commit without gaining authority"
        );
        assert!(
            !apply_named_group_metadata_event(
                &w_state,
                authority_recovery,
                fixture.state.agent.agent_id(),
                true,
            )
            .await,
            "independent recovery delivery never mutates the roster"
        );

        // Restart W on the same directory: the durable cache is reloaded and
        // SERVES the verified event to a member-keyed catch-up requester.
        let w_agent = Arc::clone(&w_state.agent);
        let restarted = secure_endpoint_test_state_at(w_dir.path(), w_agent).await?;
        let request = TreeKemCatchupRequest {
            message_type: "treekem_catchup_request".to_string(),
            group_id: stable_group_id.clone(),
            requester_agent_id: hex::encode(restarted.agent.agent_id().as_bytes()),
            from_revision: 0,
            from_treekem_epoch: 0,
            current_state_hash: String::new(),
            missing_prev_state_hash: None,
            target_member_id: Some(member_hex.clone()),
            limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
        };
        let log_keys = vec![group_id.clone(), stable_group_id.clone()];
        let response = member_keyed_treekem_catchup_response(&restarted, &log_keys, &request)
            .await
            .expect("restarted witness serves the cached event");
        assert_eq!(response.events.len(), 1, "exactly one cached event served");
        assert!(
            verify_member_joined_key_package_event(&response.events[0]),
            "served event retains a valid member signature — independently re-verifiable"
        );
        Ok(())
    }

    /// WP-TK1 CRITICAL — admin removal recovery (issue #205): a promoted admin
    /// A that never witnessed target B's join (roster carries B Active WITHOUT a
    /// key package) recovers B's package from a peer's cached, self-signed
    /// `MemberJoined` via a member-keyed catch-up, after which the removal-path
    /// resolver returns B's package — all WITHOUT owner/inviter O or target B
    /// cooperating. The package is authenticated by B's embedded ML-DSA-65
    /// signature (re-verified on install), independent of the delivering peer,
    /// so a forged or replayed response cannot install a wrong key.
    #[tokio::test]
    async fn member_keyed_catchup_then_recovery_advances_removal_without_inviter() -> Result<()> {
        // O = owner/inviter, B = target, W = independent witness, and A = a
        // later-promoted admin. W validates and retains B's event before O
        // performs the inviter-only authoritative add.
        let fixture = member_joined_treekem_fixture(0x93, 0x94).await?;
        let o_state = Arc::clone(&fixture.state);
        let group_id = fixture.group_id.clone();
        let stable_group_id = fixture.stable_group_id.clone();
        let member_hex = fixture.member_hex.clone();
        let o_hex = hex::encode(o_state.agent.agent_id().as_bytes());
        let raw_join_event = without_recovery_attestation(fixture.event.clone());

        let (w_state, _w_dir) = secure_endpoint_test_state().await?;
        add_active_witness_to_treekem_fixture(&fixture, &w_state).await?;
        assert!(
            !apply_named_group_metadata_event(
                &w_state,
                raw_join_event.clone(),
                fixture.member_id,
                true,
            )
            .await,
            "W retains B's signed event without exercising inviter mutation authority"
        );
        assert!(
            w_state
                .treekem_member_key_packages
                .get(&join_result_key(&group_id, &member_hex))
                .await
                .is_some(),
            "independent witness W retained B's recovery record"
        );

        let _ = apply_named_group_metadata_event(&o_state, raw_join_event, fixture.member_id, true)
            .await;
        let authority_event = {
            let logs = o_state.treekem_event_log.read().await;
            logs.get(&stable_group_id)
                .and_then(|events| {
                    events.iter().find(|event| {
                        matches!(
                            event,
                            NamedGroupMetadataEvent::MemberAdded { agent_id, .. }
                                if agent_id == &member_hex
                        )
                    })
                })
                .cloned()
                .expect("O logged authority-attested MemberAdded")
        };
        let authority_recovery = o_state
            .treekem_member_key_packages
            .get(&join_result_key(&group_id, &member_hex))
            .await
            .expect("O cached authority-attested recovery");
        assert!(
            apply_named_group_metadata_event(
                &w_state,
                authority_event,
                o_state.agent.agent_id(),
                true,
            )
            .await,
            "W upgrades its provisional cache from O's authority commit"
        );
        assert!(
            !apply_named_group_metadata_event(
                &w_state,
                authority_recovery,
                o_state.agent.agent_id(),
                true,
            )
            .await,
            "separate recovery delivery upgrades W's cache without roster mutation"
        );
        let original_kp = member_treekem_kp(&o_state, &group_id, &member_hex)
            .await
            .expect("inviter O installed B's package");

        // A receives the authority-authored roster state, is promoted to Admin,
        // but never receives B's KeyPackage. O and B take no further part.
        let (a_state, _a_dir) = secure_endpoint_test_state().await?;
        let a_hex = hex::encode(a_state.agent.agent_id().as_bytes());
        let mut a_info = {
            let groups = o_state.named_groups.read().await;
            groups.get(&group_id).expect("group exists on O").clone()
        };
        a_info.members_v2.insert(
            a_hex.clone(),
            x0x::groups::GroupMember::new_member(a_hex.clone(), None, Some(o_hex.clone()), 1),
        );
        let w_hex = hex::encode(w_state.agent.agent_id().as_bytes());
        a_info.members_v2.insert(
            w_hex.clone(),
            x0x::groups::GroupMember::new_member(w_hex, None, Some(o_hex.clone()), 1),
        );
        a_info.set_member_role(&a_hex, x0x::groups::GroupRole::Admin);
        a_info.recompute_state_hash();
        a_state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), a_info);
        a_state
            .treekem_groups
            .write()
            .await
            .insert(group_id.clone(), Arc::clone(&fixture.group));
        insert_active_member_without_kp(&a_state, &group_id, &member_hex, &o_hex).await;
        {
            let groups = a_state.named_groups.read().await;
            let info = groups.get(&group_id).expect("A holds the group");
            assert!(
                require_admin_or_above(info, &a_hex).is_ok(),
                "A has independent admin authority"
            );
        }
        assert!(member_treekem_kp(&a_state, &group_id, &member_hex)
            .await
            .is_none());

        let blocked = resolve_member_treekem_kp_for_removal(&a_state, &group_id, &member_hex).await;
        let (status, body) = blocked.expect_err("removal waits for recovery evidence");
        assert_eq!(status, StatusCode::FAILED_DEPENDENCY);
        assert_eq!(body["error"], "member_key_package_pending");

        // W, not O or B, serves the original signed event. A installs it through
        // the production response handler, which re-verifies B's signature.
        let request = TreeKemCatchupRequest {
            message_type: "treekem_catchup_request".to_string(),
            group_id: stable_group_id.clone(),
            requester_agent_id: a_hex.clone(),
            from_revision: 0,
            from_treekem_epoch: 0,
            current_state_hash: String::new(),
            missing_prev_state_hash: None,
            target_member_id: Some(member_hex.clone()),
            limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
        };
        let log_keys = vec![group_id.clone(), stable_group_id];
        let response = member_keyed_treekem_catchup_response(&w_state, &log_keys, &request)
            .await
            .expect("independent witness W serves B's cached event");
        handle_treekem_catchup_response(&a_state, &w_state.agent.agent_id(), true, response).await;
        assert_eq!(
            member_treekem_kp(&a_state, &group_id, &member_hex)
                .await
                .as_deref(),
            Some(original_kp.as_str()),
            "A installed the package authenticated by B's original signature"
        );

        // Exercise the actual TreeKEM removal helper under its documented outer
        // serialization boundary. Neither O nor B is consulted after recovery.
        let membership_lock = group_membership_lock(&a_state, &group_id).await;
        let membership_guard = membership_lock.lock().await;
        let (status, body) = remove_treekem_named_group_member(
            Arc::clone(&a_state),
            group_id.clone(),
            member_hex.clone(),
            a_hex,
        )
        .await;
        drop(membership_guard);
        assert_eq!(status, StatusCode::OK, "removal failed: {body:?}");
        assert_eq!(body["removed_member"], member_hex);
        Ok(())
    }

    /// WP-TK1 CRITICAL — stale-clone serialization (issue #205): a recovered
    /// key-package install and a racing full-`GroupInfo` write-back must be
    /// serialized by the per-group membership lock, or a stale clone stored
    /// after the install erases the just-installed package. T1 holds the lock
    /// and writes a stale clone (member present, package absent — a snapshot
    /// predating the install); T2's `apply_recovered_member_key_package` BLOCKS
    /// on the lock, so its install is the final write and the package survives.
    /// Without the lock, T2 would install first and T1's stale write-back would
    /// clobber it — the exact regression the lock exists to prevent.
    #[tokio::test]
    async fn recovered_key_package_survives_stale_clone_race_under_membership_lock() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0x95, 0x96).await?;
        let state = Arc::clone(&fixture.state);
        let group_id = fixture.group_id.clone();
        let member_hex = fixture.member_hex.clone();
        let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
        let expected_kp = match &fixture.event {
            NamedGroupMetadataEvent::MemberJoined {
                treekem_key_package_b64: Some(kp),
                ..
            } => kp.clone(),
            _ => unreachable!("fixture carries a key package"),
        };

        // Roster: member Active WITHOUT a key package — the regression scenario.
        insert_active_member_without_kp(&state, &group_id, &member_hex, &inviter_hex).await;
        assert!(
            member_treekem_kp(&state, &group_id, &member_hex)
                .await
                .is_none(),
            "member starts without a key package"
        );

        // T1 acquires the per-group membership lock — the SAME lock
        // `apply_recovered_member_key_package` takes — and holds it across a
        // stale-clone write-back.
        let membership_lock = group_membership_lock(state.as_ref(), &group_id).await;
        let t1_guard = membership_lock.lock().await;

        let reached_lock_attempt = Arc::new(tokio::sync::Notify::new());
        *RECOVERED_KP_BEFORE_MEMBERSHIP_LOCK_NOTIFY
            .lock()
            .expect("recovery lock test hook poisoned") =
            Some((group_id.clone(), Arc::clone(&reached_lock_attempt)));
        // T2: production recovery install. It resolves the same lock Arc and
        // PARKS on it because T1 owns the mutex.
        let t2_state = Arc::clone(&state);
        let t2_event = fixture.event.clone();
        let t2 =
            tokio::spawn(
                async move { apply_recovered_member_key_package(&t2_state, &t2_event).await },
            );

        // The production hook fires after T2 resolves the exact per-group lock
        // and immediately before it awaits acquisition. This barrier proves T2
        // reached the contested boundary; scheduling cannot make the test pass
        // merely because the spawned task ran late.
        reached_lock_attempt.notified().await;
        *RECOVERED_KP_BEFORE_MEMBERSHIP_LOCK_NOTIFY
            .lock()
            .expect("recovery lock test hook poisoned") = None;
        assert!(
            !t2.is_finished(),
            "T2 reached the membership lock and remains blocked behind T1"
        );
        assert!(
            member_treekem_kp(&state, &group_id, &member_hex)
                .await
                .is_none(),
            "T2 is blocked on the membership lock while T1 owns it — no install yet"
        );

        // T1 writes the STALE clone under the lock: member present, key package
        // explicitly absent (a read-modify-write whose snapshot predates the
        // install). This is exactly the write-back that, unsynchronized, would
        // erase a concurrent install.
        {
            let mut groups = state.named_groups.write().await;
            if let Some(info) = groups.get_mut(&group_id) {
                if let Some(m) = info.members_v2.get_mut(&member_hex) {
                    m.treekem_key_package_b64 = None;
                    m.updated_at = 7777;
                }
            }
        }

        // Release the lock — T2 acquires it and installs as the final write.
        drop(t1_guard);
        let installed = t2.await.expect("T2 recover task panicked");
        assert!(
            installed,
            "T2 installed the recovered package after T1 released the lock"
        );

        // The package SURVIVED T1's stale-clone write-back: because the lock
        // serialized T2's install AFTER it, the install is the final word.
        assert_eq!(
            member_treekem_kp(&state, &group_id, &member_hex).await,
            Some(expected_kp),
            "package survived the stale-clone write-back — install serialized last by the membership lock"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recovered_key_package_survives_stale_disk_snapshot_write() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0xb1, 0xb2).await?;
        let state = Arc::clone(&fixture.state);
        let group_id = fixture.group_id.clone();
        let member_hex = fixture.member_hex.clone();
        let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
        insert_active_member_without_kp(&state, &group_id, &member_hex, &inviter_hex).await;

        let snapshot_reached = Arc::new(tokio::sync::Notify::new());
        let release_snapshot = Arc::new(tokio::sync::Notify::new());
        *NAMED_GROUP_SAVE_AFTER_SNAPSHOT_NOTIFY
            .lock()
            .expect("save race hook poisoned") =
            Some((Arc::clone(&snapshot_reached), Arc::clone(&release_snapshot)));
        let stale_state = Arc::clone(&state);
        let stale_save = tokio::spawn(async move { save_named_groups(&stale_state).await });
        snapshot_reached.notified().await;
        *NAMED_GROUP_SAVE_AFTER_SNAPSHOT_NOTIFY
            .lock()
            .expect("save race hook poisoned") = None;

        let recovery_state = Arc::clone(&state);
        let recovery_event = fixture.event.clone();
        let recovery = tokio::spawn(async move {
            apply_recovered_member_key_package(&recovery_state, &recovery_event).await
        });
        tokio::task::yield_now().await;
        assert!(
            !recovery.is_finished(),
            "recovery save waits behind the older persistence snapshot"
        );

        release_snapshot.notify_one();
        stale_save.await.expect("stale save task panicked");
        assert!(recovery.await.expect("recovery task panicked"));

        let persisted = tokio::fs::read_to_string(&state.named_groups_path).await?;
        let groups: HashMap<String, x0x::groups::GroupInfo> = serde_json::from_str(&persisted)?;
        assert!(
            groups
                .get(&group_id)
                .and_then(|info| info.members_v2.get(&member_hex))
                .and_then(|member| member.treekem_key_package_b64.as_ref())
                .is_some(),
            "newer recovery snapshot is the final durable write"
        );
        Ok(())
    }

    /// WP-TK1 CRITICAL — fail-closed recovery gate (issue #205): a recovered
    /// key-package install is authenticated THREE independent ways, each of
    /// which alone must refuse the install. (1) The member's ML-DSA-65 signature
    /// over the canonical bytes must verify. (2) The AgentId derived from the
    /// embedded public key must equal the claimed `member_agent_id` — an impostor
    /// signing with its own key while claiming a victim's AgentId is refused
    /// EVEN with a valid signature (AgentId-binding, the defense the existing
    /// signature/cross-group tests do not isolate). (3) The `group_id` bound into
    /// the signed bytes must match this group. A positive control at the end
    /// proves the member/roster setup is valid, so the three refusals are
    /// attributable to the specific gate, not to a setup defect.
    #[tokio::test]
    async fn recovered_member_key_package_rejects_forgery_agent_mismatch_and_cross_group(
    ) -> Result<()> {
        let fixture = member_joined_treekem_fixture(0x97, 0x98).await?;
        let state = &fixture.state;
        let group_id = fixture.group_id.clone();
        let member_hex = fixture.member_hex.clone();
        let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
        // Member is Active in the roster so rejection is attributable to the
        // specific defense under test, not "unknown member".
        insert_active_member_without_kp(state, &group_id, &member_hex, &inviter_hex).await;
        let valid_event = fixture.event.clone();

        // A compromised target can self-sign a fresh package after joining.
        // Member authentication alone is therefore insufficient: without the
        // inviter's post-acceptance countersignature, recovery must reject it.
        let member_only_event = without_recovery_attestation(valid_event.clone());
        assert!(
            !apply_recovered_member_key_package(state, &member_only_event).await,
            "member-signed package without inviter acceptance is refused"
        );
        assert!(
            member_treekem_kp(state, &group_id, &member_hex)
                .await
                .is_none(),
            "unattested member package cannot poison the sticky roster slot"
        );

        // A historical inviter cannot countersign a replacement package against
        // the old admission commit: that commit binds the exact accepted record.
        let replacement_prepared =
            x0x::mls::TreeKemMlsGroup::prepare_member(fixture.member_id, &[0xee; 32])?;
        let mut replacement = without_recovery_attestation(valid_event.clone());
        let old_commit = match &valid_event {
            NamedGroupMetadataEvent::MemberJoined {
                recovery_authority_commit: Some(commit),
                ..
            } => commit.clone(),
            _ => unreachable!("fixture carries authority commit"),
        };
        if let NamedGroupMetadataEvent::MemberJoined {
            member_public_key_b64,
            treekem_key_package_b64,
            signature_b64,
            ..
        } = &mut replacement
        {
            member_public_key_b64.clear();
            *treekem_key_package_b64 =
                Some(BASE64.encode(replacement_prepared.key_package_bytes()));
            signature_b64.clear();
        }
        let replacement = attest_member_joined_recovery_event(
            &replacement,
            state.agent.identity().agent_keypair(),
            &old_commit,
        )?;
        assert!(
            !apply_recovered_member_key_package(state, &replacement).await,
            "old admission commit cannot authorize a later replacement package"
        );

        // (1) Forged signature → refused; roster untouched.
        let forged_sig = match valid_event.clone() {
            NamedGroupMetadataEvent::MemberJoined {
                group_id,
                stable_group_id,
                member_agent_id,
                member_public_key_b64,
                role,
                display_name,
                inviter_agent_id,
                invite_secret,
                ts_ms,
                treekem_key_package_b64,
                ..
            } => NamedGroupMetadataEvent::MemberJoined {
                group_id,
                stable_group_id,
                member_agent_id,
                member_public_key_b64,
                role,
                display_name,
                inviter_agent_id,
                invite_secret,
                ts_ms,
                treekem_key_package_b64,
                recovery_authority_agent_id: None,
                recovery_authority_public_key_b64: None,
                recovery_authority_signature_b64: None,
                recovery_authority_commit: None,
                signature_b64: BASE64.encode(vec![0xcdu8; 64]),
            },
            _ => unreachable!("fixture is MemberJoined"),
        };
        assert!(
            !apply_recovered_member_key_package(state, &forged_sig).await,
            "forged signature refused"
        );
        assert!(
            member_treekem_kp(state, &group_id, &member_hex)
                .await
                .is_none(),
            "forged event installed nothing"
        );

        // (2) AgentId-binding mismatch: an impostor signs the canonical bytes
        // (claiming the victim's member_agent_id) with ITS OWN key. The
        // signature verifies, but the AgentId derived from the impostor's public
        // key != the claimed member_agent_id, so the binding check refuses. The
        // member is in the roster, so this isolates the AgentId-binding defense
        // — not "unknown member" and not a signature failure.
        let impostor = x0x::identity::AgentKeypair::generate()?;
        let impostor_pub_b64 = BASE64.encode(impostor.public_key().as_bytes());
        let agent_mismatch_event = match valid_event.clone() {
            NamedGroupMetadataEvent::MemberJoined {
                group_id,
                stable_group_id,
                role,
                display_name,
                inviter_agent_id,
                invite_secret,
                ts_ms,
                treekem_key_package_b64,
                ..
            } => {
                // Recompute canonical bytes with the impostor's public key but
                // the VICTIM's member_agent_id, then sign with the impostor key.
                let canonical = canonical_member_joined_bytes(
                    &group_id,
                    stable_group_id.as_deref(),
                    &member_hex,
                    &impostor_pub_b64,
                    role,
                    display_name.as_deref(),
                    &inviter_agent_id,
                    &invite_secret,
                    ts_ms,
                    treekem_key_package_b64.as_deref(),
                );
                let sig = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
                    impostor.secret_key(),
                    &canonical,
                )
                .map_err(|e| anyhow::anyhow!("sign impostor fixture: {e:?}"))?;
                NamedGroupMetadataEvent::MemberJoined {
                    group_id,
                    stable_group_id,
                    member_agent_id: member_hex.clone(),
                    member_public_key_b64: impostor_pub_b64,
                    role,
                    display_name,
                    inviter_agent_id,
                    invite_secret,
                    ts_ms,
                    treekem_key_package_b64,
                    recovery_authority_agent_id: None,
                    recovery_authority_public_key_b64: None,
                    recovery_authority_signature_b64: None,
                    recovery_authority_commit: None,
                    signature_b64: BASE64.encode(sig.as_bytes()),
                }
            }
            _ => unreachable!("fixture is MemberJoined"),
        };
        assert!(
            !apply_recovered_member_key_package(state, &agent_mismatch_event).await,
            "AgentId-binding mismatch refused — impostor's key does not derive to the claimed member"
        );
        assert!(
            member_treekem_kp(state, &group_id, &member_hex)
                .await
                .is_none(),
            "AgentId-mismatch event installed nothing"
        );

        // (3) Cross-group: a validly-signed event for group A is refused for a
        // different group B because group_id is bound into the signed canonical
        // bytes, so the signature fails to verify against B's group_id.
        let group_b = "99".repeat(32);
        let stable_b = "9a".repeat(32);
        let info_b = treekem_metadata_group_info(state.agent.agent_id(), &group_b, &stable_b);
        state
            .named_groups
            .write()
            .await
            .insert(group_b.clone(), info_b);
        insert_active_member_without_kp(state, &group_b, &member_hex, &inviter_hex).await;
        let cross_group_event = match valid_event.clone() {
            NamedGroupMetadataEvent::MemberJoined {
                member_agent_id,
                member_public_key_b64,
                role,
                display_name,
                inviter_agent_id,
                invite_secret,
                ts_ms,
                treekem_key_package_b64,
                signature_b64,
                ..
            } => NamedGroupMetadataEvent::MemberJoined {
                group_id: group_b.clone(),
                stable_group_id: Some(stable_b.clone()),
                member_agent_id,
                member_public_key_b64,
                role,
                display_name,
                inviter_agent_id,
                invite_secret,
                ts_ms,
                treekem_key_package_b64,
                recovery_authority_agent_id: None,
                recovery_authority_public_key_b64: None,
                recovery_authority_signature_b64: None,
                recovery_authority_commit: None,
                signature_b64,
            },
            _ => unreachable!("fixture is MemberJoined"),
        };
        assert!(
            !apply_recovered_member_key_package(state, &cross_group_event).await,
            "cross-group forgery refused — group_id is bound into the signed canonical bytes"
        );
        assert!(
            member_treekem_kp(state, &group_b, &member_hex)
                .await
                .is_none(),
            "group B roster untouched by group A's signed event"
        );

        // Positive control: the untampered valid event installs for the member,
        // proving the three refusals above were due to the specific gate, not a
        // setup defect (and that removing any one gate would let an attack in).
        assert!(
            apply_recovered_member_key_package(state, &valid_event).await,
            "valid event installs — the three gates are the only reason the above were refused"
        );
        let replacement =
            x0x::mls::TreeKemMlsGroup::prepare_member(fixture.member_id, &[0xef; 32])?;
        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_id).expect("group exists");
            info.set_member_treekem_key_package(
                &member_hex,
                BASE64.encode(replacement.key_package_bytes()),
            );
            info.members_v2
                .get_mut(&member_hex)
                .expect("member exists")
                .treekem_key_package_b64 = None;
        }
        let cache_key = join_result_key(&group_id, &member_hex);
        let aliases = HashSet::from([group_id.clone()]);
        state
            .treekem_member_key_packages
            .remove_member(&aliases, &member_hex)
            .await;
        assert!(
            !apply_named_group_metadata_event(state, valid_event.clone(), fixture.member_id, true,)
                .await,
            "self-delivered recovery evidence never exercises roster mutation authority"
        );
        assert!(
            state
                .treekem_member_key_packages
                .get(&cache_key)
                .await
                .is_none(),
            "a valid old-incarnation attestation cannot poison the current recovery cache"
        );
        assert!(
            !apply_recovered_member_key_package(state, &valid_event).await,
            "an exact prior admission cannot poison a re-added member's new package slot"
        );
        Ok(())
    }

    #[tokio::test]
    async fn provisional_witness_recovery_cache_is_bounded_per_group() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0xa7, 0xa8).await?;
        let inviter_hex = hex::encode(fixture.state.agent.agent_id().as_bytes());
        for sequence in 1..=(TREEKEM_PROVISIONAL_RECOVERY_PER_GROUP_CAP as u64 + 1) {
            let (key, event) = signed_provisional_recovery_event_for_test(
                &fixture.group_id,
                &fixture.stable_group_id,
                &inviter_hex,
                sequence,
            )?;
            let status = cache_treekem_member_key_package(&fixture.state, key, event, false).await;
            assert!(matches!(
                status,
                TreeKemCachePersistenceStatus::Durable { .. }
            ));
        }
        let provisional = fixture
            .state
            .treekem_member_key_packages
            .events_matching(|event| {
                matches!(
                    event,
                    NamedGroupMetadataEvent::MemberJoined {
                        recovery_authority_signature_b64: None,
                        ..
                    } if recovery_cache_group_identity(event) == fixture.stable_group_id
                )
            })
            .await;
        assert_eq!(
            provisional.len(),
            TREEKEM_PROVISIONAL_RECOVERY_PER_GROUP_CAP,
            "valid independently witnessed records share the bounded cache"
        );
        assert!(
            provisional
                .iter()
                .all(verify_member_joined_key_package_event),
            "every retained provisional record preserves member authentication"
        );
        let diagnostics = fixture
            .state
            .treekem_member_key_packages
            .diagnostics()
            .await;
        assert!(diagnostics.entries <= diagnostics.max_entries);
        assert!(diagnostics.encoded_bytes <= diagnostics.max_encoded_bytes);
        assert_eq!(
            durable_cache_keys(&fixture.state.treekem_member_key_packages.path)
                .await?
                .len(),
            TREEKEM_PROVISIONAL_RECOVERY_PER_GROUP_CAP,
            "per-group witness compaction is durable"
        );
        Ok(())
    }

    #[tokio::test]
    async fn request_access_treekem_approval_publishes_recoverable_attestation() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0xb3, 0xb4).await?;
        let requester = x0x::identity::AgentKeypair::generate()?;
        let requester_id = requester.agent_id();
        let requester_hex = hex::encode(requester_id.as_bytes());
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(requester_id, &[0xb5; 32])?;
        let mut request = x0x::groups::JoinRequest::new(
            fixture.group_id.clone(),
            requester_hex.clone(),
            None,
            now_millis_u64(),
        );
        request.treekem_key_package_b64 = Some(BASE64.encode(prepared.key_package_bytes()));
        let request_id = request.request_id.clone();
        fixture
            .state
            .named_groups
            .write()
            .await
            .get_mut(&fixture.group_id)
            .expect("group exists")
            .join_requests
            .insert(request_id.clone(), request);
        let caller_hex = hex::encode(fixture.state.agent.agent_id().as_bytes());
        let (status, _) = approve_treekem_join_request(
            Arc::clone(&fixture.state),
            fixture.group_id.clone(),
            request_id,
            caller_hex,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "TreeKEM request approval succeeds");

        let recovery = fixture
            .state
            .treekem_member_key_packages
            .get(&join_result_key(&fixture.group_id, &requester_hex))
            .await
            .expect("request approval caches recovery evidence");
        {
            let mut groups = fixture.state.named_groups.write().await;
            groups
                .get_mut(&fixture.group_id)
                .and_then(|info| info.members_v2.get_mut(&requester_hex))
                .expect("approved requester exists")
                .treekem_key_package_b64 = None;
        }
        assert!(
            apply_recovered_member_key_package(&fixture.state, &recovery).await,
            "approved requester's exact package remains recoverable"
        );
        Ok(())
    }

    #[tokio::test]
    async fn request_access_treekem_approval_binds_receiver_to_authority_accepted_package(
    ) -> Result<()> {
        // Authority O admits requester R via package A. An independent
        // receiver W holds a divergent local JoinRequestCreated snapshot
        // (package B). W must adopt the authority-accepted hash, discard B,
        // and later install A from the separately authority-attested recovery
        // record — proving the approval binds every receiver to O's choice.
        let fixture = member_joined_treekem_fixture(0xc1, 0xc2).await?;
        let authority_id = fixture.state.agent.agent_id();
        let authority_hex = hex::encode(authority_id.as_bytes());

        let (w_state, _w_dir) = secure_endpoint_test_state().await?;
        assert_ne!(
            w_state.agent.agent_id(),
            authority_id,
            "receiver W must be a distinct agent from the authority"
        );
        add_active_witness_to_treekem_fixture(&fixture, &w_state).await?;

        let requester = x0x::identity::AgentKeypair::generate()?;
        let requester_id = requester.agent_id();
        let requester_hex = hex::encode(requester_id.as_bytes());
        let prepared_a = x0x::mls::TreeKemMlsGroup::prepare_member(requester_id, &[0xc3; 32])?;
        let package_a_b64 = BASE64.encode(prepared_a.key_package_bytes());
        let package_a_hash = blake3::hash(package_a_b64.as_bytes()).to_hex().to_string();
        let prepared_b = x0x::mls::TreeKemMlsGroup::prepare_member(requester_id, &[0xc4; 32])?;
        let package_b_b64 = BASE64.encode(prepared_b.key_package_bytes());
        assert_ne!(
            blake3::hash(package_b_b64.as_bytes()).to_hex().to_string(),
            package_a_hash,
            "packages A and B must be distinct incarnations"
        );

        let now_ms = now_millis_u64();
        let mut request = x0x::groups::JoinRequest::new(
            fixture.group_id.clone(),
            requester_hex.clone(),
            None,
            now_ms,
        );
        request.treekem_key_package_b64 = Some(package_a_b64.clone());
        let request_id = request.request_id.clone();
        {
            let mut groups = fixture.state.named_groups.write().await;
            groups
                .get_mut(&fixture.group_id)
                .expect("authority group exists")
                .join_requests
                .insert(request_id.clone(), request.clone());
        }
        {
            let mut request_b = request.clone();
            request_b.treekem_key_package_b64 = Some(package_b_b64.clone());
            let mut groups = w_state.named_groups.write().await;
            groups
                .get_mut(&fixture.group_id)
                .expect("receiver W has the group")
                .join_requests
                .insert(request_id.clone(), request_b);
        }

        let (status, _) = approve_treekem_join_request(
            Arc::clone(&fixture.state),
            fixture.group_id.clone(),
            request_id.clone(),
            authority_hex,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "authority approves package A");

        let approval_event = {
            let logs = fixture.state.treekem_event_log.read().await;
            logs.get(&fixture.stable_group_id)
                .and_then(|events| {
                    events.iter().rev().find(|event| {
                        matches!(
                            event,
                            NamedGroupMetadataEvent::JoinRequestApproved {
                                requester_agent_id, ..
                            } if requester_agent_id == &requester_hex
                        )
                    })
                })
                .cloned()
                .expect("authority logged JoinRequestApproved")
        };
        let recovery = fixture
            .state
            .treekem_member_key_packages
            .get(&join_result_key(&fixture.group_id, &requester_hex))
            .await
            .expect("authority cached the attested recovery record");

        // (1) The approval event carries A's hash.
        let NamedGroupMetadataEvent::JoinRequestApproved {
            treekem_key_package_hash,
            ..
        } = &approval_event
        else {
            unreachable!("captured event is JoinRequestApproved");
        };
        assert_eq!(
            treekem_key_package_hash.as_deref(),
            Some(package_a_hash.as_str()),
            "approval event commits package A's hash"
        );

        // (2) Receiver W applies the authority commit/hash through the
        // production apply path, even though its local snapshot held B.
        assert!(
            apply_named_group_metadata_event(&w_state, approval_event, authority_id, true).await,
            "receiver applies the authority JoinRequestApproved commit"
        );
        {
            let groups = w_state.named_groups.read().await;
            let info = groups.get(&fixture.group_id).expect("W retains group");
            let member = info
                .members_v2
                .get(&requester_hex)
                .expect("requester admitted on W");
            assert_eq!(
                member.treekem_key_package_hash.as_deref(),
                Some(package_a_hash.as_str()),
                "receiver adopts the authority-accepted hash"
            );
            assert!(
                member.treekem_key_package_b64.is_none(),
                "receiver discards local package B — bytes do not match the committed hash"
            );
        }

        // (3) The separately authority-attested recovery record installs A.
        assert!(
            apply_recovered_member_key_package(&w_state, &recovery).await,
            "authority-attested recovery installs package A on the receiver"
        );
        {
            let groups = w_state.named_groups.read().await;
            let info = groups.get(&fixture.group_id).expect("W retains group");
            let member = info
                .members_v2
                .get(&requester_hex)
                .expect("requester present on W");
            assert_eq!(
                member.treekem_key_package_b64.as_deref(),
                Some(package_a_b64.as_str()),
                "receiver installed package A from the recovery record"
            );
            assert_eq!(
                member.treekem_key_package_hash.as_deref(),
                Some(package_a_hash.as_str()),
                "installed package A matches the committed incarnation hash"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn second_join_group_via_invite_for_present_group_returns_ok_idempotent_preserving_state(
    ) -> Result<()> {
        // Issue #188: a duplicate/replayed join cmd (retried cmd-DM,
        // redelivered invite) for an already-present group is an idempotent
        // 200 no-op — it must not mutate GroupInfo / TreeKEM state and must
        // not re-publish the MemberJoined event. Previously this returned
        // 409, which the dogfood runner surfaced as a join failure.
        let fixture = member_joined_treekem_fixture(0xd1, 0xd2).await?;
        let state = Arc::clone(&fixture.state);
        let (pre_hash, pre_epoch) = {
            let groups = state.named_groups.read().await;
            let info = groups.get(&fixture.group_id).expect("group present");
            let epoch = fixture.group.lock().await.epoch();
            (info.state_hash.clone(), epoch)
        };
        let invite = x0x::groups::invite::SignedInvite::new(
            fixture.group_id.clone(),
            "idempotent-replay".to_string(),
            &state.agent.agent_id(),
            3600,
        );
        let invite_link = invite
            .encode_link()
            .expect("minimal invite encodes under budget");
        NAMED_GROUP_METADATA_PUBLISH_ATTEMPTS_FOR_TEST
            .lock()
            .expect("publish-attempt recorder poisoned")
            .clear();
        let response = join_group_via_invite(
            State(Arc::clone(&state)),
            Json(JoinGroupRequest {
                invite: invite_link,
                display_name: None,
            }),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "duplicate join for present group is an idempotent 200, body: {body}"
        );
        assert_eq!(body["ok"], true);
        assert_eq!(
            body["already_joined"], true,
            "duplicate join is flagged as an idempotent no-op, body: {body}"
        );
        assert_eq!(body["group_id"], fixture.group_id);
        assert!(
            body["chat_topic"].as_str().is_some_and(|t| !t.is_empty()),
            "idempotent response keeps the success shape, body: {body}"
        );
        assert!(
            NAMED_GROUP_METADATA_PUBLISH_ATTEMPTS_FOR_TEST
                .lock()
                .expect("publish-attempt recorder poisoned")
                .is_empty(),
            "duplicate join must not re-publish MemberJoined"
        );
        let (post_hash, post_epoch) = {
            let groups = state.named_groups.read().await;
            let info = groups.get(&fixture.group_id).expect("group still present");
            let epoch = fixture.group.lock().await.epoch();
            (info.state_hash.clone(), epoch)
        };
        assert_eq!(post_hash, pre_hash, "GroupInfo state hash preserved");
        assert_eq!(post_epoch, pre_epoch, "TreeKEM epoch preserved");
        Ok(())
    }

    fn direct_send_test_request(agent_id: String, payload: String) -> DirectSendRequest {
        DirectSendRequest {
            agent_id,
            payload,
            prefer_raw_quic_if_connected: false,
            raw_quic_receive_ack_ms: None,
            stop_fallback_on_raw_error: false,
            require_gossip: false,
            require_gossip_ack: None,
            require_ack_ms: None,
        }
    }

    #[tokio::test]
    async fn direct_send_malformed_request_fields_stay_bad_request() -> Result<()> {
        // Issue #188 acceptance: genuinely malformed payloads remain 400.
        let (state, _dir) = secure_endpoint_test_state().await?;

        // Non-hex agent_id.
        let response = direct_send(
            State(Arc::clone(&state)),
            Json(direct_send_test_request(
                "not-hex".to_string(),
                BASE64.encode(b"hello"),
            )),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "garbage agent_id stays 400, body: {body}"
        );
        assert_eq!(body["ok"], false);

        // Well-formed agent_id, invalid base64 payload.
        let response = direct_send(
            State(state),
            Json(direct_send_test_request(
                "ab".repeat(32),
                "!!!not-base64!!!".to_string(),
            )),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "garbage base64 payload stays 400, body: {body}"
        );
        assert_eq!(body["ok"], false);
        Ok(())
    }

    #[tokio::test]
    async fn direct_send_undecodable_recipient_key_is_retryable_conflict_not_bad_request(
    ) -> Result<()> {
        // Issue #188: a cached capability advert whose KEM key does not
        // decode (the sender's not-yet-converged / corrupt view of the
        // recipient) is a transient — 409 with a distinct error string,
        // never the opaque `envelope_construction` 400 the dogfood hit.
        let (state, _dir) = secure_endpoint_test_state().await?;
        let recipient = AgentId([7u8; 32]);
        state.agent.capability_store().insert(
            recipient,
            x0x::identity::MachineId([9u8; 32]),
            x0x::dm::DmCapabilities::v1_gossip_ready(vec![0xAAu8; 32]),
            x0x::dm::now_unix_ms(),
        );
        let response = direct_send(
            State(state),
            Json(direct_send_test_request(
                hex::encode(recipient.as_bytes()),
                BASE64.encode(b"hello"),
            )),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "undecodable cached key must be a retryable 409, body: {body}"
        );
        assert_eq!(body["error"], "recipient_key_invalid");
        Ok(())
    }

    #[tokio::test]
    async fn direct_send_unready_gossip_runtime_is_retryable_503_not_bad_request() -> Result<()> {
        // Issue #188: the recipient's capability is valid but the local
        // gossip runtime is not up yet — a not-ready transient surfaced as
        // 503, never 400.
        let (state, _dir) = secure_endpoint_test_state().await?;
        let recipient = AgentId([7u8; 32]);
        let kem = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
        state.agent.capability_store().insert(
            recipient,
            x0x::identity::MachineId([9u8; 32]),
            x0x::dm::DmCapabilities::v1_gossip_ready(kem.public_bytes.clone()),
            x0x::dm::now_unix_ms(),
        );
        let response = direct_send(
            State(state),
            Json(direct_send_test_request(
                hex::encode(recipient.as_bytes()),
                BASE64.encode(b"hello"),
            )),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "not-ready gossip runtime must be a retryable 503, body: {body}"
        );
        assert_eq!(body["error"], "local_gossip_unavailable");
        Ok(())
    }

    #[tokio::test]
    async fn direct_treekem_add_publishes_recoverable_authority_attestation() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0xa4, 0xa5).await?;
        let target = x0x::identity::AgentKeypair::generate()?;
        let target_id = target.agent_id();
        let target_hex = hex::encode(target_id.as_bytes());
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(target_id, &[0xa6; 32])?;
        let (status, _) = add_treekem_named_group_member(
            Arc::clone(&fixture.state),
            fixture.group_id.clone(),
            target_id,
            AddNamedGroupMemberRequest {
                agent_id: target_hex.clone(),
                display_name: None,
                treekem_key_package_b64: Some(BASE64.encode(prepared.key_package_bytes())),
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK, "direct TreeKEM add succeeds");

        let member_added = {
            let logs = fixture.state.treekem_event_log.read().await;
            logs.values()
                .flat_map(|events| events.iter())
                .find(|event| {
                    matches!(
                        event,
                        NamedGroupMetadataEvent::MemberAdded { agent_id, .. }
                            if agent_id == &target_hex
                    )
                })
                .cloned()
                .expect("direct add records its compact MemberAdded event")
        };
        let NamedGroupMetadataEvent::MemberAdded {
            treekem_key_package_hash,
            member_joined_recovery,
            member_recovery_history,
            ..
        } = &member_added
        else {
            unreachable!("selected event is MemberAdded");
        };
        assert!(
            treekem_key_package_hash.is_some(),
            "MemberAdded commits only the admitted package hash"
        );
        assert!(
            member_joined_recovery.is_none() && member_recovery_history.is_empty(),
            "large recovery records travel as independently retryable direct events"
        );
        assert!(
            serde_json::to_vec(&member_added)?.len() <= crate::dm::MAX_PAYLOAD_BYTES,
            "the Welcome-bearing authority event must remain deliverable in one DM"
        );

        let recovery = fixture
            .state
            .treekem_member_key_packages
            .get(&join_result_key(&fixture.group_id, &target_hex))
            .await
            .expect("direct add caches authority recovery attestation");
        {
            let groups = fixture.state.named_groups.read().await;
            let info = groups.get(&fixture.group_id).expect("group exists");
            assert!(
                verify_authority_attested_member_joined_recovery(info, &recovery),
                "direct-add KeyPackage is bound to the signed admission commit"
            );
        }
        {
            let mut groups = fixture.state.named_groups.write().await;
            groups
                .get_mut(&fixture.group_id)
                .and_then(|info| info.members_v2.get_mut(&target_hex))
                .expect("direct-added member exists")
                .treekem_key_package_b64 = None;
        }
        assert!(
            apply_recovered_member_key_package(&fixture.state, &recovery).await,
            "direct-added member package can be recovered for removal"
        );
        let restarted =
            secure_endpoint_test_state_at(fixture._dir.path(), Arc::clone(&fixture.state.agent))
                .await?;
        let restarted_recovery = restarted
            .treekem_member_key_packages
            .get(&join_result_key(&fixture.group_id, &target_hex))
            .await
            .expect("authority-only direct-add recovery survives restart");
        let groups = restarted.named_groups.read().await;
        assert!(
            verify_authority_attested_member_joined_recovery(
                groups
                    .get(&fixture.group_id)
                    .expect("restarted group exists"),
                &restarted_recovery,
            ),
            "restarted direct-add recovery remains verifiable"
        );
        Ok(())
    }

    #[tokio::test]
    async fn later_joiner_installs_individually_delivered_recovery_history() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0xa1, 0xa2).await?;
        let state = &fixture.state;
        let group_id = fixture.group_id.clone();
        let stable_group_id = fixture.stable_group_id.clone();
        let first_member = fixture.member_hex.clone();
        let raw_first = without_recovery_attestation(fixture.event.clone());
        let _ = apply_named_group_metadata_event(state, raw_first, fixture.member_id, true).await;

        let later_keypair = x0x::identity::AgentKeypair::generate()?;
        let later_id = later_keypair.agent_id();
        let later_hex = hex::encode(later_id.as_bytes());
        let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
        let invite_secret = "later-joiner-history-invite".to_string();
        let now_ms = now_millis_u64();
        {
            let mut groups = state.named_groups.write().await;
            groups
                .get_mut(&group_id)
                .expect("group exists")
                .record_issued_invite(
                    invite_secret.clone(),
                    now_ms / 1_000,
                    0,
                    x0x::groups::GroupRole::Member,
                );
        }
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(later_id, &[0xa3; 32])?;
        let kp_b64 = BASE64.encode(prepared.key_package_bytes());
        let public_key_b64 = BASE64.encode(later_keypair.public_key().as_bytes());
        let canonical = canonical_member_joined_bytes(
            &group_id,
            Some(&stable_group_id),
            &later_hex,
            &public_key_b64,
            x0x::groups::GroupRole::Member,
            None,
            &inviter_hex,
            &invite_secret,
            now_ms,
            Some(&kp_b64),
        );
        let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            later_keypair.secret_key(),
            &canonical,
        )
        .map_err(|e| anyhow::anyhow!("sign later MemberJoined: {e:?}"))?;
        let later_join = NamedGroupMetadataEvent::MemberJoined {
            group_id: group_id.clone(),
            stable_group_id: Some(stable_group_id.clone()),
            member_agent_id: later_hex.clone(),
            member_public_key_b64: public_key_b64,
            role: x0x::groups::GroupRole::Member,
            display_name: None,
            inviter_agent_id: inviter_hex,
            invite_secret,
            ts_ms: now_ms,
            treekem_key_package_b64: Some(kp_b64),
            recovery_authority_agent_id: None,
            recovery_authority_public_key_b64: None,
            recovery_authority_signature_b64: None,
            recovery_authority_commit: None,
            signature_b64: BASE64.encode(signature.as_bytes()),
        };
        let _ = apply_named_group_metadata_event(state, later_join, later_id, true).await;

        let later_added = {
            let logs = state.treekem_event_log.read().await;
            logs.get(&stable_group_id)
                .and_then(|events| {
                    events.iter().rev().find(|event| {
                        matches!(
                            event,
                            NamedGroupMetadataEvent::MemberAdded { agent_id, .. }
                                if agent_id == &later_hex
                        )
                    })
                })
                .cloned()
                .expect("later MemberAdded logged")
        };
        let NamedGroupMetadataEvent::MemberAdded {
            member_recovery_history,
            ..
        } = later_added
        else {
            panic!("expected MemberAdded");
        };
        assert!(
            member_recovery_history.is_empty(),
            "recovery history must not grow the Welcome-bearing MemberAdded payload"
        );
        let prior_recovery = state
            .treekem_member_key_packages
            .events_matching(|event| {
                matches!(
                    event,
                    NamedGroupMetadataEvent::MemberJoined { member_agent_id, .. }
                        if member_agent_id == &first_member
                )
            })
            .await
            .into_iter()
            .next()
            .expect("prior authority-attested recovery record");
        assert!(
            serde_json::to_vec(&prior_recovery)?.len() < crate::dm::MAX_PAYLOAD_BYTES,
            "each independently delivered recovery record fits one DM payload"
        );
        let (later_state, _later_dir) = secure_endpoint_test_state().await?;
        let mut later_info = state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .expect("authority group exists")
            .clone();
        later_info
            .members_v2
            .get_mut(&first_member)
            .expect("prior member exists")
            .treekem_key_package_b64 = None;
        later_state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), later_info);
        assert!(
            apply_recovered_member_key_package(&later_state, &prior_recovery).await,
            "later joiner installs a separately delivered historical recovery record"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recovered_member_key_package_survives_inviter_demotion() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0x9d, 0x9e).await?;
        let state = &fixture.state;
        let group_id = fixture.group_id.clone();
        let member_hex = fixture.member_hex.clone();
        let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
        insert_active_member_without_kp(state, &group_id, &member_hex, &inviter_hex).await;
        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_id).expect("group exists");
            info.set_member_role(&inviter_hex, x0x::groups::GroupRole::Member);
            info.recompute_state_hash();
        }

        assert!(
            apply_recovered_member_key_package(state, &fixture.event).await,
            "historical signed admission remains valid after inviter demotion"
        );
        assert!(
            member_treekem_kp(state, &group_id, &member_hex)
                .await
                .is_some(),
            "recovery depends on historical commit authority, not current role"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recovered_member_key_package_rejects_unauthorized_and_revoked_couriers() -> Result<()>
    {
        let fixture = member_joined_treekem_fixture(0x9b, 0x9c).await?;
        let state = &fixture.state;
        let group_id = fixture.group_id.clone();
        let member_hex = fixture.member_hex.clone();
        let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
        insert_active_member_without_kp(state, &group_id, &member_hex, &inviter_hex).await;

        let response = TreeKemCatchupResponse {
            message_type: "treekem_catchup_response".to_string(),
            group_id: fixture.stable_group_id.clone(),
            events: vec![fixture.event.clone()],
            truncated: false,
        };
        let unauthorized = x0x::identity::AgentKeypair::generate()?;
        handle_treekem_catchup_response(state, &unauthorized.agent_id(), true, response.clone())
            .await;
        assert!(
            member_treekem_kp(state, &group_id, &member_hex)
                .await
                .is_none(),
            "verified transport alone does not authorize an unsolicited recovery courier"
        );

        let courier = x0x::identity::AgentKeypair::generate()?;
        let courier_id = courier.agent_id();
        let courier_hex = hex::encode(courier_id.as_bytes());
        insert_active_member_without_kp(state, &group_id, &courier_hex, &inviter_hex).await;
        let revocation = x0x::revocation::RevocationRecord::sign(
            x0x::revocation::RevokedSubject::Agent(courier_id),
            courier.public_key(),
            courier.secret_key(),
            now_millis_u64(),
            Some("recovery courier compromised".to_string()),
        )?;
        state
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(revocation, None)?;
        handle_treekem_catchup_response(state, &courier_id, true, response).await;
        assert!(
            member_treekem_kp(state, &group_id, &member_hex)
                .await
                .is_none(),
            "revoked active member cannot courier recovery evidence"
        );
        Ok(())
    }

    /// A newly created private TreeKEM group provisions a creator recovery
    /// package that is fully authority-attested (signed by the creator-as-admin
    /// over the sealed group-state commit), whose package hashes to the live
    /// roster incarnation, and which reinstalls itself on demand after the
    /// roster bytes are wiped. Driven through the real POST /groups handler so
    /// the entire production create-group TreeKEM provisioning path is
    /// exercised — no production logic is re-implemented in the test.
    #[tokio::test]
    async fn creator_package_is_authority_attested_and_recoverable_after_roster_wipe() -> Result<()>
    {
        let (state, _dir) = secure_endpoint_test_state().await?;

        // Drive the real production create-group handler with a private-secure
        // request, which routes through the secure-by-default TreeKEM path and
        // provisions the creator's attested recovery package.
        let response = create_named_group(
            State(Arc::clone(&state)),
            Json(CreateGroupRequest {
                name: "secure".to_string(),
                description: String::new(),
                display_name: None,
                preset: Some("private_secure".to_string()),
            }),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "private TreeKEM group created via handler: {body}"
        );
        let group_id = body["group_id"]
            .as_str()
            .expect("group_id in create response")
            .to_string();
        let creator_hex = hex::encode(state.agent.agent_id().as_bytes());

        // (1) The creator package was provisioned as a fully authority-attested
        //     recovery record: it carries an authority signature over the
        //     sealed group-state commit (not merely a member self-signature).
        let cached = state
            .treekem_member_key_packages
            .get(&join_result_key(&group_id, &creator_hex))
            .await
            .expect("creator recovery record is cached at group creation");
        let cached_package = match &cached {
            NamedGroupMetadataEvent::MemberJoined {
                recovery_authority_agent_id: Some(auth),
                recovery_authority_signature_b64: Some(sig),
                recovery_authority_commit: Some(commit),
                treekem_key_package_b64: Some(kp),
                ..
            } if !auth.is_empty() && !sig.is_empty() && commit.verify_structure().is_ok() => {
                kp.clone()
            }
            _ => panic!("creator recovery record is authority-attested over the sealed commit"),
        };

        // (2) The cached package matches the current roster incarnation: the
        //     resolver's hash gate (blake3(package) == roster hash) admits it.
        let roster_package = {
            let groups = state.named_groups.read().await;
            groups
                .get(&group_id)
                .and_then(|info| info.members_v2.get(&creator_hex))
                .and_then(current_member_treekem_key_package)
        };
        assert_eq!(
            roster_package.as_deref(),
            Some(cached_package.as_str()),
            "creator package hashes to the current roster incarnation"
        );

        // (3) Wipe the roster bytes (a stale GroupInfo write-back or cache miss
        //     that dropped the in-roster package). The hash is retained, so the
        //     gate must refuse to serve anything from the roster alone.
        {
            let mut groups = state.named_groups.write().await;
            groups
                .get_mut(&group_id)
                .expect("group exists")
                .members_v2
                .get_mut(&creator_hex)
                .expect("creator exists")
                .treekem_key_package_b64 = None;
        }
        let gated = {
            let groups = state.named_groups.read().await;
            groups
                .get(&group_id)
                .and_then(|info| info.members_v2.get(&creator_hex))
                .and_then(current_member_treekem_key_package)
        };
        assert!(
            gated.is_none(),
            "with roster bytes wiped, the hash gate serves no unverified package"
        );

        // (4) On-demand recovery signature-verifies the cached attested record
        //     and reinstalls the exact package, restoring the hash-matched leaf.
        let recovered = recover_member_treekem_key_package(&state, &group_id, &creator_hex).await;
        assert!(
            recovered,
            "creator package recovered from the authority-attested cache after a roster wipe"
        );
        let restored = {
            let groups = state.named_groups.read().await;
            groups
                .get(&group_id)
                .and_then(|info| info.members_v2.get(&creator_hex))
                .and_then(current_member_treekem_key_package)
        };
        assert_eq!(
            restored.as_deref(),
            Some(cached_package.as_str()),
            "recovered creator package still hashes to the current roster incarnation"
        );
        Ok(())
    }

    /// Replacing a member's committed incarnation hash wipes any stale package
    /// bytes from the roster, and the removal-path resolver never serves a
    /// package whose hash no longer matches the current incarnation — even when
    /// a fully authority-attested record for the superseded package is sitting
    /// in the recovery cache. This pins the incarnation-invalidation invariant:
    /// a re-keyed or re-added member's old KeyPackage cannot be replayed.
    #[tokio::test]
    async fn replacing_incarnation_hash_clears_stale_package_bytes() -> Result<()> {
        let fixture = member_joined_treekem_fixture(0x91, 0x92).await?;
        let state = &fixture.state;
        let group_id = fixture.group_id.clone();
        let member_hex = fixture.member_hex.clone();
        let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());

        // The fixture leaves the member soft-removed with the original
        // incarnation hash retained; re-activate them and install the matching
        // package bytes so the resolver currently serves it.
        let original_package = match fixture.event.clone() {
            NamedGroupMetadataEvent::MemberJoined {
                treekem_key_package_b64: Some(kp),
                ..
            } => kp,
            _ => unreachable!("fixture event carries a key package"),
        };
        insert_active_member_without_kp(state, &group_id, &member_hex, &inviter_hex).await;
        {
            let mut groups = state.named_groups.write().await;
            groups
                .get_mut(&group_id)
                .expect("group exists")
                .set_member_treekem_key_package(&member_hex, original_package.clone());
        }

        // Sanity: the resolver currently serves the installed, incarnation-matched package.
        let served = resolve_member_treekem_kp_for_removal(state, &group_id, &member_hex)
            .await
            .expect("resolver serves the current incarnation package");
        assert_eq!(
            served, original_package,
            "resolver returns the package whose hash matches the current incarnation"
        );

        // Seed the recovery cache with the authority-attested record for the
        // ORIGINAL package — the stale evidence that must NOT be replayable.
        state
            .treekem_member_key_packages
            .insert(
                join_result_key(&group_id, &member_hex),
                fixture.event.clone(),
                true,
            )
            .await?;

        // Replace the member's incarnation hash (a re-key / re-add). The setter
        // MUST wipe the now-stale package bytes because they no longer match.
        let new_incarnation_hash = blake3::hash(b"a-fresh-rotated-key-package")
            .to_hex()
            .to_string();
        {
            let mut groups = state.named_groups.write().await;
            groups
                .get_mut(&group_id)
                .expect("group exists")
                .set_member_treekem_key_package_hash(&member_hex, new_incarnation_hash.clone());
        }
        let (stale_bytes, recorded_hash) = {
            let groups = state.named_groups.read().await;
            let member = groups
                .get(&group_id)
                .and_then(|info| info.members_v2.get(&member_hex))
                .expect("member exists");
            (
                member.treekem_key_package_b64.clone(),
                member.treekem_key_package_hash.clone(),
            )
        };
        assert!(
            stale_bytes.is_none(),
            "stale package bytes are wiped when the incarnation hash changes"
        );
        assert_eq!(
            recorded_hash.as_deref(),
            Some(new_incarnation_hash.as_str()),
            "the new incarnation hash is recorded"
        );

        // The resolver refuses to serve the stale package: the roster has no
        // hash-matched bytes, and recovery cannot install the cached attested
        // record because its package hashes to the superseded incarnation.
        let resolved = resolve_member_treekem_kp_for_removal(state, &group_id, &member_hex).await;
        assert!(
            resolved.is_err(),
            "resolver never returns a hash-mismatched stale package, even with attested cache evidence"
        );
        let (status, body) = resolved.expect_err("pending error");
        assert_eq!(
            status,
            StatusCode::FAILED_DEPENDENCY,
            "a missing current-incarnation package is a retryable pending condition"
        );
        assert_eq!(body["error"], "member_key_package_pending");
        assert_eq!(body["retry"], true);
        Ok(())
    }

    fn without_recovery_attestation(mut event: NamedGroupMetadataEvent) -> NamedGroupMetadataEvent {
        if let NamedGroupMetadataEvent::MemberJoined {
            recovery_authority_agent_id,
            recovery_authority_public_key_b64,
            recovery_authority_signature_b64,
            recovery_authority_commit,
            ..
        } = &mut event
        {
            *recovery_authority_agent_id = None;
            *recovery_authority_public_key_b64 = None;
            *recovery_authority_signature_b64 = None;
            *recovery_authority_commit = None;
        }
        event
    }

    async fn set_member_state(
        state: &Arc<AppState>,
        group_id: &str,
        member: &str,
        new_state: x0x::groups::GroupMemberState,
    ) {
        let mut groups = state.named_groups.write().await;
        if let Some(info) = groups.get_mut(group_id) {
            if let Some(m) = info.members_v2.get_mut(member) {
                m.state = new_state;
                m.treekem_key_package_b64 = None;
                m.updated_at = 2;
            }
        }
    }

    async fn member_treekem_kp(
        state: &Arc<AppState>,
        group_id: &str,
        member: &str,
    ) -> Option<String> {
        let groups = state.named_groups.read().await;
        groups
            .get(group_id)
            .and_then(|info| info.members_v2.get(member))
            .and_then(|m| m.treekem_key_package_b64.clone())
    }

    async fn insert_active_member_without_kp(
        state: &Arc<AppState>,
        group_id: &str,
        member: &str,
        added_by: &str,
    ) {
        let mut groups = state.named_groups.write().await;
        if let Some(info) = groups.get_mut(group_id) {
            let package_hash = info
                .members_v2
                .get(member)
                .and_then(|existing| existing.treekem_key_package_hash.clone());
            let mut active = x0x::groups::GroupMember::new_member(
                member.to_string(),
                None,
                Some(added_by.to_string()),
                1,
            );
            active.treekem_key_package_hash = package_hash;
            info.members_v2.insert(member.to_string(), active);
        }
    }

    fn signed_provisional_recovery_event_for_test(
        group_id: &str,
        stable_group_id: &str,
        inviter_agent_id: &str,
        sequence: u64,
    ) -> Result<(String, NamedGroupMetadataEvent)> {
        let member_keypair = x0x::identity::AgentKeypair::generate()?;
        let member_id = member_keypair.agent_id();
        let member_hex = hex::encode(member_id.as_bytes());
        let member_public_key_b64 = BASE64.encode(member_keypair.public_key().as_bytes());
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_id, &[sequence as u8; 32])?;
        let key_package = BASE64.encode(prepared.key_package_bytes());
        let invite_secret = format!("witness-cache-{sequence}");
        let canonical = canonical_member_joined_bytes(
            group_id,
            Some(stable_group_id),
            &member_hex,
            &member_public_key_b64,
            x0x::groups::GroupRole::Member,
            None,
            inviter_agent_id,
            &invite_secret,
            sequence,
            Some(&key_package),
        );
        let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            member_keypair.secret_key(),
            &canonical,
        )
        .map_err(|e| anyhow::anyhow!("sign provisional recovery fixture: {e:?}"))?;
        let event = NamedGroupMetadataEvent::MemberJoined {
            group_id: group_id.to_string(),
            stable_group_id: Some(stable_group_id.to_string()),
            member_agent_id: member_hex.clone(),
            member_public_key_b64,
            role: x0x::groups::GroupRole::Member,
            display_name: None,
            inviter_agent_id: inviter_agent_id.to_string(),
            invite_secret,
            ts_ms: sequence,
            treekem_key_package_b64: Some(key_package),
            recovery_authority_agent_id: None,
            recovery_authority_public_key_b64: None,
            recovery_authority_signature_b64: None,
            recovery_authority_commit: None,
            signature_b64: BASE64.encode(signature.as_bytes()),
        };
        Ok((join_result_key(group_id, &member_hex), event))
    }

    /// Read the durable cache JSON and return its key set. Used to prove the
    /// on-disk state — not just the in-memory cache — after loader/lifecycle
    /// operations.
    async fn durable_cache_keys(path: &FsPath) -> Result<HashSet<String>> {
        let on_disk = tokio::fs::read_to_string(path).await?;
        let parsed: BTreeMap<String, serde_json::Value> = serde_json::from_str(&on_disk)?;
        Ok(parsed.into_keys().collect())
    }
}
