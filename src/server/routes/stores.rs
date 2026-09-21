//! Route handlers (`category: "stores"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use super::super::crdt_subscriptions;
use super::super::state::AppState;
use super::super::{
    api_error, api_error_with_reason, bad_request, direct_message_send_config, forbidden,
    not_found, parse_agent_id_hex,
};
use super::named_groups::GROUP_BACKGROUND_PUBLISH_DELAY;
use crate as x0x;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use x0x::contacts::TrustLevel;
use x0x::identity::AgentId;
use x0x::kv::encrypted::KvSecureContext;
use x0x::logging::LogHexId;

const LEGACY_PAGE_SNAPSHOT_MAX_BYTES: u64 = 20 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub(in crate::server) struct ImportLegacyStoreRequest {
    source_digest: String,
    idempotency_key: String,
}

#[derive(Debug, Serialize)]
struct LegacyStoreCandidate {
    target_group_id: String,
    source_store_id: String,
    topic: String,
    owner: String,
    source_digest: String,
    active_keys: usize,
    keys: Vec<String>,
    ambiguous_group_prefix: bool,
    conflicts: Vec<String>,
    imported: bool,
    import_pending: bool,
    publish_pending: bool,
    publish_accepted: bool,
    import_idempotency_key: Option<String>,
    can_import: bool,
    import_refusal_reason: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(in crate::server) struct LegacyDownloadQuery {
    idempotency_key: Option<String>,
}

struct LoadedLegacyStore {
    store: x0x::kv::KvStore,
    store_id_hex: String,
    topic: String,
    owner: AgentId,
    digest: String,
    bytes: Vec<u8>,
}

pub(in crate::server) const KV_STORE_DELTA_DM_PREFIX: &[u8] = b"X0X-KV-DELTA-V1\n";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::server) struct KvStoreDirectDelta {
    store_id: String,
    peer_id: saorsa_gossip_types::PeerId,
    delta: x0x::kv::KvStoreDelta,
}

fn encode_kv_store_delta_direct_payload(
    store_id: &str,
    peer_id: saorsa_gossip_types::PeerId,
    delta: &x0x::kv::KvStoreDelta,
) -> serde_json::Result<Vec<u8>> {
    let msg = KvStoreDirectDelta {
        store_id: store_id.to_string(),
        peer_id,
        delta: delta.clone(),
    };
    let json = serde_json::to_vec(&msg)?;
    let mut payload = Vec::with_capacity(KV_STORE_DELTA_DM_PREFIX.len() + json.len());
    payload.extend_from_slice(KV_STORE_DELTA_DM_PREFIX);
    payload.extend_from_slice(&json);
    Ok(payload)
}

fn kv_store_delta_direct_delivery_config() -> x0x::dm::DmSendConfig {
    let mut config = direct_message_send_config();
    config.require_gossip = true;
    config.require_gossip_ack = true;
    config
}

async fn kv_store_delta_direct_recipients(state: &AppState) -> Vec<String> {
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let contacts = state.contacts.read().await;
    contacts
        .list()
        .into_iter()
        .filter_map(|contact| {
            let recipient = hex::encode(contact.agent_id.as_bytes());
            if recipient == local_agent_hex || contact.trust_level == TrustLevel::Blocked {
                return None;
            }
            let caps = contact.dm_capabilities.as_ref()?;
            if !caps.gossip_inbox || caps.kem_public_key.is_empty() {
                return None;
            }
            Some(recipient)
        })
        .collect()
}

fn spawn_kv_store_delta_delivery_one(
    state: &AppState,
    recipient_hex: &str,
    store_id: &str,
    peer_id: saorsa_gossip_types::PeerId,
    delta: &x0x::kv::KvStoreDelta,
    delay: Option<Duration>,
) {
    let recipient = match parse_agent_id_hex(recipient_hex) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(
                recipient = %LogHexId::agent(&recipient_hex),
                "cannot direct-deliver kv-store delta: invalid recipient id: {e}"
            );
            return;
        }
    };
    let payload = match encode_kv_store_delta_direct_payload(store_id, peer_id, delta) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!(
                store_id,
                "failed to serialize kv-store delta for direct delivery: {e}"
            );
            return;
        }
    };
    let agent = Arc::clone(&state.agent);
    let recipient_label = recipient_hex.to_string();
    let store_label = store_id.to_string();
    tokio::spawn(async move {
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        if let Err(e) = agent
            .send_direct_with_config(&recipient, payload, kv_store_delta_direct_delivery_config())
            .await
        {
            tracing::warn!(
                store_id = %store_label,
                recipient = %LogHexId::agent(&recipient_label),
                "failed to direct-deliver kv-store delta: {e}"
            );
        }
    });
}

fn spawn_kv_store_delta_delivery(
    state: &AppState,
    recipients: Vec<String>,
    store_id: &str,
    peer_id: saorsa_gossip_types::PeerId,
    delta: &x0x::kv::KvStoreDelta,
) {
    for recipient in recipients {
        spawn_kv_store_delta_delivery_one(state, &recipient, store_id, peer_id, delta, None);
        spawn_kv_store_delta_delivery_one(
            state,
            &recipient,
            store_id,
            peer_id,
            delta,
            Some(GROUP_BACKGROUND_PUBLISH_DELAY),
        );
    }
}

pub(in crate::server) async fn apply_direct_kv_store_delta(
    state: &AppState,
    sender: x0x::identity::AgentId,
    delta_msg: KvStoreDirectDelta,
) {
    let store_id = delta_msg.store_id.clone();
    let handle = {
        let stores = state.kv_stores.read().await;
        stores.get(&store_id).cloned()
    };
    let Some(handle) = handle else {
        tracing::debug!(
            store_id = %store_id,
            sender = %hex::encode(sender.as_bytes()),
            "ignoring direct kv-store delta for unjoined store"
        );
        return;
    };
    if let Err(e) = handle
        .apply_remote_delta(delta_msg.peer_id, &delta_msg.delta, Some(sender))
        .await
    {
        tracing::warn!(
            store_id = %store_id,
            "failed to apply direct kv-store delta: {e}"
        );
    }
}

/// Request body for POST /stores.
///
/// `policy` selects the access policy: `"signed"` (default — owner-only
/// writes), `"append_only"` (owner-only writes AND existing keys are
/// immutable, even to the owner), or `"self_keyed"` (owner-free open
/// directory: any joiner writes only keys prefixed by its own AgentId).
#[derive(Debug, Deserialize)]
pub(in crate::server) struct CreateStoreRequest {
    name: String,
    topic: String,
    policy: Option<String>,
}

/// Request body for PUT /stores/:id/:key.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct PutValueRequest {
    value: String,
    content_type: Option<String>,
}

/// Request body for POST /stores/:id/join.
///
/// `expected_owner` is the optional hex-encoded AgentId of the authoritative
/// owner, supplied out-of-band (the local user/operator is the trust root).
/// Omitting it yields a permanently read-only replica (no permissive
/// fallback) — EXCEPT under `policy: "self_keyed"`, the owner-free directory
/// policy, which requires joining WITHOUT an owner.
#[derive(Debug, Default, Deserialize)]
pub(in crate::server) struct JoinStoreRequest {
    expected_owner: Option<String>,
    /// Optional policy discriminator for the join. `"self_keyed"` selects
    /// the owner-free directory join (no `expected_owner` allowed); any
    /// other value is ignored in favor of the owner-anchored path.
    policy: Option<String>,
}

/// Response entry for GET /stores.
#[derive(Debug, Serialize)]
pub(in crate::server) struct StoreListEntry {
    id: String,
    topic: String,
    /// Hex-encoded anchored owner, or `null` for a read-only no-anchor store.
    owner: Option<String>,
    /// Access policy string.
    policy: String,
    /// Store version.
    version: u64,
    /// Owner-announce policy freshness counter.
    policy_version: u64,
    /// Strongly-typed ownership discriminant.
    ownership_status: x0x::kv::OwnershipStatus,
    /// True while snapshot persistence is failing (local writes refused
    /// until a snapshot succeeds).
    durability_degraded: bool,
}

/// GET /stores
pub(in crate::server) async fn list_kv_stores(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Snapshot (id, handle) pairs without holding the read lock across the
    // per-store ownership_info() awaits.
    let pairs: Vec<(String, x0x::KvStoreHandle)> = {
        let stores = state.kv_stores.read().await;
        stores
            .iter()
            .map(|(id, h)| (id.clone(), h.clone()))
            .collect()
    };
    let mut entries = Vec::with_capacity(pairs.len());
    for (id, handle) in pairs {
        let info = handle.ownership_info().await;
        entries.push(StoreListEntry {
            topic: id.clone(),
            id,
            owner: info.owner,
            policy: info.policy,
            version: info.version,
            policy_version: info.policy_version,
            ownership_status: info.ownership_status,
            durability_degraded: info.durability_degraded,
        });
    }
    Json(serde_json::json!({ "ok": true, "stores": entries }))
}

/// POST /stores
pub(in crate::server) async fn create_kv_store(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateStoreRequest>,
) -> impl IntoResponse {
    let id = req.topic.clone();
    // Resolve the requested access policy before any state is reserved.
    let policy = match req.policy.as_deref() {
        None | Some("signed") => x0x::kv::AccessPolicy::Signed,
        Some("append_only") => x0x::kv::AccessPolicy::AppendOnly,
        Some("self_keyed") => x0x::kv::AccessPolicy::SelfKeyed,
        Some(other) => {
            return bad_request(format!(
            "unsupported policy {other:?}: expected \"signed\", \"append_only\", or \"self_keyed\""
        ))
        }
    };
    // Reserve the entire handle+manifest transaction for this (kind,id) so
    // a concurrent create/rehydrate for the same id cannot interleave handle
    // insertion with failure rollback, or spawn a duplicate listener.
    let reservation =
        crdt_subscriptions::handle_reservation(&state, crdt_subscriptions::KIND_KV_STORE, &id)
            .await;
    let _guard = reservation.lock().await;
    // Under the reservation: if a handle already exists (created by a prior
    // successful request or rehydration), return conflict rather than
    // overwriting it and leaking the existing sync listener.
    if state.kv_stores.read().await.contains_key(&id) {
        return api_error(StatusCode::CONFLICT, "store already exists");
    }
    let policy_str = policy.to_string();
    // A self_keyed directory is owner-free for life: no expected_owner is
    // recorded for it (I3/I4) — rehydrate derives everything from the topic.
    let is_self_keyed = matches!(policy, x0x::kv::AccessPolicy::SelfKeyed);
    match state
        .agent
        .create_kv_store_persistent(&req.name, &req.topic, policy, &state.kv_store_state_dir)
        .await
    {
        Ok(handle) => {
            let info = handle.ownership_info().await;
            state.kv_stores.write().await.insert(id.clone(), handle);
            // Persist the registration so it survives a daemon restart
            // (rehydrated after join_network — see crdt_subscriptions).
            // Record the owner so a restarted creator re-anchors on itself.
            let mut extra = serde_json::Map::new();
            if !is_self_keyed {
                let owner_hex = hex::encode(state.agent.agent_id().as_bytes());
                extra.insert(
                    "expected_owner".to_string(),
                    serde_json::Value::String(owner_hex),
                );
            }
            // Persist the policy so a restarted creator rehydrates with the
            // same policy (an append-only store must never come back Signed).
            extra.insert("policy".to_string(), serde_json::Value::String(policy_str));
            if let Err(e) = crdt_subscriptions::record(
                &state,
                crdt_subscriptions::CrdtSubscriptionEntry {
                    kind: crdt_subscriptions::KIND_KV_STORE.to_string(),
                    id: id.clone(),
                    name: req.name.clone(),
                    topic: req.topic.clone(),
                    role: crdt_subscriptions::ROLE_CREATED.to_string(),
                    extra,
                },
            )
            .await
            {
                // Durable write failed: roll back the live handle so success is
                // not acknowledged for an un-persisted registration, and STOP
                // its sync — the discarded handle's bootstrap requester is
                // infinite while unconverged (issue #238) and would otherwise
                // chatter until daemon shutdown.
                tracing::error!("failed to persist kv store registration {id}: {e}");
                if let Some(h) = state.kv_stores.write().await.remove(&id) {
                    h.cancel_sync();
                }
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to persist subscription registration: {e}"),
                );
            }
            let mut resp = serde_json::to_value(&info).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(obj) = resp.as_object_mut() {
                obj.insert("ok".to_string(), serde_json::Value::Bool(true));
                obj.insert("id".to_string(), serde_json::Value::String(id));
            }
            (StatusCode::CREATED, Json(resp))
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// POST /stores/:id/join
pub(in crate::server) async fn join_kv_store(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Option<Json<JoinStoreRequest>>,
) -> impl IntoResponse {
    let body = body.map(|Json(r)| r).unwrap_or_default();
    // The `self_keyed` directory policy is the one owner-free join: knowing
    // only the topic is enough (I4). An `expected_owner` anchor is not
    // merely unnecessary there — it is contradictory (the store has no owner
    // for life, I3), so supplying one is a 422 rather than a silent ignore.
    if body.policy.as_deref() == Some("self_keyed") {
        if body.expected_owner.is_some() {
            return api_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "owner_not_allowed: policy \"self_keyed\" stores have no owner — join without expected_owner",
            );
        }
        return join_self_keyed_store(state, id).await;
    }
    // The out-of-band owner anchor is REQUIRED for every owner-anchored
    // policy: a replica with no anchor can never accept policy-restricted
    // data, so an unanchored join is a dead replica, not a successful join.
    // The local user/operator is the trust root for this param.
    let owner: AgentId = match body.expected_owner {
        Some(hex_owner) => match parse_agent_id_hex(&hex_owner) {
            Ok(agent) => agent,
            Err(e) => return bad_request(format!("invalid expected_owner: {e}")),
        },
        None => {
            return api_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "owner_required: an expected_owner anchor is required to join a store",
            )
        }
    };
    // Reserve the entire handle+manifest transaction for this (kind,id) so
    // a concurrent join/rehydrate for the same id cannot interleave handle
    // insertion with failure rollback, or spawn a duplicate listener.
    let reservation =
        crdt_subscriptions::handle_reservation(&state, crdt_subscriptions::KIND_KV_STORE, &id)
            .await;
    let _guard = reservation.lock().await;
    // Under the reservation: if a handle already exists (created by a prior
    // successful request or rehydration), return conflict rather than
    // overwriting it and leaking the existing sync listener.
    if state.kv_stores.read().await.contains_key(&id) {
        return api_error(StatusCode::CONFLICT, "store already joined");
    }
    match state
        .agent
        .join_kv_store_persistent(
            &id,
            owner,
            x0x::kv::store::AnchorChannel::RestParam,
            &state.kv_store_state_dir,
        )
        .await
    {
        Ok(handle) => {
            let info = handle.ownership_info().await;
            state.kv_stores.write().await.insert(id.clone(), handle);
            // Persist the registration so it survives a daemon restart
            // (rehydrated after join_network — see crdt_subscriptions). The
            // join path only knows the topic, so it doubles as the name.
            // Record the anchor so rehydrate re-anchors on the same owner.
            let mut extra = serde_json::Map::new();
            extra.insert(
                "expected_owner".to_string(),
                serde_json::Value::String(hex::encode(owner.as_bytes())),
            );
            if let Err(e) = crdt_subscriptions::record(
                &state,
                crdt_subscriptions::CrdtSubscriptionEntry {
                    kind: crdt_subscriptions::KIND_KV_STORE.to_string(),
                    id: id.clone(),
                    name: id.clone(),
                    topic: id.clone(),
                    role: crdt_subscriptions::ROLE_JOINED.to_string(),
                    extra,
                },
            )
            .await
            {
                // Durable write failed: roll back the live handle so success is
                // not acknowledged for an un-persisted registration, and STOP
                // its sync — the discarded handle's bootstrap requester is
                // infinite while unconverged (issue #238) and would otherwise
                // chatter until daemon shutdown.
                tracing::error!("failed to persist kv store join {id}: {e}");
                if let Some(h) = state.kv_stores.write().await.remove(&id) {
                    h.cancel_sync();
                }
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to persist subscription registration: {e}"),
                );
            }
            let mut resp = serde_json::to_value(&info).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(obj) = resp.as_object_mut() {
                obj.insert("ok".to_string(), serde_json::Value::Bool(true));
                obj.insert("id".to_string(), serde_json::Value::String(id));
            }
            (StatusCode::OK, Json(resp))
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// Owner-free join for `self_keyed` directory stores (issue #340).
///
/// Shared tail of `POST /stores/:id/join` for the `policy: "self_keyed"`
/// body: reserves the (kind,id), joins by topic alone, and persists a
/// manifest entry whose `extra` records the policy but deliberately OMITS
/// `expected_owner` (the store has none — rehydrate must not require one).
async fn join_self_keyed_store(
    state: Arc<AppState>,
    id: String,
) -> (StatusCode, Json<serde_json::Value>) {
    let reservation =
        crdt_subscriptions::handle_reservation(&state, crdt_subscriptions::KIND_KV_STORE, &id)
            .await;
    let _guard = reservation.lock().await;
    if state.kv_stores.read().await.contains_key(&id) {
        return api_error(StatusCode::CONFLICT, "store already joined");
    }
    match state
        .agent
        .join_self_keyed_kv_store_persistent(&id, &state.kv_store_state_dir)
        .await
    {
        Ok(handle) => {
            let info = handle.ownership_info().await;
            state.kv_stores.write().await.insert(id.clone(), handle);
            let mut extra = serde_json::Map::new();
            // No expected_owner: a self_keyed store is owner-free for life.
            extra.insert(
                "policy".to_string(),
                serde_json::Value::String("self_keyed".to_string()),
            );
            if let Err(e) = crdt_subscriptions::record(
                &state,
                crdt_subscriptions::CrdtSubscriptionEntry {
                    kind: crdt_subscriptions::KIND_KV_STORE.to_string(),
                    id: id.clone(),
                    name: id.clone(),
                    topic: id.clone(),
                    role: crdt_subscriptions::ROLE_JOINED.to_string(),
                    extra,
                },
            )
            .await
            {
                tracing::error!("failed to persist kv store join {id}: {e}");
                if let Some(h) = state.kv_stores.write().await.remove(&id) {
                    h.cancel_sync();
                }
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to persist subscription registration: {e}"),
                );
            }
            let mut resp = serde_json::to_value(&info).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(obj) = resp.as_object_mut() {
                obj.insert("ok".to_string(), serde_json::Value::Bool(true));
                obj.insert("id".to_string(), serde_json::Value::String(id));
            }
            (StatusCode::OK, Json(resp))
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /stores/:id/keys
pub(in crate::server) async fn list_kv_keys(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let handle = {
        let stores = state.kv_stores.read().await;
        let Some(handle) = stores.get(&id) else {
            return not_found("store not found");
        };
        handle.clone()
    };

    match handle.keys().await {
        Ok(entries) => {
            let keys: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "key": e.key,
                        "content_type": e.content_type,
                        "content_hash": e.content_hash,
                        "size": e.value.len(),
                        "updated_at": e.updated_at,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "keys": keys })),
            )
        }
        Err(e) if matches!(e, x0x::error::IdentityError::Unauthorized(_)) => {
            api_error(StatusCode::FORBIDDEN, format!("{e}"))
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// PUT /stores/:id/:key
pub(in crate::server) async fn put_kv_value(
    State(state): State<Arc<AppState>>,
    Path((id, key)): Path<(String, String)>,
    Json(req): Json<PutValueRequest>,
) -> impl IntoResponse {
    let handle = {
        let stores = state.kv_stores.read().await;
        let Some(handle) = stores.get(&id) else {
            return not_found("store not found");
        };
        handle.clone()
    };

    use base64::Engine;
    let value = match BASE64.decode(&req.value) {
        Ok(v) => v,
        Err(e) => {
            return bad_request(format!("invalid base64: {e}"));
        }
    };

    let content_type = req
        .content_type
        .unwrap_or_else(|| "application/octet-stream".to_string());

    match handle.put_with_delta(key, value, content_type).await {
        Ok(delta) => {
            // #341 Phase B: encrypted stores replicate ONLY via the sealed
            // gossip path — never ship the plaintext local delta over the
            // DM direct-delivery side channel.
            if !handle.is_encrypted().await && !handle.is_group_signed().await {
                let recipients = kv_store_delta_direct_recipients(&state).await;
                spawn_kv_store_delta_delivery(&state, recipients, &id, handle.peer_id(), &delta);
            }
            (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
        }
        Err(e) => {
            let status = if matches!(e, x0x::error::IdentityError::ImmutableKey(_)) {
                // AppendOnly store: the key already exists and existing keys
                // are immutable, even to the owner.
                StatusCode::CONFLICT
            } else if matches!(e, x0x::error::IdentityError::Unauthorized(_)) {
                // Local write rejected by the store's access policy — the
                // caller is not the owner (or an allowlisted writer), or the
                // joined replica has not yet learned the authoritative owner.
                StatusCode::FORBIDDEN
            } else if format!("{e}").contains("value too large") {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
            )
        }
    }
}

/// GET /stores/:id/:key
pub(in crate::server) async fn get_kv_value(
    State(state): State<Arc<AppState>>,
    Path((id, key)): Path<(String, String)>,
) -> impl IntoResponse {
    let handle = {
        let stores = state.kv_stores.read().await;
        let Some(handle) = stores.get(&id) else {
            return not_found("store not found");
        };
        handle.clone()
    };

    match handle.get(&key).await {
        Ok(Some(entry)) => {
            use base64::Engine;
            let value_b64 = BASE64.encode(&entry.value);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "key": entry.key,
                    "value": value_b64,
                    "content_type": entry.content_type,
                    "content_hash": entry.content_hash,
                    "metadata": entry.metadata,
                    "created_at": entry.created_at,
                    "updated_at": entry.updated_at,
                })),
            )
        }
        Ok(None) => not_found("key not found"),
        Err(e) if matches!(e, x0x::error::IdentityError::Unauthorized(_)) => {
            api_error(StatusCode::FORBIDDEN, format!("{e}"))
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// DELETE /stores/:id/:key
pub(in crate::server) async fn delete_kv_value(
    State(state): State<Arc<AppState>>,
    Path((id, key)): Path<(String, String)>,
) -> impl IntoResponse {
    let handle = {
        let stores = state.kv_stores.read().await;
        let Some(handle) = stores.get(&id) else {
            return not_found("store not found");
        };
        handle.clone()
    };

    match handle.remove_with_delta(&key).await {
        Ok(delta) => {
            // #341 Phase B: see put_kv_value — no plaintext DM fallback for
            // encrypted stores.
            if !handle.is_encrypted().await && !handle.is_group_signed().await {
                let recipients = kv_store_delta_direct_recipients(&state).await;
                spawn_kv_store_delta_delivery(&state, recipients, &id, handle.peer_id(), &delta);
            }
            (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
        }
        Err(e) if matches!(e, x0x::error::IdentityError::ImmutableKey(_)) => {
            // AppendOnly store: keys can never be deleted, even by the owner.
            api_error(StatusCode::CONFLICT, format!("{e}"))
        }
        Err(e) if matches!(e, x0x::error::IdentityError::Unauthorized(_)) => {
            api_error(StatusCode::FORBIDDEN, format!("{e}"))
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

// ---------------------------------------------------------------------------
// Group-scoped encrypted stores (#341 Phase B)
// ---------------------------------------------------------------------------

/// Request body for `POST /groups/:id/stores`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct CreateGroupStoreRequest {
    name: String,
}

type GroupStoreResponse = (StatusCode, Json<serde_json::Value>);

/// Creation-fixed identity; app names retain the existing trim-only semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GssGroupStoreBinding {
    group_key: String,
    stable_group_id: String,
    creator: AgentId,
    name: String,
    store_id: x0x::kv::KvStoreId,
    topic: String,
}

/// Live TreeKEM adapter for one deterministic group store.
///
/// The group mutex covers crypto and the durable snapshot write. A failed
/// write restores the pre-operation ratchet before releasing the mutex, so a
/// record is never acknowledged or published from state that only existed in
/// memory.
struct TreeKemGroupStoreProtector {
    state: Arc<AppState>,
    group_key: String,
    stable_group_id: String,
    authorization: Arc<x0x::groups::TreeKemKvAuthorizationContext>,
    invalid: std::sync::atomic::AtomicBool,
}

impl TreeKemGroupStoreProtector {
    fn new(
        state: &Arc<AppState>,
        binding: &GssGroupStoreBinding,
        authorization: Arc<x0x::groups::TreeKemKvAuthorizationContext>,
    ) -> Self {
        Self {
            state: Arc::clone(state),
            group_key: binding.group_key.clone(),
            stable_group_id: binding.stable_group_id.clone(),
            authorization,
            invalid: std::sync::atomic::AtomicBool::new(false),
        }
    }

    async fn current_info(&self) -> x0x::kv::Result<x0x::groups::GroupInfo> {
        if self.invalid.load(std::sync::atomic::Ordering::Acquire) {
            return Err(x0x::kv::KvError::Unauthorized(
                "TreeKEM group store is retired".to_string(),
            ));
        }
        let groups = self.state.named_groups.read().await;
        // ADR-0067 hard requirement: BOTH spellings. This was a bare
        // `groups.get(&self.group_key)`. It failed closed rather than open
        // (the `stable_group_id()` comparison below catches a mismatch), but a
        // protector bound under one alias while the roster is keyed by the
        // other then reports "unavailable" for a perfectly live group — and a
        // gate that resolves only one spelling is exactly the defect
        // ADR-0066 slice 3 review r1 found. One shared resolver now.
        let info = crate::server::resolve_group_entry_locked(&groups, &self.group_key)
            .map(|(_, info)| info.clone())
            .ok_or_else(|| {
                x0x::kv::KvError::Unauthorized("TreeKEM group is unavailable".to_string())
            })?;
        if info.withdrawn
            || info.is_fork_quarantined()
            || info.stable_group_id() != self.stable_group_id
            || info.policy.confidentiality != x0x::groups::GroupConfidentiality::MlsEncrypted
            || info.secure_plane != x0x::mls::SecureGroupPlane::TreeKem
        {
            return Err(x0x::kv::KvError::Unauthorized(
                "TreeKEM group binding is no longer eligible".to_string(),
            ));
        }
        self.authorization.update_from_group(&info);
        Ok(info)
    }

    fn permits(info: &x0x::groups::GroupInfo, agent: &AgentId, writer: bool) -> bool {
        let Some(member) = info.members_v2.get(&hex::encode(agent.as_bytes())) else {
            return false;
        };
        if !member.is_active() {
            return false;
        }
        if !writer {
            return true;
        }
        match info.policy.write_access {
            x0x::groups::GroupWriteAccess::MembersOnly => true,
            x0x::groups::GroupWriteAccess::AdminOnly => {
                member.role.at_least(x0x::groups::GroupRole::Admin)
            }
            x0x::groups::GroupWriteAccess::ModeratedPublic => false,
        }
    }

    fn authorization_binding(info: &x0x::groups::GroupInfo) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"x0x.kv.treekem-roster-policy.v1");
        hasher.update(info.stable_group_id().as_bytes());
        hasher.update(&info.state_revision.to_le_bytes());
        hasher.update(x0x::groups::compute_roster_root(&info.members_v2).as_bytes());
        if let Some(binding) = info.security_binding.as_deref() {
            hasher.update(binding.as_bytes());
        }
        hasher.update(&[match info.policy.read_access {
            x0x::groups::GroupReadAccess::Public => 0,
            x0x::groups::GroupReadAccess::MembersOnly => 1,
        }]);
        hasher.update(&[match info.policy.write_access {
            x0x::groups::GroupWriteAccess::MembersOnly => 0,
            x0x::groups::GroupWriteAccess::ModeratedPublic => 1,
            x0x::groups::GroupWriteAccess::AdminOnly => 2,
        }]);
        *hasher.finalize().as_bytes()
    }

    async fn live_group(
        &self,
    ) -> x0x::kv::Result<Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>>> {
        self.state
            .treekem_groups
            .read()
            .await
            .get(&self.group_key)
            .cloned()
            .ok_or_else(|| {
                x0x::kv::KvError::SecureRecord("live TreeKEM ratchet is unavailable".to_string())
            })
    }

    fn map_crypto_error(error: impl std::fmt::Display) -> x0x::kv::KvError {
        x0x::kv::KvError::SecureRecord(format!("TreeKEM group-store crypto failed: {error}"))
    }

    async fn rollback(
        &self,
        info: &x0x::groups::GroupInfo,
        snapshot: &[u8],
        group: &mut x0x::mls::TreeKemMlsGroup,
    ) {
        match super::named_groups::restore_local_treekem_group_from_snapshot(
            &self.state,
            info,
            snapshot,
        ) {
            Ok(restored) => *group = restored,
            Err(error) => {
                self.invalid
                    .store(true, std::sync::atomic::Ordering::Release);
                tracing::error!("failed to rollback TreeKEM store ratchet: {error}");
            }
        }
    }
}

#[async_trait::async_trait]
impl x0x::kv::TreeKemKvProtector for TreeKemGroupStoreProtector {
    fn group_id(&self) -> Vec<u8> {
        self.stable_group_id.as_bytes().to_vec()
    }

    async fn seal_record(
        &self,
        signing: &x0x::kv::AuthorSigning,
        kind: x0x::kv::KvMutationKind,
        store_id: &x0x::kv::KvStoreId,
        payload: &[u8],
        reader_only: bool,
    ) -> x0x::kv::Result<x0x::kv::TreeKemKvStoreRecordV1> {
        let membership =
            super::named_groups::group_membership_lock(&self.state, &self.group_key).await;
        let _membership_guard = membership.lock().await;
        let live = self.live_group().await?;
        let mut group = live.lock().await;
        // Re-read authority only after acquiring the ratchet mutex. Membership
        // commits use the same mutex, so this snapshot cannot predate a commit
        // that won while this operation was waiting.
        let info = self.current_info().await?;
        let reader_admission = kind == x0x::kv::KvMutationKind::Control && reader_only;
        if !Self::permits(&info, &signing.agent_id, !reader_admission) {
            return Err(x0x::kv::KvError::Unauthorized(
                "TreeKEM mutation author is not currently authorized".to_string(),
            ));
        }
        let rollback = group.to_snapshot_bytes().map_err(Self::map_crypto_error)?;
        let epoch = group.epoch();
        let inner = x0x::kv::treekem::sign_inner_mutation(
            signing,
            kind,
            payload,
            x0x::kv::treekem::TreeKemInnerBinding {
                group_id: self.group_id(),
                epoch,
                store_id,
                authorization_binding: Self::authorization_binding(&info),
                reader_only,
            },
        )?;
        let ciphertext = match group.encrypt_message(&inner) {
            Ok(ciphertext) => ciphertext,
            Err(error) => {
                self.rollback(&info, &rollback, &mut group).await;
                return Err(Self::map_crypto_error(error));
            }
        };
        if let Err(error) = super::named_groups::persist_treekem_snapshot_bound(
            &self.state,
            &self.group_key,
            &group,
        )
        .await
        {
            self.rollback(&info, &rollback, &mut group).await;
            return Err(x0x::kv::KvError::Gossip(format!(
                "persist TreeKEM send ratchet: {error}"
            )));
        }
        Ok(x0x::kv::TreeKemKvStoreRecordV1 {
            version: 1,
            group_id: self.group_id(),
            store_id: *store_id.as_bytes(),
            epoch,
            reader_only,
            ciphertext,
        })
    }

    async fn open_record(
        &self,
        store_id: &x0x::kv::KvStoreId,
        record: &x0x::kv::TreeKemKvStoreRecordV1,
    ) -> x0x::kv::Result<x0x::kv::treekem::OpenedTreeKemKvRecord> {
        if record.version != 1
            || record.group_id != self.group_id()
            || record.store_id != *store_id.as_bytes()
        {
            return Err(x0x::kv::KvError::SecureRecord(
                "TreeKEM record binding mismatch".to_string(),
            ));
        }
        let membership =
            super::named_groups::group_membership_lock(&self.state, &self.group_key).await;
        let _membership_guard = membership.lock().await;
        let live = self.live_group().await?;
        let mut group = live.lock().await;
        let info = self.current_info().await?;
        if record.epoch != group.epoch() {
            return Err(x0x::kv::KvError::SecureRecord(
                "TreeKEM record epoch is stale or ahead".to_string(),
            ));
        }
        let rollback = group.to_snapshot_bytes().map_err(Self::map_crypto_error)?;
        let plaintext = match group.decrypt_message(&record.ciphertext) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                self.rollback(&info, &rollback, &mut group).await;
                return Err(Self::map_crypto_error(error));
            }
        };
        let opened = match x0x::kv::treekem::open_inner_mutation(
            self.stable_group_id.as_bytes(),
            record.epoch,
            store_id,
            &plaintext,
            Self::authorization_binding(&info),
        ) {
            Ok(opened) => opened,
            Err(error) => {
                self.rollback(&info, &rollback, &mut group).await;
                return Err(error);
            }
        };
        if opened.reader_only != record.reader_only
            || opened.reader_only && opened.mutation.kind != x0x::kv::KvMutationKind::Control
            || !Self::permits(&info, &opened.mutation.author_id, !opened.reader_only)
        {
            self.rollback(&info, &rollback, &mut group).await;
            return Err(x0x::kv::KvError::Unauthorized(
                "TreeKEM mutation author is not currently authorized".to_string(),
            ));
        }
        if let Err(error) = super::named_groups::persist_treekem_snapshot_bound(
            &self.state,
            &self.group_key,
            &group,
        )
        .await
        {
            self.rollback(&info, &rollback, &mut group).await;
            return Err(x0x::kv::KvError::Gossip(format!(
                "persist TreeKEM receive ratchet: {error}"
            )));
        }
        Ok(opened)
    }

    async fn is_authorized_reader(&self, agent: &AgentId) -> bool {
        self.current_info()
            .await
            .is_ok_and(|info| Self::permits(&info, agent, false))
    }

    async fn is_authorized_writer(&self, agent: &AgentId) -> bool {
        self.current_info()
            .await
            .is_ok_and(|info| Self::permits(&info, agent, true))
    }

    async fn merge_main_record(
        &self,
        opened: x0x::kv::treekem::OpenedTreeKemKvRecord,
        sender_peer: saorsa_gossip_types::PeerId,
        local_peer: saorsa_gossip_types::PeerId,
        store: &Arc<tokio::sync::RwLock<x0x::kv::KvStore>>,
        retained_image: Option<Vec<u8>>,
    ) -> x0x::kv::Result<()> {
        if opened.reader_only || opened.mutation.kind == x0x::kv::KvMutationKind::Control {
            return Err(x0x::kv::KvError::Unauthorized(
                "read-side TreeKEM record cannot mutate a store".to_string(),
            ));
        }
        let membership =
            super::named_groups::group_membership_lock(&self.state, &self.group_key).await;
        let _membership_guard = membership.lock().await;
        let info = self.current_info().await?;
        if opened.authorization_binding != Self::authorization_binding(&info)
            || !Self::permits(&info, &opened.mutation.author_id, true)
        {
            return Err(x0x::kv::KvError::Unauthorized(
                "TreeKEM record authority changed before merge".to_string(),
            ));
        }
        let mut target = store.write().await;
        match opened.mutation.kind {
            x0x::kv::KvMutationKind::Delta | x0x::kv::KvMutationKind::FullState => {
                let delta: x0x::kv::KvStoreDelta =
                    bincode::deserialize(&opened.mutation.payload)
                        .map_err(|e| x0x::kv::KvError::Gossip(format!("bad TreeKEM delta: {e}")))?;
                target.merge_delta(&delta, sender_peer, Some(&opened.mutation.author_id))
            }
            x0x::kv::KvMutationKind::RetainedState => {
                let image: x0x::kv::KvStore =
                    bincode::deserialize(retained_image.as_deref().ok_or_else(|| {
                        x0x::kv::KvError::Gossip(
                            "complete TreeKEM retained image required".to_string(),
                        )
                    })?)
                    .map_err(|e| x0x::kv::KvError::Gossip(format!("bad retained image: {e}")))?;
                target.merge_group_retained_image(&image, opened.mutation.author_id, local_peer)
            }
            x0x::kv::KvMutationKind::Control => Err(x0x::kv::KvError::Unauthorized(
                "TreeKEM control record on main topic".to_string(),
            )),
        }
    }

    fn invalidate(&self) {
        self.invalid
            .store(true, std::sync::atomic::Ordering::Release);
        self.authorization.invalidate();
    }
}

fn find_store_group<'a>(
    groups: &'a std::collections::HashMap<String, x0x::groups::GroupInfo>,
    id: &str,
) -> Result<(&'a String, &'a x0x::groups::GroupInfo), GroupStoreResponse> {
    if let Some(pair) = groups.get_key_value(id) {
        return Ok(pair);
    }
    let mut matches = groups
        .iter()
        .filter(|(_, info)| info.stable_group_id() == id);
    let pair = matches.next().ok_or_else(|| not_found("group not found"))?;
    if matches.next().is_some() {
        return Err(api_error(
            StatusCode::CONFLICT,
            "ambiguous local group binding",
        ));
    }
    Ok(pair)
}

fn validate_gss_store_group(
    info: &x0x::groups::GroupInfo,
    caller: &AgentId,
) -> Result<(), GroupStoreResponse> {
    if info.withdrawn {
        return Err(api_error(StatusCode::CONFLICT, "group is withdrawn"));
    }
    // ADR-0066 §4 / ADR-0067: the GSS refresh validator was blind to the
    // marker, so `gss_kv_refresh`'s per-operation refresh could re-arm a
    // cached context for a group that had been quarantined since the bind.
    // The marker is the one condition here that can appear mid-flight (a fork
    // observation lands asynchronously), which is why it is checked on the
    // refresh path and not only at bind time. §5: the refusal says what
    // happened and how to lift it.
    if info.is_fork_quarantined() {
        return Err(api_error_with_reason(
            StatusCode::CONFLICT,
            "group is under ADR-0066 fork quarantine: authenticated fork evidence is \
             outstanding, so encrypted-store access fails closed until an operator clears \
             the marker (POST /groups/:id/quarantine/clear)",
            "fork_quarantined",
        ));
    }
    if !info.has_active_member(&hex::encode(caller.as_bytes())) {
        return Err(forbidden("not a member"));
    }
    if info.policy.confidentiality != x0x::groups::GroupConfidentiality::MlsEncrypted {
        return Err(bad_request(
            "encrypted stores require an MlsEncrypted group",
        ));
    }
    if info.secure_plane != x0x::mls::SecureGroupPlane::Gss {
        return Err(bad_request(
            "encrypted stores v1 are GSS-backed; other planes are not supported yet",
        ));
    }
    if info.shared_secret.is_none() {
        return Err(api_error(
            StatusCode::CONFLICT,
            "local daemon holds no shared secret for this group yet",
        ));
    }
    Ok(())
}

fn resolve_gss_group_store(
    groups: &std::collections::HashMap<String, x0x::groups::GroupInfo>,
    id: &str,
    name: &str,
    caller: &AgentId,
) -> Result<GssGroupStoreBinding, GroupStoreResponse> {
    let name = name.trim();
    if name.is_empty() {
        return Err(bad_request("store name must not be empty"));
    }
    let (group_key, info) = find_store_group(groups, id)?;
    validate_gss_store_group(info, caller)?;
    let stable_group_id = info.stable_group_id().to_string();
    let (store_id, topic) = x0x::kv::encrypted::group_store_identity(&stable_group_id, name);
    Ok(GssGroupStoreBinding {
        group_key: group_key.clone(),
        stable_group_id,
        creator: info.creator,
        name: name.to_string(),
        store_id,
        topic,
    })
}

fn resolve_treekem_group_store(
    groups: &std::collections::HashMap<String, x0x::groups::GroupInfo>,
    id: &str,
    name: &str,
    caller: &AgentId,
) -> Result<GssGroupStoreBinding, GroupStoreResponse> {
    let name = name.trim();
    if name.is_empty() {
        return Err(bad_request("store name must not be empty"));
    }
    let (group_key, info) = find_store_group(groups, id)?;
    if info.withdrawn || info.is_fork_quarantined() {
        return Err(api_error(StatusCode::CONFLICT, "group is unavailable"));
    }
    if !info.has_active_member(&hex::encode(caller.as_bytes())) {
        return Err(forbidden("not a member"));
    }
    if info.policy.confidentiality != x0x::groups::GroupConfidentiality::MlsEncrypted
        || info.secure_plane != x0x::mls::SecureGroupPlane::TreeKem
    {
        return Err(bad_request("store requires a real-TreeKEM encrypted group"));
    }
    let stable_group_id = info.stable_group_id().to_string();
    let (store_id, topic) = x0x::kv::encrypted::group_store_identity(&stable_group_id, name);
    Ok(GssGroupStoreBinding {
        group_key: group_key.clone(),
        stable_group_id,
        creator: info.creator,
        name: name.to_string(),
        store_id,
        topic,
    })
}

fn resolve_public_group_store(
    groups: &std::collections::HashMap<String, x0x::groups::GroupInfo>,
    id: &str,
    name: &str,
    caller: &AgentId,
) -> Result<GssGroupStoreBinding, GroupStoreResponse> {
    let name = name.trim();
    if name.is_empty() {
        return Err(bad_request("store name must not be empty"));
    }
    let (group_key, info) = find_store_group(groups, id)?;
    if info.withdrawn {
        return Err(api_error(StatusCode::CONFLICT, "group is withdrawn"));
    }
    if info.policy.confidentiality != x0x::groups::GroupConfidentiality::SignedPublic {
        return Err(bad_request("public stores require a SignedPublic group"));
    }
    if info.policy.write_access == x0x::groups::GroupWriteAccess::ModeratedPublic {
        return Err(bad_request(
            "ModeratedPublic group stores are unsupported without a moderation protocol",
        ));
    }
    if info.policy.read_access == x0x::groups::GroupReadAccess::MembersOnly
        && !info.has_active_member(&hex::encode(caller.as_bytes()))
    {
        return Err(forbidden(
            "public group store is restricted to current members",
        ));
    }
    let stable_group_id = info.stable_group_id().to_string();
    let (store_id, topic) = x0x::kv::encrypted::group_store_identity(&stable_group_id, name);
    Ok(GssGroupStoreBinding {
        group_key: group_key.clone(),
        stable_group_id,
        creator: info.creator,
        name: name.to_string(),
        store_id,
        topic,
    })
}

fn refresh_public_store_binding(
    ctx: &x0x::groups::PublicGroupKvContext,
    info: Option<&x0x::groups::GroupInfo>,
    creator: AgentId,
    caller: &AgentId,
) -> bool {
    if let Some(info) = info {
        if info.creator == creator
            && info.stable_group_id().as_bytes() == ctx.group_id()
            && !info.withdrawn
            && info.policy.confidentiality == x0x::groups::GroupConfidentiality::SignedPublic
            && info.policy.write_access != x0x::groups::GroupWriteAccess::ModeratedPublic
            && (info.policy.read_access == x0x::groups::GroupReadAccess::Public
                || info.has_active_member(&hex::encode(caller.as_bytes())))
        {
            ctx.update_from_group(info);
            return true;
        }
    }
    ctx.invalidate();
    false
}

fn public_kv_refresh(
    state: &Arc<AppState>,
    ctx: Arc<x0x::groups::PublicGroupKvContext>,
    group_key: String,
    topic: String,
    creator: AgentId,
) -> x0x::kv::sync::SecureRefreshFn {
    let state = Arc::clone(state);
    Arc::new(move || {
        let ctx = Arc::clone(&ctx);
        let state = Arc::clone(&state);
        let group_key = group_key.clone();
        let topic = topic.clone();
        Box::pin(async move {
            let valid = {
                let groups = state.named_groups.read().await;
                refresh_public_store_binding(
                    &ctx,
                    groups.get(&group_key),
                    creator,
                    &state.agent.agent_id(),
                )
            };
            if !valid {
                tracing::warn!(target: "x0x::kv", "retiring public group store {topic}: group binding is no longer eligible");
                if let Some(handle) = state.kv_stores.write().await.remove(&topic) {
                    handle.retire();
                }
            }
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
    })
}

/// Used by the real per-record refresh hook; invalidation also fences clones.
fn refresh_gss_store_binding(
    ctx: &x0x::groups::GssKvSecureContext,
    info: Option<&x0x::groups::GroupInfo>,
    creator: AgentId,
    caller: &AgentId,
) -> bool {
    if let Some(info) = info {
        if info.creator == creator
            && info.stable_group_id().as_bytes() == ctx.group_id()
            && validate_gss_store_group(info, caller).is_ok()
        {
            ctx.update_from_group(info);
            return true;
        }
    }
    ctx.invalidate();
    false
}

/// Deterministic refresh hook for a GSS encrypted-store context: re-reads
/// the authoritative group from the daemon's named-groups map (under the
/// read guard — no `GroupInfo` clone) and refreshes the context snapshot.
/// The sync loops call this before every seal/open, so a rekey or roster
/// change takes effect on the very next record.
pub(in crate::server) fn gss_kv_refresh(
    state: &Arc<AppState>,
    ctx: Arc<x0x::groups::GssKvSecureContext>,
    group_key: String,
    topic: String,
    creator: AgentId,
) -> x0x::kv::sync::SecureRefreshFn {
    let state = Arc::clone(state);
    Arc::new(move || {
        let ctx = Arc::clone(&ctx);
        let state = Arc::clone(&state);
        let group_key = group_key.clone();
        let topic = topic.clone();
        Box::pin(async move {
            let valid = {
                let groups = state.named_groups.read().await;
                refresh_gss_store_binding(
                    &ctx,
                    groups.get(&group_key),
                    creator,
                    &state.agent.agent_id(),
                )
            };
            if !valid {
                tracing::warn!(target: "x0x::kv", "retiring encrypted store {topic}: group binding is no longer eligible");
                if let Some(h) = state.kv_stores.write().await.remove(&topic) {
                    h.retire();
                }
            }
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
    })
}

/// Retire EVERY encrypted store handle bound to `stable_group_id` (topic
/// prefix `x0x/group/<gid>/kv/`): invalidate its secure context (local
/// authorization fails closed immediately, even for handles cloned
/// elsewhere) and cancel its sync loops.
///
/// Called from the group-lifecycle paths — leave, group deletion, and
/// state withdrawal — so a departed member cannot keep reading, writing,
/// or publishing old-epoch records through a live handle. The per-store
/// refresh hook ([`gss_kv_refresh`]) is the second layer: it invalidates
/// and retires on the next sync activity even if a lifecycle path is
/// missed.
pub(in crate::server) async fn retire_group_kv_stores(state: &AppState, stable_group_id: &str) {
    let prefix = format!("x0x/group/{stable_group_id}/kv/");
    let mut stores = state.kv_stores.write().await;
    let doomed: Vec<String> = stores
        .keys()
        .filter(|topic| topic.starts_with(&prefix))
        .cloned()
        .collect();
    for topic in &doomed {
        if let Some(h) = stores.remove(topic) {
            tracing::info!(
                target: "x0x::kv",
                "retiring encrypted store {topic}: group {stable_group_id} left/removed/withdrawn"
            );
            h.retire();
        }
    }
}

/// Retire a cached handle whose binding no longer matches, before it is
/// unregistered (#757). Callers hold the group membership guard and no
/// map/store guard.
///
/// The decision follows the CACHED sync, not the plane being opened: a policy
/// change (e.g. TreeKEM -> SignedPublic) keeps the topic, so any plane's
/// mismatch arm can find any kind of sync. A TreeKEM sync's receive section
/// takes that same membership guard (`TreeKemGroupStoreProtector::open_record`
/// / `merge_main_record`) while holding its lifecycle lock, so draining it
/// here would deadlock; it gets the non-blocking `retire` and the re-open
/// residual tracked in #760. GSS and public sections take only `named_groups`
/// / `kv_stores` (refresh hook), which are not held here, so they are drained.
async fn retire_mismatched_cached_store(handle: &x0x::KvStoreHandle) {
    if handle.is_treekem_protected() {
        handle.retire();
    } else {
        handle.retire_and_drain().await;
    }
}

/// Called only while the canonical store reservation and group membership
/// guard are held. Re-resolve before touching a cached handle or starting sync.
async fn open_bound_gss_store(
    state: &Arc<AppState>,
    expected: &GssGroupStoreBinding,
) -> Result<
    (
        x0x::KvStoreHandle,
        Arc<x0x::groups::GssKvSecureContext>,
        bool,
    ),
    GroupStoreResponse,
> {
    let secure = {
        let groups = state.named_groups.read().await;
        let current = resolve_gss_group_store(
            &groups,
            &expected.group_key,
            &expected.name,
            &state.agent.agent_id(),
        )?;
        if &current != expected {
            return Err(api_error(
                StatusCode::CONFLICT,
                "group store binding changed during open",
            ));
        }
        let info = groups
            .get(&current.group_key)
            .ok_or_else(|| not_found("group not found"))?;
        Arc::new(
            x0x::groups::GssKvSecureContext::from_group(info)
                .ok_or_else(|| api_error(StatusCode::CONFLICT, "group secret unavailable"))?,
        )
    };
    let cached = { state.kv_stores.read().await.get(&expected.topic).cloned() };
    if let Some(handle) = cached {
        if handle
            .validate_group_binding(
                &expected.name,
                &expected.stable_group_id,
                expected.creator,
                x0x::GroupStoreProtection::Encrypted,
            )
            .await
            .is_err()
        {
            retire_mismatched_cached_store(&handle).await;
            state.kv_stores.write().await.remove(&expected.topic);
            return Err(api_error(
                StatusCode::CONFLICT,
                "cached group store binding mismatch or retired context",
            ));
        }
        return Ok((handle, secure, false));
    }
    let refresh = gss_kv_refresh(
        state,
        Arc::clone(&secure),
        expected.group_key.clone(),
        expected.topic.clone(),
        expected.creator,
    );
    let handle = state
        .agent
        .open_group_kv_store_persistent(
            &expected.name,
            &expected.stable_group_id,
            expected.creator,
            Arc::clone(&secure) as Arc<dyn KvSecureContext>,
            refresh,
            &state.kv_store_state_dir,
        )
        .await
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")))?;
    Ok((handle, secure, true))
}

async fn open_bound_treekem_store(
    state: &Arc<AppState>,
    expected: &GssGroupStoreBinding,
) -> Result<(x0x::KvStoreHandle, u64, bool), GroupStoreResponse> {
    let authorization = {
        let groups = state.named_groups.read().await;
        let current = resolve_treekem_group_store(
            &groups,
            &expected.group_key,
            &expected.name,
            &state.agent.agent_id(),
        )?;
        if &current != expected {
            return Err(api_error(
                StatusCode::CONFLICT,
                "TreeKEM group store binding changed during open",
            ));
        }
        let info = groups
            .get(&current.group_key)
            .ok_or_else(|| not_found("group not found"))?;
        let authorization = x0x::groups::TreeKemKvAuthorizationContext::from_group(info)
            .ok_or_else(|| api_error(StatusCode::CONFLICT, "TreeKEM group unavailable"))?;
        Arc::new(authorization)
    };
    let live = state
        .treekem_groups
        .read()
        .await
        .get(&expected.group_key)
        .cloned()
        .ok_or_else(|| api_error(StatusCode::CONFLICT, "TreeKEM ratchet unavailable"))?;
    let epoch = live.lock().await.epoch();
    let cached = { state.kv_stores.read().await.get(&expected.topic).cloned() };
    if let Some(handle) = cached {
        if handle
            .validate_group_binding(
                &expected.name,
                &expected.stable_group_id,
                expected.creator,
                x0x::GroupStoreProtection::TreeKemEncrypted,
            )
            .await
            .is_ok()
        {
            return Ok((handle, epoch, false));
        }
        retire_mismatched_cached_store(&handle).await;
        state.kv_stores.write().await.remove(&expected.topic);
        return Err(api_error(
            StatusCode::CONFLICT,
            "cached TreeKEM group store binding mismatch",
        ));
    }
    let protector: x0x::kv::SharedTreeKemKvProtector = Arc::new(TreeKemGroupStoreProtector::new(
        state,
        expected,
        Arc::clone(&authorization),
    ));
    let handle = state
        .agent
        .open_treekem_group_kv_store_persistent(
            &expected.name,
            &expected.stable_group_id,
            expected.creator,
            authorization,
            protector,
            &state.kv_store_state_dir,
        )
        .await
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")))?;
    Ok((handle, epoch, true))
}

async fn open_bound_public_store(
    state: &Arc<AppState>,
    expected: &GssGroupStoreBinding,
) -> Result<
    (
        x0x::KvStoreHandle,
        Arc<x0x::groups::PublicGroupKvContext>,
        bool,
    ),
    GroupStoreResponse,
> {
    let context = {
        let groups = state.named_groups.read().await;
        let current = resolve_public_group_store(
            &groups,
            &expected.group_key,
            &expected.name,
            &state.agent.agent_id(),
        )?;
        if &current != expected {
            return Err(api_error(
                StatusCode::CONFLICT,
                "public group store binding changed during open",
            ));
        }
        let info = groups
            .get(&current.group_key)
            .ok_or_else(|| not_found("group not found"))?;
        Arc::new(
            x0x::groups::PublicGroupKvContext::from_group(info)
                .ok_or_else(|| bad_request("group is not SignedPublic"))?,
        )
    };
    // Drop the map read guard before any mismatch cleanup takes the write
    // guard. In edition 2021 an `if let` scrutinee temporary otherwise lives
    // through the whole arm and self-deadlocks on `write().await` below.
    let cached = {
        let stores = state.kv_stores.read().await;
        stores.get(&expected.topic).cloned()
    };
    if let Some(handle) = cached {
        if handle
            .validate_group_binding(
                &expected.name,
                &expected.stable_group_id,
                expected.creator,
                x0x::GroupStoreProtection::PublicSigned,
            )
            .await
            .is_ok()
        {
            return Ok((handle, context, false));
        }
        retire_mismatched_cached_store(&handle).await;
        state.kv_stores.write().await.remove(&expected.topic);
        return Err(api_error(
            StatusCode::CONFLICT,
            "cached public group store binding mismatch",
        ));
    }
    let refresh = public_kv_refresh(
        state,
        Arc::clone(&context),
        expected.group_key.clone(),
        expected.topic.clone(),
        expected.creator,
    );
    let handle = state
        .agent
        .open_public_group_kv_store_persistent(
            &expected.name,
            &expected.stable_group_id,
            expected.creator,
            Arc::clone(&context) as Arc<dyn KvSecureContext>,
            refresh,
            &state.kv_store_state_dir,
        )
        .await
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")))?;
    Ok((handle, context, true))
}

/// Shared metadata payload for create / idempotent re-open responses.
async fn group_store_json(
    handle: &x0x::KvStoreHandle,
    topic: &str,
    store_id: &x0x::kv::KvStoreId,
    stable_group_id: &str,
    epoch: u64,
    policy: &str,
) -> serde_json::Value {
    let ownership = handle.ownership_info().await;
    serde_json::json!({
        "ok": true,
        "id": topic,
        "store_id": hex::encode(store_id.as_bytes()),
        "group_id": stable_group_id,
        "topic": topic,
        "policy": policy,
        "epoch": epoch,
        "checkpoint_available": handle.has_checkpoint().await,
        "ownership": ownership,
    })
}

/// `POST /groups/:id/stores` — open (create or re-open) a group-scoped
/// ENCRYPTED KvStore bound to the named group (#341 Phase B, design:
/// `docs/design/encrypted-kvstore.md`).
///
/// Store identity is deterministic from `(stable group id, name)`, so every
/// member computes the same store id and topic with no out-of-band anchor;
/// ownership is anchored on the GROUP CREATOR. Every publication is
/// sign-then-encrypt sealed under the group's current secret epoch and the
/// v1 write rule is active group membership.
///
/// Guards: caller must be an active member, the group must be
/// `MlsEncrypted` on the GSS plane (the v1 backend, ADR-0010), and a rider
/// token must explicitly cover the group (ADR-0039 deny-by-default).
///
/// Idempotent: opening an already-open store returns 200 with its metadata
/// instead of a conflict.
pub(in crate::server) async fn create_group_kv_store(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Extension(actor): Extension<crate::server::rider_auth::ActorContext>,
    Json(req): Json<CreateGroupStoreRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    #[derive(Clone, Copy)]
    enum StorePlane {
        Gss,
        TreeKem,
        Public,
    }
    let (binding, plane) = {
        let groups = state.named_groups.read().await;
        let plane = match find_store_group(&groups, &id) {
            Ok((_, info))
                if info.policy.confidentiality
                    == x0x::groups::GroupConfidentiality::SignedPublic =>
            {
                StorePlane::Public
            }
            Ok((_, info)) if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem => {
                StorePlane::TreeKem
            }
            Ok(_) => StorePlane::Gss,
            Err(response) => return response,
        };
        let resolved = match plane {
            StorePlane::Public => {
                resolve_public_group_store(&groups, &id, &req.name, &state.agent.agent_id())
            }
            StorePlane::TreeKem => {
                resolve_treekem_group_store(&groups, &id, &req.name, &state.agent.agent_id())
            }
            StorePlane::Gss => {
                resolve_gss_group_store(&groups, &id, &req.name, &state.agent.agent_id())
            }
        };
        match resolved {
            Ok(binding) => (binding, plane),
            Err(response) => return response,
        }
    };
    if !actor.rider_allows_group(&binding.stable_group_id) {
        return forbidden("rider token is not granted this group");
    }
    let reservation = crdt_subscriptions::handle_reservation(
        &state,
        crdt_subscriptions::KIND_KV_STORE,
        &binding.topic,
    )
    .await;
    let _reservation_guard = reservation.lock().await;
    // Use the same alias-canonicalizing mutex as all group membership writers.
    let membership = super::named_groups::group_membership_lock(&state, &binding.group_key).await;
    let _membership_guard = membership.lock().await;
    let (handle, epoch, created) = match plane {
        StorePlane::Public => match open_bound_public_store(&state, &binding).await {
            Ok((handle, context, created)) => (handle, context.current_epoch(), created),
            Err(response) => return response,
        },
        StorePlane::TreeKem => match open_bound_treekem_store(&state, &binding).await {
            Ok(opened) => opened,
            Err(response) => return response,
        },
        StorePlane::Gss => match open_bound_gss_store(&state, &binding).await {
            Ok((handle, context, created)) => (handle, context.current_epoch(), created),
            Err(response) => return response,
        },
    };
    if created {
        state
            .kv_stores
            .write()
            .await
            .insert(binding.topic.clone(), handle.clone());
        let mut extra = serde_json::Map::new();
        extra.insert(
            "policy".into(),
            serde_json::Value::String(if matches!(plane, StorePlane::Public) {
                "group_signed".into()
            } else {
                "encrypted".into()
            }),
        );
        extra.insert(
            "expected_owner".into(),
            serde_json::Value::String(hex::encode(binding.creator.as_bytes())),
        );
        extra.insert(
            "stable_group_id".into(),
            serde_json::Value::String(binding.stable_group_id.clone()),
        );
        if !matches!(plane, StorePlane::Public) {
            extra.insert(
                "secure_plane".into(),
                serde_json::Value::String(match plane {
                    StorePlane::TreeKem => "treekem".into(),
                    StorePlane::Gss | StorePlane::Public => "gss".into(),
                }),
            );
        }
        if let Err(e) = crdt_subscriptions::record(
            &state,
            crdt_subscriptions::CrdtSubscriptionEntry {
                kind: crdt_subscriptions::KIND_KV_STORE.to_string(),
                id: binding.topic.clone(),
                name: binding.name.clone(),
                topic: binding.topic.clone(),
                role: crdt_subscriptions::ROLE_CREATED.to_string(),
                extra,
            },
        )
        .await
        {
            handle.retire();
            state.kv_stores.write().await.remove(&binding.topic);
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to persist subscription registration: {e}"),
            );
        }
    }
    (
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(
            group_store_json(
                &handle,
                &binding.topic,
                &binding.store_id,
                &binding.stable_group_id,
                epoch,
                if matches!(plane, StorePlane::Public) {
                    "group_signed"
                } else {
                    "encrypted"
                },
            )
            .await,
        ),
    )
}

/// Manifest binding must agree with current group authority, not supply it.
fn validate_gss_store_manifest(
    entry: &crdt_subscriptions::CrdtSubscriptionEntry,
    binding: &GssGroupStoreBinding,
    expected_policy: &str,
    expected_secure_plane: Option<&str>,
) -> Result<(), GroupStoreResponse> {
    let recorded_plane = entry.extra.get("secure_plane").and_then(|v| v.as_str());
    let plane_matches = match expected_secure_plane {
        Some("gss") => recorded_plane.is_none() || recorded_plane == Some("gss"),
        Some(expected) => recorded_plane == Some(expected),
        None => recorded_plane.is_none(),
    };
    if entry.id != binding.topic
        || entry.topic != binding.topic
        || entry.name != binding.name
        || entry.extra.get("stable_group_id").and_then(|v| v.as_str())
            != Some(binding.stable_group_id.as_str())
        || entry
            .extra
            .get("expected_owner")
            .and_then(|v| v.as_str())
            .and_then(|owner| parse_agent_id_hex(owner).ok())
            != Some(binding.creator)
        || entry.extra.get("policy").and_then(|v| v.as_str()) != Some(expected_policy)
        || !plane_matches
    {
        return Err(api_error(
            StatusCode::CONFLICT,
            "encrypted store manifest binding mismatch",
        ));
    }
    Ok(())
}

/// Encrypted restore's final decision. Caller holds the per-entry reservation;
/// canonical ID validation precedes cached lookup and prevents alternate keys
/// from evading that reservation. Membership stays serialized through install.
pub(in crate::server) async fn restore_bound_gss_store(
    state: &Arc<AppState>,
    entry: &crdt_subscriptions::CrdtSubscriptionEntry,
) -> Result<bool, GroupStoreResponse> {
    let stable = entry
        .extra
        .get("stable_group_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad_request("encrypted store manifest has no stable group ID"))?;
    let public = entry.extra.get("policy").and_then(|v| v.as_str()) == Some("group_signed");
    let (binding, treekem) = {
        let groups = state.named_groups.read().await;
        if public {
            (
                resolve_public_group_store(&groups, stable, &entry.name, &state.agent.agent_id())?,
                false,
            )
        } else {
            let (_, info) = find_store_group(&groups, stable)?;
            if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
                (
                    resolve_treekem_group_store(
                        &groups,
                        stable,
                        &entry.name,
                        &state.agent.agent_id(),
                    )?,
                    true,
                )
            } else {
                (
                    resolve_gss_group_store(&groups, stable, &entry.name, &state.agent.agent_id())?,
                    false,
                )
            }
        }
    };
    validate_gss_store_manifest(
        entry,
        &binding,
        if public { "group_signed" } else { "encrypted" },
        if public {
            None
        } else if treekem {
            Some("treekem")
        } else {
            Some("gss")
        },
    )?;
    let membership = super::named_groups::group_membership_lock(state, &binding.group_key).await;
    let _membership_guard = membership.lock().await;
    let (handle, created) = if public {
        let (handle, _, created) = open_bound_public_store(state, &binding).await?;
        (handle, created)
    } else if treekem {
        let (handle, _, created) = open_bound_treekem_store(state, &binding).await?;
        (handle, created)
    } else {
        let (handle, _, created) = open_bound_gss_store(state, &binding).await?;
        (handle, created)
    };
    if created {
        state
            .kv_stores
            .write()
            .await
            .insert(binding.topic.clone(), handle);
    }
    Ok(created)
}

fn legacy_page_app(app: &str) -> Result<&'static str, GroupStoreResponse> {
    match app.trim().to_ascii_lowercase().as_str() {
        "wiki" => Ok("wiki"),
        "web" => Ok("web"),
        _ => Err(bad_request("legacy import app must be wiki or web")),
    }
}

fn legacy_page_topic(stable_group_id: &str, app: &str) -> Result<String, GroupStoreResponse> {
    let prefix = stable_group_id
        .get(..16)
        .ok_or_else(|| bad_request("stable group id is too short for a legacy alias"))?;
    Ok(format!("x0x-{app}-{prefix}"))
}

async fn load_legacy_page_store(
    state: &AppState,
    stable_group_id: &str,
    app: &str,
    requested_source_id: Option<&str>,
) -> Result<Option<LoadedLegacyStore>, GroupStoreResponse> {
    let topic = legacy_page_topic(stable_group_id, app)?;
    let owner = state.agent.agent_id();
    let owner_hex = hex::encode(owner.as_bytes());
    let store_id = x0x::kv::KvStoreId::for_topic_owner(&topic, &owner);
    let store_id_hex = hex::encode(store_id.as_bytes());
    if requested_source_id.is_some_and(|requested| requested != store_id_hex) {
        return Err(api_error(
            StatusCode::CONFLICT,
            "source id does not match the exact legacy manifest binding",
        ));
    }
    let manifest = crdt_subscriptions::probe_manifest_strict(&state.crdt_subscriptions_path)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::CONFLICT,
                format!("legacy subscription manifest is unreadable: {error}"),
            )
        })?
        .unwrap_or_default();
    let Some(entry) = manifest.entries.iter().find(|entry| {
        entry.kind == crdt_subscriptions::KIND_KV_STORE && entry.id == topic && entry.topic == topic
    }) else {
        return Ok(None);
    };
    if entry.role != crdt_subscriptions::ROLE_CREATED
        || !entry.name.eq_ignore_ascii_case(app)
        || entry.extra.get("policy").and_then(|value| value.as_str()) != Some("signed")
        || entry
            .extra
            .get("expected_owner")
            .and_then(|value| value.as_str())
            != Some(owner_hex.as_str())
    {
        return Err(api_error(
            StatusCode::CONFLICT,
            "legacy source manifest authority binding is invalid",
        ));
    }
    let snapshot_path = state.kv_store_state_dir.join(format!("{store_id_hex}.bin"));
    let metadata = tokio::fs::metadata(&snapshot_path).await.map_err(|error| {
        api_error(
            StatusCode::CONFLICT,
            format!("legacy source snapshot is unavailable: {error}"),
        )
    })?;
    if metadata.len() > LEGACY_PAGE_SNAPSHOT_MAX_BYTES {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "legacy source snapshot exceeds the migration limit",
        ));
    }
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(&snapshot_path)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::CONFLICT,
                format!("legacy source snapshot cannot be read: {error}"),
            )
        })?;
    let mut bytes = Vec::new();
    file.take(LEGACY_PAGE_SNAPSHOT_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::CONFLICT,
                format!("legacy source snapshot cannot be read: {error}"),
            )
        })?;
    if bytes.len() as u64 > LEGACY_PAGE_SNAPSHOT_MAX_BYTES {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "legacy source snapshot exceeds the migration limit",
        ));
    }
    let store = x0x::kv::sync::load_snapshot_bytes(&bytes).map_err(|error| {
        api_error(
            StatusCode::CONFLICT,
            format!("legacy source snapshot is invalid: {error}"),
        )
    })?;
    if store.id() != &store_id
        || store.owner() != Some(&owner)
        || store.policy() != &x0x::kv::AccessPolicy::Signed
    {
        return Err(api_error(
            StatusCode::CONFLICT,
            "legacy source snapshot binding is invalid",
        ));
    }
    Ok(Some(LoadedLegacyStore {
        store,
        store_id_hex,
        topic,
        owner,
        digest: hex::encode(blake3::hash(&bytes).as_bytes()),
        bytes,
    }))
}

fn group_writer(info: &x0x::groups::GroupInfo, agent: &AgentId) -> bool {
    TreeKemGroupStoreProtector::permits(info, agent, true)
        && !info.withdrawn
        && !info.is_fork_quarantined()
}

fn migration_authority_binding(info: &x0x::groups::GroupInfo) -> String {
    format!(
        "{}:{}:{}",
        info.state_revision,
        info.state_hash,
        info.security_binding.as_deref().unwrap_or("")
    )
}

async fn preview_legacy_import_conflicts(
    state: &AppState,
    destination_topic: &str,
    destination_store_id: &x0x::kv::KvStoreId,
    source: &x0x::kv::KvStore,
) -> Result<Vec<String>, GroupStoreResponse> {
    if let Some(handle) = state.kv_stores.read().await.get(destination_topic).cloned() {
        return Ok(handle.legacy_import_conflicts(source).await);
    }
    let path = state.kv_store_state_dir.join(format!(
        "{}.bin",
        hex::encode(destination_store_id.as_bytes())
    ));
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(api_error(
                StatusCode::CONFLICT,
                format!("destination snapshot cannot be previewed: {error}"),
            ))
        }
    };
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    file.take(LEGACY_PAGE_SNAPSHOT_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::CONFLICT,
                format!("destination snapshot cannot be previewed: {error}"),
            )
        })?;
    if bytes.len() as u64 > LEGACY_PAGE_SNAPSHOT_MAX_BYTES {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "destination snapshot exceeds the migration preview limit",
        ));
    }
    let destination = x0x::kv::sync::load_snapshot_bytes(&bytes).map_err(|error| {
        api_error(
            StatusCode::CONFLICT,
            format!("destination snapshot cannot be previewed: {error}"),
        )
    })?;
    Ok(destination.legacy_import_conflicts(source))
}

pub(in crate::server) async fn list_legacy_page_imports(
    State(state): State<Arc<AppState>>,
    Path((id, app)): Path<(String, String)>,
    Extension(actor): Extension<crate::server::rider_auth::ActorContext>,
) -> (StatusCode, Json<serde_json::Value>) {
    let app = match legacy_page_app(&app) {
        Ok(app) => app,
        Err(response) => return response,
    };
    let (stable_group_id, ambiguous, binding, can_import) = {
        let groups = state.named_groups.read().await;
        let (_, info) = match find_store_group(&groups, &id) {
            Ok(found) => found,
            Err(response) => return response,
        };
        let stable = info.stable_group_id().to_string();
        if id != stable {
            return bad_request("legacy imports require the full canonical group id");
        }
        if !matches!(
            &actor,
            crate::server::rider_auth::ActorContext::Owner { .. }
        ) {
            return forbidden("legacy source export requires the local owner authority");
        }
        if !actor.rider_allows_group(&stable) {
            return forbidden("rider token is not granted this group");
        }
        let Some(prefix) = stable.get(..16) else {
            return bad_request("stable group id is too short for a legacy alias");
        };
        let matches = groups
            .values()
            .filter(|candidate| candidate.stable_group_id().starts_with(prefix))
            .count();
        let public = info.policy.confidentiality == x0x::groups::GroupConfidentiality::SignedPublic;
        let treekem = !public && info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem;
        let binding = if public {
            resolve_public_group_store(&groups, &id, app, &state.agent.agent_id())
        } else if treekem {
            resolve_treekem_group_store(&groups, &id, app, &state.agent.agent_id())
        } else {
            resolve_gss_group_store(&groups, &id, app, &state.agent.agent_id())
        };
        let binding = match binding {
            Ok(binding) => binding,
            Err(response) => return response,
        };
        let can_import = group_writer(info, &state.agent.agent_id());
        (stable, matches > 1, binding, can_import)
    };
    let source = match load_legacy_page_store(&state, &stable_group_id, app, None).await {
        Ok(source) => source,
        Err(response) => return response,
    };
    let receipts = match super::super::legacy_store_migration::read_receipts(
        &super::super::legacy_store_migration::journal_path(&state.kv_store_state_dir),
    )
    .await
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return api_error(
                StatusCode::CONFLICT,
                format!("legacy import receipt journal is unreadable: {error}"),
            )
        }
    };
    let intents =
        match super::super::legacy_store_migration::read_intents(&state.kv_store_state_dir).await {
            Ok(intents) => intents,
            Err(error) => {
                return api_error(
                    StatusCode::CONFLICT,
                    format!("legacy import intent journal is unreadable: {error}"),
                )
            }
        };
    let local_endorser = hex::encode(state.agent.agent_id().as_bytes());
    let mut relevant_intents = Vec::new();
    for intent in intents {
        if receipts
            .iter()
            .any(|receipt| receipt.idempotency_key == intent.idempotency_key)
        {
            continue;
        }
        if intent.group_id != stable_group_id || intent.app != app {
            continue;
        }
        if intent.endorser != local_endorser {
            return api_error(
                StatusCode::CONFLICT,
                "legacy import intent owner binding is invalid",
            );
        }
        relevant_intents.push(intent);
    }
    let conflicts = match source.as_ref() {
        Some(source) => match preview_legacy_import_conflicts(
            &state,
            &binding.topic,
            &binding.store_id,
            &source.store,
        )
        .await
        {
            Ok(conflicts) => conflicts,
            Err(response) => return response,
        },
        None => Vec::new(),
    };
    let mut candidates = source
        .into_iter()
        .map(|source| {
            let receipt = receipts.iter().find(|receipt| {
                receipt.group_id == stable_group_id
                    && receipt.app == app
                    && receipt.source_store_id == source.store_id_hex
                    && receipt.source_digest == source.digest
            });
            LegacyStoreCandidate {
                target_group_id: stable_group_id.clone(),
                imported: receipt.is_some(),
                import_pending: false,
                publish_pending: receipt
                    .is_some_and(|receipt| receipt.publish_accepted_at_ms.is_none()),
                publish_accepted: receipt
                    .is_some_and(|receipt| receipt.publish_accepted_at_ms.is_some()),
                import_idempotency_key: receipt.map(|receipt| receipt.idempotency_key.clone()),
                source_store_id: source.store_id_hex,
                topic: source.topic,
                owner: hex::encode(source.owner.as_bytes()),
                source_digest: source.digest,
                active_keys: source.store.active_keys().len(),
                keys: {
                    let mut keys = source
                        .store
                        .active_keys()
                        .into_iter()
                        .cloned()
                        .collect::<Vec<_>>();
                    keys.sort();
                    keys
                },
                ambiguous_group_prefix: ambiguous,
                conflicts: conflicts.clone(),
                can_import,
                import_refusal_reason: (!can_import)
                    .then(|| "your current group role cannot endorse legacy history".to_string()),
            }
        })
        .collect::<Vec<_>>();
    for intent in relevant_intents {
        let recovered =
            match recover_intended_legacy_source(&state, &stable_group_id, app, &intent).await {
                Ok(source) => source,
                Err(response) => return response,
            };
        candidates.retain(|candidate| {
            candidate.source_store_id != intent.source_store_id
                || candidate.source_digest != intent.source_digest
                || candidate.import_pending
        });
        let conflicts = match preview_legacy_import_conflicts(
            &state,
            &binding.topic,
            &binding.store_id,
            &recovered.store,
        )
        .await
        {
            Ok(conflicts) => conflicts,
            Err(response) => return response,
        };
        let mut keys = recovered
            .store
            .active_keys()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        candidates.push(LegacyStoreCandidate {
            target_group_id: stable_group_id.clone(),
            source_store_id: recovered.store_id_hex,
            topic: recovered.topic,
            owner: hex::encode(recovered.owner.as_bytes()),
            source_digest: recovered.digest,
            active_keys: keys.len(),
            keys,
            ambiguous_group_prefix: ambiguous,
            conflicts,
            imported: false,
            import_pending: true,
            publish_pending: false,
            publish_accepted: false,
            import_idempotency_key: Some(intent.idempotency_key),
            can_import,
            import_refusal_reason: (!can_import)
                .then(|| "your current group role cannot endorse legacy history".to_string()),
        });
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "candidates": candidates})),
    )
}

pub(in crate::server) async fn download_legacy_page_import(
    State(state): State<Arc<AppState>>,
    Path((id, app, source_id)): Path<(String, String, String)>,
    Extension(actor): Extension<crate::server::rider_auth::ActorContext>,
    Query(query): Query<LegacyDownloadQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let app = match legacy_page_app(&app) {
        Ok(app) => app,
        Err(response) => return response,
    };
    let stable = {
        let groups = state.named_groups.read().await;
        let (_, info) = match find_store_group(&groups, &id) {
            Ok(found) => found,
            Err(response) => return response,
        };
        let stable = info.stable_group_id().to_string();
        if id != stable {
            return bad_request("legacy imports require the full canonical group id");
        }
        if !matches!(
            &actor,
            crate::server::rider_auth::ActorContext::Owner { .. }
        ) {
            return forbidden("legacy source export requires the local owner authority");
        }
        stable
    };
    if let Some(idempotency_key) = query.idempotency_key.as_deref() {
        let intent = match super::super::legacy_store_migration::read_intent(
            &state.kv_store_state_dir,
            idempotency_key,
        )
        .await
        {
            Ok(Some(intent)) => intent,
            Ok(None) => return not_found("legacy import intent is not registered on this device"),
            Err(error) => {
                return api_error(
                    StatusCode::CONFLICT,
                    format!("legacy import intent is unreadable: {error}"),
                )
            }
        };
        if intent.group_id != stable
            || intent.app != app
            || intent.source_store_id != source_id
            || intent.endorser != hex::encode(state.agent.agent_id().as_bytes())
        {
            return api_error(
                StatusCode::CONFLICT,
                "legacy import intent does not match the requested source",
            );
        }
        let source = match recover_intended_legacy_source(&state, &stable, app, &intent).await {
            Ok(source) => source,
            Err(response) => return response,
        };
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "source_store_id": source.store_id_hex,
                "source_digest": source.digest,
                "snapshot_b64": BASE64.encode(source.bytes),
            })),
        );
    }
    match load_legacy_page_store(&state, &stable, app, Some(&source_id)).await {
        Ok(Some(source)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "source_store_id": source.store_id_hex,
                "source_digest": source.digest,
                "snapshot_b64": BASE64.encode(source.bytes),
            })),
        ),
        Ok(None) => not_found("legacy source is not registered on this device"),
        Err(response) => response,
    }
}

/// Rebuild the reviewed legacy source from a durable pre-merge intent.
///
/// The preserved bytes must still match the intent's recorded digest and the
/// deterministic (topic, owner, policy, store id) binding, so a corrupt or
/// tampered journal cannot inject foreign content into the canonical
/// destination. This NEVER reads the live legacy store — recovery replays
/// exactly what was reviewed.
async fn recover_intended_legacy_source(
    state: &AppState,
    stable_group_id: &str,
    app: &str,
    intent: &super::super::legacy_store_migration::LegacyImportIntent,
) -> Result<LoadedLegacyStore, GroupStoreResponse> {
    let topic = legacy_page_topic(stable_group_id, app)?;
    let owner = state.agent.agent_id();
    let store_id = x0x::kv::KvStoreId::for_topic_owner(&topic, &owner);
    let bytes = intent.source_snapshot().map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("legacy import intent snapshot is unreadable: {error}"),
        )
    })?;
    if bytes.len() as u64 > LEGACY_PAGE_SNAPSHOT_MAX_BYTES {
        return Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "legacy import intent snapshot exceeds the migration limit",
        ));
    }
    let digest = hex::encode(blake3::hash(&bytes).as_bytes());
    if digest != intent.source_digest {
        return Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "legacy import intent snapshot does not match its recorded digest",
        ));
    }
    let store = x0x::kv::sync::load_snapshot_bytes(&bytes).map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("legacy import intent snapshot is invalid: {error}"),
        )
    })?;
    if hex::encode(store_id.as_bytes()) != intent.source_store_id
        || store.id() != &store_id
        || store.owner() != Some(&owner)
        || store.policy() != &x0x::kv::AccessPolicy::Signed
    {
        return Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "legacy import intent source binding is invalid",
        ));
    }
    Ok(LoadedLegacyStore {
        store,
        store_id_hex: intent.source_store_id.clone(),
        topic,
        owner,
        digest,
        bytes,
    })
}

pub(in crate::server) async fn import_legacy_page_store(
    State(state): State<Arc<AppState>>,
    Path((id, app, source_id)): Path<(String, String, String)>,
    Extension(actor): Extension<crate::server::rider_auth::ActorContext>,
    Json(request): Json<ImportLegacyStoreRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let app = match legacy_page_app(&app) {
        Ok(app) => app,
        Err(response) => return response,
    };
    if request.idempotency_key.trim().is_empty() || request.idempotency_key.len() > 128 {
        return bad_request("idempotency_key must contain 1 to 128 characters");
    }
    let reservation = crdt_subscriptions::handle_reservation(
        &state,
        "legacy_page_import",
        &request.idempotency_key,
    )
    .await;
    let _reservation_guard = reservation.lock().await;
    let membership = super::named_groups::group_membership_lock(&state, &id).await;
    let membership_guard = membership.lock().await;
    let (binding, authority_binding, public, treekem) = {
        let groups = state.named_groups.read().await;
        let (_, info) = match find_store_group(&groups, &id) {
            Ok(found) => found,
            Err(response) => return response,
        };
        let stable = info.stable_group_id();
        if id != stable {
            return bad_request("legacy imports require the full canonical group id");
        }
        if !matches!(
            &actor,
            crate::server::rider_auth::ActorContext::Owner { .. }
        ) {
            return forbidden("legacy source export requires the local owner authority");
        }
        if !actor.rider_allows_group(stable) {
            return forbidden("rider token is not granted this group");
        }
        if !group_writer(info, &state.agent.agent_id()) {
            return forbidden("current group role cannot endorse legacy history");
        }
        let public = info.policy.confidentiality == x0x::groups::GroupConfidentiality::SignedPublic;
        let treekem = !public && info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem;
        let resolved = if public {
            resolve_public_group_store(&groups, &id, app, &state.agent.agent_id())
        } else if treekem {
            resolve_treekem_group_store(&groups, &id, app, &state.agent.agent_id())
        } else {
            resolve_gss_group_store(&groups, &id, app, &state.agent.agent_id())
        };
        let binding = match resolved {
            Ok(binding) => binding,
            Err(response) => return response,
        };
        (binding, migration_authority_binding(info), public, treekem)
    };
    let receipt_path =
        super::super::legacy_store_migration::journal_path(&state.kv_store_state_dir);
    let receipts = match super::super::legacy_store_migration::read_receipts(&receipt_path).await {
        Ok(receipts) => receipts,
        Err(error) => {
            return api_error(
                StatusCode::CONFLICT,
                format!("legacy import receipt journal is unreadable: {error}"),
            )
        }
    };
    let existing_receipt = receipts
        .iter()
        .find(|receipt| receipt.idempotency_key == request.idempotency_key)
        .cloned();
    if let Some(existing) = existing_receipt.as_ref() {
        let same = existing.group_id == binding.stable_group_id
            && existing.app == app
            && existing.source_store_id == source_id
            && existing.source_digest == request.source_digest;
        if !same {
            return api_error(
                StatusCode::CONFLICT,
                "idempotency key already binds different import arguments",
            );
        }
        // The receipt is the durable idempotency binding, so a pre-merge
        // intent snapshot left by a crash between the receipt append and the
        // intent removal is redundant. Best-effort: a failed removal must
        // not fail an otherwise durable import, and the next retry retries.
        let _ = super::super::legacy_store_migration::remove_intent(
            &state.kv_store_state_dir,
            &request.idempotency_key,
        )
        .await;
        if existing.publish_accepted_at_ms.is_some() {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true, "receipt": existing,
                    "imported_locally": true, "publish_accepted": true
                })),
            );
        }
    }
    let existing_intent = if existing_receipt.is_none() {
        match super::super::legacy_store_migration::read_intent(
            &state.kv_store_state_dir,
            &request.idempotency_key,
        )
        .await
        {
            Ok(intent) => intent,
            Err(error) => {
                return api_error(
                    StatusCode::CONFLICT,
                    format!("legacy import intent journal is unreadable: {error}"),
                )
            }
        }
    } else {
        None
    };
    if let Some(intent) = existing_intent.as_ref() {
        let same = intent.group_id == binding.stable_group_id
            && intent.app == app
            && intent.source_store_id == source_id
            && intent.source_digest == request.source_digest;
        if !same {
            return api_error(
                StatusCode::CONFLICT,
                "idempotency key already binds different import arguments",
            );
        }
        // The intent file survived a prior attempt whose kv_state_dir sync
        // may never have completed: prove the directory entry is durable
        // before this retry is allowed to mutate the canonical destination.
        if let Err(error) = super::super::legacy_store_migration::ensure_intent_durable(
            &state.kv_store_state_dir,
            &request.idempotency_key,
        )
        .await
        {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "legacy import intent durability is unproven; canonical destination is unmodified: {error}"
                ),
            );
        }
    }
    let source = if existing_receipt.is_none() {
        if let Some(intent) = existing_intent.as_ref() {
            // Recover the reviewed source from the durable intent instead
            // of the on-disk legacy store: a retry after a merge-persist or
            // receipt-append failure finishes the ORIGINAL import even when
            // the source was edited after review.
            match recover_intended_legacy_source(&state, &binding.stable_group_id, app, intent)
                .await
            {
                Ok(source) => Some(source),
                Err(response) => return response,
            }
        } else {
            match load_legacy_page_store(&state, &binding.stable_group_id, app, Some(&source_id))
                .await
            {
                Ok(Some(source)) => Some(source),
                Ok(None) => return not_found("legacy source is not registered on this device"),
                Err(response) => return response,
            }
        }
    } else {
        // Pending retries publish the already-persisted canonical image and
        // never remerge or create a duplicate receipt.
        None
    };
    if source
        .as_ref()
        .is_some_and(|source| source.digest != request.source_digest)
    {
        return api_error(
            StatusCode::CONFLICT,
            "legacy source changed after it was reviewed",
        );
    }
    if let Some(source) = source.as_ref() {
        if let Err(error) =
            x0x::kv::KvStore::validate_legacy_signed_source(&source.store, source.owner)
        {
            return api_error(
                StatusCode::CONFLICT,
                format!("legacy source content is invalid: {error}"),
            );
        }
    }
    if existing_intent.is_none() && existing_receipt.is_none() {
        // Durable intent BEFORE any canonical mutation: bind the reviewed
        // snapshot to this idempotency key first, so a crash or receipt
        // append failure after the merge can still finish this exact import.
        let Some(source) = source.as_ref() else {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "legacy source unavailable",
            );
        };
        if let Err(error) = super::super::legacy_store_migration::write_intent(
            &state.kv_store_state_dir,
            super::super::legacy_store_migration::LegacyImportIntentInput {
                idempotency_key: request.idempotency_key.clone(),
                group_id: binding.stable_group_id.clone(),
                app: app.to_string(),
                source_store_id: source.store_id_hex.clone(),
                source_digest: source.digest.clone(),
                endorser: hex::encode(state.agent.agent_id().as_bytes()),
                authority_binding: authority_binding.clone(),
                source_snapshot: source.bytes.clone(),
            },
        )
        .await
        {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "legacy import intent did not persist; canonical destination is unmodified: {error}"
                ),
            );
        }
    }
    let (handle, created) = if public {
        match open_bound_public_store(&state, &binding).await {
            Ok((handle, _, created)) => (handle, created),
            Err(response) => return response,
        }
    } else if treekem {
        match open_bound_treekem_store(&state, &binding).await {
            Ok((handle, _, created)) => (handle, created),
            Err(response) => return response,
        }
    } else {
        match open_bound_gss_store(&state, &binding).await {
            Ok((handle, _, created)) => (handle, created),
            Err(response) => return response,
        }
    };
    if created {
        state
            .kv_stores
            .write()
            .await
            .insert(binding.topic.clone(), handle.clone());
    }
    let (receipt, conflicts) = if let Some(existing) = existing_receipt {
        (existing, Vec::new())
    } else {
        let Some(source) = source else {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "legacy source unavailable",
            );
        };
        let conflicts = handle.legacy_import_conflicts(&source.store).await;
        let before = handle.retained_content_digest_hex().await;
        if let Err(error) = handle
            .import_legacy_signed_history(&source.store, source.owner)
            .await
        {
            return match error {
                x0x::error::IdentityError::Unauthorized(message) => forbidden(message),
                other => api_error(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
            };
        }
        let after = handle.retained_content_digest_hex().await;
        let receipt = super::super::legacy_store_migration::new_receipt(
            super::super::legacy_store_migration::LegacyImportReceiptInput {
                idempotency_key: request.idempotency_key.clone(),
                group_id: binding.stable_group_id,
                app: app.to_string(),
                source_store_id: source.store_id_hex,
                source_digest: source.digest,
                endorser: hex::encode(state.agent.agent_id().as_bytes()),
                authority_binding,
                destination_digest_before: before,
                destination_digest_after: after,
            },
        );
        if let Err(error) =
            super::super::legacy_store_migration::append_receipt(&receipt_path, receipt.clone())
                .await
        {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("destination persisted but import receipt did not: {error}"),
            );
        }
        // The receipt is now the durable binding; the preserved intent
        // snapshot is redundant. Best-effort — the next retry retries it.
        let _ = super::super::legacy_store_migration::remove_intent(
            &state.kv_store_state_dir,
            &request.idempotency_key,
        )
        .await;
        (receipt, conflicts)
    };
    drop(membership_guard);
    if let Err(error) = handle.publish_retained_group_history().await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("import persisted locally but sync publication is pending: {error}"),
                "receipt": receipt,
                "idempotency_key": receipt.idempotency_key,
                "imported_locally": true,
                "publish_accepted": false,
            })),
        );
    }
    let accepted = match super::super::legacy_store_migration::mark_publish_accepted(
        &receipt_path,
        &receipt.idempotency_key,
    )
    .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!("import persisted and publication was accepted, but receipt status remains pending: {error}"),
                    "receipt": receipt,
                    "idempotency_key": receipt.idempotency_key,
                    "imported_locally": true,
                    "publish_accepted": false,
                })),
            )
        }
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true, "receipt": accepted, "conflicts": conflicts,
            "imported_locally": true, "publish_accepted": true
        })),
    )
}

// ---------------------------------------------------------------------------
// Direct messaging handlers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_store_delta_direct_payload_is_prefixed_json() {
        let peer_id = saorsa_gossip_types::PeerId::new([9; 32]);
        let delta = x0x::kv::KvStoreDelta::new(42);

        let payload = encode_kv_store_delta_direct_payload("store-1", peer_id, &delta)
            .expect("payload should encode");
        assert!(payload.starts_with(KV_STORE_DELTA_DM_PREFIX));

        let decoded: KvStoreDirectDelta =
            serde_json::from_slice(&payload[KV_STORE_DELTA_DM_PREFIX.len()..])
                .expect("payload JSON should decode");
        assert_eq!(decoded.store_id, "store-1");
        assert_eq!(decoded.peer_id, peer_id);
        assert_eq!(decoded.delta.version, delta.version);
    }

    // -- #341 Phase B: POST /groups/:id/stores ---------------------------------

    use crate::groups::{GroupConfidentiality, GroupInfo, GroupPolicy, GssKvSecureContext};
    use crate::mls::SecureGroupPlane;

    fn binding_fixture(id: &str) -> GroupInfo {
        let mut info = GroupInfo::with_policy(
            "group".into(),
            String::new(),
            AgentId([1; 32]),
            id.into(),
            GroupPolicy::default(),
        );
        info.policy.confidentiality = GroupConfidentiality::MlsEncrypted;
        info.secure_plane = SecureGroupPlane::Gss;
        info.add_member(
            hex::encode(AgentId([2; 32]).as_bytes()),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        info.shared_secret = Some(vec![7; 32]);
        info
    }

    #[test]
    fn issue565_full_group_and_trim_only_application_identity() {
        let first = "abcdef0123456789aaaaaaaaaaaaaaaa";
        let second = "abcdef0123456789bbbbbbbbbbbbbbbb";
        let groups = std::collections::HashMap::from([
            ("alias".into(), binding_fixture(first)),
            (second.into(), binding_fixture(second)),
        ]);
        let owner =
            resolve_gss_group_store(&groups, "alias", "  Wiki  ", &AgentId([1; 32])).unwrap();
        let member = resolve_gss_group_store(&groups, first, "Wiki", &AgentId([2; 32])).unwrap();
        assert_eq!(
            owner, member,
            "creator and member resolve the same full identity through alias/stable ID"
        );
        assert_ne!(
            owner.store_id,
            resolve_gss_group_store(&groups, second, "Wiki", &AgentId([2; 32]))
                .unwrap()
                .store_id
        );
        assert_ne!(
            owner.store_id,
            resolve_gss_group_store(&groups, first, "wiki", &AgentId([2; 32]))
                .unwrap()
                .store_id
        );
        assert!(resolve_gss_group_store(&groups, first, "  ", &AgentId([2; 32])).is_err());
    }

    #[test]
    fn signed_public_store_resolver_enforces_current_read_axis() {
        let group_id = "13".repeat(16);
        let creator = AgentId([1; 32]);
        let outsider = AgentId([2; 32]);
        let mut info = GroupInfo::new(
            "public".to_string(),
            String::new(),
            creator,
            group_id.clone(),
        );
        info.migrate_from_v1();
        info.policy.confidentiality = GroupConfidentiality::SignedPublic;
        info.policy.read_access = crate::groups::GroupReadAccess::Public;
        let mut groups = std::collections::HashMap::from([(group_id.clone(), info)]);
        assert!(resolve_public_group_store(&groups, &group_id, "Wiki", &outsider).is_ok());

        let info = groups.get_mut(&group_id).expect("group");
        info.policy.read_access = crate::groups::GroupReadAccess::MembersOnly;
        assert!(resolve_public_group_store(&groups, &group_id, "Wiki", &outsider).is_err());
        groups.get_mut(&group_id).expect("group").add_member(
            hex::encode(outsider.as_bytes()),
            crate::groups::GroupRole::Member,
            Some(hex::encode(creator.as_bytes())),
            None,
        );
        assert!(resolve_public_group_store(&groups, &group_id, "Wiki", &outsider).is_ok());
    }

    #[test]
    fn issue565_resolver_and_refresh_reject_ineligible_binding_and_fence_clones() {
        let gid = "ab".repeat(16);
        let base = binding_fixture(&gid);
        for case in 0..10 {
            let mut info = base.clone();
            match case {
                0 => info.withdrawn = true,
                1 => {
                    info.remove_member(&hex::encode(AgentId([2; 32]).as_bytes()), None);
                }
                2 => info.policy.confidentiality = GroupConfidentiality::SignedPublic,
                3 => info.secure_plane = SecureGroupPlane::TreeKem,
                4 => info.shared_secret = None,
                5 => info.creator = AgentId([9; 32]),
                6 => info = binding_fixture(&"cd".repeat(16)),
                8 | 9 => {
                    info.members_v2
                        .get_mut(&hex::encode(AgentId([2; 32]).as_bytes()))
                        .unwrap()
                        .state = if case == 8 {
                        x0x::groups::GroupMemberState::Pending
                    } else {
                        x0x::groups::GroupMemberState::Banned
                    };
                }
                _ => {}
            }
            let ctx = GssKvSecureContext::from_group(&base).unwrap();
            let cloned = ctx.clone();
            let current = (case != 7).then_some(&info);
            assert!(
                !refresh_gss_store_binding(&ctx, current, base.creator, &AgentId([2; 32])),
                "case {case}"
            );
            assert!(
                !cloned.is_active_member(&AgentId([2; 32])),
                "clone fenced case {case}"
            );
            let id = x0x::kv::encrypted::group_store_identity(&gid, "Wiki").0;
            assert!(cloned.seal(&id, b"private").is_err());
            if !(5..8).contains(&case) {
                let groups = std::collections::HashMap::from([(gid.clone(), info)]);
                assert!(resolve_gss_group_store(&groups, &gid, "Wiki", &AgentId([2; 32])).is_err());
            }
        }
        let ctx = GssKvSecureContext::from_group(&base).unwrap();
        let mut advanced = base.clone();
        advanced.secret_epoch += 1;
        assert!(refresh_gss_store_binding(
            &ctx,
            Some(&advanced),
            base.creator,
            &AgentId([2; 32])
        ));
        assert_eq!(ctx.current_epoch(), advanced.secret_epoch);
        let groups = std::collections::HashMap::from([(gid.clone(), base)]);
        assert!(resolve_gss_group_store(&groups, &gid, "Wiki", &AgentId([3; 32])).is_err());
        assert!(resolve_gss_group_store(&groups, "missing", "Wiki", &AgentId([2; 32])).is_err());
    }

    #[test]
    fn issue565_restore_manifest_cannot_supply_identity_or_authority() {
        let gid = "ab".repeat(16);
        let groups = std::collections::HashMap::from([(gid.clone(), binding_fixture(&gid))]);
        let binding = resolve_gss_group_store(&groups, &gid, "Wiki", &AgentId([2; 32])).unwrap();
        let good = crdt_subscriptions::CrdtSubscriptionEntry {
            kind: crdt_subscriptions::KIND_KV_STORE.into(),
            id: binding.topic.clone(),
            topic: binding.topic.clone(),
            name: binding.name.clone(),
            role: crdt_subscriptions::ROLE_CREATED.into(),
            extra: serde_json::Map::from_iter([
                ("stable_group_id".into(), serde_json::Value::String(gid)),
                (
                    "expected_owner".into(),
                    serde_json::Value::String(hex::encode(binding.creator.as_bytes())),
                ),
                (
                    "policy".into(),
                    serde_json::Value::String("encrypted".into()),
                ),
            ]),
        };
        assert!(validate_gss_store_manifest(&good, &binding, "encrypted", Some("gss")).is_ok());
        let mut hex_binding = binding.clone();
        hex_binding.creator = AgentId([0xab; 32]);
        let mut upper_owner = good.clone();
        upper_owner.extra.insert(
            "expected_owner".into(),
            serde_json::Value::String("AB".repeat(32)),
        );
        assert!(
            validate_gss_store_manifest(&upper_owner, &hex_binding, "encrypted", Some("gss"))
                .is_ok(),
            "preserve parsed owner-ID spelling compatibility"
        );
        for case in 0..6 {
            let mut entry = good.clone();
            match case {
                0 => entry.id = "different-registry-key".into(),
                1 => entry.topic = "different-topic".into(),
                2 => {
                    entry.extra.insert(
                        "expected_owner".into(),
                        serde_json::Value::String(hex::encode(AgentId([9; 32]).as_bytes())),
                    );
                }
                3 => {
                    entry.extra.insert(
                        "stable_group_id".into(),
                        serde_json::Value::String("foreign".into()),
                    );
                }
                4 => {
                    entry
                        .extra
                        .insert("policy".into(), serde_json::Value::String("signed".into()));
                }
                _ => entry.name = " Wiki ".into(),
            }
            assert!(
                validate_gss_store_manifest(&entry, &binding, "encrypted", Some("gss")).is_err(),
                "case {case}"
            );
        }
    }

    /// Explicit test-only network config (#417/#337): loopback bind, no
    /// seeds, discovery/port-mapping off. Still a real socket constructor.
    fn test_network_config() -> x0x::network::NetworkConfig {
        x0x::network::NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
            bootstrap_nodes: Vec::new(),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..x0x::network::NetworkConfig::default()
        }
    }

    /// Agent + AppState over a temp dir, WITH an in-process gossip runtime
    /// (the encrypted-store happy path spawns real sync loops).
    async fn encrypted_store_test_state() -> (Arc<AppState>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let agent = Arc::new(
            x0x::Agent::builder()
                .with_identity_dir(&data_dir)
                .with_machine_key(data_dir.join("machine.key"))
                .with_agent_key(x0x::identity::AgentKeypair::generate().unwrap())
                .with_agent_cert_path(data_dir.join("agent.cert"))
                .with_peer_cache_disabled()
                .with_contact_store_path(data_dir.join("contacts.json"))
                .with_network_config(test_network_config())
                .build()
                .await
                .unwrap(),
        );
        let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
            &data_dir, agent,
        )
        .await
        .unwrap();
        (state, dir)
    }

    fn owner_actor() -> crate::server::rider_auth::ActorContext {
        crate::server::rider_auth::ActorContext::Owner { durable: false }
    }

    async fn seed_legacy_page_source(
        state: &AppState,
        group_id: &str,
        app: &str,
    ) -> (String, x0x::KvStoreHandle) {
        let topic = legacy_page_topic(group_id, app).expect("legacy topic");
        let handle = state
            .agent
            .create_kv_store_persistent(
                app,
                &topic,
                x0x::kv::AccessPolicy::Signed,
                &state.kv_store_state_dir,
            )
            .await
            .expect("legacy store");
        handle
            .put(
                "shared".to_string(),
                b"legacy".to_vec(),
                "text/plain".to_string(),
            )
            .await
            .expect("legacy value");
        handle
            .put(
                "legacy-only".to_string(),
                b"history".to_vec(),
                "text/plain".to_string(),
            )
            .await
            .expect("legacy-only value");
        let source_id = hex::encode(
            x0x::kv::KvStoreId::for_topic_owner(&topic, &state.agent.agent_id()).as_bytes(),
        );
        crdt_subscriptions::record(
            state,
            crdt_subscriptions::CrdtSubscriptionEntry {
                kind: crdt_subscriptions::KIND_KV_STORE.to_string(),
                id: topic.clone(),
                name: app.to_string(),
                topic,
                role: crdt_subscriptions::ROLE_CREATED.to_string(),
                extra: serde_json::Map::from_iter([
                    ("policy".to_string(), serde_json::json!("signed")),
                    (
                        "expected_owner".to_string(),
                        serde_json::json!(hex::encode(state.agent.agent_id().as_bytes())),
                    ),
                ]),
            },
        )
        .await
        .expect("legacy manifest");
        (source_id, handle)
    }

    async fn seed_public_migration_group(state: &AppState, group_id: &str) {
        let mut info = GroupInfo::new(
            "migration".to_string(),
            String::new(),
            state.agent.agent_id(),
            group_id.to_string(),
        );
        info.migrate_from_v1();
        info.policy.confidentiality = GroupConfidentiality::SignedPublic;
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info);
    }

    #[tokio::test]
    async fn legacy_import_endpoint_discovery_authority_digest_and_stale_writer() {
        let (state, _dir) = encrypted_store_test_state().await;
        let group_id = "91".repeat(16);
        seed_public_migration_group(&state, &group_id).await;
        let (source_id, _source_handle) = seed_legacy_page_source(&state, &group_id, "wiki").await;

        let (code, body) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{body:?}");
        let candidate = &body.0["candidates"][0];
        assert_eq!(candidate["source_store_id"], source_id);
        assert_eq!(
            candidate["keys"],
            serde_json::json!(["legacy-only", "shared"])
        );
        let digest = candidate["source_digest"]
            .as_str()
            .expect("digest")
            .to_string();

        let (code, download) = download_legacy_page_import(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Query(LegacyDownloadQuery::default()),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{download:?}");
        assert_eq!(download.0["source_store_id"], source_id);
        assert_eq!(download.0["source_digest"], digest);
        assert!(
            download.0["snapshot_b64"]
                .as_str()
                .is_some_and(|snapshot| !snapshot.is_empty()),
            "download returns the reviewed immutable source snapshot: {download:?}"
        );

        let rider = crate::server::rider_auth::ActorContext::Rider {
            sub_agent_id: "rider".to_string(),
            token_id: 1,
            token_hash: "hash".to_string(),
            groups: vec![group_id.clone()],
        };
        let (code, _) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(rider),
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN);

        let manifest_before = tokio::fs::read(&state.crdt_subscriptions_path)
            .await
            .expect("manifest bytes");
        let mut forged_manifest: serde_json::Value =
            serde_json::from_slice(&manifest_before).expect("manifest json");
        let legacy_entry = forged_manifest["entries"]
            .as_array_mut()
            .expect("manifest entries")
            .iter_mut()
            .find(|entry| entry["id"] == legacy_page_topic(&group_id, "wiki").expect("topic"))
            .expect("legacy entry");
        // `CrdtSubscriptionEntry::extra` is flattened into the entry object.
        legacy_entry["expected_owner"] = serde_json::json!("00".repeat(32));
        // Hold the production manifest-writer lock while installing the
        // deliberately forged durable image. A concurrent registration must
        // not repair the fixture before the strict disk probe observes it.
        let manifest_guard = state.crdt_subscriptions_persistence_lock.lock().await;
        let forged_bytes = serde_json::to_vec(&forged_manifest).expect("forged manifest bytes");
        tokio::fs::write(&state.crdt_subscriptions_path, &forged_bytes)
            .await
            .expect("write forged manifest");
        assert_eq!(
            tokio::fs::read(&state.crdt_subscriptions_path)
                .await
                .expect("read forged manifest"),
            forged_bytes,
            "strict probe fixture is the durable manifest actually read"
        );
        let probed = crdt_subscriptions::probe_manifest_strict(&state.crdt_subscriptions_path)
            .await
            .expect("typed forged manifest probe")
            .expect("forged manifest exists");
        let probed_legacy = probed
            .entries
            .iter()
            .find(|entry| entry.id == legacy_page_topic(&group_id, "wiki").expect("topic"))
            .expect("typed legacy entry");
        assert_eq!(
            probed_legacy.extra.get("expected_owner"),
            Some(&serde_json::json!("00".repeat(32))),
            "typed production probe observes the forged authority binding"
        );
        let (code, _) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        assert_eq!(code, StatusCode::CONFLICT);
        tokio::fs::write(&state.crdt_subscriptions_path, manifest_before)
            .await
            .expect("restore manifest");
        drop(manifest_guard);

        let (code, _) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(ImportLegacyStoreRequest {
                source_digest: "forged".to_string(),
                idempotency_key: "forged-digest".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::CONFLICT);

        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_id).expect("group");
            info.policy.write_access = crate::groups::GroupWriteAccess::AdminOnly;
            info.members_v2
                .get_mut(&hex::encode(state.agent.agent_id().as_bytes()))
                .expect("local member")
                .role = crate::groups::GroupRole::Member;
        }
        let (code, _) = import_legacy_page_store(
            State(state),
            Path((group_id, "wiki".to_string(), source_id)),
            Extension(owner_actor()),
            Json(ImportLegacyStoreRequest {
                source_digest: digest,
                idempotency_key: "stale-writer".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn legacy_import_partial_publication_is_pending_and_exact_retry_marks_accepted() {
        let (state, _dir) = encrypted_store_test_state().await;
        let group_id = "92".repeat(16);
        seed_public_migration_group(&state, &group_id).await;
        state
            .named_groups
            .write()
            .await
            .get_mut(&group_id)
            .expect("group")
            .policy
            .write_access = crate::groups::GroupWriteAccess::AdminOnly;
        let (source_id, source_handle) = seed_legacy_page_source(&state, &group_id, "wiki").await;
        for index in 0..17 {
            source_handle
                .put(
                    format!("large-{index}"),
                    vec![index as u8; x0x::kv::entry::MAX_INLINE_SIZE],
                    "application/octet-stream".to_string(),
                )
                .await
                .expect("large retained source entry");
        }
        let (code, opened) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(group_id.clone()),
            Extension(owner_actor()),
            Json(CreateGroupStoreRequest {
                name: "wiki".to_string(),
            }),
        )
        .await;
        assert!(
            matches!(code, StatusCode::OK | StatusCode::CREATED),
            "{opened:?}"
        );
        let topic = opened.0["topic"].as_str().expect("topic");
        let handle = state
            .kv_stores
            .read()
            .await
            .get(topic)
            .cloned()
            .expect("destination handle");
        handle.fail_retained_publish_after_for_test(1);
        let (_, listing) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        let digest = listing.0["candidates"][0]["source_digest"]
            .as_str()
            .expect("source digest")
            .to_string();
        let request = || ImportLegacyStoreRequest {
            source_digest: digest.clone(),
            idempotency_key: "partial-publish".to_string(),
        };
        let (code, failed) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{failed:?}");
        assert_eq!(failed.0["imported_locally"], true);
        assert_eq!(failed.0["publish_accepted"], false);
        assert_eq!(handle.retained_publish_accepted_for_test(), 1);
        assert!(
            handle
                .get("legacy-only")
                .await
                .expect("imported read")
                .is_some(),
            "partial publication never rolls back the persisted import"
        );
        let receipt_path =
            crate::server::legacy_store_migration::journal_path(&state.kv_store_state_dir);
        let pending = crate::server::legacy_store_migration::read_receipts(&receipt_path)
            .await
            .expect("pending receipt");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].publish_accepted_at_ms, None);
        let (_, pending_listing) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        let pending_candidate = &pending_listing.0["candidates"][0];
        assert_eq!(pending_candidate["imported"], true);
        assert_eq!(pending_candidate["publish_pending"], true);
        assert_eq!(pending_candidate["publish_accepted"], false);
        assert_eq!(
            pending_candidate["import_idempotency_key"],
            "partial-publish"
        );
        source_handle
            .put(
                "after-reviewed-snapshot".to_string(),
                b"must not merge on retry".to_vec(),
                "text/plain".to_string(),
            )
            .await
            .expect("mutate source after reviewed import");

        {
            let mut groups = state.named_groups.write().await;
            groups
                .get_mut(&group_id)
                .expect("group")
                .members_v2
                .get_mut(&hex::encode(state.agent.agent_id().as_bytes()))
                .expect("local member")
                .role = crate::groups::GroupRole::Member;
        }
        let (code, _) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(
            code,
            StatusCode::FORBIDDEN,
            "pending retry must reauthorize"
        );
        assert_eq!(
            crate::server::legacy_store_migration::read_receipts(&receipt_path)
                .await
                .expect("still pending")[0]
                .publish_accepted_at_ms,
            None
        );
        {
            let mut groups = state.named_groups.write().await;
            groups
                .get_mut(&group_id)
                .expect("group")
                .members_v2
                .get_mut(&hex::encode(state.agent.agent_id().as_bytes()))
                .expect("local member")
                .role = crate::groups::GroupRole::Admin;
        }
        handle.clear_retained_publish_failure_for_test();
        let (code, retried) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{retried:?}");
        assert_eq!(retried.0["publish_accepted"], true);
        let accepted = crate::server::legacy_store_migration::read_receipts(&receipt_path)
            .await
            .expect("accepted receipt");
        assert_eq!(accepted.len(), 1, "retry must not duplicate receipt");
        assert!(accepted[0].publish_accepted_at_ms.is_some());
        assert!(
            handle
                .get("after-reviewed-snapshot")
                .await
                .expect("read canonical after retry")
                .is_none(),
            "pending retry republishes the persisted canonical image without remerging source"
        );
        let accepted_frames = handle.retained_publish_accepted_for_test();
        let (code, accepted_repeat) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{accepted_repeat:?}");
        assert_eq!(accepted_repeat.0["publish_accepted"], true);
        assert_eq!(
            handle.retained_publish_accepted_for_test(),
            accepted_frames,
            "accepted retry does not publish again"
        );

        let (code, _) = import_legacy_page_store(
            State(state),
            Path((group_id, "wiki".to_string(), source_id)),
            Extension(owner_actor()),
            Json(ImportLegacyStoreRequest {
                source_digest: "changed".to_string(),
                idempotency_key: "partial-publish".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn legacy_import_intent_persist_failure_leaves_destination_unmodified() {
        let (state, _dir) = encrypted_store_test_state().await;
        let group_id = "93".repeat(16);
        seed_public_migration_group(&state, &group_id).await;
        let (source_id, _source_handle) = seed_legacy_page_source(&state, &group_id, "wiki").await;
        let (code, opened) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(group_id.clone()),
            Extension(owner_actor()),
            Json(CreateGroupStoreRequest {
                name: "wiki".to_string(),
            }),
        )
        .await;
        assert!(
            matches!(code, StatusCode::OK | StatusCode::CREATED),
            "{opened:?}"
        );
        let topic = opened.0["topic"].as_str().expect("topic").to_string();
        let handle = state
            .kv_stores
            .read()
            .await
            .get(&topic)
            .cloned()
            .expect("destination handle");
        let (_, listing) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        let digest = listing.0["candidates"][0]["source_digest"]
            .as_str()
            .expect("source digest")
            .to_string();

        crate::server::legacy_store_migration::fail_next_intent_for_test("intent-fault");
        let (code, failed) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(ImportLegacyStoreRequest {
                source_digest: digest.clone(),
                idempotency_key: "intent-fault".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "{failed:?}");
        assert!(
            failed.0["error"]
                .as_str()
                .is_some_and(|error| error.contains("intent did not persist")),
            "must fail at the pre-mutation intent boundary: {failed:?}"
        );
        assert!(
            handle
                .get("legacy-only")
                .await
                .expect("read destination")
                .is_none(),
            "failed intent write must not merge any source content"
        );
        let receipt_path =
            crate::server::legacy_store_migration::journal_path(&state.kv_store_state_dir);
        assert!(
            crate::server::legacy_store_migration::read_receipts(&receipt_path)
                .await
                .expect("receipts after intent fault")
                .is_empty()
        );
        assert!(
            crate::server::legacy_store_migration::read_intent(
                &state.kv_store_state_dir,
                "intent-fault"
            )
            .await
            .expect("intent after fault")
            .is_none(),
            "failed intent write leaves no durable binding"
        );

        let (code, retried) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(ImportLegacyStoreRequest {
                source_digest: digest,
                idempotency_key: "intent-fault".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{retried:?}");
        assert_eq!(retried.0["publish_accepted"], true);
        assert!(handle
            .get("legacy-only")
            .await
            .expect("read after retry")
            .is_some());
        assert_eq!(
            crate::server::legacy_store_migration::read_receipts(&receipt_path)
                .await
                .expect("receipts after retry")
                .len(),
            1
        );
        assert!(
            crate::server::legacy_store_migration::read_intent(
                &state.kv_store_state_dir,
                "intent-fault"
            )
            .await
            .expect("intent after retry")
            .is_none(),
            "settled intent snapshot is removed once the receipt exists"
        );
    }

    #[tokio::test]
    async fn legacy_import_intent_directory_sync_failure_blocks_canonical_mutation() {
        let (state, _dir) = encrypted_store_test_state().await;
        let group_id = "97".repeat(16);
        seed_public_migration_group(&state, &group_id).await;
        let (source_id, _source_handle) = seed_legacy_page_source(&state, &group_id, "wiki").await;
        let (code, opened) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(group_id.clone()),
            Extension(owner_actor()),
            Json(CreateGroupStoreRequest {
                name: "wiki".to_string(),
            }),
        )
        .await;
        assert!(
            matches!(code, StatusCode::OK | StatusCode::CREATED),
            "{opened:?}"
        );
        let topic = opened.0["topic"].as_str().expect("topic").to_string();
        let handle = state
            .kv_stores
            .read()
            .await
            .get(&topic)
            .cloned()
            .expect("destination handle");
        let (_, listing) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        let digest = listing.0["candidates"][0]["source_digest"]
            .as_str()
            .expect("source digest")
            .to_string();
        let receipt_path =
            crate::server::legacy_store_migration::journal_path(&state.kv_store_state_dir);
        let request = || ImportLegacyStoreRequest {
            source_digest: digest.clone(),
            idempotency_key: "dir-sync-fault".to_string(),
        };

        // The atomic intent write succeeds but the kv_state_dir entry sync
        // fails: the intent file exists yet the route must refuse to mutate
        // the canonical destination on an unproven intent.
        crate::server::legacy_store_migration::fail_next_intent_dir_sync_for_test("dir-sync-fault");
        let (code, failed) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "{failed:?}");
        assert!(
            failed.0["error"]
                .as_str()
                .is_some_and(|error| error.contains("intent did not persist")),
            "fresh import stops at the intent durability boundary: {failed:?}"
        );
        assert!(
            crate::server::legacy_store_migration::read_intent(
                &state.kv_store_state_dir,
                "dir-sync-fault"
            )
            .await
            .expect("intent readable")
            .is_some(),
            "the intent file itself was written; only its durability is unproven"
        );
        // Path-target control: the durability sync must have fsynced
        // kv_state_dir ITSELF, never its parent — the exact regression
        // sync_parent_directory(kv_state_dir) would reintroduce.
        let target = crate::server::legacy_store_migration::intent_dir_sync_target_for_test(
            "dir-sync-fault",
        )
        .expect("sync target recorded");
        assert_eq!(
            target, state.kv_store_state_dir,
            "intent durability must fsync kv_state_dir itself"
        );
        assert_ne!(
            target,
            state.kv_store_state_dir.parent().expect("state dir parent"),
            "syncing kv_state_dir's PARENT leaves the intents directory entry unlinked"
        );
        assert!(
            handle
                .get("legacy-only")
                .await
                .expect("read destination")
                .is_none(),
            "unproven intent durability must block the canonical merge"
        );
        assert!(
            crate::server::legacy_store_migration::read_receipts(&receipt_path)
                .await
                .expect("receipts after dir-sync fault")
                .is_empty()
        );

        // Identical-intent retry with the sync still failing: the recovery
        // path must re-prove durability instead of merging on file presence.
        crate::server::legacy_store_migration::fail_next_intent_dir_sync_for_test("dir-sync-fault");
        let (code, retry_failed) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "{retry_failed:?}");
        assert!(
            retry_failed.0["error"]
                .as_str()
                .is_some_and(|error| error.contains("intent durability is unproven")),
            "recovery retry stops at the durability proof: {retry_failed:?}"
        );
        assert!(
            handle
                .get("legacy-only")
                .await
                .expect("read destination again")
                .is_none(),
            "canonical destination is still untouched"
        );
        assert!(
            crate::server::legacy_store_migration::read_receipts(&receipt_path)
                .await
                .expect("receipts after failed retry")
                .is_empty()
        );

        // With durability provable, the SAME key finishes the original
        // import exactly once.
        let (code, done) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id, "wiki".to_string(), source_id)),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{done:?}");
        assert_eq!(done.0["imported_locally"], true);
        assert_eq!(done.0["publish_accepted"], true);
        assert!(handle
            .get("legacy-only")
            .await
            .expect("read after completion")
            .is_some());
        assert_eq!(
            crate::server::legacy_store_migration::read_receipts(&receipt_path)
                .await
                .expect("receipts after completion")
                .len(),
            1
        );
        assert!(crate::server::legacy_store_migration::read_intent(
            &state.kv_store_state_dir,
            "dir-sync-fault"
        )
        .await
        .expect("intent after completion")
        .is_none());
    }

    #[tokio::test]
    async fn legacy_import_receipt_fault_intent_recovers_after_source_edit_and_reopen() {
        let (state, _dir) = encrypted_store_test_state().await;
        let group_id = "94".repeat(16);
        seed_public_migration_group(&state, &group_id).await;
        let (source_id, source_handle) = seed_legacy_page_source(&state, &group_id, "wiki").await;
        let source_path = state.kv_store_state_dir.join(format!("{source_id}.bin"));
        let source_before_edit = tokio::fs::read(&source_path)
            .await
            .expect("reviewed source bytes");
        let (code, opened) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(group_id.clone()),
            Extension(owner_actor()),
            Json(CreateGroupStoreRequest {
                name: "wiki".to_string(),
            }),
        )
        .await;
        assert!(
            matches!(code, StatusCode::OK | StatusCode::CREATED),
            "{opened:?}"
        );
        let topic = opened.0["topic"].as_str().expect("topic").to_string();
        let handle = state
            .kv_stores
            .read()
            .await
            .get(&topic)
            .cloned()
            .expect("destination handle");
        let (_, listing) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        let digest = listing.0["candidates"][0]["source_digest"]
            .as_str()
            .expect("source digest")
            .to_string();

        // Destination persists, receipt append fails: the exact PR727 window.
        crate::server::legacy_store_migration::fail_next_append_for_test("intent-recovery");
        let request = || ImportLegacyStoreRequest {
            source_digest: digest.clone(),
            idempotency_key: "intent-recovery".to_string(),
        };
        let (code, failed) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "{failed:?}");
        assert!(
            failed.0["error"].as_str().is_some_and(
                |error| error.contains("destination persisted but import receipt did not")
            ),
            "must reach the post-persist receipt append boundary: {failed:?}"
        );
        assert!(
            handle
                .get("legacy-only")
                .await
                .expect("read applied content")
                .is_some(),
            "merge applied before the receipt fault"
        );
        let intent = crate::server::legacy_store_migration::read_intent(
            &state.kv_store_state_dir,
            "intent-recovery",
        )
        .await
        .expect("intent journal readable")
        .expect("durable intent survived the receipt fault");
        assert_eq!(intent.source_digest, digest);
        let receipt_path =
            crate::server::legacy_store_migration::journal_path(&state.kv_store_state_dir);
        assert!(
            crate::server::legacy_store_migration::read_receipts(&receipt_path)
                .await
                .expect("receipts after fault")
                .is_empty()
        );

        // The reviewed source changes AFTER the failed import attempt.
        source_handle
            .put(
                "post-review-edit".to_string(),
                b"edited after review".to_vec(),
                "text/plain".to_string(),
            )
            .await
            .expect("edit legacy source after failed import");
        let source_after_edit = tokio::fs::read(&source_path)
            .await
            .expect("source bytes after edit");
        let (endorser, authority_binding) = {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_id).expect("group");
            let values = (
                hex::encode(state.agent.agent_id().as_bytes()),
                migration_authority_binding(info),
            );
            info.state_revision = info.state_revision.saturating_add(1);
            values
        };
        crate::server::legacy_store_migration::write_intent(
            &state.kv_store_state_dir,
            crate::server::legacy_store_migration::LegacyImportIntentInput {
                idempotency_key: "intent-recovery-second".to_string(),
                group_id: group_id.clone(),
                app: "wiki".to_string(),
                source_store_id: source_id.clone(),
                source_digest: digest.clone(),
                endorser,
                authority_binding,
                source_snapshot: source_before_edit.clone(),
            },
        )
        .await
        .expect("second pending key for the same reviewed source");

        // Daemon-restart seam: drop the live handle so the retry reopens the
        // destination from its persisted snapshot and the intent from disk.
        handle.retire();
        state.kv_stores.write().await.remove(&topic);
        let (_, pending_listing) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        let candidates = pending_listing.0["candidates"]
            .as_array()
            .expect("candidate array");
        assert_eq!(
            candidates.len(),
            3,
            "changed source and both pending keys stay distinct"
        );
        assert_eq!(
            candidates
                .iter()
                .filter(|candidate| candidate["import_pending"] == true)
                .count(),
            2,
            "each unsettled idempotency key retains a recovery card"
        );
        let pending_candidate = candidates
            .iter()
            .find(|candidate| candidate["import_idempotency_key"] == "intent-recovery")
            .expect("original pending reviewed intent candidate");
        assert_eq!(
            pending_candidate["imported"], false,
            "an intent is not a completed local import"
        );
        assert_eq!(pending_candidate["source_digest"], digest);
        assert_eq!(
            pending_candidate["import_idempotency_key"],
            "intent-recovery"
        );
        let current_candidate = candidates
            .iter()
            .find(|candidate| candidate["import_pending"] == false)
            .expect("changed current-source candidate");
        assert_ne!(current_candidate["source_digest"], digest);

        let (code, preserved_download) = download_legacy_page_import(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Query(LegacyDownloadQuery {
                idempotency_key: Some("intent-recovery".to_string()),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{preserved_download:?}");
        let preserved_bytes = BASE64
            .decode(
                preserved_download.0["snapshot_b64"]
                    .as_str()
                    .expect("preserved snapshot"),
            )
            .expect("decode preserved snapshot");
        assert_eq!(preserved_bytes, source_before_edit);
        assert_eq!(preserved_download.0["source_digest"], digest);

        // Same ORIGINAL key and digest resumes the original import.
        let (code, retried) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{retried:?}");
        assert_eq!(retried.0["imported_locally"], true);
        assert_eq!(retried.0["publish_accepted"], true);
        let handle = state
            .kv_stores
            .read()
            .await
            .get(&topic)
            .cloned()
            .expect("reopened destination handle");
        assert!(
            handle
                .get("legacy-only")
                .await
                .expect("read recovered content")
                .is_some(),
            "no imported data was lost across the fault and reopen"
        );
        assert!(handle.get("shared").await.expect("read shared").is_some(),);
        assert!(
            handle
                .get("post-review-edit")
                .await
                .expect("read post-review key")
                .is_none(),
            "recovery merges the preserved reviewed snapshot, never the edited source"
        );
        assert_eq!(
            crate::server::legacy_store_migration::read_receipts(&receipt_path)
                .await
                .expect("receipts after recovery")
                .len(),
            1,
            "recovery publishes exactly one receipt for the original key"
        );
        assert!(
            crate::server::legacy_store_migration::read_intent(
                &state.kv_store_state_dir,
                "intent-recovery"
            )
            .await
            .expect("intent after recovery")
            .is_none(),
            "settled intent snapshot is removed"
        );
        assert_eq!(
            tokio::fs::read(&source_path).await.expect("source after"),
            source_after_edit,
            "recovery never mutates the legacy source"
        );
    }

    #[tokio::test]
    async fn legacy_import_listing_fails_closed_on_corrupt_or_excess_intents() {
        let (state, _dir) = encrypted_store_test_state().await;
        let group_id = "9a".repeat(16);
        seed_public_migration_group(&state, &group_id).await;
        seed_legacy_page_source(&state, &group_id, "wiki").await;
        let corrupt_path = crate::server::legacy_store_migration::intent_path(
            &state.kv_store_state_dir,
            "corrupt-listing",
        );
        tokio::fs::create_dir_all(corrupt_path.parent().expect("intent directory"))
            .await
            .expect("create intent directory");
        tokio::fs::write(&corrupt_path, b"{}")
            .await
            .expect("write corrupt intent");
        let (code, body) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        assert_eq!(code, StatusCode::CONFLICT, "{body:?}");
        assert!(body.0["error"]
            .as_str()
            .is_some_and(|error| error.contains("intent journal is unreadable")));

        let intent_directory = corrupt_path.parent().expect("intent directory");
        tokio::fs::remove_dir_all(intent_directory)
            .await
            .expect("remove corrupt fixture");
        tokio::fs::create_dir_all(intent_directory)
            .await
            .expect("recreate intent directory");
        for index in 0..=128 {
            tokio::fs::write(intent_directory.join(format!("{index:064x}.json")), b"{}")
                .await
                .expect("write count-bound fixture");
        }
        let (code, body) = list_legacy_page_imports(
            State(state),
            Path((group_id, "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        assert_eq!(code, StatusCode::CONFLICT, "{body:?}");
        assert!(body.0["error"]
            .as_str()
            .is_some_and(|error| error.contains("intent journal is unreadable")));
    }

    #[tokio::test]
    async fn legacy_import_pending_intent_conflicts_on_args_and_reauthorizes_writer() {
        let (state, _dir) = encrypted_store_test_state().await;
        let group_id = "95".repeat(16);
        seed_public_migration_group(&state, &group_id).await;
        let (source_id, _source_handle) = seed_legacy_page_source(&state, &group_id, "wiki").await;
        let (code, opened) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(group_id.clone()),
            Extension(owner_actor()),
            Json(CreateGroupStoreRequest {
                name: "wiki".to_string(),
            }),
        )
        .await;
        assert!(
            matches!(code, StatusCode::OK | StatusCode::CREATED),
            "{opened:?}"
        );
        let (_, listing) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        let digest = listing.0["candidates"][0]["source_digest"]
            .as_str()
            .expect("source digest")
            .to_string();

        crate::server::legacy_store_migration::fail_next_append_for_test("intent-gate");
        let request = || ImportLegacyStoreRequest {
            source_digest: digest.clone(),
            idempotency_key: "intent-gate".to_string(),
        };
        let (code, _) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(crate::server::legacy_store_migration::read_intent(
            &state.kv_store_state_dir,
            "intent-gate"
        )
        .await
        .expect("pending intent")
        .is_some());

        // Same key, different arguments: conflict, nothing recovered.
        let (code, _) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(ImportLegacyStoreRequest {
                source_digest: "different".to_string(),
                idempotency_key: "intent-gate".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::CONFLICT);

        // Current writer revoked mid-flight: the retry reauthorizes and
        // refuses without consuming the durable intent.
        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_id).expect("group");
            info.policy.write_access = crate::groups::GroupWriteAccess::AdminOnly;
            info.members_v2
                .get_mut(&hex::encode(state.agent.agent_id().as_bytes()))
                .expect("local member")
                .role = crate::groups::GroupRole::Member;
        }
        let (_, revoked_listing) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        let pending = revoked_listing.0["candidates"]
            .as_array()
            .expect("revoked candidate array")
            .iter()
            .find(|candidate| candidate["import_pending"] == true)
            .expect("pending candidate remains discoverable");
        assert_eq!(pending["can_import"], false);
        assert!(pending["import_refusal_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("cannot endorse")));
        let (code, _) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(
            code,
            StatusCode::FORBIDDEN,
            "pending-intent retry must reauthorize the current writer"
        );
        let receipt_path =
            crate::server::legacy_store_migration::journal_path(&state.kv_store_state_dir);
        assert!(
            crate::server::legacy_store_migration::read_receipts(&receipt_path)
                .await
                .expect("receipts after refusal")
                .is_empty()
        );
        assert!(
            crate::server::legacy_store_migration::read_intent(
                &state.kv_store_state_dir,
                "intent-gate"
            )
            .await
            .expect("intent after refusal")
            .is_some(),
            "refused retry leaves the durable intent intact"
        );

        // Writer restored: the same original key still finishes.
        {
            let mut groups = state.named_groups.write().await;
            groups
                .get_mut(&group_id)
                .expect("group")
                .members_v2
                .get_mut(&hex::encode(state.agent.agent_id().as_bytes()))
                .expect("local member")
                .role = crate::groups::GroupRole::Admin;
        }
        let (code, done) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id, "wiki".to_string(), source_id)),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{done:?}");
        assert_eq!(done.0["publish_accepted"], true);
        assert_eq!(
            crate::server::legacy_store_migration::read_receipts(&receipt_path)
                .await
                .expect("receipts after completion")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn legacy_import_intent_without_merge_is_not_imported_and_finishes_on_retry() {
        let (state, _dir) = encrypted_store_test_state().await;
        let group_id = "96".repeat(16);
        seed_public_migration_group(&state, &group_id).await;
        let (source_id, _source_handle) = seed_legacy_page_source(&state, &group_id, "wiki").await;
        let source_path = state.kv_store_state_dir.join(format!("{source_id}.bin"));
        let source_bytes = tokio::fs::read(&source_path).await.expect("source bytes");
        let (code, opened) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(group_id.clone()),
            Extension(owner_actor()),
            Json(CreateGroupStoreRequest {
                name: "wiki".to_string(),
            }),
        )
        .await;
        assert!(
            matches!(code, StatusCode::OK | StatusCode::CREATED),
            "{opened:?}"
        );
        let topic = opened.0["topic"].as_str().expect("topic").to_string();
        let handle = state
            .kv_stores
            .read()
            .await
            .get(&topic)
            .cloned()
            .expect("destination handle");
        let (_, listing) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        let digest = listing.0["candidates"][0]["source_digest"]
            .as_str()
            .expect("source digest")
            .to_string();

        // Emulate a crash after the durable intent write but before the
        // merge: the durable state is exactly an intent file and nothing
        // else. Write it through the production journal API.
        let authority_binding = {
            let groups = state.named_groups.read().await;
            migration_authority_binding(groups.get(&group_id).expect("group"))
        };
        crate::server::legacy_store_migration::write_intent(
            &state.kv_store_state_dir,
            crate::server::legacy_store_migration::LegacyImportIntentInput {
                idempotency_key: "crash-before-merge".to_string(),
                group_id: group_id.clone(),
                app: "wiki".to_string(),
                source_store_id: source_id.clone(),
                source_digest: digest.clone(),
                endorser: hex::encode(state.agent.agent_id().as_bytes()),
                authority_binding,
                source_snapshot: source_bytes,
            },
        )
        .await
        .expect("durable pre-merge intent");

        let (_, crashed_listing) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        assert_eq!(
            crashed_listing.0["candidates"][0]["imported"], false,
            "an intent without a merge is not falsely imported"
        );
        assert!(
            handle
                .get("legacy-only")
                .await
                .expect("read destination")
                .is_none(),
            "crash-before-merge never touched the canonical destination"
        );
        let receipt_path =
            crate::server::legacy_store_migration::journal_path(&state.kv_store_state_dir);
        assert!(
            crate::server::legacy_store_migration::read_receipts(&receipt_path)
                .await
                .expect("receipts after crash")
                .is_empty()
        );

        let (code, done) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(ImportLegacyStoreRequest {
                source_digest: digest,
                idempotency_key: "crash-before-merge".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{done:?}");
        assert_eq!(done.0["imported_locally"], true);
        assert_eq!(done.0["publish_accepted"], true);
        assert!(handle
            .get("legacy-only")
            .await
            .expect("read after recovery")
            .is_some());
        assert_eq!(
            crate::server::legacy_store_migration::read_receipts(&receipt_path)
                .await
                .expect("receipts after recovery")
                .len(),
            1
        );
        assert!(crate::server::legacy_store_migration::read_intent(
            &state.kv_store_state_dir,
            "crash-before-merge"
        )
        .await
        .expect("intent after recovery")
        .is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_import_unloaded_preview_ambiguity_and_receipt_retry_preserve_state() {
        let (state, _dir) = encrypted_store_test_state().await;
        let prefix = "ab".repeat(8);
        let group_id = format!("{prefix}{}", "11".repeat(8));
        let colliding_id = format!("{prefix}{}", "22".repeat(8));
        seed_public_migration_group(&state, &group_id).await;
        let (source_id, source_handle) = seed_legacy_page_source(&state, &group_id, "wiki").await;
        let source_path = state.kv_store_state_dir.join(format!("{source_id}.bin"));
        let source_before = tokio::fs::read(&source_path).await.expect("source bytes");

        let (code, opened) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(group_id.clone()),
            Extension(owner_actor()),
            Json(CreateGroupStoreRequest {
                name: "wiki".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{opened:?}");
        let topic = opened.0["topic"].as_str().expect("topic").to_string();
        let destination_snapshot_path = state.kv_store_state_dir.join(format!(
            "{}.bin",
            opened.0["store_id"].as_str().expect("destination store id")
        ));
        let handle = state
            .kv_stores
            .read()
            .await
            .get(&topic)
            .cloned()
            .expect("destination handle");
        handle
            .put(
                "shared".to_string(),
                b"current".to_vec(),
                "text/plain".to_string(),
            )
            .await
            .expect("destination conflict");
        // Drained, not just cancelled (#757): this test replaces the
        // snapshot path with a directory below, so no listener section —
        // e.g. the self-echo of the put above — may still be writing it.
        handle.retire_and_drain().await;
        state.kv_stores.write().await.remove(&topic);

        seed_public_migration_group(&state, &colliding_id).await;
        let (code, listing) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{listing:?}");
        let candidate = &listing.0["candidates"][0];
        assert_eq!(candidate["ambiguous_group_prefix"], true);
        assert_eq!(candidate["conflicts"], serde_json::json!(["shared"]));
        let digest = candidate["source_digest"]
            .as_str()
            .expect("digest")
            .to_string();

        // Restore the already-open handle after exercising the unloaded GET
        // preview, then make only its final snapshot rename fail. The handle
        // remains readable and writable through the merge, so this reaches
        // the post-mutation persist boundary rather than failing during open.
        state
            .kv_stores
            .write()
            .await
            .insert(topic.clone(), handle.clone());
        tokio::fs::remove_file(&destination_snapshot_path)
            .await
            .expect("remove prior destination snapshot");
        tokio::fs::create_dir(&destination_snapshot_path)
            .await
            .expect("block destination snapshot rename");
        let (code, failed) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(ImportLegacyStoreRequest {
                source_digest: digest.clone(),
                idempotency_key: "persist-fault".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "{failed:?}");
        assert!(
            failed.0["error"].as_str().is_some_and(
                |error| error.contains("applied in memory but destination persistence failed")
            ),
            "must reach the post-mutation destination persist boundary: {failed:?}"
        );
        tokio::fs::remove_dir(&destination_snapshot_path)
            .await
            .expect("heal destination persistence");
        let (code, persisted_retry) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(ImportLegacyStoreRequest {
                source_digest: digest.clone(),
                idempotency_key: "persist-fault".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{persisted_retry:?}");
        assert_eq!(
            tokio::fs::read(&source_path)
                .await
                .expect("source after persist retry"),
            source_before,
            "persistence failure and retry never mutate the source"
        );

        source_handle
            .put(
                "receipt-wave".to_string(),
                b"new history".to_vec(),
                "text/plain".to_string(),
            )
            .await
            .expect("new legacy source wave");
        let source_before_receipt = tokio::fs::read(&source_path)
            .await
            .expect("source bytes before receipt-fault import");
        let (_, refreshed) = list_legacy_page_imports(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string())),
            Extension(owner_actor()),
        )
        .await;
        let receipt_digest = refreshed.0["candidates"][0]["source_digest"]
            .as_str()
            .expect("refreshed digest")
            .to_string();

        let receipt_path =
            crate::server::legacy_store_migration::journal_path(&state.kv_store_state_dir);
        crate::server::legacy_store_migration::fail_next_append_for_test(
            "retry-after-receipt-fault",
        );
        let request = || ImportLegacyStoreRequest {
            source_digest: receipt_digest.clone(),
            idempotency_key: "retry-after-receipt-fault".to_string(),
        };
        let (code, failed) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id.clone(), "wiki".to_string(), source_id.clone())),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "{failed:?}");
        assert!(
            failed.0["error"].as_str().is_some_and(
                |error| error.contains("destination persisted but import receipt did not")
            ),
            "must reach the post-persist receipt append boundary: {failed:?}"
        );

        let handle = state
            .kv_stores
            .read()
            .await
            .get(&topic)
            .cloned()
            .expect("restored destination");
        assert!(
            handle
                .get("legacy-only")
                .await
                .expect("read applied content")
                .is_some(),
            "receipt failure occurs after the import was applied"
        );
        assert!(
            handle
                .get("receipt-wave")
                .await
                .expect("read newly applied content")
                .is_some(),
            "new source bytes were applied before receipt append failed"
        );
        let destination_id = x0x::kv::encrypted::group_store_identity(&group_id, "wiki").0;
        let persisted = x0x::kv::sync::load_snapshot(
            &state
                .kv_store_state_dir
                .join(format!("{}.bin", hex::encode(destination_id.as_bytes()))),
        )
        .expect("load persisted destination")
        .expect("persisted destination exists");
        assert!(persisted.get("legacy-only").is_some());
        assert!(persisted.get("receipt-wave").is_some());
        handle
            .put(
                "concurrent".to_string(),
                b"keep".to_vec(),
                "text/plain".to_string(),
            )
            .await
            .expect("concurrent destination write");
        let (code, retried) = import_legacy_page_store(
            State(Arc::clone(&state)),
            Path((group_id, "wiki".to_string(), source_id)),
            Extension(owner_actor()),
            Json(request()),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{retried:?}");
        assert_eq!(
            handle
                .get("concurrent")
                .await
                .expect("read concurrent")
                .expect("concurrent preserved")
                .value,
            b"keep"
        );
        assert_eq!(
            tokio::fs::read(source_path).await.expect("source after"),
            source_before_receipt,
            "legacy source snapshot is never mutated"
        );
        assert_eq!(
            crate::server::legacy_store_migration::read_receipts(&receipt_path)
                .await
                .expect("receipt journal")
                .len(),
            2
        );
    }

    /// Seed an MlsEncrypted/GSS group owned by the DAEMON AGENT (the caller),
    /// unless a foreign creator is requested.
    async fn seed_group(state: &AppState, group_key: &str, creator: x0x::identity::AgentId) {
        let mut info = GroupInfo::new(
            "kv-group".to_string(),
            String::new(),
            creator,
            group_key.to_string(),
        );
        info.migrate_from_v1();
        let _ = info.rotate_shared_secret();
        state
            .named_groups
            .write()
            .await
            .insert(group_key.to_string(), info);
    }

    async fn seed_treekem_group(state: &AppState, group_key: &str) {
        let group_id = hex::decode(group_key).expect("hex group id");
        let creator = state.agent.agent_id();
        let seed = crate::server::routes::named_groups::agent_treekem_seed(
            state.agent.as_ref(),
            &group_id,
        );
        let live =
            x0x::mls::TreeKemMlsGroup::create(group_id, creator, &seed).expect("TreeKEM group");
        let mut info = GroupInfo::new(
            "treekem".to_string(),
            String::new(),
            creator,
            group_key.to_string(),
        );
        info.migrate_from_v1();
        info.secure_plane = SecureGroupPlane::TreeKem;
        info.shared_secret = None;
        info.secret_epoch = live.epoch();
        info.security_binding = Some(format!("treekem:epoch={}", live.epoch()));
        info.recompute_state_hash();
        state
            .named_groups
            .write()
            .await
            .insert(group_key.to_string(), info);
        state.treekem_groups.write().await.insert(
            group_key.to_string(),
            Arc::new(tokio::sync::Mutex::new(live)),
        );
    }

    #[tokio::test]
    async fn treekem_non_owner_endorses_retained_history_and_revocation_fences_merge() {
        use x0x::kv::TreeKemKvProtector;

        let (writer_state, _writer_dir) = encrypted_store_test_state().await;
        let (reader_state, _reader_dir) = encrypted_store_test_state().await;
        let owner = AgentId([77; 32]);
        let writer = writer_state.agent.agent_id();
        let reader = reader_state.agent.agent_id();
        let group_key = "45".repeat(16);
        let group_id = hex::decode(&group_key).expect("group id");
        let writer_seed = crate::server::routes::named_groups::agent_treekem_seed(
            writer_state.agent.as_ref(),
            &group_id,
        );
        let reader_seed = crate::server::routes::named_groups::agent_treekem_seed(
            reader_state.agent.as_ref(),
            &group_id,
        );
        let mut owner_group =
            x0x::mls::TreeKemMlsGroup::create(group_id, owner, &[77; 32]).expect("owner group");
        let writer_prepared =
            x0x::mls::TreeKemMlsGroup::prepare_member(writer, &writer_seed).expect("writer kp");
        let writer_add = owner_group
            .add_member(writer, writer_prepared.key_package_bytes())
            .expect("add writer");
        let mut writer_group =
            x0x::mls::TreeKemMlsGroup::join_from_welcome(writer_prepared, &writer_add.welcome)
                .expect("writer join");
        let reader_prepared =
            x0x::mls::TreeKemMlsGroup::prepare_member(reader, &reader_seed).expect("reader kp");
        let reader_add = owner_group
            .add_member(reader, reader_prepared.key_package_bytes())
            .expect("add reader");
        writer_group
            .process_commit(&reader_add.commit)
            .expect("writer advances for reader");
        let reader_group =
            x0x::mls::TreeKemMlsGroup::join_from_welcome(reader_prepared, &reader_add.welcome)
                .expect("reader join");

        let mut info = GroupInfo::new(
            "private".to_string(),
            String::new(),
            owner,
            group_key.clone(),
        );
        info.migrate_from_v1();
        info.secure_plane = SecureGroupPlane::TreeKem;
        info.shared_secret = None;
        info.policy.write_access = x0x::groups::GroupWriteAccess::AdminOnly;
        info.add_member(
            hex::encode(writer.as_bytes()),
            x0x::groups::GroupRole::Admin,
            Some(hex::encode(owner.as_bytes())),
            None,
        );
        info.add_member(
            hex::encode(reader.as_bytes()),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(owner.as_bytes())),
            None,
        );
        info.secret_epoch = writer_group.epoch();
        info.security_binding = Some(format!("treekem:epoch={}", writer_group.epoch()));
        info.recompute_state_hash();
        writer_state
            .named_groups
            .write()
            .await
            .insert(group_key.clone(), info.clone());
        reader_state
            .named_groups
            .write()
            .await
            .insert(group_key.clone(), info.clone());
        writer_state.treekem_groups.write().await.insert(
            group_key.clone(),
            Arc::new(tokio::sync::Mutex::new(writer_group)),
        );
        reader_state.treekem_groups.write().await.insert(
            group_key.clone(),
            Arc::new(tokio::sync::Mutex::new(reader_group)),
        );
        let writer_binding = {
            let groups = writer_state.named_groups.read().await;
            resolve_treekem_group_store(&groups, &group_key, "Home", &writer)
                .expect("writer binding")
        };
        let reader_binding = {
            let groups = reader_state.named_groups.read().await;
            resolve_treekem_group_store(&groups, &group_key, "Home", &reader)
                .expect("reader binding")
        };
        assert_eq!(writer_binding.store_id, reader_binding.store_id);
        let writer_auth = Arc::new(
            x0x::groups::TreeKemKvAuthorizationContext::from_group(&info).expect("writer auth"),
        );
        let reader_auth = Arc::new(
            x0x::groups::TreeKemKvAuthorizationContext::from_group(&info).expect("reader auth"),
        );
        let writer_protector = TreeKemGroupStoreProtector::new(
            &writer_state,
            &writer_binding,
            Arc::clone(&writer_auth),
        );
        let reader_protector = TreeKemGroupStoreProtector::new(
            &reader_state,
            &reader_binding,
            Arc::clone(&reader_auth),
        );
        assert!(reader_protector.is_authorized_reader(&reader).await);
        assert!(!reader_protector.is_authorized_writer(&reader).await);

        let group_id = group_key.as_bytes().to_vec();
        let mut source = x0x::kv::KvStore::new_treekem_encrypted(
            writer_binding.store_id,
            "Home".to_string(),
            owner,
            group_id.clone(),
            writer_auth,
        )
        .expect("source store");
        source
            .put(
                "removed".to_string(),
                b"old".to_vec(),
                "text/plain".to_string(),
                saorsa_gossip_types::PeerId::new([1; 32]),
            )
            .expect("seed removed key");
        for index in 0..17 {
            source
                .put(
                    format!("large-{index}"),
                    vec![index as u8; x0x::kv::entry::MAX_INLINE_SIZE],
                    "application/octet-stream".to_string(),
                    saorsa_gossip_types::PeerId::new([1; 32]),
                )
                .expect("large retained value");
        }
        let mut target = source.clone();
        target
            .set_secure_context(reader_auth)
            .expect("reader context");
        source.remove("removed").expect("retained tombstone");
        target
            .put(
                "concurrent".to_string(),
                b"local".to_vec(),
                "text/plain".to_string(),
                saorsa_gossip_types::PeerId::new([2; 32]),
            )
            .expect("concurrent reader state");
        let retained = bincode::serialize(&source).expect("retained image");
        assert!(retained.len() > 1024 * 1024, "history requires paging");
        let signing =
            x0x::kv::AuthorSigning::from_keypair(writer_state.agent.identity().agent_keypair())
                .expect("writer signing");
        let record = writer_protector
            .seal_record(
                &signing,
                x0x::kv::KvMutationKind::RetainedState,
                &writer_binding.store_id,
                b"paged-image-complete",
                false,
            )
            .await
            .expect("non-owner writer endorsement");
        let opened = reader_protector
            .open_record(&reader_binding.store_id, &record)
            .await
            .expect("reader opens endorsed history");
        let target = Arc::new(tokio::sync::RwLock::new(target));
        reader_protector
            .merge_main_record(
                opened,
                saorsa_gossip_types::PeerId::new([1; 32]),
                saorsa_gossip_types::PeerId::new([2; 32]),
                &target,
                Some(retained),
            )
            .await
            .expect("current writer retained merge");
        let merged = target.read().await;
        assert!(merged.get("removed").is_none());
        assert_eq!(
            merged.get("concurrent").expect("concurrent").value,
            b"local"
        );
        assert_eq!(merged.last_history_endorser(), Some(&writer));
        drop(merged);

        let stale_record = writer_protector
            .seal_record(
                &signing,
                x0x::kv::KvMutationKind::RetainedState,
                &writer_binding.store_id,
                b"paged-image-complete",
                false,
            )
            .await
            .expect("record before removal");
        let stale_opened = reader_protector
            .open_record(&reader_binding.store_id, &stale_record)
            .await
            .expect("opened before removal");
        {
            let mut groups = reader_state.named_groups.write().await;
            groups
                .get_mut(&group_key)
                .expect("reader group")
                .remove_member(&hex::encode(writer.as_bytes()), None);
        }
        assert!(reader_protector
            .merge_main_record(
                stale_opened,
                saorsa_gossip_types::PeerId::new([1; 32]),
                saorsa_gossip_types::PeerId::new([2; 32]),
                &target,
                Some(bincode::serialize(&source).expect("stale image")),
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn create_group_kv_store_route_creates_encrypted_store() {
        let (state, _dir) = encrypted_store_test_state().await;
        let group_key = "ab".repeat(16);
        seed_group(&state, &group_key, state.agent.agent_id()).await;

        let (code, resp) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(group_key.clone()),
            Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
            Json(CreateGroupStoreRequest {
                name: "workspace".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{resp:?}");
        assert_eq!(resp.0["policy"], "encrypted");
        assert_eq!(resp.0["group_id"], group_key);
        assert!(resp.0["store_id"].as_str().is_some());
        let topic = resp.0["topic"].as_str().expect("topic").to_string();

        // The deterministic identity is what got registered.
        let (store_id, derived_topic) =
            x0x::kv::encrypted::group_store_identity(&group_key, "workspace");
        assert_eq!(topic, derived_topic);
        assert!(state.kv_stores.read().await.contains_key(&topic));
        let handle = state.kv_stores.read().await.get(&topic).cloned().unwrap();
        assert!(
            handle.is_encrypted().await,
            "registered handle is encrypted"
        );

        // A member write goes through the sealed publish path and reads back.
        handle
            .put_with_delta(
                "royalty-split".to_string(),
                b"hush".to_vec(),
                "text/plain".to_string(),
            )
            .await
            .expect("member put on encrypted store");
        let entry = handle
            .get("royalty-split")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(entry.value, b"hush".to_vec());

        // Idempotent re-open returns 200 with the same store id.
        let (code2, resp2) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(group_key),
            Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
            Json(CreateGroupStoreRequest {
                name: "workspace".to_string(),
            }),
        )
        .await;
        assert_eq!(code2, StatusCode::OK, "{resp2:?}");
        assert_eq!(resp2.0["store_id"], resp.0["store_id"]);
        let _ = store_id;
    }

    /// WHY (PR #508 review P1): the leave/removal path deletes the group
    /// from `named_groups`. The refresh hook must treat a MISSING group as
    /// lifecycle: invalidate the context AND retire the live handle, so the
    /// departed member cannot keep reading, writing, or publishing
    /// old-epoch records on a stale secret/roster snapshot.
    #[tokio::test]
    async fn leave_invalidates_and_retires_group_encrypted_store() {
        let (state, _dir) = encrypted_store_test_state().await;
        let group_key = "ab".repeat(16);
        seed_group(&state, &group_key, state.agent.agent_id()).await;
        let (code, resp) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(group_key.clone()),
            Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
            Json(CreateGroupStoreRequest {
                name: "ws".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{resp:?}");
        let topic = resp.0["topic"].as_str().expect("topic").to_string();
        let handle = state.kv_stores.read().await.get(&topic).cloned().unwrap();

        // The member LEAVES: the group entry disappears from the map.
        state.named_groups.write().await.remove(&group_key);

        // Next sync activity runs the refresh hook -> lifecycle branch. The
        // hook is rebuilt exactly as create wired it, bound to the context
        // snapshot the live sync captured BEFORE the leave.
        let pre_leave_info = crate::groups::GroupInfo::new(
            group_key.clone(),
            String::new(),
            state.agent.agent_id(),
            group_key.clone(),
        );
        let ctx =
            Arc::new(x0x::groups::GssKvSecureContext::from_group(&pre_leave_info).expect("ctx"));
        assert!(ctx.is_active_member(&state.agent.agent_id()));
        let hook = gss_kv_refresh(
            &state,
            ctx,
            group_key.clone(),
            topic.clone(),
            state.agent.agent_id(),
        );
        hook().await;

        // The handle is retired out of the registry...
        assert!(
            !state.kv_stores.read().await.contains_key(&topic),
            "retired handle must leave the registry"
        );
        // ...and a STALE clone (held elsewhere) fails closed on writes.
        let err = handle
            .put_with_delta("k".to_string(), b"v".to_vec(), "text/plain".to_string())
            .await
            .expect_err("post-leave write must be refused");
        assert!(
            matches!(err, x0x::error::IdentityError::Unauthorized(_)),
            "got {err:?}"
        );
    }

    /// WHY (PR #508 review P1): a WITHDRAWN group is equally terminal — the
    /// tombstone keeps the roster entry but the store must not operate.
    #[tokio::test]
    async fn withdrawn_group_invalidates_encrypted_store() {
        let (state, _dir) = encrypted_store_test_state().await;
        let group_key = "cd".repeat(16);
        seed_group(&state, &group_key, state.agent.agent_id()).await;
        let (code, resp) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(group_key.clone()),
            Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
            Json(CreateGroupStoreRequest {
                name: "ws".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{resp:?}");
        let topic = resp.0["topic"].as_str().expect("topic").to_string();
        let handle = state.kv_stores.read().await.get(&topic).cloned().unwrap();

        // The group is WITHDRAWN (tombstone retained, roster intact).
        state
            .named_groups
            .write()
            .await
            .get_mut(&group_key)
            .expect("group")
            .withdrawn = true;

        // Directly retire the way the withdraw lifecycle path does.
        retire_group_kv_stores(&state, &group_key).await;
        assert!(
            !state.kv_stores.read().await.contains_key(&topic),
            "withdrawal must retire the handle"
        );
        // A stale clone fails closed on writes even though the roster entry
        // would still say "active member".
        let err = handle
            .put_with_delta("k".to_string(), b"v".to_vec(), "text/plain".to_string())
            .await
            .expect_err("post-withdrawal write must be refused");
        assert!(matches!(err, x0x::error::IdentityError::Unauthorized(_)));

        // And the refresh hook independently invalidates on withdrawn state
        // (second layer, for handles the lifecycle paths miss).
        let ctx = Arc::new(
            x0x::groups::GssKvSecureContext::from_group(
                state
                    .named_groups
                    .read()
                    .await
                    .get(&group_key)
                    .expect("group"),
            )
            .expect("ctx"),
        );
        assert!(ctx.is_active_member(&state.agent.agent_id()));
        let hook = gss_kv_refresh(
            &state,
            Arc::clone(&ctx),
            group_key.clone(),
            topic,
            state.agent.agent_id(),
        );
        hook().await;
        assert!(
            !ctx.is_active_member(&state.agent.agent_id()),
            "withdrawn group must invalidate the context"
        );
    }

    #[tokio::test]
    async fn create_group_kv_store_route_guards() {
        let (state, _dir) = encrypted_store_test_state().await;
        let owner_actor = crate::server::rider_auth::ActorContext::Owner { durable: true };

        // Unknown group -> 404.
        let (code, resp) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path("missing".to_string()),
            Extension(owner_actor.clone()),
            Json(CreateGroupStoreRequest {
                name: "n".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::NOT_FOUND, "{resp:?}");

        // Non-member: the group exists but the daemon agent is not in it.
        let outsider = x0x::identity::AgentId([9; 32]);
        seed_group(&state, &"cd".repeat(16), outsider).await;
        let (code, resp) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path("cd".repeat(16)),
            Extension(owner_actor.clone()),
            Json(CreateGroupStoreRequest {
                name: "n".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN, "{resp:?}");

        // SignedPublic group -> creator-anchored group-signed store.
        let signed_key = "ef".repeat(16);
        {
            let mut info = GroupInfo::new(
                "public".to_string(),
                String::new(),
                state.agent.agent_id(),
                signed_key.clone(),
            );
            info.migrate_from_v1();
            info.policy.confidentiality = GroupConfidentiality::SignedPublic;
            state
                .named_groups
                .write()
                .await
                .insert(signed_key.clone(), info);
        }
        let (code, resp) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(signed_key),
            Extension(owner_actor.clone()),
            Json(CreateGroupStoreRequest {
                name: "n".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{resp:?}");
        assert_eq!(resp.0["policy"], "group_signed");

        // TreeKEM-plane group uses the distinct mutable-ratchet backend.
        let treekem_key = "12".repeat(16);
        seed_treekem_group(&state, &treekem_key).await;
        let (code, resp) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(treekem_key.clone()),
            Extension(owner_actor.clone()),
            Json(CreateGroupStoreRequest {
                name: "n".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{resp:?}");
        assert_eq!(resp.0["policy"], "encrypted");
        let topic = resp.0["topic"].as_str().expect("topic").to_string();
        let handle = state
            .kv_stores
            .read()
            .await
            .get(&topic)
            .cloned()
            .expect("TreeKEM handle");
        handle
            .validate_group_binding(
                "n",
                &treekem_key,
                state.agent.agent_id(),
                x0x::GroupStoreProtection::TreeKemEncrypted,
            )
            .await
            .expect("distinct TreeKEM binding");
        handle
            .put_with_delta("k".into(), b"v".to_vec(), "text/plain".into())
            .await
            .expect("TreeKEM store write");
        assert_eq!(
            handle.get("k").await.expect("read").expect("stored").value,
            b"v"
        );
        handle.retire();
        state.kv_stores.write().await.remove(&topic);
        let binding = {
            let groups = state.named_groups.read().await;
            resolve_treekem_group_store(&groups, &treekem_key, "n", &state.agent.agent_id())
                .expect("restart binding")
        };
        let (restored, _, _) = open_bound_treekem_store(&state, &binding)
            .await
            .expect("restore TreeKEM store snapshot");
        assert_eq!(
            restored
                .get("k")
                .await
                .expect("restored read")
                .expect("restored value")
                .value,
            b"v",
            "restart must retain the durable store image"
        );
        let _ = GssKvSecureContext::from_group; // keep backend import referenced
        let _ = GroupPolicy::default();
    }

    #[tokio::test]
    async fn public_store_cached_binding_mismatch_returns_without_deadlock() {
        let (state, _dir) = encrypted_store_test_state().await;
        let group_key = "34".repeat(16);
        let mut info = GroupInfo::new(
            "public".to_string(),
            String::new(),
            state.agent.agent_id(),
            group_key.clone(),
        );
        info.migrate_from_v1();
        info.policy.confidentiality = GroupConfidentiality::SignedPublic;
        info.policy.read_access = crate::groups::GroupReadAccess::Public;
        state
            .named_groups
            .write()
            .await
            .insert(group_key.clone(), info);
        let binding = {
            let groups = state.named_groups.read().await;
            resolve_public_group_store(&groups, &group_key, "Wiki", &state.agent.agent_id())
                .expect("binding")
        };
        let wrong = state
            .agent
            .create_kv_store("wrong", "wrong/topic")
            .await
            .expect("wrong cached handle");
        state
            .kv_stores
            .write()
            .await
            .insert(binding.topic.clone(), wrong);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            open_bound_public_store(&state, &binding),
        )
        .await
        .expect("mismatch cleanup must not deadlock");
        assert!(result.is_err(), "mismatched cached handle must fail closed");
        assert!(!state.kv_stores.read().await.contains_key(&binding.topic));
    }

    #[tokio::test]
    async fn cached_binding_mismatch_drains_in_flight_persist_before_unregistering() {
        // WHY (#757): the mismatch path unregisters the cached handle, after
        // which a later open may start a NEW sync over the same snapshot
        // path. A receive section the old sync already admitted still owes
        // its snapshot write, so the handle must not be unregistered — and
        // this call must not return — until that write has landed.
        let (state, _dir) = encrypted_store_test_state().await;
        let group_key = "35".repeat(16);
        let mut info = GroupInfo::new(
            "public".to_string(),
            String::new(),
            state.agent.agent_id(),
            group_key.clone(),
        );
        info.migrate_from_v1();
        info.policy.confidentiality = GroupConfidentiality::SignedPublic;
        info.policy.read_access = crate::groups::GroupReadAccess::Public;
        state
            .named_groups
            .write()
            .await
            .insert(group_key.clone(), info);
        let binding = {
            let groups = state.named_groups.read().await;
            resolve_public_group_store(&groups, &group_key, "Wiki", &state.agent.agent_id())
                .expect("binding")
        };
        let snapshots = tempfile::tempdir().expect("snapshot dir");
        let wrong = state
            .agent
            .create_kv_store_persistent(
                "wrong",
                "wrong/topic-757",
                x0x::kv::AccessPolicy::Signed,
                snapshots.path(),
            )
            .await
            .expect("wrong cached handle");
        let snapshot_bytes = || {
            std::fs::read_dir(snapshots.path())
                .expect("snapshot dir")
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "bin"))
                .map(|entry| std::fs::read(entry.path()).expect("snapshot bytes"))
                .collect::<Vec<_>>()
        };
        let before = snapshot_bytes();
        state
            .kv_stores
            .write()
            .await
            .insert(binding.topic.clone(), wrong.clone());

        let bound = std::time::Duration::from_secs(10);
        let mut delta = x0x::kv::KvStoreDelta::new(1);
        let entry = x0x::kv::KvEntry::new(
            "late-key".to_string(),
            b"late".to_vec(),
            "text/plain".to_string(),
        );
        delta.added.insert(
            "late-key".to_string(),
            (entry, (saorsa_gossip_types::PeerId::new([7; 32]), 1)),
        );
        let (open,) = wrong
            .with_persist_gate_held_for_test(async {
                wrong.publish_delta_for_test(delta).await;
                // Barrier: merged in memory, so its snapshot write is now
                // parked on the gate — a receive section in flight.
                tokio::time::timeout(bound, async {
                    while !matches!(wrong.get("late-key").await, Ok(Some(_))) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("listener must merge the delta");
                let mut open = Box::pin(open_bound_public_store(&state, &binding));
                for _ in 0..64 {
                    assert!(
                        futures::poll!(open.as_mut()).is_pending(),
                        "mismatch cleanup returned with a snapshot write still in flight"
                    );
                    assert!(
                        state.kv_stores.read().await.contains_key(&binding.topic),
                        "handle unregistered before its in-flight write drained"
                    );
                    tokio::task::yield_now().await;
                }
                assert_eq!(snapshot_bytes(), before);
                // Tuple: hand the still-pending future back un-awaited.
                (open,)
            })
            .await;
        let result = tokio::time::timeout(bound, open)
            .await
            .expect("mismatch cleanup must finish once the write lands");
        assert!(result.is_err(), "mismatched cached handle must fail closed");
        assert_ne!(
            snapshot_bytes(),
            before,
            "cleanup returned before the admitted snapshot write landed"
        );
        assert!(!state.kv_stores.read().await.contains_key(&binding.topic));
    }

    #[tokio::test]
    async fn public_mismatch_cleanup_never_drains_a_cached_treekem_sync() {
        // WHY (#757 r3, Codex P1): `update_group_policy` lets a group go
        // TreeKEM -> SignedPublic without retiring cached stores, and the
        // topic does not change, so the PUBLIC mismatch arm can find a
        // TreeKEM sync. Its receive section waits on the group membership
        // guard (protector `open_record`) while holding the lifecycle lock —
        // and every caller of `open_bound_public_store` holds that guard.
        // Draining there deadlocks the request forever; the cleanup must
        // pick plain `retire` from the cached sync, not the requested plane.
        let (state, _dir) = encrypted_store_test_state().await;
        let group_key = "13".repeat(16);
        seed_treekem_group(&state, &group_key).await;
        let (code, resp) = create_group_kv_store(
            State(Arc::clone(&state)),
            Path(group_key.clone()),
            Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
            Json(CreateGroupStoreRequest {
                name: "n".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{resp:?}");
        let topic = resp.0["topic"].as_str().expect("topic").to_string();
        let handle = state
            .kv_stores
            .read()
            .await
            .get(&topic)
            .cloned()
            .expect("TreeKEM handle");
        assert!(handle.is_treekem_protected());

        // Park the TreeKEM listener inside a receive section: each write's
        // self-echo makes it take the lifecycle lock and then wait on the
        // membership guard we grab right after the write returns. Retry
        // until that ordering is observed (an echo handled before we hold
        // the guard parks nothing).
        let membership =
            crate::server::routes::named_groups::group_membership_lock(&state, &group_key).await;
        let mut held = None;
        for round in 0..64 {
            handle
                .put_with_delta(format!("k{round}"), b"v".to_vec(), "text/plain".into())
                .await
                .expect("TreeKEM store write");
            let guard = Arc::clone(&membership).lock_owned().await;
            for _ in 0..64 {
                if handle.receive_section_active_for_test() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            if handle.receive_section_active_for_test() {
                held = Some(guard);
                break;
            }
        }
        let _membership_guard =
            held.expect("TreeKEM listener must park on the membership guard in a section");

        // The policy transition: same group, same topic, now SignedPublic.
        let binding = {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_key).expect("group");
            info.policy.confidentiality = GroupConfidentiality::SignedPublic;
            info.policy.read_access = crate::groups::GroupReadAccess::Public;
            resolve_public_group_store(&groups, &group_key, "n", &state.agent.agent_id())
                .expect("public binding after the policy change")
        };
        assert_eq!(binding.topic, topic, "policy change must keep the topic");

        // Safety net, not an oracle: it only turns the deadlock into a FAIL.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            open_bound_public_store(&state, &binding),
        )
        .await
        .expect("mismatch cleanup deadlocked against the parked TreeKEM section");
        assert!(result.is_err(), "mismatched cached handle must fail closed");
        assert!(!state.kv_stores.read().await.contains_key(&topic));
    }

    #[tokio::test]
    async fn cached_public_store_read_refresh_rejects_removed_member() {
        let (state, _dir) = encrypted_store_test_state().await;
        let group_key = "56".repeat(16);
        let local = state.agent.agent_id();
        let creator = AgentId([8; 32]);
        let mut info = GroupInfo::new(
            "public".to_string(),
            String::new(),
            creator,
            group_key.clone(),
        );
        info.migrate_from_v1();
        info.policy.confidentiality = GroupConfidentiality::SignedPublic;
        info.policy.read_access = crate::groups::GroupReadAccess::MembersOnly;
        info.add_member(
            hex::encode(local.as_bytes()),
            crate::groups::GroupRole::Member,
            Some(hex::encode(creator.as_bytes())),
            None,
        );
        state
            .named_groups
            .write()
            .await
            .insert(group_key.clone(), info);
        let binding = {
            let groups = state.named_groups.read().await;
            resolve_public_group_store(&groups, &group_key, "Wiki", &local).expect("binding")
        };
        let (handle, _, _) = open_bound_public_store(&state, &binding)
            .await
            .expect("open member store");
        state
            .kv_stores
            .write()
            .await
            .insert(binding.topic.clone(), handle.clone());
        handle
            .put(
                "visible".to_string(),
                b"value".to_vec(),
                "text/plain".to_string(),
            )
            .await
            .expect("member write");
        assert!(handle.get("visible").await.expect("member read").is_some());
        let version_before = handle.ownership_info().await.version;

        state
            .named_groups
            .write()
            .await
            .get_mut(&group_key)
            .expect("group")
            .remove_member(&hex::encode(local.as_bytes()), None);
        assert!(handle
            .put(
                "late".to_string(),
                b"denied".to_vec(),
                "text/plain".to_string()
            )
            .await
            .is_err());
        assert_eq!(handle.ownership_info().await.version, version_before);
        let mut direct = x0x::kv::KvStoreDelta::new(version_before + 1);
        direct.added.insert(
            "direct".to_string(),
            (
                x0x::kv::KvEntry::new(
                    "direct".to_string(),
                    b"denied".to_vec(),
                    "text/plain".to_string(),
                ),
                (saorsa_gossip_types::PeerId::new([9; 32]), 1),
            ),
        );
        assert!(handle
            .apply_remote_delta(
                saorsa_gossip_types::PeerId::new([9; 32]),
                &direct,
                Some(local)
            )
            .await
            .is_err());
        assert_eq!(handle.ownership_info().await.version, version_before);

        state
            .kv_stores
            .write()
            .await
            .insert(binding.topic.clone(), handle.clone());
        let get_response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            get_kv_value(
                State(Arc::clone(&state)),
                Path((binding.topic.clone(), "visible".to_string())),
            ),
        )
        .await
        .expect("GET must not deadlock")
        .into_response();
        assert_eq!(get_response.status(), StatusCode::FORBIDDEN);

        state
            .kv_stores
            .write()
            .await
            .insert(binding.topic.clone(), handle);
        let keys_response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            list_kv_keys(State(Arc::clone(&state)), Path(binding.topic.clone())),
        )
        .await
        .expect("keys listing must not deadlock")
        .into_response();
        assert_eq!(keys_response.status(), StatusCode::FORBIDDEN);
        assert!(!state.kv_stores.read().await.contains_key(&binding.topic));
    }
}
