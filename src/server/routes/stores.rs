//! Route handlers (`category: "stores"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use super::super::crdt_subscriptions;
use super::super::state::AppState;
use super::super::{
    api_error, bad_request, direct_message_send_config, forbidden, not_found, parse_agent_id_hex,
};
use super::named_groups::GROUP_BACKGROUND_PUBLISH_DELAY;
use crate as x0x;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use x0x::contacts::TrustLevel;
use x0x::identity::AgentId;
use x0x::kv::encrypted::KvSecureContext;
use x0x::logging::LogHexId;

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
    let stores = state.kv_stores.read().await;
    let Some(handle) = stores.get(&id) else {
        return not_found("store not found");
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
            if !handle.is_encrypted().await {
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
    let stores = state.kv_stores.read().await;
    let Some(handle) = stores.get(&id) else {
        return not_found("store not found");
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
            if !handle.is_encrypted().await {
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

/// Deterministic refresh hook for a GSS encrypted-store context: re-reads
/// the authoritative group from the daemon's named-groups map (under the
/// read guard — no `GroupInfo` clone) and refreshes the context snapshot.
/// The sync loops call this before every seal/open, so a rekey or roster
/// change takes effect on the very next record.
pub(in crate::server) fn gss_kv_refresh(
    state: &Arc<AppState>,
    ctx: Arc<x0x::groups::GssKvSecureContext>,
    group_key: String,
) -> x0x::kv::sync::SecureRefreshFn {
    let state = Arc::clone(state);
    Arc::new(move || {
        let ctx = Arc::clone(&ctx);
        let state = Arc::clone(&state);
        let group_key = group_key.clone();
        Box::pin(async move {
            if let Some(info) = state.named_groups.read().await.get(&group_key) {
                ctx.update_from_group(info);
            }
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
    })
}

/// Resolve the GSS secure context for a group store, re-reading the group
/// under the named-groups read lock. Fails when the group is gone or the
/// daemon holds no shared secret for it yet.
async fn gss_context_for_group(
    state: &Arc<AppState>,
    group_key: &str,
) -> Result<Arc<x0x::groups::GssKvSecureContext>, (StatusCode, Json<serde_json::Value>)> {
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(group_key) else {
        return Err(not_found("group not found"));
    };
    match x0x::groups::GssKvSecureContext::from_group(info) {
        Some(ctx) => Ok(Arc::new(ctx)),
        None => Err(api_error(
            StatusCode::CONFLICT,
            "local daemon holds no shared secret for this group yet — join or refresh group state first",
        )),
    }
}

/// Shared metadata payload for create / idempotent re-open responses.
async fn group_store_json(
    handle: &x0x::KvStoreHandle,
    topic: &str,
    store_id: &x0x::kv::KvStoreId,
    stable_group_id: &str,
    epoch: u64,
) -> serde_json::Value {
    let ownership = handle.ownership_info().await;
    serde_json::json!({
        "ok": true,
        "id": topic,
        "store_id": hex::encode(store_id.as_bytes()),
        "group_id": stable_group_id,
        "topic": topic,
        "policy": "encrypted",
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
    let caller_hex = hex::encode(state.agent.agent_id().as_bytes());
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return bad_request("store name must not be empty");
    }
    // Group authorization + v1-backend gates (single read pass).
    let creator = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return not_found("group not found");
        };
        if info.withdrawn {
            return api_error(StatusCode::CONFLICT, "group is withdrawn");
        }
        if !info.has_active_member(&caller_hex) {
            return forbidden("not a member");
        }
        if !actor.rider_allows_group(info.stable_group_id()) {
            return forbidden("rider token is not granted this group");
        }
        if info.policy.confidentiality != x0x::groups::GroupConfidentiality::MlsEncrypted {
            return bad_request(
                "group is not MlsEncrypted — encrypted stores require a confidential group",
            );
        }
        if info.secure_plane != x0x::mls::SecureGroupPlane::Gss {
            return bad_request(
                "encrypted stores v1 are GSS-backed (ADR-0010); TreeKEM-plane groups are not supported yet",
            );
        }
        info.creator
    };
    let stable_group_id = {
        // The stable group id is creation-fixed; re-read to avoid holding
        // the lock across the derive.
        let groups = state.named_groups.read().await;
        match groups.get(&id) {
            Some(info) => info.stable_group_id().to_string(),
            None => return not_found("group not found"),
        }
    };

    let (store_id, topic) = x0x::kv::encrypted::group_store_identity(&stable_group_id, &name);
    // Idempotent re-open: an already-open store returns its metadata.
    if let Some(handle) = state.kv_stores.read().await.get(&topic) {
        let secure = gss_context_for_group(&state, &id).await;
        let epoch = secure.as_ref().map(|c| c.current_epoch()).unwrap_or(0);
        return (
            StatusCode::OK,
            Json(group_store_json(handle, &topic, &store_id, &stable_group_id, epoch).await),
        );
    }

    // Serialize concurrent create/rehydrate for this store.
    let reservation =
        crdt_subscriptions::handle_reservation(&state, crdt_subscriptions::KIND_KV_STORE, &topic)
            .await;
    let _guard = reservation.lock().await;
    if let Some(handle) = state.kv_stores.read().await.get(&topic) {
        let secure = gss_context_for_group(&state, &id).await;
        let epoch = secure.as_ref().map(|c| c.current_epoch()).unwrap_or(0);
        return (
            StatusCode::OK,
            Json(group_store_json(handle, &topic, &store_id, &stable_group_id, epoch).await),
        );
    }

    let secure = match gss_context_for_group(&state, &id).await {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };
    let refresh = gss_kv_refresh(&state, Arc::clone(&secure), id.clone());

    match state
        .agent
        .open_group_kv_store_persistent(
            &name,
            &stable_group_id,
            creator,
            Arc::clone(&secure) as Arc<dyn KvSecureContext>,
            refresh,
            &state.kv_store_state_dir,
        )
        .await
    {
        Ok(handle) => {
            state
                .kv_stores
                .write()
                .await
                .insert(topic.clone(), handle.clone());
            // Persist the registration so a restart re-opens the store with
            // the group binding (creator + stable group id) instead of
            // skipping it (manifest_policy fail-closes unknown policies).
            let mut extra = serde_json::Map::new();
            extra.insert(
                "policy".to_string(),
                serde_json::Value::String("encrypted".to_string()),
            );
            extra.insert(
                "expected_owner".to_string(),
                serde_json::Value::String(hex::encode(creator.as_bytes())),
            );
            extra.insert(
                "stable_group_id".to_string(),
                serde_json::Value::String(stable_group_id.clone()),
            );
            if let Err(e) = crdt_subscriptions::record(
                &state,
                crdt_subscriptions::CrdtSubscriptionEntry {
                    kind: crdt_subscriptions::KIND_KV_STORE.to_string(),
                    id: topic.clone(),
                    name: name.clone(),
                    topic: topic.clone(),
                    role: crdt_subscriptions::ROLE_CREATED.to_string(),
                    extra,
                },
            )
            .await
            {
                tracing::error!("failed to persist group kv store registration {topic}: {e}");
                if let Some(h) = state.kv_stores.write().await.remove(&topic) {
                    h.cancel_sync();
                }
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to persist subscription registration: {e}"),
                );
            }
            let epoch = secure.current_epoch();
            (
                StatusCode::CREATED,
                Json(group_store_json(&handle, &topic, &store_id, &stable_group_id, epoch).await),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
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

    /// Agent + AppState over a temp dir, WITH an in-process gossip runtime
    /// (the encrypted-store happy path spawns real sync loops).
    async fn encrypted_store_test_state() -> (Arc<AppState>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let agent = Arc::new(
            x0x::Agent::builder()
                .with_machine_key(data_dir.join("machine.key"))
                .with_agent_key(x0x::identity::AgentKeypair::generate().unwrap())
                .with_contact_store_path(data_dir.join("contacts.json"))
                .with_network_config(x0x::network::NetworkConfig::default())
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

        // SignedPublic group -> 400 (encrypted stores need a confidential group).
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
        assert_eq!(code, StatusCode::BAD_REQUEST, "{resp:?}");

        // TreeKEM-plane group -> 400 (v1 encrypted stores are GSS-backed).
        let treekem_key = "12".repeat(16);
        {
            let mut info = GroupInfo::new(
                "treekem".to_string(),
                String::new(),
                state.agent.agent_id(),
                treekem_key.clone(),
            );
            info.migrate_from_v1();
            info.secure_plane = SecureGroupPlane::TreeKem;
            state
                .named_groups
                .write()
                .await
                .insert(treekem_key.clone(), info);
        }
        let (code, resp) = create_group_kv_store(
            State(state),
            Path(treekem_key),
            Extension(owner_actor.clone()),
            Json(CreateGroupStoreRequest {
                name: "n".to_string(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{resp:?}");
        let _ = GssKvSecureContext::from_group; // keep backend import referenced
        let _ = GroupPolicy::default();
    }
}
