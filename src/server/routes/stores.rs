//! Route handlers (`category: "stores"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use crate as x0x;
use super::super::{api_error, bad_request, not_found, parse_agent_id_hex, direct_message_send_config};
use super::named_groups::GROUP_BACKGROUND_PUBLISH_DELAY;
use super::super::state::AppState;
use super::super::crdt_subscriptions;
use std::sync::Arc;
use std::time::Duration;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use x0x::contacts::TrustLevel;
use x0x::identity::AgentId;
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
/// writes) or `"append_only"` (owner-only writes AND existing keys are
/// immutable, even to the owner).
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
/// Omitting it yields a permanently read-only replica (no permissive fallback).
#[derive(Debug, Default, Deserialize)]
pub(in crate::server) struct JoinStoreRequest {
    expected_owner: Option<String>,
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
pub(in crate::server) async fn list_kv_stores(State(state): State<Arc<AppState>>) -> impl IntoResponse {
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
        Some(other) => {
            return bad_request(format!(
                "unsupported policy {other:?}: expected \"signed\" or \"append_only\""
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
            let owner_hex = hex::encode(state.agent.agent_id().as_bytes());
            let mut extra = serde_json::Map::new();
            extra.insert(
                "expected_owner".to_string(),
                serde_json::Value::String(owner_hex),
            );
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
    // The out-of-band owner anchor is REQUIRED: a replica with no anchor can
    // never accept policy-restricted data, so an unanchored join is a dead
    // replica, not a successful join. The local user/operator is the trust
    // root for this param.
    let owner: AgentId = match body.and_then(|Json(r)| r.expected_owner) {
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
            let recipients = kv_store_delta_direct_recipients(&state).await;
            spawn_kv_store_delta_delivery(&state, recipients, &id, handle.peer_id(), &delta);
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
            let recipients = kv_store_delta_direct_recipients(&state).await;
            spawn_kv_store_delta_delivery(&state, recipients, &id, handle.peer_id(), &delta);
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
}
