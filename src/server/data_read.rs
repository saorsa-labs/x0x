//! Issue #1094 slice D1 (A03 amendment of 15 Nov 2026): a grantee reads a
//! store it holds a `ShareCap::Data` grant for.
//!
//! - Granted-agent side ([`serve_data_read`]): checks the sender's grants
//!   with `Agent::share_grant_access` (the transport-authenticated machine,
//!   the grantee binding, revocation), then reads this daemon's own copy of
//!   the store and replies once.
//! - Grantee side ([`read_granted_store`], the `GET /grants/data/...`
//!   routes): sends one request and waits for the matching reply from the
//!   agent it was sent to.
//! - Slice D2 (A03 amendment of 16 Nov 2026): an `rw` grantee writes the
//!   store ([`serve_data_write`], the `PUT`/`DELETE /grants/data/...`
//!   routes). The granted agent applies the write through the same code as
//!   its own `PUT`/`DELETE /stores/:id/:key`, so the store's plane, access
//!   policy and the ADR 0110 write refusal apply unchanged.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::dm_inbox::{DmTypedPayload, DmTypedPayloadCompletion};
use crate::groups::eviction::WaitingCause;
use crate::identity::AgentId;
use crate::share_grant::data_read::{
    DataReadEntry, DataReadKey, DataReadOp, DataReadReply, DataReadRequest, DataReadStatus,
    DataWriteOp, DataWriteRefusal, DataWriteRequest, DATA_READ_REPLY_DM_PREFIX,
    DATA_READ_REQUEST_DM_PREFIX, DATA_WRITE_REQUEST_DM_PREFIX, MAX_DATA_READ_CONTENT_TYPE_BYTES,
    MAX_DATA_READ_VALUE_BYTES, MAX_DATA_WRITE_VALUE_BYTES,
};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::Engine as _;
use tokio::sync::oneshot;

use super::state::AppState;
use super::{api_error, parse_agent_id_hex};

/// How long a grantee's HTTP call waits for the reply.
const DATA_READ_REPLY_TIMEOUT: Duration = Duration::from_secs(15);

/// Most reads a grantee may have in flight at once on this daemon.
const DATA_READ_WAITER_CAP: usize = 64;

/// Per-sender serve limit: at most this many requests per window.
const DATA_READ_SERVE_PER_WINDOW: u32 = 30;
const DATA_READ_SERVE_WINDOW_MS: u64 = 10_000;
/// Grantees the serve limiter remembers.
const DATA_READ_SERVE_SENDERS_CAP: usize = 256;
/// Senders with no data grant here share a smaller, separate bucket, so
/// strangers cannot fill the grantees' slots.
const DATA_READ_SERVE_STRANGERS_CAP: usize = 32;

/// Grantee-side waiters, by request id: the agent the request went to, and
/// where its reply goes.
pub(super) type DataReadWaiters = HashMap<String, (AgentId, oneshot::Sender<DataReadReply>)>;

/// Per-sender serve counters: window start (Unix ms) and count.
pub(super) type DataReadServeCounts = HashMap<AgentId, (u64, u32)>;

/// Serve counters: senders that hold a data grant here, and the rest.
#[derive(Debug, Default)]
pub(super) struct DataReadServeLimits {
    grantees: DataReadServeCounts,
    strangers: DataReadServeCounts,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn finish(mut typed: DmTypedPayload) {
    if let Some(tx) = typed.completion.take() {
        let _ = tx.send(Ok(DmTypedPayloadCompletion::Inserted));
    }
}

/// Handle one data-read typed DM (either prefix).
pub(super) async fn handle_data_read_typed(state: &Arc<AppState>, typed: DmTypedPayload) {
    if typed.payload.starts_with(DATA_READ_REQUEST_DM_PREFIX) {
        if let Some((to, reply)) = serve_data_read(state, &typed).await {
            send_payload(state, to, reply);
        }
    } else if typed.payload.starts_with(DATA_WRITE_REQUEST_DM_PREFIX) {
        if let Some((to, reply)) = serve_data_write(state, &typed).await {
            send_payload(state, to, reply);
        }
    } else if typed.payload.starts_with(DATA_READ_REPLY_DM_PREFIX) && typed.verified {
        if let Some(reply) = DataReadReply::decode(&typed.payload) {
            complete_waiter(state, &typed.sender, reply);
        }
    }
    finish(typed);
}

/// Whether `sender` is under the serve limit; counts this request. A
/// sender with a data grant here counts in the grantees' bucket.
fn admit_sender(state: &AppState, sender: &AgentId, grantee: bool, now: u64) -> bool {
    let mut all = state
        .data_read_serve_limits
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (limits, cap) = if grantee {
        (&mut all.grantees, DATA_READ_SERVE_SENDERS_CAP)
    } else {
        (&mut all.strangers, DATA_READ_SERVE_STRANGERS_CAP)
    };
    limits.retain(|_, (start, _)| now.saturating_sub(*start) < DATA_READ_SERVE_WINDOW_MS);
    if !limits.contains_key(sender) && limits.len() >= cap {
        return false;
    }
    let (_, count) = limits.entry(*sender).or_insert((now, 0));
    if *count >= DATA_READ_SERVE_PER_WINDOW {
        return false;
    }
    *count += 1;
    true
}

/// Granted-agent side: the reply to one request, and who gets it. `None`
/// when nothing is sent (unverified, malformed, or over the serve limit).
pub(super) async fn serve_data_read(
    state: &AppState,
    typed: &DmTypedPayload,
) -> Option<(AgentId, Vec<u8>)> {
    if !typed.verified {
        return None;
    }
    let request = DataReadRequest::decode(&typed.payload)?;
    let access = state
        .agent
        .share_grant_access(&typed.sender, &typed.machine_id)
        .await;
    if !admit_sender(state, &typed.sender, !access.data.is_empty(), now_ms()) {
        return None;
    }
    let reply = if !access.allows_data_read(&request.group, &request.store) {
        DataReadReply::status(&request.request_id, DataReadStatus::Forbidden).encode()
    } else {
        read_local_store(state, &request).await
    };
    let reply = reply.or_else(|| {
        DataReadReply::status(&request.request_id, DataReadStatus::Unavailable).encode()
    })?;
    Some((typed.sender, reply))
}

/// The reply bytes for an admitted request; `None` when this daemon cannot
/// serve it (the caller then sends `unavailable`).
async fn read_local_store(state: &AppState, request: &DataReadRequest) -> Option<Vec<u8>> {
    let (_, topic) = crate::kv::encrypted::group_store_identity(&request.group, &request.store);
    let handle = state.kv_stores.read().await.get(&topic).cloned()?;
    match &request.op {
        DataReadOp::Keys => {
            let entries = handle.keys().await.ok()?;
            let keys = entries
                .iter()
                .map(|e| DataReadKey {
                    key: e.key.clone(),
                    content_type: e.content_type.clone(),
                    size: e.value.len(),
                    updated_at: e.updated_at,
                })
                .collect();
            DataReadReply::keys_fitting(&request.request_id, keys)
        }
        DataReadOp::Get { key } => match handle.get(key).await {
            Ok(Some(entry)) if entry.content_type.len() > MAX_DATA_READ_CONTENT_TYPE_BYTES => {
                DataReadReply::status(&request.request_id, DataReadStatus::ContentTypeTooLong)
                    .encode()
            }
            Ok(Some(entry)) if entry.value.len() > MAX_DATA_READ_VALUE_BYTES => {
                DataReadReply::status(&request.request_id, DataReadStatus::TooLarge).encode()
            }
            Ok(Some(entry)) => DataReadReply {
                entry: Some(DataReadEntry {
                    key: entry.key.clone(),
                    value_b64: base64::engine::general_purpose::STANDARD.encode(&entry.value),
                    content_type: entry.content_type.clone(),
                    updated_at: entry.updated_at,
                }),
                ..DataReadReply::status(&request.request_id, DataReadStatus::Ok)
            }
            // Within the bounds above the reply always fits (const-checked
            // in `share_grant::data_read`); `None` would answer unavailable.
            .encode(),
            Ok(None) => {
                DataReadReply::status(&request.request_id, DataReadStatus::NotFound).encode()
            }
            Err(_) => None,
        },
    }
}

/// Slice D2, granted-agent side: the reply to one write request, and who
/// gets it. `None` when nothing is sent (unverified, malformed, or over the
/// serve limit, which reads and writes share).
pub(super) async fn serve_data_write(
    state: &Arc<AppState>,
    typed: &DmTypedPayload,
) -> Option<(AgentId, Vec<u8>)> {
    if !typed.verified {
        return None;
    }
    let request = DataWriteRequest::decode(&typed.payload)?;
    let access = state
        .agent
        .share_grant_access(&typed.sender, &typed.machine_id)
        .await;
    if !admit_sender(state, &typed.sender, !access.data.is_empty(), now_ms()) {
        return None;
    }
    let reply = if access.allows_data_write(&request.group, &request.store) {
        write_local_store(state, &request).await
    } else {
        DataReadReply::status(&request.request_id, DataReadStatus::Forbidden)
    };
    let reply = reply.encode().or_else(|| {
        DataReadReply::status(&request.request_id, DataReadStatus::Unavailable).encode()
    })?;
    Some((typed.sender, reply))
}

/// Apply an admitted write as this daemon's own write to the store, through
/// the `PUT`/`DELETE /stores/:id/:key` handlers.
async fn write_local_store(state: &Arc<AppState>, request: &DataWriteRequest) -> DataReadReply {
    let (_, topic) = crate::kv::encrypted::group_store_identity(&request.group, &request.store);
    let (code, Json(body)) = match &request.op {
        DataWriteOp::Put {
            key,
            value_b64,
            content_type,
        } => {
            super::routes::stores::put_kv_value(
                None,
                State(Arc::clone(state)),
                Path((topic, key.clone())),
                Json(super::routes::stores::PutValueRequest {
                    value: value_b64.clone(),
                    content_type: Some(content_type.clone()),
                }),
            )
            .await
        }
        DataWriteOp::Delete { key } => {
            super::routes::stores::delete_kv_value(
                State(Arc::clone(state)),
                Path((topic, key.clone())),
            )
            .await
        }
    };
    write_reply(&request.request_id, code, &body)
}

/// The write reply for the store handler's answer.
fn write_reply(request_id: &str, code: StatusCode, body: &serde_json::Value) -> DataReadReply {
    let status = match code {
        StatusCode::OK | StatusCode::ACCEPTED => DataReadStatus::Ok,
        // The store is not open here.
        StatusCode::NOT_FOUND => DataReadStatus::Unavailable,
        StatusCode::PAYLOAD_TOO_LARGE => DataReadStatus::TooLarge,
        code if code.is_client_error() => DataReadStatus::Refused,
        _ => DataReadStatus::Unavailable,
    };
    let mut reply = DataReadReply::status(request_id, status);
    match status {
        DataReadStatus::Ok => reply.published = Some(code == StatusCode::OK),
        DataReadStatus::Refused => {
            reply.error = Some(refusal_for(code, body).as_str().to_string());
        }
        _ => {}
    }
    reply
}

/// The fixed refusal code for a store handler's refusal. The handler's own
/// error text stays on this daemon (review of #1953).
fn refusal_for(code: StatusCode, body: &serde_json::Value) -> DataWriteRefusal {
    match code {
        StatusCode::FORBIDDEN => DataWriteRefusal::StorePolicy,
        StatusCode::GONE => DataWriteRefusal::GroupAdminRevoked,
        StatusCode::CONFLICT
            if body["reason"].as_str()
                == Some(WaitingCause::WaitingForEligibleAdminRevocation.as_str()) =>
        {
            DataWriteRefusal::WaitingForEligibleAdminRevocation
        }
        StatusCode::CONFLICT => DataWriteRefusal::ImmutableKey,
        _ => DataWriteRefusal::Other,
    }
}

/// Send one data-read DM, one attempt, off the caller's task.
fn send_payload(state: &AppState, to: AgentId, payload: Vec<u8>) {
    #[cfg(test)]
    test_seam::record(state, to, payload.clone());
    let agent = Arc::clone(&state.agent);
    state.spawn_detached(async move {
        let mut config = crate::server::routes::named_groups::named_group_direct_delivery_config();
        config.require_gossip = true;
        config.max_retries = 0;
        if let Err(error) = agent.send_direct_with_config(&to, payload, config).await {
            tracing::debug!(%error, "#1094: data-read DM was not delivered (best effort)");
        }
    });
}

/// Grantee side: hand a reply to the waiter for its request id, when the
/// reply comes from the agent that request went to.
pub(super) fn complete_waiter(state: &AppState, from: &AgentId, reply: DataReadReply) {
    let mut waiters = state
        .data_read_waiters
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if waiters
        .get(&reply.request_id)
        .is_some_and(|(to, _)| to == from)
    {
        if let Some((_, tx)) = waiters.remove(&reply.request_id) {
            let _ = tx.send(reply);
        }
    }
}

/// Removes its waiter on drop (timeout, send failure, or a dropped call).
struct WaiterGuard<'a> {
    state: &'a AppState,
    request_id: String,
}

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        self.state
            .data_read_waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.request_id);
    }
}

fn reply_response(reply: DataReadReply) -> (StatusCode, Json<serde_json::Value>) {
    match reply.status {
        DataReadStatus::Ok => {
            let mut body = serde_json::json!({ "ok": true });
            if let Some(keys) = reply.keys {
                body["keys"] = serde_json::json!(keys);
                body["truncated"] = serde_json::json!(reply.truncated);
            }
            if let Some(entry) = reply.entry {
                body["key"] = serde_json::json!(entry.key);
                body["value"] = serde_json::json!(entry.value_b64);
                body["content_type"] = serde_json::json!(entry.content_type);
                body["updated_at"] = serde_json::json!(entry.updated_at);
            }
            if let Some(published) = reply.published {
                body["published"] = serde_json::json!(published);
            }
            (StatusCode::OK, Json(body))
        }
        DataReadStatus::Refused => api_error(
            StatusCode::CONFLICT,
            format!(
                "the granted agent's store refused the write: {}",
                DataWriteRefusal::from_wire(reply.error.as_deref().unwrap_or_default()).describe()
            ),
        ),
        DataReadStatus::Forbidden => api_error(
            StatusCode::FORBIDDEN,
            "the granted agent holds no grant that lets this agent do this to the store",
        ),
        DataReadStatus::NotFound => api_error(StatusCode::NOT_FOUND, "key not found"),
        DataReadStatus::TooLarge => api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "the value is over the {MAX_DATA_READ_VALUE_BYTES}-byte limit of a granted read"
            ),
        ),
        DataReadStatus::ContentTypeTooLong => api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "the value's content type is over the {MAX_DATA_READ_CONTENT_TYPE_BYTES}-byte limit of a granted read"
            ),
        ),
        DataReadStatus::Unavailable => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the granted agent cannot serve this store now",
        ),
    }
}

/// Grantee side: read `op` of `(group, store)` from `agent`.
pub(super) async fn read_granted_store(
    state: &AppState,
    agent: AgentId,
    group: String,
    store: String,
    op: DataReadOp,
) -> (StatusCode, Json<serde_json::Value>) {
    let encode = |request_id| {
        DataReadRequest {
            request_id,
            group,
            store,
            op,
        }
        .encode()
    };
    let bit = crate::dm::CapabilityRegistry::DATA_READ_V1;
    call_granted_agent(state, agent, encode, bit, "data_read_v1").await
}

/// Slice D2, grantee side: write `op` to `(group, store)` on `agent`.
pub(super) async fn write_granted_store(
    state: &AppState,
    agent: AgentId,
    group: String,
    store: String,
    op: DataWriteOp,
) -> (StatusCode, Json<serde_json::Value>) {
    let encode = |request_id| {
        DataWriteRequest {
            request_id,
            group,
            store,
            op,
        }
        .encode()
    };
    let bit = crate::dm::CapabilityRegistry::DATA_WRITE_V1;
    call_granted_agent(state, agent, encode, bit, "data_write_v1").await
}

/// Send one request, built by `encode` from a fresh request id, to `agent`
/// when its current verified advert sets `bit`, and answer with its reply.
async fn call_granted_agent(
    state: &AppState,
    agent: AgentId,
    encode: impl FnOnce(String) -> Option<Vec<u8>>,
    bit: u64,
    capability: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    let request_id = hex::encode(rand::random::<[u8; 16]>());
    let Some(payload) = encode(request_id.clone()) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "group, store or key is empty or too long",
        );
    };
    if state
        .agent
        .capability_store()
        .verified_registry_supports(&agent, bit)
        != Some(true)
    {
        return api_error(
            StatusCode::FAILED_DEPENDENCY,
            format!("the agent does not advertise {capability}"),
        );
    }
    let rx = {
        let mut waiters = state
            .data_read_waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if waiters.len() >= DATA_READ_WAITER_CAP {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many requests in flight",
            );
        }
        let (tx, rx) = oneshot::channel();
        waiters.insert(request_id.clone(), (agent, tx));
        rx
    };
    let _guard = WaiterGuard { state, request_id };
    send_payload(state, agent, payload);
    match tokio::time::timeout(DATA_READ_REPLY_TIMEOUT, rx).await {
        Ok(Ok(reply)) => reply_response(reply),
        _ => api_error(
            StatusCode::GATEWAY_TIMEOUT,
            "no reply from the granted agent",
        ),
    }
}

/// `GET /grants/data/:agent/:group/:store`: the keys of a granted store.
pub(super) async fn get_granted_store_keys(
    State(state): State<Arc<AppState>>,
    Path((agent, group, store)): Path<(String, String, String)>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Ok(agent) = parse_agent_id_hex(&agent) else {
        return api_error(StatusCode::BAD_REQUEST, "invalid agent id");
    };
    read_granted_store(&state, agent, group, store, DataReadOp::Keys).await
}

/// `GET /grants/data/:agent/:group/:store/:key`: one value of a granted
/// store.
pub(super) async fn get_granted_store_value(
    State(state): State<Arc<AppState>>,
    Path((agent, group, store, key)): Path<(String, String, String, String)>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Ok(agent) = parse_agent_id_hex(&agent) else {
        return api_error(StatusCode::BAD_REQUEST, "invalid agent id");
    };
    read_granted_store(&state, agent, group, store, DataReadOp::Get { key }).await
}

/// Body of `PUT /grants/data/:agent/:group/:store/:key`.
#[derive(Debug, serde::Deserialize)]
pub(super) struct PutGrantedValueRequest {
    /// Base64 of the value bytes.
    value: String,
    /// The value's content type (default `application/octet-stream`).
    content_type: Option<String>,
}

/// `PUT /grants/data/:agent/:group/:store/:key`: set one value of a granted
/// store (slice D2; the grant must be `rw`).
pub(super) async fn put_granted_store_value(
    State(state): State<Arc<AppState>>,
    Path((agent, group, store, key)): Path<(String, String, String, String)>,
    Json(req): Json<PutGrantedValueRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Ok(agent) = parse_agent_id_hex(&agent) else {
        return api_error(StatusCode::BAD_REQUEST, "invalid agent id");
    };
    let Ok(value) = base64::engine::general_purpose::STANDARD.decode(&req.value) else {
        return api_error(StatusCode::BAD_REQUEST, "value is not base64");
    };
    if value.len() > MAX_DATA_WRITE_VALUE_BYTES {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "the value is over the {MAX_DATA_WRITE_VALUE_BYTES}-byte limit of a granted write"
            ),
        );
    }
    let content_type = req
        .content_type
        .unwrap_or_else(|| "application/octet-stream".to_string());
    if content_type.len() > MAX_DATA_READ_CONTENT_TYPE_BYTES {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "the content type is over the {MAX_DATA_READ_CONTENT_TYPE_BYTES}-byte limit of a granted write"
            ),
        );
    }
    let op = DataWriteOp::Put {
        key,
        value_b64: base64::engine::general_purpose::STANDARD.encode(value),
        content_type,
    };
    write_granted_store(&state, agent, group, store, op).await
}

/// `DELETE /grants/data/:agent/:group/:store/:key`: remove one key of a
/// granted store (slice D2; the grant must be `rw`).
pub(super) async fn delete_granted_store_value(
    State(state): State<Arc<AppState>>,
    Path((agent, group, store, key)): Path<(String, String, String, String)>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Ok(agent) = parse_agent_id_hex(&agent) else {
        return api_error(StatusCode::BAD_REQUEST, "invalid agent id");
    };
    write_granted_store(&state, agent, group, store, DataWriteOp::Delete { key }).await
}

#[cfg(test)]
pub(super) mod test_seam {
    use crate::identity::AgentId;
    use crate::server::state::AppState;
    use std::sync::Mutex;

    type Sent = (String, AgentId, Vec<u8>);
    static SENT: Mutex<Vec<Sent>> = Mutex::new(Vec::new());

    pub(super) fn record(state: &AppState, to: AgentId, payload: Vec<u8>) {
        let from = hex::encode(state.agent.agent_id().as_bytes());
        SENT.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((from, to, payload));
    }

    /// The data-read DMs `state` sent, oldest first.
    pub(in crate::server) fn sent_by(state: &AppState) -> Vec<(AgentId, Vec<u8>)> {
        let from = hex::encode(state.agent.agent_id().as_bytes());
        SENT.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(sender, _, _)| *sender == from)
            .map(|(_, to, payload)| (*to, payload.clone()))
            .collect()
    }
}

#[cfg(test)]
#[path = "data_read_tests.rs"]
mod tests;
