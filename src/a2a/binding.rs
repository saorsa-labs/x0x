//! A2A-over-x0x transport binding — envelope codec + unary request/response.
//!
//! Increment 1 of GitHub issue #112 (ADR-0017 workstream #3), implementing
//! §4 of `docs/design/a2a-over-x0x-binding.md`: unary A2A JSON-RPC methods
//! (`message/send`, `tasks/get`, `tasks/cancel`, …) carried over x0x direct
//! messages with `corrId` correlation. "A2A semantics, x0x delivery."
//!
//! Wire envelope — versioned and additive:
//!
//! ```json
//! {
//!   "x0xBinding": "a2a/1",
//!   "corrId": "<uuid>",
//!   "kind": "request",
//!   "jsonrpc": { "jsonrpc": "2.0", "method": "message/send", "params": {}, "id": "<uuid>" }
//! }
//! ```
//!
//! Forward-compat rules (both directions):
//!
//! - Receivers skip envelopes whose `x0xBinding` version they do not speak.
//! - Receivers skip unknown `kind` values, so later increments (streaming,
//!   push) can add kinds without breaking old peers. `kind` is therefore a
//!   plain string on the wire, not a closed enum.
//! - Unknown JSON members are ignored (serde default), keeping additions
//!   additive.
//!
//! Delivery uses `send_direct_with_config` preferring the `RawQuicAcked`
//! path (design §4 delivery proof), falling back per [`DmSendConfig`]
//! policy when no live raw connection exists.
//!
//! Streaming (`message/stream`), push notifications, and large-artifact
//! transfer are later increments (design §5–7) and are intentionally absent
//! here; the served Agent Card keeps `capabilities.streaming` /
//! `pushNotifications` at `false`.

use crate::dm::{DmError, DmSendConfig};
use crate::identity::AgentId;
use crate::Agent;
use dashmap::DashMap;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::{debug, trace, warn};
use uuid::Uuid;

/// Binding wire version carried in the `x0xBinding` envelope member.
///
/// `<name>/<major>` token: receivers skip envelopes whose version they do
/// not understand, and skip unknown `kind` values, so new envelope kinds
/// stay additive.
pub const X0X_BINDING_VERSION: &str = "a2a/1";

/// Envelope `kind` for a JSON-RPC request.
pub const KIND_REQUEST: &str = "request";
/// Envelope `kind` for a JSON-RPC response.
pub const KIND_RESPONSE: &str = "response";

/// JSON-RPC version member (always `"2.0"`).
const JSONRPC_2_0: &str = "2.0";

/// JSON-RPC 2.0 error code: parse error.
pub const JSONRPC_PARSE_ERROR: i64 = -32700;
/// JSON-RPC 2.0 error code: invalid request.
pub const JSONRPC_INVALID_REQUEST: i64 = -32600;
/// JSON-RPC 2.0 error code: method not found.
pub const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC 2.0 error code: internal error.
pub const JSONRPC_INTERNAL_ERROR: i64 = -32603;

// ─── Envelope ─────────────────────────────────────────────────────────────

/// One binding envelope — the DM payload unit for A2A-over-x0x traffic.
///
/// `kind` is a plain string (not a closed enum) so envelopes carrying kinds
/// introduced by later increments still decode on old peers, which skip
/// them. `jsonrpc` carries the verbatim A2A JSON-RPC 2.0 body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BindingEnvelope {
    /// Binding version token — must equal [`X0X_BINDING_VERSION`].
    #[serde(rename = "x0xBinding")]
    pub binding: String,
    /// Correlation id tying a response to its request.
    #[serde(rename = "corrId")]
    pub corr_id: String,
    /// Envelope kind — `request` / `response` today; unknown kinds decode
    /// fine and are skipped by the receive loop.
    pub kind: String,
    /// Verbatim JSON-RPC 2.0 request or response object.
    pub jsonrpc: Value,
}

impl BindingEnvelope {
    /// Build an envelope at the current wire version, serializing the
    /// JSON-RPC body verbatim.
    pub fn new(
        kind: &str,
        corr_id: String,
        jsonrpc: &impl Serialize,
    ) -> Result<Self, BindingError> {
        Ok(Self {
            binding: X0X_BINDING_VERSION.to_string(),
            corr_id,
            kind: kind.to_string(),
            jsonrpc: serde_json::to_value(jsonrpc)
                .map_err(|e| BindingError::Encode(e.to_string()))?,
        })
    }
}

/// Serialize an envelope for the DM wire, enforcing the DM payload cap.
pub fn encode_envelope(envelope: &BindingEnvelope) -> Result<Vec<u8>, BindingError> {
    let bytes =
        serde_json::to_vec(envelope).map_err(|e| BindingError::Encode(e.to_string()))?;
    if bytes.len() > crate::direct::MAX_DIRECT_PAYLOAD_SIZE {
        return Err(BindingError::PayloadTooLarge {
            len: bytes.len(),
            max: crate::direct::MAX_DIRECT_PAYLOAD_SIZE,
        });
    }
    Ok(bytes)
}

/// Decode an envelope, rejecting binding versions this peer does not speak.
///
/// Unknown `kind` values and unknown JSON members are *not* errors — they
/// decode successfully and callers skip them (additive evolution).
pub fn decode_envelope(bytes: &[u8]) -> Result<BindingEnvelope, BindingError> {
    let envelope: BindingEnvelope =
        serde_json::from_slice(bytes).map_err(|e| BindingError::Malformed(e.to_string()))?;
    if envelope.binding != X0X_BINDING_VERSION {
        return Err(BindingError::UnsupportedVersion(envelope.binding));
    }
    Ok(envelope)
}

/// Cheap probe of a DM payload: the `x0xBinding` version token, if this is
/// an A2A binding envelope at all. The DM channel is shared with other x0x
/// protocols, so the receive loop probes before fully decoding.
#[must_use]
pub fn probe_binding_version(bytes: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Probe {
        #[serde(rename = "x0xBinding")]
        binding: Option<String>,
    }
    serde_json::from_slice::<Probe>(bytes).ok()?.binding
}

// ─── JSON-RPC 2.0 ─────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 request — the `jsonrpc` member of a `request` envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// A2A method name (e.g. `message/send`).
    pub method: String,
    /// Method params, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Request id — the binding mirrors the envelope `corrId` here.
    pub id: Value,
}

impl JsonRpcRequest {
    /// Build a request at JSON-RPC version 2.0.
    #[must_use]
    pub fn new(method: impl Into<String>, params: Option<Value>, id: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_2_0.to_string(),
            method: method.into(),
            params,
            id,
        }
    }
}

/// A JSON-RPC 2.0 response — the `jsonrpc` member of a `response` envelope.
///
/// Carries exactly one of `result` / `error`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Success result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Request id echoed back.
    pub id: Value,
}

impl JsonRpcResponse {
    /// A successful response.
    #[must_use]
    pub fn result(result: Value, id: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_2_0.to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// An error response.
    #[must_use]
    pub fn error(error: JsonRpcError, id: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_2_0.to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code (e.g. [`JSONRPC_METHOD_NOT_FOUND`]).
    pub code: i64,
    /// Human-readable message.
    pub message: String,
    /// Optional structured data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Build an error with no data member.
    #[must_use]
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// `-32601` — the peer has no handler registered for this method.
    #[must_use]
    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            JSONRPC_METHOD_NOT_FOUND,
            format!("method not found: {method}"),
        )
    }

    /// `-32600` — the envelope's `jsonrpc` member is not a valid request.
    #[must_use]
    pub fn invalid_request(reason: impl Into<String>) -> Self {
        Self::new(JSONRPC_INVALID_REQUEST, reason)
    }

    /// `-32603` — internal failure (e.g. unparseable response body).
    #[must_use]
    pub fn internal(reason: impl Into<String>) -> Self {
        Self::new(JSONRPC_INTERNAL_ERROR, reason)
    }
}

// ─── Errors ───────────────────────────────────────────────────────────────

/// Errors surfaced by the A2A-over-x0x binding.
#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    /// Payload is not a well-formed binding envelope.
    #[error("malformed binding envelope: {0}")]
    Malformed(String),
    /// Envelope carried an `x0xBinding` version this peer does not speak.
    #[error("unsupported x0xBinding version {0:?}")]
    UnsupportedVersion(String),
    /// Serializing an envelope or JSON-RPC body failed.
    #[error("envelope encode failed: {0}")]
    Encode(String),
    /// Envelope exceeded the direct-message payload cap.
    #[error("envelope too large: {len} bytes (max {max})")]
    PayloadTooLarge {
        /// Actual encoded size.
        len: usize,
        /// Wire cap.
        max: usize,
    },
    /// The direct-message send itself failed.
    #[error("direct send failed: {0}")]
    Send(#[from] DmError),
    /// No correlated response arrived within the configured timeout.
    #[error("request timed out after {0:?}")]
    Timeout(Duration),
    /// The peer answered with a JSON-RPC error object.
    #[error("remote error {code}: {message}")]
    Remote {
        /// JSON-RPC error code.
        code: i64,
        /// Human-readable message.
        message: String,
        /// Optional structured data.
        data: Option<Value>,
    },
    /// Response carried neither (or both) `result` and `error`.
    #[error("invalid JSON-RPC response: {0}")]
    InvalidResponse(String),
    /// The session was shut down while a request was in flight.
    #[error("binding session closed")]
    Closed,
}

// ─── Session ──────────────────────────────────────────────────────────────

/// Application handler for one A2A method: params in, JSON-RPC result or
/// error out. Handlers run in their own tasks so a slow handler never
/// blocks the receive loop.
pub type BindingHandler = Arc<
    dyn Fn(Option<Value>) -> BoxFuture<'static, Result<Value, JsonRpcError>> + Send + Sync,
>;

/// Per-session configuration.
#[derive(Debug, Clone)]
pub struct BindingConfig {
    /// Max wait for a correlated response before
    /// [`BindingSession::call`] fails with [`BindingError::Timeout`].
    pub request_timeout: Duration,
    /// DM send behaviour for requests and responses. The default prefers
    /// the `RawQuicAcked` path (design §4 delivery proof) and falls back
    /// per [`DmSendConfig`] policy.
    pub send_config: DmSendConfig,
}

impl Default for BindingConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            send_config: DmSendConfig {
                prefer_raw_quic_if_connected: true,
                raw_quic_receive_ack_timeout: Some(Duration::from_secs(4)),
                ..DmSendConfig::default()
            },
        }
    }
}

struct SessionInner {
    agent: Arc<Agent>,
    /// method name → handler.
    handlers: DashMap<String, BindingHandler>,
    /// corrId → waiter for the matching response.
    in_flight: DashMap<String, oneshot::Sender<JsonRpcResponse>>,
    /// Spawned per-request handler tasks; aborted on session drop.
    handler_tasks: Mutex<JoinSet<()>>,
    config: BindingConfig,
}

/// One agent's A2A-over-x0x endpoint — both client (`call`) and server
/// (registered handlers) over the shared DM channel.
///
/// A background receive task (spawned by [`BindingSession::start`]) consumes
/// this agent's direct messages, dispatches `request` envelopes to handlers,
/// answers them, and correlates `response` envelopes to in-flight `call`s.
/// Dropping the session aborts the receive task and any in-flight handlers.
pub struct BindingSession {
    inner: Arc<SessionInner>,
    receive_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl BindingSession {
    /// Start a session on `agent`, spawning the DM receive loop.
    ///
    /// Safe to start before `join_network`: the loop simply sees no traffic
    /// until the DM channel is live.
    #[must_use]
    pub fn start(agent: Arc<Agent>, config: BindingConfig) -> Self {
        let inner = Arc::new(SessionInner {
            agent,
            handlers: DashMap::new(),
            in_flight: DashMap::new(),
            handler_tasks: Mutex::new(JoinSet::new()),
            config,
        });
        let rx = inner.agent.subscribe_direct();
        let loop_inner = Arc::clone(&inner);
        let receive_task = tokio::spawn(async move { receive_loop(loop_inner, rx).await });
        Self {
            inner,
            receive_task: Mutex::new(Some(receive_task)),
        }
    }

    /// Register `handler` for an A2A method (e.g. `message/send`).
    /// Re-registering replaces the previous handler.
    pub fn register_handler<F, Fut>(&self, method: &str, handler: F)
    where
        F: Fn(Option<Value>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, JsonRpcError>> + Send + 'static,
    {
        self.inner.handlers.insert(
            method.to_string(),
            Arc::new(move |params| Box::pin(handler(params)) as BoxFuture<'static, _>),
        );
    }

    /// Number of `call`s currently awaiting a correlated response.
    #[must_use]
    pub fn in_flight_len(&self) -> usize {
        self.inner.in_flight.len()
    }

    /// Call a unary A2A method on `peer` and await its correlated response.
    ///
    /// Correlation: a fresh `corrId` (uuid) is registered in the in-flight
    /// map *before* the request DM is sent, so a fast peer's answer can
    /// never be missed. On timeout the entry is removed and a late response
    /// is skipped by the receive loop.
    ///
    /// # Errors
    ///
    /// - [`BindingError::Send`] if the request DM could not be delivered.
    /// - [`BindingError::Timeout`] if no response arrives within
    ///   `config.request_timeout`.
    /// - [`BindingError::Remote`] if the peer answered with a JSON-RPC
    ///   error (e.g. `-32601` for an unregistered method).
    /// - [`BindingError::InvalidResponse`] for a malformed response body.
    pub async fn call(
        &self,
        peer: &AgentId,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, BindingError> {
        let corr_id = Uuid::new_v4().to_string();
        let request = JsonRpcRequest::new(method, params, Value::String(corr_id.clone()));
        let envelope = BindingEnvelope::new(KIND_REQUEST, corr_id.clone(), &request)?;
        let bytes = encode_envelope(&envelope)?;

        let (tx, rx) = oneshot::channel();
        // Insert BEFORE sending: a fast peer can answer before the send
        // returns, and the receive loop must find the waiter.
        self.inner.in_flight.insert(corr_id.clone(), tx);
        // Every exit path other than successful delivery — send failure,
        // timeout, or the caller dropping this future mid-flight — removes
        // the waiter via the guard. After successful delivery the receive
        // loop already consumed the entry, so the removal is a no-op.
        let _cleanup = InFlightCleanup {
            in_flight: &self.inner.in_flight,
            corr_id: corr_id.clone(),
        };

        if let Err(err) = self
            .inner
            .agent
            .send_direct_with_config(peer, bytes, self.inner.config.send_config.clone())
            .await
        {
            return Err(BindingError::Send(err));
        }
        debug!(%corr_id, method, "a2a request sent");

        let response = match tokio::time::timeout(self.inner.config.request_timeout, rx).await {
            Ok(Ok(response)) => response,
            Ok(Err(_sender_dropped)) => return Err(BindingError::Closed),
            Err(_elapsed) => {
                return Err(BindingError::Timeout(self.inner.config.request_timeout));
            }
        };
        response_into_result(response)
    }
}

impl Drop for BindingSession {
    fn drop(&mut self) {
        if let Ok(Some(task)) = self.receive_task.lock().map(|mut slot| slot.take()) {
            task.abort();
        }
        if let Ok(mut tasks) = self.inner.handler_tasks.lock() {
            tasks.abort_all();
        }
    }
}

/// RAII cleanup for one in-flight `call`.
///
/// Removes the corrId from the in-flight map on EVERY exit path of
/// [`BindingSession::call`]: send failure, timeout, and — critically —
/// caller cancellation (the caller dropping the `call` future, e.g. an
/// HTTP client disconnect) when the peer never responds. After successful
/// delivery the receive loop has already consumed the entry, so the
/// removal is a no-op. Without this, cancelled calls leak waiters and the
/// map grows unboundedly.
struct InFlightCleanup<'a> {
    in_flight: &'a DashMap<String, oneshot::Sender<JsonRpcResponse>>,
    corr_id: String,
}

impl Drop for InFlightCleanup<'_> {
    fn drop(&mut self) {
        self.in_flight.remove(&self.corr_id);
    }
}

/// Translate a decoded response into the caller-visible result.
fn response_into_result(response: JsonRpcResponse) -> Result<Value, BindingError> {
    match (response.result, response.error) {
        (Some(value), None) => Ok(value),
        (None, Some(error)) => Err(BindingError::Remote {
            code: error.code,
            message: error.message,
            data: error.data,
        }),
        (result, error) => Err(BindingError::InvalidResponse(format!(
            "exactly one of result/error required (result present: {}, error present: {})",
            result.is_some(),
            error.is_some()
        ))),
    }
}

async fn receive_loop(inner: Arc<SessionInner>, mut rx: crate::direct::DirectMessageReceiver) {
    while let Some(msg) = rx.recv().await {
        // Cheap probe first: the DM channel is shared with other x0x
        // protocols — non-binding payloads are skipped without log spam.
        let Some(version) = probe_binding_version(&msg.payload) else {
            continue;
        };
        if version != X0X_BINDING_VERSION {
            debug!(%version, "skipping A2A binding envelope with unsupported version");
            continue;
        }
        let envelope = match decode_envelope(&msg.payload) {
            Ok(envelope) => envelope,
            Err(err) => {
                warn!(%err, "dropping malformed A2A binding envelope");
                continue;
            }
        };
        match envelope.kind.as_str() {
            KIND_REQUEST => {
                let handler_inner = Arc::clone(&inner);
                let sender = msg.sender;
                let Ok(mut tasks) = inner.handler_tasks.lock() else {
                    warn!("handler task set poisoned; dropping request");
                    continue;
                };
                // Reap completed handler tasks so the set stays bounded.
                while tasks.try_join_next().is_some() {}
                // TODO(#112 streaming increment): handler tasks are
                // spawned uncapped — a flood of inbound requests spawns a
                // task each. Add a semaphore cap on concurrent handlers
                // (backpressure for chatty streams, design §10.3) when the
                // streaming increment lands.
                tasks.spawn(async move {
                    handler_inner.handle_request(sender, envelope).await;
                });
            }
            KIND_RESPONSE => inner.handle_response(envelope),
            other => {
                // Additive evolution: newer peers may send kinds we do not
                // know (stream, stream-end, …). Skip, don't fail.
                trace!(kind = %other, "skipping unknown A2A binding envelope kind");
            }
        }
    }
    debug!("a2a binding receive loop ended (DM channel closed)");
}

impl SessionInner {
    async fn handle_request(&self, peer: AgentId, envelope: BindingEnvelope) {
        let response = match serde_json::from_value::<JsonRpcRequest>(envelope.jsonrpc) {
            Ok(request) => self.dispatch(request).await,
            Err(err) => JsonRpcResponse::error(
                JsonRpcError::invalid_request(format!("not a JSON-RPC 2.0 request: {err}")),
                Value::Null,
            ),
        };
        let result = BindingEnvelope::new(KIND_RESPONSE, envelope.corr_id, &response)
            .and_then(|response_envelope| encode_envelope(&response_envelope));
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(%err, "failed to encode A2A response; dropping");
                return;
            }
        };
        if let Err(err) = self
            .agent
            .send_direct_with_config(&peer, bytes, self.config.send_config.clone())
            .await
        {
            warn!(%err, "failed to send A2A response");
        }
    }

    async fn dispatch(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        // Clone the Arc and drop the map guard before awaiting — a handler
        // may re-enter the session (nested calls) and must not deadlock.
        let handler = self
            .handlers
            .get(&request.method)
            .map(|entry| Arc::clone(entry.value()));
        let Some(handler) = handler else {
            return JsonRpcResponse::error(
                JsonRpcError::method_not_found(&request.method),
                request.id,
            );
        };
        match handler(request.params).await {
            Ok(result) => JsonRpcResponse::result(result, request.id),
            Err(error) => JsonRpcResponse::error(error, request.id),
        }
    }

    fn handle_response(&self, envelope: BindingEnvelope) {
        let Some((_, waiter)) = self.in_flight.remove(&envelope.corr_id) else {
            // Late answer to a timed-out request, duplicate, or not ours.
            trace!(
                corr_id = %envelope.corr_id,
                "no in-flight request for A2A response; skipping"
            );
            return;
        };
        let response = match serde_json::from_value::<JsonRpcResponse>(envelope.jsonrpc) {
            Ok(response) => response,
            Err(err) => JsonRpcResponse::error(
                JsonRpcError::internal(format!("unparseable JSON-RPC response: {err}")),
                Value::Null,
            ),
        };
        // The waiter may have raced a timeout and gone away; that is fine.
        let _ = waiter.send(response);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_request() -> JsonRpcRequest {
        JsonRpcRequest::new(
            "message/send",
            Some(json!({"message": {"parts": [{"kind": "text", "text": "ping"}]}})),
            Value::String("corr-1".to_string()),
        )
    }

    #[test]
    fn envelope_round_trips_request() {
        let envelope =
            BindingEnvelope::new(KIND_REQUEST, "corr-1".to_string(), &sample_request())
                .expect("build envelope");
        assert_eq!(envelope.binding, X0X_BINDING_VERSION);
        let bytes = encode_envelope(&envelope).expect("encode");
        let decoded = decode_envelope(&bytes).expect("decode");
        assert_eq!(decoded, envelope);
        let request: JsonRpcRequest =
            serde_json::from_value(decoded.jsonrpc).expect("parse jsonrpc");
        assert_eq!(request.method, "message/send");
        assert_eq!(request.jsonrpc, "2.0");
    }

    #[test]
    fn envelope_round_trips_error_response() {
        let response = JsonRpcResponse::error(
            JsonRpcError::method_not_found("tasks/resubscribe"),
            Value::String("corr-9".to_string()),
        );
        let envelope =
            BindingEnvelope::new(KIND_RESPONSE, "corr-9".to_string(), &response)
                .expect("build envelope");
        let decoded = decode_envelope(&encode_envelope(&envelope).expect("encode"))
            .expect("decode");
        let parsed: JsonRpcResponse =
            serde_json::from_value(decoded.jsonrpc).expect("parse jsonrpc");
        let error = parsed.error.expect("error object");
        assert_eq!(error.code, JSONRPC_METHOD_NOT_FOUND);
        assert!(parsed.result.is_none());
    }

    #[test]
    fn wire_shape_matches_design_sketch() {
        let envelope =
            BindingEnvelope::new(KIND_REQUEST, "corr-1".to_string(), &sample_request())
                .expect("build envelope");
        let value: Value =
            serde_json::from_slice(&encode_envelope(&envelope).expect("encode")).expect("json");
        assert_eq!(value["x0xBinding"], json!("a2a/1"));
        assert_eq!(value["corrId"], json!("corr-1"));
        assert_eq!(value["kind"], json!("request"));
        assert_eq!(value["jsonrpc"]["jsonrpc"], json!("2.0"));
        assert_eq!(value["jsonrpc"]["method"], json!("message/send"));
    }

    #[test]
    fn decode_preserves_unknown_kind_and_members() {
        // A future `stream` envelope with members this version does not
        // know must still decode — additive evolution (design §5 kinds).
        let bytes = br#"{"x0xBinding":"a2a/1","corrId":"c","kind":"stream","seq":7,"jsonrpc":{}}"#;
        let envelope = decode_envelope(bytes).expect("decode");
        assert_eq!(envelope.kind, "stream");
        assert_eq!(envelope.corr_id, "c");
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let bytes = br#"{"x0xBinding":"a2a/2","corrId":"c","kind":"request","jsonrpc":{}}"#;
        let err = decode_envelope(bytes).expect_err("must reject");
        assert!(matches!(err, BindingError::UnsupportedVersion(v) if v == "a2a/2"));
    }

    #[test]
    fn decode_rejects_malformed_payload() {
        let err = decode_envelope(b"not json at all").expect_err("must reject");
        assert!(matches!(err, BindingError::Malformed(_)));
    }

    #[test]
    fn probe_distinguishes_binding_payloads() {
        assert_eq!(probe_binding_version(b"plain-text-dm"), None);
        assert_eq!(probe_binding_version(br#"{"other":"json"}"#), None);
        assert_eq!(
            probe_binding_version(
                br#"{"x0xBinding":"a2a/1","corrId":"c","kind":"request","jsonrpc":{}}"#
            ),
            Some("a2a/1".to_string())
        );
    }

    #[test]
    fn response_into_result_variants() {
        let ok = response_into_result(JsonRpcResponse::result(json!({"ok": true}), Value::Null));
        assert_eq!(ok.expect("result"), json!({"ok": true}));

        let err = response_into_result(JsonRpcResponse::error(
            JsonRpcError::method_not_found("nope"),
            Value::Null,
        ))
        .expect_err("remote error");
        assert!(matches!(
            err,
            BindingError::Remote {
                code: JSONRPC_METHOD_NOT_FOUND,
                ..
            }
        ));

        let both = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(Value::Null),
            error: Some(JsonRpcError::internal("x")),
            id: Value::Null,
        };
        assert!(matches!(
            response_into_result(both),
            Err(BindingError::InvalidResponse(_))
        ));

        let neither = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: None,
            id: Value::Null,
        };
        assert!(matches!(
            response_into_result(neither),
            Err(BindingError::InvalidResponse(_))
        ));
    }
}
