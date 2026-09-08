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
//!   "corrId": "<corr-id>",
//!   "kind": "request",
//!   "jsonrpc": { "jsonrpc": "2.0", "method": "message/send", "params": {}, "id": "<corr-id>" }
//! }
//! ```
//!
//! `<corr-id>` is an opaque correlation string chosen by the caller; peers
//! must echo it verbatim and must not parse it. This implementation emits
//! `<uuid>-<call-token>` (see [`BindingSession::call`]), and the JSON-RPC
//! `id` is that same string.
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
//! path (design §4 delivery proof), falling back per `DmSendConfig`
//! policy when no live raw connection exists.
//!
//! Streaming (`message/stream`), push notifications, and large-artifact
//! transfer are later increments (design §5–7) and are intentionally absent
//! here; the served Agent Card keeps `capabilities.streaming` /
//! `pushNotifications` at `false`.

use crate::dm::{DmError, DmSendConfig};
use crate::identity::AgentId;
use crate::Agent;
use dashmap::mapref::entry::Entry as DashEntry;
use dashmap::DashMap;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
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
    let bytes = serde_json::to_vec(envelope).map_err(|e| BindingError::Encode(e.to_string()))?;
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
    /// Also returned when this session can no longer open a correlation
    /// slot for a new call: its call-token space is exhausted, or the
    /// freshly generated correlation id is somehow already in flight.
    /// Both mean the session cannot serve further requests, which is what
    /// `Closed` denotes; no new variant is added, so the public enum stays
    /// exhaustively matchable by existing consumers.
    Closed,
}

// ─── Session ──────────────────────────────────────────────────────────────

/// Application handler for one A2A method: params in, JSON-RPC result or
/// error out. Handlers run in their own tasks so a slow handler never
/// blocks the receive loop.
pub type BindingHandler =
    Arc<dyn Fn(Option<Value>) -> BoxFuture<'static, Result<Value, JsonRpcError>> + Send + Sync>;

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
    /// corrId → the in-flight call authorised to consume that corrId.
    in_flight: DashMap<String, InFlightCall>,
    /// Monotonic per-session source of `InFlightCall::call_token`.
    ///
    /// Starts at 1 so 0 is never a live token, and `next_call_token`
    /// refuses to wrap, so a token is never silently reused while an older
    /// cleanup guard still holds it.
    call_tokens: AtomicU64,
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
            call_tokens: AtomicU64::new(1),
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
    /// Correlation: a fresh `corrId` — an opaque string, emitted here as
    /// `<uuid>-<call-token>` so it cannot collide with a live entry of this
    /// session — is registered in the in-flight map *before* the request DM
    /// is sent, so a fast peer's answer can never be missed. The JSON-RPC
    /// `id` carries the same string and the response must echo it exactly.
    /// On timeout the entry is removed and a late response is skipped by the
    /// receive loop.
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
        let call_token = next_call_token(&self.inner.call_tokens)?;
        // The token is unique for the lifetime of this session, so the
        // correlation id cannot collide with another live entry.
        let corr_id = format!("{}-{call_token}", Uuid::new_v4());
        let request = JsonRpcRequest::new(method, params, Value::String(corr_id.clone()));
        let envelope = BindingEnvelope::new(KIND_REQUEST, corr_id.clone(), &request)?;
        let bytes = encode_envelope(&envelope)?;

        let (tx, rx) = oneshot::channel();
        // Insert BEFORE sending: a fast peer can answer before the send
        // returns, and the receive loop must find the waiter. Insert via a
        // VACANT entry only: overwriting an occupied corrId would silently
        // strand another live call's waiter, so a collision is an error
        // rather than a replacement.
        match self.inner.in_flight.entry(corr_id.clone()) {
            DashEntry::Occupied(_) => {
                // Unreachable: `corr_id` embeds this session's unique
                // `call_token`, so it cannot collide with a live entry.
                // Refuse rather than overwrite another call's waiter.
                warn!(%corr_id, "correlation id already in flight; refusing to overwrite");
                return Err(BindingError::Closed);
            }
            DashEntry::Vacant(slot) => {
                slot.insert(InFlightCall {
                    expected_peer: *peer,
                    expected_jsonrpc_id: Value::String(corr_id.clone()),
                    call_token,
                    waiter: tx,
                });
            }
        }
        // Every exit path other than successful delivery — send failure,
        // timeout, or the caller dropping this future mid-flight — removes
        // the waiter via the guard. After successful delivery the receive
        // loop already consumed the entry, so the removal is a no-op. The
        // guard removes ONLY its own entry (matched on `call_token`), so a
        // late drop cannot erase a newer call that reused this corrId.
        let _cleanup = InFlightCleanup {
            in_flight: &self.inner.in_flight,
            corr_id: corr_id.clone(),
            call_token,
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
    in_flight: &'a DashMap<String, InFlightCall>,
    corr_id: String,
    call_token: u64,
}

impl Drop for InFlightCleanup<'_> {
    fn drop(&mut self) {
        // Token-conditional and atomic: a separate get-then-remove pair
        // could observe our token and then delete a newer call's entry
        // inserted in between. `remove_if` evaluates the predicate under
        // the shard lock, so an entry belonging to a newer call (different
        // token) is left alone.
        self.in_flight
            .remove_if(&self.corr_id, |_, call| call.call_token == self.call_token);
    }
}

/// One registered, not-yet-answered `call`.
///
/// Holds the correlation authority for its corrId: only a response from
/// `expected_peer`, with verified provenance and the exact echoed
/// `expected_jsonrpc_id`, may consume it.
struct InFlightCall {
    /// The peer this request was addressed to. A verified response from
    /// any other agent must not satisfy this call.
    expected_peer: AgentId,
    /// The exact JSON-RPC `id` sent; the response must echo it verbatim.
    expected_jsonrpc_id: Value,
    /// Identifies this call's ownership of the corrId slot.
    call_token: u64,
    waiter: oneshot::Sender<JsonRpcResponse>,
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
            KIND_RESPONSE => inner.handle_response(msg.sender, msg.verified, envelope),
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

    /// Correlate an inbound response to its waiting `call`.
    ///
    /// Every admission condition is evaluated BEFORE the entry is consumed,
    /// so a response that fails any of them leaves the waiter registered and
    /// a later valid response can still satisfy the same call:
    ///
    /// 1. `verified` provenance — a self-asserted `sender` is not enough
    ///    (see [`crate::direct::DirectMessage::sender`]).
    /// 2. the verified sender is the peer this call was addressed to;
    /// 3. literal `"jsonrpc": "2.0"`;
    /// 4. `id` echoes the exact value sent;
    /// 5. exactly one of `result` / `error` is present;
    /// 6. a present `error` decodes to a real [`JsonRpcError`].
    ///
    /// A raw `result` of JSON `null` is a legal success and is preserved as
    /// `Some(Value::Null)`, so the caller's `call` returns `Ok(Value::Null)`
    /// rather than an `InvalidResponse`.
    fn handle_response(&self, sender: AgentId, verified: bool, envelope: BindingEnvelope) {
        // Occupied-entry validation: the shard lock is held across the
        // checks and the removal, and nothing awaits inside, so no other
        // task can consume or replace the entry mid-decision.
        deliver_response(&self.in_flight, sender, verified, &envelope);
    }
}

/// Admit or refuse `envelope` against the in-flight map, and on admission
/// consume the entry and answer its waiter.
///
/// This is THE production correlation operation — [`SessionInner::handle_response`]
/// does nothing else — factored to take `&DashMap` so the whole
/// admit → remove → send sequence is drivable with a real map and a real
/// `oneshot` receiver, with no session, agent, or network.
///
/// Ordering is load-bearing and is what the tests pin: the occupied entry is
/// held (no await) across validation, the entry is removed ONLY after
/// admission, and the response is sent from the removed entry. A refusal
/// therefore leaves the entry occupied and its receiver pending, so a later
/// valid response can still satisfy the same call.
///
/// Returns `true` when a response was admitted and the entry consumed.
fn deliver_response(
    in_flight: &DashMap<String, InFlightCall>,
    sender: AgentId,
    verified: bool,
    envelope: &BindingEnvelope,
) -> bool {
    let DashEntry::Occupied(entry) = in_flight.entry(envelope.corr_id.clone()) else {
        // Late answer to a timed-out request, duplicate, or not ours.
        trace!(
            corr_id = %envelope.corr_id,
            "no in-flight request for A2A response; skipping"
        );
        return false;
    };
    let Some(response) = admit_response(entry.get(), sender, verified, envelope) else {
        // Refused: the entry stays occupied and answerable.
        return false;
    };
    // Admitted: consume the slot atomically, then answer.
    let call = entry.remove();
    // The waiter may have raced a timeout and gone away; that is fine.
    let _ = call.waiter.send(response);
    true
}

/// Reserve the next call token from `counter`, refusing to wrap.
///
/// Uses a checked compare-and-swap, not `fetch_add`: `fetch_add` at
/// `u64::MAX` stores 0 *before* returning, so the following call would be
/// handed token 0 and then 1 — silently reusing tokens a live
/// [`InFlightCleanup`] still owns. On exhaustion the counter is left at
/// `u64::MAX` permanently and every later call fails the same way.
///
/// # Errors
///
/// [`BindingError::Closed`] once the token space is exhausted.
fn next_call_token(counter: &AtomicU64) -> Result<u64, BindingError> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_exhausted| BindingError::Closed)
}

/// Decide whether `envelope` may consume `call`, and build the
/// caller-visible response if so.
///
/// `None` means "reject and leave the waiter registered". Split out of
/// [`SessionInner::handle_response`] so the admission boundary is exercised
/// directly with inert fixtures, with no session, agent, or network.
fn admit_response(
    call: &InFlightCall,
    sender: AgentId,
    verified: bool,
    envelope: &BindingEnvelope,
) -> Option<JsonRpcResponse> {
    {
        if !verified {
            warn!(
                corr_id = %envelope.corr_id,
                "rejecting A2A response with unverified sender; waiter left in place"
            );
            return None;
        }
        if sender != call.expected_peer {
            warn!(
                corr_id = %envelope.corr_id,
                "rejecting A2A response from a peer this call was not addressed to"
            );
            return None;
        }
        if envelope.jsonrpc.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC_2_0) {
            warn!(corr_id = %envelope.corr_id, "rejecting A2A response with wrong jsonrpc version");
            return None;
        }
        if envelope.jsonrpc.get("id") != Some(&call.expected_jsonrpc_id) {
            warn!(corr_id = %envelope.corr_id, "rejecting A2A response with mismatched id");
            return None;
        }

        // Presence is checked on the RAW object: `JsonRpcResponse` cannot
        // distinguish an absent `result` from `"result": null`.
        let raw_result = envelope.jsonrpc.get("result");
        let raw_error = envelope.jsonrpc.get("error");
        let response = match (raw_result, raw_error) {
            (Some(result), None) => {
                JsonRpcResponse::result(result.clone(), call.expected_jsonrpc_id.clone())
            }
            (None, Some(raw)) => {
                // A key named `error` is not an error object. Decode it
                // fully before consuming the waiter; `error: null` and any
                // other malformed shape leave the call answerable.
                let Ok(error) = serde_json::from_value::<JsonRpcError>(raw.clone()) else {
                    warn!(
                        corr_id = %envelope.corr_id,
                        "rejecting A2A response with malformed error object; waiter left in place"
                    );
                    return None;
                };
                JsonRpcResponse::error(error, call.expected_jsonrpc_id.clone())
            }
            _ => {
                warn!(
                    corr_id = %envelope.corr_id,
                    "rejecting A2A response without exactly one of result/error"
                );
                return None;
            }
        };
        Some(response)
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
        let envelope = BindingEnvelope::new(KIND_REQUEST, "corr-1".to_string(), &sample_request())
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
        let envelope = BindingEnvelope::new(KIND_RESPONSE, "corr-9".to_string(), &response)
            .expect("build envelope");
        let decoded =
            decode_envelope(&encode_envelope(&envelope).expect("encode")).expect("decode");
        let parsed: JsonRpcResponse =
            serde_json::from_value(decoded.jsonrpc).expect("parse jsonrpc");
        let error = parsed.error.expect("error object");
        assert_eq!(error.code, JSONRPC_METHOD_NOT_FOUND);
        assert!(parsed.result.is_none());
    }

    #[test]
    fn wire_shape_matches_design_sketch() {
        let envelope = BindingEnvelope::new(KIND_REQUEST, "corr-1".to_string(), &sample_request())
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

    // ---- #112 packet 1: authenticated response correlation ----
    //
    // These exercise the real production seams (`admit_response`, the real
    // `InFlightCall`, and the real `InFlightCleanup` guard over a real
    // `DashMap`) with inert signed-identity fixtures. Nothing here builds an
    // Agent, NetworkNode, PubSub, socket, or daemon.

    fn test_agent_id() -> AgentId {
        crate::identity::AgentKeypair::generate()
            .expect("inert keypair")
            .agent_id()
    }

    fn in_flight(
        peer: AgentId,
        corr_id: &str,
        token: u64,
    ) -> (InFlightCall, oneshot::Receiver<JsonRpcResponse>) {
        let (tx, rx) = oneshot::channel();
        (
            InFlightCall {
                expected_peer: peer,
                expected_jsonrpc_id: Value::String(corr_id.to_string()),
                call_token: token,
                waiter: tx,
            },
            rx,
        )
    }

    fn response_envelope(corr_id: &str, body: Value) -> BindingEnvelope {
        BindingEnvelope {
            binding: X0X_BINDING_VERSION.to_string(),
            corr_id: corr_id.to_string(),
            kind: KIND_RESPONSE.to_string(),
            jsonrpc: body,
        }
    }

    fn register(
        map: &DashMap<String, InFlightCall>,
        peer: AgentId,
        corr_id: &str,
        token: u64,
    ) -> oneshot::Receiver<JsonRpcResponse> {
        let (call, rx) = in_flight(peer, corr_id, token);
        map.insert(corr_id.to_string(), call);
        rx
    }

    /// Why: `fetch_add` at `u64::MAX` stores 0 before returning, so the next
    /// call would be handed token 0 and then 1 — reusing tokens a live
    /// cleanup guard still owns. The allocator must refuse without mutating
    /// the counter, and stay refused.
    #[test]
    fn call_token_allocator_refuses_exhaustion_without_wrapping() {
        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(next_call_token(&counter).expect("last token"), u64::MAX - 1);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        for _ in 0..3 {
            assert!(
                matches!(next_call_token(&counter), Err(BindingError::Closed)),
                "exhausted allocator must keep refusing"
            );
            assert_eq!(
                counter.load(Ordering::Relaxed),
                u64::MAX,
                "a refused allocation must not mutate the counter"
            );
        }
    }

    /// Why (R1 review P2): the central invariant is that a refused response
    /// leaves the ENTRY occupied and its WAITER pending, so a later valid
    /// response still wins. Driven through the real map + real oneshot, so a
    /// production regression that removed the entry before validating, or
    /// stopped sending, fails here.
    #[test]
    fn refused_responses_preserve_the_entry_and_a_later_valid_null_is_delivered() {
        let map: DashMap<String, InFlightCall> = DashMap::new();
        let peer = test_agent_id();
        let other = test_agent_id();
        let mut rx = register(&map, peer, "k1", 1);

        let refusals = [
            (
                other,
                true,
                json!({"jsonrpc": "2.0", "id": "k1", "result": 1}),
            ),
            (
                peer,
                false,
                json!({"jsonrpc": "2.0", "id": "k1", "result": 1}),
            ),
            (
                peer,
                true,
                json!({"jsonrpc": "2.1", "id": "k1", "result": 1}),
            ),
            (
                peer,
                true,
                json!({"jsonrpc": "2.0", "id": "other", "result": 1}),
            ),
            (
                peer,
                true,
                json!({"jsonrpc": "2.0", "id": "k1", "error": null}),
            ),
            (
                peer,
                true,
                json!({"jsonrpc": "2.0", "id": "k1", "error": {"code": 1}}),
            ),
            (peer, true, json!({"jsonrpc": "2.0", "id": "k1"})),
            (
                peer,
                true,
                json!({"jsonrpc": "2.0", "id": "k1", "result": 1, "error": {"code": 1, "message": "m"}}),
            ),
        ];
        for (from, verified, body) in refusals {
            assert!(
                !deliver_response(&map, from, verified, &response_envelope("k1", body.clone())),
                "must refuse {body}"
            );
            assert!(
                map.contains_key("k1"),
                "refusal must leave the entry: {body}"
            );
            assert!(
                matches!(rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
                "refusal must leave the waiter pending: {body}"
            );
        }

        let ok = response_envelope("k1", json!({"jsonrpc": "2.0", "id": "k1", "result": null}));
        assert!(deliver_response(&map, peer, true, &ok));
        assert!(!map.contains_key("k1"), "admission must consume the entry");
        let delivered = rx
            .try_recv()
            .expect("waiter must receive the admitted response");
        assert_eq!(delivered.result, Some(Value::Null));
        assert_eq!(response_into_result(delivered).expect("ok"), Value::Null);

        // Duplicate: the slot is gone, so nothing else can be completed.
        assert!(!deliver_response(&map, peer, true, &ok));
    }

    /// Why: an admitted error must reach the real waiter as `Remote`, and a
    /// response for a corrId this session never registered must not complete
    /// some other call.
    #[test]
    fn admitted_error_reaches_the_waiter_and_unknown_corr_id_completes_nothing() {
        let map: DashMap<String, InFlightCall> = DashMap::new();
        let peer = test_agent_id();
        let mut rx = register(&map, peer, "k2", 7);
        let stray = response_envelope("nope", json!({"jsonrpc": "2.0", "id": "nope", "result": 1}));
        assert!(!deliver_response(&map, peer, true, &stray));
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        let err = response_envelope(
            "k2",
            json!({"jsonrpc": "2.0", "id": "k2", "error": {"code": -32601, "message": "nope"}}),
        );
        assert!(deliver_response(&map, peer, true, &err));
        let delivered = rx.try_recv().expect("waiter must receive the error");
        assert!(matches!(
            response_into_result(delivered),
            Err(BindingError::Remote { code, .. }) if code == -32601
        ));
        assert!(!map.contains_key("k2"));
    }

    /// Why: a JSON-RPC `result` of `null` is a legal success. The raw
    /// presence check must preserve it as `Some(Value::Null)` so the public
    /// `call` returns `Ok(Value::Null)` — decoding into `JsonRpcResponse`
    /// alone collapses it to `None` and would report `InvalidResponse`.
    #[test]
    fn null_result_reaches_the_caller_as_ok_null() {
        let peer = test_agent_id();
        let (call, _rx) = in_flight(peer, "c1", 1);
        let env = response_envelope("c1", json!({"jsonrpc": "2.0", "id": "c1", "result": null}));
        let response = admit_response(&call, peer, true, &env).expect("null result is admissible");
        assert_eq!(response.result, Some(Value::Null));
        assert_eq!(response_into_result(response).expect("ok"), Value::Null);
    }

    /// Why: an `error` key is not an error object. Malformed shapes must be
    /// rejected BEFORE the waiter is consumed, so the call stays answerable
    /// and a later valid response still wins.
    #[test]
    fn malformed_errors_leave_the_call_answerable_then_a_valid_one_wins() {
        let peer = test_agent_id();
        let (call, _rx) = in_flight(peer, "c2", 1);
        for bad in [
            json!({"jsonrpc": "2.0", "id": "c2", "error": null}),
            json!({"jsonrpc": "2.0", "id": "c2", "error": "boom"}),
            json!({"jsonrpc": "2.0", "id": "c2", "error": {"message": "no code"}}),
            json!({"jsonrpc": "2.0", "id": "c2", "error": {"code": 1}}),
            json!({"jsonrpc": "2.0", "id": "c2", "error": {"code": "x", "message": "m"}}),
            json!({"jsonrpc": "2.0", "id": "c2", "result": 1, "error": {"code": 1, "message": "m"}}),
            json!({"jsonrpc": "2.0", "id": "c2"}),
        ] {
            assert!(
                admit_response(&call, peer, true, &response_envelope("c2", bad.clone())).is_none(),
                "malformed response must not consume the waiter: {bad}"
            );
        }
        let good = response_envelope(
            "c2",
            json!({"jsonrpc": "2.0", "id": "c2", "error": {"code": -32601, "message": "nope"}}),
        );
        let response = admit_response(&call, peer, true, &good).expect("valid error admitted");
        assert!(matches!(
            response_into_result(response),
            Err(BindingError::Remote { code, .. }) if code == -32601
        ));
    }

    /// Why: correlation authority is the peer the request was addressed to.
    /// A verified response from a different agent must not satisfy the call.
    #[test]
    fn verified_wrong_peer_is_refused_and_expected_peer_is_admitted() {
        let expected = test_agent_id();
        let other = test_agent_id();
        assert_ne!(expected, other);
        let (call, _rx) = in_flight(expected, "c3", 1);
        let env = response_envelope("c3", json!({"jsonrpc": "2.0", "id": "c3", "result": 7}));
        assert!(admit_response(&call, other, true, &env).is_none());
        assert!(admit_response(&call, expected, true, &env).is_some());
    }

    /// Why: `DirectMessage::sender` is self-asserted. Verified provenance is
    /// required, so a claimed-but-unverified expected peer is refused.
    #[test]
    fn unverified_claimed_sender_is_refused() {
        let peer = test_agent_id();
        let (call, _rx) = in_flight(peer, "c4", 1);
        let env = response_envelope("c4", json!({"jsonrpc": "2.0", "id": "c4", "result": 7}));
        assert!(admit_response(&call, peer, false, &env).is_none());
        assert!(admit_response(&call, peer, true, &env).is_some());
    }

    /// Why: literal `"2.0"` and the exact echoed id are the remaining
    /// correlation invariants; near-misses must not be admitted.
    #[test]
    fn version_and_id_must_match_exactly() {
        let peer = test_agent_id();
        let (call, _rx) = in_flight(peer, "c5", 1);
        for bad in [
            json!({"jsonrpc": "2.1", "id": "c5", "result": 1}),
            json!({"jsonrpc": 2.0, "id": "c5", "result": 1}),
            json!({"id": "c5", "result": 1}),
            json!({"jsonrpc": "2.0", "id": "c5 ", "result": 1}),
            json!({"jsonrpc": "2.0", "id": 5, "result": 1}),
            json!({"jsonrpc": "2.0", "result": 1}),
        ] {
            assert!(
                admit_response(&call, peer, true, &response_envelope("c5", bad.clone())).is_none(),
                "must reject {bad}"
            );
        }
    }

    /// Why: an authenticated inbox/loopback delivery is the positive case
    /// the whole gate exists to let through, for both result and error.
    #[test]
    fn authenticated_delivery_positives_are_admitted() {
        let peer = test_agent_id();
        let (call, _rx) = in_flight(peer, "c6", 1);
        let ok = response_envelope(
            "c6",
            json!({"jsonrpc": "2.0", "id": "c6", "result": {"a": 1}}),
        );
        assert_eq!(
            response_into_result(admit_response(&call, peer, true, &ok).expect("result admitted"))
                .expect("ok"),
            json!({"a": 1})
        );
        let err = response_envelope(
            "c6",
            json!({"jsonrpc": "2.0", "id": "c6", "error": {"code": -32603, "message": "boom"}}),
        );
        assert!(matches!(
            response_into_result(admit_response(&call, peer, true, &err).expect("error admitted")),
            Err(BindingError::Remote { code, .. }) if code == -32603
        ));
    }

    /// Why: the reply removes corrId X, then a (forced) id reuse inserts a
    /// NEW call at X before the old call's cleanup guard drops. The old
    /// guard must not erase the new entry.
    #[test]
    fn old_cleanup_drop_cannot_erase_a_reused_corr_id() {
        let map: DashMap<String, InFlightCall> = DashMap::new();
        let peer = test_agent_id();
        let (first, _rx1) = in_flight(peer, "reused", 1);
        map.insert("reused".to_string(), first);
        let old_guard = InFlightCleanup {
            in_flight: &map,
            corr_id: "reused".to_string(),
            call_token: 1,
        };
        // The response consumed the first call's entry.
        assert!(map.remove("reused").is_some());
        // A forced id reuse registers a NEW call in the same slot.
        let (second, _rx2) = in_flight(peer, "reused", 2);
        map.insert("reused".to_string(), second);
        // The first call's guard now drops.
        drop(old_guard);
        let survivor = map.get("reused").expect("newer call must survive");
        assert_eq!(survivor.call_token, 2);
    }

    /// Why: the guard must still clean up its OWN entry, or cancelled and
    /// timed-out calls leak waiters.
    #[test]
    fn cleanup_drop_removes_its_own_entry() {
        let map: DashMap<String, InFlightCall> = DashMap::new();
        let peer = test_agent_id();
        let (call, _rx) = in_flight(peer, "mine", 9);
        map.insert("mine".to_string(), call);
        drop(InFlightCleanup {
            in_flight: &map,
            corr_id: "mine".to_string(),
            call_token: 9,
        });
        assert!(map.get("mine").is_none());
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
