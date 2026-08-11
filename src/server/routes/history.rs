//! Route handlers (`category: "history"` in `src/api/mod.rs`).
//!
//! ADR-0023 durable-history read surface: scoped listing, FTS search,
//! stats, local purge, and writer/reaper diagnostics. All reads go through
//! `spawn_blocking` — the store is synchronous SQLite and must never run on
//! the async executor threads.

use super::super::api_error;
use super::super::state::AppState;
use crate as x0x;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::sync::Arc;
use x0x::history::{HistoryQuery, Scope, StoredRecord};

/// Query parameters shared by `GET /history` and `GET /history/search`.
#[derive(Debug, serde::Deserialize)]
pub(in crate::server) struct HistoryListParams {
    /// Canonical scope string: `dm:<agent_hex>` | `group:<stable_id>` |
    /// `topic:<name>`.
    scope: String,
    /// Inclusive lower bound on `seen_at_ms`.
    since_ms: Option<i64>,
    /// Inclusive upper bound on `seen_at_ms`.
    until_ms: Option<i64>,
    /// Max rows (server clamps; 0 ⇒ default).
    limit: Option<usize>,
    /// Keyset cursor: rows strictly older than this rowid.
    before_id: Option<i64>,
    /// FTS needle — required for `/history/search`, ignored by `/history`.
    q: Option<String>,
}

fn parse_scope(s: &str) -> Result<Scope, String> {
    Scope::parse(s).map_err(|e| format!("invalid scope {s:?}: {e}"))
}

fn query_from(params: &HistoryListParams, scope: Scope) -> HistoryQuery {
    HistoryQuery {
        scope: Some(scope),
        scope_kind: None,
        since_ms: params.since_ms,
        until_ms: params.until_ms,
        limit: params.limit.unwrap_or(0),
        before_id: params.before_id,
    }
}

/// Serialize one stored row for the REST surface. The signed artifact is
/// omitted from list responses (it can be multi-KB per row); `signed`
/// indicates whether one exists for offline re-verification.
fn row_json(row: &StoredRecord) -> serde_json::Value {
    let r = &row.record;
    let group_message = group_history_message(r);
    let msg_id = group_message
        .as_ref()
        .map(x0x::groups::GroupPublicMessage::msg_id)
        .unwrap_or_else(|| hex::encode(r.msg_id));
    let thread_root = group_message
        .as_ref()
        .and_then(|message| message.thread_root.as_deref())
        .or(r.thread_root.as_deref());
    let thread_parent = group_message
        .as_ref()
        .and_then(|message| message.thread_parent.as_deref())
        .or(r.thread_parent.as_deref());
    serde_json::json!({
        "id": row.id,
        "msg_id": msg_id,
        "scope": r.scope.canonical(),
        "author_agent": r.author_agent,
        "author_machine": r.author_machine,
        "sent_at_ms": r.sent_at_ms,
        "seen_at_ms": r.seen_at_ms,
        "direction": r.direction,
        "content_type": r.content_type,
        "payload": BASE64.encode(&r.payload),
        "signed": r.signature.is_some(),
        "provenance": r.provenance,
        "replace_key": r.replace_key,
        "thread_root": thread_root,
        "thread_parent": thread_parent,
    })
}

/// Recover the rendering identity and ADR-0029 ancestry from the verified
/// group-public artifact. The history store's `msg_id` remains its dedupe key
/// (`BLAKE3(signed_artifact)`), while the desktop contract uses the message's
/// canonical signing-domain id (`GroupPublicMessage::msg_id()`).
fn group_history_message(
    record: &x0x::history::HistoryRecord,
) -> Option<x0x::groups::GroupPublicMessage> {
    let Scope::Group(scope_group_id) = &record.scope else {
        return None;
    };
    let artifact = record.signed_artifact.as_deref()?;
    let message = serde_json::from_slice::<x0x::groups::GroupPublicMessage>(artifact).ok()?;
    if message.group_id != *scope_group_id || message.body.as_bytes() != record.payload {
        return None;
    }
    Some(message)
}

/// GET /history — scoped durable-history listing (newest first, keyset
/// paginated via `before_id`).
pub(in crate::server) async fn history_list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HistoryListParams>,
) -> impl IntoResponse {
    let Some(history) = state.agent.history() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "history store disabled");
    };
    let scope = match parse_scope(&params.scope) {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, e),
    };
    let store = Arc::clone(history.store());
    let q = query_from(&params, scope);
    match tokio::task::spawn_blocking(move || store.query(&q)).await {
        Ok(Ok(rows)) => {
            let next_before_id = rows.last().map(|r| r.id);
            let items: Vec<_> = rows.iter().map(row_json).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "count": items.len(),
                    "next_before_id": next_before_id,
                    "records": items,
                })),
            )
        }
        Ok(Err(e)) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("query: {e}")),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
    }
}

/// GET /history/search — FTS5 search over text payloads within a scope.
pub(in crate::server) async fn history_search(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HistoryListParams>,
) -> impl IntoResponse {
    let Some(history) = state.agent.history() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "history store disabled");
    };
    let Some(needle) = params.q.clone().filter(|s| !s.trim().is_empty()) else {
        return api_error(StatusCode::BAD_REQUEST, "missing search parameter q");
    };
    let scope = match parse_scope(&params.scope) {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, e),
    };
    let store = Arc::clone(history.store());
    let q = query_from(&params, scope);
    match tokio::task::spawn_blocking(move || store.search(&needle, &q)).await {
        Ok(Ok(rows)) => {
            let items: Vec<_> = rows.iter().map(row_json).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "count": items.len(), "records": items })),
            )
        }
        Ok(Err(e)) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("search: {e}")),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
    }
}

/// GET /history/stats — row counts, database size, and retention config.
pub(in crate::server) async fn history_stats(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let Some(history) = state.agent.history() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "history store disabled");
    };
    let store = Arc::clone(history.store());
    match tokio::task::spawn_blocking(move || store.stats()).await {
        Ok(Ok(stats)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "stats": stats,
                "retention": {
                    "max_bytes": state.history_config.max_bytes,
                    "max_age_days": state.history_config.max_age_days,
                    "scope_limits": state.history_config.scope_limits,
                },
            })),
        ),
        Ok(Err(e)) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("stats: {e}")),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
    }
}

/// Query parameters for `DELETE /history`.
#[derive(Debug, serde::Deserialize)]
pub(in crate::server) struct HistoryPurgeParams {
    /// Scope to purge — required; there is no purge-everything shortcut.
    scope: String,
}

/// DELETE /history — purge one scope from the local store. Local-only:
/// nothing is propagated to the network (ADR-0023 non-goal).
pub(in crate::server) async fn history_purge(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HistoryPurgeParams>,
) -> impl IntoResponse {
    let Some(history) = state.agent.history() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "history store disabled");
    };
    let scope = match parse_scope(&params.scope) {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, e),
    };
    let store = Arc::clone(history.store());
    match tokio::task::spawn_blocking(move || store.purge(&scope)).await {
        Ok(Ok(removed)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "removed": removed })),
        ),
        Ok(Err(e)) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("purge: {e}")),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
    }
}

/// GET /diagnostics/history — writer/reaper counters (one-per-subsystem
/// diagnostics convention, like `/diagnostics/dm`).
pub(in crate::server) async fn history_diagnostics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    use std::sync::atomic::Ordering;
    let Some(history) = state.agent.history() else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "enabled": false })),
        );
    };
    let c = history.counters();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "enabled": true,
            "written_total": c.written_total.load(Ordering::Relaxed),
            "dropped_full": c.dropped_full.load(Ordering::Relaxed),
            "dedup_hits": c.dedup_hits.load(Ordering::Relaxed),
            "write_errors": c.write_errors.load(Ordering::Relaxed),
            "abandoned_at_shutdown": c.abandoned_at_shutdown.load(Ordering::Relaxed),
            "reaper_evicted_total": c.reaper_evicted_total.load(Ordering::Relaxed),
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use x0x::groups::{GroupPublicMessage, GroupPublicMessageKind};
    use x0x::history::{Direction, HistoryRecord, Provenance};

    #[test]
    fn group_history_json_uses_canonical_message_id_and_thread_ancestry() {
        let root = "a".repeat(64);
        let message = GroupPublicMessage {
            group_id: "group-1".to_string(),
            state_hash_at_send: "state-1".to_string(),
            revision_at_send: 1,
            author_agent_id: "author-1".to_string(),
            author_public_key: "public-key-1".to_string(),
            author_user_id: None,
            kind: GroupPublicMessageKind::Chat,
            body: "thread reply".to_string(),
            timestamp: 42,
            thread_root: Some(root.clone()),
            thread_parent: Some(root.clone()),
            signature: "signature-1".to_string(),
        };
        let artifact = serde_json::to_vec(&message).expect("serialize message");
        let payload = message.body.as_bytes().to_vec();
        let stored = StoredRecord {
            id: 7,
            record: HistoryRecord {
                msg_id: HistoryRecord::compute_msg_id(Some(&artifact), &payload),
                scope: Scope::Group(message.group_id.clone()),
                author_agent: Some(message.author_agent_id.clone()),
                author_machine: None,
                author_pubkey: None,
                sent_at_ms: 42,
                seen_at_ms: 43,
                direction: Direction::Inbound,
                content_type: "text/plain".to_string(),
                payload,
                signed_artifact: Some(artifact),
                signature: Some(vec![1]),
                sig_context: Some("x0x.group.public-message.v2".to_string()),
                provenance: Provenance::VerifiedEnvelope,
                replace_key: None,
                thread_root: None,
                thread_parent: None,
            },
        };

        let json = row_json(&stored);
        assert_eq!(json["msg_id"], message.msg_id());
        assert_eq!(json["thread_root"], root);
        assert_eq!(json["thread_parent"], root);
    }
}
