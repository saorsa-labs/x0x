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
    serde_json::json!({
        "id": row.id,
        "msg_id": hex::encode(r.msg_id),
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
    })
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
