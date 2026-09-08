//! Route handlers (`category: "history"` in `src/api/mod.rs`).
//!
//! ADR-0023 durable-history read surface: scoped listing, FTS search,
//! stats, local purge, and writer/reaper diagnostics. All reads go through
//! `spawn_blocking` — the store is synchronous SQLite and must never run on
//! the async executor threads.

use super::super::api_error;
use super::super::state::AppState;
use crate as x0x;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::sync::Arc;
use x0x::history::{HistoryQuery, Scope, ScopeSummary, Store, StoredRecord};

/// Query parameters shared by `GET /history` and `GET /history/search`.
#[derive(Debug, serde::Deserialize)]
pub(in crate::server) struct HistoryListParams {
    /// Canonical scope string: `dm:<agent_hex>` | `group:<stable_id>` |
    /// `topic:<name>`.
    ///
    /// **Required by `GET /history`** (the handler 400s without it, and the
    /// ADR-0039 rider grant is expressed per scope, so a scope-less list can
    /// never be authorized). **Optional on `GET /history/search`** (issue
    /// #275): omitting it searches the owner's whole retained local history
    /// across scopes. A supplied-but-malformed scope is still a 400 on both.
    scope: Option<String>,
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

fn query_from(params: &HistoryListParams, scope: Option<Scope>) -> HistoryQuery {
    HistoryQuery {
        scope,
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
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Query(params): Query<HistoryListParams>,
) -> impl IntoResponse {
    let Some(history) = state.agent.history() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "history store disabled");
    };
    // `scope` stays REQUIRED here (issue #275 relaxed it only for
    // `/history/search`): the ADR-0039 rider grant is expressed per group
    // scope, so a scope-less listing has nothing to authorize against.
    let Some(requested_scope) = params.scope.as_deref() else {
        return api_error(StatusCode::BAD_REQUEST, "missing required parameter scope");
    };
    let scope = match parse_scope(requested_scope) {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, e),
    };
    // ADR-0039 bounded rider read: a rider may list only `group:` scopes
    // EXPLICITLY granted to its token (review r4: no implicit Home —
    // Home is delegated like any other group), and never more than
    // RIDER_HISTORY_MAX_LIMIT rows per request. The route itself is the
    // only history surface the deny-by-default predicate lets riders
    // reach — search/stats/message lookups stay owner-only.
    let mut params = params;
    if let crate::server::rider_auth::ActorContext::Rider { groups, .. } = &actor {
        let allowed = match &scope {
            x0x::history::Scope::Group(gid) => groups.contains(gid),
            _ => false,
        };
        if !allowed {
            return api_error(
                StatusCode::FORBIDDEN,
                "rider tokens may only read history scopes they are granted (ADR-0039)",
            );
        }
        params.limit = Some(
            params
                .limit
                .unwrap_or(crate::server::rider_auth::RIDER_HISTORY_MAX_LIMIT)
                .min(crate::server::rider_auth::RIDER_HISTORY_MAX_LIMIT),
        );
    }
    let store = Arc::clone(history.store());
    let q = query_from(&params, Some(scope));
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

/// Optional query for `GET /history/message/:msg_id`.
#[derive(Debug, serde::Deserialize)]
pub(in crate::server) struct HistoryMessageParams {
    /// Scope hint (`group:<stable_id>` | `dm:<agent_hex>` | `topic:<name>`).
    /// Required to resolve a *canonical* group-message id (ADR 0029): the
    /// store's `msg_id` column is the dedupe key `BLAKE3(signed_artifact)`,
    /// not the canonical signing-domain id, so group canonical ids are found
    /// by a bounded newest-first scan of the scope's rows.
    scope: Option<String>,
}

/// Newest-first rows scanned per request when resolving a canonical group id
/// within a scope. Callers holding older ids should use `GET /history` paging.
const HISTORY_MESSAGE_SCAN_BUDGET: usize = 4096;
const HISTORY_MESSAGE_SCAN_PAGE: usize = 256;

/// GET /history/message/:msg_id — point lookup of one durable row (issue
/// #319, ADR-0023 completeness). Accepts either the store dedupe id (DM and
/// topic rows expose exactly that id) or a canonical ADR-0029 group-message
/// id when `?scope=group:<stable_id>` is supplied. 400 on malformed id, 404
/// when absent; the record uses the same JSON shape as `/history`.
pub(in crate::server) async fn history_message(
    State(state): State<Arc<AppState>>,
    Path(msg_id_hex): Path<String>,
    Query(params): Query<HistoryMessageParams>,
) -> impl IntoResponse {
    let Some(history) = state.agent.history() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "history store disabled");
    };
    let requested_hex = msg_id_hex.trim().to_ascii_lowercase();
    let msg_id: [u8; 32] = match hex::decode(&requested_hex) {
        Ok(bytes) => match bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "msg_id must be 64 hex characters (32 bytes)",
                )
            }
        },
        Err(_) => return api_error(StatusCode::BAD_REQUEST, "msg_id must be lowercase hex"),
    };
    let scope = match params.scope.as_deref().map(parse_scope).transpose() {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, e),
    };

    let store = Arc::clone(history.store());
    let lookup = tokio::task::spawn_blocking(move || {
        resolve_history_message(&store, msg_id, &requested_hex, scope)
    })
    .await;

    match lookup {
        Ok(Ok(Some(row))) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "record": row_json(&row) })),
        ),
        Ok(Ok(None)) => api_error(
            StatusCode::NOT_FOUND,
            "no history row for msg_id (canonical group ids require ?scope=group:<stable_id>; \
             scan budget covers the newest 4096 rows of the scope)",
        ),
        Ok(Err(e)) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("lookup: {e}")),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
    }
}

/// Resolve the point-lookup contract in the same order as the HTTP handler:
/// internal dedupe id, indexed canonical group id, then the bounded legacy
/// scan for rows written before the derived projection existed.
fn resolve_history_message(
    store: &Store,
    msg_id: [u8; 32],
    requested_hex: &str,
    scope: Option<Scope>,
) -> Result<Option<StoredRecord>, String> {
    // Fast path: the store dedupe key. DM/topic rows expose exactly this id
    // via row_json, and pre-ADR-0029 callers hold it directly.
    if let Some(row) = store.get_by_msg_id(msg_id).map_err(|e| e.to_string())? {
        return Ok(Some(row));
    }
    // Canonical group-message ids differ from the dedupe key and are
    // maintained in a derived indexed projection. Legacy rows that predate
    // that projection still fall through to the bounded scan.
    let Some(scope) = scope else {
        return Ok(None);
    };
    if let Scope::Group(group_id) = &scope {
        if let Some(row) = store
            .get_by_canonical_group_msg_id(msg_id, group_id)
            .map_err(|e| e.to_string())?
        {
            return Ok(Some(row));
        }
    }
    let mut before_id: Option<i64> = None;
    let mut scanned = 0usize;
    while scanned < HISTORY_MESSAGE_SCAN_BUDGET {
        let q = HistoryQuery {
            scope: Some(scope.clone()),
            scope_kind: None,
            since_ms: None,
            until_ms: None,
            limit: HISTORY_MESSAGE_SCAN_PAGE,
            before_id,
        };
        let rows = store.query(&q).map_err(|e| e.to_string())?;
        if rows.is_empty() {
            return Ok(None);
        }
        scanned += rows.len();
        before_id = rows.last().map(|r| r.id);
        for row in rows {
            let canonical = group_history_message(&row.record)
                .map(|m| m.msg_id())
                .unwrap_or_else(|| hex::encode(row.record.msg_id));
            if canonical == requested_hex {
                return Ok(Some(row));
            }
        }
    }
    Ok(None)
}

/// GET /history/search — FTS5 search over text payloads.
///
/// `scope` is OPTIONAL (issue #275): omitted, the search runs across every
/// scope in the owner's retained local history; supplied, it narrows to that
/// one scope exactly as before. A malformed `scope` is still a 400, and an
/// absent or blank `q` is still a 400 — omitting `scope` widens the search,
/// it never relaxes validation.
///
/// Owner-only: `/history/search` is not in the ADR-0039 rider allowlist, so
/// the auth middleware 403s a rider token before this handler runs. That is
/// what keeps the cross-scope form from leaking counts or rows outside a
/// rider's granted groups.
///
/// Paginates on the same newest-rowid-first keyset as `GET /history`:
/// `before_id` in, `next_before_id` out.
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
    let scope = match params.scope.as_deref().map(parse_scope).transpose() {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, e),
    };
    let store = Arc::clone(history.store());
    let q = query_from(&params, scope);
    match tokio::task::spawn_blocking(move || store.search(&needle, &q)).await {
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
        Ok(Err(e)) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("search: {e}")),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
    }
}

/// Query parameters for `GET /history/scopes`.
#[derive(Debug, serde::Deserialize)]
pub(in crate::server) struct HistoryScopesParams {
    /// Keyset cursor: the canonical scope string of the last row of the
    /// previous page. Enumeration resumes strictly after its
    /// `(scope_kind, scope_id)` tuple. Malformed ⇒ 400.
    after_scope: Option<String>,
    /// Max scopes (server clamps to [`x0x::history::MAX_QUERY_LIMIT`];
    /// omitted or 0 ⇒ the history default of 100).
    limit: Option<usize>,
}

/// Serialize one scope-enumeration row.
fn scope_json(summary: &ScopeSummary) -> serde_json::Value {
    serde_json::json!({
        "scope": summary.scope.canonical(),
        "scope_kind": summary.scope.kind(),
        "scope_id": summary.scope.id(),
        "rows": summary.rows,
        "newest_seen_at_ms": summary.newest_seen_at_ms,
    })
}

/// GET /history/scopes — enumerate the scopes that still hold retained rows
/// (issue #275 discovery), ascending by `(scope_kind, scope_id)`.
///
/// Answers "what can I query?" without the caller already knowing a scope
/// string. Each row carries the canonical scope, its stored
/// `scope_kind`/`scope_id` columns, its retained row count, and the newest
/// `seen_at_ms` in it. Counts are of LOCALLY RETAINED rows only — retention
/// and `DELETE /history` shrink them, and a scope whose last row is gone
/// disappears entirely. This is not a claim about network completeness.
///
/// Paging uses the `(scope_kind, scope_id)` keyset (`after_scope`), never an
/// offset and never a timestamp, so it is stable under concurrent writes;
/// it is live, not a snapshot.
///
/// Owner-only: not in the ADR-0039 rider allowlist, so the middleware 403s
/// rider tokens before this handler runs — a rider cannot learn that scopes
/// outside its grants exist, nor their counts.
pub(in crate::server) async fn history_scopes(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HistoryScopesParams>,
) -> impl IntoResponse {
    let Some(history) = state.agent.history() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "history store disabled");
    };
    let after = match params.after_scope.as_deref().map(parse_scope).transpose() {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, e),
    };
    let limit = params.limit.unwrap_or(0);
    let store = Arc::clone(history.store());
    match tokio::task::spawn_blocking(move || store.scopes(after.as_ref(), limit)).await {
        Ok(Ok(summaries)) => {
            let next_after_scope = summaries.last().map(|s| s.scope.canonical());
            let items: Vec<_> = summaries.iter().map(scope_json).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "count": items.len(),
                    "next_after_scope": next_after_scope,
                    "scopes": items,
                })),
            )
        }
        Ok(Err(e)) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("scopes: {e}")),
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
    use x0x::history::{Direction, HistoryRecord, Provenance, Store};

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
            mentions: Vec::new(),
            delegation_digest: None,
            rider_provenance: None,
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
                ingress_sender_agent: None,
                logical_request_id: None,
            },
        };

        let json = row_json(&stored);
        assert_eq!(json["msg_id"], message.msg_id());
        assert_eq!(json["thread_root"], root);
        assert_eq!(json["thread_parent"], root);
    }

    #[test]
    fn canonical_resolver_uses_index_past_legacy_scan_budget() {
        let dir = tempfile::tempdir().expect("temporary history directory");
        let store = Store::open(&dir.path().join("history.db")).expect("open history store");
        let message = GroupPublicMessage {
            group_id: "resolver-group".to_string(),
            state_hash_at_send: "state-1".to_string(),
            revision_at_send: 1,
            author_agent_id: "author-1".to_string(),
            author_public_key: "public-key-1".to_string(),
            author_user_id: None,
            kind: GroupPublicMessageKind::Chat,
            body: "old canonical payload".to_string(),
            timestamp: 1,
            thread_root: None,
            thread_parent: None,
            mentions: Vec::new(),
            delegation_digest: None,
            rider_provenance: None,
            signature: "signature-1".to_string(),
        };
        let artifact = serde_json::to_vec(&message).expect("serialize group artifact");
        let payload = message.body.as_bytes().to_vec();
        let target = HistoryRecord {
            msg_id: HistoryRecord::compute_msg_id(Some(&artifact), &payload),
            scope: Scope::Group(message.group_id.clone()),
            author_agent: Some(message.author_agent_id.clone()),
            author_machine: None,
            author_pubkey: None,
            sent_at_ms: 1,
            seen_at_ms: 1,
            direction: Direction::Outbound,
            content_type: "text/plain".to_string(),
            payload,
            signed_artifact: Some(artifact),
            signature: Some(vec![1]),
            sig_context: Some("x0x.group.public-message.v1".to_string()),
            provenance: Provenance::VerifiedEnvelope,
            replace_key: None,
            thread_root: None,
            thread_parent: None,
            ingress_sender_agent: None,
            logical_request_id: None,
        };
        store.insert(&target).expect("insert canonical target");

        let mut local_message = message.clone();
        local_message.body = "old local canonical payload".to_string();
        local_message.timestamp = 2;
        local_message.revision_at_send = 2;
        local_message.signature = "signature-local".to_string();
        let local_artifact =
            serde_json::to_vec(&local_message).expect("serialize local group artifact");
        let local_payload = local_message.body.as_bytes().to_vec();
        let local_target = HistoryRecord {
            msg_id: HistoryRecord::compute_msg_id(Some(&local_artifact), &local_payload),
            scope: Scope::Group(local_message.group_id.clone()),
            author_agent: Some(local_message.author_agent_id.clone()),
            author_machine: None,
            author_pubkey: None,
            sent_at_ms: 2,
            seen_at_ms: 2,
            direction: Direction::Outbound,
            content_type: "text/plain".to_string(),
            payload: local_payload,
            signed_artifact: Some(local_artifact),
            signature: Some(vec![2]),
            sig_context: Some("x0x.group.public-message.v1".to_string()),
            provenance: Provenance::LocalSend,
            replace_key: None,
            thread_root: None,
            thread_parent: None,
            ingress_sender_agent: None,
            logical_request_id: None,
        };
        store
            .insert(&local_target)
            .expect("insert local canonical target");

        let newer: Vec<HistoryRecord> = (0..4_100_u64)
            .map(|n| {
                let payload = format!("newer resolver row {n}").into_bytes();
                HistoryRecord {
                    msg_id: HistoryRecord::compute_msg_id(None, &payload),
                    scope: Scope::Group("resolver-group".to_string()),
                    author_agent: Some("author-1".to_string()),
                    author_machine: None,
                    author_pubkey: None,
                    sent_at_ms: n as i64 + 2,
                    seen_at_ms: n as i64 + 2,
                    direction: Direction::Inbound,
                    content_type: "text/plain".to_string(),
                    payload,
                    signed_artifact: None,
                    signature: None,
                    sig_context: None,
                    provenance: Provenance::VerifiedEnvelope,
                    replace_key: None,
                    thread_root: None,
                    thread_parent: None,
                    ingress_sender_agent: None,
                    logical_request_id: None,
                }
            })
            .collect();
        assert_eq!(
            store.insert_batch(&newer).expect("insert newer rows").0,
            newer.len() as u64
        );

        let canonical = message.msg_id();
        let canonical_bytes: [u8; 32] = hex::decode(&canonical)
            .expect("canonical hex")
            .try_into()
            .expect("canonical length");
        let resolved = resolve_history_message(
            &store,
            canonical_bytes,
            &canonical,
            Some(Scope::Group("resolver-group".to_string())),
        )
        .expect("resolve canonical id")
        .expect("canonical target");
        assert_eq!(resolved.record.msg_id, target.msg_id);
        assert_eq!(resolved.record.provenance, Provenance::VerifiedEnvelope);

        let local_canonical = local_message.msg_id();
        let local_canonical_bytes: [u8; 32] = hex::decode(&local_canonical)
            .expect("local canonical hex")
            .try_into()
            .expect("local canonical length");
        let local_resolved = resolve_history_message(
            &store,
            local_canonical_bytes,
            &local_canonical,
            Some(Scope::Group("resolver-group".to_string())),
        )
        .expect("resolve local canonical id")
        .expect("local canonical target");
        assert_eq!(local_resolved.record.msg_id, local_target.msg_id);
        assert_eq!(local_resolved.record.provenance, Provenance::LocalSend);
    }
}

#[cfg(test)]
mod discovery_auth_tests {
    //! Issue #275 read surface, driven through the REAL `auth_middleware`
    //! and the REAL handlers on an in-process router — no sockets, no
    //! daemon, no test-only auth shim.
    //!
    //! ADR-0039 is accepted and unchanged: `rider_route_allowed` admits
    //! GET `/history` and nothing else under `/history`. The tests below
    //! assert the consequence at the REQUEST layer rather than by
    //! re-reading the predicate, because the predicate agreeing with itself
    //! would not prove the middleware is in the path for these new routes.

    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use axum::routing::get;
    use tower::ServiceExt;
    use x0x::history::{Direction, HistoryConfig, HistoryRecord, Provenance};

    /// The fixture's durable API token (`secure_endpoint_test_state_at`
    /// hard-codes `"test-token"`).
    const DURABLE: &str = "test-token";
    const GRANTED_GROUP: &str = "granted-group";

    /// Owned state whose agent has a real, isolated history store.
    async fn history_state(dir: &std::path::Path) -> anyhow::Result<Arc<AppState>> {
        let identity_dir = dir.join("identity");
        tokio::fs::create_dir_all(&identity_dir).await?;
        let agent = Arc::new(
            x0x::Agent::builder()
                .with_identity_dir(&identity_dir)
                .with_machine_key(identity_dir.join("machine.key"))
                .with_agent_key_path(identity_dir.join("agent.key"))
                .with_agent_cert_path(identity_dir.join("agent.cert"))
                .with_user_key(x0x::identity::UserKeypair::generate()?)
                .with_contact_store_path(dir.join("contacts.json"))
                .with_history(HistoryConfig {
                    db_path: Some(dir.join("history.db")),
                    ..HistoryConfig::daemon_default()
                })
                .build()
                .await?,
        );
        super::super::named_groups::tests::secure_endpoint_test_state_at(dir, agent).await
    }

    /// The history routes exactly as `server::mod` wires them, behind the
    /// production auth middleware.
    fn history_router(state: Arc<AppState>) -> axum::Router {
        axum::Router::new()
            .route("/history", get(history_list))
            .route("/history/scopes", get(history_scopes))
            .route("/history/search", get(history_search))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::server::auth::auth_middleware,
            ))
            .with_state(state)
    }

    async fn get_as(
        app: &axum::Router,
        path: &str,
        bearer: &str,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("authorization", format!("Bearer {bearer}"))
            .body(axum::body::Body::empty())
            .expect("request builds");
        let resp = app.clone().oneshot(req).await.expect("router answers");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body reads");
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    /// A rider token granted exactly `GRANTED_GROUP`.
    async fn rider_token(state: &AppState) -> String {
        let mut store = state.rider_tokens.lock().await;
        let (token, _record) = store
            .issue(
                "aa".repeat(32),
                vec![GRANTED_GROUP.to_string()],
                None,
                60,
                String::new(),
                None,
                None,
                crate::server::rider_auth::unix_now_secs(),
            )
            .await
            .expect("rider token issues");
        token
    }

    fn text_row(scope: Scope, body: &str, seen_at_ms: i64) -> HistoryRecord {
        HistoryRecord {
            msg_id: HistoryRecord::compute_msg_id(None, body.as_bytes()),
            scope,
            author_agent: Some("aa".repeat(32)),
            author_machine: None,
            author_pubkey: None,
            sent_at_ms: seen_at_ms,
            seen_at_ms,
            direction: Direction::Inbound,
            content_type: "text/plain".to_string(),
            payload: body.as_bytes().to_vec(),
            signed_artifact: None,
            signature: None,
            sig_context: None,
            provenance: Provenance::LocalAppDecrypt,
            replace_key: None,
            thread_root: None,
            thread_parent: None,
            ingress_sender_agent: None,
            logical_request_id: None,
        }
    }

    /// Seed one searchable row per scope kind, including the rider's
    /// granted group and a group it was NOT granted.
    fn seed(state: &AppState) {
        let store = state.agent.history().expect("history enabled").store();
        for (scope, body, seen) in [
            (Scope::Dm("peer-a".into()), "needle in the dm", 1_000),
            (
                Scope::Group(GRANTED_GROUP.into()),
                "needle in the granted group",
                2_000,
            ),
            (
                Scope::Group("secret-group".into()),
                "needle in the ungranted group",
                3_000,
            ),
            (Scope::Topic("chat".into()), "needle in the topic", 4_000),
        ] {
            store.insert(&text_row(scope, body, seen)).expect("insert");
        }
    }

    /// WHY (ADR-0039, unchanged): the cross-scope search added by issue #275
    /// would hand a rider every scope in the store at once. The accepted
    /// boundary admits GET `/history` and nothing else, so the middleware
    /// must reject the rider BEFORE the handler runs — asserted here with a
    /// real request, since a handler-level check alone could be bypassed by
    /// any future route that forgets it.
    #[tokio::test]
    async fn rider_is_denied_search_and_scopes_but_keeps_granted_group_list() -> anyhow::Result<()>
    {
        let dir = tempfile::tempdir()?;
        let state = history_state(dir.path()).await?;
        seed(&state);
        let app = history_router(Arc::clone(&state));
        let rider = rider_token(&state).await;

        for path in [
            "/history/search?q=needle",
            "/history/search?scope=group:granted-group&q=needle",
            "/history/scopes",
            "/history/scopes?limit=1",
        ] {
            let (status, json) = get_as(&app, path, &rider).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "rider must be denied {path}: {json}"
            );
            assert!(
                json["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("deny-by-default"),
                "denial must come from the ADR-0039 middleware, not a handler: {json}"
            );
        }

        // The retained grant still works, unchanged.
        let (status, json) = get_as(&app, "/history?scope=group:granted-group", &rider).await;
        assert_eq!(status, StatusCode::OK, "granted group list: {json}");
        assert_eq!(json["count"], 1);
        assert_eq!(json["records"][0]["scope"], "group:granted-group");

        // …and only for the granted scope.
        for path in [
            "/history?scope=group:secret-group",
            "/history?scope=dm:peer-a",
            "/history?scope=topic:chat",
        ] {
            let (status, json) = get_as(&app, path, &rider).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {json}");
        }
        Ok(())
    }

    /// WHY (issue #275): omitting `scope` must widen the search to every
    /// retained scope while supplying one must still narrow it. Driven
    /// through the router so the optional-`scope` deserialization, not just
    /// the store call, is what is proven.
    #[tokio::test]
    async fn owner_search_spans_scopes_without_scope_and_narrows_with_one() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = history_state(dir.path()).await?;
        seed(&state);
        let app = history_router(Arc::clone(&state));

        let (status, json) = get_as(&app, "/history/search?q=needle", DURABLE).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["count"], 4, "every scope is searched: {json}");
        assert!(
            json["next_before_id"].is_i64(),
            "search must expose the rowid cursor for paging: {json}"
        );

        let (status, json) =
            get_as(&app, "/history/search?scope=dm:peer-a&q=needle", DURABLE).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["count"], 1, "scoped search still filters: {json}");
        assert_eq!(json["records"][0]["scope"], "dm:peer-a");
        Ok(())
    }

    /// WHY (issue #275): the cursor a page hands back must be the cursor the
    /// next page accepts. Two single-row pages over a four-row result set
    /// prove the round trip and that the second page does not repeat the
    /// first row.
    #[tokio::test]
    async fn owner_search_pages_through_its_own_next_before_id() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = history_state(dir.path()).await?;
        seed(&state);
        let app = history_router(Arc::clone(&state));

        let (_, first) = get_as(&app, "/history/search?q=needle&limit=1", DURABLE).await;
        let cursor = first["next_before_id"].as_i64().expect("cursor");
        assert_eq!(first["records"][0]["id"], cursor);

        let (status, second) = get_as(
            &app,
            &format!("/history/search?q=needle&limit=1&before_id={cursor}"),
            DURABLE,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{second}");
        assert_eq!(second["count"], 1);
        assert!(
            second["records"][0]["id"].as_i64().expect("id") < cursor,
            "the next page is strictly older: {second}"
        );
        Ok(())
    }

    /// WHY (issue #275): discovery is the point — a caller with no scope
    /// string must be able to learn which scopes exist, how many retained
    /// rows each holds, and how recent they are, then walk them with the
    /// canonical cursor.
    #[tokio::test]
    async fn owner_scopes_enumerates_and_pages_by_canonical_cursor() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = history_state(dir.path()).await?;
        seed(&state);
        let app = history_router(Arc::clone(&state));

        let (status, json) = get_as(&app, "/history/scopes", DURABLE).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["count"], 4, "{json}");
        let first = &json["scopes"][0];
        assert_eq!(first["scope"], "dm:peer-a");
        assert_eq!(first["scope_kind"], 0);
        assert_eq!(first["scope_id"], "peer-a");
        assert_eq!(first["rows"], 1);
        assert_eq!(first["newest_seen_at_ms"], 1_000);
        assert_eq!(json["next_after_scope"], "topic:chat");

        let (status, page) = get_as(&app, "/history/scopes?limit=1", DURABLE).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["count"], 1);
        assert_eq!(page["next_after_scope"], "dm:peer-a");
        let (status, page2) = get_as(
            &app,
            "/history/scopes?limit=1&after_scope=dm:peer-a",
            DURABLE,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page2}");
        assert_eq!(
            page2["scopes"][0]["scope"], "group:granted-group",
            "the cursor is exclusive and resumes in (kind, id) order: {page2}"
        );
        Ok(())
    }

    /// WHY (issue #275): relaxing `scope` on search must not relax anything
    /// else. `GET /history` keeps requiring it (the rider grant is scoped),
    /// a supplied-but-malformed scope is still rejected on both, a blank `q`
    /// is still rejected, and a malformed enumeration cursor is a 400 rather
    /// than a silent restart from the first scope.
    #[tokio::test]
    async fn validation_boundaries_survive_the_optional_scope() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = history_state(dir.path()).await?;
        seed(&state);
        let app = history_router(Arc::clone(&state));

        for path in [
            "/history",                            // scope still required
            "/history?scope=nope",                 // malformed scope
            "/history/search?scope=nope&q=needle", // malformed scope, search
            "/history/search?scope=dm:&q=needle",  // empty scope id
            "/history/search",                     // missing q
            "/history/search?q=",                  // blank q
            "/history/search?q=%20",               // whitespace-only q
            "/history/scopes?after_scope=nope",    // malformed cursor
            "/history/scopes?after_scope=group:",  // empty cursor id
        ] {
            let (status, json) = get_as(&app, path, DURABLE).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {json}");
        }

        // An oversized limit is clamped, not rejected (history convention).
        let (status, json) = get_as(&app, "/history/scopes?limit=100000", DURABLE).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["count"], 4, "{json}");
        Ok(())
    }

    /// WHY (issue #275): a fresh install has no rows. Discovery must answer
    /// "nothing yet" as a normal empty page — a 404 or an error here would
    /// make the first-run path look broken.
    #[tokio::test]
    async fn empty_store_returns_empty_pages_not_errors() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = history_state(dir.path()).await?;
        let app = history_router(Arc::clone(&state));

        let (status, json) = get_as(&app, "/history/scopes", DURABLE).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["count"], 0);
        assert!(json["next_after_scope"].is_null(), "{json}");
        assert_eq!(json["scopes"], serde_json::json!([]));

        let (status, json) = get_as(&app, "/history/search?q=needle", DURABLE).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["count"], 0);
        assert!(json["next_before_id"].is_null(), "{json}");
        Ok(())
    }
}
