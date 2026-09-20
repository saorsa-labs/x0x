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
///
/// `marker`, when present, is the fork-quarantine marker held for THIS
/// row's group scope; a row seen at or after the marker's observation is
/// additionally flagged `fork_quarantined_at_ingest` (ADR-0066 R3 — see
/// [`fork_quarantined_at_ingest`]).
fn row_json(row: &StoredRecord, marker: Option<&x0x::groups::ForkQuarantine>) -> serde_json::Value {
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
    let mut json = serde_json::json!({
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
    });
    if marker.is_some_and(|marker| fork_quarantined_at_ingest(marker, r.seen_at_ms)) {
        if let Some(obj) = json.as_object_mut() {
            obj.insert("fork_quarantined_at_ingest".to_string(), true.into());
        }
    }
    json
}

/// ADR-0066 R3 (tag-and-retain): was this row ingested while the node held
/// the fork-quarantine marker for its group?
///
/// The marker records the local observation time of the authenticated fork
/// evidence, and `seen_at_ms` is the local receipt time of the row — both
/// are this node's own clock, so the comparison is exact rather than a
/// heuristic. Ingest is never refused (R3: refusing it would blank the
/// record across the incident window, the opposite of §3a's purpose), so
/// this flag is the only thing that separates rows that arrived on a
/// contested roster from the rest of the scope.
///
/// **The tag is derived, not persisted, and that is a deliberate trade.**
/// A stored column would survive a manual clear; it would also mean a new
/// `HistoryRecord` field, a SQLite schema bump, and — because `migrate`
/// refuses a database newer than the running binary — a history store an
/// older x0x could no longer open after a rollback. The ADR scopes this
/// slice to this file and asks only that ingest be distinguishable; a
/// derived tag costs nothing to downgrade and is exact for as long as the
/// marker (the very thing that makes the distinction interesting) exists.
/// A clear is the operator asserting the fork is resolved; the rows
/// survive it, only the contested label does not. Persisting it is a
/// superseding-ADR decision, not a slice-4 one.
fn fork_quarantined_at_ingest(marker: &x0x::groups::ForkQuarantine, seen_at_ms: i64) -> bool {
    seen_at_ms >= i64::try_from(marker.observed_at_ms).unwrap_or(i64::MAX)
}

/// One fork-quarantined group in a response's view: its canonical history
/// scope string and the marker this node holds for it.
pub(in crate::server) type ScopeMarker = (String, x0x::groups::ForkQuarantine);

/// ADR-0066 §3a: the read surface is **never** refused — containment must
/// not blind the operator — so a history read with a fork-quarantined
/// group in view says so in its envelope instead:
///
/// ```json
/// "fork_quarantined": true,
/// "fork_quarantine": {
///   "clear_with": "POST /groups/:id/quarantine/clear",
///   "scopes": [{"scope": "group:g1", "revision": 9,
///               "observed_at_ms": 1758240000000, "no_anchor": true}]
/// }
/// ```
///
/// The per-scope object mirrors the §5 refusal body's `fork_quarantine`
/// (`revision`, `observed_at_ms`, `no_anchor`, `clear_with`); §3a names
/// the `fork_quarantined` flag and the marker's `revision` and
/// `observed_at_ms` but does not say how to carry MORE than one marker,
/// and these surfaces are not single-group: a cross-scope search,
/// `/history/scopes`, `/history/stats` and `/diagnostics/history` can each
/// have several quarantined groups in view. A list, always, beats a shape
/// that changes with the query.
///
/// Returns `None` when nothing in view is quarantined, so both keys are
/// ABSENT (not null) and an existing client's body is byte-identical.
fn fork_quarantine_annotation(markers: &[ScopeMarker]) -> Option<serde_json::Value> {
    if markers.is_empty() {
        return None;
    }
    let scopes: Vec<serde_json::Value> = markers
        .iter()
        .map(|(scope, marker)| {
            serde_json::json!({
                "scope": scope,
                "revision": marker.revision,
                "observed_at_ms": marker.observed_at_ms,
                "no_anchor": marker.no_anchor,
            })
        })
        .collect();
    Some(serde_json::json!({
        "clear_with": crate::server::routes::named_groups::FORK_QUARANTINE_CLEAR_ROUTE,
        "scopes": scopes,
    }))
}

/// Fold [`fork_quarantine_annotation`] into a response envelope.
///
/// Visible to the whole server because `GET /groups/:id/messages`
/// (`named_groups.rs`) is the same ADR-0023 read on the group plane — the
/// §1 map gap slice 2 recorded — and it must carry the SAME annotation
/// rather than a second dialect of it.
pub(in crate::server) fn annotate(
    mut body: serde_json::Value,
    markers: &[ScopeMarker],
) -> serde_json::Value {
    let Some(annotation) = fork_quarantine_annotation(markers) else {
        return body;
    };
    if let Some(obj) = body.as_object_mut() {
        obj.insert("fork_quarantined".to_string(), true.into());
        obj.insert("fork_quarantine".to_string(), annotation);
    }
    body
}

/// The marker for one row's scope, if that scope is a quarantined group.
fn marker_for<'a>(
    markers: &'a [ScopeMarker],
    scope: &Scope,
) -> Option<&'a x0x::groups::ForkQuarantine> {
    let canonical = scope.canonical();
    markers
        .iter()
        .find(|(scope, _)| *scope == canonical)
        .map(|(_, marker)| marker)
}

/// Resolve one group id to its roster entry under **either spelling**, and
/// return the entry's MAP KEY alongside it.
///
/// **This is load-bearing, not defensive (review r1, omp/GLM-5.3).** The
/// `named_groups` map is keyed by whichever alias this daemon learned the
/// group under, and the apply path installs the marker under that map key
/// (`resolved_group_key`, `named_groups.rs:9124`). History rows, by
/// contrast, are always scoped by the **stable** id: the ingest record uses
/// `GroupPublicMessage.group_id` (`named_groups.rs:13723`), and
/// `GET /history/scopes` therefore hands the operator `group:<stable id>`.
/// A bare `get(group_id)` misses the marker exactly when key ≠ stable id —
/// and on the purge path a missed marker is not a degraded answer, it is a
/// **deletion of the forensic record row 14 exists to protect**. So this
/// resolves the same way the metadata apply path does: direct key hit
/// first, then a scan by `stable_group_id()`. The scan is bounded by the
/// group count and runs only at the lookup points below.
///
/// The key is returned because the manual clear endpoint
/// (`clear_group_quarantine`, `named_groups.rs:12607`) looks the group up by
/// **map key only** — so a refusal must name that spelling in its §5 remedy,
/// or it would hand the operator an id its own clear route cannot find.
///
/// Slice 3 (#744, `delegations::fork_quarantine_marker`) and slice 6 (#745,
/// `ws::fork_quarantine_annotation`) carry the same two-spelling resolver by
/// deliberate duplication; folding the three into one shared helper is a
/// follow-up, not a slice-4 refactor.
fn resolve_group_entry<'a>(
    groups: &'a std::collections::HashMap<String, x0x::groups::GroupInfo>,
    group_id: &str,
) -> Option<(&'a String, &'a x0x::groups::GroupInfo)> {
    groups.get_key_value(group_id).or_else(|| {
        groups
            .iter()
            .find(|(_, info)| info.stable_group_id() == group_id)
    })
}

/// Markers for the group scopes named by `scopes` (deduplicated, ordered
/// by canonical scope so a response is stable page to page). Takes the
/// `named_groups` read lock exactly once.
///
/// Each marker is reported under the scope spelling the CALLER used, which
/// is also the spelling its rows carry — the lookup accepts either (see
/// [`resolve_group_entry`]), so an alias-keyed group annotates whether the
/// request named it by alias or by stable id.
pub(in crate::server) async fn markers_for_scopes<'a>(
    state: &AppState,
    scopes: impl IntoIterator<Item = &'a Scope>,
) -> Vec<ScopeMarker> {
    let wanted: std::collections::BTreeSet<&str> = scopes
        .into_iter()
        .filter_map(|scope| match scope {
            Scope::Group(id) => Some(id.as_str()),
            _ => None,
        })
        .collect();
    if wanted.is_empty() {
        return Vec::new();
    }
    let groups = state.named_groups.read().await;
    wanted
        .into_iter()
        .filter_map(|id| {
            let (_, info) = resolve_group_entry(&groups, id)?;
            let marker = info.fork_quarantine.clone()?;
            Some((Scope::Group(id.to_string()).canonical(), marker))
        })
        .collect()
}

/// Every group this node currently holds a marker for. Used by the two
/// node-wide surfaces (`/history/stats`, `/diagnostics/history`), where
/// "in view" is the whole store rather than one scope.
///
/// **Both spellings are listed when they differ**, because these two
/// surfaces are where an operator learns which scopes are contested and
/// then goes and queries them: the map key is what the clear route accepts,
/// the stable id is what `GET /history/scopes` and the rows themselves
/// carry, and printing only one of the two would send the operator to a
/// scope string that returns nothing.
async fn all_quarantine_markers(state: &AppState) -> Vec<ScopeMarker> {
    let groups = state.named_groups.read().await;
    let mut markers: Vec<ScopeMarker> = Vec::new();
    for (key, info) in groups.iter() {
        let Some(marker) = info.fork_quarantine.clone() else {
            continue;
        };
        let stable = info.stable_group_id();
        if stable != key.as_str() {
            markers.push((Scope::Group(stable.to_string()).canonical(), marker.clone()));
        }
        markers.push((Scope::Group(key.clone()).canonical(), marker));
    }
    markers.sort_by(|(a, _), (b, _)| a.cmp(b));
    markers.dedup_by(|(a, _), (b, _)| a == b);
    markers
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
    let q = query_from(&params, Some(scope.clone()));
    match tokio::task::spawn_blocking(move || store.query(&q)).await {
        Ok(Ok(rows)) => {
            let next_before_id = rows.last().map(|r| r.id);
            // ADR-0066 §3a (row 13): serve, annotate, never refuse. The
            // annotation comes from the REQUESTED scope, not from the rows,
            // so an empty page of a quarantined group is still labelled.
            let markers = markers_for_scopes(&state, std::iter::once(&scope)).await;
            let items: Vec<_> = rows
                .iter()
                .map(|row| row_json(row, marker_for(&markers, &row.record.scope)))
                .collect();
            (
                StatusCode::OK,
                Json(annotate(
                    serde_json::json!({
                        "ok": true,
                        "count": items.len(),
                        "next_before_id": next_before_id,
                        "records": items,
                    }),
                    &markers,
                )),
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
        Ok(Ok(Some(row))) => {
            // ADR-0066 §3a (row 13): the row's OWN scope decides, so a
            // point lookup made without `?scope=` is annotated too.
            let markers = markers_for_scopes(&state, std::iter::once(&row.record.scope)).await;
            let record = row_json(&row, marker_for(&markers, &row.record.scope));
            (
                StatusCode::OK,
                Json(annotate(
                    serde_json::json!({ "ok": true, "record": record }),
                    &markers,
                )),
            )
        }
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
    let q = query_from(&params, scope.clone());
    match tokio::task::spawn_blocking(move || store.search(&needle, &q)).await {
        Ok(Ok(rows)) => {
            let next_before_id = rows.last().map(|r| r.id);
            // ADR-0066 §3a (row 13). A cross-scope search (no `scope=`)
            // can span several quarantined groups at once, which is why
            // the annotation carries a list rather than one marker.
            let markers = markers_for_scopes(
                &state,
                rows.iter().map(|r| &r.record.scope).chain(scope.iter()),
            )
            .await;
            let items: Vec<_> = rows
                .iter()
                .map(|row| row_json(row, marker_for(&markers, &row.record.scope)))
                .collect();
            (
                StatusCode::OK,
                Json(annotate(
                    serde_json::json!({
                        "ok": true,
                        "count": items.len(),
                        "next_before_id": next_before_id,
                        "records": items,
                    }),
                    &markers,
                )),
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
            // ADR-0066 §3a (row 13): annotate the quarantined groups on
            // THIS page, so the label pages with the enumeration it
            // describes.
            let markers = markers_for_scopes(&state, summaries.iter().map(|s| &s.scope)).await;
            let items: Vec<_> = summaries.iter().map(scope_json).collect();
            (
                StatusCode::OK,
                Json(annotate(
                    serde_json::json!({
                        "ok": true,
                        "count": items.len(),
                        "next_after_scope": next_after_scope,
                        "scopes": items,
                    }),
                    &markers,
                )),
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
        // ADR-0066 §3a (row 13). `stats` is node-wide, so "in view" is
        // every group this node holds a marker for: the counts it reports
        // include contested rows, and the operator is told which scopes
        // those are.
        Ok(Ok(stats)) => (
            StatusCode::OK,
            Json(annotate(
                serde_json::json!({
                    "ok": true,
                    "stats": stats,
                    "retention": {
                        "max_bytes": state.history_config.max_bytes,
                        "max_age_days": state.history_config.max_age_days,
                        "scope_limits": state.history_config.scope_limits,
                    },
                }),
                &all_quarantine_markers(&state).await,
            )),
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
///
/// ADR-0066 §3a (row 14) — REFUSED while the scope's group is
/// fork-quarantined. This is the one history path that is gated, and it is
/// gated for the same reason the reads are not: the ADR-0023 durable record
/// is the primary post-hoc artefact for a fork, and a purge destroys it
/// irreversibly. Reads stay open so the operator can see the incident;
/// purge closes so nobody — operator or attacker — can delete the evidence
/// mid-incident. The check runs BEFORE any deletion, so a refused purge
/// leaves the store untouched.
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
    if let Scope::Group(group_id) = &scope {
        // §3e: the one shared refusal helper, so this route inherits the
        // §5 message (machine `reason`, remedy-bearing `error`, and the
        // `fork_quarantine` object) instead of minting its own wording.
        //
        // BOTH SPELLINGS (review r1): the purge scope an operator holds is
        // `group:<stable id>` — that is what the rows carry and what
        // `GET /history/scopes` lists — while the marker sits under the map
        // key. A single-spelling lookup here does not merely miss an
        // annotation; it lets `Store::purge` below destroy the forensic
        // record of a quarantined group. The refusal names the resolved MAP
        // KEY, because that is the id the manual clear route accepts.
        let refusal = {
            let groups = state.named_groups.read().await;
            resolve_group_entry(&groups, group_id).and_then(|(key, info)| {
                crate::server::routes::named_groups::reject_fork_quarantined(&state, key, info)
            })
        };
        if let Some(refusal) = refusal {
            return refusal;
        }
    }
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
        Json(annotate(
            serde_json::json!({
                "ok": true,
                "enabled": true,
                "written_total": c.written_total.load(Ordering::Relaxed),
                "dropped_full": c.dropped_full.load(Ordering::Relaxed),
                "dedup_hits": c.dedup_hits.load(Ordering::Relaxed),
                "write_errors": c.write_errors.load(Ordering::Relaxed),
                "abandoned_at_shutdown": c.abandoned_at_shutdown.load(Ordering::Relaxed),
                "reaper_evicted_total": c.reaper_evicted_total.load(Ordering::Relaxed),
            }),
            // ADR-0066 §3a (row 26): the writer/reaper counters are
            // node-wide, so the annotation names every group this node has
            // quarantined — R3 ingest keeps writing for them, and these
            // counters are what an operator reads to confirm it.
            &all_quarantine_markers(&state).await,
        )),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use x0x::groups::{GroupPublicMessage, GroupPublicMessageKind};
    use x0x::history::{Direction, HistoryRecord, InsertOutcome, Provenance, Store};

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

        let json = row_json(&stored, None);
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

    #[test]
    fn canonical_projection_rejects_scope_and_body_mismatches() {
        let dir = tempfile::tempdir().expect("temporary history directory");
        let store = Store::open(&dir.path().join("history.db")).expect("open history store");
        let message = GroupPublicMessage {
            group_id: "canonical-guard".to_string(),
            state_hash_at_send: "state".to_string(),
            revision_at_send: 1,
            author_agent_id: "author".to_string(),
            author_public_key: "key".to_string(),
            author_user_id: None,
            kind: GroupPublicMessageKind::Chat,
            body: "canonical body".to_string(),
            timestamp: 1,
            thread_root: None,
            thread_parent: None,
            mentions: Vec::new(),
            delegation_digest: None,
            rider_provenance: None,
            signature: "signature".to_string(),
        };
        let artifact = serde_json::to_vec(&message).expect("serialize artifact");
        let canonical = message.msg_id();
        let canonical_bytes: [u8; 32] = hex::decode(&canonical)
            .expect("canonical hex")
            .try_into()
            .expect("canonical length");

        let record = |scope: Scope, payload: Vec<u8>, seen_at_ms: i64| HistoryRecord {
            msg_id: HistoryRecord::compute_msg_id(Some(&artifact), &payload),
            scope,
            author_agent: Some("author".to_string()),
            author_machine: None,
            author_pubkey: None,
            sent_at_ms: seen_at_ms,
            seen_at_ms,
            direction: Direction::Inbound,
            content_type: "text/plain".to_string(),
            payload,
            signed_artifact: Some(artifact.clone()),
            signature: Some(vec![1]),
            sig_context: Some("x0x.group.public-message.v2".to_string()),
            provenance: Provenance::VerifiedEnvelope,
            replace_key: None,
            thread_root: None,
            thread_parent: None,
            ingress_sender_agent: None,
            logical_request_id: None,
        };
        let wrong_scope = record(
            Scope::Group("other-group".to_string()),
            message.body.as_bytes().to_vec(),
            1,
        );
        let wrong_body = record(
            Scope::Group(message.group_id.clone()),
            b"tampered body".to_vec(),
            2,
        );
        let wrong_scope_id = wrong_scope.msg_id;
        let wrong_body_id = wrong_body.msg_id;
        store.insert(&wrong_scope).expect("insert scope mismatch");
        store.insert(&wrong_body).expect("insert body mismatch");

        for (id, scope) in [
            (wrong_scope_id, "other-group"),
            (wrong_body_id, "canonical-guard"),
        ] {
            assert!(store.get_by_msg_id(id).expect("dedupe lookup").is_some());
            assert!(
                resolve_history_message(
                    &store,
                    canonical_bytes,
                    &canonical,
                    Some(Scope::Group(scope.to_string())),
                )
                .expect("canonical lookup")
                .is_none(),
                "mismatched artifact must never resolve as canonical group {scope}"
            );
        }
    }

    #[test]
    fn canonical_projection_dedupes_local_and_verified_recorders() {
        let dir = tempfile::tempdir().expect("temporary history directory");
        let store = Store::open(&dir.path().join("history.db")).expect("open history store");
        let message = GroupPublicMessage {
            group_id: "recorder-order".to_string(),
            state_hash_at_send: "state".to_string(),
            revision_at_send: 1,
            author_agent_id: "author".to_string(),
            author_public_key: "key".to_string(),
            author_user_id: None,
            kind: GroupPublicMessageKind::Chat,
            body: "same signed body".to_string(),
            timestamp: 1,
            thread_root: None,
            thread_parent: None,
            mentions: Vec::new(),
            delegation_digest: None,
            rider_provenance: None,
            signature: "signature".to_string(),
        };
        let artifact = serde_json::to_vec(&message).expect("serialize artifact");
        let payload = message.body.as_bytes().to_vec();
        let make_record = |provenance| HistoryRecord {
            msg_id: HistoryRecord::compute_msg_id(Some(&artifact), &payload),
            scope: Scope::Group(message.group_id.clone()),
            author_agent: Some(message.author_agent_id.clone()),
            author_machine: None,
            author_pubkey: None,
            sent_at_ms: 1,
            seen_at_ms: 1,
            direction: Direction::Inbound,
            content_type: "text/plain".to_string(),
            payload: payload.clone(),
            signed_artifact: Some(artifact.clone()),
            signature: Some(vec![1]),
            sig_context: Some("x0x.group.public-message.v2".to_string()),
            provenance,
            replace_key: None,
            thread_root: None,
            thread_parent: None,
            ingress_sender_agent: None,
            logical_request_id: None,
        };
        let local = make_record(Provenance::LocalSend);
        let verified = make_record(Provenance::VerifiedEnvelope);
        assert_eq!(
            store.insert(&local).expect("insert LocalSend"),
            InsertOutcome::Inserted
        );
        assert_eq!(
            store.insert(&verified).expect("insert VerifiedEnvelope"),
            InsertOutcome::Duplicate,
            "same signed artifact/body must not create competing history rows"
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
            Some(Scope::Group(message.group_id)),
        )
        .expect("canonical lookup")
        .expect("deduped canonical row");
        assert_eq!(resolved.record.provenance, Provenance::LocalSend);
    }

    #[test]
    fn canonical_projection_backfills_after_auxiliary_table_loss() {
        let dir = tempfile::tempdir().expect("temporary history directory");
        let db = dir.path().join("history.db");
        let message = GroupPublicMessage {
            group_id: "backfill-group".to_string(),
            state_hash_at_send: "state".to_string(),
            revision_at_send: 1,
            author_agent_id: "author".to_string(),
            author_public_key: "key".to_string(),
            author_user_id: None,
            kind: GroupPublicMessageKind::Chat,
            body: "backfill body".to_string(),
            timestamp: 1,
            thread_root: None,
            thread_parent: None,
            mentions: Vec::new(),
            delegation_digest: None,
            rider_provenance: None,
            signature: "signature".to_string(),
        };
        let artifact = serde_json::to_vec(&message).expect("serialize artifact");
        let payload = message.body.as_bytes().to_vec();
        let row = HistoryRecord {
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
            sig_context: Some("x0x.group.public-message.v2".to_string()),
            provenance: Provenance::LocalSend,
            replace_key: None,
            thread_root: None,
            thread_parent: None,
            ingress_sender_agent: None,
            logical_request_id: None,
        };
        let canonical = message.msg_id();
        let canonical_bytes: [u8; 32] = hex::decode(&canonical)
            .expect("canonical hex")
            .try_into()
            .expect("canonical length");
        {
            let store = Store::open(&db).expect("open history store");
            store.insert(&row).expect("insert history row");
        }
        {
            let conn = rusqlite::Connection::open(&db).expect("open legacy-shaped database");
            conn.execute_batch("DROP TABLE history_canonical_ids;")
                .expect("drop derived table");
        }
        let reopened = Store::open(&db).expect("reopen and backfill history store");
        let resolved = resolve_history_message(
            &reopened,
            canonical_bytes,
            &canonical,
            Some(Scope::Group(message.group_id)),
        )
        .expect("canonical lookup after backfill")
        .expect("backfill must restore valid projection");
        assert_eq!(resolved.record.msg_id, row.msg_id);
        assert_eq!(resolved.record.provenance, Provenance::LocalSend);
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
    pub(super) const DURABLE: &str = "test-token";
    const GRANTED_GROUP: &str = "granted-group";

    /// Owned state whose agent has a real, isolated history store.
    pub(super) async fn history_state(dir: &std::path::Path) -> anyhow::Result<Arc<AppState>> {
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

    pub(super) fn text_row(scope: Scope, body: &str, seen_at_ms: i64) -> HistoryRecord {
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

#[cfg(test)]
mod adr0066_fork_quarantine_tests {
    //! ADR-0066 §3a (slice 4): rows 13, 14 and 26 — history purge is
    //! REFUSED under the fork-quarantine marker while every read keeps
    //! serving, annotated.
    //!
    //! WHY the asymmetry, encoded here so a later "consistency" refactor
    //! cannot quietly flatten it: the ADR-0023 durable record is the
    //! primary post-hoc artefact for a fork. Refusing reads would delete
    //! the operator's only view of the incident at the moment it matters
    //! (ADR-0066 Drivers); permitting a purge would delete the incident
    //! itself, irreversibly, which is the act David's R5 fail-closed
    //! decision exists to stop. Containment without blindness.
    //!
    //! Driven through the REAL router and the production auth middleware,
    //! on an isolated on-disk store — a handler re-reading its own
    //! predicate would not prove the gate is in the request path.

    use super::discovery_auth_tests::{history_state, text_row, DURABLE};
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use axum::routing::get;
    use tower::ServiceExt;

    const QUARANTINED: &str = "contested-group";
    const CLEAN: &str = "quiet-group";
    /// The ALIAS-keyed contested group (review r1): the roster map key this
    /// daemon learned it under…
    const ALIAS_KEY: &str = "alias-key-a";
    /// …and the STABLE id its history rows are scoped by. `ALIAS_KEY !=
    /// ALIAS_STABLE` is the whole point of the fixture.
    const ALIAS_STABLE: &str = "stable-id-s";
    /// Local observation time of the fork evidence. Rows seen before it
    /// predate the incident; rows seen at or after it arrived on a
    /// contested roster (R3).
    const OBSERVED_AT_MS: u64 = 2_000;

    /// Every history surface §1 rows 13/14/26 name, wired as
    /// `server::mod` wires them and behind the production middleware.
    fn full_history_router(state: Arc<AppState>) -> axum::Router {
        axum::Router::new()
            .route("/history", get(history_list).delete(history_purge))
            .route("/history/message/:msg_id", get(history_message))
            .route("/history/scopes", get(history_scopes))
            .route("/history/search", get(history_search))
            .route("/history/stats", get(history_stats))
            .route("/diagnostics/history", get(history_diagnostics))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::server::auth::auth_middleware,
            ))
            .with_state(state)
    }

    async fn call(app: &axum::Router, method: &str, path: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {DURABLE}"))
            .body(axum::body::Body::empty())
            .expect("request builds");
        let resp = app.clone().oneshot(req).await.expect("router answers");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body reads");
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    /// Two rows in the contested group — one ingested BEFORE the evidence
    /// was observed, one AFTER — plus one row in an unrelated group that
    /// must stay completely unlabelled.
    fn seed_rows(state: &AppState) {
        let store = state.agent.history().expect("history enabled").store();
        for (scope, body, seen) in [
            (Scope::Group(QUARANTINED.into()), "before the fork", 1_000),
            (
                Scope::Group(QUARANTINED.into()),
                "after the fork",
                i64::try_from(OBSERVED_AT_MS).unwrap_or(i64::MAX) + 500,
            ),
            (Scope::Group(CLEAN.into()), "unrelated traffic", 1_500),
        ] {
            store.insert(&text_row(scope, body, seen)).expect("insert");
        }
    }

    /// Rows for the ALIAS-keyed group, scoped by its STABLE id exactly as
    /// the ingest path scopes them (`GroupPublicMessage.group_id`). One row
    /// before the evidence, one after, so the ingest tag has something to
    /// discriminate.
    fn seed_alias_rows(state: &AppState) {
        let store = state.agent.history().expect("history enabled").store();
        for (body, seen) in [
            ("alias row before the fork", 1_000),
            (
                "alias row after the fork",
                i64::try_from(OBSERVED_AT_MS).unwrap_or(i64::MAX) + 500,
            ),
        ] {
            store
                .insert(&text_row(Scope::Group(ALIAS_STABLE.into()), body, seen))
                .expect("insert");
        }
    }

    /// The full content of the store, in a form a purge cannot survive:
    /// every row of every scope with its id, scope, payload bytes and
    /// receipt time. Compared before and after a refused purge, this is
    /// what "the store is unchanged" means operationally — and unlike
    /// hashing `history.db`, it cannot pass because SQLite wrote the
    /// deletion to the WAL instead of the main file.
    fn store_snapshot(state: &AppState) -> Vec<(i64, String, Vec<u8>, i64)> {
        let store = state.agent.history().expect("history enabled").store();
        let mut rows: Vec<(i64, String, Vec<u8>, i64)> = store
            .query(&HistoryQuery {
                scope: None,
                scope_kind: None,
                since_ms: None,
                until_ms: None,
                limit: 0,
                before_id: None,
            })
            .expect("snapshot query")
            .into_iter()
            .map(|row| {
                (
                    row.id,
                    row.record.scope.canonical(),
                    row.record.payload.clone(),
                    row.record.seen_at_ms,
                )
            })
            .collect();
        rows.sort();
        rows
    }

    /// Install a group carrying the ADR-0066 §2 ordinary-group marker
    /// (`no_anchor`), i.e. the population whose quarantine NOTHING clears
    /// automatically — the sharpest case for both the refusal and its
    /// message.
    async fn quarantine(state: &AppState, group_id: &str) {
        // The simple shape: this daemon learned the group under its own
        // stable id, so map key == stable id == history scope id.
        quarantine_under(state, group_id, group_id).await;
    }

    /// The ALIAS shape, which production reaches routinely: the roster map
    /// is keyed by whatever id this daemon learned the group under
    /// (`resolved_group_key`), while history rows are scoped by the group's
    /// STABLE id. `map_key` is where the marker lives; `stable_id` is what
    /// `GET /history/scopes` lists and what a purge request names.
    async fn quarantine_under(state: &AppState, map_key: &str, stable_id: &str) {
        let creator = state.agent.agent_id();
        let mut info = x0x::groups::GroupInfo::new(
            map_key.to_string(),
            "adr-0066 slice 4 fixture".to_string(),
            creator,
            // `stable_group_id()` falls back to `mls_group_id` with no
            // genesis record, so this is what makes key ≠ stable id.
            stable_id.to_string(),
        );
        assert_eq!(
            info.stable_group_id(),
            stable_id,
            "fixture precondition: the group's stable id is the scope its rows carry"
        );
        info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision: 9,
            state_hash: info.state_hash.clone(),
            committed_by: hex::encode(creator.as_bytes()),
            observed_at_ms: OBSERVED_AT_MS,
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: info.terminal_commit_header(),
                conflicting_commit: info.terminal_commit_header(),
                classification: Some("signer_only".to_string()),
            },
            no_anchor: true,
        });
        state
            .named_groups
            .write()
            .await
            .insert(map_key.to_string(), info);
    }

    /// A group present in state with NO marker — the control that proves
    /// the gate keys on the marker and not merely on the group existing.
    async fn unquarantined(state: &AppState, group_id: &str) {
        let creator = state.agent.agent_id();
        let info = x0x::groups::GroupInfo::new(
            group_id.to_string(),
            "adr-0066 slice 4 control".to_string(),
            creator,
            format!("mls-{group_id}"),
        );
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info);
    }

    /// WHY (ADR-0066 §1 row 14, §3a, and the R5 fail-closed ratification):
    /// a purge is the irreversible destruction of the forensic record of a
    /// fork. If it were permitted while the marker is set, the operator —
    /// or whoever holds the token mid-incident — could delete the evidence
    /// the whole quarantine exists to preserve. The gate must therefore
    /// run BEFORE any deletion, which is why this asserts the store's full
    /// contents are identical afterwards rather than merely that the
    /// response was a 409: a refusal that deleted first and apologised
    /// second would still read as green on status alone.
    #[tokio::test]
    async fn purge_is_refused_while_quarantined_and_the_store_is_untouched() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = history_state(dir.path()).await?;
        seed_rows(&state);
        quarantine(&state, QUARANTINED).await;
        unquarantined(&state, CLEAN).await;
        let app = full_history_router(Arc::clone(&state));
        let before = store_snapshot(&state);
        assert_eq!(before.len(), 3, "precondition: three seeded rows");

        let (status, json) = call(&app, "DELETE", "/history?scope=group:contested-group").await;
        assert_eq!(status, StatusCode::CONFLICT, "purge must refuse: {json}");
        assert_eq!(
            store_snapshot(&state),
            before,
            "a refused purge must leave the store byte-identical — the gate runs before \
             `Store::purge`, not after it"
        );

        // §5's acceptance bar: the machine code lives in `reason`, and
        // `error` is an actionable sentence, not the code again.
        assert_eq!(
            json["reason"], "fork_quarantined",
            "§5 machine code: {json}"
        );
        let message = json["error"].as_str().unwrap_or_default();
        assert!(
            !message.is_empty() && message != "fork_quarantined",
            "§5: `error` must be prose, not the machine code: {json}"
        );
        assert!(
            message.contains("quarantine clear") || message.contains("quarantine/clear"),
            "§5: the refusal must name the remedy: {json}"
        );
        assert_eq!(json["fork_quarantine"]["revision"], 9, "{json}");
        assert_eq!(
            json["fork_quarantine"]["no_anchor"], true,
            "an ordinary group's marker says plainly that nothing clears it automatically: {json}"
        );
        assert_eq!(
            json["fork_quarantine"]["clear_with"], "POST /groups/:id/quarantine/clear",
            "{json}"
        );

        // The route itself still works: an unquarantined group purges, so
        // the 409 above is the marker talking and not a broken handler.
        let (status, json) = call(&app, "DELETE", "/history?scope=group:quiet-group").await;
        assert_eq!(status, StatusCode::OK, "control purge: {json}");
        assert_eq!(json["removed"], 1, "control purge removes its one row");
        Ok(())
    }

    /// WHY (ADR-0066 §3a, rows 13 and 26): containment must not blind the
    /// operator. Every read keeps serving the same rows it served before
    /// the marker — the annotation is ADDITIVE — and a client that reads
    /// no ADR-0066 field sees a byte-identical body for an unquarantined
    /// scope. The absence assertion is the load-bearing half: an
    /// annotation emitted as `false`/`null` for every group would be a
    /// silent response-shape change on every history read in the fleet.
    #[tokio::test]
    async fn reads_serve_and_are_annotated_only_while_quarantined() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = history_state(dir.path()).await?;
        seed_rows(&state);
        let app = full_history_router(Arc::clone(&state));

        // Before any marker: nothing at all is added.
        let (status, clean) = call(&app, "GET", "/history?scope=group:contested-group").await;
        assert_eq!(status, StatusCode::OK, "{clean}");
        assert_eq!(clean["count"], 2, "both rows serve: {clean}");
        assert!(
            clean.get("fork_quarantined").is_none() && clean.get("fork_quarantine").is_none(),
            "an unquarantined read must be byte-identical to the pre-ADR body: {clean}"
        );

        quarantine(&state, QUARANTINED).await;
        unquarantined(&state, CLEAN).await;

        let (status, annotated) = call(&app, "GET", "/history?scope=group:contested-group").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "reads are NEVER refused: {annotated}"
        );
        assert_eq!(
            annotated["count"], 2,
            "the same rows still serve under quarantine: {annotated}"
        );
        assert_eq!(annotated["fork_quarantined"], true, "{annotated}");
        assert_eq!(
            annotated["fork_quarantine"]["scopes"][0]["scope"],
            "group:contested-group"
        );
        assert_eq!(annotated["fork_quarantine"]["scopes"][0]["revision"], 9);
        assert_eq!(
            annotated["fork_quarantine"]["scopes"][0]["observed_at_ms"],
            OBSERVED_AT_MS
        );
        assert_eq!(annotated["fork_quarantine"]["scopes"][0]["no_anchor"], true);
        assert_eq!(
            annotated["records"].as_array().map(Vec::len),
            clean["records"].as_array().map(Vec::len),
            "annotation adds fields, it never drops rows: {annotated}"
        );

        // The unrelated group is untouched by its neighbour's quarantine.
        let (_, other) = call(&app, "GET", "/history?scope=group:quiet-group").await;
        assert!(
            other.get("fork_quarantined").is_none(),
            "one group's marker must not label another: {other}"
        );

        // A cross-scope search spans both and is annotated for exactly the
        // contested one — the reason the annotation carries a list.
        let (status, search) = call(&app, "GET", "/history/search?q=fork").await;
        assert_eq!(status, StatusCode::OK, "{search}");
        assert_eq!(search["fork_quarantined"], true, "{search}");
        assert_eq!(
            search["fork_quarantine"]["scopes"].as_array().map(Vec::len),
            Some(1),
            "only the quarantined scope is listed: {search}"
        );

        // Scope enumeration labels the page it describes.
        let (status, scopes) = call(&app, "GET", "/history/scopes").await;
        assert_eq!(status, StatusCode::OK, "{scopes}");
        assert_eq!(scopes["fork_quarantined"], true, "{scopes}");
        Ok(())
    }

    /// WHY (ADR-0066 R3 — tag-and-retain, never refuse): refusing ingest
    /// would blank the durable record across exactly the incident window
    /// an operator needs, which is the opposite of §3a's purpose. So a row
    /// that arrives while the marker is set is STORED, served, and
    /// distinguishable from the group's pre-fork traffic. The row seeded
    /// before the evidence was observed must NOT be tagged — a tag on
    /// every row of the scope would carry no information at all.
    #[tokio::test]
    async fn ingest_during_quarantine_is_retained_and_tagged() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = history_state(dir.path()).await?;
        seed_rows(&state);
        quarantine(&state, QUARANTINED).await;
        let app = full_history_router(Arc::clone(&state));

        let (status, json) = call(&app, "GET", "/history?scope=group:contested-group").await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let records = json["records"].as_array().cloned().unwrap_or_default();
        assert_eq!(records.len(), 2, "nothing is dropped on ingest: {json}");

        let tagged: Vec<&serde_json::Value> = records
            .iter()
            .filter(|row| row["fork_quarantined_at_ingest"] == serde_json::Value::Bool(true))
            .collect();
        assert_eq!(
            tagged.len(),
            1,
            "exactly the row ingested after the evidence is tagged: {json}"
        );
        assert!(
            tagged[0]["seen_at_ms"].as_i64().unwrap_or_default()
                >= i64::try_from(OBSERVED_AT_MS).unwrap_or(i64::MAX),
            "the tagged row is the one seen at or after the marker: {json}"
        );
        for row in &records {
            if row["fork_quarantined_at_ingest"] != serde_json::Value::Bool(true) {
                assert!(
                    row.get("fork_quarantined_at_ingest").is_none(),
                    "an untagged row carries no key at all, not a false one: {row}"
                );
            }
        }
        Ok(())
    }

    /// WHY (ADR-0066 §1 row 26 and §3a): `/history/stats` and
    /// `/diagnostics/history` are node-wide — they report the counters an
    /// operator reads to confirm that R3 ingest is still writing during an
    /// incident. Reporting those totals without naming the contested
    /// groups they include is the "unlabelled record" the ADR's attack
    /// matrix calls out.
    #[tokio::test]
    async fn node_wide_surfaces_name_every_quarantined_group() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = history_state(dir.path()).await?;
        seed_rows(&state);
        let app = full_history_router(Arc::clone(&state));

        for path in ["/history/stats", "/diagnostics/history"] {
            let (status, json) = call(&app, "GET", path).await;
            assert_eq!(status, StatusCode::OK, "{path}: {json}");
            assert!(
                json.get("fork_quarantined").is_none(),
                "{path} must not annotate when no group is quarantined: {json}"
            );
        }

        quarantine(&state, QUARANTINED).await;
        unquarantined(&state, CLEAN).await;

        for path in ["/history/stats", "/diagnostics/history"] {
            let (status, json) = call(&app, "GET", path).await;
            assert_eq!(status, StatusCode::OK, "{path} still serves: {json}");
            assert_eq!(json["fork_quarantined"], true, "{path}: {json}");
            assert_eq!(
                json["fork_quarantine"]["scopes"],
                serde_json::json!([{
                    "scope": "group:contested-group",
                    "revision": 9,
                    "observed_at_ms": OBSERVED_AT_MS,
                    "no_anchor": true,
                }]),
                "{path} names exactly the quarantined groups: {json}"
            );
        }
        Ok(())
    }

    /// WHY (review r1, omp/GLM-5.3 — the defect this test exists for): the
    /// roster map is keyed by whichever id this daemon learned the group
    /// under, while history rows are scoped by the group's STABLE id. A
    /// single-spelling `groups.get(scope_id)` therefore misses the marker
    /// for every alias-keyed group — and on THIS path a missed marker is not
    /// a missing label, it is `Store::purge` destroying the forensic record
    /// of a quarantined group. That is row 14's exact failure mode, reached
    /// with the very scope string `GET /history/scopes` hands the operator.
    ///
    /// The tests above cannot catch it: they seed map key and rows under one
    /// spelling, so a bare `get` looks correct. This one makes key ≠ stable
    /// id, purges by the STABLE id (the rows' own spelling), and checks the
    /// store afterwards.
    #[tokio::test]
    async fn alias_keyed_purge_is_refused_under_the_stable_scope_and_the_store_is_untouched(
    ) -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = history_state(dir.path()).await?;
        seed_alias_rows(&state);
        quarantine_under(&state, ALIAS_KEY, ALIAS_STABLE).await;
        let app = full_history_router(Arc::clone(&state));
        let before = store_snapshot(&state);
        assert_eq!(before.len(), 2, "precondition: two alias-scoped rows");
        assert!(
            before
                .iter()
                .all(|(_, scope, _, _)| scope == "group:stable-id-s"),
            "precondition: rows carry the STABLE spelling, not the map key: {before:?}"
        );

        // The spelling an operator actually holds: the one /history/scopes
        // lists and the rows carry.
        let (status, json) = call(&app, "DELETE", "/history?scope=group:stable-id-s").await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a purge naming the STABLE id must still find the alias-keyed marker: {json}"
        );
        assert_eq!(
            store_snapshot(&state),
            before,
            "the alias-keyed group's forensic record must survive a purge attempt"
        );
        assert_eq!(json["reason"], "fork_quarantined", "{json}");
        // The §5 remedy must name the MAP KEY: `clear_group_quarantine`
        // looks its group up by map key only, so a sentence naming the
        // stable id would hand the operator an id the clear route cannot
        // find.
        let message = json["error"].as_str().unwrap_or_default();
        assert!(
            message.contains(ALIAS_KEY),
            "the remedy must name the id the clear route accepts ({ALIAS_KEY}): {json}"
        );

        // Reverse spelling: a caller naming the ALIAS is refused too (the
        // direct key hit). Its rows live under the stable id, so even a
        // permitted purge would have deleted nothing — but the refusal is
        // what keeps the two spellings from disagreeing about one group.
        let (status, json) = call(&app, "DELETE", "/history?scope=group:alias-key-a").await;
        assert_eq!(status, StatusCode::CONFLICT, "alias spelling: {json}");
        assert_eq!(store_snapshot(&state), before, "still untouched");

        // A DM scope with the same text is not group state and never
        // consults the marker — proof the gate keys on the group, not on
        // the string.
        let (status, json) = call(&app, "DELETE", "/history?scope=dm:stable-id-s").await;
        assert_eq!(status, StatusCode::OK, "dm scopes are unaffected: {json}");
        Ok(())
    }

    /// WHY (review r1, rows 13 and 26): the same alias miss silently
    /// un-annotates every read surface for exactly one group — the operator
    /// sees an ordinary history during a live fork. Each surface is driven
    /// with the STABLE spelling, because that is what the rows and
    /// `/history/scopes` carry, and `markers_for_scopes` is additionally
    /// exercised with BOTH spellings because it is the shared path
    /// `GET /groups/:id/messages` (`named_groups.rs`) annotates through.
    #[tokio::test]
    async fn alias_keyed_group_annotates_every_read_surface_and_tags_ingest() -> anyhow::Result<()>
    {
        let dir = tempfile::tempdir()?;
        let state = history_state(dir.path()).await?;
        seed_alias_rows(&state);
        quarantine_under(&state, ALIAS_KEY, ALIAS_STABLE).await;
        let app = full_history_router(Arc::clone(&state));

        // Scoped list: annotated, and the ingest tag discriminates the row
        // that arrived after the evidence (R3 tag-and-retain).
        let (status, list) = call(&app, "GET", "/history?scope=group:stable-id-s").await;
        assert_eq!(status, StatusCode::OK, "reads never refuse: {list}");
        assert_eq!(list["count"], 2, "both alias rows still serve: {list}");
        assert_eq!(list["fork_quarantined"], true, "{list}");
        assert_eq!(
            list["fork_quarantine"]["scopes"][0]["scope"], "group:stable-id-s",
            "the annotation names the scope the caller asked for: {list}"
        );
        assert_eq!(list["fork_quarantine"]["scopes"][0]["no_anchor"], true);
        let tagged = list["records"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter(|row| {
                        row["fork_quarantined_at_ingest"] == serde_json::Value::Bool(true)
                    })
                    .count()
            })
            .unwrap_or_default();
        assert_eq!(
            tagged, 1,
            "exactly the post-evidence alias row is tagged: {list}"
        );

        // Cross-scope search, scope enumeration, and the two node-wide
        // surfaces.
        for path in [
            "/history/search?q=alias",
            "/history/scopes",
            "/history/stats",
            "/diagnostics/history",
        ] {
            let (status, json) = call(&app, "GET", path).await;
            assert_eq!(status, StatusCode::OK, "{path}: {json}");
            assert_eq!(
                json["fork_quarantined"], true,
                "{path} must label the alias-keyed group: {json}"
            );
        }

        // The node-wide surfaces list BOTH spellings, so the operator can
        // match the scope their rows carry AND the id the clear route takes.
        let (_, stats) = call(&app, "GET", "/history/stats").await;
        let listed: Vec<&str> = stats["fork_quarantine"]["scopes"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| row["scope"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            listed,
            vec!["group:alias-key-a", "group:stable-id-s"],
            "both spellings, sorted: {stats}"
        );

        // Point lookup by dedupe id, with no `?scope=` at all: the row's own
        // scope resolves the marker.
        let msg_id = hex::encode(x0x::history::HistoryRecord::compute_msg_id(
            None,
            b"alias row after the fork",
        ));
        let (status, one) = call(&app, "GET", &format!("/history/message/{msg_id}")).await;
        assert_eq!(status, StatusCode::OK, "{one}");
        assert_eq!(one["fork_quarantined"], true, "{one}");
        assert_eq!(
            one["record"]["fork_quarantined_at_ingest"],
            serde_json::Value::Bool(true),
            "{one}"
        );

        // The shared resolver both this module and `/groups/:id/messages`
        // annotate through: EITHER spelling finds the one marker.
        for spelling in [ALIAS_STABLE, ALIAS_KEY] {
            let markers =
                markers_for_scopes(&state, std::iter::once(&Scope::Group(spelling.to_string())))
                    .await;
            assert_eq!(
                markers.len(),
                1,
                "markers_for_scopes must resolve `{spelling}` to the alias-keyed marker"
            );
            assert_eq!(markers[0].0, format!("group:{spelling}"));
            assert_eq!(markers[0].1.revision, 9);
        }

        // And a group that is not quarantined at all stays unlabelled even
        // though it shares the store.
        unquarantined(&state, CLEAN).await;
        let (_, other) = call(&app, "GET", "/history?scope=group:quiet-group").await;
        assert!(
            other.get("fork_quarantined").is_none(),
            "the control group must not inherit the neighbour's label: {other}"
        );
        Ok(())
    }
}
