//! Task-list REST handlers (`category: "tasks"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate as x0x;

use super::super::crdt_subscriptions;
use super::super::state::AppState;
use super::super::{api_error, bad_request, forbidden, not_found};

// ---------------------------------------------------------------------------
// Group-membership enforcement (#153)
// ---------------------------------------------------------------------------
//
// Task-list REST endpoints are local daemon control-plane endpoints
// authenticated by the daemon's bearer API token (`src/server/auth.rs`
// `auth_middleware`). That token authenticates the daemon, NOT a remote
// requester agent — there is no per-request agent identity in this path.
//
// So group isolation is enforced against the daemon's *local* agent: if a
// task-list id is group-scoped, the daemon's local agent must be an ACTIVE
// member of that named group, otherwise the handler returns 403. This gives
// hard cross-daemon isolation (a daemon whose local agent is not in group G
// cannot read/write G's task lists via its own REST API) and is what the
// x0x-symphony XSY-0021 two-daemon isolation test proves. Non-group-scoped
// ids are unchanged.
//
// Fail-closed: a malformed scoped id, a missing group, or a
// non-active/non-member local agent all deny. See `ensure_task_list_access`.

/// Symphony's group-scoped task-list id convention:
/// `x0x.group.<group_id>.symphony.<list_id>`.
///
/// Returns the parsed `<group_id>` when `id` is group-scoped, or `None` for a
/// plain (non-scoped) task-list id. A string that *looks* scoped but is
/// malformed (wrong segment count, empty group id, …) is NOT treated as
/// plain: callers must deny it via [`ensure_task_list_access`].
pub(in crate::server) fn parse_group_scoped_task_list_id(id: &str) -> Option<GroupScopedId> {
    // Split on '.' but keep it simple and strict: exactly 5 non-empty segments
    // `x0x . group . <group_id> . symphony . <list_id>`.
    let parts: Vec<&str> = id.split('.').collect();
    if parts.len() != 5 {
        return None;
    }
    if parts[0] != "x0x" || parts[1] != "group" || parts[3] != "symphony" {
        return None;
    }
    let group_id = parts[2];
    let list_id = parts[4];
    if group_id.is_empty() || list_id.is_empty() {
        // Malformed scoped id — signal "looked scoped but invalid" distinctly
        // from a plain id by returning Some with an empty group id, which the
        // guard treats as deny. We use a dedicated sentinel for clarity.
        return Some(GroupScopedId::malformed());
    }
    Some(GroupScopedId {
        group_id: group_id.to_string(),
        list_id: list_id.to_string(),
    })
}

/// A parsed group-scoped task-list id, or a malformed sentinel.
///
/// `list_id` is retained for diagnostics/future use but is not consulted by
/// the membership guard (only `group_id` is needed to check access).
#[derive(Debug, PartialEq, Eq)]
pub(in crate::server) struct GroupScopedId {
    pub(in crate::server) group_id: String,
    #[allow(dead_code)]
    pub(in crate::server) list_id: String,
}

impl GroupScopedId {
    /// Sentinel for an id that looked scoped (`x0x.group.…`) but was malformed.
    /// `group_id` is empty so the guard cannot find a matching group ⇒ deny.
    pub(in crate::server) fn malformed() -> Self {
        Self {
            group_id: String::new(),
            list_id: String::new(),
        }
    }

    pub(in crate::server) fn is_malformed(&self) -> bool {
        self.group_id.is_empty()
    }
}

/// Enforcement guard for group-scoped task lists (#153).
///
/// - Non-scoped id  ⇒ allow (returns `Ok(())`).
/// - Group-scoped id ⇒ allow only if the daemon's local agent is an ACTIVE
///   member of the named group in `state.named_groups`.
/// - Malformed scoped id, missing group, or non-member ⇒ `Err(403)`.
///
/// `Ok(())` means the caller may proceed; the `Err` is an `impl IntoResponse`
/// 403 ready to return.
pub(in crate::server) async fn ensure_task_list_access(
    state: &Arc<AppState>,
    id: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let Some(scoped) = parse_group_scoped_task_list_id(id) else {
        // Plain (non-group-scoped) task-list id — unchanged behavior.
        return Ok(());
    };
    if scoped.is_malformed() {
        return Err(forbidden("malformed group-scoped task-list id"));
    }
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let Some(info) = groups.get(&scoped.group_id) else {
        // Unknown group ⇒ fail closed. We do NOT reveal whether the group
        // exists to a non-member, but the id namespace is public-by-convention
        // so a plain 403 is the safe, non-leaky response.
        return Err(forbidden("not a member of task-list group"));
    };
    let member = info.members_v2.get(&local_agent_hex);
    let allowed = member.is_some_and(|m| matches!(m.state, x0x::groups::GroupMemberState::Active));
    if allowed {
        Ok(())
    } else {
        Err(forbidden("not a member of task-list group"))
    }
}

/// Apply group authorization to a task list handle at the CRDT layer.
///
/// If the list `id` is group-scoped (`x0x.group.<gid>.symphony.<lid>`), look
/// up the group's active members and call `set_authorized_agents` so remote
/// CRDT admission rejects claims/completions from non-members. For plain
/// (non-scoped) lists this is a no-op.
///
/// This closes the gap where group membership was enforced at REST but not at
/// replication admission: a remote peer who subscribes to the topic but is not
/// a group member cannot inject operations even with a valid signature.
pub(in crate::server) async fn apply_group_authorization(
    state: &Arc<AppState>,
    id: &str,
    handle: &x0x::TaskListHandle,
) {
    let Some(scoped) = parse_group_scoped_task_list_id(id) else {
        return; // plain list — no group authorization
    };
    if scoped.is_malformed() {
        return;
    }
    let mut agents = std::collections::HashSet::new();
    {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&scoped.group_id) else {
            return; // unknown group — can't authorize; leave open
        };
        for (agent_hex, member) in &info.members_v2 {
            if matches!(member.state, x0x::groups::GroupMemberState::Active) {
                if let Ok(bytes) = hex::decode(agent_hex) {
                    if bytes.len() == x0x::identity::PEER_ID_LENGTH {
                        let mut arr = [0u8; x0x::identity::PEER_ID_LENGTH];
                        arr.copy_from_slice(&bytes);
                        agents.insert(x0x::identity::AgentId(arr));
                    }
                }
            }
        }
    }
    handle.set_authorized_agents(agents).await;
}

// ---------------------------------------------------------------------------
// Request / response DTOs
// ---------------------------------------------------------------------------

/// POST /task-lists request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct CreateTaskListRequest {
    pub(in crate::server) name: String,
    pub(in crate::server) topic: String,
}

/// POST /task-lists/:id/tasks request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct AddTaskRequest {
    pub(in crate::server) title: String,
    #[serde(default)]
    pub(in crate::server) description: Option<String>,
}

/// PATCH /task-lists/:id/tasks/:tid request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct UpdateTaskRequest {
    pub(in crate::server) action: String, // "claim" or "complete"
    /// Optional **local-replica** fencing precondition (opaque token). Echo
    /// the `fence_token` from a prior GET/mutation verbatim. If it does not
    /// match THIS daemon's current `(epoch, revision)`, the mutation is
    /// rejected with 409 and nothing changes. This is NOT a distributed
    /// compare-and-swap: two daemons at the same token both accept. A token
    /// captured before a daemon restart never matches post-restart (the epoch
    /// differs), closing the restart-ABA window.
    #[serde(default)]
    pub(in crate::server) fence_token: Option<String>,
}

/// Task list entry.
#[derive(Debug, Serialize)]
pub(in crate::server) struct TaskListEntry {
    pub(in crate::server) id: String,
    pub(in crate::server) topic: String,
}

/// Task snapshot for API response.
#[derive(Debug, Serialize)]
pub(in crate::server) struct TaskEntry {
    pub(in crate::server) id: String,
    pub(in crate::server) title: String,
    pub(in crate::server) description: String,
    /// Legacy Display string ("empty" | "claimed:<hex>" | "done:<hex>").
    /// Kept for backward compatibility — prefer the structured fields below.
    pub(in crate::server) state: String,
    pub(in crate::server) assignee: Option<String>,
    pub(in crate::server) priority: u8,
    /// Hex AgentId of the deterministic claim winner; null if never claimed.
    pub(in crate::server) claimed_by: Option<String>,
    /// Unix-ms timestamp of the winning claim; null if never claimed.
    pub(in crate::server) claimed_at: Option<u64>,
    /// Hex AgentId of the deterministic completion winner; null unless done.
    pub(in crate::server) completed_by: Option<String>,
    /// Unix-ms timestamp of the winning completion; null unless done.
    pub(in crate::server) completed_at: Option<u64>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /task-lists
pub(in crate::server) async fn list_task_lists(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Snapshot the keys, then release the lock before the per-id membership
    // check (which takes `named_groups.read()`). Holding both read locks at
    // once is safe for an RwLock, but collecting first keeps the critical
    // section short and avoids re-entrancy surprises.
    let ids: Vec<String> = state.task_lists.read().await.keys().cloned().collect();
    // #153: filter the collection through the same membership guard as the
    // per-id read/write handlers, so this endpoint does not leak the existence
    // or exact topics of group-scoped task lists the local agent is not an
    // active member of. (The per-id handlers already 403 those; this prevents
    // the collection from enumerating them.) Red-team review of #166 found
    // this collection endpoint was the sole unguarded path.
    let mut entries = Vec::with_capacity(ids.len());
    for id in ids {
        if ensure_task_list_access(&state, &id).await.is_ok() {
            entries.push(TaskListEntry {
                id: id.clone(),
                topic: id, // topic is used as ID
            });
        }
    }
    Json(serde_json::json!({ "ok": true, "task_lists": entries }))
}

/// POST /task-lists
pub(in crate::server) async fn create_task_list(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTaskListRequest>,
) -> impl IntoResponse {
    // #153: creating a group-scoped task list requires membership of that group.
    if let Err(denied) = ensure_task_list_access(&state, &req.topic).await {
        return denied;
    }
    let id = req.topic.clone();
    // Reserve the entire handle+manifest transaction for this (kind,id) so
    // a concurrent create/rehydrate for the same id cannot interleave handle
    // insertion with failure rollback, or spawn a duplicate listener.
    let reservation =
        crdt_subscriptions::handle_reservation(&state, crdt_subscriptions::KIND_TASK_LIST, &id)
            .await;
    let _guard = reservation.lock().await;
    // Under the reservation: if a handle already exists (created by a prior
    // successful request or rehydration), return conflict rather than
    // overwriting it and leaking the existing sync listener.
    if state.task_lists.read().await.contains_key(&id) {
        return api_error(StatusCode::CONFLICT, "task list already exists");
    }
    match state.agent.create_task_list(&req.name, &req.topic).await {
        Ok(handle) => {
            let version = handle.version().await;
            // Apply group authorization at the CRDT layer so remote admission
            // rejects nonmember operations for group-scoped lists. Runs inside
            // the reservation guard (serialized per (kind,id)).
            apply_group_authorization(&state, &id, &handle).await;
            state.task_lists.write().await.insert(id.clone(), handle);
            // Persist the registration so it survives a daemon restart
            // (rehydrated after join_network — see crdt_subscriptions). This
            // is a durable transaction: if the manifest write fails we roll
            // back the just-inserted live handle and surface the error, so the
            // registration is never acknowledged as durable when it is not.
            let entry = crdt_subscriptions::CrdtSubscriptionEntry {
                kind: crdt_subscriptions::KIND_TASK_LIST.to_string(),
                id: id.clone(),
                name: req.name.clone(),
                topic: req.topic.clone(),
                role: crdt_subscriptions::ROLE_CREATED.to_string(),
                extra: serde_json::Map::new(),
            };
            if let Err(e) = crdt_subscriptions::record(&state, entry).await {
                tracing::error!(
                    topic = %req.topic,
                    "failed to persist task-list subscription registration: {e}"
                );
                state.task_lists.write().await.remove(&id);
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to persist subscription registration",
                );
            }
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "ok": true,
                    "id": id,
                    "version": version.revision,
                    "fence_token": version.to_wire(),
                    "committed": "local",
                })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /task-lists/:id/tasks
pub(in crate::server) async fn list_tasks(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // #153: group-scoped task lists require local-agent membership.
    if let Err(denied) = ensure_task_list_access(&state, &id).await {
        return denied;
    }
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return not_found("task list not found");
    };

    match handle.list_tasks_with_version().await {
        Ok((tasks, fence)) => {
            let entries: Vec<TaskEntry> = tasks
                .into_iter()
                .map(|t| TaskEntry {
                    id: format!("{}", t.id),
                    title: t.title,
                    description: t.description,
                    state: format!("{}", t.state),
                    assignee: t.assignee.map(|a| hex::encode(a.as_bytes())),
                    priority: t.priority,
                    claimed_by: t.claimed_by.map(|a| hex::encode(a.as_bytes())),
                    claimed_at: t.claimed_at,
                    completed_by: t.completed_by.map(|a| hex::encode(a.as_bytes())),
                    completed_at: t.completed_at,
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "version": fence.revision,
                    "fence_token": fence.to_wire(),
                    "tasks": entries,
                })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// POST /task-lists/:id/tasks
pub(in crate::server) async fn add_task(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AddTaskRequest>,
) -> impl IntoResponse {
    // #153: group-scoped task lists require local-agent membership (write too).
    if let Err(denied) = ensure_task_list_access(&state, &id).await {
        return denied;
    }
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return not_found("task list not found");
    };

    match handle
        .add_task_versioned(req.title, req.description.unwrap_or_default())
        .await
    {
        Ok((task_id, version)) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "ok": true,
                "task_id": format!("{task_id}"),
                "version": version,
                "committed": "local",
            })),
        ),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// PATCH /task-lists/:id/tasks/:tid
pub(in crate::server) async fn update_task(
    State(state): State<Arc<AppState>>,
    Path((id, tid)): Path<(String, String)>,
    Json(req): Json<UpdateTaskRequest>,
) -> impl IntoResponse {
    // #153: group-scoped task lists require local-agent membership (write too).
    if let Err(denied) = ensure_task_list_access(&state, &id).await {
        return denied;
    }
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return not_found("task list not found");
    };

    // Parse task ID from hex
    let task_id_bytes: [u8; 32] = match hex::decode(&tid) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return bad_request("invalid task ID (expected 64 hex chars)");
        }
    };
    let task_id = x0x::crdt::TaskId::from_bytes(task_id_bytes);

    // Parse the opaque fence token.
    //
    // Distinguish **absent** (None ⇒ unconditional advisory commit) from
    // **present but malformed** (parse error ⇒ 400 BAD_REQUEST, non-mutating).
    // Collapsing the two would let a corrupt/legacy/attacker token silently
    // downgrade a fenced request to an unfenced mutation.
    let expected = match req.fence_token.as_deref() {
        None => None,
        Some(s) => match x0x::FenceToken::from_wire(s) {
            Ok(token) => Some(token),
            Err(_) => {
                // Machine-readable error code — the API contract (and
                // daemon_api_claim_malformed_fence_token_is_rejected_non_mutating)
                // matches on this exact string.
                return bad_request("malformed_fence_token");
            }
        },
    };

    let result = match req.action.as_str() {
        "claim" => handle.claim_task_versioned(task_id, expected).await,
        "complete" => handle.complete_task_versioned(task_id, expected).await,
        _ => {
            return bad_request("action must be 'claim' or 'complete'");
        }
    };

    match result {
        // `committed:"local"` makes explicit that success = local CRDT
        // commit + best-effort delta publish — NOT replicated observation and
        // NOT exclusive ownership. The `resolution` block reports the local
        // OR-Set snapshot at commit time; the deterministic winner may change
        // when concurrent operations from other replicas merge in. `cas.scope`
        // localizes the version guard; `execution.authorization:"advisory"`
        // and `exclusive:false` make the non-exclusive status unambiguous, so
        Ok(x0x::TaskMutationOutcome::Committed { fence, advisory }) => {
            let current_winner = advisory.current_winner.map(|(agent, ts)| {
                serde_json::json!({
                    "agent_id": hex::encode(agent.as_bytes()),
                    "timestamp_ms": ts,
                })
            });
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "version": fence.revision,
                    "fence_token": fence.to_wire(),
                    "committed": "local",
                    "resolution": {
                        "agent_id": hex::encode(advisory.agent.as_bytes()),
                        "locally_winning": advisory.locally_winning,
                        "current_winner": current_winner,
                        "pending_convergence": true,
                    },
                    "cas": { "scope": "local_replica" },
                    "execution": { "authorization": "advisory" },
                    "exclusive": false,
                })),
            )
        }
        Ok(x0x::TaskMutationOutcome::StaleLocalVersion { current }) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "error": "stale_local_version",
                "current_version": current.revision,
                "fence_token": current.to_wire(),
                "cas": { "scope": "local_replica" },
            })),
        ),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_group_scoped_task_list_id: the security crown jewel ──────────
    //
    // The parser's contract is the foundation of #153's fail-closed
    // property. It must partition every input into exactly one of:
    //   - None              ⇒ plain id, ALLOW (unchanged behavior)
    //   - Some(valid)       ⇒ group-scoped, defer to membership check
    //   - Some(malformed)   ⇒ looked scoped but invalid, DENY
    // A misspelled prefix (`x0x.grop.…`) MUST NOT silently fall through to the
    // plain-id allow path, and a malformed scoped id MUST NOT be treated as a
    // valid group lookup.

    #[test]
    fn parser_recognizes_well_formed_scoped_id() {
        let parsed = parse_group_scoped_task_list_id("x0x.group.acme-corp.symphony.inbox");
        let scoped = parsed.expect("well-formed scoped id parses");
        assert!(!scoped.is_malformed());
        assert_eq!(scoped.group_id, "acme-corp");
    }

    #[test]
    fn parser_treats_plain_id_as_none() {
        // A non-scoped topic is unchanged behavior — must return None so the
        // guard allows it without any group lookup.
        assert_eq!(parse_group_scoped_task_list_id("plain-topic"), None);
        assert_eq!(parse_group_scoped_task_list_id("inbox"), None);
        assert_eq!(parse_group_scoped_task_list_id(""), None);
        // A 4-segment id is NOT the scoped shape (needs exactly 5).
        assert_eq!(parse_group_scoped_task_list_id("x0x.group.acme"), None);
        // 6 segments is also not the shape.
        assert_eq!(
            parse_group_scoped_task_list_id("x0x.group.acme.symphony.inbox.extra"),
            None
        );
    }

    #[test]
    fn parser_rejects_wrong_prefix_as_plain() {
        // A scoped shape with a misspelled prefix is NOT treated as scoped —
        // it falls through to plain (None). This is safe because such an id
        // is genuinely not the symphony convention; treating it as scoped
        // would be over-eager denial of legitimate plain ids.
        assert_eq!(
            parse_group_scoped_task_list_id("x0x.grop.acme.symphony.inbox"),
            None
        );
        assert_eq!(
            parse_group_scoped_task_list_id("foo.group.acme.symphony.inbox"),
            None
        );
        assert_eq!(
            parse_group_scoped_task_list_id("x0x.group.acme.secure.inbox"),
            None // wrong 4th segment (not "symphony")
        );
    }

    #[test]
    fn parser_flags_empty_group_or_list_as_malformed() {
        // A scoped *shape* with an empty group_id or list_id is malformed and
        // MUST be denied (Some(malformed)), never allowed as plain.
        let empty_group = parse_group_scoped_task_list_id("x0x.group..symphony.inbox");
        let scoped = empty_group.expect("scoped shape with empty group is Some");
        assert!(scoped.is_malformed(), "empty group_id ⇒ malformed ⇒ deny");

        let empty_list = parse_group_scoped_task_list_id("x0x.group.acme.symphony.");
        let scoped = empty_list.expect("scoped shape with empty list is Some");
        assert!(scoped.is_malformed(), "empty list_id ⇒ malformed ⇒ deny");
    }

    // ── UpdateTaskRequest strict parsing: no silent fence downgrade ────────
    //
    // The PATCH claim/complete body must reject unknown fields. The pre-fence
    // API used `expected_version`; a client still sending it MUST get a 4xx
    // (serde reject → axum Json extractor), NOT a silent ignore that drops the
    // field and downgrades the request to fence_token=None (unfenced) — which
    // would let a stale claim commit 200. `deny_unknown_fields` enforces this.

    #[test]
    fn update_task_request_rejects_obsolete_expected_version_field() {
        // The obsolete pre-fence field is now unknown → rejected, not ignored.
        let obsolete =
            serde_json::from_str::<UpdateTaskRequest>(r#"{"action":"claim","expected_version":3}"#);
        assert!(
            obsolete.is_err(),
            "obsolete expected_version must be rejected (4xx), not silently \
             downgraded to an unfenced claim"
        );
    }

    #[test]
    fn update_task_request_accepts_current_contract_and_rejects_typos() {
        // fence_token provided (fenced) parses.
        let fenced =
            serde_json::from_str::<UpdateTaskRequest>(r#"{"action":"claim","fence_token":"1:2"}"#);
        assert!(fenced.is_ok(), "fenced request parses");
        // fence_token omitted (unfenced) is still a valid shape — strictness is
        // about UNKNOWN fields, not requiring a fence.
        let unfenced = serde_json::from_str::<UpdateTaskRequest>(r#"{"action":"claim"}"#);
        assert!(unfenced.is_ok(), "unfenced request parses");
        // A typo'd field name is also rejected (defense in depth).
        let typo =
            serde_json::from_str::<UpdateTaskRequest>(r#"{"action":"claim","fence_tokn":"1:2"}"#);
        assert!(typo.is_err(), "typo'd field name must be rejected");
    }
}
