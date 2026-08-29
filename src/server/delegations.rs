//! ADR-0040 daemon-side delegation routing.
//!
//! One effectiveness rule (blocker 28): a delegation is effective iff its
//! carrier message is durably committed in THIS daemon's group history
//! (ADR-0023). [`DelegationIndex`] is a lazily-built, in-memory view over
//! those durable rows — a crash or restart simply re-derives it from
//! history on first use. The DM-v2 durable-ACK handoff to the delegate is
//! a NOTIFICATION on top of that rule, never the source of truth.

use std::collections::HashMap;

use crate as x0x;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

use crate::server::state::AppState;

/// Prefix marking a delegation-handoff DM payload (ADR-0040 notification).
pub(crate) const DELEGATION_DM_PREFIX: &[u8] = b"x0x-delegation:v1:";

/// Per-group view of durably-committed delegation envelopes.
#[derive(Debug, Default)]
pub(crate) struct DelegationIndex {
    /// True once the index has been (re)built from durable history. A
    /// restarted daemon starts empty+unloaded and rebuilds on first use.
    loaded: bool,
    /// Verified envelopes keyed by delegation digest. Presence == the
    /// carrier is durably committed locally.
    by_digest: HashMap<[u8; 32], x0x::delegation::SignedDelegation>,
}

/// Extract + verify every delegation envelope from a group's durable
/// history rows.
///
/// Pure function over rows: parse the carrier artifact, keep only
/// `kind == "delegation"` messages, decode the
/// [`x0x::delegation::SignedDelegation`] body, verify it against the
/// delegator's own key, and key it by digest. Invalid carriers are skipped
/// (fail-closed): a malformed row means the envelope never becomes
/// effective here until a valid copy arrives.
fn index_from_rows(
    rows: &[x0x::history::StoredRecord],
) -> HashMap<[u8; 32], x0x::delegation::SignedDelegation> {
    let mut map = HashMap::new();
    for row in rows {
        let Some(artifact) = row.record.signed_artifact.as_deref() else {
            continue;
        };
        let Ok(carrier) = serde_json::from_slice::<x0x::groups::GroupPublicMessage>(artifact)
        else {
            continue;
        };
        if !matches!(
            carrier.kind,
            x0x::groups::GroupPublicMessageKind::Delegation
        ) {
            continue;
        }
        let Ok(sd) = serde_json::from_str::<x0x::delegation::SignedDelegation>(&carrier.body)
        else {
            continue;
        };
        if x0x::delegation::verify_delegation(&sd).is_ok() {
            map.insert(x0x::delegation::signed_delegation_digest(&sd), sd);
        }
    }
    map
}

/// Ensure the per-group index is loaded from durable history, then return a
/// snapshot of every durably-committed envelope.
pub(in crate::server) async fn committed_delegations(
    state: &AppState,
    group_id: &str,
) -> Vec<x0x::delegation::SignedDelegation> {
    // Fast path: already loaded.
    {
        let index = state.delegation_index.read().await;
        if let Some(loaded) = index.get(group_id) {
            if loaded.loaded {
                return loaded.by_digest.values().cloned().collect();
            }
        }
    }
    // Slow path: rebuild from THIS daemon's durable history (blocker 28:
    // crash/restart re-derives from the store).
    let mut map = HashMap::new();
    if let Some(history) = state.agent.history() {
        let store = std::sync::Arc::clone(history.store());
        let scope = group_id.to_string();
        let queried = tokio::task::spawn_blocking(move || {
            let q = x0x::history::HistoryQuery {
                scope: Some(x0x::history::Scope::Group(scope)),
                limit: 1000,
                ..Default::default()
            };
            store.query(&q)
        })
        .await;
        if let Ok(Ok(rows)) = queried {
            map = index_from_rows(&rows);
        }
    }
    let mut index = state.delegation_index.write().await;
    let entry = index.entry(group_id.to_string()).or_default();
    entry.loaded = true;
    entry.by_digest = map;
    entry.by_digest.values().cloned().collect()
}

/// Record a just-committed delegation into the index (called only after the
/// carrier's SQLite transaction committed).
pub(in crate::server) async fn index_committed(
    state: &AppState,
    group_id: &str,
    sd: x0x::delegation::SignedDelegation,
) {
    let mut index = state.delegation_index.write().await;
    let entry = index.entry(group_id.to_string()).or_default();
    entry.loaded = true;
    entry
        .by_digest
        .insert(x0x::delegation::signed_delegation_digest(&sd), sd);
}

/// Is `sd` an effective authorization for `actor` to exercise `verb` in
/// `group_id` at `now_ms`?
///
/// Checks (in order): `to_agent == actor` (only the delegate may act —
/// blocker 25: the actor signs with its own key, so identity is the actor,
/// never the delegator), scope/verb match, not expired, and — for depth-2
/// chains — the parent grant is itself committed and chains correctly.
pub(in crate::server) fn authorize(
    sd: &x0x::delegation::SignedDelegation,
    actor: &x0x::identity::AgentId,
    verb: x0x::delegation::DelegationVerb,
    group_id: &str,
    now_ms: u64,
    committed: &[x0x::delegation::SignedDelegation],
) -> Result<(), String> {
    let d = &sd.delegation;
    if d.group_id != group_id {
        return Err(format!(
            "delegation is for group {}, not {}",
            d.group_id, group_id
        ));
    }
    if d.to_agent != *actor {
        return Err("actor is not the delegate of this delegation".into());
    }
    if d.authority_scope != verb.scope() {
        return Err(format!(
            "verb {verb:?} is outside the delegation's scope {:?}",
            d.authority_scope
        ));
    }
    if !d.verbs.contains(&verb) {
        return Err(format!("verb {verb:?} is not granted by this delegation"));
    }
    if !x0x::delegation::is_effective_time(d, now_ms) {
        return Err("delegation has expired".into());
    }
    if d.depth > 1 {
        // Re-delegation: the parent must also be durably committed and the
        // chain must verify. Authority that cannot be traced to a committed
        // root is not authority.
        let Some(parent_digest) = d.parent_delegation else {
            return Err("re-delegation without a parent digest".into());
        };
        let parent = committed
            .iter()
            .find(|p| x0x::delegation::signed_delegation_digest(p) == parent_digest);
        let Some(parent) = parent else {
            return Err("parent delegation is not durably committed here".into());
        };
        if let Err(e) = x0x::delegation::verify_chain(parent, sd) {
            return Err(format!("chain verification failed: {e}"));
        }
    }
    Ok(())
}

/// Look up + authorize a send-as message's delegation reference (hex digest)
/// against the committed set. Returns the envelope so the caller can derive
/// `delegator` attribution.
pub(in crate::server) async fn authorize_send_as(
    state: &AppState,
    group_id: &str,
    actor: &x0x::identity::AgentId,
    digest_hex: &str,
    now_ms: u64,
) -> Result<x0x::delegation::SignedDelegation, String> {
    let digest = hex::decode(digest_hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok());
    let Some(digest) = digest else {
        return Err("delegation_digest must be 64 hex chars".into());
    };
    let committed = committed_delegations(state, group_id).await;
    let sd = committed
        .iter()
        .find(|sd| x0x::delegation::signed_delegation_digest(sd) == digest);
    let Some(sd) = sd else {
        // Effectiveness rule: an un-committed delegation never authorizes,
        // even if the envelope itself is otherwise valid.
        return Err(
            "referenced delegation is not durably committed in this group's history".into(),
        );
    };
    authorize(
        sd,
        actor,
        x0x::delegation::DelegationVerb::SendPublicMessage,
        group_id,
        now_ms,
        &committed,
    )
    .map(|()| sd.clone())
}

// ───────────────────────────── REST handlers ─────────────────────────────

/// POST /groups/:id/delegate request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct DelegateRequest {
    /// Hex AgentId of the delegate.
    to_agent: String,
    /// `"task_execute"` or `"send_as"`.
    scope: String,
    /// Granted verbs; subset of the scope's verbs. Default: all of them.
    #[serde(default)]
    verbs: Option<Vec<String>>,
    /// Unix-ms expiry (required — authority must be bounded).
    expiry_ms: u64,
    /// Hex TaskId for `task_execute`.
    #[serde(default)]
    task: Option<String>,
    /// Hex parent delegation digest for re-delegation (depth 2).
    #[serde(default)]
    parent: Option<String>,
}

/// POST /groups/:id/delegate — issue a signed delegation (ADR-0040).
///
/// Effectiveness contract: 200 is returned ONLY after the carrier message's
/// history row has committed to SQLite. The DM handoff to the delegate is a
/// best-effort NOTIFICATION reported in the response — its failure never
/// revokes the (already effective) delegation, and its success is never
/// what makes the delegation effective.
pub(in crate::server) async fn delegate_group_authority(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<DelegateRequest>,
) -> impl IntoResponse {
    let local = state.agent.agent_id();
    let local_hex = hex::encode(local.as_bytes());
    let now_ms = crate::server::routes::now_millis_u64();

    // Parse the delegate.
    let to_bytes = hex::decode(&req.to_agent).ok().filter(|b| b.len() == 32);
    let Some(to_bytes) = to_bytes else {
        return bad_request("to_agent must be 64 hex chars (AgentId)");
    };
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&to_bytes);
    let to_agent = x0x::identity::AgentId(arr);

    // Parse scope + verbs.
    let scope = match req.scope.as_str() {
        "task_execute" => x0x::delegation::AuthorityScope::TaskExecute,
        "send_as" => x0x::delegation::AuthorityScope::SendAs,
        other => {
            return bad_request(format!(
                "unknown scope '{other}' (expected 'task_execute' or 'send_as')"
            ));
        }
    };
    let all_verbs = match scope {
        x0x::delegation::AuthorityScope::TaskExecute => vec![
            x0x::delegation::DelegationVerb::Claim,
            x0x::delegation::DelegationVerb::Complete,
        ],
        x0x::delegation::AuthorityScope::SendAs => {
            vec![x0x::delegation::DelegationVerb::SendPublicMessage]
        }
    };
    let verbs = match &req.verbs {
        None => all_verbs,
        Some(requested) => {
            let mut selected = Vec::new();
            for v in requested {
                let verb = match v.as_str() {
                    "claim" => x0x::delegation::DelegationVerb::Claim,
                    "complete" => x0x::delegation::DelegationVerb::Complete,
                    "send_public_message" => x0x::delegation::DelegationVerb::SendPublicMessage,
                    other => {
                        return bad_request(format!("unknown verb '{other}'"));
                    }
                };
                if !all_verbs.contains(&verb) {
                    return bad_request(format!("verb '{v}' is outside scope '{}'", req.scope));
                }
                selected.push(verb);
            }
            if selected.is_empty() {
                return bad_request("verbs must not be empty");
            }
            selected
        }
    };
    let task_ref = match (&req.task, scope) {
        (Some(t), x0x::delegation::AuthorityScope::TaskExecute) => {
            let bytes = hex::decode(t).ok().filter(|b| b.len() == 32);
            let Some(bytes) = bytes else {
                return bad_request("task must be 64 hex chars (TaskId)");
            };
            let mut t = [0u8; 32];
            t.copy_from_slice(&bytes);
            Some(t)
        }
        (Some(_), _) => {
            return bad_request("task is only valid for scope 'task_execute'");
        }
        (None, x0x::delegation::AuthorityScope::TaskExecute) => {
            return bad_request("scope 'task_execute' requires a task reference");
        }
        (None, _) => None,
    };

    // Group snapshot: membership, policy, state binding for the carrier.
    let snapshot = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return not_found("group not found");
        };
        if info.withdrawn {
            return not_found("group is withdrawn");
        }
        if info.policy.confidentiality != x0x::groups::GroupConfidentiality::SignedPublic {
            return bad_request("delegation rides the SignedPublic group bus");
        }
        if info.is_banned(&local_hex) {
            return forbidden("you are banned");
        }
        let role = info.caller_role(&local_hex);
        let write_ok = match info.policy.write_access {
            x0x::groups::GroupWriteAccess::MembersOnly => role.is_some(),
            x0x::groups::GroupWriteAccess::ModeratedPublic => true,
            x0x::groups::GroupWriteAccess::AdminOnly => {
                role.is_some_and(|r| r.at_least(x0x::groups::GroupRole::Admin))
            }
        };
        if !write_ok {
            return forbidden("write policy denies issuing delegations");
        }
        // The delegate must be an active member: authority to a nonmember
        // could not be exercised and would pollute history.
        if !info.has_active_member(&req.to_agent) {
            return bad_request("to_agent is not an active member of this group");
        }
        (
            info.stable_group_id().to_string(),
            info.state_hash.clone(),
            info.state_revision,
        )
    };
    let (stable_id, state_hash, state_revision) = snapshot;

    // Depth/parent: a re-delegation must chain off a delegation held by the
    // local agent (to_agent == local) that is effective NOW.
    let (parent, depth) = match &req.parent {
        None => (None, 1u8),
        Some(parent_hex) => {
            let digest = hex::decode(parent_hex)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok());
            let Some(digest) = digest else {
                return bad_request("parent must be 64 hex chars (delegation digest)");
            };
            let committed = committed_delegations(&state, &stable_id).await;
            let parent = committed
                .iter()
                .find(|sd| x0x::delegation::signed_delegation_digest(sd) == digest);
            let Some(parent) = parent else {
                return conflict(
                    "parent delegation is not durably committed in this group's history",
                );
            };
            if parent.delegation.to_agent != local {
                return forbidden("only the delegate of the parent may re-delegate it");
            }
            if !x0x::delegation::is_effective_time(&parent.delegation, now_ms) {
                return conflict("parent delegation has expired");
            }
            if parent.delegation.depth >= x0x::delegation::MAX_DELEGATION_DEPTH {
                return conflict("parent is already at the depth cap (A→B→C, not further)");
            }
            (Some(digest), parent.delegation.depth + 1)
        }
    };

    // Build + sign the envelope with the LOCAL agent's key (blocker 25: the
    // delegator's own key; the delegate never holds it).
    let delegation = x0x::delegation::Delegation {
        delegation_id: rand_delegation_id(),
        issued_at_ms: now_ms,
        task_ref,
        from_agent: local,
        to_agent,
        authority_scope: scope,
        verbs,
        expiry_ms: req.expiry_ms,
        parent_delegation: parent,
        depth,
        group_id: stable_id.to_string(),
    };
    let signing_kp = state.agent.identity().agent_keypair();
    let signed = match x0x::delegation::sign_delegation(signing_kp, &delegation) {
        Ok(sd) => sd,
        Err(e) => return bad_request(format!("delegation invalid: {e}")),
    };

    // Carrier message on the group bus (kind = delegation).
    let carrier_body = serde_json::to_string(&signed).unwrap_or_default();
    let carrier = match x0x::groups::GroupPublicMessage::sign(
        stable_id.to_string(),
        state_hash,
        state_revision,
        signing_kp,
        None,
        x0x::groups::GroupPublicMessageKind::Delegation,
        carrier_body,
        now_ms,
        None,
        None,
    ) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": format!("sign failed: {e}") })),
            )
                .into_response();
        }
    };

    // EFFECTIVENESS GATE (blocker 28): commit the carrier to durable
    // history and WAIT for the SQLite transaction. Only then is the
    // delegation effective; only then do we fan out or notify.
    if let Err(e) =
        crate::server::routes::named_groups::record_group_public_history_committed(&state, &carrier)
            .await
    {
        tracing::error!(group_id = %stable_id, "delegation durability gate failed: {e}");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("durable history commit failed: {e}"),
                "effective": false,
            })),
        )
            .into_response();
    }
    index_committed(&state, &stable_id, signed.clone()).await;

    // Fan out on the group bus so peers' histories (and registries) learn
    // the delegation.
    crate::server::routes::named_groups::publish_delegation_carrier(
        std::sync::Arc::clone(&state),
        carrier.clone(),
    )
    .await;

    // NOTIFICATION (not the source of truth): DM-v2 durable-ACK handoff to
    // the delegate. Typed refusal/unreachable is reported, never fatal.
    let notification = notify_delegate(&state, to_agent, &signed).await;

    let digest_hex = hex::encode(x0x::delegation::signed_delegation_digest(&signed));
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "effective": true,
            "effectiveness": "durable_group_history",
            "delegation_digest": digest_hex,
            "depth": signed.delegation.depth,
            "expiry_ms": signed.delegation.expiry_ms,
            "notification": notification,
            "msg_id": carrier.msg_id(),
        })),
    )
        .into_response()
}

/// Best-effort DM notification of a new delegation (ADR-0030 hardened
/// durable-ACK path). Returns a machine-readable status string.
async fn notify_delegate(
    state: &AppState,
    to: x0x::identity::AgentId,
    sd: &x0x::delegation::SignedDelegation,
) -> String {
    let mut payload = DELEGATION_DM_PREFIX.to_vec();
    payload.extend_from_slice(&serde_json::to_vec(sd).unwrap_or_else(|_| b"{}".to_vec()));
    let config = x0x::dm::DmSendConfig {
        timeout_per_attempt: std::time::Duration::from_secs(3),
        max_retries: 1,
        ..Default::default()
    };
    match state
        .agent
        .send_direct_with_config(&to, payload, config)
        .await
    {
        Ok(_) => "durable_ack".to_string(),
        Err(e) => {
            tracing::warn!(
                delegate = %hex::encode(to.as_bytes()),
                "delegation handoff DM failed (delegation remains effective via history): {e}"
            );
            format!("unreachable:{e}")
        }
    }
}

/// Random 128-bit delegation id. Uniqueness, not unpredictability, is the
/// requirement (the digest binds the grant); time-seeded BLAKE3 is ample.
fn rand_delegation_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let h = blake3::hash(&seed.to_le_bytes());
    id.copy_from_slice(&h.as_bytes()[..16]);
    id
}

/// GET /groups/:id/delegations — list effective delegations in a group.
///
/// Re-derives from durable history (the index may be cold after a restart —
/// this is exactly the crash/retry path) and filters by time and the
/// CURRENT roster: revoked members' authority auto-expires (ADR-0040).
pub(in crate::server) async fn list_group_delegations(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let snapshot = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(&id) else {
            return not_found("group not found");
        };
        if info.withdrawn {
            return not_found("group is withdrawn");
        }
        let is_member = info.has_active_member(&local_hex);
        let read_open = info.policy.read_access == x0x::groups::GroupReadAccess::Public;
        if !is_member && !read_open {
            return forbidden("members-only read policy");
        }
        (info.stable_group_id().to_string(), info.members_v2.clone())
    };
    let (stable_id, members) = snapshot;
    let now_ms = crate::server::routes::now_millis_u64();

    let committed = committed_delegations(&state, &stable_id).await;
    let active_hex: std::collections::HashSet<String> = members
        .values()
        .filter(|m| m.state == x0x::groups::GroupMemberState::Active)
        .map(|m| m.agent_id.to_lowercase())
        .collect();
    let mut out: Vec<serde_json::Value> = committed
        .iter()
        .filter(|sd| x0x::delegation::is_effective_time(&sd.delegation, now_ms))
        .filter(|sd| {
            active_hex.contains(&hex::encode(sd.delegation.from_agent.as_bytes()))
                && active_hex.contains(&hex::encode(sd.delegation.to_agent.as_bytes()))
        })
        .filter(|sd| {
            // Depth-2 chains only count when their parent is also committed
            // and the chain verifies (authorize re-checks the link).
            sd.delegation.depth == 1
                || authorize(
                    sd,
                    &sd.delegation.to_agent,
                    sd.delegation
                        .verbs
                        .first()
                        .copied()
                        .unwrap_or(x0x::delegation::DelegationVerb::SendPublicMessage),
                    &stable_id,
                    now_ms,
                    &committed,
                )
                .is_ok()
        })
        .map(|sd| {
            serde_json::json!({
                "delegation_digest": hex::encode(x0x::delegation::signed_delegation_digest(sd)),
                "from_agent": hex::encode(sd.delegation.from_agent.as_bytes()),
                "to_agent": hex::encode(sd.delegation.to_agent.as_bytes()),
                "scope": sd.delegation.authority_scope,
                "verbs": sd.delegation.verbs,
                "task_ref": sd.delegation.task_ref.map(hex::encode),
                "depth": sd.delegation.depth,
                "issued_at_ms": sd.delegation.issued_at_ms,
                "expiry_ms": sd.delegation.expiry_ms,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        a["delegation_digest"]
            .as_str()
            .unwrap_or_default()
            .cmp(b["delegation_digest"].as_str().unwrap_or_default())
    });
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": stable_id,
            "delegations": out,
        })),
    )
        .into_response()
}

fn bad_request(msg: impl std::fmt::Display) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "ok": false, "error": msg.to_string() })),
    )
        .into_response()
}

fn forbidden(msg: impl std::fmt::Display) -> axum::response::Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "ok": false, "error": msg.to_string() })),
    )
        .into_response()
}

fn conflict(msg: impl std::fmt::Display) -> axum::response::Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({ "ok": false, "error": msg.to_string() })),
    )
        .into_response()
}

fn not_found(msg: impl std::fmt::Display) -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "ok": false, "error": msg.to_string() })),
    )
        .into_response()
}
