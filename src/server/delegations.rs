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

/// Per-group cache over durably-committed delegation envelopes. Durable
/// history is the source of truth; this index is ONLY a cache with a
/// rowid freshness probe (review r2): any use first checks the group's
/// newest history rowid and rescans when history has grown, so an
/// already-committed delegation is never rejected because of a stale
/// warmed index.
#[derive(Debug, Default)]
pub(crate) struct DelegationIndex {
    /// True once the index has been (re)built from durable history.
    loaded: bool,
    /// Highest history rowid observed at build/rescan time. The freshness
    /// probe compares the group's current newest rowid against this.
    max_row_id: i64,
    /// Verified envelopes keyed by delegation digest. Presence == the
    /// carrier is durably committed locally.
    by_digest: HashMap<[u8; 32], x0x::delegation::SignedDelegation>,
    /// Per-group seen delegation ids — the uniqueness registry (review r2):
    /// one issuance id may ever name one envelope here. A second envelope
    /// reusing an id (replay/forge) is rejected, keeping ADR-0040's
    /// unique-issuance audit property honest.
    seen_ids: std::collections::HashSet<[u8; 16]>,
}

/// Build the digest map + seen-id registry from history rows in COMMIT
/// order (ascending rowid). First-seen delegation_id wins; a different
/// envelope reusing the id is dropped (never enters the digest map, so it
/// can never authorize).
fn index_from_rows(
    rows: &[x0x::history::StoredRecord],
) -> (
    HashMap<[u8; 32], x0x::delegation::SignedDelegation>,
    std::collections::HashSet<[u8; 16]>,
) {
    let mut map = HashMap::new();
    let mut seen: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    // Query pages arrive newest-first; commit order is ascending rowid.
    let mut ordered: Vec<&x0x::history::StoredRecord> = rows.iter().collect();
    ordered.sort_by_key(|r| r.id);
    for row in ordered {
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
        if x0x::delegation::verify_delegation(&sd).is_err() {
            continue;
        }
        // Uniqueness registry: a replayed/modified envelope reusing an
        // already-seen delegation_id is rejected outright.
        if !seen.insert(sd.delegation.delegation_id) {
            tracing::warn!(
                group_id = %sd.delegation.group_id,
                "dropping delegation carrier: delegation_id already issued (replay)"
            );
            continue;
        }
        map.insert(x0x::delegation::signed_delegation_digest(&sd), sd);
    }
    (map, seen)
}

/// Newest rowid for the group's history scope, if any row exists.
fn newest_row_id(store: &x0x::history::Store, group_id: &str) -> Option<i64> {
    let q = x0x::history::HistoryQuery {
        scope: Some(x0x::history::Scope::Group(group_id.to_string())),
        limit: 1,
        ..Default::default()
    };
    store.query(&q).ok()?.first().map(|r| r.id)
}

/// Full paginated rescan of the group's durable history (review r2: no
/// newest-N cap — every committed row is visible, keyed by rowid cursor).
fn scan_group_history(
    store: &x0x::history::Store,
    group_id: &str,
) -> (Vec<x0x::history::StoredRecord>, i64) {
    let mut rows = Vec::new();
    let mut before_id: Option<i64> = None;
    let mut max_row_id = 0i64;
    loop {
        let q = x0x::history::HistoryQuery {
            scope: Some(x0x::history::Scope::Group(group_id.to_string())),
            limit: 500,
            before_id,
            ..Default::default()
        };
        let Ok(page) = store.query(&q) else { break };
        if page.is_empty() {
            break;
        }
        if let Some(newest) = page.first().map(|r| r.id) {
            max_row_id = max_row_id.max(newest);
        }
        let next_cursor = page.last().map(|r| r.id);
        let done = page.len() < 500;
        rows.extend(page);
        if done {
            break;
        }
        before_id = next_cursor;
    }
    (rows, max_row_id)
}

/// Ensure the per-group index is FRESH against durable history, then return
/// a snapshot of every durably-committed envelope.
///
/// The freshness probe queries the group's newest history rowid on every
/// call: durable history stays the single source of truth, the in-memory
/// map is only a cache, and a warmed-but-stale index can never cause a
/// false rejection of an already-committed delegation.
pub(in crate::server) async fn committed_delegations(
    state: &AppState,
    group_id: &str,
) -> Vec<x0x::delegation::SignedDelegation> {
    // Freshness probe (cheap: limit-1 query).
    let mut newest: Option<i64> = None;
    if let Some(history) = state.agent.history() {
        let store = std::sync::Arc::clone(history.store());
        let scope = group_id.to_string();
        newest = tokio::task::spawn_blocking(move || newest_row_id(&store, &scope))
            .await
            .ok()
            .flatten();
    }
    {
        let index = state.delegation_index.read().await;
        if let Some(entry) = index.get(group_id) {
            if entry.loaded && newest.is_none_or(|id| id <= entry.max_row_id) {
                return entry.by_digest.values().cloned().collect();
            }
        }
    }
    // Slow path: full rescan from THIS daemon's durable history (blocker
    // 28: crash/restart re-derives from the store; r2: complete, uncapped).
    let mut map = HashMap::new();
    let mut seen = std::collections::HashSet::new();
    let mut max_row_id = 0i64;
    if let Some(history) = state.agent.history() {
        let store = std::sync::Arc::clone(history.store());
        let scope = group_id.to_string();
        let scanned = tokio::task::spawn_blocking(move || scan_group_history(&store, &scope)).await;
        if let Ok((rows, scanned_max)) = scanned {
            max_row_id = scanned_max;
            let (m, s) = index_from_rows(&rows);
            map = m;
            seen = s;
        }
    }
    let mut index = state.delegation_index.write().await;
    let entry = index.entry(group_id.to_string()).or_default();
    entry.loaded = true;
    entry.max_row_id = entry.max_row_id.max(max_row_id);
    entry.by_digest = map;
    entry.seen_ids = seen;
    entry.by_digest.values().cloned().collect()
}

/// Record a just-committed delegation into the index (called only after the
/// carrier's SQLite transaction committed). Fast path only — the next
/// freshness probe still verifies against history (rowid watermark is NOT
/// bumped here, so a subsequent committed row triggers a proper rescan).
pub(in crate::server) async fn index_committed(
    state: &AppState,
    group_id: &str,
    sd: x0x::delegation::SignedDelegation,
) {
    let mut index = state.delegation_index.write().await;
    let entry = index.entry(group_id.to_string()).or_default();
    entry.loaded = true;
    // Uniqueness registry holds even on the fast path.
    if entry.seen_ids.insert(sd.delegation.delegation_id) {
        entry
            .by_digest
            .insert(x0x::delegation::signed_delegation_digest(&sd), sd);
    }
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
        // Re-delegation: the parent must also be durably committed, the
        // chain must verify, the child must be ATTENUATED by the parent
        // (review r2 — no authority escalation), and the PARENT must still
        // be effective: removing or expiring the root stops the whole chain.
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
        if let Err(e) = x0x::delegation::is_attenuated_by(&parent.delegation, d) {
            return Err(format!("re-delegation is not bounded by its parent: {e}"));
        }
        if !x0x::delegation::is_effective_time(&parent.delegation, now_ms) {
            return Err("parent delegation has expired".into());
        }
        // The PARENT's delegate (this chain's delegator) must still be the
        // actor of the parent link — verify_chain proved it — and the
        // parent's own parties must still be members; the caller supplies
        // the roster view (chain_members_active).
    }
    Ok(())
}

/// Membership of every agent in the delegation chain (review r2): removing
/// the ROOT delegator (or any intermediate) must stop use of a depth-2
/// grant, not just removal of the child's own parties.
pub(in crate::server) fn chain_members_active(
    sd: &x0x::delegation::SignedDelegation,
    committed: &[x0x::delegation::SignedDelegation],
    active_hex: &std::collections::HashSet<String>,
) -> Result<(), String> {
    let mut chain = vec![sd.delegation.from_agent, sd.delegation.to_agent];
    let mut current = sd;
    while current.delegation.depth > 1 {
        let Some(parent_digest) = current.delegation.parent_delegation else {
            return Err("re-delegation without a parent digest".into());
        };
        let Some(parent) = committed
            .iter()
            .find(|p| x0x::delegation::signed_delegation_digest(p) == parent_digest)
        else {
            return Err("parent delegation is not durably committed here".into());
        };
        chain.push(parent.delegation.from_agent);
        chain.push(parent.delegation.to_agent);
        current = parent;
    }
    for agent in chain {
        if !active_hex.contains(&hex::encode(agent.as_bytes())) {
            return Err(format!(
                "delegation chain touches a removed member ({}) — authority auto-expired",
                hex::encode(agent.as_bytes())
            ));
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
    )?;
    // Chain-wide membership (review r2): every agent in the delegation
    // chain must still be an active member — removing the root delegator
    // stops the child grant's use.
    let active_hex = active_member_hex(state, group_id).await;
    chain_members_active(sd, &committed, &active_hex)?;
    Ok(sd.clone())
}

/// Snapshot of the group's active-member hex ids (lowercase).
async fn active_member_hex(state: &AppState, group_id: &str) -> std::collections::HashSet<String> {
    let groups = state.named_groups.read().await;
    groups
        .get(group_id)
        .map(|info| {
            info.members_v2
                .values()
                .filter(|m| m.state == x0x::groups::GroupMemberState::Active)
                .map(|m| m.agent_id.to_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

/// Roster snapshot for cross-module authorization checks (task-execute).
pub(in crate::server) async fn active_members_of(
    state: &AppState,
    group_id: &str,
) -> std::collections::HashSet<String> {
    active_member_hex(state, group_id).await
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
    // local agent (to_agent == local) that is effective NOW, and the child
    // must be ATTENUATED by it (review r2 — no authority escalation).
    let (parent, parent_sd) = match &req.parent {
        None => (None, None),
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
            (Some(digest), Some(parent.clone()))
        }
    };
    let depth = parent_sd.as_ref().map_or(1u8, |p| p.delegation.depth + 1);

    // Build + sign the envelope with the LOCAL agent's key (blocker 25: the
    // delegator's own key; the delegate never holds it).
    let delegation = x0x::delegation::Delegation {
        delegation_id: fresh_delegation_id(&state, &stable_id).await,
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
    // Issue-side attenuation (review r2): reject escalation BEFORE signing.
    if let Some(parent_sd) = &parent_sd {
        if let Err(e) = x0x::delegation::is_attenuated_by(&parent_sd.delegation, &delegation) {
            return conflict(format!("re-delegation exceeds its parent grant: {e}"));
        }
    }
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

/// Fresh, registry-checked delegation id (review r2): the id must be unique
/// within the group's seen-issuance registry — the ADR's unique-issuance
/// audit claim is enforced, not assumed from a hash.
async fn fresh_delegation_id(state: &AppState, group_id: &str) -> [u8; 16] {
    for _ in 0..8 {
        let candidate = rand_delegation_id();
        let seen = state
            .delegation_index
            .read()
            .await
            .get(group_id)
            .is_some_and(|entry| entry.seen_ids.contains(&candidate));
        if !seen {
            return candidate;
        }
    }
    // Practically unreachable (128-bit space); last resort still unique-ish
    // by time and the registry will reject a true collision at commit.
    rand_delegation_id()
}

fn rand_delegation_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = nanos ^ ((std::process::id() as u128) << 96);
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
