//! ADR-0038 Home — the owner's auto-provisioned personal space.
//!
//! An install with an owner (ADR-0036 `OwnerProfile` + user key) provisions
//! exactly ONE Home at first daemon run: `Hidden + OwnerCertified(owner) +
//! MlsEncrypted + MembersOnly/MembersOnly`, named "Home" (renamable). The
//! daemon's own owner-certified agent is the founding member and the
//! designated PRIMARY agent (`GroupInfo::home.primary_agent`); the
//! provisioning commit is signed by that agent, so the Home metadata is
//! owner-signed by construction.
//!
//! Genesis race scope (v1): dedup is PER-MACHINE — a marker file in the
//! instance data dir plus a scan for an existing Home in the loaded roster.
//! Two machines provisioning their own Homes for the same owner is expected
//! until ADR-0041's tier-1 cross-machine sync decides adoption; this module
//! deliberately does not invent that protocol (see the WP report).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::named_groups::{
    create_named_group, now_millis_u64, persist_named_groups_mutation, update_named_group,
    AtomicWriteOutcome, CreateGroupRequest, UpdateGroupRequest,
};
use crate::server::AppState;

/// Marker file in the instance data dir recording that this machine already
/// provisioned its Home (per-machine dedup; cross-machine is ADR-0041).
pub(in crate::server) const HOME_MARKER_FILE: &str = "home.json";

/// On-disk marker: which group is this machine's Home, under which owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::server) struct HomeMarker {
    pub group_id: String,
    pub owner_user_id: String,
    pub provisioned_at_ms: u64,
}

/// ADR-0038 Home policy: Hidden + OwnerCertified(owner) + MlsEncrypted +
/// MembersOnly/MembersOnly.
#[must_use]
pub(in crate::server) fn home_policy(
    owner: &crate::identity::UserId,
) -> crate::groups::GroupPolicy {
    crate::groups::GroupPolicy {
        discoverability: crate::groups::GroupDiscoverability::Hidden,
        admission: crate::groups::GroupAdmission::OwnerCertified(*owner),
        confidentiality: crate::groups::GroupConfidentiality::MlsEncrypted,
        read_access: crate::groups::GroupReadAccess::MembersOnly,
        write_access: crate::groups::GroupWriteAccess::MembersOnly,
    }
}

/// The loaded Home group, if this machine has one (roster scan —
/// restart-safe even if the marker file was deleted).
pub(in crate::server) async fn find_home(
    state: &AppState,
) -> Option<(String, crate::groups::GroupInfo)> {
    let groups = state.named_groups.read().await;
    groups
        .iter()
        .find(|(_, info)| info.home.is_some())
        .map(|(id, info)| (id.clone(), info.clone()))
}

/// Auto-provision the Home space for an owned install. Idempotent and
/// best-effort: never fails startup — a provisioning failure logs loudly
/// and retries on the next daemon start (no marker is written on failure).
pub(in crate::server) async fn provision_home(state: &Arc<AppState>) {
    // Only an OWNED install provisions: user key + builder-issued
    // certificate must both be live (OwnerCertified admission needs a
    // certifiable founding member).
    let Some(user_kp) = state.agent.identity().user_keypair() else {
        tracing::debug!("no owner user key: Home not provisioned (anonymous install)");
        return;
    };
    if state.agent.identity().agent_certificate().is_none() {
        tracing::warn!("owner key present but no agent certificate: Home not provisioned");
        return;
    }
    let marker_path = state.data_dir.join(HOME_MARKER_FILE);
    if tokio::fs::try_exists(&marker_path).await.unwrap_or(false) {
        return; // Already provisioned on this machine.
    }
    // Restart safety even without the marker: adopt any existing Home.
    if let Some((id, info)) = find_home(state).await {
        tracing::info!(
            group_id = %id,
            "Home already present; recording marker (no duplicate provisioned)"
        );
        write_marker(
            &marker_path,
            &HomeMarker {
                group_id: id,
                owner_user_id: hex::encode(user_kp.user_id().as_bytes()),
                provisioned_at_ms: info
                    .home
                    .as_ref()
                    .map_or_else(now_millis_u64, |h| h.provisioned_at_ms),
            },
        )
        .await;
        return;
    }

    let owner = user_kp.user_id();
    let req = CreateGroupRequest {
        name: "Home".to_string(),
        description: "Owner's personal space (auto-provisioned)".to_string(),
        display_name: None,
        preset: None,
        policy: Some(home_policy(&owner)),
    };
    let response = create_named_group(State(Arc::clone(state)), Json(req)).await;
    let resp = response.into_response();
    if !resp.status().is_success() {
        tracing::error!(
            status = %resp.status(),
            "Home auto-provisioning failed (will retry on next start)"
        );
        return;
    }
    // Locate the freshly created Home and stamp its metadata + marker.
    let Some((group_id, mut info)) = find_home_by_policy(state, &owner).await else {
        tracing::error!("Home group created but not found afterwards; marker not written");
        return;
    };
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let mut placements = std::collections::BTreeMap::new();
    placements.insert(local_hex.clone(), crate::groups::MemberPlacement::Pinned);
    info.home = Some(crate::groups::HomeMetadata {
        primary_agent: local_hex,
        placements,
        provisioned_at_ms: now_millis_u64(),
    });
    let stamped = info;
    if !matches!(
        persist_named_groups_mutation(state, |groups| {
            groups.insert(group_id.clone(), stamped.clone());
            true
        })
        .await,
        Ok(AtomicWriteOutcome::Durable)
    ) {
        tracing::error!(
            "Home provisioning could not persist metadata (marker not written; will retry)"
        );
        return;
    }
    write_marker(
        &marker_path,
        &HomeMarker {
            group_id: group_id.clone(),
            owner_user_id: hex::encode(owner.as_bytes()),
            provisioned_at_ms: stamped.home.as_ref().map_or(0, |h| h.provisioned_at_ms),
        },
    )
    .await;
    tracing::info!(group_id = %group_id, "provisioned Home (ADR-0038)");
}

/// Find the group just created with the Home policy for `owner` (used
/// between creation and metadata stamping, when `home` is still None).
async fn find_home_by_policy(
    state: &AppState,
    owner: &crate::identity::UserId,
) -> Option<(String, crate::groups::GroupInfo)> {
    let groups = state.named_groups.read().await;
    groups
        .iter()
        .find(|(_, info)| {
            info.policy.admission == crate::groups::GroupAdmission::OwnerCertified(*owner)
                && info.home.is_none()
                && info.name == "Home"
        })
        .map(|(id, info)| (id.clone(), info.clone()))
}

async fn write_marker(path: &std::path::Path, marker: &HomeMarker) {
    match serde_json::to_vec_pretty(marker) {
        Ok(bytes) => {
            if let Err(e) = tokio::fs::write(path, bytes).await {
                tracing::warn!(
                    path = %path.display(),
                    "failed to write Home marker (Home still provisioned; restart will adopt by scan): {e}"
                );
            }
        }
        Err(e) => tracing::warn!("failed to serialize Home marker: {e}"),
    }
}

/// Structured roaming warning for an existing Home with zero Roaming
/// agents (ADR-0038: Home always contains ≥1 roaming agent so it follows
/// the user across machines — surface the violation until ADR-0037 lands).
pub(in crate::server) async fn home_roaming_warning(state: &AppState) -> Option<serde_json::Value> {
    let (_, info) = find_home(state).await?;
    let has_roaming = info
        .home
        .as_ref()?
        .placements
        .values()
        .any(|p| *p == crate::groups::MemberPlacement::Roaming);
    if has_roaming {
        return None;
    }
    Some(serde_json::json!({
        "code": "home_no_roaming_agent",
        "message": "Home has no Roaming agent — it will not follow the owner to a new \
                    machine until one is marked Roaming (ADR-0037 placement wave)",
    }))
}

/// Self-name for an agent, resolved from the identity-discovery cache
/// (ADR-0036 self-names ride announces); `None` when unknown.
async fn self_name_for(state: &AppState, agent_hex: &str) -> Option<String> {
    let agent_id = crate::server::parse_agent_id_hex(agent_hex).ok()?;
    let cache = state.agent.identity_discovery_cache();
    let cache = cache.read().await;
    cache
        .get(&agent_id)
        .and_then(|entry| entry.self_name.clone())
}

/// GET /home — resolve the Home group and its metadata.
pub(in crate::server) async fn get_home(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some((group_id, info)) = find_home(state.as_ref()).await else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": "no Home provisioned (un-owned install or not yet created)"
            })),
        );
    };
    let home = info.home.clone().unwrap_or_else(|| {
        // Adopted pre-metadata Home (should not happen; degrade honestly).
        crate::groups::HomeMetadata {
            primary_agent: hex::encode(state.agent.agent_id().as_bytes()),
            placements: std::collections::BTreeMap::new(),
            provisioned_at_ms: 0,
        }
    });
    let mut members = Vec::new();
    for member in info.active_members() {
        members.push(serde_json::json!({
            "agent_id": member.agent_id,
            "role": format!("{:?}", member.role),
            "placement": if home
                .placements
                .get(&member.agent_id)
                .is_some_and(|p| *p == crate::groups::MemberPlacement::Roaming)
            {
                "roaming"
            } else {
                "pinned"
            },
            "self_name": self_name_for(state.as_ref(), &member.agent_id).await,
        }));
    }
    let human_name = state.profile.read().await.human_name.clone();
    let primary_self_name = self_name_for(state.as_ref(), &home.primary_agent).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": group_id,
            "name": info.name,
            "description": info.description,
            "human_name": human_name,
            "primary_agent": {
                "agent_id": home.primary_agent,
                "self_name": primary_self_name,
            },
            "members": members,
            "warnings": {
                "no_roaming_agent": home_roaming_warning(state.as_ref()).await.is_some(),
            },
        })),
    )
}

#[derive(Debug, Deserialize)]
pub(in crate::server) struct RenameHomeRequest {
    name: String,
}

/// POST /home/rename — convenience wrapper over the existing
/// PATCH /groups/:id (admin-gated, sealed, persisted).
pub(in crate::server) async fn rename_home(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RenameHomeRequest>,
) -> Response {
    let Some((group_id, _)) = find_home(state.as_ref()).await else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": "no Home provisioned"
            })),
        )
            .into_response();
    };
    let update = UpdateGroupRequest {
        name: Some(req.name),
        description: None,
    };
    update_named_group(State(state), Path(group_id), Json(update))
        .await
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    /// Owned test state: user key (deterministic seed so the owner id is
    /// stable across the "restart" arm) + builder-issued agent certificate —
    /// the exact shape `serve` produces for an owned install.
    async fn owned_state(
        data_dir: &std::path::Path,
        owner_seed: [u8; 32],
    ) -> anyhow::Result<Arc<AppState>> {
        let user = crate::identity::UserKeypair::from_seed(&owner_seed)?;
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(data_dir.join("machine.key"))
                .with_agent_key(crate::identity::AgentKeypair::generate()?)
                .with_agent_cert_path(data_dir.join("agent.cert"))
                .with_user_key(user)
                .with_contact_store_path(data_dir.join("contacts.json"))
                .build()
                .await?,
        );
        let state =
            super::super::named_groups::tests::secure_endpoint_test_state_at(data_dir, agent)
                .await?;
        Ok(state)
    }

    /// Un-owned state: no user key (anonymous install).
    async fn unowned_state(data_dir: &std::path::Path) -> anyhow::Result<Arc<AppState>> {
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(data_dir.join("machine.key"))
                .with_agent_key(crate::identity::AgentKeypair::generate()?)
                .with_agent_cert_path(data_dir.join("agent.cert"))
                .with_contact_store_path(data_dir.join("contacts.json"))
                .build()
                .await?,
        );
        let state =
            super::super::named_groups::tests::secure_endpoint_test_state_at(data_dir, agent)
                .await?;
        Ok(state)
    }

    async fn response_json(
        response: axum::response::Response,
    ) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let status = response.status();
        let body = to_bytes(response.into_body(), 1 << 20).await?;
        Ok((status, serde_json::from_slice(&body)?))
    }

    /// WHY (ADR-0038 validation): a fresh owned install provisions exactly
    /// one Home with the Home policy, the daemon's agent as founding member
    /// and recorded primary agent — and a restart (fresh state over the
    /// SAME data dir) does NOT provision a second one.
    #[tokio::test]
    async fn owned_install_provisions_home_once_across_restart() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x38; 32]).await?;
        provision_home(&state).await;
        let (group_id, info) = find_home(state.as_ref()).await.expect("Home provisioned");
        assert_eq!(info.name, "Home");
        assert_eq!(
            info.policy.discoverability,
            crate::groups::GroupDiscoverability::Hidden
        );
        assert!(matches!(
            info.policy.admission,
            crate::groups::GroupAdmission::OwnerCertified(_)
        ));
        assert_eq!(
            info.policy.confidentiality,
            crate::groups::GroupConfidentiality::MlsEncrypted
        );
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        assert!(
            info.has_active_member(&local_hex),
            "the daemon's own agent is the founding member"
        );
        let home = info.home.as_ref().expect("home metadata");
        assert_eq!(home.primary_agent, local_hex, "primary agent persisted");
        assert_eq!(
            home.placements.get(&local_hex),
            Some(&crate::groups::MemberPlacement::Pinned),
            "placement placeholder defaults to Pinned"
        );
        // Owner-signed: the provisioning commit was authored by the
        // owner-certified agent.
        assert_eq!(
            info.commit_log
                .last()
                .map(|c| c.commit.committed_by.as_str()),
            Some(local_hex.as_str()),
            "provisioning commit signed by the owner's agent"
        );

        // Restart: fresh state over the same data dir — no duplicate.
        drop(state);
        let state2 = owned_state(dir.path(), [0x38; 32]).await?;
        provision_home(&state2).await;
        provision_home(&state2).await; // and idempotent within one run
        {
            let groups = state2.named_groups.read().await;
            let homes = groups.values().filter(|info| info.home.is_some()).count();
            assert_eq!(homes, 1, "exactly one Home after restart + re-run");
        }
        let (group_id2, info2) = find_home(state2.as_ref()).await.expect("home found");
        assert_eq!(group_id2, group_id, "same Home group id across restart");
        assert_eq!(
            info2.home.as_ref().expect("meta").primary_agent,
            local_hex,
            "primary agent persists"
        );
        Ok(())
    }

    /// WHY: an un-owned (anonymous) install provisions nothing — Home is
    /// the OWNER's personal space.
    #[tokio::test]
    async fn unowned_install_provisions_nothing() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = unowned_state(dir.path()).await?;
        provision_home(&state).await;
        assert!(find_home(state.as_ref()).await.is_none());
        assert!(
            !tokio::fs::try_exists(dir.path().join(HOME_MARKER_FILE)).await?,
            "no marker written for an un-owned install"
        );
        Ok(())
    }

    /// WHY: GET /home resolves the (possibly renamed) Home, its primary
    /// agent, members with placements, and the no-roaming warning until
    /// ADR-0037 marks an agent Roaming.
    #[tokio::test]
    async fn get_home_returns_metadata_and_warning() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x39; 32]).await?;
        provision_home(&state).await;

        let response = get_home(State(Arc::clone(&state))).await.into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["name"], "Home");
        assert_eq!(body["ok"], true);
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        assert_eq!(body["primary_agent"]["agent_id"], local_hex);
        assert!(
            body["members"]
                .as_array()
                .is_some_and(|m| !m.is_empty() && m[0]["placement"] == "pinned"),
            "members rendered with placement: {body}"
        );
        assert_eq!(
            body["warnings"]["no_roaming_agent"], true,
            "zero-Roaming Home must surface the warning: {body}"
        );

        // Health surfaces the same warning as a structured detail.
        let health_json = crate::server::routes::status::health(State(Arc::clone(&state))).await;
        let body: serde_json::Value = serde_json::to_value(&health_json.0.data).unwrap_or_default();
        let body = serde_json::json!({ "data": body });
        assert_eq!(status, StatusCode::OK);
        assert!(
            body["data"]["warnings"]
                .as_array()
                .is_some_and(|w| w.iter().any(|w| w["code"] == "home_no_roaming_agent")),
            "health details carry the home warning: {body}"
        );
        Ok(())
    }

    /// WHY: rename round-trips through the convenience endpoint (which
    /// rides the sealed PATCH /groups/:id path).
    #[tokio::test]
    async fn home_rename_round_trips() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x3A; 32]).await?;
        provision_home(&state).await;
        let (group_id, _) = find_home(state.as_ref()).await.expect("home");

        let response = rename_home(
            State(Arc::clone(&state)),
            Json(RenameHomeRequest {
                name: "Irvine HQ".to_string(),
            }),
        )
        .await;
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::OK, "{body}");

        let response = get_home(State(Arc::clone(&state))).await.into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["name"], "Irvine HQ", "renamed: {body}");
        assert_eq!(body["group_id"], group_id);

        // GET /groups/:id carries home details + warnings too.
        let response = crate::server::routes::named_groups::get_named_group(
            State(Arc::clone(&state)),
            Path(group_id.clone()),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["home"]["primary_agent"], body["creator"]);
        assert!(
            body["warnings"]
                .as_array()
                .is_some_and(|w| w.iter().any(|w| w["code"] == "home_no_roaming_agent")),
            "group view carries the warning: {body}"
        );
        Ok(())
    }

    /// WHY: GET /home on an un-owned install is a clean 404.
    #[tokio::test]
    async fn get_home_without_home_is_404() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = unowned_state(dir.path()).await?;
        let response = get_home(State(Arc::clone(&state))).await.into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        Ok(())
    }

    /// Router-level smoke: the routes are wired with the right methods.
    #[tokio::test]
    async fn home_routes_wired() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x3B; 32]).await?;
        provision_home(&state).await;
        let app = axum::Router::new()
            .route("/home", axum::routing::get(get_home))
            .with_state(state);
        let response = app
            .oneshot(Request::get("/home").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }
}
