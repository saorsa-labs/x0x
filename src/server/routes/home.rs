//! ADR-0038 Home — the owner's auto-provisioned personal space.
//!
//! An install with an owner (ADR-0036 `OwnerProfile` + user key) provisions
//! exactly ONE Home at first daemon run: `Hidden + OwnerCertified(owner) +
//! MlsEncrypted + MembersOnly/MembersOnly`, named "Home" (renamable). The
//! daemon's own owner-certified agent is the founding member and the
//! designated PRIMARY agent; the provisioning seal covers the Home metadata
//! commitment (review fix 1: `home_digest` rides the signed state hash).
//!
//! Genesis race scope (v1): dedup is PER-MACHINE — a verified marker file
//! in the instance data dir plus a trust-checked roster scan. Two machines
//! provisioning their own Homes for the same owner is expected until
//! ADR-0041's tier-1 cross-machine sync decides adoption; this module
//! deliberately does not invent that protocol (see the WP report).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::named_groups::{
    create_named_group, now_millis_u64, persist_named_groups_mutation, seal_commit_owner_certified,
    update_named_group, AtomicWriteOutcome, CreateGroupRequest, UpdateGroupRequest,
};
use crate::server::AppState;

/// Owner-cert evidence for `agents` — thin re-export of the ADR-0038
/// evidence builder (own identity + revocation set + discovery cache) for
/// sibling modules (the POST /groups owner-chain gate).
pub(in crate::server) async fn owner_chain_evidence(
    state: &AppState,
    agents: &[&str],
) -> crate::groups::owner_cert::OwnerCertEvidence {
    super::named_groups::owner_cert_evidence_for(state, agents).await
}

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

/// Whether `policy` is EXACTLY the Home policy for `owner` — all five axes
/// (review fix 3: the crash-recovery scan must match the whole shape, not
/// just name+admission).
fn is_home_policy(policy: &crate::groups::GroupPolicy, owner: &crate::identity::UserId) -> bool {
    *policy == home_policy(owner)
}

/// TRUSTED Home resolution (review fix 1): a group is this machine's Home
/// only when it carries Home metadata AND its policy is exactly
/// `OwnerCertified(owner)` Home-shaped AND our own agent is an active
/// member. Anything else (injected metadata, a foreign owner's Home, a
/// group we were removed from) is not trusted.
pub(in crate::server) async fn find_home(
    state: &AppState,
    owner: &crate::identity::UserId,
) -> Option<(String, crate::groups::GroupInfo)> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    groups
        .iter()
        .find(|(_, info)| {
            info.home.is_some()
                && is_home_policy(&info.policy, owner)
                && info.has_active_member(&local_hex)
        })
        .map(|(id, info)| (id.clone(), info.clone()))
}

/// A group that matches the full Home policy for `owner` whether or not the
/// Home metadata was stamped — the crash-recovery predicate (review fix 3:
/// a crash between create and stamp must adopt the created group, not mint
/// a second one).
#[must_use]
pub(in crate::server) fn is_home_candidate(
    info: &crate::groups::GroupInfo,
    owner: &crate::identity::UserId,
) -> bool {
    is_home_policy(&info.policy, owner)
}

/// Read + verify the marker (review fix 3): PARSED (never a bare
/// existence check), checked against the CURRENT owner, and checked to
/// point at a group that still exists. Absent/corrupt/stale → `None`
/// (corrupt + stale are logged); the trusted roster scan re-derives.
async fn read_verified_marker(state: &AppState, owner_hex: &str) -> Option<HomeMarker> {
    let path = state.data_dir.join(HOME_MARKER_FILE);
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                "cannot read Home marker (treating as absent; the trusted roster scan re-derives): {e}"
            );
            return None;
        }
    };
    match serde_json::from_slice::<HomeMarker>(&bytes) {
        Ok(marker) => {
            if marker.owner_user_id != owner_hex {
                tracing::warn!(
                    marker_owner = %marker.owner_user_id,
                    "Home marker names a different owner (ownership transition?); ignoring it"
                );
                return None;
            }
            let exists = state
                .named_groups
                .read()
                .await
                .contains_key(&marker.group_id);
            if !exists {
                tracing::warn!(
                    group_id = %marker.group_id,
                    "Home marker points at a missing group; ignoring it"
                );
                return None;
            }
            Some(marker)
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                "corrupt Home marker (treating as absent; the trusted roster scan re-derives): {e}"
            );
            None
        }
    }
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

/// Stamp Home metadata on `group_id` and SEAL it into the signed state
/// chain (review fix 1): the Home digest enters the state hash via
/// `public_meta()`, so `primary_agent` is covered by an owner-agent-signed
/// commit. Returns the stamped info on success.
async fn stamp_and_seal_home(
    state: &Arc<AppState>,
    group_id: &str,
) -> Option<crate::groups::GroupInfo> {
    let signing_kp = state.agent.identity().agent_keypair();
    let mut info = {
        let groups = state.named_groups.read().await;
        groups.get(group_id).cloned()?
    };
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let mut placements = std::collections::BTreeMap::new();
    placements.insert(local_hex.clone(), crate::groups::MemberPlacement::Pinned);
    info.home = Some(crate::groups::HomeMetadata {
        primary_agent: local_hex,
        placements,
        provisioned_at_ms: now_millis_u64(),
    });
    // Seal through the OwnerCertified wrapper: it re-verifies the roster
    // (refusing on any failing member) and the seal covers the freshly
    // stamped home digest.
    if let Err(e) =
        seal_commit_owner_certified(state, &mut info, signing_kp, now_millis_u64()).await
    {
        tracing::error!(group_id, "Home metadata seal failed: {e}");
        return None;
    }
    if !matches!(
        persist_named_groups_mutation(state, |groups| {
            groups.insert(group_id.to_string(), info.clone());
            true
        })
        .await,
        Ok(AtomicWriteOutcome::Durable)
    ) {
        tracing::error!(
            group_id,
            "Home metadata could not be persisted (marker not written; will retry)"
        );
        return None;
    }
    Some(info)
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
    let owner = user_kp.user_id();
    let owner_hex = hex::encode(owner.as_bytes());
    let marker_path = state.data_dir.join(HOME_MARKER_FILE);

    // 1) Trusted Home already present (the marker is only advisory — the
    //    roster scan is authoritative). Repair a missing/stale marker.
    if let Some((id, info)) = find_home(state, &owner).await {
        let needs_repair = read_verified_marker(state, &owner_hex)
            .await
            .is_none_or(|m| m.group_id != id);
        if needs_repair {
            tracing::info!(group_id = %id, "Home already present; recording marker");
            write_marker(
                &marker_path,
                &HomeMarker {
                    group_id: id,
                    owner_user_id: owner_hex,
                    provisioned_at_ms: info
                        .home
                        .as_ref()
                        .map_or_else(now_millis_u64, |h| h.provisioned_at_ms),
                },
            )
            .await;
        }
        return;
    }

    // 2) Crash recovery (review fix 3): a group matching the FULL Home
    //    policy exists but was never stamped (crash between create and
    //    stamp, or a failed stamp/persist). Adopt the OLDEST such group —
    //    complete its metadata + seal instead of minting a duplicate.
    let candidate: Option<String> = {
        let groups = state.named_groups.read().await;
        let mut matches: Vec<(&String, u64)> = groups
            .iter()
            .filter(|(_, info)| info.home.is_none() && is_home_candidate(info, &owner))
            .map(|(id, info)| (id, info.created_at))
            .collect();
        matches.sort_by_key(|(_, created)| *created);
        matches.first().map(|(id, _)| (*id).clone())
    };
    if let Some(id) = candidate {
        tracing::info!(
            group_id = %id,
            "adopting unstamped Home-shaped group (crash recovery); stamping + sealing"
        );
        if let Some(info) = stamp_and_seal_home(state, &id).await {
            write_marker(
                &marker_path,
                &HomeMarker {
                    group_id: id,
                    owner_user_id: owner_hex,
                    provisioned_at_ms: info.home.as_ref().map_or(0, |h| h.provisioned_at_ms),
                },
            )
            .await;
        }
        return;
    }

    // 3) Fresh provisioning through the full creation path.
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
    let group_id = {
        let groups = state.named_groups.read().await;
        groups
            .iter()
            .find(|(_, info)| info.home.is_none() && is_home_candidate(info, &owner))
            .map(|(id, _)| id.clone())
    };
    let Some(group_id) = group_id else {
        tracing::error!("Home group created but not found afterwards; marker not written");
        return;
    };
    if let Some(info) = stamp_and_seal_home(state, &group_id).await {
        write_marker(
            &marker_path,
            &HomeMarker {
                group_id: group_id.clone(),
                owner_user_id: owner_hex,
                provisioned_at_ms: info.home.as_ref().map_or(0, |h| h.provisioned_at_ms),
            },
        )
        .await;
        tracing::info!(group_id = %group_id, "provisioned Home (ADR-0038)");
    }
}

/// Roaming-guarantee warning computed from a GroupInfo ALREADY IN HAND
/// (review fix 6: no lock re-acquisition — call while holding the roster
/// guard). Intersects placements with ACTIVE members (review fix 7: a
/// stale Roaming entry for a removed agent must not suppress it).
///
/// ADR-0038: Home always contains ≥1 Roaming agent so it follows the user
/// across machines — surface the violation until ADR-0037 lands.
#[must_use]
pub(in crate::server) fn home_roaming_warning_for(
    info: &crate::groups::GroupInfo,
) -> Option<serde_json::Value> {
    let home = info.home.as_ref()?;
    let has_roaming = info.active_members().any(|m| {
        home.placements
            .get(&m.agent_id)
            .is_some_and(|p| *p == crate::groups::MemberPlacement::Roaming)
    });
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

/// Whether `primary_agent` is an active member whose roster-embedded
/// certificate chains to `owner` — the trust check behind the owner chip
/// (review fix 5). Falls back to `false` when no committed certificate is
/// present (fail-closed attribution).
fn primary_agent_trusted(
    info: &crate::groups::GroupInfo,
    owner: &crate::identity::UserId,
    now_unix: u64,
) -> bool {
    let Some(home) = info.home.as_ref() else {
        return false;
    };
    let Some(member) = info.members_v2.get(&home.primary_agent) else {
        return false;
    };
    if !member.is_active() {
        return false;
    }
    member.certificate.as_ref().is_some_and(|cert| {
        crate::groups::owner_cert::verify_cert_against_owner(
            owner,
            &home.primary_agent,
            cert,
            false,
            now_unix,
        )
        .is_ok()
    })
}

/// GET /home — resolve the Home group and its metadata. Trust-checked
/// (review fix 5): the group must be the CURRENT owner's Home with our
/// agent an active member; the primary agent's verification status is
/// reported (`verified`) so the GUI only shows the owner chip when the
/// SENDING agent is that verified primary.
pub(in crate::server) async fn get_home(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let not_found = |reason: &str| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": reason,
            })),
        )
    };
    let Some(user_kp) = state.agent.identity().user_keypair() else {
        return not_found("no Home provisioned (un-owned install)");
    };
    let owner = user_kp.user_id();
    let Some((group_id, info)) = find_home(state.as_ref(), &owner).await else {
        return not_found("no Home provisioned");
    };
    let home = info
        .home
        .clone()
        .unwrap_or_else(|| crate::groups::HomeMetadata {
            primary_agent: hex::encode(state.agent.agent_id().as_bytes()),
            placements: std::collections::BTreeMap::new(),
            provisioned_at_ms: 0,
        });
    let primary_ok = primary_agent_trusted(
        &info,
        &owner,
        crate::groups::owner_cert::restore_clock_now(),
    );
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
                "verified": primary_ok,
            },
            "members": members,
            "warnings": {
                "no_roaming_agent": home_roaming_warning_for(&info).is_some(),
                "primary_agent_unverified": !primary_ok,
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
    let Some(user_kp) = state.agent.identity().user_keypair() else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": "no Home provisioned"
            })),
        )
            .into_response();
    };
    let Some((group_id, _)) = find_home(state.as_ref(), &user_kp.user_id()).await else {
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
    /// stable across the "restart" arm) + builder-issued agent certificate.
    async fn owned_state(
        data_dir: &std::path::Path,
        owner_seed: [u8; 32],
    ) -> anyhow::Result<Arc<AppState>> {
        let user = crate::identity::UserKeypair::from_seed(&owner_seed)?;
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(data_dir.join("machine.key"))
                // Persisted agent key: the "restart" arm reloads the SAME
                // agent identity (a real restart), so Home membership and
                // the marker survive it.
                .with_agent_key_path(data_dir.join("agent.key"))
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

    fn owner_of(state: &AppState) -> crate::identity::UserId {
        state
            .agent
            .identity()
            .user_keypair()
            .expect("owned fixture")
            .user_id()
    }

    /// WHY: a fresh owned install provisions exactly one Home, and the Home
    /// metadata is SEALED (review fix 1) — mutating `home` after the fact
    /// breaks state-hash validation. Restart does not duplicate.
    #[tokio::test]
    async fn owned_install_provisions_home_once_across_restart() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x38; 32]).await?;
        provision_home(&state).await;

        let owner = owner_of(&state);
        let (group_id, info) = find_home(&state, &owner).await.expect("Home provisioned");
        assert_eq!(info.name, "Home");
        assert!(is_home_policy(&info.policy, &owner));
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        assert!(info.has_active_member(&local_hex));
        let home = info.home.as_ref().expect("home metadata");
        assert_eq!(home.primary_agent, local_hex);
        assert_eq!(
            home.placements.get(&local_hex),
            Some(&crate::groups::MemberPlacement::Pinned)
        );

        // Review fix 1: the home digest is committed by a signed seal —
        // forging `home` afterwards must change the state hash.
        let sealed_hash = info.state_hash.clone();
        let mut forged = info.clone();
        let evil = "ff".repeat(32);
        forged.home = Some(crate::groups::HomeMetadata {
            primary_agent: evil,
            placements: std::collections::BTreeMap::new(),
            provisioned_at_ms: 0,
        });
        forged.recompute_state_hash();
        assert_ne!(
            forged.state_hash, sealed_hash,
            "forged home metadata must not validate under the sealed state hash"
        );
        // And the digest actually rides the meta hash (empty home == absent
        // digest; present home == Some).
        assert!(
            crate::groups::compute_public_meta_hash(&info.public_meta())
                != crate::groups::compute_public_meta_hash(&forged.public_meta())
        );

        // Marker was written and verifies.
        assert!(read_verified_marker(&state, &hex::encode(owner.as_bytes()))
            .await
            .is_some());

        // Restart: fresh state over the same data dir — no duplicate.
        drop(state);
        let state2 = owned_state(dir.path(), [0x38; 32]).await?;
        provision_home(&state2).await;
        provision_home(&state2).await; // idempotent within one run
        let owner2 = owner_of(&state2);
        let (group_id2, info2) = find_home(&state2, &owner2).await.expect("home found");
        assert_eq!(group_id2, group_id, "same Home across restart");
        assert_eq!(
            info2.home.as_ref().expect("meta").primary_agent,
            local_hex,
            "primary agent persists"
        );
        Ok(())
    }

    /// WHY (review fix 3): a crash between group-create and home-stamp must
    /// be RECOVERED — the next start adopts the unstamped Home-shaped group
    /// instead of minting a duplicate.
    #[tokio::test]
    async fn crash_between_create_and_stamp_is_recovered() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x3C; 32]).await?;
        let owner = owner_of(&state);
        // Simulate the crash: create a Home-shaped group with NO metadata
        // and NO marker.
        let req = CreateGroupRequest {
            name: "Home".to_string(),
            description: String::new(),
            display_name: None,
            preset: None,
            policy: Some(home_policy(&owner)),
        };
        let response = create_named_group(State(Arc::clone(&state)), Json(req)).await;
        let (status, body) = response_json(response.into_response()).await?;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let created: String = body["group_id"].as_str().unwrap_or_default().to_string();
        assert!(!created.is_empty());

        provision_home(&state).await;
        let (id, info) = find_home(&state, &owner).await.expect("recovered");
        assert_eq!(
            id, created,
            "adopted the crashed-create group, not a new one"
        );
        assert!(info.home.is_some(), "metadata stamped + sealed");
        Ok(())
    }

    /// WHY (review fix 3): a corrupt marker must not short-circuit
    /// provisioning; the trusted scan re-derives.
    #[tokio::test]
    async fn corrupt_marker_does_not_suppress_provisioning() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x3D; 32]).await?;
        tokio::fs::write(dir.path().join(HOME_MARKER_FILE), b"{not json").await?;
        provision_home(&state).await;
        let owner = owner_of(&state);
        assert!(
            find_home(&state, &owner).await.is_some(),
            "provisioned despite corrupt marker"
        );
        Ok(())
    }

    /// WHY (review fix 1): injected home metadata on a group that is NOT
    /// our-owner Home-shaped must not be trusted by find_home.
    #[tokio::test]
    async fn injected_home_metadata_on_foreign_group_is_untrusted() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x3E; 32]).await?;
        let owner = owner_of(&state);
        // A default InviteOnly group with attacker-stamped home metadata.
        let mut info = crate::groups::GroupInfo::with_policy(
            "evil".to_string(),
            String::new(),
            state.agent.agent_id(),
            "ee".repeat(16),
            crate::groups::GroupPolicy::default(),
        );
        info.home = Some(crate::groups::HomeMetadata {
            primary_agent: "ff".repeat(32),
            placements: std::collections::BTreeMap::new(),
            provisioned_at_ms: 0,
        });
        state
            .named_groups
            .write()
            .await
            .insert("ee".repeat(16), info);
        assert!(
            find_home(&state, &owner).await.is_none(),
            "home metadata without the OwnerCertified Home policy must be untrusted"
        );
        // And GET /home stays 404 rather than serving the forged metadata.
        let response = get_home(State(Arc::clone(&state))).await.into_response();
        let (status, _) = response_json(response).await?;
        assert_eq!(status, StatusCode::NOT_FOUND);
        Ok(())
    }

    /// WHY (review fix 2): POST /groups with an OwnerCertified policy for
    /// an owner we do NOT chain to is a typed 403.
    #[tokio::test]
    async fn owner_certified_create_requires_cert_chain() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x3F; 32]).await?;
        let victim = crate::identity::UserKeypair::generate()?;
        let req = CreateGroupRequest {
            name: "stolen".to_string(),
            description: String::new(),
            display_name: None,
            preset: None,
            policy: Some(home_policy(&victim.user_id())),
        };
        let response = create_named_group(State(Arc::clone(&state)), Json(req)).await;
        let (status, body) = response_json(response.into_response()).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body["error"].as_str().is_some_and(|e| e.contains("chain")));
        // And no group was created.
        assert!(state
            .named_groups
            .read()
            .await
            .values()
            .all(|i| i.name != "stolen"));
        Ok(())
    }

    /// WHY (review fix 2): the create response echoes the effective policy
    /// so callers detect silent downgrade on older daemons.
    #[tokio::test]
    async fn create_response_echoes_effective_policy() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x40; 32]).await?;
        let owner = owner_of(&state);
        let req = CreateGroupRequest {
            name: "echo".to_string(),
            description: String::new(),
            display_name: None,
            preset: None,
            policy: Some(home_policy(&owner)),
        };
        let response = create_named_group(State(Arc::clone(&state)), Json(req)).await;
        let (status, body) = response_json(response.into_response()).await?;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let echoed = body["policy"]["admission"]["owner_certified"].as_str();
        assert_eq!(
            echoed,
            Some(hex::encode(owner.as_bytes()).as_str()),
            "effective policy echoed for downgrade detection: {body}"
        );
        Ok(())
    }

    /// WHY (review fix 7): a stale Roaming placement for a REMOVED agent
    /// must not suppress the warning; an active Roaming member must.
    #[tokio::test]
    async fn roaming_warning_intersects_active_members() -> anyhow::Result<()> {
        let mut info = crate::groups::GroupInfo::with_policy(
            "Home".to_string(),
            String::new(),
            crate::identity::AgentId([1; 32]),
            "aa".repeat(16),
            crate::groups::GroupPolicy::default(),
        );
        let active = "11".repeat(32);
        let removed = "22".repeat(32);
        info.home = Some(crate::groups::HomeMetadata {
            primary_agent: active.clone(),
            placements: [
                (removed.clone(), crate::groups::MemberPlacement::Roaming),
                (active.clone(), crate::groups::MemberPlacement::Pinned),
            ]
            .into_iter()
            .collect(),
            provisioned_at_ms: 0,
        });
        info.add_member(active.clone(), crate::groups::GroupRole::Admin, None, None);
        // Removed agent is NOT an active member (state Removed).
        {
            let mut m = crate::groups::GroupMember::new_member(removed.clone(), None, None, 0);
            m.state = crate::groups::GroupMemberState::Removed;
            info.members_v2.insert(removed, m);
        }
        assert!(
            home_roaming_warning_for(&info).is_some(),
            "stale Roaming entry for a removed agent must NOT satisfy the guarantee"
        );
        // Mark the ACTIVE member Roaming — warning clears.
        if let Some(home) = info.home.as_mut() {
            home.placements
                .insert(active, crate::groups::MemberPlacement::Roaming);
        }
        assert!(home_roaming_warning_for(&info).is_none());
        Ok(())
    }

    /// WHY: an un-owned install provisions nothing.
    #[tokio::test]
    async fn unowned_install_provisions_nothing() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = unowned_state(dir.path()).await?;
        provision_home(&state).await;
        assert!(state
            .named_groups
            .read()
            .await
            .values()
            .all(|i| i.home.is_none()));
        assert!(
            !tokio::fs::try_exists(dir.path().join(HOME_MARKER_FILE)).await?,
            "no marker written for an un-owned install"
        );
        Ok(())
    }

    /// WHY: GET /home resolves the Home and reports the no-roaming warning;
    /// /health no longer leaks it (review fix 6).
    #[tokio::test]
    async fn get_home_reports_warning_health_does_not() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x41; 32]).await?;
        provision_home(&state).await;
        let response = get_home(State(Arc::clone(&state))).await.into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["name"], "Home");
        assert_eq!(body["warnings"]["no_roaming_agent"], true);
        let health_json = crate::server::routes::status::health(State(Arc::clone(&state))).await;
        let health_body: serde_json::Value =
            serde_json::to_value(&health_json.0).unwrap_or_default();
        assert!(
            health_body["warnings"]
                .as_array()
                .is_none_or(|w| w.is_empty()),
            "auth-exempt /health must not leak Home existence: {health_body}"
        );
        Ok(())
    }

    /// WHY: rename round-trips through the convenience endpoint.
    #[tokio::test]
    async fn home_rename_round_trips() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x42; 32]).await?;
        provision_home(&state).await;
        let response = rename_home(
            State(Arc::clone(&state)),
            Json(RenameHomeRequest {
                name: "Irvine HQ".to_string(),
            }),
        )
        .await;
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let owner = owner_of(&state);
        let (_, info) = find_home(&state, &owner).await.expect("home");
        assert_eq!(info.name, "Irvine HQ");
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

    /// Router-level smoke: routes wired with the right methods.
    #[tokio::test]
    async fn home_routes_wired() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x43; 32]).await?;
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
