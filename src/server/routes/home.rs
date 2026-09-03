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
    // #487: a pending join stub lives in MEMORY only — the join is not
    // durable, so it must not become "the Home" (the marker would dangle
    // after the stub is dropped on restart). Snapshot the set and drop
    // the std Mutex guard BEFORE awaiting (Send futures).
    let pending: Vec<String> = {
        let pending = state
            .pending_join_stubs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pending.iter().cloned().collect()
    };
    let groups = state.named_groups.read().await;
    groups
        .iter()
        .find(|(id, info)| {
            !pending.iter().any(|p| p == id.as_str())
                && info.home.is_some()
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
    // Round-2 fix 3: the founding agent provisions as ROAMING — ADR-0038
    // requires the Home agent to follow the user across machines, so the
    // invariant holds from first provisioning instead of warning on every
    // fresh install. NOMINAL UNTIL ADR-0043: placement is still the
    // ADR-0037 placeholder (no move protocol, no enforcement) — this bit
    // is the stated intent; 0043 makes it load-bearing.
    placements.insert(local_hex.clone(), crate::groups::MemberPlacement::Roaming);
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

/// Reseal EXISTING Home metadata (round-2 fix 1): keep the metadata as
/// restored, but push it through a fresh OwnerCertified-aware seal so the
/// `home_digest` rides the signed state hash. Returns the resealed info.
async fn reseal_home(state: &Arc<AppState>, group_id: &str) -> Option<crate::groups::GroupInfo> {
    let signing_kp = state.agent.identity().agent_keypair();
    let mut info = {
        let groups = state.named_groups.read().await;
        groups.get(group_id).cloned()?
    };
    info.home.as_ref()?;
    // Round-3 fix b: explicit Admin-role gate — resealing writes a signed
    // commit for the group; only an active Admin (or better) of THIS group
    // may author it. find_home guarantees it on the trusted path, but this
    // function is also the chokepoint for any future caller.
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    if !info
        .caller_role(&local_hex)
        .is_some_and(|role| role.at_least(crate::groups::GroupRole::Admin))
    {
        tracing::warn!(
            group_id,
            "refusing to reseal Home metadata: local agent is not an active Admin"
        );
        return None;
    }
    if seal_commit_owner_certified(state, &mut info, signing_kp, now_millis_u64())
        .await
        .is_err()
    {
        tracing::error!(group_id, "Home reseal failed");
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
        tracing::error!(group_id, "resealed Home could not be persisted");
        return None;
    }
    Some(info)
}

/// Write the marker if it is missing or points elsewhere.
async fn repair_or_write_marker(
    state: &AppState,
    owner_hex: &str,
    marker_path: &std::path::Path,
    id: &str,
    info: &crate::groups::GroupInfo,
) {
    let needs_repair = read_verified_marker(state, owner_hex)
        .await
        .is_none_or(|m| m.group_id != id);
    if needs_repair {
        tracing::info!(group_id = %id, "Home already present; recording marker");
        write_marker(
            marker_path,
            &HomeMarker {
                group_id: id.to_string(),
                owner_user_id: owner_hex.to_string(),
                provisioned_at_ms: info
                    .home
                    .as_ref()
                    .map_or_else(now_millis_u64, |h| h.provisioned_at_ms),
            },
        )
        .await;
    }
}

/// Round-3/4 fix a: restore-side digest verification for EVERY group with
/// nonempty `home` metadata (not just the trusted-Home pick), running
/// BEFORE any owned-install guard so un-owned and cert-less installs are
/// covered too. A record whose state hash does not commit to its digest is
/// legacy-unsigned or tampered; reseal only when the group is OUR-owner
/// Home policy with our active Admin seat, otherwise strip + warn (with no
/// owner at all there is nobody entitled to reseal — everything strips).
async fn verify_restored_home_records(
    state: &Arc<AppState>,
    owner: Option<&crate::identity::UserId>,
) {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let records: Vec<(String, bool, bool)> = {
        let groups = state.named_groups.read().await;
        groups
            .iter()
            .filter(|(_, info)| info.home.is_some() && !info.state_hash_is_current())
            .map(|(id, info)| {
                let ours = owner.is_some_and(|owner| is_home_policy(&info.policy, owner));
                let admin = info
                    .caller_role(&local_hex)
                    .is_some_and(|r| r.at_least(crate::groups::GroupRole::Admin));
                (id.clone(), ours, admin)
            })
            .collect()
    };
    for (id, ours, admin) in records {
        if ours && admin {
            tracing::warn!(
                group_id = %id,
                "restored Home metadata is not covered by the sealed state hash; resealing"
            );
            if reseal_home(state, &id).await.is_some() {
                tracing::info!(group_id = %id, "legacy Home metadata resealed");
            } else {
                tracing::warn!(
                    group_id = %id,
                    "reseal failed; stripping untrusted Home metadata"
                );
                strip_home_metadata(state, &id).await;
            }
        } else {
            tracing::warn!(
                group_id = %id,
                "restored Home metadata is unsigned and the group is not ours to reseal \
                 (foreign owner, non-Home policy, or no Admin seat); stripping"
            );
            strip_home_metadata(state, &id).await;
        }
    }
}

/// Strip untrusted Home metadata from a group (persisted).
async fn strip_home_metadata(state: &AppState, group_id: &str) {
    let _ = persist_named_groups_mutation(state, |groups| {
        if let Some(info) = groups.get_mut(group_id) {
            info.home = None;
        }
        true
    })
    .await;
}

/// Auto-provision the Home space for an owned install. Idempotent and
/// best-effort: never fails startup — a provisioning failure logs loudly
/// and retries on the next daemon start (no marker is written on failure).
pub(in crate::server) async fn provision_home(state: &Arc<AppState>) {
    // Round-4 fix 1: the restore sweep runs FIRST, before ANY owned-install
    // guard — EVERY restored nonempty `home` record is digest-verified even
    // on un-owned installs or installs without an agent certificate (there
    // is simply nobody entitled to reseal, so unsigned records strip).
    let owner_opt = state.agent.identity().user_keypair().map(|kp| kp.user_id());
    verify_restored_home_records(state, owner_opt.as_ref()).await;

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
        // Round-2 fix 1: a restored Home whose state hash does not commit
        // to its (nonempty) metadata is LEGACY-UNSIGNED (a `9c86f2d`-era
        // Home sealed before `home_digest` existed) or tampered. We are
        // the owner with an active Admin seat (find_home guarantees it),
        // so reseal the existing metadata through the provisioning commit
        // path; if resealing is impossible, strip the metadata and warn —
        // never keep trusting unsigned Home claims.
        if info.home.is_some() && !info.state_hash_is_current() {
            tracing::warn!(
                group_id = %id,
                "restored Home metadata is not covered by the sealed state hash; resealing"
            );
            match reseal_home(state, &id).await {
                Some(resealed) => {
                    tracing::info!(group_id = %id, "legacy Home metadata resealed");
                    repair_or_write_marker(state, &owner_hex, &marker_path, &id, &resealed).await;
                    return;
                }
                None => {
                    tracing::warn!(
                        group_id = %id,
                        "could not reseal Home metadata; stripping untrusted metadata"
                    );
                    let _ = persist_named_groups_mutation(state, |groups| {
                        if let Some(info) = groups.get_mut(&id) {
                            info.home = None;
                        }
                        true
                    })
                    .await;
                    // Fall through: the (now unstamped) group becomes a
                    // recovery candidate below and is re-stamped fresh.
                }
            }
        } else {
            repair_or_write_marker(state, &owner_hex, &marker_path, &id, &info).await;
        }
        return;
    }

    // 2) Crash recovery (review fix 3): a group matching the FULL Home
    //    policy exists but was never stamped (crash between create and
    //    stamp, or a failed stamp/persist). Adopt the OLDEST such group —
    //    complete its metadata + seal instead of minting a duplicate.
    let candidate: Option<String> = {
        // #487: same durability rule as find_home — a pending join stub
        // must not be adopted/stamped as this machine's Home. Guard is
        // scoped before the await (Send futures).
        let pending: Vec<String> = {
            let pending = state
                .pending_join_stubs
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            pending.iter().cloned().collect()
        };
        let groups = state.named_groups.read().await;
        let mut matches: Vec<(String, u64)> = groups
            .iter()
            .filter(|(id, info)| {
                !pending.iter().any(|p| p == id.as_str())
                    && info.home.is_none()
                    && is_home_candidate(info, &owner)
            })
            .map(|(id, info)| (id.clone(), info.created_at))
            .collect();
        matches.sort_by_key(|(_, created)| *created);
        matches.into_iter().next().map(|(id, _)| id)
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
    // Round-2 fix 2: stamp the group id the creation call RETURNED — never
    // re-scan. A scan could pick a concurrently provisioned same-policy
    // group (or a pre-existing one) and stamp the wrong roster.
    let body_bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    let created: Option<String> = serde_json::from_slice::<serde_json::Value>(&body_bytes)
        .ok()
        .and_then(|body| {
            body["group_id"]
                .as_str()
                .map(std::string::ToString::to_string)
        });
    let Some(group_id) = created else {
        tracing::error!("Home creation response carried no group_id; marker not written");
        return;
    };
    // Defensive existence check (the create path inserted it durably).
    if !state.named_groups.read().await.contains_key(&group_id) {
        tracing::error!(
            group_id = %group_id,
            "Home creation returned an id that is not in the roster; marker not written"
        );
        return;
    }
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
            // #469 (A3): the Home-join pin (`x0x group join --home
            // --owner <hex>`) needs the owner's user id visible where the
            // operator actually looks — `x0x home` prints this payload
            // verbatim. `find_home` only matches a group whose admission
            // axis is OwnerCertified(owner), so this IS the Home policy
            // admission owner id (additive, backwards-compatible field).
            "owner_user_id": hex::encode(owner.as_bytes()),
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
///
/// Issue #446 (review round 2): requires the DURABLE owner — and the
/// underlying PATCH requires it too when the target is the Home (see
/// `update_named_group`), so the alias cannot be bypassed via PATCH.
/// Enforced at the route layer (`requires_durable_owner`) and here.
pub(in crate::server) async fn rename_home(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(req): Json<RenameHomeRequest>,
) -> Response {
    if !actor.is_durable_owner() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "renaming the Home requires the durable API token (not a session token)"
            })),
        )
            .into_response();
    }
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
    update_named_group(
        State(state),
        axum::extract::Extension(actor),
        Path(group_id),
        Json(update),
    )
    .await
    .into_response()
}

#[cfg(test)]
pub(in crate::server::routes) mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    /// Owned test state: user key (deterministic seed so the owner id is
    /// stable across the "restart" arm) + builder-issued agent certificate.
    pub(in crate::server::routes) async fn owned_state(
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

    pub(in crate::server::routes::home) fn owner_of(state: &AppState) -> crate::identity::UserId {
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
            Some(&crate::groups::MemberPlacement::Roaming),
            "founding agent provisions Roaming (ADR-0038 roaming invariant; \
             nominal until ADR-0043 enforcement)"
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
        // #469 (A3): the payload carries the Home admission owner's user
        // id so `x0x group join --home --owner <hex>` has a place to read
        // the pin from (`x0x home` prints this payload verbatim).
        let expected_owner = hex::encode(
            crate::identity::UserKeypair::from_seed(&[0x41; 32])?
                .user_id()
                .as_bytes(),
        );
        assert_eq!(body["owner_user_id"], expected_owner.as_str());
        assert_eq!(body["owner_user_id"].as_str().map(str::len), Some(64));
        // Founding agent is provisioned Roaming (round-2 fix 3): the
        // warning must NOT fire on a fresh Home.
        assert_eq!(
            body["warnings"]["no_roaming_agent"], false,
            "fresh Home carries a Roaming founding agent"
        );
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
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
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

    /// WHY (issue #446, review round 2): `/home/rename` requires the
    /// DURABLE owner — session bearers and riders get 403, the durable
    /// token renames. Pinned end-to-end through the real auth middleware
    /// (route classification + handler gate).
    #[tokio::test]
    async fn home_rename_requires_durable_owner() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x44; 32]).await?;
        provision_home(&state).await;
        let app = axum::Router::new()
            .route("/home/rename", axum::routing::post(rename_home))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::server::auth::auth_middleware,
            ))
            .with_state(Arc::clone(&state));

        let call = |bearer: String, name: &'static str| {
            let app = app.clone();
            async move {
                app.clone()
                    .oneshot(
                        Request::post("/home/rename")
                            .header("authorization", format!("Bearer {bearer}"))
                            .header("content-type", "application/json")
                            .body(Body::from(serde_json::json!({ "name": name }).to_string()))
                            .expect("body builds"),
                    )
                    .await
            }
        };

        let session = state.sessions.issue(std::time::Instant::now());
        let response = call(session, "Session Rename").await?;
        let (status, body) = response_json(response.into_response()).await?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "session bearer must be refused: {body}"
        );

        // A rider token is denied (ADR-0039 deny-by-default).
        let mut store = state.rider_tokens.lock().await;
        let (rider, _record) = store
            .issue(
                "ab".repeat(32),
                Vec::new(),
                None,
                60,
                String::new(),
                None,
                None,
                crate::server::rider_auth::unix_now_secs(),
            )
            .await?;
        drop(store);
        let response = call(rider, "Rider Rename").await?;
        let (status, body) = response_json(response.into_response()).await?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "rider must be denied: {body}"
        );

        let response = call("test-token".to_string(), "Durable Rename").await?;
        let (status, body) = response_json(response.into_response()).await?;
        assert_eq!(status, StatusCode::OK, "durable bearer must rename: {body}");
        let owner = owner_of(&state);
        let (_, info) = find_home(&state, &owner).await.expect("home");
        assert_eq!(info.name, "Durable Rename");
        Ok(())
    }

    /// WHY (issue #446, review round 2): the underlying PATCH must fence
    /// the SAME authority for the HOME group (else the /home/rename gate
    /// is bypassable by PATCHing the Home `group_id` revealed by
    /// session-readable GET /home), while ordinary groups keep the
    /// session-allowed admin path.
    #[tokio::test]
    async fn patch_on_home_requires_durable_owner_plain_groups_stay_session_allowed(
    ) -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x45; 32]).await?;
        provision_home(&state).await;

        // A plain (non-Home) group created through the real handler.
        let created = super::super::named_groups::create_named_group(
            State(Arc::clone(&state)),
            axum::Json(super::super::named_groups::CreateGroupRequest {
                name: "Plain Space".to_string(),
                description: String::new(),
                display_name: None,
                preset: None,
                policy: None,
            }),
        )
        .await
        .into_response();
        let (status, body) = response_json(created).await?;
        assert_eq!(status, StatusCode::CREATED, "plain group created: {body}");
        let plain_id = body["group_id"]
            .as_str()
            .map(str::to_string)
            .filter(|id| !id.is_empty())
            .unwrap_or_default();
        assert!(
            !plain_id.is_empty(),
            "create response carries the id: {body}"
        );

        let owner = owner_of(&state);
        let (home_id, _) = find_home(&state, &owner).await.expect("home");

        let app = axum::Router::new()
            .route(
                "/groups/:id",
                axum::routing::patch(super::super::named_groups::update_named_group),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::server::auth::auth_middleware,
            ))
            .with_state(Arc::clone(&state));
        let patch = |bearer: String, id: String| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::patch(format!("/groups/{id}"))
                        .header("authorization", format!("Bearer {bearer}"))
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({ "name": "Renamed" }).to_string(),
                        ))
                        .expect("body builds"),
                )
                .await
            }
        };

        // Session bearer: Home PATCH → 403 …
        let session = state.sessions.issue(std::time::Instant::now());
        let response = patch(session.clone(), home_id.clone()).await?;
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "session PATCH on the Home must be refused: {body}"
        );
        // … but a PLAIN group PATCH stays session-allowed (boundary pin).
        let response = patch(session.clone(), plain_id).await?;
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "session PATCH on a plain group must keep working: {body}"
        );

        // Durable bearer: Home PATCH succeeds through the same path.
        let response = patch("test-token".to_string(), home_id).await?;
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "durable PATCH on the Home must rename: {body}"
        );
        Ok(())
    }

    /// WHY (issue #446, review round 3): the round-2 gate matched the
    /// EXACT current Home policy, so a session could flip discoverability
    /// via PATCH /groups/:id/policy, rename while the check was false,
    /// and restore — renaming the Home with a session token. The round-3
    /// fix gates on Home METADATA presence in BOTH PATCH handlers. This
    /// test drives the entire exploit chain and asserts every step fails.
    #[tokio::test]
    async fn home_policy_flip_rename_bypass_is_closed() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x46; 32]).await?;
        provision_home(&state).await;
        let owner = owner_of(&state);
        let (home_id, _) = find_home(&state, &owner).await.expect("home");

        let app = axum::Router::new()
            .route(
                "/groups/:id",
                axum::routing::patch(super::super::named_groups::update_named_group),
            )
            .route(
                "/groups/:id/policy",
                axum::routing::patch(super::super::named_groups::update_group_policy),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::server::auth::auth_middleware,
            ))
            .with_state(Arc::clone(&state));
        let call = |bearer: String, path: String, body: String| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::patch(path)
                        .header("authorization", format!("Bearer {bearer}"))
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .expect("body builds"),
                )
                .await
            }
        };
        let rename_body = serde_json::json!({ "name": "Stolen Rename" }).to_string();
        let flip_body = serde_json::json!({ "discoverability": "listed_to_contacts" }).to_string();
        let session = state.sessions.issue(std::time::Instant::now());

        // Chain step 1 — flip the Home's discoverability: refused.
        let response = call(
            session.clone(),
            format!("/groups/{home_id}/policy"),
            flip_body.clone(),
        )
        .await?;
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "session must not flip the Home policy: {body}"
        );

        // Chain step 2 — even with the policy ALREADY non-Home (flipped
        // by the durable owner), the rename PATCH stays gated: the marker
        // is Home metadata, not the policy shape.
        let response = call(
            "test-token".to_string(),
            format!("/groups/{home_id}/policy"),
            flip_body.clone(),
        )
        .await?;
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "durable may flip the Home policy: {body}"
        );
        let response = call(
            session.clone(),
            format!("/groups/{home_id}"),
            rename_body.clone(),
        )
        .await?;
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "session rename on a policy-flipped Home must STILL be refused: {body}"
        );

        // Chain step 3 — restoring the policy is the durable owner's act.
        let restore = serde_json::json!({ "discoverability": "hidden" }).to_string();
        let response = call(
            session,
            format!("/groups/{home_id}/policy"),
            restore.clone(),
        )
        .await?;
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "session must not restore the Home policy either: {body}"
        );
        let response = call(
            "test-token".to_string(),
            format!("/groups/{home_id}"),
            rename_body,
        )
        .await?;
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::OK, "durable renames the Home: {body}");

        // Rider arm: the policy PATCH is not rider-allowed at all.
        let mut store = state.rider_tokens.lock().await;
        let (rider, _record) = store
            .issue(
                "cd".repeat(32),
                Vec::new(),
                None,
                60,
                String::new(),
                None,
                None,
                crate::server::rider_auth::unix_now_secs(),
            )
            .await?;
        drop(store);
        let response = call(rider, format!("/groups/{home_id}/policy"), restore).await?;
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "rider must be denied on the policy PATCH: {body}"
        );
        Ok(())
    }

    /// WHY (issue #446, review round 4): the central Home-mutation fence
    /// (`home_mutation_requires_durable`) covers EVERY mutating group
    /// route. This matrix drives each through the REAL auth middleware:
    /// session → typed 403, rider → 403, durable → past the gate (the
    /// exact past-gate outcome is body/state dependent; ≠403 proves the
    /// fence passed). Benign bodies keep the durable arms non-destructive
    /// except withdraw, which runs last.
    #[tokio::test]
    async fn home_all_mutation_routes_three_principal_matrix() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x47; 32]).await?;
        provision_home(&state).await;
        let owner = owner_of(&state);
        let (home_id, _) = find_home(&state, &owner).await.expect("home");
        let stranger = "ef".repeat(32);

        let app = axum::Router::new()
            .route(
                "/groups/:id",
                axum::routing::patch(super::super::named_groups::update_named_group),
            )
            .route(
                "/groups/:id",
                axum::routing::delete(super::super::named_groups::leave_group),
            )
            .route(
                "/groups/:id/policy",
                axum::routing::patch(super::super::named_groups::update_group_policy),
            )
            .route(
                "/groups/:id/state/seal",
                axum::routing::post(super::super::named_groups::seal_group_state),
            )
            .route(
                "/groups/:id/invite",
                axum::routing::post(super::super::named_groups::create_group_invite),
            )
            .route(
                "/groups/:id/requests/:request_id/approve",
                axum::routing::post(super::super::named_groups::approve_join_request),
            )
            .route(
                "/groups/:id/requests/:request_id/reject",
                axum::routing::post(super::super::named_groups::reject_join_request),
            )
            .route(
                "/groups/:id/state/withdraw",
                axum::routing::post(super::super::named_groups::withdraw_group_state),
            )
            .route(
                "/groups/:id/members",
                axum::routing::post(super::super::named_groups::add_named_group_member),
            )
            .route(
                "/groups/:id/members/:agent_id",
                axum::routing::delete(super::super::named_groups::remove_named_group_member),
            )
            .route(
                "/groups/:id/members/:agent_id/role",
                axum::routing::patch(super::super::named_groups::update_member_role),
            )
            .route(
                "/groups/:id/ban/:agent_id",
                axum::routing::post(super::super::named_groups::ban_group_member),
            )
            .route(
                "/groups/:id/ban/:agent_id",
                axum::routing::delete(super::super::named_groups::unban_group_member),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::server::auth::auth_middleware,
            ))
            .with_state(Arc::clone(&state));

        let rider = {
            let mut store = state.rider_tokens.lock().await;
            let (token, _record) = store
                .issue(
                    "99".repeat(32),
                    Vec::new(),
                    None,
                    60,
                    String::new(),
                    None,
                    None,
                    crate::server::rider_auth::unix_now_secs(),
                )
                .await?;
            token
        };
        let session = state.sessions.issue(std::time::Instant::now());

        // (label, method, path, body, durable_expects_200). The durable
        // arm must prove AUTHORIZED pass: rename/policy really mutate
        // (200); remove/ban/unban target a non-member stranger, so the
        // durable arm passes fence+admin and lands in ordinary target
        // resolution — asserted by "not the fence's typed error".
        // add-member and role-change are handled separately after the
        // certified add seats a REAL target (an absent stranger would
        // 404 before the admin check, proving nothing).
        let routes: &[(&str, &str, String, Option<serde_json::Value>, bool)] = &[
            (
                "PATCH /groups/:id (rename)",
                "PATCH",
                format!("/groups/{home_id}"),
                Some(serde_json::json!({ "name": "X" })),
                true,
            ),
            (
                "PATCH /groups/:id/policy",
                "PATCH",
                format!("/groups/{home_id}/policy"),
                Some(serde_json::json!({ "discoverability": "listed_to_contacts" })),
                true,
            ),
            (
                "DELETE /groups/:id/members/:agent_id",
                "DELETE",
                format!("/groups/{home_id}/members/{stranger}"),
                None,
                false,
            ),
            (
                "POST /groups/:id/ban/:agent_id",
                "POST",
                format!("/groups/{home_id}/ban/{stranger}"),
                None,
                false,
            ),
            (
                "DELETE /groups/:id/ban/:agent_id",
                "DELETE",
                format!("/groups/{home_id}/ban/{stranger}"),
                None,
                false,
            ),
        ];
        for (label, method, path, body, durable_200) in routes {
            let send = |bearer: String, body: Option<serde_json::Value>| {
                let app = app.clone();
                let method: &'static str = match *method {
                    "PATCH" => "PATCH",
                    "POST" => "POST",
                    _ => "DELETE",
                };
                let path = path.clone();
                async move {
                    let builder = Request::builder()
                        .method(method)
                        .uri(path)
                        .header("authorization", format!("Bearer {bearer}"))
                        .header("content-type", "application/json");
                    let req = match body {
                        Some(json) => builder.body(Body::from(json.to_string())),
                        None => builder.body(Body::empty()),
                    }
                    .expect("request builds");
                    app.oneshot(req).await
                }
            };
            let response = send(session.clone(), body.clone()).await?;
            let (status, out) = response_json(response).await?;
            assert_eq!(status, StatusCode::FORBIDDEN, "{label} session: {out}");
            assert!(
                out["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("durable API token"),
                "{label} session 403 must be typed: {out}"
            );
            let response = send(rider.clone(), body.clone()).await?;
            let (status, out) = response_json(response).await?;
            assert_eq!(status, StatusCode::FORBIDDEN, "{label} rider: {out}");
            let response = send("test-token".to_string(), body.clone()).await?;
            let (status, out) = response_json(response).await?;
            if *durable_200 {
                assert_eq!(
                    status,
                    StatusCode::OK,
                    "{label} durable arm must be an authorized 200: {out}"
                );
            } else {
                // Authorized past fence AND admin gate; the outcome is
                // ordinary target resolution (stranger is not a member),
                // never the fence's typed error.
                assert_ne!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{label} durable must clear the fence: {out}"
                );
                assert!(
                    !out["error"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("durable API token"),
                    "{label} durable outcome must not be the fence error: {out}"
                );
            }
        }

        // add-member: a REAL authorized add. The candidate is certified
        // by this install's owner (cert announced into the discovery
        // cache) and supplies a real TreeKEM key package — Home is
        // MlsEncrypted/TreeKEM, so the direct-add path requires both.
        // Session and rider are fenced; durable gets a real 200.
        let user_kp = state
            .agent
            .identity()
            .user_keypair()
            .expect("owned fixture has a user key");
        let target_kp = crate::identity::AgentKeypair::generate()?;
        let target_id = target_kp.agent_id();
        let target_hex = hex::encode(target_id.as_bytes());
        let cert = crate::identity::AgentCertificate::issue(user_kp, &target_kp)?;
        {
            let cache = state.agent.identity_discovery_cache();
            cache.write().await.insert(
                target_id,
                crate::DiscoveredAgent {
                    agent_id: target_id,
                    machine_id: crate::identity::MachineId([0u8; 32]),
                    user_id: cert.user_id().ok(),
                    self_name: None,
                    addresses: Vec::new(),
                    announced_at: 0,
                    last_seen: 0,
                    machine_public_key: Vec::new(),
                    nat_type: None,
                    can_receive_direct: None,
                    is_relay: None,
                    is_coordinator: None,
                    reachable_via: Vec::new(),
                    relay_candidates: Vec::new(),
                    cert_not_after: cert.not_after(),
                    agent_certificate: Some(cert),
                    agent_public_key: Vec::new(),
                    cert_digest: None,
                },
            );
        }
        let prepared = crate::mls::TreeKemMlsGroup::prepare_member(target_id, &[0x5e; 32])?;
        let kp_b64 = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(prepared.key_package_bytes())
        };
        let add_body = serde_json::json!({
            "agent_id": target_hex,
            "treekem_key_package_b64": kp_b64,
        });
        let add_json = |bearer: String| {
            let app = app.clone();
            let body = add_body.clone();
            let path = format!("/groups/{home_id}/members");
            async move {
                app.oneshot(
                    Request::post(path)
                        .header("authorization", format!("Bearer {bearer}"))
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .expect("request builds"),
                )
                .await
            }
        };
        let response = add_json(session.clone()).await?;
        let (status, out) = response_json(response).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "add-member session: {out}");
        assert!(
            out["error"]
                .as_str()
                .unwrap_or_default()
                .contains("durable API token"),
            "add-member session 403 must be the fence: {out}"
        );
        let response = add_json(rider.clone()).await?;
        let (status, out) = response_json(response).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "add-member rider: {out}");
        let response = add_json("test-token".to_string()).await?;
        let (status, out) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "add-member durable arm must be an AUTHORIZED 200 (certified agent + key package): {out}"
        );
        assert_eq!(out["ok"], true);
        assert!(
            state
                .named_groups
                .read()
                .await
                .get(&home_id)
                .is_some_and(|info| info.has_active_member(&target_hex)),
            "the durable add must really have seated the certified member"
        );

        // role-change: the target is the PRESENT, certified member just
        // seated — the handler resolves the target BEFORE the admin
        // check, so an absent stranger would 404 without ever proving
        // the admin authority. With a real target: session/rider are
        // fenced, durable performs an authorized role change (200).
        let role_json = |bearer: String| {
            let app = app.clone();
            let path = format!("/groups/{home_id}/members/{target_hex}/role");
            async move {
                app.oneshot(
                    Request::patch(path)
                        .header("authorization", format!("Bearer {bearer}"))
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({ "role": "admin" }).to_string(),
                        ))
                        .expect("request builds"),
                )
                .await
            }
        };
        let response = role_json(session.clone()).await?;
        let (status, out) = response_json(response).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "role-change session: {out}");
        assert!(
            out["error"]
                .as_str()
                .unwrap_or_default()
                .contains("durable API token"),
            "role-change session 403 must be the fence: {out}"
        );
        let response = role_json(rider.clone()).await?;
        let (status, out) = response_json(response).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "role-change rider: {out}");
        let response = role_json("test-token".to_string()).await?;
        let (status, out) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "role-change durable arm must be an AUTHORIZED 200 on the seated member: {out}"
        );
        assert!(
            state
                .named_groups
                .read()
                .await
                .get(&home_id)
                .is_some_and(
                    |info| info.caller_role(&target_hex) == Some(crate::groups::GroupRole::Admin)
                ),
            "the durable role change must really have taken effect"
        );

        // Review round 7: the four remaining Home-admin mutation routes.
        // seal and invite perform real authorized mutations (200);
        // approve/reject reference a nonexistent request, so the durable
        // arm proves fence+authority passage by landing in ordinary
        // request resolution — never the fence's typed error.
        let round7: &[(&str, String, Option<serde_json::Value>, bool)] = &[
            ("seal", format!("/groups/{home_id}/state/seal"), None, true),
            ("invite", format!("/groups/{home_id}/invite"), None, true),
            (
                "approve",
                format!("/groups/{home_id}/requests/{stranger}/approve"),
                None,
                false,
            ),
            (
                "reject",
                format!("/groups/{home_id}/requests/{stranger}/reject"),
                None,
                false,
            ),
        ];
        for (label, path, body, durable_200) in round7 {
            let send = |bearer: String, body: Option<serde_json::Value>| {
                let app = app.clone();
                let path = path.clone();
                async move {
                    let builder = Request::post(path)
                        .header("authorization", format!("Bearer {bearer}"))
                        .header("content-type", "application/json");
                    let req = match body {
                        Some(json) => builder.body(Body::from(json.to_string())),
                        None => builder.body(Body::empty()),
                    }
                    .expect("request builds");
                    app.oneshot(req).await
                }
            };
            let response = send(session.clone(), body.clone()).await?;
            let (status, out) = response_json(response).await?;
            assert_eq!(status, StatusCode::FORBIDDEN, "{label} session: {out}");
            assert!(
                out["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("durable API token"),
                "{label} session 403 must be the fence: {out}"
            );
            let response = send(rider.clone(), body.clone()).await?;
            let (status, out) = response_json(response).await?;
            assert_eq!(status, StatusCode::FORBIDDEN, "{label} rider: {out}");
            let response = send("test-token".to_string(), body.clone()).await?;
            let (status, out) = response_json(response).await?;
            if *durable_200 {
                assert_eq!(
                    status,
                    StatusCode::OK,
                    "{label} durable arm must be an authorized 200: {out}"
                );
            } else {
                assert_ne!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{label} durable must clear the fence: {out}"
                );
                assert!(
                    !out["error"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("durable API token"),
                    "{label} durable outcome must not be the fence error: {out}"
                );
            }
        }

        // leave: its OWN live sole-member Home on a fresh state (after
        // the certified add the main Home has a second member, so a
        // self-leave there would be LastAdminBlocked — a 409, not an
        // authorized pass). The durable arm proves a real SoleMemberDelete.
        let dir_leave = tempfile::tempdir()?;
        let state_l = owned_state(dir_leave.path(), [0x49; 32]).await?;
        provision_home(&state_l).await;
        let (home_l, _) = find_home(&state_l, &owner_of(&state_l))
            .await
            .expect("leave home");
        let app_l = axum::Router::new()
            .route(
                "/groups/:id",
                axum::routing::delete(super::super::named_groups::leave_group),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state_l),
                crate::server::auth::auth_middleware,
            ))
            .with_state(Arc::clone(&state_l));
        let response = app_l
            .clone()
            .oneshot(
                Request::delete(format!("/groups/{home_l}"))
                    .header(
                        "authorization",
                        format!(
                            "Bearer {}",
                            state_l.sessions.issue(std::time::Instant::now())
                        ),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        let (status, out) = response_json(response).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "leave session: {out}");
        let response = app_l
            .clone()
            .oneshot(
                Request::delete(format!("/groups/{home_l}"))
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())?,
            )
            .await?;
        let (status, out) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "leave durable arm must be an authorized SoleMemberDelete of a LIVE Home: {out}"
        );
        assert_eq!(out["ok"], true);

        // withdraw: its OWN live Home on a fresh state — the durable arm
        // proves an authorized terminal withdrawal of a live group, not
        // of the tombstone the leave above just created.
        let dir2 = tempfile::tempdir()?;
        let state2 = owned_state(dir2.path(), [0x48; 32]).await?;
        provision_home(&state2).await;
        let (home2, _) = find_home(&state2, &owner_of(&state2))
            .await
            .expect("home 2");
        let app2 = axum::Router::new()
            .route(
                "/groups/:id/state/withdraw",
                axum::routing::post(super::super::named_groups::withdraw_group_state),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state2),
                crate::server::auth::auth_middleware,
            ))
            .with_state(Arc::clone(&state2));
        let response = app2
            .clone()
            .oneshot(
                Request::post(format!("/groups/{home2}/state/withdraw"))
                    .header(
                        "authorization",
                        format!(
                            "Bearer {}",
                            state2.sessions.issue(std::time::Instant::now())
                        ),
                    )
                    .body(Body::empty())?,
            )
            .await?;
        let (status, out) = response_json(response).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "withdraw session: {out}");
        let response = app2
            .clone()
            .oneshot(
                Request::post(format!("/groups/{home2}/state/withdraw"))
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())?,
            )
            .await?;
        let (status, out) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "withdraw durable arm must be an authorized terminal withdrawal of a LIVE Home: {out}"
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

#[cfg(test)]
mod round2_tests {
    use super::tests::{owned_state, owner_of};
    use super::*;

    /// WHY (round-2 fix 1): a persisted Home from the `9c86f2d` era (or an
    /// attacker-persisted roster) carries nonempty `home` metadata whose
    /// digest was NEVER sealed — the stored state hash predates
    /// `home_digest`. Restore (provision_home at startup) must detect the
    /// stale hash and RESEAL the metadata through the provisioning commit
    /// path, never keep trusting it unsigned.
    #[tokio::test]
    async fn persisted_unsigned_home_metadata_is_resealed_on_restore() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x50; 32]).await?;
        let owner = owner_of(&state);

        // First provisioning (normal, sealed).
        provision_home(&state).await;
        let (id, info) = find_home(&state, &owner).await.expect("home");
        assert!(
            info.state_hash_is_current(),
            "fresh Home is sealed: digest committed"
        );

        // Simulate the 9c86f2d-era / attacker state: rewrite the persisted
        // roster with the metadata PRESENT but the state hash recomputed
        // WITHOUT the digest (exactly what a pre-home_digest daemon stored).
        let mut legacy = info.clone();
        let sealed_hash = legacy.state_hash.clone();
        {
            let meta = crate::groups::state_commit::GroupPublicMeta {
                home_digest: None,
                ..legacy.public_meta()
            };
            let roster_root = crate::groups::compute_roster_root(&legacy.members_v2);
            let policy_hash = crate::groups::compute_policy_hash(&legacy.policy);
            let meta_hash = crate::groups::compute_public_meta_hash(&meta);
            legacy.state_hash = crate::groups::state_commit::compute_state_hash(
                legacy.stable_group_id(),
                legacy.state_revision,
                legacy.prev_state_hash.as_deref(),
                &roster_root,
                &policy_hash,
                &meta_hash,
                legacy.security_binding.as_deref(),
                legacy.withdrawn,
            );
        }
        assert_ne!(legacy.state_hash, sealed_hash);
        assert!(
            !legacy.state_hash_is_current(),
            "legacy-unsigned metadata detected"
        );
        // Round-3 fix c: REAL write-to-disk + reload through the restore
        // path (not an in-memory swap) — persist the legacy roster, reload
        // via load_named_groups exactly like a daemon restart, and swap the
        // reloaded map into state.
        state.named_groups.write().await.insert(id.clone(), legacy);
        assert!(
            super::super::named_groups::save_named_groups(&state).await,
            "legacy roster persisted to disk"
        );
        let reloaded = super::super::named_groups::load_named_groups_merged(
            &state.named_groups_path,
            &state.home_suite_groups_path,
        )
        .await?;
        assert!(
            reloaded
                .get(&id)
                .is_some_and(|i| !i.state_hash_is_current()),
            "the reloaded record decodes legacy-unsigned, as a restart would see"
        );
        *state.named_groups.write().await = reloaded;

        // Restore path: provision_home must reseal.
        provision_home(&state).await;
        let (_, resealed) = find_home(&state, &owner).await.expect("home survives");
        assert!(
            resealed.state_hash_is_current(),
            "metadata resealed: state hash now commits to the digest"
        );
        assert!(
            resealed.home.is_some(),
            "metadata kept (not stripped) when we are the owner+admin"
        );
        Ok(())
    }

    /// WHY (round-2 fix 1, strip branch): when resealing is impossible the
    /// untrusted metadata is STRIPPED — unsigned claims never survive a
    /// restore.
    #[tokio::test]
    async fn unrestorable_home_metadata_is_stripped() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x51; 32]).await?;
        let owner = owner_of(&state);
        provision_home(&state).await;
        let (id, info) = find_home(&state, &owner).await.expect("home");

        // Round-5 fix (codex r4/r5): exercise the reseal-FAILURE branch
        // itself. The caller STAYS Admin (admin gate passes, reseal_home is
        // genuinely invoked); the seal then fails because a SECOND member's
        // evidence is missing with the grace window long expired (verdict =
        // Failed → the owner-certified seal wrapper refuses with the typed
        // eviction-required error), driving the "reseal failed; stripping"
        // path — not the non-admin strip branch.
        let mut broken = info.clone();
        let meta = crate::groups::state_commit::GroupPublicMeta {
            home_digest: None,
            ..broken.public_meta()
        };
        let roster_root = crate::groups::compute_roster_root(&broken.members_v2);
        let policy_hash = crate::groups::compute_policy_hash(&broken.policy);
        let meta_hash = crate::groups::compute_public_meta_hash(&meta);
        broken.state_hash = crate::groups::state_commit::compute_state_hash(
            broken.stable_group_id(),
            broken.state_revision,
            broken.prev_state_hash.as_deref(),
            &roster_root,
            &policy_hash,
            &meta_hash,
            broken.security_binding.as_deref(),
            broken.withdrawn,
        );
        // A second member whose certificate never resolved and whose grace
        // window expired long ago: the seal verdict is Failed for it, so
        // reseal_home's seal refuses (ordinary seals refuse on non-clean
        // verdicts; the eviction path is not taken inside reseal).
        let stranger = crate::identity::AgentKeypair::generate()?;
        let stranger_hex = hex::encode(stranger.agent_id().as_bytes());
        broken.add_member(
            stranger_hex.clone(),
            crate::groups::GroupRole::Member,
            None,
            None,
        );
        if let Some(member) = broken.members_v2.get_mut(&stranger_hex) {
            member.certificate_missing_since_ms = Some(0); // grace expired long ago
        }
        assert!(!broken.state_hash_is_current(), "unsigned condition holds");
        state.named_groups.write().await.insert(id.clone(), broken);

        provision_home(&state).await;
        // Either stripped + re-stamped fresh, or (if the wrapper still
        // refused) metadata gone — but NEVER trusted-unsigned.
        let after = state.named_groups.read().await;
        let info = after.get(&id).expect("group kept");
        assert!(
            info.home
                .as_ref()
                .is_none_or(|_| info.state_hash_is_current()),
            "metadata is either absent or sealed — never unsigned"
        );
        Ok(())
    }

    /// WHY (round-2 fix 3): fresh provisioning records the founding agent
    /// as Roaming and GET /home reports the invariant satisfied.
    #[tokio::test]
    async fn fresh_home_provisions_roaming_founding_agent() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x52; 32]).await?;
        provision_home(&state).await;
        let owner = owner_of(&state);
        let (_, info) = find_home(&state, &owner).await.expect("home");
        let home = info.home.as_ref().expect("meta");
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        assert_eq!(
            home.placements.get(&local_hex),
            Some(&crate::groups::MemberPlacement::Roaming)
        );
        assert!(
            home_roaming_warning_for(&info).is_none(),
            "no warning on a fresh Home"
        );
        Ok(())
    }

    /// Issue #451 end-to-end acceptance: after this daemon provisions a
    /// Home, every durable store a v0.40.4 binary reads at startup parses
    /// with the frozen old shapes — no `owner_certified` anywhere it looks —
    /// and a downgrade-window REWRITE of `named_groups.json` by the old
    /// binary cannot destroy the Home: the re-upgraded daemon restores the
    /// authoritative sidecar state.
    #[tokio::test]
    async fn provisioned_home_store_is_downgrade_safe() {
        use super::super::named_groups::old_decoder_451;
        use std::collections::HashMap;

        let dir = tempfile::tempdir().expect("tempdir");
        let data = dir.path().to_path_buf();
        let state = owned_state(&data, [0x45; 32]).await.expect("owned state");
        provision_home(&state).await;
        let owner = owner_of(&state);
        let (group_id, info) = find_home(&state, &owner).await.expect("Home provisioned");

        // 1) named_groups.json: old decoder parses; the Home id is present
        //    as an inert placeholder; no new variant anywhere in the bytes.
        let named_path = data.join("named_groups.json");
        let legacy = tokio::fs::read_to_string(&named_path)
            .await
            .expect("read roster");
        assert!(
            !legacy.contains("owner_certified"),
            "the #451 crash variant must never reach named_groups.json"
        );
        let old = old_decoder_451::parse_roster(&legacy)
            .expect("frozen v0.40.4 decoder must parse the provisioned store");
        let placeholder = &old[&group_id];
        assert_eq!(
            placeholder.policy.admission,
            old_decoder_451::OldAdmission::InviteOnly
        );
        assert!(placeholder.members_v2.is_empty());
        assert_eq!(
            placeholder.secure_plane,
            crate::mls::SecureGroupPlane::Gss,
            "an old binary must not restore the Home TreeKEM snapshot"
        );
        assert_eq!(placeholder.state_revision, info.state_revision);
        assert_eq!(placeholder.state_hash, info.state_hash);

        // 2) The sidecar carries the real Home state.
        let sidecar_path = data.join(super::super::named_groups::HOME_SUITE_GROUPS_FILE);
        let sidecar_json = tokio::fs::read_to_string(&sidecar_path)
            .await
            .expect("Home-Suite sidecar written");
        let sidecar: HashMap<String, crate::groups::GroupInfo> =
            serde_json::from_str(&sidecar_json).expect("sidecar json");
        let real = &sidecar[&group_id];
        assert!(matches!(
            real.policy.admission,
            crate::groups::GroupAdmission::OwnerCertified(_)
        ));
        assert!(real.home.is_some());
        assert_eq!(real.members_v2.len(), info.members_v2.len());

        // 3) The marker (old binaries never read it) and the snapshot
        //    (old binaries skip it: the placeholder is not TreeKem-tagged).
        assert!(data.join(HOME_MARKER_FILE).exists());
        assert!(
            data.join("treekem")
                .join(format!("{group_id}.snap"))
                .exists(),
            "Home snapshot persists for the re-upgraded binary"
        );

        // 4) member-key-packages.json parses whole-file for an old binary
        //    and carries only event tags v0.40.4 knows.
        let key_packages = data.join("treekem").join("member-key-packages.json");
        if let Ok(cache_json) = tokio::fs::read_to_string(&key_packages).await {
            let cache: serde_json::Value = serde_json::from_str(&cache_json).expect("cache json");
            if let Some(entries) = cache.as_object() {
                for entry in entries.values() {
                    let tag = entry["event"].as_str().expect("event tag");
                    assert!(
                        old_decoder_451::KNOWN_EVENT_TAGS.contains(&tag),
                        "unknown-to-v0.40.4 event tag {tag} in the key-package cache"
                    );
                }
            }
        }

        // 5) Downgrade window: the old binary rewrites named_groups.json
        //    from ITS (placeholder) view — its map has no Home entry, so
        //    the rewrite drops even the placeholder.
        let rewritten = serde_json::to_string(&old).expect("old-binary rewrite");
        tokio::fs::write(&named_path, rewritten)
            .await
            .expect("old-binary rewrite write");

        // 6) Re-upgrade: same data dir, same owner seed → the merged load
        //    restores the authoritative sidecar Home; provisioning adopts
        //    it instead of duplicating.
        let state2 = owned_state(&data, [0x45; 32]).await.expect("restart state");
        provision_home(&state2).await;
        let owner2 = owner_of(&state2);
        let (id2, info2) = find_home(&state2, &owner2)
            .await
            .expect("Home survives the downgrade window");
        assert_eq!(id2, group_id, "no duplicate Home after re-upgrade");
        assert!(matches!(
            info2.policy.admission,
            crate::groups::GroupAdmission::OwnerCertified(_)
        ));
        assert!(info2.home.is_some());
        assert_eq!(info2.members_v2.len(), info.members_v2.len());
    }
}
