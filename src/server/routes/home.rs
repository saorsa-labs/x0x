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
pub(in crate::server) fn is_home_policy(
    policy: &crate::groups::GroupPolicy,
    owner: &crate::identity::UserId,
) -> bool {
    *policy == home_policy(owner)
}

/// #449: where the owner's Home lives, from THIS device's point of view.
///
/// Before this existed, `GET /home` had exactly two outcomes — a local Home
/// or a 404 — so a second owner device could not say "the Home is on another
/// device". It returned its OWN duplicate as the owner's Home instead, which
/// is what made N devices silently become N Homes with no error anywhere.
#[derive(Debug, Clone)]
pub(in crate::server) enum HomeResolution {
    /// We are seated in the owner's canonical Home.
    Local {
        group_id: String,
        info: Box<crate::groups::GroupInfo>,
    },
    /// The canonical Home lives on another device and we hold none.
    Elsewhere { canonical: String },
    /// We hold a Home that LOST the election; adoption into `canonical` is
    /// pending. Our local Home stays fully usable until that completes.
    AdoptionPending { local: String, canonical: String },
    /// No Home anywhere yet, or an un-owned install.
    Unknown,
}

/// Resolve [`HomeResolution`] for the current owner (#449).
///
/// The canonical Home is the Tier-1 `("home")` register winner. Absence of a
/// register value means "no owner device has advertised one yet" — NOT "none
/// exists" — so an un-synced device with its own Home still reports `Local`.
/// Home-shaped groups this device is seated in that are NOT the canonical
/// Home — the duplicates a pre-#449 fork left behind (P4).
pub(in crate::server) async fn home_duplicates(
    state: &Arc<AppState>,
    canonical: &str,
    owner: &crate::identity::UserId,
) -> Vec<String> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let groups = state.named_groups.read().await;
    let mut ids: Vec<String> = groups
        .iter()
        .filter(|(id, info)| {
            id.as_str() != canonical
                && info.stable_group_id() != canonical
                && !info.withdrawn
                && info.home.is_some()
                && is_home_policy(&info.policy, owner)
                && info.has_active_member(&local_hex)
        })
        .map(|(id, _)| id.clone())
        .collect();
    ids.sort();
    ids
}

/// Evidence AGAINST deleting a duplicate Home (#449 P4).
///
/// This is an OBSERVATION, not a safety verdict. An empty list means no
/// evidence was found by these probes at the moment they ran — it does NOT
/// mean the group is safe to delete, because the observation is not held
/// across any subsequent mutation. Automatic retirement is deliberately not
/// implemented; see `docs/design/449-p4-retirement-fence.md`. Withdrawal is terminal and cleans only crypto
/// material: durable history, the group delegations that live ONLY in history,
/// group-scoped task lists and rider grants all key off the group id and would
/// be silently orphaned. So the rule is **join first, retire second, and only
/// when there is provably nothing to lose** — anything else is surfaced to the
/// owner instead of deleted.
///
/// Fails CLOSED: a probe that cannot prove emptiness (unreadable history) is
/// itself a blocker.
pub(in crate::server) async fn home_retire_blockers(
    state: &Arc<AppState>,
    group_id: &str,
) -> Vec<String> {
    let mut blockers = Vec::new();
    let Some(user_kp) = state.agent.identity().user_keypair() else {
        return vec!["un-owned install".to_string()];
    };
    let owner = user_kp.user_id();
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());

    let (stable_id, active_members, join_requests, issued_invites) = {
        let groups = state.named_groups.read().await;
        let Some(info) = groups.get(group_id) else {
            return vec!["group not found".to_string()];
        };
        if info.withdrawn {
            return vec!["already withdrawn".to_string()];
        }
        if !is_home_policy(&info.policy, &owner) {
            return vec!["not a Home for this owner".to_string()];
        }
        (
            info.stable_group_id().to_string(),
            info.active_members()
                .map(|m| m.agent_id.clone())
                .collect::<Vec<_>>(),
            info.join_requests.len(),
            info.issued_invites.len(),
        )
    };

    // Sole membership: another seated agent would lose its space.
    if active_members.len() != 1 || active_members.first() != Some(&local_hex) {
        blockers.push(format!(
            "not the sole member ({} active)",
            active_members.len()
        ));
    }
    if join_requests > 0 {
        blockers.push(format!("{join_requests} pending join request(s)"));
    }
    if issued_invites > 0 {
        blockers.push(format!("{issued_invites} outstanding invite(s)"));
    }

    // Durable history — and therefore group delegations, which live only there.
    //
    // Review P2: a MISSING handle is not evidence of emptiness. History is off
    // by default in the library (`AgentBuilder::with_history`), and a disabled
    // or unopened store says nothing about the rows already on disk at
    // `<data_dir>/history.db` — which an operator can re-enable at any time.
    // Treating `None` as "no history" would let this path delete a Home whose
    // messages and delegations are sitting in a database we simply did not
    // open. "Cannot prove empty" must behave like "not empty", so an absent
    // handle is itself a blocker.
    match state.agent.history() {
        Some(history) => {
            let store = Arc::clone(history.store());
            let query = crate::history::HistoryQuery {
                scope: Some(crate::history::Scope::Group(stable_id.clone())),
                limit: 1,
                ..Default::default()
            };
            match tokio::task::spawn_blocking(move || store.query(&query)).await {
                Ok(Ok(rows)) if !rows.is_empty() => {
                    blockers.push("has durable history (and possibly delegations)".to_string());
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => blockers.push(format!("history unreadable: {e}")),
                Err(e) => blockers.push(format!("history probe failed: {e}")),
            }
        }
        None => blockers.push(
            "history store unavailable — cannot prove this Home has no durable rows".to_string(),
        ),
    }

    // Group-scoped CRDT task lists are namespaced by convention, not keyed,
    // so nothing would clean them up.
    //
    // Review P2: the in-memory manifest is NOT sufficient evidence. Its loader
    // maps read and parse failures to an empty manifest — correct for REST and
    // rehydration, which fail closed elsewhere, but for a destructive decision
    // "could not read the evidence" would masquerade as "there is none". The
    // durable file is therefore probed directly, and an unreadable or
    // unparseable one is a blocker in its own right.
    // Review r3 P2: observe the VALIDATED DURABLE entries, not the in-memory
    // manifest and not a generic-JSON probe. `null` and `{"entries":"corrupt"}`
    // are valid JSON that the typed loader rejects, so a `serde_json::Value`
    // probe would silently drop the unavailable-evidence warning in exactly
    // the cases it exists for.
    let prefixes = [
        format!("x0x.group.{group_id}."),
        format!("x0x.group.{stable_id}."),
    ];
    match crate::server::crdt_subscriptions::probe_manifest_strict(&state.crdt_subscriptions_path)
        .await
    {
        Ok(None) => {}
        Ok(Some(manifest)) => {
            if manifest
                .entries
                .iter()
                .any(|entry| prefixes.iter().any(|p| entry.id.starts_with(p.as_str())))
            {
                blockers.push("has group-scoped task lists".to_string());
            }
        }
        Err(why) => blockers.push(format!(
            "task-list manifest unreadable ({why}) — cannot observe whether this Home has task lists"
        )),
    }

    // Same class for rider grants, read from the durable file under its real
    // schema. An unreadable or wrong-schema store is not proof that the grant
    // set is empty.
    let rider_path = state
        .data_dir
        .join(crate::server::rider_auth::RIDER_TOKENS_FILE);
    match crate::server::rider_auth::probe_granted_groups_strict(&rider_path).await {
        Ok(None) => {}
        Ok(Some(granted)) => {
            if granted
                .iter()
                .any(|g| g == group_id || g == stable_id.as_str())
            {
                blockers.push("a rider token grants this group".to_string());
            }
        }
        Err(why) => blockers.push(format!(
            "rider-token store unreadable ({why}) — cannot observe whether this Home has grants"
        )),
    }

    blockers
}

/// Whether `group_id` is a Home this device can PROVE is retired (r3 P2).
///
/// Proof means: the group is in our own roster and carries the terminal
/// `withdrawn` flag. Not being able to see the group is deliberately NOT
/// proof — a canonical Home living on an unreachable device is simply
/// unknown, and treating unknown as retired would let any partitioned device
/// mint over the owner's real Home.
async fn is_provably_retired(state: &Arc<AppState>, group_id: &str) -> bool {
    state.named_groups.read().await.iter().any(|(id, info)| {
        (id.as_str() == group_id || info.stable_group_id() == group_id) && info.withdrawn
    })
}

/// The canonical Home pointer that should actually govern this device (r3 P2).
///
/// The stored `("home")` record survives the withdrawal of the Home it names —
/// tombstone retention never touches owner-sync state — so a device that
/// retires its own advertised Home would otherwise keep yielding to the dead
/// pointer forever and never build a replacement. Filtering the PUBLISHER was
/// only half the fix; the stored record has to stop governing too.
pub(in crate::server) async fn effective_canonical_home(state: &Arc<AppState>) -> Option<String> {
    let canonical = state
        .owner_sync
        .as_ref()?
        .canonical_home()
        .await
        .map(|home| home.group_id)?;
    if is_provably_retired(state, &canonical).await {
        tracing::info!(
            group_id = %canonical,
            "canonical Home pointer names a group we hold and know to be retired; ignoring it (#449)"
        );
        return None;
    }
    Some(canonical)
}

pub(in crate::server) async fn resolve_home(state: &Arc<AppState>) -> HomeResolution {
    let Some(user_kp) = state.agent.identity().user_keypair() else {
        return HomeResolution::Unknown;
    };
    let owner = user_kp.user_id();
    let local = find_home(state.as_ref(), &owner).await;
    let canonical = effective_canonical_home(state).await;
    // Prefer the CANONICAL Home whenever we are already seated in it. After
    // adoption a device is briefly seated in both its old duplicate and the
    // canonical Home; without this, `find_home`'s smallest-id rule could
    // keep answering with the duplicate.
    if let Some(canonical) = canonical.as_deref() {
        let groups = state.named_groups.read().await;
        if let Some(info) = groups.get(canonical).filter(|info| {
            !info.withdrawn
                && info.home.is_some()
                && is_home_policy(&info.policy, &owner)
                && info.has_active_member(&hex::encode(state.agent.agent_id().as_bytes()))
        }) {
            return HomeResolution::Local {
                group_id: canonical.to_string(),
                info: Box::new(info.clone()),
            };
        }
    }

    match (local, canonical) {
        (Some((group_id, info)), canonical) => {
            match canonical {
                // Seated in a Home the register does NOT name: we lost the
                // election and must adopt the canonical one.
                Some(canonical) if canonical != group_id => HomeResolution::AdoptionPending {
                    local: group_id,
                    canonical,
                },
                // Uncontested, or already the canonical Home.
                _ => HomeResolution::Local {
                    group_id,
                    info: Box::new(info),
                },
            }
        }
        // Not seated anywhere, but the owner's Home is advertised elsewhere.
        (None, Some(canonical)) => HomeResolution::Elsewhere { canonical },
        (None, None) => HomeResolution::Unknown,
    }
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
    // #487 (code review r1 item 2): re-check the pending set AFTER the
    // groups read — a join can insert the marker and publish the stub
    // between a pre-read snapshot and the map acquisition (TOCTOU). The
    // re-check closes the window: any stub published before the map read
    // has its marker by then (pending-set-first ordering).
    loop {
        let pending_before: Vec<String> = {
            let pending = state
                .pending_join_stubs
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            pending.iter().cloned().collect()
        };
        let groups = state.named_groups.read().await;
        // #449: `.find()` over an unordered map made this nondeterministic
        // once a device was seated in more than one Home-shaped group —
        // which is exactly the state adoption passes through. Select the
        // smallest stable id so every caller agrees, and never match a
        // WITHDRAWN group: withdrawal keeps `members_v2` and `home`
        // populated, so a retired Home would otherwise still resolve here
        // and wedge `GET /home` plus re-provisioning forever (D5).
        let found = groups
            .iter()
            .filter(|(id, info)| {
                !pending_before.iter().any(|p| p == id.as_str())
                    && !info.withdrawn
                    && info.home.is_some()
                    && is_home_policy(&info.policy, owner)
                    && info.has_active_member(&local_hex)
            })
            .min_by(|(_, a), (_, b)| a.stable_group_id().cmp(b.stable_group_id()))
            .map(|(id, info)| (id.clone(), info.clone()));
        let pending_after: Vec<String> = {
            let pending = state
                .pending_join_stubs
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            pending.iter().cloned().collect()
        };
        // #487 (code review r2 item 4): compare set CONTENTS, not length —
        // a concurrent removal+insertion can swap an id without growing
        // the count. Sort for deterministic comparison (HashSet iteration
        // is unordered).
        let mut before_sorted = pending_before.clone();
        before_sorted.sort();
        let mut after_sorted = pending_after.clone();
        after_sorted.sort();
        if after_sorted == before_sorted {
            return found;
        }
        // The pending set changed during the read: retry with a fresh
        // snapshot.
    }
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
        // #487: same durability rule + TOCTOU recheck as find_home — the
        // pending-set snapshot is re-verified after the groups read
        // (code review r2 item 4: the adoption path previously had no
        // recheck and could stamp a newly published pending stub).
        loop {
            let pending_before: Vec<String> = {
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
                    !pending_before.iter().any(|p| p == id.as_str())
                        && info.home.is_none()
                        && is_home_candidate(info, &owner)
                })
                .map(|(id, info)| (id.clone(), info.created_at))
                .collect();
            matches.sort_by_key(|(_, created)| *created);
            let candidate = matches.into_iter().next().map(|(id, _)| id);
            let pending_after: Vec<String> = {
                let pending = state
                    .pending_join_stubs
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                pending.iter().cloned().collect()
            };
            let mut before_sorted = pending_before.clone();
            before_sorted.sort();
            let mut after_sorted = pending_after.clone();
            after_sorted.sort();
            if after_sorted == before_sorted {
                break candidate;
            }
            // Pending set changed during the read: retry.
        }
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

    // 3) #449: another owner device has already advertised the owner's Home.
    //    Minting a second one here is exactly the reported bug — N devices
    //    becoming N competing Homes. Yield instead: `GET /home` reports
    //    `elsewhere`, and adoption seats us in the canonical Home.
    //
    //    Absence of a register value means "nobody has advertised one yet",
    //    NOT "none exists", so an un-synced or first device still provisions
    //    optimistically — that is what keeps an offline install usable.
    //    A pointer naming a Home we hold and know to be RETIRED does not
    //    count (r3 P2): the stored record outlives the group it names, so
    //    yielding to it would leave this device permanently without a Home.
    if let Some(canonical) = effective_canonical_home(state).await {
        tracing::info!(
            canonical_group_id = %canonical,
            "owner's Home is advertised by another device; not provisioning a duplicate (#449)"
        );
        return;
    }

    // 4) Fresh provisioning through the full creation path.
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

/// 200 body for "the owner's Home lives on another device" (#449).
///
/// Deliberately NOT a 404: the caller asked where the owner's Home is, and
/// "on another device, not yet joined" answers that. A 404 here is what made
/// a second device look Home-less and silently provision a duplicate.
/// #449 (option (c)): the owner-driven exit from a non-canonical Home.
///
/// Adoption is deliberately NOT automatic — no evidence this device holds
/// distinguishes an owner's other DEVICE from an ADR-0039 API-key rider, so
/// the owner decides. Reporting `elsewhere`/`adoption_pending` without
/// naming the two commands that resolve it leaves the operator with a
/// diagnosis and no cure, which is what made the duplicate feel permanent.
fn home_seat_next_step(local_agent_hex: &str, owner_hex: &str) -> String {
    format!(
        "run `x0x home seat {local_agent_hex}` on the device that holds the canonical Home, \
         then `x0x group join --home --owner {owner_hex} <invite>` here"
    )
}

fn home_elsewhere_response(
    owner: &crate::identity::UserId,
    canonical: &str,
    local: Option<&str>,
    local_agent_hex: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    let owner_hex = hex::encode(owner.as_bytes());
    let next_step = home_seat_next_step(local_agent_hex, &owner_hex);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "state": "elsewhere",
            "owner_user_id": owner_hex,
            "canonical_group_id": canonical,
            "local_group_id": local,
            "detail": "the owner's Home lives on another device; this device is not a member yet",
            "next_step": next_step,
        })),
    )
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
    let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    // #449: "the Home is on another device" is a real answer, not a 404.
    // Reporting 404 there is what let a duplicate stay invisible.
    let (group_id, info, adopting_from) = match resolve_home(&state).await {
        HomeResolution::Local { group_id, info } => (group_id, *info, None),
        HomeResolution::AdoptionPending { local, canonical } => {
            match find_home(state.as_ref(), &owner).await {
                Some((_, info)) => (local, info, Some(canonical)),
                // Raced with a membership change: fall back to the honest
                // "not seated here" answer rather than serving stale state.
                None => return home_elsewhere_response(&owner, &canonical, None, &local_agent_hex),
            }
        }
        HomeResolution::Elsewhere { canonical } => {
            return home_elsewhere_response(&owner, &canonical, None, &local_agent_hex)
        }
        HomeResolution::Unknown => return not_found("no Home provisioned"),
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
    // #449 P4: leftover duplicate Homes, each with the reason it survived, so
    // "why is this still here" is answerable without reading the logs. Home
    // itself works — this is the owner's cleanup list, not an error state.
    let mut duplicates = Vec::new();
    for id in home_duplicates(&state, &group_id, &owner).await {
        let blockers = home_retire_blockers(&state, &id).await;
        // #449 P4: report evidence, never a safety verdict. `safe_to_retire`
        // was removed deliberately — no sound emptiness proof exists yet (the
        // proof is not held across a terminal withdrawal), so claiming safety
        // is exactly the thing this device cannot currently establish.
        duplicates.push(serde_json::json!({
            "group_id": id,
            "retirement": "manual_only",
            "evidence_against_deletion": blockers,
        }));
    }
    let primary_self_name = self_name_for(state.as_ref(), &home.primary_agent).await;
    let mut payload = serde_json::json!({
            "ok": true,
            // #469 (A3): the Home-join pin (`x0x group join --home
            // --owner <hex>`) needs the owner's user id visible where the
            // operator actually looks — `x0x home` prints this payload
            // verbatim. `find_home` only matches a group whose admission
            // axis is OwnerCertified(owner), so this IS the Home policy
            // admission owner id (additive, backwards-compatible field).
            "owner_user_id": hex::encode(owner.as_bytes()),
            // #449: which Home this device is actually serving. `local` is
            // the settled case; `adoption_pending` means this Home LOST the
            // election and stays usable only until we are seated in
            // `canonical_group_id`.
            "state": if adopting_from.is_some() { "adoption_pending" } else { "local" },
            "canonical_group_id": adopting_from,
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
            // Read-only inventory. Automatic retirement is not implemented;
            // see docs/design/449-p4-retirement-fence.md.
            "duplicates": duplicates,
            "warnings": {
                "no_roaming_agent": home_roaming_warning_for(&info).is_some(),
                "primary_agent_unverified": !primary_ok,
                "unretired_duplicate_home": !duplicates.is_empty(),
            },
    });
    // #449 (option (c)): only the LOSING device needs a cure, so `local`
    // keeps its exact pre-#449 shape — an added key there would be a wire
    // change every settled install pays for nothing.
    if adopting_from.is_some() {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "next_step".to_string(),
                serde_json::Value::String(home_seat_next_step(
                    &local_agent_hex,
                    &hex::encode(owner.as_bytes()),
                )),
            );
        }
    }
    (StatusCode::OK, Json(payload))
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

#[derive(Debug, Deserialize)]
pub(in crate::server) struct SeatHomeRequest {
    agent_id: String,
}

/// Test-only barrier fired by [`seat_home`] once it holds the canonical
/// gate and has selected its Home, immediately before it enters the invite
/// authority.
///
/// A regression for the #449 r3 P2 race has to observe that exact instant:
/// a sleep would prove only that the race is slow to lose, not that the
/// gate orders anything. `notify_one` stores a permit, so a test that waits
/// after the handler has already passed the point still wakes.
///
/// Test binaries run one process per test under nextest, so this static is
/// not shared between concurrent regressions.
#[cfg(test)]
pub(in crate::server::routes::home) fn seat_selected_canonical_hook() -> &'static tokio::sync::Notify
{
    static HOOK: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();
    HOOK.get_or_init(tokio::sync::Notify::new)
}

/// #449 option (c): 409 body for a seat request this device cannot serve.
/// `reason` is a TYPED token (`elsewhere` / `adoption_pending` /
/// `unknown`), not prose — the CLI and the GUI branch on it.
fn seat_conflict(reason: &str, canonical: Option<&str>, detail: &str) -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "ok": false,
            "error": detail,
            "reason": reason,
            "canonical_group_id": canonical,
        })),
    )
        .into_response()
}

fn seat_bad_request(detail: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "ok": false, "error": detail })),
    )
        .into_response()
}

/// POST /home/seat — mint an ADDRESSED Home invite for one of the owner's
/// other devices (#449, decision option (c): adoption is OWNER-DRIVEN).
///
/// Why a command and not an automatic rule: nothing this device holds
/// separates the owner's other DEVICE from an ADR-0039 API-key rider
/// sub-agent. `CertMode` does not survive owner-journal sync (it is
/// re-materialised as `Acp`), the certificate carries no hosting mode, and
/// the Tier-1 device set is keyed by machine with no machine-to-agent
/// binding. Any automatic rule would be guessing, and guessing wrong seats
/// a rider in the owner's private space. The owner naming the agent is the
/// only evidence that exists today.
///
/// Deliberately NOT done here: no auto-delivery of the invite over any
/// transport, and no new `SyncKind`/`SyncValue`/protocol version. The
/// invite string travels the way every other Home invite already does — by
/// hand, consumed with the #469 A3 owner pin.
///
/// Refuses unless this device is seated in the CANONICAL Home: a device
/// that lost the election would otherwise mint seats into the duplicate it
/// is itself supposed to leave, multiplying the very fork #449 closes.
pub(in crate::server) async fn seat_home(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(req): Json<SeatHomeRequest>,
) -> Response {
    // Same authority as every other Home mutation (#446): a seat is device
    // admission to the owner's private space, so a session token — which a
    // harness holds — must not be able to grant one.
    if !actor.is_durable_owner() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "seating a device in the Home requires the durable API token (not a session token)"
            })),
        )
            .into_response();
    }
    if state.agent.identity().user_keypair().is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "ok": false,
                "error": "no Home provisioned (un-owned install)"
            })),
        )
            .into_response();
    }

    let joiner = req.agent_id;
    if joiner.len() != 64
        || !joiner
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return seat_bad_request("agent_id must be 64 lowercase hex characters");
    }
    // Seating ourselves is a no-op that would burn a live-invite slot and
    // hand the operator a token no one can consume.
    if joiner == hex::encode(state.agent.agent_id().as_bytes()) {
        return seat_bad_request(
            "agent_id is this daemon's own agent, which already holds the Home seat; \
             pass the agent id of the device you want to seat",
        );
    }

    // #449 r3 P2: hold the canonical-Home admission gate ACROSS the
    // resolution and the mint. Resolving canonical A and then awaiting the
    // invite authority's per-group membership lock leaves a window in which
    // an owner-sync commit can make B canonical; the mint reloads A, sees a
    // live non-withdrawn group, and durably records an addressed invite into
    // the LOSING Home. A recheck before the await cannot close it, because
    // the mint transaction awaits too. Under the gate this call is
    // linearized: a pointer accepted before it makes us refuse below, and a
    // pointer accepted after it waits for our invite to become durable.
    //
    // Lock order (see `OwnerSyncStore::canonical_home_gate`): this gate →
    // per-group membership lock → named_groups/persistence. Nothing on the
    // owner-sync writer side takes a membership lock, so there is no cycle.
    let _canonical_gate = match state.owner_sync.as_ref() {
        Some(sync) => Some(sync.store().canonical_home_gate_read().await),
        // No owner sync means no canonical register exists to race with.
        None => None,
    };

    let (group_id, info) = match resolve_home(&state).await {
        HomeResolution::Local { group_id, info } => (group_id, info),
        HomeResolution::AdoptionPending { canonical, .. } => {
            return seat_conflict(
                "adoption_pending",
                Some(&canonical),
                "this device holds a Home that LOST the election, so it cannot seat other \
                 devices; run this on the device that holds the canonical Home",
            )
        }
        HomeResolution::Elsewhere { canonical } => {
            return seat_conflict(
                "elsewhere",
                Some(&canonical),
                "the owner's Home lives on another device; run this there",
            )
        }
        HomeResolution::Unknown => {
            return seat_conflict("unknown", None, "no Home provisioned on this device")
        }
    };
    // The join pin the operator will type MUST be the owner axis of the group
    // the invite actually belongs to. Deriving it from the local user key
    // would echo what this device believes rather than what the group
    // asserts, and deriving it from the invite would be reading unverified
    // content back to the verifier — both make the #469 A3 pin circular.
    let Some(owner_hex) = info
        .policy
        .admission
        .owner_certified_user_id()
        .map(|owner| hex::encode(owner.as_bytes()))
    else {
        return seat_conflict(
            "unknown",
            Some(&group_id),
            "the resolved Home carries no OwnerCertified admission axis, so no owner pin \
             exists to hand the joining device",
        );
    };

    #[cfg(test)]
    seat_selected_canonical_hook().notify_one();

    // Mint through the EXISTING invite authority (`POST /groups/:id/invite`)
    // rather than a parallel path: the live-cap, the owner-axis durable
    // fence, the signed v4 assembly, the recorded secret and the durable
    // persist are one transaction there, and a second mint surface would be
    // a second place for that transaction to drift.
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    let body =
        axum::body::Bytes::from(serde_json::json!({ "intended_joiner": joiner }).to_string());
    let minted = super::named_groups::create_group_invite(
        State(Arc::clone(&state)),
        axum::extract::Extension(actor),
        Path(group_id.clone()),
        headers,
        body,
    )
    .await
    .into_response();
    if !minted.status().is_success() {
        return minted;
    }
    let minted_body = match axum::body::to_bytes(minted.into_body(), 1 << 20).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!("could not read the minted invite: {e}")
                })),
            )
                .into_response()
        }
    };
    let invite = serde_json::from_slice::<serde_json::Value>(&minted_body)
        .ok()
        .and_then(|body| {
            body["invite_link"]
                .as_str()
                .map(std::string::ToString::to_string)
        });
    let Some(invite) = invite else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "ok": false,
                "error": "the invite authority returned no invite link"
            })),
        )
            .into_response();
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": group_id,
            "invite": invite,
            "intended_joiner": joiner,
            // The owner axis of THIS group, read from its policy — the value
            // the joining device must pin.
            "owner_user_id": owner_hex,
            // #469 A3: the owner pin is not optional advice — an unpinned
            // Home join can be answered by any group, so the hint carries it.
            "join_hint": format!("x0x group join {invite} --home --owner {owner_hex}"),
            // A minted invite is an OFFER, not a seat. The named device holds
            // no membership until it joins and that join is accepted, so a
            // 200 here must not read as "the device is in". `seated` is the
            // machine-readable half of that: a caller that branches on it
            // cannot mistake a mint for a completed adoption.
            "seated": false,
            "note": "an invite was minted; the device is NOT seated until it redeems the invite via the join path",
        })),
    )
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

    /// Publish `group_id` as the owner's canonical Home on the Tier-1
    /// register, as a peer device would (#449).
    /// WHY (#449, ADR-0060 validation gap): the retired-pointer lifecycle
    /// across a DISK RELOAD. The `AppState` is dropped and rebuilt from the
    /// same data dir, so the named-group roster and the owner-sync record
    /// store are both re-read from disk.
    ///
    /// SCOPE LIMIT — this is a disk-reload fixture, NOT a process restart.
    /// It does not exit, reap or respawn a process; everything happens in one
    /// test process. It therefore exercises the persistence and reload path,
    /// and says nothing about process teardown, signal handling or
    /// supervision. Concretely: dropping `AppState` does not synchronously
    /// release every resource the way process exit would — an enabled history
    /// store still holds its sqlite file across the drop — which is why this
    /// fixture deliberately runs WITHOUT history. It covers the owner-sync
    /// pointer lifecycle only.
    ///
    /// The hazard it does cover: tombstone retention never clears owner-sync
    /// state, so a persisted pointer to a Home retired before shutdown could
    /// come back on reload and suppress every replacement permanently — the
    /// worst form of this bug, an owner left with no Home and no way to
    /// obtain one.
    #[tokio::test]
    async fn a_retired_pointer_reloaded_from_disk_does_not_suppress_replacement(
    ) -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let retired_id = {
            let state = owned_state(dir.path(), [0x6D; 32]).await?;
            provision_home(&state).await;
            let owner = owner_of(&state);
            let (home_id, _) = find_home(&state, &owner).await.expect("Home provisioned");

            // Advertise it, then retire it through the real terminal path.
            advertise_canonical_home(&state, &home_id).await;
            // Owner-driven deletion through the audited terminal path. This is
            // the operator action that is still available today; it is NOT the
            // automated retirement, which is deliberately not implemented.
            let response = super::super::named_groups::leave_group(
                State(Arc::clone(&state)),
                axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                    durable: true,
                }),
                Path(home_id.clone()),
            )
            .await
            .into_response();
            anyhow::ensure!(
                response.status().is_success(),
                "leave_group returned {}",
                response.status()
            );
            assert!(
                find_home(&state, &owner).await.is_none(),
                "precondition: the retired Home no longer resolves"
            );
            drop(state);
            home_id
        };

        // Disk reload (NOT a process restart): same data dir, state rebuilt.
        let state = owned_state(dir.path(), [0x6D; 32]).await?;
        let owner = owner_of(&state);
        assert_eq!(
            state
                .owner_sync
                .as_ref()
                .expect("sync")
                .canonical_home()
                .await
                .map(|home| home.group_id)
                .as_deref(),
            Some(retired_id.as_str()),
            "precondition: the stored pointer to the retired Home survived the reload"
        );
        assert!(
            effective_canonical_home(&state).await.is_none(),
            "a reloaded pointer to a locally-proven retired Home must not govern"
        );

        provision_home(&state).await;

        let (replacement, info) = find_home(&state, &owner)
            .await
            .expect("a usable replacement Home must be provisioned after the reload");
        assert_ne!(replacement, retired_id, "the replacement is a NEW Home");
        assert!(!info.withdrawn);
        Ok(())
    }

    /// Owned test state with a REAL, isolated durable-history store.
    ///
    /// Review P2: `owned_state` never calls `AgentBuilder::with_history`, and
    /// history is off by default in the library — so `agent.history()` is
    /// `None` there and every history-dependent assertion built on it is
    /// vacuous. The retirement gate is *about* durable rows, so its tests must
    /// run against a store that actually exists. The db lives under the test's
    /// own tempdir; nothing is shared and no network is involved.
    async fn owned_state_with_history(
        data_dir: &std::path::Path,
        owner_seed: [u8; 32],
    ) -> anyhow::Result<Arc<AppState>> {
        let user = crate::identity::UserKeypair::from_seed(&owner_seed)?;
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(data_dir.join("machine.key"))
                .with_agent_key_path(data_dir.join("agent.key"))
                .with_agent_cert_path(data_dir.join("agent.cert"))
                .with_user_key(user)
                .with_contact_store_path(data_dir.join("contacts.json"))
                .with_history(crate::history::HistoryConfig {
                    enabled: true,
                    db_path: Some(data_dir.join("history.db")),
                    ..Default::default()
                })
                .build()
                .await?,
        );
        anyhow::ensure!(
            agent.history().is_some(),
            "test fixture must provide a live history store, or the retirement \
             gate's history assertions are vacuous"
        );
        super::super::named_groups::tests::secure_endpoint_test_state_at(data_dir, agent).await
    }

    /// Create a REAL second Home-shaped group and stamp it, mimicking the
    /// duplicate a pre-#449 device would have provisioned.
    async fn provision_duplicate_home(state: &Arc<AppState>) -> anyhow::Result<String> {
        let owner = owner_of(state);
        let response = super::super::named_groups::create_named_group(
            State(Arc::clone(state)),
            Json(super::super::named_groups::CreateGroupRequest {
                name: "Home".to_string(),
                description: "duplicate".to_string(),
                display_name: None,
                preset: None,
                policy: Some(home_policy(&owner)),
            }),
        )
        .await
        .into_response();
        anyhow::ensure!(response.status().is_success(), "create duplicate Home");
        let body = axum::body::to_bytes(response.into_body(), 1 << 20).await?;
        let id = serde_json::from_slice::<serde_json::Value>(&body)?["group_id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("no group_id"))?;
        stamp_and_seal_home(state, &id).await;
        Ok(id)
    }

    /// WHY (review P2): an unreadable task-list manifest is not evidence of
    /// absence. Its loader maps read/parse failure to an EMPTY manifest —
    /// correct for REST and rehydration, which fail closed elsewhere — but for
    /// a deletion decision that turns "could not read the evidence" into
    /// "there is none". A corrupt manifest must therefore be reported as
    /// evidence against deletion, not silently as a clean bill of health.
    #[tokio::test]
    async fn an_unreadable_task_list_manifest_is_evidence_against_deletion() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state_with_history(dir.path(), [0x6F; 32]).await?;
        provision_home(&state).await;
        let duplicate = provision_duplicate_home(&state).await?;
        tokio::fs::write(&state.crdt_subscriptions_path, b"{ not json").await?;

        let blockers = home_retire_blockers(&state, &duplicate).await;
        assert!(
            blockers
                .iter()
                .any(|b| b.contains("task-list manifest unreadable")),
            "a corrupt manifest must block, got {blockers:?}"
        );
        Ok(())
    }

    /// WHY (review P2): same class for rider grants. A missing, unreadable or
    /// corrupt `rider-tokens.json` maps to an empty grant set — safe for token
    /// AUTHENTICATION, which fails closed by granting nothing, but not proof
    /// that the durable grant set is empty. Repairing a transient read problem
    /// after deletion would leave a grant pointing at an orphaned group.
    #[tokio::test]
    async fn an_unreadable_rider_store_is_evidence_against_deletion() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state_with_history(dir.path(), [0x70; 32]).await?;
        provision_home(&state).await;
        let duplicate = provision_duplicate_home(&state).await?;
        tokio::fs::write(
            state
                .data_dir
                .join(crate::server::rider_auth::RIDER_TOKENS_FILE),
            b"{ not json",
        )
        .await?;

        let blockers = home_retire_blockers(&state, &duplicate).await;
        assert!(
            blockers
                .iter()
                .any(|b| b.contains("rider-token store unreadable")),
            "a corrupt rider store must block, got {blockers:?}"
        );
        Ok(())
    }

    /// WHY (review r3 P2): WRONG-SCHEMA evidence is not absent evidence.
    ///
    /// The earlier probe parsed a generic `serde_json::Value`, so `null` and
    /// `{"entries":"corrupt"}` — both valid JSON that the typed loader
    /// rejects and flattens to empty — sailed through and the inventory
    /// dropped its unavailable-evidence warning in exactly the cases the
    /// warning exists for. These are the schema-valid-JSON controls that a
    /// syntax-only test cannot catch.
    #[tokio::test]
    async fn wrong_schema_evidence_files_are_reported_unavailable() -> anyhow::Result<()> {
        for body in [&b"null"[..], &br#"{"entries":"corrupt"}"#[..]] {
            let dir = tempfile::tempdir()?;
            let state = owned_state_with_history(dir.path(), [0x71; 32]).await?;
            provision_home(&state).await;
            let duplicate = provision_duplicate_home(&state).await?;
            tokio::fs::write(&state.crdt_subscriptions_path, body).await?;

            let blockers = home_retire_blockers(&state, &duplicate).await;
            assert!(
                blockers
                    .iter()
                    .any(|b| b.contains("task-list manifest unreadable")),
                "valid JSON of the wrong schema must be reported unavailable, got {blockers:?}"
            );
        }

        for body in [&b"null"[..], &br#"{"next_id":1,"tokens":[]}"#[..]] {
            let dir = tempfile::tempdir()?;
            let state = owned_state_with_history(dir.path(), [0x72; 32]).await?;
            provision_home(&state).await;
            let duplicate = provision_duplicate_home(&state).await?;
            tokio::fs::write(
                state
                    .data_dir
                    .join(crate::server::rider_auth::RIDER_TOKENS_FILE),
                body,
            )
            .await?;

            let blockers = home_retire_blockers(&state, &duplicate).await;
            assert!(
                blockers
                    .iter()
                    .any(|b| b.contains("rider-token store unreadable")),
                "valid JSON of the wrong schema must be reported unavailable, got {blockers:?}"
            );
        }
        Ok(())
    }

    /// WHY (review r3 P2): a schema-VALID durable manifest must be observed
    /// from disk, not from the in-memory map — the positive control for the
    /// probe, and the case the startup-ordering P1 previously missed.
    #[tokio::test]
    async fn a_durable_task_list_entry_is_observed_from_disk() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state_with_history(dir.path(), [0x73; 32]).await?;
        provision_home(&state).await;
        let duplicate = provision_duplicate_home(&state).await?;
        let stable = state
            .named_groups
            .read()
            .await
            .get(&duplicate)
            .expect("duplicate")
            .stable_group_id()
            .to_string();
        // Written straight to disk; the in-memory manifest is never touched,
        // which is exactly the state startup retirement used to act on.
        tokio::fs::write(
            &state.crdt_subscriptions_path,
            serde_json::to_vec(&serde_json::json!({
                "entries": [{
                    "kind": "task_list",
                    "id": format!("x0x.group.{stable}.symphony.todo"),
                    "name": "todo",
                    "topic": "t",
                    "role": "created",
                }]
            }))?,
        )
        .await?;

        let blockers = home_retire_blockers(&state, &duplicate).await;
        assert!(
            blockers
                .iter()
                .any(|b| b.contains("group-scoped task lists")),
            "a durable task-list entry must be observed from disk, got {blockers:?}"
        );
        Ok(())
    }

    /// WHY (review P2): an ABSENT history store must block retirement.
    ///
    /// History is off by default in the library, so `agent.history()` is
    /// `None` on an install that never enabled it — but rows for this group
    /// may already sit in `<data_dir>/history.db`, and an operator can
    /// re-enable the store at any time. Treating a missing handle as "no
    /// history" would let this path delete a Home whose messages and
    /// delegations are in a database we simply did not open. "Cannot prove
    /// empty" must behave like "not empty".
    ///
    /// Uses `owned_state` deliberately — the fixture WITHOUT history — which
    /// is the exact configuration that made the earlier blocker test vacuous.
    #[tokio::test]
    async fn an_unavailable_history_store_blocks_retirement() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x6E; 32]).await?;
        assert!(
            state.agent.history().is_none(),
            "precondition: this fixture has NO history store"
        );
        provision_home(&state).await;
        let owner = owner_of(&state);
        let (canonical, _) = find_home(&state, &owner).await.expect("canonical Home");
        let duplicate = provision_duplicate_home(&state).await?;
        advertise_canonical_home(&state, &canonical).await;

        let blockers = home_retire_blockers(&state, &duplicate).await;
        assert!(
            blockers
                .iter()
                .any(|b| b.contains("history store unavailable")),
            "an absent history store must block retirement, got {blockers:?}"
        );

        Ok(())
    }

    /// WHY (#449 P4): withdrawal cleans only crypto material — durable
    /// history, and the group delegations that live ONLY in history, are
    /// orphaned. A duplicate carrying history is therefore never retired
    /// automatically; it is surfaced for the owner instead.
    #[tokio::test]
    async fn duplicate_with_history_is_kept_and_reported() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state_with_history(dir.path(), [0x6C; 32]).await?;
        provision_home(&state).await;
        let owner = owner_of(&state);
        let (canonical, _) = find_home(&state, &owner).await.expect("canonical Home");
        let duplicate = provision_duplicate_home(&state).await?;
        advertise_canonical_home(&state, &canonical).await;

        let stable = state
            .named_groups
            .read()
            .await
            .get(&duplicate)
            .expect("duplicate")
            .stable_group_id()
            .to_string();
        let history = state
            .agent
            .history()
            .expect("fixture guarantees a live history store");
        // Insert through the store directly so the row is durable BEFORE the
        // probe runs — the async writer would race the assertion.
        let payload = b"a message the owner would lose".to_vec();
        let record = crate::history::HistoryRecord {
            msg_id: crate::history::HistoryRecord::compute_msg_id(None, &payload),
            scope: crate::history::Scope::Group(stable),
            author_agent: None,
            author_machine: None,
            author_pubkey: None,
            sent_at_ms: 1,
            seen_at_ms: 1,
            direction: crate::history::Direction::Inbound,
            content_type: "text/plain".to_string(),
            payload,
            signed_artifact: None,
            signature: None,
            sig_context: None,
            provenance: crate::history::Provenance::LocalAppDecrypt,
            replace_key: None,
            thread_root: None,
            thread_parent: None,
            ingress_sender_agent: None,
            logical_request_id: None,
        };
        history.store().insert(&record)?;

        let blockers = home_retire_blockers(&state, &duplicate).await;
        assert!(
            blockers.iter().any(|b| b.contains("history")),
            "history must block automatic retirement, got {blockers:?}"
        );

        Ok(())
    }

    async fn advertise_canonical_home(state: &Arc<AppState>, group_id: &str) {
        let sync = state.owner_sync.as_ref().expect("owned state wires sync");
        let owner_kp = state
            .agent
            .identity()
            .user_keypair()
            .expect("owned state has a user key");
        sync.store()
            .mint(
                crate::owner_sync::SyncKind::HomePointer,
                crate::owner_sync::HOME_POINTER_KEY,
                &crate::owner_sync::SyncValue::HomePointer {
                    group_id: group_id.to_string(),
                    policy: home_policy(&owner_kp.user_id()),
                    roster: vec![],
                    primary_agent: "aa".repeat(32),
                    provisioned_at_ms: 1,
                },
                owner_kp,
                state.agent.machine_id(),
            )
            .await
            .expect("mint canonical Home pointer");
    }

    /// WHY (#449): THE bug. A second owner device used to auto-provision its
    /// OWN Home because dedup was per-machine, leaving an owner with N
    /// devices holding N competing Homes and no error anywhere.
    ///
    /// Once a peer has advertised the owner's Home on the Tier-1 register,
    /// this device must yield rather than mint a duplicate.
    #[tokio::test]
    async fn second_device_does_not_provision_a_duplicate_home() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x5A; 32]).await?;
        let owner = owner_of(&state);
        let canonical = "dd".repeat(16);
        advertise_canonical_home(&state, &canonical).await;

        provision_home(&state).await;

        assert!(
            find_home(&state, &owner).await.is_none(),
            "a second device must not provision its own Home once the owner's is advertised"
        );
        let home_shaped = state
            .named_groups
            .read()
            .await
            .values()
            .filter(|info| is_home_policy(&info.policy, &owner))
            .count();
        assert_eq!(home_shaped, 0, "no duplicate Home group may be created");
        Ok(())
    }

    /// WHY (#449): "the Home is on another device" must be a real answer.
    /// Reporting 404 is what let the duplicate stay invisible — the device
    /// looked Home-less, so nothing ever revealed the fork.
    #[tokio::test]
    async fn get_home_reports_a_home_that_lives_elsewhere() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x5B; 32]).await?;
        let canonical = "ee".repeat(16);
        advertise_canonical_home(&state, &canonical).await;

        let response = get_home(State(Arc::clone(&state))).await.into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "elsewhere is 200, not 404: {body:?}"
        );
        assert_eq!(body["state"], "elsewhere");
        assert_eq!(body["canonical_group_id"], canonical);
        Ok(())
    }

    /// WHY (r3 P2): the stored-pointer lifecycle — advertise, then withdraw,
    /// then re-provision. This is the case the earlier test could not reach,
    /// because it only inserted an already-withdrawn group into an EMPTY
    /// store, so no stored pointer ever governed.
    ///
    /// Tombstone retention never clears owner-sync state, so the stored
    /// `("home")` record outlives the Home it names. Filtering the publisher
    /// stops future advertisements but leaves the old record governing: the
    /// device yields to a dead pointer, provisions no replacement, and
    /// `GET /home` reports `elsewhere` for a group that no longer exists.
    ///
    /// SCOPE LIMIT — this is an IN-PROCESS re-provision. It sets `withdrawn`
    /// and calls `provision_home` directly; it does not restart a process or
    /// reload the record store from disk. The claim it supports is "a stored
    /// retired pointer stops governing a re-provision", NOT "this survives a
    /// real restart" — the on-disk reload path holds by construction
    /// (the record store is read back through the same `canonical_home`
    /// accessor) but is not exercised here.
    #[tokio::test]
    async fn a_retired_advertised_home_does_not_suppress_its_replacement() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x5D; 32]).await?;
        let owner = owner_of(&state);

        // 1. Advertise our real Home, exactly as a live device would.
        provision_home(&state).await;
        let (advertised, _) = find_home(&state, &owner).await.expect("Home provisioned");
        advertise_canonical_home(&state, &advertised).await;

        // 2. Retire it. The stored pointer still names it.
        state
            .named_groups
            .write()
            .await
            .get_mut(&advertised)
            .expect("advertised Home")
            .withdrawn = true;
        assert_eq!(
            state
                .owner_sync
                .as_ref()
                .expect("sync")
                .canonical_home()
                .await
                .map(|home| home.group_id)
                .as_deref(),
            Some(advertised.as_str()),
            "precondition: the retired Home is still the stored canonical pointer"
        );

        // 3. Re-provision in-process (NOT a process/disk restart — see above).
        assert!(
            effective_canonical_home(&state).await.is_none(),
            "a pointer to a Home we hold and know to be retired must stop governing"
        );
        provision_home(&state).await;

        let (replacement, info) = find_home(&state, &owner)
            .await
            .expect("a usable replacement Home must be provisioned");
        assert_ne!(replacement, advertised, "the replacement is a NEW Home");
        assert!(!info.withdrawn);
        Ok(())
    }

    /// WHY (r3 P2): proof of retirement is LOCAL, and absence of knowledge is
    /// not proof. A canonical Home living on a device we cannot currently
    /// reach is unknown, not retired — clearing it would let any partitioned
    /// device mint over the owner's real Home and refork the space this whole
    /// issue exists to unify.
    #[tokio::test]
    async fn an_unreachable_remote_home_is_never_treated_as_retired() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x5E; 32]).await?;
        let remote = "ac".repeat(16);
        advertise_canonical_home(&state, &remote).await;

        assert_eq!(
            effective_canonical_home(&state).await.as_deref(),
            Some(remote.as_str()),
            "a Home we simply cannot see must keep governing — unknown is not retired"
        );

        provision_home(&state).await;
        assert!(
            find_home(&state, &owner_of(&state)).await.is_none(),
            "we must still yield to an unreachable canonical Home, not fork a new one"
        );
        Ok(())
    }

    /// WHY (#449 D5): withdrawal keeps `members_v2` and `home` populated, so
    /// without an explicit filter a RETIRED Home still resolves here — which
    /// would make `GET /home` serve a tombstone and `provision_home` return
    /// early forever, wedging Home permanently.
    #[tokio::test]
    async fn find_home_ignores_a_withdrawn_home() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x5C; 32]).await?;
        let owner = owner_of(&state);
        let id = "ab".repeat(16);
        let mut info = crate::groups::GroupInfo::with_policy(
            "Home".to_string(),
            String::new(),
            state.agent.agent_id(),
            id.clone(),
            home_policy(&owner),
        );
        info.home = Some(crate::groups::HomeMetadata {
            primary_agent: hex::encode(state.agent.agent_id().as_bytes()),
            placements: std::collections::BTreeMap::new(),
            provisioned_at_ms: 1,
        });
        assert!(
            info.has_active_member(&hex::encode(state.agent.agent_id().as_bytes())),
            "precondition: the creator is seated, so only `withdrawn` can exclude it"
        );
        info.withdrawn = true;
        state.named_groups.write().await.insert(id, info);

        assert!(
            find_home(&state, &owner).await.is_none(),
            "a withdrawn Home must never resolve as this device's Home"
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

    fn durable_owner() -> crate::server::rider_auth::ActorContext {
        crate::server::rider_auth::ActorContext::Owner { durable: true }
    }

    /// Every invite secret recorded across every group this device holds.
    /// A refusal that still minted would show up here even if the refusal
    /// path returned the right status.
    async fn issued_invite_count(state: &Arc<AppState>) -> usize {
        state
            .named_groups
            .read()
            .await
            .values()
            .map(|info| info.issued_invites.len())
            .sum()
    }

    async fn seat(
        state: &Arc<AppState>,
        agent_id: &str,
    ) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let response = seat_home(
            State(Arc::clone(state)),
            axum::extract::Extension(durable_owner()),
            Json(SeatHomeRequest {
                agent_id: agent_id.to_string(),
            }),
        )
        .await;
        response_json(response).await
    }

    /// WHY (#449, option (c)): adoption is owner-driven, so the ONE thing
    /// the seat command must produce is an invite that only the named
    /// device can consume. An unaddressed invite would be first-joiner-wins
    /// — the owner would be handing a Home seat to whoever redeems the
    /// string first, which is the failure #469 A4 addressing exists to
    /// prevent. This asserts the DECODED, signature-verified invite rather
    /// than the echoed response field, so dropping the addressing anywhere
    /// between the handler and the mint transaction fails the test.
    ///
    /// The no-op half of the contract — that a mint seats nobody and
    /// deletes nothing — is pinned separately by
    /// `home_seat_mint_changes_no_membership_or_groups`.
    #[tokio::test]
    async fn home_seat_mints_addressed_invite_for_named_device() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x49; 32]).await?;
        provision_home(&state).await;
        let owner = owner_of(&state);
        let (home_id, _) = find_home(&state, &owner).await.expect("Home provisioned");

        let device = "7c".repeat(32);
        let (status, body) = seat(&state, &device).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true);
        assert_eq!(body["group_id"], home_id);
        assert_eq!(body["intended_joiner"], device);
        // The pin must be the group's OWN admission axis, not this device's
        // idea of who the owner is.
        let owner_hex = hex::encode(owner.as_bytes());
        assert_eq!(
            body["owner_user_id"], owner_hex,
            "the owner pin must be a first-class field, not only prose inside join_hint"
        );
        let hint = body["join_hint"].as_str().expect("join hint");
        // The machine-readable and human-readable halves of "this is an
        // offer, not an adoption" must BOTH be present.
        assert_eq!(
            body["seated"], false,
            "a mint must report seated=false: {body}"
        );
        assert!(
            body["note"]
                .as_str()
                .is_some_and(|note| note.contains("NOT seated")),
            "the response must not read as a completed seat: {body}"
        );

        // Decode and CRYPTOGRAPHICALLY verify the returned invite: the
        // addressing is only meaningful if the signatures that bind it hold.
        let invite = body["invite"].as_str().expect("invite link");
        assert_eq!(
            hint,
            format!("x0x group join {invite} --home --owner {owner_hex}"),
            "the hint must be the real CLI argument order with the owner pin"
        );
        let signed = crate::groups::invite::SignedInvite::from_link(invite)
            .map_err(|e| anyhow::anyhow!("invite does not decode: {e}"))?;
        signed
            .verify_v4_signatures()
            .map_err(|e| anyhow::anyhow!("invite signatures do not verify: {e:?}"))?;
        signed
            .verify_v4_owner_countersignature()
            .map_err(|e| anyhow::anyhow!("owner countersignature does not verify: {e:?}"))?;
        assert_eq!(
            signed.intended_joiner.as_deref(),
            Some(device.as_str()),
            "the SIGNED invite must address the named device"
        );
        assert_eq!(signed.group_id, home_id);
        assert_eq!(
            signed.inviter,
            hex::encode(state.agent.agent_id().as_bytes()),
            "this daemon must be the recorded inviter"
        );
        assert!(
            signed.base_state_hash.is_some(),
            "an authority-minted v4 invite carries the base state snapshot"
        );
        assert_eq!(
            signed
                .policy
                .as_ref()
                .and_then(|p| p.admission.owner_certified_user_id())
                .map(|o| hex::encode(o.as_bytes())),
            Some(owner_hex),
            "the invite's own policy must carry the same owner axis as the pin"
        );

        let groups = state.named_groups.read().await;
        let info = groups.get(&home_id).expect("home still held");
        let addressed: Vec<&Option<String>> = info
            .issued_invites
            .values()
            .map(|record| &record.intended_joiner)
            .collect();
        assert_eq!(
            addressed,
            vec![&Some(device.clone())],
            "the authority must record exactly one invite, addressed to the named device"
        );
        Ok(())
    }

    /// WHY (#449, and Root checklist item 6): minting is an OFFER. The named
    /// device holds no membership until it redeems the invite and that join
    /// is accepted, so a mint that quietly added a roster entry would report
    /// an adoption that never happened and let a device that never proved
    /// possession of its key read the Home.
    ///
    /// The other half matters more: retirement of a leftover duplicate is a
    /// separate MANUAL act (`docs/design/449-p4-retirement-fence.md`), because
    /// no sound emptiness proof exists yet. A seat command that deleted or
    /// withdrew the duplicate as a side effect would destroy data the owner
    /// has not migrated. This snapshots the whole group map, the canonical
    /// Home's roster, and every withdrawn flag, so ANY structural side effect
    /// of a mint fails the test rather than only the ones anticipated here.
    #[tokio::test]
    async fn home_seat_mint_changes_no_membership_or_groups() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x51; 32]).await?;
        provision_home(&state).await;
        let owner = owner_of(&state);
        let (home_id, _) = find_home(&state, &owner).await.expect("Home provisioned");
        // A leftover duplicate must survive the mint untouched.
        let duplicate = provision_duplicate_home(&state).await?;
        advertise_canonical_home(&state, &home_id).await;

        let snapshot = |state: Arc<AppState>, home_id: String, duplicate: String| async move {
            let groups = state.named_groups.read().await;
            (
                groups
                    .iter()
                    .map(|(id, info)| (id.clone(), info.withdrawn))
                    .collect::<std::collections::BTreeMap<_, _>>(),
                groups.get(&home_id).cloned(),
                groups.get(&duplicate).cloned(),
            )
        };
        let before = snapshot(Arc::clone(&state), home_id.clone(), duplicate.clone()).await;

        let device = "7d".repeat(32);
        let (status, body) = seat(&state, &device).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["seated"], false);

        let after = snapshot(Arc::clone(&state), home_id.clone(), duplicate.clone()).await;
        assert_eq!(
            after.0, before.0,
            "minting must neither create, delete nor withdraw any group"
        );
        let (home_before, home_after) = (
            before.1.as_ref().expect("home before"),
            after.1.as_ref().expect("home after"),
        );
        assert_eq!(
            home_after.members_v2, home_before.members_v2,
            "minting must not add the named device to the roster"
        );
        assert_eq!(
            home_after.membership_revision, home_before.membership_revision,
            "minting must not advance the membership revision"
        );
        assert!(
            !home_after.members.contains(&device),
            "the named device must not appear as a member before it joins"
        );
        assert_eq!(
            after.2, before.2,
            "the leftover duplicate Home must be byte-identical after a seat mint"
        );
        Ok(())
    }

    /// WHY (#446 fence at the ROUTE layer, applied to #449): the durable
    /// check must fire BEFORE the body extractor, so a session or rider
    /// bearer gets the typed refusal whatever it posts — a malformed body
    /// must not turn a 403 into a 400 that leaks which bodies are accepted.
    /// Driven through the real `auth_middleware` rather than a handler call,
    /// because the handler gate alone would leave the pre-extractor path
    /// untested. A rider is denied here as the CALLER; ADR-0039 riders hold
    /// no owner authority regardless of what scopes they were granted.
    #[tokio::test]
    async fn home_seat_denies_session_and_rider_through_real_middleware() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x4F; 32]).await?;
        provision_home(&state).await;
        let before = issued_invite_count(&state).await;
        let app = axum::Router::new()
            .route("/home/seat", axum::routing::post(seat_home))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::server::auth::auth_middleware,
            ))
            .with_state(Arc::clone(&state));

        let call = |bearer: String, body: &'static str| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::post("/home/seat")
                        .header("authorization", format!("Bearer {bearer}"))
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .expect("body builds"),
                )
                .await
            }
        };

        let well_formed = serde_json::json!({ "agent_id": "7c".repeat(32) }).to_string();
        let well_formed: &'static str = Box::leak(well_formed.into_boxed_str());

        // An unknown bearer never reaches the durable question.
        let response = call("not-a-real-token".to_string(), well_formed).await?;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "an unknown bearer is 401"
        );

        let session = state.sessions.issue(std::time::Instant::now());
        for body in [well_formed, "{\"agent_id\":", "not json at all"] {
            let response = call(session.clone(), body).await?;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "a session bearer is 403 whatever the body is ({body})"
            );
        }

        // A rider — even one granted Home scopes — is not the owner.
        let rider = {
            let mut store = state.rider_tokens.lock().await;
            let (token, _record) = store
                .issue(
                    "ab".repeat(32),
                    vec!["home".to_string(), "groups".to_string()],
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
        for body in [well_formed, "{\"agent_id\":"] {
            let response = call(rider.clone(), body).await?;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "an explicitly Home-scoped rider still cannot mint a seat ({body})"
            );
        }

        assert_eq!(
            issued_invite_count(&state).await,
            before,
            "no refused caller may leave a minted invite behind"
        );
        Ok(())
    }

    /// WHY (ADR-0039, mode-agnostic Home eligibility): the seat command must
    /// NOT read `CertMode` on the TARGET. Mode does not survive owner-journal
    /// sync (it is re-materialised as `Acp`) and the certificate carries none,
    /// so a mode-based target rule would be unreliable AND would amend an
    /// Accepted ADR as a side effect of a duplicate-Home fix. When the durable
    /// owner explicitly names an agent their journal labels `Rider`, the mint
    /// proceeds. The refusal that matters is on the CALLER, pinned by
    /// `home_seat_denies_session_and_rider_through_real_middleware` and
    /// `home_seat_refuses_rider_caller`.
    #[tokio::test]
    async fn home_seat_does_not_filter_target_by_mode() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x50; 32]).await?;
        provision_home(&state).await;

        // Certify a sub-agent the owner's own journal labels `Rider`.
        let target = crate::identity::AgentKeypair::generate()?;
        let (public_key, _secret) = target.to_bytes();
        let response = super::super::owner::owner_agents_issue(
            State(Arc::clone(&state)),
            axum::extract::Extension(durable_owner()),
            Json(serde_json::from_value(serde_json::json!({
                "agent_public_key": hex::encode(public_key),
                "mode": "rider",
                "label": "a harness rider",
            }))?),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK, "{:?}", response.1 .0);
        let issued = response.1 .0;
        let rider_agent = issued["agent_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("issue response carries no agent_id: {issued}"))?
            .to_string();

        // Sanity: the roster really does label this target `Rider`, so the
        // test would notice if a mode filter were added.
        let roster = state.agent.owner_issued_certificates().await;
        assert!(
            roster.iter().any(|record| record.agent_id == rider_agent
                && record.mode == crate::profile::CertMode::Rider),
            "fixture must produce a Rider-labelled target: {roster:?}"
        );

        let (status, body) = seat(&state, &rider_agent).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "a durable owner naming a Rider-labelled agent must still mint: {body}"
        );
        assert_eq!(body["intended_joiner"], rider_agent);
        Ok(())
    }

    /// WHY (#446 fence, applied to #449): a Home seat is device admission
    /// to the owner's private space. A session token is what a harness
    /// holds, so if a session could seat a device, an ADR-0039 rider could
    /// let itself into the Home — the exact outcome owner-driven adoption
    /// exists to prevent. Refusal must also leave NO minted invite behind.
    #[tokio::test]
    async fn home_seat_refuses_session_owner() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x4A; 32]).await?;
        provision_home(&state).await;
        let before = issued_invite_count(&state).await;

        let response = seat_home(
            State(Arc::clone(&state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: false,
            }),
            Json(SeatHomeRequest {
                agent_id: "7c".repeat(32),
            }),
        )
        .await;
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(
            issued_invite_count(&state).await,
            before,
            "a refused seat must not mint an invite"
        );
        Ok(())
    }

    /// WHY (#449): the device that LOST the Home election is the one whose
    /// operator is most likely to type this command, and it is precisely
    /// the device that must not answer it. Minting there would seat a
    /// second device into the duplicate that is itself supposed to be
    /// retired — turning a two-way fork into a three-way one. The refusal
    /// carries the typed reason and the canonical id so the operator learns
    /// WHERE to run it, and mints nothing.
    #[tokio::test]
    async fn home_seat_refuses_when_adoption_is_pending() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x4B; 32]).await?;
        provision_home(&state).await;
        let canonical = "e1".repeat(16);
        advertise_canonical_home(&state, &canonical).await;
        let before = issued_invite_count(&state).await;

        let (status, body) = seat(&state, &"7c".repeat(32)).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "adoption_pending");
        assert_eq!(body["canonical_group_id"], canonical);
        assert_eq!(
            issued_invite_count(&state).await,
            before,
            "a device that lost the election must mint nothing"
        );
        Ok(())
    }

    /// WHY (#449): the agent id becomes the invite's `intended_joiner`,
    /// which the authority compares byte-for-byte against
    /// `MemberJoined.member_agent_id`. A malformed id would mint an invite
    /// no device can ever consume while still consuming a live-invite slot,
    /// so it has to be refused BEFORE the mint, not discovered at join time.
    #[tokio::test]
    async fn home_seat_rejects_malformed_agent_id() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x4C; 32]).await?;
        provision_home(&state).await;
        let before = issued_invite_count(&state).await;

        for bad in [
            String::new(),
            "7c".repeat(31),
            "7C".repeat(32),
            format!("{}zz", "7c".repeat(31)),
        ] {
            let (status, body) = seat(&state, &bad).await?;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "agent_id {bad:?} must be refused: {body}"
            );
        }
        assert_eq!(issued_invite_count(&state).await, before);
        Ok(())
    }

    /// WHY (#449): this daemon's own agent already holds the seat, so
    /// seating it is not a mutation — it is a live-invite slot spent on a
    /// token nobody can redeem (the addressed joiner is already a member).
    /// Answering `ok` there would tell the operator their duplicate was
    /// resolved when nothing happened.
    #[tokio::test]
    async fn home_seat_refuses_seating_the_local_agent() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x4D; 32]).await?;
        provision_home(&state).await;
        let before = issued_invite_count(&state).await;

        let local = hex::encode(state.agent.agent_id().as_bytes());
        let (status, body) = seat(&state, &local).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(issued_invite_count(&state).await, before);
        Ok(())
    }

    /// WHY (#449): `adoption_pending` is a diagnosis. Without the cure
    /// alongside it the operator knows their Home is a duplicate and has no
    /// way to act, which is what made the duplicate feel permanent. The
    /// settled `local` shape must stay byte-identical — every healthy
    /// install reads that response, and none of them needs the advice.
    #[tokio::test]
    async fn home_adoption_pending_reports_the_seat_command() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x4E; 32]).await?;
        provision_home(&state).await;

        let (status, settled) =
            response_json(get_home(State(Arc::clone(&state))).await.into_response()).await?;
        assert_eq!(status, StatusCode::OK, "{settled}");
        assert_eq!(settled["state"], "local");
        assert!(
            settled.get("next_step").is_none(),
            "a settled Home must not carry adoption advice: {settled}"
        );

        advertise_canonical_home(&state, &"e2".repeat(16)).await;
        let (status, pending) =
            response_json(get_home(State(Arc::clone(&state))).await.into_response()).await?;
        assert_eq!(status, StatusCode::OK, "{pending}");
        assert_eq!(pending["state"], "adoption_pending");
        let next_step = pending["next_step"].as_str().expect("next_step present");
        let local = hex::encode(state.agent.agent_id().as_bytes());
        let owner = hex::encode(owner_of(&state).as_bytes());
        assert!(
            next_step.contains(&format!("x0x home seat {local}")),
            "next_step must name THIS device's agent id: {next_step}"
        );
        assert!(
            next_step.contains(&format!("--owner {owner}")),
            "next_step must carry the owner pin: {next_step}"
        );
        Ok(())
    }

    /// WHY (ADR-0039 deny-by-default, Root checklist item 1): a rider is not
    /// a diminished owner, it is a different principal. `is_durable_owner`
    /// matches only `Owner { durable: true }`, so a rider must be refused
    /// even when its token was granted the Home group explicitly — the grant
    /// buys it reach into Home CONTENT, never the authority to admit new
    /// devices to the owner's private space. This drives the handler
    /// directly with a `Rider` actor, so it fails if the gate is ever
    /// loosened to "any non-session actor" while the middleware still
    /// happens to reject riders on its own.
    #[tokio::test]
    async fn home_seat_refuses_rider_caller() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x52; 32]).await?;
        provision_home(&state).await;
        let owner = owner_of(&state);
        let (home_id, _) = find_home(&state, &owner).await.expect("Home provisioned");
        let before = issued_invite_count(&state).await;

        // A rider granted this very Home, which is the strongest grant a
        // rider token can carry.
        let rider = crate::server::rider_auth::ActorContext::Rider {
            sub_agent_id: "ab".repeat(32),
            token_id: 1,
            token_hash: "cd".repeat(32),
            groups: vec![home_id.clone()],
        };
        assert!(
            rider.rider_allows_group(&home_id),
            "fixture must grant the rider this Home, or the test proves nothing"
        );

        let response = seat_home(
            State(Arc::clone(&state)),
            axum::extract::Extension(rider),
            Json(SeatHomeRequest {
                agent_id: "7c".repeat(32),
            }),
        )
        .await;
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a Home-granted rider still cannot mint a seat: {body}"
        );
        assert_eq!(
            issued_invite_count(&state).await,
            before,
            "a refused rider must not leave a minted invite behind"
        );
        Ok(())
    }

    /// WHY (Root checklist item 6): each refusal is asserted in isolation
    /// elsewhere, which cannot catch a leak that only appears once a caller
    /// retries. This walks the three non-durable refusal paths in sequence
    /// against ONE before/after count, so a mint that escaped on any attempt
    /// — or a partial mint rolled back on only the first — shows up here.
    /// The invariant is absolute: no refused seat request may consume a
    /// live-invite slot, because the slots are capped and burning them would
    /// let a rejected caller deny the owner their own seating capacity.
    #[tokio::test]
    async fn home_seat_refusals_mint_nothing() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x53; 32]).await?;
        provision_home(&state).await;
        let before = issued_invite_count(&state).await;
        let local = hex::encode(state.agent.agent_id().as_bytes());

        // Session owner → 403.
        let response = seat_home(
            State(Arc::clone(&state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: false,
            }),
            Json(SeatHomeRequest {
                agent_id: "7c".repeat(32),
            }),
        )
        .await;
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "session refusal: {body}");

        // Malformed target → 400.
        let (status, body) = seat(&state, "not-a-hex-agent-id").await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "malformed refusal: {body}");

        // The local agent → 400.
        let (status, body) = seat(&state, &local).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "self-seat refusal: {body}");

        assert_eq!(
            issued_invite_count(&state).await,
            before,
            "three refusals in sequence must leave the invite ledger untouched"
        );
        Ok(())
    }

    /// Advertise `group_id` as the canonical Home through the REAL store
    /// writer, so the fence under test is the production one.
    async fn commit_canonical_home(state: &Arc<AppState>, group_id: &str) -> anyhow::Result<()> {
        let sync = state
            .owner_sync
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("owned state wires sync"))?;
        let owner_kp = state
            .agent
            .identity()
            .user_keypair()
            .ok_or_else(|| anyhow::anyhow!("owned state has a user key"))?;
        sync.store()
            .mint(
                crate::owner_sync::SyncKind::HomePointer,
                crate::owner_sync::HOME_POINTER_KEY,
                &crate::owner_sync::SyncValue::HomePointer {
                    group_id: group_id.to_string(),
                    policy: home_policy(&owner_kp.user_id()),
                    roster: vec![],
                    primary_agent: "aa".repeat(32),
                    provisioned_at_ms: 1,
                },
                owner_kp,
                state.agent.machine_id(),
            )
            .await?;
        Ok(())
    }

    /// WHY (#449 r3 P2, the TOCTOU root found): `seat_home` resolves the
    /// canonical Home, then awaits the invite authority's per-group
    /// membership lock. In that window an owner-sync commit can accept a
    /// pointer naming a DIFFERENT Home. The mint reloads the old group,
    /// finds it live and non-withdrawn, and durably records an addressed
    /// invite into the Home that just lost — offering a device a seat in the
    /// duplicate the owner is trying to leave, which is fork amplification,
    /// exactly what #449 exists to stop.
    ///
    /// A recheck before the await cannot fix this, because the mint
    /// transaction awaits too. So this test refuses to be satisfied by one:
    /// it proves ORDERING. While the seat is parked on the membership lock,
    /// the competing pointer commit must still be PENDING. If the gate were
    /// a recheck, or absent, that commit would complete immediately and the
    /// assertion fails.
    ///
    /// The barrier is a test hook fired at the instant the handler has taken
    /// the gate and selected its Home, never a sleep: a sleep would prove
    /// only that the race is slow, not that anything orders it.
    ///
    /// The linearization this pins is the one root permits: a pointer
    /// accepted AFTER the gate waits for the mint to become durable, and the
    /// NEXT seat then refuses. Durable ledger state is inspected on both
    /// sides, not only the HTTP status.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn home_seat_mint_is_linearized_ahead_of_a_later_canonical_pointer() -> anyhow::Result<()>
    {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x54; 32]).await?;
        provision_home(&state).await;
        let owner = owner_of(&state);
        let (home_a, _) = find_home(&state, &owner).await.expect("Home A provisioned");
        commit_canonical_home(&state, &home_a).await?;
        // B is a Home this device is NOT seated in. That is what makes the
        // post-switch expectation unambiguous: had B been a local duplicate
        // we also hold, the correct answer after the switch would be a
        // successful mint into B, and the refusal this test asserts would be
        // wrong. A stays a fully live, non-withdrawn Home throughout, so no
        // withdrawal or role check can account for the refusal.
        let home_b = "e5".repeat(16);

        // Park the seat: hold A's REAL membership lock, the same lock the
        // invite authority takes.
        let membership = super::super::named_groups::group_membership_lock(&state, &home_a).await;
        let held = membership.lock().await;

        let seat_state = Arc::clone(&state);
        let device = "7e".repeat(32);
        let seat_device = device.clone();
        let seat_task = tokio::spawn(async move {
            let response = seat_home(
                State(seat_state),
                axum::extract::Extension(durable_owner()),
                Json(SeatHomeRequest {
                    agent_id: seat_device,
                }),
            )
            .await;
            response_json(response).await
        });

        // The handler now holds the gate and has selected A.
        seat_selected_canonical_hook().notified().await;

        let commit_state = Arc::clone(&state);
        let commit_b = home_b.clone();
        let mut commit =
            tokio::spawn(async move { commit_canonical_home(&commit_state, &commit_b).await });

        // THE FENCE. The two directions are asymmetric on purpose.
        //
        // FENCED: the commit CANNOT complete. It is blocked on the gate's
        // write side, held for reading by a seat that is itself blocked on
        // the membership lock this test holds. That is a hard impossibility,
        // not a timing assumption, so this direction cannot flake.
        //
        // UNFENCED: the commit is one `records` write plus one small durable
        // persist on a tmpdir — single-digit milliseconds. The window below
        // is three orders of magnitude larger, so an unfenced writer lands
        // inside it every time. The window is the ORACLE for that direction;
        // the BARRIER that put us at the exact instant of the race is the
        // test hook above, never a sleep. The mutation that removes the gate
        // is run against this test and must fail it.
        let landed = tokio::time::timeout(std::time::Duration::from_secs(5), &mut commit).await;
        assert!(
            landed.is_err(),
            "a canonical pointer accepted after the seat took the gate must wait for the \
             mint to become durable; it completed while the seat was still blocked: {landed:?}"
        );
        assert_eq!(
            state
                .owner_sync
                .as_ref()
                .expect("sync")
                .canonical_home()
                .await
                .map(|home| home.group_id),
            Some(home_a.clone()),
            "the register must still name A while the seat holds the gate"
        );

        drop(held);

        let (status, body) = seat_task.await??;
        assert_eq!(
            status,
            StatusCode::OK,
            "the fenced seat must succeed: {body}"
        );
        assert_eq!(body["group_id"], home_a, "the invite must belong to A");
        let signed = crate::groups::invite::SignedInvite::from_link(
            body["invite"].as_str().expect("invite link"),
        )
        .map_err(|e| anyhow::anyhow!("invite does not decode: {e}"))?;
        signed
            .verify_v4_signatures()
            .map_err(|e| anyhow::anyhow!("invite signatures do not verify: {e:?}"))?;
        assert_eq!(signed.intended_joiner.as_deref(), Some(device.as_str()));

        // Durable ledger, not just the response.
        let after_mint = issued_invite_count(&state).await;
        assert_eq!(after_mint, 1, "exactly one invite is recorded on A");

        commit.await??;
        assert_eq!(
            state
                .owner_sync
                .as_ref()
                .expect("sync")
                .canonical_home()
                .await
                .map(|home| home.group_id),
            Some(home_b.clone()),
            "once the mint is durable the queued pointer takes effect"
        );

        // The NEXT seat sees the new canonical and refuses.
        let (status, body) = seat(&state, &"7f".repeat(32)).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "after B wins, seating from A must refuse: {body}"
        );
        assert_eq!(body["reason"], "adoption_pending");
        assert_eq!(body["canonical_group_id"], home_b);
        assert_eq!(
            issued_invite_count(&state).await,
            after_mint,
            "the refused second seat must add nothing to the durable ledger"
        );
        Ok(())
    }

    /// WHY (#449 r3 P2, the ordering that must NOT mint): when the canonical
    /// pointer moved to B before the seat request arrives, there is no race
    /// to fence — the answer is simply that this device is no longer the one
    /// that may seat. The gate must not turn a settled refusal into a
    /// mint. Asserted on the durable ledger, which must stay empty: a
    /// refusal that still burned a live-invite slot would let a stale
    /// operator exhaust the owner's seating capacity.
    #[tokio::test]
    async fn home_seat_refuses_when_canonical_moved_before_the_gate() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x55; 32]).await?;
        provision_home(&state).await;
        let owner = owner_of(&state);
        let (home_a, _) = find_home(&state, &owner).await.expect("Home A provisioned");
        commit_canonical_home(&state, &home_a).await?;

        let home_b = "e6".repeat(16);
        commit_canonical_home(&state, &home_b).await?;

        let (status, body) = seat(&state, &"7e".repeat(32)).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "adoption_pending");
        assert_eq!(body["canonical_group_id"], home_b);
        assert_eq!(
            issued_invite_count(&state).await,
            0,
            "a seat refused on a moved canonical must leave A's ledger empty"
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
