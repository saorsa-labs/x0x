//! ADR 0110 §4a and §4b(2): the daemon side of `CertificateRebindV1`, the
//! commit that binds a renewed certificate into an Active seat in place.
//!
//! - **Self-rebind route** ([`rebind_member_certificate`],
//!   `POST /groups/:id/members/:agent_id/certificate/rebind`). The seat's
//!   own agent rebinds its own certificate. Before the cutoff
//!   `not_after − τ` on its own clock it commits the rebind. After the
//!   cutoff the route refuses with `rebind_window_closed`, hands the
//!   renewal to every eligible admin in an `EvictionHandoffV1`, and the
//!   agent shows `waiting_for_admin_rebind`, naming the designated admin,
//!   until a rebind or a removal for its seat lands (D155). When no
//!   eligible admin exists because every admin's certificate expired, an
//!   admin's own self-rebind is allowed after its cutoff (§4b(2)).
//! - **Admin rebind** ([`try_admin_rebind`]). At an expiry-only row's
//!   commit point, the designated expiry worker (or a ranked fallback)
//!   commits the rebind instead of `MemberRemoved` when it holds a
//!   verified renewal for the seat (from the hand-off or the announce
//!   cache) and the mixed-version rule allows it. Otherwise it evicts.
//! - **Mixed versions.** An ordinary rebind runs only when every other
//!   Active member's current verified advert sets `certificate_rebind_v1`
//!   (D129). The §4b(2) self-rebind follows the D76 hold rule instead: a
//!   known lacking advert holds it (`waiting_for_receiver_upgrade`), and
//!   the held rebind commits once the hold lifts; unknown, expired or
//!   offline members are stranded until they upgrade.
//! - **Delivery** ([`drive`]). Per-recipient, capability-gated direct
//!   delivery only, never the metadata topic and never a legacy-decoded
//!   container. Each write re-checks roster membership and the agent,
//!   machine and binding revocations just before it. **Catch-up**
//!   ([`serve_catchup`]) sends held frames to a capable requester on the
//!   same carrier.
//! - **Receive** ([`spawn_receipt`]) verifies the frame and the §4a L4
//!   rule and installs it atomically. A verified rebind on the current
//!   chain ends that seat's expiry rows with cause `certificate_valid`
//!   (the S4 pass re-derives it from the roster).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::Deserialize;
use tokio::time::Instant;

use crate as x0x;
use crate::server::state::AppState;
use x0x::groups::cert_rebind as cr;
use x0x::groups::eviction::{self as s4, EvictionKey, ObligationRow, WaitingCause, WaitingState};
use x0x::groups::{GroupInfo, GroupMemberState, GroupRole};
use x0x::identity::{AgentCertificate, AgentId};
use x0x::logging::LogHexId;

use super::crypto_exclusion::{write_allowed, RecipientDelivery};

/// A delivery round runs no more often than this per frame.
const CRB_RESEND_INTERVAL: Duration = Duration::from_secs(5);
/// A delivery is abandoned after this long; later catch-up serves it.
const CRB_DELIVERY_TTL: Duration = Duration::from_secs(600);
/// Frames held per group for catch-up serving.
const CRB_LOG_PER_GROUP: usize = 16;
/// Frames that arrived ahead of this node's head, waiting for it.
const CRB_STASH_CAP: usize = 64;
/// A stashed frame is dropped after this long.
const CRB_STASH_TTL: Duration = Duration::from_secs(600);
/// The per-exchange bound of one catch-up frame write.
const CRB_CATCHUP_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);

/// The public refusal of a self-rebind after the cutoff (D155).
pub(in crate::server) const REBIND_WINDOW_CLOSED: &str = "rebind_window_closed";
/// The seat agent's wait after it handed the renewal to the admins.
pub(in crate::server) const WAITING_FOR_ADMIN_REBIND: &str = "waiting_for_admin_rebind";

/// The retained delivery of one committed rebind.
#[derive(Debug, Clone)]
struct Delivery {
    bytes: Arc<Vec<u8>>,
    result_head: String,
    recipients: BTreeMap<[u8; 32], RecipientDelivery>,
    next_at: Instant,
    started: Instant,
}

#[derive(Debug, Clone)]
struct LogEntry {
    next_revision: u64,
    bytes: Arc<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct StashedFrame {
    sender: AgentId,
    bytes: Vec<u8>,
    at: Instant,
}

/// The seat agent's `waiting_for_admin_rebind` (§4a, D155).
#[derive(Debug, Clone)]
struct AdminRebindWait {
    designated: Option<[u8; 32]>,
    old_digest: String,
    renewal_digest: String,
    since_unix_ms: u64,
}

/// A §4b(2) self-rebind held by the D76 rule.
#[derive(Debug, Clone)]
struct HeldSelfRebind {
    group_key: String,
    certificate: AgentCertificate,
    holders: Vec<[u8; 32]>,
}

/// The certificate-rebind state held in the S4 runtime.
#[derive(Debug, Default)]
pub(super) struct RebindState {
    /// Keyed by (stable group ID, result head).
    deliveries: HashMap<(String, String), Delivery>,
    log: HashMap<String, VecDeque<LogEntry>>,
    stash: Vec<StashedFrame>,
    /// Verified renewals an admin holds for a seat, from a hand-off.
    renewals: HashMap<EvictionKey, AgentCertificate>,
    /// Seat-agent side `waiting_for_admin_rebind`.
    admin_waits: HashMap<EvictionKey, AdminRebindWait>,
    /// §4b(2) self-rebinds held by the D76 rule.
    held: HashMap<EvictionKey, HeldSelfRebind>,
}

impl RebindState {
    fn remember(&mut self, stable_group_id: &str, next_revision: u64, bytes: Arc<Vec<u8>>) {
        let log = self.log.entry(stable_group_id.to_string()).or_default();
        if log.iter().any(|entry| entry.next_revision == next_revision) {
            return;
        }
        log.push_back(LogEntry {
            next_revision,
            bytes,
        });
        while log.len() > CRB_LOG_PER_GROUP {
            log.pop_front();
        }
    }
}

fn agent_bytes(hex_id: &str) -> Option<[u8; 32]> {
    super::super::parse_agent_id_hex(hex_id)
        .ok()
        .map(|agent| *agent.as_bytes())
}

fn now_unix_ms() -> u64 {
    super::now_unix_ms()
}

fn owner_certified(info: &GroupInfo) -> bool {
    info.policy.admission.owner_certified_user_id().is_some()
}

/// Active members of `info` other than `local`.
fn other_active_members(info: &GroupInfo, local: &[u8; 32]) -> Vec<[u8; 32]> {
    info.active_members()
        .filter_map(|member| agent_bytes(&member.agent_id))
        .filter(|id| id != local)
        .collect()
}

/// Admin-or-higher Active seats with their selected certificate's
/// `not_after` (§1a), for [`cr::admins_needing_renewal`].
fn admins_with_expiry(info: &GroupInfo) -> Vec<([u8; 32], Option<u64>)> {
    info.active_members()
        .filter(|member| member.role.at_least(GroupRole::Admin))
        .filter_map(|member| {
            let id = agent_bytes(&member.agent_id)?;
            let not_after = cr::committed_certificate(member).and_then(AgentCertificate::not_after);
            Some((id, not_after))
        })
        .collect()
}

/// The capability support of each member for `certificate_rebind_v1`.
fn rebind_support(state: &AppState, members: &[[u8; 32]]) -> Vec<([u8; 32], Option<bool>)> {
    let capabilities = state.agent.capability_store();
    members
        .iter()
        .map(|id| {
            (
                *id,
                capabilities.verified_registry_supports(
                    &AgentId(*id),
                    x0x::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1,
                ),
            )
        })
        .collect()
}

/// Ask every member with unknown support for an advert refresh (ADR 0093).
fn refresh_unknown(state: &Arc<AppState>, support: &[([u8; 32], Option<bool>)]) {
    for (id, supported) in support {
        if supported.is_none() {
            let task_state = Arc::clone(state);
            let agent = AgentId(*id);
            let _spawned = state.spawn_detached(async move {
                task_state
                    .agent
                    .refresh_application_capability(
                        agent,
                        x0x::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1,
                    )
                    .await;
            });
        }
    }
}

async fn revoked_ids(state: &AppState, ids: &[[u8; 32]]) -> BTreeSet<[u8; 32]> {
    let revocation_set = state.agent.revocation_set();
    let set = revocation_set.read().await;
    ids.iter()
        .copied()
        .filter(|id| set.is_agent_revoked(&AgentId(*id)))
        .collect()
}

/// The eligible admins of `info` for a hand-off about `seat`: Active,
/// Admin-or-higher, not revoked, not the seat itself.
async fn eligible_admins(state: &AppState, info: &GroupInfo, seat: &[u8; 32]) -> Vec<[u8; 32]> {
    let admins: Vec<[u8; 32]> = info
        .active_members()
        .filter(|member| member.role.at_least(GroupRole::Admin))
        .filter_map(|member| agent_bytes(&member.agent_id))
        .filter(|id| id != seat)
        .collect();
    let revoked = revoked_ids(state, &admins).await;
    admins
        .into_iter()
        .filter(|id| !revoked.contains(id))
        .collect()
}

// ─── S4 row override (§1a, §4b(2)) ─────────────────────────────────────────

/// §1a and §4b(2): an expiry-only row of a seated target in an
/// `OwnerCertified` group, where every admin other than the target holds an
/// expired selected certificate, waits for an owner renewal
/// (`waiting_for_admin_certificate_renewal`, naming those admins). While a
/// renewing admin's self-rebind is held by the D76 rule, the row shows
/// `waiting_for_receiver_upgrade`, naming the holders.
pub(super) fn row_override(
    rebind: &RebindState,
    info: &GroupInfo,
    row: &ObligationRow,
    target_seated: bool,
    now_unix: u64,
) -> Option<WaitingState> {
    if !row.expiry_only() || !target_seated || !owner_certified(info) {
        return None;
    }
    let admins = cr::admins_needing_renewal(&admins_with_expiry(info), &row.target, now_unix)?;
    let holders: Vec<[u8; 32]> = rebind
        .held
        .iter()
        .filter(|(key, _)| key.stable_group_id == row.stable_group_id)
        .flat_map(|(_, held)| held.holders.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut waiting = if holders.is_empty() {
        let mut waiting = WaitingState::cause(WaitingCause::WaitingForAdminCertificateRenewal);
        waiting.named = admins;
        waiting
    } else {
        let mut waiting = WaitingState::cause(WaitingCause::WaitingForReceiverUpgrade);
        waiting.named = holders;
        waiting
    };
    waiting.designated_detail = None;
    Some(waiting)
}

// ─── Commit ────────────────────────────────────────────────────────────────

/// Why a local rebind did not commit.
#[derive(Debug)]
enum CommitError {
    Refused(cr::CertificateRebindRefusal),
    Oversized,
    Persist(String),
}

/// Seal, check, persist and schedule delivery of one rebind. The caller
/// holds `group_key`'s membership lock and read `info` under it.
async fn commit_locked(
    state: &Arc<AppState>,
    group_key: &str,
    info: &GroupInfo,
    seat: [u8; 32],
    certificate: &AgentCertificate,
) -> Result<GroupInfo, CommitError> {
    use super::super as ng;
    let signing_kp = state.agent.identity().agent_keypair();
    let now_ms = ng::now_millis_u64();
    let (next, frame) =
        cr::seal(info, seat, certificate, signing_kp, now_ms).map_err(CommitError::Refused)?;
    // The author checks its own frame with the receiver's rule first.
    {
        let revocation_set = state.agent.revocation_set();
        let set = revocation_set.read().await;
        cr::validate_against_parent(&frame.body, info, now_ms / 1000, |id| {
            set.is_agent_revoked(&AgentId(*id))
        })
        .map_err(CommitError::Refused)?;
    }
    let bytes = cr::encode_frame(&frame)
        .map_err(|_| CommitError::Refused(cr::CertificateRebindRefusal::Malformed))?;
    if bytes.len() > x0x::dm::MAX_PAYLOAD_BYTES {
        return Err(CommitError::Oversized);
    }
    match ng::persist_named_group_info(state, group_key, next.clone()).await {
        Ok(ng::AtomicWriteOutcome::Durable) => {}
        Ok(ng::AtomicWriteOutcome::ReplacedNotDurable) => {
            // The replacement is visible on disk and in memory; deliver it
            // so the chain stays coherent, and say so.
            tracing::warn!(group_id = %LogHexId::group(group_key), "ADR 0110 S4: certificate rebind persisted without a durability confirmation");
        }
        Ok(ng::AtomicWriteOutcome::NotReplaced) => {
            return Err(CommitError::Persist("not replaced".to_string()));
        }
        Err(error) => return Err(CommitError::Persist(error.to_string())),
    }
    ng::refresh_group_card_cache_from_info(state, group_key, &next).await;
    let local = *state.agent.agent_id().as_bytes();
    let bytes = Arc::new(bytes);
    {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner.rebind.remember(
            next.stable_group_id(),
            next.state_revision,
            Arc::clone(&bytes),
        );
        inner.rebind.deliveries.insert(
            (next.stable_group_id().to_string(), next.state_hash.clone()),
            Delivery {
                bytes,
                result_head: next.state_hash.clone(),
                recipients: other_active_members(&next, &local)
                    .into_iter()
                    .map(|id| (id, RecipientDelivery::Due))
                    .collect(),
                next_at: Instant::now(),
                started: Instant::now(),
            },
        );
        let key = EvictionKey::new(next.stable_group_id(), seat);
        inner.rebind.admin_waits.remove(&key);
        inner.rebind.renewals.remove(&key);
        inner.rebind.held.remove(&key);
    }
    tracing::info!(
        group_id = %LogHexId::group(group_key),
        seat = %LogHexId::agent(&hex::encode(seat)),
        revision = next.state_revision,
        "ADR 0110 S4: certificate rebind committed"
    );
    state.agent.s4_revocation_intake().request_reconcile();
    let task_state = Arc::clone(state);
    let card_key = group_key.to_string();
    let _spawned = state.spawn_detached(async move {
        ng::maybe_publish_group_card_after_state_change(&task_state, &card_key).await;
        drive_deliveries(&task_state).await;
    });
    Ok(next)
}

// ─── Self-rebind route (§4a, §4b(2)) ───────────────────────────────────────

/// Request body for `POST /groups/:id/members/:agent_id/certificate/rebind`.
#[derive(Debug, Default, Deserialize)]
pub(in crate::server) struct RebindCertificateRequest {
    /// The renewed certificate in its storage encoding, base64 (the
    /// `certificate.storage_b64` of `POST /owner/agents/issue`). When
    /// absent, the daemon's own loaded agent certificate is used.
    #[serde(default)]
    certificate: Option<String>,
}

fn refusal(
    status: StatusCode,
    error: &str,
    extra: serde_json::Value,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut body = serde_json::json!({ "ok": false, "error": error, "reason": error });
    if let (Some(object), serde_json::Value::Object(more)) = (body.as_object_mut(), extra) {
        object.extend(more);
    }
    (status, Json(body))
}

fn rebind_refusal_status(refusal: cr::CertificateRebindRefusal) -> StatusCode {
    match refusal {
        cr::CertificateRebindRefusal::SignerIneligible => StatusCode::FORBIDDEN,
        cr::CertificateRebindRefusal::CertificateInvalid
        | cr::CertificateRebindRefusal::NotLater => StatusCode::UNPROCESSABLE_ENTITY,
        cr::CertificateRebindRefusal::SealFailed => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::CONFLICT,
    }
}

/// `POST /groups/:id/members/:agent_id/certificate/rebind`: the agent's
/// self-rebind of its own seat (ADR 0110 §4a, D129, D155; §4b(2)).
pub(in crate::server) async fn rebind_member_certificate(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Path((id, agent_id_hex)): Path<(String, String)>,
    body: Option<Json<RebindCertificateRequest>>,
) -> (StatusCode, Json<serde_json::Value>) {
    use super::super as ng;
    if let Some(resp) = ng::home_mutation_requires_durable(&state, &actor, &id).await {
        return resp;
    }
    let local = *state.agent.agent_id().as_bytes();
    let local_hex = hex::encode(local);
    if !agent_id_hex.eq_ignore_ascii_case(&local_hex) {
        // Only the seat's own agent self-rebinds; an admin's rebind is the
        // expiry worker's, never this route's.
        return refusal(
            StatusCode::FORBIDDEN,
            cr::CertificateRebindRefusal::SignerIneligible.as_str(),
            serde_json::json!({ "detail": "only the seat's own agent may self-rebind" }),
        );
    }
    let requested = body.and_then(|Json(request)| request.certificate);
    let certificate = match requested {
        Some(encoded) => {
            match BASE64
                .decode(encoded.trim())
                .ok()
                .and_then(|bytes| AgentCertificate::from_storage_bytes(&bytes).ok())
            {
                Some(certificate) => certificate,
                None => {
                    return refusal(
                        StatusCode::BAD_REQUEST,
                        cr::CertificateRebindRefusal::CertificateInvalid.as_str(),
                        serde_json::json!({ "detail": "certificate is not a base64 storage-encoded AgentCertificate" }),
                    )
                }
            }
        }
        None => match state.agent.agent_certificate().cloned() {
            Some(certificate) => certificate,
            None => {
                return refusal(
                    StatusCode::BAD_REQUEST,
                    cr::CertificateRebindRefusal::CertificateInvalid.as_str(),
                    serde_json::json!({ "detail": "no certificate given and none loaded" }),
                )
            }
        },
    };
    if certificate.agent_id().ok() != Some(AgentId(local)) {
        return refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            cr::CertificateRebindRefusal::CertificateInvalid.as_str(),
            serde_json::json!({ "detail": "certificate binds a different agent" }),
        );
    }
    let Some(group_key) = ng::resolve_named_group_storage_key(&state, &id).await else {
        return refusal(
            StatusCode::NOT_FOUND,
            "group not found",
            serde_json::json!({}),
        );
    };
    let membership_lock = ng::group_membership_lock(&state, &group_key).await;
    let _membership_guard = membership_lock.lock().await;
    let Some(info) = state.named_groups.read().await.get(&group_key).cloned() else {
        return refusal(
            StatusCode::NOT_FOUND,
            "group not found",
            serde_json::json!({}),
        );
    };
    let stable = info.stable_group_id().to_string();
    let Some(seat) = info
        .members_v2
        .get(&local_hex)
        .filter(|member| member.state == GroupMemberState::Active)
        .cloned()
    else {
        return refusal(
            StatusCode::CONFLICT,
            cr::CertificateRebindRefusal::SeatNotActive.as_str(),
            serde_json::json!({ "group_id": stable }),
        );
    };
    let now_unix = now_unix_ms() / 1000;
    // Pre-check the renewal against the committed seat with the receiver's
    // rule, so a refused renewal is never handed off or held.
    let old_not_after = cr::committed_certificate(&seat).and_then(AgentCertificate::not_after);
    let precheck = precheck_renewal(&state, &info, &local, &certificate, now_unix).await;
    if let Err(refused) = precheck {
        return refusal(
            rebind_refusal_status(refused),
            refused.as_str(),
            serde_json::json!({ "group_id": stable }),
        );
    }
    let seat_is_admin = seat.role.at_least(GroupRole::Admin);
    // §4b(2): no eligible admin exists because every other admin's
    // certificate expired. An admin's own self-rebind then runs after its
    // cutoff, under the D76 hold rule.
    let window_open = cr::self_rebind_window_open(old_not_after, now_unix);
    let admins = admins_with_expiry(&info);
    let every_admin_expired = !window_open
        && seat_is_admin
        && (admins.iter().all(|(id, _)| *id == local)
            || cr::admins_needing_renewal(&admins, &local, now_unix).is_some());
    let key = EvictionKey::new(stable.clone(), local);
    if !window_open && !every_admin_expired {
        return hand_to_admins(&state, &info, &seat, &certificate, now_unix).await;
    }
    let others = other_active_members(&info, &local);
    let support = rebind_support(&state, &others);
    if every_admin_expired {
        let holders = x0x::groups::crypto_exclusion::receiver_upgrade_holders(support.clone());
        if !holders.is_empty() {
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .rebind
                .held
                .insert(
                    key,
                    HeldSelfRebind {
                        group_key: group_key.clone(),
                        certificate,
                        holders: holders.clone(),
                    },
                );
            return refusal(
                StatusCode::CONFLICT,
                WaitingCause::WaitingForReceiverUpgrade.as_str(),
                serde_json::json!({
                    "group_id": stable,
                    "state": WaitingCause::WaitingForReceiverUpgrade.as_str(),
                    "named": holders.iter().map(hex::encode).collect::<Vec<_>>(),
                    "detail": "held: an Active member's current advert lacks certificate_rebind_v1; it commits when the hold lifts",
                }),
            );
        }
    } else if !cr::rebind_allowed_for_members(support.iter().map(|(_, supported)| *supported)) {
        refresh_unknown(&state, &support);
        let lacking: Vec<String> = support
            .iter()
            .filter(|(_, supported)| *supported != Some(true))
            .map(|(id, _)| hex::encode(id))
            .collect();
        return refusal(
            StatusCode::CONFLICT,
            WaitingCause::WaitingForReceiverUpgrade.as_str(),
            serde_json::json!({
                "group_id": stable,
                "state": WaitingCause::WaitingForReceiverUpgrade.as_str(),
                "named": lacking,
                "detail": "rebinding is off while an Active member's current verified advert does not set certificate_rebind_v1",
            }),
        );
    }
    match commit_locked(&state, &group_key, &info, local, &certificate).await {
        Ok(next) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "group_id": stable,
                "agent_id": local_hex,
                "certificate_digest": x0x::groups::owner_cert::certificate_digest_hex(&certificate),
                "not_after": certificate.not_after(),
                "state_revision": next.state_revision,
                "state_hash": next.state_hash,
            })),
        ),
        Err(CommitError::Refused(refused)) => refusal(
            rebind_refusal_status(refused),
            refused.as_str(),
            serde_json::json!({ "group_id": stable }),
        ),
        Err(CommitError::Oversized) => refusal(
            StatusCode::PAYLOAD_TOO_LARGE,
            "rebind_frame_oversized",
            serde_json::json!({ "group_id": stable }),
        ),
        Err(CommitError::Persist(error)) => refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "persist_failed",
            serde_json::json!({ "group_id": stable, "detail": error }),
        ),
    }
}

/// The receiver's checks on a renewal for `seat` on `info`, without a
/// commit: signer, seat, owner chain, revocation, expiry and later
/// `not_after`.
async fn precheck_renewal(
    state: &AppState,
    info: &GroupInfo,
    seat: &[u8; 32],
    certificate: &AgentCertificate,
    now_unix: u64,
) -> Result<(), cr::CertificateRebindRefusal> {
    let seat_hex = hex::encode(seat);
    let member = info
        .members_v2
        .get(&seat_hex)
        .filter(|member| member.state == GroupMemberState::Active)
        .ok_or(cr::CertificateRebindRefusal::SeatNotActive)?;
    let owner = info
        .policy
        .admission
        .owner_certified_user_id()
        .ok_or(cr::CertificateRebindRefusal::CertificateInvalid)?;
    let revoked = !revoked_ids(state, &[*seat]).await.is_empty();
    if revoked && agent_bytes(&seat_hex) == Some(*state.agent.agent_id().as_bytes()) {
        return Err(cr::CertificateRebindRefusal::SignerIneligible);
    }
    x0x::groups::owner_cert::verify_cert_against_owner(
        owner,
        &seat_hex,
        certificate,
        revoked,
        now_unix,
    )
    .map_err(|_| cr::CertificateRebindRefusal::CertificateInvalid)?;
    let committed =
        cr::committed_digest(member).ok_or(cr::CertificateRebindRefusal::DigestMismatch)?;
    let old = cr::committed_certificate(member)
        .ok_or(cr::CertificateRebindRefusal::CertificateEvidenceMissing)?;
    if x0x::groups::owner_cert::certificate_digest_hex(certificate) == committed
        || !cr::expires_later(certificate.not_after(), old.not_after())
    {
        return Err(cr::CertificateRebindRefusal::NotLater);
    }
    Ok(())
}

/// After the cutoff (D155): hand the renewal to every eligible admin in an
/// `EvictionHandoffV1`, record `waiting_for_admin_rebind` naming the
/// designated admin, and refuse with `rebind_window_closed`.
async fn hand_to_admins(
    state: &Arc<AppState>,
    info: &GroupInfo,
    seat: &x0x::groups::GroupMember,
    certificate: &AgentCertificate,
    now_unix: u64,
) -> (StatusCode, Json<serde_json::Value>) {
    let local = *state.agent.agent_id().as_bytes();
    let stable = info.stable_group_id().to_string();
    let admins = eligible_admins(state, info, &local).await;
    let designated = s4::designate(admins.iter().copied(), &local).map(|d| d.designated);
    let old_digest = cr::committed_digest(seat).unwrap_or_default();
    let renewal_digest = x0x::groups::owner_cert::certificate_digest_hex(certificate);
    let handed_to = match cr::encode_certificate(certificate) {
        Some(bytes) => {
            let handoff = s4::EvictionHandoffV1 {
                stable_group_id: stable.clone(),
                target: local,
                observed_parent_head: info.state_hash.clone(),
                revocation_records: Vec::new(),
                self_leave_commit: None,
                expired_certificate: None,
                renewed_certificate: Some(bytes),
            };
            send_handoff(state, &handoff, &admins)
        }
        None => Vec::new(),
    };
    state
        .revocation_evictions
        .inner
        .lock()
        .await
        .rebind
        .admin_waits
        .insert(
            EvictionKey::new(stable.clone(), local),
            AdminRebindWait {
                designated,
                old_digest,
                renewal_digest: renewal_digest.clone(),
                since_unix_ms: now_unix.saturating_mul(1000),
            },
        );
    tracing::info!(
        group_id = %LogHexId::group(&stable),
        "ADR 0110 S4: self-rebind window closed; renewal handed to the eligible admins"
    );
    refusal(
        StatusCode::CONFLICT,
        REBIND_WINDOW_CLOSED,
        serde_json::json!({
            "group_id": stable,
            "state": WAITING_FOR_ADMIN_REBIND,
            "designated_admin": designated.map(hex::encode),
            "renewal_digest": renewal_digest,
            "handed_to": handed_to.iter().map(hex::encode).collect::<Vec<_>>(),
        }),
    )
}

/// Send a hand-off to each admin whose current verified advert sets
/// `eviction_handoff_v1`. Returns the admins it was sent to.
fn send_handoff(
    state: &Arc<AppState>,
    handoff: &s4::EvictionHandoffV1,
    admins: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    let Ok(payload) = s4::encode_handoff(handoff) else {
        return Vec::new();
    };
    if payload.len() > x0x::dm::MAX_PAYLOAD_BYTES {
        return Vec::new();
    }
    let capabilities = state.agent.capability_store();
    let mut sent = Vec::new();
    for admin in admins {
        let agent = AgentId(*admin);
        if capabilities
            .verified_registry_supports(&agent, x0x::dm::CapabilityRegistry::EVICTION_HANDOFF_V1)
            != Some(true)
        {
            continue;
        }
        sent.push(*admin);
        let send_state = Arc::clone(state);
        let bytes = payload.clone();
        let _spawned = state.spawn_detached(async move {
            if let Err(error) = send_state.agent.send_direct(&agent, bytes).await {
                tracing::debug!(%error, "ADR 0110 S4: renewal hand-off send failed");
            }
        });
    }
    sent
}

// ─── Admin side: hand-off renewal and expiry worker ───────────────────────

/// A hand-off from the seat's own agent carried a renewed certificate
/// (§4). Verify it independently against this node's committed seat and
/// keep it for the expiry worker. Returns whether it was kept.
pub(super) async fn note_handoff_renewal(
    state: &AppState,
    stable_group_id: &str,
    target: [u8; 32],
    sender: AgentId,
    bytes: &[u8],
) -> bool {
    if sender.as_bytes() != &target {
        // §4: the renewal is sent by the seat's own agent.
        return false;
    }
    let Some(certificate) = cr::decode_certificate(bytes) else {
        return false;
    };
    let info = {
        let groups = state.named_groups.read().await;
        groups
            .values()
            .find(|info| info.stable_group_id() == stable_group_id && !info.withdrawn)
            .cloned()
    };
    let Some(info) = info else {
        return false;
    };
    let now_unix = now_unix_ms() / 1000;
    if let Err(refused) = precheck_renewal(state, &info, &target, &certificate, now_unix).await {
        tracing::debug!(
            reason = refused.as_str(),
            "ADR 0110 S4: hand-off renewal refused"
        );
        return false;
    }
    state
        .revocation_evictions
        .inner
        .lock()
        .await
        .rebind
        .renewals
        .insert(EvictionKey::new(stable_group_id, target), certificate);
    true
}

/// §4a "The designated admin commits it": at the commit point of an
/// expiry-only row, commit the rebind instead of `MemberRemoved` when this
/// node holds a verified renewal for the seat and every other Active
/// member's current verified advert sets `certificate_rebind_v1`. Returns
/// whether the rebind committed; on `false` the caller evicts.
pub(super) async fn try_admin_rebind(
    state: &Arc<AppState>,
    key: &EvictionKey,
    group_key: &str,
) -> bool {
    use super::super as ng;
    let (expiry_only, held) = {
        let inner = state.revocation_evictions.inner.lock().await;
        (
            inner.store.get(key).is_some_and(ObligationRow::expiry_only),
            inner.rebind.renewals.get(key).cloned(),
        )
    };
    // A renewal never cancels revocation or self-leave work (§1a).
    if !expiry_only {
        return false;
    }
    let announced = match state.agent.discovered_agent(AgentId(key.target)).await {
        Ok(Some(entry)) => entry.agent_certificate,
        _ => None,
    };
    let candidates: Vec<AgentCertificate> = held.into_iter().chain(announced).collect();
    if candidates.is_empty() {
        return false;
    }
    let membership_lock = ng::group_membership_lock(state, group_key).await;
    let _membership_guard = membership_lock.lock().await;
    let Some(info) = state.named_groups.read().await.get(group_key).cloned() else {
        return false;
    };
    let local = *state.agent.agent_id().as_bytes();
    let support = rebind_support(state, &other_active_members(&info, &local));
    if !cr::rebind_allowed_for_members(support.iter().map(|(_, supported)| *supported)) {
        // D129: an unknown or lacking advert disables rebinding; evict.
        refresh_unknown(state, &support);
        return false;
    }
    let now_unix = now_unix_ms() / 1000;
    for certificate in candidates {
        if precheck_renewal(state, &info, &key.target, &certificate, now_unix)
            .await
            .is_err()
        {
            continue;
        }
        match commit_locked(state, group_key, &info, key.target, &certificate).await {
            Ok(_) => return true,
            Err(error) => {
                tracing::warn!(
                    group_id = %LogHexId::group(group_key),
                    target = %LogHexId::agent(&hex::encode(key.target)),
                    ?error,
                    "ADR 0110 S4: admin certificate rebind failed; evicting"
                );
                return false;
            }
        }
    }
    false
}

// ─── Worker ────────────────────────────────────────────────────────────────

/// One worker step: deliveries, stashed receipts, held self-rebinds and
/// the seat agent's admin waits.
pub(super) async fn drive(state: &Arc<AppState>) {
    drive_deliveries(state).await;
    retry_stash(state).await;
    drive_held(state).await;
    prune_admin_waits(state).await;
}

/// §4b(2): re-evaluate each held self-rebind; commit it once no known
/// Active member's current verified advert lacks the capability.
async fn drive_held(state: &Arc<AppState>) {
    use super::super as ng;
    let held: Vec<(EvictionKey, HeldSelfRebind)> = {
        let inner = state.revocation_evictions.inner.lock().await;
        inner
            .rebind
            .held
            .iter()
            .map(|(key, held)| (key.clone(), held.clone()))
            .collect()
    };
    for (key, held) in held {
        let membership_lock = ng::group_membership_lock(state, &held.group_key).await;
        let _membership_guard = membership_lock.lock().await;
        let info = state
            .named_groups
            .read()
            .await
            .get(&held.group_key)
            .cloned();
        let Some(info) = info.filter(|info| {
            !info.withdrawn
                && info
                    .members_v2
                    .get(&hex::encode(key.target))
                    .is_some_and(|member| member.state == GroupMemberState::Active)
        }) else {
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .rebind
                .held
                .remove(&key);
            continue;
        };
        let holders = x0x::groups::crypto_exclusion::receiver_upgrade_holders(rebind_support(
            state,
            &other_active_members(&info, &key.target),
        ));
        if !holders.is_empty() {
            if let Some(entry) = state
                .revocation_evictions
                .inner
                .lock()
                .await
                .rebind
                .held
                .get_mut(&key)
            {
                entry.holders = holders;
            }
            continue;
        }
        match commit_locked(state, &held.group_key, &info, key.target, &held.certificate).await {
            Ok(_) => {}
            Err(CommitError::Refused(refused)) => {
                tracing::info!(
                    group_id = %LogHexId::group(&held.group_key),
                    reason = refused.as_str(),
                    "ADR 0110 S4: held self-rebind refused; dropped"
                );
                state
                    .revocation_evictions
                    .inner
                    .lock()
                    .await
                    .rebind
                    .held
                    .remove(&key);
            }
            Err(error) => {
                tracing::warn!(group_id = %LogHexId::group(&held.group_key), ?error, "ADR 0110 S4: held self-rebind commit failed; retrying");
            }
        }
    }
}

/// End the seat agent's `waiting_for_admin_rebind` once a rebind or a
/// removal for its seat landed.
async fn prune_admin_waits(state: &AppState) {
    let seats: HashMap<EvictionKey, Option<String>> = {
        let groups = state.named_groups.read().await;
        let inner = state.revocation_evictions.inner.lock().await;
        inner
            .rebind
            .admin_waits
            .keys()
            .chain(inner.rebind.renewals.keys())
            .map(|key| {
                let digest = groups
                    .values()
                    .find(|info| info.stable_group_id() == key.stable_group_id && !info.withdrawn)
                    .and_then(|info| info.members_v2.get(&hex::encode(key.target)))
                    .filter(|member| member.state == GroupMemberState::Active)
                    .and_then(cr::committed_digest);
                (key.clone(), digest)
            })
            .collect()
    };
    let mut inner = state.revocation_evictions.inner.lock().await;
    inner.rebind.admin_waits.retain(|key, wait| {
        seats
            .get(key)
            .is_some_and(|digest| digest.as_deref() == Some(wait.old_digest.as_str()))
    });
    // A held renewal is useful only while its seat is still Active.
    inner
        .rebind
        .renewals
        .retain(|key, _| seats.get(key).is_some_and(Option::is_some));
}

// ─── Delivery ──────────────────────────────────────────────────────────────

async fn drive_deliveries(state: &Arc<AppState>) {
    let now = Instant::now();
    let due: Vec<((String, String), Delivery)> = {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner.rebind.deliveries.retain(|_, delivery| {
            now.saturating_duration_since(delivery.started) < CRB_DELIVERY_TTL
        });
        let keys: Vec<(String, String)> = inner
            .rebind
            .deliveries
            .iter()
            .filter(|(_, delivery)| delivery.next_at <= now)
            .map(|(key, _)| key.clone())
            .collect();
        keys.into_iter()
            .filter_map(|key| {
                let delivery = inner.rebind.deliveries.get_mut(&key)?;
                delivery.next_at = now + CRB_RESEND_INTERVAL;
                Some((key, delivery.clone()))
            })
            .collect()
    };
    if due.is_empty() {
        return;
    }
    let local = *state.agent.agent_id().as_bytes();
    let capabilities = state.agent.capability_store();
    for (key, delivery) in due {
        let info = {
            let groups = state.named_groups.read().await;
            groups
                .values()
                .find(|info| info.stable_group_id() == key.0)
                .cloned()
        };
        let on_chain = info.as_ref().is_some_and(|info| {
            !info.withdrawn
                && info.fork_quarantine.is_none()
                && (info.state_hash == delivery.result_head
                    || info
                        .commit_log
                        .iter()
                        .any(|retained| retained.commit.state_hash == delivery.result_head))
        });
        let Some(info) = info.filter(|_| on_chain) else {
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .rebind
                .deliveries
                .remove(&key);
            continue;
        };
        let active: BTreeSet<[u8; 32]> = other_active_members(&info, &local).into_iter().collect();
        let mut updates: Vec<([u8; 32], Option<RecipientDelivery>)> = Vec::new();
        for (recipient, status) in &delivery.recipients {
            if !active.contains(recipient) {
                updates.push((*recipient, None));
                continue;
            }
            if matches!(
                status,
                RecipientDelivery::Sent | RecipientDelivery::InFlight(_)
            ) {
                continue;
            }
            let agent = AgentId(*recipient);
            if !write_allowed(state, &agent).await {
                continue;
            }
            match capabilities.verified_registry_supports(
                &agent,
                x0x::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1,
            ) {
                Some(true) => {
                    updates.push((
                        *recipient,
                        Some(RecipientDelivery::InFlight(
                            super::crypto_exclusion::next_attempt(),
                        )),
                    ));
                    spawn_send(state, key.clone(), agent, Arc::clone(&delivery.bytes));
                }
                Some(false) => updates.push((*recipient, Some(RecipientDelivery::Lacking))),
                None => {
                    updates.push((*recipient, Some(RecipientDelivery::Unknown)));
                    refresh_unknown(state, &[(*recipient, None)]);
                }
            }
        }
        let mut inner = state.revocation_evictions.inner.lock().await;
        if let Some(stored) = inner.rebind.deliveries.get_mut(&key) {
            for (recipient, update) in updates {
                match update {
                    Some(status) => {
                        stored.recipients.insert(recipient, status);
                    }
                    None => {
                        stored.recipients.remove(&recipient);
                    }
                }
            }
            if stored
                .recipients
                .values()
                .all(|status| *status == RecipientDelivery::Sent)
            {
                inner.rebind.deliveries.remove(&key);
            }
        }
    }
}

fn spawn_send(state: &Arc<AppState>, key: (String, String), agent: AgentId, bytes: Arc<Vec<u8>>) {
    let task_state = Arc::clone(state);
    let _spawned = state.spawn_detached(async move {
        let status = match task_state.agent.send_direct(&agent, bytes.to_vec()).await {
            Ok(_) => RecipientDelivery::Sent,
            Err(x0x::dm::DmError::RecipientUpgradeRequired { .. }) => RecipientDelivery::Lacking,
            Err(error) => {
                tracing::debug!(%error, "ADR 0110 S4: certificate rebind send failed; retrying");
                RecipientDelivery::Due
            }
        };
        let mut inner = task_state.revocation_evictions.inner.lock().await;
        if let Some(delivery) = inner.rebind.deliveries.get_mut(&key) {
            if let Some(entry) = delivery.recipients.get_mut(agent.as_bytes()) {
                *entry = status;
            }
        }
    });
}

// ─── Catch-up ──────────────────────────────────────────────────────────────

/// Serve the rebind frames this node holds for the group (any of
/// `group_ids`) above `from_revision` to a catch-up requester, on the
/// distinct gated carrier only. A requester without a current verified
/// advert setting `certificate_rebind_v1` gets nothing: the frame never
/// goes into a legacy-decoded catch-up page. Each write uses ADR 0107's
/// serving guard plus D60 under the membership lock, re-checked at the
/// seam immediately before the physical write.
pub(in crate::server) async fn serve_catchup(
    state: &Arc<AppState>,
    requester: &AgentId,
    group_ids: &[String],
    from_revision: u64,
) {
    let frames: Vec<(String, Arc<Vec<u8>>)> = {
        let inner = state.revocation_evictions.inner.lock().await;
        group_ids
            .iter()
            .find_map(|id| inner.rebind.log.get(id).map(|log| (id, log)))
            .map(|(id, log)| {
                log.iter()
                    .filter(|entry| entry.next_revision > from_revision)
                    .map(|entry| (id.clone(), Arc::clone(&entry.bytes)))
                    .collect()
            })
            .unwrap_or_default()
    };
    for (group_id, bytes) in frames {
        let admission = catchup_admission(state, &group_id, requester);
        let resolve_within = std::cmp::min(
            x0x::dm::PINNED_RESOLUTION_WAIT,
            CRB_CATCHUP_EXCHANGE_TIMEOUT / 2,
        );
        let exchange = state.agent.send_direct_pinned_admitted(
            requester,
            bytes.as_slice(),
            &admission,
            resolve_within,
        );
        match tokio::time::timeout(CRB_CATCHUP_EXCHANGE_TIMEOUT, exchange).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::debug!(%error, "ADR 0110 S4: certificate rebind catch-up send refused or failed");
                return;
            }
            Err(_) => {
                tracing::debug!(
                    "ADR 0110 S4: certificate rebind catch-up exchange deadline elapsed"
                );
                return;
            }
        }
    }
}

fn catchup_admission(
    state: &Arc<AppState>,
    group_id: &str,
    requester: &AgentId,
) -> x0x::dm::ArtifactAdmission {
    use super::super as ng;
    let state = Arc::clone(state);
    let group_id = group_id.to_string();
    let requester = *requester;
    Arc::new(move || {
        let state = Arc::clone(&state);
        let group_id = group_id.clone();
        Box::pin(async move {
            let requester_hex = hex::encode(requester.as_bytes());
            let lock = ng::group_membership_lock_for_known_group(&state, &group_id).await?;
            let evidence = {
                let _membership_guard = lock.lock().await;
                let evidence = ng::join_artifact_serving_check(&state, &group_id, &requester_hex)
                    .await
                    .ok()?;
                let supported = state.agent.capability_store().verified_registry_supports(
                    &requester,
                    x0x::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1,
                );
                if supported != Some(true) || !write_allowed(&state, &requester).await {
                    return None;
                }
                evidence
            };
            let seam: x0x::dm::SeamAdmission = Box::new(move || {
                ng::join_artifact_seam_refusal(&state, &group_id, &requester_hex, evidence)
                    .is_none()
            });
            Some(seam)
        })
    })
}

// ─── Receive (§4a "Receiver checks") ───────────────────────────────────────

/// The result of one receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum ReceiveOutcome {
    /// The rebind was verified and installed.
    Applied,
    /// This node already holds the result.
    Duplicate,
    /// This node is behind the frame's parent, or lacks the committed
    /// certificate bytes; the frame is stashed.
    Behind,
    /// The frame was refused.
    Refused(cr::CertificateRebindRefusal),
    /// A local persist fault; the frame is kept for retry.
    LocalFailure,
    /// The group is unknown here.
    NotApplicable,
}

impl ReceiveOutcome {
    fn is_retained(self) -> bool {
        matches!(self, Self::Behind | Self::LocalFailure)
    }
}

/// The direct-message listener hands every `X0XCRB1` payload here.
pub(in crate::server) fn spawn_receipt(
    state: &Arc<AppState>,
    sender: AgentId,
    verified: bool,
    payload: Vec<u8>,
) {
    if !verified {
        return;
    }
    let task_state = Arc::clone(state);
    let _spawned = state.spawn_detached(async move {
        let outcome = receive(&task_state, sender, &payload).await;
        if outcome.is_retained() {
            let mut inner = task_state.revocation_evictions.inner.lock().await;
            if inner.rebind.stash.len() >= CRB_STASH_CAP {
                inner.rebind.stash.remove(0);
            }
            inner.rebind.stash.push(StashedFrame {
                sender,
                bytes: payload,
                at: Instant::now(),
            });
        }
    });
}

async fn retry_stash(state: &Arc<AppState>) {
    let stash = std::mem::take(&mut state.revocation_evictions.inner.lock().await.rebind.stash);
    if stash.is_empty() {
        return;
    }
    let now = Instant::now();
    let mut keep = Vec::new();
    for frame in stash {
        if now.saturating_duration_since(frame.at) > CRB_STASH_TTL {
            continue;
        }
        if receive(state, frame.sender, &frame.bytes)
            .await
            .is_retained()
        {
            keep.push(frame);
        }
    }
    if !keep.is_empty() {
        let mut inner = state.revocation_evictions.inner.lock().await;
        keep.append(&mut inner.rebind.stash);
        let excess = keep.len().saturating_sub(CRB_STASH_CAP);
        keep.drain(..excess);
        inner.rebind.stash = keep;
    }
}

/// Verify and install one frame.
pub(in crate::server) async fn receive(
    state: &Arc<AppState>,
    sender: AgentId,
    payload: &[u8],
) -> ReceiveOutcome {
    use super::super as ng;
    let frame = match cr::decode_frame(payload) {
        Ok(frame) => frame,
        Err(refused) => return ReceiveOutcome::Refused(refused),
    };
    if let Err(refused) = cr::verify_signatures(&frame) {
        return ReceiveOutcome::Refused(refused);
    }
    let body = frame.body;
    let Some(group_key) = ng::resolve_named_group_storage_key(state, &body.stable_group_id).await
    else {
        return ReceiveOutcome::NotApplicable;
    };
    let membership_lock = ng::group_membership_lock(state, &group_key).await;
    let membership_guard = membership_lock.lock().await;
    let Some(info) = state.named_groups.read().await.get(&group_key).cloned() else {
        return ReceiveOutcome::NotApplicable;
    };
    // The frame is self-authenticating; a relaying sender must still be an
    // Active member of the group.
    if sender.as_bytes() != &body.signer && !info.has_active_member(&hex::encode(sender.as_bytes()))
    {
        return ReceiveOutcome::Refused(cr::CertificateRebindRefusal::SignerIneligible);
    }
    if info.state_hash == body.commit.state_hash {
        return ReceiveOutcome::Duplicate;
    }
    if info.state_hash != body.prior_head
        && info.state_revision.saturating_add(1) < body.next_revision
    {
        return ReceiveOutcome::Behind;
    }
    let now_unix = now_unix_ms() / 1000;
    let validated = {
        // Read the revocation set under the membership lock, immediately
        // before the apply (§3 L231).
        let revocation_set = state.agent.revocation_set();
        let set = revocation_set.read().await;
        if set.is_agent_revoked(&sender) {
            Err(cr::CertificateRebindRefusal::SignerIneligible)
        } else {
            cr::validate_against_parent(&body, &info, now_unix, |id| {
                set.is_agent_revoked(&AgentId(*id))
            })
        }
    };
    let commit = body.commit.to_commit();
    let (signer, certificate) = match validated {
        Ok(accepted) => accepted,
        Err(refused) => {
            match refused {
                cr::CertificateRebindRefusal::HeadMismatch => {
                    // A competing child of our head: the shared apply hook
                    // records the fork evidence it records for any commit.
                    let _ = ng::apply_stateful_event_with_evidence(
                        state,
                        &group_key,
                        &info,
                        &commit,
                        None,
                        false,
                        None,
                        x0x::groups::ActionKind::MemberSelf,
                        |_| {},
                    )
                    .await;
                }
                cr::CertificateRebindRefusal::CertificateEvidenceMissing => {
                    // §1a: fetch the committed bytes, keep the frame.
                    ng::warranted_fetch_for_pending_seats(state, &info, &[hex::encode(body.seat)]);
                    return ReceiveOutcome::Behind;
                }
                _ => {}
            }
            tracing::info!(
                group_id = %LogHexId::group(&group_key),
                reason = refused.as_str(),
                "ADR 0110 S4: certificate rebind refused"
            );
            return ReceiveOutcome::Refused(refused);
        }
    };
    let seat_hex = hex::encode(body.seat);
    let next = match ng::apply_stateful_event_with_evidence(
        state,
        &group_key,
        &info,
        &commit,
        None,
        false,
        None,
        signer.action_kind(),
        |next| cr::install_certificate(next, &seat_hex, certificate),
    )
    .await
    {
        Ok(next) => next,
        Err(error) => {
            tracing::info!(group_id = %LogHexId::group(&group_key), "ADR 0110 S4: certificate rebind commit refused: {error}");
            return ReceiveOutcome::Refused(cr::CertificateRebindRefusal::StateMismatch);
        }
    };
    match ng::persist_named_group_info(state, &group_key, next.clone()).await {
        Ok(ng::AtomicWriteOutcome::Durable | ng::AtomicWriteOutcome::ReplacedNotDurable) => {}
        Ok(ng::AtomicWriteOutcome::NotReplaced) | Err(_) => {
            return ReceiveOutcome::LocalFailure;
        }
    }
    ng::refresh_group_card_cache_from_info(state, &group_key, &next).await;
    {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner.rebind.remember(
            &body.stable_group_id,
            body.next_revision,
            Arc::new(payload.to_vec()),
        );
        let key = EvictionKey::new(body.stable_group_id.clone(), body.seat);
        inner.rebind.renewals.remove(&key);
        inner.rebind.admin_waits.remove(&key);
    }
    tracing::info!(
        group_id = %LogHexId::group(&group_key),
        seat = %LogHexId::agent(&seat_hex),
        "ADR 0110 S4: certificate rebind installed"
    );
    drop(membership_guard);
    // Later commits that queued behind this link can now chain.
    if next.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        ng::replay_pending_treekem_events(state, &group_key).await;
    }
    state.agent.s4_revocation_intake().request_reconcile();
    ReceiveOutcome::Applied
}

// ─── Status ────────────────────────────────────────────────────────────────

/// `certificate_rebind` on `GET /groups/:id`: the seat agent's
/// `waiting_for_admin_rebind` (naming the designated admin), §4b(2)
/// self-rebinds held by the D76 rule (`waiting_for_receiver_upgrade`,
/// naming the holders), and the seats for which this admin holds a
/// verified renewal.
pub(super) fn status_json(rebind: &RebindState, info: &GroupInfo) -> serde_json::Value {
    let stable = info.stable_group_id();
    let waits: Vec<serde_json::Value> = rebind
        .admin_waits
        .iter()
        .filter(|(key, _)| key.stable_group_id == stable)
        .map(|(key, wait)| {
            serde_json::json!({
                "cause": WAITING_FOR_ADMIN_REBIND,
                "agent_id": hex::encode(key.target),
                "designated_admin": wait.designated.map(hex::encode),
                "old_certificate_digest": wait.old_digest,
                "renewal_digest": wait.renewal_digest,
                "since_unix_ms": wait.since_unix_ms,
            })
        })
        .collect();
    let held: Vec<serde_json::Value> = rebind
        .held
        .iter()
        .filter(|(key, _)| key.stable_group_id == stable)
        .map(|(key, held)| {
            serde_json::json!({
                "cause": WaitingCause::WaitingForReceiverUpgrade.as_str(),
                "agent_id": hex::encode(key.target),
                "named": held.holders.iter().map(hex::encode).collect::<Vec<_>>(),
            })
        })
        .collect();
    let renewals: Vec<String> = rebind
        .renewals
        .keys()
        .filter(|key| key.stable_group_id == stable)
        .map(|key| hex::encode(key.target))
        .collect();
    serde_json::json!({
        "waiting_for_admin_rebind": waits,
        "held_self_rebinds": held,
        "held_renewals": renewals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catchup_log_is_bounded_and_deduplicated() {
        let mut rebind = RebindState::default();
        for revision in 0..(CRB_LOG_PER_GROUP as u64 + 4) {
            rebind.remember("g", revision, Arc::new(vec![1]));
            rebind.remember("g", revision, Arc::new(vec![2]));
        }
        assert_eq!(
            rebind.log.get("g").map(VecDeque::len),
            Some(CRB_LOG_PER_GROUP)
        );
    }

    #[test]
    fn retained_outcomes_are_behind_and_local_failure_only() {
        assert!(ReceiveOutcome::Behind.is_retained());
        assert!(ReceiveOutcome::LocalFailure.is_retained());
        assert!(!ReceiveOutcome::Applied.is_retained());
        assert!(!ReceiveOutcome::Duplicate.is_retained());
        assert!(!ReceiveOutcome::NotApplicable.is_retained());
        assert!(!ReceiveOutcome::Refused(cr::CertificateRebindRefusal::NotLater).is_retained());
    }

    #[test]
    fn status_names_the_designated_admin_and_holders() {
        let mut rebind = RebindState::default();
        let info = GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            AgentId([1; 32]),
            "ab".repeat(16),
        );
        let key = EvictionKey::new(info.stable_group_id(), [9; 32]);
        rebind.admin_waits.insert(
            key.clone(),
            AdminRebindWait {
                designated: Some([2; 32]),
                old_digest: "old".to_string(),
                renewal_digest: "new".to_string(),
                since_unix_ms: 5,
            },
        );
        let status = status_json(&rebind, &info);
        assert_eq!(
            status["waiting_for_admin_rebind"][0]["cause"],
            WAITING_FOR_ADMIN_REBIND
        );
        assert_eq!(
            status["waiting_for_admin_rebind"][0]["designated_admin"],
            hex::encode([2u8; 32])
        );
        assert_eq!(status["held_self_rebinds"], serde_json::json!([]));
    }
}
