//! ADR 0110 §4a and §4b(2): the daemon side of `CertificateRebindV1`, the
//! commit that binds a renewed certificate into an Active seat in place.
//!
//! - **Self-rebind route** ([`rebind_member_certificate`],
//!   `POST /groups/:id/members/:agent_id/certificate/rebind`). The seat's
//!   own agent rebinds its own certificate. Before the cutoff
//!   `not_after − τ` on its own clock it commits the rebind once this
//!   replica's head is synced (§2); until then it holds the rebind with
//!   `waiting_for_head_sync` and the worker commits it. After the
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
//!   machine and binding revocations just before it. A delivery that a
//!   restart restored waits for the §2 head sync first. **Catch-up**
//!   ([`serve_catchup`]) sends held frames to a capable requester on the
//!   same carrier.
//! - **Receive** ([`spawn_receipt`]) verifies the frame and the §4a L4
//!   rule, makes the frame durable in the held log ([`replay_log`]), and
//!   then installs it atomically. A verified rebind on the current
//!   chain ends that seat's expiry rows with cause `certificate_valid`
//!   (the S4 pass re-derives it from the roster).

use std::collections::{BTreeMap, BTreeSet, HashMap};
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

use super::crypto_exclusion::{
    all_converged, apply_round, ask_heads, finish_attempt, guarded_admission_for, head_rule_admits,
    next_attempt, note_converged, write_allowed, HeadRule, RecipientDelivery, RoundUpdate,
};
use super::frame_stash::{FrameStash, StashedFrame};

pub(super) mod replay_log;

/// A delivery round runs no more often than this per frame.
const CRB_RESEND_INTERVAL: Duration = Duration::from_secs(5);
/// A delivery is abandoned after this long; later catch-up serves it.
const CRB_DELIVERY_TTL: Duration = Duration::from_secs(600);
/// Frames held per group for catch-up serving.
const CRB_LOG_PER_GROUP: usize = 16;
/// Frames that arrived ahead of this node's head, waiting for it
/// ([`FrameStash`]).
const CRB_STASH_CAP: usize = 64;
/// The per-exchange bound of one frame write (live delivery and catch-up).
const CRB_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);

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
    /// A restart restored this delivery from the held log: each round
    /// waits for the group's §2 head sync first (#1508 review F3).
    resumed: bool,
}

/// The seat agent's `waiting_for_admin_rebind` (§4a, D155).
///
/// The wait keeps the renewed certificate itself, not only its digest: the
/// worker hands it to the eligible admins again each round
/// ([`drive_admin_waits`]) until a rebind or a removal of the seat lands
/// ([`prune_admin_waits`]). One hand-off write is not delivery: an admin
/// whose advert was unknown or stale, or a failed send, gets it on a
/// later round (#1533 Codex P2).
#[derive(Debug, Clone)]
struct AdminRebindWait {
    designated: Option<[u8; 32]>,
    old_digest: String,
    renewal_digest: String,
    since_unix_ms: u64,
    certificate: AgentCertificate,
    next_at: Instant,
}

/// A self-rebind the route accepted but did not commit yet: a §4b(2)
/// self-rebind held by the D76 rule (`holders` not empty), or a
/// self-rebind that waits for the §2 head sync (#1508 Codex P1 F3). The
/// worker re-checks the route's rules before it commits it.
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
    /// Frames held for catch-up; the authored and the received frames are
    /// durable ([`replay_log`]).
    log: replay_log::HeldLog<CRB_LOG_PER_GROUP, true>,
    stash: FrameStash<CRB_STASH_CAP>,
    /// Verified renewals an admin holds for a seat, from a hand-off.
    renewals: HashMap<EvictionKey, AgentCertificate>,
    /// Seat-agent side `waiting_for_admin_rebind`.
    admin_waits: HashMap<EvictionKey, AdminRebindWait>,
    /// Self-rebinds held by the §4b(2) D76 rule or for the §2 head sync.
    held: HashMap<EvictionKey, HeldSelfRebind>,
    /// Test builds only: each hand-off write started, by admin.
    #[cfg(test)]
    handoff_sends: Vec<[u8; 32]>,
    /// Test builds only: each `eviction_handoff_v1` advert refresh asked.
    #[cfg(test)]
    handoff_refreshes: Vec<[u8; 32]>,
}

impl RebindState {
    /// §2 and §3: the groups whose rebind work waits for
    /// [`super::group_head_synced`] and that may have no open row: a
    /// delivery a restart restored (#1508 review F3) and a held
    /// self-rebind (§4b(2) or the head sync). The worker pass keeps a head
    /// round for each, so the head sync can complete (#1508 Codex P1). No
    /// peer is excluded from the holders: the self-rebind target is this
    /// node.
    pub(super) fn head_round_groups(&self) -> BTreeMap<String, BTreeSet<[u8; 32]>> {
        self.deliveries
            .iter()
            .filter(|(_, delivery)| delivery.resumed)
            .map(|(key, _)| key.0.clone())
            .chain(self.held.keys().map(|key| key.stable_group_id.clone()))
            .map(|stable| (stable, BTreeSet::new()))
            .collect()
    }
}

impl RebindState {
    /// #1508 rc17 (Codex P1): whether a retained rebind frame of
    /// `stable_group_id` commits a revision above `revision`. #1508 rc18
    /// (Codex P1): only a frame that passed [`cr::check_ahead`] on this
    /// node's latest head, or every receiver check, counts, with no time
    /// limit ([`FrameStash`]).
    pub(super) fn stash_ahead(&self, stable_group_id: &str, revision: u64) -> bool {
        self.stash.ahead(stable_group_id, revision)
    }
}

fn held(inner: &mut super::S4Inner) -> &mut replay_log::HeldLog<CRB_LOG_PER_GROUP, true> {
    &mut inner.rebind.log
}

/// Load the durable rebind frames once, and deliver an authored frame
/// that is still its group's head again (#1508 review). A received frame
/// that a crash stopped before its install goes to the stash: the next
/// pass receives it again, with every receiver check.
async fn ensure_restored(state: &AppState) {
    let restored = replay_log::ensure_restored(state, replay_log::REBIND_EXTENSION, held).await;
    let local = *state.agent.agent_id().as_bytes();
    let mut inner = state.revocation_evictions.inner.lock().await;
    for bytes in restored.received {
        // The frame is self-authenticating; its signer is the sender. It
        // passed every receiver check before it was written.
        let Ok(frame) = cr::decode_frame(&bytes) else {
            continue;
        };
        let body = &frame.body;
        let _kept = inner.rebind.stash.push(StashedFrame::new(
            AgentId(body.signer),
            bytes.to_vec(),
            &body.stable_group_id,
            body.next_revision,
            true,
        ));
    }
    for resume in restored.resumes {
        let key = (resume.stable_group_id, resume.result_head.clone());
        inner
            .rebind
            .deliveries
            .entry(key)
            .or_insert_with(|| Delivery {
                bytes: resume.bytes,
                result_head: resume.result_head,
                recipients: other_active_members(&resume.info, &local)
                    .into_iter()
                    .map(|id| (id, RecipientDelivery::Due))
                    .collect(),
                next_at: Instant::now(),
                started: Instant::now(),
                resumed: true,
            });
    }
}

/// §2 and §3 "re-sync the head before any resend", for the rebind and
/// owner-recovery deliveries that a restart restored: the groups among
/// `groups` whose head is synced now. The gate is
/// [`super::group_head_synced`], the one gate that the removal and
/// crypto-exclusion resends use
/// ([`super::crypto_exclusion::resumed_groups_head_synced`]): the restart
/// minimum, a completed current catch-up round and no unresolved
/// higher-head or conflicting-head evidence. Call it with no S4 lock held.
pub(super) async fn restored_groups_head_synced(
    state: &AppState,
    groups: BTreeSet<String>,
) -> BTreeSet<String> {
    let mut synced = BTreeSet::new();
    for group in groups {
        if super::group_head_synced(state, &group).await {
            synced.insert(group);
        }
    }
    synced
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
            refresh_advert(
                state,
                *id,
                x0x::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1,
            );
        }
    }
}

/// Ask `id` for a fresh advert of the application capability `bit`.
fn refresh_advert(state: &Arc<AppState>, id: [u8; 32], bit: u64) {
    let task_state = Arc::clone(state);
    let _spawned = state.spawn_detached(async move {
        task_state
            .agent
            .refresh_application_capability(AgentId(id), bit)
            .await;
    });
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
    /// §2: this replica's head is not synced; nothing was sealed.
    HeadNotSynced,
    Refused(cr::CertificateRebindRefusal),
    Oversized,
    Persist(String),
}

/// Seal, check, persist and schedule delivery of one rebind. The caller
/// holds `group_key`'s membership lock and read `info` under it.
///
/// §2: every local rebind seal, the self-rebind route's, the admin's and
/// a held one's, passes [`super::group_head_synced`] here first, just
/// before the seal and under the membership lock. A replica with no
/// completed current catch-up round, or with unresolved higher-head
/// evidence, seals nothing ([`CommitError::HeadNotSynced`]); a stale
/// replica would otherwise make a sibling of a head it has not seen
/// (#1508 Codex P1 F3).
async fn commit_locked(
    state: &Arc<AppState>,
    group_key: &str,
    info: &GroupInfo,
    seat: [u8; 32],
    certificate: &AgentCertificate,
) -> Result<GroupInfo, CommitError> {
    use super::super as ng;
    if !super::group_head_synced(state, group_key).await {
        return Err(CommitError::HeadNotSynced);
    }
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
    // ADR 0109 §2 "Conflict" (#1533 Codex P1 2): the author's own commit
    // passes the one conflict gate too, before anything is persisted. A
    // recorded attestation conflict contains the group until a re-seat.
    if !ng::group_recovery::conflict_admits_commit(state, info, &frame.body.commit.to_commit())
        .await
    {
        return Err(CommitError::Refused(
            cr::CertificateRebindRefusal::GroupContained,
        ));
    }
    let bytes = cr::encode_frame(&frame)
        .map_err(|_| CommitError::Refused(cr::CertificateRebindRefusal::Malformed))?;
    if bytes.len() > x0x::dm::MAX_PAYLOAD_BYTES {
        return Err(CommitError::Oversized);
    }
    // #1508 review: the exact frame is durable before the local commit, so
    // a crash before the delivery cannot lose the chain link.
    let bytes = Arc::new(bytes);
    let stable = next.stable_group_id();
    ensure_restored(state).await;
    let at = (next.state_revision, next.state_hash.as_str());
    let ext = replay_log::REBIND_EXTENSION;
    if !replay_log::write_planned(state, ext, held, stable, at, &bytes).await {
        return Err(CommitError::Persist("frame not durable".to_string()));
    }
    let persisted = match ng::persist_named_group_info(state, group_key, next.clone()).await {
        Ok(ng::AtomicWriteOutcome::Durable) => Ok(()),
        Ok(ng::AtomicWriteOutcome::ReplacedNotDurable) => {
            // The replacement is visible on disk and in memory, so the
            // commit stands and its delivery is scheduled. The guarded
            // egress sends nothing until the re-save is durable (§5).
            tracing::warn!(group_id = %LogHexId::group(group_key), "ADR 0110 S4: certificate rebind persisted without a durability confirmation");
            Ok(())
        }
        Ok(ng::AtomicWriteOutcome::NotReplaced) => Err("not replaced".to_string()),
        Err(error) => Err(error.to_string()),
    };
    if let Err(error) = persisted {
        replay_log::rewrite_without(state, ext, held, stable, at).await;
        return Err(CommitError::Persist(error));
    }
    ng::refresh_group_card_cache_from_info(state, group_key, &next).await;
    let local = *state.agent.agent_id().as_bytes();
    {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner.rebind.log.remember(
            next.stable_group_id(),
            next.state_revision,
            &next.state_hash,
            Arc::clone(&bytes),
            true,
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
                resumed: false,
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
    if seat == local {
        adopt_own_renewal(state, certificate).await;
    }
    let task_state = Arc::clone(state);
    let card_key = group_key.to_string();
    let _spawned = state.spawn_detached(async move {
        ng::maybe_publish_group_card_after_state_change(&task_state, &card_key).await;
        drive_deliveries(&task_state).await;
    });
    Ok(next)
}

/// #1357 (ADR 0110 §4a run (6); Engineer call 24 Oct 2026, pending
/// ZCode's concurrence): a verified renewal of this daemon's OWN
/// certificate (the self-rebind route's body, or a committed rebind of its
/// own seat) becomes the certificate in use when it expires strictly later
/// ([`x0x::Agent::adopt_own_certificate_renewal`]), and the daemon
/// re-announces it. Otherwise the daemon keeps announcing the certificate
/// it loaded at startup; after that one expires, no peer's pinned send
/// reaches it, so the admin's post-cutoff rebind frame never arrives.
async fn adopt_own_renewal(state: &Arc<AppState>, certificate: &AgentCertificate) {
    match state.agent.adopt_own_certificate_renewal(certificate).await {
        Ok(x0x::CertificateRenewalAdoption::Adopted) => {
            let task_state = Arc::clone(state);
            let _spawned = state.spawn_detached(async move {
                if let Err(error) = task_state.agent.reannounce_identity_if_consented().await {
                    tracing::warn!("re-announce after certificate renewal failed: {error}");
                }
            });
        }
        Ok(x0x::CertificateRenewalAdoption::Refused(refused)) => {
            tracing::debug!(
                reason = refused.as_str(),
                "own certificate renewal not adopted"
            );
        }
        Err(error) => {
            tracing::warn!("own certificate renewal not persisted: {error}");
        }
    }
}

// ─── Self-rebind route (§4a, §4b(2)) ───────────────────────────────────────

/// The rule a self-rebind of `local`'s seat follows now. The route and the
/// worker's held self-rebinds use the same decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelfRebindRule {
    /// After the cutoff with an eligible admin left: hand the renewal to
    /// the admins (D155).
    HandOff,
    /// Before the cutoff: the D129 rule, every other Active member's
    /// current verified advert sets `certificate_rebind_v1`.
    Ordinary,
    /// §4b(2): no eligible admin exists because every admin's certificate
    /// expired. An admin's own self-rebind then runs after its cutoff,
    /// under the D76 hold rule.
    EveryAdminExpired,
}

/// Which [`SelfRebindRule`] applies to `local`'s `seat` on `info` at
/// `now_unix`. `old_not_after` is the seat's committed certificate's
/// `not_after`.
fn self_rebind_rule(
    info: &GroupInfo,
    local: &[u8; 32],
    seat: &x0x::groups::GroupMember,
    old_not_after: Option<u64>,
    now_unix: u64,
) -> SelfRebindRule {
    if cr::self_rebind_window_open(old_not_after, now_unix) {
        return SelfRebindRule::Ordinary;
    }
    let admins = admins_with_expiry(info);
    // #1533 Codex P2: past the cutoff is not expired. The exception needs
    // this admin's own certificate expired on this node's clock too (own
    // trigger, `not_after + τ`); before that it is still eligible and
    // hands the renewal off.
    let own_expired = old_not_after.is_some_and(|not_after| {
        x0x::groups::eviction::own_expiry_trigger_due(not_after, now_unix)
    });
    let every_admin_expired = seat.role.at_least(GroupRole::Admin)
        && own_expired
        && (admins.iter().all(|(id, _)| id == local)
            || cr::admins_needing_renewal(&admins, local, now_unix).is_some());
    if every_admin_expired {
        SelfRebindRule::EveryAdminExpired
    } else {
        SelfRebindRule::HandOff
    }
}

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
    // The renewal passed the receiver's owner-chain checks, so this daemon
    // uses it from now on, whatever happens to the seat commit below.
    adopt_own_renewal(&state, &certificate).await;
    let rule = self_rebind_rule(&info, &local, &seat, old_not_after, now_unix);
    let key = EvictionKey::new(stable.clone(), local);
    if rule == SelfRebindRule::HandOff {
        return hand_to_admins(&state, &info, &seat, &certificate, now_unix).await;
    }
    let others = other_active_members(&info, &local);
    let support = rebind_support(&state, &others);
    if rule == SelfRebindRule::EveryAdminExpired {
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
        Err(CommitError::HeadNotSynced) => {
            // §2: this replica may hold a stale head. Hold the rebind; the
            // worker keeps a head round for the group, re-checks these
            // rules and commits it once the head is synced.
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
                        holders: Vec::new(),
                    },
                );
            refusal(
                StatusCode::CONFLICT,
                WaitingCause::WaitingForHeadSync.as_str(),
                serde_json::json!({
                    "group_id": stable,
                    "state": WaitingCause::WaitingForHeadSync.as_str(),
                    "detail": "held: this replica's head is not synced yet (ADR 0110 §2); it commits when the head is synced",
                }),
            )
        }
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
    let handed_to = hand_off_renewal(state, info, &local, certificate, &admins).await;
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
                certificate: certificate.clone(),
                next_at: Instant::now() + CRB_RESEND_INTERVAL,
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

/// Hand `certificate`, the renewal of `seat`, to `admins` in an
/// `EvictionHandoffV1` on `info`'s current head. Returns the admins it was
/// sent to.
async fn hand_off_renewal(
    state: &Arc<AppState>,
    info: &GroupInfo,
    seat: &[u8; 32],
    certificate: &AgentCertificate,
    admins: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    let Some(bytes) = cr::encode_certificate(certificate) else {
        return Vec::new();
    };
    let handoff = s4::EvictionHandoffV1 {
        stable_group_id: info.stable_group_id().to_string(),
        target: *seat,
        observed_parent_head: info.state_hash.clone(),
        revocation_records: Vec::new(),
        self_leave_commit: None,
        expired_certificate: None,
        renewed_certificate: Some(bytes),
    };
    send_handoff(state, &handoff, admins).await
}

/// Send a hand-off to each admin whose current verified advert sets
/// `eviction_handoff_v1`, and ask each admin whose advert is unknown or
/// stale for a refresh (ADR 0093), so a later round can send to it.
/// Returns the admins it was sent to.
async fn send_handoff(
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
        match capabilities
            .verified_registry_supports(&agent, x0x::dm::CapabilityRegistry::EVICTION_HANDOFF_V1)
        {
            Some(true) => {}
            Some(false) => continue,
            None => {
                #[cfg(test)]
                state
                    .revocation_evictions
                    .inner
                    .lock()
                    .await
                    .rebind
                    .handoff_refreshes
                    .push(*admin);
                refresh_advert(
                    state,
                    *admin,
                    x0x::dm::CapabilityRegistry::EVICTION_HANDOFF_V1,
                );
                continue;
            }
        }
        #[cfg(test)]
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .rebind
            .handoff_sends
            .push(*admin);
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
/// member's current verified advert sets `certificate_rebind_v1`.
///
/// Returns whether the row was handled here: the rebind committed, or a
/// rebind is due but this replica's head is not synced (§2) or a local
/// write failed, so the row waits (`waiting_for_head_sync`,
/// `waiting_for_durable_intake`) and retries next tick rather than
/// evicting. On `false` the caller evicts.
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
    // The row may have completed or changed while this task waited.
    let still_pending = state
        .revocation_evictions
        .inner
        .lock()
        .await
        .store
        .get(key)
        .is_some_and(|row| row.phase == s4::Phase::Pending && row.expiry_only());
    if !still_pending {
        return false;
    }
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
    let mut usable = None;
    for certificate in candidates {
        if precheck_renewal(state, &info, &key.target, &certificate, now_unix)
            .await
            .is_ok()
        {
            usable = Some(certificate);
            break;
        }
    }
    let Some(certificate) = usable else {
        return false;
    };
    match commit_locked(state, group_key, &info, key.target, &certificate).await {
        // §2: `commit_locked` re-read the head and the evidence under the
        // membership lock just before the seal. The 13 s restart wait is
        // only a minimum: a current catch-up round with no unresolved
        // higher-head evidence is required. A rebind is due, so an
        // unsynced head waits; it never evicts instead.
        Err(CommitError::HeadNotSynced) => {
            wait_and_retry(state, key, WaitingCause::WaitingForHeadSync).await;
            true
        }
        // §4a (ZCode MAJOR 3, #1533 rc13): a local storage fault (the
        // `.crblog` frame or the group record was not written) is not a
        // reason to evict. The seat holds a verified renewal and every
        // member can take the rebind, so the row waits and retries next
        // tick. Only a refusal of the renewal itself evicts.
        Err(CommitError::Persist(error)) => {
            tracing::warn!(
                group_id = %LogHexId::group(group_key),
                target = %LogHexId::agent(&hex::encode(key.target)),
                %error,
                "ADR 0110 S4: admin certificate rebind not persisted; retrying, not evicting"
            );
            wait_and_retry(state, key, WaitingCause::WaitingForDurableIntake).await;
            true
        }
        Ok(_) => {
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .attempt_wait
                .remove(key);
            true
        }
        Err(error) => {
            tracing::warn!(
                group_id = %LogHexId::group(group_key),
                target = %LogHexId::agent(&hex::encode(key.target)),
                ?error,
                "ADR 0110 S4: admin certificate rebind failed; evicting"
            );
            false
        }
    }
}

/// A due admin rebind waits with `cause` and runs again next tick.
async fn wait_and_retry(state: &AppState, key: &EvictionKey, cause: WaitingCause) {
    let mut inner = state.revocation_evictions.inner.lock().await;
    inner
        .attempt_wait
        .insert(key.clone(), WaitingState::cause(cause));
    inner
        .next_attempt
        .insert(key.clone(), Instant::now() + super::S4_WORKER_TICK);
}

// ─── Worker ────────────────────────────────────────────────────────────────

/// One worker step: deliveries, stashed receipts, held self-rebinds and
/// the seat agent's admin waits.
pub(in crate::server) async fn drive(state: &Arc<AppState>) {
    ensure_restored(state).await;
    drive_deliveries(state).await;
    retry_stash(state).await;
    drive_held(state).await;
    prune_admin_waits(state).await;
    drive_admin_waits(state).await;
}

/// §4a (D155): hand each kept renewal to the seat's eligible admins again,
/// once per [`CRB_RESEND_INTERVAL`], on the current roster and head. The
/// wait ends only in [`prune_admin_waits`], when a rebind or a removal of
/// the seat lands, so neither an admin with an unknown or stale advert
/// nor a failed send loses the renewal (#1533 Codex P2).
async fn drive_admin_waits(state: &Arc<AppState>) {
    let now = Instant::now();
    let due: Vec<(EvictionKey, AgentCertificate)> = {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner
            .rebind
            .admin_waits
            .iter_mut()
            .filter(|(_, wait)| wait.next_at <= now)
            .map(|(key, wait)| {
                wait.next_at = now + CRB_RESEND_INTERVAL;
                (key.clone(), wait.certificate.clone())
            })
            .collect()
    };
    for (key, certificate) in due {
        let info = {
            let groups = state.named_groups.read().await;
            groups
                .values()
                .find(|info| info.stable_group_id() == key.stable_group_id && !info.withdrawn)
                .cloned()
        };
        let Some(info) = info else {
            continue;
        };
        let admins = eligible_admins(state, &info, &key.target).await;
        let _sent = hand_off_renewal(state, &info, &key.target, &certificate, &admins).await;
    }
}

/// Re-evaluate each held self-rebind with the route's rules
/// ([`self_rebind_rule`]) on the current roster and clock, and commit it
/// once no hold applies and the head is synced. §4b(2): no known Active
/// member's current verified advert lacks the capability. §4a: every
/// other Active member's advert sets it (D129), and the cutoff has not
/// passed; after it the renewal goes to the admins (D155).
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
        let active = info.as_ref().and_then(|info| {
            info.members_v2
                .get(&hex::encode(key.target))
                .filter(|member| !info.withdrawn && member.state == GroupMemberState::Active)
                .cloned()
                .map(|seat| (info, seat))
        });
        let Some((info, seat)) = active else {
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
        let now_unix = now_unix_ms() / 1000;
        let old_not_after = cr::committed_certificate(&seat).and_then(AgentCertificate::not_after);
        let support = rebind_support(state, &other_active_members(info, &key.target));
        let holders = match self_rebind_rule(info, &key.target, &seat, old_not_after, now_unix) {
            SelfRebindRule::EveryAdminExpired => {
                x0x::groups::crypto_exclusion::receiver_upgrade_holders(support)
            }
            SelfRebindRule::Ordinary
                if cr::rebind_allowed_for_members(support.iter().map(|(_, s)| *s)) =>
            {
                Vec::new()
            }
            rule => {
                // §4a: rebinding is off (D129), or the cutoff passed while
                // the rebind waited (D155). The route's outcome applies.
                state
                    .revocation_evictions
                    .inner
                    .lock()
                    .await
                    .rebind
                    .held
                    .remove(&key);
                if rule == SelfRebindRule::HandOff {
                    let _refusal =
                        hand_to_admins(state, info, &seat, &held.certificate, now_unix).await;
                } else {
                    refresh_unknown(state, &support);
                    tracing::info!(
                        group_id = %LogHexId::group(&held.group_key),
                        "ADR 0110 S4: held self-rebind dropped; an Active member's current verified advert does not set certificate_rebind_v1"
                    );
                }
                continue;
            }
        };
        let hold = !holders.is_empty();
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
        if hold {
            continue;
        }
        match commit_locked(state, &held.group_key, info, key.target, &held.certificate).await {
            Ok(_) => {}
            // §2: the held commit is a worker seal on a possibly old view;
            // it waits for a current catch-up round (re-read under the
            // lock in `commit_locked`).
            Err(CommitError::HeadNotSynced) => {}
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

/// Plan one delivery round from a snapshot of `recipients` (§4a "Egress").
///
/// `gate` gives each recipient's write inputs, read before the plan:
/// `None` when D60 withholds the write this round (agent, machine or
/// binding revocation), else its `certificate_rebind_v1` support. A
/// recipient no longer Active (`active`) is dropped. A `Converged` or
/// `InFlight` recipient is left alone. A `Sent` recipient is sent the
/// frame again: a write is not delivery (ADR 0110 §3), so it is retried
/// until the recipient's head shows it installed the rebind. Every planned
/// change names the status it read, so [`apply_round`] applies it only
/// while that status is still stored. Returns the updates and the recipients whose support is
/// unknown (an advert refresh is due).
fn plan_round(
    recipients: &BTreeMap<[u8; 32], RecipientDelivery>,
    active: &BTreeSet<[u8; 32]>,
    gate: impl Fn(&[u8; 32]) -> Option<Option<bool>>,
) -> (Vec<RoundUpdate>, Vec<[u8; 32]>) {
    let mut updates = Vec::new();
    let mut refreshes = Vec::new();
    for (recipient, status) in recipients {
        let observed = *status;
        if !active.contains(recipient) {
            updates.push(RoundUpdate {
                recipient: *recipient,
                observed,
                next: None,
            });
            continue;
        }
        if matches!(
            observed,
            RecipientDelivery::Converged | RecipientDelivery::InFlight(_)
        ) {
            continue;
        }
        let Some(support) = gate(recipient) else {
            continue;
        };
        let next = match support {
            Some(true) => RecipientDelivery::InFlight(next_attempt()),
            Some(false) => RecipientDelivery::Lacking,
            None => {
                refreshes.push(*recipient);
                RecipientDelivery::Unknown
            }
        };
        updates.push(RoundUpdate {
            recipient: *recipient,
            observed,
            next: Some(next),
        });
    }
    (updates, refreshes)
}

/// Install one round's plan into the stored delivery under the runtime
/// lock, and drop the delivery once every recipient converged (ADR 0110
/// §3: survivor convergence, not a write, proves delivery). Returns the
/// `(recipient, attempt)` sends to start, after the lock is released:
/// each one's `InFlight` status exists before its task runs.
fn install_round(
    rebind: &mut RebindState,
    key: &(String, String),
    updates: Vec<RoundUpdate>,
) -> Vec<([u8; 32], u64)> {
    let Some(delivery) = rebind.deliveries.get_mut(key) else {
        return Vec::new();
    };
    let started = apply_round(&mut delivery.recipients, updates);
    if all_converged(&delivery.recipients) {
        rebind.deliveries.remove(key);
    }
    started
}

/// §3 survivor convergence ([`super::crypto_exclusion::note_survivor_head`]):
/// `sender` holds each head in `installed`, so it converged in each rebind
/// delivery of `stable_group_id` whose result is one of them.
pub(super) fn note_survivor_head(
    rebind: &mut RebindState,
    stable_group_id: &str,
    sender: &[u8; 32],
    installed: &BTreeSet<String>,
) {
    for ((stable, result_head), delivery) in &mut rebind.deliveries {
        if stable == stable_group_id {
            note_converged(&mut delivery.recipients, result_head, sender, installed);
        }
    }
}

/// Record the result of send attempt `attempt` to `recipient`. Only that
/// attempt's own `InFlight` status is replaced.
fn complete_send(
    rebind: &mut RebindState,
    key: &(String, String),
    recipient: &[u8; 32],
    attempt: u64,
    status: RecipientDelivery,
) -> bool {
    rebind.deliveries.get_mut(key).is_some_and(|delivery| {
        finish_attempt(&mut delivery.recipients, recipient, attempt, status)
    })
}

/// One delivery round for every due frame: per recipient, re-check the
/// roster and the agent, machine and binding revocations, then send only to
/// a recipient whose current verified advert sets `certificate_rebind_v1`.
/// Each send runs the guarded admission again at the physical write.
///
/// Live delivery uses [`HeadRule::OnChain`], not the crypto exclusion's
/// current-head rule: the frame carries no key material (§4a), and a
/// recipient that missed it needs this link before any later commit on the
/// chain can apply.
async fn drive_deliveries(state: &Arc<AppState>) {
    let now = Instant::now();
    let restored: BTreeSet<String> = {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner.rebind.deliveries.retain(|_, delivery| {
            now.saturating_duration_since(delivery.started) < CRB_DELIVERY_TTL
        });
        inner
            .rebind
            .deliveries
            .iter()
            .filter(|(_, delivery)| delivery.resumed && delivery.next_at <= now)
            .map(|(key, _)| key.0.clone())
            .collect()
    };
    // #1508 review F3: a restored delivery waits for its group's real
    // head sync (ADR 0110 §3), not only for the local chain.
    let synced = restored_groups_head_synced(state, restored).await;
    let due: Vec<((String, String), Delivery)> = {
        let mut inner = state.revocation_evictions.inner.lock().await;
        let keys: Vec<(String, String)> = inner
            .rebind
            .deliveries
            .iter()
            .filter(|(key, delivery)| {
                delivery.next_at <= now && (!delivery.resumed || synced.contains(&key.0))
            })
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
        let rule = HeadRule::OnChain(delivery.result_head.clone());
        let Some(info) = info.filter(|info| head_rule_admits(info, &rule)) else {
            // Withdrawn, contained, or the frame left the verified chain.
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
        let mut gates: HashMap<[u8; 32], Option<Option<bool>>> = HashMap::new();
        let mut head_asks: Vec<AgentId> = Vec::new();
        for (recipient, status) in &delivery.recipients {
            if !active.contains(recipient)
                || matches!(
                    status,
                    RecipientDelivery::Converged | RecipientDelivery::InFlight(_)
                )
            {
                continue;
            }
            let agent = AgentId(*recipient);
            // §3: a written frame is not an installed one. Ask the
            // recipient for its head (its convergence evidence).
            if *status == RecipientDelivery::Sent {
                head_asks.push(agent);
            }
            let gate = if write_allowed(state, &agent).await {
                Some(capabilities.verified_registry_supports(
                    &agent,
                    x0x::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1,
                ))
            } else {
                None
            };
            gates.insert(*recipient, gate);
        }
        let (updates, refreshes) = plan_round(&delivery.recipients, &active, |recipient| {
            gates.get(recipient).copied().flatten()
        });
        // Install every status, `InFlight` included, BEFORE any send task
        // starts: a fast completion can then never be overwritten.
        let started = install_round(
            &mut state.revocation_evictions.inner.lock().await.rebind,
            &key,
            updates,
        );
        ask_heads(state, &key.0, head_asks);
        for (recipient, attempt) in started {
            spawn_send(
                state,
                key.clone(),
                AgentId(recipient),
                attempt,
                Arc::clone(&delivery.bytes),
            );
        }
        let refreshes: Vec<([u8; 32], Option<bool>)> =
            refreshes.into_iter().map(|id| (id, None)).collect();
        refresh_unknown(state, &refreshes);
    }
}

/// One live send. `key` is (stable group ID, result head). The write goes
/// through [`guarded_admission_for`] (ADR 0107 serving guard plus D60,
/// capability bit `certificate_rebind_v1`, [`HeadRule::OnChain`]), which
/// re-checks under the membership lock and again at the seam.
fn spawn_send(
    state: &Arc<AppState>,
    key: (String, String),
    agent: AgentId,
    attempt: u64,
    bytes: Arc<Vec<u8>>,
) {
    let task_state = Arc::clone(state);
    let _spawned = state.spawn_detached(async move {
        let admission = guarded_admission_for(
            &task_state,
            &key.0,
            &agent,
            HeadRule::OnChain(key.1.clone()),
            x0x::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1,
        );
        let resolve_within =
            std::cmp::min(x0x::dm::PINNED_RESOLUTION_WAIT, CRB_EXCHANGE_TIMEOUT / 2);
        let exchange = task_state.agent.send_direct_pinned_admitted(
            &agent,
            bytes.as_slice(),
            &admission,
            resolve_within,
        );
        let status = match tokio::time::timeout(CRB_EXCHANGE_TIMEOUT, exchange).await {
            Ok(Ok(_)) => RecipientDelivery::Sent,
            Ok(Err(x0x::dm::DmError::RecipientUpgradeRequired { .. })) => {
                RecipientDelivery::Lacking
            }
            Ok(Err(error)) => {
                // An admission refusal is a withhold: the next round
                // re-evaluates the recipient from the current state.
                tracing::debug!(%error, "ADR 0110 S4: certificate rebind send refused or failed; retrying");
                RecipientDelivery::Due
            }
            Err(_) => {
                tracing::debug!(
                    "ADR 0110 S4: certificate rebind exchange deadline elapsed; retrying"
                );
                RecipientDelivery::Due
            }
        };
        let mut inner = task_state.revocation_evictions.inner.lock().await;
        complete_send(&mut inner.rebind, &key, agent.as_bytes(), attempt, status);
    });
}

// ─── Catch-up ──────────────────────────────────────────────────────────────

/// Serve the rebind frames this node holds for the group (any of
/// `group_ids`) above `from_revision`, oldest first, to a catch-up
/// requester, on the distinct gated carrier only. A requester without a
/// current verified advert setting `certificate_rebind_v1` gets nothing:
/// the frame never goes into a legacy-decoded catch-up page. A competing
/// frame kept as fork evidence (#1579) is not on this node's verified
/// chain, so it is skipped, not served, and it does not stop the round.
/// A fork-quarantined group serves nothing on purpose: `head_rule_admits`
/// refuses every frame of it, so the skip leaves the round empty.
/// Each write uses [`guarded_admission_for`] with [`HeadRule::OnChain`]:
/// ADR 0107's serving guard plus D60 under the membership lock,
/// re-checked at the seam immediately before the physical write.
pub(in crate::server) async fn serve_catchup(
    state: &Arc<AppState>,
    requester: &AgentId,
    group_ids: &[String],
    from_revision: u64,
) {
    ensure_restored(state).await;
    let frames = state
        .revocation_evictions
        .inner
        .lock()
        .await
        .rebind
        .log
        .catchup_frames(group_ids, from_revision);
    // The frames all come from one group (`catchup_frames` serves the
    // first of `group_ids` that has a log).
    let info = {
        let groups = state.named_groups.read().await;
        frames.first().and_then(|(group, _, _)| {
            groups
                .values()
                .find(|info| info.stable_group_id() == group)
                .cloned()
        })
    };
    let Some(info) = info else {
        return;
    };
    for (group_id, result_head, bytes) in frames {
        // #1579: a competing frame kept as fork evidence is not on this
        // node's verified chain. It is never served, and it does not stop
        // the round for the frames that are.
        if !head_rule_admits(&info, &HeadRule::OnChain(result_head.clone())) {
            continue;
        }
        let admission = guarded_admission_for(
            state,
            &group_id,
            requester,
            HeadRule::OnChain(result_head),
            x0x::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1,
        );
        let resolve_within =
            std::cmp::min(x0x::dm::PINNED_RESOLUTION_WAIT, CRB_EXCHANGE_TIMEOUT / 2);
        let exchange = state.agent.send_direct_pinned_admitted(
            requester,
            bytes.as_slice(),
            &admission,
            resolve_within,
        );
        match tokio::time::timeout(CRB_EXCHANGE_TIMEOUT, exchange).await {
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

// ─── Receive (§4a "Receiver checks") ───────────────────────────────────────

/// The result of one receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum ReceiveOutcome {
    /// The rebind was verified and installed.
    Applied,
    /// This node already holds the result.
    Duplicate,
    /// This node is behind the frame's parent, or lacks the committed
    /// certificate bytes; the frame is stashed. `verified`: the frame
    /// passed every check this node can make on its latest head, so it is
    /// known higher-head evidence (#1508 rc18, [`FrameStash`]).
    Behind { verified: bool },
    /// The frame was refused.
    Refused(cr::CertificateRebindRefusal),
    /// A local persist fault; the frame is kept for retry.
    LocalFailure,
    /// The group is unknown here.
    NotApplicable,
}

impl ReceiveOutcome {
    fn is_retained(self) -> bool {
        matches!(self, Self::Behind { .. } | Self::LocalFailure)
    }

    /// A retained frame that is known higher-head evidence (§2): it passed
    /// [`cr::check_ahead`], or every receiver check before a local fault.
    fn head_evidence(self) -> bool {
        matches!(self, Self::Behind { verified: true } | Self::LocalFailure)
    }
}

/// The stash entry of a rebind frame, or `None` when it does not decode.
fn stashed(sender: AgentId, bytes: Vec<u8>, evidence: bool) -> Option<StashedFrame> {
    let body = cr::decode_frame(&bytes).ok()?.body;
    Some(StashedFrame::new(
        sender,
        bytes,
        &body.stable_group_id,
        body.next_revision,
        evidence,
    ))
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
            if let Some(frame) = stashed(sender, payload, outcome.head_evidence()) {
                let mut inner = task_state.revocation_evictions.inner.lock().await;
                let _kept = inner.rebind.stash.push(frame);
            }
        }
    });
}

/// Retry every stashed frame. #1508 rc18 (Codex P1): the frames stay in
/// the stash while the retry runs, so head evidence holds throughout, and
/// each retained frame's evidence state is checked again on the new head.
async fn retry_stash(state: &Arc<AppState>) {
    let frames = state
        .revocation_evictions
        .inner
        .lock()
        .await
        .rebind
        .stash
        .retry_set(Instant::now());
    if frames.is_empty() {
        return;
    }
    let mut results = Vec::with_capacity(frames.len());
    for frame in frames {
        let outcome = receive(state, frame.sender, &frame.bytes).await;
        let kept = outcome.is_retained().then(|| outcome.head_evidence());
        results.push((frame, kept));
    }
    state
        .revocation_evictions
        .inner
        .lock()
        .await
        .rebind
        .stash
        .settle(results);
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
    let now_unix = now_unix_ms() / 1000;
    if info.state_hash != body.prior_head
        && info.state_revision.saturating_add(1) < body.next_revision
    {
        // #1508 rc18 (Codex P1): a frame of a later revision is head
        // evidence only when its signer has standing on this node's latest
        // head and its certificate verifies. A forged future frame is kept
        // for a retry but holds nothing.
        let revocation_set = state.agent.revocation_set();
        let set = revocation_set.read().await;
        let verified = !set.is_agent_revoked(&sender)
            && cr::check_ahead(&body, &info, now_unix, |id| {
                set.is_agent_revoked(&AgentId(*id))
            })
            .is_ok();
        return ReceiveOutcome::Behind { verified };
    }
    // Set when the frame is a valid rebind on a sibling branch.
    let mut sibling = None;
    let validated = {
        // Read the revocation set under the membership lock, immediately
        // before the apply (§3 L231).
        let revocation_set = state.agent.revocation_set();
        let set = revocation_set.read().await;
        let is_revoked = |id: &[u8; 32]| set.is_agent_revoked(&AgentId(*id));
        if set.is_agent_revoked(&sender) {
            Err(cr::CertificateRebindRefusal::SignerIneligible)
        } else {
            match cr::validate_against_parent(&body, &info, now_unix, is_revoked) {
                // #1508 Codex P1 A: a frame that does not chain from this
                // node's head is checked against its retained parent
                // before it can be fork evidence. A frame that fails
                // there is refused with that reason and records nothing;
                // a frame whose parent is not retained stays unvalidated.
                Err(cr::CertificateRebindRefusal::HeadMismatch) => {
                    match cr::validate_sibling(&body, &info, now_unix, is_revoked) {
                        Ok(kind) => {
                            sibling = Some(kind);
                            Err(cr::CertificateRebindRefusal::HeadMismatch)
                        }
                        // #1533 r11: this node's branch no longer holds
                        // the parent's certificate bytes, so the sibling
                        // cannot be checked. It stays unvalidated and
                        // records nothing; a fetch of the current bytes
                        // would not supply the parent's.
                        Err(cr::CertificateRebindRefusal::CertificateEvidenceMissing) => {
                            Err(cr::CertificateRebindRefusal::HeadMismatch)
                        }
                        Err(refused) => Err(refused),
                    }
                }
                other => other,
            }
        }
    };
    let commit = body.commit.to_commit();
    let (signer, certificate) = match validated {
        Ok(accepted) => accepted,
        Err(refused) => {
            match refused {
                cr::CertificateRebindRefusal::HeadMismatch => {
                    if sibling.is_some() {
                        contain_sibling(state, &group_key, &info, &commit).await;
                    }
                    // §4a "Effect on S4 rows": a rebind that arrives after
                    // the seat's removal is refused with
                    // `rebind_seat_not_active`; the fork evidence above
                    // is kept either way.
                    if !info.has_active_member(&hex::encode(body.seat)) {
                        tracing::info!(
                            group_id = %LogHexId::group(&group_key),
                            reason = cr::CertificateRebindRefusal::SeatNotActive.as_str(),
                            "ADR 0110 S4: certificate rebind refused"
                        );
                        return ReceiveOutcome::Refused(
                            cr::CertificateRebindRefusal::SeatNotActive,
                        );
                    }
                }
                cr::CertificateRebindRefusal::CertificateEvidenceMissing => {
                    // §1a: fetch the committed bytes, keep the frame.
                    ng::warranted_fetch_for_pending_seats(state, &info, &[hex::encode(body.seat)]);
                    return ReceiveOutcome::Behind { verified: true };
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
    // ADR 0109 §2 "Conflict" (#1533 r6): the one conflict gate bounds
    // this commit as it bounds every metadata route.
    if !ng::group_recovery::conflict_admits_commit(state, &info, &commit).await {
        tracing::warn!(
            group_id = %LogHexId::group(&group_key),
            revision = commit.revision,
            "ADR 0109 S3: certificate rebind past the attestation conflict's common prefix refused"
        );
        return ReceiveOutcome::Refused(cr::CertificateRebindRefusal::GroupContained);
    }
    // #1508 review F2: the received frame is durable before the roster it
    // carries is installed, in the held log that the author uses. A
    // restarted receiver then serves it to a survivor that missed it while
    // the author is offline. The load runs first, so this write keeps the
    // frames that a restart restored.
    ensure_restored(state).await;
    let frame_bytes = Arc::new(payload.to_vec());
    let stable = body.stable_group_id.as_str();
    let at = (body.next_revision, body.commit.state_hash.as_str());
    let ext = replay_log::REBIND_EXTENSION;
    if !replay_log::write_received(state, ext, held, stable, at, &frame_bytes).await {
        return ReceiveOutcome::LocalFailure;
    }
    let seat_hex = hex::encode(body.seat);
    let own_renewal =
        (body.seat == *state.agent.agent_id().as_bytes()).then(|| certificate.clone());
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
            replay_log::rewrite_without(state, ext, held, stable, at).await;
            tracing::info!(group_id = %LogHexId::group(&group_key), "ADR 0110 S4: certificate rebind commit refused: {error}");
            return ReceiveOutcome::Refused(cr::CertificateRebindRefusal::StateMismatch);
        }
    };
    match ng::persist_named_group_info(state, &group_key, next.clone()).await {
        Ok(ng::AtomicWriteOutcome::Durable | ng::AtomicWriteOutcome::ReplacedNotDurable) => {}
        Ok(ng::AtomicWriteOutcome::NotReplaced) | Err(_) => {
            // A local fault: the frame stays durable and in the stash.
            return ReceiveOutcome::LocalFailure;
        }
    }
    ng::refresh_group_card_cache_from_info(state, &group_key, &next).await;
    {
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner.rebind.log.remember(
            &body.stable_group_id,
            body.next_revision,
            &body.commit.state_hash,
            frame_bytes,
            false,
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
    if let Some(renewal) = own_renewal {
        adopt_own_renewal(state, &renewal).await;
    }
    // Later commits that queued behind this link can now chain.
    if next.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
        ng::replay_pending_treekem_events(state, &group_key).await;
    }
    state.agent.s4_revocation_intake().request_reconcile();
    ReceiveOutcome::Applied
}

/// ADR 0110 §2 and §4a run (10) (#1508 Codex P1 B): a valid rebind on a
/// sibling branch of this node's chain (for example, a delayed self-rebind
/// on the parent of the seat's expiry removal) is fork evidence. It is
/// kept by [`install_sibling_evidence`]. The own branch's rebind
/// deliveries and held self-rebinds for the group stop. The caller has
/// checked the frame with [`cr::validate_sibling`].
async fn contain_sibling(
    state: &Arc<AppState>,
    group_key: &str,
    info: &GroupInfo,
    commit: &x0x::groups::state_commit::GroupStateCommit,
) {
    if install_sibling_evidence(state, group_key, info, commit).await {
        let stable = info.stable_group_id();
        let mut inner = state.revocation_evictions.inner.lock().await;
        inner
            .rebind
            .deliveries
            .retain(|(group, _), _| group != stable);
        inner
            .rebind
            .held
            .retain(|key, _| key.stable_group_id != stable);
    }
}

/// ADR 0110 §2 fork containment for a validated S4 sibling commit (a
/// certificate rebind or a crypto-only exclusion, #1508 r6): keep it with
/// the existing fork-quarantine marker, as for any authenticated
/// conflict, on every record. The shared fork hook skips an
/// `OwnerCertified` record without invite lineage, such as the creator's,
/// and it labels a self-rebind signer as unauthorized. The group is
/// contained (no seal, delivery or key serving), no node applies both
/// siblings, and ADR 0064's owner-anchored recovery resolves it. S4 adds
/// no fork choice. The sibling frame is not kept for serving. Returns
/// whether the marker was installed durably.
pub(super) async fn install_sibling_evidence(
    state: &Arc<AppState>,
    group_key: &str,
    info: &GroupInfo,
    commit: &x0x::groups::state_commit::GroupStateCommit,
) -> bool {
    use super::super as ng;
    let evidence = x0x::groups::ForkEvidence {
        revision: commit.revision,
        state_hash: commit.state_hash.clone(),
        committed_by: commit.committed_by.clone(),
        observed_at_ms: ng::now_millis_u64(),
    };
    // The signer is authenticated at the claimed parent, and the other
    // branch is not available to apply: ADR 0064 slice 4's `signer_only`.
    let quarantine = ng::fork_quarantine_for_evidence(
        info,
        &evidence,
        commit,
        Some(ng::FORK_EVIDENCE_CLASSIFICATION_SIGNER_ONLY),
    );
    let installed =
        ng::install_fork_evidence(state, group_key, evidence, quarantine, false, None).await;
    if installed {
        tracing::warn!(
            group_id = %LogHexId::group(group_key),
            revision = commit.revision,
            state_hash = %commit.state_hash,
            committed_by = %LogHexId::agent(&commit.committed_by),
            "ADR 0110 S4: sibling commit kept as fork evidence; the group is contained"
        );
    }
    installed
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
            let cause = if held.holders.is_empty() {
                WaitingCause::WaitingForHeadSync
            } else {
                WaitingCause::WaitingForReceiverUpgrade
            };
            serde_json::json!({
                "cause": cause.as_str(),
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

/// W3-H diagnostics: every live rebind delivery, and for each recipient
/// its status and each egress gate as this node sees it now.
#[cfg(test)]
pub(super) async fn delivery_report(state: &Arc<AppState>) -> String {
    use super::super as ng;
    let deliveries: Vec<((String, String), Delivery)> = state
        .revocation_evictions
        .inner
        .lock()
        .await
        .rebind
        .deliveries
        .iter()
        .map(|(key, delivery)| (key.clone(), delivery.clone()))
        .collect();
    let now = Instant::now();
    let durable = ng::roster_durable_for_publication(state).await;
    let mut out = format!("roster durable {durable}; {} deliveries", deliveries.len());
    for ((stable, head), delivery) in deliveries {
        let head_ok = {
            let groups = state.named_groups.read().await;
            groups
                .values()
                .find(|info| info.stable_group_id() == stable)
                .is_some_and(|info| head_rule_admits(info, &HeadRule::OnChain(head.clone())))
        };
        out.push_str(&format!(
            "; [{} head {} on chain {head_ok} age {:?} next in {:?} resumed {}:",
            LogHexId::group(&stable),
            &head[..head.len().min(12)],
            now.saturating_duration_since(delivery.started),
            delivery.next_at.saturating_duration_since(now),
            delivery.resumed
        ));
        for (recipient, status) in &delivery.recipients {
            let agent = AgentId(*recipient);
            let hex = hex::encode(recipient);
            let support = state.agent.capability_store().verified_registry_supports(
                &agent,
                x0x::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1,
            );
            let write = write_allowed(state, &agent).await;
            let member = ng::join_artifact_member_check(state, &stable, &hex)
                .await
                .map(|_| ());
            out.push_str(&format!(
                " {}={status:?} cap={support:?} write={write} member={member:?}",
                &hex[..8]
            ));
        }
        out.push(']');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catchup_log_is_bounded_and_deduplicated() {
        let mut rebind = RebindState::default();
        for revision in 0..(CRB_LOG_PER_GROUP as u64 + 4) {
            rebind
                .log
                .remember("g", revision, "h", Arc::new(vec![1]), false);
            rebind
                .log
                .remember("g", revision, "h", Arc::new(vec![2]), false);
        }
        assert_eq!(rebind.log.len("g"), Some(CRB_LOG_PER_GROUP));
    }

    /// Catch-up serves frames oldest first with their result heads, even
    /// when a later frame was remembered first (a stashed receipt).
    #[test]
    fn catchup_frames_are_served_oldest_first_with_their_heads() {
        let mut rebind = RebindState::default();
        rebind.log.remember("g", 7, "r7", Arc::new(vec![7]), false);
        rebind.log.remember("g", 5, "r5", Arc::new(vec![5]), false);
        rebind.log.remember("g", 6, "r6", Arc::new(vec![6]), false);
        let frames = rebind
            .log
            .catchup_frames(&["other".to_string(), "g".to_string()], 5);
        let heads: Vec<(String, String)> = frames
            .iter()
            .map(|(group, head, _)| (group.clone(), head.clone()))
            .collect();
        assert_eq!(
            heads,
            vec![
                ("g".to_string(), "r6".to_string()),
                ("g".to_string(), "r7".to_string())
            ]
        );
    }

    /// #1508 review (Codex P1 #3): the author writes the rebind frame
    /// before its local commit and dies before any delivery. The restart
    /// serves the exact bytes at catch-up and resumes the delivery.
    #[tokio::test]
    async fn a_crash_after_the_rebind_commit_keeps_the_exact_frame() {
        let (local, survivor) = (AgentId([1; 32]), [2u8; 32]);
        let (stable, groups) = replay_log::tests::committed_group(local, survivor);
        let frame = Arc::new(b"X0XCRB1\0exact frame bytes".to_vec());
        let resumes = replay_log::tests::crash_and_restart::<CRB_LOG_PER_GROUP>(
            replay_log::REBIND_EXTENSION,
            &stable,
            &groups,
            &frame,
        )
        .await;
        assert_eq!(resumes.len(), 1, "the restart resumes the delivery");
        assert_eq!(resumes[0].bytes.as_slice(), frame.as_slice());
        assert_eq!(
            other_active_members(&resumes[0].info, local.as_bytes()),
            [survivor]
        );
    }

    fn delivery_to(recipients: &[([u8; 32], RecipientDelivery)]) -> Delivery {
        Delivery {
            bytes: Arc::new(vec![1]),
            result_head: "r".to_string(),
            recipients: recipients.iter().copied().collect(),
            next_at: Instant::now(),
            started: Instant::now(),
            resumed: false,
        }
    }

    /// #1357 review P2 (#1508): the old round spawned the send and wrote
    /// `InFlight` after it, unconditionally. A send that finished first had
    /// its `Sent` overwritten by `InFlight`, and the recipient was never
    /// retried or completed. Now the round installs `InFlight(token)` from
    /// the observed status before any send starts, and only that token's
    /// completion writes.
    #[test]
    fn a_fast_rebind_completion_is_never_overwritten_by_in_flight() {
        let survivor = [5; 32];
        let key = ("g".to_string(), "r".to_string());
        let mut rebind = RebindState::default();
        rebind.deliveries.insert(
            key.clone(),
            delivery_to(&[(survivor, RecipientDelivery::Due)]),
        );
        let active = BTreeSet::from([survivor]);
        let snapshot = rebind.deliveries[&key].recipients.clone();
        let (updates, refreshes) = plan_round(&snapshot, &active, |_| Some(Some(true)));
        assert!(refreshes.is_empty());
        let stale_plan = updates.clone();
        let started = install_round(&mut rebind, &key, updates);
        let [(recipient, attempt)] = started.as_slice() else {
            panic!("exactly one send starts: {started:?}");
        };
        assert_eq!(*recipient, survivor);
        assert_eq!(
            rebind.deliveries[&key].recipients.get(&survivor),
            Some(&RecipientDelivery::InFlight(*attempt)),
            "InFlight is installed before the send runs"
        );
        // The send completes at once.
        assert!(complete_send(
            &mut rebind,
            &key,
            &survivor,
            *attempt,
            RecipientDelivery::Sent
        ));
        // A late write of a plan made from the old `Due` snapshot changes
        // nothing, and starts no second send.
        let late = install_round(&mut rebind, &key, stale_plan);
        assert!(late.is_empty());
        assert_eq!(
            rebind.deliveries[&key].recipients.get(&survivor),
            Some(&RecipientDelivery::Sent)
        );
        // A stale attempt's completion never writes.
        assert!(!complete_send(
            &mut rebind,
            &key,
            &survivor,
            *attempt,
            RecipientDelivery::Due
        ));
    }

    /// ADR 0110 §3 (#1508 review r8 P1): a successful write is `Sent`,
    /// not delivered. A recipient that took the frame but did not install
    /// the rebind keeps the delivery, and the next round sends the frame
    /// again. Only its head report that holds the result head ends it.
    #[test]
    fn a_written_rebind_without_install_keeps_retrying() {
        let survivor = [5; 32];
        let key = ("g".to_string(), "r".to_string());
        let mut rebind = RebindState::default();
        rebind.deliveries.insert(
            key.clone(),
            delivery_to(&[(survivor, RecipientDelivery::Due)]),
        );
        let active = BTreeSet::from([survivor]);
        let round = |rebind: &mut RebindState| {
            let snapshot = rebind.deliveries[&key].recipients.clone();
            let (updates, _) = plan_round(&snapshot, &active, |_| Some(Some(true)));
            install_round(rebind, &key, updates)
        };
        let &[(_, attempt)] = round(&mut rebind).as_slice() else {
            panic!("one send starts");
        };
        assert!(complete_send(
            &mut rebind,
            &key,
            &survivor,
            attempt,
            RecipientDelivery::Sent
        ));
        // The receiver crashed before it persisted the rebind: no install.
        let resend = round(&mut rebind);
        assert_eq!(
            resend.len(),
            1,
            "a write without an install is retried, not complete"
        );
        let &[(_, resent)] = resend.as_slice() else {
            panic!("one resend starts");
        };
        assert!(complete_send(
            &mut rebind,
            &key,
            &survivor,
            resent,
            RecipientDelivery::Sent
        ));
        // A head report of a later head on the chain through "r" is the
        // recipient's convergence evidence: the delivery ends.
        let installed = BTreeSet::from(["r".to_string(), "r2".to_string()]);
        note_survivor_head(&mut rebind, "g", &survivor, &installed);
        assert!(round(&mut rebind).is_empty());
        assert!(!rebind.deliveries.contains_key(&key));
    }

    /// A round drops recipients that left the roster, withholds a D60
    /// refusal without changing its status, leaves `InFlight` alone, and
    /// marks lacking and unknown support (refresh due).
    #[test]
    fn a_round_plans_from_the_gate_and_the_roster() {
        let (due, gone, withheld, lacking, unknown, busy) =
            ([1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]);
        let recipients: BTreeMap<[u8; 32], RecipientDelivery> = [
            (due, RecipientDelivery::Due),
            (gone, RecipientDelivery::InFlight(9)),
            (withheld, RecipientDelivery::Due),
            (lacking, RecipientDelivery::Unknown),
            (unknown, RecipientDelivery::Due),
            (busy, RecipientDelivery::InFlight(8)),
        ]
        .into_iter()
        .collect();
        let active = BTreeSet::from([due, withheld, lacking, unknown, busy]);
        let (updates, refreshes) = plan_round(&recipients, &active, |id| match *id {
            [3, ..] => None,
            [4, ..] => Some(Some(false)),
            [5, ..] => Some(None),
            _ => Some(Some(true)),
        });
        assert_eq!(refreshes, vec![unknown]);
        let next: BTreeMap<[u8; 32], Option<RecipientDelivery>> = updates
            .iter()
            .map(|update| (update.recipient, update.next))
            .collect();
        assert!(matches!(
            next.get(&due),
            Some(Some(RecipientDelivery::InFlight(_)))
        ));
        assert_eq!(next.get(&gone), Some(&None));
        assert_eq!(next.get(&withheld), None);
        assert_eq!(next.get(&lacking), Some(&Some(RecipientDelivery::Lacking)));
        assert_eq!(next.get(&unknown), Some(&Some(RecipientDelivery::Unknown)));
        assert_eq!(next.get(&busy), None);
    }

    #[test]
    fn retained_outcomes_are_behind_and_local_failure_only() {
        assert!(ReceiveOutcome::Behind { verified: false }.is_retained());
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
                certificate: AgentCertificate::issue_with_expiry(
                    &x0x::identity::UserKeypair::generate().expect("owner"),
                    &x0x::identity::AgentKeypair::generate().expect("agent"),
                    Some(10),
                )
                .expect("certificate"),
                next_at: Instant::now(),
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

/// Daemon-level tests (an in-process `AppState`; no network). They run in
/// CI under the isolated test runner.
#[cfg(test)]
mod daemon_tests {
    use super::super::super as ng;
    use super::*;
    use anyhow::Result;

    /// Install a verified advert. The store keeps an advert only when it is
    /// strictly newer than the held one, so each call passes a later
    /// `created_at_unix_ms`.
    fn advertise(state: &AppState, peer: AgentId, bits: u64, created_at_unix_ms: u64) {
        let mut capabilities = x0x::dm::DmCapabilities::v1_gossip_ready(vec![9; 16]);
        capabilities.application_registry = x0x::dm::CapabilityRegistry { version: 1, bits };
        assert!(
            state.agent.capability_store().insert(
                peer,
                x0x::identity::MachineId([4; 32]),
                capabilities,
                created_at_unix_ms,
            ),
            "verified capability advert"
        );
    }

    async fn admit(
        state: &Arc<AppState>,
        group_id: &str,
        recipient: &AgentId,
        rule: &HeadRule,
    ) -> Option<x0x::dm::SeamAdmission> {
        guarded_admission_for(
            state,
            group_id,
            recipient,
            rule.clone(),
            x0x::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1,
        )()
        .await
    }

    /// #1357 review P1 (#1508): rebind delivery and catch-up go through the
    /// guarded admission with capability bit 6, evaluated again at the
    /// write. A recipient that advertises only `crypto_exclusion_v1` is
    /// refused. A recipient that was eligible when the round scheduled it,
    /// then was removed or banned, or saw the frame leave the chain or the
    /// group quarantined, is refused by the seam (after a passing
    /// pre-phase) and by a fresh pre-phase.
    #[tokio::test]
    async fn rebind_egress_refuses_a_recipient_that_became_ineligible() -> Result<()> {
        let (state, _dir) = ng::tests::secure_endpoint_test_state().await?;
        let admin = state.agent.agent_id();
        let survivor = AgentId([0x77; 32]);
        let survivor_hex = hex::encode(survivor.as_bytes());
        let group_id = "cb".repeat(16);
        let mut info = GroupInfo::new("cb".into(), String::new(), admin, group_id.clone());
        info.add_member(
            survivor_hex.clone(),
            GroupRole::Member,
            Some(hex::encode(admin.as_bytes())),
            None,
        );
        info.recompute_state_hash();
        let stable = info.stable_group_id().to_string();
        let rule = HeadRule::OnChain(info.state_hash.clone());
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());

        // Bit 5 alone is not bit 6: no admission.
        let now_ms = x0x::dm_capability::now_unix_ms();
        advertise(
            &state,
            survivor,
            x0x::dm::CapabilityRegistry::CRYPTO_EXCLUSION_V1,
            now_ms.saturating_sub(1_000),
        );
        assert!(
            admit(&state, &stable, &survivor, &rule).await.is_none(),
            "a recipient without certificate_rebind_v1 is refused"
        );
        advertise(
            &state,
            survivor,
            x0x::dm::CapabilityRegistry::current().bits,
            now_ms,
        );
        let seam = admit(&state, &stable, &survivor, &rule).await;
        assert!(
            seam.is_some_and(|seam| seam()),
            "an eligible recipient is admitted"
        );

        type Change = fn(&mut GroupInfo, &str);
        let changes: [(&str, Change); 4] = [
            ("removed", |info, member| {
                info.remove_member(member, None);
            }),
            ("banned", |info, member| {
                info.ban_member(member, None);
            }),
            ("frame left the chain", |info, _| {
                // The state hash commits to `security_binding`, not to
                // `secret_epoch`, so move both.
                info.secret_epoch = info.secret_epoch.saturating_add(1);
                info.security_binding = Some(format!("treekem:epoch={}", info.secret_epoch));
                info.recompute_state_hash();
            }),
            ("quarantined", |info, _| {
                info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
                    revision: 1,
                    state_hash: "other".into(),
                    committed_by: String::new(),
                    observed_at_ms: 0,
                    snapshot: x0x::groups::ForkSnapshot {
                        terminal_commit: info.terminal_commit_header(),
                        conflicting_commit: info.terminal_commit_header(),
                        classification: None,
                    },
                    no_anchor: true,
                });
            }),
        ];
        for (label, change) in changes {
            let seam = admit(&state, &stable, &survivor, &rule)
                .await
                .unwrap_or_else(|| panic!("{label}: the pre-phase must admit first"));
            {
                let mut groups = state.named_groups.write().await;
                let stored = groups.get_mut(&group_id).expect("group");
                change(stored, &survivor_hex);
            }
            assert!(!seam(), "{label}: the seam must refuse the write");
            assert!(
                admit(&state, &stable, &survivor, &rule).await.is_none(),
                "{label}: a fresh pre-phase must refuse"
            );
            state
                .named_groups
                .write()
                .await
                .insert(group_id.clone(), info.clone());
        }
        Ok(())
    }
}

/// #1508 review (Codex P1 F2 and F3): a received frame survives a
/// restart of its receiver, and a restored delivery waits for the §2 head
/// sync. Offline daemons only (no network node), so the tests are inert.
#[cfg(test)]
pub(super) mod restart_tests {
    use super::super::super as ng;
    use super::super::{HeadRound, S4Runtime};
    use super::*;
    use anyhow::{Context, Result};
    use x0x::groups::eviction::S4Timing;
    use x0x::identity::{AgentKeypair, UserKeypair};

    /// An offline daemon (no network node) over `dir`. The agent key is
    /// kept in `dir`, so a second call is the same node after a restart.
    pub(in super::super) async fn offline_daemon(
        dir: &std::path::Path,
        user: Option<UserKeypair>,
    ) -> Result<Arc<AppState>> {
        let mut builder = x0x::Agent::builder()
            .with_machine_key(dir.join("machine.key"))
            .with_agent_key_path(dir.join("agent.key"))
            .with_agent_cert_path(dir.join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(dir.join("contacts.json"));
        if let Some(user) = user {
            builder = builder.with_user_key(user);
        }
        let agent = Arc::new(builder.build().await?);
        ng::tests::secure_endpoint_test_state_at(dir, agent).await
    }

    /// Hold `info` in memory and on disk, as a loaded group.
    pub(in super::super) async fn hold_persisted(state: &AppState, info: &GroupInfo) -> Result<()> {
        let key = info.stable_group_id().to_string();
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), info.clone());
        let outcome = ng::persist_named_group_info(state, &key, info.clone()).await?;
        anyhow::ensure!(
            matches!(outcome, ng::AtomicWriteOutcome::Durable),
            "the parent is durable"
        );
        Ok(())
    }

    /// The process "crashes" at the install: each group file path becomes
    /// a non-empty directory, so the group persist fails after the frame
    /// write. Returns a guard value for [`unblock_install`].
    pub(in super::super) async fn block_install(
        state: &AppState,
    ) -> Result<Vec<std::path::PathBuf>> {
        let mut blocked = Vec::new();
        for path in [&state.named_groups_path, &state.home_suite_groups_path] {
            if tokio::fs::metadata(path).await.is_ok() {
                tokio::fs::rename(path, path.with_extension("saved")).await?;
            }
            tokio::fs::create_dir_all(path).await?;
            tokio::fs::write(path.join("blocker"), b"x").await?;
            blocked.push(path.clone());
        }
        Ok(blocked)
    }

    /// Undo [`block_install`] after the "crashed" process stopped.
    pub(in super::super) async fn unblock_install(blocked: Vec<std::path::PathBuf>) -> Result<()> {
        for path in blocked {
            tokio::fs::remove_dir_all(&path).await?;
            let saved = path.with_extension("saved");
            if tokio::fs::metadata(&saved).await.is_ok() {
                tokio::fs::rename(&saved, &path).await?;
            }
        }
        Ok(())
    }

    /// A daemon whose restart sync wait has already elapsed, so only the
    /// per-group head sync can hold a resend.
    pub(in super::super) async fn state_past_restart_wait(
    ) -> Result<(Arc<AppState>, tempfile::TempDir)> {
        let (mut state, dir) = ng::tests::secure_endpoint_test_state().await?;
        Arc::get_mut(&mut state)
            .context("the fresh test state is not shared yet")?
            .revocation_evictions = S4Runtime::new(S4Timing {
            restart_sync_wait: Duration::ZERO,
            ..S4Timing::default()
        });
        Ok((state, dir))
    }

    /// The §2 head evidence that must hold a restored delivery.
    #[derive(Debug, Clone, Copy)]
    pub(in super::super) enum HeadEvidence {
        /// Epoch-ahead traffic that the catch-up still chases.
        Higher,
        /// A verified holder reported a different head.
        Conflicting,
    }

    /// Set (`on`) or clear one kind of head evidence for `info`. A head
    /// round for the current head that has run its course is in place
    /// before, so with no evidence the head is synced.
    pub(in super::super) async fn set_evidence(
        state: &AppState,
        group_key: &str,
        info: &GroupInfo,
        evidence: HeadEvidence,
        on: bool,
    ) {
        match evidence {
            HeadEvidence::Higher => {
                let mut targets = state.treekem_epoch_ahead_targets.lock().await;
                if on {
                    targets.insert(
                        group_key.to_string(),
                        ng::EpochAheadTarget {
                            epoch: info.secret_epoch.saturating_add(1),
                            observations: 0,
                        },
                    );
                } else {
                    targets.remove(group_key);
                }
            }
            HeadEvidence::Conflicting => {
                let mut inner = state.revocation_evictions.inner.lock().await;
                let round = inner
                    .head_rounds
                    .entry(info.stable_group_id().to_string())
                    .or_insert_with(|| HeadRound::new(&info.state_hash, Instant::now()));
                if on {
                    round.conflicting.insert([0xC0; 32]);
                } else {
                    round.conflicting.clear();
                }
            }
        }
    }

    /// One group with the local agent as its admin and `survivor` Active.
    pub(in super::super) async fn insert_group(
        state: &AppState,
        group_id: &str,
        survivor: &AgentId,
    ) -> GroupInfo {
        let admin = state.agent.agent_id();
        let mut info = GroupInfo::new("s4".into(), String::new(), admin, group_id.to_string());
        info.add_member(
            hex::encode(survivor.as_bytes()),
            GroupRole::Member,
            Some(hex::encode(admin.as_bytes())),
            None,
        );
        info.recompute_state_hash();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info.clone());
        info
    }

    /// An `OwnerCertified` group: `admin` is its admin, and `seat` and the
    /// receiver are certified Members. Each certificate expires in ten
    /// minutes. The frame rebinds `seat`'s certificate.
    struct RebindFixture {
        owner: UserKeypair,
        admin: AgentKeypair,
        seat: AgentKeypair,
        info: GroupInfo,
    }

    impl RebindFixture {
        fn new(receiver: &AgentKeypair) -> Result<Self> {
            let owner = UserKeypair::generate()?;
            let admin = AgentKeypair::generate()?;
            let seat = AgentKeypair::generate()?;
            let now = now_unix_ms() / 1000;
            let mut info = GroupInfo::new(
                "crb".to_string(),
                String::new(),
                admin.agent_id(),
                "c7".repeat(16),
            );
            info.policy.admission =
                x0x::groups::policy::GroupAdmission::OwnerCertified(owner.user_id());
            let admin_hex = hex::encode(admin.agent_id().as_bytes());
            for member in [&seat, receiver] {
                info.add_member(
                    hex::encode(member.agent_id().as_bytes()),
                    GroupRole::Member,
                    Some(admin_hex.clone()),
                    None,
                );
            }
            for member in [&admin, &seat, receiver] {
                let cert = AgentCertificate::issue_with_expiry(&owner, member, Some(now + 600))?;
                cr::install_certificate(
                    &mut info,
                    &hex::encode(member.agent_id().as_bytes()),
                    cert,
                );
            }
            info.recompute_state_hash();
            // The held state is a sealed parent, so its head is a retained
            // commit: a later frame that does not chain from this node's
            // head can be checked against it (#1579, the sibling rule).
            // The admin renews its own certificate once; every fixture
            // frame seals on that state.
            let renewal = AgentCertificate::issue_with_expiry(&owner, &admin, Some(now + 900))?;
            let (parent, _) = cr::seal(
                &info,
                *admin.agent_id().as_bytes(),
                &renewal,
                &admin,
                now_unix_ms(),
            )
            .map_err(|refused| anyhow::anyhow!("seal: {}", refused.as_str()))?;
            Ok(Self {
                owner,
                admin,
                seat,
                info: parent,
            })
        }

        /// The admin's signed rebind of the seat, and its result head.
        fn frame(&self) -> Result<(Vec<u8>, String)> {
            let now_ms = now_unix_ms();
            let renewal = AgentCertificate::issue_with_expiry(
                &self.owner,
                &self.seat,
                Some(now_ms / 1000 + 6000),
            )?;
            let seat = *self.seat.agent_id().as_bytes();
            let (next, frame) = cr::seal(&self.info, seat, &renewal, &self.admin, now_ms)
                .map_err(|refused| anyhow::anyhow!("seal: {}", refused.as_str()))?;
            let bytes = cr::encode_frame(&frame)?;
            Ok((bytes, next.state_hash))
        }

        /// A second, different rebind of the seat on the same parent: a
        /// competing commit at the same revision (#1579) — a different
        /// renewal, so a different roster root and result head.
        fn competing_frame(&self) -> Result<(Vec<u8>, String)> {
            let now_ms = now_unix_ms();
            let renewal = AgentCertificate::issue_with_expiry(
                &self.owner,
                &self.seat,
                Some(now_ms / 1000 + 7000),
            )?;
            let seat = *self.seat.agent_id().as_bytes();
            let (next, frame) = cr::seal(&self.info, seat, &renewal, &self.admin, now_ms)
                .map_err(|refused| anyhow::anyhow!("seal: {}", refused.as_str()))?;
            let bytes = cr::encode_frame(&frame)?;
            Ok((bytes, next.state_hash))
        }
    }

    async fn head_of(state: &AppState, stable: &str) -> Option<String> {
        state
            .named_groups
            .read()
            .await
            .get(stable)
            .map(|info| info.state_hash.clone())
    }

    async fn served(state: &AppState, stable: &str, from: u64) -> Vec<(String, Vec<u8>)> {
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .rebind
            .log
            .catchup_frames(std::slice::from_ref(&stable.to_string()), from)
            .into_iter()
            .map(|(_, head, bytes)| (head, bytes.to_vec()))
            .collect()
    }

    /// #1533 r6 (Codex P1 1), ADR 0109 §2 "Conflict": "Nothing past the
    /// common prefix applies" holds for an S4 rebind too. The receiver
    /// records an attestation conflict on its head (no fork marker), then
    /// a valid rebind on that head arrives: it is refused and the head
    /// does not move. Before the fix the rebind receiver applied the
    /// commit without the conflict gate. Inert.
    #[tokio::test]
    async fn a_recorded_attestation_conflict_refuses_a_valid_rebind() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let receiver = offline_daemon(dir.path(), None).await?;
        let fixture = RebindFixture::new(receiver.agent.identity().agent_keypair())?;
        let stable = fixture.info.stable_group_id().to_string();
        hold_persisted(&receiver, &fixture.info).await?;
        anyhow::ensure!(
            ng::group_recovery::record_conflict_at_head_for_test(&receiver, &fixture.info).await?,
            "the conflict is durable"
        );
        let (bytes, _result_head) = fixture.frame()?;
        let outcome = receive(&receiver, fixture.admin.agent_id(), &bytes).await;
        assert_eq!(
            outcome,
            ReceiveOutcome::Refused(cr::CertificateRebindRefusal::GroupContained)
        );
        assert_eq!(
            head_of(&receiver, &stable).await.as_ref(),
            Some(&fixture.info.state_hash),
            "nothing past the common prefix applies (rebind)"
        );
        Ok(())
    }

    /// F2 (a): a survivor installs a rebind, then restarts while the author
    /// is offline. The restarted survivor serves the exact frame to another
    /// survivor that asks for catch-up from the parent revision.
    #[tokio::test]
    async fn a_restarted_receiver_serves_the_received_rebind_frame() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let receiver = offline_daemon(dir.path(), None).await?;
        let fixture = RebindFixture::new(receiver.agent.identity().agent_keypair())?;
        let stable = fixture.info.stable_group_id().to_string();
        hold_persisted(&receiver, &fixture.info).await?;
        let (bytes, result_head) = fixture.frame()?;
        let outcome = receive(&receiver, fixture.admin.agent_id(), &bytes).await;
        assert_eq!(outcome, ReceiveOutcome::Applied);
        assert_eq!(
            head_of(&receiver, &stable).await.as_ref(),
            Some(&result_head)
        );

        // The receiver stops. The author is offline from here on.
        receiver.agent.shutdown().await;
        drop(receiver);
        let restarted = offline_daemon(dir.path(), None).await?;
        assert_eq!(
            head_of(&restarted, &stable).await.as_ref(),
            Some(&result_head),
            "the installed rebind survived the restart"
        );
        ensure_restored(&restarted).await;
        let frames = served(&restarted, &stable, fixture.info.state_revision).await;
        assert_eq!(
            frames,
            vec![(result_head, bytes)],
            "the restarted receiver serves the exact frame at catch-up"
        );
        restarted.agent.shutdown().await;
        Ok(())
    }

    /// F2 (b): the frame is durable before the roster it carries is
    /// installed. The install fails (a crash at that point), the frame is
    /// on disk, and after the restart the node installs it from its own
    /// copy and serves it, with the author offline.
    #[tokio::test]
    async fn a_crash_before_the_rebind_install_keeps_the_frame_durable() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let receiver = offline_daemon(dir.path(), None).await?;
        let fixture = RebindFixture::new(receiver.agent.identity().agent_keypair())?;
        let stable = fixture.info.stable_group_id().to_string();
        hold_persisted(&receiver, &fixture.info).await?;
        let (bytes, result_head) = fixture.frame()?;

        let blocked = block_install(&receiver).await?;
        let outcome = receive(&receiver, fixture.admin.agent_id(), &bytes).await;
        assert_eq!(outcome, ReceiveOutcome::LocalFailure, "the install failed");
        assert_eq!(
            head_of(&receiver, &stable).await.as_ref(),
            Some(&fixture.info.state_hash),
            "the roster is not installed"
        );
        let on_disk =
            replay_log::tests::frames_on_disk(&receiver, replay_log::REBIND_EXTENSION, &stable)
                .await;
        assert_eq!(on_disk.len(), 1, "the received frame is durable");
        assert_eq!(on_disk[0].frame, bytes, "exact bytes");
        assert_eq!(on_disk[0].result_head, result_head);
        assert!(!on_disk[0].authored);

        // The process dies before the install; the author stays offline.
        receiver.agent.shutdown().await;
        drop(receiver);
        unblock_install(blocked).await?;
        let restarted = offline_daemon(dir.path(), None).await?;
        assert_eq!(
            head_of(&restarted, &stable).await.as_ref(),
            Some(&fixture.info.state_hash)
        );
        ensure_restored(&restarted).await;
        retry_stash(&restarted).await;
        assert_eq!(
            head_of(&restarted, &stable).await.as_ref(),
            Some(&result_head),
            "the restarted node installs its durable copy"
        );
        let frames = served(&restarted, &stable, fixture.info.state_revision).await;
        assert_eq!(frames, vec![(result_head, bytes)]);
        restarted.agent.shutdown().await;
        Ok(())
    }

    /// #1579: a received frame at a revision the `.crblog` already holds
    /// — the crash window left it there, memory has not installed it — is
    /// written beside the held frame, never in its place, and both stay
    /// durable. After the restart one installs and the other, a valid
    /// sibling, contains the group as fork evidence.
    #[tokio::test]
    async fn a_competing_rebind_frame_is_kept_as_fork_evidence() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let receiver = offline_daemon(dir.path(), None).await?;
        let fixture = RebindFixture::new(receiver.agent.identity().agent_keypair())?;
        let stable = fixture.info.stable_group_id().to_string();
        hold_persisted(&receiver, &fixture.info).await?;
        let (bytes1, head1) = fixture.frame()?;
        let (bytes2, head2) = fixture.competing_frame()?;
        assert_ne!(head1, head2, "the fixture frames compete at one revision");

        // The installs fail after each frame write (a crash at that
        // point): the first frame stays in the file, and the second is
        // written beside it.
        let blocked = block_install(&receiver).await?;
        assert_eq!(
            receive(&receiver, fixture.admin.agent_id(), &bytes1).await,
            ReceiveOutcome::LocalFailure
        );
        assert_eq!(
            receive(&receiver, fixture.admin.agent_id(), &bytes2).await,
            ReceiveOutcome::LocalFailure
        );
        let on_disk =
            replay_log::tests::frames_on_disk(&receiver, replay_log::REBIND_EXTENSION, &stable)
                .await;
        assert_eq!(on_disk.len(), 2, "the competing frame is written");
        assert_eq!(
            (on_disk[0].result_head.as_str(), on_disk[0].frame.as_slice()),
            (head1.as_str(), bytes1.as_slice()),
            "the held frame is never replaced"
        );
        assert_eq!(
            (on_disk[1].result_head.as_str(), on_disk[1].frame.as_slice()),
            (head2.as_str(), bytes2.as_slice()),
            "the competing frame is kept"
        );

        // The process dies before either install. The restart re-receives
        // both: one installs, the other contains the group.
        receiver.agent.shutdown().await;
        drop(receiver);
        unblock_install(blocked).await?;
        let restarted = offline_daemon(dir.path(), None).await?;
        ensure_restored(&restarted).await;
        retry_stash(&restarted).await;
        let head = head_of(&restarted, &stable).await.context("the head")?;
        assert!(
            head == head1 || head == head2,
            "one of the competing pair installed: {head}"
        );
        assert!(
            quarantine_of(&restarted, &stable).await.is_some(),
            "the other frame contains the group as fork evidence"
        );
        let on_disk =
            replay_log::tests::frames_on_disk(&restarted, replay_log::REBIND_EXTENSION, &stable)
                .await;
        assert_eq!(on_disk.len(), 2, "both frames stay durable as evidence");
        restarted.agent.shutdown().await;
        Ok(())
    }

    /// F3 (c) and #1508 Codex P1: a rebind delivery restored after a
    /// restart, with no open row, waits for its group's §2 head sync, and
    /// the real worker pass gives it the head round that the sync needs.
    /// The process stops after the local commit (the authored frame is
    /// durable at the head) and restarts through the real load and restore
    /// path. The delivery is not resent while the group has higher-head or
    /// conflicting-head evidence. Once the survivor answers the catch-up
    /// with the local head ([`super::super::note_catchup_head`], the call
    /// of the response handler), the next worker step resends it.
    #[tokio::test]
    async fn a_restored_rebind_delivery_waits_for_the_head_sync() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let survivor = AgentId([0x5A; 32]);
        let survivor_hex = hex::encode(survivor.as_bytes());
        let group_id = "c8".repeat(16);
        let frame = Arc::new(b"X0XCRB1\0restored frame".to_vec());
        let info = {
            let author = offline_daemon(dir.path(), None).await?;
            let info = insert_group(&author, &group_id, &survivor).await;
            hold_persisted(&author, &info).await?;
            let at = (info.state_revision, info.state_hash.as_str());
            let ext = replay_log::REBIND_EXTENSION;
            let stable = info.stable_group_id();
            assert!(replay_log::write_planned(&author, ext, held, stable, at, &frame).await);
            author.agent.shutdown().await;
            info
        };
        // The restart: the same node over the same directory. Its restart
        // sync wait is zero, so only the per-group head sync holds.
        let mut state = offline_daemon(dir.path(), None).await?;
        Arc::get_mut(&mut state)
            .context("the restarted state is not shared yet")?
            .revocation_evictions = S4Runtime::new(S4Timing {
            restart_sync_wait: Duration::ZERO,
            ..S4Timing::default()
        });
        // The catch-up request records instead of sending.
        state
            .named_group_test_recorders
            .catchup_page_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let stable = info.stable_group_id().to_string();
        let key = (stable.clone(), info.state_hash.clone());
        // One worker iteration: the pass, then the rebind step.
        let worker_step = |state: &Arc<AppState>| {
            let state = Arc::clone(state);
            async move {
                super::super::revocation_eviction_pass(&state).await;
                drive(&state).await;
            }
        };
        set_evidence(&state, &group_id, &info, HeadEvidence::Higher, true).await;
        worker_step(&state).await;
        let scheduled = {
            let inner = state.revocation_evictions.inner.lock().await;
            inner
                .rebind
                .deliveries
                .get(&key)
                .context("the restart restored the delivery")?
                .next_at
        };
        let held_back = |state: &Arc<AppState>| {
            let state = Arc::clone(state);
            let key = key.clone();
            async move {
                let inner = state.revocation_evictions.inner.lock().await;
                let delivery = inner.rebind.deliveries.get(&key).cloned();
                delivery.is_some_and(|delivery| {
                    delivery.next_at == scheduled
                        && delivery.recipients.get(survivor.as_bytes())
                            == Some(&RecipientDelivery::Due)
                })
            }
        };
        let asked_survivor = |state: &Arc<AppState>| {
            let state = Arc::clone(state);
            let stable = stable.clone();
            async move {
                let inner = state.revocation_evictions.inner.lock().await;
                inner
                    .head_rounds
                    .get(&stable)
                    .is_some_and(|round| round.asked.contains(survivor.as_bytes()))
            }
        };
        // Higher-head evidence: the worker pass made a round and asked the
        // survivor, but the delivery waits.
        worker_step(&state).await;
        assert!(
            asked_survivor(&state).await,
            "the worker pass opened a head round for the restored delivery"
        );
        assert!(held_back(&state).await, "higher-head evidence holds it");
        set_evidence(&state, &group_id, &info, HeadEvidence::Higher, false).await;
        // The survivor answers with a head this node does not have.
        let unknown = "f0".repeat(32);
        super::super::note_catchup_head(
            &state,
            std::slice::from_ref(&group_id),
            &survivor_hex,
            Some(&unknown),
        )
        .await;
        worker_step(&state).await;
        worker_step(&state).await;
        assert!(
            held_back(&state).await,
            "a conflicting head report holds it"
        );
        assert!(
            asked_survivor(&state).await,
            "the retry asks the conflicting holder again"
        );
        // The survivor answers again with the local head: synced.
        super::super::note_catchup_head(
            &state,
            std::slice::from_ref(&group_id),
            &survivor_hex,
            Some(&info.state_hash),
        )
        .await;
        worker_step(&state).await;
        assert!(
            !held_back(&state).await,
            "the synced group's restored delivery ran"
        );
        state.agent.shutdown().await;
        Ok(())
    }

    /// An `OwnerCertified` group created by `admin`, with each of
    /// `members` a certified Member. Each certificate expires in ten
    /// minutes.
    fn certified_group(
        owner: &UserKeypair,
        admin: &AgentKeypair,
        members: &[&AgentKeypair],
    ) -> Result<GroupInfo> {
        let now = now_unix_ms() / 1000;
        let mut info = GroupInfo::new(
            "crb".to_string(),
            String::new(),
            admin.agent_id(),
            "c8".repeat(16),
        );
        info.policy.admission =
            x0x::groups::policy::GroupAdmission::OwnerCertified(owner.user_id());
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        for member in members {
            info.add_member(
                hex::encode(member.agent_id().as_bytes()),
                GroupRole::Member,
                Some(admin_hex.clone()),
                None,
            );
        }
        for member in std::iter::once(admin).chain(members.iter().copied()) {
            let cert = AgentCertificate::issue_with_expiry(owner, member, Some(now + 600))?;
            cr::install_certificate(&mut info, &hex::encode(member.agent_id().as_bytes()), cert);
        }
        info.recompute_state_hash();
        Ok(info)
    }

    /// ZCode MAJOR 3 (ADR 0110 §4a, #1533 rc13): the designated admin
    /// holds a verified renewal for an expiry-only seat and every member
    /// can take the rebind, but the local group write fails. The row must
    /// wait and retry, never evict the still-valid member; the next try
    /// commits the rebind. Before the fix any error but `HeadNotSynced`
    /// returned `false`, and the caller ran `commit_removal`.
    #[tokio::test]
    async fn an_admin_rebind_persist_failure_retries_and_never_evicts() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let owner = UserKeypair::generate()?;
        let seat = AgentKeypair::generate()?;
        let seat_id = seat.agent_id();
        let mut state = offline_daemon(dir.path(), None).await?;
        Arc::get_mut(&mut state)
            .context("the fresh state is not shared yet")?
            .revocation_evictions = S4Runtime::new(S4Timing {
            restart_sync_wait: Duration::ZERO,
            ..S4Timing::default()
        });
        let info = certified_group(&owner, state.agent.identity().agent_keypair(), &[&seat])?;
        hold_persisted(&state, &info).await?;
        let group_key = info.stable_group_id().to_string();
        let seat_hex = hex::encode(seat_id.as_bytes());
        let old_digest = info
            .members_v2
            .get(&seat_hex)
            .and_then(cr::committed_digest)
            .context("the seat's committed digest")?;
        // D129: the seat's current verified advert sets the bit.
        let mut capabilities = x0x::dm::DmCapabilities::v1_gossip_ready(vec![9; 16]);
        capabilities.application_registry = x0x::dm::CapabilityRegistry {
            version: 1,
            bits: x0x::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1,
        };
        assert!(state.agent.capability_store().insert(
            seat_id,
            x0x::identity::MachineId([4; 32]),
            capabilities,
            now_unix_ms(),
        ));
        let key = EvictionKey::new(group_key.clone(), *seat_id.as_bytes());
        let renewal =
            AgentCertificate::issue_with_expiry(&owner, &seat, Some(now_unix_ms() / 1000 + 6000))?;
        {
            let mut inner = state.revocation_evictions.inner.lock().await;
            inner.head_rounds.insert(
                group_key.clone(),
                HeadRound::new(&info.state_hash, Instant::now()),
            );
            inner.store.intake(
                &key,
                x0x::groups::eviction::EvictionTrigger::CertificateExpiry {
                    certificate_digest: old_digest.clone(),
                    not_after: now_unix_ms() / 1000,
                },
                None,
                now_unix_ms(),
                [0; 16],
            );
            inner.rebind.renewals.insert(key.clone(), renewal);
        }

        let blocked = block_install(&state).await?;
        assert!(
            try_admin_rebind(&state, &key, &group_key).await,
            "a local write failure is handled here; the caller must not evict"
        );
        {
            let inner = state.revocation_evictions.inner.lock().await;
            assert_eq!(
                inner.attempt_wait.get(&key).map(|wait| wait.cause),
                Some(WaitingCause::WaitingForDurableIntake)
            );
            assert!(inner.next_attempt.contains_key(&key), "retried next tick");
            assert!(
                inner.rebind.renewals.contains_key(&key),
                "the renewal is kept"
            );
        }
        unblock_install(blocked).await?;

        assert!(try_admin_rebind(&state, &key, &group_key).await);
        let rebound = state
            .named_groups
            .read()
            .await
            .get(&group_key)
            .cloned()
            .context("group")?;
        let member = rebound.members_v2.get(&seat_hex).context("the seat")?;
        assert_eq!(member.state, GroupMemberState::Active, "the seat stays");
        assert_ne!(
            cr::committed_digest(member),
            Some(old_digest),
            "the retry commits the rebind"
        );
        assert!(!state
            .revocation_evictions
            .inner
            .lock()
            .await
            .attempt_wait
            .contains_key(&key));
        state.agent.shutdown().await;
        Ok(())
    }

    /// #1508 rc17 (Codex P1): a valid admin-signed rebind at R+2 that
    /// waits for R+1 is known higher-head evidence. A round that confirmed
    /// the head at R must not let this node seal another S4 commit from it
    /// (a competing branch, ADR 0110 §2). Before the fix the stashed frame
    /// was not head evidence, so the head stayed synced.
    #[tokio::test]
    async fn a_stashed_future_rebind_unsyncs_a_confirmed_head() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut state = offline_daemon(dir.path(), None).await?;
        Arc::get_mut(&mut state)
            .context("the state is not shared yet")?
            .revocation_evictions = S4Runtime::new(S4Timing {
            restart_sync_wait: Duration::ZERO,
            ..S4Timing::default()
        });
        let owner = UserKeypair::generate()?;
        let admin = AgentKeypair::generate()?;
        let member = AgentKeypair::generate()?;
        let me = state.agent.identity().agent_keypair();
        let base = certified_group(&owner, &admin, &[&member, me])?;
        hold_persisted(&state, &base).await?;
        let stable = base.stable_group_id().to_string();
        // R+1: the admin renews its own certificate; this node misses it.
        let now_ms = now_unix_ms();
        let renewal =
            AgentCertificate::issue_with_expiry(&owner, &admin, Some(now_ms / 1000 + 900))?;
        let (parent, _) = cr::seal(
            &base,
            *admin.agent_id().as_bytes(),
            &renewal,
            &admin,
            now_ms,
        )
        .map_err(|refused| anyhow::anyhow!("seal: {}", refused.as_str()))?;
        // R+2: the admin rebinds the member's seat on R+1.
        let (frame, _) = sibling_frame(&parent, &owner, &member, &admin)?;
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .head_rounds
            .insert(
                stable.clone(),
                HeadRound {
                    head: base.state_hash.clone(),
                    started: Instant::now(),
                    asked: BTreeSet::new(),
                    confirmed: true,
                    conflicting: BTreeSet::new(),
                },
            );
        assert!(
            super::super::group_head_synced(&state, &stable).await,
            "no false hold"
        );
        assert_eq!(
            receive(&state, admin.agent_id(), &frame).await,
            ReceiveOutcome::Behind { verified: true }
        );
        // The worker keeps the frame, as `spawn_receipt` does.
        let stashed = stashed(admin.agent_id(), frame, true).context("decode")?;
        assert!(state
            .revocation_evictions
            .inner
            .lock()
            .await
            .rebind
            .stash
            .push(stashed));
        assert!(
            !super::super::group_head_synced(&state, &stable).await,
            "a stashed later-revision frame is unresolved head evidence"
        );
        state.agent.shutdown().await;
        Ok(())
    }

    /// #1508 rc18 (Codex P1): a self-signed future rebind from a sender
    /// with no standing on this node's head holds nothing. A stranger and
    /// an ordinary member each fabricate an R+1 roster that makes them an
    /// admin, and sign a rebind at R+2 on it. Before the fix each frame
    /// was kept as head evidence, and the confirmed head stopped being
    /// synced, which stops eviction and recovery.
    #[tokio::test]
    async fn a_forged_future_rebind_does_not_unsync_the_head() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut state = offline_daemon(dir.path(), None).await?;
        Arc::get_mut(&mut state)
            .context("the state is not shared yet")?
            .revocation_evictions = S4Runtime::new(S4Timing {
            restart_sync_wait: Duration::ZERO,
            ..S4Timing::default()
        });
        let owner = UserKeypair::generate()?;
        let admin = AgentKeypair::generate()?;
        let member = AgentKeypair::generate()?;
        let stranger = AgentKeypair::generate()?;
        let me = state.agent.identity().agent_keypair();
        let base = certified_group(&owner, &admin, &[&member, me])?;
        hold_persisted(&state, &base).await?;
        let stable = base.stable_group_id().to_string();
        let now_ms = now_unix_ms();
        let renewal =
            AgentCertificate::issue_with_expiry(&owner, &admin, Some(now_ms / 1000 + 900))?;
        let (parent, _) = cr::seal(
            &base,
            *admin.agent_id().as_bytes(),
            &renewal,
            &admin,
            now_ms,
        )
        .map_err(|refused| anyhow::anyhow!("seal: {}", refused.as_str()))?;
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .head_rounds
            .insert(
                stable.clone(),
                HeadRound {
                    head: base.state_hash.clone(),
                    started: Instant::now(),
                    asked: BTreeSet::new(),
                    confirmed: true,
                    conflicting: BTreeSet::new(),
                },
            );
        assert!(super::super::group_head_synced(&state, &stable).await);
        for (forger, seat) in [(&stranger, &member), (&member, &admin)] {
            let mut forged = parent.clone();
            forged.add_member(
                hex::encode(forger.agent_id().as_bytes()),
                GroupRole::Admin,
                None,
                None,
            );
            forged.set_member_role(&hex::encode(forger.agent_id().as_bytes()), GroupRole::Admin);
            let (frame, _) = sibling_frame(&forged, &owner, seat, forger)?;
            let outcome = receive(&state, forger.agent_id(), &frame).await;
            assert_eq!(outcome, ReceiveOutcome::Behind { verified: false });
            let stashed =
                stashed(forger.agent_id(), frame, outcome.head_evidence()).context("decode")?;
            assert!(state
                .revocation_evictions
                .inner
                .lock()
                .await
                .rebind
                .stash
                .push(stashed));
            assert!(
                super::super::group_head_synced(&state, &stable).await,
                "a forged future frame is not head evidence"
            );
        }
        state.agent.shutdown().await;
        Ok(())
    }

    /// ADR 0110 §4a run (10): the chain the receiver holds when a delayed
    /// self-rebind races the seat's expiry removal. The admin renews its
    /// own certificate (`parent`, retained), then seals the removal of
    /// `seat` on it (`head`). A rebind on `parent` is a sibling of the
    /// removal.
    fn removal_race(
        owner: &UserKeypair,
        base: &GroupInfo,
        admin: &AgentKeypair,
        seat: &AgentKeypair,
    ) -> Result<(GroupInfo, GroupInfo)> {
        let now_ms = now_unix_ms();
        let renewal = AgentCertificate::issue_with_expiry(owner, admin, Some(now_ms / 1000 + 900))?;
        let (parent, _) = cr::seal(base, *admin.agent_id().as_bytes(), &renewal, admin, now_ms)
            .map_err(|refused| anyhow::anyhow!("seal: {}", refused.as_str()))?;
        let mut head = parent.clone();
        head.remove_member(
            &hex::encode(seat.agent_id().as_bytes()),
            Some(hex::encode(admin.agent_id().as_bytes())),
        );
        head.seal_commit_evicting(admin, now_ms + 1)?;
        Ok((parent, head))
    }

    /// A rebind of `seat` on `parent`, signed by `signer`, carrying a
    /// certificate for `seat` issued by `issuer`. Returns the frame and its
    /// result head.
    fn sibling_frame(
        parent: &GroupInfo,
        issuer: &UserKeypair,
        seat: &AgentKeypair,
        signer: &AgentKeypair,
    ) -> Result<(Vec<u8>, String)> {
        let now_ms = now_unix_ms();
        let renewal =
            AgentCertificate::issue_with_expiry(issuer, seat, Some(now_ms / 1000 + 6000))?;
        let (next, frame) = cr::seal(
            parent,
            *seat.agent_id().as_bytes(),
            &renewal,
            signer,
            now_ms,
        )
        .map_err(|refused| anyhow::anyhow!("seal: {}", refused.as_str()))?;
        Ok((cr::encode_frame(&frame)?, next.state_hash))
    }

    async fn quarantine_of(state: &AppState, stable: &str) -> Option<x0x::groups::ForkQuarantine> {
        state
            .named_groups
            .read()
            .await
            .get(stable)
            .and_then(|info| info.fork_quarantine.clone())
    }

    /// #1508 Codex P1 A (ADR 0110 §4a "Receiver checks", ADR 0064 slice
    /// 4): a rebind that does not chain from this node's head is checked
    /// against its retained parent before anything is kept as fork
    /// evidence. An unrevoked ordinary member signs two fabricated
    /// siblings of the admin's removal: a self-rebind that carries a
    /// certificate from another user key, and a rebind of the admin's
    /// seat. Neither quarantines an invite-derived receiver; each is
    /// refused with its own typed reason. A valid sibling still does.
    #[tokio::test]
    async fn an_invalid_rebind_sibling_quarantines_no_receiver() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let receiver = offline_daemon(dir.path(), None).await?;
        let owner = UserKeypair::generate()?;
        let admin = AgentKeypair::generate()?;
        let member = AgentKeypair::generate()?;
        let me = receiver.agent.identity().agent_keypair();
        let base = certified_group(&owner, &admin, &[&member, me])?;
        let (parent, mut head) = removal_race(&owner, &base, &admin, &member)?;
        // This receiver joined through an invite.
        head.invite_lineage = Some(x0x::groups::InviteLineage {
            base_revision: base.state_revision,
            base_hash: base.state_hash.clone(),
            seated_at_revision: Some(base.state_revision),
            ..Default::default()
        });
        let stable = head.stable_group_id().to_string();
        hold_persisted(&receiver, &head).await?;

        let stranger = UserKeypair::generate()?;
        let (forged, _) = sibling_frame(&parent, &stranger, &member, &member)?;
        let outcome = receive(&receiver, member.agent_id(), &forged).await;
        assert_eq!(
            quarantine_of(&receiver, &stable).await,
            None,
            "a sibling with an invalid certificate is no fork evidence"
        );
        assert_eq!(
            outcome,
            ReceiveOutcome::Refused(cr::CertificateRebindRefusal::CertificateInvalid)
        );

        let (other_seat, _) = sibling_frame(&parent, &owner, &admin, &member)?;
        let outcome = receive(&receiver, member.agent_id(), &other_seat).await;
        assert_eq!(
            quarantine_of(&receiver, &stable).await,
            None,
            "a member's rebind of another seat is no fork evidence"
        );
        assert_eq!(
            outcome,
            ReceiveOutcome::Refused(cr::CertificateRebindRefusal::SignerIneligible)
        );
        let lineage = receiver
            .named_groups
            .read()
            .await
            .get(&stable)
            .and_then(|info| info.invite_lineage.clone());
        assert_eq!(lineage.and_then(|lineage| lineage.fork_evidence), None);

        // The control: the member's valid self-rebind on the same parent
        // is an authenticated sibling.
        let (valid, sibling_head) = sibling_frame(&parent, &owner, &member, &member)?;
        let outcome = receive(&receiver, member.agent_id(), &valid).await;
        assert_eq!(
            outcome,
            ReceiveOutcome::Refused(cr::CertificateRebindRefusal::SeatNotActive)
        );
        let marker = quarantine_of(&receiver, &stable)
            .await
            .context("the valid sibling contains the group")?;
        assert_eq!(marker.state_hash, sibling_head);
        receiver.agent.shutdown().await;
        Ok(())
    }

    /// #1508 Codex P1 B (ADR 0110 §4a run (10), §2 fork containment): the
    /// creator seals the seat's expiry removal; the seat's delayed valid
    /// self-rebind on the same parent then arrives. The creator's record
    /// has no invite lineage, and it is still contained: the fork evidence
    /// is durable across a restart, and the rebind is refused with
    /// `rebind_seat_not_active`.
    #[tokio::test]
    async fn a_valid_rebind_sibling_contains_the_creator() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let creator = offline_daemon(dir.path(), None).await?;
        let owner = UserKeypair::generate()?;
        let member = AgentKeypair::generate()?;
        let survivor = AgentKeypair::generate()?;
        let me = creator.agent.identity().agent_keypair();
        let base = certified_group(&owner, me, &[&member, &survivor])?;
        let (parent, head) = removal_race(&owner, &base, me, &member)?;
        assert!(head.invite_lineage.is_none(), "the creator has no lineage");
        let stable = head.stable_group_id().to_string();
        hold_persisted(&creator, &head).await?;

        let (valid, sibling_head) = sibling_frame(&parent, &owner, &member, &member)?;
        let outcome = receive(&creator, member.agent_id(), &valid).await;
        assert_eq!(
            outcome,
            ReceiveOutcome::Refused(cr::CertificateRebindRefusal::SeatNotActive)
        );
        let marker = quarantine_of(&creator, &stable)
            .await
            .context("the creator is contained")?;
        assert_eq!(marker.state_hash, sibling_head);
        assert_eq!(marker.revision, head.state_revision);
        assert_eq!(
            marker.snapshot.classification.as_deref(),
            Some(ng::FORK_EVIDENCE_CLASSIFICATION_SIGNER_ONLY)
        );
        assert_eq!(
            head_of(&creator, &stable).await.as_ref(),
            Some(&head.state_hash),
            "no node applies both siblings"
        );

        creator.agent.shutdown().await;
        drop(creator);
        let restarted = offline_daemon(dir.path(), None).await?;
        assert_eq!(
            quarantine_of(&restarted, &stable)
                .await
                .map(|marker| marker.state_hash),
            Some(sibling_head),
            "the containment survives a restart"
        );
        restarted.agent.shutdown().await;
        Ok(())
    }

    /// The self-rebind route (§4a) with this node's own renewal.
    async fn self_rebind(
        state: &Arc<AppState>,
        stable: &str,
        renewal: &AgentCertificate,
    ) -> Result<(StatusCode, serde_json::Value)> {
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let request = RebindCertificateRequest {
            certificate: Some(BASE64.encode(renewal.to_storage_bytes()?)),
        };
        let (status, Json(body)) = rebind_member_certificate(
            State(Arc::clone(state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path((stable.to_string(), local_hex)),
            Some(Json(request)),
        )
        .await;
        Ok((status, body))
    }

    /// #1508 Codex P1 F3 (ADR 0110 §2, §4a): the immediate self-rebind
    /// passes the same head-sync gate as the background rebinds. A
    /// restart restored a rebind delivery, so the worker keeps a head
    /// round for the group; the survivor then reports a head this node
    /// does not have (the catch-up response handler's call). This replica
    /// is stale: the route must not seal. It holds the rebind with
    /// `waiting_for_head_sync`, and the worker commits it once the
    /// survivor reports the local head.
    #[tokio::test]
    async fn a_self_rebind_waits_for_the_head_sync() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let owner = UserKeypair::generate()?;
        let survivor = AgentKeypair::generate()?;
        let survivor_id = survivor.agent_id();
        let survivor_hex = hex::encode(survivor_id.as_bytes());
        let frame = Arc::new(b"X0XCRB1\0restored frame".to_vec());
        let info = {
            let author = offline_daemon(dir.path(), None).await?;
            let me = author.agent.identity().agent_keypair();
            let info = certified_group(&owner, me, &[&survivor])?;
            hold_persisted(&author, &info).await?;
            let at = (info.state_revision, info.state_hash.as_str());
            let ext = replay_log::REBIND_EXTENSION;
            let stable = info.stable_group_id();
            assert!(replay_log::write_planned(&author, ext, held, stable, at, &frame).await);
            author.agent.shutdown().await;
            info
        };
        let stable = info.stable_group_id().to_string();
        let mut state = offline_daemon(dir.path(), None).await?;
        Arc::get_mut(&mut state)
            .context("the restarted state is not shared yet")?
            .revocation_evictions = S4Runtime::new(S4Timing {
            restart_sync_wait: Duration::ZERO,
            ..S4Timing::default()
        });
        state
            .named_group_test_recorders
            .catchup_page_force_ok
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // D129: the survivor's current verified advert sets the bit.
        let mut capabilities = x0x::dm::DmCapabilities::v1_gossip_ready(vec![9; 16]);
        capabilities.application_registry = x0x::dm::CapabilityRegistry {
            version: 1,
            bits: x0x::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1,
        };
        assert!(state.agent.capability_store().insert(
            survivor_id,
            x0x::identity::MachineId([4; 32]),
            capabilities,
            now_unix_ms(),
        ));
        let worker_step = |state: &Arc<AppState>| {
            let state = Arc::clone(state);
            async move {
                super::super::revocation_eviction_pass(&state).await;
                drive(&state).await;
            }
        };
        // The first step restores the delivery; the next pass opens the
        // group's head round and asks the survivor.
        worker_step(&state).await;
        worker_step(&state).await;
        assert!(
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .head_rounds
                .get(&stable)
                .is_some_and(|round| round.asked.contains(survivor_id.as_bytes())),
            "the worker pass opened a head round and asked the survivor"
        );
        // The survivor answers the catch-up with a head this node lacks.
        let unknown = "f0".repeat(32);
        super::super::note_catchup_head(
            &state,
            std::slice::from_ref(&stable),
            &survivor_hex,
            Some(&unknown),
        )
        .await;
        assert!(
            !super::super::group_head_synced(&state, &stable).await,
            "the replica holds unresolved higher-head evidence"
        );

        let me = state.agent.identity().agent_keypair();
        let renewal =
            AgentCertificate::issue_with_expiry(&owner, me, Some(now_unix_ms() / 1000 + 1200))?;
        let (status, body) = self_rebind(&state, &stable, &renewal).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"], WaitingCause::WaitingForHeadSync.as_str());
        assert_eq!(
            head_of(&state, &stable).await.as_ref(),
            Some(&info.state_hash),
            "a stale replica seals nothing"
        );
        worker_step(&state).await;
        assert_eq!(
            head_of(&state, &stable).await.as_ref(),
            Some(&info.state_hash),
            "the held self-rebind waits while the evidence is unresolved"
        );

        // The survivor reports the local head: synced, the rebind commits.
        super::super::note_catchup_head(
            &state,
            std::slice::from_ref(&stable),
            &survivor_hex,
            Some(&info.state_hash),
        )
        .await;
        worker_step(&state).await;
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let after = state
            .named_groups
            .read()
            .await
            .get(&stable)
            .cloned()
            .context("the group")?;
        assert_eq!(after.state_revision, info.state_revision + 1);
        assert_eq!(
            after.members_v2[&local_hex].certificate_digest.as_deref(),
            Some(x0x::groups::owner_cert::certificate_digest_hex(&renewal).as_str()),
            "the held self-rebind committed after the head sync"
        );
        state.agent.shutdown().await;
        Ok(())
    }

    /// #1533 Codex P1 2 (ADR 0109 §2 "Conflict"): a locally authored
    /// rebind passes the same conflict gate as a received one. This node
    /// holds a recorded attestation conflict on its head (no fork marker)
    /// and a synced head. The self-rebind route must refuse with
    /// `group_contained` and persist nothing: no head move and no
    /// planned frame. Before the fix `commit_locked` sealed and persisted
    /// the rebind past the common prefix. Inert.
    #[tokio::test]
    async fn a_recorded_attestation_conflict_refuses_a_local_self_rebind() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let owner = UserKeypair::generate()?;
        let survivor = AgentKeypair::generate()?;
        let survivor_id = survivor.agent_id();
        let mut state = offline_daemon(dir.path(), None).await?;
        Arc::get_mut(&mut state)
            .context("the fresh state is not shared yet")?
            .revocation_evictions = S4Runtime::new(S4Timing {
            restart_sync_wait: Duration::ZERO,
            ..S4Timing::default()
        });
        let me = state.agent.identity().agent_keypair();
        let info = certified_group(&owner, me, &[&survivor])?;
        hold_persisted(&state, &info).await?;
        let stable = info.stable_group_id().to_string();
        // D129: the survivor's current verified advert sets the bit.
        let mut capabilities = x0x::dm::DmCapabilities::v1_gossip_ready(vec![9; 16]);
        capabilities.application_registry = x0x::dm::CapabilityRegistry {
            version: 1,
            bits: x0x::dm::CapabilityRegistry::CERTIFICATE_REBIND_V1,
        };
        assert!(state.agent.capability_store().insert(
            survivor_id,
            x0x::identity::MachineId([4; 32]),
            capabilities,
            now_unix_ms(),
        ));
        set_evidence(&state, &stable, &info, HeadEvidence::Conflicting, false).await;
        assert!(
            super::super::group_head_synced(&state, &stable).await,
            "the head is synced, so only the conflict gate can refuse"
        );
        anyhow::ensure!(
            ng::group_recovery::record_conflict_at_head_for_test(&state, &info).await?,
            "the conflict is durable"
        );

        let me = state.agent.identity().agent_keypair();
        let renewal =
            AgentCertificate::issue_with_expiry(&owner, me, Some(now_unix_ms() / 1000 + 1200))?;
        let (status, body) = self_rebind(&state, &stable, &renewal).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(
            body["error"],
            cr::CertificateRebindRefusal::GroupContained.as_str()
        );
        assert_eq!(
            head_of(&state, &stable).await.as_ref(),
            Some(&info.state_hash),
            "nothing past the common prefix applies (local rebind)"
        );
        assert!(
            served(&state, &stable, info.state_revision)
                .await
                .is_empty(),
            "no rebind frame was planned"
        );
        state.agent.shutdown().await;
        Ok(())
    }

    /// #1533 Codex P2: a renewal handed to the admins after the cutoff is
    /// kept, with the certificate itself, while the seat agent shows
    /// `waiting_for_admin_rebind`. The admin's advert is unknown at the
    /// hand-off, so nothing is sent and a refresh is asked. Once the advert
    /// arrives the next worker round sends the hand-off, and a failed send
    /// (this daemon is offline) is sent again on the round after. Before
    /// the fix the hand-off was one write, skipped for that admin with no
    /// refresh, and only the digest was kept: the renewal was lost.
    #[tokio::test]
    async fn a_handed_off_renewal_is_kept_and_sent_again_until_an_admin_takes_it() -> Result<()> {
        use base64::Engine as _;
        use x0x::groups::policy::GroupAdmission;
        let dir = tempfile::tempdir()?;
        let state = offline_daemon(dir.path(), None).await?;
        let owner = UserKeypair::generate()?;
        let admin = AgentKeypair::generate()?;
        let now = now_unix_ms() / 1000;
        let local_kp = state.agent.identity().agent_keypair();
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let mut info = GroupInfo::new(
            "rebind".to_string(),
            "hand-off retry".to_string(),
            state.agent.agent_id(),
            "c7".repeat(16),
        );
        info.policy.admission = GroupAdmission::OwnerCertified(owner.user_id());
        // `not_after − τ` is past: the self-rebind window is closed.
        cr::install_certificate(
            &mut info,
            &local_hex,
            AgentCertificate::issue_with_expiry(&owner, local_kp, Some(now + 60))?,
        );
        let mut member = x0x::groups::GroupMember::new_member(
            admin_hex.clone(),
            None,
            Some(local_hex.clone()),
            1,
        );
        member.role = GroupRole::Admin;
        info.members_v2.insert(admin_hex.clone(), member);
        cr::install_certificate(
            &mut info,
            &admin_hex,
            AgentCertificate::issue_with_expiry(&owner, &admin, Some(now + 86_400))?,
        );
        info.recompute_state_hash();
        let group_key = info.mls_group_id.clone();
        let stable = info.stable_group_id().to_string();
        state
            .named_groups
            .write()
            .await
            .insert(group_key.clone(), info.clone());

        let renewal = AgentCertificate::issue_with_expiry(&owner, local_kp, Some(now + 86_400))?;
        let request: RebindCertificateRequest = serde_json::from_value(serde_json::json!({
            "certificate": base64::engine::general_purpose::STANDARD
                .encode(renewal.to_storage_bytes()?),
        }))?;
        let (status, Json(body)) = rebind_member_certificate(
            State(Arc::clone(&state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path((group_key.clone(), local_hex.clone())),
            Some(Json(request)),
        )
        .await;
        anyhow::ensure!(status == StatusCode::CONFLICT, "route: {body}");
        assert_eq!(body["error"], REBIND_WINDOW_CLOSED);

        let admin_id = *admin.agent_id().as_bytes();
        let key = EvictionKey::new(stable.clone(), *state.agent.agent_id().as_bytes());
        let renewal_digest = x0x::groups::owner_cert::certificate_digest_hex(&renewal);
        // Make the kept wait due now and run one worker round.
        let round = |state: &Arc<AppState>| {
            let state = Arc::clone(state);
            let key = key.clone();
            async move {
                if let Some(wait) = state
                    .revocation_evictions
                    .inner
                    .lock()
                    .await
                    .rebind
                    .admin_waits
                    .get_mut(&key)
                {
                    wait.next_at = Instant::now();
                }
                drive(&state).await;
            }
        };
        {
            let inner = state.revocation_evictions.inner.lock().await;
            assert!(
                inner.rebind.handoff_sends.is_empty(),
                "no hand-off to an admin whose advert is unknown"
            );
            assert_eq!(
                inner.rebind.handoff_refreshes,
                vec![admin_id],
                "the unknown advert is refreshed"
            );
            let wait = inner
                .rebind
                .admin_waits
                .get(&key)
                .context("the seat agent waits for the admin")?;
            assert_eq!(
                x0x::groups::owner_cert::certificate_digest_hex(&wait.certificate),
                renewal_digest,
                "the wait keeps the renewal itself"
            );
        }

        // The advert arrives: the next round sends the hand-off.
        let mut capabilities = x0x::dm::DmCapabilities::v1_gossip_ready(vec![9; 16]);
        capabilities.application_registry = x0x::dm::CapabilityRegistry {
            version: 1,
            bits: x0x::dm::CapabilityRegistry::current().bits,
        };
        assert!(state.agent.capability_store().insert(
            admin.agent_id(),
            x0x::identity::MachineId([4; 32]),
            capabilities,
            x0x::dm_capability::now_unix_ms(),
        ));
        round(&state).await;
        assert_eq!(
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .rebind
                .handoff_sends,
            vec![admin_id],
            "the refreshed admin gets the hand-off"
        );
        // That write failed (no network); the round after sends it again.
        round(&state).await;
        assert_eq!(
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .rebind
                .handoff_sends,
            vec![admin_id, admin_id],
            "a failed hand-off is sent again"
        );
        let status = status_json(&state.revocation_evictions.inner.lock().await.rebind, &info);
        assert_eq!(
            status["waiting_for_admin_rebind"][0]["renewal_digest"],
            renewal_digest
        );
        state.agent.shutdown().await;
        Ok(())
    }
}
