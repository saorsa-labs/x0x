//! PR #291 restart marker matrix: live/expired × durable clock {None, exact, other}.
//!
//! Tests the durable-request binding checks that commit 1545699 moved BEFORE the
//! live/expired split in `load_predecessor_relay_outbox`. Every mismatch
//! (requester, digest, clock, terminal-status, occupied-request binding) must
//! be fatal for BOTH live and expired markers, with the sidecar byte-preserved.
//!
//! Also covers: expired missing-request cleanup with durable clear + second
//! reload, unrelated-group obligation survival through expired-marker
//! fall-through, and signed re-offer through the extracted handler proving the
//! original clock is not refreshed.
//!
//! Mutation evidence (each test documents the mutation it reddens):
//! - MUT-BIND: move the binding-conflict check (:17727) back inside the
//!   live-only `if let Some(validated_obligation)` block → expired markers
//!   with mismatched bindings silently clear instead of erroring.
//! - MUT-TERMINAL: move the terminal-without-receipt check (:17751) back
//!   inside the live-only block → expired terminal markers silently clear.
//! - MUT-CLOCK-MIGRATION: remove the `:17205` clock-binding mismatch error.
//!   Alone this does NOT redden — `:17727` (binding conflict) independently
//!   catches the same clock-mismatch condition (defense-in-depth). Only when
//!   BOTH `:17205` and `:17727` are removed do the clock=other tests RED.
//! - MUT-CLEAR: move `pending_listener_admission = None` (:17819) inside
//!   the live-only block → expired markers are never cleared.
//! - MUT-REFRESH: force `first_seen_is_live = true` in the handler's
//!   AdmissionState classification (mod.rs:2226) → an expired durable request
//!   is re-admitted as Repair, minting a fresh obligation. The re-offer test
//!   fails (obligation count != 0).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_arguments,
    clippy::redundant_clone
)]

use super::*;
use crate::dm_inbox::DmTypedPayload;
use crate::groups::GroupInfo;
use crate::identity::MachineId;
use crate::server::handle_predecessor_relay_typed_payload;
use x0x::identity::AgentKeypair;

// ============================== Helpers ====================================

pub(super) fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(super) async fn s_state() -> (Arc<AppState>, tempfile::TempDir) {
    let (state, dir) = secure_endpoint_test_state().await.expect("secure state");
    (state, dir)
}

fn fresh_kp() -> AgentKeypair {
    AgentKeypair::generate().expect("agent keypair")
}

pub(super) fn local_hex(state: &AppState) -> String {
    hex::encode(state.agent.agent_id().as_bytes())
}

/// Drive the real `approve_join_request` handler and return the HTTP status.
/// Mirrors `adr0028_direct_controls.rs:369-382` so each row binds the
/// (group_key, request_id) of the obligation it creates (or, for the
/// expired sibling, refuses to create) to a concrete B8 outcome rather
/// than to obligation-existence prose.
async fn approve_status(state: &Arc<AppState>, group_key: &str, request_id: &str) -> StatusCode {
    let (status, _body) = response_json(
        approve_join_request(
            State(Arc::clone(state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path((group_key.to_string(), request_id.to_string())),
        )
        .await
        .into_response(),
    )
    .await
    .expect("response");
    status
}

/// Real requester-signed V2 pub/sub envelope (same construction as
/// `pubsub::encode_v2` using only public ML-DSA-65 primitives).
pub(super) fn sign_v2_envelope(
    kp: &AgentKeypair,
    topic: &str,
    event: &NamedGroupMetadataEvent,
) -> Vec<u8> {
    use ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa;

    let payload = serde_json::to_vec(event).expect("serialize event");
    let agent_id = kp.agent_id();
    let pub_bytes = kp.public_key().as_bytes();
    let mut signing = Vec::with_capacity(10 + 32 + topic.len() + payload.len());
    signing.extend_from_slice(b"x0x-msg-v2");
    signing.extend_from_slice(agent_id.as_bytes());
    signing.extend_from_slice(topic.as_bytes());
    signing.extend_from_slice(&payload);
    let sig = sign_with_ml_dsa(kp.secret_key(), &signing).expect("ml-dsa sign");
    let sig_bytes = sig.as_bytes();
    let topic_bytes = topic.as_bytes();
    let mut buf = Vec::with_capacity(
        1 + 32 + 2 + pub_bytes.len() + 2 + sig_bytes.len() + 2 + topic_bytes.len() + payload.len(),
    );
    buf.push(0x02u8);
    buf.extend_from_slice(agent_id.as_bytes());
    buf.extend_from_slice(&(pub_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(pub_bytes);
    buf.extend_from_slice(&(sig_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(sig_bytes);
    buf.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(topic_bytes);
    buf.extend_from_slice(&payload);
    buf
}

fn predecessor_event(
    group_key: &str,
    request_id: &str,
    requester_hex: &str,
    ts: u64,
) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::JoinRequestCreated {
        group_id: group_key.to_string(),
        request_id: request_id.to_string(),
        requester_agent_id: requester_hex.to_string(),
        message: None,
        ts,
        requester_kem_public_key_b64: None,
        treekem_key_package_b64: None,
        commit: None,
    }
}

#[derive(Clone)]
pub(super) struct RelayEntry {
    pub(super) envelope: Vec<u8>,
    pub(super) digest: [u8; 32],
    pub(super) request_id: String,
    pub(super) byte_size: usize,
}

pub(super) fn build_relay_entry(
    requester_kp: &AgentKeypair,
    topic: &str,
    group_key: &str,
    request_id: &str,
    requester_hex: &str,
    first_seen_ms: u64,
) -> RelayEntry {
    let event = predecessor_event(group_key, request_id, requester_hex, first_seen_ms);
    let envelope = sign_v2_envelope(requester_kp, topic, &event);
    let digest: [u8; 32] = blake3::hash(&envelope).into();
    RelayEntry {
        byte_size: envelope.len(),
        envelope,
        digest,
        request_id: request_id.to_string(),
    }
}
/// Same as `build_relay_entry` but with a `commit: Some(...)` on the
/// `JoinRequestCreated` event. The apply path (mod.rs:6799) rejects events
/// whose commit is `None`, so the handler-driven New row needs a commit to
/// exercise the apply code path. The other restart-driven fixtures short-
/// circuit before apply and keep `commit: None`.
pub(super) fn build_relay_entry_with_commit(
    requester_kp: &AgentKeypair,
    topic: &str,
    group_key: &str,
    request_id: &str,
    requester_hex: &str,
    first_seen_ms: u64,
    commit: x0x::groups::GroupStateCommit,
) -> RelayEntry {
    let event = NamedGroupMetadataEvent::JoinRequestCreated {
        group_id: group_key.to_string(),
        request_id: request_id.to_string(),
        requester_agent_id: requester_hex.to_string(),
        message: None,
        ts: first_seen_ms,
        requester_kem_public_key_b64: None,
        treekem_key_package_b64: None,
        commit: Some(commit),
    };
    let envelope = sign_v2_envelope(requester_kp, topic, &event);
    let digest: [u8; 32] = blake3::hash(&envelope).into();
    RelayEntry {
        byte_size: envelope.len(),
        envelope,
        digest,
        request_id: request_id.to_string(),
    }
}

pub(super) fn bound_join_request(
    entry: &RelayEntry,
    group_key: &str,
    requester_hex: &str,
    first_seen_ms: u64,
) -> x0x::groups::JoinRequest {
    x0x::groups::JoinRequest {
        request_id: entry.request_id.clone(),
        group_id: group_key.to_string(),
        requester_agent_id: requester_hex.to_string(),
        requester_user_id: None,
        requested_role: x0x::groups::GroupRole::Member,
        message: None,
        treekem_key_package_b64: None,
        created_at: first_seen_ms,
        reviewed_at: None,
        reviewed_by: None,
        status: x0x::groups::JoinRequestStatus::Pending,
        predecessor_envelope_digest: Some(entry.digest),
        predecessor_first_seen_ms: Some(first_seen_ms),
    }
}

/// Build a join request with a specific clock and status (for mismatch tests).
fn join_request_with(
    entry: &RelayEntry,
    group_key: &str,
    requester_hex: &str,
    first_seen_ms: Option<u64>,
    status: x0x::groups::JoinRequestStatus,
) -> x0x::groups::JoinRequest {
    x0x::groups::JoinRequest {
        request_id: entry.request_id.clone(),
        group_id: group_key.to_string(),
        requester_agent_id: requester_hex.to_string(),
        requester_user_id: None,
        requested_role: x0x::groups::GroupRole::Member,
        message: None,
        treekem_key_package_b64: None,
        created_at: first_seen_ms.unwrap_or(0),
        reviewed_at: None,
        reviewed_by: None,
        status,
        predecessor_envelope_digest: Some(entry.digest),
        predecessor_first_seen_ms: first_seen_ms,
    }
}

/// Install a group with the local agent as authority + witness_count witnesses.
async fn install_group(state: &AppState, group_key: &str, witness_count: usize) {
    let admin_id = state.agent.agent_id();
    let mut info = GroupInfo::with_policy(
        "pr291-restart".to_string(),
        String::new(),
        admin_id,
        group_key.to_string(),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    let lh = local_hex(state);
    for i in 1..=witness_count {
        let whex = format!("{:064x}", 0x2000u64 + i as u64);
        if whex != lh {
            info.add_member(whex, x0x::groups::GroupRole::Member, Some(lh.clone()), None);
        }
    }
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_key.to_string(), info);
}

/// Install a group with the local agent as authority + witness_count witnesses
/// under the given policy preset. The default `install_group` uses
/// `PrivateSecure` (InviteOnly), which the apply rejects for JoinRequestCreated
/// (mod.rs:6805). The handler-driven New row exercises the apply path, so it
/// installs a group with `PublicRequestSecure` admission.
pub(super) async fn install_group_with_policy(
    state: &AppState,
    group_key: &str,
    witness_count: usize,
    preset: x0x::groups::GroupPolicyPreset,
) {
    let admin_id = state.agent.agent_id();
    let mut info = GroupInfo::with_policy(
        "pr291-restart".to_string(),
        String::new(),
        admin_id,
        group_key.to_string(),
        preset.to_policy(),
    );
    let lh = local_hex(state);
    for i in 1..=witness_count {
        let whex = format!("{:064x}", 0x2000u64 + i as u64);
        if whex != lh {
            info.add_member(whex, x0x::groups::GroupRole::Member, Some(lh.clone()), None);
        }
    }
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_key.to_string(), info);
}
/// Build a properly-signed `GroupStateCommit` for a non-member
/// `JoinRequestCreated` event. The commit's `prev_state_hash` and revision
/// are taken from the group's current state; `state_hash` and the signature
/// are computed by the production `sign` path so the apply's
/// `verify_structure` (commit signature/state_hash) and `validate_apply`
/// (prev_state_hash chain, revision monotonicity, signer authority) all pass
/// against the pre-mutation group.
pub(super) fn signed_request_join_commit(
    group: &x0x::groups::GroupInfo,
    requester_kp: &AgentKeypair,
) -> x0x::groups::GroupStateCommit {
    let prev_state_hash = group.state_hash.clone();
    let new_revision = group.state_revision + 1;
    let roster_root = x0x::groups::state_commit::compute_roster_root(&group.members_v2);
    let policy_hash = x0x::groups::state_commit::compute_policy_hash(&group.policy);
    let public_meta_hash =
        x0x::groups::state_commit::compute_public_meta_hash(&group.public_meta());
    let security_binding = group.security_binding.clone();
    x0x::groups::GroupStateCommit::sign(
        group.stable_group_id().to_string(),
        new_revision,
        Some(prev_state_hash),
        roster_root,
        policy_hash,
        public_meta_hash,
        security_binding,
        false,
        new_revision,
        requester_kp,
    )
    .expect("sign JoinRequestCreated commit")
}

pub(super) async fn group_topic(state: &AppState, group_key: &str) -> String {
    state
        .named_groups
        .read()
        .await
        .get(group_key)
        .expect("group exists")
        .metadata_topic
        .clone()
}

async fn save_relay(state: &AppState) -> std::io::Result<AtomicWriteOutcome> {
    save_predecessor_relay_outbox(state).await
}

pub(super) async fn save_roster(state: &AppState) -> std::io::Result<AtomicWriteOutcome> {
    save_named_groups_checked(state).await
}

async fn relay_sidecar_bytes(state: &AppState) -> Vec<u8> {
    tokio::fs::read(&state.predecessor_relay_outbox_path)
        .await
        .expect("sidecar read")
}

async fn restart_relay(state: &Arc<AppState>) -> Result<(), String> {
    state.predecessor_relay_outbox.write().await.clear();
    state.completed_relay_tombstones.write().await.clear();
    *state.pending_b8_compensation.lock().await = None;
    *state.pending_listener_admission.lock().await = None;
    load_predecessor_relay_outbox(state).await
}

async fn relay_outbox_total(state: &AppState) -> usize {
    state
        .predecessor_relay_outbox
        .read()
        .await
        .values()
        .flatten()
        .count()
}

pub(super) async fn listener_admission_is_none(state: &AppState) -> bool {
    state.pending_listener_admission.lock().await.is_none()
}

/// Read obligations for a specific group (clone for inspection).
async fn relay_outbox_for_group(
    state: &AppState,
    group_key: &str,
) -> Vec<PredecessorRelayObligation> {
    state
        .predecessor_relay_outbox
        .read()
        .await
        .get(group_key)
        .cloned()
        .unwrap_or_default()
}

/// Count tombstones for a specific group.
async fn tombstone_count_for_group(state: &AppState, group_key: &str) -> usize {
    state
        .completed_relay_tombstones
        .read()
        .await
        .get(group_key)
        .map(|l| l.len())
        .unwrap_or(0)
}

/// Reload named_groups from disk through the production loader, proving
/// persisted state survives a process-style roster reload.
async fn reload_roster(state: &AppState) {
    let loaded = load_named_groups(&state.named_groups_path)
        .await
        .expect("roster load from disk");
    *state.named_groups.write().await = loaded;
}

/// Assert an exact obligation tuple exists for a group.
async fn assert_obligation_exists(
    state: &AppState,
    group_key: &str,
    request_id: &str,
    requester_hex: &str,
    digest: &[u8; 32],
    first_seen_ms: u64,
) {
    let obligations = relay_outbox_for_group(state, group_key).await;
    let found = obligations.iter().any(|o| {
        o.request_id == request_id
            && o.requester_agent_id == requester_hex
            && o.digest == *digest
            && o.first_seen_ms == first_seen_ms
    });
    assert!(
        found,
        "obligation tuple not found in outbox for {group_key}"
    );
}

/// Build a PendingListenerAdmission marker from a relay entry.
fn marker_admission(
    group_key: &str,
    requester_hex: &str,
    entry: &RelayEntry,
    first_seen_ms: u64,
) -> PendingListenerAdmission {
    PendingListenerAdmission {
        group_id: group_key.to_string(),
        request_id: entry.request_id.clone(),
        requester_agent_id: requester_hex.to_string(),
        envelope_bytes: entry.envelope.clone(),
        digest: entry.digest,
        byte_size: entry.byte_size,
        first_seen_ms,
    }
}

// ===========================================================================
// Matrix: clock = exact × marker {live, expired} — success rows
// ===========================================================================

/// Live marker with an exactly-matching pending request → marker clears,
/// obligation persists, second reload shows no marker. Reddens on MUT-CLEAR.
#[tokio::test]
async fn pr291_live_exact_clock_pending_request_clears_marker() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1001u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let marker_time = now - 1000; // well within 5-min retention → live

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-exact-live",
        &requester_hex,
        marker_time,
    );

    // Install matching pending request with exact clock.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            bound_join_request(&entry, &gk, &requester_hex, marker_time),
        );
        info.recompute_state_hash();
    }

    // Set marker, save both files.
    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster save"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay save"),
        AtomicWriteOutcome::Durable
    );

    // Restart: live marker with matching pending request but no pre-existing
    // obligation → recovery must push exactly one obligation.
    restart_relay(&state)
        .await
        .expect("live exact-clock marker must succeed");
    assert!(listener_admission_is_none(&state).await, "marker cleared");
    assert_obligation_exists(
        &state,
        &gk,
        &entry.request_id,
        &requester_hex,
        &entry.digest,
        marker_time,
    )
    .await;
    assert_eq!(
        tombstone_count_for_group(&state, &gk).await,
        0,
        "no tombstone for live admission"
    );

    // Second reload: marker still gone, obligation persists, no tombstone.
    restart_relay(&state)
        .await
        .expect("second reload with no marker");
    assert!(listener_admission_is_none(&state).await, "still no marker");
    assert_obligation_exists(
        &state,
        &gk,
        &entry.request_id,
        &requester_hex,
        &entry.digest,
        marker_time,
    )
    .await;
    assert_eq!(tombstone_count_for_group(&state, &gk).await, 0);
}

/// Expired marker with an exactly-matching pending request → marker clears,
/// no new obligation, second reload shows no marker. Reddens on MUT-CLEAR.
#[tokio::test]
async fn pr291_expired_exact_clock_pending_request_clears_marker() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1002u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let marker_time = now - CAUSAL_APPROVAL_RETENTION_MS - 1; // expired

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-exact-exp",
        &requester_hex,
        marker_time,
    );

    // Install matching pending request with exact clock.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            bound_join_request(&entry, &gk, &requester_hex, marker_time),
        );
        info.recompute_state_hash();
    }

    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster save"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay save"),
        AtomicWriteOutcome::Durable
    );

    restart_relay(&state)
        .await
        .expect("expired exact-clock marker must clear");
    assert!(listener_admission_is_none(&state).await, "marker cleared");
    assert_eq!(
        relay_outbox_for_group(&state, &gk).await.len(),
        0,
        "no obligation for expired marker"
    );
    assert_eq!(
        tombstone_count_for_group(&state, &gk).await,
        0,
        "no tombstone for expired marker"
    );

    // Second reload: no marker.
    restart_relay(&state).await.expect("second reload clean");
    assert!(listener_admission_is_none(&state).await);
    assert_eq!(relay_outbox_for_group(&state, &gk).await.len(), 0);
    assert_eq!(tombstone_count_for_group(&state, &gk).await, 0);
}

// ===========================================================================
// Matrix: clock = None × marker {live, expired}
// ===========================================================================

/// Live marker with clock=None on the durable request (pubsub-first state).
/// The migration pass backfills predecessor_first_seen_ms from None to
/// Some(marker_time). The request then matches, no binding conflict, and the
/// marker clears. Reddens on MUT-CLEAR (if clock migration doesn't run before
/// the split, the None clock causes exact_request_status=None, occupied=true →
/// false binding conflict).
#[tokio::test]
async fn pr291_live_none_clock_occupied_request_migrates_and_clears() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1003u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let marker_time = now - 1000; // live

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-none-live",
        &requester_hex,
        marker_time,
    );

    // Install a request with clock=None (pubsub-first state: correct digest,
    // correct requester, but predecessor_first_seen_ms = None).
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            join_request_with(
                &entry,
                &gk,
                &requester_hex,
                None,
                x0x::groups::JoinRequestStatus::Pending,
            ),
        );
        info.recompute_state_hash();
    }

    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay"),
        AtomicWriteOutcome::Durable
    );

    restart_relay(&state)
        .await
        .expect("live None-clock marker must migrate and clear");
    assert!(listener_admission_is_none(&state).await, "marker cleared");

    // Live marker + migrated pending request → recovery pushes obligation.
    assert_obligation_exists(
        &state,
        &gk,
        &entry.request_id,
        &requester_hex,
        &entry.digest,
        marker_time,
    )
    .await;
    assert_eq!(tombstone_count_for_group(&state, &gk).await, 0);

    // Verify clock was backfilled from None to Some(marker_time) in memory.
    let migrated_clock = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .and_then(|info| info.join_requests.get("req-none-live"))
        .and_then(|r| r.predecessor_first_seen_ms);
    assert_eq!(
        migrated_clock,
        Some(marker_time),
        "clock backfilled from None to marker time"
    );

    // Reload roster from disk through the production loader — proves the
    // migrated clock persisted across a process-style roster reload.
    reload_roster(&state).await;
    let persisted_clock = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .and_then(|info| info.join_requests.get("req-none-live"))
        .and_then(|r| r.predecessor_first_seen_ms);
    assert_eq!(
        persisted_clock,
        Some(marker_time),
        "migrated clock survived roster reload"
    );

    // Second reload: no marker, obligation persists, no tombstone.
    restart_relay(&state).await.expect("second reload clean");
    assert!(listener_admission_is_none(&state).await);
    assert_obligation_exists(
        &state,
        &gk,
        &entry.request_id,
        &requester_hex,
        &entry.digest,
        marker_time,
    )
    .await;
    assert_eq!(tombstone_count_for_group(&state, &gk).await, 0);
}

/// Expired marker with clock=None on the durable request. Migration
/// backfills the clock, then the expired marker clears without creating an
/// obligation. Reddens on MUT-CLEAR.
#[tokio::test]
async fn pr291_expired_none_clock_occupied_request_migrates_and_clears() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1033u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let marker_time = now - CAUSAL_APPROVAL_RETENTION_MS - 1; // expired

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-none-exp-clock",
        &requester_hex,
        marker_time,
    );

    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            join_request_with(
                &entry,
                &gk,
                &requester_hex,
                None,
                x0x::groups::JoinRequestStatus::Pending,
            ),
        );
        info.recompute_state_hash();
    }

    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay"),
        AtomicWriteOutcome::Durable
    );

    let outbox_before = relay_outbox_total(&state).await;
    restart_relay(&state)
        .await
        .expect("expired None-clock marker must migrate and clear");
    assert!(listener_admission_is_none(&state).await, "marker cleared");
    assert_eq!(
        relay_outbox_total(&state).await,
        outbox_before,
        "no new obligation"
    );

    // Clock backfilled in memory.
    let migrated_clock = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .and_then(|info| info.join_requests.get("req-none-exp-clock"))
        .and_then(|r| r.predecessor_first_seen_ms);
    assert_eq!(migrated_clock, Some(marker_time), "clock backfilled");
    assert_eq!(tombstone_count_for_group(&state, &gk).await, 0);

    // Roster reload: migrated clock persisted on disk.
    reload_roster(&state).await;
    let persisted_clock = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .and_then(|info| info.join_requests.get("req-none-exp-clock"))
        .and_then(|r| r.predecessor_first_seen_ms);
    assert_eq!(
        persisted_clock,
        Some(marker_time),
        "migrated clock survived roster reload"
    );

    restart_relay(&state).await.expect("second reload clean");
    assert!(listener_admission_is_none(&state).await);
    assert_eq!(relay_outbox_for_group(&state, &gk).await.len(), 0);
    assert_eq!(tombstone_count_for_group(&state, &gk).await, 0);
}

/// Expired marker with no durable request → marker clears, no obligation,
/// durable sidecar, second reload clean. This is the "missing-request cleanup"
/// row. Reddens on MUT-CLEAR.
#[tokio::test]
async fn pr291_expired_no_request_cleanup_clears_durable_second_reload() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1004u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let marker_time = now - CAUSAL_APPROVAL_RETENTION_MS - 1; // expired

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-none-exp",
        &requester_hex,
        marker_time,
    );

    // NO join request installed — expired cleanup path.
    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster save"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay save"),
        AtomicWriteOutcome::Durable
    );

    restart_relay(&state)
        .await
        .expect("expired no-request marker must cleanup");
    assert!(listener_admission_is_none(&state).await, "marker cleared");
    assert_eq!(
        relay_outbox_for_group(&state, &gk).await.len(),
        0,
        "no obligation for expired missing-request marker"
    );
    assert_eq!(
        tombstone_count_for_group(&state, &gk).await,
        0,
        "no tombstone for expired missing-request marker"
    );

    // Verify the sidecar was re-saved durably (file exists and has no marker).
    let sidecar_after = relay_sidecar_bytes(&state).await;
    assert!(!sidecar_after.is_empty(), "sidecar exists after cleanup");

    // Second reload: no marker, no error.
    restart_relay(&state).await.expect("second reload clean");
    assert!(listener_admission_is_none(&state).await);
    assert_eq!(relay_outbox_for_group(&state, &gk).await.len(), 0);
    assert_eq!(tombstone_count_for_group(&state, &gk).await, 0);
}

// ===========================================================================
// Matrix: clock = other (mismatched) → fatal for both live and expired
// ===========================================================================

/// A request with predecessor_first_seen_ms = Some(other_time) conflicts with
/// the admission marker's clock. Defense-in-depth: caught independently by
/// both the migration pass (:17205) and the binding-conflict check (:17727).
/// Reddens only when BOTH guards are removed.
#[tokio::test]
async fn pr291_live_other_clock_binding_conflict_fatal_bytes_preserved() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1005u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let marker_time = now - 1000; // live
    let other_time = now - 200_000; // different clock

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-other-live",
        &requester_hex,
        marker_time,
    );

    // Install request with OTHER clock.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            join_request_with(
                &entry,
                &gk,
                &requester_hex,
                Some(other_time),
                x0x::groups::JoinRequestStatus::Pending,
            ),
        );
        info.recompute_state_hash();
    }

    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster save"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay save"),
        AtomicWriteOutcome::Durable
    );

    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(r.is_err(), "live other-clock binding must be fatal: {r:?}");
    assert_eq!(
        relay_sidecar_bytes(&state).await,
        before,
        "sidecar bytes preserved on fatal"
    );
}

/// Same as above but with an EXPIRED marker. Reddens only when both :17205
/// and :17727 are removed (defense-in-depth).
#[tokio::test]
async fn pr291_expired_other_clock_binding_conflict_fatal_bytes_preserved() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1006u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let marker_time = now - CAUSAL_APPROVAL_RETENTION_MS - 1; // expired
    let other_time = now - 200_000;

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-other-exp",
        &requester_hex,
        marker_time,
    );

    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            join_request_with(
                &entry,
                &gk,
                &requester_hex,
                Some(other_time),
                x0x::groups::JoinRequestStatus::Pending,
            ),
        );
        info.recompute_state_hash();
    }

    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster save"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay save"),
        AtomicWriteOutcome::Durable
    );

    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(
        r.is_err(),
        "expired other-clock binding must be fatal: {r:?}"
    );
    assert_eq!(
        relay_sidecar_bytes(&state).await,
        before,
        "sidecar bytes preserved on fatal"
    );
}

// ===========================================================================
// Mismatch fatals: requester mismatch — fatal for both live and expired
// ===========================================================================

/// A request with a different requester_agent_id occupying the same request_id
/// is a binding conflict. Fatal for live markers. Reddens on MUT-BIND.
#[tokio::test]
async fn pr291_live_requester_mismatch_occupied_request_fatal_bytes_preserved() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1007u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let other_hex = format!("{:064x}", 0xDEADu64);
    let now = unix_ms();
    let marker_time = now - 1000; // live

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-req-mis-live",
        &requester_hex,
        marker_time,
    );

    // Install request with WRONG requester but same request_id.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            x0x::groups::JoinRequest {
                request_id: entry.request_id.clone(),
                group_id: gk.clone(),
                requester_agent_id: other_hex, // wrong requester
                requester_user_id: None,
                requested_role: x0x::groups::GroupRole::Member,
                message: None,
                treekem_key_package_b64: None,
                created_at: marker_time,
                reviewed_at: None,
                reviewed_by: None,
                status: x0x::groups::JoinRequestStatus::Pending,
                predecessor_envelope_digest: Some(entry.digest),
                predecessor_first_seen_ms: Some(marker_time),
            },
        );
        info.recompute_state_hash();
    }

    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay"),
        AtomicWriteOutcome::Durable
    );

    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(r.is_err(), "live requester mismatch must be fatal: {r:?}");
    assert_eq!(relay_sidecar_bytes(&state).await, before, "bytes preserved");
}

/// Same as above but EXPIRED marker. This is the key MUT-BIND test: if the
/// binding-conflict check were moved back inside the live-only branch, this
/// expired marker would silently clear instead of erroring.
#[tokio::test]
async fn pr291_expired_requester_mismatch_occupied_request_fatal_bytes_preserved() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1008u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let other_hex = format!("{:064x}", 0xBEEFu64);
    let now = unix_ms();
    let marker_time = now - CAUSAL_APPROVAL_RETENTION_MS - 1; // expired

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-req-mis-exp",
        &requester_hex,
        marker_time,
    );

    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            x0x::groups::JoinRequest {
                request_id: entry.request_id.clone(),
                group_id: gk.clone(),
                requester_agent_id: other_hex,
                requester_user_id: None,
                requested_role: x0x::groups::GroupRole::Member,
                message: None,
                treekem_key_package_b64: None,
                created_at: marker_time,
                reviewed_at: None,
                reviewed_by: None,
                status: x0x::groups::JoinRequestStatus::Pending,
                predecessor_envelope_digest: Some(entry.digest),
                predecessor_first_seen_ms: Some(marker_time),
            },
        );
        info.recompute_state_hash();
    }

    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay"),
        AtomicWriteOutcome::Durable
    );

    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(
        r.is_err(),
        "expired requester mismatch must be fatal: {r:?}"
    );
    assert_eq!(relay_sidecar_bytes(&state).await, before, "bytes preserved");
}

// ===========================================================================
// Mismatch fatals: digest mismatch — fatal for both live and expired
// ===========================================================================

/// A request with a different predecessor_envelope_digest occupying the same
/// request_id is a binding conflict. Fatal for expired markers. Reddens on
/// MUT-BIND.
#[tokio::test]
async fn pr291_expired_digest_mismatch_occupied_request_fatal_bytes_preserved() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1009u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let marker_time = now - CAUSAL_APPROVAL_RETENTION_MS - 1; // expired

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-dig-mis-exp",
        &requester_hex,
        marker_time,
    );

    // Install request with WRONG digest.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            x0x::groups::JoinRequest {
                request_id: entry.request_id.clone(),
                group_id: gk.clone(),
                requester_agent_id: requester_hex.clone(),
                requester_user_id: None,
                requested_role: x0x::groups::GroupRole::Member,
                message: None,
                treekem_key_package_b64: None,
                created_at: marker_time,
                reviewed_at: None,
                reviewed_by: None,
                status: x0x::groups::JoinRequestStatus::Pending,
                predecessor_envelope_digest: Some([0xAA; 32]), // wrong digest
                predecessor_first_seen_ms: Some(marker_time),
            },
        );
        info.recompute_state_hash();
    }

    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay"),
        AtomicWriteOutcome::Durable
    );

    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(r.is_err(), "expired digest mismatch must be fatal: {r:?}");
    assert_eq!(relay_sidecar_bytes(&state).await, before, "bytes preserved");
}

/// Same as above but with a LIVE marker. Reddens on MUT-BIND.
#[tokio::test]
async fn pr291_live_digest_mismatch_occupied_request_fatal_bytes_preserved() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x100Cu32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let marker_time = now - 1000; // live

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-dig-mis-live",
        &requester_hex,
        marker_time,
    );

    // Install request with WRONG digest.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            x0x::groups::JoinRequest {
                request_id: entry.request_id.clone(),
                group_id: gk.clone(),
                requester_agent_id: requester_hex.clone(),
                requester_user_id: None,
                requested_role: x0x::groups::GroupRole::Member,
                message: None,
                treekem_key_package_b64: None,
                created_at: marker_time,
                reviewed_at: None,
                reviewed_by: None,
                status: x0x::groups::JoinRequestStatus::Pending,
                predecessor_envelope_digest: Some([0xBB; 32]), // wrong digest
                predecessor_first_seen_ms: Some(marker_time),
            },
        );
        info.recompute_state_hash();
    }

    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay"),
        AtomicWriteOutcome::Durable
    );

    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(r.is_err(), "live digest mismatch must be fatal: {r:?}");
    assert_eq!(relay_sidecar_bytes(&state).await, before, "bytes preserved");
    assert_eq!(tombstone_count_for_group(&state, &gk).await, 0);
}

// ===========================================================================
// Mismatch fatals: terminal-status without receipt — fatal for both
// ===========================================================================

/// An approved request (terminal) without a matching obligation or receipt is
/// fatal for expired markers. Reddens on MUT-TERMINAL.
#[tokio::test]
async fn pr291_expired_terminal_without_receipt_fatal_bytes_preserved() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x100Au32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let marker_time = now - CAUSAL_APPROVAL_RETENTION_MS - 1; // expired

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-term-exp",
        &requester_hex,
        marker_time,
    );

    // Install request with APPROVED status (terminal) — exact binding matches
    // so exact_request_status = Some(Approved), but no obligation or receipt.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            join_request_with(
                &entry,
                &gk,
                &requester_hex,
                Some(marker_time),
                x0x::groups::JoinRequestStatus::Approved,
            ),
        );
        info.recompute_state_hash();
    }

    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay"),
        AtomicWriteOutcome::Durable
    );

    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(
        r.is_err(),
        "expired terminal-without-receipt must be fatal: {r:?}"
    );
    assert_eq!(relay_sidecar_bytes(&state).await, before, "bytes preserved");
}

/// Same as above but with a LIVE marker. Reddens on MUT-TERMINAL.
#[tokio::test]
async fn pr291_live_terminal_without_receipt_fatal_bytes_preserved() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x100Bu32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let marker_time = now - 1000; // live

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-term-live",
        &requester_hex,
        marker_time,
    );

    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            join_request_with(
                &entry,
                &gk,
                &requester_hex,
                Some(marker_time),
                x0x::groups::JoinRequestStatus::Approved,
            ),
        );
        info.recompute_state_hash();
    }

    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay"),
        AtomicWriteOutcome::Durable
    );

    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(
        r.is_err(),
        "live terminal-without-receipt must be fatal: {r:?}"
    );
    assert_eq!(relay_sidecar_bytes(&state).await, before, "bytes preserved");
}

// ===========================================================================
// Unrelated-group obligation survives expired-marker fall-through
// ===========================================================================

/// An expired marker for group A must not destroy a normal obligation for
/// group B. The early-return path for the expired marker falls through to the
/// common tail, preserving B's obligation. Reddens on MUT-CLEAR if the expired
/// path returns Err instead of falling through.
#[tokio::test]
async fn pr291_expired_marker_does_not_destroy_unrelated_group_obligation() {
    let (state, _dir) = s_state().await;

    // Group A: expired marker.
    let gk_a = format!("{:032x}", 0x2001u32);
    install_group(&state, &gk_a, 2).await;
    let topic_a = group_topic(&state, &gk_a).await;
    let req_a_kp = fresh_kp();
    let req_a_hex = hex::encode(req_a_kp.agent_id().as_bytes());
    let now = unix_ms();
    let marker_time = now - CAUSAL_APPROVAL_RETENTION_MS - 1; // expired

    let entry_a = build_relay_entry(&req_a_kp, &topic_a, &gk_a, "req-a", &req_a_hex, marker_time);

    // Group B: normal live obligation (unrelated group).
    let gk_b = format!("{:032x}", 0x2002u32);
    install_group(&state, &gk_b, 2).await;
    let topic_b = group_topic(&state, &gk_b).await;
    let req_b_kp = fresh_kp();
    let req_b_hex = hex::encode(req_b_kp.agent_id().as_bytes());
    let live_time = now - 1000; // live

    let entry_b = build_relay_entry(&req_b_kp, &topic_b, &gk_b, "req-b", &req_b_hex, live_time);

    // Install B's obligation + join request (NOT group A — A has no request).
    {
        let mut groups = state.named_groups.write().await;
        let info_b = groups.get_mut(&gk_b).expect("group B");
        info_b.join_requests.insert(
            entry_b.request_id.clone(),
            bound_join_request(&entry_b, &gk_b, &req_b_hex, live_time),
        );
        info_b.recompute_state_hash();
    }
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        outbox
            .entry(gk_b.clone())
            .or_default()
            .push(PredecessorRelayObligation {
                envelope_bytes: entry_b.envelope.clone(),
                digest: entry_b.digest,
                byte_size: entry_b.byte_size,
                first_seen_ms: live_time,
                next_retry_at_ms: live_time,
                retry_count: 0,
                group_id: gk_b.clone(),
                request_id: entry_b.request_id.clone(),
                requester_agent_id: req_b_hex.clone(),
                relay_targets: Vec::new(),
                completed_at_ms: None,
            });
    }

    // Set A's expired marker.
    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk_a, &req_a_hex, &entry_a, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay"),
        AtomicWriteOutcome::Durable
    );

    restart_relay(&state)
        .await
        .expect("expired marker for A must not block B");
    assert!(
        listener_admission_is_none(&state).await,
        "A's marker cleared"
    );
    assert_eq!(
        relay_outbox_for_group(&state, &gk_a).await.len(),
        0,
        "no obligation for A's expired marker"
    );
    assert_eq!(
        tombstone_count_for_group(&state, &gk_a).await,
        0,
        "no tombstone for A's expired marker"
    );

    // B's obligation must survive.
    let b_outbox = state
        .predecessor_relay_outbox
        .read()
        .await
        .get(&gk_b)
        .map(|l| l.len())
        .unwrap_or(0);
    assert_eq!(b_outbox, 1, "B's obligation survived A's expired marker");

    // Second reload: still clean.
    restart_relay(&state).await.expect("second reload clean");
    assert!(listener_admission_is_none(&state).await);
    assert_eq!(relay_outbox_for_group(&state, &gk_a).await.len(), 0);
    assert_eq!(tombstone_count_for_group(&state, &gk_a).await, 0);
    let b_outbox_2 = state
        .predecessor_relay_outbox
        .read()
        .await
        .get(&gk_b)
        .map(|l| l.len())
        .unwrap_or(0);
    assert_eq!(
        b_outbox_2, 1,
        "B's obligation still present after second reload"
    );
}

// ===========================================================================
// Signed re-offer through extracted handler proving expired clock not refreshed
// ===========================================================================

/// An expired durable request whose clock was migrated from None must NOT be
/// refreshed by re-offering the exact original envelope through the handler.
/// The handler classifies the expired-but-matching request as Inconsistent
/// (no fresh marker, no obligation, clock unchanged). Reddens on MUT-REFRESH:
/// if `first_seen_is_live` is forced true in the handler's AdmissionState
/// classification (mod.rs:2226), the expired request is re-admitted as Repair,
/// minting a fresh obligation.
#[tokio::test]
async fn pr291_expired_reoffer_exact_envelope_does_not_refresh_clock() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x3001u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let old_marker_time = now - CAUSAL_APPROVAL_RETENTION_MS - 1; // expired

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-reoffer",
        &requester_hex,
        old_marker_time,
    );

    // Install request with clock=None (pubsub-first state).
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            join_request_with(
                &entry,
                &gk,
                &requester_hex,
                None,
                x0x::groups::JoinRequestStatus::Pending,
            ),
        );
        info.recompute_state_hash();
    }

    // Set expired marker, save, restart to migrate clock and clear marker.
    *state.pending_listener_admission.lock().await = Some(marker_admission(
        &gk,
        &requester_hex,
        &entry,
        old_marker_time,
    ));
    assert_eq!(
        save_roster(&state).await.expect("roster"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay"),
        AtomicWriteOutcome::Durable
    );

    restart_relay(&state)
        .await
        .expect("expired None-clock marker must migrate and clear");
    assert!(listener_admission_is_none(&state).await, "marker cleared");

    // Verify clock was migrated to Some(old_marker_time).
    let migrated_clock = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .and_then(|info| info.join_requests.get("req-reoffer"))
        .and_then(|r| r.predecessor_first_seen_ms);
    assert_eq!(
        migrated_clock,
        Some(old_marker_time),
        "clock migrated from None to old_marker_time"
    );

    // Reload roster from disk to prove the migrated clock persisted.
    reload_roster(&state).await;
    let persisted_clock = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .and_then(|info| info.join_requests.get("req-reoffer"))
        .and_then(|r| r.predecessor_first_seen_ms);
    assert_eq!(
        persisted_clock,
        Some(old_marker_time),
        "migrated clock survived roster reload"
    );
    // Explicit pre-relay fixture assertions (Dario's third precondition +
    // tuple-keyed controls). The migration pass already cleared the marker
    // and persisted the expired clock; assert that state is in place
    // before driving the direct re-offer. The :2141-2148 abort and the
    // :2127-2132 expiry gate are otherwise invisible to any outcome-shaped
    // assertion, so this is the only row that catches a leftover marker.
    assert!(
        listener_admission_is_none(&state).await,
        "pre-relay: pending_listener_admission must be None"
    );
    assert_eq!(
        relay_outbox_for_group(&state, &gk).await.len(),
        0,
        "pre-relay: no obligation for this (group, request, requester, digest) tuple"
    );
    assert_eq!(
        tombstone_count_for_group(&state, &gk).await,
        0,
        "pre-relay: no completion tombstone for this tuple"
    );
    assert_eq!(
        persisted_clock,
        Some(old_marker_time),
        "pre-relay: stored clock must still be the expired migrated value"
    );

    // Now pass the EXACT original envelope through the handler. The handler
    // must classify this as Inconsistent (expired request, matching binding,
    // no receipt) and NOT create a fresh marker or obligation.
    let lh = local_hex(&state);
    let mut dm_payload =
        Vec::with_capacity(GROUP_PREDECESSOR_RELAY_DM_PREFIX.len() + entry.envelope.len());
    dm_payload.extend_from_slice(GROUP_PREDECESSOR_RELAY_DM_PREFIX);
    dm_payload.extend_from_slice(&entry.envelope);
    let dm = DmTypedPayload {
        sender: requester_kp.agent_id(),
        machine_id: MachineId([0u8; 32]),
        payload: dm_payload,
        verified: true,
        trust_decision: None,
        received_at_unix_ms: unix_ms(),
        request_id: [0u8; 16],
        completion: None,
    };
    handle_predecessor_relay_typed_payload(&state, &lh, dm).await;

    // No fresh marker — the expired request must not mint a new admission.
    assert!(
        listener_admission_is_none(&state).await,
        "no fresh marker for expired re-offer"
    );
    // No new obligation.
    assert_eq!(
        relay_outbox_for_group(&state, &gk).await.len(),
        0,
        "no obligation for expired re-offer"
    );
    assert_eq!(tombstone_count_for_group(&state, &gk).await, 0);

    // Clock must still be the old expired value, not refreshed.
    let clock_after = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .and_then(|info| info.join_requests.get("req-reoffer"))
        .and_then(|r| r.predecessor_first_seen_ms);
    assert_eq!(
        clock_after,
        Some(old_marker_time),
        "clock not refreshed by expired re-offer"
    );

    // Second sidecar reload: still no marker, no obligation.
    restart_relay(&state).await.expect("second reload clean");
    assert!(listener_admission_is_none(&state).await);
    assert_eq!(relay_outbox_for_group(&state, &gk).await.len(), 0);
    assert_eq!(tombstone_count_for_group(&state, &gk).await, 0);

    // B8 outcome: the expired re-offer created no obligation, so the real
    // `approve_join_request` handler cannot consume one and must refuse
    // with 412. Drives the executable B8 path, not obligation prose.
    assert_eq!(
        approve_status(&state, &gk, &entry.request_id).await,
        StatusCode::PRECONDITION_FAILED,
        "expired re-offer must refuse B8 approval with 412 (no obligation exists)"
    );
}

// ===========================================================================
// Direct-relay admission classification (handler-driven, not restart-driven)
// ===========================================================================
// These rows drive the EXACT direct re-offer through the extracted handler
// (handle_predecessor_relay_typed_payload) and prove the AdmissionState
// classification resolves to the right arm with the right named properties.
// The rows are the same logical matrix as the restart-driven rows above, but
// exercise the live handler path instead of the on-restart loader.

/// Drive the requester-signed offer through the extracted handler using
/// the production path. The handler is the same function the typed-DM
/// receiver loop calls per incoming payload.
pub(super) async fn offer_via_handler(
    state: &Arc<AppState>,
    local_hex: &str,
    entry: &RelayEntry,
    requester_kp: &AgentKeypair,
    received_at_unix_ms: u64,
) {
    let mut dm_payload =
        Vec::with_capacity(GROUP_PREDECESSOR_RELAY_DM_PREFIX.len() + entry.envelope.len());
    dm_payload.extend_from_slice(GROUP_PREDECESSOR_RELAY_DM_PREFIX);
    dm_payload.extend_from_slice(&entry.envelope);
    let dm = DmTypedPayload {
        sender: requester_kp.agent_id(),
        machine_id: MachineId([0u8; 32]),
        payload: dm_payload,
        verified: true,
        trust_decision: None,
        received_at_unix_ms,
        request_id: [0u8; 16],
        completion: None,
    };
    handle_predecessor_relay_typed_payload(state, local_hex, dm).await;
}

/// Assert Dario's third precondition (no leftover admission marker) plus
/// the two tuple-keyed controls (no durable join request, no matching
/// obligation or completion tombstone). These are the jointly-selecting
/// preconditions for the New / Repair / PubsubFirst classifications.
async fn assert_classification_preconditions(
    state: &AppState,
    group_key: &str,
    request_id: &str,
    requester_hex: &str,
    digest: &[u8; 32],
) {
    // Dario's third precondition: pending_listener_admission is None.
    assert!(
        listener_admission_is_none(state).await,
        "precondition: pending_listener_admission must be None"
    );
    // No durable join request for this request_id.
    let request_present = state
        .named_groups
        .read()
        .await
        .get(group_key)
        .and_then(|info| info.join_requests.get(request_id))
        .is_some();
    assert!(
        !request_present,
        "precondition: no durable join request must exist for {request_id}"
    );
    // No matching obligation.
    let obligations = relay_outbox_for_group(state, group_key).await;
    let matching_obligation = obligations.iter().any(|o| {
        o.request_id == request_id && o.requester_agent_id == requester_hex && o.digest == *digest
    });
    assert!(
        !matching_obligation,
        "precondition: no obligation must match ({group_key}, {request_id}, {requester_hex})"
    );
    // No matching completion tombstone.
    let tombstones = state.completed_relay_tombstones.read().await;
    let matching_tombstone = tombstones
        .get(group_key)
        .map(|l| {
            l.iter().any(|t| {
                t.request_id == request_id
                    && t.requester_agent_id == requester_hex
                    && t.digest == *digest
            })
        })
        .unwrap_or(false);
    assert!(
        !matching_tombstone,
        "precondition: no completion tombstone must match ({group_key}, {request_id}, {requester_hex})"
    );
}

/// Watson v4: New regression control. The exact direct re-offer is first
/// contact for the authority. The handler must classify New, durably store
/// the request with the exact predecessor digest and first-seen clock,
/// create the matching obligation with that same clock, and permit B8
/// approval. The third precondition (no leftover admission marker) and
/// the two tuple-keyed controls (no durable request, no obligation/
/// tombstone) are asserted before the handler call, not just arranged.
///
/// Mutation evidence (MUT-NEW-APPLY): remove the
/// `apply_named_group_metadata_event_inner_serialized` call in the New arm
/// (src/server/mod.rs:2492-2503) → New classifies correctly but the
/// JoinRequestCreated is never durably stored, so the "request now exists"
/// assertion fails. MUT-NEW-OBLIGATION: drop the obligation push at
/// src/server/mod.rs:2637 → no obligation is created and the test fails.
/// MUT-NEW-CLOCK: change `admission_first_seen_ms` at src/server/mod.rs:2337-2339
/// to `now_ms.wrapping_add(1)` — the stored request clock diverges from the
/// obligation clock, failing the "exact same clock" assertion.
#[tokio::test]
async fn pr291_new_direct_relay_journals_applies_creates_obligation() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x3002u32);
    // New arm applies the request, so the group must have `RequestAccess`
    // admission (mod.rs:6805) and the event must carry a commit (mod.rs:6799).
    install_group_with_policy(
        &state,
        &gk,
        2,
        x0x::groups::GroupPolicyPreset::PublicRequestSecure,
    )
    .await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let lh = local_hex(&state);

    // The commit must chain from the group's pre-mutation state and be
    // signed by the requester (a non-member), so the apply's
    // `verify_structure` (signature + state_hash) and `validate_apply`
    // (prev_state_hash chain, revision monotonicity, NonMemberRequest
    // authority) all pass. `signed_request_join_commit` reads the group's
    // current state_revision + state_hash, recomputes the component
    // hashes from the current roster/policy/meta, and signs with the
    // requester's key — the same path the production signer uses, so
    // the post-mutation roster's recomputed state_hash matches the
    // commit's claimed state_hash.
    let commit = {
        let groups = state.named_groups.read().await;
        let group = groups.get(&gk).expect("group exists");
        signed_request_join_commit(group, &requester_kp)
    };

    let entry = build_relay_entry_with_commit(
        &requester_kp,
        &topic,
        &gk,
        "req-new-direct",
        &requester_hex,
        0, // first_seen_ms is resolved to now_ms inside the handler
        commit,
    );

    // Three jointly-selecting preconditions asserted before the relay.
    assert_classification_preconditions(
        &state,
        &gk,
        &entry.request_id,
        &requester_hex,
        &entry.digest,
    )
    .await;

    // Drive the requester offer through the handler.
    let now_before = unix_ms();
    offer_via_handler(&state, &lh, &entry, &requester_kp, now_before).await;
    let now_after = unix_ms();

    // New arm: marker cleared, request applied, obligation created.
    assert!(
        listener_admission_is_none(&state).await,
        "New arm cleared the marker on success"
    );

    // The durable request is now stored with the exact digest and clock.
    let stored = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .and_then(|info| info.join_requests.get(&entry.request_id))
        .cloned()
        .expect("New arm must durably store the request");
    assert_eq!(
        stored.predecessor_envelope_digest,
        Some(entry.digest),
        "stored request has exact predecessor digest"
    );
    let stored_clock = stored
        .predecessor_first_seen_ms
        .expect("New arm must record the first-seen clock");
    assert!(
        stored_clock >= now_before && stored_clock <= now_after,
        "stored clock ({stored_clock}) must resolve to now_ms (window {now_before}..={now_after})"
    );
    assert!(stored.is_pending(), "stored request must be Pending");

    // The obligation carries the exact same clock.
    assert_obligation_exists(
        &state,
        &gk,
        &entry.request_id,
        &requester_hex,
        &entry.digest,
        stored_clock,
    )
    .await;
    assert_eq!(
        tombstone_count_for_group(&state, &gk).await,
        0,
        "no completion tombstone for New arm"
    );

    // B8 outcome: the New arm's obligation must be consumable by the real
    // `approve_join_request` handler with HTTP 200. Drives the executable
    // B8 path, not obligation-existence prose.
    assert_eq!(
        approve_status(&state, &gk, &entry.request_id).await,
        StatusCode::OK,
        "New arm must permit B8 approval with 200"
    );
}

/// Watson v4: live Repair. A pre-existing durable pending request carries the
/// exact envelope digest and a still-live original first-observation clock.
/// exact direct relay must select Repair, leave the request clock
/// unchanged, create the obligation with that same clock, and permit B8
/// approval.
///
/// Mutation evidence (MUT-REPAIR-CLOCK): change
/// `admission_first_seen_ms = stored_first_seen_ms` (src/server/mod.rs:2371) to
/// `= now_ms` → the Repair arm refreshes the obligation clock instead of
/// preserving the persisted clock, and the exact-match assertion reddens.
/// (Forcing `first_seen_is_live = true` at the classifier is inert for this
/// row — the live clock already satisfies the predicate, and produces the same
/// RED as MUT-REFRESH.) MUT-REPAIR-OBLIGATION drops the obligation push at
/// `src/server/mod.rs:2641`. MUT-REPAIR-APPLY: force `is_new_request = true`
/// in the Repair arm → the apply runs on an existing request, returns
/// ACCEPTED_REJECTED (src/server/routes/named_groups.rs:6821-6822), the
/// handler breaks out with the marker left set, and no obligation is created.
#[tokio::test]
async fn pr291_live_repair_direct_relay_creates_obligation_without_apply() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x3003u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let lh = local_hex(&state);
    let now = unix_ms();
    let stored_clock = now - 1000; // well within 5-min retention → live

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-repair-live",
        &requester_hex,
        stored_clock,
    );

    // Install the pre-existing durable pending request with the exact digest
    // and a still-live original first-seen clock.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            bound_join_request(&entry, &gk, &requester_hex, stored_clock),
        );
        info.recompute_state_hash();
    }

    // Marker is None (Dario's third precondition) and no obligation/
    // tombstone matches this tuple.
    assert!(
        listener_admission_is_none(&state).await,
        "precondition: pending_listener_admission must be None"
    );
    assert_eq!(
        relay_outbox_for_group(&state, &gk).await.len(),
        0,
        "precondition: no obligation"
    );
    assert_eq!(
        tombstone_count_for_group(&state, &gk).await,
        0,
        "precondition: no completion tombstone"
    );

    // Drive the offer through the handler.
    offer_via_handler(&state, &lh, &entry, &requester_kp, unix_ms()).await;

    // Repair arm: marker cleared, request clock unchanged, obligation
    // created with the same clock.
    assert!(
        listener_admission_is_none(&state).await,
        "Repair arm cleared the marker on success"
    );

    let stored = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .and_then(|info| info.join_requests.get(&entry.request_id))
        .cloned()
        .expect("Repair must preserve the pre-existing durable request");
    assert_eq!(
        stored.predecessor_first_seen_ms,
        Some(stored_clock),
        "Repair must not refresh the persisted clock"
    );
    assert_eq!(
        stored.predecessor_envelope_digest,
        Some(entry.digest),
        "stored request has exact predecessor digest"
    );
    assert!(stored.is_pending(), "stored request must be Pending");

    // The obligation carries the exact same clock.
    assert_obligation_exists(
        &state,
        &gk,
        &entry.request_id,
        &requester_hex,
        &entry.digest,
        stored_clock,
    )
    .await;
    assert_eq!(
        tombstone_count_for_group(&state, &gk).await,
        0,
        "no completion tombstone for Repair arm"
    );

    // B8 outcome: the live Repair arm's obligation must be consumable by
    // the real `approve_join_request` handler with HTTP 200. Drives the
    // executable B8 path, not obligation-existence prose.
    assert_eq!(
        approve_status(&state, &gk, &entry.request_id).await,
        StatusCode::OK,
        "live Repair arm must permit B8 approval with 200"
    );
}

/// Watson v4: PubsubFirst. A pre-existing durable pending request carries the
/// byte-identical predecessor digest but no first-seen clock (the
/// intermediate-build compatibility state). The marker is None (Dario's third
/// precondition) and no obligation or completion tombstone matches. The exact
/// direct relay must backfill the clock at `src/server/mod.rs:2471`, create
/// the obligation at `src/server/mod.rs:2544-2556`, and permit B8 approval.
///
/// Mutation evidence (MUT-PUBSUB-BACKFILL): remove the clock backfill at
/// `src/server/mod.rs:2471` → the stored request stays at
/// `predecessor_first_seen_ms = None`, and the stored-clock/obligation-clock
/// assertion fails. The `created_at == 0` independence check guards the
/// request-preservation invariant: if the classifier is forced to New, the
/// apply path runs, sees an existing request
/// (src/server/routes/named_groups.rs:6821-6822), returns rejected, and the
/// handler breaks out without creating the obligation.
#[tokio::test]
async fn pr291_pubsub_first_direct_relay_backfills_clock_and_creates_obligation() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x3004u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let lh = local_hex(&state);

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-pubsub-first",
        &requester_hex,
        0, // first_seen_ms is resolved to now_ms inside the handler
    );

    // Install the pre-existing durable pending request with the byte-identical
    // predecessor digest but no first-seen clock (intermediate-build state).
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            join_request_with(
                &entry,
                &gk,
                &requester_hex,
                None,
                x0x::groups::JoinRequestStatus::Pending,
            ),
        );
        info.recompute_state_hash();
    }

    // Marker is None and no obligation/tombstone matches this tuple.
    assert!(
        listener_admission_is_none(&state).await,
        "precondition: pending_listener_admission must be None"
    );
    assert_eq!(
        relay_outbox_for_group(&state, &gk).await.len(),
        0,
        "precondition: no obligation"
    );
    assert_eq!(
        tombstone_count_for_group(&state, &gk).await,
        0,
        "precondition: no completion tombstone"
    );

    // Drive the offer through the handler.
    let now_before = unix_ms();
    offer_via_handler(&state, &lh, &entry, &requester_kp, now_before).await;
    let now_after = unix_ms();

    // PubsubFirst arm: marker cleared, clock backfilled, obligation
    // created with the same clock.
    assert!(
        listener_admission_is_none(&state).await,
        "PubsubFirst arm cleared the marker on success"
    );

    let stored = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .and_then(|info| info.join_requests.get(&entry.request_id))
        .cloned()
        .expect("PubsubFirst must preserve the pre-existing durable request");
    assert_eq!(
        stored.predecessor_envelope_digest,
        Some(entry.digest),
        "stored request has exact predecessor digest"
    );
    let backfilled_clock = stored
        .predecessor_first_seen_ms
        .expect("PubsubFirst must backfill the clock");
    assert!(
        backfilled_clock >= now_before && backfilled_clock <= now_after,
        "backfilled clock ({backfilled_clock}) must resolve to now_ms (window {now_before}..={now_after})"
    );
    assert!(stored.is_pending(), "stored request must be Pending");
    // The request must be preserved (not overwritten by an apply).
    // `join_request_with(..., None, ...)` sets `created_at = 0` via
    // `unwrap_or(0)`; an apply-driven rewrite would set `created_at`
    // from the event's `ts`, which is built from the now-stale
    // predecessor_event timestamp.
    assert_eq!(
        stored.created_at, 0,
        "PubsubFirst must preserve the pre-existing durable request (not apply a new one)"
    );

    // The obligation carries the exact same clock.
    assert_obligation_exists(
        &state,
        &gk,
        &entry.request_id,
        &requester_hex,
        &entry.digest,
        backfilled_clock,
    )
    .await;
    assert_eq!(
        tombstone_count_for_group(&state, &gk).await,
        0,
        "no completion tombstone for PubsubFirst arm"
    );

    // B8 outcome: the PubsubFirst arm's obligation must be consumable by
    // the real `approve_join_request` handler with HTTP 200. Drives the
    // executable B8 path, not obligation-existence prose.
    assert_eq!(
        approve_status(&state, &gk, &entry.request_id).await,
        StatusCode::OK,
        "PubsubFirst arm must permit B8 approval with 200"
    );
}

/// PubsubFirst arm driven through a real load cycle, not an in-memory
/// fixture. The intermediate-build roster shape
/// (`predecessor_envelope_digest = Some(digest)`,
/// `predecessor_first_seen_ms = None`) is written to disk via
/// `save_named_groups_checked`, then re-read via `load_named_groups` so
/// the in-memory state is behaviourally equivalent to what an intermediate-build
/// daemon would surface at startup. The handler then classifies
/// re-offer as PubsubFirst and backfills the clock from `now_ms` —
/// the exact branch PR #291 documents for the migration path.
///
/// This is the disk-persisted counterpart to
/// `pr291_pubsub_first_direct_relay_backfills_clock_and_creates_obligation`,
/// which only mutates the in-memory map. A passing green here proves
/// `predecessor_first_seen_ms = None` survives the round-trip through
/// `serde_json` (the `Option<u64>` is preserved, not coerced to
/// `Some(0)`), and that the handler still selects PubsubFirst (not
/// New) when the durable state was loaded from disk.
///
/// MUT-DISK-LOAD-DIGEST: replace `predecessor_envelope_digest: Some(digest)`
/// with `None` on load (mutate the loaded map, then offer). The PubsubFirst
/// arm requires the byte-identical predecessor digest match; without it
/// the handler falls into the `New` arm and backfill is skipped. The missing
/// digest assertion is the sole catcher under this mutation.
#[tokio::test]
async fn pr291_loaded_intermediate_build_pubsub_first_classifies_on_reload() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x3005u32);
    install_group(&state, &gk, 2).await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let lh = local_hex(&state);

    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-pubsub-first-loaded",
        &requester_hex,
        0, // first_seen_ms is resolved to now_ms inside the handler
    );

    // persist and reload so the in-memory state is behaviourally equivalent to
    // what an intermediate-build daemon would surface at startup.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&gk).expect("group");
        info.join_requests.insert(
            entry.request_id.clone(),
            join_request_with(
                &entry,
                &gk,
                &requester_hex,
                None,
                x0x::groups::JoinRequestStatus::Pending,
            ),
        );
        info.recompute_state_hash();
    }
    let save_outcome = save_roster(&state).await.expect("save_roster");
    assert_eq!(
        save_outcome,
        AtomicWriteOutcome::Durable,
        "intermediate-build roster must persist durably before reload"
    );
    reload_roster(&state).await;

    // The loaded state must preserve `predecessor_first_seen_ms = None`
    // and the byte-identical `predecessor_envelope_digest = Some(digest)`.
    // (An Option<u64> serde round-trip is the load-bearing property the
    // PubsubFirst arm depends on.)
    {
        let groups = state.named_groups.read().await;
        let info = groups.get(&gk).expect("group");
        let stored = info
            .join_requests
            .get(&entry.request_id)
            .expect("loaded request");
        assert_eq!(
            stored.predecessor_envelope_digest,
            Some(entry.digest),
            "intermediate-build round-trip must preserve predecessor digest"
        );
        assert_eq!(
            stored.predecessor_first_seen_ms, None,
            "intermediate-build round-trip must preserve None clock"
        );
    }

    // Marker is None and no obligation/tombstone matches this tuple —
    // same jointly-selecting preconditions as the in-memory row.
    assert!(
        listener_admission_is_none(&state).await,
        "precondition: pending_listener_admission must be None after reload"
    );
    assert_eq!(
        relay_outbox_for_group(&state, &gk).await.len(),
        0,
        "precondition: no obligation after reload"
    );
    assert_eq!(
        tombstone_count_for_group(&state, &gk).await,
        0,
        "precondition: no completion tombstone after reload"
    );

    // Drive the offer through the handler against the loaded state.
    let now_before = unix_ms();
    offer_via_handler(&state, &lh, &entry, &requester_kp, now_before).await;
    let now_after = unix_ms();

    // PubsubFirst arm: marker cleared, clock backfilled from now_ms,
    // obligation created with the same clock.
    assert!(
        listener_admission_is_none(&state).await,
        "PubsubFirst arm cleared the marker on success (loaded state)"
    );

    let stored = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .and_then(|info| info.join_requests.get(&entry.request_id))
        .cloned()
        .expect("PubsubFirst must preserve the pre-existing durable request (loaded)");
    assert_eq!(
        stored.predecessor_envelope_digest,
        Some(entry.digest),
        "loaded PubsubFirst: stored request has exact predecessor digest"
    );
    let backfilled_clock = stored
        .predecessor_first_seen_ms
        .expect("PubsubFirst must backfill the clock (loaded)");
    assert!(
        backfilled_clock >= now_before && backfilled_clock <= now_after,
        "loaded PubsubFirst: backfilled clock ({backfilled_clock}) must resolve to now_ms (window {now_before}..={now_after})"
    );
    assert!(
        stored.is_pending(),
        "loaded PubsubFirst: stored request must be Pending"
    );

    // The obligation carries the exact same clock.
    assert_obligation_exists(
        &state,
        &gk,
        &entry.request_id,
        &requester_hex,
        &entry.digest,
        backfilled_clock,
    )
    .await;
    assert_eq!(
        tombstone_count_for_group(&state, &gk).await,
        0,
        "no completion tombstone for loaded PubsubFirst arm"
    );

    // B8 outcome: the loaded PubsubFirst arm's obligation must be
    // consumable by the real `approve_join_request` handler with HTTP 200.
    assert_eq!(
        approve_status(&state, &gk, &entry.request_id).await,
        StatusCode::OK,
        "loaded PubsubFirst arm must permit B8 approval with 200"
    );
}

/// Live Repair arm driven through the real metadata apply path, not an
/// in-memory `join_requests.insert`. The JoinRequestCreated is applied
/// through `apply_named_group_metadata_event` (the same path a witness
/// daemon uses when a metadata event arrives via pubsub), the roster
/// is persisted and reloaded, and only then is the predecessor-relay
/// re-offer driven through the handler. The handler must select
/// Repair — the durable request is byte-identical to the envelope
/// and the original first-seen clock is still live.
///
/// This is the "real metadata-first" counterpart to
/// `pr291_live_repair_direct_relay_creates_obligation_without_apply`,
/// which hand-rolls the durable state via `info.join_requests.insert`.
/// The new row proves the durable state populated by the production
/// apply path (with a real signed commit, prev_state_hash chain, and
/// roster hash) is correctly recognised by the Repair arm after a
/// restart. The existing row's hand-rolled fixture could pass with
/// the apply arm broken; this one cannot.
///
/// `src/server/routes/named_groups.rs:6842` leaves the field as `None` after
/// apply. After reload, the handler's `request_matches` predicate fails on the
/// digest equality check and the request falls into the `New` arm (or
/// `Inconsistent` if other preconditions fail). The Repair-clock assertion
/// reddens under this mutation.
#[tokio::test]
async fn pr291_metadata_first_repair_re_offers_after_real_apply() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x3006u32);
    // The apply arm requires `RequestAccess` admission
    // (src/server/routes/named_groups.rs:6805) and the event must carry a
    // valid commit (src/server/routes/named_groups.rs:6799), so the group uses
    // the same `PublicRequestSecure` policy as the New row.
    install_group_with_policy(
        &state,
        &gk,
        2,
        x0x::groups::GroupPolicyPreset::PublicRequestSecure,
    )
    .await;
    let topic = group_topic(&state, &gk).await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let lh = local_hex(&state);
    let now = unix_ms();
    let original_clock = now - 1000; // well within 5-min retention → live

    // Build a real requester-signed V2 envelope with a properly-signed
    // GroupStateCommit so the apply's `verify_structure` and the
    // `validate_apply` NonMemberRequest authority both pass.
    let commit = {
        let groups = state.named_groups.read().await;
        let group = groups.get(&gk).expect("group");
        signed_request_join_commit(group, &requester_kp)
    };
    let entry = build_relay_entry_with_commit(
        &requester_kp,
        &topic,
        &gk,
        "req-repair-metadata-first",
        &requester_hex,
        original_clock,
        commit.clone(),
    );

    // Apply the JoinRequestCreated through the production metadata
    // apply path — the same path a witness daemon uses when the
    // event arrives via pubsub. This populates the durable state
    // (`info.join_requests[request_id]`) with the byte-identical
    // predecessor digest and a live first-seen clock, and persists
    // the roster to disk.
    let apply_outcome = apply_named_group_metadata_event(
        &state,
        NamedGroupMetadataEvent::JoinRequestCreated {
            group_id: gk.clone(),
            request_id: entry.request_id.clone(),
            requester_agent_id: requester_hex.clone(),
            message: None,
            ts: original_clock,
            requester_kem_public_key_b64: None,
            treekem_key_package_b64: None,
            commit: Some(commit.clone()),
        },
        requester_kp.agent_id(),
        true,
        Some(&entry.envelope),
    )
    .await;
    assert!(
        apply_outcome.accepted,
        "metadata-first apply must accept the JoinRequestCreated"
    );

    // Persist + reload so the in-memory state is byte-faithful to
    // what a witness daemon would surface after a restart.
    let save_outcome = save_roster(&state).await.expect("save_roster");
    assert_eq!(
        save_outcome,
        AtomicWriteOutcome::Durable,
        "metadata-first roster must persist durably before reload"
    );
    reload_roster(&state).await;

    // The loaded state must carry the exact predecessor digest and
    // a live first-seen clock — the load-bearing Repair predicates.
    // The production `apply_named_group_metadata_event` populates
    // `predecessor_first_seen_ms` from `now_millis_u64()` (the public
    // wrapper passes `predecessor_first_seen_ms: None` to the inner
    // function, so the apply resolves the observed-clock via
    // `None.unwrap_or_else(now_millis_u64)`), not from the event's
    // `ts`. The clock is therefore a fresh live value — exactly the
    // shape a witness daemon would surface after restart.
    let apply_clock = {
        let groups = state.named_groups.read().await;
        let info = groups.get(&gk).expect("group");
        let stored = info
            .join_requests
            .get(&entry.request_id)
            .expect("loaded apply-populated request");
        assert_eq!(
            stored.predecessor_envelope_digest,
            Some(entry.digest),
            "metadata-first apply must persist the byte-identical predecessor digest"
        );
        let clock = stored
            .predecessor_first_seen_ms
            .expect("metadata-first apply must populate predecessor_first_seen_ms");
        assert!(
            stored.is_pending(),
            "metadata-first apply must leave the request Pending"
        );
        clock
    };
    // Live range: 5 min retention (CAUSAL_APPROVAL_RETENTION_MS).
    assert!(
        apply_clock + 5 * 60 * 1000 > unix_ms(),
        "apply_clock ({apply_clock}) must be live (within 5-min retention of now {})",
        unix_ms()
    );

    // Marker is None and no obligation/tombstone matches this tuple.
    assert!(
        listener_admission_is_none(&state).await,
        "precondition: pending_listener_admission must be None after apply+reload"
    );
    assert_eq!(
        relay_outbox_for_group(&state, &gk).await.len(),
        0,
        "precondition: no obligation after apply+reload"
    );
    assert_eq!(
        tombstone_count_for_group(&state, &gk).await,
        0,
        "precondition: no completion tombstone after apply+reload"
    );

    // Drive the re-offer through the handler against the apply-populated
    // durable state. The clock argument here is `unix_ms()` — distinct
    // from `original_clock` — to prove the handler leaves the durable
    // clock unchanged (Repair must not refresh it).
    offer_via_handler(&state, &lh, &entry, &requester_kp, unix_ms()).await;

    // Repair arm: marker cleared, original clock preserved, obligation
    // created with the exact same clock.
    assert!(
        listener_admission_is_none(&state).await,
        "Repair arm cleared the marker on success (metadata-first apply)"
    );
    let stored = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .and_then(|info| info.join_requests.get(&entry.request_id))
        .cloned()
        .expect("Repair must preserve the apply-populated request");
    assert_eq!(
        stored.predecessor_envelope_digest,
        Some(entry.digest),
        "Repair: stored request has exact predecessor digest"
    );
    assert_eq!(
        stored.predecessor_first_seen_ms,
        Some(apply_clock),
        "Repair: apply-populated clock must be preserved across the re-offer"
    );
    assert!(
        stored.is_pending(),
        "Repair: stored request must remain Pending"
    );

    // The obligation carries the apply-populated clock — distinct from
    // both `original_clock` (the event's `ts`) and the re-offer's
    // `unix_ms()` argument.
    assert_obligation_exists(
        &state,
        &gk,
        &entry.request_id,
        &requester_hex,
        &entry.digest,
        apply_clock,
    )
    .await;
    assert_eq!(
        tombstone_count_for_group(&state, &gk).await,
        0,
        "no completion tombstone for Repair arm"
    );

    // B8 outcome: the Repair arm's obligation must be consumable by
    // the real `approve_join_request` handler with HTTP 200.
    assert_eq!(
        approve_status(&state, &gk, &entry.request_id).await,
        StatusCode::OK,
        "Repair arm must permit B8 approval with 200 (metadata-first apply)"
    );
}

// ===========================================================================
// Issue #1840 — a request the authority refuses by validation must not hold
// the single-slot admission journal, live or across a restart.
// ===========================================================================

/// How the requester's signed commit goes stale against the authority.
#[derive(Clone, Copy, Debug)]
pub(super) enum StaleCommit {
    /// Issue #1840 route 2: the requester sealed over an owner-only stub
    /// while the authority's roster has more members.
    StubRoster,
    /// Issue #1840 route 3: the authority's revision moved on (a PATCH)
    /// after the requester sealed.
    AuthorityMovedOn,
}

/// Build a requester-signed `JoinRequestCreated` relay entry whose commit
/// cannot apply to the authority's current state of `gk`.
pub(super) async fn stale_request_entry(
    state: &AppState,
    gk: &str,
    request_id: &str,
    requester_kp: &AgentKeypair,
    kind: StaleCommit,
) -> RelayEntry {
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let topic = group_topic(state, gk).await;
    let lh = local_hex(state);
    let commit = {
        let mut groups = state.named_groups.write().await;
        let group = groups.get_mut(gk).expect("group exists");
        match kind {
            StaleCommit::StubRoster => {
                // The stub keeps the authority's chain head (hash and
                // revision, as an imported card gives them) but holds an
                // owner-only roster, so the sealed roster root is wrong.
                let mut stub = group.clone();
                stub.members_v2.retain(|id, _| *id == lh);
                assert_ne!(stub.members_v2.len(), group.members_v2.len());
                signed_request_join_commit(&stub, requester_kp)
            }
            StaleCommit::AuthorityMovedOn => {
                let commit = signed_request_join_commit(group, requester_kp);
                group.description = "edited after the request was sealed".to_string();
                group.state_revision += 1;
                group.recompute_state_hash();
                commit
            }
        }
    };
    build_relay_entry_with_commit(
        requester_kp,
        &topic,
        gk,
        request_id,
        &requester_hex,
        0,
        commit,
    )
}

async fn refused_evidence_exists(state: &AppState) -> bool {
    tokio::fs::try_exists(refused_listener_admission_evidence_path(state))
        .await
        .expect("stat refused-admission evidence path")
}

async fn request_is_stored(state: &AppState, gk: &str, request_id: &str) -> bool {
    state
        .named_groups
        .read()
        .await
        .get(gk)
        .is_some_and(|info| info.join_requests.contains_key(request_id))
}

/// Live path, routes 2 and 3. The authority journals the request, the
/// validator refuses the stale commit, and nothing durable holds the
/// request. The journal slot must then be free, durably, so that a valid
/// request on ANOTHER group of the same authority is admitted and approved.
///
/// RED on main: the marker stays held ("keeping admission journal and
/// stopping") and the second group's request is refused ("unresolved
/// listener-admission journal blocks new admission").
#[tokio::test]
async fn issue1840_live_validation_refusal_frees_journal_for_other_groups() {
    for kind in [StaleCommit::StubRoster, StaleCommit::AuthorityMovedOn] {
        let (state, _dir) = s_state().await;
        let lh = local_hex(&state);
        let gk_a = format!("{:032x}", 0x1840_000au32);
        let gk_b = format!("{:032x}", 0x1840_000bu32);
        for gk in [&gk_a, &gk_b] {
            install_group_with_policy(
                &state,
                gk,
                2,
                x0x::groups::GroupPolicyPreset::PublicRequestSecure,
            )
            .await;
        }
        assert_eq!(
            save_roster(&state).await.expect("roster save"),
            AtomicWriteOutcome::Durable
        );

        let stale_kp = fresh_kp();
        let stale = stale_request_entry(&state, &gk_a, "req-1840-stale", &stale_kp, kind).await;
        offer_via_handler(&state, &lh, &stale, &stale_kp, unix_ms()).await;

        assert!(
            !request_is_stored(&state, &gk_a, &stale.request_id).await,
            "{kind:?}: the refused request must not be stored"
        );
        assert_eq!(
            relay_outbox_total(&state).await,
            0,
            "{kind:?}: a refused request creates no relay obligation"
        );
        assert!(
            listener_admission_is_none(&state).await,
            "{kind:?}: a validation refusal must not hold the admission journal"
        );
        // The clear is durable: a restart finds no marker and succeeds.
        restart_relay(&state)
            .await
            .unwrap_or_else(|e| panic!("{kind:?}: restart after a refusal must succeed: {e}"));
        assert!(listener_admission_is_none(&state).await);
        // Startup found no marker ON DISK: had the live release been
        // memory-only, the loader would have refused the on-disk marker
        // here and written the refused-admission copy.
        assert!(
            !refused_evidence_exists(&state).await,
            "{kind:?}: the live release must be durable"
        );

        // A valid request on an unrelated group of the same authority.
        let good_kp = fresh_kp();
        let good_hex = hex::encode(good_kp.agent_id().as_bytes());
        let topic_b = group_topic(&state, &gk_b).await;
        let commit = {
            let groups = state.named_groups.read().await;
            signed_request_join_commit(groups.get(&gk_b).expect("group b"), &good_kp)
        };
        let good = build_relay_entry_with_commit(
            &good_kp,
            &topic_b,
            &gk_b,
            "req-1840-good",
            &good_hex,
            0,
            commit,
        );
        offer_via_handler(&state, &lh, &good, &good_kp, unix_ms()).await;
        assert!(
            request_is_stored(&state, &gk_b, &good.request_id).await,
            "{kind:?}: another group's request must be admitted"
        );
        assert_eq!(
            approve_status(&state, &gk_b, &good.request_id).await,
            StatusCode::OK,
            "{kind:?}: approval on another group must not be blocked"
        );
    }
}

/// Restart path, routes 2 and 3. A live marker (inside the retention
/// window) whose request cannot be rebuilt against the durable roster must
/// not stop startup. The entry is refused: no request, no obligation, the
/// marker is cleared durably, and the sidecar bytes that held it are kept
/// as evidence.
///
/// RED on main: `listener admission journal commit is invalid: state hash
/// mismatch` / `stale revision`, which ends daemon startup.
#[tokio::test]
async fn issue1840_restart_refuses_unbuildable_live_marker_and_continues() {
    for kind in [StaleCommit::StubRoster, StaleCommit::AuthorityMovedOn] {
        let (state, _dir) = s_state().await;
        let gk = format!("{:032x}", 0x1840_000cu32);
        install_group_with_policy(
            &state,
            &gk,
            2,
            x0x::groups::GroupPolicyPreset::PublicRequestSecure,
        )
        .await;
        let requester_kp = fresh_kp();
        let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
        let entry = stale_request_entry(&state, &gk, "req-1840-restart", &requester_kp, kind).await;
        let marker_time = unix_ms() - 1000; // live

        *state.pending_listener_admission.lock().await =
            Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
        assert_eq!(
            save_roster(&state).await.expect("roster save"),
            AtomicWriteOutcome::Durable
        );
        assert_eq!(
            save_relay(&state).await.expect("relay save"),
            AtomicWriteOutcome::Durable
        );
        let held_bytes = relay_sidecar_bytes(&state).await;

        let result = restart_relay(&state).await;
        assert!(
            result.is_ok(),
            "{kind:?}: an unbuildable journal entry must not stop startup: {result:?}"
        );
        assert!(
            listener_admission_is_none(&state).await,
            "{kind:?}: the refused entry must not stay in the journal"
        );
        assert!(
            !request_is_stored(&state, &gk, &entry.request_id).await,
            "{kind:?}: the refused request must not be applied"
        );
        assert_eq!(relay_outbox_total(&state).await, 0);

        // Evidence: the sidecar bytes that carried the marker are kept.
        let evidence_path = refused_listener_admission_evidence_path(&state);
        let evidence = tokio::fs::read(&evidence_path)
            .await
            .expect("refused-admission evidence copy");
        assert_eq!(evidence, held_bytes, "{kind:?}: evidence is byte-exact");
        // The release is durable: the re-saved sidecar no longer holds
        // the marker.
        let resaved = relay_sidecar_bytes(&state).await;
        assert_ne!(resaved, held_bytes, "{kind:?}: sidecar was re-saved");
        assert!(
            !String::from_utf8_lossy(&resaved).contains(&entry.request_id),
            "{kind:?}: the on-disk sidecar must not hold the refused marker"
        );

        // The clear is durable: the next start is clean too.
        restart_relay(&state)
            .await
            .unwrap_or_else(|e| panic!("{kind:?}: second restart must succeed: {e}"));
        assert!(listener_admission_is_none(&state).await);
    }
}

/// Control for the transient side. When the request is valid but the roster
/// write fails, the outcome is NOT a validation refusal: the journal marker
/// stays held, exactly as before #1840.
#[tokio::test]
async fn issue1840_transient_roster_write_failure_keeps_journal() {
    let (state, _dir) = s_state().await;
    let lh = local_hex(&state);
    let gk = format!("{:032x}", 0x1840_000du32);
    install_group_with_policy(
        &state,
        &gk,
        2,
        x0x::groups::GroupPolicyPreset::PublicRequestSecure,
    )
    .await;
    assert_eq!(
        save_roster(&state).await.expect("roster save"),
        AtomicWriteOutcome::Durable
    );
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let topic = group_topic(&state, &gk).await;
    let commit = {
        let groups = state.named_groups.read().await;
        signed_request_join_commit(groups.get(&gk).expect("group"), &requester_kp)
    };
    let entry = build_relay_entry_with_commit(
        &requester_kp,
        &topic,
        &gk,
        "req-1840-transient",
        &requester_hex,
        0,
        commit,
    );

    // Make the roster replacement fail: a non-empty directory sits at the
    // roster path, so the atomic rename cannot replace it.
    tokio::fs::remove_file(&state.named_groups_path)
        .await
        .expect("remove roster file");
    tokio::fs::create_dir(&state.named_groups_path)
        .await
        .expect("block roster path");
    tokio::fs::write(state.named_groups_path.join("blocker"), b"x")
        .await
        .expect("blocker file");

    offer_via_handler(&state, &lh, &entry, &requester_kp, unix_ms()).await;

    assert!(
        !request_is_stored(&state, &gk, &entry.request_id).await,
        "the request did not become durable, so memory must not keep it"
    );
    let marker = state.pending_listener_admission.lock().await.clone();
    assert!(
        marker.is_some_and(|m| m.request_id == entry.request_id && m.digest == entry.digest),
        "a transient durability failure must keep the admission journal"
    );
}

/// Review r1 (#1842) control. A live marker whose envelope is not a
/// `JoinRequestCreated` is never written by the live path, so the sidecar
/// is suspect: startup still fails closed and the sidecar bytes stay.
#[tokio::test]
async fn issue1840_restart_non_request_marker_is_still_fatal() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1840_000eu32);
    install_group_with_policy(
        &state,
        &gk,
        2,
        x0x::groups::GroupPolicyPreset::PublicRequestSecure,
    )
    .await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let topic = group_topic(&state, &gk).await;
    let event = NamedGroupMetadataEvent::JoinRequestCancelled {
        group_id: gk.clone(),
        request_id: "req-1840-not-a-request".to_string(),
        requester_agent_id: requester_hex.clone(),
        commit: None,
    };
    let envelope = sign_v2_envelope(&requester_kp, &topic, &event);
    let entry = RelayEntry {
        digest: blake3::hash(&envelope).into(),
        byte_size: envelope.len(),
        envelope,
        request_id: "req-1840-not-a-request".to_string(),
    };
    *state.pending_listener_admission.lock().await = Some(marker_admission(
        &gk,
        &requester_hex,
        &entry,
        unix_ms() - 1000,
    ));
    assert_eq!(
        save_roster(&state).await.expect("roster save"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay save"),
        AtomicWriteOutcome::Durable
    );
    let held_bytes = relay_sidecar_bytes(&state).await;

    let result = restart_relay(&state).await;
    assert_eq!(
        result,
        Err("relay envelope is not JoinRequestCreated".to_string()),
        "a non-request marker must stay fatal at startup"
    );
    assert_eq!(
        relay_sidecar_bytes(&state).await,
        held_bytes,
        "the rejected sidecar is preserved byte-for-byte"
    );
    assert!(
        !refused_evidence_exists(&state).await,
        "a fatal rejection is not a refusal: no refused-admission copy"
    );
}

/// #1842 review r2. Startup `Refused` arm: a live marker whose request has
/// no state commit is not admissible, and nothing of it is durable. The
/// entry is refused, the marker is dropped durably and startup continues.
#[tokio::test]
async fn issue1840_restart_refuses_marker_without_commit_and_continues() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1840_000fu32);
    install_group_with_policy(
        &state,
        &gk,
        2,
        x0x::groups::GroupPolicyPreset::PublicRequestSecure,
    )
    .await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let topic = group_topic(&state, &gk).await;
    let marker_time = unix_ms() - 1000;
    let entry = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "req-1840-no-commit",
        &requester_hex,
        marker_time,
    );
    *state.pending_listener_admission.lock().await =
        Some(marker_admission(&gk, &requester_hex, &entry, marker_time));
    assert_eq!(
        save_roster(&state).await.expect("roster save"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay save"),
        AtomicWriteOutcome::Durable
    );
    let held_bytes = relay_sidecar_bytes(&state).await;

    let result = restart_relay(&state).await;
    assert_eq!(result, Ok(()), "a refused entry must not stop startup");
    assert!(listener_admission_is_none(&state).await);
    assert!(!request_is_stored(&state, &gk, &entry.request_id).await);
    assert_eq!(relay_outbox_total(&state).await, 0);
    assert!(refused_evidence_exists(&state).await);
    assert!(
        !String::from_utf8_lossy(&relay_sidecar_bytes(&state).await).contains(&entry.request_id),
        "the on-disk sidecar must not hold the refused marker"
    );
    assert_ne!(relay_sidecar_bytes(&state).await, held_bytes);
    assert_eq!(restart_relay(&state).await, Ok(()), "second start is clean");
}

/// Fixture for the fork-evidence rows: a request-access group whose
/// retained log shows `requester` as an Active Admin at revision 1 and
/// removed at revision 2 (the head). The returned entry carries the
/// requester's commit sealed over revision 1, so the authority refuses it
/// as `stale revision` AND classifies it as authenticated fork evidence.
async fn removed_admin_fork_request(
    state: &AppState,
    gk: &str,
    request_id: &str,
    requester_kp: &AgentKeypair,
) -> RelayEntry {
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let owner_kp = state.agent.identity().agent_keypair();
    install_group_with_policy(
        state,
        gk,
        0,
        x0x::groups::GroupPolicyPreset::PublicRequestSecure,
    )
    .await;
    let at_revision_1 = {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(gk).expect("group");
        info.add_member(
            requester_hex.clone(),
            x0x::groups::GroupRole::Admin,
            Some(local_hex(state)),
            None,
        );
        info.seal_commit(owner_kp, unix_ms()).expect("seal rev 1");
        let at_revision_1 = info.clone();
        info.remove_member(&requester_hex, Some(local_hex(state)));
        info.seal_commit(owner_kp, unix_ms()).expect("seal rev 2");
        at_revision_1
    };
    let commit = signed_request_join_commit(&at_revision_1, requester_kp);
    let topic = group_topic(state, gk).await;
    build_relay_entry_with_commit(
        requester_kp,
        &topic,
        gk,
        request_id,
        &requester_hex,
        0,
        commit,
    )
}

async fn group_is_quarantined(state: &AppState, gk: &str) -> bool {
    state
        .named_groups
        .read()
        .await
        .get(gk)
        .is_some_and(|info| info.fork_quarantine.is_some())
}

/// #1842 review r1/r2, startup. Fork evidence is found for the refused
/// commit but its install fails: startup stays fatal and keeps the sidecar
/// (the marker is the only copy of the conflict). When the install can
/// succeed, the next start records the evidence, refuses the entry and
/// continues.
#[tokio::test]
async fn issue1840_restart_keeps_marker_until_fork_evidence_is_durable() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1840_0010u32);
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let entry =
        removed_admin_fork_request(&state, &gk, "req-1840-fork-restart", &requester_kp).await;
    *state.pending_listener_admission.lock().await = Some(marker_admission(
        &gk,
        &requester_hex,
        &entry,
        unix_ms() - 1000,
    ));
    assert_eq!(
        save_roster(&state).await.expect("roster save"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay save"),
        AtomicWriteOutcome::Durable
    );
    let held_bytes = relay_sidecar_bytes(&state).await;

    {
        let _fault = set_save_fault(&state, SaveFault::Error);
        let result = restart_relay(&state).await;
        let error = result.expect_err("evidence not durable must stay fatal");
        assert!(
            error.contains("stale revision")
                && error.contains("fork evidence was not installed durably"),
            "unexpected startup error: {error}"
        );
    }
    assert_eq!(relay_sidecar_bytes(&state).await, held_bytes);
    assert!(!refused_evidence_exists(&state).await);
    assert!(!group_is_quarantined(&state, &gk).await);

    assert_eq!(
        restart_relay(&state).await,
        Ok(()),
        "retry installs evidence"
    );
    assert!(group_is_quarantined(&state, &gk).await);
    assert!(listener_admission_is_none(&state).await);
    assert!(!request_is_stored(&state, &gk, &entry.request_id).await);
    assert!(refused_evidence_exists(&state).await);
}

/// #1842 review r3 (Greptile P1 "Failed quarantine saves are forgotten").
/// Each roster-save outcome that is not `Durable` keeps startup fatal when
/// the refused commit is fork evidence: the sidecar keeps the marker
/// byte-for-byte, no refused-admission copy is written, and the group is
/// not served. The next start, with a working save, installs the
/// quarantine and only then drops the marker.
///
/// RED with the `evidence_not_durable` stop removed from the startup
/// `CommitInvalid` arm: startup returns `Ok`, the marker is cleared and the
/// group is served without a quarantine.
#[tokio::test]
async fn issue1842_restart_stays_fatal_for_each_non_durable_fork_evidence_save() {
    for (index, fault) in [
        SaveFault::Error,
        SaveFault::NotReplaced,
        SaveFault::ReplacedNotDurable,
    ]
    .into_iter()
    .enumerate()
    {
        let (state, _dir) = s_state().await;
        let gk = format!("{:032x}", 0x1842_0100u32 + index as u32);
        let requester_kp = fresh_kp();
        let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
        let entry =
            removed_admin_fork_request(&state, &gk, "req-1842-fork-save", &requester_kp).await;
        *state.pending_listener_admission.lock().await = Some(marker_admission(
            &gk,
            &requester_hex,
            &entry,
            unix_ms() - 1000,
        ));
        assert_eq!(
            save_roster(&state).await.expect("roster save"),
            AtomicWriteOutcome::Durable
        );
        assert_eq!(
            save_relay(&state).await.expect("relay save"),
            AtomicWriteOutcome::Durable
        );
        let held_bytes = relay_sidecar_bytes(&state).await;

        {
            let _fault = set_save_fault(&state, fault);
            let error = restart_relay(&state)
                .await
                .expect_err("fork evidence that is not durable must stop startup");
            assert!(
                error.contains("fork evidence was not installed durably"),
                "index {index}: unexpected startup error: {error}"
            );
        }
        assert_eq!(
            relay_sidecar_bytes(&state).await,
            held_bytes,
            "index {index}: the sidecar must keep the marker"
        );
        assert!(
            !refused_evidence_exists(&state).await,
            "index {index}: a fatal stop is not a refusal"
        );
        assert!(
            !group_is_quarantined(&state, &gk).await,
            "index {index}: a save that is not durable leaves no live quarantine"
        );

        assert_eq!(
            restart_relay(&state).await,
            Ok(()),
            "index {index}: the next start installs the evidence"
        );
        assert!(group_is_quarantined(&state, &gk).await, "index {index}");
        assert!(listener_admission_is_none(&state).await, "index {index}");
        assert!(!request_is_stored(&state, &gk, &entry.request_id).await);
    }
}

/// #1842 review r3 (Greptile P1 "Groups without lineage miss quarantine").
/// A request-access group formed without an invite has no `invite_lineage`.
/// Startup must use the live gate (`fork_evidence_path_open`), so a refused
/// commit signed by a former admin still sets the quarantine before the
/// marker is dropped.
///
/// RED with the gate narrowed to `invite_lineage.is_some()`: startup
/// returns `Ok` and clears the marker, but the group is not quarantined.
#[tokio::test]
async fn issue1842_restart_quarantines_group_without_invite_lineage() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 0x1842_0200u32);
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let entry = removed_admin_fork_request(&state, &gk, "req-1842-no-lineage", &requester_kp).await;
    {
        let groups = state.named_groups.read().await;
        let info = groups.get(&gk).expect("group");
        assert!(
            info.invite_lineage.is_none(),
            "fixture: the group must have no invite lineage"
        );
        assert!(
            info.policy.admission.owner_certified_user_id().is_none(),
            "fixture: an ordinary request-access group"
        );
        assert!(info.fork_quarantine.is_none());
    }
    *state.pending_listener_admission.lock().await = Some(marker_admission(
        &gk,
        &requester_hex,
        &entry,
        unix_ms() - 1000,
    ));
    assert_eq!(
        save_roster(&state).await.expect("roster save"),
        AtomicWriteOutcome::Durable
    );
    assert_eq!(
        save_relay(&state).await.expect("relay save"),
        AtomicWriteOutcome::Durable
    );

    assert_eq!(restart_relay(&state).await, Ok(()));
    {
        let groups = state.named_groups.read().await;
        let info = groups.get(&gk).expect("group");
        let marker = info
            .fork_quarantine
            .as_ref()
            .expect("startup must quarantine a group without lineage");
        assert!(marker.committed_by.eq_ignore_ascii_case(&requester_hex));
        assert!(info.invite_lineage.is_none());
    }
    // The quarantine is in the roster file, not only in memory.
    let roster = tokio::fs::read_to_string(&state.named_groups_path)
        .await
        .expect("roster file");
    let roster: serde_json::Value = serde_json::from_str(&roster).expect("roster json");
    fn has_quarantine(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(map) => map
                .iter()
                .any(|(key, v)| (key == "fork_quarantine" && !v.is_null()) || has_quarantine(v)),
            serde_json::Value::Array(items) => items.iter().any(has_quarantine),
            _ => false,
        }
    }
    assert!(
        has_quarantine(&roster),
        "the quarantine must be in the durable roster"
    );
    assert!(listener_admission_is_none(&state).await);
    assert!(!request_is_stored(&state, &gk, &entry.request_id).await);
    assert!(refused_evidence_exists(&state).await);
}

/// #1842 review r2, live path — the same rule. Evidence found but not
/// installed durably keeps the journal marker; once the install is
/// durable, the re-offer of the same envelope is a clean refusal and the
/// marker is released.
#[tokio::test]
async fn issue1840_live_keeps_marker_until_fork_evidence_is_durable() {
    let (state, _dir) = s_state().await;
    let lh = local_hex(&state);
    let gk = format!("{:032x}", 0x1840_0011u32);
    let requester_kp = fresh_kp();
    let entry = removed_admin_fork_request(&state, &gk, "req-1840-fork-live", &requester_kp).await;
    assert_eq!(
        save_roster(&state).await.expect("roster save"),
        AtomicWriteOutcome::Durable
    );

    {
        let _fault = set_save_fault(&state, SaveFault::Error);
        offer_via_handler(&state, &lh, &entry, &requester_kp, unix_ms()).await;
    }
    let marker = state.pending_listener_admission.lock().await.clone();
    assert!(
        marker.is_some_and(|m| m.digest == entry.digest),
        "evidence found but not durable must keep the admission journal"
    );
    assert!(!group_is_quarantined(&state, &gk).await);

    offer_via_handler(&state, &lh, &entry, &requester_kp, unix_ms()).await;
    assert!(group_is_quarantined(&state, &gk).await);
    assert!(
        listener_admission_is_none(&state).await,
        "with the evidence durable the refusal releases the journal"
    );
    assert!(!request_is_stored(&state, &gk, &entry.request_id).await);
}
