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

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn s_state() -> (Arc<AppState>, tempfile::TempDir) {
    let (state, dir) = secure_endpoint_test_state().await.expect("secure state");
    (state, dir)
}

fn fresh_kp() -> AgentKeypair {
    AgentKeypair::generate().expect("agent keypair")
}

fn local_hex(state: &AppState) -> String {
    hex::encode(state.agent.agent_id().as_bytes())
}

/// Real requester-signed V2 pub/sub envelope (same construction as
/// `pubsub::encode_v2` using only public ML-DSA-65 primitives).
fn sign_v2_envelope(kp: &AgentKeypair, topic: &str, event: &NamedGroupMetadataEvent) -> Vec<u8> {
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
struct RelayEntry {
    envelope: Vec<u8>,
    digest: [u8; 32],
    request_id: String,
    byte_size: usize,
}

fn build_relay_entry(
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

fn bound_join_request(
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

async fn group_topic(state: &AppState, group_key: &str) -> String {
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

async fn save_roster(state: &AppState) -> std::io::Result<AtomicWriteOutcome> {
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

async fn listener_admission_is_none(state: &AppState) -> bool {
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
}
