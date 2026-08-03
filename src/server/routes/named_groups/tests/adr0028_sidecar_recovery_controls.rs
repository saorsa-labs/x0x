//! ADR 0028 sidecar recovery durability-boundary controls (rows 4–7, 10).
//!
//! Drives the REAL atomic writer/loaders (`save_predecessor_relay_outbox`,
//! `load_predecessor_relay_outbox`, `save_causal_approval_queue`,
//! `load_causal_approval_queue`, `write_named_groups_json_atomic`) with
//! semantically valid signed V2 envelopes bound to real roster join-requests.
//!
//! Every over-cap rejection asserts the loader contract: `Err`, zero installed
//! live state, and the sidecar file left byte-identical for diagnosis. Every
//! boundary has a paired under-cap (GREEN) control.
//!
//! No production file is touched; no `cfg(test)` signing seam is added.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_arguments,
    clippy::redundant_clone
)]

use super::*;
use crate::groups::GroupInfo;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
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

/// Real requester-signed V2 pub/sub envelope — faithful re-implementation of
/// `pubsub::encode_v2` using only public `ant_quic` ML-DSA-65 primitives.
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
    msg: Option<String>,
) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::JoinRequestCreated {
        group_id: group_key.to_string(),
        request_id: request_id.to_string(),
        requester_agent_id: requester_hex.to_string(),
        message: msg,
        ts,
        requester_kem_public_key_b64: None,
        treekem_key_package_b64: None,
        commit: None,
    }
}

fn approval_event(
    group_key: &str,
    request_id: &str,
    requester_hex: &str,
    actor_hex: &str,
    revision: u64,
) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::JoinRequestApproved {
        group_id: group_key.to_string(),
        request_id: request_id.to_string(),
        revision,
        actor: actor_hex.to_string(),
        requester_agent_id: requester_hex.to_string(),
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_key_package_hash: None,
        treekem_epoch: None,
        commit: None,
    }
}

// ---- relay entry building -------------------------------------------------

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
    msg_pad: usize,
) -> RelayEntry {
    let msg = (msg_pad > 0).then(|| "P".repeat(msg_pad));
    let event = predecessor_event(group_key, request_id, requester_hex, first_seen_ms, msg);
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

/// Install a group with the local agent as authority + `witness_count` active
/// non-local witnesses (valid 32-byte hex agent IDs).
async fn install_group(state: &AppState, group_key: &str, witness_count: usize) {
    let admin_id = state.agent.agent_id();
    let mut info = GroupInfo::with_policy(
        "adr0028-sidecar".to_string(),
        String::new(),
        admin_id,
        group_key.to_string(),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    let lh = local_hex(state);
    for i in 1..=witness_count {
        let whex = format!("{:064x}", 0x1000u64 + i as u64);
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

/// Add `entries` as bound join-requests + live obligations for `group_key`.
async fn install_relay_entries(
    state: &AppState,
    group_key: &str,
    entries: &[RelayEntry],
    requester_hex: &str,
    first_seen_ms: u64,
) {
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(group_key).expect("group exists");
        for entry in entries {
            info.join_requests.insert(
                entry.request_id.clone(),
                bound_join_request(entry, group_key, requester_hex, first_seen_ms),
            );
        }
        info.recompute_state_hash();
    }
    let mut outbox = state.predecessor_relay_outbox.write().await;
    let list = outbox.entry(group_key.to_string()).or_default();
    for entry in entries {
        list.push(PredecessorRelayObligation {
            envelope_bytes: entry.envelope.clone(),
            digest: entry.digest,
            byte_size: entry.byte_size,
            first_seen_ms,
            next_retry_at_ms: first_seen_ms,
            retry_count: 0,
            group_id: group_key.to_string(),
            request_id: entry.request_id.clone(),
            requester_agent_id: requester_hex.to_string(),
            relay_targets: Vec::new(),
            completed_at_ms: None,
        });
    }
}

/// Add COMPLETED tombstones (with per-entry first_seen_ms) + roster bindings.
async fn install_relay_tombstones(
    state: &AppState,
    group_key: &str,
    entries: &[(RelayEntry, u64)],
    requester_hex: &str,
    completed_at_ms: u64,
) {
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(group_key).expect("group exists");
        for (entry, fsm) in entries {
            info.join_requests.insert(
                entry.request_id.clone(),
                bound_join_request(entry, group_key, requester_hex, *fsm),
            );
        }
        info.recompute_state_hash();
    }
    let mut tombstones = state.completed_relay_tombstones.write().await;
    let list = tombstones.entry(group_key.to_string()).or_default();
    for (entry, fsm) in entries {
        list.push(CompletedRelayTombstone {
            group_id: group_key.to_string(),
            request_id: entry.request_id.clone(),
            requester_agent_id: requester_hex.to_string(),
            digest: entry.digest,
            completed_at_ms,
            envelope_bytes: entry.envelope.clone(),
            first_seen_ms: *fsm,
        });
    }
}

/// Build `count` relay entries for one group (no install).
fn build_entries(
    requester_kp: &AgentKeypair,
    topic: &str,
    group_key: &str,
    requester_hex: &str,
    first_seen_ms: u64,
    count: usize,
    msg_pad: usize,
) -> Vec<RelayEntry> {
    (0..count)
        .map(|j| {
            let rid = format!("r-{}-{:04}", &group_key[..8], j);
            build_relay_entry(
                requester_kp,
                topic,
                group_key,
                &rid,
                requester_hex,
                first_seen_ms,
                msg_pad,
            )
        })
        .collect()
}

// ---- sidecar I/O ----------------------------------------------------------

async fn save_relay(state: &AppState) -> std::io::Result<AtomicWriteOutcome> {
    save_predecessor_relay_outbox(state).await
}

async fn relay_sidecar_bytes(state: &AppState) -> Vec<u8> {
    tokio::fs::read(&state.predecessor_relay_outbox_path)
        .await
        .unwrap_or_default()
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
        .map(|l| l.len())
        .sum()
}

async fn relay_outbox_for_group(state: &AppState, gk: &str) -> Vec<PredecessorRelayObligation> {
    state
        .predecessor_relay_outbox
        .read()
        .await
        .get(gk)
        .cloned()
        .unwrap_or_default()
}

// ---- causal queue helpers -------------------------------------------------

/// Build and install causal-queue entries (JoinRequestApproved signed by a
/// fresh admin who is an active admin member of the group).
/// Build and install causal-queue entries (JoinRequestApproved signed by
/// the local agent, who is the group's active admin/creator).
async fn install_queue_entries(state: &AppState, group_key: &str, count: usize) {
    let admin_kp = state.agent.identity().agent_keypair();
    let admin_hex = local_hex(state);
    let requester_hex = hex::encode(fresh_kp().agent_id().as_bytes());
    let now = unix_ms();
    let topic = state
        .named_groups
        .read()
        .await
        .get(group_key)
        .expect("group")
        .metadata_topic
        .clone();
    let sender = state.agent.agent_id();
    // Build all signed envelopes while borrowing only state.agent (disjoint
    // from the queue write lock below).
    let mut built: Vec<(Vec<u8>, [u8; 32], String, NamedGroupMetadataEvent)> = Vec::new();
    for j in 0..count {
        let rid = format!("q-{}-{:04}", &group_key[..8], j);
        let event = approval_event(group_key, &rid, &requester_hex, &admin_hex, 1);
        let envelope = sign_v2_envelope(admin_kp, &topic, &event);
        let digest: [u8; 32] = blake3::hash(&envelope).into();
        built.push((envelope, digest, rid, event));
    }
    let mut queue = state.causal_approval_queue.write().await;
    let dq = queue.entry(group_key.to_string()).or_default();
    for (envelope, digest, rid, event) in built {
        dq.push_back(PendingCausalApproval {
            envelope_bytes: envelope.clone(),
            digest,
            byte_size: envelope.len(),
            event,
            sender,
            first_seen_ms: now,
            expires_at_ms: now + 300_000,
            request_id: rid,
            requester_agent_id: requester_hex.clone(),
            revision: 1,
            conflicted: false,
            conflicted_with: None,
        });
    }
}

async fn queue_total(state: &AppState) -> usize {
    state
        .causal_approval_queue
        .read()
        .await
        .values()
        .map(|l| l.len())
        .sum()
}

async fn restart_queue(state: &AppState) -> Result<(), String> {
    state.causal_approval_queue.write().await.clear();
    state.causal_conflict_tombstones.write().await.clear();
    load_causal_approval_queue(state).await
}

async fn queue_sidecar_bytes(state: &AppState) -> Vec<u8> {
    tokio::fs::read(&state.causal_approval_queue_path)
        .await
        .unwrap_or_default()
}

// ---- permission RAII ------------------------------------------------------

struct PermGuard {
    path: PathBuf,
    restore: u32,
}
impl PermGuard {
    async fn arm(path: impl Into<PathBuf>, mode: u32, restore: u32) -> Self {
        let path = path.into();
        let _ = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).await;
        PermGuard { path, restore }
    }
}
impl Drop for PermGuard {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.restore));
    }
}

// ===========================================================================
// Row 7 — relay outbox per-group COUNT cap (64 accepted / 65 rejected)
// ===========================================================================

/// MUT2: drop the per-group count check in `enforce_combined_relay_budget`
/// (16326) and 65 obligations survive restart in one group.
#[tokio::test]
async fn relay_per_group_count_cap_64_accepted_then_65_rejected() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 1u32);
    install_group(&state, &gk, 0).await;
    let topic = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .expect("gk")
        .metadata_topic
        .clone();
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();

    // --- GREEN: exactly 64 in one group ---
    let entries = build_entries(&requester_kp, &topic, &gk, &requester_hex, now, 64, 0);
    install_relay_entries(&state, &gk, &entries, &requester_hex, now).await;
    assert_eq!(relay_outbox_for_group(&state, &gk).await.len(), 64);
    save_relay(&state).await.expect("save 64");
    let r = restart_relay(&state).await;
    assert!(r.is_ok(), "64 entries at per-group cap must load: {:?}", r);
    assert_eq!(relay_outbox_total(&state).await, 64);

    // --- RED: 65 in the SAME group ---
    let extra = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "extra-65",
        &requester_hex,
        now,
        0,
    );
    install_relay_entries(
        &state,
        &gk,
        std::slice::from_ref(&extra),
        &requester_hex,
        now,
    )
    .await;
    assert_eq!(relay_outbox_for_group(&state, &gk).await.len(), 65);
    save_relay(&state).await.expect("save 65");
    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(r.is_err(), "65 in one group must be rejected: {:?}", r);
    assert_eq!(
        relay_outbox_total(&state).await,
        0,
        "zero installed on rejection"
    );
    assert_eq!(
        relay_sidecar_bytes(&state).await,
        before,
        "diagnostic bytes preserved"
    );
}

// ===========================================================================
// Row 7 — relay outbox daemon-wide COUNT cap (1024 accepted / 1025 rejected)
// ===========================================================================

/// MUT2: raise CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP past 1025 and the over-cap
/// sidecar installs instead of rejecting.
#[tokio::test]
async fn relay_daemon_count_cap_1024_accepted_then_1025_rejected() {
    let (state, _dir) = s_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let per_group = CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP;

    // --- GREEN: exactly 1024 across 16 groups × 64 ---
    for gi in 0..16u32 {
        let gk = format!("{:032x}", gi);
        install_group(&state, &gk, 0).await;
        let topic = state
            .named_groups
            .read()
            .await
            .get(&gk)
            .expect("gk")
            .metadata_topic
            .clone();
        let entries = build_entries(
            &requester_kp,
            &topic,
            &gk,
            &requester_hex,
            now,
            per_group,
            0,
        );
        install_relay_entries(&state, &gk, &entries, &requester_hex, now).await;
    }
    assert_eq!(relay_outbox_total(&state).await, 1024);
    save_relay(&state).await.expect("save 1024");
    let r = restart_relay(&state).await;
    assert!(r.is_ok(), "1024 entries at daemon cap must load: {:?}", r);
    assert_eq!(relay_outbox_total(&state).await, 1024);

    // --- RED: add one more entry in a 17th group → 1025 ---
    let gk17 = format!("{:032x}", 17u32);
    install_group(&state, &gk17, 0).await;
    let topic17 = state
        .named_groups
        .read()
        .await
        .get(&gk17)
        .expect("g17")
        .metadata_topic
        .clone();
    let extra = build_relay_entry(
        &requester_kp,
        &topic17,
        &gk17,
        "extra-1025",
        &requester_hex,
        now,
        0,
    );
    install_relay_entries(
        &state,
        &gk17,
        std::slice::from_ref(&extra),
        &requester_hex,
        now,
    )
    .await;
    assert_eq!(relay_outbox_total(&state).await, 1025);
    save_relay(&state).await.expect("save 1025");
    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(r.is_err(), "1025 must exceed daemon count cap: {:?}", r);
    assert_eq!(
        relay_outbox_total(&state).await,
        0,
        "zero installed on rejection"
    );
    assert_eq!(
        relay_sidecar_bytes(&state).await,
        before,
        "diagnostic bytes preserved"
    );
}

// ===========================================================================
// Row 7 — relay outbox per-group BYTE cap boundary
// ===========================================================================

/// MUT2: drop the per-group byte check in `enforce_combined_relay_budget`
/// (16363) and oversized entries survive restart.
#[tokio::test]
async fn relay_per_group_byte_cap_boundary() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 1u32);
    install_group(&state, &gk, 0).await;
    let topic = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .expect("gk")
        .metadata_topic
        .clone();
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let pad = 55_000usize;

    // Measure one entry's envelope size.
    let probe = build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "probe",
        &requester_hex,
        now,
        pad,
    );
    let s = probe.byte_size;
    assert!(
        s <= CAUSAL_ENVELOPE_MAX_BYTES,
        "envelope within semantic cap"
    );
    let cap = CAUSAL_RELAY_OUTBOX_PER_GROUP_BYTE_CAP;
    let max_under = cap / s;
    assert!(
        max_under < CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP,
        "count under per-group count cap"
    );

    // --- GREEN: max_under entries → total ≤ byte cap ---
    let entries = build_entries(
        &requester_kp,
        &topic,
        &gk,
        &requester_hex,
        now,
        max_under,
        pad,
    );
    let total_bytes: usize = entries.iter().map(|e| e.byte_size).sum();
    assert!(total_bytes <= cap, "GREEN total within byte cap");
    install_relay_entries(&state, &gk, &entries, &requester_hex, now).await;
    save_relay(&state).await.expect("save under");
    let r = restart_relay(&state).await;
    assert!(r.is_ok(), "under per-group byte cap must load: {:?}", r);
    assert_eq!(relay_outbox_for_group(&state, &gk).await.len(), max_under);

    // --- RED: max_under + 1 → total > byte cap ---
    let mut over = entries.clone();
    over.push(build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "over",
        &requester_hex,
        now,
        pad,
    ));
    let over_bytes: usize = over.iter().map(|e| e.byte_size).sum();
    assert!(over_bytes > cap, "RED total exceeds byte cap");
    // Reset roster + outbox for this group.
    state.predecessor_relay_outbox.write().await.clear();
    {
        let mut groups = state.named_groups.write().await;
        groups.get_mut(&gk).expect("gk").join_requests.clear();
    }
    install_relay_entries(&state, &gk, &over, &requester_hex, now).await;
    save_relay(&state).await.expect("save over");
    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(
        r.is_err(),
        "over per-group byte cap must be rejected: {:?}",
        r
    );
    assert_eq!(relay_outbox_total(&state).await, 0, "zero installed");
    assert_eq!(relay_sidecar_bytes(&state).await, before, "bytes preserved");
}

// ===========================================================================
// Row 7 — relay outbox daemon-wide BYTE cap boundary
// ===========================================================================

/// MUT2: raise CAUSAL_RELAY_OUTBOX_PER_DAEMON_BYTE_CAP and the over-cap
/// sidecar installs.
#[tokio::test]
async fn relay_daemon_byte_cap_boundary() {
    let (state, _dir) = s_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let pad = 55_000usize;

    // Measure envelope size and compute how many fit under the daemon byte cap.
    let gk0 = format!("{:032x}", 0u32);
    install_group(&state, &gk0, 0).await;
    let topic0 = state
        .named_groups
        .read()
        .await
        .get(&gk0)
        .expect("g0")
        .metadata_topic
        .clone();
    let probe = build_relay_entry(
        &requester_kp,
        &topic0,
        &gk0,
        "probe",
        &requester_hex,
        now,
        pad,
    );
    let s = probe.byte_size;
    let daemon_cap = CAUSAL_RELAY_OUTBOX_PER_DAEMON_BYTE_CAP;
    let max_under = daemon_cap / s;
    // Per-group limits: count cap AND per-group byte cap.
    let per_group = std::cmp::min(
        CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP,
        CAUSAL_RELAY_OUTBOX_PER_GROUP_BYTE_CAP / s,
    );
    assert!(per_group > 0 && max_under > 0);

    // --- GREEN: max_under entries distributed across groups ---
    let mut built = 0usize;
    let mut gi = 0u32;
    // Re-use gk0 for the first batch.
    let first_batch = std::cmp::min(per_group, max_under);
    let entries0 = build_entries(
        &requester_kp,
        &topic0,
        &gk0,
        &requester_hex,
        now,
        first_batch,
        pad,
    );
    install_relay_entries(&state, &gk0, &entries0, &requester_hex, now).await;
    built += first_batch;
    gi += 1;
    while built < max_under {
        let gk = format!("{:032x}", gi);
        gi += 1;
        install_group(&state, &gk, 0).await;
        let gtopic = state
            .named_groups
            .read()
            .await
            .get(&gk)
            .expect("gk")
            .metadata_topic
            .clone();
        let take = std::cmp::min(per_group, max_under - built);
        let batch = build_entries(&requester_kp, &gtopic, &gk, &requester_hex, now, take, pad);
        install_relay_entries(&state, &gk, &batch, &requester_hex, now).await;
        built += take;
    }
    let total_bytes: usize = state
        .predecessor_relay_outbox
        .read()
        .await
        .values()
        .flatten()
        .map(|o| o.byte_size)
        .sum();
    assert!(total_bytes <= daemon_cap, "GREEN: within daemon byte cap");
    save_relay(&state).await.expect("save under");
    let r = restart_relay(&state).await;
    assert!(r.is_ok(), "within daemon byte cap must load: {:?}", r);
    assert_eq!(relay_outbox_total(&state).await, max_under);

    // --- RED: one more entry → over daemon byte cap ---
    let gk_over = format!("{:032x}", gi);
    install_group(&state, &gk_over, 0).await;
    let otopic = state
        .named_groups
        .read()
        .await
        .get(&gk_over)
        .expect("gk_over")
        .metadata_topic
        .clone();
    let extra = build_relay_entry(
        &requester_kp,
        &otopic,
        &gk_over,
        "db-over",
        &requester_hex,
        now,
        pad,
    );
    install_relay_entries(
        &state,
        &gk_over,
        std::slice::from_ref(&extra),
        &requester_hex,
        now,
    )
    .await;
    save_relay(&state).await.expect("save over");
    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(r.is_err(), "over daemon byte cap must be rejected: {:?}", r);
    assert_eq!(relay_outbox_total(&state).await, 0, "zero installed");
    assert_eq!(relay_sidecar_bytes(&state).await, before, "bytes preserved");
}

// ===========================================================================
// Row 10 — relay TARGET cap (4096 accepted / 4097 rejected, post-load)
// ===========================================================================

/// The loader re-derives relay targets from active non-local witnesses.
/// With 64 witnesses per group, N groups × 1 obligation × 64 targets =
/// N×64 total targets. MUT2: drop the post-load 4096 cap (17538) and 4097
/// targets survive restart. Asserts the SPECIFIC target-cap error to
/// distinguish from the 256 MiB file-size error.
#[tokio::test]
async fn relay_target_cap_4096_accepted_then_4097_rejected() {
    let (state, _dir) = s_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let witnesses = 64usize;

    // --- GREEN: 64 groups × 64 targets = 4096 (at cap) ---
    for gi in 0..64u32 {
        let gk = format!("{:032x}", gi);
        install_group(&state, &gk, witnesses).await;
        let topic = state
            .named_groups
            .read()
            .await
            .get(&gk)
            .expect("gk")
            .metadata_topic
            .clone();
        let entry = build_relay_entry(
            &requester_kp,
            &topic,
            &gk,
            &format!("t-{}", gi),
            &requester_hex,
            now,
            0,
        );
        install_relay_entries(
            &state,
            &gk,
            std::slice::from_ref(&entry),
            &requester_hex,
            now,
        )
        .await;
    }
    save_relay(&state).await.expect("save 4096");
    let r = restart_relay(&state).await;
    assert!(r.is_ok(), "4096 targets at cap must load: {:?}", r);
    let total_targets: usize = state
        .predecessor_relay_outbox
        .read()
        .await
        .values()
        .flatten()
        .map(|o| o.relay_targets.len())
        .sum();
    assert_eq!(total_targets, 4096, "exactly 4096 re-derived targets");
    assert_eq!(relay_outbox_total(&state).await, 64);

    // --- RED: 65th group → 65 × 64 = 4160 > 4096 ---
    let gk65 = format!("{:032x}", 65u32);
    install_group(&state, &gk65, witnesses).await;
    let topic65 = state
        .named_groups
        .read()
        .await
        .get(&gk65)
        .expect("g65")
        .metadata_topic
        .clone();
    let entry65 = build_relay_entry(
        &requester_kp,
        &topic65,
        &gk65,
        "t-65",
        &requester_hex,
        now,
        0,
    );
    install_relay_entries(
        &state,
        &gk65,
        std::slice::from_ref(&entry65),
        &requester_hex,
        now,
    )
    .await;
    save_relay(&state).await.expect("save 4160");
    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    let err = r.expect_err("4097+ targets must be rejected");
    assert!(
        err.contains("live relay targets exceed daemon cap"),
        "must be the specific target-cap error, not file-size or count: got {err}",
    );
    assert_eq!(
        relay_outbox_total(&state).await,
        0,
        "zero installed on rejection"
    );
    assert_eq!(relay_sidecar_bytes(&state).await, before, "bytes preserved");
}

// ===========================================================================
// Row 4 — terminal-only excess: oldest tombstones pruned to live budget
// (never-evict-live policy, deterministic oldest-first).
// ===========================================================================

/// With 10 live + 60 completed in one group (combined 70 > per-group cap 64),
/// the loader sheds the 6 OLDEST tombstones to reach budget_for_completed =
/// 64 - 10 = 54. MUT2: evict live instead of completed → live count drops.
#[tokio::test]
async fn relay_terminal_excess_sheds_oldest_to_live_budget() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 1u32);
    install_group(&state, &gk, 0).await;
    let topic = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .expect("gk")
        .metadata_topic
        .clone();
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let base = unix_ms();

    // 10 live obligations.
    let live = build_entries(&requester_kp, &topic, &gk, &requester_hex, base, 10, 0);
    install_relay_entries(&state, &gk, &live, &requester_hex, base).await;

    // 60 completed tombstones with DISTINCT ascending first_seen_ms.
    let mut tombs: Vec<(RelayEntry, u64)> = Vec::new();
    for j in 0..60u32 {
        let fsm = base + 100 + j as u64;
        let e = build_relay_entry(
            &requester_kp,
            &topic,
            &gk,
            &format!("tmb-{}", j),
            &requester_hex,
            fsm,
            0,
        );
        tombs.push((e, fsm));
    }
    install_relay_tombstones(&state, &gk, &tombs, &requester_hex, base + 1000).await;

    save_relay(&state).await.expect("save");
    let r = restart_relay(&state).await;
    assert!(r.is_ok(), "within budget after shedding: {:?}", r);

    // All 10 live survive (never-evict-live).
    assert_eq!(
        relay_outbox_for_group(&state, &gk).await.len(),
        10,
        "all live survive"
    );
    // Tombstones pruned to 64 - 10 = 54.
    let surviving = state
        .completed_relay_tombstones
        .read()
        .await
        .get(&gk)
        .cloned()
        .unwrap_or_default();
    assert_eq!(surviving.len(), 54, "54 newest tombstones survive");
    let surviving_fsms: std::collections::HashSet<u64> =
        surviving.iter().map(|t| t.first_seen_ms).collect();
    // Oldest 6 (indices 0..5) shed; newest 54 (indices 6..59) survive.
    for j in 0..6u32 {
        assert!(
            !surviving_fsms.contains(&(base + 100 + j as u64)),
            "oldest shed: {}",
            j
        );
    }
    for j in 6..60u32 {
        assert!(
            surviving_fsms.contains(&(base + 100 + j as u64)),
            "newer survives: {}",
            j
        );
    }
}

// ===========================================================================
// Row 4 — conflict tombstones: deterministic oldest-first pruning.
// ===========================================================================

/// `prune_conflict_tombstones` keeps the newest 64 per group using
/// first_seen_ms. MUT2: remove the timestamp sort (16137) and eviction
/// becomes HashMap-order arbitrary.
#[tokio::test]
async fn conflict_tombstones_prune_oldest_first_with_timestamps() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 1u32);
    install_group(&state, &gk, 0).await;
    let base = unix_ms();

    // 70 conflict tombstones with distinct ascending first_seen_ms.
    {
        let mut tombs = state.causal_conflict_tombstones.write().await;
        let list = tombs.entry(gk.clone()).or_default();
        for j in 0..70u32 {
            list.push(ConflictTombstoneEntry {
                digest: [j as u8; 32],
                first_seen_ms: base + j as u64,
            });
        }
    }
    {
        let _g = state.causal_approval_queue_persistence_lock.lock().await;
        save_causal_approval_queue_unlocked(&state)
            .await
            .expect("save queue sidecar");
    }
    let r = restart_queue(&state).await;
    assert!(r.is_ok(), "queue loads after pruning: {:?}", r);

    let surviving = state
        .causal_conflict_tombstones
        .read()
        .await
        .get(&gk)
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        surviving.len(),
        CAUSAL_APPROVAL_PER_GROUP_CAP,
        "pruned to per-group cap"
    );
    let surviving_fsms: std::collections::HashSet<u64> =
        surviving.iter().map(|t| t.first_seen_ms).collect();
    for j in 0..6u32 {
        assert!(
            !surviving_fsms.contains(&(base + j as u64)),
            "oldest shed: {}",
            j
        );
    }
    for j in 6..70u32 {
        assert!(
            surviving_fsms.contains(&(base + j as u64)),
            "newer survives: {}",
            j
        );
    }
}

// ===========================================================================
// Row 7 — causal approval queue per-group COUNT cap (64 / 65)
// ===========================================================================

/// MUT2: remove the per-group count rejection (16750) and 65 entries survive.
#[tokio::test]
async fn causal_queue_per_group_count_64_accepted_then_65_rejected() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 1u32);
    install_group(&state, &gk, 0).await;
    // The local agent (creator) is the active admin signer.

    // --- GREEN: exactly 64 ---
    install_queue_entries(&state, &gk, 64).await;
    {
        let _g = state.causal_approval_queue_persistence_lock.lock().await;
        save_causal_approval_queue_unlocked(&state)
            .await
            .expect("save 64");
    }
    let r = restart_queue(&state).await;
    assert!(r.is_ok(), "64 queue entries at cap must load: {:?}", r);
    assert_eq!(queue_total(&state).await, 64);

    // --- RED: 65 in one group ---
    state.causal_approval_queue.write().await.clear();
    install_queue_entries(&state, &gk, 65).await;
    {
        let _g = state.causal_approval_queue_persistence_lock.lock().await;
        save_causal_approval_queue_unlocked(&state)
            .await
            .expect("save 65");
    }
    let before = queue_sidecar_bytes(&state).await;
    let r = restart_queue(&state).await;
    assert!(r.is_err(), "65 queue entries must be rejected: {:?}", r);
    assert_eq!(queue_total(&state).await, 0, "zero installed");
    assert_eq!(queue_sidecar_bytes(&state).await, before, "bytes preserved");
}

// ===========================================================================
// Row 7 — causal approval queue daemon-wide COUNT cap (1024 / 1025)
// ===========================================================================

/// MUT2: raise CAUSAL_APPROVAL_PER_DAEMON_CAP past 1025.
#[tokio::test]
async fn causal_queue_daemon_count_cap_1024_accepted_then_1025_rejected() {
    let (state, _dir) = s_state().await;

    // --- GREEN: 1024 across 16 groups × 64 ---
    for gi in 0..16u32 {
        let gk = format!("{:032x}", gi);
        install_group(&state, &gk, 0).await;
        install_queue_entries(&state, &gk, 64).await;
    }
    {
        let _g = state.causal_approval_queue_persistence_lock.lock().await;
        save_causal_approval_queue_unlocked(&state)
            .await
            .expect("save 1024");
    }
    let r = restart_queue(&state).await;
    assert!(
        r.is_ok(),
        "1024 queue entries at daemon cap must load: {:?}",
        r
    );
    assert_eq!(queue_total(&state).await, 1024);

    // --- RED: one more in a 17th group → 1025 ---
    let gk17 = format!("{:032x}", 17u32);
    install_group(&state, &gk17, 0).await;
    install_queue_entries(&state, &gk17, 1).await;
    {
        let _g = state.causal_approval_queue_persistence_lock.lock().await;
        save_causal_approval_queue_unlocked(&state)
            .await
            .expect("save 1025");
    }
    let before = queue_sidecar_bytes(&state).await;
    let r = restart_queue(&state).await;
    assert!(r.is_err(), "1025 queue entries must be rejected: {:?}", r);
    assert_eq!(queue_total(&state).await, 0, "zero installed");
    assert_eq!(queue_sidecar_bytes(&state).await, before, "bytes preserved");
}

// ===========================================================================
// Row 6 — high-expansion within-budget reload under the derived ×16 guard.
// ===========================================================================

/// The file-size guard (RELAY_SIDECAR_FILE_SIZE_CAP = byte_cap × 16) must
/// accommodate the ×4 JSON expansion of Vec<u8> as number arrays. A sidecar
/// whose raw envelope bytes are within the daemon byte cap but whose JSON
/// file is several times larger must load. MUT2: tighten the guard to ×2.
#[tokio::test]
async fn relay_high_expansion_within_budget_reloads_under_file_guard() {
    let (state, _dir) = s_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let pad = 55_000usize;
    // 4 groups × 16 entries × ~55 KB → ~3.9 MB raw, ~16 MB JSON (×4).
    for gi in 0..4u32 {
        let gk = format!("{:032x}", gi);
        install_group(&state, &gk, 0).await;
        let topic = state
            .named_groups
            .read()
            .await
            .get(&gk)
            .expect("gk")
            .metadata_topic
            .clone();
        let entries = build_entries(&requester_kp, &topic, &gk, &requester_hex, now, 16, pad);
        let gp_bytes: usize = entries.iter().map(|e| e.byte_size).sum();
        assert!(
            gp_bytes <= CAUSAL_RELAY_OUTBOX_PER_GROUP_BYTE_CAP,
            "per-group bytes OK"
        );
        install_relay_entries(&state, &gk, &entries, &requester_hex, now).await;
    }
    let raw_bytes: usize = state
        .predecessor_relay_outbox
        .read()
        .await
        .values()
        .flatten()
        .map(|o| o.byte_size)
        .sum();
    assert!(
        raw_bytes <= CAUSAL_RELAY_OUTBOX_PER_DAEMON_BYTE_CAP,
        "raw within daemon byte cap"
    );
    save_relay(&state).await.expect("save high-expansion");
    let file_bytes = relay_sidecar_bytes(&state).await.len();
    assert!(
        file_bytes > raw_bytes * 2,
        "JSON expansion significant (file {} > raw {} × 2)",
        file_bytes,
        raw_bytes
    );
    assert!(
        file_bytes <= RELAY_SIDECAR_FILE_SIZE_CAP,
        "within ×16 guard"
    );
    let r = restart_relay(&state).await;
    assert!(
        r.is_ok(),
        "high-expansion within-budget sidecar must load: {:?}",
        r
    );
    assert_eq!(
        relay_outbox_total(&state).await,
        64,
        "all 64 entries installed"
    );
}

// ===========================================================================
// Row 10 — atomic write stages (real POSIX permission seams).
// ===========================================================================

/// Parent dir 0o500 (r+x, no write): temp creation fails BEFORE rename,
/// destination unchanged. MUT2: return Durable on create failure.
#[tokio::test]
async fn atomic_write_pre_rename_0o500_leaves_seed_unchanged() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("atomic_pre.json");
    tokio::fs::write(&path, b"SEED_BYTES_NOT_REPLACED")
        .await
        .expect("seed");
    let _guard = PermGuard::arm(dir.path(), 0o500, 0o700).await;

    let outcome = write_named_groups_json_atomic(&path, "{\"replaced\":true}")
        .await
        .expect("no io err");
    assert_eq!(
        outcome,
        AtomicWriteOutcome::NotReplaced,
        "pre-rename failure"
    );
    let after = tokio::fs::read(&path).await.expect("read seed");
    assert_eq!(after, b"SEED_BYTES_NOT_REPLACED", "destination unchanged");
}

/// Parent dir 0o300 (w+x, no read): rename succeeds but
/// `sync_parent_dir_for_path` `File::open(parent)` fails EACCES →
/// ReplacedNotDurable with destination visibly replaced. MUT2: return
/// Durable when parent-fsync fails.
#[tokio::test]
async fn atomic_write_post_rename_0o300_reports_replaced_not_durable() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("atomic_rnd.json");
    let _guard = PermGuard::arm(dir.path(), 0o300, 0o700).await;

    let outcome = write_named_groups_json_atomic(&path, "{\"replaced\":true}")
        .await
        .expect("no io err");
    assert_eq!(
        outcome,
        AtomicWriteOutcome::ReplacedNotDurable,
        "rename OK, parent-fsync failed (RND)"
    );
    let after = tokio::fs::read(&path).await.expect("read replaced");
    assert_eq!(
        after, b"{\"replaced\":true}",
        "destination visibly replaced"
    );
}

// ===========================================================================
// Row 5 — detached B8 recovery journal validation.
// ===========================================================================

/// A pending_compensation journal referencing an unknown group is rejected
/// by the detached validation (17593). MUT2: skip journal validation.
#[tokio::test]
async fn relay_b8_journal_unknown_group_rejected_zero_installed() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 1u32);
    install_group(&state, &gk, 0).await;
    let topic = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .expect("gk")
        .metadata_topic
        .clone();
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let entry = build_relay_entry(&requester_kp, &topic, &gk, "seed-1", &requester_hex, now, 0);
    install_relay_entries(
        &state,
        &gk,
        std::slice::from_ref(&entry),
        &requester_hex,
        now,
    )
    .await;

    *state.pending_b8_compensation.lock().await = Some(PendingB8Compensation {
        group_id: format!("{:032x}", 0xDEADu32),
        request_id: "req-b8".to_string(),
        outbox_snapshot: Vec::new(),
        timestamp_ms: now,
        requester_agent_id: requester_hex,
        actor: local_hex(&state),
        predecessor_digest: [0u8; 32],
        approved_revision: 1,
        approved_state_hash: String::new(),
    });
    save_relay(&state).await.expect("save with bad B8 journal");
    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(
        r.is_err(),
        "B8 journal for unknown group must be rejected: {:?}",
        r
    );
    assert_eq!(relay_outbox_total(&state).await, 0, "zero installed");
    assert_eq!(relay_sidecar_bytes(&state).await, before, "bytes preserved");
}

// ===========================================================================
// Row 5 — detached listener admission journal digest mismatch.
// ===========================================================================

/// A pending_listener_admission with a digest ≠ blake3(envelope_bytes) is
/// rejected (17659). MUT2: skip the digest check.
#[tokio::test]
async fn relay_listener_journal_digest_mismatch_rejected_zero_installed() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 1u32);
    install_group(&state, &gk, 0).await;
    let topic = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .expect("gk")
        .metadata_topic
        .clone();
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let entry = build_relay_entry(&requester_kp, &topic, &gk, "seed-1", &requester_hex, now, 0);
    install_relay_entries(
        &state,
        &gk,
        std::slice::from_ref(&entry),
        &requester_hex,
        now,
    )
    .await;

    let env = sign_v2_envelope(
        &requester_kp,
        &topic,
        &predecessor_event(&gk, "lj-1", &requester_hex, now, None),
    );
    *state.pending_listener_admission.lock().await = Some(PendingListenerAdmission {
        group_id: gk,
        request_id: "lj-1".to_string(),
        requester_agent_id: requester_hex,
        envelope_bytes: env,
        digest: [0u8; 32], // wrong
        byte_size: 999,    // wrong
        first_seen_ms: now,
    });
    save_relay(&state)
        .await
        .expect("save with bad listener journal");
    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    assert!(
        r.is_err(),
        "listener journal digest mismatch must be rejected: {:?}",
        r
    );
    assert_eq!(relay_outbox_total(&state).await, 0, "zero installed");
    assert_eq!(relay_sidecar_bytes(&state).await, before, "bytes preserved");
}

// ===========================================================================
// Row 5 — dual-journal ordering: B8 validated BEFORE listener.
// ===========================================================================

/// The loader validates pending_compensation (17565) before
/// pending_listener_admission (17655). When BOTH are bad, the B8 error
/// surfaces. MUT2: swap the validation order.
#[tokio::test]
async fn relay_dual_journal_b8_validated_before_listener() {
    let (state, _dir) = s_state().await;
    let gk = format!("{:032x}", 1u32);
    install_group(&state, &gk, 0).await;
    let topic = state
        .named_groups
        .read()
        .await
        .get(&gk)
        .expect("gk")
        .metadata_topic
        .clone();
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let entry = build_relay_entry(&requester_kp, &topic, &gk, "seed-1", &requester_hex, now, 0);
    install_relay_entries(
        &state,
        &gk,
        std::slice::from_ref(&entry),
        &requester_hex,
        now,
    )
    .await;

    *state.pending_b8_compensation.lock().await = Some(PendingB8Compensation {
        group_id: format!("{:032x}", 0xBADC0DEu32),
        request_id: "req-dual".to_string(),
        outbox_snapshot: Vec::new(),
        timestamp_ms: now,
        requester_agent_id: requester_hex.clone(),
        actor: local_hex(&state),
        predecessor_digest: [0u8; 32],
        approved_revision: 1,
        approved_state_hash: String::new(),
    });
    *state.pending_listener_admission.lock().await = Some(PendingListenerAdmission {
        group_id: gk,
        request_id: "lj-dual".to_string(),
        requester_agent_id: requester_hex,
        envelope_bytes: vec![0u8; 10],
        digest: [0u8; 32],
        byte_size: 999,
        first_seen_ms: now,
    });
    save_relay(&state).await.expect("save dual journal");
    let before = relay_sidecar_bytes(&state).await;
    let r = restart_relay(&state).await;
    let err = r.expect_err("dual bad journals must be rejected");
    assert!(
        err.contains("B8 recovery journal"),
        "B8 journal error must surface before listener: got {err}",
    );
    assert_eq!(relay_outbox_total(&state).await, 0, "zero installed");
    assert_eq!(relay_sidecar_bytes(&state).await, before, "bytes preserved");
}
