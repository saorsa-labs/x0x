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

fn approval_event_with_welcome_pad(
    group_key: &str,
    request_id: &str,
    requester_hex: &str,
    actor_hex: &str,
    revision: u64,
    pad_len: usize,
) -> NamedGroupMetadataEvent {
    let mut event = approval_event(group_key, request_id, requester_hex, actor_hex, revision);
    if let NamedGroupMetadataEvent::JoinRequestApproved {
        treekem_welcome_b64,
        ..
    } = &mut event
    {
        *treekem_welcome_b64 = Some("P".repeat(pad_len));
    }
    event
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

fn build_relay_entry_exact_size(
    requester_kp: &AgentKeypair,
    topic: &str,
    group_key: &str,
    request_id: &str,
    requester_hex: &str,
    first_seen_ms: u64,
    exact_bytes: usize,
) -> RelayEntry {
    let probe = build_relay_entry(
        requester_kp,
        topic,
        group_key,
        request_id,
        requester_hex,
        first_seen_ms,
        1,
    );
    assert!(
        probe.byte_size <= exact_bytes,
        "exact envelope target {exact_bytes} is smaller than the valid probe {}",
        probe.byte_size
    );
    let pad_len = 1 + exact_bytes - probe.byte_size;
    let entry = build_relay_entry(
        requester_kp,
        topic,
        group_key,
        request_id,
        requester_hex,
        first_seen_ms,
        pad_len,
    );
    assert_eq!(
        entry.byte_size, exact_bytes,
        "ASCII welcome padding must produce the requested semantic byte size"
    );
    entry
}

fn build_exact_relay_entries(
    requester_kp: &AgentKeypair,
    topic: &str,
    group_key: &str,
    requester_hex: &str,
    first_seen_ms: u64,
    count: usize,
    exact_bytes: usize,
) -> Vec<RelayEntry> {
    (0..count)
        .map(|index| {
            let request_id = format!("x-{}-{index:04}", &group_key[..8]);
            build_relay_entry_exact_size(
                requester_kp,
                topic,
                group_key,
                &request_id,
                requester_hex,
                first_seen_ms,
                exact_bytes,
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

async fn relay_semantic_bytes(state: &AppState) -> usize {
    let live_bytes: usize = state
        .predecessor_relay_outbox
        .read()
        .await
        .values()
        .flatten()
        .map(|entry| entry.byte_size)
        .sum();
    let completed_bytes: usize = state
        .completed_relay_tombstones
        .read()
        .await
        .values()
        .flatten()
        .map(|entry| entry.envelope_bytes.len())
        .sum();
    live_bytes + completed_bytes
}

async fn relay_live_digests(state: &AppState) -> std::collections::HashSet<[u8; 32]> {
    state
        .predecessor_relay_outbox
        .read()
        .await
        .values()
        .flatten()
        .map(|entry| entry.digest)
        .collect()
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

async fn install_queue_entries_exact_size(
    state: &AppState,
    group_key: &str,
    count: usize,
    exact_bytes: usize,
) {
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
    let mut built = Vec::with_capacity(count);
    for index in 0..count {
        let request_id = format!("z-{}-{index:04}", &group_key[..8]);
        let probe_event = approval_event_with_welcome_pad(
            group_key,
            &request_id,
            &requester_hex,
            &admin_hex,
            1,
            1,
        );
        let probe = sign_v2_envelope(admin_kp, &topic, &probe_event);
        assert!(
            probe.len() <= exact_bytes,
            "exact queue envelope target {exact_bytes} is smaller than the valid probe {}",
            probe.len()
        );
        let pad_len = 1 + exact_bytes - probe.len();
        let event = approval_event_with_welcome_pad(
            group_key,
            &request_id,
            &requester_hex,
            &admin_hex,
            1,
            pad_len,
        );
        let envelope = sign_v2_envelope(admin_kp, &topic, &event);
        assert_eq!(
            envelope.len(),
            exact_bytes,
            "ASCII welcome padding must produce the requested queue byte size"
        );
        let digest: [u8; 32] = blake3::hash(&envelope).into();
        built.push((envelope, digest, request_id, event));
    }
    let mut queue = state.causal_approval_queue.write().await;
    let entries = queue.entry(group_key.to_string()).or_default();
    for (envelope, digest, request_id, event) in built {
        entries.push_back(PendingCausalApproval {
            byte_size: envelope.len(),
            envelope_bytes: envelope,
            digest,
            event,
            sender,
            first_seen_ms: now,
            expires_at_ms: now + 300_000,
            request_id,
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

async fn save_queue(state: &AppState) -> std::io::Result<AtomicWriteOutcome> {
    let _guard = state.causal_approval_queue_persistence_lock.lock().await;
    save_causal_approval_queue_unlocked(state).await
}

async fn queue_semantic_bytes(state: &AppState) -> usize {
    state
        .causal_approval_queue
        .read()
        .await
        .values()
        .flatten()
        .map(|entry| entry.byte_size)
        .sum()
}

async fn queue_live_digests(state: &AppState) -> std::collections::HashSet<[u8; 32]> {
    state
        .causal_approval_queue
        .read()
        .await
        .values()
        .flatten()
        .map(|entry| entry.digest)
        .collect()
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

/// MUT2: add one maximum-envelope grace to the per-group byte check in
/// `enforce_combined_relay_budget`; the minimal over-cap candidate survives.
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
    let cap = CAUSAL_RELAY_OUTBOX_PER_GROUP_BYTE_CAP;
    let exact_entry_bytes = CAUSAL_ENVELOPE_MAX_BYTES;
    let accepted_count = cap / exact_entry_bytes;
    assert_eq!(accepted_count, 16, "1 MiB is exactly 16 × 64 KiB");
    assert!(accepted_count < CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP);

    // --- GREEN: exactly 16 × 64 KiB = 1 MiB ---
    let entries = build_exact_relay_entries(
        &requester_kp,
        &topic,
        &gk,
        &requester_hex,
        now,
        accepted_count,
        exact_entry_bytes,
    );
    let total_bytes: usize = entries.iter().map(|e| e.byte_size).sum();
    assert_eq!(total_bytes, cap, "accepted semantic total is exactly 1 MiB");
    install_relay_entries(&state, &gk, &entries, &requester_hex, now).await;
    let accepted_digests = relay_live_digests(&state).await;
    save_relay(&state).await.expect("save under");
    let r = restart_relay(&state).await;
    assert!(r.is_ok(), "under per-group byte cap must load: {:?}", r);
    assert_eq!(
        relay_outbox_for_group(&state, &gk).await.len(),
        accepted_count
    );
    assert_eq!(relay_live_digests(&state).await, accepted_digests);

    // --- RED: exact 1 MiB plus one minimal valid envelope ---
    let mut over = entries.clone();
    over.push(build_relay_entry(
        &requester_kp,
        &topic,
        &gk,
        "over",
        &requester_hex,
        now,
        0,
    ));
    let over_bytes: usize = over.iter().map(|e| e.byte_size).sum();
    assert!(over_bytes > cap, "RED total exceeds byte cap");
    assert!(over.len() < CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP);
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

/// MUT2: add one maximum-envelope grace to the daemon byte check in
/// `enforce_combined_relay_budget`; the minimal over-cap candidate installs.
#[tokio::test]
async fn relay_daemon_byte_cap_boundary() {
    let (state, _dir) = s_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let daemon_cap = CAUSAL_RELAY_OUTBOX_PER_DAEMON_BYTE_CAP;
    let exact_entry_bytes = CAUSAL_ENVELOPE_MAX_BYTES;
    let accepted_count = daemon_cap / exact_entry_bytes;
    let per_group = CAUSAL_RELAY_OUTBOX_PER_GROUP_BYTE_CAP / exact_entry_bytes;
    assert_eq!(accepted_count, 256, "16 MiB is exactly 256 × 64 KiB");
    assert_eq!(per_group, 16, "1 MiB is exactly 16 × 64 KiB");

    // --- GREEN: 16 groups × 16 exact-size envelopes = 16 MiB ---
    for group_index in 0..16u32 {
        let gk = format!("{:032x}", group_index);
        install_group(&state, &gk, 0).await;
        let topic = state
            .named_groups
            .read()
            .await
            .get(&gk)
            .expect("gk")
            .metadata_topic
            .clone();
        let batch = build_exact_relay_entries(
            &requester_kp,
            &topic,
            &gk,
            &requester_hex,
            now,
            per_group,
            exact_entry_bytes,
        );
        install_relay_entries(&state, &gk, &batch, &requester_hex, now).await;
    }
    assert_eq!(
        relay_semantic_bytes(&state).await,
        daemon_cap,
        "accepted semantic total is exactly 16 MiB"
    );
    let accepted_digests = relay_live_digests(&state).await;
    save_relay(&state).await.expect("save under");
    let r = restart_relay(&state).await;
    assert!(r.is_ok(), "within daemon byte cap must load: {:?}", r);
    assert_eq!(relay_outbox_total(&state).await, accepted_count);
    assert_eq!(relay_live_digests(&state).await, accepted_digests);

    // --- RED: exact 16 MiB plus one minimal valid envelope ---
    let gk_over = format!("{:032x}", 16u32);
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
        0,
    );
    install_relay_entries(
        &state,
        &gk_over,
        std::slice::from_ref(&extra),
        &requester_hex,
        now,
    )
    .await;
    assert!(relay_semantic_bytes(&state).await > daemon_cap);
    assert!(relay_outbox_total(&state).await < CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP);
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
/// N×64 total targets. MUT2: raise the post-load cap from 4096 to 4097 and
/// 4097 targets survive restart. Asserts the SPECIFIC target-cap error to
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

    // --- RED: 65th group contributes exactly one target → 4097 ---
    let gk65 = format!("{:032x}", 65u32);
    install_group(&state, &gk65, 1).await;
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
    let expected_derived_targets = 64 * witnesses + 1;
    assert_eq!(
        expected_derived_targets, 4097,
        "the rejected arm crosses the target cap by exactly one"
    );
    save_relay(&state).await.expect("save 4097");
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

/// MUT2: permit one extra combined per-group record before terminal pruning.
/// The 64 live obligations must remain byte-for-byte represented by the same
/// digest set while the single completed tombstone is shed.
#[tokio::test]
async fn relay_terminal_per_group_count_64_live_plus_1_completed() {
    let (state, _dir) = s_state().await;
    let group_key = format!("{:032x}", 0x41u32);
    install_group(&state, &group_key, 0).await;
    let topic = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .expect("group")
        .metadata_topic
        .clone();
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let live = build_entries(
        &requester_kp,
        &topic,
        &group_key,
        &requester_hex,
        now,
        CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP,
        0,
    );
    install_relay_entries(&state, &group_key, &live, &requester_hex, now).await;
    let live_digests = relay_live_digests(&state).await;
    let completed = build_relay_entry(
        &requester_kp,
        &topic,
        &group_key,
        "terminal-count-group",
        &requester_hex,
        now + 1,
        0,
    );
    install_relay_tombstones(
        &state,
        &group_key,
        &[(completed, now + 1)],
        &requester_hex,
        now + 2,
    )
    .await;

    save_relay(&state)
        .await
        .expect("save 64 live plus terminal");
    restart_relay(&state)
        .await
        .expect("terminal-only count excess must be pruned");
    assert_eq!(relay_outbox_total(&state).await, 64);
    assert_eq!(relay_live_digests(&state).await, live_digests);
    assert!(
        state
            .completed_relay_tombstones
            .read()
            .await
            .values()
            .all(Vec::is_empty),
        "only the completed tombstone is shed"
    );
}

/// MUT2: permit one extra combined daemon record before terminal pruning. The
/// exact set of 1024 live obligations must survive while the 1025th terminal
/// record is discarded.
#[tokio::test]
async fn relay_terminal_daemon_count_1024_live_plus_1_completed() {
    let (state, _dir) = s_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    for group_index in 0..16u32 {
        let group_key = format!("{:032x}", 0x100u32 + group_index);
        install_group(&state, &group_key, 0).await;
        let topic = state
            .named_groups
            .read()
            .await
            .get(&group_key)
            .expect("group")
            .metadata_topic
            .clone();
        let live = build_entries(
            &requester_kp,
            &topic,
            &group_key,
            &requester_hex,
            now,
            CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP,
            0,
        );
        install_relay_entries(&state, &group_key, &live, &requester_hex, now).await;
    }
    assert_eq!(relay_outbox_total(&state).await, 1024);
    let live_digests = relay_live_digests(&state).await;

    let terminal_group = format!("{:032x}", 0x200u32);
    install_group(&state, &terminal_group, 0).await;
    let terminal_topic = state
        .named_groups
        .read()
        .await
        .get(&terminal_group)
        .expect("terminal group")
        .metadata_topic
        .clone();
    let completed = build_relay_entry(
        &requester_kp,
        &terminal_topic,
        &terminal_group,
        "terminal-count-daemon",
        &requester_hex,
        now + 1,
        0,
    );
    install_relay_tombstones(
        &state,
        &terminal_group,
        &[(completed, now + 1)],
        &requester_hex,
        now + 2,
    )
    .await;

    save_relay(&state)
        .await
        .expect("save 1024 live plus terminal");
    restart_relay(&state)
        .await
        .expect("daemon terminal-only count excess must be pruned");
    assert_eq!(relay_outbox_total(&state).await, 1024);
    assert_eq!(relay_live_digests(&state).await, live_digests);
    assert!(
        state
            .completed_relay_tombstones
            .read()
            .await
            .values()
            .all(Vec::is_empty),
        "only the daemon-wide terminal excess is shed"
    );
}

/// MUT2: add one maximum-envelope grace to combined per-group bytes before
/// terminal pruning. Exactly 1 MiB of live envelope data must survive unchanged.
#[tokio::test]
async fn relay_terminal_per_group_byte_boundary() {
    let (state, _dir) = s_state().await;
    let group_key = format!("{:032x}", 0x301u32);
    install_group(&state, &group_key, 0).await;
    let topic = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .expect("group")
        .metadata_topic
        .clone();
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let live = build_exact_relay_entries(
        &requester_kp,
        &topic,
        &group_key,
        &requester_hex,
        now,
        16,
        CAUSAL_ENVELOPE_MAX_BYTES,
    );
    install_relay_entries(&state, &group_key, &live, &requester_hex, now).await;
    assert_eq!(
        relay_semantic_bytes(&state).await,
        CAUSAL_RELAY_OUTBOX_PER_GROUP_BYTE_CAP
    );
    let live_digests = relay_live_digests(&state).await;
    let completed = build_relay_entry(
        &requester_kp,
        &topic,
        &group_key,
        "terminal-byte-group",
        &requester_hex,
        now + 1,
        0,
    );
    install_relay_tombstones(
        &state,
        &group_key,
        &[(completed, now + 1)],
        &requester_hex,
        now + 2,
    )
    .await;
    assert!(relay_semantic_bytes(&state).await > CAUSAL_RELAY_OUTBOX_PER_GROUP_BYTE_CAP);

    save_relay(&state)
        .await
        .expect("save 1 MiB live plus terminal");
    restart_relay(&state)
        .await
        .expect("terminal-only per-group byte excess must be pruned");
    assert_eq!(
        relay_semantic_bytes(&state).await,
        CAUSAL_RELAY_OUTBOX_PER_GROUP_BYTE_CAP
    );
    assert_eq!(relay_live_digests(&state).await, live_digests);
}

/// MUT2: add one maximum-envelope grace to combined daemon bytes before
/// terminal pruning. Exactly 16 MiB of live envelope data must survive unchanged.
#[tokio::test]
async fn relay_terminal_daemon_byte_boundary() {
    let (state, _dir) = s_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    for group_index in 0..16u32 {
        let group_key = format!("{:032x}", 0x400u32 + group_index);
        install_group(&state, &group_key, 0).await;
        let topic = state
            .named_groups
            .read()
            .await
            .get(&group_key)
            .expect("group")
            .metadata_topic
            .clone();
        let live = build_exact_relay_entries(
            &requester_kp,
            &topic,
            &group_key,
            &requester_hex,
            now,
            16,
            CAUSAL_ENVELOPE_MAX_BYTES,
        );
        install_relay_entries(&state, &group_key, &live, &requester_hex, now).await;
    }
    assert_eq!(
        relay_semantic_bytes(&state).await,
        CAUSAL_RELAY_OUTBOX_PER_DAEMON_BYTE_CAP
    );
    let live_digests = relay_live_digests(&state).await;

    let terminal_group = format!("{:032x}", 0x500u32);
    install_group(&state, &terminal_group, 0).await;
    let terminal_topic = state
        .named_groups
        .read()
        .await
        .get(&terminal_group)
        .expect("terminal group")
        .metadata_topic
        .clone();
    let completed = build_relay_entry(
        &requester_kp,
        &terminal_topic,
        &terminal_group,
        "terminal-byte-daemon",
        &requester_hex,
        now + 1,
        0,
    );
    install_relay_tombstones(
        &state,
        &terminal_group,
        &[(completed, now + 1)],
        &requester_hex,
        now + 2,
    )
    .await;
    assert!(relay_semantic_bytes(&state).await > CAUSAL_RELAY_OUTBOX_PER_DAEMON_BYTE_CAP);

    save_relay(&state)
        .await
        .expect("save 16 MiB live plus terminal");
    restart_relay(&state)
        .await
        .expect("terminal-only daemon byte excess must be pruned");
    assert_eq!(
        relay_semantic_bytes(&state).await,
        CAUSAL_RELAY_OUTBOX_PER_DAEMON_BYTE_CAP
    );
    assert_eq!(relay_live_digests(&state).await, live_digests);
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
// Row 7 — causal approval queue per-group BYTE cap (exact 1 MiB)
// ===========================================================================

/// MUT2: raise or omit the per-group byte rejection in
/// `load_causal_approval_queue`; the exact 1 MiB plus one valid envelope arm
/// then installs instead of rejecting the complete sidecar.
#[tokio::test]
async fn causal_queue_per_group_byte_cap_exact_1mib_accepted_rejected() {
    let (state, _dir) = s_state().await;
    let group_key = format!("{:032x}", 0x601u32);
    install_group(&state, &group_key, 0).await;
    let exact_entry_bytes = CAUSAL_ENVELOPE_MAX_BYTES;
    let accepted_count = CAUSAL_APPROVAL_PER_GROUP_BYTE_CAP / exact_entry_bytes;
    assert_eq!(accepted_count, 16);
    assert!(accepted_count < CAUSAL_APPROVAL_PER_GROUP_CAP);

    install_queue_entries_exact_size(&state, &group_key, accepted_count, exact_entry_bytes).await;
    assert_eq!(
        queue_semantic_bytes(&state).await,
        CAUSAL_APPROVAL_PER_GROUP_BYTE_CAP,
        "accepted causal semantic total is exactly 1 MiB"
    );
    let accepted_digests = queue_live_digests(&state).await;
    save_queue(&state).await.expect("save exact 1 MiB queue");
    restart_queue(&state)
        .await
        .expect("exact per-group causal byte cap must load");
    assert_eq!(queue_total(&state).await, accepted_count);
    assert_eq!(queue_live_digests(&state).await, accepted_digests);

    state.causal_approval_queue.write().await.clear();
    install_queue_entries_exact_size(&state, &group_key, accepted_count, exact_entry_bytes).await;
    install_queue_entries(&state, &group_key, 1).await;
    assert!(queue_semantic_bytes(&state).await > CAUSAL_APPROVAL_PER_GROUP_BYTE_CAP);
    assert!(queue_total(&state).await < CAUSAL_APPROVAL_PER_GROUP_CAP);
    save_queue(&state).await.expect("save over 1 MiB queue");
    let before = queue_sidecar_bytes(&state).await;
    let result = restart_queue(&state).await;
    assert!(result.is_err(), "over-cap causal group must be rejected");
    assert_eq!(queue_total(&state).await, 0, "zero entries installed");
    assert_eq!(queue_sidecar_bytes(&state).await, before, "bytes preserved");
}

// ===========================================================================
// Row 7 — causal approval queue daemon BYTE cap (exact 16 MiB)
// ===========================================================================

/// MUT2: raise or omit the daemon byte rejection in
/// `load_causal_approval_queue`; the exact 16 MiB plus one valid envelope arm
/// then installs instead of rejecting the complete sidecar.
#[tokio::test]
async fn causal_queue_daemon_byte_cap_exact_16mib_accepted_rejected() {
    let (state, _dir) = s_state().await;
    let exact_entry_bytes = CAUSAL_ENVELOPE_MAX_BYTES;
    let per_group = CAUSAL_APPROVAL_PER_GROUP_BYTE_CAP / exact_entry_bytes;
    for group_index in 0..16u32 {
        let group_key = format!("{:032x}", 0x700u32 + group_index);
        install_group(&state, &group_key, 0).await;
        install_queue_entries_exact_size(&state, &group_key, per_group, exact_entry_bytes).await;
    }
    assert_eq!(queue_total(&state).await, 256);
    assert_eq!(
        queue_semantic_bytes(&state).await,
        CAUSAL_APPROVAL_PER_DAEMON_BYTE_CAP,
        "accepted causal semantic total is exactly 16 MiB"
    );
    let accepted_digests = queue_live_digests(&state).await;
    save_queue(&state).await.expect("save exact 16 MiB queue");
    restart_queue(&state)
        .await
        .expect("exact daemon causal byte cap must load");
    assert_eq!(queue_total(&state).await, 256);
    assert_eq!(queue_live_digests(&state).await, accepted_digests);

    let over_group = format!("{:032x}", 0x800u32);
    install_group(&state, &over_group, 0).await;
    install_queue_entries(&state, &over_group, 1).await;
    assert!(queue_semantic_bytes(&state).await > CAUSAL_APPROVAL_PER_DAEMON_BYTE_CAP);
    assert!(queue_total(&state).await < CAUSAL_APPROVAL_PER_DAEMON_CAP);
    save_queue(&state).await.expect("save over 16 MiB queue");
    let before = queue_sidecar_bytes(&state).await;
    let result = restart_queue(&state).await;
    assert!(result.is_err(), "over-cap causal daemon must be rejected");
    assert_eq!(queue_total(&state).await, 0, "zero entries installed");
    assert_eq!(queue_sidecar_bytes(&state).await, before, "bytes preserved");
}

// ===========================================================================
// Row 6 — causal high expansion under the derived ×16 file guard.
// ===========================================================================

/// Both the signed envelope and the decoded event carry the large welcome
/// field. MUT2: tighten the queue loader threshold to half the semantic daemon
/// byte cap; the authenticated, within-budget queue then fails before validation.
#[tokio::test]
async fn causal_queue_high_expansion_within_budget_reloads_under_file_guard() {
    let (state, _dir) = s_state().await;
    let exact_entry_bytes = CAUSAL_ENVELOPE_MAX_BYTES;
    for group_index in 0..4u32 {
        let group_key = format!("{:032x}", 0x900u32 + group_index);
        install_group(&state, &group_key, 0).await;
        install_queue_entries_exact_size(&state, &group_key, 16, exact_entry_bytes).await;
    }
    let raw_bytes = queue_semantic_bytes(&state).await;
    assert_eq!(raw_bytes, 4 * 1024 * 1024);
    assert!(raw_bytes < CAUSAL_APPROVAL_PER_DAEMON_BYTE_CAP);
    let accepted_digests = queue_live_digests(&state).await;
    save_queue(&state)
        .await
        .expect("save high-expansion causal queue");
    let file_bytes = queue_sidecar_bytes(&state).await.len();
    assert!(
        file_bytes > raw_bytes * 2,
        "numeric envelope arrays plus decoded events expand the file: {file_bytes} > {}",
        raw_bytes * 2
    );
    assert!(file_bytes <= QUEUE_SIDECAR_FILE_SIZE_CAP);
    restart_queue(&state)
        .await
        .expect("within-budget high-expansion causal queue must reload");
    assert_eq!(queue_total(&state).await, 64);
    assert_eq!(queue_live_digests(&state).await, accepted_digests);
}

// ===========================================================================
// Row 6 — high-expansion within-budget reload under the derived ×16 guard.
// ===========================================================================

/// The file-size guard (RELAY_SIDECAR_FILE_SIZE_CAP = byte_cap × 16) must
/// accommodate the ×4 JSON expansion of Vec<u8> as number arrays. A sidecar
/// whose raw envelope bytes are within the daemon byte cap but whose JSON
/// file is several times larger must load. MUT2: tighten the relay loader
/// threshold to half the semantic daemon byte cap.
#[tokio::test]
async fn relay_high_expansion_within_budget_reloads_under_file_guard() {
    let (state, _dir) = s_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let now = unix_ms();
    let exact_entry_bytes = CAUSAL_ENVELOPE_MAX_BYTES;
    // 4 groups × 16 entries × 64 KiB = 4 MiB raw, with Vec<u8> JSON
    // number-array expansion well above ×2 but below the derived ×16 guard.
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
        let entries = build_exact_relay_entries(
            &requester_kp,
            &topic,
            &gk,
            &requester_hex,
            now,
            16,
            exact_entry_bytes,
        );
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
    assert_eq!(raw_bytes, 4 * 1024 * 1024);
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
