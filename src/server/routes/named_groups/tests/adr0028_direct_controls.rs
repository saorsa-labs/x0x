//! MiniMax direct ADR-0028 controls — the B1–B8 family against frozen `277505c`.
//!
//! Frozen red baseline: `277505ce2f38fd73bd26f1cb2650c8c4469c2dc8` (the
//! seven-residual + unwrap correction pass). This module replaces the prior
//! proxy rows (single-mutex timeout, static-review dedup, hand-built-only
//! concurrency) with direct behavioural controls that drive the REAL
//! production paths: the relay listener admission sequence, the finite relay
//! step (`causal_relay_step`), the durable save/load sidecar, the B8 approval
//! gate in `approve_join_request`, and the B8 journal/roster persistence.
//!
//! Failures are triggered by REAL mechanisms, never mocks:
//! - a read-only parent directory forces `save_predecessor_relay_outbox` to
//!   return `Err` (the production write path creates its temp file there);
//! - the `NAMED_GROUP_SAVE_AFTER_SNAPSHOT_NOTIFY` test hook gates the roster
//!   save so its failure can be interleaved after a successful outbox save;
//! - a loopback relay target (the local agent) makes a due obligation
//!   deterministically complete without any network peer;
//! - a `first_seen_ms` deep in the past exercises the restart expiry prune;
//! - tampered sidecar bytes exercise the loader's exact-journal rejection.
//!
//! Each control names the sole-catching mutation (`MUT-*`) it defends. A
//! control is RED at `277505c` when its named production blocker is live and
//! turns GREEN once the union correction lands; controls over behaviour
//! `277505c` already gets right are GREEN and redden only under their named
//! mutation. Envelopes are real requester-signed V2 wire bytes built with the
//! same public `ant_quic` ML-DSA-65 primitives production uses. No production
//! file is touched; no `cfg(test)` signing seam is added.

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

/// Identity-only `AppState` rooted at a fresh tempdir, with the local agent
/// as the group authority. Mirrors the sibling `b_state` helper.
pub(super) async fn d_state() -> (Arc<AppState>, tempfile::TempDir) {
    let (state, dir) = secure_endpoint_test_state().await.expect("secure state");
    (state, dir)
}

fn fresh_kp() -> AgentKeypair {
    AgentKeypair::generate().expect("agent keypair")
}

/// Build a real requester-signed V2 pub/sub envelope for `event` on `topic`.
///
/// This is a faithful, self-contained re-implementation of
/// `pubsub::encode_v2` + `pubsub::build_signing_payload` using only the
/// public `ant_quic` ML-DSA-65 signing primitives. The returned bytes
/// `decode_auto` to a `verified` `PubSubMessage` whose `sender` is
/// `kp.agent_id()` — exactly the wire shape the production relay listener
/// offers to the authority and the shape `decode_and_verify_v2` demands.
pub(super) fn sign_v2_envelope(
    kp: &AgentKeypair,
    topic: &str,
    event: &NamedGroupMetadataEvent,
) -> Vec<u8> {
    use ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa;

    let payload = serde_json::to_vec(event).expect("serialize event");
    let agent_id = kp.agent_id();
    let pub_bytes = kp.public_key().as_bytes();

    // Signing payload: b"x0x-msg-v2" || agent_id(32) || topic || payload
    let mut signing = Vec::with_capacity(10 + 32 + topic.len() + payload.len());
    signing.extend_from_slice(b"x0x-msg-v2");
    signing.extend_from_slice(agent_id.as_bytes());
    signing.extend_from_slice(topic.as_bytes());
    signing.extend_from_slice(&payload);
    let sig = sign_with_ml_dsa(kp.secret_key(), &signing).expect("ml-dsa sign");
    let sig_bytes = sig.as_bytes();
    let topic_bytes = topic.as_bytes();

    // Wire: 0x02 || agent_id(32) || lp(pubkey) || lp(sig) || lp(topic) || payload
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

/// A `JoinRequestCreated` predecessor event authored by `requester_hex` for
/// `group_key` (the group map key — the value the B8 gate compares the
/// decoded group_id against). `commit` is `None`: the B8 gate never inspects
/// the predecessor commit, only the request/requester/group_id binding.
fn predecessor_event(
    group_key: &str,
    request_id: &str,
    requester_hex: &str,
) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::JoinRequestCreated {
        group_id: group_key.to_string(),
        request_id: request_id.to_string(),
        requester_agent_id: requester_hex.to_string(),
        message: None,
        ts: unix_ms(),
        requester_kem_public_key_b64: None,
        treekem_key_package_b64: None,
        commit: None,
    }
}

/// Build a `PredecessorRelayObligation` from a real signed envelope, deriving
/// digest + byte_size from the envelope bytes (derive-not-trust) and the
/// relay target set from the group's active non-local members — exactly as
/// `src/server/mod.rs` does at the obligation-construction site (lines
/// ~1354-1392). `due_now` forces `next_retry_at_ms = first_seen_ms` so a
/// relay step picks the obligation up immediately.
fn obligation_from_envelope(
    info: &GroupInfo,
    local_hex: &str,
    envelope: Vec<u8>,
    request_id: &str,
    requester_hex: &str,
    due_now: bool,
) -> PredecessorRelayObligation {
    let now = unix_ms();
    let digest: [u8; 32] = blake3::hash(&envelope).into();
    let relay_targets = info
        .members_v2
        .iter()
        .filter(|(id, m)| {
            m.state == x0x::groups::GroupMemberState::Active && id.as_str() != local_hex
        })
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    let group_key = info.stable_group_id().to_string();
    PredecessorRelayObligation {
        envelope_bytes: envelope,
        digest,
        byte_size: 0, // replaced below
        first_seen_ms: now,
        next_retry_at_ms: if due_now { now } else { now + 60_000 },
        retry_count: 0,
        group_id: group_key.clone(),
        request_id: request_id.to_string(),
        requester_agent_id: requester_hex.to_string(),
        relay_targets,
        completed_at_ms: None,
    }
}

/// Real production predecessor-obligation creation path for the positive-path
/// fixture. Builds the requester-signed V2 `JoinRequestCreated` envelope,
/// constructs the obligation exactly as the relay listener does, inserts it
/// into the live outbox, and durably persists via the production save. No
/// sidecar is hand-built: the on-disk record is the serialized in-memory
/// state produced by `save_predecessor_relay_outbox`.
///
/// Returns the envelope bytes (for callers that want to re-derive the digest).
pub(super) async fn offer_predecessor_obligation_via_real_path(
    state: &AppState,
    group_key: &str,
    request_id: &str,
    requester_kp: &AgentKeypair,
) -> Vec<u8> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let (metadata_topic, info) = {
        let groups = state.named_groups.read().await;
        let info = groups
            .get(group_key)
            .expect("group must exist for predecessor obligation")
            .clone();
        (info.metadata_topic.clone(), info)
    };
    let event = predecessor_event(group_key, request_id, &requester_hex);
    let envelope = sign_v2_envelope(requester_kp, &metadata_topic, &event);
    let mut obl = obligation_from_envelope(
        &info,
        &local_hex,
        envelope.clone(),
        request_id,
        &requester_hex,
        true,
    );
    obl.byte_size = envelope.len();
    obl.group_id = group_key.to_string();
    {
        let mut groups = state.named_groups.write().await;
        let request = groups
            .get_mut(group_key)
            .and_then(|info| info.join_requests.get_mut(request_id))
            .expect("pending request must exist for predecessor obligation");
        request.predecessor_envelope_digest = Some(obl.digest);
        request.predecessor_first_seen_ms = Some(obl.first_seen_ms);
    }
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        outbox.entry(group_key.to_string()).or_default().push(obl);
    }
    // Production durable persist (mirrors mod.rs ~1451). A failure here would
    // mean the obligation is not durably recorded — surface it, do not swallow.
    save_predecessor_relay_outbox(state)
        .await
        .expect("predecessor relay outbox persist");
    envelope
}

/// Read the live outbox for `group_key`.
async fn outbox_snapshot(state: &AppState, group_key: &str) -> Vec<PredecessorRelayObligation> {
    state
        .predecessor_relay_outbox
        .read()
        .await
        .get(group_key)
        .cloned()
        .unwrap_or_default()
}

/// Read the completed tombstones for `group_key`.
async fn tombstone_snapshot(state: &AppState, group_key: &str) -> Vec<CompletedRelayTombstone> {
    state
        .completed_relay_tombstones
        .read()
        .await
        .get(group_key)
        .cloned()
        .unwrap_or_default()
}

async fn bind_pending_request_to_predecessor(
    state: &AppState,
    group_key: &str,
    request_id: &str,
    digest: [u8; 32],
    first_seen_ms: u64,
) {
    let mut groups = state.named_groups.write().await;
    let request = groups
        .get_mut(group_key)
        .and_then(|info| info.join_requests.get_mut(request_id))
        .expect("pending request must exist for predecessor binding");
    request.predecessor_envelope_digest = Some(digest);
    request.predecessor_first_seen_ms = Some(first_seen_ms);
}

/// Install a GSS group keyed by `group_key` (map key == stable id, as
/// production keys it) with the local agent as the sole admin and `requester`
/// as a pending join request. Returns the request id.
pub(super) async fn install_group_with_pending_request(
    state: &AppState,
    group_key: &str,
    requester_hex: &str,
) -> String {
    let admin_id = state.agent.agent_id();
    let mut info = GroupInfo::with_policy(
        "adr0028-direct".to_string(),
        String::new(),
        admin_id,
        group_key.to_string(),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
        group_key.to_string(),
        hex::encode(admin_id.as_bytes()),
        info.created_at,
        String::new(),
    ));
    info.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    let request = x0x::groups::JoinRequest::new(
        group_key.to_string(),
        requester_hex.to_string(),
        None,
        unix_ms(),
    );
    let request_id = request.request_id.clone();
    info.join_requests.insert(request_id.clone(), request);
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_key.to_string(), info);
    request_id
}

/// Install a GSS group with the local agent as admin PLUS one active non-local
/// witness `witness_hex` (so the relay target set is non-empty).
async fn install_group_with_witness(
    state: &AppState,
    group_key: &str,
    requester_hex: &str,
    witness_hex: &str,
) -> String {
    let request_id = install_group_with_pending_request(state, group_key, requester_hex).await;
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(group_key).expect("group");
        info.add_member(
            witness_hex.to_string(),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(state.agent.agent_id().as_bytes())),
            None,
        );
        info.recompute_state_hash();
    }
    request_id
}

/// Build a real, loader-valid `PredecessorRelayObligation` (real requester-signed
/// V2 envelope, derive-not-trust digest/byte_size) WITHOUT inserting or saving.
/// Lets the restart loader keep the record so restart assertions are meaningful.
async fn real_obligation(
    state: &AppState,
    group_key: &str,
    request_id: &str,
    requester_kp: &AgentKeypair,
    completed: bool,
    due_now: bool,
) -> PredecessorRelayObligation {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let metadata_topic = state
        .named_groups
        .read()
        .await
        .get(group_key)
        .expect("group")
        .metadata_topic
        .clone();
    let event = predecessor_event(group_key, request_id, &requester_hex);
    let envelope = sign_v2_envelope(requester_kp, &metadata_topic, &event);
    let now = unix_ms();
    PredecessorRelayObligation {
        digest: blake3::hash(&envelope).into(),
        byte_size: envelope.len(),
        envelope_bytes: envelope,
        first_seen_ms: now,
        next_retry_at_ms: if due_now {
            now
        } else {
            now.saturating_add(3_600_000)
        },
        retry_count: 0,
        group_id: group_key.to_string(),
        request_id: request_id.to_string(),
        requester_agent_id: requester_hex,
        relay_targets: vec![local_hex],
        completed_at_ms: completed.then_some(now),
    }
}

/// Drive the real `approve_join_request` handler and return the HTTP status.
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

/// Parent directory of the durable predecessor outbox sidecar — the directory
/// the production atomic-write helper creates its temp file in. Making this
/// read-only forces `save_predecessor_relay_outbox` to return `Err` for real.
fn outbox_parent(state: &AppState) -> PathBuf {
    state
        .predecessor_relay_outbox_path
        .parent()
        .expect("outbox path has a parent")
        .to_path_buf()
}

/// RAII guard: makes outbox saves fail (read-only parent, mode 0o500 — still
/// readable so `load_predecessor_relay_outbox` works) and restores write
/// permission on drop so the tempdir cleans up. Real I/O failure, not a mock.
struct SaveFailureGuard {
    parent: PathBuf,
}
impl SaveFailureGuard {
    async fn arm(state: &AppState) -> Self {
        let parent = outbox_parent(state);
        let _ = tokio::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).await;
        SaveFailureGuard { parent }
    }
}
impl Drop for SaveFailureGuard {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.parent, std::fs::Permissions::from_mode(0o700));
    }
}

/// Simulate a daemon restart of the relay outbox: drop in-memory live +
/// completed state and reload from the durable sidecar.
async fn restart_reload(state: &Arc<AppState>) {
    state.predecessor_relay_outbox.write().await.clear();
    state.completed_relay_tombstones.write().await.clear();
    load_predecessor_relay_outbox(state)
        .await
        .expect("restart relay outbox load");
}

// ===========================================================================
// B1 — real listener / admission path
// ===========================================================================
//
// The relay listener admits a requester-signed JoinRequestCreated, constructs
// the durable predecessor obligation exactly as `src/server/mod.rs`
// (~1330-1460) does, and persists it. Two controls:
//  (a) a real admitted obligation MUST satisfy the B8 approval gate (GREEN);
//  (b) when the group has NO active non-local witness the admitted obligation
//      has an empty target set and the live relay engine never retires it
//      (R1 / ADR Validation 3) — RED at 277505c.

// --- B1a: zero-target admitted obligation leaks in the live outbox (RED) ---
//
// MUT-zero-target-leak: the no-due prune in `causal_relay_step` retains
// `o.completed_at_ms.is_none() && retry_count < schedule.len()`. A
// zero-target obligation is skipped at the `relay_targets.is_empty()` guard,
// so `completed_at_ms` is never set and `retry_count` never advances. The
// retain keeps it forever — the obligation leaks in the live outbox.
#[tokio::test]
async fn b1_zero_target_obligation_from_real_admission_leaks_in_live_outbox() {
    let (state, _dir) = d_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    // No active non-local witness → the real construction path yields an
    // empty relay target set, exactly as the listener would for a
    // one-authority group.
    let group_key = "aa".repeat(16);
    let request_id = install_group_with_pending_request(&state, &group_key, &requester_hex).await;
    offer_predecessor_obligation_via_real_path(&state, &group_key, &request_id, &requester_kp)
        .await;

    causal_relay_step(&state).await;

    let live = outbox_snapshot(&state, &group_key).await;
    assert!(
        live.is_empty(),
        "MUT-zero-target-leak: a zero-target obligation admitted through the \
         real path has no remaining relay work and must be retired from the \
         live outbox by causal_relay_step, but {} leaked (the no-due prune \
         keeps completed_at_ms.is_none() entries, and a zero-target obligation \
         never reaches the completion path)",
        live.len(),
    );
}

// --- B1b: a real admitted obligation satisfies the B8 gate (GREEN) --------
//
// MUT-listener-rejects-all: a future commit that rejects every real listener
// envelope would manufacture no obligation, so the B8 gate would refuse the
// approval (412). This control stays GREEN at 277505c and reddens only if the
// real admission path stops creating an admittable obligation.
#[tokio::test]
async fn b1_real_admission_obligation_satisfies_b8_gate() {
    let (state, _dir) = d_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let witness_kp = fresh_kp();
    let witness_hex = hex::encode(witness_kp.agent_id().as_bytes());
    let group_key = "ab".repeat(16);
    let request_id =
        install_group_with_witness(&state, &group_key, &requester_hex, &witness_hex).await;

    // Real requester-signed envelope through the real construction path; the
    // obligation is B8-verifiable (decode + ML-DSA + bindings all hold).
    offer_predecessor_obligation_via_real_path(&state, &group_key, &request_id, &requester_kp)
        .await;

    let status = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        approve_status(&state, &group_key, &request_id),
    )
    .await
    .expect("real admission approval must complete within bounded wait");
    assert_eq!(
        status,
        StatusCode::OK,
        "MUT-listener-rejects-all: a real admitted predecessor obligation must \
         satisfy the B8 approval gate (got {status})"
    );
}

// ===========================================================================
// B2 — replay / admission lock-cycle (two-task reproduction)
// ===========================================================================
//
// The finite relay step (`causal_relay_step`) and the B8 admission refresh
// (`approve_join_request`) both touch the predecessor outbox under the same
// persistence mutex. A future commit that holds an outbox data lock while
// waiting for the persistence mutex (or vice-versa) inverts the order against
// the save helper (persistence-then-data) and deadlocks the two writers.
//
// This replaces the prior single-mutex-timeout proxy with a real two-task
// reproduction: one task drives the relay step to completion while a second
// drives an approval's B8 refresh, and we assert both converge without
// deadlock and leave consistent durable state.
//
// MUT-deadlock-lock-order: a future commit that takes the locks in the
// opposite order (data-while-holding-persistence) deadlocks these two tasks;
// the control would then hit the timeout. GREEN at 277505c.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b2_concurrent_replay_and_admission_converge_without_deadlock() {
    use std::time::Duration;
    use tokio::time::timeout;

    let (state, _dir) = d_state().await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let group_key = "b2".repeat(16);
    let request_id =
        install_group_with_witness(&state, &group_key, &requester_hex, &local_hex).await;

    // A due obligation with a loopback target so the relay step completes it
    // deterministically (no network peer required).
    offer_predecessor_obligation_via_real_path(&state, &group_key, &request_id, &requester_kp)
        .await;
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        if let Some(list) = outbox.get_mut(&group_key) {
            for o in list.iter_mut() {
                o.relay_targets = vec![local_hex.clone()];
                o.next_retry_at_ms = unix_ms();
            }
        }
    }

    // Two concurrent writers: the relay step and the B8 approval refresh.
    let relay_state = Arc::clone(&state);
    let relay = tokio::spawn(async move { causal_relay_step(&relay_state).await });
    let approve_state = Arc::clone(&state);
    let approve_key = group_key.clone();
    let approve_rid = request_id.clone();
    let approval =
        tokio::spawn(
            async move { approve_status(&approve_state, &approve_key, &approve_rid).await },
        );

    // If a future commit inverts the lock order, one of these times out.
    let relay_done = timeout(Duration::from_secs(15), relay).await;
    let approval_status = timeout(Duration::from_secs(15), approval).await;
    assert!(
        relay_done.is_ok(),
        "MUT-deadlock-lock-order: the relay step deadlocked against the \
         concurrent B8 admission refresh — the two writers must use one lock order"
    );
    assert!(
        approval_status.is_ok(),
        "MUT-deadlock-lock-order: the B8 admission refresh deadlocked against \
         the concurrent relay step — the two writers must use one lock order"
    );
    // Whichever way they interleaved, the durable state must be well-formed:
    // the request is no longer pending (approval observed a valid predecessor)
    // or was retired to a tombstone.
    let live = outbox_snapshot(&state, &group_key).await;
    let tombs = tombstone_snapshot(&state, &group_key).await;
    let approved = {
        let groups = state.named_groups.read().await;
        groups.get(&group_key).is_some_and(|i| {
            i.join_requests
                .get(&request_id)
                .is_some_and(|r| !r.is_pending())
        })
    };
    assert!(
        approved || !tombs.is_empty() || live.iter().any(|o| o.completed_at_ms.is_some()),
        "converged state must reflect either the approval or the relay completion"
    );
}

// ===========================================================================
// B3 — expiry-only durable restart
// ===========================================================================
//
// An obligation past the frozen 5-minute retention window
// (`first_seen_ms + CAUSAL_APPROVAL_RETENTION_MS <= now`) MUST be dropped on
// restart load. The live relay engine has no time-based expiry at 277505c
// (R1), but the restart loader DOES prune expired entries — so an
// expiry-only obligation survives in the sidecar yet vanishes after reload.
//
// MUT-loader-skip-expiry: if `load_predecessor_relay_outbox` stops dropping
// entries whose `first_seen_ms + RETENTION <= now`, the expired obligation
// survives restart and this control reddens. GREEN at 277505c.
#[tokio::test]
async fn b3_expired_obligation_survives_save_but_is_dropped_on_restart() {
    let (state, _dir) = d_state().await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let group_key = "b3".repeat(16);
    let request_id =
        install_group_with_witness(&state, &group_key, &requester_hex, &local_hex).await;

    // Real signed envelope so the loader's decode+verify would otherwise keep it.
    let (metadata_topic, info) = {
        let g = state.named_groups.read().await;
        let info = g.get(&group_key).unwrap().clone();
        (info.metadata_topic.clone(), info)
    };
    let event = predecessor_event(&group_key, &request_id, &requester_hex);
    let envelope = sign_v2_envelope(&requester_kp, &metadata_topic, &event);
    let mut obl = obligation_from_envelope(
        &info,
        &local_hex,
        envelope.clone(),
        &request_id,
        &requester_hex,
        true,
    );
    // Force expiry: first_seen deep in the past, beyond the 5-minute window.
    let expired_first_seen = unix_ms().saturating_sub(CAUSAL_APPROVAL_RETENTION_MS + 60_000);
    obl.first_seen_ms = expired_first_seen;
    obl.next_retry_at_ms = expired_first_seen;
    obl.byte_size = envelope.len();
    obl.group_id = group_key.clone();
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        outbox.insert(group_key.clone(), vec![obl]);
    }
    // Durable: the sidecar DOES contain the expired obligation before restart.
    save_predecessor_relay_outbox(&state).await.expect("save");
    assert!(
        !outbox_snapshot(&state, &group_key).await.is_empty(),
        "sanity: the expired obligation is present before restart"
    );

    // Restart: the loader must drop the expired entry.
    restart_reload(&state).await;
    let reloaded = outbox_snapshot(&state, &group_key).await;
    assert!(
        reloaded.is_empty(),
        "MUT-loader-skip-expiry: an obligation past the 5-minute retention \
         window must be dropped on durable restart (loader kept {})",
        reloaded.len(),
    );
}

// ===========================================================================
// B4 — no-due and due save-failure full rollback (incl. unrelated-group eviction)
// ===========================================================================
//
// `causal_relay_step` mutates the live outbox (and completed tombstones) and
// then calls `save_predecessor_relay_outbox`. On save failure it MUST restore
// the full pre-operation state across BOTH stores, including groups it pruned
// that were not part of the relay result. At 277505c the rollback is partial:
//  - the no-due path prunes in-memory then never restores on save failure;
//  - the due path restores only the snapshotted (due) groups, not unrelated
//    groups pruned by the daemon-wide retain;
//  - the tombstone rollback removes the FIRST digest match, so a pre-existing
//    tombstone sharing a just-added digest is wrongly deleted.
// All three are RED at 277505c.

// --- B4a: no-due save failure must roll back live memory (RED) ------------
//
// MUT-no-due-skip-rollback: the `due.is_empty()` branch prunes completed/
// exhausted obligations in-memory, then attempts `save_predecessor_relay_outbox`
// with no rollback on Err. Memory ends up pruned while disk still holds the
// pre-prune state — memory != disk.
#[tokio::test]
async fn b4_no_due_save_failure_must_roll_back_live_memory() {
    let (state, _dir) = d_state().await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let group_key = "b4a".repeat(10);
    let request_id =
        install_group_with_witness(&state, &group_key, &requester_hex, &local_hex).await;

    // A COMPLETED obligation (completed_at_ms set) whose next_retry is in the
    // future, so it is not due — `due` is empty and the no-due prune removes it.
    // Real signed envelope so the restart loader keeps the durable record.
    let obl = real_obligation(&state, &group_key, &request_id, &requester_kp, true, false).await;
    bind_pending_request_to_predecessor(
        &state,
        &group_key,
        &request_id,
        obl.digest,
        obl.first_seen_ms,
    )
    .await;
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        outbox.insert(group_key.clone(), vec![obl]);
    }
    save_predecessor_relay_outbox(&state)
        .await
        .expect("seed save");

    // Force every subsequent save to stop before replacement (real read-only parent).
    let guard = SaveFailureGuard::arm(&state).await;
    causal_relay_step(&state).await;

    let live = outbox_snapshot(&state, &group_key).await;
    assert!(
        live.iter().any(|o| o.completed_at_ms.is_some()),
        "MUT-no-due-skip-rollback: on a no-due save failure causal_relay_step \
         must restore the pre-prune live obligation, but memory was left pruned \
         ({} live) while disk still holds it",
        live.len(),
    );
    // Disk is untouched by the failed atomic write, so a restart shows the
    // obligation still present — the memory prune diverged from durable state.
    drop(guard);
    restart_reload(&state).await;
    let after_restart = outbox_snapshot(&state, &group_key).await;
    let terminal_after_restart = tombstone_snapshot(&state, &group_key).await;
    assert!(
        after_restart.iter().any(|o| o.request_id == request_id)
            || terminal_after_restart
                .iter()
                .any(|receipt| receipt.request_id == request_id),
        "the failed save must leave durable state unchanged (obligation present \
         as live or normalized terminal state on restart)"
    );
}

// --- B4b: due save failure must restore an unrelated group's prune (RED) --
//
// MUT-due-rollback-misses-unrelated-group: the due-path rollback restores only
// the snapshotted (due) groups. The daemon-wide prune that follows removes
// completed obligations from EVERY group, so an unrelated group's completed
// obligation is pruned but never restored on save failure.
#[tokio::test]
async fn b4_due_save_failure_must_restore_unrelated_group_prune() {
    let (state, _dir) = d_state().await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());

    // Group A: a DUE obligation (loopback target → completes deterministically).
    let req_a_kp = fresh_kp();
    let req_a = hex::encode(req_a_kp.agent_id().as_bytes());
    let key_a = "b4ba".repeat(10);
    let rid_a = install_group_with_witness(&state, &key_a, &req_a, &local_hex).await;
    let env_a = b"b4b-due-A".to_vec();
    let digest_a: [u8; 32] = blake3::hash(&env_a).into();
    let obl_a = PredecessorRelayObligation {
        envelope_bytes: env_a,
        digest: digest_a,
        byte_size: 64,
        first_seen_ms: unix_ms(),
        next_retry_at_ms: unix_ms(),
        retry_count: 0,
        group_id: key_a.clone(),
        request_id: rid_a,
        requester_agent_id: req_a,
        relay_targets: vec![local_hex.clone()],
        completed_at_ms: None,
    };
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        outbox.insert(key_a.clone(), vec![obl_a]);
    }

    // Group B (unrelated): a COMPLETED obligation that the daemon-wide prune
    // will remove — but B is not a due group, so it is never snapshotted and
    // never restored on save failure.
    let req_b_kp = fresh_kp();
    let req_b = hex::encode(req_b_kp.agent_id().as_bytes());
    let key_b = "b4bb".repeat(10);
    let rid_b = install_group_with_witness(&state, &key_b, &req_b, &local_hex).await;
    let env_b = b"b4b-completed-B".to_vec();
    let digest_b: [u8; 32] = blake3::hash(&env_b).into();
    let obl_b = PredecessorRelayObligation {
        envelope_bytes: env_b,
        digest: digest_b,
        byte_size: 64,
        first_seen_ms: unix_ms(),
        next_retry_at_ms: unix_ms().saturating_add(3_600_000),
        retry_count: 0,
        group_id: key_b.clone(),
        request_id: rid_b,
        requester_agent_id: req_b,
        relay_targets: vec![local_hex],
        completed_at_ms: Some(unix_ms()),
    };
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        outbox.insert(key_b.clone(), vec![obl_b]);
    }
    save_predecessor_relay_outbox(&state)
        .await
        .expect("seed save");

    let _guard = SaveFailureGuard::arm(&state).await;
    causal_relay_step(&state).await;

    let live_b = outbox_snapshot(&state, &key_b).await;
    assert!(
        live_b.iter().any(|o| o.completed_at_ms.is_some()),
        "MUT-due-rollback-misses-unrelated-group: the due-path save failure \
         must restore the unrelated group B's pruned obligation, but it was \
         left pruned in memory ({} live) while group A's snapshot was restored",
        live_b.len(),
    );
}

// --- B4c: due save-failure tombstone rollback must spare pre-existing (RED)
//
// MUT-dedup-rollback: the tombstone rollback removes the FIRST obligation whose
// digest matches a just-added tombstone. If a pre-existing tombstone shares
// that digest, the rollback deletes the pre-existing one and strands the
// just-added one. This is the live (no-fault-injection) reproduction: a due
// obligation whose envelope hashes to a pre-existing tombstone's digest
// completes, the just-added tombstone shares the digest, and the save failure
// rolls back the wrong row.
#[tokio::test]
async fn b4_due_save_failure_tombstone_rollback_must_remove_just_added_not_pre_existing() {
    let (state, _dir) = d_state().await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_key = "b4c".repeat(10);
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let request_id =
        install_group_with_witness(&state, &group_key, &requester_hex, &local_hex).await;

    // The completing obligation's envelope hashes to digest D.
    let env = b"b4c-shared-digest-envelope".to_vec();
    let digest_d: [u8; 32] = blake3::hash(&env).into();
    let obl = PredecessorRelayObligation {
        envelope_bytes: env.clone(),
        digest: digest_d,
        byte_size: env.len(),
        first_seen_ms: unix_ms(),
        next_retry_at_ms: unix_ms(),
        retry_count: 0,
        group_id: group_key.clone(),
        request_id: request_id.clone(),
        requester_agent_id: requester_hex.clone(),
        relay_targets: vec![local_hex],
        completed_at_ms: None,
    };
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        outbox.insert(group_key.clone(), vec![obl]);
    }
    // Pre-existing tombstone with the SAME digest D (request "pre").
    let pre_existing = CompletedRelayTombstone {
        group_id: group_key.clone(),
        request_id: "req-pre-existing".to_string(),
        requester_agent_id: requester_hex.clone(),
        digest: digest_d,
        first_seen_ms: unix_ms().saturating_sub(60_000),
        completed_at_ms: unix_ms().saturating_sub(60_000),
        envelope_bytes: b"pre-existing-envelope".to_vec(),
    };
    {
        let mut tombs = state.completed_relay_tombstones.write().await;
        tombs.insert(group_key.clone(), vec![pre_existing]);
    }
    save_predecessor_relay_outbox(&state)
        .await
        .expect("seed save");

    let _guard = SaveFailureGuard::arm(&state).await;
    causal_relay_step(&state).await;

    let tombs = tombstone_snapshot(&state, &group_key).await;
    let pre_survives = tombs
        .iter()
        .any(|t| t.request_id == "req-pre-existing" && t.digest == digest_d);
    assert!(
        pre_survives,
        "MUT-dedup-rollback: the save-failure tombstone rollback must remove \
         ONLY the just-added tombstone (the completing obligation's), not the \
         pre-existing one sharing digest D — production matches by digest and \
         removes the first occurrence. Tombstones: {tombs:?}"
    );
}

// ===========================================================================
// B5 — combined live + completed 1024 / 16 MiB bound, newest retention, restart
// ===========================================================================
//
// One relay budget covers live obligations PLUS completed receipts together:
// at most 1,024 retained envelopes and 16 MiB of envelope material per daemon,
// with eviction retaining the NEWEST completed receipts. At 277505c the loader
// bounds only the live outbox; completed tombstones are loaded verbatim with
// no count/byte/time cap, so the combined population grows without bound.
//
// MUT-completed-unbounded: there is no daemon-wide cap on
// `completed_relay_tombstones`. This control fills completed receipts across
// many groups past the 1,024 daemon count and asserts the combined retained
// population is bounded with newest retention. RED at 277505c.
#[tokio::test]
async fn b5_completed_store_is_unbounded_across_groups_and_restart() {
    let (state, _dir) = d_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());

    // Spread completed receipts across many groups so the per-group cap cannot
    // disguise the missing daemon-wide bound. Total > 1,024.
    let groups = 33usize;
    let per_group = (CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP / groups) + 2;
    let base_ms = unix_ms();
    let mut total = 0usize;
    {
        let mut store = state.completed_relay_tombstones.write().await;
        for g in 0..groups {
            let key = make_hex_id(0xb500 + g as u64);
            let mut list = Vec::with_capacity(per_group);
            for i in 0..per_group {
                let env = format!("b5-g{g}-i{i}").into_bytes();
                let digest: [u8; 32] = blake3::hash(&env).into();
                list.push(CompletedRelayTombstone {
                    group_id: key.clone(),
                    request_id: format!("req-b5-{g}-{i}"),
                    requester_agent_id: requester_hex.clone(),
                    digest,
                    first_seen_ms: base_ms.wrapping_add((g as u64) * per_group as u64 + i as u64),
                    // Newer envelopes carry a larger completed_at_ms so the
                    // "retain newest" policy is well-defined.
                    completed_at_ms: base_ms.wrapping_add((g as u64) * per_group as u64 + i as u64),
                    envelope_bytes: env,
                });
                total += 1;
            }
            store.insert(key, list);
        }
    }
    // Also install the corresponding named groups so the loader treats them known.
    {
        let mut groups_map = state.named_groups.write().await;
        for g in 0..groups {
            let key = make_hex_id(0xb500 + g as u64);
            let admin_id = state.agent.agent_id();
            let mut info = GroupInfo::with_policy(
                "b5".to_string(),
                String::new(),
                admin_id,
                key.clone(),
                x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
            );
            info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
                key.clone(),
                hex::encode(admin_id.as_bytes()),
                info.created_at,
                String::new(),
            ));
            info.secure_plane = x0x::mls::SecureGroupPlane::Gss;
            groups_map.insert(key, info);
        }
    }
    assert!(
        total > CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP,
        "seeded past cap"
    );
    save_predecessor_relay_outbox(&state).await.expect("save");
    state.completed_relay_tombstones.write().await.clear();
    load_predecessor_relay_outbox(&state)
        .await
        .expect("bounded completed relay outbox load");

    let retained: usize = state
        .completed_relay_tombstones
        .read()
        .await
        .values()
        .map(Vec::len)
        .sum();
    assert!(
        retained <= CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP,
        "MUT-completed-unbounded: completed receipts plus live obligations \
         must be bounded to {} per daemon with newest retention; production \
         loaded {} completed receipts verbatim (no daemon-wide cap), so the \
         combined population exceeds the relay budget",
        CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP,
        retained,
    );
}

// --- B5 byte boundary: large completed material discards live obligations (RED)
//
// Because completed receipts carry their full envelope bytes AND are never
// capped, unbounded growth lets the shared sidecar exceed the 2× daemon byte
// guard (32 MiB). At that point the loader's whole-file guard discards the
// ENTIRE file — including still-LIVE obligations — losing live relay state
// alongside the unbounded completed store. This is the R2 consequence named in
// the 277505c disposition: "once the shared sidecar exceeds 32 MiB the restart
// guard discards the ENTIRE file incl. still-live obligations."
//
// (A direct ">16 MiB retained" assertion is not observable at 277505c:
// `Vec<u8>` serializes as a JSON number array (~4×), so any payload past the
// 16 MiB byte cap already blows the file past the 32 MiB whole-file guard,
// shadowing the per-record cap. The whole-file discard IS the byte/material
// failure mode the unbounded completed store produces.)
//
// MUT-completed-unbounded-whole-file-discard: no completed cap → the sidecar
// crosses the whole-file guard → live obligations are discarded on restart.
// RED at 277505c.
#[tokio::test]
async fn b5_unbounded_completed_material_discards_live_obligations_on_restart() {
    let (state, _dir) = d_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let live_key = make_hex_id(0xb5c0);
    let live_rid = install_group_with_witness(
        &state,
        &live_key,
        &requester_hex,
        &hex::encode(state.agent.agent_id().as_bytes()),
    )
    .await;
    // A real, valid live obligation that the loader would otherwise keep.
    offer_predecessor_obligation_via_real_path(&state, &live_key, &live_rid, &requester_kp).await;
    assert!(
        !outbox_snapshot(&state, &live_key).await.is_empty(),
        "sanity: live obligation present before restart"
    );

    // Completed receipts large enough that the serialized sidecar crosses the
    // 2× daemon byte guard (32 MiB). Vec<u8> serializes as a JSON number array
    // (~3× bloat), so size for 3× and add margin to clear the guard reliably.
    let big = vec![0u8; 1024 * 1024];
    let over_guard = (2 * CAUSAL_RELAY_OUTBOX_PER_DAEMON_BYTE_CAP / 3 / big.len()) + 4;
    let tomb_key = make_hex_id(0xb5c1);
    let admin_id = state.agent.agent_id();
    let mut info = GroupInfo::with_policy(
        "b5c".to_string(),
        String::new(),
        admin_id,
        tomb_key.clone(),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
        tomb_key.clone(),
        hex::encode(admin_id.as_bytes()),
        info.created_at,
        String::new(),
    ));
    info.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    state
        .named_groups
        .write()
        .await
        .insert(tomb_key.clone(), info);
    let mut list = Vec::with_capacity(over_guard);
    for i in 0..over_guard {
        let mut env = big.clone();
        env[0] = i as u8;
        let digest: [u8; 32] = blake3::hash(&env).into();
        list.push(CompletedRelayTombstone {
            group_id: tomb_key.clone(),
            request_id: format!("req-b5c-{i}"),
            requester_agent_id: requester_hex.clone(),
            digest,
            first_seen_ms: unix_ms().wrapping_add(i as u64),
            completed_at_ms: unix_ms().wrapping_add(i as u64),
            envelope_bytes: env,
        });
    }
    state
        .completed_relay_tombstones
        .write()
        .await
        .insert(tomb_key, list);
    save_predecessor_relay_outbox(&state).await.expect("save");
    restart_reload(&state).await;

    let live_after = outbox_snapshot(&state, &live_key).await;
    assert!(
        !live_after.is_empty(),
        "MUT-completed-unbounded-whole-file-discard: unbounded completed \
         material pushed the sidecar past the 32 MiB whole-file guard, so the \
         loader discarded the ENTIRE file including the still-LIVE obligation \
         ({} live after restart) — live relay state must never be lost to \
         completed-store growth",
        live_after.len(),
    );
}

// ===========================================================================
// B6 — exact-journal mismatch and recovery-write failure
// ===========================================================================
//
// The durable predecessor journal (the relay-outbox sidecar) must be EXACT and
// atomic: a tampered record is rejected on load, and a failed recovery write
// leaves the prior journal intact with no completion acknowledged. Both hold
// at 277505c (the loader is derive-not-trust and the save is atomic) — these
// are GREEN controls that redden only under their named mutation.

// --- B6a: a tampered journal entry is dropped on load (GREEN control) -----
//
// MUT-loader-trust-tampered-journal: if the loader stops re-deriving each
// digest from the envelope bytes (the `entry.digest = derived_digest.into();`
// line), a tombstone whose stored digest does not match its envelope survives
// restart. This control confirms the exact-journal rejection.
#[tokio::test]
async fn b6_tampered_journal_entry_is_dropped_on_load() {
    let (state, _dir) = d_state().await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let group_key = "b6a".repeat(10);
    let request_id =
        install_group_with_witness(&state, &group_key, &requester_hex, &local_hex).await;

    // A valid live obligation (real signed envelope) plus a tampered one whose
    // stored digest deliberately does NOT match its envelope bytes.
    let (metadata_topic, info) = {
        let g = state.named_groups.read().await;
        let info = g.get(&group_key).unwrap().clone();
        (info.metadata_topic.clone(), info)
    };
    let event = predecessor_event(&group_key, &request_id, &requester_hex);
    let envelope = sign_v2_envelope(&requester_kp, &metadata_topic, &event);
    let valid = obligation_from_envelope(
        &info,
        &local_hex,
        envelope,
        &request_id,
        &requester_hex,
        true,
    );
    let tampered_env = b"b6-tampered".to_vec();
    let tampered = PredecessorRelayObligation {
        envelope_bytes: tampered_env.clone(),
        // Deliberately WRONG digest — does not match blake3(envelope).
        digest: [0x99; 32],
        byte_size: tampered_env.len(),
        first_seen_ms: unix_ms(),
        next_retry_at_ms: unix_ms().saturating_add(60_000),
        retry_count: 0,
        group_id: group_key.clone(),
        request_id: "req-tampered".to_string(),
        requester_agent_id: requester_hex,
        relay_targets: vec![local_hex],
        completed_at_ms: None,
    };
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        outbox.insert(group_key.clone(), vec![valid, tampered]);
    }
    save_predecessor_relay_outbox(&state).await.expect("save");
    restart_reload(&state).await;

    let reloaded = outbox_snapshot(&state, &group_key).await;
    let tampered_survived = reloaded.iter().any(|o| o.digest == [0x99; 32]);
    assert!(
        !tampered_survived,
        "MUT-loader-trust-tampered-journal: a record whose stored digest does \
         not match blake3(envelope) must be dropped on load (derive-not-trust)"
    );
}

// --- B6b: a failed recovery write leaves the journal intact (GREEN) -------
//
// MUT-count-before-persist: if the relay step counted `record_causal_relayed`
// before the durable write succeeded, a failed save would still acknowledge
// completion. The production path saves first and returns before counting on
// Err, so a failed recovery write leaves the prior journal intact and counts
// nothing. GREEN at 277505c.
#[tokio::test]
async fn b6_recovery_write_failure_leaves_journal_intact_and_counts_nothing() {
    let (state, _dir) = d_state().await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let group_key = "b6b".repeat(10);
    let request_id =
        install_group_with_witness(&state, &group_key, &requester_hex, &local_hex).await;

    // Seed a durable valid obligation (the intact prior journal).
    offer_predecessor_obligation_via_real_path(&state, &group_key, &request_id, &requester_kp)
        .await;
    let before = outbox_snapshot(&state, &group_key).await;

    // Make the obligation due with no remaining targets so the relay step
    // terminalizes it without a network wait, then tries the recovery write.
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        if let Some(list) = outbox.get_mut(&group_key) {
            for o in list.iter_mut() {
                o.relay_targets.clear();
                o.next_retry_at_ms = unix_ms();
            }
        }
    }
    let guard = SaveFailureGuard::arm(&state).await;
    tokio::time::timeout(std::time::Duration::from_secs(5), causal_relay_step(&state))
        .await
        .expect("bounded relay recovery step");
    drop(guard);

    // The failed atomic write must leave the prior journal intact.
    restart_reload(&state).await;
    let after = outbox_snapshot(&state, &group_key).await;
    assert_eq!(
        after.len(),
        before.len(),
        "a failed recovery write must leave the prior journal intact (got {})",
        after.len()
    );
    // And no completion may be acknowledged for a write that never went durable:
    // the rollback must have removed the just-added completed tombstone, so the
    // durable receipt store stays empty. (The internal record_causal_relayed
    // counter is gated on the same successful save — not observable here, but
    // the durable tombstone is the externally visible acknowledgement.)
    let receipts = tombstone_snapshot(&state, &group_key).await;
    assert!(
        receipts.is_empty(),
        "MUT-count-before-persist: a failed recovery write must not leave a \
         completed receipt behind (got {} tombstones)",
        receipts.len(),
    );
}

// ===========================================================================
// B7 — listener dirty-write interleaving
// ===========================================================================
//
// A mutates the outbox (insert A); B enters save and snapshots A+B; B's save
// succeeds (durable A+B); A's save then fails and A rolls back memory; a
// restart proves A absent and B present. At 277505c the persistence lock
// covers only the save snapshot, not the mutate→write transaction, so B's
// snapshot captures A's not-yet-committed mutation and A leaks into the
// durable file.
//
// MUT-drop-persistence-lock: the F7 lock holds only inside
// `save_predecessor_relay_outbox` (snapshot through rename). The caller mutates
// BEFORE acquiring it, so a concurrent save can durable-write another caller's
// uncommitted mutation. RED at 277505c.

// --- B7: one relay transaction excludes another group's dirty candidate ---
#[tokio::test]
async fn b7_relay_transaction_excludes_cross_group_dirty_write() {
    let (state, _dir) = d_state().await;
    let kp_a = fresh_kp();
    let kp_b = fresh_kp();
    let witness_a = fresh_kp();
    let witness_b = fresh_kp();
    let req_a = hex::encode(kp_a.agent_id().as_bytes());
    let req_b = hex::encode(kp_b.agent_id().as_bytes());
    let key_a = "b7a".repeat(10);
    let key_b = "b7b".repeat(10);
    let rid_a = install_group_with_witness(
        &state,
        &key_a,
        &req_a,
        &hex::encode(witness_a.agent_id().as_bytes()),
    )
    .await;
    let rid_b = install_group_with_witness(
        &state,
        &key_b,
        &req_b,
        &hex::encode(witness_b.agent_id().as_bytes()),
    )
    .await;
    let obligation_a = real_obligation(&state, &key_a, &rid_a, &kp_a, false, false).await;
    let obligation_b = real_obligation(&state, &key_b, &rid_b, &kp_b, false, false).await;
    let digest_a = obligation_a.digest;
    let digest_b = obligation_b.digest;
    bind_pending_request_to_predecessor(
        &state,
        &key_a,
        &rid_a,
        digest_a,
        obligation_a.first_seen_ms,
    )
    .await;
    bind_pending_request_to_predecessor(
        &state,
        &key_b,
        &rid_b,
        digest_b,
        obligation_b.first_seen_ms,
    )
    .await;

    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        outbox.insert(key_a.clone(), vec![obligation_a]);
    }
    let seed_outcome = save_predecessor_relay_outbox(&state)
        .await
        .expect("seed group A relay work");
    assert_eq!(seed_outcome, AtomicWriteOutcome::Durable);

    // Hold the production persistence mutex while group B's candidate exists.
    // The normal save helper must block before taking its snapshot. If its
    // internal lock is removed, it snapshots A+B here and durably leaks B even
    // though the transaction rolls B back before releasing the mutex.
    let persistence_guard = state.predecessor_relay_outbox_persistence_lock.lock().await;
    state
        .predecessor_relay_outbox
        .write()
        .await
        .insert(key_b.clone(), vec![obligation_b]);
    let save_state = Arc::clone(&state);
    let mut blocked_save =
        tokio::spawn(async move { save_predecessor_relay_outbox(&save_state).await });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(250), &mut blocked_save,)
            .await
            .is_err(),
        "MUT-drop-persistence-lock: the normal save helper must not snapshot \
         another group's in-flight candidate while the transaction mutex is held"
    );
    state.predecessor_relay_outbox.write().await.remove(&key_b);
    drop(persistence_guard);

    let save_outcome = tokio::time::timeout(std::time::Duration::from_secs(5), &mut blocked_save)
        .await
        .expect("blocked save must finish after the transaction releases")
        .expect("blocked save task")
        .expect("blocked save result");
    assert_eq!(save_outcome, AtomicWriteOutcome::Durable);

    restart_reload(&state).await;
    let a_present = outbox_snapshot(&state, &key_a)
        .await
        .iter()
        .any(|entry| entry.digest == digest_a)
        || tombstone_snapshot(&state, &key_a)
            .await
            .iter()
            .any(|entry| entry.digest == digest_a);
    let b_present = outbox_snapshot(&state, &key_b)
        .await
        .iter()
        .any(|entry| entry.digest == digest_b)
        || tombstone_snapshot(&state, &key_b)
            .await
            .iter()
            .any(|entry| entry.digest == digest_b);
    assert!(
        !b_present,
        "group B's rolled-back relay candidate must not become durable"
    );
    assert!(
        a_present,
        "group A's previously committed relay work must remain durable"
    );
}

// --- B7 control: an isolated failed save leaves no durable trace (GREEN) --
//
// The paired control: when no concurrent save captures A's mutation, A's
// failed save correctly leaves no durable trace. This isolates that the leak
// above is caused by B's intervening capture, not by the save itself.
#[tokio::test]
async fn b7_isolated_failed_save_leaves_no_durable_trace() {
    let (state, _dir) = d_state().await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let kp_a = fresh_kp();
    let req_a = hex::encode(kp_a.agent_id().as_bytes());
    let key_a = "b7c".repeat(10);
    let rid_a = install_group_with_witness(&state, &key_a, &req_a, &local_hex).await;
    let topic = state
        .named_groups
        .read()
        .await
        .get(&key_a)
        .unwrap()
        .metadata_topic
        .clone();
    let env_a = sign_v2_envelope(&kp_a, &topic, &predecessor_event(&key_a, &rid_a, &req_a));
    let digest_a: [u8; 32] = blake3::hash(&env_a).into();

    // A mutates, then its save fails BEFORE any other save captures it.
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        outbox.insert(
            key_a.clone(),
            vec![PredecessorRelayObligation {
                byte_size: env_a.len(),
                envelope_bytes: env_a,
                digest: digest_a,
                first_seen_ms: unix_ms(),
                next_retry_at_ms: unix_ms().saturating_add(60_000),
                retry_count: 0,
                group_id: key_a.clone(),
                request_id: rid_a,
                requester_agent_id: req_a,
                relay_targets: Vec::new(),
                completed_at_ms: None,
            }],
        );
    }
    let guard = SaveFailureGuard::arm(&state).await;
    let a_save = save_predecessor_relay_outbox(&state).await;
    assert!(
        !matches!(a_save, Ok(AtomicWriteOutcome::Durable)),
        "sanity: A's save must not become durable"
    );
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        if let Some(list) = outbox.get_mut(&key_a) {
            list.retain(|o| o.digest != digest_a);
        }
    }
    drop(guard);
    restart_reload(&state).await;
    let a_present = outbox_snapshot(&state, &key_a)
        .await
        .iter()
        .any(|o| o.digest == digest_a);
    assert!(
        !a_present,
        "an isolated failed save (no concurrent capture) must leave no \
         durable trace — A must be absent after restart"
    );
}

// ===========================================================================
// B8 — both persistence failure orders
// ===========================================================================
//
// `approve_join_request` mutates the roster, refreshes the predecessor outbox
// target set, then persists outbox BEFORE roster. Two failure orders must each
// roll back BOTH stores so no relay state derives from an approval the endpoint
// reported as aborted. At 277505c only the roster is rolled back in each order;
// the outbox refresh is left inconsistent — RED in both.

// MUT-B8-final-clock-before-journal: move `authorization_now_ms` above the
// `B8_BEFORE_FINAL_AUTHORIZATION_NOW_NOTIFY` barrier (or remove the final
// expiry check). The handler then authorizes with the stale pre-boundary time,
// installs PendingB8Compensation, and approves after the five-minute window.
// GREEN keeps the final clock sample and journal installation in the same
// non-suspending section after every potentially blocking lock acquisition.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b8_final_expiry_check_linearizes_with_journal_installation() {
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    let (state, _dir) = d_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let witness_hex = hex::encode(fresh_kp().agent_id().as_bytes());
    let group_key = "b8f1".repeat(8);
    let request_id =
        install_group_with_witness(&state, &group_key, &requester_hex, &witness_hex).await;

    offer_predecessor_obligation_via_real_path(&state, &group_key, &request_id, &requester_kp)
        .await;

    // Leave enough time for the first authenticated proof read to finish, but
    // little enough that the deterministic barrier crosses the retention edge.
    let first_seen_ms = unix_ms()
        .saturating_sub(CAUSAL_APPROVAL_RETENTION_MS)
        .saturating_add(1_500);
    {
        let mut groups = state.named_groups.write().await;
        let request = groups
            .get_mut(&group_key)
            .and_then(|group| group.join_requests.get_mut(&request_id))
            .expect("pending request");
        request.predecessor_first_seen_ms = Some(first_seen_ms);
    }
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        let obligation = outbox
            .get_mut(&group_key)
            .and_then(|entries| entries.first_mut())
            .expect("live predecessor obligation");
        obligation.first_seen_ms = first_seen_ms;
        obligation.next_retry_at_ms = first_seen_ms.saturating_add(60_000);
    }
    assert!(matches!(
        save_predecessor_relay_outbox(&state).await,
        Ok(AtomicWriteOutcome::Durable)
    ));
    assert!(matches!(
        save_named_groups_checked(&state).await,
        Ok(AtomicWriteOutcome::Durable)
    ));

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    *B8_BEFORE_FINAL_AUTHORIZATION_NOW_NOTIFY
        .lock()
        .expect("B8 final-authorization test hook poisoned") =
        Some((Arc::clone(&entered), Arc::clone(&release)));

    let approve_state = Arc::clone(&state);
    let approve_group = group_key.clone();
    let approve_request = request_id.clone();
    let approval = tokio::spawn(async move {
        approve_status(&approve_state, &approve_group, &approve_request).await
    });

    timeout(Duration::from_secs(5), entered.notified())
        .await
        .expect("B8 reached the final authorization barrier within 5s");
    sleep(Duration::from_millis(1_600)).await;
    release.notify_one();

    let status = timeout(Duration::from_secs(5), approval)
        .await
        .expect("B8 approval completed within 5s")
        .expect("B8 approval task did not panic");
    assert_eq!(
        status,
        StatusCode::PRECONDITION_FAILED,
        "MUT-B8-final-clock-before-journal: approval must be refused when the proof expires after lock acquisition but before the journal linearization point"
    );
    assert!(
        state.pending_b8_compensation.lock().await.is_none(),
        "an expired proof must never install PendingB8Compensation"
    );
    let groups = state.named_groups.read().await;
    let request = groups
        .get(&group_key)
        .and_then(|group| group.join_requests.get(&request_id))
        .expect("request survives refused approval");
    assert!(
        request.is_pending(),
        "the refused approval must restore the pending roster state"
    );
}

// --- B8 order 1: outbox-refresh save failure (RED) ------------------------
//
// MUT-b8-outbox-refresh-no-rollback: when `save_predecessor_relay_outbox`
// fails after the B8 target refresh, the roster is rolled back but the
// refreshed relay targets remain live in memory (and were never persisted).
// The approval returns 500 yet the obligation's target set reflects it.
#[tokio::test]
async fn b8_outbox_refresh_save_failure_leaves_refreshed_targets_in_memory() {
    let (state, _dir) = d_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    // An active witness so the obligation starts with a non-empty target set.
    let witness_kp = fresh_kp();
    let witness_hex = hex::encode(witness_kp.agent_id().as_bytes());
    let group_key = "b81".repeat(10);
    let request_id =
        install_group_with_witness(&state, &group_key, &requester_hex, &witness_hex).await;
    offer_predecessor_obligation_via_real_path(&state, &group_key, &request_id, &requester_kp)
        .await;

    let targets_before: Vec<String> = outbox_snapshot(&state, &group_key).await[0]
        .relay_targets
        .clone();

    // Force the outbox-refresh save to fail (the approval reaches the refresh,
    // mutates the roster + targets, then `save_predecessor_relay_outbox` Errs).
    let _guard = SaveFailureGuard::arm(&state).await;
    let status = approve_status(&state, &group_key, &request_id).await;
    drop(_guard);
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the outbox-refresh save failure must abort the approval (500)"
    );

    // The roster MUST be rolled back (request still pending) — this holds.
    let request_pending = {
        let groups = state.named_groups.read().await;
        groups
            .get(&group_key)
            .and_then(|i| i.join_requests.get(&request_id))
            .is_some_and(|r| r.is_pending())
    };
    assert!(
        request_pending,
        "the roster must be rolled back after the outbox-save failure"
    );

    // The refreshed relay targets MUST ALSO be rolled back — they are not.
    let targets_after = &outbox_snapshot(&state, &group_key).await[0].relay_targets;
    assert!(
        targets_after == &targets_before,
        "MUT-b8-outbox-refresh-no-rollback: the refreshed relay targets must be \
         rolled back alongside the roster, but the approval's target refresh \
         survived in memory (before {targets_before:?}, after {targets_after:?})"
    );
    assert!(
        !targets_after.contains(&requester_hex),
        "the requester (added by the aborted approval) must not remain a relay \
         target after the rollback"
    );
}

// --- B8 order 2: roster-save failure after a successful outbox save (RED) -
//
// MUT-b8-roster-fail-no-outbox-rollback: the outbox save succeeds (refreshed
// targets durable), then the roster save fails and rolls back only the roster.
// The durable outbox now carries refreshed targets for an approval the endpoint
// reported as aborted — durable state derives from a transition that did not
// happen.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b8_roster_save_failure_after_outbox_success_leaves_durable_outbox_for_aborted_approval() {
    use tokio::sync::Notify;

    let (state, _dir) = d_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let witness_kp = fresh_kp();
    let witness_hex = hex::encode(witness_kp.agent_id().as_bytes());
    let group_key = "b82".repeat(10);
    let request_id =
        install_group_with_witness(&state, &group_key, &requester_hex, &witness_hex).await;
    offer_predecessor_obligation_via_real_path(&state, &group_key, &request_id, &requester_kp)
        .await;

    // Gate the roster save: let the outbox save succeed, then flip the parent
    // read-only so save_named_groups_checked fails and approve rolls the roster
    // back — leaving the already-durable outbox refresh behind.
    let reached = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    {
        let mut hook = NAMED_GROUP_SAVE_AFTER_SNAPSHOT_NOTIFY
            .lock()
            .expect("hook lock");
        *hook = Some((Arc::clone(&reached), Arc::clone(&release)));
    }
    // The roster save writes named_groups.json in the DATA dir (not the
    // treekem dir the outbox sidecar lives in), so flip the data dir read-only
    // — the outbox save has already succeeded by the time the hook fires.
    let data_dir = state
        .named_groups_path
        .parent()
        .expect("named_groups_path has a parent")
        .to_path_buf();
    let reached_c = Arc::clone(&reached);
    let release_c = Arc::clone(&release);
    let orchestrator = tokio::spawn(async move {
        // Wait for the roster save to reach its post-snapshot hook point (the
        // outbox save has already succeeded by then), then force its write fail.
        reached_c.notified().await;
        *NAMED_GROUP_SAVE_AFTER_SNAPSHOT_NOTIFY
            .lock()
            .expect("hook lock") = None;
        let _ = tokio::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o500)).await;
        release_c.notify_one();
    });

    // Defensive timeout: a correct failure returns 503 fast; a hang means the
    // roster save did not fail and approve reached fan-out (a test bug).
    let status_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        approve_status(&state, &group_key, &request_id),
    )
    .await;
    if status_result.is_err() {
        orchestrator.abort();
    }
    assert!(
        status_result.is_ok(),
        "approve did not return within 5s — roster save did not fail"
    );
    let Ok(status) = status_result else {
        return;
    };
    // Restore writability + clear the hook regardless of outcome.
    let _ = tokio::fs::set_permissions(
        state.named_groups_path.parent().expect("parent"),
        std::fs::Permissions::from_mode(0o700),
    )
    .await;
    {
        let mut hook = NAMED_GROUP_SAVE_AFTER_SNAPSHOT_NOTIFY
            .lock()
            .expect("hook lock");
        *hook = None;
    }
    let _ = orchestrator.await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the roster-save failure must abort the approval (503)"
    );

    // Roster rolled back: the requester was never durably added as a member.
    let requester_is_member = {
        let groups = state.named_groups.read().await;
        groups
            .get(&group_key)
            .is_some_and(|i| i.members_v2.contains_key(&requester_hex))
    };
    assert!(
        !requester_is_member,
        "the roster must be rolled back (requester not a member) after the \
         roster-save failure"
    );

    // But the durable outbox was already refreshed — restart shows the
    // requester (added by the aborted approval) as a relay target.
    restart_reload(&state).await;
    let durable_targets: Vec<String> = outbox_snapshot(&state, &group_key)
        .await
        .into_iter()
        .flat_map(|o| o.relay_targets)
        .collect();
    assert!(
        !durable_targets.contains(&requester_hex),
        "MUT-b8-roster-fail-no-outbox-rollback: the durable outbox must NOT \
         carry refreshed targets for an aborted approval, but the requester \
         (added by the rolled-back approval) survived as a durable relay \
         target ({durable_targets:?})"
    );
}

// ===========================================================================
// Preserved controls — paired digest, malformed / no-obligation, restart
// ===========================================================================

// --- Exact digest refresh with two roster-bound records (GREEN control) ---
//
// Each live obligation must bind to its exact durable request, requester,
// first-observation time, and authenticated envelope digest. On restart the
// loader must still re-derive each digest from its own envelope bytes
// (derive-not-trust), so a tampered stored digest cannot survive.
//
// MUT-trust-stored-digest: if `load_predecessor_relay_outbox` stops
// overwriting `entry.digest` with `blake3(entry.envelope_bytes)`, a tampered
// stored digest survives and both records' digests would be wrong.
#[tokio::test]
async fn outbox_loader_refreshes_exact_digest_for_two_bound_records() {
    let (state, _dir) = d_state().await;
    let group_key = "dd".repeat(16);
    let kp_a = fresh_kp();
    let kp_b = fresh_kp();
    let witness_kp = fresh_kp();
    let req_a_hex = hex::encode(kp_a.agent_id().as_bytes());
    let req_b_hex = hex::encode(kp_b.agent_id().as_bytes());
    let witness_hex = hex::encode(witness_kp.agent_id().as_bytes());
    install_group_with_witness(&state, &group_key, &req_a_hex, &witness_hex).await;
    let metadata_topic = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .unwrap()
        .metadata_topic
        .clone();

    let request_id_a = "req-bound-a";
    let request_id_b = "req-bound-b";
    let ev_a = predecessor_event(&group_key, request_id_a, &req_a_hex);
    let ev_b = predecessor_event(&group_key, request_id_b, &req_b_hex);
    let env_a = sign_v2_envelope(&kp_a, &metadata_topic, &ev_a);
    let env_b = sign_v2_envelope(&kp_b, &metadata_topic, &ev_b);
    let real_digest_a: [u8; 32] = blake3::hash(&env_a).into();
    let real_digest_b: [u8; 32] = blake3::hash(&env_b).into();
    let first_seen_a = unix_ms();
    let first_seen_b = first_seen_a.saturating_add(1);

    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group_key).expect("group");
        info.join_requests.clear();
        let mut request_a =
            x0x::groups::JoinRequest::new(group_key.clone(), req_a_hex.clone(), None, first_seen_a);
        request_a.request_id = request_id_a.to_string();
        request_a.predecessor_envelope_digest = Some(real_digest_a);
        request_a.predecessor_first_seen_ms = Some(first_seen_a);
        let mut request_b =
            x0x::groups::JoinRequest::new(group_key.clone(), req_b_hex.clone(), None, first_seen_b);
        request_b.request_id = request_id_b.to_string();
        request_b.predecessor_envelope_digest = Some(real_digest_b);
        request_b.predecessor_first_seen_ms = Some(first_seen_b);
        info.join_requests
            .insert(request_a.request_id.clone(), request_a);
        info.join_requests
            .insert(request_b.request_id.clone(), request_b);
        info.recompute_state_hash();
    }

    let mk_obl = |env: Vec<u8>, request_id: &str, requester_hex: String, first_seen_ms: u64| {
        PredecessorRelayObligation {
            envelope_bytes: env.clone(),
            digest: [0xAA; 32], // deliberately WRONG — loader must overwrite it
            byte_size: env.len(),
            first_seen_ms,
            next_retry_at_ms: unix_ms() + 60_000,
            retry_count: 0,
            group_id: group_key.clone(),
            request_id: request_id.to_string(),
            requester_agent_id: requester_hex,
            relay_targets: vec![witness_hex.clone()],
            completed_at_ms: None,
        }
    };
    {
        let mut outbox = state.predecessor_relay_outbox.write().await;
        outbox.insert(
            group_key.clone(),
            vec![
                mk_obl(env_a, request_id_a, req_a_hex.clone(), first_seen_a),
                mk_obl(env_b, request_id_b, req_b_hex.clone(), first_seen_b),
            ],
        );
    }
    save_predecessor_relay_outbox(&state).await.expect("save");
    restart_reload(&state).await;

    let reloaded = outbox_snapshot(&state, &group_key).await;
    assert_eq!(
        reloaded.len(),
        2,
        "both exact roster-bound records must survive restart revalidation"
    );
    let digests: Vec<[u8; 32]> = reloaded.iter().map(|o| o.digest).collect();
    assert!(
        digests.contains(&real_digest_a),
        "record A digest refreshed"
    );
    assert!(
        digests.contains(&real_digest_b),
        "record B digest refreshed"
    );
    assert!(
        !digests.contains(&[0xAA; 32]),
        "MUT-trust-stored-digest: the tampered stored digest must NOT survive \
         restart — the loader must re-derive each digest from its envelope"
    );
}

// --- B8 tombstone path: wrong digest (valid envelope) — GREEN control -----
//
// MUT-tombstone-skip-digest-check: if the tombstone branch stops comparing
// `t.digest != computed`, a tombstone whose stored digest does NOT match its
// (otherwise valid, correctly signed) envelope satisfies the gate and the
// approval wrongly succeeds.
#[tokio::test]
async fn b8_tombstone_path_rejects_wrong_digest_valid_envelope() {
    let (state, _dir) = d_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let group_key = make_hex_id(0x0b81);
    let request_id = install_group_with_pending_request(&state, &group_key, &requester_hex).await;

    let metadata_topic = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .unwrap()
        .metadata_topic
        .clone();
    let event = predecessor_event(&group_key, &request_id, &requester_hex);
    let envelope = sign_v2_envelope(&requester_kp, &metadata_topic, &event);
    let envelope_digest: [u8; 32] = blake3::hash(&envelope).into();
    let first_seen_ms = unix_ms();
    bind_pending_request_to_predecessor(
        &state,
        &group_key,
        &request_id,
        envelope_digest,
        first_seen_ms,
    )
    .await;
    let wrong_digest = [0x55; 32];
    let tombstone = CompletedRelayTombstone {
        group_id: group_key.clone(),
        request_id: request_id.clone(),
        requester_agent_id: requester_hex,
        digest: wrong_digest,
        first_seen_ms,
        completed_at_ms: unix_ms(),
        envelope_bytes: envelope,
    };
    {
        let mut tombs = state.completed_relay_tombstones.write().await;
        tombs.insert(group_key.clone(), vec![tombstone]);
    }

    let status = approve_status(&state, &group_key, &request_id).await;
    assert_eq!(
        status,
        StatusCode::PRECONDITION_FAILED,
        "MUT-tombstone-skip-digest-check: approval must be refused (412) when \
         a tombstone carries a valid signed envelope but a digest that does \
         not match blake3(envelope)"
    );
}

// --- B8 tombstone path: correct digest (valid envelope) — paired control -
//
// The paired control for the wrong-digest mutation: the SAME valid signed
// envelope with the CORRECT digest MUST satisfy the B8 gate (200). This proves
// the wrong-digest failure is caused by the digest mismatch alone.
//
// MUT-tombstone-digest-too-strict: if the comparison were inverted or the
// tombstone path over-restricted, this correct case would wrongly fail (412).
#[tokio::test]
async fn b8_tombstone_path_accepts_correct_digest_valid_envelope() {
    let (state, _dir) = d_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let group_key = make_hex_id(0x0b82);
    let request_id = install_group_with_pending_request(&state, &group_key, &requester_hex).await;

    let metadata_topic = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .unwrap()
        .metadata_topic
        .clone();
    let event = predecessor_event(&group_key, &request_id, &requester_hex);
    let envelope = sign_v2_envelope(&requester_kp, &metadata_topic, &event);
    let correct_digest: [u8; 32] = blake3::hash(&envelope).into();
    let first_seen_ms = unix_ms();
    bind_pending_request_to_predecessor(
        &state,
        &group_key,
        &request_id,
        correct_digest,
        first_seen_ms,
    )
    .await;
    let tombstone = CompletedRelayTombstone {
        group_id: group_key.clone(),
        request_id: request_id.clone(),
        requester_agent_id: requester_hex,
        digest: correct_digest,
        first_seen_ms,
        completed_at_ms: unix_ms(),
        envelope_bytes: envelope,
    };
    {
        let mut tombs = state.completed_relay_tombstones.write().await;
        tombs.insert(group_key.clone(), vec![tombstone]);
    }

    let status = approve_status(&state, &group_key, &request_id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a tombstone with a valid signed envelope and the correct digest must \
         satisfy the B8 gate (got {status})"
    );
}

// --- Completed tombstone survives restart (GREEN control) -----------------
//
// A completed relay tombstone must survive a save → reload cycle so the B8
// approval gate can still re-verify the predecessor after a daemon restart.
//
// MUT-tombstone-not-loaded: if the loader stops restoring completed_tombstones
// from the sidecar, the tombstone vanishes on restart and this reddens.
#[tokio::test]
async fn completed_tombstone_survives_restart() {
    let (state, _dir) = d_state().await;
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());
    let group_key = "bb".repeat(16);
    let request_id = install_group_with_pending_request(&state, &group_key, &requester_hex).await;

    let metadata_topic = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .unwrap()
        .metadata_topic
        .clone();
    let event = predecessor_event(&group_key, &request_id, &requester_hex);
    let envelope = sign_v2_envelope(&requester_kp, &metadata_topic, &event);
    let digest: [u8; 32] = blake3::hash(&envelope).into();
    let first_seen_ms = unix_ms();
    bind_pending_request_to_predecessor(&state, &group_key, &request_id, digest, first_seen_ms)
        .await;
    let tombstone = CompletedRelayTombstone {
        group_id: group_key.clone(),
        request_id: request_id.clone(),
        requester_agent_id: requester_hex.clone(),
        digest,
        first_seen_ms,
        completed_at_ms: unix_ms(),
        envelope_bytes: envelope,
    };
    {
        let mut tombs = state.completed_relay_tombstones.write().await;
        tombs.insert(group_key.clone(), vec![tombstone]);
    }
    save_predecessor_relay_outbox(&state).await.expect("save");
    restart_reload(&state).await;

    let reloaded = tombstone_snapshot(&state, &group_key).await;
    assert!(
        !reloaded.is_empty(),
        "MUT-tombstone-not-loaded: completed tombstone must survive restart"
    );
    let t = &reloaded[0];
    let recomputed: [u8; 32] = blake3::hash(&t.envelope_bytes).into();
    assert_eq!(
        t.digest, recomputed,
        "retained tombstone digest must match its envelope bytes after restart"
    );
    assert_eq!(t.request_id, request_id);
}

// --- Prior omission rows (table-driven edge cases) — GREEN control --------
//
// Rows for B8 boundary cases that must refuse (412) / not-manufacture an
// obligation. Each row is the sole catcher for its named weakening.
#[tokio::test]
async fn b8_omission_rows_refuse_without_valid_predecessor() {
    let requester_kp = fresh_kp();
    let requester_hex = hex::encode(requester_kp.agent_id().as_bytes());

    // Row 1 — no obligation at all.
    {
        let (state, _dir) = d_state().await;
        let group_key = make_hex_id(0x0c01);
        let request_id =
            install_group_with_pending_request(&state, &group_key, &requester_hex).await;
        let status = approve_status(&state, &group_key, &request_id).await;
        assert_eq!(
            status,
            StatusCode::PRECONDITION_FAILED,
            "MUT-b8-no-obligation: approval with no durable predecessor obligation \
             must be refused (412)"
        );
    }

    // Row 2 — outbox obligation whose envelope does not decode (garbage bytes).
    {
        let (state, _dir) = d_state().await;
        let group_key = make_hex_id(0x0c02);
        let request_id =
            install_group_with_pending_request(&state, &group_key, &requester_hex).await;
        let garbage = b"not-a-v2-envelope".to_vec();
        let obl = PredecessorRelayObligation {
            digest: blake3::hash(&garbage).into(),
            byte_size: garbage.len(),
            envelope_bytes: garbage,
            first_seen_ms: unix_ms(),
            next_retry_at_ms: unix_ms() + 60_000,
            retry_count: 0,
            group_id: group_key.clone(),
            request_id: request_id.clone(),
            requester_agent_id: requester_hex.clone(),
            relay_targets: Vec::new(),
            completed_at_ms: None,
        };
        {
            let mut outbox = state.predecessor_relay_outbox.write().await;
            outbox.insert(group_key.clone(), vec![obl]);
        }
        let status = approve_status(&state, &group_key, &request_id).await;
        assert_eq!(
            status,
            StatusCode::PRECONDITION_FAILED,
            "MUT-outbox-trust-stored-digest: an outbox obligation whose envelope \
             fails V2 decode must be refused (412) even if its stored digest \
             matches the garbage bytes"
        );
    }

    // Row 3 — outbox obligation for a different request_id.
    {
        let (state, _dir) = d_state().await;
        let group_key = make_hex_id(0x0c03);
        let request_id =
            install_group_with_pending_request(&state, &group_key, &requester_hex).await;
        let metadata_topic = state
            .named_groups
            .read()
            .await
            .get(&group_key)
            .unwrap()
            .metadata_topic
            .clone();
        let event = predecessor_event(&group_key, "req-someone-else", &requester_hex);
        let envelope = sign_v2_envelope(&requester_kp, &metadata_topic, &event);
        let obl = PredecessorRelayObligation {
            digest: blake3::hash(&envelope).into(),
            byte_size: envelope.len(),
            envelope_bytes: envelope,
            first_seen_ms: unix_ms(),
            next_retry_at_ms: unix_ms() + 60_000,
            retry_count: 0,
            group_id: group_key.clone(),
            request_id: "req-someone-else".to_string(),
            requester_agent_id: requester_hex.clone(),
            relay_targets: Vec::new(),
            completed_at_ms: None,
        };
        {
            let mut outbox = state.predecessor_relay_outbox.write().await;
            outbox.insert(group_key.clone(), vec![obl]);
        }
        let status = approve_status(&state, &group_key, &request_id).await;
        assert_eq!(
            status,
            StatusCode::PRECONDITION_FAILED,
            "MUT-outbox-skip-request-id-binding: an outbox obligation for a \
             different request_id must not satisfy the approval's B8 gate"
        );
    }
}

// ===========================================================================
// Helper: deterministic 64-char hex group id from a seed.
// ===========================================================================
fn make_hex_id(seed: u64) -> String {
    let mut bytes = [0u8; 32];
    let s = seed.to_le_bytes();
    for i in 0..32 {
        bytes[i] = s[i % 8].wrapping_add(i as u8);
    }
    hex::encode(bytes)
}
