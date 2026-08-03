//! ADR 0028 row-6 recovery/startup controls.
//!
//! These tests drive the real predecessor-sidecar loader and public server
//! startup entrypoint. Detached journal candidates use real requester-signed
//! V2 envelopes; listener recovery additionally carries a real signed
//! `GroupStateCommit` so the governed-cap check is the branch under test.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_arguments,
    clippy::unwrap_used
)]

use super::*;
use crate::groups::GroupInfo;
use crate::server::{serve_with_options, DaemonConfig, ServeOptions};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use x0x::identity::AgentKeypair;

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn test_state() -> (Arc<AppState>, tempfile::TempDir) {
    secure_endpoint_test_state()
        .await
        .expect("secure endpoint test state")
}

fn fresh_keypair() -> AgentKeypair {
    AgentKeypair::generate().expect("agent keypair")
}

fn local_agent_hex(state: &AppState) -> String {
    hex::encode(state.agent.agent_id().as_bytes())
}

fn sign_v2_envelope(
    keypair: &AgentKeypair,
    topic: &str,
    event: &NamedGroupMetadataEvent,
) -> Vec<u8> {
    use ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa;

    let payload = serde_json::to_vec(event).expect("serialize metadata event");
    let agent_id = keypair.agent_id();
    let public_key = keypair.public_key().as_bytes();
    let mut signing = Vec::with_capacity(10 + 32 + topic.len() + payload.len());
    signing.extend_from_slice(b"x0x-msg-v2");
    signing.extend_from_slice(agent_id.as_bytes());
    signing.extend_from_slice(topic.as_bytes());
    signing.extend_from_slice(&payload);
    let signature = sign_with_ml_dsa(keypair.secret_key(), &signing).expect("ML-DSA signature");
    let signature = signature.as_bytes();
    let topic = topic.as_bytes();

    let mut encoded = Vec::with_capacity(
        1 + 32 + 2 + public_key.len() + 2 + signature.len() + 2 + topic.len() + payload.len(),
    );
    encoded.push(0x02);
    encoded.extend_from_slice(agent_id.as_bytes());
    encoded.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    encoded.extend_from_slice(public_key);
    encoded.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    encoded.extend_from_slice(signature);
    encoded.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    encoded.extend_from_slice(topic);
    encoded.extend_from_slice(&payload);
    encoded
}

fn predecessor_event(
    group_id: &str,
    request_id: &str,
    requester_agent_id: &str,
    timestamp_ms: u64,
    commit: Option<x0x::groups::GroupStateCommit>,
) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::JoinRequestCreated {
        group_id: group_id.to_string(),
        request_id: request_id.to_string(),
        requester_agent_id: requester_agent_id.to_string(),
        message: None,
        ts: timestamp_ms,
        requester_kem_public_key_b64: None,
        treekem_key_package_b64: None,
        commit,
    }
}

fn relay_obligation(
    keypair: &AgentKeypair,
    topic: &str,
    group_id: &str,
    requester_agent_id: &str,
    request_index: usize,
    first_seen_ms: u64,
) -> PredecessorRelayObligation {
    let request_id = format!("row6-request-{request_index}");
    let envelope_bytes = sign_v2_envelope(
        keypair,
        topic,
        &predecessor_event(
            group_id,
            &request_id,
            requester_agent_id,
            first_seen_ms,
            None,
        ),
    );
    PredecessorRelayObligation {
        digest: blake3::hash(&envelope_bytes).into(),
        byte_size: envelope_bytes.len(),
        envelope_bytes,
        first_seen_ms,
        next_retry_at_ms: first_seen_ms,
        retry_count: 0,
        group_id: group_id.to_string(),
        request_id,
        requester_agent_id: requester_agent_id.to_string(),
        relay_targets: Vec::new(),
        completed_at_ms: None,
    }
}

fn bound_join_request(entry: &PredecessorRelayObligation) -> x0x::groups::JoinRequest {
    x0x::groups::JoinRequest {
        request_id: entry.request_id.clone(),
        group_id: entry.group_id.clone(),
        requester_agent_id: entry.requester_agent_id.clone(),
        requester_user_id: None,
        requested_role: x0x::groups::GroupRole::Member,
        message: None,
        treekem_key_package_b64: None,
        created_at: entry.first_seen_ms,
        reviewed_at: None,
        reviewed_by: None,
        status: x0x::groups::JoinRequestStatus::Pending,
        predecessor_envelope_digest: Some(entry.digest),
        predecessor_first_seen_ms: Some(entry.first_seen_ms),
    }
}

async fn install_request_group(state: &AppState, group_id: &str) {
    let mut group = GroupInfo::with_policy(
        "ADR 0028 row 6".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.to_string(),
        x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
    );
    group.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), group);
}

async fn bind_requests(state: &AppState, group_id: &str, entries: &[PredecessorRelayObligation]) {
    let mut groups = state.named_groups.write().await;
    let group = groups.get_mut(group_id).expect("group exists");
    for entry in entries {
        group
            .join_requests
            .insert(entry.request_id.clone(), bound_join_request(entry));
    }
    group.recompute_state_hash();
}

async fn install_live_entries(
    state: &AppState,
    group_id: &str,
    entries: &[PredecessorRelayObligation],
) {
    bind_requests(state, group_id, entries).await;
    state
        .predecessor_relay_outbox
        .write()
        .await
        .insert(group_id.to_string(), entries.to_vec());
}

async fn build_entries(
    state: &AppState,
    group_id: &str,
    keypair: &AgentKeypair,
    count: usize,
    first_seen_ms: u64,
) -> Vec<PredecessorRelayObligation> {
    let topic = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .expect("group exists")
        .metadata_topic
        .clone();
    let requester_agent_id = hex::encode(keypair.agent_id().as_bytes());
    (0..count)
        .map(|index| {
            relay_obligation(
                keypair,
                &topic,
                group_id,
                &requester_agent_id,
                index,
                first_seen_ms,
            )
        })
        .collect()
}

async fn save_relay_sidecar(state: &AppState) {
    let outcome = save_predecessor_relay_outbox(state)
        .await
        .expect("save predecessor sidecar");
    assert_eq!(outcome, AtomicWriteOutcome::Durable);
}

async fn sidecar_bytes(state: &AppState) -> Vec<u8> {
    tokio::fs::read(&state.predecessor_relay_outbox_path)
        .await
        .expect("read predecessor sidecar")
}

async fn outbox_len(state: &AppState) -> usize {
    state
        .predecessor_relay_outbox
        .read()
        .await
        .values()
        .map(Vec::len)
        .sum()
}

async fn roster_bytes(state: &AppState) -> Vec<u8> {
    serde_json::to_vec(&*state.named_groups.read().await).expect("serialize roster")
}

async fn b8_candidate_arm(
    entry_count: usize,
) -> (
    Result<(), String>,
    Arc<AppState>,
    Vec<u8>,
    tempfile::TempDir,
) {
    let (state, dir) = test_state().await;
    let group_id = format!("{:032x}", 0xB8u32);
    install_request_group(&state, &group_id).await;
    let requester = fresh_keypair();
    let requester_agent_id = hex::encode(requester.agent_id().as_bytes());
    let first_seen_ms = unix_ms();
    let entries = build_entries(&state, &group_id, &requester, entry_count, first_seen_ms).await;
    bind_requests(&state, &group_id, &entries).await;
    let first = entries.first().expect("at least one entry");
    let first_request_id = first.request_id.clone();
    let first_digest = first.digest;
    *state.pending_b8_compensation.lock().await = Some(PendingB8Compensation {
        group_id: group_id.clone(),
        request_id: first_request_id,
        outbox_snapshot: entries,
        timestamp_ms: first_seen_ms,
        requester_agent_id,
        actor: local_agent_hex(&state),
        predecessor_digest: first_digest,
        approved_revision: 1,
        approved_state_hash: "unmatched-approved-state".to_string(),
    });
    save_relay_sidecar(&state).await;
    let before = sidecar_bytes(&state).await;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        load_predecessor_relay_outbox(&state),
    )
    .await
    .expect("B8 recovery must be bounded");
    (result, state, before, dir)
}

/// MUT2: remove the detached B8 candidate budget check. The rejected arm then
/// installs 65 live records instead of failing with zero installed state.
#[tokio::test]
async fn b8_detached_candidate_64_accepts_65_rejects_zero_installed() {
    let (accepted, accepted_state, _, _accepted_dir) = b8_candidate_arm(64).await;
    assert_eq!(accepted, Ok(()));
    assert_eq!(outbox_len(&accepted_state).await, 64);
    assert!(accepted_state
        .pending_b8_compensation
        .lock()
        .await
        .is_none());

    let (rejected, rejected_state, before, _rejected_dir) = b8_candidate_arm(65).await;
    assert_eq!(
        rejected,
        Err("B8 recovery journal rejected: detached candidate exceeds governed caps".to_string())
    );
    assert_eq!(outbox_len(&rejected_state).await, 0);
    assert!(rejected_state
        .completed_relay_tombstones
        .read()
        .await
        .is_empty());
    assert_eq!(sidecar_bytes(&rejected_state).await, before);
}

fn stateful_listener_envelope(
    group: &GroupInfo,
    group_id: &str,
    request_id: &str,
    requester: &AgentKeypair,
    first_seen_ms: u64,
) -> Vec<u8> {
    let requester_agent_id = hex::encode(requester.agent_id().as_bytes());
    let mut committed_group = group.clone();
    committed_group.join_requests.insert(
        request_id.to_string(),
        x0x::groups::JoinRequest {
            request_id: request_id.to_string(),
            group_id: group_id.to_string(),
            requester_agent_id: requester_agent_id.clone(),
            requester_user_id: None,
            requested_role: x0x::groups::GroupRole::Member,
            message: None,
            treekem_key_package_b64: None,
            created_at: first_seen_ms,
            reviewed_at: None,
            reviewed_by: None,
            status: x0x::groups::JoinRequestStatus::Pending,
            predecessor_envelope_digest: None,
            predecessor_first_seen_ms: None,
        },
    );
    let commit = committed_group
        .seal_commit(requester, first_seen_ms)
        .expect("sign non-member request commit");
    let event = predecessor_event(
        group_id,
        request_id,
        &requester_agent_id,
        first_seen_ms,
        Some(commit),
    );
    sign_v2_envelope(requester, &group.metadata_topic, &event)
}

async fn listener_candidate_arm(
    ordinary_count: usize,
) -> (
    Result<(), String>,
    Arc<AppState>,
    Vec<u8>,
    Vec<u8>,
    String,
    tempfile::TempDir,
) {
    let (state, dir) = test_state().await;
    let group_id = format!("{:032x}", 0x1A57u32);
    install_request_group(&state, &group_id).await;

    let ordinary_requester = fresh_keypair();
    let first_seen_ms = unix_ms();
    let ordinary_entries = build_entries(
        &state,
        &group_id,
        &ordinary_requester,
        ordinary_count,
        first_seen_ms,
    )
    .await;
    install_live_entries(&state, &group_id, &ordinary_entries).await;

    let marker_requester = fresh_keypair();
    let marker_requester_id = hex::encode(marker_requester.agent_id().as_bytes());
    let marker_request_id = "row6-listener-marker".to_string();
    let group = state
        .named_groups
        .read()
        .await
        .get(&group_id)
        .expect("group exists")
        .clone();
    let envelope_bytes = stateful_listener_envelope(
        &group,
        &group_id,
        &marker_request_id,
        &marker_requester,
        first_seen_ms,
    );
    let digest: [u8; 32] = blake3::hash(&envelope_bytes).into();
    *state.pending_listener_admission.lock().await = Some(PendingListenerAdmission {
        group_id: group_id.clone(),
        request_id: marker_request_id.clone(),
        requester_agent_id: marker_requester_id,
        byte_size: envelope_bytes.len(),
        envelope_bytes,
        digest,
        first_seen_ms,
    });
    save_relay_sidecar(&state).await;
    let before_sidecar = sidecar_bytes(&state).await;
    let before_roster = roster_bytes(&state).await;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        load_predecessor_relay_outbox(&state),
    )
    .await
    .expect("listener recovery must be bounded");
    (
        result,
        state,
        before_sidecar,
        before_roster,
        marker_request_id,
        dir,
    )
}

/// MUT2: remove the detached listener candidate budget check. The 65th live
/// record then installs after a valid requester-signed stateful request.
#[tokio::test]
async fn listener_detached_candidate_64_accepts_65_rejects_zero_installed() {
    let (accepted, accepted_state, _, _, marker_request_id, _accepted_dir) =
        listener_candidate_arm(63).await;
    assert_eq!(accepted, Ok(()));
    assert_eq!(outbox_len(&accepted_state).await, 64);
    assert!(accepted_state
        .named_groups
        .read()
        .await
        .values()
        .any(|group| group
            .join_requests
            .get(&marker_request_id)
            .is_some_and(x0x::groups::JoinRequest::is_pending)));
    assert!(accepted_state
        .pending_listener_admission
        .lock()
        .await
        .is_none());

    let (rejected, rejected_state, before_sidecar, before_roster, _, _rejected_dir) =
        listener_candidate_arm(64).await;
    assert_eq!(
        rejected,
        Err("listener admission recovery rejected: candidate exceeds governed caps".to_string())
    );
    assert_eq!(outbox_len(&rejected_state).await, 0);
    assert_eq!(roster_bytes(&rejected_state).await, before_roster);
    assert_eq!(sidecar_bytes(&rejected_state).await, before_sidecar);
}

struct PermissionGuard {
    path: PathBuf,
    restore_mode: u32,
}

impl PermissionGuard {
    async fn arm(path: impl Into<PathBuf>, mode: u32, restore_mode: u32) -> Self {
        let path = path.into();
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .await
            .expect("arm directory permissions");
        Self { path, restore_mode }
    }
}

impl Drop for PermissionGuard {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(
            &self.path,
            std::fs::Permissions::from_mode(self.restore_mode),
        );
    }
}

/// MUT2: accept `ReplacedNotDurable` in the loader's unconditional final
/// re-save. The first load would then authorize startup without a successful
/// parent-directory durability retry.
#[tokio::test]
async fn replaced_not_durable_requires_successful_supervisor_retry() {
    let (state, _dir) = test_state().await;
    let group_id = format!("{:032x}", 0xD0AB1Eu32);
    install_request_group(&state, &group_id).await;
    let requester = fresh_keypair();
    let entries = build_entries(&state, &group_id, &requester, 1, unix_ms()).await;
    install_live_entries(&state, &group_id, &entries).await;
    save_relay_sidecar(&state).await;

    let parent = state
        .predecessor_relay_outbox_path
        .parent()
        .expect("sidecar parent")
        .to_path_buf();
    let guard = PermissionGuard::arm(parent, 0o300, 0o700).await;
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        load_predecessor_relay_outbox(&state),
    )
    .await
    .expect("first loader attempt must be bounded");
    assert_eq!(
        first,
        Err("relay recovery replacement is visible but not directory-durable".to_string())
    );

    drop(guard);
    let second = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        load_predecessor_relay_outbox(&state),
    )
    .await
    .expect("retry must be bounded");
    assert_eq!(second, Ok(()));
    assert_eq!(outbox_len(&state).await, 1);
}

fn reserve_tcp_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve TCP port");
    let address = listener.local_addr().expect("reserved address");
    drop(listener);
    address
}

fn startup_config(data_dir: &Path, api_address: SocketAddr) -> DaemonConfig {
    let mut config = DaemonConfig {
        data_dir: data_dir.to_path_buf(),
        identity_dir: Some(data_dir.join("identity")),
        api_address,
        bind_address: "127.0.0.1:0".parse().expect("loopback QUIC address"),
        bootstrap_peers: Some(Vec::new()),
        network_id: Some("adr0028.row6.startup-control".to_string()),
        ..DaemonConfig::default()
    };
    config.history.enabled = false;
    config
}

fn startup_options() -> ServeOptions {
    ServeOptions {
        skip_update_check: true,
        cli_no_port_mapping: true,
        cli_disable_peer_cache: true,
        ..ServeOptions::default()
    }
}

/// The public startup seam must return the loader error before advertising or
/// retaining the API socket. The successful retry is the passing control: it
/// occupies the same socket until graceful shutdown, then releases it.
///
/// MUT2-A: write `api.port` before the causal loaders.
/// MUT2-B: leak/retain the bound API listener on the loader-error path.
#[tokio::test]
async fn loader_error_precedes_service_advertisement_and_socket_survival() {
    let dir = tempfile::tempdir().expect("startup tempdir");
    let api_address = reserve_tcp_address();
    let config = startup_config(dir.path(), api_address);
    let sidecar_path = dir.path().join("predecessor_relay_outbox.json");
    let port_file = dir.path().join("api.port");
    tokio::fs::write(&sidecar_path, b"{")
        .await
        .expect("write malformed sidecar");
    tokio::fs::write(&port_file, b"stale-advertisement")
        .await
        .expect("write stale API advertisement");

    let failed = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        serve_with_options(config.clone(), startup_options()),
    )
    .await
    .expect("failing startup must be bounded");
    let error = match failed {
        Err(error) => error,
        Ok(handle) => {
            let _ = handle.shutdown_and_wait().await;
            panic!("malformed recovery sidecar unexpectedly started the service");
        }
    };
    assert!(
        error
            .to_string()
            .contains("ADR 0028 startup: predecessor relay outbox sidecar is malformed"),
        "unexpected startup error: {error}"
    );
    assert!(!port_file.exists(), "loader failure must remove api.port");
    assert_eq!(
        tokio::fs::read(&sidecar_path)
            .await
            .expect("read preserved malformed sidecar"),
        b"{"
    );
    let rebound = TcpListener::bind(api_address).expect("failed startup must release API socket");
    drop(rebound);

    tokio::fs::remove_file(&sidecar_path)
        .await
        .expect("remove rejected sidecar for passing control");
    let handle = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        serve_with_options(config, startup_options()),
    )
    .await
    .expect("successful startup must be bounded")
    .expect("same configuration must start after sidecar repair");
    assert_eq!(handle.local_addr(), api_address);
    assert!(
        TcpListener::bind(api_address).is_err(),
        "successful startup must own the API socket"
    );
    handle
        .shutdown_and_wait()
        .await
        .expect("graceful test shutdown");
    let released = TcpListener::bind(api_address).expect("shutdown must release API socket");
    drop(released);
}
