//! ADR 0028 causal-replay and cross-group persistence controls.
//!
//! These tests drive the real causal admission, conflict, replay, roster
//! transaction, and atomic sidecar writers. Test hooks only provide bounded
//! scheduling and real pre-rename I/O failure; they do not replace state or
//! persistence mechanisms.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::adr0028_direct_controls::{install_group_with_pending_request, sign_v2_envelope};
use super::*;
use crate::groups::GroupInfo;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::timeout;
use x0x::identity::AgentKeypair;

struct CausalSaveFailureGuard {
    parent: PathBuf,
}

impl CausalSaveFailureGuard {
    async fn arm(state: &AppState) -> Self {
        let parent = state
            .causal_approval_queue_path
            .parent()
            .expect("causal sidecar has a parent")
            .to_path_buf();
        tokio::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500))
            .await
            .expect("arm causal sidecar pre-rename failure");
        Self { parent }
    }
}

impl Drop for CausalSaveFailureGuard {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.parent, std::fs::Permissions::from_mode(0o700));
    }
}

fn approval_candidate(
    info: &GroupInfo,
    signer: &AgentKeypair,
    request_id: &str,
    requester_hex: &str,
    timestamp_ms: u64,
) -> NamedGroupMetadataEvent {
    let actor = hex::encode(signer.agent_id().as_bytes());
    let mut next = info.clone();
    {
        let request = next
            .join_requests
            .get_mut(request_id)
            .expect("pending request exists");
        request.status = x0x::groups::JoinRequestStatus::Approved;
        request.reviewed_by = Some(actor.clone());
        request.reviewed_at = Some(timestamp_ms);
    }
    next.add_member(
        requester_hex.to_string(),
        x0x::groups::GroupRole::Member,
        Some(actor.clone()),
        None,
    );
    next.roster_revision = next.roster_revision.saturating_add(1);
    let commit = next
        .seal_commit(signer, timestamp_ms)
        .expect("seal valid approval candidate");
    NamedGroupMetadataEvent::JoinRequestApproved {
        group_id: info.stable_group_id().to_string(),
        request_id: request_id.to_string(),
        revision: next.roster_revision,
        actor,
        requester_agent_id: requester_hex.to_string(),
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: None,
        commit: Some(commit),
    }
}

async fn queue_real_approval(
    state: &Arc<AppState>,
    group_id: &str,
    request_id: &str,
    requester_hex: &str,
    timestamp_ms: u64,
) -> ([u8; 32], NamedGroupMetadataEvent) {
    let info = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .expect("group exists")
        .clone();
    let signer = state.agent.identity().agent_keypair();
    let event = approval_candidate(&info, signer, request_id, requester_hex, timestamp_ms);
    let envelope = sign_v2_envelope(signer, &info.metadata_topic, &event);
    let digest: [u8; 32] = blake3::hash(&envelope).into();
    let actor_hex = hex::encode(signer.agent_id().as_bytes());
    assert!(matches!(
        &event,
        NamedGroupMetadataEvent::JoinRequestApproved {
            commit: Some(_),
            ..
        }
    ));
    if let NamedGroupMetadataEvent::JoinRequestApproved {
        actor,
        commit: Some(commit),
        revision,
        ..
    } = &event
    {
        assert_eq!(actor, &actor_hex, "approval actor is the authority signer");
        assert_eq!(commit.committed_by, actor_hex);
        assert_eq!(commit.group_id, info.stable_group_id());
        assert_eq!(commit.revision, *revision);
        commit
            .verify_structure()
            .expect("approval commit passes predecessor-independent validation");
        validate_causal_envelope(&envelope, group_id, &event, actor, &info.metadata_topic)
            .expect("approval envelope passes live causal admission validation");
    }
    assert!(!info.has_active_member(requester_hex));
    assert!(!info.is_banned(requester_hex));
    try_queue_causal_approval(
        state,
        group_id,
        &info,
        event.clone(),
        signer.agent_id(),
        request_id,
        requester_hex,
        Some(&envelope),
    )
    .await;
    (digest, event)
}

fn saturated_conflict_tombstones() -> HashMap<String, Vec<ConflictTombstoneEntry>> {
    let mut tombstones = HashMap::new();
    for group_index in 0..16_u32 {
        let mut entries = Vec::new();
        for entry_index in 0..64_u32 {
            let ordinal = group_index * 64 + entry_index;
            let mut digest = [0_u8; 32];
            digest[..4].copy_from_slice(&ordinal.to_be_bytes());
            entries.push(ConflictTombstoneEntry {
                digest,
                first_seen_ms: u64::from(ordinal) + 1,
            });
        }
        tombstones.insert(format!("conflict-saturation-{group_index:02}"), entries);
    }
    tombstones
}

// MUT-conflict-prune-partial-rollback: remove the full-map restoration
// (`*tombstones = tombstones_snapshot`) from the conflict save-failure arm.
// The prune then permanently evicts receipts in unrelated groups even though
// the sidecar replacement failed. GREEN restores the exact pre-conflict map,
// the existing queue entry, and the byte-identical durable sidecar.
#[tokio::test]
async fn conflict_prune_pre_rename_failure_restores_full_cross_group_map() {
    let (state, _dir) = secure_endpoint_test_state().await.expect("secure state");
    let requester = AgentKeypair::generate().expect("requester keypair");
    let requester_hex = hex::encode(requester.agent_id().as_bytes());
    let group_id = "c3a1".repeat(8);
    let request_id = install_group_with_pending_request(&state, &group_id, &requester_hex).await;

    let now = now_millis_u64();
    let (first_digest, _) =
        queue_real_approval(&state, &group_id, &request_id, &requester_hex, now).await;
    let queue = state.causal_approval_queue.read().await;
    assert_eq!(queue.get(&group_id).map(VecDeque::len), Some(1));
    assert_eq!(queue[&group_id][0].digest, first_digest);
    drop(queue);

    let before_tombstones = saturated_conflict_tombstones();
    *state.causal_conflict_tombstones.write().await = before_tombstones.clone();
    assert_eq!(
        save_causal_approval_queue(&state)
            .await
            .expect("persist saturated conflict baseline"),
        AtomicWriteOutcome::Durable
    );
    let bytes_before = tokio::fs::read(&state.causal_approval_queue_path)
        .await
        .expect("read causal baseline bytes");
    let queue_before = state.causal_approval_queue.read().await;
    let before_json = serialize_causal_queue_sidecar(&queue_before, &before_tombstones)
        .expect("serialize tombstone baseline");
    drop(queue_before);

    let failure = CausalSaveFailureGuard::arm(&state).await;
    let _ = queue_real_approval(
        &state,
        &group_id,
        &request_id,
        &requester_hex,
        now.saturating_add(1),
    )
    .await;
    drop(failure);

    let queue = state.causal_approval_queue.read().await;
    let retained = queue.get(&group_id).expect("original queue survives");
    assert_eq!(retained.len(), 1, "conflicting candidate is never admitted");
    assert_eq!(retained[0].digest, first_digest);
    assert!(!retained[0].conflicted, "failed reject-both is rolled back");
    assert_eq!(retained[0].conflicted_with, None);
    drop(queue);

    let after_tombstones = state.causal_conflict_tombstones.read().await;
    let queue_after = state.causal_approval_queue.read().await;
    let after_json = serialize_causal_queue_sidecar(&queue_after, &after_tombstones)
        .expect("serialize tombstone rollback");
    assert_eq!(
        after_json, before_json,
        "the full cross-group map is restored"
    );
    drop(queue_after);
    drop(after_tombstones);
    assert_eq!(
        tokio::fs::read(&state.causal_approval_queue_path)
            .await
            .expect("read causal bytes after failed conflict"),
        bytes_before,
        "pre-rename conflict failure leaves the durable sidecar byte-identical"
    );
}

// MUT-replay-drop-global-roster-lock: remove `_replay_roster_guard` from the
// replay loop. A concurrent group-B transaction can then mutate/snapshot the
// shared full map while group A's replay candidate is paused in persistence.
// GREEN keeps B blocked until A is durable, then persists both transitions in
// order so memory and the full-map file agree.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_persistence_excludes_cross_group_roster_transaction() {
    let (state, _dir) = secure_endpoint_test_state().await.expect("secure state");
    let requester_a = AgentKeypair::generate().expect("requester A");
    let requester_a_hex = hex::encode(requester_a.agent_id().as_bytes());
    let group_a = "c3b1".repeat(8);
    let request_a = install_group_with_pending_request(&state, &group_a, &requester_a_hex).await;
    queue_real_approval(
        &state,
        &group_a,
        &request_a,
        &requester_a_hex,
        now_millis_u64(),
    )
    .await;

    let requester_b = AgentKeypair::generate().expect("requester B");
    let requester_b_hex = hex::encode(requester_b.agent_id().as_bytes());
    let group_b = "c3b2".repeat(8);
    install_group_with_pending_request(&state, &group_b, &requester_b_hex).await;
    assert_eq!(
        save_named_groups_checked(&state)
            .await
            .expect("persist replay baseline"),
        AtomicWriteOutcome::Durable
    );

    let snapshot_reached = Arc::new(tokio::sync::Notify::new());
    let release_snapshot = Arc::new(tokio::sync::Notify::new());
    *NAMED_GROUP_SAVE_AFTER_SNAPSHOT_NOTIFY
        .lock()
        .expect("roster snapshot hook poisoned") =
        Some((Arc::clone(&snapshot_reached), Arc::clone(&release_snapshot)));

    let replay_state = Arc::clone(&state);
    let replay_group = group_a.clone();
    let replay = tokio::spawn(async move {
        replay_pending_causal_approvals(&replay_state, &replay_group).await;
    });
    timeout(Duration::from_secs(5), snapshot_reached.notified())
        .await
        .expect("replay reached roster persistence snapshot");
    *NAMED_GROUP_SAVE_AFTER_SNAPSHOT_NOTIFY
        .lock()
        .expect("roster snapshot hook poisoned") = None;

    let group_b_for_task = group_b.clone();
    let b_state = Arc::clone(&state);
    let mut group_b_save = tokio::spawn(async move {
        persist_named_groups_mutation(&b_state, |groups| {
            let Some(info) = groups.get_mut(&group_b_for_task) else {
                return false;
            };
            info.description = "group-B-committed-after-replay".to_string();
            info.updated_at = info.updated_at.saturating_add(1);
            info.recompute_state_hash();
            true
        })
        .await
    });
    assert!(
        timeout(Duration::from_millis(250), &mut group_b_save)
            .await
            .is_err(),
        "MUT-replay-drop-global-roster-lock: group B must block behind A's replay transaction"
    );
    assert_ne!(
        state.named_groups.read().await[&group_b].description,
        "group-B-committed-after-replay",
        "B cannot mutate the shared map before A's durable replay outcome"
    );

    release_snapshot.notify_one();
    timeout(Duration::from_secs(5), replay)
        .await
        .expect("replay completes after release")
        .expect("replay task does not panic");
    assert_eq!(
        timeout(Duration::from_secs(5), group_b_save)
            .await
            .expect("group B completes after replay")
            .expect("group B task does not panic")
            .expect("group B persistence result"),
        AtomicWriteOutcome::Durable
    );

    let groups = state.named_groups.read().await;
    let applied_request = groups[&group_a]
        .join_requests
        .get(&request_a)
        .expect("request A retained");
    assert_eq!(
        applied_request.status,
        x0x::groups::JoinRequestStatus::Approved,
        "A's replay becomes durable before B mutates"
    );
    assert_eq!(
        groups[&group_b].description,
        "group-B-committed-after-replay"
    );
    drop(groups);

    let durable: HashMap<String, GroupInfo> = serde_json::from_slice(
        &tokio::fs::read(&state.named_groups_path)
            .await
            .expect("read durable roster"),
    )
    .expect("decode durable roster");
    assert_eq!(
        durable[&group_a].join_requests[&request_a].status,
        x0x::groups::JoinRequestStatus::Approved
    );
    assert_eq!(
        durable[&group_b].description,
        "group-B-committed-after-replay"
    );
}
