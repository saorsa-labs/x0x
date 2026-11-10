//! Issue #1840 route 2 and the "several requesters" ruling: requesters that
//! seal over a partial or used head wait in a fixed order, and each one is
//! listed on the authority after it seals again over the head of its turn.
//!
//! Every test drives the real handlers: `import_group_card` and
//! `create_join_request` on a requester daemon state, then the real
//! predecessor-relay listener on the authority state. The turn hand-off
//! (the authority tells the turn holder the head) is done by `sequencer::
//! drive_turns` below; the daemon does not send it yet (slice 2).

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::dm_inbox::DmTypedPayload;
use crate::identity::MachineId;
use crate::server::handle_predecessor_relay_typed_payload;

fn agent_hex(state: &AppState) -> String {
    hex::encode(state.agent.agent_id().as_bytes())
}

/// Install a `public_request_secure` group on the authority with
/// `extra_members` Active members besides the owner, at a sealed head.
async fn install_authority_group(
    owner: &Arc<AppState>,
    tag: &[u8],
    extra_members: usize,
) -> String {
    let group_id = hex::encode(blake3::hash(tag).as_bytes());
    let mut info = x0x::groups::GroupInfo::with_policy(
        "1840 sequence".to_string(),
        String::new(),
        owner.agent.agent_id(),
        group_id.clone(),
        x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
    );
    let owner_hex = agent_hex(owner);
    for i in 0..extra_members {
        info.add_member(
            format!("{:064x}", 0x1840_0000u64 + i as u64),
            x0x::groups::GroupRole::Member,
            Some(owner_hex.clone()),
            None,
        );
    }
    info.seal_commit(owner.agent.identity().agent_keypair(), now_millis_u64())
        .expect("authority seals its head");
    let key = info.stable_group_id().to_string();
    owner.named_groups.write().await.insert(key.clone(), info);
    assert_eq!(
        save_named_groups_checked(owner).await.expect("roster save"),
        AtomicWriteOutcome::Durable
    );
    key
}

/// The card the authority would publish for its current head.
async fn authority_card(owner: &Arc<AppState>, key: &str) -> x0x::groups::GroupCard {
    let groups = owner.named_groups.read().await;
    groups
        .get(key)
        .expect("group")
        .to_signed_group_card(owner.agent.identity().agent_keypair())
        .expect("sign card")
        .expect("public group has a card")
}

/// A new requester daemon imports `card` and calls `POST /groups/:id/requests`.
/// Returns the requester state, its request id and the offered envelope.
async fn requester_asks(
    card: &x0x::groups::GroupCard,
) -> (Arc<AppState>, tempfile::TempDir, String, Vec<u8>) {
    let (requester, dir) = secure_endpoint_test_state().await.expect("requester state");
    requester
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let response = import_group_card(State(Arc::clone(&requester)), Json(card.clone()))
        .await
        .into_response();
    assert_eq!(response.status(), StatusCode::OK, "card import");
    let (status, body) = response_json(
        create_join_request(
            State(Arc::clone(&requester)),
            Path(card.group_id.clone()),
            None,
        )
        .await
        .into_response(),
    )
    .await
    .expect("response");
    assert_eq!(status, StatusCode::CREATED, "request: {body}");
    let request_id = body["request_id"].as_str().expect("request id").to_string();
    let envelope = offered_envelope(&requester, &request_id, None).await;
    (requester, dir, request_id, envelope)
}

/// The exact `JoinRequestCreated` envelope the requester would offer. The
/// test agent has no gossip runtime, so the publish in the handler returns no
/// bytes; the envelope is rebuilt here from the requester's stored request
/// and the commit it sealed (or `resealed`), and signed with the requester's
/// key.
async fn offered_envelope(
    requester: &AppState,
    request_id: &str,
    resealed: Option<x0x::groups::GroupStateCommit>,
) -> Vec<u8> {
    use base64::Engine as _;
    let groups = requester.named_groups.read().await;
    let stub = groups
        .values()
        .find(|info| info.join_requests.contains_key(request_id))
        .expect("the requester stored its request");
    let request = &stub.join_requests[request_id];
    let commit = resealed.unwrap_or_else(|| {
        stub.commit_log
            .last()
            .expect("sealed commit")
            .commit
            .clone()
    });
    let event = NamedGroupMetadataEvent::JoinRequestCreated {
        group_id: stub.stable_group_id().to_string(),
        request_id: request.request_id.clone(),
        requester_agent_id: request.requester_agent_id.clone(),
        message: request.message.clone(),
        ts: request.created_at,
        requester_kem_public_key_b64: Some(
            BASE64.encode(&requester.agent_kem_keypair.public_bytes),
        ),
        treekem_key_package_b64: request.treekem_key_package_b64.clone(),
        commit: Some(commit),
    };
    super::pr291_restart_marker_matrix::sign_v2_envelope(
        requester.agent.identity().agent_keypair(),
        &stub.metadata_topic,
        &event,
    )
}

/// Deliver a requester's offer DM to the authority's real listener.
async fn offer(owner: &Arc<AppState>, requester: &AppState, envelope: &[u8]) {
    let mut payload = GROUP_PREDECESSOR_RELAY_DM_PREFIX.to_vec();
    payload.extend_from_slice(envelope);
    let dm = DmTypedPayload {
        sender: requester.agent.agent_id(),
        machine_id: MachineId([0u8; 32]),
        payload,
        verified: true,
        trust_decision: None,
        received_at_unix_ms: now_millis_u64(),
        request_id: [0u8; 16],
        completion: None,
    };
    handle_predecessor_relay_typed_payload(owner, &agent_hex(owner), dm).await;
}

async fn pending_request_ids(owner: &AppState, key: &str) -> Vec<String> {
    let groups = owner.named_groups.read().await;
    let mut requests: Vec<_> = groups
        .get(key)
        .expect("group")
        .join_requests
        .values()
        .filter(|r| r.is_pending())
        .collect();
    requests.sort_by_key(|r| r.created_at);
    requests.iter().map(|r| r.request_id.clone()).collect()
}

async fn approve(owner: &Arc<AppState>, key: &str, request_id: &str) -> StatusCode {
    let (status, _body) = response_json(
        approve_join_request(
            State(Arc::clone(owner)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path((key.to_string(), request_id.to_string())),
        )
        .await
        .into_response(),
    )
    .await
    .expect("response");
    status
}

type Asked = (Arc<AppState>, tempfile::TempDir, String, Vec<u8>);

/// TEST-ONLY seal of a join request over the authority's current head, read
/// straight from the authority's record. It stands in for slice 2: there the
/// turn holder is told the head and a production seal, with its own checks,
/// signs. A pending request is not in the state hash, so the link repeats
/// the head's hash inputs at the next revision.
fn seal_request_over_authority_head(
    head: &x0x::groups::GroupInfo,
    requester: &AppState,
) -> x0x::groups::GroupStateCommit {
    x0x::groups::GroupStateCommit::sign(
        head.stable_group_id().to_string(),
        head.state_revision + 1,
        Some(head.state_hash.clone()),
        x0x::groups::state_commit::compute_roster_root(&head.members_v2),
        x0x::groups::state_commit::compute_policy_hash(&head.policy),
        x0x::groups::state_commit::compute_public_meta_hash(&head.public_meta()),
        head.security_binding.clone(),
        false,
        now_millis_u64(),
        requester.agent.identity().agent_keypair(),
    )
    .expect("sign the request link")
}

/// The only code in this file that uses the #1840 sequencer. For the RED
/// run on origin/main these bodies are empty (main has no sequencer).
mod sequencer {
    use super::*;
    use crate::server::routes::named_groups::join_sequence::{
        note_refused_request, turn_on, JOIN_SEQUENCE_TURN_MS,
    };

    /// Do what the turn DM will do: while a requester holds the turn, let
    /// it seal the SAME request again over the authority's head and offer
    /// it. A holder that is not in `online` does nothing; its turn runs
    /// out. Returns the turn holders in order and the clock at the end.
    pub(super) async fn drive_turns(
        owner: &Arc<AppState>,
        key: &str,
        online: &[&Asked],
        mut now_ms: u64,
    ) -> (Vec<String>, u64) {
        let mut holders = Vec::new();
        for _ in 0..32 {
            let (turn, head) = {
                let groups = owner.named_groups.read().await;
                let info = groups.get(key).expect("group");
                let mut queue = owner.join_sequencer.lock().await;
                let Some(turn) = turn_on(&mut queue, info, key, now_ms) else {
                    break;
                };
                assert_eq!(turn.head_revision, info.state_revision);
                (turn, info.clone())
            };
            let holder = turn.request.requester_agent_id.clone();
            if holders.last() != Some(&holder) {
                holders.push(holder.clone());
            }
            let Some((requester, _, request_id, _)) =
                online.iter().find(|a| agent_hex(&a.0) == holder)
            else {
                now_ms += JOIN_SEQUENCE_TURN_MS;
                continue;
            };
            assert_eq!(
                &turn.request.request_id, request_id,
                "the turn names the request"
            );
            let commit = seal_request_over_authority_head(&head, requester);
            {
                let mut groups = requester.named_groups.write().await;
                let stub = groups.get_mut(key).expect("stub");
                stub.state_revision = commit.revision;
                stub.prev_state_hash = commit.prev_state_hash.clone();
                stub.state_hash = commit.state_hash.clone();
            }
            let envelope = offered_envelope(requester, request_id, Some(commit)).await;
            offer(owner, requester, &envelope).await;
        }
        (holders, now_ms)
    }

    pub(super) async fn waiting(owner: &AppState) -> usize {
        owner.join_sequencer.lock().await.len()
    }

    /// A daemon restart: the in-memory queue is gone.
    pub(super) async fn forget_queue(owner: &AppState) {
        *owner.join_sequencer.lock().await = Default::default();
    }

    /// What the listener calls after a refusal with no roster write.
    /// Returns the number of waiting entries afterwards.
    pub(super) async fn refused(
        owner: &AppState,
        key: &str,
        event: &NamedGroupMetadataEvent,
    ) -> usize {
        note_refused_request(owner, key, event, now_millis_u64()).await;
        waiting(owner).await
    }
}

async fn listener_journal_is_free(owner: &AppState) -> bool {
    owner.pending_listener_admission.lock().await.is_none()
}

/// The requesters of the last `n` chain links on the authority, oldest first.
async fn last_link_signers(owner: &AppState, key: &str, n: usize) -> Vec<String> {
    let groups = owner.named_groups.read().await;
    let log = &groups.get(key).expect("group").commit_log;
    log[log.len() - n..]
        .iter()
        .map(|c| c.commit.committed_by.clone())
        .collect()
}

/// Route 2: the group has one member besides the owner; the second joiner
/// holds only the card. Its first seal is refused, it waits, gets the turn,
/// seals again and is then listed and approved.
///
/// RED on main: the request is refused (`state hash mismatch`) and never
/// listed; nothing gives the requester a turn.
#[tokio::test]
async fn issue1840_second_joiner_gets_a_turn_and_is_listed_and_approved() {
    let (owner, _o) = secure_endpoint_test_state().await.expect("owner state");
    let key = install_authority_group(&owner, b"1840-seq-second-joiner", 1).await;
    let asked = requester_asks(&authority_card(&owner, &key).await).await;
    offer(&owner, &asked.0, &asked.3).await;
    assert!(pending_request_ids(&owner, &key).await.is_empty());

    let (holders, _) = sequencer::drive_turns(&owner, &key, &[&asked], now_millis_u64()).await;
    assert_eq!(holders, vec![agent_hex(&asked.0)]);
    assert_eq!(
        pending_request_ids(&owner, &key).await,
        vec![asked.2.clone()],
        "the second joiner's request must be listed on the authority"
    );
    assert_eq!(approve(&owner, &key, &asked.2).await, StatusCode::OK);
    assert!(owner
        .named_groups
        .read()
        .await
        .get(&key)
        .expect("group")
        .has_active_member(&agent_hex(&asked.0)));
    assert_eq!(sequencer::waiting(&owner).await, 0);
}

/// Three requesters seal over the same card. All three are listed, one link
/// at a time, in the order their first offers reached the authority. The
/// order follows arrival for each interleaving, not the requester ids.
///
/// RED on main: all three are refused (the group has a member).
#[tokio::test]
async fn issue1840_three_concurrent_requesters_are_listed_in_arrival_order() {
    for arrival in [[0usize, 1, 2], [2, 0, 1], [1, 2, 0]] {
        let (owner, _o) = secure_endpoint_test_state().await.expect("owner state");
        let key = install_authority_group(&owner, b"1840-seq-concurrent", 1).await;
        let card = authority_card(&owner, &key).await;
        let mut asked = Vec::new();
        for _ in 0..3 {
            asked.push(requester_asks(&card).await);
        }
        let expected: Vec<String> = arrival.iter().map(|i| agent_hex(&asked[*i].0)).collect();
        for i in arrival {
            offer(&owner, &asked[i].0, &asked[i].3).await;
        }
        let online: Vec<&Asked> = asked.iter().collect();
        let (holders, _) = sequencer::drive_turns(&owner, &key, &online, now_millis_u64()).await;
        assert_eq!(holders, expected, "{arrival:?}: turns follow arrival");
        assert_eq!(pending_request_ids(&owner, &key).await.len(), 3);
        assert_eq!(
            last_link_signers(&owner, &key, 3).await,
            expected,
            "{arrival:?}: the chain holds one request link per requester, in arrival order"
        );
        assert!(listener_journal_is_free(&owner).await);
        for a in &asked {
            assert_eq!(approve(&owner, &key, &a.2).await, StatusCode::OK);
        }
    }
}

/// The requester in the middle never seals again (it is offline). Its turn
/// runs out and the requester behind it is listed. Nothing durable changed
/// for the one that was never served, and its entry goes away by itself.
///
/// RED on main: nobody is listed.
#[tokio::test]
async fn issue1840_missed_turn_does_not_block_and_leaves_nothing_durable() {
    let (owner, _o) = secure_endpoint_test_state().await.expect("owner state");
    let key = install_authority_group(&owner, b"1840-seq-missed-turn", 1).await;
    let card = authority_card(&owner, &key).await;
    let mut asked = Vec::new();
    for _ in 0..3 {
        asked.push(requester_asks(&card).await);
    }
    // Only the silent requester first: the queue alone must write nothing.
    // The baseline is read BEFORE the first refused offer.
    let roster_before = tokio::fs::read(&owner.named_groups_path)
        .await
        .expect("roster");
    offer(&owner, &asked[1].0, &asked[1].3).await;
    offer(&owner, &asked[1].0, &asked[1].3).await;
    assert_eq!(
        sequencer::waiting(&owner).await,
        1,
        "one slot per requester"
    );
    assert_eq!(
        tokio::fs::read(&owner.named_groups_path)
            .await
            .expect("roster"),
        roster_before,
        "a waiting entry writes no roster state"
    );
    assert!(listener_journal_is_free(&owner).await);
    restart_relay_is_clean(&owner, &[&asked[1].2, &agent_hex(&asked[1].0)]).await;

    offer(&owner, &asked[0].0, &asked[0].3).await;
    offer(&owner, &asked[2].0, &asked[2].3).await;
    let (holders, _) =
        sequencer::drive_turns(&owner, &key, &[&asked[0], &asked[2]], now_millis_u64()).await;
    let silent = agent_hex(&asked[1].0);
    assert_eq!(
        holders.first(),
        Some(&silent),
        "the silent requester was first in line"
    );
    assert_eq!(
        last_link_signers(&owner, &key, 2).await,
        vec![agent_hex(&asked[0].0), agent_hex(&asked[2].0)],
        "the two behind it are listed, in their arrival order"
    );
    assert_eq!(
        sequencer::waiting(&owner).await,
        0,
        "the unserved entry is gone"
    );
    assert!(!pending_request_ids(&owner, &key)
        .await
        .contains(&asked[1].2));
}

/// The relay sidecar holds no trace of a waiting entry, and startup is
/// clean. (The #1842 refusal itself writes the sidecar, to release the
/// journal marker, so the file is searched and not compared byte for byte.)
async fn restart_relay_is_clean(owner: &Arc<AppState>, absent: &[&str]) {
    let sidecar = tokio::fs::read(&owner.predecessor_relay_outbox_path)
        .await
        .unwrap_or_default();
    let sidecar = String::from_utf8_lossy(&sidecar);
    for needle in absent {
        assert!(
            !sidecar.contains(needle),
            "a waiting entry writes no sidecar state"
        );
    }
    load_predecessor_relay_outbox(owner)
        .await
        .expect("startup with a waiting requester is clean");
    assert!(listener_journal_is_free(owner).await);
}

/// Restart with a non-empty queue. The queue is memory only: it is rebuilt
/// from the requesters' re-offers, in the order of those re-offers. No
/// request is lost and none is listed twice.
///
/// RED on main: nobody is listed.
#[tokio::test]
async fn issue1840_queue_is_rebuilt_from_reoffers_after_restart() {
    let (owner, _o) = secure_endpoint_test_state().await.expect("owner state");
    let key = install_authority_group(&owner, b"1840-seq-restart", 1).await;
    let card = authority_card(&owner, &key).await;
    let mut asked = Vec::new();
    for _ in 0..3 {
        asked.push(requester_asks(&card).await);
    }
    for a in &asked {
        offer(&owner, &a.0, &a.3).await;
    }
    sequencer::forget_queue(&owner).await;
    load_predecessor_relay_outbox(&owner)
        .await
        .expect("startup");
    // The requesters' offer workers offer the same envelopes again.
    let reoffer = [2usize, 1, 0];
    for i in reoffer {
        offer(&owner, &asked[i].0, &asked[i].3).await;
    }
    let online: Vec<&Asked> = asked.iter().collect();
    sequencer::drive_turns(&owner, &key, &online, now_millis_u64()).await;
    let expected: Vec<String> = reoffer.iter().map(|i| agent_hex(&asked[*i].0)).collect();
    assert_eq!(last_link_signers(&owner, &key, 3).await, expected);
    assert_eq!(pending_request_ids(&owner, &key).await.len(), 3);
}

/// R1 of the design, traced: after the authority approves a requester whose
/// stub roster is partial, the requester can not apply the approval link.
/// The control is a group with only the owner, where the stub roster is
/// complete and the same apply succeeds.
#[tokio::test]
async fn issue1840_r1_approved_requester_with_partial_stub_cannot_apply_the_approval() {
    for extra_members in [0usize, 1] {
        let (owner, _o) = secure_endpoint_test_state().await.expect("owner state");
        let key = install_authority_group(&owner, b"1840-seq-r1", extra_members).await;
        let asked = requester_asks(&authority_card(&owner, &key).await).await;
        offer(&owner, &asked.0, &asked.3).await;
        sequencer::drive_turns(&owner, &key, &[&asked], now_millis_u64()).await;
        assert_eq!(approve(&owner, &key, &asked.2).await, StatusCode::OK);
        let (commit, revision) = {
            let groups = owner.named_groups.read().await;
            let info = groups.get(&key).expect("group");
            (
                info.commit_log.last().expect("approval").commit.clone(),
                info.roster_revision,
            )
        };
        let stub = asked
            .0
            .named_groups
            .read()
            .await
            .get(&key)
            .expect("stub")
            .clone();
        let (owner_hex, requester_hex) = (agent_hex(&owner), agent_hex(&asked.0));
        let applied = apply_stateful_event_to_group(
            &stub,
            &commit,
            x0x::groups::ActionKind::AdminOrHigher,
            |next| {
                set_join_request_approved(
                    next,
                    &asked.2,
                    &owner_hex,
                    &requester_hex,
                    revision,
                    commit.committed_at,
                )
            },
        );
        eprintln!(
            "R1 extra_members={extra_members}: requester applies approval -> {:?}",
            applied
                .as_ref()
                .map(|_| "applied")
                .map_err(ToString::to_string)
        );
        if extra_members == 0 {
            assert!(
                applied.is_ok(),
                "control: a complete stub applies the approval"
            );
        } else {
            assert!(
                matches!(
                    applied,
                    Err(x0x::groups::ApplyError::StateHashMismatch { .. })
                ),
                "a partial stub refuses the approval with a state hash mismatch"
            );
        }
    }
}

/// Only a request that is still admissible, and whose commit the validator
/// refuses for the head it was sealed over, is queued. Every terminal
/// refusal, every other validator refusal and an over-long request id are
/// not queued.
#[tokio::test]
async fn issue1840_only_head_refusals_are_queued() {
    let (owner, _o) = secure_endpoint_test_state().await.expect("owner state");
    let key = install_authority_group(&owner, b"1840-seq-class", 1).await;
    let asked = requester_asks(&authority_card(&owner, &key).await).await;
    let requester_hex = agent_hex(&asked.0);
    let (request, commit) = {
        let groups = asked.0.named_groups.read().await;
        let stub = groups.get(&key).expect("stub");
        (
            stub.join_requests[&asked.2].clone(),
            stub.commit_log.last().expect("commit").commit.clone(),
        )
    };
    let event_with = |request_id: &str, commit: Option<x0x::groups::GroupStateCommit>| {
        NamedGroupMetadataEvent::JoinRequestCreated {
            group_id: key.clone(),
            request_id: request_id.to_string(),
            requester_agent_id: requester_hex.clone(),
            message: None,
            ts: request.created_at,
            requester_kem_public_key_b64: None,
            treekem_key_package_b64: None,
            commit,
        }
    };
    let base = owner
        .named_groups
        .read()
        .await
        .get(&key)
        .expect("group")
        .clone();
    let owner_hex = agent_hex(&owner);

    // Control: the stub-sealed commit is refused for its head and is queued.
    let good = event_with(&asked.2, Some(commit.clone()));
    assert_eq!(sequencer::refused(&owner, &key, &good).await, 1);
    sequencer::forget_queue(&owner).await;

    let mut member = base.clone();
    member.add_member(
        requester_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(owner_hex.clone()),
        None,
    );
    let mut banned = base.clone();
    banned.ban_member(&requester_hex, Some(owner_hex.clone()));
    let mut pending = base.clone();
    let mut other = request.clone();
    other.request_id = "another-pending-request".to_string();
    pending
        .join_requests
        .insert(other.request_id.clone(), other);
    let mut used = base.clone();
    let mut rejected = request.clone();
    rejected.status = x0x::groups::JoinRequestStatus::Rejected;
    used.join_requests
        .insert(rejected.request_id.clone(), rejected);
    let mut invite_only = base.clone();
    invite_only.policy = x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy();
    for (case, info) in [
        ("member", member),
        ("banned", banned),
        ("pending request", pending),
        ("used request id", used),
        ("not request-access", invite_only),
    ] {
        owner.named_groups.write().await.insert(key.clone(), info);
        assert_eq!(sequencer::refused(&owner, &key, &good).await, 0, "{case}");
    }
    owner.named_groups.write().await.insert(key.clone(), base);

    let mut wrong_group = commit.clone();
    wrong_group.group_id = "ff".repeat(32);
    let mut bad_signature = commit.clone();
    bad_signature.committed_at += 1;
    let long_id = "r".repeat(129);
    for (case, event) in [
        ("no commit", event_with(&asked.2, None)),
        ("group id mismatch", event_with(&asked.2, Some(wrong_group))),
        ("bad signature", event_with(&asked.2, Some(bad_signature))),
        (
            "request id over the cap",
            event_with(&long_id, Some(commit.clone())),
        ),
    ] {
        assert_eq!(sequencer::refused(&owner, &key, &event).await, 0, "{case}");
    }
}
