//! ADR 0110 §3 and §5: the delivery of a seated target's committed
//! removal.
//!
//! The unchanged legacy removal path builds the signed `MemberRemoved`
//! (with its TreeKEM commit) inside its own transaction, publishes it once
//! and resends it on an in-memory schedule. A crash or a partition in that
//! window loses the event: the TreeKEM commit is not stored anywhere else,
//! so no survivor can catch up from this node later.
//!
//! - **Save** ([`record_committed_removal`]). When S4 runs the removal,
//!   its row saves the exact outgoing event, the result head and the epoch,
//!   and moves to `committed_delivery_pending`. The `.evs` is fsynced
//!   before the first publication.
//! - **Delivery** ([`drive`]). The row stays `committed_delivery_pending`
//!   until every eligible survivor accepted the saved event on the direct
//!   carrier. Each write re-checks roster membership and the agent,
//!   machine and binding revocations just before it. Resends stop once the
//!   head moves past the result: old crypto material is never sent after
//!   an epoch change.
//! - **Restart** ([`resume_after_load`]). A saved event is classified
//!   against the verified chain like a crypto-only frame. Only an event
//!   whose result is still the head is resent, and only after the restart
//!   sync wait (§3 "re-sync the head before any resend"). No second rekey
//!   runs.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate as x0x;
use crate::server::state::AppState;
use x0x::groups::eviction::{EvictionKey, ObligationStore, Phase, WaitingCause, WaitingState};
use x0x::groups::GroupInfo;

use super::super::NamedGroupMetadataEvent;
use super::crypto_exclusion::{self, RecipientDelivery, SavedFrameState};

/// A live delivery waits this long before its first send: the legacy
/// removal path already sent the initial volley.
const REMOVAL_FIRST_SEND_DELAY: Duration = Duration::from_secs(5);
/// A delivery round runs no more often than this per row.
const REMOVAL_RESEND_INTERVAL: Duration = Duration::from_secs(5);

/// The retained delivery of one committed seated-target removal.
#[derive(Debug, Clone)]
pub(super) struct RemovalDelivery {
    event: Arc<NamedGroupMetadataEvent>,
    result_head: String,
    /// The event was saved by an earlier boot: no resend before the
    /// restart sync wait.
    resumed: bool,
    recipients: BTreeMap<[u8; 32], RecipientDelivery>,
    next_at: Instant,
}

/// The parts of a saved removal event that the restart needs.
#[derive(Debug, Clone)]
pub(super) struct SavedRemoval {
    pub(super) event: NamedGroupMetadataEvent,
    pub(super) result_head: String,
    pub(super) result_epoch: Option<u64>,
}

/// Decode a saved removal event: a `MemberRemoved` that carries its
/// signed commit. A crypto-only `X0XCE1` frame is not JSON and gives
/// `None`.
pub(super) fn decode_saved_removal(bytes: &[u8]) -> Option<SavedRemoval> {
    let event: NamedGroupMetadataEvent = serde_json::from_slice(bytes).ok()?;
    let NamedGroupMetadataEvent::MemberRemoved {
        commit: Some(commit),
        treekem_epoch,
        secret_epoch,
        ..
    } = &event
    else {
        return None;
    };
    let result_head = commit.state_hash.clone();
    let result_epoch = treekem_epoch.or(*secret_epoch);
    Some(SavedRemoval {
        event,
        result_head,
        result_epoch,
    })
}

fn agent_bytes(hex_id: &str) -> Option<[u8; 32]> {
    super::super::parse_agent_id_hex(hex_id)
        .ok()
        .map(|agent| *agent.as_bytes())
}

/// The Active survivors of `info` other than `local` and `target`.
fn survivors(info: &GroupInfo, local: &[u8; 32], target: &[u8; 32]) -> Vec<[u8; 32]> {
    info.active_members()
        .filter_map(|member| agent_bytes(&member.agent_id))
        .filter(|id| id != local && id != target)
        .collect()
}

fn new_delivery(
    event: NamedGroupMetadataEvent,
    result_head: String,
    recipients: Vec<[u8; 32]>,
    resumed: bool,
    next_at: Instant,
) -> RemovalDelivery {
    RemovalDelivery {
        event: Arc::new(event),
        result_head,
        resumed,
        recipients: recipients
            .into_iter()
            .map(|id| (id, RecipientDelivery::Due))
            .collect(),
        next_at,
    }
}

// ─── Save (§5) ─────────────────────────────────────────────────────────────

/// Save the exact outgoing `MemberRemoved` of S4's own removal of
/// `target_hex` from `info` (the committed after-image).
///
/// The caller is the legacy TreeKEM removal path. It holds the group's
/// membership lock, its roster/crypto transaction is durable, and it has
/// not published the event yet. Only a row that S4 prepared for this
/// removal changes; any other removal returns at once. The `.evs` is
/// fsynced before this returns (§5: "persist ... exact outgoing event
/// before publication").
pub(in crate::server) async fn record_committed_removal(
    state: &AppState,
    info: &GroupInfo,
    target_hex: &str,
    event: &NamedGroupMetadataEvent,
) {
    let Some(target) = agent_bytes(target_hex) else {
        return;
    };
    let Ok(bytes) = serde_json::to_vec(event) else {
        return;
    };
    let Some(saved) = decode_saved_removal(&bytes) else {
        return;
    };
    let key = EvictionKey::new(info.stable_group_id().to_string(), target);
    let local = *state.agent.agent_id().as_bytes();
    {
        let mut inner = state.revocation_evictions.inner.lock().await;
        let Some(row) = inner.store.get_mut(&key) else {
            return;
        };
        if row.phase != Phase::Prepared {
            return;
        }
        row.phase = Phase::CommittedDeliveryPending;
        row.result_head = Some(saved.result_head.clone());
        row.result_epoch = saved.result_epoch;
        row.outgoing_event = Some(bytes);
        row.waiting = None;
        inner.removals.insert(
            key,
            new_delivery(
                saved.event,
                saved.result_head,
                survivors(info, &local, &target),
                false,
                Instant::now() + REMOVAL_FIRST_SEND_DELAY,
            ),
        );
        inner.dirty = true;
    }
    if !super::persist_obligations(state).await {
        tracing::warn!(
            group_id = %super::super::LogHexId::group(info.stable_group_id()),
            target = %super::super::LogHexId::agent(target_hex),
            "ADR 0110 S4: the saved removal event is not durable yet"
        );
    }
}

// ─── Restart (§3) ──────────────────────────────────────────────────────────

/// What a restart does with one saved removal event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ResumeAction {
    /// The result is the head: resend the saved event after the restart
    /// sync wait, with no second rekey.
    Deliver,
    /// The head moved past the result: discard the delivery; the next pass
    /// completes the row from the chain.
    Discard,
    /// The legacy commit did not land: the row returns to `pending`.
    Abandon,
    /// A competing branch: keep the event as fork evidence and never
    /// publish it.
    Fork,
    /// The relation is unknown yet: `waiting_for_head_sync`.
    WaitForHeadSync,
}

/// Classify a saved removal against `info`'s verified chain (§3).
pub(super) fn classify(
    info: &GroupInfo,
    parent_head: Option<&str>,
    result_head: &str,
) -> ResumeAction {
    let Some(parent_head) = parent_head else {
        // Without the parent the relation cannot be proved; a head equal
        // to the result is still the committed removal.
        return if info.fork_quarantine.is_none() && info.state_hash == result_head {
            ResumeAction::Deliver
        } else {
            ResumeAction::WaitForHeadSync
        };
    };
    match crypto_exclusion::classify_saved_frame(info, parent_head, result_head) {
        SavedFrameState::CurrentHead => ResumeAction::Deliver,
        SavedFrameState::Superseded => ResumeAction::Discard,
        SavedFrameState::Abandoned => ResumeAction::Abandon,
        SavedFrameState::Fork => ResumeAction::Fork,
        SavedFrameState::Unknown => ResumeAction::WaitForHeadSync,
    }
}

/// §3 restart: reconcile every open row that holds a saved removal event
/// against the loaded, verified chain.
pub(super) fn resume_after_load(
    groups: &[(String, GroupInfo)],
    local: &[u8; 32],
    store: &mut ObligationStore,
    removals: &mut HashMap<EvictionKey, RemovalDelivery>,
    ce_state: &mut crypto_exclusion::CeState,
) {
    let saved: Vec<(EvictionKey, SavedRemoval)> = store
        .rows()
        .filter(|row| row.phase.is_open())
        .filter_map(|row| {
            let saved = decode_saved_removal(row.outgoing_event.as_deref()?)?;
            Some((row.key(), saved))
        })
        .collect();
    for (key, saved) in saved {
        let Some(info) = groups
            .iter()
            .map(|(_, info)| info)
            .find(|info| info.stable_group_id() == key.stable_group_id)
        else {
            continue;
        };
        let Some(row) = store.get_mut(&key) else {
            continue;
        };
        match classify(info, row.parent_head.as_deref(), &saved.result_head) {
            ResumeAction::Deliver => {
                row.phase = Phase::CommittedDeliveryPending;
                row.result_head = Some(saved.result_head.clone());
                removals.insert(
                    key.clone(),
                    new_delivery(
                        saved.event,
                        saved.result_head,
                        survivors(info, local, &key.target),
                        true,
                        Instant::now(),
                    ),
                );
            }
            ResumeAction::Discard => {
                row.phase = Phase::CommittedDeliveryPending;
                row.result_head = Some(saved.result_head);
                row.outgoing_event = None;
            }
            ResumeAction::Abandon => {
                row.phase = Phase::Pending;
                row.parent_head = None;
                row.result_head = None;
                row.result_epoch = None;
                row.outgoing_event = None;
            }
            ResumeAction::Fork => {
                ce_state.fork.insert(key.clone());
                tracing::warn!(
                    group_id = %super::super::LogHexId::group(&key.stable_group_id),
                    target = %super::super::LogHexId::agent(&hex::encode(key.target)),
                    "ADR 0110 S4: a saved removal meets a competing branch; waiting for fork resolution"
                );
            }
            ResumeAction::WaitForHeadSync => {
                row.waiting = Some(WaitingState::cause(WaitingCause::WaitingForHeadSync));
            }
        }
    }
}

// ─── Delivery ──────────────────────────────────────────────────────────────

/// One delivery round for every due saved removal: per recipient,
/// re-check the roster and the agent, machine and binding revocations,
/// then send the saved event on the direct carrier.
pub(super) async fn drive(state: &Arc<AppState>) {
    let runtime = &state.revocation_evictions;
    let now = Instant::now();
    let head_synced = runtime.head_synced(now);
    let due: Vec<(EvictionKey, RemovalDelivery)> = {
        let mut inner = runtime.inner.lock().await;
        let keys: Vec<EvictionKey> = inner
            .removals
            .iter()
            .filter(|(_, delivery)| delivery.next_at <= now && (!delivery.resumed || head_synced))
            .map(|(key, _)| key.clone())
            .collect();
        keys.into_iter()
            .filter_map(|key| {
                let delivery = inner.removals.get_mut(&key)?;
                delivery.next_at = now + REMOVAL_RESEND_INTERVAL;
                Some((key, delivery.clone()))
            })
            .collect()
    };
    if due.is_empty() {
        return;
    }
    let local = *state.agent.agent_id().as_bytes();
    for (key, delivery) in due {
        let info = {
            let groups = state.named_groups.read().await;
            groups
                .values()
                .find(|info| info.stable_group_id() == key.stable_group_id)
                .cloned()
        };
        let Some(info) = info.filter(|info| !info.withdrawn) else {
            runtime.inner.lock().await.removals.remove(&key);
            continue;
        };
        if info.fork_quarantine.is_some() {
            let mut inner = runtime.inner.lock().await;
            inner.removals.remove(&key);
            inner.ce.fork.insert(key.clone());
            continue;
        }
        if info.state_hash != delivery.result_head {
            // The head moved past the removal: never resend old crypto
            // material after an epoch change.
            let mut inner = runtime.inner.lock().await;
            inner.removals.remove(&key);
            inner.dirty = true;
            continue;
        }
        let active: std::collections::BTreeSet<[u8; 32]> =
            survivors(&info, &local, &key.target).into_iter().collect();
        let mut updates: Vec<([u8; 32], Option<RecipientDelivery>)> = Vec::new();
        for (recipient, status) in &delivery.recipients {
            if !active.contains(recipient) {
                updates.push((*recipient, None));
                continue;
            }
            if matches!(
                status,
                RecipientDelivery::Sent | RecipientDelivery::InFlight
            ) {
                continue;
            }
            let agent = x0x::identity::AgentId(*recipient);
            if !crypto_exclusion::write_allowed(state, &agent).await {
                continue;
            }
            let recipient_hex = hex::encode(recipient);
            let Some(send) = super::super::named_group_event_send_future(
                state,
                &recipient_hex,
                &delivery.event,
                "s4-removal",
            ) else {
                updates.push((*recipient, None));
                continue;
            };
            updates.push((*recipient, Some(RecipientDelivery::InFlight)));
            spawn_send(state, key.clone(), *recipient, send);
        }
        let mut inner = runtime.inner.lock().await;
        if let Some(stored) = inner.removals.get_mut(&key) {
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
                inner.removals.remove(&key);
                inner.dirty = true;
            }
        }
    }
}

fn spawn_send(
    state: &Arc<AppState>,
    key: EvictionKey,
    recipient: [u8; 32],
    send: impl std::future::Future<Output = Result<(), String>> + Send + 'static,
) {
    let task_state = Arc::clone(state);
    let _spawned = state.spawn_detached(async move {
        let status = match send.await {
            Ok(()) => RecipientDelivery::Sent,
            Err(error) => {
                tracing::debug!(%error, "ADR 0110 S4: saved removal send failed; retrying");
                RecipientDelivery::Due
            }
        };
        let mut inner = task_state.revocation_evictions.inner.lock().await;
        if let Some(delivery) = inner.removals.get_mut(&key) {
            if let Some(entry) = delivery.recipients.get_mut(&recipient) {
                *entry = status;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap as Map;
    use x0x::groups::state_commit::{GroupStateCommit, RetainedCommit};
    use x0x::groups::GroupRole;

    fn commit(prev: &str, hash: &str) -> GroupStateCommit {
        GroupStateCommit {
            group_id: "g".to_string(),
            revision: 4,
            prev_state_hash: Some(prev.to_string()),
            roster_root: String::new(),
            policy_hash: String::new(),
            public_meta_hash: String::new(),
            security_binding: None,
            state_hash: hash.to_string(),
            withdrawn: false,
            committed_by: String::new(),
            committed_at: 0,
            signer_public_key: String::new(),
            signature: String::new(),
        }
    }

    fn info_with_log(head: &str, log: &[(&str, &str)]) -> GroupInfo {
        let mut info = GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            x0x::identity::AgentId([1; 32]),
            "ab".repeat(16),
        );
        info.state_hash = head.to_string();
        for (prev, hash) in log {
            info.commit_log.push(RetainedCommit {
                commit: commit(prev, hash),
                roster: Map::new(),
                meta: None,
            });
        }
        info
    }

    fn removal_bytes(prev: &str, hash: &str) -> Vec<u8> {
        let event = NamedGroupMetadataEvent::MemberRemoved {
            group_id: "g".to_string(),
            revision: 4,
            actor: "aa".repeat(32),
            agent_id: "bb".repeat(32),
            treekem_commit_b64: Some("Y29tbWl0".to_string()),
            treekem_epoch: Some(3),
            secret_epoch: None,
            commit: Some(commit(prev, hash)),
        };
        serde_json::to_vec(&event).expect("encode")
    }

    #[test]
    fn saved_removal_decodes_its_result_head_and_epoch() {
        let saved = decode_saved_removal(&removal_bytes("p", "r")).expect("decoded");
        assert_eq!(saved.result_head, "r");
        assert_eq!(saved.result_epoch, Some(3));
        assert!(decode_saved_removal(b"X0XCE1\0frame").is_none());
    }

    /// The `s4_restart_intake_prepare` crash: the legacy commit landed and
    /// was persisted, its publication was lost, and the restarted node's
    /// head is the removal's result. The saved event is delivered again,
    /// with no second rekey.
    #[test]
    fn committed_removal_on_the_current_head_is_delivered_again() {
        let info = info_with_log("r", &[("p", "r")]);
        assert_eq!(classify(&info, Some("p"), "r"), ResumeAction::Deliver);
        assert_eq!(classify(&info, None, "r"), ResumeAction::Deliver);
    }

    #[test]
    fn committed_removal_behind_a_later_head_is_discarded() {
        let info = info_with_log("later", &[("p", "r"), ("r", "later")]);
        assert_eq!(classify(&info, Some("p"), "r"), ResumeAction::Discard);
    }

    #[test]
    fn removal_on_an_unchanged_parent_is_abandoned() {
        let info = info_with_log("p", &[]);
        assert_eq!(classify(&info, Some("p"), "r"), ResumeAction::Abandon);
    }

    #[test]
    fn removal_beside_a_competing_child_is_a_fork() {
        let info = info_with_log("other", &[("p", "other")]);
        assert_eq!(classify(&info, Some("p"), "r"), ResumeAction::Fork);
    }

    #[test]
    fn removal_with_an_unrelated_head_waits_for_head_sync() {
        let info = info_with_log("x", &[]);
        assert_eq!(
            classify(&info, Some("p"), "r"),
            ResumeAction::WaitForHeadSync
        );
        assert_eq!(classify(&info, None, "r"), ResumeAction::WaitForHeadSync);
    }

    #[test]
    fn resume_restores_the_delivery_to_each_survivor() {
        // The creator in `info_with_log` is this node.
        let local = [1; 32];
        let target = [0xbb; 32];
        let survivor = [0xcc; 32];
        let mut info = info_with_log("r", &[("p", "r")]);
        for id in [local, target, survivor] {
            info.add_member(hex::encode(id), GroupRole::Member, None, None);
        }
        info.remove_member(&hex::encode(target), Some(hex::encode(local)));
        let key = EvictionKey::new(info.stable_group_id().to_string(), target);
        let mut store = ObligationStore::new();
        store.intake(
            &key,
            x0x::groups::eviction::EvictionTrigger::AgentRevocation {
                record_hash: [7; 32],
                record_bytes: vec![7],
            },
            None,
            0,
            [0; 16],
        );
        let row = store.get_mut(&key).expect("row");
        row.phase = Phase::CommittedDeliveryPending;
        row.parent_head = Some("p".to_string());
        row.outgoing_event = Some(removal_bytes("p", "r"));
        let mut removals = HashMap::new();
        let mut ce_state = crypto_exclusion::CeState::default();
        let groups = vec![("g".to_string(), info)];
        resume_after_load(&groups, &local, &mut store, &mut removals, &mut ce_state);
        let delivery = removals.get(&key).expect("delivery resumed");
        assert!(delivery.resumed);
        assert_eq!(delivery.result_head, "r");
        assert_eq!(
            delivery.recipients.keys().copied().collect::<Vec<_>>(),
            vec![survivor]
        );
        assert_eq!(
            store.get(&key).expect("row").phase,
            Phase::CommittedDeliveryPending
        );
    }
}
