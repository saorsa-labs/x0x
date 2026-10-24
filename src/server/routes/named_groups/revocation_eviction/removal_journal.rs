//! ADR 0110 §5: the prepare barrier of a seated target's removal or ban.
//!
//! The §5 order is: the exact outgoing frame goes into a prepared
//! `.evjournal` and the `.evs` row first, then the legacy roster/crypto
//! transaction runs, then the row moves to `committed_delivery_pending`
//! and the journal retires. The crypto-only exclusion has always done
//! this. A seated-target removal or ban builds its `MemberRemoved` or
//! `MemberBanned` (with the signed state commit, and the TreeKEM commit
//! or the rotated GSS secret epoch) inside the legacy route. Every such
//! route that S4 can run (TreeKEM, GSS `MlsEncrypted` and `SignedPublic`;
//! remove and ban) goes through the one [`RemovalBarrier`] after it builds
//! the event and before it persists anything.
//!
//! - **Prepare** ([`RemovalBarrier::prepare`]). Only a row that S4
//!   prepared for this removal changes. The row and the journal get the
//!   exact event, its result head and its epoch, and both are fsynced. If
//!   either write fails, or the §1a/D135 re-check cancels the work, the
//!   removal must not commit.
//! - **Abandon** ([`RemovalBarrier::abandon`]). The legacy transaction
//!   failed after the prepare: the saved event is cleared, so a restart
//!   never delivers an event that did not commit.
//! - **Not durable** ([`RemovalBarrier::not_durable`]). The roster write
//!   was not directory-durable. If the new roster is live anyway, the
//!   removal committed: the event is kept and delivered with the rotated
//!   secret. If it is not live, this is an abandon.
//! - **Committed** ([`RemovalBarrier::committed`]). The transaction is
//!   durable: the row moves to `committed_delivery_pending` and its
//!   delivery starts, before the first publication.
//! - **Restart** ([`adopt_journal_removals`]). A journal that holds a
//!   removal event gives that event to its row when the `.evs` row has
//!   none. `removal_delivery::resume_after_load` then classifies it
//!   against the verified chain like a crypto-only frame: a landed commit
//!   is delivered again, an unchanged parent returns the row to `pending`.

use std::collections::HashMap;

use axum::http::StatusCode;
use axum::Json;

use crate as x0x;
use crate::server::state::AppState;
use x0x::groups::eviction::{self as s4, EvJournalV1, EvictionKey, ObligationStore, Phase};
use x0x::groups::GroupInfo;

use super::super::NamedGroupMetadataEvent;
use super::removal_delivery::decode_saved_removal;

/// The reply of a route that the barrier stops.
type RouteReply = (StatusCode, Json<serde_json::Value>);

/// ADR 0110 §5: the one prepare barrier of every roster removal or ban
/// that S4 can run, on every plane.
///
/// The route builds its exact outgoing event first. Then it calls
/// [`Self::prepare`], persists its roster/crypto transaction, and calls
/// [`Self::abandon`] if the persist fails or [`Self::committed`] at once
/// after it is durable, before any publication. A removal that S4 did not
/// prepare passes through unchanged.
#[must_use = "a prepared removal must be abandoned or committed"]
pub(in crate::server) struct RemovalBarrier {
    /// S4 prepared this removal and its event is durable.
    s4: bool,
}

impl RemovalBarrier {
    /// §5 step 1: save `event`, the exact outgoing event of the removal or
    /// ban of `target_hex`, for S4's prepared row. `info` is the sealed
    /// after-image. The caller holds the group's membership lock and has
    /// not persisted the transaction yet. On `Err` the caller rolls back
    /// what it changed in memory and returns the reply.
    pub(in crate::server) async fn prepare(
        state: &AppState,
        info: &GroupInfo,
        target_hex: &str,
        event: &NamedGroupMetadataEvent,
    ) -> Result<Self, RouteReply> {
        match prepare_committed_removal(state, info, target_hex, event).await {
            RemovalPrepare::NotS4 => Ok(Self { s4: false }),
            RemovalPrepare::Durable => Ok(Self { s4: true }),
            RemovalPrepare::NotDurable => {
                let error = if matches!(event, NamedGroupMetadataEvent::MemberBanned { .. }) {
                    "ban event is not durable yet"
                } else {
                    "removal event is not durable yet"
                };
                Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({ "ok": false, "error": error })),
                ))
            }
            RemovalPrepare::Cancelled => Err(super::s4_exclusion_cancelled_response()),
        }
    }

    /// The transaction did not persist: clear the saved event.
    pub(in crate::server) async fn abandon(
        self,
        state: &AppState,
        info: &GroupInfo,
        target_hex: &str,
    ) {
        if self.s4 {
            abandon_prepared_removal(state, info, target_hex).await;
        }
    }

    /// §3 and §5: the transaction is durable. S4's row moves to
    /// `committed_delivery_pending` and its delivery to each survivor
    /// starts. Call it before the first publication. `info` is the
    /// committed after-image.
    ///
    /// `Err` only in tests: the test crash point after the commit
    /// (`crash_after_removal_commit_on_this_thread_for_test`).
    pub(in crate::server) async fn committed(
        self,
        state: &AppState,
        info: &GroupInfo,
        target_hex: &str,
        event: &NamedGroupMetadataEvent,
    ) -> Result<(), RouteReply> {
        #[cfg(test)]
        if super::super::CRASH_AFTER_REMOVAL_COMMIT_FOR_TEST.with(|flag| flag.replace(false)) {
            // Test-only crash: the transaction is durable, nothing after it ran.
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "ok": false, "error": "test crash after commit" })),
            ));
        }
        if self.s4 {
            super::record_committed_removal(state, info, target_hex, event, false).await;
        }
        Ok(())
    }

    /// The transaction did not reach directory durability. When its sealed
    /// after-image `info` is nevertheless the live head (a
    /// `ReplacedNotDurable` roster write, or an installed TreeKEM epoch),
    /// the removal has committed: the saved event is kept and S4 delivers
    /// it and, for GSS, the rotated secret, because the route stops before
    /// its own publication (#1508 review P1). Otherwise the saved event is
    /// cleared as in [`Self::abandon`]. Returns whether the removal is live.
    pub(in crate::server) async fn not_durable(
        self,
        state: &AppState,
        info: &GroupInfo,
        target_hex: &str,
        event: &NamedGroupMetadataEvent,
    ) -> bool {
        let live = live_head_is(state, info).await;
        if self.s4 {
            if live {
                super::record_committed_removal(state, info, target_hex, event, true).await;
            } else {
                abandon_prepared_removal(state, info, target_hex).await;
            }
        }
        live
    }

    /// A TreeKEM persist failed. When the error says the epoch is
    /// installed, this is [`Self::not_durable`]; otherwise it is
    /// [`Self::abandon`]. Returns whether the removal is live, in which case
    /// the caller must not roll the tree back.
    pub(in crate::server) async fn persist_failed(
        self,
        state: &AppState,
        info: &GroupInfo,
        target_hex: &str,
        event: &NamedGroupMetadataEvent,
        epoch_installed: bool,
    ) -> bool {
        if epoch_installed {
            self.not_durable(state, info, target_hex, event).await
        } else {
            self.abandon(state, info, target_hex).await;
            false
        }
    }
}

/// Whether the live roster of `info`'s group is `info`'s sealed head.
/// #1574 item 4: the read holds `named_groups_persistence_lock`, because
/// `persist_named_group_info` shows its candidate in the map before the
/// write and restores the map when the write fails. An unlocked read can
/// decide on that candidate — a removal whose transaction rolls back would
/// be recorded as committed and delivered. Under the lock the read sees
/// only roster states a write already committed to (`Durable` or kept
/// `ReplacedNotDurable`) or restored.
async fn live_head_is(state: &AppState, info: &GroupInfo) -> bool {
    let _committed = state.named_groups_persistence_lock.lock().await;
    state.named_groups.read().await.values().any(|group| {
        group.stable_group_id() == info.stable_group_id() && group.state_hash == info.state_hash
    })
}

/// The result of [`prepare_committed_removal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemovalPrepare {
    /// S4 did not prepare this removal: the legacy path runs unchanged.
    NotS4,
    /// The exact event is durable in the `.evjournal` and the `.evs`.
    Durable,
    /// The event could not be made durable: do not commit the removal.
    NotDurable,
    /// The §1a/D135 re-check under the lock cancelled S4's removal: do not
    /// commit it; reply `409 s4_exclusion_cancelled`.
    Cancelled,
}

fn row_key(info: &GroupInfo, target_hex: &str) -> Option<EvictionKey> {
    let target = super::super::parse_agent_id_hex(target_hex).ok()?;
    Some(EvictionKey::new(
        info.stable_group_id().to_string(),
        *target.as_bytes(),
    ))
}

/// Read the prepared journal of `key`, when the file holds one for it.
async fn read_prepared_journal(path: &std::path::Path, key: &EvictionKey) -> Option<EvJournalV1> {
    let bytes = tokio::fs::read(path).await.ok()?;
    let journal = s4::decode_evjournal(&bytes).ok()?;
    (journal.stable_group_id == key.stable_group_id && journal.target == key.target)
        .then_some(journal)
}

/// §5 step 1 of S4's removal of `target_hex`: save the exact outgoing
/// `event` in the prepared `.evjournal` and the `.evs` row, and fsync both,
/// before the legacy transaction commits (see [`RemovalBarrier::prepare`]).
async fn prepare_committed_removal(
    state: &AppState,
    info: &GroupInfo,
    target_hex: &str,
    event: &NamedGroupMetadataEvent,
) -> RemovalPrepare {
    let Some(key) = row_key(info, target_hex) else {
        return RemovalPrepare::NotS4;
    };
    // §1a/D135 (#1508 review): re-check the trigger and its cancellation
    // under the caller's membership lock, against the current committed
    // seat, just before the commit.
    let target = hex::encode(key.target);
    let seat = state
        .named_groups
        .read()
        .await
        .values()
        .find(|group| group.stable_group_id() == key.stable_group_id)
        .and_then(|group| group.members_v2.get(&target).cloned());
    match super::locked_removal_state(state, &key, seat.as_ref()).await {
        super::LockedRemoval::NotS4 => return RemovalPrepare::NotS4,
        super::LockedRemoval::Cancelled => return RemovalPrepare::Cancelled,
        super::LockedRemoval::Prepared => {}
    }
    let Ok(bytes) = serde_json::to_vec(event) else {
        return RemovalPrepare::NotDurable;
    };
    let Some(saved) = decode_saved_removal(&bytes) else {
        return RemovalPrepare::NotDurable;
    };
    let path = super::evjournal_path(state, &key.stable_group_id);
    let existing = read_prepared_journal(&path, &key).await;
    let journal = {
        let mut inner = state.revocation_evictions.inner.lock().await;
        let Some(row) = inner.store.get_mut(&key) else {
            return RemovalPrepare::NotS4;
        };
        let Some(parent_head) = row.parent_head.clone() else {
            return RemovalPrepare::NotS4;
        };
        if row.phase != Phase::Prepared {
            return RemovalPrepare::NotS4;
        }
        row.result_head = Some(saved.result_head.clone());
        row.result_epoch = saved.result_epoch;
        row.outgoing_event = Some(bytes.clone());
        let mut journal = super::prepared_journal(row, parent_head, info.state_revision);
        if let Some(existing) = existing {
            // Keep the transaction identity of the journal S4 wrote first.
            journal.txid = existing.txid;
        }
        journal.result_epoch = saved.result_epoch;
        journal.result_head = Some(saved.result_head);
        journal.outgoing_event = bytes;
        inner.dirty = true;
        journal
    };
    let written = super::write_evjournal(&path, &journal).await;
    let durable = written && super::persist_obligations(state).await;
    if durable {
        return RemovalPrepare::Durable;
    }
    tracing::warn!(
        group_id = %super::super::LogHexId::group(info.stable_group_id()),
        target = %super::super::LogHexId::agent(target_hex),
        "ADR 0110 S4: the removal event is not durable; the removal does not commit"
    );
    abandon_prepared_removal(state, info, target_hex).await;
    RemovalPrepare::NotDurable
}

/// The legacy transaction did not commit after [`prepare_committed_removal`]:
/// clear the saved event of the still-`prepared` row. The S4 caller then
/// returns the row to `pending`, persists the `.evs` and retires the
/// journal.
async fn abandon_prepared_removal(state: &AppState, info: &GroupInfo, target_hex: &str) {
    let Some(key) = row_key(info, target_hex) else {
        return;
    };
    let mut inner = state.revocation_evictions.inner.lock().await;
    let Some(row) = inner.store.get_mut(&key) else {
        return;
    };
    if row.phase != Phase::Prepared {
        return;
    }
    row.result_head = None;
    row.result_epoch = None;
    row.outgoing_event = None;
    inner.dirty = true;
}

/// §5 restart: give each open row the removal event of its prepared
/// journal when the `.evs` row lost it or never saved it. The parent head
/// comes from the journal too, so the classification against the chain
/// can tell a landed commit from an unchanged parent.
pub(super) fn adopt_journal_removals(
    store: &mut ObligationStore,
    journals: &HashMap<EvictionKey, EvJournalV1>,
) {
    for (key, journal) in journals {
        let Some(saved) = decode_saved_removal(&journal.outgoing_event) else {
            continue;
        };
        let Some(row) = store.get_mut(key) else {
            continue;
        };
        if !row.phase.is_open() || row.outgoing_event.is_some() {
            continue;
        }
        row.parent_head = Some(journal.parent_head.clone());
        row.result_head = Some(saved.result_head);
        row.result_epoch = saved.result_epoch;
        row.outgoing_event = Some(journal.outgoing_event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::server::routes::named_groups::tests::secure_endpoint_test_state;
    use x0x::groups::eviction::EvictionTrigger;

    fn commit(prev: &str, hash: &str) -> x0x::groups::state_commit::GroupStateCommit {
        x0x::groups::state_commit::GroupStateCommit {
            group_id: "g".to_string(),
            revision: 2,
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

    fn removal_bytes(prev: &str, hash: &str, target: &[u8; 32]) -> Vec<u8> {
        let event = NamedGroupMetadataEvent::MemberRemoved {
            group_id: "g".to_string(),
            revision: 2,
            actor: "a".repeat(64),
            agent_id: hex::encode(target),
            treekem_commit_b64: Some("Y29tbWl0".to_string()),
            treekem_epoch: Some(3),
            secret_epoch: None,
            commit: Some(commit(prev, hash)),
        };
        serde_json::to_vec(&event).unwrap_or_default()
    }

    fn prepared_store(key: &EvictionKey) -> ObligationStore {
        let mut store = ObligationStore::new();
        store.intake(
            key,
            EvictionTrigger::SelfLeave {
                commit_hash: "p".to_string(),
            },
            None,
            0,
            [0; 16],
        );
        if let Some(row) = store.get_mut(key) {
            row.phase = Phase::Prepared;
        }
        store
    }

    fn journal(key: &EvictionKey, outgoing_event: Vec<u8>) -> EvJournalV1 {
        EvJournalV1 {
            txid: [1; 16],
            stable_group_id: key.stable_group_id.clone(),
            target: key.target,
            parent_head: "p".to_string(),
            next_revision: 2,
            result_epoch: Some(3),
            evidence: Vec::new(),
            outgoing_event,
            result_head: Some("r".to_string()),
        }
    }

    #[test]
    fn a_journal_removal_event_is_adopted_by_its_row() {
        let key = EvictionKey::new("g", [7; 32]);
        let mut store = prepared_store(&key);
        let bytes = removal_bytes("p", "r", &key.target);
        let journals = HashMap::from([(key.clone(), journal(&key, bytes.clone()))]);
        adopt_journal_removals(&mut store, &journals);
        let row = store.get(&key).expect("row");
        assert_eq!(row.outgoing_event.as_deref(), Some(bytes.as_slice()));
        assert_eq!(row.parent_head.as_deref(), Some("p"));
        assert_eq!(row.result_head.as_deref(), Some("r"));
        assert_eq!(row.result_epoch, Some(3));
    }

    #[test]
    fn an_empty_or_crypto_journal_is_not_a_removal_event() {
        let key = EvictionKey::new("g", [7; 32]);
        let mut store = prepared_store(&key);
        let journals = HashMap::from([
            (key.clone(), journal(&key, Vec::new())),
            (
                EvictionKey::new("g", [8; 32]),
                journal(&key, b"X0XCE1\0frame".to_vec()),
            ),
        ]);
        adopt_journal_removals(&mut store, &journals);
        assert!(store.get(&key).expect("row").outgoing_event.is_none());
    }

    #[test]
    fn a_saved_row_event_wins_over_the_journal() {
        let key = EvictionKey::new("g", [7; 32]);
        let mut store = prepared_store(&key);
        let saved = removal_bytes("p", "r", &key.target);
        if let Some(row) = store.get_mut(&key) {
            row.outgoing_event = Some(saved.clone());
        }
        let journals = HashMap::from([(
            key.clone(),
            journal(&key, removal_bytes("p", "other", &key.target)),
        )]);
        adopt_journal_removals(&mut store, &journals);
        assert_eq!(
            store.get(&key).expect("row").outgoing_event.as_deref(),
            Some(saved.as_slice())
        );
    }

    /// A two-member TreeKEM group on `state`: the local admin and a seated
    /// target with its KeyPackage, plus one roster-only survivor.
    async fn seated_target_group(
        state: &AppState,
        group_id: &str,
    ) -> anyhow::Result<(String, x0x::identity::AgentKeypair)> {
        let admin_id = state.agent.agent_id();
        let group_id_bytes = hex::decode(group_id)?;
        let seed = super::super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
        let mut admin_group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, admin_id, &seed)?;
        let target_kp = x0x::identity::AgentKeypair::generate()?;
        let target_id = target_kp.agent_id();
        let target_hex = hex::encode(target_id.as_bytes());
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(target_id, &[9u8; 32])?;
        let kp_bytes = prepared.key_package_bytes().to_vec();
        admin_group.add_member(target_id, &kp_bytes)?;
        let epoch = admin_group.epoch();
        let admin_hex = hex::encode(admin_id.as_bytes());
        let mut info = GroupInfo::new(
            "s4-removal-journal".to_string(),
            String::new(),
            admin_id,
            group_id.to_string(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        info.add_member(
            target_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.set_member_treekem_key_package(
            &target_hex,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &kp_bytes),
        );
        let survivor = x0x::identity::AgentKeypair::generate()?.agent_id();
        info.add_member(
            hex::encode(survivor.as_bytes()),
            x0x::groups::GroupRole::Member,
            Some(admin_hex),
            None,
        );
        info.secret_epoch = epoch;
        info.security_binding = Some(format!("treekem:epoch={epoch}"));
        info.recompute_state_hash();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info);
        state.treekem_groups.write().await.insert(
            group_id.to_string(),
            Arc::new(tokio::sync::Mutex::new(admin_group)),
        );
        Ok((target_hex, target_kp))
    }

    /// ADR 0110 §5 crash window (#1357 review): S4 prepared the removal,
    /// the legacy roster/crypto transaction committed the new epoch, and
    /// the process died before the old post-commit save of the outgoing
    /// event. A restart must still hold the exact `MemberRemoved` with its
    /// TreeKEM commit and deliver it to the survivors; it must not return
    /// the row to `pending` with no event.
    #[tokio::test]
    async fn a_crash_after_the_removal_commit_keeps_the_exact_event() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "ab".repeat(16);
        let (target_hex, _) = seated_target_group(&state, &group_id).await?;
        let target = super::super::super::parse_agent_id_hex(&target_hex)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let (stable, parent_head, next_revision) = {
            let groups = state.named_groups.read().await;
            let info = groups.get(&group_id).expect("group");
            (
                info.stable_group_id().to_string(),
                info.state_hash.clone(),
                info.state_revision.saturating_add(1),
            )
        };
        let key = EvictionKey::new(stable, *target.as_bytes());

        // S4's prepare step, as `commit_removal` runs it.
        let journal = {
            let mut inner = state.revocation_evictions.inner.lock().await;
            inner.store = prepared_store(&key);
            let row = inner.store.get_mut(&key).expect("row");
            row.parent_head = Some(parent_head.clone());
            let journal = super::super::prepared_journal(row, parent_head, next_revision);
            inner.dirty = true;
            journal
        };
        let journal_path = super::super::evjournal_path(&state, &key.stable_group_id);
        assert!(super::super::write_evjournal(&journal_path, &journal).await);
        assert!(super::super::persist_obligations(&state).await);

        // The legacy transaction commits, then the process dies.
        super::super::super::crash_after_removal_commit_on_this_thread_for_test();
        let membership_lock = super::super::super::group_membership_lock(&state, &group_id).await;
        let membership_guard = membership_lock.lock().await;
        let (status, body) = super::super::super::remove_treekem_named_group_member(
            Arc::clone(&state),
            group_id.clone(),
            target_hex.clone(),
            hex::encode(state.agent.agent_id().as_bytes()),
        )
        .await;
        drop(membership_guard);
        assert_eq!(
            status,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "{body:?}"
        );
        let committed_head = {
            let groups = state.named_groups.read().await;
            let info = groups.get(&group_id).expect("group");
            assert!(
                !info.has_active_member(&target_hex),
                "the legacy transaction committed the removal"
            );
            info.state_hash.clone()
        };

        // Restart: the S4 state is reloaded from disk.
        *state.revocation_evictions.inner.lock().await = super::super::S4Inner::default();
        super::super::load_persisted_obligations(&state).await;

        let inner = state.revocation_evictions.inner.lock().await;
        let row = inner.store.get(&key).expect("row survives the restart");
        assert_eq!(
            row.phase,
            Phase::CommittedDeliveryPending,
            "the committed removal is still being delivered"
        );
        assert_eq!(row.result_head.as_deref(), Some(committed_head.as_str()));
        let saved = row
            .outgoing_event
            .as_deref()
            .and_then(decode_saved_removal)
            .expect("the exact MemberRemoved survives the crash");
        assert!(matches!(
            saved.event,
            NamedGroupMetadataEvent::MemberRemoved {
                treekem_commit_b64: Some(_),
                ..
            }
        ));
        assert!(
            inner.removals.contains_key(&key),
            "restart resumes the delivery to the survivors"
        );
        Ok(())
    }

    /// S4's prepare step of `commit_removal` for the row of `target_hex`
    /// in `group_id`: the row in `store` moves to `prepared` and the
    /// prepared `.evjournal` and the `.evs` are written. Returns the key.
    async fn s4_prepare(
        state: &AppState,
        group_id: &str,
        target_hex: &str,
        store: impl FnOnce(&EvictionKey) -> ObligationStore,
    ) -> anyhow::Result<EvictionKey> {
        let target = super::super::super::parse_agent_id_hex(target_hex)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let (stable, parent_head, next_revision) = {
            let groups = state.named_groups.read().await;
            let info = groups.get(group_id).expect("group");
            (
                info.stable_group_id().to_string(),
                info.state_hash.clone(),
                info.state_revision.saturating_add(1),
            )
        };
        let key = EvictionKey::new(stable, *target.as_bytes());
        let journal = {
            let mut inner = state.revocation_evictions.inner.lock().await;
            inner.store = store(&key);
            let row = inner.store.get_mut(&key).expect("row");
            row.phase = Phase::Prepared;
            row.parent_head = Some(parent_head.clone());
            let journal = super::super::prepared_journal(row, parent_head, next_revision);
            inner.dirty = true;
            journal
        };
        let journal_path = super::super::evjournal_path(state, &key.stable_group_id);
        assert!(super::super::write_evjournal(&journal_path, &journal).await);
        assert!(super::super::persist_obligations(state).await);
        Ok(key)
    }

    /// ADR 0110 §5 crash window for an S4 ban (#1508 review P1 #4): the
    /// TreeKEM ban committed the new epoch and the process died before
    /// the publication. The ban must pass the same prepare barrier as a
    /// removal, so a restart still holds the exact `MemberBanned` with its
    /// TreeKEM commit and delivers it to the survivors.
    #[tokio::test]
    async fn a_crash_after_the_ban_commit_keeps_the_exact_event() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "cd".repeat(16);
        let (target_hex, _) = seated_target_group(&state, &group_id).await?;
        let key = s4_prepare(&state, &group_id, &target_hex, prepared_store).await?;

        // The ban transaction commits, then the process dies.
        super::super::super::crash_after_removal_commit_on_this_thread_for_test();
        let membership_lock = super::super::super::group_membership_lock(&state, &group_id).await;
        let membership_guard = membership_lock.lock().await;
        let (status, body) = super::super::super::ban_treekem_group_member(
            Arc::clone(&state),
            group_id.clone(),
            target_hex.clone(),
            hex::encode(state.agent.agent_id().as_bytes()),
        )
        .await;
        drop(membership_guard);
        assert_eq!(
            status,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "the ban stops at the test crash point: {body:?}"
        );
        let committed_head = {
            let groups = state.named_groups.read().await;
            let info = groups.get(&group_id).expect("group");
            assert!(info.is_banned(&target_hex), "the ban transaction committed");
            info.state_hash.clone()
        };

        // Restart: the S4 state is reloaded from disk.
        *state.revocation_evictions.inner.lock().await = super::super::S4Inner::default();
        super::super::load_persisted_obligations(&state).await;

        let inner = state.revocation_evictions.inner.lock().await;
        let row = inner.store.get(&key).expect("row survives the restart");
        assert_eq!(row.phase, Phase::CommittedDeliveryPending);
        assert_eq!(row.result_head.as_deref(), Some(committed_head.as_str()));
        let saved = row
            .outgoing_event
            .as_deref()
            .and_then(decode_saved_removal)
            .expect("the exact MemberBanned survives the crash");
        assert!(matches!(
            saved.event,
            NamedGroupMetadataEvent::MemberBanned {
                treekem_commit_b64: Some(_),
                ..
            }
        ));
        assert!(
            inner.removals.contains_key(&key),
            "restart resumes the delivery to the survivors"
        );
        Ok(())
    }

    /// ADR 0110 §1a/D135 cancellation race (#1508 review P1 #2): the S4
    /// worker prepared the expiry removal, and a certificate rebind landed
    /// while it wrote the journal. The route's reconciliation then ends the
    /// row (`certificate_valid`). The S4 removal must stop; it must not
    /// continue as an ordinary removal of the renewed seat.
    #[tokio::test]
    async fn a_rebind_during_the_expiry_prepare_keeps_the_renewed_seat() -> anyhow::Result<()> {
        use x0x::identity::AgentCertificate;
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "ef".repeat(16);
        let (target_hex, target_kp) = seated_target_group(&state, &group_id).await?;
        let owner = x0x::identity::UserKeypair::generate()?;
        let now_unix = super::super::now_unix_ms() / 1000;
        let expired =
            AgentCertificate::issue_with_expiry(&owner, &target_kp, Some(now_unix - 1_000))?;
        let renewed =
            AgentCertificate::issue_with_expiry(&owner, &target_kp, Some(now_unix + 86_400))?;
        let expired_digest = x0x::groups::owner_cert::certificate_digest_hex(&expired);
        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_id).expect("group");
            info.set_member_certificate(&target_hex, expired)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            info.recompute_state_hash();
        }
        // The worker's eligibility check passed: the row is prepared.
        let key = s4_prepare(&state, &group_id, &target_hex, |key| {
            let mut store = ObligationStore::new();
            store.intake(
                key,
                EvictionTrigger::CertificateExpiry {
                    certificate_digest: expired_digest.clone(),
                    not_after: now_unix - 1_000,
                },
                None,
                0,
                [0; 16],
            );
            store
        })
        .await?;

        // The rebind commit lands before the removal takes the lock.
        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_id).expect("group");
            let member = info.members_v2.get_mut(&target_hex).expect("seat");
            member.certificate_digest =
                Some(x0x::groups::owner_cert::certificate_digest_hex(&renewed));
            member.certificate = Some(renewed);
            info.recompute_state_hash();
        }

        let scope = {
            let inner = state.revocation_evictions.inner.lock().await;
            super::super::eviction_seal_scope(&inner.store, &key)
        };
        let (status, body) = super::super::run_member_route(
            &state,
            &group_id,
            &target_hex,
            super::super::ManualRequestKind::Remove,
            scope,
        )
        .await;
        assert_ne!(status, axum::http::StatusCode::OK, "{body:?}");
        assert!(
            state
                .named_groups
                .read()
                .await
                .get(&group_id)
                .expect("group")
                .has_active_member(&target_hex),
            "the renewed seat is kept"
        );
        let inner = state.revocation_evictions.inner.lock().await;
        let row = inner.store.get(&key).expect("row");
        assert_eq!(row.phase, Phase::Terminated);
        assert_eq!(
            row.termination,
            Some(x0x::groups::eviction::TerminationCause::CertificateValid)
        );
        Ok(())
    }

    /// One under-lock cancellation case: the seat of `target_hex` commits
    /// `old` and the S4 row is prepared for its expiry. Then the committed
    /// certificate changes to `new` (also expired, so the gate's
    /// reconciliation keeps the row open and the request reaches the
    /// membership lock). The worker's `kind` request must stop with
    /// `409 s4_exclusion_cancelled` and keep the seat.
    async fn assert_cancelled_under_lock(
        state: &Arc<AppState>,
        group_id: &str,
        target_hex: &str,
        target_kp: &x0x::identity::AgentKeypair,
        kind: super::super::ManualRequestKind,
    ) -> anyhow::Result<()> {
        use x0x::identity::AgentCertificate;
        let owner = x0x::identity::UserKeypair::generate()?;
        let now_unix = super::super::now_unix_ms() / 1000;
        let old = AgentCertificate::issue_with_expiry(&owner, target_kp, Some(now_unix - 2_000))?;
        let new = AgentCertificate::issue_with_expiry(&owner, target_kp, Some(now_unix - 1_000))?;
        let old_digest = x0x::groups::owner_cert::certificate_digest_hex(&old);
        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(group_id).expect("group");
            info.set_member_certificate(target_hex, old)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            info.recompute_state_hash();
        }
        let key = s4_prepare(state, group_id, target_hex, |key| {
            let mut store = ObligationStore::new();
            store.intake(
                key,
                EvictionTrigger::CertificateExpiry {
                    certificate_digest: old_digest.clone(),
                    not_after: now_unix - 2_000,
                },
                None,
                0,
                [0; 16],
            );
            store
        })
        .await?;
        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(group_id).expect("group");
            let member = info.members_v2.get_mut(target_hex).expect("seat");
            member.certificate_digest = Some(x0x::groups::owner_cert::certificate_digest_hex(&new));
            member.certificate = Some(new);
            info.recompute_state_hash();
        }
        let mut scope = {
            let inner = state.revocation_evictions.inner.lock().await;
            super::super::eviction_seal_scope(&inner.store, &key)
        };
        scope.prepared_removal = true;
        let (status, body) =
            super::super::run_member_route(state, group_id, target_hex, kind, scope).await;
        assert_eq!(
            status,
            axum::http::StatusCode::CONFLICT,
            "{kind:?}: {body:?}"
        );
        assert_eq!(body["error"], "s4_exclusion_cancelled", "{kind:?}");
        let groups = state.named_groups.read().await;
        let info = groups.get(group_id).expect("group");
        assert!(
            info.has_active_member(target_hex),
            "{kind:?}: the seat is kept"
        );
        Ok(())
    }

    /// #1508 review P1 #2, every plane: the S4 eligibility re-check runs
    /// under the membership lock in the remove and ban routes, for GSS and
    /// TreeKEM groups, and the cancellation is a typed `409`.
    #[tokio::test]
    async fn a_cancelled_expiry_removal_stops_under_the_lock_on_every_plane() -> anyhow::Result<()>
    {
        use super::super::ManualRequestKind::{Ban, Remove};
        let (state, _dir) = secure_endpoint_test_state().await?;
        let (treekem_target, treekem_kp) = seated_target_group(&state, &"a2".repeat(16)).await?;
        assert_cancelled_under_lock(
            &state,
            &"a2".repeat(16),
            &treekem_target,
            &treekem_kp,
            Remove,
        )
        .await?;
        for (group_id, kind) in [("a3".repeat(16), Remove), ("a4".repeat(16), Ban)] {
            let admin = state.agent.agent_id();
            let target_kp = x0x::identity::AgentKeypair::generate()?;
            let target_hex = hex::encode(target_kp.agent_id().as_bytes());
            let mut info = GroupInfo::new("s4-gss".into(), String::new(), admin, group_id.clone());
            info.secure_plane = x0x::mls::SecureGroupPlane::Gss;
            let admin_hex = hex::encode(admin.as_bytes());
            info.add_member(
                target_hex.clone(),
                x0x::groups::GroupRole::Member,
                Some(admin_hex),
                None,
            );
            info.recompute_state_hash();
            state
                .named_groups
                .write()
                .await
                .insert(group_id.clone(), info);
            assert_cancelled_under_lock(&state, &group_id, &target_hex, &target_kp, kind).await?;
        }
        Ok(())
    }

    /// A test state whose restart sync wait has already elapsed, so a
    /// resumed delivery waits only for its group's head round.
    async fn state_past_restart_wait() -> anyhow::Result<(Arc<AppState>, tempfile::TempDir)> {
        let (mut state, dir) = secure_endpoint_test_state().await?;
        Arc::get_mut(&mut state)
            .ok_or_else(|| anyhow::anyhow!("the fresh test state is not shared yet"))?
            .revocation_evictions = super::super::S4Runtime::new(x0x::groups::eviction::S4Timing {
            restart_sync_wait: std::time::Duration::ZERO,
            ..x0x::groups::eviction::S4Timing::default()
        });
        Ok((state, dir))
    }

    /// A GSS-plane group on `state` under `preset`: the local admin, a
    /// seated target and one survivor with an ML-KEM-768 key. Returns the
    /// target and the survivor.
    async fn gss_target_group(
        state: &AppState,
        group_id: &str,
        preset: x0x::groups::GroupPolicyPreset,
    ) -> anyhow::Result<(String, String)> {
        let admin = state.agent.agent_id();
        let admin_hex = hex::encode(admin.as_bytes());
        let mut info = GroupInfo::with_policy(
            "s4-gss-barrier".to_string(),
            String::new(),
            admin,
            group_id.to_string(),
            preset.to_policy(),
        );
        info.secure_plane = x0x::mls::SecureGroupPlane::Gss;
        let target_hex = hex::encode(
            x0x::identity::AgentKeypair::generate()?
                .agent_id()
                .as_bytes(),
        );
        info.add_member(
            target_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        let survivor_hex = hex::encode(
            x0x::identity::AgentKeypair::generate()?
                .agent_id()
                .as_bytes(),
        );
        info.add_member(
            survivor_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex),
            None,
        );
        let kem = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
        if let Some(member) = info.members_v2.get_mut(&survivor_hex) {
            member.kem_public_key_b64 = Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &kem.public_bytes,
            ));
        }
        if info.policy.confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted {
            let _ = info.rotate_shared_secret();
        }
        info.recompute_state_hash();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.to_string(), info);
        Ok((target_hex, survivor_hex))
    }

    /// #1508 review P1 (GSS and SignedPublic bypass the crash barrier):
    /// S4 prepared the removal or ban of a seated target in a GSS-plane
    /// group, the roster transaction committed, and the process died
    /// before the publication. A restart must hold the exact
    /// `MemberRemoved` or `MemberBanned` and resume its delivery, the
    /// reconciliation must not complete the row while that delivery runs,
    /// and in an `MlsEncrypted` group the survivors must get the rotated
    /// secret again.
    async fn assert_gss_crash_keeps_the_exact_event(
        group_id: &str,
        preset: x0x::groups::GroupPolicyPreset,
        kind: super::super::ManualRequestKind,
    ) -> anyhow::Result<()> {
        let (state, _dir) = state_past_restart_wait().await?;
        let (target_hex, survivor_hex) = gss_target_group(&state, group_id, preset).await?;
        let key = s4_prepare(&state, group_id, &target_hex, prepared_store).await?;

        // The roster transaction commits, then the process dies.
        super::super::super::crash_after_removal_commit_on_this_thread_for_test();
        let scope = {
            let inner = state.revocation_evictions.inner.lock().await;
            super::super::eviction_seal_scope(&inner.store, &key)
        };
        let (status, body) =
            super::super::run_member_route(&state, group_id, &target_hex, kind, scope).await;
        let (committed_head, committed_epoch, encrypted) = {
            let groups = state.named_groups.read().await;
            let info = groups.get(group_id).expect("group");
            assert!(
                !info.has_active_member(&target_hex),
                "{kind:?}: the roster transaction committed"
            );
            (
                info.state_hash.clone(),
                info.secret_epoch,
                info.policy.confidentiality == x0x::groups::GroupConfidentiality::MlsEncrypted,
            )
        };

        // Restart: the S4 state is reloaded from disk.
        *state.revocation_evictions.inner.lock().await = super::super::S4Inner::default();
        super::super::load_persisted_obligations(&state).await;
        {
            let mut inner = state.revocation_evictions.inner.lock().await;
            let row = inner.store.get(&key).expect("row survives the restart");
            assert_eq!(row.phase, Phase::CommittedDeliveryPending, "{kind:?}");
            assert_eq!(row.result_head.as_deref(), Some(committed_head.as_str()));
            let saved = row
                .outgoing_event
                .as_deref()
                .and_then(decode_saved_removal)
                .expect("the exact event survives the crash");
            let expected_epoch = encrypted.then_some(committed_epoch);
            match (&saved.event, kind) {
                (
                    NamedGroupMetadataEvent::MemberRemoved {
                        treekem_commit_b64: None,
                        secret_epoch,
                        ..
                    },
                    super::super::ManualRequestKind::Remove,
                )
                | (
                    NamedGroupMetadataEvent::MemberBanned {
                        treekem_commit_b64: None,
                        secret_epoch,
                        ..
                    },
                    super::super::ManualRequestKind::Ban,
                ) => assert_eq!(*secret_epoch, expected_epoch, "{kind:?}"),
                (event, _) => panic!("{kind:?}: unexpected saved event {event:?}"),
            }
            assert!(
                inner.removals.contains_key(&key),
                "{kind:?}: restart resumes the delivery to the survivors"
            );

            // The reconciliation of the next pass keeps the row open.
            let groups = super::super::snapshot_groups(&state).await;
            let mut delivering = inner.ce.delivering();
            delivering.extend(inner.removals.keys().cloned());
            super::super::reconcile_completion(
                &mut inner.store,
                &groups,
                &super::super::RetainedLeaves::default(),
                &delivering,
                super::super::now_unix_ms(),
                true,
            );
            assert_eq!(
                inner.store.get(&key).expect("row").phase,
                Phase::CommittedDeliveryPending,
                "{kind:?}: no completion while the survivors lack the event"
            );
            // The group's head round has run its course.
            inner.head_rounds.insert(
                key.stable_group_id.clone(),
                super::super::HeadRound::new(&committed_head, tokio::time::Instant::now()),
            );
        }

        // Checked after the restart, so a removal that skips the barrier
        // fails on the lost event, not only on the crash point.
        assert_eq!(
            status,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "{kind:?}: the route stops at the test crash point: {body:?}"
        );

        // The resumed delivery also gives each survivor the rotated secret.
        state
            .named_group_test_recorders
            .secure_share_scheduled
            .lock()
            .map_err(|_| anyhow::anyhow!("recorder poisoned"))?
            .clear();
        super::super::removal_delivery::drive(&state).await;
        let shares: Vec<(String, u64)> = state
            .named_group_test_recorders
            .secure_share_scheduled
            .lock()
            .map_err(|_| anyhow::anyhow!("recorder poisoned"))?
            .iter()
            .filter_map(
                |(_, recipient, payload)| match serde_json::from_slice(payload).ok()? {
                    NamedGroupMetadataEvent::SecureShareDelivered { secret_epoch, .. } => {
                        Some((recipient.clone(), secret_epoch))
                    }
                    _ => None,
                },
            )
            .collect();
        if encrypted {
            assert_eq!(
                shares,
                vec![(survivor_hex, committed_epoch)],
                "{kind:?}: the survivor gets the rotated secret again"
            );
        } else {
            assert!(
                shares.is_empty(),
                "{kind:?}: a SignedPublic group has no secret"
            );
        }
        Ok(())
    }

    /// #1508 review P1: the roster write of S4's GSS removal or ban
    /// renames the file but the directory fsync fails
    /// (`ReplacedNotDurable`). The new roster is live, so the removal has
    /// committed: the row keeps the exact event, moves to
    /// `committed_delivery_pending`, and its first delivery round also
    /// sends the rotated secret, because the route stops before its own
    /// publication. Before the fix the barrier abandoned the event and the
    /// worker retired the journal, so nothing reached the survivors.
    async fn assert_not_durable_roster_keeps_the_event(
        group_id: &str,
        kind: super::super::ManualRequestKind,
    ) -> anyhow::Result<()> {
        let (state, _dir) = state_past_restart_wait().await?;
        let (target_hex, _survivor_hex) = gss_target_group(
            &state,
            group_id,
            x0x::groups::GroupPolicyPreset::PrivateSecure,
        )
        .await?;
        let key = s4_prepare(&state, group_id, &target_hex, prepared_store).await?;
        let scope = {
            let inner = state.revocation_evictions.inner.lock().await;
            super::super::eviction_seal_scope(&inner.store, &key)
        };
        let (status, body) = {
            let _fault = super::super::super::set_save_fault(
                &state,
                super::super::super::SaveFault::ReplacedNotDurableAfterWrite,
            );
            super::super::run_member_route(&state, group_id, &target_hex, kind, scope).await
        };
        assert_eq!(
            status,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "{kind:?}: {body:?}"
        );
        let (head, epoch) = {
            let groups = state.named_groups.read().await;
            let info = groups.get(group_id).expect("group");
            assert!(
                !info.has_active_member(&target_hex),
                "{kind:?}: the new roster is live"
            );
            (info.state_hash.clone(), info.secret_epoch)
        };
        let inner = state.revocation_evictions.inner.lock().await;
        let row = inner.store.get(&key).expect("row");
        assert_eq!(row.phase, Phase::CommittedDeliveryPending, "{kind:?}");
        assert_eq!(row.result_head.as_deref(), Some(head.as_str()), "{kind:?}");
        assert!(
            row.outgoing_event
                .as_deref()
                .and_then(decode_saved_removal)
                .is_some(),
            "{kind:?}: the exact event is kept"
        );
        let delivery = inner
            .removals
            .get(&key)
            .expect("the delivery to the survivors runs");
        assert_eq!(
            delivery.reshare_epoch_for_test(),
            Some(epoch),
            "{kind:?}: the survivors get the rotated secret"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_not_durable_gss_removal_keeps_and_delivers_its_event() -> anyhow::Result<()> {
        assert_not_durable_roster_keeps_the_event(
            &"b5".repeat(16),
            super::super::ManualRequestKind::Remove,
        )
        .await
    }

    #[tokio::test]
    async fn a_not_durable_gss_ban_keeps_and_delivers_its_event() -> anyhow::Result<()> {
        assert_not_durable_roster_keeps_the_event(
            &"b6".repeat(16),
            super::super::ManualRequestKind::Ban,
        )
        .await
    }

    /// #1574 item 4: the live-head read of the not-durable barrier must
    /// not decide on a roster candidate that a failing write later rolls
    /// back. `persist_named_group_info` shows its candidate in the map
    /// before the write and restores the map when the write fails, so the
    /// read holds the persistence lock and can never observe that window.
    /// Before the fix the unlocked read saw the mid-write after-image, and
    /// the barrier kept and delivered an event whose transaction rolled
    /// back everywhere.
    #[tokio::test]
    async fn the_live_head_read_waits_out_a_candidate_that_rolls_back() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "b7".repeat(16);
        let mut info = GroupInfo::new(
            "s4-live-head".into(),
            String::new(),
            state.agent.agent_id(),
            group_id.clone(),
        );
        info.recompute_state_hash();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());
        let mut candidate = info.clone();
        candidate.state_hash = format!("{}-candidate", info.state_hash);
        // The persist window: the candidate is visible in the map while
        // the writer still holds the persistence lock.
        let guard = state.named_groups_persistence_lock.lock().await;
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), candidate.clone());
        let reader = {
            let state = Arc::clone(&state);
            let probe = candidate.clone();
            tokio::spawn(async move { live_head_is(&state, &probe).await })
        };
        // An unlocked read would finish inside this window and see the
        // candidate as the live head.
        for _ in 0..60 {
            if reader.is_finished() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            !reader.is_finished(),
            "the live-head read must block on the persistence lock, not read the mid-write candidate"
        );
        // The write failed: the map is restored under the same lock hold.
        state.named_groups.write().await.insert(group_id, info);
        drop(guard);
        assert!(
            !reader.await.expect("the read finishes after the rollback"),
            "a rolled-back candidate is not the live head"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_crash_after_a_gss_removal_commit_keeps_the_exact_event() -> anyhow::Result<()> {
        assert_gss_crash_keeps_the_exact_event(
            &"b1".repeat(16),
            x0x::groups::GroupPolicyPreset::PrivateSecure,
            super::super::ManualRequestKind::Remove,
        )
        .await
    }

    #[tokio::test]
    async fn a_crash_after_a_gss_ban_commit_keeps_the_exact_event() -> anyhow::Result<()> {
        assert_gss_crash_keeps_the_exact_event(
            &"b2".repeat(16),
            x0x::groups::GroupPolicyPreset::PrivateSecure,
            super::super::ManualRequestKind::Ban,
        )
        .await
    }

    #[tokio::test]
    async fn a_crash_after_a_signed_public_removal_commit_keeps_the_exact_event(
    ) -> anyhow::Result<()> {
        assert_gss_crash_keeps_the_exact_event(
            &"b3".repeat(16),
            x0x::groups::GroupPolicyPreset::PublicOpen,
            super::super::ManualRequestKind::Remove,
        )
        .await
    }

    #[tokio::test]
    async fn a_crash_after_a_signed_public_ban_commit_keeps_the_exact_event() -> anyhow::Result<()>
    {
        assert_gss_crash_keeps_the_exact_event(
            &"b4".repeat(16),
            x0x::groups::GroupPolicyPreset::PublicOpen,
            super::super::ManualRequestKind::Ban,
        )
        .await
    }
}
