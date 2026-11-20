#![cfg(test)]
//! #1366: each listener class stops when no stored record needs it, not
//! only at a restart.
//!
//! - A self-leave takes the record away, on the GSS and the TreeKEM plane,
//!   and so does a local-only drop of a non-member TreeKEM record and a
//!   cleared stale join row: both listeners stop.
//! - A sole-member leave and a terminal withdrawal keep a withdrawn
//!   tombstone, which needs no listener: both stop.
//! - A self-removal and a withdrawal applied through
//!   `apply_listener_metadata_event` (the apply that the topic listener and
//!   the direct lanes share) and a refused join stub
//!   (`finalize_join_attempt_with_reason`) stop the public-message
//!   listener. An accepted event that keeps the record keeps it.
//! - A refreshed card that changes a non-member stub to `MlsEncrypted`, and
//!   a withdrawn card, stop the public-message listener; a withdrawn card
//!   that a live keyed record ignores keeps it.
//! - Records that share a stable id share one public-message listener: it
//!   runs while any of them needs it, also beside a withdrawn tombstone.
//! - A request-access applicant keeps its metadata listener while it waits.
//!
//! The `LiveListener` counter of the sibling file, and the abort handle of
//! a metadata listener, prove that a stopped listener task really ended. Local topics drive the real
//! subscribers. Inert apart from the loopback-only test network of
//! `networked_test_state`.

use super::issue1366_public_listener::live;
use super::*;

/// Set when a listener step ran while its caller held the card cache.
static CARD_CACHE_HELD_AT_LISTENER_STEP: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Test hook of `listener_lifecycle`: no listener step may run while its
/// caller holds `group_card_cache`. Another path holds `named_groups` while
/// it waits for that cache, so the other order could deadlock. Each test
/// runs in its own process under nextest, so the flag is per test.
pub(in crate::server) fn note_listener_step(state: &AppState) {
    if state.group_card_cache.try_write().is_err() {
        CARD_CACHE_HELD_AT_LISTENER_STEP.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn assert_no_listener_step_held_the_card_cache(why: &str) {
    assert!(
        !CARD_CACHE_HELD_AT_LISTENER_STEP.load(std::sync::atomic::Ordering::SeqCst),
        "#1366: {why}: a listener step ran while its caller held the card cache"
    );
}

/// Lets queued tasks run a turn (no wall-clock wait).
async fn settle() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

/// Polls `check` until it holds, for up to 10 s.
async fn eventually<F, Fut>(mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if check().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The public-message listener of `stable_id` is registered and its one
/// task runs. A stopped listener never comes back, so polling for this also
/// catches a wrong stop.
async fn assert_public_running(state: &AppState, stable_id: &str, why: &str) {
    assert!(
        eventually(|| async { public_registered(state, stable_id).await && live(stable_id) == 1 })
            .await,
        "#1366: {why}: the public-message listener runs"
    );
}

async fn metadata_registered(state: &AppState, group_key: &str) -> bool {
    state
        .group_metadata_tasks
        .read()
        .await
        .contains_key(group_key)
}

async fn public_registered(state: &AppState, stable_id: &str) -> bool {
    state
        .public_message_tasks
        .read()
        .await
        .contains_key(stable_id)
}

/// The public-message listener of `stable_id` is not registered and its
/// task has ended.
async fn assert_public_stopped(state: &AppState, stable_id: &str, why: &str) {
    assert!(
        eventually(|| async { !public_registered(state, stable_id).await }).await,
        "#1366: {why}: the public-message listener is deregistered"
    );
    assert!(
        eventually(|| async { live(stable_id) == 0 }).await,
        "#1366: {why}: the public-message listener task has ended"
    );
    assert_no_listener_step_held_the_card_cache(why);
}

/// The abort handle of the running metadata listener under `group_key`.
async fn metadata_task(state: &AppState, group_key: &str) -> Result<tokio::task::AbortHandle> {
    state
        .group_metadata_tasks
        .read()
        .await
        .get(group_key)
        .map(|reg| reg.handle.abort_handle())
        .context("precondition: the metadata listener is registered")
}

/// The metadata listener under `group_key` is deregistered and its task
/// has ended.
async fn assert_metadata_stopped(
    state: &AppState,
    group_key: &str,
    task: &tokio::task::AbortHandle,
    why: &str,
) {
    assert!(
        eventually(|| async { !metadata_registered(state, group_key).await }).await,
        "#1366: {why}: the metadata listener is deregistered"
    );
    assert!(
        eventually(|| async { task.is_finished() }).await,
        "#1366: {why}: the metadata listener task has ended"
    );
    assert_no_listener_step_held_the_card_cache(why);
}

fn local_hex(state: &AppState) -> String {
    hex::encode(state.agent.agent_id().as_bytes())
}

/// A SignedPublic group with a second admin, so the local agent may leave.
/// `adjust` changes the record before it is stored.
async fn signed_public_fixture_with(
    plane: &str,
    group_id: &str,
    adjust: impl FnOnce(&mut x0x::groups::GroupInfo),
) -> Result<(Arc<AppState>, tempfile::TempDir, String)> {
    let (state, dir) = networked_test_state(plane).await?;
    let (mut info, _, member_hex) = metadata_terminality_test_group(&state, group_id);
    info.policy.confidentiality = x0x::groups::GroupConfidentiality::SignedPublic;
    info.metadata_topic = format!("local:1366-lifecycle-metadata-{group_id}");
    if let Some(member) = info.members_v2.get_mut(&member_hex) {
        member.role = x0x::groups::GroupRole::Admin;
    }
    adjust(&mut info);
    info.recompute_state_hash();
    let stable = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
    ensure_named_group_listeners(Arc::clone(&state), group_id).await;
    assert!(
        metadata_registered(&state, group_id).await,
        "precondition: the metadata listener runs"
    );
    assert_public_running(&state, &stable, "precondition").await;
    Ok((state, dir, stable))
}

async fn signed_public_fixture(
    plane: &str,
    group_id: &str,
) -> Result<(Arc<AppState>, tempfile::TempDir, String)> {
    signed_public_fixture_with(plane, group_id, |_| {}).await
}

async fn leave(state: &Arc<AppState>, group_id: &str) -> Result<serde_json::Value> {
    let (status, body) = response_json(
        leave_group(
            State(Arc::clone(state)),
            Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
            Path(group_id.to_string()),
        )
        .await
        .into_response(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "the leave applies: {body}");
    Ok(body)
}

/// Also the lock-order check: the leave releases the card cache before the
/// listener reconcile (`assert_metadata_stopped` checks the test hook).
#[tokio::test]
async fn issue1366_self_leave_stops_both_listeners() -> Result<()> {
    let group_id = "1366-lifecycle-leave-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-leave", group_id).await?;
    let meta = metadata_task(&state, group_id).await?;
    leave(&state, group_id).await?;
    settle().await;
    assert!(
        !state.named_groups.read().await.contains_key(group_id),
        "the leave removes the record"
    );
    assert_metadata_stopped(&state, group_id, &meta, "a self-leave").await;
    assert_public_stopped(&state, &stable, "a self-leave").await;
    Ok(())
}

#[tokio::test]
async fn issue1366_treekem_self_leave_stops_both_listeners() -> Result<()> {
    let group_id = "1366-lifecycle-tk-leave-key";
    let (state, _dir, stable) =
        signed_public_fixture_with("1366-lifecycle-tk-leave", group_id, |info| {
            info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        })
        .await?;
    let meta = metadata_task(&state, group_id).await?;
    leave(&state, group_id).await?;
    settle().await;
    assert!(
        !state.named_groups.read().await.contains_key(group_id),
        "the TreeKEM leave removes the record"
    );
    assert_metadata_stopped(&state, group_id, &meta, "a TreeKEM self-leave").await;
    assert_public_stopped(&state, &stable, "a TreeKEM self-leave").await;
    Ok(())
}

#[tokio::test]
async fn issue1366_treekem_local_only_drop_stops_both_listeners() -> Result<()> {
    let group_id = "1366-lifecycle-tk-drop-key";
    let (state, _dir, stable) =
        signed_public_fixture_with("1366-lifecycle-tk-drop", group_id, |info| {
            info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        })
        .await?;
    // The local agent holds no Active seat: the leave is a local-only drop
    // (`drop_local_named_group_state`).
    let local = local_hex(&state);
    if let Some(info) = state.named_groups.write().await.get_mut(group_id) {
        info.members_v2.remove(&local);
    }
    let meta = metadata_task(&state, group_id).await?;
    let (status, body) = response_json(
        leave_treekem_group(Arc::clone(&state), group_id.to_string(), local)
            .await
            .into_response(),
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the local-only drop applies: {body}"
    );
    assert_eq!(
        body["local_only"],
        serde_json::json!(true),
        "the leave took the local-only drop: {body}"
    );
    settle().await;
    assert!(!state.named_groups.read().await.contains_key(group_id));
    assert_metadata_stopped(&state, group_id, &meta, "a local-only drop").await;
    assert_public_stopped(&state, &stable, "a local-only drop").await;
    Ok(())
}

/// The local agent's own leave event, applied through the listener apply:
/// the self-removal branch takes the record away.
#[tokio::test]
async fn issue1366_applied_self_removal_stops_the_public_listener() -> Result<()> {
    let group_id = "1366-lifecycle-removal-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-removal", group_id).await?;
    let parent = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .context("fixture record")?;
    let local = local_hex(&state);
    let meta = metadata_task(&state, group_id).await?;
    let mut next = parent.clone();
    next.roster_revision = next.roster_revision.saturating_add(1);
    next.remove_member(&local, Some(local.clone()));
    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: stable.clone(),
        revision: next.roster_revision,
        actor: local.clone(),
        agent_id: local,
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(sign_metadata_terminality_commit(
            &parent,
            &next,
            &state,
            now_millis_u64(),
        )),
    };
    let applied =
        apply_listener_metadata_event(&state, event, state.agent.agent_id(), true, None).await;
    assert!(
        applied.as_ref().is_some_and(|result| result.accepted),
        "the signed self-removal applies"
    );
    assert!(
        !state.named_groups.read().await.contains_key(group_id),
        "the self-removal takes the record away"
    );
    assert_metadata_stopped(&state, group_id, &meta, "an applied self-removal").await;
    assert_public_stopped(&state, &stable, "an applied self-removal").await;
    Ok(())
}

/// An accepted event that keeps the record keeps its public listener.
#[tokio::test]
async fn issue1366_applied_rename_keeps_the_public_listener() -> Result<()> {
    let group_id = "1366-lifecycle-rename-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-rename", group_id).await?;
    let parent = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .context("fixture record")?;
    let mut next = parent.clone();
    next.name = "renamed".to_string();
    next.roster_revision = next.roster_revision.saturating_add(1);
    let event = NamedGroupMetadataEvent::GroupMetadataUpdated {
        group_id: stable.clone(),
        revision: next.roster_revision,
        actor: local_hex(&state),
        name: Some(next.name.clone()),
        description: None,
        commit: Some(sign_metadata_terminality_commit(
            &parent,
            &next,
            &state,
            now_millis_u64(),
        )),
    };
    let applied =
        apply_listener_metadata_event(&state, event, state.agent.agent_id(), true, None).await;
    assert!(
        applied.as_ref().is_some_and(|result| result.accepted),
        "the signed rename applies"
    );
    settle().await;
    assert_public_running(
        &state,
        &stable,
        "an accepted event that keeps the SignedPublic record keeps its listener",
    )
    .await;
    assert!(
        metadata_registered(&state, group_id).await,
        "#1366: an accepted event that keeps the record keeps its metadata listener"
    );
    Ok(())
}

#[tokio::test]
async fn issue1366_refused_join_stub_stops_the_public_listener() -> Result<()> {
    let group_id = "1366-lifecycle-stub-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-stub", group_id).await?;
    let member = local_hex(&state);
    // A pending stub does not seat the joiner (a seated joiner finalizes as
    // joined, not refused).
    if let Some(info) = state.named_groups.write().await.get_mut(group_id) {
        info.members_v2.remove(&member);
    }
    let meta = metadata_task(&state, group_id).await?;
    let token = state
        .group_metadata_tasks
        .read()
        .await
        .get(group_id)
        .map(|reg| reg.token);
    state
        .pending_join_stubs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(group_id.to_string());
    state
        .pending_join_attempts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            join_result_key(&stable, &member),
            PendingJoinAttempt {
                attempt_id: "a1366".into(),
                local_group_key: group_id.to_string(),
                invite_fingerprint: "fp".into(),
                invite_group_id: stable.clone(),
                inviter_public_key_b64: String::new(),
                stored_resend: None,
                polls: Vec::new(),
                tasks: Vec::new(),
                listener_token: token,
                held_pending_notice: None,
            },
        );
    let lock = group_membership_lock_for_known_group(&state, group_id)
        .await
        .context("known group")?;
    let guard = lock.lock().await;
    finalize_join_attempt_with_reason(
        &state,
        group_id,
        &stable,
        &member,
        "a1366",
        JoinAttemptOutcome::Refused,
        Some("1366"),
        JoinFinalizeGuard::Owned(guard),
    )
    .await;
    assert!(
        !state.named_groups.read().await.contains_key(group_id),
        "the refusal removes the pending stub"
    );
    settle().await;
    assert_metadata_stopped(&state, group_id, &meta, "a refused join stub").await;
    assert_public_stopped(&state, &stable, "a refused join stub").await;
    Ok(())
}

#[tokio::test]
async fn issue1366_withdrawn_card_stops_an_unneeded_public_listener() -> Result<()> {
    let (state, _dir) = networked_test_state("1366-lifecycle-withdrawn").await?;
    let group_id = "d1".repeat(32);
    // A public-cache read for a group with no local record starts a
    // listener on the supplied id (the fail-open path).
    spawn_public_message_listener(Arc::clone(&state), group_id.clone()).await;
    settle().await;
    assert_public_running(
        &state,
        &group_id,
        "precondition: the fail-open listener runs",
    )
    .await;
    let creator = x0x::identity::AgentKeypair::generate()?;
    let mut card = lifecycle_card(
        &creator,
        &group_id,
        2,
        x0x::groups::GroupConfidentiality::SignedPublic,
    )?;
    card.withdrawn = true;
    card.sign(&creator)?;
    import(&state, card).await?;
    settle().await;
    assert_public_stopped(&state, &group_id, "a withdrawn card").await;
    Ok(())
}

/// Two records share a stable id: the listener runs while either needs it.
#[tokio::test]
async fn issue1366_shared_stable_id_listener_runs_while_any_record_needs_it() -> Result<()> {
    let group_id = "1366-lifecycle-shared-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-shared", group_id).await?;
    let alias_key = "1366-lifecycle-shared-alias";
    let mut alias = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .context("fixture record")?;
    alias.policy.confidentiality = x0x::groups::GroupConfidentiality::MlsEncrypted;
    assert_eq!(
        alias.stable_group_id(),
        stable,
        "the alias shares the stable id"
    );
    state
        .named_groups
        .write()
        .await
        .insert(alias_key.to_string(), alias);
    for key in [alias_key, stable.as_str()] {
        assert_eq!(
            public_message_listener_wanted(&*state.named_groups.read().await, key),
            Some((stable.clone(), true)),
            "#1366: a SignedPublic record with the stable id needs the listener (via {key})"
        );
    }
    reconcile_public_message_listener(&state, alias_key).await;
    listener_lifecycle::retire_unwanted_public_message_listener(&state, alias_key).await;
    settle().await;
    assert_public_running(
        &state,
        &stable,
        "an MlsEncrypted alias does not stop the listener another record needs",
    )
    .await;

    state.named_groups.write().await.remove(group_id);
    reconcile_public_message_listener(&state, alias_key).await;
    settle().await;
    assert_public_stopped(&state, &stable, "only an MlsEncrypted record is left").await;
    Ok(())
}

#[tokio::test]
async fn issue1366_a_gone_record_keeps_no_public_listener() -> Result<()> {
    let group_id = "1366-lifecycle-gone-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-gone", group_id).await?;
    state.named_groups.write().await.remove(group_id);
    reconcile_public_message_listener(&state, &stable).await;
    settle().await;
    assert_public_stopped(&state, &stable, "no stored record needs it").await;
    Ok(())
}

#[tokio::test]
async fn issue1366_a_stored_record_keeps_the_public_listener() -> Result<()> {
    let group_id = "1366-lifecycle-alias-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-alias", group_id).await?;
    // The record is still stored under its key: the retire is a no-op.
    listener_lifecycle::retire_unwanted_public_message_listener(&state, &stable).await;
    listener_lifecycle::retire_unwanted_public_message_listener(&state, group_id).await;
    settle().await;
    assert_public_running(&state, &stable, "a record that needs the listener keeps it").await;
    Ok(())
}

/// A sole member's leave withdraws the group (`withdraw_named_group_terminal`):
/// the retained tombstone needs no listener.
#[tokio::test]
async fn issue1366_sole_member_leave_stops_both_listeners() -> Result<()> {
    let group_id = "1366-lifecycle-sole-key";
    let (state, _dir, stable) =
        signed_public_fixture_with("1366-lifecycle-sole", group_id, |info| {
            info.members_v2.remove(&"22".repeat(32));
        })
        .await?;
    let meta = metadata_task(&state, group_id).await?;
    leave(&state, group_id).await?;
    settle().await;
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(group_id)
            .is_none_or(|info| info.withdrawn),
        "the sole-member leave withdraws the group"
    );
    assert_metadata_stopped(&state, group_id, &meta, "a sole-member leave").await;
    assert_public_stopped(&state, &stable, "a sole-member leave").await;
    Ok(())
}

#[tokio::test]
async fn issue1366_terminal_withdraw_stops_both_listeners() -> Result<()> {
    let group_id = "1366-lifecycle-withdraw-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-withdraw", group_id).await?;
    let meta = metadata_task(&state, group_id).await?;
    let (status, body) = response_json(
        withdraw_group_state(
            State(Arc::clone(&state)),
            Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
            Path(group_id.to_string()),
        )
        .await
        .into_response(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "the withdrawal applies: {body}");
    settle().await;
    assert_metadata_stopped(&state, group_id, &meta, "a terminal withdrawal").await;
    assert_public_stopped(&state, &stable, "a terminal withdrawal").await;
    Ok(())
}

/// A signed `GroupDeleted` applied through the listener apply.
#[tokio::test]
async fn issue1366_applied_withdrawal_stops_the_public_listener() -> Result<()> {
    let group_id = "1366-lifecycle-deleted-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-deleted", group_id).await?;
    let parent = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .context("fixture record")?;
    let meta = metadata_task(&state, group_id).await?;
    let mut terminal = parent.clone();
    terminal.withdrawn = true;
    let event = NamedGroupMetadataEvent::GroupDeleted {
        group_id: stable.clone(),
        revision: parent.roster_revision.saturating_add(1),
        actor: local_hex(&state),
        commit: Some(sign_metadata_terminality_commit(
            &parent,
            &terminal,
            &state,
            now_millis_u64(),
        )),
    };
    let applied =
        apply_listener_metadata_event(&state, event, state.agent.agent_id(), true, None).await;
    assert!(
        applied.as_ref().is_some_and(|result| result.accepted),
        "the signed GroupDeleted applies"
    );
    assert_metadata_stopped(&state, group_id, &meta, "an applied withdrawal").await;
    assert_public_stopped(&state, &stable, "an applied withdrawal").await;
    Ok(())
}

/// A withdrawn card that a live keyed record ignores keeps its listener.
#[tokio::test]
async fn issue1366_withdrawn_card_keeps_the_listener_of_a_live_keyed_record() -> Result<()> {
    let group_id = "1366-lifecycle-keyed-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-keyed", group_id).await?;
    let now = now_millis_u64();
    let mut card = sample_group_card(&stable, 1_000, now);
    card.owner_agent_id = local_hex(&state);
    card.expires_at = now.saturating_add(3_600_000);
    card.updated_at = now.saturating_add(1_000);
    card.policy_summary.confidentiality = x0x::groups::GroupConfidentiality::SignedPublic;
    card.policy_summary.read_access = x0x::groups::GroupReadAccess::Public;
    card.withdrawn = true;
    card.sign(state.agent.identity().agent_keypair())?;
    import(&state, card).await?;
    settle().await;
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(group_id)
            .is_some_and(|info| !info.withdrawn),
        "the keyed record ignores the withdrawn card"
    );
    assert_public_running(
        &state,
        &stable,
        "a withdrawn card keeps the listener a live keyed record needs",
    )
    .await;
    Ok(())
}

/// D39/#1161: a cleared stale join row leaves no listener behind.
#[tokio::test]
async fn issue1366_cleared_stale_join_row_stops_both_listeners() -> Result<()> {
    let group_id = "1366-lifecycle-remnant-key";
    let (state, _dir, stable) =
        signed_public_fixture_with("1366-lifecycle-remnant", group_id, |info| {
            info.invite_lineage = Some(x0x::groups::InviteLineage::default());
        })
        .await?;
    let local = local_hex(&state);
    if let Some(info) = state.named_groups.write().await.get_mut(group_id) {
        info.members_v2.remove(&local);
    }
    let meta = metadata_task(&state, group_id).await?;
    let cleared = clear_stale_not_member_join_row(&state, group_id, &local, &stable).await;
    assert!(
        matches!(cleared, ClearStaleNotMemberJoinRowResult::Cleared),
        "the unseated join remnant is cleared"
    );
    settle().await;
    assert_metadata_stopped(&state, group_id, &meta, "a cleared join row").await;
    assert_public_stopped(&state, &stable, "a cleared join row").await;
    Ok(())
}

/// A withdrawn tombstone under the stable id and a live SignedPublic record
/// with the same stable id: an install for the stable id proceeds.
#[tokio::test]
async fn issue1366_install_beside_a_withdrawn_tombstone_follows_the_live_record() -> Result<()> {
    let group_id = "1366-lifecycle-tomb-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-tomb", group_id).await?;
    let mut tombstone = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .context("fixture record")?;
    tombstone.withdrawn = true;
    let live_record = state
        .named_groups
        .write()
        .await
        .remove(group_id)
        .context("fixture record")?;
    state
        .named_groups
        .write()
        .await
        .insert("1366-lifecycle-tomb-live".to_string(), live_record);
    state
        .named_groups
        .write()
        .await
        .insert(stable.clone(), tombstone);
    if let Some(handle) = state.public_message_tasks.write().await.remove(&stable) {
        handle.abort();
    }
    settle().await;
    assert!(
        eventually(|| async { live(&stable) == 0 }).await,
        "precondition: no listener runs"
    );
    spawn_public_message_listener(Arc::clone(&state), stable.clone()).await;
    settle().await;
    assert_public_running(
        &state,
        &stable,
        "the live SignedPublic record still gets its listener",
    )
    .await;
    Ok(())
}

fn lifecycle_card(
    creator: &x0x::identity::AgentKeypair,
    group_id: &str,
    revision: u64,
    confidentiality: x0x::groups::GroupConfidentiality,
) -> Result<x0x::groups::GroupCard> {
    let now = now_millis_u64();
    let mut card = sample_group_card(group_id, revision, now);
    card.owner_agent_id = hex::encode(creator.agent_id().as_bytes());
    card.expires_at = now.saturating_add(3_600_000);
    card.updated_at = now.saturating_add(revision);
    card.policy_summary.confidentiality = confidentiality;
    if confidentiality == x0x::groups::GroupConfidentiality::SignedPublic {
        card.policy_summary.read_access = x0x::groups::GroupReadAccess::Public;
    }
    card.sign(creator)?;
    Ok(card)
}

async fn import(state: &Arc<AppState>, card: x0x::groups::GroupCard) -> Result<()> {
    let (status, body) = response_json(
        import_group_card(State(Arc::clone(state)), Json(card))
            .await
            .into_response(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "card import: {body}");
    Ok(())
}

#[tokio::test]
async fn issue1366_card_refresh_to_mls_stops_the_stub_public_listener() -> Result<()> {
    let (state, _dir) = networked_test_state("1366-lifecycle-card").await?;
    let creator = x0x::identity::AgentKeypair::generate()?;
    let group_id = "c1".repeat(32);
    import(
        &state,
        lifecycle_card(
            &creator,
            &group_id,
            1,
            x0x::groups::GroupConfidentiality::SignedPublic,
        )?,
    )
    .await?;
    settle().await;
    assert!(
        metadata_registered(&state, &group_id).await,
        "an imported non-member stub runs its metadata listener"
    );
    assert_public_running(
        &state,
        &group_id,
        "a SignedPublic stub runs its public-message listener",
    )
    .await;

    import(
        &state,
        lifecycle_card(
            &creator,
            &group_id,
            2,
            x0x::groups::GroupConfidentiality::MlsEncrypted,
        )?,
    )
    .await?;
    settle().await;
    assert_eq!(
        state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .map(|info| info.policy.confidentiality),
        Some(x0x::groups::GroupConfidentiality::MlsEncrypted),
        "the refreshed card changes the stub's policy"
    );
    assert_public_stopped(&state, &group_id, "a card refresh to MlsEncrypted").await;
    assert!(
        metadata_registered(&state, &group_id).await,
        "the stub keeps its metadata listener"
    );
    Ok(())
}

#[tokio::test]
async fn issue1366_request_access_applicant_keeps_its_metadata_listener() -> Result<()> {
    let (state, _dir) = networked_test_state("1366-lifecycle-applicant").await?;
    state
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let creator = x0x::identity::AgentKeypair::generate()?;
    let group_id = "a1".repeat(32);
    import(
        &state,
        lifecycle_card(
            &creator,
            &group_id,
            1,
            x0x::groups::GroupConfidentiality::MlsEncrypted,
        )?,
    )
    .await?;
    let (status, body) = response_json(
        create_join_request(State(Arc::clone(&state)), Path(group_id.clone()), None)
            .await
            .into_response(),
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "request: {body}");
    settle().await;
    assert!(
        metadata_registered(&state, &group_id).await,
        "#1366: a request-access applicant keeps the metadata listener that \
         carries the approval"
    );
    assert!(
        !public_registered(&state, &group_id).await,
        "an MlsEncrypted applicant stub runs no public-message listener"
    );
    Ok(())
}
