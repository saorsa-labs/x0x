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

/// The lock-order check of `listener_lifecycle::note_listener_step`, on
/// this state only: the path under test reached a listener step since the
/// fixture reset the count, and no step ran while its caller held the card
/// cache.
fn assert_no_listener_step_held_the_card_cache(state: &AppState, why: &str) {
    let recorders = &state.named_group_test_recorders;
    assert!(
        recorders
            .listener_steps
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0,
        "#2124: {why}: the path reached a listener step"
    );
    assert!(
        !recorders
            .listener_step_held_card_cache
            .load(std::sync::atomic::Ordering::SeqCst),
        "#1366: {why}: a listener step ran while its caller held the card cache"
    );
}

fn reset_listener_steps(state: &AppState) {
    state
        .named_group_test_recorders
        .listener_steps
        .store(0, std::sync::atomic::Ordering::SeqCst);
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
    assert_no_listener_step_held_the_card_cache(state, why);
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
    assert_no_listener_step_held_the_card_cache(state, why);
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
    signed_public_fixture_keyed(plane, group_id, group_id, adjust).await
}

/// As [`signed_public_fixture_with`], with the record stored under the map
/// key `group_key`; its stable id stays `group_id`.
async fn signed_public_fixture_keyed(
    plane: &str,
    group_id: &str,
    group_key: &str,
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
        .insert(group_key.to_string(), info);
    ensure_named_group_listeners(Arc::clone(&state), group_key).await;
    assert!(
        metadata_registered(&state, group_key).await,
        "precondition: the metadata listener runs"
    );
    assert_public_running(&state, &stable, "precondition").await;
    reset_listener_steps(&state);
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
        target_key_package_b64: None,
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

/// The local agent's signed self-removal of the fixture group.
async fn self_removal_event(
    state: &Arc<AppState>,
    group_id: &str,
    stable: &str,
) -> Result<NamedGroupMetadataEvent> {
    let parent = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .context("fixture record")?;
    let local = local_hex(state);
    let mut next = parent.clone();
    next.roster_revision = next.roster_revision.saturating_add(1);
    next.remove_member(&local, Some(local.clone()));
    Ok(NamedGroupMetadataEvent::MemberRemoved {
        target_key_package_b64: None,
        group_id: stable.to_string(),
        revision: next.roster_revision,
        actor: local.clone(),
        agent_id: local,
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(sign_metadata_terminality_commit(
            &parent,
            &next,
            state,
            now_millis_u64(),
        )),
    })
}

/// #2124 item 1: catch-up, the parked-event replays and the recovery
/// replays apply through `apply_named_group_metadata_event`, not through
/// the listener apply. A self-removal applied there stops both listeners.
#[tokio::test]
async fn issue2124_self_removal_applied_outside_the_listener_stops_both_listeners() -> Result<()> {
    let group_id = "2124-replay-removal-key";
    let (state, _dir, stable) = signed_public_fixture("2124-replay-removal", group_id).await?;
    let meta = metadata_task(&state, group_id).await?;
    let event = self_removal_event(&state, group_id, &stable).await?;
    let applied =
        apply_named_group_metadata_event(&state, event, state.agent.agent_id(), true, None).await;
    assert!(applied.accepted, "the signed self-removal applies");
    assert!(
        !state.named_groups.read().await.contains_key(group_id),
        "the self-removal takes the record away"
    );
    assert_metadata_stopped(&state, group_id, &meta, "a replayed self-removal").await;
    assert_public_stopped(&state, &stable, "a replayed self-removal").await;
    Ok(())
}

/// #2124 item 1: catch-up drains the TreeKEM pending queue through
/// `replay_pending_treekem_events`, which applies below the apply entry.
/// A queued self-removal there stops both listeners too.
#[tokio::test]
async fn issue2124_queued_self_removal_replayed_by_catch_up_stops_both_listeners() -> Result<()> {
    let group_id = "2124-queued-removal-key";
    let (state, _dir, stable) = signed_public_fixture("2124-queued-removal", group_id).await?;
    let meta = metadata_task(&state, group_id).await?;
    let event = self_removal_event(&state, group_id, &stable).await?;
    state
        .treekem_pending_events
        .write()
        .await
        .entry(group_id.to_string())
        .or_default()
        .push_back(PendingTreeKemMetadataEvent {
            event,
            sender: state.agent.agent_id(),
            queued_at: Instant::now(),
        });
    replay_pending_treekem_events(&state, group_id, None).await;
    assert!(
        !state.named_groups.read().await.contains_key(group_id),
        "the replayed self-removal takes the record away"
    );
    assert_metadata_stopped(&state, group_id, &meta, "a queued self-removal").await;
    assert_public_stopped(&state, &stable, "a queued self-removal").await;
    Ok(())
}

/// #2124 (ZCode review of 3f8ffd41): an event applied inside an open
/// ADR 0109 re-seat staging changes the staged record only. A self-removal
/// there takes the staged record away while the live record stays, so the
/// live record keeps both listeners.
#[tokio::test]
async fn issue2124_staged_self_removal_keeps_the_live_listeners() -> Result<()> {
    let group_id = "2124-staged-removal-key";
    let (state, _dir, stable) = signed_public_fixture("2124-staged-removal", group_id).await?;
    let live_record = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .context("fixture record")?;
    let meta = metadata_task(&state, group_id).await?;
    let event = self_removal_event(&state, group_id, &stable).await?;
    state
        .named_groups
        .staging_write()
        .await
        .insert(group_id.to_string(), live_record);
    state.reseat_stagings.open(group_id, &stable);
    let applied = state
        .reseat_stagings
        .run_in_staging_of(
            group_id,
            apply_named_group_metadata_event(&state, event, state.agent.agent_id(), true, None),
        )
        .await;
    assert!(applied.accepted, "the staged self-removal applies");
    assert!(
        !state
            .named_groups
            .staging_read()
            .await
            .contains_key(group_id),
        "the self-removal took the staged record away"
    );
    assert!(
        state.named_groups.live_read().await.contains_key(group_id),
        "the live record stays"
    );
    assert!(
        state
            .named_group_test_recorders
            .metadata_retire_steps
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0,
        "the apply reached its metadata-listener stop check"
    );
    settle().await;
    assert!(
        metadata_registered(&state, group_id).await && !meta.is_finished(),
        "the live record keeps its metadata listener"
    );
    assert_public_running(&state, &stable, "a staged self-removal").await;
    Ok(())
}

/// #2124 (Fable review of 6d1e440e): the public registry is keyed by the
/// stable id and the metadata registry by the map key. With a record whose
/// map key differs from its stable id, a queued self-removal replayed by
/// catch-up (which names the group by its map key) stops both listeners.
#[tokio::test]
async fn issue2124_queued_self_removal_under_a_distinct_key_stops_both_listeners() -> Result<()> {
    let group_key = "2124-distinct-key";
    let (state, _dir, stable) =
        signed_public_fixture_keyed("2124-distinct", "2124-distinct-stable", group_key, |_| {})
            .await?;
    assert_ne!(
        stable, group_key,
        "precondition: the key is not the stable id"
    );
    let meta = metadata_task(&state, group_key).await?;
    let event = self_removal_event(&state, group_key, &stable).await?;
    state
        .treekem_pending_events
        .write()
        .await
        .entry(group_key.to_string())
        .or_default()
        .push_back(PendingTreeKemMetadataEvent {
            event,
            sender: state.agent.agent_id(),
            queued_at: Instant::now(),
        });
    replay_pending_treekem_events(&state, group_key, None).await;
    assert!(
        !state.named_groups.read().await.contains_key(group_key),
        "the replayed self-removal takes the record away"
    );
    assert_metadata_stopped(&state, group_key, &meta, "a distinct-key self-removal").await;
    assert_public_stopped(&state, &stable, "a distinct-key self-removal").await;
    Ok(())
}

/// #2124 item 1: an accepted event that keeps the record keeps both
/// listeners on the same path.
#[tokio::test]
async fn issue2124_rename_applied_outside_the_listener_keeps_both_listeners() -> Result<()> {
    let group_id = "2124-replay-rename-key";
    let (state, _dir, stable) = signed_public_fixture("2124-replay-rename", group_id).await?;
    let parent = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .context("fixture record")?;
    let meta = metadata_task(&state, group_id).await?;
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
        apply_named_group_metadata_event(&state, event, state.agent.agent_id(), true, None).await;
    assert!(applied.accepted, "the signed rename applies");
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(group_id)
            .is_some_and(|info| info.name == "renamed"),
        "the rename keeps the record"
    );
    assert!(
        state
            .named_group_test_recorders
            .metadata_retire_steps
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0,
        "the apply reached its metadata-listener stop check"
    );
    settle().await;
    assert!(
        metadata_registered(&state, group_id).await && !meta.is_finished(),
        "the metadata listener keeps running"
    );
    assert_public_running(&state, &stable, "a replayed rename").await;
    Ok(())
}

/// #2124 item 2: a pending join stub whose attempt entry is gone (its
/// stub marker survived, the attempt registry did not) has its metadata
/// listener, and the legacy `TimedOut` owner finalizes it with no listener
/// token. That finalize stops the listener too.
#[tokio::test]
async fn issue2124_legacy_timed_out_stub_stops_its_metadata_listener() -> Result<()> {
    let group_id = "2124-legacy-stub-key";
    let (state, _dir, stable) = signed_public_fixture("2124-legacy-stub", group_id).await?;
    let member = local_hex(&state);
    if let Some(info) = state.named_groups.write().await.get_mut(group_id) {
        info.members_v2.remove(&member);
    }
    let meta = metadata_task(&state, group_id).await?;
    state
        .pending_join_stubs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(group_id.to_string());
    assert!(
        state
            .pending_join_attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty(),
        "precondition: no attempt owns the stub"
    );
    let lock = group_membership_lock_for_known_group(&state, group_id)
        .await
        .context("known group")?;
    let guard = lock.lock().await;
    let disposition = finalize_join_attempt_with_reason(
        &state,
        group_id,
        &stable,
        &member,
        "legacy",
        JoinAttemptOutcome::TimedOut,
        None,
        JoinFinalizeGuard::Owned(guard),
    )
    .await;
    assert!(
        matches!(disposition, JoinFinalizeDisposition::Finalized),
        "the legacy owner finalizes the pending stub"
    );
    assert!(
        !state.named_groups.read().await.contains_key(group_id),
        "the timeout removes the pending stub"
    );
    assert_metadata_stopped(&state, group_id, &meta, "a legacy timed-out stub").await;
    assert_public_stopped(&state, &stable, "a legacy timed-out stub").await;
    Ok(())
}

/// #2124 item 5: listeners for groups with no stored record are capped.
/// Past the cap such an install runs nothing; a stored group still gets
/// its listener.
#[tokio::test]
async fn issue2124_unrecorded_public_listeners_are_capped() -> Result<()> {
    let group_id = "2124-cap-key";
    let (state, _dir, stable) = signed_public_fixture("2124-cap", group_id).await?;
    let unrecorded = |i: usize| format!("{i:064x}");
    for i in 0..MAX_UNRECORDED_PUBLIC_MESSAGE_LISTENERS {
        spawn_public_message_listener(Arc::clone(&state), unrecorded(i)).await;
    }
    let installed = state.public_message_tasks.read().await.len();
    assert_eq!(
        installed,
        MAX_UNRECORDED_PUBLIC_MESSAGE_LISTENERS + 1,
        "the fixture's listener and one per unrecorded id up to the cap"
    );
    let over = unrecorded(MAX_UNRECORDED_PUBLIC_MESSAGE_LISTENERS);
    spawn_public_message_listener(Arc::clone(&state), over.clone()).await;
    assert!(
        !public_registered(&state, &over).await,
        "an unrecorded install past the cap is refused"
    );
    // The public-cache read refuses a further unrecorded group with a
    // typed error.
    let (status, body) = response_json(
        get_group_public_messages(
            State(Arc::clone(&state)),
            Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
            Path(over.clone()),
            Query(GetMessagesQuery::default()),
            crate::server::group_access::GroupAccess::for_test_unknown(&over),
        )
        .await
        .into_response(),
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["reason"], "public_listener_cap", "{body}");

    // A stored group is not counted against the cap.
    if let Some(handle) = state.public_message_tasks.write().await.remove(&stable) {
        handle.abort();
    }
    settle().await;
    assert!(
        eventually(|| async { live(&stable) == 0 }).await,
        "precondition: the stored group's listener has ended"
    );
    reconcile_public_message_listener(&state, group_id).await;
    settle().await;
    assert_public_running(&state, &stable, "a stored group past the cap").await;
    Ok(())
}

/// #2124 (Fable review of 6d1e440e): two installs that both pass the cap
/// pre-check race to the insert. The check under the registry write lock
/// refuses the one past the cap, and that install's task does not run on.
#[tokio::test]
async fn issue2124_the_insert_check_refuses_an_install_that_raced_past_the_cap() -> Result<()> {
    let group_id = "2124-race-key";
    let (state, _dir, _stable) = signed_public_fixture("2124-race", group_id).await?;
    let unrecorded = |i: usize| format!("{:064x}", i + 0x2124_0000);
    for i in 0..MAX_UNRECORDED_PUBLIC_MESSAGE_LISTENERS - 1 {
        spawn_public_message_listener(Arc::clone(&state), unrecorded(i)).await;
    }
    let first = unrecorded(1_000);
    let second = unrecorded(1_001);
    assert!(
        !unrecorded_public_listener_cap_reached(&state, &first).await
            && !unrecorded_public_listener_cap_reached(&state, &second).await,
        "precondition: both installs pass the cap pre-check"
    );
    tokio::join!(
        spawn_public_message_listener(Arc::clone(&state), first.clone()),
        spawn_public_message_listener(Arc::clone(&state), second.clone()),
    );
    let first_in = public_registered(&state, &first).await;
    let second_in = public_registered(&state, &second).await;
    assert!(
        first_in != second_in,
        "exactly one raced install is registered (first {first_in}, second {second_in})"
    );
    let (kept, refused) = if first_in {
        (first, second)
    } else {
        (second, first)
    };
    settle().await;
    assert!(
        eventually(|| async { live(&kept) == 1 }).await,
        "the registered install runs"
    );
    assert_eq!(live(&refused), 0, "the refused install's task does not run");
    Ok(())
}

/// #2124 (orchestrator decision on 6d1e440e): at the cap the public-cache
/// read still serves what is stored for an unrecorded group, with 200, and
/// starts no listener for it.
#[tokio::test]
async fn issue2124_at_the_cap_the_read_serves_stored_history() -> Result<()> {
    let group_id = "2124-history-key";
    let (state, _dir, _stable) = signed_public_fixture("2124-history", group_id).await?;
    let unrecorded = |i: usize| format!("{:064x}", i + 0x2125_0000);
    for i in 0..MAX_UNRECORDED_PUBLIC_MESSAGE_LISTENERS {
        spawn_public_message_listener(Arc::clone(&state), unrecorded(i)).await;
    }
    let stored_id = unrecorded(5_000);
    let author = x0x::identity::AgentKeypair::generate()?;
    let message = x0x::groups::GroupPublicMessage::sign(
        stored_id.clone(),
        "state-hash-1".into(),
        1,
        &author,
        None,
        x0x::groups::GroupPublicMessageKind::Chat,
        "kept".to_string(),
        1_000,
        None,
        None,
        None,
    )?;
    state
        .public_messages
        .write()
        .await
        .entry(stored_id.clone())
        .or_default()
        .push(message);
    let (status, body) = response_json(
        get_group_public_messages(
            State(Arc::clone(&state)),
            Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
            Path(stored_id.clone()),
            Query(GetMessagesQuery::default()),
            crate::server::group_access::GroupAccess::for_test_unknown(&stored_id),
        )
        .await
        .into_response(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["messages"][0]["body"], "kept",
        "the stored message is served: {body}"
    );
    assert!(
        !public_registered(&state, &stored_id).await,
        "no listener starts past the cap"
    );
    Ok(())
}
