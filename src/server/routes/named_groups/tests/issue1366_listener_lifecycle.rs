#![cfg(test)]
//! #1366: each listener class stops when no stored record needs it, not
//! only at a restart.
//!
//! - A self-leave takes the record away: both listeners stop.
//! - A refreshed card changes a non-member stub to `MlsEncrypted`: the
//!   public-message listener stops and the metadata listener stays.
//! - A record that is gone (a remote self-removal from either transport,
//!   or a refused join stub) keeps no public-message listener.
//! - A request-access applicant keeps its metadata listener while it waits.
//!
//! Local topics drive the real subscribers. Inert apart from the
//! loopback-only test network of `networked_test_state`.

use super::*;

/// Lets aborted tasks drop and new tasks reach their first poll.
async fn settle() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
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

/// A SignedPublic group with a second admin, so the local agent may leave.
async fn signed_public_fixture(
    plane: &str,
    group_id: &str,
) -> Result<(Arc<AppState>, tempfile::TempDir, String)> {
    let (state, dir) = networked_test_state(plane).await?;
    let (mut info, _, member_hex) = metadata_terminality_test_group(&state, group_id);
    info.policy.confidentiality = x0x::groups::GroupConfidentiality::SignedPublic;
    info.metadata_topic = format!("local:1366-lifecycle-metadata-{group_id}");
    if let Some(member) = info.members_v2.get_mut(&member_hex) {
        member.role = x0x::groups::GroupRole::Admin;
    }
    info.recompute_state_hash();
    let stable = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
    ensure_named_group_listeners(Arc::clone(&state), group_id).await;
    settle().await;
    assert!(
        metadata_registered(&state, group_id).await,
        "precondition: the metadata listener runs"
    );
    assert!(
        public_registered(&state, &stable).await,
        "precondition: the public-message listener runs"
    );
    Ok((state, dir, stable))
}

#[tokio::test]
async fn issue1366_self_leave_stops_both_listeners() -> Result<()> {
    let group_id = "1366-lifecycle-leave-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-leave", group_id).await?;
    let (status, body) = response_json(
        leave_group(
            State(Arc::clone(&state)),
            Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
            Path(group_id.to_string()),
        )
        .await
        .into_response(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "the leave applies: {body}");
    settle().await;
    assert!(
        !state.named_groups.read().await.contains_key(group_id),
        "the leave removes the record"
    );
    assert!(
        !metadata_registered(&state, group_id).await,
        "#1366: a self-leave stops the metadata listener"
    );
    assert!(
        !public_registered(&state, &stable).await,
        "#1366: a self-leave stops the public-message listener"
    );
    Ok(())
}

#[tokio::test]
async fn issue1366_a_gone_record_keeps_no_public_listener() -> Result<()> {
    let group_id = "1366-lifecycle-gone-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-gone", group_id).await?;
    // A remote self-removal (topic or direct lane) or a refused join stub
    // takes the record away outside the leave route.
    state.named_groups.write().await.remove(group_id);
    reconcile_public_message_listener(&state, &stable).await;
    settle().await;
    assert!(
        !public_registered(&state, &stable).await,
        "#1366: no stored record needs the public-message listener, so it stops"
    );
    Ok(())
}

#[tokio::test]
async fn issue1366_a_stored_alias_keeps_the_public_listener() -> Result<()> {
    let group_id = "1366-lifecycle-alias-key";
    let (state, _dir, stable) = signed_public_fixture("1366-lifecycle-alias", group_id).await?;
    // The record is still stored under its key: the retire is a no-op.
    listener_lifecycle::retire_unwanted_public_message_listener(&state, &stable).await;
    listener_lifecycle::retire_unwanted_public_message_listener(&state, group_id).await;
    settle().await;
    assert!(
        public_registered(&state, &stable).await,
        "#1366: a record that needs the listener keeps it"
    );
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
    assert!(
        public_registered(&state, &group_id).await,
        "a SignedPublic stub runs its public-message listener"
    );

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
    assert!(
        !public_registered(&state, &group_id).await,
        "#1366: a card refresh to MlsEncrypted stops the stub's public-message listener"
    );
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
