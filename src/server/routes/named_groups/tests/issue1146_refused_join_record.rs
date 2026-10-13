//! #1146: a consumed-invite refusal after another member's signed addition
//! must not prevent a later addressed invitation from seating this identity.
//! Offline agents only: no network config, sockets, bootstrap or join_network.
//! Deliver protocol events explicitly; copy the authority's real Welcome bytes
//! into the supported inline field instead of fetching them over transport.

use super::*;

fn member(state: &AppState) -> String {
    hex::encode(state.agent.agent_id().as_bytes())
}

async fn invite(state: &Arc<AppState>, group: &str, intended: Option<String>) -> String {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    let response = create_group_invite(
        State(Arc::clone(state)),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group.to_string()),
        headers,
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "expiry_secs": 3600,
                "intended_joiner": intended,
            }))
            .unwrap(),
        ),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    body["invite_link"]
        .as_str()
        .expect("invite link")
        .to_string()
}

async fn join(state: &Arc<AppState>, link: String) {
    let response = join_group_via_invite(
        State(Arc::clone(state)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["join_state"], "pending_authority_commit", "{body}");
}

fn attempt(state: &AppState, stable: &str) -> (String, NamedGroupMetadataEvent) {
    let attempts = state.pending_join_attempts.lock().unwrap();
    let entry = attempts
        .get(&join_result_key(stable, &member(state)))
        .expect("new attempt");
    (
        entry.attempt_id.clone(),
        entry
            .stored_resend
            .as_ref()
            .expect("new admission volley")
            .event
            .clone(),
    )
}

async fn result(authority: &AppState, stable: &str, joiner: &AppState) -> NamedGroupMetadataEvent {
    let mut event = authority
        .pending_join_results
        .read()
        .await
        .get(&join_result_key(stable, &member(joiner)))
        .expect("staged result")
        .event
        .clone();
    if let NamedGroupMetadataEvent::MemberAdded {
        treekem_welcome_b64,
        welcome_ref,
        ..
    } = &mut event
    {
        let reference = welcome_ref.take().expect("authority staged a Welcome");
        let welcomes = authority.pending_welcomes.read().await;
        let welcome = welcomes
            .get(&reference.welcome_id)
            .expect("real Welcome bytes");
        assert_eq!(welcome.joiner_agent, member(joiner));
        *treekem_welcome_b64 = Some(BASE64.encode(&welcome.bytes));
    } else {
        panic!("expected MemberAdded");
    }
    event
}

async fn deliver_result(
    joiner: &Arc<AppState>,
    authority: &AppState,
    event: NamedGroupMetadataEvent,
) {
    handle_join_result_message(
        joiner,
        &authority.agent.agent_id(),
        true,
        JoinResultMessage::Result {
            event: Box::new(event),
            chain: Vec::new(),
            head_attestation: None,
            roster_certificates_b64: Vec::new(),
            intervening_events: Vec::new(),
        },
    )
    .await;
}

async fn encrypt(
    state: &Arc<AppState>,
    group: &str,
    plaintext: &[u8],
) -> (StatusCode, serde_json::Value) {
    let (status, body) = secure_group_encrypt(
        State(Arc::clone(state)),
        Path(group.to_string()),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Json(SecureEncryptRequest {
            payload_b64: BASE64.encode(plaintext),
        }),
    )
    .await;
    (status, body.0)
}

async fn decrypt(
    state: &Arc<AppState>,
    group: &str,
    ciphertext: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let (status, body) = secure_group_decrypt(
        State(Arc::clone(state)),
        Path(group.to_string()),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Json(SecureDecryptRequest {
            ciphertext_b64: ciphertext["ciphertext_b64"]
                .as_str()
                .expect("ciphertext")
                .to_string(),
            nonce_b64: String::new(),
            secret_epoch: 0,
        }),
    )
    .await;
    (status, body.0)
}

#[tokio::test]
async fn refused_join_retained_record_accepts_fresh_addressed_invite() -> Result<()> {
    let (authority, _a) = secure_endpoint_test_state().await?;
    let (first, _b) = secure_endpoint_test_state().await?;
    let (refused, _d) = secure_endpoint_test_state().await?;
    let created = create_named_group(
        State(Arc::clone(&authority)),
        Json(CreateGroupRequest {
            name: "issue1146".to_string(),
            description: String::new(),
            display_name: None,
            preset: Some("private_secure".to_string()),
            policy: None,
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(created).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let group = body["group_id"].as_str().expect("group id").to_string();
    let (stable, base_revision) = {
        let groups = authority.named_groups.read().await;
        let info = groups.get(&group).unwrap();
        assert_eq!(info.secure_plane, x0x::mls::SecureGroupPlane::TreeKem);
        (info.stable_group_id().to_string(), info.state_revision)
    };
    let consumed_link = invite(&authority, &group, None).await;
    join(&first, consumed_link.clone()).await;
    let (_, first_join) = attempt(&first, &stable);
    assert!(
        apply_named_group_metadata_event(
            &authority,
            first_join,
            first.agent.agent_id(),
            true,
            None
        )
        .await
        .accepted
    );
    let first_add = result(&authority, &stable, &first).await;
    deliver_result(&first, &authority, first_add.clone()).await;
    assert!(first.named_groups.read().await[&group].has_active_member(&member(&first)));

    join(&refused, consumed_link).await;
    let (old_attempt, refused_join) = attempt(&refused, &stable);
    // Explicit race ordering: persist the OTHER member's valid signed add
    // before the consumed-invite refusal. ADR 0107 retains this carry state.
    assert!(
        apply_named_group_metadata_event(
            &refused,
            first_add,
            authority.agent.agent_id(),
            true,
            None
        )
        .await
        .accepted
    );
    {
        let groups = refused.named_groups.read().await;
        let info = &groups[&group];
        assert_eq!(info.state_revision, base_revision + 1);
        assert!(!info.has_active_member(&member(&refused)));
        assert_eq!(
            classify_not_member_join_row(info, &member(&refused)),
            NotMemberJoinRow::UnseatedJoinRemnant
        );
    }
    assert!(!refused.pending_join_stubs.lock().unwrap().contains(&group));
    assert!(
        !apply_named_group_metadata_event(
            &authority,
            refused_join,
            refused.agent.agent_id(),
            true,
            None
        )
        .await
        .accepted
    );
    let lock = group_membership_lock_for_known_group(&authority, &stable)
        .await
        .expect("group lock");
    let refusal_bytes = serve_staged_join_refusal(
        &authority,
        &stable,
        &member(&refused),
        &old_attempt,
        lock.lock().await,
    )
    .await
    .expect("authority serves signed consumed-invite refusal");
    let receipt = match serde_json::from_slice::<JoinResultMessage>(&refusal_bytes)? {
        JoinResultMessage::Refused { receipt } => receipt,
        _ => panic!("expected typed refusal"),
    };
    assert_eq!(receipt.reason, JoinRefusalReason::InviteSecretConsumed);
    handle_join_result_message(
        &refused,
        &authority.agent.agent_id(),
        true,
        JoinResultMessage::Refused {
            receipt: receipt.clone(),
        },
    )
    .await;
    let (status, body) = join_status_body(&refused, &group).await;
    assert_eq!(status, StatusCode::OK, "retained-row precondition: {body}");
    assert_eq!(
        body["last_join_outcome"]["reason"],
        "invite_secret_consumed"
    );
    assert!(refused.pending_join_attempts.lock().unwrap().is_empty());
    assert!(!refused.treekem_groups.read().await.contains_key(&group));

    let (status, ciphertext) = encrypt(&authority, &group, b"before admission").await;
    assert_eq!(status, StatusCode::OK, "{ciphertext}");
    for (status, body) in [
        encrypt(&refused, &group, b"denied").await,
        decrypt(&refused, &group, &ciphertext).await,
    ] {
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["error"].as_str().unwrap().contains("not a member"),
            "{body}"
        );
    }

    // Same identity and process, no row deletion or restart by the fixture.
    let fresh_link = invite(&authority, &group, Some(member(&refused))).await;
    join(&refused, fresh_link).await;
    let (new_attempt, fresh_join) = attempt(&refused, &stable);
    assert_ne!(new_attempt, old_attempt);
    assert!(!refused
        .last_join_outcomes
        .lock()
        .unwrap()
        .contains_key(&group));
    handle_join_result_message(
        &refused,
        &authority.agent.agent_id(),
        true,
        JoinResultMessage::Refused {
            receipt: receipt.clone(),
        },
    )
    .await;
    assert_eq!(
        attempt(&refused, &stable).0,
        new_attempt,
        "delayed old refusal cannot cancel the fresh attempt"
    );
    assert!(
        apply_named_group_metadata_event(
            &authority,
            fresh_join,
            refused.agent.agent_id(),
            true,
            None
        )
        .await
        .accepted
    );
    let fresh_add = result(&authority, &stable, &refused).await;
    deliver_result(&refused, &authority, fresh_add).await;
    handle_join_result_message(
        &refused,
        &authority.agent.agent_id(),
        true,
        JoinResultMessage::Refused { receipt },
    )
    .await;
    assert!(refused.pending_join_attempts.lock().unwrap().is_empty());
    assert!(!refused.pending_join_stubs.lock().unwrap().contains(&group));
    assert!(
        !refused
            .last_join_outcomes
            .lock()
            .unwrap()
            .contains_key(&group),
        "a delayed refusal cannot replace a committed seat"
    );
    {
        let local = refused.named_groups.read().await;
        let remote = authority.named_groups.read().await;
        assert!(local[&group].has_active_member(&member(&refused)));
        assert!(remote[&group].has_active_member(&member(&refused)));
        assert_eq!(local[&group].state_hash, remote[&group].state_hash);
    }
    for (sender, receiver, plaintext) in [
        (
            &authority,
            &refused,
            b"fresh authority to admitted member".as_slice(),
        ),
        (
            &refused,
            &authority,
            b"fresh admitted member to authority".as_slice(),
        ),
    ] {
        let (status, ciphertext) = encrypt(sender, &group, plaintext).await;
        assert_eq!(status, StatusCode::OK, "{ciphertext}");
        let (status, opened) = decrypt(receiver, &group, &ciphertext).await;
        assert_eq!(status, StatusCode::OK, "{opened}");
        assert_eq!(opened["payload_b64"], BASE64.encode(plaintext));
    }
    Ok(())
}
