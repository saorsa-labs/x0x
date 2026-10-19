use super::*;

// Inert tests: GroupInfo values, classification and JSON responses only.
// No AppState, agent, sockets, tasks or filesystem writes.
fn lineage_free_row() -> (x0x::groups::GroupInfo, String) {
    let info = x0x::groups::GroupInfo::new(
        "carry remnant".into(),
        String::new(),
        AgentId([1; 32]),
        "1161".repeat(16),
    );
    let mut row = serde_json::to_value(info).expect("serialize row");
    row.as_object_mut()
        .expect("object")
        .remove("invite_lineage");
    assert!(row.get("invite_lineage").is_none());
    let info: x0x::groups::GroupInfo = serde_json::from_value(row).expect("absent field is valid");
    let joiner = hex::encode(AgentId([2; 32]).as_bytes());
    assert!(info.invite_lineage.is_none());
    assert!(!info.members_v2.contains_key(&joiner));
    assert!(!info.has_active_member(&joiner));
    // Default PrivateSecure mints a shared_secret — not an inert card stub.
    assert!(info.shared_secret.is_some());
    (info, joiner)
}

/// Exact shape [`import_card_into_groups`] inserts for a discoverable card.
fn card_import_stub(owner: AgentId, group_id: &str, joiner_hex: &str) -> x0x::groups::GroupInfo {
    let owner_hex = hex::encode(owner.as_bytes());
    let mut stub = x0x::groups::GroupInfo::with_policy(
        "card stub".into(),
        String::new(),
        owner,
        group_id.to_string(),
        x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
    );
    stub.members_v2.clear();
    stub.members_v2.insert(
        owner_hex.clone(),
        x0x::groups::GroupMember::new_admin(owner_hex.clone(), None, stub.created_at),
    );
    stub.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
        group_id.to_string(),
        owner_hex,
        stub.created_at,
        String::new(),
    ));
    stub.shared_secret = None;
    stub.secret_epoch = 0;
    stub.invite_lineage = None;
    stub.issued_invites.clear();
    stub.issued_invite_secrets.clear();
    stub.join_requests.clear();
    stub.commit_log.clear();
    stub.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    assert!(
        !stub.members_v2.contains_key(joiner_hex),
        "importer is not a member"
    );
    assert_eq!(
        classify_not_member_join_row(&stub, joiner_hex),
        NotMemberJoinRow::InertCardImportStub
    );
    stub
}

#[test]
fn absent_lineage_reports_failed_join_with_existing_error_shape_and_remedy() {
    let (info, joiner) = lineage_free_row();
    let before = serde_json::to_value(&info).expect("snapshot");
    let row = classify_not_member_join_row(&info, &joiner);
    assert_eq!(row, NotMemberJoinRow::JoinFailed);
    let (status, Json(body)) = row
        .refusal_response(&info)
        .expect("failed join must refuse");
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["ok"], false);
    assert_eq!(body.as_object().expect("error object").len(), 2);
    let error = body["error"].as_str().expect("existing error field");
    assert!(error.contains("join failed"));
    assert!(error.contains("no invite lineage"));
    assert!(error.contains("no seat"));
    assert!(error.contains("fresh invite cannot replace"));
    // Default GroupInfo::new policy is not RequestAccess — do not claim that path.
    assert!(!error.contains("request access"));
    assert!(!error.contains("/requests"));
    // No implementation identifiers in REST-facing text.
    assert!(!error.contains("UnseatedJoinRemnant"));
    assert!(!error.contains("clear_stale_not_member_join_row"));
    assert!(!error.contains("no supported recovery path"));
    // Honest remedy: do not claim authority/fresh-invite recovery works for
    // this shape — those steps leave the local row unchanged.
    assert!(!error.contains("authority device"));
    assert!(!error.contains("request a fresh invite"));
    assert_eq!(serde_json::to_value(&info).expect("snapshot"), before);
}

#[test]
fn request_access_lineage_free_remedy_names_join_request_path() {
    let (mut info, joiner) = lineage_free_row();
    info.policy.admission = x0x::groups::GroupAdmission::RequestAccess;
    let row = classify_not_member_join_row(&info, &joiner);
    assert_eq!(row, NotMemberJoinRow::JoinFailed);
    let (_, Json(body)) = row
        .refusal_response(&info)
        .expect("failed join must refuse");
    let error = body["error"].as_str().expect("existing error field");
    assert!(error.contains("fresh invite cannot replace"));
    assert!(error.contains("request access"));
    assert!(error.contains("POST /groups/:id/requests"));
    assert!(error.contains("admin to approve"));
    // Lost-join case: authority may already seat this device, so a new
    // request is rejected — do not claim waiting for approval always works.
    assert!(error.contains("has not already seated"));
    assert!(error.contains("new request is rejected"));
    assert!(error.contains("seating result") || error.contains("group catch-up"));
    assert!(!error.contains("UnseatedJoinRemnant"));
    assert!(!error.contains("clear_stale_not_member_join_row"));
}

#[test]
fn missing_lineage_does_not_override_roster_or_withdrawal() {
    let (info, joiner) = lineage_free_row();
    for member_state in [
        x0x::groups::GroupMemberState::Active,
        x0x::groups::GroupMemberState::Pending,
        x0x::groups::GroupMemberState::Removed,
        x0x::groups::GroupMemberState::Banned,
    ] {
        let mut row = info.clone();
        row.add_member(joiner.clone(), x0x::groups::GroupRole::Member, None, None);
        row.members_v2.get_mut(&joiner).expect("seat").state = member_state;
        let classified = classify_not_member_join_row(&row, &joiner);
        assert_eq!(classified, NotMemberJoinRow::Other, "{member_state:?}");
        assert!(classified.refusal_response(&row).is_none());
    }
    let mut withdrawn = info;
    withdrawn.withdrawn = true;
    assert_eq!(
        classify_not_member_join_row(&withdrawn, &joiner),
        NotMemberJoinRow::Other
    );
}

#[test]
fn lineage_and_quarantine_keep_their_existing_classification() {
    let (mut info, joiner) = lineage_free_row();
    let header = info.terminal_commit_header();
    info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
        revision: 1,
        state_hash: info.state_hash.clone(),
        committed_by: hex::encode(info.creator.as_bytes()),
        observed_at_ms: 1,
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: header.clone(),
            conflicting_commit: header,
            classification: None,
        },
        no_anchor: true,
    });
    let quarantined = classify_not_member_join_row(&info, &joiner);
    assert_eq!(quarantined, NotMemberJoinRow::Quarantined);
    let (status, Json(body)) = quarantined
        .refusal_response(&info)
        .expect("quarantine refuses");
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "fork_quarantined");
    assert!(body["error"]
        .as_str()
        .expect("error")
        .contains("/quarantine/clear"));

    info.fork_quarantine = None;
    info.invite_lineage = Some(x0x::groups::InviteLineage::default());
    let remnant = classify_not_member_join_row(&info, &joiner);
    assert_eq!(remnant, NotMemberJoinRow::UnseatedJoinRemnant);
    assert!(remnant.refusal_response(&info).is_none());

    let lineage = info.invite_lineage.as_mut().expect("lineage");
    lineage.seated_at_revision = Some(1);
    assert_eq!(
        classify_not_member_join_row(&info, &joiner),
        NotMemberJoinRow::Other
    );
    info.invite_lineage.as_mut().expect("lineage").fork_evidence =
        Some(x0x::groups::ForkEvidence {
            revision: 1,
            state_hash: "ab".repeat(32),
            committed_by: "cd".repeat(32),
            observed_at_ms: 1,
        });
    assert_eq!(
        classify_not_member_join_row(&info, &joiner),
        NotMemberJoinRow::Quarantined
    );
}

/// Card-import-shaped lineage-free stub (RequestAccess): request access on
/// the stuck requester row, deliver `JoinRequestCreated` to the admin, approve,
/// then deliver `JoinRequestApproved` back onto the requester and assert that
/// device's own row recovers to membership (not merely the admin roster).
#[tokio::test]
async fn lineage_free_request_access_stub_seats_after_request_and_approve() -> Result<()> {
    let admin_kp = crate::identity::AgentKeypair::generate()?;
    let admin_id = admin_kp.agent_id();
    let admin_hex = hex::encode(admin_id.as_bytes());

    let (requester_state, _req_dir) = secure_endpoint_test_state().await?;
    let (admin_state, _admin_dir) = secure_endpoint_test_state_with_key(admin_kp).await?;
    let requester_hex = hex::encode(requester_state.agent.agent_id().as_bytes());
    let requester_id = requester_state.agent.agent_id();
    let requester_kp = requester_state.agent.identity().agent_keypair();

    requester_state
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    admin_state
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let group_id = "1161reqaccess".repeat(2); // 32 hex-ish chars
    let group_id = hex::encode(blake3::hash(group_id.as_bytes()).as_bytes());

    // Shared card-import stub / live base so create→approve commits chain
    // across both daemons (authority seated, importer not a member,
    // invite_lineage absent, admission request_access, GSS plane).
    let mut base = x0x::groups::GroupInfo::with_policy(
        "issue1161 request-access stub".into(),
        String::new(),
        admin_id,
        group_id.clone(),
        x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
    );
    base.members_v2.clear();
    base.members_v2.insert(
        admin_hex.clone(),
        x0x::groups::GroupMember::new_admin(admin_hex.clone(), None, base.created_at),
    );
    base.shared_secret = None;
    base.secret_epoch = 0;
    base.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    assert!(base.invite_lineage.is_none());
    assert!(!base.members_v2.contains_key(&requester_hex));
    // Card-import shape with no secret is the new clearable stub; request
    // access remains a recovery path when the caller chooses not to redeem
    // a fresh invite (or when the stub fails the invite-match gate).
    assert_eq!(
        classify_not_member_join_row(&base, &requester_hex),
        NotMemberJoinRow::InertCardImportStub
    );
    assert!(classify_not_member_join_row(&base, &requester_hex)
        .refusal_response(&base)
        .is_none());
    requester_state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), base.clone());
    admin_state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), base);

    let (create_status, create_body) = response_json(
        create_join_request(
            State(Arc::clone(&requester_state)),
            Path(group_id.clone()),
            None,
        )
        .await
        .into_response(),
    )
    .await?;
    assert_eq!(
        create_status,
        StatusCode::CREATED,
        "non-member may request access on a lineage-free RequestAccess stub: {create_body}"
    );
    let request_id = create_body["request_id"]
        .as_str()
        .expect("request_id")
        .to_string();

    // Offline create publishes via with_envelope (no offer outbox when
    // gossip signing cannot return wire bytes). Rebuild the sealed
    // JoinRequestCreated from the requester's post-create commit_log and
    // deliver it onto the admin so approve chains from the same head.
    let created = {
        use base64::Engine as _;
        let groups = requester_state.named_groups.read().await;
        let info = groups.get(&group_id).expect("requester stub after create");
        let req = info
            .join_requests
            .get(&request_id)
            .cloned()
            .expect("pending request on requester stub");
        let commit = info.terminal_commit_header();
        assert!(
            !commit.signature.is_empty(),
            "create must retain a signed commit for delivery"
        );
        NamedGroupMetadataEvent::JoinRequestCreated {
            group_id: info.stable_group_id().to_string(),
            request_id: request_id.clone(),
            requester_agent_id: req.requester_agent_id,
            message: req.message,
            ts: req.created_at,
            requester_kem_public_key_b64: Some(
                BASE64.encode(&requester_state.agent_kem_keypair.public_bytes),
            ),
            treekem_key_package_b64: req.treekem_key_package_b64,
            commit: Some(commit),
        }
    };
    assert!(
        apply_named_group_metadata_event(&admin_state, created, requester_id, true, None)
            .await
            .accepted,
        "admin must accept the requester's JoinRequestCreated on the shared base"
    );

    adr0028_direct_controls::offer_predecessor_obligation_via_real_path(
        &admin_state,
        &group_id,
        &request_id,
        requester_kp,
    )
    .await;

    admin_state
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish hook")
        .clear();

    let (approve_status, approve_body) = response_json(
        approve_join_request(
            State(Arc::clone(&admin_state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path((group_id.clone(), request_id.clone())),
        )
        .await
        .into_response(),
    )
    .await?;
    assert_eq!(
        approve_status,
        StatusCode::OK,
        "admin approval must seat the requester: {approve_body}"
    );

    {
        let groups = admin_state.named_groups.read().await;
        let seated = groups.get(&group_id).expect("admin group");
        assert!(
            seated.has_active_member(&requester_hex),
            "admin roster seats the requester after approval"
        );
    }

    let approved = admin_state
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish hook")
        .iter()
        .filter_map(|(_topic, bytes)| serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok())
        .find_map(|event| match &event {
            NamedGroupMetadataEvent::JoinRequestApproved {
                request_id: rid, ..
            } if *rid == request_id => Some(event),
            _ => None,
        })
        .expect("admin published JoinRequestApproved");
    assert!(
        apply_named_group_metadata_event(&requester_state, approved, admin_id, true, None)
            .await
            .accepted,
        "requester must accept JoinRequestApproved on its stuck row"
    );

    let groups = requester_state.named_groups.read().await;
    let seated = groups.get(&group_id).expect("requester group");
    assert!(
        seated.has_active_member(&requester_hex),
        "delivered JoinRequestApproved must recover the requester's own stuck row to membership"
    );
    Ok(())
}

#[test]
fn card_import_stub_classifies_as_inert_clearable_not_join_failed() {
    let owner = AgentId([9; 32]);
    let joiner = hex::encode(AgentId([8; 32]).as_bytes());
    let group_id = "1161stub".repeat(4);
    let stub = card_import_stub(owner, &group_id, &joiner);
    let row = classify_not_member_join_row(&stub, &joiner);
    assert_eq!(row, NotMemberJoinRow::InertCardImportStub);
    assert!(row.refusal_response(&stub).is_none());
    // JoinFailed stays a distinct refusal — a secret-bearing lineage-free
    // row must not become clearable just because lineage is absent.
    let (secret_row, secret_joiner) = lineage_free_row();
    assert_eq!(
        classify_not_member_join_row(&secret_row, &secret_joiner),
        NotMemberJoinRow::JoinFailed
    );
    assert!(NotMemberJoinRow::JoinFailed
        .refusal_response(&secret_row)
        .is_some());
}

#[test]
fn inert_stub_predicate_rejects_secret_seat_pending_invite_denial_and_extra_roster() {
    let owner = AgentId([9; 32]);
    let joiner = hex::encode(AgentId([8; 32]).as_bytes());
    let group_id = "1161pred".repeat(4);
    let base = card_import_stub(owner, &group_id, &joiner);

    let mut with_secret = base.clone();
    with_secret.shared_secret = Some(vec![1; 32]);
    assert_eq!(
        classify_not_member_join_row(&with_secret, &joiner),
        NotMemberJoinRow::JoinFailed
    );

    let mut with_epoch = base.clone();
    with_epoch.secret_epoch = 1;
    assert_eq!(
        classify_not_member_join_row(&with_epoch, &joiner),
        NotMemberJoinRow::JoinFailed
    );

    let mut with_seat = base.clone();
    with_seat.add_member(joiner.clone(), x0x::groups::GroupRole::Member, None, None);
    assert_eq!(
        classify_not_member_join_row(&with_seat, &joiner),
        NotMemberJoinRow::Other
    );

    let mut with_issued = base.clone();
    with_issued.issued_invite_secrets.insert("sec".into());
    assert_eq!(
        classify_not_member_join_row(&with_issued, &joiner),
        NotMemberJoinRow::JoinFailed
    );

    let mut with_request = base.clone();
    let mut denied = x0x::groups::JoinRequest::new(group_id.clone(), joiner.clone(), None, 1);
    denied.status = x0x::groups::JoinRequestStatus::Rejected;
    denied.reviewed_at = Some(2);
    denied.reviewed_by = Some(hex::encode(owner.as_bytes()));
    with_request
        .join_requests
        .insert(denied.request_id.clone(), denied);
    assert_eq!(
        classify_not_member_join_row(&with_request, &joiner),
        NotMemberJoinRow::JoinFailed
    );

    let mut with_extra = base.clone();
    with_extra.add_member(
        hex::encode(AgentId([7; 32]).as_bytes()),
        x0x::groups::GroupRole::Member,
        None,
        None,
    );
    assert_eq!(
        classify_not_member_join_row(&with_extra, &joiner),
        NotMemberJoinRow::JoinFailed
    );
}

#[test]
fn inert_stub_invite_match_requires_stable_and_owner() {
    let owner = AgentId([9; 32]);
    let joiner = hex::encode(AgentId([8; 32]).as_bytes());
    let group_id = "1161match".repeat(4);
    let stub = card_import_stub(owner, &group_id, &joiner);
    let owner_hex = hex::encode(owner.as_bytes());
    assert!(inert_stub_matches_verified_invite(
        &stub, &group_id, &owner_hex
    ));
    assert!(!inert_stub_matches_verified_invite(
        &stub,
        &"dead".repeat(16),
        &owner_hex
    ));
    assert!(!inert_stub_matches_verified_invite(
        &stub,
        &group_id,
        &"ab".repeat(32)
    ));
}

/// #1161: verified fresh invite replaces an inert card-import stub, then the
/// ordinary first-join path seats the requester with a usable GSS key.
#[tokio::test]
async fn inert_card_import_stub_replaced_by_verified_invite_seats_with_key() -> Result<()> {
    let (authority_state, _a) = secure_endpoint_test_state().await?;
    let (joiner_state, _j) = secure_endpoint_test_state().await?;
    authority_state
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    joiner_state
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let group = hex::encode(blake3::hash(b"1161-stub-replace-success").as_bytes());
    let authority_id = authority_state.agent.agent_id();
    let joiner_hex = hex::encode(joiner_state.agent.agent_id().as_bytes());

    // Live authority group (InviteOnly / GSS / secret present).
    let mut authority = x0x::groups::GroupInfo::with_policy(
        "live".into(),
        String::new(),
        authority_id,
        group.clone(),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    authority.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    assert!(authority.shared_secret.is_some());
    let projection = x0x::groups::state_commit::roster_projection(&authority.members_v2);
    let stable = authority.stable_group_id().to_string();
    authority.state_hash = x0x::groups::state_commit::compute_state_hash(
        &stable,
        authority.state_revision,
        authority.prev_state_hash.as_deref(),
        &x0x::groups::state_commit::roster_root_of_projection(&projection),
        &x0x::groups::state_commit::compute_policy_hash(&authority.policy),
        &x0x::groups::state_commit::compute_public_meta_hash(&authority.public_meta()),
        authority.security_binding.as_deref(),
        false,
    );
    authority_state
        .named_groups
        .write()
        .await
        .insert(group.clone(), authority.clone());

    // Joiner holds the inert card-import stub for the same genesis.
    let stub = card_import_stub(authority_id, &group, &joiner_hex);
    joiner_state
        .named_groups
        .write()
        .await
        .insert(group.clone(), stub);

    let (invite, link) =
        assemble_signed_v4_invite(&authority_state, &authority, 3_600, None).expect("mint invite");
    {
        let now_secs = now_millis_u64() / 1_000;
        let mut groups = authority_state.named_groups.write().await;
        let info = groups.get_mut(&group).expect("authority");
        info.record_issued_invite_v2(
            invite.invite_secret.clone(),
            now_secs.saturating_sub(60),
            now_secs + 3_600,
            x0x::groups::GroupRole::Member,
            None,
            x0x::groups::InviteOrigin::Explicit,
            Some(link.clone()),
        );
    }

    let response = join_group_via_invite(
        State(Arc::clone(&joiner_state)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "join after stub replace: {body}");
    assert_eq!(
        body["join_state"].as_str(),
        Some("pending_authority_commit"),
        "{body}"
    );
    // Clearing grants no seat/key — the join stub is a fresh first-join row.
    {
        let groups = joiner_state.named_groups.read().await;
        let info = groups.get(&group).expect("fresh join stub");
        assert!(
            info.invite_lineage.is_some(),
            "first-join lineage installed"
        );
        assert!(!info.has_active_member(&joiner_hex));
        assert!(info.shared_secret.is_none());
    }

    let attempt_event = {
        let attempts = joiner_state
            .pending_join_attempts
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let entry = attempts
            .get(&join_result_key(&stable, &joiner_hex))
            .expect("attempt registered");
        entry
            .stored_resend
            .as_ref()
            .expect("stored MemberJoined")
            .event
            .clone()
    };
    assert!(
        apply_named_group_metadata_event(
            &authority_state,
            attempt_event,
            joiner_state.agent.agent_id(),
            true,
            None,
        )
        .await
        .accepted,
        "authority accepts the joiner's MemberJoined"
    );
    assert!(
        authority_state
            .named_groups
            .read()
            .await
            .get(&group)
            .is_some_and(|i| i.has_active_member(&joiner_hex)),
        "authority seats the joiner"
    );

    let staged = authority_state
        .pending_join_results
        .read()
        .await
        .get(&join_result_key(&stable, &joiner_hex))
        .map(|p| (p.event.clone(), p.head_attestation.clone()))
        .expect("join result staged");
    handle_join_result_message(
        &joiner_state,
        &authority_id,
        true,
        JoinResultMessage::Result {
            event: Box::new(staged.0),
            chain: Vec::new(),
            head_attestation: staged.1.map(Box::new),
            roster_certificates_b64: Vec::new(),
            intervening_events: Vec::new(),
        },
    )
    .await;
    assert!(
        joiner_state
            .named_groups
            .read()
            .await
            .get(&group)
            .is_some_and(|i| i.has_active_member(&joiner_hex)),
        "requester seat completes after stub replace"
    );

    let share = authority_state
        .named_group_test_recorders
        .secure_share_scheduled
        .lock()
        .expect("share witness")
        .iter()
        .filter(|(_, to, _)| to == &joiner_hex)
        .find_map(|(_, _, bytes)| serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok())
        .expect("authority sealed a SecureShareDelivered for the joiner");
    assert!(
        apply_named_group_metadata_event(&joiner_state, share, authority_id, true, None)
            .await
            .accepted,
        "joiner opens the sealed share"
    );
    let (auth_secret, auth_epoch) = {
        let groups = authority_state.named_groups.read().await;
        let info = groups.get(&group).expect("authority");
        (info.shared_secret.clone(), info.secret_epoch)
    };
    let (joiner_secret, joiner_epoch) = {
        let groups = joiner_state.named_groups.read().await;
        let info = groups.get(&group).expect("joiner");
        (info.shared_secret.clone(), info.secret_epoch)
    };
    assert!(auth_secret.is_some());
    assert_eq!(
        (joiner_secret, joiner_epoch),
        (auth_secret, auth_epoch),
        "requester holds the group's current key after stub replace"
    );
    Ok(())
}

#[tokio::test]
async fn inert_stub_owner_or_group_mismatch_keeps_join_failed_refusal() -> Result<()> {
    let (authority_state, _a) = secure_endpoint_test_state().await?;
    let (joiner_state, _j) = secure_endpoint_test_state().await?;
    let group = hex::encode(blake3::hash(b"1161-stub-mismatch").as_bytes());
    let authority_id = authority_state.agent.agent_id();
    let joiner_hex = hex::encode(joiner_state.agent.agent_id().as_bytes());

    let mut authority = x0x::groups::GroupInfo::with_policy(
        "live".into(),
        String::new(),
        authority_id,
        group.clone(),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    authority.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    let projection = x0x::groups::state_commit::roster_projection(&authority.members_v2);
    let stable = authority.stable_group_id().to_string();
    authority.state_hash = x0x::groups::state_commit::compute_state_hash(
        &stable,
        authority.state_revision,
        authority.prev_state_hash.as_deref(),
        &x0x::groups::state_commit::roster_root_of_projection(&projection),
        &x0x::groups::state_commit::compute_policy_hash(&authority.policy),
        &x0x::groups::state_commit::compute_public_meta_hash(&authority.public_meta()),
        authority.security_binding.as_deref(),
        false,
    );
    authority_state
        .named_groups
        .write()
        .await
        .insert(group.clone(), authority.clone());

    // Stub genesis owner differs from the invite creator.
    let foreign_owner = AgentId([0x42; 32]);
    let mut stub = card_import_stub(foreign_owner, &group, &joiner_hex);
    stub.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
        group.clone(),
        hex::encode(foreign_owner.as_bytes()),
        stub.created_at,
        String::new(),
    ));
    // Re-insert foreign owner as sole admin so the shape stays inert.
    stub.members_v2.clear();
    let foreign_hex = hex::encode(foreign_owner.as_bytes());
    stub.members_v2.insert(
        foreign_hex.clone(),
        x0x::groups::GroupMember::new_admin(foreign_hex, None, stub.created_at),
    );
    assert_eq!(
        classify_not_member_join_row(&stub, &joiner_hex),
        NotMemberJoinRow::InertCardImportStub
    );
    joiner_state
        .named_groups
        .write()
        .await
        .insert(group.clone(), stub);

    let (_invite, link) =
        assemble_signed_v4_invite(&authority_state, &authority, 3_600, None).expect("mint invite");
    let response = join_group_via_invite(
        State(Arc::clone(&joiner_state)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let error = body["error"].as_str().unwrap_or_default();
    assert!(error.contains("fresh invite cannot replace"), "{body}");
    assert!(
        joiner_state.named_groups.read().await.contains_key(&group),
        "mismatch must not clear the stub"
    );
    Ok(())
}

#[tokio::test]
async fn inert_stub_refusal_controls_secret_removed_banned_quarantine_withdrawn_alias_pending(
) -> Result<()> {
    let (joiner_state, _j) = secure_endpoint_test_state().await?;
    let (authority_state, _a) = secure_endpoint_test_state().await?;
    let group = hex::encode(blake3::hash(b"1161-stub-controls").as_bytes());
    let authority_id = authority_state.agent.agent_id();
    let joiner_hex = hex::encode(joiner_state.agent.agent_id().as_bytes());

    let mut authority = x0x::groups::GroupInfo::with_policy(
        "live".into(),
        String::new(),
        authority_id,
        group.clone(),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    authority.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    let projection = x0x::groups::state_commit::roster_projection(&authority.members_v2);
    let stable = authority.stable_group_id().to_string();
    authority.state_hash = x0x::groups::state_commit::compute_state_hash(
        &stable,
        authority.state_revision,
        authority.prev_state_hash.as_deref(),
        &x0x::groups::state_commit::roster_root_of_projection(&projection),
        &x0x::groups::state_commit::compute_policy_hash(&authority.policy),
        &x0x::groups::state_commit::compute_public_meta_hash(&authority.public_meta()),
        authority.security_binding.as_deref(),
        false,
    );
    authority_state
        .named_groups
        .write()
        .await
        .insert(group.clone(), authority.clone());
    let (invite_a, link_a) =
        assemble_signed_v4_invite(&authority_state, &authority, 3_600, None).expect("mint a");
    let (invite_b, link_b) =
        assemble_signed_v4_invite(&authority_state, &authority, 3_600, None).expect("mint b");
    {
        let now_secs = now_millis_u64() / 1_000;
        let mut groups = authority_state.named_groups.write().await;
        let info = groups.get_mut(&group).expect("authority");
        for (inv, link) in [(&invite_a, &link_a), (&invite_b, &link_b)] {
            info.record_issued_invite_v2(
                inv.invite_secret.clone(),
                now_secs.saturating_sub(60),
                now_secs + 3_600,
                x0x::groups::GroupRole::Member,
                None,
                x0x::groups::InviteOrigin::Explicit,
                Some(link.clone()),
            );
        }
    }

    // secret
    {
        let mut stub = card_import_stub(authority_id, &group, &joiner_hex);
        stub.shared_secret = Some(vec![9; 32]);
        joiner_state
            .named_groups
            .write()
            .await
            .insert(group.clone(), stub);
        let response = join_group_via_invite(
            State(Arc::clone(&joiner_state)),
            Json(JoinGroupRequest {
                invite: link_a.clone(),
                display_name: None,
                mode: None,
                expected_owner_user_id: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(joiner_state.named_groups.read().await.contains_key(&group));
    }

    // existing MLS key on the inert stub — refuse without clearing or deleting key
    {
        let stub = card_import_stub(authority_id, &group, &joiner_hex);
        joiner_state
            .named_groups
            .write()
            .await
            .insert(group.clone(), stub);
        let group_bytes = hex::decode(&group).expect("group id hex");
        let mls = x0x::mls::MlsGroup::new(group_bytes, joiner_state.agent.agent_id())
            .await
            .expect("mls group");
        joiner_state
            .mls_groups
            .write()
            .await
            .insert(group.clone(), mls);
        let response = join_group_via_invite(
            State(Arc::clone(&joiner_state)),
            Json(JoinGroupRequest {
                invite: link_a.clone(),
                display_name: None,
                mode: None,
                expected_owner_user_id: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(joiner_state.named_groups.read().await.contains_key(&group));
        assert!(joiner_state.mls_groups.read().await.contains_key(&group));
        joiner_state.mls_groups.write().await.remove(&group);
        joiner_state.named_groups.write().await.remove(&group);
    }

    // removed / banned
    for member_state in [
        x0x::groups::GroupMemberState::Removed,
        x0x::groups::GroupMemberState::Banned,
    ] {
        let mut stub = card_import_stub(authority_id, &group, &joiner_hex);
        stub.add_member(
            joiner_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        stub.members_v2.get_mut(&joiner_hex).expect("seat").state = member_state;
        joiner_state
            .named_groups
            .write()
            .await
            .insert(group.clone(), stub);
        let response = join_group_via_invite(
            State(Arc::clone(&joiner_state)),
            Json(JoinGroupRequest {
                invite: link_a.clone(),
                display_name: None,
                mode: None,
                expected_owner_user_id: None,
            }),
        )
        .await
        .into_response();
        assert_ne!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(joiner_state.named_groups.read().await.contains_key(&group));
    }

    // quarantine
    {
        let mut stub = card_import_stub(authority_id, &group, &joiner_hex);
        let header = stub.terminal_commit_header();
        stub.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision: 1,
            state_hash: stub.state_hash.clone(),
            committed_by: hex::encode(authority_id.as_bytes()),
            observed_at_ms: 1,
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: header.clone(),
                conflicting_commit: header,
                classification: None,
            },
            no_anchor: true,
        });
        joiner_state
            .named_groups
            .write()
            .await
            .insert(group.clone(), stub);
        let response = join_group_via_invite(
            State(Arc::clone(&joiner_state)),
            Json(JoinGroupRequest {
                invite: link_a.clone(),
                display_name: None,
                mode: None,
                expected_owner_user_id: None,
            }),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["reason"], "fork_quarantined");
    }

    // withdrawn
    {
        let mut stub = card_import_stub(authority_id, &group, &joiner_hex);
        stub.withdrawn = true;
        joiner_state
            .named_groups
            .write()
            .await
            .insert(group.clone(), stub);
        let response = join_group_via_invite(
            State(Arc::clone(&joiner_state)),
            Json(JoinGroupRequest {
                invite: link_a.clone(),
                display_name: None,
                mode: None,
                expected_owner_user_id: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    // conflicting same-stable alias
    {
        let stub = card_import_stub(authority_id, &group, &joiner_hex);
        let mut alias = stub.clone();
        alias.mls_group_id = format!("alias{group}");
        joiner_state
            .named_groups
            .write()
            .await
            .insert(group.clone(), stub);
        joiner_state
            .named_groups
            .write()
            .await
            .insert(format!("alias-key-{group}"), alias);
        let response = join_group_via_invite(
            State(Arc::clone(&joiner_state)),
            Json(JoinGroupRequest {
                invite: link_a.clone(),
                display_name: None,
                mode: None,
                expected_owner_user_id: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(joiner_state.named_groups.read().await.contains_key(&group));
        joiner_state.named_groups.write().await.clear();
    }

    // pending: first invite clears stub and arms an attempt; a different
    // invite must 409 join_already_pending without a second clear path.
    {
        joiner_state.named_groups.write().await.insert(
            group.clone(),
            card_import_stub(authority_id, &group, &joiner_hex),
        );
        let first = join_group_via_invite(
            State(Arc::clone(&joiner_state)),
            Json(JoinGroupRequest {
                invite: link_a,
                display_name: None,
                mode: None,
                expected_owner_user_id: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);
        let second = join_group_via_invite(
            State(Arc::clone(&joiner_state)),
            Json(JoinGroupRequest {
                invite: link_b,
                display_name: None,
                mode: None,
                expected_owner_user_id: None,
            }),
        )
        .await
        .into_response();
        let (status, body) = response_json(second).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("join_already_pending")
                || body["reason"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("join_already_pending")
                || body.to_string().contains("join_already_pending"),
            "pending attempt blocks a different invite: {body}"
        );
    }
    Ok(())
}

/// Failed join after stub clear: sign failure installs nothing. Recovery is
/// card re-import (then request_access) or another verified invite.
#[tokio::test]
async fn cleared_stub_sign_failure_leaves_no_row_for_reimport_or_request_access() -> Result<()> {
    let (authority_state, _a) = secure_endpoint_test_state().await?;
    let (joiner_state, _j) = secure_endpoint_test_state().await?;
    let group = hex::encode(blake3::hash(b"1161-stub-signfail").as_bytes());
    let authority_id = authority_state.agent.agent_id();
    let joiner_hex = hex::encode(joiner_state.agent.agent_id().as_bytes());

    let mut authority = x0x::groups::GroupInfo::with_policy(
        "live".into(),
        String::new(),
        authority_id,
        group.clone(),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    authority.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    let projection = x0x::groups::state_commit::roster_projection(&authority.members_v2);
    let stable = authority.stable_group_id().to_string();
    authority.state_hash = x0x::groups::state_commit::compute_state_hash(
        &stable,
        authority.state_revision,
        authority.prev_state_hash.as_deref(),
        &x0x::groups::state_commit::roster_root_of_projection(&projection),
        &x0x::groups::state_commit::compute_policy_hash(&authority.policy),
        &x0x::groups::state_commit::compute_public_meta_hash(&authority.public_meta()),
        authority.security_binding.as_deref(),
        false,
    );
    authority_state
        .named_groups
        .write()
        .await
        .insert(group.clone(), authority.clone());
    joiner_state.named_groups.write().await.insert(
        group.clone(),
        card_import_stub(authority_id, &group, &joiner_hex),
    );

    let (_invite, link) =
        assemble_signed_v4_invite(&authority_state, &authority, 3_600, None).expect("mint");
    let _sign_failure = fail_next_member_joined_sign_for_test(&group, &joiner_hex);
    let response = join_group_via_invite(
        State(Arc::clone(&joiner_state)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !joiner_state.named_groups.read().await.contains_key(&group),
        "cleared stub must not silently remain after a failed fresh join"
    );
    assert!(joiner_state
        .pending_join_attempts
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
    let _ = stable;
    Ok(())
}

#[tokio::test]
async fn inert_stub_survives_disk_reload_then_clears_on_verified_invite() -> Result<()> {
    let (authority_state, _a) = secure_endpoint_test_state().await?;
    let (joiner_state, _j) = secure_endpoint_test_state().await?;
    let group = hex::encode(blake3::hash(b"1161-stub-restart").as_bytes());
    let authority_id = authority_state.agent.agent_id();
    let joiner_hex = hex::encode(joiner_state.agent.agent_id().as_bytes());

    let mut authority = x0x::groups::GroupInfo::with_policy(
        "live".into(),
        String::new(),
        authority_id,
        group.clone(),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    authority.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    let projection = x0x::groups::state_commit::roster_projection(&authority.members_v2);
    let stable = authority.stable_group_id().to_string();
    authority.state_hash = x0x::groups::state_commit::compute_state_hash(
        &stable,
        authority.state_revision,
        authority.prev_state_hash.as_deref(),
        &x0x::groups::state_commit::roster_root_of_projection(&projection),
        &x0x::groups::state_commit::compute_policy_hash(&authority.policy),
        &x0x::groups::state_commit::compute_public_meta_hash(&authority.public_meta()),
        authority.security_binding.as_deref(),
        false,
    );
    authority_state
        .named_groups
        .write()
        .await
        .insert(group.clone(), authority.clone());
    let (_invite, link) =
        assemble_signed_v4_invite(&authority_state, &authority, 3_600, None).expect("mint");

    joiner_state.named_groups.write().await.insert(
        group.clone(),
        card_import_stub(authority_id, &group, &joiner_hex),
    );
    assert!(save_named_groups(&joiner_state).await, "persist stub");
    joiner_state.named_groups.write().await.clear();
    let loaded = load_named_groups(&joiner_state.named_groups_path)
        .await
        .expect("reload stub");
    {
        let mut groups = joiner_state.named_groups.write().await;
        *groups = loaded;
    }
    assert_eq!(
        classify_not_member_join_row(
            joiner_state
                .named_groups
                .read()
                .await
                .get(&group)
                .expect("stub survived reload"),
            &joiner_hex
        ),
        NotMemberJoinRow::InertCardImportStub
    );

    let response = join_group_via_invite(
        State(Arc::clone(&joiner_state)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "post-reload clear+join: {body}");
    assert_eq!(
        body["join_state"].as_str(),
        Some("pending_authority_commit")
    );
    Ok(())
}

/// #1463 / Codex P2: keyed exclusion must be atomic with replacement.
/// Holding `named_groups` write, poll clear to its first wait, insert MLS
/// (as `POST /mls/groups` does without the membership guard), then release:
/// the concurrent keyed object and the inert stub must both survive.
#[tokio::test]
async fn clear_preserves_mls_key_installed_while_waiting_on_named_groups_writer() -> Result<()> {
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    let (state, _dir) = secure_endpoint_test_state().await?;
    let group = hex::encode(blake3::hash(b"1161-stub-concurrent-key").as_bytes());
    let owner = AgentId([0x11; 32]);
    let owner_hex = hex::encode(owner.as_bytes());
    let joiner_hex = hex::encode(AgentId([0x22; 32]).as_bytes());
    state
        .named_groups
        .write()
        .await
        .insert(group.clone(), card_import_stub(owner, &group, &joiner_hex));

    let blocked = state.named_groups.write().await;
    let mut clear = Box::pin(clear_stale_not_member_join_row(
        state.as_ref(),
        &group,
        &joiner_hex,
        &group,
        &owner_hex,
    ));
    poll_fn(|cx| {
        assert!(
            matches!(clear.as_mut().poll(cx), Poll::Pending),
            "clear must wait on the held named_groups writer before keyed recheck"
        );
        Poll::Ready(())
    })
    .await;

    // create_mls_group inserts without taking a group-membership guard.
    let group_bytes = hex::decode(&group).expect("group id hex");
    let mls = x0x::mls::MlsGroup::new(group_bytes, state.agent.agent_id())
        .await
        .expect("mls group");
    state.mls_groups.write().await.insert(group.clone(), mls);
    drop(blocked);

    let outcome = clear.await;
    assert_eq!(
        outcome,
        ClearStaleNotMemberJoinRowResult::RefusedKeyedMaterial,
        "keyed recheck under the write hold must refuse, not clear"
    );
    assert!(
        state.mls_groups.read().await.contains_key(&group),
        "concurrent keyed MLS object was deleted"
    );
    assert!(
        state.named_groups.read().await.contains_key(&group),
        "inert stub must remain when keyed material blocks clear"
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_same_invite_while_pending_keeps_single_attempt() -> Result<()> {
    let (authority_state, _a) = secure_endpoint_test_state().await?;
    let (joiner_state, _j) = secure_endpoint_test_state().await?;
    let group = hex::encode(blake3::hash(b"1161-stub-race").as_bytes());
    let authority_id = authority_state.agent.agent_id();
    let joiner_hex = hex::encode(joiner_state.agent.agent_id().as_bytes());

    let mut authority = x0x::groups::GroupInfo::with_policy(
        "live".into(),
        String::new(),
        authority_id,
        group.clone(),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    authority.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    let projection = x0x::groups::state_commit::roster_projection(&authority.members_v2);
    let stable = authority.stable_group_id().to_string();
    authority.state_hash = x0x::groups::state_commit::compute_state_hash(
        &stable,
        authority.state_revision,
        authority.prev_state_hash.as_deref(),
        &x0x::groups::state_commit::roster_root_of_projection(&projection),
        &x0x::groups::state_commit::compute_policy_hash(&authority.policy),
        &x0x::groups::state_commit::compute_public_meta_hash(&authority.public_meta()),
        authority.security_binding.as_deref(),
        false,
    );
    authority_state
        .named_groups
        .write()
        .await
        .insert(group.clone(), authority.clone());
    joiner_state.named_groups.write().await.insert(
        group.clone(),
        card_import_stub(authority_id, &group, &joiner_hex),
    );

    let (invite, link) =
        assemble_signed_v4_invite(&authority_state, &authority, 3_600, None).expect("mint");
    {
        let now_secs = now_millis_u64() / 1_000;
        let mut groups = authority_state.named_groups.write().await;
        groups
            .get_mut(&group)
            .expect("auth")
            .record_issued_invite_v2(
                invite.invite_secret.clone(),
                now_secs.saturating_sub(60),
                now_secs + 3_600,
                x0x::groups::GroupRole::Member,
                None,
                x0x::groups::InviteOrigin::Explicit,
                Some(link.clone()),
            );
    }

    let first = join_group_via_invite(
        State(Arc::clone(&joiner_state)),
        Json(JoinGroupRequest {
            invite: link.clone(),
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(first.status(), StatusCode::OK);
    let second = join_group_via_invite(
        State(Arc::clone(&joiner_state)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(second).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        joiner_state
            .pending_join_attempts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        1,
        "exactly one attempt owns the join"
    );
    let _ = (stable, joiner_hex);
    Ok(())
}
