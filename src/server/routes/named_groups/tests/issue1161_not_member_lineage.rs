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
    (info, joiner)
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

/// Card-import-shaped lineage-free stub (RequestAccess): request access,
/// admin approve, requester is seated. Invite join remains refused for this
/// shape; seating comes from the existing join-request path only.
#[tokio::test]
async fn lineage_free_request_access_stub_seats_after_request_and_approve() -> Result<()> {
    let admin_kp = crate::identity::AgentKeypair::generate()?;
    let admin_id = admin_kp.agent_id();
    let admin_hex = hex::encode(admin_id.as_bytes());

    let (requester_state, _req_dir) = secure_endpoint_test_state().await?;
    let (admin_state, _admin_dir) = secure_endpoint_test_state_with_key(admin_kp).await?;
    let requester_hex = hex::encode(requester_state.agent.agent_id().as_bytes());
    let requester_kp = requester_state.agent.identity().agent_keypair();

    let group_id = "1161reqaccess".repeat(2); // 32 hex-ish chars
    let group_id = hex::encode(blake3::hash(group_id.as_bytes()).as_bytes());

    // Requester-side card-import stub: authority seated, importer not a member,
    // invite_lineage absent, admission request_access (GSS plane from with_policy).
    let mut stub = x0x::groups::GroupInfo::with_policy(
        "issue1161 request-access stub".into(),
        String::new(),
        admin_id,
        group_id.clone(),
        x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
    );
    stub.members_v2.clear();
    stub.members_v2.insert(
        admin_hex.clone(),
        x0x::groups::GroupMember::new_admin(admin_hex.clone(), None, stub.created_at),
    );
    stub.shared_secret = None;
    stub.secret_epoch = 0;
    assert!(stub.invite_lineage.is_none());
    assert!(!stub.members_v2.contains_key(&requester_hex));
    assert_eq!(
        classify_not_member_join_row(&stub, &requester_hex),
        NotMemberJoinRow::JoinFailed
    );
    requester_state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), stub);

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
    let pending = {
        let groups = requester_state.named_groups.read().await;
        groups
            .get(&group_id)
            .and_then(|g| g.join_requests.get(&request_id))
            .cloned()
            .expect("pending request on requester stub")
    };

    // Admin holds the live group and the pending request, then approves.
    let mut admin_info = x0x::groups::GroupInfo::with_policy(
        "issue1161 request-access live".into(),
        String::new(),
        admin_id,
        group_id.clone(),
        x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
    );
    admin_info.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    admin_info.join_requests.insert(request_id.clone(), pending);
    admin_info.recompute_state_hash();
    admin_state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), admin_info);

    adr0028_direct_controls::offer_predecessor_obligation_via_real_path(
        &admin_state,
        &group_id,
        &request_id,
        requester_kp,
    )
    .await;

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

    let groups = admin_state.named_groups.read().await;
    let seated = groups.get(&group_id).expect("admin group");
    assert!(
        seated.has_active_member(&requester_hex),
        "verified JoinRequestApproved seating must place the requester on the roster"
    );
    Ok(())
}
