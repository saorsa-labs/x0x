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
    let (status, Json(body)) = row.refusal_response().expect("failed join must refuse");
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["ok"], false);
    assert_eq!(body.as_object().expect("error object").len(), 2);
    let error = body["error"].as_str().expect("existing error field");
    assert!(error.contains("join failed"));
    assert!(error.contains("authority device"));
    assert!(error.contains("fresh invite"));
    assert_eq!(serde_json::to_value(&info).expect("snapshot"), before);
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
        assert!(classified.refusal_response().is_none());
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
    let (status, Json(body)) = quarantined.refusal_response().expect("quarantine refuses");
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
    assert!(remnant.refusal_response().is_none());

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
