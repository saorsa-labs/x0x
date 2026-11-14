//! #1655 (ADR 0110 §3): every TreeKEM catch-up write re-reads the agent
//! revocation immediately before the write, on both paths. Each test
//! lets the handler pass its top-of-handler revocation gate, parks it at
//! the send seam, revokes the peer's AGENT while it is parked, and then
//! releases it. No write may reach the revoked agent.
//!
//! - Response path (red on main, green with the fix): a truncated page
//!   that moves the cursor makes the handler ask its sender for the next
//!   page. The ask now re-reads the revocation before the write.
//! - Request path (regression pin): the page serve. Its write already
//!   re-reads the full ladder at the machine-addressed send (#1664); the
//!   #1664 test pins the MACHINE half, and this test pins the AGENT half.

use super::*;
use x0x::identity::AgentKeypair;

/// Insert a verified self-revocation of `subject`'s agent (the #1577
/// fabric).
async fn revoke_agent(state: &AppState, subject: &AgentKeypair) {
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(subject.agent_id()),
        subject.public_key(),
        subject.secret_key(),
        now_millis_u64() / 1_000,
        Some("test".to_string()),
    )
    .expect("sign agent revocation");
    let revocation_set = state.agent.revocation_set();
    let mut set = revocation_set.write().await;
    assert!(set
        .verify_and_insert(record, None)
        .expect("agent self-revocation verifies"));
    assert!(set.is_agent_revoked(&subject.agent_id()));
    assert!(!set.revocation_resync_required());
}

/// The page-request and page-serve decisions the test recorders saw
/// (the `catchup_page_force_ok` stand-in write and the serve decision
/// share this recorder).
fn recorded_catchup_writes(state: &AppState) -> usize {
    state
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .len()
}

/// Every machine-addressed data reply that passed every gate and left.
fn machine_reply_egress(state: &AppState) -> Vec<(MachineId, Vec<u8>)> {
    state
        .agent
        .machine_reply_egress
        .lock()
        .expect("machine reply egress recorder")
        .clone()
}

/// Wait until the armed pause is reached by the parked task.
async fn wait_reached(pause: &detached_send_test_seam::ArmedSendPause, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !pause.reached() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the parked {what} never reached its send"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Response path: the sender of a truncated page passes the response
/// gate, its page applies and moves the cursor, and the handler asks it
/// for the next page. The sender's agent is revoked while that ask is
/// parked at its send. On main the ask still goes out to the revoked
/// agent; with the fix it is withheld.
#[tokio::test]
async fn a_next_page_ask_to_a_sender_revoked_mid_handler_is_not_sent() -> Result<()> {
    let group_id = "5a".repeat(32);
    let (mut state, _dir) = secure_endpoint_test_state().await?;
    super::super::revocation_eviction::zero_restart_wait_for_test(&mut state);
    let admin_id = state.agent.agent_id();
    let group_id_bytes = hex::decode(&group_id)?;
    let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let mut admin_group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, admin_id, &seed)?;
    let member_kp = AgentKeypair::generate()?;
    let member_id = member_kp.agent_id();
    let member_hex = hex::encode(member_id.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_id, &[9u8; 32])?;
    let kp_bytes = prepared.key_package_bytes().to_vec();
    let added = admin_group.add_member(member_id, &kp_bytes)?;
    let _leaver_group = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome)?;
    let epoch_before = admin_group.epoch();

    let mut info = x0x::groups::GroupInfo::new(
        "issue1655-response".to_string(),
        String::new(),
        admin_id,
        group_id.clone(),
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.add_member(
        member_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(hex::encode(admin_id.as_bytes())),
        None,
    );
    info.set_member_treekem_key_package(
        &member_hex,
        base64::engine::general_purpose::STANDARD.encode(&kp_bytes),
    );
    info.secret_epoch = epoch_before;
    info.security_binding = Some(format!("treekem:epoch={epoch_before}"));
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    state.treekem_groups.write().await.insert(
        group_id.clone(),
        Arc::new(tokio::sync::Mutex::new(admin_group)),
    );

    // The member's linked self-leave (the #1685 progressing-page shape):
    // it applies, so the cursor moves and the handler asks for the next
    // page.
    let mut leaving = {
        let groups = state.named_groups.read().await;
        groups.get(&group_id).cloned().expect("group")
    };
    leaving.roster_revision = leaving.roster_revision.saturating_add(1);
    let revision = leaving.roster_revision;
    leaving.remove_member(&member_hex, Some(member_hex.clone()));
    let commit = leaving.seal_commit(&member_kp, now_millis_u64())?;
    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: group_id.clone(),
        revision,
        actor: member_hex.clone(),
        agent_id: member_hex,
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    };
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let pause = detached_send_test_seam::arm(&format!("treekem-catchup-page:{group_id}"));
    let parked_state = Arc::clone(&state);
    let parked_group = group_id.clone();
    let handler = tokio::spawn(async move {
        handle_treekem_catchup_response(
            &parked_state,
            &member_id,
            &MachineId([0x16; 32]),
            true,
            TreeKemCatchupResponse {
                message_type: "treekem_catchup_response".to_string(),
                group_id: parked_group,
                events: vec![event],
                truncated: true,
                responder_state_hash: Some("next-head".to_string()),
                responder_state_revision: None,
            },
        )
        .await;
    });
    // The handler passed its top gate (the agent was clean), applied the
    // page and parked at the next-page ask.
    wait_reached(&pause, "next-page ask").await;
    assert_eq!(
        recorded_catchup_writes(&state),
        0,
        "nothing was written before the park"
    );
    revoke_agent(&state, &member_kp).await;
    drop(pause);
    handler.await.expect("the parked handler completes");

    assert_eq!(
        recorded_catchup_writes(&state),
        0,
        "the next-page ask is not written to an agent revoked after the handler's top gate"
    );
    Ok(())
}

/// Request path: the requester passes the top-of-handler ladder and the
/// page serve parks at its send. The requester's AGENT is revoked while
/// it is parked. The released send writes nothing to it. CONTROL: a
/// clean requester under the same transport script gets its page.
#[tokio::test]
async fn a_page_serve_to_a_requester_revoked_mid_handler_writes_nothing() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "5b".repeat(32);
    let clean = AgentKeypair::generate()?;
    let revoked = AgentKeypair::generate()?;
    let admin = state.agent.agent_id();
    let mut info = x0x::groups::GroupInfo::new(
        "issue1655-request".to_string(),
        String::new(),
        admin,
        group_id.clone(),
    );
    for member in [&clean, &revoked] {
        info.add_member(
            hex::encode(member.agent_id().as_bytes()),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(admin.as_bytes())),
            None,
        );
    }
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    let clean_device = x0x::identity::MachineKeypair::generate()?.machine_id();
    let revoked_device = x0x::identity::MachineKeypair::generate()?.machine_id();
    state.agent.script_pinned_standin_transport_for_testing(
        x0x::PinnedTransportScript::connected_only(&[clean_device, revoked_device], false),
    );

    let request = |requester: &AgentId| TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_id.clone(),
        requester_agent_id: hex::encode(requester.as_bytes()),
        from_revision: 0,
        from_treekem_epoch: 0,
        current_state_hash: String::new(),
        missing_prev_state_hash: None,
        target_member_id: None,
        limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
    };

    // CONTROL: the clean requester's page leaves for its machine.
    handle_treekem_catchup_request(
        &state,
        &clean.agent_id(),
        &clean_device,
        true,
        request(&clean.agent_id()),
    )
    .await;
    assert!(
        machine_reply_egress(&state)
            .iter()
            .any(|(machine, _)| *machine == clean_device),
        "CONTROL: a clean requester's page leaves for its machine"
    );

    let revoked_hex = hex::encode(revoked.agent_id().as_bytes());
    let pause = detached_send_test_seam::arm(&format!("treekem-catchup-serve:{revoked_hex}"));
    let parked_state = Arc::clone(&state);
    let parked_agent = revoked.agent_id();
    let parked_request = request(&parked_agent);
    let serve = tokio::spawn(async move {
        handle_treekem_catchup_request(
            &parked_state,
            &parked_agent,
            &revoked_device,
            true,
            parked_request,
        )
        .await;
    });
    wait_reached(&pause, "page serve").await;
    assert_eq!(
        recorded_catchup_writes(&state),
        2,
        "the page decision was made while the requester was clean"
    );
    revoke_agent(&state, &revoked).await;
    drop(pause);
    serve.await.expect("the parked serve completes");
    assert!(
        !machine_reply_egress(&state)
            .iter()
            .any(|(machine, _)| *machine == revoked_device),
        "the released page write is closed by the agent revocation that landed while it was parked"
    );
    Ok(())
}
