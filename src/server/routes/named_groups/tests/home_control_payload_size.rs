use super::*;

/// A socket-free size reproduction using the same signed Home, certificate,
/// owner mandate, state commit, and TreeKEM add material as an admitted seat.
#[tokio::test]
async fn real_home_seat_control_envelopes_exceed_direct_message_limit() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let state = super::super::super::home::tests::owned_state(dir.path(), [0x62; 32]).await?;
    super::super::super::home::provision_home(&state).await;
    let owner = state.agent.identity().user_keypair().expect("owned Home");
    let (_, before) = super::super::super::home::find_home(&state, &owner.user_id())
        .await
        .expect("provisioned Home");
    let group_key = before.mls_group_id.clone();
    let stable_group_id = before.stable_group_id().to_string();
    let authority = state.agent.agent_id();
    let authority_hex = hex::encode(authority.as_bytes());
    let member_kp = x0x::identity::AgentKeypair::generate()?;
    let member = member_kp.agent_id();
    let member_hex = hex::encode(member.as_bytes());
    let cert = x0x::identity::AgentCertificate::issue(owner, &member_kp)?;
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member, &[0x63; 32])?;
    let kp_b64 = BASE64.encode(prepared.key_package_bytes());
    let now_ms = now_millis_u64();
    let mut next = before.clone();
    let group = state
        .treekem_groups
        .read()
        .await
        .get(&group_key)
        .cloned()
        .expect("Home TreeKEM group");
    let mut group = group.lock().await;
    let epoch = group.epoch() + 1;
    next.roster_revision += 1;
    let revision = next.roster_revision;
    next.add_member(
        member_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(authority_hex.clone()),
        None,
    );
    next.set_member_treekem_key_package(&member_hex, kp_b64.clone());
    next.set_member_certificate(&member_hex, cert.clone())
        .expect("owner certificate binds to fresh seat");
    next.secret_epoch = epoch;
    let direct_recovery = NamedGroupMetadataEvent::MemberJoined {
        group_id: group_key.clone(),
        stable_group_id: Some(stable_group_id.clone()),
        member_agent_id: member_hex.clone(),
        member_public_key_b64: String::new(),
        role: x0x::groups::GroupRole::Member,
        display_name: None,
        inviter_agent_id: authority_hex.clone(),
        invite_secret: String::new(),
        ts_ms: now_ms,
        treekem_key_package_b64: Some(kp_b64),
        kem_public_key_b64: None,
        kem_signature_b64: None,
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: None,
        recovery_authority_commit: None,
        signature_b64: String::new(),

        certificate_b64: None,
    };
    next.security_binding = treekem_recovery_security_binding(epoch, &direct_recovery);
    let mandate = mint_owner_mandate_for_seat(
        &state,
        &next,
        epoch,
        &member_hex,
        &authority_hex,
        "",
        Some(&cert),
        now_ms,
    )
    .await
    .expect("owner signs mandate");
    let commit = seal_commit_owner_certified(
        &state,
        &mut next,
        state.agent.identity().agent_keypair(),
        now_ms,
    )
    .await?;
    let out = group.add_member(member, prepared.key_package_bytes())?;
    assert_eq!(group.epoch(), epoch);
    drop(group);
    let member_group = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &out.welcome)?;
    let welcome_ref =
        stage_treekem_welcome(&state, &stable_group_id, &member_hex, out.welcome).await;
    let event = NamedGroupMetadataEvent::MemberAdded {
        group_id: stable_group_id.clone(),
        revision,
        actor: authority_hex.clone(),
        agent_id: member_hex.clone(),
        display_name: None,
        treekem_commit_b64: Some(BASE64.encode(out.commit)),
        treekem_welcome_b64: None,
        welcome_ref: Some(welcome_ref),
        treekem_epoch: Some(epoch),
        treekem_key_package_hash: next
            .members_v2
            .get(&member_hex)
            .and_then(|member| member.treekem_key_package_hash.clone()),
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: Some(BASE64.encode(bincode::serialize(&cert)?)),
        owner_mandate: Some(mandate),
        commit: Some(commit.clone()),
    };
    let event_bytes = serde_json::to_vec(&event)?;
    let event_len = event_bytes.len();
    let pulled_event = super::super::control_blob::socket_free_roundtrip(
        super::super::control_blob::ControlBlobKind::NamedGroupEvent,
        &stable_group_id,
        &authority,
        &authority,
        None,
        event_bytes,
    );
    let first_retained = next.commit_log.first().expect("Home retained commit");
    let from_revision = first_retained.commit.revision - 1;
    let chain = intervening_chain_from(&next, from_revision, commit.revision);
    let head = HeadAttestation::sign(
        &stable_group_id,
        commit.revision - 1,
        commit.prev_state_hash.as_deref().expect("parent hash"),
        &member_hex,
        owner,
    )
    .expect("owner signs head attestation");
    let result = JoinResultMessage::Result {
        event: Box::new(event.clone()),
        chain,
        head_attestation: Some(Box::new(head)),
    };
    let result_len = serde_json::to_vec(&result)?.len();
    let result_bytes = serde_json::to_vec(&result)?;
    let pulled_result = super::super::control_blob::socket_free_roundtrip(
        super::super::control_blob::ControlBlobKind::JoinResult,
        &stable_group_id,
        &authority,
        &member,
        Some("socket-free-attempt"),
        result_bytes.clone(),
    );
    assert_eq!(pulled_result, result_bytes);
    eprintln!(
        "socket-free real Home control sizes: event={event_len} result={result_len} cap={} from_revision={from_revision} chain={}",
        crate::dm::MAX_PAYLOAD_BYTES,
        match &result { JoinResultMessage::Result { chain, .. } => chain.len(), _ => 0 }
    );
    assert!(event_len > crate::dm::MAX_PAYLOAD_BYTES);
    assert!(result_len > crate::dm::MAX_PAYLOAD_BYTES);
    assert_eq!(pulled_event, serde_json::to_vec(&event)?);

    // A second, genuinely remote member can process the owner's next
    // UpdatePath. A copied owner snapshot cannot: TreeKEM correctly refuses
    // to process one's own UpdatePath, which is why the original witness was
    // an invalid apply oracle even though the exact-byte pull succeeded.
    let witness_dir = dir.path().join("witness");
    tokio::fs::create_dir_all(&witness_dir).await?;
    let member_agent = Arc::new(
        Agent::builder()
            .with_machine_key(witness_dir.join("machine.key"))
            .with_agent_key(member_kp)
            .with_agent_cert_path(witness_dir.join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(witness_dir.join("contacts.json"))
            .build()
            .await?,
    );
    let witness = secure_endpoint_test_state_at(&witness_dir, member_agent).await?;
    witness
        .named_groups
        .write()
        .await
        .insert(group_key.clone(), next.clone());
    witness
        .treekem_groups
        .write()
        .await
        .insert(group_key.clone(), Arc::new(Mutex::new(member_group)));

    let second_kp = x0x::identity::AgentKeypair::generate()?;
    let second = second_kp.agent_id();
    let second_hex = hex::encode(second.as_bytes());
    let second_cert = x0x::identity::AgentCertificate::issue(owner, &second_kp)?;
    let second_prepared = x0x::mls::TreeKemMlsGroup::prepare_member(second, &[0x64; 32])?;
    let second_kp_b64 = BASE64.encode(second_prepared.key_package_bytes());
    let mut after = next.clone();
    let second_epoch = epoch + 1;
    after.roster_revision += 1;
    after.add_member(
        second_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(authority_hex.clone()),
        None,
    );
    after.set_member_treekem_key_package(&second_hex, second_kp_b64);
    after
        .set_member_certificate(&second_hex, second_cert.clone())
        .expect("owner certificate binds to second seat");
    after.secret_epoch = second_epoch;
    let second_recovery = NamedGroupMetadataEvent::MemberJoined {
        group_id: group_key.clone(),
        stable_group_id: Some(stable_group_id.clone()),
        member_agent_id: second_hex.clone(),
        member_public_key_b64: String::new(),
        role: x0x::groups::GroupRole::Member,
        display_name: None,
        inviter_agent_id: authority_hex.clone(),
        invite_secret: String::new(),
        ts_ms: now_ms,
        treekem_key_package_b64: Some(BASE64.encode(second_prepared.key_package_bytes())),
        kem_public_key_b64: None,
        kem_signature_b64: None,
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: None,
        recovery_authority_commit: None,
        signature_b64: String::new(),

        certificate_b64: None,
    };
    after.security_binding = treekem_recovery_security_binding(second_epoch, &second_recovery);
    let second_mandate = mint_owner_mandate_for_seat(
        &state,
        &after,
        second_epoch,
        &second_hex,
        &authority_hex,
        "",
        Some(&second_cert),
        now_ms,
    )
    .await
    .expect("owner signs second mandate");
    let second_commit = seal_commit_owner_certified(
        &state,
        &mut after,
        state.agent.identity().agent_keypair(),
        now_ms,
    )
    .await?;
    let owner_group = state
        .treekem_groups
        .read()
        .await
        .get(&group_key)
        .cloned()
        .expect("owner TreeKEM group");
    let second_out = owner_group
        .lock()
        .await
        .add_member(second, second_prepared.key_package_bytes())?;
    let second_welcome_ref =
        stage_treekem_welcome(&state, &stable_group_id, &second_hex, second_out.welcome).await;
    let second_event = NamedGroupMetadataEvent::MemberAdded {
        group_id: stable_group_id.clone(),
        revision: after.roster_revision,
        actor: authority_hex,
        agent_id: second_hex.clone(),
        display_name: None,
        treekem_commit_b64: Some(BASE64.encode(second_out.commit)),
        treekem_welcome_b64: None,
        welcome_ref: Some(second_welcome_ref),
        treekem_epoch: Some(second_epoch),
        treekem_key_package_hash: after
            .members_v2
            .get(&second_hex)
            .and_then(|member| member.treekem_key_package_hash.clone()),
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: Some(BASE64.encode(bincode::serialize(&second_cert)?)),
        owner_mandate: Some(second_mandate),
        commit: Some(second_commit),
    };
    let second_bytes = serde_json::to_vec(&second_event)?;
    let pulled_second = super::super::control_blob::socket_free_roundtrip(
        super::super::control_blob::ControlBlobKind::NamedGroupEvent,
        &stable_group_id,
        &authority,
        &member,
        None,
        second_bytes,
    );
    let applied = apply_named_group_metadata_event(
        &witness,
        serde_json::from_slice(&pulled_second)?,
        authority,
        true,
        None,
    )
    .await;
    assert!(applied.accepted, "retrieved signed Home add must apply");
    let duplicate = apply_named_group_metadata_event(
        &witness,
        serde_json::from_slice(&pulled_second)?,
        authority,
        true,
        None,
    )
    .await;
    assert!(!duplicate.accepted, "duplicate must not apply twice");
    Ok(())
}

/// Shared socket-free scenario: a provisioned Home authority, one real
/// member seat sealed with the joiner's deterministic TreeKEM identity, an
/// oversized inline-welcome `Result` envelope, and a pre-join member state
/// holding a live attempt.
#[allow(dead_code)]
struct BoundJoinerScenario {
    state: std::sync::Arc<crate::server::AppState>,
    joiner: std::sync::Arc<crate::server::AppState>,
    authority: x0x::identity::AgentId,
    member_hex: String,
    group_key: String,
    stable_group_id: String,
    before_roster_revision: u64,
    event: NamedGroupMetadataEvent,
    head_attestation: HeadAttestation,
    chain: Vec<x0x::groups::state_commit::RetainedCommit>,
    key: String,
}

impl BoundJoinerScenario {
    fn result_message(&self) -> JoinResultMessage {
        JoinResultMessage::Result {
            event: Box::new(self.event.clone()),
            chain: self.chain.clone(),
            head_attestation: Some(Box::new(self.head_attestation.clone())),
        }
    }
}

async fn build_bound_joiner_scenario(dir: &std::path::Path) -> Result<BoundJoinerScenario> {
    let state = super::super::super::home::tests::owned_state(dir, [0x65; 32]).await?;
    super::super::super::home::provision_home(&state).await;
    let owner = state.agent.identity().user_keypair().expect("owned Home");
    let (_, before) = super::super::super::home::find_home(&state, &owner.user_id())
        .await
        .expect("provisioned Home");
    let group_key = before.mls_group_id.clone();
    let stable_group_id = before.stable_group_id().to_string();
    let authority = state.agent.agent_id();
    let authority_hex = hex::encode(authority.as_bytes());
    let member_kp = x0x::identity::AgentKeypair::generate()?;
    let member = member_kp.agent_id();
    let member_hex = hex::encode(member.as_bytes());
    let cert = x0x::identity::AgentCertificate::issue(owner, &member_kp)?;
    // The joiner derives its TreeKEM identity deterministically from its
    // agent key and the group id, so the KeyPackage the authority seals the
    // Welcome for must be prepared with that exact seed.
    let joiner_dir = dir.join("joiner");
    tokio::fs::create_dir_all(&joiner_dir).await?;
    let joiner_agent = Arc::new(
        Agent::builder()
            .with_machine_key(joiner_dir.join("machine.key"))
            .with_agent_key(member_kp)
            .with_agent_cert_path(joiner_dir.join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(joiner_dir.join("contacts.json"))
            .build()
            .await?,
    );
    let joiner_seed = agent_treekem_seed(&joiner_agent, &hex::decode(&group_key)?);
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member, &joiner_seed)?;
    let kp_b64 = BASE64.encode(prepared.key_package_bytes());
    let now_ms = now_millis_u64();
    let mut next = before.clone();
    let group = state
        .treekem_groups
        .read()
        .await
        .get(&group_key)
        .cloned()
        .expect("Home TreeKEM group");
    let mut group = group.lock().await;
    let epoch = group.epoch() + 1;
    next.roster_revision += 1;
    let revision = next.roster_revision;
    next.add_member(
        member_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(authority_hex.clone()),
        None,
    );
    next.set_member_treekem_key_package(&member_hex, kp_b64.clone());
    next.set_member_certificate(&member_hex, cert.clone())
        .expect("owner certificate binds to seat");
    next.secret_epoch = epoch;
    let direct_recovery = NamedGroupMetadataEvent::MemberJoined {
        group_id: group_key.clone(),
        stable_group_id: Some(stable_group_id.clone()),
        member_agent_id: member_hex.clone(),
        member_public_key_b64: String::new(),
        role: x0x::groups::GroupRole::Member,
        display_name: None,
        inviter_agent_id: authority_hex.clone(),
        invite_secret: String::new(),
        ts_ms: now_ms,
        treekem_key_package_b64: Some(kp_b64),
        kem_public_key_b64: None,
        kem_signature_b64: None,
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: None,
        recovery_authority_commit: None,
        signature_b64: String::new(),

        certificate_b64: None,
    };
    next.security_binding = treekem_recovery_security_binding(epoch, &direct_recovery);
    let mandate = mint_owner_mandate_for_seat(
        &state,
        &next,
        epoch,
        &member_hex,
        &authority_hex,
        "",
        Some(&cert),
        now_ms,
    )
    .await
    .expect("owner signs mandate");
    let commit = seal_commit_owner_certified(
        &state,
        &mut next,
        state.agent.identity().agent_keypair(),
        now_ms,
    )
    .await?;
    let out = group.add_member(member, prepared.key_package_bytes())?;
    drop(group);
    // INLINE welcome: the joiner consumes its Welcome from the event bytes,
    // so adoption stays socket-free (no welcome fetch transfer).
    let event = NamedGroupMetadataEvent::MemberAdded {
        group_id: stable_group_id.clone(),
        revision,
        actor: authority_hex.clone(),
        agent_id: member_hex.clone(),
        display_name: None,
        treekem_commit_b64: Some(BASE64.encode(out.commit)),
        treekem_welcome_b64: Some(BASE64.encode(out.welcome)),
        welcome_ref: None,
        treekem_epoch: Some(epoch),
        treekem_key_package_hash: next
            .members_v2
            .get(&member_hex)
            .and_then(|member| member.treekem_key_package_hash.clone()),
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: Some(BASE64.encode(bincode::serialize(&cert)?)),
        owner_mandate: Some(mandate),
        commit: Some(commit.clone()),
    };
    assert!(serde_json::to_vec(&event)?.len() > crate::dm::MAX_PAYLOAD_BYTES);
    let first_retained = next.commit_log.first().expect("Home retained commit");
    let chain = intervening_chain_from(&next, first_retained.commit.revision - 1, commit.revision);
    let head = HeadAttestation::sign(
        &stable_group_id,
        commit.revision - 1,
        commit.prev_state_hash.as_deref().expect("parent hash"),
        &member_hex,
        owner,
    )
    .expect("owner signs head attestation");
    // Pre-join member state: the member itself, knowing only the group
    // stub, with a live pending attempt addressed to it.
    let joiner = secure_endpoint_test_state_at(&joiner_dir, joiner_agent).await?;
    joiner
        .named_groups
        .write()
        .await
        .insert(group_key.clone(), before.clone());
    let key = join_result_key(&stable_group_id, &member_hex);
    joiner
        .pending_join_attempts
        .lock()
        .expect("attempt registry")
        .insert(
            key.clone(),
            PendingJoinAttempt {
                attempt_id: "attempt-live".to_string(),
                local_group_key: group_key.clone(),
                invite_fingerprint: "test".to_string(),
                invite_group_id: stable_group_id.clone(),
                inviter_public_key_b64: BASE64.encode(
                    state
                        .agent
                        .identity()
                        .agent_keypair()
                        .public_key()
                        .as_bytes(),
                ),
                stored_resend: None,
                polls: Vec::new(),
                tasks: Vec::new(),
                listener_token: None,
            },
        );
    record_expected_join_result_inviter(&joiner, key.clone(), authority_hex.clone());
    assert!(
        serde_json::to_vec(&JoinResultMessage::Result {
            event: Box::new(event.clone()),
            chain: chain.clone(),
            head_attestation: Some(Box::new(head.clone())),
        })?
        .len()
            > crate::dm::MAX_PAYLOAD_BYTES
    );
    Ok(BoundJoinerScenario {
        state,
        joiner,
        authority,
        member_hex,
        group_key,
        stable_group_id: stable_group_id.clone(),
        before_roster_revision: before.roster_revision,
        event,
        head_attestation: head,
        chain,
        key,
    })
}

/// The bound JoinResult handler path, not just the byte roundtrip: a real
/// 80 KiB-class Result with an INLINE welcome (the legacy field, so no
/// welcome fetch is needed) is adopted by a pre-join member state through
/// `handle_join_result_message_bound` when the bound attempt is current,
/// and rejected — with no adoption, attestation, or attempt-registry
/// corruption — when the bound attempt is stale.
#[tokio::test]
async fn bound_join_result_adopts_when_current_and_rejects_stale_attempt() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let scenario = build_bound_joiner_scenario(dir.path()).await?;
    let BoundJoinerScenario {
        state: _state,
        joiner,
        authority,
        member_hex,
        group_key,
        stable_group_id: _,
        before_roster_revision,
        event,
        head_attestation: _,
        chain: _,
        key,
    } = &scenario;
    let revision = match event {
        NamedGroupMetadataEvent::MemberAdded { revision, .. } => *revision,
        _ => panic!("scenario event is a MemberAdded"),
    };

    // STALE bound attempt: rejected after the membership lock. Nothing may
    // be adopted and no attestation/chain/attempt state may be corrupted.
    super::super::handle_join_result_message_bound(
        joiner,
        authority,
        true,
        scenario.result_message(),
        Some("attempt-dead"),
    )
    .await;
    {
        let groups = joiner.named_groups.read().await;
        let info = groups.get(group_key).expect("stub survives stale reject");
        assert!(
            !info.members_v2.contains_key(member_hex),
            "stale attempt must not seat"
        );
        assert_eq!(
            info.roster_revision, *before_roster_revision,
            "stale attempt must not advance revision"
        );
    }
    assert!(
        joiner
            .pending_join_attempts
            .lock()
            .expect("attempts")
            .get(key)
            .is_some_and(|attempt| attempt.attempt_id == "attempt-live"),
        "live attempt must survive stale rejection"
    );
    let authority_hex = hex::encode(authority.as_bytes());
    assert_eq!(
        expected_join_result_inviter(joiner, key).as_deref(),
        Some(authority_hex.as_str()),
        "expected inviter must survive stale rejection"
    );
    assert!(
        joiner
            .pending_adoption_chains
            .lock()
            .expect("chains")
            .get(key)
            .is_none(),
        "no adoption chain residue after stale reject"
    );
    assert!(
        joiner
            .pending_head_attestations
            .lock()
            .expect("attestations")
            .get(key)
            .is_none(),
        "no attestation residue after stale reject"
    );

    // CURRENT bound attempt: the identical envelope adopts the seat.
    super::super::handle_join_result_message_bound(
        joiner,
        authority,
        true,
        scenario.result_message(),
        Some("attempt-live"),
    )
    .await;
    {
        let groups = joiner.named_groups.read().await;
        let info = groups.get(group_key).expect("group survives adoption");
        let seat = info.members_v2.get(member_hex).expect("member seated");
        assert_eq!(seat.role, x0x::groups::GroupRole::Member);
        assert_eq!(info.roster_revision, revision);
    }
    assert!(
        joiner
            .pending_join_attempts
            .lock()
            .expect("attempts")
            .get(key)
            .is_none(),
        "attempt finalized by adoption"
    );
    assert_eq!(
        expected_join_result_inviter(joiner, key),
        None,
        "inviter expectation cleared on adoption"
    );
    assert!(joiner
        .pending_adoption_chains
        .lock()
        .expect("chains")
        .get(key)
        .is_none());
    assert!(joiner
        .pending_head_attestations
        .lock()
        .expect("attestations")
        .get(key)
        .is_none());
    Ok(())
}

/// Concurrency custody: while a CURRENT bound result is mid-apply with the
/// membership lock held and its chain/attestation context installed, a
/// concurrently delivered STALE bound result must not strip that context,
/// corrupt the attempt registry, or disturb the adoption. This pins the
/// per-joiner processing serialization the handler now enforces.
#[tokio::test]
async fn concurrent_stale_result_cannot_strip_current_adoption_context() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let scenario = build_bound_joiner_scenario(dir.path()).await?;
    let joiner = &scenario.joiner;
    let authority = scenario.authority;
    let member_hex = &scenario.member_hex;
    let group_key = &scenario.group_key;
    let key = &scenario.key;
    let revision = match &scenario.event {
        NamedGroupMetadataEvent::MemberAdded { revision, .. } => *revision,
        _ => panic!("scenario event is a MemberAdded"),
    };

    // Hold the SAME per-group membership lock the apply path takes, so the
    // current result stalls mid-lifecycle with its context installed.
    let membership = group_membership_lock(joiner, group_key).await;
    let _membership_held = membership.lock().await;

    let current = tokio::spawn({
        let joiner = std::sync::Arc::clone(joiner);
        let message = scenario.result_message();
        async move {
            super::super::handle_join_result_message_bound(
                &joiner,
                &authority,
                true,
                message,
                Some("attempt-live"),
            )
            .await;
        }
    });
    // Wait until the current result's context is installed (custody point).
    let custody = tokio::time::timeout(std::time::Duration::from_secs(5), {
        let joiner = std::sync::Arc::clone(joiner);
        let key = key.clone();
        async move {
            loop {
                if joiner
                    .pending_adoption_chains
                    .lock()
                    .expect("chains")
                    .contains_key(&key)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
    })
    .await;
    assert!(
        custody.is_ok(),
        "current result must install its adoption context while blocked on the membership lock"
    );

    let stale = tokio::spawn({
        let joiner = std::sync::Arc::clone(joiner);
        let message = scenario.result_message();
        async move {
            super::super::handle_join_result_message_bound(
                &joiner,
                &authority,
                true,
                message,
                Some("attempt-dead"),
            )
            .await;
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        joiner
            .pending_adoption_chains
            .lock()
            .expect("chains")
            .get(key)
            .is_some(),
        "stale delivery must not strip the current result's installed chain context"
    );
    assert!(
        joiner
            .pending_head_attestations
            .lock()
            .expect("attestations")
            .get(key)
            .is_some(),
        "stale delivery must not strip the current result's installed attestation"
    );

    // Release the membership lock: the current result adopts, the stale one
    // then rejects at its pre-check without touching anything.
    drop(_membership_held);
    current.await.expect("current result task");
    stale.await.expect("stale result task");

    {
        let groups = joiner.named_groups.read().await;
        let info = groups.get(group_key).expect("group survives");
        let seat = info.members_v2.get(member_hex).expect("member seated");
        assert_eq!(seat.role, x0x::groups::GroupRole::Member);
        assert_eq!(info.roster_revision, revision);
    }
    assert!(
        joiner
            .pending_join_attempts
            .lock()
            .expect("attempts")
            .get(key)
            .is_none(),
        "attempt finalized by adoption"
    );
    assert!(joiner
        .pending_adoption_chains
        .lock()
        .expect("chains")
        .get(key)
        .is_none());
    assert!(joiner
        .pending_head_attestations
        .lock()
        .expect("attestations")
        .get(key)
        .is_none());
    Ok(())
}
