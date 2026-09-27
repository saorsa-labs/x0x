//! #946 intent tests: the group-scoped certificate fetch that lets an
//! admin seal while a digest-only member's certificate owner is offline,
//! and the deadline that keeps the resulting refusal retryable.

use super::*;

fn seat_cert_digest_of(cert: &x0x::identity::AgentCertificate) -> String {
    let bytes = bincode::serialize(cert).unwrap_or_else(|_| cert.agent_public_key().to_vec());
    hex::encode(blake3::hash(&bytes).as_bytes())
}

fn digest_arr(digest_hex: &str) -> [u8; 32] {
    <[u8; 32]>::try_from(hex::decode(digest_hex).expect("digest hex")).expect("32-byte digest")
}

/// An OwnerCertified group whose roster holds the LOCAL agent (admin) and
/// `remote_hex` DIGEST-ONLY — the R17 shape. The group is stored under a
/// local map key (`local-…`) that differs from its stable id (the genesis
/// id), so every stable-id-keyed lookup is exercised across spellings.
async fn r17_fixture(
    state: &AppState,
    owner: &x0x::identity::UserKeypair,
    remote_hex: &str,
    remote_digest: &str,
) -> String {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let mut info = x0x::groups::GroupInfo::with_policy(
        "r17-v2".to_string(),
        String::new(),
        state.agent.agent_id(),
        format!("r17v2-{remote_hex}"),
        x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
    );
    info.policy.admission = x0x::groups::GroupAdmission::OwnerCertified(owner.user_id());
    info.metadata_topic = format!("x0x/group/r17v2-{remote_hex}");
    info.members_v2.clear();
    // The local admin's seat. Tests that need a clean local seat install
    // an owner-issued certificate with `install_owner_issued_local_cert`.
    info.add_member(local_hex, x0x::groups::GroupRole::Admin, None, None);
    info.add_member(
        remote_hex.to_string(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    if let Some(seat) = info.members_v2.get_mut(remote_hex) {
        seat.certificate = None;
        seat.certificate_digest = Some(remote_digest.to_string());
    }
    let group_key = format!("local-{remote_hex}");
    assert_ne!(group_key, info.stable_group_id());
    state
        .named_groups
        .write()
        .await
        .insert(group_key.clone(), info);
    group_key
}

/// Give the local admin an owner-issued certificate on its seat AND in the
/// discovery cache, so the seal's evidence ladder rates the local agent
/// Clean (the state's own identity certificate is self-issued).
async fn install_owner_issued_local_cert(
    state: &AppState,
    owner: &x0x::identity::UserKeypair,
    group_key: &str,
) {
    let local_kp = state.agent.identity().agent_keypair();
    let local_cert = x0x::identity::AgentCertificate::issue(owner, local_kp).expect("local cert");
    {
        let mut groups = state.named_groups.write().await;
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let info = groups.get_mut(group_key).expect("fixture");
        if let Some(seat) = info.members_v2.get_mut(&local_hex) {
            seat.certificate = Some(local_cert.clone());
            seat.certificate_digest = Some(seat_cert_digest_of(&local_cert));
        }
    }
    install_discovery_cert(state, &state.agent, &local_cert).await;
}

/// Record `cert` as `subject`'s discovered certificate in `state`'s
/// discovery cache (the seal's evidence ladder reads it).
async fn install_discovery_cert(
    state: &AppState,
    subject: &Agent,
    cert: &x0x::identity::AgentCertificate,
) {
    state.agent.identity_discovery_cache().write().await.insert(
        subject.agent_id(),
        x0x::DiscoveredAgent {
            self_name: None,
            agent_id: subject.agent_id(),
            machine_id: subject.machine_id(),
            user_id: cert.user_id().ok(),
            addresses: Vec::new(),
            announced_at: 0,
            last_seen: 0,
            machine_public_key: Vec::new(),
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            cert_not_after: cert.not_after(),
            agent_certificate: Some(cert.clone()),
            agent_public_key: subject
                .identity()
                .agent_keypair()
                .public_key()
                .as_bytes()
                .to_vec(),
            cert_digest: None,
        },
    );
}

async fn cache_pair(
    state: &AppState,
    user: Option<x0x::identity::UserId>,
    cert: &x0x::identity::AgentCertificate,
) {
    let pair = (user, Some(cert.clone()));
    let pair_digest = x0x::announce_v3::cert_digest(&pair.0, &pair.1);
    state
        .agent
        .announce_blob_cache
        .insert_verified(x0x::announce_blob::CachedBlob {
            digest: pair_digest,
            payload_version: 1,
            user_id: pair.0,
            agent_certificate: pair.1,
            fetched_at_unix: 0,
        })
        .await;
}

fn member_joined(group_key: &str, member_hex: &str, inviter_hex: &str) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::MemberJoined {
        group_id: group_key.to_string(),
        stable_group_id: None,
        member_agent_id: member_hex.to_string(),
        member_public_key_b64: String::new(),
        role: x0x::groups::GroupRole::Member,
        display_name: None,
        inviter_agent_id: inviter_hex.to_string(),
        invite_secret: String::new(),
        ts_ms: 1,
        treekem_key_package_b64: None,
        signature_b64: String::new(),
        certificate_b64: None,
        kem_public_key_b64: None,
        kem_signature_b64: None,
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: None,
        recovery_authority_commit: None,
    }
}

fn pending_error(group_key: &str, pending_hex: &str) -> x0x::groups::state_commit::ApplyError {
    x0x::groups::state_commit::ApplyError::OwnerCertMemberPending {
        group_id: group_key.to_string(),
        members: vec![pending_hex.to_string()],
    }
}

fn certificate_refusal_staged(state: &AppState) -> bool {
    state
        .pending_join_refusals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .values()
        .any(|pending| pending.receipt.reason == JoinRefusalReason::CertificateEvidenceUnavailable)
}

fn stamp_for(
    state: &AppState,
    stable_group_id: &str,
    member_hex: &str,
) -> Option<CertEvidenceStamp> {
    state
        .cert_unresolvable_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&seat_cert_fetch::cert_evidence_stamp_key(
            stable_group_id,
            member_hex,
        ))
        .cloned()
}

async fn stable_id_of_group(state: &AppState, group_key: &str) -> String {
    state
        .named_groups
        .read()
        .await
        .get(group_key)
        .expect("fixture")
        .stable_group_id()
        .to_string()
}

/// THE R17 CASE across TWO daemons. Admin A holds member M's seat
/// digest-only and has NOTHING cached for it; M's owner is offline. Member
/// B holds the verified owner-issued (owner, M) pair. A's first seal
/// refuses and publishes a group-scoped request; B's REAL responder
/// answers with B's cached pair; A's REAL response branch hydrates the
/// seat durably; A's second seal succeeds. A's cache never holds the pair,
/// so the hydrate can only have come through B's responder — breaking that
/// branch fails the hydration assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_daemon_admin_seals_from_a_members_responder() -> Result<()> {
    let plane = format!("r17v2-two-{}", rand::random::<u32>());
    let (a, _a_dir) = networked_test_state(&plane).await?;
    let (b, _b_dir) = networked_test_state(&plane).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    // M: never started — its owner is offline.
    let m_kp = x0x::identity::AgentKeypair::generate().expect("member key");
    let m_cert = x0x::identity::AgentCertificate::issue(&owner, &m_kp).expect("member cert");
    let m_hex = hex::encode(m_kp.agent_id().as_bytes());
    let m_digest = seat_cert_digest_of(&m_cert);
    let group_key = r17_fixture(&a, &owner, &m_hex, &m_digest).await;
    install_owner_issued_local_cert(&a, &owner, &group_key).await;
    // B: an ACTIVE member with an owner-issued embedded certificate.
    let b_hex = hex::encode(b.agent.agent_id().as_bytes());
    let b_cert = x0x::identity::AgentCertificate::issue(&owner, b.agent.identity().agent_keypair())
        .expect("b cert");
    {
        let mut groups = a.named_groups.write().await;
        let info = groups.get_mut(&group_key).expect("fixture");
        info.add_member(b_hex.clone(), x0x::groups::GroupRole::Member, None, None);
        let seat = info.members_v2.get_mut(&b_hex).expect("b seat");
        seat.certificate = Some(b_cert.clone());
        seat.certificate_digest = Some(seat_cert_digest_of(&b_cert));
    }
    // Both daemons hold the same group (same stable id, same topic).
    let shared = a
        .named_groups
        .read()
        .await
        .get(&group_key)
        .expect("fixture")
        .clone();
    b.named_groups
        .write()
        .await
        .insert(group_key.clone(), shared.clone());
    let stable_group_id = shared.stable_group_id().to_string();
    assert_ne!(
        stable_group_id, group_key,
        "the map key and stable id must differ so the stamp key spelling is exercised"
    );
    // The verified pair lives ONLY in B's cache.
    cache_pair(&b, Some(owner.user_id()), &m_cert).await;
    let m_digest_arr = digest_arr(&m_digest);
    assert!(
        a.agent
            .announce_blob_cache
            .find_by_cert_digest(&m_digest_arr)
            .await
            .is_none(),
        "admin A starts with an EMPTY cache for M's certificate"
    );
    assert!(
        b.agent
            .announce_blob_cache
            .find_by_cert_digest(&m_digest_arr)
            .await
            .is_some(),
        "member B holds the verified pair"
    );

    // One pump per daemon on its own subscription, routing exactly as the
    // production metadata listener does (real sender + verified flag).
    let topic = shared.metadata_topic.clone();
    let mut a_sub = a
        .agent
        .pubsub()
        .expect("a gossip")
        .subscribe(topic.clone())
        .await;
    let mut b_sub = b.agent.pubsub().expect("b gossip").subscribe(topic).await;
    wait_connected(&a.agent, &b.agent).await?;
    // Eager-set refresh is a 1s tick (see tests/gossip_plane_isolation.rs).
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let b_state = Arc::clone(&b);
    let b_key = group_key.clone();
    let b_pump = tokio::spawn(async move {
        while let Some(msg) = b_sub.recv().await {
            if let Some(rest) = msg.payload.strip_prefix(GROUP_CERT_FETCH_DOMAIN) {
                handle_group_cert_fetch_request(
                    &b_state,
                    rest,
                    msg.sender.as_ref(),
                    msg.verified,
                    &b_key,
                )
                .await;
            }
        }
    });
    let a_state = Arc::clone(&a);
    let a_key = group_key.clone();
    let a_pump = tokio::spawn(async move {
        while let Some(msg) = a_sub.recv().await {
            if let Some(rest) = msg.payload.strip_prefix(GROUP_CERT_FETCH_RESPONSE_DOMAIN) {
                handle_group_cert_fetch_response(&a_state, rest, msg.verified, &a_key).await;
            }
        }
    });

    // An open refusal window on A (a joiner blocked by M's seat), keyed by
    // the STABLE id. The response hydrate must clear it.
    assert!(!cert_evidence_deadline_elapsed(
        &a,
        &stable_group_id,
        "joiner",
        "attempt-1"
    ));
    assert!(stamp_for(&a, &stable_group_id, "joiner").is_some());

    // Seal #1: refuses (M is digest-only) and publishes the request.
    let signing_kp = a.agent.identity().agent_keypair();
    let mut first = shared.clone();
    let err = seal_commit_owner_certified(&a, &mut first, signing_kp, now_millis_u64())
        .await
        .expect_err("first seal: M's certificate is only in B's cache");
    assert!(
        matches!(
            &err,
            x0x::groups::state_commit::ApplyError::OwnerCertMemberPending { members, .. }
                if members.iter().any(|m| m == &m_hex)
        ),
        "{err}"
    );

    // A's durable seat hydrates via B's responder → A's response branch.
    let hydrated = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let done = a
                .named_groups
                .read()
                .await
                .get(&group_key)
                .and_then(|info| info.members_v2.get(&m_hex))
                .is_some_and(|seat| seat.certificate.is_some());
            if done {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .is_ok();
    assert!(
        hydrated,
        "A's digest-only seat must hydrate from B's group-scoped responder"
    );
    assert!(
        a.agent
            .announce_blob_cache
            .find_by_cert_digest(&m_digest_arr)
            .await
            .is_none(),
        "the hydrate came through the response branch, not A's cache"
    );
    // The in-memory seat is visible before the persist returns Durable,
    // and the clear runs after it, so poll for the clear.
    let window_cleared = tokio::time::timeout(Duration::from_secs(5), async {
        while stamp_for(&a, &stable_group_id, "joiner").is_some() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok();
    assert!(
        window_cleared,
        "the response hydrate clears the stable-id-keyed refusal window"
    );

    // Seal #2 (the joiner's retry re-drives it): succeeds. B announces its
    // harness-issued identity, not the owner-issued certificate on its
    // seat, so A's discovery entry for B is set to what A holds for a Home
    // member — B's owner-issued certificate — immediately before sealing.
    install_discovery_cert(&a, &b.agent, &b_cert).await;
    let mut second = a
        .named_groups
        .read()
        .await
        .get(&group_key)
        .expect("fixture")
        .clone();
    let commit = seal_commit_owner_certified(&a, &mut second, signing_kp, now_millis_u64())
        .await
        .expect("the admin seals while M's owner is offline");
    assert!(!commit.roster_root.is_empty());
    a_pump.abort();
    b_pump.abort();
    a.agent.shutdown().await;
    b.agent.shutdown().await;
    Ok(())
}

/// A cached pair whose user is NOT the group owner is never served: the
/// responder's owner-user check refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn responder_refuses_a_wrong_user_pair() -> Result<()> {
    let plane = format!("r17v2-b-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let remote_kp = x0x::identity::AgentKeypair::generate().expect("remote key");
    let wrong_user = x0x::identity::UserKeypair::generate().expect("wrong user");
    let remote_cert =
        x0x::identity::AgentCertificate::issue(&wrong_user, &remote_kp).expect("remote cert");
    let remote_hex = hex::encode(remote_kp.agent_id().as_bytes());
    let remote_digest = seat_cert_digest_of(&remote_cert);
    // The cache holds the WRONG-USER pair (digest matches the seat, the
    // agent binds, the user does not).
    cache_pair(&state, Some(wrong_user.user_id()), &remote_cert).await;
    let group_key = r17_fixture(&state, &owner, &remote_hex, &remote_digest).await;
    let request = serde_json::to_vec(&seat_cert_fetch::GroupCertFetchRequest {
        group_id: group_key.clone(),
        cert_digest: remote_digest.clone(),
        requester: hex::encode(state.agent.agent_id().as_bytes()),
    })
    .expect("request json");
    assert!(
        !seat_cert_fetch::handle_group_cert_fetch_request(
            &state,
            &request,
            Some(&state.agent.agent_id()),
            true,
            &group_key,
        )
        .await,
        "the responder refuses a wrong-user pair"
    );
    state.agent.shutdown().await;
    Ok(())
}

/// Requester side: a response whose certificate hashes to the seat's
/// committed digest and binds the seat's agent, but was issued by a user
/// who is NOT the group owner, is rejected — the seat stays digest-only and
/// nothing is cached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requester_rejects_a_wrong_user_response() -> Result<()> {
    let plane = format!("r17v2-f-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let wrong_user = x0x::identity::UserKeypair::generate().expect("wrong user");
    let remote_kp = x0x::identity::AgentKeypair::generate().expect("remote key");
    let remote_cert =
        x0x::identity::AgentCertificate::issue(&wrong_user, &remote_kp).expect("remote cert");
    let remote_hex = hex::encode(remote_kp.agent_id().as_bytes());
    let remote_digest = seat_cert_digest_of(&remote_cert);
    let group_key = r17_fixture(&state, &owner, &remote_hex, &remote_digest).await;
    let stable_group_id = stable_id_of_group(&state, &group_key).await;
    // This node asked for the digest (the response is not unsolicited).
    state
        .cert_fetch_requested
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(remote_digest.clone(), std::time::Instant::now());
    use base64::Engine as _;
    let response = serde_json::to_vec(&seat_cert_fetch::GroupCertFetchResponse {
        group_id: stable_group_id,
        cert_digest: remote_digest.clone(),
        cert_json_b64: base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&remote_cert).expect("cert json")),
    })
    .expect("response json");
    assert!(
        !handle_group_cert_fetch_response(&state, &response, true, &group_key).await,
        "a non-owner-issued certificate is rejected"
    );
    let still_digest_only = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .and_then(|info| info.members_v2.get(&remote_hex))
        .is_some_and(|seat| seat.certificate.is_none());
    assert!(still_digest_only, "the seat stays digest-only");
    assert!(
        state
            .agent
            .announce_blob_cache
            .find_by_cert_digest(&digest_arr(&remote_digest))
            .await
            .is_none(),
        "the rejected pair is not cached"
    );
    state.agent.shutdown().await;
    Ok(())
}

/// Before the deadline, a certificate-unobtainable refusal of a real
/// MemberJoined attempt stages NOTHING (the joiner keeps retrying) but does
/// open a window. Deleting the deadline check stages the typed refusal
/// here and fails this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusal_before_the_deadline_stays_retryable() -> Result<()> {
    let plane = format!("r17v2-g-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let remote_kp = x0x::identity::AgentKeypair::generate().expect("remote key");
    let remote_cert =
        x0x::identity::AgentCertificate::issue(&owner, &remote_kp).expect("remote cert");
    let remote_hex = hex::encode(remote_kp.agent_id().as_bytes());
    let group_key = r17_fixture(
        &state,
        &owner,
        &remote_hex,
        &seat_cert_digest_of(&remote_cert),
    )
    .await;
    let stable_group_id = stable_id_of_group(&state, &group_key).await;
    let joiner = hex::encode(
        x0x::identity::AgentKeypair::generate()
            .expect("joiner key")
            .agent_id()
            .as_bytes(),
    );
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    stage_refusal_if_certificates_unobtainable(
        &state,
        &group_key,
        &joiner,
        &member_joined(&group_key, &joiner, &local_hex),
        &pending_error(&group_key, &remote_hex),
    )
    .await;
    assert!(
        !certificate_refusal_staged(&state),
        "no typed refusal before the 10-minute deadline"
    );
    assert!(
        stamp_for(&state, &stable_group_id, &joiner).is_some(),
        "the refusal opened a window under the stable id"
    );
    state.agent.shutdown().await;
    Ok(())
}

/// After the deadline (a window backdated to 11 minutes of continuous
/// refusals for the same attempt), the same refusal DOES stage the typed
/// terminal outcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_refusal_after_the_deadline() -> Result<()> {
    let plane = format!("r17v2-c-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let remote_kp = x0x::identity::AgentKeypair::generate().expect("remote key");
    let remote_cert =
        x0x::identity::AgentCertificate::issue(&owner, &remote_kp).expect("remote cert");
    let remote_hex = hex::encode(remote_kp.agent_id().as_bytes());
    let group_key = r17_fixture(
        &state,
        &owner,
        &remote_hex,
        &seat_cert_digest_of(&remote_cert),
    )
    .await;
    let stable_group_id = stable_id_of_group(&state, &group_key).await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let event = member_joined(&group_key, &remote_hex, &local_hex);
    let attempt_id = member_joined_event_attempt_id(&event).expect("attempt id");
    let now = now_millis_u64();
    state
        .cert_unresolvable_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(
            seat_cert_fetch::cert_evidence_stamp_key(&stable_group_id, &remote_hex),
            CertEvidenceStamp {
                first_ms: now.saturating_sub(11 * 60_000),
                last_ms: now.saturating_sub(60_000),
                attempt_id,
            },
        );
    stage_refusal_if_certificates_unobtainable(
        &state,
        &group_key,
        &remote_hex,
        &event,
        &pending_error(&group_key, &remote_hex),
    )
    .await;
    assert!(
        certificate_refusal_staged(&state),
        "the typed refusal IS staged after the deadline"
    );
    state.agent.shutdown().await;
    Ok(())
}

/// RETRYABLE-THEN-SUCCESS: a joiner's refusal window has run 11 minutes;
/// then a seal succeeds (the certificate reached the local cache). The
/// success must end the window, so the joiner's next refusal starts a
/// FRESH window and stages nothing. Without the clear on seal success the
/// backdated window would stage the terminal refusal and fail this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seal_success_resets_the_refusal_window() -> Result<()> {
    let plane = format!("r17v2-d-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let remote_kp = x0x::identity::AgentKeypair::generate().expect("remote key");
    let remote_cert =
        x0x::identity::AgentCertificate::issue(&owner, &remote_kp).expect("remote cert");
    let remote_hex = hex::encode(remote_kp.agent_id().as_bytes());
    let group_key = r17_fixture(
        &state,
        &owner,
        &remote_hex,
        &seat_cert_digest_of(&remote_cert),
    )
    .await;
    install_owner_issued_local_cert(&state, &owner, &group_key).await;
    let stable_group_id = stable_id_of_group(&state, &group_key).await;
    let joiner = hex::encode(
        x0x::identity::AgentKeypair::generate()
            .expect("joiner key")
            .agent_id()
            .as_bytes(),
    );
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let event = member_joined(&group_key, &joiner, &local_hex);
    let error = pending_error(&group_key, &remote_hex);

    // 1. A miss: retryable, and a window opens.
    stage_refusal_if_certificates_unobtainable(&state, &group_key, &joiner, &event, &error).await;
    assert!(!certificate_refusal_staged(&state));
    // The window has in fact been open for 11 minutes of refusals.
    {
        let mut since = state
            .cert_unresolvable_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let stamp = since
            .get_mut(&seat_cert_fetch::cert_evidence_stamp_key(
                &stable_group_id,
                &joiner,
            ))
            .expect("the miss opened a window");
        stamp.first_ms = stamp.first_ms.saturating_sub(11 * 60_000);
    }

    // 2. The certificate reaches the local cache and a seal succeeds.
    cache_pair(&state, Some(owner.user_id()), &remote_cert).await;
    let mut info = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .expect("fixture")
        .clone();
    seal_commit_owner_certified(
        &state,
        &mut info,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await
    .expect("the seal succeeds from the local cache");
    assert!(
        stamp_for(&state, &stable_group_id, &joiner).is_none(),
        "a successful seal ends the refusal window"
    );

    // 3. A later refusal for the same attempt (the durable seat is still
    // digest-only) starts a fresh window: nothing staged.
    stage_refusal_if_certificates_unobtainable(&state, &group_key, &joiner, &event, &error).await;
    assert!(
        !certificate_refusal_staged(&state),
        "a fresh window starts retryable — nothing staged"
    );
    state.agent.shutdown().await;
    Ok(())
}

/// The responder ignores UNVERIFIED senders, senders who are NOT active
/// roster members, and requests for a group other than the topic's — and
/// (positive control) answers a verified roster member on the right topic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn responder_refuses_unverified_foreign_and_mismatched_requests() -> Result<()> {
    let plane = format!("r17v2-e-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let remote_kp = x0x::identity::AgentKeypair::generate().expect("remote key");
    let remote_cert =
        x0x::identity::AgentCertificate::issue(&owner, &remote_kp).expect("remote cert");
    let remote_hex = hex::encode(remote_kp.agent_id().as_bytes());
    let remote_digest = seat_cert_digest_of(&remote_cert);
    let group_key = r17_fixture(&state, &owner, &remote_hex, &remote_digest).await;
    // Seed the cache so ONLY the gates under test can refuse.
    cache_pair(&state, Some(owner.user_id()), &remote_cert).await;
    let request = serde_json::to_vec(&seat_cert_fetch::GroupCertFetchRequest {
        group_id: group_key.clone(),
        cert_digest: remote_digest.clone(),
        requester: hex::encode(state.agent.agent_id().as_bytes()),
    })
    .expect("request json");
    let local = state.agent.agent_id();
    assert!(
        !seat_cert_fetch::handle_group_cert_fetch_request(
            &state,
            &request,
            Some(&local),
            false,
            &group_key
        )
        .await,
        "unverified senders are ignored"
    );
    let stranger = x0x::identity::AgentKeypair::generate().expect("stranger");
    assert!(
        !seat_cert_fetch::handle_group_cert_fetch_request(
            &state,
            &request,
            Some(&stranger.agent_id()),
            true,
            &group_key
        )
        .await,
        "non-roster senders are ignored"
    );
    assert!(
        !seat_cert_fetch::handle_group_cert_fetch_request(
            &state,
            &request,
            Some(&local),
            true,
            "some-other-group"
        )
        .await,
        "a request for a foreign group id on this topic is ignored"
    );
    assert!(
        seat_cert_fetch::handle_group_cert_fetch_request(
            &state,
            &request,
            Some(&local),
            true,
            &group_key
        )
        .await,
        "positive control: a verified roster member on the group's topic is answered"
    );
    state.agent.shutdown().await;
    Ok(())
}
