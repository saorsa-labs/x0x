//! #946 r2 (Root design) intent tests: the group-scoped certificate fetch.

use super::*;

fn seat_cert_digest_of(cert: &x0x::identity::AgentCertificate) -> String {
    let bytes = bincode::serialize(cert).unwrap_or_else(|_| cert.agent_public_key().to_vec());
    hex::encode(blake3::hash(&bytes).as_bytes())
}

/// An OwnerCertified group whose roster holds the LOCAL agent (admin,
/// certificate embedded) and `remote_hex` DIGEST-ONLY — the R17 shape.
/// The remote's certificate is issued by `owner`, and `cache_pair` says
/// whether the LOCAL announce-blob cache holds it (an active member's
/// cache in production).
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
    // The local admin's seat: certificate embedded (issued by the group
    // owner, as every Home member's is).
    info.add_member(local_hex.clone(), x0x::groups::GroupRole::Admin, None, None);
    if let Some(cert) = state.agent.identity().agent_certificate() {
        let digest = seat_cert_digest_of(cert);
        if let Some(seat) = info.members_v2.get_mut(&local_hex) {
            seat.certificate = Some(cert.clone());
            seat.certificate_digest = Some(digest);
        }
    }
    // Wait: the local admin's cert must verify against the GROUP owner —
    // re-issue conceptually by pointing the fixture owner at the local
    // user key is wrong; instead the seat stays cert-less here and the
    // ladder's own-identity evidence covers the local agent (the test's
    // verdict needs every member Clean, so see the issuance note in the
    // test bodies: the local seat cert is installed by each test).
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
    let group_key = format!("r17v2-{remote_hex}");
    state
        .named_groups
        .write()
        .await
        .insert(group_key.clone(), info);
    group_key
}

/// THE R17 CASE (item A): the seal refuses on the first pass and
/// PUBLISHES a group-scoped request; the REAL responder branch (roster
/// member, digest in roster, verified cached pair, owner user check)
/// answers; the REAL response branch verifies and durably hydrates the
/// seat; the SECOND seal succeeds — an admin sealed while the
/// certificate's owner was offline, using another member's cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_offline_seal_hydrates_from_a_members_cache() -> Result<()> {
    let plane = format!("r17v2-a-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    // The local admin's certificate, issued by the GROUP owner (Home
    // shape) — install it on the identity so own-identity evidence and
    // the seat agree. The state's own cert is self-issued instead, so we
    // overwrite the SEAT with an owner-issued cert and give the ladder
    // the same bytes via the discovery cache entry below.
    let local_kp = state.agent.identity().agent_keypair();
    let local_cert = x0x::identity::AgentCertificate::issue(&owner, local_kp).expect("local cert");
    // The remote member's certificate (also owner-issued) — held ONLY in
    // the local announce-blob cache (another member's cache).
    let remote_kp = x0x::identity::AgentKeypair::generate().expect("remote key");
    let remote_cert =
        x0x::identity::AgentCertificate::issue(&owner, &remote_kp).expect("remote cert");
    let remote_hex = hex::encode(remote_kp.agent_id().as_bytes());
    let remote_digest = seat_cert_digest_of(&remote_cert);
    // The cache starts EMPTY (the certificate lives only in ANOTHER
    // MEMBER's cache — modeled by the pump injecting it into the shared
    // test state's cache when the request arrives, just before the real
    // responder branch reads it).
    let group_key = r17_fixture(&state, &owner, &remote_hex, &remote_digest).await;
    // Install the owner-issued local cert on the admin seat + discovery.
    {
        let mut groups = state.named_groups.write().await;
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let digest = seat_cert_digest_of(&local_cert);
        let info = groups.get_mut(&group_key).expect("fixture");
        if let Some(seat) = info.members_v2.get_mut(&local_hex) {
            seat.certificate = Some(local_cert.clone());
            seat.certificate_digest = Some(digest);
        }
    }
    state.agent.identity_discovery_cache().write().await.insert(
        state.agent.agent_id(),
        x0x::DiscoveredAgent {
            self_name: None,
            agent_id: state.agent.agent_id(),
            machine_id: state.agent.machine_id(),
            user_id: local_cert.user_id().ok(),
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
            cert_not_after: local_cert.not_after(),
            agent_certificate: Some(local_cert.clone()),
            agent_public_key: state
                .agent
                .identity()
                .agent_keypair()
                .public_key()
                .as_bytes()
                .to_vec(),
            cert_digest: None,
        },
    );

    // The REAL listener loop, driven by the test (the production listener
    // is started by serve; here we exercise its exact routing arms).
    let pubsub = state.agent.pubsub().expect("gossip");
    let metadata_topic = {
        let groups = state.named_groups.read().await;
        groups
            .get(&group_key)
            .expect("fixture")
            .metadata_topic
            .clone()
    };
    let mut sub = pubsub.subscribe(metadata_topic.clone()).await;
    let pump_state = Arc::clone(&state);
    let owner_id = owner.user_id();
    let remote_cert_for_member = remote_cert.clone();
    let pump = tokio::spawn(async move {
        while let Some(msg) = sub.recv().await {
            if let Some(rest) = msg.payload.strip_prefix(GROUP_CERT_FETCH_DOMAIN) {
                // The answering member's cache: verified pair for the
                // requested digest (the test injects exactly what another
                // member holds; the responder branch below is REAL).
                let pair = (Some(owner_id), Some(remote_cert_for_member.clone()));
                let pair_digest = x0x::announce_v3::cert_digest(&pair.0, &pair.1);
                pump_state
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
                handle_group_cert_fetch_request(&pump_state, rest).await;
            }
            if let Some(rest) = msg.payload.strip_prefix(GROUP_CERT_FETCH_RESPONSE_DOMAIN) {
                handle_group_cert_fetch_response(&pump_state, rest).await;
            }
        }
    });

    // Seal #1: refuses (digest-only seat) and PUBLISHES the request.
    let signing_kp = state.agent.identity().agent_keypair();
    let mut info = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .expect("fixture")
        .clone();
    let err = seal_commit_owner_certified(&state, &mut info, signing_kp, now_millis_u64())
        .await
        .expect_err("first pass: certificate only in a peer's cache");
    assert!(
        matches!(
            err,
            x0x::groups::state_commit::ApplyError::OwnerCertMemberPending { .. }
        ),
        "{err}"
    );
    // Give the pump a moment to deliver request → answer → hydrate.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let hydrated = state
            .named_groups
            .read()
            .await
            .get(&group_key)
            .and_then(|i| i.members_v2.get(&remote_hex))
            .is_some_and(|seat| seat.certificate.is_some());
        if hydrated || std::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // Seal #2 (the MemberJoined cadence's re-drive): succeeds.
    let mut info = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .expect("fixture")
        .clone();
    let commit = seal_commit_owner_certified(&state, &mut info, signing_kp, now_millis_u64())
        .await
        .expect("the admin seals while the cert's owner is offline");
    assert!(!commit.roster_root.is_empty());
    pump.abort();
    state.agent.shutdown().await;
    Ok(())
}

/// Item C: a cached pair whose user is NOT the group owner is never
/// served — the REAL responder branch rejects it (owner-user check) and
/// nothing reaches the wire, so the seat never hydrates and the seal
/// keeps refusing. Item B: the refusal is RETRYABLE (no typed refusal
/// before the deadline).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_user_pair_is_rejected_and_refusal_is_retryable() -> Result<()> {
    let plane = format!("r17v2-b-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let local_kp = state.agent.identity().agent_keypair();
    let local_cert = x0x::identity::AgentCertificate::issue(&owner, local_kp).expect("local cert");
    let remote_kp = x0x::identity::AgentKeypair::generate().expect("remote key");
    let wrong_user = x0x::identity::UserKeypair::generate().expect("wrong user");
    let remote_cert =
        x0x::identity::AgentCertificate::issue(&wrong_user, &remote_kp).expect("remote cert");
    let remote_hex = hex::encode(remote_kp.agent_id().as_bytes());
    let remote_digest = seat_cert_digest_of(&remote_cert);
    // The member's cache holds the WRONG-USER pair (digest matches the
    // seat, agent binds, user does not).
    let pair = (Some(wrong_user.user_id()), Some(remote_cert.clone()));
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
    let group_key = r17_fixture(&state, &owner, &remote_hex, &remote_digest).await;
    {
        let mut groups = state.named_groups.write().await;
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let digest = seat_cert_digest_of(&local_cert);
        let info = groups.get_mut(&group_key).expect("fixture");
        if let Some(seat) = info.members_v2.get_mut(&local_hex) {
            seat.certificate = Some(local_cert.clone());
            seat.certificate_digest = Some(digest);
        }
    }
    // The REAL responder branch, driven directly with the wire request
    // this seal would publish: it must REFUSE (wrong user).
    let request = serde_json::to_vec(&seat_cert_fetch::GroupCertFetchRequest {
        group_id: group_key.clone(),
        cert_digest: remote_digest.clone(),
        requester: hex::encode(state.agent.agent_id().as_bytes()),
    })
    .expect("request json");
    assert!(
        !seat_cert_fetch::handle_group_cert_fetch_request(&state, &request).await,
        "the responder refuses a wrong-user pair"
    );
    // The seat is untouched and the seal still refuses; no typed refusal
    // is staged (retryable, item B).
    let signing_kp = state.agent.identity().agent_keypair();
    let mut info = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .expect("fixture")
        .clone();
    // The wrong-user pair sits in the LOCAL cache too, so the local
    // hydrate installs it and the LADDER catches it: a present-but-failing
    // certificate is a DEFINITIVE failure (explicit eviction path), never
    // a hydrate-success. That is the second half of item C — a wrong-user
    // certificate can never seat a member.
    let second = seal_commit_owner_certified(&state, &mut info, signing_kp, now_millis_u64())
        .await
        .expect_err("the wrong-user pair is caught");
    assert!(
        matches!(
            &second,
            x0x::groups::state_commit::ApplyError::OwnerCertifiedEvictionRequired { members, .. }
                if members.iter().any(|m| m == &remote_hex)
        ),
        "{second}"
    );
    let staged = {
        let refusals = state
            .pending_join_refusals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        !refusals.is_empty()
    };
    assert!(!staged, "no typed refusal before the 10-minute deadline");
    state.agent.shutdown().await;
    Ok(())
}

/// Item B: after the deadline (simulated by backdating the first-miss
/// stamp), the same refusal DOES stage the typed terminal outcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_refusal_after_the_deadline() -> Result<()> {
    let plane = format!("r17v2-c-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let remote_kp = x0x::identity::AgentKeypair::generate().expect("remote key");
    let remote_cert =
        x0x::identity::AgentCertificate::issue(&owner, &remote_kp).expect("remote cert");
    let remote_hex = hex::encode(remote_kp.agent_id().as_bytes());
    let remote_digest = seat_cert_digest_of(&remote_cert);
    let group_key = r17_fixture(&state, &owner, &remote_hex, &remote_digest).await;
    // Backdate the first miss beyond the deadline.
    state
        .cert_unresolvable_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(
            format!("{group_key}:{remote_hex}"),
            now_millis_u64().saturating_sub(11 * 60_000),
        );
    let err = x0x::groups::state_commit::ApplyError::OwnerCertMemberPending {
        group_id: group_key.clone(),
        members: vec![remote_hex.clone()],
    };
    stage_refusal_if_certificates_unobtainable(
        &state,
        &group_key,
        &remote_hex,
        &NamedGroupMetadataEvent::MemberJoined {
            group_id: group_key.clone(),
            stable_group_id: None,
            member_agent_id: remote_hex.clone(),
            member_public_key_b64: String::new(),
            role: x0x::groups::GroupRole::Member,
            display_name: None,
            inviter_agent_id: hex::encode(state.agent.agent_id().as_bytes()),
            invite_secret: String::new(),
            ts_ms: now_millis_u64(),
            treekem_key_package_b64: None,
            signature_b64: String::new(),
            certificate_b64: None,
            kem_public_key_b64: None,
            kem_signature_b64: None,
            recovery_authority_agent_id: None,
            recovery_authority_public_key_b64: None,
            recovery_authority_signature_b64: None,
            recovery_authority_commit: None,
        },
        &err,
    )
    .await;
    let staged = {
        let refusals = state
            .pending_join_refusals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        refusals.values().any(|pending| {
            pending.receipt.reason == JoinRefusalReason::CertificateEvidenceUnavailable
        })
    };
    assert!(staged, "the typed refusal IS staged after the deadline");
    state.agent.shutdown().await;
    Ok(())
}
