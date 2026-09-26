//! #908/R17 Home-blocker intent tests: DigestPending seats must hydrate
//! at seal time even when the certificate's owner is offline, as long as
//! ANY peer can serve the certificate; the refusal must name the pending
//! members; and a non-converging refusal stages the typed join refusal.

use super::*;

/// blake3(bincode(cert)) — the roster-seat certificate digest rule.
fn seat_cert_digest(cert: &x0x::identity::AgentCertificate) -> String {
    let bytes = bincode::serialize(cert).unwrap_or_else(|_| cert.agent_public_key().to_vec());
    hex::encode(blake3::hash(&bytes).as_bytes())
}

/// An owner-certified group whose roster holds the LOCAL agent with its
/// certificate inline and `remote_hex` DIGEST-ONLY (bytes absent, digest
/// committed) — the R17 singapore shape while the remote's owner is
/// offline and no local cache holds the certificate.
async fn owner_offline_fixture(
    state: &AppState,
    owner: &x0x::identity::UserKeypair,
    remote_hex: &str,
    remote_digest: &str,
) -> String {
    let mut info = x0x::groups::GroupInfo::with_policy(
        "r17-digestpending".to_string(),
        String::new(),
        state.agent.agent_id(),
        format!("r17-{remote_hex}"),
        x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
    );
    info.policy.admission = x0x::groups::GroupAdmission::OwnerCertified(owner.user_id());
    // with_policy seats the creator; this roster is JUST the digest-only
    // remote member (the local agent seals as the admin authority
    // without holding a seat).
    info.members_v2.clear();
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
    let group_key = format!("r17-digestpending-{remote_hex}");
    state
        .named_groups
        .write()
        .await
        .insert(group_key.clone(), info);
    group_key
}

/// Rule 9 (THE gate): an admin seals while the certificate's owner is
/// offline; the seat hydrates via the seal-time warranted fetch answered
/// by a PEER on the real blob-request topic. Without the fetch, the seal
/// refuses (the pre-fix behavior — the R17 blocker).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_offline_admin_seal_hydrates_from_a_peer() -> Result<()> {
    let plane = format!("r17-seal-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    // The owner is a THIRD PARTY (offline: nothing of it exists locally);
    // the remote member's certificate is only obtainable from a peer.
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let owner_id = owner.user_id();
    let remote_kp = x0x::identity::AgentKeypair::generate().expect("remote key");
    let cert = x0x::identity::AgentCertificate::issue(&owner, &remote_kp).expect("remote cert");
    let remote_hex = hex::encode(remote_kp.agent_id().as_bytes());
    let cert_digest = seat_cert_digest(&cert);
    let group_key = owner_offline_fixture(&state, &owner, &remote_hex, &cert_digest).await;

    // A PEER on the same gossip plane: answers blob requests whose digest
    // matches the remote's CERT digest with the real signed pair — exactly
    // what any node that once heard the member announce does via its
    // cache. The fetcher re-verifies (cert hash + agent binding).
    let pubsub = state.agent.pubsub().expect("networked state has gossip");
    let mut req_sub = pubsub
        .subscribe(x0x::announce_blob::ANNOUNCE_BLOB_TOPIC.to_string())
        .await;
    let peer = tokio::spawn(async move {
        // Answer every message on the topic with the remote's signed
        // pair; the fetcher accepts it only when the certificate hashes
        // to the requested digest and binds the expected agent, so an
        // unconditional answer is exactly a cooperative peer.
        let pair_bytes =
            bincode::serialize(&(Some(owner_id), Some(cert.clone()))).expect("pair bytes");
        let mut wire = x0x::announce_blob::encode_blob_response(pair_bytes);
        let mut prefixed = Vec::with_capacity(
            x0x::announce_blob::ANNOUNCE_BLOB_RESPONSE_DOMAIN.len() + wire.len(),
        );
        prefixed.extend_from_slice(x0x::announce_blob::ANNOUNCE_BLOB_RESPONSE_DOMAIN);
        prefixed.append(&mut wire);
        while req_sub.recv().await.is_some() {
            let _ = pubsub
                .publish(
                    x0x::announce_blob::ANNOUNCE_BLOB_TOPIC.to_string(),
                    bytes::Bytes::from(prefixed.clone()),
                )
                .await;
        }
    });

    // The local caches hold NOTHING for the remote member — the hydrate
    // inside the seal must go to the wire.
    let signing_kp = state.agent.identity().agent_keypair();
    let mut info = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .expect("fixture group")
        .clone();
    let commit = seal_commit_owner_certified(&state, &mut info, signing_kp, now_millis_u64())
        .await
        .expect("the admin seals while the cert's owner is offline");
    assert!(!commit.roster_root.is_empty(), "a real commit was sealed");
    // The remote seat HYDRATED onto the info we hold.
    assert!(
        info.members_v2
            .get(&remote_hex)
            .is_some_and(|seat| seat.certificate.is_some()),
        "the digest-only seat hydrated from the peer-served certificate"
    );
    peer.abort();
    state.agent.shutdown().await;
    Ok(())
}

/// Rule 9 (error + refusal): with NO peer able to serve the certificate,
/// the seal refuses naming the DIGEST-PENDING member (the R17 log showed
/// `[]`), and the non-converging refusal stages the typed join refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unresolvable_seat_refusal_names_member_and_stages_typed_refusal() -> Result<()> {
    let plane = format!("r17-refusal-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let remote_kp = x0x::identity::AgentKeypair::generate().expect("remote key");
    let cert = x0x::identity::AgentCertificate::issue(&owner, &remote_kp).expect("remote cert");
    let remote_hex = hex::encode(remote_kp.agent_id().as_bytes());
    let cert_digest = seat_cert_digest(&cert);
    let group_key = owner_offline_fixture(&state, &owner, &remote_hex, &cert_digest).await;
    // No peer responder: the warranted fetch times out.

    let signing_kp = state.agent.identity().agent_keypair();
    let mut info = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .expect("fixture group")
        .clone();
    let err = seal_commit_owner_certified(&state, &mut info, signing_kp, now_millis_u64())
        .await
        .expect_err("no peer can serve the certificate");
    match &err {
        x0x::groups::state_commit::ApplyError::OwnerCertMemberPending { members, .. } => {
            assert!(
                members.iter().any(|m| m == &remote_hex),
                "the refusal names the digest-pending member (was `[]` before): {err}"
            );
        }
        other => panic!("expected OwnerCertMemberPending, got {other:?}"),
    }
    // The non-converging refusal stages the typed join refusal for the
    // joiner (attempt-bound; the event shape only needs the attempt id).
    let event = NamedGroupMetadataEvent::MemberJoined {
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
    };
    stage_refusal_if_certificates_unobtainable(&state, &group_key, &remote_hex, &event, &err).await;
    let staged = {
        let refusals = state
            .pending_join_refusals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        refusals.values().any(|pending| {
            pending.receipt.reason == JoinRefusalReason::CertificateEvidenceUnavailable
        })
    };
    assert!(staged, "the typed refusal is staged for the joiner");
    state.agent.shutdown().await;
    Ok(())
}
