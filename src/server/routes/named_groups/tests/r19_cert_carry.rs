//! R19 intent tests (#802 R18 Home blocker): owner-device certificates
//! travel with the admission, so an admin can seal after the owner device
//! goes offline.
//!
//! The R18 wedge: roster seats carry only certificate DIGESTS, and a
//! device's certificate bytes otherwise travel only on its own identity
//! announce. An owner device that announced before its peers started and
//! then went offline is held by nobody, so an admin's seal of the next
//! joiner refused forever with "members pending certificate resolution".

use super::*;

fn seat_digest(cert: &x0x::identity::AgentCertificate) -> String {
    x0x::groups::owner_cert::certificate_digest_hex(cert)
}

fn digest_arr(digest_hex: &str) -> [u8; 32] {
    <[u8; 32]>::try_from(hex::decode(digest_hex).expect("digest hex")).expect("32-byte digest")
}

fn cert_b64(cert: &x0x::identity::AgentCertificate) -> String {
    BASE64.encode(bincode::serialize(cert).expect("cert bincode"))
}

/// An OwnerCertified group keyed `local-<suffix>` (differs from its stable
/// id). `seats` are (agent hex, certificate, keep bytes on the seat?): a
/// seat without bytes is DIGEST-ONLY with the certificate's digest.
fn owner_certified_group(
    creator: &Agent,
    owner: &x0x::identity::UserKeypair,
    suffix: &str,
    seats: &[(String, &x0x::identity::AgentCertificate, bool)],
) -> (String, x0x::groups::GroupInfo) {
    let mut info = x0x::groups::GroupInfo::with_policy(
        "r19".to_string(),
        String::new(),
        creator.agent_id(),
        format!("r19-{suffix}"),
        x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
    );
    info.policy.admission = x0x::groups::GroupAdmission::OwnerCertified(owner.user_id());
    info.metadata_topic = format!("x0x/group/r19-{suffix}");
    info.members_v2.clear();
    for (agent_hex, cert, with_bytes) in seats {
        info.add_member(agent_hex.clone(), x0x::groups::GroupRole::Admin, None, None);
        let seat = info.members_v2.get_mut(agent_hex).expect("seat");
        seat.certificate = with_bytes.then(|| (*cert).clone());
        seat.certificate_digest = Some(seat_digest(cert));
    }
    let group_key = format!("local-{suffix}");
    assert_ne!(group_key, info.stable_group_id());
    (group_key, info)
}

/// Record `cert` as `subject`'s discovered certificate in `state`'s
/// discovery cache (the seal's evidence ladder reads it for the local
/// agent, whose harness identity certificate is self-issued).
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

/// The authority's MemberAdded for `member_hex` as staged for its
/// JoinResult. It carries no state commit: the joiner in these tests was
/// already seated by the gossip copy, so this Result's apply is a no-op
/// and ONLY its certificate sidecar matters.
fn staged_member_added(
    group_key: &str,
    actor_hex: &str,
    member_hex: &str,
    member_cert: &x0x::identity::AgentCertificate,
) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::MemberAdded {
        group_id: group_key.to_string(),
        revision: 2,
        actor: actor_hex.to_string(),
        agent_id: member_hex.to_string(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: Some(cert_b64(member_cert)),
        owner_mandate: None,
        commit: None,
    }
}

async fn seat_has_bytes(state: &AppState, group_key: &str, agent_hex: &str) -> bool {
    state
        .named_groups
        .read()
        .await
        .get(group_key)
        .and_then(|info| info.members_v2.get(agent_hex))
        .is_some_and(|seat| seat.certificate.is_some())
}

/// THE R18 CASE. Owner device A announced before anyone else existed, so
/// no peer ever cached its certificate. A admits admin C: C's roster holds
/// A's seat digest-only (roster projections strip the bytes). A then goes
/// offline. C seals the next joiner D, which must succeed.
///
/// The ONLY carrier of A's bytes to C is the certificate sidecar on the
/// JoinResult that A served to C, produced by the production serve builder
/// and applied through C's real Result arm. C's announce-blob cache and
/// discovery cache never hold A's pair, and A is offline before C seals,
/// so neither the announce path nor a #946 fetch can supply them. Removing
/// the sidecar (serve side or receive side) leaves A's seat digest-only
/// and the seal refuses with OwnerCertMemberPending, which is the R18
/// wedge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_seals_after_owner_device_goes_offline() -> Result<()> {
    let run = rand::random::<u32>();
    // Distinct planes: A and C never meet on gossip, which models "A's
    // announce happened before C existed".
    let (a, _a_dir) = networked_test_state(&format!("r19-a-{run}")).await?;
    let (c, _c_dir) = networked_test_state(&format!("r19-c-{run}")).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let a_hex = hex::encode(a.agent.agent_id().as_bytes());
    let c_hex = hex::encode(c.agent.agent_id().as_bytes());
    let a_cert = x0x::identity::AgentCertificate::issue(&owner, a.agent.identity().agent_keypair())
        .expect("owner device cert");
    let c_cert = x0x::identity::AgentCertificate::issue(&owner, c.agent.identity().agent_keypair())
        .expect("admin cert");
    // D: the next joiner (never started).
    let d_kp = x0x::identity::AgentKeypair::generate().expect("joiner key");
    let d_hex = hex::encode(d_kp.agent_id().as_bytes());
    let d_cert = x0x::identity::AgentCertificate::issue(&owner, &d_kp).expect("joiner cert");

    // A's roster: both seats byte-bearing (A holds its own certificate and
    // C's, which arrived on C's MemberJoined).
    let (group_key, a_info) = owner_certified_group(
        &a.agent,
        &owner,
        &format!("{run}"),
        &[
            (a_hex.clone(), &a_cert, true),
            (c_hex.clone(), &c_cert, true),
        ],
    );
    a.named_groups
        .write()
        .await
        .insert(group_key.clone(), a_info.clone());
    // C's roster after adopting A's commit: A's seat is DIGEST-ONLY.
    let mut c_info = a_info.clone();
    if let Some(seat) = c_info.members_v2.get_mut(&a_hex) {
        seat.certificate = None;
    }
    c.named_groups
        .write()
        .await
        .insert(group_key.clone(), c_info.clone());
    install_discovery_cert(&c, &c.agent, &c_cert).await;
    let a_digest = seat_digest(&a_cert);
    assert!(
        c.agent
            .announce_blob_cache
            .find_by_cert_digest(&digest_arr(&a_digest))
            .await
            .is_none(),
        "C never cached A's pair (A announced before C existed)"
    );

    // Precondition, the R18 wedge: with A's seat digest-only, C's seal of
    // D refuses and names A as pending.
    let c_kp = c.agent.identity().agent_keypair();
    let mut wedged = c_info.clone();
    wedged.add_member(d_hex.clone(), x0x::groups::GroupRole::Member, None, None);
    wedged
        .set_member_certificate(&d_hex, d_cert.clone())
        .expect("D's certificate binds its fresh seat");
    let err = seal_commit_owner_certified(&c, &mut wedged, c_kp, now_millis_u64())
        .await
        .expect_err("A's seat is digest-only and nobody holds A's bytes");
    assert!(
        matches!(
            &err,
            x0x::groups::state_commit::ApplyError::OwnerCertMemberPending { members, .. }
                if members.iter().any(|m| m == &a_hex)
        ),
        "{err}"
    );

    // A serves C's JoinResult through the production builder.
    let served = join_result_payload_with_roster_certificates(
        &a,
        &group_key,
        &c_hex,
        JoinResultMessage::Result {
            event: Box::new(staged_member_added(&group_key, &a_hex, &c_hex, &c_cert)),
            chain: Vec::new(),
            head_attestation: None,
            roster_certificates_b64: Vec::new(),
        },
    )
    .await?;
    let result: JoinResultMessage = serde_json::from_slice(&served)?;

    // A goes offline before any heartbeat reaches C.
    a.agent.shutdown().await;
    drop(a);

    // C receives the JoinResult through its real Result arm.
    record_expected_join_result_inviter(&c, join_result_key(&group_key, &c_hex), a_hex.clone());
    let a_id = parse_agent_id_hex(&a_hex).expect("agent id");
    handle_join_result_message(&c, &a_id, true, result).await;
    assert!(
        seat_has_bytes(&c, &group_key, &a_hex).await,
        "the JoinResult sidecar hydrates the owner device's digest-only seat on C"
    );
    assert!(
        c.agent
            .announce_blob_cache
            .find_by_cert_digest(&digest_arr(&a_digest))
            .await
            .is_none(),
        "the bytes came through the sidecar, not C's announce cache"
    );

    // C seals D's join with A offline: succeeds. C's own harness identity
    // announce is self-issued and replaces C's discovery entry, so C's
    // entry is set back to its owner-issued certificate (what a Home
    // device holds) immediately before sealing. This touches only C's
    // own evidence, never A's.
    install_discovery_cert(&c, &c.agent, &c_cert).await;
    let mut next = c
        .named_groups
        .read()
        .await
        .get(&group_key)
        .expect("C's group")
        .clone();
    next.add_member(d_hex.clone(), x0x::groups::GroupRole::Member, None, None);
    next.set_member_certificate(&d_hex, d_cert)
        .expect("D's certificate binds its fresh seat");
    let commit = seal_commit_owner_certified(&c, &mut next, c_kp, now_millis_u64())
        .await
        .expect("the admin seals the next joiner while the owner device is offline");
    assert!(!commit.roster_root.is_empty());
    c.agent.shutdown().await;
    Ok(())
}

/// A sidecar is not signed, so every entry must authenticate itself
/// against the owner-signed roster before it touches a seat. Entries with
/// the wrong digest, the wrong agent, or the wrong owner are rejected and
/// the seat keeps its committed digest with no bytes. One correct entry
/// in the same sidecar still installs, which shows the rejections are
/// per-entry checks and not a helper that installs nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sidecar_entries_failing_digest_agent_or_owner_are_not_installed() -> Result<()> {
    let run = rand::random::<u32>();
    let (state, _dir) = networked_test_state(&format!("r19-neg-{run}")).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let wrong_owner = x0x::identity::UserKeypair::generate().expect("wrong owner");
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let local_cert =
        x0x::identity::AgentCertificate::issue(&owner, state.agent.identity().agent_keypair())
            .expect("local cert");
    let kp = || x0x::identity::AgentKeypair::generate().expect("agent key");
    let hex_of = |kp: &x0x::identity::AgentKeypair| hex::encode(kp.agent_id().as_bytes());

    // Wrong digest: the seat commits to `v_committed`; the sidecar offers a
    // DIFFERENT, otherwise valid owner-issued certificate for the same
    // agent (a v2 certificate with a far-future expiry). Owner and agent
    // are right; only the digest is not the committed one.
    let v = kp();
    let v_committed = x0x::identity::AgentCertificate::issue(&owner, &v).expect("v cert");
    let v_other = x0x::identity::AgentCertificate::issue_with_expiry(&owner, &v, Some(u64::MAX))
        .expect("v other");
    assert_ne!(seat_digest(&v_committed), seat_digest(&v_other));
    // Wrong agent: seat Y commits to the digest of a certificate that binds
    // a DIFFERENT agent Z (digest matches, binding does not).
    let y = kp();
    let z = kp();
    let z_cert = x0x::identity::AgentCertificate::issue(&owner, &z).expect("z cert");
    // Wrong owner: seat W commits to a certificate issued by a user who is
    // not the group owner (digest and agent match, owner does not).
    let w = kp();
    let w_cert = x0x::identity::AgentCertificate::issue(&wrong_owner, &w).expect("w cert");
    // Positive control.
    let p = kp();
    let p_cert = x0x::identity::AgentCertificate::issue(&owner, &p).expect("p cert");

    let (group_key, info) = owner_certified_group(
        &state.agent,
        &owner,
        &format!("neg-{run}"),
        &[
            (local_hex.clone(), &local_cert, true),
            (hex_of(&v), &v_committed, false),
            (hex_of(&y), &z_cert, false),
            (hex_of(&w), &w_cert, false),
            (hex_of(&p), &p_cert, false),
        ],
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_key.clone(), info);

    let sidecar = vec![
        cert_b64(&v_other),
        cert_b64(&z_cert),
        cert_b64(&w_cert),
        cert_b64(&p_cert),
        "not base64 !!".to_string(),
    ];
    let hydrated =
        seat_cert_fetch::hydrate_from_roster_certificate_sidecar(&state, &group_key, &sidecar)
            .await;
    assert_eq!(hydrated, 1, "only the correct entry installs");
    assert!(seat_has_bytes(&state, &group_key, &hex_of(&p)).await);
    let groups = state.named_groups.read().await;
    let info = groups.get(&group_key).expect("group");
    for (label, agent, committed) in [
        ("wrong digest", hex_of(&v), seat_digest(&v_committed)),
        ("wrong agent", hex_of(&y), seat_digest(&z_cert)),
        ("wrong owner", hex_of(&w), seat_digest(&w_cert)),
    ] {
        let seat = info.members_v2.get(&agent).expect("seat");
        assert!(seat.certificate.is_none(), "{label}: must not be installed");
        assert_eq!(
            seat.certificate_digest.as_deref(),
            Some(committed.as_str()),
            "{label}: the committed digest is untouched"
        );
    }
    drop(groups);
    state.agent.shutdown().await;
    Ok(())
}

/// #946 responder fallback. A node whose seat for M was hydrated through
/// the group path (a sidecar or an earlier fetch) holds M's bytes only on
/// the roster seat, not in its announce-blob cache. It must still answer a
/// fetch for M's digest; otherwise hydrated bytes could never be relayed
/// to a member that missed them. Seat bytes whose user is not the group
/// owner are never served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn responder_serves_certificate_bytes_held_on_its_roster_seat() -> Result<()> {
    let run = rand::random::<u32>();
    let (state, _dir) = networked_test_state(&format!("r19-resp-{run}")).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let wrong_owner = x0x::identity::UserKeypair::generate().expect("wrong owner");
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let local_cert =
        x0x::identity::AgentCertificate::issue(&owner, state.agent.identity().agent_keypair())
            .expect("local cert");
    let m_kp = x0x::identity::AgentKeypair::generate().expect("member key");
    let m_hex = hex::encode(m_kp.agent_id().as_bytes());
    let m_cert = x0x::identity::AgentCertificate::issue(&owner, &m_kp).expect("m cert");
    let x_kp = x0x::identity::AgentKeypair::generate().expect("other key");
    let x_hex = hex::encode(x_kp.agent_id().as_bytes());
    let x_cert = x0x::identity::AgentCertificate::issue(&wrong_owner, &x_kp).expect("x cert");
    let (group_key, info) = owner_certified_group(
        &state.agent,
        &owner,
        &format!("resp-{run}"),
        &[
            (local_hex.clone(), &local_cert, true),
            (m_hex.clone(), &m_cert, true),
            (x_hex.clone(), &x_cert, true),
        ],
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_key.clone(), info);
    let request_for = |digest: String| {
        serde_json::to_vec(&seat_cert_fetch::GroupCertFetchRequest {
            group_id: group_key.clone(),
            cert_digest: digest,
            requester: local_hex.clone(),
        })
        .expect("request json")
    };
    let m_digest = seat_digest(&m_cert);
    assert!(
        state
            .agent
            .announce_blob_cache
            .find_by_cert_digest(&digest_arr(&m_digest))
            .await
            .is_none(),
        "the pair is NOT in the announce-blob cache"
    );
    assert!(
        seat_cert_fetch::handle_group_cert_fetch_request(
            &state,
            &request_for(m_digest),
            Some(&state.agent.agent_id()),
            true,
            &group_key,
        )
        .await,
        "the responder answers from its own roster seat bytes"
    );
    assert!(
        !seat_cert_fetch::handle_group_cert_fetch_request(
            &state,
            &request_for(seat_digest(&x_cert)),
            Some(&state.agent.agent_id()),
            true,
            &group_key,
        )
        .await,
        "seat bytes issued by a non-owner user are never served"
    );
    state.agent.shutdown().await;
    Ok(())
}

/// A joiner that cannot pull control blobs receives the JoinResult inline,
/// so the sidecar must never push an inline result over the direct-message
/// limit. With a roster far larger than the limit, the served payload
/// stays inline-sized and still carries the certificates that fit, with
/// the authority's own first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sidecar_never_pushes_an_inline_join_result_over_the_dm_limit() -> Result<()> {
    let run = rand::random::<u32>();
    let (state, _dir) = networked_test_state(&format!("r19-size-{run}")).await?;
    let owner = x0x::identity::UserKeypair::generate().expect("owner key");
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let local_cert =
        x0x::identity::AgentCertificate::issue(&owner, state.agent.identity().agent_keypair())
            .expect("local cert");
    let others: Vec<(String, x0x::identity::AgentCertificate)> = (0..12)
        .map(|_| {
            let kp = x0x::identity::AgentKeypair::generate().expect("agent key");
            let cert = x0x::identity::AgentCertificate::issue(&owner, &kp).expect("cert");
            (hex::encode(kp.agent_id().as_bytes()), cert)
        })
        .collect();
    let mut seats = vec![(local_hex.clone(), &local_cert, true)];
    seats.extend(others.iter().map(|(hex, cert)| (hex.clone(), cert, true)));
    let (group_key, info) =
        owner_certified_group(&state.agent, &owner, &format!("size-{run}"), &seats);
    state
        .named_groups
        .write()
        .await
        .insert(group_key.clone(), info);
    let joiner_kp = x0x::identity::AgentKeypair::generate().expect("joiner key");
    let joiner_hex = hex::encode(joiner_kp.agent_id().as_bytes());
    let joiner_cert = x0x::identity::AgentCertificate::issue(&owner, &joiner_kp).expect("cert");
    let all_certs_len: usize = std::iter::once(&local_cert)
        .chain(others.iter().map(|(_, cert)| cert))
        .map(|cert| cert_b64(cert).len())
        .sum();
    assert!(
        all_certs_len > x0x::dm::MAX_PAYLOAD_BYTES,
        "the roster's certificates alone exceed the DM limit"
    );
    let bare = JoinResultMessage::Result {
        event: Box::new(staged_member_added(
            &group_key,
            &local_hex,
            &joiner_hex,
            &joiner_cert,
        )),
        chain: Vec::new(),
        head_attestation: None,
        roster_certificates_b64: Vec::new(),
    };
    assert!(serde_json::to_vec(&bare)?.len() <= x0x::dm::MAX_PAYLOAD_BYTES);
    let served =
        join_result_payload_with_roster_certificates(&state, &group_key, &joiner_hex, bare).await?;
    assert!(
        served.len() <= x0x::dm::MAX_PAYLOAD_BYTES,
        "an inline result stays inline-sized: {} bytes",
        served.len()
    );
    let JoinResultMessage::Result {
        roster_certificates_b64,
        ..
    } = serde_json::from_slice::<JoinResultMessage>(&served)?
    else {
        panic!("served payload is a Result");
    };
    assert!(
        !roster_certificates_b64.is_empty(),
        "certificates that fit are still carried"
    );
    assert_eq!(
        roster_certificates_b64.first(),
        Some(&cert_b64(&local_cert)),
        "the authority's own certificate is carried first"
    );
    state.agent.shutdown().await;
    Ok(())
}
