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
        roster_certificates_b64: Vec::new(),
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

// ---------------------------------------------------------------------------
// #1023 (R19 Home blocker): the seat event carries the roster certificates
// ---------------------------------------------------------------------------

/// A socket-free daemon state that holds the owner USER key, as every Home
/// device does in R19. Its identity certificate is therefore issued by
/// the owner (the builder issues it at startup).
async fn owner_device_state(
    seed: &[u8; 32],
) -> Result<(
    Arc<AppState>,
    tempfile::TempDir,
    x0x::identity::AgentCertificate,
)> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(x0x::identity::AgentKeypair::generate()?)
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_user_key(x0x::identity::UserKeypair::from_seed(seed)?)
            .with_peer_cache_disabled()
            .with_contact_store_path(data_dir.join("contacts.json"))
            .build()
            .await?,
    );
    let cert = agent
        .identity()
        .agent_certificate()
        .cloned()
        .expect("an owner-key device holds an owner-issued certificate");
    let state = secure_endpoint_test_state_at(data_dir, agent).await?;
    Ok((state, dir, cert))
}

/// How [`creator_offline_scenario`] promotes the admin.
#[derive(Clone, Copy)]
enum Promotion {
    /// Set the role on the admin's local record.
    LocalRecord,
    /// Apply the creator's real signed role-update commit, published by
    /// the production `update_member_role` route, through the normal
    /// receive path.
    SignedCommit,
}

/// The R19 Home cast, from the moment the creator went offline.
struct CreatorOfflineScenario {
    /// Creator and original owner device ("nyc"). Already shut down.
    creator_hex: String,
    creator_cert: x0x::identity::AgentCertificate,
    /// The member that is later promoted and seals the next join
    /// ("singapore"), with the seat event it was seated by applied.
    admin: Arc<AppState>,
    _admin_dir: tempfile::TempDir,
    group_id: String,
    owner: x0x::identity::UserKeypair,
    /// The seat event exactly as the creator published it.
    seat_event: NamedGroupMetadataEvent,
    /// The creator's JoinResult for the admin, served by the production
    /// builder before the creator went offline (never delivered).
    served_join_result: Vec<u8>,
}

/// Build the R19 shape through production code:
/// 1. The creator (owner device, owner key) creates an owner-certified
///    group whose creator seat commits to its own certificate, and seals
///    the base revision.
/// 2. The admin-to-be holds the group stub a joiner gets from its invite:
///    the base roster projection, so the creator's seat is DIGEST-ONLY.
///    It never cached the creator's announce (the creator announced
///    before it existed).
/// 3. The creator admits it through the real add-member route and the
///    published seat event is captured. The creator then goes OFFLINE.
/// 4. The admin applies that seat event through the gossip/direct receive
///    path. It is never handed a JoinResult: in R19 the seat event won
///    the race, the joiner stopped polling, and #970's JoinResult sidecar
///    never arrived.
/// 5. The admin is promoted, per `promotion`.
async fn creator_offline_scenario(promotion: Promotion) -> Result<CreatorOfflineScenario> {
    let seed: [u8; 32] = rand::random();
    let owner = x0x::identity::UserKeypair::from_seed(&seed)?;
    let (creator, _creator_dir, creator_cert) = owner_device_state(&seed).await?;
    let (admin, admin_dir, admin_cert) = owner_device_state(&seed).await?;
    let creator_hex = hex::encode(creator.agent.agent_id().as_bytes());
    let admin_hex = hex::encode(admin.agent.agent_id().as_bytes());
    let group_id = hex::encode(rand::random::<[u8; 32]>());

    // (1) The creator's owner-certified group, creator seat byte-bearing.
    let mut base = x0x::groups::GroupInfo::with_policy(
        "r1023-home".to_string(),
        String::new(),
        creator.agent.agent_id(),
        group_id.clone(),
        x0x::groups::GroupPolicy {
            discoverability: x0x::groups::GroupDiscoverability::Hidden,
            admission: x0x::groups::GroupAdmission::OwnerCertified(owner.user_id()),
            confidentiality: x0x::groups::GroupConfidentiality::MlsEncrypted,
            read_access: x0x::groups::GroupReadAccess::MembersOnly,
            write_access: x0x::groups::GroupWriteAccess::MembersOnly,
        },
    );
    assert_eq!(base.secure_plane, x0x::mls::SecureGroupPlane::Gss);
    base.set_member_certificate(&creator_hex, creator_cert.clone())
        .expect("the creator's certificate binds its own seat");
    seal_commit_owner_certified(
        &creator,
        &mut base,
        creator.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await?;
    creator
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), base.clone());

    // (2) The admin-to-be's stub: the creator's seat is digest-only.
    let mut stub = base.clone();
    stub.members_v2
        .get_mut(&creator_hex)
        .expect("creator seat")
        .certificate = None;
    admin
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), stub);
    let creator_digest = seat_digest(&creator_cert);
    assert!(
        admin
            .agent
            .announce_blob_cache
            .find_by_cert_digest(&digest_arr(&creator_digest))
            .await
            .is_none(),
        "the admin never cached the creator's announce"
    );

    // (3) The creator admits the admin-to-be through the production route.
    install_discovery_cert(&creator, &admin.agent, &admin_cert).await;
    creator
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish hook")
        .clear();
    let response = add_named_group_member(
        State(Arc::clone(&creator)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
        Json(AddNamedGroupMemberRequest {
            agent_id: admin_hex.clone(),
            display_name: None,
            treekem_key_package_b64: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "the creator admits");
    let seat_event = creator
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish hook")
        .iter()
        .filter_map(|(_topic, bytes)| serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok())
        .find(|event| {
            matches!(event, NamedGroupMetadataEvent::MemberAdded { agent_id, .. }
                if *agent_id == admin_hex)
        })
        .expect("the creator published the admin's seat event");
    let served_join_result = join_result_payload_with_roster_certificates(
        &creator,
        &group_id,
        &admin_hex,
        JoinResultMessage::Result {
            event: Box::new(seat_event.clone()),
            chain: Vec::new(),
            head_attestation: None,
            roster_certificates_b64: Vec::new(),
        },
    )
    .await?;
    // (5a) With `Promotion::SignedCommit` the creator promotes the admin
    // through the production role route BEFORE going offline, and the
    // published signed role-update commit is captured for delivery.
    let role_event = match promotion {
        Promotion::LocalRecord => None,
        Promotion::SignedCommit => {
            let response = update_member_role(
                State(Arc::clone(&creator)),
                axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                    durable: true,
                }),
                Path((group_id.clone(), admin_hex.clone())),
                Json(UpdateMemberRoleRequest {
                    role: "admin".to_string(),
                }),
            )
            .await
            .into_response();
            assert_eq!(response.status(), StatusCode::OK, "the creator promotes");
            let event = creator
                .named_group_test_recorders
                .publish_bytes
                .lock()
                .expect("publish hook")
                .iter()
                .filter_map(|(_topic, bytes)| {
                    serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok()
                })
                .find(|event| {
                    matches!(event, NamedGroupMetadataEvent::MemberRoleUpdated {
                        agent_id, role: x0x::groups::GroupRole::Admin, commit: Some(_), ..
                    } if *agent_id == admin_hex)
                })
                .expect("the creator published a signed role-update commit");
            Some(event)
        }
    };
    let creator_id = creator.agent.agent_id();
    creator.agent.shutdown().await;
    drop(creator);

    // (4) The admin is seated by the seat event alone.
    let applied =
        apply_named_group_metadata_event(&admin, seat_event.clone(), creator_id, true, None).await;
    assert!(applied.accepted, "the seat event seats the admin");

    // (5b) Promotion.
    match role_event {
        None => {
            let mut groups = admin.named_groups.write().await;
            let info = groups.get_mut(&group_id).expect("admin's group");
            assert!(info.has_active_member(&admin_hex), "the admin is seated");
            info.members_v2
                .get_mut(&admin_hex)
                .expect("admin seat")
                .role = x0x::groups::GroupRole::Admin;
        }
        Some(event) => {
            let applied =
                apply_named_group_metadata_event(&admin, event, creator_id, true, None).await;
            assert!(
                applied.accepted,
                "the admin applies the creator's signed role-update commit"
            );
        }
    }
    {
        let groups = admin.named_groups.read().await;
        let info = groups.get(&group_id).expect("admin's group");
        assert_eq!(
            info.members_v2.get(&admin_hex).map(|seat| seat.role),
            Some(x0x::groups::GroupRole::Admin),
            "the admin is promoted"
        );
    }
    Ok(CreatorOfflineScenario {
        creator_hex,
        creator_cert,
        admin,
        _admin_dir: admin_dir,
        group_id,
        owner,
        seat_event,
        served_join_result,
    })
}

/// The promoted admin's seal of a new joiner D, after first adding each
/// `extra_digest_only` seat (agent hex, committed digest) with no bytes.
async fn promoted_admin_seals_new_joiner(
    s: &CreatorOfflineScenario,
    extra_digest_only: &[(String, String)],
) -> std::result::Result<x0x::groups::GroupStateCommit, x0x::groups::state_commit::ApplyError> {
    let d_kp = x0x::identity::AgentKeypair::generate().expect("joiner key");
    let d_hex = hex::encode(d_kp.agent_id().as_bytes());
    let d_cert = x0x::identity::AgentCertificate::issue(&s.owner, &d_kp).expect("joiner cert");
    let mut next = s
        .admin
        .named_groups
        .read()
        .await
        .get(&s.group_id)
        .expect("admin's group")
        .clone();
    for (agent_hex, digest) in extra_digest_only {
        next.add_member(
            agent_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        next.members_v2
            .get_mut(agent_hex)
            .expect("extra seat")
            .certificate_digest = Some(digest.clone());
    }
    next.add_member(d_hex.clone(), x0x::groups::GroupRole::Member, None, None);
    next.set_member_certificate(&d_hex, d_cert)
        .expect("D's certificate binds its fresh seat");
    seal_commit_owner_certified(
        &s.admin,
        &mut next,
        s.admin.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await
}

/// THE R19 CASE (#1023). The creator and original owner device is
/// offline; the promoted admin, which was seated by the seat event and
/// never received a JoinResult, must seal the next joiner.
///
/// Before #1023 only the JoinResult carried certificates (#970). The seat
/// event carried just the joiner's own, so the admin kept the creator's
/// seat digest-only and every seal refused with
/// `OwnerCertMemberPending [creator]` for as long as the creator was
/// offline: the 20 refusals in the R19 Singapore log.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn promoted_admin_seals_join_while_creator_offline() -> Result<()> {
    let s = creator_offline_scenario(Promotion::LocalRecord).await?;
    let commit = promoted_admin_seals_new_joiner(&s, &[])
        .await
        .unwrap_or_else(|err| {
            panic!("the promoted admin must seal while the creator is offline: {err}")
        });
    assert!(!commit.roster_root.is_empty());

    // The creator's bytes reached the admin through the seat event: they
    // are on its seat, they are not in its announce cache, and the event
    // carried exactly the creator's certificate.
    assert!(seat_has_bytes(&s.admin, &s.group_id, &s.creator_hex).await);
    assert!(s
        .admin
        .agent
        .announce_blob_cache
        .find_by_cert_digest(&digest_arr(&seat_digest(&s.creator_cert)))
        .await
        .is_none());
    let NamedGroupMetadataEvent::MemberAdded {
        roster_certificates_b64,
        ..
    } = &s.seat_event
    else {
        panic!("seat event is a MemberAdded");
    };
    assert_eq!(
        roster_certificates_b64,
        &vec![cert_b64(&s.creator_cert)],
        "the seat event carries every other certified seat (here the creator), not the joiner's own"
    );
    s.admin.agent.shutdown().await;
    Ok(())
}

/// The R19 case with a REAL promotion: the creator promotes the admin
/// through the production role route before going offline, and the admin
/// applies that signed `MemberRoleUpdated` commit through the normal
/// receive path (no local role edit). The promoted admin then seals the
/// next joiner. Fails without #1023 exactly like
/// `promoted_admin_seals_join_while_creator_offline`: the role commit
/// carries no certificates, so the creator's seat stays digest-only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_promoted_by_signed_commit_seals_join_while_creator_offline() -> Result<()> {
    let s = creator_offline_scenario(Promotion::SignedCommit).await?;
    let commit = promoted_admin_seals_new_joiner(&s, &[])
        .await
        .unwrap_or_else(|err| {
            panic!(
                "the admin promoted by the creator's signed commit must seal while the creator is offline: {err}"
            )
        });
    assert!(!commit.roster_root.is_empty());
    assert!(seat_has_bytes(&s.admin, &s.group_id, &s.creator_hex).await);
    s.admin.agent.shutdown().await;
    Ok(())
}

/// The carry does not weaken the gate. A seat whose certificate was never
/// carried anywhere (no seat event, no JoinResult, no announce) still
/// blocks the promoted admin's seal with `OwnerCertMemberPending`, and it
/// is the ONLY member named: the creator, whose certificate was carried,
/// is resolved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uncarried_certificate_still_blocks_with_owner_cert_member_pending() -> Result<()> {
    let s = creator_offline_scenario(Promotion::LocalRecord).await?;
    let x_kp = x0x::identity::AgentKeypair::generate().expect("x key");
    let x_hex = hex::encode(x_kp.agent_id().as_bytes());
    let x_cert = x0x::identity::AgentCertificate::issue(&s.owner, &x_kp).expect("x cert");
    let err = promoted_admin_seals_new_joiner(&s, &[(x_hex.clone(), seat_digest(&x_cert))])
        .await
        .expect_err("a never-carried certificate must keep blocking the seal");
    match &err {
        x0x::groups::state_commit::ApplyError::OwnerCertMemberPending { members, .. } => {
            assert_eq!(members, &vec![x_hex.clone()], "{err}");
        }
        other => panic!("expected OwnerCertMemberPending, got {other}"),
    }
    s.admin.agent.shutdown().await;
    Ok(())
}

/// Wire compatibility of the new `MemberAdded.roster_certificates_b64`:
/// - a legacy event (no key) decodes, with an empty sidecar;
/// - an event with no sidecar serializes WITHOUT the key, byte-identical
///   to the legacy wire;
/// - the event enum ignores keys it does not know, which is how a legacy
///   receiver (the same derive, without this field) reads a new event;
/// - the JoinResult keeps #970's shape: its event copy drops the sidecar
///   and the result-level sidecar still carries the certificates.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn member_added_certificate_sidecar_is_wire_compatible() -> Result<()> {
    let s = creator_offline_scenario(Promotion::LocalRecord).await?;
    let mut json = serde_json::to_value(&s.seat_event)?;
    let object = json.as_object_mut().expect("event object");
    assert!(object.contains_key("roster_certificates_b64"));

    object.remove("roster_certificates_b64");
    let legacy: NamedGroupMetadataEvent = serde_json::from_value(json)?;
    let mut expected = s.seat_event.clone();
    if let NamedGroupMetadataEvent::MemberAdded {
        roster_certificates_b64,
        ..
    } = &mut expected
    {
        roster_certificates_b64.clear();
    }
    assert_eq!(legacy, expected, "a legacy event decodes with no sidecar");
    assert!(
        !String::from_utf8(serde_json::to_vec(&legacy)?)?.contains("roster_certificates_b64"),
        "no sidecar means no key on the wire"
    );

    let mut future = serde_json::to_value(&s.seat_event)?;
    future
        .as_object_mut()
        .expect("event object")
        .insert("x0x_unknown_future_key".to_string(), serde_json::json!([1]));
    let decoded: NamedGroupMetadataEvent = serde_json::from_value(future)?;
    assert_eq!(
        decoded, s.seat_event,
        "unknown keys are ignored, not refused"
    );

    let JoinResultMessage::Result {
        event,
        roster_certificates_b64,
        ..
    } = serde_json::from_slice::<JoinResultMessage>(&s.served_join_result)?
    else {
        panic!("served payload is a Result");
    };
    let NamedGroupMetadataEvent::MemberAdded {
        roster_certificates_b64: event_sidecar,
        ..
    } = event.as_ref()
    else {
        panic!("JoinResult event is a MemberAdded");
    };
    assert!(
        event_sidecar.is_empty(),
        "the JoinResult's event copy drops the sidecar"
    );
    assert_eq!(roster_certificates_b64, vec![cert_b64(&s.creator_cert)]);
    s.admin.agent.shutdown().await;
    Ok(())
}
