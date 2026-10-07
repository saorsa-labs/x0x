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

/// Drive the real local pubsub listener through the formerly racy ordering.
/// A unique V3.1 name defeats payload dedup even within the same clock second;
/// waiting for that name AND digest proves ingest, not just publish completion.
async fn anonymous_announce_lands(agent: &Agent) -> Result<()> {
    let marker = format!("r1132-{}", rand::random::<u64>());
    agent.set_self_name(Some(marker.clone()));
    agent.announce_identity(false, false).await?;
    let anonymous = x0x::announce_v3::cert_digest(&None, &None);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if agent
                .discovered_agent(agent.agent_id())
                .await?
                .is_some_and(|entry| {
                    entry.self_name.as_deref() == Some(marker.as_str())
                        && entry.cert_digest == Some(anonymous)
                        && entry.agent_certificate.is_none()
                })
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("anonymous V3 must invalidate the discovered certificate")??;
    Ok(())
}

/// Mechanism control: the ordinary announcement listener, with no peer or
/// reconnect, invalidates a hand-installed cert and makes the seal pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anonymous_announce_invalidates_hand_installed_cert() -> Result<()> {
    let plane = format!("r19-writer-{}", rand::random::<u32>());
    let dir = tempfile::tempdir()?;
    let mut config = isolated_loopback_config(&plane);
    config.port_mapping_enabled = false;
    let agent = Arc::new(
        Agent::builder()
            .with_identity_dir(dir.path())
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key(x0x::identity::AgentKeypair::generate()?)
            .with_agent_cert_path(dir.path().join("agent.cert"))
            .with_user_key_path(dir.path().join("absent-user.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(config)
            .build()
            .await?,
    );
    // No join_network: make the FIRST announce land at a deterministic point.
    // It still goes through the real signed pubsub and identity listener.
    let state = secure_endpoint_test_state_at(dir.path(), agent).await?;
    let owner = x0x::identity::UserKeypair::generate()?;
    let cert =
        x0x::identity::AgentCertificate::issue(&owner, state.agent.identity().agent_keypair())?;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (_, mut info) = owner_certified_group(
        &state.agent,
        &owner,
        &plane,
        &[(local_hex.clone(), &cert, true)],
    );
    install_discovery_cert(&state, &state.agent, &cert).await;
    let evidence = owner_cert_seal_evidence(&state, &info).await;
    assert!(info.owner_cert_verdict(&evidence).is_all_clean());

    anonymous_announce_lands(&state.agent).await?;
    let err = seal_commit_owner_certified(
        &state,
        &mut info,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await
    .expect_err("an anonymous digest contradicts the hand-installed owner certificate");
    assert!(matches!(
        err,
        x0x::groups::state_commit::ApplyError::OwnerCertMemberPending { members, .. }
            if members == vec![local_hex]
    ));
    assert!(state.agent.peers().await?.is_empty());
    state.agent.shutdown().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// ADR 0108 S2-1 (#1143): the Home verdict rule at all three verdict sites —
// the seal, the eviction path and the ADR 0107 serving guard. The ordinary
// OwnerCertified control above is kept unchanged.
// ---------------------------------------------------------------------------

/// The mechanism control's daemon: a loopback-only agent with no owner key
/// (so no certificate of its own), no peer cache, and no `join_network`.
async fn announce_writer_state(dir: &std::path::Path, plane: &str) -> Result<Arc<AppState>> {
    let mut config = isolated_loopback_config(plane);
    config.port_mapping_enabled = false;
    let agent = Arc::new(
        Agent::builder()
            .with_identity_dir(dir)
            .with_machine_key(dir.join("machine.key"))
            .with_agent_key(x0x::identity::AgentKeypair::generate()?)
            .with_agent_cert_path(dir.join("agent.cert"))
            .with_user_key_path(dir.join("absent-user.key"))
            .with_contact_store_path(dir.join("contacts.json"))
            .with_peer_cache_disabled()
            .with_network_config(config)
            .build()
            .await?,
    );
    secure_endpoint_test_state_at(dir, agent).await
}

/// [`owner_certified_group`] as a Home: the ADR-0038 policy and metadata,
/// committed by one owner-certified seal, so `is_home_scope()` holds
/// (ADR 0108 §1). Every seat must be Clean for that seal.
async fn committed_home_group(
    state: &AppState,
    owner: &x0x::identity::UserKeypair,
    suffix: &str,
    seats: &[(String, &x0x::identity::AgentCertificate, bool)],
) -> Result<(String, x0x::groups::GroupInfo)> {
    let (group_key, mut info) = owner_certified_group(&state.agent, owner, suffix, seats);
    info.policy = x0x::groups::GroupPolicy::home(&owner.user_id());
    info.home = Some(x0x::groups::HomeMetadata {
        primary_agent: hex::encode(state.agent.agent_id().as_bytes()),
        placements: std::collections::BTreeMap::new(),
        provisioned_at_ms: 1,
    });
    assert!(
        !info.is_home_scope(),
        "the Home metadata is not committed yet"
    );
    seal_commit_owner_certified(
        state,
        &mut info,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await?;
    assert!(info.is_home_scope(), "fixture: a committed Home scope");
    Ok((group_key, info))
}

/// [`owner_certified_group`], sealed once like [`committed_home_group`], so
/// the ordinary twin differs from the Home only in Home scope.
async fn committed_ordinary_group(
    state: &AppState,
    owner: &x0x::identity::UserKeypair,
    suffix: &str,
    seats: &[(String, &x0x::identity::AgentCertificate, bool)],
) -> Result<(String, x0x::groups::GroupInfo)> {
    let (group_key, mut info) = owner_certified_group(&state.agent, owner, suffix, seats);
    seal_commit_owner_certified(
        state,
        &mut info,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await?;
    assert!(!info.is_home_scope());
    Ok((group_key, info))
}

/// An ANONYMOUS announce by `subject`'s own machine: `subject` is bound to a
/// fresh machine (the authenticated binding its direct-origin announce
/// leaves), and that machine's anonymous announce lands in discovery
/// through the real listener ([`relayed_anonymous_announce_lands`]): the
/// canonical anonymous digest and no certificate. ADR 0108 §4 reads that
/// digest as no disclosure only because the subject's bound machine
/// signed it.
async fn install_anonymous_discovery(
    state: &AppState,
    subject: &x0x::identity::AgentKeypair,
) -> Result<x0x::identity::MachineKeypair> {
    let machine = x0x::identity::MachineKeypair::generate()?;
    state
        .agent
        .record_authenticated_binding_for_testing(
            subject.agent_id(),
            machine.machine_id(),
            x0x::groups::owner_cert::restore_clock_now(),
        )
        .await;
    relayed_anonymous_announce_lands(state, subject, &machine).await?;
    Ok(machine)
}

/// An anonymous V3 announce naming `subject`, signed by `machine`, through
/// `state`'s real identity listener; returns once discovery shows it.
///
/// A V3 announce is signed by a machine key alone (`announce_v3` `verify`:
/// machine key ↔ machine id, agent key ↔ agent id, machine signature), so
/// `machine` need not be the subject's: any machine can sign one. It is
/// published on `state`'s own pubsub, so the pubsub sender is `state`'s
/// agent, never `subject`. The listener therefore refuses it as a binding
/// source (`record_authenticated_machine_binding_from_message`: not
/// direct-origin) and still caches it for discovery, exactly as for a
/// forged or relayed announce from the mesh.
async fn relayed_anonymous_announce_lands(
    state: &AppState,
    subject: &x0x::identity::AgentKeypair,
    machine: &x0x::identity::MachineKeypair,
) -> Result<()> {
    // Starts the identity listener; it subscribes before this returns.
    state.agent.discovered_agents().await?;
    let announced_at = x0x::groups::owner_cert::restore_clock_now();
    let v2 = x0x::IdentityAnnouncement {
        self_name: None,
        agent_id: subject.agent_id(),
        machine_id: machine.machine_id(),
        user_id: None,
        agent_certificate: None,
        machine_public_key: machine.public_key().as_bytes().to_vec(),
        machine_signature: Vec::new(),
        addresses: Vec::new(),
        announced_at,
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        agent_public_key: subject.public_key().as_bytes().to_vec(),
    };
    let v3 = x0x::announce_v3::IdentityAnnouncementV3::build_from_v2(&v2, machine.secret_key(), 0)?;
    v3.verify()?;
    let anonymous = x0x::announce_v3::anonymous_cert_digest();
    anyhow::ensure!(v3.cert_digest == anonymous, "fixture: an anonymous V3");
    let payload = x0x::announce_v3::serialize_v3(&v3)
        .map_err(|error| anyhow::anyhow!("serialize v3: {error}"))?;
    state
        .agent
        .pubsub()
        .context("gossip runtime")?
        .publish(
            x0x::IDENTITY_ANNOUNCE_TOPIC.to_string(),
            bytes::Bytes::from(payload),
        )
        .await?;
    let key = machine.public_key().as_bytes().to_vec();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if state
                .agent
                .discovered_agent_for_testing(&subject.agent_id())
                .await
                .is_some_and(|entry| {
                    entry.cert_digest == Some(anonymous)
                        && entry.agent_certificate.is_none()
                        && entry.machine_public_key == key
                        && entry.announced_at == announced_at
                })
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("the relayed anonymous announce must land in discovery")?;
    Ok(())
}

/// The machine `subject`'s authenticated machine binding names, if any.
async fn bound_machine(
    state: &AppState,
    subject: x0x::identity::AgentId,
) -> Option<x0x::identity::MachineId> {
    x0x::dm_inbox::authenticated_machine_binding_for_testing(
        &state.agent.authenticated_machine_bindings_for_testing(),
        &subject,
    )
    .await
}

/// SEAL SITE. The Home twin of
/// `anonymous_announce_invalidates_hand_installed_cert`: the same anonymous
/// announce lands through the same real listener and drops the discovered
/// certificate, but the group is a committed Home, so the anonymous digest
/// is no disclosure (ADR 0108 §4). The seal succeeds on the roster-embedded
/// certificate and starts no grace. Before S2-1 it refused with
/// `OwnerCertMemberPending`, exactly like the ordinary control.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anonymous_announce_keeps_hand_installed_cert_in_a_committed_home() -> Result<()> {
    let plane = format!("r19-home-writer-{}", rand::random::<u32>());
    let dir = tempfile::tempdir()?;
    let state = announce_writer_state(dir.path(), &plane).await?;
    let owner = x0x::identity::UserKeypair::generate()?;
    let cert =
        x0x::identity::AgentCertificate::issue(&owner, state.agent.identity().agent_keypair())?;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    install_discovery_cert(&state, &state.agent, &cert).await;
    let (_, mut info) =
        committed_home_group(&state, &owner, &plane, &[(local_hex.clone(), &cert, true)]).await?;

    anonymous_announce_lands(&state.agent).await?;
    let evidence = owner_cert_seal_evidence(&state, &info).await;
    assert_eq!(
        evidence.digest_for(&local_hex),
        Some(x0x::announce_v3::anonymous_cert_digest()),
        "the seal evidence holds the anonymous digest"
    );
    assert!(evidence.cert_for(&local_hex).is_none());
    seal_commit_owner_certified(
        &state,
        &mut info,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await
    .expect("in a committed Home the anonymous digest is no disclosure");
    assert_eq!(
        info.members_v2[&local_hex].certificate_missing_since_ms, None,
        "no grace was started"
    );
    assert!(info.is_home_scope(), "the new head still covers the Home");
    assert!(state.agent.peers().await?.is_empty());
    state.agent.shutdown().await;
    Ok(())
}

/// EVICTION SITE (`owner_certified_seal_with_eviction`, the explicit seal
/// route), on the live record. The creator's announce is anonymous and its
/// missing-evidence grace window has expired. In the ordinary twin that
/// verdict is `Failed(NoCertificate)`, the eviction set. In a committed Home
/// the creator is Clean: nothing is evicted, the stale grace stamp is
/// cleared, and the all-clean seal commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eviction_path_keeps_an_anonymous_creator_seated_in_a_committed_home() -> Result<()> {
    let plane = format!("r19-home-evict-{}", rand::random::<u32>());
    let dir = tempfile::tempdir()?;
    let state = announce_writer_state(dir.path(), &plane).await?;
    let owner = x0x::identity::UserKeypair::generate()?;
    let local_cert =
        x0x::identity::AgentCertificate::issue(&owner, state.agent.identity().agent_keypair())?;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    install_discovery_cert(&state, &state.agent, &local_cert).await;
    let creator_kp = x0x::identity::AgentKeypair::generate()?;
    let creator_hex = hex::encode(creator_kp.agent_id().as_bytes());
    let creator_cert = x0x::identity::AgentCertificate::issue(&owner, &creator_kp)?;
    let seats = [
        (local_hex.clone(), &local_cert, true),
        (creator_hex.clone(), &creator_cert, true),
    ];
    let (_, ordinary) = committed_ordinary_group(&state, &owner, "evict-ordinary", &seats).await?;
    let (home_key, home) = committed_home_group(&state, &owner, "evict-home", &seats).await?;
    install_anonymous_discovery(&state, &creator_kp).await?;
    let expired_grace = |mut info: x0x::groups::GroupInfo| {
        info.members_v2
            .get_mut(&creator_hex)
            .expect("creator seat")
            .certificate_missing_since_ms = Some(1);
        info
    };

    // Ordinary control: the expired grace window makes the creator the
    // eviction set.
    let mut ordinary = expired_grace(ordinary);
    let evidence = owner_cert_seal_evidence(&state, &ordinary).await;
    let failed = ordinary.owner_cert_verdict(&evidence).failed();
    assert_eq!(
        failed,
        vec![(
            creator_hex.clone(),
            x0x::groups::owner_cert::OwnerCertFailure::NoCertificate
        )],
        "the ordinary twin evicts the anonymous creator"
    );

    // The Home, through the production eviction path.
    state
        .named_groups
        .write()
        .await
        .insert(home_key.clone(), expired_grace(home));
    let (commit, evicted, _) = owner_certified_seal_with_eviction(&state, &home_key, &local_hex)
        .await
        .expect("an OwnerCertified group takes the eviction path")
        .unwrap_or_else(|(status, body)| panic!("eviction-path seal refused: {status} {body:?}"));
    assert!(evicted.is_empty(), "nobody is evicted: {evicted:?}");
    assert!(!commit.roster_root.is_empty());
    let groups = state.named_groups.read().await;
    let info = groups.get(&home_key).expect("the Home");
    assert!(
        info.has_active_member(&creator_hex),
        "the creator stays seated"
    );
    assert_eq!(
        info.members_v2[&creator_hex].certificate_missing_since_ms, None,
        "the stale grace stamp is cleared"
    );
    drop(groups);
    state.agent.shutdown().await;
    Ok(())
}

/// SERVING GUARD SITE (ADR 0107, both the pre-phase check and the stream
/// seam). The verdict there runs on a probe clone trimmed to the recipient's
/// seat. A Home joiner whose announce is anonymous is Clean there and is
/// served: ADR 0107's permitted Clean alternative (ADR 0108 §4). In the
/// ordinary twin the same joiner is still withheld as `InGrace`. The W3-H
/// #1143 case cannot catch this: its joiner announces consented.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serving_guard_serves_an_anonymous_home_joiner_and_withholds_the_ordinary_one() -> Result<()>
{
    let plane = format!("r19-home-serve-{}", rand::random::<u32>());
    let dir = tempfile::tempdir()?;
    let state = announce_writer_state(dir.path(), &plane).await?;
    let owner = x0x::identity::UserKeypair::generate()?;
    let local_cert =
        x0x::identity::AgentCertificate::issue(&owner, state.agent.identity().agent_keypair())?;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    install_discovery_cert(&state, &state.agent, &local_cert).await;
    let joiner_kp = x0x::identity::AgentKeypair::generate()?;
    let joiner_hex = hex::encode(joiner_kp.agent_id().as_bytes());
    let joiner_cert = x0x::identity::AgentCertificate::issue(&owner, &joiner_kp)?;
    let seats = [
        (local_hex.clone(), &local_cert, true),
        (joiner_hex.clone(), &joiner_cert, true),
    ];
    let (ordinary_key, ordinary) =
        committed_ordinary_group(&state, &owner, "serve-ordinary", &seats).await?;
    let (home_key, home) = committed_home_group(&state, &owner, "serve-home", &seats).await?;
    install_anonymous_discovery(&state, &joiner_kp).await?;
    {
        let mut groups = state.named_groups.write().await;
        groups.insert(ordinary_key.clone(), ordinary);
        groups.insert(home_key.clone(), home);
    }

    // Home: served at the pre-phase and at the seam.
    let evidence = join_artifact_serving_check(&state, &home_key, &joiner_hex)
        .await
        .unwrap_or_else(|refusal| panic!("the anonymous Home joiner was withheld: {refusal:?}"));
    assert!(evidence.is_some(), "an OwnerCertified verdict was taken");
    assert_eq!(
        join_artifact_seam_refusal(&state, &home_key, &joiner_hex, evidence),
        None,
        "the seam serves the anonymous Home joiner"
    );

    // Ordinary twin: still withheld on both checks.
    assert_eq!(
        join_artifact_serving_refusal(&state, &ordinary_key, &joiner_hex).await,
        Some(JoinArtifactRefusal::CertificateInGrace)
    );
    let evidence = owner_cert_evidence_for(&state, &[joiner_hex.as_str()]).await;
    assert_eq!(
        join_artifact_seam_refusal(&state, &ordinary_key, &joiner_hex, Some(evidence)),
        Some(JoinArtifactRefusal::CertificateInGrace)
    );
    state.agent.shutdown().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// ADR 0108 §4's premise (Codex P2 on #1247): "Only the subject agent's
// authenticated bound machine can sign its announce; an arbitrary third
// party cannot manufacture this absence signal." A V3 announce is signed by
// a machine key alone, and the identity listener caches one for discovery
// even when it refuses it as a binding source. Every anonymous announce
// below goes through that real listener
// ([`relayed_anonymous_announce_lands`]).
// ---------------------------------------------------------------------------

/// A Home member that is not this daemon: its agent keys and the machine
/// its authenticated binding names once a test binds it.
struct RemoteMember {
    kp: x0x::identity::AgentKeypair,
    hex: String,
    machine: x0x::identity::MachineKeypair,
}

impl RemoteMember {
    fn generate() -> Result<Self> {
        let kp = x0x::identity::AgentKeypair::generate()?;
        let hex = hex::encode(kp.agent_id().as_bytes());
        Ok(Self {
            kp,
            hex,
            machine: x0x::identity::MachineKeypair::generate()?,
        })
    }

    /// The discovery entry an announce from this member's machine leaves:
    /// `cert` resolved (or none), committing to `cert_digest`.
    fn entry(
        &self,
        cert: Option<&x0x::identity::AgentCertificate>,
        cert_digest: [u8; 32],
        announced_at: u64,
    ) -> x0x::DiscoveredAgent {
        x0x::DiscoveredAgent {
            self_name: None,
            agent_id: self.kp.agent_id(),
            machine_id: self.machine.machine_id(),
            user_id: cert.and_then(|cert| cert.user_id().ok()),
            addresses: Vec::new(),
            announced_at,
            last_seen: x0x::groups::owner_cert::restore_clock_now(),
            machine_public_key: self.machine.public_key().as_bytes().to_vec(),
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            cert_not_after: cert.and_then(x0x::identity::AgentCertificate::not_after),
            agent_certificate: cert.cloned(),
            agent_public_key: self.kp.public_key().as_bytes().to_vec(),
            cert_digest: Some(cert_digest),
        }
    }

    /// Bind this member to `machine` as its direct-origin announce (or an
    /// origin attestation) would, with that announce's certificate expiry.
    async fn bind(
        &self,
        state: &AppState,
        machine: x0x::identity::MachineId,
        announced_at: u64,
        cert_not_after: Option<u64>,
    ) {
        state
            .agent
            .record_authenticated_binding_with_expiry_for_testing(
                self.kp.agent_id(),
                machine,
                announced_at,
                cert_not_after,
            )
            .await;
    }
}

/// A committed Home of this daemon and one remote member, each seat
/// embedding a valid owner certificate. The member has no discovery entry
/// and no machine binding yet.
async fn remote_member_home(
    state: &AppState,
    owner: &x0x::identity::UserKeypair,
    suffix: &str,
) -> Result<(String, x0x::groups::GroupInfo, RemoteMember)> {
    let local_cert =
        x0x::identity::AgentCertificate::issue(owner, state.agent.identity().agent_keypair())?;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    install_discovery_cert(state, &state.agent, &local_cert).await;
    let member = RemoteMember::generate()?;
    let member_cert = x0x::identity::AgentCertificate::issue(owner, &member.kp)?;
    let (home_key, info) = committed_home_group(
        state,
        owner,
        suffix,
        &[
            (local_hex, &local_cert, true),
            (member.hex.clone(), &member_cert, true),
        ],
    )
    .await?;
    Ok((home_key, info, member))
}

/// A committed Home of this daemon and one remote member that is RENEWING:
/// the member's seat embeds (and commits) a certificate that has expired,
/// and its bound machine has announced a renewal, a certificate-bearing
/// digest whose bytes have not resolved here yet. That member is InGrace
/// (a fetch in flight), before and after ADR 0108 S2-1.
///
/// The fixture's own seal needs the member Clean, so its valid
/// certificate resolves here at seal time; the renewal announce then
/// replaces it in discovery.
async fn renewing_home(
    state: &AppState,
    owner: &x0x::identity::UserKeypair,
    suffix: &str,
) -> Result<(String, x0x::groups::GroupInfo, RemoteMember)> {
    let now = x0x::groups::owner_cert::restore_clock_now();
    let local_cert =
        x0x::identity::AgentCertificate::issue(owner, state.agent.identity().agent_keypair())?;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    install_discovery_cert(state, &state.agent, &local_cert).await;
    let member = RemoteMember::generate()?;
    let user = Some(owner.user_id());
    let valid = x0x::identity::AgentCertificate::issue(owner, &member.kp)?;
    let expired = x0x::identity::AgentCertificate::issue_with_expiry(owner, &member.kp, Some(1))?;
    let renewal =
        x0x::identity::AgentCertificate::issue_with_expiry(owner, &member.kp, Some(now + 86_400))?;
    state.agent.identity_discovery_cache().write().await.insert(
        member.kp.agent_id(),
        member.entry(
            Some(&valid),
            x0x::announce_v3::cert_digest(&user, &Some(valid.clone())),
            now - 100,
        ),
    );
    let (home_key, info) = committed_home_group(
        state,
        owner,
        suffix,
        &[
            (local_hex, &local_cert, true),
            (member.hex.clone(), &expired, true),
        ],
    )
    .await?;
    // The renewal: the member's direct-origin announce binds it to its
    // machine and commits to the renewal's digest; the bytes are in flight.
    member
        .bind(state, member.machine.machine_id(), now - 50, None)
        .await;
    state
        .agent
        .insert_discovered_agent_for_testing(member.entry(
            None,
            x0x::announce_v3::cert_digest(&user, &Some(renewal)),
            now - 50,
        ))
        .await;
    let status = member_status(state, &info, &member.hex).await;
    assert!(
        matches!(
            status,
            x0x::groups::owner_cert::MemberCertStatus::InGrace { .. }
        ),
        "fixture: the renewal is in flight, got {status:?}"
    );
    Ok((home_key, info, member))
}

/// `member_hex`'s status in the seal's verdict over `info`, evaluated on a
/// clone (the verdict stamps grace).
async fn member_status(
    state: &AppState,
    info: &x0x::groups::GroupInfo,
    member_hex: &str,
) -> x0x::groups::owner_cert::MemberCertStatus {
    let evidence = owner_cert_seal_evidence(state, info).await;
    info.clone()
        .owner_cert_verdict(&evidence)
        .per_member
        .get(member_hex)
        .cloned()
        .expect("an active member")
}

/// The live record of `home_key`.
async fn live_home(state: &AppState, home_key: &str) -> Result<x0x::groups::GroupInfo> {
    state
        .named_groups
        .read()
        .await
        .get(home_key)
        .cloned()
        .context("the Home")
}

/// EVICTION SITE: the explicit seal route on the live record refuses,
/// retryable, and `member_hex` stays seated.
async fn eviction_path_keeps(
    state: &Arc<AppState>,
    home_key: &str,
    local_hex: &str,
    member_hex: &str,
) -> Result<()> {
    match owner_certified_seal_with_eviction(state, home_key, local_hex)
        .await
        .context("an OwnerCertified group takes the eviction path")?
    {
        Ok((_, evicted, _)) => anyhow::bail!("the eviction path sealed, evicting {evicted:?}"),
        Err((status, body)) => {
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "a retryable refusal: {body:?}"
            );
        }
    }
    assert!(
        live_home(state, home_key)
            .await?
            .has_active_member(member_hex),
        "the member stays seated"
    );
    Ok(())
}

/// THE FINDING, ingress to eviction. A renewing Home member (expired seat
/// bytes, renewal in flight) is InGrace. A third machine signs an anonymous
/// announce naming it; the real listener refuses it as a binding source
/// (the binding still names the member's machine) and caches it for
/// discovery. It is no absence signal: the member stays InGrace (today's
/// fetch-in-flight rule) and the eviction path keeps it seated. With the
/// S2-1 rule unguarded the forged digest read as no disclosure, so the
/// member was Failed(Expired) and the next seal evicted it.
///
/// Then routing reconciles the entry's machine id to the member's bound
/// machine (the connector rewrites `machine_id` to whatever machine is
/// connected). The machine key the announce carried still names the
/// forger, so nothing changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_anonymous_announce_keeps_a_renewing_home_member_in_grace() -> Result<()> {
    let plane = format!("r19-home-forged-{}", rand::random::<u32>());
    let dir = tempfile::tempdir()?;
    let state = announce_writer_state(dir.path(), &plane).await?;
    let owner = x0x::identity::UserKeypair::generate()?;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (home_key, info, member) = renewing_home(&state, &owner, &plane).await?;
    let in_grace = |status: &x0x::groups::owner_cert::MemberCertStatus| {
        matches!(
            status,
            x0x::groups::owner_cert::MemberCertStatus::InGrace { .. }
        )
    };

    let forger = x0x::identity::MachineKeypair::generate()?;
    relayed_anonymous_announce_lands(&state, &member.kp, &forger).await?;
    assert_eq!(
        bound_machine(&state, member.kp.agent_id()).await,
        Some(member.machine.machine_id()),
        "the listener did not take the forged announce as a binding"
    );
    let evidence = owner_cert_seal_evidence(&state, &info).await;
    assert_eq!(
        evidence.digest_for(&member.hex),
        Some(x0x::announce_v3::anonymous_cert_digest()),
        "the forged anonymous digest reached the seal evidence"
    );
    assert!(evidence.cert_for(&member.hex).is_none());
    let status = member_status(&state, &info, &member.hex).await;
    assert!(
        in_grace(&status),
        "a forged anonymous announce must not end the renewal's grace, got {status:?}"
    );
    state
        .named_groups
        .write()
        .await
        .insert(home_key.clone(), info);
    eviction_path_keeps(&state, &home_key, &local_hex, &member.hex).await?;

    // Routing reconciliation: the entry now names the bound machine.
    if let Some(entry) = state
        .agent
        .identity_discovery_cache()
        .write()
        .await
        .get_mut(&member.kp.agent_id())
    {
        entry.machine_id = member.machine.machine_id();
    }
    let live = live_home(&state, &home_key).await?;
    let status = member_status(&state, &live, &member.hex).await;
    assert!(
        in_grace(&status),
        "a reconciled machine id does not make the forger's announce the member's, got {status:?}"
    );
    eviction_path_keeps(&state, &home_key, &local_hex, &member.hex).await?;
    state.agent.shutdown().await;
    Ok(())
}

/// The Home rule needs the announce's machine to be the subject's CURRENT
/// authenticated bound machine. Each state below has an anonymous announce
/// signed by the member's machine M in discovery and valid embedded bytes:
/// - no binding at all, a binding whose certificate expiry has passed, a
///   binding that has moved to another machine, an entry whose machine id
///   routing has rewritten to another machine, or M revoked: today's rule
///   (InGrace), so the seal refuses with `OwnerCertMemberPending` and the
///   ADR 0107 serving guard withholds;
/// - a current binding to M: the Home rule (Clean), so the seal succeeds
///   and the guard serves.
///
/// With the S2-1 rule unguarded every state read as the Home rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anonymous_announce_needs_a_current_bound_machine() -> Result<()> {
    let plane = format!("r19-home-binding-{}", rand::random::<u32>());
    let dir = tempfile::tempdir()?;
    let state = announce_writer_state(dir.path(), &plane).await?;
    let owner = x0x::identity::UserKeypair::generate()?;
    let (home_key, info, member) = remote_member_home(&state, &owner, &plane).await?;
    state
        .named_groups
        .write()
        .await
        .insert(home_key.clone(), info);
    relayed_anonymous_announce_lands(&state, &member.kp, &member.machine).await?;
    let now = x0x::groups::owner_cert::restore_clock_now();
    let m = member.machine.machine_id();

    // Every verdict site, on the live record (the seal on a working copy).
    let sites = async |case: &str, bound: bool| -> Result<()> {
        let live = live_home(&state, &home_key).await?;
        let status = member_status(&state, &live, &member.hex).await;
        let mut working = live;
        let seal = seal_commit_owner_certified(
            &state,
            &mut working,
            state.agent.identity().agent_keypair(),
            now_millis_u64(),
        )
        .await;
        let serving = join_artifact_serving_refusal(&state, &home_key, &member.hex).await;
        if bound {
            assert_eq!(
                status,
                x0x::groups::owner_cert::MemberCertStatus::Clean,
                "[{case}]"
            );
            assert!(seal.is_ok(), "[{case}] the seal succeeds: {seal:?}");
            assert_eq!(serving, None, "[{case}] the guard serves");
        } else {
            assert!(
                matches!(
                    status,
                    x0x::groups::owner_cert::MemberCertStatus::InGrace { .. }
                ),
                "[{case}] today's rule, got {status:?}"
            );
            assert!(
                matches!(
                    &seal,
                    Err(x0x::groups::state_commit::ApplyError::OwnerCertMemberPending { members, .. })
                        if *members == vec![member.hex.clone()]
                ),
                "[{case}] the seal refuses: {seal:?}"
            );
            assert_eq!(
                serving,
                Some(JoinArtifactRefusal::CertificateInGrace),
                "[{case}] the guard withholds"
            );
        }
        Ok(())
    };

    assert_eq!(bound_machine(&state, member.kp.agent_id()).await, None);
    sites("no binding", false).await?;
    member.bind(&state, m, now + 1, Some(1)).await;
    sites("binding certificate expired", false).await?;
    let other = x0x::identity::MachineKeypair::generate()?;
    member.bind(&state, other.machine_id(), now + 2, None).await;
    sites("binding moved to another machine", false).await?;
    member.bind(&state, m, now + 3, None).await;
    sites("current binding", true).await?;
    let entry_machine = async |machine: x0x::identity::MachineId| {
        if let Some(entry) = state
            .agent
            .identity_discovery_cache()
            .write()
            .await
            .get_mut(&member.kp.agent_id())
        {
            entry.machine_id = machine;
        }
    };
    entry_machine(other.machine_id()).await;
    sites("entry machine id rewritten to another machine", false).await?;
    entry_machine(m).await;
    sites("entry machine id back on the bound machine", true).await?;
    let revocation = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Machine(m),
        member.machine.public_key(),
        member.machine.secret_key(),
        now,
        Some("r19 bound machine revoked".to_string()),
    )?;
    state
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(revocation, None)?;
    sites("bound machine revoked", false).await?;
    state.agent.shutdown().await;
    Ok(())
}

/// Positive control: ADR 0108 §4 as written still holds for the subject's
/// own machine. The same relayed anonymous announce, signed by the
/// member's current bound machine, is the member's own absence signal:
/// valid embedded bytes are Clean, and expired ones are Failed(Expired)
/// with no grace (the eviction set) even with a renewal in flight. That is
/// the ADR's stated residual: an anonymous announce after re-issue erases
/// the rotation signal, and now only the member's own machine can send it.
///
/// The direct-origin source of a binding is the real listener: this
/// daemon's own anonymous announce binds it to its own machine, and the
/// entry's machine key derives that machine. That is the W3-H #1143 path,
/// where A ingests O's own announce. (Checked last: the announce's
/// copies can still be landing, and the fixtures' first seals run before
/// their groups are Home scope.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bound_machine_anonymous_announce_applies_the_home_rule() -> Result<()> {
    let plane = format!("r19-home-bound-{}", rand::random::<u32>());
    let dir = tempfile::tempdir()?;
    let state = announce_writer_state(dir.path(), &plane).await?;
    let owner = x0x::identity::UserKeypair::generate()?;

    // Valid embedded bytes: Clean.
    let (_, info, member) = remote_member_home(&state, &owner, &format!("{plane}-valid")).await?;
    let now = x0x::groups::owner_cert::restore_clock_now();
    member
        .bind(&state, member.machine.machine_id(), now, None)
        .await;
    relayed_anonymous_announce_lands(&state, &member.kp, &member.machine).await?;
    assert_eq!(
        member_status(&state, &info, &member.hex).await,
        x0x::groups::owner_cert::MemberCertStatus::Clean
    );

    // Expired embedded bytes with a renewal in flight: Failed(Expired).
    let (_, info, member) = renewing_home(&state, &owner, &format!("{plane}-expired")).await?;
    relayed_anonymous_announce_lands(&state, &member.kp, &member.machine).await?;
    assert_eq!(
        bound_machine(&state, member.kp.agent_id()).await,
        Some(member.machine.machine_id())
    );
    let evidence = owner_cert_seal_evidence(&state, &info).await;
    assert_eq!(
        info.clone().owner_cert_verdict(&evidence).failed(),
        vec![(
            member.hex.clone(),
            x0x::groups::owner_cert::OwnerCertFailure::Expired
        )],
        "the member's own anonymous announce is no disclosure: expired bytes fail"
    );

    // Direct origin, through the real listener.
    anonymous_announce_lands(&state.agent).await?;
    assert_eq!(
        bound_machine(&state, state.agent.agent_id()).await,
        Some(state.agent.machine_id()),
        "a direct-origin announce binds its agent to its machine"
    );
    let own = state
        .agent
        .discovered_agent_for_testing(&state.agent.agent_id())
        .await
        .context("this daemon's own entry")?;
    let own_key = ant_quic::MlDsaPublicKey::from_bytes(&own.machine_public_key)
        .map_err(|error| anyhow::anyhow!("own machine key: {error:?}"))?;
    assert_eq!(
        x0x::identity::MachineId::from_public_key(&own_key),
        state.agent.machine_id()
    );
    assert_eq!(own.machine_id, state.agent.machine_id());
    state.agent.shutdown().await;
    Ok(())
}

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

/// Synthetic discovery evidence for the mechanism control and the offline
/// owner-device fixture below. Never use this to replace a live identity's
/// certificate: its next V3 announcement can invalidate the entry (#1132).
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
    let owner_seed = rand::random::<[u8; 32]>();
    let owner = x0x::identity::UserKeypair::from_seed(&owner_seed)?;
    let (a, _a_dir) = networked_owner_test_state(&format!("r19-a-{run}"), &owner_seed).await?;
    let (c, _c_dir) = networked_owner_test_state(&format!("r19-c-{run}"), &owner_seed).await?;
    let a_hex = hex::encode(a.agent.agent_id().as_bytes());
    let c_hex = hex::encode(c.agent.agent_id().as_bytes());
    let a_cert = a.agent.agent_certificate().context("A owner cert")?.clone();
    let c_cert = c.agent.agent_certificate().context("C owner cert")?.clone();
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
    announce_owner_cert_to(&c.agent, &c.agent).await?;
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
                if members == &vec![a_hex.clone()]
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
            intervening_events: Vec::new(),
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

    // Exercise another real announcement before sealing. The local identity,
    // roster and announce now agree; no last-moment cache reinstall is needed.
    // First/delayed/heartbeat/reconnect writers all remain enabled (#1132).
    announce_owner_cert_to(&c.agent, &c.agent).await?;
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
        intervening_events: Vec::new(),
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
    creator_offline_scenario_on_plane(promotion, false, 0, false, false).await
}

async fn creator_offline_scenario_on_plane(
    promotion: Promotion,
    home_treekem: bool,
    extra_seats: usize,
    legacy_sidecar: bool,
    recover: bool,
) -> Result<CreatorOfflineScenario> {
    let seed: [u8; 32] = rand::random();
    let owner = x0x::identity::UserKeypair::from_seed(&seed)?;
    let (creator, _creator_dir, creator_cert) = owner_device_state(&seed).await?;
    let (admin, admin_dir, admin_cert) = owner_device_state(&seed).await?;
    let creator_hex = hex::encode(creator.agent.agent_id().as_bytes());
    let admin_hex = hex::encode(admin.agent.agent_id().as_bytes());
    let mut group_id = hex::encode(rand::random::<[u8; 32]>());

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
    for _ in 0..extra_seats {
        let key = x0x::identity::AgentKeypair::generate()?;
        let id = hex::encode(key.agent_id().as_bytes());
        base.add_member(id.clone(), x0x::groups::GroupRole::Member, None, None);
        base.set_member_certificate(&id, x0x::identity::AgentCertificate::issue(&owner, &key)?)
            .expect("extra certificate binds its seat");
    }
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

    let prepared = if home_treekem {
        creator.named_groups.write().await.remove(&group_id);
        super::super::super::home::provision_home(&creator).await;
        let (_, home) = super::super::super::home::find_home(&creator, &owner.user_id())
            .await
            .expect("provisioned Home");
        base = home;
        group_id = base.mls_group_id.clone();
        assert_eq!(base.secure_plane, x0x::mls::SecureGroupPlane::TreeKem);
        let seed = agent_treekem_seed(&admin.agent, &hex::decode(&group_id)?);
        Some(x0x::mls::TreeKemMlsGroup::prepare_member(
            admin.agent.agent_id(),
            &seed,
        )?)
    } else {
        None
    };

    // (2) The admin-to-be's stub: the creator's seat is digest-only.
    let mut stub = base.clone();
    for seat in stub.members_v2.values_mut() {
        seat.certificate = None;
    }
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
            treekem_key_package_b64: prepared
                .as_ref()
                .map(|p| BASE64.encode(p.key_package_bytes())),
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "the creator admits");
    let mut seat_event = creator
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
    if extra_seats > 0 {
        let NamedGroupMetadataEvent::MemberAdded {
            roster_certificates_b64,
            ..
        } = &mut seat_event
        else {
            panic!("seat event")
        };
        if !legacy_sidecar {
            assert!(
                roster_certificates_b64.len() < extra_seats + 1,
                "the production builder really trimmed the large group's sidecar"
            );
        }
        if legacy_sidecar {
            roster_certificates_b64.clear();
        }
    }
    let served_join_result = join_result_payload_with_roster_certificates(
        &creator,
        &group_id,
        &admin_hex,
        JoinResultMessage::Result {
            event: Box::new(seat_event.clone()),
            chain: Vec::new(),
            head_attestation: None,
            roster_certificates_b64: Vec::new(),
            intervening_events: Vec::new(),
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
    // Deliver the actual staged Welcome inline, without a live creator or
    // a JoinResult when the receiver processes the seat event.
    if home_treekem {
        let NamedGroupMetadataEvent::MemberAdded {
            treekem_welcome_b64,
            welcome_ref,
            roster_certificates_b64,
            ..
        } = &mut seat_event
        else {
            panic!("TreeKEM seat event")
        };
        assert_eq!(
            roster_certificates_b64,
            &vec![cert_b64(&creator_cert)],
            "the separate TreeKEM Home builder attaches the creator certificate"
        );
        let reference = welcome_ref.take().expect("staged Welcome");
        let welcomes = creator.pending_welcomes.read().await;
        let welcome = welcomes.get(&reference.welcome_id).expect("Welcome bytes");
        *treekem_welcome_b64 = Some(BASE64.encode(&welcome.bytes));
    }
    if extra_seats > 0 {
        // Seat from the event ONLY. Never fetch/deliver a JoinResult.
        assert!(
            apply_named_group_metadata_event(
                &admin,
                seat_event.clone(),
                creator.agent.agent_id(),
                true,
                None
            )
            .await
            .accepted
        );
        let missing: Vec<_> = admin
            .named_groups
            .read()
            .await
            .get(&group_id)
            .expect("group")
            .active_members()
            .filter(|seat| seat.certificate.is_none())
            .map(|seat| {
                (
                    seat.agent_id.clone(),
                    seat.certificate_digest.clone().expect("digest"),
                )
            })
            .collect();
        assert!(
            !missing.is_empty(),
            "trimmed seats remain digest-only until fetched"
        );
        for (_, digest) in &missing {
            assert!(
                admin
                    .cert_fetch_requested
                    .lock()
                    .expect("requests")
                    .contains_key(digest),
                "admission must request every omitted certificate BEFORE the first seal"
            );
        }
        if recover {
            // Deterministic transport harness: exercise both #946 handlers.
            // Only the authority holds omitted bytes, solely on roster seats.
            for (member, digest) in &missing {
                let request = serde_json::to_vec(&seat_cert_fetch::GroupCertFetchRequest {
                    group_id: group_id.clone(),
                    cert_digest: digest.clone(),
                    requester: admin_hex.clone(),
                })?;
                assert!(
                    seat_cert_fetch::handle_group_cert_fetch_request(
                        &creator,
                        &request,
                        Some(&admin.agent.agent_id()),
                        true,
                        &group_id
                    )
                    .await
                );
                let cert = creator
                    .named_groups
                    .read()
                    .await
                    .get(&group_id)
                    .expect("group")
                    .members_v2
                    .get(member)
                    .expect("member")
                    .certificate
                    .clone()
                    .expect("bytes");
                let response = serde_json::to_vec(&seat_cert_fetch::GroupCertFetchResponse {
                    group_id: group_id.clone(),
                    cert_digest: digest.clone(),
                    cert_json_b64: BASE64.encode(serde_json::to_vec(&cert)?),
                })?;
                assert!(
                    seat_cert_fetch::handle_group_cert_fetch_response(
                        &admin, &response, true, &group_id
                    )
                    .await
                );
            }
        }
    }
    let creator_id = creator.agent.agent_id();
    creator.agent.shutdown().await;
    drop(creator);

    // (4) The admin is seated by the seat event alone.
    if extra_seats == 0 {
        let applied =
            apply_named_group_metadata_event(&admin, seat_event.clone(), creator_id, true, None)
                .await;
        assert!(applied.accepted, "the seat event seats the admin");
    }

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

/// Exercises the separate TreeKEM Home builder and the real signed promotion.
/// Runtime execution belongs to isolated Linux CI, never the macOS host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn treekem_home_promoted_admin_seals_while_creator_offline() -> Result<()> {
    let s =
        creator_offline_scenario_on_plane(Promotion::SignedCommit, true, 0, false, false).await?;
    assert!(
        s.admin
            .treekem_groups
            .read()
            .await
            .contains_key(&s.group_id),
        "the receiver installed its own TreeKEM Welcome"
    );
    assert!(seat_has_bytes(&s.admin, &s.group_id, &s.creator_hex).await);
    let commit = promoted_admin_seals_new_joiner(&s, &[]).await?;
    assert!(!commit.roster_root.is_empty());
    s.admin.agent.shutdown().await;
    Ok(())
}

/// Legacy MemberAdded events have no sidecar, but still need the same
/// post-apply certificate recovery as a trimmed event. Pure wire unit test.
#[test]
fn legacy_member_added_retains_certificate_recovery_context() {
    let event: NamedGroupMetadataEvent = serde_json::from_value(serde_json::json!({
        "event": "member_added", "group_id": "group", "revision": 1,
        "actor": "creator", "agent_id": "joiner", "display_name": null
    }))
    .expect("legacy event");
    assert_eq!(
        seat_cert_fetch::member_added_sidecar(&event),
        Some(seat_cert_fetch::MemberAddedCertificates {
            group_id: "group".to_string(),
            certificates: Vec::new(),
            seated_member: "joiner".to_string(),
            roster_root: None,
        }),
        "an empty legacy sidecar must not skip post-apply recovery"
    );
}

/// Red before the fix: seating does not request the trimmed certificates.
/// With recovery during admission, all other holders can leave before seal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trimmed_member_added_recovers_before_creator_offline_seal() -> Result<()> {
    let s =
        creator_offline_scenario_on_plane(Promotion::SignedCommit, false, 15, false, true).await?;
    assert!(!promoted_admin_seals_new_joiner(&s, &[])
        .await?
        .roster_root
        .is_empty());
    s.admin.agent.shutdown().await;
    Ok(())
}

/// A 0.45 / pre-#1025 authority omits the sidecar altogether.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_member_added_recovers_before_creator_offline_seal() -> Result<()> {
    let s =
        creator_offline_scenario_on_plane(Promotion::SignedCommit, false, 12, true, true).await?;
    assert!(!promoted_admin_seals_new_joiner(&s, &[])
        .await?
        .roster_root
        .is_empty());
    s.admin.agent.shutdown().await;
    Ok(())
}

/// No receiver can recover bytes after their last holder disappears.
/// Keep the fail-closed seal and bounded retry deadline in this case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trimmed_member_added_all_holders_offline_stays_pending() -> Result<()> {
    let s =
        creator_offline_scenario_on_plane(Promotion::SignedCommit, false, 15, false, false).await?;
    let err = promoted_admin_seals_new_joiner(&s, &[])
        .await
        .expect_err("no holder answered");
    assert!(matches!(
        err,
        x0x::groups::state_commit::ApplyError::OwnerCertMemberPending { .. }
    ));
    assert!(!seat_cert_fetch::cert_evidence_deadline_elapsed(
        &s.admin,
        &s.group_id,
        "next",
        "attempt"
    ));
    let key = seat_cert_fetch::cert_evidence_stamp_key(&s.group_id, "next");
    s.admin
        .cert_unresolvable_since
        .lock()
        .expect("deadlines")
        .get_mut(&key)
        .expect("stamp")
        .first_ms = now_millis_u64() - seat_cert_fetch::CERT_EVIDENCE_DEADLINE_MS;
    assert!(seat_cert_fetch::cert_evidence_deadline_elapsed(
        &s.admin,
        &s.group_id,
        "next",
        "attempt"
    ));
    s.admin.agent.shutdown().await;
    Ok(())
}
