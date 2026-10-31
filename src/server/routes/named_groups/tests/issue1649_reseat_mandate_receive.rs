//! #1649: ADR 0109 §3a receiver evidence on the real receive path.
//!
//! The #1533 review left the §3a receiver unproven end to end: the pure
//! verifier tests cover `verify_reseat_mandate` and the route tests the
//! issuer, but nothing drove a forged or tampered `ReseatMandateV1` through
//! `verify_reseat_mandate_on_receive`, which runs a real
//! `verify_cert_against_owner` on a real receiver.
//!
//! Two daemons, in process (no socket, no network config): the admin `A`
//! whose re-seat commit the mandate blesses, and a member receiver `R`
//! holding the real parent chain — the subject's seating commit and `A`'s
//! removal commit. The mandate-carrying `MemberAdded` travels the
//! production DM lane (`DirectMessaging::handle_incoming` →
//! `run_direct_metadata_listener` → the shielded apply) with the JSON
//! payload `spawn_named_group_event_delivery` sends; each bad mandate also
//! goes through the listener's own apply entry, for the typed refusal cause
//! and a byte-identical committed record.

use super::*;

use crate::groups::owner_cert::OwnerCertEvidence;
use crate::groups::policy::{GroupAdmission, GroupPolicy};
use crate::groups::recovery::{
    genesis_hash, invite_secret_hash, ReseatMandateFields, ReseatMandateV1,
};
use crate::groups::{GroupConfidentiality, GroupDiscoverability};
use crate::identity::{AgentCertificate, AgentKeypair, UserKeypair};

/// How long a DM-lane test waits for an apply the lane must make.
const WAIT: Duration = Duration::from_secs(10);
/// How long it then watches the queued events behind that apply.
const QUIET: Duration = Duration::from_millis(300);

/// The two daemons and the §3a parent chain the receiver holds.
struct Stage {
    receiver: Arc<AppState>,
    admin: Arc<AppState>,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
    group_id: String,
    admin_hex: String,
    subject_hex: String,
    subject_kp: AgentKeypair,
    /// The second admin of [`stage_with_peer_removal`], with its keypair
    /// for the D170 control.
    peer_kp: Option<AgentKeypair>,
    subject_cert: AgentCertificate,
    /// The post-removal record `R` holds (the parent of the re-seat).
    parent: x0x::groups::GroupInfo,
    seating_hash: String,
    removal_hash: String,
    /// The re-seat seat-write the terminal commit covers.
    next: x0x::groups::GroupInfo,
    terminal: x0x::groups::GroupStateCommit,
}

/// Seat `agent_hex` as a Member with its committed certificate.
fn seat_member(
    info: &mut x0x::groups::GroupInfo,
    agent_hex: &str,
    admin_hex: &str,
    cert: &AgentCertificate,
) {
    info.add_member(
        agent_hex.to_string(),
        x0x::groups::GroupRole::Member,
        Some(admin_hex.to_string()),
        None,
    );
    assert!(info.set_member_certificate(agent_hex, cert.clone()).is_ok());
}

fn owner_certified_policy(owner: &UserKeypair) -> GroupPolicy {
    GroupPolicy {
        discoverability: GroupDiscoverability::Hidden,
        admission: GroupAdmission::OwnerCertified(owner.user_id()),
        confidentiality: GroupConfidentiality::MlsEncrypted,
        read_access: x0x::groups::GroupReadAccess::MembersOnly,
        write_access: x0x::groups::GroupWriteAccess::MembersOnly,
    }
}

/// Seal with the owner-certificate evidence (ADR-0038); retains the commit.
fn sealed(
    info: &mut x0x::groups::GroupInfo,
    admin: &AgentKeypair,
    certs: &[(String, AgentCertificate)],
    at: u64,
) -> x0x::groups::GroupStateCommit {
    let mut evidence = OwnerCertEvidence::new(x0x::groups::owner_cert::restore_clock_now());
    for (agent, cert) in certs {
        evidence.insert_cert(agent.clone(), cert.clone());
    }
    let verdict = info.owner_cert_verdict(&evidence);
    info.seal_commit_with_owner_certs(admin, at, &verdict)
        .expect("owner-certified seal")
        .0
}

async fn stage() -> Result<Stage> {
    stage_with_peer_removal(false).await
}

/// [`stage`] with the removal committed by a second admin (D170's shape):
/// a peer is seated as an Admin beside the receiver and the subject, and
/// the peer — not the group's creator — seals the removal commit.
async fn stage_with_peer_removal(peer_removal: bool) -> Result<Stage> {
    let (receiver, dir_r) = secure_endpoint_test_state_with_key(AgentKeypair::generate()?).await?;
    let (admin, dir_a) = secure_endpoint_test_state_with_key(AgentKeypair::generate()?).await?;
    let owner = UserKeypair::generate()?;
    let subject_kp = AgentKeypair::generate()?;
    let subject_hex = hex::encode(subject_kp.agent_id().as_bytes());
    let admin_hex = hex::encode(admin.agent.agent_id().as_bytes());
    let receiver_hex = hex::encode(receiver.agent.agent_id().as_bytes());
    let admin_kp = admin.agent.identity().agent_keypair();
    let admin_cert = AgentCertificate::issue(&owner, admin_kp)?;
    let receiver_cert = AgentCertificate::issue(&owner, receiver.agent.identity().agent_keypair())?;
    let subject_cert = AgentCertificate::issue(&owner, &subject_kp)?;
    let peer_kp = AgentKeypair::generate()?;
    let peer_hex = hex::encode(peer_kp.agent_id().as_bytes());
    let peer_cert = AgentCertificate::issue(&owner, &peer_kp)?;
    let group_id = "a9".repeat(32);
    let mut info = x0x::groups::GroupInfo::with_policy(
        "issue 1649 reseat receiver".to_string(),
        String::new(),
        admin.agent.agent_id(),
        group_id.clone(),
        owner_certified_policy(&owner),
    );
    seat_member(&mut info, &receiver_hex, &admin_hex, &receiver_cert);
    seat_member(&mut info, &subject_hex, &admin_hex, &subject_cert);
    assert!(info
        .set_member_certificate(&admin_hex, admin_cert.clone())
        .is_ok());
    let mut certs = vec![
        (admin_hex.clone(), admin_cert),
        (receiver_hex, receiver_cert),
        (subject_hex.clone(), subject_cert.clone()),
    ];
    if peer_removal {
        info.add_member(
            peer_hex.clone(),
            x0x::groups::GroupRole::Admin,
            Some(admin_hex.clone()),
            None,
        );
        assert!(info
            .set_member_certificate(&peer_hex, peer_cert.clone())
            .is_ok());
        certs.push((peer_hex.clone(), peer_cert));
    }
    // Seating (r1): the subject active on the retained roster.
    sealed(&mut info, admin_kp, &certs, 1_000);
    let seating_hash = info.state_hash.clone();
    // Removal (r2): the admin's own removal commit, the §3a `Removal`
    // basis — or, for D170, the peer admin's, remover and signer alike.
    info.remove_member(
        &subject_hex,
        Some(if peer_removal {
            peer_hex.clone()
        } else {
            admin_hex.clone()
        }),
    );
    let removal_signer = if peer_removal { &peer_kp } else { admin_kp };
    sealed(&mut info, removal_signer, &certs, 2_000);
    let removal_hash = info.state_hash.clone();
    receiver
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info.clone());
    // The re-seat terminal (r3): the subject back as Member, committed by
    // the admin, exactly the write the apply's mutation performs.
    let mut next = info.clone();
    seat_member(&mut next, &subject_hex, &admin_hex, &subject_cert);
    let terminal = terminal_commit(&info, &next, admin_kp, 3_000);
    Ok(Stage {
        receiver,
        admin,
        _dirs: (dir_r, dir_a),
        group_id,
        admin_hex,
        subject_hex,
        subject_kp,
        peer_kp: peer_removal.then_some(peer_kp),
        subject_cert,
        parent: info,
        seating_hash,
        removal_hash,
        next,
        terminal,
    })
}

/// The re-seat terminal over the parent and the seat-write, at `at`.
fn terminal_commit(
    parent: &x0x::groups::GroupInfo,
    next: &x0x::groups::GroupInfo,
    admin_kp: &AgentKeypair,
    at: u64,
) -> x0x::groups::GroupStateCommit {
    x0x::groups::GroupStateCommit::sign(
        parent.stable_group_id().to_string(),
        parent.state_revision.saturating_add(1),
        Some(parent.state_hash.clone()),
        x0x::groups::state_commit::compute_roster_root(&next.members_v2),
        x0x::groups::compute_policy_hash(&next.policy),
        x0x::groups::compute_public_meta_hash(&next.public_meta()),
        next.security_binding.clone(),
        false,
        at,
        admin_kp,
    )
    .expect("re-seat terminal commit")
}

/// The §3a fields the seal binds, in `reseat_mandate_for_seat` order.
fn mandate_fields(stage: &Stage) -> ReseatMandateFields {
    let owner = stage
        .parent
        .policy
        .admission
        .owner_certified_user_id()
        .map(|owner| hex::encode(owner.as_bytes()))
        .expect("owner axis");
    ReseatMandateFields {
        owner_user_id: owner,
        group_id: stage.parent.stable_group_id().to_string(),
        genesis_hash: genesis_hash(&stage.parent),
        signer: stage.admin_hex.clone(),
        subject: stage.subject_hex.clone(),
        seating_commit_hash: stage.seating_hash.clone(),
        removal_commit_hash: stage.removal_hash.clone(),
        parent_commit_hash: stage.parent.state_hash.clone(),
        terminal_roster_hash: x0x::groups::state_commit::compute_roster_root(
            &stage.next.members_v2,
        ),
        invite_secret_hash: invite_secret_hash("issue-1649-reseat-invite"),
        authorisation_digest: "00".repeat(32),
        key_package_hash: String::new(),
        epoch: 0,
        certificate_digest: crate::groups::owner_cert::certificate_digest_hex(&stage.subject_cert),
        policy_hash: x0x::groups::compute_policy_hash(&stage.parent.policy),
        role: x0x::groups::GroupRole::Member,
    }
}

fn mint(fields: ReseatMandateFields, signer: &AgentKeypair) -> ReseatMandateV1 {
    ReseatMandateV1::sign(fields, signer).expect("sign mandate")
}

/// The valid mandate, and the forged, tampered and wrong-owner shapes.
#[allow(clippy::type_complexity)]
fn mandates(
    stage: &Stage,
) -> (
    ReseatMandateV1,
    ReseatMandateV1,
    ReseatMandateV1,
    ReseatMandateV1,
) {
    let admin_kp = stage.admin.agent.identity().agent_keypair();
    let valid = mint(mandate_fields(stage), admin_kp);
    // Forged: an impostor signs its own mandate, then re-attributes it to
    // the admin after the signature.
    let impostor = AgentKeypair::generate().expect("impostor key");
    let mut fields = mandate_fields(stage);
    fields.signer = hex::encode(impostor.agent_id().as_bytes());
    let mut forged = mint(fields, &impostor);
    forged.fields.signer = stage.admin_hex.clone();
    // Tampered: the valid mandate with a signed field changed after the
    // signature.
    let mut tampered = valid.clone();
    tampered.fields.removal_commit_hash = "ee".repeat(32);
    // Wrong owner: properly re-signed by the admin, but binding a foreign
    // owner user.
    let wrong_owner = UserKeypair::generate().expect("foreign owner");
    let mut fields = mandate_fields(stage);
    fields.owner_user_id = hex::encode(wrong_owner.user_id().as_bytes());
    let wrong_owner_mandate = mint(fields, admin_kp);
    (valid, forged, tampered, wrong_owner_mandate)
}

/// A fourth bad shape: re-signed by the admin, binding the digest of a
/// certificate a DIFFERENT owner issued for the subject. Over the DM lane
/// the committed certificate is still the real owner's (the ADR-0038
/// ingress gate refuses a foreign one first), so the §3a check refuses the
/// digest mismatch; called with the foreign certificate itself, the same
/// rule runs a real `verify_cert_against_owner` and refuses that instead.
fn wrong_owner_certificate_mandate(stage: &Stage) -> (ReseatMandateV1, AgentCertificate) {
    let foreign = UserKeypair::generate().expect("foreign cert owner");
    let cert = AgentCertificate::issue(&foreign, &stage.subject_kp).expect("foreign cert");
    let mut fields = mandate_fields(stage);
    fields.certificate_digest = crate::groups::owner_cert::certificate_digest_hex(&cert);
    (
        mint(fields, stage.admin.agent.identity().agent_keypair()),
        cert,
    )
}

fn member_added(
    stage: &Stage,
    mandate: ReseatMandateV1,
    commit: &x0x::groups::GroupStateCommit,
    key_package_hash: Option<&str>,
) -> NamedGroupMetadataEvent {
    member_added_with(stage, mandate, commit, key_package_hash, None, None)
}

/// [`member_added`] with the carried recovery record and the event's
/// TreeKEM commit supplied.
fn member_added_with(
    stage: &Stage,
    mandate: ReseatMandateV1,
    commit: &x0x::groups::GroupStateCommit,
    key_package_hash: Option<&str>,
    member_joined_recovery: Option<NamedGroupMetadataEvent>,
    treekem_commit_b64: Option<&str>,
) -> NamedGroupMetadataEvent {
    use base64::Engine as _;
    NamedGroupMetadataEvent::MemberAdded {
        roster_certificates_b64: Vec::new(),
        group_id: stage.group_id.clone(),
        revision: commit.revision,
        actor: stage.admin_hex.clone(),
        agent_id: stage.subject_hex.clone(),
        display_name: None,
        treekem_commit_b64: treekem_commit_b64.map(str::to_string),
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: key_package_hash.map(str::to_string),
        member_joined_recovery: member_joined_recovery.map(Box::new),
        member_recovery_history: Vec::new(),
        certificate_b64: Some(
            BASE64.encode(bincode::serialize(&stage.subject_cert).expect("cert")),
        ),
        owner_mandate: None,
        commit: Some(commit.clone()),
        reseat_mandate: Some(mandate),
    }
}

async fn live(stage: &Stage) -> x0x::groups::GroupInfo {
    stage
        .receiver
        .named_groups
        .read()
        .await
        .get(&stage.group_id)
        .cloned()
        .expect("receiver holds the group")
}

async fn record_json(stage: &Stage) -> String {
    serde_json::to_string(&live(stage).await).expect("record json")
}

async fn diag_counters(stage: &Stage) -> crate::groups::diagnostics::GroupCounters {
    let groups_snapshot = stage.receiver.named_groups.read().await.clone();
    stage
        .receiver
        .groups_diagnostics
        .snapshot(
            &groups_snapshot,
            &std::collections::HashSet::new(),
            &std::collections::HashSet::new(),
            &std::collections::HashMap::new(),
            stage.receiver.groups_config.mandate_grace_days,
        )
        .groups
        .into_iter()
        .find(|g| g.group_id == stage.group_id)
        .expect("diagnostics row")
        .counters
}

/// The receiver rule the receive path runs, on the real receiver state,
/// with `certificate` as the committed certificate it sees.
async fn receiver_cause(
    stage: &Stage,
    mandate: &ReseatMandateV1,
    certificate: &AgentCertificate,
) -> Result<(), &'static str> {
    receiver_cause_over(
        stage,
        &stage.parent,
        &stage.next,
        &stage.terminal,
        mandate,
        certificate,
        None,
        None,
        None,
    )
    .await
}

/// [`receiver_cause`] over an explicit parent, seat-write and terminal
/// commit, with the event's KeyPackage hash, carried recovery record and
/// TreeKEM commit supplied.
#[allow(clippy::too_many_arguments)]
async fn receiver_cause_over(
    stage: &Stage,
    parent: &x0x::groups::GroupInfo,
    next: &x0x::groups::GroupInfo,
    commit: &x0x::groups::GroupStateCommit,
    mandate: &ReseatMandateV1,
    certificate: &AgentCertificate,
    key_package_hash: Option<&str>,
    member_joined_recovery: Option<&NamedGroupMetadataEvent>,
    treekem_commit_b64: Option<&str>,
) -> Result<(), &'static str> {
    group_recovery::verify_reseat_mandate_on_receive(
        stage.receiver.as_ref(),
        parent,
        next,
        commit,
        mandate,
        &stage.subject_hex,
        key_package_hash,
        None,
        Some(certificate),
        member_joined_recovery,
        treekem_commit_b64,
    )
    .await
}

/// The listener's own apply entry refuses the event, with the typed cause
/// the receiver rule names, and leaves the committed record byte-identical.
async fn refused_unchanged(stage: &Stage, mandate: ReseatMandateV1, expected: &str) -> Result<()> {
    assert_eq!(
        receiver_cause(stage, &mandate, &stage.subject_cert).await,
        Err(expected),
        "the receiver rule must name the {expected} cause"
    );
    let before = record_json(stage).await;
    let applied = apply_listener_metadata_event(
        &stage.receiver,
        member_added(stage, mandate, &stage.terminal, None),
        stage.admin.agent.agent_id(),
        true,
        None,
    )
    .await;
    let result = applied.expect("the shielded apply completes");
    assert!(!result.accepted, "the {expected} mandate must be refused");
    assert_eq!(
        before,
        record_json(stage).await,
        "a refused re-seat leaves the committed record byte-identical"
    );
    assert!(
        !live(stage).await.has_active_member(&stage.subject_hex),
        "the subject stays unseated"
    );
    Ok(())
}

/// Put `event` from the admin daemon on the receiver's DM bus (the
/// production DM ingress).
async fn inject(stage: &Stage, event: &NamedGroupMetadataEvent) -> Result<()> {
    let delivered = stage
        .receiver
        .agent
        .direct_messaging()
        .handle_incoming(
            stage.admin.agent.machine_id(),
            stage.admin.agent.agent_id(),
            serde_json::to_vec(event)?,
            true,
            None,
            None,
        )
        .await;
    anyhow::ensure!(delivered >= 1, "the direct metadata listener is subscribed");
    Ok(())
}

/// Poll until the lane seats the subject, or `WAIT` ends.
async fn wait_seated(stage: &Stage, why: &str) -> Result<()> {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !live(stage).await.has_active_member(&stage.subject_hex) {
        anyhow::ensure!(tokio::time::Instant::now() < deadline, "{why}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

/// Control: the DM lane applies a VALID §3a re-seat, so the refusals below
/// are refusals of the real acceptance path, not of a dead one. The absent
/// counter staying 0 proves the §3a rule accepted the mandate — not the
/// mixed-fleet arm that applies an event with no mandate at all.
#[tokio::test]
async fn a_valid_mandate_reseats_the_subject_over_the_dm_lane() -> Result<()> {
    let stage = stage().await?;
    let (valid, _, _, _) = mandates(&stage);
    let listener = tokio::spawn(run_direct_metadata_listener(
        Arc::clone(&stage.receiver),
        stage.receiver.agent.subscribe_direct(),
    ));
    inject(&stage, &member_added(&stage, valid, &stage.terminal, None)).await?;
    wait_seated(&stage, "the valid re-seat must apply over the DM lane").await?;
    let live = live(&stage).await;
    assert_eq!(live.state_revision, stage.parent.state_revision + 1);
    assert_eq!(live.state_hash, stage.terminal.state_hash);
    assert_eq!(
        diag_counters(&stage).await.owner_mandate_absent,
        0,
        "the §3a rule must accept the mandate, not the absent-mandate arm"
    );
    crate::server::drain_server_tasks(&stage.receiver, vec![listener]).await;
    Ok(())
}

/// The #1649 end-to-end: forged, tampered and wrong-owner mandates travel
/// the real DM lane ahead of the valid one, each on its own terminal
/// commit. Every bad mandate is refused with the committed state unchanged
/// and the lane unwedged (the valid re-seat still applies, so no event is
/// dropped as a chain gap — a wrongly accepted mandate would strand every
/// later event and fail the counter assertion).
#[tokio::test]
async fn bad_mandates_are_refused_over_the_dm_lane_and_only_the_valid_reseat_applies() -> Result<()>
{
    let stage = stage().await?;
    let (valid, forged, tampered, wrong_owner) = mandates(&stage);
    let (wrong_owner_cert, _) = wrong_owner_certificate_mandate(&stage);
    let listener = tokio::spawn(run_direct_metadata_listener(
        Arc::clone(&stage.receiver),
        stage.receiver.agent.subscribe_direct(),
    ));
    let admin_kp = stage.admin.agent.identity().agent_keypair();
    let bad_terminals = [3_100, 3_200, 3_300, 3_400]
        .map(|at| terminal_commit(&stage.parent, &stage.next, admin_kp, at));
    for (mandate, commit) in [forged, tampered, wrong_owner, wrong_owner_cert]
        .into_iter()
        .zip(bad_terminals)
    {
        inject(&stage, &member_added(&stage, mandate, &commit, None)).await?;
    }
    inject(&stage, &member_added(&stage, valid, &stage.terminal, None)).await?;
    wait_seated(
        &stage,
        "the valid re-seat must apply after the refused mandates",
    )
    .await?;
    // Let the events behind the seat finish the lane before reading the
    // record and the counters.
    tokio::time::sleep(QUIET).await;
    let live = live(&stage).await;
    assert_eq!(
        live.state_revision,
        stage.parent.state_revision + 1,
        "every bad mandate left the record at the parent"
    );
    assert_eq!(
        live.commit_log.last().map(|kept| kept.commit.committed_at),
        Some(stage.terminal.committed_at),
        "only the valid terminal is retained (the terminals share a state \
         hash; their committed_at is what tells them apart)"
    );
    assert_eq!(
        diag_counters(&stage)
            .await
            .member_added_events_rejected_state_chain_gap,
        0,
        "a refused mandate must leave no chain gap: only a wrongly accepted \
         one could strand the later events"
    );
    crate::server::drain_server_tasks(&stage.receiver, vec![listener]).await;
    Ok(())
}

#[tokio::test]
async fn a_forged_mandate_is_refused_with_cause_signature() -> Result<()> {
    let stage = stage().await?;
    let (_, forged, _, _) = mandates(&stage);
    refused_unchanged(&stage, forged, "signature").await
}

#[tokio::test]
async fn a_tampered_mandate_is_refused_with_cause_signature() -> Result<()> {
    let stage = stage().await?;
    let (_, _, tampered, _) = mandates(&stage);
    refused_unchanged(&stage, tampered, "signature").await
}

#[tokio::test]
async fn a_wrong_owner_mandate_is_refused_with_cause_policy_mismatch() -> Result<()> {
    let stage = stage().await?;
    let (_, _, _, wrong_owner) = mandates(&stage);
    refused_unchanged(&stage, wrong_owner, "policy_mismatch").await
}

/// Over the lane the committed certificate is the real owner's, so §3a
/// check 6 refuses the digest mismatch. Called with the foreign certificate
/// itself — the branch the lane cannot reach, because the ADR-0038 ingress
/// gate refuses that certificate first — the rule runs a real
/// `verify_cert_against_owner`, which rejects it.
#[tokio::test]
async fn a_wrong_owner_certificate_mandate_is_refused_with_cause_certificate_invalid() -> Result<()>
{
    let stage = stage().await?;
    let (wrong_owner_cert, foreign_cert) = wrong_owner_certificate_mandate(&stage);
    refused_unchanged(&stage, wrong_owner_cert.clone(), "certificate_invalid").await?;
    assert_eq!(
        receiver_cause(&stage, &wrong_owner_cert, &foreign_cert).await,
        Err("certificate_invalid"),
        "the real owner verification must refuse the foreign certificate"
    );
    Ok(())
}

/// #1680, ADR 0109 §3a check 7 at the receiver: the bound role may not
/// exceed the subject's role before its removal. A mandate properly
/// re-signed by the admin but binding the Admin role for a subject that
/// held Member is refused with `role_raised`.
#[tokio::test]
async fn a_role_raising_mandate_is_refused_with_cause_role_raised() -> Result<()> {
    let stage = stage().await?;
    let mut fields = mandate_fields(&stage);
    fields.role = x0x::groups::GroupRole::Admin;
    let raised = mint(fields, stage.admin.agent.identity().agent_keypair());
    refused_unchanged(&stage, raised, "role_raised").await
}

/// #1680, ADR 0109 §3a check 5 and D170 at the receiver: a mandate may
/// re-seat only a removal the signer itself committed. The admin's
/// mandate binding the peer admin's removal commit is refused with
/// `removal_mismatch`, byte-identical record and all. Control: the
/// peer's own mandate, on a terminal it committed, passes the rule.
#[tokio::test]
async fn a_removal_another_admin_committed_is_refused_with_cause_removal_mismatch() -> Result<()> {
    let stage = stage_with_peer_removal(true).await?;
    // `mandate_fields` binds the peer's removal commit; the mandate is
    // the admin's own (the re-seater).
    let mandate = mint(
        mandate_fields(&stage),
        stage.admin.agent.identity().agent_keypair(),
    );
    refused_unchanged(&stage, mandate, "removal_mismatch").await?;
    // Control: the peer re-seats its own removal.
    let peer_kp = stage.peer_kp.as_ref().expect("the peer admin's key");
    let peer_hex = hex::encode(peer_kp.agent_id().as_bytes());
    let peer_terminal = terminal_commit(&stage.parent, &stage.next, peer_kp, 3_600);
    let mut fields = mandate_fields(&stage);
    fields.signer = peer_hex;
    let own = mint(fields, peer_kp);
    assert_eq!(
        receiver_cause_over(
            &stage,
            &stage.parent,
            &stage.next,
            &peer_terminal,
            &own,
            &stage.subject_cert,
            None,
            None,
            None
        )
        .await,
        Ok(()),
        "the admin that committed the removal may re-seat it"
    );
    Ok(())
}

/// #1680 round 2, ADR 0109 §3a check 8: the TreeKEM plane always seats a
/// package, so a mandate that binds none (an empty hash) fails the
/// binding there; the no-package carve-out belongs to the non-package
/// planes alone.
#[tokio::test]
async fn a_packageless_reseat_on_the_treekem_plane_is_refused_with_cause_binding_mismatch(
) -> Result<()> {
    let stage = stage().await?;
    let mut parent = stage.parent.clone();
    parent.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    let mandate = mint(
        mandate_fields(&stage),
        stage.admin.agent.identity().agent_keypair(),
    );
    assert_eq!(
        receiver_cause_over(
            &stage,
            &parent,
            &stage.next,
            &stage.terminal,
            &mandate,
            &stage.subject_cert,
            None,
            None,
            None
        )
        .await,
        Err("binding_mismatch"),
        "an empty KeyPackage binding cannot seat a TreeKEM re-seat"
    );
    Ok(())
}

/// #1680, ADR 0109 §3a check 5's replay clause at the receiver: a second
/// mandate on the same removal fails, because the first re-seat's
/// terminal — a commit between the removal and the new parent — seats
/// the subject again. The first re-seat applies; the replay is refused
/// and the record keeps the first terminal.
#[tokio::test]
async fn a_replay_of_the_same_removal_is_refused_with_cause_removal_mismatch() -> Result<()> {
    let stage = stage().await?;
    let (valid, _, _, _) = mandates(&stage);
    let applied = apply_listener_metadata_event(
        &stage.receiver,
        member_added(&stage, valid, &stage.terminal, None),
        stage.admin.agent.agent_id(),
        true,
        None,
    )
    .await
    .expect("the shielded apply completes");
    assert!(applied.accepted, "the first re-seat must apply");
    let parent = live(&stage).await;
    let next = parent.clone();
    let admin_kp = stage.admin.agent.identity().agent_keypair();
    let replay_terminal = terminal_commit(&parent, &next, admin_kp, 3_500);
    let mut fields = mandate_fields(&stage);
    fields.parent_commit_hash = parent.state_hash.clone();
    fields.terminal_roster_hash = x0x::groups::state_commit::compute_roster_root(&next.members_v2);
    let replay = mint(fields, admin_kp);
    assert_eq!(
        receiver_cause_over(
            &stage,
            &parent,
            &next,
            &replay_terminal,
            &replay,
            &stage.subject_cert,
            None,
            None,
            None
        )
        .await,
        Err("removal_mismatch"),
        "the seated-again subject must fail check 5, not re-seat twice"
    );
    let before = record_json(&stage).await;
    let refused = apply_listener_metadata_event(
        &stage.receiver,
        member_added(&stage, replay, &replay_terminal, None),
        stage.admin.agent.agent_id(),
        true,
        None,
    )
    .await
    .expect("the shielded apply completes");
    assert!(!refused.accepted, "the replay must be refused");
    assert_eq!(
        before,
        record_json(&stage).await,
        "the refused replay leaves the committed record byte-identical"
    );
    Ok(())
}

/// A `MemberJoined` binding `package` for the subject, self-signed by
/// `signer` over the canonical join bytes — the ordinary join's KeyPackage
/// binding. With `signer` the subject it authenticates; with another key
/// it claims the subject while signing as someone else, which
/// `verify_member_joined_key_package_event` refuses.
fn member_joined_record(
    stage: &Stage,
    signer: &AgentKeypair,
    package: &str,
    ts_ms: u64,
) -> NamedGroupMetadataEvent {
    member_joined_record_as(stage, signer, &stage.subject_hex, package, ts_ms)
}

/// The subject's own record for `package`, self-signed as a join of
/// `group_id` (see [`member_joined_record`]): a valid record that
/// belongs to another group.
fn member_joined_record_in_group(
    stage: &Stage,
    signer: &AgentKeypair,
    group_id: &str,
    package: &str,
    ts_ms: u64,
) -> NamedGroupMetadataEvent {
    member_joined_record_in_group_as(stage, signer, &stage.subject_hex, group_id, package, ts_ms)
}

/// [`member_joined_record`] claiming `member_agent_id` instead of the
/// subject: with `signer` and `member_agent_id` both the impostor's, the
/// record is internally consistent (it passes self-verification) while
/// belonging to another agent — the certificate-key comparison's own
/// negative shape.
fn member_joined_record_as(
    stage: &Stage,
    signer: &AgentKeypair,
    member_agent_id: &str,
    package: &str,
    ts_ms: u64,
) -> NamedGroupMetadataEvent {
    member_joined_record_in_group_as(
        stage,
        signer,
        member_agent_id,
        &stage.group_id,
        package,
        ts_ms,
    )
}

/// [`member_joined_record_as`] with the record's group ids supplied: a
/// join of another group names that group in both its own ids and the
/// bytes the member signs, so the record stays self-consistent while
/// belonging to a different group.
fn member_joined_record_in_group_as(
    stage: &Stage,
    signer: &AgentKeypair,
    member_agent_id: &str,
    group_id: &str,
    package: &str,
    ts_ms: u64,
) -> NamedGroupMetadataEvent {
    let member_public_key_b64 = BASE64.encode(signer.public_key().as_bytes());
    let canonical = canonical_member_joined_bytes(
        group_id,
        Some(group_id),
        member_agent_id,
        &member_public_key_b64,
        x0x::groups::GroupRole::Member,
        None,
        &stage.admin_hex,
        "issue-1680-invite",
        ts_ms,
        Some(package),
    );
    let signature =
        ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(signer.secret_key(), &canonical)
            .expect("sign MemberJoined record");
    NamedGroupMetadataEvent::MemberJoined {
        group_id: group_id.to_string(),
        stable_group_id: Some(group_id.to_string()),
        member_agent_id: member_agent_id.to_string(),
        member_public_key_b64,
        role: x0x::groups::GroupRole::Member,
        display_name: None,
        inviter_agent_id: stage.admin_hex.clone(),
        invite_secret: "issue-1680-invite".to_string(),
        ts_ms,
        treekem_key_package_b64: Some(package.to_string()),
        kem_public_key_b64: None,
        kem_signature_b64: None,
        certificate_b64: None,
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: None,
        recovery_authority_commit: None,
        signature_b64: BASE64.encode(signature.as_bytes()),
    }
}

/// The authority-only shape: the subject's seat evidence with NO member
/// half (empty member key and signature), as a direct-add attestation
/// carries. It binds no member key to the package.
fn authority_only_record(stage: &Stage, package: &str) -> NamedGroupMetadataEvent {
    let mut record = member_joined_record(stage, &stage.subject_kp, package, 4_250);
    if let NamedGroupMetadataEvent::MemberJoined {
        member_public_key_b64,
        signature_b64,
        ..
    } = &mut record
    {
        *member_public_key_b64 = String::new();
        *signature_b64 = String::new();
    }
    record
}

/// A real one-member TreeKEM group and the commit that adds a second
/// member's prepared package, through the production codecs:
/// (the joiner's package b64, the commit b64).
fn real_treekem_add_commit(tag: u8) -> Result<(String, String)> {
    let creator = crate::identity::AgentId([tag; 32]);
    let joiner = crate::identity::AgentId([tag ^ 0xff; 32]);
    let mut group = crate::mls::treekem::TreeKemMlsGroup::create(
        b"issue-1680-leaf-binding".to_vec(),
        creator,
        &[tag; 32],
    )?;
    let prepared = crate::mls::treekem::TreeKemMlsGroup::prepare_member(joiner, &[tag ^ 0xff; 32])?;
    let package = BASE64.encode(prepared.key_package_bytes());
    let out = group.add_member(joiner, prepared.key_package_bytes())?;
    Ok((package, BASE64.encode(out.commit)))
}

/// Make `signer`'s record (see [`member_joined_record`]) the receiver's
/// held evidence for the subject's seat. The record is planted straight
/// into the cache state, past the cache's own ingress gate (which would
/// refuse a foreign-signed record): the persisted cache file is restored
/// verbatim at startup, so the §3a rule must not trust a held record
/// blindly. The subject-signed control goes through the real gate below.
async fn hold_subject_record(stage: &Stage, signer: &AgentKeypair, package: &str) {
    hold_record_under_subject_key(stage, member_joined_record(stage, signer, package, 4_000)).await;
}

/// [`hold_subject_record`] for a ready-made event planted under the
/// subject's cache key (the greptile P2 shape: an internally consistent
/// record of ANOTHER agent, which the ingress gate would never seat).
async fn hold_record_under_subject_key(stage: &Stage, event: NamedGroupMetadataEvent) {
    let key = join_result_key(&stage.group_id, &stage.subject_hex);
    let encoded_bytes = cache_entry_encoded_bytes(&key, &event).expect("encode cache entry");
    let mut cache = stage
        .receiver
        .treekem_member_key_packages
        .state
        .write()
        .await;
    if let Some(previous) = cache.entries.remove(&key) {
        cache.encoded_bytes = cache.encoded_bytes.saturating_sub(previous.encoded_bytes);
    }
    cache.encoded_bytes = cache.encoded_bytes.saturating_add(encoded_bytes);
    cache.entries.insert(
        key,
        TreeKemMemberKeyPackageCacheEntry {
            event,
            encoded_bytes,
        },
    );
}

/// Seat the subject's own record for `package` through the cache's real
/// ingress gate (its self-signature verifies, so the gate accepts it).
async fn admit_subject_record(stage: &Stage, package: &str) {
    cache_treekem_member_key_package(
        &stage.receiver,
        join_result_key(&stage.group_id, &stage.subject_hex),
        member_joined_record(stage, &stage.subject_kp, package, 4_100),
        true,
    )
    .await;
}

/// #1680 round 3 (Engineer ruling 30 Oct 2026, PR comment 6528069544):
/// ADR 0109 §3a check 8 fails closed, as the Accepted ADR reads. A
/// re-seat that binds a KeyPackage must carry the subject's own signed
/// `MemberJoined` for it in `member_joined_recovery`; a receiver that
/// gets no record at all — the shape every sender before the ruling
/// emits — refuses with `binding_mismatch`, the committed record stays
/// byte-identical and the subject stays unseated.
#[tokio::test]
async fn a_reseat_without_the_subject_signed_record_is_refused_with_cause_binding_mismatch(
) -> Result<()> {
    let stage = stage().await?;
    let package = BASE64.encode([7u8; 96]);
    let hash = blake3::hash(package.as_bytes()).to_hex().to_string();
    let mut fields = mandate_fields(&stage);
    fields.key_package_hash = hash.clone();
    let mandate = mint(fields, stage.admin.agent.identity().agent_keypair());
    // The receiver holds nothing and the event carries nothing: the
    // mandate's signed hash binding alone must not seat the package.
    assert_eq!(
        receiver_cause_over(
            &stage,
            &stage.parent,
            &stage.next,
            &stage.terminal,
            &mandate,
            &stage.subject_cert,
            Some(&hash),
            None,
            None
        )
        .await,
        Err("binding_mismatch"),
        "a bound package with no carried subject-signed record must fail check 8"
    );
    // An authority-only carried record fails the same way: with no member
    // half it binds no member key to the package.
    assert_eq!(
        receiver_cause_over(
            &stage,
            &stage.parent,
            &stage.next,
            &stage.terminal,
            &mandate,
            &stage.subject_cert,
            Some(&hash),
            Some(&authority_only_record(&stage, &package)),
            None
        )
        .await,
        Err("binding_mismatch"),
        "an authority-only carried record has no member binding and must fail check 8"
    );
    let before = record_json(&stage).await;
    let applied = apply_listener_metadata_event(
        &stage.receiver,
        member_added(&stage, mandate, &stage.terminal, Some(&hash)),
        stage.admin.agent.agent_id(),
        true,
        None,
    )
    .await
    .expect("the shielded apply completes");
    assert!(
        !applied.accepted,
        "the recordless re-seat must be refused (old senders are refused, per the ruling)"
    );
    assert_eq!(
        before,
        record_json(&stage).await,
        "a refused re-seat leaves the committed record byte-identical"
    );
    assert!(
        !live(&stage).await.has_active_member(&stage.subject_hex),
        "the subject stays unseated"
    );
    Ok(())
}

/// #1680, ADR 0109 §3a check 8 at the receiver: the re-seat KeyPackage
/// must verify against the subject's agent key, exactly as an ordinary
/// join's does. The receiver holds the subject's `MemberJoined` record
/// for the bound package; when that record is signed by another key the
/// mandate is refused with `binding_mismatch`, the committed record stays
/// byte-identical and the subject stays unseated. The subject's own
/// record for the same package passes (control).
#[tokio::test]
async fn a_key_package_signed_by_another_key_is_refused_with_cause_binding_mismatch() -> Result<()>
{
    let stage = stage().await?;
    let package = BASE64.encode([7u8; 96]);
    let hash = blake3::hash(package.as_bytes()).to_hex().to_string();
    let mut fields = mandate_fields(&stage);
    fields.key_package_hash = hash.clone();
    let mandate = mint(fields, stage.admin.agent.identity().agent_keypair());
    // The event carries the subject's valid record (round 3: check 8's
    // evidence), and the receiver's held record for that package is
    // signed by another key claiming the subject: the poisoned cache
    // contradicts the carried evidence and refuses the re-seat.
    let carried = member_joined_record(&stage, &stage.subject_kp, &package, 4_050);
    let impostor = AgentKeypair::generate()?;
    hold_subject_record(&stage, &impostor, &package).await;
    assert_eq!(
        receiver_cause_over(
            &stage,
            &stage.parent,
            &stage.next,
            &stage.terminal,
            &mandate,
            &stage.subject_cert,
            Some(&hash),
            Some(&carried),
            None
        )
        .await,
        Err("binding_mismatch")
    );
    let before = record_json(&stage).await;
    let applied = apply_listener_metadata_event(
        &stage.receiver,
        member_added_with(
            &stage,
            mandate.clone(),
            &stage.terminal,
            Some(&hash),
            Some(carried.clone()),
            None,
        ),
        stage.admin.agent.agent_id(),
        true,
        None,
    )
    .await
    .expect("the shielded apply completes");
    assert!(
        !applied.accepted,
        "the foreign-signed package must be refused"
    );
    assert_eq!(
        before,
        record_json(&stage).await,
        "a refused re-seat leaves the committed record byte-identical"
    );
    assert!(
        !live(&stage).await.has_active_member(&stage.subject_hex),
        "the subject stays unseated"
    );
    // Control: the subject's own signature over the same package binds
    // it to the subject's certified agent key, so check 8 passes —
    // through the cache's real ingress gate.
    admit_subject_record(&stage, &package).await;
    assert_eq!(
        receiver_cause_over(
            &stage,
            &stage.parent,
            &stage.next,
            &stage.terminal,
            &mandate,
            &stage.subject_cert,
            Some(&hash),
            Some(&carried),
            None
        )
        .await,
        Ok(())
    );
    Ok(())
}

/// #1680 round 3: a carried record that is itself foreign-signed —
/// another key signing while claiming the subject — fails check 8 even
/// though the receiver holds nothing at all.
#[tokio::test]
async fn a_carried_record_signed_by_another_key_is_refused_with_cause_binding_mismatch(
) -> Result<()> {
    let stage = stage().await?;
    let package = BASE64.encode([7u8; 96]);
    let hash = blake3::hash(package.as_bytes()).to_hex().to_string();
    let mut fields = mandate_fields(&stage);
    fields.key_package_hash = hash.clone();
    let mandate = mint(fields, stage.admin.agent.identity().agent_keypair());
    let impostor = AgentKeypair::generate()?;
    let record = member_joined_record(&stage, &impostor, &package, 4_300);
    assert_eq!(
        receiver_cause_over(
            &stage,
            &stage.parent,
            &stage.next,
            &stage.terminal,
            &mandate,
            &stage.subject_cert,
            Some(&hash),
            Some(&record),
            None
        )
        .await,
        Err("binding_mismatch"),
        "a carried record the subject did not sign must fail check 8"
    );
    Ok(())
}

/// Round-2 review thread (greptile P2): the certificate-key comparison
/// has its own coverage. The receiver holds, under the subject's cache
/// key, a record that belongs to ANOTHER agent but is internally
/// consistent — its member id, key and signature all match the impostor,
/// so it passes self-verification — while the event carries the
/// subject's valid record. Only the comparison of the record's member
/// key against the certificate's agent key refuses, with
/// `binding_mismatch`; seating the subject's own record under the same
/// key passes (control).
#[tokio::test]
async fn a_held_record_of_another_agent_fails_only_the_certificate_comparison() -> Result<()> {
    let stage = stage().await?;
    let package = BASE64.encode([7u8; 96]);
    let hash = blake3::hash(package.as_bytes()).to_hex().to_string();
    let mut fields = mandate_fields(&stage);
    fields.key_package_hash = hash.clone();
    let mandate = mint(fields, stage.admin.agent.identity().agent_keypair());
    let carried = member_joined_record(&stage, &stage.subject_kp, &package, 4_400);
    let impostor = AgentKeypair::generate()?;
    let impostor_hex = hex::encode(impostor.agent_id().as_bytes());
    hold_record_under_subject_key(
        &stage,
        member_joined_record_as(&stage, &impostor, &impostor_hex, &package, 4_410),
    )
    .await;
    assert!(
        verify_member_joined_key_package_event(&member_joined_record_as(
            &stage,
            &impostor,
            &impostor_hex,
            &package,
            4_410
        )),
        "precondition: the impostor's record passes self-verification"
    );
    assert_eq!(
        receiver_cause_over(
            &stage,
            &stage.parent,
            &stage.next,
            &stage.terminal,
            &mandate,
            &stage.subject_cert,
            Some(&hash),
            Some(&carried),
            None
        )
        .await,
        Err("binding_mismatch"),
        "the certificate-key comparison alone must refuse the impostor's record"
    );
    // Control: the subject's own record under the same key passes. The
    // cache replaces an entry only on a strictly later timestamp, so the
    // control is seated with one newer than the planted impostor record.
    cache_treekem_member_key_package(
        &stage.receiver,
        join_result_key(&stage.group_id, &stage.subject_hex),
        member_joined_record(&stage, &stage.subject_kp, &package, 4_600),
        true,
    )
    .await;
    assert_eq!(
        receiver_cause_over(
            &stage,
            &stage.parent,
            &stage.next,
            &stage.terminal,
            &mandate,
            &stage.subject_cert,
            Some(&hash),
            Some(&carried),
            None
        )
        .await,
        Ok(())
    );
    Ok(())
}

/// #1680 follow-up (Engineer ruling 31 Oct 2026): a valid
/// subject-signed `MemberJoined` from ANOTHER group — every other
/// check-8 clause of it passes — is evidence about that group's seat,
/// not this re-seat, so §3a check 8 refuses it with the typed
/// `binding_mismatch` cause; the same record for the parent group
/// passes (control).
#[tokio::test]
async fn a_carried_member_joined_from_another_group_is_refused_with_cause_binding_mismatch(
) -> Result<()> {
    let stage = stage().await?;
    let package = BASE64.encode([7u8; 96]);
    let hash = blake3::hash(package.as_bytes()).to_hex().to_string();
    let mut fields = mandate_fields(&stage);
    fields.key_package_hash = hash.clone();
    let mandate = mint(fields, stage.admin.agent.identity().agent_keypair());
    let foreign_group_id = "6c".repeat(32);
    let foreign = member_joined_record_in_group(
        &stage,
        &stage.subject_kp,
        &foreign_group_id,
        &package,
        4_060,
    );
    assert!(
        verify_member_joined_key_package_event(&foreign),
        "precondition: the foreign-group record passes self-verification"
    );
    // The typed clause: check 8's carried-record evidence must name the
    // parent group, and a foreign-group record does not. The clause
    // runs in the §3a receive wiring beside the mandate rule (the
    // rule's own file is fenced to open PRs), and refuses with
    // `binding_mismatch` before the later attestation gate's plain
    // rejection.
    assert!(
        !carried_member_joined_recovery_binds_parent_group(&mandate, &stage.parent, Some(&foreign)),
        "a carried record from another group must not bind to the parent group"
    );
    let before = record_json(&stage).await;
    let applied = apply_listener_metadata_event(
        &stage.receiver,
        member_added_with(
            &stage,
            mandate.clone(),
            &stage.terminal,
            Some(&hash),
            Some(foreign.clone()),
            None,
        ),
        stage.admin.agent.agent_id(),
        true,
        None,
    )
    .await
    .expect("the shielded apply completes");
    assert!(
        !applied.accepted,
        "a carried record from another group must be refused"
    );
    assert_eq!(
        before,
        record_json(&stage).await,
        "a refused re-seat leaves the committed record byte-identical"
    );
    assert!(
        !live(&stage).await.has_active_member(&stage.subject_hex),
        "the subject stays unseated"
    );
    // Control: the same subject-signed record for the parent group
    // binds the package to this re-seat, so check 8 passes it.
    let carried = member_joined_record(&stage, &stage.subject_kp, &package, 4_050);
    assert!(carried_member_joined_recovery_binds_parent_group(
        &mandate,
        &stage.parent,
        Some(&carried)
    ));
    assert_eq!(
        receiver_cause_over(
            &stage,
            &stage.parent,
            &stage.next,
            &stage.terminal,
            &mandate,
            &stage.subject_cert,
            Some(&hash),
            Some(&carried),
            None
        )
        .await,
        Ok(()),
        "the parent-group record passes check 8"
    );
    Ok(())
}

/// #1680 round 3: the honest re-seat — the event carries the subject's
/// own signed, authority-countersigned record for the bound package
/// (exactly what the seal path now puts in `member_joined_recovery`), and
/// it applies end to end: the §3a rule accepts, the receiver's
/// authority-attestation gate verifies the record against the terminal
/// commit's recovery security binding, the subject is seated and the
/// record reaches the member-key-package cache.
#[tokio::test]
async fn an_honest_reseat_with_the_carried_record_applies() -> Result<()> {
    let stage = stage().await?;
    let package = BASE64.encode([7u8; 96]);
    let hash = blake3::hash(package.as_bytes()).to_hex().to_string();
    let original = member_joined_record(&stage, &stage.subject_kp, &package, 4_200);
    // The seal's terminal commit carries the recovery security binding
    // (`treekem:epoch=…;member-recovery=…`), exactly as the TreeKEM seal
    // sets it before `seal_commit_owner_certified`. The receiver's parent
    // already runs under that binding, so the state the apply rebuilds
    // hashes to the commit the seal signed.
    let binding =
        treekem_recovery_security_binding(3, &original).expect("the member record binds a package");
    let mut parent = stage.parent.clone();
    parent.security_binding = Some(binding.clone());
    let mut next = stage.next.clone();
    next.security_binding = Some(binding);
    stage
        .receiver
        .named_groups
        .write()
        .await
        .insert(stage.group_id.clone(), parent.clone());
    let admin_kp = stage.admin.agent.identity().agent_keypair();
    let terminal = terminal_commit(&parent, &next, admin_kp, 3_000);
    let recovery = attest_member_joined_recovery_event(&original, admin_kp, &terminal)?;
    let mut fields = mandate_fields(&stage);
    fields.key_package_hash = hash.clone();
    let mandate = mint(fields, admin_kp);
    assert_eq!(
        receiver_cause_over(
            &stage,
            &parent,
            &next,
            &terminal,
            &mandate,
            &stage.subject_cert,
            Some(&hash),
            Some(&recovery),
            None
        )
        .await,
        Ok(()),
        "the carried subject-signed record for the bound package passes check 8"
    );
    let applied = apply_listener_metadata_event(
        &stage.receiver,
        member_added_with(
            &stage,
            mandate,
            &terminal,
            Some(&hash),
            Some(recovery.clone()),
            None,
        ),
        stage.admin.agent.agent_id(),
        true,
        None,
    )
    .await
    .expect("the shielded apply completes");
    assert!(applied.accepted, "the honest re-seat must apply");
    assert!(
        live(&stage).await.has_active_member(&stage.subject_hex),
        "the subject is seated"
    );
    assert!(
        stage
            .receiver
            .treekem_member_key_packages
            .get(&join_result_key(&stage.group_id, &stage.subject_hex))
            .await
            .is_some_and(|record| record == recovery),
        "the carried record reaches the member-key-package cache"
    );
    Ok(())
}

/// #1680 round 3 (round-1 review finding 3): §3a check 8's commit half —
/// the TreeKEM commit a re-seat carries must add exactly the bound
/// package. Built through the real codecs: a real TreeKEM group, a real
/// prepared joiner package, and the commit its add produces. The mandate
/// and the carried record bind a DIFFERENT package, so checks 1-8 pass
/// and only the leaf the commit adds refuses; binding the package the
/// commit actually adds passes (control, which also proves the package
/// hash round-trips through the commit's postcard codecs).
#[tokio::test]
async fn a_treekem_commit_adding_another_package_is_refused_with_cause_binding_mismatch(
) -> Result<()> {
    let stage = stage().await?;
    let (package, commit_b64) = real_treekem_add_commit(0x11)?;
    let (other, _) = real_treekem_add_commit(0x22)?;
    let admin_kp = stage.admin.agent.identity().agent_keypair();
    let other_hash = blake3::hash(other.as_bytes()).to_hex().to_string();
    let carried = member_joined_record(&stage, &stage.subject_kp, &other, 4_500);
    let mut fields = mandate_fields(&stage);
    fields.key_package_hash = other_hash.clone();
    let mandate = mint(fields, admin_kp);
    assert_eq!(
        receiver_cause_over(
            &stage,
            &stage.parent,
            &stage.next,
            &stage.terminal,
            &mandate,
            &stage.subject_cert,
            Some(&other_hash),
            Some(&carried),
            Some(&commit_b64)
        )
        .await,
        Err("binding_mismatch"),
        "a commit adding a leaf other than the bound package must fail check 8"
    );
    let hash = blake3::hash(package.as_bytes()).to_hex().to_string();
    let carried = member_joined_record(&stage, &stage.subject_kp, &package, 4_510);
    let mut fields = mandate_fields(&stage);
    fields.key_package_hash = hash.clone();
    let mandate = mint(fields, admin_kp);
    assert_eq!(
        receiver_cause_over(
            &stage,
            &stage.parent,
            &stage.next,
            &stage.terminal,
            &mandate,
            &stage.subject_cert,
            Some(&hash),
            Some(&carried),
            Some(&commit_b64)
        )
        .await,
        Ok(()),
        "a commit adding exactly the bound package passes check 8's commit half"
    );
    Ok(())
}
