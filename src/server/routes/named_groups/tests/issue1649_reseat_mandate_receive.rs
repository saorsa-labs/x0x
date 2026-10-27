//! #1649: ADR 0109 §3a receiver evidence on the real receive path.
//!
//! The #1533 review left the §3a receiver unproven end to end: the pure
//! verifier tests cover `verify_reseat_mandate` and the route tests cover
//! the issuer, but nothing drove a forged or tampered `ReseatMandateV1`
//! through `verify_reseat_mandate_on_receive`, which runs a real
//! `verify_cert_against_owner` on a real receiver.
//!
//! Two daemons, in process (no socket, no network config): the admin `A`
//! whose re-seat commit the mandate blesses, and a member receiver `R`
//! holding the real parent chain — the subject's seating commit and `A`'s
//! removal commit. The mandate-carrying `MemberAdded` travels the
//! production DM lane (`DirectMessaging::handle_incoming` →
//! `run_direct_metadata_listener` → the shielded apply) with the JSON
//! payload `spawn_named_group_event_delivery` sends. Each bad mandate is
//! also driven through the listener's own apply entry to prove the typed
//! refusal cause and a byte-identical committed record.

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
    /// Kept alive for both daemons' data directories.
    _dirs: (tempfile::TempDir, tempfile::TempDir),
    group_id: String,
    admin_hex: String,
    subject_hex: String,
    subject_kp: AgentKeypair,
    subject_cert: AgentCertificate,
    /// The post-removal record `R` holds (the parent of the re-seat).
    parent: x0x::groups::GroupInfo,
    seating_hash: String,
    removal_hash: String,
    /// The re-seat seat-write the terminal commit covers.
    next: x0x::groups::GroupInfo,
    terminal: x0x::groups::GroupStateCommit,
}

/// A daemon state with a generated agent key (one per pair member).
async fn daemon() -> Result<(Arc<AppState>, tempfile::TempDir)> {
    secure_endpoint_test_state_with_key(AgentKeypair::generate()?).await
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
    let (receiver, dir_r) = daemon().await?;
    let (admin, dir_a) = daemon().await?;
    let owner = UserKeypair::generate()?;
    let subject_kp = AgentKeypair::generate()?;
    let subject_hex = hex::encode(subject_kp.agent_id().as_bytes());
    let admin_hex = hex::encode(admin.agent.agent_id().as_bytes());
    let receiver_hex = hex::encode(receiver.agent.agent_id().as_bytes());
    let admin_kp = admin.agent.identity().agent_keypair();
    let admin_cert = AgentCertificate::issue(&owner, admin_kp)?;
    let receiver_cert = AgentCertificate::issue(&owner, receiver.agent.identity().agent_keypair())?;
    let subject_cert = AgentCertificate::issue(&owner, &subject_kp)?;
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
    let certs = vec![
        (admin_hex.clone(), admin_cert),
        (receiver_hex, receiver_cert),
        (subject_hex.clone(), subject_cert.clone()),
    ];
    // Seating (r1): the subject active on the retained roster.
    sealed(&mut info, admin_kp, &certs, 1_000);
    let seating_hash = info.state_hash.clone();
    // Removal (r2): the admin's own removal commit, the §3a `Removal` basis.
    info.remove_member(&subject_hex, Some(admin_hex.clone()));
    sealed(&mut info, admin_kp, &certs, 2_000);
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

/// The valid mandate, and the three bad shapes of #1649.
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
/// certificate a DIFFERENT owner issued for the subject, while the
/// committed certificate is the real owner's (so the §3a check runs
/// `verify_cert_against_owner` for real).
fn wrong_owner_certificate_mandate(stage: &Stage) -> ReseatMandateV1 {
    let foreign = UserKeypair::generate().expect("foreign cert owner");
    let cert = AgentCertificate::issue(&foreign, &stage.subject_kp).expect("foreign cert");
    let mut fields = mandate_fields(stage);
    fields.certificate_digest = crate::groups::owner_cert::certificate_digest_hex(&cert);
    mint(fields, stage.admin.agent.identity().agent_keypair())
}

fn member_added(
    stage: &Stage,
    mandate: ReseatMandateV1,
    commit: &x0x::groups::GroupStateCommit,
) -> NamedGroupMetadataEvent {
    use base64::Engine as _;
    NamedGroupMetadataEvent::MemberAdded {
        roster_certificates_b64: Vec::new(),
        group_id: stage.group_id.clone(),
        revision: commit.revision,
        actor: stage.admin_hex.clone(),
        agent_id: stage.subject_hex.clone(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: None,
        member_joined_recovery: None,
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

/// The listener's own apply entry refuses the event, with the typed cause
/// the receiver rule names, and leaves the committed record byte-identical.
async fn refused_unchanged(stage: &Stage, mandate: ReseatMandateV1, expected: &str) -> Result<()> {
    // The receiver rule the receive path runs, on the real receiver state.
    let cause = group_recovery::verify_reseat_mandate_on_receive(
        stage.receiver.as_ref(),
        &stage.parent,
        &stage.next,
        &stage.terminal,
        &mandate,
        &stage.subject_hex,
        None,
        None,
        Some(&stage.subject_cert),
    )
    .await;
    assert_eq!(
        cause,
        Err(expected),
        "the receiver rule must name the {expected} cause"
    );
    let before = record_json(stage).await;
    let applied = apply_listener_metadata_event(
        &stage.receiver,
        member_added(stage, mandate, &stage.terminal),
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
/// are refusals of the real acceptance path, not of a dead one.
#[tokio::test]
async fn a_valid_mandate_reseats_the_subject_over_the_dm_lane() -> Result<()> {
    let stage = stage().await?;
    let (valid, _, _, _) = mandates(&stage);
    let listener = tokio::spawn(run_direct_metadata_listener(
        Arc::clone(&stage.receiver),
        stage.receiver.agent.subscribe_direct(),
    ));
    inject(&stage, &member_added(&stage, valid, &stage.terminal)).await?;
    wait_seated(&stage, "the valid re-seat must apply over the DM lane").await?;
    let live = live(&stage).await;
    assert_eq!(live.state_revision, stage.parent.state_revision + 1);
    assert_eq!(live.state_hash, stage.terminal.state_hash);
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
    let wrong_owner_cert = wrong_owner_certificate_mandate(&stage);
    let listener = tokio::spawn(run_direct_metadata_listener(
        Arc::clone(&stage.receiver),
        stage.receiver.agent.subscribe_direct(),
    ));
    let admin_kp = stage.admin.agent.identity().agent_keypair();
    let bad_terminals = [3_100, 3_200, 3_300, 3_400]
        .map(|at| terminal_commit(&stage.parent, &stage.next, admin_kp, at));
    for (mandate, commit) in [&forged, &tampered, &wrong_owner, &wrong_owner_cert]
        .into_iter()
        .zip(bad_terminals)
    {
        inject(&stage, &member_added(&stage, mandate.clone(), &commit)).await?;
    }
    inject(&stage, &member_added(&stage, valid, &stage.terminal)).await?;
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

#[tokio::test]
async fn a_wrong_owner_certificate_mandate_is_refused_with_cause_certificate_invalid() -> Result<()>
{
    let stage = stage().await?;
    let wrong_owner_cert = wrong_owner_certificate_mandate(&stage);
    refused_unchanged(&stage, wrong_owner_cert, "certificate_invalid").await
}
