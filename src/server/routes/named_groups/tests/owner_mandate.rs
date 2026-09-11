//! ADR-0064 slice 2 unit tests: the `OwnerMandate` type (sign/verify/tamper
//! per bound field), the promoted-admin current-roster derivation vs the
//! rejected invite-projection variant (fault matrix §2b), authority mint
//! gating (owner user key + owner axis only, pre-mutation triple-equality
//! with the seal that follows), the receiver verify-if-present arm driven
//! through the REAL apply entry (invalid → byte-identical rejection, absent
//! → warn-accept + counter, valid → capability recorded and persisted
//! across `load_named_groups_merged`), the non-owner-axis byte-for-byte
//! restriction, and the #451 mixed-fleet JSON shapes.

use super::*;

use crate::groups::policy::{GroupAdmission, GroupPolicy};
use crate::groups::{GroupConfidentiality, GroupDiscoverability};
use crate::identity::{AgentKeypair, UserKeypair};

/// Authority-side fixture (same shape as the fork-quarantine cluster): the
/// local daemon IS the owner's primary agent — user key + builder-issued
/// certificate.
async fn owner_authority_state() -> Result<(Arc<AppState>, tempfile::TempDir, UserKeypair)> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    let owner_seed = [0xD4u8; 32];
    let user_kp = UserKeypair::from_seed(&owner_seed)?;
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(AgentKeypair::generate()?)
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_user_key(UserKeypair::from_seed(&owner_seed)?)
            .with_peer_cache_disabled()
            .with_contact_store_path(data_dir.join("contacts.json"))
            .build()
            .await?,
    );
    let state = secure_endpoint_test_state_at(data_dir, agent).await?;
    Ok((state, dir, user_kp))
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

fn invite_only_policy() -> GroupPolicy {
    GroupPolicy {
        discoverability: GroupDiscoverability::Hidden,
        admission: GroupAdmission::InviteOnly,
        confidentiality: GroupConfidentiality::MlsEncrypted,
        read_access: x0x::groups::GroupReadAccess::MembersOnly,
        write_access: x0x::groups::GroupWriteAccess::MembersOnly,
    }
}

/// A group with a SEALED base commit (revision 1) so a terminal
/// `MemberAdded` can chain from it, inserted into the live map.
async fn sealed_group(
    state: &AppState,
    group_id: &str,
    policy: GroupPolicy,
) -> Result<x0x::groups::GroupInfo> {
    let mut info = x0x::groups::GroupInfo::with_policy(
        "mandate-under-test".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.to_string(),
        policy,
    );
    if info.policy.admission.owner_certified_user_id().is_some() {
        seal_commit_owner_certified(
            state,
            &mut info,
            state.agent.identity().agent_keypair(),
            now_millis_u64(),
        )
        .await?;
    } else {
        info.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    }
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info.clone());
    Ok(info)
}

fn blake3_hex_of(input: &str) -> String {
    hex::encode(blake3::hash(input.as_bytes()).as_bytes())
}

/// Apply the seat-write the production receiver arm applies, on a clone.
fn seat_write(
    base: &x0x::groups::GroupInfo,
    joiner_hex: &str,
    actor_hex: &str,
    cert: &x0x::identity::AgentCertificate,
) -> x0x::groups::GroupInfo {
    let mut next = base.clone();
    next.add_member(
        joiner_hex.to_string(),
        x0x::groups::GroupRole::Member,
        Some(actor_hex.to_string()),
        None,
    );
    assert!(next
        .set_member_certificate(joiner_hex, cert.clone())
        .is_ok());
    next
}

/// The terminal commit the authority's seal produces for `pre_seal`
/// (the clone WITH the seat already applied, nothing sealed yet).
fn terminal_commit_for(
    pre_seal: &x0x::groups::GroupInfo,
    authority_kp: &AgentKeypair,
    now_ms: u64,
) -> x0x::groups::GroupStateCommit {
    x0x::groups::GroupStateCommit::sign(
        pre_seal.stable_group_id().to_string(),
        pre_seal.state_revision.saturating_add(1),
        Some(pre_seal.state_hash.clone()),
        x0x::groups::compute_roster_root(&pre_seal.members_v2),
        x0x::groups::compute_policy_hash(&pre_seal.policy),
        x0x::groups::compute_public_meta_hash(&pre_seal.public_meta()),
        pre_seal.security_binding.clone(),
        false,
        now_ms,
        authority_kp,
    )
    .expect("sign terminal")
}

/// Mint a mandate over `pre_seal` the way the authority path does.
#[allow(clippy::too_many_arguments)]
fn mint_mandate_like_authority(
    pre_seal: &x0x::groups::GroupInfo,
    roster_root_override: Option<&str>,
    declared_epoch: u64,
    joiner_hex: &str,
    authority_hex: &str,
    invite_secret: &str,
    cert: &x0x::identity::AgentCertificate,
    owner_kp: &UserKeypair,
    now_ms: u64,
) -> x0x::groups::OwnerMandate {
    x0x::groups::OwnerMandate::sign(
        pre_seal.stable_group_id(),
        pre_seal.state_revision.saturating_add(1),
        &pre_seal.state_hash,
        roster_root_override.unwrap_or(&x0x::groups::compute_roster_root(&pre_seal.members_v2)),
        &x0x::groups::compute_policy_hash(&pre_seal.policy),
        &x0x::groups::compute_public_meta_hash(&pre_seal.public_meta()),
        declared_epoch,
        joiner_hex,
        &blake3_hex_of(invite_secret),
        &x0x::groups::owner_cert::certificate_digest_hex(cert),
        authority_hex,
        now_ms,
        owner_kp,
    )
    .expect("sign mandate")
}

fn member_added_event(
    group_id: &str,
    revision: u64,
    actor_hex: &str,
    joiner_hex: &str,
    cert: &x0x::identity::AgentCertificate,
    commit: x0x::groups::GroupStateCommit,
    owner_mandate: Option<x0x::groups::OwnerMandate>,
) -> NamedGroupMetadataEvent {
    use base64::Engine as _;
    NamedGroupMetadataEvent::MemberAdded {
        group_id: group_id.to_string(),
        revision,
        actor: actor_hex.to_string(),
        agent_id: joiner_hex.to_string(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: Some(BASE64.encode(bincode::serialize(cert).expect("cert"))),
        owner_mandate,
        commit: Some(commit),
    }
}

async fn apply_event(state: &Arc<AppState>, event: NamedGroupMetadataEvent) -> ApplyMetadataResult {
    apply_named_group_metadata_event_inner(state, event, state.agent.agent_id(), true, true, None)
        .await
}

async fn live_record(state: &AppState, group_id: &str) -> x0x::groups::GroupInfo {
    state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .expect("group record")
}

async fn diag_row(state: &AppState, group_id: &str) -> crate::groups::diagnostics::GroupDiagnostic {
    let groups_snapshot = state.named_groups.read().await.clone();
    state
        .groups_diagnostics
        .snapshot(
            &groups_snapshot,
            &std::collections::HashSet::new(),
            &std::collections::HashSet::new(),
            &std::collections::HashMap::new(),
            state.groups_config.mandate_grace_days,
        )
        .groups
        .into_iter()
        .find(|g| g.group_id == group_id)
        .expect("diagnostics row")
}

struct MandateFixture {
    owner_kp: UserKeypair,
    authority_kp: AgentKeypair,
    cert: x0x::identity::AgentCertificate,
    base: x0x::groups::GroupInfo,
    candidate: x0x::groups::GroupInfo,
    terminal: x0x::groups::GroupStateCommit,
    mandate: x0x::groups::OwnerMandate,
    authority_hex: String,
    joiner_hex: String,
}

fn mandate_fixture(policy: GroupPolicy) -> MandateFixture {
    let owner_kp = UserKeypair::from_seed(&[0x9Bu8; 32]).expect("owner key");
    let authority_kp = AgentKeypair::generate().expect("authority key");
    let joiner_kp = AgentKeypair::generate().expect("joiner key");
    let cert = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner_kp.public_key().as_bytes(),
        None,
    )
    .expect("joiner certificate");
    let authority_hex = hex::encode(authority_kp.agent_id().as_bytes());
    let joiner_hex = hex::encode(joiner_kp.agent_id().as_bytes());
    let base = x0x::groups::GroupInfo::with_policy(
        "fixture".to_string(),
        String::new(),
        authority_kp.agent_id(),
        "5e".repeat(32),
        policy,
    );
    // No seal: the owner-axis plain seal refuses
    // (OwnerCertifiedEvidenceRequired) and none is needed — the mandate
    // binds the base the terminal chains from, and the genesis state
    // (revision 0, genesis hash) is exactly that base.
    let candidate = seat_write(&base, &joiner_hex, &authority_hex, &cert);
    let terminal = terminal_commit_for(&candidate, &authority_kp, 2_000);
    let mandate = mint_mandate_like_authority(
        &candidate,
        None,
        0,
        &joiner_hex,
        &authority_hex,
        "fixture-invite-secret",
        &cert,
        &owner_kp,
        1_500,
    );
    MandateFixture {
        owner_kp,
        authority_kp,
        cert,
        base,
        candidate,
        terminal,
        mandate,
        authority_hex,
        joiner_hex,
    }
}

impl MandateFixture {
    fn verify(
        &self,
        mandate: &x0x::groups::OwnerMandate,
    ) -> Result<(), x0x::groups::OwnerMandateError> {
        mandate.verify_against_terminal(
            self.owner_kp.public_key(),
            &self.owner_kp.user_id(),
            &self.candidate,
            &self.terminal,
            &self.authority_hex,
            &self.joiner_hex,
            None,
            Some(&x0x::groups::owner_cert::certificate_digest_hex(&self.cert)),
        )
    }
}

/// WHY: every bound field must be unforgeable — the mandate is the owner's
/// ONLY pre-mutation blessing of an invite-derived seat, so flipping ANY
/// input (roster shape, anchor, epoch, joiner, authority, invite, cert,
/// timing, version, signature) must break verification. A field that could
/// be flipped without failing would let a forgery re-anchor a forked add.
#[test]
fn mandate_round_trip_tamper_per_bound_field() {
    let f = mandate_fixture(owner_certified_policy(
        &UserKeypair::from_seed(&[0x9Bu8; 32]).unwrap(),
    ));
    assert!(f.verify(&f.mandate).is_ok(), "honest mandate verifies");

    let flips: Vec<(&str, x0x::groups::OwnerMandate)> = {
        use x0x::groups::OwnerMandate as M;
        let m = &f.mandate;
        let mut out: Vec<(&str, M)> = Vec::new();
        let mut t = m.clone();
        t.version ^= 1;
        out.push(("version", t));
        let mut t = m.clone();
        t.stable_group_id.push('x');
        out.push(("stable_group_id", t));
        let mut t = m.clone();
        t.expected_terminal_revision += 1;
        out.push(("expected_terminal_revision", t));
        let mut t = m.clone();
        t.parent_state_hash.push('x');
        out.push(("parent_state_hash", t));
        let mut t = m.clone();
        t.roster_root_after_add.push('x');
        out.push(("roster_root_after_add", t));
        let mut t = m.clone();
        t.policy_hash.push('x');
        out.push(("policy_hash", t));
        let mut t = m.clone();
        t.public_meta_hash.push('x');
        out.push(("public_meta_hash", t));
        let mut t = m.clone();
        t.declared_epoch += 1;
        out.push(("declared_epoch", t));
        let mut t = m.clone();
        t.joiner_agent_id.push('x');
        out.push(("joiner_agent_id", t));
        let mut t = m.clone();
        t.invite_secret_hash.push('x');
        out.push(("invite_secret_hash", t));
        let mut t = m.clone();
        t.admission_cert_digest.push('x');
        out.push(("admission_cert_digest", t));
        let mut t = m.clone();
        t.authority_agent_id.push('x');
        out.push(("authority_agent_id", t));
        let mut t = m.clone();
        t.issued_at_ms += 1;
        out.push(("issued_at_ms", t));
        let mut t = m.clone();
        t.signature_b64 = "AAAA".to_string();
        out.push(("signature_b64", t));
        out
    };
    assert_eq!(flips.len(), 14, "one flip per bound field");
    for (field, tampered) in flips {
        assert!(
            f.verify(&tampered).is_err(),
            "flipping `{field}` must fail verification"
        );
    }
    // The epoch binding also fires through the event's treekem_epoch.
    let mut epoched = f.mandate.clone();
    epoched.declared_epoch = 7;
    let signed = x0x::groups::OwnerMandate::sign(
        &f.mandate.stable_group_id,
        f.mandate.expected_terminal_revision,
        &f.mandate.parent_state_hash,
        &f.mandate.roster_root_after_add,
        &f.mandate.policy_hash,
        &f.mandate.public_meta_hash,
        7,
        &f.joiner_hex,
        &f.mandate.invite_secret_hash,
        &f.mandate.admission_cert_digest,
        &f.authority_hex,
        f.mandate.issued_at_ms,
        &f.owner_kp,
    )
    .expect("re-sign with epoch 7");
    assert!(
        signed
            .verify_against_terminal(
                f.owner_kp.public_key(),
                &f.owner_kp.user_id(),
                &f.candidate,
                &f.terminal,
                &f.authority_hex,
                &f.joiner_hex,
                Some(8),
                None,
            )
            .is_err(),
        "a declared epoch != the event's treekem_epoch must fail"
    );
    // A non-owner key never verifies, even over identical bytes.
    let stranger = UserKeypair::from_seed(&[0x01u8; 32]).expect("stranger");
    assert!(matches!(
        f.verify_against_owner(&stranger),
        Err(x0x::groups::OwnerMandateError::OwnerKeyMismatch)
    ));
}

impl MandateFixture {
    fn verify_against_owner(&self, kp: &UserKeypair) -> Result<(), x0x::groups::OwnerMandateError> {
        self.mandate.verify_against_terminal(
            kp.public_key(),
            &self.owner_kp.user_id(),
            &self.candidate,
            &self.terminal,
            &self.authority_hex,
            &self.joiner_hex,
            None,
            None,
        )
    }
}

/// WHY (fault matrix §2b, promoted-admin row / ADR r2 P1): the mandate's
/// roster root must cover the authority's ACTUAL CURRENT roster at mint
/// time — {authority, A, B, joiner} after B was admitted between the
/// invite mint and the join. The rejected invite-projection variant
/// ({authority, A, joiner}) can never verify, which is exactly why the
/// preimage is derived from the pre-seal clone and not the invite base.
#[test]
fn promoted_admin_current_roster_verifies_invite_projection_fails() {
    let f = mandate_fixture(owner_certified_policy(
        &UserKeypair::from_seed(&[0x9Bu8; 32]).unwrap(),
    ));
    // The r2 sequence: invite minted at N over {authority, A}; B admitted
    // at N+1; the join lands at N+2. Build the CURRENT roster explicitly.
    let a_hex = "a1".repeat(32);
    let b_hex = "b2".repeat(32);
    let mut at_invite = f.base.clone();
    at_invite.add_member(a_hex.clone(), x0x::groups::GroupRole::Member, None, None);
    let mut current = at_invite.clone();
    current.add_member(b_hex.clone(), x0x::groups::GroupRole::Member, None, None);
    let candidate = seat_write(&current, &f.joiner_hex, &f.authority_hex, &f.cert);
    let terminal = terminal_commit_for(&candidate, &f.authority_kp, 2_000);
    let mandate = mint_mandate_like_authority(
        &candidate,
        None,
        0,
        &f.joiner_hex,
        &f.authority_hex,
        "fixture-invite-secret",
        &f.cert,
        &f.owner_kp,
        1_500,
    );
    let verify = |m: &x0x::groups::OwnerMandate| {
        m.verify_against_terminal(
            f.owner_kp.public_key(),
            &f.owner_kp.user_id(),
            &candidate,
            &terminal,
            &f.authority_hex,
            &f.joiner_hex,
            None,
            None,
        )
    };
    // The invite projection: the stale N roster ({authority, A}) + the
    // joiner — the root the REJECTED v1 recipe would have signed.
    let mut projection = at_invite.clone();
    projection.add_member(
        f.joiner_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(f.authority_hex.clone()),
        None,
    );
    assert!(projection
        .set_member_certificate(&f.joiner_hex, f.cert.clone())
        .is_ok());
    let invite_projection_root = x0x::groups::compute_roster_root(&projection.members_v2);
    assert_ne!(
        invite_projection_root, mandate.roster_root_after_add,
        "fixture must exercise a genuinely stale projection"
    );
    assert!(
        verify(&mandate).is_ok(),
        "current-roster mandate verifies after intervening admissions"
    );
    let projection_mandate = mint_mandate_like_authority(
        &candidate,
        Some(&invite_projection_root),
        0,
        &f.joiner_hex,
        &f.authority_hex,
        "fixture-invite-secret",
        &f.cert,
        &f.owner_kp,
        1_500,
    );
    assert_eq!(
        verify(&projection_mandate),
        Err(x0x::groups::OwnerMandateError::RosterRootMismatch),
        "the invite-projection variant must fail the triple-equality"
    );
}

/// WHY: the mint is capability-gated exactly like the #469 A1b invite
/// fence — only an install holding the OWNER USER key (whose derived
/// UserId equals the policy owner) on an OWNER-AXIS group mints. Nodes
/// without the key (the keyless tier) and ordinary groups must omit the
/// mandate, and a minted mandate must be consistent with the seal that
/// follows it (pre-mutation derivation, no circularity).
#[tokio::test]
async fn mint_requires_owner_user_key_and_owner_axis() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "d4".repeat(32);
    let base = sealed_group(state.as_ref(), &group_id, owner_certified_policy(&owner_kp)).await?;
    let joiner_kp = AgentKeypair::generate()?;
    let joiner_hex = hex::encode(joiner_kp.agent_id().as_bytes());
    let actor_hex = hex::encode(state.agent.agent_id().as_bytes());
    let cert = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner_kp.public_key().as_bytes(),
        None,
    )?;
    let pre_seal = seat_write(&base, &joiner_hex, &actor_hex, &cert);

    let minted = mint_owner_mandate_for_seat(
        state.as_ref(),
        &pre_seal,
        0,
        &joiner_hex,
        &actor_hex,
        "d4-invite-secret",
        Some(&cert),
        42_000,
    )
    .await;
    let Some(minted) = minted else {
        panic!("owner-key install on an owner-axis group must mint");
    };
    assert_eq!(
        diag_row(state.as_ref(), &group_id)
            .await
            .counters
            .owner_mandate_minted,
        1
    );

    // The seal that follows must agree with every anchored value — the
    // preimage was derivable pre-mutation (ADR-0064 §1a).
    let mut sealed = pre_seal.clone();
    let commit = seal_commit_owner_certified(
        state.as_ref(),
        &mut sealed,
        state.agent.identity().agent_keypair(),
        43_000,
    )
    .await?;
    assert_eq!(minted.expected_terminal_revision, commit.revision);
    assert_eq!(
        minted.parent_state_hash,
        commit.prev_state_hash.clone().expect("parent")
    );
    assert_eq!(minted.roster_root_after_add, commit.roster_root);
    assert_eq!(minted.policy_hash, commit.policy_hash);
    assert_eq!(minted.public_meta_hash, commit.public_meta_hash);

    // No owner user key → no mandate, no counter (the keyless tier). No
    // seal needed: the mint fence is keyed on the policy + key, not on a
    // sealed chain, and the plain fixture's agent holds no certificate
    // an owner-certified seal could certify.
    let (plain, _pdir) = secure_endpoint_test_state().await?;
    let plain_group_id = "d5".repeat(32);
    let mut plain_base = x0x::groups::GroupInfo::with_policy(
        "keyless".to_string(),
        String::new(),
        plain.agent.agent_id(),
        plain_group_id.clone(),
        owner_certified_policy(&owner_kp),
    );
    plain_base.recompute_state_hash();
    plain
        .named_groups
        .write()
        .await
        .insert(plain_group_id.clone(), plain_base.clone());
    let plain_pre_seal = seat_write(
        &plain_base,
        &joiner_hex,
        &hex::encode(plain.agent.agent_id().as_bytes()),
        &cert,
    );
    assert!(
        mint_owner_mandate_for_seat(
            plain.as_ref(),
            &plain_pre_seal,
            0,
            &joiner_hex,
            &joiner_hex,
            "d4-invite-secret",
            Some(&cert),
            42_000,
        )
        .await
        .is_none(),
        "an install without the owner user key must omit the mandate"
    );
    assert_eq!(
        diag_row(plain.as_ref(), &plain_group_id)
            .await
            .counters
            .owner_mandate_minted,
        0
    );

    // Owner-axis key present but a NON-owner-axis group → no mandate.
    let ordinary_group_id = "d6".repeat(32);
    sealed_group(state.as_ref(), &ordinary_group_id, invite_only_policy()).await?;
    let ordinary_pre_seal = seat_write(
        &live_record(state.as_ref(), &ordinary_group_id).await,
        &joiner_hex,
        &actor_hex,
        &cert,
    );
    assert!(
        mint_owner_mandate_for_seat(
            state.as_ref(),
            &ordinary_pre_seal,
            0,
            &joiner_hex,
            &actor_hex,
            "d4-invite-secret",
            Some(&cert),
            42_000,
        )
        .await
        .is_none(),
        "non-owner-axis groups never mint (byte-for-byte restriction)"
    );
    Ok(())
}

/// Shared receiver-arm stage: an owner-axis group at revision 1 on the
/// local (owner-primary) install, plus a joiner certificate and the
/// pre-seal candidate the terminal commit is derived from.
async fn receiver_stage() -> Result<(
    Arc<AppState>,
    tempfile::TempDir,
    UserKeypair,
    String,
    String,
    x0x::groups::GroupInfo,
    x0x::identity::AgentCertificate,
)> {
    let (state, dir, owner_kp) = owner_authority_state().await?;
    let group_id = "e1".repeat(32);
    let base = sealed_group(state.as_ref(), &group_id, owner_certified_policy(&owner_kp)).await?;
    let joiner_kp = AgentKeypair::generate()?;
    let joiner_hex = hex::encode(joiner_kp.agent_id().as_bytes());
    let actor_hex = hex::encode(state.agent.agent_id().as_bytes());
    let cert = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner_kp.public_key().as_bytes(),
        None,
    )?;
    let pre_seal = seat_write(&base, &joiner_hex, &actor_hex, &cert);
    Ok((state, dir, owner_kp, group_id, joiner_hex, pre_seal, cert))
}

/// WHY: a PRESENT-but-invalid mandate is the one case this slice refuses —
/// absent mandates warn-accept (mixed fleet), but a broken owner blessing
/// means the event is not what the owner signed. The rejection must leave
/// the local state BYTE-IDENTICAL (nothing persisted; `next` was a clone).
#[tokio::test]
async fn invalid_mandate_rejects_with_state_byte_identical() -> Result<()> {
    let (state, _dir, owner_kp, group_id, joiner_hex, pre_seal, cert) = receiver_stage().await?;
    let actor_hex = hex::encode(state.agent.agent_id().as_bytes());
    let terminal = terminal_commit_for(&pre_seal, state.agent.identity().agent_keypair(), 2_000);
    let mut tampered = mint_mandate_like_authority(
        &pre_seal,
        None,
        0,
        &joiner_hex,
        &actor_hex,
        "e1-invite-secret",
        &cert,
        &owner_kp,
        1_500,
    );
    tampered.roster_root_after_add.push('x');
    let event = member_added_event(
        &group_id,
        terminal.revision,
        &actor_hex,
        &joiner_hex,
        &cert,
        terminal.clone(),
        Some(tampered),
    );
    let before =
        serde_json::to_string(&live_record(state.as_ref(), &group_id).await).expect("json");
    let result = apply_event(&state, event).await;
    assert!(!result.accepted, "invalid mandate must reject the event");
    let after = serde_json::to_string(&live_record(state.as_ref(), &group_id).await).expect("json");
    assert_eq!(
        before, after,
        "rejected apply leaves the record byte-identical"
    );
    assert!(
        !live_record(state.as_ref(), &group_id)
            .await
            .has_active_member(&joiner_hex),
        "joiner must not be seated by an event with a broken mandate"
    );
    assert_eq!(
        diag_row(state.as_ref(), &group_id)
            .await
            .counters
            .owner_mandate_invalid,
        1
    );
    Ok(())
}

/// WHY: absence is the mixed-fleet shape (pre-mandate authorities and the
/// keyless tier) — it must apply EXACTLY as today, counted and warned, so
/// the fleet never wedges while mandates roll out. No capability is
/// recorded (nothing proved the agent holds the owner key).
#[tokio::test]
async fn absent_mandate_applies_with_counter() -> Result<()> {
    let (state, _dir, _owner_kp, group_id, joiner_hex, pre_seal, cert) = receiver_stage().await?;
    let actor_hex = hex::encode(state.agent.agent_id().as_bytes());
    let terminal = terminal_commit_for(&pre_seal, state.agent.identity().agent_keypair(), 2_000);
    let event = member_added_event(
        &group_id,
        terminal.revision,
        &actor_hex,
        &joiner_hex,
        &cert,
        terminal.clone(),
        None,
    );
    let result = apply_event(&state, event).await;
    assert!(result.accepted, "absent mandate applies as today (slice 2)");
    assert!(
        live_record(state.as_ref(), &group_id)
            .await
            .has_active_member(&joiner_hex),
        "joiner seated by the ordinary apply path"
    );
    let row = diag_row(state.as_ref(), &group_id).await;
    assert_eq!(row.counters.owner_mandate_absent, 1);
    assert_eq!(row.counters.owner_mandate_valid, 0);
    assert!(
        live_record(state.as_ref(), &group_id)
            .await
            .mandate_capability
            .is_empty(),
        "no capability without a verified proof"
    );
    Ok(())
}

/// WHY: a VALID mandate is the capability observation (ADR-0064 §1b) —
/// the first proof that THIS authority agent's install holds the owner
/// user key. Slice 3's grace clock starts here, so the record must
/// persist across daemon restarts (`load_named_groups_merged`), and the
/// first observation time must be retained across later events.
#[tokio::test]
async fn valid_mandate_applies_records_capability_and_persists() -> Result<()> {
    let (state, dir, owner_kp, group_id, joiner_hex, pre_seal, cert) = receiver_stage().await?;
    let actor_hex = hex::encode(state.agent.agent_id().as_bytes());
    let terminal = terminal_commit_for(&pre_seal, state.agent.identity().agent_keypair(), 2_000);
    let mandate = mint_mandate_like_authority(
        &pre_seal,
        None,
        0,
        &joiner_hex,
        &actor_hex,
        "e1-invite-secret",
        &cert,
        &owner_kp,
        1_500,
    );
    let event = member_added_event(
        &group_id,
        terminal.revision,
        &actor_hex,
        &joiner_hex,
        &cert,
        terminal,
        Some(mandate),
    );
    let result = apply_event(&state, event).await;
    assert!(result.accepted, "valid mandate applies");
    let live = live_record(state.as_ref(), &group_id).await;
    assert!(live.has_active_member(&joiner_hex));
    let row = diag_row(state.as_ref(), &group_id).await;
    assert_eq!(row.counters.owner_mandate_valid, 1);
    assert_eq!(row.counters.owner_mandate_absent, 0);
    assert!(
        live.mandate_capability.contains_key(&actor_hex),
        "capability recorded for the authority agent"
    );
    // The map is local-only data on the group record: reload through the
    // REAL loader and it must survive.
    let reloaded =
        load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path).await?;
    let persisted = reloaded.get(&group_id).expect("group persisted");
    assert_eq!(
        persisted.mandate_capability.get(&actor_hex).cloned(),
        live.mandate_capability.get(&actor_hex).cloned(),
        "capability map persists across load_named_groups_merged"
    );
    drop(dir);
    Ok(())
}

/// WHY (slice-1 parity restriction, maintainer decision 2): non-owner-axis
/// groups have no owner anchor, so the mandate machinery must be INERT for
/// them — an event carrying a (bogus) mandate applies exactly like one
/// without, no counters move, and the record never grows the map.
#[tokio::test]
async fn non_owner_axis_group_is_byte_for_byte_unchanged() -> Result<()> {
    let (state, _dir, owner_kp, group_id, joiner_hex, pre_seal, cert) = receiver_stage().await?;
    // Downgrade the live record to an invite-only policy and re-seal so
    // the terminal can chain.
    let mut ordinary = pre_seal.clone();
    ordinary.policy = invite_only_policy();
    ordinary.state_hash = String::new();
    ordinary.prev_state_hash = None;
    ordinary.state_revision = 0;
    ordinary.recompute_state_hash();
    ordinary.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), ordinary.clone());
    let actor_hex = hex::encode(state.agent.agent_id().as_bytes());
    let candidate = seat_write(&ordinary, &joiner_hex, &actor_hex, &cert);
    let terminal = terminal_commit_for(&candidate, state.agent.identity().agent_keypair(), 2_000);
    let bogus = mint_mandate_like_authority(
        &candidate,
        None,
        0,
        &joiner_hex,
        &actor_hex,
        "e1-invite-secret",
        &cert,
        &owner_kp,
        1_500,
    );

    let with_mandate = apply_event(
        &state,
        member_added_event(
            &group_id,
            terminal.revision,
            &actor_hex,
            &joiner_hex,
            &cert,
            terminal.clone(),
            Some(bogus),
        ),
    )
    .await;
    assert!(
        with_mandate.accepted,
        "mandate on a non-owner-axis group is inert"
    );
    let after = live_record(state.as_ref(), &group_id).await;
    assert!(after.has_active_member(&joiner_hex));
    assert!(after.mandate_capability.is_empty());
    let row = diag_row(state.as_ref(), &group_id).await;
    assert_eq!(row.counters.owner_mandate_valid, 0);
    assert_eq!(row.counters.owner_mandate_invalid, 0);
    assert_eq!(row.counters.owner_mandate_absent, 0);
    let record_json = serde_json::to_value(&after).expect("json");
    assert!(
        record_json.get("mandate_capability").is_none(),
        "the map is skip-serialized when empty: {record_json}"
    );
    Ok(())
}

/// WHY (#451 mixed-fleet hazard): the mandate rides a JSON event field —
/// an old binary receiving the new shape ignores the key, and a new
/// binary receiving the OLD shape (key dropped in transit / pre-mandate
/// authority) decodes it as absent. Neither direction may brick a peer,
/// and the same holds for the `mandate_capability` group-record field.
#[test]
fn mixed_fleet_json_shapes_decode_both_ways() {
    let f = mandate_fixture(owner_certified_policy(
        &UserKeypair::from_seed(&[0x9Bu8; 32]).unwrap(),
    ));
    let event = member_added_event(
        f.base.stable_group_id(),
        f.terminal.revision,
        &f.authority_hex,
        &f.joiner_hex,
        &f.cert,
        f.terminal.clone(),
        Some(f.mandate.clone()),
    );
    let mut value = serde_json::to_value(&event).expect("json");
    assert!(value.get("owner_mandate").is_some(), "mandate serializes");
    // New shape → old binary: the key is dropped (serde ignores unknown).
    value
        .as_object_mut()
        .expect("object")
        .remove("owner_mandate");
    let decoded_old: NamedGroupMetadataEvent =
        serde_json::from_value(value).expect("old shape decodes");
    match decoded_old {
        NamedGroupMetadataEvent::MemberAdded {
            owner_mandate: None,
            ..
        } => {}
        _ => panic!("decoded MemberAdded with absent mandate"),
    }
    // Old shape → new binary: a JSON blob without the key decodes (default).
    let mut legacy = serde_json::to_value(member_added_event(
        f.base.stable_group_id(),
        f.terminal.revision,
        &f.authority_hex,
        &f.joiner_hex,
        &f.cert,
        f.terminal.clone(),
        None,
    ))
    .expect("json");
    legacy
        .as_object_mut()
        .expect("object")
        .remove("owner_mandate");
    let decoded: NamedGroupMetadataEvent =
        serde_json::from_str(&legacy.to_string()).expect("legacy decodes");
    match decoded {
        NamedGroupMetadataEvent::MemberAdded {
            owner_mandate: None,
            ..
        } => {}
        _ => panic!("legacy MemberAdded decodes with default None"),
    }
    // Same both-ways contract for the group record's capability map.
    let mut record = serde_json::to_value(&f.candidate).expect("json");
    record
        .as_object_mut()
        .expect("object")
        .remove("mandate_capability");
    let record: x0x::groups::GroupInfo =
        serde_json::from_value(record).expect("record without map decodes");
    assert!(record.mandate_capability.is_empty());
    let mut with_map = f.candidate.clone();
    with_map.mandate_capability.insert(
        f.authority_hex.clone(),
        x0x::groups::MandateCapabilityState {
            first_seen_ms: 7,
            ..Default::default()
        },
    );
    let round: x0x::groups::GroupInfo =
        serde_json::from_str(&serde_json::to_string(&with_map).expect("json"))
            .expect("record with map round-trips");
    assert_eq!(round.mandate_capability, with_map.mandate_capability);
}

/// WHY (round 2, review item 2): the policy/public-meta comparisons are
/// INDEPENDENT of the signature — a mandate re-signed (validly, under
/// the real owner key) over a DIFFERENT hash than the terminal commit's
/// must fail the terminal comparison, proving the receiver checks what
/// the commit actually sealed rather than trusting the signed claim.
#[test]
fn mandate_terminal_hash_comparisons_are_independent_of_signature() {
    let f = mandate_fixture(owner_certified_policy(
        &UserKeypair::from_seed(&[0x9Bu8; 32]).unwrap(),
    ));
    let resign_with = |policy_hash: String, meta_hash: String| {
        x0x::groups::OwnerMandate::sign(
            &f.mandate.stable_group_id,
            f.mandate.expected_terminal_revision,
            &f.mandate.parent_state_hash,
            &f.mandate.roster_root_after_add,
            &policy_hash,
            &meta_hash,
            f.mandate.declared_epoch,
            &f.joiner_hex,
            &f.mandate.invite_secret_hash,
            &f.mandate.admission_cert_digest,
            &f.authority_hex,
            f.mandate.issued_at_ms,
            &f.owner_kp,
        )
        .expect("re-sign under the real owner key")
    };
    // Policy-hash mismatch: signature verifies over the signed (wrong)
    // value — only the terminal comparison can catch it.
    let wrong_policy = resign_with(
        f.mandate.policy_hash.clone() + "x",
        f.mandate.public_meta_hash.clone(),
    );
    assert_eq!(
        f.verify(&wrong_policy),
        Err(x0x::groups::OwnerMandateError::PolicyHashMismatch),
        "a validly-signed policy-hash mismatch must fail with the typed variant"
    );
    // Public-meta-hash mismatch: same proof for the meta hash.
    let wrong_meta = resign_with(
        f.mandate.policy_hash.clone(),
        f.mandate.public_meta_hash.clone() + "x",
    );
    assert_eq!(
        f.verify(&wrong_meta),
        Err(x0x::groups::OwnerMandateError::MetaHashMismatch),
        "a validly-signed meta-hash mismatch must fail with the typed variant"
    );
    // Control: re-signing with the terminal's own hashes still verifies.
    let right = resign_with(
        f.mandate.policy_hash.clone(),
        f.mandate.public_meta_hash.clone(),
    );
    assert!(f.verify(&right).is_ok());
}

/// WHY (round 2, review item 4): `HeadAttestation::verify_against_terminal`
/// must enforce the two-phase epoch closure (ADR-0064 §1a) — a mandate is
/// pre-mutation intent, and the terminal's ACTUAL TreeKEM epoch must equal
/// its declared epoch. A pre-slice-2 peer sends no mandate and must be
/// unaffected; a GSS-plane event carries no epoch to bind (check skipped).
/// (The across-gap adoption caller is non-TreeKEM-only today, so the
/// direct unit on the method is the honest way to drive Some-epoch arms.)
#[test]
fn head_attestation_mandate_epoch_check() {
    use x0x::server::routes::named_groups::HeadAttestation;

    let owner_kp = UserKeypair::from_seed(&[0xC3u8; 32]).expect("owner key");
    let authority_kp = AgentKeypair::generate().expect("authority key");
    let joiner_hex = hex::encode(
        AgentKeypair::generate()
            .expect("joiner")
            .agent_id()
            .as_bytes(),
    );
    let group_id = "c3".repeat(32);
    let head_state_hash = "ab".repeat(32);
    let attestation = HeadAttestation::sign(&group_id, 3, &head_state_hash, &joiner_hex, &owner_kp)
        .expect("attestation");
    let terminal = x0x::groups::GroupStateCommit::sign(
        group_id.clone(),
        4,
        Some(head_state_hash.clone()),
        "roster".to_string(),
        "policy".to_string(),
        "meta".to_string(),
        None,
        false,
        1,
        &authority_kp,
    )
    .expect("terminal");
    let owner_pk = owner_kp.public_key();
    let owner = owner_kp.user_id();
    let mandate = x0x::groups::OwnerMandate::sign(
        &group_id,
        4,
        &head_state_hash,
        "roster",
        "policy",
        "meta",
        5,
        &joiner_hex,
        &"00".repeat(32),
        &"11".repeat(32),
        &hex::encode(authority_kp.agent_id().as_bytes()),
        1,
        &owner_kp,
    )
    .expect("mandate with declared epoch 5");

    let verify = |mandate: Option<&x0x::groups::OwnerMandate>, epoch: Option<u64>| {
        attestation.verify_against_terminal(
            owner_pk,
            &owner,
            &terminal,
            &joiner_hex,
            mandate,
            epoch,
        )
    };
    assert!(
        verify(Some(&mandate), Some(5)),
        "matching declared epoch verifies"
    );
    assert!(
        !verify(Some(&mandate), Some(6)),
        "declared epoch != the terminal's actual epoch must refuse"
    );
    assert!(
        verify(None, Some(5)),
        "no mandate (pre-slice-2 peer) is unaffected"
    );
    assert!(
        verify(Some(&mandate), None),
        "GSS-plane events carry no epoch to bind"
    );
}

// ── ADR-0064 slice 3: grace state machine + owner_mandate_missing ──────

/// Seed a capability entry directly on the LIVE record — the persisted
/// shape slice 2 owns (`BTreeMap<agent, MandateCapabilityState{first_seen_ms}>`;
/// the `Refusing` phase is DERIVED at read time — only the
/// per-agent observation data persists).
async fn seed_capability(state: &AppState, group_id: &str, actor: &str, first_seen_ms: u64) {
    state
        .named_groups
        .write()
        .await
        .get_mut(group_id)
        .expect("live record")
        .mandate_capability
        .insert(
            actor.to_string(),
            x0x::groups::MandateCapabilityState {
                first_seen_ms,
                ..Default::default()
            },
        );
}

/// Apply with an explicit sender (the multi-admin test needs events whose
/// actor/sender is a remote admin, not the local agent).
async fn apply_event_from(
    state: &Arc<AppState>,
    sender: crate::identity::AgentId,
    event: NamedGroupMetadataEvent,
) -> ApplyMetadataResult {
    apply_named_group_metadata_event_inner(state, event, sender, true, true, None).await
}

/// WHY (ADR-0064 §1b exact boundary): the refusal fires at
/// `now >= first_seen + grace` — AT the deadline it refuses, one
/// millisecond earlier it applies. The exact equality is pinned at unit
/// level (deterministic); the apply path uses ±60s margins because the
/// wall clock ticks between seeding and apply. An off-by-one here either
/// wedges a capable authority a day early or leaves the enforcement
/// window open past the configured deadline.
#[test]
fn grace_deadline_is_inclusive_at_unit_level() {
    let grace_days = 60u64;
    let grace_ms = x0x::groups::mandate_grace_window_ms(grace_days);
    let state = x0x::groups::MandateCapabilityState {
        first_seen_ms: 1_000_000,
        ..Default::default()
    };
    assert!(
        state.refusal_due(grace_days, 1_000_000 + grace_ms),
        "now == first_seen + grace refuses (inclusive deadline)"
    );
    assert!(
        !state.refusal_due(grace_days, 1_000_000 + grace_ms - 1),
        "now == first_seen + grace - 1 applies"
    );
    assert_eq!(
        state.phase_label(grace_days, 1_000_000 + grace_ms),
        "refusing"
    );
    assert_eq!(
        state.phase_label(grace_days, 1_000_000 + grace_ms - 1),
        "capable"
    );
    // Poisoned clock record fails closed.
    assert!(x0x::groups::MandateCapabilityState {
        first_seen_ms: u64::MAX,
        ..Default::default()
    }
    .refusal_due(grace_days, 0));
}

#[tokio::test]
async fn grace_boundary_deadline_refuses_before_deadline_applies() -> Result<()> {
    let grace_ms = x0x::groups::mandate_grace_window_ms(60);
    // ±60s of wall-clock slack (r2 advisory E): seeding happens before
    // the apply's own `now`, and a loaded CI runner can stall for seconds
    // between the two — the margins keep the comparison unambiguous
    // without approaching the 60-day window.
    for (offset, expect_accepted, label) in [
        (-60_000i64, false, "past the deadline"),
        (60_000, true, "before the deadline"),
    ] {
        let (state, _dir, owner_kp, group_id, joiner_hex, pre_seal, cert) =
            receiver_stage().await?;
        let actor_hex = hex::encode(state.agent.agent_id().as_bytes());
        seed_capability(
            state.as_ref(),
            &group_id,
            &actor_hex,
            (now_millis_u64() as i64 - grace_ms as i64 + offset).max(0) as u64,
        )
        .await;
        let terminal =
            terminal_commit_for(&pre_seal, state.agent.identity().agent_keypair(), 2_000);
        let event = member_added_event(
            &group_id,
            terminal.revision,
            &actor_hex,
            &joiner_hex,
            &cert,
            terminal,
            None,
        );
        let result = apply_event(&state, event).await;
        assert_eq!(
            result.accepted, expect_accepted,
            "grace boundary {label}: expected accepted={expect_accepted}"
        );
        if !expect_accepted {
            let row = diag_row(state.as_ref(), &group_id).await;
            assert_eq!(row.counters.owner_mandate_missing, 1, "{label}");
            assert_eq!(row.counters.mandate_capability_refusing_transitions, 1);
            assert_eq!(row.counters.owner_mandate_absent, 0);
        } else {
            let row = diag_row(state.as_ref(), &group_id).await;
            assert_eq!(row.counters.owner_mandate_missing, 0, "{label}");
            assert_eq!(row.counters.owner_mandate_absent, 1);
        }
        drop(_dir);
        let _ = &owner_kp;
    }
    Ok(())
}

/// WHY (§1b "clock retained"): a valid mandate from a past-grace authority
/// is ACCEPTED (Refusing → Capable on that event) and the FIRST observation
/// time is retained — a second absent-mandate event is refused again. A
/// clock reset here would hand a compromised authority an infinite
/// reset-on-demand window.
#[tokio::test]
async fn valid_mandate_recapables_but_retained_clock_refuses_next_absence() -> Result<()> {
    let (state, _dir, owner_kp, group_id, joiner_hex, pre_seal, cert) = receiver_stage().await?;
    let actor_hex = hex::encode(state.agent.agent_id().as_bytes());
    let first_seen = now_millis_u64() - x0x::groups::mandate_grace_window_ms(60) - 1;
    seed_capability(state.as_ref(), &group_id, &actor_hex, first_seen).await;

    // Event 1: VALID mandate → accepted, clock retained.
    let terminal = terminal_commit_for(&pre_seal, state.agent.identity().agent_keypair(), 2_000);
    let mandate = mint_mandate_like_authority(
        &pre_seal,
        None,
        0,
        &joiner_hex,
        &actor_hex,
        "s3-recapable",
        &cert,
        &owner_kp,
        1_500,
    );
    let event = member_added_event(
        &group_id,
        terminal.revision,
        &actor_hex,
        &joiner_hex,
        &cert,
        terminal,
        Some(mandate),
    );
    assert!(
        apply_event(&state, event).await.accepted,
        "valid mandate applies"
    );
    let live = live_record(state.as_ref(), &group_id).await;
    assert_eq!(
        live.mandate_capability
            .get(&actor_hex)
            .map(|c| c.first_seen_ms),
        Some(first_seen),
        "capability clock retained, not reset"
    );

    // Event 2: another joiner, no mandate, SAME retained clock → refused.
    let joiner2 = AgentKeypair::generate()?;
    let joiner2_hex = hex::encode(joiner2.agent_id().as_bytes());
    let cert2 = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner2.public_key().as_bytes(),
        None,
    )?;
    let pre_seal2 = seat_write(&live, &joiner2_hex, &actor_hex, &cert2);
    let terminal2 = terminal_commit_for(&pre_seal2, state.agent.identity().agent_keypair(), 3_000);
    let event2 = member_added_event(
        &group_id,
        terminal2.revision,
        &actor_hex,
        &joiner2_hex,
        &cert2,
        terminal2,
        None,
    );
    assert!(
        !apply_event(&state, event2).await.accepted,
        "retained clock: next absent-mandate event refuses again"
    );
    let row = diag_row(state.as_ref(), &group_id).await;
    assert_eq!(row.counters.owner_mandate_missing, 1);
    Ok(())
}

/// WHY (§1b refusal contract): the refusal is typed, retryable, and leaves
/// the record BYTE-IDENTICAL — nothing persisted, nothing queued as a
/// revision gap, no causal side effects. The sender-side bounded resend
/// (or a mandate-carrying re-issue) is the redelivery path.
#[tokio::test]
async fn refusal_is_byte_identical_not_queued_no_causal_side_effects() -> Result<()> {
    let (state, _dir, owner_kp, group_id, joiner_hex, pre_seal, cert) = receiver_stage().await?;
    let actor_hex = hex::encode(state.agent.agent_id().as_bytes());
    seed_capability(
        state.as_ref(),
        &group_id,
        &actor_hex,
        now_millis_u64() - x0x::groups::mandate_grace_window_ms(60),
    )
    .await;
    let terminal = terminal_commit_for(&pre_seal, state.agent.identity().agent_keypair(), 2_000);
    let event = member_added_event(
        &group_id,
        terminal.revision,
        &actor_hex,
        &joiner_hex,
        &cert,
        terminal,
        None,
    );
    let strip_map = |mut value: serde_json::Value| {
        if let Some(record) = value.as_object_mut() {
            record.remove("mandate_capability");
        }
        value
    };
    let before = serde_json::to_string(&strip_map(serde_json::to_value(
        &live_record(state.as_ref(), &group_id).await,
    )?))?;
    let result = apply_event(&state, event).await;
    assert!(!result.accepted, "past-grace absent mandate refuses");
    let after_live = live_record(state.as_ref(), &group_id).await;
    let after = serde_json::to_string(&strip_map(serde_json::to_value(&after_live)?))?;
    assert_eq!(
        before, after,
        "refusal leaves the COMMITTED record byte-identical (the only write is the local-only capability map)"
    );
    let capability = after_live
        .mandate_capability
        .get(&actor_hex)
        .expect("capability entry survives the refusal");
    assert_eq!(capability.refusals, 1, "per-agent refusal counted");
    assert!(capability.refusal_transition_counted);
    assert!(!live_record(state.as_ref(), &group_id)
        .await
        .has_active_member(&joiner_hex));
    let row = diag_row(state.as_ref(), &group_id).await;
    assert_eq!(row.counters.owner_mandate_missing, 1);
    assert_eq!(row.counters.owner_mandate_absent, 0);
    // NOT queued: neither the revision-gap queue nor any causal counter
    // moved — the refusal must not masquerade as a chain gap (blueprint
    // §5: queue admission is for catch-up, not enforcement refusals).
    assert_eq!(row.counters.membership_events_queued_revision_gap, 0);
    assert_eq!(row.counters.causal_queued, 0);
    assert_eq!(row.counters.causal_invalid, 0);
    assert_eq!(
        row.counters.member_added_events_rejected_state_chain_gap, 0,
        "the mandate refusal is not the chain-gap bucket"
    );
    let _ = &owner_kp;
    Ok(())
}

/// WHY (blueprint slice-3 fault row, the group-level-state trap): one
/// group, two admins — A is recorded-capable and past grace (refused),
/// B was never observed (warn-accepted). A group-level state would have
/// refused BOTH; the per-agent map preserves the multi-admin model
/// (#472 decision 7 ratifies the never-observed boundary).
#[tokio::test]
async fn multi_admin_capable_refused_unknown_accepted_same_group() -> Result<()> {
    let (state, _dir, owner_kp, group_id, _joiner_hex, _pre_seal, _cert) = receiver_stage().await?;
    let admin_a = AgentKeypair::generate()?;
    let admin_b = AgentKeypair::generate()?;
    let a_hex = hex::encode(admin_a.agent_id().as_bytes());
    let b_hex = hex::encode(admin_b.agent_id().as_bytes());
    // Seat both as admins on the live record (post-seal; the terminal
    // commits below chain from the sealed base and carry the signer-admin
    // roster the apply arm validates).
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group_id).expect("live record");
        info.add_member(a_hex.clone(), x0x::groups::GroupRole::Admin, None, None);
        info.add_member(b_hex.clone(), x0x::groups::GroupRole::Admin, None, None);
    }
    let base = live_record(state.as_ref(), &group_id).await;
    // A: recorded-capable, past grace.
    seed_capability(
        state.as_ref(),
        &group_id,
        &a_hex,
        now_millis_u64() - x0x::groups::mandate_grace_window_ms(60),
    )
    .await;

    let joiner1 = AgentKeypair::generate()?;
    let joiner1_hex = hex::encode(joiner1.agent_id().as_bytes());
    let cert1 = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner1.public_key().as_bytes(),
        None,
    )?;
    let pre_a = seat_write(&base, &joiner1_hex, &a_hex, &cert1);
    let terminal_a = terminal_commit_for(&pre_a, &admin_a, 2_000);
    let event_a = member_added_event(
        &group_id,
        terminal_a.revision,
        &a_hex,
        &joiner1_hex,
        &cert1,
        terminal_a,
        None,
    );
    let result_a = apply_event_from(&state, admin_a.agent_id(), event_a).await;
    assert!(!result_a.accepted, "capable admin A past grace: refused");

    let joiner2 = AgentKeypair::generate()?;
    let joiner2_hex = hex::encode(joiner2.agent_id().as_bytes());
    let cert2 = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner2.public_key().as_bytes(),
        None,
    )?;
    let pre_b = seat_write(&base, &joiner2_hex, &b_hex, &cert2);
    let terminal_b = terminal_commit_for(&pre_b, &admin_b, 2_500);
    let event_b = member_added_event(
        &group_id,
        terminal_b.revision,
        &b_hex,
        &joiner2_hex,
        &cert2,
        terminal_b,
        None,
    );
    let result_b = apply_event_from(&state, admin_b.agent_id(), event_b).await;
    assert!(
        result_b.accepted,
        "never-observed admin B (no capability entry): warn-accepted"
    );
    let live = live_record(state.as_ref(), &group_id).await;
    assert!(
        !live.has_active_member(&joiner1_hex),
        "A's joiner not seated"
    );
    assert!(live.has_active_member(&joiner2_hex), "B's joiner seated");
    let row = diag_row(state.as_ref(), &group_id).await;
    assert_eq!(row.counters.owner_mandate_missing, 1);
    assert_eq!(row.counters.owner_mandate_absent, 1);
    Ok(())
}

/// WHY (round-2 advisory A1, closed by slice 3): a node holding the owner
/// user key must mint a mandate on EVERY seat path — the direct admin-add
/// routes included, or a Capable authority's own direct adds would be
/// refused by its peers the moment the grace window closes. Drive the REAL
/// GSS add route, capture the published event bytes, and prove the
/// mandate rides the wire and verifies for a peer.
#[tokio::test]
async fn direct_admin_add_mints_mandate_peer_applies_and_records_capable() -> Result<()> {
    let (authority, _dir, owner_kp, group_id, base_before) = async {
        let (state, dir, owner_kp) = owner_authority_state().await?;
        let group_id = "3c".repeat(32);
        let base =
            sealed_group(state.as_ref(), &group_id, owner_certified_policy(&owner_kp)).await?;
        Ok::<_, anyhow::Error>((state, dir, owner_kp, group_id, base))
    }
    .await?;
    let joiner_kp = AgentKeypair::generate()?;
    let joiner_hex = hex::encode(joiner_kp.agent_id().as_bytes());
    let joiner_cert = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner_kp.public_key().as_bytes(),
        None,
    )?;
    // ADR-0038 admission evidence: seed the discovery cache the way a
    // verified announce fetch does (same as the adr0038 fixtures).
    {
        let cache = authority.agent.identity_discovery_cache();
        cache.write().await.insert(
            joiner_cert.agent_id()?,
            x0x::DiscoveredAgent {
                agent_id: joiner_cert.agent_id()?,
                machine_id: x0x::identity::MachineId([0u8; 32]),
                user_id: joiner_cert.user_id().ok(),
                self_name: None,
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
                cert_not_after: joiner_cert.not_after(),
                agent_certificate: Some(joiner_cert.clone()),
                cert_digest: None,
                agent_public_key: Vec::new(),
            },
        );
    }
    NAMED_GROUP_METADATA_PUBLISH_BYTES_FOR_TEST
        .lock()
        .expect("publish hook")
        .clear();
    let response = add_named_group_member(
        State(Arc::clone(&authority)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
        Json(AddNamedGroupMemberRequest {
            agent_id: joiner_hex.clone(),
            display_name: None,
            treekem_key_package_b64: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    // The published MemberAdded carries a mandate that verifies.
    let published = NAMED_GROUP_METADATA_PUBLISH_BYTES_FOR_TEST
        .lock()
        .expect("publish hook")
        .iter()
        .filter_map(|(_topic, bytes)| serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok())
        .find_map(|event| match &event {
            NamedGroupMetadataEvent::MemberAdded { agent_id, .. } if *agent_id == joiner_hex => {
                Some(event)
            }
            _ => None,
        })
        .expect("published MemberAdded for the direct add");
    let (actor_field, mandate, commit, cert_b64) = match &published {
        NamedGroupMetadataEvent::MemberAdded {
            actor,
            owner_mandate,
            commit: Some(commit),
            certificate_b64,
            ..
        } => (
            actor.clone(),
            owner_mandate.clone(),
            commit.clone(),
            certificate_b64.clone(),
        ),
        _ => panic!("shape"),
    };
    let mandate = mandate.expect("direct add on an owner-key install mints a mandate");
    assert_eq!(mandate.invite_secret_hash, blake3_hex_of(""));
    let _ = cert_b64;
    let authority_base = live_record(authority.as_ref(), &group_id).await;
    use base64::Engine as _;
    let cert_bytes = BASE64
        .decode(cert_b64.expect("certificate rides the direct add"))
        .expect("cert bytes");
    let peer_cert = bincode::deserialize::<x0x::identity::AgentCertificate>(&cert_bytes)?;
    mandate
        .verify_against_terminal(
            owner_kp.public_key(),
            &owner_kp.user_id(),
            &authority_base,
            &commit,
            &actor_field,
            &joiner_hex,
            None,
            Some(&x0x::groups::owner_cert::certificate_digest_hex(&peer_cert)),
        )
        .expect("the direct-add mandate verifies against the terminal");
    // Peer node: same base, applies the captured event, records Capable.
    let peer_dir = tempfile::tempdir()?;
    let peer_agent = Arc::new(
        Agent::builder()
            .with_machine_key(peer_dir.path().join("machine.key"))
            .with_agent_key(AgentKeypair::generate()?)
            .with_peer_cache_disabled()
            .with_contact_store_path(peer_dir.path().join("contacts.json"))
            .build()
            .await?,
    );
    let peer = secure_endpoint_test_state_at(peer_dir.path(), peer_agent).await?;
    {
        // The peer holds the PRE-ADD base (revision 1); applying the
        // event advances it to the authority's post-add head.
        let mut groups = peer.named_groups.write().await;
        groups.insert(group_id.clone(), base_before.clone());
    }
    let sender = authority.agent.agent_id();
    let result =
        apply_named_group_metadata_event_inner(&peer, published, sender, true, true, None).await;
    assert!(result.accepted, "peer applies the direct add");
    let peer_live = live_record(peer.as_ref(), &group_id).await;
    assert!(peer_live.has_active_member(&joiner_hex));
    let peer_capability = peer_live
        .mandate_capability
        .get(&actor_field)
        .expect("peer records Capable for the direct-add authority");
    assert!(peer_capability.first_seen_ms > 0);
    assert!(
        !peer_capability.refusal_due(60, now_millis_u64()),
        "freshly recorded capability is within grace"
    );
    Ok(())
}

// ── ADR-0064 slice 3: manual quarantine clear (#472 decision 1) ────────

/// Plant a fork-quarantine marker on the LIVE record (in-memory; the
/// endpoint reads the live map, so no persist round-trip is needed) and
/// return the marked view.
async fn quarantine_live(state: &AppState, group_id: &str) -> x0x::groups::GroupInfo {
    let mut groups = state.named_groups.write().await;
    let info = groups.get_mut(group_id).expect("live record");
    let snapshot_commit = fake_group_state_commit(
        info.stable_group_id(),
        1,
        &hex::encode(state.agent.agent_id().as_bytes()),
    );
    info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
        revision: 1,
        state_hash: info.state_hash.clone(),
        committed_by: hex::encode(state.agent.agent_id().as_bytes()),
        observed_at_ms: now_millis_u64(),
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: snapshot_commit.clone(),
            conflicting_commit: snapshot_commit,
            classification: None,
        },
        no_anchor: false,
    });
    info.clone()
}

async fn call_clear(
    state: &Arc<AppState>,
    group_id: &str,
    req: ClearQuarantineRequest,
) -> (StatusCode, serde_json::Value) {
    let response = clear_group_quarantine(
        State(Arc::clone(state)),
        Path(group_id.to_string()),
        Json(req),
    )
    .await
    .into_response();
    let status = response.status();
    let body = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body"),
    )
    .expect("json body");
    (status, body)
}

/// WHY (#472 decision 1, r2 maintainer decision): the clear paths.
/// (a) OWNER-KEY NODE — called without force on the install holding the
///     owner user key, the endpoint mints a fresh quarantine-clear
///     attestation over the CURRENT head under the dedicated domain,
///     verifies it, and clears; a KEYLESS node gets the typed
///     `owner_key_unavailable` 409. (b) `force` + non-empty `reason`
///     clears on any node. Anything else is a typed 409.
#[tokio::test]
async fn manual_clear_owner_key_and_force_paths() -> Result<()> {
    let (state, _dir, owner_kp, group_id, _j, _p, _c) = receiver_stage().await?;
    let info = quarantine_live(state.as_ref(), &group_id).await;

    // (c) force without a reason → 409, marker stays.
    let (status, body) = call_clear(
        &state,
        &group_id,
        ClearQuarantineRequest {
            force: true,
            reason: String::new(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        live_record(state.as_ref(), &group_id)
            .await
            .fork_quarantine
            .is_some(),
        "refused clear leaves the marker"
    );

    // (a) owner-key node, no force → minted+verified attestation clears.
    let (status, body) = call_clear(
        &state,
        &group_id,
        ClearQuarantineRequest {
            force: false,
            reason: String::new(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["cleared_by"], "owner-key");
    assert!(body["fork_quarantine"].is_null());
    assert!(live_record(state.as_ref(), &group_id)
        .await
        .fork_quarantine
        .is_none());

    // Re-quarantine and take the (b) force path.
    quarantine_live(state.as_ref(), &group_id).await;
    let (status, body) = call_clear(
        &state,
        &group_id,
        ClearQuarantineRequest {
            force: true,
            reason: "ops runbook R1: false positive reviewed".to_string(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["cleared_by"], "force");
    assert!(live_record(state.as_ref(), &group_id)
        .await
        .fork_quarantine
        .is_none());
    let row = diag_row(state.as_ref(), &group_id).await;
    assert_eq!(row.counters.fork_quarantine_manual_clears, 2);
    let _ = (&info, &owner_kp);
    Ok(())
}

/// WHY: a node WITHOUT the group's owner user key cannot take path (a) —
/// the typed `owner_key_unavailable` 409 names the force path instead of
/// failing opaquely.
#[tokio::test]
async fn manual_clear_keyless_node_gets_typed_owner_key_unavailable() -> Result<()> {
    // Same group record, but the local install has NO user key.
    let (owner_state, dir, owner_kp, group_id, _j, _p, _c) = receiver_stage().await?;
    let marked = quarantine_live(owner_state.as_ref(), &group_id).await;
    let keyless_dir = tempfile::tempdir()?;
    let keyless_agent = Arc::new(
        Agent::builder()
            .with_machine_key(keyless_dir.path().join("machine.key"))
            .with_agent_key(AgentKeypair::generate()?)
            .with_peer_cache_disabled()
            .with_contact_store_path(keyless_dir.path().join("contacts.json"))
            .build()
            .await?,
    );
    let keyless = secure_endpoint_test_state_at(keyless_dir.path(), keyless_agent).await?;
    keyless
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), marked);
    let (status, body) = call_clear(
        &keyless,
        &group_id,
        ClearQuarantineRequest {
            force: false,
            reason: String::new(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("owner_key_unavailable")),
        "typed refusal names the escape hatch: {body}"
    );
    // The force path still works on the keyless node.
    let (status, _body) = call_clear(
        &keyless,
        &group_id,
        ClearQuarantineRequest {
            force: true,
            reason: "keyless node, operator override".to_string(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    drop(dir);
    let _ = &owner_kp;
    Ok(())
}

/// WHY (item 7 of the r2 CI addendum): prove the endpoint through the
/// REAL router + auth middleware (path resolution, durable-token gate),
/// not only via the handler — the coverage marker for
/// `POST /groups/:id/quarantine/clear` points here.
#[tokio::test]
async fn quarantine_clear_route_through_real_middleware() -> Result<()> {
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    let (state, _dir, _owner_kp, group_id, _j, _p, _c) = receiver_stage().await?;
    quarantine_live(state.as_ref(), &group_id).await;
    let app = axum::Router::new()
        .route(
            "/groups/:id/quarantine/clear",
            axum::routing::post(clear_group_quarantine),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::server::auth::auth_middleware,
        ))
        .with_state(Arc::clone(&state));

    // No token → 401 before the handler runs.
    let response = app
        .clone()
        .oneshot(
            Request::post(format!("/groups/{group_id}/quarantine/clear"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .expect("body builds"),
        )
        .await
        .unwrap_or_else(|never| match never {});
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Durable token + owner-key node → the owner-key clear path.
    let token = state.api_token.clone();
    let response = app
        .oneshot(
            Request::post(format!("/groups/{group_id}/quarantine/clear"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .expect("body builds"),
        )
        .await
        .unwrap_or_else(|never| match never {});
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1 << 20).await?;
    let body: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(body["cleared_by"], "owner-key");
    assert!(body["fork_quarantine"].is_null());
    assert!(live_record(state.as_ref(), &group_id)
        .await
        .fork_quarantine
        .is_none());
    Ok(())
}

/// WHY (decision 2, byte-for-byte restriction): non-owner-axis groups
/// never carry a marker, so the clear endpoint answers 409 (nothing to
/// clear) — the ordinary groups' behaviour is unchanged by this slice.
#[tokio::test]
async fn manual_clear_non_owner_axis_group_refuses() -> Result<()> {
    let (state, _dir, _owner_kp, group_id, _j, _p, _c) = receiver_stage().await?;
    // An ordinary (invite-only) group: never marked.
    sealed_group(state.as_ref(), &group_id, invite_only_policy()).await?;
    let (status, body) = call_clear(
        &state,
        &group_id,
        ClearQuarantineRequest {
            force: true,
            reason: "should not clear".to_string(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("not quarantined")),
        "{body}"
    );
    assert!(live_record(state.as_ref(), &group_id)
        .await
        .mandate_capability
        .is_empty());
    Ok(())
}

/// WHY (#451-style mixed fleet): a SLICE-2-persisted record (capability
/// map, no other slice-3 state — none was added) loads under the slice-3
/// binary and the grace derivation activates from the persisted clock
/// alone. Downgrades/upgrades never brick on the persisted shape.
#[tokio::test]
async fn slice2_persisted_record_derives_grace_under_slice3() -> Result<()> {
    let (state, dir, _owner_kp, group_id, _j, _p, _c) = receiver_stage().await?;
    let now = now_millis_u64();
    let grace_ms = x0x::groups::mandate_grace_window_ms(60);
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group_id).expect("live record");
        info.mandate_capability.insert(
            "aa".repeat(32),
            x0x::groups::MandateCapabilityState {
                first_seen_ms: now - grace_ms,
                ..Default::default()
            },
        );
        info.mandate_capability.insert(
            "bb".repeat(32),
            x0x::groups::MandateCapabilityState {
                first_seen_ms: now,
                ..Default::default()
            },
        );
    }
    // Durably persist the mutated record (the slice-2 JSON shape; no
    // slice-3 fields exist), then round-trip through the REAL loader.
    let marked = live_record(state.as_ref(), &group_id).await;
    persist_named_group_info(&state, &group_id, marked).await?;
    let reloaded =
        load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path).await?;
    let record = reloaded.get(&group_id).expect("persisted");
    let refusing = record
        .mandate_capability
        .get(&"aa".repeat(32))
        .expect("persisted entry");
    assert!(
        refusing.refusal_due(60, now),
        "past-grace entry derives Refusing"
    );
    assert_eq!(refusing.phase_label(60, now), "refusing");
    let capable = record
        .mandate_capability
        .get(&"bb".repeat(32))
        .expect("persisted entry");
    assert!(!capable.refusal_due(60, now), "fresh entry derives Capable");
    assert_eq!(capable.phase_label(60, now), "capable");
    // The diagnostics snapshot surfaces the derived phases per agent.
    let row = diag_row(state.as_ref(), &group_id).await;
    assert_eq!(row.mandate_capability.len(), 2);
    assert!(row
        .mandate_capability
        .iter()
        .any(|entry| entry.agent_id == "aa".repeat(32) && entry.state == "refusing"));
    assert!(row
        .mandate_capability
        .iter()
        .any(|entry| entry.agent_id == "bb".repeat(32) && entry.state == "capable"));
    drop(dir);
    Ok(())
}

/// WHY (r2 item 5): the TreeKEM sibling of the direct-add mint — the
/// route must mint with `declared_epoch == guard.epoch()+1` and the event
/// must carry that same epoch, or a previously warn-accepted direct add
/// turns into `owner_mandate_invalid` on every mandate-aware peer. The
/// negative arm documents exactly that regression class: a mandate whose
/// declared epoch disagrees with the event's treekem_epoch is refused
/// even though the signature itself is honest owner-key material.
#[tokio::test]
async fn treekem_direct_add_mints_epoch_bound_mandate_peer_applies() -> Result<()> {
    let (authority, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "5e".repeat(32);
    let group_id_bytes = hex::decode(&group_id)?;
    let creator_seed = agent_treekem_seed(authority.agent.as_ref(), &group_id_bytes);
    let treekem_group = x0x::mls::TreeKemMlsGroup::create(
        group_id_bytes,
        authority.agent.agent_id(),
        &creator_seed,
    )?;
    let initial_epoch = treekem_group.epoch();
    let mut info = x0x::groups::GroupInfo::with_policy(
        "treekem-direct-add".to_string(),
        String::new(),
        authority.agent.agent_id(),
        group_id.clone(),
        owner_certified_policy(&owner_kp),
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.shared_secret = None;
    info.secret_epoch = initial_epoch;
    info.security_binding = Some(format!("treekem:epoch={initial_epoch}"));
    info.recompute_state_hash();
    // Genesis + revision-1 base commit (the mint refuses genesis-less
    // groups — a mandate minted against the mls-id fallback could never
    // verify against the seal's derived stable id).
    seal_commit_owner_certified(
        authority.as_ref(),
        &mut info,
        authority.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await?;
    let base_before = info.clone();
    authority
        .treekem_groups
        .write()
        .await
        .insert(group_id.clone(), Arc::new(Mutex::new(treekem_group)));
    authority
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    // Joiner: owner-issued certificate (ADR-0038 admission) + a real
    // TreeKEM key package.
    let joiner_kp = AgentKeypair::generate()?;
    let joiner_id = joiner_kp.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let joiner_cert = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner_kp.public_key().as_bytes(),
        None,
    )?;
    {
        let cache = authority.agent.identity_discovery_cache();
        cache.write().await.insert(
            joiner_cert.agent_id()?,
            x0x::DiscoveredAgent {
                agent_id: joiner_cert.agent_id()?,
                machine_id: x0x::identity::MachineId([0u8; 32]),
                user_id: joiner_cert.user_id().ok(),
                self_name: None,
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
                cert_not_after: joiner_cert.not_after(),
                agent_certificate: Some(joiner_cert.clone()),
                cert_digest: None,
                agent_public_key: Vec::new(),
            },
        );
    }
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(joiner_id, &[0x5E; 32])?;
    let key_package_b64 = BASE64.encode(prepared.key_package_bytes());

    NAMED_GROUP_METADATA_PUBLISH_BYTES_FOR_TEST
        .lock()
        .expect("publish hook")
        .clear();
    let response = add_named_group_member(
        State(Arc::clone(&authority)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
        Json(AddNamedGroupMemberRequest {
            agent_id: joiner_hex.clone(),
            display_name: None,
            treekem_key_package_b64: Some(key_package_b64),
        }),
    )
    .await
    .into_response();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "TreeKEM direct add must succeed"
    );

    let published = NAMED_GROUP_METADATA_PUBLISH_BYTES_FOR_TEST
        .lock()
        .expect("publish hook")
        .iter()
        .filter_map(|(_topic, bytes)| serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok())
        .find_map(|event| match &event {
            NamedGroupMetadataEvent::MemberAdded { agent_id, .. } if *agent_id == joiner_hex => {
                Some(event)
            }
            _ => None,
        })
        .expect("published TreeKEM MemberAdded");
    let (actor_field, mandate, commit, event_epoch) = match &published {
        NamedGroupMetadataEvent::MemberAdded {
            actor,
            owner_mandate,
            commit: Some(commit),
            treekem_epoch,
            ..
        } => (
            actor.clone(),
            owner_mandate
                .clone()
                .expect("TreeKEM direct add mints a mandate"),
            commit.clone(),
            *treekem_epoch,
        ),
        _ => panic!("shape"),
    };
    let event_epoch = event_epoch.expect("TreeKEM direct add carries an epoch");
    assert_eq!(
        mandate.declared_epoch, event_epoch,
        "declared_epoch must equal the event's treekem_epoch (guard.epoch()+1)"
    );
    assert!(event_epoch > initial_epoch);

    // A peer (non-member, no local TreeKEM ratchet) applies the
    // state-only arm and records Capable.
    let peer_dir = tempfile::tempdir()?;
    let peer_agent = Arc::new(
        Agent::builder()
            .with_machine_key(peer_dir.path().join("machine.key"))
            .with_agent_key(AgentKeypair::generate()?)
            .with_peer_cache_disabled()
            .with_contact_store_path(peer_dir.path().join("contacts.json"))
            .build()
            .await?,
    );
    let peer = secure_endpoint_test_state_at(peer_dir.path(), peer_agent).await?;
    peer.named_groups
        .write()
        .await
        .insert(group_id.clone(), base_before.clone());
    let sender = authority.agent.agent_id();
    let result =
        apply_named_group_metadata_event_inner(&peer, published.clone(), sender, true, true, None)
            .await;
    // First admission with allow_queue=true (the subscriber path): a
    // peer with no local TreeKEM ratchet DEFERS the event to the #492
    // queue (treekem_not_ready) — exactly the production catch-up flow.
    assert!(
        !result.accepted,
        "first admission defers to the revision-gap queue, not a drop"
    );
    let queued = peer
        .treekem_pending_events
        .read()
        .await
        .get(&group_id)
        .map(|queue| queue.len())
        .unwrap_or(0);
    assert_eq!(
        queued, 1,
        "the event is QUEUED (redelivery path), never dropped"
    );
    // The queue-drain path (replay_pending_treekem_events re-applies
    // with allow_queue=false): state-only apply for the non-member peer.
    let replay =
        apply_named_group_metadata_event_inner(&peer, published.clone(), sender, true, false, None)
            .await;
    assert!(
        replay.accepted,
        "peer applies the TreeKEM direct add on drain"
    );
    let peer_live = live_record(peer.as_ref(), &group_id).await;
    assert!(peer_live.has_active_member(&joiner_hex));
    assert!(
        peer_live
            .mandate_capability
            .get(&actor_field)
            .is_some_and(|capability| capability.first_seen_ms > 0),
        "peer records Capable for the TreeKEM direct-add authority"
    );

    // Negative arm: an honestly owner-signed mandate whose declared epoch
    // disagrees with the event's treekem_epoch must refuse as
    // owner_mandate_invalid on a fresh peer (state byte-identical) — the
    // exact regression class a wrong epoch at the mint site would ship.
    let peer2_dir = tempfile::tempdir()?;
    let peer2_agent = Arc::new(
        Agent::builder()
            .with_machine_key(peer2_dir.path().join("machine.key"))
            .with_agent_key(AgentKeypair::generate()?)
            .with_peer_cache_disabled()
            .with_contact_store_path(peer2_dir.path().join("contacts.json"))
            .build()
            .await?,
    );
    let peer2 = secure_endpoint_test_state_at(peer2_dir.path(), peer2_agent).await?;
    peer2
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), base_before.clone());
    let mut wrong_epoch_mandate = mandate.clone();
    wrong_epoch_mandate.declared_epoch = event_epoch + 1;
    let signed_wrong = x0x::groups::OwnerMandate::sign(
        &wrong_epoch_mandate.stable_group_id,
        wrong_epoch_mandate.expected_terminal_revision,
        &wrong_epoch_mandate.parent_state_hash,
        &wrong_epoch_mandate.roster_root_after_add,
        &wrong_epoch_mandate.policy_hash,
        &wrong_epoch_mandate.public_meta_hash,
        wrong_epoch_mandate.declared_epoch,
        &wrong_epoch_mandate.joiner_agent_id,
        &wrong_epoch_mandate.invite_secret_hash,
        &wrong_epoch_mandate.admission_cert_digest,
        &wrong_epoch_mandate.authority_agent_id,
        wrong_epoch_mandate.issued_at_ms,
        &owner_kp,
    )
    .map_err(|e| anyhow::anyhow!("re-sign: {e}"))?;
    let wrong_event = match published.clone() {
        NamedGroupMetadataEvent::MemberAdded {
            group_id,
            revision,
            actor,
            agent_id,
            display_name,
            treekem_commit_b64,
            treekem_welcome_b64,
            welcome_ref,
            treekem_epoch,
            treekem_key_package_hash,
            member_joined_recovery,
            member_recovery_history,
            certificate_b64,
            ..
        } => NamedGroupMetadataEvent::MemberAdded {
            group_id,
            revision,
            actor,
            agent_id,
            display_name,
            treekem_commit_b64,
            treekem_welcome_b64,
            welcome_ref,
            treekem_epoch,
            treekem_key_package_hash,
            member_joined_recovery,
            member_recovery_history,
            certificate_b64,
            owner_mandate: Some(signed_wrong),
            commit: Some(commit),
        },
        _ => panic!("shape"),
    };
    let before = serde_json::to_string(&live_record(peer2.as_ref(), &group_id).await)?;
    let result =
        apply_named_group_metadata_event_inner(&peer2, wrong_event, sender, true, false, None)
            .await;
    assert!(
        !result.accepted,
        "declared_epoch != treekem_epoch must refuse as owner_mandate_invalid"
    );
    let after = serde_json::to_string(&live_record(peer2.as_ref(), &group_id).await)?;
    assert_eq!(before, after, "refusal leaves the record byte-identical");
    let row = diag_row(peer2.as_ref(), &group_id).await;
    assert_eq!(row.counters.owner_mandate_invalid, 1);
    Ok(())
}

/// WHY (r2 item 4): `mandate_capability_refusing_transitions` must be a
/// PER-AGENT one-shot transition count, not a second name for
/// `owner_mandate_missing`. Two refusals from the same agent count ONE
/// Capable→Refusing transition; a later valid mandate restores Capable
/// (the flag clears), so the next refusal is a NEW transition. The
/// per-agent refusal total lives on the persisted capability state.
#[tokio::test]
async fn refusing_transitions_counted_per_agent_one_shot() -> Result<()> {
    let (state, _dir, owner_kp, group_id, _j1, pre_seal, _cert) = receiver_stage().await?;
    let actor_hex = hex::encode(state.agent.agent_id().as_bytes());
    let first_seen = now_millis_u64() - x0x::groups::mandate_grace_window_ms(60) - 1;
    seed_capability(state.as_ref(), &group_id, &actor_hex, first_seen).await;

    // Refusal #1: the Capable → Refusing transition.
    let terminal = terminal_commit_for(&pre_seal, state.agent.identity().agent_keypair(), 2_000);
    let joiner1 = AgentKeypair::generate()?;
    let joiner1_hex = hex::encode(joiner1.agent_id().as_bytes());
    let cert1 = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner1.public_key().as_bytes(),
        None,
    )?;
    let pre1 = seat_write(
        &live_record(state.as_ref(), &group_id).await,
        &joiner1_hex,
        &actor_hex,
        &cert1,
    );
    let terminal1 = terminal_commit_for(&pre1, state.agent.identity().agent_keypair(), 2_000);
    let _ = terminal;
    assert!(
        !apply_event(
            &state,
            member_added_event(
                &group_id,
                terminal1.revision,
                &actor_hex,
                &joiner1_hex,
                &cert1,
                terminal1,
                None
            ),
        )
        .await
        .accepted
    );

    // Refusal #2 from the SAME agent: another refused event, NOT another
    // transition.
    let joiner2 = AgentKeypair::generate()?;
    let joiner2_hex = hex::encode(joiner2.agent_id().as_bytes());
    let cert2 = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner2.public_key().as_bytes(),
        None,
    )?;
    let pre2 = seat_write(
        &live_record(state.as_ref(), &group_id).await,
        &joiner2_hex,
        &actor_hex,
        &cert2,
    );
    let terminal2 = terminal_commit_for(&pre2, state.agent.identity().agent_keypair(), 2_500);
    assert!(
        !apply_event(
            &state,
            member_added_event(
                &group_id,
                terminal2.revision,
                &actor_hex,
                &joiner2_hex,
                &cert2,
                terminal2,
                None
            ),
        )
        .await
        .accepted
    );

    let row = diag_row(state.as_ref(), &group_id).await;
    assert_eq!(
        row.counters.owner_mandate_missing, 2,
        "every refusal counts"
    );
    assert_eq!(
        row.counters.mandate_capability_refusing_transitions, 1,
        "one Capable→Refusing transition per episode"
    );
    let live = live_record(state.as_ref(), &group_id).await;
    let capability = live
        .mandate_capability
        .get(&actor_hex)
        .expect("capability entry");
    assert_eq!(capability.refusals, 2, "per-agent refusals == 2");
    assert_eq!(capability.first_seen_ms, first_seen, "clock retained");
    // r3 safety advisory: the persist-side update can never (re)mint an
    // entry — a vanished entry is skipped, so `first_seen_ms = 0`
    // (permanently-Refusing under any clock) is unreachable.
    assert_ne!(
        capability.first_seen_ms, 0,
        "refusal persist must never mint a zero clock"
    );
    assert!(
        row.mandate_capability
            .iter()
            .any(|entry| entry.agent_id == actor_hex && entry.refusals == 2),
        "per-agent refusals surfaced in /diagnostics/groups"
    );

    // A valid mandate restores Capable: the flag clears, so the NEXT
    // refusal is a new transition (and the clock is still retained).
    let joiner3 = AgentKeypair::generate()?;
    let joiner3_hex = hex::encode(joiner3.agent_id().as_bytes());
    let cert3 = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner3.public_key().as_bytes(),
        None,
    )?;
    let pre3 = seat_write(
        &live_record(state.as_ref(), &group_id).await,
        &joiner3_hex,
        &actor_hex,
        &cert3,
    );
    let terminal3 = terminal_commit_for(&pre3, state.agent.identity().agent_keypair(), 3_000);
    let mandate3 = mint_mandate_like_authority(
        &pre3,
        None,
        0,
        &joiner3_hex,
        &actor_hex,
        "s3r2-transitions",
        &cert3,
        &owner_kp,
        1_500,
    );
    assert!(
        apply_event(
            &state,
            member_added_event(
                &group_id,
                terminal3.revision,
                &actor_hex,
                &joiner3_hex,
                &cert3,
                terminal3,
                Some(mandate3)
            ),
        )
        .await
        .accepted
    );
    let live = live_record(state.as_ref(), &group_id).await;
    let capability = live
        .mandate_capability
        .get(&actor_hex)
        .expect("capability entry");
    assert!(
        !capability.refusal_transition_counted,
        "valid mandate restores Capable"
    );
    assert_eq!(capability.first_seen_ms, first_seen, "clock still retained");
    assert_eq!(
        capability.refusals, 2,
        "valid mandates do not reset refusals"
    );

    let joiner4 = AgentKeypair::generate()?;
    let joiner4_hex = hex::encode(joiner4.agent_id().as_bytes());
    let cert4 = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner4.public_key().as_bytes(),
        None,
    )?;
    let pre4 = seat_write(
        &live_record(state.as_ref(), &group_id).await,
        &joiner4_hex,
        &actor_hex,
        &cert4,
    );
    let terminal4 = terminal_commit_for(&pre4, state.agent.identity().agent_keypair(), 3_500);
    assert!(
        !apply_event(
            &state,
            member_added_event(
                &group_id,
                terminal4.revision,
                &actor_hex,
                &joiner4_hex,
                &cert4,
                terminal4,
                None
            ),
        )
        .await
        .accepted
    );
    let row = diag_row(state.as_ref(), &group_id).await;
    assert_eq!(row.counters.owner_mandate_missing, 3);
    assert_eq!(
        row.counters.mandate_capability_refusing_transitions, 2,
        "refusal after a restored Capable is a NEW transition"
    );
    Ok(())
}

/// WHY (r3 item 2): the join attestation and the quarantine-clear
/// attestation sign the SAME field shape over the SAME head, so domain
/// separation is the ONLY thing that keeps a join attestation (owner
/// blesses a joiner's seat) from clearing a quarantine (owner blesses
/// this node's local containment state). Sign the identical fields under
/// the join domain and the clear verification MUST fail — a refactor
/// back to one shared `canonical_bytes` fails here.
#[test]
fn quarantine_clear_domain_is_separate_from_join_attestation() {
    let owner = UserKeypair::from_seed(&[0x3E; 32]).expect("owner key");
    let owner_id = owner.user_id();
    let stable_id = "7f".repeat(32);
    let local_hex = "1a".repeat(32);
    // A join-domain attestation over the exact fields the clear path
    // checks (honest owner signature, correct head, correct agent).
    let join_domain =
        HeadAttestation::sign(&stable_id, 12, "head-state-hash-r3", &local_hex, &owner)
            .expect("sign under the join domain");
    assert!(
        !join_domain.verify_quarantine_clear(
            owner.public_key(),
            &owner_id,
            &stable_id,
            12,
            "head-state-hash-r3",
            &local_hex,
        ),
        "a join-domain attestation must never clear a quarantine"
    );
    // Control: the same fields under the clear domain verify.
    let clear_domain = HeadAttestation::sign_quarantine_clear(
        &stable_id,
        12,
        "head-state-hash-r3",
        &local_hex,
        &owner,
    )
    .expect("sign under the clear domain");
    assert!(
        clear_domain.verify_quarantine_clear(
            owner.public_key(),
            &owner_id,
            &stable_id,
            12,
            "head-state-hash-r3",
            &local_hex,
        ),
        "the clear-domain attestation over identical fields verifies"
    );
}

/// WHY (ADR-0064 slice 4, Decision §2/§3): `anchors_commit` is the
/// owner-anchor predicate for a CONFLICTING commit (one that failed to
/// apply, so there is no candidate roster to re-derive) — it must bind
/// EVERY header field the mandate signs to the commit's own claims and
/// verify the owner signature, while a full roster re-derivation is
/// deliberately out of scope (that runs on real apply). Perturbing any
/// bound field, swapping the authority, or signing under the wrong key
/// must each break the anchor independently of the commit signature.
#[tokio::test]
async fn anchors_commit_binds_the_full_header_under_the_owner_key() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "9a".repeat(32);
    let base = sealed_group(&state, &group_id, owner_certified_policy(&owner_kp)).await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let joiner_kp = AgentKeypair::generate()?;
    let joiner_hex = hex::encode(joiner_kp.agent_id().as_bytes());
    let cert = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner_kp.public_key().as_bytes(),
        None,
    )?;
    let candidate = seat_write(&base, &joiner_hex, &authority_hex, &cert);
    let terminal = terminal_commit_for(&candidate, state.agent.identity().agent_keypair(), 9_000);
    let mandate = mint_mandate_like_authority(
        &candidate,
        None,
        0,
        &joiner_hex,
        &authority_hex,
        "invite-secret",
        &cert,
        &owner_kp,
        9_000,
    );

    // Control: the honest mandate anchors its own terminal.
    assert!(
        mandate.anchors_commit(
            owner_kp.public_key(),
            &owner_kp.user_id(),
            base.stable_group_id(),
            &terminal
        ),
        "an honestly minted mandate anchors the terminal it was minted over"
    );

    // Each header-bound field perturbed (still honestly SIGNED under a
    // re-mint) must break the anchor against the unchanged terminal.
    let wrong_root = {
        let mut perturbed = candidate.clone();
        perturbed.remove_member(&authority_hex, None);
        mint_mandate_like_authority(
            &perturbed,
            None,
            0,
            &joiner_hex,
            &authority_hex,
            "invite-secret",
            &cert,
            &owner_kp,
            9_001,
        )
    };
    assert!(!wrong_root.anchors_commit(
        owner_kp.public_key(),
        &owner_kp.user_id(),
        base.stable_group_id(),
        &terminal
    ));
    let wrong_parent = mint_mandate_like_authority(
        &candidate,
        None,
        0,
        &joiner_hex,
        &authority_hex,
        "invite-secret",
        &cert,
        &owner_kp,
        9_002,
    );
    let mut shifted = wrong_parent.clone();
    shifted.parent_state_hash = "00".repeat(32);
    assert!(!shifted.anchors_commit(
        owner_kp.public_key(),
        &owner_kp.user_id(),
        base.stable_group_id(),
        &terminal
    ));
    let mut wrong_authority = mandate.clone();
    wrong_authority.authority_agent_id = joiner_hex.clone();
    assert!(!wrong_authority.anchors_commit(
        owner_kp.public_key(),
        &owner_kp.user_id(),
        base.stable_group_id(),
        &terminal
    ));
    let mut wrong_group = mandate.clone();
    wrong_group.stable_group_id = "9b".repeat(32);
    assert!(!wrong_group.anchors_commit(
        owner_kp.public_key(),
        &owner_kp.user_id(),
        base.stable_group_id(),
        &terminal
    ));

    // A DIFFERENT owner's key never anchors (the policy-owner pin).
    let stranger_owner = UserKeypair::from_seed(&[0x5Au8; 32])?;
    assert!(!mandate.anchors_commit(
        stranger_owner.public_key(),
        &stranger_owner.user_id(),
        base.stable_group_id(),
        &terminal
    ));
    Ok(())
}
