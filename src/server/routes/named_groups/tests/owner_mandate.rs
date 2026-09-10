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

    let minted = mint_owner_mandate_for_member_joined(
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
        mint_owner_mandate_for_member_joined(
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
        mint_owner_mandate_for_member_joined(
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
        x0x::groups::MandateCapabilityState { first_seen_ms: 7 },
    );
    let round: x0x::groups::GroupInfo =
        serde_json::from_str(&serde_json::to_string(&with_map).expect("json"))
            .expect("record with map round-trips");
    assert_eq!(round.mandate_capability, with_map.mandate_capability);
}
