//! ADR 0038 OwnerCertified admission tests.
//!
//! Covers the four ADR validation gates: an uncertified joiner holding a
//! VALID invite is rejected at accept and pruned at seal; a revoked cert
//! fails re-verification at the next seal and triggers eviction + rekey; a
//! certified agent joins; legacy byte-compat lives in `groups::policy`
//! tests. Also pins the joiner-side fail-fast and the library's refusal to
//! seal an OwnerCertified group without certificate evidence.

use super::*;
use crate::groups::owner_cert::OwnerCertEvidence;
use crate::groups::policy::{GroupAdmission, GroupPolicy};
use crate::groups::{GroupConfidentiality, GroupDiscoverability};
use crate::identity::{AgentKeypair, UserKeypair};
/// Authority-side fixture: the local daemon IS the owner's primary agent —
/// it holds a user key and a builder-issued certificate (the ADR-0038 Home
/// shape). Returns the owner keypair so tests can certify remote joiners.
async fn owner_authority_state() -> Result<(Arc<AppState>, tempfile::TempDir, UserKeypair)> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    // Deterministic seed: `with_user_key` consumes the keypair, and the
    // test needs the SAME owner identity to certify remote joiners —
    // `UserKeypair::from_seed` is byte-deterministic (issue #95).
    let owner_seed = [0x38u8; 32];
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

/// Home-shaped policy: Hidden + OwnerCertified(owner) + MlsEncrypted +
/// members-only read/write (ADR-0038 decision).
fn owner_certified_policy(owner: &UserKeypair) -> GroupPolicy {
    GroupPolicy {
        discoverability: GroupDiscoverability::Hidden,
        admission: GroupAdmission::OwnerCertified(owner.user_id()),
        confidentiality: GroupConfidentiality::MlsEncrypted,
        read_access: x0x::groups::GroupReadAccess::MembersOnly,
        write_access: x0x::groups::GroupWriteAccess::MembersOnly,
    }
}

/// Seed the identity-discovery cache the way a verified V3 announce
/// blob-fetch does, so the authority can resolve the joiner's cert with
/// no side channel (PR #419 resolution path).
async fn announce_cert_for(state: &AppState, cert: x0x::identity::AgentCertificate) {
    let agent_id = cert.agent_id().expect("cert agent id");
    let cache = state.agent.identity_discovery_cache();
    cache.write().await.insert(
        agent_id,
        x0x::DiscoveredAgent {
            agent_id,
            machine_id: x0x::identity::MachineId([0u8; 32]),
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
            agent_certificate: Some(cert),
            agent_public_key: Vec::new(),
        },
    );
}

async fn insert_owner_group(
    state: &AppState,
    group_id: &str,
    policy: GroupPolicy,
    invite_secret: &str,
) {
    let inviter = state.agent.agent_id();
    let mut info = x0x::groups::GroupInfo::with_policy(
        "home".to_string(),
        String::new(),
        inviter,
        group_id.to_string(),
        policy,
    );
    info.record_issued_invite(
        invite_secret.to_string(),
        now_millis_u64() / 1_000,
        0,
        x0x::groups::GroupRole::Member,
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
}

#[tokio::test]
async fn uncertified_joiner_with_valid_invite_rejected_then_admitted_once_certified() -> Result<()>
{
    // WHY (ADR-0038 validation gate 1): an uncertified agent holding a
    // genuine one-time invite must NOT be admitted — this is the
    // "no other human can ever join" guarantee, and it must hold even
    // though the inviter (local admin) is fully authorized. Proving the
    // SAME invite works once the cert resolves shows the rejection is
    // the certificate check, not some other gate.
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "71".repeat(32);
    let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
    let invite_secret = "adr0038-valid-invite-secret".to_string();
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        &invite_secret,
    )
    .await;

    let joiner = AgentKeypair::generate()?;
    let (joiner_id, joiner_hex, _, event) = signed_member_joined_event_for_test(
        &joiner,
        &group_id,
        &inviter_hex,
        &invite_secret,
        x0x::groups::GroupRole::Member,
    )?;

    // 1. No certificate anywhere -> rejected at invite-accept.
    let result =
        apply_named_group_metadata_event_inner(&state, event.clone(), joiner_id, true, true, None)
            .await;
    assert!(!result.should_exit);
    {
        let groups = state.named_groups.read().await;
        let live = groups.get(&group_id).expect("group retained");
        assert!(
            !live.has_active_member(&joiner_hex),
            "uncertified joiner must not be admitted at invite-accept"
        );
    }

    // 2. The one-time invite was NOT consumed by the rejection: once the
    //    joiner's cert resolves over the announce-blob path, the SAME
    //    invite admits it (certified agent joins — validation gate 3).
    let cert = x0x::identity::AgentCertificate::issue(&owner_kp, &joiner)?;
    announce_cert_for(state.as_ref(), cert).await;
    let result =
        apply_named_group_metadata_event_inner(&state, event, joiner_id, true, true, None).await;
    assert!(!result.should_exit);
    {
        let groups = state.named_groups.read().await;
        let live = groups.get(&group_id).expect("group retained");
        assert!(
            live.has_active_member(&joiner_hex),
            "certified joiner must be admitted once its cert resolves"
        );
    }
    Ok(())
}

#[tokio::test]
async fn revoked_cert_member_evicted_with_rekey_at_seal() -> Result<()> {
    // WHY (ADR-0038 validation gate 2): a member whose cert is revoked
    // (ADR-0018) fails re-verification at the next state-commit seal
    // and is evicted WITH a rekey — losing both the roster seat AND the
    // group secret in one commit. The seal endpoint is the ADR's
    // explicit re-verification point.
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "72".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused-invite",
    )
    .await;

    // A certified member joins the roster.
    let member = AgentKeypair::generate()?;
    let member_hex = hex::encode(member.agent_id().as_bytes());
    let cert = x0x::identity::AgentCertificate::issue(&owner_kp, &member)?;
    announce_cert_for(state.as_ref(), cert.clone()).await;
    {
        let mut groups = state.named_groups.write().await;
        let live = groups.get_mut(&group_id).expect("group");
        live.add_member(
            member_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(state.agent.agent_id().as_bytes())),
            None,
        );
        live.shared_secret = Some(vec![7u8; 32]);
    }

    // The member self-revokes (ADR-0018: self-revocation is always
    // authority-verifiable from the record alone) and the set sees it.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(member.agent_id()),
        member.public_key(),
        member.secret_key(),
        now,
        Some("adr0038 eviction test".to_string()),
    )?;
    state
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(record, Some(&cert))?;

    let epoch_before = {
        let groups = state.named_groups.read().await;
        groups.get(&group_id).expect("group").secret_epoch
    };
    let secret_before = {
        let groups = state.named_groups.read().await;
        groups.get(&group_id).expect("group").shared_secret.clone()
    };

    // Seal: re-verification runs, the revoked member is evicted and the
    // GSS secret rotates (rekey via the existing rotation machinery).
    let response = seal_group_state(State(Arc::clone(&state)), Path(group_id.clone()))
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "seal must succeed: {body}");
    let evicted = body["evicted"]
        .as_array()
        .expect("evicted list in response")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        evicted,
        vec![member_hex.clone()],
        "the revoked-cert member must be the one evicted: {body}"
    );

    {
        let groups = state.named_groups.read().await;
        let live = groups.get(&group_id).expect("group");
        assert!(
            !live.has_active_member(&member_hex),
            "revoked member must be roster-removed at seal"
        );
        assert!(
            live.secret_epoch > epoch_before,
            "eviction must rekey: secret_epoch {} must advance past {epoch_before}",
            live.secret_epoch
        );
        let secret_after = live.shared_secret.clone();
        assert_ne!(
            secret_after, secret_before,
            "eviction must rotate the shared secret"
        );
    }
    Ok(())
}

#[tokio::test]
async fn uncertified_roster_member_is_pruned_at_seal() -> Result<()> {
    // WHY (ADR-0038 validation gate 1b): even when an uncertified agent
    // is ALREADY on the roster (legacy roster, pre-upgrade join, or a
    // node that missed the accept-time check), the next seal must prune
    // it — a later-stolen invite cannot resurrect membership.
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "73".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    let stranger_hex = "8b".repeat(32);
    {
        let mut groups = state.named_groups.write().await;
        let live = groups.get_mut(&group_id).expect("group");
        live.add_member(
            stranger_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
    }

    let response = seal_group_state(State(Arc::clone(&state)), Path(group_id.clone()))
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "seal must succeed: {body}");
    assert_eq!(
        body["evicted"],
        serde_json::json!([stranger_hex]),
        "uncertified roster member must be pruned at seal: {body}"
    );
    let groups = state.named_groups.read().await;
    let live = groups.get(&group_id).expect("group");
    assert!(
        !live.has_active_member(&stranger_hex),
        "uncertified member must not survive the seal"
    );
    Ok(())
}

#[tokio::test]
async fn owner_primary_agent_survives_the_seal() -> Result<()> {
    // WHY: the owner's own primary agent holds a builder-issued cert
    // chaining to the owner; the seal must NOT evict it (otherwise Home
    // locks itself out on every seal — the ADR's stated negative
    // consequence must not fire for a healthy install).
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "74".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    let owner_hex = hex::encode(state.agent.agent_id().as_bytes());
    let response = seal_group_state(State(Arc::clone(&state)), Path(group_id.clone()))
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "seal must succeed: {body}");
    assert_eq!(
        body["evicted"],
        serde_json::json!([]),
        "owner's certified primary agent must not be evicted: {body}"
    );
    let groups = state.named_groups.read().await;
    let live = groups.get(&group_id).expect("group");
    assert!(live.has_active_member(&owner_hex));
    Ok(())
}

#[tokio::test]
async fn joiner_without_certificate_fails_fast_on_owner_certified_invite() -> Result<()> {
    // WHY: the joiner-side REST check tells an uncertified agent WHY it
    // cannot use the invite (403) instead of creating a local stub that
    // the authority silently rejects — the authority-side gate in the
    // test above remains the enforcement; this is fail-fast UX.
    let (state, _dir) = secure_endpoint_test_state().await?;
    let owner_kp = UserKeypair::generate()?;
    let mut invite = x0x::groups::invite::SignedInvite::new(
        "75".repeat(32),
        "home".to_string(),
        &state.agent.agent_id(),
        3_600,
    );
    invite.policy = Some(owner_certified_policy(&owner_kp));
    let link = invite.to_link();

    let req = serde_json::from_value(serde_json::json!({ "invite": link }))?;
    let response = join_group_via_invite(State(Arc::clone(&state)), Json(req))
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "uncertified joiner must fail fast: {body}"
    );
    assert!(
        body["error"].as_str().is_some_and(|e| e.contains("owner")),
        "error must point at owner certification: {body}"
    );
    Ok(())
}

#[test]
fn blind_seal_of_owner_certified_group_is_refused() {
    // WHY: `seal_commit` (the no-evidence path) must REFUSE an
    // OwnerCertified group so a forgotten enforcement point fails loudly
    // instead of certifying an unverified roster.
    let owner = UserKeypair::generate().expect("owner");
    let creator = AgentKeypair::generate().expect("creator");
    let mut info = x0x::groups::GroupInfo::with_policy(
        "home".into(),
        String::new(),
        creator.agent_id(),
        "aa".repeat(16),
        owner_certified_policy(&owner),
    );
    let err = info
        .seal_commit(&creator, 1_000)
        .expect_err("blind seal must refuse");
    assert!(
        matches!(
            err,
            x0x::groups::state_commit::ApplyError::OwnerCertifiedEvidenceRequired { .. }
        ),
        "wrong error: {err}"
    );

    // Empty evidence prunes the uncertified sole admin, and the
    // last-admin invariant then vetoes the commit — the documented
    // fail-closed "Home locks itself out" consequence (ADR-0038).
    let err = info
        .seal_commit_with_owner_certs(&creator, 1_000, &OwnerCertEvidence::new(1_000))
        .expect_err("empty evidence must fail closed");
    assert!(
        err.to_string().contains("zero active admins"),
        "expected last-admin veto, got: {err}"
    );

    // With the creator's own owner-signed cert in evidence the same
    // seal succeeds and evicts nobody.
    let cert = x0x::identity::AgentCertificate::issue(&owner, &creator).expect("cert");
    let creator_hex = hex::encode(creator.agent_id().as_bytes());
    let mut evidence = OwnerCertEvidence::new(1_000);
    evidence.insert_cert(creator_hex, cert);
    let (commit, evicted) = info
        .seal_commit_with_owner_certs(&creator, 1_000, &evidence)
        .expect("seal with evidence");
    assert!(evicted.is_empty(), "certified creator must not be evicted");
    assert_eq!(commit.revision, 1);
}
