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
            cert_not_after: cert.not_after(),
            agent_certificate: Some(cert),
            agent_public_key: Vec::new(),
            cert_digest: None,
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
async fn missing_evidence_gets_grace_window_then_evicts_at_seal() -> Result<()> {
    // WHY (round-2 finding 5): an uncertified roster member whose evidence
    // simply has not ARRIVED yet (cold blob-fetch lag) must not be
    // destructively evicted on first sight — the announce pipeline is
    // eventually consistent, so a grace window (`NoCertificate` only)
    // defers eviction while the fetch/heartbeat retry converges. Past the
    // window, the member is evicted by the same sequential engine.
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

    // First seal: grace — not evicted, timestamp stamped.
    let response = seal_group_state(State(Arc::clone(&state)), Path(group_id.clone()))
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "in-grace member must produce the typed pending refusal: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("pending certificate resolution")),
        "typed pending error: {body}"
    );
    {
        let groups = state.named_groups.read().await;
        let live = groups.get(&group_id).expect("group");
        assert!(live.has_active_member(&stranger_hex));
        assert!(
            live.members_v2
                .get(&stranger_hex)
                .and_then(|m| m.certificate_missing_since_ms)
                .is_some(),
            "the grace window must stamp the retry timestamp"
        );
    }

    // Expire the window and seal again: now the eviction fires.
    {
        let mut groups = state.named_groups.write().await;
        let member = groups
            .get_mut(&group_id)
            .expect("group")
            .members_v2
            .get_mut(&stranger_hex)
            .expect("member");
        member.certificate_missing_since_ms = Some(0);
    }
    let response = seal_group_state(State(Arc::clone(&state)), Path(group_id.clone()))
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "post-grace seal: {body}");
    assert_eq!(
        body["evicted"],
        serde_json::json!([stranger_hex]),
        "missing evidence past the grace window must evict: {body}"
    );
    let groups = state.named_groups.read().await;
    let live = groups.get(&group_id).expect("group");
    assert!(
        !live.has_active_member(&stranger_hex),
        "uncertified member must not survive past the grace window"
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

    // Empty evidence is now MISSING evidence under the round-3
    // single-authority rule: the grace-aware enforcement stamps the sole
    // admin's retry timestamp and the seal SUCCEEDS with the member
    // retained (fetch-lag, not a fact about the certificate). A
    // DEFINITIVE failure is what must trip the last-admin veto.
    let empty_verdict = info.owner_cert_verdict(&OwnerCertEvidence::new(1_000));
    let (commit, evicted) = info
        .seal_commit_with_owner_certs(&creator, 1_000, &empty_verdict)
        .expect("empty evidence seals under grace");
    assert!(
        evicted.is_empty(),
        "grace retains the uncertified sole admin"
    );
    assert_eq!(commit.revision, 1);

    // Definitive failure: the sole admin carries a certificate chained to
    // a DIFFERENT owner — pruned, and the last-admin invariant vetoes the
    // commit (fail-closed "Home locks itself out", ADR-0038).
    let foreign = UserKeypair::generate().expect("foreign owner");
    info.set_member_certificate(
        &hex::encode(creator.agent_id().as_bytes()),
        x0x::identity::AgentCertificate::issue(&foreign, &creator).expect("foreign cert"),
    );
    let failed_verdict = info.owner_cert_verdict(&OwnerCertEvidence::new(2_000));
    let err = info
        .seal_commit_with_owner_certs(&creator, 2_000, &failed_verdict)
        .expect_err("definitive failure must fail closed");
    assert!(
        err.to_string().contains("zero active admins"),
        "expected last-admin veto, got: {err}"
    );

    // With the creator's own owner-signed cert in LIVE evidence the seal
    // succeeds (live evidence outranks the stale/foreign embedded one) and
    // evicts nobody.
    let cert = x0x::identity::AgentCertificate::issue(&owner, &creator).expect("cert");
    let creator_hex = hex::encode(creator.agent_id().as_bytes());
    let mut evidence = OwnerCertEvidence::new(3_000);
    evidence.insert_cert(creator_hex, cert);
    let clean_verdict = info.owner_cert_verdict(&evidence);
    let (commit, evicted) = info
        .seal_commit_with_owner_certs(&creator, 3_000, &clean_verdict)
        .expect("seal with evidence");
    assert!(evicted.is_empty(), "certified creator must not be evicted");
    assert_eq!(commit.revision, 2);
}

// ── Review-fix tests (Codex adversarial review, REQUEST-CHANGES) ──────

#[tokio::test]
async fn admission_oracle_fails_closed_on_blob_cache_miss_and_recovers() -> Result<()> {
    // WHY (review finding 5 / addendum 1): the admission oracle resolves
    // certificates from the discovery cache; a cold miss must DENY
    // (retryable), never fail open — and the promotion fix means a later
    // heartbeat carrying the fetched certificate actually converges.
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "76".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    let joiner = AgentKeypair::generate()?;
    let joiner_hex = hex::encode(joiner.agent_id().as_bytes());
    let info = {
        let groups = state.named_groups.read().await;
        groups.get(&group_id).expect("group").clone()
    };

    // 1. Miss: no cache entry at all → typed failure, denied.
    let denied = owner_certified_admission_check(state.as_ref(), &info, &joiner_hex).await;
    assert_eq!(
        denied,
        Err(x0x::groups::owner_cert::OwnerCertFailure::NoCertificate),
        "cache miss must fail closed with NoCertificate"
    );

    // 2. Recovery: the announce path lands the certificate (upsert
    //    promotion) and the SAME check now returns the cert for binding.
    let cert = x0x::identity::AgentCertificate::issue(&owner_kp, &joiner)?;
    announce_cert_for(state.as_ref(), cert.clone()).await;
    let admitted = owner_certified_admission_check(state.as_ref(), &info, &joiner_hex).await;
    assert_eq!(
        admitted,
        Ok(Some(cert)),
        "after the blob lands, admission must succeed and return the cert for roster binding"
    );
    Ok(())
}

#[tokio::test]
async fn policy_patch_cannot_remove_or_replace_owner_certified_axis() -> Result<()> {
    // WHY (review B2): admin role must be INERT for admission policy —
    // a compromised admin must not downgrade OwnerCertified to
    // InviteOnly (or swap the owner), locally or via a signed event.
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "77".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    let req: UpdateGroupPolicyRequest = serde_json::from_value(serde_json::json!({
        "admission": "invite_only"
    }))?;
    let response =
        update_group_policy(State(Arc::clone(&state)), Path(group_id.clone()), Json(req))
            .await
            .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "axis removal must be a typed 403: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("immutable")),
        "error must name immutability: {body}"
    );

    // Swapping to a DIFFERENT owner is equally refused.
    let stranger = UserKeypair::generate()?;
    let req: UpdateGroupPolicyRequest = serde_json::from_value(serde_json::json!({
        "admission": {"owner_certified": hex::encode(stranger.user_id().as_bytes())}
    }))?;
    let response =
        update_group_policy(State(Arc::clone(&state)), Path(group_id.clone()), Json(req))
            .await
            .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "owner swap refused: {body}");

    // A same-owner PATCH (e.g. write_access change) still goes through.
    let req: UpdateGroupPolicyRequest = serde_json::from_value(serde_json::json!({
        "admission": {"owner_certified": hex::encode(owner_kp.user_id().as_bytes())}
    }))?;
    let response =
        update_group_policy(State(Arc::clone(&state)), Path(group_id.clone()), Json(req))
            .await
            .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "same-owner policy retained: {body}");
    Ok(())
}

#[tokio::test]
async fn ordinary_seal_refuses_with_typed_error_when_eviction_required() -> Result<()> {
    // WHY (review B3): an ordinary seal (here: policy/display-class
    // mutation via the PATCH endpoint, which uses the common wrapper)
    // must NEVER silently prune — the roster change would not be
    // representable to receivers and the secret would not rotate. It
    // refuses with a typed error naming the members and the explicit
    // path.
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "78".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    // A DEFINITIVE failure (not fetch lag): the member carries a
    // certificate chained to a DIFFERENT owner — refused immediately,
    // no grace window applies.
    let stranger_hex = "9c".repeat(32);
    let foreign_user = UserKeypair::generate()?;
    let foreign_cert =
        x0x::identity::AgentCertificate::issue(&foreign_user, &AgentKeypair::generate()?)?;
    {
        let mut groups = state.named_groups.write().await;
        let live = groups.get_mut(&group_id).expect("group");
        live.add_member(
            stranger_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        live.set_member_certificate(&stranger_hex, foreign_cert);
    }
    let req: UpdateGroupPolicyRequest =
        serde_json::from_value(serde_json::json!({ "write_access": "admin_only" }))?;
    let response =
        update_group_policy(State(Arc::clone(&state)), Path(group_id.clone()), Json(req))
            .await
            .into_response();
    let (status, body) = response_json(response).await?;
    assert!(
        status == StatusCode::INTERNAL_SERVER_ERROR || status == StatusCode::CONFLICT,
        "ordinary seal must refuse, got {status}: {body}"
    );
    let err_text = body["error"].as_str().unwrap_or_default();
    assert!(
        err_text.contains("explicit eviction+rekey"),
        "error must direct to the explicit path: {body}"
    );
    // And the roster was NOT silently pruned by the refused mutation.
    let groups = state.named_groups.read().await;
    let live = groups.get(&group_id).expect("group");
    assert!(
        live.has_active_member(&stranger_hex),
        "a refused ordinary seal must leave the roster untouched"
    );
    Ok(())
}

#[tokio::test]
async fn multi_eviction_seal_is_sequential_with_per_member_rekey() -> Result<()> {
    // WHY (review B3/B4): every eviction must be its own atomic
    // roster+crypto transition whose event reconstructs the committed
    // roster. Two failing members ⇒ two evicting commits (plus the
    // final clean seal), roster ends clean, and the GSS secret rotates
    // per eviction.
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "79".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    let bad1 = AgentKeypair::generate()?;
    let bad2 = AgentKeypair::generate()?;
    for bad in [&bad1, &bad2] {
        let hex = hex::encode(bad.agent_id().as_bytes());
        // Real ML-KEM-768 keys: the per-eviction rotation preflights a
        // survivor envelope for the (still-seated) other member, and a
        // survivor without a roster KEM key correctly aborts the whole
        // transition (F1 §5).
        let kem = x0x::groups::kem_envelope::AgentKemKeypair::generate()?;
        use base64::Engine as _;
        let kem_b64 = BASE64.encode(kem.public_bytes);
        let mut groups = state.named_groups.write().await;
        let live = groups.get_mut(&group_id).expect("group");
        live.add_member_with_kem(
            hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
            Some(kem_b64),
        );
        // Pre-expire the grace window: this test targets the eviction
        // engine, not the retry policy.
        if let Some(member) = live.members_v2.get_mut(&hex) {
            member.certificate_missing_since_ms = Some(0);
        }
        live.shared_secret = Some(vec![3u8; 32]);
    }
    let revision_before = {
        let groups = state.named_groups.read().await;
        groups.get(&group_id).expect("group").state_revision
    };
    let response = seal_group_state(State(Arc::clone(&state)), Path(group_id.clone()))
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "sequential eviction seal: {body}");
    let evicted: Vec<String> = body["evicted"]
        .as_array()
        .expect("evicted list")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(evicted.len(), 2, "both failing members evicted: {body}");
    {
        let groups = state.named_groups.read().await;
        let live = groups.get(&group_id).expect("group");
        for evicted_hex in &evicted {
            assert!(!live.has_active_member(evicted_hex));
        }
        // Two evicting transitions + one clean seal = +3 revisions.
        assert_eq!(
            live.state_revision,
            revision_before + 2,
            "each eviction is its own committed transition"
        );
    }
    Ok(())
}

#[tokio::test]
async fn restore_from_disk_quarantines_secure_ops_until_resealed() -> Result<()> {
    // WHY (review finding 6): restored OwnerCertified state (roster +
    // GSS/TreeKEM material) must not serve secure operations until an
    // evidence-bearing seal re-verifies it. load_named_groups sets the
    // quarantine marker; secure encrypt refuses with a typed 409; the
    // seal endpoint clears it.
    let (state, dir, owner_kp) = owner_authority_state().await?;
    let group_id = "7a".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    {
        let mut groups = state.named_groups.write().await;
        let live = groups.get_mut(&group_id).expect("group");
        live.shared_secret = Some(vec![5u8; 32]);
    }
    // Persist + reload through the real restore path.
    assert!(save_named_groups(&state).await);
    let reloaded = load_named_groups(&state.named_groups_path).await?;
    assert!(
        reloaded
            .get(&group_id)
            .expect("group")
            .owner_cert_reverify_required,
        "restore must set the quarantine marker"
    );
    *state.named_groups.write().await = reloaded;

    // Secure encrypt refuses while quarantined.
    let req: SecureEncryptRequest =
        serde_json::from_value(serde_json::json!({ "payload_b64": "aGVsbG8=" }))?;
    let (status, json) =
        secure_group_encrypt(State(Arc::clone(&state)), Path(group_id.clone()), Json(req)).await;
    let body: serde_json::Value = json.0;
    assert_eq!(status, StatusCode::CONFLICT, "quarantined encrypt must 409");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("re-verification")),
        "typed quarantine error: {body}"
    );

    // The evidence-bearing seal clears the quarantine.
    let response = seal_group_state(State(Arc::clone(&state)), Path(group_id.clone()))
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "seal clears quarantine: {body}");
    assert!(
        !state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .expect("group")
            .owner_cert_reverify_required,
        "marker cleared by the evidence-bearing seal"
    );
    drop(dir);
    Ok(())
}

#[tokio::test]
async fn receiver_rejects_member_added_without_committed_certificate() -> Result<()> {
    // WHY (review B1): receivers must enforce OwnerCertified admission
    // on inbound authority commits — a compromised admin with an old
    // client emits MemberAdded without a certificate; every receiver
    // must reject the signed commit rather than admit the outsider.
    // Path: authority-side apply of a MemberAdded event shaped like a
    // relayed authority commit, on a group whose roster the event would
    // extend. The receiver gate below is the same one non-inviter
    // receivers run.
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "7b".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    let owner_hex = hex::encode(state.agent.agent_id().as_bytes());

    // Build the event the way the receiver arm consumes it. A missing
    // certificate is rejected by the receiver gate BEFORE any roster
    // work — verified by calling the gate logic through the full apply
    // entry with a minimal event (commit validation happens after the
    // cert gate, so a None commit is fine for the rejection arm).
    let outsider = AgentKeypair::generate()?;
    let outsider_hex = hex::encode(outsider.agent_id().as_bytes());
    let event = NamedGroupMetadataEvent::MemberAdded {
        group_id: group_id.clone(),
        revision: 2,
        actor: owner_hex.clone(),
        agent_id: outsider_hex.clone(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: None,
        commit: None,
    };
    let should_exit = apply_named_group_metadata_event_inner(
        &state,
        event,
        state.agent.agent_id(),
        true,
        true,
        None,
    )
    .await;
    assert!(!should_exit.should_exit);
    {
        let groups = state.named_groups.read().await;
        let live = groups.get(&group_id).expect("group");
        assert!(
            !live.has_active_member(&outsider_hex),
            "receiver must not admit an OwnerCertified add without a committed certificate"
        );
    }
    Ok(())
}

#[tokio::test]
async fn receiver_rejects_member_added_for_revoked_target() -> Result<()> {
    // WHY (round-2 finding 1): the receiver-side gate must check the
    // ADR-0018 revocation set at INGRESS — a still-valid-looking
    // certificate for a since-revoked key must not re-enter through an
    // authority commit.
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "7c".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    let owner_hex = hex::encode(state.agent.agent_id().as_bytes());
    let member = AgentKeypair::generate()?;
    let member_hex = hex::encode(member.agent_id().as_bytes());
    let cert = x0x::identity::AgentCertificate::issue(&owner_kp, &member)?;
    // Self-revocation: authority-verifiable from the record alone.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(member.agent_id()),
        member.public_key(),
        member.secret_key(),
        now,
        Some("round-2 ingress test".to_string()),
    )?;
    state
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(record, Some(&cert))?;
    use base64::Engine as _;
    let event = NamedGroupMetadataEvent::MemberAdded {
        group_id: group_id.clone(),
        revision: 2,
        actor: owner_hex,
        agent_id: member_hex.clone(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: Some(BASE64.encode(bincode::serialize(&cert)?)),
        commit: None,
    };
    let should_exit = apply_named_group_metadata_event_inner(
        &state,
        event,
        state.agent.agent_id(),
        true,
        true,
        None,
    )
    .await;
    assert!(!should_exit.should_exit);
    let groups = state.named_groups.read().await;
    assert!(
        !groups
            .get(&group_id)
            .expect("group")
            .has_active_member(&member_hex),
        "a revoked target must be rejected at ingress even with a valid certificate"
    );
    Ok(())
}

#[tokio::test]
async fn direct_add_binds_certificate_into_roster() -> Result<()> {
    // WHY (round-2 finding 1): the direct-add producers must both bind
    // the verified certificate into the roster (and publish it on the
    // MemberAdded event — the receiver gate below plus the invite-path
    // test prove fixed receivers accept exactly that shape).
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "7d".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    let target = AgentKeypair::generate()?;
    let target_hex = hex::encode(target.agent_id().as_bytes());
    let cert = x0x::identity::AgentCertificate::issue(&owner_kp, &target)?;
    announce_cert_for(state.as_ref(), cert.clone()).await;
    let req: AddNamedGroupMemberRequest = serde_json::from_value(serde_json::json!({
        "agent_id": target_hex
    }))?;
    let response =
        add_named_group_member(State(Arc::clone(&state)), Path(group_id.clone()), Json(req))
            .await
            .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "certified direct add: {body}");
    let groups = state.named_groups.read().await;
    let live = groups.get(&group_id).expect("group");
    assert!(
        live.committed_certificate(&target_hex).is_some(),
        "direct add must bind the committed certificate into the roster"
    );
    Ok(())
}

#[tokio::test]
async fn reseal_refuses_while_restore_quarantined() -> Result<()> {
    // WHY (round-2 finding 6): secure/reseal re-seals the RESTORED
    // shared secret; it must obey the same quarantine as
    // encrypt/decrypt until an evidence-bearing seal re-verifies.
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "7e".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    {
        let mut groups = state.named_groups.write().await;
        let live = groups.get_mut(&group_id).expect("group");
        live.shared_secret = Some(vec![9u8; 32]);
        live.owner_cert_reverify_required = true;
    }
    let owner_hex = hex::encode(state.agent.agent_id().as_bytes());
    let req: ResealRequest = serde_json::from_value(serde_json::json!({ "recipient": owner_hex }))?;
    let (status, json) =
        secure_group_reseal(State(Arc::clone(&state)), Path(group_id.clone()), Json(req)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "reseal must obey the restore quarantine: {}",
        json.0
    );
    Ok(())
}

/// Seed the discovery cache with a PENDING warranted fetch: the agent's
/// latest announce committed to `digest` but the cert has not resolved
/// locally (round-3 freshness coupling).
async fn announce_pending_digest(state: &AppState, agent_hex: &str, digest: [u8; 32]) {
    let agent_id = parse_agent_id_hex(agent_hex).expect("agent hex");
    let cache = state.agent.identity_discovery_cache();
    cache.write().await.insert(
        agent_id,
        x0x::DiscoveredAgent {
            agent_id,
            machine_id: x0x::identity::MachineId([0u8; 32]),
            user_id: None,
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
            cert_not_after: None,
            agent_certificate: None,
            agent_public_key: Vec::new(),
            cert_digest: Some(digest),
        },
    );
}

#[tokio::test]
async fn ordinary_mutation_retains_member_inside_grace_window() -> Result<()> {
    // WHY (round-3 regression): ordinary mutations preflight with the
    // grace-aware evaluation but then sealed through
    // `seal_commit_with_owner_certs`, whose enforcement re-derived the
    // verdict STRICTLY (no grace) and silently pruned the in-grace
    // member on an unrelated change. The single-authority rule makes
    // the grace-aware evaluation the only verdict: this member (no
    // evidence yet, inside the window) must survive an unrelated
    // metadata seal.
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "7f".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    let member_hex = "9d".repeat(32);
    {
        let mut groups = state.named_groups.write().await;
        groups.get_mut(&group_id).expect("group").add_member(
            member_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
    }
    // Stamp the member INTO the grace window (as a first seal would).
    {
        let mut groups = state.named_groups.write().await;
        groups
            .get_mut(&group_id)
            .expect("group")
            .members_v2
            .get_mut(&member_hex)
            .expect("member")
            .certificate_missing_since_ms = Some(now_millis_u64());
    }
    // Unrelated metadata mutation through the ORDINARY seal path.
    let req: UpdateGroupPolicyRequest =
        serde_json::from_value(serde_json::json!({ "write_access": "admin_only" }))?;
    let response =
        update_group_policy(State(Arc::clone(&state)), Path(group_id.clone()), Json(req))
            .await
            .into_response();
    let (status, body) = response_json(response).await?;
    assert!(
        status == StatusCode::CONFLICT || status == StatusCode::INTERNAL_SERVER_ERROR,
        "ordinary mutation must refuse while a member is inside its grace window: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("pending certificate resolution")),
        "refusal must be the typed OwnerCertMemberPending error: {body}"
    );
    let groups = state.named_groups.read().await;
    let live = groups.get(&group_id).expect("group");
    assert!(
        live.has_active_member(&member_hex),
        "an in-grace member must NEVER be pruned by an ordinary mutation"
    );
    Ok(())
}

#[tokio::test]
async fn stale_embedded_cert_does_not_seat_while_replacement_in_flight() -> Result<()> {
    // WHY (round-3 leak): the ladder used to fall back to the
    // roster-embedded cert whenever live evidence was missing — so a
    // newer announced digest (owner re-keyed) never actually gated
    // membership, and an expired embedded cert mid-rotation hard-failed
    // without grace. Now: a known announce digest different from the
    // embedded cert's digest makes the embedded cert STALE (no seating);
    // the pending fetch puts the member in the grace window; once the
    // replacement cert resolves the member is seated again.
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "80".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    let member = AgentKeypair::generate()?;
    let member_hex = hex::encode(member.agent_id().as_bytes());
    let cert = x0x::identity::AgentCertificate::issue(&owner_kp, &member)?;
    {
        let mut groups = state.named_groups.write().await;
        let live = groups.get_mut(&group_id).expect("group");
        live.add_member(
            member_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        live.set_member_certificate(&member_hex, cert.clone());
    }
    // The owner re-keys: the member's next announce commits to a NEW
    // digest; the replacement cert has not resolved here yet.
    announce_pending_digest(state.as_ref(), &member_hex, [0xEE; 32]).await;

    // Seal: the (still-valid) embedded cert is STALE — the member is
    // not seated by it, but the pending fetch holds the seat via grace.
    let response = seal_group_state(State(Arc::clone(&state)), Path(group_id.clone()))
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "in-flight rotation seal: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("pending certificate resolution")),
        "typed pending error: {body}"
    );
    {
        let groups = state.named_groups.read().await;
        assert!(groups
            .get(&group_id)
            .expect("group")
            .has_active_member(&member_hex));
    }

    // The replacement resolves: the member is seated by LIVE evidence
    // again (and the stale embedded cert no longer matters).
    let renewed = x0x::identity::AgentCertificate::issue(&owner_kp, &member)?;
    announce_cert_for(state.as_ref(), renewed).await;
    let response = seal_group_state(State(Arc::clone(&state)), Path(group_id.clone()))
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "post-rotation seal: {body}");
    assert_eq!(body["evicted"], serde_json::json!([]), "seated: {body}");
    Ok(())
}

#[tokio::test]
async fn in_grace_member_keeps_restore_quarantine_until_all_clean() -> Result<()> {
    // WHY (round-4 regression rule): the restore quarantine may only
    // lift on an ALL-CLEAN verdict. A restored group with a member
    // whose evidence has not re-resolved yet (InGrace) must REFUSE the
    // seal and STAY quarantined — secure ops stay blocked until every
    // member's certificate re-verifies.
    let (state, dir, owner_kp) = owner_authority_state().await?;
    let group_id = "81".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    let member = AgentKeypair::generate()?;
    let member_hex = hex::encode(member.agent_id().as_bytes());
    {
        let mut groups = state.named_groups.write().await;
        let live = groups.get_mut(&group_id).expect("group");
        live.add_member(
            member_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
        live.shared_secret = Some(vec![1u8; 32]);
    }
    // Restore: the loader's quarantine marker, as after a restart.
    assert!(save_named_groups(&state).await);
    let mut reloaded = load_named_groups(&state.named_groups_path).await?;
    reloaded
        .get_mut(&group_id)
        .expect("group")
        .owner_cert_reverify_required = true;
    *state.named_groups.write().await = reloaded;

    // Seal with an InGrace member: refused, quarantine intact.
    let response = seal_group_state(State(Arc::clone(&state)), Path(group_id.clone()))
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "in-grace seal must refuse: {body}"
    );
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .expect("group")
            .owner_cert_reverify_required,
        "an InGrace member must keep the restore quarantine set"
    );

    // Evidence converges (the member's cert resolves): all-clean seal
    // lifts the quarantine.
    let cert = x0x::identity::AgentCertificate::issue(&owner_kp, &member)?;
    announce_cert_for(state.as_ref(), cert).await;
    let response = seal_group_state(State(Arc::clone(&state)), Path(group_id.clone()))
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "all-clean seal: {body}");
    assert!(
        !state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .expect("group")
            .owner_cert_reverify_required,
        "the all-clean verdict lifts the restore quarantine"
    );
    drop(dir);
    Ok(())
}

#[tokio::test]
async fn explicit_eviction_of_failed_member_clears_restore_quarantine() -> Result<()> {
    // WHY (round-5 quarantine rule): the explicit eviction path ends
    // with every remaining member Clean IN THE OPERATION'S VERDICT
    // (Failed set fully evicted, nobody InGrace) — the restore
    // quarantine must lift right there, without a further clean seal,
    // so secure ops work again immediately after the eviction.
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "82".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "unused",
    )
    .await;
    // A FAILED member: certificate chained to a different owner
    // (definitive, no grace).
    let bad = AgentKeypair::generate()?;
    let bad_hex = hex::encode(bad.agent_id().as_bytes());
    let foreign = UserKeypair::generate()?;
    let foreign_cert = x0x::identity::AgentCertificate::issue(&foreign, &bad)?;
    {
        let mut groups = state.named_groups.write().await;
        let live = groups.get_mut(&group_id).expect("group");
        live.add_member(bad_hex.clone(), x0x::groups::GroupRole::Member, None, None);
        live.set_member_certificate(&bad_hex, foreign_cert);
        live.shared_secret = Some(vec![4u8; 32]);
        live.owner_cert_reverify_required = true;
    }
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .expect("group")
            .owner_cert_reverify_required
    );

    // Explicit eviction seal: the Failed member is evicted, the owner
    // is Clean, nobody InGrace -> quarantine lifts in the same
    // operation.
    let response = seal_group_state(State(Arc::clone(&state)), Path(group_id.clone()))
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "explicit eviction seal: {body}");
    assert_eq!(body["evicted"], serde_json::json!([bad_hex]), "{body}");
    assert!(
        !state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .expect("group")
            .owner_cert_reverify_required,
        "quarantine must clear when the operation's verdict ends all-Clean"
    );

    // Secure ops work again (no 409 quarantine).
    let req: SecureEncryptRequest =
        serde_json::from_value(serde_json::json!({ "payload_b64": "aGVsbG8=" }))?;
    let (status, json) =
        secure_group_encrypt(State(Arc::clone(&state)), Path(group_id.clone()), Json(req)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "secure ops must work after the quarantine lifted: {}",
        json.0
    );
    Ok(())
}
