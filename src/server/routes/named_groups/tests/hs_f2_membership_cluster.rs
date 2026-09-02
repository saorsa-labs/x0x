//! HS-F2 certified-membership cluster regression tests (#447, #457, #458).
//!
//! Each test encodes the LIVE failure observed in the 2026-08-30/31 Home
//! Suite campaigns (`omp-reports/hs-f1-repro-20260830.md`,
//! `omp-reports/x0x-hs-E1-lan-cli-skill-20260830-report.md`).

use super::*;

use crate::groups::policy::{GroupAdmission, GroupPolicy};
use crate::groups::{GroupConfidentiality, GroupDiscoverability};
use crate::identity::{AgentKeypair, UserKeypair};

/// Authority-side fixture (ADR-0038 Home shape): the local daemon IS the
/// owner's primary agent — user key + builder-issued certificate.
async fn owner_authority_state() -> Result<(Arc<AppState>, tempfile::TempDir, UserKeypair)> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    let owner_seed = [0xF2u8; 32];
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

/// Insert an OwnerCertified group with a recorded invite (the authority's
/// pre-join shape).
async fn insert_owner_group(
    state: &AppState,
    group_id: &str,
    policy: GroupPolicy,
    invite_secret: &str,
) -> x0x::groups::GroupInfo {
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
        .insert(group_id.to_string(), info.clone());
    info
}

/// Seed the discovery cache the way the FIRST V3 announce does: digest
/// known, certificate NOT attached — the #447 evidence-in-flight shape
/// (fetch completed after the announce was ingested).
async fn announce_digest_only(state: &AppState, cert: x0x::identity::AgentCertificate) -> [u8; 32] {
    let agent_id = cert.agent_id().expect("cert agent id");
    let digest = x0x::announce_v3::cert_digest(&cert.user_id().ok(), &Some(cert.clone()));
    let entry = x0x::DiscoveredAgent {
        agent_id,
        machine_id: x0x::identity::MachineId([0u8; 32]),
        user_id: None,
        self_name: None,
        addresses: Vec::new(),
        announced_at: 1,
        last_seen: 1,
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
    };
    state
        .agent
        .identity_discovery_cache()
        .write()
        .await
        .insert(agent_id, entry);
    digest
}

/// Insert a verify-before-cache blob (what `ensure_blob`'s async fetch
/// leaves behind on success).
async fn cache_verified_blob(state: &AppState, cert: x0x::identity::AgentCertificate) {
    let digest = x0x::announce_v3::cert_digest(&cert.user_id().ok(), &Some(cert.clone()));
    use x0x::announce_blob::CachedBlob;
    state
        .agent
        .announce_blob_cache
        .insert_verified(CachedBlob {
            digest,
            user_id: cert.user_id().ok(),
            agent_certificate: Some(cert),
            payload_version: 1,
            fetched_at_unix: 1,
        })
        .await;
}

fn issue_joiner_cert(
    owner_kp: &UserKeypair,
    joiner: &AgentKeypair,
) -> Result<x0x::identity::AgentCertificate> {
    Ok(x0x::identity::AgentCertificate::issue_for_public_key(
        owner_kp,
        joiner.public_key().as_bytes(),
        None,
    )?)
}

/// Seed the discovery cache with the joiner's FULLY RESOLVED certificate
/// (the shape after the blob merge / next-announce hit).
async fn announce_full_cert(state: &AppState, cert: x0x::identity::AgentCertificate) {
    let agent_id = cert.agent_id().expect("cert agent id");
    let entry = x0x::DiscoveredAgent {
        agent_id,
        machine_id: x0x::identity::MachineId([0u8; 32]),
        user_id: cert.user_id().ok(),
        self_name: None,
        addresses: Vec::new(),
        announced_at: 1,
        last_seen: 1,
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
    };
    state
        .agent
        .identity_discovery_cache()
        .write()
        .await
        .insert(agent_id, entry);
}

async fn diagnostics_row(
    state: &AppState,
    group_id: &str,
) -> crate::groups::diagnostics::GroupDiagnostic {
    let snapshot = state.groups_diagnostics.snapshot(
        &state.named_groups.read().await.clone(),
        &std::collections::HashSet::new(),
        &std::collections::HashSet::new(),
        &std::collections::HashMap::new(),
    );
    snapshot
        .groups
        .into_iter()
        .find(|g| g.group_id == group_id)
        .unwrap_or_else(|| panic!("diagnostics row for {group_id}"))
}

// ── #447 ──────────────────────────────────────────────────────────────────

/// #447: the authority rejects a certified joiner with
/// `no agent certificate resolved` for up to the 600 s heartbeat because
/// the fetched cert lands ONLY in the announce-blob cache — the discovery
/// entry stays digest-only until the joiner's next announce.
/// `owner_cert_evidence_for` must consult the blob cache for that shape.
#[tokio::test]
async fn issue447_evidence_resolves_cert_from_announce_blob_cache() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_hex = hex::encode(joiner.agent_id().as_bytes());
    let cert = issue_joiner_cert(&owner_kp, &joiner)?;

    announce_digest_only(state.as_ref(), cert.clone()).await;
    cache_verified_blob(state.as_ref(), cert).await;

    let evidence = owner_cert_evidence_for(state.as_ref(), &[&joiner_hex]).await;
    assert!(
        evidence.cert_for(&joiner_hex).is_some(),
        "#447: a fetched-and-cached announce blob must count as admission evidence"
    );
    let verdict = x0x::groups::owner_cert::verify_owner_certified_member(
        &owner_kp.user_id(),
        &joiner_hex,
        &evidence,
    );
    assert_eq!(verdict, Ok(()), "certified joiner must verify: {verdict:?}");
    Ok(())
}

/// #447 negative control: a blob whose certificate binds a DIFFERENT agent
/// than the discovery entry must NOT become evidence (the digest is
/// attacker-choosable — an agent can copy another agent's digest).
#[tokio::test]
async fn issue447_blob_cache_cert_bound_to_other_agent_is_not_evidence() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_hex = hex::encode(joiner.agent_id().as_bytes());
    let joiner_cert = issue_joiner_cert(&owner_kp, &joiner)?;
    let other = AgentKeypair::generate()?;
    let other_cert = issue_joiner_cert(&owner_kp, &other)?;

    announce_digest_only(state.as_ref(), joiner_cert).await;
    cache_verified_blob(state.as_ref(), other_cert).await;

    let evidence = owner_cert_evidence_for(state.as_ref(), &[&joiner_hex]).await;
    assert!(
        evidence.cert_for(&joiner_hex).is_none(),
        "#447: a copied digest must not import another agent's certificate"
    );
    Ok(())
}

/// #447: a MemberJoined rejected for `no agent certificate resolved` is
/// RETAINED on the authority and re-applied once evidence resolves — the
/// joiner's retry volley may have already stopped by then.
#[tokio::test]
async fn issue447_rejected_member_joined_is_retained_and_retried() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "47".repeat(32);
    let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
    let invite_secret = "issue447-invite-secret".to_string();
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

    // 1. No evidence anywhere → rejected AND retained.
    let result =
        apply_named_group_metadata_event_inner(&state, event, joiner_id, true, true, None).await;
    assert!(!result.accepted, "uncertified joiner must be rejected");
    let pending_key = join_result_key(&group_id, &joiner_hex);
    assert!(
        state
            .owner_cert_pending_joins
            .read()
            .await
            .contains_key(&pending_key),
        "#447: NoCertificate rejection must retain the signed MemberJoined for retry"
    );

    // 2. Evidence lands (blob fetch completed; entry still digest-only).
    let cert = issue_joiner_cert(&owner_kp, &joiner)?;
    announce_digest_only(state.as_ref(), cert.clone()).await;
    cache_verified_blob(state.as_ref(), cert).await;

    // 3. The retry sweep applies the retained event without a new volley.
    retry_pending_owner_cert_joins(&state, Some(&group_id)).await;
    {
        let groups = state.named_groups.read().await;
        let info = groups.get(&group_id).expect("group exists");
        assert!(
            info.has_active_member(&joiner_hex),
            "#447: retained MemberJoined must apply once evidence resolves"
        );
    }
    assert!(
        !state
            .owner_cert_pending_joins
            .read()
            .await
            .contains_key(&pending_key),
        "applied retention must be cleared"
    );
    let row = diagnostics_row(state.as_ref(), &group_id).await;
    assert_eq!(
        row.counters
            .member_joined_events_rejected_owner_cert_pending,
        1,
        "#447: the rejection must be visible in /diagnostics/groups"
    );
    Ok(())
}

/// #447/#458 typed joiner state: a joiner holding a stub + expected-inviter
/// pin but NO roster seat must read `pending_authority_commit`, not a bare
/// success. A seated member still reads `active`.
#[tokio::test]
async fn issue447_typed_pending_join_state() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "48".repeat(32);
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let info = insert_owner_group(
        state.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
        "issue447-typed-secret",
    )
    .await;

    // The joiner's stub: the invite's base roster — creator is the
    // AUTHORITY (a foreign agent), so the local joiner holds no seat.
    let inviter = x0x::identity::AgentId([0xAB; 32]);
    let mut stub = x0x::groups::GroupInfo::with_policy(
        "Home".to_string(),
        String::new(),
        inviter,
        group_id.clone(),
        owner_certified_policy(&owner_kp),
    );
    stub.record_issued_invite(
        "issue447-typed-secret".to_string(),
        now_millis_u64() / 1_000,
        0,
        x0x::groups::GroupRole::Member,
    );

    // Limbo: stub + expected-inviter pin, no roster seat for the joiner.
    record_expected_join_result_inviter(
        state.as_ref(),
        join_result_key(&group_id, &local_hex),
        local_hex.clone(),
    );
    assert_eq!(
        local_join_membership_state(state.as_ref(), &stub, &local_hex).await,
        "pending_authority_commit",
        "#447/#458: limbo must be typed"
    );

    // Seated: the founder reads active.
    let founder_hex = hex::encode(state.agent.agent_id().as_bytes());
    let mut seated = info.clone();
    seated.add_member(
        founder_hex.clone(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    assert_eq!(
        local_join_membership_state(state.as_ref(), &seated, &founder_hex).await,
        "active"
    );
    Ok(())
}

// ── #457 ──────────────────────────────────────────────────────────────────

/// #457 (E1 P1): `POST /home/rename` (PATCH /groups/:id) on a TreeKEM group
/// bumps the named-group revision; the persisted TreeKEM snapshot envelope
/// must be re-bound so a restart does NOT drop the secure plane with
/// "TreeKEM snapshot/named-group binding mismatch".
#[tokio::test]
async fn issue457_rename_keeps_treekem_snapshot_binding_across_restart() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0x57, 0x57).await?;
    let state = &fixture.state;
    let group_id = fixture.group_id.clone();
    assert!(
        state.treekem_groups.read().await.contains_key(&group_id),
        "fixture TreeKEM group must be live"
    );

    let response = update_named_group(
        State(Arc::clone(state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
        Json(UpdateGroupRequest {
            name: Some("Renamed Home".to_string()),
            description: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);

    // Simulate the daemon restart: rebuild the live map from disk.
    let named_groups = state.named_groups.read().await.clone();
    let restored =
        restore_treekem_groups(&named_groups, state.agent.as_ref(), &state.treekem_dir).await;
    assert!(
        restored.contains_key(&group_id),
        "#457: after rename + restart the TreeKEM group must restore (binding kept in step)"
    );
    Ok(())
}

/// #457: `state/seal` repairs an ALREADY-mismatched binding (the wedge a
/// pre-fix daemon restarts into) when the divergence is metadata-only.
#[tokio::test]
async fn issue457_state_seal_repairs_metadata_only_binding_mismatch() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0x58, 0x58).await?;
    let state = &fixture.state;
    let group_id = fixture.group_id.clone();

    // Seed the on-disk snapshot (bound at the CURRENT revision) while the
    // group is live, so a stale envelope exists to repair.
    let seeded = state
        .named_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .unwrap();
    let seeded = persist_named_group_info(state, &group_id, seeded).await;
    assert!(
        matches!(seeded, Ok(AtomicWriteOutcome::Durable)),
        "seed persist must be durable"
    );

    // Force the pre-fix wedge: advance the named state WITHOUT rebinding
    // the snapshot envelope (the stale on-disk envelope a pre-fix rename
    // leaves behind — the generic mutation bypasses the rebind hook), then
    // restart into the mismatch.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group_id).expect("group");
        info.roster_revision = info.roster_revision.saturating_add(1);
        info.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    }
    let forced =
        persist_named_groups_mutation(state, |groups| groups.get(&group_id).is_some()).await;
    assert!(
        matches!(forced, Ok(AtomicWriteOutcome::Durable)),
        "forced stale persist must be durable"
    );
    state.treekem_groups.write().await.remove(&group_id);

    // Repair surface 1 — STARTUP: restore_treekem_groups re-binds a
    // metadata-only mismatch instead of dropping the secure plane (the
    // pre-fix behavior this test replaces).
    {
        let named_groups = state.named_groups.read().await.clone();
        let restored =
            restore_treekem_groups(&named_groups, state.agent.as_ref(), &state.treekem_dir).await;
        assert!(
            restored.contains_key(&group_id),
            "#457: startup must repair a metadata-only binding mismatch"
        );
    }

    // Repair surface 2 — RUNTIME persist: with the live map entry lost but
    // no restart, any durable named-group persist re-binds and restores
    // (the same chokepoint POST /groups/:id/state/seal's OwnerCertified
    // arm and every metadata mutator flow through).
    state.treekem_groups.write().await.remove(&group_id);
    let updated = state
        .named_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .unwrap();
    let persist = persist_named_group_info(state, &group_id, updated).await;
    assert!(
        matches!(persist, Ok(AtomicWriteOutcome::Durable)),
        "#457 repair persist must be durable: {persist:?}"
    );
    assert!(
        state.treekem_groups.read().await.contains_key(&group_id),
        "#457: a durable named persist must repair a metadata-only binding mismatch"
    );
    Ok(())
}

/// #457: the previously-SILENT rejection (TreeKEM group missing at
/// MemberJoined apply) must now be counted in /diagnostics/groups.
#[tokio::test]
async fn issue457_treekem_unavailable_rejection_is_counted() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0x59, 0x59).await?;
    let state = &fixture.state;
    let group_id = fixture.group_id.clone();

    // A second joiner with the fixture's valid invite + a REAL TreeKEM
    // KeyPackage (a keypackage-less TreeKEM join is rejected earlier, by
    // design), but the TreeKEM group is GONE (the post-restart mismatch
    // shape).
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
    let invite_secret = "member-joined-invite-59".to_string();
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(joiner_id, &[0x59; 32])?;
    let treekem_key_package_b64 = BASE64.encode(prepared.key_package_bytes());
    let now_ms = now_millis_u64();
    let canonical = canonical_member_joined_bytes(
        &group_id,
        Some(&fixture.stable_group_id),
        &joiner_hex,
        &BASE64.encode(joiner.public_key().as_bytes()),
        x0x::groups::GroupRole::Member,
        None,
        &inviter_hex,
        &invite_secret,
        now_ms,
        Some(&treekem_key_package_b64),
    );
    let signature =
        ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(joiner.secret_key(), &canonical)
            .map_err(|e| anyhow::anyhow!("sign fixture: {e:?}"))?;
    let event = NamedGroupMetadataEvent::MemberJoined {
        group_id: group_id.clone(),
        stable_group_id: Some(fixture.stable_group_id.clone()),
        member_agent_id: joiner_hex,
        member_public_key_b64: BASE64.encode(joiner.public_key().as_bytes()),
        role: x0x::groups::GroupRole::Member,
        display_name: None,
        inviter_agent_id: inviter_hex,
        invite_secret,
        ts_ms: now_ms,
        treekem_key_package_b64: Some(treekem_key_package_b64),
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: None,
        recovery_authority_commit: None,
        signature_b64: BASE64.encode(signature.as_bytes()),
    };
    state.treekem_groups.write().await.remove(&group_id);

    let result = apply_named_group_metadata_event(state, event, joiner_id, true, None).await;
    assert!(!result.accepted, "missing TreeKEM group must reject");
    let row = diagnostics_row(state.as_ref(), &fixture.stable_group_id).await;
    assert_eq!(
        row.counters
            .member_joined_events_rejected_treekem_unavailable,
        1,
        "#457: the silent rejection must be counted"
    );
    Ok(())
}

// ── #458 ──────────────────────────────────────────────────────────────────

/// Shared #458 stage: authority prepares a NON-TreeKEM OwnerCertified Home,
/// seals a RENAME between the invite base and the join accept (the LAN P4
/// sequence — the joiner stub holds the revision-0 base while the
/// MemberAdded chains from revision 1), then accepts the certified join.
/// Returns (authority state, group id, base info the joiner stubs from,
/// the sealed MemberAdded event, joiner identity pieces).
struct Issue458Stage {
    authority: Arc<AppState>,
    /// The authority agent's keypair bytes — r3 chain-forgery tests
    /// re-sign tampered links with the REAL admin key to isolate the
    /// linkage/roster checks from the signer check.
    authority_key_bytes: (Vec<u8>, Vec<u8>),
    group_id: String,
    base_info: x0x::groups::GroupInfo,
    member_added: NamedGroupMetadataEvent,
    /// Joiner keypair BYTES — `AgentKeypair` is not `Clone`, so the joiner
    /// side rebuilds the same identity from serialized bytes.
    joiner_key_bytes: (Vec<u8>, Vec<u8>),
    joiner_hex: String,
}

async fn issue458_stage(group_byte: u8, rename_first: bool) -> Result<Issue458Stage> {
    issue458_stage_with_policy(group_byte, rename_first, owner_certified_policy_owner_f3).await
}

/// The r6b tier-2 fixtures use an ORDINARY (invite-only, no owner axis)
/// policy — #458 was reproduced on exactly these groups.
fn owner_certified_policy_owner_f3(owner_kp: &UserKeypair) -> x0x::groups::GroupPolicy {
    owner_certified_policy(owner_kp)
}

fn invite_only_policy(_owner_kp: &UserKeypair) -> x0x::groups::GroupPolicy {
    x0x::groups::GroupPolicy::default()
}

async fn issue458_stage_with_policy<F>(
    group_byte: u8,
    rename_first: bool,
    policy_fn: F,
) -> Result<Issue458Stage>
where
    F: Fn(&UserKeypair) -> x0x::groups::GroupPolicy,
{
    let dir = tempfile::tempdir()?;
    let owner_seed = [0xF3u8; 32];
    let owner_kp = UserKeypair::from_seed(&owner_seed)?;
    let authority_kp = AgentKeypair::generate()?;
    let authority_key_bytes = authority_kp.to_bytes();
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key(authority_kp)
            .with_agent_cert_path(dir.path().join("agent.cert"))
            .with_user_key(UserKeypair::from_seed(&owner_seed)?)
            .with_peer_cache_disabled()
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await?,
    );
    let authority = secure_endpoint_test_state_at(dir.path(), agent).await?;
    let group_id = format!("{group_byte:02x}").repeat(32);
    let authority_hex = hex::encode(authority.agent.agent_id().as_bytes());
    let invite_secret = format!("issue458-{group_byte:02x}-secret");
    let policy = policy_fn(&owner_kp);
    let base_info = insert_owner_group(
        authority.as_ref(),
        &group_id,
        policy.clone(),
        &invite_secret,
    )
    .await;

    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let joiner_cert = issue_joiner_cert(&owner_kp, &joiner)?;
    announce_full_cert(authority.as_ref(), joiner_cert).await;

    // The intermediate commit between invite base and join: a rename
    // (exactly the E1 P1/P4 sequence — POST /home/rename between invite
    // mint and join accept).
    if rename_first {
        let response = update_named_group(
            State(Arc::clone(&authority)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path(group_id.clone()),
            Json(UpdateGroupRequest {
                name: Some("Renamed mid-join".to_string()),
                description: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // The join: authority applies the member-signed MemberJoined and seals
    // the authoritative MemberAdded.
    let (.., join_event) = signed_member_joined_event_for_test(
        &joiner,
        &group_id,
        &authority_hex,
        &invite_secret,
        x0x::groups::GroupRole::Member,
    )?;
    assert!(
        apply_named_group_metadata_event(&authority, join_event, joiner_id, true, None)
            .await
            .accepted,
        "authority accepts the certified join"
    );

    // Capture the sealed MemberAdded from the staged join result.
    let member_added = {
        let results = authority.pending_join_results.read().await;
        results
            .get(&join_result_key(&group_id, &joiner_hex))
            .map(|pending| pending.event.clone())
            .expect("authority staged the MemberAdded join result")
    };
    Ok(Issue458Stage {
        authority,
        authority_key_bytes,
        group_id,
        base_info,
        member_added,
        joiner_key_bytes: joiner.to_bytes(),
        joiner_hex,
    })
}

/// #458 r3: the verified intervening chain the authority would send with
/// its join result — every retained commit strictly between the stub's
/// revision and the terminal MemberAdded commit.
async fn staged_head_attestation(
    stage: &Issue458Stage,
) -> Option<x0x::server::routes::named_groups::HeadAttestation> {
    let results = stage.authority.pending_join_results.read().await;
    results
        .get(&join_result_key(&stage.group_id, &stage.joiner_hex))
        .and_then(|pending| pending.head_attestation.clone())
}

async fn stage_intervening_chain(
    stage: &Issue458Stage,
    stub_revision: u64,
) -> Vec<x0x::groups::state_commit::RetainedCommit> {
    let terminal_revision = match &stage.member_added {
        NamedGroupMetadataEvent::MemberAdded {
            commit: Some(commit),
            ..
        } => commit.revision,
        _ => panic!("stage carries a MemberAdded with a commit"),
    };
    let info = stage
        .authority
        .named_groups
        .read()
        .await
        .get(&stage.group_id)
        .cloned()
        .expect("authority group");
    intervening_chain_from(&info, stub_revision, terminal_revision)
}

/// Build a JOINER-side AppState whose local agent IS the stage's joiner.
async fn joiner_state_for(stage: &Issue458Stage) -> Result<(Arc<AppState>, tempfile::TempDir)> {
    let jdir = tempfile::tempdir()?;
    let joiner_agent = Arc::new(
        Agent::builder()
            .with_machine_key(jdir.path().join("machine.key"))
            .with_agent_key(AgentKeypair::from_bytes(
                &stage.joiner_key_bytes.0,
                &stage.joiner_key_bytes.1,
            )?)
            .with_agent_cert_path(jdir.path().join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(jdir.path().join("contacts.json"))
            .build()
            .await?,
    );
    let joiner_state = secure_endpoint_test_state_at(jdir.path(), joiner_agent).await?;
    Ok((joiner_state, jdir))
}

/// #458 (LAN P4): the joiner stub holds the invite base (revision 0); the
/// authority renamed the Home before sealing the MemberAdded (revision 2,
/// prev = hash of the rename commit) — `prev_state_hash mismatch` rejected
/// the apply and the joiner wedged `already_joined`. The joiner must ADOPT
/// the authority-signed commit and seat itself.
#[tokio::test]
async fn issue458_joiner_adopts_member_added_across_rename_gap() -> Result<()> {
    let stage = issue458_stage(0x45, true).await?;
    let (joiner_state, _jdir) = joiner_state_for(&stage).await?;

    // Joiner stub: the invite base state (revision 0, founder-only roster).
    joiner_state
        .named_groups
        .write()
        .await
        .insert(stage.group_id.clone(), stage.base_info.clone());

    // #458 r3: the join-result response carries the verified intervening
    // chain (here: the rename commit at revision 1).
    let chain = stage_intervening_chain(&stage, stage.base_info.state_revision).await;
    assert!(
        !chain.is_empty(),
        "stage must retain the intervening rename commit"
    );
    let attest_key = join_result_key(&stage.group_id, &stage.joiner_hex);
    let staged_attestation = staged_head_attestation(&stage).await;
    assert!(
        staged_attestation.is_some(),
        "owner install stages the head attestation (the CAS anchor)"
    );
    joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(attest_key.clone(), chain);
    joiner_state
        .pending_head_attestations
        .lock()
        .unwrap()
        .insert(attest_key, staged_attestation.expect("checked above"));
    let result = apply_named_group_metadata_event(
        &joiner_state,
        stage.member_added.clone(),
        stage.authority.agent.agent_id(),
        true,
        None,
    )
    .await;
    assert!(
        result.accepted,
        "#458: joiner stub must adopt the authority MemberAdded across the prev-hash gap"
    );
    let commit_hash = {
        match &stage.member_added {
            NamedGroupMetadataEvent::MemberAdded {
                commit: Some(c), ..
            } => c.state_hash.clone(),
            _ => String::new(),
        }
    };
    {
        let groups = joiner_state.named_groups.read().await;
        let jinfo = groups.get(&stage.group_id).expect("joiner group");
        assert!(
            jinfo.has_active_member(&stage.joiner_hex),
            "#458: adopted commit must seat the joiner"
        );
        // r4: the adoption RECONSTRUCTS — the adopted hash EQUALS the
        // verified terminal commit's hash (a differing hash is a failure),
        // and hash == content by construction.
        assert_eq!(
            jinfo.state_hash, commit_hash,
            "#458 r4: the reconstructed adoption's hash MUST match the terminal commit"
        );
        assert!(
            jinfo.state_hash_is_current(),
            "#458 r4: adopted state must be internally consistent (hash == recomputed content)"
        );
    }
    let row = diagnostics_row(joiner_state.as_ref(), &stage.group_id).await;
    assert_eq!(
        row.counters.member_added_events_adopted, 1,
        "#458: the adoption must be visible in /diagnostics/groups"
    );
    Ok(())
}

/// #458 control: without the intermediate rename there is NO gap — the
/// ordinary chained apply must succeed and count no adoption.
#[tokio::test]
async fn issue458_no_gap_applies_without_adoption() -> Result<()> {
    let stage = issue458_stage(0x4b, false).await?;
    let (joiner_state, _jdir) = joiner_state_for(&stage).await?;
    joiner_state
        .named_groups
        .write()
        .await
        .insert(stage.group_id.clone(), stage.base_info.clone());

    let result = apply_named_group_metadata_event(
        &joiner_state,
        stage.member_added.clone(),
        stage.authority.agent.agent_id(),
        true,
        None,
    )
    .await;
    assert!(result.accepted, "chained apply must succeed with no gap");
    let row = diagnostics_row(joiner_state.as_ref(), &stage.group_id).await;
    assert_eq!(
        row.counters.member_added_events_adopted, 0,
        "no gap → no adoption counter"
    );
    Ok(())
}

/// #458 negative control: a THIRD-PARTY witness (not the joiner) must NOT
/// adopt across the same gap — adoption is reserved for the joiner's own
/// add; everyone else keeps the strict chain check.
#[tokio::test]
async fn issue458_third_party_cannot_adopt_across_gap() -> Result<()> {
    let stage = issue458_stage(0x4a, true).await?;
    let (witness, _wdir) = secure_endpoint_test_state().await?;
    // Witness holds the same revision-0 base stub.
    witness
        .named_groups
        .write()
        .await
        .insert(stage.group_id.clone(), stage.base_info.clone());

    let result = apply_named_group_metadata_event(
        &witness,
        stage.member_added.clone(),
        stage.authority.agent.agent_id(),
        true,
        None,
    )
    .await;
    assert!(
        !result.accepted,
        "#458: adoption is reserved for the joiner itself"
    );
    Ok(())
}

// ── Integration walkthrough (the E1 step-3/4 recipe, end to end) ─────────

/// Fresh owner → rename Home → RESTART → certified second device announces
/// ONCE (with identity) → join succeeds WITHOUT a second manual announce
/// and without the joiner wedging. This is the exact live sequence the
/// 2026-08-30/31 campaigns wedged on (#447 evidence timing + #457 rename
/// binding + #458 rename-gap commit).
#[tokio::test]
async fn integration_rename_restart_certified_join_single_announce() -> Result<()> {
    let owner_dir = tempfile::tempdir()?;
    let owner_seed = [0x0F; 32];
    let owner_kp = UserKeypair::from_seed(&owner_seed)?;
    let build_owner = || async {
        let agent = Arc::new(
            Agent::builder()
                .with_machine_key(owner_dir.path().join("machine.key"))
                .with_agent_key_path(owner_dir.path().join("agent.key"))
                .with_agent_cert_path(owner_dir.path().join("agent.cert"))
                .with_user_key(UserKeypair::from_seed(&owner_seed)?)
                .with_peer_cache_disabled()
                .with_contact_store_path(owner_dir.path().join("contacts.json"))
                .build()
                .await?,
        );
        secure_endpoint_test_state_at(owner_dir.path(), agent).await
    };
    let owner = build_owner().await?;
    let group_id = "0F".repeat(32);
    let policy = owner_certified_policy(&owner_kp);
    let invite_secret = "integration-walkthrough-secret".to_string();
    let base_info = insert_owner_group(owner.as_ref(), &group_id, policy, &invite_secret).await;

    // Rename the Home (POST /home/rename → PATCH /groups/:id) — the E1
    // step that used to desync the snapshot/named binding and wedge every
    // later certified join.
    let response = update_named_group(
        State(Arc::clone(&owner)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
        Json(UpdateGroupRequest {
            name: Some("David's Home".to_string()),
            description: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);

    // RESTART the owner daemon: rebuild AppState + named groups from the
    // same data dir (the durable named-group json is reloaded).
    drop(owner);
    let owner = build_owner().await?;
    assert!(
        owner.named_groups.read().await.contains_key(&group_id),
        "renamed Home must survive the restart"
    );

    // The certified second device announces ONCE with identity: the
    // discovery entry holds the digest, the async blob fetch landed in the
    // blob cache — the exact post-first-announce shape that used to answer
    // `no agent certificate resolved` until a SECOND announce.
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let joiner_cert = issue_joiner_cert(&owner_kp, &joiner)?;
    announce_digest_only(owner.as_ref(), joiner_cert.clone()).await;
    cache_verified_blob(owner.as_ref(), joiner_cert).await;

    // Authority applies the join — FIRST attempt, no second announce.
    let inviter_hex = hex::encode(owner.agent.agent_id().as_bytes());
    let (.., join_event) = signed_member_joined_event_for_test(
        &joiner,
        &group_id,
        &inviter_hex,
        &invite_secret,
        x0x::groups::GroupRole::Member,
    )?;
    assert!(
        apply_named_group_metadata_event(&owner, join_event, joiner_id, true, None)
            .await
            .accepted,
        "#447: one identity announce must be enough — evidence resolves from the blob cache"
    );

    // The joiner (stub from the ORIGINAL invite base, revision 0) receives
    // the authority's post-rename MemberAdded — the #458 prev-hash gap —
    // and must adopt it, seating itself without limbo.
    let member_added = {
        let results = owner.pending_join_results.read().await;
        results
            .get(&join_result_key(&group_id, &joiner_hex))
            .map(|pending| pending.event.clone())
            .expect("authority staged the MemberAdded")
    };
    let jdir = tempfile::tempdir()?;
    let joiner_agent = Arc::new(
        Agent::builder()
            .with_machine_key(jdir.path().join("machine.key"))
            .with_agent_key(AgentKeypair::from_bytes(
                &joiner.to_bytes().0,
                &joiner.to_bytes().1,
            )?)
            .with_agent_cert_path(jdir.path().join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(jdir.path().join("contacts.json"))
            .build()
            .await?,
    );
    let joiner_state = secure_endpoint_test_state_at(jdir.path(), joiner_agent).await?;
    joiner_state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), base_info.clone());

    // Pre-apply: the joiner is in limbo (stub, no seat) — typed, not a
    // bare already_joined.
    record_expected_join_result_inviter(
        joiner_state.as_ref(),
        join_result_key(&group_id, &joiner_hex),
        inviter_hex.clone(),
    );
    assert_eq!(
        local_join_membership_state(joiner_state.as_ref(), &base_info, &joiner_hex).await,
        "pending_authority_commit"
    );

    // #458 r3: the join-result response carries the intervening rename
    // commit so the adoption is chain-verified.
    let chain = {
        let groups = owner.named_groups.read().await;
        let info = groups.get(&group_id).cloned().expect("owner group");
        let terminal_revision = match &member_added {
            NamedGroupMetadataEvent::MemberAdded {
                commit: Some(commit),
                ..
            } => commit.revision,
            _ => panic!("member added carries a commit"),
        };
        intervening_chain_from(&info, base_info.state_revision, terminal_revision)
    };
    assert!(
        !chain.is_empty(),
        "owner retains the intervening rename commit"
    );
    let attest_key = join_result_key(&group_id, &joiner_hex);
    let staged_attestation = {
        let results = owner.pending_join_results.read().await;
        results
            .get(&attest_key)
            .and_then(|pending| pending.head_attestation.clone())
    };
    assert!(
        staged_attestation.is_some(),
        "owner install stages the head attestation (the CAS anchor)"
    );
    joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(attest_key.clone(), chain);
    joiner_state
        .pending_head_attestations
        .lock()
        .unwrap()
        .insert(attest_key, staged_attestation.expect("checked above"));
    assert!(
        apply_named_group_metadata_event(
            &joiner_state,
            member_added,
            owner.agent.agent_id(),
            true,
            None,
        )
        .await
        .accepted,
        "#458: the joiner must adopt the post-rename MemberAdded"
    );
    {
        let groups = joiner_state.named_groups.read().await;
        let info = groups.get(&group_id).expect("joiner group");
        assert!(
            info.has_active_member(&joiner_hex),
            "joiner seated after the single-announce join"
        );
    }
    Ok(())
}

// ── Review round 2 ────────────────────────────────────────────────────────

/// #458 r2 item 1 (route level): the join stub is NOT durable before the
/// member's own `MemberAdded` is observed; the initial AND duplicate join
/// responses carry the typed pending state; durability lands exactly when
/// the confirmation applies.
#[tokio::test]
async fn issue458r2_join_stub_not_durable_and_typed_until_member_added() -> Result<()> {
    // Authority side: OwnerCertified group at revision 0 with an invite,
    // and the certified joiner admitted (no rename → the MemberAdded
    // chains cleanly from the invite base).
    let stage = issue458_stage(0x51, false).await?;

    // Build the invite LINK the way the authority's invite endpoint does:
    // base state = the authority's revision-0 frontier.
    let inviter_id = stage.authority.agent.agent_id();
    let mut invite = x0x::groups::invite::SignedInvite::new(
        stage.group_id.clone(),
        "issue458r2-secret".to_string(),
        &inviter_id,
        3600,
    );
    {
        // Rebuild the invite base from the PRE-JOIN authority info (the
        // stub the joiner seeds from): founder-only roster.
        let mut base_info = stage.base_info.clone();
        base_info.recompute_state_hash();
        invite.group_name = base_info.name.clone();
        invite.group_description = Some(base_info.description.clone());
        invite.group_created_at = Some(base_info.created_at);
        invite.policy = Some(base_info.policy.clone());
        invite.stable_group_id = Some(base_info.stable_group_id().to_string());
        invite.base_state_revision = Some(base_info.state_revision);
        invite.base_members_v2 = Some(base_info.members_v2.clone());
        invite.base_state_hash = Some(base_info.state_hash.clone());
        invite.base_prev_state_hash = base_info.prev_state_hash.clone();
    }
    let invite_link = invite.encode_link()?;

    // JOINER side: owned install under the SAME owner (self-issued agent
    // cert — the certified second device), no group state yet.
    let jdir = tempfile::tempdir()?;
    // r3: the stage's authority owner seed — the certified second device
    // must chain to the SAME owner as the group's admission policy.
    let owner_seed = [0xF3u8; 32];
    let (joiner_pk, joiner_sk) = stage.joiner_key_bytes.clone();
    let joiner_kp = crate::identity::AgentKeypair::from_bytes(&joiner_pk, &joiner_sk)?;
    let agent_key_bytes = x0x::storage::serialize_agent_keypair(&joiner_kp)?;
    std::fs::write(jdir.path().join("agent.key"), agent_key_bytes)?;
    let joiner_agent = Arc::new(
        Agent::builder()
            .with_machine_key(jdir.path().join("machine2.key"))
            .with_agent_key_path(jdir.path().join("agent.key"))
            .with_agent_cert_path(jdir.path().join("agent.cert"))
            .with_user_key(UserKeypair::from_seed(&owner_seed)?)
            .with_peer_cache_disabled()
            .with_contact_store_path(jdir.path().join("contacts.json"))
            .build()
            .await?,
    );
    assert_eq!(
        hex::encode(joiner_agent.agent_id().as_bytes()),
        stage.joiner_hex,
        "joiner agent identity must be the staged joiner (persisted key)"
    );
    let joiner_state = secure_endpoint_test_state_at(jdir.path(), joiner_agent).await?;
    let named_groups_json = jdir.path().join("named_groups.json");

    // 1. Initial join via the REAL route: typed pending, nothing durable.
    let response = join_group_via_invite(
        State(Arc::clone(&joiner_state)),
        Json(JoinGroupRequest {
            invite: invite_link.clone(),
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "initial join accepted, body: {body}"
    );
    assert_eq!(
        body["join_state"], "pending_authority_commit",
        "r2: initial join must be typed pending, body: {body}"
    );
    assert!(
        joiner_state
            .named_groups
            .read()
            .await
            .contains_key(&stage.group_id),
        "in-memory stub exists for the poll/listener machinery"
    );
    let on_disk = tokio::fs::read_to_string(&named_groups_json)
        .await
        .unwrap_or_default();
    assert!(
        !on_disk.contains(&stage.group_id),
        "r2: an unconfirmed join must NOT be durable (named_groups.json)"
    );

    // 2. Duplicate join (retry while unconfirmed): typed pending, NOT
    // already_joined.
    let response = join_group_via_invite(
        State(Arc::clone(&joiner_state)),
        Json(JoinGroupRequest {
            invite: invite_link,
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "duplicate join ok, body: {body}");
    assert_eq!(
        body["already_joined"], false,
        "r2: an unconfirmed join must not claim already_joined, body: {body}"
    );
    assert_eq!(
        body["join_state"], "pending_authority_commit",
        "r2: duplicate join carries the typed pending state, body: {body}"
    );

    // 3. The authority's MemberAdded applies (the confirmation) — NOW the
    // group must be durable.
    let result = apply_named_group_metadata_event(
        &joiner_state,
        stage.member_added.clone(),
        stage.authority.agent.agent_id(),
        true,
        None,
    )
    .await;
    if !result.accepted {
        let stub = joiner_state
            .named_groups
            .read()
            .await
            .get(&stage.group_id)
            .cloned()
            .unwrap();
        let NamedGroupMetadataEvent::MemberAdded {
            commit: Some(c), ..
        } = &stage.member_added
        else {
            panic!("no commit")
        };
        let authority_hex = hex::encode(stage.authority.agent.agent_id().as_bytes());
        let probe_persist =
            persist_named_group_info(joiner_state.as_ref(), &stage.group_id, stub.clone()).await;
        let cert_probe = match &stage.member_added {
            NamedGroupMetadataEvent::MemberAdded {
                certificate_b64: Some(b),
                ..
            } => {
                use base64::Engine as _;
                let bytes = BASE64.decode(b).unwrap_or_default();
                bincode::deserialize::<x0x::identity::AgentCertificate>(&bytes)
                    .map(|cert| {
                        let owner = stub.policy.admission.owner_certified_user_id().cloned();
                        (
                            hex::encode(
                                cert.user_id()
                                    .map(|u| u.as_bytes().to_vec())
                                    .unwrap_or_default(),
                            ),
                            owner.map(|o| hex::encode(o.as_bytes())),
                            cert.agent_id().map(|a| hex::encode(a.as_bytes())),
                        )
                    })
                    .map_err(|e| format!("decode: {e}"))
            }
            _ => Err("no cert".to_string()),
        };
        panic!(
            "confirmation apply rejected: {result:?} | persist={probe_persist:?} | cert={cert_probe:?} | role={:?} verify={:?} stub_binding={:?} commit_binding={:?} stub_hash={} commit_prev={:?} commit_rev={} stub_rev={}",
            stub.caller_role(&authority_hex),
            c.verify_structure(),
            stub.security_binding,
            c.security_binding,
            stub.state_hash,
            c.prev_state_hash,
            c.revision,
            stub.state_revision,
        );
    }
    let on_disk = tokio::fs::read_to_string(&named_groups_json)
        .await
        .unwrap_or_default();
    assert!(
        on_disk.contains(&stage.group_id),
        "r2: the confirmed join IS durable once the member's own MemberAdded applied"
    );
    Ok(())
}

/// #458 r2 item 2 (security): adoption refuses a commit whose signer is not
/// the admin the event names — `committed_by` must equal the actor.
#[tokio::test]
async fn issue458r2_adoption_refuses_commit_signed_by_non_actor() -> Result<()> {
    let stage = issue458_stage(0x52, true).await?;
    let (joiner_state, _jdir) = joiner_state_for(&stage).await?;
    joiner_state
        .named_groups
        .write()
        .await
        .insert(stage.group_id.clone(), stage.base_info.clone());

    // Rebuild the authority's commit fields but SIGNED BY A THIRD KEY: the
    // event still names the authority as `actor` (admin per the stub), the
    // signature is internally valid, but `committed_by` ≠ actor.
    let forged = {
        let NamedGroupMetadataEvent::MemberAdded {
            commit: Some(real),
            revision,
            actor,
            agent_id,
            display_name,
            treekem_key_package_hash,
            certificate_b64,
            ..
        } = stage.member_added.clone()
        else {
            panic!("stage carries a MemberAdded with a commit");
        };
        let signer = AgentKeypair::generate()?;
        let signer_hex = hex::encode(signer.agent_id().as_bytes());
        let _ = &signer_hex;
        let forged_commit = x0x::groups::GroupStateCommit::sign(
            real.group_id.clone(),
            real.revision,
            real.prev_state_hash.clone(),
            real.roster_root.clone(),
            real.policy_hash.clone(),
            real.public_meta_hash.clone(),
            real.security_binding.clone(),
            real.withdrawn,
            real.committed_at,
            &signer,
        )?;
        NamedGroupMetadataEvent::MemberAdded {
            group_id: stage.group_id.clone(),
            revision,
            actor,
            agent_id,
            display_name,
            treekem_commit_b64: None,
            treekem_welcome_b64: None,
            welcome_ref: None,
            treekem_epoch: None,
            treekem_key_package_hash,
            member_joined_recovery: None,
            member_recovery_history: Vec::new(),
            certificate_b64,
            commit: Some(forged_commit),
        }
    };

    let chain = stage_intervening_chain(&stage, stage.base_info.state_revision).await;
    joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(join_result_key(&stage.group_id, &stage.joiner_hex), chain);
    let result = apply_named_group_metadata_event(
        &joiner_state,
        forged,
        stage.authority.agent.agent_id(),
        true,
        None,
    )
    .await;
    assert!(
        !result.accepted,
        "#458 r2: a commit signed by a non-actor key must never be adopted"
    );
    let row = diagnostics_row(joiner_state.as_ref(), &stage.group_id).await;
    assert_eq!(
        row.counters.member_added_events_adopted, 0,
        "no adoption for a third-party-signed commit"
    );
    Ok(())
}

/// #457 r2 item 4 (r5 semantics): a failed rebind JOURNAL PREPARATION
/// fails the whole named persist with a full rollback (map + sidecar +
/// journals) — success is never reported over a torn pair. (A snapshot
/// write failing AFTER the durable named save is the r5c case: journals
/// retained for startup replay, no rollback.)
#[tokio::test]
async fn issue457r2_rebind_failure_fails_the_persist() -> Result<()> {
    let fixture = member_joined_treekem_fixture(0x53, 0x53).await?;
    let state = &fixture.state;
    let group_id = fixture.group_id.clone();

    // Sabotage the JOURNAL PREPARATION: a DIRECTORY where the legacy
    // commit-point journal must land makes every journal write fail
    // BEFORE the named save, so the entire transaction rolls back.
    let journal_path = treekem_journal_path(&state.treekem_dir, &group_id);
    tokio::fs::create_dir_all(&journal_path).await?;

    let (pre_name, pre_hash) = {
        let groups = state.named_groups.read().await;
        let info = groups.get(&group_id).expect("group");
        (info.name.clone(), info.state_hash.clone())
    };
    let outcome = update_named_group(
        State(Arc::clone(state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
        Json(UpdateGroupRequest {
            name: Some("Must Not Stick".to_string()),
            description: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(
        outcome.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "#457 r2: rebind failure must fail the mutation, not report success"
    );
    let (post_name, post_hash) = {
        let groups = state.named_groups.read().await;
        let info = groups.get(&group_id).expect("group");
        (info.name.clone(), info.state_hash.clone())
    };
    assert_eq!(
        (post_name.as_str(), post_hash.as_str()),
        (pre_name.as_str(), pre_hash.as_str()),
        "#457 r2: the visible map must be rolled back on rebind failure"
    );
    Ok(())
}

/// #457/#458 r3: drive the JOINER's production Welcome receive path with
/// the OWNER's staged blob — the joiner's MemberAdded apply fetches the
/// Welcome by `welcome_ref` over the (daemon-wired) chunk protocol; the
/// production receive handlers are invoked directly with the real bytes.
async fn drive_joiner_welcome_install(
    owner_state: &Arc<AppState>,
    joiner_state: &Arc<AppState>,
    owner_id: &x0x::identity::AgentId,
    staged: &NamedGroupMetadataEvent,
) -> Result<()> {
    let welcome_ref = match staged {
        NamedGroupMetadataEvent::MemberAdded {
            welcome_ref: Some(r),
            ..
        } => r.clone(),
        _ => return Ok(()), // no Welcome reference — GSS shape
    };
    let group_id = match staged {
        NamedGroupMetadataEvent::MemberAdded { group_id, .. } => group_id.clone(),
        _ => String::new(),
    };
    let owner_blob = {
        let welcomes = owner_state.pending_welcomes.read().await;
        welcomes
            .get(&welcome_ref.welcome_id)
            .map(|p| p.bytes.clone())
            .expect("owner staged the Welcome blob")
    };
    assert_eq!(
        x0x::server::routes::named_groups::welcome_id_for_bytes(&owner_blob),
        welcome_ref.welcome_id
    );
    let slot_deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if joiner_state
            .pending_welcome_receives
            .read()
            .await
            .contains_key(&welcome_ref.welcome_id)
        {
            break;
        }
        assert!(
            std::time::Instant::now() < slot_deadline,
            "joiner never started the Welcome fetch"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let chunk_size = x0x::files::DEFAULT_CHUNK_SIZE;
    let total_chunks = x0x::files::total_chunks_for_size(welcome_ref.byte_len, chunk_size);
    handle_welcome_blob_message(
        joiner_state,
        owner_id,
        x0x::server::routes::named_groups::WelcomeBlobMessage::Offer {
            group_id,
            welcome_id: welcome_ref.welcome_id.clone(),
            byte_len: welcome_ref.byte_len,
            chunk_size,
            total_chunks,
            blake3_hex: welcome_ref.welcome_id.clone(),
        },
    )
    .await;
    for sequence in 0..total_chunks {
        let start = (sequence as usize) * chunk_size;
        let end = (((sequence as usize) + 1) * chunk_size).min(owner_blob.len());
        handle_welcome_blob_message(
            joiner_state,
            owner_id,
            x0x::server::routes::named_groups::WelcomeBlobMessage::Chunk {
                welcome_id: welcome_ref.welcome_id.clone(),
                sequence,
                data: BASE64.encode(&owner_blob[start..end]),
            },
        )
        .await;
    }
    handle_welcome_blob_message(
        joiner_state,
        owner_id,
        x0x::server::routes::named_groups::WelcomeBlobMessage::Complete {
            welcome_id: welcome_ref.welcome_id.clone(),
        },
    )
    .await;
    Ok(())
}

/// #457/#447/#458 review r2 item 5 — the REAL end-to-end walkthrough on the
/// certified-TreeKEM OwnerCertified Home path: two REAL agents on loopback
/// networking, the owner provisions a TreeKEM OwnerCertified Home, RENAMES
/// it, RESTARTS (AppState rebuilt from the same dir, production
/// `restore_treekem_groups`), and the certified second device announces
/// exactly ONCE with identity — the real V3 publish, the real owner ingest,
/// the real `ensure_blob` fetch over pubsub, the real watcher patch — then
/// `POST /groups/:id/invite` + `POST /groups/join` run as ROUTES, the
/// MemberJoined volley rides the metadata topic, and the joiner converges
/// (TreeKEM Welcome installed, roster seat, durable state) with NO second
/// manual announce.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_treekem_home_rename_restart_single_announce_end_to_end() -> Result<()> {
    let owner_dir = tempfile::tempdir()?;
    let joiner_dir = tempfile::tempdir()?;
    let owner_seed = [0x0E; 32];

    let loopback_addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    let loopback_cfg = move || x0x::network::NetworkConfig {
        bind_addr: Some(loopback_addr),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        ..x0x::network::NetworkConfig::default()
    };

    let build_owner_agent = || async {
        Agent::builder()
            .with_machine_key(owner_dir.path().join("machine.key"))
            .with_agent_key_path(owner_dir.path().join("agent.key"))
            .with_agent_cert_path(owner_dir.path().join("agent.cert"))
            .with_user_key(UserKeypair::from_seed(&owner_seed)?)
            .with_peer_cache_disabled()
            .with_contact_store_path(owner_dir.path().join("contacts.json"))
            .with_network_config(loopback_cfg())
            .build()
            .await
    };
    let joiner_agent = Arc::new(
        Agent::builder()
            .with_machine_key(joiner_dir.path().join("machine.key"))
            .with_agent_key_path(joiner_dir.path().join("agent.key"))
            .with_agent_cert_path(joiner_dir.path().join("agent.cert"))
            // The certified second device: same owner user key — the builder
            // load-or-self-issues an agent certificate chained to the owner.
            .with_user_key(UserKeypair::from_seed(&owner_seed)?)
            .with_peer_cache_disabled()
            .with_contact_store_path(joiner_dir.path().join("contacts.json"))
            .with_network_config(loopback_cfg())
            .build()
            .await?,
    );

    // Bring up both networks (identity listeners + blob responders + the
    // 3 s anonymous auto re-announce) and connect them.
    let owner_agent = Arc::new(build_owner_agent().await?);
    owner_agent.join_network().await?;
    joiner_agent.join_network().await?;
    let owner_net = owner_agent.network().expect("owner network").clone();
    let joiner_net = joiner_agent.network().expect("joiner network").clone();
    let joiner_addr = {
        let a = joiner_net.bound_addr().await.expect("joiner bound");
        if a.ip().is_unspecified() {
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                a.port(),
            )
        } else {
            a
        }
    };
    owner_net.connect_addr(joiner_addr).await?;
    let joiner_peer = ant_quic::PeerId(joiner_agent.machine_id().0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if owner_net.is_connected(&joiner_peer).await {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    if !owner_net.is_connected(&joiner_peer).await {
        eprintln!("SKIP: loopback connect unavailable in this environment");
        return Ok(());
    }
    // Let the 3 s anonymous auto re-announce fire and the gossip mesh settle
    // BEFORE the joiner's single identity announce.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Owner state + TreeKEM OwnerCertified Home.
    let owner_state =
        secure_endpoint_test_state_at(owner_dir.path(), Arc::clone(&owner_agent)).await?;
    let group_id = "0E".repeat(32);
    let owner_kp = UserKeypair::from_seed(&owner_seed)?;
    let mut home_info = x0x::groups::GroupInfo::with_policy(
        "Home".to_string(),
        String::new(),
        owner_agent.agent_id(),
        group_id.clone(),
        owner_certified_policy(&owner_kp),
    );
    home_info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    home_info.shared_secret = None;
    let group_id_bytes = hex::decode(&group_id)?;
    let creator_seed = agent_treekem_seed(owner_agent.as_ref(), &group_id_bytes);
    let treekem_group =
        x0x::mls::TreeKemMlsGroup::create(group_id_bytes, owner_agent.agent_id(), &creator_seed)?;
    home_info.secret_epoch = treekem_group.epoch();
    home_info.security_binding = Some(format!("treekem:epoch={}", treekem_group.epoch()));
    home_info.recompute_state_hash();
    let treekem_group = Arc::new(Mutex::new(treekem_group));
    owner_state
        .treekem_groups
        .write()
        .await
        .insert(group_id.clone(), Arc::clone(&treekem_group));
    owner_state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), home_info.clone());
    let persist = persist_named_group_info(&owner_state, &group_id, home_info).await;
    assert!(
        matches!(persist, Ok(AtomicWriteOutcome::Durable)),
        "Home provision must be durable (with snapshot rebind): {persist:?}"
    );
    ensure_named_group_listeners(Arc::clone(&owner_state), &group_id).await;

    // RENAME the Home (the #457 trigger), durably.
    let response = update_named_group(
        State(Arc::clone(&owner_state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
        Json(UpdateGroupRequest {
            name: Some("David's Home".to_string()),
            description: None,
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "rename must succeed");

    // RESTART the owner daemon: same dirs, agent key persisted, AppState
    // rebuilt, production snapshot restore, listeners re-armed.
    drop(owner_state);
    let owner_agent = Arc::new(build_owner_agent().await?);
    owner_agent.join_network().await?;
    // Reconnect the restarted daemon to the joiner and let the mesh settle —
    // the restart is a NEW network endpoint (exactly the live shape).
    let owner_net = owner_agent
        .network()
        .expect("restarted owner network")
        .clone();
    owner_net.connect_addr(joiner_addr).await?;
    let reconnect_deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < reconnect_deadline {
        if owner_net.is_connected(&joiner_peer).await {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        owner_net.is_connected(&joiner_peer).await,
        "restarted owner must reconnect to the joiner"
    );
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // The restarted daemon's STARTUP announce (anonymous — real daemons
    // announce at boot) starts its identity listener so it can INGEST.
    owner_agent.announce_identity(false, false).await?;
    let owner_state =
        secure_endpoint_test_state_at(owner_dir.path(), Arc::clone(&owner_agent)).await?;
    {
        let named_groups = owner_state.named_groups.read().await.clone();
        let restored = restore_treekem_groups(
            &named_groups,
            owner_state.agent.as_ref(),
            &owner_state.treekem_dir,
        )
        .await;
        assert!(
            restored.contains_key(&group_id),
            "#457: the renamed Home's TreeKEM group must survive the restart"
        );
    }
    ensure_named_group_listeners(Arc::clone(&owner_state), &group_id).await;

    // The certified second device announces exactly ONCE, with identity.
    joiner_agent.announce_identity(true, true).await?;
    let joiner_id = joiner_agent.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let evidence_deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let resolved = {
            let cache = owner_state.agent.identity_discovery_cache();
            let cache = cache.read().await;
            cache
                .get(&joiner_id)
                .and_then(|e| e.agent_certificate.clone())
        };
        if resolved.is_some() {
            break;
        }
        if std::time::Instant::now() >= evidence_deadline {
            let cache = owner_state.agent.identity_discovery_cache();
            let cache = cache.read().await;
            let entry = cache.get(&joiner_id);
            let peers = owner_net.connected_peers().await.len();
            eprintln!(
                "DIAG entry_present={} digest={:?} cert={:?} blob_stats={:?} peers={}",
                entry.is_some(),
                entry.and_then(|e| e.cert_digest.map(|d| hex::encode(&d[..4]))),
                entry.and_then(|e| e.agent_certificate.as_ref().map(|c| c.agent_id().is_ok())),
                owner_state.agent.announce_blob_cache.snapshot(),
                peers
            );
            panic!("#447: the single identity announce must resolve (blob fetch + watcher)");
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    // Invite via the real route.
    let response = create_group_invite(
        State(Arc::clone(&owner_state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
        HeaderMap::new(),
        axum::body::Bytes::new(),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "invite minted: {body}");
    let invite_link = body["invite_link"]
        .as_str()
        .expect("invite_link in response")
        .to_string();

    // Joiner joins via the real route (in-memory stub + real volley).
    let joiner_state =
        secure_endpoint_test_state_at(joiner_dir.path(), Arc::clone(&joiner_agent)).await?;
    let response = join_group_via_invite(
        State(Arc::clone(&joiner_state)),
        Json(JoinGroupRequest {
            invite: invite_link,
            display_name: Some("second-device".to_string()),
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "join accepted: {body}");
    assert_eq!(
        body["join_state"], "pending_authority_commit",
        "r2: the initial join response is typed pending: {body}"
    );

    // Converge, leg 1: the authority applies the volley's MemberJoined and
    // STAGES the authoritative MemberAdded (join result) — driven purely by
    // the real pubsub volley from the join route.
    let converge_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let owner_has = owner_state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .is_some_and(|i| i.has_active_member(&joiner_hex));
        if owner_has {
            break;
        }
        assert!(
            std::time::Instant::now() < converge_deadline,
            "authority never applied the certified MemberJoined"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // Converge, leg 2: the joiner receives the staged MemberAdded. In a
    // real daemon this arrives over the join-result DM (the poll's
    // FetchRequest → `handle_join_result_message`, wired at the DM router)
    // or the metadata topic; in-process the DM router is daemon wiring, so
    // the production RECEIVE handler is driven directly with the owner's
    // staged event — every check inside it (inviter pin, apply, Welcome
    // install) is the shipped code.
    let staged = loop {
        let results = owner_state.pending_join_results.read().await;
        if let Some(pending) = results.get(&join_result_key(&group_id, &joiner_hex)) {
            break pending.event.clone();
        }
        drop(results);
        assert!(
            std::time::Instant::now() < converge_deadline,
            "authority never staged the MemberAdded join result"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    // The joiner's METADATA LISTENER applies the pubsub-delivered
    // MemberAdded; its Welcome fetch is served through the production
    // chunk-receive handlers with the owner's staged blob (the chunk
    // transport itself is daemon wiring absent in-process).
    drive_joiner_welcome_install(
        &owner_state,
        &joiner_state,
        &owner_agent.agent_id(),
        &staged,
    )
    .await?;
    let joiner_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let joiner_installed = joiner_state
            .treekem_groups
            .read()
            .await
            .contains_key(&group_id);
        if joiner_installed {
            break;
        }
        if std::time::Instant::now() >= joiner_deadline {
            let groups = joiner_state.named_groups.read().await;
            let info = groups.get(&group_id);
            let row = diagnostics_row(joiner_state.as_ref(), &group_id).await;
            panic!(
                "joiner never installed the TreeKEM group: seat={:?} epoch={:?} counters={:?}",
                info.and_then(|i| i.members_v2.get(&joiner_hex).map(|m| m.state)),
                info.map(|i| i.secret_epoch),
                row.counters
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    // The confirmed join is durable on the joiner (r2 item 1) and the
    // owner applied exactly one MemberJoined.
    let joiner_disk = tokio::fs::read_to_string(joiner_dir.path().join("named_groups.json"))
        .await
        .unwrap_or_default();
    assert!(
        joiner_disk.contains(&group_id),
        "r2: the confirmed join is durable on the joiner"
    );
    let owner_row = diagnostics_row(owner_state.as_ref(), &group_id).await;
    assert!(
        owner_row.counters.member_joined_events_applied >= 1,
        "authority applied the certified MemberJoined on the single-announce evidence"
    );
    Ok(())
}

// ── Review round 3 ────────────────────────────────────────────────────────

/// Shared r3 stage harness: authority (join admitted, rename sealed in
/// between), joiner state holding the base stub, the staged MemberAdded,
/// and the VALID intervening chain.
struct R3Stage {
    /// Keeps the joiner state's tempdir alive for the struct's lifetime —
    /// dropping it deletes the directory and every persist fails.
    _keep_alive: tempfile::TempDir,
    joiner_state: Arc<AppState>,
    /// #458 r5: the owner-signed head attestation staged with the result —
    /// the CAS anchor adoption now REQUIRES.
    head_attestation: Option<x0x::server::routes::named_groups::HeadAttestation>,
    member_added: NamedGroupMetadataEvent,
    chain: Vec<x0x::groups::state_commit::RetainedCommit>,
    group_id: String,
    joiner_hex: String,
    authority_hex: String,
    authority_key_bytes: (Vec<u8>, Vec<u8>),
    base_policy_hash: String,
    /// r6: the stage authority's OWNER USER key (seed [0xF3]) — tests
    /// re-issue head attestations for mutated heads so the ONLY refusing
    /// check is the one under test.
    owner_kp: UserKeypair,
}

async fn r3_stage(group_byte: u8) -> Result<R3Stage> {
    let stage = issue458_stage(group_byte, true).await?;
    let (joiner_state, _keep_alive) = joiner_state_for(&stage).await?;
    joiner_state
        .named_groups
        .write()
        .await
        .insert(stage.group_id.clone(), stage.base_info.clone());
    let chain = stage_intervening_chain(&stage, stage.base_info.state_revision).await;
    let base_policy_hash = {
        let groups = joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("stub");
        x0x::groups::compute_policy_hash(&info.policy)
    };
    let owner_kp = UserKeypair::from_seed(&[0xF3u8; 32])?;
    let head_attestation = staged_head_attestation(&stage).await;
    Ok(R3Stage {
        _keep_alive,
        head_attestation,
        joiner_state,
        member_added: stage.member_added.clone(),
        chain,
        group_id: stage.group_id.clone(),
        joiner_hex: stage.joiner_hex.clone(),
        authority_hex: hex::encode(stage.authority.agent.agent_id().as_bytes()),
        authority_key_bytes: stage.authority_key_bytes.clone(),
        base_policy_hash,
        owner_kp,
    })
}

fn r3_apply_with_chain(
    stage: &R3Stage,
    chain: Vec<x0x::groups::state_commit::RetainedCommit>,
) -> impl std::future::Future<Output = ApplyMetadataResult> + '_ {
    let key = join_result_key(&stage.group_id, &stage.joiner_hex);
    stage
        .joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(key.clone(), chain);
    if let Some(attestation) = &stage.head_attestation {
        stage
            .joiner_state
            .pending_head_attestations
            .lock()
            .unwrap()
            .insert(key.clone(), attestation.clone());
    }
    let state = Arc::clone(&stage.joiner_state);
    let event = stage.member_added.clone();
    let actor = crate::server::parse_agent_id_hex(&stage.authority_hex).expect("actor id");
    async move {
        let result = apply_named_group_metadata_event(&state, event, actor, true, None).await;
        state.pending_adoption_chains.lock().unwrap().remove(&key);
        state.pending_head_attestations.lock().unwrap().remove(&key);
        result
    }
}

/// #458 r3: NO chain → NO adoption. The joiner stays pending instead of
/// trusting an unverifiable fork.
#[tokio::test]
async fn issue458r3_no_chain_means_no_adoption() -> Result<()> {
    let stage = r3_stage(0x61).await?;
    let result = r3_apply_with_chain(&stage, Vec::new()).await;
    assert!(!result.accepted, "no chain → refused");
    {
        let groups = stage.joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("stub retained");
        assert!(
            !info.has_active_member(&stage.joiner_hex),
            "joiner stays pending without a verifiable chain"
        );
    }
    let row = diagnostics_row(stage.joiner_state.as_ref(), &stage.group_id).await;
    assert_eq!(row.counters.member_added_events_rejected_state_chain_gap, 1);
    Ok(())
}

/// #458 r4: forge a chain LINK from explicit artifacts — the commit is
/// signed over the GIVEN roster projection + meta (so the snapshot checks
/// pass) with the GIVEN signer; the attack under test decides which
/// invariant must refuse it.
fn forge_retained_link(
    group_id: &str,
    policy_hash: &str,
    revision: u64,
    prev_hash: Option<String>,
    roster: std::collections::BTreeMap<String, x0x::groups::state_commit::RosterMemberSnapshot>,
    meta: x0x::groups::state_commit::GroupPublicMeta,
    signer: &AgentKeypair,
) -> x0x::groups::state_commit::RetainedCommit {
    let roster_root = x0x::groups::state_commit::roster_root_of_projection(&roster);
    let meta_hash = x0x::groups::compute_public_meta_hash(&meta);
    let commit = x0x::groups::GroupStateCommit::sign(
        group_id.to_string(),
        revision,
        prev_hash,
        roster_root,
        policy_hash.to_string(),
        meta_hash,
        None,
        false,
        revision,
        signer,
    )
    .expect("sign forged link");
    x0x::groups::state_commit::RetainedCommit {
        commit,
        roster,
        meta: Some(meta),
    }
}

#[tokio::test]
async fn issue458r3_chain_with_roster_churn_refused() -> Result<()> {
    // A link whose COMMITTED roster root covers a CHURNED roster (an extra
    // member) — internally consistent (snapshot re-derives the root), so
    // the refusal must come from the RECONSTRUCTION checks: the terminal
    // hash can no longer match the reconstruction... in fact the fold
    // ACCEPTS the churned snapshot by design (folding is the point); the
    // invariant exercised here is that a link whose snapshot does NOT
    // re-derive its signed root is refused.
    let stage = r3_stage(0x62).await?;
    let real = stage.chain.first().cloned().expect("one link");
    let mut tampered_roster = real.roster.clone();
    tampered_roster.insert(
        "ee".repeat(32),
        x0x::groups::state_commit::RosterMemberSnapshot {
            role: x0x::groups::GroupRole::Member,
            state: x0x::groups::GroupMemberState::Active,
            treekem_key_package_hash: None,
            certificate_digest: None,
        },
    );
    let churned = x0x::groups::state_commit::RetainedCommit {
        commit: real.commit.clone(),
        roster: tampered_roster,
        meta: real.meta.clone(),
    };
    let mut chain = stage.chain.clone();
    chain[0] = churned;
    let result = r3_apply_with_chain(&stage, chain).await;
    assert!(
        !result.accepted,
        "a snapshot that does not re-derive its signed roster_root → refused"
    );
    Ok(())
}

/// #458 r3: broken prev_state_hash linkage anywhere in the chain → refused
/// (the tampered link is re-signed by the REAL admin so the signature and
/// snapshot checks pass and the LINKAGE check is what refuses).
#[tokio::test]
async fn issue458r3_chain_with_broken_linkage_refused() -> Result<()> {
    let stage = r3_stage(0x63).await?;
    let real = stage.chain.first().cloned().expect("one link");
    let signer =
        AgentKeypair::from_bytes(&stage.authority_key_bytes.0, &stage.authority_key_bytes.1)?;
    let forged = forge_retained_link(
        &stage.group_id,
        &stage.base_policy_hash,
        real.commit.revision,
        Some("tampered".to_string()),
        real.roster.clone(),
        real.meta.clone().expect("meta"),
        &signer,
    );
    let mut chain = stage.chain.clone();
    chain[0] = forged;
    let result = r3_apply_with_chain(&stage, chain).await;
    assert!(!result.accepted, "broken linkage → refused");
    Ok(())
}

/// #458 r3: an intervening commit signed by a NON-admin of the verified
/// base roster → the authority re-derivation fails → refused. The link is
/// fully consistent (snapshot + meta re-derive) — only the SIGNER is wrong.
#[tokio::test]
async fn issue458r3_chain_signed_by_non_admin_refused() -> Result<()> {
    let stage = r3_stage(0x64).await?;
    let real = stage.chain.first().cloned().expect("one link");
    let stranger = AgentKeypair::generate()?;
    let forged = forge_retained_link(
        &stage.group_id,
        &stage.base_policy_hash,
        real.commit.revision,
        real.commit.prev_state_hash.clone(),
        real.roster.clone(),
        real.meta.clone().expect("meta"),
        &stranger,
    );
    let mut chain = stage.chain.clone();
    chain[0] = forged;
    let result = r3_apply_with_chain(&stage, chain).await;
    assert!(!result.accepted, "non-admin chain signer → refused");
    Ok(())
}

/// #458 r3 (`intervening_chain_from`): a truncated retained history sends
/// NO chain (joiner stays pending rather than blind-adopting).
#[tokio::test]
async fn issue458r3_truncated_history_sends_no_chain() -> Result<()> {
    let stage = issue458_stage(0x65, true).await?;
    let mut info = {
        let groups = stage.authority.named_groups.read().await;
        groups
            .get(&stage.group_id)
            .cloned()
            .expect("authority group")
    };
    let terminal_revision = match &stage.member_added {
        NamedGroupMetadataEvent::MemberAdded {
            commit: Some(commit),
            ..
        } => commit.revision,
        _ => panic!("commit"),
    };
    let full = intervening_chain_from(&info, stage.base_info.state_revision, terminal_revision);
    assert!(!full.is_empty(), "complete history yields the chain");
    let cutoff = stage.base_info.state_revision;
    info.commit_log
        .retain(|retained| retained.commit.revision > cutoff + 1);
    let truncated =
        intervening_chain_from(&info, stage.base_info.state_revision, terminal_revision);
    assert!(
        truncated.is_empty(),
        "truncated history must yield an EMPTY chain (joiner stays pending)"
    );
    Ok(())
}

/// #458 r3 item 1: an unrelated group's durable save must NOT capture a
/// pending join stub; the confirmation makes it durable.
#[tokio::test]
async fn issue458r3_pending_stub_excluded_from_unrelated_saves() -> Result<()> {
    let (state, dir, owner_kp) = owner_authority_state().await?;
    let other_id = "66".repeat(32);
    insert_owner_group(
        state.as_ref(),
        &other_id,
        owner_certified_policy(&owner_kp),
        "unrelated-secret",
    )
    .await;
    let other = state
        .named_groups
        .read()
        .await
        .get(&other_id)
        .cloned()
        .unwrap();
    persist_named_group_info(state.as_ref(), &other_id, other).await?;

    let stub_id = "67".repeat(32);
    let mut stub = x0x::groups::GroupInfo::with_policy(
        "pending".to_string(),
        String::new(),
        state.agent.agent_id(),
        stub_id.clone(),
        owner_certified_policy(&owner_kp),
    );
    stub.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(stub_id.clone(), stub.clone());
    state
        .pending_join_stubs
        .lock()
        .unwrap()
        .insert(stub_id.clone());

    let other2 = state
        .named_groups
        .read()
        .await
        .get(&other_id)
        .cloned()
        .unwrap();
    persist_named_group_info(state.as_ref(), &other_id, other2).await?;
    let on_disk = tokio::fs::read_to_string(dir.path().join("named_groups.json"))
        .await
        .unwrap_or_default();
    assert!(
        !on_disk.contains(&stub_id),
        "r3: an unrelated save must not durably capture the pending stub"
    );
    assert!(
        on_disk.contains(&other_id),
        "the unrelated group IS durable"
    );

    persist_named_group_info(state.as_ref(), &stub_id, stub).await?;
    let on_disk = tokio::fs::read_to_string(dir.path().join("named_groups.json"))
        .await
        .unwrap_or_default();
    assert!(
        on_disk.contains(&stub_id),
        "once confirmed, the group becomes durable"
    );
    Ok(())
}

/// #458/#447/#457 r3 item 5 — the REAL Home path end to end: the owner's
/// Home is created by the production `provision_home` auto-provisioning
/// (real policy, real marker, real seal), renamed through the production
/// `POST /home/rename` handler, the daemon RESTARTS, and the certified
/// second device joins after exactly ONE real identity announce — through
/// the real invite/join routes and the production join-result receive
/// handler. No hand-built GroupInfo anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_real_home_provision_rename_restart_join_e2e() -> Result<()> {
    let owner_dir = tempfile::tempdir()?;
    let joiner_dir = tempfile::tempdir()?;
    let owner_seed = [0x1E; 32];
    let loopback_addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    let loopback_cfg = move || x0x::network::NetworkConfig {
        bind_addr: Some(loopback_addr),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        ..x0x::network::NetworkConfig::default()
    };

    let build_owner_agent = || async {
        Agent::builder()
            .with_machine_key(owner_dir.path().join("machine.key"))
            .with_agent_key_path(owner_dir.path().join("agent.key"))
            .with_agent_cert_path(owner_dir.path().join("agent.cert"))
            .with_user_key(UserKeypair::from_seed(&owner_seed)?)
            .with_peer_cache_disabled()
            .with_contact_store_path(owner_dir.path().join("contacts.json"))
            .with_network_config(loopback_cfg())
            .build()
            .await
    };
    let joiner_agent = Arc::new(
        Agent::builder()
            .with_machine_key(joiner_dir.path().join("machine.key"))
            .with_agent_key_path(joiner_dir.path().join("agent.key"))
            .with_agent_cert_path(joiner_dir.path().join("agent.cert"))
            .with_user_key(UserKeypair::from_seed(&owner_seed)?)
            .with_peer_cache_disabled()
            .with_contact_store_path(joiner_dir.path().join("contacts.json"))
            .with_network_config(loopback_cfg())
            .build()
            .await?,
    );

    let owner_agent = Arc::new(build_owner_agent().await?);
    owner_agent.join_network().await?;
    joiner_agent.join_network().await?;
    let joiner_addr = {
        let net = joiner_agent.network().expect("joiner network");
        let a = net.bound_addr().await.expect("joiner bound");
        if a.ip().is_unspecified() {
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                a.port(),
            )
        } else {
            a
        }
    };
    owner_agent
        .network()
        .expect("owner network")
        .connect_addr(joiner_addr)
        .await?;
    let joiner_peer = ant_quic::PeerId(joiner_agent.machine_id().0);
    let mut deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if owner_agent
            .network()
            .expect("owner network")
            .is_connected(&joiner_peer)
            .await
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        owner_agent
            .network()
            .expect("owner network")
            .is_connected(&joiner_peer)
            .await,
        "loopback connect must succeed (bind already succeeded)"
    );
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // REAL Home auto-provision.
    let owner_state =
        secure_endpoint_test_state_at(owner_dir.path(), Arc::clone(&owner_agent)).await?;
    crate::server::routes::home::provision_home(&owner_state).await;
    let owner_kp = UserKeypair::from_seed(&owner_seed)?;
    let (home_id, home_info) =
        crate::server::routes::home::find_home(owner_state.as_ref(), &owner_kp.user_id())
            .await
            .expect("Home auto-provisioned");
    assert!(
        home_info.home.is_some(),
        "the real Home carries its Home metadata (trusted-Home predicate)"
    );
    ensure_named_group_listeners(Arc::clone(&owner_state), &home_id).await;

    // REAL rename route (POST /home/rename).
    let rename_req: crate::server::routes::home::RenameHomeRequest =
        serde_json::from_str(&format!("{{\"name\":\"{}\"}}", "Davids Home")).expect("rename body");
    let response = crate::server::routes::home::rename_home(
        State(Arc::clone(&owner_state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Json(rename_req),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK, "real rename succeeds");

    // RESTART the owner daemon.
    drop(owner_state);
    let owner_agent = Arc::new(build_owner_agent().await?);
    owner_agent.join_network().await?;
    owner_agent
        .network()
        .expect("restarted owner network")
        .connect_addr(joiner_addr)
        .await?;
    deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if owner_agent
            .network()
            .expect("restarted owner network")
            .is_connected(&joiner_peer)
            .await
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        owner_agent
            .network()
            .expect("restarted owner network")
            .is_connected(&joiner_peer)
            .await,
        "restarted owner must reconnect"
    );
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    owner_agent.announce_identity(false, false).await?;
    let owner_state =
        secure_endpoint_test_state_at(owner_dir.path(), Arc::clone(&owner_agent)).await?;
    let (found_id, _) =
        crate::server::routes::home::find_home(owner_state.as_ref(), &owner_kp.user_id())
            .await
            .expect("Home survives the restart");
    assert_eq!(found_id, home_id, "same Home across the restart");
    ensure_named_group_listeners(Arc::clone(&owner_state), &home_id).await;

    // The certified second device announces exactly ONCE with identity.
    let joiner_id = joiner_agent.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    joiner_agent.announce_identity(true, true).await?;
    let evidence_deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let resolved = owner_state
            .agent
            .identity_discovery_cache()
            .read()
            .await
            .get(&joiner_id)
            .and_then(|e| e.agent_certificate.clone());
        if resolved.is_some() {
            break;
        }
        assert!(
            std::time::Instant::now() < evidence_deadline,
            "#447: single identity announce must resolve (real ensure_blob + watcher)"
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    // Real invite + join routes.
    let response = create_group_invite(
        State(Arc::clone(&owner_state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(home_id.clone()),
        HeaderMap::new(),
        axum::body::Bytes::new(),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "invite minted: {body}");
    let invite_link = body["invite_link"].as_str().expect("link").to_string();

    let joiner_state =
        secure_endpoint_test_state_at(joiner_dir.path(), Arc::clone(&joiner_agent)).await?;
    let response = join_group_via_invite(
        State(Arc::clone(&joiner_state)),
        Json(JoinGroupRequest {
            invite: invite_link,
            display_name: Some("second-device".to_string()),
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "join accepted: {body}");
    assert_eq!(
        body["join_state"], "pending_authority_commit",
        "typed: {body}"
    );

    // Leg 1: the authority admits on the single-announce evidence.
    let admit_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let owner_has = owner_state
            .named_groups
            .read()
            .await
            .get(&home_id)
            .is_some_and(|i| i.has_active_member(&joiner_hex));
        if owner_has {
            break;
        }
        assert!(
            std::time::Instant::now() < admit_deadline,
            "authority never applied the certified MemberJoined"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let owner_row = diagnostics_row(owner_state.as_ref(), &home_id).await;
    assert!(
        owner_row.counters.member_joined_events_applied >= 1,
        "authority applied the certified join from ONE announce"
    );

    // Leg 2: the joiner receives its MemberAdded via the production
    // join-result receive handler (the DM transport itself is daemon
    // wiring absent in-process; the receive/apply code is shipped code).
    let staged = loop {
        let results = owner_state.pending_join_results.read().await;
        if let Some(pending) = results.get(&join_result_key(&home_id, &joiner_hex)) {
            break pending.event.clone();
        }
        drop(results);
        assert!(
            std::time::Instant::now() < admit_deadline,
            "authority never staged the MemberAdded"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    // Leg 2: the joiner's METADATA LISTENER applies the pubsub-delivered
    // MemberAdded (the real path); its Welcome fetch is served through the
    // production chunk-receive handlers with the owner's staged blob.
    drive_joiner_welcome_install(
        &owner_state,
        &joiner_state,
        &owner_agent.agent_id(),
        &staged,
    )
    .await?;
    let seat_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let seated = joiner_state
            .named_groups
            .read()
            .await
            .get(&home_id)
            .is_some_and(|i| i.has_active_member(&joiner_hex));
        let installed = joiner_state
            .treekem_groups
            .read()
            .await
            .contains_key(&home_id);
        if seated && installed {
            break;
        }
        assert!(
            std::time::Instant::now() < seat_deadline,
            "joiner never converged (seated={seated}, treekem_installed={installed})"
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    let joiner_disk =
        std::fs::read_to_string(joiner_dir.path().join("named_groups.json")).unwrap_or_default();
    assert!(
        joiner_disk.contains(&home_id),
        "confirmed join is durable on the joiner"
    );
    Ok(())
}

// ── Review round 4 ────────────────────────────────────────────────────────

/// #458 r4/r5 SECURITY regression — the removed-admin fork attack, built
/// for real: admin A is valid at the invite base revision but REMOVED on
/// the canonical chain the joiner has already observed. A serves a full
/// fork: an internally consistent rev-(base+1) link RETAINING its admin
/// seat, then a rev-(base+2) `MemberAdded` terminal signed by A, chaining
/// from A's fork hash with `roster_root` = fork roster + joiner — every
/// invariant the fork relies on holds except the ones the joiner's
/// CONVERGED view and the reconstruction enforce. The terminal PASSES the
/// revision gate (base+2 > canonical base+1), so the refusal must come
/// from the authority/linkage checks: A is not an admin in the joiner's
/// current (canonical) roster, and A's chain links from the BASE hash,
/// not the canonical head. If either check is removed the fork adopts and
/// this test fails.
#[tokio::test]
async fn issue458r4_removed_admin_fork_rejected() -> Result<()> {
    let stage = issue458_stage(0x71, false).await?;
    let (joiner_state, _keep) = joiner_state_for(&stage).await?;
    let attacker = AgentKeypair::generate()?;
    let attacker_hex = hex::encode(attacker.agent_id().as_bytes());

    // The joiner's stub: base roster WITH A seated as admin (the invite
    // base A minted while still valid).
    let mut stub = stage.base_info.clone();
    stub.add_member(
        attacker_hex.clone(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    stub.recompute_state_hash();
    joiner_state
        .named_groups
        .write()
        .await
        .insert(stage.group_id.clone(), stub.clone());

    // CANONICAL advance the joiner has already observed (the metadata
    // topic delivered it): the authority REMOVES A at base+1. The joiner
    // applies it — it chains from the stub.
    let signer =
        AgentKeypair::from_bytes(&stage.authority_key_bytes.0, &stage.authority_key_bytes.1)?;
    let mut canonical = stub.clone();
    canonical.remove_member(&attacker_hex, None);
    let removal_commit = x0x::groups::GroupStateCommit::sign(
        canonical.stable_group_id().to_string(),
        canonical.state_revision + 1,
        Some(canonical.state_hash.clone()),
        x0x::groups::compute_roster_root(&canonical.members_v2),
        x0x::groups::compute_policy_hash(&canonical.policy),
        x0x::groups::compute_public_meta_hash(&canonical.public_meta()),
        canonical.security_binding.clone(),
        false,
        canonical.state_revision + 1,
        &signer,
    )?;
    canonical.state_revision = removal_commit.revision;
    canonical.prev_state_hash = removal_commit.prev_state_hash.clone();
    canonical.state_hash = removal_commit.state_hash.clone();
    canonical
        .commit_log
        .push(x0x::groups::state_commit::RetainedCommit {
            commit: removal_commit,
            roster: x0x::groups::state_commit::roster_projection(&canonical.members_v2),
            meta: Some(canonical.public_meta()),
        });
    *joiner_state
        .named_groups
        .write()
        .await
        .get_mut(&stage.group_id)
        .unwrap() = canonical;

    // ── A's FORK ──
    // rev-(base+1): A's alternate commit retaining its own seat — the
    // exact commit the r3 review's working attack used. Internally
    // consistent: its projection re-derives its signed roster_root and
    // its sealed meta its signed meta hash.
    let fork_roster = x0x::groups::state_commit::roster_projection(&stub.members_v2);
    let fork_commit = x0x::groups::GroupStateCommit::sign(
        stub.stable_group_id().to_string(),
        stub.state_revision + 1,
        Some(stub.state_hash.clone()),
        x0x::groups::state_commit::roster_root_of_projection(&fork_roster),
        x0x::groups::compute_policy_hash(&stub.policy),
        x0x::groups::compute_public_meta_hash(&stub.public_meta()),
        stub.security_binding.clone(),
        false,
        stub.state_revision + 1,
        &attacker,
    )?;
    let fork_link = x0x::groups::state_commit::RetainedCommit {
        commit: fork_commit.clone(),
        roster: fork_roster.clone(),
        meta: Some(stub.public_meta()),
    };

    // rev-(base+2): the REAL terminal — a MemberAdded for the certified
    // joiner, signed by A, chained from A's fork hash, with
    // `roster_root` = fork roster + joiner (with the committed cert
    // digest, exactly as an honest authority would seal it).
    let (joiner_cert_b64, joiner_kp_hash) = match &stage.member_added {
        NamedGroupMetadataEvent::MemberAdded {
            certificate_b64,
            treekem_key_package_hash,
            ..
        } => (certificate_b64.clone(), treekem_key_package_hash.clone()),
        _ => panic!("stage member_added"),
    };
    let mut fork_members = stub.members_v2.clone();
    let mut added = x0x::groups::GroupMember::new_member(
        stage.joiner_hex.clone(),
        None,
        Some(attacker_hex.clone()),
        0,
    );
    added.role = x0x::groups::GroupRole::Member;
    added.state = x0x::groups::GroupMemberState::Active;
    if let Some(b64) = &joiner_cert_b64 {
        use base64::Engine as _;
        if let Ok(bytes) = BASE64.decode(b64) {
            if let Ok(cert) = bincode::deserialize::<x0x::identity::AgentCertificate>(&bytes) {
                added.certificate = Some(cert);
            }
        }
    }
    fork_members.insert(stage.joiner_hex.clone(), added);
    let terminal_roster_root = x0x::groups::compute_roster_root(&fork_members);
    let terminal_commit = x0x::groups::GroupStateCommit::sign(
        stub.stable_group_id().to_string(),
        stub.state_revision + 2,
        Some(fork_commit.state_hash.clone()),
        terminal_roster_root,
        x0x::groups::compute_policy_hash(&stub.policy),
        x0x::groups::compute_public_meta_hash(&stub.public_meta()),
        stub.security_binding.clone(),
        false,
        stub.state_revision + 2,
        &attacker,
    )?;
    let fork_event = NamedGroupMetadataEvent::MemberAdded {
        group_id: stage.group_id.clone(),
        revision: stub.roster_revision + 2,
        actor: attacker_hex.clone(),
        agent_id: stage.joiner_hex.clone(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: joiner_kp_hash,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: joiner_cert_b64,
        commit: Some(terminal_commit),
    };

    // Serve the fork with the join result: chain + terminal, actor = A,
    // sender = A (A "authorized-as-of-invite" — that is the whole point).
    joiner_state.pending_adoption_chains.lock().unwrap().insert(
        join_result_key(&stage.group_id, &stage.joiner_hex),
        vec![fork_link],
    );
    let attacker_id = attacker.agent_id();
    let result =
        apply_named_group_metadata_event(&joiner_state, fork_event, attacker_id, true, None).await;
    assert!(
        !result.accepted,
        "#458 r4: the removed-admin fork must be REJECTED against the joiner's converged view"
    );
    {
        let groups = joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("group");
        assert!(
            !info.has_active_member(&stage.joiner_hex),
            "the fork must not seat the joiner"
        );
        assert!(
            !info.has_active_member(&attacker_hex),
            "the canonical removal of A must STAY applied"
        );
    }
    Ok(())
}

/// #458 r4 positive: the reconstructed adoption's state hash MUST MATCH
/// the terminal commit (a differing hash is now a failure) — pins the
/// full-node verification on the happy path.
#[tokio::test]
async fn issue458r4_reconstruction_adopts_matching_hash() -> Result<()> {
    let stage = r3_stage(0x72).await?;
    let commit_hash = match &stage.member_added {
        NamedGroupMetadataEvent::MemberAdded {
            commit: Some(commit),
            ..
        } => commit.state_hash.clone(),
        _ => panic!("commit"),
    };
    let result = r3_apply_with_chain(&stage, stage.chain.clone()).await;
    assert!(result.accepted, "valid chain adopts");
    {
        let groups = stage.joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("group");
        assert!(
            info.has_active_member(&stage.joiner_hex),
            "joiner seated via reconstruction"
        );
        assert_eq!(
            info.state_hash, commit_hash,
            "#458 r4: the adopted state hash MUST equal the verified terminal commit's hash"
        );
        assert!(
            info.state_hash_is_current(),
            "hash == content by construction"
        );
    }
    Ok(())
}

// ── Review round 5 ────────────────────────────────────────────────────────

/// #458 r5 SECURITY — the STALE-JOINER removed-admin fork (the round-4
/// review's working attack, now defended): the joiner sits at the invite
/// base where A is still an admin; the CANONICAL chain removed A at
/// base+1 (the joiner has NOT observed it); A serves a full, internally
/// consistent fork — rev-(base+1) retaining its seat + rev-(base+2)
/// `MemberAdded` for the certified joiner. Every reconstruction check A
/// can satisfy, it does. The defense is the OWNER-SIGNED HEAD ATTESTATION:
/// A never holds the owner's user key, so its fork is either unattested
/// (unanchorable gap → refuse) or attested by the wrong key (verification
/// fails). Both variants must be REJECTED; the joiner stays pending.
#[tokio::test]
async fn issue458r5_stale_joiner_removed_admin_fork_rejected() -> Result<()> {
    let stage = issue458_stage(0x81, false).await?;
    let (joiner_state, _keep) = joiner_state_for(&stage).await?;
    let attacker = AgentKeypair::generate()?;
    let attacker_hex = hex::encode(attacker.agent_id().as_bytes());

    // Joiner stub AT THE INVITE BASE with A seated as admin (A minted the
    // invite while valid). The canonical removal is NOT applied here —
    // that is what makes the joiner "stale".
    let mut stub = stage.base_info.clone();
    stub.add_member(
        attacker_hex.clone(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    stub.recompute_state_hash();
    joiner_state
        .named_groups
        .write()
        .await
        .insert(stage.group_id.clone(), stub.clone());

    // A's fork: rev-(base+1) retaining its seat (internally consistent:
    // the projection re-derives the signed root, the sealed meta the meta
    // hash), then a rev-(base+2) MemberAdded signed by A chaining from
    // the fork hash with roster_root = fork roster + joiner (with the
    // committed cert digest) — indistinguishable from an honest authority
    // seal by every check except the owner anchor.
    let fork_roster = x0x::groups::state_commit::roster_projection(&stub.members_v2);
    let fork_commit = x0x::groups::GroupStateCommit::sign(
        stub.stable_group_id().to_string(),
        stub.state_revision + 1,
        Some(stub.state_hash.clone()),
        x0x::groups::state_commit::roster_root_of_projection(&fork_roster),
        x0x::groups::compute_policy_hash(&stub.policy),
        x0x::groups::compute_public_meta_hash(&stub.public_meta()),
        stub.security_binding.clone(),
        false,
        stub.state_revision + 1,
        &attacker,
    )?;
    let fork_link = x0x::groups::state_commit::RetainedCommit {
        commit: fork_commit.clone(),
        roster: fork_roster.clone(),
        meta: Some(stub.public_meta()),
    };
    let (joiner_cert_b64, joiner_kp_hash) = match &stage.member_added {
        NamedGroupMetadataEvent::MemberAdded {
            certificate_b64,
            treekem_key_package_hash,
            ..
        } => (certificate_b64.clone(), treekem_key_package_hash.clone()),
        _ => panic!("stage member_added"),
    };
    let mut fork_members = stub.members_v2.clone();
    let mut added = x0x::groups::GroupMember::new_member(
        stage.joiner_hex.clone(),
        None,
        Some(attacker_hex.clone()),
        0,
    );
    added.role = x0x::groups::GroupRole::Member;
    added.state = x0x::groups::GroupMemberState::Active;
    if let Some(b64) = &joiner_cert_b64 {
        use base64::Engine as _;
        if let Ok(bytes) = BASE64.decode(b64) {
            if let Ok(cert) = bincode::deserialize::<x0x::identity::AgentCertificate>(&bytes) {
                added.certificate = Some(cert);
            }
        }
    }
    fork_members.insert(stage.joiner_hex.clone(), added);
    let terminal_commit = x0x::groups::GroupStateCommit::sign(
        stub.stable_group_id().to_string(),
        stub.state_revision + 2,
        Some(fork_commit.state_hash.clone()),
        x0x::groups::compute_roster_root(&fork_members),
        x0x::groups::compute_policy_hash(&stub.policy),
        x0x::groups::compute_public_meta_hash(&stub.public_meta()),
        stub.security_binding.clone(),
        false,
        stub.state_revision + 2,
        &attacker,
    )?;
    let fork_event = NamedGroupMetadataEvent::MemberAdded {
        group_id: stage.group_id.clone(),
        revision: stub.roster_revision + 2,
        actor: attacker_hex.clone(),
        agent_id: stage.joiner_hex.clone(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: joiner_kp_hash,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: joiner_cert_b64,
        commit: Some(terminal_commit.clone()),
    };
    let attacker_id = attacker.agent_id();

    // Variant 1: NO attestation — the unanchorable gap. A cannot produce
    // the owner's signature, so it serves the fork bare.
    let key = join_result_key(&stage.group_id, &stage.joiner_hex);
    joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(key.clone(), vec![fork_link.clone()]);
    let result = apply_named_group_metadata_event(
        &joiner_state,
        fork_event.clone(),
        attacker_id,
        true,
        None,
    )
    .await;
    assert!(
        !result.accepted,
        "#458 r5: an unattested fork across a stale base must be REJECTED (unanchorable)"
    );

    // Variant 2: a FORGED attestation signed by A's AGENT key — the
    // verification key must come from the trusted committed certificate's
    // owner public key, so A's key fails both the owner-id binding and the
    // signature check.
    use base64::Engine as _;
    let canonical = {
        // Mirror HeadAttestation's canonical bytes (the field layout is
        // fixed and versioned): build via sign on the real owner key path
        // is impossible for A; hand-build the same bytes.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"x0x.join-head-attest.v1\0");
        buf.extend_from_slice(stub.stable_group_id().as_bytes());
        buf.push(0);
        buf.extend_from_slice(&(terminal_commit.revision - 1).to_le_bytes());
        buf.extend_from_slice(
            terminal_commit
                .prev_state_hash
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        );
        buf.push(0);
        buf.extend_from_slice(stage.joiner_hex.as_bytes());
        buf
    };
    let forged_sig = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        attacker.secret_key(),
        &canonical,
    )?;
    let forged = x0x::server::routes::named_groups::HeadAttestation {
        group_id: stub.stable_group_id().to_string(),
        head_revision: terminal_commit.revision - 1,
        head_state_hash: terminal_commit.prev_state_hash.clone().unwrap_or_default(),
        member_agent_id: stage.joiner_hex.clone(),
        signature_b64: BASE64.encode(forged_sig.as_bytes()),
    };
    joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(key.clone(), vec![fork_link]);
    joiner_state
        .pending_head_attestations
        .lock()
        .unwrap()
        .insert(key.clone(), forged);
    let result =
        apply_named_group_metadata_event(&joiner_state, fork_event, attacker_id, true, None).await;
    assert!(
        !result.accepted,
        "#458 r5: a fork with an attestation signed by the WRONG key must be REJECTED"
    );
    {
        let groups = joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("group");
        assert!(
            !info.has_active_member(&stage.joiner_hex),
            "the fork must never seat the joiner"
        );
        // A was active in the invite-base stub by construction; what must
        // hold is that the fork advanced NOTHING — the stub is unchanged.
        assert_eq!(
            info.state_revision, stub.state_revision,
            "the fork must not advance the stub at all"
        );
    }
    Ok(())
}

/// #458 r5b/r6 item 3: withdrawal is TERMINAL — a WITHDRAWN intermediate
/// link followed by an UNWITHDRAWN MemberAdded terminal must be refused
/// outright. The terminal is RE-SIGNED to chain from the withdrawn link
/// and the owner attestation is RE-ISSUED for the mutated head, so the
/// anchor CAS, linkage, roster and hash checks all PASS and the ONLY
/// refusing check is withdrawal terminality.
#[tokio::test]
async fn issue458r5_withdrawn_link_refused() -> Result<()> {
    let stage = r3_stage(0x82).await?;
    let real = stage.chain.first().cloned().expect("one link");
    let signer =
        AgentKeypair::from_bytes(&stage.authority_key_bytes.0, &stage.authority_key_bytes.1)?;
    let withdrawn_commit = x0x::groups::GroupStateCommit::sign(
        real.commit.group_id.clone(),
        real.commit.revision,
        real.commit.prev_state_hash.clone(),
        real.commit.roster_root.clone(),
        real.commit.policy_hash.clone(),
        real.commit.public_meta_hash.clone(),
        real.commit.security_binding.clone(),
        true, // withdrawn
        real.commit.committed_at,
        &signer,
    )?;
    let withdrawn_link = x0x::groups::state_commit::RetainedCommit {
        commit: withdrawn_commit.clone(),
        roster: real.roster.clone(),
        meta: real.meta.clone(),
    };

    // UNWITHDRAWN terminal chained from the withdrawn link: roster =
    // withdrawn link's roster + joiner, all hashes consistent, signed by
    // the authority.
    let (joiner_cert_b64, joiner_kp_hash) = match &stage.member_added {
        NamedGroupMetadataEvent::MemberAdded {
            certificate_b64,
            treekem_key_package_hash,
            ..
        } => (certificate_b64.clone(), treekem_key_package_hash.clone()),
        _ => panic!("stage member_added"),
    };
    let mut members = std::collections::BTreeMap::new();
    for (id, snap) in &real.roster {
        let mut m = x0x::groups::GroupMember::new_member(id.clone(), None, None, 0);
        m.role = snap.role;
        m.state = snap.state;
        members.insert(id.clone(), m);
    }
    let mut added = x0x::groups::GroupMember::new_member(stage.joiner_hex.clone(), None, None, 0);
    added.role = x0x::groups::GroupRole::Member;
    added.state = x0x::groups::GroupMemberState::Active;
    if let Some(b64) = &joiner_cert_b64 {
        use base64::Engine as _;
        if let Ok(bytes) = BASE64.decode(b64) {
            if let Ok(cert) = bincode::deserialize::<x0x::identity::AgentCertificate>(&bytes) {
                added.certificate = Some(cert);
            }
        }
    }
    members.insert(stage.joiner_hex.clone(), added);
    let terminal = x0x::groups::GroupStateCommit::sign(
        withdrawn_commit.group_id.clone(),
        withdrawn_commit.revision + 1,
        Some(withdrawn_commit.state_hash.clone()),
        x0x::groups::compute_roster_root(&members),
        withdrawn_commit.policy_hash.clone(),
        withdrawn_commit.public_meta_hash.clone(),
        withdrawn_commit.security_binding.clone(),
        false, // UNWITHDRAWN terminal after a withdrawn link
        withdrawn_commit.revision + 1,
        &signer,
    )?;
    let event = NamedGroupMetadataEvent::MemberAdded {
        group_id: stage.group_id.clone(),
        revision: terminal.revision,
        actor: stage.authority_hex.clone(),
        agent_id: stage.joiner_hex.clone(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: joiner_kp_hash,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: joiner_cert_b64,
        commit: Some(terminal.clone()),
    };
    // Fresh owner attestation for the MUTATED head (the withdrawn link's
    // hash) so the anchor CAS passes.
    let attestation = x0x::server::routes::named_groups::HeadAttestation::sign(
        &stage.group_id,
        terminal.revision - 1,
        terminal.prev_state_hash.as_deref().unwrap_or_default(),
        &stage.joiner_hex,
        &stage.owner_kp,
    )
    .expect("attest");

    let key = join_result_key(&stage.group_id, &stage.joiner_hex);
    stage
        .joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(key.clone(), vec![withdrawn_link]);
    stage
        .joiner_state
        .pending_head_attestations
        .lock()
        .unwrap()
        .insert(key, attestation);
    let actor = crate::server::parse_agent_id_hex(&stage.authority_hex).expect("actor");
    let result =
        apply_named_group_metadata_event(&stage.joiner_state, event, actor, true, None).await;
    assert!(
        !result.accepted,
        "#458 r6: an unwithdrawn terminal after a withdrawn link MUST be refused"
    );
    {
        let groups = stage.joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("group");
        assert!(
            !info.has_active_member(&stage.joiner_hex),
            "the joiner stays pending"
        );
        assert!(
            !info.withdrawn,
            "the withdrawn fork must not touch the stub"
        );
    }
    Ok(())
}

/// #458 r6 item 4: a GSS/legacy `security_binding` that CHANGED inside the
/// gap (an unverifiable secret rotation) refuses adoption — the binding is
/// never copied unverified. Terminal re-signed with a CHANGED binding,
/// owner attestation re-issued, so ONLY the binding gate refuses.
#[tokio::test]
async fn issue458r6_gss_binding_change_refused() -> Result<()> {
    let stage = r3_stage(0x86).await?;
    let real = stage.chain.first().cloned().expect("one link");
    let signer =
        AgentKeypair::from_bytes(&stage.authority_key_bytes.0, &stage.authority_key_bytes.1)?;
    let stage2 = &stage;
    let _ = stage2;
    // Terminal identical to the staged one EXCEPT the binding string.
    let terminal = match &stage.member_added {
        NamedGroupMetadataEvent::MemberAdded {
            commit: Some(commit),
            ..
        } => commit.clone(),
        _ => panic!("commit"),
    };
    let rotated = x0x::groups::GroupStateCommit::sign(
        terminal.group_id.clone(),
        terminal.revision,
        terminal.prev_state_hash.clone(),
        terminal.roster_root.clone(),
        terminal.policy_hash.clone(),
        terminal.public_meta_hash.clone(),
        Some("gss:epoch=99".to_string()), // CHANGED binding
        terminal.withdrawn,
        terminal.committed_at,
        &signer,
    )?;
    let mut event = stage.member_added.clone();
    if let NamedGroupMetadataEvent::MemberAdded {
        commit: commit_slot,
        ..
    } = &mut event
    {
        *commit_slot = Some(rotated.clone());
    }
    let attestation = x0x::server::routes::named_groups::HeadAttestation::sign(
        &stage.group_id,
        rotated.revision - 1,
        rotated.prev_state_hash.as_deref().unwrap_or_default(),
        &stage.joiner_hex,
        &stage.owner_kp,
    )
    .expect("attest");
    let key = join_result_key(&stage.group_id, &stage.joiner_hex);
    stage
        .joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(key.clone(), vec![real]);
    stage
        .joiner_state
        .pending_head_attestations
        .lock()
        .unwrap()
        .insert(key, attestation);
    let actor = crate::server::parse_agent_id_hex(&stage.authority_hex).expect("actor");
    let result =
        apply_named_group_metadata_event(&stage.joiner_state, event, actor, true, None).await;
    assert!(
        !result.accepted,
        "#458 r6: a changed GSS/legacy binding inside the gap must be REFUSED"
    );
    Ok(())
}

/// Shared builder for the r6c "targeted-check" regression shape: re-sign
/// an UNWITHDRAWN MemberAdded terminal chained on a MUTATED link
/// (`prev_state_hash` = the mutated link's hash, `roster_root` computed
/// over the given terminal roster) and issue a FRESH owner attestation
/// for the mutated head, so linkage, snapshot/meta re-derivation, the
/// anchor CAS and the hash machinery all PASS and the ONLY refusing
/// check can be the one under test.
async fn r6c_targeted_refusal(
    stage: &R3Stage,
    mutated_link: x0x::groups::state_commit::RetainedCommit,
    terminal_roster_members: &std::collections::BTreeMap<String, x0x::groups::GroupMember>,
) -> Result<ApplyMetadataResult> {
    let signer =
        AgentKeypair::from_bytes(&stage.authority_key_bytes.0, &stage.authority_key_bytes.1)?;
    let terminal = x0x::groups::GroupStateCommit::sign(
        stage.group_id.clone(),
        mutated_link.commit.revision + 1,
        Some(mutated_link.commit.state_hash.clone()),
        x0x::groups::compute_roster_root(terminal_roster_members),
        mutated_link.commit.policy_hash.clone(),
        mutated_link.commit.public_meta_hash.clone(),
        mutated_link.commit.security_binding.clone(),
        false,
        mutated_link.commit.revision + 1,
        &signer,
    )?;
    let (joiner_cert_b64, joiner_kp_hash) = match &stage.member_added {
        NamedGroupMetadataEvent::MemberAdded {
            certificate_b64,
            treekem_key_package_hash,
            ..
        } => (certificate_b64.clone(), treekem_key_package_hash.clone()),
        _ => panic!("stage member_added"),
    };
    let event = NamedGroupMetadataEvent::MemberAdded {
        group_id: stage.group_id.clone(),
        revision: terminal.revision,
        actor: stage.authority_hex.clone(),
        agent_id: stage.joiner_hex.clone(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: joiner_kp_hash,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: joiner_cert_b64,
        commit: Some(terminal.clone()),
    };
    let attestation = x0x::server::routes::named_groups::HeadAttestation::sign(
        &stage.group_id,
        terminal.revision - 1,
        terminal.prev_state_hash.as_deref().unwrap_or_default(),
        &stage.joiner_hex,
        &stage.owner_kp,
    )
    .expect("fresh owner attestation for the mutated head");
    let key = join_result_key(&stage.group_id, &stage.joiner_hex);
    stage
        .joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(key.clone(), vec![mutated_link]);
    stage
        .joiner_state
        .pending_head_attestations
        .lock()
        .unwrap()
        .insert(key, attestation);
    let actor = crate::server::parse_agent_id_hex(&stage.authority_hex).expect("actor");
    let result =
        apply_named_group_metadata_event(&stage.joiner_state, event, actor, true, None).await;
    stage
        .joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .remove(&join_result_key(&stage.group_id, &stage.joiner_hex));
    Ok(result)
}

/// Materialize a projection into full members (the shape
/// `apply_reconstructed_roster` reconstructs — certificates are NOT
/// recoverable from digests).
fn r6c_materialize(
    projection: &std::collections::BTreeMap<
        String,
        x0x::groups::state_commit::RosterMemberSnapshot,
    >,
) -> std::collections::BTreeMap<String, x0x::groups::GroupMember> {
    let mut members = std::collections::BTreeMap::new();
    for (id, snap) in projection {
        let mut m = x0x::groups::GroupMember::new_member(id.clone(), None, None, 0);
        m.role = snap.role;
        m.state = snap.state;
        members.insert(id.clone(), m);
    }
    members
}

/// #458 r5c/r6c: a link that folds to a roster violating the LAST-ADMIN
/// invariant (the sole admin demoted inside the gap) is refused PER LINK.
/// The terminal is re-signed ON the mutated link with a fresh owner
/// attestation, so linkage, snapshot/meta re-derivation, the anchor CAS
/// and the terminal hash machinery all PASS. PINNING LIMITATION (r7
/// item 7.7, reviewer-acknowledged): a zero-admin folded roster ALSO
/// fails the terminal committer-admin check (`admin_in(&roster,
/// &commit.committed_by)` — the committer is no longer an admin in its
/// own folded roster), so the per-link invariant cannot be uniquely
/// pinned by any single-check deletion; the test proves the INVARIANT
/// FAMILY (fold + terminal authority) refuses the smuggling shape.
#[tokio::test]
async fn issue458r5_last_admin_smuggle_refused() -> Result<()> {
    let stage = r3_stage(0x83).await?;
    let real = stage.chain.first().cloned().expect("one link");
    let signer =
        AgentKeypair::from_bytes(&stage.authority_key_bytes.0, &stage.authority_key_bytes.1)?;
    // Demote the sole admin to Member inside the link's snapshot.
    let mut smuggled = real.roster.clone();
    for snap in smuggled.values_mut() {
        if snap.role.at_least(x0x::groups::GroupRole::Admin) {
            snap.role = x0x::groups::GroupRole::Member;
        }
    }
    let smuggled_root = x0x::groups::state_commit::roster_root_of_projection(&smuggled);
    let smuggled_commit = x0x::groups::GroupStateCommit::sign(
        real.commit.group_id.clone(),
        real.commit.revision,
        real.commit.prev_state_hash.clone(),
        smuggled_root,
        real.commit.policy_hash.clone(),
        real.commit.public_meta_hash.clone(),
        real.commit.security_binding.clone(),
        false,
        real.commit.committed_at,
        &signer,
    )?;
    let smuggled_link = x0x::groups::state_commit::RetainedCommit {
        commit: smuggled_commit,
        roster: smuggled.clone(),
        meta: real.meta.clone(),
    };
    // Terminal roster: the mutated (demoted-admin) roster + the joiner —
    // exactly what an honest authority sealing on this fork would commit.
    let mut terminal_roster = r6c_materialize(&smuggled);
    let mut added = x0x::groups::GroupMember::new_member(stage.joiner_hex.clone(), None, None, 0);
    added.role = x0x::groups::GroupRole::Member;
    added.state = x0x::groups::GroupMemberState::Active;
    if let NamedGroupMetadataEvent::MemberAdded {
        certificate_b64: Some(b64),
        ..
    } = &stage.member_added
    {
        use base64::Engine as _;
        if let Ok(bytes) = BASE64.decode(b64) {
            if let Ok(cert) = bincode::deserialize::<x0x::identity::AgentCertificate>(&bytes) {
                added.certificate = Some(cert);
            }
        }
    }
    terminal_roster.insert(stage.joiner_hex.clone(), added);

    let result = r6c_targeted_refusal(&stage, smuggled_link, &terminal_roster).await?;
    assert!(
        !result.accepted,
        "#458 r6c: the last-admin INVARIANT FAMILY refuses here (per-link fold invariant + terminal committer-admin; see the docstring's pinning limitation) — every other check passes by construction"
    );
    {
        let groups = stage.joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("group");
        assert!(
            !info.has_active_member(&stage.joiner_hex),
            "joiner stays pending"
        );
    }
    let row = diagnostics_row(stage.joiner_state.as_ref(), &stage.group_id).await;
    assert_eq!(
        row.counters.member_added_events_rejected_state_chain_gap, 1,
        "the refusal is recorded in /diagnostics/groups"
    );
    Ok(())
}

/// #458 r5e/r6c: a chain whose gap ADDS A CERTIFIED MEMBER is
/// unreconstructable (the projection carries only the cert digest, not the
/// cert bytes, so the reconstructed roster cannot re-derive the terminal
/// root) — the joiner must REFUSE and stay pending at the terminal
/// roster-root check. The mutated link, its projection digest, and the
/// re-signed terminal's roster all agree on ONE freshly issued filler
/// certificate; the terminal is chained on the mutated link with a fresh
/// owner attestation, so every other check (linkage, snapshot/meta
/// re-derivation, committer authority, the anchor CAS, per-link invariants)
/// PASSES — the only possible refusal is the reconstruction's cert-drop
/// mismatch. Documented consequence: for OwnerCertified/Home groups only
/// metadata-only gaps (renames etc.) adopt.
#[tokio::test]
async fn issue458r5_certified_member_in_gap_refused() -> Result<()> {
    let stage = r3_stage(0x84).await?;
    let real = stage.chain.first().cloned().expect("one link");
    let signer =
        AgentKeypair::from_bytes(&stage.authority_key_bytes.0, &stage.authority_key_bytes.1)?;

    // ONE filler certificate everything agrees on (link projection digest,
    // link signed root, terminal roster bytes).
    let filler_owner = UserKeypair::generate()?;
    let filler_agent = AgentKeypair::generate()?;
    let filler_cert = x0x::identity::AgentCertificate::issue_for_public_key(
        &filler_owner,
        filler_agent.public_key().as_bytes(),
        None,
    )?;
    let filler_digest = x0x::groups::owner_cert::certificate_digest_hex(&filler_cert);

    // The mutated link: base roster + the certified member (digest-only in
    // the projection, exactly what a retained snapshot carries).
    let mut churned = real.roster.clone();
    churned.insert(
        "cd".repeat(32),
        x0x::groups::state_commit::RosterMemberSnapshot {
            role: x0x::groups::GroupRole::Member,
            state: x0x::groups::GroupMemberState::Active,
            treekem_key_package_hash: None,
            certificate_digest: Some(filler_digest),
        },
    );
    let churned_commit = x0x::groups::GroupStateCommit::sign(
        real.commit.group_id.clone(),
        real.commit.revision,
        real.commit.prev_state_hash.clone(),
        x0x::groups::state_commit::roster_root_of_projection(&churned),
        real.commit.policy_hash.clone(),
        real.commit.public_meta_hash.clone(),
        real.commit.security_binding.clone(),
        false,
        real.commit.committed_at,
        &signer,
    )?;
    let churned_link = x0x::groups::state_commit::RetainedCommit {
        commit: churned_commit,
        roster: churned.clone(),
        meta: real.meta.clone(),
    };

    // Terminal roster: the churned roster WITH the filler cert BYTES (what
    // the honest authority's signed roster_root covers — the root includes
    // the digest) + the joiner with its committed cert. The joiner's
    // reconstruction materializes the filler member WITHOUT the cert
    // (digest-only) → the recomputed root drops the digest → mismatch.
    let mut terminal_roster = r6c_materialize(&churned);
    let mut certified_member = x0x::groups::GroupMember::new_member("cd".repeat(32), None, None, 0);
    certified_member.role = x0x::groups::GroupRole::Member;
    certified_member.state = x0x::groups::GroupMemberState::Active;
    certified_member.certificate = Some(filler_cert);
    terminal_roster.insert("cd".repeat(32), certified_member);
    let mut added = x0x::groups::GroupMember::new_member(stage.joiner_hex.clone(), None, None, 0);
    added.role = x0x::groups::GroupRole::Member;
    added.state = x0x::groups::GroupMemberState::Active;
    if let NamedGroupMetadataEvent::MemberAdded {
        certificate_b64: Some(b64),
        ..
    } = &stage.member_added
    {
        use base64::Engine as _;
        if let Ok(bytes) = BASE64.decode(b64) {
            if let Ok(cert) = bincode::deserialize::<x0x::identity::AgentCertificate>(&bytes) {
                added.certificate = Some(cert);
            }
        }
    }
    terminal_roster.insert(stage.joiner_hex.clone(), added);

    let result = r6c_targeted_refusal(&stage, churned_link, &terminal_roster).await?;
    assert!(
        !result.accepted,
        "#458 r6c: only the CERT-RECONSTRUCTION mismatch may refuse here — every other check passes by construction"
    );
    {
        let groups = stage.joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("group");
        assert!(
            !info.has_active_member(&stage.joiner_hex),
            "joiner stays pending"
        );
    }
    let row = diagnostics_row(stage.joiner_state.as_ref(), &stage.group_id).await;
    assert_eq!(
        row.counters.member_added_events_rejected_state_chain_gap, 1,
        "the refusal is recorded in /diagnostics/groups"
    );
    Ok(())
}

// ── Review round 6b — tier 2 (no owner axis) ─────────────────────────────

/// #458 r6b item 1: an ORDINARY (invite-only, no owner axis) group with an
/// honest metadata-only gap DOES adopt through the production apply path —
/// the tier-2 fallback. #458 was reproduced on exactly these groups (LAN
/// P4 rev-0 joiner vs rev-2 commit), so refusing them would re-open the
/// wedge. No attestation is served (none exists for tier 2); the
/// reconstruction alone decides.
#[tokio::test]
async fn issue458r6b_tier2_ordinary_group_adopts_across_gap() -> Result<()> {
    let stage = issue458_stage_with_policy(0xC1, true, invite_only_policy).await?;
    let (joiner_state, _keep) = joiner_state_for(&stage).await?;
    joiner_state
        .named_groups
        .write()
        .await
        .insert(stage.group_id.clone(), stage.base_info.clone());

    let chain = stage_intervening_chain(&stage, stage.base_info.state_revision).await;
    assert!(!chain.is_empty(), "authority retains the gap link");
    // Tier 2: NO head attestation inserted — the anchor is skipped.
    let key = join_result_key(&stage.group_id, &stage.joiner_hex);
    joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(key.clone(), chain);
    let actor = crate::server::parse_agent_id_hex(&hex::encode(
        stage.authority.agent.agent_id().as_bytes(),
    ))
    .expect("actor");
    let result = apply_named_group_metadata_event(
        &joiner_state,
        stage.member_added.clone(),
        actor,
        true,
        None,
    )
    .await;
    assert!(
        result.accepted,
        "#458 r6b: an ordinary group MUST adopt across an honest metadata-only gap (tier 2)"
    );
    let terminal_hash = match &stage.member_added {
        NamedGroupMetadataEvent::MemberAdded {
            commit: Some(commit),
            ..
        } => commit.state_hash.clone(),
        _ => panic!("commit"),
    };
    {
        let groups = joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("group");
        assert!(
            info.has_active_member(&stage.joiner_hex),
            "the joiner is seated via tier-2 adoption"
        );
        assert_eq!(
            info.state_hash, terminal_hash,
            "#458 r6b: tier-2 adoption is full-hash-equal too"
        );
        assert!(info.state_hash_is_current(), "hash == content");
    }
    Ok(())
}

/// #458 r6b item 1 (negative): the r4 converged-view removed-admin fork on
/// an ORDINARY group is rejected at the PRE-ADOPTION actor gate (A is not
/// an admin in the joiner's converged current roster) BEFORE the tier-2
/// reconstruction runs. The reconstruction's linkage would also refuse
/// (the fork chains from the stale BASE hash), but this test does NOT pin
/// that inner refusal — see the actor-gate NOTE at the apply call below.
#[tokio::test]
async fn issue458r6b_tier2_removed_admin_fork_rejected() -> Result<()> {
    let stage = issue458_stage_with_policy(0xC2, false, invite_only_policy).await?;
    let (joiner_state, _keep) = joiner_state_for(&stage).await?;
    let attacker = AgentKeypair::generate()?;
    let attacker_hex = hex::encode(attacker.agent_id().as_bytes());

    let mut stub = stage.base_info.clone();
    stub.add_member(
        attacker_hex.clone(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    stub.recompute_state_hash();
    joiner_state
        .named_groups
        .write()
        .await
        .insert(stage.group_id.clone(), stub.clone());

    // Canonical advance (observed by the joiner): the authority removes A.
    let signer =
        AgentKeypair::from_bytes(&stage.authority_key_bytes.0, &stage.authority_key_bytes.1)?;
    let mut canonical = stub.clone();
    canonical.remove_member(&attacker_hex, None);
    let removal = x0x::groups::GroupStateCommit::sign(
        canonical.stable_group_id().to_string(),
        canonical.state_revision + 1,
        Some(canonical.state_hash.clone()),
        x0x::groups::compute_roster_root(&canonical.members_v2),
        x0x::groups::compute_policy_hash(&canonical.policy),
        x0x::groups::compute_public_meta_hash(&canonical.public_meta()),
        canonical.security_binding.clone(),
        false,
        canonical.state_revision + 1,
        &signer,
    )?;
    canonical.state_revision = removal.revision;
    canonical.prev_state_hash = removal.prev_state_hash.clone();
    canonical.state_hash = removal.state_hash.clone();
    *joiner_state
        .named_groups
        .write()
        .await
        .get_mut(&stage.group_id)
        .unwrap() = canonical;

    // A's fork: a rev-(base+1) link retaining its seat (chained from the
    // BASE, now stale against the joiner's canonical view).
    let fork_roster = x0x::groups::state_commit::roster_projection(&stub.members_v2);
    let fork_commit = x0x::groups::GroupStateCommit::sign(
        stub.stable_group_id().to_string(),
        stub.state_revision + 1,
        Some(stub.state_hash.clone()),
        x0x::groups::state_commit::roster_root_of_projection(&fork_roster),
        x0x::groups::compute_policy_hash(&stub.policy),
        x0x::groups::compute_public_meta_hash(&stub.public_meta()),
        stub.security_binding.clone(),
        false,
        stub.state_revision + 1,
        &attacker,
    )?;
    let fork_link = x0x::groups::state_commit::RetainedCommit {
        commit: fork_commit,
        roster: fork_roster,
        meta: Some(stub.public_meta()),
    };
    // Terminal: the staged MemberAdded (rev base+2... the stage's terminal
    // is base+1; the fork link already occupies base+1, so use the staged
    // event — the arm's admin gate refuses A first).
    let mut fork_event = stage.member_added.clone();
    if let NamedGroupMetadataEvent::MemberAdded { actor, .. } = &mut fork_event {
        *actor = attacker_hex.clone();
    }
    let attacker_id = attacker.agent_id();
    let key = join_result_key(&stage.group_id, &stage.joiner_hex);
    joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(key, vec![fork_link]);
    // NOTE (r7 item 7.9): the refusal here fires at the PRE-ADOPTION actor
    // gate (A is not an admin in the joiner's converged current roster) —
    // not inside the tier-2 reconstruction. That is acceptable: the fold
    // checks are tier-independent and would also refuse (the fork chains
    // from the BASE hash, stale against the canonical head).
    let result =
        apply_named_group_metadata_event(&joiner_state, fork_event, attacker_id, true, None).await;
    assert!(
        !result.accepted,
        "#458 r6b: the removed-admin fork is rejected on ordinary groups too"
    );
    {
        let groups = joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("group");
        assert!(
            !info.has_active_member(&stage.joiner_hex),
            "the fork must not seat the joiner"
        );
        assert!(
            !info.has_active_member(&attacker_hex),
            "the canonical removal of A stays applied"
        );
    }
    Ok(())
}
