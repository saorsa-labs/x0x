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
    group_id: String,
    base_info: x0x::groups::GroupInfo,
    member_added: NamedGroupMetadataEvent,
    /// Joiner keypair BYTES — `AgentKeypair` is not `Clone`, so the joiner
    /// side rebuilds the same identity from serialized bytes.
    joiner_key_bytes: (Vec<u8>, Vec<u8>),
    joiner_hex: String,
}

async fn issue458_stage(group_byte: u8, rename_first: bool) -> Result<Issue458Stage> {
    let (authority, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = format!("{group_byte:02x}").repeat(32);
    let authority_hex = hex::encode(authority.agent.agent_id().as_bytes());
    let invite_secret = format!("issue458-{group_byte:02x}-secret");
    let base_info = insert_owner_group(
        authority.as_ref(),
        &group_id,
        owner_certified_policy(&owner_kp),
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
        group_id,
        base_info,
        member_added,
        joiner_key_bytes: joiner.to_bytes(),
        joiner_hex,
    })
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
    {
        let groups = joiner_state.named_groups.read().await;
        let jinfo = groups.get(&stage.group_id).expect("joiner group");
        assert!(
            jinfo.has_active_member(&stage.joiner_hex),
            "#458: adopted commit must seat the joiner"
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
