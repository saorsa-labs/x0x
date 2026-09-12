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

#[derive(Clone, Copy)]
enum BlobDiagnosticRole {
    Owner,
    Joiner,
}

// All values are independent per-agent lifetime totals. No target digest,
// observation window, coherent snapshot, pending count or causal inference.
fn format_blob_diagnostics(
    role: BlobDiagnosticRole,
    stats: &crate::announce_blob::AnnounceBlobCacheStats,
) -> String {
    let role = match role {
        BlobDiagnosticRole::Owner => "owner",
        BlobDiagnosticRole::Joiner => "joiner",
    };
    let fields = [
        ("blob_cache_hits", stats.blob_cache_hits),
        ("blob_cache_misses", stats.blob_cache_misses),
        ("blob_fetches_ok", stats.blob_fetches_ok),
        ("blob_fetches_failed", stats.blob_fetches_failed),
        ("fetches_spawned", stats.diagnostics.fetches_spawned),
        (
            "terminal_both_carriers_failed",
            stats.diagnostics.terminal_both_carriers_failed,
        ),
        (
            "terminal_deadline_elapsed",
            stats.diagnostics.terminal_deadline_elapsed,
        ),
        (
            "terminal_subscription_closed",
            stats.diagnostics.terminal_subscription_closed,
        ),
        (
            "terminal_verifier_error",
            stats.diagnostics.terminal_verifier_error,
        ),
        ("responses_seen", stats.diagnostics.responses_seen),
        (
            "responses_skipped_malformed",
            stats.diagnostics.responses_skipped_malformed,
        ),
        (
            "responses_skipped_mismatched_digest",
            stats.diagnostics.responses_skipped_mismatched_digest,
        ),
        (
            "verified_requests_decoded",
            stats.diagnostics.verified_requests_decoded,
        ),
        ("unknown_digest", stats.diagnostics.unknown_digest),
        ("pair_available", stats.diagnostics.pair_available),
        ("coalesced_dropped", stats.diagnostics.coalesced_dropped),
        (
            "response_publish_ok_local",
            stats.diagnostics.response_publish_ok_local,
        ),
        (
            "publish_failed_local",
            stats.diagnostics.publish_failed_local,
        ),
    ];
    let mut line = String::from(
        "counters_are_independent_relaxed_no_snapshot_pending_not_exact scope=per_agent_lifetime_no_digest_window_attempt_attribution",
    );
    for (name, value) in fields {
        line.push_str(&format!(" {role}_{name}={value}"));
    }
    line
}

fn emit_joiner_blob_diagnostics(joiner: &Agent) {
    eprintln!(
        "DIAG cert-resolution-blob {}",
        format_blob_diagnostics(
            BlobDiagnosticRole::Joiner,
            &joiner.announce_blob_cache.snapshot()
        )
    );
}

/// Emit a bounded, privacy-minimal snapshot when a certificate wait expires.
///
/// The cache uses `try_read` so a diagnostic cannot extend or mask the wait.
/// Aggregate blob counters describe the cache process as a whole; they are
/// not attributed to this joiner.
fn emit_certificate_resolution_diagnostics(state: &AppState, joiner_id: x0x::identity::AgentId) {
    let cache = state.agent.identity_discovery_cache();
    let (
        cache_busy,
        entry_present,
        digest_present,
        cert_present,
        digest_matches_cert,
        cert_binds_joiner,
    ) = match cache.try_read() {
        Ok(cache) => match cache.get(&joiner_id) {
            Some(entry) => {
                let cert = entry.agent_certificate.as_ref();
                let digest = entry.cert_digest;
                let digest_matches_cert = digest.zip(cert).is_some_and(|(digest, cert)| {
                    digest == crate::announce_v3::cert_digest(&entry.user_id, &Some(cert.clone()))
                });
                let cert_binds_joiner = cert
                    .and_then(|cert| cert.agent_id().ok())
                    .is_some_and(|agent_id| agent_id == joiner_id);
                (
                    false,
                    true,
                    digest.is_some(),
                    cert.is_some(),
                    digest_matches_cert,
                    cert_binds_joiner,
                )
            }
            None => (false, false, false, false, false, false),
        },
        Err(_) => (true, false, false, false, false, false),
    };
    let blob_stats = state.agent.announce_blob_cache.snapshot();
    eprintln!(
        concat!(
            "DIAG cert-resolution-state cache_busy={} entry_present={} ",
            "digest_present={} cert_present={} digest_matches_cert={} ",
            "cert_binds_joiner={} blob_cache_hits={} blob_cache_misses={} ",
            "blob_fetches_ok={} blob_fetches_failed={} {}"
        ),
        cache_busy,
        entry_present,
        digest_present,
        cert_present,
        digest_matches_cert,
        cert_binds_joiner,
        blob_stats.blob_cache_hits,
        blob_stats.blob_cache_misses,
        blob_stats.blob_fetches_ok,
        blob_stats.blob_fetches_failed,
        format_blob_diagnostics(BlobDiagnosticRole::Owner, &blob_stats),
    );
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
        state.groups_config.mandate_grace_days,
    );
    snapshot
        .groups
        .into_iter()
        .find(|g| g.group_id == group_id)
        .unwrap_or_else(|| panic!("diagnostics row for {group_id}"))
}

/// Bounded-poll variant of [`diagnostics_row`] for counter assertions:
/// the diagnostics bookkeeping lands asynchronously relative to the roster
/// state these tests observe through other paths, so an immediate read can
/// legitimately see a stale snapshot (observed on a CI host:
/// `member_joined_events_applied == 0` right after the roster poll saw the
/// active member). Poll until the counter reaches `at_least` or the bound
/// expires, and return the final row either way.
async fn diagnostics_counter_at_least(
    state: &AppState,
    group_id: &str,
    at_least: u64,
    what: &str,
) -> crate::groups::diagnostics::GroupDiagnostic {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let row = diagnostics_row(state, group_id).await;
        if row.counters.member_joined_events_applied >= at_least {
            return row;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "diagnostics counter {what} never reached {at_least} (last: {})",
            row.counters.member_joined_events_applied
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
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

    // Mint the invite through the SINGLE mint authority exactly like the
    // route (#469 A1b): signed v4 assembly + owner countersignature from
    // the PRE-JOIN authority info (the founder-only revision-0 base the
    // joiner stubs from), with the one-time secret recorded so the
    // authority could consume the joiner's volley.
    let mut base_info = stage.base_info.clone();
    base_info.recompute_state_hash();
    let (invite, invite_link) = assemble_signed_v4_invite(&stage.authority, &base_info, 3600, None)
        .expect("mint signed v4 invite");
    base_info.record_issued_invite_v2(
        invite.invite_secret.clone(),
        invite.created_at,
        invite.expires_at,
        x0x::groups::GroupRole::Member,
        None,
        x0x::groups::InviteOrigin::Explicit,
        None,
    );

    // JOINER side: owned install under the SAME owner (self-issued agent
    // cert — the certified second device), no group state yet.
    let jdir = tempfile::tempdir()?;
    // r3: the stage's authority owner seed — the certified second device
    // must chain to the SAME owner as the group's admission policy.
    let owner_seed = [0xF3u8; 32];
    // #469 A3: an OwnerCertified invite is joined in HOME mode with the
    // admission owner pinned — the typed gate precedes the cert checks.
    let owner_pin = hex::encode(UserKeypair::from_seed(&owner_seed)?.user_id().as_bytes());
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
            mode: Some("home".to_string()),
            expected_owner_user_id: Some(owner_pin.clone()),
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
            mode: Some("home".to_string()),
            expected_owner_user_id: Some(owner_pin),
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
            owner_mandate: None,
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

/// Restart readiness barrier (#447 CI-flake follow-up): after an owner
/// restart, `is_connected` proves only the QUIC transport. The single
/// certified announce that follows needs gossip pubsub (announce publish,
/// one-shot 5 s blob fetch with no retry) already routing between the
/// peers. Prove delivery end-to-end in BOTH directions via the PUBLIC
/// agent APIs: both sides subscribe to the announce-blob topic, publish a
/// nonce-tagged probe, and each side awaits receipt of the REMOTE probe.
/// The probes are inert for production: the blob responder ignores any
/// payload lacking the `ANNOUNCE_BLOB_REQUEST_DOMAIN` prefix
/// (`spawn_blob_responder`), and announce traffic never matches a probe
/// nonce.
async fn await_restart_gossip_ready(owner: &Agent, joiner: &Agent) -> Result<()> {
    let started = std::time::Instant::now();
    let topic = crate::announce_blob::ANNOUNCE_BLOB_TOPIC;
    let mut owner_sub = owner.subscribe(topic).await?;
    let mut joiner_sub = joiner.subscribe(topic).await?;
    restart_readiness_diag("subscriptions_ready", started);
    // #510: sample the fanout surface both publishes read, at barrier entry
    // and then on the same 1 s cadence as the barrier's own rounds, so a
    // surface that EMPTIES mid-barrier is distinguishable from one that was
    // already empty at entry. Observational only — it never gates, never
    // extends the 20 s deadline, and is aborted the moment the barrier ends.
    let surface_sampler = match (owner.network(), joiner.network()) {
        (Some(owner_net), Some(joiner_net)) => {
            let owner_net = Arc::clone(owner_net);
            let joiner_net = Arc::clone(joiner_net);
            let joiner_peer = ant_quic::PeerId(joiner.machine_id().0);
            let owner_peer = ant_quic::PeerId(owner.machine_id().0);
            Some(tokio::spawn(async move {
                let mut round = 0u32;
                loop {
                    let owner_surface = restart_peer_surface(&owner_net, &joiner_peer).await;
                    let joiner_surface = restart_peer_surface(&joiner_net, &owner_peer).await;
                    eprintln!(
                        "DIAG hs_f2_restart phase=barrier_surface elapsed_ms={} round={round} \
                         owner[{owner_surface}] joiner[{joiner_surface}]",
                        started.elapsed().as_millis()
                    );
                    round = round.saturating_add(1);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }))
        }
        _ => None,
    };
    // #510: publish WITH fanout observation via the existing PUBLIC Agent API.
    // Fanout = attempted eager-peer opportunity, never confirmed delivery.
    let (result, diag) = await_restart_gossip_ready_with(
        async |probe| {
            owner
                .publish_with_fanout(topic, probe)
                .await
                .map_err(anyhow::Error::from)
        },
        async |probe| {
            joiner
                .publish_with_fanout(topic, probe)
                .await
                .map_err(anyhow::Error::from)
        },
        async || {
            owner_sub
                .recv()
                .await
                .map(|message| message.payload.to_vec())
        },
        async || {
            joiner_sub
                .recv()
                .await
                .map(|message| message.payload.to_vec())
        },
    )
    .await;
    if let Some(sampler) = surface_sampler {
        sampler.abort();
    }
    if result.is_err() {
        // #510: connectivity scalars are OBSERVATIONAL and must never extend
        // the helper past its single absolute 20 s deadline. Use a zero-budget
        // try-style probe: if the answer isn't immediately available, record
        // UNKNOWN rather than a measured negative.
        let joiner_peer = ant_quic::PeerId(joiner.machine_id().0);
        let owner_peer = ant_quic::PeerId(owner.machine_id().0);
        // Zero-budget observational probe: only report what is immediately
        // available without extending past the absolute 20 s deadline. An
        // unavailable probe is UNKNOWN, never a measured negative.
        let connectivity: Option<String> = {
            let fut = async {
                match (owner.network(), joiner.network()) {
                    (Some(on), Some(jn)) => {
                        let oc = on.is_connected(&joiner_peer).await;
                        let jc = jn.is_connected(&owner_peer).await;
                        format!("connected={}/{}", u8::from(oc), u8::from(jc))
                    }
                    _ => "no_network".to_string(),
                }
            };
            // Yield once; if the answer needs awaiting (network lock held),
            // report UNKNOWN rather than blocking past the deadline.
            match futures::poll!(Box::pin(fut)) {
                std::task::Poll::Ready(desc) => Some(desc),
                std::task::Poll::Pending => None,
            }
        };
        eprintln!(
            "DIAG hs_f2_restart phase=fanout_snapshot \\
             owner_attempts={} owner_last_fanout={:?} owner_ever_nonzero={} \\
             owner_remote_seen={} joiner_attempts={} joiner_last_fanout={:?} \\
             joiner_ever_nonzero={} joiner_remote_seen={} \\
             connectivity={} \\
             (fanout=attempted_eager_opportunity_not_delivery \\
              connectivity=unknown_if_probe_unavailable)",
            diag.attempts[0],
            diag.last_fanout[0],
            diag.ever_nonzero_fanout[0],
            diag.remote_seen[0],
            diag.attempts[1],
            diag.last_fanout[1],
            diag.ever_nonzero_fanout[1],
            diag.remote_seen[1],
            connectivity.as_deref().unwrap_or("unavailable"),
        );
    }
    result
}

fn restart_readiness_diag(phase: &str, started: std::time::Instant) {
    eprintln!(
        "DIAG hs_f2_restart phase={phase} elapsed_ms={}",
        started.elapsed().as_millis()
    );
}

/// #510: the two peer surfaces that disagree after an owner restart.
///
/// `is_connected` (`network.rs` `NetworkNode::is_connected`) is raw ant-quic
/// transport truth. The publish path the certified announce depends on reads
/// a STRICTER surface — `connected_peers()` filtered by the #206 plane gate,
/// i.e. `gossip_plane_peers()` — which is what `publish_with_fanout` counts.
/// A barrier gating on the former can clear while the fanout surface is
/// empty; that mismatch is why #510 presents as a mystery 20 s timeout
/// instead of an assertion.
struct RestartPeerSurface {
    transport_connected: bool,
    connected_len: usize,
    plane_len: usize,
    counterpart_in_connected: bool,
    counterpart_in_plane: bool,
    admission: crate::network::PeerAdmission,
}

impl std::fmt::Display for RestartPeerSurface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "is_connected={} connected_peers={} plane_peers={} \
             counterpart_connected={} counterpart_plane={} admission={:?}",
            u8::from(self.transport_connected),
            self.connected_len,
            self.plane_len,
            u8::from(self.counterpart_in_connected),
            u8::from(self.counterpart_in_plane),
            self.admission,
        )
    }
}

async fn restart_peer_surface(
    net: &crate::network::NetworkNode,
    counterpart: &ant_quic::PeerId,
) -> RestartPeerSurface {
    let connected = net.connected_peers().await;
    let plane = net.gossip_plane_peers().await;
    RestartPeerSurface {
        transport_connected: net.is_connected(counterpart).await,
        connected_len: connected.len(),
        plane_len: plane.len(),
        counterpart_in_connected: connected.contains(counterpart),
        counterpart_in_plane: plane.contains(counterpart),
        admission: net.peer_admission(counterpart).await,
    }
}

/// #510: record every ant-quic peer-lifecycle transition the RESTARTED owner
/// observes (`Established` / `Replaced` / `Closed` with its reason). This is
/// the line that decides between "the reconnect was never durable" and "it
/// was torn down mid-barrier" — both product defects, but different ones
/// (the #278 half-open/zombie-connection lineage).
fn spawn_restart_lifecycle_diag(
    mut events: tokio::sync::broadcast::Receiver<(ant_quic::PeerId, ant_quic::PeerLifecycleEvent)>,
    watched: ant_quic::PeerId,
    started: std::time::Instant,
    side: &'static str,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok((peer, event)) => {
                    let scope = if peer == watched { "joiner" } else { "other" };
                    eprintln!(
                        "DIAG hs_f2_restart phase={side}_lifecycle elapsed_ms={} \
                         peer={scope} event={event:?}",
                        started.elapsed().as_millis()
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    eprintln!(
                        "DIAG hs_f2_restart phase=owner_lifecycle_lagged elapsed_ms={} \
                         skipped={skipped}",
                        started.elapsed().as_millis()
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

fn restart_readiness_failure_diag(
    phase: &str,
    started: std::time::Instant,
    owner_last: &str,
    joiner_last: &str,
) {
    eprintln!(
        "DIAG hs_f2_restart phase={phase} elapsed_ms={} \
         owner_expected=joiner_probe owner_last={owner_last} \
         joiner_expected=owner_probe joiner_last={joiner_last}",
        started.elapsed().as_millis()
    );
}

/// #510 pure fanout diagnostics (closed scalars; fanout is ATTEMPTED
/// eager-peer opportunity, never confirmed delivery).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct DirectionalFanoutDiagnostics {
    attempts: [u64; 2],
    /// None = unobserved (publish failed or never resolved); Some(n) = the
    /// attempted eager-peer count from the most recent successful publish.
    last_fanout: [Option<u32>; 2],
    ever_nonzero_fanout: [bool; 2],
    remote_seen: [bool; 2],
}

// The real-agent wrapper and deterministic delayed-delivery regressions share
// this entire readiness loop; the tests replace only publication/reception IO.
async fn await_restart_gossip_ready_with(
    mut owner_publish: impl AsyncFnMut(Vec<u8>) -> Result<u32>,
    mut joiner_publish: impl AsyncFnMut(Vec<u8>) -> Result<u32>,
    mut owner_receive: impl AsyncFnMut() -> Option<Vec<u8>>,
    mut joiner_receive: impl AsyncFnMut() -> Option<Vec<u8>>,
) -> (Result<()>, DirectionalFanoutDiagnostics) {
    let mut diag = DirectionalFanoutDiagnostics::default();
    let started = std::time::Instant::now();
    use std::sync::atomic::{AtomicU64, Ordering};
    static PROBE_SEQ: AtomicU64 = AtomicU64::new(0);
    let base = PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut owner_last = "none";
    let mut joiner_last = "none";

    // Fresh retries avoid epidemic dedupe, but delivery can take longer than
    // one retry interval. Accept exact probes issued in THIS invocation in
    // their expected direction and retain each observation across rounds.
    let result = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let mut round = 0u64;
        let mut owner_probes = std::collections::HashSet::new();
        let mut joiner_probes = std::collections::HashSet::new();
        let mut owner_got = false;
        let mut joiner_got = false;
        let mut owner_publish_reported = false;
        let mut joiner_publish_reported = false;
        let mut owner_remote_reported = false;
        let mut joiner_remote_reported = false;
        loop {
            let owner_probe =
                format!("hs-f2/restart-gossip-probe/{base}.{round}/owner").into_bytes();
            let joiner_probe =
                format!("hs-f2/restart-gossip-probe/{base}.{round}/joiner").into_bytes();
            owner_probes.insert(owner_probe.clone());
            joiner_probes.insert(joiner_probe.clone());
            // #510: record the ATTEMPT before awaiting; if the publish
            // fails or never resolves, attempts is still truthful.
            diag.attempts[0] += 1;
            match owner_publish(owner_probe).await {
                Ok(fanout) => {
                    diag.last_fanout[0] = Some(fanout);
                    if fanout > 0 {
                        diag.ever_nonzero_fanout[0] = true;
                    }
                }
                Err(error) => {
                    restart_readiness_failure_diag(
                        "owner_publish_error",
                        started,
                        owner_last,
                        joiner_last,
                    );
                    return Err(error);
                }
            }
            if !owner_publish_reported {
                restart_readiness_diag("owner_probe_published", started);
                owner_publish_reported = true;
            }
            diag.attempts[1] += 1;
            match joiner_publish(joiner_probe).await {
                Ok(fanout) => {
                    diag.last_fanout[1] = Some(fanout);
                    if fanout > 0 {
                        diag.ever_nonzero_fanout[1] = true;
                    }
                }
                Err(error) => {
                    restart_readiness_failure_diag(
                        "joiner_publish_error",
                        started,
                        owner_last,
                        joiner_last,
                    );
                    return Err(error);
                }
            }
            if !joiner_publish_reported {
                restart_readiness_diag("joiner_probe_published", started);
                joiner_publish_reported = true;
            }
            let quiet = tokio::time::sleep(std::time::Duration::from_secs(1));
            tokio::pin!(quiet);
            while !(owner_got && joiner_got) {
                tokio::select! {
                    _ = &mut quiet => break,
                    message = owner_receive() => {
                        let Some(message) = message else {
                            owner_last = "subscription_closed";
                            restart_readiness_failure_diag(
                                "owner_receive_error",
                                started,
                                owner_last,
                                joiner_last,
                            );
                            anyhow::bail!("owner gossip subscription closed");
                        };
                        if joiner_probes.contains(&message) {
                            owner_got = true;
                            diag.remote_seen[0] = true;
                            owner_last = "expected_remote_probe";
                            if !owner_remote_reported {
                                restart_readiness_diag("owner_received_remote_probe", started);
                                owner_remote_reported = true;
                            }
                        } else if !owner_got {
                            owner_last = if owner_probes.contains(&message) {
                                "local_probe"
                            } else {
                                "unrelated_payload"
                            };
                        }
                    }
                    message = joiner_receive() => {
                        let Some(message) = message else {
                            joiner_last = "subscription_closed";
                            restart_readiness_failure_diag(
                                "joiner_receive_error",
                                started,
                                owner_last,
                                joiner_last,
                            );
                            anyhow::bail!("joiner gossip subscription closed");
                        };
                        if owner_probes.contains(&message) {
                            joiner_got = true;
                            diag.remote_seen[1] = true;
                            joiner_last = "expected_remote_probe";
                            if !joiner_remote_reported {
                                restart_readiness_diag("joiner_received_remote_probe", started);
                                joiner_remote_reported = true;
                            }
                        } else if !joiner_got {
                            joiner_last = if joiner_probes.contains(&message) {
                                "local_probe"
                            } else {
                                "unrelated_payload"
                            };
                        }
                    }
                }
            }
            if owner_got && joiner_got {
                restart_readiness_diag("ready", started);
                return Ok(());
            }
            round += 1;
        }
    })
    .await
    .map_err(|_| {
        restart_readiness_failure_diag("timeout", started, owner_last, joiner_last);
        anyhow::anyhow!(
            "gossip delivery between the restarted owner and the joiner \
             never became bidirectionally ready within 20 s \
             (owner_expected=joiner_probe owner_last={owner_last}; \
             joiner_expected=owner_probe joiner_last={joiner_last})"
        )
    })
    .and_then(|inner| inner);
    (result, diag)
}

/// #510 inert controls: fanout scalars NEVER satisfy or weaken the barrier —
/// bilateral zero fanout with local echoes fails at the 20 s deadline;
/// bilateral NONZERO fanout without remote probes also fails; asymmetric
/// fanout is recorded on the correct side; a delayed exact remote probe
/// still passes. All IO is in-memory mpsc; the paused clock advances only
/// through the loop's own sleeps — no network exists on this path. These
/// drive the SAME `_with` loop the real-agent wrapper uses.
async fn fanout_control_fixture(
    owner_fanout: u32,
    joiner_fanout: u32,
    owner_remote_delay_ms: Option<u64>,
    joiner_remote_delay_ms: Option<u64>,
    echo_local: bool,
) -> (Result<()>, DirectionalFanoutDiagnostics) {
    let (to_owner, mut owner_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    let (to_joiner, mut joiner_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    let result = await_restart_gossip_ready_with(
        {
            let echo = to_owner.clone();
            let remote = to_joiner.clone();
            async move |probe: Vec<u8>| {
                if echo_local {
                    let _ = echo.try_send(probe.clone());
                }
                if let Some(ms) = owner_remote_delay_ms {
                    let remote = remote.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                        let _ = remote.send(probe).await;
                    });
                }
                Ok(owner_fanout)
            }
        },
        {
            let echo = to_joiner.clone();
            let remote = to_owner.clone();
            async move |probe: Vec<u8>| {
                if echo_local {
                    let _ = echo.try_send(probe.clone());
                }
                if let Some(ms) = joiner_remote_delay_ms {
                    let remote = remote.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                        let _ = remote.send(probe).await;
                    });
                }
                Ok(joiner_fanout)
            }
        },
        async || owner_rx.recv().await,
        async || joiner_rx.recv().await,
    )
    .await;
    result
}

/// Bilateral ZERO fanout plus local echoes: still a 20 s failure.
#[tokio::test(start_paused = true)]
async fn fanout_control_zero_fanout_with_echoes_fails_at_deadline() {
    let started = tokio::time::Instant::now();
    let (result, diag) = fanout_control_fixture(0, 0, None, None, true).await;
    assert!(result.is_err(), "zero fanout must not satisfy the barrier");
    assert_eq!(started.elapsed(), std::time::Duration::from_secs(20));
    assert!(diag.ever_nonzero_fanout == [false, false]);
}

/// Bilateral NONZERO fanout with NO remote probe: still a 20 s failure —
/// attempted eager opportunity is never treated as delivery.
#[tokio::test(start_paused = true)]
async fn fanout_control_nonzero_fanout_without_remote_fails() {
    let started = tokio::time::Instant::now();
    let (result, diag) = fanout_control_fixture(3, 3, None, None, false).await;
    assert!(
        result.is_err(),
        "nonzero fanout without remote receipt must fail"
    );
    assert_eq!(started.elapsed(), std::time::Duration::from_secs(20));
    assert!(diag.ever_nonzero_fanout == [true, true]);
}

/// Asymmetric fanout recorded on the correct side; success stays
/// strictly bilateral-remote (pure diagnostics assertions).
#[tokio::test(start_paused = true)]
async fn fanout_control_asymmetric_recorded_and_still_fails() {
    let (result, diag) = fanout_control_fixture(5, 0, None, None, false).await;
    assert!(result.is_err());
    assert!(diag.attempts[0] >= 1);
    assert_eq!(diag.last_fanout[0], Some(5));
    assert_eq!(diag.ever_nonzero_fanout, [true, false]);
    assert_eq!(diag.remote_seen, [false, false]);
}

/// Delayed EXACT remote probes in both directions still pass through the
/// actual shared loop at 50 ms (within one round's receive window).
/// Cross-round retention (>1 s delivery) is exercised separately by the
/// existing delayed-out-of-phase controls at 1200/2200 ms.
#[tokio::test(start_paused = true)]
async fn fanout_control_delayed_exact_remote_passes() {
    let (result, diag) = fanout_control_fixture(1, 1, Some(50), Some(50), true).await;
    assert!(result.is_ok(), "delayed bilateral remote probes must pass");
    assert_eq!(diag.remote_seen, [true, true]);
}

/// #510 truthful-diagnostics control A: a FAILED first publish returns
/// immediately (existing error semantics preserved); attempts truthfully
/// records 1, and last_fanout is None (unobserved, NOT a measured zero).
#[tokio::test(start_paused = true)]
async fn fanout_control_failed_publish_attempts_one_fanout_none() {
    let (_to_owner, mut owner_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    let (_to_joiner, mut joiner_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    let (result, diag) = await_restart_gossip_ready_with(
        async |_| anyhow::bail!("injected first-publish failure"),
        async |_| Ok(0),
        async || owner_rx.recv().await,
        async || joiner_rx.recv().await,
    )
    .await;
    assert!(result.is_err(), "publish error must fail immediately");
    assert_eq!(
        diag.attempts[0], 1,
        "failed publish truthfully counted as attempt 1"
    );
    assert_eq!(
        diag.last_fanout[0], None,
        "unobserved fanout is None, not measured zero"
    );
    assert!(!diag.ever_nonzero_fanout[0]);
    assert_eq!(diag.remote_seen, [false, false], "no delivery occurred");
}

/// #510 truthful-diagnostics control B: one-way successful owner→joiner
/// traffic times out at 20 s; the receiving side's remote_seen is true,
/// the opposite is false — per-side, not bilateral override.
#[tokio::test(start_paused = true)]
async fn fanout_control_one_way_remote_seen_per_side() {
    let (_to_owner, mut owner_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    let (to_joiner, mut joiner_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    let (result, diag) = await_restart_gossip_ready_with(
        {
            let to_joiner = to_joiner.clone();
            async move |probe: Vec<u8>| {
                let _ = to_joiner.try_send(probe);
                Ok(2)
            }
        },
        async |_| Ok(0),
        async || owner_rx.recv().await,
        async || joiner_rx.recv().await,
    )
    .await;
    assert!(
        result.is_err(),
        "one-way delivery must fail at the 20 s deadline"
    );
    assert!(diag.attempts[0] >= 1);
    assert_eq!(
        diag.last_fanout[0],
        Some(2),
        "successful publish observed fanout"
    );
    assert!(diag.ever_nonzero_fanout[0]);
    assert!(diag.attempts[1] >= 1);
    assert_eq!(
        diag.last_fanout[1],
        Some(0),
        "zero-fanout publish is a measured Some(0)"
    );
    assert!(!diag.ever_nonzero_fanout[1]);
    assert!(
        diag.remote_seen[1],
        "joiner received owner probe: remote_seen[1] true"
    );
    assert!(
        !diag.remote_seen[0],
        "owner never received remote: remote_seen[0] false"
    );
}

/// #510 truthful-diagnostics control C: a PENDING first publish (never
/// resolves) still counts as attempt 1 with unobserved fanout at the 20 s
/// deadline.
#[tokio::test(start_paused = true)]
async fn fanout_control_pending_publish_attempts_one_fanout_none() {
    let (_to_owner, mut owner_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    let (_to_joiner, mut joiner_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    let (result, diag) = await_restart_gossip_ready_with(
        async |_| std::future::pending().await,
        async |_| Ok(0),
        async || owner_rx.recv().await,
        async || joiner_rx.recv().await,
    )
    .await;
    assert!(
        result.is_err(),
        "pending publish must hit the 20 s deadline"
    );
    assert_eq!(
        diag.attempts[0], 1,
        "pending publish truthfully counted as attempt 1"
    );
    assert_eq!(diag.last_fanout[0], None, "unresolved fanout is None");
}

async fn delayed_restart_probe(
    tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    delay_ms: Option<u64>,
    mut probe: Vec<u8>,
    wrong_nonce: bool,
) -> Result<u32> {
    if let Some(delay_ms) = delay_ms {
        let tx = tx.clone();
        if wrong_nonce {
            probe.push(b'!');
        }
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            let _ = tx.send(probe).await;
        });
    }
    Ok(0)
}

async fn restart_gossip_probe_fixture(
    owner_delay_ms: Option<u64>,
    joiner_delay_ms: Option<u64>,
    wrong_nonce: bool,
) -> (Result<()>, usize, usize) {
    let (to_owner, mut owner_rx) = tokio::sync::mpsc::channel(100);
    let (to_joiner, mut joiner_rx) = tokio::sync::mpsc::channel(100);
    let mut owner_received = 0;
    let mut joiner_received = 0;
    let (result, _diag) = await_restart_gossip_ready_with(
        async |probe| delayed_restart_probe(&to_joiner, owner_delay_ms, probe, wrong_nonce).await,
        async |probe| delayed_restart_probe(&to_owner, joiner_delay_ms, probe, false).await,
        async || {
            let message = owner_rx.recv().await;
            owner_received += usize::from(message.is_some());
            message
        },
        async || {
            let message = joiner_rx.recv().await;
            joiner_received += usize::from(message.is_some());
            message
        },
    )
    .await;
    (result, owner_received, joiner_received)
}

#[tokio::test(start_paused = true)]
async fn restart_gossip_ready_accepts_delayed_out_of_phase_probes() {
    // Both directions work, but their first deliveries cross different retry
    // boundaries. The old current-round-only oracle timed out after 20 s.
    let started = tokio::time::Instant::now();
    let (result, owner_received, joiner_received) =
        restart_gossip_probe_fixture(Some(1200), Some(2200), false).await;
    assert!(result.is_ok(), "delayed bidirectional delivery: {result:?}");
    assert!(owner_received > 0 && joiner_received > 0);
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
}

#[tokio::test(start_paused = true)]
async fn restart_gossip_ready_rejects_missing_return_direction() {
    let started = tokio::time::Instant::now();
    let (result, owner_received, joiner_received) =
        restart_gossip_probe_fixture(Some(200), None, false).await;
    let error = result.expect_err("one-way delivery must never satisfy readiness");
    assert!(
        error.to_string().contains(
            "owner_expected=joiner_probe owner_last=none; \
             joiner_expected=owner_probe joiner_last=expected_remote_probe"
        ),
        "missing-direction receipt: {error:#}"
    );
    assert_eq!(owner_received, 0);
    assert!(joiner_received > 0);
    assert_eq!(started.elapsed(), std::time::Duration::from_secs(20));
}

#[tokio::test(start_paused = true)]
async fn restart_gossip_ready_rejects_unissued_nonce() {
    let started = tokio::time::Instant::now();
    let (result, owner_received, joiner_received) =
        restart_gossip_probe_fixture(Some(200), Some(200), true).await;
    let error = result.expect_err("unissued probe must never satisfy readiness");
    assert!(
        error.to_string().contains(
            "owner_expected=joiner_probe owner_last=expected_remote_probe; \
             joiner_expected=owner_probe joiner_last=unrelated_payload"
        ),
        "wrong-probe receipt: {error:#}"
    );
    assert!(owner_received > 0 && joiner_received > 0);
    assert_eq!(started.elapsed(), std::time::Duration::from_secs(20));
}

#[tokio::test(start_paused = true)]
async fn restart_gossip_ready_preserves_subscription_close_failure() {
    let (result, _diag) = await_restart_gossip_ready_with(
        async |_| Ok(0),
        async |_| Ok(0),
        async || None,
        async || std::future::pending().await,
    )
    .await;

    assert_eq!(
        result
            .expect_err("closed subscription must remain an error")
            .to_string(),
        "owner gossip subscription closed"
    );
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
    // Hermetic plane (#337/#417 class, mirroring
    // `issue506_public_broadcast_control.rs`): `mdns_enabled` DEFAULTS TO TRUE
    // (`network.rs::default_mdns_enabled`), so without this the agents below are
    // mDNS-discoverable and auto-connectable by any co-located node — including
    // the other agents this test binary spawns concurrently. The `network_id` is
    // unique to this test AND this process, and is SHARED by the owner, the
    // joiner, and the owner's post-restart rebuild, so those three still gossip
    // with each other and with nothing else.
    //
    // This closes an isolation gap; it is NOT a proven root cause for the
    // observed CI timeout. Whether cross-test discovery actually contributed
    // there is unestablished, and a transport or gossip defect is not excluded.
    let network_id = format!(
        "hs-f2-restart-single-announce-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let loopback_cfg = move || x0x::network::NetworkConfig {
        bind_addr: Some(loopback_addr),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        mdns_enabled: false,
        network_id: Some(network_id.clone()),
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
    // Restart barrier: `Agent::drop` only aborts the two heartbeat handles
    // — it neither cancels the shutdown token nor drains the tracked
    // listeners, so shadowing `owner_agent` alone would keep the OLD
    // owner's network, PubSub and blob-responder tasks alive, sharing
    // identity and peer state with the replacement (the CI flake: the
    // joiner's single certified announce could be served by the leaked
    // old owner and its one-shot 5 s blob fetch had no retry). A real
    // daemon restart is clean: shut the old agent down, THEN rebuild.
    owner_agent.shutdown().await;
    drop(owner_agent);
    // #510: let the joiner's ant-quic finish unwinding the old connection's
    // CONNECTION_CLOSE before the rebuilt owner dials it again. Without this
    // settle the new handshake can arrive inside that window and be dropped as
    // a stale generation, so `connect_addr` returns Ok yet `connected_peers`
    // is 0 on the first barrier poll and stays 0 for the whole 20 s deadline
    // (observed on CI only; local reconnects take 123–155 ms). 300 ms is ~2×
    // the observed reconnect, far below the 10 s legacy grace and the 20 s
    // barrier, and the barrier below still gates strictly on
    // `gossip_plane_peers`, so a genuine never-connects failure still fails
    // at the same assertion.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let owner_agent = Arc::new(build_owner_agent().await?);
    owner_agent.join_network().await?;
    // Reconnect the restarted daemon to the joiner and let the mesh settle —
    // the restart is a NEW network endpoint (exactly the live shape).
    let owner_net = owner_agent
        .network()
        .expect("restarted owner network")
        .clone();
    let reconnect_started = std::time::Instant::now();
    let owner_peer = ant_quic::PeerId(owner_agent.machine_id().0);
    // #510: watch ant-quic's lifecycle stream on the RESTARTED owner from
    // BEFORE the dial, so a `Replaced`/`Closed` for the joiner — during the
    // reconnect or later inside the gossip barrier — is recorded with its
    // reason instead of vanishing.
    let _lifecycle_diag = owner_net.subscribe_all_peer_events().await.map(|events| {
        spawn_restart_lifecycle_diag(events, joiner_peer, reconnect_started, "owner")
    });
    owner_net.connect_addr(joiner_addr).await?;
    // #510: the old gate was `owner_net.is_connected(&joiner_peer)` — raw
    // ant-quic transport truth. The certified announce that follows publishes
    // through `gossip_plane_peers()` (`connected_peers()` + the #206 plane
    // gate), a STRICTER surface, so the old gate could clear while the fanout
    // surface was empty and the real failure only surfaced 20 s later as a
    // silent gossip timeout. Gate on the surface publish actually reads, on
    // BOTH sides. Same 20 s deadline, no retries (ADR-0025).
    let reconnect_deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut poll = 0u32;
    let (owner_surface, joiner_surface) = loop {
        let owner_surface = restart_peer_surface(&owner_net, &joiner_peer).await;
        let joiner_surface = restart_peer_surface(&joiner_net, &owner_peer).await;
        let ready = owner_surface.plane_len > 0 && joiner_surface.plane_len > 0;
        // Every poll is 100 ms; log the first, then once a second, plus the
        // decisive one, so a 20 s wait stays readable.
        if poll.is_multiple_of(10) || ready {
            eprintln!(
                "DIAG hs_f2_restart phase=reconnect_poll elapsed_ms={} poll={poll} \
                 owner[{owner_surface}] joiner[{joiner_surface}]",
                reconnect_started.elapsed().as_millis()
            );
        }
        if ready || std::time::Instant::now() >= reconnect_deadline {
            break (owner_surface, joiner_surface);
        }
        poll = poll.saturating_add(1);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    let reconnected = owner_surface.plane_len > 0 && joiner_surface.plane_len > 0;
    if !reconnected {
        restart_readiness_diag("reconnect_timeout", reconnect_started);
    }
    assert!(
        reconnected,
        "restarted owner and joiner must BOTH expose a non-empty gossip fanout \
         surface (gossip_plane_peers) before the certified announce — an empty \
         side makes publish fanout structurally zero (#510/#278): \
         owner[{owner_surface}] joiner[{joiner_surface}]"
    );
    restart_readiness_diag("reconnect_established", reconnect_started);
    // Readiness barrier replacing the old fixed 2 s settle: the QUIC
    // reconnect above proves TRANSPORT only — prove gossip pubsub routes
    // in BOTH directions before the one-shot certified announce depends
    // on it.
    await_restart_gossip_ready(&owner_agent, &joiner_agent).await?;
    // Evidence channel, subscribed before ANY announce activity on the
    // restarted owner: the verified-certificate broadcast fires the
    // instant a fetched announce blob is patched into the discovery
    // cache. Receipt below is the success condition.
    let mut cert_events = owner_agent.subscribe_verified_certificates();
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
    // Await the joiner's verified-certificate event — receipt IS the
    // success condition. The 45 s bound is a diagnostic guard only; if it
    // ever elapses, the cache loop below reports the full DIAG picture.
    let cert_event = tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            match cert_events.recv().await {
                Ok(event) if event.agent_id == joiner_id => break Some(event),
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                    eprintln!("DIAG verified-cert receiver lagged by {missed} events");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break None,
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        eprintln!("DIAG no verified-certificate event within 45 s of the single announce");
        None
    });
    if cert_event.is_none() {
        emit_certificate_resolution_diagnostics(owner_state.as_ref(), joiner_id);
        emit_joiner_blob_diagnostics(&joiner_agent);
    }
    assert!(
        cert_event.is_some_and(|event| event.agent_id == joiner_id),
        "#447: the single identity announce must land the joiner's verified \
         certificate event on the restarted owner"
    );
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
            emit_certificate_resolution_diagnostics(owner_state.as_ref(), joiner_id);
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
            mode: Some("home".to_string()),
            expected_owner_user_id: Some(hex::encode(owner_kp.user_id().as_bytes())),
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
    let owner_row = diagnostics_counter_at_least(
        owner_state.as_ref(),
        &group_id,
        1,
        "member_joined_events_applied (certified MemberJoined on the single-announce evidence)",
    )
    .await;
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
    // Hermetic plane (#337/#417 class, mirroring
    // `issue506_public_broadcast_control.rs`): `mdns_enabled` DEFAULTS TO TRUE
    // (`network.rs::default_mdns_enabled`), so without this the agents below are
    // mDNS-discoverable and auto-connectable by any co-located node — including
    // the other agents this test binary spawns concurrently. The `network_id` is
    // unique to this test AND this process, and is SHARED by the owner, the
    // joiner, and the owner's post-restart rebuild, so those three still gossip
    // with each other and with nothing else.
    //
    // This closes an isolation gap; it is NOT a proven root cause for the
    // observed CI timeout. Whether cross-test discovery actually contributed
    // there is unestablished, and a transport or gossip defect is not excluded.
    let network_id = format!(
        "hs-f2-real-home-provision-restart-join-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let loopback_cfg = move || x0x::network::NetworkConfig {
        bind_addr: Some(loopback_addr),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        mdns_enabled: false,
        network_id: Some(network_id.clone()),
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
    // Restart barrier (identical to the TreeKEM Home variant): `Agent::drop`
    // alone leaks the old owner's network/PubSub/blob-responder tasks into
    // the replacement — shut the old agent down first, THEN rebuild.
    owner_agent.shutdown().await;
    drop(owner_agent);
    // #510: same settle as the TreeKEM variant — let the joiner finish
    // unwinding the old connection before the rebuilt owner dials it.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let owner_agent = Arc::new(build_owner_agent().await?);
    owner_agent.join_network().await?;
    // #510 RCA instrumentation (mirrors the TreeKEM variant): watch BOTH
    // sides' ant-quic lifecycle streams from before the dial, and poll BOTH
    // sides' surfaces during the reconnect gate. The 2026-09-10 CI failure
    // showed the owner's transport connection dropping within ~1s of the
    // barrier while the joiner kept `counterpart_connected=1` for the whole
    // 20s window (a possible stale/joiner-side view — the #278 zombie
    // lineage). The owner-side `Closed { reason }` plus the joiner's
    // simultaneous belief that it is still connected is exactly the evidence
    // that distinguishes a genuine transport drop from a stale joiner view.
    let real_home_reconnect_started = std::time::Instant::now();
    let _real_home_owner_lifecycle = owner_agent
        .network()
        .expect("restarted owner network")
        .subscribe_all_peer_events()
        .await
        .map(|events| {
            spawn_restart_lifecycle_diag(
                events,
                joiner_peer,
                real_home_reconnect_started,
                "real_home_owner",
            )
        });
    let _real_home_joiner_lifecycle = joiner_agent
        .network()
        .expect("joiner network")
        .subscribe_all_peer_events()
        .await
        .map(|events| {
            spawn_restart_lifecycle_diag(
                events,
                ant_quic::PeerId(owner_agent.machine_id().0),
                real_home_reconnect_started,
                "real_home_joiner",
            )
        });
    owner_agent
        .network()
        .expect("restarted owner network")
        .connect_addr(joiner_addr)
        .await?;
    eprintln!(
        "DIAG hs_f2_restart phase=real_home_connect_returned elapsed_ms={}",
        real_home_reconnect_started.elapsed().as_millis()
    );
    deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut real_home_poll = 0u32;
    while std::time::Instant::now() < deadline {
        if real_home_poll.is_multiple_of(10) {
            let owner_surface = restart_peer_surface(
                owner_agent.network().expect("restarted owner network"),
                &joiner_peer,
            )
            .await;
            let joiner_surface = restart_peer_surface(
                joiner_agent.network().expect("joiner network"),
                &ant_quic::PeerId(owner_agent.machine_id().0),
            )
            .await;
            eprintln!(
                "DIAG hs_f2_restart phase=real_home_reconnect_poll elapsed_ms={} \
                 poll={real_home_poll} owner[{owner_surface}] joiner[{joiner_surface}]",
                real_home_reconnect_started.elapsed().as_millis()
            );
        }
        if owner_agent
            .network()
            .expect("restarted owner network")
            .is_connected(&joiner_peer)
            .await
        {
            break;
        }
        real_home_poll = real_home_poll.saturating_add(1);
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
    restart_readiness_diag(
        "real_home_reconnect_established",
        real_home_reconnect_started,
    );
    // Readiness barrier replacing the old fixed 2 s settle: prove gossip
    // pubsub routes BOTH directions before the one-shot certified announce.
    await_restart_gossip_ready(&owner_agent, &joiner_agent).await?;
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
        if std::time::Instant::now() >= evidence_deadline {
            emit_certificate_resolution_diagnostics(owner_state.as_ref(), joiner_id);
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
            mode: Some("home".to_string()),
            expected_owner_user_id: Some(hex::encode(owner_kp.user_id().as_bytes())),
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
    let owner_row = diagnostics_counter_at_least(
        owner_state.as_ref(),
        &home_id,
        1,
        "member_joined_events_applied (certified join from ONE announce)",
    )
    .await;
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
        owner_mandate: None,
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
        owner_mandate: None,
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
        owner_mandate: None,
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
        owner_mandate: None,
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

/// #458 r5e/r6c → #468/#469 design v5 D2 re-pin. ORIGINAL INTENT: a gap
/// that ADDS A CERTIFIED MEMBER was unreconstructable (the projection
/// carries only the cert digest, and the reconstruction used to drop it,
/// so the terminal roster root could not be re-derived) — the joiner
/// refused and stayed pending. D2 made the DIGEST the commitment
/// (`apply_reconstructed_roster` carries `certificate_digest` across the
/// gap; byte-bearing and digest-only members hash identically), so the
/// same shape is now intentionally ADOPTABLE: the filler seats
/// digest-only and the cert bytes hydrate later via the announce bridge.
/// This test keeps the original construction (mutated link + re-signed
/// terminal + fresh owner attestation, every other check passing by
/// construction) and pins the NEW outcome: adoption succeeds, the filler
/// is digest-seated without bytes, and no gap rejection is recorded.
#[tokio::test]
async fn issue458r5_certified_member_in_gap_adopts_digest_only() -> Result<()> {
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
            certificate_digest: Some(filler_digest.clone()),
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
        result.accepted,
        "#468/#469 D2: the digest IS the signed commitment — the reconstruction re-derives the terminal root with the filler digest-seated, so adoption succeeds"
    );
    {
        let groups = stage.joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("group");
        assert!(
            info.has_active_member(&stage.joiner_hex),
            "joiner is admitted across the digest-committed gap"
        );
        let filler = info
            .members_v2
            .get(&"cd".repeat(32))
            .expect("filler member adopted");
        assert_eq!(
            filler.certificate, None,
            "cert bytes are NOT recoverable from the projection — the seat is digest-only"
        );
        assert_eq!(
            filler.certificate_digest.as_deref(),
            Some(filler_digest.as_str()),
            "the projection's committed digest rides onto the adopted seat (hydration target)"
        );
    }
    let row = diagnostics_row(stage.joiner_state.as_ref(), &stage.group_id).await;
    assert_eq!(
        row.counters.member_added_events_rejected_state_chain_gap, 0,
        "a reconstructable digest-committed gap must NOT be counted as a refusal"
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

/// r4 (hs-FU-A round 4, original item 1a / addendum item 9): the
/// across-gap ADOPTION success path materializes the reconstructed
/// roster's seats DIGEST-ONLY — same construction as the r5 digest-only
/// adoption test, but with the filler's certificate ALREADY in the
/// joiner's discovered-certificate cache. The seat-time hydrate on the
/// adoption success arm must install the bytes BEFORE the caller
/// persists `next`, with NO bridge event (raw cache write; no bridge
/// worker runs in the test state).
#[tokio::test]
async fn issue458r4_adoption_hydrates_reconstructed_digest_only_seats() -> Result<()> {
    let stage = r3_stage(0x94).await?;
    let real = stage.chain.first().cloned().expect("one link");
    let signer =
        AgentKeypair::from_bytes(&stage.authority_key_bytes.0, &stage.authority_key_bytes.1)?;

    // ONE filler certificate everything agrees on (link projection
    // digest, link signed root, terminal roster bytes).
    let filler_owner = UserKeypair::generate()?;
    let filler_agent = AgentKeypair::generate()?;
    let filler_cert = x0x::identity::AgentCertificate::issue_for_public_key(
        &filler_owner,
        filler_agent.public_key().as_bytes(),
        None,
    )?;
    let filler_digest = x0x::groups::owner_cert::certificate_digest_hex(&filler_cert);

    // The mutated link: base roster + the certified member (digest-only
    // in the projection, exactly what a retained snapshot carries).
    let mut churned = real.roster.clone();
    churned.insert(
        "cd".repeat(32),
        x0x::groups::state_commit::RosterMemberSnapshot {
            role: x0x::groups::GroupRole::Member,
            state: x0x::groups::GroupMemberState::Active,
            treekem_key_package_hash: None,
            certificate_digest: Some(filler_digest.clone()),
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

    // Terminal roster: the churned roster WITH the filler cert BYTES +
    // the joiner with its committed cert (the honest authority's signed
    // root covers the digest either way — D2).
    let mut terminal_roster = r6c_materialize(&churned);
    let mut certified_member = x0x::groups::GroupMember::new_member("cd".repeat(32), None, None, 0);
    certified_member.role = x0x::groups::GroupRole::Member;
    certified_member.state = x0x::groups::GroupMemberState::Active;
    certified_member.certificate = Some(filler_cert.clone());
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

    // r4: PRE-POPULATE the joiner's discovered-certificate cache for the
    // filler's ROSTER seat — a raw map write that fires NO
    // verified-certificate event (the bridge can never see it).
    stage
        .joiner_state
        .agent
        .identity_discovery_cache()
        .write()
        .await
        .insert(
            x0x::identity::AgentId([0xCD; 32]),
            x0x::DiscoveredAgent {
                agent_id: x0x::identity::AgentId([0xCD; 32]),
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
                reachable_via: vec![],
                relay_candidates: vec![],
                cert_not_after: filler_cert.not_after(),
                agent_certificate: Some(filler_cert.clone()),
                agent_public_key: Vec::new(),
                cert_digest: None,
            },
        );

    let result = r6c_targeted_refusal(&stage, churned_link, &terminal_roster).await?;
    assert!(
        result.accepted,
        "the digest-committed gap adoption succeeds (r5 shape)"
    );
    {
        let groups = stage.joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("group");
        let filler = info
            .members_v2
            .get(&"cd".repeat(32))
            .expect("filler member adopted");
        assert_eq!(
            filler.certificate.as_ref(),
            Some(&filler_cert),
            "the adopted digest-only seat hydrated from the cache at adoption time — no bridge event"
        );
        assert_eq!(
            filler.certificate_digest.as_deref(),
            Some(filler_digest.as_str()),
            "hydration keeps the committed digest"
        );
    }
    // The hydrated bytes also reached the DURABLE record (the caller
    // persists `next` after the seat-time hydrate).
    let on_disk = load_named_groups_merged(
        &stage.joiner_state.named_groups_path,
        &stage.joiner_state.home_suite_groups_path,
    )
    .await?;
    assert_eq!(
        on_disk[&stage.group_id]
            .members_v2
            .get(&"cd".repeat(32))
            .and_then(|seat| seat.certificate.clone()),
        Some(filler_cert),
        "the hydrated certificate persisted with the adopted roster"
    );
    Ok(())
}

#[test]
fn blob_diagnostic_formatter_preserves_closed_numeric_fields_and_roles() {
    use crate::announce_blob::{AnnounceBlobCacheStats, AnnounceBlobDiagnostics};
    let stats = AnnounceBlobCacheStats {
        blob_cache_hits: 1,
        blob_cache_misses: 2,
        blob_fetches_ok: 3,
        blob_fetches_failed: 4,
        diagnostics: AnnounceBlobDiagnostics {
            fetches_spawned: 5,
            terminal_both_carriers_failed: 6,
            terminal_deadline_elapsed: 7,
            terminal_subscription_closed: 8,
            terminal_verifier_error: 9,
            responses_seen: 10,
            responses_skipped_malformed: 11,
            responses_skipped_mismatched_digest: 12,
            verified_requests_decoded: 13,
            unknown_digest: 14,
            pair_available: 15,
            coalesced_dropped: 16,
            response_publish_ok_local: 17,
            publish_failed_local: 18,
        },
    };
    let expected_names = [
        "blob_cache_hits",
        "blob_cache_misses",
        "blob_fetches_ok",
        "blob_fetches_failed",
        "fetches_spawned",
        "terminal_both_carriers_failed",
        "terminal_deadline_elapsed",
        "terminal_subscription_closed",
        "terminal_verifier_error",
        "responses_seen",
        "responses_skipped_malformed",
        "responses_skipped_mismatched_digest",
        "verified_requests_decoded",
        "unknown_digest",
        "pair_available",
        "coalesced_dropped",
        "response_publish_ok_local",
        "publish_failed_local",
    ];
    for (role, prefix) in [
        (BlobDiagnosticRole::Owner, "owner"),
        (BlobDiagnosticRole::Joiner, "joiner"),
    ] {
        let text = format_blob_diagnostics(role, &stats);
        let parts: Vec<_> = text.split_whitespace().collect();
        assert_eq!(parts.len(), expected_names.len() + 2);
        assert_eq!(
            parts[0],
            "counters_are_independent_relaxed_no_snapshot_pending_not_exact"
        );
        assert_eq!(
            parts[1],
            "scope=per_agent_lifetime_no_digest_window_attempt_attribution"
        );
        for (i, name) in expected_names.into_iter().enumerate() {
            assert_eq!(parts[i + 2], format!("{prefix}_{name}={}", i + 1));
        }
    }
}

#[test]
fn blob_diagnostic_formatter_does_not_infer_pending_or_normalize_observations() {
    let mut stats = crate::announce_blob::AnnounceBlobCacheStats::default();
    // Deliberately incoherent across a read interval; output must remain raw.
    stats.diagnostics.terminal_deadline_elapsed = u64::MAX;
    stats.diagnostics.responses_skipped_malformed = 7;
    stats.diagnostics.responses_skipped_mismatched_digest = 11;
    let text = format_blob_diagnostics(BlobDiagnosticRole::Owner, &stats);
    assert!(text.contains("owner_fetches_spawned=0"));
    assert!(text.contains(&format!("owner_terminal_deadline_elapsed={}", u64::MAX)));
    assert!(text.contains("owner_responses_skipped_malformed=7"));
    assert!(text.contains("owner_responses_skipped_mismatched_digest=11"));
    let fields: Vec<_> = text.split_whitespace().skip(2).collect();
    assert!(fields.iter().all(|field| field
        .split_once('=')
        .is_some_and(|(_, value)| value.parse::<u64>().is_ok())));
    assert!(!fields.iter().any(|field| [
        "in_flight",
        "pending",
        "identity",
        "payload",
        "agent_id",
        "peer_id"
    ]
    .iter()
    .any(|name| field.contains(name))));
}

// ── ADR-0064 slice 1 (Guard A): owner-axis fork quarantine ─────────────

/// Clone the base, mutate the description, and seal through the
/// PRODUCTION owner-certified seal path (the same wrapper every
/// authority commit site uses).
async fn adr0064_owner_seal_variant(
    state: &AppState,
    base: &x0x::groups::GroupInfo,
    description: &str,
) -> Result<x0x::groups::GroupInfo> {
    let mut v = base.clone();
    v.description = description.to_string();
    seal_commit_owner_certified(
        state,
        &mut v,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await?;
    Ok(v)
}

/// An owner-axis group with a sealed base commit and a lineage record —
/// the joiner-side shape on which conflicts produce evidence (and, from
/// ADR-0064 slice 1, the quarantine marker).
async fn adr0064_sealed_owner_group_with_lineage(
    state: &AppState,
    group_id: &str,
    policy: GroupPolicy,
) -> Result<x0x::groups::GroupInfo> {
    let mut info = x0x::groups::GroupInfo::with_policy(
        "quarantine-e2e".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.to_string(),
        policy,
    );
    seal_commit_owner_certified(
        state,
        &mut info,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await?;
    info.invite_lineage = Some(x0x::groups::InviteLineage {
        base_revision: info.state_revision,
        base_hash: info.state_hash.clone(),
        base_roster_root: String::new(),
        seated_at_revision: None,
        corroborated: false,
        fork_evidence: None,
    });
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info.clone());
    Ok(info)
}

/// Drive one state-commit through the REAL central apply hook.
async fn adr0064_apply_commit(
    state: &Arc<AppState>,
    group_id: &str,
    commit: x0x::groups::state_commit::GroupStateCommit,
    description: &str,
) -> Result<Result<x0x::groups::GroupInfo, x0x::groups::state_commit::ApplyError>> {
    let current = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .expect("group record present");
    let mutation = description.to_string();
    Ok(apply_stateful_event_with_evidence(
        state,
        group_id,
        &current,
        &commit,
        None,
        false,
        x0x::groups::ActionKind::AdminOrHigher,
        |next| {
            next.description = mutation;
        },
    )
    .await)
}

/// Two EQUAL-REVISION twins sealed by the same local admin key on an
/// OWNER-AXIS group (the conflicting twin classifies as StaleRevision
/// evidence): ADR-0064 slice 1 adds the durable containment — the
/// authenticated evidence sets the persistent quarantine marker (with
/// its forensic snapshot), the membership-gated routes refuse with the
/// typed 409 `fork_quarantined`, and the EXPLICIT owner-key seal route
/// (revision strictly greater than the evidence) lifts it again. r2
/// honesty note: this is NOT the full #468 stale-removal shape (removed
/// admin, joiner seated at N, MemberAdded across a gap, attestation
/// refusal) — that shape is only partially covered here via the
/// adoption-clear test and the clear-rule negative controls in
/// `fork_quarantine.rs`.
#[tokio::test]
async fn adr0064_owner_axis_twin_conflict_quarantines_gates_and_owner_seal_clears() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "7d".repeat(32);
    let base = adr0064_sealed_owner_group_with_lineage(
        &state,
        &group_id,
        owner_certified_policy(&owner_kp),
    )
    .await?;

    // Two different validly-signed commits at revision 2 (same prev):
    // whichever applies second is the stale fork.
    let fork_a = adr0064_owner_seal_variant(&state, &base, "fork-a").await?;
    let fork_b = adr0064_owner_seal_variant(&state, &base, "fork-b").await?;
    let fork_a_commit = fork_a.commit_log.last().expect("sealed").commit.clone();
    let fork_b_commit = fork_b.commit_log.last().expect("sealed").commit.clone();

    let first = adr0064_apply_commit(&state, &group_id, fork_a_commit.clone(), "fork-a").await?;
    assert!(first.is_ok(), "the first fork applies cleanly: {first:?}");
    persist_named_groups_mutation(&state, |groups| {
        let info = groups.get_mut(&group_id).expect("group");
        *info = first.expect("applied");
        true
    })
    .await?;

    // The conflicting twin: refused AND contained.
    let second = adr0064_apply_commit(&state, &group_id, fork_b_commit.clone(), "fork-b").await?;
    assert!(second.is_err(), "the conflicting twin must be refused");
    {
        let groups = state.named_groups.read().await;
        let record = groups.get(&group_id).expect("group");
        let marker = record
            .fork_quarantine
            .as_ref()
            .expect("owner-axis conflict sets the persistent marker");
        assert_eq!(marker.revision, 2);
        assert_eq!(marker.state_hash, fork_b_commit.state_hash);
        assert_eq!(marker.committed_by, authority_hex);
        assert!(!marker.no_anchor, "owner-axis groups have an anchor");
        // Forensic snapshot: our terminal vs the conflicting commit.
        assert_eq!(
            marker.snapshot.terminal_commit.state_hash, fork_a_commit.state_hash,
            "the snapshot's terminal is the observing node's head"
        );
        assert_eq!(
            marker.snapshot.conflicting_commit.state_hash,
            fork_b_commit.state_hash
        );
    }
    let row = diagnostics_row(state.as_ref(), &group_id).await;
    assert_eq!(row.counters.fork_quarantine_set, 1);

    // The gate: secure encrypt refuses with the typed 409 while the
    // marker is set (parity with the ADR-0038 restore gate).
    let req: SecureEncryptRequest =
        serde_json::from_value(serde_json::json!({ "payload_b64": "aGVsbG8=" }))?;
    let (status, json) = secure_group_encrypt(
        State(Arc::clone(&state)),
        Path(group_id.clone()),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Json(req),
    )
    .await;
    let body: serde_json::Value = json.0;
    assert_eq!(status, StatusCode::CONFLICT, "gated while quarantined");
    assert_eq!(
        body["error"].as_str(),
        Some("fork_quarantined"),
        "typed quarantine error: {body}"
    );
    let row = diagnostics_row(state.as_ref(), &group_id).await;
    assert_eq!(row.counters.fork_quarantine_refusals, 1);

    // The LOCAL owner-certified seal is an owner-anchored clear: the
    // evidence-bearing seal re-verifies the roster and lifts the marker.
    let response = seal_group_state(
        State(Arc::clone(&state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "seal clears the quarantine: {body}");
    assert!(
        !state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .expect("group")
            .is_fork_quarantined(),
        "marker cleared by the owner-certified seal"
    );
    Ok(())
}

/// Blueprint fault matrix "restart mid-quarantine": the marker is
/// PERSISTED (unlike the ADR-0038 `#[serde(skip)]` transient) — a full
/// store reload through `load_named_groups_merged` must carry it back
/// verbatim and the gate must still refuse. A transient marker would
/// silently un-contain the node on every restart.
#[tokio::test]
async fn adr0064_restart_preserves_marker_and_gate_still_refuses() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "7e".repeat(32);
    let base = adr0064_sealed_owner_group_with_lineage(
        &state,
        &group_id,
        owner_certified_policy(&owner_kp),
    )
    .await?;

    let fork_a = adr0064_owner_seal_variant(&state, &base, "fork-a").await?;
    let fork_b = adr0064_owner_seal_variant(&state, &base, "fork-b").await?;
    let fork_a_commit = fork_a.commit_log.last().expect("sealed").commit.clone();
    let fork_b_commit = fork_b.commit_log.last().expect("sealed").commit.clone();

    let first = adr0064_apply_commit(&state, &group_id, fork_a_commit, "fork-a").await?;
    assert!(first.is_ok());
    persist_named_groups_mutation(&state, |groups| {
        let info = groups.get_mut(&group_id).expect("group");
        *info = first.expect("applied");
        true
    })
    .await?;
    let second = adr0064_apply_commit(&state, &group_id, fork_b_commit, "fork-b").await?;
    assert!(second.is_err());
    let live_marker = state
        .named_groups
        .read()
        .await
        .get(&group_id)
        .expect("group")
        .fork_quarantine
        .clone()
        .expect("marker set before restart");

    // Persist → restart-load through the real merged loader.
    assert!(save_named_groups(&state).await);
    let reloaded =
        load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path).await?;
    let reloaded_marker = reloaded
        .get(&group_id)
        .expect("group survives the reload")
        .fork_quarantine
        .clone();
    assert_eq!(
        reloaded_marker,
        Some(live_marker),
        "the quarantine marker (snapshot included) reloads verbatim from disk"
    );

    // Install the reloaded store as the live map. The loader sets the
    // ADR-0038 restore flag for owner-certified groups; clear ONLY that
    // transient (it is a separate, seal-liftable gate) so this test
    // isolates the FORK gate's post-restart posture.
    *state.named_groups.write().await = reloaded;
    {
        let mut groups = state.named_groups.write().await;
        let record = groups.get_mut(&group_id).expect("group");
        record.owner_cert_reverify_required = false;
    }
    let req: SecureEncryptRequest =
        serde_json::from_value(serde_json::json!({ "payload_b64": "aGVsbG8=" }))?;
    let (status, json) = secure_group_encrypt(
        State(Arc::clone(&state)),
        Path(group_id.clone()),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Json(req),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the gate still refuses after the restart"
    );
    assert_eq!(
        json.0["error"].as_str(),
        Some("fork_quarantined"),
        "typed fork-quarantine error after reload: {}",
        json.0
    );
    Ok(())
}

/// ADR-0064 r2 item 3e: the SECOND owner-anchored clear — tier-1
/// (owner-attestation-anchored) across-gap adoption on a joiner stub
/// that already carries ≥1 applied commit. Positive arm: the terminal
/// revision is strictly greater than the evidenced revision, so the
/// attestation-verified adoption clears the marker. Negative arm
/// (r2 item 2b): the same adoption with the marker AT the terminal
/// revision still seats the joiner but must NOT clear — the contested
/// branch can never buy a clear at or below the evidence it caused.
/// A bare invite stub cannot hold evidence (empty commit_log), so the
/// fixture seats the marker on the r3-stage stub, which retains its
/// sealed base commit.
#[tokio::test]
async fn adr0064_adoption_clear_requires_strictly_greater_revision() -> Result<()> {
    let terminal_revision = |stage: &R3Stage| -> u64 {
        match &stage.member_added {
            NamedGroupMetadataEvent::MemberAdded {
                commit: Some(commit),
                ..
            } => commit.revision,
            _ => panic!("staged MemberAdded carries its terminal commit"),
        }
    };
    async fn seat_marker(stage: &R3Stage, revision: u64) {
        let terminal_header = {
            let groups = stage.joiner_state.named_groups.read().await;
            groups
                .get(&stage.group_id)
                .expect("stub")
                .terminal_commit_header()
        };
        let mut groups = stage.joiner_state.named_groups.write().await;
        groups
            .get_mut(&stage.group_id)
            .expect("stub")
            .fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision,
            state_hash: "evidenced-conflict-hash".to_string(),
            committed_by: stage.authority_hex.clone(),
            observed_at_ms: now_millis_u64(),
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: terminal_header.clone(),
                conflicting_commit: terminal_header,
                classification: None,
            },
            no_anchor: false,
        });
    }

    // Positive: evidence revision strictly below the terminal.
    let stage = r3_stage(0x9A).await?;
    let terminal = terminal_revision(&stage);
    assert!(terminal >= 1, "the staged terminal advances the chain");
    seat_marker(&stage, terminal - 1).await;
    let result = r3_apply_with_chain(&stage, stage.chain.clone()).await;
    assert!(result.accepted, "the attested adoption seats the joiner");
    {
        let groups = stage.joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("group");
        assert!(info.has_active_member(&stage.joiner_hex));
        assert!(
            !info.is_fork_quarantined(),
            "tier-1 attestation-anchored adoption at revision {terminal} > evidence {} clears",
            terminal - 1
        );
    }

    // Negative: marker AT the terminal revision — adoption succeeds but
    // never clears.
    let stage = r3_stage(0x9B).await?;
    let terminal = terminal_revision(&stage);
    seat_marker(&stage, terminal).await;
    let result = r3_apply_with_chain(&stage, stage.chain.clone()).await;
    assert!(
        result.accepted,
        "the quarantined stub still adopts (ingest must stay open)"
    );
    {
        let groups = stage.joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("group");
        assert!(
            info.has_active_member(&stage.joiner_hex),
            "joiner seated regardless of the marker"
        );
        assert!(
            info.is_fork_quarantined(),
            "adoption at revision == evidence revision does NOT clear"
        );
    }
    Ok(())
}

/// WHY (#468 / ADR-0064 slice 4, blueprint fault matrix "stale removal"):
/// the REAL #468 shape. The joiner's invite base (revision N) seats a
/// second admin A; the CANONICAL chain removes A at N+1 — invisible to
/// the joiner, which is exactly why the retained-base checks cannot see
/// it. A's install keeps driving the join it invited: it serves its own
/// fork N+1'..N+2' (the MemberAdded terminal) WITHOUT the owner head
/// attestation (the owner refuses to attest a removed admin's chain —
/// the attestation refusal). Tier-1 adoption refuses; the served chain
/// runs through the extracted ancestor walk (A IS an active admin at
/// the joiner's base, so the fork is internally perfect); with no owner
/// anchor reachable, the joiner quarantines on the walk-authenticated
/// evidence, records the `signer_only` classification, and stays
/// pending.
#[tokio::test]
async fn adr0064_s4_removed_admin_fork_to_joiner_quarantines() -> Result<()> {
    let stage = issue458_stage(0x9D, false).await?;
    let (joiner_state, _jdir) = joiner_state_for(&stage).await?;
    let owner_kp = UserKeypair::from_seed(&[0xF3u8; 32])?;
    let authority_hex = hex::encode(stage.authority.agent.agent_id().as_bytes());
    let authority_kp =
        AgentKeypair::from_bytes(&stage.authority_key_bytes.0, &stage.authority_key_bytes.1)?;

    // The joiner's invite base: founder admin + admin A (A invited the
    // joiner). Hand-sealed so the retained base commit covers the
    // {authority, A} roster the fork walks from.
    let a_kp = AgentKeypair::generate()?;
    let a_hex = hex::encode(a_kp.agent_id().as_bytes());
    let mut stub = stage.base_info.clone();
    stub.add_member(
        a_hex.clone(),
        x0x::groups::GroupRole::Admin,
        Some(authority_hex.clone()),
        None,
    );
    let base_revision = stub.state_revision.saturating_add(1);
    let base_commit = x0x::groups::GroupStateCommit::sign(
        stub.stable_group_id().to_string(),
        base_revision,
        Some(stub.state_hash.clone()),
        x0x::groups::compute_roster_root(&stub.members_v2),
        x0x::groups::compute_policy_hash(&stub.policy),
        x0x::groups::compute_public_meta_hash(&stub.public_meta()),
        stub.security_binding.clone(),
        false,
        now_millis_u64(),
        &authority_kp,
    )?;
    stub.prev_state_hash = Some(stub.state_hash.clone());
    stub.state_hash = base_commit.state_hash.clone();
    stub.state_revision = base_revision;
    stub.commit_log
        .push(x0x::groups::state_commit::RetainedCommit {
            commit: base_commit,
            roster: x0x::groups::state_commit::roster_projection(&stub.members_v2),
            meta: Some(stub.public_meta()),
        });
    stub.invite_lineage = Some(x0x::groups::InviteLineage {
        base_revision: stub.state_revision,
        base_hash: stub.state_hash.clone(),
        base_roster_root: String::new(),
        seated_at_revision: None,
        corroborated: false,
        fork_evidence: None,
    });
    joiner_state
        .named_groups
        .write()
        .await
        .insert(stage.group_id.clone(), stub.clone());

    // A's fork: link N+1' (A commits a metadata change over the base
    // roster) then the MemberAdded terminal N+2' seating the joiner.
    let policy_hash = x0x::groups::compute_policy_hash(&stub.policy);
    let mut fork_meta = stub.public_meta();
    fork_meta.description = "a-fork-1".to_string();
    let link = forge_retained_link(
        &stage.group_id,
        &policy_hash,
        base_revision.saturating_add(1),
        Some(stub.state_hash.clone()),
        x0x::groups::state_commit::roster_projection(&stub.members_v2),
        fork_meta.clone(),
        &a_kp,
    );
    let mut fork_roster_with_joiner = stub.members_v2.clone();
    fork_roster_with_joiner.insert(stage.joiner_hex.clone(), {
        let mut m = x0x::groups::GroupMember::new_member(
            stage.joiner_hex.clone(),
            None,
            None,
            now_millis_u64(),
        );
        m.role = x0x::groups::GroupRole::Member;
        m
    });
    let terminal = x0x::groups::GroupStateCommit::sign(
        stage.group_id.clone(),
        base_revision.saturating_add(2),
        Some(link.commit.state_hash.clone()),
        x0x::groups::compute_roster_root(&fork_roster_with_joiner),
        policy_hash.clone(),
        x0x::groups::compute_public_meta_hash(&fork_meta),
        stub.security_binding.clone(),
        false,
        now_millis_u64(),
        &a_kp,
    )?;

    // The joiner's certificate (owner-issued — the receiver gate needs
    // committed certificate evidence) and the MemberAdded event.
    let joiner_kp = AgentKeypair::from_bytes(&stage.joiner_key_bytes.0, &stage.joiner_key_bytes.1)?;
    let joiner_cert = issue_joiner_cert(&owner_kp, &joiner_kp)?;
    use base64::Engine as _;
    let event = NamedGroupMetadataEvent::MemberAdded {
        group_id: stage.group_id.clone(),
        revision: terminal.revision,
        actor: a_hex.clone(),
        agent_id: stage.joiner_hex.clone(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: Some(
            base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&joiner_cert)?),
        ),
        owner_mandate: None,
        commit: Some(terminal.clone()),
    };

    // Serve the fork chain with the join result — NO head attestation
    // (the #468 attestation refusal: the owner will not anchor a
    // removed admin's chain).
    let chain_key = join_result_key(&stage.group_id, &stage.joiner_hex);
    joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(chain_key, vec![link]);

    let result =
        apply_named_group_metadata_event(&joiner_state, event, a_kp.agent_id(), true, None).await;
    assert!(
        !result.accepted,
        "the unattested removed-admin fork is refused"
    );
    {
        let groups = joiner_state.named_groups.read().await;
        let info = groups.get(&stage.group_id).expect("stub retained");
        assert!(
            !info.has_active_member(&stage.joiner_hex),
            "the joiner stays pending (tier-1 anchor refused)"
        );
        let marker = info.fork_quarantine.as_ref().expect("quarantine marker");
        assert_eq!(marker.revision, terminal.revision);
        assert_eq!(marker.committed_by, a_hex);
        assert_eq!(
            marker.snapshot.classification.as_deref(),
            Some("signer_only"),
            "the served chain walked clean (A was admin at the base) — signer-only, no owner anchor"
        );
        assert!(
            info.invite_lineage
                .as_ref()
                .and_then(|lineage| lineage.fork_evidence.as_ref())
                .is_some(),
            "walk-authenticated evidence installed"
        );
    }
    let row = diagnostics_row(joiner_state.as_ref(), &stage.group_id).await;
    assert_eq!(row.counters.fork_evidence_signer_only, 1);
    assert_eq!(row.counters.fork_quarantine_set, 1);

    // Negative control: the same fork with a STRANGER-signed link (the
    // chain does not validate from the base) records nothing.
    let (joiner2_state, _jdir2) = joiner_state_for(&stage).await?;
    let mut stub2 = stub.clone();
    stub2.fork_quarantine = None;
    if let Some(lineage) = stub2.invite_lineage.as_mut() {
        lineage.fork_evidence = None;
    }
    joiner2_state
        .named_groups
        .write()
        .await
        .insert(stage.group_id.clone(), stub2);
    let stranger = AgentKeypair::generate()?;
    let stranger_link = forge_retained_link(
        &stage.group_id,
        &policy_hash,
        base_revision.saturating_add(1),
        Some(stub.state_hash.clone()),
        x0x::groups::state_commit::roster_projection(&stub.members_v2),
        fork_meta.clone(),
        &stranger,
    );
    let stranger_terminal = x0x::groups::GroupStateCommit::sign(
        stage.group_id.clone(),
        base_revision.saturating_add(2),
        Some(stranger_link.commit.state_hash.clone()),
        x0x::groups::compute_roster_root(&fork_roster_with_joiner),
        policy_hash.clone(),
        x0x::groups::compute_public_meta_hash(&fork_meta),
        stub.security_binding.clone(),
        false,
        now_millis_u64(),
        &a_kp,
    )?;
    let event2 = NamedGroupMetadataEvent::MemberAdded {
        group_id: stage.group_id.clone(),
        revision: stranger_terminal.revision,
        actor: a_hex.clone(),
        agent_id: stage.joiner_hex.clone(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: Some(
            base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&joiner_cert)?),
        ),
        owner_mandate: None,
        commit: Some(stranger_terminal),
    };
    let chain_key2 = join_result_key(&stage.group_id, &stage.joiner_hex);
    joiner2_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(chain_key2, vec![stranger_link]);
    let result2 =
        apply_named_group_metadata_event(&joiner2_state, event2, a_kp.agent_id(), true, None).await;
    assert!(!result2.accepted);
    let groups = joiner2_state.named_groups.read().await;
    let info = groups.get(&stage.group_id).expect("stub retained");
    assert!(
        !info.is_fork_quarantined(),
        "a chain that does not validate from the base is NOT evidence"
    );
    Ok(())
}

/// WHY (ADR-0064 slice 4 r2, review item 2 — DEADLOCK): the causal-replay
/// loop calls the serialized apply with `roster_lock_already_held = true`
/// while HOLDING `named_groups_persistence_lock`; a queued MemberAdded
/// that replays into the refused-adoption arm must not try to take that
/// lock again inside the joiner chain classification. Same #468 fixture
/// as the sibling test, driven through the replay-shaped call under the
/// held lock, bounded by a timeout so a regression FAILS instead of
/// hanging the suite.
#[tokio::test]
async fn adr0064_s4_removed_admin_fork_replay_under_held_lock_no_deadlock() -> Result<()> {
    let stage = issue458_stage(0x9E, false).await?;
    let (joiner_state, _jdir) = joiner_state_for(&stage).await?;
    let owner_kp = UserKeypair::from_seed(&[0xF3u8; 32])?;
    let authority_kp =
        AgentKeypair::from_bytes(&stage.authority_key_bytes.0, &stage.authority_key_bytes.1)?;
    let authority_hex = hex::encode(stage.authority.agent.agent_id().as_bytes());

    let a_kp = AgentKeypair::generate()?;
    let a_hex = hex::encode(a_kp.agent_id().as_bytes());
    let mut stub = stage.base_info.clone();
    stub.add_member(
        a_hex.clone(),
        x0x::groups::GroupRole::Admin,
        Some(authority_hex.clone()),
        None,
    );
    let base_revision = stub.state_revision.saturating_add(1);
    let base_commit = x0x::groups::GroupStateCommit::sign(
        stub.stable_group_id().to_string(),
        base_revision,
        Some(stub.state_hash.clone()),
        x0x::groups::compute_roster_root(&stub.members_v2),
        x0x::groups::compute_policy_hash(&stub.policy),
        x0x::groups::compute_public_meta_hash(&stub.public_meta()),
        stub.security_binding.clone(),
        false,
        now_millis_u64(),
        &authority_kp,
    )?;
    stub.prev_state_hash = Some(stub.state_hash.clone());
    stub.state_hash = base_commit.state_hash.clone();
    stub.state_revision = base_revision;
    stub.commit_log
        .push(x0x::groups::state_commit::RetainedCommit {
            commit: base_commit,
            roster: x0x::groups::state_commit::roster_projection(&stub.members_v2),
            meta: Some(stub.public_meta()),
        });
    stub.invite_lineage = Some(x0x::groups::InviteLineage {
        base_revision: stub.state_revision,
        base_hash: stub.state_hash.clone(),
        base_roster_root: String::new(),
        seated_at_revision: None,
        corroborated: false,
        fork_evidence: None,
    });
    joiner_state
        .named_groups
        .write()
        .await
        .insert(stage.group_id.clone(), stub.clone());

    let policy_hash = x0x::groups::compute_policy_hash(&stub.policy);
    let mut fork_meta = stub.public_meta();
    fork_meta.description = "a-fork-1".to_string();
    let link = forge_retained_link(
        &stage.group_id,
        &policy_hash,
        base_revision.saturating_add(1),
        Some(stub.state_hash.clone()),
        x0x::groups::state_commit::roster_projection(&stub.members_v2),
        fork_meta.clone(),
        &a_kp,
    );
    let mut fork_roster_with_joiner = stub.members_v2.clone();
    fork_roster_with_joiner.insert(stage.joiner_hex.clone(), {
        let mut m = x0x::groups::GroupMember::new_member(
            stage.joiner_hex.clone(),
            None,
            None,
            now_millis_u64(),
        );
        m.role = x0x::groups::GroupRole::Member;
        m
    });
    let terminal = x0x::groups::GroupStateCommit::sign(
        stage.group_id.clone(),
        base_revision.saturating_add(2),
        Some(link.commit.state_hash.clone()),
        x0x::groups::compute_roster_root(&fork_roster_with_joiner),
        policy_hash.clone(),
        x0x::groups::compute_public_meta_hash(&fork_meta),
        stub.security_binding.clone(),
        false,
        now_millis_u64(),
        &a_kp,
    )?;
    let joiner_kp = AgentKeypair::from_bytes(&stage.joiner_key_bytes.0, &stage.joiner_key_bytes.1)?;
    let joiner_cert = issue_joiner_cert(&owner_kp, &joiner_kp)?;
    use base64::Engine as _;
    let event = NamedGroupMetadataEvent::MemberAdded {
        group_id: stage.group_id.clone(),
        revision: terminal.revision,
        actor: a_hex.clone(),
        agent_id: stage.joiner_hex.clone(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: Some(
            base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&joiner_cert)?),
        ),
        owner_mandate: None,
        commit: Some(terminal.clone()),
    };
    let chain_key = join_result_key(&stage.group_id, &stage.joiner_hex);
    joiner_state
        .pending_adoption_chains
        .lock()
        .unwrap()
        .insert(chain_key, vec![link]);

    // The causal-replay shape: hold the persistence lock, drive the
    // serialized apply with roster_lock_already_held = true. Bounded by a
    // timeout so a deadlock regression FAILS rather than hangs.
    let _guard = joiner_state.named_groups_persistence_lock.lock().await;
    let mut replay_group_id: Option<String> = None;
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        apply_named_group_metadata_event_inner_serialized(
            &joiner_state,
            event,
            a_kp.agent_id(),
            true,
            false,
            None,
            None,
            &mut replay_group_id,
            true,
            true,
        ),
    )
    .await;
    let result = outcome.expect(
        "no deadlock: the joiner chain classification uses the UNLOCKED persist under the held lock",
    );
    assert!(
        !result.accepted,
        "the unattested removed-admin fork is refused"
    );
    let groups = joiner_state.named_groups.read().await;
    let info = groups.get(&stage.group_id).expect("stub retained");
    assert!(
        info.fork_quarantine.as_ref().is_some_and(|marker| marker
            .snapshot
            .classification
            .as_deref()
            == Some("signer_only")),
        "the evidence install completed under the held lock (unlocked persist)"
    );
    Ok(())
}
