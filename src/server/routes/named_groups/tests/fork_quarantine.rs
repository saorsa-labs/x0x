//! ADR-0064 slice 1 (Guard A) unit tests: quarantine-marker set/no-set
//! matrix, bootstrap strip/reject, equal-revision negative control, and
//! forced-persist-failure retryability. The owner-axis end-to-end arm
//! (route gating + restart) lives in `hs_f2_membership_cluster.rs`; the
//! reverify-gate parity arm lives in `adr0038_owner_certified.rs`.

use super::*;

use crate::groups::policy::{GroupAdmission, GroupPolicy};
use crate::groups::{GroupConfidentiality, GroupDiscoverability};
use crate::identity::{AgentKeypair, UserKeypair};

/// Authority-side fixture (ADR-0038 Home shape, same as
/// `hs_f2_membership_cluster::owner_authority_state`): the local daemon
/// IS the owner's primary agent — user key + builder-issued certificate.
async fn owner_authority_state() -> Result<(Arc<AppState>, tempfile::TempDir, UserKeypair)> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    let owner_seed = [0xA6u8; 32];
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

/// A group with a sealed base commit (revision 1, via the PRODUCTION
/// owner-certified seal for owner-axis policy, or the plain seal
/// otherwise) and a lineage record — evidence only lands on groups that
/// carry lineage.
async fn sealed_group_with_lineage(
    state: &AppState,
    group_id: &str,
    policy: GroupPolicy,
) -> Result<x0x::groups::GroupInfo> {
    let mut info = x0x::groups::GroupInfo::with_policy(
        "quarantine-under-test".to_string(),
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

/// Drive one state-commit through the REAL central apply hook (the only
/// production path that classifies rejections as fork evidence).
async fn apply_commit(
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
        false,
        x0x::groups::ActionKind::AdminOrHigher,
        |next| {
            next.description = mutation;
        },
    )
    .await)
}

/// Persist an applied result the way the production arms do.
async fn persist_applied(
    state: &AppState,
    group_id: &str,
    applied: x0x::groups::GroupInfo,
) -> Result<()> {
    persist_named_groups_mutation(state, |groups| {
        let Some(info) = groups.get_mut(group_id) else {
            return false;
        };
        *info = applied;
        true
    })
    .await?;
    Ok(())
}

/// The group's live record out of the map.
async fn live_record(state: &AppState, group_id: &str) -> x0x::groups::GroupInfo {
    state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .expect("group record")
}

/// The stable-id diagnostics row for a group in the live map.
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

/// WHY (ADR-0064 slice-1 scope restriction): the quarantine marker is a
/// David-decision boundary — set and gated ONLY for owner-axis groups.
/// An ordinary invite-only group records fork EVIDENCE exactly as before
/// (ADR-0059 semantics are untouched) but must remain byte-for-byte
/// unchanged with respect to the marker: no marker, no
/// `fork_quarantine_set` counter, and the gate predicate inert.
#[tokio::test]
async fn adr0064_non_owner_axis_conflict_never_sets_marker() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "b0".repeat(32);
    let base = sealed_group_with_lineage(&state, &group_id, invite_only_policy()).await?;

    // Two different validly-signed commits at revision 2 (same prev).
    let seal_variant = |description: &str| -> Result<x0x::groups::state_commit::GroupStateCommit> {
        let mut v = base.clone();
        v.description = description.to_string();
        v.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
        Ok(v.commit_log.last().expect("sealed commit").commit.clone())
    };
    let fork_a = seal_variant("fork-a")?;
    let fork_b = seal_variant("fork-b")?;

    let first = apply_commit(&state, &group_id, fork_a, "fork-a").await?;
    assert!(first.is_ok(), "first fork applies: {first:?}");
    persist_applied(&state, &group_id, first.expect("applied")).await?;

    let second = apply_commit(&state, &group_id, fork_b, "fork-b").await?;
    assert!(second.is_err(), "conflicting twin must be refused");

    let record = live_record(&state, &group_id).await;
    // Evidence IS recorded (pre-existing ADR-0059 behaviour)…
    assert!(
        record
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.fork_evidence.as_ref())
            .is_some_and(
                |evidence| evidence.revision == 2 && evidence.committed_by == authority_hex
            ),
        "evidence still lands on non-owner-axis groups (unchanged)"
    );
    // …but the quarantine marker is NEVER set and nothing counted.
    assert!(
        !record.is_fork_quarantined(),
        "slice-1 scope: non-owner-axis groups never receive the marker"
    );
    let row = diag_row(&state, &group_id).await;
    assert_eq!(row.counters.fork_quarantine_set, 0);
    assert_eq!(row.counters.fork_quarantine_refusals, 0);
    Ok(())
}

/// WHY (ADR-0064 Decision 3 / Attack matrix "false quarantine"): only
/// AUTHENTICATED evidence may set the marker — a conflicting commit
/// whose signature or committer-authority check fails records nothing,
/// so an unauthenticated conflict can never contain the local node.
#[tokio::test]
async fn adr0064_unauthenticated_conflict_never_sets_marker() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "b1".repeat(32);
    let base =
        sealed_group_with_lineage(&state, &group_id, owner_certified_policy(&owner_kp)).await?;

    // A valid rev-2 twin applied first, so the stranger's own rev-2
    // commit arrives as a CONFLICT (StaleRevision against a retained
    // different-hash commit) — the only shape that reaches the
    // authentication gate.
    let mut twin = base.clone();
    twin.description = "fork-a".to_string();
    seal_commit_owner_certified(
        &state,
        &mut twin,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await?;
    let twin_commit = twin.commit_log.last().expect("sealed").commit.clone();
    let first = apply_commit(&state, &group_id, twin_commit, "fork-a").await?;
    assert!(first.is_ok());
    persist_applied(&state, &group_id, first.expect("applied")).await?;

    // The conflicting rev-2 commit signed by a STRANGER's key: structure
    // verifies (it is genuinely signed) but the committer is not an
    // active admin in the retained predecessor roster.
    let stranger = AgentKeypair::generate()?;
    let stranger_commit = x0x::groups::GroupStateCommit::sign(
        base.stable_group_id().to_string(),
        2,
        Some(base.state_hash.clone()),
        x0x::groups::compute_roster_root(&base.members_v2),
        x0x::groups::compute_policy_hash(&base.policy),
        x0x::groups::compute_public_meta_hash(&base.public_meta()),
        base.security_binding.clone(),
        false,
        now_millis_u64(),
        &stranger,
    )?;

    let applied = apply_commit(&state, &group_id, stranger_commit, "stranger-fork").await?;
    assert!(applied.is_err(), "stranger commit must be refused");

    let record = live_record(&state, &group_id).await;
    assert!(
        record
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.fork_evidence.as_ref())
            .is_none(),
        "no evidence for an unauthenticated conflict"
    );
    assert!(
        !record.is_fork_quarantined(),
        "no marker without authenticated evidence"
    );
    let row = diag_row(&state, &group_id).await;
    assert_eq!(row.counters.fork_quarantine_set, 0);
    assert!(
        row.counters.conflict_unauthenticated >= 1,
        "the unauthenticated-conflict counter fires instead"
    );
    Ok(())
}

/// WHY (ADR-0064 Migration table): the marker is strictly LOCAL
/// containment state — it must never leak on an outbound bootstrap
/// snapshot, and an inbound snapshot carrying one must be rejected
/// wholesale (containment is per-node; propagation is explicitly
/// rejected by Decision 3).
#[tokio::test]
async fn adr0064_bootstrap_snapshot_strips_and_rejects_marker() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "b2".repeat(32);
    let mut info = x0x::groups::GroupInfo::with_policy(
        "public".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.clone(),
        GroupPolicy {
            discoverability: GroupDiscoverability::PublicDirectory,
            admission: GroupAdmission::OwnerCertified(owner_kp.user_id()),
            confidentiality: GroupConfidentiality::SignedPublic,
            read_access: x0x::groups::GroupReadAccess::MembersOnly,
            write_access: x0x::groups::GroupWriteAccess::MembersOnly,
        },
    );
    // SignedPublic bootstrap shape: no secret/binding, one retained
    // sealed commit, and the local marker under test.
    info.shared_secret = None;
    info.security_binding = None;
    // The OwnerCertified bootstrap validator requires every active
    // member to carry a certificate verifying against the owner — seat
    // the builder-issued certificate BEFORE sealing so the signed
    // roster root covers its digest.
    {
        let creator_hex = hex::encode(state.agent.agent_id().as_bytes());
        let cert = state
            .agent
            .agent_certificate()
            .expect("builder-issued certificate")
            .clone();
        info.set_member_certificate(&creator_hex, cert)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    seal_commit_owner_certified(
        &state,
        &mut info,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await?;
    let creator_hex = hex::encode(state.agent.agent_id().as_bytes());
    let clean = info.clone();

    // Control: the clean record validates as an inbound bootstrap.
    assert!(
        validate_public_group_bootstrap(&clean, &creator_hex, &creator_hex),
        "control: a marker-free snapshot validates"
    );

    // Strip: the outbound snapshot never carries the marker.
    info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
        revision: 1,
        state_hash: info.state_hash.clone(),
        committed_by: creator_hex.clone(),
        observed_at_ms: now_millis_u64(),
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: info.terminal_commit_header(),
            conflicting_commit: info.terminal_commit_header(),
        },
        no_anchor: false,
    });
    let snapshot = signed_public_bootstrap_snapshot(info.clone()).expect("snapshot still produced");
    assert!(
        snapshot.fork_quarantine.is_none(),
        "outbound snapshot strips the marker"
    );

    // Reject: an inbound snapshot carrying a marker is refused wholesale.
    assert!(
        !validate_public_group_bootstrap(&info, &creator_hex, &creator_hex),
        "inbound snapshot carrying a marker is rejected"
    );
    Ok(())
}

/// Clone the base, mutate the description, and seal through the
/// PRODUCTION owner-certified seal (async — closures cannot carry the
/// await).
async fn owner_seal_variant(
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

/// WHY (ADR-0064 Validation bullet + r2 review item 3g): the marker
/// CANNOT be cleared by the contested branch — and the refusal must be
/// attributable to the CLEAR RULE, not to a chain check that never
/// reaches it. r2 replaced the old contested-apply arm (which failed on
/// PrevHashMismatch before any clear logic ran — tautological) with
/// arms that REACH the clear path: an explicit owner-key seal at
/// revision == evidence revision (refused by the strictly-greater
/// check) and the routine shared-wrapper seal (refused because only the
/// explicit route is an owner anchor). The self-chaining apply arm stays
/// because the ordinary apply path must keep serving the group so the
/// anchored clearing commit can arrive — without ever clearing.
#[tokio::test]
async fn adr0064_equal_revision_contested_commit_cannot_clear() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "b3".repeat(32);
    let base =
        sealed_group_with_lineage(&state, &group_id, owner_certified_policy(&owner_kp)).await?;

    let fork_a = owner_seal_variant(&state, &base, "fork-a").await?;
    let fork_b = owner_seal_variant(&state, &base, "fork-b").await?;
    let fork_a_commit = fork_a.commit_log.last().expect("sealed").commit.clone();
    let fork_b_commit = fork_b.commit_log.last().expect("sealed").commit.clone();

    // Apply A, then let B conflict → marker set at revision 2 (the
    // conflicting twin's revision; our head is also 2).
    let first = apply_commit(&state, &group_id, fork_a_commit, "fork-a").await?;
    assert!(first.is_ok());
    persist_applied(&state, &group_id, first.expect("applied")).await?;
    let second = apply_commit(&state, &group_id, fork_b_commit.clone(), "fork-b").await?;
    assert!(second.is_err());
    assert!(
        live_record(&state, &group_id).await.is_fork_quarantined(),
        "owner-axis conflict sets the marker"
    );

    // The routine shared-wrapper seal (what rename/policy/add/ban/
    // promote all seal through) REACHES a seal+persist on a quarantined
    // group and must NOT clear: only the explicit seal route is an
    // owner anchor.
    {
        let mut next = live_record(&state, &group_id).await;
        next.description = "routine-rename".to_string();
        seal_commit_owner_certified(
            &state,
            &mut next,
            state.agent.identity().agent_keypair(),
            now_millis_u64(),
        )
        .await?;
        persist_named_groups_mutation(&state, |groups| {
            let info = groups.get_mut(&group_id).expect("group");
            *info = next;
            true
        })
        .await?;
        assert!(
            live_record(&state, &group_id).await.is_fork_quarantined(),
            "the shared wrapper seal (routine mutations) never clears the marker"
        );
    }

    // Positive arm (the strictly-greater refusal itself is pinned by the
    // dedicated `adr0064_explicit_seal_at_evidence_revision_does_not_clear`
    // test): the explicit owner-key seal route at revision 4 — STRICTLY
    // greater than the evidenced revision 2 — is the owner anchor that
    // clears. In this equal-revision sibling shape the marker's revision
    // equals our head, so the clearing seal must advance strictly past
    // BOTH.
    let response = seal_group_state(
        State(Arc::clone(&state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "the explicit seal succeeds: {body}");
    let record = live_record(&state, &group_id).await;
    assert!(
        !record.is_fork_quarantined(),
        "explicit owner-key seal at revision 4 > evidence 2 clears (positive arm; the \
         strictly-greater refusal is pinned by the dedicated test below)"
    );
    assert_eq!(
        record.state_revision, 4,
        "the clearing seal advanced strictly past the evidence (wrapper seal 3, explicit seal 4)"
    );
    assert_eq!(
        record.fork_quarantine, None,
        "the marker is gone after the owner-anchored clear"
    );

    // The self-chaining canonical apply arm: on a FRESH quarantine, a
    // commit that chains from our head applies cleanly and must NOT
    // clear — the ordinary apply path never clears.
    let group2 = "b5".repeat(32);
    let base2 =
        sealed_group_with_lineage(&state, &group2, owner_certified_policy(&owner_kp)).await?;
    let twin_a = owner_seal_variant(&state, &base2, "twin-a").await?;
    let twin_b = owner_seal_variant(&state, &base2, "twin-b").await?;
    let twin_a_commit = twin_a.commit_log.last().expect("sealed").commit.clone();
    let twin_b_commit = twin_b.commit_log.last().expect("sealed").commit.clone();
    let first2 = apply_commit(&state, &group2, twin_a_commit, "twin-a").await?;
    assert!(first2.is_ok());
    persist_applied(&state, &group2, first2.expect("applied")).await?;
    let second2 = apply_commit(&state, &group2, twin_b_commit, "twin-b").await?;
    assert!(second2.is_err());
    assert!(live_record(&state, &group2).await.is_fork_quarantined());
    let mut canonical = live_record(&state, &group2).await;
    canonical.description = "canonical-advance".to_string();
    seal_commit_owner_certified(
        &state,
        &mut canonical,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await?;
    let canonical_commit = canonical.commit_log.last().expect("sealed").commit.clone();
    let applied = apply_commit(&state, &group2, canonical_commit, "canonical-advance").await?;
    assert!(
        applied.is_ok(),
        "a self-chaining commit still applies (the clearing commit must be able to arrive): {applied:?}"
    );
    persist_applied(&state, &group2, applied.expect("applied")).await?;
    let record = live_record(&state, &group2).await;
    assert!(
        record.is_fork_quarantined(),
        "ordinary applies never clear the marker — owner anchor only"
    );
    assert_eq!(
        record
            .fork_quarantine
            .as_ref()
            .expect("marker")
            .committed_by,
        authority_hex
    );
    Ok(())
}

/// WHY (blueprint fault matrix "crash between journal writes"): the
/// marker write rides the standard
/// `persist_named_groups_mutation` compare-and-restore path — a forced
/// persist FAILURE must leave the marker absent (rolled back, nothing
/// counted) so the identical conflict stays retryable, exactly like the
/// evidence record it accompanies.
#[tokio::test]
async fn adr0064_forced_persist_failure_leaves_marker_retryable() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "b4".repeat(32);
    let base =
        sealed_group_with_lineage(&state, &group_id, owner_certified_policy(&owner_kp)).await?;

    let fork_a = owner_seal_variant(&state, &base, "fork-a").await?;
    let fork_b = owner_seal_variant(&state, &base, "fork-b").await?;
    let fork_a_commit = fork_a.commit_log.last().expect("sealed").commit.clone();
    let fork_b_commit = fork_b.commit_log.last().expect("sealed").commit.clone();

    let first = apply_commit(&state, &group_id, fork_a_commit, "fork-a").await?;
    assert!(first.is_ok());
    persist_applied(&state, &group_id, first.expect("applied")).await?;

    // Force the roster save itself to fail (the #470 fault cell compiled
    // into the production persist path).
    {
        let _fault = set_save_fault(SaveFault::Error);
        let second = apply_commit(&state, &group_id, fork_b_commit.clone(), "fork-b").await?;
        assert!(second.is_err(), "the conflicting twin is still refused");
        let record = live_record(&state, &group_id).await;
        assert!(
            !record.is_fork_quarantined(),
            "failed persist rolls the marker back — never a live-only quarantine"
        );
        assert!(
            record
                .invite_lineage
                .as_ref()
                .and_then(|lineage| lineage.fork_evidence.as_ref())
                .is_none(),
            "the evidence record rolls back with it (retryable)"
        );
        assert_eq!(
            diag_row(&state, &group_id)
                .await
                .counters
                .fork_quarantine_set,
            0
        );
    }

    // The identical conflict retries the install once the fault clears.
    let retry = apply_commit(&state, &group_id, fork_b_commit, "fork-b").await?;
    assert!(retry.is_err());
    let record = live_record(&state, &group_id).await;
    assert!(
        record.is_fork_quarantined(),
        "the retried conflict installs the marker durably"
    );
    assert_eq!(
        diag_row(&state, &group_id)
            .await
            .counters
            .fork_quarantine_set,
        1,
        "the set counter fires exactly once (on the durable install)"
    );
    Ok(())
}

/// WHY (r2 item 3a): a ROUTINE non-seal-route mutation — the actual
/// rename route (`update_named_group`), which seals through the shared
/// `seal_commit_owner_certified` wrapper like every other routine site —
/// must NOT clear the marker on a quarantined owner-axis group. If the
/// shared wrapper cleared, any admin rename would silently lift
/// containment.
#[tokio::test]
async fn adr0064_routine_rename_mutation_does_not_clear() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "b6".repeat(32);
    let base =
        sealed_group_with_lineage(&state, &group_id, owner_certified_policy(&owner_kp)).await?;
    let fork_a = owner_seal_variant(&state, &base, "fork-a").await?;
    let fork_b = owner_seal_variant(&state, &base, "fork-b").await?;
    let fork_a_commit = fork_a.commit_log.last().expect("sealed").commit.clone();
    let fork_b_commit = fork_b.commit_log.last().expect("sealed").commit.clone();
    let first = apply_commit(&state, &group_id, fork_a_commit, "fork-a").await?;
    assert!(first.is_ok());
    persist_applied(&state, &group_id, first.expect("applied")).await?;
    let second = apply_commit(&state, &group_id, fork_b_commit, "fork-b").await?;
    assert!(second.is_err());
    assert!(live_record(&state, &group_id).await.is_fork_quarantined());

    // The REAL rename route (admin actor, durable owner context).
    let req: UpdateGroupRequest =
        serde_json::from_value(serde_json::json!({ "description": "renamed-while-quarantined" }))?;
    let response = update_named_group(
        State(Arc::clone(&state)),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
        Json(req),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "the rename itself succeeds: {body}");
    let record = live_record(&state, &group_id).await;
    assert_eq!(record.description, "renamed-while-quarantined");
    assert!(
        record.is_fork_quarantined(),
        "a routine rename (shared wrapper seal) never clears the marker"
    );
    Ok(())
}

/// WHY (r2 item 3b): the explicit owner-key seal must refuse to clear
/// when the sealed revision is NOT strictly greater than the evidenced
/// revision. Fixture: our head is at revision 2 (fork-a applied, its
/// commit retained); the fork's own rev-3 commit (chaining from fork-b's
/// rev-2 head, so it PrevHashMismatches ours) is AUTHENTICATED evidence
/// at revision 3 — above our head. The explicit seal then lands at
/// revision 3 == evidence and must NOT clear; the NEXT seal (revision
/// 4 > 3) finally clears.
#[tokio::test]
async fn adr0064_explicit_seal_at_evidence_revision_does_not_clear() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "b7".repeat(32);
    let base =
        sealed_group_with_lineage(&state, &group_id, owner_certified_policy(&owner_kp)).await?;
    let fork_a = owner_seal_variant(&state, &base, "fork-a").await?;
    let fork_b = owner_seal_variant(&state, &base, "fork-b").await?;
    let fork_a_commit = fork_a.commit_log.last().expect("sealed").commit.clone();
    let first = apply_commit(&state, &group_id, fork_a_commit, "fork-a").await?;
    assert!(first.is_ok());
    persist_applied(&state, &group_id, first.expect("applied")).await?;

    // The contested branch's rev-3 commit (chains from fork-b's rev-2):
    // PrevHashMismatch against our fork-a head → evidence at revision 3.
    let contested_rev3 = owner_seal_variant(&state, &fork_b, "contested-rev3").await?;
    let contested_commit = contested_rev3
        .commit_log
        .last()
        .expect("sealed")
        .commit
        .clone();
    assert_eq!(contested_commit.revision, 3);
    let conflicted = apply_commit(&state, &group_id, contested_commit, "contested-rev3").await?;
    assert!(conflicted.is_err());
    {
        let record = live_record(&state, &group_id).await;
        let marker = record.fork_quarantine.as_ref().expect("marker set");
        assert_eq!(marker.revision, 3, "evidence above our head (rev 2)");
        assert_eq!(record.state_revision, 2);
    }

    // Explicit owner-key seal #1: sealed revision 3 == evidence 3 → the
    // strictly-greater check refuses the clear, seal still succeeds.
    let seal = |state: Arc<AppState>, id: String| async move {
        let response = seal_group_state(
            State(state),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path(id),
        )
        .await
        .into_response();
        response_json(response).await
    };
    let (status, body) = seal(Arc::clone(&state), group_id.clone()).await?;
    assert_eq!(status, StatusCode::OK, "the seal succeeds: {body}");
    let record = live_record(&state, &group_id).await;
    assert_eq!(record.state_revision, 3, "the seal advanced the head");
    assert!(
        record.is_fork_quarantined(),
        "seal at revision == evidence revision does NOT clear (strictly-greater rule)"
    );

    // Explicit owner-key seal #2: sealed revision 4 > evidence 3 → clears.
    let (status, body) = seal(Arc::clone(&state), group_id.clone()).await?;
    assert_eq!(status, StatusCode::OK, "the second seal succeeds: {body}");
    let record = live_record(&state, &group_id).await;
    assert_eq!(record.state_revision, 4);
    assert!(
        !record.is_fork_quarantined(),
        "the next explicit owner-key seal (4 > 3) finally clears"
    );
    Ok(())
}

/// WHY (r2 item 3c): an agent-key seal carrying only an ADR-0038
/// certificate verdict is NOT an owner anchor — the local install must
/// hold the OWNER USER KEY (the #469 A1b `owner_key_unavailable` fence).
/// Fixture: a keyless-owner secondary admin (no local user key) whose
/// roster is fully certified by an owner key held ELSEWHERE, so the
/// explicit seal SUCCEEDS (all-clean verdict) at a revision strictly
/// above the evidence — and still must not clear.
#[tokio::test]
async fn adr0064_explicit_seal_without_owner_user_key_does_not_clear() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    // The owner's user key exists (it issued the local agent's
    // certificate) but is NOT loaded on this install.
    let owner_kp = UserKeypair::from_seed(&[0xC7u8; 32])?;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "b8".repeat(32);
    let mut info = x0x::groups::GroupInfo::with_policy(
        "keyless-owner-admin".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.clone(),
        owner_certified_policy(&owner_kp),
    );
    let cert = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        state
            .agent
            .identity()
            .agent_keypair()
            .public_key()
            .as_bytes(),
        None,
    )?;
    info.set_member_certificate(&local_hex, cert.clone())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    // Seed the discovery cache so the seal's evidence builder resolves
    // the certificate (the shape after the owner's primary announced).
    state.agent.identity_discovery_cache().write().await.insert(
        cert.agent_id()?,
        x0x::DiscoveredAgent {
            agent_id: cert.agent_id()?,
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
        },
    );
    seal_commit_owner_certified(
        &state,
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
        .insert(group_id.clone(), info.clone());
    let base = info;

    // Equal-revision twins → evidence at revision 2, head at 2.
    let fork_a = owner_seal_variant(&state, &base, "fork-a").await?;
    let fork_b = owner_seal_variant(&state, &base, "fork-b").await?;
    let fork_a_commit = fork_a.commit_log.last().expect("sealed").commit.clone();
    let fork_b_commit = fork_b.commit_log.last().expect("sealed").commit.clone();
    let first = apply_commit(&state, &group_id, fork_a_commit, "fork-a").await?;
    assert!(first.is_ok(), "first twin applies: {first:?}");
    persist_applied(&state, &group_id, first.expect("applied")).await?;
    let second = apply_commit(&state, &group_id, fork_b_commit, "fork-b").await?;
    assert!(second.is_err());
    assert!(live_record(&state, &group_id).await.is_fork_quarantined());

    // The explicit seal SUCCEEDS (cert-resolved all-clean roster) at
    // revision 3 > evidence 2 — but this install holds no owner USER
    // key, so the fence refuses the clear.
    let response = seal_group_state(
        State(Arc::clone(&state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the seal itself succeeds on the certified roster: {body}"
    );
    let record = live_record(&state, &group_id).await;
    assert_eq!(
        record.state_revision, 3,
        "revision strictly past the evidence"
    );
    assert!(
        record.is_fork_quarantined(),
        "no local owner user key → the seal is not an owner anchor and must not clear"
    );
    Ok(())
}
