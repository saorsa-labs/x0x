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

/// WHY (ADR-0064 Validation bullet): the marker CANNOT be cleared by the
/// contested branch's own valid commits — strict owner anchor only. A
/// higher-revision commit from the contested fork still
/// PrevHashMismatches against this node's head, and even a
/// canonical-looking commit that applies cleanly through the ordinary
/// path must NOT clear the marker (slice 1: only the verified head
/// attestation on adoption or a local owner-certified seal clears).
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

    // Apply A, then let B conflict → marker set.
    let first = apply_commit(&state, &group_id, fork_a_commit, "fork-a").await?;
    assert!(first.is_ok());
    persist_applied(&state, &group_id, first.expect("applied")).await?;
    let second = apply_commit(&state, &group_id, fork_b_commit.clone(), "fork-b").await?;
    assert!(second.is_err());
    assert!(
        live_record(&state, &group_id).await.is_fork_quarantined(),
        "owner-axis conflict sets the marker"
    );

    // Contested-branch N+3: chains from FORK B's own head, not ours.
    let mut contested = fork_b.clone();
    contested.description = "contested-n+3".to_string();
    seal_commit_owner_certified(
        &state,
        &mut contested,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await?;
    let contested_commit = contested.commit_log.last().expect("sealed").commit.clone();
    assert_eq!(contested_commit.revision, 3);
    let contested_apply =
        apply_commit(&state, &group_id, contested_commit, "contested-n+3").await?;
    assert!(
        contested_apply.is_err(),
        "the contested branch's higher commit still conflicts with our head"
    );
    assert!(
        live_record(&state, &group_id).await.is_fork_quarantined(),
        "a contested-branch commit with revision > evidence revision does NOT clear"
    );

    // Even a commit that chains from OUR head (applies cleanly through
    // the ordinary path) must not clear: slice 1 clears only via the
    // attestation-anchored adoption or a local owner-certified seal.
    let mut canonical = live_record(&state, &group_id).await;
    canonical.description = "canonical-advance".to_string();
    seal_commit_owner_certified(
        &state,
        &mut canonical,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await?;
    let canonical_commit = canonical.commit_log.last().expect("sealed").commit.clone();
    let applied = apply_commit(&state, &group_id, canonical_commit, "canonical-advance").await?;
    assert!(
        applied.is_ok(),
        "a self-chaining commit still applies (the clearing commit must be able to arrive): {applied:?}"
    );
    persist_applied(&state, &group_id, applied.expect("applied")).await?;
    let record = live_record(&state, &group_id).await;
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
