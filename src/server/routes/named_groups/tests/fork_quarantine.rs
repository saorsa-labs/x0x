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
        None,
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

/// Two validly-signed sibling commits at revision 2 over the same parent,
/// signed with the plain (non-owner-certified) seal.
fn plain_seal_variant(
    state: &AppState,
    base: &x0x::groups::GroupInfo,
    description: &str,
) -> Result<x0x::groups::state_commit::GroupStateCommit> {
    let mut v = base.clone();
    v.description = description.to_string();
    v.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    Ok(v.commit_log.last().expect("sealed commit").commit.clone())
}

/// WHY (ADR-0066 §2 — the single largest finding of the §1 census, and the
/// behaviour this slice exists to change). ADR-0064 shipped the marker for
/// owner-axis groups only, so for ORDINARY groups the gated count was 0 of
/// 26: every data-plane route served both branches of a fork, indefinitely,
/// while ADR-0064's own text claimed `quarantine_no_anchor` semantics for
/// exactly that population. This test pins the repair end to end.
///
/// The `no_anchor: true` flag is not decoration: it is what the three
/// owner-anchored clear arms consult to DECLINE, and what the §5 message
/// reads to name the only remedy that can work (`--force --reason`). A
/// marker installed on an ordinary group without it would be handed an
/// automatic clear by the mandate arm and the user would be told to wait
/// for an anchor that can never arrive.
///
/// This test supersedes `adr0064_non_owner_axis_conflict_never_sets_marker`,
/// which asserted the inverse. The old assertion was correct for ADR-0064's
/// deliberate slice boundary and is wrong under ADR-0066 §2; it is replaced
/// rather than relaxed so the change of contract is visible in the diff.
#[tokio::test]
async fn adr0066_ordinary_group_conflict_sets_a_no_anchor_marker() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "b0".repeat(32);
    let base = sealed_group_with_lineage(&state, &group_id, invite_only_policy()).await?;

    let fork_a = plain_seal_variant(&state, &base, "fork-a")?;
    let fork_b = plain_seal_variant(&state, &base, "fork-b")?;

    let first = apply_commit(&state, &group_id, fork_a, "fork-a").await?;
    assert!(first.is_ok(), "first fork applies: {first:?}");
    persist_applied(&state, &group_id, first.expect("applied")).await?;

    let second = apply_commit(&state, &group_id, fork_b, "fork-b").await?;
    assert!(second.is_err(), "conflicting twin must be refused");

    let record = live_record(&state, &group_id).await;
    // Evidence is recorded exactly as before — ADR-0059 semantics untouched.
    assert!(
        record
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.fork_evidence.as_ref())
            .is_some_and(
                |evidence| evidence.revision == 2 && evidence.committed_by == authority_hex
            ),
        "evidence still lands on ordinary groups (unchanged)"
    );
    let marker = record.fork_quarantine.as_ref().expect(
        "ADR-0066 §2: authenticated conflicting evidence now quarantines an ORDINARY group too",
    );
    assert!(
        marker.no_anchor,
        "an ordinary group has no owner axis, so the marker must say so — this flag is what \
         makes every automatic clear decline and what picks the only workable remedy in the \
         §5 message"
    );
    assert_eq!(marker.revision, 2, "the marker names the evidenced fork");
    assert_eq!(
        diag_row(&state, &group_id)
            .await
            .counters
            .fork_quarantine_set,
        1,
        "operators upgrading should expect fork_quarantine_set to rise for this population"
    );

    // Rows 1–6 are now REACHABLE for this population, and each refusal
    // carries the slice-1 message with the `no_anchor` branch: the R5
    // override removed the warn-only window only on condition that the
    // user is told why, and for a marker that never auto-clears a bare
    // code would be a permanent mystery.
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
        "a data-plane route on a quarantined ordinary group refuses: {}",
        json.0
    );
    assert_fork_quarantine_refusal_body(&json.0);
    assert_eq!(
        json.0["fork_quarantine"]["no_anchor"].as_bool(),
        Some(true),
        "§5: the body says plainly that nothing will clear this automatically"
    );
    let message = json.0["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("--force") && message.contains("--reason"),
        "the remedy named must be the one that can actually succeed for a group with no \
         owner axis: {message}"
    );

    // ADR-0066 §2 "Clear is manual and only manual": a perfectly valid
    // commit at a HIGHER revision on our own ancestry advances the group
    // and leaves the marker exactly where it is.
    let head = live_record(&state, &group_id).await;
    let advance = plain_seal_variant(&state, &head, "valid-advance")?;
    let advanced = apply_commit(&state, &group_id, advance, "valid-advance").await?;
    let advanced = advanced.expect("a valid successor applies");
    assert_eq!(advanced.state_revision, 3, "the group did advance");
    persist_applied(&state, &group_id, advanced).await?;
    let record = live_record(&state, &group_id).await;
    assert!(
        record
            .fork_quarantine
            .as_ref()
            .is_some_and(|marker| marker.no_anchor && marker.revision == 2),
        "no commit, of any revision, on any ancestry clears a `no_anchor` marker"
    );
    Ok(())
}

/// WHY (ADR-0066 R2 — the widened `invite_lineage` fence): before this
/// slice the evidence path was reached only for INVITE-DERIVED groups,
/// because the evidence record lives on `invite_lineage`. An ordinary group
/// created locally, with no invite in its history, recorded nothing at all
/// — so "ordinary group" silently meant two populations with different
/// containment. R2 ratified widening the fence, and for a lineage-less
/// group the MARKER is the durable record.
///
/// This is the fixture that fails if the widening is reverted to
/// `invite_lineage.is_some()`, or if `install_fork_evidence` keeps its old
/// "no lineage, no install" early return — in which case the group would
/// look contained (the conflict is still refused) while nothing was
/// recorded and every other route kept serving.
#[tokio::test]
async fn adr0066_ordinary_group_without_invite_lineage_is_covered() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "b9".repeat(32);
    let mut info = x0x::groups::GroupInfo::with_policy(
        "no-lineage-under-test".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.clone(),
        invite_only_policy(),
    );
    info.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    assert!(
        info.invite_lineage.is_none(),
        "the fixture's whole point: this group never held an invite record"
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info.clone());

    let fork_a = plain_seal_variant(&state, &info, "fork-a")?;
    let fork_b = plain_seal_variant(&state, &info, "fork-b")?;
    let first = apply_commit(&state, &group_id, fork_a, "fork-a").await?;
    assert!(first.is_ok());
    persist_applied(&state, &group_id, first.expect("applied")).await?;
    let second = apply_commit(&state, &group_id, fork_b, "fork-b").await?;
    assert!(second.is_err(), "the conflicting twin is refused");

    let record = live_record(&state, &group_id).await;
    assert!(
        record.invite_lineage.is_none(),
        "no lineage record is fabricated — provenance is not invented to hold evidence"
    );
    assert!(
        record
            .fork_quarantine
            .as_ref()
            .is_some_and(|marker| marker.no_anchor),
        "R2: a group formed without an invite is quarantined too, with no anchor"
    );
    assert_eq!(
        diag_row(&state, &group_id)
            .await
            .counters
            .fork_quarantine_set,
        1
    );

    // The marker doubles as the first-complete-wins silence gate for this
    // population: a SECOND, different authenticated conflict must not
    // re-install, re-count or re-warn on an already-contained group.
    let mut third_meta = info.public_meta();
    third_meta.description = "fork-c".to_string();
    let fork_c = x0x::groups::GroupStateCommit::sign(
        info.stable_group_id().to_string(),
        2,
        Some(info.state_hash.clone()),
        x0x::groups::compute_roster_root(&info.members_v2),
        x0x::groups::compute_policy_hash(&info.policy),
        x0x::groups::compute_public_meta_hash(&third_meta),
        info.security_binding.clone(),
        false,
        now_millis_u64(),
        state.agent.identity().agent_keypair(),
    )?;
    let third = apply_commit(&state, &group_id, fork_c, "fork-c").await?;
    assert!(third.is_err(), "the third commit also conflicts");
    let record = live_record(&state, &group_id).await;
    assert!(
        record
            .fork_quarantine
            .as_ref()
            .is_some_and(|marker| marker.revision == 2 && marker.no_anchor),
        "first complete evidence wins — the original marker is kept"
    );
    assert_eq!(
        diag_row(&state, &group_id)
            .await
            .counters
            .fork_quarantine_set,
        1,
        "an already-contained group does not re-count on every later conflict"
    );
    Ok(())
}

/// WHY (ADR-0066 §2 "Trigger is unchanged" + ADR-0064 Attack matrix "false
/// quarantine"): widening the marker to ordinary groups widens the blast
/// radius of a FALSE positive from 0 routes to 12, so the authentication of
/// evidence is the security boundary of this whole slice. If an
/// unauthenticated conflicting commit could install a marker, any stranger
/// who can reach the metadata topic could take an ordinary group's data
/// plane offline until a human intervened — a remote denial of service with
/// no automatic recovery, because a `no_anchor` marker never auto-clears.
///
/// The gate is `fork_candidate_authenticated`: the commit's own signature
/// must verify AND its committer must have been an ACTIVE ADMIN in the
/// retained predecessor roster. This fixture is the ordinary-group twin of
/// `adr0064_unauthenticated_conflict_never_sets_marker`.
#[tokio::test]
async fn adr0066_unauthenticated_conflict_never_quarantines_an_ordinary_group() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "ba".repeat(32);
    let base = sealed_group_with_lineage(&state, &group_id, invite_only_policy()).await?;

    let fork_a = plain_seal_variant(&state, &base, "fork-a")?;
    let first = apply_commit(&state, &group_id, fork_a, "fork-a").await?;
    assert!(first.is_ok());
    persist_applied(&state, &group_id, first.expect("applied")).await?;

    // Genuinely signed — by a key that holds no seat in the retained
    // roster. Structure verification passes; authority does not.
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
    let refused = apply_commit(&state, &group_id, stranger_commit, "stranger-fork").await?;
    assert!(refused.is_err(), "the stranger's commit is refused");

    let record = live_record(&state, &group_id).await;
    assert!(
        !record.is_fork_quarantined(),
        "ADR-0066 §2: extending the marker to ordinary groups must NOT relax authentication — \
         an unauthenticated conflict is a remote DoS if it can quarantine"
    );
    assert!(
        record
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.fork_evidence.as_ref())
            .is_none(),
        "and no evidence is recorded either"
    );
    let row = diag_row(&state, &group_id).await;
    assert_eq!(row.counters.fork_quarantine_set, 0);
    assert!(
        row.counters.conflict_unauthenticated >= 1,
        "the unauthenticated-conflict counter fires instead"
    );

    // A FORGED commit — one whose signature does not verify at all — is
    // refused a step earlier, and likewise quarantines nothing.
    let mut forged = plain_seal_variant(&state, &base, "forged")?;
    forged.signature = "not-a-signature".to_string();
    let forged_refused = apply_commit(&state, &group_id, forged, "forged").await?;
    assert!(forged_refused.is_err(), "the forged commit is refused");
    assert!(
        !live_record(&state, &group_id).await.is_fork_quarantined(),
        "a commit whose signature does not verify is never evidence"
    );
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
            classification: None,
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
        let _fault = set_save_fault(&state, SaveFault::Error);
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

// ─────────── ADR-0064 slice 4: classification + clear completion ───────────

/// Slice-4 fixture: like [`sealed_group_with_lineage`] but with the
/// local agent's builder-issued certificate SEATED before the seal, so
/// the roster carries committed owner-keyed material the
/// owner-anchored-successor predicate can derive the owner public key
/// from (`trusted_owner_public_key`).
async fn cert_sealed_group_with_lineage(
    state: &AppState,
    group_id: &str,
    policy: GroupPolicy,
) -> Result<x0x::groups::GroupInfo> {
    let mut info = x0x::groups::GroupInfo::with_policy(
        "quarantine-s4-under-test".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.to_string(),
        policy,
    );
    let creator_hex = hex::encode(state.agent.agent_id().as_bytes());
    let cert = state
        .agent
        .agent_certificate()
        .expect("builder-issued certificate")
        .clone();
    info.set_member_certificate(&creator_hex, cert)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
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

/// WHY (ADR-0064 slice 4, #472 decision 3): the classification labels
/// the forensic snapshot with what the retained log could prove:
/// `signer_only` for a signer who was an ACTIVE ADMIN at the
/// conflicting commit's claimed parent, `unauthorized_signer` for a
/// seat-holder who was NOT active-admin there (the removed-admin
/// chaining-from-its-own-removal shape).
#[tokio::test]
async fn adr0064_classification_signer_only_and_unauthorized_labels() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "ba".repeat(32);
    let base = cert_sealed_group_with_lineage(&state, &group_id, owner_certified_policy(&owner_kp))
        .await?;

    // (b) signer_only: the authority's own conflicting twin — it was an
    // active admin at the twin's claimed parent (our retained base).
    let fork_a = owner_seal_variant(&state, &base, "fork-a").await?;
    let fork_b = owner_seal_variant(&state, &base, "fork-b").await?;
    let fork_a_commit = fork_a.commit_log.last().expect("sealed").commit.clone();
    let fork_b_commit = fork_b.commit_log.last().expect("sealed").commit.clone();
    let first = apply_commit(&state, &group_id, fork_a_commit, "fork-a").await?;
    assert!(first.is_ok());
    persist_applied(&state, &group_id, first.expect("applied")).await?;
    let second = apply_commit(&state, &group_id, fork_b_commit, "fork-b").await?;
    assert!(second.is_err());
    {
        let record = live_record(&state, &group_id).await;
        let marker = record.fork_quarantine.as_ref().expect("marker");
        assert_eq!(
            marker.committed_by, authority_hex,
            "the twin is the evidenced conflict"
        );
        assert_eq!(
            marker.snapshot.classification.as_deref(),
            Some("signer_only"),
            "signer was an active admin at the claimed parent"
        );
    }
    let row = diag_row(&state, &group_id).await;
    assert_eq!(row.counters.fork_evidence_signer_only, 1);
    assert_eq!(row.counters.fork_evidence_unauthorized_signer, 0);

    // (c) unauthorized_signer: a second admin A is seated then REMOVED
    // canonically; A's later conflicting commit chains from the removal
    // commit — A held a seat in retained history but was NOT an active
    // admin at the claimed parent.
    let group2 = "bb".repeat(32);
    let base2 =
        cert_sealed_group_with_lineage(&state, &group2, owner_certified_policy(&owner_kp)).await?;
    let a_kp = AgentKeypair::generate()?;
    let a_hex = hex::encode(a_kp.agent_id().as_bytes());
    // Seat A WITH an owner-issued certificate (the owner-certified seal
    // requires certifiable actives) and seed the discovery cache so the
    // seal's evidence builder resolves it.
    let a_cert = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        a_kp.public_key().as_bytes(),
        None,
    )?;
    state.agent.identity_discovery_cache().write().await.insert(
        a_cert.agent_id()?,
        x0x::DiscoveredAgent {
            agent_id: a_cert.agent_id()?,
            machine_id: x0x::identity::MachineId([0u8; 32]),
            user_id: a_cert.user_id().ok(),
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
            cert_not_after: a_cert.not_after(),
            agent_certificate: Some(a_cert.clone()),
            agent_public_key: Vec::new(),
            cert_digest: None,
        },
    );
    let mut removed = base2.clone();
    removed.add_member(
        a_hex.clone(),
        x0x::groups::GroupRole::Admin,
        Some(authority_hex.clone()),
        None,
    );
    removed
        .set_member_certificate(&a_hex, a_cert.clone())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    seal_commit_owner_certified(
        &state,
        &mut removed,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await?;
    let removal_commit = removed.commit_log.last().expect("sealed").commit.clone();
    let current2 = live_record(&state, &group2).await;
    let a_cert_for_seat = a_cert.clone();
    let seated = apply_stateful_event_with_evidence(
        &state,
        &group2,
        &current2,
        &removal_commit,
        None,
        false,
        x0x::groups::ActionKind::AdminOrHigher,
        |next| {
            next.add_member(
                a_hex.clone(),
                x0x::groups::GroupRole::Admin,
                Some(authority_hex.clone()),
                None,
            );
            next.set_member_certificate(&a_hex, a_cert_for_seat.clone())
                .expect("seat cert");
        },
    )
    .await
    .expect("seating applies (chains from the base)");
    persist_applied(&state, &group2, seated).await?;
    // Canonical removal of A at rev 3.
    let mut after_removal = live_record(&state, &group2).await;
    after_removal.remove_member(&a_hex, Some(authority_hex.clone()));
    seal_commit_owner_certified(
        &state,
        &mut after_removal,
        state.agent.identity().agent_keypair(),
        now_millis_u64(),
    )
    .await?;
    let removal_commit = after_removal
        .commit_log
        .last()
        .expect("sealed")
        .commit
        .clone();
    let current3 = live_record(&state, &group2).await;
    let removal_applied = apply_stateful_event_with_evidence(
        &state,
        &group2,
        &current3,
        &removal_commit,
        None,
        false,
        x0x::groups::ActionKind::AdminOrHigher,
        |next| {
            next.remove_member(&a_hex, Some(authority_hex.clone()));
        },
    )
    .await
    .expect("removal applies");
    persist_applied(&state, &group2, removal_applied).await?;
    let removal_head_hash = removal_commit.state_hash.clone();
    let head = live_record(&state, &group2).await;
    assert!(
        head.commit_log
            .iter()
            .any(|rc| rc.roster.contains_key(&a_hex)),
        "A is still visible in the retained history (its seating commit)"
    );
    // One more canonical commit so A's conflicting rev-4 twin (claiming
    // the REMOVAL commit as parent) arrives as StaleRevision evidence
    // rather than dying at the authority check.
    let canonical4 = {
        let mut next = live_record(&state, &group2).await;
        next.description = "canonical-4".to_string();
        seal_commit_owner_certified(
            &state,
            &mut next,
            state.agent.identity().agent_keypair(),
            now_millis_u64(),
        )
        .await?;
        next
    };
    let canonical4_commit = canonical4.commit_log.last().expect("sealed").commit.clone();
    let applied4 = apply_commit(&state, &group2, canonical4_commit, "canonical-4").await?;
    assert!(applied4.is_ok());
    persist_applied(&state, &group2, applied4.expect("applied")).await?;
    let head = live_record(&state, &group2).await;

    // A's conflicting commit at rev 4 claiming the REMOVAL commit as its
    // parent: claimed parent retained, A absent from its roster (removed
    // there) but visible in earlier retained history. Distinct meta so
    // the twin hash differs from our retained canonical-4.
    let mut stale_meta = head.public_meta();
    stale_meta.description = "removed-admin-fork".to_string();
    let stale = x0x::groups::GroupStateCommit::sign(
        head.stable_group_id().to_string(),
        head.state_revision,
        Some(removal_head_hash.clone()),
        x0x::groups::compute_roster_root(&head.members_v2),
        x0x::groups::compute_policy_hash(&head.policy),
        x0x::groups::compute_public_meta_hash(&stale_meta),
        head.security_binding.clone(),
        false,
        now_millis_u64(),
        &a_kp,
    )?;
    assert_eq!(
        stale.prev_state_hash.as_deref(),
        Some(removal_head_hash.as_str()),
        "the fork claims the removal commit as its parent"
    );
    let refused = apply_commit(&state, &group2, stale, "removed-admin-fork").await?;
    assert!(refused.is_err(), "the removed admin's commit is refused");
    {
        let record = live_record(&state, &group2).await;
        let marker = record.fork_quarantine.as_ref().expect("marker");
        assert_eq!(marker.committed_by, a_hex);
        assert_eq!(
            marker.snapshot.classification.as_deref(),
            Some("unauthorized_signer"),
            "removed admin chaining from its own removal"
        );
    }
    let row2 = diag_row(&state, &group2).await;
    assert_eq!(row2.counters.fork_evidence_unauthorized_signer, 1);
    assert_eq!(row2.counters.fork_evidence_signer_only, 0);

    // r2 advisory — parent-roster vs CURRENT-roster discrimination: A is
    // admin at the claimed parent (the retained rev-1 seating commit)
    // but REMOVED from the current roster (the canonical rev-2 removal
    // is our head). A's conflicting twin claiming the rev-1 parent is
    // `signer_only` — the classification reads the PARENT snapshot, so
    // a current-roster check would have (wrongly) called A
    // unauthenticated.
    let group3 = "bc3".repeat(32);
    let base3 =
        cert_sealed_group_with_lineage(&state, &group3, owner_certified_policy(&owner_kp)).await?;
    let a_kp3 = AgentKeypair::generate()?;
    let a_hex3 = hex::encode(a_kp3.agent_id().as_bytes());
    let cert3 = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        a_kp3.public_key().as_bytes(),
        None,
    )?;
    state.agent.identity_discovery_cache().write().await.insert(
        cert3.agent_id()?,
        x0x::DiscoveredAgent {
            agent_id: cert3.agent_id()?,
            machine_id: x0x::identity::MachineId([0u8; 32]),
            user_id: cert3.user_id().ok(),
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
            cert_not_after: cert3.not_after(),
            agent_certificate: Some(cert3.clone()),
            agent_public_key: Vec::new(),
            cert_digest: None,
        },
    );
    let seating_commit = {
        let mut seated = base3.clone();
        seated.add_member(
            a_hex3.clone(),
            x0x::groups::GroupRole::Admin,
            Some(authority_hex.clone()),
            None,
        );
        seated
            .set_member_certificate(&a_hex3, cert3.clone())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        seal_commit_owner_certified(
            &state,
            &mut seated,
            state.agent.identity().agent_keypair(),
            now_millis_u64(),
        )
        .await?;
        seated.commit_log.last().expect("sealed").commit.clone()
    };
    {
        let current3 = live_record(&state, &group3).await;
        let applied = apply_stateful_event_with_evidence(
            &state,
            &group3,
            &current3,
            &seating_commit,
            None,
            false,
            x0x::groups::ActionKind::AdminOrHigher,
            |next| {
                next.add_member(
                    a_hex3.clone(),
                    x0x::groups::GroupRole::Admin,
                    Some(authority_hex.clone()),
                    None,
                );
                next.set_member_certificate(&a_hex3, cert3.clone())
                    .expect("seat cert");
            },
        )
        .await
        .expect("seating applies");
        persist_applied(&state, &group3, applied).await?;
    }
    // Canonical removal of A at the next revision (our head).
    {
        let mut after = live_record(&state, &group3).await;
        after.remove_member(&a_hex3, Some(authority_hex.clone()));
        seal_commit_owner_certified(
            &state,
            &mut after,
            state.agent.identity().agent_keypair(),
            now_millis_u64(),
        )
        .await?;
        let commit = after.commit_log.last().expect("sealed").commit.clone();
        let current3 = live_record(&state, &group3).await;
        let applied = apply_stateful_event_with_evidence(
            &state,
            &group3,
            &current3,
            &commit,
            None,
            false,
            x0x::groups::ActionKind::AdminOrHigher,
            |next| {
                next.remove_member(&a_hex3, Some(authority_hex.clone()));
            },
        )
        .await
        .expect("removal applies");
        persist_applied(&state, &group3, applied).await?;
    }
    let head3 = live_record(&state, &group3).await;
    assert!(!head3
        .members_v2
        .iter()
        .any(|(id, m)| { id == &a_hex3 && m.state == x0x::groups::GroupMemberState::Active }));
    // A's conflicting twin claiming the RETAINED seating commit as
    // parent (A was admin there), while our head is the removal.
    let mut twin_meta = head3.public_meta();
    twin_meta.description = "a-twin-from-seating".to_string();
    let a_twin = x0x::groups::GroupStateCommit::sign(
        head3.stable_group_id().to_string(),
        seating_commit.revision.saturating_add(1),
        Some(seating_commit.state_hash.clone()),
        x0x::groups::compute_roster_root(&head3.members_v2),
        x0x::groups::compute_policy_hash(&head3.policy),
        x0x::groups::compute_public_meta_hash(&twin_meta),
        head3.security_binding.clone(),
        false,
        now_millis_u64(),
        &a_kp3,
    )?;
    let refused3 = apply_commit(&state, &group3, a_twin, "a-twin-from-seating").await?;
    assert!(refused3.is_err());
    {
        let record = live_record(&state, &group3).await;
        let marker = record.fork_quarantine.as_ref().expect("marker");
        assert_eq!(
            marker.committed_by, a_hex3,
            "the removed admin's twin is the evidenced conflict"
        );
        assert_eq!(
            marker.snapshot.classification.as_deref(),
            Some("signer_only"),
            "admin at the CLAIMED PARENT (the seating commit) — the parent snapshot decides, \
             not the current roster where A is removed"
        );
    }
    let row3 = diag_row(&state, &group3).await;
    assert_eq!(row3.counters.fork_evidence_signer_only, 1);
    Ok(())
}

/// WHY (ADR-0064 slice 4, item 3iii / slice-1 residual): containment
/// must not be one-shot. After ANY owner-anchored clear the stored
/// fork-evidence silence gate re-arms, so a LATER authenticated fork
/// re-evaluates, re-installs evidence and RE-QUARANTINES.
#[tokio::test]
async fn adr0064_quarantine_clears_then_reforks_requarantines() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "bc".repeat(32);
    let base = cert_sealed_group_with_lineage(&state, &group_id, owner_certified_policy(&owner_kp))
        .await?;

    // Fork #1: equal-revision twins → evidence + marker at rev 2.
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
    assert_eq!(
        diag_row(&state, &group_id)
            .await
            .counters
            .fork_quarantine_set,
        1
    );

    // Owner-anchored clear: the explicit owner-key seal at revision 4
    // (wrapper seal 3, explicit 4) strictly past the evidence 2.
    let response = seal_group_state(
        State(Arc::clone(&state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_id.clone()),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "explicit seal clears: {body}");
    {
        let record = live_record(&state, &group_id).await;
        assert!(!record.is_fork_quarantined(), "cleared");
        assert!(
            record
                .invite_lineage
                .as_ref()
                .and_then(|lineage| lineage.fork_evidence.as_ref())
                .is_none(),
            "the evidence gate re-armed (stored evidence reset by the clear)"
        );
    }

    // Fork #2: a NEW conflicting twin at revision 5 — the re-armed gate
    // must let it re-evaluate and re-quarantine.
    // The twin is signed directly over the SAME rev-4 parent the
    // canonical commit claims, with different metadata (a re-seal of a
    // clone would chain from the new head and simply apply).
    let head4 = live_record(&state, &group_id).await;
    let canonical = {
        let mut next = head4.clone();
        next.description = "canonical-5".to_string();
        seal_commit_owner_certified(
            &state,
            &mut next,
            state.agent.identity().agent_keypair(),
            now_millis_u64(),
        )
        .await?;
        next
    };
    let canonical_commit = canonical.commit_log.last().expect("sealed").commit.clone();
    let applied = apply_commit(&state, &group_id, canonical_commit, "canonical-5").await?;
    assert!(applied.is_ok());
    persist_applied(&state, &group_id, applied.expect("applied")).await?;
    let mut twin5_meta = head4.public_meta();
    twin5_meta.description = "twin-5-fork".to_string();
    let twin5_commit = x0x::groups::GroupStateCommit::sign(
        head4.stable_group_id().to_string(),
        head4.state_revision.saturating_add(1),
        Some(head4.state_hash.clone()),
        x0x::groups::compute_roster_root(&head4.members_v2),
        x0x::groups::compute_policy_hash(&head4.policy),
        x0x::groups::compute_public_meta_hash(&twin5_meta),
        head4.security_binding.clone(),
        false,
        now_millis_u64(),
        state.agent.identity().agent_keypair(),
    )?;
    let refused = apply_commit(&state, &group_id, twin5_commit, "twin-5-fork").await?;
    assert!(refused.is_err(), "the second fork conflicts");
    let record = live_record(&state, &group_id).await;
    assert!(
        record.is_fork_quarantined(),
        "containment is NOT one-shot: the post-clear fork re-quarantines"
    );
    assert!(
        record
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.fork_evidence.as_ref())
            .is_some_and(|evidence| evidence.revision == head4.state_revision + 1),
        "fresh evidence recorded for the new fork"
    );
    let row = diag_row(&state, &group_id).await;
    assert_eq!(
        row.counters.fork_quarantine_set, 2,
        "the marker was set twice (quarantine → clear → quarantine)"
    );
    Ok(())
}

/// WHY (ADR-0064 slice 4, fault-matrix "contested-branch-cannot-clear"):
/// the contested branch mints an honestly owner-SIGNED mandate over its
/// own N+3 (the owner-defection shape) and publishes it. The
/// owner-anchor evaluation RUNS (the mandate verifies — not short-
/// circuited by the PrevHashMismatch apply failure) and is REFUSED on
/// the retained-ancestry fence: the clear path is reached and refused,
/// with an attributable counter, and the marker stays.
#[tokio::test]
async fn adr0064_contested_branch_anchored_commit_cannot_clear() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "bd".repeat(32);
    let base = cert_sealed_group_with_lineage(&state, &group_id, owner_certified_policy(&owner_kp))
        .await?;

    // Quarantine: twins at rev 2 (we hold fork-a; fork-b is evidence).
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

    // The CONTESTED branch's own rev-3 commit, chaining from fork-b's
    // head (NOT our retained history) — and an HONEST owner-key mandate
    // over it (the owner vouches for the contested successor).
    let contested3 = owner_seal_variant(&state, &fork_b, "contested-3").await?;
    let contested_commit = contested3.commit_log.last().expect("sealed").commit.clone();
    let mandate = x0x::groups::OwnerMandate::sign(
        contested3.stable_group_id(),
        contested_commit.revision,
        contested_commit
            .prev_state_hash
            .as_deref()
            .unwrap_or_default(),
        &contested_commit.roster_root,
        &contested_commit.policy_hash,
        &contested_commit.public_meta_hash,
        0,
        &authority_hex,
        "",
        "",
        &authority_hex,
        now_millis_u64(),
        &owner_kp,
    )
    .expect("sign contested mandate");

    // Drive the hook with the mandate present: the anchor VERIFIES
    // against the owner key derived from the roster certificate, so the
    // clear evaluation RUNS — and must refuse on retained ancestry.
    let current = live_record(&state, &group_id).await;
    let refused = apply_stateful_event_with_evidence(
        &state,
        &group_id,
        &current,
        &contested_commit,
        Some(&mandate),
        false,
        x0x::groups::ActionKind::AdminOrHigher,
        |next| {
            next.description = "contested-3".to_string();
        },
    )
    .await;
    assert!(refused.is_err(), "the contested commit cannot apply here");

    let record = live_record(&state, &group_id).await;
    assert!(
        record.is_fork_quarantined(),
        "a contested-ancestry anchored commit NEVER clears the marker"
    );
    let row = diag_row(&state, &group_id).await;
    assert_eq!(
        row.counters.fork_quarantine_owner_anchored_refusals, 1,
        "the clear evaluation ran and refused — attributable, not a silent PrevHashMismatch"
    );
    assert_eq!(row.counters.fork_quarantine_owner_anchored_clears, 0);
    Ok(())
}

/// WHY (ADR-0064 slice 4 r2, review item 1 — ADR §3 conformance): the
/// CONFLICT PATH NEVER CLEARS. A mandate-anchored conflicting commit
/// that chains through retained ancestry at strictly greater revision
/// than the evidence is still a CONFLICT — this node holds the disowned
/// sibling and would keep applying it, so clearing would un-gate the
/// node and the next canonical commit would re-quarantine the same
/// divergence (flapping). The Accepted ADR's clear rule ("a
/// same-revision sibling — the contested branch itself — can never
/// clear"; the marker clears ONLY when this node APPLIES commit C)
/// wins over the round-1 reading. The anchored conflicting successor
/// is recorded as `owner_anchored_conflict` EVIDENCE and the
/// attributable no-clear counter fires; containment lifts only when an
/// anchored commit APPLIES (the apply-path clear, pinned in
/// tests/owner_mandate.rs::owner_anchored_apply_path_clears_quarantine).
#[tokio::test]
async fn adr0064_owner_anchored_successor_conflicting_commit_never_clears() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "be".repeat(32);
    let base = cert_sealed_group_with_lineage(&state, &group_id, owner_certified_policy(&owner_kp))
        .await?;

    // Fork at rev 2: we keep fork-a; fork-b is evidence (marker rev 2).
    let fork_a = owner_seal_variant(&state, &base, "fork-a").await?;
    let fork_b = owner_seal_variant(&state, &base, "fork-b").await?;
    let fork_a_commit = fork_a.commit_log.last().expect("sealed").commit.clone();
    let fork_b_commit = fork_b.commit_log.last().expect("sealed").commit.clone();
    let first = apply_commit(&state, &group_id, fork_a_commit.clone(), "fork-a").await?;
    assert!(first.is_ok());
    persist_applied(&state, &group_id, first.expect("applied")).await?;
    let second = apply_commit(&state, &group_id, fork_b_commit.clone(), "fork-b").await?;
    assert!(second.is_err());
    assert!(live_record(&state, &group_id).await.is_fork_quarantined());

    // Our head advances to rev 3 on OUR (contested) chain — retained.
    let canonical3 = {
        let mut next = live_record(&state, &group_id).await;
        next.description = "our-chain-3".to_string();
        seal_commit_owner_certified(
            &state,
            &mut next,
            state.agent.identity().agent_keypair(),
            now_millis_u64(),
        )
        .await?;
        next
    };
    let canonical3_commit = canonical3.commit_log.last().expect("sealed").commit.clone();
    let applied3 = apply_commit(&state, &group_id, canonical3_commit, "our-chain-3").await?;
    assert!(applied3.is_ok());
    persist_applied(&state, &group_id, applied3.expect("applied")).await?;
    assert!(
        live_record(&state, &group_id).await.is_fork_quarantined(),
        "ordinary applies never clear (owner anchor only)"
    );

    // The owner anchors the OTHER branch's rev-3 sibling: chains from
    // our RETAINED rev-2 commit (the fork-a twin we applied — its hash
    // is in our log), conflicts with our rev-3 head (StaleRevision
    // twin), carries a verifying mandate, and is at revision 3 > the
    // evidenced revision 2 — the coherent anchored successor shape.
    // Round 1 cleared here; r2 records evidence instead.
    let current = live_record(&state, &group_id).await;
    let mut anchored_meta = current.public_meta();
    anchored_meta.description = "owner-anchored-3".to_string();
    let anchored_commit = x0x::groups::GroupStateCommit::sign(
        current.stable_group_id().to_string(),
        fork_a_commit.revision.saturating_add(1),
        Some(fork_a_commit.state_hash.clone()),
        x0x::groups::compute_roster_root(&current.members_v2),
        x0x::groups::compute_policy_hash(&current.policy),
        x0x::groups::compute_public_meta_hash(&anchored_meta),
        current.security_binding.clone(),
        false,
        now_millis_u64(),
        state.agent.identity().agent_keypair(),
    )?;
    let mandate = x0x::groups::OwnerMandate::sign(
        current.stable_group_id(),
        anchored_commit.revision,
        anchored_commit
            .prev_state_hash
            .as_deref()
            .unwrap_or_default(),
        &anchored_commit.roster_root,
        &anchored_commit.policy_hash,
        &anchored_commit.public_meta_hash,
        0,
        &authority_hex,
        "",
        "",
        &authority_hex,
        now_millis_u64(),
        &owner_kp,
    )
    .expect("sign anchored mandate");

    let outcome = apply_stateful_event_with_evidence(
        &state,
        &group_id,
        &current,
        &anchored_commit,
        Some(&mandate),
        false,
        x0x::groups::ActionKind::AdminOrHigher,
        |next| {
            next.description = "owner-anchored-3".to_string();
        },
    )
    .await;
    assert!(
        outcome.is_err(),
        "the anchored sibling still cannot APPLY (no rollback) — classification only"
    );
    let record = live_record(&state, &group_id).await;
    assert!(
        record.is_fork_quarantined(),
        "r2 (ADR §3): the conflict path NEVER clears — even a coherent anchored successor"
    );
    let row = diag_row(&state, &group_id).await;
    assert_eq!(
        row.counters.fork_quarantine_owner_anchored_refusals, 1,
        "the anchored conflicting commit counted an attributable no-clear"
    );
    assert_eq!(
        row.counters.fork_quarantine_owner_anchored_clears, 0,
        "no clear fired on the conflict path"
    );
    Ok(())
}

/// WHY (ADR-0064 slice 4, #472 decision 6 + the sidecar correction): for
/// owner-axis groups the authoritative persisted record is the
/// `home-suite-groups.json` SIDECAR, and it must carry the quarantine
/// marker AND the mandate-capability map through the SAME
/// compare-and-restore mutation (`persist_named_groups_mutation`) that
/// keeps the two-file write recoverable as a unit — so an old (or
/// downgraded) binary rewriting `named_groups.json` alone can never drop
/// containment. The load path merges with the sidecar winning.
#[tokio::test]
async fn adr0064_sidecar_mirrors_marker_and_capability_survives_legacy_rewrite() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "bf".repeat(32);
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let base = cert_sealed_group_with_lineage(&state, &group_id, owner_certified_policy(&owner_kp))
        .await?;

    // Seat the marker + a capability-map entry through the STANDARD
    // compare-and-restore mutation (the same write every production
    // site uses — one atomic pair, #617-recoverable as a unit).
    let terminal_header = base.terminal_commit_header();
    persist_named_groups_mutation(&state, |groups| {
        let Some(info) = groups.get_mut(&group_id) else {
            return false;
        };
        info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision: info.state_revision,
            state_hash: info.state_hash.clone(),
            committed_by: authority_hex.clone(),
            observed_at_ms: now_millis_u64(),
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: terminal_header.clone(),
                conflicting_commit: terminal_header.clone(),
                classification: Some("signer_only".to_string()),
            },
            no_anchor: false,
        });
        info.mandate_capability.insert(
            authority_hex.clone(),
            x0x::groups::MandateCapabilityState {
                first_seen_ms: now_millis_u64(),
                refusals: 0,
                refusal_transition_counted: false,
            },
        );
        true
    })
    .await?;

    // The sidecar physically carries BOTH local-only fields.
    let sidecar_json = tokio::fs::read_to_string(&state.home_suite_groups_path).await?;
    let sidecar: HashMap<String, x0x::groups::GroupInfo> = serde_json::from_str(&sidecar_json)?;
    let sidecar_entry = sidecar.get(&group_id).expect("sidecar entry");
    assert!(sidecar_entry.fork_quarantine.is_some(), "marker in sidecar");
    assert!(
        sidecar_entry
            .mandate_capability
            .contains_key(&authority_hex),
        "capability map in sidecar"
    );

    // Simulate an old binary rewriting `named_groups.json` WITHOUT the
    // fields (it ignores/drops them).
    let named_json = tokio::fs::read_to_string(&state.named_groups_path).await?;
    let mut legacy: HashMap<String, serde_json::Value> = serde_json::from_str(&named_json)?;
    if let Some(entry) = legacy.get_mut(&group_id) {
        if let Some(obj) = entry.as_object_mut() {
            obj.remove("fork_quarantine");
            obj.remove("mandate_capability");
        }
    }
    tokio::fs::write(&state.named_groups_path, serde_json::to_string(&legacy)?).await?;

    // Load: the sidecar wins for owner-axis groups — containment and
    // the capability clock survive the legacy rewrite.
    let merged =
        load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path).await?;
    let record = merged.get(&group_id).expect("merged record");
    assert!(
        record.is_fork_quarantined(),
        "the marker survives an old binary rewriting named_groups.json"
    );
    assert!(
        record.mandate_capability.contains_key(&authority_hex),
        "the capability map survives the rewrite too"
    );
    Ok(())
}

/// WHY (r3): the `owner_anchored_conflict` label itself needs a fixture
/// with NO prior evidence — the never-clears test's group already holds
/// rev-2 twin evidence (first-complete-wins refuses a second install,
/// so its marker keeps the ORIGINAL unclassified snapshot). Here the
/// anchored sibling is the FIRST conflict: no marker, empty lineage →
/// the anchored classification lands on the installed evidence and the
/// marker's snapshot, and the attributable no-clear counter fires.
#[tokio::test]
async fn adr0064_owner_anchored_conflict_label_lands_on_fresh_evidence() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "b9".repeat(32);
    let base = cert_sealed_group_with_lineage(&state, &group_id, owner_certified_policy(&owner_kp))
        .await?;

    // Advance to rev 2 canonically (no fork, no evidence, no marker).
    let canonical2 = {
        let mut next = base.clone();
        next.description = "canonical-2".to_string();
        seal_commit_owner_certified(
            &state,
            &mut next,
            state.agent.identity().agent_keypair(),
            now_millis_u64(),
        )
        .await?;
        next
    };
    let canonical2_commit = canonical2.commit_log.last().expect("sealed").commit.clone();
    let applied = apply_commit(&state, &group_id, canonical2_commit, "canonical-2").await?;
    assert!(applied.is_ok());
    persist_applied(&state, &group_id, applied.expect("applied")).await?;
    assert!(
        !live_record(&state, &group_id).await.is_fork_quarantined(),
        "no prior conflict — clean fixture"
    );

    // The owner-anchored rev-2 SIBLING: chains from the retained base
    // (rev 1, consecutive), conflicts with our rev-2 head
    // (StaleRevision), carries a verifying mandate — the first
    // conflict this node sees.
    let head = live_record(&state, &group_id).await;
    let base_commit = base.commit_log.last().expect("base sealed").commit.clone();
    let mut anchored_meta = head.public_meta();
    anchored_meta.description = "owner-anchored-sibling-2".to_string();
    let anchored_commit = x0x::groups::GroupStateCommit::sign(
        head.stable_group_id().to_string(),
        base_commit.revision.saturating_add(1),
        Some(base_commit.state_hash.clone()),
        x0x::groups::compute_roster_root(&head.members_v2),
        x0x::groups::compute_policy_hash(&head.policy),
        x0x::groups::compute_public_meta_hash(&anchored_meta),
        head.security_binding.clone(),
        false,
        now_millis_u64(),
        state.agent.identity().agent_keypair(),
    )?;
    let mandate = x0x::groups::OwnerMandate::sign(
        head.stable_group_id(),
        anchored_commit.revision,
        anchored_commit
            .prev_state_hash
            .as_deref()
            .unwrap_or_default(),
        &anchored_commit.roster_root,
        &anchored_commit.policy_hash,
        &anchored_commit.public_meta_hash,
        0,
        &authority_hex,
        "",
        "",
        &authority_hex,
        now_millis_u64(),
        &owner_kp,
    )
    .expect("sign anchored mandate");

    let outcome = apply_stateful_event_with_evidence(
        &state,
        &group_id,
        &head,
        &anchored_commit,
        Some(&mandate),
        false,
        x0x::groups::ActionKind::AdminOrHigher,
        |next| {
            next.description = "owner-anchored-sibling-2".to_string();
        },
    )
    .await;
    assert!(outcome.is_err(), "the anchored sibling still conflicts");

    let record = live_record(&state, &group_id).await;
    let marker = record.fork_quarantine.as_ref().expect("marker set");
    assert_eq!(marker.revision, anchored_commit.revision);
    assert_eq!(marker.committed_by, authority_hex);
    assert_eq!(
        marker.snapshot.classification.as_deref(),
        Some("owner_anchored_conflict"),
        "the FIRST conflict's evidence carries the anchored classification"
    );
    assert!(
        record
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.fork_evidence.as_ref())
            .is_some_and(|evidence| evidence.revision == anchored_commit.revision),
        "the anchored sibling's evidence installed (no prior evidence to win)"
    );
    let row = diag_row(&state, &group_id).await;
    assert_eq!(
        row.counters.fork_quarantine_owner_anchored_refusals, 1,
        "verifying anchor — attributable no-clear signal"
    );
    assert_eq!(
        row.counters.fork_quarantine_owner_anchored_clears, 0,
        "r2/ADR §3: the conflict path never clears"
    );
    Ok(())
}

/// ADR-0066 §5 acceptance bar, asserted in ONE place so the three
/// pre-existing refusal sites and every future refusing row check the
/// same contract instead of each re-deriving it (§3e: one helper builds
/// the refusal, so one helper should assert it).
///
/// WHY each clause matters, not just what it checks:
/// - `reason` is the stable machine code. R5 moved it out of `error`
///   precisely so that `error` is free to be prose; if `reason` is
///   missing, every client that migrated has silently lost its match.
/// - `error` must NOT equal the code. This is the clause that fails if
///   someone reverts to `api_error(CONFLICT, "fork_quarantined")` — the
///   exact regression §5 exists to prevent, and one a "409 is returned"
///   test cannot see.
/// - `error` must name the quarantine, the reason operations are
///   refused, and the clearing path. R5 removed the warn-only window on
///   the condition that a user always learns why; a marker that never
///   auto-clears turns a bare code into a permanent mystery, so
///   "mentions quarantine" alone is not the bar — "actionable" is.
/// - `fork_quarantine.clear_with` carries the remedy machine-readably so
///   a GUI or script can offer it without parsing prose.
pub(super) fn assert_fork_quarantine_refusal_body(body: &serde_json::Value) {
    assert_eq!(
        body["ok"].as_bool(),
        Some(false),
        "ADR-0066 §5: `ok: false` is unchanged — the envelope shape is compatible: {body}"
    );
    assert_eq!(
        body["reason"].as_str(),
        Some("fork_quarantined"),
        "ADR-0066 §5: the stable machine code lives in `reason`: {body}"
    );
    let message = body["error"].as_str().unwrap_or_default();
    assert!(
        !message.is_empty(),
        "ADR-0066 §5: a refusal without a message is a failing test, not a cosmetic gap: {body}"
    );
    assert_ne!(
        message, "fork_quarantined",
        "ADR-0066 §5 regression guard: `error` must be prose, never the bare machine code — \
         this assertion is what fails if the refusal reverts to `api_error`: {body}"
    );
    assert!(
        message.contains("fork-quarantined"),
        "ADR-0066 §5: the sentence must name the condition: {message}"
    );
    assert!(
        message.contains("contested") && message.contains("refused"),
        "ADR-0066 §5: the sentence must say WHY the operation was refused: {message}"
    );
    assert!(
        message.contains("/quarantine/clear") && message.contains("x0x groups quarantine clear"),
        "ADR-0066 §5: a message that names the condition but not the remedy does not satisfy \
         R5 — the CLI command is named for CLI users: {message}"
    );
    let marker = &body["fork_quarantine"];
    assert!(
        marker["revision"].is_u64(),
        "ADR-0066 §5: which divergence: {body}"
    );
    assert!(
        marker["observed_at_ms"].is_u64(),
        "ADR-0066 §5: when this node saw it: {body}"
    );
    assert!(
        marker["no_anchor"].is_boolean(),
        "ADR-0066 §5: whether anything will clear this automatically: {body}"
    );
    assert_eq!(
        marker["clear_with"].as_str(),
        Some("POST /groups/:id/quarantine/clear"),
        "ADR-0066 §5: the remedy, machine-readable: {body}"
    );
}

/// A marker built without a daemon, for the inert payload-contract test.
fn synthetic_marker(no_anchor: bool) -> Result<x0x::groups::ForkQuarantine> {
    let kp = AgentKeypair::generate()?;
    let info = x0x::groups::GroupInfo::with_policy(
        "payload-contract".to_string(),
        String::new(),
        crate::identity::AgentId::from_public_key(kp.public_key()),
        "aa".repeat(32),
        invite_only_policy(),
    );
    let header = info.terminal_commit_header();
    Ok(x0x::groups::ForkQuarantine {
        revision: 7,
        state_hash: "0".repeat(64),
        committed_by: "ff".repeat(32),
        observed_at_ms: 1_700_000_000_123,
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: header.clone(),
            conflicting_commit: header,
            classification: None,
        },
        no_anchor,
    })
}

/// WHY (ADR-0066 §5, slice 1): the refusal must explain itself. R5
/// removed the warn-only window *on the condition* that a user always
/// learns why an operation was refused, so the message is part of the
/// containment contract, not presentation polish.
///
/// Both marker shapes are asserted because the remedy differs and a
/// wrong remedy is worse than none: an owner-axis marker also clears
/// when the owner anchor advances, while a `no_anchor` marker never
/// auto-clears and its manual clear has no owner axis to attest with, so
/// it can only be cleared with the operator override
/// (`clear_group_quarantine` path (b)). A message that told an ordinary
/// group's operator to "wait for the owner anchor", or told them to run
/// the clear without `--force`, would send them down a path that cannot
/// succeed.
///
/// Inert by construction: no AppState, no Agent, no sockets — the §5
/// bar is a property of the body, and a payload test that needs a node
/// stood up is a payload test nobody runs.
#[test]
fn adr0066_refusal_body_carries_the_machine_code_and_an_actionable_message() -> Result<()> {
    let group_id = "c1".repeat(32);

    let owner_axis = fork_quarantine_refusal_body(&group_id, &synthetic_marker(false)?);
    assert_fork_quarantine_refusal_body(&owner_axis);
    let owner_message = owner_axis["error"].as_str().unwrap_or_default();
    assert!(
        owner_message.contains("owner-anchored commit advances past revision 7"),
        "an owner-axis marker's exit includes the anchored advance, named with the \
         evidenced revision: {owner_message}"
    );
    assert_eq!(
        owner_axis["fork_quarantine"]["no_anchor"].as_bool(),
        Some(false)
    );
    assert_eq!(owner_axis["fork_quarantine"]["revision"].as_u64(), Some(7));
    assert_eq!(
        owner_axis["fork_quarantine"]["observed_at_ms"].as_u64(),
        Some(1_700_000_000_123)
    );

    let no_anchor = fork_quarantine_refusal_body(&group_id, &synthetic_marker(true)?);
    assert_fork_quarantine_refusal_body(&no_anchor);
    let no_anchor_message = no_anchor["error"].as_str().unwrap_or_default();
    assert!(
        no_anchor_message.contains("nothing clears the marker automatically"),
        "a `no_anchor` marker must say plainly that no advance will lift it: {no_anchor_message}"
    );
    assert!(
        no_anchor_message.contains("--force") && no_anchor_message.contains("--reason"),
        "the only clear available to a group with no owner axis is the operator override: \
         {no_anchor_message}"
    );
    assert!(
        !no_anchor_message.contains("owner-anchored commit advances"),
        "a `no_anchor` marker must NOT offer the anchored advance — it cannot happen: \
         {no_anchor_message}"
    );
    assert_eq!(
        no_anchor["fork_quarantine"]["no_anchor"].as_bool(),
        Some(true)
    );

    // The group id is in the CLI hint so the remedy is copy-pasteable
    // rather than a template the operator has to fill in under
    // incident pressure.
    assert!(
        owner_message.contains(&group_id) && no_anchor_message.contains(&group_id),
        "the printed remedy names the group"
    );
    Ok(())
}

/// WHY (ADR-0066 §5 + R5 no-grace): the message must arrive on the
/// FIRST refused request after the marker installs. R5 rejected the
/// warn-only window, so there is no request budget, counter threshold or
/// elapsed-time window that lets one operation through unexplained; this
/// is the regression test for that rejected design, so a future
/// re-introduction of grace fails loudly instead of silently weakening
/// containment.
#[tokio::test]
async fn adr0066_first_request_after_install_is_refused_with_the_message() -> Result<()> {
    let (state, _dir, owner_kp) = owner_authority_state().await?;
    let group_id = "c3".repeat(32);
    let base =
        sealed_group_with_lineage(&state, &group_id, owner_certified_policy(&owner_kp)).await?;
    let fork_a = owner_seal_variant(&state, &base, "fork-a").await?;
    let fork_b = owner_seal_variant(&state, &base, "fork-b").await?;
    let first = apply_commit(
        &state,
        &group_id,
        fork_a.commit_log.last().expect("sealed").commit.clone(),
        "fork-a",
    )
    .await?;
    persist_applied(&state, &group_id, first.expect("applied")).await?;
    let second = apply_commit(
        &state,
        &group_id,
        fork_b.commit_log.last().expect("sealed").commit.clone(),
        "fork-b",
    )
    .await?;
    assert!(second.is_err(), "the twin conflicts");
    let marker_revision = live_record(&state, &group_id)
        .await
        .fork_quarantine
        .as_ref()
        .expect("marker installed")
        .revision;
    assert_eq!(
        diag_row(&state, &group_id)
            .await
            .counters
            .fork_quarantine_refusals,
        0,
        "no request has been refused yet — the first one below is the first"
    );

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
        "the very first request after the install is refused — no grace: {}",
        json.0
    );
    assert_fork_quarantine_refusal_body(&json.0);
    assert_eq!(
        json.0["fork_quarantine"]["revision"].as_u64(),
        Some(marker_revision),
        "the body names the divergence the live marker recorded, not a placeholder"
    );
    assert_eq!(
        diag_row(&state, &group_id)
            .await
            .counters
            .fork_quarantine_refusals,
        1,
        "§3e: one refusal, one increment — the message did not change the diagnostic contract"
    );
    Ok(())
}

/// WHY (ADR-0066 §2 table, the OPPOSITE direction — the trap this slice
/// had to avoid): `rollback_live_fork_evidence` looks identical to a clear
/// at the call site (`info.fork_quarantine = None`) and differs only in
/// provenance. A *clear* asserts the fork was resolved; a *rollback*
/// asserts the install never durably happened. Gating the rollback on
/// `no_anchor` — the intuitive "be consistent" move — would strand a
/// marker whose evidence was retracted by a benign persist retry, turning a
/// transient failure into an UNCLEARABLE quarantine on a group that never
/// forked as far as disk is concerned.
///
/// So this fixture asserts the rollback arm was NOT gated: a `no_anchor`
/// marker installed by a non-durable mutation IS rolled back on the exact
/// identity match, and the identical conflict then re-installs it durably.
#[tokio::test]
async fn adr0066_non_durable_install_rolls_back_a_no_anchor_marker() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "bb".repeat(32);
    let base = sealed_group_with_lineage(&state, &group_id, invite_only_policy()).await?;
    let fork_a = plain_seal_variant(&state, &base, "fork-a")?;
    let fork_b = plain_seal_variant(&state, &base, "fork-b")?;
    let first = apply_commit(&state, &group_id, fork_a, "fork-a").await?;
    assert!(first.is_ok());
    persist_applied(&state, &group_id, first.expect("applied")).await?;

    {
        // The install is visible in memory but never confirmed durable.
        let _fault = set_save_fault(&state, SaveFault::ReplacedNotDurable);
        let second = apply_commit(&state, &group_id, fork_b.clone(), "fork-b").await?;
        assert!(second.is_err(), "the conflicting twin is still refused");
        let record = live_record(&state, &group_id).await;
        assert!(
            !record.is_fork_quarantined(),
            "the `no_anchor` marker is rolled back with its evidence — an undo of an install is \
             NOT a clear, and leaving it would need a human to clear a quarantine that only ever \
             existed in memory"
        );
        assert!(
            record
                .invite_lineage
                .as_ref()
                .and_then(|lineage| lineage.fork_evidence.as_ref())
                .is_none(),
            "the evidence record rolls back with it, so the conflict stays retryable"
        );
        assert_eq!(
            diag_row(&state, &group_id)
                .await
                .counters
                .fork_quarantine_set,
            0,
            "nothing is counted for an install that never reached durability"
        );
    }

    let retry = apply_commit(&state, &group_id, fork_b, "fork-b").await?;
    assert!(retry.is_err());
    assert!(
        live_record(&state, &group_id)
            .await
            .fork_quarantine
            .as_ref()
            .is_some_and(|marker| marker.no_anchor),
        "the identical conflict re-installs the `no_anchor` marker durably"
    );
    Ok(())
}

/// WHY (ADR-0066 §2 "Clear is manual and only manual"): the manual
/// endpoint is the ONLY exit for an ordinary group, which makes it
/// load-bearing rather than a niche override. Two things must hold, and
/// both are easy to get wrong:
///
/// - the clear must WORK for a `no_anchor` marker — if the endpoint refused
///   it (for instance by demanding an owner attestation it can never mint),
///   an ordinary group's quarantine would be permanent and the §5 message
///   would name a remedy that does not exist;
/// - path (a) must still be unavailable: with no owner axis there is
///   nothing to attest with, so the endpoint must say `force_required`
///   rather than silently falling back.
#[tokio::test]
async fn adr0066_manual_clear_is_the_exit_for_a_no_anchor_marker() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "bd".repeat(32);
    let base = sealed_group_with_lineage(&state, &group_id, invite_only_policy()).await?;
    let fork_a = plain_seal_variant(&state, &base, "fork-a")?;
    let fork_b = plain_seal_variant(&state, &base, "fork-b")?;
    let first = apply_commit(&state, &group_id, fork_a, "fork-a").await?;
    assert!(first.is_ok());
    persist_applied(&state, &group_id, first.expect("applied")).await?;
    let second = apply_commit(&state, &group_id, fork_b, "fork-b").await?;
    assert!(second.is_err());
    assert!(live_record(&state, &group_id)
        .await
        .fork_quarantine
        .as_ref()
        .is_some_and(|marker| marker.no_anchor));

    // Path (a) is unreachable for this population, and says so.
    let req: ClearQuarantineRequest = serde_json::from_value(serde_json::json!({}))?;
    let response =
        clear_group_quarantine(State(Arc::clone(&state)), Path(group_id.clone()), Json(req))
            .await
            .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("force_required"),
        "an ordinary group has no owner axis to attest with: {body}"
    );
    assert!(
        live_record(&state, &group_id).await.is_fork_quarantined(),
        "a refused clear leaves the marker in place"
    );

    // Path (b): the operator override, with the audit reason the §5
    // message asks for.
    let req: ClearQuarantineRequest = serde_json::from_value(serde_json::json!({
        "force": true,
        "reason": "benign split confirmed by both operators",
    }))?;
    let response =
        clear_group_quarantine(State(Arc::clone(&state)), Path(group_id.clone()), Json(req))
            .await
            .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "the override clears: {body}");
    assert_eq!(body["cleared_by"].as_str(), Some("force"));
    let record = live_record(&state, &group_id).await;
    assert!(
        !record.is_fork_quarantined(),
        "the manual clear is the exit ADR-0066 §2 promises"
    );
    assert_eq!(
        diag_row(&state, &group_id)
            .await
            .counters
            .fork_quarantine_manual_clears,
        1,
        "the clear is attributable — this counter is what an operator's audit reads"
    );

    // The data plane serves again immediately.
    let req: SecureEncryptRequest =
        serde_json::from_value(serde_json::json!({ "payload_b64": "aGVsbG8=" }))?;
    let (status, json) = secure_group_encrypt(
        State(Arc::clone(&state)),
        Path(group_id.clone()),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Json(req),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::CONFLICT,
        "after the clear the route no longer refuses on quarantine grounds: {}",
        json.0
    );
    Ok(())
}

/// WHY (ADR-0066 §2 clear-arm table, asserted as a PREDICATE): the three
/// owner-anchored clear arms differ in their surroundings — one is fenced
/// by policy, one is not fenced at all, one lives on `GroupInfo` — but they
/// must agree on the decision. Sharing
/// [`x0x::groups::ForkQuarantine::owner_anchored_clear_permitted`] is what
/// makes drift impossible; this test pins the shared decision itself, so
/// the per-arm fixtures only have to prove each arm consults it.
///
/// The `no_anchor` clause is the load-bearing one: the ADR's own first
/// draft named the wrong arm, and the arm it missed
/// (`apply_named_group_metadata_event_inner`) has no owner-axis fence of
/// its own — it relied on the marker only ever existing for owner-axis
/// groups, which §2 invalidates. Without the flag test, extending the
/// marker to ordinary groups would hand them an automatic clear.
#[test]
fn adr0066_owner_anchored_clear_predicate_declines_no_anchor_markers() -> Result<()> {
    let anchored = synthetic_marker(false)?;
    let no_anchor = synthetic_marker(true)?;
    assert_eq!(anchored.revision, 7, "fixture precondition");

    assert!(
        anchored.owner_anchored_clear_permitted(8),
        "an owner-anchored advance PAST the evidenced revision clears an owner-axis marker"
    );
    assert!(
        !anchored.owner_anchored_clear_permitted(7),
        "ADR-0064 r2: a same-revision sibling — the contested branch itself — never clears"
    );
    assert!(
        !anchored.owner_anchored_clear_permitted(6),
        "nor does anything below the evidence"
    );

    for revision in [0, 6, 7, 8, u64::MAX] {
        assert!(
            !no_anchor.owner_anchored_clear_permitted(revision),
            "ADR-0066 §2: a `no_anchor` marker is never cleared by a commit, of ANY revision, \
             on any ancestry — only the manual clear lifts it (revision {revision})"
        );
    }
    Ok(())
}

/// WHY (ADR-0066 §2 table, site 3 — `clear_fork_quarantine_on_explicit_
/// owner_seal`): the explicit owner-key seal is unreachable for an ordinary
/// group in practice (it has no owner key), so this fixture documents the
/// invariant rather than a behaviour change. It is worth having anyway: the
/// arm's own fence is a test of the POLICY, and a `no_anchor` marker on an
/// owner-axis record — a group whose policy changed, or a marker restored
/// from a peer-era record — would otherwise clear through a route §2 says
/// nothing may clear.
///
/// Inert: `GroupInfo` plus a user keypair, no daemon.
#[test]
fn adr0066_explicit_owner_seal_declines_a_no_anchor_marker() -> Result<()> {
    let owner_kp = UserKeypair::from_seed(&[0x5Au8; 32])?;
    let agent_kp = AgentKeypair::generate()?;
    let seeded = |no_anchor: bool| -> Result<x0x::groups::GroupInfo> {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "explicit-seal-decline".to_string(),
            String::new(),
            crate::identity::AgentId::from_public_key(agent_kp.public_key()),
            "ab".repeat(32),
            owner_certified_policy(&owner_kp),
        );
        // The seal itself is not under test here (an owner-certified seal
        // needs ADR-0038 certificate evidence and an AppState); the clear
        // reads only the head revision, the policy and the marker, so the
        // post-seal head is set directly to keep the fixture inert.
        info.state_revision = 5;
        let header = info.terminal_commit_header();
        // The marker sits strictly BELOW the sealed revision, so the
        // strictly-greater fence is satisfied and `no_anchor` is the only
        // thing that can decide the outcome.
        info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision: info.state_revision.saturating_sub(1),
            state_hash: "evidenced-conflict-hash".to_string(),
            committed_by: "ff".repeat(32),
            observed_at_ms: now_millis_u64(),
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: header.clone(),
                conflicting_commit: header,
                classification: None,
            },
            no_anchor,
        });
        Ok(info)
    };

    let mut owner_axis = seeded(false)?;
    owner_axis.clear_fork_quarantine_on_explicit_owner_seal(Some(&owner_kp));
    assert!(
        !owner_axis.is_fork_quarantined(),
        "control: the owner-key seal DOES clear an anchored marker above the evidence — \
         otherwise this test could pass with the route simply broken"
    );

    let mut no_anchor = seeded(true)?;
    no_anchor.clear_fork_quarantine_on_explicit_owner_seal(Some(&owner_kp));
    assert!(
        no_anchor.is_fork_quarantined(),
        "ADR-0066 §2: the marker's own claim is authoritative over the policy's owner axis"
    );
    Ok(())
}

/// WHY (ADR-0066 Validation "Mixed-version serde fixtures both
/// directions"): the marker is persisted JSON, and `no_anchor` is the field
/// this slice starts writing. A marker written before ADR-0066 has no
/// `no_anchor` key at all, and it MUST decode as `false` — i.e. as the
/// owner-axis marker it was. If it decoded as `true`, every previously
/// quarantined owner-axis group would silently lose its automatic clear on
/// upgrade and need a human; if the field were not `#[serde(default)]` at
/// all, the whole record would fail to load and the group would come back
/// UNQUARANTINED, which is worse.
#[test]
fn adr0066_marker_persisted_before_the_field_decodes_as_owner_axis() -> Result<()> {
    let marker = synthetic_marker(true)?;
    let mut encoded = serde_json::to_value(&marker)?;
    // The pre-ADR-0066 on-disk shape: the key is simply absent.
    assert!(encoded
        .as_object_mut()
        .expect("marker encodes as an object")
        .remove("no_anchor")
        .is_some());
    let decoded: x0x::groups::ForkQuarantine = serde_json::from_value(encoded)?;
    assert!(
        !decoded.no_anchor,
        "an old persisted marker is an owner-axis marker and keeps its anchored clear path"
    );
    assert_eq!(
        decoded.revision, marker.revision,
        "and nothing else shifted"
    );

    // Forward direction: a `no_anchor` marker written by this binary
    // round-trips, so a restart does not quietly re-anchor an ordinary
    // group's quarantine.
    let round_tripped: x0x::groups::ForkQuarantine =
        serde_json::from_str(&serde_json::to_string(&marker)?)?;
    assert!(round_tripped.no_anchor, "the flag survives a restart");
    assert_eq!(round_tripped, marker, "and the record is byte-equal");
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// #732 — the STARTUP / JOURNAL-RECOVERY containment gap (GPT-6 Astra audit,
// findings 1 and 2).
//
// Both defects live on the file-level recovery path that runs BEFORE the
// in-memory roster loads and before any listener starts (`server::mod`
// ordering), so every fixture here is on-disk state plus the production
// recovery entry point — never a daemon.
// ───────────────────────────────────────────────────────────────────────────

/// A group sealed TWICE, so its retained commit log holds the revision-1
/// predecessor that `fork_candidate_authenticated` authenticates a
/// conflicting revision-2 commit against. Returns the base (revision 1), the
/// advanced record (revision 2) and the signer that sealed both.
fn recovery_fixture(
    group_id: &str,
    policy: GroupPolicy,
) -> Result<(x0x::groups::GroupInfo, x0x::groups::GroupInfo, AgentKeypair)> {
    let kp = AgentKeypair::generate()?;
    let mut info = x0x::groups::GroupInfo::with_policy(
        "recovery-under-test".to_string(),
        String::new(),
        crate::identity::AgentId::from_public_key(kp.public_key()),
        group_id.to_string(),
        policy,
    );
    info.seal_commit(&kp, now_millis_u64())?;
    let base = info.clone();
    info.description = "advanced".to_string();
    info.seal_commit(&kp, now_millis_u64())?;
    Ok((base, info, kp))
}

/// One record, encoded as the whole-file store image both the journal and the
/// live store files use.
fn store_image(key: &str, info: &x0x::groups::GroupInfo) -> Result<String> {
    let mut view: HashMap<String, x0x::groups::GroupInfo> = HashMap::new();
    view.insert(key.to_string(), info.clone());
    Ok(serde_json::to_string(&view)?)
}

async fn read_store(path: &std::path::Path) -> Result<HashMap<String, x0x::groups::GroupInfo>> {
    let json = tokio::fs::read_to_string(path).await?;
    Ok(serde_json::from_str(&json)?)
}

/// A durable `no_anchor` marker at the group's CURRENT frontier — the shape an
/// authenticated fork observation installs, which deliberately advances
/// neither `state_revision` nor `state_hash`.
fn marker_at_frontier(info: &x0x::groups::GroupInfo) -> x0x::groups::ForkQuarantine {
    x0x::groups::ForkQuarantine {
        revision: info.state_revision,
        state_hash: info.state_hash.clone(),
        committed_by: "9c".repeat(32),
        observed_at_ms: 1_700_000_000_000,
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: info.terminal_commit_header(),
            conflicting_commit: info.terminal_commit_header(),
            classification: None,
        },
        no_anchor: info.policy.admission.owner_certified_user_id().is_none(),
    }
}

fn evidence_at_frontier(info: &x0x::groups::GroupInfo) -> x0x::groups::ForkEvidence {
    x0x::groups::ForkEvidence {
        revision: info.state_revision,
        state_hash: info.state_hash.clone(),
        committed_by: "9c".repeat(32),
        observed_at_ms: 1_700_000_000_000,
    }
}

fn lineage_for(info: &x0x::groups::GroupInfo) -> x0x::groups::InviteLineage {
    x0x::groups::InviteLineage {
        base_revision: 1,
        base_hash: info.state_hash.clone(),
        base_roster_root: String::new(),
        seated_at_revision: None,
        corroborated: false,
        fork_evidence: None,
    }
}

/// WHY (#732 finding 1 — HIGH, CONFIRMED). A TreeKEM transaction whose
/// snapshot/cleanup step fails AFTER the named save reached durability leaves
/// BOTH journals at their live names on purpose (`persist_named_group_info`:
/// "never discard a journal whose named half is durable"). The live record is
/// then byte-equal to the journalled one, so the paired-replay verdict reads
/// equal-revision/equal-hash and returns `Apply`. But an ADR-0066 marker
/// installed in the meantime is NOT part of that frontier — the install
/// advances neither revision nor hash — and the replay's wholesale record
/// replacement therefore erased a containment decision that, being
/// `no_anchor`, nothing would ever re-install automatically. A restart lifted
/// the quarantine.
///
/// The claim this test defends: a marker is LOCAL containment state, and
/// journal equality is not equality of containment.
///
/// Its negative-control arm is what stops a vacuous pass: the journal image
/// genuinely carries no marker, and the replay still replaces every OTHER
/// field of the live record — so this is not "the replay stopped writing".
///
/// #732 r2: the second arm of this test used to pin the OPPOSITE rule — "a
/// journal record carrying its own marker keeps it" — which cross-model review
/// showed is wrong at one frontier, and which now lives inverted in
/// [`issue732_same_frontier_replay_takes_live_containment_including_absence`].
/// It is replaced rather than relaxed so the change of contract is visible in
/// the diff.
#[tokio::test]
async fn issue732_journal_replay_preserves_a_durable_quarantine_marker() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = dir.path().join("named_groups.json");
    let group_id = "d7".repeat(32);
    let (_base, mut advanced, _kp) = recovery_fixture(&group_id, invite_only_policy())?;
    advanced.invite_lineage = Some(lineage_for(&advanced));

    // The journal image: the record exactly as the transaction staged it.
    let journal_image = store_image(&group_id, &advanced)?;
    assert!(
        serde_json::from_str::<HashMap<String, x0x::groups::GroupInfo>>(&journal_image)?[&group_id]
            .fork_quarantine
            .is_none(),
        "negative control (a): the journal image must NOT already carry a marker, \
         or the assertion below passes without the fix"
    );

    // The live half: the SAME committed frontier, plus the containment a
    // later authenticated fork observation installed.
    let mut contained = advanced.clone();
    contained.fork_quarantine = Some(marker_at_frontier(&advanced));
    contained.description = "stale-live-description".to_string();
    if let Some(lineage) = contained.invite_lineage.as_mut() {
        lineage.fork_evidence = Some(evidence_at_frontier(&advanced));
    }
    write_named_groups_json_atomic(&store, &store_image(&group_id, &contained)?).await?;

    merge_group_record_into_store_file(&store, &group_id, &journal_image, "named groups").await?;

    let after = read_store(&store).await?;
    let record = &after[&group_id];
    assert!(
        record
            .fork_quarantine
            .as_ref()
            .is_some_and(|marker| marker.revision == advanced.state_revision && marker.no_anchor),
        "#732: the replay must carry the live marker forward — a restart is not a clear"
    );
    assert!(
        record
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.fork_evidence.as_ref())
            .is_some(),
        "#732: the evidence record that justifies the marker survives with it"
    );
    // Negative control (a), the other half: the journalled record still wins
    // everywhere else, so the fix did not disable the replay.
    assert_eq!(
        record.description, "advanced",
        "the journalled roster/metadata still applies — only containment is preserved"
    );
    assert_eq!(record.state_revision, advanced.state_revision);
    assert_eq!(record.state_hash, advanced.state_hash);

    Ok(())
}

/// The alias-keyed variant of the finding-1 repair: the live store files a
/// group under an alias key (map key ≠ stable group id) while the replay
/// inserts at the journal's `group_id_hex`. A single-spelling carry-forward
/// would miss the marker and the restart would lift the quarantine on exactly
/// the population ADR-0066's both-spellings rule exists for.
#[tokio::test]
async fn issue732_journal_replay_preserves_a_marker_on_an_alias_keyed_store() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = dir.path().join("named_groups.json");
    let group_id = "d8".repeat(32);
    let (_base, advanced, _kp) = recovery_fixture(&group_id, invite_only_policy())?;
    let mut contained = advanced.clone();
    contained.fork_quarantine = Some(marker_at_frontier(&advanced));
    // Filed under a human alias, exactly as the roster may key it.
    write_named_groups_json_atomic(&store, &store_image("recovery-under-test", &contained)?)
        .await?;
    assert_eq!(
        contained.stable_group_id(),
        advanced.stable_group_id(),
        "the alias record IS this group — the carry-forward must match on the stable id"
    );

    merge_group_record_into_store_file(
        &store,
        &group_id,
        &store_image(&group_id, &advanced)?,
        "named groups",
    )
    .await?;

    let after = read_store(&store).await?;
    assert!(
        !after.contains_key("recovery-under-test"),
        "the alias is superseded by the stable id, as before #732"
    );
    assert!(
        after[&group_id].fork_quarantine.is_some(),
        "#732: the marker is carried across the re-key — both spellings are consulted"
    );
    Ok(())
}

/// The same finding-1 repair through the REAL startup entry point, with the
/// journal pair retained on disk the way a post-commit snapshot failure
/// leaves it: `recover_treekem_named_journals` must replay the trio forward
/// (snapshot written, journal consumed) and still leave the group contained.
#[tokio::test]
async fn issue732_startup_replay_leaves_the_group_contained() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let treekem = dir.path().join("treekem");
    tokio::fs::create_dir_all(&treekem).await?;
    let named_path = dir.path().join("named_groups.json");
    let sidecar_path = dir.path().join(HOME_SUITE_GROUPS_FILE);
    let group_id = "d9".repeat(32);
    let (_base, advanced, _kp) = recovery_fixture(&group_id, invite_only_policy())?;

    let mut contained = advanced.clone();
    contained.fork_quarantine = Some(marker_at_frontier(&advanced));
    write_named_groups_json_atomic(&named_path, &store_image(&group_id, &contained)?).await?;

    // The retained legacy journal (no `.hsjournal`: an ordinary group's
    // sidecar half changes nothing) plus the snapshot the failed step owed.
    let envelope = vec![9u8; 24];
    let journal = TreeKemNamedPersistJournal {
        version: TREEKEM_NAMED_JOURNAL_VERSION,
        group_id_hex: group_id.clone(),
        named_groups_json: store_image(&group_id, &advanced)?,
        snapshot_envelope: envelope.clone(),
    };
    x0x::storage::write_private_bytes(
        &treekem_journal_path(&treekem, &group_id),
        postcard::to_stdvec(&journal)?,
    )
    .await?;

    recover_treekem_named_journals(&named_path, &sidecar_path, &treekem).await?;

    assert!(
        read_store(&named_path).await?[&group_id]
            .fork_quarantine
            .as_ref()
            .is_some_and(|marker| marker.no_anchor),
        "#732: a restart that replays a retained journal must not lift the quarantine"
    );
    assert_eq!(
        tokio::fs::read(treekem.join(format!("{group_id}.snap"))).await?,
        envelope,
        "and the replay still completes the trio it exists for"
    );
    assert!(
        !treekem_journal_path(&treekem, &group_id).exists(),
        "the journal is consumed once the live files are durable"
    );
    Ok(())
}

/// A conflicting sibling at the SAME revision: signed, structurally valid,
/// and (when `signer` holds the revision-1 seat) authenticated.
fn conflicting_sibling(
    base: &x0x::groups::GroupInfo,
    signer: &AgentKeypair,
    description: &str,
) -> Result<x0x::groups::GroupInfo> {
    let mut variant = base.clone();
    variant.description = description.to_string();
    variant.seal_commit(signer, now_millis_u64())?;
    Ok(variant)
}

/// WHY (#732 finding 2 — HIGH, CONFIRMED). ADR-0066 §2's whole purpose is
/// that an ORDINARY group is one population, not two: a group formed without
/// an invite has no lineage record to hold evidence, so the MARKER is the
/// record. Slice 2 widened the LIVE apply fence and left the recovery path
/// lineage-fenced as a named residual. The consequence at startup was the
/// exact silence §2 exists to close: `record_recovery_fork_evidence` returned
/// before doing anything, the conflicting journals were moved aside, startup
/// continued — and the live group's data plane served both branches of an
/// authenticated fork with no marker and no operator signal.
///
/// The claim: the recovery path installs the same marker-only,
/// first-complete-wins, `no_anchor: true` containment the live path does, and
/// the restored record then refuses the data plane with the §5 body.
#[tokio::test]
async fn issue732_startup_quarantines_a_lineage_free_ordinary_group() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let treekem = dir.path().join("treekem");
    tokio::fs::create_dir_all(&treekem).await?;
    let named_path = dir.path().join("named_groups.json");
    let sidecar_path = dir.path().join(HOME_SUITE_GROUPS_FILE);
    let group_id = "da".repeat(32);
    let (base, live, signer) = recovery_fixture(&group_id, invite_only_policy())?;
    assert!(
        live.invite_lineage.is_none(),
        "the fixture's whole point: an ordinary group that never held an invite"
    );

    // The journal's record is the OTHER branch: same revision, different
    // state hash, sealed by a holder of the retained revision-1 seat.
    let fork = conflicting_sibling(&base, &signer, "the-other-branch")?;
    assert_eq!(fork.state_revision, live.state_revision);
    assert_ne!(
        fork.state_hash, live.state_hash,
        "equal revision, different hash — the only shape the verdict calls Fork"
    );

    write_named_groups_json_atomic(&named_path, &store_image(&group_id, &live)?).await?;
    let journal = TreeKemNamedPersistJournal {
        version: TREEKEM_NAMED_JOURNAL_VERSION,
        group_id_hex: group_id.clone(),
        named_groups_json: store_image(&group_id, &fork)?,
        snapshot_envelope: vec![3u8; 8],
    };
    x0x::storage::write_private_bytes(
        &treekem_journal_path(&treekem, &group_id),
        postcard::to_stdvec(&journal)?,
    )
    .await?;

    recover_treekem_named_journals(&named_path, &sidecar_path, &treekem).await?;

    let restored = read_store(&named_path).await?[&group_id].clone();
    let marker = restored.fork_quarantine.clone().ok_or_else(|| {
        anyhow::anyhow!("#732: the lineage-free ordinary group must be contained")
    })?;
    assert!(
        marker.no_anchor,
        "ADR-0066 §2: no owner axis ⇒ no anchor ⇒ only the manual clear lifts it"
    );
    assert_eq!(marker.revision, fork.state_revision);
    assert_eq!(marker.state_hash, fork.state_hash);
    assert!(
        restored.invite_lineage.is_none(),
        "provenance is not invented to hold evidence — the marker IS the record"
    );
    assert_eq!(
        restored.state_hash, live.state_hash,
        "containment is not adoption: the live branch is untouched"
    );

    // The restored record refuses the data plane. Rows 4/5/6 are exercised
    // directly here because their §3 gate sits ahead of every membership and
    // GSS precondition; rows 1–3 consult the SAME `is_fork_quarantined()`
    // predicate on the same record, pinned by `adr0066_send_path` and
    // `adr0066_treekem_gates`.
    let (state, _state_dir) = secure_endpoint_test_state().await?;
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), restored.clone());
    assert!(
        restored.is_fork_quarantined(),
        "the predicate every §1 row consults is true after the restart"
    );
    let (status, body) = secure_group_encrypt(
        State(Arc::clone(&state)),
        Path(group_id.clone()),
        axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Json(serde_json::from_value::<SecureEncryptRequest>(
            serde_json::json!({ "payload_b64": "aGVsbG8=" }),
        )?),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "row 4 refuses: {}", body.0);
    assert_fork_quarantine_refusal_body(&body.0);
    let (status, body) = secure_group_decrypt(
        State(Arc::clone(&state)),
        Path(group_id.clone()),
        Json(serde_json::from_value::<SecureDecryptRequest>(
            serde_json::json!({ "ciphertext_b64": "aGVsbG8=" }),
        )?),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "row 5 refuses: {}", body.0);
    assert_fork_quarantine_refusal_body(&body.0);
    let (status, body) = secure_group_reseal(
        State(Arc::clone(&state)),
        Path(group_id.clone()),
        Json(serde_json::from_value::<ResealRequest>(
            serde_json::json!({ "recipient": "ab".repeat(32) }),
        )?),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "row 6 refuses: {}", body.0);
    assert_fork_quarantine_refusal_body(&body.0);
    Ok(())
}

/// The negative control for finding 2, and the security boundary of the
/// whole repair (ADR-0064 Attack matrix "false quarantine"): a `no_anchor`
/// marker never auto-clears, so if an UNAUTHENTICATED journal could install
/// one, anyone who could drop a file in the data directory — or a benign
/// retry artifact — would take an ordinary group's data plane offline until a
/// human intervened. The recovery install therefore runs behind the SAME
/// `fork_candidate_authenticated` gate as the live path: signature verify
/// plus committer Active+Admin in the retained predecessor roster.
///
/// Delete the authentication and this test fails while the positive test
/// above still passes — that pair is what makes the gate observable.
#[tokio::test]
async fn issue732_unauthenticated_startup_conflict_quarantines_nothing() -> Result<()> {
    for (label, group_id, forge) in [
        ("stranger-signed", "db".repeat(32), false),
        ("forged-signature", "dc".repeat(32), true),
    ] {
        let dir = tempfile::tempdir()?;
        let treekem = dir.path().join("treekem");
        tokio::fs::create_dir_all(&treekem).await?;
        let named_path = dir.path().join("named_groups.json");
        let sidecar_path = dir.path().join(HOME_SUITE_GROUPS_FILE);
        let (base, live, signer) = recovery_fixture(&group_id, invite_only_policy())?;

        let mut fork = if forge {
            conflicting_sibling(&base, &signer, "forged")?
        } else {
            // Genuinely signed, by a key that holds no seat in the retained
            // predecessor roster.
            conflicting_sibling(&base, &AgentKeypair::generate()?, "stranger")?
        };
        if forge {
            if let Some(retained) = fork.commit_log.last_mut() {
                retained.commit.signature = "not-a-signature".to_string();
            }
        }
        assert_eq!(fork.state_revision, live.state_revision, "{label}");
        assert_ne!(fork.state_hash, live.state_hash, "{label}");

        write_named_groups_json_atomic(&named_path, &store_image(&group_id, &live)?).await?;
        let journal = TreeKemNamedPersistJournal {
            version: TREEKEM_NAMED_JOURNAL_VERSION,
            group_id_hex: group_id.clone(),
            named_groups_json: store_image(&group_id, &fork)?,
            snapshot_envelope: vec![4u8; 8],
        };
        x0x::storage::write_private_bytes(
            &treekem_journal_path(&treekem, &group_id),
            postcard::to_stdvec(&journal)?,
        )
        .await?;

        recover_treekem_named_journals(&named_path, &sidecar_path, &treekem).await?;

        assert!(
            !read_store(&named_path).await?[&group_id].is_fork_quarantined(),
            "#732 ({label}): an unauthenticated journal conflict must never install a \
             never-auto-clearing marker — that is a local/remote denial of service"
        );
    }
    Ok(())
}

/// The owner axis is deliberately unchanged (ADR-0066 §2 Migration table:
/// "trigger is unchanged" for owner-axis groups). An owner-certified group
/// WITHOUT lineage is an authority-side record, not a joiner stub, so the
/// recovery path must still install nothing for it — `fork_evidence_path_open`
/// is the single predicate both paths now use, and this test is what stops
/// #732's widening from leaking into that population.
#[tokio::test]
async fn issue732_owner_axis_lineage_free_group_is_unchanged_at_startup() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let treekem = dir.path().join("treekem");
    tokio::fs::create_dir_all(&treekem).await?;
    let named_path = dir.path().join("named_groups.json");
    let sidecar_path = dir.path().join(HOME_SUITE_GROUPS_FILE);
    let group_id = "dd".repeat(32);
    // The PRODUCTION owner-certified seal (ADR-0038 requires certificate
    // evidence), driven twice so the commit log retains the revision-1
    // predecessor — and no lineage record is ever added.
    let (state, _state_dir, owner) = owner_authority_state().await?;
    let signer = state.agent.identity().agent_keypair();
    let mut live = x0x::groups::GroupInfo::with_policy(
        "owner-axis-recovery".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.clone(),
        owner_certified_policy(&owner),
    );
    seal_commit_owner_certified(&state, &mut live, signer, now_millis_u64()).await?;
    let base = live.clone();
    live.description = "advanced".to_string();
    seal_commit_owner_certified(&state, &mut live, signer, now_millis_u64()).await?;
    assert!(
        live.invite_lineage.is_none() && live.policy.admission.owner_certified_user_id().is_some(),
        "owner axis, no lineage — the population whose trigger must not move"
    );
    let mut fork = base.clone();
    fork.description = "the-other-branch".to_string();
    seal_commit_owner_certified(&state, &mut fork, signer, now_millis_u64()).await?;
    assert_eq!(fork.state_revision, live.state_revision);
    assert_ne!(fork.state_hash, live.state_hash);

    write_named_groups_json_atomic(&named_path, &store_image(&group_id, &live)?).await?;
    let journal = TreeKemNamedPersistJournal {
        version: TREEKEM_NAMED_JOURNAL_VERSION,
        group_id_hex: group_id.clone(),
        named_groups_json: store_image(&group_id, &fork)?,
        snapshot_envelope: vec![5u8; 8],
    };
    x0x::storage::write_private_bytes(
        &treekem_journal_path(&treekem, &group_id),
        postcard::to_stdvec(&journal)?,
    )
    .await?;

    recover_treekem_named_journals(&named_path, &sidecar_path, &treekem).await?;

    assert!(
        !read_store(&named_path).await?[&group_id].is_fork_quarantined(),
        "#732 must not move the owner-axis trigger ADR-0066 promised unchanged"
    );
    Ok(())
}

/// Write a legacy TreeKEM journal (no `.hsjournal`: an ordinary group's
/// sidecar half changes nothing) holding `record` as its staged image.
async fn stage_journal(
    treekem: &std::path::Path,
    group_id: &str,
    record: &x0x::groups::GroupInfo,
) -> Result<()> {
    let journal = TreeKemNamedPersistJournal {
        version: TREEKEM_NAMED_JOURNAL_VERSION,
        group_id_hex: group_id.to_string(),
        named_groups_json: store_image(group_id, record)?,
        snapshot_envelope: vec![6u8; 12],
    };
    x0x::storage::write_private_bytes(
        &treekem_journal_path(treekem, group_id),
        postcard::to_stdvec(&journal)?,
    )
    .await?;
    Ok(())
}

/// One on-disk recovery scenario: write the live store and the staged journal,
/// run the REAL startup entry, hand back the record it left behind.
async fn replay_scenario(
    group_id: &str,
    live: &x0x::groups::GroupInfo,
    staged: &x0x::groups::GroupInfo,
    live_key: &str,
) -> Result<x0x::groups::GroupInfo> {
    let dir = tempfile::tempdir()?;
    let treekem = dir.path().join("treekem");
    tokio::fs::create_dir_all(&treekem).await?;
    let named_path = dir.path().join("named_groups.json");
    let sidecar_path = dir.path().join(HOME_SUITE_GROUPS_FILE);
    write_named_groups_json_atomic(&named_path, &store_image(live_key, live)?).await?;
    stage_journal(&treekem, group_id, staged).await?;
    recover_treekem_named_journals(&named_path, &sidecar_path, &treekem).await?;
    let after = read_store(&named_path).await?;
    let record = after
        .get(group_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("the replay left no record under the stable id"))?;
    // #732 r5 (review point 2): assert the AUTHORITATIVE in-memory view the
    // daemon actually loads, not just the file on disk. With no sidecar these
    // must agree; asserting it here makes that an invariant every fixture
    // inherits rather than an argument.
    let merged = load_named_groups_merged(&named_path, &sidecar_path).await?;
    assert_eq!(
        merged
            .get(group_id)
            .and_then(|info| info.fork_quarantine.clone()),
        record.fork_quarantine,
        "the merged authoritative view must carry the same containment as the named store"
    );
    Ok(record)
}

/// WHY (#732 r2 — cross-model review, Codex P2-b and omp nit (a); this test
/// INVERTS an assertion the first round shipped). The first repair only FILLED
/// an empty journal slot, which is wrong in both directions at one frontier:
///
/// - **resurrection.** A manual clear advances no revision
///   (`clear_group_quarantine` sets `fork_quarantine = None` and re-arms the
///   evidence gate; the committed frontier is untouched). So a journal staged
///   BEFORE the clear replays at the SAME frontier afterwards, and its own
///   stale marker was written straight back: a restart undid an operator's
///   durable clear, on a marker that then needs clearing again.
/// - **replacement.** Two markers at one frontier meant the journal's won,
///   even though the live one is the node's current containment decision and
///   may be the stronger (`no_anchor`) of the two.
///
/// The rule: at the same committed frontier the containment PAIR is the live
/// one, its ABSENCE included. There is exactly one containment truth per
/// frontier and it is local — the journal is a snapshot of metadata, not of
/// this node's decisions.
///
/// Negative control, in the same test: the journalled record still wins on
/// every other field in BOTH arms, so this is not "same-frontier replays stop
/// writing".
#[tokio::test]
async fn issue732_same_frontier_replay_takes_live_containment_including_absence() -> Result<()> {
    let group_id = "de".repeat(32);
    let (_base, advanced, _kp) = recovery_fixture(&group_id, invite_only_policy())?;

    // Arm 1 — RESURRECTION. Live was cleared; the staged image predates the
    // clear and still carries the marker.
    let mut cleared = advanced.clone();
    cleared.fork_quarantine = None;
    cleared.description = "cleared-live".to_string();
    let mut stale = advanced.clone();
    stale.fork_quarantine = Some(marker_at_frontier(&advanced));
    assert_eq!(
        stale.state_hash, cleared.state_hash,
        "a marker install and a clear both leave the frontier alone — that is the whole defect"
    );
    let after = replay_scenario(&group_id, &cleared, &stale, &group_id).await?;
    assert!(
        after.fork_quarantine.is_none(),
        "#732 r2: a restart must not resurrect a marker the operator durably cleared"
    );
    assert_eq!(
        after.description, "advanced",
        "negative control: the journalled record still wins everywhere else"
    );

    // Arm 2 — REPLACEMENT. Both halves carry a marker at one frontier; the
    // LIVE one is the node's decision.
    let mut live_marked = advanced.clone();
    let mut live_marker = marker_at_frontier(&advanced);
    live_marker.observed_at_ms = 1_800_000_000_000;
    live_marked.fork_quarantine = Some(live_marker);
    live_marked.description = "stale-live".to_string();
    let mut journal_marked = advanced.clone();
    let mut journal_marker = marker_at_frontier(&advanced);
    journal_marker.observed_at_ms = 1_600_000_000_000;
    journal_marked.fork_quarantine = Some(journal_marker);
    let after = replay_scenario(&group_id, &live_marked, &journal_marked, &group_id).await?;
    assert_eq!(
        after
            .fork_quarantine
            .as_ref()
            .map(|marker| marker.observed_at_ms),
        Some(1_800_000_000_000),
        "#732 r2: the LIVE marker survives — a journal marker does not override local containment"
    );
    assert_eq!(after.description, "advanced", "negative control, arm 2");
    Ok(())
}

/// The alias-keyed variant of the same-frontier rule: a live store that files
/// the cleared record under an alias must still have its CLEAR honoured when
/// the replay re-keys the record to the stable id. A single-spelling resolve
/// would find no live half, fall through to "the journal record as staged",
/// and resurrect the marker on exactly the population ADR-0066's
/// both-spellings rule exists for.
#[tokio::test]
async fn issue732_same_frontier_alias_keyed_clear_is_not_resurrected() -> Result<()> {
    let group_id = "df".repeat(32);
    let (_base, advanced, _kp) = recovery_fixture(&group_id, invite_only_policy())?;
    let mut cleared = advanced.clone();
    cleared.fork_quarantine = None;
    let mut stale = advanced.clone();
    stale.fork_quarantine = Some(marker_at_frontier(&advanced));

    let after = replay_scenario(&group_id, &cleared, &stale, "recovery-under-test").await?;
    assert!(
        after.fork_quarantine.is_none(),
        "#732 r2: the alias-keyed live half is found, so its clear is honoured"
    );
    Ok(())
}

/// A three-revision owner-axis fixture through the PRODUCTION owner-certified
/// seal (ADR-0038 requires certificate evidence, so `seal_commit` alone cannot
/// build one). Returns the record at revision 2 and the same record advanced to
/// revision 3 — the shape a staged owner-anchored advance leaves on disk.
async fn owner_axis_advance_fixture(
    group_id: &str,
) -> Result<(
    Arc<AppState>,
    tempfile::TempDir,
    x0x::groups::GroupInfo,
    x0x::groups::GroupInfo,
)> {
    let (state, dir, owner) = owner_authority_state().await?;
    let signer = state.agent.identity().agent_keypair();
    let mut info = x0x::groups::GroupInfo::with_policy(
        "owner-axis-advance".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.to_string(),
        owner_certified_policy(&owner),
    );
    // ADR-0038: bind the builder-issued certificate into the creator's roster
    // entry, so the roster ATTESTS that this agent is the policy owner's own —
    // the trust `trusted_owner_public_key` derives and the one the recovery
    // predicate needs. Without it an owner-axis roster names no owner agent at
    // all and no replayed advance can be owner-provenanced (fail closed).
    let creator_hex = hex::encode(state.agent.agent_id().as_bytes());
    let cert = state
        .agent
        .agent_certificate()
        .ok_or_else(|| anyhow::anyhow!("builder-issued certificate"))?
        .clone();
    info.set_member_certificate(&creator_hex, cert)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    seal_commit_owner_certified(&state, &mut info, signer, now_millis_u64()).await?;
    info.description = "at-revision-two".to_string();
    seal_commit_owner_certified(&state, &mut info, signer, now_millis_u64()).await?;
    let at_two = info.clone();
    info.description = "the-anchored-advance".to_string();
    seal_commit_owner_certified(&state, &mut info, signer, now_millis_u64()).await?;
    assert_eq!(at_two.state_revision + 1, info.state_revision);
    Ok((state, dir, at_two, info))
}

/// WHY (#732 r4 — this test is the INVERSE of what r2 and r3 shipped, and the
/// change of contract is deliberately visible in the diff).
///
/// r2 let a forward replay honour a clear on the journal's unsigned outer
/// revision. r3 required the journalled advance to be a verified, head-chaining
/// commit signed by an agent the live roster certified under the policy owner.
/// Both reviewers then showed that the last condition is not owner
/// authorization at all: in an OwnerCertified group EVERY seated member's
/// certificate binds the owner key, quarantine evicts nobody, so the FORKER —
/// seated, holding only its own agent key — can sign a fresh higher-revision
/// DESCENDANT of the contested live head and satisfy every check. Ancestry
/// excludes the other existing branch; it cannot stop this branch being
/// extended. `GroupInfo::clear_fork_quarantine_on_explicit_owner_seal` makes
/// the distinction explicit by rejecting a certificate verdict as an owner
/// anchor and demanding the owner USER key.
///
/// Neither that key nor an `OwnerMandate` is persisted with a group record, so
/// there is nothing on disk from which recovery could establish equal-strength
/// authorization — and #732 does not add persistence for it, because that is a
/// schema change owed its own ADR.
///
/// So the rule is now simply: a FORWARD replay NEVER lifts containment. The
/// liveness cost is real and named in the runbook — a clear interrupted between
/// staging and saving leaves the marker, and the operator clears it once by hand
/// — and it is the price of not handing the contained adversary a bypass.
#[tokio::test]
async fn issue732_forward_replay_never_lifts_containment() -> Result<()> {
    let group_id = "e1".repeat(32);
    let (_state, _dir, at_two, at_three) = owner_axis_advance_fixture(&group_id).await?;

    // THE STRONGEST-POSSIBLE GENUINE ADVANCE: owner-axis, `no_anchor: false`,
    // sealed through the production owner-certified seal by the owner's own
    // certificate-bound agent, chaining directly from the live head, at a
    // revision strictly past the evidence — everything r3's predicate asked
    // for, and everything the production clear predicate asks for BAR the owner
    // user key, which no journal carries. It still must not clear.
    let mut live = at_two.clone();
    let marker = marker_at_frontier(&at_two);
    assert!(
        !marker.no_anchor,
        "the fixture uses the only marker kind a commit could ever clear"
    );
    assert!(
        marker.owner_anchored_clear_permitted(at_three.state_revision),
        "the PRODUCTION clear predicate is satisfied — so any refusal below is \
         attributable to the missing owner authorization, not to that predicate"
    );
    assert_eq!(
        at_three
            .commit_log
            .last()
            .map(|r| r.commit.prev_state_hash.clone()),
        Some(Some(at_two.state_hash.clone())),
        "and the advance really chains from the live head"
    );
    live.fork_quarantine = Some(marker);

    let after = replay_scenario(&group_id, &live, &at_three, &group_id).await?;
    assert!(
        after.fork_quarantine.is_some(),
        "#732 r4: NO replayed advance lifts containment — a certificate verdict is \
         not owner authorization, and the forker holds one too"
    );
    assert_eq!(
        after.state_revision, at_three.state_revision,
        "negative control: the advance is still APPLIED — only containment is kept"
    );
    assert_eq!(
        after.description, at_three.description,
        "negative control: the journalled record still wins on every other field"
    );

    // Control 1 — a `no_anchor` marker is likewise never lifted. Only the
    // manual clear removes it, and a manual clear is a same-frontier event.
    let mut live_no_anchor = at_two.clone();
    let mut no_anchor = marker_at_frontier(&at_two);
    no_anchor.no_anchor = true;
    live_no_anchor.fork_quarantine = Some(no_anchor);
    assert!(
        replay_scenario(&group_id, &live_no_anchor, &at_three, &group_id)
            .await?
            .fork_quarantine
            .is_some_and(|marker| marker.no_anchor),
        "a `no_anchor` marker survives a forward replay — the manual-only rule holds on disk too"
    );

    // Control 2 — an anchored revision that is NOT strictly past the
    // evidenced one buys no clear (ADR-0064 r2: a same-revision sibling is
    // the contested branch itself).
    let mut live_same_revision = at_two.clone();
    let mut at_advance = marker_at_frontier(&at_two);
    at_advance.revision = at_three.state_revision;
    assert!(!at_advance.owner_anchored_clear_permitted(at_three.state_revision));
    live_same_revision.fork_quarantine = Some(at_advance);
    assert!(
        replay_scenario(&group_id, &live_same_revision, &at_three, &group_id)
            .await?
            .fork_quarantine
            .is_some(),
        "an advance level with the evidence revision does not clear"
    );

    // Control 3 — when the journal image carries its OWN marker at the higher
    // frontier, both halves assert containment and the STRONGER one survives
    // (#732 r5, `challenger_containment_is_stronger`): here that is the journalled marker,
    // whose higher `revision` is a HIGHER clear threshold. "Never lifted" is
    // also "never weakened", so the arm asserts the stronger threshold — not
    // "live always wins", which would have let a journalled rev-2 marker
    // replace a live rev-7 one.
    let mut staged_marked = at_three.clone();
    staged_marked.fork_quarantine = Some(marker_at_frontier(&at_three));
    let kept = replay_scenario(&group_id, &live, &staged_marked, &group_id)
        .await?
        .fork_quarantine
        .ok_or_else(|| anyhow::anyhow!("containment must survive"))?;
    assert_eq!(
        kept.revision, at_three.state_revision,
        "the STRONGER of the two markers is kept when both halves assert containment"
    );
    assert!(
        !kept.owner_anchored_clear_permitted(at_three.state_revision),
        "and the surviving threshold is the higher one — this advance cannot clear it"
    );

    // Control 4 (#732 r6, omp's r5 nit) — MARKER AND EVIDENCE ARE ONE DECISION.
    // Every clear arm removes them together
    // (`GroupInfo::reset_fork_evidence_after_quarantine_clear`), so the evidence
    // must follow the marker that WINS. r5 applied the evidence outside the
    // strength gate, which let the LOSING half's evidence replace the winner's —
    // producing a record that paired one observation's marker with another's
    // evidence. Here the journalled marker wins on revision, so the journalled
    // evidence must survive with it.
    let mut live_with_evidence = live.clone();
    live_with_evidence.invite_lineage = Some(lineage_for(&at_two));
    if let Some(lineage) = live_with_evidence.invite_lineage.as_mut() {
        let mut losing = evidence_at_frontier(&at_two);
        losing.committed_by = "11".repeat(32);
        losing.observed_at_ms = 111;
        lineage.fork_evidence = Some(losing);
    }
    let mut staged_winning = at_three.clone();
    staged_winning.fork_quarantine = Some(marker_at_frontier(&at_three));
    staged_winning.invite_lineage = Some(lineage_for(&at_three));
    if let Some(lineage) = staged_winning.invite_lineage.as_mut() {
        let mut winning = evidence_at_frontier(&at_three);
        winning.committed_by = "22".repeat(32);
        winning.observed_at_ms = 222;
        lineage.fork_evidence = Some(winning);
    }
    let after = replay_scenario(&group_id, &live_with_evidence, &staged_winning, &group_id).await?;
    assert_eq!(
        after.fork_quarantine.as_ref().map(|marker| marker.revision),
        Some(at_three.state_revision),
        "the journalled marker wins on revision"
    );
    assert_eq!(
        after
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.fork_evidence.as_ref())
            .map(|evidence| evidence.observed_at_ms),
        Some(222),
        "#732 r6: the WINNING marker's own evidence survives with it — the losing half's \
         evidence may only fill an empty slot, never replace it"
    );
    Ok(())
}

/// WHY (#732 r2 — cross-model review, Codex P1). `fork_candidate_authenticated`
/// proves the journal's terminal commit is genuine, but a `GroupInfo`'s OUTER
/// `state_revision`/`state_hash` are plain fields beside the commit log. A
/// local journal writer could copy the live record, alter ONLY the outer hash,
/// and keep the untouched valid commit: the paired-replay verdict compares
/// those outer scalars, so it declared a fork, and the lineage-free arm then
/// installed PERMANENT `no_anchor` containment with no authenticated
/// CONFLICTING commit behind it. Severity is bounded — it needs a local writer
/// in the data directory, no remote induction was established — but the cost of
/// binding is two comparisons and the damage is a quarantine nothing
/// auto-clears.
///
/// The rule: the frontier the journal CLAIMS must be the frontier its verified
/// commit SIGNS, and that commit must genuinely differ from the live committed
/// state at the same revision.
///
/// The control is in this test rather than elsewhere: the SAME fixture with a
/// genuinely different signed commit still installs the marker. Without that
/// pair, "install nothing" would satisfy the forged arm.
#[tokio::test]
async fn issue732_forged_outer_hash_journal_installs_no_marker() -> Result<()> {
    let group_id = "e2".repeat(32);
    let (base, live, signer) = recovery_fixture(&group_id, invite_only_policy())?;

    // The forgery: the LIVE record verbatim — its terminal commit still
    // verifies and its committer still holds the revision-1 seat — with only
    // the outer state hash rewritten so the verdict sees a fork.
    let mut forged = live.clone();
    forged.state_hash = "ff".repeat(32);
    assert_eq!(
        forged
            .commit_log
            .last()
            .map(|retained| retained.commit.state_hash.clone()),
        live.commit_log
            .last()
            .map(|retained| retained.commit.state_hash.clone()),
        "the commit is untouched — only the record's outer claim was edited"
    );
    assert!(
        !replay_scenario(&group_id, &live, &forged, &group_id)
            .await?
            .is_fork_quarantined(),
        "#732 r2: a claimed frontier that no verified commit signs installs nothing"
    );

    // The control: a genuinely different signed commit at the same revision
    // IS a fork, and still quarantines. Delete the binding and the arm above
    // fails; delete the install and this arm fails.
    let genuine = conflicting_sibling(&base, &signer, "the-other-branch")?;
    assert!(
        replay_scenario(&group_id, &live, &genuine, &group_id)
            .await?
            .fork_quarantine
            .is_some_and(|marker| marker.no_anchor),
        "the authenticated conflict still installs the marker — the binding is not a blanket refusal"
    );
    Ok(())
}

/// WHY. A forward journal replay never lifts containment (see
/// [`issue732_forward_replay_never_lifts_containment`] for the rule and the note
/// above `install_fork_evidence` for why no replayed advance can be owner
/// authorization). These arms are the four distinct forgeries that #732's
/// earlier, narrower rules each admitted — an unsigned bumped outer revision, a
/// signed advance on another branch, a non-owner committer, and an ordinary
/// group — kept so the refusal cannot be quietly re-narrowed to one shape. The
/// APPLY side is the control: every arm asserts the record still advances, so
/// "nothing was written" cannot pass for "containment survived".
#[tokio::test]
async fn issue732_forged_forward_journal_cannot_lift_containment() -> Result<()> {
    let group_id = "e3".repeat(32);
    let (_state, _dir, at_two, at_three) = owner_axis_advance_fixture(&group_id).await?;
    let mut live = at_two.clone();
    let marker = marker_at_frontier(&at_two);
    assert!(
        marker.owner_anchored_clear_permitted(at_three.state_revision),
        "the marker itself permits the GENUINE advance — so any refusal below is \
         attributable to the authentication, not to the clear predicate"
    );
    live.fork_quarantine = Some(marker);
    // A lineage record so the evidence half of the containment pair is
    // observable too: the attack removes BOTH, so both must survive.
    live.invite_lineage = Some(lineage_for(&at_two));
    if let Some(lineage) = live.invite_lineage.as_mut() {
        lineage.fork_evidence = Some(evidence_at_frontier(&at_two));
    }

    // Forgery 1 — THE ATTACK. Clone the live record, bump only the unsigned
    // outer revision, strip the marker. The terminal commit is the one that
    // sealed revision 2, so nothing signs revision 3.
    let mut bumped = at_two.clone();
    bumped.fork_quarantine = None;
    // The attacker strips the whole containment PAIR — marker and evidence —
    // which is what makes the lift durable; both must come back.
    bumped.invite_lineage = Some(lineage_for(&at_two));
    bumped.state_revision = at_three.state_revision;
    let after = replay_scenario(&group_id, &live, &bumped, &group_id).await?;
    assert!(
        after.fork_quarantine.is_some(),
        "#732 r3: an UNSIGNED forward revision must not lift containment — recovery \
         may not be a cheaper clear than the live arms"
    );
    assert!(
        after
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.fork_evidence.as_ref())
            .is_some(),
        "and the evidence that justifies the marker is not dropped either"
    );

    // Forgery 2 — a genuinely signed advance that does NOT chain from this
    // node's head: a sibling sealed over revision 1, so it advances some other
    // branch. Ancestry is what the live apply arm gets by construction.
    let (state_b, _dir_b, owner_b) = owner_authority_state().await?;
    let signer_b = state_b.agent.identity().agent_keypair();
    let mut other_branch = x0x::groups::GroupInfo::with_policy(
        "owner-axis-advance".to_string(),
        String::new(),
        state_b.agent.agent_id(),
        group_id.clone(),
        owner_certified_policy(&owner_b),
    );
    seal_commit_owner_certified(&state_b, &mut other_branch, signer_b, now_millis_u64()).await?;
    other_branch.description = "a-different-branch".to_string();
    seal_commit_owner_certified(&state_b, &mut other_branch, signer_b, now_millis_u64()).await?;
    other_branch.description = "and-its-advance".to_string();
    seal_commit_owner_certified(&state_b, &mut other_branch, signer_b, now_millis_u64()).await?;
    assert_eq!(other_branch.state_revision, at_three.state_revision);
    assert_ne!(
        other_branch.prev_state_hash, at_three.prev_state_hash,
        "the fixture must really be a different branch"
    );
    assert!(
        replay_scenario(&group_id, &live, &other_branch, &group_id)
            .await?
            .fork_quarantine
            .is_some(),
        "#732 r3: a signed advance on ANOTHER branch does not clear this node's marker"
    );

    // Forgery 3 — a signed advance by an agent the live roster does NOT
    // certify as the policy owner's own. Signature and ancestry are fine;
    // owner provenance is not.
    let mut stranger_advance = at_three.clone();
    if let Some(retained) = stranger_advance.commit_log.last_mut() {
        retained.commit.committed_by = "ab".repeat(16);
    }
    assert!(
        replay_scenario(&group_id, &live, &stranger_advance, &group_id)
            .await?
            .fork_quarantine
            .is_some(),
        "#732 r3: only the owner's own certified agent anchors a clear"
    );

    // Forgery 4 — an ORDINARY group can never buy a clear this way, whatever
    // the advance looks like: the predicate's owner-axis fence is the same one
    // the live arms carry.
    let ordinary_id = "e4".repeat(32);
    let (_base, ordinary_live, ordinary_signer) =
        recovery_fixture(&ordinary_id, invite_only_policy())?;
    let mut ordinary_marked = ordinary_live.clone();
    let mut ordinary_marker = marker_at_frontier(&ordinary_live);
    // Pretend it is anchorable, so ONLY the owner-axis fence can refuse.
    ordinary_marker.no_anchor = false;
    ordinary_marked.fork_quarantine = Some(ordinary_marker);
    let mut ordinary_advance = ordinary_live.clone();
    ordinary_advance.description = "an-ordinary-advance".to_string();
    ordinary_advance.seal_commit(&ordinary_signer, now_millis_u64())?;
    assert!(
        ordinary_advance.state_revision > ordinary_live.state_revision,
        "the ordinary advance really advances"
    );
    assert!(
        replay_scenario(
            &ordinary_id,
            &ordinary_marked,
            &ordinary_advance,
            &ordinary_id
        )
        .await?
        .fork_quarantine
        .is_some(),
        "#732 r3: an ordinary group has no owner axis, so no replayed commit clears it"
    );
    Ok(())
}

/// WHY (#732 r3 — both reviewers, independently). The r2 code claimed Rule 3's
/// second binding was unreachable behind the first. That holds only for a live
/// record whose outer `state_hash` agrees with its own signed terminal commit,
/// and recovery establishes no such invariant. The MIRROR forgery edits the
/// LIVE record's outer hash and leaves the log intact: `terminal_commit_header`
/// returns the log's hash, so the JOURNAL is perfectly consistent, binding (a)
/// passes, and only (b) — "the verified commit must genuinely differ from the
/// live committed state at that revision" — refuses the install.
///
/// Without (b) this shape installs permanent `no_anchor` containment on a group
/// that never forked: the two halves hold the SAME signed commit.
#[tokio::test]
async fn issue732_mirror_forged_live_hash_installs_no_marker() -> Result<()> {
    let group_id = "e5".repeat(32);
    let (base, advanced, signer) = recovery_fixture(&group_id, invite_only_policy())?;

    // The live half: outer hash rewritten, signed log untouched.
    let mut live_forged = advanced.clone();
    live_forged.state_hash = "ee".repeat(32);
    assert_eq!(
        live_forged
            .commit_log
            .last()
            .map(|retained| retained.commit.state_hash.clone()),
        Some(advanced.state_hash.clone()),
        "the live log still signs the REAL frontier — that is what makes (a) pass"
    );

    // The journal half is the untouched record: same signed commit, consistent
    // outer fields. There is no fork here at all.
    let after = replay_scenario(&group_id, &live_forged, &advanced, &group_id).await?;
    assert!(
        !after.is_fork_quarantined(),
        "#732 r3: two halves holding the SAME signed commit are not a fork — \
         binding (b) is load-bearing, not redundant"
    );

    // The control: a genuinely different signed commit at that revision still
    // installs, so (b) is not a blanket refusal.
    let genuine = conflicting_sibling(&base, &signer, "the-other-branch")?;
    assert!(
        replay_scenario(&group_id, &live_forged, &genuine, &group_id)
            .await?
            .fork_quarantine
            .is_some_and(|marker| marker.no_anchor),
        "an authenticated CONFLICTING commit is still contained"
    );
    Ok(())
}

/// WHY (#732 r3 — Codex's Rule 1 note). "Equal or older" conflated two very
/// different situations. A journal that is stale against the MERGED store is
/// consumed before any write, so it never reaches this helper. But an
/// individual FILE can still be newer than the journalled record: the merged
/// load lets the authoritative Home-Suite sidecar record supersede a legacy
/// placeholder in `named_groups.json` (`merge_home_suite_groups`), and that
/// placeholder can carry a higher `state_revision` than the sidecar record the
/// journal staged. Replacing it is intentional — it is the whole point of the
/// supersession.
///
/// Taking case 1's rule there (the live pair VERBATIM) would let the
/// placeholder's containment state overwrite the authoritative record's, which
/// in the direction that matters means DROPPING a marker. So case 3 unions
/// instead: the live half fills only what the journal record lacks, and nothing
/// is ever cleared. Containment survives from whichever half holds it.
///
/// This exercises the merge helper directly on the exact on-disk divergence,
/// because reaching it through the full entry needs a merged view that
/// disagrees with the named file — state the load path creates, not the replay.
#[tokio::test]
async fn issue732_older_journal_at_one_file_unions_containment() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let group_id = "e6".repeat(32);
    let (_base, advanced, _kp) = recovery_fixture(&group_id, invite_only_policy())?;

    // Arm 1 — the direction that matters: the newer placeholder carries NO
    // marker, the journalled authoritative record does. The marker must live.
    let mut placeholder = legacy_safe_placeholder(&advanced);
    placeholder.state_revision = advanced.state_revision + 5;
    placeholder.fork_quarantine = None;
    let mut authoritative = advanced.clone();
    authoritative.fork_quarantine = Some(marker_at_frontier(&advanced));
    let store = dir.path().join("named_groups.json");
    write_named_groups_json_atomic(&store, &store_image(&group_id, &placeholder)?).await?;
    merge_group_record_into_store_file(
        &store,
        &group_id,
        &store_image(&group_id, &authoritative)?,
        "named groups",
    )
    .await?;
    assert!(
        read_store(&store).await?[&group_id]
            .fork_quarantine
            .is_some(),
        "#732 r3: a placeholder's ABSENT containment must not erase the authoritative \
         record's marker — case 1's verbatim rule would have"
    );

    // Arm 2 — the other direction: the placeholder carries the marker (a
    // placeholder clone preserves it) and the journalled record does not. The
    // union keeps it: case 3 never clears.
    let mut placeholder_marked = legacy_safe_placeholder(&advanced);
    placeholder_marked.state_revision = advanced.state_revision + 5;
    placeholder_marked.fork_quarantine = Some(marker_at_frontier(&advanced));
    let store_b = dir.path().join("named_groups_b.json");
    write_named_groups_json_atomic(&store_b, &store_image(&group_id, &placeholder_marked)?).await?;
    merge_group_record_into_store_file(
        &store_b,
        &group_id,
        &store_image(&group_id, &advanced)?,
        "named groups",
    )
    .await?;
    let after = read_store(&store_b).await?[&group_id].clone();
    assert!(
        after.fork_quarantine.is_some(),
        "#732 r3: case 3 unions containment — an older journal never lifts it"
    );
    assert_eq!(
        after.state_revision, advanced.state_revision,
        "negative control: the authoritative record still supersedes the placeholder \
         everywhere else, which is what the supersession is FOR"
    );
    assert!(
        !after.members_v2.is_empty(),
        "and the real roster is restored over the placeholder's empty one"
    );
    Ok(())
}

/// Like [`replay_scenario`] but also seeds the Home-Suite SIDECAR, so the merged
/// view (which `merge_home_suite_groups` lets the sidecar win) can disagree with
/// the individual `named_groups.json` file — the divergence #732's case 3 exists
/// for.
///
/// Returns `(named record, merged authoritative record)`. Both are handed back on
/// purpose: for a group present in the sidecar the two records differ in every
/// other field (the sidecar wins, and with no `.hsjournal` staged the recovery
/// rewrites only the named half), so a fixture that inspected one would be silent
/// about the other. #732 r6: they must NOT differ in containment — the merge
/// unions it, because `server::serve_with_options` loads the merged view and a
/// marker held only in the legacy half is invisible to every ADR-0066 gate.
async fn replay_scenario_with_sidecar(
    group_id: &str,
    named_live: &x0x::groups::GroupInfo,
    sidecar_live: &x0x::groups::GroupInfo,
    staged: &x0x::groups::GroupInfo,
) -> Result<(x0x::groups::GroupInfo, x0x::groups::GroupInfo)> {
    let dir = tempfile::tempdir()?;
    let treekem = dir.path().join("treekem");
    tokio::fs::create_dir_all(&treekem).await?;
    let named_path = dir.path().join("named_groups.json");
    let sidecar_path = dir.path().join(HOME_SUITE_GROUPS_FILE);
    write_named_groups_json_atomic(&named_path, &store_image(group_id, named_live)?).await?;
    write_named_groups_json_atomic(&sidecar_path, &store_image(group_id, sidecar_live)?).await?;
    stage_journal(&treekem, group_id, staged).await?;
    // The merged verdict must read Apply, or the journal is consumed as stale
    // and this fixture proves nothing about the merge.
    let merged = load_named_groups_merged(&named_path, &sidecar_path).await?;
    assert_eq!(
        merged[group_id].state_revision, sidecar_live.state_revision,
        "the sidecar record must win the merge, which is the premise of case 3"
    );
    recover_treekem_named_journals(&named_path, &sidecar_path, &treekem).await?;
    let named_after = read_store(&named_path)
        .await?
        .get(group_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("the replay left no record under the stable id"))?;
    let merged_after = load_named_groups_merged(&named_path, &sidecar_path)
        .await?
        .get(group_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("the merged view lost the group"))?;
    Ok((named_after, merged_after))
}

/// WHY (#732 r4 — Codex's fixture gap). The r3 "non-owner committer" arm rewrote
/// `committed_by` WITHOUT re-signing, so `verify_structure` rejected it on the
/// signature and the owner-provenance step was never reached: a passing test
/// that proved the wrong thing. This is the attack properly built — and it is
/// the attack that broke r3's design.
///
/// The adversary is the forker itself: still SEATED (quarantine evicts nobody),
/// Active and Admin, holding a certificate that — like every seat in an
/// OwnerCertified group — binds the policy owner's key, and holding only its OWN
/// agent key. It signs a genuine, structurally valid, higher-revision DESCENDANT
/// of the contested live head with the containment stripped. Every r3 condition
/// is satisfied: retained terminal commit, `verify_structure` passes, the outer
/// claim matches the signed one, `owner_anchored_clear_permitted` holds at that
/// revision, ancestry chains from the live head, and the roster certifies the
/// committer under the owner.
///
/// So "certified" is not "authorized", and the only safe answer is the one #732
/// r4 takes: no replayed advance clears. The negative control is the code at
/// `5b7b5da`, where this fixture lifts containment.
#[tokio::test]
async fn issue732_certified_admin_resigned_advance_cannot_lift_containment() -> Result<()> {
    let group_id = "e7".repeat(32);
    let (state, _dir, owner) = owner_authority_state().await?;
    let signer = state.agent.identity().agent_keypair();
    let mut live = x0x::groups::GroupInfo::with_policy(
        "certified-admin-attack".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.clone(),
        owner_certified_policy(&owner),
    );
    let creator_hex = hex::encode(state.agent.agent_id().as_bytes());
    live.set_member_certificate(
        &creator_hex,
        state
            .agent
            .agent_certificate()
            .ok_or_else(|| anyhow::anyhow!("builder-issued certificate"))?
            .clone(),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // THE FORKER: a second Active+Admin seat whose certificate is issued by the
    // SAME owner user key — which is what every seat in an OwnerCertified group
    // looks like — and which holds only its own agent key.
    let forker_kp = AgentKeypair::generate()?;
    let forker_hex =
        hex::encode(crate::identity::AgentId::from_public_key(forker_kp.public_key()).as_bytes());
    let creator_seat = live
        .members_v2
        .get(&creator_hex)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("creator seat"))?;
    let mut forker_seat = creator_seat.clone();
    forker_seat.agent_id = forker_hex.clone();
    forker_seat.role = x0x::groups::GroupRole::Admin;
    forker_seat.state = x0x::groups::GroupMemberState::Active;
    // A cloned seat carries the CREATOR's certificate and its committed digest;
    // clear both so this seat gets its own.
    forker_seat.certificate = None;
    forker_seat.certificate_digest = None;
    live.members_v2.insert(forker_hex.clone(), forker_seat);
    live.set_member_certificate(
        &forker_hex,
        crate::identity::AgentCertificate::issue(&owner, &forker_kp)
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    seal_commit_owner_certified(&state, &mut live, signer, now_millis_u64()).await?;
    live.description = "the contested head".to_string();
    seal_commit_owner_certified(&state, &mut live, signer, now_millis_u64()).await?;
    let contested_head = live.clone();
    let marker = marker_at_frontier(&contested_head);
    assert!(!marker.no_anchor, "owner axis — the clearable kind");
    live.fork_quarantine = Some(marker);
    live.invite_lineage = Some(lineage_for(&contested_head));
    if let Some(lineage) = live.invite_lineage.as_mut() {
        lineage.fork_evidence = Some(evidence_at_frontier(&contested_head));
    }

    // The forker's own descendant of that head, VALIDLY SIGNED with its agent
    // key, containment stripped.
    let mut forked_advance = contested_head.clone();
    forked_advance.description = "the forker's advance".to_string();
    seal_commit_owner_certified(&state, &mut forked_advance, &forker_kp, now_millis_u64()).await?;
    let staged = forked_advance
        .commit_log
        .last()
        .ok_or_else(|| anyhow::anyhow!("sealed"))?
        .commit
        .clone();
    assert!(
        staged.verify_structure().is_ok(),
        "the attack commit VERIFIES — that is the whole point; r3's arm never got here"
    );
    assert_eq!(
        staged.committed_by, forker_hex,
        "signed by the forker itself"
    );
    assert_eq!(
        staged.prev_state_hash.as_deref(),
        Some(contested_head.state_hash.as_str()),
        "and it is a DESCENDANT of the contested live head, not another branch"
    );
    assert!(
        staged.revision > contested_head.state_revision,
        "at a strictly higher revision, so the clear predicate would permit it"
    );
    assert!(
        live.members_v2
            .get(&forker_hex)
            .and_then(|m| m.certificate.as_ref())
            .is_some_and(
                |cert| ant_quic::MlDsaPublicKey::from_bytes(cert.user_public_key_bytes())
                    .is_ok_and(
                        |pk| crate::identity::UserId::from_public_key(&pk) == owner.user_id()
                    )
            ),
        "and the live roster certifies the forker UNDER THE POLICY OWNER — the \
         degeneracy that made r3's provenance check vacuous"
    );
    assert!(forked_advance.fork_quarantine.is_none());
    // The attacker keeps the provenance record and strips only the containment
    // PAIR — marker and evidence — which is what makes the lift durable.
    forked_advance.invite_lineage = Some(lineage_for(&contested_head));

    let after = replay_scenario(&group_id, &live, &forked_advance, &group_id).await?;
    assert!(
        after.fork_quarantine.is_some(),
        "#732 r4: a certified Active+Admin signing a descendant of the contested head \
         is NOT owner authorization — containment must survive"
    );
    assert!(
        after
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.fork_evidence.as_ref())
            .is_some(),
        "and the evidence with it: the attack strips the whole pair"
    );
    assert_eq!(
        after.state_revision, forked_advance.state_revision,
        "negative control: the advance is still applied — only containment is kept"
    );
    Ok(())
}

/// #732 r4 (Codex): the case-3 fixture, driven through the REAL startup entry
/// rather than the merge helper. The divergence is built the way the load path
/// builds it: `merge_home_suite_groups` lets the authoritative sidecar record win
/// the MERGED view (so the verdict reads Apply), while `named_groups.json` still
/// holds a legacy placeholder at a HIGHER `state_revision` — which is the live
/// half the named-store merge then sees.
///
/// Both arms of the union are asserted, and the second is r3's nit: the union is
/// over containment STRENGTH, so a journal-side ANCHORED marker must not outrank
/// a live `no_anchor` one, or the supersession would silently downgrade a
/// manual-only quarantine into one an owner-anchored advance could clear.
#[tokio::test]
async fn issue732_older_journal_at_one_file_unions_containment_through_recovery() -> Result<()> {
    let group_id = "e8".repeat(32);
    let (_state, _dir, authoritative, _at_three) = owner_axis_advance_fixture(&group_id).await?;

    // Arm 1 — the direction that matters: the newer placeholder carries NO
    // marker, the journalled authoritative record does. Case 1's verbatim rule
    // would erase it.
    let mut placeholder = legacy_safe_placeholder(&authoritative);
    placeholder.state_revision = authoritative.state_revision + 5;
    placeholder.fork_quarantine = None;
    let mut staged = authoritative.clone();
    staged.fork_quarantine = Some(marker_at_frontier(&authoritative));
    let (after, merged) =
        replay_scenario_with_sidecar(&group_id, &placeholder, &authoritative, &staged).await?;
    assert!(
        after.fork_quarantine.is_some(),
        "#732 r4: a placeholder's ABSENT containment must not erase the authoritative \
         record's marker"
    );
    assert!(
        merged.fork_quarantine.is_some(),
        "#732 r6: the AUTHORITATIVE view must carry it too. r5 asserted the opposite and \
         called it benign; review was right that it is not — `serve_with_options` loads this \
         view, so a marker preserved only in the legacy half is invisible to every \
         ADR-0066 gate. The merge now unions containment."
    );
    assert_eq!(
        after.state_revision, authoritative.state_revision,
        "negative control: the authoritative record still supersedes the placeholder"
    );
    assert!(
        !after.members_v2.is_empty(),
        "and the real roster replaces the placeholder's empty one"
    );

    // Arm 2 — strength, not presence: the live placeholder's marker is
    // `no_anchor`, the journalled one is anchored. The result must be
    // `no_anchor`, or a manual-only quarantine is quietly downgraded.
    let mut placeholder_no_anchor = legacy_safe_placeholder(&authoritative);
    placeholder_no_anchor.state_revision = authoritative.state_revision + 5;
    let mut strong = marker_at_frontier(&authoritative);
    strong.no_anchor = true;
    placeholder_no_anchor.fork_quarantine = Some(strong);
    let mut staged_anchored = authoritative.clone();
    let mut weak = marker_at_frontier(&authoritative);
    weak.no_anchor = false;
    staged_anchored.fork_quarantine = Some(weak);
    let (after, merged) = replay_scenario_with_sidecar(
        &group_id,
        &placeholder_no_anchor,
        &authoritative,
        &staged_anchored,
    )
    .await?;
    assert_eq!(
        merged.state_revision, authoritative.state_revision,
        "the authoritative view is still the sidecar's record for every other field"
    );
    assert!(
        merged
            .fork_quarantine
            .as_ref()
            .is_some_and(|marker| marker.no_anchor),
        "#732 r6: the authoritative view carries the STRONGER marker, `no_anchor` included"
    );
    assert!(
        after
            .fork_quarantine
            .as_ref()
            .is_some_and(|marker| marker.no_anchor),
        "#732 r4: the union takes the STRONGER containment — an anchored journal marker \
         cannot downgrade a live `no_anchor` one into something a commit could clear"
    );
    Ok(())
}

/// WHY (#732 r5 — cross-model review, Codex P2; omp noted the same as a nit).
/// r4 ordered containment strength by `no_anchor` alone, which left the
/// ANCHORED-versus-ANCHORED case unordered. A live marker at revision 7 could
/// therefore be replaced by a journalled one at revision 2, and that is not
/// cosmetic: a marker's `revision` is half of
/// `ForkQuarantine::owner_anchored_clear_permitted`, which requires a revision
/// strictly past the evidenced one. Swapping 7 for 2 flips an advance at
/// revision 3 from REFUSED to PERMITTED — the replay would hand out a clear
/// nobody granted, one step removed.
///
/// The claim: `challenger_containment_is_stronger` is a TOTAL order (`no_anchor`
/// class first, then the strictly higher `revision`; at equal strength the
/// INCUMBENT survives — under #732 r8's sorted-key folds, the first candidate
/// in key order), so the surviving threshold is never lower
/// than either half's, and the WHOLE stronger marker is installed — never a mix
/// of fields from both, which would describe a fork observation that never
/// happened (ADR-0067 derives `ForkQuarantineIdentity` from exactly those
/// fields).
///
/// Driven through `recover_treekem_named_journals`, with the merged
/// authoritative view asserted alongside the named store.
#[tokio::test]
async fn issue732_anchored_union_keeps_the_higher_clear_threshold() -> Result<()> {
    let group_id = "ea".repeat(32);
    let (_state, _dir, authoritative, _at_three) = owner_axis_advance_fixture(&group_id).await?;

    // The live (placeholder) half: ANCHORED at revision 7, observed later.
    let mut placeholder = legacy_safe_placeholder(&authoritative);
    placeholder.state_revision = authoritative.state_revision + 5;
    let mut strong = marker_at_frontier(&authoritative);
    strong.no_anchor = false;
    strong.revision = 7;
    strong.observed_at_ms = 200;
    strong.state_hash = "77".repeat(32);
    strong.committed_by = "71".repeat(32);
    placeholder.fork_quarantine = Some(strong.clone());

    // The journalled half: ANCHORED too, but at revision 2 and observed
    // earlier — strictly weaker containment.
    let mut staged = authoritative.clone();
    let mut weak = marker_at_frontier(&authoritative);
    weak.no_anchor = false;
    weak.revision = 2;
    weak.observed_at_ms = 100;
    weak.state_hash = "22".repeat(32);
    weak.committed_by = "21".repeat(32);
    staged.fork_quarantine = Some(weak.clone());

    assert!(
        !strong.owner_anchored_clear_permitted(3),
        "the LIVE threshold refuses an advance at revision 3"
    );
    assert!(
        weak.owner_anchored_clear_permitted(3),
        "the JOURNALLED threshold would permit it — that is the regression under test"
    );

    let (after, merged) =
        replay_scenario_with_sidecar(&group_id, &placeholder, &authoritative, &staged).await?;
    let kept = after
        .fork_quarantine
        .clone()
        .ok_or_else(|| anyhow::anyhow!("containment must survive"))?;
    assert_eq!(
        kept.revision, 7,
        "#732 r5: the HIGHER evidenced revision survives — the clear threshold cannot regress"
    );
    assert!(
        !kept.owner_anchored_clear_permitted(3),
        "so an advance at revision 3 is STILL refused after the replay"
    );
    // Coherence: the whole stronger marker, never a field mix.
    assert_eq!(
        kept, strong,
        "the marker is installed whole; no franken-identity"
    );
    assert_eq!(kept.observed_at_ms, 200);
    assert_eq!(kept.state_hash, "77".repeat(32));
    assert_eq!(kept.committed_by, "71".repeat(32));
    assert_eq!(
        merged.state_revision, authoritative.state_revision,
        "the authoritative view is still the sidecar's record for every other field"
    );
    assert_eq!(
        merged
            .fork_quarantine
            .as_ref()
            .map(|marker| marker.revision),
        Some(7),
        "#732 r6: and the union reaches the AUTHORITATIVE view at its stronger form too"
    );
    // Negative control in the same test: with the halves swapped the journalled
    // marker is the stronger one and IT survives, so this is a real order and
    // not "live always wins".
    let mut placeholder_weak = legacy_safe_placeholder(&authoritative);
    placeholder_weak.state_revision = authoritative.state_revision + 5;
    placeholder_weak.fork_quarantine = Some(weak.clone());
    let mut staged_strong = authoritative.clone();
    staged_strong.fork_quarantine = Some(strong.clone());
    let (swapped, _) =
        replay_scenario_with_sidecar(&group_id, &placeholder_weak, &authoritative, &staged_strong)
            .await?;
    assert_eq!(
        swapped
            .fork_quarantine
            .as_ref()
            .map(|marker| marker.revision),
        Some(7),
        "the order is over STRENGTH, not over which half the marker came from"
    );
    Ok(())
}

/// WHY (#732 r6 — cross-model review, Codex P1; omp judged it pre-existing and
/// benign, and I sided with Codex after establishing reachability).
///
/// `merge_home_suite_groups` replaces a named placeholder with the sidecar record
/// wholesale (#451 sidecar-wins), and `server::serve_with_options` loads that
/// merged view — so it is the only containment the running daemon's ADR-0066
/// gates can see. Two recovery paths write containment to the NAMED half alone:
///
/// - `record_recovery_fork_evidence` walks `[named, sidecar]` and returns after
///   its first successful write, and a Home-Suite group's named entry is a
///   `legacy_safe_placeholder`, which preserves the record's identity and its
///   `invite_lineage` — so the install lands there and returns;
/// - the replay's Apply arm writes the sidecar half only when a decodable
///   `.hsjournal` is present, while the named write is unconditional.
///
/// So a marker recovery had deliberately preserved could be discarded before the
/// daemon ever loaded it. This fixture drives the second path through
/// `recover_treekem_named_journals` and asserts the MERGED view, not just the
/// file: containment must survive into the authoritative record while the sidecar
/// still wins every other field.
///
/// Negative control: with the union at the merge removed, the merged view loses
/// the marker and this test fails while the named-store assertions still pass —
/// which is exactly the r5 state review rejected.
#[tokio::test]
async fn issue732_merged_authoritative_view_keeps_recovered_containment() -> Result<()> {
    let group_id = "eb".repeat(32);
    let (_state, _dir, authoritative, _at_three) = owner_axis_advance_fixture(&group_id).await?;

    // The sidecar half is the authoritative record and carries NO containment —
    // recovery never rewrote it, because no `.hsjournal` was staged.
    let sidecar = authoritative.clone();
    assert!(sidecar.fork_quarantine.is_none());

    // The named half is the legacy placeholder. The journalled record is the
    // authoritative record WITH the marker recovery preserved, so the named
    // write is where containment lands.
    let mut placeholder = legacy_safe_placeholder(&authoritative);
    placeholder.state_revision = authoritative.state_revision + 5;
    placeholder.fork_quarantine = None;
    let mut staged = authoritative.clone();
    let marker = marker_at_frontier(&authoritative);
    staged.fork_quarantine = Some(marker.clone());

    let (named_after, merged_after) =
        replay_scenario_with_sidecar(&group_id, &placeholder, &sidecar, &staged).await?;
    assert!(
        named_after.fork_quarantine.is_some(),
        "the legacy half holds the marker — that much already worked"
    );
    let authoritative_marker = merged_after.fork_quarantine.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "#732 r6: the AUTHORITATIVE merged view must carry the recovered marker — this is \
             the view `serve_with_options` loads and every ADR-0066 gate consults"
        )
    })?;
    assert_eq!(
        authoritative_marker, marker,
        "the whole marker crosses the merge, not a field mix"
    );
    // Negative control: the sidecar still wins everything else, so this is not
    // "the merge stopped preferring the sidecar".
    assert_eq!(
        merged_after.state_revision, authoritative.state_revision,
        "sidecar-wins is intact for every other field"
    );
    assert!(
        !merged_after.members_v2.is_empty(),
        "and the authoritative roster is the sidecar's, not the placeholder's empty one"
    );
    assert!(
        merged_after
            .policy
            .admission
            .owner_certified_user_id()
            .is_some(),
        "including the policy the placeholder deliberately strips"
    );
    Ok(())
}

/// WHY (#732 r7 — cross-model review, Codex P1). The merged view can
/// legitimately hold TWO entries for one group: `merge_home_suite_groups`
/// inserts the sidecar record under ITS key and does NOT remove a
/// differently-keyed named entry, which is the shape
/// `collect_same_stable_group_aliases` exists for. r6 unioned containment into
/// the sidecar record only, so the alias entry stayed unmarked — and
/// `server::resolve_group_entry_locked` returns an EXACT key match first, so a
/// gate asked by the alias spelling resolved the unmarked entry and served the
/// group. Containment present in the roster, absent at the gate.
///
/// The claim: after the load, EVERY spelling of a quarantined group resolves to
/// a contained record. Entries are deliberately not canonicalised or deleted —
/// losing a record is worse than keeping a duplicate — so the fix is that the
/// duplicate cannot disagree about containment.
///
/// Negative control (executed): with the post-insert spread removed, the alias
/// spelling resolves to an unmarked record and this test fails while the
/// sidecar-keyed assertions still pass — exactly the r6 state.
#[tokio::test]
async fn issue732_every_spelling_resolves_to_containment_after_load() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let named_path = dir.path().join("named_groups.json");
    let sidecar_path = dir.path().join(HOME_SUITE_GROUPS_FILE);
    let group_id = "ec".repeat(32);
    let (_state, _sdir, authoritative, _at_three) = owner_axis_advance_fixture(&group_id).await?;

    // The named half is filed under an ALIAS and carries NO containment — the
    // shape a legacy rewrite or a re-keyed replay leaves behind.
    let alias_key = "issue732-merge-alias";
    let mut alias_entry = legacy_safe_placeholder(&authoritative);
    alias_entry.fork_quarantine = None;
    write_named_groups_json_atomic(&named_path, &store_image(alias_key, &alias_entry)?).await?;

    // The sidecar half is the authoritative record, keyed by the stable id and
    // QUARANTINED.
    let mut sidecar_entry = authoritative.clone();
    let marker = marker_at_frontier(&authoritative);
    sidecar_entry.fork_quarantine = Some(marker.clone());
    write_named_groups_json_atomic(
        &sidecar_path,
        &store_image(authoritative.stable_group_id(), &sidecar_entry)?,
    )
    .await?;

    let merged = load_named_groups_merged(&named_path, &sidecar_path).await?;
    assert_eq!(
        merged
            .values()
            .filter(|info| info.stable_group_id() == authoritative.stable_group_id())
            .count(),
        2,
        "the premise: the merge leaves the alias entry in place beside the sidecar's"
    );
    assert!(
        merged.contains_key(alias_key),
        "and the alias key really survived the merge"
    );

    // What the gates actually ask, by BOTH spellings.
    for spelling in [alias_key, authoritative.stable_group_id()] {
        let (_key, info) = crate::server::resolve_group_entry_locked(&merged, spelling)
            .ok_or_else(|| anyhow::anyhow!("resolver lost {spelling}"))?;
        assert!(
            info.is_fork_quarantined(),
            "#732 r7: the spelling `{spelling}` must resolve to a CONTAINED record — the \
             resolver returns an exact key match first, so an unmarked duplicate is a \
             silent bypass"
        );
    }
    assert!(
        merged
            .values()
            .filter(|info| info.stable_group_id() == authoritative.stable_group_id())
            .all(|info| info.fork_quarantine.as_ref() == Some(&marker)),
        "every spelling carries the SAME, whole marker — no field mix, no weaker copy"
    );
    // Negative control: sidecar-wins is untouched for everything else, so this
    // is not "the merge stopped preferring the sidecar".
    assert!(
        merged[authoritative.stable_group_id()]
            .policy
            .admission
            .owner_certified_user_id()
            .is_some(),
        "the authoritative record still wins on policy"
    );
    Ok(())
}

/// #732 r8 (Codex r7 P1a): the four owner-anchored clear arms persist
/// their cleared record through `persist_named_group_info` — a transaction
/// that does NOT pass through `persist_named_groups_mutation_unlocked`, so
/// an invariant enforced only at that chokepoint would leave the sibling
/// spelling marked, and a restart would spread the marker back from disk.
/// The clear must reach EVERY alias spelling in memory and survive reload.
#[tokio::test]
async fn issue732_owner_anchored_clear_reaches_every_alias_and_survives_reload() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let stable = "ee".repeat(32);
    let alias_key = "issue732-owner-clear-alias".to_string();
    let mut record = x0x::groups::GroupInfo::with_policy(
        "owner-clear-spread".to_string(),
        String::new(),
        state.agent.agent_id(),
        stable.clone(),
        invite_only_policy(),
    );
    record.state_revision = 5;
    record.fork_quarantine = Some(synthetic_marker(false)?);
    {
        let mut groups = state.named_groups.write().await;
        groups.insert(stable.clone(), record.clone());
        groups.insert(alias_key.clone(), record.clone());
    }

    // What the seal/apply/adoption clear arms do: persist the ONE cleared
    // record through `persist_named_group_info`.
    let mut cleared = record.clone();
    cleared.fork_quarantine = None;
    cleared.reset_fork_evidence_after_quarantine_clear();
    let outcome = super::super::persist_named_group_info(&state, &alias_key, cleared).await?;
    assert!(
        matches!(&outcome, super::super::AtomicWriteOutcome::Durable),
        "fixture precondition — the clear itself was durable: {outcome:?}"
    );

    {
        let groups = state.named_groups.read().await;
        for key in [stable.as_str(), alias_key.as_str()] {
            assert!(
                groups[key].fork_quarantine.is_none(),
                "#732 r8: the clear reached the `{key}` spelling in memory"
            );
        }
    }
    // Reload survival: the on-disk bytes carry the spread, not just memory.
    let raw = tokio::fs::read_to_string(&state.named_groups_path).await?;
    let disk: std::collections::HashMap<String, x0x::groups::GroupInfo> =
        serde_json::from_str(&raw)?;
    for key in [stable.as_str(), alias_key.as_str()] {
        assert!(
            disk[key].fork_quarantine.is_none(),
            "#732 r8: the clear survived reload for `{key}` — the disk bytes were converged"
        );
    }
    Ok(())
}

/// #732 r8 (Codex r7 P1b, at the LOAD BOUNDARY): the erasing sequence r7
/// described needs a divergent map — sibling durably marked, the retried
/// spelling clean — which a pre-invariant binary could write. The claim
/// under test is about EXISTING inputs: `load_named_groups_merged` converges
/// such a map before any live mutation can run, so (a) every spelling
/// resolves contained, and (b) the first-complete-wins gate (`the marker IS
/// the record`) refuses an identical re-install, leaving nothing for a
/// durability rollback to erase. The clean-group control then shows the
/// rollback restoring absence on EVERY spelling — no half state.
#[tokio::test]
async fn issue732_inherited_divergent_containment_survives_the_load_boundary() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let stable = "f0".repeat(32);
    let alias_key = "issue732-inherited-alias".to_string();
    let marker_x = synthetic_marker(false)?;

    // Phase A — INHERITED divergence, exactly the pre-r8 disk shape: the
    // stable-keyed spelling durably marked, the alias spelling clean. The
    // pair is written to the NAMED STORE, because the load boundary reads
    // files, not the live map.
    {
        let mut marked = x0x::groups::GroupInfo::with_policy(
            "inherited-divergence".to_string(),
            String::new(),
            state.agent.agent_id(),
            stable.clone(),
            invite_only_policy(),
        );
        marked.state_revision = 5;
        marked.fork_quarantine = Some(marker_x.clone());
        let mut clean = marked.clone();
        clean.fork_quarantine = None;
        let mut disk = std::collections::HashMap::new();
        disk.insert(stable.clone(), marked);
        disk.insert(alias_key.clone(), clean);
        write_named_groups_json_atomic(&state.named_groups_path, &serde_json::to_string(&disk)?)
            .await?;
    }
    // The load boundary (the same merged view `server::serve` builds at
    // startup) converges the inherited divergence: strongest whole pair on
    // every spelling.
    let merged =
        load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path).await?;
    for key in [stable.as_str(), alias_key.as_str()] {
        assert!(
            merged[key].fork_quarantine.as_ref() == Some(&marker_x),
            "#732 r8: the load boundary converged the inherited containment onto `{key}`"
        );
        assert!(
            super::super::fork_evidence_already_recorded(&merged[key]),
            "post-load, the dedup gate holds for `{key}` — an identical conflict is \
             NotEvidence, so no re-install and no rollback can touch the inherited marker"
        );
    }
    // And the gate's consequence, executed: an identical install is refused.
    *state.named_groups.write().await = merged.clone();
    let evidence = x0x::groups::ForkEvidence {
        revision: marker_x.revision,
        state_hash: marker_x.state_hash.clone(),
        committed_by: marker_x.committed_by.clone(),
        observed_at_ms: marker_x.observed_at_ms,
    };
    assert!(
        !super::super::install_fork_evidence(
            &state,
            &stable,
            evidence.clone(),
            Some(marker_x.clone()),
            false,
        )
        .await,
        "first-complete-wins: an identical marker is already recorded, nothing installs"
    );
    {
        let groups = state.named_groups.read().await;
        assert_eq!(
            groups[&alias_key].fork_quarantine.as_ref(),
            Some(&marker_x),
            "the inherited containment survived the refused retry on every spelling"
        );
    }

    // Phase B — clean-group control: a fresh conflict installs under a
    // durability fault, and the rollback restores absence EVERYWHERE.
    let marker_y = {
        let mut other = synthetic_marker(false)?;
        other.revision = marker_x.revision + 1;
        other
    };
    {
        let mut groups = state.named_groups.write().await;
        for key in [stable.clone(), alias_key.clone()] {
            let info = groups
                .get_mut(&key)
                .ok_or_else(|| anyhow::anyhow!("gone"))?;
            info.fork_quarantine = None;
            info.reset_fork_evidence_after_quarantine_clear();
        }
    }
    let _fault = set_save_fault(&state, SaveFault::ReplacedNotDurable);
    let evidence_y = x0x::groups::ForkEvidence {
        revision: marker_y.revision,
        state_hash: marker_y.state_hash.clone(),
        committed_by: marker_y.committed_by.clone(),
        observed_at_ms: marker_y.observed_at_ms,
    };
    assert!(
        !super::super::install_fork_evidence(
            &state,
            &stable,
            evidence_y,
            Some(marker_y.clone()),
            false,
        )
        .await,
        "the faulted install never reaches durability"
    );
    {
        let groups = state.named_groups.read().await;
        for key in [stable.as_str(), alias_key.as_str()] {
            assert!(
                groups[key].fork_quarantine.is_none(),
                "#732 r8: the rollback restored absence on `{key}` — no half state, no \
                 orphaned marker on a spelling the install never reached"
            );
        }
    }
    Ok(())
}

/// #732 r8: the load-side convergence is DETERMINISTIC. Two equal-strength
/// markers (same anchor class, same revision, different `state_hash`) fold
/// with ties to the incumbent, and the candidates are visited in sorted-key
/// order — so the winner is a property of the MAP, not of hash iteration
/// order, and swapping which key holds which marker moves the winner with
/// the key, not randomly.
#[test]
fn issue732_reconcile_winner_is_deterministic_under_content_swap() -> Result<()> {
    let stable = "f1".repeat(32);
    let key_a = format!("{stable}-a");
    let key_b = format!("{stable}-b");
    let agent = crate::identity::AgentId([9u8; 32]);
    let seeded = |hash: &str| -> Result<x0x::groups::GroupInfo> {
        let mut info = x0x::groups::GroupInfo::with_policy(
            "reconcile-determinism".to_string(),
            String::new(),
            agent,
            stable.clone(),
            invite_only_policy(),
        );
        let mut marker = synthetic_marker(false)?;
        marker.state_hash = hash.to_string();
        info.fork_quarantine = Some(marker);
        Ok(info)
    };

    let mut first = std::collections::HashMap::new();
    first.insert(key_a.clone(), seeded("aaaa")?);
    first.insert(key_b.clone(), seeded("bbbb")?);
    super::super::reconcile_containment_across_aliases(&mut first);
    let first_winner = first[&key_a].fork_quarantine.clone();
    assert_eq!(
        first[&key_b].fork_quarantine, first_winner,
        "converged whole — one marker everywhere"
    );
    assert_eq!(
        first_winner
            .as_ref()
            .map(|marker| marker.state_hash.as_str()),
        Some("aaaa"),
        "ties keep the incumbent: the lexicographically-first key's marker wins"
    );

    // Swap the CONTENT between the keys: the rule is about the KEY, so the
    // same key wins with its new content — not the same content by luck.
    let mut swapped = std::collections::HashMap::new();
    swapped.insert(key_a.clone(), seeded("bbbb")?);
    swapped.insert(key_b.clone(), seeded("aaaa")?);
    super::super::reconcile_containment_across_aliases(&mut swapped);
    assert_eq!(
        swapped[&key_a]
            .fork_quarantine
            .as_ref()
            .map(|marker| marker.state_hash.as_str()),
        Some("bbbb"),
        "deterministic by sorted key: key-a wins again, now carrying its own content"
    );
    assert_eq!(
        swapped[&key_b].fork_quarantine, swapped[&key_a].fork_quarantine,
        "still converged whole"
    );
    Ok(())
}

/// #732 r8 (Sol, mixed-lineage aliases; root's concrete sequence): a
/// lineage-LESS alias and a lineage-BEARING sibling can share one stable
/// id, and only the lineage-bearing record has a destination for the
/// evidence half of containment. The tie in `strongest_containment` picks
/// the lexicographically-first pair — the lineage-less `(M, None)` — and
/// `write_containment` used to overwrite the sibling's lineage slot with
/// that pair's `None`, SILENTLY ERASING a retained evidence record that
/// matched the very marker being kept. With the record gone, the dedup
/// gate re-opened, an identical conflict could re-install, and a non-
/// durable rollback of that retry would identity-match and delete the
/// pre-existing marker — containment lost from a converging write.
///
/// The contract under test, stated honestly: markers match across ALL
/// aliases; evidence is coherent FOR DESTINATIONS THAT CAN CARRY IT, and a
/// retained record matching the converged marker is never silently erased.
/// No provenance is invented — the lineage-less record still stores no
/// evidence.
#[tokio::test]
async fn issue732_mixed_lineage_aliases_keep_retained_evidence_and_refuse_the_identical_retry(
) -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let stable = "f2".repeat(32);
    // Lexicographically FIRST key (`a-…` < `f2…`), lineage-less, marker only.
    let first_key = format!("a-{stable}");
    let marker = synthetic_marker(false)?;
    let evidence = x0x::groups::ForkEvidence {
        revision: marker.revision,
        state_hash: marker.state_hash.clone(),
        committed_by: marker.committed_by.clone(),
        observed_at_ms: marker.observed_at_ms,
    };

    // Phase 1 — LOAD: the divergent disk shape a pre-r8 binary could write.
    {
        let mut lineage_less = x0x::groups::GroupInfo::with_policy(
            "mixed-lineage-first".to_string(),
            String::new(),
            state.agent.agent_id(),
            stable.clone(),
            invite_only_policy(),
        );
        lineage_less.state_revision = 5;
        lineage_less.fork_quarantine = Some(marker.clone());
        let mut lineage_bearing = lineage_less.clone();
        lineage_bearing.invite_lineage = Some(x0x::groups::InviteLineage {
            base_revision: 5,
            base_hash: lineage_bearing.state_hash.clone(),
            base_roster_root: String::new(),
            seated_at_revision: None,
            corroborated: false,
            fork_evidence: Some(evidence.clone()),
        });
        let mut disk = std::collections::HashMap::new();
        disk.insert(first_key.clone(), lineage_less);
        disk.insert(stable.clone(), lineage_bearing);
        write_named_groups_json_atomic(&state.named_groups_path, &serde_json::to_string(&disk)?)
            .await?;
    }
    let merged =
        load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path).await?;
    assert_eq!(
        merged[&first_key].fork_quarantine.as_ref(),
        Some(&marker),
        "the marker converges onto the lineage-less first spelling"
    );
    assert_eq!(
        merged[&stable].fork_quarantine.as_ref(),
        Some(&marker),
        "and onto the lineage-bearing sibling — markers match on ALL aliases"
    );
    assert_eq!(
        merged[&stable]
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.fork_evidence.as_ref()),
        Some(&evidence),
        "#732 r8: the retained matching evidence was NOT erased by convergence — \
         evidence is coherent for the destination that can carry it"
    );
    for key in [first_key.as_str(), stable.as_str()] {
        assert!(
            super::super::fork_evidence_already_recorded(&merged[key]),
            "post-load, the dedup gate holds for `{key}`"
        );
    }
    // The gate's marker disjunct, pinned independently: a lineage-bearing
    // record holding the marker with an EMPTY evidence slot is still
    // recorded — that is exactly the shape whose retry used to erase M.
    {
        let mut marker_only = merged[&stable].clone();
        if let Some(lineage) = marker_only.invite_lineage.as_mut() {
            lineage.fork_evidence = None;
        }
        assert!(
            super::super::fork_evidence_already_recorded(&marker_only),
            "a marker with no evidence slot filled still counts as recorded"
        );
    }

    // Phase 2 — the faulted identical retry: refused BEFORE any durability
    // dependence, and nothing erases the pre-existing containment.
    *state.named_groups.write().await = merged.clone();
    {
        let _fault = set_save_fault(&state, SaveFault::ReplacedNotDurable);
        assert!(
            !super::super::install_fork_evidence(
                &state,
                &stable,
                evidence.clone(),
                Some(marker.clone()),
                false,
            )
            .await,
            "first-complete-wins: the identical conflict does not re-install"
        );
    }
    {
        let groups = state.named_groups.read().await;
        for key in [first_key.as_str(), stable.as_str()] {
            assert_eq!(
                groups[key].fork_quarantine.as_ref(),
                Some(&marker),
                "the faulted retry erased nothing on `{key}`"
            );
        }
        assert_eq!(
            groups[&stable]
                .invite_lineage
                .as_ref()
                .and_then(|lineage| lineage.fork_evidence.as_ref()),
            Some(&evidence),
            "and the retained evidence survived the refused retry"
        );
    }

    // Phase 3 — LIVE convergence from a lineage-less authoritative write:
    // persisting the first spelling's marker-only record (the TreeKEM
    // resurrection shape) must still not erase the sibling's evidence.
    let again = state.named_groups.read().await[&first_key].clone();
    let outcome = super::super::persist_named_group_info(&state, &first_key, again).await?;
    assert!(
        matches!(&outcome, super::super::AtomicWriteOutcome::Durable),
        "fixture precondition: {outcome:?}"
    );
    {
        let groups = state.named_groups.read().await;
        assert_eq!(
            groups[&stable]
                .invite_lineage
                .as_ref()
                .and_then(|lineage| lineage.fork_evidence.as_ref()),
            Some(&evidence),
            "#732 r8: a live spread whose authoritative slot carries no evidence \
             keeps a retained matching record on the sibling"
        );
        assert_eq!(
            groups[&stable].fork_quarantine.as_ref(),
            Some(&marker),
            "and the marker stays converged"
        );
    }
    Ok(())
}

/// #732 r8 (root review, atomic admission): the marker-presence refusal
/// must hold INSIDE `install_fork_evidence`'s locked mutation, not only at
/// the earlier `fork_evidence_already_recorded` check — that gate reads a
/// `current` cloned before the persistence lock, so a marker landing in
/// between would let a stale observation fill an empty lineage evidence
/// slot while `get_or_insert` retains the pre-existing marker, and the
/// non-durable rollback of that install would then DELETE the marker it
/// never owned. The exact shape: lineage present, evidence slot EMPTY,
/// marker PRESENT — the direct helper call must refuse and retain.
#[tokio::test]
async fn issue732_install_refuses_when_a_marker_already_exists_despite_an_empty_evidence_slot(
) -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let stable = "f3".repeat(32);
    let marker = synthetic_marker(false)?;
    let evidence = x0x::groups::ForkEvidence {
        revision: marker.revision,
        state_hash: marker.state_hash.clone(),
        committed_by: marker.committed_by.clone(),
        observed_at_ms: marker.observed_at_ms,
    };

    let mut lineage_bearing = x0x::groups::GroupInfo::with_policy(
        "atomic-admission".to_string(),
        String::new(),
        state.agent.agent_id(),
        stable.clone(),
        invite_only_policy(),
    );
    lineage_bearing.state_revision = 5;
    lineage_bearing.fork_quarantine = Some(marker.clone());
    lineage_bearing.invite_lineage = Some(x0x::groups::InviteLineage {
        base_revision: 5,
        base_hash: lineage_bearing.state_hash.clone(),
        base_roster_root: String::new(),
        seated_at_revision: None,
        corroborated: false,
        fork_evidence: None,
    });
    state
        .named_groups
        .write()
        .await
        .insert(stable.clone(), lineage_bearing.clone());

    // The fault is armed to prove the refusal happens BEFORE any write the
    // rollback semantics could touch: nothing installs, nothing rolls back.
    let _fault = set_save_fault(&state, SaveFault::ReplacedNotDurable);
    assert!(
        !super::super::install_fork_evidence(
            &state,
            &stable,
            evidence.clone(),
            Some(marker.clone()),
            false,
        )
        .await,
        "atomic admission: a pre-existing marker refuses the install even with \
         an empty lineage evidence slot"
    );
    drop(_fault);
    {
        let groups = state.named_groups.read().await;
        assert_eq!(
            groups[&stable].fork_quarantine.as_ref(),
            Some(&marker),
            "the pre-existing marker is retained — the refused install never \
             owned it, so no rollback can identity-match it away"
        );
        assert_eq!(
            groups[&stable]
                .invite_lineage
                .as_ref()
                .and_then(|lineage| lineage.fork_evidence.as_ref()),
            None,
            "and the empty evidence slot stays empty — nothing installed"
        );
    }
    Ok(())
}

/// #732 r8 (Sol P1, new-alias authority — the ACTUAL production caller):
/// `import_group_card` inserts a clean discovered stub under the signed
/// card's STABLE key whenever that exact key is absent, while an active,
/// fork-quarantined record for the same stable id may live under an ALIAS
/// key (the route's own lookup does not resolve aliases). The generic
/// convergence used to read the insertion's `before=None →
/// Some((None, None))` as an authoritative containment CHANGE and copy
/// ABSENCE onto the quarantined alias — an ordinary, replayable, VALID
/// card import performed an unauthorized clear. Insertion is not a
/// containment mutation: the new stub JOINS the group's containment, and
/// the quarantined alias is untouched.
#[tokio::test]
async fn issue732_valid_card_import_cannot_clear_a_quarantined_alias() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let stable = "f4".repeat(32);
    let alias_key = format!("local-alias-{stable}");
    let marker = synthetic_marker(false)?;

    // The quarantined record exists ONLY under the alias; the stable key is
    // absent, so the import takes the insert branch.
    {
        let mut quarantined = x0x::groups::GroupInfo::with_policy(
            "card-import-alias".to_string(),
            String::new(),
            state.agent.agent_id(),
            stable.clone(),
            invite_only_policy(),
        );
        quarantined.state_revision = 5;
        quarantined.fork_quarantine = Some(marker.clone());
        state
            .named_groups
            .write()
            .await
            .insert(alias_key.clone(), quarantined);
    }

    // A genuinely valid, non-withdrawn, discoverable signed card.
    let creator = AgentKeypair::generate()?;
    let mut card = super::sample_group_card(&stable, 2, now_millis_u64());
    card.sign(&creator)?;
    let response = super::super::import_group_card(State(Arc::clone(&state)), Json(card))
        .await
        .into_response();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the valid card import is accepted — it is an ordinary supported operation"
    );

    {
        let groups = state.named_groups.read().await;
        assert!(
            groups.contains_key(&stable),
            "the import inserted the stable-keyed discovered stub"
        );
        for key in [alias_key.as_str(), stable.as_str()] {
            assert_eq!(
                groups[key].fork_quarantine.as_ref(),
                Some(&marker),
                "#732 r8: `{key}` — the new stub JOINED the group's containment and \
                 the quarantined alias was NOT cleared by an unauthorized insertion"
            );
        }
    }
    // And the cleared-map write never reached disk either.
    let merged =
        load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path).await?;
    for key in [alias_key.as_str(), stable.as_str()] {
        assert_eq!(
            merged[key].fork_quarantine.as_ref(),
            Some(&marker),
            "the durable bytes keep both spellings contained"
        );
    }

    // Control: a GENUINELY new group's card import inserts a clean stub —
    // Rule 2 has no sibling to join, so nothing is marked and nothing warns.
    let fresh_stable = "f5".repeat(32);
    let mut fresh_card = super::sample_group_card(&fresh_stable, 2, now_millis_u64());
    fresh_card.sign(&creator)?;
    let response = super::super::import_group_card(State(Arc::clone(&state)), Json(fresh_card))
        .await
        .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let groups = state.named_groups.read().await;
    assert!(
        !groups[&fresh_stable].is_fork_quarantined(),
        "a genuinely new group imports clean — no containment is invented"
    );
    assert!(
        groups[&fresh_stable]
            .invite_lineage
            .as_ref()
            .is_none_or(|lineage| lineage.fork_evidence.is_none()),
        "and no provenance is fabricated for a brand-new stub"
    );
    Ok(())
}
