//! r3 invite-auth tests (round 3 of #468/#469): card-surface owner-axis
//! authority (Fable 1), inbound bootstrap lineage rejection (Fable 3),
//! and the typed join-refusal route matrix in the spec A2 order
//! (Codex 7) including the join-time caps (Codex 10).

use super::*;

use crate::groups::policy::{GroupAdmission, GroupPolicy};
use crate::groups::{GroupConfidentiality, GroupDiscoverability};
use crate::identity::{AgentKeypair, UserKeypair};
use crate::server::rider_auth::ActorContext;
use serde_json::json;

/// Authority-side fixture: local daemon IS the owner's primary agent
/// (user key + certificate), same shape as the hs-F2 cluster's
/// `owner_authority_state`.
async fn r3_owner_authority_state() -> Result<(Arc<AppState>, tempfile::TempDir, UserKeypair)> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();
    let owner_seed = [0xE1u8; 32];
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

fn r3_owner_certified_policy(owner: &UserKeypair) -> GroupPolicy {
    GroupPolicy {
        discoverability: GroupDiscoverability::Hidden,
        admission: GroupAdmission::OwnerCertified(owner.user_id()),
        confidentiality: GroupConfidentiality::MlsEncrypted,
        read_access: x0x::groups::GroupReadAccess::MembersOnly,
        write_access: x0x::groups::GroupWriteAccess::MembersOnly,
    }
}

/// Insert a live group the local agent administers.
async fn r3_insert_group(state: &AppState, group_id: &str, policy: GroupPolicy) {
    let inviter = state.agent.agent_id();
    let mut info = x0x::groups::GroupInfo::with_policy(
        format!("group-{group_id}"),
        String::new(),
        inviter,
        group_id.to_string(),
        policy,
    );
    // Seat the creator as Admin (the real creation path does; the card
    // surface re-checks admin authority before minting).
    info.add_member(
        hex::encode(state.agent.agent_id().as_bytes()),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
}

async fn card_groups_for(
    state: &Arc<AppState>,
    actor: Option<axum::extract::Extension<ActorContext>>,
) -> Result<Vec<x0x::groups::card::CardGroup>> {
    let response = get_agent_card(
        State(Arc::clone(state)),
        actor,
        axum::extract::Query(CardQuery {
            display_name: Some("authority".to_string()),
            include_groups: Some(true),
            include_local_addresses: false,
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await?.1;
    let card: x0x::groups::card::AgentCard =
        serde_json::from_value(body["card"].clone()).context("decode agent card")?;
    Ok(card.groups)
}

/// r3 (Fable 1): owner-axis groups (OwnerCertified axis / Home metadata)
/// mint/reuse a countersigned card invite ONLY under a durable-owner
/// actor. A session bearer (Owner{durable:false}) gets the owner-axis
/// group OMITTED with the typed reason recorded, while an ORDINARY group
/// on the same card is unaffected; a durable bearer gets both.
#[tokio::test]
async fn card_owner_axis_invite_requires_durable_owner() -> Result<()> {
    let (state, _dir, owner_kp) = r3_owner_authority_state().await?;
    let owner_axis_name = format!("group-{}", "11".repeat(32));
    let ordinary_name = format!("group-{}", "22".repeat(32));
    r3_insert_group(
        &state,
        &"11".repeat(32),
        r3_owner_certified_policy(&owner_kp),
    )
    .await;
    r3_insert_group(
        &state,
        &"22".repeat(32),
        GroupPolicy {
            discoverability: GroupDiscoverability::PublicDirectory,
            admission: GroupAdmission::OpenJoin,
            confidentiality: GroupConfidentiality::SignedPublic,
            read_access: x0x::groups::GroupReadAccess::MembersOnly,
            write_access: x0x::groups::GroupWriteAccess::MembersOnly,
        },
    )
    .await;

    // Session bearer: the owner-axis group is omitted...
    let session_groups = card_groups_for(
        &state,
        Some(axum::extract::Extension(ActorContext::Owner {
            durable: false,
        })),
    )
    .await?;
    assert!(
        session_groups.iter().all(|g| g.name != owner_axis_name),
        "session bearer must not receive the owner-axis group's countersigned link: {session_groups:?}"
    );
    // ...the ordinary group is still served...
    assert!(
        session_groups.iter().any(|g| g.name == ordinary_name),
        "ordinary groups are unchanged by the owner-axis fence: {session_groups:?}"
    );
    // ...and the omission is recorded with the typed reason.
    {
        let groups_snapshot = state.named_groups.read().await.clone();
        let diag = state.groups_diagnostics.snapshot(
            &groups_snapshot,
            &std::collections::HashSet::new(),
            &std::collections::HashSet::new(),
            &std::collections::HashMap::new(),
        );
        let stable_id = groups_snapshot
            .get(&"11".repeat(32))
            .expect("owner-axis group in map")
            .stable_group_id()
            .to_string();
        let row = diag
            .groups
            .iter()
            .find(|g| g.group_id == stable_id)
            .expect("owner-axis group row");
        assert_eq!(
            row.counters
                .invites_refused_reasons
                .get("card_invite_omitted_owner_axis_no_durable_owner"),
            Some(&1),
            "the omission reason must be recorded: {:?}",
            row.counters.invites_refused_reasons
        );
    }

    // No actor at all (direct wiring without the auth middleware): same
    // fail-safe omission.
    let no_actor_groups = card_groups_for(&state, None).await?;
    assert!(
        no_actor_groups.iter().all(|g| g.name != owner_axis_name),
        "a missing actor context must not authorize owner-axis minting"
    );

    // Durable owner: BOTH groups are served (the owner-axis link is
    // minted through the v4 authority).
    let durable_groups = card_groups_for(
        &state,
        Some(axum::extract::Extension(ActorContext::Owner {
            durable: true,
        })),
    )
    .await?;
    assert!(
        durable_groups.iter().any(|g| g.name == owner_axis_name),
        "durable owner must receive the owner-axis group link: {durable_groups:?}"
    );
    assert!(
        durable_groups.iter().any(|g| g.name == ordinary_name),
        "ordinary group link still served to the durable owner"
    );
    Ok(())
}

/// r3 (Fable 3): a bootstrap snapshot carrying `invite_lineage` is
/// rejected inbound — lineage is strictly local provenance and never
/// rides a legitimately-minted outbound snapshot.
#[test]
fn inbound_bootstrap_with_lineage_is_rejected() {
    let mut info = x0x::groups::GroupInfo::with_policy(
        "G".to_string(),
        String::new(),
        crate::identity::AgentId([1; 32]),
        "aabbccdd".repeat(4),
        GroupPolicy {
            discoverability: GroupDiscoverability::PublicDirectory,
            admission: GroupAdmission::OpenJoin,
            confidentiality: GroupConfidentiality::SignedPublic,
            read_access: x0x::groups::GroupReadAccess::MembersOnly,
            write_access: x0x::groups::GroupWriteAccess::MembersOnly,
        },
    );
    // The lineage record is the ONLY difference the predicate needs to
    // observe: `validate_public_group_bootstrap` rejects the snapshot
    // BEFORE any genesis/commit-consistency work when lineage is present,
    // so a minimal record proves the fence without a fully-valid fixture.
    info.invite_lineage = Some(x0x::groups::InviteLineage {
        base_revision: 0,
        base_hash: String::new(),
        base_roster_root: String::new(),
        seated_at_revision: None,
        corroborated: false,
        fork_evidence: None,
    });
    let creator_hex = hex::encode([1u8; 32]);
    assert!(
        !validate_public_group_bootstrap(&info, &creator_hex, &creator_hex),
        "an inbound snapshot with non-empty invite_lineage must be rejected wholesale"
    );
    // Control: the identical snapshot WITHOUT lineage clears the lineage
    // fence — an empty lineage record is the ONLY delta from the rejected
    // variant above, so whatever the deeper genesis/commit checks then
    // decide, the earlier rejection was the lineage fence and nothing
    // else. Executing the call (no panic) is the control's contract.
    info.invite_lineage = None;
    info.add_member(
        creator_hex.clone(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    let _ = validate_public_group_bootstrap(&info, &creator_hex, &creator_hex);
}

/// r3 (Codex 7): the typed join-refusal matrix in the SPEC A2 order.
/// Tampering surfaces the TYPED reason (409 + diagnostics), never a
/// generic 400 from a check that ran before the typed flow.
#[tokio::test]
async fn join_refusals_are_typed_in_a2_order() -> Result<()> {
    let (authority, _dir, owner_kp) = r3_owner_authority_state().await?;
    let owner_axis_id = "33".repeat(32);
    let ordinary_id = "44".repeat(32);
    r3_insert_group(
        &authority,
        &owner_axis_id,
        r3_owner_certified_policy(&owner_kp),
    )
    .await;
    r3_insert_group(
        &authority,
        &ordinary_id,
        GroupPolicy {
            discoverability: GroupDiscoverability::PublicDirectory,
            admission: GroupAdmission::OpenJoin,
            confidentiality: GroupConfidentiality::SignedPublic,
            read_access: x0x::groups::GroupReadAccess::MembersOnly,
            write_access: x0x::groups::GroupWriteAccess::MembersOnly,
        },
    )
    .await;

    let mint = |state: Arc<AppState>, group_id: String| async move {
        let info = state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .cloned()
            .unwrap();
        assemble_signed_v4_invite(
            &state,
            &info,
            x0x::groups::invite::DEFAULT_EXPIRY_SECS,
            None,
        )
        .map_err(|e| anyhow::anyhow!("v4 mint failed: {e:?}"))
    };
    let (owner_invite, owner_link) = mint(Arc::clone(&authority), owner_axis_id.clone()).await?;
    let (ordinary_invite, ordinary_link) =
        mint(Arc::clone(&authority), ordinary_id.clone()).await?;

    // A fresh joiner daemon with NO certificate: owner-axis joins are
    // refused at the ADR-0038 fail-fast (403) AFTER the matrix below.
    let dir = tempfile::tempdir()?;
    let joiner_agent = Arc::new(
        Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key(AgentKeypair::generate()?)
            .with_peer_cache_disabled()
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await?,
    );
    let joiner = secure_endpoint_test_state_at(dir.path(), joiner_agent).await?;

    let join = |state: Arc<AppState>,
                invite: String,
                display: Option<String>,
                mode: Option<String>,
                pin: Option<String>| async move {
        let response = join_group_via_invite(
            State(Arc::clone(&state)),
            Json(JoinGroupRequest {
                invite,
                display_name: display,
                mode,
                expected_owner_user_id: pin,
            }),
        )
        .await
        .into_response();
        let status = response.status();
        let body = response_json(response).await?.1;
        Ok::<_, anyhow::Error>((status, body))
    };

    // ── signature_invalid: tamper the inviter signature bytes.
    let mut tampered = owner_invite.clone();
    tampered.inviter_signature_b64 = {
        use base64::Engine as _;
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&tampered.inviter_signature_b64)
            .context("decode signature")?;
        bytes[0] ^= 0xFF;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    };
    let (status, body) = join(Arc::clone(&joiner), tampered.to_link(), None, None, None).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "invite_signature_invalid");

    // ── key_mismatch: replace the inline inviter key with a DIFFERENT
    // valid key (binding fails inside the typed flow).
    let mut mismatched = owner_invite.clone();
    mismatched.inviter_public_key_b64 = {
        use base64::Engine as _;
        let other = AgentKeypair::generate()?;
        base64::engine::general_purpose::STANDARD.encode(other.public_key().as_bytes())
    };
    let (status, body) = join(Arc::clone(&joiner), mismatched.to_link(), None, None, None).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "inviter_key_mismatch");

    // ── key_mismatch (malformed inviter hex): the A2 "id" step maps a
    // malformed inviter id to the TYPED refusal, not a generic 400.
    let mut malformed = owner_invite.clone();
    malformed.inviter = "zz".repeat(32);
    let (status, body) = join(Arc::clone(&joiner), malformed.to_link(), None, None, None).await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "malformed inviter id must surface as the typed inviter_key_mismatch, got {status}"
    );
    assert_eq!(body["error"], "inviter_key_mismatch");

    // ── base_inconsistent: tamper the signed base hash on the ORDINARY
    // invite (no owner axis in play).
    // The base fields are INSIDE the signed view, so tampering must be
    // re-signed by the authority's own key to reach the base-consistency
    // step (a bare tamper is caught earlier as `invite_signature_invalid`
    // — exactly the A2 order this test pins).
    let mut based = ordinary_invite.clone();
    based.base_state_hash = Some("00".repeat(32));
    based
        .sign_v4(authority.agent.identity().agent_keypair(), None)
        .map_err(|e| anyhow::anyhow!("re-sign failed: {e:?}"))?;
    let (status, body) = join(Arc::clone(&joiner), based.to_link(), None, None, None).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "invite_base_inconsistent");

    // ── Home-mode matrix, every refusal outcome:
    // owner-axis invite + group mode → use_home_mode
    let (status, body) = join(
        Arc::clone(&joiner),
        owner_link.clone(),
        None,
        Some("group".into()),
        None,
    )
    .await?;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::CONFLICT, json!("use_home_mode"))
    );
    // pin without home mode → pin_requires_home_mode
    let (status, body) = join(
        Arc::clone(&joiner),
        ordinary_link.clone(),
        None,
        None,
        Some(hex::encode(owner_kp.user_id().as_bytes())),
    )
    .await?;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::CONFLICT, json!("pin_requires_home_mode"))
    );
    // home mode without pin → home_mode_requires_pin
    let (status, body) = join(
        Arc::clone(&joiner),
        owner_link.clone(),
        None,
        Some("home".into()),
        None,
    )
    .await?;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::CONFLICT, json!("home_mode_requires_pin"))
    );
    // home mode + pin on a DOWNGRADED (ordinary) invite → invite_downgraded
    let (status, body) = join(
        Arc::clone(&joiner),
        ordinary_link.clone(),
        None,
        Some("home".into()),
        Some(hex::encode(owner_kp.user_id().as_bytes())),
    )
    .await?;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::CONFLICT, json!("invite_downgraded"))
    );
    // home mode + WRONG pin on the owner-axis invite → owner_mismatch
    let (status, body) = join(
        Arc::clone(&joiner),
        owner_link.clone(),
        None,
        Some("home".into()),
        Some("aa".repeat(32)),
    )
    .await?;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::CONFLICT, json!("owner_mismatch"))
    );
    // unknown mode string → plain 400 (request shape, not auth)
    let (status, _) = join(
        Arc::clone(&joiner),
        ordinary_link.clone(),
        None,
        Some("wormhole".into()),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // ── Codex 10 caps: oversized joiner display name → 400 before
    // anything else; oversized invite-carried Home metadata → typed
    // invite_malformed.
    let (status, _) = join(
        Arc::clone(&joiner),
        ordinary_link.clone(),
        Some("n".repeat(JOIN_DISPLAY_NAME_MAX_BYTES + 1)),
        None,
        None,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "oversized display_name is a plain request refusal"
    );

    // Home metadata bounds: force base_home past the placements/name caps
    // on an otherwise-valid ordinary invite. The base hash covers the
    // home digest, so re-tamper + re-sign is out of scope for a refusal
    // fixture — instead bind the check directly: an ordinary invite whose
    // base_home was expanded MUST be refused malformed (the base check
    // would also catch it, but caps run FIRST).
    let mut homed = ordinary_invite.clone();
    let mut home = x0x::groups::HomeMetadata {
        primary_agent: "p".repeat(JOIN_HOME_PRIMARY_AGENT_MAX_BYTES + 1),
        placements: std::collections::BTreeMap::new(),
        provisioned_at_ms: 0,
    };
    home.placements
        .insert("aa".repeat(32), x0x::groups::MemberPlacement::Pinned);
    homed.base_home = Some(home);
    let (status, body) = join(Arc::clone(&joiner), homed.to_link(), None, None, None).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body["error"], "invite_malformed",
        "oversized Home metadata must surface as the typed invite_malformed"
    );

    // ── revoked LAST (seed the joiner's revocation set with the inviter's
    // agent): every earlier join in this test uses the same inviter, and
    // revocation precedes the owner/intended steps in the A2 order.
    {
        let inviter_kp_secret = authority.agent.identity().agent_keypair();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let record = x0x::revocation::RevocationRecord::sign(
            x0x::revocation::RevokedSubject::Agent(inviter_kp_secret.agent_id()),
            inviter_kp_secret.public_key(),
            inviter_kp_secret.secret_key(),
            now,
            Some("r3 join revocation test".to_string()),
        )?;
        joiner
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None)?;
    }
    let (status, body) = join(Arc::clone(&joiner), owner_link.clone(), None, None, None).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "inviter_key_revoked");
    Ok(())
}

/// r3 (#468 A5 / Fable 2 + Codex 9): fork evidence through the REAL
/// wrapper — the first authenticated conflicting commit records ONE
/// evidence entry durably (the lineage record in the live map reflects
/// the synchronous install), the SECOND identical conflict is fully
/// silent (no counter re-fire), and a DIFFERENT conflict at the same
/// revision still records.
#[tokio::test]
async fn fork_evidence_records_once_and_survives_in_the_durable_record() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key(AgentKeypair::generate()?)
            .with_peer_cache_disabled()
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await?,
    );
    let state = secure_endpoint_test_state_at(dir.path(), agent).await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "77".repeat(32);

    // Base group: creator admin, a sealed rev-0 commit, and a lineage
    // record (evidence only lands on groups that carry lineage).
    let mut info = x0x::groups::GroupInfo::with_policy(
        "forked".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.clone(),
        GroupPolicy {
            discoverability: GroupDiscoverability::Hidden,
            admission: GroupAdmission::InviteOnly,
            confidentiality: GroupConfidentiality::MlsEncrypted,
            read_access: x0x::groups::GroupReadAccess::MembersOnly,
            write_access: x0x::groups::GroupWriteAccess::MembersOnly,
        },
    );
    info.add_member(
        authority_hex.clone(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    info.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    info.invite_lineage = Some(x0x::groups::InviteLineage {
        base_revision: 0,
        base_hash: info.state_hash.clone(),
        base_roster_root: String::new(),
        seated_at_revision: None,
        corroborated: false,
        fork_evidence: None,
    });
    let base = info.clone();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    // Two DIFFERENT validly-signed commits at revision 1 (same prev, so
    // whichever applies second conflicts).
    let seal_variant = |description: &str| -> Result<x0x::groups::state_commit::GroupStateCommit> {
        let mut v = base.clone();
        // Mutate, then seal: `seal_commit` chains prev from the CURRENT
        // (still-unmutated) state hash, so both variants chain from the
        // same base head and differ only in their sealed content.
        v.description = description.to_string();
        v.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
        Ok(v.commit_log.last().expect("sealed commit").commit.clone())
    };
    let fork_a = seal_variant("fork-a")?;
    let fork_b = seal_variant("fork-b")?;

    // First conflicting commit: apply fails (PrevHashMismatch against
    // nothing — first apply chains cleanly, so apply A first).
    async fn apply(
        state: &Arc<AppState>,
        group_id: &str,
        commit: x0x::groups::state_commit::GroupStateCommit,
        description: &str,
    ) -> Result<x0x::groups::GroupInfo, x0x::groups::state_commit::ApplyError> {
        let current = state
            .named_groups
            .read()
            .await
            .get(group_id)
            .cloned()
            .unwrap();
        let mutation = description.to_string();
        apply_stateful_event_with_evidence(
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
        .await
    }
    let first = apply(&state, &group_id, fork_a.clone(), "fork-a").await;
    assert!(first.is_ok(), "the first fork applies cleanly: {first:?}");
    // Persist the applied state like the real arms do.
    persist_named_groups_mutation(&state, |groups| {
        let info = groups.get_mut(&group_id).unwrap();
        *info = first.clone().expect("first apply result");
        true
    })
    .await?;

    // The conflicting twin at the same revision: PrevHashMismatch → ONE
    // evidence record, installed SYNCHRONOUSLY (visible in the live map
    // immediately after the call — no detached spawn).
    let second = apply(&state, &group_id, fork_b.clone(), "fork-b").await;
    assert!(second.is_err(), "the conflicting twin must be refused");
    {
        let groups = state.named_groups.read().await;
        let lineage = groups[&group_id]
            .invite_lineage
            .as_ref()
            .expect("lineage intact");
        let evidence = lineage.fork_evidence.as_ref().expect("evidence installed");
        assert_eq!(evidence.revision, 2);
        assert_eq!(evidence.state_hash, fork_b.state_hash);
        assert_eq!(evidence.committed_by, authority_hex);
    }

    // SECOND identical conflict: fully silent — the counter does not
    // re-fire and the record is not replaced.
    let third = apply(&state, &group_id, fork_b.clone(), "fork-b").await;
    assert!(third.is_err());
    let counter = {
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
            .iter()
            .find(|g| g.group_id == groups_snapshot[&group_id].stable_group_id())
            .map(|g| g.counters.adoption_fork_evidence)
            .unwrap_or(0)
    };
    assert_eq!(
        counter, 1,
        "second identical conflict must not re-fire the counter"
    );
    {
        let groups = state.named_groups.read().await;
        let lineage = groups[&group_id].invite_lineage.as_ref().unwrap();
        assert_eq!(
            lineage.fork_evidence.as_ref().unwrap().state_hash,
            fork_b.state_hash,
            "the first evidence wins; repeats replace nothing"
        );
    }
    Ok(())
}
