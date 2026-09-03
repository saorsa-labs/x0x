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
/// r4 makes the test SOLE-CATCHING: the identical snapshot WITHOUT the
/// lineage record passes the fence AND every deeper genesis/commit
/// check (a full positive control), so the rejection is attributable to
/// the lineage fence alone.
#[test]
fn inbound_bootstrap_with_lineage_is_rejected() {
    // A fully-valid bootstrap snapshot: creator-admin sender, local
    // agent seated, SignedPublic, no secret/binding, one consistent
    // sealed commit, genesis bound to the stable id and creation time.
    let creator_kp = AgentKeypair::generate().expect("creator keypair");
    let creator = creator_kp.agent_id();
    let creator_hex = hex::encode(creator.as_bytes());
    let mut info = x0x::groups::GroupInfo::with_policy(
        "G".to_string(),
        String::new(),
        creator,
        "aabbccdd".repeat(4),
        GroupPolicy {
            discoverability: GroupDiscoverability::PublicDirectory,
            admission: GroupAdmission::OpenJoin,
            confidentiality: GroupConfidentiality::SignedPublic,
            read_access: x0x::groups::GroupReadAccess::MembersOnly,
            write_access: x0x::groups::GroupWriteAccess::MembersOnly,
        },
    );
    info.add_member(
        creator_hex.clone(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    info.seal_commit(&creator_kp, 1_000)
        .expect("bootstrap base seals");
    info.genesis = Some(x0x::groups::GroupGenesis::with_existing_id(
        info.stable_group_id().to_string(),
        creator_hex.clone(),
        info.created_at,
        hex::encode(blake3::hash(info.mls_group_id.as_bytes()).as_bytes()),
    ));

    // Positive control: WITHOUT lineage the snapshot clears the fence
    // AND every deeper check.
    assert!(
        validate_public_group_bootstrap(&info, &creator_hex, &creator_hex),
        "the identical snapshot WITHOUT lineage is accepted deeper (positive control)"
    );

    // The ONLY delta — a lineage record — flips the verdict wholesale.
    info.invite_lineage = Some(x0x::groups::InviteLineage {
        base_revision: 0,
        base_hash: String::new(),
        base_roster_root: String::new(),
        seated_at_revision: None,
        corroborated: false,
        fork_evidence: None,
    });
    assert!(
        !validate_public_group_bootstrap(&info, &creator_hex, &creator_hex),
        "an inbound snapshot with non-empty invite_lineage must be rejected wholesale"
    );
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

    // ── r5 (Codex 7a) combined: REVOKED inviter + INVALID owner
    // countersignature ⇒ the REVOCATION result fires. The inviter axis
    // (key binding + signature) passes — the bound-but-revoked key is
    // exactly the binding-then-revocation order — so the revocation
    // check, which sits between the inviter half and the owner half,
    // answers before any owner-key work. (The countersignature is not
    // signed-view input, so tampering it leaves the inviter signature
    // valid.)
    let mut revoked_and_broken = owner_invite.clone();
    revoked_and_broken.owner_countersignature_b64 = {
        use base64::Engine as _;
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(
                revoked_and_broken
                    .owner_countersignature_b64
                    .as_deref()
                    .context("countersignature present")?,
            )
            .context("decode countersignature")?;
        bytes[0] ^= 0xFF;
        Some(base64::engine::general_purpose::STANDARD.encode(bytes))
    };
    let (status, body) = join(
        Arc::clone(&joiner),
        revoked_and_broken.to_link(),
        None,
        None,
        None,
    )
    .await?;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::CONFLICT, json!("inviter_key_revoked")),
        "revocation must precede the owner countersignature check"
    );

    // ── r5 (Codex 7b) combined: INCONSISTENT base + MISSING owner
    // countersignature ⇒ invite_base_inconsistent — the base recompute
    // precedes the owner half (r5 Fable 1's reorder, pinned here at the
    // precedence level too). The roster entry is tampered and the view
    // re-signed by the inviter so the failure reaches the base check
    // instead of dying at the inviter signature.
    let mut based_and_unsigned = owner_invite.clone();
    {
        let authority_hex = hex::encode(authority.agent.agent_id().as_bytes());
        let roster = based_and_unsigned
            .base_roster
            .as_mut()
            .context("v4 projection present")?;
        let seat = roster
            .get_mut(&authority_hex)
            .context("authority seated in the projection")?;
        seat.role = x0x::groups::GroupRole::Member;
    }

    based_and_unsigned.owner_countersignature_b64 = None;
    based_and_unsigned
        .sign_v4(authority.agent.identity().agent_keypair(), None)
        .map_err(|e| anyhow::anyhow!("re-sign failed: {e:?}"))?;
    // A FRESH joiner: the first joiner's revocation set now names this
    // inviter, and revocation precedes the base check — the 7b pin
    // needs the base-vs-countersignature pair in isolation.
    let dir_b = tempfile::tempdir()?;
    let joiner_b_agent = Arc::new(
        Agent::builder()
            .with_machine_key(dir_b.path().join("machine.key"))
            .with_agent_key(AgentKeypair::generate()?)
            .with_peer_cache_disabled()
            .with_contact_store_path(dir_b.path().join("contacts.json"))
            .build()
            .await?,
    );
    let joiner_b = secure_endpoint_test_state_at(dir_b.path(), joiner_b_agent).await?;
    let (status, body) = join(
        Arc::clone(&joiner_b),
        based_and_unsigned.to_link(),
        None,
        None,
        None,
    )
    .await?;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::CONFLICT, json!("invite_base_inconsistent")),
        "base consistency must precede the owner countersignature check"
    );
    Ok(())
}

/// r5 (Fable 1): the A2 base-consistency recompute runs BEFORE the
/// owner countersignature — an owner-axis invite whose ROSTER ENTRY was
/// tampered (the projection no longer re-derives the signed base hash)
/// AND whose owner countersignature is MISSING refuses with
/// `invite_base_inconsistent`, never the countersignature reason. The
/// control leg (strip only, roster intact) proves the
/// missing-countersignature refusal is live in the same fixture, so the
/// ordering — not reachability — is what the first leg pins.
#[tokio::test]
async fn join_tampered_base_refuses_before_missing_owner_countersignature() -> Result<()> {
    let (authority, _dir, owner_kp) = r3_owner_authority_state().await?;
    let group_id = "9f".repeat(32);
    r3_insert_group(&authority, &group_id, r3_owner_certified_policy(&owner_kp)).await;
    let info = authority
        .named_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .context("seeded group")?;
    let (owner_invite, _) = assemble_signed_v4_invite(
        &authority,
        &info,
        x0x::groups::invite::DEFAULT_EXPIRY_SECS,
        None,
    )
    .map_err(|e| anyhow::anyhow!("v4 mint failed: {e:?}"))?;

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

    // COMBINED failure: tamper the authority's own roster entry (Admin →
    // Member — the projection no longer re-derives `base_state_hash`),
    // strip the owner countersignature, and re-sign ONLY the inviter
    // half over the tampered view so the invite survives the inviter
    // axis and reaches the base recompute.
    let mut tampered = owner_invite.clone();
    {
        let authority_hex = hex::encode(authority.agent.agent_id().as_bytes());
        let roster = tampered
            .base_roster
            .as_mut()
            .context("v4 projection present")?;
        let seat = roster
            .get_mut(&authority_hex)
            .context("authority seated in the projection")?;
        seat.role = x0x::groups::GroupRole::Member;
    }
    tampered.owner_countersignature_b64 = None;
    tampered
        .sign_v4(authority.agent.identity().agent_keypair(), None)
        .map_err(|e| anyhow::anyhow!("re-sign failed: {e:?}"))?;

    let response = join_group_via_invite(
        State(Arc::clone(&joiner)),
        Json(JoinGroupRequest {
            invite: tampered.to_link(),
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let status = response.status();
    let body = response_json(response).await?.1;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::CONFLICT, json!("invite_base_inconsistent")),
        "a tampered base must refuse with invite_base_inconsistent EVEN \
         when the owner countersignature is also missing"
    );

    // CONTROL (same fixture, roster intact): the stripped countersignature
    // alone refuses with the countersignature reason — proving that leg
    // is reachable and the first leg genuinely pinned the ORDER.
    let mut stripped = owner_invite;
    stripped.owner_countersignature_b64 = None;
    let response = join_group_via_invite(
        State(Arc::clone(&joiner)),
        Json(JoinGroupRequest {
            invite: stripped.to_link(),
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let status = response.status();
    let body = response_json(response).await?.1;
    assert_eq!(
        (status, body["error"].clone()),
        (
            StatusCode::CONFLICT,
            json!("invite_owner_countersignature_missing")
        ),
        "control: with the base intact the missing countersignature fires its own reason"
    );
    Ok(())
}

/// r3 (#468 A5 / Fable 2 + Codex 9) → r4 (addendum item 7): fork
/// evidence through the REAL wrapper — the first authenticated
/// conflicting commit records ONE evidence entry durably (the lineage
/// record in the live map reflects the synchronous install), the SECOND
/// identical conflict is fully silent (no counter re-fire), a DIFFERENT
/// post-first conflict is silent too (first COMPLETE evidence wins; no
/// warn for anything after the first STORED record), and the record
/// survives a full store RELOAD from disk verbatim (the r4 restart leg).
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

    // r4 (addendum item 7): a DIFFERENT conflict after the first STORED
    // evidence is fully silent — no warn, no counter, no replacement.
    let fork_c = seal_variant("fork-c")?;
    let fourth = apply(&state, &group_id, fork_c, "fork-c").await;
    assert!(fourth.is_err(), "the different conflict is still refused");
    {
        let groups_snapshot = state.named_groups.read().await.clone();
        let row = state
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
            .cloned()
            .expect("diagnostics row");
        assert_eq!(
            row.counters.adoption_fork_evidence, 1,
            "a different post-first conflict must not re-fire any diagnostics"
        );
        let groups = state.named_groups.read().await;
        assert_eq!(
            groups[&group_id]
                .invite_lineage
                .as_ref()
                .unwrap()
                .fork_evidence
                .as_ref()
                .unwrap()
                .state_hash,
            fork_b.state_hash,
            "first COMPLETE evidence wins; a different conflict changes nothing"
        );
    }

    // r4 (original round-4 item 6): the RELOAD leg — drop the in-memory
    // map entirely and rebuild it from disk through the store loader;
    // the lineage record with its fork evidence must be present
    // VERBATIM.
    {
        let live_record = state.named_groups.read().await[&group_id].clone();
        let reloaded =
            load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path)
                .await?;
        let reloaded_record = reloaded
            .get(&group_id)
            .expect("group survives the store reload");
        assert_eq!(
            reloaded_record.invite_lineage, live_record.invite_lineage,
            "the lineage record (fork_evidence included) reloads verbatim from disk"
        );
        let evidence = reloaded_record
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.fork_evidence.clone())
            .expect("reloaded lineage carries the fork evidence");
        assert_eq!(evidence.revision, 2);
        assert_eq!(evidence.state_hash, fork_b.state_hash);
        assert_eq!(evidence.committed_by, authority_hex);
    }

    // r5 (Codex 8): the REPLAY leg — install the disk-rebuilt store as
    // the live map and replay the IDENTICAL conflict: the reloaded
    // lineage's evidence gate must silence it — no re-warn, no counter
    // increment, no record replacement.
    {
        let reloaded =
            load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path)
                .await?;
        *state.named_groups.write().await = reloaded;
        let replayed = apply(&state, &group_id, fork_b.clone(), "fork-b").await;
        assert!(
            replayed.is_err(),
            "the identical conflict is still refused after the disk rebuild"
        );
        assert_eq!(
            r4_diag_row(&state, &group_id)
                .await
                .counters
                .adoption_fork_evidence,
            1,
            "the disk-rebuilt state does NOT re-fire the once-only diagnostics \
             on the identical replay"
        );
        let groups = state.named_groups.read().await;
        assert_eq!(
            groups[&group_id]
                .invite_lineage
                .as_ref()
                .unwrap()
                .fork_evidence
                .as_ref()
                .unwrap()
                .state_hash,
            fork_b.state_hash,
            "the replay replaces nothing — the first stored record wins"
        );
    }
    Ok(())
}

// ── r4 (hs-FU-A round 4): typed join refusals, precedence, mint
// transaction, intended-joiner end-to-end, evidence matrix ───────────────

/// The stable-id keyed diagnostics row for a group in the live map.
async fn r4_diag_row(
    state: &AppState,
    group_id: &str,
) -> crate::groups::diagnostics::GroupDiagnostic {
    let groups_snapshot = state.named_groups.read().await.clone();
    let stable = groups_snapshot
        .get(group_id)
        .unwrap_or_else(|| panic!("group {group_id} present"))
        .stable_group_id()
        .to_string();
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
        .find(|g| g.group_id == stable)
        .unwrap_or_else(|| panic!("diagnostics row for {group_id}"))
}

/// r4 (original item 2): the three typed join refusals that were not
/// individually pinned — each surfaces the EXACT typed reason string in
/// the response body AND the `invites_refused{reason}` counter.
#[tokio::test]
async fn join_refusals_version_countersignature_and_addressing_are_typed() -> Result<()> {
    let (authority, _dir, owner_kp) = r3_owner_authority_state().await?;
    let owner_axis_id = "55".repeat(32);
    let ordinary_id = "66".repeat(32);
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
    let (owner_invite, _) = mint(Arc::clone(&authority), owner_axis_id.clone()).await?;
    let _ = mint(Arc::clone(&authority), ordinary_id.clone()).await?;

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
    // Seat placeholder records in the JOINER's map so the per-group
    // diagnostics rows exist for the refusal counters (the typed A2
    // checks all run BEFORE the duplicate/stub handling, so a present
    // group changes nothing about the refusals under test).
    for id in [&owner_axis_id, &ordinary_id] {
        let stub = x0x::groups::GroupInfo::with_policy(
            format!("group-{id}"),
            String::new(),
            joiner.agent.agent_id(),
            id.to_string(),
            GroupPolicy::default(),
        );
        joiner
            .named_groups
            .write()
            .await
            .insert(id.to_string(), stub);
    }

    let join = |state: Arc<AppState>, invite: String| async move {
        let response = join_group_via_invite(
            State(Arc::clone(&state)),
            Json(JoinGroupRequest {
                invite,
                display_name: None,
                mode: None,
                expected_owner_user_id: None,
            }),
        )
        .await
        .into_response();
        let status = response.status();
        let body = response_json(response).await?.1;
        Ok::<_, anyhow::Error>((status, body))
    };

    // ── invite_unsigned: version < 4 refuses at view construction.
    let mut downgraded = owner_invite.clone();
    downgraded.version = 3;
    let (status, body) = join(Arc::clone(&joiner), downgraded.to_link()).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body["error"], "invite_unsigned",
        "a version<4 invite must surface the typed invite_unsigned"
    );
    assert_eq!(
        r4_diag_row(&joiner, &owner_axis_id)
            .await
            .counters
            .invites_refused_reasons
            .get("invite_unsigned"),
        Some(&1),
        "invite_unsigned must be counted in invites_refused{{reason}}"
    );

    // ── invite_owner_countersignature_missing: owner-axis invite with
    // the countersignature stripped (base consistency still passes — the
    // countersignature is an output, not signed view input).
    let mut stripped = owner_invite.clone();
    stripped.owner_countersignature_b64 = None;
    let (status, body) = join(Arc::clone(&joiner), stripped.to_link()).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body["error"], "invite_owner_countersignature_missing",
        "a stripped owner countersignature must surface the typed reason"
    );
    assert_eq!(
        r4_diag_row(&joiner, &owner_axis_id)
            .await
            .counters
            .invites_refused_reasons
            .get("invite_owner_countersignature_missing"),
        Some(&1),
        "the countersignature refusal must be counted"
    );

    // ── invite_not_addressed_to_me: an ordinary invite addressed to
    // ANOTHER agent (the intended check is A2 step 10 — LAST).
    let intended = AgentKeypair::generate()?;
    let addressed = {
        let info = authority
            .named_groups
            .read()
            .await
            .get(&ordinary_id)
            .cloned()
            .unwrap();
        assemble_signed_v4_invite(
            &authority,
            &info,
            x0x::groups::invite::DEFAULT_EXPIRY_SECS,
            Some(intended.agent_id()),
        )
        .map_err(|e| anyhow::anyhow!("addressed mint failed: {e:?}"))?
        .1
    };
    let (status, body) = join(Arc::clone(&joiner), addressed).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body["error"], "invite_not_addressed_to_me",
        "a join by anyone but the intended joiner must surface the typed reason"
    );
    assert_eq!(
        r4_diag_row(&joiner, &ordinary_id)
            .await
            .counters
            .invites_refused_reasons
            .get("invite_not_addressed_to_me"),
        Some(&1),
        "the not-addressed refusal must be counted"
    );
    Ok(())
}

/// r4 (addendum item 8): the two precedence pins the A2 order demands —
/// the legacy `signature` refusal fires BEFORE the expiry 400, and the
/// expiry 400 fires BEFORE any cryptographic key/signature work.
#[tokio::test]
async fn join_precedence_legacy_signature_and_expiry() -> Result<()> {
    let (authority, _dir, _owner_kp) = r3_owner_authority_state().await?;
    let ordinary_id = "88".repeat(32);
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
    let info = authority
        .named_groups
        .read()
        .await
        .get(&ordinary_id)
        .cloned()
        .unwrap();
    let (invite, _) = assemble_signed_v4_invite(
        &authority, &info, // Expiry long past: the invite IS expired for both legs below.
        1, None,
    )
    .map_err(|e| anyhow::anyhow!("mint failed: {e:?}"))?;

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

    let join = |state: Arc<AppState>, invite: x0x::groups::invite::SignedInvite| async move {
        let response = join_group_via_invite(
            State(Arc::clone(&state)),
            Json(JoinGroupRequest {
                invite: invite.to_link(),
                display_name: None,
                mode: None,
                expected_owner_user_id: None,
            }),
        )
        .await
        .into_response();
        let status = response.status();
        let body = response_json(response).await?.1;
        Ok::<_, anyhow::Error>((status, body))
    };

    // Force the invite into expiry deterministically (a 1970 deadline):
    // both legs below are joins with an EXPIRED invite.
    let mut invite = invite;
    invite.expires_at = 1;

    // Legacy-sig BEFORE expiry: an expired invite carrying a non-empty
    // legacy signature refuses with the TYPED invite_signature_invalid,
    // not the plain expiry 400.
    let mut legacy = invite.clone();
    legacy.signature = "legacy-sig".to_string();
    let (status, body) = join(Arc::clone(&joiner), legacy).await?;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::CONFLICT, json!("invite_signature_invalid")),
        "legacy-sig refusal must precede the expiry check"
    );

    // Expiry BEFORE cryptography: an expired invite with a TAMPERED
    // inviter signature answers the plain 400 expiry refusal — the clock
    // check runs before any key/signature work.
    let mut tampered = invite;
    tampered.inviter_signature_b64 = {
        use base64::Engine as _;
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&tampered.inviter_signature_b64)
            .context("decode signature")?;
        bytes[0] ^= 0xFF;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    };
    let (status, body) = join(Arc::clone(&joiner), tampered).await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expiry must precede the cryptographic checks: {body}"
    );
    assert_eq!(body["error"], "invite has expired");
    Ok(())
}

/// r4 (original item 3 + addendum item 6): the mint route's typed
/// refusal surface through the SINGLE mint transaction — live-cap 429,
/// D5 cap 413, owner-key 409, and the rollback leg (a failed durable
/// persist leaves NO recorded secret behind).
#[tokio::test]
async fn mint_route_refusals_cap_size_owner_key_and_rollback() -> Result<()> {
    // ── invite_cap_reached: 64 live records ⇒ 429 + typed body.
    {
        let (state, _dir, owner_kp) = r3_owner_authority_state().await?;
        let group_id = "99".repeat(32);
        r3_insert_group(&state, &group_id, r3_owner_certified_policy(&owner_kp)).await;
        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_id).unwrap();
            let now_secs = now_millis_u64() / 1_000;
            for i in 0..x0x::groups::MAX_LIVE_ISSUED_INVITES_PER_GROUP {
                info.record_issued_invite_v2(
                    format!("cap-secret-{i}"),
                    now_secs,
                    0,
                    x0x::groups::GroupRole::Member,
                    None,
                    x0x::groups::InviteOrigin::Explicit,
                    None,
                );
            }
        }
        let response = create_group_invite(
            State(Arc::clone(&state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path(group_id.clone()),
            HeaderMap::new(),
            axum::body::Bytes::new(),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"], "invite_cap_reached");
        assert_eq!(
            body["limit"],
            json!(x0x::groups::MAX_LIVE_ISSUED_INVITES_PER_GROUP),
            "the cap body carries the limit"
        );
        // Nothing further was recorded at the cap.
        let live = state.named_groups.read().await[&group_id]
            .live_issued_invite_count(now_millis_u64() / 1_000);
        assert_eq!(
            live,
            x0x::groups::MAX_LIVE_ISSUED_INVITES_PER_GROUP,
            "the refused mint records no secret"
        );
    }

    // ── invite_too_large: a group name past the D5 cap ⇒ 413 + field.
    {
        let (state, _dir, owner_kp) = r3_owner_authority_state().await?;
        let group_id = "aa".repeat(32);
        r3_insert_group(&state, &group_id, r3_owner_certified_policy(&owner_kp)).await;
        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_id).unwrap();
            info.name = "n".repeat(x0x::groups::invite::INVITE_MAX_GROUP_NAME + 1);
        }
        let response = create_group_invite(
            State(Arc::clone(&state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path(group_id.clone()),
            HeaderMap::new(),
            axum::body::Bytes::new(),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["error"], "invite_too_large");
        assert_eq!(
            body["field"], "group_name",
            "the 413 body names the offending field"
        );
    }

    // ── owner_key_unavailable: owner-axis group, daemon holds NO local
    // user key ⇒ 409 with the typed message.
    {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "bb".repeat(32);
        let other_owner = UserKeypair::generate()?;
        r3_insert_group(&state, &group_id, r3_owner_certified_policy(&other_owner)).await;
        let response = create_group_invite(
            State(Arc::clone(&state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path(group_id.clone()),
            HeaderMap::new(),
            axum::body::Bytes::new(),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::CONFLICT);
        // r5 (Codex 9): the EXACT typed error value — a starts_with
        // prefix would tolerate a truncated or edited message silently.
        assert_eq!(
            body["error"],
            json!(
                "owner_key_unavailable: minting an owner-axis (Home-capable) \
                 invite requires the durable owner's loaded user key"
            ),
            "owner-axis mint without a local owner key is the typed 409"
        );
    }

    // ── rollback: a failed durable persist ⇒ 503 AND the in-memory map
    // carries NO new live secret (the #470 compare-and-restore rolled it
    // back); clearing the fault lets the identical mint succeed.
    {
        let (state, _dir, owner_kp) = r3_owner_authority_state().await?;
        let group_id = "cc".repeat(32);
        r3_insert_group(&state, &group_id, r3_owner_certified_policy(&owner_kp)).await;
        let before = state.named_groups.read().await[&group_id]
            .live_issued_invite_count(now_millis_u64() / 1_000);
        {
            let _fault = set_save_fault(SaveFault::Error);
            let response = create_group_invite(
                State(Arc::clone(&state)),
                axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                    durable: true,
                }),
                Path(group_id.clone()),
                HeaderMap::new(),
                axum::body::Bytes::new(),
            )
            .await
            .into_response();
            let (status, body) = response_json(response).await?;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["error"], "named-group state is not directory-durable");
            let after = state.named_groups.read().await[&group_id]
                .live_issued_invite_count(now_millis_u64() / 1_000);
            assert_eq!(
                after, before,
                "the rolled-back mint must leave NO live secret in memory"
            );
            // (The two-file save under the legacy-write fault may leave a
            // torn on-disk image — the #470 contract restores the LIVE
            // map; the never-handed-out secret is what must not exist.)
        }
        let response = create_group_invite(
            State(Arc::clone(&state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path(group_id.clone()),
            HeaderMap::new(),
            axum::body::Bytes::new(),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "mint succeeds once the fault clears"
        );
        assert_eq!(body["ok"], json!(true));
        let after = state.named_groups.read().await[&group_id]
            .live_issued_invite_count(now_millis_u64() / 1_000);
        assert_eq!(
            after,
            before + 1,
            "the retried mint records exactly one secret"
        );
    }
    Ok(())
}

/// r4 (addendum item 6): the card mint surface through the REAL auth
/// middleware with a SESSION bearer — the route-layer durable fence does
/// not cover GET /agent/card, so the actor arrives as
/// Owner{durable:false} and the handler-side fence (now folded into the
/// shared mint transaction) must omit the owner-axis group's link.
#[tokio::test]
async fn card_session_bearer_through_middleware_omits_owner_axis() -> Result<()> {
    let (state, _dir, owner_kp) = r3_owner_authority_state().await?;
    let owner_axis_id = "dd".repeat(32);
    let ordinary_id = "ee".repeat(32);
    r3_insert_group(&state, &owner_axis_id, r3_owner_certified_policy(&owner_kp)).await;
    r3_insert_group(
        &state,
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

    // The real wiring: the card route behind the bearer auth middleware.
    use tower::ServiceExt as _;
    let app = axum::Router::new()
        .route(
            "/agent/card",
            axum::routing::get(crate::server::routes::identity::get_agent_card),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::server::auth::auth_middleware,
        ))
        .with_state(Arc::clone(&state));

    // A short-lived browser SESSION token (NOT the durable api token).
    let session = state.sessions.issue(std::time::Instant::now());
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::GET)
                .uri("/agent/card?include_groups=true&display_name=authority")
                .header("authorization", format!("Bearer {session}"))
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let (_, body) = response_json(response).await?;
    let card: x0x::groups::card::AgentCard =
        serde_json::from_value(body["card"].clone()).context("decode card")?;
    let names: Vec<String> = card.groups.iter().map(|g| g.name.clone()).collect();
    assert!(
        !names.contains(&format!("group-{owner_axis_id}")),
        "a session bearer must not receive the owner-axis link through the middleware: {names:?}"
    );
    assert!(
        names.contains(&format!("group-{ordinary_id}")),
        "the ordinary group's link is unaffected: {names:?}"
    );
    // The omission is typed, exactly like the direct-call r3 test.
    assert_eq!(
        r4_diag_row(&state, &owner_axis_id)
            .await
            .counters
            .invites_refused_reasons
            .get("card_invite_omitted_owner_axis_no_durable_owner"),
        Some(&1),
        "the middleware-delivered session bearer's omission is counted"
    );
    Ok(())
}

/// r4 (addendum item 6): the card surface's cap/owner-key/oversize
/// refusals all flow through the SHARED mint transaction and surface the
/// typed omission counters; the rollback leg leaves no live secret.
#[tokio::test]
async fn card_mint_refusals_share_the_transaction() -> Result<()> {
    // ── cap: 64 live records ⇒ omitted + card_invite_omitted_cap_reached.
    {
        let (state, _dir, owner_kp) = r3_owner_authority_state().await?;
        let group_id = "1d".repeat(32);
        r3_insert_group(&state, &group_id, r3_owner_certified_policy(&owner_kp)).await;
        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_id).unwrap();
            let now_secs = now_millis_u64() / 1_000;
            for i in 0..x0x::groups::MAX_LIVE_ISSUED_INVITES_PER_GROUP {
                info.record_issued_invite_v2(
                    format!("card-cap-{i}"),
                    now_secs,
                    0,
                    x0x::groups::GroupRole::Member,
                    None,
                    x0x::groups::InviteOrigin::Card,
                    None,
                );
            }
        }
        let groups = card_groups_for(
            &state,
            Some(axum::extract::Extension(
                crate::server::rider_auth::ActorContext::Owner { durable: true },
            )),
        )
        .await?;
        assert!(
            groups.iter().all(|g| g.name != format!("group-{group_id}")),
            "the capped group is omitted from the card"
        );
        assert_eq!(
            r4_diag_row(&state, &group_id)
                .await
                .counters
                .invites_refused_reasons
                .get("card_invite_omitted_cap_reached"),
            Some(&1)
        );
    }

    // ── owner key: owner-axis group, no local user key ⇒ omitted +
    // card_invite_omitted_owner_axis.
    {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let group_id = "2d".repeat(32);
        let other_owner = UserKeypair::generate()?;
        r3_insert_group(&state, &group_id, r3_owner_certified_policy(&other_owner)).await;
        let groups = card_groups_for(
            &state,
            Some(axum::extract::Extension(
                crate::server::rider_auth::ActorContext::Owner { durable: true },
            )),
        )
        .await?;
        assert!(
            groups.iter().all(|g| g.name != format!("group-{group_id}")),
            "the owner-keyless group is omitted from the card"
        );
        assert_eq!(
            r4_diag_row(&state, &group_id)
                .await
                .counters
                .invites_refused_reasons
                .get("card_invite_omitted_owner_axis"),
            Some(&1)
        );
    }

    // ── oversize: name past the D5 cap ⇒ omitted +
    // card_invite_omitted_mint_failed.
    {
        let (state, _dir, owner_kp) = r3_owner_authority_state().await?;
        let group_id = "3d".repeat(32);
        r3_insert_group(&state, &group_id, r3_owner_certified_policy(&owner_kp)).await;
        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_id).unwrap();
            info.name = "n".repeat(x0x::groups::invite::INVITE_MAX_GROUP_NAME + 1);
        }
        let groups = card_groups_for(
            &state,
            Some(axum::extract::Extension(
                crate::server::rider_auth::ActorContext::Owner { durable: true },
            )),
        )
        .await?;
        assert!(
            groups.iter().all(|g| g.name != "n".repeat(130)),
            "the oversize group is omitted from the card"
        );
        assert_eq!(
            r4_diag_row(&state, &group_id)
                .await
                .counters
                .invites_refused_reasons
                .get("card_invite_omitted_mint_failed"),
            Some(&1)
        );
    }

    // ── rollback: failed durable persist ⇒ omitted +
    // card_invite_omitted_not_durable, and NO live secret remains.
    {
        let (state, _dir, owner_kp) = r3_owner_authority_state().await?;
        let group_id = "4d".repeat(32);
        r3_insert_group(&state, &group_id, r3_owner_certified_policy(&owner_kp)).await;
        let before = state.named_groups.read().await[&group_id]
            .live_issued_invite_count(now_millis_u64() / 1_000);
        let _fault = set_save_fault(SaveFault::Error);
        let groups = card_groups_for(
            &state,
            Some(axum::extract::Extension(
                crate::server::rider_auth::ActorContext::Owner { durable: true },
            )),
        )
        .await?;
        assert!(
            groups.iter().all(|g| g.name != format!("group-{group_id}")),
            "the not-durable group is omitted from the card"
        );
        assert_eq!(
            r4_diag_row(&state, &group_id)
                .await
                .counters
                .invites_refused_reasons
                .get("card_invite_omitted_not_durable"),
            Some(&1)
        );
        assert_eq!(
            state.named_groups.read().await[&group_id]
                .live_issued_invite_count(now_millis_u64() / 1_000),
            before,
            "the rolled-back card mint leaves NO live secret"
        );
    }
    Ok(())
}

/// r5 (Codex 4): two CONCURRENT card GETs for one group — phase 1's
/// reuse scan runs UNLOCKED, so both getters can miss reuse and each
/// mint. The re-check inside the serialized (membership-locked) section
/// must serve the first getter's link to the second: exactly ONE new
/// issuance record and BOTH responses carry the SAME link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_card_gets_share_one_minted_invite() -> Result<()> {
    let (state, _dir, owner_kp) = r3_owner_authority_state().await?;
    let group_id = "bf".repeat(32);
    r3_insert_group(&state, &group_id, r3_owner_certified_policy(&owner_kp)).await;
    let name = format!("group-{group_id}");

    let get_card_groups = |state: Arc<AppState>| async move {
        let response = get_agent_card(
            State(state),
            Some(axum::extract::Extension(
                crate::server::rider_auth::ActorContext::Owner { durable: true },
            )),
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
        Ok::<_, anyhow::Error>(card.groups)
    };
    let (first, second) = tokio::join!(
        get_card_groups(Arc::clone(&state)),
        get_card_groups(Arc::clone(&state))
    );
    let first = first?;
    let second = second?;

    let link_of = |groups: &[x0x::groups::card::CardGroup]| -> String {
        groups
            .iter()
            .find(|g| g.name == name)
            .unwrap_or_else(|| panic!("group {name} served on the card"))
            .invite_link
            .clone()
    };
    let first_link = link_of(&first);
    let second_link = link_of(&second);
    assert_eq!(
        first_link, second_link,
        "both concurrent card GETs serve the SAME link"
    );
    let card_origin_records = state.named_groups.read().await[&group_id]
        .issued_invites
        .values()
        .filter(|record| matches!(record.origin, x0x::groups::InviteOrigin::Card))
        .count();
    assert_eq!(
        card_origin_records, 1,
        "exactly ONE new Card-origin issuance record across both GETs"
    );
    assert_eq!(
        state.named_groups.read().await[&group_id]
            .live_issued_invite_count(now_millis_u64() / 1_000),
        1,
        "the group carries exactly one live invite after the race"
    );
    Ok(())
}

/// r4 (original item 4a): an ADDRESSED invite under CONCURRENT
/// MemberJoined volleys — the wrong agent's volley is refused with the
/// not-addressed refusal (the one-time secret SURVIVES for the rightful
/// joiner), and exactly ONE consumption happens: the addressed joiner's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn addressed_invite_consumed_exactly_once_under_concurrent_volleys() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "5e".repeat(32);
    let invite_secret = "addressed-concurrency-secret".to_string();

    let mut info = x0x::groups::GroupInfo::with_policy(
        "addressed".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.clone(),
        x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
    );
    info.add_member(
        authority_hex.clone(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    // The ADDRESSED record: intended joiner = A.
    let addressed_kp = AgentKeypair::generate()?;
    let addressed_hex = hex::encode(addressed_kp.agent_id().as_bytes());
    info.record_issued_invite_v2(
        invite_secret.clone(),
        now_millis_u64() / 1_000,
        0,
        x0x::groups::GroupRole::Member,
        Some(addressed_hex.clone()),
        x0x::groups::InviteOrigin::Explicit,
        None,
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    // Two CONCURRENT volleys for the same addressed secret: the rightful
    // joiner A and a wrong agent W.
    let wrong_kp = AgentKeypair::generate()?;
    let (wrong_id, _wrong_hex, _pk, wrong_event) = signed_member_joined_event_for_test(
        &wrong_kp,
        &group_id,
        &authority_hex,
        &invite_secret,
        x0x::groups::GroupRole::Member,
    )?;
    let (addressed_id, _a_hex, _pk, addressed_event) = signed_member_joined_event_for_test(
        &addressed_kp,
        &group_id,
        &authority_hex,
        &invite_secret,
        x0x::groups::GroupRole::Member,
    )?;
    let wrong_state = Arc::clone(&state);
    let wrong = tokio::spawn(async move {
        apply_named_group_metadata_event(&wrong_state, wrong_event, wrong_id, true, None).await
    });
    let right_state = Arc::clone(&state);
    let right = tokio::spawn(async move {
        apply_named_group_metadata_event(&right_state, addressed_event, addressed_id, true, None)
            .await
    });
    let wrong = wrong.await?;
    let right = right.await?;

    // Whichever order the serialized applies ran in, the outcome set is
    // fixed: the addressed joiner is seated, the wrong agent is refused
    // with the not-addressed reason, and the secret was consumed ONCE —
    // by the addressed joiner.
    assert!(
        right.accepted,
        "the addressed joiner's volley must be accepted (either order)"
    );
    assert!(
        !wrong.accepted,
        "the wrong agent's volley must be refused (either order)"
    );
    {
        let groups = state.named_groups.read().await;
        let info = &groups[&group_id];
        assert!(
            info.has_active_member(&addressed_hex),
            "the addressed joiner is seated"
        );
        assert!(
            !info.has_active_member(&hex::encode(wrong_kp.agent_id().as_bytes())),
            "the wrong agent is never seated"
        );
        let record = info
            .issued_invites
            .get(&invite_secret)
            .expect("the consumed record persists for audit");
        assert_eq!(
            record.consumed_by.as_deref(),
            Some(addressed_hex.as_str()),
            "EXACTLY ONE consumption — by the addressed joiner"
        );
    }
    assert_eq!(
        r4_diag_row(&state, &group_id)
            .await
            .counters
            .invites_refused_reasons
            .get("invite_not_addressed_to_joiner"),
        Some(&1),
        "the wrong agent's refusal is the not-addressed reason"
    );
    Ok(())
}

/// r5 (Codex 6): an UNADDRESSED invite under CONCURRENT MemberJoined
/// volleys from TWO DIFFERENT agents — first-joiner-wins: exactly ONE
/// consumption happens, the winner is seated, and the loser's volley is
/// refused (the one-time secret does not admit two members no matter
/// how the serialized applies interleave).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unaddressed_invite_first_joiner_wins_under_concurrent_volleys() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "af".repeat(32);
    let invite_secret = "unaddressed-concurrency-secret".to_string();

    let mut info = x0x::groups::GroupInfo::with_policy(
        "unaddressed".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.clone(),
        x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
    );
    info.add_member(
        authority_hex.clone(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    // The UNADDRESSED record: no intended joiner — either agent may
    // consume it, but only ONE may.
    info.record_issued_invite_v2(
        invite_secret.clone(),
        now_millis_u64() / 1_000,
        0,
        x0x::groups::GroupRole::Member,
        None,
        x0x::groups::InviteOrigin::Explicit,
        None,
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    // Two CONCURRENT volleys from two DIFFERENT agents on the same
    // unaddressed secret.
    let first_kp = AgentKeypair::generate()?;
    let second_kp = AgentKeypair::generate()?;
    let (first_id, first_hex, _pk, first_event) = signed_member_joined_event_for_test(
        &first_kp,
        &group_id,
        &authority_hex,
        &invite_secret,
        x0x::groups::GroupRole::Member,
    )?;
    let (second_id, second_hex, _pk, second_event) = signed_member_joined_event_for_test(
        &second_kp,
        &group_id,
        &authority_hex,
        &invite_secret,
        x0x::groups::GroupRole::Member,
    )?;
    let first_state = Arc::clone(&state);
    let first = tokio::spawn(async move {
        apply_named_group_metadata_event(&first_state, first_event, first_id, true, None).await
    });
    let second_state = Arc::clone(&state);
    let second = tokio::spawn(async move {
        apply_named_group_metadata_event(&second_state, second_event, second_id, true, None).await
    });
    let first = first.await?;
    let second = second.await?;

    // Whichever volley serialized first, EXACTLY ONE consumption: one
    // apply accepted, the other refused — never both, never neither.
    assert_ne!(
        first.accepted, second.accepted,
        "exactly ONE of the two concurrent volleys is accepted"
    );
    let winner_hex = if first.accepted {
        &first_hex
    } else {
        &second_hex
    };
    let loser_hex = if first.accepted {
        &second_hex
    } else {
        &first_hex
    };
    {
        let groups = state.named_groups.read().await;
        let info = &groups[&group_id];
        assert!(
            info.has_active_member(winner_hex),
            "the first joiner to serialize is seated"
        );
        assert!(
            !info.has_active_member(loser_hex),
            "the second volley's agent is never seated"
        );
        let record = info
            .issued_invites
            .get(&invite_secret)
            .expect("the consumed record persists for audit");
        assert_eq!(
            record.consumed_by.as_deref(),
            Some(winner_hex.as_str()),
            "EXACTLY ONE consumption — by whichever joiner serialized first"
        );
    }
    Ok(())
}

/// r4 (original item 4b): an addressed invite record SURVIVES a restart
/// — after the durable persist, dropping the in-memory map and reloading
/// through the store loader still returns the intended joiner, and the
/// consumption compare still enforces it (wrong agent refused, rightful
/// joiner accepted).
#[tokio::test]
async fn addressed_invite_survives_restart_reload() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "6e".repeat(32);
    let invite_secret = "addressed-restart-secret".to_string();

    let mut info = x0x::groups::GroupInfo::with_policy(
        "addressed-restart".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.clone(),
        x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
    );
    info.add_member(
        authority_hex.clone(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    let addressed_kp = AgentKeypair::generate()?;
    let addressed_hex = hex::encode(addressed_kp.agent_id().as_bytes());
    info.record_issued_invite_v2(
        invite_secret.clone(),
        now_millis_u64() / 1_000,
        0,
        x0x::groups::GroupRole::Member,
        Some(addressed_hex.clone()),
        x0x::groups::InviteOrigin::Explicit,
        None,
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info.clone());
    // Durable persist, then RESTART: drop the in-memory map entirely and
    // rebuild it from disk through the startup loader.
    persist_named_groups_mutation(&state, |groups| {
        groups.insert(group_id.clone(), info.clone());
        true
    })
    .await?;
    *state.named_groups.write().await =
        load_named_groups_merged(&state.named_groups_path, &state.home_suite_groups_path).await?;
    {
        let groups = state.named_groups.read().await;
        assert_eq!(
            groups[&group_id].issued_invite_intended_joiner(&invite_secret),
            Some(addressed_hex.as_str()),
            "the reloaded record still names the intended joiner"
        );
    }

    // Consumption still ENFORCES the address after the reload.
    let wrong_kp = AgentKeypair::generate()?;
    let (wrong_id, _w, _pk, wrong_event) = signed_member_joined_event_for_test(
        &wrong_kp,
        &group_id,
        &authority_hex,
        &invite_secret,
        x0x::groups::GroupRole::Member,
    )?;
    let wrong = apply_named_group_metadata_event(&state, wrong_event, wrong_id, true, None).await;
    assert!(
        !wrong.accepted,
        "the wrong agent is refused on the reloaded record"
    );
    assert_eq!(
        r4_diag_row(&state, &group_id)
            .await
            .counters
            .invites_refused_reasons
            .get("invite_not_addressed_to_joiner"),
        Some(&1)
    );

    let (addressed_id, _a, _pk, addressed_event) = signed_member_joined_event_for_test(
        &addressed_kp,
        &group_id,
        &authority_hex,
        &invite_secret,
        x0x::groups::GroupRole::Member,
    )?;
    let right =
        apply_named_group_metadata_event(&state, addressed_event, addressed_id, true, None).await;
    assert!(
        right.accepted,
        "the rightful joiner consumes the reloaded secret"
    );
    {
        let groups = state.named_groups.read().await;
        assert_eq!(
            groups[&group_id]
                .issued_invites
                .get(&invite_secret)
                .and_then(|record| record.consumed_by.clone()),
            Some(addressed_hex),
            "the reloaded record is consumed by the intended joiner"
        );
    }
    Ok(())
}

// ── r4 (addendum item 7): evidence classification, retryability,
// per-variant routing, journal recovery ──────────────────────────────────

/// Seed a live group with a sealed rev-0 base AND a lineage record —
/// the shape evidence lands on. Returns the sealed base.
async fn r4_seed_lineage_group(
    state: &AppState,
    group_id: &str,
    admission: GroupAdmission,
    extra_member: Option<&str>,
) -> Result<x0x::groups::GroupInfo> {
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let mut info = x0x::groups::GroupInfo::with_policy(
        format!("group-{group_id}"),
        String::new(),
        state.agent.agent_id(),
        group_id.to_string(),
        GroupPolicy {
            discoverability: GroupDiscoverability::Hidden,
            admission,
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
    if let Some(member) = extra_member {
        info.add_member(
            member.to_string(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
    }
    info.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
    info.invite_lineage = Some(x0x::groups::InviteLineage {
        base_revision: 0,
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

/// Drive one commit through the CENTRAL wrapper against the live map.
/// `lock_held` mirrors the causal-replay caller's
/// `persistence_lock_already_held` flag (the caller itself must hold
/// `named_groups_persistence_lock` when passing `true`).
async fn r4_apply_through_wrapper(
    state: &Arc<AppState>,
    group_id: &str,
    commit: x0x::groups::state_commit::GroupStateCommit,
    description: &str,
    lock_held: bool,
) -> Result<Result<x0x::groups::GroupInfo, x0x::groups::state_commit::ApplyError>> {
    let current = state
        .named_groups
        .read()
        .await
        .get(group_id)
        .cloned()
        .context("group present")?;
    let mutation = description.to_string();
    Ok(apply_stateful_event_with_evidence(
        state,
        group_id,
        &current,
        &commit,
        lock_held,
        x0x::groups::ActionKind::AdminOrHigher,
        |next| {
            next.description = mutation;
        },
    )
    .await)
}

/// The stored evidence on a group's lineage (if any).
async fn r4_evidence(state: &AppState, group_id: &str) -> Option<x0x::groups::ForkEvidence> {
    state
        .named_groups
        .read()
        .await
        .get(group_id)
        .and_then(|info| info.invite_lineage.as_ref())
        .and_then(|lineage| lineage.fork_evidence.clone())
}

/// r4 (addendum item 7): the evidence CLASSIFICATION matrix —
/// PrevHashMismatch records; StaleRevision with a different retained
/// hash records; StaleRevision with an IDENTICAL hash is a silent
/// duplicate replay; StaleRevision outside retained history is
/// unclassifiable (no evidence AND no unauthenticated counter); an
/// unauthenticated candidate counts `conflict_unauthenticated` only.
#[tokio::test]
async fn fork_evidence_classification_matrix() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let signer = state.agent.identity().agent_keypair();

    // Variant factory: two different sealed rev-1 children of `base`.
    fn variant(
        state: &AppState,
        mut base: x0x::groups::GroupInfo,
        description: &str,
    ) -> Result<x0x::groups::state_commit::GroupStateCommit> {
        base.description = description.to_string();
        base.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
        Ok(base
            .commit_log
            .last()
            .context("sealed commit")?
            .commit
            .clone())
    }

    // ── PrevHashMismatch (with the predecessor retained): records.
    {
        let group_id = "7e".repeat(32);
        let base =
            r4_seed_lineage_group(&state, &group_id, GroupAdmission::InviteOnly, None).await?;
        // Advance to rev 1 so the predecessor roster is retained.
        let a = variant(&state, base.clone(), "prevhash-a")?;
        let applied =
            r4_apply_through_wrapper(&state, &group_id, a.clone(), "prevhash-a", false).await?;
        assert!(applied.is_ok(), "variant A applies: {applied:?}");
        persist_named_groups_mutation(&state, |groups| {
            let info = groups.get_mut(&group_id).unwrap();
            *info = applied.clone().expect("applied");
            true
        })
        .await?;
        // A rev-2 commit whose prev does NOT chain from the live head.
        let current = state.named_groups.read().await[&group_id].clone();
        let conflicting = x0x::groups::GroupStateCommit::sign(
            current.stable_group_id().to_string(),
            current.state_revision + 1,
            Some("dead".repeat(32)),
            x0x::groups::compute_roster_root(&current.members_v2),
            x0x::groups::compute_policy_hash(&current.policy),
            x0x::groups::compute_public_meta_hash(&current.public_meta()),
            current.security_binding.clone(),
            false,
            now_millis_u64(),
            signer,
        )?;
        let refused =
            r4_apply_through_wrapper(&state, &group_id, conflicting, "prevhash-b", false).await?;
        assert!(refused.is_err(), "the prev-hash conflict must be refused");
        let evidence = r4_evidence(&state, &group_id)
            .await
            .expect("PrevHashMismatch records");
        // Seeded base seals at rev 1, variant A at rev 2, the conflicting
        // child claims rev 3 with a prev that cannot chain.
        assert_eq!(evidence.revision, 3);
        assert_eq!(evidence.committed_by, authority_hex);
    }

    // ── StaleRevision + IDENTICAL retained hash: silent duplicate.
    {
        let group_id = "8e".repeat(32);
        let base =
            r4_seed_lineage_group(&state, &group_id, GroupAdmission::InviteOnly, None).await?;
        let a = variant(&state, base, "stale-identical")?;
        let applied =
            r4_apply_through_wrapper(&state, &group_id, a.clone(), "stale-identical", false)
                .await?;
        assert!(applied.is_ok());
        persist_named_groups_mutation(&state, |groups| {
            let info = groups.get_mut(&group_id).unwrap();
            *info = applied.clone().expect("applied");
            true
        })
        .await?;
        // Replay the IDENTICAL retained commit: StaleRevision with the
        // same hash — an ordinary duplicate, not evidence.
        let replay =
            r4_apply_through_wrapper(&state, &group_id, a, "stale-identical", false).await?;
        assert!(replay.is_err(), "the duplicate is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_none(),
            "identical-hash duplicate replay records NO evidence"
        );
        let row = r4_diag_row(&state, &group_id).await;
        assert_eq!(row.counters.adoption_fork_evidence, 0);
        assert_eq!(row.counters.conflict_unauthenticated, 0);
    }

    // ── StaleRevision OUTSIDE retained history: unclassifiable.
    {
        let group_id = "9e".repeat(32);
        r4_seed_lineage_group(&state, &group_id, GroupAdmission::InviteOnly, None).await?;
        // Force the live revision past the retained history (a pruned
        // log shape): stale commits landing in the pruned span have no
        // retained twin to compare against.
        {
            let mut groups = state.named_groups.write().await;
            let info = groups.get_mut(&group_id).unwrap();
            info.state_revision = 5;
            info.state_hash = "pruned-head".to_string();
            info.prev_state_hash = Some("pruned-prev".to_string());
        }
        persist_named_groups_mutation(&state, |groups| groups.get(&group_id).is_some()).await?;
        let stale = x0x::groups::GroupStateCommit::sign(
            group_id.clone(),
            3,
            Some("whatever".to_string()),
            x0x::groups::compute_roster_root(
                &state.named_groups.read().await[&group_id]
                    .members_v2
                    .clone(),
            ),
            x0x::groups::compute_policy_hash(&state.named_groups.read().await[&group_id].policy),
            x0x::groups::compute_public_meta_hash(
                &state.named_groups.read().await[&group_id].public_meta(),
            ),
            None,
            false,
            now_millis_u64(),
            signer,
        )?;
        let refused =
            r4_apply_through_wrapper(&state, &group_id, stale, "outside-history", false).await?;
        assert!(refused.is_err(), "the pruned-span stale commit is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_none(),
            "outside-history is unclassifiable — no evidence"
        );
        let row = r4_diag_row(&state, &group_id).await;
        assert_eq!(
            row.counters.conflict_unauthenticated, 0,
            "unclassified is not an authentication failure either"
        );
    }

    // ── Unauthenticated candidate: counter only, never evidence.
    {
        let group_id = "ae".repeat(32);
        let current = r4_seed_lineage_group(&state, &group_id, GroupAdmission::InviteOnly, None)
            .await?
            .clone();
        let stranger = AgentKeypair::generate()?;
        let conflicting = x0x::groups::GroupStateCommit::sign(
            current.stable_group_id().to_string(),
            current.state_revision + 1,
            Some("00".repeat(32)),
            x0x::groups::compute_roster_root(
                &state.named_groups.read().await[&group_id]
                    .members_v2
                    .clone(),
            ),
            x0x::groups::compute_policy_hash(&state.named_groups.read().await[&group_id].policy),
            x0x::groups::compute_public_meta_hash(
                &state.named_groups.read().await[&group_id].public_meta(),
            ),
            current.security_binding.clone(),
            false,
            now_millis_u64(),
            &stranger,
        )?;
        let refused =
            r4_apply_through_wrapper(&state, &group_id, conflicting, "unauth", false).await?;
        assert!(refused.is_err());
        assert!(
            r4_evidence(&state, &group_id).await.is_none(),
            "a stranger-signed conflict records NO evidence"
        );
        assert_eq!(
            r4_diag_row(&state, &group_id)
                .await
                .counters
                .conflict_unauthenticated,
            1,
            "the unauthenticated attempt is counted"
        );
    }
    Ok(())
}

/// r4 (addendum item 7) → r5 (Fable 2): a FAILED evidence install is
/// RETRYABLE — the identical conflict is not marked seen before durable
/// success, so once the persist fault clears the very same conflict
/// installs the record and fires the once-only diagnostics exactly once.
/// The r5 leg covers the ReplacedNotDurable shape on the held-lock
/// (causal-replay) path: the install went LIVE in the map but never
/// reached directory durability — the arm rolls the live record back,
/// fires no once-only diagnostics, and the identical conflict still
/// retries to a durable install once the fault clears.
#[tokio::test]
async fn fork_evidence_failed_install_is_retryable_not_seen_marked() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "be".repeat(32);
    let base = r4_seed_lineage_group(&state, &group_id, GroupAdmission::InviteOnly, None).await?;
    fn variant(
        state: &AppState,
        base: &x0x::groups::GroupInfo,
        description: &str,
    ) -> Result<x0x::groups::state_commit::GroupStateCommit> {
        let mut v = base.clone();
        v.description = description.to_string();
        v.seal_commit(state.agent.identity().agent_keypair(), now_millis_u64())?;
        Ok(v.commit_log.last().context("sealed commit")?.commit.clone())
    }
    let fork_a = variant(&state, &base, "retry-a")?;
    let fork_b = variant(&state, &base, "retry-b")?;

    // Apply A, persist; then B conflicts — under an injected save fault
    let applied = r4_apply_through_wrapper(&state, &group_id, fork_a, "retry-a", false).await?;
    assert!(applied.is_ok());
    persist_named_groups_mutation(&state, |groups| {
        let info = groups.get_mut(&group_id).unwrap();
        *info = applied.clone().expect("applied");
        true
    })
    .await?;
    {
        let _fault = set_save_fault(SaveFault::Error);
        let refused =
            r4_apply_through_wrapper(&state, &group_id, fork_b.clone(), "retry-b", false).await?;
        assert!(refused.is_err(), "the conflicting twin is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_none(),
            "the failed install recorded no evidence in the live map"
        );
        assert_eq!(
            r4_diag_row(&state, &group_id)
                .await
                .counters
                .adoption_fork_evidence,
            0,
            "the failed install fired no once-only diagnostics — the conflict stays retryable"
        );
    }
    let retried =
        r4_apply_through_wrapper(&state, &group_id, fork_b.clone(), "retry-b", false).await?;
    assert!(retried.is_err(), "still a conflict, still refused");
    let evidence = r4_evidence(&state, &group_id)
        .await
        .expect("the retry installs the evidence");
    assert_eq!(evidence.state_hash, fork_b.state_hash);
    assert_eq!(
        r4_diag_row(&state, &group_id)
            .await
            .counters
            .adoption_fork_evidence,
        1,
        "exactly one once-only firing after the durable retry"
    );

    // ── r5 (Fable 2): the ReplacedNotDurable arm on the HELD-lock
    // (causal-replay) path. The install goes LIVE in the map but the
    // save never confirms durability; the arm must roll the live record
    // back (identity-matched, no nested persist), fire NO once-only
    // diagnostics, and leave the identical conflict retryable — the
    // retry after the fault clears installs DURABLY. Driven under the
    // ACTUAL persistence lock, exactly like the replay caller that
    // passes the flag (this also proves the rollback cannot
    // self-deadlock on that lock).
    {
        let group_id = "5f".repeat(32);
        let base =
            r4_seed_lineage_group(&state, &group_id, GroupAdmission::InviteOnly, None).await?;
        let fork_a = variant(&state, &base, "rnd-a")?;
        let fork_b = variant(&state, &base, "rnd-b")?;
        let applied = r4_apply_through_wrapper(&state, &group_id, fork_a, "rnd-a", false).await?;
        assert!(applied.is_ok());
        persist_named_groups_mutation(&state, |groups| {
            let info = groups.get_mut(&group_id).unwrap();
            *info = applied.clone().expect("applied");
            true
        })
        .await?;
        {
            let _fault = set_save_fault(SaveFault::ReplacedNotDurable);
            let _persistence_guard = state.named_groups_persistence_lock.lock().await;
            let refused =
                r4_apply_through_wrapper(&state, &group_id, fork_b.clone(), "rnd-b", true).await?;
            assert!(refused.is_err(), "the conflicting twin is refused");
            assert!(
                r4_evidence(&state, &group_id).await.is_none(),
                "the live-but-not-durable record was ROLLED BACK — nothing \
                 remains in the map to silence the identical retry"
            );
            assert_eq!(
                r4_diag_row(&state, &group_id)
                    .await
                    .counters
                    .adoption_fork_evidence,
                0,
                "the rolled-back install fired no once-only diagnostics"
            );
        }
        let retried =
            r4_apply_through_wrapper(&state, &group_id, fork_b.clone(), "rnd-b", false).await?;
        assert!(retried.is_err(), "still a conflict, still refused");
        let evidence = r4_evidence(&state, &group_id)
            .await
            .expect("the identical conflict installs DURABLY once the fault clears");
        assert_eq!(evidence.state_hash, fork_b.state_hash);
        assert_eq!(
            r4_diag_row(&state, &group_id)
                .await
                .counters
                .adoption_fork_evidence,
            1,
            "exactly one once-only firing after the durable retry"
        );
    }
    Ok(())
}

/// r4 (addendum item 7) → r5 (Fable 3 + Codex 5): EVERY stateful event
/// variant routes its conflicting commits through the CENTRAL wrapper —
/// all TWELVE commit-carrying variants (MemberAdded, MemberRemoved,
/// GroupDeleted via the terminal twin, PolicyUpdated, MemberRoleUpdated,
/// MemberBanned, MemberUnbanned, JoinRequestCreated,
/// JoinRequestApproved, JoinRequestRejected, JoinRequestCancelled,
/// GroupMetadataUpdated) record evidence on a conflicting commit.
#[tokio::test]
async fn every_stateful_event_variant_routes_conflicts_through_the_wrapper() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let authority_hex = hex::encode(state.agent.agent_id().as_bytes());
    let authority_id = state.agent.agent_id();
    let signer = state.agent.identity().agent_keypair();
    let member_hex = hex::encode(AgentKeypair::generate()?.agent_id().as_bytes());
    let requester_hex = hex::encode(AgentKeypair::generate()?.agent_id().as_bytes());

    // A conflicting rev-1 commit for the freshly seeded group (prev does
    // not chain from the sealed base head). `withdrawn` selects the
    // terminal shape GroupDeleted carries.
    async fn conflicting_commit(
        state: &AppState,
        group_id: &str,
        signer: &x0x::identity::AgentKeypair,
        withdrawn: bool,
    ) -> Result<x0x::groups::GroupStateCommit> {
        let current = state.named_groups.read().await[group_id].clone();
        Ok(x0x::groups::GroupStateCommit::sign(
            current.stable_group_id().to_string(),
            // A child of the current head whose prev cannot chain —
            // PrevHashMismatch with the predecessor retained.
            current.state_revision + 1,
            Some("ba".repeat(32)),
            x0x::groups::compute_roster_root(&current.members_v2),
            x0x::groups::compute_policy_hash(&current.policy),
            x0x::groups::compute_public_meta_hash(&current.public_meta()),
            current.security_binding.clone(),
            withdrawn,
            now_millis_u64(),
            signer,
        )?)
    }

    // Seed a PENDING join request on a seeded group — the approval,
    // rejection and cancellation arms gate on its presence before they
    // reach the commit apply.
    async fn seed_pending_join_request(state: &AppState, group_id: &str, requester_hex: &str) {
        state
            .named_groups
            .write()
            .await
            .get_mut(group_id)
            .expect("seeded group")
            .join_requests
            .insert(
                "req-1".to_string(),
                x0x::groups::JoinRequest {
                    request_id: "req-1".to_string(),
                    group_id: group_id.to_string(),
                    requester_agent_id: requester_hex.to_string(),
                    requester_user_id: None,
                    requested_role: x0x::groups::GroupRole::Member,
                    message: None,
                    treekem_key_package_b64: None,
                    created_at: now_millis_u64(),
                    reviewed_at: None,
                    reviewed_by: None,
                    status: x0x::groups::JoinRequestStatus::Pending,
                    predecessor_envelope_digest: None,
                    predecessor_first_seen_ms: None,
                },
            );
    }

    // MemberRemoved: admin remove of the extra member.
    {
        let group_id = "ce".repeat(32);
        r4_seed_lineage_group(
            &state,
            &group_id,
            GroupAdmission::InviteOnly,
            Some(&member_hex),
        )
        .await?;
        let event = NamedGroupMetadataEvent::MemberRemoved {
            group_id: group_id.clone(),
            revision: 1,
            actor: authority_hex.clone(),
            agent_id: member_hex.clone(),
            treekem_commit_b64: None,
            treekem_epoch: None,
            secret_epoch: None,
            commit: Some(conflicting_commit(&state, &group_id, signer, false).await?),
        };
        let result =
            apply_named_group_metadata_event(&state, event, authority_id, true, None).await;
        assert!(!result.accepted, "the conflicting remove is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_some(),
            "MemberRemoved conflicts record evidence through the wrapper"
        );
    }

    // MemberRoleUpdated: admin role change of the extra member.
    {
        let group_id = "de".repeat(32);
        r4_seed_lineage_group(
            &state,
            &group_id,
            GroupAdmission::InviteOnly,
            Some(&member_hex),
        )
        .await?;
        let event = NamedGroupMetadataEvent::MemberRoleUpdated {
            group_id: group_id.clone(),
            revision: 1,
            actor: authority_hex.clone(),
            agent_id: member_hex.clone(),
            role: x0x::groups::GroupRole::Admin,
            commit: Some(conflicting_commit(&state, &group_id, signer, false).await?),
        };
        let result =
            apply_named_group_metadata_event(&state, event, authority_id, true, None).await;
        assert!(!result.accepted, "the conflicting role change is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_some(),
            "MemberRoleUpdated conflicts record evidence through the wrapper"
        );
    }

    // PolicyUpdated.
    {
        let group_id = "ef".repeat(32);
        let policy = r4_seed_lineage_group(&state, &group_id, GroupAdmission::InviteOnly, None)
            .await?
            .policy
            .clone();
        let event = NamedGroupMetadataEvent::PolicyUpdated {
            group_id: group_id.clone(),
            revision: 1,
            actor: authority_hex.clone(),
            policy,
            commit: Some(conflicting_commit(&state, &group_id, signer, false).await?),
        };
        let result =
            apply_named_group_metadata_event(&state, event, authority_id, true, None).await;
        assert!(!result.accepted, "the conflicting policy update is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_some(),
            "PolicyUpdated conflicts record evidence through the wrapper"
        );
    }

    // JoinRequestCreated (RequestAccess policy; sender == requester).
    {
        let group_id = "fe".repeat(32);
        r4_seed_lineage_group(&state, &group_id, GroupAdmission::RequestAccess, None).await?;
        let event = NamedGroupMetadataEvent::JoinRequestCreated {
            group_id: group_id.clone(),
            request_id: "req-1".to_string(),
            requester_agent_id: requester_hex.clone(),
            message: None,
            ts: now_millis_u64(),
            requester_kem_public_key_b64: Some(String::new()),
            treekem_key_package_b64: None,
            commit: Some(conflicting_commit(&state, &group_id, signer, false).await?),
        };
        let sender = crate::server::parse_agent_id_hex(&requester_hex)
            .map_err(|e| anyhow::anyhow!("requester id: {e}"))?;
        let result = apply_named_group_metadata_event(&state, event, sender, true, None).await;
        assert!(!result.accepted, "the conflicting join request is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_some(),
            "JoinRequestCreated conflicts record evidence through the wrapper"
        );
    }

    // ── r5 (Fable 3): the seven variants the r4 test left uncovered,
    // plus the terminal twin below ─────────────────────────────────────

    // MemberAdded: authority adds a third agent (the conflicting commit
    // fails in the wrapper BEFORE the across-gap adoption body runs).
    {
        let group_id = "0a".repeat(32);
        r4_seed_lineage_group(
            &state,
            &group_id,
            GroupAdmission::InviteOnly,
            Some(&member_hex),
        )
        .await?;
        let added_hex = hex::encode(AgentKeypair::generate()?.agent_id().as_bytes());
        let event = NamedGroupMetadataEvent::MemberAdded {
            group_id: group_id.clone(),
            revision: 1,
            actor: authority_hex.clone(),
            agent_id: added_hex,
            display_name: None,
            treekem_commit_b64: None,
            treekem_welcome_b64: None,
            welcome_ref: None,
            treekem_epoch: None,
            treekem_key_package_hash: None,
            member_joined_recovery: None,
            member_recovery_history: Vec::new(),
            certificate_b64: None,
            commit: Some(conflicting_commit(&state, &group_id, signer, false).await?),
        };
        let result =
            apply_named_group_metadata_event(&state, event, authority_id, true, None).await;
        assert!(!result.accepted, "the conflicting add is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_some(),
            "MemberAdded conflicts record evidence through the wrapper"
        );
    }

    // GroupDeleted (r5 Codex 5): the TERMINAL withdrawal commit routes
    // through the terminal twin of the central wrapper — a conflicting
    // delete records evidence instead of bypassing it.
    {
        let group_id = "0b".repeat(32);
        r4_seed_lineage_group(&state, &group_id, GroupAdmission::InviteOnly, None).await?;
        let event = NamedGroupMetadataEvent::GroupDeleted {
            group_id: group_id.clone(),
            revision: 1,
            actor: authority_hex.clone(),
            commit: Some(conflicting_commit(&state, &group_id, signer, true).await?),
        };
        let result =
            apply_named_group_metadata_event(&state, event, authority_id, true, None).await;
        assert!(!result.accepted, "the conflicting delete is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_some(),
            "GroupDeleted conflicts record evidence through the TERMINAL twin of the wrapper"
        );
    }

    // MemberBanned: admin ban of the extra member.
    {
        let group_id = "0c".repeat(32);
        r4_seed_lineage_group(
            &state,
            &group_id,
            GroupAdmission::InviteOnly,
            Some(&member_hex),
        )
        .await?;
        let event = NamedGroupMetadataEvent::MemberBanned {
            group_id: group_id.clone(),
            revision: 1,
            actor: authority_hex.clone(),
            agent_id: member_hex.clone(),
            secret_epoch: None,
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit: Some(conflicting_commit(&state, &group_id, signer, false).await?),
        };
        let result =
            apply_named_group_metadata_event(&state, event, authority_id, true, None).await;
        assert!(!result.accepted, "the conflicting ban is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_some(),
            "MemberBanned conflicts record evidence through the wrapper"
        );
    }

    // MemberUnbanned: admin unban.
    {
        let group_id = "0d".repeat(32);
        r4_seed_lineage_group(
            &state,
            &group_id,
            GroupAdmission::InviteOnly,
            Some(&member_hex),
        )
        .await?;
        let event = NamedGroupMetadataEvent::MemberUnbanned {
            group_id: group_id.clone(),
            revision: 1,
            actor: authority_hex.clone(),
            agent_id: member_hex.clone(),
            commit: Some(conflicting_commit(&state, &group_id, signer, false).await?),
        };
        let result =
            apply_named_group_metadata_event(&state, event, authority_id, true, None).await;
        assert!(!result.accepted, "the conflicting unban is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_some(),
            "MemberUnbanned conflicts record evidence through the wrapper"
        );
    }

    // JoinRequestApproved: authority approves the seeded pending request.
    {
        let group_id = "0e".repeat(32);
        r4_seed_lineage_group(&state, &group_id, GroupAdmission::RequestAccess, None).await?;
        seed_pending_join_request(&state, &group_id, &requester_hex).await;
        let event = NamedGroupMetadataEvent::JoinRequestApproved {
            group_id: group_id.clone(),
            request_id: "req-1".to_string(),
            revision: 1,
            actor: authority_hex.clone(),
            requester_agent_id: requester_hex.clone(),
            treekem_commit_b64: None,
            treekem_welcome_b64: None,
            welcome_ref: None,
            treekem_epoch: None,
            treekem_key_package_hash: None,
            commit: Some(conflicting_commit(&state, &group_id, signer, false).await?),
        };
        let result =
            apply_named_group_metadata_event(&state, event, authority_id, true, None).await;
        assert!(!result.accepted, "the conflicting approval is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_some(),
            "JoinRequestApproved conflicts record evidence through the wrapper"
        );
    }

    // JoinRequestRejected: authority rejects the seeded pending request.
    {
        let group_id = "0f".repeat(32);
        r4_seed_lineage_group(&state, &group_id, GroupAdmission::RequestAccess, None).await?;
        seed_pending_join_request(&state, &group_id, &requester_hex).await;
        let event = NamedGroupMetadataEvent::JoinRequestRejected {
            group_id: group_id.clone(),
            request_id: "req-1".to_string(),
            actor: authority_hex.clone(),
            requester_agent_id: requester_hex.clone(),
            commit: Some(conflicting_commit(&state, &group_id, signer, false).await?),
        };
        let result =
            apply_named_group_metadata_event(&state, event, authority_id, true, None).await;
        assert!(!result.accepted, "the conflicting rejection is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_some(),
            "JoinRequestRejected conflicts record evidence through the wrapper"
        );
    }

    // JoinRequestCancelled: the requester cancels (sender == requester).
    {
        let group_id = "1a".repeat(32);
        r4_seed_lineage_group(&state, &group_id, GroupAdmission::RequestAccess, None).await?;
        seed_pending_join_request(&state, &group_id, &requester_hex).await;
        let event = NamedGroupMetadataEvent::JoinRequestCancelled {
            group_id: group_id.clone(),
            request_id: "req-1".to_string(),
            requester_agent_id: requester_hex.clone(),
            commit: Some(conflicting_commit(&state, &group_id, signer, false).await?),
        };
        let sender = crate::server::parse_agent_id_hex(&requester_hex)
            .map_err(|e| anyhow::anyhow!("requester id: {e}"))?;
        let result = apply_named_group_metadata_event(&state, event, sender, true, None).await;
        assert!(!result.accepted, "the conflicting cancellation is refused");
        assert!(
            r4_evidence(&state, &group_id).await.is_some(),
            "JoinRequestCancelled conflicts record evidence through the wrapper"
        );
    }

    // GroupMetadataUpdated: admin description change.
    {
        let group_id = "2a".repeat(32);
        r4_seed_lineage_group(&state, &group_id, GroupAdmission::InviteOnly, None).await?;
        let event = NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: group_id.clone(),
            revision: 1,
            actor: authority_hex.clone(),
            name: None,
            description: Some("conflicting description".to_string()),
            commit: Some(conflicting_commit(&state, &group_id, signer, false).await?),
        };
        let result =
            apply_named_group_metadata_event(&state, event, authority_id, true, None).await;
        assert!(
            !result.accepted,
            "the conflicting metadata update is refused"
        );
        assert!(
            r4_evidence(&state, &group_id).await.is_some(),
            "GroupMetadataUpdated conflicts record evidence through the wrapper"
        );
    }
    Ok(())
}

/// r4 (addendum item 7): the JOURNAL-RECOVERY fork path records evidence
/// on the live lineage through the same shared rules — an equal-revision
/// fork between the live store and a recovered journal pair installs the
/// journal's terminal commit as evidence BEFORE the pair is quarantined.
#[tokio::test]
async fn journal_recovery_records_fork_evidence_on_live_lineage() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let treekem_dir = dir.path().join("treekem");
    tokio::fs::create_dir_all(&treekem_dir).await?;
    let named_path = dir.path().join("named_groups.json");
    let sidecar_path = dir.path().join(HOME_SUITE_GROUPS_FILE);
    let group_id = "5f".repeat(16);

    // Build live and journal records sharing a sealed rev-0 base but
    // diverging at rev 1 (both signed by the local admin).
    let admin_kp = AgentKeypair::generate()?;
    let admin_hex = hex::encode(admin_kp.agent_id().as_bytes());
    let mut base = x0x::groups::GroupInfo::with_policy(
        "recovery-fork".to_string(),
        String::new(),
        admin_kp.agent_id(),
        group_id.clone(),
        GroupPolicy {
            discoverability: GroupDiscoverability::Hidden,
            admission: GroupAdmission::InviteOnly,
            confidentiality: GroupConfidentiality::MlsEncrypted,
            read_access: x0x::groups::GroupReadAccess::MembersOnly,
            write_access: x0x::groups::GroupWriteAccess::MembersOnly,
        },
    );
    base.add_member(admin_hex.clone(), x0x::groups::GroupRole::Admin, None, None);
    base.seal_commit(&admin_kp, now_millis_u64())?;

    let mut live = base.clone();
    live.description = "live".to_string();
    live.seal_commit(&admin_kp, now_millis_u64())?;
    live.invite_lineage = Some(x0x::groups::InviteLineage {
        base_revision: 0,
        base_hash: base.state_hash.clone(),
        base_roster_root: String::new(),
        seated_at_revision: None,
        corroborated: false,
        fork_evidence: None,
    });
    let mut journal_record = base;
    journal_record.description = "journal".to_string();
    journal_record.seal_commit(&admin_kp, now_millis_u64())?;
    let journal_commit = journal_record
        .commit_log
        .last()
        .context("journal terminal commit")?
        .commit
        .clone();

    // The live store carries the live record; the journal pair carries
    // the conflicting record at the SAME revision.
    let live_json = serde_json::to_string(&HashMap::from([(group_id.clone(), live.clone())]))?;
    write_named_groups_json_atomic(&named_path, &live_json).await?;
    let journal_json = serde_json::to_string(&HashMap::from([(group_id.clone(), journal_record)]))?;
    let journal = TreeKemNamedPersistJournal {
        version: TREEKEM_NAMED_JOURNAL_VERSION,
        group_id_hex: group_id.clone(),
        named_groups_json: journal_json,
        snapshot_envelope: sample_treekem_snapshot_envelope()?,
    };
    x0x::storage::write_private_bytes(
        &treekem_journal_path(&treekem_dir, &group_id),
        postcard::to_stdvec(&journal)?,
    )
    .await?;

    recover_treekem_named_journals(&named_path, &sidecar_path, &treekem_dir).await?;

    // The live lineage now carries the journal's terminal commit as
    // evidence — first-complete-wins, digest of the journal conflict.
    let reloaded = load_named_groups_merged(&named_path, &sidecar_path).await?;
    let evidence = reloaded
        .get(&group_id)
        .and_then(|info| info.invite_lineage.as_ref())
        .and_then(|lineage| lineage.fork_evidence.clone())
        .expect("recovery recorded the fork evidence on the live lineage");
    // The base seal lands at rev 1 and the divergent child at rev 2 —
    // the equal-revision fork is at revision 2.
    assert_eq!(evidence.revision, 2);
    assert_eq!(evidence.state_hash, journal_commit.state_hash);
    assert_eq!(evidence.committed_by, admin_hex);

    // The pair was quarantined aside (the fail-closed act still ran).
    let journal_gone = tokio::fs::read(&treekem_journal_path(&treekem_dir, &group_id))
        .await
        .is_err();
    assert!(
        journal_gone,
        "the forked journal pair is quarantined aside, not replayed"
    );
    Ok(())
}

/// r4 (original item 1b / addendum item 9): the join route's
/// base-already-seated arm — the invite's base roster seats the local
/// joiner DIGEST-ONLY (the self-rejoin shape; the projection carries no
/// certificate bytes), the joiner's own discovered-certificate cache
/// holds the matching cert, and the SEAT-TIME hydrate installs the bytes
/// BEFORE the durable write — with NO bridge event (the cache insert is
/// a raw map write that fires nothing, and no bridge worker runs).
#[tokio::test]
async fn base_seated_rejoin_hydrates_certificate_without_bridge_event() -> Result<()> {
    let (authority, _dir, owner_kp) = r3_owner_authority_state().await?;
    let group_id = "1b".repeat(32);

    // The joiner's owner-issued certificate (what the authority's base
    // roster committed the digest of).
    let joiner_kp = AgentKeypair::generate()?;
    let joiner_hex = hex::encode(joiner_kp.agent_id().as_bytes());
    let joiner_cert = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner_kp,
        joiner_kp.public_key().as_bytes(),
        None,
    )?;
    let committed_digest = x0x::groups::owner_cert::certificate_digest_hex(&joiner_cert);

    // The authority's group: creator admin + the joiner seated
    // DIGEST-ONLY (their previous membership, bytes stripped by the
    // projection the base roster rides on).
    let mut info = x0x::groups::GroupInfo::with_policy(
        format!("group-{group_id}"),
        String::new(),
        authority.agent.agent_id(),
        group_id.clone(),
        r3_owner_certified_policy(&owner_kp),
    );
    let authority_hex = hex::encode(authority.agent.agent_id().as_bytes());
    info.add_member(
        authority_hex.clone(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    info.add_member(
        joiner_hex.clone(),
        x0x::groups::GroupRole::Member,
        None,
        None,
    );
    info.members_v2
        .get_mut(&joiner_hex)
        .unwrap()
        .certificate_digest = Some(committed_digest.clone());
    // The digest rides the roster root — recompute the base state hash so
    // the minted invite's signed base covers it.
    info.recompute_state_hash();
    authority
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info.clone());

    // Mint the invite from this base — the projection seats the joiner
    // with the committed digest.
    let (_invite, link) = assemble_signed_v4_invite(
        &authority,
        &info,
        x0x::groups::invite::DEFAULT_EXPIRY_SECS,
        None,
    )
    .map_err(|e| anyhow::anyhow!("mint failed: {e:?}"))?;

    // The JOINER daemon: no local user key; its discovery cache already
    // holds its own owner-issued certificate (raw map write — NO
    // verified-certificate event fires, and no bridge worker exists in
    // the test state).
    let joiner_agent_id = joiner_kp.agent_id();
    let jdir = tempfile::tempdir()?;
    let joiner_agent = Arc::new(
        Agent::builder()
            .with_machine_key(jdir.path().join("machine.key"))
            .with_agent_key(joiner_kp)
            .with_peer_cache_disabled()
            .with_contact_store_path(jdir.path().join("contacts.json"))
            .build()
            .await?,
    );
    let joiner = secure_endpoint_test_state_at(jdir.path(), joiner_agent).await?;
    joiner
        .agent
        .identity_discovery_cache()
        .write()
        .await
        .insert(
            joiner_agent_id,
            x0x::DiscoveredAgent {
                agent_id: joiner_agent_id,
                machine_id: x0x::identity::MachineId([0u8; 32]),
                user_id: joiner_cert.user_id().ok(),
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
                cert_not_after: joiner_cert.not_after(),
                agent_certificate: Some(joiner_cert.clone()),
                agent_public_key: Vec::new(),
                cert_digest: None,
            },
        );

    // Home-mode join (owner-axis invite): pin the admission owner.
    let response = join_group_via_invite(
        State(Arc::clone(&joiner)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: Some("home".to_string()),
            expected_owner_user_id: Some(hex::encode(owner_kp.user_id().as_bytes())),
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the base-seated rejoin succeeds: {body}"
    );
    assert_eq!(body["join_state"], json!("active"));

    // The seat-time hydrate installed the joiner's OWN cached cert BEFORE
    // the durable write — live map AND the durable store carry the bytes.
    {
        let groups = joiner.named_groups.read().await;
        let seat = groups[&group_id]
            .members_v2
            .get(&joiner_hex)
            .expect("joiner seat");
        assert_eq!(
            seat.certificate.as_ref(),
            Some(&joiner_cert),
            "the digest-only base seat hydrated at materialization time"
        );
        assert_eq!(
            seat.certificate_digest.as_deref(),
            Some(committed_digest.as_str()),
            "hydration keeps the committed digest"
        );
    }
    let on_disk =
        load_named_groups_merged(&joiner.named_groups_path, &joiner.home_suite_groups_path).await?;
    assert_eq!(
        on_disk[&group_id]
            .members_v2
            .get(&joiner_hex)
            .and_then(|seat| seat.certificate.clone()),
        Some(joiner_cert),
        "the hydrated bytes reached the durable record"
    );
    Ok(())
}
