//! #1508 (and #1533): ADR 0110 §4 (D75) and §4b(3) (D126) on the
//! admission and key-delivery paths. While verified Agent-subject
//! revocations cover every Admin-or-higher Active seat, admission and
//! other admin operations return the typed state, and no class-K artifact
//! (secure share, Welcome, join result) leaves this node.
//!
//! Red on b4adc95: the four admin routes answered with other statuses,
//! the class-K serving guard passed, and the inviter admitted a joiner.

use super::*;
use x0x::identity::AgentKeypair;

/// Insert a verified self-revocation of `subject`.
async fn revoke_agent(state: &AppState, subject: &AgentKeypair) {
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(subject.agent_id()),
        subject.public_key(),
        subject.secret_key(),
        now_millis_u64() / 1_000,
        Some("test".to_string()),
    )
    .expect("sign revocation");
    let revocation_set = state.agent.revocation_set();
    assert!(revocation_set
        .write()
        .await
        .verify_and_insert(record, None)
        .expect("self-revocation verifies"));
}

/// A GSS `MlsEncrypted` group whose sole admin is `admin` (the creator),
/// with this node and `other` as ordinary members. `other` has a roster
/// KEM key, so a reseal to it could build.
async fn seed_group(state: &AppState, group_key: &str, admin: &AgentKeypair, other: &AgentId) {
    let admin_hex = hex::encode(admin.agent_id().as_bytes());
    let mut info = x0x::groups::GroupInfo::new(
        "s4".to_string(),
        String::new(),
        admin.agent_id(),
        group_key.to_string(),
    );
    info.migrate_from_v1();
    let _ = info.rotate_shared_secret();
    for member in [state.agent.agent_id(), *other] {
        info.add_member(
            hex::encode(member.as_bytes()),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
    }
    info.set_member_kem_public_key(
        &hex::encode(other.as_bytes()),
        BASE64.encode(&state.agent_kem_keypair.public_bytes),
    );
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_key.to_string(), info);
}

async fn body_of(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn is_s4_state(body: &serde_json::Value) -> bool {
    matches!(
        body["state"].as_str(),
        Some("waiting_for_eligible_admin_revocation" | "group_admin_revoked")
    )
}

/// The admin routes that admit a member, deliver a group key or advance
/// the state chain. This node is an ordinary Member of the seeded group,
/// so a route that runs its own seat gate before the §4 refusal answers
/// 403 instead of the typed state (#1581: `seal` did).
async fn admin_route_bodies(
    state: &Arc<AppState>,
    group_key: &str,
    other_hex: &str,
) -> Vec<(&'static str, StatusCode, serde_json::Value)> {
    let owner =
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true });
    let approve = approve_join_request(
        State(Arc::clone(state)),
        owner.clone(),
        Path((group_key.to_string(), "no-such-request".to_string())),
    )
    .await
    .into_response();
    let ban = ban_group_member(
        State(Arc::clone(state)),
        owner.clone(),
        Path((group_key.to_string(), other_hex.to_string())),
    )
    .await
    .into_response();
    let remove = remove_named_group_member(
        State(Arc::clone(state)),
        owner.clone(),
        Path((group_key.to_string(), other_hex.to_string())),
    )
    .await
    .into_response();
    let (reseal_status, reseal_body) = secure_group_reseal(
        State(Arc::clone(state)),
        Path(group_key.to_string()),
        owner,
        Json(ResealRequest {
            recipient: other_hex.to_string(),
        }),
    )
    .await;
    let seal = seal_group_state(
        State(Arc::clone(state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path(group_key.to_string()),
    )
    .await
    .into_response();
    let mut out = Vec::new();
    for (name, response) in [
        ("approve", approve),
        ("ban", ban),
        ("remove", remove),
        ("seal", seal),
    ] {
        let (status, body) = body_of(response).await;
        out.push((name, status, body));
    }
    out.push(("reseal", reseal_status, reseal_body.0));
    out
}

#[tokio::test]
async fn admin_routes_return_the_s4_state_while_every_admin_seat_is_revoked() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let admin = AgentKeypair::generate()?;
    let other = AgentKeypair::generate()?.agent_id();
    let other_hex = hex::encode(other.as_bytes());
    let group_key = "c1".repeat(32);
    seed_group(&state, &group_key, &admin, &other).await;

    // No false refusal: with the admin seat unrevoked no route names the
    // §4 state (they refuse for their own reasons: this node is a Member).
    for (name, _, body) in admin_route_bodies(&state, &group_key, &other_hex).await {
        assert!(!is_s4_state(&body), "{name}: false §4 refusal: {body}");
    }

    revoke_agent(&state, &admin).await;
    for (name, status, body) in admin_route_bodies(&state, &group_key, &other_hex).await {
        assert!(
            is_s4_state(&body),
            "{name}: expected the §4 typed state, got {status}: {body}"
        );
        assert!(
            status == StatusCode::CONFLICT || status == StatusCode::GONE,
            "{name}: {status}"
        );
        assert!(
            body["kem_ciphertext_b64"].is_null(),
            "{name}: no key material"
        );
    }
    Ok(())
}

/// The class-K serving guard (every secure share, Welcome and join-result
/// write) withholds, and never purges, while the cover holds.
#[tokio::test]
async fn class_k_serving_guard_withholds_while_every_admin_seat_is_revoked() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let admin = AgentKeypair::generate()?;
    let other = AgentKeypair::generate()?.agent_id();
    let other_hex = hex::encode(other.as_bytes());
    let group_key = "c2".repeat(32);
    seed_group(&state, &group_key, &admin, &other).await;

    assert_eq!(
        join_artifact_serving_refusal(&state, &group_key, &other_hex)
            .await
            .map(JoinArtifactRefusal::reason),
        None,
        "an eligible recipient is served while an admin seat is unrevoked"
    );
    revoke_agent(&state, &admin).await;
    let refusal = join_artifact_serving_refusal(&state, &group_key, &other_hex).await;
    assert_eq!(
        refusal.map(JoinArtifactRefusal::reason),
        Some("no_eligible_admin")
    );
    assert!(
        !refusal.is_some_and(JoinArtifactRefusal::is_definitive),
        "the derived state withholds; staged artifacts are kept"
    );
    // S4's own guarded deliveries (the owner-recovery mandate and commit,
    // crypto exclusion, removal, rebind) are the exits from this state:
    // the recipient half alone must still admit them.
    assert!(
        join_artifact_member_check(&state, &group_key, &other_hex)
            .await
            .is_ok(),
        "the S4 exit deliveries are not held by the cover"
    );
    Ok(())
}

/// The inviter's automatic admission (MemberJoined → TreeKEM add and
/// Welcome, or GSS share) does not run, and the invite is not consumed.
#[tokio::test]
async fn member_joined_admission_is_withheld_while_every_admin_seat_is_revoked() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let inviter = state.agent.agent_id();
    let inviter_hex = hex::encode(inviter.as_bytes());
    let now_ms = now_millis_u64();
    let mut joined = Vec::new();
    for (group_id, revoke) in [("c3".repeat(32), false), ("c4".repeat(32), true)] {
        let invite_secret = format!("s4-member-joined-{group_id}");
        let mut info = x0x::groups::GroupInfo::with_policy(
            "s4 MemberJoined".to_string(),
            String::new(),
            inviter,
            group_id.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        );
        info.record_issued_invite(
            invite_secret.clone(),
            now_ms / 1_000,
            0,
            x0x::groups::GroupRole::Member,
        );
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info);
        assert!(save_named_groups(&state).await);
        if revoke {
            // The local inviter is the sole admin seat.
            revoke_agent(&state, state.agent.identity().agent_keypair()).await;
        }
        let joiner = AgentKeypair::generate()?;
        let (joiner_id, joiner_hex, _, event) = signed_member_joined_event_for_test(
            &joiner,
            &group_id,
            &inviter_hex,
            &invite_secret,
            x0x::groups::GroupRole::Member,
        )?;
        let result =
            apply_named_group_metadata_event_inner(&state, event, joiner_id, true, true, None)
                .await;
        let groups = state.named_groups.read().await;
        let info = groups.get(&group_id).expect("group kept");
        joined.push((
            revoke,
            result.accepted,
            info.has_active_member(&joiner_hex),
            info.live_issued_invite_count(now_ms / 1_000) == 1,
        ));
    }
    let (_, accepted, active, _) = joined[0];
    assert!(
        accepted && active,
        "control: an ordinary group admits the joiner"
    );
    let (_, accepted, active, invite_kept) = joined[1];
    assert!(
        !accepted && !active,
        "no admission while no eligible admin remains"
    );
    assert!(invite_kept, "the invite is not consumed");
    Ok(())
}

/// #1508 rc12 Codex P1 (ADR 0110 §5): a class-K share waits for roster
/// durability, as an S4 frame does. The roster write renames the file and
/// the directory fsync fails (`ReplacedNotDurable`), then every re-save
/// fails. The share delivery is withheld (not purged), a fresh admission
/// pre-phase refuses, and a seam taken before the write refuses. Once a
/// re-save is durable, the share is delivered. Before the fix the share
/// left at once, so a crash could lose the sender's new secret after a
/// survivor installed it.
#[tokio::test]
async fn no_share_leaves_before_the_roster_is_durable() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_key = "d5".repeat(16);
    let admin = state.agent.identity().agent_keypair();
    let other = AgentId([0x6E; 32]);
    let other_hex = hex::encode(other.as_bytes());
    seed_group(&state, &group_key, admin, &other).await;
    let info = state.named_groups.read().await[&group_key].clone();
    let epoch = info.secret_epoch;
    assert!(matches!(
        secure_share_delivery_verdict(&state, &group_key, &other_hex, epoch).await,
        SecureShareDeliveryVerdict::Deliver
    ));
    let seam = secure_share_admission(&state, &group_key, &other_hex, epoch)()
        .await
        .ok_or_else(|| anyhow::anyhow!("admitted while the roster is durable"))?;

    let fault = set_save_fault(&state, SaveFault::ReplacedNotDurableAfterWriteThenError);
    assert_eq!(
        persist_named_group_info(&state, &group_key, info).await?,
        AtomicWriteOutcome::ReplacedNotDurable
    );
    assert!(!seam(), "the seam refuses while the roster is not durable");
    assert!(
        secure_share_admission(&state, &group_key, &other_hex, epoch)()
            .await
            .is_none(),
        "the pre-phase refuses while every re-save fails"
    );
    assert!(matches!(
        secure_share_delivery_verdict(&state, &group_key, &other_hex, epoch).await,
        SecureShareDeliveryVerdict::Withhold("roster_not_durable")
    ));

    drop(fault);
    assert!(matches!(
        secure_share_delivery_verdict(&state, &group_key, &other_hex, epoch).await,
        SecureShareDeliveryVerdict::Deliver
    ));
    let seam = secure_share_admission(&state, &group_key, &other_hex, epoch)()
        .await
        .ok_or_else(|| anyhow::anyhow!("admitted once the re-save is durable"))?;
    assert!(seam(), "the share leaves once the roster is durable");
    Ok(())
}
