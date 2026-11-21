#![cfg(test)]
//! #2139, daemon level: the TreeKEM known limits of #2133 that A09 (21 Nov
//! 2026) keeps as accepted limits. These tests pin today's behaviour, so a
//! later change to it is deliberate.
//!
//! - Limit (ii): a recovery whose revoked admins hold no TreeKEM leaf
//!   carries no TreeKEM commit (`commit_treekem` skips every leafless
//!   removed seat), so the epoch does not move and the expired creator,
//!   still seated with its leaf, stays in step with the promoted admin's
//!   tree. It applies the next public commit and reads the new epoch.
//! - Limit (iii): the recovery-frame gate refuses only a seat whose expiry
//!   is DUE (past `not_after` + τ). A seat inside τ, or one whose
//!   certificate becomes due only after the recovery, is served the frame.

use super::*;
use x0x::mls::TreeKemMlsGroup;

/// A certified Member seat for `agent`, its certificate expiring at
/// `not_after` (`None`: no expiry).
fn member_seat(
    owner: &x0x::identity::UserKeypair,
    agent: &x0x::identity::AgentKeypair,
    not_after: Option<u64>,
) -> x0x::groups::GroupMember {
    let cert = x0x::identity::AgentCertificate::issue_with_expiry(owner, agent, not_after).unwrap();
    let mut member = x0x::groups::GroupMember::new_member(
        hex::encode(agent.agent_id().as_bytes()),
        None,
        None,
        1,
    );
    member.certificate_digest = Some(x0x::groups::owner_cert::certificate_digest_hex(&cert));
    member.certificate = Some(cert);
    member
}

/// #2133 mixed case on the TreeKEM plane, with a leafless revoked admin:
/// the creator C is a Member whose certificate expired two hours ago (it
/// holds a leaf), and a revoked Member T (with a leaf) is tolerated. The
/// real recovery attempt commits past the held creator with NO TreeKEM
/// commit: the epoch stays, and the promoted admin's tree still holds C's
/// leaf. C, which never got the recovery frame, then applies the admin's
/// next public commit (T's removal) and reads the new epoch.
#[tokio::test]
async fn known_limit_2139_a_leafless_recovery_leaves_the_expired_creator_in_step() {
    use base64::Engine as _;
    let (_dir, state, mut info, admin_hex) = recovery_fixture().await;
    let owner = state.agent.identity().user_keypair().unwrap();
    let local = state.agent.agent_id();
    let local_hex = hex::encode(local.as_bytes());
    let creator = x0x::identity::AgentKeypair::generate().unwrap();
    let tolerated = x0x::identity::AgentKeypair::generate().unwrap();
    let (creator_id, tolerated_id) = (creator.agent_id(), tolerated.agent_id());
    let creator_hex = hex::encode(creator_id.as_bytes());
    let tolerated_hex = hex::encode(tolerated_id.as_bytes());

    // The promoted member's tree holds its own leaf, C's and T's; the
    // revoked admin has none. C joins from the Welcome and follows T's add.
    let group_id_bytes = hex::decode(&info.mls_group_id).unwrap();
    let mut tree = TreeKemMlsGroup::create(group_id_bytes, local, &[0x5A; 32]).unwrap();
    let creator_prepared = TreeKemMlsGroup::prepare_member(creator_id, &[0xC1; 32]).unwrap();
    let creator_kp = creator_prepared.key_package_bytes().to_vec();
    let added = tree.add_member(creator_id, &creator_kp).unwrap();
    let mut creator_tree =
        TreeKemMlsGroup::join_from_welcome(creator_prepared, &added.welcome).unwrap();
    let tolerated_prepared = TreeKemMlsGroup::prepare_member(tolerated_id, &[0x71; 32]).unwrap();
    let tolerated_kp = tolerated_prepared.key_package_bytes().to_vec();
    let added = tree.add_member(tolerated_id, &tolerated_kp).unwrap();
    creator_tree.process_commit(&added.commit).unwrap();
    let epoch = tree.epoch();
    assert_eq!(creator_tree.epoch(), epoch, "precondition: C is in step");

    let now = x0x::groups::owner_cert::restore_clock_now();
    info.members_v2.insert(
        creator_hex.clone(),
        member_seat(owner, &creator, Some(now.saturating_sub(2 * 3_600))),
    );
    info.members_v2
        .insert(tolerated_hex.clone(), member_seat(owner, &tolerated, None));
    let b64 = base64::engine::general_purpose::STANDARD;
    info.set_member_treekem_key_package(&creator_hex, b64.encode(&creator_kp));
    info.set_member_treekem_key_package(&tolerated_hex, b64.encode(&tolerated_kp));
    assert!(
        info.members_v2[&admin_hex]
            .treekem_key_package_hash
            .is_none(),
        "precondition: the revoked admin holds no leaf"
    );
    info.creator = creator_id;
    info.policy.confidentiality = x0x::groups::policy::GroupConfidentiality::MlsEncrypted;
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.secret_epoch = epoch;
    info.security_binding = Some(format!("treekem:epoch={epoch}"));
    info.recompute_state_hash();
    assert_eq!(orc::crypto_kind(&info), orc::RecoveryCryptoKind::TreeKem);
    assert!(
        info.creator_expired_certificate_hold(&creator_hex, now),
        "precondition: the creator is held on its own expired certificate"
    );
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(tolerated_id),
        tolerated.public_key(),
        tolerated.secret_key(),
        1,
        None,
    )
    .unwrap();
    assert!(state
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(record, None)
        .unwrap());
    let stable = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(stable.clone(), info.clone());
    let tree = Arc::new(tokio::sync::Mutex::new(tree));
    state
        .treekem_groups
        .write()
        .await
        .insert(stable.clone(), Arc::clone(&tree));

    let (status, Json(body)) = sign_recovery_mandate(&state, owner, &stable, &local_hex).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    sync_head(&state, &info).await;
    try_commit(&state, &stable).await;

    let committed = state.named_groups.read().await[&stable].clone();
    assert_eq!(
        committed.state_revision,
        info.state_revision + 1,
        "the recovery commits past the held creator"
    );
    assert_eq!(
        committed.members_v2[&local_hex].role,
        x0x::groups::GroupRole::Admin
    );
    assert_eq!(
        committed.members_v2[&creator_hex].state,
        x0x::groups::GroupMemberState::Active,
        "the creator stays seated"
    );
    assert_eq!(
        committed.secret_epoch, epoch,
        "a recovery with no leafed removed seat does not move the epoch"
    );
    assert_eq!(
        committed.security_binding.as_deref(),
        Some(orc::treekem_binding(epoch, &[]).as_str()),
        "the recovery carries no TreeKEM commit"
    );

    let mut tree = tree.lock().await;
    assert_eq!(tree.epoch(), epoch);
    assert!(
        tree.tracks_member(&creator_id),
        "the promoted admin's tree still holds the creator's leaf"
    );
    // The admin's next public commit: T's removal.
    let eviction = tree.remove_member(tolerated_id).unwrap();
    creator_tree
        .process_commit(&eviction)
        .expect("KNOWN LIMIT (ii): the in-step creator applies the next public commit");
    assert_eq!(creator_tree.epoch(), tree.epoch());
    let ciphertext = tree.encrypt_message(b"after the eviction").unwrap();
    assert_eq!(
        creator_tree
            .decrypt_message(&ciphertext)
            .expect("KNOWN LIMIT (ii): the creator reads the new epoch"),
        b"after the eviction"
    );
}

/// Limit (iii): the recovery-frame gate tests only a DUE expiry. A seat
/// whose certificate expires after the recovery, or that is past
/// `not_after` but inside τ, is not refused, so on TreeKEM it can take the
/// recovery epoch and follow later commits.
#[test]
fn known_limit_2139_the_recovery_frame_gate_serves_a_seat_not_yet_due() {
    let owner = x0x::identity::UserKeypair::generate().unwrap();
    let now = now_unix();
    let tau = x0x::groups::eviction::EXPIRY_TOLERANCE_SECS;
    let mut info = GroupInfo::new(
        "2139".to_string(),
        String::new(),
        AgentId([0xA1; 32]),
        "e1".repeat(16),
    );
    for (not_after, due) in [
        (now + 3_600, false),
        (now.saturating_sub(tau - 120), false),
        (now.saturating_sub(tau + 1), true),
    ] {
        let agent = x0x::identity::AgentKeypair::generate().unwrap();
        let seat = member_seat(&owner, &agent, Some(not_after));
        info.members_v2.insert(seat.agent_id.clone(), seat);
        assert_eq!(
            recipient_expiry_due(&info, &agent.agent_id(), now),
            due,
            "not_after = now {:+}",
            not_after as i64 - now as i64
        );
    }
}
