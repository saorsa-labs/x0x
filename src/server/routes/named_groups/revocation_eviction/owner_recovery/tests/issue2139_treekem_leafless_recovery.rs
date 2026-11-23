#![cfg(test)]
//! #2139, daemon level. Limit (ii) of #2133 (a recovery whose revoked
//! admins hold no leaf left the held creator in step) is closed by the V2
//! body: see `issue2139_owner_recovery_v2`. These tests pin what stays:
//!
//! - Limit (iii): the recovery-frame gate refuses only a seat whose expiry
//!   is DUE (past `not_after` + τ). A seat inside τ, or one whose
//!   certificate becomes due only after the recovery, is served the frame.
//! - The V1 receiver rule: a V1 recovery removes only the revoked seats'
//!   leaves, one per commit.

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

/// #2139 receiver tightening: a received TreeKEM recovery may remove the
/// revoked seats' leaves and no other. One wire commit can remove several
/// leaves, or add one, so the commit count alone does not prove it.
#[test]
fn a_recovery_commit_may_remove_only_the_revoked_seats_leaves() {
    let (admin_id, revoked_id, survivor_id) = (
        AgentId([0xA1; 32]),
        AgentId([0x51; 32]),
        AgentId([0x5E; 32]),
    );
    let mut tree = TreeKemMlsGroup::create(b"2139-exact".to_vec(), admin_id, &[0xA1; 32]).unwrap();
    for (id, seed) in [(revoked_id, 0x51u8), (survivor_id, 0x5E)] {
        let prepared = TreeKemMlsGroup::prepare_member(id, &[seed; 32]).unwrap();
        tree.add_member(id, prepared.key_package_bytes()).unwrap();
    }
    let before = tree.member_count();
    let removal = tree.remove_member(revoked_id).unwrap();
    let (revoked, survivor) = (
        hex::encode(revoked_id.as_bytes()),
        hex::encode(survivor_id.as_bytes()),
    );
    let presence = |revoked_present: bool, survivor_present: bool| {
        BTreeMap::from([
            (revoked.clone(), Some(revoked_present)),
            (survivor.clone(), Some(survivor_present)),
        ])
    };
    let revoked_set = BTreeSet::from([revoked.clone()]);
    let exact = |commits: &[Vec<u8>], after: u32, survivor_after: bool| {
        recovery_commits_remove_only_revoked_leaves(
            commits,
            before,
            after,
            &presence(true, true),
            &presence(false, survivor_after),
            &revoked_set,
        )
    };

    assert!(
        exact(std::slice::from_ref(&removal), before - 1, true),
        "the honest single removal passes"
    );
    assert!(
        recovery_commits_remove_only_revoked_leaves(
            &[],
            before,
            before,
            &presence(true, true),
            &presence(true, true),
            &BTreeSet::new(),
        ),
        "a leafless recovery with no commit passes"
    );
    // One commit that also removes the survivor's leaf.
    let mut widened: saorsa_mls::treekem_group::TreeKemCommit =
        postcard::from_bytes(&removal).unwrap();
    let extra = widened.removed_leaves[0] + 1;
    widened.removed_leaves.push(extra);
    let widened = postcard::to_stdvec(&widened).unwrap();
    assert!(
        !exact(&[widened], before - 2, false),
        "a commit that removes a second leaf is refused"
    );
    assert!(
        !exact(std::slice::from_ref(&removal), before - 1, false),
        "a surviving seat's leaf must still be present"
    );
    assert!(
        !exact(std::slice::from_ref(&removal), before - 2, true),
        "the leaf count must fall by exactly one per commit"
    );
    // An add in place of the removal.
    let prepared = TreeKemMlsGroup::prepare_member(AgentId([0x77; 32]), &[0x77; 32]).unwrap();
    let mut other = TreeKemMlsGroup::create(b"2139-add".to_vec(), admin_id, &[0xA2; 32]).unwrap();
    let add = other
        .add_member(AgentId([0x77; 32]), prepared.key_package_bytes())
        .unwrap();
    assert!(
        !exact(&[add.commit], before - 1, true),
        "a commit that adds a leaf is refused"
    );
}
