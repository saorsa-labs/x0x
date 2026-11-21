#![cfg(test)]
//! #2133, TreeKEM plane, at the TreeKEM layer (follow-up #2139). After an
//! owner recovery the held (expired-certificate) creator keeps its leaf.
//! What it can derive from later public commits depends on whether a
//! commit was withheld from it:
//!
//! - A recovery that carries a TreeKEM commit moves the epoch, and that
//!   commit travels only in the recovery frame, which is refused to the
//!   creator (#2004). A creator one commit behind cannot apply the next
//!   public commit: a commit applies only at `epoch + 1`, and the new epoch
//!   is derived from the previous epoch's secret, which it never had.
//! - A recovery with no TreeKEM commit (the revoked admins hold no leaf)
//!   leaves the creator in step, so it follows the next public commit
//!   (KNOWN LIMIT, #2139).
//!
//! The GSS tests of #2133
//! (`restart_tests::issue2133_recovery_proceeds_past_an_expired_creator_with_no_key_for_it`)
//! do not cover TreeKEM.

use crate::identity::AgentId;
use crate::mls::TreeKemMlsGroup;

fn agent(id: u8) -> AgentId {
    AgentId([id; 32])
}

/// An admin and three Members: the creator, a seat the recovery removes,
/// and a tolerated seat evicted later. Every Member follows every add, so
/// all are in step before the recovery.
fn group() -> (TreeKemMlsGroup, TreeKemMlsGroup, [AgentId; 3]) {
    let (admin_id, creator_id, removed_id, tolerated_id) =
        (agent(0xA1), agent(0xC1), agent(0x51), agent(0x71));
    let mut admin =
        TreeKemMlsGroup::create(b"2133-treekem".to_vec(), admin_id, &[0xA1; 32]).expect("admin");
    let creator_prepared =
        TreeKemMlsGroup::prepare_member(creator_id, &[0xC1; 32]).expect("creator prepare");
    let added = admin
        .add_member(creator_id, creator_prepared.key_package_bytes())
        .expect("add creator");
    let mut creator =
        TreeKemMlsGroup::join_from_welcome(creator_prepared, &added.welcome).expect("creator join");
    for (id, seed) in [(removed_id, 0x51), (tolerated_id, 0x71)] {
        let prepared = TreeKemMlsGroup::prepare_member(id, &[seed; 32]).expect("prepare");
        let added = admin
            .add_member(id, prepared.key_package_bytes())
            .expect("add member");
        creator
            .process_commit(&added.commit)
            .expect("creator follows the add");
    }
    assert_eq!(creator.epoch(), admin.epoch(), "precondition: in step");
    (admin, creator, [creator_id, removed_id, tolerated_id])
}

/// A recovery commit withheld from the creator: the creator cannot apply
/// the next public commit and cannot read the new epoch, although the
/// admin keeps its leaf.
#[test]
fn a_creator_one_commit_behind_cannot_follow_the_next_public_commit() {
    let (mut admin, mut creator, [creator_id, removed_id, tolerated_id]) = group();
    let start = creator.epoch();
    // The recovery's TreeKEM commit; the frame is never written to the
    // creator.
    let _recovery_commit = admin.remove_member(removed_id).expect("recovery commit");
    // The tolerated seat's eviction, published on the metadata topic.
    let eviction = admin.remove_member(tolerated_id).expect("eviction commit");
    assert!(
        admin.tracks_member(&creator_id),
        "the admin's tree still holds the creator's leaf"
    );
    let expected = format!("Invalid epoch: expected {}, got {}", start + 1, start + 2);
    match creator.process_commit(&eviction) {
        Err(crate::mls::MlsError::SaorsaMls(message)) if message.contains(&expected) => {}
        other => panic!("a commit two epochs ahead is refused as InvalidEpoch: {other:?}"),
    }
    assert_eq!(creator.epoch(), start, "the creator stays at its epoch");
    let ciphertext = admin
        .encrypt_message(b"after the eviction")
        .expect("encrypt");
    assert!(
        creator.decrypt_message(&ciphertext).is_err(),
        "the creator cannot read the new epoch"
    );
}

/// KNOWN LIMIT (#2139): with no commit withheld (a recovery that carries
/// no TreeKEM commit, or a leaked recovery frame), the creator's leaf
/// follows the next public commit and reads the new epoch.
#[test]
fn known_limit_2139_a_creator_in_step_follows_the_next_public_commit() {
    let (mut admin, mut creator, [creator_id, _removed_id, tolerated_id]) = group();
    let eviction = admin.remove_member(tolerated_id).expect("eviction commit");
    assert!(
        admin.tracks_member(&creator_id),
        "the admin's tree still holds the creator's leaf"
    );
    creator
        .process_commit(&eviction)
        .expect("an in-step leaf applies the public commit");
    assert_eq!(creator.epoch(), admin.epoch());
    let ciphertext = admin
        .encrypt_message(b"after the eviction")
        .expect("encrypt");
    assert_eq!(
        creator
            .decrypt_message(&ciphertext)
            .expect("the creator reads the new epoch"),
        b"after the eviction"
    );
}
