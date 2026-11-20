#![cfg(test)]
//! #2133 KNOWN LIMIT (TreeKEM plane), follow-up #2139. This test pins
//! today's behaviour and is not evidence that the expired-creator rule
//! holds on TreeKEM. The GSS tests of #2133
//! (`restart_tests::issue2133_recovery_proceeds_past_an_expired_creator_with_no_key_for_it`)
//! cover the GSS plane only.
//!
//! On TreeKEM the owner recovery leaves the held (expired-certificate)
//! creator its leaf. The recovery frame and the TreeKEM catch-up refuse it
//! (#2004), so it does not get the recovery epoch. But the next commit, for
//! example the tolerated seat's own eviction (`MemberRemoved` with its
//! `treekem_commit_b64`, published on the metadata topic), encrypts path
//! secrets to every leaf. Any leaf holder that receives that public commit
//! derives the new epoch key. The same holds for a non-creator due-expired
//! seat until its own eviction commit, because each S4 target gets its own
//! transition. When #2139 lands, this test must change.

use crate::identity::AgentId;
use crate::mls::TreeKemMlsGroup;

fn agent(id: u8) -> AgentId {
    AgentId([id; 32])
}

/// A held creator's leaf derives the epoch of a later public removal
/// commit: it processes the commit and decrypts a message of the new
/// epoch.
#[test]
fn known_limit_2139_a_held_creator_leaf_derives_a_later_commits_epoch() {
    let (admin_id, creator_id, tolerated_id) = (agent(0xA1), agent(0xC1), agent(0x71));
    let mut admin =
        TreeKemMlsGroup::create(b"2133-treekem".to_vec(), admin_id, &[0xA1; 32]).expect("admin");
    let creator_prepared =
        TreeKemMlsGroup::prepare_member(creator_id, &[0xC1; 32]).expect("creator prepare");
    let added = admin
        .add_member(creator_id, creator_prepared.key_package_bytes())
        .expect("add creator");
    let mut creator =
        TreeKemMlsGroup::join_from_welcome(creator_prepared, &added.welcome).expect("creator join");
    let tolerated_prepared =
        TreeKemMlsGroup::prepare_member(tolerated_id, &[0x71; 32]).expect("tolerated prepare");
    let added = admin
        .add_member(tolerated_id, tolerated_prepared.key_package_bytes())
        .expect("add tolerated");
    creator
        .process_commit(&added.commit)
        .expect("creator follows the add");
    assert_eq!(creator.epoch(), admin.epoch(), "precondition: in step");

    // The creator's leaf stays (no commit removes it), and the next commit
    // is the tolerated seat's eviction.
    let before = admin.epoch();
    let eviction = admin.remove_member(tolerated_id).expect("evict tolerated");
    assert!(admin.epoch() > before, "the eviction moves the epoch");
    assert!(
        creator.tracks_member(&creator_id),
        "the held creator keeps its leaf"
    );

    // KNOWN LIMIT: the leaf holder derives the new epoch from the public
    // commit and reads a message of that epoch.
    creator
        .process_commit(&eviction)
        .expect("the held creator's leaf processes the public eviction commit");
    assert_eq!(
        creator.epoch(),
        admin.epoch(),
        "the creator reaches the new epoch"
    );
    let ciphertext = admin
        .encrypt_message(b"after the eviction")
        .expect("encrypt at the new epoch");
    assert_eq!(
        creator
            .decrypt_message(&ciphertext)
            .expect("the held creator decrypts the new epoch"),
        b"after the eviction"
    );
}
