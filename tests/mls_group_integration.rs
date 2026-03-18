//! Integration tests for MLS group management, invite flow, and encrypted sync.
//!
//! These are unit-level tests that exercise the types and logic directly,
//! without requiring a running network.

use std::collections::HashMap;
use x0x::contacts::TrustLevel;
use x0x::crdt::{EncryptedTaskListDelta, TaskId, TaskItem, TaskListDelta, TaskMetadata};
use x0x::groups::{GroupState, PendingInvite};
use x0x::identity::{AgentId, Identity};
use x0x::mls::{MlsCipher, MlsGroup, MlsKeySchedule, MlsWelcome};
use x0x::types::GroupId;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_identity() -> Identity {
    Identity::generate().expect("identity generation failed")
}

fn agent_of(identity: &Identity) -> AgentId {
    identity.agent_id()
}

fn make_delta(agent_id: &AgentId) -> TaskListDelta {
    let mut delta = TaskListDelta::new(1);
    let timestamp = 1000u64;
    let task_id = TaskId::new("Test task", agent_id, timestamp);
    let peer_id = saorsa_gossip_types::PeerId::new(*agent_id.as_bytes());
    let metadata = TaskMetadata::new("Test task", "Description", 128, *agent_id, timestamp);
    let task = TaskItem::new(task_id, metadata, peer_id);
    delta.added_tasks.insert(task_id, (task, (peer_id, 1)));
    delta
}

fn make_pending_invite(
    _group_id: GroupId,
    sender: AgentId,
    welcome: MlsWelcome,
    received_at: u64,
) -> PendingInvite {
    PendingInvite {
        welcome,
        sender,
        verified: true,
        trust_level: Some(TrustLevel::Known),
        received_at,
    }
}

// ---------------------------------------------------------------------------
// Test 1: Create group and invite flow
// ---------------------------------------------------------------------------

#[test]
fn test_create_group_and_invite_flow() {
    let creator_id = test_identity();
    let creator = agent_of(&creator_id);

    let invitee_id = test_identity();
    let invitee = agent_of(&invitee_id);

    // Creator creates an MLS group
    let group_id = b"invite-flow-group".to_vec();
    let group = MlsGroup::new(group_id.clone(), creator).expect("group creation failed");
    assert!(group.is_member(&creator));

    // Creator issues a Welcome for the invitee
    let welcome = MlsWelcome::create(&group, &invitee).expect("welcome creation failed");
    assert_eq!(welcome.group_id(), group_id.as_slice());

    // Invitee accepts via from_welcome
    let joined = MlsGroup::from_welcome(&welcome, invitee).expect("from_welcome failed");

    // Verify: invitee's group has the same group_id
    assert_eq!(joined.group_id(), group_id.as_slice());
    // Verify: invitee is a member of the joined group
    assert!(joined.is_member(&invitee));
    // Verify: epoch matches the creator's group epoch
    assert_eq!(joined.current_epoch(), group.current_epoch());
}

// ---------------------------------------------------------------------------
// Test 2: Reject invite removes pending
// ---------------------------------------------------------------------------

#[test]
fn test_reject_invite_removes_pending() {
    let creator_id = test_identity();
    let creator = agent_of(&creator_id);
    let invitee_id = test_identity();
    let invitee = agent_of(&invitee_id);

    let group_id_bytes = b"reject-test-group".to_vec();
    let group = MlsGroup::new(group_id_bytes.clone(), creator).expect("group creation failed");
    let welcome = MlsWelcome::create(&group, &invitee).expect("welcome creation failed");

    let group_id = GroupId::from_mls_group_id(&group_id_bytes);

    let mut state = GroupState::default();
    let invite = make_pending_invite(group_id, creator, welcome, 1000);
    state.pending_invites.insert((group_id, creator), invite);
    assert_eq!(state.pending_invites.len(), 1);

    // Reject: remove from pending_invites
    state.pending_invites.remove(&(group_id, creator));
    assert!(state.pending_invites.is_empty());
}

// ---------------------------------------------------------------------------
// Test 3: Non-member cannot decrypt
// ---------------------------------------------------------------------------

#[test]
fn test_non_member_cannot_decrypt() {
    let creator_id = test_identity();
    let creator = agent_of(&creator_id);

    let non_member_id = test_identity();
    let non_member = agent_of(&non_member_id);

    // Creator's group
    let group = MlsGroup::new(b"creator-group".to_vec(), creator).expect("group creation failed");
    let delta = make_delta(&creator);

    // Encrypt delta with creator's group keys
    let encrypted =
        EncryptedTaskListDelta::encrypt_with_group(&delta, &group, 0).expect("encrypt failed");

    // Non-member has a different group — different group_id means different keys
    let other_group =
        MlsGroup::new(b"other-group".to_vec(), non_member).expect("group creation failed");

    // Attempt to decrypt with the other group's keys should fail
    let result = encrypted.decrypt_with_group(&other_group);
    assert!(result.is_err(), "non-member should not be able to decrypt");
}

// ---------------------------------------------------------------------------
// Test 4: Wrong agent cannot accept welcome
// ---------------------------------------------------------------------------

#[test]
fn test_wrong_agent_cannot_accept_welcome() {
    let creator_id = test_identity();
    let creator = agent_of(&creator_id);

    let agent_a_id = test_identity();
    let agent_a = agent_of(&agent_a_id);

    let agent_b_id = test_identity();
    let agent_b = agent_of(&agent_b_id);

    let group = MlsGroup::new(b"wrong-agent-group".to_vec(), creator).expect("group failed");

    // Creator issues welcome for Agent A
    let welcome = MlsWelcome::create(&group, &agent_a).expect("welcome creation failed");

    // Agent B tries to accept — should fail with MemberNotInGroup
    let result = MlsGroup::from_welcome(&welcome, agent_b);
    assert!(result.is_err(), "wrong agent should not be able to accept");
    match result.unwrap_err() {
        x0x::mls::MlsError::MemberNotInGroup(_) => {} // expected
        other => panic!("expected MemberNotInGroup, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Test 5: Duplicate invite from same sender replaces
// ---------------------------------------------------------------------------

#[test]
fn test_duplicate_invite_from_same_sender_replaces() {
    let creator_id = test_identity();
    let creator = agent_of(&creator_id);
    let invitee_id = test_identity();
    let invitee = agent_of(&invitee_id);

    let group_id_bytes = b"dup-invite-group".to_vec();
    let group = MlsGroup::new(group_id_bytes.clone(), creator).expect("group creation failed");
    let group_id = GroupId::from_mls_group_id(&group_id_bytes);

    let welcome1 = MlsWelcome::create(&group, &invitee).expect("welcome 1 failed");
    let welcome2 = MlsWelcome::create(&group, &invitee).expect("welcome 2 failed");

    let mut state = GroupState::default();

    // Insert first invite at t=1000
    let invite1 = make_pending_invite(group_id, creator, welcome1, 1000);
    state.pending_invites.insert((group_id, creator), invite1);

    // Insert second invite at t=2000 — same (group_id, sender) key
    let invite2 = make_pending_invite(group_id, creator, welcome2, 2000);
    state.pending_invites.insert((group_id, creator), invite2);

    // Only one entry should exist, and it should be the latest one
    assert_eq!(state.pending_invites.len(), 1);
    let stored = state.pending_invites.get(&(group_id, creator)).unwrap();
    assert_eq!(stored.received_at, 2000);
}

// ---------------------------------------------------------------------------
// Test 6: Invites from different senders stored separately
// ---------------------------------------------------------------------------

#[test]
fn test_invite_from_different_sender_stored_separately() {
    let sender_a_id = test_identity();
    let sender_a = agent_of(&sender_a_id);
    let sender_b_id = test_identity();
    let sender_b = agent_of(&sender_b_id);
    let invitee_id = test_identity();
    let invitee = agent_of(&invitee_id);

    let group_id_bytes = b"multi-sender-group".to_vec();
    let group_id = GroupId::from_mls_group_id(&group_id_bytes);

    // Create groups for each sender so we can issue welcomes
    let group_a = MlsGroup::new(group_id_bytes.clone(), sender_a).expect("group_a creation failed");
    let group_b = MlsGroup::new(group_id_bytes.clone(), sender_b).expect("group_b creation failed");

    let welcome_a = MlsWelcome::create(&group_a, &invitee).expect("welcome_a failed");
    let welcome_b = MlsWelcome::create(&group_b, &invitee).expect("welcome_b failed");

    let mut state = GroupState::default();
    let invite_a = make_pending_invite(group_id, sender_a, welcome_a, 1000);
    let invite_b = make_pending_invite(group_id, sender_b, welcome_b, 1001);
    state.pending_invites.insert((group_id, sender_a), invite_a);
    state.pending_invites.insert((group_id, sender_b), invite_b);

    // Two entries: same group, different senders
    assert_eq!(state.pending_invites.len(), 2);
    assert!(state.pending_invites.contains_key(&(group_id, sender_a)));
    assert!(state.pending_invites.contains_key(&(group_id, sender_b)));
}

// ---------------------------------------------------------------------------
// Test 7: Nonce counter increments produce different ciphertexts
// ---------------------------------------------------------------------------

#[test]
fn test_nonce_counter_increments() {
    let creator_id = test_identity();
    let creator = agent_of(&creator_id);

    let group = MlsGroup::new(b"nonce-counter-group".to_vec(), creator).expect("group failed");
    let delta = make_delta(&creator);

    let enc0 = EncryptedTaskListDelta::encrypt_with_group(&delta, &group, 0).expect("encrypt c=0");
    let enc1 = EncryptedTaskListDelta::encrypt_with_group(&delta, &group, 1).expect("encrypt c=1");
    let enc2 = EncryptedTaskListDelta::encrypt_with_group(&delta, &group, 2).expect("encrypt c=2");

    // All three ciphertexts must be different
    assert_ne!(enc0.ciphertext(), enc1.ciphertext());
    assert_ne!(enc1.ciphertext(), enc2.ciphertext());
    assert_ne!(enc0.ciphertext(), enc2.ciphertext());

    // All three must decrypt successfully
    let dec0 = enc0.decrypt_with_group(&group).expect("decrypt c=0");
    let dec1 = enc1.decrypt_with_group(&group).expect("decrypt c=1");
    let dec2 = enc2.decrypt_with_group(&group).expect("decrypt c=2");

    assert_eq!(dec0.version, delta.version);
    assert_eq!(dec1.version, delta.version);
    assert_eq!(dec2.version, delta.version);
}

// ---------------------------------------------------------------------------
// Test 8: Encrypted delta roundtrip with group keys
// ---------------------------------------------------------------------------

#[test]
fn test_encrypted_delta_roundtrip_with_group_keys() {
    let creator_id = test_identity();
    let creator = agent_of(&creator_id);

    let group = MlsGroup::new(b"roundtrip-group".to_vec(), creator).expect("group creation failed");
    let delta = make_delta(&creator);

    // Derive keys, create cipher, encrypt, decrypt
    let key_schedule = MlsKeySchedule::from_group(&group).expect("key schedule failed");
    let cipher = MlsCipher::new(
        key_schedule.encryption_key().to_vec(),
        key_schedule.base_nonce().to_vec(),
    );

    let encrypted =
        EncryptedTaskListDelta::encrypt(&delta, &group, &cipher, 0).expect("encrypt failed");
    let decrypted = encrypted.decrypt(&cipher).expect("decrypt failed");

    // Verify round-tripped delta matches original
    assert_eq!(decrypted.version, delta.version);
    assert_eq!(decrypted.added_tasks.len(), delta.added_tasks.len());
    for (task_id, (task, _tag)) in &delta.added_tasks {
        assert!(
            decrypted.added_tasks.contains_key(task_id),
            "decrypted delta should contain task {:?}",
            task.id()
        );
    }
}

// ---------------------------------------------------------------------------
// Test 9: GroupId derivation is consistent
// ---------------------------------------------------------------------------

#[test]
fn test_group_id_derivation_is_consistent() {
    let bytes = b"consistent-group-id";

    // Same input twice should produce equal GroupIds
    let id1 = GroupId::from_mls_group_id(bytes);
    let id2 = GroupId::from_mls_group_id(bytes);
    assert_eq!(id1, id2);

    // Different input should produce a different GroupId
    let id3 = GroupId::from_mls_group_id(b"different-group-id");
    assert_ne!(id1, id3);
}

// ---------------------------------------------------------------------------
// Test 10: Pending invite keyed by group and sender
// ---------------------------------------------------------------------------

#[test]
fn test_pending_invite_keyed_by_group_and_sender() {
    let sender_a_id = test_identity();
    let sender_a = agent_of(&sender_a_id);
    let sender_b_id = test_identity();
    let sender_b = agent_of(&sender_b_id);
    let invitee_id = test_identity();
    let invitee = agent_of(&invitee_id);

    let group_id_1_bytes = b"group-1-lookup".to_vec();
    let group_id_2_bytes = b"group-2-lookup".to_vec();
    let gid1 = GroupId::from_mls_group_id(&group_id_1_bytes);
    let gid2 = GroupId::from_mls_group_id(&group_id_2_bytes);

    let group1 = MlsGroup::new(group_id_1_bytes.clone(), sender_a).expect("group1 creation failed");
    let group2 = MlsGroup::new(group_id_2_bytes.clone(), sender_b).expect("group2 creation failed");

    let welcome_1a = MlsWelcome::create(&group1, &invitee).expect("welcome 1a failed");
    let welcome_2b = MlsWelcome::create(&group2, &invitee).expect("welcome 2b failed");

    let mut map: HashMap<(GroupId, AgentId), PendingInvite> = HashMap::new();

    // (group1, sender_a)
    map.insert(
        (gid1, sender_a),
        make_pending_invite(gid1, sender_a, welcome_1a, 100),
    );
    // (group2, sender_b)
    map.insert(
        (gid2, sender_b),
        make_pending_invite(gid2, sender_b, welcome_2b, 200),
    );

    // Lookups should work correctly
    assert!(map.contains_key(&(gid1, sender_a)));
    assert!(map.contains_key(&(gid2, sender_b)));

    // Cross lookups should not match
    assert!(!map.contains_key(&(gid1, sender_b)));
    assert!(!map.contains_key(&(gid2, sender_a)));

    assert_eq!(map.get(&(gid1, sender_a)).unwrap().received_at, 100);
    assert_eq!(map.get(&(gid2, sender_b)).unwrap().received_at, 200);
}
