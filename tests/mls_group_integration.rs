//! Integration tests for MLS group management, invite flow, and encrypted sync.
//!
//! These are unit-level tests that exercise the types and logic directly,
//! without requiring a running network.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;
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

// ---------------------------------------------------------------------------
// Test 11: End-to-end create → invite → accept → encrypted sync
// ---------------------------------------------------------------------------

#[test]
fn test_end_to_end_create_invite_accept_encrypted_sync() {
    use x0x::crdt::{TaskList, TaskListId};

    // 1. Alice creates group
    let alice = test_identity();
    let alice_id = agent_of(&alice);
    let group_id_bytes = b"e2e-test-group".to_vec();
    let mut alice_group = MlsGroup::new(group_id_bytes.clone(), alice_id).unwrap();
    let group_id = GroupId::from_mls_group_id(&group_id_bytes);

    // 2. Alice invites Bob
    let bob = test_identity();
    let bob_id = agent_of(&bob);
    let _commit = alice_group.add_member(bob_id).unwrap();
    let welcome = MlsWelcome::create(&alice_group, &bob_id).unwrap();

    // 3. Bob accepts
    let bob_group = MlsGroup::from_welcome(&welcome, bob_id).unwrap();
    assert_eq!(bob_group.group_id(), alice_group.group_id());

    // 4. Both create task lists (simulating what init_encrypted_sync does)
    let alice_peer = saorsa_gossip_types::PeerId::new(*alice_id.as_bytes());
    let bob_peer = saorsa_gossip_types::PeerId::new(*bob_id.as_bytes());
    let list_id = TaskListId::new(*group_id.as_bytes());
    let mut alice_list = TaskList::new(list_id, "E2E Test".to_string(), alice_peer);
    let mut bob_list = TaskList::new(list_id, "E2E Test".to_string(), bob_peer);

    // 5. Alice adds a task and creates a delta
    let task_id = TaskId::new("Review the PR", &alice_id, 2000);
    let metadata = TaskMetadata::new(
        "Review the PR",
        "Check the MLS implementation",
        128,
        alice_id,
        2000,
    );
    let task = TaskItem::new(task_id, metadata, alice_peer);
    let mut delta = TaskListDelta::new(1);
    delta
        .added_tasks
        .insert(task_id, (task.clone(), (alice_peer, 1)));
    alice_list.add_task(task, alice_peer, 1).unwrap();

    // 6. Alice encrypts the delta with her group
    let encrypted = EncryptedTaskListDelta::encrypt_with_group(&delta, &alice_group, 0).unwrap();

    // 7. Bob decrypts with his group
    let decrypted = encrypted.decrypt_with_group(&bob_group).unwrap();
    assert_eq!(decrypted.added_tasks.len(), 1);
    assert!(decrypted.added_tasks.contains_key(&task_id));

    // 8. Bob merges the delta into his task list
    bob_list.merge_delta(&decrypted, alice_peer).unwrap();
    assert_eq!(bob_list.task_count(), 1);
    let bob_task = bob_list.get_task(&task_id).unwrap();
    assert_eq!(bob_task.title(), "Review the PR");
}

// ---------------------------------------------------------------------------
// Test 12: Non-member encrypted mutation rejected
// ---------------------------------------------------------------------------

#[test]
fn test_non_member_encrypted_mutation_rejected() {
    // Setup: Alice's group
    let alice = test_identity();
    let alice_id = agent_of(&alice);
    let group_id_bytes = b"rejection-test".to_vec();
    let alice_group = MlsGroup::new(group_id_bytes.clone(), alice_id).unwrap();

    // Eve creates her own group (different keys)
    let eve = test_identity();
    let eve_id = agent_of(&eve);
    let eve_group = MlsGroup::new(b"eve-group".to_vec(), eve_id).unwrap();

    // Eve encrypts a delta with her own group keys
    let delta = make_delta(&eve_id);
    let eve_encrypted = EncryptedTaskListDelta::encrypt_with_group(&delta, &eve_group, 0).unwrap();

    // Alice tries to decrypt Eve's delta — should fail
    let result = eve_encrypted.decrypt_with_group(&alice_group);
    assert!(
        result.is_err(),
        "non-member encrypted delta should not decrypt with group keys"
    );
}

// ---------------------------------------------------------------------------
// Test 13: Ciphertext does not contain plaintext marker (privacy backstop)
// ---------------------------------------------------------------------------

#[test]
fn test_ciphertext_does_not_contain_plaintext_marker() {
    let creator_id = test_identity();
    let creator = agent_of(&creator_id);

    let group = MlsGroup::new(b"ciphertext-backstop-group".to_vec(), creator)
        .expect("group creation failed");

    // Create a delta with a distinctive canary marker in the task title
    let canary = "CANARY_SECRET_xK9mQ2";
    let timestamp = 3000u64;
    let task_id = TaskId::new(canary, &creator, timestamp);
    let peer_id = saorsa_gossip_types::PeerId::new(*creator.as_bytes());
    let metadata = TaskMetadata::new(canary, "also secret description", 128, creator, timestamp);
    let task = TaskItem::new(task_id, metadata, peer_id);
    let mut delta = TaskListDelta::new(1);
    delta.added_tasks.insert(task_id, (task, (peer_id, 1)));

    // Encrypt
    let encrypted =
        EncryptedTaskListDelta::encrypt_with_group(&delta, &group, 0).expect("encryption failed");

    // Serialize the entire encrypted envelope to bytes
    let envelope_bytes = bincode::serialize(&encrypted).expect("serialization failed");

    // The canary string must not appear in the raw bytes
    let canary_bytes = canary.as_bytes();
    for window in envelope_bytes.windows(canary_bytes.len()) {
        assert_ne!(
            window, canary_bytes,
            "plaintext canary '{}' found in encrypted envelope",
            canary
        );
    }

    // Also check the ciphertext field directly
    let ct = encrypted.ciphertext();
    for window in ct.windows(canary_bytes.len()) {
        assert_ne!(
            window, canary_bytes,
            "plaintext canary '{}' found in raw ciphertext",
            canary
        );
    }

    // Sanity: the canary IS in the plaintext delta
    let plaintext_bytes = bincode::serialize(&delta).expect("delta serialization failed");
    let found_in_plaintext = plaintext_bytes
        .windows(canary_bytes.len())
        .any(|w| w == canary_bytes);
    assert!(
        found_in_plaintext,
        "canary should be present in unencrypted delta (test sanity check)"
    );
}

// ---------------------------------------------------------------------------
// Test 14: Tampered welcome payload is rejected
// ---------------------------------------------------------------------------

#[test]
fn test_tampered_welcome_payload_rejected() {
    let creator_id = test_identity();
    let creator = agent_of(&creator_id);
    let invitee_id = test_identity();
    let invitee = agent_of(&invitee_id);

    let group_id_bytes = b"tampered-welcome-group".to_vec();
    let mut group = MlsGroup::new(group_id_bytes.clone(), creator).expect("group creation failed");
    let _commit = group.add_member(invitee).unwrap();
    let welcome = MlsWelcome::create(&group, &invitee).expect("welcome creation failed");

    // Sanity: untampered welcome works
    let ok = MlsGroup::from_welcome(&welcome, invitee);
    assert!(ok.is_ok(), "untampered welcome should succeed");

    // Tamper with the welcome by serialising, flipping bytes, deserialising
    let mut bytes = bincode::serialize(&welcome).expect("serialization failed");

    // Flip bytes in the middle of the payload (likely inside encrypted secrets)
    let mid = bytes.len() / 2;
    for i in mid..std::cmp::min(mid + 8, bytes.len()) {
        bytes[i] ^= 0xFF;
    }

    let tampered: MlsWelcome = match bincode::deserialize(&bytes) {
        Ok(w) => w,
        Err(_) => {
            // If deserialization itself fails, that's also a valid rejection —
            // the tampered payload cannot produce a functioning group.
            return;
        }
    };

    // Tampered welcome should fail — either verify() or from_welcome()
    let result = MlsGroup::from_welcome(&tampered, invitee);
    assert!(
        result.is_err(),
        "tampered welcome should not produce a valid group"
    );
}

// ---------------------------------------------------------------------------
// Test 15: Malformed payloads do not crash or alter state
// ---------------------------------------------------------------------------

#[test]
fn test_malformed_payloads_do_not_alter_state() {
    let creator_id = test_identity();
    let creator = agent_of(&creator_id);

    let group_id_bytes = b"malformed-payload-group".to_vec();
    let group = MlsGroup::new(group_id_bytes.clone(), creator).expect("group creation failed");

    // Set up a task list with one known task
    let peer_id = saorsa_gossip_types::PeerId::new(*creator.as_bytes());
    let list_id = x0x::crdt::TaskListId::new(
        *x0x::types::GroupId::from_mls_group_id(&group_id_bytes).as_bytes(),
    );
    let mut task_list = x0x::crdt::TaskList::new(list_id, "Resilience test".to_string(), peer_id);
    let task_id = TaskId::new("Existing task", &creator, 1000);
    let metadata = TaskMetadata::new("Existing task", "Already here", 128, creator, 1000);
    let task = TaskItem::new(task_id, metadata, peer_id);
    task_list.add_task(task, peer_id, 1).unwrap();
    assert_eq!(task_list.task_count(), 1);

    // --- Case 1: Random garbage bytes → fails envelope deserialization ---
    let garbage: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
    let deser_result: Result<EncryptedTaskListDelta, _> = bincode::deserialize(&garbage);
    assert!(deser_result.is_err(), "garbage should fail deserialization");
    assert_eq!(task_list.task_count(), 1, "state unchanged after garbage");

    // --- Case 2: Corrupted ciphertext → fails AEAD decryption ---
    let delta = make_delta(&creator);
    let encrypted =
        EncryptedTaskListDelta::encrypt_with_group(&delta, &group, 0).expect("encryption failed");

    // Serialize, flip bytes near the end (ciphertext region), deserialize
    let mut envelope_bytes = bincode::serialize(&encrypted).expect("serialization failed");
    let len = envelope_bytes.len();
    for byte in envelope_bytes.iter_mut().skip(len.saturating_sub(20)) {
        *byte ^= 0xFF;
    }
    let corrupted: EncryptedTaskListDelta =
        bincode::deserialize(&envelope_bytes).expect("envelope structure should still parse");
    let decrypt_result = corrupted.decrypt_with_group(&group);
    assert!(
        decrypt_result.is_err(),
        "corrupted ciphertext should fail decryption"
    );
    assert_eq!(
        task_list.task_count(),
        1,
        "state unchanged after corrupted ciphertext"
    );

    // --- Case 3: Valid AEAD ciphertext containing garbage plaintext ---
    // This exercises the decrypt() → bincode::deserialize error path:
    // decryption succeeds but the plaintext is not valid TaskListDelta.
    let key_schedule = x0x::mls::MlsKeySchedule::from_group(&group).expect("key schedule failed");
    let cipher = x0x::mls::MlsCipher::new(
        key_schedule.encryption_key().to_vec(),
        key_schedule.base_nonce().to_vec(),
    );
    let fake_plaintext = vec![0xFF; 64]; // Not valid bincode for TaskListDelta
    let context = group.context();
    let mut aad = Vec::new();
    aad.extend_from_slice(b"EncryptedDelta");
    aad.extend_from_slice(context.group_id());
    aad.extend_from_slice(&context.epoch().to_le_bytes());
    aad.extend_from_slice(&99u64.to_le_bytes());
    let fake_ciphertext = cipher
        .encrypt(&fake_plaintext, &aad, 99)
        .expect("encrypt failed");

    // Decrypt succeeds (valid AEAD), but the plaintext is garbage bincode
    let decrypted_garbage = cipher.decrypt(&fake_ciphertext, &aad, 99);
    assert!(
        decrypted_garbage.is_ok(),
        "decryption of validly-encrypted garbage should succeed"
    );
    let bad_delta: Result<x0x::crdt::TaskListDelta, _> =
        bincode::deserialize(&decrypted_garbage.unwrap());
    assert!(
        bad_delta.is_err(),
        "garbage plaintext should fail delta deserialization"
    );
    assert_eq!(
        task_list.task_count(),
        1,
        "state unchanged after bad delta deserialization"
    );
}

// ---------------------------------------------------------------------------
// Test 16: Logging does not expose plaintext canary (privacy regression)
// ---------------------------------------------------------------------------

/// A tracing writer that captures all output to a shared buffer.
#[derive(Clone)]
struct CaptureWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl CaptureWriter {
    fn new() -> Self {
        Self {
            buf: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn contents(&self) -> String {
        let buf = self.buf.lock().unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }
}

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn test_logging_does_not_expose_plaintext_canary() {
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;

    let capture = CaptureWriter::new();
    let capture_clone = capture.clone();

    // Install a scoped subscriber that captures all output.
    // Uses set_default so it applies only to this thread.
    let subscriber = fmt::layer()
        .with_writer(capture_clone)
        .with_ansi(false)
        .with_level(true)
        .with_target(true);

    let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(subscriber));

    let canary = "CANARY_SECRET_xK9mQ2";

    // --- Run the encrypted group lifecycle ---

    // 1. Create group
    let alice = test_identity();
    let alice_id = agent_of(&alice);
    let group_id_bytes = b"logging-test-group".to_vec();
    let mut alice_group = MlsGroup::new(group_id_bytes.clone(), alice_id).unwrap();

    // 2. Invite bob
    let bob = test_identity();
    let bob_id = agent_of(&bob);
    let _commit = alice_group.add_member(bob_id).unwrap();
    let welcome = MlsWelcome::create(&alice_group, &bob_id).unwrap();

    // 3. Bob accepts
    let bob_group = MlsGroup::from_welcome(&welcome, bob_id).unwrap();

    // 4. Alice creates a delta with the canary in the task title
    let timestamp = 5000u64;
    let task_id = TaskId::new(canary, &alice_id, timestamp);
    let peer_id = saorsa_gossip_types::PeerId::new(*alice_id.as_bytes());
    let metadata = TaskMetadata::new(canary, "secret description too", 128, alice_id, timestamp);
    let task = TaskItem::new(task_id, metadata, peer_id);
    let mut delta = TaskListDelta::new(1);
    delta.added_tasks.insert(task_id, (task, (peer_id, 1)));

    // 5. Alice encrypts
    let encrypted = EncryptedTaskListDelta::encrypt_with_group(&delta, &alice_group, 0).unwrap();

    // 6. Bob decrypts
    let decrypted = encrypted.decrypt_with_group(&bob_group).unwrap();
    assert_eq!(decrypted.added_tasks.len(), 1);

    // 7. Trigger a decryption failure path (wrong group)
    let eve = test_identity();
    let eve_id = agent_of(&eve);
    let eve_group = MlsGroup::new(b"eve-logging-group".to_vec(), eve_id).unwrap();
    let _ = encrypted.decrypt_with_group(&eve_group); // Expected to fail

    // --- Check captured logs ---
    let logs = capture.contents();
    assert!(
        !logs.contains(canary),
        "plaintext canary '{}' found in tracing output:\n{}",
        canary,
        logs
    );
}
