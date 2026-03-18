//! Private group demo — two agents creating an encrypted collaboration.
//!
//! Run with: cargo run --example private_group_demo --all-features

use x0x::crdt::{EncryptedTaskListDelta, TaskId, TaskItem, TaskListDelta, TaskMetadata};
use x0x::identity::{AgentKeypair, Identity};
use x0x::mls::{MlsGroup, MlsWelcome};
use x0x::types::GroupId;

use saorsa_gossip_types::PeerId;

fn main() {
    println!("=== x0x Private Group Demo ===\n");

    // Step 1: Generate identities
    println!("1. Generating identities...");
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let alice_id = alice_identity.agent_id();
    let bob_id = bob_identity.agent_id();
    println!("   Alice: {}", alice_id);
    println!("   Bob:   {}", bob_id);

    // Step 2: Alice creates a group
    println!("\n2. Alice creates a private group...");
    let group_id_bytes = b"demo-private-group".to_vec();
    let mut alice_group = MlsGroup::new(group_id_bytes.clone(), alice_id).expect("create group");
    let group_id = GroupId::from_mls_group_id(&group_id_bytes);
    println!("   Group: {}", group_id);
    println!("   Members: {} (Alice only)", alice_group.members().len());

    // Step 3: Alice invites Bob
    println!("\n3. Alice invites Bob...");
    let _commit = alice_group.add_member(bob_id).expect("add bob");
    let welcome = MlsWelcome::create(&alice_group, &bob_id).expect("create welcome");
    println!("   Welcome created for Bob");
    println!("   Welcome epoch: {}", welcome.epoch());

    // Step 4: Bob accepts the invite
    println!("\n4. Bob accepts the invite...");
    let bob_group = MlsGroup::from_welcome(&welcome, bob_id).expect("bob joins");
    println!(
        "   Bob joined group: {}",
        GroupId::from_mls_group_id(bob_group.group_id())
    );
    println!(
        "   Bob sees {} member(s) (himself)",
        bob_group.members().len()
    );

    // Step 5: Alice encrypts a task list delta
    println!("\n5. Alice encrypts a task delta...");
    let peer_id = PeerId::new(*alice_id.as_bytes());
    let task_id = TaskId::new("Review PR #26", &alice_id, 1000);
    let metadata = TaskMetadata::new(
        "Review PR #26",
        "Review the MLS private groups implementation",
        128,
        alice_id,
        1000,
    );
    let task = TaskItem::new(task_id, metadata, peer_id);

    let mut delta = TaskListDelta::new(1);
    delta.added_tasks.insert(task_id, (task, (peer_id, 1)));

    // Alice encrypts at the current epoch of her group view.
    // After add_member, Alice's group is at epoch 1.
    // Bob's group (from welcome) is at the pre-add epoch (epoch 1 from the
    // welcome which was created after the add_member commit).
    // Both must be at the same epoch for decrypt_with_group to succeed.
    let encrypted =
        EncryptedTaskListDelta::encrypt_with_group(&delta, &alice_group, 0).expect("encrypt delta");
    println!(
        "   Encrypted {} bytes of ciphertext",
        encrypted.ciphertext().len()
    );
    println!(
        "   Epoch: {}, Counter: {}",
        encrypted.epoch(),
        encrypted.counter()
    );

    // Step 6: Bob decrypts it
    println!("\n6. Bob decrypts the delta...");
    let decrypted = encrypted
        .decrypt_with_group(&bob_group)
        .expect("bob decrypt");
    println!("   Decrypted {} task(s)", decrypted.added_tasks.len());
    for (task, _tag) in decrypted.added_tasks.values() {
        println!("   - {}", task.title());
    }

    // Step 7: Verify non-member can't decrypt
    println!("\n7. Verifying non-member cannot decrypt...");
    let eve_kp = AgentKeypair::generate().expect("eve keypair");
    let eve_id = eve_kp.agent_id();
    let eve_group = MlsGroup::new(b"different-group".to_vec(), eve_id).expect("eve group");
    match encrypted.decrypt_with_group(&eve_group) {
        Err(e) => println!("   Eve's decryption failed as expected: {}", e),
        Ok(_) => println!("   ERROR: Eve decrypted successfully!"),
    }

    println!("\n=== Demo complete! ===");
}
