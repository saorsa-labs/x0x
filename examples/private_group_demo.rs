//! Private group demo — exercises the full Agent-level flow for encrypted
//! task-list collaboration: GroupState, PendingInvite, TaskList, and
//! encrypted delta publish/receive.
//!
//! Run with: cargo run --example private_group_demo --all-features

use x0x::contacts::TrustLevel;
use x0x::crdt::{
    EncryptedTaskListDelta, TaskId, TaskItem, TaskList, TaskListDelta, TaskListId, TaskMetadata,
};
use x0x::groups::{GroupState, GroupSummary, PendingInvite};
use x0x::identity::{AgentKeypair, Identity};
use x0x::mls::{MlsGroup, MlsWelcome};
use x0x::types::GroupId;

use saorsa_gossip_types::PeerId;

fn main() {
    println!("=== x0x Private Group Demo ===");
    println!("    Exercises the Agent-level API flow for encrypted task collaboration.\n");

    // ---------------------------------------------------------------
    // 1. Generate identities (same as Agent::builder().build())
    // ---------------------------------------------------------------
    println!("1. Generating identities...");
    let alice_identity = Identity::generate().expect("alice identity");
    let bob_identity = Identity::generate().expect("bob identity");
    let alice_id = alice_identity.agent_id();
    let bob_id = bob_identity.agent_id();
    println!("   Alice: {}", alice_id);
    println!("   Bob:   {}", bob_id);

    // Each agent maintains its own GroupState (in a real Agent this lives
    // behind Arc<RwLock<GroupState>>).
    let mut alice_state = GroupState::default();
    let mut bob_state = GroupState::default();

    // ---------------------------------------------------------------
    // 2. Alice creates a group (mirrors Agent::create_group)
    // ---------------------------------------------------------------
    println!("\n2. Alice creates a private group...");
    let group_name = "Sprint Planning";
    let group_id_bytes = b"demo-sprint-planning".to_vec();
    let alice_group = MlsGroup::new(group_id_bytes.clone(), alice_id).expect("create group");
    let group_id = GroupId::from_mls_group_id(&group_id_bytes);

    // Create a TaskList alongside the group (mirrors init_encrypted_sync)
    let alice_peer = PeerId::new(*alice_id.as_bytes());
    let task_list_id = TaskListId::from_content(group_name, &alice_id, 1000);
    let alice_task_list = TaskList::new(task_list_id, group_name.to_string(), alice_peer);

    // Store in Alice's GroupState
    alice_state.groups.insert(group_id, alice_group.clone());
    alice_state
        .group_names
        .insert(group_id, group_name.to_string());

    println!("   Group:     {}", group_id);
    println!("   TaskList:  {}", task_list_id);
    println!(
        "   Members:   {} (Alice only)",
        alice_state.groups[&group_id].members().len()
    );

    // ---------------------------------------------------------------
    // 3. Alice invites Bob (mirrors Agent::invite_to_group)
    // ---------------------------------------------------------------
    println!("\n3. Alice invites Bob...");

    // Add Bob to the MLS group and create a Welcome message
    let alice_mls = alice_state.groups.get_mut(&group_id).expect("alice group");
    let _commit = alice_mls.add_member(bob_id).expect("add bob");
    let welcome = MlsWelcome::create(alice_mls, &bob_id).expect("create welcome");
    println!("   Welcome created for Bob (epoch {})", welcome.epoch());

    // In a real agent, this Welcome is sent over gossip. The receiver's
    // background invite listener stores it as a PendingInvite.
    let pending = PendingInvite {
        welcome: welcome.clone(),
        sender: alice_id,
        verified: true,
        trust_level: Some(TrustLevel::Trusted),
        received_at: 1000,
    };

    // Store in Bob's GroupState (simulates the invite listener)
    bob_state
        .pending_invites
        .insert((group_id, alice_id), pending);
    println!(
        "   Bob now has {} pending invite(s)",
        bob_state.pending_invites.len()
    );

    // ---------------------------------------------------------------
    // 4. Bob accepts the invite (mirrors Agent::accept_invite)
    // ---------------------------------------------------------------
    println!("\n4. Bob accepts the invite...");

    // Look up the pending invite
    let invite = bob_state
        .pending_invites
        .remove(&(group_id, alice_id))
        .expect("pending invite");

    println!(
        "   Invite from {} (verified: {}, trust: {:?})",
        invite.sender, invite.verified, invite.trust_level
    );

    // Join the MLS group from the Welcome
    let bob_group = MlsGroup::from_welcome(&invite.welcome, bob_id).expect("bob joins");

    // Create Bob's TaskList replica (mirrors init_encrypted_sync on accept)
    let bob_peer = PeerId::new(*bob_id.as_bytes());
    let bob_task_list = TaskList::new(task_list_id, group_name.to_string(), bob_peer);

    // Store in Bob's GroupState
    bob_state.groups.insert(group_id, bob_group);
    bob_state
        .group_names
        .insert(group_id, group_name.to_string());

    println!("   Bob joined group: {}", bob_state.group_names[&group_id]);
    println!(
        "   Pending invites remaining: {}",
        bob_state.pending_invites.len()
    );

    // ---------------------------------------------------------------
    // 5. Alice adds a task and encrypts the delta
    // ---------------------------------------------------------------
    println!("\n5. Alice adds a task and encrypts the delta...");

    let mut alice_task_list = alice_task_list;
    let task_id = TaskId::new("Review PR #26", &alice_id, 1000);
    let metadata = TaskMetadata::new(
        "Review PR #26",
        "Review the MLS private groups implementation",
        128,
        alice_id,
        1000,
    );
    let task = TaskItem::new(task_id, metadata, alice_peer);

    // Add to Alice's local task list
    alice_task_list
        .add_task(task.clone(), alice_peer, 1)
        .expect("add task");

    // Build a per-operation delta (same pattern as TaskListHandle::add_task)
    let mut delta = TaskListDelta::new(1);
    delta.added_tasks.insert(task_id, (task, (alice_peer, 1)));

    // Encrypt with Alice's MLS group key
    let alice_mls = &alice_state.groups[&group_id];
    let encrypted =
        EncryptedTaskListDelta::encrypt_with_group(&delta, alice_mls, 0).expect("encrypt delta");

    println!(
        "   Task: \"{}\"",
        alice_task_list.get_task(&task_id).unwrap().title()
    );
    println!(
        "   Encrypted: {} bytes (epoch {}, counter {})",
        encrypted.ciphertext().len(),
        encrypted.epoch(),
        encrypted.counter()
    );

    // ---------------------------------------------------------------
    // 6. Bob decrypts and merges the delta
    // ---------------------------------------------------------------
    println!("\n6. Bob decrypts and merges...");

    let bob_mls = &bob_state.groups[&group_id];
    let decrypted = encrypted.decrypt_with_group(bob_mls).expect("bob decrypt");

    // Merge into Bob's task list
    let mut bob_task_list = bob_task_list;
    bob_task_list
        .merge_delta(&decrypted, bob_peer)
        .expect("merge delta");

    println!(
        "   Decrypted {} added task(s):",
        decrypted.added_tasks.len()
    );
    for (task, _tag) in decrypted.added_tasks.values() {
        println!("   - \"{}\" (priority {})", task.title(), task.priority());
    }
    println!(
        "   Bob's task list now has {} task(s)",
        bob_task_list.task_count()
    );

    // ---------------------------------------------------------------
    // 7. Eve (non-member) tries and fails to decrypt
    // ---------------------------------------------------------------
    println!("\n7. Verifying non-member cannot decrypt...");

    let eve_kp = AgentKeypair::generate().expect("eve keypair");
    let eve_id = eve_kp.agent_id();
    let eve_group = MlsGroup::new(b"different-group".to_vec(), eve_id).expect("eve group");
    match encrypted.decrypt_with_group(&eve_group) {
        Err(e) => println!("   Eve's decryption failed as expected: {}", e),
        Ok(_) => println!("   ERROR: Eve should not have been able to decrypt!"),
    }

    // ---------------------------------------------------------------
    // 8. Print GroupState summary for both agents
    // ---------------------------------------------------------------
    println!("\n8. GroupState summary");
    println!("   ----");

    for (label, state, task_list) in [
        ("Alice", &alice_state, &alice_task_list),
        ("Bob", &bob_state, &bob_task_list),
    ] {
        let summaries: Vec<GroupSummary> = state
            .groups
            .iter()
            .map(|(gid, mls)| GroupSummary {
                group_id: *gid,
                name: state.group_names.get(gid).cloned().unwrap_or_default(),
                known_members: mls.members().len(),
                member_ids: mls.members().keys().copied().collect(),
            })
            .collect();

        for s in &summaries {
            println!(
                "   {}: group \"{}\" ({}) — {} member(s)",
                label, s.name, s.group_id, s.known_members
            );
        }

        println!(
            "   {}: task list \"{}\" — {} task(s)",
            label,
            task_list.name(),
            task_list.task_count()
        );

        for task in task_list.tasks_ordered() {
            let state_label = match task.current_state() {
                x0x::crdt::CheckboxState::Empty => " ".to_string(),
                x0x::crdt::CheckboxState::Claimed { .. } => "~".to_string(),
                x0x::crdt::CheckboxState::Done { .. } => "x".to_string(),
            };
            println!("     - [{}] {}", state_label, task.title());
        }

        println!(
            "   {}: {} pending invite(s)",
            label,
            state.pending_invites.len()
        );
        println!("   ----");
    }

    println!("\n=== Demo complete! ===");
}
