// WP-C targeted tests (#482 #483 #484 #487). Production-path tests only;
// run via: X0X_HOME=<tmp> cargo nextest run -p x0x --lib wp_c_
#![cfg(test)]

use super::super::*;

/// #482: a state-adjacent, hash-linked membership event whose roster clock
/// runs ahead must NOT be queued — the signed state commit is the
/// authoritative chain and the apply path reconciles the roster clock with
/// `max`. Queueing on roster-ahead alone is what wedged the verified
/// self-leave forever.
#[tokio::test]
async fn wp_c_482_roster_ahead_state_adjacent_is_not_queued() {
    let mut info = crate::groups::GroupInfo::new(
        "g".to_string(),
        String::new(),
        crate::identity::AgentId([1; 32]),
        "ab".repeat(16),
    );
    info.secure_plane = crate::mls::SecureGroupPlane::TreeKem;
    info.state_revision = 6;
    info.state_hash = "hash-6".to_string();
    info.roster_revision = 2;
    // The event's commit is EXACTLY adjacent (rev 7 linking hash-6) but its
    // roster revision is 9 (leaver-local numbering) — 9 > 2+1.
    let commit = crate::groups::state_commit::GroupStateCommit {
        revision: 7,
        prev_state_hash: Some("hash-6".to_string()),
        ..sample_commit()
    };
    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: "g".to_string(),
        revision: 9,
        actor: "cd".repeat(32),
        agent_id: "cd".repeat(32),
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    };
    let reason = treekem_state_frontier_gap_reason(&info, &event, "ef".repeat(32).as_str(), None);
    assert!(
        reason.is_none(),
        "state-adjacent hash-linked event must apply despite roster-ahead; got {reason:?}"
    );
}

/// #482: a STATE-chain gap still queues (the security property is
/// unchanged — events from a divergent/future chain are not applied).
#[tokio::test]
async fn wp_c_482_state_chain_gap_still_queues() {
    let mut info = crate::groups::GroupInfo::new(
        "g".to_string(),
        String::new(),
        crate::identity::AgentId([1; 32]),
        "ab".repeat(16),
    );
    info.secure_plane = crate::mls::SecureGroupPlane::TreeKem;
    info.state_revision = 4;
    info.state_hash = "hash-4".to_string();
    info.roster_revision = 4;
    let commit = crate::groups::state_commit::GroupStateCommit {
        revision: 9,
        prev_state_hash: Some("hash-8".to_string()),
        ..sample_commit()
    };
    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: "g".to_string(),
        revision: 9,
        actor: "cd".repeat(32),
        agent_id: "cd".repeat(32),
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    };
    let reason = treekem_state_frontier_gap_reason(&info, &event, "ef".repeat(32).as_str(), None);
    assert_eq!(reason.as_deref(), Some("revision_gap"));
}

/// #482: a hash mismatch on an adjacent commit still queues as
/// `state_hash_gap` (chain integrity gate unchanged).
#[tokio::test]
async fn wp_c_482_hash_gap_still_queues() {
    let mut info = crate::groups::GroupInfo::new(
        "g".to_string(),
        String::new(),
        crate::identity::AgentId([1; 32]),
        "ab".repeat(16),
    );
    info.secure_plane = crate::mls::SecureGroupPlane::TreeKem;
    info.state_revision = 6;
    info.state_hash = "hash-6".to_string();
    info.roster_revision = 6;
    let commit = crate::groups::state_commit::GroupStateCommit {
        revision: 7,
        prev_state_hash: Some("DIFFERENT".to_string()),
        ..sample_commit()
    };
    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: "g".to_string(),
        revision: 7,
        actor: "cd".repeat(32),
        agent_id: "cd".repeat(32),
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    };
    let reason = treekem_state_frontier_gap_reason(&info, &event, "ef".repeat(32).as_str(), None);
    assert_eq!(reason.as_deref(), Some("state_hash_gap"));
}

#[tokio::test]
async fn wp_c_482_counter_increments_on_queue() {
    let diag = crate::groups::GroupsDiagnostics::new();
    diag.record_membership_event_queued_revision_gap("g1");
    diag.record_membership_event_queued_revision_gap("g1");
    let snapshot = diag.snapshot(
        &std::collections::HashMap::new(),
        &std::collections::HashSet::new(),
        &std::collections::HashSet::new(),
        &std::collections::HashMap::new(),
    );
    let row = snapshot
        .groups
        .iter()
        .find(|r| r.group_id == "g1")
        .expect("row");
    assert_eq!(row.counters.membership_events_queued_revision_gap, 2);
}

fn sample_commit() -> crate::groups::state_commit::GroupStateCommit {
    crate::groups::state_commit::GroupStateCommit {
        group_id: "g".to_string(),
        revision: 1,
        committed_at: 1,
        committed_by: "02".repeat(32),
        prev_state_hash: None,
        roster_root: String::new(),
        policy_hash: String::new(),
        public_meta_hash: String::new(),
        security_binding: None,
        state_hash: String::new(),
        withdrawn: false,
        signer_public_key: String::new(),
        signature: String::new(),
    }
}

#[test]
fn wp_c_484_v4_mapped_normalizes() {
    let mapped: std::net::SocketAddr = "[::ffff:192.168.1.4]:51820".parse().unwrap();
    let normalized = crate::network::normalize_v4_mapped_addr(mapped);
    assert_eq!(normalized.to_string(), "192.168.1.4:51820");
    // Non-mapped IPv6 stays untouched.
    let native: std::net::SocketAddr = "[fe80::1]:51820".parse().unwrap();
    assert_eq!(crate::network::normalize_v4_mapped_addr(native), native);
}

#[tokio::test]
async fn wp_c_487_find_home_ignores_pending_stub() {
    // An OWNED state (user key) — find_home needs the owner id.
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    let user = crate::identity::UserKeypair::from_seed(&[0x48; 32]).unwrap();
    let agent = std::sync::Arc::new(
        crate::Agent::builder()
            .with_machine_key(data.join("machine.key"))
            .with_agent_key_path(data.join("agent.key"))
            .with_agent_cert_path(data.join("agent.cert"))
            .with_user_key(user)
            .with_peer_cache_disabled()
            .with_contact_store_path(data.join("contacts.json"))
            .build()
            .await
            .unwrap(),
    );
    let state = tests::secure_endpoint_test_state_at(data, agent)
        .await
        .unwrap();
    let owner = state.agent.identity().user_keypair().unwrap().user_id();
    let mut stub = crate::groups::GroupInfo::with_policy(
        "Home".to_string(),
        String::new(),
        crate::identity::AgentId([7; 32]),
        "cd".repeat(16),
        crate::server::routes::home::home_policy(&owner),
    );
    stub.home = Some(crate::groups::HomeMetadata {
        primary_agent: hex::encode(state.agent.agent_id().as_bytes()),
        placements: Default::default(),
        provisioned_at_ms: 1,
    });
    stub.members_v2.insert(
        hex::encode(state.agent.agent_id().as_bytes()),
        crate::groups::GroupMember::new_admin(
            hex::encode(state.agent.agent_id().as_bytes()),
            None,
            1,
        ),
    );
    let stub_id = "ee".repeat(16);
    state
        .named_groups
        .write()
        .await
        .insert(stub_id.to_string(), stub.clone());
    state
        .pending_join_stubs
        .lock()
        .unwrap()
        .insert(stub_id.to_string());

    assert!(
        crate::server::routes::home::find_home(&state, &owner)
            .await
            .is_none(),
        "a pending (memory-only) join stub must not be found as the Home"
    );

    // Mark it durable (not pending): found again.
    state.pending_join_stubs.lock().unwrap().remove(&stub_id);
    let found = crate::server::routes::home::find_home(&state, &owner).await;
    assert!(found.is_some(), "a durable Home-shaped seat is found");
    assert_eq!(found.unwrap().0, stub_id);
}
