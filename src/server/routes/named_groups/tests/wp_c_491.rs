// #491: production-seam regressions for the WP-C fixes (#482/#483/#484).
// Deterministic, no networking. The shared secure_endpoint_test_state fixture
// calls Agent::builder().build() without network config (no socket bind).
//
// Root review r2 corrections:
// - The self-leave convergence test is REMOVED — the production apply path
//   requires a signed commit plus potentially TreeKEM crypto state; without
//   full setup an implementation that rejects every self-leave passes.
//   The convergence acceptance is explicitly retained as missing and
//   documented in review-artifacts/491-runtime-plan.md (RT-1).
// - The fan-out is split into TWO tests: one for the actor-exception
//   contract (actor IS the first candidate) and one for the DISTINCT
//   actor≠target case (target excluded, eligible recipient positive).
//   Throttle entries record scheduling decisions, not completed delivery.
#![cfg(test)]

use crate::server::routes::named_groups::tests::secure_endpoint_test_state;

/// Valid 64-hex-char agent id (32 bytes).
fn agent_hex(seed: u8) -> String {
    format!("{:02x}", seed).repeat(32)
}

// ── #482: adopt_roster_revision clamp (pure function) ──

/// Poison-negative: a u64::MAX roster revision on any membership event
/// advances the local clock by at most one step — no saturation, no wrap.
#[test]
fn n491_u64_max_roster_revision_is_clamped() {
    let f = crate::server::routes::named_groups::adopt_roster_revision;
    assert_eq!(f(5, u64::MAX), 6, "u64::MAX clamps to local+1");
    assert_eq!(f(u64::MAX - 1, u64::MAX), u64::MAX, "saturates at top");
    assert_eq!(f(u64::MAX, u64::MAX), u64::MAX, "no wrapping");
    assert_eq!(f(3, 4), 4, "legitimate +1 passes through");
    assert_eq!(f(5, 3), 5, "already-applied revision is a no-op (max)");
}

// ── #482: catch-up fan-out — scheduling observations via throttle map ──
// NOTE: a throttle entry records a scheduling decision, not completed
// transport delivery. These tests prove the candidate-set filter, not
// the network send.

/// ACTOR-EXCEPTION CONTRACT: in a self-leave (actor == target), the actor
/// is deliberately included as a catch-up candidate (they may
/// still be reachable and hold the missing events). This is by design,
/// not an exclusion failure.
#[tokio::test]
async fn n491_fanout_self_leave_actor_is_scheduled() {
    let (state, _dir) = secure_endpoint_test_state().await.unwrap();
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let leaver_hex = agent_hex(0xbb);
    let other_hex = agent_hex(0xcc);
    let group_id = "dd49".repeat(8);

    let mut group = crate::groups::GroupInfo::new(
        "g".to_string(),
        String::new(),
        crate::identity::AgentId([1; 32]),
        group_id.clone(),
    );
    group.secure_plane = crate::mls::SecureGroupPlane::TreeKem;
    group.state_revision = 4;
    group.state_hash = "h4".to_string();
    group.roster_revision = 4;
    for h in [&local_hex, &leaver_hex, &other_hex] {
        group.members_v2.insert(
            h.clone(),
            crate::groups::GroupMember::new_admin(h.clone(), None, 1),
        );
    }
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), group);

    // Self-leave: actor == agent_id (the leaver removes itself).
    let commit = crate::groups::state_commit::GroupStateCommit {
        group_id: group_id.clone(),
        revision: 6,
        committed_at: 1,
        committed_by: leaver_hex.clone(),
        prev_state_hash: Some("h5".to_string()),
        roster_root: String::new(),
        policy_hash: String::new(),
        public_meta_hash: String::new(),
        security_binding: None,
        state_hash: String::new(),
        withdrawn: false,
        signer_public_key: String::new(),
        signature: String::new(),
    };
    let event = crate::server::routes::named_groups::NamedGroupMetadataEvent::MemberRemoved {
        group_id: group_id.clone(),
        revision: 6,
        actor: leaver_hex.clone(),
        agent_id: leaver_hex.clone(),
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    };
    crate::server::routes::named_groups::request_treekem_catchup_for_gap(
        &state,
        &group_id,
        &event,
        state.agent.agent_id(), // sender is the local agent processing it
    )
    .await;

    let throttle = state.treekem_catchup_throttle.read().await;
    let keys: Vec<&String> = throttle.keys().collect();

    // The actor/leaver IS scheduled (scheduled by design).
    assert!(
        keys.iter().any(|k| k.contains(&leaver_hex)),
        "self-leave actor IS scheduled; keys: {keys:?}"
    );
    // The OTHER member IS scheduled (redundancy fan-out).
    assert!(
        keys.iter().any(|k| k.contains(&other_hex)),
        "other member IS scheduled (redundancy); keys: {keys:?}"
    );
    // The LOCAL agent is NOT scheduled (never self-dial).
    assert!(
        !keys.iter().any(|k| k.contains(&local_hex)),
        "local agent NOT scheduled (never self-dial); keys: {keys:?}"
    );
}

/// DISTINCT actor≠target case: when an ADMIN removes a DIFFERENT member,
/// the removed TARGET is excluded from the fan-out while the admin (actor)
/// and other eligible members are scheduled.
#[tokio::test]
async fn n491_fanout_admin_removes_target_excludes_target() {
    let (state, _dir) = secure_endpoint_test_state().await.unwrap();
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let admin_hex = agent_hex(0xaa); // the actor (admin doing the removal)
    let target_hex = agent_hex(0xbb); // the member being removed
    let other_hex = agent_hex(0xcc); // an unrelated eligible member
    let group_id = "ee49".repeat(8);

    let mut group = crate::groups::GroupInfo::new(
        "g".to_string(),
        String::new(),
        crate::identity::AgentId([1; 32]),
        group_id.clone(),
    );
    group.secure_plane = crate::mls::SecureGroupPlane::TreeKem;
    group.state_revision = 4;
    group.state_hash = "h4".to_string();
    group.roster_revision = 4;
    for h in [&local_hex, &admin_hex, &target_hex, &other_hex] {
        group.members_v2.insert(
            h.clone(),
            crate::groups::GroupMember::new_admin(h.clone(), None, 1),
        );
    }
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), group);

    // Admin removes the target (actor ≠ target).
    let commit = crate::groups::state_commit::GroupStateCommit {
        group_id: group_id.clone(),
        revision: 6,
        committed_at: 1,
        committed_by: admin_hex.clone(),
        prev_state_hash: Some("h5".to_string()),
        roster_root: String::new(),
        policy_hash: String::new(),
        public_meta_hash: String::new(),
        security_binding: None,
        state_hash: String::new(),
        withdrawn: false,
        signer_public_key: String::new(),
        signature: String::new(),
    };
    let event = crate::server::routes::named_groups::NamedGroupMetadataEvent::MemberRemoved {
        group_id: group_id.clone(),
        revision: 6,
        actor: admin_hex.clone(),
        agent_id: target_hex.clone(), // TARGET ≠ actor
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    };
    crate::server::routes::named_groups::request_treekem_catchup_for_gap(
        &state,
        &group_id,
        &event,
        state.agent.agent_id(), // sender is the local agent
    )
    .await;

    let throttle = state.treekem_catchup_throttle.read().await;
    let keys: Vec<&String> = throttle.keys().collect();

    // POSITIVE: the admin (actor) IS scheduled.
    assert!(
        keys.iter().any(|k| k.contains(&admin_hex)),
        "admin/actor IS scheduled; keys: {keys:?}"
    );
    // POSITIVE: the other eligible member IS scheduled.
    assert!(
        keys.iter().any(|k| k.contains(&other_hex)),
        "other eligible member IS scheduled; keys: {keys:?}"
    );
    // NEGATIVE: the removed TARGET is NOT scheduled.
    assert!(
        !keys.iter().any(|k| k.contains(&target_hex)),
        "removed target NOT scheduled (excluded from fan-out); keys: {keys:?}"
    );
    // NEGATIVE: local agent NOT scheduled.
    assert!(
        !keys.iter().any(|k| k.contains(&local_hex)),
        "local agent NOT scheduled; keys: {keys:?}"
    );
}

// ── #483: restart hydration — durable blob cache resolves digest-only seats ──

/// After a "restart" (discovery map empty, blob cache populated), the
/// cert-digest scan finds the blob and the binding rules hold.
/// NOTE: this is an in-process cache operation, not a process restart —
/// the disk-persistence half is a runtime-only case (RT-3).
#[tokio::test]
async fn n491_blob_cache_resolves_by_cert_digest() {
    let (state, _dir) = secure_endpoint_test_state().await.unwrap();

    // Issue a real cert so we have bytes with a real digest.
    let user_kp = crate::identity::UserKeypair::generate().unwrap();
    let agent_kp = state.agent.identity().agent_keypair();
    let cert = crate::identity::AgentCertificate::issue(&user_kp, agent_kp).unwrap();
    let agent_id = cert.agent_id().unwrap();

    // Compute the roster digest (owner_cert::certificate_digest_hex).
    let digest_hex = crate::groups::owner_cert::certificate_digest_hex(&cert);
    let digest_bytes: [u8; 32] = hex::decode(&digest_hex).unwrap().try_into().unwrap();

    // Populate the durable blob cache (the fetched-blob shape).
    let blob = crate::announce_blob::CachedBlob {
        digest: digest_bytes,
        payload_version: 1,
        user_id: cert.user_id().ok(),
        agent_certificate: Some(cert.clone()),
        fetched_at_unix: 1,
    };
    state.agent.announce_blob_cache.insert_verified(blob).await;

    // The identity-discovery map is EMPTY (fresh state — the restart shape).
    let found = state
        .agent
        .announce_blob_cache
        .find_by_cert_digest(&digest_bytes)
        .await
        .expect("blob found by cert digest");
    assert_eq!(
        found
            .agent_certificate
            .as_ref()
            .unwrap()
            .agent_id()
            .unwrap(),
        agent_id
    );
    assert_eq!(found.user_id, cert.user_id().ok());

    // Negative: a wrong digest finds nothing.
    let wrong = [0u8; 32];
    assert!(
        state
            .agent
            .announce_blob_cache
            .find_by_cert_digest(&wrong)
            .await
            .is_none(),
        "wrong digest → no match"
    );
}
