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

/// #492 item 1: the mixed-version roster-clock convergence waiver extends
/// to ALL adjacent, hash-linked events, not just self-leave. A surviving
/// legacy member emitting an adjacent non-self commit with a high roster
/// clock must be admitted at first delivery instead of paying a deferral
/// plus a catch-up round trip whose recovery (replay on an admitted
/// catch-up response) is conditional on TTL/cap and a live responder.
#[tokio::test]
async fn wp_c_492_non_self_leave_roster_ahead_is_not_queued() {
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
    // roster revision is 9 (higher than 2+1).
    let commit = crate::groups::state_commit::GroupStateCommit {
        revision: 7,
        prev_state_hash: Some("hash-6".to_string()),
        ..sample_commit()
    };
    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: "g".to_string(),
        revision: 9,
        actor: "cd".repeat(32),
        agent_id: "ef".repeat(32), // DIFFERENT FROM ACTOR -> non-self-leave
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    };
    let reason = treekem_state_frontier_gap_reason(&info, &event, "aa".repeat(32).as_str(), None);
    assert!(
        reason.is_none(),
        "non-self-leave state-adjacent hash-linked event must apply despite roster-ahead; got {reason:?}"
    );
}

/// #492 counter-only negative control: the widened waiver must NOT also
/// waive the hash link for the event kinds it newly admits. A NON-self
/// MemberRemoved whose commit revision is exactly adjacent but whose
/// prev_state_hash does not link to our chain must still queue as
/// `state_hash_gap` — the signed state chain, not the roster counter, is
/// the admission authority. The existing #482 hash-gap control covers
/// only the self-leave shape; without this control nothing proves the
/// waiver is counter-only for non-self events.
#[tokio::test]
async fn wp_c_492_non_self_leave_hash_gap_still_queues() {
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
    // Revision is EXACTLY adjacent, but the commit links to a DIFFERENT
    // chain than ours (hash-5, not our hash-6).
    let commit = crate::groups::state_commit::GroupStateCommit {
        revision: 7,
        prev_state_hash: Some("hash-5".to_string()),
        ..sample_commit()
    };
    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: "g".to_string(),
        revision: 9,
        actor: "cd".repeat(32),
        agent_id: "ef".repeat(32), // DIFFERENT FROM ACTOR -> non-self-leave
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    };
    let reason = treekem_state_frontier_gap_reason(&info, &event, "aa".repeat(32).as_str(), None);
    assert_eq!(
        reason.as_deref(),
        Some("state_hash_gap"),
        "non-self events with a counter match but a broken hash link must still queue"
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

/// #491 negative control (the #492 poison shape): `roster_revision` is
/// NOT committed by the signed state hash, so the apply path must adopt
/// an incoming event revision through the +1 CLAMP — a `u64::MAX`
/// roster revision advances the local clock by exactly one, never
/// saturates it, and replayed catch-up (revision ≤ local) never regresses.
#[test]
fn wp_c_491_roster_clock_poison_is_clamped_to_plus_one() {
    assert_eq!(adopt_roster_revision(5, u64::MAX), 6);
    assert_eq!(adopt_roster_revision(5, 9), 6);
    assert_eq!(adopt_roster_revision(5, 6), 6);
    assert_eq!(adopt_roster_revision(5, 5), 5);
    assert_eq!(adopt_roster_revision(5, 0), 5);
    assert_eq!(adopt_roster_revision(u64::MAX, u64::MAX), u64::MAX);
}

/// #491 poison-negative: a self-leave whose roster revision is `u64::MAX`
/// but whose commit is exactly adjacent and hash-linked must not be queued
/// forever — it applies, and the clamp above bounds the clock advance to 1.
/// Pre-#482 this exact shape wedged the owner (HS-E1 defect D4): the event
/// was re-delivered and queued `revision_gap` forever with no convergence.
#[test]
fn wp_c_491_u64_max_self_leave_is_not_queued_forever() {
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
    let commit = crate::groups::state_commit::GroupStateCommit {
        revision: 7,
        prev_state_hash: Some("hash-6".to_string()),
        ..sample_commit()
    };
    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: "g".to_string(),
        revision: u64::MAX,
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
        "poison u64::MAX self-leave on an adjacent hash-linked commit must apply \
         (clock advance bounded by adopt_roster_revision); got {reason:?}"
    );
    // And the adoption side of the same contract: exactly +1.
    assert_eq!(adopt_roster_revision(info.roster_revision, u64::MAX), 3);
}

/// Shared #491 fixture: the local daemon is the owner's certified primary
/// (user key + builder-issued cert), holding an OwnerCertified group whose
/// SECOND admin seat is certificate-pending (digest-only, inside its grace
/// window) — the exact roster shape that makes a self-leave seal refuse
/// with `OwnerCertMemberPending`. `treekem` selects the leave plane arm.
async fn wp_c_491_owner_state_with_pending_member(
    group_id: &str,
    treekem: bool,
) -> Result<(std::sync::Arc<crate::server::AppState>, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let data = dir.path();
    let seed = [0x49u8; 32];
    let user = crate::identity::UserKeypair::from_seed(&seed)?;
    let agent = std::sync::Arc::new(
        crate::Agent::builder()
            .with_machine_key(data.join("machine.key"))
            .with_agent_key(crate::identity::AgentKeypair::generate()?)
            .with_agent_cert_path(data.join("agent.cert"))
            .with_user_key(user)
            .with_peer_cache_disabled()
            .with_contact_store_path(data.join("contacts.json"))
            .build()
            .await?,
    );
    let state = tests::secure_endpoint_test_state_at(data, agent).await?;
    let owner_user = state
        .agent
        .identity()
        .user_keypair()
        .expect("owner user keypair")
        .user_id();
    let mut info = crate::groups::GroupInfo::with_policy(
        "wp-c-491".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.to_string(),
        crate::groups::GroupPolicy {
            discoverability: crate::groups::GroupDiscoverability::Hidden,
            admission: crate::groups::GroupAdmission::OwnerCertified(owner_user),
            confidentiality: crate::groups::GroupConfidentiality::MlsEncrypted,
            read_access: crate::groups::GroupReadAccess::MembersOnly,
            write_access: crate::groups::GroupWriteAccess::MembersOnly,
        },
    );
    if treekem {
        info.secure_plane = crate::mls::SecureGroupPlane::TreeKem;
    }
    // The pending member must be a second ADMIN: the local agent's
    // self-leave must pass the last-admin invariant (its 409 is a
    // different refusal) so the ONLY blocker left is the certificate.
    let pending_hex = "5d".repeat(32);
    let mut pending = crate::groups::GroupMember::new_admin(pending_hex.clone(), None, 1);
    // Inside the grace window, as a first seal would stamp it: the seal
    // refuses with the typed pending error but must NOT evict the seat.
    pending.certificate_missing_since_ms = Some(now_millis_u64());
    info.members_v2.insert(pending_hex.clone(), pending);
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
    Ok((state, dir))
}

async fn wp_c_491_leave_response(
    state: &std::sync::Arc<crate::server::AppState>,
    group_id: &str,
) -> Result<(axum::http::StatusCode, serde_json::Value)> {
    let response = leave_group(
        axum::extract::State(std::sync::Arc::clone(state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        axum::extract::Path(group_id.to_string()),
    )
    .await
    .into_response();
    let (status, body) = tests::response_json(response).await?;
    Ok((status, body))
}

/// #491 (from #483 part 3): the NON-TreeKEM self-leave arm must surface
/// `OwnerCertMemberPending` as a typed, retryable 409 CONFLICT — not the
/// opaque 500 it was mapped to before. WHY: a 500 tells the client (and
/// the operator) the server is broken; the truth is that certificate
/// evidence has not converged yet and a retry after the owner announces
/// will succeed. The refusal must also be pre-teardown: the group and
/// the pending seat survive for the retry.
#[tokio::test]
async fn wp_c_491_leave_gss_arm_returns_409_owner_cert_member_pending() {
    let group_id = "5c".repeat(32);
    let (state, _dir) = wp_c_491_owner_state_with_pending_member(&group_id, false)
        .await
        .expect("fixture");
    let (status, body) = wp_c_491_leave_response(&state, &group_id)
        .await
        .expect("leave response");
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "body: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("pending certificate resolution")),
        "refusal must be the typed OwnerCertMemberPending error: {body}"
    );
    let groups = state.named_groups.read().await;
    let live = groups.get(&group_id).expect("group retained for retry");
    assert!(
        !live.withdrawn,
        "a refused leave must not tear down or tombstone the group"
    );
    assert!(
        live.has_active_member(&"5d".repeat(32)),
        "the pending seat must survive the refused seal"
    );
}

/// #491 (from #483 part 3): the TreeKEM self-leave arm carries the SAME
/// typed 409 mapping as the GSS arm. WHY: before the fix only the
/// dedicated seal endpoint returned 409 — a second device leaving a
/// Home-shaped TreeKEM group got a 500 `seal failed: … pending
/// certificate resolution`, which is indistinguishable from a bug and
/// unbounded (it persists until an owner announce happens to be watched).
#[tokio::test]
async fn wp_c_491_leave_treekem_arm_returns_409_owner_cert_member_pending() {
    let group_id = "5e".repeat(32);
    let (state, _dir) = wp_c_491_owner_state_with_pending_member(&group_id, true)
        .await
        .expect("fixture");
    let (status, body) = wp_c_491_leave_response(&state, &group_id)
        .await
        .expect("leave response");
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "body: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("pending certificate resolution")),
        "refusal must be the typed OwnerCertMemberPending error: {body}"
    );
    let groups = state.named_groups.read().await;
    let live = groups.get(&group_id).expect("group retained for retry");
    assert!(
        !live.withdrawn,
        "a refused TreeKEM leave must not tombstone the group"
    );
    assert!(
        live.has_active_member(&hex::encode(state.agent.agent_id().as_bytes())),
        "the leaver keeps their seat across the refused seal"
    );
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
