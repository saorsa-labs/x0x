//! Listener lifecycle controls. Run only in the isolated Linux harness.
//! A local topic drives the real subscriber and signed metadata apply without
//! a DM fallback. The W3-H #1257 case covers the remote gossip transport.

use super::*;

const GROUP: &str = "1256-listener-local-key";
const STABLE: &str = "1256-listener-stable-id";
const FOREIGN: &str = "3333333333333333333333333333333333333333333333333333333333333333";

async fn fixture() -> Result<(Arc<AppState>, tempfile::TempDir, x0x::groups::GroupInfo)> {
    let (state, dir) = networked_test_state("1256-listener").await?;
    let (mut info, _, other) = metadata_terminality_test_group(&state, GROUP);
    // A second admin lets the local admin leave without a last-admin rejection.
    info.set_member_role(&other, x0x::groups::GroupRole::Admin);
    info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
        STABLE.to_string(),
        hex::encode(state.agent.agent_id().as_bytes()),
        info.created_at,
        String::new(),
    ));
    info.metadata_topic = "local:1256-metadata".to_string();
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(GROUP.to_string(), info.clone());
    Ok((state, dir, info))
}

async fn token(state: &AppState) -> u64 {
    let tasks = state.group_metadata_tasks.read().await;
    let reg = tasks.get(GROUP).expect("registered listener");
    assert!(
        !reg.handle.is_finished(),
        "registration must own a live task"
    );
    reg.token
}

async fn publish(state: &AppState, topic: &str, event: &NamedGroupMetadataEvent) {
    state
        .agent
        .publish(topic, serde_json::to_vec(event).expect("event JSON"))
        .await
        .expect("local publish");
}

async fn wait_for_name(state: &AppState, expected: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if state
                .named_groups
                .read()
                .await
                .get(GROUP)
                .is_some_and(|g| g.name == expected)
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the queued follow-up must apply through the same listener");
}

fn renamed_event(
    state: &Arc<AppState>,
    parent: &x0x::groups::GroupInfo,
    name: &str,
) -> NamedGroupMetadataEvent {
    let mut next = parent.clone();
    next.name = name.to_string();
    next.roster_revision += 1;
    NamedGroupMetadataEvent::GroupMetadataUpdated {
        group_id: STABLE.to_string(),
        revision: next.roster_revision,
        actor: hex::encode(state.agent.agent_id().as_bytes()),
        name: Some(next.name.clone()),
        description: None,
        commit: Some(sign_metadata_terminality_commit(
            parent,
            &next,
            state,
            now_millis_u64(),
        )),
    }
}

#[tokio::test]
async fn member_added_keeps_registration_and_queued_followup() -> Result<()> {
    let (state, _dir, parent) = fixture().await?;
    ensure_named_group_metadata_listener(Arc::clone(&state), GROUP).await;
    let installed = token(&state).await;
    let local = hex::encode(state.agent.agent_id().as_bytes());
    let mut seated = parent.clone();
    seated.roster_revision += 1;
    seated.add_member(
        FOREIGN.to_string(),
        x0x::groups::GroupRole::Member,
        Some(local.clone()),
        None,
    );
    let commit = sign_metadata_terminality_commit(&parent, &seated, &state, now_millis_u64());
    seated.prev_state_hash = Some(parent.state_hash.clone());
    seated.state_hash = commit.state_hash.clone();
    seated.state_revision = commit.revision;
    let added = NamedGroupMetadataEvent::MemberAdded {
        roster_certificates_b64: Vec::new(),
        group_id: STABLE.to_string(),
        revision: seated.roster_revision,
        actor: local,
        agent_id: FOREIGN.to_string(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: None,
        owner_mandate: None,
        commit: Some(commit),
    };
    // Park apply so both events are queued before the first one can exit.
    let lock = group_membership_lock(&state, GROUP).await;
    let guard = lock.lock().await;
    publish(&state, &parent.metadata_topic, &added).await;
    publish(
        &state,
        &parent.metadata_topic,
        &renamed_event(&state, &seated, "after-add"),
    )
    .await;
    drop(guard);
    wait_for_name(&state, "after-add").await;
    assert!(state.named_groups.read().await[GROUP].has_active_member(FOREIGN));
    assert_eq!(token(&state).await, installed, "same #477 J2 registration");
    ensure_named_group_metadata_listener(Arc::clone(&state), GROUP).await;
    assert_eq!(token(&state).await, installed, "ensure remains idempotent");
    stop_named_group_metadata_listener(&state, GROUP).await;
    Ok(())
}

#[tokio::test]
async fn removing_or_banning_another_member_keeps_listener() -> Result<()> {
    for ban in [false, true] {
        let (state, _dir, parent) = fixture().await?;
        ensure_named_group_metadata_listener(Arc::clone(&state), GROUP).await;
        let installed = token(&state).await;
        let local = hex::encode(state.agent.agent_id().as_bytes());
        let other = "22".repeat(32);
        let mut next = parent.clone();
        next.roster_revision += 1;
        if ban {
            next.ban_member(&other, Some(local.clone()));
        } else {
            next.remove_member(&other, Some(local.clone()));
        }
        let commit = sign_metadata_terminality_commit(&parent, &next, &state, now_millis_u64());
        next.prev_state_hash = Some(parent.state_hash.clone());
        next.state_hash = commit.state_hash.clone();
        next.state_revision = commit.revision;
        let event = if ban {
            NamedGroupMetadataEvent::MemberBanned {
                group_id: STABLE.to_string(),
                revision: next.roster_revision,
                actor: local,
                agent_id: other,
                secret_epoch: None,
                treekem_commit_b64: None,
                treekem_epoch: None,
                commit: Some(commit),
            }
        } else {
            NamedGroupMetadataEvent::MemberRemoved {
                group_id: STABLE.to_string(),
                revision: next.roster_revision,
                actor: local,
                agent_id: other,
                secret_epoch: None,
                treekem_commit_b64: None,
                treekem_epoch: None,
                commit: Some(commit),
            }
        };
        publish(&state, &parent.metadata_topic, &event).await;
        publish(
            &state,
            &parent.metadata_topic,
            &renamed_event(&state, &next, "after-departure"),
        )
        .await;
        wait_for_name(&state, "after-departure").await;
        assert_eq!(token(&state).await, installed);
        stop_named_group_metadata_listener(&state, GROUP).await;
    }
    Ok(())
}

#[tokio::test]
async fn self_removal_ban_and_group_deletion_stop_listener() -> Result<()> {
    for terminal in ["remove", "ban", "delete"] {
        let (state, _dir, parent) = fixture().await?;
        ensure_named_group_metadata_listener(Arc::clone(&state), GROUP).await;
        let local = hex::encode(state.agent.agent_id().as_bytes());
        let mut next = parent.clone();
        next.roster_revision += 1;
        match terminal {
            "remove" => next.remove_member(&local, Some(local.clone())),
            "ban" => next.ban_member(&local, Some(local.clone())),
            _ => next.withdrawn = true,
        }
        let commit = Some(sign_metadata_terminality_commit(
            &parent,
            &next,
            &state,
            now_millis_u64(),
        ));
        let event = match terminal {
            "remove" => NamedGroupMetadataEvent::MemberRemoved {
                group_id: STABLE.to_string(),
                revision: next.roster_revision,
                actor: local.clone(),
                agent_id: local.clone(),
                secret_epoch: None,
                treekem_commit_b64: None,
                treekem_epoch: None,
                commit,
            },
            "ban" => NamedGroupMetadataEvent::MemberBanned {
                group_id: STABLE.to_string(),
                revision: next.roster_revision,
                actor: local.clone(),
                agent_id: local.clone(),
                secret_epoch: None,
                treekem_commit_b64: None,
                treekem_epoch: None,
                commit,
            },
            _ => NamedGroupMetadataEvent::GroupDeleted {
                group_id: STABLE.to_string(),
                revision: next.roster_revision,
                actor: local.clone(),
                commit,
            },
        };
        publish(&state, &parent.metadata_topic, &event).await;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while state.group_metadata_tasks.read().await.contains_key(GROUP) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("terminal apply removes the registration");
        let groups = state.named_groups.read().await;
        match terminal {
            "remove" => assert!(!groups.contains_key(GROUP)),
            "ban" => assert!(groups[GROUP].is_banned(&local)),
            _ => assert!(groups[GROUP].withdrawn),
        }
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_ensures_keep_one_token_and_stale_epilogue_cannot_remove_it() -> Result<()> {
    let (state, _dir, _) = fixture().await?;
    // All calls must observe the SAME install, not overwrite earlier tasks.
    // Park the initial group read so every caller reaches ensure before an
    // install can finish. Without the registry write lock they all subscribe.
    let group_guard = state.named_groups.write().await;
    let (entered, mut waiting) = mpsc::unbounded_channel();
    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let state = Arc::clone(&state);
        let entered = entered.clone();
        calls.spawn(async move {
            entered.send(()).expect("ensure started");
            ensure_named_group_metadata_listener(Arc::clone(&state), GROUP).await;
            token(&state).await
        });
    }
    for _ in 0..16 {
        waiting.recv().await.expect("contending ensure");
    }
    drop(group_guard);
    let mut tokens = std::collections::HashSet::new();
    while let Some(result) = calls.join_next().await {
        tokens.insert(result.expect("ensure task"));
    }
    assert_eq!(tokens.len(), 1);
    // A map of length one alone cannot detect orphaned receivers. Local
    // publish counts every live receiver it enqueues to, including orphans.
    let before = state
        .agent
        .gossip_stats()
        .expect("gossip stats")
        .delivered_to_subscriber;
    state
        .agent
        .publish("local:1256-metadata", b"probe".to_vec())
        .await?;
    let after = state
        .agent
        .gossip_stats()
        .expect("gossip stats")
        .delivered_to_subscriber;
    assert_eq!(after - before, 1, "exactly one live subscription");
    let old = token(&state).await;
    stop_named_group_metadata_listener_if_token(&state, GROUP, old).await;
    ensure_named_group_metadata_listener(Arc::clone(&state), GROUP).await;
    let new = token(&state).await;
    assert_ne!(old, new);
    remove_listener_if_token(&state, GROUP, old).await;
    assert_eq!(token(&state).await, new);
    stop_named_group_metadata_listener(&state, GROUP).await;
    Ok(())
}
