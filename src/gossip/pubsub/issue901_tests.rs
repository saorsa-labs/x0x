//! #901 follow-up coverage for the group roster to topic mapping.
//!
//! The #890 tests use an empty metadata topic. These tests use the real
//! `x0x.group.<16 hex>.meta` metadata form, and the KV `state-sync` form,
//! next to a second group and a Full pass-through topic.

use super::*;

async fn manager(reason: &str) -> PubSubManager {
    let node = Arc::new(
        NetworkNode::new(
            crate::network::NetworkConfig {
                bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
                bootstrap_nodes: Vec::new(),
                mdns_enabled: false,
                port_mapping_enabled: false,
                ..crate::network::NetworkConfig::default()
            },
            None,
            None,
        )
        .await
        .expect("test node"),
    );
    let manager = PubSubManager::new_with_participation(
        node,
        test_support::signing_context(),
        None,
        ParticipationMode::Full,
        reason,
    )
    .expect("manager");
    *manager.transport.recorder.lock().expect("recorder") = Some(super::super::egress::Recorder {
        peers: Vec::new(),
        sends: Vec::new(),
    });
    manager
}

/// Bind agent `[n - 30; 32]` to machine `[n; 32]` and connect every machine.
async fn authorize_and_connect(manager: &PubSubManager, machines: &[u8]) {
    let bindings = Arc::new(RwLock::new(
        crate::dm_inbox::AuthenticatedMachineBindingCache::default(),
    ));
    manager.set_group_identity_context(
        Arc::clone(&bindings),
        Arc::new(RwLock::new(crate::revocation::RevocationSet::new())),
        Arc::new(RwLock::new(crate::key_move::MoveState::default())),
    );
    for n in machines {
        crate::dm_inbox::record_authenticated_machine_binding(
            &bindings,
            AgentId([n - 30; 32]),
            MachineId([*n; 32]),
            1,
        )
        .await;
    }
    manager
        .transport
        .recorder
        .lock()
        .expect("recorder")
        .as_mut()
        .expect("recorder installed")
        .peers = machines.iter().map(|n| PeerId::new([*n; 32])).collect();
}

fn meta(prefix: &str) -> String {
    format!("x0x.group.{prefix}.meta")
}

fn state_sync(group: &str, store: &str) -> String {
    format!("x0x/group/{group}/kv/{store}/state-sync")
}

fn id(name: &str) -> TopicId {
    TopicId::from_entity(name.as_bytes())
}

async fn preferred(manager: &PubSubManager, name: &str) -> Vec<PeerId> {
    let connected = manager.transport.connected_peer_ids().await;
    manager.preferred_roster_peers(id(name), &connected).await
}

#[tokio::test]
async fn issue901_metadata_topic_maps_by_exact_name_and_kv_shape_wins() {
    let manager = manager("issue901_exact_name").await;
    authorize_and_connect(&manager, &[70, 71]).await;
    let group_a = "ab".repeat(32);
    let group_b = "cd".repeat(32);
    let meta_a = meta(&group_a[..16]);
    let chat_a = format!("x0x.group.{}.chat", &group_a[..16]);
    let kv_a = state_sync(&group_a, &"01".repeat(32));
    // Subscribe before any roster loads.
    let _subs = [
        manager.subscribe(meta_a.clone()).await,
        manager.subscribe(chat_a.clone()).await,
        manager.subscribe(kv_a.clone()).await,
    ];
    for name in [&meta_a, &chat_a, &kv_a] {
        assert!(preferred(&manager, name).await.is_empty(), "{name}");
    }

    // Group B names group A's KV topic as its metadata topic. The KV shape
    // must still map to group A, not to group B's roster.
    manager
        .replace_group_rosters(vec![
            (group_a.clone(), meta_a.clone(), vec![AgentId([40; 32])]),
            (group_b, kv_a.clone(), vec![AgentId([41; 32])]),
        ])
        .await;
    let member_a = vec![PeerId::new([70; 32])];
    assert_eq!(preferred(&manager, &meta_a).await, member_a);
    assert_eq!(preferred(&manager, &kv_a).await, member_a);
    assert!(
        preferred(&manager, &chat_a).await.is_empty(),
        "a sibling of the metadata topic is not the metadata topic"
    );
}

#[tokio::test]
async fn issue901_group_a_change_does_not_reapply_group_b_or_passthrough() {
    let manager = manager("issue901_scoped_refresh").await;
    authorize_and_connect(&manager, &[70, 71, 72]).await;
    let group_a = "ab".repeat(32);
    let group_b = "cd".repeat(32);
    let (meta_a, meta_b) = (meta(&group_a[..16]), meta(&group_b[..16]));
    let new_meta_a = meta("ef01ef01ef01ef01");
    let kv_a = state_sync(&group_a, &"01".repeat(32));
    let kv_b = state_sync(&group_b, &"02".repeat(32));
    let passthrough = id("issue901-full-passthrough");
    let mut subs = Vec::new();
    for name in [&meta_a, &meta_b, &new_meta_a, &kv_a, &kv_b] {
        subs.push(manager.subscribe(name.clone()).await);
    }
    let mut known: Vec<TopicId> = [&meta_a, &meta_b, &new_meta_a, &kv_a, &kv_b]
        .into_iter()
        .map(|name| id(name))
        .collect();
    known.push(passthrough);
    manager.set_known_plumtree_topics_for_test(known);
    let b = (group_b.clone(), meta_b.clone(), vec![AgentId([42; 32])]);
    manager
        .replace_group_rosters(vec![
            (group_a.clone(), meta_a.clone(), vec![AgentId([40; 32])]),
            b.clone(),
        ])
        .await;
    manager.take_refreshed_topic_ids();

    // Member change in group A.
    manager
        .replace_group_rosters(vec![
            (group_a.clone(), meta_a.clone(), vec![AgentId([41; 32])]),
            b.clone(),
        ])
        .await;
    let refreshed: HashSet<TopicId> = manager.take_refreshed_topic_ids().into_iter().collect();
    assert_eq!(refreshed, HashSet::from([id(&meta_a), id(&kv_a)]));
    assert_eq!(
        preferred(&manager, &meta_a).await,
        vec![PeerId::new([71; 32])]
    );

    // Metadata topic move in group A: old and new topic, and A's KV topic.
    manager
        .replace_group_rosters(vec![
            (group_a, new_meta_a.clone(), vec![AgentId([41; 32])]),
            b,
        ])
        .await;
    let refreshed: HashSet<TopicId> = manager.take_refreshed_topic_ids().into_iter().collect();
    assert_eq!(
        refreshed,
        HashSet::from([id(&meta_a), id(&new_meta_a), id(&kv_a)])
    );
    assert!(preferred(&manager, &meta_a).await.is_empty());
    assert_eq!(
        preferred(&manager, &new_meta_a).await,
        vec![PeerId::new([71; 32])]
    );
    for name in [&meta_b, &kv_b] {
        assert_eq!(
            preferred(&manager, name).await,
            vec![PeerId::new([72; 32])],
            "{name}"
        );
    }
}

#[tokio::test]
async fn issue901_shared_metadata_topic_prefers_the_group_that_derives_it() {
    let manager = manager("issue901_shared_metadata_derived").await;
    authorize_and_connect(&manager, &[70, 71]).await;
    // Group A's own ID derives the topic; group B's card only names it.
    let shared = meta("abababababababab");
    let _sub = manager.subscribe(shared.clone()).await;
    // Each install builds a new roster map with a new hash seed, so a
    // first-match lookup would pick group A or group B by chance.
    for round in 0..32 {
        manager
            .replace_group_rosters(vec![
                ("ab".repeat(32), shared.clone(), vec![AgentId([40; 32])]),
                ("cd".repeat(32), shared.clone(), vec![AgentId([41; 32])]),
            ])
            .await;
        assert_eq!(
            preferred(&manager, &shared).await,
            vec![PeerId::new([70; 32])],
            "round {round}: the group whose ID derives the topic keeps it"
        );
        manager.replace_group_rosters(Vec::new()).await;
    }
    // When the collision ends, the remaining claimant is preferred again.
    manager
        .replace_group_rosters(vec![(
            "cd".repeat(32),
            shared.clone(),
            vec![AgentId([41; 32])],
        )])
        .await;
    assert_eq!(
        preferred(&manager, &shared).await,
        vec![PeerId::new([71; 32])]
    );
}

#[tokio::test]
async fn issue901_shared_metadata_topic_gives_no_roster_preference() {
    let manager = manager("issue901_shared_metadata").await;
    authorize_and_connect(&manager, &[70, 71]).await;
    // Neither group's ID derives the topic, so neither claim is stronger.
    let shared = meta("efefefefefefefef");
    let _sub = manager.subscribe(shared.clone()).await;
    for round in 0..32 {
        manager
            .replace_group_rosters(vec![
                ("ab".repeat(32), shared.clone(), vec![AgentId([40; 32])]),
                ("cd".repeat(32), shared.clone(), vec![AgentId([41; 32])]),
            ])
            .await;
        assert!(
            preferred(&manager, &shared).await.is_empty(),
            "round {round}: two rosters claim one metadata topic; neither may win"
        );
        manager.replace_group_rosters(Vec::new()).await;
    }
}
