//! #901 follow-up coverage for the group roster to topic mapping.
//!
//! The #890 tests use an empty metadata topic. These tests use the real
//! `x0x.group.<16 hex>.meta` metadata form, and the KV `state-sync` form,
//! next to a second group and a Full pass-through topic.

#![cfg(test)]

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
async fn issue901_preference_returns_when_the_collision_ends() {
    let manager = manager("issue901_collision_ends").await;
    authorize_and_connect(&manager, &[70, 71]).await;
    let shared = meta("abababababababab");
    let _sub = manager.subscribe(shared.clone()).await;
    manager
        .replace_group_rosters(vec![
            ("ab".repeat(32), shared.clone(), vec![AgentId([40; 32])]),
            ("cd".repeat(32), shared.clone(), vec![AgentId([41; 32])]),
        ])
        .await;
    assert!(preferred(&manager, &shared).await.is_empty());
    // Group A leaves the collision; group B is the sole claimant again.
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
    let shared = meta("abababababababab");
    let _sub = manager.subscribe(shared.clone()).await;
    // Each install builds a new roster map with a new hash seed, so a
    // first-match lookup would pick group A or group B by chance. A card's
    // group ID is a free string, so "the ID that derives the topic" is not
    // a safe tie-break either: neither claim may win.
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

type Bindings = crate::dm_inbox::AuthenticatedMachineBindings;

/// Install `cache` as the group identity context and connect `machines`.
fn install_bindings(
    manager: &PubSubManager,
    cache: crate::dm_inbox::AuthenticatedMachineBindingCache,
    machines: &[u8],
) -> Bindings {
    let bindings = Arc::new(RwLock::new(cache));
    manager.set_group_identity_context(
        Arc::clone(&bindings),
        Arc::new(RwLock::new(crate::revocation::RevocationSet::new())),
        Arc::new(RwLock::new(crate::key_move::MoveState::default())),
    );
    manager
        .transport
        .recorder
        .lock()
        .expect("recorder")
        .as_mut()
        .expect("recorder installed")
        .peers = machines.iter().map(|n| PeerId::new([*n; 32])).collect();
    bindings
}

/// Bind agent `[n - 30; 32]` to machine `[n; 32]`.
async fn bind(bindings: &Bindings, n: u8) {
    crate::dm_inbox::record_authenticated_machine_binding(
        bindings,
        AgentId([n - 30; 32]),
        MachineId([n; 32]),
        1,
    )
    .await;
}

/// Subscribe to one KV topic of a new group whose roster is `agents`.
async fn roster_topic(manager: &PubSubManager, agents: Vec<AgentId>) -> String {
    let group = "ab".repeat(32);
    let topic = state_sync(&group, &"01".repeat(32));
    std::mem::forget(manager.subscribe(topic.clone()).await);
    manager
        .replace_group_rosters(vec![(group, String::new(), agents)])
        .await;
    topic
}

/// #901 item 4: one roster resolve takes the binding-cache write lock once,
/// not once per member.
#[tokio::test]
async fn issue901_roster_resolve_takes_the_binding_lock_once() {
    let manager = manager("issue901_one_lock").await;
    let machines: Vec<u8> = (70..82).collect();
    let bindings = install_bindings(&manager, Default::default(), &machines);
    for n in &machines {
        bind(&bindings, *n).await;
    }
    let agents: Vec<AgentId> = machines.iter().map(|n| AgentId([n - 30; 32])).collect();
    let topic = roster_topic(&manager, agents).await;

    let before = bindings.read().await.resolve_lock_takes();
    let chosen = preferred(&manager, &topic).await;
    let takes = bindings.read().await.resolve_lock_takes() - before;
    println!("issue901: binding write-lock takes for a 12-member roster = {takes}");
    assert_eq!(chosen.len(), 8, "all 12 members resolve; 8 slots");
    assert_eq!(takes, 1, "one write lock per roster resolve");
}

/// #901 item 4: the batch touches every resolved member in the LRU order.
/// The next insert at capacity evicts the member that is not in the roster.
#[tokio::test]
async fn issue901_roster_resolve_touches_each_member_in_the_lru() {
    let manager = manager("issue901_lru_touch").await;
    let cache = crate::dm_inbox::AuthenticatedMachineBindingCache::with_capacity(3);
    let bindings = install_bindings(&manager, cache, &[70, 71, 72, 73]);
    for n in [70, 71, 72] {
        bind(&bindings, n).await;
    }
    // Machine 72's agent is the newest entry and is not in the roster.
    let topic = roster_topic(&manager, vec![AgentId([40; 32]), AgentId([41; 32])]).await;
    assert_eq!(preferred(&manager, &topic).await.len(), 2);
    bind(&bindings, 73).await;
    let cache = bindings.read().await;
    assert!(cache.peek(&AgentId([40; 32])).is_some());
    assert!(cache.peek(&AgentId([41; 32])).is_some());
    assert!(
        cache.peek(&AgentId([42; 32])).is_none(),
        "the roster resolve made both members newer than the outsider"
    );
}

/// #901 item 5: a member whose binding the cache bound evicted gets no
/// preference, and the miss is counted as evicted. A member that never
/// announced is counted as without binding only. The local agent is not
/// counted.
#[tokio::test]
async fn issue901_evicted_member_gets_no_preference_and_is_counted() {
    let manager = manager("issue901_evicted").await;
    let cache = crate::dm_inbox::AuthenticatedMachineBindingCache::with_capacity(2);
    // Machine 70 stays connected after its binding is evicted, and machine
    // 73 is connected without any binding: reachability gives no preference.
    let bindings = install_bindings(&manager, cache, &[70, 71, 72, 73]);
    for n in [70, 71, 72] {
        bind(&bindings, n).await;
    }
    assert!(bindings.read().await.peek(&AgentId([40; 32])).is_none());
    let topic = roster_topic(
        &manager,
        vec![
            AgentId([40; 32]),
            AgentId([41; 32]),
            AgentId([42; 32]),
            AgentId([43; 32]),
            manager.signing.agent_id,
        ],
    )
    .await;

    let before = bindings.read().await.roster_binding_misses();
    let mut chosen = preferred(&manager, &topic).await;
    let after = bindings.read().await.roster_binding_misses();
    chosen.sort_unstable_by_key(|peer| *peer.as_bytes());
    assert_eq!(
        chosen,
        vec![PeerId::new([71; 32]), PeerId::new([72; 32])],
        "no binding, no preference"
    );
    assert_eq!(
        (after.0 - before.0, after.1 - before.1),
        (2, 1),
        "(without binding, of which evicted)"
    );

    // A new announcement restores the preference. At capacity it evicts
    // the least recently used member (machine 71), which is counted next.
    bind(&bindings, 70).await;
    let before = bindings.read().await.roster_binding_misses();
    let mut chosen = preferred(&manager, &topic).await;
    let after = bindings.read().await.roster_binding_misses();
    chosen.sort_unstable_by_key(|peer| *peer.as_bytes());
    assert_eq!(chosen, vec![PeerId::new([70; 32]), PeerId::new([72; 32])]);
    assert_eq!((after.0 - before.0, after.1 - before.1), (2, 1));
}

/// #901 item 4 measurement. Not a gate: run with `--run-ignored only`.
/// One task resolves a 256-member roster 2,000 times. A second task
/// resolves one sender's binding in a loop, as DM ingress does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement only"]
async fn issue901_measure_roster_resolve_against_dm_ingress() {
    const MEMBERS: u16 = 256;
    const RESOLVES: u32 = 2_000;
    let agent = |n: u16| {
        let mut id = [7u8; 32];
        id[..2].copy_from_slice(&n.to_be_bytes());
        AgentId(id)
    };
    let local = AgentId([0xEE; 32]);
    let agents: Vec<AgentId> = (0..MEMBERS).map(agent).collect();
    for batch in [false, true] {
        let bindings: Bindings = Arc::new(RwLock::new(Default::default()));
        for member in &agents {
            crate::dm_inbox::record_authenticated_machine_binding(
                &bindings,
                *member,
                MachineId(member.0),
                1,
            )
            .await;
        }
        let before = bindings.read().await.resolve_lock_takes();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ingress = tokio::spawn({
            let (bindings, stop, sender) = (Arc::clone(&bindings), Arc::clone(&stop), agents[0]);
            async move {
                let mut worst = std::time::Duration::ZERO;
                let mut count = 0u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let start = std::time::Instant::now();
                    crate::dm_inbox::authenticated_machine_binding_evidence(&bindings, &sender)
                        .await;
                    worst = worst.max(start.elapsed());
                    count += 1;
                    tokio::task::yield_now().await;
                }
                (count, worst)
            }
        });
        let start = std::time::Instant::now();
        for _ in 0..RESOLVES {
            if batch {
                crate::dm_inbox::authenticated_roster_machine_bindings(&bindings, &agents, &local)
                    .await;
            } else {
                for member in &agents {
                    crate::dm_inbox::authenticated_machine_binding(&bindings, member).await;
                }
            }
        }
        let elapsed = start.elapsed();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let (ingress_count, ingress_worst) = ingress.await.expect("ingress task");
        let takes = bindings.read().await.resolve_lock_takes() - before - ingress_count;
        println!(
            "issue901 measure: batch={batch} roster_lock_takes={takes} roster_wall={elapsed:?} \
             ingress_resolves={ingress_count} ingress_worst_wait={ingress_worst:?}"
        );
    }
}
