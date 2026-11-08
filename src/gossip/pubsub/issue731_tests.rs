//! #731: a Leaf publisher that does not subscribe to its own topic must
//! still serve IWANT for its own messages, and the #380 C0 refuse gate must
//! stay for every other unsubscribed pass-through frame.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::test_support::signing_context;
use super::*;
use crate::gossip::participation::{PublisherTopics, PUBLISHER_IWANT_WINDOW, PUBLISHER_TOPICS_CAP};
use crate::network::{NetworkConfig, NetworkNode};
use saorsa_gossip_types::MessageHeader;

async fn test_node() -> Arc<NetworkNode> {
    Arc::new(
        NetworkNode::new(
            NetworkConfig {
                bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
                bootstrap_nodes: Vec::new(),
                mdns_enabled: false,
                port_mapping_enabled: false,
                ..NetworkConfig::default()
            },
            None,
            None,
        )
        .await
        .expect("test node"),
    )
}

async fn manager(mode: ParticipationMode, reason: &str) -> PubSubManager {
    PubSubManager::new_with_participation(test_node().await, signing_context(), None, mode, reason)
        .expect("manager")
}

/// A signed control frame that passes SG's structural header inspection.
/// IWANT and IHAVE carry a postcard list of message ids as payload.
fn control_frame(kind: MessageKind, topic: TopicId) -> Bytes {
    let key = saorsa_gossip_identity::MlDsaKeyPair::generate().expect("fixture key");
    let header = MessageHeader {
        version: 1,
        topic,
        msg_id: [0u8; 32],
        kind,
        hop: 0,
        ttl: 10,
        payload_hash: None,
    };
    let signature = key
        .sign(&postcard::to_stdvec(&header).expect("header serializes"))
        .expect("fixture signature");
    let ids: Vec<[u8; 32]> = vec![[0x31; 32]];
    let msg = saorsa_gossip_pubsub::GossipMessage {
        header,
        payload: Some(postcard::to_stdvec(&ids).expect("ids").into()),
        signature,
        public_key: key.public_key().to_vec(),
    };
    postcard::to_stdvec(&msg).expect("frame serializes").into()
}

fn iwant_reached_plumtree(manager: &PubSubManager) -> u64 {
    manager.stage_stats().message_kinds.iwant
}

#[tokio::test]
async fn issue731_leaf_publisher_serves_iwant_on_unsubscribed_own_topic() {
    let manager = manager(ParticipationMode::Leaf, "default_leaf").await;
    let topic = "issue731/publisher-only";
    let topic_id = TopicId::from_entity(topic.as_bytes());
    manager
        .publish(topic.to_string(), Bytes::from_static(b"own message"))
        .await
        .expect("leaf publish on an unsubscribed topic");
    let before = iwant_reached_plumtree(&manager);

    manager
        .handle_incoming(
            PeerId::new([0x42; 32]),
            None,
            control_frame(MessageKind::IWant, topic_id),
        )
        .await;

    let snap = manager.participation_snapshot();
    assert_eq!(
        snap.unsubscribed_refused_frames, 0,
        "a Leaf must not refuse IWANT for a topic it published to"
    );
    assert_eq!(
        iwant_reached_plumtree(&manager),
        before + 1,
        "the IWANT must reach PlumTree so the cached own message is served"
    );
}

#[tokio::test]
async fn issue731_leaf_still_refuses_iwant_on_unrelated_unsubscribed_topic() {
    let manager = manager(ParticipationMode::Leaf, "default_leaf").await;
    manager
        .publish(
            "issue731/published".to_string(),
            Bytes::from_static(b"own message"),
        )
        .await
        .expect("leaf publish");
    let unrelated = TopicId::from_entity(b"issue731/never-published");
    let before = iwant_reached_plumtree(&manager);

    manager
        .handle_incoming(
            PeerId::new([0x43; 32]),
            None,
            control_frame(MessageKind::IWant, unrelated),
        )
        .await;

    let snap = manager.participation_snapshot();
    assert_eq!(snap.unsubscribed_refused_frames, 1);
    assert_eq!(snap.unsubscribed_refused_graft_equiv, 1);
    assert_eq!(iwant_reached_plumtree(&manager), before);
    assert!(
        !manager.plumtree.all_topic_ids().await.contains(&unrelated),
        "C0 must keep pass-through state off a topic this node never published"
    );
}

#[tokio::test]
async fn issue731_leaf_publisher_still_refuses_eager_ihave_and_anti_entropy() {
    // Only IWANT serves the publisher's own messages. EAGER, IHAVE and
    // anti-entropy carry or pull other peers' messages: real pass-through.
    let manager = manager(ParticipationMode::Leaf, "default_leaf").await;
    let topic = "issue731/publisher-only-other-kinds";
    let topic_id = TopicId::from_entity(topic.as_bytes());
    manager
        .publish(topic.to_string(), Bytes::from_static(b"own message"))
        .await
        .expect("leaf publish");

    for kind in [
        MessageKind::Eager,
        MessageKind::IHave,
        MessageKind::AntiEntropy,
    ] {
        manager
            .handle_incoming(PeerId::new([0x44; 32]), None, control_frame(kind, topic_id))
            .await;
    }

    let snap = manager.participation_snapshot();
    assert_eq!(snap.unsubscribed_refused_frames, 3);
}

#[tokio::test]
async fn issue731_full_node_does_not_record_publisher_topics() {
    let manager = manager(ParticipationMode::Full, "operator_relay").await;
    manager
        .publish(
            "issue731/full".to_string(),
            Bytes::from_static(b"own message"),
        )
        .await
        .expect("full publish");
    assert_eq!(
        manager.publisher_topics.len(),
        0,
        "Full forwards pass-through anyway; it keeps no publisher set"
    );
}

#[test]
fn issue731_publisher_topics_expire_after_the_cache_window() {
    let topics = PublisherTopics::default();
    let topic = TopicId::from_entity(b"issue731/expiry");
    let start = Instant::now();
    topics.record(topic, start);
    assert!(topics.contains(&topic, start));
    assert!(topics.contains(
        &topic,
        start + PUBLISHER_IWANT_WINDOW - Duration::from_millis(1)
    ));
    assert!(!topics.contains(&topic, start + PUBLISHER_IWANT_WINDOW));
    assert!(!topics.contains(&TopicId::from_entity(b"issue731/other"), start));
}

#[test]
fn issue731_publisher_topics_stay_bounded_and_evict_the_oldest() {
    let topics = PublisherTopics::default();
    let start = Instant::now();
    let topic = |i: usize| TopicId::from_entity(format!("issue731/cap/{i}").as_bytes());
    for i in 0..PUBLISHER_TOPICS_CAP {
        let offset = Duration::from_millis(u64::try_from(i).expect("small index"));
        topics.record(topic(i), start + offset);
    }
    assert_eq!(topics.len(), PUBLISHER_TOPICS_CAP);

    let now = start + Duration::from_secs(1);
    topics.record(topic(PUBLISHER_TOPICS_CAP), now);
    assert_eq!(topics.len(), PUBLISHER_TOPICS_CAP, "the cap holds");
    assert!(
        !topics.contains(&topic(0), now),
        "the oldest entry goes first"
    );
    assert!(topics.contains(&topic(1), now));
    assert!(topics.contains(&topic(PUBLISHER_TOPICS_CAP), now));

    // At the cap, expired entries are removed before any live one.
    let later = start + PUBLISHER_IWANT_WINDOW + Duration::from_secs(2);
    topics.record(topic(PUBLISHER_TOPICS_CAP + 1), later);
    assert_eq!(topics.len(), 1, "every expired entry was removed");
    assert!(topics.contains(&topic(PUBLISHER_TOPICS_CAP + 1), later));
}
