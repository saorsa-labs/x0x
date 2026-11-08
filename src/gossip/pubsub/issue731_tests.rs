//! #731: a Leaf publisher that does not subscribe to its own topic must
//! still serve IWANT for its own messages, and the #380 C0 refuse gate must
//! stay for every other unsubscribed pass-through frame.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::test_support::{outer_v2_frame, signed_inner_v2, signing_context};
use super::*;
use crate::gossip::participation::{
    PublisherTopics, PUBLISHER_IWANT_WINDOW, PUBLISHER_TOPICS_CAP, UNSUBSCRIBE_QUIET,
};
use crate::identity::AgentKeypair;
use crate::network::{NetworkConfig, NetworkNode};
use saorsa_gossip_types::MessageHeader;

const REQUESTER: PeerId = PeerId::new([7; 32]);

async fn manager(mode: ParticipationMode, reason: &str) -> PubSubManager {
    let config = NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
        bootstrap_nodes: Vec::new(),
        mdns_enabled: false,
        port_mapping_enabled: false,
        ..NetworkConfig::default()
    };
    let node = Arc::new(NetworkNode::new(config, None, None).await.expect("node"));
    PubSubManager::new_with_participation(node, signing_context(), None, mode, reason)
        .expect("manager")
}

/// A Leaf whose transport records every send to the connected peers 1..=8.
async fn recording_leaf() -> PubSubManager {
    let manager = manager(ParticipationMode::Leaf, "default_leaf").await;
    *manager.transport.recorder.lock().unwrap() = Some(crate::gossip::egress::Recorder {
        peers: (1..=8).rev().map(|id| PeerId::new([id; 32])).collect(),
        sends: Vec::new(),
    });
    manager
}

/// Decoded recorded sends; `drain` also forgets them.
fn sends(
    manager: &PubSubManager,
    drain: bool,
) -> Vec<(PeerId, saorsa_gossip_pubsub::GossipMessage)> {
    let mut recorder = manager.transport.recorder.lock().unwrap();
    let sends = &mut recorder.as_mut().unwrap().sends;
    let taken = if drain {
        std::mem::take(sends)
    } else {
        sends.clone()
    };
    taken
        .iter()
        .filter_map(|(to, bytes)| Some((*to, postcard::from_bytes(bytes).ok()?)))
        .collect()
}

/// Wait up to `limit` for an EAGER copy of `id` sent to `peer`.
async fn served_to(manager: &PubSubManager, peer: PeerId, id: [u8; 32], limit: Duration) -> bool {
    let served = || {
        sends(manager, false).iter().any(|(to, msg)| {
            *to == peer && msg.header.kind == MessageKind::Eager && msg.header.msg_id == id
        })
    };
    tokio::time::timeout(limit, async {
        while !served() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok()
}

/// A signed control frame that passes SG's structural header inspection.
/// IWANT and IHAVE carry a postcard list of message ids as payload.
fn control_frame(kind: MessageKind, topic: TopicId, ids: &[[u8; 32]]) -> Bytes {
    let key = saorsa_gossip_identity::MlDsaKeyPair::generate().expect("fixture key");
    let payload: Bytes = postcard::to_stdvec(&ids.to_vec()).expect("ids").into();
    let mut header = MessageHeader::new(topic, kind, 10);
    header.seal_payload_hash(Some(&payload));
    let signature = key
        .sign(&postcard::to_stdvec(&header).expect("header serializes"))
        .expect("fixture signature");
    let msg = saorsa_gossip_pubsub::GossipMessage {
        header,
        payload: Some(payload),
        signature,
        public_key: key.public_key().to_vec(),
    };
    postcard::to_stdvec(&msg).expect("frame serializes").into()
}

fn iwant_reached_plumtree(manager: &PubSubManager) -> u64 {
    manager.stage_stats().message_kinds.iwant
}

#[tokio::test]
async fn issue731_leaf_publisher_sends_its_own_cached_message_to_the_requester() {
    let manager = recording_leaf().await;
    let topic = "issue731/served";
    let topic_id = TopicId::from_entity(topic.as_bytes());
    manager
        .publish(topic.to_string(), Bytes::from_static(b"own message"))
        .await
        .expect("leaf publish on an unsubscribed topic");
    let own_id = sends(&manager, true)[0].1.header.msg_id;

    manager
        .handle_incoming(
            REQUESTER,
            None,
            control_frame(MessageKind::IWant, topic_id, &[own_id]),
        )
        .await;

    assert!(
        served_to(&manager, REQUESTER, own_id, Duration::from_secs(2)).await,
        "the publisher must send its own cached message to the requester"
    );
    assert_eq!(
        manager.participation_snapshot().unsubscribed_refused_frames,
        0
    );
}

#[tokio::test]
async fn issue731_dropped_subscription_cache_is_not_served_to_iwant() {
    // The last subscription drop leaves the sg cache in place, with other
    // peers' messages in it. The exemption must not serve that cache.
    let manager = recording_leaf().await;
    let topic = "issue731/dropped-subscription";
    let topic_id = TopicId::from_entity(topic.as_bytes());
    let sub = manager.subscribe(topic.to_string()).await;
    let author = SigningContext::from_keypair(&AgentKeypair::generate().expect("author"));
    let inner = signed_inner_v2(&author, topic, &Bytes::from_static(b"foreign"));
    let foreign_id = [0x5a; 32];
    manager
        .handle_incoming(
            PeerId::new([3; 32]),
            None,
            outer_v2_frame(topic_id, inner, foreign_id),
        )
        .await;
    manager
        .publish(topic.to_string(), Bytes::from_static(b"own message"))
        .await
        .expect("leaf publish while subscribed");
    // Precondition: while subscribed, the cache serves the foreign message.
    sends(&manager, true);
    let witness = PeerId::new([6; 32]);
    manager
        .handle_incoming(
            witness,
            None,
            control_frame(MessageKind::IWant, topic_id, &[foreign_id]),
        )
        .await;
    assert!(
        served_to(&manager, witness, foreign_id, Duration::from_secs(2)).await,
        "precondition: the subscribed cache holds the foreign message"
    );

    let completed_before = manager.drop_completed.load(Ordering::Relaxed);
    drop(sub);
    tokio::time::timeout(Duration::from_secs(2), async {
        while manager.drop_completed.load(Ordering::Relaxed) == completed_before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("subscription drop completed");
    let refused_before = manager.participation_snapshot().unsubscribed_refused_frames;
    sends(&manager, true);

    manager
        .handle_incoming(
            REQUESTER,
            None,
            control_frame(MessageKind::IWant, topic_id, &[foreign_id]),
        )
        .await;

    assert!(
        !served_to(&manager, REQUESTER, foreign_id, Duration::from_millis(300)).await,
        "an unsubscribed Leaf must never serve another peer's cached message"
    );
    assert_eq!(
        manager.participation_snapshot().unsubscribed_refused_frames,
        refused_before + 1
    );
}

#[tokio::test]
async fn issue731_leaf_publisher_still_refuses_real_passthrough() {
    // Only IWANT on a published topic is exempt. EAGER, IHAVE and
    // anti-entropy carry or pull other peers' messages, and a topic this
    // node never published to keeps the full C0 refusal.
    let manager = manager(ParticipationMode::Leaf, "default_leaf").await;
    let topic = "issue731/publisher-only";
    let topic_id = TopicId::from_entity(topic.as_bytes());
    manager
        .publish(topic.into(), Bytes::from_static(b"own message"))
        .await
        .expect("leaf publish");
    let unrelated = TopicId::from_entity(b"issue731/never-published");
    let before = iwant_reached_plumtree(&manager);
    let frames = [
        (MessageKind::Eager, topic_id),
        (MessageKind::IHave, topic_id),
        (MessageKind::AntiEntropy, topic_id),
        (MessageKind::IWant, unrelated),
    ];
    for (kind, topic) in frames {
        let frame = control_frame(kind, topic, &[[0x31; 32]]);
        manager
            .handle_incoming(PeerId::new([0x44; 32]), None, frame)
            .await;
    }

    let snap = manager.participation_snapshot();
    assert_eq!(snap.unsubscribed_refused_frames, 4);
    assert_eq!(iwant_reached_plumtree(&manager), before);
    assert!(
        !manager.plumtree.all_topic_ids().await.contains(&unrelated),
        "C0 must keep pass-through state off a topic this node never published"
    );
}

#[test]
fn issue731_publisher_topics_expire_and_unsubscribe_starts_a_quiet_period() {
    let topics = PublisherTopics::default();
    let topic = TopicId::from_entity(b"issue731/quiet");
    let start = Instant::now();
    topics.record(topic, start);
    let last_ms = PUBLISHER_IWANT_WINDOW - Duration::from_millis(1);
    assert!(topics.contains(&topic, start + last_ms));
    assert!(
        !topics.contains(&topic, start + PUBLISHER_IWANT_WINDOW),
        "expired"
    );
    assert!(!topics.contains(&TopicId::from_entity(b"issue731/other"), start));
    topics.note_unsubscribed(topic, start);
    assert!(
        !topics.contains(&topic, start),
        "unsubscribe clears the publish"
    );
    let republish = start + Duration::from_secs(1);
    topics.record(topic, republish);
    assert!(!topics.contains(&topic, republish), "quiet period holds");
    let after_quiet = start + UNSUBSCRIBE_QUIET;
    topics.record(topic, after_quiet);
    assert!(topics.contains(&topic, after_quiet));

    // A full unsubscribe map fails closed for every topic.
    let full = PublisherTopics::default();
    for i in 0..=PUBLISHER_TOPICS_CAP {
        full.note_unsubscribed(TopicId::from_entity(format!("q/{i}").as_bytes()), start);
    }
    let other = TopicId::from_entity(b"issue731/other");
    full.record(other, start);
    assert!(!full.contains(&other, start), "overflow blocks all topics");
    full.record(other, start + UNSUBSCRIBE_QUIET);
    assert!(
        full.contains(&other, start + UNSUBSCRIBE_QUIET),
        "block ends"
    );
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
