#![cfg(test)]
//! #504 (A06): a targeted capability answer goes as one direct frame to a
//! requester that names its machine, and the response topic stays the
//! fallback.

use std::sync::Arc;
use std::time::Duration;

use crate::dm_capability::{
    DM_CAPABILITY_TARGETED_REQUEST_TOPIC, DM_CAPABILITY_TARGETED_RESPONSE_TOPIC,
    DM_CAPABILITY_TOPIC,
};
use crate::dm_capability_service::{
    build_signed_advert, decode_targeted_capability_request,
    decode_targeted_capability_request_with_reply, decode_unicast_capability_response,
    encode_unicast_capability_response, ingest_unicast_capability_response,
    publish_targeted_capability_request, UNICAST_REPLY_TRAILER_TAG, WARM_TARGETED_REQUEST_DOMAIN,
};
use crate::groups::kem_envelope::AgentKemKeypair;
use crate::identity::{AgentId, AgentKeypair, MachineId};
use crate::{dm_inbox, gossip, network, Agent};

/// The request record exactly as a responder from before #504 decodes it.
#[derive(serde::Deserialize)]
struct PreUnicastRequest {
    protocol_version: u16,
    requested_agent_id: [u8; 32],
}

fn request_bytes(agent: AgentId, reply_to: Option<MachineId>) -> Vec<u8> {
    let mut bytes = postcard::to_stdvec(&(2u16, agent.0)).expect("encode");
    if let Some(machine) = reply_to {
        bytes.push(UNICAST_REPLY_TRAILER_TAG);
        bytes.extend_from_slice(&machine.0);
    }
    bytes
}

#[test]
fn a_request_with_a_reply_to_still_decodes_on_a_pre_unicast_responder() {
    let agent = AgentId([0x31; 32]);
    let machine = MachineId([0x32; 32]);
    let with_reply = request_bytes(agent, Some(machine));
    // A responder from before #504 uses `postcard::from_bytes`, which
    // ignores the trailer: it still answers on the topic.
    let old: PreUnicastRequest = postcard::from_bytes(&with_reply).expect("old decode");
    assert_eq!((old.protocol_version, old.requested_agent_id), (2, agent.0));
    let topic = DM_CAPABILITY_TARGETED_REQUEST_TOPIC;
    assert_eq!(
        decode_targeted_capability_request_with_reply(topic, &with_reply),
        Some((agent, Some(machine)))
    );
    assert_eq!(
        decode_targeted_capability_request_with_reply(topic, &request_bytes(agent, None)),
        Some((agent, None))
    );
    assert_eq!(
        decode_targeted_capability_request(topic, &with_reply),
        Some(agent)
    );
    // Any other trailer is refused.
    let mut bad = request_bytes(agent, Some(machine));
    bad.push(0);
    assert_eq!(
        decode_targeted_capability_request_with_reply(topic, &bad),
        None
    );
    let mut bad_tag = request_bytes(agent, Some(machine));
    let tag_at = bad_tag.len() - 33;
    bad_tag[tag_at] = 0x02;
    assert_eq!(
        decode_targeted_capability_request_with_reply(topic, &bad_tag),
        None
    );
    // The warm carrier never takes the trailer.
    let mut warm = WARM_TARGETED_REQUEST_DOMAIN.to_vec();
    warm.extend_from_slice(&with_reply);
    assert_eq!(
        decode_targeted_capability_request_with_reply(DM_CAPABILITY_TOPIC, &warm),
        None
    );
}

#[test]
fn a_unicast_answer_is_ingested_only_with_its_own_proof() {
    let responder = AgentKeypair::generate().expect("agent key");
    let signing = gossip::SigningContext::from_keypair(&responder);
    let machine = MachineId([0x41; 32]);
    let caps = crate::dm::DmCapabilities::pending();
    let mut ready = caps;
    ready.gossip_inbox = true;
    ready.kem_public_key = vec![7; 32];
    let advert =
        build_signed_advert(&signing, responder.agent_id(), machine, ready).expect("advert");
    let frame =
        encode_unicast_capability_response(&signing.public_key_bytes, &advert).expect("frame");
    let (key, body) = decode_unicast_capability_response(&frame).expect("decode");
    assert_eq!((key, body), (&signing.public_key_bytes[..], &advert[..]));
    assert_eq!(
        decode_unicast_capability_response(b"not a caps frame"),
        None
    );

    let local = AgentId([0x51; 32]);
    let store = crate::dm_capability::CapabilityStore::new();
    // Another agent's key, or a transport peer other than the advert's
    // machine: refused.
    let other = AgentKeypair::generate().expect("other key");
    let other_signing = gossip::SigningContext::from_keypair(&other);
    assert!(!ingest_unicast_capability_response(
        &store,
        local,
        responder.agent_id(),
        machine,
        &other_signing.public_key_bytes,
        &advert,
    ));
    assert!(!ingest_unicast_capability_response(
        &store,
        local,
        responder.agent_id(),
        MachineId([0x42; 32]),
        key,
        body,
    ));
    assert!(store.lookup(&responder.agent_id()).is_none());
    // The right sender, key and machine: ingested.
    assert!(ingest_unicast_capability_response(
        &store,
        local,
        responder.agent_id(),
        machine,
        key,
        body,
    ));
    assert_eq!(
        store
            .lookup_binding(&responder.agent_id())
            .map(|b| b.machine_id),
        Some(machine)
    );
}

async fn build(dir: &std::path::Path, name: &str) -> Agent {
    Agent::builder()
        .with_machine_key(dir.join(format!("{name}-machine")))
        .with_agent_key_path(dir.join(format!("{name}-agent")))
        .with_contact_store_path(dir.join(format!("{name}-contacts.json")))
        .with_peer_cache_disabled()
        .with_network_config(network::NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
            bootstrap_nodes: vec![],
            port_mapping_enabled: false,
            mdns_enabled: false,
            ..Default::default()
        })
        .build()
        .await
        .expect("agent")
}

/// Request `responder`'s advert from `requester` until it is ingested,
/// counting the requests sent.
async fn request_until_ingested(
    requester: &Agent,
    responder: &Agent,
    reply_to: Option<MachineId>,
) -> usize {
    let pubsub = requester.gossip_runtime.as_ref().expect("runtime").pubsub();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut sent = 0;
    loop {
        if requester
            .capability_store
            .lookup(&responder.agent_id())
            .is_some_and(|c| c.gossip_inbox)
        {
            return sent;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "advert not ingested after {sent} requests"
        );
        publish_targeted_capability_request(pubsub, responder.agent_id(), reply_to)
            .await
            .expect("request");
        sent += 1;
        tokio::time::sleep(Duration::from_millis(1_200)).await;
    }
}

/// Count `responder`'s answers that reach `requester` on the response topic.
async fn count_topic_answers(
    requester: &Agent,
    responder: &Agent,
) -> Arc<std::sync::atomic::AtomicUsize> {
    let mut sub = requester
        .gossip_runtime
        .as_ref()
        .unwrap()
        .pubsub()
        .subscribe(DM_CAPABILITY_TARGETED_RESPONSE_TOPIC.to_string())
        .await;
    let responder = responder.agent_id();
    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Some(message) = sub.recv().await {
            if message.sender == Some(responder) {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    });
    seen
}

/// Connected agents. With a reply-to machine, the answer arrives as a
/// direct frame and the responder publishes nothing on the response topic.
/// A third agent that sends no reply-to (an old requester) gets the answer
/// on the topic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connected_requester_gets_the_answer_direct_and_no_topic_publish() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let a = build(dir.path(), "responder").await;
    let b = build(dir.path(), "requester").await;
    for agent in [&a, &b] {
        agent
            .start_dm_inbox(
                Arc::new(AgentKemKeypair::generate().expect("kem")),
                dm_inbox::DmInboxConfig::default(),
            )
            .await
            .expect("inbox");
        agent.join_network().await.expect("join");
    }
    let addr = a.network().unwrap().bound_addr().await.unwrap();
    b.network()
        .unwrap()
        .connect_addr(addr)
        .await
        .expect("connect");
    for agent in [&a, &b] {
        agent
            .gossip_runtime
            .as_ref()
            .unwrap()
            .pubsub()
            .refresh_topic_peers()
            .await;
    }
    let unicast_before = crate::dm_capability_service::unicast_ingested_for_test();
    let b_topic_answers = count_topic_answers(&b, &a).await;

    // New requester: names its machine.
    let requests = request_until_ingested(&b, &a, Some(b.machine_id())).await;
    assert!(
        crate::dm_capability_service::unicast_ingested_for_test() > unicast_before,
        "the advert arrived as a direct frame (after {requests} requests)"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        b_topic_answers.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no answer was published on the response topic"
    );

    // Old requester: no reply-to, so the answer is on the topic.
    let c = build(dir.path(), "old-requester").await;
    c.start_dm_inbox(
        Arc::new(AgentKemKeypair::generate().expect("kem")),
        dm_inbox::DmInboxConfig::default(),
    )
    .await
    .expect("inbox");
    c.join_network().await.expect("join");
    c.network()
        .unwrap()
        .connect_addr(addr)
        .await
        .expect("connect");
    for agent in [&a, &c] {
        agent
            .gossip_runtime
            .as_ref()
            .unwrap()
            .pubsub()
            .refresh_topic_peers()
            .await;
    }
    let c_topic_answers = count_topic_answers(&c, &a).await;
    let unicast_before_old = crate::dm_capability_service::unicast_ingested_for_test();
    request_until_ingested(&c, &a, None).await;
    assert!(
        c_topic_answers.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "a request without a reply-to is answered on the topic"
    );
    assert_eq!(
        crate::dm_capability_service::unicast_ingested_for_test(),
        unicast_before_old,
        "no direct frame without a reply-to"
    );
    c.shutdown().await;

    a.shutdown().await;
    b.shutdown().await;
}
