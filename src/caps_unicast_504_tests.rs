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

/// Review of #1912 (amplification): only the requester's own verified
/// binding is answered directly.
#[test]
fn only_the_requesters_own_binding_is_answered_directly() {
    use crate::dm_capability_service::unicast_target;
    let own = MachineId([0x61; 32]);
    let victim = MachineId([0x62; 32]);
    assert_eq!(unicast_target(Some(own), Some(own)), Some(own));
    assert_eq!(unicast_target(Some(victim), Some(own)), None, "forged");
    assert_eq!(unicast_target(Some(own), None), None, "no binding held");
    assert_eq!(unicast_target(None, Some(own)), None, "no reply-to");
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

/// Request `responder`'s advert from `requester` until `done` holds,
/// returning the requests sent. Each answer is a freshly signed advert, so
/// it is ingested even when an older one is already stored.
async fn request_until(
    requester: &Agent,
    responder: &Agent,
    reply_to: Option<MachineId>,
    done: impl Fn() -> bool,
) -> usize {
    let pubsub = requester.gossip_runtime.as_ref().expect("runtime").pubsub();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut sent = 0;
    while !done() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition not met after {sent} requests"
        );
        publish_targeted_capability_request(pubsub, responder.agent_id(), reply_to)
            .await
            .expect("request");
        sent += 1;
        tokio::time::sleep(Duration::from_millis(1_200)).await;
    }
    sent
}

/// A third agent with an inbox, connected to the responder at `addr`.
async fn third(dir: &std::path::Path, name: &str, addr: std::net::SocketAddr) -> Agent {
    let agent = build(dir, name).await;
    agent
        .start_dm_inbox(
            Arc::new(AgentKemKeypair::generate().expect("kem")),
            dm_inbox::DmInboxConfig::default(),
        )
        .await
        .expect("inbox");
    agent.join_network().await.expect("join");
    agent
        .network()
        .unwrap()
        .connect_addr(addr)
        .await
        .expect("connect");
    agent
        .gossip_runtime
        .as_ref()
        .unwrap()
        .pubsub()
        .refresh_topic_peers()
        .await;
    agent
}

/// Make `holder` learn `peer`'s verified binding (its signed advert).
async fn ensure_binding(holder: &Agent, peer: &Agent) {
    let pubsub = holder.gossip_runtime.as_ref().expect("runtime").pubsub();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while holder
        .capability_store
        .lookup_binding(&peer.agent_id())
        .is_none()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "binding not learned"
        );
        publish_targeted_capability_request(pubsub, peer.agent_id(), None)
            .await
            .expect("request");
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

/// Connected agents. With a reply-to that is its own verified machine, the
/// requester gets the answer as a direct frame and the responder publishes
/// nothing on the response topic. A requester whose reply-to names another
/// machine (forged), and one that sends none (an old requester), get the
/// answer on the topic, and no direct frame goes anywhere.
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
    // The responder answers direct only to a requester whose binding it
    // holds; learn B's first.
    ensure_binding(&a, &b).await;
    let unicast_before = crate::dm_capability_service::unicast_ingested_for_test();
    let b_topic_answers = count_topic_answers(&b, &a).await;

    // New requester: names its own machine.
    let requests = request_until(&b, &a, Some(b.machine_id()), || {
        crate::dm_capability_service::unicast_ingested_for_test() > unicast_before
    })
    .await;
    assert!(requests >= 1, "the direct frame answered a request");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        b_topic_answers.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no answer was published on the response topic"
    );

    // Forged trailer: C names B's machine. The responder holds C's
    // binding, which is not B, so it answers on the topic and sends B
    // nothing.
    let c = third(dir.path(), "forger", addr).await;
    ensure_binding(&a, &c).await;
    let c_topic_answers = count_topic_answers(&c, &a).await;
    let unicast_before_forged = crate::dm_capability_service::unicast_ingested_for_test();
    request_until(&c, &a, Some(b.machine_id()), || {
        c_topic_answers.load(std::sync::atomic::Ordering::SeqCst) >= 1
    })
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        crate::dm_capability_service::unicast_ingested_for_test(),
        unicast_before_forged,
        "no direct frame goes to the machine a forged trailer names"
    );
    c.shutdown().await;

    // Old requester: no reply-to, so the answer is on the topic.
    let d = third(dir.path(), "old-requester", addr).await;
    let d_topic_answers = count_topic_answers(&d, &a).await;
    let unicast_before_old = crate::dm_capability_service::unicast_ingested_for_test();
    request_until(&d, &a, None, || {
        d_topic_answers.load(std::sync::atomic::Ordering::SeqCst) >= 1
    })
    .await;
    assert_eq!(
        crate::dm_capability_service::unicast_ingested_for_test(),
        unicast_before_old,
        "no direct frame without a reply-to"
    );
    d.shutdown().await;

    a.shutdown().await;
    b.shutdown().await;
}
