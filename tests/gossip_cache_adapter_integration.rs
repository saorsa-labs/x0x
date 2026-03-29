//! GossipCacheAdapter integration tests.
//!
//! Verifies that the gossip cache adapter is properly wired into the Agent
//! and shares the same bootstrap cache.

use saorsa_gossip_coordinator::{AddrHint, CoordinatorAdvert, CoordinatorRoles, NatClass};
use saorsa_gossip_types::PeerId;
use tempfile::TempDir;
use x0x::network::NetworkConfig;
use x0x::Agent;

async fn agent_with_network() -> (Agent, TempDir) {
    let dir = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_network_config(NetworkConfig {
            bind_addr: Some("0.0.0.0:0".parse().unwrap()),
            bootstrap_nodes: vec![],
            ..Default::default()
        })
        .with_peer_cache_dir(dir.path().join("peers"))
        .build()
        .await
        .unwrap();
    (agent, dir)
}

async fn agent_without_network() -> (Agent, TempDir) {
    let dir = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .build()
        .await
        .unwrap();
    (agent, dir)
}

#[tokio::test]
async fn adapter_absent_without_network_config() {
    let (agent, _dir) = agent_without_network().await;
    assert!(agent.gossip_cache_adapter().is_none());
}

#[tokio::test]
async fn adapter_present_with_network_config() {
    let (agent, _dir) = agent_with_network().await;
    assert!(agent.gossip_cache_adapter().is_some());
}

#[tokio::test]
async fn adapter_insert_advert_enriches_cache() {
    let (agent, _dir) = agent_with_network().await;
    let adapter = agent.gossip_cache_adapter().unwrap();

    assert_eq!(adapter.advert_count(), 0);

    let peer_id = PeerId::new([42u8; 32]);
    let advert = CoordinatorAdvert::new(
        peer_id,
        CoordinatorRoles::default(),
        vec![AddrHint::new("127.0.0.1:5483".parse().unwrap())],
        NatClass::Unknown,
        60_000,
    );

    let inserted = adapter.insert_advert(advert).await;
    assert!(inserted);
    assert_eq!(adapter.advert_count(), 1);
    assert!(adapter.get_advert(&peer_id).is_some());
}

#[tokio::test]
async fn adapter_clone_shares_state() {
    let (agent, _dir) = agent_with_network().await;
    let adapter = agent.gossip_cache_adapter().unwrap().clone();
    let adapter2 = adapter.clone();

    let peer_id = PeerId::new([99u8; 32]);
    let advert = CoordinatorAdvert::new(
        peer_id,
        CoordinatorRoles::default(),
        vec![AddrHint::new("127.0.0.1:5483".parse().unwrap())],
        NatClass::Unknown,
        60_000,
    );

    adapter.insert_advert(advert).await;
    assert_eq!(adapter2.advert_count(), 1);
}

#[test]
fn advert_cbor_round_trip() {
    let peer_id = PeerId::new([7u8; 32]);
    let advert = CoordinatorAdvert::new(
        peer_id,
        CoordinatorRoles::default(),
        vec![AddrHint::new("10.0.0.1:5483".parse().unwrap())],
        NatClass::Eim,
        60_000,
    );

    let bytes = advert.to_bytes().unwrap();
    let decoded = CoordinatorAdvert::from_bytes(&bytes).unwrap();

    assert_eq!(decoded.peer, peer_id);
    assert!(decoded.is_valid());
    assert_eq!(decoded.addr_hints.len(), 1);
}

#[test]
fn coordinator_topic_is_deterministic() {
    let hash1 = blake3::hash(b"saorsa-coordinator-topic");
    let hash2 = blake3::hash(b"saorsa-coordinator-topic");
    assert_eq!(hash1, hash2);
    let topic = hex::encode(hash1.as_bytes());
    assert_eq!(topic.len(), 64);
}

#[test]
fn message_envelope_round_trip() {
    // Test the tag-prefixed wire format used on the coordinator topic
    let peer_id = PeerId::new([11u8; 32]);
    let advert = CoordinatorAdvert::new(
        peer_id,
        CoordinatorRoles::default(),
        vec![AddrHint::new("10.0.0.1:5483".parse().unwrap())],
        NatClass::Eim,
        60_000,
    );

    let cbor = advert.to_bytes().unwrap();

    // Envelope: tag byte + CBOR payload
    let mut envelope = Vec::with_capacity(1 + cbor.len());
    envelope.push(0x01); // COORD_TAG_ADVERT
    envelope.extend_from_slice(&cbor);

    // Decode: strip tag, parse CBOR
    assert_eq!(envelope[0], 0x01);
    let decoded = CoordinatorAdvert::from_bytes(&envelope[1..]).unwrap();
    assert_eq!(decoded.peer, peer_id);
    assert!(decoded.is_valid());
}

#[test]
fn foaf_query_cbor_round_trip() {
    let origin = PeerId::new([55u8; 32]);
    let query = saorsa_gossip_coordinator::FindCoordinatorQuery::new(origin);

    let mut cbor = Vec::new();
    ciborium::into_writer(&query, &mut cbor).unwrap();

    let decoded: saorsa_gossip_coordinator::FindCoordinatorQuery =
        ciborium::from_reader(&cbor[..]).unwrap();

    assert_eq!(decoded.origin, origin);
    assert_eq!(decoded.ttl, 3);
    assert!(!decoded.is_expired());
}
