//! GossipCacheAdapter integration tests.
//!
//! Verifies that the gossip cache adapter is properly wired into the Agent
//! and shares the same bootstrap cache.

#![allow(clippy::unwrap_used)]

use saorsa_gossip_coordinator::{AddrHint, CoordinatorAdvert, CoordinatorRoles, NatClass};
use saorsa_gossip_types::PeerId;
use tempfile::TempDir;
use x0x::network::NetworkConfig;
use x0x::Agent;

async fn agent_with_network_in(dir: &TempDir) -> Agent {
    Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_network_config(NetworkConfig {
            bind_addr: Some("0.0.0.0:0".parse().unwrap()),
            bootstrap_nodes: vec![],
            ..Default::default()
        })
        .with_peer_cache_dir(dir.path().join("peers"))
        .build()
        .await
        .unwrap()
}

async fn agent_with_network() -> (Agent, TempDir) {
    let dir = TempDir::new().unwrap();
    let agent = agent_with_network_in(&dir).await;
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
    let dir = TempDir::new().unwrap();

    let peer_id = PeerId::new([42u8; 32]);
    let addr = "127.0.0.1:5483".parse().unwrap();
    let advert = CoordinatorAdvert::new(
        peer_id,
        CoordinatorRoles::default(),
        vec![AddrHint::new(addr)],
        NatClass::Unknown,
        60_000,
    );

    {
        let agent = agent_with_network_in(&dir).await;
        let adapter = agent.gossip_cache_adapter().unwrap();

        assert_eq!(adapter.advert_count(), 0);
        assert_eq!(adapter.peer_count().await, 0);

        let inserted = adapter.insert_advert(advert).await;
        assert!(inserted);
        assert_eq!(adapter.advert_count(), 1);
        assert!(adapter.get_advert(&peer_id).is_some());
        assert!(adapter.get_peer(&peer_id).await.is_some());

        agent.shutdown().await;
    }

    {
        let agent = agent_with_network_in(&dir).await;
        let adapter = agent.gossip_cache_adapter().unwrap();

        assert_eq!(adapter.advert_count(), 0);
        let cached_peer = adapter.get_peer(&peer_id).await.unwrap();
        assert_eq!(cached_peer.peer_id, ant_quic::PeerId(*peer_id.as_bytes()));
        assert!(cached_peer.addresses.contains(&addr));

        agent.shutdown().await;
    }
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
