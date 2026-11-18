#![cfg(test)]

use super::*;
use crate::dm::{DmBody, DmEnvelope, DmPayload, DM_PROTOCOL_VERSION};
use crate::peer_relay::{PeerRelay, RelayPolicy};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn sim_addr(host: u8) -> SocketAddr {
    SocketAddr::from(([198, 18, 0, host], 5483))
}

async fn sim_node(plane: &str, host: u8) -> network::NetworkNode {
    network::NetworkNode::new(
        network::NetworkConfig {
            bind_addr: Some(sim_addr(host)),
            network_id: Some(plane.to_string()),
            bootstrap_nodes: Vec::new(),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..network::NetworkConfig::default()
        },
        None,
        None,
    )
    .await
    .unwrap()
}

fn discovered(agent_id: identity::AgentId, machine_id: [u8; 32]) -> DiscoveredAgent {
    DiscoveredAgent {
        agent_id,
        machine_id: identity::MachineId(machine_id),
        user_id: None,
        addresses: Vec::new(),
        announced_at: 0,
        last_seen: 0,
        machine_public_key: Vec::new(),
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
        cert_digest: None,
        self_name: None,
    }
}

fn inner_envelope(sender: &identity::AgentKeypair, sender_machine: [u8; 32]) -> DmEnvelope {
    let created = dm::now_unix_ms();
    DmEnvelope {
        protocol_version: DM_PROTOCOL_VERSION,
        request_id: [0x64; 16],
        sender_agent_id: sender.agent_id().0,
        sender_machine_id: sender_machine,
        recipient_agent_id: [0x00; 32],
        created_at_unix_ms: created,
        expires_at_unix_ms: created.saturating_add(60_000),
        body: DmBody::Payload(DmPayload {
            kem_ciphertext: vec![0u8; 8],
            body_nonce: [0u8; 12],
            body_ciphertext: vec![0u8; 8],
        }),
        signature: vec![0u8; 8],
        origin_attestation: None,
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn relay_forward_is_metered_as_relay_bandwidth() {
    let plane = "issue1964-bandwidth-relay-forward";
    let fabric = network::sim::SimFabric::new(19643);
    network::sim::register(plane, &fabric);
    let sender = Arc::new(sim_node(plane, 1).await);
    let relay = Arc::new(sim_node(plane, 2).await);
    let dest = sim_node(plane, 3).await;
    let peer_relay_node = sender.connect_addr(sim_addr(2)).await.unwrap();
    let peer_dest = relay.connect_addr(sim_addr(3)).await.unwrap();
    assert_eq!(peer_dest, dest.peer_id());

    let sender_agent = identity::AgentKeypair::generate().unwrap();
    let relay_agent = identity::AgentId([0x52; 32]);
    let dest_agent = identity::AgentId([0x44; 32]);

    let peer_relay = Arc::new(PeerRelay::with_policy(RelayPolicy {
        enabled: true,
        require_contact_to_relay: false,
        ..RelayPolicy::default()
    }));
    let discovery = Arc::new(tokio::sync::RwLock::new(HashMap::from([(
        dest_agent,
        discovered(dest_agent, dest.peer_id().0),
    )])));
    let contacts_dir = tempfile::tempdir().unwrap();
    spawn_relay_dm_listener(
        Arc::clone(&relay),
        Arc::clone(&peer_relay),
        discovery,
        Arc::new(tokio::sync::RwLock::new(revocation::RevocationSet::new())),
        Arc::new(tokio::sync::RwLock::new(contacts::ContactStore::new(
            contacts_dir.path().join("contacts.json"),
        ))),
        relay_agent,
    );

    let inner = inner_envelope(&sender_agent, sender.peer_id().0);
    let forward_frame =
        u64::try_from(1 + 32 + postcard::to_allocvec(&inner).unwrap().len()).unwrap();
    let (sender_public_key, _) = sender_agent.to_bytes();
    let relayed = peer_relay
        .build_relayed_dm(
            &dest_agent,
            &sender_agent.agent_id(),
            sender_public_key,
            dm::now_unix_ms(),
            inner,
            true,
            |bytes| {
                ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
                    sender_agent.secret_key(),
                    bytes,
                )
                .map(|signature| signature.as_bytes().to_vec())
                .map_err(|e| e.to_string())
            },
        )
        .unwrap();

    let relay_before = relay.bandwidth_usage().sent_bytes;
    let dest_before = dest.bandwidth_usage().received_bytes.direct;
    sender
        .send_direct_typed(
            &peer_relay_node,
            sender_agent.agent_id().as_bytes(),
            network::RELAYED_DM_STREAM_TYPE,
            &relayed.to_postcard().unwrap(),
            network::bandwidth::BandwidthKind::Relay,
        )
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while dest.bandwidth_usage().received_bytes.direct - dest_before < forward_frame {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the forwarded frame never reached the destination"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let relay_after = relay.bandwidth_usage().sent_bytes;
    assert_eq!(
        relay_after.relay - relay_before.relay,
        forward_frame,
        "the relay meters its forward under `relay`"
    );
    assert_eq!(
        relay_after.direct, relay_before.direct,
        "the forward is not metered as the relay's own direct traffic"
    );
}
