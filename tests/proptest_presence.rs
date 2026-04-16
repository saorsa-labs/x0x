//! Property-based tests for presence helpers and configuration.

use proptest::prelude::*;
use saorsa_gossip_types::{PeerId, PresenceRecord};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use x0x::identity::{AgentId, MachineId};
use x0x::presence::{
    global_presence_topic, parse_addr_hints, peer_to_agent_id, presence_record_to_discovered_agent,
    PresenceConfig, PresenceVisibility,
};
use x0x::DiscoveredAgent;

fn arb_addr() -> impl Strategy<Value = SocketAddr> {
    (any::<[u8; 4]>(), 1024u16..65535).prop_map(|(ip, port)| {
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            port,
        ))
    })
}

proptest! {
    #[test]
    fn config_defaults_are_sane(_seed in 0u64..100) {
        let config = PresenceConfig::default();
        prop_assert!(config.beacon_interval_secs > 0);
        prop_assert!(config.foaf_default_ttl > 0);
        prop_assert!(config.foaf_timeout_ms > 0);
        prop_assert!(config.adaptive_timeout_fallback_secs > 0);
    }

    #[test]
    fn parse_addr_hints_roundtrips_globally_advertisable_addresses(
        addrs in prop::collection::vec(arb_addr(), 0..5)
    ) {
        // parse_addr_hints now drops non-globally-advertisable entries (the
        // inbound defence against LAN-scope leakage from older peers). The
        // round-trip only holds for the filtered subset.
        let hints: Vec<String> = addrs.iter().map(std::string::ToString::to_string).collect();
        let expected: Vec<SocketAddr> = addrs
            .iter()
            .copied()
            .filter(|a| x0x::is_publicly_advertisable(*a))
            .collect();
        prop_assert_eq!(parse_addr_hints(&hints), expected);
    }

    #[test]
    fn peer_to_agent_id_resolves_matching_machine(
        agent_bytes in prop::array::uniform32(any::<u8>()),
        machine_bytes in prop::array::uniform32(any::<u8>()),
        other_machine_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(machine_bytes != other_machine_bytes);

        let agent_id = AgentId(agent_bytes);
        let machine_id = MachineId(machine_bytes);
        let mut cache: HashMap<AgentId, DiscoveredAgent> = HashMap::new();
        cache.insert(
            agent_id,
            DiscoveredAgent {
                agent_id,
                machine_id,
                user_id: None,
                addresses: Vec::new(),
                announced_at: 1,
                last_seen: 1,
                machine_public_key: Vec::new(),
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
            },
        );

        prop_assert_eq!(peer_to_agent_id(PeerId::new(machine_bytes), &cache), Some(agent_id));
        prop_assert_eq!(peer_to_agent_id(PeerId::new(other_machine_bytes), &cache), None);
    }

    #[test]
    fn presence_record_to_discovered_agent_uses_addr_hints(
        machine_bytes in prop::array::uniform32(any::<u8>()),
        addrs in prop::collection::vec(arb_addr(), 1..5),
    ) {
        let hints: Vec<String> = addrs.iter().map(std::string::ToString::to_string).collect();
        let record = PresenceRecord::new([0u8; 32], hints, 60);
        let cache: HashMap<AgentId, DiscoveredAgent> = HashMap::new();

        let discovered = presence_record_to_discovered_agent(PeerId::new(machine_bytes), &record, &cache);
        prop_assert!(discovered.is_some());
        let discovered = discovered.unwrap();

        prop_assert_eq!(discovered.agent_id, AgentId(machine_bytes));
        prop_assert_eq!(discovered.machine_id, MachineId(machine_bytes));
        // Inbound filter drops non-globally-advertisable addrs — only the
        // filtered subset survives into the DiscoveredAgent entry.
        let expected: Vec<SocketAddr> = addrs
            .iter()
            .copied()
            .filter(|a| x0x::is_publicly_advertisable(*a))
            .collect();
        prop_assert_eq!(discovered.addresses, expected);
    }
}

#[test]
fn presence_visibility_variants_are_distinct() {
    assert_ne!(PresenceVisibility::Network, PresenceVisibility::Social);
}

#[test]
fn global_presence_topic_is_deterministic() {
    assert_eq!(global_presence_topic(), global_presence_topic());
}

#[test]
fn invalid_addr_hints_are_ignored() {
    // `parse_addr_hints` now also drops non-globally-advertisable addrs,
    // so the loopback entry is filtered out in addition to the malformed one.
    let hints = vec!["1.2.3.4:1234".to_string(), "not-an-addr".to_string()];
    assert_eq!(
        parse_addr_hints(&hints),
        vec!["1.2.3.4:1234".parse().unwrap()]
    );
}

#[test]
fn expired_presence_records_are_filtered() {
    let mut record = PresenceRecord::new([0u8; 32], vec!["127.0.0.1:5483".to_string()], 60);
    record.expires = 0;
    let cache: HashMap<AgentId, DiscoveredAgent> = HashMap::new();

    let discovered = presence_record_to_discovered_agent(PeerId::new([7u8; 32]), &record, &cache);
    assert!(discovered.is_none());
}
