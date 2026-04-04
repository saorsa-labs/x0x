//! Property-based tests for connectivity.

use proptest::prelude::*;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use x0x::connectivity::{ConnectOutcome, ReachabilityInfo};

fn arb_addr() -> impl Strategy<Value = SocketAddr> {
    (any::<[u8; 4]>(), 1024u16..65535).prop_map(|(ip, port)| {
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            port,
        ))
    })
}

proptest! {
    /// likely_direct and needs_coordination always return booleans (never panic).
    #[test]
    fn heuristics_never_panic(
        addrs in prop::collection::vec(arb_addr(), 0..5),
        nat in prop_oneof![Just(None), Just(Some("FullCone".into())), Just(Some("Symmetric".into())), Just(Some("None".into()))],
        cd in prop::option::of(any::<bool>()),
    ) {
        let info = ReachabilityInfo { addresses: addrs, nat_type: nat, can_receive_direct: cd, is_relay: None, is_coordinator: None };
        // Just verify they don't panic — the heuristics may overlap.
        let _d = info.likely_direct();
        let _c = info.needs_coordination();
    }

    #[test]
    fn empty_addrs_not_direct(nat in prop_oneof![Just(None), Just(Some("FullCone".into()))], cd in prop::option::of(any::<bool>())) {
        let info = ReachabilityInfo { addresses: vec![], nat_type: nat, can_receive_direct: cd, is_relay: None, is_coordinator: None };
        prop_assert!(!info.likely_direct());
    }

    #[test]
    fn explicit_direct_true(addr in arb_addr()) {
        let info = ReachabilityInfo { addresses: vec![addr], nat_type: None, can_receive_direct: Some(true), is_relay: None, is_coordinator: None };
        prop_assert!(info.likely_direct());
    }

    #[test]
    fn symmetric_nat_needs_coord(_seed in 0u64..100) {
        let info = ReachabilityInfo { addresses: vec![SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1,2,3,4), 5000))], nat_type: Some("Symmetric".into()), can_receive_direct: Some(false), is_relay: None, is_coordinator: None };
        prop_assert!(info.needs_coordination());
    }

    #[test]
    fn connect_outcome_display_not_empty(addr in arb_addr()) {
        for o in [ConnectOutcome::Direct(addr), ConnectOutcome::Coordinated(addr), ConnectOutcome::NotFound, ConnectOutcome::Unreachable] {
            let display = format!("{}", o);
            prop_assert!(!display.is_empty());
        }
    }
}
