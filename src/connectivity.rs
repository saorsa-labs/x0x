//! Connectivity helpers for agent-to-agent connection establishment.
//!
//! This module provides types and utilities for understanding the
//! reachability of discovered agents and for establishing connections
//! using the best available strategy:
//!
//! 1. **Direct** — a peer has verified the agent is directly reachable.
//! 2. **Coordinated** — hole-punching via a common coordinator node.
//! 3. **Unreachable** — no viable path found with current information.

use crate::identity::MachineId;
use crate::{DiscoveredAgent, DiscoveredMachine};

/// Summarises the connectivity properties of a discovered agent.
///
/// Built from a [`DiscoveredAgent`] and used to decide which connection
/// strategy to attempt.
#[derive(Debug, Clone)]
pub struct ReachabilityInfo {
    /// Agent's known addresses.
    pub addresses: Vec<std::net::SocketAddr>,
    /// NAT type reported by the agent (e.g. "FullCone", "Symmetric").
    /// `None` when the agent has not yet reported NAT information.
    ///
    /// This is informational only. Connection strategy should not infer direct
    /// reachability from NAT type alone.
    pub nat_type: Option<String>,
    /// Whether the agent can receive direct inbound connections.
    /// `None` when not reported.
    pub can_receive_direct: Option<bool>,
    /// Whether the agent advertises relay service capability.
    /// `None` when not reported.
    pub is_relay: Option<bool>,
    /// Whether the agent advertises coordinator capability.
    /// `None` when not reported.
    pub is_coordinator: Option<bool>,
    /// Coordinator machines through which the advertising peer is reachable.
    ///
    /// Prefer these when `can_receive_direct == Some(false)` — the peer has
    /// explicitly named who can hole-punch for them.
    pub reachable_via: Vec<MachineId>,
    /// Relay machines the peer proposes as a fallback.
    pub relay_candidates: Vec<MachineId>,
}

impl ReachabilityInfo {
    /// Build from a [`DiscoveredAgent`].
    #[must_use]
    pub fn from_discovered(agent: &DiscoveredAgent) -> Self {
        Self {
            addresses: agent.addresses.clone(),
            nat_type: agent.nat_type.clone(),
            can_receive_direct: agent.can_receive_direct,
            is_relay: agent.is_relay,
            is_coordinator: agent.is_coordinator,
            reachable_via: agent.reachable_via.clone(),
            relay_candidates: agent.relay_candidates.clone(),
        }
    }

    /// Build from a [`DiscoveredMachine`].
    #[must_use]
    pub fn from_discovered_machine(machine: &DiscoveredMachine) -> Self {
        Self {
            addresses: machine.addresses.clone(),
            nat_type: machine.nat_type.clone(),
            can_receive_direct: machine.can_receive_direct,
            is_relay: machine.is_relay,
            is_coordinator: machine.is_coordinator,
            reachable_via: machine.reachable_via.clone(),
            relay_candidates: machine.relay_candidates.clone(),
        }
    }

    /// Returns `true` if the remote agent has observer-verified direct reachability.
    #[must_use]
    pub fn likely_direct(&self) -> bool {
        !self.addresses.is_empty() && self.can_receive_direct == Some(true)
    }

    /// Returns `true` if it is still worth attempting a direct connection.
    ///
    /// Unknown reachability should still get a direct probe, especially for new
    /// networks where the first nodes have not yet accumulated observations.
    #[must_use]
    pub fn should_attempt_direct(&self) -> bool {
        !self.addresses.is_empty() && self.can_receive_direct != Some(false)
    }

    /// Returns `true` if coordinated NAT traversal may be needed to connect.
    ///
    /// Any agent that is not positively known to be directly reachable may still
    /// need coordination after direct attempts are exhausted.
    #[must_use]
    pub fn needs_coordination(&self) -> bool {
        !self.addresses.is_empty() && self.can_receive_direct != Some(true)
    }

    /// Returns `true` if the agent advertises relay service capability.
    #[must_use]
    pub fn is_relay(&self) -> bool {
        self.is_relay.unwrap_or(false)
    }

    /// Returns `true` if the agent advertises coordinator capability.
    #[must_use]
    pub fn is_coordinator(&self) -> bool {
        self.is_coordinator.unwrap_or(false)
    }
}

/// Outcome of a `connect_to_agent()` attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// Connected directly without NAT traversal assistance.
    Direct(std::net::SocketAddr),
    /// Connected via coordinated hole-punch through a relay peer (QUIC extension
    /// frames, PUNCH_ME_NOW). The relay was a bootstrap node or other reachable peer
    /// used as the NAT traversal coordinator.
    Coordinated(std::net::SocketAddr),
    /// Already connected via gossip overlay (e.g. LAN peer with no public
    /// address in their announcement).  Direct messaging is available.
    AlreadyConnected,
    /// Agent was found but could not be reached.
    Unreachable,
    /// Agent was not found in the discovery cache.
    NotFound,
}

impl std::fmt::Display for ConnectOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct(addr) => write!(f, "direct({addr})"),
            Self::Coordinated(addr) => write!(f, "coordinated({addr})"),
            Self::AlreadyConnected => write!(f, "already_connected"),
            Self::Unreachable => write!(f, "unreachable"),
            Self::NotFound => write!(f, "not_found"),
        }
    }
}

// ─── Transport environment assessment (ADR-0011 §4) ──────────────────────────

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// QUIC's mandatory minimum Initial datagram size (`ant-quic`
/// `MIN_INITIAL_SIZE`). A path that cannot carry a datagram this large cannot
/// complete a QUIC handshake on any port.
pub const QUIC_MIN_MTU: u16 = 1200;

/// MTU at or below which a path is critically constrained — only a few bytes of
/// headroom above the QUIC floor, so any extra tunnel/option overhead drops the
/// handshake. WireGuard-style full-tunnel VPNs commonly land here.
pub const MTU_CRITICAL_THRESHOLD: u16 = 1252;

/// MTU below which a path is "constrained" — still works but is small enough to
/// indicate a tunnel/VPN rather than a native ~1500-byte link.
pub const MTU_CONSTRAINED_THRESHOLD: u16 = 1400;

/// IPv4 CIDR blocks whose appearance as a node's **own external address**
/// indicates traffic is egressing through Cloudflare (WARP / "1.1.1.1: Faster
/// Internet" full-tunnel mode, or a Cloudflare tunnel). A normal ISP customer
/// never has a Cloudflare anycast IP as their public source address, so this is
/// a high-signal heuristic for the WARP class of UDP-hostile path. `(network,
/// prefix_len)`.
const CLOUDFLARE_WARP_V4_RANGES: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(104, 16, 0, 0), 12), // 104.16.0.0 – 104.31.255.255 (incl. WARP 104.28.x egress)
    (Ipv4Addr::new(172, 64, 0, 0), 13), // 172.64.0.0 – 172.71.255.255
];

/// Cloudflare WARP IPv6 egress prefix (`2606:4700::/32`).
const CLOUDFLARE_WARP_V6_RANGE: (Ipv6Addr, u8) =
    (Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0), 32);

/// RFC 6598 carrier-grade NAT range (`100.64.0.0/10`). A node whose external
/// address is in this block sits behind CGNAT and cannot receive unsolicited
/// inbound — it must relay. Distinct from a VPN: no split-tunnel fix applies.
const CGNAT_V4_RANGE: (Ipv4Addr, u8) = (Ipv4Addr::new(100, 64, 0, 0), 10);

fn v4_in_cidr(addr: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u32 = u32::MAX << (32 - prefix);
    (u32::from(addr) & mask) == (u32::from(net) & mask)
}

fn v6_in_cidr(addr: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u128 = u128::MAX << (128 - prefix);
    (u128::from(addr) & mask) == (u128::from(net) & mask)
}

/// Whether `ip` looks like a Cloudflare WARP / full-tunnel-VPN egress address.
fn is_vpn_egress(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => CLOUDFLARE_WARP_V4_RANGES
            .iter()
            .any(|&(net, prefix)| v4_in_cidr(v4, net, prefix)),
        IpAddr::V6(v6) => {
            let (net, prefix) = CLOUDFLARE_WARP_V6_RANGE;
            v6_in_cidr(v6, net, prefix)
        }
    }
}

/// Whether `ip` is in the RFC 6598 CGNAT range.
fn is_cgnat(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let (net, prefix) = CGNAT_V4_RANGE;
            v4_in_cidr(v4, net, prefix)
        }
        IpAddr::V6(_) => false,
    }
}

/// Observed transport facts fed into [`assess_transport_environment`].
///
/// Kept as a plain input struct (not the live `NodeStatus`) so the assessment
/// logic is pure and unit-testable independent of the network stack.
#[derive(Debug, Clone, Default)]
pub struct TransportObservation {
    /// External (reflexive) addresses ant-quic has observed for this node.
    pub external_addrs: Vec<SocketAddr>,
    /// Whether ant-quic believes this node can receive direct inbound.
    pub can_receive_direct: Option<bool>,
    /// Count of currently connected peers.
    pub connected_peers: usize,
    /// Smallest `current_mtu` observed across connected peers, if any.
    pub min_observed_mtu: Option<u16>,
    /// Total lost PLPMTUD probes across connected peers.
    pub lost_plpmtud_probes: u64,
    /// Total black-hole detections across connected peers.
    pub black_holes_detected: u64,
}

/// Structured assessment of the local transport environment (ADR-0011 §4).
///
/// Turns the silent "x0x just can't connect behind my VPN" failure into a
/// self-service signal: detects full-tunnel-VPN / constrained-MTU / CGNAT paths
/// and emits actionable guidance. Serialized into `/diagnostics/connectivity`
/// as `transport_environment` and printed by `x0xd --doctor`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TransportEnvironment {
    /// True if any degradation signal fired (the node's P2P may be impaired).
    pub degraded: bool,
    /// A full-tunnel VPN (Cloudflare WARP) appears to be in the path.
    pub vpn_suspected: bool,
    /// The node sits behind carrier-grade NAT (RFC 6598).
    pub cgnat_suspected: bool,
    /// The path MTU is small enough to threaten QUIC's 1200-byte Initial.
    pub constrained_mtu: bool,
    /// MTU is at/below the critical threshold (near the QUIC floor).
    pub mtu_critical: bool,
    /// Smallest MTU observed across peers, if any peer reported one.
    pub min_observed_mtu: Option<u16>,
    /// Total lost PLPMTUD probes (a blocked larger-packet path indicator).
    pub lost_plpmtud_probes: u64,
    /// Total black-hole detections.
    pub black_holes_detected: u64,
    /// The external address that matched a VPN egress range, if any.
    pub vpn_egress_addr: Option<String>,
    /// Human-readable reasons each signal fired (for logs / doctor output).
    pub reasons: Vec<String>,
    /// Actionable guidance for the operator, present only when `degraded`.
    pub guidance: Option<String>,
}

/// Assess the local transport environment from observed transport facts.
///
/// Pure function: same inputs always yield the same assessment. The heuristics
/// (ADR-0011 §4) are intentionally conservative — they flag *suspected*
/// degradation and explain why, rather than asserting a diagnosis.
#[must_use]
pub fn assess_transport_environment(obs: &TransportObservation) -> TransportEnvironment {
    let mut reasons = Vec::new();

    // 1. VPN egress: an external address inside a known WARP/Cloudflare range.
    let vpn_egress_addr = obs
        .external_addrs
        .iter()
        .find(|a| is_vpn_egress(a.ip()))
        .map(|a| a.to_string());
    let vpn_suspected = vpn_egress_addr.is_some();
    if let Some(addr) = &vpn_egress_addr {
        reasons.push(format!(
            "external address {addr} is in a Cloudflare WARP / full-tunnel-VPN egress range"
        ));
    }

    // 2. CGNAT: external address in RFC 6598 space.
    let cgnat_suspected = obs.external_addrs.iter().any(|a| is_cgnat(a.ip()));
    if cgnat_suspected {
        reasons.push(
            "external address is in the RFC 6598 carrier-grade NAT range (100.64.0.0/10); \
             direct inbound is not possible — connections must relay"
                .to_string(),
        );
    }

    // 3. Constrained MTU: a small discovered MTU, or lost PLPMTUD probes /
    //    detected black holes that indicate larger packets are being dropped.
    let mtu_critical = obs
        .min_observed_mtu
        .is_some_and(|m| m <= MTU_CRITICAL_THRESHOLD);
    let constrained_mtu = obs
        .min_observed_mtu
        .is_some_and(|m| m < MTU_CONSTRAINED_THRESHOLD)
        || obs.lost_plpmtud_probes > 0
        || obs.black_holes_detected > 0;
    if let Some(mtu) = obs.min_observed_mtu {
        if mtu < MTU_CONSTRAINED_THRESHOLD {
            reasons.push(format!(
                "path MTU {mtu} is constrained (< {MTU_CONSTRAINED_THRESHOLD}); QUIC needs {QUIC_MIN_MTU}"
            ));
        }
    }
    if obs.lost_plpmtud_probes > 0 {
        reasons.push(format!(
            "{} PLPMTUD probe(s) lost — a larger-packet path is being blocked",
            obs.lost_plpmtud_probes
        ));
    }
    if obs.black_holes_detected > 0 {
        reasons.push(format!(
            "{} path black-hole(s) detected",
            obs.black_holes_detected
        ));
    }

    // 4. Is connectivity actually impaired? A node with connected peers is
    //    working — even at the 1200-byte QUIC MTU floor with some black-holed
    //    larger-packet probes (a real, common case on tunnelled paths). So
    //    constrained-MTU is *informational*, not a degradation: flagging a
    //    node with live peers "degraded" only cries wolf. "Degraded" is
    //    reserved for paths genuinely breaking connectivity:
    //      - a full-tunnel VPN egress (Cloudflare WARP) — known-hostile to the
    //        high UDP ports x0x uses, worth surfacing even if some connections
    //        currently succeed; or
    //      - zero connected peers together with an explaining cause (CGNAT /
    //        no inbound / a constrained path).
    let no_peers = obs.connected_peers == 0;
    let no_inbound = obs.can_receive_direct == Some(false);
    if no_peers && no_inbound {
        reasons.push("node cannot receive direct inbound and has no connected peers".to_string());
    }

    let degraded =
        vpn_suspected || (no_peers && (cgnat_suspected || no_inbound || constrained_mtu));

    let guidance = if vpn_suspected {
        Some(
            "Full-tunnel VPN (e.g. Cloudflare WARP) detected; it throttles/drops the high UDP \
             ports x0x uses and degrades P2P even when some connections succeed. Use \
             split-tunnel mode and exclude x0x, or switch the VPN to DNS-only / 1.1.1.1 mode. \
             x0x bootstrap nodes also listen on UDP/443, which traverses most port-throttling \
             networks (but cannot raise a sub-1200 path MTU)."
                .to_string(),
        )
    } else if degraded && cgnat_suspected {
        Some(
            "Carrier-grade NAT detected and no peers connected; direct inbound is impossible. \
             x0x will relay through bootstrap/relay nodes — ensure UDP/443 and UDP/5483 \
             outbound are not blocked."
                .to_string(),
        )
    } else if degraded {
        Some(
            "No peers connected and the path looks constrained (low MTU / black-holed large \
             packets / no inbound). x0x bootstrap nodes listen on UDP/443, which traverses most \
             port-throttling networks; a path that cannot carry QUIC's 1200-byte Initial cannot \
             run QUIC on any port."
                .to_string(),
        )
    } else {
        None
    };

    TransportEnvironment {
        degraded,
        vpn_suspected,
        cgnat_suspected,
        constrained_mtu,
        mtu_critical,
        min_observed_mtu: obs.min_observed_mtu,
        lost_plpmtud_probes: obs.lost_plpmtud_probes,
        black_holes_detected: obs.black_holes_detected,
        vpn_egress_addr,
        reasons,
        guidance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AgentId, MachineId};

    fn discovered(
        addresses: Vec<std::net::SocketAddr>,
        nat_type: Option<&str>,
        can_receive_direct: Option<bool>,
        is_relay: Option<bool>,
        is_coordinator: Option<bool>,
    ) -> DiscoveredAgent {
        DiscoveredAgent {
            agent_id: AgentId([1u8; 32]),
            machine_id: MachineId([2u8; 32]),
            user_id: None,
            addresses,
            announced_at: 0,
            last_seen: 0,
            machine_public_key: Vec::new(),
            nat_type: nat_type.map(str::to_string),
            can_receive_direct,
            is_relay,
            is_coordinator,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
        }
    }

    fn addr() -> std::net::SocketAddr {
        "127.0.0.1:9000".parse().unwrap()
    }

    #[test]
    fn likely_direct_true_when_can_receive_direct_is_true() {
        let agent = discovered(vec![addr()], None, Some(true), None, None);
        let info = ReachabilityInfo::from_discovered(&agent);
        assert!(info.likely_direct());
    }

    #[test]
    fn likely_direct_false_when_can_receive_direct_is_false() {
        let agent = discovered(vec![addr()], None, Some(false), None, None);
        let info = ReachabilityInfo::from_discovered(&agent);
        assert!(!info.likely_direct());
    }

    #[test]
    fn likely_direct_false_when_only_nat_type_is_known() {
        let agent = discovered(vec![addr()], Some("FullCone"), None, None, None);
        let info = ReachabilityInfo::from_discovered(&agent);
        assert!(!info.likely_direct());
        assert!(info.should_attempt_direct());
    }

    #[test]
    fn likely_direct_false_for_symmetric_nat() {
        let agent = discovered(vec![addr()], Some("Symmetric"), None, None, None);
        let info = ReachabilityInfo::from_discovered(&agent);
        assert!(!info.likely_direct());
        assert!(info.should_attempt_direct());
    }

    #[test]
    fn likely_direct_false_when_no_addresses() {
        let agent = discovered(vec![], None, Some(true), None, None);
        let info = ReachabilityInfo::from_discovered(&agent);
        assert!(!info.likely_direct());
    }

    #[test]
    fn likely_direct_false_when_no_reachability_info_but_has_address() {
        let agent = discovered(vec![addr()], None, None, None, None);
        let info = ReachabilityInfo::from_discovered(&agent);
        assert!(!info.likely_direct());
        assert!(info.should_attempt_direct());
    }

    #[test]
    fn needs_coordination_true_for_symmetric_nat() {
        let agent = discovered(vec![addr()], Some("Symmetric"), None, None, None);
        let info = ReachabilityInfo::from_discovered(&agent);
        assert!(info.needs_coordination());
    }

    #[test]
    fn needs_coordination_true_when_cannot_receive_direct() {
        let agent = discovered(vec![addr()], None, Some(false), None, None);
        let info = ReachabilityInfo::from_discovered(&agent);
        assert!(info.needs_coordination());
    }

    #[test]
    fn needs_coordination_false_for_verified_direct_peer() {
        let agent = discovered(vec![addr()], Some("FullCone"), Some(true), None, None);
        let info = ReachabilityInfo::from_discovered(&agent);
        assert!(!info.needs_coordination());
    }

    #[test]
    fn from_discovered_copies_all_fields() {
        let agent = discovered(
            vec![addr()],
            Some("PortRestricted"),
            Some(false),
            Some(true),
            Some(true),
        );
        let info = ReachabilityInfo::from_discovered(&agent);
        assert_eq!(info.addresses.len(), 1);
        assert_eq!(info.nat_type.as_deref(), Some("PortRestricted"));
        assert_eq!(info.can_receive_direct, Some(false));
        assert!(info.is_relay());
        assert!(info.is_coordinator());
    }

    #[test]
    fn connect_outcome_display() {
        let a = addr();
        assert_eq!(
            ConnectOutcome::Direct(a).to_string(),
            format!("direct({a})")
        );
        assert_eq!(
            ConnectOutcome::Coordinated(a).to_string(),
            format!("coordinated({a})")
        );
        assert_eq!(ConnectOutcome::Unreachable.to_string(), "unreachable");
        assert_eq!(ConnectOutcome::NotFound.to_string(), "not_found");
    }

    #[test]
    fn connect_outcome_equality() {
        let a = addr();
        assert_eq!(ConnectOutcome::Direct(a), ConnectOutcome::Direct(a));
        assert_ne!(ConnectOutcome::Direct(a), ConnectOutcome::Unreachable);
    }

    #[test]
    fn reachability_info_from_discovered_machine() {
        let machine = DiscoveredMachine {
            machine_id: MachineId([1u8; 32]),
            addresses: vec!["10.0.0.1:5483".parse().unwrap()],
            announced_at: 100,
            last_seen: 200,
            machine_public_key: vec![],
            nat_type: Some("FullCone".to_string()),
            can_receive_direct: Some(true),
            is_relay: Some(false),
            is_coordinator: Some(true),
            reachable_via: vec![MachineId([2u8; 32])],
            relay_candidates: vec![],
            agent_ids: vec![],
            user_ids: vec![],
        };
        let info = ReachabilityInfo::from_discovered_machine(&machine);
        assert_eq!(info.addresses.len(), 1);
        assert_eq!(info.nat_type, Some("FullCone".to_string()));
        assert_eq!(info.can_receive_direct, Some(true));
        assert_eq!(info.is_relay, Some(false));
        assert_eq!(info.is_coordinator, Some(true));
        assert_eq!(info.reachable_via.len(), 1);
        assert!(info.relay_candidates.is_empty());
    }

    #[test]
    fn reachability_info_from_discovered_machine_empty() {
        let machine = DiscoveredMachine {
            machine_id: MachineId([3u8; 32]),
            addresses: vec![],
            announced_at: 0,
            last_seen: 0,
            machine_public_key: vec![],
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: vec![],
            relay_candidates: vec![],
            agent_ids: vec![],
            user_ids: vec![],
        };
        let info = ReachabilityInfo::from_discovered_machine(&machine);
        assert!(info.addresses.is_empty());
        assert!(info.nat_type.is_none());
        assert!(info.can_receive_direct.is_none());
    }

    fn obs(external: &[&str]) -> TransportObservation {
        TransportObservation {
            external_addrs: external.iter().map(|s| s.parse().unwrap()).collect(),
            can_receive_direct: Some(true),
            connected_peers: 5,
            ..Default::default()
        }
    }

    #[test]
    fn healthy_native_path_is_not_degraded() {
        // WHY: a normal residential/public IP with peers connected must never be
        // flagged — false positives would scare users into breaking working setups.
        let env = assess_transport_environment(&obs(&["203.0.113.7:5483"]));
        assert!(!env.degraded);
        assert!(!env.vpn_suspected);
        assert!(env.guidance.is_none());
    }

    #[test]
    fn warp_egress_address_is_flagged_as_vpn() {
        // WHY: a Cloudflare WARP egress IP (104.28.x) as our *own* external
        // address is the canonical UDP-hostile path ADR-0011 targets; it must
        // produce VPN guidance so the user can split-tunnel.
        let env = assess_transport_environment(&obs(&["104.28.5.9:5483"]));
        assert!(env.vpn_suspected);
        assert!(env.degraded);
        let guidance = env.guidance.expect("degraded path must carry guidance");
        assert!(guidance.contains("split-tunnel"));
        assert_eq!(env.vpn_egress_addr.as_deref(), Some("104.28.5.9:5483"));
    }

    #[test]
    fn cloudflare_v6_egress_is_flagged() {
        let env = assess_transport_environment(&obs(&["[2606:4700:abcd::1]:5483"]));
        assert!(env.vpn_suspected);
    }

    #[test]
    fn ordinary_cloudflare_adjacent_ip_outside_ranges_is_clean() {
        // WHY: the heuristic must be tight. 104.32.x is just outside 104.16/12
        // and must not trip the VPN flag, or every nearby ISP would be mislabelled.
        let env = assess_transport_environment(&obs(&["104.32.0.1:5483"]));
        assert!(!env.vpn_suspected);
    }

    #[test]
    fn cgnat_with_no_peers_is_degraded_but_distinct_from_vpn() {
        // WHY: CGNAT and VPN need different guidance — a split-tunnel tip is
        // useless behind carrier NAT. They must not be conflated.
        let mut o = obs(&["100.100.1.1:5483"]);
        o.can_receive_direct = Some(false);
        o.connected_peers = 0;
        let env = assess_transport_environment(&o);
        assert!(env.cgnat_suspected);
        assert!(!env.vpn_suspected);
        assert!(env.degraded);
        assert!(env.guidance.unwrap().contains("Carrier-grade NAT"));
    }

    #[test]
    fn cgnat_with_working_peers_is_not_degraded() {
        // WHY: CGNAT alone, while peers are connected (relayed), is normal and
        // working — don't alarm the user.
        let env = assess_transport_environment(&obs(&["100.100.1.1:5483"]));
        assert!(env.cgnat_suspected);
        assert!(!env.degraded);
    }

    #[test]
    fn constrained_mtu_with_peers_connected_is_not_degraded() {
        // WHY (learned from a live :443 probe that reported MTU 1200 + 13 black
        // holes while 8 peers were connected): a node with live peers is working
        // even at the QUIC MTU floor. Constrained-MTU is informational here, not
        // a degradation — labelling a connected node "degraded" only cries wolf.
        let mut o = obs(&["203.0.113.7:5483"]); // helper sets connected_peers = 5
        o.min_observed_mtu = Some(1200);
        o.black_holes_detected = 13;
        let env = assess_transport_environment(&o);
        assert!(
            env.constrained_mtu,
            "low MTU + black holes is still flagged"
        );
        assert!(env.mtu_critical);
        assert!(
            !env.degraded,
            "a node with connected peers must never be labelled degraded"
        );
        assert!(env.guidance.is_none());
    }

    #[test]
    fn lost_plpmtud_probes_signal_constrained_mtu_but_not_degraded_when_connected() {
        let mut o = obs(&["203.0.113.7:5483"]);
        o.lost_plpmtud_probes = 3;
        let env = assess_transport_environment(&o);
        assert!(env.constrained_mtu);
        assert!(
            !env.degraded,
            "lossy probes while connected is not an outage"
        );
        assert!(!env.mtu_critical, "no MTU value reported, so not critical");
    }

    #[test]
    fn no_peers_with_no_inbound_is_degraded_with_actionable_guidance() {
        // WHY: the actual silent-failure case ADR-0011 §4 targets — a client
        // that cannot connect at all must get explicit guidance, not silence.
        let mut o = obs(&["203.0.113.7:5483"]);
        o.connected_peers = 0;
        o.can_receive_direct = Some(false);
        let env = assess_transport_environment(&o);
        assert!(env.degraded);
        assert!(!env.vpn_suspected && !env.cgnat_suspected);
        assert!(env.guidance.unwrap().contains("UDP/443"));
    }
}
