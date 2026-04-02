//! Connectivity helpers for agent-to-agent connection establishment.
//!
//! This module provides types and utilities for understanding the
//! reachability of discovered agents and for establishing connections
//! using the best available strategy:
//!
//! 1. **Direct** — the remote agent has a public IP or open NAT.
//! 2. **Coordinated** — hole-punching via a common coordinator node.
//! 3. **Unreachable** — no viable path found with current information.

use crate::DiscoveredAgent;

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
    pub nat_type: Option<String>,
    /// Whether the agent can receive direct inbound connections.
    /// `None` when not reported.
    pub can_receive_direct: Option<bool>,
    /// Whether the agent is acting as a relay for peers behind strict NATs.
    /// `None` when not reported.
    pub is_relay: Option<bool>,
    /// Whether the agent is coordinating NAT traversal timing for peers.
    /// `None` when not reported.
    pub is_coordinator: Option<bool>,
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
        }
    }

    /// Returns `true` if a direct connection attempt is likely to succeed.
    ///
    /// This is the case when:
    /// - The agent explicitly reports `can_receive_direct: true`, OR
    /// - The agent has a NAT type that is easy to traverse (Full Cone), OR
    /// - We have no NAT information but the agent has at least one address.
    #[must_use]
    pub fn likely_direct(&self) -> bool {
        if self.addresses.is_empty() {
            return false;
        }
        match self.can_receive_direct {
            Some(true) => return true,
            Some(false) => return false,
            None => {}
        }
        // Fall back to NAT type heuristics
        match self.nat_type.as_deref() {
            Some("None") | Some("FullCone") => true,
            Some("Symmetric") => false,
            // Unknown, AddressRestricted, PortRestricted: optimistically try direct
            _ => true,
        }
    }

    /// Returns `true` if coordinated NAT traversal may be needed to connect.
    ///
    /// This is the case when the agent reports a symmetric NAT type or
    /// explicitly says it cannot receive direct connections.
    #[must_use]
    pub fn needs_coordination(&self) -> bool {
        if let Some(false) = self.can_receive_direct {
            return true;
        }
        matches!(self.nat_type.as_deref(), Some("Symmetric"))
    }

    /// Returns `true` if the agent is acting as a relay node.
    #[must_use]
    pub fn is_relay(&self) -> bool {
        self.is_relay.unwrap_or(false)
    }

    /// Returns `true` if the agent can coordinate NAT traversal for others.
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
    /// Connected via coordinated hole-punch or relay.
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
    fn likely_direct_true_for_full_cone_nat() {
        let agent = discovered(vec![addr()], Some("FullCone"), None, None, None);
        let info = ReachabilityInfo::from_discovered(&agent);
        assert!(info.likely_direct());
    }

    #[test]
    fn likely_direct_false_for_symmetric_nat() {
        let agent = discovered(vec![addr()], Some("Symmetric"), None, None, None);
        let info = ReachabilityInfo::from_discovered(&agent);
        assert!(!info.likely_direct());
    }

    #[test]
    fn likely_direct_false_when_no_addresses() {
        let agent = discovered(vec![], None, Some(true), None, None);
        let info = ReachabilityInfo::from_discovered(&agent);
        assert!(!info.likely_direct());
    }

    #[test]
    fn likely_direct_true_when_no_nat_info_but_has_address() {
        let agent = discovered(vec![addr()], None, None, None, None);
        let info = ReachabilityInfo::from_discovered(&agent);
        assert!(info.likely_direct());
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
    fn needs_coordination_false_for_full_cone_nat() {
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
}
