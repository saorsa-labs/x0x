//! Connectivity helpers for agent-to-agent connection establishment.
//!
//! This module provides types and utilities for understanding the
//! reachability of discovered agents and for establishing connections
//! using the best available strategy:
//!
//! 1. **Direct** — a peer has verified the agent is directly reachable.
//! 2. **Coordinated** — hole-punching via a common coordinator node.
//! 3. **Unreachable** — no viable path found with current information.

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

    /// Build from a [`DiscoveredMachine`].
    #[must_use]
    pub fn from_discovered_machine(machine: &DiscoveredMachine) -> Self {
        Self {
            addresses: machine.addresses.clone(),
            nat_type: machine.nat_type.clone(),
            can_receive_direct: machine.can_receive_direct,
            is_relay: machine.is_relay,
            is_coordinator: machine.is_coordinator,
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
}
