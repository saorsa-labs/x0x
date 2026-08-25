//! Gossip participation mode (issue #380 / designs/380.md).
//!
//! Ordinary desktop/client daemons default to [`ParticipationMode::Leaf`]:
//! they refresh PlumTree eager sets only for topics they subscribe to.
//! Backbone processes (seed, dual-listen `:443`, managed `/opt/x0x/x0xd*`,
//! or explicit `--relay` / `gossip.relay`) stay [`ParticipationMode::Full`]
//! and keep today's pass-through refresh so they forward unsubscribed topics.
//!
//! Detection fail-closes to Full: any backbone signal wins over a missing
//! or contradictory Leaf intent. Never silent Leaf on the backbone.

use crate::network::DEFAULT_BOOTSTRAP_PEERS;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::OnceLock;

/// ADR-0011 dual-listen port. Clients never bind this; `x0xd-443` does.
const DUAL_LISTEN_PORT: u16 = 443;

/// ADR-0026 managed-host binary prefix (`authority-inventory.json`).
const MANAGED_BINARY_PREFIX: &str = "/opt/x0x/x0xd";

/// How this process participates in PlumTree topic-peer refresh.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipationMode {
    /// Subscribe/publish only. Do not expand eager sets for unsubscribed
    /// PlumTree topics.
    #[default]
    Leaf,
    /// Today's pass-through loop: every PlumTree-known topic gets the plane
    /// peer list so this node can forward traffic it does not subscribe to.
    Full,
}

impl ParticipationMode {
    /// True when `refresh_topic_peers` should still feed unsubscribed topics.
    #[must_use]
    pub const fn forwards_passthrough(self) -> bool {
        matches!(self, Self::Full)
    }
}

impl std::fmt::Display for ParticipationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Leaf => f.write_str("leaf"),
            Self::Full => f.write_str("full"),
        }
    }
}

/// Inputs used to classify Leaf vs Full. Built from existing daemon bind,
/// seed list, managed-install path, and the operator `--relay` / `gossip.relay`
/// opt-in — no new identity and no root requirement.
#[derive(Debug, Clone)]
pub struct ParticipationInputs<'a> {
    /// `--relay` and/or TOML `gossip.relay = true`.
    pub operator_relay: bool,
    /// Final QUIC bind address after named-instance / dual-stack promotion.
    pub bind_addr: SocketAddr,
    /// Extra listen candidates (tests). Empty means "derive from `bind_addr`
    /// plus local interfaces when the bind IP is unspecified".
    pub local_addrs: &'a [SocketAddr],
    /// `std::env::current_exe()` when known.
    pub current_exe: Option<&'a Path>,
}

/// Resolved mode plus the first fail-closed reason that selected it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipationSelection {
    pub mode: ParticipationMode,
    pub reason: &'static str,
}

/// Snapshot exposed on `GET /diagnostics/gossip`.
#[derive(Debug, Clone, Serialize)]
pub struct ParticipationSnapshot {
    pub mode: ParticipationMode,
    pub reason: String,
    pub passthrough_refresh_runs: u64,
    pub passthrough_refresh_ran: bool,
}

/// Classify this process. Full wins on any backbone or opt-in signal.
#[must_use]
pub fn resolve_participation(inputs: ParticipationInputs<'_>) -> ParticipationSelection {
    if is_dual_listen(inputs.bind_addr) {
        return ParticipationSelection {
            mode: ParticipationMode::Full,
            reason: "dual_listen",
        };
    }
    if is_seed_listen(inputs.bind_addr, inputs.local_addrs) {
        return ParticipationSelection {
            mode: ParticipationMode::Full,
            reason: "seed_addr",
        };
    }
    if is_managed_binary(inputs.current_exe) {
        return ParticipationSelection {
            mode: ParticipationMode::Full,
            reason: "managed_binary",
        };
    }
    if inputs.operator_relay {
        return ParticipationSelection {
            mode: ParticipationMode::Full,
            reason: "operator_relay",
        };
    }
    ParticipationSelection {
        mode: ParticipationMode::Leaf,
        reason: "default_leaf",
    }
}

fn is_dual_listen(bind_addr: SocketAddr) -> bool {
    bind_addr.port() == DUAL_LISTEN_PORT
}

fn is_managed_binary(current_exe: Option<&Path>) -> bool {
    current_exe
        .and_then(Path::to_str)
        .is_some_and(|path| path.starts_with(MANAGED_BINARY_PREFIX))
}

fn is_seed_listen(bind_addr: SocketAddr, extra: &[SocketAddr]) -> bool {
    let seeds = seed_addrs();
    listen_candidates(bind_addr, extra)
        .iter()
        .any(|addr| seeds.contains(addr))
}

fn listen_candidates(bind_addr: SocketAddr, extra: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut out = extra.to_vec();
    if !bind_addr.ip().is_unspecified() {
        out.push(bind_addr);
    } else if extra.is_empty() {
        out.extend(crate::collect_local_interface_addrs(bind_addr.port()));
    }
    out
}

fn seed_addrs() -> &'static HashSet<SocketAddr> {
    static SEEDS: OnceLock<HashSet<SocketAddr>> = OnceLock::new();
    SEEDS.get_or_init(|| {
        DEFAULT_BOOTSTRAP_PEERS
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_QUIC_PORT: u16 = 5483;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn ephemeral() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    #[test]
    fn ordinary_client_defaults_to_leaf() {
        // Why: desktops must stop acting as full-mesh pass-through relays.
        let selection = resolve_participation(ParticipationInputs {
            operator_relay: false,
            bind_addr: ephemeral(),
            local_addrs: &[loopback(CLIENT_QUIC_PORT)],
            current_exe: Some(Path::new("/home/user/.local/bin/x0xd")),
        });
        assert_eq!(selection.mode, ParticipationMode::Leaf);
        assert_eq!(selection.reason, "default_leaf");
        assert!(!selection.mode.forwards_passthrough());
    }

    #[test]
    fn operator_relay_opts_in_to_full() {
        let selection = resolve_participation(ParticipationInputs {
            operator_relay: true,
            bind_addr: ephemeral(),
            local_addrs: &[],
            current_exe: Some(Path::new("/home/user/.local/bin/x0xd")),
        });
        assert_eq!(selection.mode, ParticipationMode::Full);
        assert_eq!(selection.reason, "operator_relay");
        assert!(selection.mode.forwards_passthrough());
    }

    #[test]
    fn dual_listen_port_fail_closes_to_full() {
        // Why: ADR-0011 x0xd-443 is backbone. Never silent Leaf there.
        let selection = resolve_participation(ParticipationInputs {
            operator_relay: false,
            bind_addr: SocketAddr::from(([0, 0, 0, 0], DUAL_LISTEN_PORT)),
            local_addrs: &[],
            current_exe: Some(Path::new("/home/user/.local/bin/x0xd")),
        });
        assert_eq!(selection.mode, ParticipationMode::Full);
        assert_eq!(selection.reason, "dual_listen");
    }

    #[test]
    fn seed_listen_addr_fail_closes_to_full() {
        let seed: SocketAddr = DEFAULT_BOOTSTRAP_PEERS[0].parse().expect("seed");
        let selection = resolve_participation(ParticipationInputs {
            operator_relay: false,
            bind_addr: SocketAddr::from(([0, 0, 0, 0], CLIENT_QUIC_PORT)),
            local_addrs: &[seed],
            current_exe: Some(Path::new("/home/user/.local/bin/x0xd")),
        });
        assert_eq!(selection.mode, ParticipationMode::Full);
        assert_eq!(selection.reason, "seed_addr");
    }

    #[test]
    fn managed_binary_fail_closes_to_full() {
        // Why: ADR-0026 fleet binaries live under /opt/x0x/x0xd*. A Leaf
        // default on those hosts would drop backbone forwarding silently.
        for path in ["/opt/x0x/x0xd", "/opt/x0x/x0xd-testnet"] {
            let selection = resolve_participation(ParticipationInputs {
                operator_relay: false,
                bind_addr: ephemeral(),
                local_addrs: &[],
                current_exe: Some(Path::new(path)),
            });
            assert_eq!(
                selection.mode,
                ParticipationMode::Full,
                "{path} must be Full"
            );
            assert_eq!(selection.reason, "managed_binary");
        }
    }

    #[test]
    fn backbone_signals_override_missing_operator_opt_in() {
        // Why: fail-closed. `gossip.relay = false` on a seed must not Leaf.
        let seed: SocketAddr = "142.93.199.50:5483".parse().expect("nyc seed");
        let selection = resolve_participation(ParticipationInputs {
            operator_relay: false,
            bind_addr: seed,
            local_addrs: &[seed],
            current_exe: Some(Path::new("/opt/x0x/x0xd")),
        });
        assert_eq!(selection.mode, ParticipationMode::Full);
        assert_ne!(selection.reason, "default_leaf");
    }

    #[test]
    fn desktop_5483_without_seed_ip_stays_leaf() {
        // Why: default desktop bind is :5483; port alone is not backbone.
        let selection = resolve_participation(ParticipationInputs {
            operator_relay: false,
            bind_addr: SocketAddr::from(([192, 168, 1, 10], CLIENT_QUIC_PORT)),
            local_addrs: &[SocketAddr::from(([192, 168, 1, 10], CLIENT_QUIC_PORT))],
            current_exe: Some(Path::new("/usr/local/bin/x0xd")),
        });
        assert_eq!(selection.mode, ParticipationMode::Leaf);
        assert_eq!(selection.reason, "default_leaf");
    }

    #[test]
    fn participation_mode_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&ParticipationMode::Leaf).expect("leaf"),
            "\"leaf\""
        );
        assert_eq!(
            serde_json::to_string(&ParticipationMode::Full).expect("full"),
            "\"full\""
        );
    }
}
