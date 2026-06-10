//! Privacy-preserving log identifiers (issue #83, privacy Layer 2).
//!
//! Mirrors `saorsa_gossip_types::logging` (their issue #13): a
//! per-process random salt plus BLAKE3 keyed hashing turn stable
//! identifiers into opaque, daemon-local tokens in `warn!`/`error!`
//! lines — `agent_a1b2c3d4` instead of a 64-char hex AgentId.
//! Properties:
//!
//! - Within one daemon run, the same identifier always shows the same
//!   token, so operators can still correlate log lines while debugging.
//! - After restart, and across daemons, the same real identifier hashes
//!   differently — logs alone cannot reconstruct a social graph.
//!
//! The salt is 32 random bytes in a `OnceLock`: memory-only, never
//! persisted, never exposed. For `PeerId`/`TopicId` use the re-exported
//! upstream wrappers; for x0x's own identifier shapes use the wrappers
//! below.
//!
//! ## Usage
//!
//! ```
//! use x0x::logging::{LogAgentId, LogHexId};
//! use x0x::identity::AgentId;
//!
//! let agent = AgentId([0xAA; 32]);
//! tracing::warn!(agent = %LogAgentId::from(&agent), "rejected");
//! // group ids and similar identifiers often travel as hex strings:
//! let group_hex = "a1b2c3";
//! tracing::warn!(group = %LogHexId::group(group_hex), "commit failed");
//! ```

use std::fmt;
use std::sync::OnceLock;

use crate::identity::{AgentId, MachineId, UserId};

pub use saorsa_gossip_types::{LogPeerId, LogTopicId};

/// Per-process random salt for keyed hashing of log identifiers.
static LOG_SALT: OnceLock<[u8; 32]> = OnceLock::new();

/// Return the per-process salt, initialising it on first call.
fn salt() -> &'static [u8; 32] {
    LOG_SALT.get_or_init(|| {
        use rand::RngCore;
        let mut s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut s);
        s
    })
}

/// **Test-only:** seed the process-global log salt deterministically.
///
/// Returns `true` if this call performed the initialisation, `false`
/// if the salt was already set. Exposed unconditionally so downstream
/// crate tests can produce deterministic log fixtures.
#[doc(hidden)]
pub fn init_log_salt_for_tests(seed: [u8; 32]) -> bool {
    LOG_SALT.set(seed).is_ok()
}

/// 8-hex-char opaque token for an identifier of any length under the
/// process-global salt.
fn opaque_token(bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(salt());
    hasher.update(bytes);
    hex::encode(&hasher.finalize().as_bytes()[..4])
}

macro_rules! log_id_wrapper {
    ($(#[$doc:meta])* $name:ident, $inner:ty, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy)]
        pub struct $name([u8; 32]);

        impl From<&$inner> for $name {
            fn from(id: &$inner) -> Self {
                Self(id.0)
            }
        }

        impl From<$inner> for $name {
            fn from(id: $inner) -> Self {
                Self(id.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($prefix, "_{}"), opaque_token(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Mirror Display — the `?` formatter must not leak either.
                fmt::Display::fmt(self, f)
            }
        }
    };
}

log_id_wrapper!(
    /// Displays an [`AgentId`] as `agent_xxxxxxxx`.
    LogAgentId,
    AgentId,
    "agent"
);
log_id_wrapper!(
    /// Displays a [`MachineId`] as `machine_xxxxxxxx`.
    LogMachineId,
    MachineId,
    "machine"
);
log_id_wrapper!(
    /// Displays a [`UserId`] as `user_xxxxxxxx`.
    LogUserId,
    UserId,
    "user"
);
log_id_wrapper!(
    /// Displays an ant-quic transport [`ant_quic::PeerId`] as `peer_xxxxxxxx`.
    LogTransportPeerId,
    ant_quic::PeerId,
    "peer"
);

/// Privacy wrapper for identifiers that travel as strings (hex group
/// ids, topic names, addresses). Displays as `<prefix>_xxxxxxxx`.
#[derive(Clone, Copy)]
pub struct LogHexId<'a> {
    prefix: &'static str,
    id: &'a str,
}

impl<'a> LogHexId<'a> {
    /// Wrap an arbitrary string identifier with a custom prefix.
    #[must_use]
    pub fn new<S: AsRef<str> + ?Sized>(prefix: &'static str, id: &'a S) -> Self {
        Self {
            prefix,
            id: id.as_ref(),
        }
    }

    /// Wrap a hex group id → `group_xxxxxxxx`.
    #[must_use]
    pub fn group<S: AsRef<str> + ?Sized>(id: &'a S) -> Self {
        Self::new("group", id)
    }

    /// Wrap a topic name → `topic_xxxxxxxx`.
    #[must_use]
    pub fn topic<S: AsRef<str> + ?Sized>(id: &'a S) -> Self {
        Self::new("topic", id)
    }

    /// Wrap a hex agent id string → `agent_xxxxxxxx`.
    #[must_use]
    pub fn agent<S: AsRef<str> + ?Sized>(id: &'a S) -> Self {
        Self::new("agent", id)
    }

    /// Wrap a network address → `addr_xxxxxxxx`.
    #[must_use]
    pub fn addr<S: AsRef<str> + ?Sized>(id: &'a S) -> Self {
        Self::new("addr", id)
    }
}

impl fmt::Display for LogHexId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.prefix, opaque_token(self.id.as_bytes()))
    }
}

impl fmt::Debug for LogHexId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_stable_within_process_and_leak_nothing() {
        // Within one process the same id must map to the same token
        // (operators correlate lines), and the rendered form must not
        // contain the real identifier (the privacy property).
        init_log_salt_for_tests([42u8; 32]);
        let agent = AgentId([0xAB; 32]);
        let a1 = format!("{}", LogAgentId::from(&agent));
        let a2 = format!("{}", LogAgentId::from(&agent));
        assert_eq!(a1, a2, "same id must render the same token in-process");
        assert!(a1.starts_with("agent_"), "prefixed for readability: {a1}");
        assert_eq!(a1.len(), "agent_".len() + 8, "8 hex chars: {a1}");
        let real_hex = hex::encode([0xAB; 32]);
        assert!(
            !a1.contains(&real_hex[..8]),
            "token must not embed the real id"
        );
    }

    #[test]
    fn different_ids_get_different_tokens() {
        init_log_salt_for_tests([42u8; 32]);
        let a = format!("{}", LogAgentId::from(AgentId([1u8; 32])));
        let b = format!("{}", LogAgentId::from(AgentId([2u8; 32])));
        assert_ne!(a, b);
    }

    #[test]
    fn debug_formatter_does_not_leak() {
        init_log_salt_for_tests([42u8; 32]);
        let agent = AgentId([0xCD; 32]);
        assert_eq!(
            format!("{:?}", LogAgentId::from(&agent)),
            format!("{}", LogAgentId::from(&agent)),
            "Debug must mirror Display so tracing's ? sigil cannot leak"
        );
    }

    #[test]
    fn string_identifier_wrapper_redacts_groups_and_topics() {
        init_log_salt_for_tests([42u8; 32]);
        let group_hex = "deadbeefdeadbeefdeadbeefdeadbeef";
        let g = format!("{}", LogHexId::group(group_hex));
        assert!(g.starts_with("group_"));
        assert!(!g.contains("deadbeef"), "must not leak the group id: {g}");
        let t = format!("{}", LogHexId::topic("secret-team-channel"));
        assert!(!t.contains("secret"), "must not leak the topic name: {t}");
    }
}
