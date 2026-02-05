//! Gossip overlay networking for x0x.
//!
//! This module provides the gossip network layer built on saorsa-gossip,
//! enabling agent discovery, pub/sub messaging, presence tracking, and
//! CRDT synchronization.

pub mod anti_entropy;
pub mod config;
pub mod coordinator;
pub mod discovery;
pub mod membership;
pub mod presence;
pub mod pubsub;
pub mod rendezvous;
pub mod runtime;
pub mod transport;

pub use anti_entropy::{AntiEntropyManager, ReconciliationStats};
pub use config::GossipConfig;
pub use coordinator::{CoordinatorAdvert, CoordinatorManager};
pub use discovery::DiscoveryManager;
pub use membership::MembershipManager;
pub use presence::{PresenceEvent, PresenceManager};
pub use pubsub::{PubSubManager, PubSubMessage};
pub use rendezvous::RendezvousManager;
pub use runtime::GossipRuntime;
pub use transport::{QuicTransportAdapter, TransportEvent};
