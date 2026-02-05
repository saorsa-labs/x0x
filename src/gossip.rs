//! Gossip overlay networking for x0x.
//!
//! This module provides the gossip network layer built on saorsa-gossip,
//! enabling agent discovery, pub/sub messaging, presence tracking, and
//! CRDT synchronization.

pub mod config;
pub mod runtime;
pub mod transport;

pub use config::GossipConfig;
pub use runtime::GossipRuntime;
pub use transport::{QuicTransportAdapter, TransportEvent};
