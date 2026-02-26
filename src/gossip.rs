//! Gossip overlay networking for x0x.
//!
//! This module provides the gossip network layer built on saorsa-gossip,
//! enabling pub/sub messaging and HyParView membership management.

pub mod config;
pub mod pubsub;
pub mod runtime;

pub use config::GossipConfig;
pub use pubsub::{PubSubManager, PubSubMessage, SigningContext, Subscription};
pub use runtime::GossipRuntime;
