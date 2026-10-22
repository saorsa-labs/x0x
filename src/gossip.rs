//! Gossip overlay networking for x0x.
//!
//! This module provides the gossip network layer built on saorsa-gossip,
//! enabling pub/sub messaging and HyParView membership management.

pub mod config;
mod egress;
pub(crate) mod join_seeds;
pub mod participation;
pub mod per_kind;
pub mod pubsub;
pub(crate) mod relay_fanout;
pub mod runtime;
pub(crate) mod stale_targets;
pub(crate) mod wire;

pub use config::{GossipConfig, LeafBytePolicy};
pub use participation::{
    classify_outbound_relay_json, leaf_refuses_unsubscribed_passthrough, resolve_participation,
    ParticipationInputs, ParticipationMode, ParticipationSelection, ParticipationSnapshot,
    RelayMetering, RELAY_BYTES_SEMANTICS,
};
pub use per_kind::{
    per_kind_gossip_stats, KindCountersSnapshot, PerKindGossipSnapshot, PerKindHealthVerdict,
    PerKindInterval, PER_KIND_BUS_SHARE_THRESHOLD, PER_KIND_ROLLING_WINDOW,
};
pub use pubsub::{
    inner_verify_stats, InboundByTopicSnapshot, InnerVerifyStats, InnerVerifyStatsSnapshot,
    PubSubManager, PubSubMessage, PubSubStats, PubSubStatsSnapshot, SigningContext, Subscription,
};
pub use runtime::{
    DispatchQueueDepthSnapshot, DispatchQueueStatsSnapshot, DispatchStreamStats,
    DispatchStreamStatsSnapshot, GossipDispatchStats, GossipDispatchStatsSnapshot, GossipRuntime,
};
pub use saorsa_gossip_pubsub::{PubSubStageStatsSnapshot, StageTimingStatsSnapshot};
