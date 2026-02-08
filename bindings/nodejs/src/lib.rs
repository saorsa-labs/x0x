#![deny(clippy::all)]

mod agent;
mod config;
mod events;
mod health;
mod identity;
mod runtime_controls;
mod task_list;

pub use agent::{Agent, AgentBuilder, Message, Subscription};
pub use config::{
    parse_persistence_mode, resolve_persistence_config, BindingHostPolicyEnvelope,
    BindingPersistenceConfigInput, BindingResolvedPersistenceConfig,
};
pub use events::{ErrorEvent, EventListener, PeerConnectedEvent, PeerDisconnectedEvent};
pub use health::{
    map_persistence_health, map_persistence_observability, BindingPersistenceErrorInfo,
    BindingPersistenceHealth, BindingPersistenceObservability,
};
pub use identity::{AgentId, MachineId};
pub use runtime_controls::{
    query_persistence_observability, request_checkpoint_frequency_adjustment,
    BindingCheckpointFrequencyUpdateRequest, BindingInvalidRequestError,
};
pub use task_list::{TaskList, TaskSnapshot};
