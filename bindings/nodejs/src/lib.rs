#![deny(clippy::all)]

mod agent;
mod config;
mod events;
mod health;
mod identity;
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
pub use task_list::{TaskList, TaskSnapshot};
