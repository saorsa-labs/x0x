pub mod agent_api;
pub mod persistence_runtime;
pub mod policy_bounds;
pub mod shutdown;

pub use agent_api::{
    AgentApiError, AgentCheckpointApi, AutomaticCheckpointOutcome, ExplicitCheckpointOutcome,
};
pub use persistence_runtime::{EnabledPersistenceRuntime, PersistenceRuntime};
pub use policy_bounds::{
    apply_checkpoint_frequency_update, ensure_policy_within_envelope, validate_host_envelope,
    PolicyBoundsError, RuntimeCheckpointPolicyUpdate,
};
pub use shutdown::{graceful_shutdown, GracefulShutdownResult};
